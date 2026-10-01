//! Tool calls an inference engine returned, extracted from the response body
//! the attesting proxy relays: chat completions (`message.tool_calls`,
//! streamed `delta.tool_calls`, legacy `function_call`) and the Responses API
//! (`function_call` output items), as plain JSON or as an SSE stream.
//!
//! The list is an *index* of the response body, whose digest is signed
//! separately (`execution.output_hash`): anyone holding the body re-derives
//! it with [`extract`] and compares. Names and call ids are recorded in
//! clear (an auditor must read *which* action ran); arguments only as
//! `sha256` of the exact string the engine emitted, stream fragments
//! concatenated. When the body cannot be parsed completely the report is
//! marked `incomplete` instead of guessing, so a missing call is evidence of
//! absence only when `incomplete` is false.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Non-streamed bodies are buffered to be parsed; larger ones are skipped.
const MAX_JSON_BODY: usize = 16 * 1024 * 1024;
/// One SSE line or event; a larger one is skipped.
const MAX_SSE_EVENT: usize = 4 * 1024 * 1024;
/// Calls recorded per response; more marks the report incomplete.
pub(crate) const MAX_CALLS: usize = 256;
/// Longest tool name or call id recorded verbatim.
pub(crate) const MAX_LABEL: usize = 1024;
/// Tool index used for the legacy single `function_call` of a choice, so it
/// sorts after (and never collides with) indexed `tool_calls`.
const LEGACY_INDEX: u32 = u32::MAX;

/// One tool invocation requested by the model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    /// `choices[].index` the call belongs to; 0 for the Responses API.
    pub choice: u32,
    /// Engine-assigned call id (`call_…`): links the call to the `tool`
    /// message that later carries its result.
    pub id: Option<String>,
    pub name: String,
    /// `sha256:` of the exact `arguments` string (JCS bytes when an engine
    /// emits a JSON object instead of a string).
    pub arguments_hash: String,
}

/// Outcome of an extraction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolCallReport {
    /// Ordered by `(choice, index)`.
    pub calls: Vec<ToolCall>,
    /// Something could not be parsed (size cap, malformed JSON or stream,
    /// compressed body): `calls` may miss entries.
    pub incomplete: bool,
}

/// Extract tool calls from a complete response body — exactly what
/// [`ToolCallExtractor`] yields when fed the same bytes in any chunking.
pub fn extract(body: &[u8]) -> ToolCallReport {
    let mut extractor = ToolCallExtractor::new();
    extractor.update(body);
    extractor.finish()
}

/// Incremental extractor fed with the decoded response body as it streams.
///
/// The format is decided from the bytes alone, never from headers, so the
/// signed list is reproducible from the body: a body whose first
/// non-whitespace byte is `{` is one JSON document, anything else is read as
/// an SSE stream (a non-SSE body simply has no `data:` events).
pub struct ToolCallExtractor {
    mode: Mode,
    acc: Accumulator,
}

enum Mode {
    Off,
    /// Only whitespace seen so far, kept to be replayed once decided.
    Undecided(Vec<u8>),
    Json {
        buf: Vec<u8>,
        overflow: bool,
    },
    Sse(SseState),
}

impl Mode {
    fn json() -> Self {
        Mode::Json {
            buf: Vec::new(),
            overflow: false,
        }
    }

    fn sse() -> Self {
        Mode::Sse(SseState::default())
    }
}

impl Default for ToolCallExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolCallExtractor {
    pub fn new() -> Self {
        Self::with_mode(Mode::Undecided(Vec::new()))
    }

    /// Extractor for a response sent with this `Content-Encoding`: a
    /// compressed body cannot be read, so its report is empty and marked
    /// incomplete.
    pub fn for_encoding(content_encoding: Option<&str>) -> Self {
        let encoded = content_encoding.is_some_and(|e| !e.trim().eq_ignore_ascii_case("identity"));
        if !encoded {
            return Self::new();
        }
        let mut extractor = Self::with_mode(Mode::Off);
        extractor.acc.incomplete = true;
        extractor
    }

    /// Extractor that records nothing (e.g. for non-`POST` calls).
    pub fn off() -> Self {
        Self::with_mode(Mode::Off)
    }

    fn with_mode(mode: Mode) -> Self {
        Self {
            mode,
            acc: Accumulator::default(),
        }
    }

    /// Feed the next decoded body bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        if let Mode::Undecided(pending) = &mut self.mode {
            let first = bytes.iter().position(|b| !b.is_ascii_whitespace());
            let leading = pending.len().saturating_add(first.unwrap_or(bytes.len()));
            if first.is_none() && leading <= MAX_SSE_EVENT {
                pending.extend_from_slice(bytes);
                return;
            }
            // More leading whitespace than the cap reads as SSE whatever
            // follows, so the decision never depends on chunking.
            let is_json = leading <= MAX_SSE_EVENT && first.is_some_and(|i| bytes[i] == b'{');
            let pending = std::mem::take(pending);
            self.mode = if is_json { Mode::json() } else { Mode::sse() };
            self.feed(&pending);
        }
        self.feed(bytes);
    }

    fn feed(&mut self, bytes: &[u8]) {
        match &mut self.mode {
            Mode::Off | Mode::Undecided(_) => {}
            Mode::Json { buf, overflow } => {
                if *overflow || buf.len().saturating_add(bytes.len()) > MAX_JSON_BODY {
                    *overflow = true;
                    buf.clear();
                } else {
                    buf.extend_from_slice(bytes);
                }
            }
            Mode::Sse(state) => state.feed(bytes, &mut self.acc),
        }
    }

    /// Finish the body and return what was found.
    pub fn finish(mut self) -> ToolCallReport {
        match std::mem::replace(&mut self.mode, Mode::Off) {
            Mode::Off | Mode::Undecided(_) => {}
            Mode::Json { overflow: true, .. } => self.acc.incomplete = true,
            Mode::Json { buf, .. } => self.acc.ingest_body(&buf),
            Mode::Sse(mut state) => state.end(&mut self.acc),
        }
        self.acc.into_report()
    }
}

// ── SSE framing (WHATWG "server-sent events", `data:` fields only) ───────

#[derive(Default)]
struct SseState {
    line: Vec<u8>,
    line_oversized: bool,
    data: Vec<u8>,
    has_data: bool,
    event_bad: bool,
}

impl SseState {
    fn feed(&mut self, mut bytes: &[u8], acc: &mut Accumulator) {
        while let Some(pos) = bytes.iter().position(|b| *b == b'\n') {
            self.push_part(&bytes[..pos]);
            self.end_line(acc);
            bytes = &bytes[pos + 1..];
        }
        self.push_part(bytes);
    }

    fn push_part(&mut self, part: &[u8]) {
        if self.line_oversized {
            return;
        }
        if self.line.len().saturating_add(part.len()) > MAX_SSE_EVENT {
            self.line_oversized = true;
            self.line.clear();
        } else {
            self.line.extend_from_slice(part);
        }
    }

    fn end_line(&mut self, acc: &mut Accumulator) {
        let line = std::mem::take(&mut self.line);
        if std::mem::take(&mut self.line_oversized) {
            self.event_bad = true;
            return;
        }
        let line = line.strip_suffix(b"\r").unwrap_or(&line);
        if line.is_empty() {
            self.dispatch(acc);
            return;
        }
        let Some(value) = line.strip_prefix(b"data:") else {
            return; // comments (`:`), `event:`, `id:`, `retry:` carry no calls
        };
        let value = value.strip_prefix(b" ").unwrap_or(value);
        if self.data.len().saturating_add(value.len()) > MAX_SSE_EVENT {
            self.event_bad = true;
            return;
        }
        if self.has_data {
            self.data.push(b'\n');
        }
        self.data.extend_from_slice(value);
        self.has_data = true;
    }

    fn dispatch(&mut self, acc: &mut Accumulator) {
        let data = std::mem::take(&mut self.data);
        let had_data = std::mem::take(&mut self.has_data);
        if std::mem::take(&mut self.event_bad) {
            acc.incomplete = true;
        } else if had_data && data.as_slice() != b"[DONE]" {
            acc.ingest_body(&data);
        }
    }

    /// End of body: a final event without its blank line still counts.
    fn end(&mut self, acc: &mut Accumulator) {
        if !self.line.is_empty() || self.line_oversized {
            self.end_line(acc);
        }
        self.dispatch(acc);
    }
}

// ── Accumulation ────────────────────────────────────────────────────────

#[derive(Default)]
struct Accumulator {
    calls: BTreeMap<(u32, u32), Partial>,
    incomplete: bool,
}

struct Partial {
    id: Option<String>,
    name: String,
    args: Sha256,
    bad: bool,
}

/// The pieces of one call carried by a message, delta or output item.
struct Piece<'a> {
    id: Option<&'a str>,
    name: Option<&'a str>,
    arguments: Option<&'a Value>,
}

impl Accumulator {
    fn ingest_body(&mut self, bytes: &[u8]) {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        match serde_json::from_slice::<Value>(bytes) {
            Ok(value) => self.ingest(&value),
            Err(_) => self.incomplete = true,
        }
    }

    fn ingest(&mut self, v: &Value) {
        if let Some(choices) = v.get("choices").and_then(Value::as_array) {
            for (pos, choice) in choices.iter().enumerate() {
                self.choice(pos, choice);
            }
        }
        match v.get("type").and_then(Value::as_str) {
            Some("response.output_item.done") => {
                if let Some(index) = self.index_of(v.get("output_index"), 0) {
                    self.output_item(index, v.get("item"));
                }
            }
            Some("response.completed") => self.response_output(v.get("response")),
            _ => {}
        }
        if v.get("object").and_then(Value::as_str) == Some("response") {
            self.response_output(Some(v));
        }
    }

    /// One chat-completions choice: `message` (complete) or `delta` (stream).
    fn choice(&mut self, pos: usize, choice: &Value) {
        let Some(c) = self.index_of(choice.get("index"), pos) else {
            return;
        };
        for (field, streamed) in [("message", false), ("delta", true)] {
            let Some(msg) = choice.get(field) else {
                continue;
            };
            if let Some(calls) = msg.get("tool_calls").and_then(Value::as_array) {
                for (j, call) in calls.iter().enumerate() {
                    if let Some(t) = self.index_of(call.get("index"), j) {
                        self.add((c, t), function_piece(call, call.get("function")), streamed);
                    }
                }
            }
            if let Some(legacy) = msg.get("function_call").filter(|f| f.is_object()) {
                self.add(
                    (c, LEGACY_INDEX),
                    function_piece(legacy, Some(legacy)),
                    streamed,
                );
            }
        }
    }

    /// `output[]` of a Responses API object (non-streamed or `completed`).
    fn response_output(&mut self, response: Option<&Value>) {
        let Some(items) = response
            .and_then(|r| r.get("output"))
            .and_then(Value::as_array)
        else {
            return;
        };
        for (k, item) in items.iter().enumerate() {
            if let Ok(index) = u32::try_from(k) {
                self.output_item(index, Some(item));
            }
        }
    }

    fn output_item(&mut self, index: u32, item: Option<&Value>) {
        let Some(item) =
            item.filter(|i| i.get("type").and_then(Value::as_str) == Some("function_call"))
        else {
            return;
        };
        let id = item.get("call_id").or_else(|| item.get("id"));
        let piece = Piece {
            id: id.and_then(Value::as_str),
            name: item.get("name").and_then(Value::as_str),
            arguments: item.get("arguments"),
        };
        self.add((0, index), piece, false);
    }

    /// `index` field if present (it must fit `u32`), else the position.
    fn index_of(&mut self, field: Option<&Value>, pos: usize) -> Option<u32> {
        let parsed = match field {
            Some(v) => v.as_u64().and_then(|n| u32::try_from(n).ok()),
            None => u32::try_from(pos).ok(),
        };
        if parsed.is_none() {
            self.incomplete = true;
        }
        parsed
    }

    /// Streamed pieces append to the call at `key`. A complete piece fills a
    /// new call; at a taken key it is either the repeat a Responses stream
    /// sends in `response.completed` (same id, ignored) or a conflict.
    fn add(&mut self, key: (u32, u32), piece: Piece<'_>, streamed: bool) {
        if let Some(existing) = self.calls.get(&key) {
            if !streamed {
                self.incomplete |= existing.id.as_deref() != piece.id;
                return;
            }
        } else if self.calls.len() >= MAX_CALLS {
            self.incomplete = true;
            return;
        }
        let partial = self.calls.entry(key).or_insert_with(Partial::new);
        let recorded = partial.absorb(&piece);
        self.incomplete |= !recorded;
    }

    fn into_report(self) -> ToolCallReport {
        let mut incomplete = self.incomplete;
        let mut calls = Vec::with_capacity(self.calls.len());
        for ((choice, _), partial) in self.calls {
            if partial.bad || partial.name.is_empty() {
                incomplete = true;
                continue;
            }
            calls.push(ToolCall {
                choice,
                id: partial.id,
                name: partial.name,
                arguments_hash: format!("sha256:{}", hex::encode(partial.args.finalize())),
            });
        }
        ToolCallReport { calls, incomplete }
    }
}

/// Id from the call object, name and arguments from its `function` object.
fn function_piece<'a>(call: &'a Value, function: Option<&'a Value>) -> Piece<'a> {
    Piece {
        id: call.get("id").and_then(Value::as_str),
        name: function.and_then(|f| f.get("name")).and_then(Value::as_str),
        arguments: function.and_then(|f| f.get("arguments")),
    }
}

/// `sha256:` of a value exactly as [`Partial::absorb`] digests arguments: a
/// string's bytes, nothing for `null`/absent, JCS bytes otherwise (`None`
/// when JCS refuses it, e.g. a float).
pub(crate) fn value_digest(value: Option<&Value>) -> Option<String> {
    let mut hasher = Sha256::new();
    match value {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => hasher.update(s.as_bytes()),
        Some(other) => hasher.update(crate::jcs::canonicalize(other).ok()?),
    }
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
}

impl Partial {
    fn new() -> Self {
        Self {
            id: None,
            name: String::new(),
            args: Sha256::new(),
            bad: false,
        }
    }

    /// Fold `piece` in; `false` when part of it could not be recorded.
    fn absorb(&mut self, piece: &Piece<'_>) -> bool {
        if let Some(id) = piece.id.filter(|id| !id.is_empty()) {
            if self.id.is_none() && id.len() <= MAX_LABEL {
                self.id = Some(id.to_string());
            } else if self.id.is_none() {
                self.bad = true;
            }
        }
        if let Some(name) = piece.name {
            if self.name.len().saturating_add(name.len()) <= MAX_LABEL {
                self.name.push_str(name);
            } else {
                self.bad = true;
            }
        }
        match piece.arguments {
            None | Some(Value::Null) => true,
            Some(Value::String(s)) => {
                self.args.update(s.as_bytes());
                true
            }
            Some(other) => match crate::jcs::canonicalize(other) {
                Ok(bytes) => {
                    self.args.update(&bytes);
                    true
                }
                Err(_) => {
                    self.bad = true;
                    false
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(s.as_bytes())))
    }

    fn call(choice: u32, id: Option<&str>, name: &str, args: &str) -> ToolCall {
        ToolCall {
            choice,
            id: id.map(str::to_string),
            name: name.to_string(),
            arguments_hash: h(args),
        }
    }

    const CHAT_JSON: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","choices":[{"index":0,
        "message":{"role":"assistant","content":null,"tool_calls":[
          {"id":"call_a","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}},
          {"id":"call_b","type":"function","function":{"name":"send_email","arguments":"{\"to\":\"x@y\"}"}}]},
        "finish_reason":"tool_calls"}]}"#;

    #[test]
    fn chat_completion_json_lists_every_call_in_order() {
        let r = extract(CHAT_JSON.as_bytes());
        assert!(!r.incomplete);
        assert_eq!(
            r.calls,
            vec![
                call(0, Some("call_a"), "get_weather", r#"{"city":"Paris"}"#),
                call(0, Some("call_b"), "send_email", r#"{"to":"x@y"}"#),
            ]
        );
    }

    #[test]
    fn plain_answer_has_no_calls_and_is_complete() {
        let r = extract(br#"{"choices":[{"index":0,"message":{"content":"hi"}}]}"#);
        assert_eq!(r, ToolCallReport::default());
        assert_eq!(extract(b""), ToolCallReport::default());
    }

    /// The same two calls streamed with split names/arguments, interleaved
    /// indexes, CRLF lines, comments and `[DONE]` hash exactly like the
    /// non-streamed body.
    #[test]
    fn streamed_deltas_concatenate_to_the_same_digests() {
        let sse = concat!(
            ": keep-alive\r\n\r\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"type\":\"function\",\"function\":{\"name\":\"get_\",\"arguments\":\"\"}}]}}]}\r\n\r\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"weather\",\"arguments\":\"{\\\"city\\\":\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_b\",\"function\":{\"name\":\"send_email\",\"arguments\":\"{\\\"to\\\":\\\"x@y\\\"}\"}}]}}]}\n\n",
            "event: ignored\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"Paris\\\"}\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let r = extract(sse.as_bytes());
        assert!(!r.incomplete, "{r:?}");
        assert_eq!(r.calls, extract(CHAT_JSON.as_bytes()).calls);
    }

    /// Byte-at-a-time feeding (worst case TCP fragmentation) changes nothing.
    #[test]
    fn extraction_is_independent_of_chunking() {
        let sse = "data: {\"choices\":[{\"index\":2,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\",\"function\":{\"name\":\"f\",\"arguments\":\"{}\"}}]}}]}\n\n";
        for body in [
            sse.as_bytes(),
            CHAT_JSON.as_bytes(),
            b"\n \r\n{\"choices\":[]}",
        ] {
            let mut x = ToolCallExtractor::new();
            for b in body {
                x.update(std::slice::from_ref(b));
            }
            assert_eq!(x.finish(), extract(body));
        }
        assert_eq!(
            extract(sse.as_bytes()).calls,
            vec![call(2, Some("c"), "f", "{}")]
        );
    }

    /// The format comes from the bytes, not from headers: a JSON body sent as
    /// `text/plain` is still read (a receipt never claims "no calls" for a
    /// body it did not parse), and leading whitespace is kept verbatim.
    #[test]
    fn format_is_sniffed_from_the_body() {
        let r = extract(format!("  \n{CHAT_JSON}").as_bytes());
        assert_eq!(r.calls.len(), 2);
        let ev = "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"c\",\"function\":{\"name\":\"f\"}}]}}]}\n\n";
        assert_eq!(extract(format!("\n\n{ev}").as_bytes()).calls.len(), 1);
        // " data:" is not a data field: the space must not be swallowed.
        assert!(extract(format!(" {ev}").as_bytes()).calls.is_empty());
        assert_eq!(extract(b"plain text answer\n"), ToolCallReport::default());
        assert_eq!(extract(b" \n\t "), ToolCallReport::default());
    }

    #[test]
    fn final_event_without_blank_line_counts() {
        let sse = "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"c\",\"function\":{\"name\":\"f\",\"arguments\":\"1\"}}]}}]}";
        assert_eq!(
            extract(sse.as_bytes()).calls,
            vec![call(0, Some("c"), "f", "1")]
        );
    }

    #[test]
    fn multiline_data_fields_join_with_newline() {
        let sse = "data: {\"choices\":[{\"delta\":{\"tool_calls\":[\ndata: {\"id\":\"c\",\"function\":{\"name\":\"f\",\"arguments\":\"\"}}]}}]}\n\n";
        let r = extract(sse.as_bytes());
        assert!(!r.incomplete);
        assert_eq!(r.calls, vec![call(0, Some("c"), "f", "")]);
    }

    #[test]
    fn legacy_function_call_is_recorded_after_indexed_calls() {
        let body = r#"{"choices":[{"index":0,"message":{"function_call":{"name":"old","arguments":"{}"},
            "tool_calls":[{"id":"n","function":{"name":"new","arguments":"[]"}}]}}]}"#;
        let r = extract(body.as_bytes());
        assert_eq!(
            r.calls,
            vec![call(0, Some("n"), "new", "[]"), call(0, None, "old", "{}")]
        );
    }

    #[test]
    fn multiple_choices_keep_their_index() {
        let body = r#"{"choices":[
            {"index":1,"message":{"tool_calls":[{"id":"b","function":{"name":"g","arguments":""}}]}},
            {"index":0,"message":{"tool_calls":[{"id":"a","function":{"name":"f","arguments":""}}]}}]}"#;
        let r = extract(body.as_bytes());
        assert_eq!(
            r.calls,
            vec![call(0, Some("a"), "f", ""), call(1, Some("b"), "g", "")]
        );
    }

    #[test]
    fn responses_api_json_and_stream_agree_without_duplicates() {
        let json = r#"{"object":"response","output":[
            {"type":"message","content":[]},
            {"type":"function_call","id":"fc_1","call_id":"call_1","name":"lookup","arguments":"{\"q\":1}"}]}"#;
        let item = r#"{"type":"function_call","id":"fc_1","call_id":"call_1","name":"lookup","arguments":"{\"q\":1}"}"#;
        let one_line = json.replace('\n', " ");
        let sse = format!(
            "event: response.output_item.done\ndata: {{\"type\":\"response.output_item.done\",\"output_index\":1,\"item\":{item}}}\n\n\
             event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{one_line}}}\n\n"
        );
        let expected = vec![call(0, Some("call_1"), "lookup", r#"{"q":1}"#)];
        assert_eq!(extract(json.as_bytes()).calls, expected);
        let r = extract(sse.as_bytes());
        assert!(!r.incomplete);
        assert_eq!(r.calls, expected);
    }

    #[test]
    fn conflicting_complete_calls_at_one_index_are_flagged() {
        let body = r#"{"choices":[{"message":{"tool_calls":[
            {"index":0,"id":"a","function":{"name":"f","arguments":""}},
            {"index":0,"id":"b","function":{"name":"g","arguments":""}}]}}]}"#;
        let r = extract(body.as_bytes());
        assert!(r.incomplete);
        assert_eq!(r.calls, vec![call(0, Some("a"), "f", "")]);
    }

    #[test]
    fn object_arguments_hash_their_jcs_bytes() {
        let body = r#"{"choices":[{"message":{"tool_calls":[{"id":"c","function":{"name":"f","arguments":{"b":1,"a":[true]}}}]}}]}"#;
        let r = extract(body.as_bytes());
        assert!(!r.incomplete);
        assert_eq!(
            r.calls,
            vec![call(0, Some("c"), "f", r#"{"a":[true],"b":1}"#)]
        );
        let float = r#"{"choices":[{"message":{"tool_calls":[{"id":"c","function":{"name":"f","arguments":{"x":1.5}}}]}}]}"#;
        let r = extract(float.as_bytes());
        assert!(r.incomplete && r.calls.is_empty(), "{r:?}");
    }

    #[test]
    fn unparseable_inputs_are_reported_incomplete_never_guessed() {
        assert!(extract(b"{not json").incomplete);
        assert!(extract(b"data: {broken\n\n").incomplete);
        let nameless = r#"{"choices":[{"message":{"tool_calls":[{"id":"c","function":{"arguments":"{}"}}]}}]}"#;
        let r = extract(nameless.as_bytes());
        assert!(r.incomplete && r.calls.is_empty());
        let huge_index = r#"{"choices":[{"index":99999999999,"message":{"tool_calls":[]}}]}"#;
        assert!(extract(huge_index.as_bytes()).incomplete);
    }

    #[test]
    fn caps_mark_incomplete() {
        let many: Vec<String> = (0..=MAX_CALLS)
            .map(|i| format!(r#"{{"id":"c{i}","function":{{"name":"f","arguments":""}}}}"#))
            .collect();
        let body = format!(
            r#"{{"choices":[{{"message":{{"tool_calls":[{}]}}}}]}}"#,
            many.join(",")
        );
        let r = extract(body.as_bytes());
        assert!(r.incomplete);
        assert_eq!(r.calls.len(), MAX_CALLS);

        let long = "x".repeat(MAX_LABEL + 1);
        let body = format!(
            r#"{{"choices":[{{"message":{{"tool_calls":[{{"function":{{"name":"{long}"}}}}]}}}}]}}"#
        );
        let r = extract(body.as_bytes());
        assert!(r.incomplete && r.calls.is_empty());

        let mut x = ToolCallExtractor::new();
        x.update(b"{");
        x.update(&vec![b' '; MAX_JSON_BODY]);
        x.update(b"}");
        assert!(x.finish().incomplete);

        let mut x = ToolCallExtractor::new();
        x.update(b"data: ");
        x.update(&vec![b'a'; MAX_SSE_EVENT]);
        x.update(b"\n\ndata: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"id\":\"c\",\"function\":{\"name\":\"f\"}}]}}]}\n\n");
        let r = x.finish();
        assert!(r.incomplete, "oversized event must be flagged");
        assert_eq!(
            r.calls,
            vec![call(0, Some("c"), "f", "")],
            "next event still parsed"
        );
    }

    #[test]
    fn compressed_bodies_are_unreadable_and_off_records_nothing() {
        let parse = |mut x: ToolCallExtractor| {
            x.update(CHAT_JSON.as_bytes());
            x.finish()
        };
        assert_eq!(parse(ToolCallExtractor::for_encoding(None)).calls.len(), 2);
        assert_eq!(
            parse(ToolCallExtractor::for_encoding(Some(" Identity ")))
                .calls
                .len(),
            2
        );
        let gz = parse(ToolCallExtractor::for_encoding(Some("gzip")));
        assert!(gz.incomplete && gz.calls.is_empty());
        assert_eq!(parse(ToolCallExtractor::off()), ToolCallReport::default());
    }

    #[test]
    fn huge_whitespace_prefix_reads_as_sse_whatever_the_chunking() {
        let mut body = vec![b' '; MAX_SSE_EVENT + 1];
        body.extend_from_slice(CHAT_JSON.as_bytes());
        let whole = extract(&body);
        let mut x = ToolCallExtractor::new();
        for part in body.chunks(MAX_SSE_EVENT / 3) {
            x.update(part);
        }
        assert_eq!(x.finish(), whole);
        assert!(whole.calls.is_empty());
    }
}
