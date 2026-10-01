//! Tool context an agent sends *to* the engine, extracted from the request
//! body the attesting proxy forwards: the tools it offers (`tools[]`,
//! legacy `functions[]`), the earlier calls it replays as history
//! (`assistant.tool_calls`, Responses `function_call` input items) and the
//! results it feeds back (`role: "tool"` messages, Responses
//! `function_call_output` items).
//!
//! Like [`crate::tool_calls`] this is an *index* of a body whose digest is
//! signed separately (`execution.input_hash`), so an auditor holding the
//! request re-derives it. Results are recorded as the call id they answer and
//! the `sha256` of their content: [`crate::tool_linkage`] then checks across a
//! trail that every result answers a call the engine really issued, and that
//! replayed history matches what the engine really returned.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::tool_calls::{value_digest, ToolCall, MAX_CALLS, MAX_LABEL};

/// Request bodies larger than this are not parsed (report incomplete).
const MAX_REQUEST_JSON: usize = 16 * 1024 * 1024;

/// A tool result the agent returned to the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResult {
    /// Id of the call this result answers (`tool_call_id` / `call_id`).
    pub id: String,
    /// `sha256:` of the result content (string bytes, JCS otherwise).
    pub content_hash: String,
}

/// Outcome of a request extraction.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestToolReport {
    /// Function tool names offered to the model, in request order.
    pub offered: Vec<String>,
    /// Earlier calls replayed as conversation history (`choice` is 0).
    pub history: Vec<ToolCall>,
    /// Results fed back, in request order.
    pub results: Vec<ToolResult>,
    /// Part of the request could not be indexed: the lists may miss entries.
    pub incomplete: bool,
}

impl RequestToolReport {
    pub fn is_empty(&self) -> bool {
        self.offered.is_empty() && self.history.is_empty() && self.results.is_empty()
    }
}

/// Index a request sent with this `Content-Encoding`: a compressed body
/// cannot be read, so its report is empty and marked incomplete.
pub fn extract_request_encoded(body: &[u8], content_encoding: Option<&str>) -> RequestToolReport {
    if content_encoding.is_some_and(|e| !e.trim().eq_ignore_ascii_case("identity")) {
        return RequestToolReport {
            incomplete: true,
            ..RequestToolReport::default()
        };
    }
    extract_request(body)
}

/// Index a complete request body. Only a body whose first non-whitespace
/// byte is `{` is read; anything else (form data, plain text) carries no
/// tool context and yields an empty, complete report.
pub fn extract_request(body: &[u8]) -> RequestToolReport {
    let mut c = Collector::default();
    let starts_json = body
        .iter()
        .find(|b| !b.is_ascii_whitespace())
        .is_some_and(|b| *b == b'{');
    if !starts_json {
        return c.report;
    }
    if body.len() > MAX_REQUEST_JSON {
        c.report.incomplete = true;
        return c.report;
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(v) => c.document(&v),
        Err(_) => c.report.incomplete = true,
    }
    c.report
}

#[derive(Default)]
struct Collector {
    report: RequestToolReport,
}

impl Collector {
    fn document(&mut self, v: &Value) {
        for field in ["tools", "functions"] {
            for tool in v.get(field).and_then(Value::as_array).into_iter().flatten() {
                self.offered(tool);
            }
        }
        for msg in v
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            self.message(msg);
        }
        for item in v
            .get("input")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            self.input_item(item);
        }
    }

    /// Chat `{type:function, function:{name}}`, Responses or legacy `{name}`;
    /// built-in tools (no name) are not function calls and are skipped.
    fn offered(&mut self, tool: &Value) {
        let name = tool
            .get("function")
            .and_then(|f| f.get("name"))
            .or_else(|| tool.get("name"));
        let Some(name) = name.and_then(|n| self.label(Some(n))) else {
            return;
        };
        if self.room(self.report.offered.len()) {
            self.report.offered.push(name);
        }
    }

    fn message(&mut self, msg: &Value) {
        match msg.get("role").and_then(Value::as_str) {
            Some("tool") => self.result(msg.get("tool_call_id"), msg.get("content")),
            Some("assistant") => {
                for call in msg
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let f = call.get("function");
                    let id = call.get("id");
                    self.history(
                        id,
                        f.and_then(|f| f.get("name")),
                        f.and_then(|f| f.get("arguments")),
                    );
                }
                if let Some(legacy) = msg.get("function_call").filter(|f| f.is_object()) {
                    self.history(None, legacy.get("name"), legacy.get("arguments"));
                }
            }
            // A legacy `function` result names the tool, not the call: it
            // cannot be linked, so its absence from `results` is flagged.
            Some("function") => self.report.incomplete = true,
            _ => {}
        }
    }

    fn input_item(&mut self, item: &Value) {
        let id = item.get("call_id").or_else(|| item.get("id"));
        match item.get("type").and_then(Value::as_str) {
            Some("function_call") => self.history(id, item.get("name"), item.get("arguments")),
            Some("function_call_output") => self.result(item.get("call_id"), item.get("output")),
            _ => {}
        }
    }

    fn history(&mut self, id: Option<&Value>, name: Option<&Value>, args: Option<&Value>) {
        let id = match id {
            None | Some(Value::Null) => None,
            Some(v) => match self.label(Some(v)) {
                Some(id) => Some(id),
                None => return,
            },
        };
        let (Some(name), Some(arguments_hash)) = (self.label(name), self.digest(args)) else {
            return;
        };
        if self.room(self.report.history.len()) {
            self.report.history.push(ToolCall {
                choice: 0,
                id,
                name,
                arguments_hash,
            });
        }
    }

    fn result(&mut self, id: Option<&Value>, content: Option<&Value>) {
        let (Some(id), Some(content_hash)) = (self.label(id), self.digest(content)) else {
            return;
        };
        if self.room(self.report.results.len()) {
            self.report.results.push(ToolResult { id, content_hash });
        }
    }

    /// A non-empty string within [`MAX_LABEL`]; anything else marks the
    /// report incomplete.
    fn label(&mut self, v: Option<&Value>) -> Option<String> {
        let s = v
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= MAX_LABEL);
        self.report.incomplete |= s.is_none();
        s.map(str::to_string)
    }

    fn digest(&mut self, v: Option<&Value>) -> Option<String> {
        let d = value_digest(v);
        self.report.incomplete |= d.is_none();
        d
    }

    fn room(&mut self, len: usize) -> bool {
        let ok = len < MAX_CALLS;
        self.report.incomplete |= !ok;
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn h(s: &str) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(s.as_bytes())))
    }

    fn hist(id: &str, name: &str, args: &str) -> ToolCall {
        ToolCall {
            choice: 0,
            id: Some(id.to_string()),
            name: name.to_string(),
            arguments_hash: h(args),
        }
    }

    fn res(id: &str, content: &str) -> ToolResult {
        ToolResult {
            id: id.to_string(),
            content_hash: h(content),
        }
    }

    const CHAT_TURN_2: &str = r#"{"model":"m","tools":[
        {"type":"function","function":{"name":"get_weather","parameters":{}}},
        {"type":"function","function":{"name":"send_email"}}],
      "messages":[
        {"role":"user","content":"weather in Paris, then mail it"},
        {"role":"assistant","content":null,"tool_calls":[
          {"id":"call_a","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]},
        {"role":"tool","tool_call_id":"call_a","content":"18C, sunny"}]}"#;

    #[test]
    fn chat_request_indexes_offered_tools_history_and_results() {
        let r = extract_request(CHAT_TURN_2.as_bytes());
        assert!(!r.incomplete, "{r:?}");
        assert_eq!(r.offered, vec!["get_weather", "send_email"]);
        assert_eq!(
            r.history,
            vec![hist("call_a", "get_weather", r#"{"city":"Paris"}"#)]
        );
        assert_eq!(r.results, vec![res("call_a", "18C, sunny")]);
    }

    #[test]
    fn history_digest_equals_the_response_side_digest_of_the_same_call() {
        let response = r#"{"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[
          {"id":"call_a","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]}}]}"#;
        let issued = crate::tool_calls::extract(response.as_bytes()).calls;
        assert_eq!(extract_request(CHAT_TURN_2.as_bytes()).history, issued);
    }

    #[test]
    fn responses_api_input_items_are_indexed() {
        let body = r#"{"model":"m","tools":[{"type":"function","name":"lookup"},{"type":"web_search"}],
          "input":[{"role":"user","content":"hi"},
            {"type":"function_call","id":"fc_1","call_id":"call_r","name":"lookup","arguments":"{}"},
            {"type":"function_call_output","call_id":"call_r","output":"42"}]}"#;
        let r = extract_request(body.as_bytes());
        assert!(!r.incomplete, "{r:?}");
        assert_eq!(r.offered, vec!["lookup"]);
        assert_eq!(r.history, vec![hist("call_r", "lookup", "{}")]);
        assert_eq!(r.results, vec![res("call_r", "42")]);
    }

    #[test]
    fn structured_result_content_is_hashed_as_jcs() {
        let body = r#"{"messages":[{"role":"tool","tool_call_id":"c","content":[{"type":"text","text":"ok"}]}]}"#;
        let r = extract_request(body.as_bytes());
        assert_eq!(
            r.results,
            vec![res("c", r#"[{"text":"ok","type":"text"}]"#)]
        );
    }

    #[test]
    fn plain_prompts_and_non_json_bodies_yield_nothing() {
        for body in [
            r#"{"messages":[{"role":"user","content":"hello"}]}"#,
            "prompt=hello",
            "",
            "[1,2]",
        ] {
            let r = extract_request(body.as_bytes());
            assert!(r.is_empty() && !r.incomplete, "{body}: {r:?}");
        }
    }

    #[test]
    fn unlinkable_or_unreadable_requests_are_flagged_not_guessed() {
        let cases = [
            r#"{"messages":[{"role":"tool","content":"no id"}]}"#,
            r#"{"messages":[{"role":"function","name":"f","content":"legacy"}]}"#,
            r#"{"messages":[{"role":"tool","tool_call_id":"c","content":{"x":1.5}}]}"#,
            r#"{"messages":[ truncated"#,
        ];
        for body in cases {
            let r = extract_request(body.as_bytes());
            assert!(r.incomplete && r.results.is_empty(), "{body}: {r:?}");
        }
        let gz = extract_request_encoded(CHAT_TURN_2.as_bytes(), Some("gzip"));
        assert!(gz.incomplete && gz.is_empty());
        let id = extract_request_encoded(CHAT_TURN_2.as_bytes(), Some("identity"));
        assert_eq!(id, extract_request(CHAT_TURN_2.as_bytes()));
    }

    #[test]
    fn oversized_lists_are_capped_and_flagged() {
        let msgs: Vec<String> = (0..=MAX_CALLS)
            .map(|i| format!(r#"{{"role":"tool","tool_call_id":"c{i}","content":"r"}}"#))
            .collect();
        let body = format!(r#"{{"messages":[{}]}}"#, msgs.join(","));
        let r = extract_request(body.as_bytes());
        assert!(r.incomplete);
        assert_eq!(r.results.len(), MAX_CALLS);
    }
}
