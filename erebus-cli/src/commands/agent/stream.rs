//! SSE streaming helpers for OpenAI-compatible and Anthropic providers.
//!
//! Tokens may be printed for UX while the stream is open. The attested receipt
//! always hashes the **assembled final JSON body** (same digests as a
//! non-streaming turn / `serve`), never mid-stream fragments.

use std::io::{BufRead, Write};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Map, Value};

/// Printed once when `--stream` is on (stderr). Not a crypto claim.
pub const STREAM_LIMIT: &str = "[erebus] streaming display is unsigned; the receipt hashes \
the assembled final response body (same digests as a non-stream turn).";

/// POST with optional SSE; returns (status, assembled body bytes, streamed text).
pub fn http_post_maybe_stream(
    url: &str,
    body: &[u8],
    bearer: Option<&str>,
    headers: &[(&str, &str)],
    stream: bool,
    assemble: AssembleKind,
) -> Result<(u16, Vec<u8>, String)> {
    if !stream {
        let (status, bytes) = super::http_post(url, body, bearer, headers)?;
        return Ok((status, bytes, String::new()));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .context("http client")?;
    let mut req = client.post(url).body(body.to_vec());
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    if let Some(token) = bearer {
        req = req.bearer_auth(token);
    }
    let resp = req.send().with_context(|| format!("POST {url}"))?;
    let status = resp.status().as_u16();
    if !(200..300).contains(&status) {
        let bytes = resp.bytes()?.to_vec();
        let preview: String = String::from_utf8_lossy(&bytes).chars().take(400).collect();
        bail!("provider HTTP {status}: {preview}");
    }
    let ctype = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !ctype.contains("text/event-stream") && !ctype.contains("event-stream") {
        // Provider ignored stream=true — treat as normal JSON.
        let bytes = resp.bytes()?.to_vec();
        return Ok((status, bytes, String::new()));
    }
    let reader = std::io::BufReader::new(resp);
    match assemble {
        AssembleKind::Openai => assemble_openai_sse(reader, status),
        AssembleKind::Anthropic => assemble_anthropic_sse(reader, status),
    }
}

#[derive(Clone, Copy)]
pub enum AssembleKind {
    Openai,
    Anthropic,
}

fn assemble_openai_sse<R: BufRead>(reader: R, status: u16) -> Result<(u16, Vec<u8>, String)> {
    let mut content = String::new();
    let mut tool_calls: Map<String, Value> = Map::new();
    let mut role = "assistant".to_string();
    // Stop at [DONE] — do not wait for EOF (HTTP/1.1 keep-alive would hang).
    for payload in SseDataIter::new(reader) {
        let payload = payload?;
        if payload.trim() == "[DONE]" {
            break;
        }
        let chunk: Value = match serde_json::from_str(&payload) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(choice) = chunk
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        else {
            continue;
        };
        if let Some(delta) = choice.get("delta") {
            if let Some(r) = delta.get("role").and_then(Value::as_str) {
                role = r.to_string();
            }
            if let Some(t) = delta.get("content").and_then(Value::as_str) {
                content.push_str(t);
                stream_print(t);
            }
            if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
                merge_openai_tool_deltas(&mut tool_calls, tcs);
            }
        }
    }
    let mut message = json!({"role": role, "content": if content.is_empty() { Value::Null } else { json!(content) }});
    if !tool_calls.is_empty() {
        let mut list: Vec<(usize, Value)> = tool_calls
            .into_iter()
            .filter_map(|(k, v)| k.parse::<usize>().ok().map(|i| (i, v)))
            .collect();
        list.sort_by_key(|(i, _)| *i);
        message["tool_calls"] = Value::Array(list.into_iter().map(|(_, v)| v).collect());
        message["content"] = Value::Null;
    }
    let assembled = json!({
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "object": "chat.completion",
    });
    let bytes = serde_json::to_vec(&assembled)?;
    Ok((status, bytes, content))
}

fn merge_openai_tool_deltas(map: &mut Map<String, Value>, tcs: &[Value]) {
    for tc in tcs {
        let idx = tc
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .to_string();
        let entry = map.entry(idx).or_insert_with(|| {
            json!({
                "id": "",
                "type": "function",
                "function": {"name": "", "arguments": ""}
            })
        });
        if let Some(id) = tc.get("id").and_then(Value::as_str) {
            if !id.is_empty() {
                entry["id"] = json!(id);
            }
        }
        if let Some(f) = tc.get("function") {
            if let Some(n) = f.get("name").and_then(Value::as_str) {
                if !n.is_empty() {
                    entry["function"]["name"] = json!(n);
                }
            }
            if let Some(a) = f.get("arguments").and_then(Value::as_str) {
                let cur = entry["function"]["arguments"]
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                entry["function"]["arguments"] = json!(format!("{cur}{a}"));
            }
        }
    }
}

fn assemble_anthropic_sse<R: BufRead>(reader: R, status: u16) -> Result<(u16, Vec<u8>, String)> {
    let mut content_blocks: Vec<Value> = Vec::new();
    let mut text_acc = String::new();
    let mut tool_json: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    let mut model = String::new();
    let mut stop_reason = Value::Null;

    for payload in SseDataIter::new(reader) {
        let payload = payload?;
        let ev: Value = match serde_json::from_str(&payload) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ev_type = ev.get("type").and_then(Value::as_str);
        if ev_type == Some("message_stop") {
            break;
        }
        match ev_type {
            Some("message_start") => {
                if let Some(m) = ev.pointer("/message/model").and_then(Value::as_str) {
                    model = m.to_string();
                }
            }
            Some("content_block_start") => {
                let idx = ev.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let block = ev.get("content_block").cloned().unwrap_or(json!({}));
                while content_blocks.len() <= idx {
                    content_blocks.push(json!({"type": "text", "text": ""}));
                }
                content_blocks[idx] = block;
                if content_blocks[idx].get("type").and_then(Value::as_str) == Some("tool_use") {
                    tool_json.insert(idx, String::new());
                }
            }
            Some("content_block_delta") => {
                let idx = ev.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let delta = ev.get("delta").cloned().unwrap_or(json!({}));
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(t) = delta.get("text").and_then(Value::as_str) {
                            text_acc.push_str(t);
                            stream_print(t);
                            if let Some(block) = content_blocks.get_mut(idx) {
                                let cur = block.get("text").and_then(Value::as_str).unwrap_or("");
                                block["text"] = json!(format!("{cur}{t}"));
                            }
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some(p) = delta.get("partial_json").and_then(Value::as_str) {
                            tool_json.entry(idx).or_default().push_str(p);
                        }
                    }
                    _ => {}
                }
            }
            Some("content_block_stop") => {
                let idx = ev.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                if let Some(raw) = tool_json.remove(&idx) {
                    if let Ok(parsed) = serde_json::from_str::<Value>(&raw) {
                        if let Some(block) = content_blocks.get_mut(idx) {
                            block["input"] = parsed;
                        }
                    }
                }
            }
            Some("message_delta") => {
                if let Some(sr) = ev.pointer("/delta/stop_reason") {
                    stop_reason = sr.clone();
                }
            }
            _ => {}
        }
    }

    let assembled = json!({
        "id": "msg_stream",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content_blocks,
        "stop_reason": stop_reason,
    });
    let bytes = serde_json::to_vec(&assembled)?;
    Ok((status, bytes, text_acc))
}

fn stream_print(text: &str) {
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "{text}");
    let _ = err.flush();
}

/// Incremental SSE `data:` payloads; yields on each blank-line-terminated event.
struct SseDataIter<R> {
    lines: std::io::Lines<R>,
    data: Option<String>,
    done: bool,
}

impl<R: BufRead> SseDataIter<R> {
    fn new(reader: R) -> Self {
        Self {
            lines: reader.lines(),
            data: None,
            done: false,
        }
    }
}

impl<R: BufRead> Iterator for SseDataIter<R> {
    type Item = Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            match self.lines.next() {
                None => {
                    self.done = true;
                    return self.data.take().map(Ok);
                }
                Some(Err(e)) => {
                    self.done = true;
                    return Some(Err(e).context("read SSE"));
                }
                Some(Ok(line)) => {
                    if line.is_empty() {
                        if let Some(d) = self.data.take() {
                            return Some(Ok(d));
                        }
                        continue;
                    }
                    if let Some(rest) = line.strip_prefix("data:") {
                        let v = rest.strip_prefix(' ').unwrap_or(rest);
                        match &mut self.data {
                            Some(buf) => {
                                buf.push('\n');
                                buf.push_str(v);
                            }
                            None => self.data = Some(v.to_string()),
                        }
                    }
                }
            }
        }
    }
}
