//! What a tool server was asked and what it answered, extracted from one
//! exchange the tool boundary relays (`erebus attest-tool`): an MCP
//! `tools/call` over JSON-RPC (stdio lines, or Streamable HTTP answered as
//! JSON or SSE) or a plain HTTP tool.
//!
//! The receipt of an engine call signs what the model *asked for*
//! (`tool_calls[].arguments_jcs_hash`); the receipt of a tool call signs
//! what the tool *received and returned*. Both sides use the same canonical
//! digest of the arguments, so [`crate::tool_linkage`] can prove that a
//! requested call really reached the tool, and that the result the agent fed
//! back to the model is what the tool returned (`result_hashes`).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::tool_calls::{canonical_arguments_digest, jcs_digest, MAX_LABEL};

/// Response bodies larger than this are not parsed (invocation incomplete).
pub const MAX_TOOL_BODY: usize = 16 * 1024 * 1024;

/// One tool execution, as signed in `execution.request.tool_invocation`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInvocation {
    /// `mcp` or `http`.
    pub protocol: String,
    /// MCP tool name; absent for a plain HTTP tool (method and path say it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Canonical digest of the arguments the tool received (MCP
    /// `params.arguments`; HTTP JSON body), as `ToolCall::arguments_jcs_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments_jcs_hash: Option<String>,
    /// Digests of the result in each form an agent may relay it to the model
    /// verbatim (see the spec, §3.4). Empty when no result was seen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub result_hashes: Vec<String>,
    /// The tool reported an error (JSON-RPC `error`, MCP `isError`, HTTP ≥ 400).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
    /// Part of the exchange could not be read: fields may be missing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub incomplete: bool,
    /// The engine call id the agent declared it was executing
    /// ([`CALL_ID_META`] / [`CALL_ID_HEADER`]). Lets the verifier tell
    /// identical calls apart and prove a call ran with altered arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
}

/// MCP `params._meta` key carrying the engine call id (reverse-DNS prefix,
/// as MCP reserves for implementation metadata).
pub const CALL_ID_META: &str = "dev.erebus/call_id";

/// HTTP request header carrying the engine call id for plain HTTP tools.
pub const CALL_ID_HEADER: &str = "Erebus-Call-Id";

/// A declared call id, if it is a usable label.
fn call_id_label(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= MAX_LABEL)
        .map(str::to_string)
}

/// `sha256:` of raw bytes.
fn raw_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Digests of a result as relayed to the model: raw bytes, plus JCS when JSON.
pub fn relayed_result_hashes(content: &[u8]) -> Vec<String> {
    let mut hashes = vec![raw_digest(content)];
    if let Ok(v) = serde_json::from_slice::<Value>(content) {
        if let Some(h) = jcs_digest(&v) {
            hashes.push(h);
        }
    }
    hashes.dedup();
    hashes
}

/// In-process tool execution for `erebus agent run`: same `tool_invocation`
/// digests as [`from_http_exchange`] / MCP attach, without a proxy boundary.
/// Prefer this over spawning `erebus attest-tool` per call.
pub fn from_agent_execution(
    protocol: &str,
    name: &str,
    arguments: Option<&Value>,
    content: &[u8],
    call_id: Option<&str>,
    mcp_result: Option<&Value>,
) -> ToolInvocation {
    let arguments_jcs_hash = canonical_arguments_digest(arguments);
    let incomplete = arguments_jcs_hash.is_none();
    let mut result_hashes = match mcp_result {
        Some(result) => mcp_result_hashes(result),
        None => relayed_result_hashes(content),
    };
    // Always cover the exact bytes the agent feeds back (text join for MCP).
    let relayed = raw_digest(content);
    if !result_hashes.contains(&relayed) {
        result_hashes.push(relayed);
    }
    ToolInvocation {
        protocol: protocol.to_string(),
        name: Some(name.to_string()).filter(|n| !n.is_empty() && n.len() <= MAX_LABEL),
        arguments_jcs_hash,
        result_hashes,
        is_error: false,
        incomplete,
        call_id: call_id_label(call_id),
    }
}

fn parse_object(bytes: &[u8]) -> Option<Value> {
    let first = bytes.iter().find(|b| !b.is_ascii_whitespace())?;
    if *first != b'{' || bytes.len() > MAX_TOOL_BODY {
        return None;
    }
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .filter(Value::is_object)
}

/// `true` when `body` is a JSON-RPC message (MCP speaks nothing else).
pub fn is_json_rpc(body: &[u8]) -> bool {
    parse_object(body).is_some_and(|v| v.get("jsonrpc").is_some())
}

/// An MCP `tools/call` request: its JSON-RPC id and the invocation so far.
/// `None` for any other message (`initialize`, `tools/list`, notifications).
pub fn mcp_tool_call(request: &[u8]) -> Option<(Value, ToolInvocation)> {
    let v = parse_object(request)?;
    if v.get("method").and_then(Value::as_str) != Some("tools/call") {
        return None;
    }
    let id = v.get("id").filter(|id| !id.is_null())?.clone();
    let params = v.get("params");
    let name = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .filter(|n| !n.is_empty() && n.len() <= MAX_LABEL);
    let arguments_jcs_hash = canonical_arguments_digest(params.and_then(|p| p.get("arguments")));
    let call_id = params
        .and_then(|p| p.get("_meta"))
        .and_then(|m| m.get(CALL_ID_META))
        .and_then(Value::as_str);
    let invocation = ToolInvocation {
        protocol: "mcp".to_string(),
        incomplete: name.is_none() || arguments_jcs_hash.is_none(),
        name: name.map(str::to_string),
        arguments_jcs_hash,
        call_id: call_id_label(call_id),
        ..ToolInvocation::default()
    };
    Some((id, invocation))
}

/// Fill `invocation` from the JSON-RPC response with `id` found in `body`
/// (a JSON document or an SSE stream of them); incomplete when absent.
pub fn mcp_attach_response(invocation: &mut ToolInvocation, id: &Value, body: &[u8]) {
    let found = json_rpc_messages(body).into_iter().find(|m| {
        m.get("id") == Some(id) && (m.get("result").is_some() || m.get("error").is_some())
    });
    let Some(message) = found else {
        invocation.incomplete = true;
        return;
    };
    if let Some(error) = message.get("error") {
        invocation.is_error = true;
        invocation.result_hashes = jcs_digest(error).into_iter().collect();
        return;
    }
    let result = message.get("result").unwrap_or(&Value::Null);
    invocation.is_error = result.get("isError").and_then(Value::as_bool) == Some(true);
    invocation.result_hashes = mcp_result_hashes(result);
    invocation.incomplete |= invocation.result_hashes.is_empty();
}

/// The forms an MCP client hands a result to the model in: the result
/// object, its `content` list or `structuredContent` (JCS), or the text of
/// an all-text `content` joined by `\n` (raw bytes).
fn mcp_result_hashes(result: &Value) -> Vec<String> {
    let mut hashes: Vec<String> = [
        Some(result),
        result.get("content"),
        result.get("structuredContent"),
    ]
    .into_iter()
    .flatten()
    .filter_map(jcs_digest)
    .collect();
    let texts: Option<Vec<&str>> = result
        .get("content")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|i| match i.get("type").and_then(Value::as_str) {
                    Some("text") => i.get("text").and_then(Value::as_str),
                    _ => None,
                })
                .collect()
        })
        .and_then(|t: Vec<Option<&str>>| t.into_iter().collect());
    if let Some(texts) = texts.filter(|t| !t.is_empty()) {
        hashes.push(raw_digest(texts.join("\n").as_bytes()));
    }
    hashes.dedup();
    hashes
}

/// JSON-RPC messages carried by a body: one JSON object or array, or the
/// `data:` payloads of an SSE stream.
pub fn json_rpc_messages(body: &[u8]) -> Vec<Value> {
    if body.len() > MAX_TOOL_BODY {
        return Vec::new();
    }
    let first = body.iter().find(|b| !b.is_ascii_whitespace());
    if matches!(first, Some(b'{' | b'[')) {
        return match serde_json::from_slice::<Value>(body) {
            Ok(Value::Array(items)) => items,
            Ok(v) => vec![v],
            Err(_) => Vec::new(),
        };
    }
    sse_payloads(body)
        .iter()
        .filter_map(|p| serde_json::from_slice::<Value>(p).ok())
        .collect()
}

fn sse_payloads(body: &[u8]) -> Vec<Vec<u8>> {
    let mut events = Vec::new();
    let mut data: Option<Vec<u8>> = None;
    for line in body.split(|b| *b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            events.extend(data.take());
        } else if let Some(v) = line.strip_prefix(b"data:") {
            let v = v.strip_prefix(b" ").unwrap_or(v);
            let d = data.get_or_insert_with(Vec::new);
            if !d.is_empty() {
                d.push(b'\n');
            }
            d.extend_from_slice(v);
        }
    }
    events.extend(data);
    events
}

/// A plain HTTP tool: arguments are the JSON request body (`{}` when
/// empty), the result the response body (raw bytes, and JCS when JSON).
/// `response` is `None` when the body could not be kept whole.
pub fn http_invocation(
    request: &[u8],
    response: Option<&[u8]>,
    status: Option<u16>,
) -> ToolInvocation {
    let arguments_jcs_hash = if request.iter().all(u8::is_ascii_whitespace) {
        canonical_arguments_digest(None)
    } else {
        serde_json::from_slice::<Value>(request)
            .ok()
            .and_then(|v| canonical_arguments_digest(Some(&v)))
    };
    let mut result_hashes = Vec::new();
    if let Some(body) = response {
        result_hashes.push(raw_digest(body));
        if let Some(v) = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| jcs_digest(&v))
        {
            result_hashes.push(v);
        }
        result_hashes.dedup();
    }
    ToolInvocation {
        protocol: "http".to_string(),
        name: None,
        arguments_jcs_hash,
        is_error: status.is_none_or(|s| s >= 400),
        incomplete: response.is_none(),
        result_hashes,
        call_id: None,
    }
}

/// One HTTP exchange in front of a tool, as the boundary relayed it.
pub struct HttpExchange<'a> {
    pub request: &'a [u8],
    pub response: Option<&'a [u8]>,
    pub status: Option<u16>,
    /// Value of the [`CALL_ID_HEADER`] request header.
    pub call_id_header: Option<&'a str>,
}

/// The invocation of one HTTP exchange in front of a tool: MCP when the
/// request is JSON-RPC (`None` unless it is a `tools/call`), plain HTTP
/// otherwise. An MCP `_meta` call id wins over the header.
pub fn from_http_exchange(x: &HttpExchange<'_>) -> Option<ToolInvocation> {
    let mut invocation = if is_json_rpc(x.request) {
        let (id, mut inv) = mcp_tool_call(x.request)?;
        match x.response {
            Some(body) => mcp_attach_response(&mut inv, &id, body),
            None => inv.incomplete = true,
        }
        inv
    } else {
        http_invocation(x.request, x.response, x.status)
    };
    if invocation.call_id.is_none() {
        invocation.call_id = call_id_label(x.call_id_header);
    }
    Some(invocation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> String {
        raw_digest(s.as_bytes())
    }

    fn from_http_exchange(
        request: &[u8],
        response: Option<&[u8]>,
        status: Option<u16>,
    ) -> Option<ToolInvocation> {
        super::from_http_exchange(&HttpExchange {
            request,
            response,
            status,
            call_id_header: None,
        })
    }

    #[test]
    fn the_declared_call_id_is_signed_from_mcp_meta_or_the_header() {
        let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"Paris"},"_meta":{"dev.erebus/call_id":"call_w"}}}"#;
        let mcp = super::from_http_exchange(&HttpExchange {
            request: call.as_bytes(),
            response: Some(RESULT.as_bytes()),
            status: Some(200),
            call_id_header: Some("ignored"),
        })
        .unwrap();
        assert_eq!(mcp.call_id.as_deref(), Some("call_w"), "_meta wins");
        let http = super::from_http_exchange(&HttpExchange {
            request: br#"{"to":"ops"}"#,
            response: Some(b"queued"),
            status: Some(200),
            call_id_header: Some(" call_e "),
        })
        .unwrap();
        assert_eq!(http.call_id.as_deref(), Some("call_e"));
        let blank = from_http_exchange(CALL.as_bytes(), Some(RESULT.as_bytes()), Some(200));
        assert_eq!(blank.unwrap().call_id, None);
        let json = serde_json::to_value(&http).unwrap();
        assert_eq!(json["call_id"], "call_e", "signed in the invocation");
    }

    const CALL: &str = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"Paris"}}}"#;
    const RESULT: &str = r#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"type":"text","text":"18C"},{"type":"text","text":"sunny"}],"isError":false}}"#;

    #[test]
    fn mcp_tools_call_is_matched_to_its_response_json_or_sse() {
        let model_side = canonical_arguments_digest(Some(&Value::from(r#"{"city": "Paris"}"#)));
        for body in [
            RESULT.to_string(),
            format!("event: message\ndata: {RESULT}\n\n"),
        ] {
            let inv =
                from_http_exchange(CALL.as_bytes(), Some(body.as_bytes()), Some(200)).unwrap();
            assert_eq!(inv.protocol, "mcp");
            assert_eq!(inv.name.as_deref(), Some("get_weather"));
            assert_eq!(
                inv.arguments_jcs_hash, model_side,
                "same digest as the model's call"
            );
            assert!(!inv.is_error && !inv.incomplete, "{inv:?}");
            assert!(inv.result_hashes.contains(&h("18C\nsunny")), "{inv:?}");
            let content =
                serde_json::json!([{"type":"text","text":"18C"},{"type":"text","text":"sunny"}]);
            assert!(inv.result_hashes.contains(&jcs_digest(&content).unwrap()));
        }
    }

    #[test]
    fn other_mcp_messages_are_not_tool_invocations() {
        for msg in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}"#,
        ] {
            assert_eq!(
                from_http_exchange(msg.as_bytes(), Some(b"{}"), Some(200)),
                None,
                "{msg}"
            );
        }
    }

    #[test]
    fn errors_and_missing_answers_are_flagged() {
        let err = r#"{"jsonrpc":"2.0","id":7,"error":{"code":-32602,"message":"bad"}}"#;
        let inv = from_http_exchange(CALL.as_bytes(), Some(err.as_bytes()), Some(200)).unwrap();
        assert!(inv.is_error && !inv.incomplete);
        let tool_err = r#"{"jsonrpc":"2.0","id":7,"result":{"content":[],"isError":true}}"#;
        assert!(
            from_http_exchange(CALL.as_bytes(), Some(tool_err.as_bytes()), Some(200))
                .unwrap()
                .is_error
        );
        let other_id = RESULT.replace("\"id\":7", "\"id\":8");
        let inv =
            from_http_exchange(CALL.as_bytes(), Some(other_id.as_bytes()), Some(200)).unwrap();
        assert!(inv.incomplete && inv.result_hashes.is_empty());
        assert!(
            from_http_exchange(CALL.as_bytes(), None, Some(200))
                .unwrap()
                .incomplete
        );
    }

    #[test]
    fn agent_execution_covers_relayed_bytes_and_call_id() {
        let args = serde_json::json!({"text": "pong"});
        let content = br#"{"text":"pong"}"#;
        let inv = from_agent_execution("http", "echo", Some(&args), content, Some("call_1"), None);
        assert_eq!(inv.protocol, "http");
        assert_eq!(inv.name.as_deref(), Some("echo"));
        assert_eq!(inv.call_id.as_deref(), Some("call_1"));
        assert_eq!(
            inv.arguments_jcs_hash,
            canonical_arguments_digest(Some(&args))
        );
        assert!(inv.result_hashes.contains(&h(r#"{"text":"pong"}"#)));
    }

    #[test]
    fn plain_http_tools_hash_the_json_body_and_the_answer() {
        let inv = from_http_exchange(br#"{ "city" : "Paris" }"#, Some(br#"{"t": 18}"#), Some(200))
            .unwrap();
        assert_eq!(inv.protocol, "http");
        assert_eq!(inv.name, None);
        assert_eq!(
            inv.arguments_jcs_hash,
            canonical_arguments_digest(Some(&serde_json::json!({"city": "Paris"})))
        );
        assert_eq!(inv.result_hashes, vec![h(r#"{"t": 18}"#), h(r#"{"t":18}"#)]);
        let get = from_http_exchange(b"", Some(b"plain"), Some(503)).unwrap();
        assert_eq!(get.arguments_jcs_hash, canonical_arguments_digest(None));
        assert!(get.is_error);
        assert_eq!(get.result_hashes, vec![h("plain")]);
    }
}
