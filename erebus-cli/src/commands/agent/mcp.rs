//! Minimal MCP client for `erebus agent run`: stdio and Streamable HTTP.
//!
//! Discovers tools via `tools/list` and executes `tools/call`. Prefer this over
//! inventing a parallel tool system; pair with `erebus attest-tool` for a
//! signed tool boundary when you need chain verification.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

/// One connected MCP server (stdio child or HTTP endpoint).
pub struct McpClient {
    transport: Transport,
    next_id: AtomicU64,
    /// OpenAI-shaped tool schemas discovered from this server.
    pub tools: Vec<Value>,
    /// Tool names owned by this server (for routing).
    pub names: Vec<String>,
}

enum Transport {
    Stdio {
        child: Child,
        stdin: ChildStdin,
        stdout: BufReader<ChildStdout>,
    },
    Http {
        url: String,
    },
}

impl McpClient {
    /// Spawn `cmd[0]` with `cmd[1..]` over stdio JSON-RPC.
    pub fn connect_stdio(cmd: &[String]) -> Result<Self> {
        if cmd.is_empty() {
            bail!("--mcp-stdio needs a command");
        }
        let mut child = Command::new(&cmd[0])
            .args(&cmd[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("cannot start MCP server {}", cmd[0]))?;
        let stdin = child.stdin.take().context("MCP stdin")?;
        let stdout = BufReader::new(child.stdout.take().context("MCP stdout")?);
        let mut client = Self {
            transport: Transport::Stdio {
                child,
                stdin,
                stdout,
            },
            next_id: AtomicU64::new(1),
            tools: Vec::new(),
            names: Vec::new(),
        };
        client.handshake_and_list()?;
        Ok(client)
    }

    /// Streamable HTTP MCP endpoint (JSON or SSE answers).
    pub fn connect_http(url: &str) -> Result<Self> {
        let mut client = Self {
            transport: Transport::Http {
                url: url.trim().trim_end_matches('/').to_string(),
            },
            next_id: AtomicU64::new(1),
            tools: Vec::new(),
            names: Vec::new(),
        };
        client.handshake_and_list()?;
        Ok(client)
    }

    fn handshake_and_list(&mut self) -> Result<()> {
        let _ = self.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "erebus-agent", "version": env!("CARGO_PKG_VERSION")},
            }),
        )?;
        // Best-effort notification; some servers ignore it.
        let _ = self.notify("notifications/initialized", json!({}));
        let listed = self.request("tools/list", json!({}))?;
        let tools = listed
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for t in &tools {
            let name = t
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            self.names.push(name.clone());
            self.tools.push(json!({
                "type": "function",
                "function": {
                    "name": name,
                    "description": t.get("description").cloned().unwrap_or(json!("")),
                    "parameters": t.get("inputSchema").cloned()
                        .unwrap_or(json!({"type": "object", "properties": {}})),
                }
            }));
        }
        Ok(())
    }

    /// Call an MCP tool; return text for the model (joined content blocks).
    pub fn call_tool(&mut self, name: &str, arguments: &Value) -> Result<String> {
        let result = self.request("tools/call", json!({"name": name, "arguments": arguments}))?;
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            bail!("MCP tool {name:?} reported isError: {result}");
        }
        Ok(mcp_result_text(&result))
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id();
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        match &mut self.transport {
            Transport::Stdio { stdin, stdout, .. } => {
                writeln!(stdin, "{msg}").context("write MCP request")?;
                stdin.flush()?;
                read_stdio_response(stdout, id)
            }
            Transport::Http { url } => http_rpc(url, &msg, id),
        }
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        let msg = json!({"jsonrpc": "2.0", "method": method, "params": params});
        match &mut self.transport {
            Transport::Stdio { stdin, .. } => {
                writeln!(stdin, "{msg}")?;
                stdin.flush()?;
                Ok(())
            }
            Transport::Http { url } => {
                // Notifications may return 202; ignore body.
                let _ = http_post_raw(url, &msg)?;
                Ok(())
            }
        }
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        if let Transport::Stdio { child, .. } = &mut self.transport {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn mcp_result_text(result: &Value) -> String {
    if let Some(items) = result.get("content").and_then(Value::as_array) {
        let texts: Vec<&str> = items
            .iter()
            .filter_map(|i| {
                (i.get("type").and_then(Value::as_str) == Some("text"))
                    .then(|| i.get("text").and_then(Value::as_str))
                    .flatten()
            })
            .collect();
        if !texts.is_empty() {
            return texts.join("\n");
        }
    }
    result.to_string()
}

fn read_stdio_response(stdout: &mut BufReader<ChildStdout>, id: u64) -> Result<Value> {
    let mut line = String::new();
    for _ in 0..64 {
        line.clear();
        if stdout.read_line(&mut line)? == 0 {
            bail!("MCP server closed stdout waiting for id={id}");
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(trimmed).context("MCP stdio JSON")?;
        if v.get("id").and_then(Value::as_u64) == Some(id)
            || v.get("id").and_then(Value::as_i64) == Some(id as i64)
        {
            if let Some(err) = v.get("error") {
                bail!("MCP JSON-RPC error: {err}");
            }
            return v
                .get("result")
                .cloned()
                .context("MCP response missing result");
        }
    }
    bail!("MCP server did not answer id={id}")
}

fn http_rpc(url: &str, msg: &Value, id: u64) -> Result<Value> {
    let (status, body) = http_post_raw(url, msg)?;
    if !(200..300).contains(&status) {
        bail!(
            "MCP HTTP {status}: {}",
            String::from_utf8_lossy(&body)
                .chars()
                .take(300)
                .collect::<String>()
        );
    }
    let messages = erebus_core::tool_exec::json_rpc_messages(&body);
    let found = messages.into_iter().find(|m| {
        m.get("id").and_then(Value::as_u64) == Some(id)
            || m.get("id").and_then(Value::as_i64) == Some(id as i64)
    });
    let Some(v) = found else {
        // Single JSON object response.
        let v: Value = serde_json::from_slice(&body).context("MCP HTTP JSON")?;
        if let Some(err) = v.get("error") {
            bail!("MCP JSON-RPC error: {err}");
        }
        return v
            .get("result")
            .cloned()
            .context("MCP HTTP response missing result");
    };
    if let Some(err) = v.get("error") {
        bail!("MCP JSON-RPC error: {err}");
    }
    v.get("result")
        .cloned()
        .context("MCP HTTP response missing result")
}

fn http_post_raw(url: &str, msg: &Value) -> Result<(u16, Vec<u8>)> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("MCP HTTP client")?;
    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .json(msg)
        .send()
        .with_context(|| format!("MCP POST {url}"))?;
    let status = resp.status().as_u16();
    let bytes = resp.bytes()?.to_vec();
    Ok((status, bytes))
}

/// Parse `--mcp-stdio` SPEC: JSON array, or whitespace-separated tokens.
pub fn parse_stdio_spec(spec: &str) -> Result<Vec<String>> {
    let s = spec.trim();
    if s.starts_with('[') {
        let arr: Vec<String> =
            serde_json::from_str(s).context("--mcp-stdio JSON array of strings")?;
        if arr.is_empty() {
            bail!("--mcp-stdio JSON array is empty");
        }
        return Ok(arr);
    }
    let parts: Vec<String> = s.split_whitespace().map(str::to_string).collect();
    if parts.is_empty() {
        bail!("--mcp-stdio needs a command");
    }
    Ok(parts)
}

/// Open all configured MCP servers; merge tools (first wins on name clash).
pub fn open_servers(http_urls: &[String], stdio_specs: &[String]) -> Result<Vec<McpClient>> {
    let mut clients = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for url in http_urls {
        let c = McpClient::connect_http(url).with_context(|| format!("MCP HTTP {url}"))?;
        register_names(&mut seen, &c.names, url)?;
        clients.push(c);
    }
    for spec in stdio_specs {
        let cmd = parse_stdio_spec(spec)?;
        let label = cmd.join(" ");
        let c = McpClient::connect_stdio(&cmd).with_context(|| format!("MCP stdio {label}"))?;
        register_names(&mut seen, &c.names, &label)?;
        clients.push(c);
    }
    Ok(clients)
}

fn register_names(
    seen: &mut std::collections::HashSet<String>,
    names: &[String],
    label: &str,
) -> Result<()> {
    for n in names {
        if !seen.insert(n.clone()) {
            bail!("MCP tool name {n:?} duplicated (from {label})");
        }
    }
    Ok(())
}

/// Route `name` to the owning client and call it.
pub fn call_named(clients: &mut [McpClient], name: &str, arguments_json: &str) -> Result<String> {
    let args: Value = serde_json::from_str(arguments_json).unwrap_or(json!({}));
    for c in clients.iter_mut() {
        if c.names.iter().any(|n| n == name) {
            return c.call_tool(name, &args);
        }
    }
    bail!("no MCP server owns tool {name:?}")
}

/// Collect `OpenAI` tool schemas from all clients.
pub fn collect_tools(clients: &[McpClient]) -> Vec<Value> {
    clients.iter().flat_map(|c| c.tools.clone()).collect()
}

/// Resolve a program on PATH (for docs / encapsulate helpers).
#[allow(dead_code)]
pub fn resolve_on_path(cmd: &str) -> Option<PathBuf> {
    let direct = std::path::Path::new(cmd);
    if direct.components().count() > 1 {
        return direct.is_file().then(|| direct.to_path_buf());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(cmd))
        .find(|p| p.is_file())
}
