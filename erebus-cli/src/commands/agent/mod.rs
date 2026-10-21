//! `erebus agent` — provider-agnostic HTTP agent runner with attested receipts.
//!
//! Talks OpenAI-compatible chat completions (or Anthropic Messages) over HTTP,
//! optionally executes allowlisted tools (echo, HTTP POST, MCP stdio/HTTP) for
//! a short loop, streams tokens when asked, and appends one signed receipt per
//! model call via the same digests as `serve --attest-key`.
//!
//! The closing line always separates **execution proof** from **task success**.

mod encapsulate;
mod mcp;
mod stream;

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use serde_json::{json, Value};

use super::attest_proxy::{CallRecorder, CallSummary, ReceiptPublisher};
use erebus_core::attest::AttestationTemplate;
use erebus_core::attest_log::AttestationLog;

use mcp::McpClient;
use stream::{AssembleKind, STREAM_LIMIT};

/// Printed after every successful run (stderr). Not a crypto claim.
pub const HONEST_LIMIT: &str = "Execution proven (signed receipt). Task success is a separate \
layer — tests, human approve, or golden checks — not the crypto claim of the receipt.";

#[derive(Args)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub command: AgentCommand,
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Run a short agent loop against an HTTP LLM and emit signed receipts
    ///
    /// Providers: `openai-compat` (Ollama, Azure, llama-server, vLLM, …) and
    /// `anthropic` (Messages API). Cursor is not a provider.
    ///
    /// Secrets: `--api-key-file` or `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` /
    /// `ERE_API_KEY` — never put the token on argv.
    ///
    /// Examples:
    ///   erebus agent run --provider openai-compat --base-url <http://127.0.0.1:11434> \
    ///       --model llama3.2 --task "Say hi" --attest-key ops.key
    ///   erebus agent run --mcp-stdio 'python3 server.py' --allow-mcp \
    ///       --stream --task "…" --attest-key ops.key --base-url …
    Run(Box<RunArgs>),
    /// Package the task config into a `.erebus` (receipt subject = bundle hash)
    Build(BuildCmdArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
pub enum Provider {
    /// `OpenAI`-compatible chat completions (`/v1/chat/completions`)
    #[value(name = "openai-compat")]
    OpenaiCompat,
    /// Anthropic Messages API (`/v1/messages`)
    Anthropic,
}

#[derive(Args)]
pub struct BuildCmdArgs {
    /// LLM HTTP dialect (embedded in task.json)
    #[arg(long, value_enum, default_value_t = Provider::OpenaiCompat)]
    pub provider: Provider,

    #[arg(long, env = "ERE_AGENT_BASE_URL")]
    pub base_url: String,

    #[arg(long)]
    pub model: String,

    #[arg(long)]
    pub task: String,

    /// Output `.erebus` path
    #[arg(short, long, default_value = "agent-task.erebus")]
    pub output: PathBuf,

    #[arg(long)]
    pub force: bool,

    /// Tool names recorded in the task descriptor (informational)
    #[arg(long = "allow-tool", value_name = "NAME", action = clap::ArgAction::Append)]
    pub allow_tool: Vec<String>,
}

#[derive(Args)]
pub struct RunArgs {
    /// LLM HTTP dialect
    #[arg(long, value_enum, default_value_t = Provider::OpenaiCompat)]
    pub provider: Provider,

    /// Provider base URL (`http://host:port`; `/v1` suffix optional)
    #[arg(long, env = "ERE_AGENT_BASE_URL")]
    pub base_url: String,

    /// Model id sent to the provider
    #[arg(long)]
    pub model: String,

    /// User task / prompt for this run
    #[arg(long)]
    pub task: String,

    /// Ed25519 key signing one receipt per model call
    #[arg(long, env = "ERE_ATTEST_KEY", value_name = "KEY")]
    pub attest_key: PathBuf,

    /// Trail directory (default: `./agent.run.attest.d`)
    #[arg(long, env = "ERE_ATTEST_LOG", value_name = "DIR")]
    pub attest_log: Option<PathBuf>,

    /// Subject bundle for receipts (`from_bundle`); else a descriptor hash
    #[arg(long, value_name = "FILE")]
    pub bundle: Option<PathBuf>,

    /// Build a temp `.erebus` from the task config and use it as `--bundle`
    #[arg(long)]
    pub encapsulate: bool,

    /// Output path when `--encapsulate` (default: `./agent-task.erebus`)
    #[arg(long, value_name = "FILE")]
    pub encapsulate_out: Option<PathBuf>,

    /// File holding the provider API key (preferred over env)
    #[arg(long, value_name = "FILE")]
    pub api_key_file: Option<PathBuf>,

    /// JSON file: `OpenAI` `tools` array (function tools)
    #[arg(long, value_name = "FILE")]
    pub tools_file: Option<PathBuf>,

    /// Allowlisted tool name (repeatable). Only these may execute.
    #[arg(long = "allow-tool", value_name = "NAME", action = clap::ArgAction::Append)]
    pub allow_tool: Vec<String>,

    /// Allow every tool discovered from `--mcp` / `--mcp-stdio`
    #[arg(long)]
    pub allow_mcp: bool,

    /// HTTP tool: `name=http://host:port/path` (POST arguments JSON)
    #[arg(long = "tool-http", value_name = "NAME=URL", action = clap::ArgAction::Append)]
    pub tool_http: Vec<String>,

    /// MCP Streamable HTTP endpoint (repeatable)
    #[arg(long = "mcp", value_name = "URL", action = clap::ArgAction::Append)]
    pub mcp: Vec<String>,

    /// MCP stdio server: JSON array `["cmd","arg"]` or whitespace-separated
    #[arg(long = "mcp-stdio", value_name = "SPEC", action = clap::ArgAction::Append)]
    pub mcp_stdio: Vec<String>,

    /// Stream tokens to stderr; receipt still hashes the assembled final body
    #[arg(long)]
    pub stream: bool,

    /// Max model turns (user → assistant [→ tools → …])
    #[arg(long, default_value_t = 4)]
    pub max_turns: u32,

    /// Refuse the final response when its body digest differs
    #[arg(long, value_name = "DIGEST")]
    pub expected_output_hash: Option<String>,

    /// Write the last model response body (for `verify-attest --response-body`)
    #[arg(long, value_name = "FILE")]
    pub response_body: Option<PathBuf>,

    /// Relay through a local attesting reverse proxy (cleartext HTTP upstream)
    #[arg(long)]
    pub via_proxy: bool,

    /// Publish every receipt to the registry transparency log
    #[arg(long, requires = "registry")]
    pub push: bool,

    /// Registry receiving receipts
    #[arg(long, env = "ERE_REGISTRY")]
    pub registry: Option<String>,

    /// File containing the registry bearer token (`ERE_TOKEN` otherwise)
    #[arg(long)]
    pub token_file: Option<PathBuf>,
}

struct Outcome {
    final_text: String,
    last_body: Vec<u8>,
    last_response_hash: String,
    calls: usize,
}

struct ToolCtx<'a> {
    allow: &'a HashSet<String>,
    http_tools: &'a HashMap<String, String>,
    mcp: &'a mut [McpClient],
    allow_mcp: bool,
}

pub fn run(args: AgentArgs) -> Result<()> {
    match args.command {
        AgentCommand::Run(a) => run_agent(*a),
        AgentCommand::Build(a) => run_build(a),
    }
}

fn run_build(args: BuildCmdArgs) -> Result<()> {
    let desc = encapsulate::task_descriptor(
        provider_name(args.provider),
        &args.model,
        &host_label(&args.base_url),
        &args.task,
        &args.allow_tool,
    );
    let path = encapsulate::build_task_bundle(&desc, &args.output, args.force)?;
    println!("{}", path.display());
    eprintln!(
        "[erebus] agent build: task bundle → {} (receipt subject = bundle hash)",
        path.display()
    );
    eprintln!("{HONEST_LIMIT}");
    Ok(())
}

fn run_agent(mut args: RunArgs) -> Result<()> {
    if args.max_turns == 0 {
        bail!("--max-turns must be ≥ 1");
    }
    if args.encapsulate {
        let out = args
            .encapsulate_out
            .clone()
            .unwrap_or_else(|| PathBuf::from("agent-task.erebus"));
        let desc = encapsulate::task_descriptor(
            provider_name(args.provider),
            &args.model,
            &host_label(&args.base_url),
            &args.task,
            &args.allow_tool,
        );
        let path = encapsulate::build_task_bundle(&desc, &out, true)?;
        eprintln!(
            "[erebus] agent: encapsulated task → {} (receipts will name this hash)",
            path.display()
        );
        args.bundle = Some(path);
    }

    let api_key = resolve_api_key(args.api_key_file.as_deref(), args.provider)?;
    let mut mcp_clients = mcp::open_servers(&args.mcp, &args.mcp_stdio)?;
    let mcp_tools = mcp::collect_tools(&mcp_clients);
    let mut tools = load_tools(args.tools_file.as_deref(), &args.allow_tool)?;
    merge_tools(&mut tools, mcp_tools);
    let http_tools = parse_tool_http(&args.tool_http)?;
    let allow: HashSet<String> = args.allow_tool.iter().cloned().collect();
    let recorder = build_recorder(&args)?;

    if args.stream {
        eprintln!("{STREAM_LIMIT}");
    }

    let base = normalize_base(&args.base_url);
    let (endpoint, client_records, proxy_stop) = if args.via_proxy {
        let (url, stop) = start_proxy(&base, Arc::clone(&recorder))?;
        (url, false, Some(stop))
    } else {
        (base, true, None)
    };

    let outcome = match args.provider {
        Provider::OpenaiCompat => loop_openai(
            &endpoint,
            api_key.as_deref(),
            &args,
            &tools,
            &allow,
            &http_tools,
            &mut mcp_clients,
            &recorder,
            client_records,
        )?,
        Provider::Anthropic => loop_anthropic(
            &endpoint,
            api_key.as_deref(),
            &args,
            &tools,
            &allow,
            &http_tools,
            &mut mcp_clients,
            &recorder,
            client_records,
        )?,
    };

    if let Some(stop) = proxy_stop {
        stop.store(true, Ordering::SeqCst);
    }
    // Drop MCP children before finish so trails are idle.
    drop(mcp_clients);
    finish_run(&args, &recorder, &outcome)
}

fn merge_tools(into: &mut Vec<Value>, extra: Vec<Value>) {
    let mut names: HashSet<String> = into
        .iter()
        .filter_map(|t| {
            t.pointer("/function/name")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    for t in extra {
        let name = t
            .pointer("/function/name")
            .and_then(Value::as_str)
            .unwrap_or("");
        if name.is_empty() || !names.insert(name.to_string()) {
            continue;
        }
        into.push(t);
    }
}

fn finish_run(args: &RunArgs, recorder: &CallRecorder, outcome: &Outcome) -> Result<()> {
    if let Some(path) = &args.response_body {
        std::fs::write(path, &outcome.last_body)
            .with_context(|| format!("cannot write {}", path.display()))?;
    }
    if let Some(want) = &args.expected_output_hash {
        erebus_core::attest::assert_output_hash_eq(&outcome.last_response_hash, want)?;
    }
    if args.stream {
        eprintln!();
    }
    println!("{}", outcome.final_text);
    eprintln!(
        "[erebus] agent: {} model call(s); receipts → {}",
        outcome.calls,
        recorder.log_dir().display()
    );
    eprintln!("{HONEST_LIMIT}");
    Ok(())
}

fn build_recorder(args: &RunArgs) -> Result<Arc<CallRecorder>> {
    let key = erebus_core::attest::load_signing_key(&args.attest_key)
        .with_context(|| format!("cannot load attestation key {}", args.attest_key.display()))?;
    let template = match &args.bundle {
        Some(bundle) => AttestationTemplate::from_bundle(bundle)
            .with_context(|| format!("cannot hash bundle {}", bundle.display()))?,
        None => AttestationTemplate::for_agent(&json!({
            "kind": "agent",
            "provider": provider_name(args.provider),
            "model": args.model,
            "base_host": host_label(&args.base_url),
        }))?,
    };
    let dir = args
        .attest_log
        .clone()
        .unwrap_or_else(|| PathBuf::from("agent.run.attest.d"));
    let log = AttestationLog::open(&dir)
        .with_context(|| format!("cannot open trail {}", dir.display()))?;
    let mut recorder = CallRecorder::new(template, key, log.clone());
    if args.push {
        let token = super::attest::resolve_token(args.token_file.as_deref())?;
        let registry = args
            .registry
            .as_deref()
            .context("--push requires --registry")?;
        let publisher = ReceiptPublisher::new(registry, token);
        publisher
            .sync(&log)
            .context("cannot publish receipt backlog")?;
        recorder = recorder.with_publisher(publisher);
    }
    Ok(Arc::new(recorder))
}

fn provider_name(p: Provider) -> &'static str {
    match p {
        Provider::OpenaiCompat => "openai-compat",
        Provider::Anthropic => "anthropic",
    }
}

fn host_label(base_url: &str) -> String {
    let rest = base_url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    rest.split(['/', ':'])
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn start_proxy(base: &str, recorder: Arc<CallRecorder>) -> Result<(String, Arc<AtomicBool>)> {
    if base.starts_with("https://") {
        bail!("--via-proxy needs an http:// upstream (TLS providers use client-side receipts)");
    }
    let upstream = resolve_upstream(base)?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").context("bind agent proxy")?;
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    std::thread::spawn(move || {
        let _ = super::attest_proxy::serve_proxy(listener, upstream, recorder, flag);
    });
    std::thread::sleep(Duration::from_millis(50));
    Ok((format!("http://{addr}"), stop))
}

fn resolve_upstream(base: &str) -> Result<SocketAddr> {
    let rest = base
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let hostport = rest.split('/').next().unwrap_or(rest);
    let with_port = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:80")
    };
    with_port
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve {with_port}"))?
        .next()
        .with_context(|| format!("{with_port} resolves to nothing"))
}

fn normalize_base(base: &str) -> String {
    let trimmed = base.trim().trim_end_matches('/');
    trimmed
        .strip_suffix("/v1")
        .map_or_else(|| trimmed.to_string(), str::to_string)
}

fn resolve_api_key(file: Option<&Path>, provider: Provider) -> Result<Option<String>> {
    if let Some(path) = file {
        let s = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read API key file {}", path.display()))?;
        let key = s.trim().to_string();
        if key.is_empty() {
            bail!("API key file {} is empty", path.display());
        }
        return Ok(Some(key));
    }
    let env_names: &[&str] = match provider {
        Provider::OpenaiCompat => &["ERE_API_KEY", "OPENAI_API_KEY"],
        Provider::Anthropic => &["ERE_API_KEY", "ANTHROPIC_API_KEY"],
    };
    for name in env_names {
        if let Ok(v) = std::env::var(name) {
            let t = v.trim().to_string();
            if !t.is_empty() {
                return Ok(Some(t));
            }
        }
    }
    Ok(None)
}

fn load_tools(path: Option<&Path>, allow: &[String]) -> Result<Vec<Value>> {
    if let Some(p) = path {
        let raw = std::fs::read_to_string(p)
            .with_context(|| format!("cannot read tools file {}", p.display()))?;
        let v: Value = serde_json::from_str(&raw).context("tools file is not JSON")?;
        return v
            .as_array()
            .cloned()
            .context("tools file must be a JSON array");
    }
    if allow.iter().any(|n| n == "echo") {
        return Ok(vec![echo_tool_schema()]);
    }
    Ok(Vec::new())
}

fn echo_tool_schema() -> Value {
    json!({
        "type": "function",
        "function": {
            "name": "echo",
            "description": "Return arguments unchanged (deterministic smoke tool)",
            "parameters": {
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"]
            }
        }
    })
}

fn parse_tool_http(specs: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for spec in specs {
        let (name, url) = spec
            .split_once('=')
            .with_context(|| format!("--tool-http expects NAME=URL, got {spec:?}"))?;
        if name.is_empty() || url.is_empty() {
            bail!("--tool-http expects NAME=URL, got {spec:?}");
        }
        map.insert(name.to_string(), url.to_string());
    }
    Ok(map)
}

#[allow(clippy::too_many_arguments)]
fn loop_openai(
    base: &str,
    api_key: Option<&str>,
    args: &RunArgs,
    tools: &[Value],
    allow: &HashSet<String>,
    http_tools: &HashMap<String, String>,
    mcp_clients: &mut [McpClient],
    recorder: &CallRecorder,
    client_records: bool,
) -> Result<Outcome> {
    let path = "/v1/chat/completions";
    let mut messages = vec![json!({"role": "user", "content": args.task})];
    let mut calls = 0usize;

    for _ in 0..args.max_turns {
        let req_bytes = openai_request_bytes(&args.model, &messages, tools, args.stream)?;
        let (status, resp_bytes, _) = stream::http_post_maybe_stream(
            &format!("{base}{path}"),
            &req_bytes,
            api_key,
            &[("Content-Type", "application/json")],
            args.stream,
            AssembleKind::Openai,
        )?;
        calls = calls.saturating_add(1);
        maybe_record(
            recorder,
            &RecordOpts {
                client_records,
                method: "POST",
                path,
                status,
                request: &req_bytes,
                response: &resp_bytes,
                expected_total: calls,
            },
        )?;
        let parsed: Value = serde_json::from_slice(&resp_bytes).context("model response JSON")?;
        let msg = &parsed["choices"][0]["message"];
        if let Some(tcs) = msg.get("tool_calls").and_then(Value::as_array) {
            if !tcs.is_empty() {
                messages.push(msg.clone());
                let mut ctx = ToolCtx {
                    allow,
                    http_tools,
                    mcp: mcp_clients,
                    allow_mcp: args.allow_mcp,
                };
                append_openai_tool_results(&mut messages, tcs, &mut ctx)?;
                continue;
            }
        }
        return Ok(Outcome {
            final_text: msg["content"].as_str().unwrap_or("").to_string(),
            last_response_hash: erebus_core::attest::sha256_hex(&resp_bytes),
            last_body: resp_bytes,
            calls,
        });
    }
    bail!(
        "agent hit --max-turns ({}) without a final answer",
        args.max_turns
    )
}

fn openai_request_bytes(
    model: &str,
    messages: &[Value],
    tools: &[Value],
    stream: bool,
) -> Result<Vec<u8>> {
    let mut body = json!({"model": model, "messages": messages});
    if !tools.is_empty() {
        body["tools"] = Value::Array(tools.to_vec());
    }
    if stream {
        body["stream"] = json!(true);
    }
    Ok(serde_json::to_vec(&body)?)
}

fn append_openai_tool_results(
    messages: &mut Vec<Value>,
    tcs: &[Value],
    ctx: &mut ToolCtx<'_>,
) -> Result<()> {
    for tc in tcs {
        let name = tc["function"]["name"].as_str().unwrap_or("");
        let id = tc["id"].as_str().unwrap_or("call");
        let arguments = tc["function"]["arguments"].as_str().unwrap_or("{}");
        let content = execute_tool(name, arguments, ctx)?;
        messages.push(json!({
            "role": "tool",
            "tool_call_id": id,
            "content": content,
        }));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn loop_anthropic(
    base: &str,
    api_key: Option<&str>,
    args: &RunArgs,
    tools: &[Value],
    allow: &HashSet<String>,
    http_tools: &HashMap<String, String>,
    mcp_clients: &mut [McpClient],
    recorder: &CallRecorder,
    client_records: bool,
) -> Result<Outcome> {
    let path = "/v1/messages";
    let mut messages = vec![json!({"role": "user", "content": args.task})];
    let mut calls = 0usize;
    let anth_tools = openai_tools_to_anthropic(tools);
    let key = api_key.context("anthropic needs --api-key-file or ANTHROPIC_API_KEY")?;

    for _ in 0..args.max_turns {
        let req_bytes = anthropic_request_bytes(&args.model, &messages, &anth_tools, args.stream)?;
        let (status, resp_bytes, _) = stream::http_post_maybe_stream(
            &format!("{base}{path}"),
            &req_bytes,
            None,
            &[
                ("Content-Type", "application/json"),
                ("x-api-key", key),
                ("anthropic-version", "2023-06-01"),
            ],
            args.stream,
            AssembleKind::Anthropic,
        )?;
        calls = calls.saturating_add(1);
        maybe_record(
            recorder,
            &RecordOpts {
                client_records,
                method: "POST",
                path,
                status,
                request: &req_bytes,
                response: &resp_bytes,
                expected_total: calls,
            },
        )?;
        let parsed: Value = serde_json::from_slice(&resp_bytes).context("model response JSON")?;
        let content = parsed["content"].as_array().cloned().unwrap_or_default();
        let tool_uses: Vec<&Value> = content
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("tool_use"))
            .collect();
        if tool_uses.is_empty() {
            return Ok(Outcome {
                final_text: anthropic_text(&content),
                last_response_hash: erebus_core::attest::sha256_hex(&resp_bytes),
                last_body: resp_bytes,
                calls,
            });
        }
        messages.push(json!({"role": "assistant", "content": content}));
        let mut ctx = ToolCtx {
            allow,
            http_tools,
            mcp: mcp_clients,
            allow_mcp: args.allow_mcp,
        };
        let results = anthropic_tool_results(&tool_uses, &mut ctx)?;
        messages.push(json!({"role": "user", "content": results}));
    }
    bail!(
        "agent hit --max-turns ({}) without a final answer",
        args.max_turns
    )
}

fn anthropic_request_bytes(
    model: &str,
    messages: &[Value],
    tools: &[Value],
    stream: bool,
) -> Result<Vec<u8>> {
    let mut body = json!({
        "model": model,
        "max_tokens": 1024,
        "messages": messages,
    });
    if !tools.is_empty() {
        body["tools"] = Value::Array(tools.to_vec());
    }
    if stream {
        body["stream"] = json!(true);
    }
    Ok(serde_json::to_vec(&body)?)
}

fn anthropic_text(content: &[Value]) -> String {
    content
        .iter()
        .filter_map(|b| {
            (b.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| b.get("text").and_then(Value::as_str))
                .flatten()
        })
        .collect::<Vec<_>>()
        .join("")
}

fn anthropic_tool_results(tool_uses: &[&Value], ctx: &mut ToolCtx<'_>) -> Result<Vec<Value>> {
    let mut results = Vec::new();
    for tu in tool_uses {
        let name = tu["name"].as_str().unwrap_or("");
        let id = tu["id"].as_str().unwrap_or("toolu");
        let input = tu.get("input").cloned().unwrap_or(json!({}));
        let arguments = serde_json::to_string(&input)?;
        let text = execute_tool(name, &arguments, ctx)?;
        results.push(json!({
            "type": "tool_result",
            "tool_use_id": id,
            "content": text,
        }));
    }
    Ok(results)
}

fn openai_tools_to_anthropic(tools: &[Value]) -> Vec<Value> {
    tools
        .iter()
        .filter_map(|t| {
            let f = t.get("function")?;
            Some(json!({
                "name": f.get("name")?,
                "description": f.get("description").cloned().unwrap_or(json!("")),
                "input_schema": f.get("parameters").cloned().unwrap_or(json!({"type":"object"})),
            }))
        })
        .collect()
}

fn execute_tool(name: &str, arguments: &str, ctx: &mut ToolCtx<'_>) -> Result<String> {
    let mcp_owned = ctx.mcp.iter().any(|c| c.names.iter().any(|n| n == name));
    let allowed = ctx.allow.contains(name) || (ctx.allow_mcp && mcp_owned);
    if ctx.allow.is_empty() && !ctx.allow_mcp {
        bail!("model called tool {name:?} but no --allow-tool / --allow-mcp was set");
    }
    if !allowed {
        bail!("tool {name:?} is not in the allowlist ({:?})", ctx.allow);
    }
    if name == "echo" {
        return Ok(arguments.to_string());
    }
    if mcp_owned {
        return mcp::call_named(ctx.mcp, name, arguments);
    }
    if let Some(url) = ctx.http_tools.get(name) {
        let (status, body) = http_post(
            url,
            arguments.as_bytes(),
            None,
            &[("Content-Type", "application/json")],
        )?;
        if !(200..300).contains(&status) {
            bail!(
                "tool {name} HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            );
        }
        return Ok(String::from_utf8_lossy(&body).into_owned());
    }
    bail!("tool {name:?} is allowlisted but has no executor (echo, --tool-http, or --mcp)")
}

struct RecordOpts<'a> {
    client_records: bool,
    method: &'a str,
    path: &'a str,
    status: u16,
    request: &'a [u8],
    response: &'a [u8],
    expected_total: usize,
}

fn maybe_record(recorder: &CallRecorder, opts: &RecordOpts<'_>) -> Result<()> {
    if !opts.client_records {
        wait_receipts(recorder, opts.expected_total)?;
        return Ok(());
    }
    let call: CallSummary = CallRecorder::summarize_engine_call(
        opts.method,
        opts.path,
        Some(opts.status),
        opts.request,
        opts.response,
    );
    recorder
        .record(&call)
        .with_context(|| format!("cannot write receipt for {} {}", opts.method, opts.path))?;
    Ok(())
}

fn wait_receipts(recorder: &CallRecorder, min: usize) -> Result<()> {
    let log = AttestationLog::open(recorder.log_dir())?;
    for _ in 0..100 {
        if log.entries()?.len() >= min {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

pub(crate) fn http_post(
    url: &str,
    body: &[u8],
    bearer: Option<&str>,
    headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>)> {
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
    let bytes = resp.bytes().context("read response body")?.to_vec();
    if !(200..300).contains(&status) {
        let preview: String = String::from_utf8_lossy(&bytes).chars().take(400).collect();
        bail!("provider HTTP {status}: {preview}");
    }
    Ok((status, bytes))
}
