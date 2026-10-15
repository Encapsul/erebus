//! `erebus attest-tool` — put a tool behind an attested boundary.
//!
//! The engine proxy (`serve --attest-key`) signs what the model *asked* an
//! agent to do. This boundary signs what the tool *received and returned*:
//! one chained receipt per tool execution, whose `tool_invocation` carries
//! the tool name, the canonical digest of its arguments and the digests of
//! its result (`erebus_core::tool_exec`). `verify-attest --chain <agent
//! trail> --tool-trail <this trail>` then proves that each requested call
//! reached the tool and that the agent relayed the tool's real answer.
//!
//! - `http`: reverse proxy in front of a plain HTTP tool or an MCP server
//!   over Streamable HTTP (JSON or SSE answers); every request is recorded.
//! - `stdio`: wraps an MCP server the client spawns (`… -- npx server`);
//!   newline-delimited JSON-RPC is relayed byte for byte and each
//!   `tools/call` / response pair is recorded. Only JSON-RPC goes to stdout;
//!   erebus logs to stderr.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use erebus_core::attest::AttestationTemplate;
use erebus_core::attest_log::AttestationLog;
use erebus_core::tool_exec::{self, ToolInvocation};
use sha2::{Digest, Sha256};

use super::attest_proxy::{CallRecorder, CallSummary, ProxyMode, ReceiptPublisher};

#[derive(Args)]
pub struct AttestToolArgs {
    #[command(subcommand)]
    pub transport: Transport,
}

#[derive(Subcommand)]
pub enum Transport {
    /// Reverse proxy in front of an HTTP tool or an MCP Streamable HTTP server
    Http(HttpArgs),
    /// Wrap an MCP server spoken to over stdio: `attest-tool stdio … -- <cmd>`
    Stdio(StdioArgs),
}

#[derive(Args)]
pub struct Common {
    /// Ed25519 key signing the tool receipts
    #[arg(long, env = "ERE_ATTEST_KEY", value_name = "KEY")]
    pub attest_key: PathBuf,

    /// Trail directory for the tool receipts
    #[arg(long, value_name = "DIR")]
    pub attest_log: PathBuf,

    /// The tool is an erebus bundle: receipts name its exact digest
    #[arg(long, value_name = "FILE")]
    pub bundle: Option<PathBuf>,

    /// Publish every tool receipt to the registry transparency log
    #[arg(long, requires = "registry")]
    pub push: bool,

    /// Registry receiving the receipts
    #[arg(long, env = "ERE_REGISTRY")]
    pub registry: Option<String>,

    /// File containing the registry bearer token (`ERE_TOKEN` otherwise)
    #[arg(long)]
    pub token_file: Option<PathBuf>,
}

#[derive(Args)]
pub struct HttpArgs {
    #[command(flatten)]
    pub common: Common,

    /// Address clients connect to
    #[arg(long, value_name = "HOST:PORT")]
    pub listen: String,

    /// Address of the tool server
    #[arg(long, value_name = "HOST:PORT")]
    pub upstream: String,
}

#[derive(Args)]
pub struct StdioArgs {
    #[command(flatten)]
    pub common: Common,

    /// MCP server command and its arguments (after `--`)
    #[arg(required = true, trailing_var_arg = true, value_name = "CMD")]
    pub command: Vec<String>,
}

pub fn run(args: AttestToolArgs) -> Result<()> {
    match args.transport {
        Transport::Http(a) => run_http(&a),
        Transport::Stdio(a) => run_stdio(&a),
    }
}

/// Signing key, template, trail and optional publisher, in tool mode.
fn tool_recorder(
    common: &Common,
    descriptor: &serde_json::Value,
    program: Option<&Path>,
) -> Result<Arc<CallRecorder>> {
    let key = erebus_core::attest::load_signing_key(&common.attest_key).with_context(|| {
        format!(
            "cannot load attestation key {}",
            common.attest_key.display()
        )
    })?;
    let template = match (&common.bundle, program) {
        (Some(bundle), _) => AttestationTemplate::from_bundle(bundle)
            .with_context(|| format!("cannot hash tool bundle {}", bundle.display()))?,
        (None, Some(p)) => {
            let bytes = std::fs::read(p)
                .with_context(|| format!("cannot read tool program {}", p.display()))?;
            AttestationTemplate::for_tool(descriptor, Some(&bytes))?
        }
        (None, None) => AttestationTemplate::for_tool(descriptor, None)?,
    };
    let log = AttestationLog::open(&common.attest_log)
        .with_context(|| format!("cannot open trail {}", common.attest_log.display()))?;
    let mut recorder = CallRecorder::new(template, key, log.clone()).with_mode(ProxyMode::Tool);
    if common.push {
        let token = super::attest::resolve_token(common.token_file.as_deref())?;
        let registry = common
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

fn run_http(args: &HttpArgs) -> Result<()> {
    let upstream: SocketAddr = args
        .upstream
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve --upstream {}", args.upstream))?
        .next()
        .with_context(|| format!("--upstream {} resolves to nothing", args.upstream))?;
    let descriptor = serde_json::json!({
        "kind": "tool", "transport": "http", "upstream": args.upstream,
    });
    let recorder = tool_recorder(&args.common, &descriptor, None)?;
    let listener = TcpListener::bind(&args.listen)
        .with_context(|| format!("cannot bind tool boundary on {}", args.listen))?;
    eprintln!(
        "[erebus] tool boundary: http://{} → {upstream}; receipts → {}",
        listener.local_addr()?,
        args.common.attest_log.display()
    );
    let stop = Arc::new(AtomicBool::new(false));
    register_stop(&stop)?;
    super::attest_proxy::serve_proxy(listener, upstream, recorder, stop)
}

#[cfg(unix)]
fn register_stop(flag: &Arc<AtomicBool>) -> Result<()> {
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(flag))
            .context("cannot install signal handler")?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn register_stop(_flag: &Arc<AtomicBool>) -> Result<()> {
    Ok(())
}

/// Requests in flight, by JSON-RPC id (its JSON text).
type Pending = Arc<Mutex<HashMap<String, (String, ToolInvocation)>>>;

fn run_stdio(args: &StdioArgs) -> Result<()> {
    let program = resolve_program(&args.command[0]);
    let descriptor = serde_json::json!({
        "kind": "tool", "transport": "stdio", "command": args.command,
    });
    let recorder = tool_recorder(&args.common, &descriptor, program.as_deref())?;
    let mut child = Command::new(&args.command[0])
        .args(&args.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("cannot start tool server {}", args.command[0]))?;
    let child_in = child.stdin.take().context("tool server stdin")?;
    let child_out = child.stdout.take().context("tool server stdout")?;
    let pending: Pending = Arc::default();

    let to_server = {
        let pending = Arc::clone(&pending);
        std::thread::spawn(move || relay_requests(std::io::stdin().lock(), child_in, &pending))
    };
    relay_responses(
        BufReader::new(child_out),
        std::io::stdout().lock(),
        &pending,
        &recorder,
    )?;
    let status = child.wait().context("waiting for tool server")?;
    drop(to_server);
    if !status.success() {
        bail!("tool server exited with {status}");
    }
    Ok(())
}

/// Client → server: forward every line; remember `tools/call` requests.
fn relay_requests<R: BufRead, W: Write>(mut r: R, mut w: W, pending: &Pending) -> Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        let message = trim_line(&line);
        if let Some((id, invocation)) = tool_exec::mcp_tool_call(message) {
            if let Ok(mut p) = pending.lock() {
                p.insert(id.to_string(), (line_digest(message), invocation));
            }
        }
        w.write_all(&line)?;
        w.flush()?;
    }
}

/// Server → client: forward every line; sign a receipt when it answers a
/// pending `tools/call`. The line is relayed before the receipt is written.
fn relay_responses<R: BufRead, W: Write>(
    mut r: R,
    mut w: W,
    pending: &Pending,
    recorder: &CallRecorder,
) -> Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        w.write_all(&line)?;
        w.flush()?;
        let message = trim_line(&line);
        if let Some(call) = answered_call(message, pending) {
            if let Err(e) = recorder.record(&call) {
                eprintln!("[erebus] attest-tool: receipt NOT written: {e:#}");
            }
        }
    }
}

/// The receipt summary when `message` answers a pending `tools/call`.
fn answered_call(message: &[u8], pending: &Pending) -> Option<CallSummary> {
    let id = serde_json::from_slice::<serde_json::Value>(message)
        .ok()?
        .get("id")
        .filter(|id| !id.is_null())?
        .clone();
    let (request_hash, mut invocation) = pending.lock().ok()?.remove(&id.to_string())?;
    tool_exec::mcp_attach_response(&mut invocation, &id, message);
    Some(CallSummary {
        method: "STDIO".to_string(),
        path: "tools/call".to_string(),
        status: None,
        request_hash,
        response_hash: line_digest(message),
        tool_calls: Default::default(),
        request_tools: Default::default(),
        tool_invocation: Some(invocation),
    })
}

fn trim_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

/// Stdio receipts hash one JSON-RPC message: the line without its newline.
fn line_digest(message: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(message)))
}

/// The file `cmd` runs, searched on `PATH` like `execvp` does.
fn resolve_program(cmd: &str) -> Option<PathBuf> {
    let direct = Path::new(cmd);
    if direct.components().count() > 1 {
        return direct.is_file().then(|| direct.to_path_buf());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(cmd))
        .find(|p| p.is_file())
}
