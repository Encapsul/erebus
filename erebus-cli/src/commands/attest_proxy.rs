//! Attesting reverse proxy behind `erebus serve --attest-key`.
//!
//! Sits between clients and the inference engine. Every request is forwarded
//! byte-for-byte; for each `POST` the proxy hashes the request
//! (`METHOD path\n` + body) and the *decoded* response body while streaming
//! it (Content-Length, chunked/SSE, or read-to-EOF), then appends one signed,
//! chained receipt to the trail. The engine's output is never buffered or
//! altered, so time-to-first-token is unchanged. Tool calls in the response
//! (`erebus_core::tool_calls`) are extracted from the same decoded bytes and
//! signed into the receipt, with the tool context of the request
//! (`erebus_core::tool_requests`) that links them across the trail (spec 2.1).
//!
//! HTTP/1.1 only, one request per connection (`Connection: close` both ways):
//! keep-alive multiplexing would make request/response pairing fragile for no
//! benefit against a local engine. `GET`s (health probes, `/v1/models`) pass
//! through unrecorded.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use erebus_core::attest::{
    append_receipt, AttestationTemplate, ExecutionCapture, RequestInfo, StopInfo,
};
use erebus_core::attest_log::AttestationLog;
use erebus_core::tool_calls::{ToolCallExtractor, ToolCallReport};
use erebus_core::tool_exec::{self, ToolInvocation};
use erebus_core::tool_requests::{extract_request_encoded, RequestToolReport};
use sha2::{Digest, Sha256};

/// Header block cap; anything larger is not an OpenAI-style API call.
const MAX_HEAD: usize = 64 * 1024;
/// Request bodies are buffered (needed to hash before forwarding is not —
/// but a bounded buffer keeps the code simple and the engine protected).
const MAX_REQUEST_BODY: u64 = 64 * 1024 * 1024;
/// How long a client may take to send its request head + body.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the engine may stay silent between two response bytes.
const UPSTREAM_READ_TIMEOUT: Duration = Duration::from_secs(600);

/// Signs one receipt per recorded call into a shared trail.
pub struct CallRecorder {
    template: AttestationTemplate,
    key: SigningKey,
    log: AttestationLog,
    publisher: Option<ReceiptPublisher>,
    mode: ProxyMode,
    /// Appends read the trail head then advance it: serialize them.
    lock: Mutex<()>,
}

/// What sits behind the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyMode {
    /// An inference engine: `POST`s are recorded with the tool calls the
    /// model returned and the tool context of the request.
    Engine,
    /// A tool server (plain HTTP or MCP Streamable HTTP): every request is
    /// recorded with the tool invocation it carried.
    Tool,
}

/// Registry destination for immediate and catch-up publication of receipts.
pub struct ReceiptPublisher {
    registry: String,
    token: Option<String>,
}

/// What ends up in the signed `execution` block for one call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSummary {
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub request_hash: String,
    pub response_hash: String,
    pub tool_calls: ToolCallReport,
    pub request_tools: RequestToolReport,
    pub tool_invocation: Option<ToolInvocation>,
}

impl CallRecorder {
    pub fn new(template: AttestationTemplate, key: SigningKey, log: AttestationLog) -> Self {
        Self {
            template,
            key,
            log,
            publisher: None,
            mode: ProxyMode::Engine,
            lock: Mutex::new(()),
        }
    }

    pub fn with_publisher(mut self, publisher: ReceiptPublisher) -> Self {
        self.publisher = Some(publisher);
        self
    }

    pub fn with_mode(mut self, mode: ProxyMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn mode(&self) -> ProxyMode {
        self.mode
    }

    pub fn log_dir(&self) -> &Path {
        self.log.dir()
    }

    /// Append a chained receipt for `call`; returns the receipt file path.
    pub fn record(&self, call: &CallSummary) -> Result<PathBuf> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("call recorder lock poisoned"))?;
        let capture = ExecutionCapture {
            input_hash: Some(call.request_hash.clone()),
            output_hash: Some(call.response_hash.clone()),
            request: Some(
                RequestInfo {
                    method: call.method.clone(),
                    path: call.path.clone(),
                    status: call.status,
                    tool_calls: (!call.tool_calls.calls.is_empty())
                        .then(|| call.tool_calls.calls.clone()),
                    tool_calls_incomplete: call.tool_calls.incomplete,
                    tool_invocation: call.tool_invocation.clone(),
                    ..RequestInfo::default()
                }
                .with_request_tools(&call.request_tools),
            ),
            ..ExecutionCapture::default()
        };
        let (_, path) = append_receipt(&self.template, &self.key, &self.log, &capture)?;
        if let Some(publisher) = &self.publisher {
            publisher.publish(&path)?;
        }
        Ok(path)
    }

    /// Append a stop receipt (only `execution.stop` set) and co-sign via the
    /// host machine identity through [`append_receipt`].
    pub fn record_stop(&self, stop: StopInfo) -> Result<PathBuf> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("call recorder lock poisoned"))?;
        let capture = ExecutionCapture {
            stop: Some(stop),
            ..ExecutionCapture::default()
        };
        let (_, path) = append_receipt(&self.template, &self.key, &self.log, &capture)?;
        if let Some(publisher) = &self.publisher {
            publisher.publish(&path)?;
        }
        Ok(path)
    }
}

impl ReceiptPublisher {
    pub fn new(registry: &str, token: Option<String>) -> Self {
        Self {
            registry: registry.trim_end_matches('/').to_string(),
            token,
        }
    }

    /// Upload receipts that have no verified proof sidecar yet. This makes a
    /// restart repair any publication interrupted after the local append.
    pub fn sync(&self, log: &AttestationLog) -> Result<usize> {
        let mut count = 0usize;
        for path in log.entries().context("cannot list receipt backlog")? {
            if !crate::commands::attest::proof_path_for(&path).exists() {
                self.publish(&path)?;
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    fn publish(&self, path: &Path) -> Result<()> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("cannot read receipt {}", path.display()))?;
        let published = crate::commands::attest::publish_receipt(
            &self.registry,
            self.token.as_deref(),
            path,
            &bytes,
        )?;
        if std::env::var_os("ERE_VERBOSE").is_some() {
            eprintln!(
                "[erebus] published receipt {} → {}",
                path.display(),
                published.id
            );
        }
        Ok(())
    }
}

/// Accept loop. Returns when `stop` is raised; in-flight connections finish
/// on their own threads.
pub fn serve_proxy(
    listener: TcpListener,
    upstream: SocketAddr,
    recorder: Arc<CallRecorder>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    listener
        .set_nonblocking(true)
        .context("proxy listener: set_nonblocking")?;
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Some platforms hand out non-blocking accepted sockets.
                let _ = stream.set_nonblocking(false);
                let rec = Arc::clone(&recorder);
                std::thread::spawn(move || handle_connection(stream, upstream, &rec));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                eprintln!("[erebus] proxy: accept failed: {e}");
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
    Ok(())
}

/// One client connection: parse, forward, relay, record. Errors before the
/// response head was relayed turn into a 502/4xx for the client.
fn handle_connection(client: TcpStream, upstream: SocketAddr, recorder: &CallRecorder) {
    let _ = client.set_read_timeout(Some(CLIENT_READ_TIMEOUT));
    let mut relay = Relay {
        client,
        sent_head: false,
    };
    match relay.run(upstream, recorder.mode()) {
        Ok(Some(call)) => match recorder.record(&call) {
            Ok(path) => {
                if std::env::var_os("ERE_VERBOSE").is_some() {
                    eprintln!(
                        "[erebus] attested {} {} → {}",
                        call.method,
                        call.path,
                        path.display()
                    );
                }
            }
            Err(e) => eprintln!(
                "[erebus] proxy: receipt NOT written for {} {}: {e:#}",
                call.method, call.path
            ),
        },
        Ok(None) => {}
        Err(e) => {
            eprintln!("[erebus] proxy: {e:#}");
            if !relay.sent_head {
                let _ = reply(&mut relay.client, status_for(&e), "Bad Gateway");
            }
        }
    }
}

struct Relay {
    client: TcpStream,
    sent_head: bool,
}

/// Errors raised while reading the client request carry their own status.
#[derive(Debug)]
struct ClientError(u16, &'static str);

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.0, self.1)
    }
}

impl std::error::Error for ClientError {}

fn status_for(e: &anyhow::Error) -> u16 {
    e.downcast_ref::<ClientError>().map_or(502, |c| c.0)
}

impl Relay {
    /// Returns `Some(summary)` for calls that must be recorded: every `POST`
    /// in front of an engine, every request in front of a tool.
    fn run(&mut self, upstream: SocketAddr, mode: ProxyMode) -> Result<Option<CallSummary>> {
        let mut cin = BufReader::new(self.client.try_clone().context("clone client socket")?);
        let req = read_head(&mut cin).context("reading client request")?;
        let (method, target) = req.request_line()?;
        let req_body = read_request_body(&mut cin, &req)?;

        let mut uin = send_upstream(upstream, &req, &req_body)?;
        let resp = read_head(&mut uin).context("reading upstream response")?;
        let status = resp.status_code();
        self.client.write_all(&resp.serialize_close())?;
        self.sent_head = true;
        let framing = resp.response_framing(status, method == "HEAD");
        let recorded = mode == ProxyMode::Tool || method == "POST";
        let mut body = BodyObserver::for_exchange(mode, recorded, resp.header("Content-Encoding"));
        relay_body(&mut uin, &mut self.client, framing, &mut body)?;
        self.client.flush()?;

        if !recorded {
            return Ok(None);
        }
        let exchange = Exchange {
            mode,
            method,
            target,
            status,
            request_encoding: req.header("Content-Encoding"),
            call_id: req.header(tool_exec::CALL_ID_HEADER),
            request_body: &req_body,
        };
        Ok(Some(exchange.summarize(body.finish())))
    }
}

/// One relayed request, ready to be summarized once its response is in.
struct Exchange<'a> {
    mode: ProxyMode,
    method: String,
    target: String,
    status: Option<u16>,
    request_encoding: Option<&'a str>,
    call_id: Option<&'a str>,
    request_body: &'a [u8],
}

impl Exchange<'_> {
    fn summarize(self, observed: Observed) -> CallSummary {
        let mut req_hasher = Sha256::new();
        req_hasher.update(format!("{} {}\n", self.method, self.target).as_bytes());
        req_hasher.update(self.request_body);
        let (request_tools, tool_invocation) = match self.mode {
            ProxyMode::Engine => (
                extract_request_encoded(self.request_body, self.request_encoding),
                None,
            ),
            ProxyMode::Tool => (
                RequestToolReport::default(),
                tool_exec::from_http_exchange(&tool_exec::HttpExchange {
                    request: self.request_body,
                    response: observed.body.as_deref(),
                    status: self.status,
                    call_id_header: self.call_id,
                }),
            ),
        };
        CallSummary {
            method: self.method,
            path: self.target,
            status: self.status,
            request_hash: hex_digest(req_hasher),
            response_hash: observed.response_hash,
            tool_calls: observed.tool_calls,
            request_tools,
            tool_invocation,
        }
    }
}

/// Open the engine connection and write the full request; returns the
/// buffered read half.
fn send_upstream(upstream: SocketAddr, req: &Head, body: &[u8]) -> Result<BufReader<TcpStream>> {
    let up = TcpStream::connect_timeout(&upstream, Duration::from_secs(5))
        .with_context(|| format!("engine at {upstream} unreachable"))?;
    let _ = up.set_read_timeout(Some(UPSTREAM_READ_TIMEOUT));
    let uin = BufReader::new(up.try_clone().context("clone upstream socket")?);
    let mut uout = up;
    uout.write_all(&req.serialize_close())?;
    uout.write_all(body)?;
    uout.flush()?;
    Ok(uin)
}

/// Minimal error reply; the body is empty so nothing is attested for it.
fn reply(w: &mut TcpStream, status: u16, reason: &str) -> io::Result<()> {
    write!(
        w,
        "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    w.flush()
}

fn hex_digest(hasher: Sha256) -> String {
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// ---------------------------------------------------------------------------
// HTTP/1.x head parsing
// ---------------------------------------------------------------------------

/// Parsed request or status head, kept verbatim for re-serialization.
struct Head {
    first_line: String,
    headers: Vec<(String, String)>,
}

/// How the message body is delimited (RFC 9112 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    None,
    Length(u64),
    Chunked,
    Close,
}

/// Read `first line + headers + blank line`, bounded by `MAX_HEAD`.
fn read_head<R: BufRead>(r: &mut R) -> Result<Head> {
    let mut raw = Vec::new();
    loop {
        let start = raw.len();
        let n = r.read_until(b'\n', &mut raw)?;
        if n == 0 {
            bail!("connection closed before end of headers");
        }
        if raw.len() > MAX_HEAD {
            bail!(ClientError(431, "Request Header Fields Too Large"));
        }
        if matches!(&raw[start..], b"\r\n" | b"\n") {
            break;
        }
    }
    Head::parse(&raw)
}

impl Head {
    fn parse(raw: &[u8]) -> Result<Self> {
        let text = String::from_utf8_lossy(raw);
        let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
        let first_line = lines
            .next()
            .filter(|l| !l.is_empty())
            .context("empty HTTP head")?
            .to_string();
        let headers = lines
            .take_while(|l| !l.is_empty())
            .filter_map(|l| {
                let (name, value) = l.split_once(':')?;
                Some((name.trim().to_string(), value.trim().to_string()))
            })
            .collect();
        Ok(Self {
            first_line,
            headers,
        })
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `(METHOD, request-target)` from a request line; rejects HTTP/0.9.
    fn request_line(&self) -> Result<(String, String)> {
        let mut parts = self.first_line.split_whitespace();
        match (parts.next(), parts.next(), parts.next()) {
            (Some(m), Some(t), Some(v)) if v.starts_with("HTTP/1.") => {
                Ok((m.to_ascii_uppercase(), t.to_string()))
            }
            _ => bail!(ClientError(400, "Bad Request")),
        }
    }

    /// Status code from a status line; `None` if unparseable.
    fn status_code(&self) -> Option<u16> {
        self.first_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
    }

    fn is_chunked(&self) -> bool {
        self.header("Transfer-Encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    }

    fn content_length(&self) -> Result<Option<u64>> {
        self.header("Content-Length")
            .map(|v| {
                v.trim()
                    .parse::<u64>()
                    .map_err(|_| anyhow::anyhow!(ClientError(400, "Bad Request")))
            })
            .transpose()
    }

    /// Body framing of a response to `HEAD`-or-not with `status`.
    fn response_framing(&self, status: Option<u16>, is_head: bool) -> Framing {
        let bodyless = matches!(status, Some(100..=199 | 204 | 304));
        if is_head || bodyless {
            return Framing::None;
        }
        if self.is_chunked() {
            return Framing::Chunked;
        }
        match self.content_length() {
            Ok(Some(n)) => Framing::Length(n),
            _ => Framing::Close,
        }
    }

    /// Re-emit the head with hop-by-hop keep-alive headers replaced by
    /// `Connection: close` so each side tears down after one exchange.
    fn serialize_close(&self) -> Vec<u8> {
        let mut out = format!("{}\r\n", self.first_line);
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("Connection") || name.eq_ignore_ascii_case("Keep-Alive") {
                continue;
            }
            out.push_str(&format!("{name}: {value}\r\n"));
        }
        out.push_str("Connection: close\r\n\r\n");
        out.into_bytes()
    }
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// Buffer the request body (bounded). Chunked uploads are refused with 411:
/// OpenAI-style clients always send `Content-Length`.
fn read_request_body<R: BufRead>(r: &mut R, head: &Head) -> Result<Vec<u8>> {
    if head.is_chunked() {
        bail!(ClientError(411, "Length Required"));
    }
    let Some(len) = head.content_length()? else {
        return Ok(Vec::new());
    };
    if len > MAX_REQUEST_BODY {
        bail!(ClientError(413, "Content Too Large"));
    }
    let mut body = vec![0u8; usize::try_from(len).context("body length overflow")?];
    r.read_exact(&mut body).context("reading request body")?;
    Ok(body)
}

/// Everything derived from the decoded response body: its digest and the
/// tool calls it carries.
struct BodyObserver {
    hasher: Sha256,
    tools: ToolCallExtractor,
    /// Tool mode keeps the decoded body (bounded) to read the tool's answer;
    /// `None` when not kept or too large.
    kept: Option<Vec<u8>>,
}

/// What was learned from a relayed response body.
struct Observed {
    response_hash: String,
    tool_calls: ToolCallReport,
    body: Option<Vec<u8>>,
}

impl BodyObserver {
    fn new(tools: ToolCallExtractor) -> Self {
        Self {
            hasher: Sha256::new(),
            tools,
            kept: None,
        }
    }

    /// Engine `POST`s are scanned for tool calls; tool answers are kept for
    /// `tool_exec`, unless compressed (then the invocation is incomplete).
    fn for_exchange(mode: ProxyMode, recorded: bool, encoding: Option<&str>) -> Self {
        match (mode, recorded) {
            (ProxyMode::Engine, true) => Self::new(ToolCallExtractor::for_encoding(encoding)),
            (ProxyMode::Tool, true) => {
                let mut observer = Self::new(ToolCallExtractor::off());
                let plain = encoding.is_none_or(|e| e.trim().eq_ignore_ascii_case("identity"));
                observer.kept = plain.then(Vec::new);
                observer
            }
            (_, false) => Self::new(ToolCallExtractor::off()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.tools.update(bytes);
        let fits = self
            .kept
            .as_ref()
            .is_some_and(|k| k.len().saturating_add(bytes.len()) <= tool_exec::MAX_TOOL_BODY);
        match (&mut self.kept, fits) {
            (Some(k), true) => k.extend_from_slice(bytes),
            _ => self.kept = None,
        }
    }

    fn finish(self) -> Observed {
        Observed {
            response_hash: hex_digest(self.hasher),
            tool_calls: self.tools.finish(),
            body: self.kept,
        }
    }
}

/// Stream the response body to the client while observing the *decoded*
/// bytes.
fn relay_body<R: BufRead, W: Write>(
    r: &mut R,
    w: &mut W,
    framing: Framing,
    h: &mut BodyObserver,
) -> Result<()> {
    match framing {
        Framing::None => Ok(()),
        Framing::Length(n) => copy_n(r, w, n, h),
        Framing::Chunked => relay_chunked(r, w, h),
        Framing::Close => copy_to_eof(r, w, h),
    }
}

/// Copy exactly `n` bytes, flushing after each read so tokens reach the
/// client as soon as the engine emits them.
fn copy_n<R: Read, W: Write>(r: &mut R, w: &mut W, mut n: u64, h: &mut BodyObserver) -> Result<()> {
    let mut buf = [0u8; 16 * 1024];
    while n > 0 {
        let want = usize::try_from(n.min(buf.len() as u64)).unwrap_or(buf.len());
        let got = r.read(&mut buf[..want])?;
        if got == 0 {
            bail!("engine closed the connection mid-body ({n} bytes missing)");
        }
        h.update(&buf[..got]);
        w.write_all(&buf[..got])?;
        w.flush()?;
        n = n.saturating_sub(got as u64);
    }
    Ok(())
}

fn copy_to_eof<R: Read, W: Write>(r: &mut R, w: &mut W, h: &mut BodyObserver) -> Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let got = r.read(&mut buf)?;
        if got == 0 {
            return Ok(());
        }
        h.update(&buf[..got]);
        w.write_all(&buf[..got])?;
        w.flush()?;
    }
}

/// Forward chunk framing verbatim; hash only chunk payloads so the digest
/// equals `sha256(decoded body)` regardless of how the engine split it.
fn relay_chunked<R: BufRead, W: Write>(r: &mut R, w: &mut W, h: &mut BodyObserver) -> Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            bail!("engine closed the connection mid-chunked-body");
        }
        w.write_all(&line)?;
        let size = parse_chunk_size(&line)?;
        if size == 0 {
            return relay_trailers(r, w);
        }
        copy_n(r, w, size, h)?;
        line.clear();
        r.read_until(b'\n', &mut line)?; // CRLF after chunk data
        w.write_all(&line)?;
        w.flush()?;
    }
}

/// Trailer section: header lines until the blank line, forwarded verbatim.
fn relay_trailers<R: BufRead, W: Write>(r: &mut R, w: &mut W) -> Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            bail!("engine closed the connection inside chunk trailers");
        }
        w.write_all(&line)?;
        if matches!(line.as_slice(), b"\r\n" | b"\n") {
            w.flush()?;
            return Ok(());
        }
    }
}

/// `1a;ext=1\r\n` → 26. Extensions are ignored.
fn parse_chunk_size(line: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(line).context("non-UTF-8 chunk size line")?;
    let hex = text.trim().split(';').next().unwrap_or_default().trim();
    u64::from_str_radix(hex, 16).with_context(|| format!("invalid chunk size {hex:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use erebus_core::attest::{sha256_hex, ArtifactInfo, ProvenanceInfo};
    use std::net::TcpListener;

    /// A one-shot fake engine: answers every connection with `response`,
    /// records the raw request it received.
    fn fake_engine(response: &'static [u8]) -> (SocketAddr, std::sync::mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut r = BufReader::new(stream.try_clone().unwrap());
                let head = read_head(&mut r).unwrap();
                let body = read_request_body(&mut r, &head).unwrap();
                let mut seen = head.serialize_close();
                seen.extend_from_slice(&body);
                tx.send(seen).unwrap();
                let mut w = stream;
                w.write_all(response).unwrap();
                w.flush().unwrap();
            }
        });
        (addr, rx)
    }

    fn recorder(dir: &Path) -> Arc<CallRecorder> {
        let template = AttestationTemplate {
            artifact: ArtifactInfo {
                bundle_hash: sha256_hex(b"bundle"),
                payload_hash: sha256_hex(b"payload"),
                metadata_hash: sha256_hex(b"meta"),
                format_version: 2,
                flags: vec![],
            },
            provenance: ProvenanceInfo {
                builder: "test".into(),
                author: None,
                license: None,
                layers: vec![],
            },
        };
        let key = SigningKey::from_bytes(&[7u8; 32]);
        Arc::new(CallRecorder::new(
            template,
            key,
            AttestationLog::open(&dir.join("trail")).unwrap(),
        ))
    }

    fn start_proxy(upstream: SocketAddr, rec: Arc<CallRecorder>) -> (SocketAddr, Arc<AtomicBool>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let s = Arc::clone(&stop);
        std::thread::spawn(move || serve_proxy(listener, upstream, rec, s));
        (addr, stop)
    }

    fn roundtrip(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(request).unwrap();
        c.flush().unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).unwrap();
        out
    }

    fn split_body(raw: &[u8]) -> &[u8] {
        let pos = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        &raw[pos + 4..]
    }

    const CHAT_REQ: &[u8] = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"messages\":[]}\n";

    #[test]
    fn post_is_relayed_unchanged_and_recorded_with_matching_hashes() {
        let dir = tempfile::tempdir().unwrap();
        let body = b"{\"choices\":[{\"message\":{\"content\":\"hi\"}}]}";
        let response: &'static [u8] = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes()
            .into_iter()
            .chain(body.iter().copied())
            .collect::<Vec<u8>>()
            .into_boxed_slice(),
        );
        let (engine, seen) = fake_engine(response);
        let rec = recorder(dir.path());
        let (proxy, stop) = start_proxy(engine, Arc::clone(&rec));

        let raw = roundtrip(proxy, CHAT_REQ);
        assert!(raw.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_eq!(split_body(&raw), body);
        let upstream_saw = seen.recv().unwrap();
        assert!(upstream_saw.ends_with(b"{\"messages\":[]}\n"));

        let entries = wait_entries(&rec, 1);
        let att: erebus_core::attest::Attestation =
            serde_json::from_slice(&std::fs::read(&entries[0]).unwrap()).unwrap();
        let req = att.execution.request.as_ref().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/v1/chat/completions");
        assert_eq!(req.status, Some(200));
        assert_eq!(
            att.execution.output_hash.as_deref(),
            Some(sha256_hex(body).as_str())
        );
        let expected_req = {
            let mut h = Sha256::new();
            h.update(b"POST /v1/chat/completions\n");
            h.update(b"{\"messages\":[]}\n");
            hex_digest(h)
        };
        assert_eq!(
            att.execution.input_hash.as_deref(),
            Some(expected_req.as_str())
        );
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn chunked_sse_is_hashed_decoded_and_chain_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let response: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n\
            d\r\ndata: hello\n\n\r\n\
            b;ext=1\r\ndata: bye\n\n\r\n\
            0\r\n\r\n";
        let (engine, _seen) = fake_engine(response);
        let rec = recorder(dir.path());
        let (proxy, stop) = start_proxy(engine, Arc::clone(&rec));

        for _ in 0..3 {
            let raw = roundtrip(proxy, CHAT_REQ);
            assert_eq!(
                split_body(&raw),
                b"d\r\ndata: hello\n\n\r\nb;ext=1\r\ndata: bye\n\n\r\n0\r\n\r\n"
            );
        }
        let entries = wait_entries(&rec, 3);
        let decoded = sha256_hex(b"data: hello\n\ndata: bye\n\n");
        for e in &entries {
            let att: erebus_core::attest::Attestation =
                serde_json::from_slice(&std::fs::read(e).unwrap()).unwrap();
            assert_eq!(att.execution.output_hash.as_deref(), Some(decoded.as_str()));
        }
        let vk = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let report = AttestationLog::open(rec.log_dir())
            .unwrap()
            .verify_chain(&[vk], None)
            .unwrap();
        assert_eq!(report.count, 3);

        // Tampering with a recorded response hash breaks the chain.
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&entries[1]).unwrap()).unwrap();
        doc["execution"]["output_hash"] = serde_json::Value::String(sha256_hex(b"forged"));
        std::fs::write(&entries[1], serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        let err = AttestationLog::open(rec.log_dir())
            .unwrap()
            .verify_chain(&[vk], None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("TAMPERED"), "{err}");
        stop.store(true, Ordering::SeqCst);
    }

    fn http_response(content_type: &str, body: &[u8]) -> &'static [u8] {
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        Box::leak(out.into_boxed_slice())
    }

    fn read_receipt(path: &Path) -> erebus_core::attest::Attestation {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    /// R2 acceptance: a chat call returning two tool calls yields a receipt
    /// whose signed predicate lists both — JSON and chunked SSE agree — and
    /// editing a tool name breaks verification.
    #[test]
    fn tool_calls_are_signed_into_the_receipt_streamed_or_not() {
        let dir = tempfile::tempdir().unwrap();
        let json = br#"{"choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"call_a","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}},{"id":"call_b","type":"function","function":{"name":"send_email","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#;
        let (engine, _seen) = fake_engine(http_response("application/json", json));
        let rec = recorder(dir.path());
        let (proxy, stop) = start_proxy(engine, Arc::clone(&rec));
        let raw = roundtrip(proxy, CHAT_REQ);
        assert_eq!(split_body(&raw), json, "relayed unchanged");
        stop.store(true, Ordering::SeqCst);

        let ev1 = r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"get_weather","arguments":"{\"city\":"}}]}}]}"#;
        let ev2 = r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"Paris\"}"}},{"index":1,"id":"call_b","function":{"name":"send_email","arguments":"{}"}}]}}]}"#;
        let mut sse = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for event in [format!("{ev1}\n\n"), format!("{ev2}\n\ndata: [DONE]\n\n")] {
            // Split each event across two chunks, mid-JSON.
            let (a, b) = event.as_bytes().split_at(event.len() / 2);
            for part in [a, b] {
                sse.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
                sse.extend_from_slice(part);
                sse.extend_from_slice(b"\r\n");
            }
        }
        sse.extend_from_slice(b"0\r\n\r\n");
        let (engine, _seen) = fake_engine(Box::leak(sse.into_boxed_slice()));
        let (proxy, stop) = start_proxy(engine, Arc::clone(&rec));
        roundtrip(proxy, CHAT_REQ);
        stop.store(true, Ordering::SeqCst);

        let entries = wait_entries(&rec, 2);
        let (plain, streamed) = (read_receipt(&entries[0]), read_receipt(&entries[1]));
        for att in [&plain, &streamed] {
            assert_eq!(att.spec_version, "2.1");
            let signed = &att.statement.predicate["execution"]["request"]["tool_calls"];
            assert_eq!(signed[0]["name"], "get_weather");
            assert_eq!(signed[0]["id"], "call_a");
            assert_eq!(
                signed[0]["arguments_hash"],
                sha256_hex(br#"{"city":"Paris"}"#)
            );
            assert_eq!(signed[1]["name"], "send_email");
            assert_eq!(signed.as_array().unwrap().len(), 2);
        }
        assert_eq!(
            plain.execution.request.as_ref().unwrap().tool_calls,
            streamed.execution.request.as_ref().unwrap().tool_calls
        );

        let vk = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let log = AttestationLog::open(rec.log_dir()).unwrap();
        assert_eq!(log.verify_chain(&[vk], None).unwrap().count, 2);
        let mut doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&entries[1]).unwrap()).unwrap();
        doc["execution"]["request"]["tool_calls"][1]["name"] = "noop".into();
        std::fs::write(&entries[1], serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
        let err = log.verify_chain(&[vk], None).unwrap_err().to_string();
        assert!(err.contains("TAMPERED"), "{err}");
    }

    #[test]
    fn plain_answers_keep_the_2_0_receipt_and_gzip_is_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let rec = recorder(dir.path());
        let (engine, _seen) = fake_engine(http_response(
            "application/json",
            br#"{"choices":[{"message":{"content":"hi"}}]}"#,
        ));
        let (proxy, stop) = start_proxy(engine, Arc::clone(&rec));
        roundtrip(proxy, CHAT_REQ);
        stop.store(true, Ordering::SeqCst);
        let gz: &'static [u8] = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n\x1f\x8b";
        let (engine, _seen) = fake_engine(gz);
        let (proxy, stop) = start_proxy(engine, Arc::clone(&rec));
        roundtrip(proxy, CHAT_REQ);
        stop.store(true, Ordering::SeqCst);

        let entries = wait_entries(&rec, 2);
        let plain = read_receipt(&entries[0]);
        assert_eq!(plain.spec_version, "2.0");
        assert!(!std::fs::read_to_string(&entries[0])
            .unwrap()
            .contains("tool_calls"));
        let gz = read_receipt(&entries[1]);
        let req = gz.execution.request.unwrap();
        assert!(req.tool_calls_incomplete && req.tool_calls.is_none());
        assert_eq!(gz.spec_version, "2.1");
    }

    fn chat_post(body: &str) -> Vec<u8> {
        format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// One proxied call: fresh fake engine answering `answer`.
    fn proxied(rec: &Arc<CallRecorder>, request: &[u8], answer: &[u8]) {
        let (engine, _seen) = fake_engine(http_response("application/json", answer));
        let (proxy, stop) = start_proxy(engine, Arc::clone(rec));
        roundtrip(proxy, request);
        stop.store(true, Ordering::SeqCst);
    }

    /// The agent loop through the proxy: turn 1 offers tools and gets a
    /// call, turn 2 replays it with its result. The trail links them; a
    /// third turn feeding a result for a call never issued is reported.
    #[test]
    fn request_side_tool_context_is_signed_and_linked_across_the_trail() {
        let dir = tempfile::tempdir().unwrap();
        let rec = recorder(dir.path());
        let tools = r#""tools":[{"type":"function","function":{"name":"get_weather"}}]"#;
        let call = r#"{"id":"call_a","type":"function","function":{"name":"get_weather","arguments":"{}"}}"#;
        let answer = format!(
            r#"{{"choices":[{{"index":0,"message":{{"role":"assistant","tool_calls":[{call}]}}}}]}}"#
        );
        let text = br#"{"choices":[{"message":{"content":"18C"}}]}"#;
        let turn1 = format!(r#"{{{tools},"messages":[{{"role":"user","content":"w?"}}]}}"#);
        let history = format!(
            r#"{{"role":"assistant","tool_calls":[{call}]}},{{"role":"tool","tool_call_id":"call_a","content":"18C"}}"#
        );
        let turn2 =
            format!(r#"{{{tools},"messages":[{{"role":"user","content":"w?"}},{history}]}}"#);
        proxied(&rec, &chat_post(&turn1), answer.as_bytes());
        wait_entries(&rec, 1);
        proxied(&rec, &chat_post(&turn2), text);

        let entries = wait_entries(&rec, 2);
        let second = read_receipt(&entries[1]);
        let req = second.execution.request.as_ref().unwrap();
        assert_eq!(second.spec_version, "2.1");
        assert_eq!(req.tool_results.as_ref().unwrap()[0].id, "call_a");
        assert_eq!(
            req.tool_results.as_ref().unwrap()[0].content_hash,
            sha256_hex(b"18C")
        );
        assert_eq!(req.tool_history.as_ref().unwrap()[0].name, "get_weather");
        erebus_core::attest::check_request_body(&second, turn2.as_bytes()).unwrap();

        let vk = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let log = AttestationLog::open(rec.log_dir()).unwrap();
        let linkage = log.verify_chain(&[vk], None).unwrap().linkage;
        assert_eq!((linkage.issued, linkage.answered), (1, 1));
        assert!(linkage.anomalies.is_empty() && linkage.unanswered.is_empty());

        let injected =
            r#"{"messages":[{"role":"tool","tool_call_id":"call_evil","content":"ok"}]}"#;
        proxied(&rec, &chat_post(injected), text);
        wait_entries(&rec, 3);
        let linkage = log.verify_chain(&[vk], None).unwrap().linkage;
        assert_eq!(linkage.anomalies.len(), 1, "{linkage:?}");
        assert_eq!(linkage.anomalies[0].receipt, 3);
        assert_eq!(linkage.anomalies[0].id.as_deref(), Some("call_evil"));
    }

    #[test]
    fn get_passes_through_unrecorded_and_bad_requests_get_status() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, _seen) = fake_engine(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let rec = recorder(dir.path());
        let (proxy, stop) = start_proxy(engine, Arc::clone(&rec));

        let raw = roundtrip(proxy, b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(split_body(&raw), b"ok");
        let raw = roundtrip(
            proxy,
            b"POST /v1/x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        );
        assert!(
            raw.starts_with(b"HTTP/1.1 411 "),
            "{}",
            String::from_utf8_lossy(&raw)
        );
        let raw = roundtrip(proxy, b"garbage\r\n\r\n");
        assert!(
            raw.starts_with(b"HTTP/1.1 400 "),
            "{}",
            String::from_utf8_lossy(&raw)
        );

        std::thread::sleep(Duration::from_millis(100));
        assert!(AttestationLog::open(rec.log_dir())
            .unwrap()
            .entries()
            .unwrap()
            .is_empty());
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn engine_down_yields_502() {
        let dir = tempfile::tempdir().unwrap();
        let dead = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let rec = recorder(dir.path());
        let (proxy, stop) = start_proxy(dead, rec);
        let raw = roundtrip(proxy, CHAT_REQ);
        assert!(
            raw.starts_with(b"HTTP/1.1 502 "),
            "{}",
            String::from_utf8_lossy(&raw)
        );
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn framing_rules() {
        let h = Head::parse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n").unwrap();
        assert_eq!(h.response_framing(Some(200), false), Framing::Chunked);
        assert_eq!(h.response_framing(Some(200), true), Framing::None);
        assert_eq!(h.response_framing(Some(204), false), Framing::None);
        let h = Head::parse(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n").unwrap();
        assert_eq!(h.response_framing(Some(200), false), Framing::Length(12));
        let h = Head::parse(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        assert_eq!(h.response_framing(Some(200), false), Framing::Close);
        assert_eq!(parse_chunk_size(b"1A;foo=bar\r\n").unwrap(), 26);
        assert!(parse_chunk_size(b"zz\r\n").is_err());
        let h =
            Head::parse(b"GET / HTTP/1.1\r\nConnection: keep-alive\r\nHost: a\r\n\r\n").unwrap();
        assert_eq!(
            h.serialize_close(),
            b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"
        );
    }

    /// Recording happens on the connection thread after the response is
    /// flushed, so poll briefly.
    fn wait_entries(rec: &CallRecorder, n: usize) -> Vec<PathBuf> {
        let log = AttestationLog::open(rec.log_dir()).unwrap();
        for _ in 0..100 {
            let entries = log.entries().unwrap();
            if entries.len() >= n {
                return entries;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("expected {n} receipts in {}", rec.log_dir().display());
    }
}
