//! `erebus agent run` against a fake OpenAI-compatible HTTP LLM.
//!
//! One-shot and a short tool loop (echo), receipts chained, honest limit on
//! stderr, `--response-body` + `verify-attest` round-trip. Unix only.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::tempdir;

/// Fake OpenAI-compat LLM: first tools turn → `echo` call; then text.
struct FakeLlm {
    base: String,
    child: Child,
}

impl FakeLlm {
    fn start() -> Self {
        let script = r#"
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a):
        pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        req = json.loads(body or b"{}")
        msgs = req.get("messages") or []
        answered = bool(msgs) and msgs[-1].get("role") == "tool"
        if req.get("tools") and not answered:
            reply = {"choices": [{"message": {"role": "assistant", "tool_calls": [
                {"id": "call_echo", "type": "function",
                 "function": {"name": "echo", "arguments": "{\"text\":\"pong\"}"}}
            ]}}]}
        else:
            reply = {"choices": [{"message": {"role": "assistant", "content": "done-ok"}}]}
        raw = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

httpd = HTTPServer(("127.0.0.1", 0), H)
print(httpd.server_address[1], flush=True)
httpd.serve_forever()
"#;
        let path = std::env::temp_dir().join(format!("erebus-agent-llm-{}.py", std::process::id()));
        std::fs::write(&path, script).unwrap();
        let mut child = Command::new("python3")
            .arg(&path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("python3");
        let stdout = child.stdout.take().expect("stdout");
        let mut lines = BufReader::new(stdout).lines();
        let port_line = lines
            .next()
            .transpose()
            .ok()
            .flatten()
            .expect("fake LLM port");
        let port: u16 = port_line.trim().parse().expect("port number");
        let _ = std::fs::remove_file(&path);
        let base = format!("http://127.0.0.1:{port}");
        wait_ready(&base, Duration::from_secs(5));
        Self { base, child }
    }
}

impl Drop for FakeLlm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_ready(base: &str, budget: Duration) {
    let addr = base.trim_start_matches("http://");
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if let Ok(mut s) = TcpStream::connect(addr) {
            let _ = s.set_read_timeout(Some(Duration::from_millis(200)));
            let req = b"POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\n\
Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
            if s.write_all(req).is_ok() {
                let mut buf = [0u8; 12];
                if s.read(&mut buf).is_ok() && buf.starts_with(b"HTTP/1.1") {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    panic!("fake LLM not ready at {base}");
}

fn erebus_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_erebus"))
}

fn keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let key_dir = dir.join("keys");
    assert!(Command::new(erebus_bin())
        .args(["keygen", "--key-dir", key_dir.to_str().unwrap()])
        .status()
        .unwrap()
        .success());
    let key = std::fs::read_dir(&key_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "key"))
        .expect("key");
    (key, key_dir)
}

#[test]
fn agent_run_tool_loop_emits_receipts_and_honest_limit() {
    let dir = tempdir().unwrap();
    let (key, trusted) = keygen(dir.path());
    let llm = FakeLlm::start();
    let trail = dir.path().join("run.attest.d");
    let body_out = dir.path().join("last.json");

    let out = Command::new(erebus_bin())
        .args([
            "agent",
            "run",
            "--provider",
            "openai-compat",
            "--base-url",
            &llm.base,
            "--model",
            "fake",
            "--task",
            "ping",
            "--attest-key",
            key.to_str().unwrap(),
            "--attest-log",
            trail.to_str().unwrap(),
            "--allow-tool",
            "echo",
            "--response-body",
            body_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("done-ok"), "{stdout}");
    assert!(
        stderr.contains("Execution proven (signed receipt)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Task success is a separate layer"),
        "{stderr}"
    );

    let mut entries: Vec<_> = std::fs::read_dir(&trail)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    assert_eq!(entries.len(), 2, "expected 2 model-call receipts");
    entries.sort();
    let last = entries.last().unwrap();
    let verify = Command::new(erebus_bin())
        .args([
            "verify-attest",
            last.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--response-body",
            body_out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn agent_run_oneshot_without_tools() {
    let dir = tempdir().unwrap();
    let (key, _) = keygen(dir.path());
    let llm = FakeLlm::start();
    let trail = dir.path().join("oneshot.attest.d");

    let out = Command::new(erebus_bin())
        .args([
            "agent",
            "run",
            "--base-url",
            &llm.base,
            "--model",
            "fake",
            "--task",
            "hi",
            "--attest-key",
            key.to_str().unwrap(),
            "--attest-log",
            trail.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("done-ok"));
    let n = std::fs::read_dir(&trail)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .count();
    assert_eq!(n, 1);
}

#[test]
fn agent_run_help_lists_providers_and_secret_file() {
    let out = Command::new(erebus_bin())
        .args(["agent", "run", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("openai-compat"));
    assert!(text.contains("anthropic"));
    assert!(text.contains("--api-key-file"));
    assert!(text.contains("--allow-tool"));
    assert!(text.contains("--expected-output-hash"));
    assert!(text.contains("--response-body"));
}
