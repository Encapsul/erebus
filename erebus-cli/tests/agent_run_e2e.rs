//! `erebus agent run` against a fake OpenAI-compatible HTTP LLM (+ fake MCP).
//!
//! Covers: tool loop (echo), MCP stdio tools, SSE streaming with one receipt
//! per assembled body, help text, honest limit. Unix only.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::tempdir;

/// Fake OpenAI-compat LLM: tools → `get_weather` or echo; then text. SSE if asked.
struct FakeLlm {
    base: String,
    child: Child,
}

impl FakeLlm {
    fn start() -> Self {
        let script = include_str!("../../examples/agent/fake_llm.py");
        // Unique path per start() — tests run in parallel and share one PID.
        let path = std::env::temp_dir().join(format!(
            "erebus-agent-llm-{}-{}.py",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, script).unwrap();
        let mut child = Command::new("python3")
            .arg(&path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("python3");
        let stdout = child.stdout.take().expect("stdout");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut lines = BufReader::new(stdout).lines();
            let _ = tx.send(lines.next().transpose().ok().flatten());
        });
        let port_line = rx
            .recv_timeout(Duration::from_secs(5))
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                let _ = child.kill();
                panic!("fake LLM port missing within 5s ({})", path.display());
            });
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

fn examples_agent() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../examples/agent")
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

fn trail_json_count(trail: &Path) -> usize {
    std::fs::read_dir(trail)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .count()
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
    assert!(
        stdout.contains("weather-ok") || stdout.contains("done-ok"),
        "{stdout}"
    );
    assert!(
        stderr.contains("Execution proven (signed receipt)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("Task success is a separate layer"),
        "{stderr}"
    );

    assert_eq!(
        trail_json_count(&trail),
        2,
        "expected 2 model-call receipts"
    );
    let tool_trail = dir.path().join("run.tools.attest.d");
    assert_eq!(
        trail_json_count(&tool_trail),
        1,
        "expected 1 in-process tool receipt"
    );
    let mut entries: Vec<_> = std::fs::read_dir(&trail)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
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
    let chain = Command::new(erebus_bin())
        .args([
            "verify-attest",
            "--chain",
            trail.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--tool-trail",
            tool_trail.to_str().unwrap(),
            "--require-tool-execution",
        ])
        .output()
        .unwrap();
    assert!(
        chain.status.success(),
        "tool-trail chain failed: {}",
        String::from_utf8_lossy(&chain.stderr)
    );
}

#[test]
fn agent_run_tool_trail_required_fails_when_forged_or_missing() {
    let dir = tempdir().unwrap();
    let (key, trusted) = keygen(dir.path());
    let llm = FakeLlm::start();
    let trail = dir.path().join("run.attest.d");
    let tool_trail = dir.path().join("tools.attest.d");

    let out = Command::new(erebus_bin())
        .args([
            "agent",
            "run",
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
            "--tool-trail",
            tool_trail.to_str().unwrap(),
            "--allow-tool",
            "echo",
            "--require-tool-execution",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(trail_json_count(&tool_trail), 1);

    // Missing trail directory: verify refuses (not "nothing executed").
    let missing = Command::new(erebus_bin())
        .args([
            "verify-attest",
            "--chain",
            trail.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--tool-trail",
            dir.path().join("no-such-trail").to_str().unwrap(),
            "--require-tool-execution",
        ])
        .output()
        .unwrap();
    assert!(!missing.status.success(), "missing tool trail should fail");

    // Empty forged trail: call executed in agent trail but no tool receipt.
    let empty = dir.path().join("empty.tools.attest.d");
    std::fs::create_dir_all(&empty).unwrap();
    let forged = Command::new(erebus_bin())
        .args([
            "verify-attest",
            "--chain",
            trail.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--tool-trail",
            empty.to_str().unwrap(),
            "--require-tool-execution",
        ])
        .output()
        .unwrap();
    assert_eq!(
        forged.status.code(),
        Some(2),
        "stderr={}",
        String::from_utf8_lossy(&forged.stderr)
    );
    let stderr = String::from_utf8_lossy(&forged.stderr);
    assert!(
        stderr.contains("no attested tool executed") || stderr.contains("result_without_execution"),
        "{stderr}"
    );
}

#[test]
fn agent_run_mcp_stdio_and_stream() {
    let dir = tempdir().unwrap();
    let (key, _) = keygen(dir.path());
    let llm = FakeLlm::start();
    let trail = dir.path().join("mcp.attest.d");
    let mcp = examples_agent().join("fake_mcp.py");
    assert!(mcp.is_file(), "missing {}", mcp.display());
    let spec = format!(
        r#"["python3","{}"]"#,
        mcp.to_str().unwrap().replace('\\', "\\\\")
    );

    let out = Command::new(erebus_bin())
        .args([
            "agent",
            "run",
            "--base-url",
            &llm.base,
            "--model",
            "fake",
            "--task",
            "weather?",
            "--attest-key",
            key.to_str().unwrap(),
            "--attest-log",
            trail.to_str().unwrap(),
            "--mcp-stdio",
            &spec,
            "--allow-mcp",
            "--stream",
        ])
        .env("WEATHER", "22C")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("weather-ok"), "{stdout}");
    assert!(stderr.contains("streaming display is unsigned"), "{stderr}");
    assert_eq!(trail_json_count(&trail), 2);
    let tool_trail = dir.path().join("mcp.tools.attest.d");
    assert_eq!(trail_json_count(&tool_trail), 1, "MCP tool receipt");
    assert!(
        stderr.contains("tool trail"),
        "stderr should mention tool trail: {stderr}"
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
    assert!(String::from_utf8_lossy(&out.stdout).contains("weather-ok"));
    assert_eq!(trail_json_count(&trail), 1);
}

#[test]
fn agent_run_help_lists_mcp_stream_encapsulate() {
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
    assert!(text.contains("--allow-mcp"));
    assert!(text.contains("--mcp"));
    assert!(text.contains("--mcp-stdio"));
    assert!(text.contains("--stream"));
    assert!(text.contains("--encapsulate"));
    assert!(text.contains("--expected-output-hash"));
    assert!(text.contains("--response-body"));
    assert!(text.contains("--tool-trail"));
    assert!(text.contains("--tool-attest-key"));
    assert!(text.contains("--require-tool-execution"));
    assert!(text.contains("--no-tool-attest"));
}

#[test]
fn agent_build_help_exists() {
    let out = Command::new(erebus_bin())
        .args(["agent", "build", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--output"));
    assert!(text.contains("--task"));
}
