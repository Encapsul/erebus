//! ROADMAP P0-3 acceptance: `erebus serve --attest-key` is an attesting
//! reverse proxy. A fake `llama-server` (python http.server) is embedded in
//! the bundle; 3 chat calls → 3 chained receipts → `verify-attest --chain`
//! OK; a tampered receipt → TAMPERED.

#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tempfile::tempdir;

/// Fake engine: honours `--host/--port`, answers `/health` and echoes the
/// request body length inside a chat-completion-shaped JSON.
const FAKE_LLAMA_SERVER: &str = r#"#!/usr/bin/env python3
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

args = sys.argv[1:]
host = args[args.index("--host") + 1]
port = int(args[args.index("--port") + 1])

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *a):
        pass
    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        self._send(200, b'{"status":"ok"}')
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        reply = {"choices": [{"message": {"role": "assistant", "content": f"echo:{len(body)}"}}]}
        self._send(200, json.dumps(reply).encode())

HTTPServer((host, port), H).serve_forever()
"#;

fn erebus_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_erebus"))
}

/// Bundle whose rootfs carries the fake engine at `bin/llama-server` and a
/// placeholder GGUF (classification is by extension).
fn make_bundle(dir: &Path) -> PathBuf {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    use std::os::unix::fs::PermissionsExt;
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(rootfs.join("bin")).unwrap();
    let engine = rootfs.join("bin/llama-server");
    std::fs::write(&engine, FAKE_LLAMA_SERVER).unwrap();
    std::fs::set_permissions(&engine, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(rootfs.join("model.gguf"), b"GGUF-placeholder").unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": "agent",
        "author": "test-user",
        "layers": [{"kind": "model", "name": "model.gguf", "size": 16}],
    });
    let bin_path = dir.join("agent.erebus");
    assemble_erebus(
        &bin_path,
        &AssemblyInput {
            stub_bytes: b"STUB",
            payload: &payload,
            meta_bytes: serde_json::to_vec(&meta).unwrap().as_slice(),
            encrypt: false,
            squashfs: false,
            target_arch: None,
            sisr: None,
        },
    )
    .unwrap();
    bin_path
}

fn keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let key_dir = dir.join("keys");
    let status = Command::new(erebus_bin())
        .args(["keygen", "--key-dir", key_dir.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let key = std::fs::read_dir(&key_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "key"))
        .expect("key file");
    (key, key_dir)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Stop `serve` on drop so a failing assertion never leaks the process.
/// SIGTERM first: that is the path where `serve` reaps its engine child; a
/// bare SIGKILL would orphan the fake llama-server.
struct Serve(Child);

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http(port: u16, request: &str) -> String {
    let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    c.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).unwrap();
    out
}

fn wait_ready(port: u16, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            panic!("erebus serve exited early: {status}");
        }
        if let Ok(mut c) = TcpStream::connect(("127.0.0.1", port)) {
            let _ = c.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n");
            let mut s = String::new();
            let _ = c.read_to_string(&mut s);
            if s.starts_with("HTTP/1.1 200") {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("proxy on {port} never became healthy");
}

fn verify_chain(trail: &Path, trusted: &Path, bundle: &Path) -> std::process::Output {
    Command::new(erebus_bin())
        .args([
            "verify-attest",
            "--chain",
            trail.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
        ])
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

#[test]
fn serve_attests_every_call_into_a_verifiable_chain() {
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("python3 missing, skipping");
        return;
    }
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let (key, trusted) = keygen(dir.path());
    let trail = dir.path().join("trail");
    let port = free_port();

    let child = Command::new(erebus_bin())
        .args([
            "serve",
            bundle.to_str().unwrap(),
            "--port",
            &port.to_string(),
            "--ngl",
            "off",
            "--attest-key",
            key.to_str().unwrap(),
            "--attest-log",
            trail.to_str().unwrap(),
        ])
        .env("XDG_CACHE_HOME", dir.path().join("cache"))
        .env("NO_COLOR", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut serve = Serve(child);
    wait_ready(port, &mut serve.0);

    let body = r#"{"model":"local","messages":[{"role":"user","content":"hi"}]}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    for _ in 0..3 {
        let resp = http(port, &request);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert!(
            resp.contains(&format!("echo:{}", body.len())),
            "engine output must pass through unchanged: {resp}"
        );
    }
    drop(serve);

    let mut receipts: Vec<PathBuf> = std::fs::read_dir(&trail)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    receipts.sort();
    assert_eq!(
        receipts.len(),
        3,
        "one receipt per POST (health GETs excluded)"
    );

    let out = verify_chain(&trail, &trusted, &bundle);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(stderr.contains("3 receipt(s)"), "{stderr}");

    // Every receipt names the call and binds it to the response bytes.
    let att: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipts[2]).unwrap()).unwrap();
    assert_eq!(att["execution"]["request"]["method"], "POST");
    assert_eq!(att["execution"]["request"]["path"], "/v1/chat/completions");
    assert_eq!(att["execution"]["request"]["status"], 200);
    assert!(att["execution"]["output_hash"]
        .as_str()
        .is_some_and(|h| h.starts_with("sha256:")));
    assert!(att["execution"]["prev_attestation_hash"].is_string());

    // Rewriting a recorded response hash is caught.
    let mut doc = att;
    doc["execution"]["output_hash"] = serde_json::Value::String("sha256:forged".into());
    std::fs::write(&receipts[2], serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    let out = verify_chain(&trail, &trusted, &bundle);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("TAMPERED"), "{stderr}");
}
