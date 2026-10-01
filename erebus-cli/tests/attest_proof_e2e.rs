//! End-to-end acceptance test for ROADMAP P0-5: `erebus attest --push`
//! against the real `scripts/registry_server.py`, then
//! `erebus verify-attest --proof` **offline** (registry stopped), then tamper.
//!
//! This is also the cross-language check that the pure-Python Ed25519 signer
//! and Merkle tree agree byte-for-byte with `ed25519-dalek` / `merkle.rs`.
//! Skips (with a notice) when `python3` is unavailable.

mod common;

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::tempdir;

fn erebus() -> Command {
    let mut cmd = Command::cargo_bin("erebus").unwrap();
    cmd.env("NO_COLOR", "1");
    cmd
}

fn make_bundle(dir: &Path) -> PathBuf {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), "print('proof')").unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": "agent", "author": "test-user", "license": "MIT",
        "layers": [{"kind": "runtime", "name": "runtime/python3", "size": 1024}],
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
    erebus()
        .args(["keygen", "--key-dir", key_dir.to_str().unwrap()])
        .assert()
        .success();
    let key = std::fs::read_dir(&key_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "key"))
        .expect("key file");
    (key, key_dir)
}

/// The real registry, killed on drop.
struct Registry {
    _process: common::registry::RegistryProcess,
    base: String,
}

impl Registry {
    fn start(root: &Path) -> Option<Self> {
        let process = common::registry::spawn_registry(root, "e2e-origin")?;
        let base = process.base.clone();
        Some(Self {
            _process: process,
            base,
        })
    }

    fn register(&self) -> String {
        let body = serde_json::json!({"username": "alice", "password": "pw12345678"});
        let (status, json) = http(
            &self.base,
            "POST",
            "/auth/register",
            None,
            Some(body.to_string().as_bytes()),
        )
        .expect("register");
        assert_eq!(status, 200, "{json}");
        json["token"].as_str().unwrap().to_string()
    }

    fn log_key_hex(&self) -> String {
        let (_, json) = http(&self.base, "GET", "/log/key", None, None).unwrap();
        json["public_key_hex"].as_str().unwrap().to_string()
    }
}

/// Tiny HTTP/1.1 client (no keep-alive) — enough for JSON endpoints.
fn http(
    base: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
) -> Option<(u16, serde_json::Value)> {
    use std::io::Write;
    let addr = base.trim_start_matches("http://");
    let mut s = std::net::TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let body = body.unwrap_or(&[]);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    req.push_str(&format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    ));
    s.write_all(req.as_bytes()).ok()?;
    s.write_all(body).ok()?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).ok()?;
    let text = String::from_utf8_lossy(&resp);
    let status: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
    let json_part = text.split("\r\n\r\n").nth(1).unwrap_or("{}");
    let json = serde_json::from_str(json_part).unwrap_or(serde_json::Value::Null);
    Some((status, json))
}

#[test]
fn attest_push_stores_proof_and_verify_attest_checks_it_offline() {
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 not found; skipping registry e2e");
        return;
    }
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let (key, trusted) = keygen(dir.path());
    let registry_root = dir.path().join("registry");
    std::fs::create_dir_all(&registry_root).unwrap();
    let Some(registry) = Registry::start(&registry_root) else {
        eprintln!("could not start python3 registry; skipping");
        return;
    };
    let token = registry.register();
    let log_key = registry.log_key_hex();

    // Two pushes so the second leaf has a non-trivial inclusion path. Ed25519
    // is deterministic and `attested_at` has second resolution, so identical
    // receipts within one second would (correctly) dedupe into one leaf.
    let mut receipts = Vec::new();
    for i in 0..2 {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(1100));
        }
        let out = dir.path().join(format!("receipt{i}.attest"));
        erebus()
            .args([
                "attest",
                bundle.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
            ])
            .args(["--output", out.to_str().unwrap(), "--no-log", "--push"])
            .args(["--registry", &registry.base, "--token", &token])
            .assert()
            .success()
            .stderr(predicate::str::contains("proof:"))
            .stderr(predicate::str::contains(format!("leaf #{i} of {}", i + 1)));
        let proof = dir.path().join(format!("receipt{i}.attest.proof.json"));
        assert!(proof.is_file(), "proof file must sit next to the receipt");
        receipts.push((out, proof));
    }
    // Everything below is offline.
    drop(registry);

    let (receipt, proof) = &receipts[1];
    let verify = |extra: &[&str]| {
        let mut cmd = erebus();
        cmd.args(["verify-attest", receipt.to_str().unwrap()])
            .args(["--trusted-dir", trusted.to_str().unwrap(), "--proof"]);
        cmd.args(extra);
        cmd
    };

    // Log key unknown → refuse (a proof signed by anyone proves nothing).
    verify(&[])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is not trusted"));

    verify(&["--log-key", &log_key])
        .assert()
        .success()
        .stderr(predicate::str::contains("OK: attestation verified"))
        .stderr(predicate::str::contains(
            "OK: transparency log — leaf #1 of 2",
        ))
        .stderr(predicate::str::contains("e2e-origin"))
        .stderr(predicate::str::contains("anchor:   none"));

    let json_out = verify(&["--log-key", &log_key, "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
    assert_eq!(report["log_proof"]["verified"], true);
    assert_eq!(report["log_proof"]["tree_size"], 2);

    // Tamper 1: rewrite the receipt with different whitespace — same JSON,
    // different bytes. The leaf is over bytes, so this must fail.
    let original = std::fs::read(receipt).unwrap();
    let compact: serde_json::Value = serde_json::from_slice(&original).unwrap();
    std::fs::write(receipt, serde_json::to_vec(&compact).unwrap()).unwrap();
    verify(&["--log-key", &log_key])
        .assert()
        .failure()
        .stderr(predicate::str::contains("do not hash to the proof's leaf"));
    std::fs::write(receipt, &original).unwrap();

    // Tamper 2: swap in the other receipt's proof.
    verify(&[
        "--log-key",
        &log_key,
        "--proof-file",
        receipts[0].1.to_str().unwrap(),
    ])
    .assert()
    .failure()
    .stderr(predicate::str::contains("TAMPERED"));

    // Tamper 3: forge the checkpoint size.
    let mut p: serde_json::Value = serde_json::from_slice(&std::fs::read(proof).unwrap()).unwrap();
    p["tree_size"] = serde_json::json!(3);
    p["checkpoint"]["size"] = serde_json::json!(3);
    std::fs::write(proof, serde_json::to_vec_pretty(&p).unwrap()).unwrap();
    verify(&["--log-key", &log_key])
        .assert()
        .failure()
        .stderr(predicate::str::contains("TAMPERED"));
}
