//! End-to-end acceptance tests for the proof chain (ROADMAP P0-1 / P0-2):
//! attest → verify-attest OK → tamper unsigned field → exit 2 → wrong bundle →
//! exit 2 → chained trail → edit/delete a receipt → exit 2.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn erebus() -> Command {
    let mut cmd = Command::cargo_bin("erebus").unwrap();
    cmd.env("NO_COLOR", "1");
    cmd
}

/// Minimal signed-format bundle (stub placeholder + tar.zst payload + metadata).
fn make_bundle(dir: &Path, name: &str, marker: &str) -> PathBuf {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    let rootfs = dir.join(format!("rootfs-{name}"));
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), format!("print('{marker}')")).unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": name,
        "author": "test-user",
        "license": "MIT",
        "layers": [{"kind": "runtime", "name": "runtime/python3", "size": 1024}],
    });
    let bin_path = dir.join(format!("{name}.erebus"));
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

/// `erebus keygen` into `dir`; returns (private key path, dir usable as
/// `--trusted-dir` since it holds the matching `.pub`).
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

fn attest(bundle: &Path, key: &Path, out: &Path, extra: &[&str]) {
    let mut args = vec![
        "attest",
        bundle.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
        "--output",
        out.to_str().unwrap(),
        "--quiet",
    ];
    args.extend_from_slice(extra);
    erebus().args(&args).assert().success();
}

#[test]
fn verify_attest_accepts_genuine_receipt_and_binds_bundle() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path(), "agent", "hello");
    let (key, trusted) = keygen(dir.path());
    let out = dir.path().join("agent.erebus.attest");
    attest(&bundle, &key, &out, &["--no-log"]);

    erebus()
        .args([
            "verify-attest",
            out.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("OK: attestation verified"))
        .stderr(predicate::str::contains("bundle file matches"));

    // JSON report exposes only signed facts.
    let json = erebus()
        .args([
            "verify-attest",
            out.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(json.status.success());
    let v: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(v["verified"], true);
    assert_eq!(v["spec_version"], "2.0");
    assert_eq!(v["envelope"], true);
    assert!(v["bundle_sha256"].as_str().unwrap().len() == 64);
}

#[test]
fn verify_attest_rejects_edited_unsigned_field() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path(), "agent", "hello");
    let (key, trusted) = keygen(dir.path());
    let out = dir.path().join("agent.erebus.attest");
    attest(&bundle, &key, &out, &["--no-log"]);

    // Forge the human-readable copy: signature over `statement` still valid.
    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    doc["execution"]["exit_code"] = serde_json::json!(0);
    doc["execution"]["output_hash"] = serde_json::json!("sha256:forged");
    std::fs::write(&out, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();

    erebus()
        .args([
            "verify-attest",
            out.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("TAMPERED: execution mismatch"));
}

#[test]
fn verify_attest_rejects_forged_key_fingerprint() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path(), "agent", "hello");
    let (key, trusted) = keygen(dir.path());
    let out = dir.path().join("agent.erebus.attest");
    attest(&bundle, &key, &out, &["--no-log"]);

    let mut doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    doc["signature"]["key_fingerprint"] = serde_json::json!("sha256:somebody-else");
    std::fs::write(&out, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();

    erebus()
        .args([
            "verify-attest",
            out.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("TAMPERED: key_fingerprint"));
}

#[test]
fn verify_attest_rejects_receipt_for_another_bundle() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path(), "agent", "hello");
    let other = make_bundle(dir.path(), "other", "different");
    let (key, trusted) = keygen(dir.path());
    let out = dir.path().join("agent.erebus.attest");
    attest(&bundle, &key, &out, &["--no-log"]);

    erebus()
        .args([
            "verify-attest",
            out.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--bundle",
            other.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("TAMPERED: bundle mismatch"));
}

#[test]
fn verify_attest_rejects_untrusted_key() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path(), "agent", "hello");
    let (key, _) = keygen(dir.path());
    let other_dir = tempdir().unwrap();
    let (_, other_trusted) = keygen(other_dir.path());
    let out = dir.path().join("agent.erebus.attest");
    attest(&bundle, &key, &out, &["--no-log"]);

    erebus()
        .args([
            "verify-attest",
            out.to_str().unwrap(),
            "--trusted-dir",
            other_trusted.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "TAMPERED: signature does not match",
        ));
}

#[test]
fn trail_chains_receipts_and_detects_tampering() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path(), "agent", "hello");
    let (key, trusted) = keygen(dir.path());
    let out = dir.path().join("agent.erebus.attest");
    let trail = dir.path().join("agent.erebus.attest.d");

    // Two runs → two chained receipts (default trail = <output>.d).
    attest(&bundle, &key, &out, &[]);
    attest(&bundle, &key, &out, &[]);

    let mut entries: Vec<PathBuf> = std::fs::read_dir(&trail)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    entries.sort();
    assert_eq!(entries.len(), 2, "every attest appends one receipt");
    assert!(trail.join("HEAD").exists());

    // The second receipt's signed prev hash links to the first file.
    let second: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&entries[1]).unwrap()).unwrap();
    let prev = second["statement"]["predicate"]["execution"]["prev_attestation_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let first_hash = erebus_core::attest_log::file_hash(&std::fs::read(&entries[0]).unwrap());
    assert_eq!(prev, first_hash);

    erebus()
        .args([
            "verify-attest",
            "--chain",
            trail.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "OK: chain verified — 2 receipt(s)",
        ));

    // Edit the first receipt's unsigned copy → exit 2.
    let text = std::fs::read_to_string(&entries[0]).unwrap();
    std::fs::write(
        &entries[0],
        text.replacen("\"builder\": \"erebus-cli", "\"builder\": \"evil-cli", 1),
    )
    .unwrap();
    erebus()
        .args([
            "verify-attest",
            "--chain",
            trail.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("TAMPERED"));

    // Restore, then delete the last receipt → HEAD mismatch → exit 2.
    std::fs::write(&entries[0], text).unwrap();
    std::fs::remove_file(&entries[1]).unwrap();
    erebus()
        .args([
            "verify-attest",
            "--chain",
            trail.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("HEAD"));
}

#[test]
fn attest_no_log_leaves_no_trail_and_log_flag_overrides_dir() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path(), "agent", "hello");
    let (key, _) = keygen(dir.path());
    let out = dir.path().join("agent.erebus.attest");

    attest(&bundle, &key, &out, &["--no-log"]);
    assert!(!dir.path().join("agent.erebus.attest.d").exists());

    let custom = dir.path().join("custom-trail");
    attest(&bundle, &key, &out, &["--log", custom.to_str().unwrap()]);
    assert!(custom.join("HEAD").exists());
}

#[test]
fn verify_attest_requires_receipt_or_chain() {
    erebus()
        .arg("verify-attest")
        .assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}
