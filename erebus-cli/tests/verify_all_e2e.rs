//! Single-command evidence flow: `erebus verify <bundle> --all` chains the
//! bundle signature, the receipt, the trail, the proof, the approval and the
//! witness seal. A sidecar that exists is never accepted without its trust
//! anchor; peripheral commands stay behind the experimental flag.

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
fn make_bundle(dir: &Path) -> PathBuf {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), "print('verify-all')").unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": "agent",
        "author": "test-user",
        "license": "MIT",
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

/// `erebus keygen` into `dir/<name>`; returns (private key, key dir).
fn keygen(dir: &Path, name: &str) -> (PathBuf, PathBuf) {
    let key_dir = dir.join(name);
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

fn pub_in(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "pub"))
        .expect("pub file")
}

fn sign(bundle: &Path, key: &Path) {
    erebus()
        .args([
            "sign",
            bundle.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--quiet",
            "--no-input",
        ])
        .assert()
        .success();
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

fn verify_all_cmd(bundle: &Path, trusted: &Path, extra: &[&str]) -> Command {
    let mut cmd = erebus();
    cmd.args([
        "verify",
        bundle.to_str().unwrap(),
        "--all",
        "--trusted-dir",
        trusted.to_str().unwrap(),
        "--json",
    ]);
    cmd.args(extra);
    cmd
}

fn verify_all_json(bundle: &Path, trusted: &Path, extra: &[&str]) -> serde_json::Value {
    let out = verify_all_cmd(bundle, trusted, extra).output().unwrap();
    assert!(
        out.status.success(),
        "verify --all failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn verify_all_reports_bundle_receipt_and_chain() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let (key, trusted) = keygen(dir.path(), "keys");
    sign(&bundle, &key);
    let out = dir.path().join("agent.erebus.attest");
    attest(&bundle, &key, &out, &[]);

    let v = verify_all_json(&bundle, &trusted, &[]);
    assert_eq!(v["mode"], "all");
    assert_eq!(v["verified"], true);
    assert_eq!(v["bundle"]["verified"], true);
    assert_eq!(v["evidence"]["verified"], true);
    assert_eq!(v["evidence"]["chain"]["verified"], true);
    assert_eq!(v["evidence"]["chain"]["count"], 1);
    assert_eq!(v["evidence"]["log_proof"]["present"], false);
    assert_eq!(v["evidence"]["approval"]["present"], false);
    assert_eq!(v["evidence"]["witness"]["present"], false);

    erebus()
        .args([
            "verify",
            bundle.to_str().unwrap(),
            "--all",
            "--trusted-dir",
            trusted.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("OK: bundle signature verified"))
        .stderr(predicate::str::contains("OK: attestation verified"))
        .stderr(predicate::str::contains("OK: chain verified"));
}

#[test]
fn verify_all_requires_the_approver_key() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let (key, trusted) = keygen(dir.path(), "keys");
    sign(&bundle, &key);
    let (approver, approver_dir) = keygen(dir.path(), "approver-keys");
    let approval = dir.path().join("approval.json");
    erebus()
        .args([
            "approve",
            "--key",
            approver.to_str().unwrap(),
            "--decision",
            "allow",
            "--subject-file",
            bundle.to_str().unwrap(),
            "-o",
            approval.to_str().unwrap(),
        ])
        .assert()
        .success();

    let out = dir.path().join("agent.erebus.attest");
    attest(
        &bundle,
        &key,
        &out,
        &["--approval", approval.to_str().unwrap()],
    );

    // Present approval + missing anchor: fail closed.
    verify_all_cmd(&bundle, &trusted, &[])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--approver-key"));

    let approver_pub = pub_in(&approver_dir);
    let v = verify_all_json(
        &bundle,
        &trusted,
        &["--approver-key", approver_pub.to_str().unwrap()],
    );
    assert_eq!(v["evidence"]["approval"]["verified"], true);
    assert_eq!(v["evidence"]["approval"]["decision"], "allow");
}

#[test]
fn verify_all_requires_the_witness_key_when_sealed() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let (key, trusted) = keygen(dir.path(), "keys");
    sign(&bundle, &key);
    let out = dir.path().join("agent.erebus.attest");
    attest(&bundle, &key, &out, &[]);
    let trail = erebus_core::attest_log::default_log_dir(&out);
    let witness_dir = dir.path().join("witness");
    let state_dir = dir.path().join("witness-state");

    erebus()
        .env("ERE_WITNESS_STATE_DIR", &state_dir)
        .args(["witness", "keygen", "--dir", witness_dir.to_str().unwrap()])
        .assert()
        .success();
    let wkey = witness_dir.join("witness.key");
    erebus()
        .env("ERE_WITNESS_STATE_DIR", &state_dir)
        .env("ERE_WITNESS_KEY", &wkey)
        .args(["witness", "seal", "--trail", trail.to_str().unwrap()])
        .assert()
        .success();

    verify_all_cmd(&bundle, &trusted, &[])
        .env("ERE_WITNESS_STATE_DIR", &state_dir)
        .assert()
        .failure()
        .stderr(predicate::str::contains("--witness-key"));

    let wpub = pub_in(&witness_dir);
    let out = verify_all_cmd(
        &bundle,
        &trusted,
        &["--witness-key", wpub.to_str().unwrap()],
    )
    .env("ERE_WITNESS_STATE_DIR", &state_dir)
    .output()
    .unwrap();
    assert!(
        out.status.success(),
        "verify --all failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["evidence"]["witness"]["verified"], true);
}

#[test]
fn verify_all_fails_closed_when_a_proof_lacks_its_log_key() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let (key, trusted) = keygen(dir.path(), "keys");
    sign(&bundle, &key);
    let out = dir.path().join("agent.erebus.attest");
    attest(&bundle, &key, &out, &[]);

    // A proof file that exists but cannot be anchored must not be ignored.
    let proof = dir.path().join("agent.erebus.attest.proof.json");
    std::fs::write(&proof, b"{}").unwrap();

    verify_all_cmd(&bundle, &trusted, &[])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--log-key"));
}

#[test]
fn verify_all_rejects_a_tampered_receipt() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let (key, trusted) = keygen(dir.path(), "keys");
    sign(&bundle, &key);
    let out = dir.path().join("agent.erebus.attest");
    attest(&bundle, &key, &out, &[]);

    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    v["execution"]["os"] = serde_json::json!("tampered");
    std::fs::write(&out, serde_json::to_vec(&v).unwrap()).unwrap();

    verify_all_cmd(&bundle, &trusted, &[]).assert().failure();
}

#[test]
fn experimental_commands_are_gated() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("missing");
    let missing_s = missing.to_str().unwrap();
    let cases: &[&[&str]] = &[
        &["billing", "status", "--registry", "http://127.0.0.1:1"],
        &[
            "mirror",
            "export",
            "--dir",
            missing_s,
            "-o",
            missing_s,
            "--password-file",
            missing_s,
        ],
        &[
            "replicate",
            "full",
            "--leader",
            "http://127.0.0.1:1",
            "--dir",
            missing_s,
        ],
        &["dashboard"],
    ];
    for args in cases {
        erebus()
            .args(*args)
            .assert()
            .failure()
            .stderr(predicate::str::contains("is experimental"))
            .stderr(predicate::str::contains("--experimental"));
    }

    // Explicit opt-in reaches the command; it then fails for its own reason.
    erebus()
        .args([
            "--experimental",
            "billing",
            "status",
            "--registry",
            "http://127.0.0.1:1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is experimental").not());
    erebus()
        .env("ERE_EXPERIMENTAL", "1")
        .args(["billing", "status", "--registry", "http://127.0.0.1:1"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is experimental").not());
}

#[test]
fn verify_all_finds_the_receipt_written_for_a_non_erebus_filename() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let renamed = dir.path().join("renamed.bin");
    std::fs::copy(&bundle, &renamed).unwrap();
    let (key, trusted) = keygen(dir.path(), "keys");
    sign(&renamed, &key);

    // `attest` replaces the final extension, so this is where it actually
    // writes the receipt for `renamed.bin` — not `renamed.bin.attest`.
    let out = dir.path().join("renamed.erebus.attest");
    attest(&renamed, &key, &out, &[]);

    let v = verify_all_json(&renamed, &trusted, &[]);
    assert_eq!(v["verified"], true);
    assert_eq!(v["evidence"]["chain"]["verified"], true);
}

#[test]
fn unsigned_bundle_is_never_a_green_gate() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path()); // assembled unsigned

    let out = erebus()
        .args(["verify", bundle.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["signed"], false);
    assert_eq!(v["verified"], false);

    erebus()
        .args(["verify", bundle.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("file is not signed"));
}
