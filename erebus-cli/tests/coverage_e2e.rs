//! the evidence pack reports coverage derived from
//! its signed receipts, a run that bypassed the attesting gateway is visible
//! in that report, and editing the report is refused by `verify-evidence`.

use assert_cmd::Command;
use ed25519_dalek::SigningKey;
use erebus_core::attest::{
    append_receipt_with, load_signing_key, AttestationTemplate, ExecutionCapture, HeartbeatInfo,
    RequestInfo, Signers,
};
use erebus_core::attest_log::AttestationLog;
use predicates::prelude::*;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
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
    std::fs::write(rootfs.join("app/main.py"), "print('coverage')").unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({"name": "coverage", "author": "test-user", "license": "MIT"});
    let bundle = dir.join("agent.erebus");
    assemble_erebus(
        &bundle,
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
    bundle
}

fn keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let keys = dir.join("keys");
    erebus()
        .args(["keygen", "--key-dir", keys.to_str().unwrap()])
        .assert()
        .success();
    let key = std::fs::read_dir(&keys)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "key"))
        .expect("key file");
    (key, keys)
}

fn add(
    log: &AttestationLog,
    template: &AttestationTemplate,
    signers: &Signers<'_>,
    at: &str,
    capture: ExecutionCapture,
) {
    let capture = ExecutionCapture {
        attested_at: Some(at.to_string()),
        ..capture
    };
    append_receipt_with(template, signers, log, &capture).unwrap();
}

fn call() -> ExecutionCapture {
    ExecutionCapture {
        request: Some(RequestInfo {
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            status: Some(200),
            ..RequestInfo::default()
        }),
        ..ExecutionCapture::default()
    }
}

fn beat(sequence: u64, calls_since_previous: u64) -> ExecutionCapture {
    ExecutionCapture {
        heartbeat: Some(HeartbeatInfo {
            sequence,
            interval_secs: 60,
            calls_since_previous,
        }),
        ..ExecutionCapture::default()
    }
}

/// A launcher-attested execution that never went through the proxy.
fn direct_run() -> ExecutionCapture {
    ExecutionCapture {
        input_hash: Some("sha256:aaaa".to_string()),
        output_hash: Some("sha256:bbbb".to_string()),
        exit_code: Some(0),
        ..ExecutionCapture::default()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Flip `complete` in COVERAGE.json and rehash MANIFEST.json to match: the
/// report is still refused because it is re-derived from the signed receipts.
fn rewrite(src: &Path, dst: &Path) {
    let mut zin = zip::ZipArchive::new(std::fs::File::open(src).unwrap()).unwrap();
    let mut entries = Vec::new();
    for i in 0..zin.len() {
        let mut e = zin.by_index(i).unwrap();
        let name = e.name().unwrap().to_string();
        let mut bytes = Vec::new();
        e.read_to_end(&mut bytes).unwrap();
        entries.push((name, bytes));
    }
    let mut manifest = patched_manifest(&entries);
    let mut edited = Vec::new();
    for (name, bytes) in entries {
        if name == "COVERAGE.json" {
            let mut c: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            c["complete"] = serde_json::Value::Bool(true);
            let bytes = serde_json::to_vec_pretty(&c).unwrap();
            manifest["files"][name.as_str()] = serde_json::Value::String(sha256_hex(&bytes));
            edited.push((name, bytes));
        } else {
            edited.push((name, bytes));
        }
    }
    let mut zout = zip::ZipWriter::new(std::fs::File::create(dst).unwrap());
    let opts = zip::write::SimpleFileOptions::default();
    for (name, bytes) in edited {
        let bytes = if name == "MANIFEST.json" {
            serde_json::to_vec_pretty(&manifest).unwrap()
        } else {
            bytes
        };
        zout.start_file(name, opts).unwrap();
        zout.write_all(&bytes).unwrap();
    }
    zout.finish().unwrap();
}

fn patched_manifest(entries: &[(String, Vec<u8>)]) -> serde_json::Value {
    let (_, bytes) = entries
        .iter()
        .find(|(name, _)| name == "MANIFEST.json")
        .unwrap();
    let mut manifest: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    for (name, bytes) in entries {
        if name != "MANIFEST.json" {
            manifest["files"][name.as_str()] = serde_json::Value::String(sha256_hex(bytes));
        }
    }
    manifest
}

#[test]
fn evidence_pack_reports_coverage_and_detects_runs_outside_gateway() {
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let (key, trusted) = keygen(dir.path());
    let signing = load_signing_key(&key).unwrap();
    let signers = Signers::operator_only(&signing);
    let template = AttestationTemplate::from_bundle(&bundle).unwrap();
    let log = AttestationLog::open(&dir.path().join("trail")).unwrap();

    add(&log, &template, &signers, "2026-11-24T10:00:00Z", call());
    add(
        &log,
        &template,
        &signers,
        "2026-11-24T10:01:00Z",
        beat(1, 1),
    );
    add(
        &log,
        &template,
        &signers,
        "2026-11-24T10:02:00Z",
        direct_run(),
    );
    add(
        &log,
        &template,
        &signers,
        "2026-11-24T10:03:00Z",
        beat(3, 0),
    );

    let other = SigningKey::generate(&mut rand::rngs::OsRng);
    let log_key = hex::encode(other.verifying_key().as_bytes());
    let pack = dir.path().join("coverage.zip");
    erebus()
        .args(["evidence", "export", bundle.to_str().unwrap()])
        .args(["--trail", dir.path().join("trail").to_str().unwrap()])
        .args(["--trusted-dir", trusted.to_str().unwrap()])
        .args(["--log-key", &log_key])
        .arg("-o")
        .arg(&pack)
        .assert()
        .success();

    let out = erebus()
        .args(["verify-evidence", pack.to_str().unwrap(), "--json"])
        .args(["--bundle", bundle.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["verified"], true);
    assert_eq!(report["spec"], "erebus-evidence/2");
    assert_eq!(report["coverage"]["gateway_calls"], 1);
    assert_eq!(report["coverage"]["heartbeats"]["count"], 2);
    assert_eq!(
        report["coverage"]["outside_gateway"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(report["coverage"]["complete"], false);
    assert!(report["coverage"]["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g.as_str().unwrap().contains("sequence")));

    erebus()
        .args(["verify-evidence", pack.to_str().unwrap()])
        .args(["--bundle", bundle.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("coverage:"))
        .stderr(predicate::str::contains("outside gateway"));

    let bad = dir.path().join("bad.zip");
    rewrite(&pack, &bad);
    erebus()
        .args(["verify-evidence", bad.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("COVERAGE.json does not match"));
}
