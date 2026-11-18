//! R7: `evidence export --since/--until` keeps only the window and
//! `verify-evidence` refuses a receipt whose `attested_at` falls outside it.

use ed25519_dalek::SigningKey;
use erebus_core::assembly::{assemble_erebus, AssemblyInput};
use erebus_core::attest::{AttestationTemplate, ExecutionCapture};
use erebus_core::attest_log::AttestationLog;
use std::path::{Path, PathBuf};
use std::process::Command;

fn erebus() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_erebus"));
    cmd.env("NO_COLOR", "1");
    cmd
}

fn bundle(dir: &Path) -> PathBuf {
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), "print(1)").unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({"name": "w", "author": "t", "license": "MIT"});
    let bin = dir.join("w.erebus");
    assemble_erebus(
        &bin,
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
    bin
}

fn append(log: &AttestationLog, bundle: &Path, key: &SigningKey, at: &str) {
    let template = AttestationTemplate::from_bundle(bundle).unwrap();
    let capture = ExecutionCapture {
        prev_attestation_hash: log.head().unwrap(),
        attested_at: Some(at.to_string()),
        ..ExecutionCapture::default()
    };
    let att = template.attest(key, &capture).unwrap();
    log.append(&att).unwrap();
}

#[test]
fn window_export_drops_the_receipt_outside_it() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = bundle(dir.path());
    let key_bytes = [7u8; 32];
    let key = SigningKey::from_bytes(&key_bytes);
    let key_path = dir.path().join("op.key");
    std::fs::write(&key_path, key_bytes).unwrap();
    let trusted = dir.path().join("trusted");
    std::fs::create_dir_all(&trusted).unwrap();
    std::fs::write(trusted.join("op.pub"), key.verifying_key().as_bytes()).unwrap();
    let trail = dir.path().join("trail");
    let log = AttestationLog::open(&trail).unwrap();
    append(&log, &bundle, &key, "2026-01-15T00:00:00Z");
    append(&log, &bundle, &key, "2026-06-15T00:00:00Z");

    let pack = dir.path().join("window.zip");
    let out = erebus()
        .args(["evidence", "export", bundle.to_str().unwrap()])
        .arg("--trail")
        .arg(&trail)
        .arg("--trusted-dir")
        .arg(&trusted)
        .args([
            "--since",
            "2026-06-01T00:00:00Z",
            "--until",
            "2026-06-30T00:00:00Z",
        ])
        .arg("--key")
        .arg(&key_path)
        .args(["-o", pack.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("1 receipt"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let verified = erebus()
        .args(["verify-evidence", pack.to_str().unwrap()])
        .arg("--bundle")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );

    let empty = erebus()
        .args(["evidence", "export", bundle.to_str().unwrap()])
        .arg("--trail")
        .arg(&trail)
        .arg("--trusted-dir")
        .arg(&trusted)
        .args([
            "--since",
            "2020-01-01T00:00:00Z",
            "--until",
            "2020-02-01T00:00:00Z",
        ])
        .arg("--key")
        .arg(&key_path)
        .args(["-o", dir.path().join("empty.zip").to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!empty.status.success());
    assert!(
        String::from_utf8_lossy(&empty.stderr).contains("no receipts in window"),
        "{}",
        String::from_utf8_lossy(&empty.stderr)
    );

    let outside = dir.path().join("outside.zip");
    rewrite_outside(&pack, &outside);
    let refused = erebus()
        .args(["verify-evidence", outside.to_str().unwrap()])
        .arg("--bundle")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(
        err.contains("outside the claim window") || err.contains("execution mismatch"),
        "{err}"
    );
}

/// Replace the last packed receipt with a byte-for-byte copy of an earlier
/// one and refresh the (unsigned) manifest hash. The receipt signatures stay
/// valid; only the signed claim's head/tallies and the chain link expose it.
#[test]
fn window_rejects_a_duplicated_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = bundle(dir.path());
    let key_bytes = [7u8; 32];
    let key = SigningKey::from_bytes(&key_bytes);
    let key_path = dir.path().join("op.key");
    std::fs::write(&key_path, key_bytes).unwrap();
    let trusted = dir.path().join("trusted");
    std::fs::create_dir_all(&trusted).unwrap();
    std::fs::write(trusted.join("op.pub"), key.verifying_key().as_bytes()).unwrap();
    let trail = dir.path().join("trail");
    let log = AttestationLog::open(&trail).unwrap();
    append(&log, &bundle, &key, "2026-06-10T00:00:00Z");
    append(&log, &bundle, &key, "2026-06-15T00:00:00Z");

    let pack = dir.path().join("window.zip");
    let out = erebus()
        .args(["evidence", "export", bundle.to_str().unwrap()])
        .arg("--trail")
        .arg(&trail)
        .arg("--trusted-dir")
        .arg(&trusted)
        .args([
            "--since",
            "2026-06-01T00:00:00Z",
            "--until",
            "2026-06-30T00:00:00Z",
        ])
        .arg("--key")
        .arg(&key_path)
        .args(["-o", pack.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("2 receipt"));

    let doctored = dir.path().join("duplicate.zip");
    duplicate_receipt(&pack, &doctored);
    let refused = erebus()
        .args(["verify-evidence", doctored.to_str().unwrap()])
        .arg("--bundle")
        .arg(&bundle)
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "a duplicated receipt must be refused"
    );
    let err = String::from_utf8_lossy(&refused.stderr);
    assert!(
        err.contains("TAMPERED") && (err.contains("duplicate") || err.contains("claim head")),
        "{err}"
    );
}

/// Overwrite the last trail receipt with an earlier one's bytes, updating
/// MANIFEST.json so the only inconsistency is the signed claim and chain.
fn duplicate_receipt(src: &Path, dst: &Path) {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    let mut archive = zip::ZipArchive::new(std::fs::File::open(src).unwrap()).unwrap();
    let mut files = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap();
        files.push((entry.name().expect("zip entry name").into_owned(), buf));
    }
    let receipts: Vec<usize> = files
        .iter()
        .enumerate()
        .filter(|(_, (n, _))| {
            n.starts_with("trail/") && n.ends_with(".json") && !n.contains(".proof.")
        })
        .map(|(i, _)| i)
        .collect();
    assert_eq!(receipts.len(), 2, "test needs exactly two receipts");
    let copy = files[receipts[0]].1.clone();
    let target = receipts[1];
    files[target].1 = copy;
    let digest = hex::encode(Sha256::digest(&files[target].1));
    let name = files[target].0.clone();
    let manifest = files
        .iter()
        .position(|(n, _)| n == "MANIFEST.json")
        .unwrap();
    let mut man: serde_json::Value = serde_json::from_slice(&files[manifest].1).unwrap();
    man["files"][&name] = serde_json::Value::String(digest);
    man["receipts"][1]["dsse"] = serde_json::Value::Null;
    files[manifest].1 = serde_json::to_vec_pretty(&man).unwrap();
    let mut zip = zip::ZipWriter::new(std::fs::File::create(dst).unwrap());
    let opts = zip::write::SimpleFileOptions::default();
    for (name, bytes) in &files {
        zip.start_file(name.as_str(), opts).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}

/// Move the packed receipt outside the window and refresh its manifest hash,
/// so verification fails on the window rather than on a missing file.
fn rewrite_outside(src: &Path, dst: &Path) {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Write};
    let mut archive = zip::ZipArchive::new(std::fs::File::open(src).unwrap()).unwrap();
    let mut files = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).unwrap();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).unwrap();
        let name = entry.name().expect("zip entry name").into_owned();
        files.push((name, buf));
    }
    let idx = files
        .iter()
        .position(|(n, _)| {
            n.starts_with("trail/") && n.ends_with(".json") && !n.contains(".proof.")
        })
        .unwrap();
    let mut att: serde_json::Value = serde_json::from_slice(&files[idx].1).unwrap();
    att["execution"]["attested_at"] = serde_json::json!("2020-01-01T00:00:00Z");
    files[idx].1 = serde_json::to_vec_pretty(&att).unwrap();
    let name = files[idx].0.clone();
    let digest = hex::encode(Sha256::digest(&files[idx].1));
    let m = files
        .iter()
        .position(|(n, _)| n == "MANIFEST.json")
        .unwrap();
    let mut man: serde_json::Value = serde_json::from_slice(&files[m].1).unwrap();
    man["files"][&name] = serde_json::Value::String(digest);
    files[m].1 = serde_json::to_vec_pretty(&man).unwrap();
    let mut zip = zip::ZipWriter::new(std::fs::File::create(dst).unwrap());
    let opts = zip::write::SimpleFileOptions::default();
    for (name, bytes) in &files {
        zip.start_file(name.as_str(), opts).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}
