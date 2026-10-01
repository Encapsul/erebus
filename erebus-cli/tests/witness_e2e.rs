//! ROADMAP R1 — disconnected anchoring (DDIL) acceptance:
//! offline trail → witness seal → failed publish keeps seal → forged
//! insertion refused → real registry sync → verify-attest --proof OK with
//! witnessed-at then anchored-at.

mod common;

use assert_cmd::Command;
use predicates::prelude::*;
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
    std::fs::write(rootfs.join("app/main.py"), "print('witness')").unwrap();
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

fn attest(bundle: &Path, key: &Path, out: &Path) {
    erebus()
        .args([
            "attest",
            bundle.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--quiet",
        ])
        .assert()
        .success();
}

fn witness_pub(dir: &Path) -> PathBuf {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "pub"))
        .expect("witness .pub")
}

#[test]
fn disconnected_anchoring_witness_refuses_insertion_then_syncs() {
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 not found; skipping witness e2e");
        return;
    }

    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path());
    let (key, trusted) = keygen(dir.path());
    let out = dir.path().join("agent.erebus.attest");
    let trail = erebus_core::attest_log::default_log_dir(&out);
    let witness_dir = dir.path().join("witness");

    // 1. Offline trail of N receipts.
    for _ in 0..3 {
        attest(&bundle, &key, &out);
    }
    assert!(trail.join("HEAD").exists());

    // 2. Witness keygen + seal.
    erebus()
        .args(["witness", "keygen", "--dir", witness_dir.to_str().unwrap()])
        .assert()
        .success();
    let wkey = witness_dir.join("witness.key");
    erebus()
        .env("ERE_WITNESS_KEY", &wkey)
        .args(["witness", "seal", "--trail", trail.to_str().unwrap()])
        .assert()
        .success();
    let witness_file = trail.join("HEAD.witness.json");
    assert!(witness_file.exists());

    // 3. Publish with a bad registry URL → fails; witness remains / is refreshed.
    erebus()
        .env("ERE_WITNESS_KEY", &wkey)
        .args([
            "attest",
            bundle.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--push",
            "--registry",
            "http://127.0.0.1:1",
            "--quiet",
        ])
        .assert()
        .failure();
    assert!(witness_file.exists());

    // Freeze the sealed size after the failed-push append.
    erebus()
        .env("ERE_WITNESS_KEY", &wkey)
        .args(["witness", "seal", "--trail", trail.to_str().unwrap()])
        .assert()
        .success();

    // 4. Insert a forged extra receipt into the trail.
    let forge = trail.join("999999-forged.json");
    std::fs::write(&forge, b"{\"forged\":true}\n").unwrap();
    let wpub = witness_pub(&witness_dir);

    // 5. --require-witness refuses the insertion.
    erebus()
        .args([
            "verify-attest",
            "--chain",
            trail.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--witness-key",
            wpub.to_str().unwrap(),
            "--require-witness",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("TAMPERED"));

    // 6. Remove forge, start real registry, publish backlog (fresh --push).
    std::fs::remove_file(&forge).unwrap();
    erebus()
        .args([
            "verify-attest",
            "--chain",
            trail.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--witness-key",
            wpub.to_str().unwrap(),
            "--require-witness",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("witnessed at"));

    let registry_root = dir.path().join("registry");
    std::fs::create_dir_all(&registry_root).unwrap();
    let Some(reg) = common::registry::spawn_registry(&registry_root, "witness-origin") else {
        eprintln!("could not start registry; skipping publish half");
        return;
    };
    let token = {
        let body = serde_json::json!({"username": "alice", "password": "pw12345678"});
        reqwest::blocking::Client::new()
            .post(format!("{}/auth/register", reg.base))
            .json(&body)
            .send()
            .unwrap()
            .json::<serde_json::Value>()
            .unwrap()["token"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let log_key = reqwest::blocking::Client::new()
        .get(format!("{}/log/key", reg.base))
        .send()
        .unwrap()
        .json::<serde_json::Value>()
        .unwrap()["public_key_hex"]
        .as_str()
        .unwrap()
        .to_string();

    erebus()
        .env("ERE_WITNESS_KEY", &wkey)
        .args([
            "attest",
            bundle.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--push",
            "--registry",
            &reg.base,
            "--token",
            &token,
            "--quiet",
        ])
        .assert()
        .success();

    let proof = {
        let mut name = out.file_name().unwrap().to_string_lossy().into_owned();
        name.push_str(".proof.json");
        out.with_file_name(name)
    };
    assert!(proof.exists(), "push must store a proof sidecar");

    // Keep the outage seal (do not re-seal): witnessed_at ≤ checkpoint time.
    // 7. Report shows witness time and later anchor time.
    erebus()
        .args([
            "verify-attest",
            out.to_str().unwrap(),
            "--trusted-dir",
            trusted.to_str().unwrap(),
            "--proof",
            "--log-key",
            &log_key,
            "--witness-key",
            wpub.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("witnessed at"))
        .stderr(predicate::str::contains("anchored at"));
}
