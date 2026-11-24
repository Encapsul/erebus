//! ROADMAP P0-4 acceptance: a launch policy that requires receipts only opens
//! a signed bundle with a valid receipt for these exact bytes. Presence of a
//! file, an empty trail, a doctored receipt and a foreign receipt are all
//! refused. The launcher calls the same core function via `enforce_embedded_at`.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn erebus() -> Command {
    let mut cmd = Command::cargo_bin("erebus").unwrap();
    cmd.env("NO_COLOR", "1");
    cmd
}

fn keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let keys = dir.join("keys");
    erebus()
        .args(["keygen", "--key-dir", keys.to_str().unwrap(), "--quiet"])
        .assert()
        .success();
    let key = std::fs::read_dir(&keys)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "key"))
        .expect("signing key");
    (key, keys)
}

fn make_bundle(dir: &Path, name: &str) -> PathBuf {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    let rootfs = dir.join(format!("rootfs-{name}"));
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), format!("print('{name}')")).unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": name,
        "runtime": "python",
        "isolation": 0,
        "launch_policy": "require_receipt: true\n",
    });
    let bundle = dir.join(format!("{name}.erebus"));
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

fn check(bundle: &Path, policy: &Path, trusted: &Path) -> assert_cmd::assert::Assert {
    erebus()
        .args(["policy", "check", bundle.to_str().unwrap()])
        .args(["--policy", policy.to_str().unwrap()])
        .args(["--trusted-dir", trusted.to_str().unwrap()])
        .assert()
}

fn sign(bundle: &Path, key: &Path) {
    erebus()
        .args(["sign", bundle.to_str().unwrap()])
        .args(["--key", key.to_str().unwrap(), "--quiet", "--no-input"])
        .assert()
        .success();
}

fn attest(bundle: &Path, key: &Path) {
    erebus()
        .args(["attest", bundle.to_str().unwrap()])
        .args(["--key", key.to_str().unwrap(), "--quiet"])
        .assert()
        .success();
}

fn first_receipt(trail: &Path) -> PathBuf {
    std::fs::read_dir(trail)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .expect("receipt")
}

fn install_trail(src: &Path, dst: &Path) {
    if dst.exists() {
        std::fs::remove_dir_all(dst).unwrap();
    }
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
    }
}

#[test]
fn require_receipt_unlocks_only_a_signed_bundle_with_its_own_valid_receipt() {
    let dir = tempdir().unwrap();
    let (key, trusted) = keygen(dir.path());
    let policy = dir.path().join("launch.yaml");
    std::fs::write(&policy, "require_receipt: true\n").unwrap();
    let bundle = make_bundle(dir.path(), "agent");
    let trail = PathBuf::from(format!("{}.attest.d", bundle.display()));

    check(&bundle, &policy, &trusted)
        .failure()
        .stderr(predicate::str::contains("bundle is unsigned"));

    sign(&bundle, &key);
    check(&bundle, &policy, &trusted)
        .failure()
        .stderr(predicate::str::contains("no receipt trail"));
    assert!(erebus_core::policy::enforce_embedded_at(&bundle, &trusted).is_err());

    attest(&bundle, &key);
    check(&bundle, &policy, &trusted)
        .success()
        .stderr(predicate::str::contains("OK: policy"));
    erebus_core::policy::enforce_embedded_at(&bundle, &trusted).unwrap();

    let receipt = first_receipt(&trail);
    let backup = dir.path().join("receipt-backup.json");
    std::fs::copy(&receipt, &backup).unwrap();
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    doc["statement"]["predicate"]["execution"]["attested_at"] =
        serde_json::Value::String("2020-01-01T00:00:00Z".to_string());
    std::fs::write(&receipt, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    check(&bundle, &policy, &trusted)
        .failure()
        .stderr(predicate::str::contains("TAMPERED"));
    assert!(erebus_core::policy::enforce_embedded_at(&bundle, &trusted).is_err());
    std::fs::copy(&backup, &receipt).unwrap();

    let other = make_bundle(dir.path(), "other");
    sign(&other, &key);
    attest(&other, &key);
    let foreign = PathBuf::from(format!("{}.attest.d", other.display()));
    install_trail(&foreign, &trail);
    check(&bundle, &policy, &trusted)
        .failure()
        .stderr(predicate::str::contains("bundle mismatch"));
}
