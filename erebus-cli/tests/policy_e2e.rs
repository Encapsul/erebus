//! Buyer smoke: `erebus policy check` allows a conforming bundle and refuses
//! one below `min_isolation` (existing approve roundtrip lives in `attest_e2e`).

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn erebus() -> Command {
    let mut cmd = Command::cargo_bin("erebus").unwrap();
    cmd.env("NO_COLOR", "1");
    cmd
}

fn pack(dir: &Path, name: &str, isolation: u32) -> PathBuf {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    let rootfs = dir.join(format!("rootfs-{name}"));
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), "print(1)").unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": name,
        "runtime": "python",
        "isolation": isolation,
        "layers": [{"kind": "runtime", "name": "runtime/python3", "size": 1024}],
    });
    let bin = dir.join(format!("{name}.erebus"));
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

#[test]
fn policy_check_allows_and_refuses_by_isolation() {
    let dir = tempdir().unwrap();
    let policy = dir.path().join("launch.yaml");
    std::fs::write(&policy, "min_isolation: 2\nrequire_receipt: false\n").unwrap();

    let ok = pack(dir.path(), "ok", 2);
    erebus()
        .args([
            "policy",
            "check",
            ok.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("OK: policy"));

    let low = pack(dir.path(), "low", 0);
    erebus()
        .args([
            "policy",
            "check",
            low.to_str().unwrap(),
            "--policy",
            policy.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("min_isolation"));
}
