//! Activation: `erebus demo` must produce a real, locally verifiable
//! receipt in one offline command.

use assert_cmd::Command;
use predicates::prelude::*;
use std::path::PathBuf;

fn stub() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("ERE_STUB_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut dirs = vec![root.join("target"), PathBuf::from("/var/tmp/erebus-target")];
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        dirs.insert(0, PathBuf::from(dir));
    }
    let arch = std::env::consts::ARCH;
    for dir in dirs {
        for candidate in [
            dir.join("debug").join("erebus-stub"),
            dir.join("release").join("erebus-stub"),
            dir.join(format!("{arch}-unknown-linux-musl"))
                .join("release")
                .join("erebus-stub"),
        ] {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[test]
fn demo_builds_runs_and_verifies_a_receipt() {
    let Some(stub) = stub() else {
        eprintln!("skip: no erebus-stub found; set ERE_STUB_PATH to run this test");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("demo");

    Command::cargo_bin("erebus")
        .unwrap()
        .env("NO_COLOR", "1")
        .env("ERE_STUB_PATH", &stub)
        .args(["demo", "--output-dir"])
        .arg(&out)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK: first receipt verified"))
        .stdout(predicate::str::contains("demo.erebus.attest"));

    assert!(out.join("app/app.py").is_file());
    assert!(out.join("demo.erebus").is_file());
    assert!(out.join("demo.erebus.attest").is_file());
    assert!(out.join("keys").is_dir());
}
