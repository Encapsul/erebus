//! P0-3 acceptance: an unpackaged Python agent emits spec 2.0 receipts with
//! three lines (`from erebus import attest`, `@attest`, `def …`). The SDK
//! writes the same DSSE/JCS bytes as the Rust writer, so `verify-attest
//! --chain` accepts a real trail and refuses an edited receipt.

#![cfg(unix)]

use assert_cmd::Command;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use tempfile::tempdir;

fn python() -> String {
    std::env::var("ERE_PYTHON").unwrap_or_else(|_| "python3".to_string())
}

fn sdk_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("sdk/python")
}

fn keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let keys = dir.join("keys");
    Command::cargo_bin("erebus")
        .unwrap()
        .args(["keygen", "--key-dir", keys.to_str().unwrap(), "--quiet"])
        .assert()
        .success();
    let mut key = None;
    for entry in std::fs::read_dir(&keys).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "key") {
            key = Some(path);
        }
    }
    (key.expect("signing key"), keys)
}

fn run_agent(dir: &Path, key: &Path, trail: &Path) -> std::process::Output {
    let script = dir.join("agent.py");
    std::fs::write(
        &script,
        "from erebus import attest\n\
         \n\
         @attest\n\
         def answer(question):\n\
         \x20   return {\"answer\": question.upper()}\n\
         \n\
         answer(\"hello\")\n\
         answer(\"world\")\n",
    )
    .unwrap();
    StdCommand::new(python())
        .arg(&script)
        .env("ERE_ATTEST_KEY", key)
        .env("ERE_ATTEST_LOG", trail)
        .env("PYTHONPATH", sdk_path())
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn verify(trail: &Path, keys: &Path) -> std::process::Output {
    Command::cargo_bin("erebus")
        .unwrap()
        .args(["verify-attest", "--chain", trail.to_str().unwrap()])
        .args(["--trusted-dir", keys.to_str().unwrap()])
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn receipt_files(trail: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(trail)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
}

#[test]
fn python_sdk_receipts_verify_and_tamper_fails() {
    let dir = tempdir().unwrap();
    let (key, keys) = keygen(dir.path());
    let trail = dir.path().join("agent.attest.d");

    let agent = run_agent(dir.path(), &key, &trail);
    assert!(
        agent.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&agent.stdout),
        String::from_utf8_lossy(&agent.stderr)
    );
    assert_eq!(receipt_files(&trail).len(), 2);

    let clean = verify(&trail, &keys);
    assert!(
        clean.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let last = receipt_files(&trail).pop().expect("two receipts");
    let mut edited: Value = serde_json::from_slice(&std::fs::read(&last).unwrap()).unwrap();
    edited["execution"]["attested_at"] = json!("2020-01-01T00:00:00Z");
    std::fs::write(&last, serde_json::to_vec_pretty(&edited).unwrap()).unwrap();

    let tampered = verify(&trail, &keys);
    assert!(!tampered.status.success());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("TAMPERED"));
}
