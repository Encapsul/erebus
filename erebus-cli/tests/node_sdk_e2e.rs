//! P0-3 acceptance: the Node SDK and the Python SDK append to the same
//! hash-chained trail. `erebus verify-attest --chain` accepts the mixed trail
//! and still refuses an edited receipt.

#![cfg(unix)]

use assert_cmd::Command;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use tempfile::tempdir;

fn sdk_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("sdk")
}

fn tool_available(tool: &str) -> bool {
    StdCommand::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// CI installs the Python SDK dependencies in a venv and points `ERE_PYTHON` at it.
fn python_command() -> String {
    std::env::var("ERE_PYTHON").unwrap_or_else(|_| "python3".to_string())
}

fn ensure_node_sdk_built(node: &Path) {
    if node.join("dist/index.js").exists() {
        return;
    }
    if !node.join("node_modules").exists() {
        let install = StdCommand::new("npm")
            .args([
                "--prefix",
                &node.to_string_lossy(),
                "install",
                "--no-audit",
                "--no-fund",
            ])
            .output()
            .expect("npm install");
        assert!(
            install.status.success(),
            "{}",
            String::from_utf8_lossy(&install.stderr)
        );
    }
    let build = StdCommand::new("npm")
        .args(["--prefix", &node.to_string_lossy(), "run", "build"])
        .output()
        .expect("npm run build");
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
}

fn keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let keys = dir.join("keys");
    Command::cargo_bin("erebus")
        .expect("erebus binary")
        .args(["keygen", "--key-dir", keys.to_str().unwrap(), "--quiet"])
        .assert()
        .success();
    let key = std::fs::read_dir(&keys)
        .expect("key directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|ext| ext == "key"))
        .expect("signing key");
    (key, keys)
}

fn run_node_agent(node: &Path, dir: &Path, key: &Path, trail: &Path) -> std::process::Output {
    let script = dir.join("agent.mjs");
    std::fs::write(
        &script,
        format!(
            "import {{ attest }} from '{}';\n\
             const answer = attest((q) => ({{ answer: q.toUpperCase() }}),\n\
             \x20 {{ name: 'node.answer' }});\n\
             answer('hello');\n\
             answer('world');\n",
            node.join("dist/index.js").display()
        ),
    )
    .expect("write node agent");
    StdCommand::new("node")
        .arg(script)
        .env("ERE_ATTEST_KEY", key)
        .env("ERE_ATTEST_LOG", trail)
        .output()
        .expect("run node agent")
}

fn run_python_agent(dir: &Path, key: &Path, trail: &Path) -> std::process::Output {
    let script = dir.join("agent.py");
    std::fs::write(
        &script,
        "from erebus import attest\n\
         \n\
         @attest\n\
         def answer(question):\n\
         \x20   return {\"answer\": question.upper()}\n\
         \n\
         answer('hello')\n\
         answer('world')\n",
    )
    .expect("write python agent");
    StdCommand::new(python_command())
        .arg(script)
        .env("ERE_ATTEST_KEY", key)
        .env("ERE_ATTEST_LOG", trail)
        .env("PYTHONPATH", sdk_root().join("python"))
        .output()
        .expect("run python agent")
}

fn verify(trail: &Path, keys: &Path) -> std::process::Output {
    Command::cargo_bin("erebus")
        .expect("erebus binary")
        .args(["verify-attest", "--chain", trail.to_str().unwrap()])
        .args(["--trusted-dir", keys.to_str().unwrap()])
        .env("NO_COLOR", "1")
        .output()
        .expect("run verify-attest")
}

fn receipts(trail: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(trail)
        .expect("trail directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    files
}

#[test]
fn node_and_python_receipts_share_one_verified_chain() {
    assert!(
        tool_available("node") && tool_available("npm") && tool_available(&python_command()),
        "node, npm and python3 (or ERE_PYTHON) are required for the mixed-SDK e2e test"
    );
    let dir = tempdir().expect("temp dir");
    let (key, keys) = keygen(dir.path());
    let trail = dir.path().join("mixed.attest.d");
    let node = sdk_root().join("node");
    ensure_node_sdk_built(&node);

    let node_agent = run_node_agent(&node, dir.path(), &key, &trail);
    assert!(
        node_agent.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&node_agent.stdout),
        String::from_utf8_lossy(&node_agent.stderr)
    );
    let python_agent = run_python_agent(dir.path(), &key, &trail);
    assert!(
        python_agent.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&python_agent.stdout),
        String::from_utf8_lossy(&python_agent.stderr)
    );
    assert_eq!(receipts(&trail).len(), 4);

    let clean = verify(&trail, &keys);
    assert!(
        clean.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&clean.stderr)
    );

    let last = receipts(&trail).pop().expect("four receipts");
    let mut edited: Value = serde_json::from_slice(&std::fs::read(&last).expect("receipt bytes"))
        .expect("receipt JSON");
    edited["execution"]["attested_at"] = json!("2020-01-01T00:00:00Z");
    std::fs::write(
        &last,
        serde_json::to_vec_pretty(&edited).expect("pretty JSON"),
    )
    .expect("rewrite receipt");

    let tampered = verify(&trail, &keys);
    assert!(!tampered.status.success());
    assert!(String::from_utf8_lossy(&tampered.stderr).contains("TAMPERED"));
}
