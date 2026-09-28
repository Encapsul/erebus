//! End-to-end acceptance test for ROADMAP P0-6 (machine identity) and P0-7
//! (standard DSSE/in-toto envelope):
//!
//! 1. `erebus enroll --registry` against the real `scripts/registry_server.py`
//!    → machine key + certificate signed by the registry key.
//! 2. `erebus attest --envelope` on the enrolled host → spec 2.0 receipt
//!    co-signed by the machine key, plus a bare DSSE envelope.
//! 3. Registry stopped. `erebus verify-attest --strict --registry-key` passes
//!    offline; an un-enrolled receipt, a wrong registry key and a swapped
//!    machine block are refused.
//! 4. If `cosign` is on PATH, `cosign verify-blob-attestation` accepts the
//!    envelope with the operator's PEM key and rejects a tampered payload —
//!    proof that the format is standard, not erebus-specific.
//!
//! Skips (with a notice) when `python3` is unavailable.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};
use tempfile::tempdir;

const PREDICATE_V2: &str = "https://erebus.dev/attestation/execution/v2";

fn erebus(machine_dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("erebus").unwrap();
    cmd.env("NO_COLOR", "1");
    // Never touch the developer's real machine identity.
    cmd.env("ERE_MACHINE_DIR", machine_dir);
    cmd
}

fn make_bundle(dir: &Path) -> PathBuf {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), "print('strict')").unwrap();
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

/// (private key, trusted dir, PEM public key)
fn keygen(dir: &Path, machine_dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let key_dir = dir.join("keys");
    erebus(machine_dir)
        .args(["keygen", "--key-dir", key_dir.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("public pem:"));
    let find = |ext: &str| {
        std::fs::read_dir(&key_dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|e| e == ext))
            .unwrap_or_else(|| panic!("{ext} file"))
    };
    (find("key"), key_dir.clone(), find("pem"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Registry {
    child: Child,
    base: String,
}

impl Registry {
    fn start(root: &Path) -> Option<Self> {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/registry_server.py");
        let port = free_port();
        let child = std::process::Command::new("python3")
            .arg(&script)
            .args(["--dir", root.to_str().unwrap(), "--port", &port.to_string()])
            .args(["--log-origin", "strict-origin", "--anchor-every", "0"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .ok()?;
        let reg = Self {
            child,
            base: format!("http://127.0.0.1:{port}"),
        };
        reg.wait_ready();
        Some(reg)
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if http(&self.base, "GET", "/health", None, None).is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("registry never became healthy");
    }

    fn register(&self) -> String {
        let body = serde_json::json!({"username": "alice", "password": "pw12345678"});
        let (status, json) = http(
            &self.base,
            "POST",
            "/auth/register",
            None,
            Some(body.to_string().as_bytes()),
        )
        .expect("register");
        assert_eq!(status, 200, "{json}");
        json["token"].as_str().unwrap().to_string()
    }

    fn log_key_hex(&self) -> String {
        let (_, json) = http(&self.base, "GET", "/log/key", None, None).unwrap();
        json["public_key_hex"].as_str().unwrap().to_string()
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn http(
    base: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&[u8]>,
) -> Option<(u16, serde_json::Value)> {
    use std::io::Write;
    let addr = base.trim_start_matches("http://");
    let mut s = std::net::TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let body = body.unwrap_or(&[]);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    req.push_str(&format!(
        "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    ));
    s.write_all(req.as_bytes()).ok()?;
    s.write_all(body).ok()?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).ok()?;
    let text = String::from_utf8_lossy(&resp);
    let status: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
    let json_part = text.split("\r\n\r\n").nth(1).unwrap_or("{}");
    let json = serde_json::from_str(json_part).unwrap_or(serde_json::Value::Null);
    Some((status, json))
}

fn attest(
    machine_dir: &Path,
    bundle: &Path,
    key: &Path,
    out: &Path,
    envelope: Option<&Path>,
) -> assert_cmd::assert::Assert {
    let mut cmd = erebus(machine_dir);
    cmd.args([
        "attest",
        bundle.to_str().unwrap(),
        "--key",
        key.to_str().unwrap(),
    ])
    .args(["--output", out.to_str().unwrap(), "--no-log"]);
    if let Some(e) = envelope {
        cmd.args(["--envelope", e.to_str().unwrap()]);
    }
    cmd.assert().success()
}

#[test]
fn enroll_then_strict_verify_offline_and_cosign_interop() {
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 not found; skipping registry e2e");
        return;
    }
    let dir = tempdir().unwrap();
    let machine_dir = dir.path().join("machine");
    let bundle = make_bundle(dir.path());
    let (key, trusted, pem) = keygen(dir.path(), &machine_dir);
    let registry_root = dir.path().join("registry");
    std::fs::create_dir_all(&registry_root).unwrap();
    let Some(registry) = Registry::start(&registry_root) else {
        eprintln!("could not start python3 registry; skipping");
        return;
    };
    let token = registry.register();
    let registry_key = registry.log_key_hex();

    // A receipt from a host that is NOT enrolled: spec 2.0, operator-only.
    let bare = dir.path().join("bare.attest");
    attest(&machine_dir, &bundle, &key, &bare, None)
        .stderr(predicate::str::contains("machine: not enrolled"));

    // Enroll: key generated locally, certified by the registry.
    erebus(&machine_dir)
        .args(["enroll", "--registry", &registry.base, "--token", &token])
        .assert()
        .success()
        .stderr(predicate::str::contains("generated key"))
        .stderr(predicate::str::contains("certified:  by"))
        .stderr(predicate::str::contains("for alice"));
    assert!(machine_dir.join("machine.key").is_file());
    assert!(machine_dir.join("machine.cert.json").is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(machine_dir.join("machine.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "machine key must be private");
    }
    // Re-running enroll keeps the same key (no silent rotation).
    let show = erebus(&machine_dir)
        .args(["enroll", "--show", "--json"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let show: serde_json::Value = serde_json::from_slice(&show).unwrap();
    let machine_id = show["machine_id"].as_str().unwrap().to_string();
    erebus(&machine_dir)
        .args(["enroll", "--registry", &registry.base, "--token", &token])
        .assert()
        .success()
        .stderr(predicate::str::contains("existing key"))
        .stderr(predicate::str::contains(&machine_id));

    // Now every receipt is co-signed by the machine key.
    let receipt = dir.path().join("strict.attest");
    let envelope = dir.path().join("strict.dsse.json");
    attest(&machine_dir, &bundle, &key, &receipt, Some(&envelope)).stderr(
        predicate::str::contains(format!("machine: {machine_id} (co-signed)")),
    );

    // Everything below is offline.
    drop(registry);

    let att: serde_json::Value = serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(att["spec_version"], "2.0");
    assert_eq!(att["statement"]["predicateType"], PREDICATE_V2);
    assert_eq!(
        att["statement"]["predicate"]["execution"]["machine_id"],
        machine_id
    );
    assert_eq!(
        att["envelope"]["payloadType"],
        "application/vnd.in-toto+json"
    );
    assert_eq!(att["envelope"]["signatures"].as_array().unwrap().len(), 2);
    assert_eq!(att["machine"]["certificate"]["owner"], "alice");

    let verify = |file: &Path, extra: &[&str]| {
        let mut cmd = erebus(&machine_dir);
        cmd.args(["verify-attest", file.to_str().unwrap()])
            .args(["--trusted-dir", trusted.to_str().unwrap()]);
        cmd.args(extra);
        cmd
    };

    // Plain verification works for both receipts (operator key only).
    verify(&bare, &[])
        .assert()
        .success()
        .stderr(predicate::str::contains("spec 2.0 (DSSE envelope)"));
    verify(&receipt, &[]).assert().success();

    // --strict: needs the registry key, refuses the un-enrolled receipt.
    verify(&receipt, &["--strict"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("strict verification failed"));
    verify(&receipt, &["--strict", "--registry-key", &registry_key])
        .assert()
        .success()
        .stderr(predicate::str::contains(format!(
            "OK: machine {machine_id} — enrolled by alice"
        )));
    verify(&bare, &["--strict", "--registry-key", &registry_key])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not enrolled"));

    let json_out = verify(
        &receipt,
        &["--strict", "--log-key", &registry_key, "--json"],
    )
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
    let report: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
    assert_eq!(report["machine"]["verified"], true);
    assert_eq!(report["machine"]["owner"], "alice");
    assert_eq!(report["machine_id"], machine_id);

    // Tamper: graft the enrolled machine block onto the bare receipt. The
    // signed statement names no machine_id, so this must fail.
    let mut grafted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&bare).unwrap()).unwrap();
    grafted["machine"] = att["machine"].clone();
    let grafted_path = dir.path().join("grafted.attest");
    std::fs::write(&grafted_path, serde_json::to_vec_pretty(&grafted).unwrap()).unwrap();
    verify(
        &grafted_path,
        &["--strict", "--registry-key", &registry_key],
    )
    .assert()
    .failure()
    .stderr(predicate::str::contains("TAMPERED"));

    // Tamper: a certificate from another "registry" (wrong key) is refused.
    let mut forged = att.clone();
    forged["machine"]["certificate"]["signature_hex"] = serde_json::json!("00".repeat(64));
    let forged_path = dir.path().join("forged.attest");
    std::fs::write(&forged_path, serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
    verify(&forged_path, &["--strict", "--registry-key", &registry_key])
        .assert()
        .failure()
        .stderr(predicate::str::contains("strict verification failed"));

    cosign_interop(&bundle, &envelope, &pem);
}

/// The DSSE envelope must verify with stock Sigstore tooling.
fn cosign_interop(bundle: &Path, envelope: &Path, pem: &Path) {
    let Ok(cosign) = which::which("cosign") else {
        eprintln!("cosign not on PATH; skipping Sigstore interop check");
        return;
    };
    let run = |env: &Path| {
        std::process::Command::new(&cosign)
            .args(["verify-blob-attestation", "--key", pem.to_str().unwrap()])
            .args(["--signature", env.to_str().unwrap()])
            .args(["--type", PREDICATE_V2, "--insecure-ignore-tlog"])
            .arg(bundle)
            .output()
            .expect("run cosign")
    };
    let ok = run(envelope);
    assert!(
        ok.status.success(),
        "cosign refused a valid erebus envelope:\n{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert!(String::from_utf8_lossy(&ok.stderr).contains("Verified OK"));

    // Flip one byte of the payload: signatures no longer match.
    let mut env: serde_json::Value =
        serde_json::from_slice(&std::fs::read(envelope).unwrap()).unwrap();
    let payload = env["payload"].as_str().unwrap().to_string();
    let mut chars: Vec<char> = payload.chars().collect();
    chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
    env["payload"] = serde_json::json!(chars.into_iter().collect::<String>());
    let bad = envelope.with_extension("bad.json");
    std::fs::write(&bad, serde_json::to_vec(&env).unwrap()).unwrap();
    assert!(
        !run(&bad).status.success(),
        "cosign accepted a tampered envelope"
    );
}
