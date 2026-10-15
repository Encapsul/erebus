//! End-to-end acceptance test for ROADMAP P1-2: `erebus evidence export`
//! over a real trail (enrolled machine, receipts pushed to the real
//! `scripts/registry_server.py`), then `erebus verify-evidence` **offline**
//! (registry stopped), then every way an auditor could be handed a doctored
//! pack. Skips (with a notice) when `python3` is unavailable.

mod common;

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::tempdir;

fn erebus() -> Command {
    let mut cmd = Command::cargo_bin("erebus").unwrap();
    cmd.env("NO_COLOR", "1");
    cmd
}

fn make_bundle(dir: &Path, name: &str, body: &str) -> PathBuf {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    let rootfs = dir.join(format!("rootfs-{name}"));
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), body).unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({"name": name, "author": "test-user", "license": "MIT"});
    let bin_path = dir.join(format!("{name}.erebus"));
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

/// The real registry, killed on drop.
struct Registry {
    _process: common::registry::RegistryProcess,
    base: String,
}

impl Registry {
    fn start(root: &Path) -> Option<Self> {
        let process = common::registry::spawn_registry(root, "evidence-e2e")?;
        let base = process.base.clone();
        Some(Self {
            _process: process,
            base,
        })
    }

    fn register(&self) -> String {
        let body = serde_json::json!({"username": "auditee", "password": "pw12345678"});
        let (status, json) = http(
            &self.base,
            "POST",
            "/auth/register",
            Some(body.to_string().as_bytes()),
        )
        .unwrap();
        assert_eq!(status, 200, "{json}");
        json["token"].as_str().unwrap().to_string()
    }

    fn log_key_hex(&self) -> String {
        let (_, json) = http(&self.base, "GET", "/log/key", None).unwrap();
        json["public_key_hex"].as_str().unwrap().to_string()
    }
}

fn http(
    base: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Option<(u16, serde_json::Value)> {
    let addr = base.trim_start_matches("http://");
    let mut s = std::net::TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let body = body.unwrap_or(&[]);
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).ok()?;
    s.write_all(body).ok()?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).ok()?;
    let text = String::from_utf8_lossy(&resp);
    let status: u16 = text.split_whitespace().nth(1)?.parse().ok()?;
    let json = serde_json::from_str(text.split("\r\n\r\n").nth(1).unwrap_or("{}"))
        .unwrap_or(serde_json::Value::Null);
    Some((status, json))
}

/// Copy `src` to `dst`, passing every entry through `edit` (None drops it)
/// and appending `extra` — the ways a pack can be doctored after export.
fn rewrite_pack(
    src: &Path,
    dst: &Path,
    edit: impl Fn(&str, Vec<u8>) -> Option<Vec<u8>>,
    extra: &[(&str, &[u8])],
) {
    let mut zin = zip::ZipArchive::new(std::fs::File::open(src).unwrap()).unwrap();
    let mut zout = zip::ZipWriter::new(std::fs::File::create(dst).unwrap());
    let opts = zip::write::SimpleFileOptions::default();
    for i in 0..zin.len() {
        let mut e = zin.by_index(i).unwrap();
        let name = e.name().to_string();
        let mut bytes = Vec::new();
        e.read_to_end(&mut bytes).unwrap();
        if let Some(b) = edit(&name, bytes) {
            zout.start_file(name, opts).unwrap();
            zout.write_all(&b).unwrap();
        }
    }
    for (name, bytes) in extra {
        zout.start_file(*name, opts).unwrap();
        zout.write_all(bytes).unwrap();
    }
    zout.finish().unwrap();
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

fn flip_last_digit(bytes: &[u8]) -> Vec<u8> {
    let mut b = bytes.to_vec();
    let i = b.iter().rposition(u8::is_ascii_digit).unwrap();
    b[i] = if b[i] == b'0' { b'1' } else { b'0' };
    b
}

fn refused(pack: &Path, needle: &str) {
    erebus()
        .args(["verify-evidence", pack.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("evidence verification failed"))
        .stderr(predicate::str::contains(needle));
}

#[test]
fn evidence_pack_verifies_offline_and_refuses_every_doctored_copy() {
    if std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("python3 not found; skipping evidence e2e");
        return;
    }
    let dir = tempdir().unwrap();
    let bundle = make_bundle(dir.path(), "agent", "print('evidence')");
    let (key, trusted) = keygen(dir.path());
    let registry_root = dir.path().join("registry");
    std::fs::create_dir_all(&registry_root).unwrap();
    let Some(registry) = Registry::start(&registry_root) else {
        eprintln!("could not start python3 registry; skipping");
        return;
    };
    let token = registry.register();
    let log_key = registry.log_key_hex();
    let machine_dir = dir.path().join("machine");
    erebus()
        .env("ERE_TOKEN", &token)
        .args(["enroll", "--registry", &registry.base])
        .env("ERE_MACHINE_DIR", &machine_dir)
        .assert()
        .success();

    let trail = dir.path().join("trail");
    for i in 0..2 {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(1100));
        }
        erebus()
            .args([
                "attest",
                bundle.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
            ])
            .args([
                "--output",
                dir.path().join("latest.attest").to_str().unwrap(),
            ])
            .args(["--log", trail.to_str().unwrap(), "--push"])
            .args(["--registry", &registry.base])
            .env("ERE_TOKEN", &token)
            .env("ERE_MACHINE_DIR", &machine_dir)
            .assert()
            .success();
    }
    drop(registry); // everything below is offline

    let pack = dir.path().join("evidence.zip");
    let export = |extra: &[&str]| {
        let mut cmd = erebus();
        cmd.args(["evidence", "export", bundle.to_str().unwrap()])
            .args(["--trail", trail.to_str().unwrap()])
            .args([
                "--trusted-dir",
                trusted.to_str().unwrap(),
                "-o",
                pack.to_str().unwrap(),
            ]);
        cmd.args(extra);
        cmd
    };
    // Without the registry key the machine certificates and log proofs are
    // unverifiable, so nothing is exported.
    export(&[])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to export evidence"));
    assert!(!pack.exists());
    export(&["--log-key", &log_key])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 receipt(s), 2 log proof(s)"));

    let json = erebus()
        .args(["verify-evidence", pack.to_str().unwrap(), "--json"])
        .args(["--bundle", bundle.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(report["verified"], true);
    assert_eq!(report["receipts"], 2);
    assert_eq!(report["machine_cosigned"], 2);
    assert_eq!(report["log_proofs"], 2);
    assert_eq!(report["bundle"]["file_checked"], true);
    assert_eq!(report["keys"]["operator_pinned"], false);

    // The pack carries its own keys: an auditor pins them out of band.
    let op_fp = report["keys"]["operator"][0].as_str().unwrap().to_string();
    let pinned = |op: &str, log: &str| {
        let mut cmd = erebus();
        cmd.args(["verify-evidence", pack.to_str().unwrap(), "--json"])
            .args(["--operator-key", op, "--log-key", log]);
        cmd
    };
    let json = pinned(&op_fp, &log_key)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(report["keys"]["operator_pinned"], true);
    assert_eq!(report["keys"]["registry_pinned"], true);
    // What the operator actually sees: the key hex `keygen` prints and names
    // the key file after.
    let op_hex = key.file_stem().unwrap().to_str().unwrap().to_string();
    assert_eq!(report["keys"]["operator_public_keys"][0], op_hex.as_str());
    pinned(&op_hex, &log_key).assert().success();
    let stranger = format!("sha256:{}", "ab".repeat(32));
    pinned(&stranger, &log_key)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("operator key"))
        .stderr(predicate::str::contains("not one of the pinned keys"));
    let other_log = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    pinned(&op_fp, other_log)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("registry key"));

    // 1. A receipt edited inside the pack.
    let receipt_name = |n: &str| {
        n.starts_with("trail/000002") && n.ends_with(".json") && !n.ends_with(".proof.json")
    };
    let bad = dir.path().join("bad1.zip");
    rewrite_pack(
        &pack,
        &bad,
        |n, b| {
            Some(if receipt_name(n) {
                flip_last_digit(&b)
            } else {
                b
            })
        },
        &[],
    );
    refused(&bad, "hash mismatch");

    // 2. Same edit, with MANIFEST.json re-hashed to match: the index is not
    //    a trust root, the receipt's own signature and log leaf still refuse.
    let edited: std::cell::RefCell<Option<(String, String)>> = std::cell::RefCell::new(None);
    let bad = dir.path().join("bad2.zip");
    rewrite_pack(
        &pack,
        &bad,
        |n, b| {
            if receipt_name(n) {
                let f = flip_last_digit(&b);
                *edited.borrow_mut() = Some((n.to_string(), sha256_hex(&f)));
                Some(f)
            } else {
                Some(b)
            }
        },
        &[],
    );
    let (name, hash) = edited.borrow().clone().unwrap();
    let bad_rehashed = dir.path().join("bad2b.zip");
    rewrite_pack(
        &bad,
        &bad_rehashed,
        |n, b| {
            if n != "MANIFEST.json" {
                return Some(b);
            }
            let mut m: serde_json::Value = serde_json::from_slice(&b).unwrap();
            m["files"][&name] = serde_json::Value::String(hash.clone());
            Some(serde_json::to_vec_pretty(&m).unwrap())
        },
        &[],
    );
    erebus()
        .args(["verify-evidence", bad_rehashed.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("evidence verification failed"));

    // 3. The first execution erased: its receipt, proof, anchor and DSSE
    //    dropped and MANIFEST.json rewritten to no longer mention them.
    //    Only the hash chain can notice.
    let first = "000001-";
    let bad = dir.path().join("bad3.zip");
    rewrite_pack(
        &pack,
        &bad,
        |n, b| {
            if n.contains(first) {
                return None;
            }
            if n != "MANIFEST.json" {
                return Some(b);
            }
            let mut m: serde_json::Value = serde_json::from_slice(&b).unwrap();
            m["files"]
                .as_object_mut()
                .unwrap()
                .retain(|k, _| !k.contains(first));
            m["receipts"]
                .as_array_mut()
                .unwrap()
                .retain(|r| !r["receipt"].as_str().unwrap().contains(first));
            Some(serde_json::to_vec_pretty(&m).unwrap())
        },
        &[],
    );
    refused(&bad, "chain broken");

    // 3b. Deleting a listed file is tampering too, not an I/O error.
    let bad = dir.path().join("bad3b.zip");
    rewrite_pack(&pack, &bad, |n, b| (!n.contains(first)).then_some(b), &[]);
    refused(&bad, "listed but missing");

    // 4. An unlisted file smuggled in.
    let bad = dir.path().join("bad4.zip");
    rewrite_pack(
        &pack,
        &bad,
        |_, b| Some(b),
        &[("keys/operator/extra.pub", &[7u8; 32])],
    );
    refused(&bad, "not listed in MANIFEST.json");

    // 5. Path traversal is refused before anything is written.
    let bad = dir.path().join("bad5.zip");
    rewrite_pack(&pack, &bad, |_, b| Some(b), &[("../escape.txt", b"x")]);
    erebus()
        .args(["verify-evidence", bad.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsafe path"));
    assert!(!dir.path().join("escape.txt").exists());

    // 6. The pack handed over with a different bundle.
    let other = make_bundle(dir.path(), "other", "print('not the audited agent')");
    erebus()
        .args(["verify-evidence", pack.to_str().unwrap()])
        .args(["--bundle", other.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("TAMPERED: bundle"));
}
