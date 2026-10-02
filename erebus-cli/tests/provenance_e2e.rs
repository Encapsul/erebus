//! R5: `erebus provenance` signs an SLSA v1 statement. A dirty tree is in the
//! signed predicate, and `verify-attest --provenance --bundle` follows
//! receipt to bundle to source. When `cosign` is installed it must accept
//! the envelope.

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
    let meta = serde_json::json!({"name": "p", "author": "t", "license": "MIT"});
    let bin = dir.join("p.erebus");
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
fn dirty_source_is_in_the_signed_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("src");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("app.py"), "print(1)\n").unwrap();
    let bundle = bundle(dir.path());
    let key_bytes = [9u8; 32];
    let key = SigningKey::from_bytes(&key_bytes);
    let key_path = dir.path().join("op.key");
    std::fs::write(&key_path, key_bytes).unwrap();
    let trusted = dir.path().join("trusted");
    std::fs::create_dir_all(&trusted).unwrap();
    std::fs::write(trusted.join("op.pub"), key.verifying_key().as_bytes()).unwrap();
    let pem = erebus_core::dsse::public_key_pem(&key.verifying_key());
    let pem_path = dir.path().join("op.pem");
    std::fs::write(&pem_path, &pem).unwrap();

    let slsa = dir.path().join("p.erebus.slsa.json");
    let emitted = erebus()
        .arg("provenance")
        .arg(&source)
        .arg("--subject")
        .arg(&bundle)
        .arg("--key")
        .arg(&key_path)
        .arg("-o")
        .arg(&slsa)
        .output()
        .unwrap();
    assert!(
        emitted.status.success(),
        "{}",
        String::from_utf8_lossy(&emitted.stderr)
    );

    let trail = dir.path().join("trail");
    let log = AttestationLog::open(&trail).unwrap();
    let template = AttestationTemplate::from_bundle(&bundle).unwrap();
    let att = template.attest(&key, &ExecutionCapture::default()).unwrap();
    let receipt = log.append(&att).unwrap();

    let verified = erebus()
        .arg("verify-attest")
        .arg(&receipt)
        .arg("--bundle")
        .arg(&bundle)
        .arg("--trusted-dir")
        .arg(&trusted)
        .arg("--provenance")
        .arg(&slsa)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&verified.stderr);
    assert!(verified.status.success(), "{text}");
    assert!(text.contains("dirty tree"), "{text}");

    if Command::new("cosign").arg("version").output().is_err() {
        return;
    }
    let cosign = Command::new("cosign")
        .args([
            "verify-blob-attestation",
            "--key",
            pem_path.to_str().unwrap(),
            "--signature",
            slsa.to_str().unwrap(),
            "--type",
            "https://slsa.dev/provenance/v1",
            "--insecure-ignore-tlog",
            bundle.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&cosign.stdout),
        String::from_utf8_lossy(&cosign.stderr)
    );
    assert!(
        cosign.status.success() && out.contains("Verified OK"),
        "{out}"
    );
}
