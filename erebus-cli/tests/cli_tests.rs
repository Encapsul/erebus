use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn erebus() -> Command {
    let mut cmd = Command::cargo_bin("erebus").unwrap();
    cmd.env("NO_COLOR", "1");
    cmd
}

#[test]
fn test_help_output() {
    erebus()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("erebus packages"));
}

#[test]
fn test_version_output() {
    erebus()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("erebus"));
}

#[test]
fn test_completion_bash() {
    erebus()
        .args(["completion", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete"));
}

#[test]
fn test_completion_zsh() {
    erebus()
        .args(["completion", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("compdef"));
}

#[test]
fn test_completion_fish() {
    erebus()
        .args(["completion", "fish"])
        .assert()
        .success()
        .stdout(predicate::str::contains("complete"));
}

#[test]
fn test_man_output() {
    let dir = tempdir().unwrap();
    let man_dir = dir.path().join("man");
    erebus()
        .args(["man", man_dir.to_str().unwrap()])
        .assert()
        .success();
    assert!(
        man_dir.join("erebus.1").exists(),
        "erebus.1 should be created"
    );
}

#[test]
fn test_doctor_output() {
    let output = erebus().arg("doctor").output().unwrap();
    assert!(
        output.status.code() == Some(0) || output.status.code() == Some(1),
        "doctor should exit 0 or 1"
    );
}

#[test]
fn test_doctor_strict() {
    let output = erebus().args(["doctor", "--strict"]).output().unwrap();
    assert!(
        output.status.code() == Some(0) || output.status.code() == Some(1),
        "doctor --strict should exit 0 or 1"
    );
}

#[test]
fn test_env_output() {
    erebus().arg("env").assert().success();
}

#[test]
fn test_clean_help() {
    erebus().args(["clean", "--help"]).assert().success();
}

#[test]
fn test_build_help_lists_sisr_flags() {
    erebus()
        .args(["build", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--enable-sisr"))
        .stdout(predicate::str::contains("--update-url"));
}

#[test]
fn test_build_dry_run_shows_sisr_when_enabled() {
    let dir = tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("app")).unwrap();
    std::fs::write(dir.path().join("app/requirements.txt"), "flask\n").unwrap();
    erebus()
        .args([
            "build",
            dir.path().join("app").to_str().unwrap(),
            "--enable-sisr",
            "--update-url",
            "https://updates.example.com/app",
            "--dry-run",
            "--no-install",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("SISR:      enabled"))
        .stderr(predicate::str::contains(
            "Update URL: https://updates.example.com/app",
        ));
}

#[test]
fn test_build_dry_run_does_not_enable_sisr_by_default() {
    let dir = tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("app")).unwrap();
    std::fs::write(dir.path().join("app/requirements.txt"), "flask\n").unwrap();
    erebus()
        .args([
            "build",
            dir.path().join("app").to_str().unwrap(),
            "--dry-run",
            "--no-install",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("SISR:      enabled").not());
}

/// `migrate` turns a legacy (SISR-less) file into a valid v2 file and
/// preserves the original payload bytes.
#[test]
fn test_migrate_converts_legacy_file() {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    use erebus_core::format::Footer;
    use erebus_core::sisr_header::read_sisr;
    use std::io::Cursor;

    let dir = tempdir().unwrap();
    let input = dir.path().join("legacy.erebus");
    assemble_erebus(
        &input,
        &AssemblyInput {
            stub_bytes: b"STUB_DATA",
            payload: b"PAYLOAD_PAYLOAD_PAYLOAD_PAYLOAD",
            meta_bytes: br#"{"name":"legacy"}"#,
            encrypt: false,
            squashfs: false,
            target_arch: None,
            sisr: None,
        },
    )
    .unwrap();

    let before = std::fs::read(&input).unwrap();
    let in_footer = Footer::read_from(&mut Cursor::new(&before)).unwrap();

    let output = dir.path().join("migrated.erebus");
    erebus()
        .args([
            "migrate",
            input.to_str().unwrap(),
            output.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("Upgraded"))
        .stderr(predicate::str::contains("manifest written"));

    let after = std::fs::read(&output).unwrap();
    let out_footer = Footer::read_from(&mut Cursor::new(&after)).unwrap();
    assert_ne!(out_footer.flags & erebus_core::format::FLAG_SISR, 0);
    assert_eq!(out_footer.payload_sha256, in_footer.payload_sha256);

    let payload_end = (in_footer.payload_offset + in_footer.payload_csize) as usize;
    assert_eq!(&after[..payload_end], &before[..payload_end]);

    let (_, manifest) = read_sisr(&mut Cursor::new(&after))
        .unwrap()
        .expect("migrated file must embed a SISR manifest");
    assert_eq!(manifest.payload_len, in_footer.payload_csize);

    assert!(dir.path().join("migrated.erebus.manifest").exists());
}

#[test]
fn test_inspect_reports_encrypted_v4() {
    use erebus_core::assembly::{assemble_erebus, build_meta_json, MetaOptions};
    use erebus_core::encrypt::encrypt_payload;
    use erebus_core::format::{Footer, CRYPTO_AES_256_GCM, FLAG_ENCRYPTED, FLAG_SIGNED};
    use erebus_core::metadata::BunFeatures;
    use std::io::Cursor;

    let dir = tempdir().unwrap();
    let out = dir.path().join("enc.erebus");
    let stub = b"STUB_DATA";
    let seed = [0xABu8; 32];
    let plaintext = b"SECRET_PAYLOAD_THAT_MUST_BE_ENCRYPTED";

    // 1. Encrypt the payload (AES-256-GCM, HKDF from a random encryption key).
    let (ciphertext, em) = encrypt_payload(plaintext, &seed).unwrap();
    assert_ne!(&ciphertext[..], plaintext);

    // 2. Build meta JSON with the `crypto` field (nonce + encryption key).
    let crypto_value = serde_json::json!({
        "nonce_hex": hex::encode(em.nonce),
        "tag_offset": em.tag_offset,
        "encryption_key_hex": hex::encode(seed),
    });
    let meta = build_meta_json(
        "enc",
        "binary",
        0,
        &["/app/app".to_string()],
        &[],
        &MetaOptions {
            version: None,
            author: None,
            description: None,
            license: None,
            payload_format: Some("raw".to_string()),
            seccomp: false,
            landlock: false,
            gui: false,
            app_hash: None,
            rt_deps_hash: None,
            update_url: None,
            crypto: Some(crypto_value),
            layers: None,
            entrypoint_layer: None,
            artifact_state: None,
            artifact_policy: None,
        },
        &BunFeatures::default(),
    )
    .unwrap();

    // 3. Assemble as v4 encrypted; integrity hash + footer cover the ciphertext.
    assemble_erebus(
        &out,
        &erebus_core::assembly::AssemblyInput {
            stub_bytes: stub,
            payload: &ciphertext,
            meta_bytes: &meta,
            encrypt: true,
            squashfs: false,
            target_arch: None,
            sisr: None,
        },
    )
    .unwrap();

    // 4. `erebus inspect` must report encrypted=true + v4, and echo the crypto meta.
    erebus()
        .args(["inspect", "--json", out.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""encrypted": true"#))
        .stdout(predicate::str::contains(r#""format_version": 4"#))
        .stdout(predicate::str::contains("nonce_hex"));

    // 5. Footer carries the encrypted flag + AES suite, and hashes the ciphertext.
    let data = std::fs::read(&out).unwrap();
    let footer = Footer::read_from(&mut Cursor::new(&data)).unwrap();
    assert_eq!(footer.format_version, 4);
    assert_ne!(
        footer.flags & FLAG_ENCRYPTED,
        0,
        "FLAG_ENCRYPTED must be set"
    );
    assert_eq!(footer.flags & FLAG_SIGNED, 0, "no signature in this test");
    assert_eq!(footer.crypto_suite(), CRYPTO_AES_256_GCM);
    assert_eq!(footer.payload_csize, ciphertext.len() as u64);
    assert_eq!(footer.payload_usize, CRYPTO_AES_256_GCM);
}

#[test]
fn test_attest_roundtrip() {
    use erebus_core::assembly::assemble_erebus;
    use erebus_core::assembly::AssemblyInput;

    let dir = tempdir().unwrap();
    let rootfs = dir.path().join("rootfs");
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), b"print('hello')").unwrap();

    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": "attest-test",
        "author": "test-user",
        "license": "MIT",
        "layers": [{
            "kind": "runtime",
            "name": "runtime/python3",
            "size": 1024,
        }],
    });
    let bin_path = dir.path().join("test.erebus");
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

    // Generate key pair
    let key_dir = dir.path().join("keys");
    erebus()
        .args(["keygen", "--key-dir", key_dir.to_str().unwrap()])
        .assert()
        .success();

    let key_file = std::fs::read_dir(&key_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.path().extension().map_or(false, |ext| ext == "key"))
        .expect("key file not found");

    // Run attest
    let attest_out = dir.path().join("test.erebus.attest");
    erebus()
        .args([
            "attest",
            bin_path.to_str().unwrap(),
            "--key",
            key_file.path().to_str().unwrap(),
            "--output",
            attest_out.to_str().unwrap(),
            "--json",
        ])
        .assert()
        .success();

    // Verify output file exists and is valid JSON
    assert!(attest_out.exists(), ".attest file must exist");
    let attest_data = std::fs::read(&attest_out).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&attest_data).unwrap();
    assert_eq!(parsed["spec_version"], "1.0");
    assert_eq!(parsed["attestation_type"], "erebus-execution");
    assert!(parsed["artifact"]["bundle_hash"].is_string());
    assert!(parsed["artifact"]["payload_hash"].is_string());
    assert!(parsed["execution"]["machine_id_hash"].is_string());
    assert!(parsed["signature"]["signature_hex"].is_string());
    assert!(parsed["signature"]["key_fingerprint"].is_string());
}

#[test]
fn test_lifecycle_promote_transitions_acquired_to_trusted() {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    use erebus_core::format::Footer;
    use erebus_core::metadata::ArtifactState;

    let dir = tempdir().unwrap();
    let rootfs = dir.path().join("rootfs");
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), b"print('hello')").unwrap();

    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": "lifecycle-test",
        "author": "test-user",
        "license": "MIT",
        "artifact_state": "Acquired",
    });
    let bin_path = dir.path().join("test.erebus");
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

    // Promote: Acquired -> Trusted
    erebus()
        .args([
            "lifecycle",
            bin_path.to_str().unwrap(),
            "--action",
            "promote",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Trusted"));

    // Re-read state from the rewritten binary
    let mut f = std::fs::File::open(&bin_path).unwrap();
    let footer = Footer::read_from(&mut f).unwrap();
    let meta = erebus_core::format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)
        .unwrap();
    let meta: serde_json::Value = serde_json::from_slice(&meta).unwrap();
    let state: ArtifactState = serde_json::from_value(meta["artifact_state"].clone()).unwrap();
    assert_eq!(state, ArtifactState::Trusted);
}

#[test]
fn test_lifecycle_quarantine_then_promote() {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    use erebus_core::format::Footer;
    use erebus_core::metadata::ArtifactState;

    let dir = tempdir().unwrap();
    let rootfs = dir.path().join("rootfs");
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), b"print('hi')").unwrap();

    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": "lifecycle-test",
        "author": "test-user",
        "license": "MIT",
        "artifact_state": "Acquired",
    });
    let bin_path = dir.path().join("test.erebus");
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

    fn read_state(p: &std::path::Path) -> ArtifactState {
        let mut f = std::fs::File::open(p).unwrap();
        let footer = Footer::read_from(&mut f).unwrap();
        let meta =
            erebus_core::format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)
                .unwrap();
        let meta: serde_json::Value = serde_json::from_slice(&meta).unwrap();
        serde_json::from_value(meta["artifact_state"].clone()).unwrap()
    }

    // Acquired -> Quarantined
    erebus()
        .args([
            "lifecycle",
            bin_path.to_str().unwrap(),
            "--action",
            "quarantine",
        ])
        .assert()
        .success();
    assert_eq!(read_state(&bin_path), ArtifactState::Quarantined);

    // Quarantined -> Trusted (valid transition)
    erebus()
        .args([
            "lifecycle",
            bin_path.to_str().unwrap(),
            "--action",
            "promote",
        ])
        .assert()
        .success();
    assert_eq!(read_state(&bin_path), ArtifactState::Trusted);

    // Trusted -> Revoked (valid transition)
    erebus()
        .args([
            "lifecycle",
            bin_path.to_str().unwrap(),
            "--action",
            "revoke",
        ])
        .assert()
        .success();
    assert_eq!(read_state(&bin_path), ArtifactState::Revoked);
}

#[test]
fn test_lifecycle_quarantine_clears_allow_untrusted() {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    use erebus_core::format::Footer;

    let dir = tempdir().unwrap();
    let rootfs = dir.path().join("rootfs");
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), b"print('hi')").unwrap();

    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    // A freshly-built artifact carries allow_untrusted=true (the build default
    // for an untrusted dev bundle). Quarantining it MUST clear that flag so
    // neither the stub nor the registry serves it.
    let meta = serde_json::json!({
        "name": "lifecycle-test",
        "author": "test-user",
        "license": "MIT",
        "artifact_state": "Acquired",
        "artifact_policy": {
            "allow_untrusted": true,
            "require_signature": false,
            "max_retries": 3,
        },
    });
    let bin_path = dir.path().join("test.erebus");
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

    fn read_policy(p: &std::path::Path) -> serde_json::Value {
        let mut f = std::fs::File::open(p).unwrap();
        let footer = Footer::read_from(&mut f).unwrap();
        let meta =
            erebus_core::format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)
                .unwrap();
        let meta: serde_json::Value = serde_json::from_slice(&meta).unwrap();
        meta["artifact_policy"].clone()
    }

    erebus()
        .args([
            "lifecycle",
            bin_path.to_str().unwrap(),
            "--action",
            "quarantine",
        ])
        .assert()
        .success();

    let policy = read_policy(&bin_path);
    assert_eq!(
        policy["allow_untrusted"].as_bool(),
        Some(false),
        "quarantine must clear allow_untrusted; got {policy}"
    );
}

#[test]
fn test_lifecycle_rejects_signed_file() {
    use erebus_core::assembly::{assemble_erebus, AssemblyInput};
    use erebus_core::format::Footer;

    let dir = tempdir().unwrap();
    let rootfs = dir.path().join("rootfs");
    std::fs::create_dir_all(rootfs.join("app")).unwrap();
    std::fs::write(rootfs.join("app/main.py"), b"print('hi')").unwrap();

    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
    let meta = serde_json::json!({
        "name": "lifecycle-signed",
        "author": "test-user",
        "license": "MIT",
        "artifact_state": "Acquired",
    });
    let bin_path = dir.path().join("signed.erebus");
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

    // Generate a key and sign the binary so it carries a signature block.
    let key_dir = dir.path().join("keys");
    erebus()
        .args(["keygen", "--key-dir", key_dir.to_str().unwrap()])
        .assert()
        .success();
    let key_file = std::fs::read_dir(&key_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| e.path().extension().map_or(false, |ext| ext == "key"))
        .expect("key file not found");
    erebus()
        .args([
            "sign",
            bin_path.to_str().unwrap(),
            "--key",
            key_file.path().to_str().unwrap(),
            "--quiet",
        ])
        .assert()
        .success();

    // Confirm it's signed.
    let mut f = std::fs::File::open(&bin_path).unwrap();
    let footer = Footer::read_from(&mut f).unwrap();
    assert!(footer.is_signed());

    // Lifecycle rewrite must fail closed on a signed file.
    erebus()
        .args([
            "lifecycle",
            bin_path.to_str().unwrap(),
            "--action",
            "promote",
        ])
        .assert()
        .failure();
}

#[test]
fn test_billing_help() {
    erebus()
        .args(["billing", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("billing"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("checkout"));
}

#[test]
fn test_billing_status_help() {
    erebus()
        .args(["billing", "status", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--registry"))
        .stdout(predicate::str::contains("--token"));
}

#[test]
fn test_billing_checkout_help() {
    erebus()
        .args(["billing", "checkout", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--plan"))
        .stdout(predicate::str::contains("--registry"))
        .stdout(predicate::str::contains("--token"));
}

#[test]
fn test_audit_log_help() {
    erebus()
        .args(["audit-log", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--registry"))
        .stdout(predicate::str::contains("--month"))
        .stdout(predicate::str::contains("--token"));
}

#[test]
fn test_sbom_help() {
    erebus()
        .args(["sbom", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--embed"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("CycloneDX"));
}
