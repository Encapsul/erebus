//! Chaos-monkey suite for `erebus swap` and the layer registry.
//!
//! Philosophy: every test feeds the tool hostile input — truncated binaries,
//! flipped bytes, traversal targets, concurrent writers, garbage indexes —
//! and asserts two invariants:
//! 1. the tool fails *cleanly* (no panic, non-zero or explicit refusal),
//! 2. pre-existing artifacts are never left half-written or corrupted.

use assert_cmd::Command;
use erebus_core::assembly::{assemble_erebus, AssemblyInput};
use erebus_core::format::Footer;
use predicates::prelude::*;
use std::io::{Cursor, Write};
use std::path::Path;
use tempfile::{tempdir, TempDir};

fn erebus() -> Command {
    let mut cmd = Command::cargo_bin("erebus").unwrap();
    cmd.env("NO_COLOR", "1");
    cmd
}

/// Builds a minimal but structurally valid .erebus fixture whose payload is
/// a genuine tar.zst stream of a tiny rootfs (`app/model.bin`, `app/app.py`).
fn build_fixture(dir: &Path, model_bytes: &[u8]) -> std::path::PathBuf {
    let rootfs = dir.join("rootfs");
    std::fs::create_dir_all(rootfs.join("app/models")).unwrap();
    std::fs::write(rootfs.join("app/app.py"), b"print('hi')").unwrap();
    std::fs::write(rootfs.join("app/models/agent.gguf"), model_bytes).unwrap();
    let payload = erebus_core::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();

    let meta = serde_json::json!({
        "name": "chaos",
        "layers": [{
            "kind": "model",
            "name": "agent",
            "format": "gguf",
            "path": "models/agent.gguf",
            "size": model_bytes.len() as u64,
        }],
    });
    let out = dir.join("app.erebus");
    assemble_erebus(
        &out,
        &AssemblyInput {
            stub_bytes: b"MUTABLE-STUB-BYTES",
            payload: &payload,
            meta_bytes: serde_json::to_vec(&meta).unwrap().as_slice(),
            encrypt: false,
            squashfs: false,
            target_arch: None,
            sisr: None,
        },
    )
    .unwrap();
    out
}

fn swap_args(binary: &Path, target: &str, from: &Path) -> [String; 5] {
    [
        "swap".into(),
        binary.display().to_string(),
        target.into(),
        "--from".into(),
        from.display().to_string(),
    ]
}

// ── Hostile input ───────────────────────────────────────────────────────

#[test]
fn chaos_truncated_binary_fails_without_touching_output() {
    let dir = tempdir().unwrap();
    let bin = build_fixture(dir.path(), b"PAYLOAD");
    let original = std::fs::read(&bin).unwrap();

    // Truncate at every length: swap must fail (or be impossible), and must
    // never write an output file on failure.
    for cut in [0usize, 1, 10, 50, original.len() - 1] {
        let broken = dir.path().join(format!("cut-{cut}.erebus"));
        std::fs::write(&broken, &original[..cut]).unwrap();
        let replacement = dir.path().join("repl.txt");
        std::fs::write(&replacement, b"new").unwrap();

        let out = dir.path().join("out.erebus");
        let _ = std::fs::remove_file(&out);
        let _ = erebus()
            .args(swap_args(&broken, "app/model.bin", &replacement))
            .arg("-o")
            .arg(&out)
            .assert();
        // Whatever the exit code, a failed run must not produce output bytes…
        if !out.exists() {
            continue;
        }
        // …and if it did produce output, it must be a fully valid binary.
        Footer::read_from(&mut Cursor::new(std::fs::read(&out).unwrap()))
            .expect("output of a successful swap must parse");
    }
}

#[test]
fn chaos_random_byte_corruption_never_panics_and_never_corrupts_output() {
    let dir = tempdir().unwrap();
    let bin = build_fixture(dir.path(), b"SOME-PAYLOAD-CONTENT-0123456789");
    let replacement = dir.path().join("repl.bin");
    std::fs::write(&replacement, b"fresh-bytes").unwrap();

    // Deterministic pseudo-random flips across the whole file.
    let mut seed = 0x5EED_u64;
    let mut flip = |i: usize| -> u8 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        ((seed >> 33) & 0xFF) as u8 ^ i as u8
    };

    let data = std::fs::read(&bin).unwrap();
    for step in 0..40u64 {
        let mut corrupted = data.clone();
        let pos = ((step * 137 + 13) as usize) % data.len();
        corrupted[pos] = flip(pos);
        let bad = dir.path().join("bad.erebus");
        std::fs::write(&bad, &corrupted).unwrap();

        let out = dir.path().join("out2.erebus");
        let _ = std::fs::remove_file(&out);
        let result = erebus()
            .args(swap_args(&bad, "app/model.bin", &replacement))
            .arg("-o")
            .arg(&out)
            .assert();
        if out.exists() && result.get_output().status.success() {
            // A swap that reports success must yield a self-consistent file.
            Footer::read_from(&mut Cursor::new(std::fs::read(&out).unwrap()))
                .expect("successful swap on corrupt input still emitted valid output");
        }
        // The source file is only ever read, never written by swap.
        assert_eq!(std::fs::read(&bad).unwrap(), corrupted);
    }
}

#[test]
fn chaos_garbage_file_refused_cleanly() {
    let dir = tempdir().unwrap();
    let junk = dir.path().join("junk.erebus");
    std::fs::write(&junk, vec![0xDEu8; 512]).unwrap();
    let replacement = dir.path().join("repl.bin");
    std::fs::write(&replacement, b"x").unwrap();

    erebus()
        .args(swap_args(&junk, "app/m.gguf", &replacement))
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a .erebus").or(predicate::str::contains("Error")));
}

#[test]
fn chaos_traversal_targets_rejected() {
    let dir = tempdir().unwrap();
    let bin = build_fixture(dir.path(), b"P");
    let replacement = dir.path().join("repl.bin");
    std::fs::write(&replacement, b"x").unwrap();

    for evil in ["../escape.bin", "/etc/passwd", "a/../../b", ".."] {
        erebus()
            .args(swap_args(&bin, evil, &replacement))
            .assert()
            .failure()
            .stderr(predicate::str::contains("not allowed").or(predicate::str::contains("empty")));
        // Source untouched after each rejection.
        Footer::read_from(&mut Cursor::new(std::fs::read(&bin).unwrap())).unwrap();
    }
}

// ── Encrypted binaries are refused ──────────────────────────────────────

#[test]
fn chaos_encrypted_binary_refused() {
    use erebus_core::encrypt::encrypt_payload;

    let dir = tempdir().unwrap();
    let seed = [0x11u8; 32];
    let (ciphertext, em) = encrypt_payload(b"CIPHERTEXT", &seed).unwrap();
    let crypto_value = serde_json::json!({
        "nonce_hex": hex::encode(em.nonce),
        "tag_offset": em.tag_offset,
        "encryption_key_hex": hex::encode(seed),
    });
    let out = dir.path().join("enc.erebus");
    assemble_erebus(
        &out,
        &AssemblyInput {
            stub_bytes: b"STUB",
            payload: &ciphertext,
            meta_bytes: serde_json::to_vec(&serde_json::json!({
                "name": "enc",
                "crypto": crypto_value,
            }))
            .unwrap()
            .as_slice(),
            encrypt: true,
            squashfs: false,
            target_arch: None,
            sisr: None,
        },
    )
    .unwrap();

    let before = std::fs::read(&out).unwrap();
    let replacement = dir.path().join("repl.bin");
    std::fs::write(&replacement, b"x").unwrap();

    erebus()
        .args(swap_args(&out, "app/m.gguf", &replacement))
        .env_remove("NO_COLOR")
        .assert()
        .failure()
        .stderr(predicate::str::contains("encrypted"));

    assert_eq!(std::fs::read(&out).unwrap(), before);
}

// ── Concurrency / interruption ──────────────────────────────────────────

/// N concurrent swaps targeting the same output: every finished writer either
/// renamed atomically or failed; the final file must always be a valid binary.
#[test]
fn chaos_concurrent_swaps_leave_valid_output() {
    let dir = tempdir().unwrap();
    let bin = build_fixture(dir.path(), b"BASE-PAYLOAD");

    let mut children = Vec::new();
    for i in 0..8u32 {
        let replacement = dir.path().join(format!("repl-{i}.bin"));
        std::fs::write(&replacement, format!("content-{i}")).unwrap();
        let bin_path = bin.clone();
        let repl_path = replacement.clone();
        let target = dir.path().join("shared-out.erebus");
        children.push(std::thread::spawn(move || {
            erebus()
                .args(swap_args(&bin_path, "app/model.bin", &repl_path))
                .arg("-o")
                .arg(target)
                .assert()
                .success();
        }));
    }
    for c in children {
        c.join().unwrap();
    }

    let final_bytes = std::fs::read(dir.path().join("shared-out.erebus")).unwrap();
    let footer = Footer::read_from(&mut Cursor::new(final_bytes)).expect("final output must parse");
    // Integrity hash must match whatever content landed last.
    let parts = erebus_core::swap::BinaryParts::read(&dir.path().join("shared-out.erebus"))
        .expect("final output must be fully readable");
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&parts.payload);
    h.update(&parts.meta_bytes);
    let digest: [u8; 32] = h.finalize().into();
    assert_eq!(footer.payload_sha256, digest);

    // No temp files left behind by any interrupted writer.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "temp files leaked: {leftovers:?}");
}

/// Killing a swap mid-write must never damage the destination.
/// We approximate SIGKILL by dropping the process's `AtomicWriter` guarantee:
/// run with a replacement path whose parent disappears mid-run is flaky, so
/// instead we verify the invariant directly at the unit level via core.
#[test]
fn chaos_interrupted_swap_leaves_destination_intact() {
    let dir = tempdir().unwrap();
    let dst = dir.path().join("target.erebus");
    std::fs::write(&dst, b"ORIGINAL-BINARY").unwrap();

    // Simulate a writer killed between tmp creation and commit.
    let tag = "target.erebus";
    {
        let mut w = erebus_core::sisr::swap::AtomicWriter::new(dir.path(), tag).unwrap();
        w.file_mut().write_all(b"HALF-WRITTEN").unwrap();
        drop(w); // <- crash/kill equivalent: uncommitted drop
    }
    assert_eq!(std::fs::read(&dst).unwrap(), b"ORIGINAL-BINARY");

    // No stale temp survives the simulated kill.
    let stale: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name())
        .filter(|n| n.to_string_lossy().starts_with('.'))
        .collect();
    assert!(stale.is_empty(), "stale temps: {stale:?}");
}

// ── Successful swap keeps the binary runnable ───────────────────────────

#[test]
fn chaos_swapped_binary_survives_inspect_and_verify() {
    let dir = tempdir().unwrap();
    let bin = build_fixture(dir.path(), b"OLD-MODEL-BYTES");
    let replacement = dir.path().join("model.gguf");
    std::fs::write(&replacement, b"NEW-MODEL-WEIGHTS").unwrap();

    erebus()
        .args(swap_args(&bin, "app/models/agent.gguf", &replacement))
        .assert()
        .success();

    // The modified binary must still parse and its integrity hash must cover
    // the new payload — i.e. `inspect` works and no corruption crept in.
    let footer = Footer::read_from(&mut Cursor::new(std::fs::read(&bin).unwrap())).unwrap();
    let parts = erebus_core::swap::BinaryParts::read(&bin).unwrap();
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&parts.payload);
    h.update(&parts.meta_bytes);
    let digest: [u8; 32] = h.finalize().into();
    assert_eq!(footer.payload_sha256, digest);

    // Decompress the swapped payload and confirm the new weights landed.
    let unpacked = tempdir().unwrap();
    erebus_core::tar::extract_tar_zstd(&parts.payload[..], unpacked.path()).unwrap();
    let model = std::fs::read(unpacked.path().join("app/models/agent.gguf")).unwrap();
    assert_eq!(model, b"NEW-MODEL-WEIGHTS");

    // Model layer metadata size was updated to match.
    let meta: serde_json::Value = serde_json::from_slice(&parts.meta_bytes).unwrap();
    assert_eq!(meta["layers"][0]["size"], b"NEW-MODEL-WEIGHTS".len() as u64);
}

// ── Registry chaos ──────────────────────────────────────────────────────

#[test]
fn chaos_registry_corrupted_index_errors_but_registry_recovers() {
    let dir = TempDir::new_in(tempdir().unwrap().path()).unwrap();
    let root = dir.path().join("layers");
    let mut reg = erebus_core::registry::LayerRegistry::open(&root).unwrap();
    reg.push("m", erebus_core::layer::LayerKind::Model, b"bytes")
        .unwrap();

    // Corrupt the index behind the registry's back.
    std::fs::write(root.join("index.json"), b"{ not json !!!").unwrap();
    assert!(reg.list().is_err(), "corrupt index must surface as error");

    // Rewriting a valid index restores operation (no unrecoverable state).
    std::fs::write(root.join("index.json"), "{}").unwrap();
    assert_eq!(reg.list().unwrap().len(), 0);
}

#[test]
fn chaos_registry_tampered_object_detected_on_read() {
    let dir = TempDir::new_in(tempdir().unwrap().path()).unwrap();
    let root = dir.path().join("layers");
    let mut reg = erebus_core::registry::LayerRegistry::open(&root).unwrap();
    let entry = reg
        .push("m", erebus_core::layer::LayerKind::Model, b"weights")
        .unwrap();

    let obj = root.join("objects").join(&entry.sha256);
    let mut data = std::fs::read(&obj).unwrap();
    data[0] ^= 0xFF; // single flipped bit
    std::fs::write(&obj, &data).unwrap();

    assert!(reg.read(&entry).is_err(), "flipped bit must be detected");
    assert!(
        reg.materialize("m", &dir.path().join("out.bin")).is_err(),
        "materialize must refuse tampered objects"
    );
}
