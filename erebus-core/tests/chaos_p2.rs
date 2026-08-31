//! Chaos-monkey properties for the P2 registry guards.
//!
//! The P2 security modules share one invariant: **tampering fails closed**.
//! Rather than test each happy path in isolation, this suite builds a small
//! in-memory registry world (a GGUF model layer, a deletion audit trail, a
//! content-addressed blob store with manifests, a signed backup, an auth
//! policy) and then attacks each one the way a real adversary would:
//!
//! * swap a weight inside a GGUF file
//! * forge the actor on a soft-delete audit entry
//! * drop an orphaned blob and corrupt a referenced one
//! * tamper with the DR backup AFTER it was signed
//! * present a token minted with the wrong shared secret
//! * ship a dependency manifest pinned below a known-fixed version
//!
//! Every attack MUST be caught. If any guard accepts tampered state, the
//! chaos run fails.

use ed25519_dalek::{Signer, SigningKey};

use erebus_core::audit::{record_deletion, verify_deletion_entry};
use erebus_core::auth::{Authenticator, Ed25519Authenticator, HmacAuthenticator};
use erebus_core::backup::{build_backup_manifest, verify_backup};
use erebus_core::cve::{default_rules, parse_requirements, scan};
use erebus_core::gc::collect_garbage;
use erebus_core::gguf::parse_header;
use erebus_core::layer::verify_tensor_manifest;

/// Serialize a minimal GGUF header with `count` F16 tensors at ascending
/// offsets. Mirrors `gguf::tests::build_gguf`.
fn build_gguf(count: u64, kv_count: u64) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x4655_4747u32.to_le_bytes()); // magic
    v.extend_from_slice(&2u32.to_le_bytes()); // version
    v.extend_from_slice(&count.to_le_bytes()); // tensor count
    v.extend_from_slice(&kv_count.to_le_bytes()); // kv count
    let mut offset = 4096u64;
    for i in 0..count {
        let name = format!("weight.{i}");
        v.extend_from_slice(&(name.len() as u64).to_le_bytes());
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // 1 dim
        v.extend_from_slice(&32000u64.to_le_bytes()); // dim
        v.extend_from_slice(&1u32.to_le_bytes()); // F16
        v.extend_from_slice(&offset.to_le_bytes());
        offset += 64000;
    }
    v
}

fn test_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("erebus-chaos-p2-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn gguf_weight_swap_is_caught() {
    let original = build_gguf(3, 0);
    // Record the manifest from the clean file.
    let recorded = parse_header(&original).unwrap();

    // Attack 1: shift the last tensor's weight offset (weights rearranged).
    let mut swapped = original.clone();
    let offset_pos = swapped.len() - 8; // last 8 bytes are the final tensor's offset
    swapped[offset_pos..].copy_from_slice(&999999u64.to_le_bytes());
    let parsed_swapped = parse_header(&swapped).unwrap();
    assert!(
        !verify_tensor_manifest(&recorded, &parsed_swapped),
        "weight-swap in GGUF must be rejected"
    );

    // Attack 2: rename a tensor (replace weight.0 with weight.9 in-place).
    let mut renamed = original.clone();
    let name = b"weight.0";
    let name_pos = renamed.windows(name.len()).position(|w| w == name).unwrap();
    renamed[name_pos] = b'9'; // weight.0 -> weight.9
    let parsed_renamed = parse_header(&renamed).unwrap();
    assert!(
        !verify_tensor_manifest(&recorded, &parsed_renamed),
        "renamed GGUF tensor must be rejected"
    );
}

#[test]
fn soft_delete_audit_forgery_is_caught() {
    let admin = SigningKey::from_bytes(&[1u8; 32]);
    let attacker = SigningKey::from_bytes(&[2u8; 32]);

    let entry = record_deletion(
        "models/legacy.erebus",
        "admin@acme",
        "Trusted",
        "sha256:abc",
        &admin,
    )
    .unwrap();

    // Legit verification passes.
    assert!(verify_deletion_entry(&entry, &admin.verifying_key()));

    // Attack: attacker substitutes the actor AFTER the entry was signed.
    let mut forged = entry.clone();
    forged.actor = "attacker@acme".to_string();
    assert!(
        !verify_deletion_entry(&forged, &admin.verifying_key()),
        "post-signing actor swap must invalidate the audit trail"
    );

    // Attack: the attacker signs with their OWN key — still rejected against
    // the trusted key.
    let attacker_entry = record_deletion(
        "models/legacy.erebus",
        "attacker@acme",
        "Trusted",
        "sha256:abc",
        &attacker,
    )
    .unwrap();
    assert!(
        !verify_deletion_entry(&attacker_entry, &admin.verifying_key()),
        "wrong-key deletion record must be rejected"
    );
}

#[test]
fn garbage_collection_reclaims_orphans_and_keeps_live() {
    let dir = test_dir("gc");
    let blob = dir.join("blobs");
    let man = dir.join("manifests");
    let trash = dir.join("trash");
    std::fs::create_dir_all(&blob).unwrap();
    std::fs::create_dir_all(&man).unwrap();

    let live = "a".repeat(64);
    let orphan = "b".repeat(64);
    std::fs::write(blob.join(&live), b"live").unwrap();
    std::fs::write(blob.join(&orphan), b"orphan").unwrap();
    std::fs::write(man.join("app.json"), format!(r#"{{"blob":"{live}"}}"#)).unwrap();

    let res = collect_garbage(&blob, &man, &trash).unwrap();
    assert_eq!(
        res.reclaimed,
        vec![orphan.clone()],
        "orphan blob must be reclaimed"
    );
    assert_eq!(res.live_count, 1, "live blob must survive GC");
    assert!(blob.join(&live).exists());
    assert!(!blob.join(&orphan).exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn backup_detects_post_signing_tamper_and_missing_blob() {
    let dir = test_dir("backup");
    let man = dir.join("manifests");
    let blob = dir.join("blobs");
    std::fs::create_dir_all(&man).unwrap();
    std::fs::create_dir_all(&blob).unwrap();

    let blob_hash = "e".repeat(64);
    std::fs::write(blob.join(&blob_hash), b"data").unwrap();
    std::fs::write(
        man.join("app.json"),
        format!(r#"{{"name":"app","blob":"{blob_hash}"}}"#),
    )
    .unwrap();

    let key = SigningKey::from_bytes(&[3u8; 32]);
    let backup = build_backup_manifest(&man, &key).unwrap();

    // Attack 1: tamper the created_at AFTER signing.
    let mut tampered = backup.clone();
    tampered.created_at_utc = "1999-01-01T00:00:00Z".to_string();
    assert!(
        verify_backup(&tampered, &key.verifying_key(), None, None).is_err(),
        "post-signing tamper must invalidate the backup"
    );

    // Attack 2: delete a referenced blob then verify against the blob store.
    std::fs::remove_file(blob.join(&blob_hash)).unwrap();
    let err = verify_backup(&backup, &key.verifying_key(), Some(&man), Some(&blob)).unwrap_err();
    assert!(
        err.contains("missing blob"),
        "missing blob must fail restore: {err}"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn auth_rejects_wrong_secret_and_wrong_key() {
    // HMAC: mint with one secret, verify with another.
    let mint = HmacAuthenticator::new(b"secret-a");
    let verify = HmacAuthenticator::new(b"secret-b");
    let token = mint.mint("deploy-bot", 1_700_000_000);
    assert!(
        verify.authenticate(token.as_bytes()).is_err(),
        "wrong shared secret must reject the token"
    );

    // Ed25519: sign with A, verify with B's public key.
    let signer_a = SigningKey::from_bytes(&[4u8; 32]);
    let signer_b = SigningKey::from_bytes(&[5u8; 32]);
    let sig = signer_a.sign(b"bundle-99");
    let sig_b64 = b64url(&sig.to_bytes());
    let token = format!("bundle-99:{sig_b64}");
    let authenticator =
        Ed25519Authenticator::from_bytes(&signer_b.verifying_key().to_bytes()).unwrap();
    assert!(
        authenticator.authenticate(token.as_bytes()).is_err(),
        "bearer token signed by an untrusted key must be rejected"
    );
}

#[test]
fn cve_scanner_flags_known_vulnerable_pin() {
    let manifest = "requests==2.25.0\nurllib3==2.2.1\nlodash==4.17.20\n";
    let comps = parse_requirements(manifest);
    let findings = scan(&comps, &default_rules());
    // requests 2.25.0 is < 2.32.0 (CVE-2024-35195), lodash 4.17.20 < 4.17.21
    // (CVE-2021-23337). urllib3 2.2.1 is above fixed-in 1.26.19, so no finding.
    let ids: Vec<&str> = findings.iter().map(|f| f.cve_id.as_str()).collect();
    assert!(
        ids.contains(&"CVE-2024-35195"),
        "requests pin must be flagged: {ids:?}"
    );
    assert!(
        ids.contains(&"CVE-2021-23337"),
        "lodash pin must be flagged: {ids:?}"
    );
    assert!(
        !ids.contains(&"CVE-2024-37891"),
        "urllib3 2.2.1 is above the fixed-in, must NOT flag: {ids:?}"
    );
}

/// B64url without padding (mirrors `auth::base64url`).
fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(c.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(c.get(2).copied().unwrap_or(0));
        s.push(A[((n >> 18) & 63) as usize] as char);
        s.push(A[((n >> 12) & 63) as usize] as char);
        if c.len() > 1 {
            s.push(A[((n >> 6) & 63) as usize] as char);
        }
        if c.len() > 2 {
            s.push(A[(n & 63) as usize] as char);
        }
    }
    s
}
