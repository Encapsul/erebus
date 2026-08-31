//! Backup / restore manifest for disaster recovery.
//!
//! A registry's durable state is its set of artifact manifests plus the blobs
//! they reference. This module produces a signed backup manifest describing
//! every entry, so a restore can verify that a recovered image matches what
//! was backed up — catching missing, truncated, or bit-rotted blobs before the
//! registry is brought back online.

use crate::attest::sha256_hex;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// One artifact entry in a backup manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    /// Registry-relative artifact name (e.g. `models/llama-3.1-8b`).
    pub name: String,
    /// SHA-256 hex of the on-disk artifact manifest file.
    pub manifest_sha256: String,
    /// The blob hashes this artifact depends on.
    pub blobs: Vec<String>,
    /// File size of the artifact manifest.
    pub size: u64,
}

/// The full backup manifest — enumerates every artifact and its blob closure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    pub spec_version: String,
    pub created_at_utc: String,
    pub artifact_count: u64,
    pub blob_count: u64,
    pub total_blob_refs: u64,
    pub entries: Vec<BackupEntry>,
    pub sig_algorithm: String,
    pub key_fingerprint: String,
    pub signature_hex: String,
}

/// Build a backup manifest by scanning `manifest_dir`.
///
/// Every `*.json` file in `manifest_dir` is treated as one artifact. Its
/// SHA-256 and size are recorded, and every 64-char lowercase hex blob token
/// inside the JSON is collected as a dependency.
///
/// The manifest is signed with `signing_key`; the signature covers the
/// serialized manifest with the signature blank, so tampering after backup is
/// detectable.
///
/// # Errors
///
/// Returns an IO error when a manifest file cannot be read.
pub fn build_backup_manifest(
    manifest_dir: &Path,
    signing_key: &SigningKey,
) -> io::Result<BackupManifest> {
    let mut entries = Vec::new();
    let mut seen_blobs = BTreeMap::new();
    let dirs = match std::fs::read_dir(manifest_dir) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(sign_empty_manifest(signing_key))
        }
        Err(e) => return Err(e),
    };
    for entry in dirs.flatten() {
        let path = entry.path();
        if !path.is_file() || !path.extension().is_some_and(|e| e == "json") {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let data = std::fs::read(&path)?;
        let manifest_sha256 = sha256_hex(&data);
        let size = data.len() as u64;
        let blobs = collect_blob_refs(&data);
        for b in &blobs {
            *seen_blobs.entry(b.clone()).or_insert(0u64) += 1;
        }
        entries.push(BackupEntry {
            name: file_name,
            manifest_sha256,
            size,
            blobs,
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let total_bytes: u64 = seen_blobs.values().sum();
    let mut manifest = BackupManifest {
        spec_version: "1.0".to_string(),
        created_at_utc: time::OffsetDateTime::now_utc().to_string(),
        artifact_count: entries.len() as u64,
        blob_count: seen_blobs.len() as u64,
        total_blob_refs: total_bytes,
        entries,
        sig_algorithm: "ed25519".to_string(),
        key_fingerprint: sha256_hex(&signing_key.verifying_key().to_bytes()),
        signature_hex: String::new(),
    };
    let hash = signed_hash(&manifest);
    manifest.signature_hex = hex::encode(signing_key.sign(&hash).to_bytes());
    Ok(manifest)
}

/// Verify a backup manifest's signature and, optionally, the content layout.
///
/// Returns `Ok(())` when the signature validates against `vk` and, when
/// `manifest_dir` is provided, every entry's manifest file rehashes to the
/// recorded value and the referenced blobs are present in `blob_dir`.
///
/// # Errors
///
/// Returns a message string wrapped as the error when verification fails.
pub fn verify_backup(
    manifest: &BackupManifest,
    vk: &VerifyingKey,
    manifest_dir: Option<&Path>,
    blob_dir: Option<&Path>,
) -> Result<(), String> {
    let hash = signed_hash(manifest);
    let sig_bytes =
        hex::decode(&manifest.signature_hex).map_err(|e| format!("bad sig hex: {e}"))?;
    let sig =
        ed25519_dalek::Signature::from_slice(&sig_bytes).map_err(|e| format!("bad sig: {e}"))?;
    vk.verify(&hash, &sig)
        .map_err(|e| format!("signature invalid: {e}"))?;

    if let Some(dir) = manifest_dir {
        for entry in &manifest.entries {
            let p = dir.join(&entry.name);
            let data = std::fs::read(&p).map_err(|e| format!("{}: {e}", entry.name))?;
            if sha256_hex(&data) != entry.manifest_sha256 {
                return Err(format!("{} hash mismatch", entry.name));
            }
        }
    }
    if let Some(blobdir) = blob_dir {
        for entry in &manifest.entries {
            for blob in &entry.blobs {
                if !blobdir.join(blob).exists() {
                    return Err(format!("missing blob {blob} (artifact {})", entry.name));
                }
            }
        }
    }
    Ok(())
}

/// Hash of the manifest with the signature field blanked.
fn signed_hash(manifest: &BackupManifest) -> Vec<u8> {
    let mut doc = manifest.clone();
    doc.signature_hex = String::new();
    let bytes = serde_json::to_vec(&doc).unwrap_or_default();
    Sha256::digest(&bytes).to_vec()
}

/// Sign an empty placeholder manifest with only signature fields populated.
fn sign_empty_manifest(signing_key: &SigningKey) -> BackupManifest {
    let mut m = BackupManifest {
        spec_version: "1.0".to_string(),
        created_at_utc: time::OffsetDateTime::now_utc().to_string(),
        artifact_count: 0,
        blob_count: 0,
        total_blob_refs: 0,
        entries: Vec::new(),
        sig_algorithm: "ed25519".to_string(),
        key_fingerprint: sha256_hex(&signing_key.verifying_key().to_bytes()),
        signature_hex: String::new(),
    };
    m.signature_hex = hex::encode(signing_key.sign(&signed_hash(&m)).to_bytes());
    m
}

/// Extract every lowercase `[0-9a-f]{64}` token from `data`.
fn collect_blob_refs(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        let lower = b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        if lower {
            let s = start.get_or_insert(i);
            if i - *s + 1 == 64 {
                out.push(String::from_utf8_lossy(&data[*s..=i]).into_owned());
                start = None;
            }
        } else {
            start = None;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("erebus-backup-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    #[test]
    fn build_and_verify_roundtrip() {
        let dir = test_dir("roundtrip");
        let man = dir.join("manifests");
        let blob = dir.join("blobs");
        fs::create_dir_all(&man).unwrap();
        fs::create_dir_all(&blob).unwrap();

        let blob_hash = "a".repeat(64);
        fs::write(blob.join(&blob_hash), b"data").unwrap();
        fs::write(
            man.join("app.json"),
            format!(r#"{{"name":"app","blob":"{blob_hash}"}}"#),
        )
        .unwrap();

        let key = test_key();
        let manifest = build_backup_manifest(&man, &key).unwrap();
        assert_eq!(manifest.artifact_count, 1);
        assert_eq!(manifest.blob_count, 1);
        assert!(!manifest.signature_hex.is_empty());

        verify_backup(&manifest, &key.verifying_key(), Some(&man), Some(&blob)).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn detects_missing_blob() {
        let dir = test_dir("missing");
        let man = dir.join("manifests");
        let blob = dir.join("blobs");
        fs::create_dir_all(&man).unwrap();
        fs::create_dir_all(&blob).unwrap();

        let b = "d".repeat(64);
        fs::write(man.join("a.json"), format!(r#"{{"b":"{b}"}}"#)).unwrap();
        // Do NOT create the blob.

        let key = test_key();
        let manifest = build_backup_manifest(&man, &key).unwrap();
        let err =
            verify_backup(&manifest, &key.verifying_key(), Some(&man), Some(&blob)).unwrap_err();
        assert!(err.contains("missing blob"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_tampered_manifest() {
        let dir = test_dir("tamper");
        let man = dir.join("manifests");
        fs::create_dir_all(&man).unwrap();
        fs::write(man.join("a.json"), r#"{"a":1}"#).unwrap();

        let key = test_key();
        let mut manifest = build_backup_manifest(&man, &key).unwrap();
        // Tamper after signing.
        manifest.created_at_utc = "1970-01-01T00:00:00Z".to_string();
        let err = verify_backup(&manifest, &key.verifying_key(), None, None).unwrap_err();
        assert!(err.contains("signature invalid"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_dir_signs_empty_manifest() {
        let dir = test_dir("empty");
        fs::create_dir_all(&dir).unwrap();
        let key = test_key();
        let manifest = build_backup_manifest(&dir, &key).unwrap();
        assert_eq!(manifest.artifact_count, 0);
        verify_backup(&manifest, &key.verifying_key(), None, None).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
