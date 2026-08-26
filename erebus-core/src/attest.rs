//! Attestation generation and verification for `.erebus` files.
//!
//! Produces detached `.erebus.attest` documents — signed JSON proving
//! what executed, on what type of machine, and when. The hostname is
//! never included in plaintext; only a SHA-256 hash of
//! `hostname + os + arch` is recorded.

use crate::format::Footer;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use time::format_description::well_known::Iso8601;
use time::OffsetDateTime;

/// Current attestation spec version.
pub const ATTESTATION_SPEC_VERSION: &str = "1.0";

/// Marker string identifying this as an erebus execution attestation.
pub const ATTESTATION_TYPE: &str = "erebus-execution";

// ── Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub spec_version: String,
    pub attestation_type: String,
    pub artifact: ArtifactInfo,
    pub provenance: ProvenanceInfo,
    pub execution: ExecutionInfo,
    pub signature: SignatureInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub bundle_hash: String,
    pub payload_hash: String,
    pub metadata_hash: String,
    pub format_version: u8,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceInfo {
    pub builder: String,
    pub author: Option<String>,
    pub license: Option<String>,
    pub layers: Vec<LayerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub name: String,
    pub kind: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionInfo {
    pub attested_at: String,
    pub machine_id_hash: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub algorithm: String,
    pub key_fingerprint: String,
    pub signature_hex: String,
}

// ── Core functions ──────────────────────────────────────────────────────

/// Compute SHA-256 hex string of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("sha256:{}", hex::encode(hash))
}

/// Compute the machine identity hash: SHA-256(hostname + os + arch).
/// The hostname is never stored in plaintext.
pub fn machine_id_hash() -> String {
    let hostname = get_hostname();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(os.as_bytes());
    hasher.update(arch.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Extract flag names from a footer's flags byte.
pub fn flag_names(flags: u8) -> Vec<String> {
    let mut names = Vec::new();
    if flags & 0x01 != 0 {
        names.push("signed".to_string());
    }
    if flags & 0x02 != 0 {
        names.push("encrypted".to_string());
    }
    if flags & 0x04 != 0 {
        names.push("sisr".to_string());
    }
    names
}

/// Generate an attestation for a `.erebus` file.
///
/// Reads the binary, extracts footer + metadata hashes, computes machine
/// identity, and signs everything with the given Ed25519 key.
///
/// # Errors
///
/// Returns an error if the file cannot be read, the footer is invalid,
/// or the signing key is invalid.
pub fn generate_attestation(
    bundle_path: &Path,
    signing_key: &SigningKey,
) -> Result<Attestation, anyhow::Error> {
    let bundle_bytes =
        std::fs::read(bundle_path).map_err(|e| anyhow::anyhow!("failed to read bundle: {e}"))?;

    let mut cursor = std::io::Cursor::new(&bundle_bytes);
    let footer = Footer::read_from(&mut cursor)
        .map_err(|e| anyhow::anyhow!("failed to read footer: {e}"))?;

    // Hash the full bundle
    let bundle_hash = sha256_hex(&bundle_bytes);

    // Hash payload
    let payload_start = footer.payload_offset as usize;
    let payload_end = payload_start + footer.payload_csize as usize;
    let payload = if payload_end <= bundle_bytes.len() {
        &bundle_bytes[payload_start..payload_end]
    } else {
        anyhow::bail!("payload extends beyond file boundary");
    };
    let payload_hash = sha256_hex(payload);

    // Hash metadata
    let meta_start = footer.meta_offset as usize;
    let meta_end = meta_start + footer.meta_size as usize;
    let meta = if meta_end <= bundle_bytes.len() {
        &bundle_bytes[meta_start..meta_end]
    } else {
        anyhow::bail!("metadata extends beyond file boundary");
    };
    let metadata_hash = sha256_hex(meta);

    // Parse metadata JSON for provenance
    let metadata: serde_json::Value = serde_json::from_slice(meta)
        .map_err(|e| anyhow::anyhow!("failed to parse metadata JSON: {e}"))?;

    let builder = format!("erebus-cli v{}", env!("CARGO_PKG_VERSION"));
    let author = metadata
        .get("author")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let license = metadata
        .get("license")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Extract layers
    let layers: Vec<LayerInfo> = metadata
        .get("layers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|layer| {
                    let name = layer.get("name")?.as_str()?.to_string();
                    let kind = layer.get("kind")?.as_str()?.to_string();
                    let sha256 = layer
                        .get("sha256")
                        .and_then(|v| v.as_str())
                        .map(|s| format!("sha256:{s}"))
                        .unwrap_or_default();
                    Some(LayerInfo { name, kind, sha256 })
                })
                .collect()
        })
        .unwrap_or_default();

    // Build attestation (unsigned first)
    let attestation = Attestation {
        spec_version: ATTESTATION_SPEC_VERSION.to_string(),
        attestation_type: ATTESTATION_TYPE.to_string(),
        artifact: ArtifactInfo {
            bundle_hash,
            payload_hash,
            metadata_hash,
            format_version: footer.format_version,
            flags: flag_names(footer.flags),
        },
        provenance: ProvenanceInfo {
            builder,
            author,
            license,
            layers,
        },
        execution: ExecutionInfo {
            attested_at: utc_now_iso8601(),
            machine_id_hash: machine_id_hash(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        },
        signature: SignatureInfo {
            algorithm: "ed25519".to_string(),
            key_fingerprint: format!(
                "sha256:{}",
                hex::encode(Sha256::digest(signing_key.verifying_key().as_bytes()))
            ),
            signature_hex: String::new(), // filled after signing
        },
    };

    // Serialize, sign, fill signature
    let doc_bytes = serde_json::to_vec_pretty(&attestation)
        .map_err(|e| anyhow::anyhow!("failed to serialize attestation: {e}"))?;
    let sig = signing_key.sign(&doc_bytes);

    let mut signed = attestation;
    signed.signature.signature_hex = hex::encode(sig.to_bytes());

    Ok(signed)
}

/// ISO 8601 UTC timestamp.
fn utc_now_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let datetime = OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .to_offset(time::UtcOffset::UTC);
    datetime.format(&Iso8601::DEFAULT).unwrap_or_default()
}

/// Get the system hostname, or "unknown" if unavailable.
fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Verify an attestation against a set of trusted public keys.
///
/// Returns the verifying key that matched, or an error.
pub fn verify_attestation(
    attestation: &Attestation,
    trusted_keys: &[VerifyingKey],
) -> Result<VerifyingKey, anyhow::Error> {
    // Reconstruct the unsigned document by clearing the signature
    let mut doc = attestation.clone();
    doc.signature.signature_hex = String::new();

    let doc_bytes = serde_json::to_vec(&doc)
        .map_err(|e| anyhow::anyhow!("failed to serialize attestation: {e}"))?;

    let sig_bytes = hex::decode(&attestation.signature.signature_hex)
        .map_err(|e| anyhow::anyhow!("invalid signature hex: {e}"))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))?;

    for vk in trusted_keys {
        if vk.verify(&doc_bytes, &sig).is_ok() {
            return Ok(*vk);
        }
    }

    anyhow::bail!("signature does not match any trusted key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

        #[test]
        fn attestation_proptest_roundtrip(
            bundle_hash in "sha256:[0-9a-f]{64}",
            payload_hash in "sha256:[0-9a-f]{64}",
            metadata_hash in "sha256:[0-9a-f]{64}",
            builder in ".*",
            machine_hash in "sha256:[0-9a-f]{64}",
            os in "(linux|macos|windows)",
            arch in "(x86_64|aarch64|riscv64)",
        ) {
            let att = Attestation {
                spec_version: "1.0".to_string(),
                attestation_type: "erebus-execution".to_string(),
                artifact: ArtifactInfo {
                    bundle_hash,
                    payload_hash,
                    metadata_hash,
                    format_version: 3,
                    flags: vec![],
                },
                provenance: ProvenanceInfo {
                    builder,
                    author: None,
                    license: None,
                    layers: vec![],
                },
                execution: ExecutionInfo {
                    attested_at: "2026-01-01T00:00:00Z".to_string(),
                    machine_id_hash: machine_hash,
                    os,
                    arch,
                },
                signature: SignatureInfo {
                    algorithm: "ed25519".to_string(),
                    key_fingerprint: "sha256:dead".to_string(),
                    signature_hex: "deadbeef".to_string(),
                },
            };
            let json = serde_json::to_string(&att).unwrap();
            let parsed: Attestation = serde_json::from_str(&json).unwrap();
            assert_eq!(&att.spec_version, &parsed.spec_version);
            assert_eq!(&att.artifact.bundle_hash, &parsed.artifact.bundle_hash);
            assert_eq!(&att.execution.os, &parsed.execution.os);
        }
    }

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    #[test]
    fn sha256_hex_deterministic() {
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"hello");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn flag_names_empty() {
        assert!(flag_names(0x00).is_empty());
    }

    #[test]
    fn flag_names_all() {
        let flags = flag_names(0x07);
        assert!(flags.contains(&"signed".to_string()));
        assert!(flags.contains(&"encrypted".to_string()));
        assert!(flags.contains(&"sisr".to_string()));
    }

    #[test]
    fn machine_id_hash_deterministic() {
        let a = machine_id_hash();
        let b = machine_id_hash();
        assert_eq!(a, b);
    }

    #[test]
    fn roundtrip_verify() {
        let key = test_key();
        let attestation = Attestation {
            spec_version: "1.0".to_string(),
            attestation_type: "erebus-execution".to_string(),
            artifact: ArtifactInfo {
                bundle_hash: "sha256:abc".to_string(),
                payload_hash: "sha256:def".to_string(),
                metadata_hash: "sha256:ghi".to_string(),
                format_version: 3,
                flags: vec!["signed".to_string()],
            },
            provenance: ProvenanceInfo {
                builder: "erebus-cli v0.5.0".to_string(),
                author: None,
                license: None,
                layers: vec![],
            },
            execution: ExecutionInfo {
                attested_at: "2026-09-15T14:32:00Z".to_string(),
                machine_id_hash: "sha256:abc123".to_string(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
            },
            signature: SignatureInfo {
                algorithm: "ed25519".to_string(),
                key_fingerprint: format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(key.verifying_key().as_bytes()))
                ),
                signature_hex: String::new(),
            },
        };

        // Sign
        let doc_bytes = serde_json::to_vec(&attestation).unwrap();
        let sig = key.sign(&doc_bytes);
        let mut signed = attestation;
        signed.signature.signature_hex = hex::encode(sig.to_bytes());

        // Verify
        let result = verify_attestation(&signed, &[key.verifying_key()]);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let key = test_key();
        let wrong_key = SigningKey::from_bytes(&[2u8; 32]);

        let attestation = Attestation {
            spec_version: "1.0".to_string(),
            attestation_type: "erebus-execution".to_string(),
            artifact: ArtifactInfo {
                bundle_hash: "sha256:abc".to_string(),
                payload_hash: "sha256:def".to_string(),
                metadata_hash: "sha256:ghi".to_string(),
                format_version: 3,
                flags: vec![],
            },
            provenance: ProvenanceInfo {
                builder: "erebus-cli v0.5.0".to_string(),
                author: None,
                license: None,
                layers: vec![],
            },
            execution: ExecutionInfo {
                attested_at: "2026-09-15T14:32:00Z".to_string(),
                machine_id_hash: "sha256:abc123".to_string(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
            },
            signature: SignatureInfo {
                algorithm: "ed25519".to_string(),
                key_fingerprint: "sha256:wrong".to_string(),
                signature_hex: String::new(),
            },
        };

        let doc_bytes = serde_json::to_vec(&attestation).unwrap();
        let sig = key.sign(&doc_bytes);
        let mut signed = attestation;
        signed.signature.signature_hex = hex::encode(sig.to_bytes());

        let result = verify_attestation(&signed, &[wrong_key.verifying_key()]);
        assert!(result.is_err());
    }

    #[test]
    fn attestation_serialization_roundtrip() {
        let att = Attestation {
            spec_version: "1.0".to_string(),
            attestation_type: "erebus-execution".to_string(),
            artifact: ArtifactInfo {
                bundle_hash: "sha256:aaa".to_string(),
                payload_hash: "sha256:bbb".to_string(),
                metadata_hash: "sha256:ccc".to_string(),
                format_version: 3,
                flags: vec!["signed".to_string(), "sisr".to_string()],
            },
            provenance: ProvenanceInfo {
                builder: "erebus-cli v0.5.0".to_string(),
                author: Some("test".to_string()),
                license: Some("MIT".to_string()),
                layers: vec![LayerInfo {
                    name: "runtime/python3".to_string(),
                    kind: "runtime".to_string(),
                    sha256: "sha256:ddd".to_string(),
                }],
            },
            execution: ExecutionInfo {
                attested_at: "2026-09-15T14:32:00Z".to_string(),
                machine_id_hash: "sha256:eee".to_string(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
            },
            signature: SignatureInfo {
                algorithm: "ed25519".to_string(),
                key_fingerprint: "sha256:fff".to_string(),
                signature_hex: "deadbeef".to_string(),
            },
        };
        let json = serde_json::to_string(&att).unwrap();
        let parsed: Attestation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.spec_version, "1.0");
        assert_eq!(parsed.artifact.flags.len(), 2);
        assert_eq!(parsed.provenance.layers.len(), 1);
        assert_eq!(parsed.provenance.layers[0].kind, "runtime");
    }
}
