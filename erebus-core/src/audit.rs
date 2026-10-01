use crate::attest::{sha256_hex, Attestation};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Top-level signed audit report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub spec_version: String,
    pub report_type: String,
    pub artifact: ArtifactSummary,
    pub sbom: Sbom,
    pub attestation_chain: AttestationChain,
    pub integrity: IntegrityInfo,
    pub signature: ReportSignature,
}

/// Artifact summary extracted from the binary footer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub bundle_hash: String,
    pub payload_hash: String,
    pub format_version: u8,
    pub flags: Vec<String>,
    pub os: String,
    pub arch: String,
}

/// A `CycloneDX`-compatible software bill of materials.
///
/// Fields follow the `CycloneDX` 1.5 JSON schema (`bomFormat`, `specVersion`,
/// `serialNumber`, `version`, `components`) so the output is consumable by
/// standard `CycloneDX` tooling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub bom_format: String,
    pub spec_version: String,
    pub serial_number: String,
    pub version: u32,
    pub components: Vec<SbomComponent>,
}

/// A single component in the SBOM (`CycloneDX` `component`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub hashes: Vec<CycloneHash>,
    pub size: u64,
}

/// A `CycloneDX` `hash` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycloneHash {
    pub alg: String,
    pub value: String,
}

/// New `CycloneDX` SBOM with a generated `serialNumber`.
pub fn new_sbom() -> Sbom {
    Sbom {
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.5".to_string(),
        serial_number: format!("urn:uuid:{}", uuid_v4()),
        version: 1,
        components: Vec::new(),
    }
}

/// Generate a UUID v4 string for the `CycloneDX` `serialNumber`.
fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);
    // RFC 4122: version 4, variant 10xx.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

/// Summary of the attestation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationChain {
    pub count: usize,
    pub first: Option<String>,
    pub last: Option<String>,
    pub chain_hash: String,
}

/// Integrity information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityInfo {
    pub payload_sha256: String,
    pub signed: bool,
    pub sisr_enabled: bool,
}

/// Report signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSignature {
    pub algorithm: String,
    pub key_fingerprint: String,
    pub signature_hex: String,
}

/// Generate an SBOM from the metadata JSON of a .erebus binary.
///
/// Layer `kind` is preferred over the display name for categorization, since
/// layer names (e.g. `model.gguf`) don't carry the `model/` prefix the old
/// name-based heuristic expected. Sizes come from the `size` field (falling
/// back to the historical `usize` key). Layer hashes are resolved from the
/// embedded per-layer `sha256` when present; the runtime layer falls back to
/// the metadata-level `rt_deps_hash`, which hashes the runtime dependency set.
pub fn generate_sbom(meta: &serde_json::Value) -> Sbom {
    let rt_deps_hash = meta.get("rt_deps_hash").and_then(|v| v.as_str());
    let runtime_name = meta.get("runtime").and_then(|v| v.as_str());

    let mut components = Vec::new();

    if let Some(layers) = meta.get("layers").and_then(|v| v.as_array()) {
        for layer in layers {
            let name = layer
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let size = layer
                .get("size")
                .and_then(|v| v.as_u64())
                .or_else(|| layer.get("usize").and_then(|v| v.as_u64()))
                .unwrap_or(0);

            let component_type = match layer.get("kind").and_then(|v| v.as_str()) {
                Some("runtime") => "runtime",
                Some("model") => "model",
                Some("tool") => "tool",
                Some("config") => "config",
                Some("extension") => "extension",
                // Legacy metadata without a `kind` field: fall back to the name.
                _ => {
                    if name.starts_with("runtime/") {
                        "runtime"
                    } else if name.starts_with("model/") {
                        "model"
                    } else if name.starts_with("extension/") {
                        "extension"
                    } else {
                        "layer"
                    }
                }
            };

            let layer_hash = layer
                .get("sha256")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    layer
                        .get("metadata")
                        .and_then(|m| m.get("sha256"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                })
                // The runtime layer has no per-layer file to hash; its
                // dependency set hash (rt_deps_hash) is the honest proxy.
                .or_else(|| {
                    if component_type == "runtime"
                        && runtime_name == Some(name.as_str())
                        && rt_deps_hash.is_some()
                    {
                        rt_deps_hash
                    } else {
                        None
                    }
                });

            let hashes = layer_hash
                .map(|s| {
                    vec![CycloneHash {
                        alg: "SHA-256".to_string(),
                        value: s.to_string(),
                    }]
                })
                .unwrap_or_default();

            components.push(SbomComponent {
                component_type: component_type.to_string(),
                name,
                hashes,
                size,
            });
        }
    }

    let mut sbom = new_sbom();
    sbom.components = components;
    sbom
}

/// Aggregate a list of attestations into a chain summary.
pub fn aggregate_attestations(attestations: &[Attestation]) -> AttestationChain {
    if attestations.is_empty() {
        return AttestationChain {
            count: 0,
            first: None,
            last: None,
            chain_hash: sha256_hex(b"empty"),
        };
    }

    let mut sorted = attestations.to_vec();
    sorted.sort_by(|a, b| a.execution.attested_at.cmp(&b.execution.attested_at));

    let first = sorted.first().map(|a| a.execution.attested_at.clone());
    let last = sorted.last().map(|a| a.execution.attested_at.clone());

    let mut hasher = Sha256::new();
    for att in &sorted {
        let bytes = serde_json::to_vec(att).unwrap_or_default();
        hasher.update(&bytes);
    }
    let chain_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

    AttestationChain {
        count: sorted.len(),
        first,
        last,
        chain_hash,
    }
}

/// Load attestations from `.attest` files in a directory.
pub fn load_attestations(dir: &Path) -> Result<Vec<Attestation>, anyhow::Error> {
    let mut attestations = Vec::new();
    if !dir.exists() {
        return Ok(attestations);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|ext| ext == "attest" || ext == "erebus.attest")
        {
            let data = std::fs::read(&path)?;
            if let Ok(att) = serde_json::from_slice::<Attestation>(&data) {
                attestations.push(att);
            }
        }
    }
    Ok(attestations)
}

/// Read the full file as bytes and return SHA-256 hex.
pub fn file_hash(path: &Path) -> Result<String, anyhow::Error> {
    let data = std::fs::read(path)?;
    Ok(sha256_hex(&data))
}

/// Signed deletion audit entry.
///
/// Soft-deletes must leave an auditable, signed record: the artifact name,
/// who deleted it, from which state, and a fingerprint of the removed bytes
/// hash. Signature is that of the deletion actor, so a later auditor can
/// attribute the removal even if the file itself is gone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletionAuditEntry {
    pub artifact: String,
    pub actor: String,
    pub from_state: String,
    pub bundle_hash: String,
    pub deleted_at_utc: String,
    pub sig_algorithm: String,
    pub key_fingerprint: String,
    pub signature_hex: String,
}

/// Sign a deletion audit record for a soft-deleted artifact.
///
/// The serialized entry (minus the signature) is hashed with SHA-256 and
/// signed with the caller's Ed25519 key. Returns the fully-populated entry
/// ready for persistence.
///
/// # Errors
///
/// Returns [`anyhow::Error`] if the signing key or serialization fails.
pub fn record_deletion(
    artifact: &str,
    actor: &str,
    from_state: &str,
    bundle_hash: &str,
    signing_key: &SigningKey,
) -> Result<DeletionAuditEntry, anyhow::Error> {
    let mut entry = DeletionAuditEntry {
        artifact: artifact.to_string(),
        actor: actor.to_string(),
        from_state: from_state.to_string(),
        bundle_hash: bundle_hash.to_string(),
        deleted_at_utc: time::OffsetDateTime::now_utc().to_string(),
        sig_algorithm: "ed25519".to_string(),
        key_fingerprint: sha256_hex(&signing_key.verifying_key().to_bytes()),
        signature_hex: String::new(),
    };
    let doc = serde_json::to_vec(&entry)?;
    let hash = Sha256::digest(&doc);
    let sig = signing_key.sign(&hash);
    entry.signature_hex = hex::encode(sig.to_bytes());
    Ok(entry)
}

/// Verify a deletion audit entry against a trusted key.
///
/// Returns `true` when the entry's signature validates against `vk`.
#[must_use]
pub fn verify_deletion_entry(entry: &DeletionAuditEntry, vk: &VerifyingKey) -> bool {
    let mut doc = entry.clone();
    doc.signature_hex = String::new();
    let Ok(doc_bytes) = serde_json::to_vec(&doc) else {
        return false;
    };
    let hash = Sha256::digest(&doc_bytes);
    let Ok(sig_bytes) = hex::decode(&entry.signature_hex) else {
        return false;
    };
    let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) else {
        return false;
    };
    vk.verify(&hash, &sig).is_ok()
}

/// Verify an audit report's signature against trusted keys.
pub fn verify_audit_report(
    report: &AuditReport,
    trusted_keys: &[(PathBuf, VerifyingKey)],
) -> Result<Option<String>, anyhow::Error> {
    let mut doc = report.clone();
    doc.signature.signature_hex = String::new();
    let doc_bytes = serde_json::to_vec(&doc)?;
    let hash = Sha256::digest(&doc_bytes);

    let sig_bytes = hex::decode(&report.signature.signature_hex)
        .map_err(|e| anyhow::anyhow!("invalid signature hex: {e}"))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)?;

    for (key_path, vk) in trusted_keys {
        if vk.verify(&hash, &sig).is_ok() {
            return Ok(Some(key_path.display().to_string()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbom_empty_when_no_layers() {
        let meta = serde_json::json!({});
        let sbom = generate_sbom(&meta);
        assert_eq!(sbom.bom_format, "CycloneDX");
        assert_eq!(sbom.spec_version, "1.5");
        assert!(sbom.components.is_empty());
    }

    #[test]
    fn sbom_categorizes_layers() {
        let meta = serde_json::json!({
            "layers": [
                {"name": "runtime/python3", "usize": 1024},
                {"name": "model/llama-3.1-8b", "usize": 4096},
                {"name": "extension/something", "usize": 512},
                {"name": "data/misc", "usize": 256},
            ]
        });
        let sbom = generate_sbom(&meta);
        assert_eq!(sbom.components.len(), 4);
        assert_eq!(sbom.components[0].component_type, "runtime");
        assert_eq!(sbom.components[1].component_type, "model");
        assert_eq!(sbom.components[2].component_type, "extension");
        assert_eq!(sbom.components[3].component_type, "layer");
    }

    #[test]
    fn sbom_uses_kind_and_nested_hash_and_size() {
        let meta = serde_json::json!({
            "runtime": "python",
            "rt_deps_hash": "aabbccdd",
            "layers": [
                {
                    "kind": "runtime",
                    "name": "python",
                    "entrypoint": ["python3", "app.py"],
                    "env": [],
                    "capabilities": []
                },
                {
                    "kind": "model",
                    "name": "model.gguf",
                    "path": "models/model.gguf",
                    "size": 643728768,
                    "metadata": { "sha256": "deadbeef" }
                },
            ]
        });
        let sbom = generate_sbom(&meta);
        assert_eq!(sbom.components.len(), 2);
        // Model: type + numeric size from `size` key + SHA-256 from `metadata.sha256`.
        let model = &sbom.components[1];
        assert_eq!(model.component_type, "model");
        assert_eq!(model.size, 643728768);
        assert_eq!(model.hashes.len(), 1);
        assert_eq!(model.hashes[0].alg, "SHA-256");
        assert_eq!(model.hashes[0].value, "deadbeef");
        // Runtime: type from `kind`, size 0, hash falls back to `rt_deps_hash`.
        let runtime = &sbom.components[0];
        assert_eq!(runtime.component_type, "runtime");
        assert_eq!(runtime.hashes.len(), 1);
        assert_eq!(runtime.hashes[0].value, "aabbccdd");
    }

    #[test]
    fn chain_empty() {
        let chain = aggregate_attestations(&[]);
        assert_eq!(chain.count, 0);
        assert!(chain.first.is_none());
    }

    #[test]
    fn chain_single() {
        let att = Attestation {
            spec_version: "1.0".to_string(),
            attestation_type: "erebus-execution".to_string(),
            artifact: crate::attest::ArtifactInfo {
                bundle_hash: "sha256:aaa".to_string(),
                payload_hash: "sha256:bbb".to_string(),
                metadata_hash: "sha256:ccc".to_string(),
                format_version: 3,
                flags: vec!["signed".to_string()],
            },
            provenance: crate::attest::ProvenanceInfo {
                builder: "test".to_string(),
                author: None,
                license: None,
                layers: vec![],
            },
            execution: crate::attest::ExecutionInfo {
                attested_at: "2026-01-01T00:00:00Z".to_string(),
                machine_id_hash: "sha256:ddd".to_string(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                input_hash: None,
                output_hash: None,
                exit_code: None,
                prev_attestation_hash: None,
                request: None,
                rootfs_root: None,
                machine_id: None,
                stdin_hash: None,
            },
            statement: crate::intoto::InTotoStatement {
                statement_type: crate::intoto::INTOTO_STATEMENT_TYPE.to_string(),
                subject: vec![],
                predicate_type: crate::intoto::EREBUS_PREDICATE_TYPE.to_string(),
                predicate: serde_json::json!({}),
            },
            signature: crate::attest::SignatureInfo {
                algorithm: "ed25519".to_string(),
                key_fingerprint: "sha256:eee".to_string(),
                signature_hex: "ffff".to_string(),
            },
            envelope: None,
            machine: None,
        };
        let chain = aggregate_attestations(&[att]);
        assert_eq!(chain.count, 1);
        assert!(chain.first.is_some());
    }

    #[test]
    fn report_roundtrip_serialize() {
        let report = AuditReport {
            spec_version: "1.0".to_string(),
            report_type: "erebus-audit".to_string(),
            artifact: ArtifactSummary {
                bundle_hash: "sha256:aaa".to_string(),
                payload_hash: "sha256:bbb".to_string(),
                format_version: 3,
                flags: vec!["signed".to_string()],
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
            },
            sbom: {
                let mut sbom = new_sbom();
                sbom.components = vec![SbomComponent {
                    component_type: "runtime".to_string(),
                    name: "runtime/python3".to_string(),
                    hashes: vec![CycloneHash {
                        alg: "SHA-256".to_string(),
                        value: "abc".to_string(),
                    }],
                    size: 1024,
                }];
                sbom
            },
            attestation_chain: AttestationChain {
                count: 0,
                first: None,
                last: None,
                chain_hash: "sha256:empty".to_string(),
            },
            integrity: IntegrityInfo {
                payload_sha256: "sha256:abc".to_string(),
                signed: true,
                sisr_enabled: true,
            },
            signature: ReportSignature {
                algorithm: "ed25519".to_string(),
                key_fingerprint: "sha256:fff".to_string(),
                signature_hex: "deadbeef".to_string(),
            },
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: AuditReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.spec_version, "1.0");
        assert_eq!(parsed.report_type, "erebus-audit");
        assert_eq!(parsed.sbom.components.len(), 1);
        assert_eq!(parsed.sbom.components[0].hashes[0].alg, "SHA-256");
        assert_eq!(parsed.sbom.components[0].hashes[0].value, "abc");
    }

    fn test_key_signing() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn deletion_entry_roundtrip_and_verify() {
        let key = test_key_signing();
        let entry = record_deletion(
            "models/llama-3.1-8b.erebus",
            "auditor@acme",
            "Trusted",
            "sha256:deadbeef",
            &key,
        )
        .unwrap();
        assert_eq!(entry.from_state, "Trusted");
        assert!(!entry.signature_hex.is_empty());
        assert_eq!(entry.sig_algorithm, "ed25519");

        let vk = key.verifying_key();
        assert!(verify_deletion_entry(&entry, &vk));
    }

    #[test]
    fn deletion_entry_rejects_forged_signature() {
        let key = test_key_signing();
        let mut entry = record_deletion("x.erebus", "alice", "Acquired", "h", &key).unwrap();
        // Tamper with the artifact name after signing.
        entry.artifact = "y.erebus".to_string();
        assert!(!verify_deletion_entry(&entry, &key.verifying_key()));
    }

    #[test]
    fn deletion_serializes_and_roundtrips() {
        let key = test_key_signing();
        let entry = record_deletion("z.erebus", "bob", "Revoked", "h2", &key).unwrap();
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: DeletionAuditEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.artifact, "z.erebus");
        assert_eq!(parsed.signature_hex, entry.signature_hex);
        assert!(verify_deletion_entry(&parsed, &key.verifying_key()));
    }
}
