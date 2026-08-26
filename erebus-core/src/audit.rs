use crate::attest::{sha256_hex, Attestation};
use ed25519_dalek::{Verifier, VerifyingKey};
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

/// Software bill of materials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sbom {
    pub format: String,
    pub components: Vec<SbomComponent>,
}

/// A single component in the SBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub hash: String,
    pub size: u64,
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
pub fn generate_sbom(meta: &serde_json::Value) -> Sbom {
    let mut components = Vec::new();

    if let Some(layers) = meta.get("layers").and_then(|v| v.as_array()) {
        for layer in layers {
            let name = layer
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let size = layer.get("usize").and_then(|v| v.as_u64()).unwrap_or(0);

            let component_type = if name.starts_with("runtime/") {
                "runtime"
            } else if name.starts_with("model/") {
                "model"
            } else if name.starts_with("extension/") {
                "extension"
            } else {
                "layer"
            };

            components.push(SbomComponent {
                component_type: component_type.to_string(),
                name,
                hash: "sha256:unavailable".to_string(),
                size,
            });
        }
    }

    Sbom {
        format: "erebus-sbom/v1".to_string(),
        components,
    }
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
        assert_eq!(sbom.format, "erebus-sbom/v1");
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
            },
            signature: crate::attest::SignatureInfo {
                algorithm: "ed25519".to_string(),
                key_fingerprint: "sha256:eee".to_string(),
                signature_hex: "ffff".to_string(),
            },
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
            sbom: Sbom {
                format: "erebus-sbom/v1".to_string(),
                components: vec![],
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
        assert!(parsed.sbom.components.is_empty());
    }
}
