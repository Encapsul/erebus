//! Offline verification of a registry transparency-log proof (ROADMAP P0-5).
//!
//! `erebus attest --push` stores what the registry returned next to the
//! receipt (`<receipt>.proof.json`); `erebus verify-attest --proof` then
//! checks, without contacting the registry:
//!
//! 1. `leaf_hash == SHA-256(0x00 ‖ receipt file bytes)` — the proof is about
//!    *this* receipt;
//! 2. the RFC 6962 inclusion path reaches the checkpoint root;
//! 3. the checkpoint is Ed25519-signed by a **trusted** log key;
//! 4. when present, the RFC 3161 token covers this checkpoint (structural
//!    check; full CMS validation is delegated to `openssl ts -verify`).
//!
//! Canonical checkpoint bytes (must match `registry_server.py`):
//! `erebus-log-checkpoint/v1\n{origin}\n{size}\n{root_hex}\n{timestamp}\n`.
//! The TSA imprint is SHA-256 over the same bytes without the timestamp line.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attest::key_fingerprint;
use crate::merkle::{self, Hash};

pub const PROOF_SPEC: &str = "erebus-log-proof/v1";
pub const CHECKPOINT_PREFIX: &str = "erebus-log-checkpoint/v1";

/// Signed tree head as served by `GET /log/checkpoint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: String,
    pub timestamp: String,
    pub key_id: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

/// RFC 3161 anchor of a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub size: u64,
    pub root: String,
    pub requested_at: String,
    pub tsa_url: String,
    #[serde(default)]
    pub gen_time: Option<String>,
    pub token_b64: String,
}

/// Everything stored in `<receipt>.proof.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogProof {
    pub spec: String,
    pub registry: String,
    pub leaf_index: u64,
    pub leaf_hash: String,
    pub tree_size: u64,
    pub root: String,
    pub inclusion_proof: Vec<String>,
    pub checkpoint: Checkpoint,
    #[serde(default)]
    pub anchor: Option<Anchor>,
}

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofReport {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub root: String,
    pub origin: String,
    pub log_key: String,
    pub checkpoint_time: String,
    /// `Some` when an anchor was present and structurally valid.
    pub anchor: Option<AnchorReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnchorReport {
    pub tsa_url: String,
    pub gen_time: Option<String>,
    /// Structural only; `openssl ts -verify` is needed for the CMS signature.
    pub cms_verified: bool,
}

impl Checkpoint {
    pub fn signed_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let root = merkle::parse_hash(&self.root)
            .ok_or_else(|| anyhow::anyhow!("checkpoint root is not a sha256 digest"))?;
        Ok(format!(
            "{CHECKPOINT_PREFIX}\n{}\n{}\n{}\n{}\n",
            self.origin,
            self.size,
            hex::encode(root),
            self.timestamp
        )
        .into_bytes())
    }

    /// Bytes the TSA imprint covers (no timestamp: the TSA's genTime is the
    /// authoritative time).
    pub fn anchor_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let root = merkle::parse_hash(&self.root)
            .ok_or_else(|| anyhow::anyhow!("checkpoint root is not a sha256 digest"))?;
        Ok(format!(
            "{CHECKPOINT_PREFIX}\n{}\n{}\n{}\n",
            self.origin,
            self.size,
            hex::encode(root)
        )
        .into_bytes())
    }

    /// Verify the signature under the embedded public key; returns that key.
    pub fn verify_signature(&self) -> Result<VerifyingKey, anyhow::Error> {
        let pk: [u8; 32] = hex::decode(&self.public_key_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("checkpoint public key is not 32 bytes of hex"))?;
        let vk = VerifyingKey::from_bytes(&pk)
            .map_err(|e| anyhow::anyhow!("checkpoint public key invalid: {e}"))?;
        if key_fingerprint(&vk) != self.key_id {
            anyhow::bail!("TAMPERED: checkpoint key_id does not match its public key");
        }
        let sig: [u8; 64] = hex::decode(&self.signature_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("checkpoint signature is not 64 bytes of hex"))?;
        vk.verify(&self.signed_bytes()?, &Signature::from_bytes(&sig))
            .map_err(|_| anyhow::anyhow!("TAMPERED: checkpoint signature does not verify"))?;
        Ok(vk)
    }
}

/// Build the proof file from a registry `log` object (POST /attestations).
pub fn from_registry_response(
    registry: &str,
    log: &serde_json::Value,
) -> Result<LogProof, anyhow::Error> {
    #[derive(Deserialize)]
    struct Position {
        leaf_index: u64,
        leaf_hash: String,
        tree_size: u64,
        root: String,
        inclusion_proof: Vec<String>,
        checkpoint: Checkpoint,
        #[serde(default)]
        anchor: Option<Anchor>,
    }
    let p: Position = serde_json::from_value(log.clone())
        .map_err(|e| anyhow::anyhow!("registry log position is malformed: {e}"))?;
    Ok(LogProof {
        spec: PROOF_SPEC.to_string(),
        registry: registry.to_string(),
        leaf_index: p.leaf_index,
        leaf_hash: p.leaf_hash,
        tree_size: p.tree_size,
        root: p.root,
        inclusion_proof: p.inclusion_proof,
        checkpoint: p.checkpoint,
        anchor: p.anchor,
    })
}

/// Full offline verification. `trusted` must contain the log key (a proof
/// signed by an unknown key proves nothing).
pub fn verify_proof(
    receipt_bytes: &[u8],
    proof: &LogProof,
    trusted: &[VerifyingKey],
) -> Result<ProofReport, anyhow::Error> {
    if proof.spec != PROOF_SPEC {
        anyhow::bail!("unsupported proof spec {:?}", proof.spec);
    }
    let leaf = merkle::leaf_hash(receipt_bytes);
    let claimed = merkle::parse_hash(&proof.leaf_hash)
        .ok_or_else(|| anyhow::anyhow!("proof leaf_hash is not a sha256 digest"))?;
    if leaf != claimed {
        anyhow::bail!("TAMPERED: receipt bytes do not hash to the proof's leaf");
    }
    let root = merkle::parse_hash(&proof.root)
        .ok_or_else(|| anyhow::anyhow!("proof root is not a sha256 digest"))?;
    if proof.checkpoint.root != proof.root || proof.checkpoint.size != proof.tree_size {
        anyhow::bail!("TAMPERED: proof root/size disagree with the checkpoint");
    }
    let path = parse_path(&proof.inclusion_proof)?;
    if !merkle::verify_inclusion(&leaf, proof.leaf_index, proof.tree_size, &path, &root) {
        anyhow::bail!("TAMPERED: inclusion proof does not reach the checkpoint root");
    }
    let vk = proof.checkpoint.verify_signature()?;
    if !trusted.contains(&vk) {
        anyhow::bail!(
            "log key {} is not trusted (pass --log-key or add its .pub to the trusted dir)",
            proof.checkpoint.key_id
        );
    }
    let anchor = match &proof.anchor {
        Some(a) => Some(check_anchor(a, &proof.checkpoint)?),
        None => None,
    };
    Ok(ProofReport {
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        root: merkle::display(&root),
        origin: proof.checkpoint.origin.clone(),
        log_key: proof.checkpoint.key_id.clone(),
        checkpoint_time: proof.checkpoint.timestamp.clone(),
        anchor,
    })
}

fn parse_path(hexes: &[String]) -> Result<Vec<Hash>, anyhow::Error> {
    hexes
        .iter()
        .map(|h| merkle::parse_hash(h).ok_or_else(|| anyhow::anyhow!("malformed inclusion proof")))
        .collect()
}

/// The token must be a granted `TimeStampResp` whose `TSTInfo` carries the
/// imprint of *this* checkpoint.
fn check_anchor(anchor: &Anchor, cp: &Checkpoint) -> Result<AnchorReport, anyhow::Error> {
    if anchor.size != cp.size || anchor.root != cp.root {
        anyhow::bail!("TAMPERED: anchor covers a different tree head than the checkpoint");
    }
    let token = base64::engine::general_purpose::STANDARD
        .decode(&anchor.token_b64)
        .map_err(|e| anyhow::anyhow!("anchor token is not base64: {e}"))?;
    let imprint: Hash = Sha256::digest(cp.anchor_bytes()?).into();
    let (status, body) = parse_timestamp_resp(&token)?;
    if status > 1 {
        anyhow::bail!("TAMPERED: TSA token status {status} (not granted)");
    }
    if !body.windows(32).any(|w| w == imprint) {
        anyhow::bail!("TAMPERED: TSA token does not cover this checkpoint's imprint");
    }
    Ok(AnchorReport {
        tsa_url: anchor.tsa_url.clone(),
        gen_time: anchor.gen_time.clone().or_else(|| extract_gen_time(body)),
        cms_verified: false,
    })
}

/// Minimal DER: `SEQUENCE { SEQUENCE { INTEGER status … } token… }`.
/// Returns `(status, bytes after the PKIStatusInfo)`.
fn parse_timestamp_resp(der: &[u8]) -> Result<(u64, &[u8]), anyhow::Error> {
    let bad = || anyhow::anyhow!("anchor token is not a TimeStampResp");
    let (tag, outer) = der_tlv(der).ok_or_else(bad)?;
    if tag != 0x30 {
        return Err(bad());
    }
    let (stag, status_info) = der_tlv(outer).ok_or_else(bad)?;
    let (itag, status_bytes) = der_tlv(status_info).ok_or_else(bad)?;
    if stag != 0x30 || itag != 0x02 || status_bytes.is_empty() || status_bytes.len() > 8 {
        return Err(bad());
    }
    let status = status_bytes
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    let consumed = der.len() - outer.len() + (outer.len() - rest_after(outer, status_info));
    Ok((status, der.get(consumed..).unwrap_or(&[])))
}

/// Split one TLV: returns `(tag, content)`; the caller computes what follows.
fn der_tlv(buf: &[u8]) -> Option<(u8, &[u8])> {
    let tag = *buf.first()?;
    let first = *buf.get(1)?;
    let (len, hdr) = if first & 0x80 == 0 {
        (usize::from(first), 2usize)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = buf.get(2..2 + n)?;
        (
            bytes
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b)),
            2 + n,
        )
    };
    Some((tag, buf.get(hdr..hdr.checked_add(len)?)?))
}

/// Length of `outer` remaining after the TLV whose content is `inner`.
fn rest_after(outer: &[u8], inner: &[u8]) -> usize {
    let inner_end = inner.as_ptr() as usize + inner.len();
    let outer_end = outer.as_ptr() as usize + outer.len();
    outer_end.saturating_sub(inner_end)
}

/// `GeneralizedTime` (tag 0x18) `YYYYMMDDHHMMSS[.fff]Z` inside the token.
fn extract_gen_time(body: &[u8]) -> Option<String> {
    for i in 0..body.len().saturating_sub(2) {
        if body[i] != 0x18 {
            continue;
        }
        let len = usize::from(body[i + 1]);
        if !(15..=24).contains(&len) {
            continue;
        }
        let Some(raw) = body.get(i + 2..i + 2 + len) else {
            continue;
        };
        if raw.last() == Some(&b'Z') && raw[..14].iter().all(u8::is_ascii_digit) {
            return String::from_utf8(raw.to_vec()).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn log_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(body);
        out
    }

    /// Registry-side construction, mirrored from `registry_server.py`.
    fn build(receipts: &[&[u8]], index: usize, anchored: bool) -> (LogProof, Vec<u8>) {
        let leaves: Vec<Hash> = receipts.iter().map(|r| merkle::leaf_hash(r)).collect();
        let root = merkle::root(&leaves);
        let path = merkle::inclusion_proof(&leaves, index).unwrap();
        let key = log_key();
        let mut cp = Checkpoint {
            origin: "test-origin".into(),
            size: leaves.len() as u64,
            root: merkle::display(&root),
            timestamp: "2026-09-17T12:00:00+00:00".into(),
            key_id: key_fingerprint(&key.verifying_key()),
            public_key_hex: hex::encode(key.verifying_key().as_bytes()),
            signature_hex: String::new(),
        };
        cp.signature_hex = hex::encode(key.sign(&cp.signed_bytes().unwrap()).to_bytes());
        let anchor = anchored.then(|| {
            let imprint: Hash = Sha256::digest(cp.anchor_bytes().unwrap()).into();
            let tst = der(
                0x30,
                &[der(0x04, &imprint), der(0x18, b"20260917120000Z")].concat(),
            );
            let token = der(
                0x30,
                &[der(0x30, &der(0x02, &[0])), der(0x30, &tst)].concat(),
            );
            Anchor {
                size: cp.size,
                root: cp.root.clone(),
                requested_at: cp.timestamp.clone(),
                tsa_url: "http://tsa.test/tsr".into(),
                gen_time: None,
                token_b64: base64::engine::general_purpose::STANDARD.encode(token),
            }
        });
        let proof = LogProof {
            spec: PROOF_SPEC.into(),
            registry: "http://registry.test".into(),
            leaf_index: index as u64,
            leaf_hash: merkle::display(&leaves[index]),
            tree_size: leaves.len() as u64,
            root: merkle::display(&root),
            inclusion_proof: path.iter().map(hex::encode).collect(),
            checkpoint: cp,
            anchor,
        };
        (proof, receipts[index].to_vec())
    }

    #[test]
    fn genuine_proof_verifies_with_and_without_anchor() {
        let receipts: [&[u8]; 5] = [b"r0", b"r1", b"r2", b"r3", b"r4"];
        for anchored in [false, true] {
            let (proof, receipt) = build(&receipts, 3, anchored);
            let report = verify_proof(&receipt, &proof, &[log_key().verifying_key()]).unwrap();
            assert_eq!(report.leaf_index, 3);
            assert_eq!(report.tree_size, 5);
            assert_eq!(report.anchor.is_some(), anchored);
            if let Some(a) = report.anchor {
                assert_eq!(a.gen_time.as_deref(), Some("20260917120000Z"));
                assert!(!a.cms_verified);
            }
            // Round-trips through JSON (what the CLI stores).
            let json = serde_json::to_vec_pretty(&proof).unwrap();
            let back: LogProof = serde_json::from_slice(&json).unwrap();
            assert_eq!(back, proof);
        }
    }

    #[test]
    fn every_tamper_is_caught() {
        let receipts: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
        let trusted = [log_key().verifying_key()];
        let (proof, receipt) = build(&receipts, 1, true);

        let err = |p: &LogProof, r: &[u8], t: &[VerifyingKey]| {
            verify_proof(r, p, t).unwrap_err().to_string()
        };
        assert!(err(&proof, b"a", &trusted).contains("do not hash to the proof's leaf"));

        let mut p = proof.clone();
        p.leaf_index = 2;
        assert!(err(&p, &receipt, &trusted).contains("inclusion proof does not reach"));

        let mut p = proof.clone();
        p.checkpoint.size = 5;
        assert!(err(&p, &receipt, &trusted).contains("disagree with the checkpoint"));

        let mut p = proof.clone();
        p.checkpoint.timestamp = "2030-01-01T00:00:00+00:00".into();
        assert!(err(&p, &receipt, &trusted).contains("checkpoint signature"));

        let mut p = proof.clone();
        let other = SigningKey::from_bytes(&[1u8; 32]);
        p.checkpoint.public_key_hex = hex::encode(other.verifying_key().as_bytes());
        assert!(err(&p, &receipt, &trusted).contains("key_id does not match"));

        assert!(err(&proof, &receipt, &[]).contains("not trusted"));

        let mut p = proof.clone();
        p.anchor.as_mut().unwrap().size = 3;
        assert!(err(&p, &receipt, &trusted).contains("different tree head"));

        let mut p = proof.clone();
        let (other_proof, _) = build(&[b"x", b"y"], 0, true);
        p.anchor.as_mut().unwrap().token_b64 = other_proof.anchor.unwrap().token_b64;
        assert!(err(&p, &receipt, &trusted).contains("does not cover this checkpoint"));
    }

    #[test]
    fn rejected_tsa_status_is_caught() {
        let receipts: [&[u8]; 1] = [b"only"];
        let (mut proof, receipt) = build(&receipts, 0, true);
        let imprint: Hash = Sha256::digest(proof.checkpoint.anchor_bytes().unwrap()).into();
        let token = der(
            0x30,
            &[der(0x30, &der(0x02, &[2])), der(0x04, &imprint)].concat(),
        );
        proof.anchor.as_mut().unwrap().token_b64 =
            base64::engine::general_purpose::STANDARD.encode(token);
        let err = verify_proof(&receipt, &proof, &[log_key().verifying_key()]).unwrap_err();
        assert!(err.to_string().contains("status 2"), "{err}");
    }
}
