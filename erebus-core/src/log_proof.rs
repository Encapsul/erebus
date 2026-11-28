//! Offline verification of a registry transparency-log proof.
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

/// CMS `ContentInfo.contentType = id-signedData`.
const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// `eContentType = id-ct-TSTInfo` inside `SignedData.encapContentInfo`.
const OID_TST_INFO: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x04,
];
const SHA256_ALGID: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

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
    /// Legacy unsigned JSON hint. Kept for wire compatibility but **ignored**
    /// by verification: `genTime` comes only from the token's `TSTInfo`.
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

/// The token must be a granted `TimeStampResp` whose `TSTInfo.messageImprint`
/// is the imprint of *this* checkpoint. Only the `TSTInfo`'s `genTime` is used.
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
    Ok(AnchorReport {
        tsa_url: anchor.tsa_url.clone(),
        gen_time: Some(tst_info_gen_time(body, &imprint)?),
        cms_verified: false,
    })
}

/// Split one TLV into `(tag, content, remainder)` without pointer arithmetic.
fn der_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
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
    let end = hdr.checked_add(len)?;
    Some((tag, buf.get(hdr..end)?, buf.get(end..)?))
}

fn expect_tag<'a>(
    buf: &'a [u8],
    tag: u8,
    what: &str,
) -> Result<(&'a [u8], &'a [u8]), anyhow::Error> {
    let (found, content, rest) =
        der_tlv(buf).ok_or_else(|| anyhow::anyhow!("anchor token has no {what}"))?;
    if found != tag {
        anyhow::bail!("anchor token has no {what}");
    }
    Ok((content, rest))
}

/// `TimeStampResp ::= SEQUENCE { PKIStatusInfo, TimeStampToken }`.
fn parse_timestamp_resp(der: &[u8]) -> Result<(u64, &[u8]), anyhow::Error> {
    let bad = || anyhow::anyhow!("anchor token is not a TimeStampResp");
    let (outer, _) = expect_tag(der, 0x30, "TimeStampResp").map_err(|_| bad())?;
    let (status_info, token) = expect_tag(outer, 0x30, "PKIStatusInfo").map_err(|_| bad())?;
    let (status_bytes, _) =
        expect_tag(status_info, 0x02, "PKIStatusInfo status").map_err(|_| bad())?;
    if status_bytes.is_empty() || status_bytes.len() > 8 {
        return Err(bad());
    }
    let status = status_bytes
        .iter()
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
    Ok((status, token))
}

/// `encapContentInfo ::= SEQUENCE { id-ct-TSTInfo, [0] OCTET STRING TSTInfo }`.
fn encap_tst_info(seq: &[u8]) -> Option<&[u8]> {
    let (tag, oid, rest) = der_tlv(seq)?;
    if tag != 0x06 || oid != OID_TST_INFO {
        return None;
    }
    let (tag, explicit, _) = der_tlv(rest)?;
    if tag != 0xA0 {
        return None;
    }
    let (tag, tst_info, _) = der_tlv(explicit)?;
    (tag == 0x04).then_some(tst_info)
}

/// Walk `SignedData` fields to the encapsulated `TSTInfo`; reject a token whose
/// CMS content is not a timestamp token.
fn tst_info_gen_time(body: &[u8], imprint: &[u8]) -> Result<String, anyhow::Error> {
    let bad = || anyhow::anyhow!("TAMPERED: anchor token is not a CMS timestamp token");
    let (content_info, _) = expect_tag(body, 0x30, "ContentInfo").map_err(|_| bad())?;
    let (oid, rest) =
        expect_tag(content_info, 0x06, "ContentInfo contentType").map_err(|_| bad())?;
    if oid != OID_SIGNED_DATA {
        return Err(bad());
    }
    let (explicit, _) = expect_tag(rest, 0xA0, "ContentInfo content").map_err(|_| bad())?;
    let (signed_data, _) = expect_tag(explicit, 0x30, "SignedData").map_err(|_| bad())?;
    let mut fields = signed_data;
    while !fields.is_empty() {
        let (tag, content, rest) = der_tlv(fields).ok_or_else(bad)?;
        if tag == 0x30 {
            if let Some(tst_info) = encap_tst_info(content) {
                return parse_tst_info(tst_info, imprint);
            }
        }
        fields = rest;
    }
    Err(bad())
}

fn validate_gen_time(raw: &[u8]) -> Result<(), anyhow::Error> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| anyhow::anyhow!("TAMPERED: TSTInfo genTime is not ASCII"))?;
    let core = text
        .strip_suffix('Z')
        .and_then(|s| s.split('.').next())
        .unwrap_or_default();
    if core.len() != 14 || !core.bytes().all(|b| b.is_ascii_digit()) {
        anyhow::bail!("TAMPERED: TSTInfo genTime is not GeneralizedTime");
    }
    Ok(())
}

/// Strict sequential `TSTInfo` parse: the imprint is `messageImprint.hashedMessage`
/// and `genTime` is the field after `serialNumber` — never a byte scan.
fn parse_tst_info(der: &[u8], imprint: &[u8]) -> Result<String, anyhow::Error> {
    let bad = || anyhow::anyhow!("TAMPERED: anchor token has no valid TSTInfo");
    let (fields, _) = expect_tag(der, 0x30, "TSTInfo").map_err(|_| bad())?;
    let (version, rest) = expect_tag(fields, 0x02, "TSTInfo version").map_err(|_| bad())?;
    if version != [1] {
        return Err(bad());
    }
    let (_, rest) = expect_tag(rest, 0x06, "TSTInfo policy").map_err(|_| bad())?;
    let (msg_imprint, rest) = expect_tag(rest, 0x30, "messageImprint").map_err(|_| bad())?;
    let (alg, hashed) =
        expect_tag(msg_imprint, 0x30, "messageImprint algorithm").map_err(|_| bad())?;
    if !alg.starts_with(SHA256_ALGID) {
        return Err(bad());
    }
    let (digest, _) = expect_tag(hashed, 0x04, "messageImprint digest").map_err(|_| bad())?;
    if digest != imprint {
        anyhow::bail!("TAMPERED: TSA token does not cover this checkpoint's imprint");
    }
    let (_, rest) = expect_tag(rest, 0x02, "TSTInfo serialNumber").map_err(|_| bad())?;
    let (time, _) = expect_tag(rest, 0x18, "TSTInfo genTime").map_err(|_| bad())?;
    validate_gen_time(time)?;
    String::from_utf8(time.to_vec()).map_err(|_| bad())
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

    /// Minimal CMS timestamp token: id-signedData → `SignedData` →
    /// id-ct-TSTInfo → `TSTInfo`. Mirrors the fake TSA in the Python tests.
    fn build_token(imprint: &[u8], gen_time: &[u8], status: u8, extra: &[u8]) -> Vec<u8> {
        let alg_seq = der(0x30, &[SHA256_ALGID, &der(0x05, &[])].concat());
        let tst_info = der(
            0x30,
            &[
                der(0x02, &[1]),
                der(0x06, &[0x2a, 0x03, 0x04]),
                der(0x30, &[alg_seq, der(0x04, imprint)].concat()),
                der(0x02, &[42]),
                der(0x18, gen_time),
            ]
            .concat(),
        );
        let encap = der(
            0x30,
            &[der(0x06, OID_TST_INFO), der(0xA0, &der(0x04, &tst_info))].concat(),
        );
        let mut sd = [der(0x02, &[1]), der(0x31, &[]), encap].concat();
        sd.extend_from_slice(extra);
        sd.extend_from_slice(&der(0x31, &[]));
        let signed_data = der(0x30, &sd);
        let content = der(
            0x30,
            &[der(0x06, OID_SIGNED_DATA), der(0xA0, &signed_data)].concat(),
        );
        der(0x30, &[der(0x30, &der(0x02, &[status])), content].concat())
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
            let token = build_token(&imprint, b"20260917120000Z", 0, &[]);
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
        let token = build_token(&imprint, b"20260917120000Z", 2, &[]);
        proof.anchor.as_mut().unwrap().token_b64 =
            base64::engine::general_purpose::STANDARD.encode(token);
        let err = verify_proof(&receipt, &proof, &[log_key().verifying_key()]).unwrap_err();
        assert!(err.to_string().contains("status 2"), "{err}");
    }

    #[test]
    fn gen_time_comes_from_tstinfo_not_json_or_stray_bytes() {
        let receipts: [&[u8]; 2] = [b"a", b"b"];
        let trusted = [log_key().verifying_key()];
        let (mut proof, receipt) = build(&receipts, 0, true);
        let imprint: Hash = Sha256::digest(proof.checkpoint.anchor_bytes().unwrap()).into();

        // Unsigned JSON hint and a stray GeneralizedTime in SignedData are
        // ignored: the report still shows the TSTInfo genTime.
        proof.anchor.as_mut().unwrap().gen_time = Some("19990101000000Z".into());
        let extra = der(0x30, &der(0x18, b"19990101000000Z"));
        proof.anchor.as_mut().unwrap().token_b64 = base64::engine::general_purpose::STANDARD
            .encode(build_token(&imprint, b"20260917120000Z", 0, &extra));
        let report = verify_proof(&receipt, &proof, &trusted).unwrap();
        assert_eq!(
            report.anchor.unwrap().gen_time.as_deref(),
            Some("20260917120000Z")
        );

        // The imprint must be inside messageImprint: a stray copy elsewhere
        // in the token does not make a TSTInfo over another digest valid.
        let extra = der(0x04, &imprint);
        proof.anchor.as_mut().unwrap().token_b64 = base64::engine::general_purpose::STANDARD
            .encode(build_token(&[0u8; 32], b"20260917120000Z", 0, &extra));
        let err = verify_proof(&receipt, &proof, &trusted).unwrap_err();
        assert!(err.to_string().contains("imprint"), "{err}");
    }
}
