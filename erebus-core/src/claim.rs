//! Incident-window claim (ROADMAP R7).
//!
//! Insurers price a window of receipts, not the whole trail. The signed claim
//! names the window and the counts an auditor replays: receipts, model-digest
//! changes, tool calls, stops, approvals.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const CLAIM_PREFIX: &str = "erebus-claim/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub since: String,
    pub until: String,
    pub receipts: u64,
    pub head: String,
    pub model_digests: Vec<String>,
    pub tool_calls: u64,
    pub stops: u64,
    pub approvals: u64,
    pub verification_failures: u64,
    pub key_id: String,
    pub signature_hex: String,
}

impl Claim {
    pub fn signed_bytes(&self) -> Vec<u8> {
        format!(
            "{CLAIM_PREFIX}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.since,
            self.until,
            self.receipts,
            self.head,
            self.model_digests.join(","),
            self.tool_calls,
            self.stops,
            self.approvals,
            self.verification_failures,
        )
        .into_bytes()
    }

    pub fn sign(mut self, key: &SigningKey) -> Self {
        self.key_id = crate::attest::key_fingerprint(&key.verifying_key());
        self.signature_hex = hex::encode(key.sign(&self.signed_bytes()).to_bytes());
        self
    }

    pub fn verify(&self, keys: &[VerifyingKey]) -> Result<(), anyhow::Error> {
        let sig: [u8; 64] = hex::decode(&self.signature_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("claim signature is not 64 bytes of hex"))?;
        let ok = keys.iter().any(|k| {
            crate::attest::key_fingerprint(k) == self.key_id
                && k.verify(&self.signed_bytes(), &Signature::from_bytes(&sig))
                    .is_ok()
        });
        if !ok {
            anyhow::bail!("TAMPERED: claim signature does not verify");
        }
        Ok(())
    }
}

/// Second-resolution prefix so `…38.000000000Z` and `…38+00:00` compare equal.
pub fn iso8601_second(ts: &str) -> &str {
    let b = ts.as_bytes();
    if b.len() >= 19 && b[4] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':' {
        &ts[..19]
    } else {
        ts
    }
}

/// Inclusive window on `attested_at`. Empty bound means unbounded on that side.
pub fn in_window(attested_at: &str, since: Option<&str>, until: Option<&str>) -> bool {
    let at = iso8601_second(attested_at);
    if let Some(s) = since {
        if at < iso8601_second(s) {
            return false;
        }
    }
    if let Some(u) = until {
        if at > iso8601_second(u) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_excludes_a_receipt_and_the_claim_verifies() {
        assert!(in_window(
            "2026-06-15T12:00:00Z",
            Some("2026-06-01T00:00:00Z"),
            Some("2026-06-30T00:00:00Z")
        ));
        assert!(!in_window(
            "2026-01-15T12:00:00Z",
            Some("2026-06-01T00:00:00Z"),
            Some("2026-06-30T00:00:00Z")
        ));
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let claim = Claim {
            since: "2026-06-01T00:00:00Z".into(),
            until: "2026-06-30T00:00:00Z".into(),
            receipts: 1,
            head: "sha256:ab".into(),
            model_digests: vec!["sha256:m1".into(), "sha256:m2".into()],
            tool_calls: 2,
            stops: 1,
            approvals: 0,
            verification_failures: 0,
            key_id: String::new(),
            signature_hex: String::new(),
        }
        .sign(&key);
        claim.verify(&[key.verifying_key()]).unwrap();
        let mut tampered = claim.clone();
        tampered.receipts = 9;
        assert!(tampered.verify(&[key.verifying_key()]).is_err());
    }
}
