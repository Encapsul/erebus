//! Dead Simple Signing Envelope (DSSE v1) with Ed25519 signatures.
//!
//! `{"payloadType", "payload": base64(bytes), "signatures": [{"keyid", "sig"}]}`
//! where each `sig` is Ed25519 over the pre-authentication encoding
//! `PAE(type, payload) = "DSSEv1" SP len(type) SP type SP len(payload) SP payload`.
//! This is the envelope in-toto, SLSA and Sigstore (`cosign
//! verify-blob-attestation`) consume, so a receipt can be checked without
//! erebus.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Payload type of in-toto statements.
pub const INTOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Standard base64 of the payload bytes.
    pub payload: String,
    pub signatures: Vec<EnvelopeSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyid: String,
    /// Standard base64 of the raw 64-byte Ed25519 signature.
    pub sig: String,
}

/// `PAE(type, payload)` — DSSE protocol §"Protocol".
/// Ed25519 public key as an RFC 5280 `SubjectPublicKeyInfo` PEM — the form
/// `cosign --key`, `openssl pkeyutl` and in-toto expect. The DER prefix is
/// fixed for Ed25519 (RFC 8410 §4), so no ASN.1 library is needed.
pub fn public_key_pem(key: &VerifyingKey) -> String {
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let mut der = SPKI_PREFIX.to_vec();
    der.extend_from_slice(key.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n")
}

pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

impl Envelope {
    /// Unsigned envelope over `payload`.
    pub fn new(payload_type: &str, payload: &[u8]) -> Self {
        Self {
            payload_type: payload_type.to_string(),
            payload: b64().encode(payload),
            signatures: Vec::new(),
        }
    }

    /// Decoded payload bytes.
    pub fn payload_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        b64()
            .decode(&self.payload)
            .map_err(|e| anyhow::anyhow!("envelope payload is not base64: {e}"))
    }

    /// Append an Ed25519 signature under `keyid`.
    pub fn sign(&mut self, key: &SigningKey, keyid: &str) -> Result<(), anyhow::Error> {
        let msg = pae(&self.payload_type, &self.payload_bytes()?);
        self.signatures.push(EnvelopeSignature {
            keyid: keyid.to_string(),
            sig: b64().encode(key.sign(&msg).to_bytes()),
        });
        Ok(())
    }

    /// First signature that verifies under one of `keys`; returns the key
    /// and the matching signature entry.
    pub fn verify_any<'k>(
        &self,
        keys: &'k [VerifyingKey],
    ) -> Result<(&'k VerifyingKey, &EnvelopeSignature), anyhow::Error> {
        let msg = pae(&self.payload_type, &self.payload_bytes()?);
        for entry in &self.signatures {
            let Some(sig) = decode_sig(&entry.sig) else {
                continue;
            };
            if let Some(vk) = keys.iter().find(|vk| vk.verify(&msg, &sig).is_ok()) {
                return Ok((vk, entry));
            }
        }
        anyhow::bail!("TAMPERED: no envelope signature verifies under a trusted key")
    }

    /// Does some signature verify under exactly `key`?
    pub fn verified_by(&self, key: &VerifyingKey) -> Result<bool, anyhow::Error> {
        let msg = pae(&self.payload_type, &self.payload_bytes()?);
        Ok(self
            .signatures
            .iter()
            .filter_map(|s| decode_sig(&s.sig))
            .any(|sig| key.verify(&msg, &sig).is_ok()))
    }
}

fn decode_sig(b64_sig: &str) -> Option<Signature> {
    let bytes: [u8; 64] = b64().decode(b64_sig).ok()?.try_into().ok()?;
    Some(Signature::from_bytes(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pae_matches_dsse_spec_vector() {
        // DSSE protocol.md test vector.
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ".to_vec());
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let other = SigningKey::from_bytes(&[4u8; 32]);
        let mut env = Envelope::new(INTOTO_PAYLOAD_TYPE, br#"{"a":1}"#);
        env.sign(&key, "kid-1").unwrap();
        let trusted = [other.verifying_key(), key.verifying_key()];
        let (vk, entry) = env.verify_any(&trusted).unwrap();
        assert_eq!(*vk, key.verifying_key());
        assert_eq!(entry.keyid, "kid-1");
        assert!(env.verified_by(&key.verifying_key()).unwrap());
        assert!(!env.verified_by(&other.verifying_key()).unwrap());
        assert!(env.verify_any(&[other.verifying_key()]).is_err());

        // Payload swap invalidates; payloadType is bound by PAE too.
        let mut tampered = env.clone();
        tampered.payload = b64().encode(br#"{"a":2}"#);
        assert!(tampered.verify_any(&[key.verifying_key()]).is_err());
        let mut tampered = env.clone();
        tampered.payload_type = "text/plain".into();
        assert!(tampered.verify_any(&[key.verifying_key()]).is_err());

        // Multiple signers: each is independently verifiable.
        env.sign(&other, "kid-2").unwrap();
        assert!(env.verified_by(&other.verifying_key()).unwrap());
        assert_eq!(env.signatures.len(), 2);
    }

    #[test]
    fn json_shape_is_the_dsse_one() {
        let mut env = Envelope::new("t", b"p");
        env.sign(&SigningKey::from_bytes(&[1u8; 32]), "k").unwrap();
        let v: serde_json::Value = serde_json::to_value(&env).unwrap();
        assert_eq!(v["payloadType"], "t");
        assert_eq!(v["payload"], "cA==");
        assert_eq!(v["signatures"][0]["keyid"], "k");
        assert!(v["signatures"][0]["sig"].is_string());
    }

    #[test]
    fn public_key_pem_is_rfc8410_spki() {
        // RFC 8410 §10.1 example key.
        let raw = hex::decode("19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1")
            .unwrap();
        let vk = VerifyingKey::from_bytes(raw.as_slice().try_into().unwrap()).unwrap();
        let pem = public_key_pem(&vk);
        assert_eq!(
            pem,
            "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n"
        );
    }
}
