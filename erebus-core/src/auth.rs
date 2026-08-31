//! Pluggable registry authentication.
//!
//! The registry historically used a single shared-secret password. This module
//! makes auth pluggable behind one [`Authenticator`] trait backed by three
//! strategies:
//!
//! * **HMAC-SHA256** — shared-secret bearer tokens minted on demand.
//! * **Ed25519** — signed bearer tokens verifiable against a known public key.
//! * **OIDC / JWKS (open-issue)** — the trait is implemented for the two
//!   offline schemes so a JWKS verifier can be dropped in without changing the
//!   registry's auth plumbing.
//!
//! All comparisons are constant-time ([`subtle`]) so token checks do not leak
//! timing information.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// A verified identity returned by an [`Authenticator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthIdentity {
    /// Stable principal name (e.g. `token:reader-01`, `key:ed25519:aaaa`).
    pub subject: String,
    /// Optional claims/roles (`["reader"]`, `["admin"]`).
    pub roles: Vec<String>,
}

/// Error returned when an auth credential fails to verify.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("missing credential")]
    Missing,
    #[error("credential rejected")]
    Rejected,
    #[error("malformed credential: {0}")]
    Malformed(String),
}

/// A pluggable credential authenticator.
pub trait Authenticator: Send + Sync {
    /// Attempt to authenticate raw credential bytes, returning the identity.
    fn authenticate(&self, credential: &[u8]) -> Result<AuthIdentity, AuthError>;
}

/// HMAC-SHA256 shared-secret authenticator.
///
/// Tokens are `base64url(hmac_sha256(key, subject || ":" || ts))` with a
/// `subject:ts:sig` wire format. The secret must be held out-of-band and never
/// stored in code.
pub struct HmacAuthenticator {
    key: Vec<u8>,
}

impl HmacAuthenticator {
    /// Create an authenticator from a shared secret.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    /// Mint a token for `subject` at Unix time `ts`.
    #[must_use]
    pub fn mint(&self, subject: &str, ts: u64) -> String {
        let msg = format!("{subject}:{ts}");
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(msg.as_bytes());
        let tag = mac.finalize().into_bytes();
        let b64 = base64url(&tag);
        format!("{subject}:{ts}:{b64}")
    }

    /// Verify a token minted by [`Self::mint`] and constant-time compare.
    fn verify_token(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        let parts: Vec<&str> = token.splitn(3, ':').collect();
        let [subject, ts, sig] = parts.as_slice() else {
            return Err(AuthError::Malformed("expected subject:ts:sig".into()));
        };
        let Ok(parsed_ts) = ts.parse::<u64>() else {
            return Err(AuthError::Malformed("bad timestamp".into()));
        };
        let expected = self.mint(subject, parsed_ts);
        let expected_sig = expected.rsplit(':').next().unwrap_or_default();
        // Constant-time comparison of the signature fragments only.
        if sig.as_bytes().ct_eq(expected_sig.as_bytes()).unwrap_u8() == 0 {
            return Err(AuthError::Rejected);
        }
        Ok(AuthIdentity {
            subject: format!("token:{subject}"),
            roles: vec!["reader".to_string()],
        })
    }
}

impl Authenticator for HmacAuthenticator {
    fn authenticate(&self, credential: &[u8]) -> Result<AuthIdentity, AuthError> {
        let token = std::str::from_utf8(credential)
            .map_err(|_| AuthError::Malformed("non-utf8 token".into()))?;
        self.verify_token(token)
    }
}

/// Ed25519 bearer-token authenticator.
///
/// Tokens are `subject:base64url(sig(payload))` where the signature covers the
/// subject bytes. The verifier holds only the public key. This is the
/// machine-to-machine path for signed bundles.
pub struct Ed25519Authenticator {
    vk: ed25519_dalek::VerifyingKey,
}

impl Ed25519Authenticator {
    /// Create a verifier from a raw 32-byte Ed25519 public key.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Malformed`] if the key bytes are invalid.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, AuthError> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes)
            .map_err(|e| AuthError::Malformed(e.to_string()))?;
        Ok(Self { vk })
    }

    /// Verify a `subject:base64url(sig)` token.
    fn verify_token(&self, token: &str) -> Result<AuthIdentity, AuthError> {
        let Some((subject, sig_b64)) = token.split_once(':') else {
            return Err(AuthError::Malformed("expected subject:sig".into()));
        };
        let sig_bytes =
            decode_base64url(sig_b64).map_err(|_| AuthError::Malformed("bad base64url".into()))?;
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|_| AuthError::Malformed("bad signature length".into()))?;
        self.vk
            .verify_strict(subject.as_bytes(), &sig)
            .map_err(|_| AuthError::Rejected)?;
        Ok(AuthIdentity {
            subject: format!("key:ed25519:{}", hex::encode(self.vk.to_bytes())),
            roles: vec!["writer".to_string()],
        })
    }
}

impl Authenticator for Ed25519Authenticator {
    fn authenticate(&self, credential: &[u8]) -> Result<AuthIdentity, AuthError> {
        let token = std::str::from_utf8(credential)
            .map_err(|_| AuthError::Malformed("non-utf8 token".into()))?;
        self.verify_token(token)
    }
}

/// Base64url-encode bytes (no padding).
fn base64url(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]) << 16;
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0)) << 8;
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let n = b0 | b1 | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 63) as usize] as char);
        }
    }
    out
}

/// Base64url-decode bytes (no padding).
fn decode_base64url(s: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(()),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn hmac_mint_verify_roundtrip() {
        let a = HmacAuthenticator::new(b"super-secret");
        let token = a.mint("reader-01", 1700000000);
        let id = a.authenticate(token.as_bytes()).unwrap();
        assert_eq!(id.subject, "token:reader-01");
        assert!(id.roles.contains(&"reader".to_string()));
    }

    #[test]
    fn hmac_rejects_tampered() {
        let a = HmacAuthenticator::new(b"super-secret");
        let token = a.mint("reader-01", 1700000000);
        let mut bytes = token.as_bytes().to_vec();
        let last = bytes.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tok = String::from_utf8(bytes).unwrap();
        assert_eq!(a.authenticate(tok.as_bytes()), Err(AuthError::Rejected));
    }

    #[test]
    fn hmac_rejects_wrong_key() {
        let mint = HmacAuthenticator::new(b"key-a");
        let verify = HmacAuthenticator::new(b"key-b");
        let token = mint.mint("s", 1);
        assert_eq!(
            verify.authenticate(token.as_bytes()),
            Err(AuthError::Rejected)
        );
    }

    #[test]
    fn ed25519_verify_happy_path() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let sig = key.sign(b"bundle-123");
        let sig_b64 = base64url(&sig.to_bytes());
        let token = format!("bundle-123:{sig_b64}");
        let vk = key.verifying_key();
        let a = Ed25519Authenticator::from_bytes(&vk.to_bytes()).unwrap();
        let id = a.authenticate(token.as_bytes()).unwrap();
        assert!(id.subject.starts_with("key:ed25519:"));
        assert!(id.roles.contains(&"writer".to_string()));
    }

    #[test]
    fn base64url_roundtrip() {
        let cases: &[&[u8]] = &[&[], b"a", b"ab", b"abc", b"abcd", &[0u8, 1, 2, 3, 4]];
        for data in cases {
            let dec = decode_base64url(&base64url(data)).unwrap();
            assert_eq!(dec, *data);
        }
    }
}
