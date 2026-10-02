//! Host-bound seal for the machine key (ROADMAP R6).
//!
//! A software key file is 32 raw bytes and can be copied. A TPM-sealed file is
//! ciphertext bound to a host secret that is **not** in the key file (the TPM,
//! or in CI a swtpm binding file). Unsealing with another host's binding does
//! not yield a key that can co-sign.

use sha2::{Digest, Sha256};

pub const SEAL_MAGIC: &[u8] = b"erebus-tpm-seal/v1\n";

/// Encrypt `key` under `binding`. The blob does not contain `binding`.
pub fn seal(key: &[u8; 32], binding: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let mut out = SEAL_MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&mask_key(key, binding, &nonce));
    out
}

/// Recover the key. A wrong binding yields bytes that are not `expected`-equal
/// to the original; callers treat a mismatch as "this host cannot co-sign".
pub fn unseal(blob: &[u8], binding: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    let rest = blob
        .strip_prefix(SEAL_MAGIC)
        .ok_or_else(|| anyhow::anyhow!("not a TPM-sealed machine key"))?;
    if rest.len() != 64 {
        anyhow::bail!("sealed machine key has the wrong length");
    }
    let (nonce, cipher) = rest.split_at(32);
    let mut key = [0u8; 32];
    key.copy_from_slice(cipher);
    let mask = mask(binding, nonce);
    for (b, m) in key.iter_mut().zip(mask) {
        *b ^= m;
    }
    Ok(key)
}

fn mask_key(key: &[u8; 32], binding: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mask = mask(binding, nonce);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = key[i] ^ mask[i];
    }
    out
}

fn mask(binding: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"erebus-tpm-seal");
    hasher.update(binding);
    hasher.update(nonce);
    hasher.finalize().into()
}

/// True when `blob` unseals to `key` under `binding`.
pub fn unseals_to(blob: &[u8], binding: &[u8], key: &[u8; 32]) -> bool {
    unseal(blob, binding).ok().as_ref() == Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn copied_seal_cannot_cosign_on_another_host() {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        let raw = key.to_bytes();
        let blob = seal(&raw, b"host-a-tpm");
        assert!(unseals_to(&blob, b"host-a-tpm", &raw));
        assert!(!unseals_to(&blob, b"host-b-tpm", &raw));
        let other = unseal(&blob, b"host-b-tpm").unwrap();
        let foreign = SigningKey::from_bytes(&other);
        let msg = b"erebus-machine-cosign";
        let sig = foreign.sign(msg);
        assert!(key.verify(msg, &sig).is_err());
    }
}
