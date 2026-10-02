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

/// Blob produced by `tpm2_create` against a TPM2 (or swtpm). The parent
/// primary lives in the TPM, not in this file, so another TPM cannot unseal it.
pub const TPM2_MAGIC: &[u8] = b"erebus-tpm2-seal/v1\n";

/// `tpm2_createprimary` is on `PATH`.
pub fn tpm2_tools_present() -> bool {
    std::process::Command::new("tpm2_createprimary")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Seal `key` with the TPM selected by `tcti` (`TPM2TOOLS_TCTI` syntax).
pub fn seal_tpm2(key: &[u8; 32], tcti: &str) -> Result<Vec<u8>, anyhow::Error> {
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("secret"), key)?;
    tpm2(
        tcti,
        dir.path(),
        &["tpm2_createprimary", "-Q", "-C", "o", "-c", "primary.ctx"],
    )?;
    tpm2(
        tcti,
        dir.path(),
        &[
            "tpm2_create",
            "-Q",
            "-C",
            "primary.ctx",
            "-i",
            "secret",
            "-u",
            "seal.pub",
            "-r",
            "seal.priv",
        ],
    )?;
    pack_tpm2(
        &std::fs::read(dir.path().join("seal.pub"))?,
        &std::fs::read(dir.path().join("seal.priv"))?,
    )
}

/// Unseal a [`TPM2_MAGIC`] blob with `tcti`. A different TPM fails the load.
pub fn unseal_tpm2(blob: &[u8], tcti: &str) -> Result<[u8; 32], anyhow::Error> {
    let (public, private) = unpack_tpm2(blob)?;
    let dir = tempfile::tempdir()?;
    std::fs::write(dir.path().join("seal.pub"), &public)?;
    std::fs::write(dir.path().join("seal.priv"), &private)?;
    tpm2(
        tcti,
        dir.path(),
        &["tpm2_createprimary", "-Q", "-C", "o", "-c", "primary.ctx"],
    )?;
    tpm2(
        tcti,
        dir.path(),
        &[
            "tpm2_load",
            "-Q",
            "-C",
            "primary.ctx",
            "-u",
            "seal.pub",
            "-r",
            "seal.priv",
            "-c",
            "seal.ctx",
        ],
    )?;
    tpm2(
        tcti,
        dir.path(),
        &["tpm2_unseal", "-Q", "-c", "seal.ctx", "-o", "key.bin"],
    )?;
    let key = std::fs::read(dir.path().join("key.bin"))?;
    key.try_into()
        .map_err(|_| anyhow::anyhow!("TPM unseal did not return 32 bytes"))
}

fn tpm2(tcti: &str, dir: &std::path::Path, args: &[&str]) -> Result<(), anyhow::Error> {
    // swtpm keeps transient objects after tpm2-tools exits. A later
    // ContextLoad then fails with TPM_RC_OBJECT_MEMORY. Flush first; the
    // context files are blobs and do not need the object to stay loaded.
    let _ = std::process::Command::new("tpm2_flushcontext")
        .arg("--transient")
        .current_dir(dir)
        .env("TPM2TOOLS_TCTI", tcti)
        .output();
    let out = std::process::Command::new(args[0])
        .args(&args[1..])
        .current_dir(dir)
        .env("TPM2TOOLS_TCTI", tcti)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run {}: {e}", args[0]))?;
    if out.status.success() {
        return Ok(());
    }
    anyhow::bail!(
        "{} failed: {}",
        args[0],
        String::from_utf8_lossy(&out.stderr).trim()
    )
}

fn pack_tpm2(public: &[u8], private: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    if public.len() > u32::MAX as usize || private.len() > u32::MAX as usize {
        anyhow::bail!("TPM seal blob is too large");
    }
    let mut out = TPM2_MAGIC.to_vec();
    out.extend_from_slice(&(public.len() as u32).to_le_bytes());
    out.extend_from_slice(public);
    out.extend_from_slice(&(private.len() as u32).to_le_bytes());
    out.extend_from_slice(private);
    Ok(out)
}

fn unpack_tpm2(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), anyhow::Error> {
    let mut rest = blob
        .strip_prefix(TPM2_MAGIC)
        .ok_or_else(|| anyhow::anyhow!("not a TPM2-sealed machine key"))?;
    let public = take_len(&mut rest)?;
    let private = take_len(&mut rest)?;
    if !rest.is_empty() {
        anyhow::bail!("TPM2 seal blob has trailing bytes");
    }
    Ok((public, private))
}

fn take_len(rest: &mut &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    if rest.len() < 4 {
        anyhow::bail!("truncated TPM2 seal blob");
    }
    let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
    *rest = &rest[4..];
    if rest.len() < len {
        anyhow::bail!("truncated TPM2 seal blob");
    }
    let (head, tail) = rest.split_at(len);
    *rest = tail;
    Ok(head.to_vec())
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

    /// Two swtpm instances. `scripts/test_tpm2_swtpm.sh` sets the env and
    /// fails the run if this test does not execute.
    #[test]
    fn swtpm_copied_blob_cannot_unseal() {
        let (Some(a), Some(b)) = (
            std::env::var("ERE_TPM_TCTI_A").ok(),
            std::env::var("ERE_TPM_TCTI_B").ok(),
        ) else {
            if std::env::var("ERE_SWTPM_TEST").is_ok() {
                panic!("ERE_SWTPM_TEST=1 but ERE_TPM_TCTI_A/B are unset");
            }
            return;
        };
        assert!(tpm2_tools_present(), "tpm2-tools not on PATH");
        let raw = [11u8; 32];
        let blob = seal_tpm2(&raw, &a).unwrap();
        assert_eq!(unseal_tpm2(&blob, &a).unwrap(), raw);
        assert!(unseal_tpm2(&blob, &b).is_err());
    }
}
