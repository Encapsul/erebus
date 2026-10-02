//! Per-machine identity (ROADMAP P0-6).
//!
//! The operator key (`ERE_ATTEST_KEY`) says *who vouches* for a run; it can
//! be copied anywhere. The machine key says *where* it ran: generated on the
//! host by `erebus enroll`, never leaves it, and is bound to an account by a
//! certificate the registry signs with its log key. Spec 2.0 receipts are
//! co-signed by the machine key and carry `execution.machine_id` (its
//! fingerprint) inside the signed statement; `verify-attest --strict` refuses
//! receipts that lack a valid machine signature + certificate.
//!
//! Certificate bytes signed by the registry (must match `registry_server.py`):
//! `erebus-machine-cert/v1\n{machine_id}\n{public_key_hex}\n{owner}\n{registry}\n{issued_at}\n`.

use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::attest::{key_fingerprint, Attestation};

pub const CERT_PREFIX: &str = "erebus-machine-cert/v1";
pub const KEY_FILE: &str = "machine.key";
pub const CERT_FILE: &str = "machine.cert.json";

/// Registry-issued binding of a machine key to an account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineCertificate {
    pub machine_id: String,
    pub public_key_hex: String,
    pub owner: String,
    /// Registry origin string (same as the log checkpoint origin).
    pub registry: String,
    pub issued_at: String,
    /// `software` (omitted, cert v1) or `tpm2` (cert v2, inside the signed bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_storage: Option<String>,
    /// Fingerprint + raw public key of the registry key that signed.
    pub registry_key_id: String,
    pub registry_key_hex: String,
    pub signature_hex: String,
}

impl MachineCertificate {
    pub fn signed_bytes(&self) -> Vec<u8> {
        if self.key_storage.as_deref() == Some("tpm2") {
            return format!(
                "erebus-machine-cert/v2\n{}\n{}\n{}\n{}\n{}\ntpm2\n",
                self.machine_id, self.public_key_hex, self.owner, self.registry, self.issued_at
            )
            .into_bytes();
        }
        format!(
            "{CERT_PREFIX}\n{}\n{}\n{}\n{}\n{}\n",
            self.machine_id, self.public_key_hex, self.owner, self.registry, self.issued_at
        )
        .into_bytes()
    }

    /// Verify the registry signature; the signer must be one of
    /// `trusted_registry_keys`.
    pub fn verify(
        &self,
        trusted_registry_keys: &[VerifyingKey],
    ) -> Result<VerifyingKey, anyhow::Error> {
        let vk = parse_verifying_key(&self.registry_key_hex, "certificate registry key")?;
        if key_fingerprint(&vk) != self.registry_key_id {
            anyhow::bail!("TAMPERED: certificate registry_key_id does not match its key");
        }
        if !trusted_registry_keys.contains(&vk) {
            anyhow::bail!(
                "certificate signed by untrusted registry key {} (pass --registry-key)",
                self.registry_key_id
            );
        }
        let sig: [u8; 64] = hex::decode(&self.signature_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("certificate signature is not 64 bytes of hex"))?;
        vk.verify(&self.signed_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| anyhow::anyhow!("TAMPERED: certificate signature does not verify"))?;
        Ok(vk)
    }
}

/// Display copy embedded in receipts (the binding facts are re-derived by
/// verifiers from the envelope signature and the certificate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineInfo {
    pub machine_id: String,
    pub public_key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<MachineCertificate>,
}

/// The host's key pair plus, once enrolled, its certificate.
pub struct MachineIdentity {
    pub key: SigningKey,
    pub certificate: Option<MachineCertificate>,
}

impl MachineIdentity {
    pub fn generate() -> Self {
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed.as_mut());
        Self {
            key: SigningKey::from_bytes(&seed),
            certificate: None,
        }
    }

    pub fn machine_id(&self) -> String {
        key_fingerprint(&self.key.verifying_key())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.key.verifying_key().as_bytes())
    }

    pub fn info(&self) -> MachineInfo {
        MachineInfo {
            machine_id: self.machine_id(),
            public_key_hex: self.public_key_hex(),
            certificate: self.certificate.clone(),
        }
    }

    /// `ERE_MACHINE_DIR`, else `$XDG_DATA_HOME/erebus/machine`, else
    /// `~/.local/share/erebus/machine`.
    pub fn default_dir() -> PathBuf {
        if let Some(d) = std::env::var_os("ERE_MACHINE_DIR") {
            return PathBuf::from(d);
        }
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            return PathBuf::from(xdg).join("erebus").join("machine");
        }
        match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("erebus")
                .join("machine"),
            None => PathBuf::from(".erebus").join("machine"),
        }
    }

    /// Write `machine.key` (0600, never overwritten) and the certificate.
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let key_path = dir.join(KEY_FILE);
        if !key_path.exists() {
            write_private(&key_path, self.key.as_bytes())?;
        }
        match &self.certificate {
            Some(cert) => {
                let json = serde_json::to_vec_pretty(cert)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                std::fs::write(dir.join(CERT_FILE), json)?;
            }
            None => {
                let _ = std::fs::remove_file(dir.join(CERT_FILE));
            }
        }
        Ok(())
    }

    /// `Ok(None)` when the host was never enrolled (no key file).
    pub fn load(dir: &Path) -> Result<Option<Self>, anyhow::Error> {
        let key_path = dir.join(KEY_FILE);
        let seed_bytes = match std::fs::read(&key_path) {
            Ok(b) => zeroize::Zeroizing::new(b),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => anyhow::bail!("failed to read {}: {e}", key_path.display()),
        };
        let seed = unseal_key_file(&key_path, &seed_bytes)?;
        let seed: &[u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} must be 32 bytes", key_path.display()))?;
        let certificate = match std::fs::read(dir.join(CERT_FILE)) {
            Ok(json) => Some(serde_json::from_slice(&json).map_err(|e| {
                anyhow::anyhow!("malformed {}: {e}", dir.join(CERT_FILE).display())
            })?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => anyhow::bail!("failed to read certificate: {e}"),
        };
        Ok(Some(Self {
            key: SigningKey::from_bytes(seed),
            certificate,
        }))
    }

    pub fn load_default() -> Result<Option<Self>, anyhow::Error> {
        Self::load(&Self::default_dir())
    }
}

fn unseal_key_file(
    path: &Path,
    bytes: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, anyhow::Error> {
    if !bytes.starts_with(crate::tpm::SEAL_MAGIC) {
        return Ok(zeroize::Zeroizing::new(bytes.to_vec()));
    }
    let binding = std::env::var("ERE_TPM_BINDING").map_err(|_| {
        anyhow::anyhow!(
            "{} is TPM-sealed; set ERE_TPM_BINDING to this host's TPM secret",
            path.display()
        )
    })?;
    let key = crate::tpm::unseal(bytes, binding.as_bytes())?;
    Ok(zeroize::Zeroizing::new(key.to_vec()))
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    std::fs::write(path, bytes)
}

pub fn parse_verifying_key(hex_key: &str, what: &str) -> Result<VerifyingKey, anyhow::Error> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("{what} must be 64 hex characters"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("{what} invalid: {e}"))
}

/// What `--strict` established about the machine that produced a receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachineReport {
    pub machine_id: String,
    pub owner: String,
    pub registry: String,
    pub issued_at: String,
}

/// Strict machine check: the receipt is co-signed by the machine key named
/// in the signed statement, and that key carries a certificate from a
/// trusted registry.
pub fn verify_machine(
    att: &Attestation,
    trusted_registry_keys: &[VerifyingKey],
) -> Result<MachineReport, anyhow::Error> {
    let machine = att.machine.as_ref().ok_or_else(|| {
        anyhow::anyhow!("STRICT: receipt carries no machine identity (host not enrolled)")
    })?;
    let envelope = att
        .envelope
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("STRICT: spec 1.x receipts have no machine signature"))?;
    if att.execution.machine_id.as_deref() != Some(machine.machine_id.as_str()) {
        anyhow::bail!("TAMPERED: execution.machine_id does not name the machine block");
    }
    let vk = parse_verifying_key(&machine.public_key_hex, "machine public key")?;
    if key_fingerprint(&vk) != machine.machine_id {
        anyhow::bail!("TAMPERED: machine_id is not the fingerprint of the machine key");
    }
    if !envelope.verified_by(&vk)? {
        anyhow::bail!("TAMPERED: receipt is not signed by the machine key");
    }
    let cert = machine
        .certificate
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("STRICT: machine key is not certified by a registry"))?;
    if cert.machine_id != machine.machine_id || cert.public_key_hex != machine.public_key_hex {
        anyhow::bail!("TAMPERED: certificate is for a different machine key");
    }
    cert.verify(trusted_registry_keys)?;
    Ok(MachineReport {
        machine_id: machine.machine_id.clone(),
        owner: cert.owner.clone(),
        registry: cert.registry.clone(),
        issued_at: cert.issued_at.clone(),
    })
}

/// Issue a certificate (registry side / tests). The Python registry does
/// the same thing; this Rust twin keeps the two in lockstep via tests.
pub fn issue_certificate(
    registry_key: &SigningKey,
    registry: &str,
    owner: &str,
    machine_public_key_hex: &str,
    issued_at: &str,
) -> Result<MachineCertificate, anyhow::Error> {
    use ed25519_dalek::Signer;
    let machine_vk = parse_verifying_key(machine_public_key_hex, "machine public key")?;
    let mut cert = MachineCertificate {
        machine_id: key_fingerprint(&machine_vk),
        public_key_hex: machine_public_key_hex.to_string(),
        owner: owner.to_string(),
        registry: registry.to_string(),
        issued_at: issued_at.to_string(),
        key_storage: None,
        registry_key_id: key_fingerprint(&registry_key.verifying_key()),
        registry_key_hex: hex::encode(registry_key.verifying_key().as_bytes()),
        signature_hex: String::new(),
    };
    cert.signature_hex = hex::encode(registry_key.sign(&cert.signed_bytes()).to_bytes());
    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn save_load_roundtrip_and_private_mode() {
        let dir = tempdir().unwrap();
        let id = MachineIdentity::generate();
        id.save(dir.path()).unwrap();
        let loaded = MachineIdentity::load(dir.path()).unwrap().unwrap();
        assert_eq!(loaded.machine_id(), id.machine_id());
        assert!(loaded.certificate.is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // A second save never rotates the key silently.
        let other = MachineIdentity::generate();
        other.save(dir.path()).unwrap();
        assert_eq!(
            MachineIdentity::load(dir.path())
                .unwrap()
                .unwrap()
                .machine_id(),
            id.machine_id()
        );
        assert!(MachineIdentity::load(&dir.path().join("nope"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn certificate_verifies_only_under_its_registry_key() {
        let registry = SigningKey::from_bytes(&[7u8; 32]);
        let rogue = SigningKey::from_bytes(&[8u8; 32]);
        let id = MachineIdentity::generate();
        let cert = issue_certificate(
            &registry,
            "reg",
            "alice",
            &id.public_key_hex(),
            "2026-09-28T00:00:00Z",
        )
        .unwrap();
        assert_eq!(cert.machine_id, id.machine_id());
        assert!(cert.verify(&[registry.verifying_key()]).is_ok());
        assert!(cert
            .verify(&[rogue.verifying_key()])
            .unwrap_err()
            .to_string()
            .contains("untrusted"));
        let mut forged = cert.clone();
        forged.owner = "mallory".into();
        assert!(forged
            .verify(&[registry.verifying_key()])
            .unwrap_err()
            .to_string()
            .contains("TAMPERED"));
    }
}
