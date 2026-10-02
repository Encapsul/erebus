//! `erebus enroll` — give this host a machine identity.
//!
//! Generates a per-machine Ed25519 key (0600, never leaves the host, never
//! rotated implicitly) and, with `--registry`, asks the registry to certify
//! it. From then on every receipt produced on this host — `erebus attest`,
//! the launcher stub, the attesting proxy — is co-signed by the machine key,
//! and `erebus verify-attest --strict` can demand that co-signature plus a
//! certificate from a trusted registry.

use anyhow::{Context, Result};
use clap::Args;
use erebus_core::machine::{MachineCertificate, MachineIdentity};
use std::path::PathBuf;

#[derive(Args)]
pub struct EnrollArgs {
    /// Registry that certifies the machine key (omit to only create the key)
    #[arg(long, env = "ERE_REGISTRY")]
    pub registry: Option<String>,

    /// Bearer token for the registry (prefer --token-file for secrets)
    #[arg(long, env = "ERE_TOKEN")]
    pub token: Option<String>,

    /// Path to a file containing the bearer token
    #[arg(long)]
    pub token_file: Option<PathBuf>,

    /// Where the machine key and certificate live
    /// (default: `$ERE_MACHINE_DIR`, else `~/.local/share/erebus/machine`)
    #[arg(long, value_name = "DIR")]
    pub dir: Option<PathBuf>,

    /// Show the current identity without changing anything
    #[arg(long)]
    pub show: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Ask the registry for a `key_storage: tpm2` certificate and seal the key
    /// file to `ERE_TPM_BINDING` (the binding is not stored in the key file).
    #[arg(long)]
    pub tpm: bool,
}

pub fn run(args: EnrollArgs) -> Result<()> {
    let dir = args
        .dir
        .clone()
        .unwrap_or_else(MachineIdentity::default_dir);
    let existing = MachineIdentity::load(&dir)
        .with_context(|| format!("failed to read machine identity in {}", dir.display()))?;
    if args.show {
        return match existing {
            Some(id) => report(&id, &dir, "unchanged", args.json),
            None => anyhow::bail!(
                "no machine identity in {} — run `erebus enroll`",
                dir.display()
            ),
        };
    }
    let (mut identity, action) = match existing {
        Some(id) => (id, "existing"),
        None => (MachineIdentity::generate(), "generated"),
    };
    if let Some(registry) = &args.registry {
        let token =
            super::attest::resolve_token(args.token.as_deref(), args.token_file.as_deref())?
                .ok_or_else(|| anyhow::anyhow!("--registry needs --token or --token-file"))?;
        identity.certificate = Some(request_certificate(registry, &token, &identity, args.tpm)?);
    }
    identity
        .save(&dir)
        .with_context(|| format!("failed to save machine identity in {}", dir.display()))?;
    if args.tpm {
        seal_machine_key(&dir)?;
    }
    report(&identity, &dir, action, args.json)
}

/// POST the public key; the registry answers with a certificate signed by
/// its log key. We verify it names *our* key before trusting the answer.
fn request_certificate(
    registry: &str,
    token: &str,
    identity: &MachineIdentity,
    tpm: bool,
) -> Result<MachineCertificate> {
    let registry = registry.trim_end_matches('/');
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;
    let resp = client
        .post(format!("{registry}/machines/enroll"))
        .header("Authorization", format!("Bearer {token}"))
        .json(&serde_json::json!({
            "public_key_hex": identity.public_key_hex(),
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "key_storage": if tpm { "tpm2" } else { "software" },
        }))
        .send()
        .context("failed to reach registry")?
        .error_for_status()
        .with_context(|| format!("registry refused enrollment at {registry}"))?;
    let body: serde_json::Value = resp.json().context("invalid registry response")?;
    let cert: MachineCertificate = serde_json::from_value(
        body.get("certificate")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("registry response has no certificate"))?,
    )
    .context("malformed certificate")?;
    if cert.machine_id != identity.machine_id() || cert.public_key_hex != identity.public_key_hex()
    {
        anyhow::bail!("registry certified a different key than ours");
    }
    let registry_key = erebus_core::machine::parse_verifying_key(
        &cert.registry_key_hex,
        "registry key in certificate",
    )?;
    cert.verify(&[registry_key])
        .context("certificate signature does not verify under the registry key it names")?;
    Ok(cert)
}

fn report(
    identity: &MachineIdentity,
    dir: &std::path::Path,
    action: &str,
    json: bool,
) -> Result<()> {
    let cert = identity.certificate.as_ref();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "machine_id": identity.machine_id(),
                "public_key_hex": identity.public_key_hex(),
                "dir": dir.display().to_string(),
                "key": action,
                "certificate": cert,
            }))?
        );
        return Ok(());
    }
    eprintln!("Machine identity ({action} key) in {}", dir.display());
    eprintln!("  machine_id: {}", identity.machine_id());
    match cert {
        Some(c) => {
            eprintln!(
                "  certified:  by {} for {} at {}",
                c.registry, c.owner, c.issued_at
            );
            eprintln!("  registry key: {}", c.registry_key_id);
        }
        None => eprintln!("  certified:  no — run `erebus enroll --registry <url> --token <t>`"),
    }
    Ok(())
}

fn seal_machine_key(dir: &std::path::Path) -> Result<()> {
    let binding = std::env::var("ERE_TPM_BINDING")
        .context("--tpm seals the key to ERE_TPM_BINDING; that secret stays off the key file")?;
    let path = dir.join(erebus_core::machine::KEY_FILE);
    let raw = std::fs::read(&path)?;
    if raw.starts_with(erebus_core::tpm::SEAL_MAGIC) {
        return Ok(());
    }
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("machine key is not 32 bytes"))?;
    std::fs::write(&path, erebus_core::tpm::seal(&raw, binding.as_bytes()))?;
    Ok(())
}
