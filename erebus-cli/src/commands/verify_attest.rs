use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use erebus_core::attest::{verify_attestation, Attestation};
use erebus_core::paths::trusted_keys_dir;
use std::path::PathBuf;

#[derive(Args)]
pub struct VerifyAttestArgs {
    /// Path to the .erebus.attest file
    pub attest_file: PathBuf,

    /// Directory containing trusted public keys
    #[arg(long)]
    pub trusted_dir: Option<PathBuf>,

    /// Output verification result as JSON
    #[arg(long)]
    pub json: bool,

    /// Write JSON output to file (requires --json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: VerifyAttestArgs) -> Result<()> {
    let trusted_dir = args.trusted_dir.unwrap_or_else(trusted_keys_dir);

    let data = std::fs::read_to_string(&args.attest_file)
        .with_context(|| format!("failed to read {}", args.attest_file.display()))?;

    let attestation: Attestation = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", args.attest_file.display()))?;

    let keys = load_trusted_keys(&trusted_dir)?;
    if keys.is_empty() {
        anyhow::bail!(
            "no trusted keys in {} — add keys with: erebus trust <pubkey_file>",
            trusted_dir.display()
        );
    }

    let vk = verify_attestation(&attestation, &keys).context("attestation verification failed")?;

    if args.json {
        let info = serde_json::json!({
            "file": args.attest_file.display().to_string(),
            "verified": true,
            "attestation_type": attestation.attestation_type,
            "attested_at": attestation.execution.attested_at,
            "os": attestation.execution.os,
            "arch": attestation.execution.arch,
        });
        let json_str = serde_json::to_string_pretty(&info)?;
        if let Some(path) = args.output {
            std::fs::write(&path, &json_str)
                .with_context(|| format!("failed to write to {}", path.display()))?;
            eprintln!("Wrote JSON to {}", path.display());
        } else {
            println!("{json_str}");
        }
    } else {
        eprintln!(
            "OK: attestation verified (key: {})",
            hex::encode(vk.as_bytes())
        );
        eprintln!("  type:     {}", attestation.attestation_type);
        eprintln!("  attested: {}", attestation.execution.attested_at);
        eprintln!("  os:       {}", attestation.execution.os);
        eprintln!("  arch:     {}", attestation.execution.arch);
    }

    Ok(())
}

fn load_trusted_keys(dir: &PathBuf) -> Result<Vec<VerifyingKey>> {
    let mut keys = Vec::new();
    if !dir.exists() {
        return Ok(keys);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map_or(false, |ext| ext == "pub") {
            let key_bytes = std::fs::read(&path)?;
            if key_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key_bytes);
                if let Ok(vk) = VerifyingKey::from_bytes(&arr) {
                    keys.push(vk);
                }
            }
        }
    }
    Ok(keys)
}
