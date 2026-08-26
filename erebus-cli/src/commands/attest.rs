use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::SigningKey;
use erebus_core::attest::generate_attestation;
use erebus_core::paths::default_key_dir;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Args)]
pub struct AttestArgs {
    /// Path to the .erebus file
    pub file: PathBuf,

    /// Path to the signing key file (defaults to the only key in default dir)
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// Output file path (defaults to <file>.attest)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Quiet output
    #[arg(short, long)]
    pub quiet: bool,

    /// Output result as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: AttestArgs) -> Result<()> {
    if !args.file.exists() {
        anyhow::bail!("file not found: {}", args.file.display());
    }

    let key_path = resolve_key_path(&args.key)?;
    let key_bytes = Zeroizing::new(
        std::fs::read(&key_path)
            .with_context(|| format!("failed to read signing key at {}", key_path.display()))?,
    );
    if key_bytes.len() != 32 {
        anyhow::bail!("key must be 32 bytes, got {}", key_bytes.len());
    }

    let mut key_arr = Zeroizing::new([0u8; 32]);
    key_arr.copy_from_slice(&key_bytes);
    let signing_key = SigningKey::from_bytes(&key_arr);

    let attestation =
        generate_attestation(&args.file, &signing_key).context("failed to generate attestation")?;

    let output_path = args
        .output
        .unwrap_or_else(|| args.file.with_extension("erebus.attest"));

    let json_bytes =
        serde_json::to_vec_pretty(&attestation).context("failed to serialize attestation")?;
    std::fs::write(&output_path, &json_bytes)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": args.file.display().to_string(),
                "attestation": output_path.display().to_string(),
                "signed": true,
                "key": key_path.display().to_string(),
            }))?
        );
    } else if !args.quiet {
        eprintln!("Attested {}", args.file.display());
        eprintln!("  output: {}", output_path.display());
        eprintln!("  key:    {}", key_path.display());
    }

    Ok(())
}

fn resolve_key_path(key: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = key {
        return Ok(p.clone());
    }

    let dir = default_key_dir();
    let keys: Vec<_> = std::fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "key"))
        .collect();

    if keys.len() == 1 {
        Ok(keys[0].path())
    } else {
        anyhow::bail!(
            "specify key with --key (found {} keys in {})",
            keys.len(),
            dir.display()
        )
    }
}
