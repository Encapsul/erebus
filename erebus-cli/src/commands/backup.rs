use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::SigningKey;
use erebus_core::backup::build_backup_manifest;
use erebus_core::paths::default_key_dir;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Args)]
pub struct BackupArgs {
    /// Directory containing artifact manifests (JSON files)
    #[arg(short, long)]
    pub manifest_dir: PathBuf,

    /// Directory containing content-addressed blobs
    #[arg(short, long)]
    pub blob_dir: PathBuf,

    /// Path to the signing key (defaults to ~/.erebus/keys/signing.key)
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// Output file for the backup manifest (defaults to backup-manifest.json)
    #[arg(short, long, default_value = "backup-manifest.json")]
    pub output: PathBuf,

    /// Dry run — show what would be backed up without writing
    #[arg(long)]
    pub dry_run: bool,
}

fn load_signing_key(key_path: &Option<PathBuf>) -> Result<SigningKey> {
    let path = match key_path {
        Some(p) => p.clone(),
        None => default_key_dir().join("signing.key"),
    };
    let key_bytes = Zeroizing::new(
        std::fs::read(&path)
            .with_context(|| format!("failed to read signing key: {}", path.display()))?,
    );
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "key must be 32 bytes, got {}: {}",
            key_bytes.len(),
            path.display()
        );
    }
    let mut key_arr = Zeroizing::new([0u8; 32]);
    key_arr.copy_from_slice(&key_bytes);
    Ok(SigningKey::from_bytes(&key_arr))
}

pub fn run(args: BackupArgs) -> Result<()> {
    let key = load_signing_key(&args.key)?;

    let manifest = build_backup_manifest(&args.manifest_dir, &key)?;

    if args.dry_run {
        eprintln!("Would create backup manifest:");
        eprintln!("  Artifacts: {}", manifest.artifact_count);
        eprintln!("  Blobs:     {}", manifest.blob_count);
        eprintln!("  Refs:      {}", manifest.total_blob_refs);
        return Ok(());
    }

    let json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&args.output, json.as_bytes())
        .with_context(|| format!("failed to write backup manifest: {}", args.output.display()))?;
    eprintln!("Backup manifest written: {}", args.output.display());
    eprintln!("  Artifacts: {}", manifest.artifact_count);
    eprintln!("  Blobs:     {}", manifest.blob_count);
    eprintln!("  Refs:      {}", manifest.total_blob_refs);
    Ok(())
}
