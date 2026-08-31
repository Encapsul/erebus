use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::SigningKey;
use erebus_core::backup::{verify_backup, BackupManifest};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Args)]
pub struct RestoreArgs {
    /// Path to the backup manifest JSON
    #[arg(short, long)]
    pub manifest: PathBuf,

    /// Path to the signing key (seed) whose public key verifies the manifest
    #[arg(short, long)]
    pub key: PathBuf,

    /// Directory to verify manifests against
    #[arg(long)]
    pub manifest_dir: Option<PathBuf>,

    /// Directory to verify blobs against
    #[arg(long)]
    pub blob_dir: Option<PathBuf>,
}

fn load_verifying_key(key_path: &PathBuf) -> Result<SigningKey> {
    let key_bytes = Zeroizing::new(
        std::fs::read(key_path)
            .with_context(|| format!("failed to read signing key: {}", key_path.display()))?,
    );
    if key_bytes.len() != 32 {
        anyhow::bail!(
            "key must be 32 bytes, got {}: {}",
            key_bytes.len(),
            key_path.display()
        );
    }
    let mut arr = Zeroizing::new([0u8; 32]);
    arr.copy_from_slice(key_bytes.as_ref());
    Ok(SigningKey::from_bytes(&arr))
}

pub fn run(args: RestoreArgs) -> Result<()> {
    let key = load_verifying_key(&args.key)?;
    let vk = key.verifying_key();

    let data = std::fs::read(&args.manifest).with_context(|| {
        format!(
            "failed to read backup manifest: {}",
            args.manifest.display()
        )
    })?;
    let manifest: BackupManifest =
        serde_json::from_slice(&data).with_context(|| "failed to parse backup manifest JSON")?;

    eprintln!("Verifying backup manifest:");
    eprintln!("  Artifacts: {}", manifest.artifact_count);
    eprintln!("  Blobs:     {}", manifest.blob_count);

    verify_backup(
        &manifest,
        &vk,
        args.manifest_dir.as_deref(),
        args.blob_dir.as_deref(),
    )
    .map_err(|e| anyhow::anyhow!("backup verification failed: {e}"))?;

    eprintln!("Backup verification: OK");
    Ok(())
}
