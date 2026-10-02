//! `erebus provenance` — SLSA v1 statement for a source tree (ROADMAP R5).
//! `erebus build --key` calls [`emit`] so the bundle sidecar is the same bytes.

use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::SigningKey;
use erebus_core::attest::key_fingerprint;
use erebus_core::slsa::{self, ProvenanceInput};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct ProvenanceArgs {
    /// Source directory the bundle was built from
    pub source: PathBuf,

    /// Built bundle (subject of the statement)
    #[arg(long)]
    pub subject: PathBuf,

    /// Operator signing key (32 bytes)
    #[arg(long)]
    pub key: PathBuf,

    /// Output DSSE envelope (default: <subject>.slsa.json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: ProvenanceArgs) -> Result<()> {
    let out = args.output.unwrap_or_else(|| sidecar(&args.subject));
    emit(&args.source, &args.subject, &args.key, &out, &[])?;
    eprintln!("SLSA provenance: {}", out.display());
    Ok(())
}

pub fn emit(
    source: &Path,
    bundle: &Path,
    key_path: &Path,
    out: &Path,
    flags: &[String],
) -> Result<()> {
    let key = load_key(key_path)?;
    let sha = hex::encode(Sha256::digest(std::fs::read(bundle)?));
    let name = bundle
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("bundle.erebus");
    let (_stmt, payload) = slsa::statement(&ProvenanceInput {
        source,
        subject_name: name,
        subject_sha256: &sha,
        builder_version: concat!("erebus-cli ", env!("CARGO_PKG_VERSION")),
        flags,
    })?;
    let env = slsa::sign(&payload, &key, &key_fingerprint(&key.verifying_key()))?;
    std::fs::write(out, serde_json::to_vec_pretty(&env)?)?;
    Ok(())
}

pub fn sidecar(bundle: &Path) -> PathBuf {
    let mut name = bundle.as_os_str().to_owned();
    name.push(".slsa.json");
    PathBuf::from(name)
}

fn load_key(path: &Path) -> Result<SigningKey> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read signing key at {}", path.display()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}
