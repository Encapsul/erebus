//! `erebus witness` — local trail witness for disconnected anchoring (R1).
//!
//! A second Ed25519 key co-signs the local trail head while offline. When the
//! link returns, receipts publish as usual; `verify-attest --witness-key`
//! proves the outage window (`witnessed at T1`, later `anchored at T2`).

use anyhow::{Context, Result};
use clap::Args;
use erebus_core::attest_log::AttestationLog;
use erebus_core::witness::{self, KEY_FILE};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct WitnessArgs {
    #[command(subcommand)]
    pub command: WitnessCommand,
}

#[derive(clap::Subcommand)]
pub enum WitnessCommand {
    /// Generate a witness Ed25519 key (0600)
    Keygen {
        /// Directory for `witness.key` (default: `~/.local/share/erebus/witness`)
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// Seal the current trail head as `HEAD.witness.json`
    Seal {
        /// Trail directory (`<bundle>.attest.d`)
        #[arg(long, value_name = "DIR")]
        trail: PathBuf,
        /// Witness key directory (or set `ERE_WITNESS_KEY`)
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
}

pub fn run(args: WitnessArgs) -> Result<()> {
    match args.command {
        WitnessCommand::Keygen { dir } => keygen(dir),
        WitnessCommand::Seal { trail, dir } => seal(&trail, dir.as_deref()),
    }
}

fn keygen(dir: Option<PathBuf>) -> Result<()> {
    let dir = dir.unwrap_or_else(witness::default_dir);
    let (key, path) = witness::keygen(&dir)
        .with_context(|| format!("failed to create witness key in {}", dir.display()))?;
    let vk = key.verifying_key();
    eprintln!("Wrote witness key to {}", path.display());
    eprintln!(
        "  fingerprint: {}",
        erebus_core::attest::key_fingerprint(&vk)
    );
    eprintln!("  public:      {}", hex::encode(vk.as_bytes()));
    eprintln!("  file:        {}", dir.join(KEY_FILE).display());
    Ok(())
}

fn seal(trail: &Path, key_dir: Option<&Path>) -> Result<()> {
    let log = AttestationLog::open(trail)
        .with_context(|| format!("cannot open trail {}", trail.display()))?;
    let cp = witness::seal_trail(&log, key_dir)
        .with_context(|| format!("failed to seal {}", trail.display()))?;
    eprintln!(
        "Sealed {} — size {}, root {}",
        trail.join(witness::WITNESS_FILE).display(),
        cp.size,
        cp.root
    );
    eprintln!("  witnessed_at: {}", cp.witnessed_at);
    eprintln!("  witness_id:   {}", cp.witness_id);
    Ok(())
}
