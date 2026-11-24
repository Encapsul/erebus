//! `erebus policy check` — refuse a bundle that breaks a launch policy.

use anyhow::{Context, Result};
use clap::Args;
use erebus_core::attest::key_fingerprint;
use erebus_core::paths::trusted_keys_dir;
use erebus_core::policy::{self, Policy};
use std::path::PathBuf;

#[derive(Args)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommand,
}

#[derive(clap::Subcommand)]
pub enum PolicyCommand {
    /// Check a bundle against a policy file. Exit 1 when it would not launch.
    Check(CheckArgs),
}

#[derive(Args)]
pub struct CheckArgs {
    pub bundle: PathBuf,
    #[arg(long)]
    pub policy: PathBuf,
    /// Trusted public keys. The signer allowlist is matched against the key
    /// that verifies the bundle (default: `erebus trust` directory).
    #[arg(long)]
    pub trusted_dir: Option<PathBuf>,
}

pub fn run(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommand::Check(a) => check(&a),
    }
}

pub fn check(args: &CheckArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.policy)
        .with_context(|| format!("failed to read {}", args.policy.display()))?;
    let policy = Policy::parse(&text)?;
    let dir = args.trusted_dir.clone().unwrap_or_else(trusted_keys_dir);
    let keys = if policy.require_receipt {
        policy::load_trusted_keys(&dir)?
    } else {
        Vec::new()
    };
    policy::enforce(&args.bundle, &policy, &keys)?;
    if policy.require_receipt || !policy.signers.is_empty() {
        let vk = super::verify::matching_key(&args.bundle, &dir)?;
        check_signer(&policy, &vk)?;
    }
    eprintln!("OK: policy {}", args.policy.display());
    Ok(())
}

fn check_signer(policy: &Policy, vk: &ed25519_dalek::VerifyingKey) -> Result<()> {
    if !policy.signers.is_empty() {
        let fp = key_fingerprint(vk);
        let raw = hex::encode(vk.as_bytes());
        let allowed = policy.signers.iter().any(|s| {
            let s = s.trim().trim_start_matches("sha256:");
            s == fp.trim_start_matches("sha256:") || s == raw
        });
        anyhow::ensure!(allowed, "policy: signer {fp} is not in the allowlist");
    }
    Ok(())
}

pub fn enforce_file(bundle: &std::path::Path, policy_path: &std::path::Path) -> Result<()> {
    check(&CheckArgs {
        bundle: bundle.to_path_buf(),
        policy: policy_path.to_path_buf(),
        trusted_dir: None,
    })
}
