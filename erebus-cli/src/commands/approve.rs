//! `erebus approve` — sign a human approval over a subject digest (R4).
//!
//! Produces an [`erebus_core::attest::Approval`] JSON that `erebus attest
//! --approval` embeds into a receipt. The signature covers
//! `erebus-approval/v1\n{decision}\n{subject_digest}\n{decided_at}\n`.

use anyhow::{bail, Context, Result};
use clap::Args;
use erebus_core::attest::{load_signing_key, sha256_hex, sign_approval};
use std::path::PathBuf;

#[derive(Args)]
pub struct ApproveArgs {
    /// Approver Ed25519 seed (raw 32-byte `erebus keygen` format)
    #[arg(long, value_name = "KEY")]
    pub key: PathBuf,

    /// Decision: `allow` or `deny`
    #[arg(long, value_name = "allow|deny")]
    pub decision: String,

    /// Subject digest (`sha256:…`)
    #[arg(long, value_name = "DIGEST", conflicts_with = "subject_file")]
    pub subject: Option<String>,

    /// Hash this file and use `sha256:<hex>` as the subject
    #[arg(long, value_name = "FILE", conflicts_with = "subject")]
    pub subject_file: Option<PathBuf>,

    /// Output path for the approval JSON
    #[arg(short, long, value_name = "FILE", default_value = "approval.json")]
    pub output: PathBuf,
}

pub fn run(args: ApproveArgs) -> Result<()> {
    let decision = args.decision.trim().to_ascii_lowercase();
    if decision != "allow" && decision != "deny" {
        bail!("--decision must be allow or deny, got {}", args.decision);
    }
    let subject = resolve_subject(args.subject.as_deref(), args.subject_file.as_ref())?;
    let key = load_signing_key(&args.key)
        .with_context(|| format!("cannot load approver key {}", args.key.display()))?;
    let approval = sign_approval(&key, &decision, &subject);
    let json = serde_json::to_vec_pretty(&approval).context("serialize approval")?;
    std::fs::write(&args.output, &json)
        .with_context(|| format!("failed to write {}", args.output.display()))?;
    eprintln!("Wrote approval to {}", args.output.display());
    eprintln!("  decision:  {decision}");
    eprintln!("  subject:   {subject}");
    eprintln!("  approver:  {}", approval.key_fingerprint);
    Ok(())
}

fn resolve_subject(subject: Option<&str>, file: Option<&PathBuf>) -> Result<String> {
    match (subject, file) {
        (Some(s), None) => {
            let s = s.trim();
            if !s.starts_with("sha256:") || s.len() != 71 {
                bail!("--subject must look like sha256:<64 hex chars>");
            }
            Ok(s.to_string())
        }
        (None, Some(path)) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            Ok(sha256_hex(&bytes))
        }
        _ => bail!("provide --subject or --subject-file"),
    }
}
