use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::{Verifier, VerifyingKey};
use erebus_core::format::{Footer, SIG_BLOCK_SIZE, SIG_LEN};
use erebus_core::paths::trusted_keys_dir;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn write_json_output(value: &serde_json::Value, output: Option<&std::path::Path>) -> Result<()> {
    let json_str = serde_json::to_string_pretty(value)?;
    if let Some(path) = output {
        std::fs::write(path, &json_str)
            .with_context(|| format!("failed to write to {}", path.display()))?;
        eprintln!("Wrote JSON to {}", path.display());
    } else {
        println!("{json_str}");
    }
    Ok(())
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to the .erebus file
    pub file: PathBuf,

    /// Directory containing trusted public keys
    #[arg(long)]
    pub trusted_dir: Option<PathBuf>,

    /// Quiet output
    #[arg(short, long)]
    pub quiet: bool,

    /// Output verification result as JSON
    #[arg(long)]
    pub json: bool,

    /// Write JSON output to file (requires --json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Verify the full evidence set in one pass: bundle signature, receipt,
    /// hash-chained trail, transparency-log proof, approval and witness seal
    #[arg(long)]
    pub all: bool,

    /// Receipt to verify with --all (default: `<file>.attest`)
    #[arg(long, value_name = "FILE", requires = "all")]
    pub attest: Option<PathBuf>,

    /// Trail directory (default: `<receipt>.d` when it exists)
    #[arg(long, value_name = "DIR", requires = "all")]
    pub chain: Option<PathBuf>,

    /// Registry public key (64 hex) for log proofs and machine certificates
    #[arg(
        long,
        value_name = "HEX",
        visible_alias = "registry-key",
        requires = "all"
    )]
    pub log_key: Option<String>,

    /// Approver public key (64 hex) or path to a `.pub` file
    #[arg(long, value_name = "HEX|FILE", requires = "all")]
    pub approver_key: Option<String>,

    /// Witness public key (64 hex) or path to a `.pub` file
    #[arg(long, value_name = "HEX|FILE", requires = "all")]
    pub witness_key: Option<String>,

    /// With --all: refuse if the witness seal is missing or the trail grew
    /// past the sealed size / head
    #[arg(long, requires = "all")]
    pub require_witness: bool,

    /// With --all: require the enrolled-machine co-signature
    #[arg(long, requires = "all")]
    pub strict: bool,

    /// With --all: SLSA provenance envelope for the bundle
    #[arg(long, value_name = "FILE", requires = "all")]
    pub provenance: Option<PathBuf>,
}

pub fn run(args: VerifyArgs) -> Result<()> {
    if args.all {
        return run_all(&args);
    }
    let trusted_dir = args.trusted_dir.clone().unwrap_or_else(trusted_keys_dir);
    let verdict = verify_bundle(&args.file, &trusted_dir)?;
    if !verdict.signed {
        if args.json {
            write_json_output(&verdict.report, args.output.as_deref())?;
        } else {
            eprintln!("file is not signed");
        }
        return Ok(());
    }
    if !args.quiet {
        if let Some(k) = verdict.report.get("key").and_then(|v| v.as_str()) {
            eprintln!("Verified against {k}");
        }
    }
    if args.json {
        write_json_output(&verdict.report, args.output.as_deref())?;
    }
    // A JSON report with `verified:false` must never be a green CI gate.
    if !verdict.verified {
        anyhow::bail!("TAMPERED: signature does not match any trusted key");
    }
    if !args.quiet && !args.json {
        eprintln!("OK: signature verified");
    }
    Ok(())
}

/// `--all`: one bundle, its receipt, and every sidecar that exists next to it.
fn run_all(args: &VerifyArgs) -> Result<()> {
    let trusted_dir = args.trusted_dir.clone().unwrap_or_else(trusted_keys_dir);
    let verdict = verify_bundle(&args.file, &trusted_dir)?;
    let base = serde_json::json!({
        "file": args.file.display().to_string(),
        "mode": "all",
        "verified": false,
        "bundle": verdict.report,
    });
    if !verdict.signed {
        if args.json {
            write_json_output(&base, args.output.as_deref())?;
        }
        anyhow::bail!("file is not signed");
    }
    if !verdict.verified {
        if args.json {
            write_json_output(&base, args.output.as_deref())?;
        }
        anyhow::bail!("TAMPERED: bundle signature does not match any trusted key");
    }

    let bundle_bytes = std::fs::read(&args.file)
        .with_context(|| format!("failed to open {}", args.file.display()))?;
    let receipt = args
        .attest
        .clone()
        .unwrap_or_else(|| receipt_path_for(&args.file));
    anyhow::ensure!(
        receipt.is_file(),
        "--all needs a receipt at {} (create one with `erebus attest {}`)",
        receipt.display(),
        args.file.display()
    );
    let keys = load_trusted_keys(&trusted_dir)?;
    let publics: Vec<VerifyingKey> = keys.into_iter().map(|(_, vk)| vk).collect();
    let evidence = super::verify_attest::verify_all_evidence(&super::verify_attest::AllEvidence {
        receipt: &receipt,
        trail: args.chain.as_deref(),
        bundle_bytes: Some(&bundle_bytes),
        operator_keys: &publics,
        log_key: args.log_key.as_deref(),
        approver_key: args.approver_key.as_deref(),
        witness_key: args.witness_key.as_deref(),
        require_witness: args.require_witness,
        strict: args.strict,
        provenance: args.provenance.as_deref(),
        proof_path: None,
    })?;

    let report = serde_json::json!({
        "file": args.file.display().to_string(),
        "mode": "all",
        "verified": true,
        "bundle": verdict.report,
        "evidence": evidence,
    });
    if args.json {
        write_json_output(&report, args.output.as_deref())?;
    } else if !args.quiet {
        let scheme = report["bundle"]["scheme"].as_str().unwrap_or("?");
        let key = report["bundle"]["key"].as_str().unwrap_or("?");
        eprintln!("OK: bundle signature verified ({scheme})");
        eprintln!("  file: {}\n  key:  {key}", args.file.display());
        eprintln!();
        super::verify_attest::print_human(&report["evidence"]);
    }
    Ok(())
}

/// Receipt that `erebus attest <bundle>` writes by default.
fn receipt_path_for(bundle: &Path) -> PathBuf {
    let mut name = bundle
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push_str(".attest");
    bundle.with_file_name(name)
}

struct BundleVerdict {
    report: serde_json::Value,
    signed: bool,
    verified: bool,
}

/// Verify the trailing Ed25519 signature and return the signed facts.
fn verify_bundle(file: &Path, trusted_dir: &Path) -> Result<BundleVerdict> {
    let mut f =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    let footer = Footer::read_from(&mut f).context("failed to read erebus footer")?;
    let has_sig_block = footer.format_version >= 3 && footer.sig_offset != 0;
    if has_sig_block != footer.is_signed() {
        anyhow::bail!("inconsistent signature state (flag/offset mismatch)");
    }
    if !has_sig_block {
        return Ok(BundleVerdict {
            report: serde_json::json!({
                "file": file.display().to_string(),
                "signed": false,
                "scheme": "none",
                "verified": false,
                "key": null,
            }),
            signed: false,
            verified: false,
        });
    }

    // Read sig block: [sig_size:u32le][64-byte ed25519 signature]
    let sig_data = erebus_core::format::read_at(&mut f, footer.sig_offset, SIG_BLOCK_SIZE)?;
    let sig_size = u32::from_le_bytes([sig_data[0], sig_data[1], sig_data[2], sig_data[3]]);
    if sig_size != SIG_LEN as u32 {
        anyhow::bail!(
            "unexpected sig_size {} (expected {SIG_LEN} for ed25519)",
            sig_size
        );
    }
    let signature_bytes = &sig_data[4..SIG_BLOCK_SIZE];

    let payload =
        erebus_core::format::read_at(&mut f, footer.payload_offset, footer.payload_csize as usize)?;
    let meta = erebus_core::format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)?;

    // SHA-256(payload || meta || footer) — the footer is hashed so a downgrade
    // of format_version/FLAG_SIGNED invalidates the signature instead of
    // being silently skipped.
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    hasher.update(&meta);
    hasher.update(&footer.pack_full());
    let hash = hasher.finalize();

    let keys = load_trusted_keys(trusted_dir)?;
    if keys.is_empty() {
        anyhow::bail!(
            "no trusted keys in {} — add keys with: erebus trust <pubkey_file>",
            trusted_dir.display()
        );
    }

    let sig = ed25519_dalek::Signature::from_slice(signature_bytes)?;
    let verified_key = keys.iter().find_map(|(key_path, vk)| {
        vk.verify(&hash, &sig)
            .ok()
            .map(|()| key_path.display().to_string())
    });
    let verified = verified_key.is_some();
    Ok(BundleVerdict {
        report: serde_json::json!({
            "file": file.display().to_string(),
            "signed": true,
            "scheme": "erebus",
            "verified": verified,
            "key": verified_key,
        }),
        signed: true,
        verified,
    })
}

/// Public key that verifies `file`, from `dir`. Used by `erebus policy` to
/// match a signer allowlist against the key that actually signed the bundle.
pub(crate) fn matching_key(file: &std::path::Path, dir: &std::path::Path) -> Result<VerifyingKey> {
    let (hash, sig) = signature_preimage(file)?;
    let keys = load_trusted_keys(dir)?;
    anyhow::ensure!(
        !keys.is_empty(),
        "no trusted keys in {} — add keys with: erebus trust <pubkey_file>",
        dir.display()
    );
    keys.into_iter()
        .find(|(_, vk)| vk.verify(&hash, &sig).is_ok())
        .map(|(_, vk)| vk)
        .context("policy: signature does not match a trusted key")
}

fn signature_preimage(file: &std::path::Path) -> Result<(Vec<u8>, ed25519_dalek::Signature)> {
    let mut f =
        std::fs::File::open(file).with_context(|| format!("failed to open {}", file.display()))?;
    let footer = Footer::read_from(&mut f).context("failed to read erebus footer")?;
    let has_sig = footer.format_version >= 3 && footer.sig_offset != 0 && footer.is_signed();
    anyhow::ensure!(
        has_sig,
        "policy: signer allowlist set but the bundle is unsigned"
    );
    let sig_data = erebus_core::format::read_at(&mut f, footer.sig_offset, SIG_BLOCK_SIZE)?;
    let sig_size = u32::from_le_bytes([sig_data[0], sig_data[1], sig_data[2], sig_data[3]]);
    anyhow::ensure!(sig_size == SIG_LEN as u32, "unexpected signature size");
    let payload =
        erebus_core::format::read_at(&mut f, footer.payload_offset, footer.payload_csize as usize)?;
    let meta = erebus_core::format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)?;
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    hasher.update(&meta);
    hasher.update(&footer.pack_full());
    let sig = ed25519_dalek::Signature::from_slice(&sig_data[4..SIG_BLOCK_SIZE])?;
    Ok((hasher.finalize().to_vec(), sig))
}

fn load_trusted_keys(dir: &Path) -> Result<Vec<(PathBuf, VerifyingKey)>> {
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
                    keys.push((path, vk));
                }
            }
        }
    }
    Ok(keys)
}
