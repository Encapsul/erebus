use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::{Signer, SigningKey};
use erebus_core::attest::Attestation;
use erebus_core::audit::{aggregate_attestations, file_hash, generate_sbom, AuditReport};
use erebus_core::format::{Footer, FLAG_SIGNED};
use erebus_core::paths::{default_key_dir, trusted_keys_dir};
use sha2::Sha256;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Args)]
pub struct AuditArgs {
    /// Path to the .erebus file
    pub file: PathBuf,

    /// Directory containing .attest files (defaults to same dir as binary)
    #[arg(long)]
    pub attest_dir: Option<PathBuf>,

    /// Path to the signing key file
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// Output file path (defaults to <file>.audit.json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Quiet output
    #[arg(short, long)]
    pub quiet: bool,

    /// Output result as JSON (unsigned, for inspection)
    #[arg(long)]
    pub json: bool,

    /// Verify an existing audit report instead of generating one
    #[arg(long)]
    pub verify: bool,
}

pub fn run(args: AuditArgs) -> Result<()> {
    if !args.file.exists() {
        anyhow::bail!("file not found: {}", args.file.display());
    }

    if args.verify {
        return verify_report(&args);
    }

    // Read binary
    let mut f = std::fs::File::open(&args.file)
        .with_context(|| format!("failed to open {}", args.file.display()))?;
    let footer = Footer::read_from(&mut f).context("failed to read erebus footer")?;
    let meta_bytes =
        erebus_core::format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)
            .context("failed to read metadata")?;
    let meta: serde_json::Value =
        serde_json::from_slice(&meta_bytes).context("failed to parse metadata JSON")?;

    // Artifact summary
    let arch_name = match footer.arch {
        1 => "x86_64",
        2 => "aarch64",
        3 => "riscv64",
        _ => "unknown",
    };
    let flags = flag_names(footer.flags);
    let bundle_hash = file_hash(&args.file)?;

    let artifact = erebus_core::audit::ArtifactSummary {
        bundle_hash,
        payload_hash: footer.sha256_hex(),
        format_version: footer.format_version,
        flags,
        os: "linux".to_string(),
        arch: arch_name.to_string(),
    };

    // SBOM
    let sbom = generate_sbom(&meta);

    // Load attestations
    let attest_dir = args.attest_dir.unwrap_or_else(|| {
        args.file
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf()
    });
    let attestations = load_attestations_from_dir(&attest_dir)?;
    let attestation_chain = aggregate_attestations(&attestations);

    // Integrity
    let integrity = erebus_core::audit::IntegrityInfo {
        payload_sha256: footer.sha256_hex(),
        signed: footer.flags & FLAG_SIGNED != 0,
        sisr_enabled: true,
    };

    // Build unsigned report
    let mut report = AuditReport {
        spec_version: "1.0".to_string(),
        report_type: "erebus-audit".to_string(),
        artifact,
        sbom,
        attestation_chain,
        integrity,
        signature: erebus_core::audit::ReportSignature {
            algorithm: "ed25519".to_string(),
            key_fingerprint: String::new(),
            signature_hex: String::new(),
        },
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Sign the report
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

    use sha2::Digest;
    let fingerprint = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(signing_key.verifying_key().as_bytes()))
    );
    report.signature.key_fingerprint = fingerprint;

    // Sign: zero out sig, serialize, hash, sign
    let doc_bytes = serde_json::to_vec(&report)?;
    let hash = Sha256::digest(&doc_bytes);
    let sig = signing_key.sign(&hash);
    report.signature.signature_hex = hex::encode(sig.to_bytes());

    // Write output
    let output_path = args
        .output
        .unwrap_or_else(|| args.file.with_extension("audit.json"));
    let json_bytes = serde_json::to_vec_pretty(&report)?;
    std::fs::write(&output_path, &json_bytes)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    if !args.quiet {
        eprintln!("Audit report: {}", args.file.display());
        eprintln!("  output:    {}", output_path.display());
        eprintln!("  signed:    yes ({})", report.signature.key_fingerprint);
        eprintln!("  layers:    {}", report.sbom.components.len());
        eprintln!("  attestations: {}", report.attestation_chain.count);
    }

    Ok(())
}

fn verify_report(args: &AuditArgs) -> Result<()> {
    let data = std::fs::read(&args.file)
        .with_context(|| format!("failed to read {}", args.file.display()))?;
    let report: AuditReport =
        serde_json::from_slice(&data).context("failed to parse audit report")?;

    let trusted_dir = trusted_keys_dir();
    let keys = load_trusted_keys(&trusted_dir)?;
    if keys.is_empty() {
        anyhow::bail!(
            "no trusted keys in {} — add with: erebus trust <pubkey>",
            trusted_dir.display()
        );
    }

    use erebus_core::audit::verify_audit_report;
    match verify_audit_report(&report, &keys)? {
        Some(key_path) => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "verified": true,
                        "key": key_path,
                    }))?
                );
            } else if !args.quiet {
                eprintln!("OK: audit report verified against {key_path}");
            }
        }
        None => {
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "verified": false,
                    }))?
                );
            } else {
                anyhow::bail!("audit report signature does not match any trusted key");
            }
        }
    }
    Ok(())
}

fn flag_names(flags: u8) -> Vec<String> {
    let mut names = Vec::new();
    if flags & 0x01 != 0 {
        names.push("signed".to_string());
    }
    if flags & 0x02 != 0 {
        names.push("encrypted".to_string());
    }
    if flags & 0x04 != 0 {
        names.push("gui".to_string());
    }
    if flags & 0x08 != 0 {
        names.push("sisr".to_string());
    }
    names
}

fn load_attestations_from_dir(dir: &std::path::Path) -> Result<Vec<Attestation>> {
    let mut attestations = Vec::new();
    if !dir.exists() {
        return Ok(attestations);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext == "attest" || path.to_string_lossy().ends_with(".erebus.attest") {
            let data = std::fs::read(&path)?;
            if let Ok(att) = serde_json::from_slice::<Attestation>(&data) {
                attestations.push(att);
            }
        }
    }
    Ok(attestations)
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

fn load_trusted_keys(dir: &PathBuf) -> Result<Vec<(PathBuf, ed25519_dalek::VerifyingKey)>> {
    use ed25519_dalek::VerifyingKey;
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
