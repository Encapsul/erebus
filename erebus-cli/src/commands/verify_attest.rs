//! `erebus verify-attest` — verify execution receipts.
//!
//! Single receipt: Ed25519 signature over the in-toto statement, key
//! fingerprint, and consistency of the unsigned display fields with the signed
//! statement. `--bundle` additionally binds the receipt to a real file.
//! `--chain <dir>` verifies a whole hash-chained trail (see
//! `erebus_core::attest_log`). Every reported value is read from the **signed**
//! statement, never from the unsigned copies. `--proof` additionally checks
//! the registry transparency-log proof stored by `erebus attest --push`
//! (`<receipt>.proof.json`) — inclusion, signed checkpoint, TSA anchor —
//! entirely offline. `--strict` additionally demands a spec 2.0 receipt
//! co-signed by an enrolled machine key certified by a trusted registry.

use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use erebus_core::attest::{check_bundle_matches, verify_attestation, Attestation};
use erebus_core::attest_log::AttestationLog;
use erebus_core::paths::trusted_keys_dir;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct VerifyAttestArgs {
    /// Path to a .erebus.attest receipt (omit when using --chain)
    #[arg(required_unless_present = "chain")]
    pub attest_file: Option<PathBuf>,

    /// Verify a whole hash-chained trail directory (<bundle>.attest.d)
    #[arg(long, value_name = "DIR", conflicts_with = "attest_file")]
    pub chain: Option<PathBuf>,

    /// Bundle the receipt(s) must cover: its SHA-256 is compared to the
    /// signed bundle digest
    #[arg(long, value_name = "FILE")]
    pub bundle: Option<PathBuf>,

    /// Directory containing trusted public keys
    #[arg(long)]
    pub trusted_dir: Option<PathBuf>,

    /// Also verify the transparency-log proof (`<receipt>.proof.json`)
    #[arg(long, conflicts_with = "chain")]
    pub proof: bool,

    /// Explicit proof file (implies --proof)
    #[arg(long, value_name = "FILE", conflicts_with = "chain")]
    pub proof_file: Option<PathBuf>,

    /// Registry public key (64 hex chars) to trust for the log checkpoint
    /// and machine certificates, in addition to `.pub` files in the trusted
    /// dir
    #[arg(long, value_name = "HEX", visible_alias = "registry-key")]
    pub log_key: Option<String>,

    /// Require a machine co-signature: spec 2.0 receipt, signed by an
    /// enrolled machine key whose certificate comes from a trusted registry
    #[arg(long, conflicts_with = "chain")]
    pub strict: bool,

    /// Output verification result as JSON
    #[arg(long)]
    pub json: bool,

    /// Write JSON output to file (requires --json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: VerifyAttestArgs) -> Result<()> {
    let trusted_dir = args.trusted_dir.clone().unwrap_or_else(trusted_keys_dir);
    let keys = load_trusted_keys(&trusted_dir)?;
    if keys.is_empty() {
        anyhow::bail!(
            "no trusted keys in {} — add keys with: erebus trust <pubkey_file>",
            trusted_dir.display()
        );
    }
    let bundle_bytes = args
        .bundle
        .as_ref()
        .map(|p| std::fs::read(p).with_context(|| format!("failed to read bundle {}", p.display())))
        .transpose()?;

    let mut report = match (&args.chain, &args.attest_file) {
        (Some(dir), _) => verify_chain(dir, &keys, bundle_bytes.as_deref())?,
        (None, Some(file)) => verify_single(file, &keys, bundle_bytes.as_deref())?,
        (None, None) => anyhow::bail!("provide a receipt path or --chain <dir>"),
    };
    let mut registry_keys = keys.clone();
    if let Some(hex_key) = &args.log_key {
        registry_keys.push(parse_log_key(hex_key)?);
    }
    if args.strict {
        let file = args
            .attest_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--strict needs a receipt path"))?;
        report["machine"] = verify_strict(file, &registry_keys)?;
    }
    if args.proof || args.proof_file.is_some() {
        let file = args
            .attest_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--proof needs a receipt path"))?;
        let log_keys = registry_keys;
        let proof_path = args
            .proof_file
            .clone()
            .unwrap_or_else(|| super::attest::proof_path_for(file));
        report["log_proof"] = verify_log_proof(file, &proof_path, &log_keys)?;
    }

    if args.json {
        let json_str = serde_json::to_string_pretty(&report)?;
        if let Some(path) = args.output {
            std::fs::write(&path, &json_str)
                .with_context(|| format!("failed to write to {}", path.display()))?;
            eprintln!("Wrote JSON to {}", path.display());
        } else {
            println!("{json_str}");
        }
    } else {
        print_human(&report);
    }
    Ok(())
}

fn verify_single(
    file: &Path,
    keys: &[VerifyingKey],
    bundle_bytes: Option<&[u8]>,
) -> Result<serde_json::Value> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let attestation: Attestation = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", file.display()))?;

    let vk = verify_attestation(&attestation, keys).context("attestation verification failed")?;
    if let Some(bytes) = bundle_bytes {
        check_bundle_matches(&attestation, bytes).context("attestation verification failed")?;
    }

    let exec = signed_execution(&attestation);
    Ok(serde_json::json!({
        "file": file.display().to_string(),
        "verified": true,
        "mode": "single",
        "key": hex::encode(vk.as_bytes()),
        "spec_version": attestation.spec_version,
        "envelope": attestation.envelope.is_some(),
        "machine_id": attestation.machine.as_ref().map(|m| m.machine_id.clone()),
        "attestation_type": attestation.attestation_type,
        "bundle_sha256": signed_subject(&attestation, "bundle"),
        "bundle_checked": bundle_bytes.is_some(),
        "execution": exec,
    }))
}

/// `--strict`: machine co-signature + registry certificate (see
/// `erebus_core::machine::verify_machine`).
fn verify_strict(file: &Path, registry_keys: &[VerifyingKey]) -> Result<serde_json::Value> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let attestation: Attestation = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", file.display()))?;
    let report = erebus_core::machine::verify_machine(&attestation, registry_keys)
        .context("strict verification failed")?;
    Ok(serde_json::json!({
        "verified": true,
        "machine_id": report.machine_id,
        "owner": report.owner,
        "registry": report.registry,
        "issued_at": report.issued_at,
    }))
}

/// Offline check of `<receipt>.proof.json`; the receipt's exact bytes are
/// the leaf preimage, so a re-serialized receipt fails here on purpose.
fn verify_log_proof(
    receipt: &Path,
    proof_path: &Path,
    log_keys: &[VerifyingKey],
) -> Result<serde_json::Value> {
    let receipt_bytes =
        std::fs::read(receipt).with_context(|| format!("failed to read {}", receipt.display()))?;
    let proof_json = std::fs::read(proof_path).with_context(|| {
        format!(
            "failed to read proof {} (push the receipt with `erebus attest --push` first)",
            proof_path.display()
        )
    })?;
    let proof: erebus_core::log_proof::LogProof = serde_json::from_slice(&proof_json)
        .with_context(|| format!("failed to parse {}", proof_path.display()))?;
    let report = erebus_core::log_proof::verify_proof(&receipt_bytes, &proof, log_keys)
        .context("transparency-log proof verification failed")?;
    let mut value = serde_json::to_value(&report)?;
    value["file"] = serde_json::Value::String(proof_path.display().to_string());
    value["registry"] = serde_json::Value::String(proof.registry.clone());
    value["verified"] = serde_json::Value::Bool(true);
    Ok(value)
}

fn parse_log_key(hex_key: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("--log-key must be 64 hex characters"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("--log-key invalid: {e}"))
}

fn verify_chain(
    dir: &Path,
    keys: &[VerifyingKey],
    bundle_bytes: Option<&[u8]>,
) -> Result<serde_json::Value> {
    let log = AttestationLog::open(dir)
        .with_context(|| format!("failed to open trail {}", dir.display()))?;
    let report = log
        .verify_chain(keys, bundle_bytes)
        .context("attestation chain verification failed")?;
    Ok(serde_json::json!({
        "dir": dir.display().to_string(),
        "verified": true,
        "mode": "chain",
        "count": report.count,
        "head": report.head,
        "bundle_checked": bundle_bytes.is_some(),
    }))
}

/// The `execution` block of the signed predicate (never the unsigned copy).
fn signed_execution(att: &Attestation) -> serde_json::Value {
    att.statement
        .predicate
        .get("execution")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

fn signed_subject(att: &Attestation, name: &str) -> Option<String> {
    att.statement
        .subject
        .iter()
        .find(|s| s.name == name)
        .and_then(|s| s.digest.get("sha256").cloned())
}

fn print_human(report: &serde_json::Value) {
    let s = |k: &str| {
        report
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string()
    };
    if report.get("mode").and_then(|v| v.as_str()) == Some("chain") {
        eprintln!(
            "OK: chain verified — {} receipt(s) in {}",
            report.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
            s("dir")
        );
        eprintln!("  head:    {}", s("head"));
    } else {
        eprintln!("OK: attestation verified (key: {})", s("key"));
        eprintln!("  type:     {}", s("attestation_type"));
        eprintln!("  bundle:   sha256:{}", s("bundle_sha256"));
        let exec = report.get("execution").cloned().unwrap_or_default();
        let e = |k: &str| {
            exec.get(k)
                .filter(|v| !v.is_null())
                .map(|v| v.to_string().trim_matches('"').to_string())
                .unwrap_or_else(|| "-".to_string())
        };
        eprintln!("  attested: {}", e("attested_at"));
        eprintln!("  os/arch:  {}/{}", e("os"), e("arch"));
        // Proxy receipts describe an HTTP call; run receipts an exit code.
        if let Some(req) = exec.get("request").filter(|v| v.is_object()) {
            let r = |k: &str| {
                req.get(k).map_or("-".to_string(), |v| {
                    v.to_string().trim_matches('"').to_string()
                })
            };
            eprintln!(
                "  call:     {} {} → {}",
                r("method"),
                r("path"),
                r("status")
            );
            eprintln!("  request:  {}", e("input_hash"));
            eprintln!("  response: {}", e("output_hash"));
        } else {
            eprintln!("  exit:     {}", e("exit_code"));
            eprintln!("  output:   {}", e("output_hash"));
        }
        eprintln!("  prev:     {}", e("prev_attestation_hash"));
        if exec.get("rootfs_root").is_some_and(|v| !v.is_null()) {
            eprintln!("  rootfs:   {}", e("rootfs_root"));
        }
        eprintln!(
            "  format:   spec {}{}",
            s("spec_version"),
            if report.get("envelope") == Some(&serde_json::Value::Bool(true)) {
                " (DSSE envelope)"
            } else {
                " (legacy signature)"
            }
        );
    }
    if let Some(m) = report.get("machine").filter(|m| m.is_object()) {
        let ms = |k: &str| m.get(k).and_then(|v| v.as_str()).unwrap_or("?");
        eprintln!(
            "OK: machine {} — enrolled by {} at {} ({})",
            ms("machine_id"),
            ms("owner"),
            ms("registry"),
            ms("issued_at")
        );
    }
    if report.get("bundle_checked") == Some(&serde_json::Value::Bool(true)) {
        eprintln!("  bundle file matches the signed digest");
    }
    if let Some(lp) = report.get("log_proof") {
        print_log_proof(lp);
    }
}

fn print_log_proof(lp: &serde_json::Value) {
    let s = |k: &str| {
        lp.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string()
    };
    let n = |k: &str| lp.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
    eprintln!(
        "OK: transparency log — leaf #{} of {} at {} ({})",
        n("leaf_index"),
        n("tree_size"),
        s("registry"),
        s("origin")
    );
    eprintln!("  root:     {}", s("root"));
    eprintln!(
        "  signed:   {} by log key {}",
        s("checkpoint_time"),
        s("log_key")
    );
    match lp.get("anchor").filter(|a| a.is_object()) {
        Some(a) => {
            let gen = a
                .get("gen_time")
                .and_then(|v| v.as_str())
                .unwrap_or("time not parsed");
            eprintln!(
                "  anchor:   RFC 3161 token from {} ({}; structural check only — run \
                 `openssl ts -verify` with the TSA chain for the CMS signature)",
                a.get("tsa_url").and_then(|v| v.as_str()).unwrap_or("?"),
                gen
            );
        }
        None => eprintln!("  anchor:   none (checkpoint not timestamped externally)"),
    }
}

fn load_trusted_keys(dir: &Path) -> Result<Vec<VerifyingKey>> {
    let mut keys = Vec::new();
    if !dir.exists() {
        return Ok(keys);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "pub") {
            let key_bytes = std::fs::read(&path)?;
            if let Ok(arr) = <[u8; 32]>::try_from(key_bytes.as_slice()) {
                if let Ok(vk) = VerifyingKey::from_bytes(&arr) {
                    keys.push(vk);
                }
            }
        }
    }
    Ok(keys)
}
