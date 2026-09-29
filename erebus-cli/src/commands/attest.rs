use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::SigningKey;
use erebus_core::attest::{
    generate_attestation, generate_attestation_with_capture, host_machine, receipt_bytes,
    ExecutionCapture,
};
use erebus_core::attest_log::{default_log_dir, AttestationLog};
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

    /// Hash-chained trail directory to append the receipt to
    /// (defaults to <output>.d; the receipt's previous-hash link points at
    /// the trail head and is covered by the signature)
    #[arg(long, value_name = "DIR")]
    pub log: Option<PathBuf>,

    /// Do not append the receipt to a trail (latest file only)
    #[arg(long, conflicts_with = "log")]
    pub no_log: bool,

    /// Push the attestation to a registry (needs --registry + a token)
    #[arg(long)]
    pub push: bool,

    /// Registry base URL (for --push)
    #[arg(long, env = "ERE_REGISTRY")]
    pub registry: Option<String>,

    /// Bearer token sent to the registry (prefer --token-file for secrets)
    #[arg(long, env = "ERE_TOKEN")]
    pub token: Option<String>,

    /// Path to a file containing the bearer token (preferred over --token)
    #[arg(long)]
    pub token_file: Option<PathBuf>,

    /// Also write the bare DSSE envelope (in-toto payload) to FILE — the
    /// interchange form for cosign / in-toto / Sigstore tooling
    #[arg(long, value_name = "FILE")]
    pub envelope: Option<PathBuf>,

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

    let output_path = args
        .output
        .unwrap_or_else(|| args.file.with_extension("erebus.attest"));

    let log = if args.no_log {
        None
    } else {
        let dir = args.log.unwrap_or_else(|| default_log_dir(&output_path));
        Some(
            AttestationLog::open(&dir)
                .with_context(|| format!("failed to open trail {}", dir.display()))?,
        )
    };

    // The trail head must be folded into the signed statement, so chaining
    // happens at generation time rather than as a post-hoc append.
    let (attestation, entry) = match &log {
        Some(log) => {
            let capture = ExecutionCapture {
                prev_attestation_hash: log.head()?,
                ..ExecutionCapture::default()
            };
            let att = generate_attestation_with_capture(&args.file, &signing_key, &capture)
                .context("failed to generate attestation")?;
            let entry = log.append(&att).context("failed to append to trail")?;
            (att, Some(entry))
        }
        None => (
            generate_attestation(&args.file, &signing_key)
                .context("failed to generate attestation")?,
            None,
        ),
    };

    let json_bytes = receipt_bytes(&attestation).context("failed to serialize attestation")?;
    std::fs::write(&output_path, &json_bytes)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    if let Some(env_path) = &args.envelope {
        let envelope = attestation
            .envelope
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("receipt has no DSSE envelope"))?;
        std::fs::write(env_path, serde_json::to_vec(envelope)?)
            .with_context(|| format!("failed to write {}", env_path.display()))?;
    }
    let machine_id = attestation.machine.as_ref().map(|m| m.machine_id.clone());

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": args.file.display().to_string(),
                "attestation": output_path.display().to_string(),
                "trail_entry": entry.as_ref().map(|p| p.display().to_string()),
                "prev_attestation_hash": attestation.execution.prev_attestation_hash,
                "signed": true,
                "key": key_path.display().to_string(),
                "spec_version": attestation.spec_version,
                "envelope": args.envelope.as_ref().map(|p| p.display().to_string()),
                "machine_id": machine_id,
            }))?
        );
    } else if !args.quiet {
        eprintln!("Attested {}", args.file.display());
        eprintln!("  output: {}", output_path.display());
        if let Some(entry) = &entry {
            eprintln!("  trail:  {}", entry.display());
        }
        eprintln!("  key:    {}", key_path.display());
        if let Some(p) = &args.envelope {
            eprintln!("  dsse:   {}", p.display());
        }
        match &machine_id {
            Some(id) => eprintln!("  machine: {id} (co-signed)"),
            None if host_machine().is_none() => {
                eprintln!("  machine: not enrolled (run `erebus enroll` for --strict receipts)");
            }
            None => {}
        }
    }

    if args.push {
        let registry = args.registry.clone().ok_or_else(|| {
            anyhow::anyhow!("--push requires --registry (or ERE_REGISTRY env var)")
        })?;
        let registry = registry.trim_end_matches('/').to_string();
        let token = resolve_token(args.token.as_deref(), args.token_file.as_deref())?;
        let published = publish_receipt(&registry, token.as_deref(), &output_path, &json_bytes)?;
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": published.id,
                    "status": published.status,
                    "recorded": published.body.get("recorded"),
                    "proof": published.proof.as_ref().map(|p| p.display().to_string()),
                    "log": published.body.get("log"),
                }))?
            );
        } else if !args.quiet {
            eprintln!("Pushed attestation to {registry}");
            eprintln!("  id:      {}", published.id);
            eprintln!("  status:  {}", published.status);
            match (&published.proof, published.body.get("log")) {
                (Some(p), Some(log)) => {
                    eprintln!(
                        "  log:     leaf #{} of {} (root {})",
                        log["leaf_index"],
                        log["tree_size"],
                        log["root"].as_str().unwrap_or("?")
                    );
                    if log.get("anchor").is_some_and(|a| !a.is_null()) {
                        eprintln!("  anchor:  RFC 3161 token stored");
                    }
                    eprintln!("  proof:   {}", p.display());
                }
                _ => eprintln!("  proof:   none (registry predates the transparency log)"),
            }
        }
    }

    Ok(())
}

/// Result of publishing an existing receipt to a registry.
pub(crate) struct PublishedReceipt {
    pub id: String,
    pub status: u16,
    pub proof: Option<PathBuf>,
    pub body: serde_json::Value,
}

/// Publish byte-exact receipt data and persist only a locally verified proof.
///
/// Shared by `attest --push` and the attesting inference proxy: this is the
/// single fail-closed path from a local receipt to the transparency log.
pub(crate) fn publish_receipt(
    registry: &str,
    token: Option<&str>,
    receipt_path: &std::path::Path,
    receipt_bytes: &[u8],
) -> Result<PublishedReceipt> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;
    let mut req = client
        .post(format!("{registry}/attestations"))
        .header("Content-Type", "application/json")
        .body(receipt_bytes.to_vec());
    if let Some(token) = token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let resp = req.send().context("failed to reach registry")?;
    let status = resp.status();
    let body = parse_publish_response(resp, registry)?;
    let proof = store_proof(registry, &body, receipt_path, receipt_bytes)?;
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .into();
    Ok(PublishedReceipt {
        id,
        status: status.as_u16(),
        proof,
        body,
    })
}

fn parse_publish_response(
    resp: reqwest::blocking::Response,
    registry: &str,
) -> Result<serde_json::Value> {
    resp.error_for_status()
        .with_context(|| format!("registry rejected attestation at {registry}"))?
        .json()
        .context("invalid registry response")
}

/// Conventional proof location: `<receipt>.proof.json`.
pub fn proof_path_for(receipt: &std::path::Path) -> PathBuf {
    let mut name = receipt
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push_str(".proof.json");
    receipt.with_file_name(name)
}

/// Verify the registry's proof against the bytes we just sent before
/// persisting it — a registry returning a proof for another leaf would
/// otherwise be stored as evidence.
pub(crate) fn store_proof(
    registry: &str,
    body: &serde_json::Value,
    receipt_path: &std::path::Path,
    receipt_bytes: &[u8],
) -> Result<Option<PathBuf>> {
    let Some(log) = body.get("log").filter(|l| !l.is_null()) else {
        return Ok(None);
    };
    let proof = erebus_core::log_proof::from_registry_response(registry, log)?;
    let signer = proof.checkpoint.verify_signature()?;
    erebus_core::log_proof::verify_proof(receipt_bytes, &proof, &[signer])
        .context("registry returned a proof that does not verify")?;
    let path = proof_path_for(receipt_path);
    std::fs::write(&path, serde_json::to_vec_pretty(&proof)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(Some(path))
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

pub fn resolve_token(
    token: Option<&str>,
    token_file: Option<&std::path::Path>,
) -> Result<Option<String>> {
    if let Some(path) = token_file {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read token file {}", path.display()))?;
        return Ok(Some(content.trim().to_string()));
    }
    Ok(token
        .map(String::from)
        .or_else(|| std::env::var("ERE_TOKEN").ok()))
}
