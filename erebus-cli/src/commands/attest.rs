use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::SigningKey;
use erebus_core::attest::generate_attestation;
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

    let attestation =
        generate_attestation(&args.file, &signing_key).context("failed to generate attestation")?;

    let output_path = args
        .output
        .unwrap_or_else(|| args.file.with_extension("erebus.attest"));

    let json_bytes =
        serde_json::to_vec_pretty(&attestation).context("failed to serialize attestation")?;
    std::fs::write(&output_path, &json_bytes)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "file": args.file.display().to_string(),
                "attestation": output_path.display().to_string(),
                "signed": true,
                "key": key_path.display().to_string(),
            }))?
        );
    } else if !args.quiet {
        eprintln!("Attested {}", args.file.display());
        eprintln!("  output: {}", output_path.display());
        eprintln!("  key:    {}", key_path.display());
    }

    if args.push {
        let registry = args.registry.clone().ok_or_else(|| {
            anyhow::anyhow!("--push requires --registry (or ERE_REGISTRY env var)")
        })?;
        let registry = registry.trim_end_matches('/').to_string();
        let token = resolve_token(args.token.as_deref(), args.token_file.as_deref())?;
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client")?;
        let mut req = client
            .post(format!("{registry}/attestations"))
            .header("Content-Type", "application/json")
            .body(json_bytes.clone());
        if let Some(ref t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let resp = req
            .send()
            .context("failed to reach registry")?
            .error_for_status()
            .with_context(|| format!("registry rejected attestation at {registry}"))?;
        let status = resp.status();
        let body: serde_json::Value = resp.json().context("invalid registry response")?;
        let id = body.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": id,
                    "status": status.as_u16(),
                    "recorded": body.get("recorded"),
                }))?
            );
        } else if !args.quiet {
            eprintln!("Pushed attestation to {registry}");
            eprintln!("  id:      {}", id);
            eprintln!("  status:  {}", status);
        }
    }

    Ok(())
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

fn resolve_token(
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
