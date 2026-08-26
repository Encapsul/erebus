use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct PublishArgs {
    /// Path to the .erebus file to publish
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Registry URL to upload to (required, cannot use placeholder)
    #[arg(long, env = "ERE_REGISTRY")]
    pub registry: Option<String>,

    /// Authentication token for the registry (prefer --token-file for secrets)
    #[arg(long, env = "ERE_TOKEN")]
    pub token: Option<String>,

    /// Path to a file containing the authentication token (preferred over --token)
    #[arg(long)]
    pub token_file: Option<PathBuf>,

    /// Skip upload, just validate the file and print info
    #[arg(long)]
    pub dry_run: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Output result as JSON
    #[arg(long)]
    pub json: bool,
}

const DEFAULT_REGISTRY_PLACEHOLDER: &str = "https://erebus.example.com";

pub fn run(args: PublishArgs) -> Result<()> {
    let file = args.file.canonicalize().context("failed to find file")?;

    if file.extension().is_none_or(|e| e != "erebus") {
        anyhow::bail!(
            "{} is not a .erebus file (expected .erebus extension)",
            file.display()
        );
    }

    let meta_size = file
        .metadata()
        .context("failed to read file metadata")?
        .len();

    // Registry URL is mandatory - no placeholder allowed as default
    let registry = match &args.registry {
        Some(url) => url.clone(),
        None => {
            anyhow::bail!("registry URL is required (use --registry or ERE_REGISTRY env var)")
        }
    };

    // Reject placeholder URLs that would result in a non-functional upload
    if registry.contains(DEFAULT_REGISTRY_PLACEHOLDER) {
        anyhow::bail!(
            "cannot use placeholder registry URL '{}'; please provide a valid registry endpoint with --registry or ERE_REGISTRY",
            DEFAULT_REGISTRY_PLACEHOLDER
        );
    }

    if args.verbose {
        eprintln!("[erebus] publish: {}", file.display());
        eprintln!("  size: {meta_size} bytes");
        eprintln!("  registry: {}", registry);
    }

    if args.dry_run {
        eprintln!("Would publish {} to {}", file.display(), registry);
        return Ok(());
    }

    let token = resolve_token(args.token.as_deref(), args.token_file.as_deref())?;

    eprintln!(
        "Publishing {}...",
        file.file_name().unwrap_or_default().to_string_lossy()
    );

    let content = std::fs::read(&file).context("failed to read .erebus file")?;

    // Build the multipart upload request using reqwest (blocking).
    // The part MUST carry a filename: registries derive the stored package
    // name from Content-Disposition's filename field.
    let upload_name = file
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .context("bundle path has no file name")?;
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .context("failed to create HTTP client")?;

    let part = reqwest::blocking::multipart::Part::bytes(content)
        .file_name(upload_name)
        .mime_str("application/octet-stream")
        .context("invalid mime type")?;
    let form = reqwest::blocking::multipart::Form::new().part("file", part);

    let mut request = client.post(&registry).multipart(form);

    if let Some(ref t) = token {
        request = request.header("Authorization", format!("Bearer {t}"));
    }

    let response = request.send().context("failed to upload .erebus file")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().unwrap_or_default();
        anyhow::bail!("upload failed (HTTP {status}): {body}");
    }

    eprintln!("  Upload complete (HTTP {})", response.status());
    if args.json {
        let info = serde_json::json!({
            "file": file.display().to_string(),
            "registry": registry,
            "status": response.status().as_u16(),
            "size_bytes": meta_size,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    }
    Ok(())
}

/// Resolve token from `--token-file`, `--token` flag, or `ERE_TOKEN` env var.
/// `--token-file` takes precedence (clig.dev: secrets via files, not flags).
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
