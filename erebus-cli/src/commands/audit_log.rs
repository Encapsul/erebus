use anyhow::{Context, Result};
use clap::Args;
use reqwest::blocking::Client;
use std::io::Write;
use std::path::PathBuf;

#[derive(Args)]
pub struct AuditLogArgs {
    /// Registry base URL (e.g. <https://registry.erebus.io>)
    #[arg(long)]
    pub registry: String,

    /// Month to download (YYYY-MM)
    #[arg(long)]
    pub month: String,

    /// Filter by org name (optional)
    #[arg(long)]
    pub org: Option<String>,

    /// Auth bearer token
    #[arg(long)]
    pub token: Option<String>,

    /// Output file (defaults to stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: AuditLogArgs) -> Result<()> {
    let mut url = format!("{}/audit/download?month={}", args.registry, args.month);
    if let Some(org) = args.org {
        url.push_str(&format!("&org={}", urlencoding::encode(&org)));
    }

    let client = Client::builder().user_agent("erebus-cli/0.5.0").build()?;

    let mut req = client.get(&url);
    if let Some(token) = args.token {
        req = req.bearer_auth(token);
    }

    let resp = req.send().context("failed to contact registry")?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "registry returned {}: {}",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }

    let body = resp.bytes().context("failed to read response body")?;

    match args.output {
        Some(path) => {
            std::fs::write(&path, &body)
                .with_context(|| format!("failed to write {}", path.display()))?;
            eprintln!("wrote {} bytes to {}", body.len(), path.display());
        }
        None => {
            std::io::stdout()
                .write_all(&body)
                .context("failed to write to stdout")?;
        }
    }

    Ok(())
}
