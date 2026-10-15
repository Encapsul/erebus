use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use reqwest::blocking::Client;

#[derive(Args)]
pub struct BillingArgs {
    #[command(subcommand)]
    pub command: BillingCommand,
}

#[derive(Subcommand)]
pub enum BillingCommand {
    /// Show current billing tier and quota
    Status {
        /// Registry base URL (e.g. <https://registry.erebus.io>)
        #[arg(long)]
        registry: String,

        /// File containing the registry bearer token (`ERE_TOKEN` otherwise)
        #[arg(long)]
        token_file: Option<std::path::PathBuf>,
    },
    /// Start a Stripe Checkout session for a paid plan
    Checkout {
        /// Registry base URL (e.g. <https://registry.erebus.io>)
        #[arg(long)]
        registry: String,

        /// Plan to subscribe to (pro or team)
        #[arg(long)]
        plan: String,

        /// File containing the registry bearer token (`ERE_TOKEN` otherwise)
        #[arg(long)]
        token_file: Option<std::path::PathBuf>,

        /// Open checkout URL in browser
        #[arg(long)]
        open: bool,
    },
}

pub fn run(args: BillingArgs) -> Result<()> {
    match args.command {
        BillingCommand::Status {
            registry,
            token_file,
        } => {
            let token = super::attest::resolve_token(token_file.as_deref())?;
            status(&registry, token.as_deref())
        }
        BillingCommand::Checkout {
            registry,
            plan,
            token_file,
            open,
        } => {
            let token = super::attest::resolve_token(token_file.as_deref())?;
            checkout(&registry, &plan, token.as_deref(), open)
        }
    }
}

fn status(registry: &str, token: Option<&str>) -> Result<()> {
    let url = format!("{}/billing/status", registry);
    let client = Client::builder()
        .user_agent(concat!("erebus-cli/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut req = client.get(&url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let resp = req.send().context("failed to contact registry")?;
    if !resp.status().is_success() {
        bail!(
            "registry returned {}: {}",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }
    let body = resp.text().context("failed to read response body")?;
    println!("{}", body);
    Ok(())
}

fn checkout(registry: &str, plan: &str, token: Option<&str>, open: bool) -> Result<()> {
    let url = format!("{}/billing/checkout", registry);
    let client = Client::builder()
        .user_agent(concat!("erebus-cli/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let resp = client
        .post(&url)
        .bearer_auth(token.unwrap_or_default())
        .json(&serde_json::json!({"plan": plan}))
        .send()
        .context("failed to contact registry")?;
    if !resp.status().is_success() {
        bail!(
            "registry returned {}: {}",
            resp.status(),
            resp.text().unwrap_or_default()
        );
    }
    let body: serde_json::Value = resp.json().context("failed to parse response")?;
    let checkout_url = body["url"].as_str().unwrap_or_default();
    if checkout_url.is_empty() {
        bail!("registry did not return a checkout URL");
    }
    println!("Checkout URL: {}", checkout_url);
    if open {
        if let Err(e) = open_checkout(checkout_url) {
            eprintln!("warning: could not open browser: {}", e);
        }
    }
    Ok(())
}

fn open_checkout(url: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).status()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).status()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .status()?;
    }
    Ok(())
}
