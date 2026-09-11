//! `erebus attest-history` — query your execution attestation trail.
//!
//! Registry contract (matches the `/attestations` POST in `erebus attest`):
//!   GET {registry}/attestations?bundle=&machine=&since=&until=&limit=&skip=
//!       Authorization: Bearer <token>
//!   → {"owner": str, "total": int, "records": [{`id`, `attested_at`, `bundle`,
//!      `machine`, `os`, `arch`, `key_fp`, `attestation`: {...}}]}
//!
//! A caller can only ever read back records it published (fail-closed
//! personal trail) — the registry never exposes other accounts' history.

use anyhow::{bail, Context, Result};
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct AttestHistoryArgs {
    /// Query filter: comma-separated `k=v` pairs.
    ///
    /// Keys: bundle (full sha256:… hash), machine (full sha256:… hash),
    /// since / until (ISO-8601 `attested_at` bounds). Example:
    ///   erebus attest-history --query 'bundle=sha256:abc…,until=2026-09-30'
    #[arg(long, value_name = "SPEC", default_value = "")]
    pub query: String,

    /// Registry base URL
    #[arg(long, env = "ERE_REGISTRY")]
    pub registry: Option<String>,

    /// Bearer token sent on every request (prefer --token-file for secrets)
    #[arg(long, env = "ERE_TOKEN")]
    pub token: Option<String>,

    /// Path to a file containing the bearer token (preferred over --token)
    #[arg(long)]
    pub token_file: Option<PathBuf>,

    /// Maximum number of records to return
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    /// Number of records to skip (pagination)
    #[arg(long, default_value_t = 0)]
    pub skip: usize,

    /// Print the raw JSON response instead of the human summary
    #[arg(long)]
    pub json: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AttestationPage {
    owner: String,
    total: usize,
    records: Vec<serde_json::Value>,
}

pub fn run(args: AttestHistoryArgs) -> Result<()> {
    let registry = args.registry.clone().ok_or_else(|| {
        anyhow::anyhow!("registry URL is required (--registry or ERE_REGISTRY env var)")
    })?;
    let registry = registry.trim_end_matches('/').to_string();
    let token = resolve_token(args.token.as_deref(), args.token_file.as_deref())?;

    let filters = parse_query(&args.query)?;
    let mut url = format!(
        "{registry}/attestations?limit={}&skip={}",
        args.limit, args.skip
    );
    for (key, value) in [
        ("bundle", &filters.bundle),
        ("machine", &filters.machine),
        ("since", &filters.since),
        ("until", &filters.until),
    ] {
        if let Some(v) = value {
            url.push('&');
            url.push_str(key);
            url.push('=');
            url.push_str(&urlencode(v));
        }
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;
    let mut req = client.get(&url);
    if let Some(ref t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let page: AttestationPage = req
        .send()
        .context("failed to reach registry")?
        .error_for_status()
        .context("registry returned an error for /attestations")?
        .json()
        .context("invalid registry /attestations JSON")?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&page)?);
    } else {
        println!("{} attestation(s) for {}", page.total, page.owner);
        for rec in &page.records {
            let id = rec.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let at = rec
                .get("attested_at")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let bundle = rec.get("bundle").and_then(|v| v.as_str()).unwrap_or("?");
            let machine = rec.get("machine").and_then(|v| v.as_str()).unwrap_or("?");
            let os = rec.get("os").and_then(|v| v.as_str()).unwrap_or("?");
            let arch = rec.get("arch").and_then(|v| v.as_str()).unwrap_or("?");
            println!("  {id}  {at}  {os}/{arch}");
            println!("      bundle:  {}", short_hash(bundle));
            println!("      machine: {}", short_hash(machine));
        }
    }
    Ok(())
}

struct Filters {
    bundle: Option<String>,
    machine: Option<String>,
    since: Option<String>,
    until: Option<String>,
}

/// Parse `k=v,k=v` into filters. Unknown keys are rejected so a typo cannot
/// silently widen into "everything".
fn parse_query(spec: &str) -> Result<Filters> {
    let mut out = Filters {
        bundle: None,
        machine: None,
        since: None,
        until: None,
    };
    for pair in spec.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("query must be k=v pairs separated by commas, got: {pair}")
        })?;
        let value = value.trim();
        if value.is_empty() {
            bail!("query key {key} has an empty value");
        }
        match key.trim() {
            "bundle" => out.bundle = Some(value.to_string()),
            "machine" => out.machine = Some(value.to_string()),
            "since" => out.since = Some(value.to_string()),
            "until" => out.until = Some(value.to_string()),
            other => bail!("unknown query key '{other}' (expected bundle|machine|since|until)"),
        }
    }
    Ok(out)
}

fn short_hash(h: &str) -> &str {
    // "sha256:0123abcd…" → "sha256:0123abcd…" truncated for the summary line.
    h.get(..h.len().min(72)).unwrap_or(h)
}

fn urlencode(s: &str) -> String {
    urlencoding::encode(s).into_owned()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parses_full_spec() {
        let f =
            parse_query("bundle=sha256:aa, machine=sha256:bb, since=2026-01-01,until=2026-12-31")
                .unwrap();
        assert_eq!(f.bundle.as_deref(), Some("sha256:aa"));
        assert_eq!(f.machine.as_deref(), Some("sha256:bb"));
        assert_eq!(f.since.as_deref(), Some("2026-01-01"));
        assert_eq!(f.until.as_deref(), Some("2026-12-31"));
    }

    #[test]
    fn query_rejects_unknown_key() {
        assert!(parse_query("package=foo").is_err());
        assert!(parse_query("bundle=sha256:aa,owner=alice").is_err());
    }

    #[test]
    fn query_rejects_malformed_pair() {
        assert!(parse_query("bundleonly").is_err());
        assert!(parse_query("bundle=").is_err());
    }

    #[test]
    fn query_empty_means_no_filters() {
        let f = parse_query("").unwrap();
        assert!(f.bundle.is_none() && f.machine.is_none());
    }
}
