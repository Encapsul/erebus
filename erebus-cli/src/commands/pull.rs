//! `erebus pull` — download a bundle from a registry with integrity checks.
//!
//! Registry contract (matches `erebus publish` uploads):
//!   GET  {registry}/index.json     → {"packages":[{name,version,sha256,size,file}]}
//!   GET  {registry}/packages/{file}
//!
//! Downloads stream to the local cache, verify SHA-256 against the index,
//! and land executable so `erebus serve <name>` works immediately.

use anyhow::{bail, Context, Result};
use clap::Args;
use sha2::Digest;
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Args)]
pub struct PullArgs {
    /// Package name as listed in the registry index
    pub name: String,

    /// Registry base URL
    #[arg(long, env = "ERE_REGISTRY")]
    pub registry: Option<String>,

    /// Bearer token sent on every request (prefer --token-file for secrets)
    #[arg(long, env = "ERE_TOKEN")]
    pub token: Option<String>,

    /// Path to a file containing the bearer token (preferred over --token)
    #[arg(long)]
    pub token_file: Option<PathBuf>,

    /// Write to this path instead of the shared pull cache
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Print the destination path only (no download if already cached)
    #[arg(long)]
    pub check: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Output result as JSON
    #[arg(long)]
    pub json: bool,
}

/// Package names become path components — lock them down hard.
fn validate_name(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ':'));
    if ok {
        Ok(())
    } else {
        bail!("invalid package name '{name}': allowed [A-Za-z0-9._:-], max 128 chars");
    }
}

#[derive(serde::Deserialize)]
struct Index {
    #[serde(default)]
    packages: Vec<IndexEntry>,
}

#[derive(serde::Deserialize)]
struct IndexEntry {
    name: String,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    file: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    size: u64,
}

pub fn run(args: PullArgs) -> Result<()> {
    validate_name(&args.name)?;
    let registry = args.registry.clone().ok_or_else(|| {
        anyhow::anyhow!("registry URL is required (--registry or ERE_REGISTRY env var)")
    })?;
    let registry = registry.trim_end_matches('/').to_string();
    let token = resolve_token(args.token.as_deref(), args.token_file.as_deref())?;

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .context("failed to build HTTP client")?;
    let mut req = client.get(format!("{registry}/index.json"));
    if let Some(ref t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let index: Index = req
        .send()
        .context("failed to reach registry")?
        .error_for_status()
        .context("registry returned an error for /index.json")?
        .json()
        .context("invalid registry index JSON")?;

    let entry = index
        .packages
        .iter()
        .find(|p| p.name == args.name)
        .with_context(|| format!("package '{0}' not found in registry index", args.name))?;

    let dest = match &args.output {
        Some(p) => p.clone(),
        None => pull_cache_dir().join(&args.file_name_of(entry)),
    };
    let expected_sha = entry.sha256.to_lowercase();

    if dest.is_file() && !args.check {
        // Content-addressed short-circuit: re-verify instead of redownload.
        let current = sha256_file(&dest)?;
        if current == expected_sha {
            if args.json {
                let info = serde_json::json!({
                    "package": entry.name,
                    "version": entry.version,
                    "sha256": expected_sha,
                    "size_bytes": std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0),
                    "path": dest.display().to_string(),
                    "cached": true,
                });
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                eprintln!("[erebus] already downloaded: {}", dest.display());
                println!("{}", dest.display());
            }
            return Ok(());
        }
        eprintln!("[erebus] cache mismatch — re-downloading");
    }

    if args.check {
        bail!("package '{}' not downloaded yet", args.name);
    }

    let file_url = if entry.file.is_empty() {
        format!("{registry}/packages/{}.erebus", entry.name)
    } else {
        format!("{registry}/packages/{}", entry.file)
    };

    let mut req = client.get(&file_url);
    if let Some(ref t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let mut response = req
        .send()
        .with_context(|| format!("failed to download {file_url}"))?
        .error_for_status()
        .context("registry returned an error for the package download")?;

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).context("failed to create download directory")?;
    }
    let tmp = dest.with_extension("part");
    let mut out = std::fs::File::create(&tmp).context("failed to create temp file")?;
    let mut hasher = sha2::Sha256::new();
    let mut received: u64 = 0;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = response.read(&mut chunk).context("download interrupted")?;
        if n == 0 {
            break;
        }
        out.write_all(&chunk[..n]).context("write failed")?;
        hasher.update(&chunk[..n]);
        received += n as u64;
        if args.verbose && received % (8 * 1024 * 1024) < chunk.len() as u64 {
            eprintln!("  {} MB", received / (1024 * 1024));
        }
    }
    out.flush().ok();
    drop(out);

    let got = hex::encode(hasher.finalize());
    if got != expected_sha {
        std::fs::remove_file(&tmp).ok();
        bail!(
            "SHA-256 mismatch for '{}' — expected {expected_sha}, got {got}; download rejected",
            entry.name
        );
    }
    if entry.size > 0 && received != entry.size {
        std::fs::remove_file(&tmp).ok();
        bail!(
            "size mismatch: index says {} bytes, got {received}",
            entry.size
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).ok();
    }
    std::fs::rename(&tmp, &dest).context("failed to finalize download")?;

    if args.json {
        let info = serde_json::json!({
            "package": entry.name,
            "version": entry.version,
            "sha256": expected_sha,
            "size_bytes": received,
            "path": dest.display().to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        eprintln!(
            "[erebus] pulled {} ({}) → {}",
            entry.name,
            fmt_size(received),
            dest.display()
        );
        println!("{}", dest.display());
    }
    Ok(())
}

impl PullArgs {
    fn file_name_of(&self, entry: &IndexEntry) -> String {
        if entry.file.is_empty() {
            format!("{}.erebus", entry.name)
        } else {
            entry.file.clone()
        }
    }
}

fn pull_cache_dir() -> PathBuf {
    erebus_core::paths::cache_dir().join("pull")
}

fn sha256_file(path: &PathBuf) -> Result<String> {
    let mut f = std::fs::File::open(path).context("cannot open cached file")?;
    let mut hasher = sha2::Sha256::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut chunk).context("read failed")?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn fmt_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_reject_traversal_and_junk() {
        assert!(validate_name("tinyllama").is_ok());
        assert!(validate_name("llama.cpp:musl-x64").is_ok());
        assert!(validate_name("model_v2-beta").is_ok());
        assert!(validate_name("../etc/passwd").is_err());
        assert!(validate_name("a/b").is_err());
        assert!(validate_name("").is_err());
        assert!(validate_name("a b").is_err());
        assert!(validate_name(&"x".repeat(129)).is_err());
    }

    #[derive(serde::Deserialize)]
    struct Idx {
        packages: Vec<IndexEntry>,
    }

    #[test]
    fn index_json_parses_minimal_shape() {
        let idx: Idx = serde_json::from_str(
            r#"{"packages":[{"name":"tiny","file":"tiny.erebus","sha256":"ABCD","size":10,"version":"1.0"}]}"#,
        )
        .unwrap();
        assert_eq!(idx.packages[0].name, "tiny");
        assert_eq!(idx.packages[0].sha256.to_lowercase(), "abcd");
    }
}
