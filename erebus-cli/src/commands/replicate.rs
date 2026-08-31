use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct ReplicateArgs {
    #[command(subcommand)]
    pub command: ReplicateCommand,
}

#[derive(Subcommand)]
pub enum ReplicateCommand {
    /// Initial full sync of all artifacts from a leader
    Full {
        /// Leader base URL (e.g. `<https://registry.example.com>`)
        #[arg(long)]
        leader: String,

        /// Local registry data directory to write into
        #[arg(long)]
        dir: PathBuf,

        /// Replication token (optional)
        #[arg(long)]
        token: Option<String>,
    },

    /// Incremental sync since the last applied sequence
    Pull {
        /// Leader base URL
        #[arg(long)]
        leader: String,

        /// Local registry data directory
        #[arg(long)]
        dir: PathBuf,

        /// Replication token (optional)
        #[arg(long)]
        token: Option<String>,
    },
}

pub fn run(args: ReplicateArgs) -> Result<()> {
    match args.command {
        ReplicateCommand::Full { leader, dir, token } => full_sync(&leader, &dir, token),
        ReplicateCommand::Pull { leader, dir, token } => incremental_sync(&leader, &dir, token),
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ReplicationJournal {
    leader: String,
    journal: Vec<JournalEntry>,
    next_seq: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct JournalEntry {
    seq: u64,
    op: String,
    name: String,
    payload: JournalPayload,
}

#[derive(Debug, Deserialize, Serialize)]
struct JournalPayload {
    sha256: String,
    size: u64,
    at: String,
    #[serde(default)]
    private: bool,
    #[serde(default)]
    deleted: bool,
    #[serde(default)]
    meta: serde_json::Value,
}

fn cursor_path(dir: &Path) -> PathBuf {
    dir.join(".replicate-cursor")
}

fn read_cursor(dir: &Path) -> u64 {
    fs::read_to_string(cursor_path(dir))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn write_cursor(dir: &Path, seq: u64) -> Result<()> {
    fs::write(cursor_path(dir), seq.to_string())
        .with_context(|| format!("failed to write cursor to {}", cursor_path(dir).display()))
}

fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")
}

fn fetch_journal(
    client: &Client,
    leader: &str,
    token: &Option<String>,
    after: u64,
) -> Result<ReplicationJournal> {
    let url = format!("{}/replicate/index", leader.trim_end_matches('/'));
    let mut req = client.get(&url);
    if let Some(t) = token {
        req = req.header("X-Replicate-Token", t);
    }
    req = req.query(&[("after", after)]);
    let resp = req
        .send()
        .with_context(|| format!("failed to fetch journal from {url}"))?
        .error_for_status()
        .with_context(|| format!("journal request failed: {url}"))?;
    resp.json::<ReplicationJournal>()
        .with_context(|| "failed to parse journal JSON")
}

fn download_blob(
    client: &Client,
    leader: &str,
    token: &Option<String>,
    name: &str,
) -> Result<Vec<u8>> {
    let url = format!("{}/replicate/blob/{}", leader.trim_end_matches('/'), name);
    let mut req = client.get(&url);
    if let Some(t) = token {
        req = req.header("X-Replicate-Token", t);
    }
    let resp = req
        .send()
        .with_context(|| format!("failed to download blob {name} from {url}"))?
        .error_for_status()
        .with_context(|| format!("blob download failed: {name}"))?;
    let bytes = resp
        .bytes()
        .with_context(|| format!("failed to read blob bytes: {name}"))?
        .to_vec();
    Ok(bytes)
}

fn verify_sha256(data: &[u8], expected: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        anyhow::bail!("SHA-256 mismatch: expected {}, got {}", expected, actual);
    }
    Ok(())
}

fn write_artifact(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    let pkg_dir = dir.join("packages");
    fs::create_dir_all(&pkg_dir)
        .with_context(|| format!("failed to create packages dir: {}", pkg_dir.display()))?;
    let path = pkg_dir.join(name);
    fs::write(&path, data)
        .with_context(|| format!("failed to write artifact: {}", path.display()))?;
    Ok(())
}

fn write_meta(dir: &Path, name: &str, meta: serde_json::Value) -> Result<()> {
    let meta_dir = dir.join("meta");
    fs::create_dir_all(&meta_dir)
        .with_context(|| format!("failed to create meta dir: {}", meta_dir.display()))?;
    let path = meta_dir.join(format!("{}.json", name));
    fs::write(&path, serde_json::to_vec_pretty(&meta)?)
        .with_context(|| format!("failed to write meta: {}", path.display()))?;
    Ok(())
}

fn delete_artifact(dir: &Path, name: &str) -> Result<()> {
    let pkg_path = dir.join("packages").join(name);
    let meta_path = dir.join("meta").join(format!("{}.json", name));
    if pkg_path.exists() {
        fs::remove_file(&pkg_path)
            .with_context(|| format!("failed to delete artifact: {}", pkg_path.display()))?;
    }
    if meta_path.exists() {
        fs::remove_file(&meta_path)
            .with_context(|| format!("failed to delete meta: {}", meta_path.display()))?;
    }
    Ok(())
}

fn merge_user(dir: &Path, user: &str, tier: &str) -> Result<()> {
    let users_path = dir.join("users.json");
    let mut users = if users_path.exists() {
        let content = fs::read_to_string(&users_path)
            .with_context(|| format!("failed to read users: {}", users_path.display()))?;
        serde_json::from_str::<serde_json::Value>(&content)
            .unwrap_or_else(|_| serde_json::json!({"users": {}}))
    } else {
        serde_json::json!({"users": {}})
    };

    if let Some(rec) = users.get_mut("users").and_then(|u| u.get_mut(user)) {
        // Update tier only, preserve existing password/token
        rec["tier"] = serde_json::Value::String(tier.to_string());
    } else {
        // New user from replication — create a minimal record (no password)
        users["users"][user] = serde_json::json!({
            "salt": "",
            "pwhash": "",
            "token_hash": "",
            "tier": tier,
            "created": chrono::Utc::now().timestamp(),
        });
    }

    fs::write(&users_path, serde_json::to_vec_pretty(&users)?)
        .with_context(|| format!("failed to write users: {}", users_path.display()))?;
    Ok(())
}

fn process_journal(
    client: &Client,
    leader: &str,
    token: &Option<String>,
    dir: &Path,
    journal: &[JournalEntry],
) -> Result<u64> {
    let mut max_seq = 0u64;
    for entry in journal {
        max_seq = max_seq.max(entry.seq);
        match entry.op.as_str() {
            "upsert_artifact" => {
                let name = &entry.name;
                let payload = &entry.payload;
                // Download and verify blob
                let data = download_blob(client, leader, token, name)?;
                verify_sha256(&data, &payload.sha256)
                    .with_context(|| format!("sha256 verify failed for {}", name))?;
                write_artifact(dir, name, &data)?;
                // Write meta sidebar
                write_meta(dir, name, payload.meta.clone())?;
            }
            "delete_artifact" => {
                let name = &entry.name;
                delete_artifact(dir, name)?;
            }
            "upsert_user" => {
                let tier = entry
                    .payload
                    .meta
                    .get("tier")
                    .and_then(|v| v.as_str())
                    .unwrap_or("free");
                merge_user(dir, &entry.name, tier)?;
            }
            "tier_change" => {
                let tier = entry
                    .payload
                    .meta
                    .get("tier")
                    .and_then(|v| v.as_str())
                    .unwrap_or("free");
                merge_user(dir, &entry.name, tier)?;
            }
            _ => {
                eprintln!("Warning: unknown journal op '{}', skipping", entry.op);
            }
        }
    }
    Ok(max_seq)
}

fn full_sync(leader: &str, dir: &Path, token: Option<String>) -> Result<()> {
    eprintln!("Full sync from {}", leader);
    // Clear existing cursor to start from beginning
    let cursor = cursor_path(dir);
    if cursor.exists() {
        fs::remove_file(&cursor).ok();
    }
    incremental_sync(leader, dir, token)
}

fn incremental_sync(leader: &str, dir: &Path, token: Option<String>) -> Result<()> {
    let client = build_client()?;
    let after = read_cursor(dir);
    eprintln!("Fetching journal after seq={}", after);
    let journal = fetch_journal(&client, leader, &token, after)?;
    if journal.journal.is_empty() {
        eprintln!("No new entries");
        return Ok(());
    }
    let max_seq = process_journal(&client, leader, &token, dir, &journal.journal)?;
    write_cursor(dir, max_seq)?;
    eprintln!(
        "Synced {} entries, cursor now at {}",
        journal.journal.len(),
        max_seq
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn cursor_read_write() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        assert_eq!(read_cursor(path), 0);
        write_cursor(path, 42).unwrap();
        assert_eq!(read_cursor(path), 42);
        write_cursor(path, 100).unwrap();
        assert_eq!(read_cursor(path), 100);
    }

    #[test]
    fn sha256_verify() {
        let data = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_sha256(data, expected).is_ok());
        assert!(verify_sha256(data, "wrong").is_err());
    }
}
