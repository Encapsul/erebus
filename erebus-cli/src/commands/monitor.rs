//! `erebus monitor` — compares the gateway's traffic journal with the signed
//! receipt trail. The journal is written before attestation and read by a
//! separate command, so a failed or skipped receipt leaves a visible gap.
//! It cannot see traffic that never reached the gateway.

use anyhow::{bail, Context, Result};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use erebus_core::attest::Attestation;
use erebus_core::attest_log::AttestationLog;
use erebus_core::paths::trusted_keys_dir;
use erebus_core::policy::load_trusted_keys;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct MonitorArgs {
    /// NDJSON traffic journal written by the attesting proxy
    #[arg(long, value_name = "FILE")]
    pub traffic_log: PathBuf,

    /// Signed receipt trail to compare against
    #[arg(long, value_name = "DIR")]
    pub trail: PathBuf,

    /// Trusted public keys (default: `erebus trust` directory)
    #[arg(long)]
    pub trusted_dir: Option<PathBuf>,

    /// Report gaps but exit 0 (for dashboards that collect the JSON)
    #[arg(long)]
    pub no_fail: bool,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct TrafficEntry {
    #[serde(default)]
    observed_at: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    request_hash: String,
}

#[derive(Debug, Serialize)]
struct Report {
    traffic: usize,
    receipts: usize,
    matched: usize,
    missing_receipts: Vec<String>,
    orphan_receipts: Vec<String>,
    healthy: bool,
}

pub fn run(args: MonitorArgs) -> Result<()> {
    let dir = args.trusted_dir.unwrap_or_else(trusted_keys_dir);
    let keys = load_trusted_keys(&dir)?;
    let traffic = read_traffic(&args.traffic_log)?;
    let hashes = call_hashes(&args.trail, &keys, &dir)?;
    let report = compare(&traffic, &hashes);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }
    if !report.healthy && !args.no_fail {
        bail!(
            "GAP: traffic/receipt mismatch ({} missing receipt(s), {} receipt(s) without traffic)",
            report.missing_receipts.len(),
            report.orphan_receipts.len()
        );
    }
    Ok(())
}

fn read_traffic(path: &Path) -> Result<Vec<TrafficEntry>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("traffic log {}", path.display()))?;
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(i, line)| {
            serde_json::from_str(line).with_context(|| format!("{} line {}", path.display(), i + 1))
        })
        .collect()
}

fn call_hashes(trail: &Path, keys: &[VerifyingKey], trusted_dir: &Path) -> Result<Vec<String>> {
    anyhow::ensure!(
        !keys.is_empty(),
        "monitor needs a trusted key in {} — add one with `erebus trust`",
        trusted_dir.display()
    );
    anyhow::ensure!(trail.is_dir(), "trail not found: {}", trail.display());
    let log = AttestationLog::open(trail)?;
    log.verify_chain(keys, None)?;
    let mut hashes = Vec::new();
    for path in log.entries()? {
        let att: Attestation = serde_json::from_slice(&std::fs::read(&path)?)?;
        if att.execution.request.is_some() {
            if let Some(h) = att.execution.input_hash {
                hashes.push(h);
            }
        }
    }
    Ok(hashes)
}

fn compare(traffic: &[TrafficEntry], receipts: &[String]) -> Report {
    let mut available: BTreeMap<&str, usize> = BTreeMap::new();
    for hash in receipts {
        *available.entry(hash.as_str()).or_insert(0) += 1;
    }
    let mut matched = 0;
    let mut missing_receipts = Vec::new();
    for entry in traffic {
        let slot = available
            .get_mut(entry.request_hash.as_str())
            .filter(|n| **n > 0);
        if let Some(n) = slot {
            *n -= 1;
            matched += 1;
        } else {
            missing_receipts.push(format!(
                "{} {} {} observed at {}",
                entry.method, entry.path, entry.request_hash, entry.observed_at
            ));
        }
    }
    let orphan_receipts = available
        .into_iter()
        .flat_map(|(hash, n)| (0..n).map(move |_| hash.to_string()))
        .collect();
    Report {
        traffic: traffic.len(),
        receipts: receipts.len(),
        matched,
        missing_receipts,
        orphan_receipts,
        healthy: false,
    }
    .with_health()
}

impl Report {
    fn with_health(mut self) -> Self {
        self.healthy = self.missing_receipts.is_empty() && self.orphan_receipts.is_empty();
        self
    }
}

fn print_report(r: &Report) {
    if r.healthy {
        eprintln!(
            "OK: traffic matches receipts ({} of {} calls attested)",
            r.matched, r.traffic
        );
        return;
    }
    for gap in &r.missing_receipts {
        eprintln!("GAP: no receipt for {gap}");
    }
    for hash in &r.orphan_receipts {
        eprintln!("GAP: receipt {hash} has no traffic entry");
    }
    eprintln!(
        "GAP: traffic/receipt mismatch ({} of {} calls matched, {} receipt(s) unmatched)",
        r.matched, r.traffic, r.receipts
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn traffic(hash: &str) -> Vec<TrafficEntry> {
        vec![TrafficEntry {
            observed_at: "2026-11-24T10:00:00Z".to_string(),
            method: "POST".to_string(),
            path: "/v1/chat/completions".to_string(),
            request_hash: hash.to_string(),
        }]
    }

    #[test]
    fn matching_is_one_to_one_and_reports_both_directions() {
        let clean = compare(&traffic("sha256:a"), &["sha256:a".to_string()]);
        assert!(clean.healthy);
        assert_eq!(clean.matched, 1);

        let missing = compare(&traffic("sha256:a"), &[]);
        assert!(!missing.healthy);
        assert_eq!(missing.missing_receipts.len(), 1);
        assert!(missing.orphan_receipts.is_empty());

        let orphan = compare(&[], &["sha256:a".to_string()]);
        assert!(!orphan.healthy);
        assert_eq!(orphan.orphan_receipts.len(), 1);
    }

    #[test]
    fn duplicate_hashes_cannot_mask_a_missing_receipt() {
        let t = vec![
            traffic("sha256:a")[0].clone(),
            traffic("sha256:a")[0].clone(),
        ];
        let report = compare(&t, &["sha256:a".to_string()]);
        assert_eq!(report.matched, 1);
        assert_eq!(report.missing_receipts.len(), 1);
    }
}
