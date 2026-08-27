//! Real SISR delta measurement.
//!
//! Drives the actual `SisrEngine` (not a heuristic) through a v1 → v2 update
//! and reports the bytes the engine really fetched — the delta that would
//! cross the wire. The v1 bundle is built with a SISR section so the engine
//! can reuse unchanged chunks from it.
//!
//! Usage:
//!   cargo run --example `sisr_bench` -- [`payload_mb`] [`change_pct`]
//!
//! Defaults: 200 MB payload, 1% change. Writes a markdown report to stdout.

use std::cell::Cell;
use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;

use ed25519_dalek::SigningKey;

use erebus_core::assembly::{assemble_erebus, AssemblyInput};
use erebus_core::sisr::engine::{ChunkFetcher, SisrEngine, SisrUpdateStats};
use erebus_core::sisr_stage::{build_artifacts, SisrBuildConfig};

const CHUNK_TARGET: usize = 64 << 10;
const META: &[u8] = br#"{"name":"sisr-bench","benchmark":true}"#;
const UNSIGNED: [u8; 64] = [0u8; 64];

/// Deterministic PRNG (xorshift64) so runs are reproducible across machines.
fn seeded_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut state = seed.max(1);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

/// Fetcher serving every v2 chunk from an in-memory map; counts transfer.
struct MapFetcher {
    map: HashMap<[u8; 32], Vec<u8>>,
    fetched: Cell<u64>,
}

impl MapFetcher {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            fetched: Cell::new(0),
        }
    }
}

impl ChunkFetcher for MapFetcher {
    fn fetch(&self, hash: &[u8; 32], _length: usize) -> io::Result<Vec<u8>> {
        let bytes = self
            .map
            .get(hash)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "chunk not served"))?;
        let total = self
            .fetched
            .get()
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "fetch counter overflow"))?;
        self.fetched.set(total);
        Ok(bytes)
    }
    fn bytes_fetched(&self) -> u64 {
        self.fetched.get()
    }
}

/// Builds a SISR-enabled `.erebus` bundle for `payload` and returns its path.
fn build_bundle(dir: &Path, name: &str, payload: &[u8]) -> io::Result<std::path::PathBuf> {
    let config = SisrBuildConfig {
        enabled: true,
        chunk_target_size: CHUNK_TARGET,
        signing_key: None,
    };
    let artifacts = build_artifacts(payload, &config)?;
    let out = dir.join(name);
    assemble_erebus(
        &out,
        &AssemblyInput {
            stub_bytes: b"STUB_DATA_HERE",
            payload,
            meta_bytes: META,
            encrypt: false,
            squashfs: false,
            target_arch: None,
            sisr: Some(artifacts),
        },
    )?;
    Ok(out)
}

fn mb(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn build_report(
    payload_mb: usize,
    change_pct: f64,
    delta_bytes: u64,
    stats: &SisrUpdateStats,
) -> String {
    let payload_bytes = (payload_mb as u64) * 1024 * 1024;
    let delta_mb = mb(delta_bytes);
    let savings = (1.0 - delta_bytes as f64 / payload_bytes as f64) * 100.0;
    let changed_bytes = ((payload_bytes as f64) * change_pct / 100.0) as u64;
    let changed_mb = mb(changed_bytes);

    format!(
        "# SISR Model Benchmark — Real Engine Measurement\n\n\
         _Measured via `erebus-core/examples/sisr_bench.rs` (drives `SisrEngine::apply_update_with_stats`)._\n\n\
         ## Scenario\n\n\
         | Property | Value |\n\
         |---|---|\n\
         | Payload size | {payload_mb} MB |\n\
         | Changed region | {changed_mb:.2} MB ({change_pct:.1}%) |\n\
         | Content-defined chunk target | {} KiB |\n\n\
         ## Results (measured through the engine)\n\n\
         | Metric | Full re-download | SISR delta | Savings |\n\
         |---|---|---|---|\n\
         | Transfer size | {payload_mb} MB | {delta_mb:.2} MB | {savings:.1}% |\n\
         | Reused chunks | — | {reused} | — |\n\
         | Fetched chunks | — | {fetched} | — |\n\n\
         The delta is the sum of only the chunks `SisrEngine` actually fetched;\n\
         unchanged chunks are copied from the running binary and never hit the\n\
         network. Because content-defined chunking may span the changed region,\n\
         the fetched bytes can slightly exceed the literal changed bytes.\n",
        CHUNK_TARGET / 1024,
        reused = stats.reused_chunks,
        fetched = stats.fetched_chunks,
    )
}

fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let payload_mb: usize = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200)
        .max(1);
    let change_pct: f64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1.0);
    let change_pct = change_pct.clamp(0.0, 100.0);

    let payload_bytes = payload_mb * 1024 * 1024;
    let work = tempfile::tempdir()?;
    let root = work.path();

    let v1 = seeded_bytes(payload_bytes, 42);
    let cur = build_bundle(root, "app.erebus", &v1)?;

    let mut v2 = v1.clone();
    let changed = (payload_bytes as f64 * change_pct / 100.0) as usize;
    if changed > 0 {
        let start = payload_bytes / 2 - changed / 2;
        v2[start..start + changed].copy_from_slice(&seeded_bytes(changed, 7));
    }

    let config = SisrBuildConfig {
        enabled: true,
        chunk_target_size: CHUNK_TARGET,
        signing_key: Some(SigningKey::from_bytes(&[2u8; 32])),
    };
    let target_artifacts = build_artifacts(&v2, &config)?;

    let mut fetcher = MapFetcher::new();
    let mut pos = 0usize;
    for chunk in &target_artifacts.manifest.chunks {
        let end = pos + chunk.length as usize;
        fetcher.map.insert(chunk.hash, v2[pos..end].to_vec());
        pos = end;
    }

    let (_, stats) = SisrEngine.apply_update_with_stats(
        &cur,
        &target_artifacts.manifest,
        &fetcher,
        &UNSIGNED,
    )?;

    let report = build_report(payload_mb, change_pct, fetcher.bytes_fetched(), &stats);
    io::stdout().write_all(report.as_bytes())?;
    io::stdout().write_all(b"\n")?;
    Ok(())
}
