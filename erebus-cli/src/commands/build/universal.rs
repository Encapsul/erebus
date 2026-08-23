//! `--universal`: build one slice per supported target and assemble them
//! into a single cross-platform polyglot binary.
//!
//! The matrix is built with `cargo zigbuild`; each slice is a complete native
//! `.erebus` artifact assembled by the normal single-target pipeline, so all
//! per-target behavior (stub selection, macOS re-signing, pip cross flags)
//! is reused unchanged.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

use erebus_core::format::{ARCH_AARCH64, ARCH_X86_64};
use erebus_core::polyglot::{self, PolyglotOS, PolyglotSlice};

use super::args::{parse_target, BuildArgs, BuildPlan};
use super::deps::is_command_available;
use super::pipeline::build_single_target;
use super::stub::find_stub;

/// Resolve the slice matrix: explicit `--target` entries or all defaults.
fn resolve_matrix(args: &BuildArgs) -> Vec<String> {
    match &args.target {
        Some(t) => t
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
        None => polyglot::DEFAULT_UNIVERSAL_TARGETS
            .iter()
            .map(|(triple, _, _, _)| (*triple).to_string())
            .collect(),
    }
}

/// Short label for a target triple (`linux-x86_64`, `macos-aarch64`, …).
fn slice_label(triple: &str) -> String {
    let (arch, os) = parse_target(triple);
    format!("{os}-{arch}")
}

fn os_of(triple: &str) -> Option<PolyglotOS> {
    PolyglotOS::parse(&parse_target(triple).1)
}

fn arch_of(triple: &str) -> Option<u8> {
    match parse_target(triple).0.as_str() {
        "x86_64" => Some(ARCH_X86_64),
        "aarch64" => Some(ARCH_AARCH64),
        _ => None,
    }
}

/// Cross-build the launcher stub for one target triple via cargo zigbuild.
fn ensure_stub(triple: &str, verbose: bool) -> Result<()> {
    if find_stub(&Some(triple.to_string())).is_ok() {
        return Ok(());
    }
    // Best effort: some triples ship with the toolchain already installed.
    let _ = Command::new("rustup")
        .args(["target", "add", triple])
        .status();

    let out = Command::new("cargo")
        .args([
            "zigbuild",
            "--release",
            "-p",
            "erebus-stub",
            "--target",
            triple,
        ])
        .output()
        .context("failed to run cargo zigbuild")?;
    if !out.status.success() {
        eprintln!("{}", String::from_utf8_lossy(&out.stderr));
        bail!("stub build failed for {triple}");
    }
    if verbose {
        eprintln!("  [{triple}] stub built");
    }
    Ok(())
}

/// Build one slice through the standard pipeline and read it back.
fn build_slice(
    args: &BuildArgs,
    plan: &BuildPlan,
    triple: &str,
    tmp_dir: &std::path::Path,
) -> Result<PolyglotSlice> {
    let label = slice_label(triple);
    ensure_stub(triple, plan.verbose)?;

    let out: PathBuf = tmp_dir.join(format!("{label}.erebus"));
    build_single_target(args, plan, Some(triple.to_string()), &out)?;
    let bytes = std::fs::read(&out)
        .with_context(|| format!("slice artifact missing at {}", out.display()))?;
    Ok(PolyglotSlice {
        target: label,
        arch: arch_of(triple).context("unsupported architecture")?,
        os: os_of(triple).context("unsupported OS")?,
        bytes,
    })
}

/// `erebus build --universal`: N slices → one polyglot binary.
pub(crate) fn run(args: &BuildArgs, plan: &BuildPlan, verbose: bool) -> Result<()> {
    let matrix = resolve_matrix(args);
    eprintln!("[erebus] universal build — targets: {}", matrix.join(", "));

    if !is_command_available("cargo-zigbuild") {
        bail!("cargo-zigbuild not found on PATH — install with: cargo install cargo-zigbuild");
    }

    let mut slices: Vec<PolyglotSlice> = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    let tmp = tempfile::tempdir().context("failed to create temp directory")?;

    for triple in &matrix {
        let key = (os_of(triple).map(|o| o as u8), arch_of(triple));
        if !seen.insert(key) {
            eprintln!("==> [{triple}] skipped (duplicate platform)");
            continue;
        }
        eprintln!("==> [{triple}] building slice...");
        match build_slice(args, plan, triple, tmp.path()) {
            Ok(slice) => slices.push(slice),
            Err(e) => {
                eprintln!("==> [{triple}] FAILED: {e:#}");
                failed.push(format!("{triple}: {e:#}"));
            }
        }
    }
    drop(tmp);

    if slices.is_empty() {
        bail!("all universal slices failed:\n  {}", failed.join("\n  "));
    }
    for f in &failed {
        eprintln!("[erebus] warning: slice omitted — {f}");
    }

    eprintln!(
        "==> assembling universal binary ({} slice{})...",
        slices.len(),
        if slices.len() == 1 { "" } else { "s" }
    );
    let total = polyglot::assemble_universal(&args.output, &slices)
        .context("failed to assemble universal binary")?;

    for s in &slices {
        eprintln!(
            "  {:<16} {:>10.1} MB",
            s.target,
            s.bytes.len() as f64 / 1_048_576.0
        );
    }
    eprintln!(
        "Built {} ({:.1} MB)",
        args.output.display(),
        total as f64 / 1_048_576.0
    );

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output": args.output.to_string_lossy(),
                "size_bytes": total,
                "runtime": plan.runtime_name,
                "universal": true,
                "slices": slices.iter().map(|s| serde_json::json!({
                    "target": s.target,
                    "size_bytes": s.bytes.len(),
                })).collect::<Vec<_>>(),
                "failed": failed,
            }))?
        );
    }
    if verbose {
        eprintln!("loader: /bin/sh routes uname -s/-m to the matching slice");
    }
    Ok(())
}
