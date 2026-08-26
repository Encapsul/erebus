use anyhow::{bail, Context, Result};
use clap::Args;
use erebus_core::format::{self, CRYPTO_NONE};
use erebus_core::swap;
use std::path::{Path, PathBuf};

use super::build::deps::is_command_available;
use super::build::payload::create_squashfs_payload;

#[derive(Args)]
pub struct SwapArgs {
    /// Path to the .erebus binary to modify
    pub binary: PathBuf,

    /// File path inside the payload rootfs (e.g. app/models/agent.gguf)
    pub target: String,

    /// Local file to splice in as replacement content
    #[arg(short, long)]
    pub from: PathBuf,

    /// Write the result here instead of modifying in place
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Re-sign the swapped binary with this Ed25519 key
    #[arg(short, long)]
    pub key: Option<PathBuf>,

    /// zstd level used when repacking a tar.zst payload (ignored for squashfs)
    #[arg(long, default_value_t = 3)]
    pub compression_level: i32,

    /// Output result as JSON
    #[arg(long)]
    pub json: bool,
}

/// `erebus swap` — replace one file inside a built binary without rebuilding.
///
/// Typical use: shipping updated model weights to an already-distributed AI
/// agent. The write is atomic; on any failure the source binary is untouched.
pub fn run(args: SwapArgs) -> Result<()> {
    swap::validate_inner_path(&args.target).map_err(anyhow::Error::msg)?;
    if !args.from.is_file() {
        bail!("replacement file {} not found", args.from.display());
    }
    let out_path = args.output.clone().unwrap_or_else(|| args.binary.clone());

    let parts = load_and_check(&args.binary)?;
    let meta: serde_json::Value =
        serde_json::from_slice(&parts.meta_bytes).context("metadata is not valid JSON")?;
    let squashfs = meta_payload_format(&meta) == format::PAYLOAD_FORMAT_SQUASHFS;

    let tmp = tempfile::tempdir().context("failed to create temp dir")?;
    let rootfs = tmp.path().join("rootfs");
    extract_payload(&parts.payload, squashfs, &rootfs)?;

    let replaced = replace_file(&rootfs, &args.target, &args.from)?;
    let new_size = std::fs::metadata(&args.from)?.len();

    let mut new_meta = meta.clone();
    let layer_updated = swap::update_model_layer(&mut new_meta, &args.target, new_size);
    let new_meta_bytes = serde_json::to_vec(&new_meta)?;

    let new_payload = repack_payload(&rootfs, squashfs, args.compression_level)?;
    swap::assemble_swapped(&parts, &new_payload, &new_meta_bytes, squashfs, &out_path)
        .with_context(|| format!("failed to write {}", out_path.display()))?;

    post_swap_cleanup(&out_path, &parts.footer, &args.key);
    if args.json {
        let new_size = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
        let info = serde_json::json!({
            "binary": args.binary.display().to_string(),
            "target": args.target,
            "replacement": args.from.display().to_string(),
            "output": out_path.display().to_string(),
            "replaced": replaced,
            "layer_updated": layer_updated,
            "output_size_bytes": new_size,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
    } else {
        report(&out_path, replaced, layer_updated);
    }
    Ok(())
}

/// Reads the binary and enforces hot-swap preconditions.
fn load_and_check(binary: &Path) -> Result<swap::BinaryParts> {
    let parts =
        swap::BinaryParts::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    if parts.footer.crypto_suite() != CRYPTO_NONE {
        bail!(
            "hot-swap refuses encrypted binaries: re-encrypt after swapping with \
               `erebus build --encrypt`, or swap on the plaintext build"
        );
    }
    Ok(parts)
}

fn meta_payload_format(meta: &serde_json::Value) -> &str {
    meta.get("payload_format")
        .and_then(|v| v.as_str())
        .unwrap_or("zstd-tar")
}

/// Unpacks the payload into `rootfs` (tar.zst natively; squashfs via unsquashfs).
fn extract_payload(payload: &[u8], squashfs: bool, rootfs: &Path) -> Result<()> {
    std::fs::create_dir_all(rootfs).context("creating extraction dir")?;
    if !squashfs {
        return erebus_core::tar::extract_tar_zstd(payload, rootfs)
            .context("payload is not a valid zstd+tar stream");
    }
    if !is_command_available("unsquashfs") {
        bail!("squashfs payload requires unsquashfs (squashfs-tools) on PATH");
    }
    let image = tempfile::tempdir()?.path().join("img.squashfs");
    std::fs::write(&image, payload).context("writing squashfs image")?;
    let status = std::process::Command::new("unsquashfs")
        .arg("-no-progress")
        .arg("-f")
        .arg("-d")
        .arg(rootfs)
        .arg(&image)
        .status()
        .context("failed to run unsquashfs")?;
    if !status.success() {
        bail!("unsquashfs failed");
    }
    Ok(())
}

/// Copies the replacement over the target inside the extracted rootfs.
///
/// Returns whether an existing file was replaced (vs newly added).
fn replace_file(rootfs: &Path, target: &str, from: &Path) -> Result<bool> {
    let dest = rootfs.join(target);
    let replaced = dest.is_file();
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::copy(from, &dest)
        .with_context(|| format!("copying {} into payload", from.display()))?;
    Ok(replaced)
}

fn repack_payload(rootfs: &Path, squashfs: bool, level: i32) -> Result<Vec<u8>> {
    if squashfs {
        create_squashfs_payload(rootfs, false)
    } else {
        erebus_core::tar::create_tar_zstd_with_level(rootfs, level)
            .context("failed to repack tar+zstd payload")
    }
}

/// Removes the stale SISR sidecar manifest and re-signs when requested.
fn post_swap_cleanup(out_path: &Path, footer: &format::Footer, key: &Option<PathBuf>) {
    if footer.has_sisr() {
        let mut sidecar = out_path.to_path_buf();
        sidecar.set_extension("erebus.manifest");
        match std::fs::remove_file(&sidecar) {
            Ok(()) => eprintln!("[erebus] removed stale SISR manifest {}", sidecar.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "[erebus] warning: could not remove {}: {e}",
                sidecar.display()
            ),
        }
        eprintln!(
            "[erebus] note: SISR delta updates are disabled after a swap — rebuild with \
             --enable-sisr to regenerate the delta channel"
        );
    }
    if footer.is_signed() {
        match key {
            Some(k) => {
                if let Err(e) = super::sign::sign_file(&out_path.to_path_buf(), k, true) {
                    eprintln!("[erebus] warning: re-signing failed: {e}");
                }
            }
            None => eprintln!(
                "[erebus] warning: source binary was signed — signature dropped. \
                 Pass --key to re-sign automatically."
            ),
        }
    }
}

fn report(out_path: &Path, replaced: bool, layer_updated: bool) {
    let action = if replaced { "replaced" } else { "added" };
    eprintln!(
        "Hot-swap complete: {action} target in {}",
        out_path.display()
    );
    if layer_updated {
        eprintln!("  model layer metadata size updated");
    }
}
