//! Lifecycle management: quarantine, promote, revoke artifacts.
//!
//! These commands update the `artifact_state` of an existing `.erebus` binary
//! by rewriting its metadata, enforcing the closed state machine defined in
//! `erebus-core::metadata`.

use anyhow::{Context, Result};
use clap::Args;
use erebus_core::format::read_at;
use erebus_core::metadata::{transition, ArtifactPolicy, ArtifactState};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[derive(Args)]
pub struct LifecycleArgs {
    /// Path to the .erebus file
    pub file: PathBuf,

    /// Target state: quarantine, promote, or revoke
    #[arg(short, long, value_enum)]
    pub action: LifecycleAction,

    /// Output file (defaults to in-place rewrite)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Quiet output
    #[arg(short, long)]
    pub quiet: bool,

    /// Output result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum LifecycleAction {
    Quarantine,
    Promote,
    Revoke,
}

impl LifecycleAction {
    /**
     * `target_state` - map a CLI action to its destination lifecycle state
     *
     * Description: translate the user-facing action verb into the internal
     * `ArtifactState` that `transition` expects.
     *
     * Return: the `ArtifactState` the action moves the artifact to.
     */
    fn target_state(self) -> ArtifactState {
        match self {
            Self::Quarantine => ArtifactState::Quarantined,
            Self::Promote => ArtifactState::Trusted,
            Self::Revoke => ArtifactState::Revoked,
        }
    }
}

/**
 * `read_metadata` - parse the current metadata JSON from a .erebus binary
 * @path: path to the .erebus file
 *
 * Description: reads the footer to locate the embedded metadata region, then
 * parses it as JSON so the caller can inspect or mutate the lifecycle state.
 *
 * Return: the parsed metadata JSON value.
 */
fn read_metadata(path: &PathBuf) -> Result<serde_json::Value> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;

    let footer =
        erebus_core::format::Footer::read_from(&mut f).context("failed to read .erebus footer")?;

    let meta_bytes = read_at(&mut f, footer.meta_offset, footer.meta_size as usize)
        .context("failed to read metadata")?;
    let meta: serde_json::Value =
        serde_json::from_slice(&meta_bytes).context("failed to parse metadata JSON")?;
    Ok(meta)
}

/**
 * `write_metadata` - rewrite metadata into a .erebus binary
 * @path: source .erebus file
 * @meta: new metadata JSON to embed
 * @output: optional destination path (None rewrites in place)
 *
 * Description: rebuilds the binary as `[stub][payload][meta][footer]`, copying
 * the payload bytes unchanged and recomputing the integrity hash, which covers
 * `payload || meta`. Signed and SISR binaries are rejected: rewriting their
 * metadata would invalidate the signature or truncate the signed delta.
 *
 * Return: `Ok(())` on success.
 */
fn write_metadata(
    path: &PathBuf,
    meta: &serde_json::Value,
    output: Option<&PathBuf>,
) -> Result<()> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let footer = erebus_core::format::Footer::read_from(&mut f)?;

    // Rewriting metadata moves the signature block (which sits after metadata)
    // and invalidates the signature digest (payload ‖ meta ‖ footer). Without
    // re-signing, a modified signed file would fail the stub's fail-closed
    // signature check. Reject rather than emit a corrupt/unsigned binary.
    // Re-sign support is a future enhancement (requires key access + prompt).
    if footer.is_signed() {
        anyhow::bail!(
            "cannot rewrite lifecycle state of a signed .erebus: metadata is \
             covered by the signature. Rebuild with `erebus build --artifacts-state <state>` \
             or re-sign after rewriting."
        );
    }
    if footer.has_sisr() {
        anyhow::bail!(
            "cannot rewrite lifecycle state of a SISR binary: the delta manifest \
             is signed and would be truncated"
        );
    }

    let json_bytes = serde_json::to_vec_pretty(meta).context("failed to serialize metadata")?;

    let tmp = path.with_extension("erebus.lifecycle-tmp");
    {
        let mut out = std::fs::File::create(&tmp)
            .with_context(|| format!("failed to create temp file {}", tmp.display()))?;

        // Read the leading bytes (stub + payload) up to meta_offset
        let mut src = std::fs::File::open(path)?;
        let mut leading = Vec::new();
        src.seek(SeekFrom::Start(0))?;
        src.read_to_end(&mut leading)
            .context("failed to read source file")?;

        let meta_offset = footer.meta_offset as usize;

        // Copy stub + payload exactly
        out.write_all(&leading[..meta_offset])
            .context("failed to copy payload")?;
        // Write new metadata
        out.write_all(&json_bytes)
            .context("failed to write metadata")?;

        // Recompute integrity hash: SHA-256(payload || metadata)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&leading[..meta_offset]);
        hasher.update(&json_bytes);
        let new_hash: [u8; 32] = hasher.finalize().into();

        let new_footer = erebus_core::format::Footer {
            format_version: footer.format_version,
            arch: footer.arch,
            flags: footer.flags,
            payload_offset: footer.payload_offset,
            payload_csize: footer.payload_csize,
            payload_usize: footer.payload_usize,
            payload_sha256: new_hash,
            meta_offset: footer.meta_offset,
            meta_size: json_bytes.len() as u64,
            sig_offset: footer.sig_offset,
        };

        let footer_bytes: Vec<u8> = if new_footer.format_version >= 3 {
            new_footer.pack_full().to_vec()
        } else {
            new_footer.pack().to_vec()
        };
        out.write_all(&footer_bytes)
            .context("failed to write footer")?;
    }

    // Preserve executable bit from source
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }

    let dest = output.unwrap_or(path);
    std::fs::rename(&tmp, dest).context("failed to rename temp to destination")?;
    Ok(())
}

/**
 * run - execute the lifecycle command
 * @args: parsed lifecycle CLI arguments
 *
 * Description: reads the artifact's current state and policy, validates the
 * requested transition against the state machine, then rewrites the embedded
 * metadata. Reports the old -> new state transition.
 *
 * Return: `Ok(())` on success.
 */
pub fn run(args: LifecycleArgs) -> Result<()> {
    if !args.file.exists() {
        anyhow::bail!("file not found: {}", args.file.display());
    }

    let mut meta = read_metadata(&args.file)?;
    let current_state: ArtifactState = meta
        .get("artifact_state")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let policy: ArtifactPolicy = meta
        .get("artifact_policy")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let target = args.action.target_state();
    let new_state = match transition(&current_state, &target, &policy) {
        Ok(s) => s,
        Err(e) => anyhow::bail!("transition failed: {e}"),
    };

    meta["artifact_state"] =
        serde_json::to_value(&new_state).context("failed to serialize new state")?;

    // A quarantine is a deny-list: the artifact must NOT be served unless an
    // operator later opts in explicitly. The build stamps `allow_untrusted:
    // true` on every fresh artifact (it means "just-built, untrusted"), which
    // would otherwise make quarantined builds servable — defeating quarantine.
    // Entering `Quarantined` therefore clears the flag so `is_servable` and the
    // registry/stub gates refuse service.
    if new_state == ArtifactState::Quarantined {
        let mut p: ArtifactPolicy = meta
            .get("artifact_policy")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        p.allow_untrusted = false;
        meta["artifact_policy"] = serde_json::to_value(&p).context("failed to serialize policy")?;
    }

    write_metadata(&args.file, &meta, args.output.as_ref())?;

    if !args.quiet {
        eprintln!("[erebus] lifecycle: {:?}", args.action);
        eprintln!(
            "  {} -> {}",
            serde_json::to_value(&current_state).unwrap(),
            serde_json::to_value(&new_state).unwrap()
        );
    }
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "file": args.file.display().to_string(),
                "from": current_state,
                "to": new_state,
            })
        );
    }
    Ok(())
}
