//! `erebus serve` — run a packaged model bundle as an OpenAI-compatible API.
//!
//! Extracts the bundle payload into the content-addressed cache, locates the
//! embedded GGUF model and a llama-server binary, then launches it bound to
//! `--host:--port`. Clients talk standard `/v1/chat/completions`: any
//! OpenAI-compatible SDK, `LangChain` or plain curl client works out of the box.

use anyhow::{bail, Context, Result};
use clap::Args;
use sha2::Digest;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::commands::build::NglPolicy;

/// How long to wait for llama-server's /health before giving up. Cold start
/// on CPU with multi-GB models is measured in minutes.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Args)]
pub struct ServeArgs {
    /// Path to the .erebus bundle embedding a GGUF model
    pub file: PathBuf,

    /// Bind address for the OpenAI-compatible endpoint
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port for the HTTP server
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// GPU offload policy: auto (probe VRAM), off, or fixed layer count
    #[arg(long)]
    pub ngl: Option<String>,

    /// Context window passed to llama-server (-c)
    #[arg(long, default_value_t = 2048)]
    pub ctx_size: u32,

    /// CPU threads (-t); defaults to llama-server's own detection
    #[arg(long)]
    pub threads: Option<u32>,

    /// Substring filter when the bundle embeds several models
    #[arg(long)]
    pub model: Option<String>,

    /// Explicit llama-server binary (else: bundle bin dirs, then $PATH)
    #[arg(long, env = "ERE_LLAMA_SERVER")]
    pub llama_server: Option<PathBuf>,
}

pub fn run(args: ServeArgs) -> Result<()> {
    let file = args
        .file
        .canonicalize()
        .context("failed to open bundle file")?;
    let verbose = std::env::var_os("ERE_VERBOSE").is_some();

    // ── Read footer + metadata, verify integrity ─────────────────────
    let mut f = std::fs::File::open(&file).context("failed to read bundle")?;
    let footer =
        erebus_core::format::Footer::read_from(&mut f).context("invalid .erebus footer")?;
    let meta_bytes =
        erebus_core::format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)
            .context("failed to read metadata")?;
    let hash = verify_sha256_streaming(&mut f, &footer, &meta_bytes)?;
    let meta: serde_json::Value =
        serde_json::from_slice(&meta_bytes).context("bundle metadata is not valid JSON")?;

    // ── Extract payload into the content-addressed cache ────────────
    let rootfs = serve_cache_dir(&hash);
    extract_payload(&mut f, &footer, &meta, &rootfs, verbose)?;

    // ── Locate model + resolve engine ─────────────────────────────────
    let model = erebus_core::inference::find_model(&rootfs, args.model.as_deref())
        .context("no supported model artifact in bundle")?;
    let model_mb = std::fs::metadata(&model.path)
        .map(|m| m.len() / (1024 * 1024))
        .unwrap_or(0)
        .max(1);
    let ngl = resolve_ngl(args.ngl.as_deref(), model_mb);

    // ── Launch the engine in the foreground ───────────────────────────
    eprintln!(
        "[erebus] serve: format={} model={} ({model_mb} MB) ngl={ngl} ctx={}",
        model.format.label(),
        model.path.display(),
        args.ctx_size
    );
    let mut plan = erebus_core::inference::plan_launch(
        &rootfs,
        &model,
        &args.host,
        args.port,
        args.ctx_size,
        ngl,
        args.threads,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    // Power-user escape hatch: force the server binary over the resolved one.
    if let Some(bin) = args.llama_server.as_deref() {
        if !bin.is_file() {
            bail!("--llama-server not found at {}", bin.display());
        }
        plan.program = bin.to_string_lossy().into_owned();
    }
    if verbose {
        eprintln!("[erebus] exec: {} {}", plan.program, plan.args.join(" "));
    }

    let mut child = Command::new(&plan.program)
        .args(&plan.args)
        .spawn()
        .with_context(|| format!("failed to launch {}", plan.program))?;

    let base_url = format!("http://{}:{}", args.host, args.port);
    wait_healthy(&base_url, &mut child)?;
    print_banner(&base_url, &model.path);

    let status = child.wait().context("failed to wait for llama-server")?;
    if !status.success() {
        bail!("llama-server exited with {status}");
    }
    Ok(())
}

/// Content-addressed extraction target: `<cache>/serve/<sha256>/rootfs`.
fn serve_cache_dir(hash: &str) -> PathBuf {
    erebus_core::paths::cache_dir()
        .join("serve")
        .join(hash)
        .join("rootfs")
}

// ---------------------------------------------------------------------------
// Integrity + extraction
// ---------------------------------------------------------------------------

/// Streaming SHA-256 over `[payload || meta]`, compared against the footer.
fn verify_sha256_streaming(
    f: &mut std::fs::File,
    footer: &erebus_core::format::Footer,
    meta_bytes: &[u8],
) -> Result<String> {
    use std::io::Seek;
    f.seek(std::io::SeekFrom::Start(footer.payload_offset))
        .context("seek to payload failed")?;
    let mut hasher = sha2::Sha256::new();
    let mut reader = f.take(footer.payload_csize);
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut chunk).context("payload read failed")?;
        if n == 0 {
            break;
        }
        hasher.update(&chunk[..n]);
    }
    hasher.update(meta_bytes);
    let got: [u8; 32] = hasher.finalize().into();
    if got != footer.payload_sha256 {
        bail!("integrity check failed: payload SHA-256 mismatch");
    }
    Ok(hex::encode(got))
}

/// Extract the zstd+tar payload into `<cache>/<hash>/rootfs`, skipping work
/// when the `.ready` marker from a previous run is present.
fn extract_payload(
    f: &mut std::fs::File,
    footer: &erebus_core::format::Footer,
    meta: &serde_json::Value,
    rootfs: &Path,
    verbose: bool,
) -> Result<()> {
    use std::io::Seek;
    let ready = rootfs.join(".ready");
    if ready.exists() {
        if verbose {
            eprintln!("[erebus] serve: cache hit {}", rootfs.display());
        }
        return Ok(());
    }
    if footer.crypto_suite() == erebus_core::format::CRYPTO_AES_256_GCM {
        bail!("serve: encrypted bundles are not supported yet — rebuild without --encrypt");
    }
    let format_tag = meta
        .get("payload_format")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if format_tag == erebus_core::format::PAYLOAD_FORMAT_SQUASHFS {
        bail!("serve does not support squashfs bundles yet");
    }

    std::fs::create_dir_all(rootfs).context("failed to create serve cache dir")?;
    f.seek(std::io::SeekFrom::Start(footer.payload_offset))?;
    // extract_tar_zstd streams (zstd + untar) internally, sanitizes entry
    // paths and enforces a size bound — no intermediate plaintext buffer.
    erebus_core::tar::extract_tar_zstd(f.take(footer.payload_csize), rootfs)
        .context("tar extraction failed")?;
    std::fs::write(&ready, b"ok").context("failed to write cache marker")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Resolve the `-ngl` value: explicit pin wins, else probe VRAM (auto).
/// Missing/invalid policies fall back to auto — serve must be usable even
/// when the flag comes from an older Agentfile.
fn resolve_ngl(raw: Option<&str>, model_mb: u64) -> u32 {
    let parsed = raw.map(NglPolicy::parse);
    match parsed {
        Some(Ok(NglPolicy::Fixed(n))) => n,
        Some(Ok(NglPolicy::Off)) => 0,
        _ => match erebus_core::gpu::detect() {
            Some((_, Some(vram_mb))) => erebus_core::gpu::auto_ngl(vram_mb, model_mb),
            _ => 0,
        },
    }
}

// ---------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------

/// Poll `/health` until llama-server reports ready. Aborts early if the
/// child dies while we wait (typo in args, missing model, port conflict).
fn wait_healthy(base_url: &str, child: &mut std::process::Child) -> Result<()> {
    let health = format!("{base_url}/health");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("failed to build HTTP client")?;
    let start = Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            bail!("llama-server exited before becoming healthy (see its output above)");
        }
        if start.elapsed() > HEALTH_TIMEOUT {
            bail!(
                "llama-server did not become healthy within {}s",
                HEALTH_TIMEOUT.as_secs()
            );
        }
        if let Ok(resp) = client.get(&health).send() {
            if resp.status().is_success() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn print_banner(base_url: &str, model: &Path) {
    eprintln!();
    eprintln!("  OpenAI-compatible endpoint ready");
    eprintln!("  ─────────────────────────────────");
    eprintln!("  base_url : {base_url}/v1");
    eprintln!("  model    : {}", model.display());
    eprintln!();
    eprintln!("  curl {base_url}/v1/chat/completions \\");
    eprintln!("    -H 'Content-Type: application/json' \\");
    eprintln!(r#"    -d '{{"model":"local","messages":[{{"role":"user","content":"Hello"}}]}}'"#);
    eprintln!();
}
