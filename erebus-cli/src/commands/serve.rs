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

    /// Run in non-interactive mode (no browser auto-open)
    #[arg(long)]
    pub no_input: bool,
}

/// Everything `chat` and `serve` need to talk to a launched engine.
pub(crate) struct EngineHandle {
    pub child: std::process::Child,
    pub base_url: String,
    pub model_label: String,
}

/// Verify + extract + resolve + launch the bundle's engine (shared by
/// `serve` and `chat`).
#[allow(clippy::too_many_arguments)]
pub(crate) fn start_engine(
    file: &Path,
    host: &str,
    port: u16,
    ngl_flag: Option<&str>,
    ctx_size: u32,
    threads: Option<u32>,
    model_filter: Option<&str>,
    llama_server: Option<&Path>,
    quiet_banner: bool,
) -> Result<EngineHandle> {
    let verbose = std::env::var_os("ERE_VERBOSE").is_some();

    // ── Read footer + metadata, verify integrity ─────────────────────
    let mut f = std::fs::File::open(file).context("failed to read bundle")?;
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
    let model = erebus_core::inference::find_model(&rootfs, model_filter)
        .context("no supported model artifact in bundle")?;
    let model_mb = std::fs::metadata(&model.path)
        .map(|m| m.len() / (1024 * 1024))
        .unwrap_or(0)
        .max(1);
    let ngl = resolve_ngl(ngl_flag, model_mb);

    // ── Pre-flight: will this host hold the model? ────────────────────
    if let Some((fits, needed, have)) =
        erebus_core::gpu::check_fit(model_mb, ctx_size, ngl, vram_probe(), ram_probe())
    {
        let what = if ngl > 0 { "VRAM" } else { "RAM" };
        if !fits {
            eprintln!(
                "[erebus] WARNING: model needs ~{needed} MB of {what} but this host reports {} MB — \
                 expect heavy swapping or a crash. Try a smaller quant or --ctx-size.",
                have.unwrap_or(0)
            );
        } else if std::env::var_os("ERE_VERBOSE").is_some() {
            eprintln!(
                "[erebus] pre-flight ok: ~{needed} MB of {what} available ({})",
                have.unwrap_or(0)
            );
        }
    }

    if !quiet_banner {
        eprintln!(
            "[erebus] serve: format={} model={} ({model_mb} MB) ngl={ngl} ctx={ctx_size}",
            model.format.label(),
            model.path.display()
        );
    }
    let mut plan = match erebus_core::inference::plan_launch(
        &rootfs, &model, host, port, ctx_size, ngl, threads,
    ) {
        Ok(plan) => plan,
        // Engine missing? Try the runtime-pack chain (local layer store,
        // then ERE_REGISTRY) before surfacing the install hint.
        Err(msg) => match ensure_engine_pack(model.format.native_engine()) {
            Ok(path) => {
                eprintln!("[erebus] using runtime pack: {}", path.display());
                erebus_core::inference::LaunchPlan {
                    program: path.to_string_lossy().into_owned(),
                    args: erebus_core::inference::engine_args(
                        &model, host, port, ctx_size, ngl, threads,
                    ),
                }
            }
            Err(pack_err) => {
                eprintln!("[erebus] runtime pack unavailable: {pack_err:#}");
                anyhow::bail!("{msg}");
            }
        },
    };
    // Power-user escape hatch: force the server binary over the resolved one.
    if let Some(bin) = llama_server {
        if !bin.is_file() {
            bail!("--llama-server not found at {}", bin.display());
        }
        plan.program = bin.to_string_lossy().into_owned();
    }
    if verbose {
        eprintln!("[erebus] exec: {} {}", plan.program, plan.args.join(" "));
    }

    let child = Command::new(&plan.program)
        .args(&plan.args)
        .spawn()
        .with_context(|| format!("failed to launch {}", plan.program))?;
    let base_url = format!("http://{host}:{port}");
    Ok(EngineHandle {
        child,
        base_url,
        model_label: model.path.file_name().map_or_else(
            || model.path.to_string_lossy().into_owned(),
            |n| n.to_string_lossy().into_owned(),
        ),
    })
}

/// Where downloaded engine packs live, shared across runs.
fn engines_cache() -> Result<PathBuf> {
    Ok(erebus_core::paths::cache_dir().join("engines"))
}

/// Resolve `engine` through the runtime-pack chain:
/// 1. already-extracted pack from a previous run,
/// 2. local layer registry entry `runtime/<engine>` (offline installs),
/// 3. `<engine>-<platform>.pack.tar.gz` + `.sha256` sidecar from `ERE_REGISTRY`.
///
/// A pack is a gzipped tarball whose top-level directory holds the engine
/// binaries (upstream llama.cpp release layout, RPATH `$ORIGIN`-portable).
fn ensure_engine_pack(engine: &str) -> Result<PathBuf> {
    if engine.is_empty() {
        bail!("no native engine for this model format");
    }
    let dir = engines_cache()?.join(erebus_core::inference::engine_pack_stem(engine));
    if let Some(bin) = find_engine_binary(&dir, engine) {
        return Ok(bin);
    }
    if let Some(path) = engine_from_local_layers(engine, &dir)? {
        return Ok(path);
    }
    engine_from_registry(engine, &dir)
}

/// Depth-first search (max 3 levels below `dir`) for the engine binary
/// inside an extracted pack — release layouts nest one versioned dir deep.
fn find_engine_binary(dir: &Path, engine: &str) -> Option<PathBuf> {
    let wanted = format!("{engine}{}", std::env::consts::EXE_SUFFIX);
    let mut stack = vec![(dir.to_path_buf(), 0u8)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() && p.file_name().is_some_and(|n| n == wanted.as_str()) {
                return Some(p);
            }
            if p.is_dir() && depth < 3 {
                stack.push((p, depth + 1));
            }
        }
    }
    None
}

/// Extract the `runtime/<engine>` layer (same tar.gz layout) into `dest`.
fn engine_from_local_layers(engine: &str, dest: &Path) -> Result<Option<PathBuf>> {
    let Some(root) = erebus_core::registry::LayerRegistry::default_dir() else {
        return Ok(None);
    };
    let Ok(reg) = erebus_core::registry::LayerRegistry::open(&root) else {
        return Ok(None);
    };
    let tmp = std::env::temp_dir().join(format!("erebus-engine-{}.tgz", std::process::id()));
    if reg
        .materialize(&format!("runtime/{engine}"), &tmp)
        .context("reading local layer registry")?
        .is_none()
    {
        return Ok(None);
    }
    let bin = unpack_engine_pack(&tmp, dest, engine)
        .map_err(|e| anyhow::anyhow!("local layer pack unusable: {e:#}"));
    let _ = std::fs::remove_file(&tmp);
    eprintln!("[erebus] engine '{engine}' materialized from local layer store");
    bin.map(Some)
}

/// Download + SHA-256-verify the platform pack from `ERE_REGISTRY`, extract.
fn engine_from_registry(engine: &str, dest: &Path) -> Result<PathBuf> {
    use erebus_core::inference::engine_pack_name;
    let registry = std::env::var("ERE_REGISTRY")
        .ok()
        .map(|u| u.trim_end_matches('/').to_string())
        .context("ERE_REGISTRY not set — nowhere to fetch the engine pack from")?;
    let name = engine_pack_name(engine);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(600))
        .build()
        .context("failed to build HTTP client")?;
    let expected = client
        .get(format!("{registry}/packages/{name}.sha256"))
        .send()
        .and_then(|r| r.error_for_status())
        .context("fetching engine pack checksum")?
        .text()
        .context("reading engine pack checksum")?;
    let expected = expected
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("registry returned a malformed checksum for {name}");
    }
    let body = client
        .get(format!("{registry}/packages/{name}"))
        .send()
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("engine pack '{name}' not found on {registry}"))?
        .bytes()
        .context("downloading engine pack")?;
    if format!("{:x}", sha2::Sha256::digest(&body)) != expected {
        bail!("engine pack corrupted in transit (sha256 mismatch)");
    }
    let archive = std::env::temp_dir().join(format!("erebus-engine-{}.tgz", std::process::id()));
    std::fs::write(&archive, &body).context("writing engine pack download")?;
    let bin = unpack_engine_pack(&archive, dest, engine);
    let _ = std::fs::remove_file(&archive);
    eprintln!(
        "[erebus] pulled runtime pack {name} ({}) from {registry}",
        humansize(body.len())
    );
    bin
}

/// Gunzip + untar `archive` into `dest`, locate + chmod the engine binary.
fn unpack_engine_pack(archive: &Path, dest: &Path, engine: &str) -> Result<PathBuf> {
    let f = std::fs::File::open(archive).context("opening downloaded pack")?;
    let decoder = flate2::read::GzDecoder::new(f);
    let mut ar = tar::Archive::new(decoder);
    ar.set_preserve_permissions(true);
    std::fs::create_dir_all(dest).context("creating engine cache dir")?;
    ar.unpack(dest).context("extracting engine pack")?;
    find_engine_binary(dest, engine).context("no engine binary inside pack")
}

#[cfg(unix)]
#[allow(dead_code)] // used when engine packs need chmod
fn make_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(path)?.permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(path, perm).context("chmod engine pack")?;
    Ok(())
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<()> {
    Ok(())
}

fn humansize(n: usize) -> String {
    if n >= 1024 * 1024 {
        format!("{} MB", n / (1024 * 1024))
    } else {
        format!("{} KB", n / 1024)
    }
}

pub fn run(args: ServeArgs) -> Result<()> {
    let file = args
        .file
        .canonicalize()
        .context("failed to open bundle file")?;
    let mut eng = start_engine(
        &file,
        &args.host,
        args.port,
        args.ngl.as_deref(),
        args.ctx_size,
        args.threads,
        args.model.as_deref(),
        args.llama_server.as_deref(),
        false,
    )?;
    wait_healthy(&eng.base_url, &mut eng.child)?;
    print_banner(&eng.base_url, Path::new(&eng.model_label));

    let status = eng.child.wait().context("failed to wait for engine")?;
    if !status.success() {
        bail!("engine exited with {status}");
    }
    Ok(())
}

/// Probe helpers kept as fns so the pre-flight stays testable and so a
/// probe failure degrades to "no data" instead of blocking the launch.
fn vram_probe() -> Option<u64> {
    erebus_core::gpu::detect().and_then(|(_, mb)| mb)
}

fn ram_probe() -> Option<u64> {
    erebus_core::gpu::total_ram_mb()
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

/// Public alias so `chat` reuses the exact same readiness contract.
pub(crate) fn wait_healthy_pub(base_url: &str, child: &mut std::process::Child) -> Result<()> {
    wait_healthy(base_url, child)
}

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
