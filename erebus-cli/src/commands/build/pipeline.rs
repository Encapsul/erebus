use crate::commands::engine;
use crate::remote_cache::remote_cache_from_args;
use anyhow::{Context, Result};
use erebus_core::detect;
use erebus_core::embed;
use erebus_core::metadata::{BunFeatures, EmbeddedInterpreter};
use erebus_core::paths::cache_dir;
use erebus_core::pkgmgr;

use std::path::{Path, PathBuf};
use std::process::Command;

use super::args::{config_fingerprint, parse_target, BuildArgs, BuildPlan};
use super::deps::is_command_available;
use super::payload::{copy_dir_recursive_with, create_squashfs_payload, include_points_to_env};
use super::sign::sign_macos_binary;
use super::sisr::{build_sisr_config, report_sisr_bandwidth};
use super::stub::{find_stub, read_existing_hashes};

/// Warn when `--seccomp`/`--landlock` are requested but the stub will not
/// enforce them (they only apply at isolation >= 2, on the `pivot_root` path).
pub(crate) fn warn_sandbox_noops(isolation_num: u32, seccomp: bool, landlock: bool) {
    if isolation_num < 2 && (seccomp || landlock) {
        let flags = [("seccomp", seccomp), ("landlock", landlock)]
            .iter()
            .filter_map(|(name, on)| on.then_some(*name))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "[erebus] warning: {flags} require --isolation sandbox (2) to take effect — \
             ignored at isolation level {isolation_num}"
        );
    }
}

fn stage_model(model_path: &Path, rootfs: &Path) -> Result<()> {
    let name = model_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("model path has no file name"))?;
    let dest = rootfs.join("app/models").join(name);
    std::fs::create_dir_all(
        dest.parent()
            .ok_or_else(|| anyhow::anyhow!("model destination has no parent"))?,
    )?;
    std::fs::copy(model_path, &dest)
        .with_context(|| format!("failed to copy model to {}", dest.display()))?;
    Ok(())
}

pub(crate) fn build_single_target(
    args: &BuildArgs,
    plan: &BuildPlan,
    target: Option<String>,
    output: &PathBuf,
) -> Result<Option<serde_json::Value>> {
    let verbose = plan.verbose;
    let app_dir = &plan.app_dir;
    let runtime = plan.runtime;
    let runtime_name = &plan.runtime_name;
    let isolation_num = plan.isolation_num;
    let no_install = plan.no_install;
    let seccomp = plan.seccomp;
    let landlock = plan.landlock;
    let gui = plan.gui;
    let encrypt = plan.encrypt;
    let squashfs = plan.squashfs;
    let version_info = plan.version_info.clone();
    let author = plan.author.clone();
    let description = plan.description.clone();
    let license = plan.license.clone();
    let env_file = plan.env_file.clone();

    // ── Sandbox flags without isolation are silent no-ops ──────────────
    // seccomp/landlock are only enforced in the stub when isolation >= 2
    // (pivot_root + namespace path). Warn so the user isn't lulled into
    // believing the sandbox is active.
    warn_sandbox_noops(isolation_num, seccomp, landlock);

    // ── Reject the broken encrypt+SISR combination ─────────────────────
    // The stub's chunked-decrypt path requires per-layer sizes from
    // `meta.layers`, but the CLI always assembles with an empty layer list —
    // the produced binary would carry a chunk-encrypted payload that the
    // stub can only attempt to decrypt as one GCM blob, failing at runtime.
    if encrypt && args.enable_sisr {
        anyhow::bail!(
            "--encrypt and --enable-sisr cannot be combined: chunk-encrypted SISR \
             binaries are not decryptable by the current stub — use one or the other"
        );
    }

    // ── Reject a bundled `.env` unless it is included explicitly ───────
    // `.env` is excluded from the payload by default (secrets would be
    // extractable from the redistributable); silently dropping it could
    // break an app that relied on it, so make the builder decide.
    if app_dir.join(".env").is_file() && !include_points_to_env(app_dir, &args.include) {
        anyhow::bail!(
            "{} contains a .env file, which is excluded from the payload by default \
             (its secrets would be extractable from the binary). Bundle it explicitly \
             with `--include {}` to accept that risk, or provide configuration via \
             `--env-file` / `--env` instead.",
            app_dir.display(),
            app_dir.join(".env").display()
        );
    }

    // ── Compute hashes for incremental update ──────────────────────────
    // Hashed BEFORE staging: mutations during packaging must not affect it
    // below, and the cache/`--update` keys must reflect the pristine
    // source, not its by-products, or a rebuild would never match.
    let new_app_hash = erebus_core::include::hash_app_files(app_dir);
    let new_rt_hash = erebus_core::include::hash_lock_file(app_dir);

    // ── Intelligent build cache: skip rebuild if hash matches ──────────
    let cfg_hash = config_fingerprint(args, plan);
    if args.use_cache {
        let cache = erebus_core::paths::BuildCache::new(app_dir, 50);
        if let Some(cached) = cache.find(&new_app_hash, &cfg_hash, target.as_deref()) {
            if verbose {
                eprintln!("[erebus] cache hit — reusing cached build");
            }
            std::fs::copy(&cached, &output).context("failed to copy cached .erebus to output")?;
            if args.json {
                return Ok(Some(serde_json::json!({
                    "output": output.to_string_lossy(),
                    "runtime": runtime_name.as_str(),
                    "cache_hit": true,
                })));
            }
            return Ok(None);
        }
        if verbose {
            eprintln!("[erebus] cache miss — building from scratch");
        }
    }

    if args.clear_cache {
        let cache = erebus_core::paths::BuildCache::new(app_dir, 50);
        cache.clear().ok();
        if verbose {
            eprintln!("  cache: cleared");
        }
    }

    // ── Incremental update: skip rebuild if nothing changed ────────────
    if args.update && output.exists() {
        if let Some((old_app_hash, old_rt_hash)) = read_existing_hashes(output) {
            if old_app_hash == new_app_hash && old_rt_hash == new_rt_hash {
                if verbose {
                    eprintln!("[erebus] everything up to date, nothing to rebuild");
                }
                return Ok(None);
            } else if old_rt_hash == new_rt_hash && old_app_hash != new_app_hash {
                if verbose {
                    eprintln!("[erebus] app changed, reusing runtime layer (full layer reuse not yet supported in Rust CLI — doing full rebuild)");
                }
            } else if verbose {
                eprintln!("[erebus] runtime deps changed, full rebuild");
            }
        }
    }

    // Determine embedded interpreter string early for pip install target
    let embedded_interpreter_str = if let Some(ref interp) = args.embed_interpreter {
        Some(interp.clone())
    } else if runtime_name == "python" {
        Some("python3".to_string())
    } else {
        None
    };

    // Detect and install all package managers (primary + secondary)
    let all_pkg_mgrs = pkgmgr::detect_all_pkgmgrs(app_dir, runtime_name);
    if verbose {
        for mgr in &all_pkg_mgrs {
            eprintln!("Package manager: {}", mgr.name());
        }
    }

    // Find stub binary
    let stub = find_stub(&target)?;
    let stub_bytes = std::fs::read(&stub)
        .with_context(|| format!("failed to read stub binary at {}", stub.display()))?;

    // Create temp directory for layer building
    let tmp = tempfile::tempdir().context("failed to create temp directory")?;
    let rootfs = tmp.path().join("rootfs");
    std::fs::create_dir_all(&rootfs).context("failed to create rootfs directory")?;

    // Install package manager dependencies into rootfs
    if !no_install {
        for mgr in &all_pkg_mgrs {
            if verbose {
                eprintln!("Package manager: {}", mgr.name());
            }

            let cmd = mgr.install_cmd();

            if !is_command_available(cmd[0]) {
                eprintln!(
                    "[erebus] skipping {} — `{}` not found on PATH",
                    mgr.name(),
                    cmd[0]
                );
                continue;
            }

            let mut full_args: Vec<String> = Vec::new();
            full_args.extend(cmd.iter().skip(1).map(|s| s.to_string()));

            // When cross-compiling for a different arch, force source builds for pip
            let is_cross_pip = matches!(mgr, pkgmgr::PkgMgr::Pip)
                && args
                    .cross_compile
                    .as_ref()
                    .is_some_and(|c| c.split(',').any(|t| t.trim() != std::env::consts::ARCH));
            if is_cross_pip {
                full_args.push("--no-binary".into());
                full_args.push(":all:".into());
            }

            // For pip, install into rootfs site-packages
            if matches!(mgr, pkgmgr::PkgMgr::Pip) {
                // Query actual python3 version
                let py_version = Command::new("python3")
                    .args([
                        "-c",
                        "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
                    ])
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|| "3.10".to_string());

                let site_packages = rootfs
                    .join("usr/local/lib")
                    .join(format!("python{}", py_version))
                    .join("site-packages");
                std::fs::create_dir_all(&site_packages).ok();
                full_args.push("--target".into());
                full_args.push(site_packages.to_string_lossy().to_string());
                if verbose {
                    eprintln!("  pip target: {}", site_packages.display());
                }
            }

            let mut command = std::process::Command::new(cmd[0]);
            command.args(&full_args).current_dir(app_dir);

            let status = command
                .status()
                .context(format!("failed to run `{}` — is it installed?", cmd[0]))?;
            if !status.success() {
                eprintln!(
                    "[erebus] warning: {} installation failed (exit code {})",
                    mgr.name(),
                    status.code().unwrap_or(-1)
                );
            }
        }
    }

    // After pip install, copy site-packages from --target location to standard location
    // so embed_interpreter can find them
    if let Some(ref interp) = embedded_interpreter_str {
        if matches!(interp.as_str(), "python3" | "python") {
            if let Ok(py_version) = Command::new("python3")
                .args([
                    "-c",
                    "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
                ])
                .output()
            {
                if let Ok(stdout) = String::from_utf8(py_version.stdout) {
                    let py_version = stdout.trim();
                    let src = rootfs
                        .join("usr/local/lib")
                        .join(format!("python{}", py_version))
                        .join("site-packages");
                    let dst = rootfs
                        .join("usr/lib")
                        .join(format!("python{}", py_version))
                        .join("site-packages");
                    if verbose {
                        eprintln!("  pip target src: {}", src.display());
                        eprintln!("  pip target dst: {}", dst.display());
                        eprintln!("  src exists: {}", src.exists());
                    }
                    if src.exists() {
                        if let Err(e) = copy_dir_recursive_with(&src, &dst, true) {
                            if verbose {
                                eprintln!("  warning: failed to copy site-packages: {}", e);
                            }
                        } else if verbose {
                            eprintln!("  copied site-packages to standard location");
                        }
                    }
                }
            }
        }
    }

    // Clean up downloaded build tools from cache (deferred: nothing downloads
    // tools today, but the cleanup stays for parity with the cache layout).

    // Copy app files
    let include_node_modules = true;
    copy_dir_recursive_with(app_dir, &rootfs.join("app"), include_node_modules)
        .context("failed to copy app files")?;

    // ── Include extra files ───────────────────────────────────────────
    if !args.include.is_empty() {
        let app_dest = rootfs.join("app");
        let count = erebus_core::include::copy_include_paths(&args.include, &app_dest, app_dir)
            .context("failed to copy include paths")?;
        if verbose {
            eprintln!("  include: copied {count} path(s) into rootfs");
        }
    }

    // ── Embed llama engine ─────────────────────────────────────────────
    //
    // AUTO-ENGINE: with `--engine`, drop a llama.cpp runtime into the payload
    // at app/.deps/llama, replacing anything the app bundled there. This makes
    // an AI agent build reproducibly from one flag instead of requiring a
    // hand-staged `.deps/llama` in the app dir. Reuses the runtime + host-lib
    // set proven in examples/real-agent.
    if let Some(ref spec_str) = args.engine {
        let engine_dest = rootfs.join("app").join(".deps").join("llama");
        let spec = engine::parse_engine(spec_str)
            .with_context(|| format!("invalid --engine value: {spec_str}"))?;
        if verbose {
            eprintln!("[erebus] embedding llama engine ({spec_str}) -> .deps/llama");
        }
        engine::stage_engine(&engine_dest, &spec)
            .with_context(|| format!("failed to embed llama engine from '{spec_str}'"))?;
    }

    // ── Embed interpreter ──────────────────────────────────
    //
    // CROSS-TARGET: CPython is copied verbatim from the *build host* plus its
    // ldd deps — a host binary cannot run on a different target arch (its ELF
    // interpreter is missing there) nor on a different OS (ELF vs PE/Mach-O).
    // Cross-platform Python builds therefore embed only the portable parts
    // (stdlib, site-packages) and rely on the target machine's own `python3`
    // found via PATH.
    let mut interpreter_embedded = false;
    if let Some(ref interpreter_name) = embedded_interpreter_str {
        let cross_python = runtime_name == "python"
            && target
                .as_deref()
                .map(parse_target)
                .is_some_and(|(arch, os)| {
                    arch != std::env::consts::ARCH || os != std::env::consts::OS
                });
        let embed_result = if cross_python {
            eprintln!(
                "[erebus] {}: skipping host interpreter embed (platform mismatch) — uses target python3",
                target.as_deref().unwrap_or("?")
            );
            erebus_core::embed::embed_python_portable(
                interpreter_name,
                &rootfs,
                Some(app_dir),
                verbose,
            )
        } else {
            if verbose {
                eprintln!("Embedding interpreter: {interpreter_name}...");
            }
            embed::embed_interpreter(interpreter_name, &rootfs, Some(app_dir), verbose)
        };
        match embed_result {
            Ok(count) => {
                if verbose && !cross_python {
                    eprintln!("Embedded interpreter ({count} files copied)");
                }
                interpreter_embedded = !cross_python;
            }
            Err(e) => {
                eprintln!("[erebus] warning: failed to embed interpreter: {}", e);
            }
        }
    }

    // Pre-compile Python bytecode for faster startup
    if runtime_name == "python" {
        let app_root = rootfs.join("app");
        if app_root.is_dir() {
            let status = std::process::Command::new("python3")
                .args(["-m", "compileall", "-f", "-q"])
                .arg(&app_root)
                .status();
            if let Ok(s) = status {
                if s.success() && verbose {
                    eprintln!("Bytecode compiled (.pyc)");
                }
            }
        }
    }

    // Embed RoadRunner binary for Laravel Octane apps (rr.yaml or .rr.yaml)
    if app_dir.join("rr.yaml").is_file() || app_dir.join(".rr.yaml").is_file() {
        if which::which("rr").is_ok() {
            if verbose {
                eprintln!("Embedding RoadRunner...");
            }
            if let Err(e) = embed::embed_interpreter("rr", &rootfs, None, verbose) {
                eprintln!("[erebus] warning: failed to embed RoadRunner: {}", e);
            }
        } else if verbose {
            eprintln!("[erebus] warning: rr binary not found on PATH; RoadRunner won't be available at runtime");
        }
    }

    if !interpreter_embedded && verbose && embedded_interpreter_str.is_some() {
        eprintln!("  (interpreter embedding skipped)");
    }

    // A pure-binary payload (`/app/app` exec'd directly) has no interpreter
    // to pull glibc into the rootfs the way embedded python does. Without the
    // dynamic loader + core libc the kernel cannot exec the (dynamic) binary
    // at all — a pivot_root'd rootfs has no host /lib to fall back on. Bundle
    // the host's minimal glibc base for binary runtimes only; interpreted
    // payloads already get libc+friends from the interpreter embed.
    if runtime_name == "binary"
        && embedded_interpreter_str.is_none()
        && app_has_elf(&rootfs)
        && !rootfs
            .join("usr/lib")
            .join(host_gnu_triple())
            .join("libc.so.6")
            .is_file()
    {
        copy_base_glibc(&rootfs, verbose)?;
    }

    // Clean up downloaded build tools. Only the tool's own cache dir is
    // removed — never a shared `/tmp` path, which another user/process may
    // own or have symlinked (roadmap #36).
    let _ = std::fs::remove_dir_all(cache_dir().join("build-tools"));

    // Model bytes must enter the rootfs before payload compression. Metadata
    // is assembled later; copying there used to advertise a ModelLayer while
    // producing a tiny bundle with no model in its payload.
    if let Some(model_path) = args.embed_model.as_deref() {
        stage_model(model_path, &rootfs)?;
    }

    // Build the payload: zstd(tar) by default, or a real SquashFS image
    // when `--squashfs` was requested (v5). Before this fix the flag only
    // flipped the metadata's payload_format while the payload stayed a
    // zstd+tar stream — the stub's squashfs extractor would fail on it.
    eprintln!("Creating payload...");
    let t0 = std::time::Instant::now();
    let mut payload = if squashfs {
        create_squashfs_payload(&rootfs, verbose).context("failed to create squashfs payload")?
    } else {
        erebus_core::tar::create_tar_zstd_with_level(&rootfs, args.compression_level)
            .context("failed to create tar+zstd payload")?
    };
    let compress_ms = t0.elapsed().as_millis();
    if verbose {
        eprintln!(
            "  compress: {compress_ms}ms, {} MB",
            payload.len() as f64 / 1_048_576.0
        );
    }

    // ── Encryption (v4) ──────────────────────────────────────────────────
    // AES-256-GCM, key derived from a random 32-byte encryption key via
    // HKDF-SHA256 (same key the stub derives at runtime).
    //
    // SECURITY: The encryption key is **separate** from the Ed25519 signing
    // seed.  `--key` is only used for SISR manifest signing (when
    // `--enable-sisr` is also set) and/or binary signing (`--sign`).
    // The encryption key itself is generated randomly at build time and
    // stored in meta `crypto` as `encryption_key_hex`.  The signing seed is
    // NEVER embedded in the binary — this prevents a key compromise from
    // breaking both confidentiality and authenticity.
    //
    // The ciphertext replaces the payload before assembly so the footer's
    // integrity hash and signature both cover the *encrypted* bytes.
    //
    // When combined with `--enable-sisr`, the payload is encrypted in
    // per-chunk mode: each SISR plaintext chunk gets an independent AES key
    // derived via HKDF(encryption_key, salt, chunk_index), and the manifest
    // tracks the ciphertext hashes.  The stub decrypts each chunk
    // independently at runtime before SISR extraction.
    let mut crypto_meta: Option<serde_json::Value> = None;
    let mut sisr_artifacts_opt: Option<erebus_core::sisr_stage::SisrArtifacts> = None;

    if encrypt {
        // Generate a fresh random encryption key — never reuse the signing seed.
        // Raw form lives only in a Zeroizing slot. The hex form below IS the
        // product's documented model (--encrypt = tamper-evidence/obfuscation,
        // NOT confidentiality): it lands in meta bytes inside the binary and
        // flows through serde_json clones we cannot track. Real
        // confidentiality requires an out-of-band key.
        let encryption_key = erebus_core::encrypt::generate_encryption_key();

        if args.enable_sisr {
            let sisr_config = build_sisr_config(&args.key, args.embed_model.is_some())?;
            let artifacts = erebus_core::sisr_stage::build_artifacts(&payload, &sisr_config)
                .context("SISR stage failed during encrypt+SISR build")?;
            let chunk_sizes: Vec<usize> = artifacts
                .manifest
                .chunks
                .iter()
                .map(|c| c.length as usize)
                .collect();
            let salt = erebus_core::encrypt::generate_salt();
            let nonce = erebus_core::encrypt::generate_nonce();
            let ciphertext = erebus_core::encrypt::encrypt_chunks(
                &payload,
                &encryption_key,
                &salt,
                &nonce,
                &chunk_sizes,
            )
            .context("chunked AES-256-GCM payload encryption failed")?;
            payload = ciphertext;
            crypto_meta = Some(serde_json::json!({
                "nonce_hex": hex::encode(nonce),
                "encryption_key_hex": hex::encode(encryption_key),
                "encryption_salt_hex": hex::encode(salt),
                "chunked": true,
            }));
            sisr_artifacts_opt = Some(artifacts);
            if verbose {
                eprintln!(
                    "  encrypt+SISR: {} -> {} bytes (per-chunk AES-256-GCM, {} chunks)",
                    payload.len(),
                    payload.len(),
                    chunk_sizes.len()
                );
            }
        } else {
            let (ciphertext, em) = erebus_core::encrypt::encrypt_payload(&payload, &encryption_key)
                .context("AES-256-GCM payload encryption failed")?;
            payload = ciphertext;
            crypto_meta = Some(serde_json::json!({
                "nonce_hex": hex::encode(em.nonce),
                "tag_offset": em.tag_offset,
                "encryption_key_hex": hex::encode(encryption_key),
                "encryption_salt_hex": hex::encode(em.salt),
            }));
            if verbose {
                eprintln!(
                    "  encrypt: {} -> {} bytes (AES-256-GCM, tag at {})",
                    payload.len(),
                    payload.len(),
                    em.tag_offset
                );
            }
        }
    }

    // Build metadata
    let app_name = app_dir
        .file_name()
        .map_or_else(|| "app".to_string(), |n| n.to_string_lossy().into());

    let mut env_map = serde_json::Map::new();
    env_map.insert("ERE_RUNTIME".into(), runtime_name.clone().into());
    env_map.insert("ERE_APP_NAME".into(), app_name.clone().into());

    // Load env-file (KEY=VALUE per line, # comments, blank lines)
    if let Some(ref ef) = env_file {
        if let Ok(content) = std::fs::read_to_string(ef) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    env_map.insert(k.trim().into(), v.trim().into());
                }
            }
        }
    }

    // Inline --env KEY=VALUE flags (override env-file)
    for entry in &args.env {
        if let Some((k, v)) = entry.split_once('=') {
            env_map.insert(k.trim().into(), v.trim().into());
        }
    }

    // Build-time --define KEY=VALUE (injected as env vars, overrides --env)
    for entry in &args.define {
        if let Some((k, v)) = entry.split_once('=') {
            env_map.insert(k.trim().into(), v.trim().into());
        }
    }

    // ── GPU offload policy (--ngl) ────────────────────────────────────
    //
    // "auto" (the default when unset) bakes nothing: the stub probes the
    // launch machine and exports ERE_GPU / ERE_VRAM_MB / ERE_NGL itself.
    if let Some(raw) = args.ngl.as_deref() {
        use super::args::NglPolicy;
        match NglPolicy::parse(raw)? {
            NglPolicy::Auto => {}
            NglPolicy::Off => {
                env_map.insert("ERE_GPU".into(), serde_json::Value::from("none"));
                env_map.insert("ERE_NGL".into(), serde_json::Value::from("0"));
            }
            NglPolicy::Fixed(n) => {
                // Values must be JSON strings: meta.env serializes through
                // as_str() and would silently drop numeric entries.
                env_map.insert("ERE_NGL".into(), serde_json::Value::from(n.to_string()));
            }
        }
    }

    // ── Persistent storage ────────────────────────────────────────────
    if args.persist {
        let persist_dir = erebus_core::persistent::get_persist_dir(&app_name);
        let _ = erebus_core::persistent::ensure_persist_dir(&app_name);
        env_map.insert(
            "ERE_PERSIST_DIR".into(),
            serde_json::Value::String(persist_dir.to_string_lossy().into()),
        );
        if verbose {
            eprintln!("  persistent storage: {}", persist_dir.display());
        }
    }

    // ── Health check port ─────────────────────────────────────────────
    if let Some(port) = args.health_port {
        env_map.insert(
            "ERE_HEALTH_PORT".into(),
            serde_json::Value::String(port.to_string()),
        );
        if verbose {
            eprintln!("  health: endpoint enabled on port {port}");
        }
    }

    // ── OpenTelemetry ─────────────────────────────────────────────────
    if let Some(ref endpoint) = args.otel_endpoint {
        let version = version_info.as_deref().unwrap_or("");
        let otel_env = erebus_core::otel::build_otel_env(
            &app_name,
            version,
            endpoint,
            &args.otel_protocol,
            "otlp",
            "otlp",
            "none",
        );
        for (k, v) in &otel_env {
            env_map.insert(k.clone(), serde_json::Value::String(v.clone()));
        }
        if verbose {
            eprintln!(
                "  otel: endpoint={endpoint} protocol={}",
                args.otel_protocol
            );
        }
    }

    // ── Cron/scheduled tasks ──────────────────────────────────────────
    if !args.cron.is_empty() {
        let mut tasks_json: Vec<serde_json::Value> = Vec::new();
        for ct in &args.cron {
            if let Some((name, schedule)) = ct.split_once(':') {
                let interval = erebus_core::cron::parse_schedule(schedule);
                tasks_json.push(serde_json::json!({
                    "name": name,
                    "schedule": schedule,
                    "interval_secs": interval,
                }));
                if verbose {
                    eprintln!("  cron: {name} -> every {interval}s (from {schedule})");
                }
            } else {
                anyhow::bail!("--cron format: NAME:SCHEDULE (got '{ct}')");
            }
        }
        env_map.insert(
            "ERE_CRON_TASKS".into(),
            serde_json::Value::Array(tasks_json),
        );
        if verbose {
            eprintln!("  cron: {} task(s) registered", args.cron.len());
        }
    }

    let env_pairs: Vec<(String, String)> = env_map
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
        .collect();

    let entrypoint = if !args.entrypoint.is_empty() {
        args.entrypoint.clone()
    } else {
        detect::resolve_entrypoint(app_dir, runtime).unwrap_or_else(|| vec!["run".to_string()])
    };

    let mut bun_features = BunFeatures::default();

    // Set embedded interpreter based on either explicit --embed-interpreter or auto-detection
    let (interpreter_opt, interpreter_path_opt) = if let Some(ref interp) = args.embed_interpreter {
        (
            Some(match interp.to_lowercase().as_str() {
                "python3" | "python" => EmbeddedInterpreter::Python3,
                other => EmbeddedInterpreter::Custom(other.to_string()),
            }),
            args.interpreter_path.clone(),
        )
    } else if runtime_name == "python" {
        (Some(EmbeddedInterpreter::Python3), None)
    } else {
        (None, None)
    };

    if let Some(interpreter) = interpreter_opt {
        bun_features.embedded_runtime.interpreter = Some(interpreter);
        if let Some(path) = interpreter_path_opt {
            bun_features.embedded_runtime.interpreter_path = Some(path);
        }
        if verbose {
            if let Some(interp) = bun_features.embedded_runtime.interpreter.as_ref() {
                eprintln!("  embedded runtime: {interp}");
            }
        }
    }

    if let Some(port) = args.health_port {
        bun_features.health_check.enabled = true;
        bun_features.health_check.port = port;
        if let Some(ref ep) = args.health_endpoint {
            bun_features.health_check.endpoint.clone_from(ep);
        }
        if verbose {
            eprintln!("  health check: port {}", port);
        }
    }

    if let Some(ref cross) = args.cross_compile {
        eprintln!("[erebus] warning: --cross-compile is not yet implemented in the stub; metadata will be written but ignored at runtime");
        let targets: Vec<String> = cross.split(',').map(|s| s.trim().to_string()).collect();
        bun_features.cross_compile_targets = targets;
        if verbose {
            eprintln!("  cross-compile: {:?}", bun_features.cross_compile_targets);
        }
    }

    bun_features.build_cache.enabled = args.use_cache;

    bun_features
        .validate()
        .map_err(|e| anyhow::anyhow!("Invalid build options: {}", e))?;

    let meta = erebus_core::assembly::build_meta_json(
        &app_name,
        runtime_name,
        isolation_num,
        &entrypoint,
        &env_pairs,
        &erebus_core::assembly::MetaOptions {
            version: version_info,
            author,
            description,
            license,
            payload_format: Some(if squashfs { "squashfs" } else { "zstd-tar" }.to_string()),
            seccomp,
            landlock,
            gui,
            app_hash: Some(new_app_hash.clone()),
            rt_deps_hash: Some(new_rt_hash.clone()),
            update_url: args.update_url.clone(),
            crypto: crypto_meta,
            artifact_state: Some(erebus_core::metadata::ArtifactState::Acquired),
            artifact_policy: Some(erebus_core::metadata::ArtifactPolicy {
                allow_untrusted: true,
                require_signature: false,
                max_retries: 3,
            }),
            layers: {
                let mut layers = Vec::new();

                // Default runtime layer
                use erebus_core::layer::{Capability, RuntimeLayer, SerializableLayer};
                layers.push(SerializableLayer::Runtime(RuntimeLayer {
                    name: runtime_name.to_string(),
                    interpreter: runtime_name.to_string(),
                    entrypoint: entrypoint.to_vec(),
                    version: None,
                    env: env_map
                        .iter()
                        .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                        .collect(),
                    capabilities: vec![
                        Capability::ReadFile,
                        Capability::WriteFile,
                        Capability::Network,
                        Capability::Exec,
                        Capability::Syscall,
                        Capability::Env,
                    ],
                }));

                // Add model layer if embed_model is provided
                if let Some(ref model_path) = args.embed_model {
                    use erebus_core::layer::{ModelLayer, SerializableLayer};
                    let model_bytes =
                        std::fs::read(model_path).context("failed to read model file")?;
                    let model_name = model_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    let _model_size = model_bytes.len() as u64;

                    // Reuse `model_name` (already derived from the source
                    // path) instead of re-deriving from the destination — a
                    // path with no filename cannot panic here.
                    use sha2::{Digest, Sha256};
                    let model_sha256 = hex::encode(Sha256::digest(&model_bytes));
                    let model_layer = ModelLayer {
                        name: model_name.clone(),
                        format: "gguf".to_string(),
                        path: format!("models/{model_name}"),
                        size: model_bytes.len() as u64,
                        tensor_manifest: None,
                        source: None,
                        scan_results: None,
                        metadata: Some(serde_json::json!({ "sha256": model_sha256 })),
                    };
                    layers.push(SerializableLayer::Model(model_layer));
                }
                Some(layers)
            },
            entrypoint_layer: None,
        },
        &bun_features,
    )?;

    // Assemble
    eprintln!("Assembling {}...", output.display());

    // Save previous SISR manifest before assembly (for bandwidth reporting)
    let prev_manifest_bytes: Option<Vec<u8>> = if args.update && args.enable_sisr {
        let mut prev_manifest_path = output.clone();
        prev_manifest_path.set_extension("erebus.manifest");
        std::fs::read(&prev_manifest_path).ok()
    } else {
        None
    };

    let size = if args.enable_sisr {
        let sisr_config = build_sisr_config(&args.key, args.embed_model.is_some())?;
        let artifacts = match sisr_artifacts_opt {
            Some(a) => a,
            None => erebus_core::sisr_stage::build_artifacts(&payload, &sisr_config)
                .context("SISR stage failed during build")?,
        };
        let input = erebus_core::assembly::AssemblyInput {
            stub_bytes: &stub_bytes,
            payload: &payload,
            meta_bytes: &meta,
            encrypt,
            squashfs,
            target_arch: target.as_deref(),
            sisr: Some(artifacts),
        };
        erebus_core::assembly::assemble_erebus(output, &input)
            .context("failed to assemble erebus (SISR)")?
    } else {
        let input = erebus_core::assembly::AssemblyInput {
            stub_bytes: &stub_bytes,
            payload: &payload,
            meta_bytes: &meta,
            encrypt,
            squashfs,
            target_arch: target.as_deref(),
            sisr: None,
        };
        erebus_core::assembly::assemble_erebus(output, &input)
            .context("failed to assemble erebus")?
    };

    eprintln!(
        "Built {} ({:.1}MB)",
        output.display(),
        size as f64 / (1024.0 * 1024.0)
    );

    if args.enable_sisr {
        eprintln!(
            "warning: SISR binaries are NOT signed at rest — authenticity is only guaranteed \
             during an update, when the remote manifest signature is verified"
        );
    }

    // macOS code signing: re-sign the assembled binary since appending
    // payload + metadata invalidates any existing Mach-O signature.
    if target
        .as_ref()
        .is_some_and(|t| t.contains("darwin") || t.contains("apple") || t.contains("macos"))
    {
        sign_macos_binary(output, verbose)?;
    }

    if args.enable_sisr {
        let mut manifest_path = output.clone();
        manifest_path.set_extension("erebus.manifest");
        eprintln!("SISR manifest written: {}", manifest_path.display());

        // Bandwidth reporting: compare new chunk set against previous manifest
        if let Some(prev_bytes) = &prev_manifest_bytes {
            if let (Ok(prev), Ok(new_bytes)) = (
                erebus_core::sisr_stage::RemoteManifest::from_bytes(prev_bytes),
                std::fs::read(&manifest_path),
            ) {
                if let Ok(new_remote) =
                    erebus_core::sisr_stage::RemoteManifest::from_bytes(&new_bytes)
                {
                    report_sisr_bandwidth(&prev, &new_remote);
                }
            }
        }
    }

    // Binary signature is mutually exclusive with SISR in a single build:
    // `sign_file` rebuilds the file as `[..meta_end][sig][footer]`, which would
    // truncate the SISR section. With `--enable-sisr`, `--key` instead signs
    // the manifest (see `build_sisr_config`).
    //
    // Signing happens BEFORE the cache store so the cached artifact is the
    // complete, signed binary — a cache hit must not serve an unsigned copy.
    if !args.enable_sisr {
        if let Some(key_path) = &args.key {
            if verbose {
                eprintln!("Signing...");
            }
            crate::commands::sign::sign_file(output, key_path, !verbose, false)?;
        }
    }

    // ── Store in build cache ──────────────────────────────────────────
    if args.use_cache {
        let cache = erebus_core::paths::BuildCache::new(app_dir, 50);
        if cache
            .store(&new_app_hash, &cfg_hash, target.as_deref(), output)
            .is_ok()
            && verbose
        {
            eprintln!("  cache: stored build");
        }
    }

    // ── Store in remote cache (Depot-style) ───────────────────────────
    if let Some(remote) = remote_cache_from_args(args, app_dir) {
        if remote
            .store(&new_app_hash, &cfg_hash, target.as_deref(), output)
            .is_ok()
            && verbose
        {
            eprintln!("  remote cache: stored build");
        }
    }

    if args.json {
        return Ok(Some(serde_json::json!({
            "output": output.to_string_lossy(),
            "size_bytes": size,
            "runtime": runtime_name,
            "format": "zstd-tar",
            "signed": args.key.is_some() && !args.enable_sisr,
            "encrypted": encrypt,
            "sisr": args.enable_sisr,
            "manifest_signed": args.enable_sisr && args.key.is_some(),
        })));
    }
    Ok(None)
}

/// GNU triplet of the build host, for locating glibc base libs and the
/// `libggml-cpu-*` backend layout.
fn host_gnu_triple() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        "riscv64" => "riscv64-linux-gnu",
        other => other,
    }
}

/// Mach-O and PE payloads load the target OS's own libraries; only an ELF
/// entry needs a glibc base inside the rootfs.
fn app_has_elf(rootfs: &Path) -> bool {
    use std::io::Read;
    let Ok(entries) = std::fs::read_dir(rootfs.join("app")) else {
        return false;
    };
    entries.flatten().any(|e| {
        let mut magic = [0u8; 4];
        std::fs::File::open(e.path())
            .and_then(|mut f| f.read_exact(&mut magic))
            .is_ok_and(|()| &magic == b"\x7fELF")
    })
}

/// Copy the minimal glibc base (dynamic loader + core libc) from the build
/// host into the rootfs, so a pure-binary payload can exec inside the sandbox.
/// The loader finds these via its compiled-in default path (`/usr/lib/<triple>`),
/// no `/etc/ld.so.cache` needed. Missing libs are only a warning — the bundle
/// still builds but will not exec on distros where the target lacks the base.
fn copy_base_glibc(rootfs: &Path, verbose: bool) -> Result<()> {
    let triple = host_gnu_triple();
    let (loader, loader_rel) = match std::env::consts::ARCH {
        "x86_64" => (
            "/lib64/ld-linux-x86-64.so.2",
            PathBuf::from("lib64/ld-linux-x86-64.so.2"),
        ),
        "aarch64" => (
            "/lib/ld-linux-aarch64.so.1",
            PathBuf::from("lib/ld-linux-aarch64.so.1"),
        ),
        "riscv64" => (
            "/lib/ld-linux-riscv64-lp64d.so.1",
            PathBuf::from("lib/ld-linux-riscv64-lp64d.so.1"),
        ),
        other => anyhow::bail!("no known glibc loader layout for arch {other}"),
    };
    const LIBS: [&str; 5] = [
        "libc.so.6",
        "libm.so.6",
        "libpthread.so.0",
        "libdl.so.2",
        "librt.so.1",
    ];
    let mut missing = Vec::new();

    let loader_dst = rootfs.join(&loader_rel);
    let loader_src = Path::new(loader);
    if Path::new(loader).is_file() {
        if let Some(parent) = loader_dst.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        std::fs::copy(loader_src, &loader_dst)
            .with_context(|| format!("failed to bundle {}", loader))?;
    } else {
        missing.push(loader.to_string());
    }

    let lib_dst = rootfs.join("usr/lib").join(triple);
    std::fs::create_dir_all(&lib_dst)
        .with_context(|| format!("failed to create {}", lib_dst.display()))?;
    let candidates = [
        PathBuf::from("/usr/lib").join(triple),
        PathBuf::from("/lib").join(triple),
    ];
    for name in LIBS {
        if lib_dst.join(name).is_file() {
            continue;
        }
        match candidates
            .iter()
            .map(|c| c.join(name))
            .find(|p| p.is_file())
        {
            Some(src) => {
                std::fs::copy(&src, lib_dst.join(name)).with_context(|| {
                    format!(
                        "failed to bundle {} from {} into rootfs",
                        name,
                        src.display()
                    )
                })?;
            }
            None => missing.push(name.to_string()),
        }
    }
    if verbose {
        let n = LIBS.len() + 1 - missing.len();
        eprintln!("[erebus] bundled {n} glibc base files into rootfs for binary payload");
    }
    if !missing.is_empty() {
        eprintln!(
            "[erebus] warning: base glibc files not found on this host: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_triple_is_sane() {
        let triple = host_gnu_triple();
        assert!(triple.contains("linux-gnu"), "triple: {triple}");
    }

    #[test]
    fn stage_model_puts_bytes_in_rootfs_before_compression() {
        let dir = tempfile::tempdir().unwrap();
        let model = dir.path().join("tiny.gguf");
        std::fs::write(&model, b"GGUF-model-bytes").unwrap();
        let rootfs = dir.path().join("rootfs");
        stage_model(&model, &rootfs).unwrap();
        assert_eq!(
            std::fs::read(rootfs.join("app/models/tiny.gguf")).unwrap(),
            b"GGUF-model-bytes"
        );
    }
}
