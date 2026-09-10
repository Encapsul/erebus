use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// The llama engine source: either a local runtime directory (`.deps/llama`
/// layout with `llama-cli` + `libggml-cpu-*.so`) or a llama.cpp release build
/// number downloaded from GitHub.
#[derive(Debug, Clone)]
pub(crate) enum EngineSpec {
    Local(PathBuf),
    Download(u64),
}

/// Parse `--engine` / init values: `b<N>` downloads release build N, anything
/// else must be an existing runtime directory.
pub(crate) fn parse_engine(spec: &str) -> Result<EngineSpec> {
    let trimmed = spec.trim();
    if let Some(digits) = trimmed.strip_prefix('b') {
        let digits_valid = !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit());
        if digits_valid {
            let build = digits.parse::<u64>().ok();
            if build.is_some_and(|b| b > 0) {
                return Ok(EngineSpec::Download(build.unwrap()));
            }
        }
    }
    let path = PathBuf::from(trimmed);
    if path.is_dir() {
        return Ok(EngineSpec::Local(path));
    }
    anyhow::bail!(
        "--engine '{spec}' is neither an existing directory nor a llama.cpp build \
         (use 'b<N>', e.g. b10636)"
    )
}

/// Stage a llama engine into `dest` (payload `.deps/llama`), replacing anything
/// already staged or bundled there. Reuses the runtime + host-lib set proven in
/// examples/real-agent.
pub(crate) fn stage_engine(dest: &Path, spec: &EngineSpec) -> Result<()> {
    if dest.exists() {
        std::fs::remove_dir_all(dest)
            .with_context(|| format!("failed to clear {}", dest.display()))?;
    }
    std::fs::create_dir_all(&dest)
        .with_context(|| format!("failed to create {}", dest.display()))?;

    match spec {
        EngineSpec::Local(src) => copy_runtime(dest, src)?,
        EngineSpec::Download(build) => {
            let bytes = download_release(*build)?;
            unzip_release(dest, &bytes)?;
        }
    }
    copy_host_libs(dest)?;
    validate_runtime(dest)?;
    Ok(())
}

/// Hash of the engine source so the build cache invalidates when a local
/// `--engine` dir changes or the download build number changes.
pub(crate) fn engine_fingerprint(spec: &EngineSpec) -> String {
    match spec {
        EngineSpec::Local(p) => erebus_core::include::hash_app_files(p),
        EngineSpec::Download(build) => format!("b{build}"),
    }
}

fn copy_runtime(dst: &Path, src: &Path) -> Result<()> {
    if !src.join("llama-cli").is_file() {
        anyhow::bail!(
            "{} is not a llama runtime dir: expected a llama-cli binary",
            src.display()
        );
    }
    let mut n = 0u32;
    for entry in walkdir::WalkDir::new(src).max_depth(1).min_depth(1) {
        let e = entry.with_context(|| format!("failed to read runtime dir {}", src.display()))?;
        let to = dst.join(e.file_name());
        if e.file_type().is_symlink() {
            let target = std::fs::read_link(e.path())
                .with_context(|| format!("failed to read symlink {}", e.path().display()))?;
            restage_symlink(&to, target.as_os_str())?;
            n += 1;
        } else if e.file_type().is_file() {
            std::fs::copy(e.path(), &to).with_context(|| {
                format!("failed to copy {} to {}", e.path().display(), to.display())
            })?;
            n += 1;
        }
    }
    eprintln!("[erebus] copied {n} files from runtime {}", src.display());
    Ok(())
}

/// Recreate a llama runtime symlink (libllama.so -> libllama.so.0 -> …). The
/// loader resolves by SONAME, so staging must keep the chain intact; skipping
/// it makes llama-cli fail with "cannot open shared object file".
#[cfg(unix)]
fn restage_symlink(to: &Path, target: &std::ffi::OsStr) -> Result<()> {
    std::os::unix::fs::symlink(target, to).with_context(|| {
        format!(
            "failed to recreate symlink {} -> {}",
            to.display(),
            target.to_string_lossy()
        )
    })
}

#[cfg(not(unix))]
fn restage_symlink(_to: &Path, _target: &std::ffi::OsStr) -> Result<()> {
    Ok(())
}

fn release_arch() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x64"),
        "aarch64" => Ok("aarch64"),
        other => anyhow::bail!("no llama.cpp ubuntu-{other} release exists"),
    }
}

fn download_release(build: u64) -> Result<Vec<u8>> {
    let arch = release_arch()?;
    let url = format!(
        "https://github.com/ggml-org/llama.cpp/releases/download/b{build}/llama-b{build}-bin-ubuntu-{arch}.zip"
    );
    eprintln!("[erebus] downloading llama.cpp runtime: {url}");
    let resp = reqwest::blocking::get(&url)
        .with_context(|| format!("failed to download llama.cpp runtime from {url}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("llama.cpp runtime download failed: HTTP {}", resp.status());
    }
    let bytes = resp
        .bytes()
        .context("failed to read downloaded llama.cpp runtime")?;
    Ok(bytes.to_vec())
}

fn unzip_release(dir: &Path, bytes: &[u8]) -> Result<()> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))
        .context("downloaded llama.cpp runtime is not a valid zip")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("failed to read zip entry")?;
        let out = dir.join(entry.mangled_name());
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // The llama release zips ship the .so version chain as symlinks
        // (libllama.so -> libllama.so.0 -> libllama.so.0.3.0); the loader
        // resolves by SONAME so the intermediate link must survive staging.
        if entry.is_symlink() {
            #[cfg(unix)]
            {
                let target = {
                    let mut buf = Vec::with_capacity(entry.size() as usize);
                    std::io::copy(&mut entry, &mut buf)?;
                    String::from_utf8_lossy(&buf).into_owned()
                };
                std::os::unix::fs::symlink(&target, &out)?;
                continue;
            }
            #[cfg(not(unix))]
            {
                continue;
            }
        }
        let mut f = std::fs::File::create(&out)?;
        std::io::copy(&mut entry, &mut f)?;
    }
    Ok(())
}

fn host_gnu_triple() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        "riscv64" => "riscv64-linux-gnu",
        other => other,
    }
}

/// Bundle the host's glibc runtime libs llama-cli dlopens at run time. The
/// sandbox (`pivot_root`) exposes nothing from /lib, so without these the
/// bundle fails at exec inside the sandbox. Missing libs are only a warning:
/// the bundle still builds, but will not exec in the sandbox until they are
/// provided.
fn copy_host_libs(dir: &Path) -> Result<()> {
    let triple = host_gnu_triple();
    let mut candidates = vec![
        PathBuf::from("/lib").join(triple),
        PathBuf::from("/usr/lib").join(triple),
    ];
    if cfg!(target_arch = "x86_64") {
        candidates.push(PathBuf::from("/lib64"));
    }
    const LIBS: [&str; 5] = [
        "libssl.so.3",
        "libcrypto.so.3",
        "libstdc++.so.6",
        "libgcc_s.so.1",
        "libgomp.so.1",
    ];
    let mut missing = Vec::new();
    let mut copied = 0u32;
    for name in LIBS {
        if dir.join(name).is_file() {
            continue;
        }
        match candidates
            .iter()
            .map(|c| c.join(name))
            .find(|p| p.is_file())
        {
            Some(src) => {
                std::fs::copy(&src, dir.join(name)).with_context(|| {
                    format!(
                        "failed to bundle {} from {} into .deps",
                        name,
                        src.display()
                    )
                })?;
                copied += 1;
            }
            None => missing.push(name),
        }
    }
    if copied > 0 {
        eprintln!("[erebus] bundled {copied} host runtime libs into .deps/llama");
    }
    if !missing.is_empty() {
        eprintln!(
            "[erebus] warning: not found on this host — copy from a matching distro: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn validate_runtime(dir: &Path) -> Result<()> {
    if !dir.join("llama-cli").is_file() {
        anyhow::bail!("llama runtime missing llama-cli: {}", dir.display());
    }
    let backends: Vec<_> = walkdir::WalkDir::new(dir)
        .max_depth(1)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("libggml-cpu-"))
        .collect();
    if backends.is_empty() {
        anyhow::bail!(
            "llama runtime missing any libggml-cpu-*.so backend: {}",
            dir.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_runtime(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("llama-cli"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.join("libllama-data.so.0.3.0"), b"ELF").unwrap();
        std::fs::write(dir.join("libggml-cpu-x64.so"), b"ELF").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("libllama-data.so.0.3.0", dir.join("libllama-data.so.0"))
            .unwrap();
    }

    #[test]
    fn stage_engine_local_preserves_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("runtime");
        fake_runtime(&src);
        let dest = dir.path().join("llama");
        stage_engine(&dest, &EngineSpec::Local(src.clone())).unwrap();

        assert!(dest.join("llama-cli").is_file());
        assert!(dest.join("libllama-data.so.0.3.0").is_file());
        assert!(dest.join("libggml-cpu-x64.so").is_file());
        #[cfg(unix)]
        {
            assert!(
                dest.join("libllama-data.so.0").is_symlink(),
                "the .so version chain must survive staging"
            );
            assert_eq!(
                std::fs::read_link(dest.join("libllama-data.so.0")).unwrap(),
                Path::new("libllama-data.so.0.3.0")
            );
        }
        // host glibc libs bundled so llama-cli execs inside the sandbox
        assert!(dest.join("libstdc++.so.6").is_file());
    }

    #[test]
    fn stage_engine_replaces_existing_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("runtime");
        fake_runtime(&src);
        let dest = dir.path().join("llama");
        std::fs::create_dir_all(dest.join("stale")).unwrap();
        std::fs::write(dest.join("old-model.gguf"), b"OLD").unwrap();

        stage_engine(&dest, &EngineSpec::Local(src)).unwrap();

        assert!(!dest.join("stale").exists(), "old bundle fully replaced");
        assert!(!dest.join("old-model.gguf").exists());
        assert!(dest.join("llama-cli").is_file());
    }

    #[test]
    fn stage_engine_rejects_bad_spec() {
        let err = parse_engine("/nonexistent/runtime")
            .unwrap_err()
            .to_string();
        assert!(err.contains("neither an existing directory"));
        // a valid build spec is accepted without touching the network
        assert!(matches!(
            parse_engine("b10636").unwrap(),
            EngineSpec::Download(10636)
        ));
        let err = parse_engine("b0").unwrap_err().to_string();
        assert!(
            err.contains("neither"),
            "b0 must not be a valid build: {err}"
        );
    }
}
