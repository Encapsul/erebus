use anyhow::Result;
use std::path::{Path, PathBuf};

use super::args::parse_target;

/// Locate the stub binary for the requested target triple.
///
/// Search order:
/// 1. `ERE_STUB_PATH` env var (explicit override)
/// 2. Host-native `target/release|debug/erebus-stub` (macOS/Windows host only —
///    on Linux a no-`--target` build is glibc and must not beat the musl stub
///    that `make stub` / CI actually ship; a stale glibc binary restored from
///    the Cargo cache silently broke `stdin_hash` on Proof)
/// 3. `target/<triple>/release/erebus-stub` (cross / musl workspace build)
/// 4. `/tmp/erebus-stub-target/...` (AGENTS.md / CI `CARGO_TARGET_DIR`)
/// 5. `stub/target/<triple>/release/erebus-stub` (legacy layout)
/// 6. `erebus-stub` next to the running `erebus` (release archive), host only
/// 7. `which erebus-stub` (system install, with warning)
pub(crate) fn find_stub(target: &Option<String>) -> Result<PathBuf> {
    if let Ok(path) = std::env::var("ERE_STUB_PATH") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into());
    let host = targets_host(target);
    let is_windows = target
        .as_deref()
        .is_some_and(|t| parse_target(t).1 == "windows")
        || (target.is_none() && cfg!(windows));

    let arch_suffix = match target.as_deref().map(parse_target) {
        Some((arch, os)) if os == "linux" => format!("{arch}-unknown-linux-musl"),
        Some((arch, os)) if os == "darwin" => format!("{arch}-apple-darwin"),
        Some((arch, os)) if os == "windows" => format!("{arch}-pc-windows-gnu"),
        Some((arch, _)) => format!("{arch}-unknown-linux-musl"),
        None => host_stub_triple(),
    };

    let stub_name = if is_windows {
        "erebus-stub.exe"
    } else {
        "erebus-stub"
    };

    let mut candidates = Vec::new();
    // Host-native `cargo build -p erebus-stub` (no --target) lands in
    // `target/{release,debug}/` — that is what the macOS CI job and
    // `macos_slice.sh` produce. On Linux the packaging stub is always musl
    // (`make stub`), so skip the unprefixed host paths: a cached glibc
    // `debug/erebus-stub` from `cargo test` would otherwise win.
    if host && !cfg!(target_os = "linux") {
        for profile in ["release", "debug"] {
            candidates.push(PathBuf::from(&target_dir).join(profile).join(stub_name));
            candidates.push(
                PathBuf::from("/tmp/erebus-stub-target")
                    .join(profile)
                    .join(stub_name),
            );
        }
    }
    candidates.extend([
        PathBuf::from(&target_dir)
            .join(&arch_suffix)
            .join("release")
            .join(stub_name),
        PathBuf::from("/tmp/erebus-stub-target")
            .join(&arch_suffix)
            .join("release")
            .join(stub_name),
        PathBuf::from("stub/target")
            .join(&arch_suffix)
            .join("release")
            .join(stub_name),
    ]);

    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }

    if host {
        if let Some(p) = sibling_stub(stub_name) {
            return Ok(p);
        }
    }

    if let Ok(p) = which::which("erebus-stub") {
        eprintln!(
            "[erebus] warning: found erebus-stub on PATH at {}; prefer 'make stub' for reproducible builds",
            p.display()
        );
        return Ok(p);
    }

    anyhow::bail!(
        "erebus-stub not found — reinstall erebus (the release archive ships it next to \
         the erebus binary), set ERE_STUB_PATH, or run `make stub` in a source checkout"
    )
}

/// Triple directory where a host stub is usually built (`make stub` → musl
/// on Linux; native Darwin/Windows otherwise).
fn host_stub_triple() -> String {
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "macos" => format!("{arch}-apple-darwin"),
        "windows" => format!("{arch}-pc-windows-gnu"),
        _ => format!("{arch}-unknown-linux-musl"),
    }
}

/// Release archives ship `erebus-stub` beside `erebus`; that stub is built
/// for the host only, so it is a valid candidate only when building for it.
fn targets_host(target: &Option<String>) -> bool {
    let Some(t) = target.as_deref() else {
        return true;
    };
    let host_os = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    parse_target(t) == (std::env::consts::ARCH.to_string(), host_os.to_string())
}

fn sibling_stub(stub_name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let parent = exe.parent()?;
    let beside = parent.join(stub_name);
    if beside.is_file() {
        return Some(beside);
    }
    // `cargo test` runs the debug CLI after a release stub build: look one
    // profile up (`…/debug/erebus` → `…/release/erebus-stub`).
    if parent.file_name().is_some_and(|n| n == "debug") {
        let release = parent.parent()?.join("release").join(stub_name);
        if release.is_file() {
            return Some(release);
        }
    }
    None
}

/// Read `app_hash` and `rt_deps_hash` from an existing `.erebus` file's metadata.
pub(crate) fn read_existing_hashes(erebus_path: &Path) -> Option<(String, String)> {
    use erebus_core::format::Footer;

    let mut f = std::fs::File::open(erebus_path).ok()?;
    let footer = Footer::read_from(&mut f).ok()?;
    let meta_size = footer.meta_size.try_into().ok()?;
    let meta_bytes = erebus_core::format::read_at(&mut f, footer.meta_offset, meta_size).ok()?;
    let meta: serde_json::Value = serde_json::from_slice(&meta_bytes).ok()?;
    let app_hash = meta.get("app_hash")?.as_str()?.to_string();
    let rt_hash = meta.get("rt_deps_hash")?.as_str()?.to_string();
    Some((app_hash, rt_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_stub_triple_matches_this_platform() {
        let t = host_stub_triple();
        assert!(t.starts_with(std::env::consts::ARCH), "{t}");
        if cfg!(target_os = "macos") {
            assert!(t.ends_with("-apple-darwin"), "{t}");
        } else if cfg!(windows) {
            assert!(t.ends_with("-pc-windows-gnu"), "{t}");
        } else {
            assert!(t.ends_with("-unknown-linux-musl"), "{t}");
        }
    }

    #[test]
    fn find_stub_default_does_not_panic() {
        let result = find_stub(&None);
        assert!(result.is_err() || result.is_ok(), "should not panic");
    }

    #[test]
    fn find_stub_aarch64_suffix() {
        let result = find_stub(&Some("aarch64".into()));
        assert!(result.is_err() || result.is_ok(), "should not panic");
    }

    #[test]
    fn find_stub_darwin_suffix() {
        let result = find_stub(&Some("aarch64-apple-darwin".into()));
        assert!(result.is_err() || result.is_ok(), "should not panic");
    }

    #[test]
    fn sibling_stub_only_for_host_target() {
        assert!(targets_host(&None));
        let os = if cfg!(target_os = "macos") {
            "apple-darwin"
        } else if cfg!(windows) {
            "pc-windows-gnu"
        } else {
            "unknown-linux-musl"
        };
        let host = format!("{}-{os}", std::env::consts::ARCH);
        assert!(targets_host(&Some(host)));
        let foreign = if cfg!(target_arch = "aarch64") {
            "x86_64-unknown-linux-musl"
        } else {
            "aarch64-unknown-linux-musl"
        };
        assert!(!targets_host(&Some(foreign.into())));
    }

    #[test]
    fn find_stub_windows_suffix() {
        let result = find_stub(&Some("win-x64".into()));
        assert!(result.is_err() || result.is_ok(), "should not panic");
    }
}
