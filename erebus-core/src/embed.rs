//! Runtime embedder: locates and bundles interpreters, package managers,
//! native libraries, and framework-specific files into the payload.
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Embed an interpreter and its shared library dependencies into a rootfs.
///
/// Returns the number of files copied (interpreter + shared libs + config).
pub fn embed_interpreter(
    interpreter: &str,
    rootfs: &Path,
    app_dir: Option<&Path>,
    verbose: bool,
) -> io::Result<usize> {
    let interp_path = find_interpreter(interpreter).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("interpreter '{interpreter}' not found on PATH"),
        )
    })?;

    if verbose {
        eprintln!("  embed: interpreter found at {}", interp_path.display());
    }

    let mut count = 0;

    // Copy the interpreter binary to rootfs/usr/bin/, keeping the source
    // filename so a Windows `python.exe` lands as `python.exe` (CreateProcessW
    // resolves the bare name via PATH and appends `.exe`).
    let bin_dir = rootfs.join("usr/bin");
    fs::create_dir_all(&bin_dir)?;
    let dest_name = interp_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new(interpreter));
    let dest_bin = bin_dir.join(dest_name);
    fs::copy(&interp_path, &dest_bin)?;
    count += 1;

    // Set executable permission
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dest_bin, fs::Permissions::from_mode(0o755))?;
    }

    if verbose {
        eprintln!("  embed: copied {interpreter} to {}", dest_bin.display());
    }

    // Find and copy shared library dependencies via ldd
    let deps = ldd_deps(&interp_path)?;
    let mut seen = HashSet::new();
    let lib_dirs = resolve_lib_dirs(rootfs);

    for lib_path in &deps {
        let name = match lib_path.file_name() {
            Some(n) => n,
            None => continue,
        };
        let name_str = name.to_string_lossy();
        if !seen.insert(name_str.to_string()) {
            continue;
        }

        // Determine destination directory based on source path
        let dest_dir = find_lib_dest(lib_path, &lib_dirs);
        fs::create_dir_all(&dest_dir)?;
        let dest_lib = dest_dir.join(name);

        let _ = fs::remove_file(&dest_lib);
        // SAFETY: always copy the dereferenced file content, never preserve
        // symlinks as-is. Host symlinks (e.g. libstdc++.so.6 ->
        // libstdc++.so.6.0.33) would be broken in rootfs because the
        // symlink target is never separately embedded. fs::copy follows
        // symlinks and writes the real file content under the SONAME name,
        // keeping the dynamic linker's NEEDED lookup working.
        fs::copy(lib_path, &dest_lib)?;
        count += 1;

        if verbose {
            eprintln!("  embed: lib {} -> {}", name_str, dest_dir.display());
        }
    }

    // Copy the ELF interpreter (dynamic loader) so the embedded binary can
    // be exec'd under `pivot_root` isolation, where the host /lib64 is gone.
    if let Some(loader) = elf_interpreter_path(&interp_path)? {
        let dest = rootfs.join(loader.strip_prefix("/").unwrap_or(&loader));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&loader, &dest)?;
        count += 1;
        if verbose {
            eprintln!(
                "  embed: ELF interpreter {} -> {}",
                loader.display(),
                dest.display()
            );
        }
    }

    // Copy runtime-specific config (stdlib paths, etc.)
    count += embed_runtime_config(interpreter, &interp_path, rootfs, app_dir, verbose)?;

    Ok(count)
}

/// Find the interpreter binary on the system PATH.
fn find_interpreter(name: &str) -> Option<PathBuf> {
    // Cross-compilation: the target runtime is staged as `<name>.exe` in a
    // tools dir prepended to PATH (e.g. `python.exe` for a win-x64 build), so
    // try the suffixed form first — it wins over any host interpreter and is
    // a no-op miss on POSIX hosts that have no `.exe` binaries on PATH.
    let candidates = [format!("{name}.exe"), name.to_string()];
    for candidate in candidates {
        let output = Command::new("which").arg(&candidate).output().ok()?;
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }
    None
}

/// Parse `ldd` output to find shared library paths for a binary.
pub(crate) fn ldd_deps(interp_path: &Path) -> io::Result<Vec<PathBuf>> {
    let output = Command::new("ldd")
        .arg(interp_path)
        .output()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ldd failed: {e}")))?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut deps = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        // Skip empty lines, vdso, and ld-linux dynamic linker (handled separately)
        if line.is_empty() || line.starts_with("linux-vdso") {
            continue;
        }

        let path_str = if let Some(after) = line.split("=>").nth(1) {
            // glibc format: "libfoo.so.1 => /path/libfoo.so.1 (0x...)"
            after.trim()
        } else if line.starts_with('/') {
            // musl format: "/path/libfoo.so.1" (no => prefix)
            line
        } else {
            continue;
        };

        // Skip the dynamic linker (ld-linux, ld-musl) — it's not a library dep
        let fname = path_str.rsplit('/').next().unwrap_or(path_str);
        if fname.starts_with("ld-linux") || fname.starts_with("ld-musl") {
            continue;
        }

        // Remove the address part: "(0x...)"
        let path_str = if let Some(idx) = path_str.find(" (") {
            &path_str[..idx]
        } else {
            path_str
        };
        let path_str = path_str.trim();
        if !path_str.starts_with('/') || path_str == "not found" {
            continue;
        }
        deps.push(PathBuf::from(path_str));
    }

    Ok(deps)
}

/// Extract the ELF interpreter (dynamic loader) path from a single `ldd`
/// output line. The loader line has no `=>`, e.g.
/// `/lib64/ld-linux-x86-64.so.2 (0x00007f...)`.
fn parse_loader_line(line: &str) -> Option<PathBuf> {
    let line = line.trim();
    if !line.starts_with('/') || line.contains("=>") {
        return None;
    }
    let path_str = line.split('(').next()?.trim();
    if path_str.contains("ld-linux") || path_str.contains("ld-musl") {
        Some(PathBuf::from(path_str))
    } else {
        None
    }
}

/// Locate the ELF interpreter required by `interp_path` (e.g. glibc's
/// `/lib64/ld-linux-x86-64.so.2`). Without it in the rootfs, the kernel
/// cannot exec the embedded binary under `pivot_root` isolation.
fn elf_interpreter_path(interp_path: &Path) -> io::Result<Option<PathBuf>> {
    let output = Command::new("ldd")
        .arg(interp_path)
        .output()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ldd failed: {e}")))?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(parse_loader_line))
}
fn resolve_lib_dirs(rootfs: &Path) -> Vec<PathBuf> {
    let arch = std::env::consts::ARCH;
    let arch_dir = match arch {
        "x86_64" => "x86_64-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        _ => "",
    };

    let mut dirs = vec![
        rootfs.join("lib"),
        rootfs.join("lib64"),
        rootfs.join("usr/lib"),
        rootfs.join("usr/lib64"),
    ];

    if !arch_dir.is_empty() {
        dirs.push(rootfs.join("usr/lib").join(arch_dir));
        dirs.push(rootfs.join("lib").join(arch_dir));
    }

    dirs
}

/// Find the best destination directory for a shared library.
///
/// Passes through known multiarch subdirectories (e.g. `x86_64-linux-gnu`) so
/// that libraries resolved from `/lib/x86_64-linux-gnu` or
/// `/usr/lib/x86_64-linux-gnu` end up in the corresponding rootfs subdirectory
/// that `LD_LIBRARY_PATH` searches.  Without this the previous `exists()`-based
/// probe always fell back to `usr/lib` on a fresh build, placing multiarch libs
/// outside the dynamic linker's search path.
fn find_lib_dest(lib_path: &Path, lib_dirs: &[PathBuf]) -> PathBuf {
    if let Some(name) = lib_path.file_name() {
        for dir in lib_dirs {
            let candidate = dir.join(name);
            if candidate.exists() || candidate.symlink_metadata().is_ok() {
                return dir.clone();
            }
        }
    }

    const MULTIARCH_SUBDIRS: &[&str] = &["x86_64-linux-gnu", "aarch64-linux-gnu"];
    if let Some(_name) = lib_path.file_name() {
        let lib_path_str = lib_path.to_string_lossy();
        for subdir in MULTIARCH_SUBDIRS {
            let marker = format!("/{subdir}/");
            if let Some(_pos) = lib_path_str.find(&marker) {
                let dest = lib_dirs
                    .iter()
                    .find(|d| d.ends_with(subdir))
                    .cloned()
                    .unwrap_or_else(|| lib_dirs.get(2).cloned().unwrap_or_default());
                let _ = std::fs::create_dir_all(&dest);
                return dest;
            }
        }
    }

    lib_dirs
        .get(2)
        .cloned()
        .unwrap_or_else(|| PathBuf::from("/usr/lib"))
}

/// Embed runtime-specific configuration (e.g. stdlib paths for Python).
fn embed_runtime_config(
    interpreter: &str,
    interp_path: &Path,
    rootfs: &Path,
    _app_dir: Option<&Path>,
    verbose: bool,
) -> io::Result<usize> {
    let mut count = 0;

    if matches!(interpreter, "python3" | "python") {
        count += embed_python_config(interp_path, rootfs, verbose)?;
    }

    Ok(count)
}

/// Embed Python configuration (standard library modules).
fn embed_python_config(interp_path: &Path, rootfs: &Path, verbose: bool) -> io::Result<usize> {
    let mut count = 0;

    // Find Python stdlib path using sysconfig (correct version-tagged directory)
    let stdlib = run_cmd(
        interp_path,
        &[
            "-c",
            "import sysconfig; print(sysconfig.get_path('stdlib'))",
        ],
    );
    if stdlib.is_empty() {
        return Ok(0);
    }

    let stdlib_path = PathBuf::from(&stdlib);
    if stdlib_path.is_dir() {
        let target = rootfs
            .join("usr")
            .join("lib")
            .join(stdlib_path.file_name().unwrap_or(stdlib_path.as_os_str()));
        copy_dir_recursive(&stdlib_path, &target)?;
        count += count_dir_files(&target);
        if verbose {
            eprintln!(
                "  embed: copied Python stdlib ({} files)",
                count_dir_files(&target)
            );
        }
    }

    Ok(count)
}

fn run_cmd(program: &Path, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Scan `rootfs/app/node_modules/` for `.node` files (N-API native addons),
/// run `ldd` on each, and embed their shared library dependencies into the rootfs.
fn count_dir_files(dir: &Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                count += count_dir_files(&entry.path());
            } else {
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_loader_line_glibc() {
        let line = "/lib64/ld-linux-x86-64.so.2 (0x00007f1234567890)";
        assert_eq!(
            parse_loader_line(line),
            Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2"))
        );
    }

    #[test]
    fn parse_loader_line_musl() {
        let line = "/lib/ld-musl-x86_64.so.1 (0x7f...)";
        assert_eq!(
            parse_loader_line(line),
            Some(PathBuf::from("/lib/ld-musl-x86_64.so.1"))
        );
    }

    #[test]
    fn parse_loader_line_rejects_regular_deps() {
        assert_eq!(
            parse_loader_line("libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x...)"),
            None
        );
        assert_eq!(parse_loader_line("linux-vdso.so.1 (0x...)"), None);
        assert_eq!(parse_loader_line("not found"), None);
    }

    #[test]
    fn count_dir_files_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(count_dir_files(dir.path()), 0);
    }

    #[test]
    fn count_dir_files_nested() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "a").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("b.txt"), "b").unwrap();
        assert_eq!(count_dir_files(dir.path()), 2);
    }
}
