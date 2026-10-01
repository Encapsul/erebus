//! Process execution for the erebus launcher stub.
//!
//! Provides single-service exec, multi-service supervisor, entrypoint
//! resolution, environment setup, and platform-specific process spawning.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::ffi::CString;
use std::io;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::config::AppConfig;
use crate::Metadata;
#[cfg(unix)]
use crate::{cstr, to_ptr_vec};
use erebus_core::detect;
#[cfg(unix)]
use erebus_core::layer::Capability;
/// Enter user + mount namespace if isolation >= 2; no-op otherwise.
/// No-op on non-Linux platforms (no namespaces available).
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub fn enter_namespace_if_needed(isolation: u8) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    if isolation >= 2 {
        crate::namespace::enter_userns()?;
    }
    Ok(())
}

/// Build the process environment: host env + `LD_LIBRARY_PATH` + meta.env + `ROOTFS` substitution.
/// When `orig_cwd` is Some, inserts `ERE_ORIG_CWD` (used by single-service exec).
pub fn setup_env(
    meta: &Metadata,
    rootfs: &Path,
    use_pivot: bool,
    orig_cwd: Option<&Path>,
    app_config: &AppConfig,
) -> io::Result<BTreeMap<String, String>> {
    let mut env: BTreeMap<String, String> = std::env::vars().collect();

    // LD_LIBRARY_PATH only matters for ELF dynamic linking; on macOS/Windows
    // the OS loader resolves system libs on its own.
    #[cfg(unix)]
    {
        if use_pivot {
            env.insert("LD_LIBRARY_PATH".into(), crate::LD_PATHS_ABS.join(":"));
        } else {
            let mut paths: Vec<String> = crate::LD_PATHS
                .iter()
                .map(|p| rootfs.join(p))
                .filter(|p| p.exists())
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            if let Some(existing) = env.get("LD_LIBRARY_PATH") {
                if !existing.is_empty() {
                    let existing_entries: Vec<String> = existing
                        .split(':')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    for entry in &existing_entries {
                        if !paths.iter().any(|p| p == entry) {
                            paths.push(entry.clone());
                        }
                    }
                }
            }
            env.insert("LD_LIBRARY_PATH".into(), paths.join(":"));
        }
    }

    // PATH: bundled binaries (usr/bin, bin, usr/local/bin) before system PATH.
    if use_pivot {
        env.insert("PATH".into(), crate::BIN_PATHS_ABS.join(":"));
    } else {
        let mut paths: Vec<String> = crate::BIN_PATHS
            .iter()
            .map(|p| rootfs.join(p))
            .filter(|p| p.exists())
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        if let Some(existing) = env.get("PATH") {
            if !existing.is_empty() {
                paths.push(existing.clone());
            }
        }
        let sep = if cfg!(windows) { ";" } else { ":" };
        env.insert("PATH".into(), paths.join(sep));
    }

    if let Some(cwd) = orig_cwd {
        env.insert("ERE_ORIG_CWD".into(), cwd.to_string_lossy().into_owned());
    }

    // App-bundled `.env` is the LOWEST-priority source: every explicit
    // override below (meta.env, config secrets, DATABASE_URL) wins on
    // collision, so a packaged `.env` can't silently shadow operator config.
    for (k, v) in erebus_core::dotenv::load_dotenv(rootfs, None, false) {
        env.entry(k).or_insert(v);
    }

    let rootfs_str = rootfs.to_string_lossy();
    for (k, v) in &meta.env {
        env.insert(k.clone(), v.replace("${ROOTFS}", &rootfs_str));
    }

    // Merge secrets from config file
    if let Some(secrets) = &app_config.secrets {
        for (k, v) in secrets {
            env.insert(format!("ERE_SECRET_{}", k.to_uppercase()), v.clone());
        }
    }

    // Merge database URL from config
    if let Some(url) = app_config.get_database_url() {
        env.insert("DATABASE_URL".into(), url);
    }

    // Framework-specific defaults (fill gaps only — .env and operator config win).
    // Uses the effective runtime so layer-based binaries get the right defaults.
    if meta.effective_runtime() == "python" {
        if !env.contains_key("PYTHONUNBUFFERED") {
            env.insert("PYTHONUNBUFFERED".into(), "1".into());
        }
        if !env.contains_key("DJANGO_SETTINGS_MODULE") {
            if let Some(settings) = detect_django_settings(rootfs) {
                env.insert("DJANGO_SETTINGS_MODULE".into(), settings);
            }
        }
    }

    // Ensure PORT is set for web frameworks
    if !env.contains_key("PORT") {
        if let Some(port) = detect_web_port(rootfs, meta.effective_runtime()) {
            env.insert("PORT".into(), port.to_string());
        }
    }

    // Add native library directories to LD_LIBRARY_PATH
    #[cfg(unix)]
    {
        use walkdir::WalkDir;
        let mut lib_dirs = Vec::new();
        for entry in WalkDir::new(rootfs).max_depth(3).into_iter().flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                    let is_so = ext == "so"
                        || p.file_name()
                            .map(|n| n.to_string_lossy().contains(".so."))
                            .unwrap_or(false);
                    if is_so || ext == "dylib" {
                        if let Some(parent) = p.parent() {
                            if parent != rootfs {
                                lib_dirs.push(parent.to_string_lossy().into_owned());
                            }
                        }
                    }
                }
            }
        }
        lib_dirs.sort();
        lib_dirs.dedup();
        if !lib_dirs.is_empty() {
            let existing = env.get("LD_LIBRARY_PATH").map(String::as_str).unwrap_or("");
            let mut paths: Vec<String> = lib_dirs;
            if !existing.is_empty() {
                for entry in existing.split(':') {
                    if !entry.is_empty() && !paths.contains(&entry.to_string()) {
                        paths.push(entry.to_string());
                    }
                }
            }
            env.insert("LD_LIBRARY_PATH".into(), paths.join(":"));
        }
    }

    // Ensure writable directories exist for apps that need them (DB, temp files)
    for dir in &["/app/data", "/app/tmp"] {
        let path = if use_pivot {
            PathBuf::from(dir)
        } else {
            rootfs.join(dir.strip_prefix('/').unwrap_or(dir))
        };
        if let Err(e) = std::fs::create_dir_all(&path) {
            eprintln!("[erebus] warning: could not create {}: {e}", path.display());
        }
    }

    // GPU facts for inference apps (ERE_GPU / ERE_VRAM_MB / ERE_NGL);
    // payload-pinned keys always win over runtime probes.
    crate::gpu::apply(&mut env, meta);

    Ok(env)
}

/// Detect Django settings module from manage.py or settings.py layout.
pub fn detect_django_settings(app_dir: &Path) -> Option<String> {
    if let Ok(content) = std::fs::read_to_string(app_dir.join("manage.py")) {
        if let Some(line) = content
            .lines()
            .find(|l| l.contains("DJANGO_SETTINGS_MODULE"))
        {
            if let Some(module) = line.split("DJANGO_SETTINGS_MODULE").nth(1) {
                let module = module.trim();
                // Use rfind to locate the VALUE's closing quote. After splitting
                // on "DJANGO_SETTINGS_MODULE", the first quote in the remainder
                // is often the closing quote of the key argument (e.g. `setdefault("KEY", "value")`).
                // We want the last pair of matching quotes — that's the value.
                if let Some(close) = module.rfind('"') {
                    if let Some(open) = module[..close].rfind('"') {
                        return Some(module[open + 1..close].to_string());
                    }
                }
                if let Some(close) = module.rfind('\'') {
                    if let Some(open) = module[..close].rfind('\'') {
                        return Some(module[open + 1..close].to_string());
                    }
                }
                let module = module
                    .trim_start_matches(|c: char| c == '=' || c.is_whitespace())
                    .trim_end_matches(|c: char| c == ')' || c == ',' || c.is_whitespace());
                if !module.is_empty() {
                    return Some(module.to_string());
                }
            }
        }
    }
    // Fallback: look for settings.py in a package directory
    if let Ok(entries) = std::fs::read_dir(app_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() && p.join("__init__.py").is_file() && p.join("settings.py").is_file() {
                let pkg = p.file_name()?.to_str()?;
                return Some(format!("{pkg}.settings"));
            }
        }
    }
    None
}

/// Detect default web port from app configuration files.
pub fn detect_web_port(app_dir: &Path, runtime: &str) -> Option<u16> {
    if runtime == "python" {
        if app_dir.join("manage.py").is_file() {
            return Some(8000);
        }
        if let Ok(content) = std::fs::read_to_string(app_dir.join("requirements.txt")) {
            if content.contains("streamlit") {
                return Some(8501);
            }
            if content.contains("gradio") {
                return Some(7860);
            }
        }
    }
    None
}

/// Resolve a rootfs path: absolute if using `pivot_root`, relative to rootfs otherwise.
pub fn make_resolve<'a>(rootfs: &'a Path, use_pivot: bool) -> impl Fn(&str) -> PathBuf + 'a {
    move |p: &str| -> PathBuf {
        if use_pivot {
            PathBuf::from(p)
        } else if let Some(stripped) = p.strip_prefix('/') {
            rootfs.join(stripped)
        } else {
            PathBuf::from(p)
        }
    }
}

/// Expand `$VAR` / `${VAR}` placeholders in an argv argument from the child env.
///
/// Returns `None` when a referenced variable is unset so the caller can drop
/// the argument (e.g. `-Dserver.port=$PORT` for a Java app with no web port).
pub fn expand_env_arg(arg: &str, env: &BTreeMap<String, String>) -> Option<String> {
    if !arg.contains('$') {
        return Some(arg.to_string());
    }
    let mut out = String::with_capacity(arg.len());
    let mut rest = arg;
    while let Some(idx) = rest.find('$') {
        out.push_str(&rest[..idx]);
        rest = &rest[idx + 1..];
        if rest.starts_with('{') {
            let Some(end) = rest.find('}') else {
                // Unbalanced `${` — keep the literal as-is.
                out.push_str(rest);
                rest = "";
                break;
            };
            out.push_str(env.get(&rest[1..end])?);
            rest = &rest[end + 1..];
        } else {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let name = &rest[..end];
            if name.is_empty() {
                // Trailing `$` — keep it literal.
                out.push('$');
            } else {
                out.push_str(env.get(name)?);
            }
            rest = &rest[end..];
        }
    }
    out.push_str(rest);
    Some(out)
}

// ---------------------------------------------------------------------------
// Unix exec helpers
// ---------------------------------------------------------------------------

/// Convert a `BTreeMap<String,String>` to a null-terminated `Vec<CString>` for execve.
#[cfg(unix)]
pub fn env_to_cstrings(env: &BTreeMap<String, String>) -> io::Result<Vec<CString>> {
    env.iter()
        .map(|(k, v)| cstr(format!("{k}={v}").as_bytes()))
        .collect()
}

/// Check if an executable path exists and is executable.
/// Searches PATH directories when given a bare name (no directory component).
#[cfg(unix)]
pub fn is_executable(prog: &[u8]) -> bool {
    if prog.is_empty() {
        return false;
    }
    let path = match std::str::from_utf8(prog) {
        Ok(s) => s,
        Err(_) => return false,
    };
    // If it's an absolute or relative path with a directory component, check it directly.
    if path.contains('/') || path.contains('\\') {
        return check_executable(path);
    }
    // Otherwise search PATH directories (mirrors execvp behavior).
    let paths = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(std::path::Path::new(path));
        if check_executable(&candidate.to_string_lossy()) {
            return true;
        }
    }
    false
}

/// Check if a specific path points to an executable file.
pub fn check_executable(path: &str) -> bool {
    std::fs::metadata(path).is_ok_and(|m| {
        m.is_file() && {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o111 != 0
            }
            #[cfg(windows)]
            {
                true
            }
        }
    })
}

/// Whether `prog` is runnable: on the host PATH or, for a bare interpreter
/// name, inside the rootfs bin dirs (embedded-interpreter case). With
/// `pivot_root` the rootfs PATH takes over before `execvp`, so a rootfs-only
/// interpreter must pass the pre-flight even when the host lacks the runtime.
#[cfg(unix)]
fn entrypoint_is_executable(prog: &[u8], interpreter_name: &str, rootfs: &Path) -> bool {
    if is_executable(prog) {
        return true;
    }
    // Absolute/relative paths can't fall back to the rootfs search.
    if prog.contains(&b'/') {
        return false;
    }
    crate::BIN_PATHS.iter().any(|dir| {
        let candidate = rootfs.join(dir).join(interpreter_name);
        check_executable(&candidate.to_string_lossy())
    })
}

// ---------------------------------------------------------------------------
// Single-service exec
// ---------------------------------------------------------------------------

/// Bind-mount X11, Wayland, and GPU devices into the rootfs before
/// `pivot_root`. Each path is created with `mkdir -p` then `mount MS_BIND`.
///
/// Source paths are best-effort: non-existent sources (e.g. no Wayland
/// socket) are silently skipped. This lets the same binary run on X11-only,
/// Wayland-only, or mixed systems.
#[cfg(target_os = "linux")]
fn bind_mount_gui_devices(rootfs: &Path) -> io::Result<()> {
    // SAFETY: getuid(2) returns the real UID of the calling process. It
    // cannot fail and has no invalid inputs.
    let uid = unsafe { libc::getuid() };
    let run_user = format!("/run/user/{uid}");

    // (host_path, rootfs_relative_dest) pairs to bind-mount.
    let mounts: &[(&str, &str)] = &[("/tmp/.X11-unix", ".X11-unix"), ("/dev/dri", "dev/dri")];

    for (src, dest_rel) in mounts {
        let dest = rootfs.join(dest_rel);
        if !Path::new(src).exists() {
            continue;
        }
        std::fs::create_dir_all(&dest)?;
        let src_c = crate::cstr(src.as_bytes())?;
        let dest_c = crate::cstr(dest.as_os_str().as_bytes())?;
        // SAFETY: mount(2) with MS_BIND makes a 1:1 bind mount of the host
        // GUI socket/GPU device into the rootfs. Source and destination are
        // valid paths; no data pointer needed for bind mounts.
        let rc = unsafe {
            libc::mount(
                src_c.as_ptr(),
                dest_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            eprintln!(
                "[erebus] warning: failed to bind-mount {} → {}: {}",
                src,
                dest.display(),
                io::Error::last_os_error()
            );
        }
    }

    // Wayland sockets glob /run/user/$UID/.wayland-*
    if Path::new(&run_user).is_dir() {
        let dest_dir = rootfs.join(&run_user);
        if let Ok(entries) = std::fs::read_dir(&run_user) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if !name.starts_with("wayland-") && !name.starts_with(".wayland-") {
                    continue;
                }
                let src = entry.path();
                let dest = dest_dir.join(std::ffi::OsStr::new(&*name));
                std::fs::create_dir_all(&dest)?;
                let src_c = crate::cstr(src.to_string_lossy().as_bytes())?;
                let dest_c = crate::cstr(dest.as_os_str().as_bytes())?;
                // SAFETY: bind-mount a single Wayland socket into rootfs.
                let rc = unsafe {
                    libc::mount(
                        src_c.as_ptr(),
                        dest_c.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                };
                if rc != 0 {
                    eprintln!(
                        "[erebus] warning: failed to bind-mount {}: {}",
                        src.display(),
                        io::Error::last_os_error()
                    );
                }
            }
        }
    }

    // GPU render nodes (dri/card*)
    if Path::new("/dev/dri").is_dir() {
        let src_dir = "/dev/dri";
        let dest_dir = rootfs.join("dev/dri");
        std::fs::create_dir_all(&dest_dir)?;
        if let Ok(entries) = std::fs::read_dir(src_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                // Only bind-mount render nodes and control nodes
                if !name.starts_with("renderD") && !name.starts_with("card") {
                    continue;
                }
                let src = format!("{src_dir}/{name}");
                let dest = dest_dir.join(std::ffi::OsStr::new(&*name));
                let src_c = crate::cstr(src.as_bytes())?;
                let dest_c = crate::cstr(dest.as_os_str().as_bytes())?;
                // SAFETY: bind-mount GPU device node into rootfs.
                let rc = unsafe {
                    libc::mount(
                        src_c.as_ptr(),
                        dest_c.as_ptr(),
                        std::ptr::null(),
                        libc::MS_BIND,
                        std::ptr::null(),
                    )
                };
                if rc != 0 {
                    eprintln!(
                        "[erebus] warning: failed to bind-mount GPU device {}: {}",
                        src,
                        io::Error::last_os_error()
                    );
                }
            }
        }
    }

    // Ensure /dev/shm is available for X11 shared memory
    if !rootfs.join("dev/shm").is_dir() {
        std::fs::create_dir_all(rootfs.join("dev/shm"))?;
    }

    Ok(())
}

/// Provision a minimal `/dev` (tmpfs + standard char devices) and a
/// read-only `/proc` inside the rootfs, before `pivot_root`.
///
/// Statically-linked payloads and Go use `getrandom(2)` directly, but JS
/// runtimes (Bun, Node) open `/dev/urandom` and `/proc/self/maps` at startup;
/// without them the exec succeeds yet the runtime crashes first thing (Bun
/// segfaults on its GC canary). Host paths become unreachable after
/// `pivot_root`, so apps can only ever see this synthetic device set.
/// Device nodes are bind-mounted (creating them via `mknod` is blocked by
/// kernel hardening in unprivileged user namespaces); bind failures warn
/// instead of aborting so payloads that never touch `/dev` keep the previous
/// behaviour.
#[cfg(target_os = "linux")]
fn mount_dev_and_proc(rootfs: &Path) -> io::Result<()> {
    let dev_dir = rootfs.join("dev");
    std::fs::create_dir_all(&dev_dir)?;
    let dev_c = crate::cstr(dev_dir.as_os_str().as_bytes())?;
    let fs_c = crate::cstr(b"tmpfs")?;
    // SAFETY: mount(2) overlays a fresh, empty tmpfs on the rootfs /dev.
    let rc = unsafe {
        libc::mount(
            fs_c.as_ptr(),
            dev_c.as_ptr(),
            fs_c.as_ptr(),
            libc::MS_NOSUID | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        eprintln!(
            "[erebus] warning: failed to mount tmpfs on /dev: {}",
            io::Error::last_os_error()
        );
        return Ok(());
    }

    // Standard char devices every runtime expects. `mknod` is blocked for
    // device nodes in unprivileged user namespaces (kernel hardening since
    // 4.18), so bind-mount the host's nodes instead — the same trick the GUI
    // path uses for /dev/dri. The bind is a 1:1 alias of an existing node,
    // so it is permitted and no new device is exposed.
    let host_dev = Path::new("/dev");
    let nodes: &[&str] = &[
        "null", "zero", "full", "random", "urandom", "tty", "console",
    ];
    for name in nodes {
        let host_node = host_dev.join(name);
        let dest = dev_dir.join(name);
        if !host_node.exists() {
            continue;
        }
        std::fs::write(&dest, []).ok();
        let src_c = crate::cstr(host_node.to_str().unwrap_or(name).as_bytes())?;
        let dest_c = crate::cstr(dest.as_os_str().as_bytes())?;
        // SAFETY: mount(2) with MS_BIND aliases an existing host device node
        // into the rootfs /dev; source and destination are valid paths.
        let rc = unsafe {
            libc::mount(
                src_c.as_ptr(),
                dest_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            eprintln!(
                "[erebus] warning: failed to bind /dev/{name}: {}",
                io::Error::last_os_error()
            );
        }
    }

    let proc_dir = rootfs.join("proc");
    std::fs::create_dir_all(&proc_dir)?;
    let proc_c = crate::cstr(proc_dir.as_os_str().as_bytes())?;
    let prs_c = crate::cstr(b"proc")?;
    let host_proc_c = crate::cstr(b"/proc")?;
    // SAFETY: mount(2) first tries a fresh procfs, then falls back to a
    // read-only bind of the host /proc when the kernel blocks procfs. When the
    // pivot path killed a new PID namespace (`CLONE_NEWPID`), the fresh mount
    // succeeds and hides all host process data; the bind is only reached when
    // NEWPID was unavailable (restrictive outer containers) and exposes host
    // process metadata — warned below so the tradeoff is visible.
    let rc = unsafe {
        libc::mount(
            prs_c.as_ptr(),
            proc_c.as_ptr(),
            prs_c.as_ptr(),
            libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        return Ok(());
    }
    eprintln!(
        "[erebus] warning: procfs mount not available (no PID namespace) — binding host /proc read-only: {}",
        io::Error::last_os_error()
    );
    if Path::new("/proc").is_dir() {
        let _ = unsafe {
            libc::mount(
                host_proc_c.as_ptr(),
                proc_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            )
        };
    }
    Ok(())
}

/// Enters the `pivot_root` isolation and installs the requested sandboxes.
///
/// Landlock rules anchor to the rootfs inode, so the `O_PATH` fd is opened
/// BEFORE `pivot_root` replaces the mount tree — afterwards the original
/// rootfs path would no longer resolve and the rule could not be added.
/// Landlock failures are fatal (fail-closed): the filesystem sandbox is the
/// last line of defense of the isolation level, and running the app without
/// it would silently defeat the requested `--landlock` guarantee.
///
/// When `meta.gui` is set, X11/Wayland/GPU devices are bind-mounted into
/// the rootfs **before** `pivot_root` so they remain accessible after the
/// mount tree swap. Bind-mounting must happen before `pivot_root` because the
/// host filesystem is unreachable afterwards.
#[cfg(target_os = "linux")]
fn enter_pivot_sandbox(rootfs: &Path, meta: &Metadata) -> io::Result<()> {
    let root_guard = if meta.landlock {
        Some(crate::landlock::RootfsGuard::open(rootfs)?)
    } else {
        None
    };

    mount_dev_and_proc(rootfs)?;

    if meta.gui {
        bind_mount_gui_devices(rootfs)?;
    }

    crate::pivot_root_into(rootfs)?;

    let caps = meta.effective_capabilities();

    if meta.seccomp {
        crate::seccomp::install_seccomp_with_capabilities(caps).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("seccomp unavailable, refusing to run without syscall filter: {e}"),
            )
        })?;
    }
    if let Some(root) = root_guard {
        crate::landlock::sandbox_with_capabilities(&root, caps).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("landlock unavailable, refusing to run without filesystem sandbox: {e}"),
            )
        })?;
    }
    Ok(())
}

/// Wait for the executor child and terminate this (supervisor) process with
/// the same status, so callers observe the app's real exit code/signal rather
/// than a wrapper's PID. Blocks until the child exits.
#[cfg(target_os = "linux")]
fn relay_child_status(pid: libc::pid_t) -> io::Result<()> {
    let mut status: libc::c_int = 0;
    // SAFETY: waitpid(2) blocks until `pid` exits or is signaled; `status` is
    // a valid pointer to a c_int, and the child is always ours.
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    relay_exit_status(status)
}

/// Terminate the current (supervisor) process with the child's exit status:
/// non-zero code → exit(code); signaled → re-raise the signal; else 129.
#[cfg(unix)]
fn relay_exit_status(status: libc::c_int) -> io::Result<()> {
    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        // SAFETY: restoring the default disposition then raise(2) re-delivers
        // the signal, so the parent dies with the same signal as the child.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
        }
    }
    std::process::exit(128 + 1)
}

/// Last confinement before exec, fail-closed: Seatbelt on macOS (filesystem
/// for `--landlock` bundles, egress for `ERE_EGRESS`), the egress ruleset on
/// Linux (the filesystem sandbox is installed with the pivot).
#[cfg(unix)]
fn apply_launch_confinement(rootfs: &Path, meta: &Metadata) -> io::Result<()> {
    let refuse = |what: &str, e: io::Error| {
        io::Error::new(e.kind(), format!("{what}, refusing to run: {e}"))
    };
    let egress = crate::egress::Policy::from_env().map_err(|e| refuse("bad egress policy", e))?;
    #[cfg(target_os = "macos")]
    if meta.landlock || egress.is_some() {
        let ports = egress.as_ref().map(|p| p.ports.as_slice());
        crate::macos_sandbox::apply_sandbox(meta.landlock.then_some(rootfs), ports)
            .map_err(|e| refuse("seatbelt sandbox unavailable", e))?;
    }
    #[cfg(target_os = "linux")]
    if let Some(policy) = &egress {
        let _ = (rootfs, meta);
        policy
            .prepare()
            .apply()
            .map_err(|e| refuse("egress confinement unavailable", e))?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    if egress.is_some() {
        let _ = (rootfs, meta);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "ERE_EGRESS cannot be enforced on this platform, refusing to run",
        ));
    }
    Ok(())
}

/// The egress policy the launch enforces, as the receipt signs it.
#[cfg(unix)]
fn signed_egress() -> Option<erebus_core::attest::EgressPolicy> {
    crate::egress::Policy::from_env()
        .ok()
        .flatten()
        .map(|p| p.signed())
}

/// Whether behavior capture is requested (opt-in) via `ERE_ATTEST_KEY`.
#[cfg(unix)]
fn attest_capture_enabled() -> bool {
    std::env::var_os("ERE_ATTEST_KEY").is_some()
}

/// Guard flag: the capture fork re-enters `exec_app` for the standard launch;
/// this prevents that inner call from recursing into `exec_app_captured`.
static CAPTURE_CHILD: AtomicBool = AtomicBool::new(false);

/// Canonical launch vector (entrypoint ++ runtime args) used for the input hash.
#[cfg(unix)]
fn launch_vector_for_hash(meta: &Metadata) -> Vec<String> {
    let mut v: Vec<String> = meta.effective_entrypoint().to_vec();
    for part in std::env::args_os().skip(1) {
        v.push(part.to_string_lossy().into_owned());
    }
    v
}

/// Resolve the attestation key + output paths from the environment.
///
/// `None` when `ERE_ATTEST_KEY` is unset — the caller then does nothing.
fn attest_paths(bin_path: &Path) -> Option<(PathBuf, PathBuf)> {
    let key_path = PathBuf::from(std::env::var_os("ERE_ATTEST_KEY")?);
    let out_path = std::env::var_os("ERE_ATTEST_OUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut p = bin_path.to_path_buf();
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            p.set_file_name(format!("{name}.attest"));
            p
        });
    Some((key_path, out_path))
}

/// Trail directory for hash-chained receipts: `ERE_ATTEST_LOG=<dir>` overrides,
/// `ERE_ATTEST_LOG=none` disables, default is `<receipt>.d` next to the latest
/// receipt.
fn attest_log_dir(out_path: &Path) -> Option<PathBuf> {
    match std::env::var_os("ERE_ATTEST_LOG") {
        Some(v) if v == "none" => None,
        Some(v) => Some(PathBuf::from(v)),
        None => Some(erebus_core::attest_log::default_log_dir(out_path)),
    }
}

/// Write the final receipt for this run: latest copy at `out_path` and, unless
/// disabled, an entry appended to the hash-chained trail. Never blocks the
/// launch — the operator's duty is to make the proof write succeed.
fn write_receipt_or_warn(
    bin_path: &Path,
    key_path: &Path,
    out_path: &Path,
    capture: &erebus_core::attest::ExecutionCapture,
    phase: &str,
) {
    let log = match attest_log_dir(out_path) {
        Some(dir) => match erebus_core::attest_log::AttestationLog::open(&dir) {
            Ok(log) => Some(log),
            Err(e) => {
                eprintln!(
                    "[erebus] warning: failed to open attestation trail {}: {e}",
                    dir.display()
                );
                return;
            }
        },
        None => None,
    };
    let result = match log {
        Some(log) => {
            erebus_core::attest::write_receipt(bin_path, key_path, out_path, &log, capture)
                .map(|(_, entry)| Some(entry))
        }
        None => erebus_core::attest::write_captured_execution_attestation(
            bin_path, key_path, out_path, capture,
        )
        .map(|_| None),
    };
    match result {
        Ok(Some(entry)) => eprintln!(
            "[erebus] attestation {phase}: {} (trail: {})",
            out_path.display(),
            entry.display()
        ),
        Ok(None) => eprintln!("[erebus] attestation {phase}: {}", out_path.display()),
        Err(e) => eprintln!("[erebus] warning: failed to write execution attestation: {e}"),
    }
}

/// Create a pipe pair (read, write).
#[cfg(unix)]
fn unix_pipe() -> io::Result<(libc::c_int, libc::c_int)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe(2) writes the read/write ends into `fds` on success.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

/// Drain a pipe into a SHA-256 hasher while teeing the bytes to `tee_fd` so the
/// user still sees the payload's output verbatim. Returns the stream digest.
#[cfg(unix)]
fn read_pipe_to_hash(fd: libc::c_int, tee_fd: libc::c_int) -> io::Result<String> {
    let mut hasher = erebus_core::attest::StreamHasher::new();
    let mut buf = [0u8; 65536];
    loop {
        // SAFETY: `fd` is a valid pipe read end owned by this process and `buf`
        // is a writable buffer of exactly `buf.len()` bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        let chunk = &buf[..n as usize];
        hasher.update(chunk);
        // The tee is best effort: a closed terminal must not stop the hash.
        write_all_fd(tee_fd, chunk);
    }
    // SAFETY: `fd` is owned by this thread and no longer needed.
    unsafe { libc::close(fd) };
    Ok(hasher.finish_hex())
}

/// Write all of `bytes` to `fd`, resuming partial writes; `false` when the
/// reader went away (EPIPE: SIGPIPE is ignored by the Rust runtime).
#[cfg(unix)]
fn write_all_fd(fd: libc::c_int, bytes: &[u8]) -> bool {
    let mut off = 0usize;
    while off < bytes.len() {
        // SAFETY: `fd` is an open fd owned by the caller and the slice
        // `bytes[off..]` is valid for `bytes.len() - off` bytes.
        let w = unsafe {
            libc::write(
                fd,
                bytes[off..].as_ptr() as *const libc::c_void,
                bytes.len() - off,
            )
        };
        if w < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if w <= 0 {
            return false;
        }
        off += w as usize;
    }
    true
}

/// Supervisor side of the stdin relay: copy our stdin into the payload's
/// stdin pipe and report the digest of what was delivered — only once stdin
/// reached EOF with every byte delivered, so a digest always covers the
/// whole input. A read error or a payload that stopped reading reports
/// nothing.
#[cfg(unix)]
fn relay_stdin(in_w: libc::c_int, done: std::sync::mpsc::Sender<String>) {
    let mut hasher = erebus_core::attest::StreamHasher::new();
    let mut buf = [0u8; 65536];
    let complete = loop {
        // SAFETY: fd 0 is this process's stdin; `buf` is writable for its length.
        let n = unsafe { libc::read(0, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if n <= 0 {
            break n == 0;
        }
        let chunk = &buf[..n as usize];
        if !write_all_fd(in_w, chunk) {
            break false;
        }
        hasher.update(chunk);
    };
    // SAFETY: closing the write end delivers EOF to the payload; this thread
    // is its only owner.
    unsafe { libc::close(in_w) };
    if complete {
        let _ = done.send(hasher.finish_hex());
    }
}

/// How long the supervisor waits, after the payload exited, for the stdin
/// relay to reach EOF before signing the receipt without `stdin_hash`.
#[cfg(unix)]
const STDIN_SETTLE: std::time::Duration = std::time::Duration::from_millis(500);

/// Normalize a wait status into the payload's exit code (128 + signal when the
/// payload was killed by a signal).
#[cfg(unix)]
fn exit_code_from_status(status: libc::c_int) -> Option<i32> {
    if libc::WIFEXITED(status) {
        Some(libc::WEXITSTATUS(status) as i32)
    } else if libc::WIFSIGNALED(status) {
        Some(128 + libc::WTERMSIG(status) as i32)
    } else {
        None
    }
}

/// Launch the app with behavior capture (Linux pivot path only).
///
/// The stub forks a supervisor that redirects the payload's stdout/stderr into
/// pipes, hashes everything while teeing it to the preserved originals, then —
/// once the whole nested launch tree exits — rewrites the signed attestation
/// with `output_hash` + `exit_code`. The inner re-entry of `exec_app` performs
/// the real isolation + payload exec with the standard flow, so the two launch
/// paths cannot drift.
///
/// Caveat if a daemonized grandchild keeps a pipe write end open: the tee
/// threads only see EOF when every holder exits, so the supervisor can wait for
/// it. That is the price of capturing output for interactive/daemon apps, and
/// capture is opt-in.
///
/// A non-terminal stdin (pipe, file, `/dev/null`) is relayed through a pipe
/// too and its digest signed as `stdin_hash`; a terminal is left attached
/// so interactive apps keep job control and line editing.
#[cfg(unix)]
fn exec_app_captured(
    meta: &Metadata,
    rootfs: &Path,
    app_config: &AppConfig,
    bin_path: &Path,
) -> io::Result<()> {
    let input_hash = Some(erebus_core::attest::launch_vector_hash(
        &launch_vector_for_hash(meta),
    ));

    let (out_r, out_w) = unix_pipe()?;
    let (err_r, err_w) = unix_pipe()?;
    // SAFETY: isatty(3) only inspects fd 0.
    let stdin_pipe = if unsafe { libc::isatty(0) } == 0 {
        Some(unix_pipe()?)
    } else {
        None
    };
    // SAFETY: dup(2) stores a private copy of the current stdout/stderr fds in
    // the supervisor so the tee threads can write through while the payload's
    // 1/2 point at the pipes. The originals stay valid across the child's exec
    // chain because `dup` new fds are process-private to the parent.
    let orig_out = unsafe { libc::dup(1) };
    let orig_err = unsafe { libc::dup(2) };

    // SAFETY: fork(2) creates the capture child. The child re-runs `exec_app` on
    // the normal path (its stdout/stderr already redirected); the parent below
    // supervises, hashes, and writes the completion attestation.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        // SAFETY: dup2 points the standard streams at the pipe write ends; the
        // read ends and preserved originals are closed to avoid leaking fds
        // into the payload through the subsequent fork/exec chain.
        unsafe {
            libc::dup2(out_w, 1);
            libc::dup2(err_w, 2);
            libc::close(out_r);
            libc::close(err_r);
            libc::close(out_w);
            libc::close(err_w);
            libc::close(orig_out);
            libc::close(orig_err);
            if let Some((in_r, in_w)) = stdin_pipe {
                libc::dup2(in_r, 0);
                libc::close(in_r);
                libc::close(in_w);
            }
        }
        CAPTURE_CHILD.store(true, Ordering::SeqCst);
        // exec_app's pivot path relays the payload's exit status by exiting the
        // nested process; returning `Ok` here means the payload exited 0, so
        // mirror that. An `Err` is a launch that never ran the payload: it
        // must not be signed as a clean exit.
        if let Err(e) = exec_app(meta, rootfs, app_config, bin_path) {
            eprintln!("[erebus] error: {e}");
            std::process::exit(126);
        }
        std::process::exit(0);
    }

    // Parent: close the write ends the child no longer needs, then start the
    // reader threads immediately so the pipes never fill while the payload runs.
    // SAFETY: these write ends are owned by the child's 1/2 now.
    unsafe {
        libc::close(out_w);
        libc::close(err_w);
    }
    let out_thread = std::thread::spawn(move || read_pipe_to_hash(out_r, orig_out));
    let err_thread = std::thread::spawn(move || read_pipe_to_hash(err_r, orig_err));
    let stdin_done = stdin_pipe.map(|(in_r, in_w)| {
        // SAFETY: the read end now belongs to the child's fd 0 only.
        unsafe { libc::close(in_r) };
        let (tx, rx) = std::sync::mpsc::channel();
        // Detached: if our stdin never reaches EOF the thread stays blocked
        // in read(0) until the supervisor exits; no digest is signed then.
        std::thread::spawn(move || relay_stdin(in_w, tx));
        rx
    });

    // SAFETY: waitpid(2) blocks until the capture child (and, through it, the
    // nested launch tree that relays the payload status) exits.
    let mut status: libc::c_int = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }

    let out_digest = out_thread
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "stdout capture thread panicked"))??;
    let err_digest = err_thread
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "stderr capture thread panicked"))??;
    let output_hash = Some(erebus_core::attest::combined_output_hash(
        &out_digest,
        &err_digest,
    ));
    let exit_code = exit_code_from_status(status);
    let stdin_hash = stdin_done.and_then(|rx| rx.recv_timeout(STDIN_SETTLE).ok());

    if let Some((key_path, out_path)) = attest_paths(bin_path) {
        let capture = erebus_core::attest::ExecutionCapture {
            input_hash,
            output_hash,
            exit_code,
            prev_attestation_hash: None, // set from the trail head by write_receipt
            request: None,
            rootfs_root: rootfs_root_of(rootfs),
            stdin_hash,
            egress: signed_egress(),
        };
        let phase = format!(
            "updated (exit {})",
            exit_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string())
        );
        write_receipt_or_warn(bin_path, &key_path, &out_path, &capture, &phase);
    }

    relay_exit_status(status)
}

/// Launch the app entrypoint. Blocks until the app exits (or never returns on
/// successful execvp).
pub fn exec_app(
    meta: &Metadata,
    rootfs: &Path,
    app_config: &AppConfig,
    bin_path: &Path,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    let use_pivot = meta.isolation >= 2;
    #[cfg(all(unix, not(target_os = "linux")))]
    let use_pivot = false;

    // Behavior capture (opt-in): on the pivot path with `ERE_ATTEST_KEY` set,
    // the supervisor tees the payload's stdout/stderr into a hash, records the
    // launch vector, and — once the payload exits — rewrites the signed
    // attestation with `output_hash` + `exit_code`. Only the pivot path has the
    // fork supervisor this needs; elsewhere we fall back to the plain
    // pre-launch attestation. The guard flag stops the nested re-entry (the
    // capture fork reverts to the normal exec_app path) from recursing.
    // macOS has no pivot path; the capture fork works there unchanged, and
    // it keeps the receipt writer outside the Seatbelt-confined child.
    #[cfg(target_os = "linux")]
    let capture_here = use_pivot;
    #[cfg(target_os = "macos")]
    let capture_here = true;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if capture_here && attest_capture_enabled() && !CAPTURE_CHILD.load(Ordering::Relaxed) {
        return exec_app_captured(meta, rootfs, app_config, bin_path);
    }

    // Auto-attestation (opt-in): with `ERE_ATTEST_KEY` set, write a signed
    // `.erebus.attest` right before launch. Done pre-pivot so host paths for
    // key and bundle still resolve; failures warn but never block the run.
    write_auto_attestation_if_requested(bin_path, rootfs);

    // Single source of truth for the argv template: the layer system when
    // `entrypoint_layer` is set, the flat field for legacy binaries.
    let entrypoint = meta.effective_entrypoint();
    if entrypoint.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty entrypoint",
        ));
    }

    #[cfg(unix)]
    let orig_cwd = std::env::current_dir().ok();

    // Sandbox flags only take effect on the pivot_root path (isolation >= 2).
    // Warn on the non-pivot path instead of silently ignoring the request —
    // metadata can be authored by any builder, not just the CLI. (macOS
    // applies its own sandbox profile for `landlock`, so this is Linux-only.)
    #[cfg(target_os = "linux")]
    if !use_pivot && (meta.seccomp || meta.landlock) {
        let flags = ["seccomp", "landlock"]
            .into_iter()
            .filter(|name| {
                (*name == "seccomp" && meta.seccomp) || (*name == "landlock" && meta.landlock)
            })
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!("[erebus] warning: {flags} requested but isolation < 2 — sandbox not applied");
    }

    #[cfg(target_os = "linux")]
    if use_pivot && crate::namespace::running_in_container() {
        eprintln!("[erebus] warning: running inside a container — namespace isolation may be restricted by the host");
    }

    enter_namespace_if_needed(meta.isolation)?;

    // Supervisor fork for the pivot path: `CLONE_NEWPID` makes the next child
    // PID 1 of a fresh namespace — the only context that may mount a hermetic
    // procfs (one that hides all host process data). The parent supervises the
    // executor child and relays its exit status, keeping the stub alive during
    // the app's run so the health endpoint works. On hosts that deny
    // `unshare(CLONE_NEWPID)`, warn and fall back to the host-`/proc` bind.
    #[cfg(target_os = "linux")]
    if use_pivot {
        if let Err(e) = crate::namespace::enter_newpid() {
            eprintln!(
                "[erebus] warning: failed to enter PID namespace ({e}) — /proc falls back to a host bind"
            );
        }
        // SAFETY: fork(2) creates the executor child (PID 1 when enter_newpid
        // succeeded). The child mounts /dev + /proc, pivots root, then execs
        // the payload; the parent supervises below.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid != 0 {
            crate::health_gate::maybe_start_health(meta);
            return relay_child_status(pid);
        }
        // Child: fall through to the shared launch path below. This mounts the
        // synthetic /dev and a fresh /proc, pivots root, and installs the
        // seccomp/Landlock sandboxes.
        enter_pivot_sandbox(rootfs, meta)?;
    }

    // Health server: spawn AFTER entering the namespaces — a live thread makes
    // `unshare(CLONE_NEWUSER)` fail with EINVAL (already-joined workers can
    // too, for a few microseconds; `namespace::enter_userns` waits for the
    // thread group to drain). On the pivot path this line
    // runs in the executor child (its thread vanishes at exec, as before the
    // supervisor fork); the parent already spawned its own inside the branch.
    crate::health_gate::maybe_start_health(meta);

    #[cfg(unix)]
    apply_launch_confinement(rootfs, meta)?;

    // ── Platform-specific argv build + process launch ─────────────────────
    #[cfg(unix)]
    {
        let (prog, direct_exec, interpreter_name) = resolve_entrypoint(meta, rootfs, use_pivot)?;
        let resolve = make_resolve(rootfs, use_pivot);
        let prog_c = cstr(prog.as_os_str().as_bytes())?;
        let prog_path_bytes = prog.as_os_str().as_bytes();

        // For interpreted languages, check if the interpreter is executable;
        // for direct_exec (compiled binaries), check the program itself.
        let check_path = if direct_exec {
            prog_path_bytes
        } else {
            interpreter_name.as_bytes()
        };
        let check_name = if direct_exec {
            prog.display().to_string()
        } else {
            interpreter_name.clone()
        };
        if !entrypoint_is_executable(check_path, &interpreter_name, rootfs) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "[erebus] error: interpreter '{}' not found (tried: {})",
                    check_name,
                    prog.display()
                ),
            ));
        }

        // Compute the child environment before building argv: entrypoint args
        // may carry `$PORT`/`${VAR}` placeholders that must expand to run-time
        // values (e.g. Java's `-Dserver.port=$PORT`).
        let env = setup_env(meta, rootfs, use_pivot, orig_cwd.as_deref(), app_config)?;

        let mut argv: Vec<CString> = Vec::new();
        if direct_exec {
            argv.push(prog_c.clone());
            for a in &entrypoint[1..] {
                if let Some(expanded) = expand_env_arg(a, &env) {
                    argv.push(cstr(resolve(&expanded).as_os_str().as_bytes())?);
                }
            }
        } else {
            if !entrypoint_is_executable(interpreter_name.as_bytes(), &interpreter_name, rootfs) {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "[erebus] error: interpreter '{}' not found",
                        interpreter_name
                    ),
                ));
            }
            argv.push(cstr(interpreter_name.as_bytes())?);
            for a in &entrypoint[1..] {
                if let Some(expanded) = expand_env_arg(a, &env) {
                    argv.push(cstr(resolve(&expanded).as_os_str().as_bytes())?);
                }
            }
        }
        for a in std::env::args_os().skip(1) {
            argv.push(cstr(a.as_bytes())?);
        }

        if let Some(cwd) = &meta.cwd {
            let dir = resolve(cwd);
            std::env::set_current_dir(&dir).ok();
        }
        for (k, v) in &env {
            std::env::set_var(k, v);
        }

        let argv_ptrs = to_ptr_vec(&argv);

        // Phase 5b: Exec capability enforcement.
        //
        // When `Capability::Exec` is absent, the seccomp filter installed by
        // `enter_pivot_sandbox` denies `execve`. The stub's own `execvp` would
        // be killed by `SECCOMP_RET_KILL_PROCESS`, so we `fork()` first: the
        // child inherits the filter, its `execvp` is blocked, and the parent
        // detects the child's exit (126) to refuse the launch cleanly.
        //
        // When Exec is absent but seccomp is NOT active, refuse outright —
        // the application should not be launched without an exec capability.
        //
        // Legacy binaries (no layer system) always get a pass here.
        let caps = meta.effective_capabilities();
        let has_exec = caps.contains(&Capability::Exec);
        let layers_active = !meta.layers.is_empty() && meta.entrypoint_layer.is_some();

        #[cfg(target_os = "linux")]
        let seccomp_blocks_exec = layers_active && !has_exec && meta.seccomp && use_pivot;
        #[cfg(not(target_os = "linux"))]
        let seccomp_blocks_exec = false;

        if layers_active && !has_exec && !seccomp_blocks_exec {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Exec capability absent — application launch refused",
            ));
        }

        if seccomp_blocks_exec {
            // SAFETY: fork(2) creates a child process. The child attempts
            // libc_execvp which is blocked by seccomp (execve denied).
            // The parent waits for the child via waitpid.
            let pid = unsafe { libc::fork() };
            if pid < 0 {
                return Err(io::Error::last_os_error());
            }
            if pid == 0 {
                // Child: execvp will fail (execve denied by seccomp).
                unsafe {
                    crate::libc_execvp(prog_c.as_ptr(), argv_ptrs.as_ptr());
                }
                eprintln!("[erebus] execvp blocked — Exec capability absent (seccomp)");
                unsafe {
                    libc::_exit(126);
                }
            }
            // Parent: wait for child and inspect exit status.
            let mut status: libc::c_int = 0;
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 126 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Exec capability absent — application launch refused (seccomp blocked execve)",
                ));
            }
            if libc::WIFSIGNALED(status) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "Exec capability absent — child killed by signal {} (seccomp)",
                        libc::WTERMSIG(status)
                    ),
                ));
            }
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unexpected child exit status: {}", status),
            ));
        }

        // Exec capability present, or seccomp not active: standard execvp.
        // SAFETY: execvp(3) replaces the current process. prog_c is a valid
        // CString, argv_ptrs is null-terminated. We never return on success.
        // execvp searches PATH for bare command names (e.g. "python3") and
        // uses absolute paths as-is (e.g. "/app/app.py"). Environment is
        // inherited from the current process after set_var calls above.
        unsafe {
            crate::libc_execvp(prog_c.as_ptr(), argv_ptrs.as_ptr());
        }
        Err(io::Error::last_os_error())
    }

    #[cfg(windows)]
    {
        let child = spawn_app_windows(meta, rootfs, app_config)?;
        let code = crate::win::wait(&child)?;
        exit(code);
    }
}

/// Best-effort auto-attestation hook: when `ERE_ATTEST_KEY` is set, write a
/// fresh signed execution attestation for the launched bundle.
///
/// Output path: `ERE_ATTEST_OUT` if set, else `<bundle>.attest`. A failure to
/// attest (missing key, read-only dir) is logged loudly but never blocks the
/// launch — the app must run; the operator's duty is to make the proof write
/// succeed.
fn write_auto_attestation_if_requested(bin_path: &Path, rootfs: &Path) {
    // Inside the capture child, the outer supervisor rewrites the attestation
    // with output+exit at the end; writing an intermediate one here would leak
    // a launcher line into the captured stderr stream.
    if CAPTURE_CHILD.load(Ordering::Relaxed) {
        return;
    }
    let Some((key_path, out_path)) = attest_paths(bin_path) else {
        return;
    };
    let capture = erebus_core::attest::ExecutionCapture {
        rootfs_root: rootfs_root_of(rootfs),
        #[cfg(unix)]
        egress: signed_egress(),
        ..Default::default()
    };
    write_receipt_or_warn(bin_path, &key_path, &out_path, &capture, "written");
}

/// `sha256:<root>` of the extracted tree, read from the manifest the cold
/// path wrote next to `rootfs/` (`<cache_root>/rootfs.merkle`). `None` when
/// the cache predates the manifest or the layout is unexpected.
fn rootfs_root_of(rootfs: &Path) -> Option<String> {
    rootfs
        .parent()
        .and_then(erebus_core::rootfs_merkle::read_root)
}

/// Resolve the entrypoint program + interpreter details shared by the
/// single-app and service-supervisor launch paths.
/// Canonical interpreter binary name for each interpreted runtime. Compiled
/// runtimes (`binary`) return `None` — their entrypoint is the program.
fn runtime_interpreter(runtime: &str) -> Option<&'static str> {
    match runtime {
        "python" => Some("python3"),
        _ => None,
    }
}

/// Resolve the entrypoint program and interpreter for `meta`, validated against
/// the supported runtime list. `None` from `Runtime::from_name` means the
/// metadata carries a runtime the stub never heard of — fail loudly instead of
/// silently launching under bash (upstream fix for roadmap #40).
///
/// The runtime name and argv template come from `Metadata::effective_runtime` /
/// `Metadata::effective_entrypoint`: the layer system when `entrypoint_layer`
/// is set, the flat fields for legacy binaries. This is the single resolution
/// path — callers must not re-implement layer lookup.
pub fn resolve_entrypoint(
    meta: &Metadata,
    rootfs: &Path,
    use_pivot: bool,
) -> io::Result<(PathBuf, bool, String)> {
    let runtime_str = meta.effective_runtime().to_string();
    let entrypoint_vec = meta.effective_entrypoint().to_vec();
    if entrypoint_vec.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty entrypoint",
        ));
    }

    if detect::Runtime::from_name(&runtime_str).is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported runtime '{}' in metadata — supported: python, binary",
                runtime_str
            ),
        ));
    }
    let resolve = make_resolve(rootfs, use_pivot);
    let mut prog = resolve(&entrypoint_vec[0]);

    // Compiled binaries (`binary`) exec `entrypoint[0]` directly;
    // interpreted runtimes get their interpreter prepended to argv.
    let direct_exec = matches!(runtime_str.as_str(), "binary");
    let interpreter_name = runtime_interpreter(&runtime_str)
        .map(str::to_string)
        .unwrap_or_else(|| {
            entrypoint_vec[0]
                .rsplit('/')
                .next()
                .unwrap_or(&entrypoint_vec[0])
                .to_string()
        });

    // For bare interpreter names without pivot_root, search rootfs bin dirs
    // so embedded interpreters are found before namespace/pivot setup.
    if !use_pivot && !entrypoint_vec[0].contains('/') {
        let prog_str = prog.to_string_lossy();
        if !check_executable(&prog_str) {
            if let Some(found) = crate::BIN_PATHS.iter().find_map(|dir| {
                let candidate = rootfs.join(dir).join(&entrypoint_vec[0]);
                if check_executable(&candidate.to_string_lossy()) {
                    Some(candidate)
                } else {
                    None
                }
            }) {
                prog = found;
            }
        }
    }

    Ok((prog, direct_exec, interpreter_name))
}

// ---------------------------------------------------------------------------
// Windows exec helpers
// ---------------------------------------------------------------------------

/// Spawn the app as a child process on Windows (`CreateProcess`), returning the
/// child handle. The caller decides whether to poll (health gate) or wait.
#[cfg(windows)]
pub fn spawn_app_windows(
    meta: &Metadata,
    rootfs: &Path,
    app_config: &AppConfig,
) -> io::Result<crate::win::Child> {
    let (prog, direct_exec, interpreter_name) = resolve_entrypoint(meta, rootfs, false)?;
    let entrypoint = meta.effective_entrypoint();
    let env = setup_env(meta, rootfs, false, None, app_config)?;
    let cwd = meta.cwd.as_ref().map(|c| make_resolve(rootfs, false)(c));
    let resolve = make_resolve(rootfs, false);

    let mut cmd = prog;
    if !is_executable_path(&cmd) {
        cmd = find_in_bin_paths(rootfs, &entrypoint[0]).unwrap_or_else(|| {
            // Portable-embed payloads ship no interpreter: fall back to the
            // bare command name and let the spawn path resolve it from the
            // target machine's PATH (execvp semantics).
            if std::env::var_os("ERE_VERBOSE").is_some() {
                eprintln!(
                    "[erebus] '{interpreter_name}' not in payload — resolving from system PATH"
                );
            }
            PathBuf::from(&entrypoint[0])
        });
    }

    let mut argv: Vec<std::ffi::OsString> = Vec::new();
    if direct_exec {
        argv.push(cmd.as_os_str().to_os_string());
    } else {
        argv.push(std::ffi::OsString::from(interpreter_name));
    }
    for a in &entrypoint[1..] {
        if let Some(expanded) = expand_env_arg(a, &env) {
            argv.push(resolve(&expanded).into_os_string());
        }
    }
    for a in std::env::args_os().skip(1) {
        argv.push(a);
    }

    crate::win::spawn(&cmd, &argv, &env, cwd.as_deref(), false)
}

/// Resolve a bare interpreter/command name against the rootfs bin dirs,
/// trying the `.exe` suffix on Windows.
#[cfg(windows)]
pub fn find_in_bin_paths(rootfs: &Path, name: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    let candidates = [name.to_string(), format!("{name}.exe")];
    #[cfg(not(windows))]
    let candidates = [name.to_string()];
    crate::BIN_PATHS.iter().find_map(|dir| {
        let base = rootfs.join(dir);
        candidates.iter().find_map(|c| {
            let candidate = base.join(c);
            if check_executable(&candidate.to_string_lossy()) {
                Some(candidate)
            } else {
                None
            }
        })
    })
}

/// `is_executable` for a `Path` (avoids unix-only `OsStr::as_bytes`).
#[cfg(windows)]
pub fn is_executable_path(path: &Path) -> bool {
    #[cfg(unix)]
    {
        is_executable(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        check_executable(&path.to_string_lossy())
    }
}

// ---------------------------------------------------------------------------
// Multi-process supervisor
// ---------------------------------------------------------------------------

/// Supervise multiple services: fork+exec each, health-check ports, wait for all.
#[cfg(unix)]
pub fn supervise_services(
    meta: &Metadata,
    rootfs: &Path,
    app_config: &AppConfig,
) -> io::Result<()> {
    let verbose = std::env::var_os("ERE_VERBOSE").is_some();
    #[cfg(target_os = "linux")]
    let use_pivot = meta.isolation >= 2;
    #[cfg(not(target_os = "linux"))]
    let use_pivot = false;

    enter_namespace_if_needed(meta.isolation)?;
    #[cfg(target_os = "linux")]
    if use_pivot {
        enter_pivot_sandbox(rootfs, meta)?;
    }

    apply_launch_confinement(rootfs, meta)?;

    let base_env = setup_env(meta, rootfs, use_pivot, None, app_config)?;
    let resolve = make_resolve(rootfs, use_pivot);

    let children = fork_services(meta, &base_env, &resolve, rootfs, verbose)?;
    // Start health gate AFTER fork to avoid fork() while thread is running
    // (fork in multithreaded process can deadlock child via held libc locks).
    crate::health_gate::maybe_start_health(meta);
    wait_for_health(meta, verbose)?;
    install_signal_handler(&children);
    wait_for_children(&children, verbose)
}

/// Supervise multiple services on Windows: spawn each with `CreateProcess`,
/// health-check ports, then wait for all handles.
#[cfg(windows)]
pub fn supervise_services(
    meta: &Metadata,
    rootfs: &Path,
    app_config: &AppConfig,
) -> io::Result<()> {
    let verbose = std::env::var_os("ERE_VERBOSE").is_some();

    crate::health_gate::maybe_start_health(meta);

    let base_env = setup_env(meta, rootfs, false, None, app_config)?;
    let resolve = make_resolve(rootfs, false);

    let mut children = Vec::new();
    for svc in &meta.services {
        let mut prog = resolve(&svc.cmd[0]);
        if !is_executable_path(&prog) {
            prog = find_in_bin_paths(rootfs, &svc.cmd[0]).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("[erebus] error: service '{}' not found", svc.cmd[0]),
                )
            })?;
        }
        let mut argv: Vec<std::ffi::OsString> = vec![prog.as_os_str().to_os_string()];
        for a in &svc.cmd[1..] {
            argv.push(resolve(a).into_os_string());
        }
        let mut env = base_env.clone();
        for (k, v) in &svc.env {
            env.insert(k.clone(), v.replace("${ROOTFS}", &rootfs.to_string_lossy()));
        }
        let child = crate::win::spawn(&prog, &argv, &env, None, false)?;
        if verbose {
            eprintln!(
                "[erebus] service '{}' started (pid {})",
                svc.name, child.pid
            );
        }
        children.push((svc.name.clone(), child));
    }

    wait_for_health(meta, verbose)?;

    let mut exit_code = 0i32;
    for (name, child) in &children {
        let code = crate::win::wait(child)?;
        if verbose {
            eprintln!("[erebus] service '{}' exited with code {}", name, code);
        }
        if code != 0 && exit_code == 0 {
            exit_code = code;
        }
    }
    if exit_code != 0 {
        exit(exit_code);
    }
    Ok(())
}

/// Fork+exec each service, returning (name, pid) pairs.
#[cfg(unix)]
pub fn fork_services(
    meta: &Metadata,
    base_env: &BTreeMap<String, String>,
    resolve: &dyn Fn(&str) -> PathBuf,
    rootfs: &Path,
    verbose: bool,
) -> io::Result<Vec<(String, i32)>> {
    let mut children = Vec::new();
    for svc in &meta.services {
        let prog = resolve(&svc.cmd[0]);
        let prog_c = cstr(prog.as_os_str().as_bytes())?;

        let mut argv: Vec<CString> = Vec::new();
        argv.push(prog_c.clone());
        for a in &svc.cmd[1..] {
            argv.push(cstr(resolve(a).as_os_str().as_bytes())?);
        }

        let mut env = base_env.clone();
        for (k, v) in &svc.env {
            env.insert(k.clone(), v.replace("${ROOTFS}", &rootfs.to_string_lossy()));
        }
        let env_c = env_to_cstrings(&env)?;

        // SAFETY: fork(2) creates a copy of the calling process. The child
        // calls execve (which never returns on success) or exit(127).
        // The parent records the pid for waitpid tracking.
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                return Err(io::Error::last_os_error());
            }
            if pid == 0 {
                let argv_ptrs = to_ptr_vec(&argv);
                let env_ptrs = to_ptr_vec(&env_c);
                // SAFETY: execve(2) replaces the child process. All pointers
                // are valid CStrings, envp is null-terminated.
                crate::libc_execve(prog_c.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
                eprintln!(
                    "[erebus] failed to exec {}: {}",
                    svc.cmd[0],
                    io::Error::last_os_error()
                );
                std::process::exit(127);
            }
            if verbose {
                eprintln!("[erebus] service '{}' started (pid {})", svc.name, pid);
            }
            children.push((svc.name.clone(), pid));
        }
    }
    Ok(children)
}

/// Block until all services with `ready_port` are accepting connections.
pub fn wait_for_health(meta: &Metadata, verbose: bool) -> io::Result<()> {
    for svc in &meta.services {
        if svc.ready_port == 0 {
            continue;
        }
        let timeout = if svc.ready_timeout > 0 {
            svc.ready_timeout
        } else {
            30
        };
        if verbose {
            eprintln!(
                "[erebus] waiting for {}:{} (timeout {}s)",
                svc.name, svc.ready_port, timeout
            );
        }
        wait_for_port(svc.ready_port, timeout)?;
        if verbose {
            eprintln!("[erebus] {}:{} is ready", svc.name, svc.ready_port);
        }
    }
    Ok(())
}

/// Wait for all children to exit. Forward SIGTERM/SIGINT to children.
/// Returns the exit code of the first failed service, or 0 if all succeeded.
#[cfg(unix)]
pub fn wait_for_children(children: &[(String, i32)], verbose: bool) -> io::Result<()> {
    let mut exit_code = 0i32;
    let mut remaining = children.len();
    while remaining > 0 {
        let mut status: i32 = 0;
        // SAFETY: waitpid(2) with pid=-1 waits for any child. status is
        // filled by the kernel. We only read it after a successful return.
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid < 0 {
            // ECHILD with services still tracked means the children were
            // reaped elsewhere (or never spawned) — report it instead of
            // silently "succeeding" while services are gone. Any other
            // error just stops the wait loop.
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ECHILD) && remaining > 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("all children gone but {remaining} tracked service(s) not reaped"),
                ));
            }
            break;
        }

        // waitpid(-1, ...) also reaps spurious children (grandchildren,
        // helpers). Only a pid we actually supervise may decrement the
        // tracked count, or the loop would exit early with services alive.
        let Some((name, _)) = children.iter().find(|(_, p)| *p == pid) else {
            continue;
        };
        remaining -= 1;

        if libc::WIFEXITED(status) {
            let code = libc::WEXITSTATUS(status);
            if verbose {
                eprintln!("[erebus] service '{}' exited with code {}", name, code);
            }
            if code != 0 && exit_code == 0 {
                exit_code = code;
            }
        } else if libc::WIFSIGNALED(status) {
            let sig = libc::WTERMSIG(status);
            eprintln!("[erebus] service '{}' killed by signal {}", name, sig);
            if exit_code == 0 {
                exit_code = 128 + sig;
            }
            // One service died: kill the rest.
            for (_, cp) in children {
                if *cp != pid {
                    // SAFETY: kill(2) sends a signal to a process we own
                    // (forked from us). SIGTERM is a graceful shutdown.
                    unsafe {
                        libc::kill(*cp, libc::SIGTERM);
                    }
                }
            }
        }
    }
    if exit_code != 0 {
        exit(exit_code);
    }
    Ok(())
}

pub fn wait_for_port(port: u16, timeout_secs: u64) -> io::Result<()> {
    use std::net::TcpStream;
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match TcpStream::connect(format!("127.0.0.1:{port}")) {
            Ok(_) => return Ok(()),
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("service port {port} not ready within {timeout_secs}s: {e}"),
                ))
            }
        }
    }
}

#[cfg(unix)]
use std::sync::atomic::{AtomicI32, AtomicUsize};

/// Maximum number of child PIDs the signal handler can forward to.
/// Fixed-size array avoids heap allocation and Mutex in signal context.
#[cfg(unix)]
const MAX_CHILDREN: usize = 64;

#[cfg(unix)]
static CHILD_PID_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
static CHILD_PIDS: [AtomicI32; MAX_CHILDREN] = {
    // Interior-mutable const is required here: array repeat syntax needs a
    // const initializer since AtomicI32 is not Copy. Safe as a static init.
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicI32 = AtomicI32::new(0);
    [ZERO; MAX_CHILDREN]
};

/// Install SIGTERM/SIGINT forwarding to child processes.
///
/// # Safety precondition
///
/// This function registers a signal handler that reads `CHILD_PIDS` via
/// atomics (safe even if threading is introduced). The handler is installed
/// in a single-threaded context post-fork — no concurrent access exists.
#[cfg(unix)]
pub fn install_signal_handler(children: &[(String, i32)]) {
    let count = children.len().min(MAX_CHILDREN);
    for (i, (_, pid)) in children.iter().take(count).enumerate() {
        CHILD_PIDS[i].store(*pid, Ordering::Relaxed);
    }
    CHILD_PID_COUNT.store(count, Ordering::Relaxed);

    // SAFETY: signal(2) registers a C function pointer as a signal handler.
    // signal_forward only calls kill(2) (async-signal-safe) and reads
    // CHILD_PIDS/CHILD_PID_COUNT via Relaxed atomics.
    unsafe {
        libc::signal(libc::SIGTERM, signal_forward as *const () as usize);
        libc::signal(libc::SIGINT, signal_forward as *const () as usize);
    }
}

#[cfg(unix)]
extern "C" fn signal_forward(sig: i32) {
    // SAFETY: signal_forward runs in signal handler context. All operations
    // are async-signal-safe: Relaxed atomic load, libc::kill(2), and reading
    // CHILD_PIDS/CHILD_PID_COUNT via atomics. No data race possible.
    let count = CHILD_PID_COUNT.load(Ordering::Relaxed);
    for slot in CHILD_PIDS.iter().take(count) {
        let pid = slot.load(Ordering::Relaxed);
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DatabaseConfig;
    #[cfg(unix)]
    use crate::FORK_TEST_LOCK;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn make_resolve_returns_absolute_when_pivot() {
        let rootfs = PathBuf::from("/app");
        let resolve = make_resolve(&rootfs, true);
        assert_eq!(
            resolve("/usr/bin/python3"),
            PathBuf::from("/usr/bin/python3")
        );
    }

    #[test]
    fn make_resolve_strips_leading_slash_when_no_pivot() {
        let rootfs = PathBuf::from("/tmp/erebus-cache/abc");
        let resolve = make_resolve(&rootfs, false);
        assert_eq!(resolve("/usr/bin/python3"), rootfs.join("usr/bin/python3"));
    }

    #[test]
    fn check_executable_returns_false_for_missing_path() {
        assert!(!check_executable("/nonexistent/binary"));
    }

    #[test]
    fn entrypoint_executable_falls_back_to_rootfs_interpreter() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        let interp = rootfs.join("usr/bin/python3");
        std::fs::write(&interp, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&interp, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Embedded interpreter exists only in the rootfs: the pre-flight must
        // still pass when the host PATH has no `python3`.
        assert!(entrypoint_is_executable(b"python3", "python3", rootfs));
    }

    #[test]
    fn entrypoint_executable_rejects_absolute_missing_path() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::create_dir_all(rootfs.join("usr/bin")).unwrap();
        std::fs::write(rootfs.join("usr/bin/python3"), b"x").unwrap();
        // An absolute prog path cannot fall back to the rootfs search.
        assert!(!entrypoint_is_executable(
            b"/app/python3",
            "python3",
            rootfs
        ));
    }

    #[test]
    fn detect_web_port_returns_8000_for_django() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("manage.py"), "").unwrap();
        assert_eq!(detect_web_port(tmp.path(), "python"), Some(8000));
    }

    #[test]
    fn detect_django_settings_handles_commas_and_parens() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("manage.py"),
            "os.environ.setdefault(\"DJANGO_SETTINGS_MODULE\", \"myproject.settings\")\n",
        )
        .unwrap();
        assert_eq!(
            detect_django_settings(tmp.path()),
            Some("myproject.settings".to_string())
        );
    }

    #[test]
    fn setup_env_dotenv_loses_to_explicit_config() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path();
        std::fs::write(
            rootfs.join(".env"),
            "DATABASE_URL=postgres://dotenv/db\nMY_KEY=dotenv\nNODE_ENV=staging",
        )
        .unwrap();

        let meta = Metadata {
            name: "test".into(),
            version: None,
            runtime: "python".into(),
            entrypoint: Vec::new(),
            env: {
                let mut m = BTreeMap::new();
                m.insert("MY_KEY".to_string(), "explicit".to_string());
                m
            },
            cwd: None,
            isolation: 0,
            seccomp: false,
            gui: false,
            landlock: false,
            services: Vec::new(),
            crypto: None,
            payload_format: String::new(),
            health_check: None,
            update_url: None,
            entrypoint_layer: None,
            artifact_state: None,
            artifact_policy: None,
            layers: Vec::new(),
        };

        let app_config = AppConfig {
            database: Some(DatabaseConfig {
                url: Some("postgres://config/db".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let env = setup_env(&meta, rootfs, false, None, &app_config).unwrap();

        // Explicit --env wins over the app's .env.
        assert_eq!(env.get("MY_KEY").map(String::as_str), Some("explicit"));
        // Config DATABASE_URL wins over the app's .env.
        assert_eq!(
            env.get("DATABASE_URL").map(String::as_str),
            Some("postgres://config/db")
        );
        // .env still fills gaps.
        assert_eq!(env.get("NODE_ENV").map(String::as_str), Some("staging"));
    }

    #[test]
    fn wait_for_children_ignores_spurious_and_waits_for_tracked() {
        // Serialized: waitpid(-1, ...) reaps ANY child of the process, so
        // fork-based tests must not run concurrently or they steal each
        // other's children.
        let _guard = FORK_TEST_LOCK.lock().unwrap();
        // SAFETY: fork(2) duplicates the test process; the children only call
        // _exit(0), which is async-signal-safe and safe after forking a
        // multithreaded process.
        let spurious = unsafe { libc::fork() };
        assert!(spurious >= 0, "fork failed");
        if spurious == 0 {
            unsafe { libc::_exit(0) };
        }

        let tracked = unsafe { libc::fork() };
        assert!(tracked >= 0, "fork failed");
        if tracked == 0 {
            std::thread::sleep(std::time::Duration::from_millis(300));
            unsafe { libc::_exit(0) };
        }

        let start = std::time::Instant::now();
        wait_for_children(&[("tracked".to_string(), tracked)], false).unwrap();

        // Reaping the spurious child must not advance the tracked count: the
        // call only returns once the tracked service has actually exited.
        assert!(
            start.elapsed() >= std::time::Duration::from_millis(250),
            "returned before the tracked service exited"
        );
    }

    #[test]
    fn wait_for_children_ok_when_tracked_exits_zero() {
        // Serialized: see wait_for_children_ignores_spurious_and_waits_for_tracked.
        let _guard = FORK_TEST_LOCK.lock().unwrap();
        // SAFETY: fork(2) duplicates the test process; the child only calls
        // _exit(0), which is async-signal-safe and safe after forking a
        // multithreaded process.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe { libc::_exit(0) };
        }

        wait_for_children(&[("ok".to_string(), pid)], false).unwrap();
    }

    fn env_map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn expand_env_arg_expands_port() {
        let env = env_map(&[("PORT", "8080")]);
        assert_eq!(
            expand_env_arg("-Dserver.port=$PORT", &env),
            Some("-Dserver.port=8080".to_string())
        );
    }

    #[test]
    fn expand_env_arg_supports_braces() {
        let env = env_map(&[("ERE_PORT", "9000")]);
        assert_eq!(
            expand_env_arg("-Dserver.port=${ERE_PORT}", &env),
            Some("-Dserver.port=9000".to_string())
        );
    }

    #[test]
    fn expand_env_arg_drops_arg_when_var_unset() {
        assert_eq!(expand_env_arg("-Dserver.port=$PORT", &env_map(&[])), None);
    }

    #[test]
    fn expand_env_arg_passes_through_without_dollar() {
        let env = env_map(&[("PORT", "8080")]);
        assert_eq!(
            expand_env_arg("/app/app.jar", &env),
            Some("/app/app.jar".to_string())
        );
    }

    #[test]
    fn expand_env_arg_handles_trailing_dollar() {
        let env = env_map(&[("PORT", "8080")]);
        assert_eq!(expand_env_arg("cost$", &env), Some("cost$".to_string()));
    }

    #[test]
    fn resolve_entrypoint_rejects_unknown_runtime() {
        let tmp = tempfile::tempdir().unwrap();
        let meta = Metadata {
            name: "crafted".into(),
            version: None,
            runtime: "cobol".into(),
            entrypoint: vec!["/app/app".into()],
            env: BTreeMap::new(),
            cwd: None,
            isolation: 0,
            seccomp: false,
            gui: false,
            landlock: false,
            services: Vec::new(),
            crypto: None,
            payload_format: String::new(),
            health_check: None,
            update_url: None,
            entrypoint_layer: None,
            artifact_state: None,
            artifact_policy: None,
            layers: Vec::new(),
        };
        let err = resolve_entrypoint(&meta, tmp.path(), false).unwrap_err();
        assert!(err.to_string().contains("unsupported runtime 'cobol'"));
    }

    #[test]
    fn runtime_interpreter_covers_all_interpreted_runtimes() {
        assert!(runtime_interpreter("python").is_some(), "runtime: python");
        for name in ["binary", "cobol", "wasm"] {
            assert!(runtime_interpreter(name).is_none(), "runtime: {name}");
        }
    }
}
