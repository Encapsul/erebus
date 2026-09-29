//! Namespace setup for the erebus launcher stub.
//!
//! Provides Linux user + mount namespace isolation (`enter_userns`,
//! `pivot_root_into`) and container detection (`running_in_container`).
//! All functions here are Linux-only and gated with `#[cfg(target_os = "linux")]`.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// Detect if the launcher is running inside a known container environment.
///
/// Checks `/.dockerenv`, `/run/.containerenv`, and cgroup v1/v2 hints.
/// Returns `true` when a container runtime is detected.
///
/// This is a best-effort hint, not a security boundary: a compromised
/// container can fake these files. Combined with namespace isolation and
/// Landlock/seccomp, it raises the bar against container escapes.
#[cfg(target_os = "linux")]
pub fn running_in_container() -> bool {
    const CGROUP_HINTS: [&str; 3] = ["/.dockerenv", "/run/.containerenv", "/.containerenv"];
    CGROUP_HINTS.iter().any(|p| Path::new(p).exists())
        || std::fs::read_to_string("/proc/1/cgroup").is_ok_and(|c| {
            c.contains("docker") || c.contains("kubepod") || c.contains("containerd")
        })
        || std::fs::read_to_string("/proc/self/cgroup").is_ok_and(|c| {
            c.contains("docker") || c.contains("kubepod") || c.contains("containerd")
        })
}

/// Enter a new user + mount namespace (unprivileged). Linux-only.
#[cfg(target_os = "linux")]
pub fn enter_userns() -> io::Result<()> {
    // SAFETY: getuid(2) and getgid(2) are always safe, returning the
    // caller's UID/GID.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    // Enter the user namespace FIRST. Requesting CLONE_NEWUSER and
    // CLONE_NEWNS in a single unshare(2) is rejected by the seccomp policy
    // of many container runtimes, whereas a user namespace followed by a
    // mount namespace is allowed once uid/gid are mapped. So we split the
    // two into sequential calls.
    unshare_userns_when_single_threaded()?;

    write_proc("/proc/self/uid_map", &format!("0 {uid} 1"))?;
    write_proc("/proc/self/setgroups", "deny")?;
    write_proc("/proc/self/gid_map", &format!("0 {gid} 1"))?;

    // Now that we are root inside the new user namespace, create a mount
    // namespace. This is permitted here even though CLONE_NEWNS alone is
    // blocked at the outset; the mount ns is created inside a fully mapped
    // userns.
    // SAFETY: unshare(2) with CLONE_NEWNS creates a new mount namespace;
    // allowed now because the caller is mapped to root in the userns.
    unsafe {
        let rc = libc::unshare(libc::CLONE_NEWNS);
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    Ok(())
}

/// Upper bound on the wait for the thread group to drain. The window is a
/// few microseconds in practice; a bound keeps a genuinely threaded caller
/// from hanging and lets the real EINVAL surface.
#[cfg(target_os = "linux")]
const SINGLE_THREAD_ATTEMPTS: u32 = 200;

/// `unshare(CLONE_NEWUSER)` implies `CLONE_THREAD` and is refused with
/// EINVAL while the thread group has more than one member. A worker thread
/// that was *just joined* still counts: the kernel wakes the joiner from
/// `mm_release` before `release_task` unlinks the thread, so the cold-start
/// rootfs hashing (one worker per core, then joined) races the unshare that
/// follows and makes a fresh bundle fail its first launch on a busy host.
/// Wait for `/proc/self/task` to show a single entry and retry on EINVAL.
#[cfg(target_os = "linux")]
fn unshare_userns_when_single_threaded() -> io::Result<()> {
    let mut attempts = 0;
    loop {
        wait_single_threaded();
        // SAFETY: unshare(2) with CLONE_NEWUSER creates a new user namespace
        // and does not require CAP_SYS_ADMIN (ANSSI DENV-STABLE: no nightly).
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        attempts += 1;
        if err.raw_os_error() != Some(libc::EINVAL) || attempts >= SINGLE_THREAD_ATTEMPTS {
            return Err(err);
        }
        std::thread::sleep(std::time::Duration::from_micros(200));
    }
}

/// Spin (bounded) until this process has a single task, i.e. every joined
/// worker has been unlinked from the thread group by the kernel.
#[cfg(target_os = "linux")]
fn wait_single_threaded() {
    for _ in 0..SINGLE_THREAD_ATTEMPTS {
        match std::fs::read_dir("/proc/self/task").map(|d| d.count()) {
            Ok(n) if n > 1 => std::thread::sleep(std::time::Duration::from_micros(200)),
            // One task, or no procfs to ask: let unshare(2) be the judge.
            _ => return,
        }
    }
}

/// Enter a new PID namespace (`CLONE_NEWPID`).
///
/// Only the *children* of the calling process land in the new namespace, and
/// the next child to be forked becomes PID 1 there. A fresh procfs can be
/// mounted **only from inside** the new PID namespace, so callers must fork
/// after this and do the `mount("proc")` in the child. Must run before any
/// threads exist, like the user/mount unshares.
#[cfg(target_os = "linux")]
pub fn enter_newpid() -> io::Result<()> {
    // SAFETY: unshare(2) with CLONE_NEWPID creates a new PID namespace for
    // future children; permitted for a mapped root in an existing userns.
    // Does not change the caller's own PID.
    let rc = unsafe { libc::unshare(libc::CLONE_NEWPID) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Write a procfs file (`uid_map`/`gid_map`). Linux-only.
#[cfg(target_os = "linux")]
pub fn write_proc(path: &str, contents: &str) -> io::Result<()> {
    let mut f = File::create(path)?;
    f.write_all(contents.as_bytes())?;
    Ok(())
}
