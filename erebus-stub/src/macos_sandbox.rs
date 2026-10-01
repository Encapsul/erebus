//! macOS filesystem sandbox via Seatbelt (`sandbox_init`), the counterpart
//! of the Linux Landlock sandbox for bundles built with `--landlock`.
//!
//! The profile is applied to the process that execs the payload and is
//! inherited across `execve` by the payload and its children. It denies
//! reading file *contents* and writing anywhere, then re-allows:
//!
//! - reads of the system trees a Mach-O or interpreter needs (`/usr`,
//!   `/System`, `/Library`, `/bin`, `/sbin`, `/dev`, `/private/etc`,
//!   `/private/var/db`) and of the root directory entry itself (dyld fails
//!   with SIGABRT without it);
//! - reads and writes under the extracted rootfs and a private `TMPDIR`
//!   beside it, plus `/dev/null`, `/dev/tty`, `/dev/dtracehelper`.
//!
//! The home directory, `/private/var/folders` (per-user temp), `/tmp`,
//! `/Volumes` and every other path are unreadable. Metadata (`stat`) stays
//! readable. With `ERE_EGRESS` (see `egress`) the same profile also limits
//! outbound connections to `localhost:<port>` (Unix sockets stay open);
//! IPC and process operations are not restricted.
//!
//! `sandbox_init` with SBPL text is a deprecated but supported API (it backs
//! `sandbox-exec`). Failure is fatal: a bundle that asked for a filesystem
//! sandbox never runs without one.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString};
use std::io;
use std::os::raw::{c_char, c_int};
use std::path::{Path, PathBuf};

extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Read-only system trees: what dyld, libSystem and the host interpreters
/// open. Everything else is denied.
const SYSTEM_READ: [&str; 8] = [
    "/usr",
    "/System",
    "/Library",
    "/bin",
    "/sbin",
    "/dev",
    "/private/etc",
    "/private/var/db",
];

const DEVICE_WRITE: [&str; 3] = ["/dev/null", "/dev/tty", "/dev/dtracehelper"];

/// SBPL string literal; paths come from the filesystem, so quote them.
fn sbpl_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len().saturating_add(2));
    out.push('"');
    for c in s.chars() {
        if c == '"' || c == '\\' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

/// The Seatbelt profile: filesystem confinement to `fs = (rootfs, tmp)`
/// and/or outbound connections only to `localhost:<port>` for each egress
/// port. Paths must be canonical: Seatbelt matches resolved paths
/// (`/private/var`, never the `/var` symlink).
pub fn profile(fs: Option<(&Path, &Path)>, egress: Option<&[u16]>) -> String {
    let mut out = String::from("(version 1)\n(allow default)\n");
    if let Some((rootfs, tmp)) = fs {
        out.push_str(&fs_rules(rootfs, tmp));
    }
    if let Some(ports) = egress {
        let remotes: Vec<String> = ports
            .iter()
            .map(|p| format!("(remote ip \"localhost:{p}\")"))
            .collect();
        out.push_str(&format!(
            "(deny network-outbound)\n(allow network-outbound (remote unix-socket) {})\n",
            remotes.join(" ")
        ));
    }
    out
}

fn fs_rules(rootfs: &Path, tmp: &Path) -> String {
    let sub = |p: &str| format!("(subpath {})", sbpl_string(p));
    let lit = |p: &str| format!("(literal {})", sbpl_string(p));
    let own = [rootfs, tmp].map(|p| sub(&p.to_string_lossy()));
    let reads: Vec<String> = SYSTEM_READ.iter().map(|p| sub(p)).collect();
    let devices: Vec<String> = DEVICE_WRITE.iter().map(|p| lit(p)).collect();
    format!(
        "(deny file-read-data file-write*)\n\
         (allow file-read-data {} {} {})\n(allow file-write* {} {})\n",
        lit("/"),
        reads.join(" "),
        own.join(" "),
        own.join(" "),
        devices.join(" "),
    )
}

/// Private temp directory beside the rootfs, so `TMPDIR` users keep working
/// without opening the per-user temp tree (where other secrets live).
fn private_tmp(rootfs: &Path) -> io::Result<PathBuf> {
    let base = rootfs.parent().unwrap_or(rootfs);
    let tmp = base.join("tmp");
    std::fs::create_dir_all(&tmp)?;
    tmp.canonicalize()
}

/// Confine this process (and the payload it is about to exec): to the
/// rootfs when `rootfs` is given (setting `TMPDIR` to the private temp
/// directory), to the egress ports when `egress` is given. One profile:
/// Seatbelt profiles cannot be installed twice.
pub fn apply_sandbox(rootfs: Option<&Path>, egress: Option<&[u16]>) -> io::Result<()> {
    let fs = rootfs
        .map(|r| {
            let root = r.canonicalize()?;
            let tmp = private_tmp(&root)?;
            Ok::<_, io::Error>((root, tmp))
        })
        .transpose()?;
    let text = CString::new(profile(
        fs.as_ref().map(|(r, t)| (r.as_path(), t.as_path())),
        egress,
    ))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in rootfs path"))?;
    install(&text)?;
    if let Some((_, tmp)) = &fs {
        std::env::set_var("TMPDIR", tmp);
    }
    Ok(())
}

fn install(profile: &CStr) -> io::Result<()> {
    let mut err: *mut c_char = std::ptr::null_mut();
    // SAFETY: `profile` is a valid NUL-terminated string that outlives the
    // call; flags 0 means "SBPL source text"; `err` is a valid out-pointer
    // that the call either leaves null or sets to a buffer we must free.
    let rc = unsafe { sandbox_init(profile.as_ptr(), 0, &mut err) };
    if rc == 0 {
        return Ok(());
    }
    let msg = if err.is_null() {
        "unknown error".to_string()
    } else {
        // SAFETY: on failure `err` points to a NUL-terminated message owned
        // by libsandbox; it is copied before being released exactly once.
        let m = unsafe { CStr::from_ptr(err) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: `err` came from sandbox_init and is not used afterwards.
        unsafe { sandbox_free_error(err) };
        m
    };
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("seatbelt sandbox_init failed: {msg}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_quotes_paths_and_scopes_writes_to_owned_trees() {
        let p = profile(
            Some((
                Path::new("/private/x/ro\"o\\t"),
                Path::new("/private/x/tmp"),
            )),
            None,
        );
        assert!(!p.contains("network"), "no egress rules unless asked: {p}");
        assert!(p.contains(r#"(subpath "/private/x/ro\"o\\t")"#), "{p}");
        assert!(p.contains("(deny file-read-data file-write*)"));
        let writes = p
            .lines()
            .find(|l| l.starts_with("(allow file-write*"))
            .unwrap();
        assert!(writes.contains("/private/x/tmp") && writes.contains("/dev/null"));
        assert!(
            !writes.contains("\"/usr\""),
            "system trees are read-only: {writes}"
        );
    }

    /// The real kernel check, in a child process so the test runner stays
    /// unconfined: inside the rootfs is readable, a file beside it is not.
    #[test]
    fn seatbelt_blocks_reads_outside_the_rootfs() {
        let _guard = crate::FORK_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::write(rootfs.join("in.txt"), b"inside").unwrap();
        std::fs::write(dir.path().join("canary.txt"), b"secret").unwrap();
        let root = rootfs.canonicalize().unwrap();
        let tmp = private_tmp(&root).unwrap();
        let script = format!(
            "cat {0}/in.txt; cat {1}/canary.txt 2>/dev/null || echo BLOCKED; \
             echo w > {2}/w && echo TMP-OK",
            root.display(),
            dir.path().canonicalize().unwrap().display(),
            tmp.display()
        );
        let out = std::process::Command::new("sandbox-exec")
            .arg("-p")
            .arg(profile(Some((&root, &tmp)), None))
            .args(["/bin/sh", "-c", &script])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(stdout, "insideBLOCKED\nTMP-OK\n", "{out:?}");
    }

    /// The real kernel check for `ERE_EGRESS`: the listed loopback port
    /// connects, another loopback port and a public address do not.
    #[test]
    fn seatbelt_limits_egress_to_the_listed_localhost_ports() {
        let _guard = crate::FORK_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let a = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let b = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (pa, pb) = (
            a.local_addr().unwrap().port(),
            b.local_addr().unwrap().port(),
        );
        let probe = |port: String, host: &str| {
            format!("/usr/bin/nc -z -G 2 {host} {port} 2>/dev/null && echo OPEN || echo CLOSED")
        };
        let script = [
            probe(pa.to_string(), "127.0.0.1"),
            probe(pb.to_string(), "127.0.0.1"),
            probe("443".into(), "1.1.1.1"),
        ]
        .join("; ");
        let run = |p: String| {
            let out = std::process::Command::new("sandbox-exec")
                .args(["-p", &p, "/bin/sh", "-c", &script])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).replace('\n', " ")
        };
        assert_eq!(run(profile(None, Some(&[pa]))), "OPEN CLOSED CLOSED ");
        assert_eq!(run(profile(None, Some(&[]))), "CLOSED CLOSED CLOSED ");
        // Control: the same probes unconfined reach both local listeners.
        assert!(run(profile(None, None)).starts_with("OPEN OPEN "));
    }
}
