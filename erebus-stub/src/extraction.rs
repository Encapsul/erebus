//! Atomic extraction for the erebus launcher stub.
//!
//! Provides `extract_atomic` (zstd+tar) and `extract_squashfs_atomic`
//! (squashfs), both built on the shared `atomic_extract` helper.
//! All operations are atomic: extraction happens in a tmp directory and
//! is renamed into place only on success.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

use crate::nanos;

/// Default maximum total decompressed bytes across all tar entries (1 GB).
const DEFAULT_MAX_DECOMPRESSED_BYTES: u64 = 1024 * 1024 * 1024;
/// Slack added on top of declared model-layer sizes so a payload containing
/// multi-GB model weights extracts without operator intervention, while the
/// bomb limit still applies to everything else.
const MODEL_ALLOWANCE_SLACK: u64 = 64 * 1024 * 1024;
/// Default maximum number of files in a single tar archive.
const DEFAULT_MAX_FILES: usize = 50_000;

/// Decompression-bomb limits for `extract_atomic`. Both are configurable at
/// runtime via env vars so operators can tighten (or relax) them per workload
/// without rebuilding the stub:
/// - `ERE_MAX_EXTRACT_SIZE`  — total decompressed bytes (default 1 GiB)
/// - `ERE_MAX_EXTRACT_FILES` — entry/file count (default 50,000)
///
/// The env vars are read once per extraction and only from the launcher's own
/// process environment — they are NOT parsed from the (untrusted) payload, so
/// an attacker cannot weaken the limits by smuggling values into the erebus.
///
/// `extra_allowance` is the sum of declared `ModelLayer` sizes from the
/// integrity-verified metadata: legitimate AI payloads legitimately exceed
/// the default bomb ceiling, so the effective byte limit is raised to fit
/// them (plus slack). Everything else stays under the configured cap.
struct ExtractLimits {
    max_bytes: u64,
    max_files: usize,
}

impl ExtractLimits {
    fn from_env(extra_allowance: u64) -> Self {
        let configured = std::env::var("ERE_MAX_EXTRACT_SIZE")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_DECOMPRESSED_BYTES);
        let max_bytes = configured.max(extra_allowance.saturating_add(MODEL_ALLOWANCE_SLACK));
        let max_files = std::env::var("ERE_MAX_EXTRACT_FILES")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(DEFAULT_MAX_FILES);
        Self {
            max_bytes,
            max_files,
        }
    }
}

/// Whether a cached extraction can be trusted as-is.
///
/// The warm path skips signature/integrity verification and execs whatever
/// lives at `cache_root/rootfs`; that is only sound if the cache directory is
/// owned by the current user and not group/other-writable (a wrong owner or a
/// 0o777 dir means someone else could have planted the rootfs). On non-Unix
/// platforms there is no permission model to inspect, so we trust the cache.
#[cfg(unix)]
pub fn cache_root_trustworthy(cache_root: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(meta) = fs::metadata(cache_root) else {
        return false;
    };
    // SAFETY: geteuid(2) cannot fail and has no invalid inputs; the effective
    // uid identifies who the kernel would credit as owner of a file we create.
    let euid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != euid {
        return false;
    }
    // Group/other-write bits would let any co-resident user replace the
    // extracted rootfs with their own code, so treat such a cache as absent.
    meta.mode() & 0o022 == 0
}

/// Non-Unix platforms have no permission model to inspect — trust the cache.
#[cfg(not(unix))]
pub fn cache_root_trustworthy(_cache_root: &Path) -> bool {
    true
}

/// Check whether the on-disk source binary still matches the cache.
///
/// Stores the source file's size + mtime in `<cache_root>/.source` (JSON).
/// On warm-start this detects byte-flips in the payload that would keep the
/// footer's SHA-256 cache key unchanged.
pub fn source_manifest_matches(
    cache_root: &Path,
    expected_size: u64,
    expected_mtime: std::time::SystemTime,
) -> bool {
    let manifest_path = cache_root.join(".source");
    let content = match std::fs::read_to_string(&manifest_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let Ok(manifest) = serde_json::from_str::<SourceManifest>(&content) else {
        return false;
    };
    manifest.size == expected_size
        && manifest.mtime_ns
            == expected_mtime
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
}

#[derive(serde::Deserialize, serde::Serialize)]
struct SourceManifest {
    size: u64,
    mtime_ns: u128,
}

/// Record the source file's identity after a successful extraction so the
/// warm path can detect tampering.
pub fn write_source_manifest(
    cache_root: &Path,
    size: u64,
    mtime: std::time::SystemTime,
) -> io::Result<()> {
    let manifest = SourceManifest {
        size,
        mtime_ns: mtime
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    };
    let path = cache_root.join(".source");
    let json = serde_json::to_string(&manifest)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("serde_json: {e}")))?;
    std::fs::write(path, json)
}

/// `ERE_ROOTFS_CHECK`: `off` skips the warm-start rootfs verification (and
/// the read-only bits), `strict` also rejects files the app created at
/// runtime, anything else is the default (tracked files must be intact).
fn rootfs_check_mode() -> String {
    std::env::var("ERE_ROOTFS_CHECK")
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default()
}

/// After a cold extraction: hash every extracted file into
/// `<cache_root>/rootfs.merkle` and strip write bits so in-place edits fail.
/// Returns the `sha256:<root>` that receipts will carry.
pub fn record_rootfs_manifest(cache_root: &Path, rootfs: &Path) -> io::Result<String> {
    let manifest = erebus_core::rootfs_merkle::compute(rootfs)?;
    erebus_core::rootfs_merkle::write(cache_root, &manifest)?;
    if rootfs_check_mode() != "off" {
        erebus_core::rootfs_merkle::make_files_read_only(rootfs, &manifest)?;
    }
    Ok(manifest.root_display())
}

/// Warm start gate (ROADMAP P0-4): re-hash the cached rootfs against its
/// manifest. `Err(reason)` means the cache must be rebuilt from the verified
/// bundle — a missing manifest (cache predating this check) counts too.
pub fn rootfs_intact(cache_root: &Path, rootfs: &Path) -> Result<(), String> {
    use erebus_core::rootfs_merkle::{read, verify, Verdict};
    let mode = rootfs_check_mode();
    if mode == "off" {
        return Ok(());
    }
    let manifest = match read(cache_root) {
        Ok(Some(m)) => m,
        Ok(None) => return Err("no rootfs.merkle in cache".to_string()),
        Err(e) => return Err(format!("unreadable rootfs.merkle: {e}")),
    };
    match verify(rootfs, &manifest, mode == "strict") {
        Ok(Verdict::Intact { .. }) => Ok(()),
        Ok(Verdict::Modified(problems)) => {
            let shown: Vec<&str> = problems.iter().take(5).map(String::as_str).collect();
            let more = problems.len().saturating_sub(shown.len());
            let suffix = if more > 0 {
                format!(" (+{more} more)")
            } else {
                String::new()
            };
            Err(format!("{}{suffix}", shown.join(", ")))
        }
        Err(e) => Err(format!("rootfs hashing failed: {e}")),
    }
}

/// Extract zstd-compressed tar blobs atomically into `cache_root/rootfs`.
///
/// `model_bytes` is the total declared size of model layers in the
/// integrity-verified metadata; the extraction byte ceiling is raised to fit
/// them (plus slack), so multi-GB model payloads extract without operator
/// intervention while the decompression-bomb cap still applies otherwise.
pub fn extract_atomic(blobs: &[&[u8]], cache_root: &Path, model_bytes: u64) -> io::Result<()> {
    atomic_extract(cache_root, |tmp_rootfs| {
        let limits = ExtractLimits::from_env(model_bytes);
        let mut total_bytes: u64 = 0;
        let mut file_count: usize = 0;
        for blob in blobs {
            let mut decoder = zstd::Decoder::new(io::Cursor::new(*blob))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("zstd: {e}")))?;
            let mut archive = tar::Archive::new(&mut decoder);
            archive.set_preserve_permissions(true);
            archive.set_overwrite(true);

            // Iterate entries manually to enforce size + file-count limits
            // (decompression-bomb defense).  `tar::unpack` alone has no limits.
            for entry in archive.entries()? {
                let mut entry = entry?;
                let size = entry.size();
                if size > limits.max_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("tar entry exceeds max size: {size} > {}", limits.max_bytes),
                    ));
                }
                total_bytes = total_bytes.saturating_add(size);
                if total_bytes > limits.max_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "total decompressed size {total_bytes} exceeds {}",
                            limits.max_bytes
                        ),
                    ));
                }
                file_count = file_count.saturating_add(1);
                if file_count > limits.max_files {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "file count exceeds max: {file_count} > {}",
                            limits.max_files
                        ),
                    ));
                }
                entry.unpack_in(tmp_rootfs)?;
            }
        }
        Ok(())
    })
}

/// Extract squashfs blobs atomically into `cache_root/rootfs`.
pub fn extract_squashfs_atomic(blobs: &[&[u8]], cache_root: &Path) -> io::Result<()> {
    atomic_extract(cache_root, |tmp_rootfs| {
        crate::squashfs_extract::extract_squashfs_layers(blobs, tmp_rootfs)
    })
}

/// Shared atomic extraction: create tmp dir, run extraction closure, write .ready, rename.
///
/// On rename failure, a stale `cache_root` (no `.ready`) is wiped and the
/// rename is retried once; a `cache_root` that carries a valid `.ready` is a
/// previous successful extraction and is used as-is.
pub fn atomic_extract(
    cache_root: &Path,
    extract_fn: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<()> {
    let parent = cache_root.parent().unwrap_or(Path::new("/tmp"));
    fs::create_dir_all(parent)?;

    let tmp = parent.join(format!(".tmp-{}-{}", std::process::id(), nanos()));
    let tmp_rootfs = tmp.join("rootfs");
    fs::create_dir_all(&tmp_rootfs)?;

    extract_fn(&tmp_rootfs)?;

    // A freshly extracted cache is private to the invoking user regardless of
    // umask; otherwise a lax umask would produce a group/other-writable cache
    // that `cache_root_trustworthy` then rejects on every warm start.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o700))?;
    }

    File::create(tmp.join(".ready"))?.write_all(b"1")?;

    // The marker lives at cache_root/.ready (the tmp dir becomes cache_root
    // on rename), so the stale-partial check below must look there.
    let marker = cache_root.join(".ready");
    match fs::rename(&tmp, cache_root) {
        Ok(()) => Ok(()),
        Err(e) => {
            // A valid .ready marker means a concurrent/successful extraction
            // already completed — surface the error but don't block the run.
            // The marker only legitimizes the cache when the directory is
            // owned by us with sane perms; a foreign cache is wiped instead.
            if marker.exists() && cache_root_trustworthy(cache_root) {
                let _ = fs::remove_dir_all(&tmp);
                eprintln!("[erebus] warning: cache rename failed but existing cache is valid: {e}");
                Ok(())
            } else {
                // Otherwise cache_root is a stale partial extraction (no
                // .ready). Wipe it and retry the rename once with tmp intact,
                // instead of leaving the binary permanently stuck on every
                // cold start.
                let _ = fs::remove_dir_all(cache_root);
                match fs::rename(&tmp, cache_root) {
                    Ok(()) => Ok(()),
                    Err(e2) => {
                        let _ = fs::remove_dir_all(&tmp);
                        Err(e2)
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_app(tmp_rootfs: &Path) -> io::Result<()> {
        fs::create_dir_all(tmp_rootfs.join("app"))?;
        fs::write(tmp_rootfs.join("app/app.py"), b"print('hi')")
    }

    // ── Chaos: decompression-bomb limit math ────────────────────────────

    // `from_env` reads ERE_MAX_EXTRACT_SIZE, and one test below sets it.
    // Tests run in parallel threads sharing one process environment, so
    // every reader must hold this lock or it may observe the other test's
    // value (seen as a 1-in-N flake on CI).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn limits_default_without_model_allowance() {
        let _env = ENV_LOCK.lock().unwrap();
        let l = ExtractLimits::from_env(0);
        assert_eq!(l.max_bytes, DEFAULT_MAX_DECOMPRESSED_BYTES);
        assert_eq!(l.max_files, DEFAULT_MAX_FILES);
    }

    #[test]
    fn limits_raise_ceiling_for_declared_models() {
        let _env = ENV_LOCK.lock().unwrap();
        let model = 3u64 * 1024 * 1024 * 1024; // 3 GB of declared weights
        let l = ExtractLimits::from_env(model);
        assert_eq!(l.max_bytes, model + MODEL_ALLOWANCE_SLACK);
    }

    #[test]
    fn limits_env_cap_wins_when_larger_than_models() {
        let _env = ENV_LOCK.lock().unwrap();
        std::env::set_var("ERE_MAX_EXTRACT_SIZE", "9000000000");
        let l = ExtractLimits::from_env(1024);
        std::env::remove_var("ERE_MAX_EXTRACT_SIZE");
        assert_eq!(l.max_bytes, 9_000_000_000);
    }

    #[test]
    fn limits_saturate_on_huge_declaration() {
        let _env = ENV_LOCK.lock().unwrap();
        let l = ExtractLimits::from_env(u64::MAX);
        assert_eq!(l.max_bytes, u64::MAX);
    }

    /// A payload whose entries exceed the configured byte ceiling is rejected.
    /// Uses an explicit 64 KiB ceiling (no env dependency for determinism).
    #[test]
    fn extract_rejects_bomb_without_model_allowance() {
        let dir = TempDir::new().unwrap();
        let cache_root = dir.path().join("hash");

        // 2 MiB of zeros compresses to a few KB — classic bomb shape.
        let mut builder = tar::Builder::new(zstd::Encoder::new(Vec::new(), 1).unwrap());
        let big = vec![0u8; 2 * 1024 * 1024];
        let mut header = tar::Header::new_gnu();
        header.set_size(big.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "app/bomb.bin", big.as_slice())
            .unwrap();
        let encoder = builder.into_inner().unwrap();
        let blob = encoder.finish().unwrap();

        let res = atomic_extract(&cache_root, |tmp| {
            let limits = ExtractLimits {
                max_bytes: 64 * 1024,
                max_files: DEFAULT_MAX_FILES,
            };
            let decoder = zstd::Decoder::new(io::Cursor::new(&blob)).unwrap();
            let mut archive = tar::Archive::new(decoder);
            let mut total: u64 = 0;
            for entry in archive.entries().unwrap() {
                let mut e = entry.unwrap();
                total = total.saturating_add(e.size());
                if total > limits.max_bytes {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "bomb"));
                }
                e.unpack_in(tmp)?;
            }
            Ok(())
        });
        assert!(res.is_err(), "undeclared bomb must be rejected");
        assert!(
            !cache_root.exists(),
            "failed extraction must not leave cache"
        );
    }

    /// Same bomb passes when model bytes are declared (ceiling raised).
    #[test]
    fn extract_accepts_bomb_with_matching_model_allowance() {
        let dir = TempDir::new().unwrap();
        let cache_root = dir.path().join("hash");

        let big = vec![0u8; 2 * 1024 * 1024];
        let mut builder = tar::Builder::new(zstd::Encoder::new(Vec::new(), 1).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(big.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "models/agent.gguf", big.as_slice())
            .unwrap();
        let blob = builder.into_inner().unwrap().finish().unwrap();

        atomic_extract(&cache_root, |tmp| {
            let limits = ExtractLimits::from_env(big.len() as u64);
            assert!(
                limits.max_bytes >= big.len() as u64,
                "allowance must cover declared models"
            );
            let decoder = zstd::Decoder::new(io::Cursor::new(&blob)).unwrap();
            let mut archive = tar::Archive::new(decoder);
            for entry in archive.entries().unwrap() {
                let mut e = entry.unwrap();
                e.unpack_in(tmp)?;
            }
            Ok(())
        })
        .unwrap();
        assert!(cache_root.join("rootfs/models/agent.gguf").is_file());
    }

    #[test]
    fn extract_creates_marker_and_rootfs() {
        let dir = TempDir::new().unwrap();
        let cache_root = dir.path().join("hash");

        atomic_extract(&cache_root, write_app).unwrap();

        assert!(cache_root.join(".ready").is_file());
        assert!(cache_root.join("rootfs/app/app.py").is_file());
    }

    /// P0-4 acceptance: a file edited after the cold start (same size, so
    /// size/mtime heuristics would miss it) forces a re-extraction, after
    /// which the manifest root matches the pristine tree again.
    #[test]
    fn warm_start_refuses_modified_rootfs_and_reextraction_restores_root() {
        let dir = TempDir::new().unwrap();
        let cache_root = dir.path().join("hash");
        let rootfs = cache_root.join("rootfs");
        atomic_extract(&cache_root, write_app).unwrap();

        // Cache predating the manifest → must rebuild.
        assert!(rootfs_intact(&cache_root, &rootfs).is_err());

        let root = record_rootfs_manifest(&cache_root, &rootfs).unwrap();
        assert!(root.starts_with("sha256:"));
        assert!(cache_root
            .join(erebus_core::rootfs_merkle::MANIFEST_FILE)
            .is_file());
        assert_eq!(rootfs_intact(&cache_root, &rootfs), Ok(()));
        assert_eq!(
            erebus_core::rootfs_merkle::read_root(&cache_root).as_deref(),
            Some(root.as_str())
        );

        // Runtime artefact: tolerated. Tampered tracked file: refused.
        fs::write(rootfs.join("app/app.pyc"), b"cache").unwrap();
        assert_eq!(rootfs_intact(&cache_root, &rootfs), Ok(()));
        let target = rootfs.join("app/app.py");
        let original = fs::read(&target).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Read-only bits block casual edits; an attacker with chmod still
            // gets caught by the hash below.
            assert!(fs::write(&target, &original).is_err());
            fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut evil = original.clone();
        evil[0] ^= 0xff;
        fs::write(&target, &evil).unwrap();
        let reason = rootfs_intact(&cache_root, &rootfs).unwrap_err();
        assert!(reason.contains("modified: app/app.py"), "{reason}");

        // What main.rs does: drop the marker, re-extract, re-record.
        fs::remove_file(cache_root.join(".ready")).unwrap();
        atomic_extract(&cache_root, write_app).unwrap();
        assert_eq!(fs::read(&target).unwrap(), original);
        let root2 = record_rootfs_manifest(&cache_root, &rootfs).unwrap();
        assert_eq!(root, root2, "root must be a pure function of the bundle");
        assert_eq!(rootfs_intact(&cache_root, &rootfs), Ok(()));
    }

    #[test]
    fn stale_cache_root_is_wiped_and_retried() {
        let dir = TempDir::new().unwrap();
        let cache_root = dir.path().join("hash");
        fs::create_dir_all(cache_root.join("rootfs")).unwrap();
        fs::write(cache_root.join("rootfs/partial"), b"leftover").unwrap();

        atomic_extract(&cache_root, write_app).unwrap();

        assert!(cache_root.join(".ready").is_file());
        assert!(cache_root.join("rootfs/app/app.py").is_file());
        assert!(!cache_root.join("rootfs/partial").exists());
    }

    #[test]
    #[cfg(unix)]
    fn valid_marker_survives_rename_failure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let cache_root = dir.path().join("hash");
        fs::create_dir_all(cache_root.join("rootfs")).unwrap();
        fs::write(cache_root.join("rootfs/old"), b"previous").unwrap();
        fs::write(cache_root.join(".ready"), b"1").unwrap();
        // The marker only legitimizes a cache the current user owns with sane
        // perms; pin 0o755 so the test does not depend on the shell's umask.
        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();

        atomic_extract(&cache_root, write_app).unwrap();

        assert!(cache_root.join("rootfs/old").exists());
    }

    #[cfg(unix)]
    #[test]
    fn trustworthy_cache_requires_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let cache_root = dir.path().join("hash");
        fs::create_dir_all(&cache_root).unwrap();

        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            cache_root_trustworthy(&cache_root),
            "a user-owned, group/other-read-only dir is trustworthy"
        );

        fs::set_permissions(&cache_root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            !cache_root_trustworthy(&cache_root),
            "a group/other-writable dir must be rejected"
        );

        assert!(!cache_root_trustworthy(&dir.path().join("absent")));
    }
}
