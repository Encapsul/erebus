//! Garbage collection for the content-addressed blob store.
//!
//! The registry keeps every blob under its SHA-256 content hash. Blobs that
//! are no longer reachable from any artifact manifest are orphans — keeping
//! them leaks disk for every deleted or superseded artifact. This module
//! finds orphans and moves them to a trash directory, where a later sweep can
//! remove them or a human can recover them. Moving to trash (never deleting
//! outright) keeps the soft-delete recovery guarantee intact.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

/// Result of a garbage-collection pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GcResult {
    /// Blobs moved to trash (filenames, which are their SHA-256 hex digests).
    pub reclaimed: Vec<String>,
    /// Bytes freed from the live store by the move.
    pub bytes_reclaimed: u64,
    /// Live blobs verified present and referenced.
    pub live_count: usize,
}

/// A single artifact manifest that references blobs by SHA-256 hex digest.
#[derive(Debug, Clone, Default)]
pub struct BlobReference {
    /// Hex SHA-256 digests referenced by this manifest.
    pub blobs: Vec<String>,
}

/// Read `blob_dir` and `manifest_dir`, returning the orphaned blobs that are
/// not referenced by any manifest in `manifest_dir`.
///
/// Blob files are expected to be named by their SHA-256 hex digest. Manifests
/// may be any files (JSON or otherwise) whose contents are scanned for
/// tokens matching a 64-char lowercase hex digest — resilient to schema drift.
///
/// `trash_dir` is created if absent. Live blobs are left untouched.
///
/// # Errors
///
/// Returns an IO error if the blob directory cannot be read.
pub fn collect_garbage(
    blob_dir: &Path,
    manifest_dir: &Path,
    trash_dir: &Path,
) -> io::Result<GcResult> {
    let live: HashSet<String> = scan_referenced_hashes(manifest_dir)?;

    let mut reclaimed = Vec::new();
    let mut bytes_reclaimed = 0u64;
    let mut live_count = 0usize;

    fs::create_dir_all(trash_dir)?;
    let entries = match fs::read_dir(blob_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(GcResult {
                reclaimed,
                bytes_reclaimed,
                live_count,
            });
        }
        Err(e) => return Err(e),
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !is_hex_sha256(&name) {
            continue;
        }
        if live.contains(&name) {
            live_count += 1;
            continue;
        }
        // Orphan: move to trash instead of deleting.
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        let dest = trash_dir.join(format!("{name}.gc"));
        if fs::rename(&path, &dest).is_err() {
            // Cross-device rename falls back to copy+remove.
            if fs::copy(&path, &dest).is_err() {
                continue;
            }
            let _ = fs::remove_file(&path);
        }
        reclaimed.push(name);
        bytes_reclaimed += size;
    }
    // Deduplicate in case two manifests claimed the same hash.
    reclaimed.sort();
    reclaimed.dedup();

    Ok(GcResult {
        reclaimed,
        bytes_reclaimed,
        live_count,
    })
}

/// Walk `manifest_dir` and collect every 64-char lowercase hex token found in
/// file contents. These are the reachable blob digests.
fn scan_referenced_hashes(manifest_dir: &Path) -> io::Result<HashSet<String>> {
    let mut live = HashSet::new();
    let entries = match fs::read_dir(manifest_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(live),
        Err(e) => return Err(e),
    };
    const MAX_CHUNK: usize = 1 << 20;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let mut buf = Vec::new();
        let mut file = fs::File::open(&path)?;
        use std::io::Read;
        loop {
            let mut chunk = vec![0u8; MAX_CHUNK];
            let n = file.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            chunk.truncate(n);
            buf.extend_from_slice(&chunk);
            if buf.len() > (1 << 24) {
                // Manifest too large to be a hash index; skip remainder.
                break;
            }
        }
        // ASCII-hex only: walk the buffer for 64-char runs of [0-9a-f].
        collect_hex_tokens(&buf, &mut live);
    }
    Ok(live)
}

/// Extract every ASCII `[0-9a-f]{64}` run from `buf` into `out`.
fn collect_hex_tokens(buf: &[u8], out: &mut HashSet<String>) {
    let mut start: Option<usize> = None;
    for (i, &b) in buf.iter().enumerate() {
        let is_lower_hex = b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        let is_upper_hex = (b'A'..=b'F').contains(&b);
        // Only lowercase hexd runs are accepted; any other byte resets.
        if is_lower_hex {
            let s = start.get_or_insert(i);
            if i - *s + 1 == 64 {
                let token = String::from_utf8_lossy(&buf[*s..=i]).into_owned();
                out.insert(token);
                start = None;
            }
        } else if is_upper_hex || !b.is_ascii_hexdigit() {
            start = None;
        }
    }
}

/// True when `name` is exactly a 64-char lowercase hex digest.
fn is_hex_sha256(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("erebus-gc-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn is_hex_digest_helper() {
        assert!(is_hex_sha256(&"a".repeat(64)));
        assert!(!is_hex_sha256(&"A".repeat(64))); // uppercase rejected
        assert!(!is_hex_sha256(&"a".repeat(63)));
        assert!(!is_hex_sha256(&"z".repeat(64)));
    }

    #[test]
    fn collects_orphans_and_keeps_live() {
        let dir = test_dir("basic");
        let blob = dir.join("blobs");
        let man = dir.join("manifests");
        let trash = dir.join("trash");
        fs::create_dir_all(&blob).unwrap();
        fs::create_dir_all(&man).unwrap();

        let live_hash = "a".repeat(64);
        let orphan_hash = "b".repeat(64);
        fs::write(blob.join(&live_hash), b"live blob").unwrap();
        fs::write(blob.join(&orphan_hash), b"orphan blob").unwrap();
        fs::write(man.join("app.json"), format!(r#"{{"blob":"{live_hash}"}}"#)).unwrap();

        let res = collect_garbage(&blob, &man, &trash).unwrap();
        assert_eq!(res.reclaimed, vec![orphan_hash.clone()]);
        assert!(res.bytes_reclaimed > 0);
        assert_eq!(res.live_count, 1);
        // Live blob stays; orphan moved to trash.
        assert!(blob.join(&live_hash).exists());
        assert!(!blob.join(&orphan_hash).exists());
        assert!(trash.join(format!("{orphan_hash}.gc")).exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn empty_blob_dir_is_ok() {
        let dir = test_dir("empty");
        let blob = dir.join("blobs");
        fs::create_dir_all(&blob).unwrap();
        let res = collect_garbage(&blob, &dir.join("manifests"), &dir.join("trash")).unwrap();
        assert!(res.reclaimed.is_empty());
        assert_eq!(res.bytes_reclaimed, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn non_hash_files_ignored() {
        let dir = test_dir("names");
        let blob = dir.join("blobs");
        fs::create_dir_all(&blob).unwrap();
        fs::write(blob.join("README.txt"), b"hi").unwrap();
        let res = collect_garbage(&blob, &dir.join("manifests"), &dir.join("trash")).unwrap();
        assert!(res.reclaimed.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_manifest_dir_yields_all_orphans() {
        let dir = test_dir("no-manifest");
        let blob = dir.join("blobs");
        fs::create_dir_all(&blob).unwrap();
        let hash = "c".repeat(64);
        fs::write(blob.join(&hash), b"x").unwrap();
        let res = collect_garbage(&blob, &dir.join("manifests"), &dir.join("trash")).unwrap();
        assert_eq!(res.reclaimed, vec![hash]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
