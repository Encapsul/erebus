//! Rootfs manifest with a Merkle root (ROADMAP P0-4).
//!
//! After a cold extraction the launcher records every extracted file
//! (`path → sha256`, sorted) in `<cache_root>/rootfs.merkle` together with the
//! RFC 6962 root over those entries. A warm start recomputes the manifest and
//! refuses to exec a rootfs whose tracked files were modified or deleted;
//! the root is also stamped into the receipt (`execution.rootfs_root`) so an
//! auditor can tie a run to the exact bytes that were on disk.
//!
//! Files the app creates at runtime (`__pycache__`, sqlite journals…) are
//! *untracked*: tolerated by default (otherwise every run would re-extract),
//! rejected in strict mode.
//!
//! ```text
//! erebus-rootfs-merkle v1
//! root sha256:<hex>
//! count <n>
//! <sha256 hex> <f|l> <size> <path>      # one line per entry, sorted by path
//! ```

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::merkle::{self, Hash};

/// Manifest file name inside the cache root (sibling of `rootfs/`).
pub const MANIFEST_FILE: &str = "rootfs.merkle";
const HEADER: &str = "erebus-rootfs-merkle v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Symlink,
}

impl Kind {
    fn tag(self) -> &'static str {
        match self {
            Kind::File => "f",
            Kind::Symlink => "l",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "f" => Some(Kind::File),
            "l" => Some(Kind::Symlink),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `/`-separated path relative to the rootfs.
    pub path: String,
    pub kind: Kind,
    pub size: u64,
    pub sha256: Hash,
}

impl Entry {
    /// Leaf preimage: every field, NUL-separated, so a rename, a size change
    /// or a file↔symlink swap each change the root.
    fn leaf(&self) -> Hash {
        let mut data = Vec::with_capacity(self.path.len() + 64);
        data.extend_from_slice(self.path.as_bytes());
        data.push(0);
        data.extend_from_slice(self.kind.tag().as_bytes());
        data.push(0);
        data.extend_from_slice(self.size.to_string().as_bytes());
        data.push(0);
        data.extend_from_slice(&self.sha256);
        merkle::leaf_hash(&data)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsManifest {
    /// Sorted by `path`.
    pub entries: Vec<Entry>,
    pub root: Hash,
}

/// Outcome of comparing a live rootfs against its manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every tracked file is byte-identical; `untracked` files appeared.
    Intact { tracked: usize, untracked: usize },
    /// Tracked files were modified or deleted (or, in strict mode, added).
    Modified(Vec<String>),
}

impl RootfsManifest {
    pub fn root_display(&self) -> String {
        merkle::display(&self.root)
    }
}

/// Walk `rootfs`, hash every regular file and symlink (in parallel), and
/// build the manifest.
pub fn compute(rootfs: &Path) -> io::Result<RootfsManifest> {
    let mut paths = Vec::new();
    walk(rootfs, rootfs, &mut paths)?;
    paths.sort();
    let entries = hash_all(rootfs, &paths)?;
    let leaves: Vec<Hash> = entries.iter().map(Entry::leaf).collect();
    Ok(RootfsManifest {
        root: merkle::root(&leaves),
        entries,
    })
}

/// Collect relative paths of files and symlinks under `dir` (not followed).
fn walk(rootfs: &Path, dir: &Path, out: &mut Vec<String>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(rootfs, &path, out)?;
        } else if ft.is_file() || ft.is_symlink() {
            if let Some(rel) = relative(rootfs, &path) {
                out.push(rel);
            }
        }
        // Sockets, fifos, devices: not extracted from a tarball, skipped.
    }
    Ok(())
}

fn relative(rootfs: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(rootfs).ok()?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    Some(parts.join("/"))
}

/// Hash `paths` with one worker per available core, preserving order.
fn hash_all(rootfs: &Path, paths: &[String]) -> io::Result<Vec<Entry>> {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(paths.len().max(1));
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<Entry>>> = Mutex::new(vec![None; paths.len()]);
    let failure: Mutex<Option<io::Error>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(rel) = paths.get(i) else {
                    return;
                };
                match hash_one(rootfs, rel) {
                    Ok(e) => {
                        if let Ok(mut r) = results.lock() {
                            r[i] = Some(e);
                        }
                    }
                    Err(e) => {
                        if let Ok(mut f) = failure.lock() {
                            f.get_or_insert(e);
                        }
                        return;
                    }
                }
            });
        }
    });
    if let Some(e) = failure.into_inner().ok().flatten() {
        return Err(e);
    }
    let entries = results.into_inner().map_err(|_| poisoned())?;
    entries
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(poisoned)
}

fn poisoned() -> io::Error {
    io::Error::other("rootfs hashing worker failed")
}

fn hash_one(rootfs: &Path, rel: &str) -> io::Result<Entry> {
    let full = rootfs.join(rel);
    let meta = std::fs::symlink_metadata(&full)?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(&full)?;
        let bytes = target.to_string_lossy().into_owned().into_bytes();
        return Ok(Entry {
            path: rel.to_string(),
            kind: Kind::Symlink,
            size: bytes.len() as u64,
            sha256: Sha256::digest(&bytes).into(),
        });
    }
    let mut file = std::fs::File::open(&full)?;
    let mut hasher = Sha256::new();
    let size = io::copy(&mut file, &mut hasher)?;
    Ok(Entry {
        path: rel.to_string(),
        kind: Kind::File,
        size,
        sha256: hasher.finalize().into(),
    })
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Render the manifest text.
pub fn render(m: &RootfsManifest) -> String {
    let mut out = format!(
        "{HEADER}\nroot {}\ncount {}\n",
        merkle::display(&m.root),
        m.entries.len()
    );
    for e in &m.entries {
        out.push_str(&format!(
            "{} {} {} {}\n",
            hex::encode(e.sha256),
            e.kind.tag(),
            e.size,
            escape(&e.path)
        ));
    }
    out
}

/// Parse a manifest; the root is recomputed from the entries and must
/// match the header (a hand-edited manifest is rejected).
pub fn parse(text: &str) -> io::Result<RootfsManifest> {
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, format!("rootfs.merkle: {m}"));
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(bad("unknown header"));
    }
    let root_line = lines
        .next()
        .and_then(|l| l.strip_prefix("root "))
        .ok_or_else(|| bad("missing root"))?;
    let declared = merkle::parse_hash(root_line).ok_or_else(|| bad("malformed root"))?;
    let count: usize = lines
        .next()
        .and_then(|l| l.strip_prefix("count "))
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| bad("missing count"))?;
    let entries: Vec<Entry> = lines
        .filter(|l| !l.is_empty())
        .map(parse_entry)
        .collect::<Option<_>>()
        .ok_or_else(|| bad("malformed entry"))?;
    if entries.len() != count {
        return Err(bad("entry count mismatch"));
    }
    let leaves: Vec<Hash> = entries.iter().map(Entry::leaf).collect();
    let root = merkle::root(&leaves);
    if root != declared {
        return Err(bad("declared root does not match entries"));
    }
    Ok(RootfsManifest { entries, root })
}

fn parse_entry(line: &str) -> Option<Entry> {
    let mut parts = line.splitn(4, ' ');
    let sha256 = merkle::parse_hash(parts.next()?)?;
    let kind = Kind::parse(parts.next()?)?;
    let size = parts.next()?.parse().ok()?;
    let path = unescape(parts.next()?)?;
    Some(Entry {
        path,
        kind,
        size,
        sha256,
    })
}

fn escape(path: &str) -> String {
    path.replace('\\', "\\\\").replace('\n', "\\n")
}

fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next()? {
            'n' => out.push('\n'),
            '\\' => out.push('\\'),
            _ => return None,
        }
    }
    Some(out)
}

/// Write `<cache_root>/rootfs.merkle` atomically (temp + rename).
pub fn write(cache_root: &Path, m: &RootfsManifest) -> io::Result<PathBuf> {
    let path = cache_root.join(MANIFEST_FILE);
    let tmp = cache_root.join(format!("{MANIFEST_FILE}.tmp"));
    std::fs::write(&tmp, render(m))?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

/// Load `<cache_root>/rootfs.merkle`; `Ok(None)` when absent.
pub fn read(cache_root: &Path) -> io::Result<Option<RootfsManifest>> {
    match std::fs::read_to_string(cache_root.join(MANIFEST_FILE)) {
        Ok(text) => parse(&text).map(Some),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Cheap: the `sha256:<hex>` root from the manifest header, without
/// re-hashing anything. `None` when the manifest is absent or malformed.
pub fn read_root(cache_root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(cache_root.join(MANIFEST_FILE)).ok()?;
    let mut lines = text.lines();
    if lines.next()? != HEADER {
        return None;
    }
    let root = lines.next()?.strip_prefix("root ")?;
    merkle::parse_hash(root).map(|h| merkle::display(&h))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Re-hash `rootfs` and compare with `manifest`.
pub fn verify(rootfs: &Path, manifest: &RootfsManifest, strict: bool) -> io::Result<Verdict> {
    let live = compute(rootfs)?;
    if live.root == manifest.root {
        return Ok(Verdict::Intact {
            tracked: manifest.entries.len(),
            untracked: 0,
        });
    }
    let live_map: BTreeMap<&str, &Entry> =
        live.entries.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut problems = Vec::new();
    for want in &manifest.entries {
        match live_map.get(want.path.as_str()) {
            None => problems.push(format!("deleted: {}", want.path)),
            Some(have) if *have != want => problems.push(format!("modified: {}", want.path)),
            Some(_) => {}
        }
    }
    let tracked: std::collections::BTreeSet<&str> =
        manifest.entries.iter().map(|e| e.path.as_str()).collect();
    let untracked: Vec<&str> = live_map
        .keys()
        .filter(|p| !tracked.contains(*p))
        .copied()
        .collect();
    if strict {
        problems.extend(untracked.iter().map(|p| format!("added: {p}")));
    }
    if problems.is_empty() {
        return Ok(Verdict::Intact {
            tracked: manifest.entries.len(),
            untracked: untracked.len(),
        });
    }
    Ok(Verdict::Modified(problems))
}

/// Strip write bits from every tracked file so in-place edits fail loudly.
/// Directories stay writable: the app may create files, and cache GC /
/// re-extraction must be able to remove the tree.
#[cfg(unix)]
pub fn make_files_read_only(rootfs: &Path, manifest: &RootfsManifest) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for e in &manifest.entries {
        if e.kind != Kind::File {
            continue;
        }
        let path = rootfs.join(&e.path);
        let meta = std::fs::symlink_metadata(&path)?;
        let mode = meta.permissions().mode() & !0o222;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn make_files_read_only(_rootfs: &Path, _manifest: &RootfsManifest) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_rootfs(dir: &Path) -> PathBuf {
        let rootfs = dir.join("rootfs");
        std::fs::create_dir_all(rootfs.join("app/sub dir")).unwrap();
        std::fs::create_dir_all(rootfs.join("empty")).unwrap();
        std::fs::write(rootfs.join("app/main.py"), b"print('hi')\n").unwrap();
        std::fs::write(rootfs.join("app/sub dir/data.bin"), vec![7u8; 100_000]).unwrap();
        std::fs::write(rootfs.join("model.gguf"), b"GGUF").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("main.py", rootfs.join("app/link.py")).unwrap();
        rootfs
    }

    #[test]
    fn compute_is_deterministic_and_roundtrips_through_text() {
        let dir = tempdir().unwrap();
        let rootfs = sample_rootfs(dir.path());
        let a = compute(&rootfs).unwrap();
        let b = compute(&rootfs).unwrap();
        assert_eq!(a, b);
        assert!(a.entries.windows(2).all(|w| w[0].path < w[1].path));
        assert!(a
            .entries
            .iter()
            .any(|e| e.path == "app/sub dir/data.bin" && e.size == 100_000));

        let path = write(dir.path(), &a).unwrap();
        assert_eq!(path.file_name().unwrap(), MANIFEST_FILE);
        let parsed = read(dir.path()).unwrap().unwrap();
        assert_eq!(parsed, a);
        assert_eq!(read_root(dir.path()), Some(a.root_display()));
        assert!(read(&dir.path().join("nowhere")).unwrap().is_none());
    }

    #[test]
    fn hand_edited_manifest_is_rejected() {
        let dir = tempdir().unwrap();
        let rootfs = sample_rootfs(dir.path());
        let m = compute(&rootfs).unwrap();
        let text = render(&m).replace("model.gguf", "model2.gguf");
        assert!(parse(&text).is_err());
        let text = render(&m).replacen("count ", "count 9", 1);
        assert!(parse(&text).is_err());
    }

    #[test]
    fn verify_flags_modified_and_deleted_but_tolerates_additions() {
        let dir = tempdir().unwrap();
        let rootfs = sample_rootfs(dir.path());
        let m = compute(&rootfs).unwrap();
        assert!(matches!(
            verify(&rootfs, &m, true).unwrap(),
            Verdict::Intact { untracked: 0, .. }
        ));

        // Runtime artefacts: tolerated unless strict.
        std::fs::create_dir_all(rootfs.join("app/__pycache__")).unwrap();
        std::fs::write(rootfs.join("app/__pycache__/main.pyc"), b"x").unwrap();
        assert_eq!(
            verify(&rootfs, &m, false).unwrap(),
            Verdict::Intact {
                tracked: m.entries.len(),
                untracked: 1
            }
        );
        assert_eq!(
            verify(&rootfs, &m, true).unwrap(),
            Verdict::Modified(vec!["added: app/__pycache__/main.pyc".to_string()])
        );

        // Same size, different bytes → caught.
        std::fs::write(rootfs.join("model.gguf"), b"EVIL").unwrap();
        std::fs::remove_file(rootfs.join("app/main.py")).unwrap();
        let Verdict::Modified(problems) = verify(&rootfs, &m, false).unwrap() else {
            panic!("expected Modified");
        };
        assert_eq!(
            problems,
            vec!["deleted: app/main.py", "modified: model.gguf"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_change_and_read_only_bits() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let rootfs = sample_rootfs(dir.path());
        let m = compute(&rootfs).unwrap();
        make_files_read_only(&rootfs, &m).unwrap();
        let mode = std::fs::metadata(rootfs.join("model.gguf"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o222, 0);
        assert!(std::fs::write(rootfs.join("model.gguf"), b"x").is_err());

        std::fs::remove_file(rootfs.join("app/link.py")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", rootfs.join("app/link.py")).unwrap();
        assert_eq!(
            verify(&rootfs, &m, false).unwrap(),
            Verdict::Modified(vec!["modified: app/link.py".to_string()])
        );
    }

    #[test]
    fn escape_roundtrip() {
        for p in ["plain", "with space", "back\\slash", "new\nline"] {
            assert_eq!(unescape(&escape(p)).unwrap(), p);
        }
    }
}
