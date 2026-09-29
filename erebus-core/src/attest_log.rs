//! Append-only, hash-chained trail of execution receipts.
//!
//! Layout of a trail directory (`<bundle>.attest.d/` by default):
//!
//! ```text
//! 000001-20260917T153000Z-3f9a1c2b.json   # receipt #1 (pretty JSON, byte-exact)
//! 000002-20260917T153412Z-77e0d9aa.json   # receipt #2, prev_attestation_hash = sha256(file #1)
//! HEAD                                    # "sha256:<hex>" of the last receipt file
//! ```
//!
//! Each receipt's `execution.prev_attestation_hash` is inside the **signed**
//! statement and equals the SHA-256 of the previous file's bytes, so deleting,
//! reordering or editing any receipt breaks the chain at verification time.
//! Writes are atomic (temp file + rename) so a crash never leaves a torn entry
//! that the next append would silently chain onto.

use std::io;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

use crate::attest::{check_bundle_matches, receipt_bytes, verify_attestation, Attestation};

/// Name of the head pointer file inside a trail directory.
pub const HEAD_FILE: &str = "HEAD";

/// A trail directory handle.
#[derive(Debug, Clone)]
pub struct AttestationLog {
    dir: PathBuf,
}

/// Outcome of a successful chain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReport {
    /// Number of receipts verified.
    pub count: usize,
    /// Hash of the last receipt (`sha256:<hex>`), `None` for an empty trail.
    pub head: Option<String>,
}

/// Default trail location next to a receipt: `<receipt>.d`.
pub fn default_log_dir(receipt_path: &Path) -> PathBuf {
    let mut name = receipt_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    name.push_str(".d");
    receipt_path.with_file_name(name)
}

/// `sha256:<hex>` over raw bytes.
pub fn file_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

impl AttestationLog {
    /// Open (creating if needed) the trail directory at `dir`.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Hash recorded in `HEAD`, `None` when the trail is empty.
    pub fn head(&self) -> Result<Option<String>, anyhow::Error> {
        match std::fs::read_to_string(self.dir.join(HEAD_FILE)) {
            Ok(s) => Ok(Some(s.trim().to_string()).filter(|s| !s.is_empty())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!("failed to read trail HEAD: {e}")),
        }
    }

    /// Receipt files in chain order (lexicographic on the zero-padded seq).
    pub fn entries(&self) -> io::Result<Vec<PathBuf>> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|ext| ext == "json")
                    && !p.to_string_lossy().ends_with(".proof.json")
            })
            .collect();
        entries.sort();
        Ok(entries)
    }

    /// Append a signed receipt. Refuses when its `prev_attestation_hash` does
    /// not equal the current head — the caller must set the link from
    /// [`AttestationLog::head`] *before* signing (see `attest::write_receipt`).
    pub fn append(&self, attestation: &Attestation) -> Result<PathBuf, anyhow::Error> {
        let head = self.head()?;
        if attestation.execution.prev_attestation_hash != head {
            anyhow::bail!(
                "receipt prev_attestation_hash {:?} does not match trail head {:?}",
                attestation.execution.prev_attestation_hash,
                head
            );
        }
        let bytes = receipt_bytes(attestation)?;
        let hash = file_hash(&bytes);
        let seq = self.entries()?.len().saturating_add(1);
        let name = format!(
            "{seq:06}-{}-{}.json",
            compact_timestamp(&attestation.execution.attested_at),
            hash["sha256:".len()..].get(..8).unwrap_or("00000000")
        );
        let path = self.dir.join(name);
        write_atomic(&path, &bytes)?;
        write_atomic(&self.dir.join(HEAD_FILE), format!("{hash}\n").as_bytes())?;
        Ok(path)
    }

    /// Verify every receipt (signature, fingerprint, consistency) and the
    /// chain links between consecutive files; `bundle_bytes`, when given, must
    /// match every receipt's signed bundle digest.
    pub fn verify_chain(
        &self,
        trusted_keys: &[VerifyingKey],
        bundle_bytes: Option<&[u8]>,
    ) -> Result<ChainReport, anyhow::Error> {
        let mut prev: Option<String> = None;
        let mut count = 0usize;
        for path in self.entries()? {
            let bytes = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
            let att: Attestation = serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", path.display()))?;
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            verify_attestation(&att, trusted_keys).map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
            if let Some(b) = bundle_bytes {
                check_bundle_matches(&att, b).map_err(|e| anyhow::anyhow!("{name}: {e}"))?;
            }
            if att.execution.prev_attestation_hash != prev {
                anyhow::bail!(
                    "TAMPERED: chain broken at {name} (expected prev {prev:?}, receipt says {:?})",
                    att.execution.prev_attestation_hash
                );
            }
            prev = Some(file_hash(&bytes));
            count += 1;
        }
        let head = self.head()?;
        if head != prev {
            anyhow::bail!("TAMPERED: trail HEAD {head:?} does not match last receipt {prev:?}");
        }
        Ok(ChainReport { count, head })
    }
}

/// `2026-09-17T15:30:00Z`-style ISO string → `20260917T153000Z`; anything
/// unparseable degrades to `unknown` (the seq prefix keeps ordering intact).
fn compact_timestamp(iso: &str) -> String {
    let compact: String = iso
        .chars()
        .take_while(|c| *c != '.' && *c != '+')
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    if compact.is_empty() {
        "unknown".to_string()
    } else {
        compact
    }
}

/// Write `bytes` to `path` via a sibling temp file + rename.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), anyhow::Error> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)
        .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| anyhow::anyhow!("failed to commit {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{write_receipt, ExecutionCapture};
    use crate::format::Footer;
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    fn fixture(dir: &Path, seed: u8) -> (PathBuf, PathBuf, SigningKey) {
        let key_path = dir.join("key");
        std::fs::write(&key_path, [seed; 32]).unwrap();
        let bundle_path = dir.join("bundle.erebus");
        let payload = b"payload";
        let meta = br#"{"name":"t","runtime":"binary"}"#;
        let mut bytes = vec![0u8; 8];
        let payload_offset = bytes.len() as u64;
        bytes.extend_from_slice(payload);
        let meta_offset = bytes.len() as u64;
        bytes.extend_from_slice(meta);
        let footer = Footer {
            format_version: 3,
            arch: 0,
            flags: 0,
            payload_offset,
            payload_csize: payload.len() as u64,
            payload_usize: payload.len() as u64,
            payload_sha256: [0u8; 32],
            meta_offset,
            meta_size: meta.len() as u64,
            sig_offset: 0,
        };
        bytes.extend_from_slice(&footer.pack_full());
        std::fs::write(&bundle_path, &bytes).unwrap();
        (bundle_path, key_path, SigningKey::from_bytes(&[seed; 32]))
    }

    fn two_receipts(dir: &Path) -> (AttestationLog, PathBuf, VerifyingKey) {
        let (bundle, key_path, key) = fixture(dir, 5);
        let latest = dir.join("bundle.erebus.attest");
        let log = AttestationLog::open(&default_log_dir(&latest)).unwrap();
        for code in [0, 3] {
            let capture = ExecutionCapture {
                exit_code: Some(code),
                ..Default::default()
            };
            write_receipt(&bundle, &key_path, &latest, &log, &capture).unwrap();
        }
        (log, bundle, key.verifying_key())
    }

    #[test]
    fn default_dir_is_receipt_plus_d() {
        assert_eq!(
            default_log_dir(Path::new("/x/agent.erebus.attest")),
            PathBuf::from("/x/agent.erebus.attest.d")
        );
    }

    #[test]
    fn entries_ignore_transparency_proof_sidecars() {
        let dir = tempdir().unwrap();
        let log = AttestationLog::open(dir.path()).unwrap();
        std::fs::write(dir.path().join("000001-x.json"), b"{}").unwrap();
        std::fs::write(dir.path().join("000001-x.json.proof.json"), b"{}").unwrap();
        assert_eq!(log.entries().unwrap().len(), 1);
    }

    #[test]
    fn chain_links_and_verifies() {
        let dir = tempdir().unwrap();
        let (log, bundle, vk) = two_receipts(dir.path());
        let entries = log.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("000001-"));
        assert!(entries[1]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("000002-"));

        let first_bytes = std::fs::read(&entries[0]).unwrap();
        let second: Attestation =
            serde_json::from_slice(&std::fs::read(&entries[1]).unwrap()).unwrap();
        assert_eq!(
            second.execution.prev_attestation_hash.as_deref(),
            Some(file_hash(&first_bytes).as_str())
        );

        let bundle_bytes = std::fs::read(&bundle).unwrap();
        let report = log.verify_chain(&[vk], Some(&bundle_bytes)).unwrap();
        assert_eq!(report.count, 2);
        assert_eq!(report.head, log.head().unwrap());
        // The latest pointer is the same document as the last entry.
        assert_eq!(
            std::fs::read(dir.path().join("bundle.erebus.attest")).unwrap(),
            std::fs::read(&entries[1]).unwrap()
        );
    }

    #[test]
    fn editing_a_middle_receipt_breaks_the_chain() {
        let dir = tempdir().unwrap();
        let (log, _, vk) = two_receipts(dir.path());
        let first = &log.entries().unwrap()[0];
        // Flip an unsigned display field: signature still valid, consistency fails.
        let text = std::fs::read_to_string(first).unwrap();
        assert!(text.contains("\"exit_code\": 0"));
        std::fs::write(
            first,
            text.replacen("\"exit_code\": 0", "\"exit_code\": 7", 1),
        )
        .unwrap();
        let err = log.verify_chain(&[vk], None).unwrap_err().to_string();
        assert!(err.contains("TAMPERED"), "{err}");
    }

    #[test]
    fn deleting_the_last_receipt_is_detected_via_head() {
        let dir = tempdir().unwrap();
        let (log, _, vk) = two_receipts(dir.path());
        std::fs::remove_file(&log.entries().unwrap()[1]).unwrap();
        let err = log.verify_chain(&[vk], None).unwrap_err().to_string();
        assert!(err.contains("HEAD"), "{err}");
    }

    #[test]
    fn deleting_the_first_receipt_is_detected_via_link() {
        let dir = tempdir().unwrap();
        let (log, _, vk) = two_receipts(dir.path());
        std::fs::remove_file(&log.entries().unwrap()[0]).unwrap();
        let err = log.verify_chain(&[vk], None).unwrap_err().to_string();
        assert!(err.contains("chain broken"), "{err}");
    }

    #[test]
    fn wrong_bundle_is_rejected() {
        let dir = tempdir().unwrap();
        let (log, _, vk) = two_receipts(dir.path());
        let err = log
            .verify_chain(&[vk], Some(b"not the bundle"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("bundle mismatch"), "{err}");
    }

    #[test]
    fn append_refuses_unlinked_receipt() {
        let dir = tempdir().unwrap();
        let (log, bundle, _) = two_receipts(dir.path());
        let key = SigningKey::from_bytes(&[5u8; 32]);
        // A receipt generated without the head link cannot be appended.
        let unlinked = crate::attest::generate_attestation(&bundle, &key).unwrap();
        assert!(log.append(&unlinked).is_err());
    }

    #[test]
    fn empty_trail_verifies_to_zero() {
        let dir = tempdir().unwrap();
        let log = AttestationLog::open(&dir.path().join("t.d")).unwrap();
        let report = log.verify_chain(&[], None).unwrap();
        assert_eq!(
            report,
            ChainReport {
                count: 0,
                head: None
            }
        );
    }

    #[test]
    fn compact_timestamp_shapes() {
        assert_eq!(
            compact_timestamp("2026-09-17T15:30:00Z"),
            "20260917T153000Z"
        );
        assert_eq!(
            compact_timestamp("2026-09-17T15:30:00.000000000Z"),
            "20260917T153000"
        );
        assert_eq!(compact_timestamp(""), "unknown");
    }
}
