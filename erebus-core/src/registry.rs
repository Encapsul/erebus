//! Local layer registry — a content-addressed store for shareable layers.
//!
//! AI agents packaged with erebus typically embed the same heavyweight
//! pieces: a Python runtime pack, llama.cpp, base model weights. The registry
//! lets tooling publish those blobs once under their SHA-256 hash and pull
//! them into later builds without re-downloading or re-embedding.
//!
//! Layout under the registry root:
//! - `objects/<hex>` — content-addressed blobs (see [`crate::cas`])
//! - `index.json` — name → [`LayerEntry`] map, written atomically

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cas::{DiskObjectStore, ObjectStore};
use crate::layer::LayerKind;

/// One registered layer, keyed by its human name.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LayerEntry {
    pub name: String,
    pub kind: LayerKind,
    /// Hex-encoded SHA-256 of the layer bytes.
    pub sha256: String,
    pub size: u64,
    /// ISO-8601 UTC timestamp of registration.
    pub created: String,
}

/// Filesystem-backed layer registry.
pub struct LayerRegistry {
    root: PathBuf,
    objects: DiskObjectStore,
}

impl LayerRegistry {
    /// Opens (creating if needed) a registry rooted at `root`.
    pub fn open(root: &Path) -> io::Result<Self> {
        let objects = DiskObjectStore::new(&root.join("objects"))?;
        Ok(Self {
            root: root.to_path_buf(),
            objects,
        })
    }

    /// Default location: `<cache_dir>/layers`, overridable via `ERE_LAYERS_DIR`.
    ///
    /// Returns `None` when no cache/home directory can be determined.
    pub fn default_dir() -> Option<PathBuf> {
        if let Ok(dir) = std::env::var("ERE_LAYERS_DIR") {
            return Some(PathBuf::from(dir));
        }
        Some(crate::paths::cache_dir().join("layers"))
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    /// Loads the index; a missing file is an empty registry, not an error
    /// (first use must not require setup).
    fn load_index(&self) -> io::Result<BTreeMap<String, LayerEntry>> {
        let data = match fs::read(self.index_path()) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(e),
        };
        serde_json::from_slice(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("index.json: {e}")))
    }

    /// Atomically persists the index (tmp + rename), keeping concurrent
    /// readers from ever observing a half-written file.
    fn save_index(&self, index: &BTreeMap<String, LayerEntry>) -> io::Result<()> {
        let data = serde_json::to_vec_pretty(index)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("serde: {e}")))?;
        let tmp = self.index_path().with_extension("json.tmp");
        fs::write(&tmp, data)?;
        fs::rename(&tmp, self.index_path())
    }

    /// Stores `data` under `name`, content-addressed by its SHA-256.
    ///
    /// Re-pushing identical bytes is idempotent; pushing different bytes
    /// under an existing name replaces the entry (the old blob becomes
    /// garbage-collectable via the object store's own lifecycle).
    pub fn push(&mut self, name: &str, kind: LayerKind, data: &[u8]) -> io::Result<LayerEntry> {
        if name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "layer name must not be empty",
            ));
        }
        let hash: [u8; 32] = Sha256::digest(data).into();
        self.objects.put(&hash, data)?;
        let entry = LayerEntry {
            name: name.to_string(),
            kind,
            sha256: hex::encode(hash),
            size: data.len() as u64,
            created: iso_now(),
        };
        let mut index = self.load_index()?;
        index.insert(name.to_string(), entry.clone());
        self.save_index(&index)?;
        Ok(entry)
    }

    /// All entries, sorted by name.
    pub fn list(&self) -> io::Result<Vec<LayerEntry>> {
        Ok(self.load_index()?.into_values().collect())
    }

    /// The entry registered under `name`, if any.
    pub fn resolve(&self, name: &str) -> io::Result<Option<LayerEntry>> {
        Ok(self.load_index()?.get(name).cloned())
    }

    /// Reads back the bytes of `entry`, re-verifying the content hash on
    /// every read (bit rot / tampering surfaces as an error).
    pub fn read(&self, entry: &LayerEntry) -> io::Result<Vec<u8>> {
        let hash = decode_hash(&entry.sha256)?;
        self.objects.get(&hash)?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("object {} missing from store", entry.sha256),
            )
        })
    }

    /// Writes the layer `name` to `dest`, returning the byte count written.
    pub fn materialize(&self, name: &str, dest: &Path) -> io::Result<Option<u64>> {
        let Some(entry) = self.resolve(name)? else {
            return Ok(None);
        };
        let data = self.read(&entry)?;
        fs::write(dest, &data)?;
        Ok(Some(data.len() as u64))
    }

    /// Removes the index entry for `name`. The blob itself stays in the
    /// store (it may be referenced by other names or in-flight builds).
    /// Returns whether an entry was removed.
    pub fn remove(&mut self, name: &str) -> io::Result<bool> {
        let mut index = self.load_index()?;
        let removed = index.remove(name).is_some();
        if removed {
            self.save_index(&index)?;
        }
        Ok(removed)
    }
}

fn decode_hash(hex_hash: &str) -> io::Result<[u8; 32]> {
    let bytes = hex::decode(hex_hash)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad hash: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "hash must be 32 bytes"))
}

/// ISO-8601 UTC timestamp, mirroring `assembly::chrono_now`.
fn iso_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .to_offset(time::UtcOffset::UTC)
        .format(&time::format_description::well_known::Iso8601::DEFAULT)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_tmp() -> (tempfile::TempDir, LayerRegistry) {
        let dir = tempfile::tempdir().unwrap();
        let reg = LayerRegistry::open(dir.path()).unwrap();
        (dir, reg)
    }

    #[test]
    fn push_list_roundtrip() {
        let (_dir, mut reg) = open_tmp();
        let e = reg
            .push("llama.cpp", LayerKind::Tool, b"tool-bytes")
            .unwrap();
        assert_eq!(e.size, 10);
        assert_eq!(reg.list().unwrap().len(), 1);
        assert_eq!(reg.resolve("llama.cpp").unwrap().unwrap(), e);
        assert!(reg.resolve("absent").unwrap().is_none());
    }

    #[test]
    fn read_verifies_content_and_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let mut reg = LayerRegistry::open(dir.path()).unwrap();
        let e = reg
            .push("model", LayerKind::Model, b"gguf-weights")
            .unwrap();
        assert_eq!(reg.read(&e).unwrap(), b"gguf-weights");

        // Corrupt the stored object behind the registry's back.
        let obj_path = dir.path().join("objects").join(&e.sha256);
        fs::write(obj_path, b"tampered").unwrap();
        assert!(reg.read(&e).is_err());
    }

    #[test]
    fn push_is_idempotent_for_identical_bytes() {
        let (_dir, mut reg) = open_tmp();
        let a = reg.push("x", LayerKind::Config, b"same").unwrap();
        let b = reg.push("x", LayerKind::Config, b"same").unwrap();
        assert_eq!(a.sha256, b.sha256);
        assert_eq!(reg.list().unwrap().len(), 1);
    }

    #[test]
    fn materialize_writes_verified_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let (_reg_dir, mut reg) = open_tmp();
        reg.push("runtime-pack", LayerKind::Runtime, b"python3-payload")
            .unwrap();

        let dest = dir.path().join("out.bin");
        assert_eq!(reg.materialize("runtime-pack", &dest).unwrap(), Some(15));
        assert_eq!(fs::read(&dest).unwrap(), b"python3-payload");
        assert_eq!(
            reg.materialize("missing", &dest).unwrap(),
            None,
            "unknown layer must not create a file"
        );
        let untouched = dir.path().join("untouched.bin");
        assert_eq!(reg.materialize("missing", &untouched).unwrap(), None);
        assert!(!untouched.exists(), "failed materialize must not write");
    }

    #[test]
    fn remove_drops_entry_but_keeps_store_intact() {
        let (_dir, mut reg) = open_tmp();
        let e = reg.push("gone", LayerKind::Model, b"data").unwrap();
        assert!(reg.remove("gone").unwrap());
        assert!(!reg.remove("gone").unwrap());
        assert!(reg.resolve("gone").unwrap().is_none());
        // Blob remains readable by hash for any other referencing entry.
        let hash: [u8; 32] = Sha256::digest(b"data").into();
        assert_eq!(hex::encode(hash), e.sha256);
    }

    #[test]
    fn empty_name_rejected() {
        let (_dir, mut reg) = open_tmp();
        assert!(reg.push("", LayerKind::Model, b"x").is_err());
    }

    #[test]
    fn missing_index_file_is_empty_registry() {
        let dir = tempfile::tempdir().unwrap();
        let reg = LayerRegistry::open(&dir.path().join("fresh")).unwrap();
        assert!(reg.list().unwrap().is_empty());
    }
}
