//! Local trail witness checkpoints (ROADMAP R1 — disconnected anchoring).
//!
//! While offline, a second Ed25519 key (the **witness**) co-signs the local
//! trail head. Design (deliberately simple; not a full Merkle tree offline):
//!
//! - `size` = number of receipt files in the trail
//! - `root` = SHA-256 of the **head receipt file bytes** (same digest as `HEAD`)
//!
//! Canonical signed bytes:
//! `erebus-witness-checkpoint/v1\n{origin}\n{size}\n{root_hex}\n{witnessed_at}\n{witness_id}\n`
//!
//! The checkpoint is stored beside the trail as `HEAD.witness.json`.

use std::io;
use std::path::{Path, PathBuf};

use crate::attest::{key_fingerprint, sha256_hex, utc_now_iso8601};
use crate::attest_log::{file_hash, AttestationLog};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Canonical message prefix (pinned across CLI / tests).
pub const WITNESS_PREFIX: &str = "erebus-witness-checkpoint/v1";
/// Sidecar next to `HEAD` in a trail directory.
pub const WITNESS_FILE: &str = "HEAD.witness.json";
/// High-water mark root, outside the trail so a trail owner cannot roll it back.
pub const STATE_DIR_ENV: &str = "ERE_WITNESS_STATE_DIR";
/// Private key file name under the witness dir.
pub const KEY_FILE: &str = "witness.key";

/// Signed snapshot of a local trail head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessCheckpoint {
    /// Trail identity string (absolute path of the trail dir).
    pub origin: String,
    /// Number of receipt files covered.
    pub size: u64,
    /// `sha256:<hex>` of the head receipt file bytes.
    pub root: String,
    /// When the witness signed (ISO 8601 UTC).
    pub witnessed_at: String,
    /// Fingerprint of the witness verifying key.
    pub witness_id: String,
    /// Ed25519 signature hex over [`WitnessCheckpoint::signed_bytes`].
    pub signature_hex: String,
}

impl WitnessCheckpoint {
    /// Canonical bytes the witness signs / verifies.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        let root_hex = self
            .root
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow::anyhow!("witness root is not a sha256 digest"))?;
        Ok(format!(
            "{WITNESS_PREFIX}\n{}\n{}\n{root_hex}\n{}\n{}\n",
            self.origin, self.size, self.witnessed_at, self.witness_id
        )
        .into_bytes())
    }

    /// Verify the witness signature; `key` must match `witness_id`.
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), anyhow::Error> {
        let expected = key_fingerprint(key);
        if self.witness_id != expected {
            anyhow::bail!(
                "TAMPERED: witness_id mismatch (document says {}, key is {expected})",
                self.witness_id
            );
        }
        let sig: [u8; 64] = hex::decode(&self.signature_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| anyhow::anyhow!("witness signature is not 64 bytes of hex"))?;
        key.verify(&self.signed_bytes()?, &Signature::from_bytes(&sig))
            .map_err(|_| anyhow::anyhow!("TAMPERED: witness signature does not verify"))?;
        Ok(())
    }
}

/// Default witness key directory: `$ERE_WITNESS_DIR`, else XDG / `~/.local/share/erebus/witness`.
pub fn default_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("ERE_WITNESS_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("erebus").join("witness");
    }
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("erebus")
            .join("witness"),
        None => PathBuf::from(".erebus").join("witness"),
    }
}

/// Last sealed head for one origin, kept outside the trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessState {
    pub origin: String,
    pub size: u64,
    pub root: String,
    pub witnessed_at: String,
}

/// State root: `$ERE_WITNESS_STATE_DIR`, else XDG / `~/.local/share/erebus`.
pub fn default_state_dir() -> PathBuf {
    if let Some(d) = std::env::var_os(STATE_DIR_ENV) {
        return PathBuf::from(d);
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("erebus").join("witness-state");
    }
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("erebus")
            .join("witness-state"),
        None => PathBuf::from(".erebus").join("witness-state"),
    }
}

fn state_path(state_dir: &Path, origin: &str) -> Result<PathBuf, anyhow::Error> {
    let digest = sha256_hex(origin.as_bytes());
    let key = digest.strip_prefix("sha256:").unwrap_or(&digest);
    Ok(state_dir.join(format!("{key}.json")))
}

fn read_state(state_dir: &Path, origin: &str) -> Result<Option<WitnessState>, anyhow::Error> {
    let path = state_path(state_dir, origin)?;
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!("failed to read {}: {e}", path.display())),
    }
}

/// Refuse to replace newer last-seen state with an older (or forked) seal.
fn record_seen(state_dir: &Path, cp: &WitnessCheckpoint) -> Result<(), anyhow::Error> {
    if let Some(prev) = read_state(state_dir, &cp.origin)? {
        if prev.size > cp.size || (prev.size == cp.size && prev.root != cp.root) {
            anyhow::bail!(
                "TAMPERED: witness state already records a newer head (size {})",
                prev.size
            );
        }
    }
    let state = WitnessState {
        origin: cp.origin.clone(),
        size: cp.size,
        root: cp.root.clone(),
        witnessed_at: cp.witnessed_at.clone(),
    };
    let path = state_path(state_dir, &cp.origin)?;
    std::fs::create_dir_all(state_dir)?;
    let json = serde_json::to_vec_pretty(&state)?;
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    write_private(&tmp, &json)
        .map_err(|e| anyhow::anyhow!("failed to write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path)
        .map_err(|e| anyhow::anyhow!("failed to install {}: {e}", path.display()))
}

/// Reject a saved seal that is older than the last one this verifier saw.
pub fn check_not_rolled_back(
    state_dir: &Path,
    cp: &WitnessCheckpoint,
) -> Result<(), anyhow::Error> {
    let Some(prev) = read_state(state_dir, &cp.origin)? else {
        return Ok(());
    };
    if prev.size > cp.size || (prev.size == cp.size && prev.root != cp.root) {
        anyhow::bail!(
            "TAMPERED: witness checkpoint (size {}) is older than last-seen state (size {})",
            cp.size,
            prev.size
        );
    }
    Ok(())
}

/// Load a witness signing key from `ERE_WITNESS_KEY` or `dir/witness.key`.
pub fn load_signing_key(dir: Option<&Path>) -> Result<SigningKey, anyhow::Error> {
    let path = match std::env::var_os("ERE_WITNESS_KEY") {
        Some(p) => PathBuf::from(p),
        None => dir.unwrap_or(&default_dir()).join(KEY_FILE),
    };
    let bytes = std::fs::read(&path)
        .map_err(|e| anyhow::anyhow!("failed to read witness key {}: {e}", path.display()))?;
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("witness key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Generate a new witness key and write it (0600, never overwritten).
pub fn keygen(dir: &Path) -> Result<(SigningKey, PathBuf), anyhow::Error> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(KEY_FILE);
    if path.exists() {
        anyhow::bail!("witness key already exists at {}", path.display());
    }
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, seed.as_mut());
    let key = SigningKey::from_bytes(&seed);
    write_private(&path, key.as_bytes())?;
    let pub_hex = hex::encode(key.verifying_key().as_bytes());
    let pub_path = dir.join(format!("{pub_hex}.pub"));
    std::fs::write(&pub_path, key.verifying_key().as_bytes())?;
    Ok((key, path))
}

/// Canonical trail origin signed into the checkpoint.
fn trail_origin(log: &AttestationLog) -> String {
    log.dir()
        .canonicalize()
        .unwrap_or_else(|_| log.dir().to_path_buf())
        .display()
        .to_string()
}

/// Sign the current trail head into a [`WitnessCheckpoint`].
///
/// Empty trails are refused: there is nothing meaningful to seal.
pub fn witness_trail_head(
    log: &AttestationLog,
    key: &SigningKey,
) -> Result<WitnessCheckpoint, anyhow::Error> {
    let entries = log.entries()?;
    let size = entries.len() as u64;
    if size == 0 {
        anyhow::bail!("cannot seal an empty trail");
    }
    let head_path = entries
        .last()
        .ok_or_else(|| anyhow::anyhow!("trail head missing"))?;
    let head_bytes = std::fs::read(head_path)
        .map_err(|e| anyhow::anyhow!("failed to read head {}: {e}", head_path.display()))?;
    let root = file_hash(&head_bytes);
    let head_ptr = log.head()?;
    if head_ptr.as_deref() != Some(root.as_str()) {
        anyhow::bail!("TAMPERED: trail HEAD does not match the last receipt file");
    }
    let witnessed_at = utc_now_iso8601();
    let witness_id = key_fingerprint(&key.verifying_key());
    let mut cp = WitnessCheckpoint {
        origin: trail_origin(log),
        size,
        root,
        witnessed_at,
        witness_id,
        signature_hex: String::new(),
    };
    let sig = key.sign(&cp.signed_bytes()?);
    cp.signature_hex = hex::encode(sig.to_bytes());
    Ok(cp)
}

/// Write `HEAD.witness.json` beside the trail (atomic replace) and remember
/// the sealed head outside the trail.
pub fn write_witness(
    log: &AttestationLog,
    cp: &WitnessCheckpoint,
) -> Result<PathBuf, anyhow::Error> {
    write_witness_with_state(log, cp, &default_state_dir())
}

/// Same as [`write_witness`] with an explicit state root (used by tests).
pub fn write_witness_with_state(
    log: &AttestationLog,
    cp: &WitnessCheckpoint,
    state_dir: &Path,
) -> Result<PathBuf, anyhow::Error> {
    let path = log.dir().join(WITNESS_FILE);
    let json = serde_json::to_vec_pretty(cp)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, &path)?;
    record_seen(state_dir, cp)?;
    Ok(path)
}

/// Load `HEAD.witness.json` if present.
pub fn load_witness(log: &AttestationLog) -> Result<Option<WitnessCheckpoint>, anyhow::Error> {
    let path = log.dir().join(WITNESS_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!("failed to read {}: {e}", path.display())),
    }
}

/// Seal the trail head with the configured witness key and persist it.
pub fn seal_trail(
    log: &AttestationLog,
    key_dir: Option<&Path>,
) -> Result<WitnessCheckpoint, anyhow::Error> {
    let key = load_signing_key(key_dir)?;
    let cp = witness_trail_head(log, &key)?;
    write_witness(log, &cp)?;
    Ok(cp)
}

/// Best-effort seal used when a registry publish fails (store-and-forward).
pub fn seal_trail_best_effort(log: &AttestationLog) {
    match seal_trail(log, None) {
        Ok(cp) => eprintln!(
            "[erebus] witness sealed trail head (size {}, root {}) at {}",
            cp.size, cp.root, cp.witnessed_at
        ),
        Err(e) => eprintln!("[erebus] warning: could not seal witness checkpoint: {e:#}"),
    }
}

/// Verify a witness seal. The signed `origin` must always match the trail;
/// with `require`, the size/head must match the seal and the seal must not be
/// older than the last one seen by this verifier.
pub fn check_trail_witness(
    log: &AttestationLog,
    key: &VerifyingKey,
    require: bool,
) -> Result<Option<WitnessCheckpoint>, anyhow::Error> {
    check_trail_witness_with_state(log, key, require, &default_state_dir())
}

/// Same as [`check_trail_witness`] with an explicit state root (used by tests).
pub fn check_trail_witness_with_state(
    log: &AttestationLog,
    key: &VerifyingKey,
    require: bool,
    state_dir: &Path,
) -> Result<Option<WitnessCheckpoint>, anyhow::Error> {
    let Some(cp) = load_witness(log)? else {
        if require {
            anyhow::bail!(
                "TAMPERED: --require-witness but {} is missing",
                WITNESS_FILE
            );
        }
        return Ok(None);
    };
    cp.verify(key)?;
    let origin = trail_origin(log);
    if cp.origin != origin {
        anyhow::bail!(
            "TAMPERED: witness origin {:?} does not match trail {:?}",
            cp.origin,
            origin
        );
    }
    if require {
        let entries = log.entries()?;
        let size = entries.len() as u64;
        if size != cp.size {
            anyhow::bail!(
                "TAMPERED: trail has {size} receipt(s) but witness sealed {}",
                cp.size
            );
        }
        let head = log.head()?.ok_or_else(|| {
            anyhow::anyhow!("TAMPERED: trail HEAD missing under a sealed witness")
        })?;
        if head != cp.root {
            anyhow::bail!("TAMPERED: trail HEAD does not match witness root");
        }
        check_not_rolled_back(state_dir, &cp)?;
    }
    Ok(Some(cp))
}

/// Parse a witness verifying key from 64 hex chars or a 32-byte `.pub` file.
pub fn load_verifying_key(spec: &str) -> Result<VerifyingKey, anyhow::Error> {
    let path = Path::new(spec);
    if path.is_file() {
        let bytes = std::fs::read(path)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("witness .pub must be 32 raw bytes"))?;
        return VerifyingKey::from_bytes(&arr)
            .map_err(|e| anyhow::anyhow!("witness key invalid: {e}"));
    }
    let bytes: [u8; 32] = hex::decode(spec.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("--witness-key must be 64 hex chars or a .pub file"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("--witness-key invalid: {e}"))
}

/// `YYYY-MM-DDTHH:MM:SS` so `…38.000000000Z` and `…38+00:00` are the same second.
fn iso8601_second(ts: &str) -> &str {
    let b = ts.as_bytes();
    if b.len() >= 19 && b[4] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':' {
        &ts[..19]
    } else {
        ts
    }
}

/// Second-resolution compare: `witnessed_at` must not be after the log checkpoint.
///
/// Receipts use `time`'s ISO-8601 (`…38.000000000Z`); the registry checkpoint
/// uses `isoformat(timespec="seconds")` (`…38+00:00`). A raw string compare
/// treats `.` as after `+` and rejects a witness sealed in the same second.
pub fn check_witness_before_anchor(
    witnessed_at: &str,
    checkpoint_time: &str,
) -> Result<(), anyhow::Error> {
    if iso8601_second(witnessed_at) > iso8601_second(checkpoint_time) {
        anyhow::bail!(
            "TAMPERED: witnessed_at ({witnessed_at}) is after log checkpoint ({checkpoint_time})"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::{generate_attestation_with_capture, ExecutionCapture};
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    fn tiny_bundle(dir: &Path) -> PathBuf {
        use crate::assembly::{assemble_erebus, AssemblyInput};
        let rootfs = dir.join("rootfs");
        std::fs::create_dir_all(rootfs.join("app")).unwrap();
        std::fs::write(rootfs.join("app/main.py"), "print(1)").unwrap();
        let payload = crate::tar::create_tar_zstd_with_level(&rootfs, 3).unwrap();
        let meta = serde_json::json!({
            "name": "w", "author": "t", "license": "MIT",
            "layers": [{"kind": "runtime", "name": "runtime/python3", "size": 1}],
        });
        let bin = dir.join("w.erebus");
        assemble_erebus(
            &bin,
            &AssemblyInput {
                stub_bytes: b"STUB",
                payload: &payload,
                meta_bytes: serde_json::to_vec(&meta).unwrap().as_slice(),
                encrypt: false,
                squashfs: false,
                target_arch: None,
                sisr: None,
            },
        )
        .unwrap();
        bin
    }

    fn append_one(log: &AttestationLog, bundle: &Path, key: &SigningKey) {
        let capture = ExecutionCapture {
            prev_attestation_hash: log.head().unwrap(),
            ..Default::default()
        };
        let att = generate_attestation_with_capture(bundle, key, &capture).unwrap();
        log.append(&att).unwrap();
    }

    #[test]
    fn witness_roundtrip_and_detects_inserted_receipt() {
        let dir = tempdir().unwrap();
        let bundle = tiny_bundle(dir.path());
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let trail = AttestationLog::open(&dir.path().join("trail")).unwrap();
        append_one(&trail, &bundle, &op);
        append_one(&trail, &bundle, &op);

        let wdir = dir.path().join("witness");
        let state = dir.path().join("state");
        let (wkey, _) = keygen(&wdir).unwrap();
        let cp = witness_trail_head(&trail, &wkey).unwrap();
        write_witness_with_state(&trail, &cp, &state).unwrap();
        assert_eq!(cp.size, 2);
        check_trail_witness_with_state(&trail, &wkey.verifying_key(), true, &state).unwrap();

        // Forge an extra receipt file that is not covered by the seal.
        std::fs::write(
            trail.dir().join("000003-forged.json"),
            b"{\"forged\":true}\n",
        )
        .unwrap();
        let err = check_trail_witness_with_state(&trail, &wkey.verifying_key(), true, &state)
            .unwrap_err();
        assert!(err.to_string().contains("TAMPERED"), "{err}");
        assert!(err.to_string().contains("3"), "{err}");
        // Without require, the historical seal still verifies.
        check_trail_witness_with_state(&trail, &wkey.verifying_key(), false, &state).unwrap();
    }

    #[test]
    fn witness_seal_is_bound_to_trail_origin() {
        let dir = tempdir().unwrap();
        let bundle = tiny_bundle(dir.path());
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let (wkey, _) = keygen(&dir.path().join("w")).unwrap();
        let state = dir.path().join("state");

        let sealed = AttestationLog::open(&dir.path().join("sealed")).unwrap();
        append_one(&sealed, &bundle, &op);
        let cp = witness_trail_head(&sealed, &wkey).unwrap();
        write_witness_with_state(&sealed, &cp, &state).unwrap();

        // Copy the whole trail and its sidecar to another path: the seal
        // stays internally consistent but names the old origin.
        let copy = AttestationLog::open(&dir.path().join("copy")).unwrap();
        append_one(&copy, &bundle, &op);
        std::fs::write(
            copy.dir().join(WITNESS_FILE),
            serde_json::to_vec(&cp).unwrap(),
        )
        .unwrap();
        for require in [false, true] {
            let err = check_trail_witness_with_state(&copy, &wkey.verifying_key(), require, &state)
                .unwrap_err()
                .to_string();
            assert!(err.contains("origin"), "{err}");
        }
    }

    #[test]
    fn witness_rollback_is_detected_by_state() {
        let dir = tempdir().unwrap();
        let bundle = tiny_bundle(dir.path());
        let op = SigningKey::from_bytes(&[7u8; 32]);
        let (wkey, _) = keygen(&dir.path().join("w")).unwrap();
        let state = dir.path().join("state");
        let trail = AttestationLog::open(&dir.path().join("trail")).unwrap();
        append_one(&trail, &bundle, &op);

        let old_cp = witness_trail_head(&trail, &wkey).unwrap();
        write_witness_with_state(&trail, &old_cp, &state).unwrap();
        let old_sidecar = std::fs::read(trail.dir().join(WITNESS_FILE)).unwrap();
        let old_head = std::fs::read(trail.dir().join("HEAD")).unwrap();

        append_one(&trail, &bundle, &op);
        let new_cp = witness_trail_head(&trail, &wkey).unwrap();
        write_witness_with_state(&trail, &new_cp, &state).unwrap();
        assert!(new_cp.size > old_cp.size);

        // Truncate back to the first seal and restore its sidecar + HEAD.
        let entries = trail.entries().unwrap();
        std::fs::remove_file(entries.last().unwrap()).unwrap();
        std::fs::write(trail.dir().join(WITNESS_FILE), &old_sidecar).unwrap();
        std::fs::write(trail.dir().join("HEAD"), &old_head).unwrap();

        let err = check_trail_witness_with_state(&trail, &wkey.verifying_key(), true, &state)
            .unwrap_err()
            .to_string();
        assert!(err.contains("older than last-seen state"), "{err}");
    }

    #[test]
    fn witness_rejects_bad_signature() {
        let dir = tempdir().unwrap();
        let bundle = tiny_bundle(dir.path());
        let op = SigningKey::from_bytes(&[3u8; 32]);
        let trail = AttestationLog::open(&dir.path().join("trail")).unwrap();
        append_one(&trail, &bundle, &op);
        let (wkey, _) = keygen(&dir.path().join("w")).unwrap();
        let mut cp = witness_trail_head(&trail, &wkey).unwrap();
        cp.signature_hex = "00".repeat(64);
        let err = cp.verify(&wkey.verifying_key()).unwrap_err();
        assert!(err.to_string().contains("TAMPERED"));
    }

    #[test]
    fn witnessed_at_must_precede_anchor() {
        check_witness_before_anchor("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z").unwrap();
        let err = check_witness_before_anchor("2026-01-03T00:00:00Z", "2026-01-02T00:00:00Z")
            .unwrap_err();
        assert!(err.to_string().contains("TAMPERED"));
        // Same second, the two formats the witness and the registry actually emit.
        check_witness_before_anchor(
            "2026-10-02T13:05:38.000000000Z",
            "2026-10-02T13:05:38+00:00",
        )
        .unwrap();
        let err = check_witness_before_anchor(
            "2026-10-02T13:05:39.000000000Z",
            "2026-10-02T13:05:38+00:00",
        )
        .unwrap_err();
        assert!(err.to_string().contains("TAMPERED"));
    }
}
