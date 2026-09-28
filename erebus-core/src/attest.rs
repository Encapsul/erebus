//! Attestation generation and verification for `.erebus` files.
//!
//! Produces detached `.erebus.attest` documents — signed JSON proving
//! what executed, on what type of machine, and when. The hostname is
//! never included in plaintext; only a SHA-256 hash of
//! `hostname + os + arch` is recorded.

use crate::format::Footer;
use crate::intoto::{
    digest_value as intoto_digest, InTotoStatement, EREBUS_PREDICATE_TYPE, INTOTO_STATEMENT_TYPE,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use time::format_description::well_known::Iso8601;
use time::OffsetDateTime;

/// Current attestation spec version.
///
/// 1.2 adds `execution.prev_attestation_hash` (signed) so receipts form a
/// hash chain; all 1.x documents remain parseable and verifiable.
pub const ATTESTATION_SPEC_VERSION: &str = "1.2";

/// Marker string identifying this as an erebus execution attestation.
pub const ATTESTATION_TYPE: &str = "erebus-execution";

// ── Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub spec_version: String,
    pub attestation_type: String,
    pub artifact: ArtifactInfo,
    pub provenance: ProvenanceInfo,
    pub execution: ExecutionInfo,
    /// The in-toto statement this attestation is about; the Ed25519 signature
    /// in [`SignatureInfo::signature_hex`] covers these canonical bytes.
    pub statement: InTotoStatement,
    pub signature: SignatureInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactInfo {
    pub bundle_hash: String,
    pub payload_hash: String,
    pub metadata_hash: String,
    pub format_version: u8,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceInfo {
    pub builder: String,
    pub author: Option<String>,
    pub license: Option<String>,
    pub layers: Vec<LayerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub name: String,
    pub kind: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionInfo {
    pub attested_at: String,
    pub machine_id_hash: String,
    pub os: String,
    pub arch: String,
    /// SHA-256 over the canonical launch vector (entrypoint + runtime args,
    /// NUL-joined), captured by the stub before launching the payload. `None`
    /// when the launcher did not capture it (e.g. `erebus attest` run offline).
    #[serde(default)]
    pub input_hash: Option<String>,
    /// SHA-256 over `sha256_hex(stdout) + ":" + sha256_hex(stderr)`, captured
    /// by the launcher supervisor while the payload ran. `None` for runs that
    /// are still in flight or whose output could not be observed.
    #[serde(default)]
    pub output_hash: Option<String>,
    /// Exit code of the payload (128 + signal when signal-delivered). `None`
    /// when unknown.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// SHA-256 of the previous receipt file in the local trail (byte-exact),
    /// `None` for the first receipt or when no trail is kept. Being inside
    /// the signed statement, it makes deletion/reordering of receipts
    /// detectable (see `attest_log`).
    #[serde(default)]
    pub prev_attestation_hash: Option<String>,
    /// Present on receipts emitted by the attesting proxy (`erebus serve
    /// --attest-key`): one receipt per inference call. `input_hash` is then
    /// the request (`METHOD path\n` + body) and `output_hash` the decoded
    /// response body; `exit_code` is unused.
    #[serde(default)]
    pub request: Option<RequestInfo>,
    /// Merkle root of the extracted rootfs that was actually executed
    /// (`rootfs.merkle`, see `rootfs_merkle`). Written by the launcher; absent
    /// on offline receipts (`erebus attest`) and on caches predating it.
    #[serde(default)]
    pub rootfs_root: Option<String>,
}

/// One HTTP call through the attesting proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestInfo {
    pub method: String,
    pub path: String,
    /// Upstream HTTP status; `None` when the engine never answered.
    pub status: Option<u16>,
}

/// Behavior-hook fields a supervising launcher can attach to a receipt.
///
/// All fields are optional so offline receipts (`erebus attest`) stay
/// schema-identical; a config struct keeps the generation API stable as the
/// spec grows.
#[derive(Debug, Clone, Default)]
pub struct ExecutionCapture {
    pub input_hash: Option<String>,
    pub output_hash: Option<String>,
    pub exit_code: Option<i32>,
    pub prev_attestation_hash: Option<String>,
    pub request: Option<RequestInfo>,
    pub rootfs_root: Option<String>,
}

/// Bundle facts hashed once, reusable for many receipts.
///
/// `generate_attestation` re-reads and re-hashes the whole bundle; the
/// attesting proxy emits one receipt per inference call, so it builds the
/// template once and only signs a fresh `ExecutionInfo` per call.
#[derive(Debug, Clone)]
pub struct AttestationTemplate {
    pub artifact: ArtifactInfo,
    pub provenance: ProvenanceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    pub algorithm: String,
    pub key_fingerprint: String,
    pub signature_hex: String,
}

// ── Core functions ──────────────────────────────────────────────────────

/// Compute SHA-256 hex string of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("sha256:{}", hex::encode(hash))
}

/// Incremental SHA-256 hasher that streams into a prefixed hex digest.
///
/// Used by the launcher supervisor to hash payload output without buffering
/// the whole stream in memory.
#[derive(Default)]
pub struct StreamHasher {
    inner: Sha256,
}

impl StreamHasher {
    /// New hasher initialized to the empty SHA-256 state.
    pub fn new() -> Self {
        StreamHasher::default()
    }

    /// Fold `data` into the hash state.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return `sha256:<hex>`.
    pub fn finish_hex(self) -> String {
        format!("sha256:{}", hex::encode(self.inner.finalize()))
    }
}

/// Hash of the canonical launch vector: `entrypoint` ++ runtime args, parts
/// NUL-joined so a part boundary can never be confused with embedded spaces.
pub fn launch_vector_hash(vector: &[String]) -> String {
    let mut joined =
        Vec::with_capacity(vector.iter().map(|s| s.len()).sum::<usize>() + vector.len());
    for (i, part) in vector.iter().enumerate() {
        if i > 0 {
            joined.push(0);
        }
        joined.extend_from_slice(part.as_bytes());
    }
    sha256_hex(&joined)
}

/// Combine separate stdout/stderr digests into one deterministic hash so the
/// result does not depend on interleaving order between the two streams.
pub fn combined_output_hash(stdout_digest: &str, stderr_digest: &str) -> String {
    let mut combined = stdout_digest.as_bytes().to_vec();
    combined.push(b':');
    combined.extend_from_slice(stderr_digest.as_bytes());
    sha256_hex(&combined)
}

/// Compute the machine identity hash: SHA-256(hostname + os + arch).
/// The hostname is never stored in plaintext.
pub fn machine_id_hash() -> String {
    let hostname = get_hostname();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let mut hasher = Sha256::new();
    hasher.update(hostname.as_bytes());
    hasher.update(os.as_bytes());
    hasher.update(arch.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Extract flag names from a footer's flags byte.
pub fn flag_names(flags: u8) -> Vec<String> {
    let mut names = Vec::new();
    if flags & 0x01 != 0 {
        names.push("signed".to_string());
    }
    if flags & 0x02 != 0 {
        names.push("encrypted".to_string());
    }
    if flags & 0x04 != 0 {
        names.push("sisr".to_string());
    }
    names
}

/// Generate an attestation for a `.erebus` file.
///
/// Reads the binary, extracts footer + metadata hashes, computes machine
/// identity, and signs everything with the given Ed25519 key.
///
/// # Errors
///
/// Returns an error if the file cannot be read, the footer is invalid,
/// or the signing key is invalid.
pub fn generate_attestation(
    bundle_path: &Path,
    signing_key: &SigningKey,
) -> Result<Attestation, anyhow::Error> {
    generate_attestation_with_capture(bundle_path, signing_key, &ExecutionCapture::default())
}

/// Like [`generate_attestation`], but records behavior-hook fields captured by
/// a supervising launcher (see [`ExecutionCapture`]). `None` fields stay
/// absent so offline attestations remain schema-identical.
pub fn generate_attestation_with_capture(
    bundle_path: &Path,
    signing_key: &SigningKey,
    capture: &ExecutionCapture,
) -> Result<Attestation, anyhow::Error> {
    AttestationTemplate::from_bundle(bundle_path)?.attest(signing_key, capture)
}

impl AttestationTemplate {
    /// Read and hash `bundle_path` once.
    pub fn from_bundle(bundle_path: &Path) -> Result<Self, anyhow::Error> {
        let bundle_bytes = std::fs::read(bundle_path)
            .map_err(|e| anyhow::anyhow!("failed to read bundle: {e}"))?;
        let (artifact, metadata) = hash_bundle(&bundle_bytes)?;
        Ok(Self {
            artifact,
            provenance: provenance_from_metadata(&metadata),
        })
    }

    /// Sign a fresh receipt (timestamped now, on this machine) carrying
    /// `capture`.
    pub fn attest(
        &self,
        signing_key: &SigningKey,
        capture: &ExecutionCapture,
    ) -> Result<Attestation, anyhow::Error> {
        let execution = ExecutionInfo {
            attested_at: utc_now_iso8601(),
            machine_id_hash: machine_id_hash(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            input_hash: capture.input_hash.clone(),
            output_hash: capture.output_hash.clone(),
            exit_code: capture.exit_code,
            prev_attestation_hash: capture.prev_attestation_hash.clone(),
            request: capture.request.clone(),
            rootfs_root: capture.rootfs_root.clone(),
        };

        // The statement is the signed payload; the top-level fields are display
        // copies that verifiers re-derive and compare (see `check_consistency`).
        let statement = build_statement(&self.artifact, &self.provenance, &execution);
        let mut attestation = Attestation {
            spec_version: ATTESTATION_SPEC_VERSION.to_string(),
            attestation_type: ATTESTATION_TYPE.to_string(),
            artifact: self.artifact.clone(),
            provenance: self.provenance.clone(),
            execution,
            statement,
            signature: SignatureInfo {
                algorithm: "ed25519".to_string(),
                key_fingerprint: key_fingerprint(&signing_key.verifying_key()),
                signature_hex: String::new(), // filled after signing
            },
        };

        let doc_bytes = statement_bytes(&attestation.statement)?;
        attestation.signature.signature_hex = hex::encode(signing_key.sign(&doc_bytes).to_bytes());
        Ok(attestation)
    }
}

/// `sha256:<hex>` fingerprint of an Ed25519 verifying key.
pub fn key_fingerprint(vk: &VerifyingKey) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(vk.as_bytes())))
}

/// Canonical bytes the Ed25519 signature covers (spec 1.x: pretty JSON of the
/// statement; `serde_json` emits object keys in sorted order, so re-serializing
/// a parsed statement reproduces them byte-for-byte).
fn statement_bytes(statement: &InTotoStatement) -> Result<Vec<u8>, anyhow::Error> {
    serde_json::to_vec_pretty(statement)
        .map_err(|e| anyhow::anyhow!("failed to serialize statement: {e}"))
}

/// Parse the footer and hash bundle / payload / metadata. Returns the artifact
/// facts plus the parsed metadata JSON for provenance extraction.
fn hash_bundle(bundle_bytes: &[u8]) -> Result<(ArtifactInfo, serde_json::Value), anyhow::Error> {
    let mut cursor = std::io::Cursor::new(bundle_bytes);
    let footer = Footer::read_from(&mut cursor)
        .map_err(|e| anyhow::anyhow!("failed to read footer: {e}"))?;

    let payload = slice_checked(
        bundle_bytes,
        footer.payload_offset,
        footer.payload_csize,
        "payload",
    )?;
    let meta = slice_checked(
        bundle_bytes,
        footer.meta_offset,
        footer.meta_size,
        "metadata",
    )?;
    let metadata: serde_json::Value = serde_json::from_slice(meta)
        .map_err(|e| anyhow::anyhow!("failed to parse metadata JSON: {e}"))?;

    let artifact = ArtifactInfo {
        bundle_hash: sha256_hex(bundle_bytes),
        payload_hash: sha256_hex(payload),
        metadata_hash: sha256_hex(meta),
        format_version: footer.format_version,
        flags: flag_names(footer.flags),
    };
    Ok((artifact, metadata))
}

/// Bounds-checked sub-slice; offsets come from an untrusted footer.
fn slice_checked<'a>(
    bytes: &'a [u8],
    off: u64,
    len: u64,
    what: &str,
) -> Result<&'a [u8], anyhow::Error> {
    let end = off
        .checked_add(len)
        .filter(|end| *end <= bytes.len() as u64)
        .ok_or_else(|| anyhow::anyhow!("{what} extends beyond file boundary"))?;
    Ok(&bytes[off as usize..end as usize])
}

/// Builder / author / license / layers, read from the bundle metadata.
fn provenance_from_metadata(metadata: &serde_json::Value) -> ProvenanceInfo {
    let str_field = |k: &str| {
        metadata
            .get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    ProvenanceInfo {
        builder: format!("erebus-cli v{}", env!("CARGO_PKG_VERSION")),
        author: str_field("author"),
        license: str_field("license"),
        layers: layers_from_metadata(metadata),
    }
}

/// Layer list with a best-effort SHA-256 per layer: model layers carry it in
/// `metadata.sha256` (embedded at build time); the runtime layer falls back to
/// the metadata-level `rt_deps_hash`.
fn layers_from_metadata(metadata: &serde_json::Value) -> Vec<LayerInfo> {
    let rt_deps_hash = metadata.get("rt_deps_hash").and_then(|v| v.as_str());
    let runtime_name = metadata.get("runtime").and_then(|v| v.as_str());
    fn non_empty(v: &serde_json::Value) -> Option<&str> {
        v.as_str().filter(|s| !s.is_empty())
    }
    metadata
        .get("layers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|layer| {
                    let name = layer.get("name")?.as_str()?.to_string();
                    let kind = layer.get("kind")?.as_str()?.to_string();
                    let sha256 = layer
                        .get("sha256")
                        .and_then(non_empty)
                        .or_else(|| layer.get("metadata")?.get("sha256").and_then(non_empty))
                        .or_else(|| {
                            (kind == "runtime" && runtime_name == Some(name.as_str()))
                                .then_some(rt_deps_hash)
                                .flatten()
                        })
                        .map(|s| format!("sha256:{s}"))
                        .unwrap_or_default();
                    Some(LayerInfo { name, kind, sha256 })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Derive the in-toto statement from the structured fields. This is the single
/// source of truth for what gets signed; `check_consistency` re-runs it on a
/// parsed document and compares, so any edit to the unsigned display copies is
/// caught.
pub fn build_statement(
    artifact: &ArtifactInfo,
    provenance: &ProvenanceInfo,
    execution: &ExecutionInfo,
) -> InTotoStatement {
    let subject = |name: &str, prefixed: &str| crate::intoto::Subject {
        name: name.to_string(),
        digest: std::collections::HashMap::from([("sha256".to_string(), intoto_digest(prefixed))]),
    };
    InTotoStatement {
        statement_type: INTOTO_STATEMENT_TYPE.to_string(),
        subject: vec![
            subject("bundle", &artifact.bundle_hash),
            subject("payload", &artifact.payload_hash),
        ],
        predicate_type: EREBUS_PREDICATE_TYPE.to_string(),
        predicate: serde_json::json!({
            "builder": provenance.builder,
            "author": provenance.author,
            "license": provenance.license,
            "layers": provenance.layers.iter().map(|l| serde_json::json!({
                "name": l.name,
                "kind": l.kind,
                "sha256": l.sha256,
            })).collect::<Vec<_>>(),
            "execution": {
                "attested_at": execution.attested_at,
                "machine_id_hash": execution.machine_id_hash,
                "os": execution.os,
                "arch": execution.arch,
                "input_hash": execution.input_hash,
                "output_hash": execution.output_hash,
                "exit_code": execution.exit_code,
                "prev_attestation_hash": execution.prev_attestation_hash,
                "request": execution.request,
                "rootfs_root": execution.rootfs_root,
            },
            "artifact": {
                "metadata_hash": artifact.metadata_hash,
                "format_version": artifact.format_version,
                "flags": artifact.flags,
            },
        }),
    }
}

/// Write a signed execution attestation for `bundle_path` to `out_path`.
///
/// Loads the Ed25519 signing key from `key_path` (a raw 32-byte seed, the
/// same format `erebus keygen` writes), attests `bundle_path` and persists the
/// pretty-printed JSON. This is the "every execution leaves a proof" hook: the
/// launcher stub calls it right before spawning the payload, so each run
/// produces a fresh detached `.erebus.attest` an auditor can verify against
/// the trusted public key.
pub fn write_execution_attestation(
    bundle_path: &Path,
    key_path: &Path,
    out_path: &Path,
) -> Result<Attestation, anyhow::Error> {
    write_captured_execution_attestation(
        bundle_path,
        key_path,
        out_path,
        &ExecutionCapture::default(),
    )
}

/// Write a signed execution attestation including behavior-hook captures.
///
/// Each write is a self-contained, self-signed document; `out_path` always
/// holds the latest receipt. Use [`write_receipt`] to also append it to a
/// hash-chained trail.
pub fn write_captured_execution_attestation(
    bundle_path: &Path,
    key_path: &Path,
    out_path: &Path,
    capture: &ExecutionCapture,
) -> Result<Attestation, anyhow::Error> {
    let key = load_signing_key(key_path)?;
    let attestation = generate_attestation_with_capture(bundle_path, &key, capture)?;
    persist_attestation(&attestation, out_path)?;
    Ok(attestation)
}

/// Write a receipt to `out_path` (latest) **and** append it to `log`.
///
/// The receipt's `prev_attestation_hash` is set from the log head before
/// signing, so the chain link is covered by the signature. Returns the
/// attestation and the path of the appended log entry.
pub fn write_receipt(
    bundle_path: &Path,
    key_path: &Path,
    out_path: &Path,
    log: &crate::attest_log::AttestationLog,
    capture: &ExecutionCapture,
) -> Result<(Attestation, std::path::PathBuf), anyhow::Error> {
    let key = load_signing_key(key_path)?;
    let template = AttestationTemplate::from_bundle(bundle_path)?;
    let (attestation, entry) = append_receipt(&template, &key, log, capture)?;
    persist_attestation(&attestation, out_path)?;
    Ok((attestation, entry))
}

/// Sign a receipt linked to the trail head and append it. The caller must
/// serialize concurrent appenders (the head is read, then advanced).
pub fn append_receipt(
    template: &AttestationTemplate,
    signing_key: &SigningKey,
    log: &crate::attest_log::AttestationLog,
    capture: &ExecutionCapture,
) -> Result<(Attestation, std::path::PathBuf), anyhow::Error> {
    let chained = ExecutionCapture {
        prev_attestation_hash: log.head()?,
        ..capture.clone()
    };
    let attestation = template.attest(signing_key, &chained)?;
    let entry = log.append(&attestation)?;
    Ok((attestation, entry))
}

/// Load a raw 32-byte Ed25519 seed (the `erebus keygen` format).
pub fn load_signing_key(key_path: &Path) -> Result<SigningKey, anyhow::Error> {
    let key_bytes = zeroize::Zeroizing::new(
        std::fs::read(key_path)
            .map_err(|e| anyhow::anyhow!("failed to read attestation key: {e}"))?,
    );
    let seed: &[u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!("attestation key must be 32 bytes, got {}", key_bytes.len())
    })?;
    Ok(SigningKey::from_bytes(seed))
}

/// Pretty JSON bytes of a whole receipt — the exact bytes stored on disk and
/// hashed by the trail.
pub fn receipt_bytes(attestation: &Attestation) -> Result<Vec<u8>, anyhow::Error> {
    serde_json::to_vec_pretty(attestation)
        .map_err(|e| anyhow::anyhow!("failed to serialize attestation: {e}"))
}

/// Serialize an attestation as pretty JSON and write it to `out_path`.
fn persist_attestation(attestation: &Attestation, out_path: &Path) -> Result<(), anyhow::Error> {
    std::fs::write(out_path, receipt_bytes(attestation)?)
        .map_err(|e| anyhow::anyhow!("failed to write attestation: {e}"))
}

/// ISO 8601 UTC timestamp.
fn utc_now_iso8601() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let datetime = OffsetDateTime::from_unix_timestamp(secs as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .to_offset(time::UtcOffset::UTC);
    datetime.format(&Iso8601::DEFAULT).unwrap_or_default()
}

/// Get the system hostname, or "unknown" if unavailable.
fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Verify an attestation against a set of trusted public keys.
///
/// Three checks, all required:
/// 1. the Ed25519 signature over the statement's canonical bytes verifies
///    under one of `trusted_keys`;
/// 2. `signature.key_fingerprint` names that key;
/// 3. the unsigned display fields (`artifact`, `provenance`, `execution`)
///    re-derive to exactly the signed statement (`check_consistency`).
///
/// Returns the verifying key that matched. Error messages for tampering start
/// with `TAMPERED:` so callers can surface them verbatim.
pub fn verify_attestation(
    attestation: &Attestation,
    trusted_keys: &[VerifyingKey],
) -> Result<VerifyingKey, anyhow::Error> {
    let doc_bytes = statement_bytes(&attestation.statement)?;
    let sig_bytes = hex::decode(&attestation.signature.signature_hex)
        .map_err(|e| anyhow::anyhow!("invalid signature hex: {e}"))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))?;

    let vk = trusted_keys
        .iter()
        .find(|vk| vk.verify(&doc_bytes, &sig).is_ok())
        .ok_or_else(|| anyhow::anyhow!("TAMPERED: signature does not match any trusted key"))?;

    let expected_fp = key_fingerprint(vk);
    if attestation.signature.key_fingerprint != expected_fp {
        anyhow::bail!(
            "TAMPERED: key_fingerprint mismatch (document says {}, signing key is {})",
            attestation.signature.key_fingerprint,
            expected_fp
        );
    }

    check_consistency(attestation)?;
    Ok(*vk)
}

/// Re-derive the statement from the unsigned display fields and compare it to
/// the signed one. Any drift means the human-readable copy was edited after
/// signing.
///
/// `null` predicate entries are dropped on both sides before comparing: a
/// null carries no signed information, and spec 1.0/1.1 documents predate
/// some optional keys.
pub fn check_consistency(attestation: &Attestation) -> Result<(), anyhow::Error> {
    let expected = build_statement(
        &attestation.artifact,
        &attestation.provenance,
        &attestation.execution,
    );
    let actual = &attestation.statement;

    if actual.statement_type != expected.statement_type
        || actual.predicate_type != expected.predicate_type
    {
        anyhow::bail!("TAMPERED: statement type mismatch with signed statement");
    }
    if actual.subject != expected.subject {
        anyhow::bail!(
            "TAMPERED: artifact hashes mismatch between unsigned fields and signed statement"
        );
    }

    let expected_pred = strip_nulls(expected.predicate);
    let actual_pred = strip_nulls(actual.predicate.clone());
    if let Some(section) = first_differing_key(&expected_pred, &actual_pred) {
        anyhow::bail!("TAMPERED: {section} mismatch between unsigned fields and signed statement");
    }
    Ok(())
}

/// Compare a receipt's signed bundle digest with the SHA-256 of `bundle_bytes`.
pub fn check_bundle_matches(
    attestation: &Attestation,
    bundle_bytes: &[u8],
) -> Result<(), anyhow::Error> {
    let signed = attestation
        .statement
        .subject
        .iter()
        .find(|s| s.name == "bundle")
        .and_then(|s| s.digest.get("sha256"))
        .ok_or_else(|| anyhow::anyhow!("attestation has no signed bundle digest"))?;
    let actual = hex::encode(Sha256::digest(bundle_bytes));
    if signed != &actual {
        anyhow::bail!(
            "TAMPERED: bundle mismatch (attestation covers sha256:{signed}, file is sha256:{actual})"
        );
    }
    Ok(())
}

/// Remove null-valued object members, recursively.
fn strip_nulls(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (k, strip_nulls(v)))
                .collect(),
        ),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(strip_nulls).collect())
        }
        other => other,
    }
}

/// Name of the first top-level predicate key whose value differs, or `None`
/// when both predicates are identical.
fn first_differing_key(expected: &serde_json::Value, actual: &serde_json::Value) -> Option<String> {
    if expected == actual {
        return None;
    }
    let (Some(e), Some(a)) = (expected.as_object(), actual.as_object()) else {
        return Some("predicate".to_string());
    };
    e.iter()
        .chain(a.iter())
        .find(|(k, _)| e.get(*k) != a.get(*k))
        .map(|(k, _)| k.clone())
        .or_else(|| Some("predicate".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use proptest::prelude::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[1u8; 32])
    }

    fn sample_fields() -> (ArtifactInfo, ProvenanceInfo, ExecutionInfo) {
        (
            ArtifactInfo {
                bundle_hash: "sha256:abc".to_string(),
                payload_hash: "sha256:def".to_string(),
                metadata_hash: "sha256:ghi".to_string(),
                format_version: 3,
                flags: vec!["signed".to_string()],
            },
            ProvenanceInfo {
                builder: "erebus-cli v0.5.0".to_string(),
                author: Some("test".to_string()),
                license: Some("MIT".to_string()),
                layers: vec![LayerInfo {
                    name: "runtime/python3".to_string(),
                    kind: "runtime".to_string(),
                    sha256: "sha256:ddd".to_string(),
                }],
            },
            ExecutionInfo {
                attested_at: "2026-09-15T14:32:00Z".to_string(),
                machine_id_hash: "sha256:abc123".to_string(),
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                input_hash: None,
                output_hash: Some("sha256:out".to_string()),
                exit_code: Some(0),
                prev_attestation_hash: None,
                request: None,
                rootfs_root: None,
            },
        )
    }

    /// Consistent, signed attestation built from `sample_fields`.
    fn signed_sample(key: &SigningKey) -> Attestation {
        let (artifact, provenance, execution) = sample_fields();
        let statement = build_statement(&artifact, &provenance, &execution);
        let mut att = Attestation {
            spec_version: ATTESTATION_SPEC_VERSION.to_string(),
            attestation_type: ATTESTATION_TYPE.to_string(),
            artifact,
            provenance,
            execution,
            statement,
            signature: SignatureInfo {
                algorithm: "ed25519".to_string(),
                key_fingerprint: key_fingerprint(&key.verifying_key()),
                signature_hex: String::new(),
            },
        };
        let sig = key.sign(&statement_bytes(&att.statement).unwrap());
        att.signature.signature_hex = hex::encode(sig.to_bytes());
        att
    }

    /// Minimal valid v3 bundle on disk: stub + payload + metadata + footer.
    fn write_bundle(dir: &Path) -> (std::path::PathBuf, Vec<u8>, &'static [u8]) {
        let bundle_path = dir.join("bundle.erebus");
        let payload: &[u8] = b"hello payload";
        let meta = br#"{"name":"test","runtime":"binary"}"#;
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
        (bundle_path, bytes, payload)
    }

    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

        #[test]
        fn attestation_proptest_roundtrip(
            bundle_hash in "sha256:[0-9a-f]{64}",
            payload_hash in "sha256:[0-9a-f]{64}",
            builder in ".*",
            os in "(linux|macos|windows)",
        ) {
            let (mut artifact, mut provenance, mut execution) = sample_fields();
            artifact.bundle_hash = bundle_hash;
            artifact.payload_hash = payload_hash;
            provenance.builder = builder;
            execution.os = os;
            let statement = build_statement(&artifact, &provenance, &execution);
            let att = Attestation {
                spec_version: "1.2".to_string(),
                attestation_type: ATTESTATION_TYPE.to_string(),
                artifact, provenance, execution, statement,
                signature: SignatureInfo {
                    algorithm: "ed25519".to_string(),
                    key_fingerprint: "sha256:dead".to_string(),
                    signature_hex: "deadbeef".to_string(),
                },
            };
            let json = serde_json::to_string(&att).unwrap();
            let parsed: Attestation = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(&att.artifact.bundle_hash, &parsed.artifact.bundle_hash);
            prop_assert_eq!(&att.execution.os, &parsed.execution.os);
            // Whatever the field values, a document built from its own fields is consistent.
            prop_assert!(check_consistency(&parsed).is_ok());
        }
    }

    #[test]
    fn sha256_hex_deterministic() {
        assert_eq!(sha256_hex(b"hello"), sha256_hex(b"hello"));
        assert!(sha256_hex(b"hello").starts_with("sha256:"));
    }

    #[test]
    fn flag_names_all_and_empty() {
        assert!(flag_names(0x00).is_empty());
        let flags = flag_names(0x07);
        assert!(flags.contains(&"signed".to_string()));
        assert!(flags.contains(&"encrypted".to_string()));
        assert!(flags.contains(&"sisr".to_string()));
    }

    #[test]
    fn machine_id_hash_deterministic() {
        assert_eq!(machine_id_hash(), machine_id_hash());
    }

    #[test]
    fn roundtrip_verify() {
        let key = test_key();
        let att = signed_sample(&key);
        let vk = verify_attestation(&att, &[key.verifying_key()]).unwrap();
        assert_eq!(vk, key.verifying_key());
    }

    #[test]
    fn verify_wrong_key_fails() {
        let att = signed_sample(&test_key());
        let wrong = SigningKey::from_bytes(&[2u8; 32]);
        let err = verify_attestation(&att, &[wrong.verifying_key()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("TAMPERED"), "{err}");
    }

    #[test]
    fn verify_survives_json_roundtrip() {
        // The verifier re-serializes a parsed statement; this must reproduce
        // the signed bytes exactly.
        let key = test_key();
        let att = signed_sample(&key);
        let parsed: Attestation =
            serde_json::from_slice(&serde_json::to_vec_pretty(&att).unwrap()).unwrap();
        verify_attestation(&parsed, &[key.verifying_key()]).unwrap();
    }

    #[test]
    fn tampering_unsigned_execution_field_is_detected() {
        let key = test_key();
        let mut att = signed_sample(&key);
        att.execution.exit_code = Some(1);
        let err = verify_attestation(&att, &[key.verifying_key()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("TAMPERED: execution mismatch"), "{err}");
    }

    #[test]
    fn tampering_unsigned_artifact_hash_is_detected() {
        let key = test_key();
        let mut att = signed_sample(&key);
        att.artifact.bundle_hash = "sha256:evil".to_string();
        let err = verify_attestation(&att, &[key.verifying_key()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("TAMPERED: artifact hashes mismatch"), "{err}");
    }

    #[test]
    fn tampering_unsigned_provenance_is_detected() {
        let key = test_key();
        let mut att = signed_sample(&key);
        att.provenance.layers[0].sha256 = "sha256:swapped".to_string();
        let err = verify_attestation(&att, &[key.verifying_key()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("TAMPERED: layers mismatch"), "{err}");
    }

    #[test]
    fn tampering_key_fingerprint_is_detected() {
        let key = test_key();
        let mut att = signed_sample(&key);
        att.signature.key_fingerprint = "sha256:someone-else".to_string();
        let err = verify_attestation(&att, &[key.verifying_key()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("TAMPERED: key_fingerprint"), "{err}");
    }

    #[test]
    fn legacy_1_1_document_without_prev_hash_is_consistent() {
        // A 1.1 predicate has no prev_attestation_hash key at all; nulls on
        // our side must not be counted as a difference.
        let key = test_key();
        let mut att = signed_sample(&key);
        att.spec_version = "1.1".to_string();
        if let Some(exec) = att
            .statement
            .predicate
            .get_mut("execution")
            .and_then(|e| e.as_object_mut())
        {
            exec.remove("prev_attestation_hash");
            exec.remove("input_hash");
        }
        let sig = key.sign(&statement_bytes(&att.statement).unwrap());
        att.signature.signature_hex = hex::encode(sig.to_bytes());
        verify_attestation(&att, &[key.verifying_key()]).unwrap();
    }

    #[test]
    fn legacy_1_0_document_parses_with_defaults() {
        let legacy = r#"{
            "spec_version": "1.0",
            "attestation_type": "erebus-execution",
            "artifact": {"bundle_hash": "sha256:aa", "payload_hash": "sha256:bb",
                         "metadata_hash": "sha256:cc", "format_version": 3, "flags": []},
            "provenance": {"builder": "b", "author": null, "license": null, "layers": []},
            "execution": {"attested_at": "2026-01-01T00:00:00Z",
                          "machine_id_hash": "sha256:mm", "os": "linux", "arch": "x86_64"},
            "statement": {"_type": "https://in-toto.io/Statement/v1",
                          "subject": [], "predicate_type": "https://slsa.dev/provenance/v1",
                          "predicate": {}},
            "signature": {"algorithm": "ed25519", "key_fingerprint": "sha256:fp",
                          "signature_hex": "00"}
        }"#;
        let parsed: Attestation = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.execution.input_hash, None);
        assert_eq!(parsed.execution.prev_attestation_hash, None);
        assert_eq!(parsed.spec_version, "1.0");
    }

    #[test]
    fn check_bundle_matches_accepts_and_rejects() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, bytes, _) = write_bundle(dir.path());
        let att = generate_attestation(&bundle_path, &test_key()).unwrap();
        check_bundle_matches(&att, &bytes).unwrap();
        let err = check_bundle_matches(&att, b"other")
            .unwrap_err()
            .to_string();
        assert!(err.contains("TAMPERED: bundle mismatch"), "{err}");
    }

    #[test]
    fn write_execution_attestation_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key");
        std::fs::write(&key_path, [7u8; 32]).unwrap();
        let (bundle_path, bytes, payload) = write_bundle(dir.path());
        let out_path = dir.path().join("bundle.erebus.attest");

        let att = write_execution_attestation(&bundle_path, &key_path, &out_path).unwrap();
        assert_eq!(att.artifact.bundle_hash, sha256_hex(&bytes));
        assert_eq!(att.artifact.payload_hash, sha256_hex(payload));
        assert_eq!(att.artifact.format_version, 3);
        assert_eq!(att.spec_version, "1.2");

        let parsed: Attestation =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        verify_attestation(&parsed, &[key.verifying_key()]).unwrap();
        check_bundle_matches(&parsed, &bytes).unwrap();
    }

    #[test]
    fn write_execution_attestation_rejects_bad_key_len() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("badkey");
        std::fs::write(&key_path, [1u8; 16]).unwrap();
        let err = write_execution_attestation(
            &dir.path().join("nope.erebus"),
            &key_path,
            &dir.path().join("out.attest"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"));
    }

    #[test]
    fn generate_rejects_footer_pointing_past_eof() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, mut bytes, _) = write_bundle(dir.path());
        // Corrupt payload_csize (footer core starts 84 bytes before EOF; csize at +16).
        let csize_at = bytes.len() - 84 + 16;
        bytes[csize_at..csize_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        std::fs::write(&bundle_path, &bytes).unwrap();
        let err = generate_attestation(&bundle_path, &test_key())
            .unwrap_err()
            .to_string();
        assert!(err.contains("beyond file boundary"), "{err}");
    }

    #[test]
    fn launch_vector_hash_distinguishes_inputs() {
        let a = launch_vector_hash(&["python3".to_string(), "/app/app.py".to_string()]);
        let b = launch_vector_hash(&[
            "python3".to_string(),
            "/app/app.py".to_string(),
            "x".to_string(),
        ]);
        let c = launch_vector_hash(&[
            "python3/".to_string(),
            "/app/app.py".to_string(),
            "x".to_string(),
        ]);
        assert_eq!(
            a,
            launch_vector_hash(&["python3".to_string(), "/app/app.py".to_string()])
        );
        assert_ne!(a, b, "extra runtime arg must change the hash");
        assert_ne!(a, c, "NUL-joining must keep element boundaries distinct");
    }

    #[test]
    fn combined_output_hash_is_deterministic_and_distinct() {
        let out = sha256_hex(b"stdout bytes");
        let err = sha256_hex(b"stderr bytes");
        assert_eq!(
            combined_output_hash(&out, &err),
            combined_output_hash(&out, &err)
        );
        assert_ne!(
            combined_output_hash(&out, &err),
            combined_output_hash(&err, &out),
            "stream order must matter (which stream produced what)"
        );
    }

    #[test]
    fn stream_hasher_matches_sha256_hex() {
        let mut h = StreamHasher::new();
        h.update(b"hello ");
        h.update(b"world");
        assert_eq!(h.finish_hex(), sha256_hex(b"hello world"));
    }

    #[test]
    fn captured_attestation_signature_covers_capture_fields() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key");
        std::fs::write(&key_path, [9u8; 32]).unwrap();
        let (bundle_path, _, _) = write_bundle(dir.path());
        let out_path = dir.path().join("bundle.erebus.attest");

        let capture = ExecutionCapture {
            input_hash: Some("sha256:in".to_string()),
            output_hash: Some("sha256:out".to_string()),
            exit_code: Some(42),
            prev_attestation_hash: Some("sha256:prev".to_string()),
            request: None,
            rootfs_root: None,
        };
        let att =
            write_captured_execution_attestation(&bundle_path, &key_path, &out_path, &capture)
                .unwrap();
        assert_eq!(att.execution.exit_code, Some(42));
        assert_eq!(
            att.execution.prev_attestation_hash.as_deref(),
            Some("sha256:prev")
        );

        let mut parsed: Attestation =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        verify_attestation(&parsed, &[key.verifying_key()]).unwrap();

        let exec = parsed.statement.predicate.get("execution").unwrap();
        assert_eq!(exec["input_hash"], "sha256:in");
        assert_eq!(exec["output_hash"], "sha256:out");
        assert_eq!(exec["exit_code"], 42);
        assert_eq!(exec["prev_attestation_hash"], "sha256:prev");

        // Flipping the unsigned copy of a captured field is caught.
        parsed.execution.output_hash = Some("sha256:forged".to_string());
        assert!(verify_attestation(&parsed, &[key.verifying_key()]).is_err());
    }

    #[test]
    fn template_signs_many_receipts_and_request_info_is_signed() {
        let dir = tempfile::tempdir().unwrap();
        let (bundle_path, bytes, _) = write_bundle(dir.path());
        let key = test_key();
        let template = AttestationTemplate::from_bundle(&bundle_path).unwrap();
        assert_eq!(template.artifact.bundle_hash, sha256_hex(&bytes));

        let capture = ExecutionCapture {
            input_hash: Some("sha256:req".to_string()),
            output_hash: Some("sha256:resp".to_string()),
            request: Some(RequestInfo {
                method: "POST".to_string(),
                path: "/v1/chat/completions".to_string(),
                status: Some(200),
            }),
            ..ExecutionCapture::default()
        };
        let mut att = template.attest(&key, &capture).unwrap();
        verify_attestation(&att, &[key.verifying_key()]).unwrap();
        check_bundle_matches(&att, &bytes).unwrap();
        let req = &att.statement.predicate["execution"]["request"];
        assert_eq!(req["method"], "POST");
        assert_eq!(req["status"], 200);

        // The template matches what generate_attestation produces.
        let direct = generate_attestation(&bundle_path, &key).unwrap();
        assert_eq!(direct.artifact.bundle_hash, att.artifact.bundle_hash);
        assert_eq!(direct.provenance.builder, att.provenance.builder);

        // Editing the unsigned request status is caught.
        att.execution.request.as_mut().unwrap().status = Some(500);
        let err = verify_attestation(&att, &[key.verifying_key()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("TAMPERED: execution mismatch"), "{err}");
    }
}
