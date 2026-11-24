//! `erebus evidence export` / `erebus verify-evidence` — the pack an auditor
//! receives: receipts byte-for-byte, their transparency-log proofs, RFC 3161
//! tokens, DSSE envelopes for cosign, and only the public keys that verify
//! them. Verification replays `verify-attest` step for step. `MANIFEST.json`
//! is an index (a hash for every file), not a trust root: trust comes from
//! the signatures inside the receipts, proofs and machine certificates.

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use erebus_core::attest::{key_fingerprint, Attestation, ExecutionInfo, HeartbeatInfo};
use erebus_core::attest_log::{AttestationLog, HEAD_FILE};
use erebus_core::log_proof::LogProof;
use erebus_core::paths::trusted_keys_dir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::verify_attest as va;

/// Pack format identifier; bump on any layout or manifest change.
pub const SPEC: &str = "erebus-evidence/2";
/// Packs made before coverage reporting; still verifiable, without coverage.
const LEGACY_SPEC: &str = "erebus-evidence/1";
const MANIFEST: &str = "MANIFEST.json";
const COVERAGE: &str = "COVERAGE.json";
/// Bundles with embedded weights reach several GB; anything beyond is hostile.
const MAX_ENTRY_BYTES: u64 = 16 << 30;

#[derive(Args)]
pub struct EvidenceArgs {
    #[command(subcommand)]
    pub command: EvidenceCommand,
}

#[derive(Subcommand)]
pub enum EvidenceCommand {
    /// Pack a bundle's receipts, log proofs, TSA tokens and public keys
    ///
    /// Every receipt is verified first (signature, machine co-signature, log
    /// proof, chain); a trail that does not verify is never exported.
    ///
    /// Examples:
    ///   erebus evidence export agent.erebus -o evidence.zip --log-key <hex>
    ///   erebus evidence export agent.erebus --trail receipts/ -o pack.zip --log-key <hex>
    Export(ExportArgs),
}

#[derive(Args)]
pub struct ExportArgs {
    /// Bundle the receipts cover
    pub bundle: PathBuf,

    /// Output zip
    #[arg(short, long)]
    pub output: PathBuf,

    /// Receipt trail directory (default: <bundle>.attest.d)
    #[arg(long, value_name = "DIR")]
    pub trail: Option<PathBuf>,

    /// Directory with trusted operator public keys
    #[arg(long)]
    pub trusted_dir: Option<PathBuf>,

    /// Registry public key (64 hex, from GET <registry>/log/key); repeatable
    #[arg(long = "log-key", value_name = "HEX", visible_alias = "registry-key")]
    pub log_keys: Vec<String>,

    /// Embed the bundle itself (default: its digest only)
    #[arg(long)]
    pub include_bundle: bool,

    /// Overwrite an existing output file
    #[arg(long)]
    pub force: bool,

    /// Inclusive start of the incident window (`execution.attested_at`)
    #[arg(long)]
    pub since: Option<String>,

    /// Inclusive end of the incident window (`execution.attested_at`)
    #[arg(long)]
    pub until: Option<String>,

    /// Operator key that signs the window claim (required with --since/--until)
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Compliance profile written into the pack: `annex-iv` or `soc2`
    #[arg(long)]
    pub profile: Option<String>,
}

#[derive(Args)]
pub struct VerifyEvidenceArgs {
    /// Evidence pack produced by `erebus evidence export`
    pub pack: PathBuf,

    /// Bundle file to check against the signed digest (when not embedded)
    #[arg(long, value_name = "FILE")]
    pub bundle: Option<PathBuf>,

    /// Operator public key obtained out of band: the 64-hex key `erebus
    /// keygen` prints, or its `sha256:` fingerprint. Every operator key in
    /// the pack must be one of these (repeatable)
    #[arg(long = "operator-key", value_name = "KEY")]
    pub operator_keys: Vec<String>,

    /// Transparency-log public key (64 hex, as served at /log/key) obtained
    /// out of band; every registry key in the pack must be one of these
    #[arg(long = "log-key", alias = "registry-key", value_name = "HEX")]
    pub log_keys: Vec<String>,

    /// Output the verification report as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    spec: String,
    created_at: String,
    generator: String,
    bundle: BundleInfo,
    receipts: Vec<ReceiptEntry>,
    chain_head: Option<String>,
    registry_keys: Vec<String>,
    files: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    until: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct BundleInfo {
    name: String,
    sha256: String,
    size: u64,
    included: bool,
}

#[derive(Serialize, Deserialize)]
struct ReceiptEntry {
    receipt: String,
    proof: Option<String>,
    anchor: Option<String>,
    dsse: Option<String>,
}

/// What the receipt-by-receipt pass established.
#[derive(Default)]
struct Tally {
    receipts: usize,
    machine_signed: usize,
    proofs: usize,
    anchors: usize,
    operator_keys: BTreeSet<String>,
}

/// Coverage derived only from the signed receipts in this trail. It is
/// re-derived by `verify-evidence`; a packed copy that disagrees is tampering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Coverage {
    /// ISO 8601 bounds of the receipts examined.
    from: String,
    to: String,
    /// Inference calls attested by the gateway (`execution.request`).
    gateway_calls: u64,
    /// Signed liveness ticks and the sequence interval they cover.
    heartbeats: Heartbeats,
    /// Call deltas signed by those ticks (may precede a window's first receipt).
    calls_in_heartbeats: u64,
    /// Launcher-attested executions with no gateway request: runs outside it.
    outside_gateway: Vec<String>,
    /// Sequence gaps or call-count mismatches, in signed order.
    gaps: Vec<String>,
    /// True only when no gap and no run outside the gateway was found.
    complete: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Heartbeats {
    count: u64,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
}

/// Keys a pack is checked against: operator keys sign receipts; registry
/// (log) keys certify machines and checkpoints. The two sets must be disjoint.
struct Keys {
    operator: Vec<VerifyingKey>,
    registry: Vec<VerifyingKey>,
}

type Receipts = Vec<(PathBuf, Option<PathBuf>)>;
type Entries = Vec<(String, Vec<u8>)>;

pub fn run(args: EvidenceArgs) -> Result<()> {
    match args.command {
        EvidenceCommand::Export(a) => export(&a),
    }
}

// ── coverage ────────────────────────────────────────────────────────────

/// Coverage is a view of signed execution facts, never an independent traffic
/// measurement: traffic that produced no receipt is invisible here.
fn coverage(executions: &[ExecutionInfo]) -> Result<Coverage> {
    let first = executions.first().context("no receipts")?;
    let last = executions.last().context("no receipts")?;
    let mut state = CoverageState::default();
    for e in executions {
        state.observe(e);
    }
    Ok(state.finish(&first.attested_at, &last.attested_at))
}

fn executions(receipts: &Receipts) -> Result<Vec<ExecutionInfo>> {
    receipts
        .iter()
        .map(|(path, _)| {
            let att: Attestation = serde_json::from_slice(&std::fs::read(path)?)?;
            Ok(att.execution)
        })
        .collect()
}

fn manifest_receipts(dir: &Path, m: &Manifest) -> Receipts {
    m.receipts
        .iter()
        .map(|r| (dir.join(&r.receipt), r.proof.as_ref().map(|p| dir.join(p))))
        .collect()
}

/// A launcher-attested execution that never passed the attesting proxy.
fn outside_gateway(e: &ExecutionInfo) -> bool {
    e.request.is_none()
        && e.heartbeat.is_none()
        && e.stop.is_none()
        && (e.rootfs_root.is_some()
            || e.exit_code.is_some()
            || e.input_hash.is_some()
            || e.output_hash.is_some())
}

#[derive(Default)]
struct CoverageState {
    gateway_calls: u64,
    since_beat: u64,
    prev_seq: Option<u64>,
    beats: Heartbeats,
    calls_in_heartbeats: u64,
    outside: Vec<String>,
    gaps: Vec<String>,
}

impl CoverageState {
    fn observe(&mut self, e: &ExecutionInfo) {
        if e.request.is_some() {
            self.gateway_calls += 1;
            self.since_beat += 1;
        }
        if let Some(h) = &e.heartbeat {
            self.tick(h);
        }
        if outside_gateway(e) {
            self.outside.push(e.attested_at.clone());
        }
    }

    /// Only consecutive ticks bound a window: the first tick of a window may
    /// count calls before it, so its delta cannot be checked against the pack.
    fn tick(&mut self, h: &HeartbeatInfo) {
        if let Some(p) = self.prev_seq {
            if p.saturating_add(1) == h.sequence && self.since_beat != h.calls_since_previous {
                self.gaps.push(format!(
                    "heartbeat {} counts {} call(s), trail has {}",
                    h.sequence, h.calls_since_previous, self.since_beat
                ));
            } else if p.saturating_add(1) != h.sequence {
                self.gaps
                    .push(format!("heartbeat sequence {p} -> {}", h.sequence));
            }
        }
        self.calls_in_heartbeats += h.calls_since_previous;
        self.beats.count += 1;
        self.beats.first_sequence.get_or_insert(h.sequence);
        self.beats.last_sequence = Some(h.sequence);
        self.prev_seq = Some(h.sequence);
        self.since_beat = 0;
    }

    fn finish(mut self, from: &str, to: &str) -> Coverage {
        if self.beats.count > 0 && self.since_beat > 0 {
            self.gaps.push(format!(
                "{} gateway call(s) after the last heartbeat",
                self.since_beat
            ));
        }
        let complete = self.gaps.is_empty() && self.outside.is_empty();
        Coverage {
            from: from.to_string(),
            to: to.to_string(),
            gateway_calls: self.gateway_calls,
            heartbeats: self.beats,
            calls_in_heartbeats: self.calls_in_heartbeats,
            gaps: self.gaps,
            outside_gateway: self.outside,
            complete,
        }
    }
}

// ── export ──────────────────────────────────────────────────────────────

fn export(args: &ExportArgs) -> Result<()> {
    if args.output.exists() && !args.force {
        anyhow::bail!("{} already exists (use --force)", args.output.display());
    }
    let (sha256, size) = hash_file(&args.bundle)?;
    let trail = args
        .trail
        .clone()
        .unwrap_or_else(|| default_trail(&args.bundle));
    let all = collect_receipts(&trail)?;
    let (keys, log_keys) = export_keys(args)?;
    // The whole trail must verify; the pack may then keep only the window.
    let (full_head, _) = verify_trail(&trail, &all, &keys, &sha256)
        .context("refusing to export evidence that does not verify")?;
    let receipts = filter_window(&all, args.since.as_deref(), args.until.as_deref())?;
    let (_, tally) = verify_trail(&trail, &receipts, &keys, &sha256)?;
    let cov = coverage(&executions(&receipts)?)?;
    let mut entries = pack_entries(&receipts, &keys.operator, &log_keys, &tally, &cov)?;
    entries.push((COVERAGE.to_string(), serde_json::to_vec_pretty(&cov)?));
    if args.since.is_some() || args.until.is_some() {
        entries.push(("CLAIM.json".into(), claim_bytes(args, &receipts)?));
    }
    if let Some(profile) = &args.profile {
        entries.push(("COMPLIANCE.json".into(), compliance_bytes(profile, &tally)?));
    }
    let bundle = BundleInfo {
        name: file_name(&args.bundle)?,
        sha256,
        size,
        included: args.include_bundle,
    };
    let chain_head = if args.since.is_some() || args.until.is_some() {
        window_head(args, &receipts)?
    } else {
        full_head
    };
    let manifest = build_manifest(args, bundle, &receipts, chain_head, &log_keys, &entries)?;
    let embed = args.include_bundle.then_some(args.bundle.as_path());
    write_zip(&args.output, &manifest, &entries, embed)?;
    eprintln!(
        "Wrote {} — {} receipt(s), {} log proof(s), {} RFC 3161 token(s)",
        args.output.display(),
        tally.receipts,
        tally.proofs,
        tally.anchors
    );
    eprintln!(
        "Verify offline: erebus verify-evidence {}",
        args.output.display()
    );
    Ok(())
}

fn export_keys(args: &ExportArgs) -> Result<(Keys, Vec<VerifyingKey>)> {
    let operator =
        va::load_trusted_keys(&args.trusted_dir.clone().unwrap_or_else(trusted_keys_dir))?;
    anyhow::ensure!(
        !operator.is_empty(),
        "no trusted operator keys — pass --trusted-dir"
    );
    let log_keys = args
        .log_keys
        .iter()
        .map(|k| va::parse_log_key(k))
        .collect::<Result<Vec<_>>>()?;
    // Only the explicit registry key may certify machines and checkpoints:
    // an operator key must never double as the "independent" log trust root.
    Ok((
        Keys {
            operator,
            registry: log_keys.clone(),
        },
        log_keys,
    ))
}

fn default_trail(bundle: &Path) -> PathBuf {
    let mut name = bundle.as_os_str().to_owned();
    name.push(".attest.d");
    PathBuf::from(name)
}

/// Receipts in chain order, each with its `.proof.json` sidecar if present.
fn collect_receipts(trail: &Path) -> Result<Receipts> {
    anyhow::ensure!(
        trail.is_dir(),
        "no receipt trail at {} — pass --trail <dir>",
        trail.display()
    );
    let entries = AttestationLog::open(trail)?.entries()?;
    anyhow::ensure!(
        !entries.is_empty(),
        "trail {} holds no receipts",
        trail.display()
    );
    Ok(entries
        .into_iter()
        .map(|r| {
            let proof = super::attest::proof_path_for(&r);
            let proof = proof.is_file().then_some(proof);
            (r, proof)
        })
        .collect())
}

fn verify_trail(
    trail: &Path,
    receipts: &Receipts,
    keys: &Keys,
    bundle_sha: &str,
) -> Result<(Option<String>, Tally)> {
    let chain = va::verify_chain(trail, &keys.operator, None)?;
    let mut tally = Tally::default();
    for (receipt, proof) in receipts {
        check_receipt(receipt, proof.as_deref(), keys, bundle_sha, &mut tally).with_context(
            || {
                format!(
                    "{} does not verify (the registry key comes from GET <registry>/log/key)",
                    receipt.display()
                )
            },
        )?;
    }
    Ok((chain["head"].as_str().map(str::to_string), tally))
}

/// The exact checks of `verify-attest`, plus `--strict` whenever the receipt
/// carries a machine co-signature and `--proof` whenever a proof exists. The
/// bundle is hashed once by the caller and compared to each signed digest.
fn check_receipt(
    receipt: &Path,
    proof: Option<&Path>,
    keys: &Keys,
    bundle_sha: &str,
    tally: &mut Tally,
) -> Result<()> {
    let single = va::verify_single(receipt, &keys.operator, None)?;
    let signed = single["bundle_sha256"].as_str().unwrap_or("-");
    anyhow::ensure!(
        signed == bundle_sha,
        "TAMPERED: receipt covers bundle sha256:{signed}, not sha256:{bundle_sha}"
    );
    if let Some(k) = single["key"].as_str() {
        tally.operator_keys.insert(k.to_string());
    }
    if !single["machine_id"].is_null() {
        va::verify_strict(receipt, &keys.registry)?;
        tally.machine_signed += 1;
    }
    if let Some(p) = proof {
        let lp = va::verify_log_proof(receipt, p, &keys.registry)?;
        tally.proofs += 1;
        tally.anchors += usize::from(lp["anchor"].is_object());
    }
    tally.receipts += 1;
    Ok(())
}

fn pack_entries(
    receipts: &Receipts,
    operator: &[VerifyingKey],
    log_keys: &[VerifyingKey],
    tally: &Tally,
    cov: &Coverage,
) -> Result<Entries> {
    let mut out = Entries::new();
    for (receipt, proof) in receipts {
        receipt_entries(receipt, proof.as_deref(), &mut out)?;
    }
    if let Some(dir) = receipts.first().and_then(|(r, _)| r.parent()) {
        let head = dir.join(HEAD_FILE);
        if head.is_file() {
            out.push((format!("trail/{HEAD_FILE}"), std::fs::read(head)?));
        }
    }
    let used = operator
        .iter()
        .filter(|k| tally.operator_keys.contains(&hex::encode(k.as_bytes())));
    key_entries("keys/operator", used, &mut out);
    key_entries("keys/registry", log_keys.iter(), &mut out);
    out.push(("README.txt".to_string(), readme(tally, cov).into_bytes()));
    Ok(out)
}

fn receipt_entries(receipt: &Path, proof: Option<&Path>, out: &mut Entries) -> Result<()> {
    let bytes = std::fs::read(receipt)?;
    let name = file_name(receipt)?;
    let stem = name.trim_end_matches(".json").to_string();
    let att: Attestation = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", receipt.display()))?;
    if let Some(env) = &att.envelope {
        out.push((
            format!("dsse/{stem}.dsse.json"),
            serde_json::to_vec_pretty(env)?,
        ));
    }
    out.push((format!("trail/{name}"), bytes));
    if let Some(p) = proof {
        let proof_bytes = std::fs::read(p)?;
        if let Some((token, checkpoint)) = anchor_parts(&proof_bytes)? {
            out.push((format!("anchors/{stem}.tsr"), token));
            out.push((format!("anchors/{stem}.checkpoint"), checkpoint));
        }
        out.push((format!("trail/{}", file_name(p)?), proof_bytes));
    }
    Ok(())
}

/// The DER RFC 3161 response carried (base64) inside a proof, if anchored,
/// with the exact checkpoint bytes it timestamps (`openssl ts -verify -data`).
fn anchor_parts(proof_bytes: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let proof: LogProof = serde_json::from_slice(proof_bytes).context("failed to parse proof")?;
    let Some(anchor) = proof.anchor else {
        return Ok(None);
    };
    let token = base64::engine::general_purpose::STANDARD
        .decode(anchor.token_b64.as_bytes())
        .context("RFC 3161 token is not valid base64")?;
    Ok(Some((token, proof.checkpoint.anchor_bytes()?)))
}

fn key_entries<'a>(dir: &str, keys: impl Iterator<Item = &'a VerifyingKey>, out: &mut Entries) {
    for key in keys {
        let fp = key_fingerprint(key);
        let short = fp.trim_start_matches("sha256:").get(..16).unwrap_or("key");
        out.push((format!("{dir}/{short}.pub"), key.as_bytes().to_vec()));
        out.push((
            format!("{dir}/{short}.pem"),
            erebus_core::dsse::public_key_pem(key).into_bytes(),
        ));
    }
}

fn verify_claim(dir: &Path, m: &Manifest, keys: &[VerifyingKey]) -> Result<()> {
    let claim: erebus_core::claim::Claim =
        serde_json::from_slice(&std::fs::read(dir.join("CLAIM.json"))?)
            .context("window pack is missing CLAIM.json")?;
    claim.verify(keys)?;
    anyhow::ensure!(
        claim.receipts == m.receipts.len() as u64,
        "TAMPERED: claim lists {} receipt(s), manifest lists {}",
        claim.receipts,
        m.receipts.len()
    );
    anyhow::ensure!(
        claim.since == m.since.clone().unwrap_or_default()
            && claim.until == m.until.clone().unwrap_or_default(),
        "TAMPERED: claim window differs from the manifest"
    );
    anyhow::ensure!(
        claim.verification_failures == 0,
        "TAMPERED: claim reports failures"
    );

    // MANIFEST.json is unsigned: only the signed claim and the already
    // signature-checked receipts can establish what the window contains.
    // Rebuild the chain and every tally from the receipts themselves.
    let mut names = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    let mut prev: Option<String> = None;
    let mut receipts = Receipts::new();
    for (i, row) in m.receipts.iter().enumerate() {
        anyhow::ensure!(
            names.insert(row.receipt.clone()),
            "TAMPERED: duplicate receipt {} in window",
            row.receipt
        );
        let bytes = std::fs::read(dir.join(&row.receipt))?;
        let hash = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        anyhow::ensure!(
            hashes.insert(hash.clone()),
            "TAMPERED: duplicate receipt bytes at {}",
            row.receipt
        );
        let att: Attestation = serde_json::from_slice(&bytes)?;
        // The first receipt's link points outside the window and is not
        // packed; every later link must match the preceding receipt's hash.
        if i > 0 {
            anyhow::ensure!(
                att.execution.prev_attestation_hash == prev,
                "TAMPERED: chain broken at {} (expected prev {:?}, receipt says {:?})",
                row.receipt,
                prev,
                att.execution.prev_attestation_hash
            );
        }
        anyhow::ensure!(
            erebus_core::claim::in_window(
                &att.execution.attested_at,
                m.since.as_deref(),
                m.until.as_deref()
            ),
            "TAMPERED: {} is outside the claim window",
            row.receipt
        );
        prev = Some(hash);
        receipts.push((
            dir.join(&row.receipt),
            row.proof.as_ref().map(|p| dir.join(p)),
        ));
    }
    let head = prev.context("TAMPERED: window claim lists no receipts")?;
    anyhow::ensure!(
        claim.head == head,
        "TAMPERED: claim head {} differs from hash of last receipt {head}",
        claim.head
    );
    anyhow::ensure!(
        m.chain_head.as_deref() == Some(head.as_str()),
        "TAMPERED: manifest chain head differs from the last receipt"
    );
    let (digests, tools, stops, approvals) = claim_counts(&receipts)?;
    anyhow::ensure!(
        claim.model_digests == digests
            && claim.tool_calls == tools
            && claim.stops == stops
            && claim.approvals == approvals,
        "TAMPERED: claim tallies differ from the packed receipts"
    );
    Ok(())
}

fn filter_window(
    receipts: &Receipts,
    since: Option<&str>,
    until: Option<&str>,
) -> Result<Receipts> {
    if since.is_none() && until.is_none() {
        return Ok(receipts.clone());
    }
    let mut kept = Receipts::new();
    for (path, proof) in receipts {
        let att: Attestation = serde_json::from_slice(&std::fs::read(path)?)?;
        if erebus_core::claim::in_window(&att.execution.attested_at, since, until) {
            kept.push((path.clone(), proof.clone()));
        }
    }
    anyhow::ensure!(
        !kept.is_empty(),
        "no receipts in window {}..{}",
        since.unwrap_or("-"),
        until.unwrap_or("-")
    );
    Ok(kept)
}

fn window_head(args: &ExportArgs, receipts: &Receipts) -> Result<Option<String>> {
    if args.since.is_none() && args.until.is_none() {
        return Ok(None);
    }
    let last = receipts.last().map(|(p, _)| p).context("empty window")?;
    Ok(Some(format!(
        "sha256:{}",
        sha256_hex(&std::fs::read(last)?)
    )))
}

fn claim_bytes(args: &ExportArgs, receipts: &Receipts) -> Result<Vec<u8>> {
    let key_path = args
        .key
        .as_ref()
        .context("--since/--until need --key to sign the claim")?;
    let seed = std::fs::read(key_path)?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| anyhow::anyhow!("--key must be 32 bytes"))?;
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let (digests, tools, stops, approvals) = claim_counts(receipts)?;
    let head = window_head(args, receipts)?.unwrap_or_default();
    let claim = erebus_core::claim::Claim {
        since: args.since.clone().unwrap_or_default(),
        until: args.until.clone().unwrap_or_default(),
        receipts: receipts.len() as u64,
        head,
        model_digests: digests,
        tool_calls: tools,
        stops,
        approvals,
        verification_failures: 0,
        key_id: String::new(),
        signature_hex: String::new(),
    }
    .sign(&key);
    Ok(serde_json::to_vec_pretty(&claim)?)
}

fn claim_counts(receipts: &Receipts) -> Result<(Vec<String>, u64, u64, u64)> {
    let mut digests = BTreeSet::new();
    let mut tools = 0u64;
    let mut stops = 0u64;
    let mut approvals = 0u64;
    for (path, _) in receipts {
        let att: Attestation = serde_json::from_slice(&std::fs::read(path)?)?;
        for layer in &att.provenance.layers {
            if layer.kind == "model" && !layer.sha256.is_empty() {
                digests.insert(layer.sha256.clone());
            }
        }
        tools += att
            .execution
            .request
            .as_ref()
            .and_then(|r| r.tool_calls.as_ref())
            .map(|c| c.len() as u64)
            .unwrap_or(0);
        stops += u64::from(att.execution.stop.is_some());
        approvals += u64::from(att.execution.approval.is_some());
    }
    Ok((digests.into_iter().collect(), tools, stops, approvals))
}

fn compliance_bytes(profile: &str, tally: &Tally) -> Result<Vec<u8>> {
    let body = match profile {
        "annex-iv" => serde_json::json!({
            "profile": "eu-ai-act-annex-iv",
            "art_12_record_keeping": { "receipts": tally.receipts },
            "art_14_human_oversight": "approvals are in CLAIM.json when a window is set",
            "art_19_logs": "hash-chained receipts, not operator-editable text logs",
        }),
        "soc2" => serde_json::json!({
            "profile": "soc2",
            "cc7_monitoring": { "receipts": tally.receipts, "proofs": tally.proofs },
        }),
        other => anyhow::bail!("unknown --profile {other} (annex-iv or soc2)"),
    };
    Ok(serde_json::to_vec_pretty(&body)?)
}

fn build_manifest(
    args: &ExportArgs,
    bundle: BundleInfo,
    receipts: &Receipts,
    chain_head: Option<String>,
    log_keys: &[VerifyingKey],
    entries: &Entries,
) -> Result<Manifest> {
    let names: BTreeSet<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    let listed = |n: String| names.contains(n.as_str()).then_some(n);
    let mut rows = Vec::new();
    for (receipt, proof) in receipts {
        let name = file_name(receipt)?;
        let stem = name.trim_end_matches(".json").to_string();
        let proof = proof.as_deref().map(file_name).transpose()?;
        rows.push(ReceiptEntry {
            receipt: format!("trail/{name}"),
            proof: proof.map(|p| format!("trail/{p}")),
            anchor: listed(format!("anchors/{stem}.tsr")),
            dsse: listed(format!("dsse/{stem}.dsse.json")),
        });
    }
    let mut files: BTreeMap<String, String> = entries
        .iter()
        .map(|(n, b)| (n.clone(), sha256_hex(b)))
        .collect();
    if bundle.included {
        files.insert(format!("bundle/{}", bundle.name), bundle.sha256.clone());
    }
    Ok(Manifest {
        spec: SPEC.to_string(),
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        generator: concat!("erebus-cli/", env!("CARGO_PKG_VERSION")).to_string(),
        bundle,
        receipts: rows,
        chain_head,
        registry_keys: log_keys.iter().map(|k| hex::encode(k.as_bytes())).collect(),
        files,
        since: args.since.clone(),
        until: args.until.clone(),
        profile: args.profile.clone(),
    })
}

fn write_zip(
    path: &Path,
    manifest: &Manifest,
    entries: &Entries,
    embed: Option<&Path>,
) -> Result<()> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    // Fixed timestamps: the same evidence always yields the same entries.
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::default())
        .large_file(true);
    zip.start_file(MANIFEST, opts)?;
    zip.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    for (name, bytes) in entries {
        zip.start_file(name.as_str(), opts)?;
        zip.write_all(bytes)?;
    }
    if let Some(bundle) = embed {
        zip.start_file(format!("bundle/{}", manifest.bundle.name), opts)?;
        std::io::copy(&mut std::fs::File::open(bundle)?, &mut zip)?;
    }
    zip.finish()?;
    Ok(())
}

fn readme(tally: &Tally, cov: &Coverage) -> String {
    format!(
        "erebus evidence pack ({SPEC})\n\n\
         {} execution receipt(s), {} transparency-log proof(s), {} RFC 3161 token(s).\n\
         Coverage: {} gateway call(s), {} heartbeat(s), {} run(s) outside gateway; complete={}.\n\n\
         Verify everything offline (no network, no account):\n  \
         erebus verify-evidence <this-pack>.zip --bundle <bundle file> \\\n    \
         --operator-key <operator public key hex> --log-key <registry /log/key hex>\n\n\
         The keys under keys/ come with the pack. Obtain the operator fingerprint\n\
         and the registry log key from them directly (not from this pack) and pin\n\
         them as above; without pins the report says NOT PINNED.\n\n\
         Layout\n  \
         trail/          receipts byte-for-byte (+ .proof.json, HEAD); each receipt names\n                  \
         the previous one's hash, so reordering or deleting inside the trail breaks it\n  \
         COVERAGE.json   derived from the signed receipts; verify-evidence re-derives it\n  \
         keys/operator/  public keys that signed the receipts (.pub raw, .pem SPKI)\n  \
         keys/registry/  transparency-log key: signs checkpoints and machine certificates\n  \
         anchors/        RFC 3161 responses (.tsr) and the checkpoint bytes they cover\n  \
         dsse/           DSSE envelopes, for tools other than erebus\n\n\
         Without erebus\n  \
         COSIGN_MAX_ATTACHMENT_SIZE=16GiB cosign verify-blob-attestation \\\n    \
         --key keys/operator/<fp>.pem \\\n    \
         --signature dsse/<receipt>.dsse.json \\\n    \
         --type https://erebus.dev/attestation/execution/v2 --insecure-ignore-tlog <bundle file>\n  \
         openssl ts -verify -in anchors/<receipt>.tsr -data anchors/<receipt>.checkpoint \\\n    \
         -CAfile <TSA CA chain, e.g. https://freetsa.org/files/cacert.pem>\n\n\
         What this proves: which exact bundle ran, on which enrolled machine, when, with\n\
         which input/output digests, and that the record was not edited afterwards.\n\
         It does not prove the computation was correct, nor reveal plaintext.\n\
         Coverage is computed from receipts only: traffic that never produced a receipt\n\
         is invisible here, so this pack is not proof that every run was captured.\n\
         Deletion of the newest receipts is detected by the transparency log (its\n\
         signed tree only grows), not by this pack alone. MANIFEST.json is an index,\n\
         not a signature: trust comes from the signatures inside the files.\n",
        tally.receipts,
        tally.proofs,
        tally.anchors,
        cov.gateway_calls,
        cov.heartbeats.count,
        cov.outside_gateway.len(),
        cov.complete
    )
}

// ── verify-evidence ─────────────────────────────────────────────────────

pub fn run_verify(args: VerifyEvidenceArgs) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let names = unpack(&args.pack, dir.path())?;
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(dir.path().join(MANIFEST)).context("pack has no MANIFEST.json")?,
    )
    .context("failed to parse MANIFEST.json")?;
    anyhow::ensure!(
        manifest.spec == SPEC || manifest.spec == LEGACY_SPEC,
        "unsupported evidence pack spec {:?} (this erebus reads {SPEC} or {LEGACY_SPEC})",
        manifest.spec
    );
    let report = check_files(dir.path(), &manifest, &names)
        .and_then(|()| verify_unpacked(dir.path(), &manifest, &args))
        .context("evidence verification failed")?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }
    Ok(())
}

/// Extract regular files only, refusing traversal, absolute paths and links.
fn unpack(pack: &Path, dest: &Path) -> Result<BTreeSet<String>> {
    let file =
        std::fs::File::open(pack).with_context(|| format!("failed to open {}", pack.display()))?;
    let mut zip = zip::ZipArchive::new(file).context("not a zip evidence pack")?;
    let mut names = BTreeSet::new();
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().with_context(|| format!("zip entry {i}"))?;
        let rel = entry
            .enclosed_name()
            .ok_or_else(|| anyhow::anyhow!("unsafe path in pack: {name}"))?;
        anyhow::ensure!(!entry.is_symlink(), "link in pack: {name}");
        anyhow::ensure!(entry.size() <= MAX_ENTRY_BYTES, "oversized entry: {name}");
        anyhow::ensure!(names.insert(name.to_string()), "duplicate entry: {name}");
        let out = dest.join(&rel);
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = std::fs::File::create(&out)?;
        std::io::copy(&mut entry.by_ref().take(MAX_ENTRY_BYTES), &mut f)?;
    }
    Ok(names)
}

/// Every listed file present with its hash; nothing unlisted smuggled in.
fn check_files(dir: &Path, manifest: &Manifest, names: &BTreeSet<String>) -> Result<()> {
    for (name, want) in &manifest.files {
        anyhow::ensure!(names.contains(name), "TAMPERED: {name} listed but missing");
        let (got, _) = hash_file(&dir.join(name))?;
        anyhow::ensure!(&got == want, "TAMPERED: {name} hash mismatch");
    }
    for name in names {
        anyhow::ensure!(
            name == MANIFEST || manifest.files.contains_key(name),
            "TAMPERED: {name} is not listed in MANIFEST.json"
        );
    }
    Ok(())
}

fn verify_unpacked(
    dir: &Path,
    m: &Manifest,
    args: &VerifyEvidenceArgs,
) -> Result<serde_json::Value> {
    let operator = va::load_trusted_keys(&dir.join("keys/operator"))?;
    anyhow::ensure!(!operator.is_empty(), "pack carries no operator key");
    let log_keys = va::load_trusted_keys(&dir.join("keys/registry"))?;
    let key_ids = check_pins(&operator, &log_keys, args)?;
    let keys = Keys {
        operator,
        registry: log_keys,
    };
    let bundle_checked = check_bundle_file(dir, m, args.bundle.as_deref())?;
    // Signature-check each receipt before trusting its signed chain link.
    let mut tally = Tally::default();
    for row in &m.receipts {
        verify_row(dir, row, &m.bundle.sha256, &keys, &mut tally)
            .with_context(|| row.receipt.clone())?;
    }
    if m.since.is_some() || m.until.is_some() {
        verify_claim(dir, m, &keys.operator)?;
    } else {
        let chain = va::verify_chain(&dir.join("trail"), &keys.operator, None)?;
        anyhow::ensure!(
            chain["count"].as_u64() == Some(m.receipts.len() as u64),
            "TAMPERED: trail holds {} receipt(s), manifest lists {}",
            chain["count"],
            m.receipts.len()
        );
        anyhow::ensure!(
            chain["head"].as_str() == m.chain_head.as_deref(),
            "TAMPERED: trail HEAD differs from the manifest"
        );
    }
    let cov = if m.spec == LEGACY_SPEC {
        None
    } else {
        let packed: Coverage = serde_json::from_slice(
            &std::fs::read(dir.join(COVERAGE)).context("pack has no COVERAGE.json")?,
        )
        .context("failed to parse COVERAGE.json")?;
        let derived = coverage(&executions(&manifest_receipts(dir, m))?)?;
        anyhow::ensure!(
            packed == derived,
            "TAMPERED: COVERAGE.json does not match the signed receipts"
        );
        Some(packed)
    };
    let mut report = report_json(m, &tally, bundle_checked, cov.as_ref())?;
    report["keys"] = key_ids;
    Ok(report)
}

/// A pack carries its own public keys, so it only proves something once
/// those keys are tied to the operator and registry by another channel.
fn check_pins(
    operator: &[VerifyingKey],
    log_keys: &[VerifyingKey],
    args: &VerifyEvidenceArgs,
) -> Result<serde_json::Value> {
    let ids = |ks: &[VerifyingKey]| ks.iter().map(key_fingerprint).collect::<Vec<_>>();
    let (op_ids, log_ids) = (ids(operator), ids(log_keys));
    let want_op = args
        .operator_keys
        .iter()
        .map(|k| operator_pin(k))
        .collect::<Result<BTreeSet<_>>>()?;
    let want_log = args
        .log_keys
        .iter()
        .map(|h| va::parse_log_key(h).map(|k| key_fingerprint(&k)))
        .collect::<Result<BTreeSet<_>>>()?;
    anyhow::ensure!(
        log_keys.iter().all(|k| !operator.contains(k)),
        "TAMPERED: a key is packed as both operator and registry — trust roots must be separate"
    );
    for (have, want, what) in [
        (&op_ids, &want_op, "operator"),
        (&log_ids, &want_log, "registry"),
    ] {
        if let Some(bad) = have
            .iter()
            .find(|id| !want.is_empty() && !want.contains(*id))
        {
            anyhow::bail!("TAMPERED: {what} key {bad} is not one of the pinned keys");
        }
    }
    Ok(serde_json::json!({
        "operator": op_ids,
        "operator_public_keys": operator.iter().map(|k| hex::encode(k.as_bytes())).collect::<Vec<_>>(),
        "registry": log_ids,
        "operator_pinned": !want_op.is_empty(),
        "registry_pinned": !want_log.is_empty(),
    }))
}

/// `sha256:<hex>` is a fingerprint; bare hex is the public key itself.
fn operator_pin(key: &str) -> Result<String> {
    let key = key.trim().to_ascii_lowercase();
    match key.strip_prefix("sha256:") {
        Some(hex) => Ok(format!("sha256:{hex}")),
        None => va::parse_log_key(&key)
            .map(|k| key_fingerprint(&k))
            .context("--operator-key must be a 64-hex public key or sha256:<fingerprint>"),
    }
}

/// Hash the real bundle (given, or embedded) against the pack's digest; the
/// receipts are then checked against that same digest.
fn check_bundle_file(dir: &Path, m: &Manifest, bundle: Option<&Path>) -> Result<bool> {
    let path = match bundle {
        Some(p) => p.to_path_buf(),
        None if m.bundle.included => dir.join("bundle").join(&m.bundle.name),
        None => return Ok(false),
    };
    let (sha, _) = hash_file(&path)?;
    anyhow::ensure!(
        sha == m.bundle.sha256,
        "TAMPERED: bundle {} is sha256:{sha}, the receipts cover sha256:{}",
        path.display(),
        m.bundle.sha256
    );
    Ok(true)
}

fn verify_row(
    dir: &Path,
    row: &ReceiptEntry,
    bundle_sha: &str,
    keys: &Keys,
    tally: &mut Tally,
) -> Result<()> {
    let receipt = dir.join(&row.receipt);
    let proof = row.proof.as_ref().map(|p| dir.join(p));
    check_receipt(&receipt, proof.as_deref(), keys, bundle_sha, tally)?;
    if let (Some(anchor), Some(proof)) = (&row.anchor, &proof) {
        let (token, checkpoint) = anchor_parts(&std::fs::read(proof)?)?.ok_or_else(|| {
            anyhow::anyhow!("TAMPERED: {anchor} listed but the proof is not anchored")
        })?;
        anyhow::ensure!(
            token == std::fs::read(dir.join(anchor))?,
            "TAMPERED: {anchor} differs from the token in the signed proof"
        );
        let cp = anchor.replace(".tsr", ".checkpoint");
        anyhow::ensure!(
            checkpoint
                == std::fs::read(dir.join(&cp))
                    .with_context(|| format!("TAMPERED: {cp} missing"))?,
            "TAMPERED: {cp} differs from the checkpoint in the signed proof"
        );
    }
    if let Some(dsse) = &row.dsse {
        let att: Attestation = serde_json::from_slice(&std::fs::read(&receipt)?)?;
        let env: erebus_core::dsse::Envelope =
            serde_json::from_slice(&std::fs::read(dir.join(dsse))?)?;
        anyhow::ensure!(
            att.envelope.as_ref() == Some(&env),
            "TAMPERED: {dsse} differs from the receipt's envelope"
        );
    }
    Ok(())
}

fn report_json(
    m: &Manifest,
    t: &Tally,
    bundle_checked: bool,
    cov: Option<&Coverage>,
) -> Result<serde_json::Value> {
    let mut report = serde_json::json!({
        "verified": true,
        "spec": m.spec,
        "created_at": m.created_at,
        "bundle": { "name": m.bundle.name, "sha256": m.bundle.sha256, "file_checked": bundle_checked },
        "receipts": t.receipts,
        "chain_head": m.chain_head,
        "operator_keys": t.operator_keys.len(),
        "machine_cosigned": t.machine_signed,
        "log_proofs": t.proofs,
        "tsa_anchors": t.anchors,
        "files": m.files.len(),
    });
    if let Some(cov) = cov {
        report["coverage"] = serde_json::to_value(cov)?;
    }
    Ok(report)
}

fn print_keys(k: &serde_json::Value) {
    for (role, pinned) in [
        ("operator", "operator_pinned"),
        ("registry", "registry_pinned"),
    ] {
        let state = if k[pinned] == true {
            "pinned"
        } else {
            "NOT PINNED"
        };
        for id in k[role].as_array().into_iter().flatten() {
            eprintln!("  {role:<9}   {} ({state})", id.as_str().unwrap_or("?"));
        }
        if role == "operator" {
            for pk in k["operator_public_keys"].as_array().into_iter().flatten() {
                eprintln!("              public key {}", pk.as_str().unwrap_or("?"));
            }
        }
    }
    if k["operator_pinned"] != true || k["registry_pinned"] != true {
        eprintln!(
            "  warning: keys come from the pack itself; confirm them with the operator and \
             registry out of band, then pass --operator-key / --log-key"
        );
    }
}

fn print_coverage(c: &serde_json::Value) {
    let h = &c["heartbeats"];
    let seq = |k: &str| {
        h[k].as_u64()
            .map_or_else(|| "-".to_string(), |v| v.to_string())
    };
    eprintln!(
        "  coverage:   {} gateway call(s), {} heartbeat(s) seq {}..{}, {} run(s) outside gateway, complete={}",
        c["gateway_calls"].as_u64().unwrap_or(0),
        h["count"].as_u64().unwrap_or(0),
        seq("first_sequence"),
        seq("last_sequence"),
        c["outside_gateway"].as_array().map_or(0, Vec::len),
        c["complete"].as_bool().unwrap_or(false)
    );
    for gap in c["gaps"].as_array().into_iter().flatten() {
        eprintln!("  gap:        {}", gap.as_str().unwrap_or("?"));
    }
}

fn print_report(r: &serde_json::Value) {
    let n = |k: &str| r[k].as_u64().unwrap_or(0);
    let total = n("receipts");
    let checked = if r["bundle"]["file_checked"] == true {
        "file checked"
    } else {
        "digest only — pass --bundle to check the file"
    };
    eprintln!(
        "OK: evidence pack verified ({})",
        r["spec"].as_str().unwrap_or("?")
    );
    eprintln!(
        "  bundle:     {} sha256:{} ({checked})",
        r["bundle"]["name"].as_str().unwrap_or("?"),
        r["bundle"]["sha256"].as_str().unwrap_or("?")
    );
    eprintln!(
        "  receipts:   {total}, hash-chained, head {}",
        r["chain_head"].as_str().unwrap_or("-")
    );
    eprintln!(
        "  signatures: {total}/{total} operator, {}/{total} machine co-signed (enrolled)",
        n("machine_cosigned")
    );
    eprintln!(
        "  log:        {}/{total} inclusion proofs under signed checkpoints, {} RFC 3161 anchor(s)",
        n("log_proofs"),
        n("tsa_anchors")
    );
    eprintln!(
        "  files:      {} hashed — none missing, none extra",
        n("files")
    );
    if let Some(c) = r.get("coverage") {
        print_coverage(c);
    }
    print_keys(&r["keys"]);
    if n("tsa_anchors") > 0 {
        eprintln!(
            "  anchors checked structurally; for the TSA signature: openssl ts -verify \
             -in anchors/<r>.tsr -data anchors/<r>.checkpoint -CAfile <TSA chain>"
        );
    }
}

/// Streaming SHA-256 (hex) and size: bundles with weights do not fit in RAM.
fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut f =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let size = std::io::copy(&mut f, &mut hasher)?;
    Ok((hex::encode(hasher.finalize()), size))
}

fn file_name(p: &Path) -> Result<String> {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| anyhow::anyhow!("{} has no file name", p.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use erebus_core::attest::RequestInfo;

    fn exec(at: &str, call: bool, beat: Option<HeartbeatInfo>, direct: bool) -> ExecutionInfo {
        ExecutionInfo {
            attested_at: at.to_string(),
            machine_id_hash: String::new(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            input_hash: None,
            output_hash: None,
            exit_code: direct.then_some(0),
            prev_attestation_hash: None,
            request: call.then(|| RequestInfo {
                method: "POST".to_string(),
                path: "/v1/chat/completions".to_string(),
                ..RequestInfo::default()
            }),
            rootfs_root: None,
            machine_id: None,
            stdin_hash: None,
            egress: None,
            stop: None,
            approval: None,
            heartbeat: beat,
        }
    }

    #[test]
    fn coverage_flags_outside_gateway_runs_and_sequence_gaps() {
        let all = vec![
            exec("t1", true, None, false),
            exec(
                "t2",
                false,
                Some(HeartbeatInfo {
                    sequence: 1,
                    interval_secs: 60,
                    calls_since_previous: 1,
                }),
                false,
            ),
            exec("t3", false, None, true),
            exec(
                "t4",
                false,
                Some(HeartbeatInfo {
                    sequence: 3,
                    interval_secs: 60,
                    calls_since_previous: 0,
                }),
                false,
            ),
        ];
        let c = coverage(&all).unwrap();
        assert_eq!(c.from, "t1");
        assert_eq!(c.to, "t4");
        assert_eq!(c.gateway_calls, 1);
        assert_eq!(c.heartbeats.count, 2);
        assert_eq!(c.outside_gateway, vec!["t3".to_string()]);
        assert!(c.gaps.iter().any(|g| g.contains("sequence 1 -> 3")));
        assert!(!c.complete);
    }

    #[test]
    fn coverage_is_complete_when_ticks_match_gateway_calls() {
        let all = vec![
            exec("t1", true, None, false),
            exec(
                "t2",
                false,
                Some(HeartbeatInfo {
                    sequence: 1,
                    interval_secs: 60,
                    calls_since_previous: 1,
                }),
                false,
            ),
            exec("t3", true, None, false),
            exec(
                "t4",
                false,
                Some(HeartbeatInfo {
                    sequence: 2,
                    interval_secs: 60,
                    calls_since_previous: 1,
                }),
                false,
            ),
        ];
        let c = coverage(&all).unwrap();
        assert!(c.gaps.is_empty());
        assert!(c.outside_gateway.is_empty());
        assert_eq!(c.calls_in_heartbeats, 2);
        assert!(c.complete);
    }

    #[test]
    fn pins_refuse_a_shared_operator_and_registry_key() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let key = sk.verifying_key();
        let args = VerifyEvidenceArgs {
            pack: PathBuf::from("pack.zip"),
            bundle: None,
            operator_keys: vec![],
            log_keys: vec![],
            json: false,
        };
        assert!(check_pins(&[key], &[key], &args).is_err());
        assert!(check_pins(&[key], &[], &args).is_ok());
    }
}
