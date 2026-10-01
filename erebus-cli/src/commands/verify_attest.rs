//! `erebus verify-attest` — verify execution receipts.
//!
//! Single receipt: Ed25519 signature over the in-toto statement, key
//! fingerprint, and consistency of the unsigned display fields with the signed
//! statement. `--bundle` additionally binds the receipt to a real file.
//! `--chain <dir>` verifies a whole hash-chained trail (see
//! `erebus_core::attest_log`) and links tool results to the calls that
//! requested them (`erebus_core::tool_linkage`; `--require-tool-linkage`
//! makes findings fatal). Every reported value is read from the **signed**
//! statement, never from the unsigned copies. `--proof` additionally checks
//! the registry transparency-log proof stored by `erebus attest --push`
//! (`<receipt>.proof.json`) — inclusion, signed checkpoint, TSA anchor —
//! entirely offline. `--strict` additionally demands a spec 2.0 receipt
//! co-signed by an enrolled machine key certified by a trusted registry.

use anyhow::{Context, Result};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use erebus_core::attest::{check_bundle_matches, verify_attestation, Attestation};
use erebus_core::attest_log::AttestationLog;
use erebus_core::paths::trusted_keys_dir;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct VerifyAttestArgs {
    /// Path to a .erebus.attest receipt (omit when using --chain)
    #[arg(required_unless_present = "chain")]
    pub attest_file: Option<PathBuf>,

    /// Verify a whole hash-chained trail directory (<bundle>.attest.d)
    #[arg(long, value_name = "DIR", conflicts_with = "attest_file")]
    pub chain: Option<PathBuf>,

    /// Bundle the receipt(s) must cover: its SHA-256 is compared to the
    /// signed bundle digest
    #[arg(long, value_name = "FILE")]
    pub bundle: Option<PathBuf>,

    /// Directory containing trusted public keys
    #[arg(long)]
    pub trusted_dir: Option<PathBuf>,

    /// Also verify the transparency-log proof (`<receipt>.proof.json`)
    #[arg(long, conflicts_with = "chain")]
    pub proof: bool,

    /// Explicit proof file (implies --proof)
    #[arg(long, value_name = "FILE", conflicts_with = "chain")]
    pub proof_file: Option<PathBuf>,

    /// Registry public key (64 hex chars) to trust for the log checkpoint
    /// and machine certificates, in addition to `.pub` files in the trusted
    /// dir
    #[arg(long, value_name = "HEX", visible_alias = "registry-key")]
    pub log_key: Option<String>,

    /// Require a machine co-signature: spec 2.0 receipt, signed by an
    /// enrolled machine key whose certificate comes from a trusted registry
    #[arg(long, conflicts_with = "chain")]
    pub strict: bool,

    /// Plaintext response body of a served call: must hash to the signed
    /// `output_hash` and re-derive the signed `tool_calls`
    #[arg(long, value_name = "FILE", conflicts_with = "chain")]
    pub response_body: Option<PathBuf>,

    /// Request body of a served call: `METHOD path` + body must hash to the
    /// signed `input_hash` and re-derive the signed tool results and history
    #[arg(long, value_name = "FILE", conflicts_with = "chain")]
    pub request_body: Option<PathBuf>,

    /// With --chain: fail when a tool result, replayed history or tool name
    /// does not link to a call the engine issued in the trail
    #[arg(long, requires = "chain")]
    pub require_tool_linkage: bool,

    /// Output verification result as JSON
    #[arg(long)]
    pub json: bool,

    /// Write JSON output to file (requires --json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: VerifyAttestArgs) -> Result<()> {
    let trusted_dir = args.trusted_dir.clone().unwrap_or_else(trusted_keys_dir);
    let keys = load_trusted_keys(&trusted_dir)?;
    if keys.is_empty() {
        anyhow::bail!(
            "no trusted keys in {} — add keys with: erebus trust <pubkey_file>",
            trusted_dir.display()
        );
    }
    let bundle_bytes = args
        .bundle
        .as_ref()
        .map(|p| std::fs::read(p).with_context(|| format!("failed to read bundle {}", p.display())))
        .transpose()?;

    let mut report = match (&args.chain, &args.attest_file) {
        (Some(dir), _) => verify_chain(dir, &keys, bundle_bytes.as_deref())?,
        (None, Some(file)) => verify_single(file, &keys, bundle_bytes.as_deref())?,
        (None, None) => anyhow::bail!("provide a receipt path or --chain <dir>"),
    };
    let mut registry_keys = keys.clone();
    if let Some(hex_key) = &args.log_key {
        registry_keys.push(parse_log_key(hex_key)?);
    }
    if args.strict {
        let file = args
            .attest_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--strict needs a receipt path"))?;
        report["machine"] = verify_strict(file, &registry_keys)?;
    }
    if let Some(body_path) = &args.response_body {
        let file = args
            .attest_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--response-body needs a receipt path"))?;
        report["response_body"] = verify_response_body(file, body_path)?;
    }
    if let Some(body_path) = &args.request_body {
        let file = args
            .attest_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--request-body needs a receipt path"))?;
        report["request_body"] = verify_request_body(file, body_path)?;
    }
    if args.require_tool_linkage {
        require_linkage(&report["tool_linkage"])?;
    }
    if args.proof || args.proof_file.is_some() {
        let file = args
            .attest_file
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--proof needs a receipt path"))?;
        let log_keys = registry_keys;
        let proof_path = args
            .proof_file
            .clone()
            .unwrap_or_else(|| super::attest::proof_path_for(file));
        report["log_proof"] = verify_log_proof(file, &proof_path, &log_keys)?;
    }

    if args.json {
        let json_str = serde_json::to_string_pretty(&report)?;
        if let Some(path) = args.output {
            std::fs::write(&path, &json_str)
                .with_context(|| format!("failed to write to {}", path.display()))?;
            eprintln!("Wrote JSON to {}", path.display());
        } else {
            println!("{json_str}");
        }
    } else {
        print_human(&report);
    }
    Ok(())
}

pub(crate) fn verify_single(
    file: &Path,
    keys: &[VerifyingKey],
    bundle_bytes: Option<&[u8]>,
) -> Result<serde_json::Value> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let attestation: Attestation = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", file.display()))?;

    let vk = verify_attestation(&attestation, keys).context("attestation verification failed")?;
    if let Some(bytes) = bundle_bytes {
        check_bundle_matches(&attestation, bytes).context("attestation verification failed")?;
    }

    let exec = signed_execution(&attestation);
    Ok(serde_json::json!({
        "file": file.display().to_string(),
        "verified": true,
        "mode": "single",
        "key": hex::encode(vk.as_bytes()),
        "spec_version": attestation.spec_version,
        "envelope": attestation.envelope.is_some(),
        "machine_id": attestation.machine.as_ref().map(|m| m.machine_id.clone()),
        "attestation_type": attestation.attestation_type,
        "bundle_sha256": signed_subject(&attestation, "bundle"),
        "bundle_checked": bundle_bytes.is_some(),
        "execution": exec,
    }))
}

/// `--strict`: machine co-signature + registry certificate (see
/// `erebus_core::machine::verify_machine`).
pub(crate) fn verify_strict(
    file: &Path,
    registry_keys: &[VerifyingKey],
) -> Result<serde_json::Value> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let attestation: Attestation = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", file.display()))?;
    let report = erebus_core::machine::verify_machine(&attestation, registry_keys)
        .context("strict verification failed")?;
    Ok(serde_json::json!({
        "verified": true,
        "machine_id": report.machine_id,
        "owner": report.owner,
        "registry": report.registry,
        "issued_at": report.issued_at,
    }))
}

/// `--response-body`: the plaintext body matches the signed digest and the
/// signed tool-call list (see `erebus_core::attest::check_response_body`).
fn verify_response_body(file: &Path, body_path: &Path) -> Result<serde_json::Value> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let attestation: Attestation = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", file.display()))?;
    let body = std::fs::read(body_path)
        .with_context(|| format!("failed to read response body {}", body_path.display()))?;
    let calls = erebus_core::attest::check_response_body(&attestation, &body)
        .context("response body verification failed")?;
    Ok(serde_json::json!({
        "file": body_path.display().to_string(),
        "verified": true,
        "tool_calls": calls.len(),
    }))
}

/// `--request-body`: the request matches the signed `input_hash` and the
/// signed request-side tool fields (see `erebus_core::attest::check_request_body`).
fn verify_request_body(file: &Path, body_path: &Path) -> Result<serde_json::Value> {
    let data = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read {}", file.display()))?;
    let attestation: Attestation = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", file.display()))?;
    let body = std::fs::read(body_path)
        .with_context(|| format!("failed to read request body {}", body_path.display()))?;
    let found = erebus_core::attest::check_request_body(&attestation, &body)
        .context("request body verification failed")?;
    Ok(serde_json::json!({
        "file": body_path.display().to_string(),
        "verified": true,
        "tool_results": found.results.len(),
        "tool_history": found.history.len(),
        "tools_offered": found.offered.len(),
    }))
}

/// `--require-tool-linkage`: any anomaly fails the verification.
fn require_linkage(linkage: &serde_json::Value) -> Result<()> {
    let anomalies = linkage
        .get("anomalies")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    if anomalies.is_empty() {
        return Ok(());
    }
    let lines: Vec<String> = anomalies.iter().map(describe_anomaly).collect();
    anyhow::bail!(
        "tool linkage verification failed: {} anomaly(ies): {}",
        lines.len(),
        lines.join("; ")
    )
}

fn describe_anomaly(a: &serde_json::Value) -> String {
    let f = |k: &str| a.get(k).and_then(|v| v.as_str()).unwrap_or("-");
    let what = match f("kind") {
        "result_without_call" => "result fed back for a call the engine never issued",
        "history_without_call" => "history replays a call the engine never issued",
        "history_altered" => "history replays a call with a different name or arguments",
        "result_rewritten" => "a second, different result for the same call",
        "unoffered_tool" => "the engine called a tool the request did not offer",
        other => other,
    };
    format!(
        "receipt #{}: {what} ({} {})",
        a.get("receipt").and_then(|v| v.as_u64()).unwrap_or(0),
        f("name"),
        f("id")
    )
}

/// Offline check of `<receipt>.proof.json`; the receipt's exact bytes are
/// the leaf preimage, so a re-serialized receipt fails here on purpose.
pub(crate) fn verify_log_proof(
    receipt: &Path,
    proof_path: &Path,
    log_keys: &[VerifyingKey],
) -> Result<serde_json::Value> {
    let receipt_bytes =
        std::fs::read(receipt).with_context(|| format!("failed to read {}", receipt.display()))?;
    let proof_json = std::fs::read(proof_path).with_context(|| {
        format!(
            "failed to read proof {} (push the receipt with `erebus attest --push` first)",
            proof_path.display()
        )
    })?;
    let proof: erebus_core::log_proof::LogProof = serde_json::from_slice(&proof_json)
        .with_context(|| format!("failed to parse {}", proof_path.display()))?;
    let report = erebus_core::log_proof::verify_proof(&receipt_bytes, &proof, log_keys)
        .context("transparency-log proof verification failed")?;
    let mut value = serde_json::to_value(&report)?;
    value["file"] = serde_json::Value::String(proof_path.display().to_string());
    value["registry"] = serde_json::Value::String(proof.registry.clone());
    value["verified"] = serde_json::Value::Bool(true);
    Ok(value)
}

pub(crate) fn parse_log_key(hex_key: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("--log-key must be 64 hex characters"))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| anyhow::anyhow!("--log-key invalid: {e}"))
}

pub(crate) fn verify_chain(
    dir: &Path,
    keys: &[VerifyingKey],
    bundle_bytes: Option<&[u8]>,
) -> Result<serde_json::Value> {
    let log = AttestationLog::open(dir)
        .with_context(|| format!("failed to open trail {}", dir.display()))?;
    let report = log
        .verify_chain(keys, bundle_bytes)
        .context("attestation chain verification failed")?;
    Ok(serde_json::json!({
        "dir": dir.display().to_string(),
        "verified": true,
        "mode": "chain",
        "count": report.count,
        "head": report.head,
        "bundle_checked": bundle_bytes.is_some(),
        "tool_linkage": serde_json::to_value(&report.linkage)?,
    }))
}

/// The `execution` block of the signed predicate (never the unsigned copy).
fn signed_execution(att: &Attestation) -> serde_json::Value {
    att.statement
        .predicate
        .get("execution")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

fn signed_subject(att: &Attestation, name: &str) -> Option<String> {
    att.statement
        .subject
        .iter()
        .find(|s| s.name == name)
        .and_then(|s| s.digest.get("sha256").cloned())
}

fn print_human(report: &serde_json::Value) {
    let s = |k: &str| {
        report
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string()
    };
    if report.get("mode").and_then(|v| v.as_str()) == Some("chain") {
        eprintln!(
            "OK: chain verified — {} receipt(s) in {}",
            report.get("count").and_then(|v| v.as_u64()).unwrap_or(0),
            s("dir")
        );
        eprintln!("  head:    {}", s("head"));
        print_linkage(&report["tool_linkage"]);
    } else {
        eprintln!("OK: attestation verified (key: {})", s("key"));
        eprintln!("  type:     {}", s("attestation_type"));
        eprintln!("  bundle:   sha256:{}", s("bundle_sha256"));
        let exec = report.get("execution").cloned().unwrap_or_default();
        let e = |k: &str| {
            exec.get(k)
                .filter(|v| !v.is_null())
                .map(|v| v.to_string().trim_matches('"').to_string())
                .unwrap_or_else(|| "-".to_string())
        };
        eprintln!("  attested: {}", e("attested_at"));
        eprintln!("  os/arch:  {}/{}", e("os"), e("arch"));
        // Proxy receipts describe an HTTP call; run receipts an exit code.
        if let Some(req) = exec.get("request").filter(|v| v.is_object()) {
            let r = |k: &str| {
                req.get(k).map_or("-".to_string(), |v| {
                    v.to_string().trim_matches('"').to_string()
                })
            };
            eprintln!(
                "  call:     {} {} → {}",
                r("method"),
                r("path"),
                r("status")
            );
            eprintln!("  request:  {}", e("input_hash"));
            eprintln!("  response: {}", e("output_hash"));
            print_tool_calls(req);
        } else {
            eprintln!("  exit:     {}", e("exit_code"));
            eprintln!("  output:   {}", e("output_hash"));
        }
        eprintln!("  prev:     {}", e("prev_attestation_hash"));
        if exec.get("rootfs_root").is_some_and(|v| !v.is_null()) {
            eprintln!("  rootfs:   {}", e("rootfs_root"));
        }
        eprintln!(
            "  format:   spec {}{}",
            s("spec_version"),
            if report.get("envelope") == Some(&serde_json::Value::Bool(true)) {
                " (DSSE envelope)"
            } else {
                " (legacy signature)"
            }
        );
    }
    if let Some(m) = report.get("machine").filter(|m| m.is_object()) {
        let ms = |k: &str| m.get(k).and_then(|v| v.as_str()).unwrap_or("?");
        eprintln!(
            "OK: machine {} — enrolled by {} at {} ({})",
            ms("machine_id"),
            ms("owner"),
            ms("registry"),
            ms("issued_at")
        );
    }
    if report.get("bundle_checked") == Some(&serde_json::Value::Bool(true)) {
        eprintln!("  bundle file matches the signed digest");
    }
    if let Some(rb) = report.get("response_body") {
        eprintln!(
            "OK: response body matches the signed digest and its {} tool call(s)",
            rb.get("tool_calls").and_then(|v| v.as_u64()).unwrap_or(0)
        );
    }
    if let Some(rb) = report.get("request_body") {
        let n = |k: &str| rb.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        eprintln!(
            "OK: request body matches the signed digest, its {} tool result(s) and {} history call(s)",
            n("tool_results"),
            n("tool_history")
        );
    }
    if let Some(lp) = report.get("log_proof") {
        print_log_proof(lp);
    }
}

/// Tool linkage of a verified trail (spec 2.1); silent when no tool was used.
fn print_linkage(l: &serde_json::Value) {
    let n = |k: &str| l.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
    let list = |k: &str| {
        l.get(k)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
    };
    let (anomalies, pending) = (list("anomalies"), list("unanswered"));
    if n("issued") == 0 && n("unlinkable") == 0 && anomalies.is_empty() && n("unverifiable") == 0 {
        return;
    }
    eprintln!(
        "  tools:   {} call(s) issued, {} answered, {} pending, {} unlinkable, {} unverifiable",
        n("issued"),
        n("answered"),
        pending.len(),
        n("unlinkable"),
        n("unverifiable")
    );
    for p in &pending {
        let f = |k: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or("-");
        let r = p.get("receipt").and_then(|v| v.as_u64()).unwrap_or(0);
        eprintln!("  pending: receipt #{r}: {} ({})", f("name"), f("id"));
    }
    for a in &anomalies {
        eprintln!("  WARNING: {}", describe_anomaly(a));
    }
    if l.get("requests_incomplete") == Some(&serde_json::Value::Bool(true)) {
        eprintln!(
            "  note:    some requests were only partially indexed; pending may be overstated"
        );
    }
}

/// Signed tool calls of a served call (spec 2.1), one line each.
fn print_tool_calls(req: &serde_json::Value) {
    let calls = req
        .get("tool_calls")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default();
    let field = |c: &serde_json::Value, k: &str| {
        c.get(k).and_then(|v| v.as_str()).unwrap_or("-").to_string()
    };
    for (i, c) in calls.iter().enumerate() {
        eprintln!(
            "  tool #{i}: {} (id {}, args {})",
            field(c, "name"),
            field(c, "id"),
            field(c, "arguments_hash")
        );
    }
    if req.get("tool_calls_incomplete") == Some(&serde_json::Value::Bool(true)) {
        eprintln!("  tools:    list may be incomplete (response not fully parsed)");
    }
}

fn print_log_proof(lp: &serde_json::Value) {
    let s = |k: &str| {
        lp.get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string()
    };
    let n = |k: &str| lp.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
    eprintln!(
        "OK: transparency log — leaf #{} of {} at {} ({})",
        n("leaf_index"),
        n("tree_size"),
        s("registry"),
        s("origin")
    );
    eprintln!("  root:     {}", s("root"));
    eprintln!(
        "  signed:   {} by log key {}",
        s("checkpoint_time"),
        s("log_key")
    );
    match lp.get("anchor").filter(|a| a.is_object()) {
        Some(a) => {
            let gen = a
                .get("gen_time")
                .and_then(|v| v.as_str())
                .unwrap_or("time not parsed");
            eprintln!(
                "  anchor:   RFC 3161 token from {} ({}; structural check only — run \
                 `openssl ts -verify` with the TSA chain for the CMS signature)",
                a.get("tsa_url").and_then(|v| v.as_str()).unwrap_or("?"),
                gen
            );
        }
        None => eprintln!("  anchor:   none (checkpoint not timestamped externally)"),
    }
}

pub(crate) fn load_trusted_keys(dir: &Path) -> Result<Vec<VerifyingKey>> {
    let mut keys = Vec::new();
    if !dir.exists() {
        return Ok(keys);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "pub") {
            let key_bytes = std::fs::read(&path)?;
            if let Ok(arr) = <[u8; 32]>::try_from(key_bytes.as_slice()) {
                if let Ok(vk) = VerifyingKey::from_bytes(&arr) {
                    keys.push(vk);
                }
            }
        }
    }
    Ok(keys)
}
