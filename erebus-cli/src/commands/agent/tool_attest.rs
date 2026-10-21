//! In-process tool-trail receipts for `erebus agent run`.
//!
//! Reuses [`CallRecorder`] in [`ProxyMode::Tool`] (same path as
//! `erebus attest-tool`) so each allowlisted / MCP / HTTP tool execution
//! appends one chained receipt. No subprocess spawn per call — the agent
//! signs what it actually relayed to the model.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use erebus_core::attest::AttestationTemplate;
use erebus_core::attest_log::AttestationLog;
use erebus_core::tool_exec::{self, ToolInvocation};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::super::attest_proxy::{CallRecorder, CallSummary, ProxyMode};

/// Signs one receipt per tool execution into a dedicated trail directory.
pub struct ToolAttestor {
    recorder: Arc<CallRecorder>,
}

impl ToolAttestor {
    /// Open (or create) the tool trail beside the agent trail.
    pub fn open(key_path: &Path, trail: &Path) -> Result<Self> {
        let key = erebus_core::attest::load_signing_key(key_path)
            .with_context(|| format!("cannot load tool attestation key {}", key_path.display()))?;
        let template = AttestationTemplate::for_agent_tool(&json!({
            "kind": "tool",
            "transport": "agent",
            "source": "erebus agent run",
        }))?;
        let log = AttestationLog::open(trail)
            .with_context(|| format!("cannot open tool trail {}", trail.display()))?;
        let recorder = CallRecorder::new(template, key, log).with_mode(ProxyMode::Tool);
        Ok(Self {
            recorder: Arc::new(recorder),
        })
    }

    pub fn log_dir(&self) -> &Path {
        self.recorder.log_dir()
    }

    /// Append a receipt for one executed tool (content = bytes fed to the model).
    pub fn record(
        &self,
        name: &str,
        call_id: Option<&str>,
        arguments_json: &str,
        content: &str,
        mcp_result: Option<&Value>,
    ) -> Result<PathBuf> {
        let args: Value = serde_json::from_str(arguments_json).unwrap_or(json!({}));
        let protocol = if mcp_result.is_some() { "mcp" } else { "http" };
        let invocation = tool_exec::from_agent_execution(
            protocol,
            name,
            Some(&args),
            content.as_bytes(),
            call_id,
            mcp_result,
        );
        let summary = summary_for(&invocation, arguments_json.as_bytes(), content.as_bytes());
        self.recorder
            .record(&summary)
            .with_context(|| format!("cannot write tool receipt for {name:?}"))
    }
}

/// Default tool trail next to the agent attest-log
/// (`foo.attest.d` → `foo.tools.attest.d`).
pub fn default_tool_trail(attest_log: &Path) -> PathBuf {
    let s = attest_log.as_os_str().to_string_lossy();
    if let Some(prefix) = s.strip_suffix(".attest.d") {
        PathBuf::from(format!("{prefix}.tools.attest.d"))
    } else {
        PathBuf::from(format!("{s}.tools.attest.d"))
    }
}

fn summary_for(invocation: &ToolInvocation, request: &[u8], response: &[u8]) -> CallSummary {
    CallSummary {
        method: "AGENT".to_string(),
        path: "tools/call".to_string(),
        status: Some(200),
        request_hash: line_digest(request),
        response_hash: line_digest(response),
        tool_calls: Default::default(),
        request_tools: Default::default(),
        tool_invocation: Some(invocation.clone()),
    }
}

fn line_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_trail_sits_beside_agent_log() {
        assert_eq!(
            default_tool_trail(Path::new("agent.run.attest.d")),
            PathBuf::from("agent.run.tools.attest.d")
        );
        assert_eq!(
            default_tool_trail(Path::new("/tmp/run.attest.d")),
            PathBuf::from("/tmp/run.tools.attest.d")
        );
    }
}
