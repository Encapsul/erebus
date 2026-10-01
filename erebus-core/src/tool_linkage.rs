//! Cross-receipt linkage of tool calls along a verified trail (spec 2.1).
//!
//! A receipt signs what the engine returned (`tool_calls`) and what the
//! agent sent with the request (`tool_history`, `tool_results`,
//! `tools_offered`). Walking the trail in chain order links them by call id:
//!
//! - a result for an id the engine never issued in this trail is an
//!   injected result (`result_without_call`);
//! - replayed history whose name or arguments differ from the signed call is
//!   a rewritten conversation (`history_altered`); history for an id never
//!   issued is `history_without_call`;
//! - a second, different result for the same id is `result_rewritten`;
//! - a call to a tool the request did not offer is `unoffered_tool`.
//!
//! What this proves: the agent reported back, for call X, exactly the
//! content whose digest is signed, and nothing it fed the model is
//! unaccounted for. Alone it does not prove the tool ran.
//!
//! With the receipts of an attested tool boundary (`erebus attest-tool`,
//! `with_executions`), each issued call is matched one-to-one, in chain
//! order, to a tool execution with the same name and canonical arguments:
//!
//! - a result fed back for a call no tool executed is
//!   `result_without_execution`;
//! - a result whose digest is not one the tool returned is
//!   `result_not_from_tool`;
//! - a tool execution no issued call accounts for is
//!   `execution_without_call`.
//!
//! Absence claims stay honest: when a response before the claim was signed
//! `tool_calls_incomplete` the issuing call may simply be unlisted, so the
//! finding is counted `unverifiable` instead of reported as an anomaly.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::attest::RequestInfo;
use crate::tool_calls::ToolCall;
use crate::tool_exec::ToolInvocation;

/// Kind of a linkage finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    ResultWithoutCall,
    HistoryWithoutCall,
    HistoryAltered,
    ResultRewritten,
    UnofferedTool,
    /// With tool trails: a result was fed back for a call no attested tool
    /// executed.
    ResultWithoutExecution,
    /// With tool trails: the result fed back is none of the forms the tool
    /// returned (fabricated, or transformed by the agent).
    ResultNotFromTool,
    /// With tool trails: a tool executed a call the engine never issued.
    ExecutionWithoutCall,
}

impl AnomalyKind {
    /// Findings that need tool trails (`--require-tool-execution`).
    pub fn is_execution(self) -> bool {
        matches!(
            self,
            Self::ResultWithoutExecution | Self::ResultNotFromTool | Self::ExecutionWithoutCall
        )
    }
}

/// One finding, at its first occurrence (1-based receipt position in the
/// agent trail; `tool_receipt` in the tool trails for execution findings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Anomaly {
    pub receipt: usize,
    pub kind: AnomalyKind,
    pub id: Option<String>,
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_receipt: Option<usize>,
}

/// A tool receipt to match against the calls the engine issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecution {
    /// 1-based position across the tool trails, in the order given.
    pub receipt: usize,
    pub invocation: ToolInvocation,
}

/// Execution summary when tool trails were given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ExecutionReport {
    pub tool_receipts: usize,
    /// Issued calls matched one-to-one to a tool receipt with the same name
    /// and canonical arguments.
    pub executed: usize,
    /// Executed calls whose fed-back result is one of the tool's result forms.
    pub verbatim: usize,
    /// Issued calls no tool receipt matches.
    pub not_executed: usize,
    /// Calls or tool receipts without canonical arguments (non-JSON, partial
    /// extraction): cannot be matched either way.
    pub unverifiable: usize,
}

/// A call the engine issued whose result never came back in the trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PendingCall {
    pub receipt: usize,
    pub id: String,
    pub name: String,
}

/// Linkage summary of a trail.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LinkageReport {
    /// Calls the engine issued with an id.
    pub issued: usize,
    /// Issued calls without an id (legacy `function_call`): not linkable.
    pub unlinkable: usize,
    /// Issued calls whose result came back later in the trail.
    pub answered: usize,
    pub unanswered: Vec<PendingCall>,
    pub anomalies: Vec<Anomaly>,
    /// Missing-call findings not provable because an earlier response was
    /// only partially indexed.
    pub unverifiable: usize,
    /// Some request was only partially indexed: `unanswered` may list calls
    /// whose result was in fact sent.
    pub requests_incomplete: bool,
    /// Present when tool trails were linked (`--tool-trail`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution: Option<ExecutionReport>,
}

struct Issued {
    receipt: usize,
    calls: Vec<ToolCall>,
    result: Option<String>,
}

/// Feed signed requests in chain order, then [`Linker::finish`].
#[derive(Default)]
pub struct Linker {
    issued: BTreeMap<String, Issued>,
    seen: BTreeSet<(AnomalyKind, Option<String>)>,
    unverifiable: BTreeSet<String>,
    responses_incomplete: bool,
    receipt: usize,
    report: LinkageReport,
    /// Every issued call in chain order, with its receipt position.
    instances: Vec<(usize, ToolCall)>,
    executions: Option<Vec<ToolExecution>>,
}

impl Linker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Tool receipts to match issued calls against; calling it (even with an
    /// empty list) turns the execution checks on.
    pub fn with_executions(mut self, executions: Vec<ToolExecution>) -> Self {
        self.executions = Some(executions);
        self
    }

    /// Next receipt of the trail; `None` for receipts that are not served
    /// calls (they still count for positions).
    pub fn push(&mut self, request: Option<&RequestInfo>) {
        self.receipt = self.receipt.saturating_add(1);
        let Some(req) = request else {
            return;
        };
        // The request is what the agent sent *before* this response.
        for h in req.tool_history.iter().flatten() {
            self.history(h);
        }
        for r in req.tool_results.iter().flatten() {
            self.result(&r.id, &r.content_hash);
        }
        self.report.requests_incomplete |= req.request_tools_incomplete;
        for c in req.tool_calls.iter().flatten() {
            self.issue(c, req.tools_offered.as_deref());
        }
        self.responses_incomplete |= req.tool_calls_incomplete;
    }

    pub fn finish(mut self) -> LinkageReport {
        if let Some(executions) = self.executions.take() {
            self.report.execution = Some(self.match_executions(&executions));
        }
        for (id, issued) in &self.issued {
            match issued.result {
                Some(_) => self.report.answered = self.report.answered.saturating_add(1),
                None => self.report.unanswered.push(PendingCall {
                    receipt: issued.receipt,
                    id: id.clone(),
                    name: issued
                        .calls
                        .first()
                        .map(|c| c.name.clone())
                        .unwrap_or_default(),
                }),
            }
        }
        self.report.unanswered.sort_by_key(|p| p.receipt);
        self.report.unverifiable = self.unverifiable.len();
        self.report
    }

    /// Match issued calls one-to-one, in chain order, to tool receipts with
    /// the same canonical arguments and name (an unnamed HTTP tool matches
    /// on arguments alone), then check each fed-back result.
    fn match_executions(&mut self, executions: &[ToolExecution]) -> ExecutionReport {
        let mut out = ExecutionReport {
            tool_receipts: executions.len(),
            ..ExecutionReport::default()
        };
        let mut used = vec![false; executions.len()];
        for (receipt, call) in std::mem::take(&mut self.instances) {
            let Some(want) = call.arguments_jcs_hash.as_deref() else {
                out.unverifiable = out.unverifiable.saturating_add(1);
                continue;
            };
            let found = executions.iter().enumerate().position(|(i, e)| {
                !used[i]
                    && e.invocation.arguments_jcs_hash.as_deref() == Some(want)
                    && e.invocation.name.as_deref().is_none_or(|n| n == call.name)
            });
            match found {
                Some(i) => {
                    used[i] = true;
                    out.executed = out.executed.saturating_add(1);
                    if self.result_is_verbatim(&call, &executions[i], receipt) {
                        out.verbatim = out.verbatim.saturating_add(1);
                    }
                }
                None => {
                    out.not_executed = out.not_executed.saturating_add(1);
                    self.check_unexecuted_result(&call, receipt);
                }
            }
        }
        for (e, _) in executions.iter().zip(&used).filter(|(_, u)| !**u) {
            if e.invocation.arguments_jcs_hash.is_none() || self.responses_incomplete {
                out.unverifiable = out.unverifiable.saturating_add(1);
            } else {
                let id = Some(format!("tool#{}", e.receipt));
                let kind = AnomalyKind::ExecutionWithoutCall;
                self.flag_at(0, kind, id, e.invocation.name.as_deref(), Some(e.receipt));
            }
        }
        out
    }

    /// The fed-back result of `call`, if any.
    fn result_of(&self, call: &ToolCall) -> Option<String> {
        self.issued.get(call.id.as_deref()?)?.result.clone()
    }

    /// `true` when the result fed back for `call` is one of the forms the
    /// tool returned; a different result is flagged.
    fn result_is_verbatim(
        &mut self,
        call: &ToolCall,
        exec: &ToolExecution,
        receipt: usize,
    ) -> bool {
        let Some(result) = self.result_of(call) else {
            return false;
        };
        if exec.invocation.result_hashes.contains(&result) {
            return true;
        }
        let kind = AnomalyKind::ResultNotFromTool;
        self.flag_at(
            receipt,
            kind,
            call.id.clone(),
            Some(&call.name),
            Some(exec.receipt),
        );
        false
    }

    fn check_unexecuted_result(&mut self, call: &ToolCall, receipt: usize) {
        if self.result_of(call).is_some() {
            let kind = AnomalyKind::ResultWithoutExecution;
            self.flag_at(receipt, kind, call.id.clone(), Some(&call.name), None);
        }
    }

    fn issue(&mut self, call: &ToolCall, offered: Option<&[String]>) {
        if offered.is_some_and(|o| !o.contains(&call.name)) {
            self.flag(
                AnomalyKind::UnofferedTool,
                call.id.clone(),
                Some(&call.name),
            );
        }
        self.instances.push((self.receipt, call.clone()));
        let Some(id) = call.id.clone() else {
            self.report.unlinkable = self.report.unlinkable.saturating_add(1);
            return;
        };
        self.report.issued = self.report.issued.saturating_add(1);
        let receipt = self.receipt;
        let entry = self.issued.entry(id).or_insert_with(|| Issued {
            receipt,
            calls: Vec::new(),
            result: None,
        });
        entry.calls.push(call.clone());
    }

    fn history(&mut self, h: &ToolCall) {
        let Some(id) = &h.id else {
            return; // legacy history has no id to link
        };
        let matches = self.issued.get(id).map(|i| {
            i.calls
                .iter()
                .any(|c| c.name == h.name && c.arguments_hash == h.arguments_hash)
        });
        match matches {
            Some(true) => {}
            Some(false) => self.flag(AnomalyKind::HistoryAltered, Some(id.clone()), Some(&h.name)),
            None => self.missing(AnomalyKind::HistoryWithoutCall, id, Some(&h.name)),
        }
    }

    fn result(&mut self, id: &str, content_hash: &str) {
        let Some(issued) = self.issued.get_mut(id) else {
            self.missing(AnomalyKind::ResultWithoutCall, id, None);
            return;
        };
        // An id issued twice (engines reusing `call_0`) has two legitimate
        // results: only a single-issue id can prove a rewrite.
        let rewritten = issued.calls.len() == 1
            && issued
                .result
                .as_deref()
                .is_some_and(|prev| prev != content_hash);
        if issued.result.is_none() {
            issued.result = Some(content_hash.to_string());
        }
        if rewritten {
            let name = issued.calls.first().map(|c| c.name.clone());
            self.flag(
                AnomalyKind::ResultRewritten,
                Some(id.to_string()),
                name.as_deref(),
            );
        }
    }

    fn missing(&mut self, kind: AnomalyKind, id: &str, name: Option<&str>) {
        if self.responses_incomplete {
            self.unverifiable.insert(id.to_string());
        } else {
            self.flag(kind, Some(id.to_string()), name);
        }
    }

    /// Record a finding once: history and results are replayed every turn.
    fn flag(&mut self, kind: AnomalyKind, id: Option<String>, name: Option<&str>) {
        self.flag_at(self.receipt, kind, id, name, None);
    }

    fn flag_at(
        &mut self,
        receipt: usize,
        kind: AnomalyKind,
        id: Option<String>,
        name: Option<&str>,
        tool_receipt: Option<usize>,
    ) {
        if self.seen.insert((kind, id.clone())) {
            self.report.anomalies.push(Anomaly {
                receipt,
                kind,
                id,
                name: name.map(str::to_string),
                tool_receipt,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_requests::ToolResult;

    fn call(id: &str, name: &str, args: &str) -> ToolCall {
        ToolCall {
            choice: 0,
            id: Some(id.to_string()),
            name: name.to_string(),
            arguments_hash: format!("sha256:{args}"),
            arguments_jcs_hash: Some(format!("sha256:jcs-{args}")),
        }
    }

    fn result(id: &str, content: &str) -> ToolResult {
        ToolResult {
            id: id.to_string(),
            content_hash: format!("sha256:{content}"),
        }
    }

    fn turn(
        history: Vec<ToolCall>,
        results: Vec<ToolResult>,
        returned: Vec<ToolCall>,
    ) -> RequestInfo {
        RequestInfo {
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            status: Some(200),
            tools_offered: Some(vec!["get_weather".into(), "send_email".into()]),
            tool_history: Some(history).filter(|v| !v.is_empty()),
            tool_results: Some(results).filter(|v| !v.is_empty()),
            tool_calls: Some(returned).filter(|v| !v.is_empty()),
            ..RequestInfo::default()
        }
    }

    fn link(turns: &[RequestInfo]) -> LinkageReport {
        let mut l = Linker::new();
        for t in turns {
            l.push(Some(t));
        }
        l.finish()
    }

    fn kinds(r: &LinkageReport) -> Vec<(usize, AnomalyKind)> {
        r.anomalies.iter().map(|a| (a.receipt, a.kind)).collect()
    }

    #[test]
    fn an_honest_agent_loop_links_every_call_to_its_result() {
        let w = call("call_w", "get_weather", "a1");
        let e = call("call_e", "send_email", "a2");
        let r = link(&[
            turn(vec![], vec![], vec![w.clone()]),
            turn(
                vec![w.clone()],
                vec![result("call_w", "18C")],
                vec![e.clone()],
            ),
            // full history replayed, as OpenAI clients do
            turn(
                vec![w, e],
                vec![result("call_w", "18C"), result("call_e", "sent")],
                vec![],
            ),
        ]);
        assert!(r.anomalies.is_empty(), "{r:?}");
        assert_eq!((r.issued, r.answered, r.unverifiable), (2, 2, 0));
        assert!(r.unanswered.is_empty());
    }

    #[test]
    fn a_result_for_a_call_never_issued_is_an_injection() {
        let r = link(&[
            turn(vec![], vec![], vec![call("call_w", "get_weather", "a1")]),
            turn(vec![], vec![result("call_evil", "x")], vec![]),
        ]);
        assert_eq!(kinds(&r), vec![(2, AnomalyKind::ResultWithoutCall)]);
        assert_eq!(r.unanswered[0].id, "call_w");
    }

    #[test]
    fn rewritten_history_is_caught_even_when_the_id_matches() {
        let r = link(&[
            turn(vec![], vec![], vec![call("call_w", "get_weather", "a1")]),
            turn(
                vec![call("call_w", "get_weather", "FORGED")],
                vec![],
                vec![],
            ),
            turn(vec![call("call_w", "send_email", "a1")], vec![], vec![]),
            turn(vec![call("call_x", "send_email", "a1")], vec![], vec![]),
        ]);
        assert_eq!(
            kinds(&r),
            vec![
                (2, AnomalyKind::HistoryAltered),
                (4, AnomalyKind::HistoryWithoutCall)
            ]
        );
    }

    #[test]
    fn a_result_changed_after_the_fact_is_caught_once() {
        let w = call("call_w", "get_weather", "a1");
        let r = link(&[
            turn(vec![], vec![], vec![w.clone()]),
            turn(vec![w.clone()], vec![result("call_w", "18C")], vec![]),
            turn(vec![w.clone()], vec![result("call_w", "35C")], vec![]),
            turn(vec![w], vec![result("call_w", "35C")], vec![]),
        ]);
        assert_eq!(kinds(&r), vec![(3, AnomalyKind::ResultRewritten)]);
    }

    #[test]
    fn calls_to_tools_the_request_never_offered_are_flagged() {
        let r = link(&[turn(vec![], vec![], vec![call("c", "rm_rf", "a")])]);
        assert_eq!(kinds(&r), vec![(1, AnomalyKind::UnofferedTool)]);
        let mut no_list = turn(vec![], vec![], vec![call("c", "rm_rf", "a")]);
        no_list.tools_offered = None;
        assert!(link(&[no_list]).anomalies.is_empty());
    }

    #[test]
    fn reused_ids_never_produce_a_false_rewrite() {
        let a = call("call_0", "get_weather", "a1");
        let b = call("call_0", "get_weather", "a2");
        let r = link(&[
            turn(vec![], vec![], vec![a.clone()]),
            turn(
                vec![a.clone()],
                vec![result("call_0", "18C")],
                vec![b.clone()],
            ),
            turn(vec![b], vec![result("call_0", "9C")], vec![]),
        ]);
        assert!(r.anomalies.is_empty(), "{r:?}");
    }

    #[test]
    fn missing_calls_after_a_partial_response_are_unverifiable_not_accused() {
        let mut partial = turn(vec![], vec![], vec![]);
        partial.tool_calls_incomplete = true;
        let r = link(&[partial, turn(vec![], vec![result("call_q", "x")], vec![])]);
        assert!(r.anomalies.is_empty());
        assert_eq!(r.unverifiable, 1);
    }

    fn exec(receipt: usize, name: Option<&str>, args: &str, result: &str) -> ToolExecution {
        ToolExecution {
            receipt,
            invocation: ToolInvocation {
                protocol: if name.is_some() { "mcp" } else { "http" }.into(),
                name: name.map(str::to_string),
                arguments_jcs_hash: Some(format!("sha256:jcs-{args}")),
                result_hashes: vec![format!("sha256:{result}")],
                ..ToolInvocation::default()
            },
        }
    }

    fn link_with(turns: &[RequestInfo], executions: Vec<ToolExecution>) -> LinkageReport {
        let mut l = Linker::new().with_executions(executions);
        for t in turns {
            l.push(Some(t));
        }
        l.finish()
    }

    fn agent_loop(result: &str) -> Vec<RequestInfo> {
        let w = call("call_w", "get_weather", "a1");
        vec![
            turn(vec![], vec![], vec![w.clone()]),
            turn(vec![w], vec![result_of("call_w", result)], vec![]),
        ]
    }

    fn result_of(id: &str, content: &str) -> ToolResult {
        result(id, content)
    }

    #[test]
    fn an_executed_call_with_the_tools_own_answer_is_proven_end_to_end() {
        let r = link_with(
            &agent_loop("18C"),
            vec![exec(1, Some("get_weather"), "a1", "18C")],
        );
        assert!(r.anomalies.is_empty(), "{r:?}");
        let e = r.execution.unwrap();
        assert_eq!(
            (e.tool_receipts, e.executed, e.verbatim, e.not_executed),
            (1, 1, 1, 0)
        );
    }

    #[test]
    fn a_result_no_tool_produced_is_caught() {
        // The agent never called the tool but fed a result back.
        let r = link_with(&agent_loop("18C"), vec![]);
        assert_eq!(kinds(&r), vec![(1, AnomalyKind::ResultWithoutExecution)]);
        // The tool ran with other arguments: not this call.
        let r = link_with(
            &agent_loop("18C"),
            vec![exec(1, Some("get_weather"), "a2", "18C")],
        );
        let k: Vec<_> = r.anomalies.iter().map(|a| a.kind).collect();
        assert_eq!(
            k,
            vec![
                AnomalyKind::ResultWithoutExecution,
                AnomalyKind::ExecutionWithoutCall
            ]
        );
        assert_eq!(r.anomalies[1].tool_receipt, Some(1));
    }

    #[test]
    fn a_result_other_than_the_tools_answer_is_caught() {
        let r = link_with(
            &agent_loop("35C"),
            vec![exec(4, Some("get_weather"), "a1", "18C")],
        );
        assert_eq!(kinds(&r), vec![(1, AnomalyKind::ResultNotFromTool)]);
        assert_eq!(r.anomalies[0].tool_receipt, Some(4));
        assert_eq!(r.execution.unwrap().verbatim, 0);
    }

    #[test]
    fn executions_match_one_to_one_and_unnamed_http_tools_on_arguments() {
        let w = call("call_1", "get_weather", "a1");
        let w2 = call("call_2", "get_weather", "a1");
        let turns = vec![turn(vec![], vec![], vec![w, w2])];
        let r = link_with(&turns, vec![exec(1, None, "a1", "x")]);
        let e = r.execution.unwrap();
        assert_eq!(
            (e.executed, e.not_executed),
            (1, 1),
            "one receipt proves one call"
        );
        assert!(r.anomalies.is_empty());
        // A tool receipt for another tool name never matches.
        let r = link_with(&turns, vec![exec(1, Some("send_email"), "a1", "x")]);
        assert_eq!(r.execution.unwrap().executed, 0);
        assert_eq!(r.anomalies[0].kind, AnomalyKind::ExecutionWithoutCall);
    }

    #[test]
    fn without_tool_trails_no_execution_claim_is_made() {
        let r = link(&agent_loop("18C"));
        assert!(r.execution.is_none() && r.anomalies.is_empty());
    }

    #[test]
    fn non_served_receipts_keep_positions() {
        let mut l = Linker::new();
        l.push(None);
        l.push(Some(&turn(vec![], vec![result("ghost", "x")], vec![])));
        assert_eq!(
            kinds(&l.finish()),
            vec![(2, AnomalyKind::ResultWithoutCall)]
        );
    }
}
