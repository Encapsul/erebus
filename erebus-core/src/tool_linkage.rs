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
//! unaccounted for. It does not prove the tool's side effect happened; that
//! needs the tool behind an attested boundary too.
//!
//! Absence claims stay honest: when a response before the claim was signed
//! `tool_calls_incomplete` the issuing call may simply be unlisted, so the
//! finding is counted `unverifiable` instead of reported as an anomaly.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::attest::RequestInfo;
use crate::tool_calls::ToolCall;

/// Kind of a linkage finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyKind {
    ResultWithoutCall,
    HistoryWithoutCall,
    HistoryAltered,
    ResultRewritten,
    UnofferedTool,
}

/// One finding, at its first occurrence (1-based receipt position).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Anomaly {
    pub receipt: usize,
    pub kind: AnomalyKind,
    pub id: Option<String>,
    pub name: Option<String>,
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
}

impl Linker {
    pub fn new() -> Self {
        Self::default()
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

    fn issue(&mut self, call: &ToolCall, offered: Option<&[String]>) {
        if offered.is_some_and(|o| !o.contains(&call.name)) {
            self.flag(
                AnomalyKind::UnofferedTool,
                call.id.clone(),
                Some(&call.name),
            );
        }
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
        if self.seen.insert((kind, id.clone())) {
            self.report.anomalies.push(Anomaly {
                receipt: self.receipt,
                kind,
                id,
                name: name.map(str::to_string),
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
