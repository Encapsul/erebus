//! In-toto attestation `Statement` (in-toto Specification v1) support.
//!
//! Standardizes the attestation payload so it is structurally consumable by
//! the broader in-toto ecosystem (and, at a stretch, SLSA tooling that
//! consumes generic statements). The erebus-specific detail lives in the
//! `predicate`, and the Ed25519 signature is computed over the statement's
//! canonical bytes — the same semantic object an in-toto layout signs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// The in-toto `Statement` resource type URI.
pub const INTOTO_STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// Erebus-specific execution predicate type.
pub const EREBUS_PREDICATE_TYPE: &str = "https://erebus.dev/attestation/execution/v1";

/// A single subject the statement is about.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subject {
    pub name: String,
    /// Map of digest algorithm → hex digest (e.g. `{"sha256": "…"}`).
    pub digest: HashMap<String, String>,
}

/// An in-toto v1 Statement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InTotoStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<Subject>,
    pub predicate_type: String,
    pub predicate: serde_json::Value,
}

/// Strip a `sha256:<hex>` prefixed hash into a bare hex digest.
///
/// In-toto digests are `{"sha256": "<hex>"}`; erebus stores
/// `"sha256:<hex>"`. This normalizes the latter into the bare hex.
pub fn digest_value(prefixed: &str) -> String {
    prefixed
        .strip_prefix("sha256:")
        .unwrap_or(prefixed)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_type_is_intoto_v1() {
        assert_eq!(INTOTO_STATEMENT_TYPE, "https://in-toto.io/Statement/v1");
    }

    #[test]
    fn digest_value_strips_prefix() {
        assert_eq!(
            digest_value("sha256:abcdef"),
            "abcdef",
            "leading sha256: prefix must be removed"
        );
        assert_eq!(
            digest_value("abcdef"),
            "abcdef",
            "bare hex is passed through"
        );
    }

    #[test]
    fn statement_serializes_with_underscore_type() {
        let mut digest = HashMap::new();
        digest.insert("sha256".to_string(), "abc".to_string());
        let stmt = InTotoStatement {
            statement_type: INTOTO_STATEMENT_TYPE.to_string(),
            subject: vec![Subject {
                name: "app.erebus".to_string(),
                digest,
            }],
            predicate_type: EREBUS_PREDICATE_TYPE.to_string(),
            predicate: serde_json::json!({"ok": true}),
        };
        let json = serde_json::to_string(&stmt).unwrap();
        assert!(
            json.contains("\"_type\":\"https://in-toto.io/Statement/v1\""),
            "the in-toto field must be `_type`"
        );
        let parsed: InTotoStatement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, stmt);
    }
}
