//! SLSA v1 provenance for an erebus build (ROADMAP R5).
//!
//! A bundle hash proves *a* binary ran, not *which source*. `erebus build --key`
//! writes a DSSE envelope whose in-toto statement uses
//! `https://slsa.dev/provenance/v1`. The predicate names the git commit, whether
//! the tree was dirty, a digest of the source tree, the builder version and the
//! flags. `cosign verify-blob-attestation` consumes the same envelope.

use std::path::{Path, PathBuf};
use std::process::Command;

use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::dsse::{Envelope, INTOTO_PAYLOAD_TYPE};
use crate::intoto::{InTotoStatement, Subject, INTOTO_STATEMENT_TYPE};

pub const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
pub const BUILD_TYPE: &str = "https://erebus.dev/slsa/build/v1";
pub const BUILDER_ID: &str = "https://erebus.dev/builder/v1";

/// What `git` and a walk of the source directory established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFacts {
    pub commit: Option<String>,
    pub dirty: bool,
    /// `sha256:` of the sorted source tree (paths + bytes), `.git` excluded.
    pub tree_digest: String,
    pub uri: String,
}

/// Inputs that become the signed statement. The subject is the built bundle.
pub struct ProvenanceInput<'a> {
    pub source: &'a Path,
    pub subject_name: &'a str,
    pub subject_sha256: &'a str,
    pub builder_version: &'a str,
    pub flags: &'a [String],
}

/// Git commit, dirty bit, tree digest. A missing git binary or a non-repo
/// is a dirty tree with no commit: we cannot claim a clean source.
pub fn inspect_source(dir: &Path) -> SourceFacts {
    let commit = git_stdout(dir, &["rev-parse", "HEAD"]);
    let dirty = match git_stdout(dir, &["status", "--porcelain"]) {
        Some(out) => !out.is_empty() || commit.is_none(),
        None => true,
    };
    let uri = git_stdout(dir, &["remote", "get-url", "origin"])
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("file://{}", dir.display()));
    SourceFacts {
        commit,
        dirty,
        tree_digest: tree_digest(dir),
        uri,
    }
}

/// SLSA statement plus the exact JSON bytes that go in the DSSE payload.
pub fn statement(input: &ProvenanceInput<'_>) -> Result<(InTotoStatement, Vec<u8>), anyhow::Error> {
    let facts = inspect_source(input.source);
    let predicate = serde_json::json!({
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {
                "source": {
                    "uri": facts.uri,
                    "commit": facts.commit,
                    "dirty": facts.dirty,
                    "treeDigest": facts.tree_digest,
                },
                "flags": input.flags,
            },
            "internalParameters": { "builderVersion": input.builder_version },
        },
        "runDetails": {
            "builder": { "id": BUILDER_ID },
        },
    });
    let stmt = InTotoStatement {
        statement_type: INTOTO_STATEMENT_TYPE.to_string(),
        subject: vec![Subject {
            name: input.subject_name.to_string(),
            digest: std::collections::HashMap::from([(
                "sha256".to_string(),
                input
                    .subject_sha256
                    .trim_start_matches("sha256:")
                    .to_string(),
            )]),
        }],
        predicate_type: PREDICATE_TYPE.to_string(),
        predicate,
    };
    let bytes = serde_json::to_vec(&stmt)?;
    Ok((stmt, bytes))
}

/// DSSE envelope over the statement, signed by the operator key.
pub fn sign(payload: &[u8], key: &SigningKey, keyid: &str) -> Result<Envelope, anyhow::Error> {
    let mut env = Envelope::new(INTOTO_PAYLOAD_TYPE, payload);
    env.sign(key, keyid)?;
    Ok(env)
}

/// Verify the envelope and that its subject is this bundle. Returns the
/// signed source object (`commit`, `dirty`, `treeDigest`).
pub fn verify(
    envelope: &Envelope,
    keys: &[VerifyingKey],
    bundle_sha256: &str,
) -> Result<serde_json::Value, anyhow::Error> {
    envelope.verify_any(keys)?;
    let stmt: InTotoStatement = serde_json::from_slice(&envelope.payload_bytes()?)?;
    if stmt.predicate_type != PREDICATE_TYPE {
        anyhow::bail!(
            "provenance predicate is {}, not SLSA v1",
            stmt.predicate_type
        );
    }
    let want = bundle_sha256.trim_start_matches("sha256:");
    let got = stmt
        .subject
        .first()
        .and_then(|s| s.digest.get("sha256"))
        .map(String::as_str)
        .unwrap_or("");
    if got != want {
        anyhow::bail!("TAMPERED: provenance subject sha256:{got} is not the bundle sha256:{want}");
    }
    Ok(stmt.predicate["buildDefinition"]["externalParameters"]["source"].clone())
}

fn git_stdout(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn tree_digest(dir: &Path) -> String {
    let mut files = Vec::new();
    collect_files(dir, &mut files);
    files.sort();
    let mut hasher = Sha256::new();
    for path in files {
        let rel = path.strip_prefix(dir).unwrap_or(&path);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update([0]);
        if let Ok(bytes) = std::fs::read(&path) {
            hasher.update(bytes);
        }
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .is_some_and(|n| n == ".git" || n == "target")
        {
            continue;
        }
        if path.is_dir() {
            collect_files(&path, out);
        } else if path.is_file() {
            out.push(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirty_tree_is_in_the_signed_predicate() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("app.py"), b"print(1)").unwrap();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let flags = vec!["--isolation=sandbox".to_string()];
        let (_stmt, payload) = statement(&ProvenanceInput {
            source: dir.path(),
            subject_name: "app.erebus",
            subject_sha256: "ab",
            builder_version: "erebus-cli 0.6.1",
            flags: &flags,
        })
        .unwrap();
        let env = sign(&payload, &key, "test").unwrap();
        let source = verify(&env, &[key.verifying_key()], "ab").unwrap();
        assert_eq!(source["dirty"], true);
        assert!(source["commit"].is_null());
        assert!(source["treeDigest"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[test]
    fn subject_mismatch_is_tampered() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"a").unwrap();
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let (_s, payload) = statement(&ProvenanceInput {
            source: dir.path(),
            subject_name: "a.erebus",
            subject_sha256: "aa",
            builder_version: "t",
            flags: &[],
        })
        .unwrap();
        let env = sign(&payload, &key, "k").unwrap();
        let err = verify(&env, &[key.verifying_key()], "bb").unwrap_err();
        assert!(err.to_string().contains("TAMPERED"));
    }
}
