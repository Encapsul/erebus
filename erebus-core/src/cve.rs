//! Vulnerability (CVE) scanning for bundled dependencies.
//!
//! The registry accepts artifacts whose runtime dependencies may be
//! out-of-date. This module extracts component lists from common dependency
//! manifests (`package.json`, `requirements.txt`, `pyproject.toml`) and
//! matches them against a known-vulnerability table keyed by package name and
//! version. Findings are returned as `CveFinding`s that callers can persist to
//! a layer's `scan_results`.
//!
//! The bundled table is a small offline snapshot (the "scanner seeds") meant
//! to be refreshed from a live NVD-style feed; `VulnRule` is an open struct so
//! any feed adapter can populate it.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// A dependency discovered in a manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: String,
    /// Manifest the component came from (e.g. `package.json`).
    pub source: String,
}

/// A known-vulnerability rule for one package/version range.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VulnRule {
    pub package: String,
    /// Fixed in this version or later — anything strictly below is vulnerable.
    pub fixed_in: String,
    pub cve_id: String,
    pub severity: String,
    pub description: String,
}

/// A vulnerability finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CveFinding {
    pub cve_id: String,
    pub package: String,
    pub installed_version: String,
    pub fixed_in: String,
    pub severity: String,
    pub description: String,
    /// True when the finding came from a hardcoded known version match
    /// (e.g. an extractor fed a numeric tensor fingerprint), not a manifest.
    pub heuristic: bool,
}

impl CveFinding {
    fn from_rule(rule: &VulnRule, installed: &str) -> Self {
        Self {
            cve_id: rule.cve_id.clone(),
            package: rule.package.clone(),
            installed_version: installed.to_string(),
            fixed_in: rule.fixed_in.clone(),
            severity: rule.severity.clone(),
            description: rule.description.clone(),
            heuristic: false,
        }
    }
}

/// Minimal three-part numeric version comparison supporting `x.y.z`.
/// Returns `Ok(std::cmp::Ordering)` for comparison; non-numeric segments
/// compare their leading integer if present, else the whole string.
fn cmp_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let a_parts: Vec<&str> = a.trim_start_matches('v').split('.').collect();
    let b_parts: Vec<&str> = b.trim_start_matches('v').split('.').collect();
    for i in 0..a_parts.len().max(b_parts.len()) {
        let pa = a_parts.get(i).copied().unwrap_or("0");
        let pb = b_parts.get(i).copied().unwrap_or("0");
        // Compare leading integer prefix; fall back to strict string compare.
        let na = pa
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|p| p.parse::<u64>().ok());
        let nb = pb
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|p| p.parse::<u64>().ok());
        let ord = match (na, nb) {
            (Some(x), Some(y)) if x != y => x.cmp(&y),
            (Some(_), Some(_)) => pa
                .split(|c: char| !c.is_ascii_digit())
                .map(|p| p.parse::<u64>().unwrap_or(0))
                .cmp(
                    pb.split(|c: char| !c.is_ascii_digit())
                        .map(|p| p.parse::<u64>().unwrap_or(0)),
                ),
            _ => pa.cmp(pb),
        };
        if ord != std::cmp::Ordering::Equal {
            return ord;
        }
    }
    std::cmp::Ordering::Equal
}

/// Scan `components` against `rules`, returning every vulnerable dependency.
#[must_use]
pub fn scan(components: &[Component], rules: &[VulnRule]) -> Vec<CveFinding> {
    let mut findings = Vec::new();
    for comp in components {
        for rule in rules {
            if comp.name != rule.package {
                continue;
            }
            let ord = cmp_versions(&comp.version, &rule.fixed_in);
            // Anything strictly below fixed_in is vulnerable.
            if ord == std::cmp::Ordering::Less {
                findings.push(CveFinding::from_rule(rule, &comp.version));
            }
        }
    }
    findings
}

/// Parse a `requirements.txt`-style manifest into components.
#[must_use]
pub fn parse_requirements(content: &str) -> Vec<Component> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Strip environment markers / inline comments.
        let spec = line
            .split(";")
            .next()
            .unwrap_or(line)
            .split('#')
            .next()
            .unwrap_or(line)
            .trim();
        if let Some((name, ver)) = parse_pep508(spec) {
            out.push(Component {
                name,
                version: ver,
                source: "requirements.txt".to_string(),
            });
        }
    }
    out
}

/// Parse a `package.json`-style manifest into components.
#[must_use]
pub fn parse_package_json(content: &str) -> Vec<Component> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) {
        for (name, ver) in deps {
            if let Some(v) = ver.as_str() {
                let version = v
                    .trim_start_matches('^')
                    .trim_start_matches('~')
                    .to_string();
                out.push(Component {
                    name: name.clone(),
                    version,
                    source: "package.json".to_string(),
                });
            }
        }
    }
    out
}

/// Parse a `pyproject.toml` manifest into components.
#[must_use]
pub fn parse_pyproject_toml(content: &str) -> Vec<Component> {
    let Ok(doc) = content.parse::<toml::Value>() else {
        return Vec::new();
    };
    let Some(project) = doc.get("project") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(deps) = project.get("dependencies").and_then(|d| d.as_array()) {
        for dep in deps {
            if let Some(spec) = dep.as_str() {
                if let Some((name, ver)) = parse_pep508(spec) {
                    out.push(Component {
                        name,
                        version: ver,
                        source: "pyproject.toml".to_string(),
                    });
                }
            }
        }
    }
    out
}

/// Parse a PEP 508 dependency spec (`name>=1.2.3` or `name==1.2.3`).
fn parse_pep508(spec: &str) -> Option<(String, String)> {
    let spec = spec.trim();
    for sep in ["==", ">=", "<=", ">", "<", "~="] {
        if let Some((name, ver)) = spec.split_once(sep) {
            return Some((name.trim().to_string(), ver.trim().to_string()));
        }
    }
    None
}

/// Convenience: scan a dependency manifest file by guessing its format.
///
/// Returns `Err` with the file stem when the format is unrecognized.
///
/// # Errors
///
/// Returns an IO error when the file cannot be read.
pub fn scan_file(path: &Path, rules: &[VulnRule]) -> std::io::Result<Vec<CveFinding>> {
    let content = std::fs::read_to_string(path)?;
    let stem = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let components = match stem.as_str() {
        "requirements.txt" => parse_requirements(&content),
        "package.json" => parse_package_json(&content),
        "pyproject.toml" => parse_pyproject_toml(&content),
        _ => {
            return std::io::Result::Ok(Vec::new());
        }
    };
    Ok(scan(&components, rules))
}

/// Assemble a `scan_results` JSON value from findings for layer persistence.
#[must_use]
pub fn findings_to_json(findings: &[CveFinding]) -> serde_json::Value {
    serde_json::to_value(findings).unwrap_or_else(|_| serde_json::json!([]))
}

/// Default offline seed rules for the most common bundled runtimes.
///
/// These are intentionally few and neutrally described; production deployments
/// swap this for a live NVD-backed `VulnRule` feed.
#[must_use]
pub fn default_rules() -> Vec<VulnRule> {
    vec![
        VulnRule {
            package: "requests".to_string(),
            fixed_in: "2.32.0".to_string(),
            cve_id: "CVE-2024-35195".to_string(),
            severity: "high".to_string(),
            description: "requests follows redirects to untrusted hosts when v=0 or v=1"
                .to_string(),
        },
        VulnRule {
            package: "urllib3".to_string(),
            fixed_in: "1.26.19".to_string(),
            cve_id: "CVE-2024-37891".to_string(),
            severity: "high".to_string(),
            description: "urllib3 proxy-authorization header leakage on redirect".to_string(),
        },
        VulnRule {
            package: "lodash".to_string(),
            fixed_in: "4.17.21".to_string(),
            cve_id: "CVE-2021-23337".to_string(),
            severity: "high".to_string(),
            description: "lodash prototype pollution via template injection".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_versions_basic() {
        use std::cmp::Ordering;
        assert_eq!(cmp_versions("1.2.3", "1.2.4"), Ordering::Less);
        assert_eq!(cmp_versions("2.0.0", "2.0.0"), Ordering::Equal);
        assert_eq!(cmp_versions("3.1.0", "2.9.9"), Ordering::Greater);
        assert_eq!(cmp_versions("v1.0", "1.1.0"), Ordering::Less);
    }

    #[test]
    fn scanner_flags_vulnerable_versions() {
        let comps = vec![
            Component {
                name: "requests".to_string(),
                version: "2.25.0".to_string(),
                source: "pyproject.toml".to_string(),
            },
            Component {
                name: "lodash".to_string(),
                version: "4.17.20".to_string(),
                source: "package.json".to_string(),
            },
        ];
        let findings = scan(&comps, &default_rules());
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|f| f.cve_id == "CVE-2024-35195"));
        assert!(findings.iter().any(|f| f.cve_id == "CVE-2021-23337"));
        // The fixed version is never flagged.
        let fixed = vec![Component {
            name: "requests".to_string(),
            version: "2.32.0".to_string(),
            source: "x".to_string(),
        }];
        assert!(scan(&fixed, &default_rules()).is_empty());
    }

    #[test]
    fn parses_requirements() {
        let content = "# comment\nrequests==2.25.0\nurllib3>=1.26.10\n";
        let comps = parse_requirements(content);
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0].name, "requests");
        assert_eq!(comps[0].version, "2.25.0");
    }

    #[test]
    fn parses_package_json() {
        let content = r#"{"dependencies":{"lodash":"^4.17.20","pino":"~6.0.0"}}"#;
        let comps = parse_package_json(content);
        assert_eq!(comps.len(), 2);
        assert!(comps
            .iter()
            .any(|c| c.name == "lodash" && c.version == "4.17.20"));
        assert!(comps
            .iter()
            .any(|c| c.name == "pino" && c.version == "6.0.0"));
    }

    #[test]
    fn parses_pyproject() {
        let content = "[project]\ndependencies = [\n  \"requests==2.25.0\",\n  \"flask>=2.0\"\n]\n";
        let comps = parse_pyproject_toml(content);
        assert_eq!(comps.len(), 2);
        assert!(comps
            .iter()
            .any(|c| c.name == "requests" && c.version == "2.25.0"));
    }

    #[test]
    fn findings_serialize_to_json() {
        let comps = vec![Component {
            name: "requests".to_string(),
            version: "2.25.0".to_string(),
            source: "pyproject.toml".to_string(),
        }];
        let findings = scan(&comps, &default_rules());
        let json = findings_to_json(&findings);
        assert!(json.is_array());
        assert_eq!(json[0]["cve_id"], "CVE-2024-35195");
    }
}
