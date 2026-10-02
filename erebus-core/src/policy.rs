//! Launch policy checked before exec (ROADMAP P2).
//!
//! A short YAML subset — four keys, no anchors — so the stub and `erebus run`
//! share one parser without a YAML crate:
//!
//! ```text
//! signer:
//!   - sha256:<fingerprint>
//! models:
//!   - sha256:<layer>
//! min_isolation: 2
//! require_receipt: true
//! ```

use std::path::Path;

use crate::format::{self, Footer};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub signers: Vec<String>,
    pub models: Vec<String>,
    pub min_isolation: Option<u32>,
    pub require_receipt: bool,
}

impl Policy {
    pub fn parse(text: &str) -> Result<Self, anyhow::Error> {
        let mut policy = Self::default();
        let mut section = "";
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("- ") {
                push_item(&mut policy, section, rest.trim())?;
                continue;
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("policy: expected key: value, got {line}"))?;
            section = match key.trim() {
                "signer" => {
                    push_scalar(&mut policy.signers, value);
                    "signer"
                }
                "models" => {
                    push_scalar(&mut policy.models, value);
                    "models"
                }
                "min_isolation" => {
                    policy.min_isolation = Some(parse_u32(value.trim())?);
                    ""
                }
                "require_receipt" => {
                    policy.require_receipt = parse_bool(value.trim())?;
                    ""
                }
                other => anyhow::bail!("policy: unknown key {other}"),
            };
        }
        Ok(policy)
    }
}

fn push_scalar(into: &mut Vec<String>, value: &str) {
    let value = value.trim().trim_matches('"');
    if !value.is_empty() {
        into.push(value.to_string());
    }
}

fn push_item(policy: &mut Policy, section: &str, value: &str) -> Result<(), anyhow::Error> {
    match section {
        "signer" => policy.signers.push(value.to_string()),
        "models" => policy.models.push(value.to_string()),
        _ => anyhow::bail!("policy: list item outside signer/models"),
    }
    Ok(())
}

fn parse_u32(v: &str) -> Result<u32, anyhow::Error> {
    v.parse()
        .map_err(|_| anyhow::anyhow!("policy: min_isolation must be an integer"))
}

fn parse_bool(v: &str) -> Result<bool, anyhow::Error> {
    match v {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => anyhow::bail!("policy: require_receipt must be true or false"),
    }
}

/// Refuse to launch when metadata carries a `launch_policy` the bundle breaks.
/// No field means no policy: existing bundles keep launching.
pub fn enforce_embedded(bundle: &Path) -> Result<(), anyhow::Error> {
    let meta = bundle_meta(bundle)?;
    let Some(text) = meta.get("launch_policy").and_then(|v| v.as_str()) else {
        return Ok(());
    };
    if text.is_empty() {
        return Ok(());
    }
    enforce(bundle, &Policy::parse(text)?)
}

/// Refuse to launch when the bundle breaks the policy.
pub fn enforce(bundle: &Path, policy: &Policy) -> Result<(), anyhow::Error> {
    let meta = bundle_meta(bundle)?;
    if !policy.signers.is_empty() {
        let mut f = std::fs::File::open(bundle)?;
        if !Footer::read_from(&mut f)?.is_signed() {
            anyhow::bail!("policy: signer allowlist set but the bundle is unsigned");
        }
    }
    if let Some(min) = policy.min_isolation {
        let got = meta.get("isolation").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        if got < min {
            anyhow::bail!("policy: isolation {got} is below min_isolation {min}");
        }
    }
    if !policy.models.is_empty() {
        check_models(&meta, &policy.models)?;
    }
    if policy.require_receipt && !receipt_present(bundle) {
        anyhow::bail!("policy: require_receipt set and no receipt trail exists");
    }
    Ok(())
}

fn check_models(meta: &serde_json::Value, allow: &[String]) -> Result<(), anyhow::Error> {
    let layers = meta.get("layers").and_then(|v| v.as_array());
    let Some(layers) = layers else {
        anyhow::bail!("policy: model allowlist set but the bundle has no layers");
    };
    for layer in layers {
        if layer.get("kind").and_then(|v| v.as_str()) != Some("model") {
            continue;
        }
        let sha = layer
            .get("sha256")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if !allow
            .iter()
            .any(|a| a.trim_start_matches("sha256:") == sha.trim_start_matches("sha256:"))
        {
            anyhow::bail!("policy: model layer {sha} is not in the allowlist");
        }
    }
    Ok(())
}

fn receipt_present(bundle: &Path) -> bool {
    let mut attest = bundle.as_os_str().to_owned();
    attest.push(".attest");
    if Path::new(&attest).is_file() {
        return true;
    }
    let mut trail = bundle.as_os_str().to_owned();
    trail.push(".attest.d");
    Path::new(&trail).is_dir()
}

fn bundle_meta(bundle: &Path) -> Result<serde_json::Value, anyhow::Error> {
    let mut f = std::fs::File::open(bundle)?;
    let footer = Footer::read_from(&mut f)?;
    let bytes = format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_policy_refuses_before_exec() {
        let dir = tempfile::tempdir().unwrap();
        let low = pack(dir.path(), 0, Some("min_isolation: 2\n"));
        let err = enforce_embedded(&low).unwrap_err().to_string();
        assert!(err.contains("min_isolation"), "{err}");
        let ok = pack(dir.path(), 2, Some("min_isolation: 2\n"));
        enforce_embedded(&ok).unwrap();
        let bare = pack(dir.path(), 0, None);
        enforce_embedded(&bare).unwrap();
    }

    fn pack(dir: &std::path::Path, isolation: u32, policy: Option<&str>) -> std::path::PathBuf {
        use crate::assembly::{assemble_erebus, AssemblyInput};
        use crate::tar::create_tar_zstd_with_level;
        let rootfs = dir.join(format!("root-{isolation}"));
        std::fs::create_dir_all(rootfs.join("app")).unwrap();
        std::fs::write(rootfs.join("app/main.py"), "print(1)").unwrap();
        let payload = create_tar_zstd_with_level(&rootfs, 3).unwrap();
        let mut meta = serde_json::json!({
            "name": "p", "runtime": "python", "isolation": isolation,
            "entrypoint": ["python3", "app.py"],
        });
        if let Some(text) = policy {
            meta["launch_policy"] = serde_json::json!(text);
        }
        let bin = dir.join(format!("p-{isolation}-{}.erebus", policy.is_some()));
        let bytes = serde_json::to_vec(&meta).unwrap();
        assemble_erebus(
            &bin,
            &AssemblyInput {
                stub_bytes: b"STUB",
                payload: &payload,
                meta_bytes: &bytes,
                encrypt: false,
                squashfs: false,
                target_arch: None,
                sisr: None,
            },
        )
        .unwrap();
        bin
    }

    #[test]
    fn parses_and_rejects_low_isolation() {
        let text = "min_isolation: 2\nrequire_receipt: false\nmodels:\n  - sha256:abc\n";
        let policy = Policy::parse(text).unwrap();
        assert_eq!(policy.min_isolation, Some(2));
        assert_eq!(policy.models, vec!["sha256:abc".to_string()]);
        assert!(!policy.require_receipt);
    }
}
