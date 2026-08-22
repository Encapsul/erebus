//! Hot-swap: replace one file inside an existing `.erebus` binary without a
//! full rebuild.
//!
//! Reads `[stub][payload][meta][footer]`, unpacks the payload, overwrites the
//! requested file and reassembles with a fresh integrity hash. Signatures and
//! SISR delta manifests bind the old payload bytes, so they are dropped on
//! swap (the CLI surfaces a warning); encrypted binaries are refused outright.

use std::io;
use std::path::Path;

use crate::assembly::{assemble_erebus, AssemblyInput};
use crate::format::{self, Footer};

/// The three content sections of a `.erebus` file, addressed by its footer.
pub struct BinaryParts {
    pub footer: Footer,
    /// Launcher bytes: everything before `payload_offset`.
    pub stub: Vec<u8>,
    pub payload: Vec<u8>,
    pub meta_bytes: Vec<u8>,
}

impl BinaryParts {
    /// Reads stub / payload / metadata from `path`.
    ///
    /// All bounds come from the (untrusted) footer; every read goes through
    /// [`format::read_at`], which clamps to the real file length before any
    /// allocation.
    pub fn read(path: &Path) -> io::Result<Self> {
        let mut f = std::fs::File::open(path)?;
        let footer = Footer::read_from(&mut f)?;
        let stub = format::read_at(&mut f, 0, footer.payload_offset as usize)?;
        let payload =
            format::read_at(&mut f, footer.payload_offset, footer.payload_csize as usize)?;
        let meta_bytes = format::read_at(&mut f, footer.meta_offset, footer.meta_size as usize)?;
        Ok(Self {
            footer,
            stub,
            payload,
            meta_bytes,
        })
    }
}

/// Rejects absolute paths and `..` traversal in payload-relative targets.
///
/// A swapped file lands inside an extracted rootfs; a target like
/// `/etc/passwd` or `../../.ssh/authorized_keys` must never escape it.
pub fn validate_inner_path(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("target path is empty".to_string());
    }
    if target.starts_with('/') {
        return Err(format!("absolute target not allowed: {target}"));
    }
    let p = Path::new(target);
    for comp in p.components() {
        if comp == std::path::Component::ParentDir {
            return Err(format!("parent traversal not allowed: {target}"));
        }
    }
    Ok(())
}

/// Updates the size of the model layer matching `inner`, keeping metadata
/// truthful after a model swap.
///
/// Matching is suffix-based both ways because builds record the layer path
/// relative to the layer root (`models/x.gguf`) while users pass the rootfs
/// path (`app/models/x.gguf`). Returns whether an entry was updated.
pub fn update_model_layer(meta: &mut serde_json::Value, inner: &str, new_size: u64) -> bool {
    let Some(layers) = meta.get_mut("layers").and_then(|l| l.as_array_mut()) else {
        return false;
    };
    for layer in layers.iter_mut() {
        let kind_ok = layer.get("kind").and_then(|k| k.as_str()) == Some("model");
        if !kind_ok {
            continue;
        }
        let matches = layer
            .get("path")
            .and_then(|p| p.as_str())
            .is_some_and(|lp| lp == inner || lp.ends_with(inner) || inner.ends_with(lp));
        if matches {
            if let Some(obj) = layer.as_object_mut() {
                obj.insert("size".into(), serde_json::Value::from(new_size));
                return true;
            }
        }
    }
    false
}

/// Reassembles a swapped binary: same launcher, new payload/meta, no SISR
/// section, no signature.
///
/// The architecture byte of the source footer is carried over by mapping it
/// back through [`crate::assembly::resolve_arch`] (the format defines `x86_64`,
/// `aarch64` and `riscv64` today; anything unknown degrades to `x86_64`).
pub fn assemble_swapped(
    parts: &BinaryParts,
    new_payload: &[u8],
    new_meta: &[u8],
    squashfs: bool,
    out_path: &Path,
) -> io::Result<u64> {
    let arch = match parts.footer.arch {
        format::ARCH_AARCH64 => "aarch64",
        format::ARCH_RISCV64 => "riscv64",
        _ => "x86_64",
    };
    let input = AssemblyInput {
        stub_bytes: &parts.stub,
        payload: new_payload,
        meta_bytes: new_meta,
        encrypt: false,
        squashfs,
        target_arch: Some(arch),
        sisr: None,
    };
    assemble_erebus(out_path, &input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_binary(dir: &Path, payload: &[u8]) -> std::path::PathBuf {
        let out = dir.join("app.erebus");
        assemble_erebus(
            &out,
            &AssemblyInput {
                stub_bytes: b"STUB",
                payload,
                meta_bytes: br#"{"name":"t"}"#,
                encrypt: false,
                squashfs: false,
                target_arch: None,
                sisr: None,
            },
        )
        .unwrap();
        out
    }

    #[test]
    fn validate_rejects_absolute_and_traversal() {
        assert!(validate_inner_path("app/models/m.gguf").is_ok());
        assert!(validate_inner_path("/etc/passwd").is_err());
        assert!(validate_inner_path("../escape").is_err());
        assert!(validate_inner_path("a/../../b").is_err());
        assert!(validate_inner_path("").is_err());
    }

    #[test]
    fn read_roundtrips_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = build_binary(tmp.path(), b"PAYLOAD_BYTES");
        let parts = BinaryParts::read(&bin).unwrap();
        assert_eq!(parts.stub, b"STUB");
        assert_eq!(parts.payload, b"PAYLOAD_BYTES");
        assert_eq!(parts.meta_bytes, br#"{"name":"t"}"#);
        assert_eq!(parts.footer.format_version, 2);
    }

    #[test]
    fn update_model_layer_matches_by_suffix() {
        let mut meta = serde_json::json!({
            "layers": [
                { "kind": "runtime", "name": "python", "interpreter": "python" },
                { "kind": "model", "name": "m", "path": "models/agent.gguf", "size": 1 }
            ]
        });
        assert!(update_model_layer(&mut meta, "app/models/agent.gguf", 42));
        let layers = meta["layers"].as_array().unwrap();
        assert_eq!(layers[1]["size"], 42);
    }

    #[test]
    fn update_model_layer_ignores_non_model_and_missing() {
        let mut meta = serde_json::json!({
            "layers": [{ "kind": "runtime", "name": "python", "path": "models/x.gguf" }]
        });
        assert!(!update_model_layer(&mut meta, "models/x.gguf", 42));
        assert!(!update_model_layer(&mut serde_json::json!({}), "x", 1));
    }

    #[test]
    fn assemble_swapped_preserves_arch_and_drops_sig_state() {
        use crate::format::{Footer, ARCH_AARCH64};
        let tmp = tempfile::tempdir().unwrap();
        let parts = BinaryParts {
            footer: Footer {
                format_version: 3,
                arch: ARCH_AARCH64,
                flags: crate::format::FLAG_SIGNED | crate::format::FLAG_SISR,
                payload_offset: 4,
                payload_csize: 7,
                payload_usize: 0,
                payload_sha256: [0; 32],
                meta_offset: 11,
                meta_size: 13,
                sig_offset: 99,
            },
            stub: b"STUB".to_vec(),
            payload: b"OLDPLD".to_vec(),
            meta_bytes: br#"{"name":"t"}"#.to_vec(),
        };
        let out = tmp.path().join("swapped.erebus");
        assemble_swapped(&parts, b"NEWPAYLOAD", br#"{"name":"t"}"#, false, &out).unwrap();

        let data = std::fs::read(&out).unwrap();
        let mut cursor = std::io::Cursor::new(data);
        let footer = Footer::read_from(&mut cursor).unwrap();
        assert_eq!(footer.arch, ARCH_AARCH64);
        assert_eq!(footer.flags & crate::format::FLAG_SIGNED, 0);
        assert_eq!(footer.flags & crate::format::FLAG_SISR, 0);
        assert_eq!(footer.payload_csize, 10);
    }

    #[test]
    fn assemble_swapped_preserves_riscv64_arch() {
        use crate::format::{Footer, ARCH_RISCV64};
        let tmp = tempfile::tempdir().unwrap();
        let parts = BinaryParts {
            footer: Footer {
                format_version: 2,
                arch: ARCH_RISCV64,
                flags: 0,
                payload_offset: 4,
                payload_csize: 7,
                payload_usize: 0,
                payload_sha256: [0; 32],
                meta_offset: 11,
                meta_size: 13,
                sig_offset: 99,
            },
            stub: b"STUB".to_vec(),
            payload: b"OLDPLD".to_vec(),
            meta_bytes: br#"{"name":"t"}"#.to_vec(),
        };
        let out = tmp.path().join("swapped.erebus");
        assemble_swapped(&parts, b"NEWPAYLOAD", br#"{"name":"t"}"#, false, &out).unwrap();

        let data = std::fs::read(&out).unwrap();
        let mut cursor = std::io::Cursor::new(data);
        assert_eq!(Footer::read_from(&mut cursor).unwrap().arch, ARCH_RISCV64);
    }

    #[test]
    fn swapped_binary_still_parses_with_new_content() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = build_binary(tmp.path(), b"OLD");
        let mut parts = BinaryParts::read(&bin).unwrap();
        parts.footer.flags = crate::format::FLAG_SIGNED;

        let out = tmp.path().join("out.erebus");
        assemble_swapped(&parts, b"FRESH", br#"{"name":"t"}"#, false, &out).unwrap();

        let reparsed = BinaryParts::read(&out).unwrap();
        assert_eq!(reparsed.payload, b"FRESH");
        // Integrity hash must cover the new payload||meta pair.
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"FRESH");
        h.update(br#"{"name":"t"}"#);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(reparsed.footer.payload_sha256, expected);
    }
}
