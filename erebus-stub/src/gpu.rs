//! GPU discovery and `-ngl` auto-tuning for llama.cpp-style inference apps.
//!
//! The stub cannot know the target machine at build time, so detection runs
//! at launch and exports advisory env vars that packaged agents consume:
//!
//! - `ERE_GPU`     — vendor hint: `nvidia` | `amd` | `metal` | `none`
//! - `ERE_VRAM_MB` — total VRAM when queryable (`nvidia-smi`)
//! - `ERE_NGL`     — suggested `--n-gpu-layers` value (see [`auto_ngl`])
//!
//! Keys already present in the payload environment (pinned via
//! `erebus build --ngl off|N`) are never overridden — pins win over probes.

use crate::Metadata;
use std::collections::BTreeMap;
use std::process::Command;

/// Export GPU facts into `env`, filling only keys the payload didn't pin.
pub fn apply(env: &mut BTreeMap<String, String>, meta: &Metadata) {
    let model_mb = model_bytes(meta) / (1024 * 1024);
    apply_with(env, model_mb);
}

pub(crate) fn apply_with(env: &mut BTreeMap<String, String>, model_mb: u64) {
    if !env.contains_key("ERE_GPU") {
        match detect_vendor() {
            Some((vendor, vram_mb)) => {
                env.insert("ERE_GPU".into(), vendor.into());
                if let Some(mb) = vram_mb {
                    env.entry("ERE_VRAM_MB".to_owned())
                        .or_insert_with(|| mb.to_string());
                    // Pinned NGL wins; probe only fills the gap.
                    env.entry("ERE_NGL".to_owned())
                        .or_insert_with(|| auto_ngl(mb, model_mb).to_string());
                }
            }
            None => {
                env.insert("ERE_GPU".into(), "none".into());
            }
        }
    }
}

/// Vendor probe, cheapest checks first. `None` means no accelerator found.
fn detect_vendor() -> Option<(&'static str, Option<u64>)> {
    if let Some(mb) = nvidia_vram_mb() {
        return Some(("nvidia", Some(mb)));
    }
    // Every Apple Silicon Mac has unified memory; llama.cpp builds with
    // Metal enabled offload eagerly, so just advertise it.
    if cfg!(target_os = "macos") {
        return Some(("metal", None));
    }
    // ROCm-capable AMD GPUs expose /dev/kfd; querying VRAM needs rocm-smi
    // which is rarely installed — leave NGL to the app or a pin.
    if std::path::Path::new("/dev/kfd").exists() {
        return Some(("amd", None));
    }
    None
}

/// Total VRAM (MB) across the first GPU reported by nvidia-smi.
///
/// A missing binary fails fast (ENOENT ≈ µs), so probing on CPU-only hosts
/// is effectively free.
fn nvidia_vram_mb() -> Option<u64> {
    let out = Command::new("nvidia-smi")
        .args(["--query-gpu=memory.total", "--format=csv,noheader,nounits"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mb: u64 = stdout.lines().next()?.trim().parse().ok()?;
    (mb > 0).then_some(mb)
}

/// Suggested `--n-gpu-layers`: saturates toward full offload as VRAM covers
/// the model. `100 × vram/model` reaches typical layer counts (~32-80) once
/// free VRAM is roughly the model size, and caps at llama.cpp's max (999).
///
/// This is deliberately conservative: GGUF Q4 overhead means the last layers
/// may still spill to CPU, which llama.cpp handles gracefully.
pub(crate) fn auto_ngl(vram_mb: u64, model_mb: u64) -> u32 {
    let ratio = vram_mb.saturating_mul(100) / model_mb.max(1);
    ratio.min(999) as u32
}

/// Sum of embedded model-layer sizes (bytes).
fn model_bytes(meta: &Metadata) -> u64 {
    meta.layers
        .iter()
        .map(|layer| match layer {
            erebus_core::layer::SerializableLayer::Model(m) => m.size,
            _ => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn auto_ngl_saturates_when_vram_covers_model() {
        assert_eq!(auto_ngl(80_000, 4_000), 999);
        assert_eq!(auto_ngl(24_000, 4_000), 600);
    }

    #[test]
    fn auto_ngl_zero_when_no_vram_or_huge_model() {
        assert_eq!(auto_ngl(0, 4_000), 0);
        assert_eq!(auto_ngl(512, 100_000), 0);
    }

    #[test]
    fn empty_model_does_not_divide_by_zero() {
        assert_eq!(auto_ngl(24_000, 0), 999);
    }

    #[test]
    fn no_gpu_exports_none() {
        // CI hosts have no nvidia-smi/kfd/metal; vendor probe falls through.
        if detect_vendor().is_some() {
            return;
        }
        let mut env = env_of(&[]);
        apply_with(&mut env, 4_000);
        assert_eq!(env.get("ERE_GPU").map(String::as_str), Some("none"));
        assert!(!env.contains_key("ERE_NGL"));
    }

    #[test]
    fn pinned_keys_are_never_overridden() {
        let mut env = env_of(&[("ERE_GPU", "none"), ("ERE_NGL", "0")]);
        apply_with(&mut env, 4_000);
        assert_eq!(env.get("ERE_GPU").map(String::as_str), Some("none"));
        assert_eq!(env.get("ERE_NGL").map(String::as_str), Some("0"));
        assert!(!env.contains_key("ERE_VRAM_MB"));
    }

    #[test]
    fn pinned_ngl_kept_even_when_gpu_present_env_preseeded() {
        // Simulate a host where detection would succeed by pre-seeding only
        // NGL: apply_with must not clobber it (VRAM unknown without probe).
        let mut env = env_of(&[("ERE_NGL", "33")]);
        apply_with(&mut env, 4_000);
        assert_eq!(env.get("ERE_NGL").map(String::as_str), Some("33"));
    }
}
