//! GPU env export for the launcher: thin delegation to the shared heuristics
//! in [`erebus_core::gpu`].
//!
//! Exports advisory vars that packaged agents consume:
//!
//! - `ERE_GPU`     — vendor hint: `nvidia` | `amd` | `metal` | `none`
//! - `ERE_VRAM_MB` — total VRAM when queryable (`nvidia-smi`)
//! - `ERE_NGL`     — suggested `--n-gpu-layers` value
//!
//! Keys already present in the payload environment (pinned via
//! `erebus build --ngl off|N`) are never overridden — pins win over probes.

use crate::Metadata;
use std::collections::BTreeMap;

/// Export GPU facts into `env`, filling only keys the payload didn't pin.
pub fn apply(env: &mut BTreeMap<String, String>, meta: &Metadata) {
    let model_mb = model_bytes(meta) / (1024 * 1024);
    apply_with(env, model_mb);
}

pub(crate) fn apply_with(env: &mut BTreeMap<String, String>, model_mb: u64) {
    if !env.contains_key("ERE_GPU") {
        match erebus_core::gpu::detect() {
            Some((vendor, vram_mb)) => {
                env.insert("ERE_GPU".into(), vendor.into());
                if let Some(mb) = vram_mb {
                    env.entry("ERE_VRAM_MB".to_owned())
                        .or_insert_with(|| mb.to_string());
                    // Pinned NGL wins; probe only fills the gap.
                    env.entry("ERE_NGL".to_owned())
                        .or_insert_with(|| erebus_core::gpu::auto_ngl(mb, model_mb).to_string());
                }
            }
            None => {
                env.insert("ERE_GPU".into(), "none".into());
            }
        }
    }
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
    fn no_gpu_exports_none() {
        // CI hosts have no nvidia-smi/kfd/metal; vendor probe falls through.
        if erebus_core::gpu::detect().is_some() {
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
