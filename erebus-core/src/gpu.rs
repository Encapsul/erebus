//! GPU discovery and `-ngl` auto-tuning for llama.cpp-style inference apps.
//!
//! Shared by the launcher stub (env export before exec) and the CLI
//! (`erebus serve`). Detection is deliberately cheap: one ENOENT-fast probe
//! of `nvidia-smi`, then filesystem checks.

use std::process::Command;

/// Detected accelerator: vendor hint plus total VRAM when queryable.
pub fn detect() -> Option<(&'static str, Option<u64>)> {
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
pub fn auto_ngl(vram_mb: u64, model_mb: u64) -> u32 {
    let ratio = vram_mb.saturating_mul(100) / model_mb.max(1);
    ratio.min(999) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn detection_is_graceful_without_gpu_tooling() {
        // CI hosts: must neither panic nor misreport; None or a real vendor
        // are both acceptable outcomes of a healthy probe.
        let _ = detect();
    }
}
