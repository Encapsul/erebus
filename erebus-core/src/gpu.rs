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

/// Total physical RAM in MB, best effort. `None` when the platform offers no
/// cheap probe (Windows for now).
pub fn total_ram_mb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let info = std::fs::read_to_string("/proc/meminfo").ok()?;
        parse_meminfo_kb(&info)
    }
    #[cfg(target_os = "macos")]
    {
        let out = Command::new("sysctl")
            .arg("-n")
            .arg("hw.memsize")
            .output()
            .ok()?;
        let bytes: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
        Some(bytes / (1024 * 1024))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn parse_meminfo_kb(info: &str) -> Option<u64> {
    for line in info.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// Pre-flight fit verdict for serving `model_mb` with the given context.
///
/// `None` = no data to judge (don't nag). `Some(false)` + the numbers mean
/// the host almost certainly cannot hold the model — say so BEFORE the
/// engine dies with an obscure allocator error.
pub fn check_fit(
    model_mb: u64,
    ctx_size: u32,
    ngl: u32,
    vram_mb: Option<u64>,
    ram_mb: Option<u64>,
) -> Option<(bool, u64, Option<u64>)> {
    // Weights + KV cache + activation headroom. KV scales with ctx; the
    // constant absorbs activations — deliberately coarse, the goal is
    // catching gross mismatches, not capacity planning.
    let kv_mb = u64::from(ctx_size).saturating_mul(3) / 4;
    let needed = model_mb.saturating_add(kv_mb).saturating_mul(13) / 10;
    let gpu_backed = ngl > 0;
    let primary = if gpu_backed { vram_mb } else { ram_mb };
    let primary = primary?; // no probe → stay silent
    let fits = primary >= needed;
    Some((fits, needed, Some(primary)))
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

    #[cfg(target_os = "linux")]
    #[test]
    fn meminfo_parser_extracts_memtotal() {
        let info = "MemTotal:       8038200 kB\nMemFree:        123456 kB\n";
        assert_eq!(parse_meminfo_kb(info), Some(7849));
        assert_eq!(parse_meminfo_kb("no match"), None);
    }

    #[test]
    fn check_fit_warns_only_on_gross_mismatch() {
        // 4 GB model, no GPU (ngl=0), 8 GB RAM → fits
        assert_eq!(
            check_fit(4_000, 2048, 0, None, Some(8_000)),
            Some((true, 7_196, Some(8_000)))
        );
        // same model, 2 GB RAM → does not fit
        let verdict = check_fit(4_000, 2048, 0, None, Some(2_000)).unwrap();
        assert!(!verdict.0);
        // no probe at all → silent
        assert_eq!(check_fit(4_000, 2048, 0, None, None), None);
        // GPU offload judges against VRAM
        let verdict = check_fit(4_000, 2048, 33, Some(24_000), Some(8_000)).unwrap();
        assert!(verdict.0);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn detection_is_graceful_without_gpu_tooling() {
        // CI hosts: must neither panic nor misreport; None or a real vendor
        // are both acceptable outcomes of a healthy probe.
        let _ = detect();
    }
}
