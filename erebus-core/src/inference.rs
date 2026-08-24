//! Model-format detection and inference-engine launch plans.
//!
//! erebus does not run inference itself — it resolves the engine that speaks
//! the bundled weights' format and launches it as an OpenAI-compatible HTTP
//! server. GGUF maps to llama.cpp's static `llama-server` (the golden path);
//! HF safetensors / GPTQ / AWQ / ONNX map to vLLM; TensorRT-LLM engines to
//! `trtllm-serve`; Apple MLX weights to `mlx_lm.server`. Engines that are
//! Python-based are resolved against the target machine at launch time, with
//! a clear install hint when absent — the bundle always carries the weights.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelFormat {
    Gguf,
    SafeTensors,
    Onnx,
    TensorRt,
    Mlx,
}

impl ModelFormat {
    pub fn label(self) -> &'static str {
        match self {
            ModelFormat::Gguf => "gguf",
            ModelFormat::SafeTensors => "safetensors",
            ModelFormat::Onnx => "onnx",
            ModelFormat::TensorRt => "tensorrt",
            ModelFormat::Mlx => "mlx",
        }
    }

    /// Native engine binary this format needs on the host ("" = python-based).
    pub fn native_engine(self) -> &'static str {
        match self {
            ModelFormat::Gguf => "llama-server",
            ModelFormat::TensorRt => "trtllm-serve",
            ModelFormat::Mlx => "mlx_lm.server",
            ModelFormat::SafeTensors | ModelFormat::Onnx => "",
        }
    }

    /// One-line engine requirement shown when the runtime is missing.
    pub fn engine_hint(self) -> &'static str {
        match self {
            ModelFormat::Gguf => "install llama.cpp (llama-server on PATH or in bundle)",
            ModelFormat::SafeTensors | ModelFormat::Onnx => {
                "pip install vllm  (or embed it via Agentfile build.env)"
            }
            ModelFormat::TensorRt => "pip install tensorrt-llm  (GPU-arch specific)",
            ModelFormat::Mlx => "pip install mlx-lm  (Apple Silicon)",
        }
    }
}

/// What to exec, once the target machine has been probed.
#[derive(Debug, Clone)]
pub struct LaunchPlan {
    pub program: String,
    pub args: Vec<String>,
}

/// A model artifact found in an extracted rootfs.
#[derive(Debug, Clone)]
pub struct FoundModel {
    pub path: PathBuf,
    pub format: ModelFormat,
}

/// Classify a single file by extension/content signals.
fn classify(path: &Path) -> Option<ModelFormat> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if name.ends_with(".gguf") {
        return Some(ModelFormat::Gguf);
    }
    if name.ends_with(".onnx") {
        return Some(ModelFormat::Onnx);
    }
    if name.ends_with(".engine") || name.ends_with(".plan") {
        return Some(ModelFormat::TensorRt);
    }
    if name == "model.safetensors.index.json" {
        return Some(ModelFormat::SafeTensors);
    }
    // MLX ships .safetensors too; disambiguate via the MLX-flavored config
    // that always sits beside the weights.
    if name == "weights.npz" {
        return Some(ModelFormat::Mlx);
    }
    if name.ends_with(".safetensors") {
        let is_mlx = path
            .parent()
            .and_then(|d| std::fs::read_to_string(d.join("config.json")).ok())
            .map(|cfg| cfg.contains("\"mlx\"") || cfg.contains("mlx-lm"))
            .unwrap_or(false);
        return Some(if is_mlx {
            ModelFormat::Mlx
        } else {
            ModelFormat::SafeTensors
        });
    }
    None
}

/// Find the best model artifact under `root`, honoring an optional substring
/// filter; largest file wins within the chosen format class.
pub fn find_model(root: &Path, filter: Option<&str>) -> Option<FoundModel> {
    let mut hits: Vec<(PathBuf, ModelFormat, u64)> = Vec::new();
    collect(root, &mut hits, 5);
    let mut filtered: Vec<_> = hits;
    if let Some(f) = filter {
        let needle = f.to_lowercase();
        filtered.retain(|(p, _, _)| p.to_string_lossy().to_lowercase().contains(&needle));
    }
    // Prefer GGUF over other equal-sized hits: it is the only format whose
    // engine is guaranteed static/portable.
    filtered.sort_by_key(|(p, fmt, size)| (format_rank(*fmt), std::cmp::Reverse(*size), p.clone()));
    filtered.first().map(|(p, f, _)| FoundModel {
        path: p.clone(),
        format: *f,
    })
}

fn format_rank(f: ModelFormat) -> u8 {
    match f {
        ModelFormat::Gguf => 0,
        ModelFormat::SafeTensors => 1,
        ModelFormat::Onnx => 2,
        ModelFormat::Mlx => 3,
        ModelFormat::TensorRt => 4,
    }
}

fn collect(dir: &Path, out: &mut Vec<(PathBuf, ModelFormat, u64)>, depth: u8) {
    if depth == 0 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, out, depth - 1);
        } else if let Some(fmt) = classify(&path) {
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            out.push((path, fmt, size));
        }
    }
}

/// Short platform key used in runtime-pack filenames ("linux-x64", …).
///
/// Packs are named `<engine>-<key>.pack` so one registry can serve every
/// supported target from the same directory.
pub fn host_pack_key() -> String {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        other => other,
    };
    match std::env::consts::OS {
        os @ ("linux" | "macos" | "windows") => format!("{os}-{arch}"),
        other => format!("{other}-{}", std::env::consts::ARCH),
    }
}

/// Platform-scoped pack identifier, e.g. `llama-server-linux-x64`.
pub fn engine_pack_stem(engine: &str) -> String {
    format!("{engine}-{}", host_pack_key())
}

/// Registry filename of the runtime pack for `engine` on this host,
/// e.g. `llama-server-linux-x64.pack.tar.gz`.
pub fn engine_pack_name(engine: &str) -> String {
    format!("{}.pack.tar.gz", engine_pack_stem(engine))
}

fn which(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|d| d.join(name))
        .find(|c| c.is_file())
}

/// Resolve the engine binary/entry for `format`: bundle bin dirs first, then
/// $PATH, then (for Python engines) any `python3` able to import the module.
fn resolve_engine(
    rootfs: &Path,
    format: ModelFormat,
    python: Option<&str>,
) -> Result<LaunchPlan, String> {
    let native = format.native_engine();
    if !native.is_empty() {
        for rel in ["usr/local/bin", "usr/bin", "bin"] {
            let candidate = rootfs.join(rel).join(native);
            if candidate.is_file() {
                return Ok(LaunchPlan {
                    program: candidate.to_string_lossy().into(),
                    args: vec![],
                });
            }
        }
        if let Some(p) = which(native) {
            return Ok(LaunchPlan {
                program: p.to_string_lossy().into(),
                args: vec![],
            });
        }
        return Err(format!("{} not found — {}", native, format.engine_hint()));
    }
    // vLLM family: needs a python that can import vllm.
    let py = python.unwrap_or("python3");
    let has_vllm = std::process::Command::new(py)
        .args(["-c", "import vllm"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if has_vllm {
        return Ok(LaunchPlan {
            program: py.to_string(),
            args: vec!["-m".into(), "vllm.entrypoints.openai.api_server".into()],
        });
    }
    Err(format!(
        "vLLM not importable via {py} — {}",
        ModelFormat::SafeTensors.engine_hint()
    ))
}

/// Build the full command line serving `model` on `host:port`.
///
/// Returns `Err` with an actionable hint when the engine is unavailable.
pub fn plan_launch(
    rootfs: &Path,
    model: &FoundModel,
    host: &str,
    port: u16,
    ctx_size: u32,
    ngl: u32,
    threads: Option<u32>,
) -> Result<LaunchPlan, String> {
    let mut plan = resolve_engine(rootfs, model.format, None)?;
    plan.args = engine_args(model, host, port, ctx_size, ngl, threads);
    Ok(plan)
}

/// Engine CLI args serving `model` on `host:port` — shared by the normal
/// launch path and the runtime-pack fallback (which resolves the binary
/// outside this module).
pub fn engine_args(
    model: &FoundModel,
    host: &str,
    port: u16,
    ctx_size: u32,
    ngl: u32,
    threads: Option<u32>,
) -> Vec<String> {
    let mut args = Vec::new();
    let model_str = model.path.to_string_lossy().into_owned();
    match model.format {
        ModelFormat::Gguf => {
            args.extend([
                "-m".into(),
                model_str,
                "--host".into(),
                host.into(),
                "--port".into(),
                port.to_string(),
                "-c".into(),
                ctx_size.to_string(),
            ]);
            if ngl > 0 {
                args.push("-ngl".into());
                args.push(ngl.to_string());
            }
            if let Some(t) = threads {
                args.push("-t".into());
                args.push(t.to_string());
            }
        }
        ModelFormat::SafeTensors | ModelFormat::Onnx => {
            let dir = model.path.parent().unwrap_or(Path::new("."));
            args.extend([
                "--model".into(),
                dir.to_string_lossy().into(),
                "--host".into(),
                host.into(),
                "--port".into(),
                port.to_string(),
            ]);
        }
        ModelFormat::TensorRt => {
            let dir = model.path.parent().unwrap_or(Path::new("."));
            args.extend([
                dir.to_string_lossy().into(),
                "--host".into(),
                host.into(),
                "--port".into(),
                port.to_string(),
            ]);
        }
        ModelFormat::Mlx => {
            args.extend([
                "--model".into(),
                model_str,
                "--host".into(),
                host.into(),
                "--port".into(),
                port.to_string(),
            ]);
        }
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_names_are_platform_scoped() {
        let key = host_pack_key();
        assert!(
            key.starts_with("linux-") || key.starts_with("macos-") || key.starts_with("windows-")
        );
        assert_eq!(
            engine_pack_stem("llama-server"),
            format!("llama-server-{key}")
        );
        assert_eq!(
            engine_pack_name("llama-server"),
            format!("llama-server-{key}.pack.tar.gz")
        );
    }

    #[test]
    fn gguf_needs_a_native_engine() {
        assert_eq!(ModelFormat::Gguf.native_engine(), "llama-server");
        assert_eq!(ModelFormat::SafeTensors.native_engine(), "");
    }

    #[test]
    fn classify_by_extension() {
        assert_eq!(classify(Path::new("/x/m.gguf")), Some(ModelFormat::Gguf));
        assert_eq!(classify(Path::new("/x/a.onnx")), Some(ModelFormat::Onnx));
        assert_eq!(
            classify(Path::new("/x/plan.engine")),
            Some(ModelFormat::TensorRt)
        );
        assert_eq!(
            classify(Path::new("/x/w.plan")),
            Some(ModelFormat::TensorRt)
        );
        assert_eq!(
            classify(Path::new("/x/m.safetensors")),
            Some(ModelFormat::SafeTensors)
        );
        assert_eq!(classify(Path::new("/x/readme.md")), None);
    }

    #[test]
    fn find_model_prefers_gguf_and_respects_filter() {
        let dir = tempfile::tempdir().unwrap();
        let big_onnx = dir.path().join("big.onnx");
        let gguf = dir.path().join("small.gguf");
        let other = dir.path().join("other.gguf");
        std::fs::write(&big_onnx, vec![0u8; 100]).unwrap();
        std::fs::write(&gguf, vec![0u8; 10]).unwrap();
        std::fs::write(&other, vec![0u8; 20]).unwrap();

        let hit = find_model(dir.path(), None).unwrap();
        assert_eq!(hit.format, ModelFormat::Gguf);

        let hit = find_model(dir.path(), Some("other")).unwrap();
        assert!(hit.path.ends_with("other.gguf"));

        assert!(find_model(dir.path(), Some("nomatch")).is_none());
    }

    #[test]
    fn gguf_launch_plan_shape() {
        let dir = tempfile::tempdir().unwrap();
        let m = FoundModel {
            path: dir.path().join("m.gguf"),
            format: ModelFormat::Gguf,
        };
        let plan = plan_launch(dir.path(), &m, "0.0.0.0", 9000, 4096, 33, Some(8)).unwrap();
        assert!(plan.program.ends_with("llama-server"));
        let joined = plan.args.join(" ");
        assert!(joined.contains("-ngl 33"));
        assert!(joined.contains("-c 4096"));
        assert!(joined.contains("--port 9000"));
        assert!(joined.contains("-t 8"));
    }

    #[test]
    fn missing_engine_yields_hint_not_panic() {
        let dir = tempfile::tempdir().unwrap();
        let m = FoundModel {
            path: dir.path().join("w.engine"),
            format: ModelFormat::TensorRt,
        };
        let err = plan_launch(dir.path(), &m, "127.0.0.1", 1, 2048, 0, None)
            .expect_err("trtllm-serve should be absent in CI");
        assert!(err.contains("tensorrt-llm"), "{err}");
    }
}
