use super::engine::{stage_engine, EngineSpec};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct InitArgs {
    #[command(subcommand)]
    pub action: InitAction,
}

#[derive(Subcommand)]
pub enum InitAction {
    /// Scaffold a ready-to-build AI agent project (llama.cpp runtime staged)
    Agent(AgentArgs),
}

#[derive(Args)]
pub struct AgentArgs {
    /// Target project directory
    #[arg(default_value = "my-agent")]
    pub dir: PathBuf,

    /// Copy an existing llama.cpp runtime directory instead of downloading
    /// (e.g. examples/real-agent/.deps/llama). Also honored via
    /// `ERE_LLAMA_RUNTIME`.
    #[arg(long, value_name = "DIR")]
    pub runtime: Option<PathBuf>,

    /// Scaffold only — do not fetch or copy the llama runtime
    #[arg(long)]
    pub no_runtime: bool,

    /// llama.cpp release build to download; 10636 is the runtime proven in
    /// examples/real-agent (build 10636, ggml 0.22.0)
    #[arg(long, default_value_t = 10636)]
    pub llama_build: u64,

    /// Overwrite an existing project
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: InitArgs) -> Result<()> {
    match args.action {
        InitAction::Agent(a) => run_agent(a),
    }
}

fn run_agent(args: AgentArgs) -> Result<()> {
    if args.dir.join("Agentfile.yaml").exists() && !args.force {
        anyhow::bail!(
            "{} already has an Agentfile.yaml. Use --force to overwrite.",
            args.dir.display()
        );
    }
    if args.dir.exists() {
        std::fs::create_dir_all(args.dir.join("models"))
            .with_context(|| format!("failed to create {}", args.dir.join("models").display()))?;
    } else {
        std::fs::create_dir_all(&args.dir)
            .with_context(|| format!("failed to create {}", args.dir.display()))?;
        std::fs::create_dir_all(args.dir.join("models"))
            .with_context(|| format!("failed to create {}", args.dir.join("models").display()))?;
    }

    scaffold_project(&args.dir)?;

    if !args.no_runtime {
        stage_runtime(&args.dir, &args)?;
    }

    eprintln!("Created agent project at {}", args.dir.display());
    eprintln!();
    eprintln!("  cd {}", args.dir.display());
    eprintln!("  ./download_model.sh");
    eprintln!(
        "  erebus build . --embed-interpreter python3 -o {}.erebus",
        args.dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    );
    eprintln!(
        "  ./{}.erebus   # API on http://localhost:8000",
        args.dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    );
    eprintln!("  curl -X POST localhost:8000/infer -d '{{\"prompt\":\"Hello\"}}'");
    eprintln!();
    eprintln!(
        "Attestation: set ERE_ATTEST_KEY=<path to .key> before running to sign every execution."
    );
    Ok(())
}

fn scaffold_project(dir: &Path) -> Result<()> {
    write(dir, "Agentfile.yaml", AGENTFILE)?;
    write(dir, "app.py", APP_PY)?;
    write(dir, "requirements.txt", "flask\n")?;
    write(dir, "download_model.sh", DOWNLOAD_MODEL_SH)?;
    write(dir, ".gitignore", "*.gguf\n.deps/\n")?;
    write(dir, "README.md", README)?;
    Ok(())
}

fn write(dir: &Path, name: &str, content: &str) -> Result<()> {
    std::fs::write(dir.join(name), content)
        .with_context(|| format!("failed to write {}/{}", dir.display(), name))
}

fn stage_runtime(project: &Path, args: &AgentArgs) -> Result<()> {
    let llama = project.join(".deps").join("llama");
    let spec = if let Some(dir) = &args.runtime {
        EngineSpec::Local(dir.clone())
    } else if let Some(dir) = std::env::var_os("ERE_LLAMA_RUNTIME") {
        EngineSpec::Local(PathBuf::from(dir))
    } else {
        EngineSpec::Download(args.llama_build)
    };
    stage_engine(&llama, &spec)
}

const AGENTFILE: &str = r#"# Agentfile.yaml — declarative build config for erebus.
# Build:  erebus build . --embed-interpreter python3 -o agent.erebus
agent:
  version: "1.0.0"
  description: "Self-contained llama.cpp AI agent"
  author: "you"

model:
  path: models/model.gguf
  ngl: auto

build:
  entrypoint:
    - python3
    - app.py
  isolation: sandbox
  seccomp: true
  health_port: 8000
  env:
    PORT: "8000"
"#;

const APP_PY: &str = r#"#!/usr/bin/env python3
"""Self-contained llama.cpp agent. Serve on :PORT (default 8000)."""
import os
import platform
import subprocess
from pathlib import Path

from flask import Flask, jsonify, request

app = Flask(__name__)

APP_DIR = Path(__file__).resolve().parent
MODEL_PATH = os.environ.get("MODEL_PATH", str(APP_DIR / "models" / "model.gguf"))
LLAMA_DIR = APP_DIR / ".deps" / "llama"
LLAMA_CLI = os.environ.get("LLAMA_CLI", str(LLAMA_DIR / "llama-cli"))
LLAMA_LIB = str(LLAMA_DIR)

# Pinned ggml backend. This llama release ships per-microarch backends; the
# default discovery (scan near /proc/self/exe) silently finds none inside the
# pivot_root sandbox, so we pin the bundle's own copy explicitly.
_ARCH = {"x86_64": "x64", "aarch64": "aarch64"}.get(platform.machine(), "")


def _ggml_backend() -> str:
    if _ARCH:
        cand = LLAMA_DIR / f"libggml-cpu-{_ARCH}.so"
        if cand.exists():
            return str(cand)
    for so in sorted(LLAMA_DIR.glob("libggml-cpu-*.so")):
        return str(so)
    return ""


SYSTEM_PROMPT = "You are a helpful AI assistant built with erebus. Answer concisely."


def run_inference(prompt: str, max_tokens: int = 512) -> str:
    cmd = [
        LLAMA_CLI, "-m", MODEL_PATH,
        "-p", f"{SYSTEM_PROMPT}\n\nUser: {prompt}\n\nAssistant:",
        "-n", str(max_tokens), "--temp", "0.7", "--top-p", "0.9",
        "--repeat-penalty", "1.1", "-c", "2048", "-st", "--no-display-prompt",
    ]
    ngl = os.environ.get("ERE_NGL", "")
    if ngl.isdigit() and int(ngl) > 0:
        cmd += ["-ngl", ngl]
    env = {
        **os.environ,
        "LD_LIBRARY_PATH": LLAMA_LIB + ":" + os.environ.get("LD_LIBRARY_PATH", ""),
    }
    backend = _ggml_backend()
    if backend:
        env["GGML_BACKEND_PATH"] = backend
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    except subprocess.TimeoutExpired:
        return "Error: inference timed out"
    except FileNotFoundError:
        return f"Error: llama-cli missing at {LLAMA_CLI}"
    if result.returncode != 0:
        return f"Error: {result.stderr.strip()}"
    out = result.stdout.strip()
    marker = "Assistant:"
    if marker in out:
        out = out.rsplit(marker, 1)[1]
    return out.split("[ Prompt:", 1)[0].strip()


@app.get("/")
def index():
    return jsonify({"status": "ok", "endpoints": ["/health", "/infer"]})


@app.get("/health")
def health():
    return jsonify({
        "status": "ok" if Path(MODEL_PATH).exists() and Path(LLAMA_CLI).exists() else "degraded",
        "model_exists": Path(MODEL_PATH).exists(),
        "llama_cli_exists": Path(LLAMA_CLI).exists(),
        "gpu": {"vendor": os.environ.get("ERE_GPU"), "ngl": os.environ.get("ERE_NGL")},
    })


@app.post("/infer")
def infer():
    body = request.get_json(silent=True) or {}
    prompt = body.get("prompt")
    if not prompt:
        return jsonify({"error": "missing 'prompt' in request body"}), 400
    max_tokens = body.get("max_tokens", 512)
    return jsonify({
        "status": "ok",
        "prompt": prompt,
        "response": run_inference(prompt, max_tokens),
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"agent listening on :{port}", flush=True)
    app.run(host="0.0.0.0", port=port)
"#;

const DOWNLOAD_MODEL_SH: &str = r#"#!/usr/bin/env bash
# Download a GGUF model into models/model.gguf.
# Pass a URL argument to use a different model.
set -euo pipefail
DIR="$(dirname "$0")"
URL="${1:-https://huggingface.co/HuggingFaceTB/SmolLM-1.7B-Instruct-GGUF/resolve/main/smollm-1.7b-instruct.Q4_K_M.gguf}"
mkdir -p "$DIR/models"
[ -f "$DIR/models/model.gguf" ] && { echo "models/model.gguf already present"; exit 0; }
echo "Downloading $URL"
wget -O "$DIR/models/model.gguf" "$URL"
echo "Saved to $DIR/models/model.gguf"
"#;

const README: &str = r#"# my-agent

Self-contained llama.cpp AI agent built with [erebus](https://github.com/Tednoob17/erebus).

## Build

```bash
./download_model.sh                      # fetch GGUF weights (~1GB)
erebus build . --embed-interpreter python3 -o agent.erebus
```

`erebus build` also auto-embeds the llama engine without a staged `.deps/llama`:

```bash
erebus build . --embed-interpreter python3 --engine b10636 -o agent.erebus
```

## Run

```bash
./agent.erebus
curl -X POST http://localhost:8000/infer -d '{"prompt": "Hello"}'
```

Sign every execution (opt-in): `ERE_ATTEST_KEY=<path to .key> ./agent.erebus` writes
`agent.erebus.attest`, verifiable with `erebus verify-attest`.

## Layout

- `app.py` — Flask server, llama-cli inference (GGML_BACKEND_PATH pinned to the bundled backend)
- `models/model.gguf` — GGUF weights (gitignored)
- `.deps/llama/` — llama.cpp runtime + host runtime libs (gitignored, staged by `erebus init agent`)

## Portability

- The staged runtime bundles the **build host's glibc ABI** (`libstdc++`,
  `libssl`, `libcrypto`, `libgomp`, `libgcc_s`): the bundle runs on any
  distro with a **same-or-newer glibc** than the build machine. Older-glibc
  hosts cannot exec the bundled llama-cli. A fully static (musl) llama.cpp
  build would break that tie (roadmap).
- The arch is pinned by `libggml-cpu-*.so` and the release zip you staged
  (`x64` on x86_64, `aarch64` on ARM): build on the same arch as the target
  machine.
"#;
