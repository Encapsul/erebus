# erebus

[![CI](https://img.shields.io/github/actions/workflow/status/Tednoob17/erebus/ci.yml?branch=main&label=build)](https://github.com/Tednoob17/erebus/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.5.0-green.svg)](https://github.com/Tednoob17/erebus/releases)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Tednoob17/erebus/pulls)

**Your AI agent. One file. Runs anywhere — then serves an OpenAI-compatible API.**

erebus packages an AI agent — model weights, inference engine config, runtime,
dependencies — into a single self-contained binary. Ship it like software:

```bash
erebus pull demo-agent                 # fetch from any registry
erebus chat demo-agent.erebus          # terminal chat, zero install on the target
# or expose it:
erebus serve demo-agent.erebus --port 8080   # POST /v1/chat/completions
```

One `.erebus` file carries **4 native platform slices** (linux-x64, linux-arm64,
macos-arm64, windows-x64) behind a POSIX-shell polyglot loader — the same 59 MB
artifact runs natively on all four ([validated](benchmarks/universal.md) on real
Linux, qemu-arm64 and Windows under Wine).

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/Tednoob17/erebus/main/scripts/install.sh | bash
erebus doctor

cd your-app && erebus build . -o myapp.erebus
./myapp.erebus                       # run it like any executable
```

Serve a bundled LLM as an OpenAI-compatible endpoint and chat with it:

```bash
erebus build . --embed-model models/model.gguf -o agent.erebus
erebus serve agent.erebus --port 8080        # llama-server / vLLM / … launched for you
erebus chat agent.erebus                     # or talk to it in the terminal
erebus chat agent.erebus --web --port 8080   # or from the browser (embedded UI)
```

## Why erebus

| | erebus | ollama | llamafile |
|---|---|---|---|
| Distribution unit | one `.erebus` per app **× 4 OS/arch inside** | app store + separate models | single binary |
| Registry | self-hostable, 2 env vars | proprietary cloud default | none |
| Engine support | GGUF + safetensors/ONNX/TRT-LLM/MLX | GGUF | GGUF |
| Delta model updates (SISR) | ✅ content-defined chunking | ❌ re-download | ❌ |
| Declarative builds | `Agentfile.yaml` | Modelfile | ❌ |
| Signing & trusted keys | Ed25519, fail-closed | ❌ | ❌ |
| Chaos/security test suites in-repo | ✅ [benchmarks/security.md](benchmarks/security.md) | ❌ | ❌ |

## The five-minute tour

### 1 · Build — declaratively

```yaml
# Agentfile.yaml — CLI flags override this file
model:
  path: models/model.gguf     # embedded as a ModelLayer (SISR-aware chunking)
  ngl: auto                   # auto | off | <layers>
build:
  entrypoint: [python3, app.py]
  seccomp: true
  health_port: 8000
  env:
    LLAMA_CLI: /app/bin/llama-cli
```

```bash
erebus build . -o agent.erebus            # Agentfile picked up automatically
erebus build . --universal -o agent.erebus  # → 4 platform slices in one file
```

Legacy `.erebus.toml` still works. Precedence: **CLI > Agentfile > detection**.

### 2 · Run anywhere

The stub verifies its own SHA-256, extracts into a content-addressed cache,
exports GPU facts (`ERE_GPU`, `ERE_VRAM_MB`, `ERE_NGL`) and execs the entrypoint.
GPU offload is auto-tuned at launch: `nvidia-smi` probe → ROCm `/dev/kfd` → Metal;
pins always win (`--ngl off|N`).

### 3 · Serve OpenAI-compatible

```bash
erebus serve agent.erebus --port 8080 [--ngl auto] [--ctx-size 4096] [--web]
```

erebus resolves the engine from the model format and launches it for you:

| Bundled artifacts | Format | Engine launched |
|---|---|---|
| `*.gguf` | GGUF | `llama-server` (static, golden path) |
| `*.safetensors` (incl. GPTQ/AWQ quant) | HF | vLLM (`python3 -m vllm…api_server`) |
| `*.onnx` | ONNX | vLLM ONNX backend |
| `*.engine` / `*.plan` | TensorRT-LLM | `trtllm-serve` |
| MLX weights + config | MLX | `mlx_lm.server` |

Missing engine on the target? You get the exact install hint — or embed it via
the Agentfile environment. Measured on CPU: TinyLlama Q4_K_M cold-start < 45 s,
warm completions ≈ 5 s — full numbers in [benchmarks/serve.md](benchmarks/serve.md).

### 4 · Distribute via your own registry

```bash
python3 scripts/registry_server.py --dir ~/erebus-registry --host 0.0.0.0 --port 8787
export ERE_REGISTRY=http://your-vps:8787
erebus publish agent.erebus       # upload (multipart, optional bearer token)
erebus pull agent-agent           # streamed download, SHA-256 verified against index
```

No database, no dependencies — one stdlib Python file, index generated live from
the packages directory. Hardened against traversal, bad filenames, tampered
indexes ([chaos-tested](benchmarks/security.md)).

### 5 · Update without re-shipping gigabytes

SISR (Self-Incremental Self-Repair) splits payloads with content-defined
chunking; updates transfer only changed chunks. Signed delta manifests verify
fail-cold at boot.

## Command reference

| Command | Description |
|---------|-------------|
| `erebus build <dir>` | Package an app dir (`--universal`, `--embed-model`, `--ngl`, `--sign`, `--encrypt`, `--enable-sisr`, `--target`) |
| `erebus run <file>` | Execute a bundle (namespace isolation, health gate) |
| `erebus serve <file>` | Launch the engine as an OpenAI-compatible HTTP API |
| `erebus chat <file>` | Terminal TUI chat; `--web` serves the embedded browser UI |
| `erebus pull <name>` | Download from a registry (integrity-checked, cached) |
| `erebus publish <file>` | Upload to a registry |
| `erebus swap <file> <path> --from <new>` | Replace a file inside an existing bundle (hot-swap) |
| `erebus inspect <file>` | Metadata, slice tables, JSON output |
| `erebus layer push/list` | Manage shared runtime packs & models (local CAS) |
| `erebus keygen/sign/verify/trust` | Ed25519 signing workflow |
| `erebus dashboard` | Interactive TUI: SISR benchmarks, cache status |
| `erebus doctor / scan / env / clean / selftest / upgrade / completion / man` | Ops & tooling |

## Binary format

```
[stub][payload][metadata][footer]
```

- **Stub** — static launcher per OS (musl ELF / Mach-O / PE32+): reads itself,
  verifies SHA-256, mmap-lazy-loads the payload, extracts, sandboxes, execs.
- **Payload** — zstd tar (or squashfs) of app + runtime + weights.
- **Metadata** — JSON: runtime, entrypoint, layers (runtime/model/tool/config),
  capabilities, env, crypto block.
- **Footer** — magic `0xBEEF_CAFE`, version flags, integrity digest.
  v2 plain · v3 signed · v4 encrypted · v5 squashfs.

Universal polyglot files prepend a 32 KiB `#!/bin/sh` loader plus a slice table;
each slice is a complete native bundle for its OS/arch.

## Supported runtimes & targets

| Runtime | Detection | Use case |
|---|---|---|
| Python | `requirements.txt`, `pyproject.toml`, … | FastAPI/Flask agents, orchestration, tools |
| Binary | ELF/executable present | llama.cpp engines, Go/Rust servers |

Cross-compiling the launcher stub uses [`cargo zigbuild`](https://github.com/cross-rs/cross-toolchains)
(zig as linker). Any host builds any target; universal builds need nothing else.

## Configuration

`Agentfile.yaml` (preferred) or legacy `.erebus.toml`:

```toml
[package]
version = "1.0.0"
author = "You"

[build]
isolation = "sandbox"
seccomp = true
env_file = ".env"
embed_model = "models/model.gguf"
ngl = "auto"
health_port = 8000
```

## Security model

- **Ed25519 signatures**, fail-cold verification against `~/.erebus/trusted-keys/`
  (CVE-2023-48022 mitigated; ed25519-dalek ≥ 2.1 with `zeroize`)
- **SHA-256 integrity** over payload ‖ metadata at every launch
- **`--encrypt` is obfuscation only** — the AES-256-GCM key lives in the file's
  metadata by design; use signing for authenticity. Mutually exclusive with SISR.
- **Isolation**: Linux namespaces + seccomp/Landlock; macOS App Sandbox;
  Windows process isolation. Secrets never baked silently (`.env` rejected unless
  explicit); keys written `0600` atomically; secrets zeroized on drop
  ([audit](benchmarks/security.md)).
- `cargo audit`: clean (RC 0).

## Benchmarks

Reproducible numbers with exact commands live in [`benchmarks/`](benchmarks/):
cold start, warm latency, cross-build times, one-file-four-platforms proof,
crypto chaos properties, and two adversarial harnesses whose latest verdicts are
**SURVIVED** (30 corruptions + 10 SIGKILLs on encrypted bundles; 22 checks across
registry/pull/serve).

## Build from source

```bash
git clone https://github.com/Tednoob17/erebus.git && cd erebus
cargo build --release          # CLI at target/release/erebus
cargo test --workspace         # 444 tests
```

| Crate | Purpose |
|-------|---------|
| `erebus-core` | Format, compression, detection, encryption, inference-engine resolution, SISR, CAS |
| `erebus-stub` | Self-extracting launcher (ELF / Mach-O / PE32+) |
| `erebus-cli` | Everything you type: build, serve, chat, pull, … |

Before contributing: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test --workspace`. Style: [CODE_STYLE.md](CODE_STYLE.md); ANSSI-Rust rules in
[RULES.md](RULES.md).

## License

MIT — see [LICENSE](LICENSE).
