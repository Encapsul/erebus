# erebus

> **Your AI agent. One file. Runs anywhere — then serves an
> OpenAI-compatible API.**

**erebus** packages an AI agent — model weights, inference engine config,
runtime and dependencies — into a single self-contained `.erebus` binary.
Ship it like software; the target machine installs nothing.

```bash
# Build once — runtime, app, libraries, weights
$ erebus build ./my-agent --embed-model models/model.gguf -o agent.erebus

# Distribute through any registry (self-hosted, stdlib-only server included)
$ erebus publish agent.erebus

# Run / serve / chat on any machine
$ erebus serve agent.erebus --port 8080     # POST /v1/chat/completions
$ erebus chat  agent.erebus                 # terminal TUI (--web for browser)
```

## What happens under the hood

| Step | What happens | Who runs it |
|---|---|---|
| `build` | detects runtime, resolves deps, chunks model layers, compresses rootfs | developer |
| `publish` / `pull` | registry upload; streamed download verified against index SHA-256 | developer ↔ users |
| `serve` / `chat` / exec | stub verifies its own SHA-256 → mmap-lazy payload read → cache extraction → GPU probe (`ERE_NGL`) → engine launched | end user |

## Key features

- **Universal binaries** — `--universal` packs four native slices
  (linux-x64, linux-arm64, macos-arm64, windows-x64 PE32+) into one file;
  a POSIX-shell polyglot loader routes by `uname`.
- **Multi-format inference** — GGUF via llama.cpp (static, golden path);
  safetensors/GPTQ/AWQ/ONNX via vLLM; TensorRT-LLM engines; Apple MLX.
  The engine is resolved at launch with an actionable install hint.
- **GPU auto-tuning** — nvidia-smi/ROCm/Metal probes export `ERE_GPU`,
  `ERE_VRAM_MB` and a suggested `ERE_NGL`; explicit pins always win.
- **Integrity first** — SHA-256 over payload‖metadata at every launch,
  optional Ed25519 signing against trusted keys, fail-cold behavior.
- **SISR delta updates** — content-defined chunking ships only changed
  chunks; signed manifests verify before reconstruction.
- **Declarative builds** — `Agentfile.yaml` (or legacy `.erebus.toml`);
  CLI flags take precedence.
- **Chaos-tested** — adversarial harnesses for the encrypted launcher and
  for registry/pull/ship ship in-repo; latest verdicts SURVIVED
  ([benchmarks](https://github.com/Tednoob17/erebus/tree/main/benchmarks)).

## Supported runtimes

| Runtime | Detection | Use case |
|---|---|---|
| Python | `requirements.txt`, `pyproject.toml`, … | FastAPI/Flask agents, tools |
| Binary | executable present | llama.cpp engines, Go/Rust servers |

Cross-platform launcher stubs are built with cargo-zigbuild; any host can
target any platform.

## Status

All nine roadmap competitive-gap items are implemented and validated:
universal binary (4 targets incl. Windows PE), OpenAI-compatible serving,
registry pull/publish, Agentfile.yaml, GPU auto-detect, chat UI, SISR deltas,
signing/trust, sandboxing. See the top-level [ROADMAP](../ROADMAP.md) and
[benchmarks](https://github.com/Tednoob17/erebus/tree/main/benchmarks).

> Note: some deeper chapters of this book still describe pre-0.5 details
> (older `.ere` naming, removed language runtimes). The authoritative,
> up-to-date references are the [README](https://github.com/Tednoob17/erebus#readme)
> and [HANDOFF](https://github.com/Tednoob17/erebus/blob/main/HANDOFF.md);
> chapter-by-chapter refresh is tracked as an open follow-up.

## Get started

```bash
git clone https://github.com/Tednoob17/erebus.git && cd erebus
cargo build --release        # CLI at target/release/erebus
./target/release/erebus doctor
```

Continue with [The Problem](./concepts/problem.md) for the why, or jump to
the [SISR overview](./concepts/sisr-overview.md) for delta updates.
