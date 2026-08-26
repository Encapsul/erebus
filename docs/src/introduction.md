# erebus

> **Sign. Track. Prove. — Ship AI agents with verifiable attestation.**

**erebus** packages an AI agent — model weights, inference engine config,
runtime and dependencies — into a single self-contained `.erebus` binary.
It generates a **detached attestation** (`.erebus.attest`) proving
what executed, where, when, and that nothing was tampered with.

```bash
# Build — runtime, app, libraries, weights
erebus build ./my-agent --embed-model models/model.gguf -o agent.erebus

# Sign — Ed25519, fail-cold verification
erebus sign agent.erebus --key my-key.pem

# Attest — generate verifiable proof of execution
erebus attest agent.erebus -o agent.erebus.attest

# Distribute through any registry
erebus publish agent.erebus

# Run / serve / chat on any machine
erebus serve agent.erebus --port 8080
erebus chat agent.erebus
```

## What happens under the hood

| Step | What happens | Who runs it |
|---|---|---|
| `build` | detects runtime, resolves deps, chunks model layers, compresses rootfs | developer |
| `sign` | Ed25519 signature over SHA-256(payload ‖ metadata ‖ footer), anti-downgrade | developer |
| `attest` | generates structured JSON with artifact hashes, provenance, execution context; signs it | developer |
| `publish` / `pull` | registry upload; streamed download verified against index SHA-256 | developer ↔ users |
| `serve` / exec | stub verifies SHA-256 → mmap-lazy payload → cache extraction → GPU probe → engine launch | end user |

## Key features

- **Verifiable attestation** — detached `.erebus.attest` files prove
  what executed, with Ed25519 signatures and machine identity hashes.
- **Universal binaries** — `--universal` packs four native slices
  (linux-x64, linux-arm64, macos-arm64, windows-x64 PE32+) into one file.
- **Multi-format inference** — GGUF via llama.cpp; safetensors/ONNX via
  vLLM; TensorRT-LLM; Apple MLX.
- **GPU auto-tuning** — nvidia-smi/ROCm/Metal probes export `ERE_GPU`,
  `ERE_VRAM_MB` and a suggested `ERE_NGL`.
- **Integrity first** — SHA-256 over payload‖metadata at every launch,
  Ed25519 signing against trusted keys, fail-cold behavior.
- **SISR delta updates** — content-defined chunking ships only changed
  chunks; signed manifests verify before reconstruction.
- **Declarative builds** — `Agentfile.yaml` (or legacy `.erebus.toml`).
- **Chaos-tested** — adversarial harnesses ship in-repo; latest verdicts
  SURVIVED ([benchmarks](https://github.com/Tednoob17/erebus/tree/main/benchmarks)).

## Supported runtimes

| Runtime | Detection | Use case |
|---|---|---|
| Python | `requirements.txt`, `pyproject.toml`, … | FastAPI/Flask agents, tools |
| Binary | executable present | llama.cpp engines, Go/Rust servers |

Cross-platform launcher stubs are built with cargo-zigbuild; any host can
target any platform.

## Status

All nine roadmap competitive-gap items are implemented and validated:
universal binary, OpenAI-compatible serving, registry pull/publish,
Agentfile.yaml, GPU auto-detect, chat UI, SISR deltas, signing/trust,
sandboxing. See [ROADMAP](../ROADMAP.md) and
[benchmarks](https://github.com/Tednoob17/erebus/tree/main/benchmarks).

## Get started

```bash
git clone https://github.com/Tednoob17/erebus.git && cd erebus
cargo build --release
./target/release/erebus doctor
```

Continue with [The Problem](./concepts/problem.md) for the why, or jump to
the [SISR overview](./concepts/sisr-overview.md) for delta updates.
