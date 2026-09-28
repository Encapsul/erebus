# erebus

> **Sign. Track. Prove. — Ship AI agents with verifiable attestation.**

**erebus** packages an AI agent — model weights, inference engine config,
runtime and dependencies — into a single self-contained `.erebus` binary.
Every execution leaves a **signed receipt** (`.erebus.attest`, spec 2.0:
DSSE envelope over an in-toto statement) proving what executed, where, when,
with which inputs and outputs — hash-chained locally, anchored in a Merkle
transparency log, co-signed by an enrolled machine key, and verifiable with
`erebus verify-attest` **or stock `cosign`**.

```bash
# Build — runtime, app, libraries, weights
erebus build ./my-agent --embed-model models/model.gguf -o agent.erebus

# Sign — Ed25519, fail-cold verification
erebus sign agent.erebus --key my-key.pem

# Enroll this host once — receipts produced here are co-signed by a machine key
erebus enroll --registry $ERE_REGISTRY --token $TOKEN

# Run with a receipt (or `serve --attest-key`: one receipt per inference call)
ERE_ATTEST_KEY=my-key ./agent.erebus < input.json

# Verify — operator signature, machine identity, transparency-log proof, offline
erebus verify-attest agent.erebus.attest --bundle agent.erebus --strict --proof

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
| exec / `serve --attest-key` | signs a spec 2.0 receipt (artifact hashes, provenance, `input_hash`/`output_hash`/`exit_code`, `rootfs_root`, previous receipt hash) with the operator key and the enrolled machine key | end user (automatically) |
| `attest --push` | detached receipt, published to the registry's Merkle transparency log; inclusion proof + signed checkpoint + RFC 3161 token stored as `<receipt>.proof.json` | developer / auditor |
| `verify-attest` | 1.x and 2.0 receipts; `--chain` trails, `--proof` log proofs, `--strict` machine identity — all offline | auditor |
| `publish` / `pull` | registry upload; streamed download verified against index SHA-256 | developer ↔ users |
| `serve` / exec | stub verifies SHA-256 → mmap-lazy payload → cache extraction → GPU probe → engine launch | end user |

## Key features

- **Verifiable receipts** — spec 2.0 DSSE/in-toto envelopes (JCS canonical),
  operator + machine co-signature, hash-chained trail, Merkle transparency
  log with RFC 3161 anchoring; `cosign verify-blob-attestation` says
  `Verified OK` ([spec](./spec/attestation.md)).
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
| Python | `requirements.txt`, `pyproject.toml`, `app.py`, `main.py`, ... | FastAPI/Flask agents, tools |
| Binary | executable present (ELF/PE) | llama.cpp engines, Go/Rust servers |

Cross-platform launcher stubs are built with cargo-zigbuild; any host can
target any platform.

## Status

The **P0 proof chain is complete** (2026-09-17): hardened verifier, hash-chained
trail, attesting proxy, warm-cache re-verification, Merkle transparency log
with external anchoring, machine identity, standard DSSE/in-toto envelope
with cosign interop. Distribution features (universal binary,
OpenAI-compatible serving, registry, Agentfile, GPU auto-detect, chat UI,
SISR deltas, sandboxing) are implemented and validated. Next: P1 — the demo
and chaos batteries run in CI, evidence export. See
[ROADMAP](https://github.com/Tednoob17/erebus/blob/main/ROADMAP.md) and
[benchmarks](https://github.com/Tednoob17/erebus/tree/main/benchmarks).

## Get started

```bash
git clone https://github.com/Tednoob17/erebus.git && cd erebus
cargo build --release
./target/release/erebus doctor
```

Continue with [The Problem](./concepts/problem.md) for the why, or jump to
the [SISR overview](./concepts/sisr-overview.md) for delta updates.