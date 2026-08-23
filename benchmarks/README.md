# Benchmarks & validation E2E

Numbers measured on the actual project tooling, with the exact commands to
reproduce each one. All runs share this environment unless noted:

| Item | Value |
|---|---|
| Host | shared VPS, 8 vCPU, 7.9 GB RAM, 97 GB disk (noisy neighbors: load avg 6-13 observed) |
| OS | Ubuntu 22.04 (glibc 2.35) |
| Toolchain | stable-x86_64-unknown-linux-gnu |
| Inference engine | llama.cpp official release `b10595` (`llama-server`, prebuilt ubuntu-x64) |
| Model | TinyLlama-1.1B-Chat `Q4_K_M` GGUF — 668,788,096 bytes |

Reproduction scripts:

- `scripts/chaos_monkey.sh [N]` — adversarial corruption + SIGKILL harness
- `scripts/registry_server.py --dir <dir> --port 8787` — registry under test
- commands inline in each section below

Sections:

1. [`serve.md`](serve.md) — OpenAI-compatible serving: cold start, warm latency, multi-format matrix
2. [`universal.md`](universal.md) — cross-compilation times, slice sizes, one-file-many-platforms proof
3. [`security.md`](security.md) — zeroization audit outcome, crypto chaos properties, process chaos monkey

Ground rules honored by every number here:

- Wall-clock times from a cold process start unless labeled *warm*.
- Cache state is stated explicitly (content-addressed hit vs fresh extraction).
- Failed/interrupted runs are documented too (e.g. the truncated-download
  incident that llama.cpp correctly rejected — see serve.md).
