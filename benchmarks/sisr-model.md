# SISR Model Benchmark — Real Engine Measurement

> Measures the bandwidth savings of updating a large model inside an erebus
> bundle using SISR. These numbers come from driving the **actual
> `SisrEngine::apply_update_with_stats`** through a v1 → v2 update — not a
> heuristic. The reported delta is the sum of chunks the engine really
> fetched (the bytes that would cross the wire); unchanged chunks are copied
> from the running binary (`~/.cache/erebus/<hash>/`) and never transferred.
>
> Repro: `bash scripts/bench_sisr_model.sh [size_mb] [change_pct]`
> (backed by `erebus-core/examples/sisr_bench.rs`).

## Test machine

| Spec | Value |
|------|-------|
| OS | Ubuntu 22.04 (glibc 2.35) |
| CPU | AMD EPYC 9V74 80-Core Processor |
| Cores | 4 |
| RAM | 15 GB |
| Architecture | x86_64 |

## Model

| Property | Value |
|----------|-------|
| Type | **Real GGUF weights** (TinyLlama-1.1B-Chat `Q4_K_M`) — see subsection below; plus deterministic seeded pseudo-random payload (xorshift64) as a scale reference |
| Size | 613 MB (real) / 100 MB (synthetic) |
| Change between v1→v2 | Nested (0.1% / 1% / 5% / 10% of payload) |
| Chunk target | 64 KiB content-defined (FastCDC) |

## Results — measured on a REAL model

> The authoritative number for the pitch: a real 613 MB GGUF model, 1%
> change. Measured by feeding the actual TinyLlama weights (not random
> bytes) through the SISR engine.

| Change | Full re-download | SISR delta (fetched) | Reused chunks | Fetched chunks | Savings |
|--------|------------------|------------------------|---------------|----------------|---------|
| **1%** (6.13 MB) | 613 MB | 6.27 MB | 5022 | 58 | **99.0%** |

> Repro: `cargo run --release --example sisr_bench -- 0 1 examples/real-agent/models/model.gguf`

## Results — synthetic scale reference (100 MB)

| Change | Full re-download | SISR delta (fetched) | Reused chunks | Fetched chunks | Savings |
|--------|------------------|------------------------|---------------|----------------|---------|
| **0.1%** | 100 MB | 0.25 MB | 841 | 1 | **99.8%** |
| **1%**  | 100 MB | 1.28 MB | 833 | 12 | **98.7%** |
| **5%**  | 100 MB | 5.16 MB | 801 | 45 | **94.8%** |
| **10%** | 100 MB | 10.40 MB | 750 | 93 | **89.6%** |

> The delta is the `fetched_bytes` counter from `SisrEngine` — the only data
> that would traverse the network. Because content-defined chunking spans the
> changed region, fetched bytes can slightly exceed the literal changed
> bytes (e.g. a ~1 MB change fetches ~1.28 MB). SISR is optimized for the
> small iterative updates of fine-tuning / LoRA, where the win is ~99%.

## vs Alternatives

| Method | Delta size (1% change) | Verification | Offline capable |
|--------|------------------------|--------------|-----------------|
| **SISR (erebus, measured)** | **~1.3% of full** | SHA-256 per chunk (mandatory) | Yes (local CAS) |
| Git LFS | ~100% (no delta) | SHA-256 per file | No (needs server) |
| rsync | ~1–2% | None (no crypto) | Yes |
| Docker layer diff | ~1–5% | SHA-256 per layer | No (needs registry daemon) |
| Ollama pull | ~100% | None | No |
| HF XetHub | ~1–5% | SHA-256 per chunk | No (needs HF) |

**Key difference**: SISR combines delta efficiency with cryptographic
verification and offline capability. The CAS is local — no server needed
after the initial build.

## Why the measurement is trustworthy

- Runs the production `SisrEngine` code path, not a dimensional estimate.
- Every chunk it fetches is SHA-256-verified before being written; a
  corrupted chunk is rejected immediately. Bandwidth accounting comes from
  the engine's own `bytes_fetched()` counter.
- Deterministic payload + seeded PRNG → reproducible on any machine.
- Honest about the boundary effect: fetched bytes can exceed literal changed
  bytes.

## Reproduction

```bash
# Real model (GGUF weights), 1% change
cargo run --release --example sisr_bench -- 0 1 examples/real-agent/models/model.gguf

# Real engine, 100 MB synthetic payload, 1% change
bash scripts/bench_sisr_model.sh 100 1

# Different size / change%
bash scripts/bench_sisr_model.sh 500 5

# Or run the example directly:
cargo run --release --example sisr_bench -- 100 1
```
