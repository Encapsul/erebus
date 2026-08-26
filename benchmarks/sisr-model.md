# SISR Model Benchmark — Delta Savings

> Measures the bandwidth savings when updating a large model file inside an
> erebus bundle using SISR (Self-Incremental Sovereign Reconstruction) delta
> updates vs full re-download.

## Test Machine

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
| Type | Synthetic (random bytes + config) |
| Size (v1) | 100 MB |
| Size (v2) | 100 MB |
| Change between v1→v2 | 1% (1 MB of weights) |

## Results

| Metric | Full Re-download | SISR Delta | Savings |
|--------|-------------------|------------|---------|
| Transfer size | 100 MB | ~3 MB | ~97% |
| Cold start (est.) | ~2000ms | ~250ms | ~88% |
| Chunk count | 1526 | ~30 dirty / 1526 total | — |

## How SISR Works

1. **Content-defined chunking (CDC)**: The bundle is split into ~64KB chunks
   using a rolling hash. Each chunk is SHA-256 hashed and stored in a CAS
   (content-addressed store).

2. **Delta manifest**: When the model changes, only the chunks whose content
   changed are included in the delta. The manifest lists which chunks to keep
   (from the current binary) and which to fetch (new chunks).

3. **Atomic reconstruction**: The stub downloads only the dirty chunks,
   verifies each SHA-256, writes them into place, and atomically swaps the
   new binary into the cache.

4. **Zero trust**: Every chunk is hash-verified before execution. A corrupted
   chunk is rejected immediately.

## Reproduction

```bash
# Run with default 100MB model
bash scripts/bench_sisr_model.sh

# Run with larger model (needs more RAM/disk)
bash scripts/bench_sisr_model.sh 500
```

## Scaling Behavior

| Model change % | Dirty chunks | Delta / Full | Savings |
|----------------|--------------|--------------|---------|
| 0.1% | ~0.3% | ~0.6% | ~99.4% |
| 1% | ~2% | ~3% | ~97% |
| 5% | ~8% | ~10% | ~90% |
| 10% | ~16% | ~18% | ~82% |
| 50% | ~50% | ~52% | ~48% |
| 100% | 100% | ~102%* | -2%* |

_*At 100% change, SISR adds ~2% overhead for the manifest. Full re-download
wins. SISR is optimized for small iterative updates — exactly the model
fine-tuning / LoRA workflow._

## vs Alternatives

| Method | Delta size (1% change) | Verification | Offline capable |
|--------|------------------------|--------------|-----------------|
| SISR (erebus) | ~3% of full | SHA-256 per chunk | Yes (CAS local) |
| Git LFS | ~100% (no delta) | SHA-256 per file | No (needs server) |
| rsync | ~1-2% | None (no crypto) | Yes |
| Docker layer diff | ~1-5% | SHA-256 per layer | No (needs registry) |
| Ollama pull | ~100% | None | No |
| HF XetHub | ~1-5% | SHA-256 per chunk | No (needs HF) |

**Key difference**: SISR combines delta efficiency with cryptographic
verification and offline capability. The CAS is local — no server needed
after initial build.

## Key Insight

The real value of SISR isn't just delta size — it's **delta size +
cryptographic verification + offline CAS**. When you update a model:

- **Git LFS / HF XetHub**: Need server access, no per-chunk verification
- **rsync**: Fast delta, but no cryptographic proof of integrity
- **Docker**: Layer diffs are good, but need a registry daemon running
- **SISR**: Delta + SHA-256 per chunk + local CAS + offline capable

For regulated environments (EU AI Act, SOC 2), the per-chunk SHA-256
verification is the differentiator. You can prove to an auditor that
every chunk of the updated model was delivered untampered.
