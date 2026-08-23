# `erebus serve` — OpenAI-compatible endpoint

## Cold start (fresh extraction + engine init)

Bundle: TinyLlama Q4_K_M embedded via `--embed-model` (payload 643 MB,
`.erebus` file 611-643 MB). First serve run extracts to
`~/.cache/erebus/serve/<sha256>/rootfs`, then launches `llama-server`.

```bash
erebus build . --embed-model model.gguf --isolation none -o tinyllama.erebus
time erebus serve tinyllama.erebus --port 8123 --ngl 0 --ctx-size 512 --threads 4 \
     --llama-server /path/to/llama-server
# wait until "OpenAI-compatible endpoint ready"
curl -s http://127.0.0.1:8123/v1/models
```

| Phase | Observed |
|---|---|
| Bundle build (634 MB model, zstd L3) | **82 s** wall |
| Extraction of 634 MB payload into cache | ~15 s (streamed, bounded RAM) |
| llama.cpp model load + warmup (CPU) | ~20 s |
| **Total cold → `/health` 200** | **< 45 s** |

## Warm latency

Second request after server is up (prompt cached by OS page cache):

```bash
time curl -s http://127.0.0.1:8123/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"local","messages":[{"role":"user","content":"What is 2+2?"}],"max_tokens":10}'
```

| Request | Wall | Output |
|---|---|---|
| `"What is 2+2?"`, max_tokens=10 | **4.8 s** | `2 + 2 = 4` |
| `"Say hello in one short sentence."`, max_tokens=40 | 11.3 s | `Hey, it's you!` (9 completion tokens) |

Context: CPU-only (`--ngl 0`), 4 threads, ctx=512, noisy shared host.
Throughput ≈ 1-2 tok/s on this box; expect order-of-magnitude better on a GPU.

## Cache hit

Second `serve` invocation of the same bundle skips extraction entirely
(`.ready` marker in the content-addressed dir):

```
[erebus] serve: cache hit /home/.../erebus/serve/<sha256>/rootfs
```

## Multi-format engine matrix

Detection lives in `erebus-core/src/inference.rs`; every row has unit tests
for classification and launch-plan shape. Runtime availability differs per
target machine — `serve` prints the exact install hint when missing:

| Artifacts found | Format | Engine launched | Status |
|---|---|---|---|
| `*.gguf` | GGUF | `llama-server -m … -ngl N …` | ✅ E2E real inference (this doc) |
| `*.safetensors` (+ GPTQ/AWQ quant config) | HF | `python3 -m vllm.entrypoints.openai.api_server` | 🟡 plan tested (unit); needs target vLLM |
| `*.onnx` | ONNX | vLLM (ONNX backend) | 🟡 same as above |
| `*.engine` / `*.plan` | TensorRT-LLM | `trtllm-serve <dir> …` | 🟡 plan tested (unit); GPU-arch locked by nature |
| MLX weights + mlx config | MLX | `mlx_lm.server --model …` | 🟡 Apple-Silicon hardware required |

## Failure handling observed during measurement

A download truncated at 95% (disk-full mid-fetch) produced a corrupted GGUF;
the full chain behaved correctly end-to-end:

- bundle build succeeded (integrity covers packaging, not upstream bytes)
- `serve` verified footer SHA-256 ✓, extracted ✓, launched engine ✓
- llama.cpp rejected the bad tensor with `data is not within the file bounds`
- `erebus serve` surfaced the child failure and exited non-zero

Lesson encoded in docs: verify model checksums before embedding; the launcher
is fail-closed but cannot detect an honestly-wrong source file.
