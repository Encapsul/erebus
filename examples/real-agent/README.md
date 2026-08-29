# Real AI Agent Example

A complete AI agent with llama.cpp inference, packaged as a single self-extracting binary.

## Quick Start

```bash
# 1. Download a GGUF model (e.g., 1-2GB for demo)
wget -O model.gguf "https://huggingface.co/mozilla-ai/llamafile_0.10.0/resolve/main/Qwen3.5-0.8B-Q8_0.llamafile"

# 2. Build the agent
erebus build . --embed-interpreter python3 --enable-sisr -o agent.erebus

# 3. Run it
./agent.erebus
# Server starts on http://localhost:8000

# 4. Interact
curl -X POST http://localhost:8000/infer -H "Content-Type: application/json" \
  -d '{"prompt": "Explain quantum computing in simple terms"}'
```

## Files

- `app.py` - Flask server with llama.cpp inference
- `requirements.txt` - Python dependencies (flask)
- `models/model.gguf` - GGUF weights (downloaded, not committed)
- `.deps/llama/` - bundled llama.cpp (`llama-cli` + libs, gitignored)
- `README.md` - This file

## Model

The agent expects a GGUF model at `models/model.gguf` next to `app.py`. When
building, the model is embedded in the payload as a ModelLayer:

```bash
erebus build . --embed-model models/model.gguf -o agent.erebus
```

`app.py` resolves the model and `llama-cli` relative to its own location, so
the same bundle runs inside the pivot_root sandbox (`/app`) and with
`--isolation none` (rootfs under `~/.cache/erebus/<hash>/`).

## llama.cpp

A working `llama-cli` plus its shared libs live in `.deps/llama/` (this is
gitignored; stage it manually, then `erebus build` bundles it). `app.py`
prepends that directory to `LD_LIBRARY_PATH` for the subprocess so the
bundled libs resolve against the system glibc.

## Endpoints

- `GET /` - Agent info
- `GET /health` - Health check (model + llama-cli availability)
- `POST /infer` - Run inference
  ```json
  {"prompt": "Your question here", "max_tokens": 512}
  ```

## SISR Delta Updates

When you update the model or code, use `erebus swap` to create a delta:

```bash
erebus swap agent.erebus app/models/model.gguf --from new-model.gguf -o agent-v2.erebus
```

This creates a delta ~95% smaller than the full model size.
