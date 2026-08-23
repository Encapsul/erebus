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

- `app.py` - FastAPI server with llama.cpp inference
- `requirements.txt` - Python dependencies (flask)
- `README.md` - This file

## Model

The agent expects a GGUF model at `/app/models/model.gguf` inside the extracted rootfs.
When building with `--embed-model`, the model is embedded in the payload.

```bash
erebus build . --embed-model model.gguf --embed-interpreter python3 -o agent.erebus
```

## llama.cpp

The agent expects `llama-cli` at `/usr/local/bin/llama-cli`. 
For the demo, you can symlink or copy it there, or build llama.cpp static and embed it as a binary layer.

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
