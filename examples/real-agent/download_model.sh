#!/usr/bin/env bash
# Download a small GGUF model for the real-agent demo
set -euo pipefail

MODELS_DIR="$(dirname "$0")/models"
mkdir -p "$MODELS_DIR"

# Option 1: TinyLlama 1.1B Q4_K_S (~630MB)
# wget -O "$MODELS_DIR/model.gguf" "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_S.gguf"

# Option 2: Qwen 0.8B Q8_0 (~900MB) - from llamafile repo
# wget -O "$MODELS_DIR/model.gguf" "https://huggingface.co/mozilla-ai/llamafile_0.10.0/resolve/main/Qwen3.5-0.8B-Q8_0.llamafile"

# Option 3: SmolLM 1.7B Q4_K_M (~1GB)
# wget -O "$MODELS_DIR/model.gguf" "https://huggingface.co/HuggingFaceTB/SmolLM-1.7B-Instruct-GGUF/resolve/main/smollm-1.7b-instruct.Q4_K_M.gguf"

echo "Choose a model to download:"
echo "1) TinyLlama 1.1B Q4_K_S (~630MB) - fastest"
echo "2) Qwen 0.8B Q8_0 (~900MB)"
echo "3) SmolLM 1.7B Q4_K_M (~1GB)"
read -p "Enter choice [1-3]: " choice

case $choice in
    1)
        url="https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_S.gguf"
        ;;
    2)
        url="https://huggingface.co/mozilla-ai/llamafile_0.10.0/resolve/main/Qwen3.5-0.8B-Q8_0.llamafile"
        ;;
    3)
        url="https://huggingface.co/HuggingFaceTB/SmolLM-1.7B-Instruct-GGUF/resolve/main/smollm-1.7b-instruct.Q4_K_M.gguf"
        ;;
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

echo "Downloading from $url..."
wget -O models/model.gguf "$url"
echo "Done! Model saved to models/model.gguf"
