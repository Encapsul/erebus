#!/usr/bin/env python3
"""
Real AI Agent with llama.cpp inference.
Run: ./agent.erebus → starts server on port 8000
Interact: curl -X POST http://localhost:8000/infer -d '{"prompt": "Hello"}'
"""
import os
import sys
import json
import subprocess
import tempfile
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)

# Model path - can be overridden by env var. Resolve relative to this file so
# the bundle runs both inside the pivot_root sandbox (/app) and with
# isolation=none (the script sits in ~/.cache/erebus/<hash>/rootfs/app).
APP_DIR = Path(__file__).resolve().parent
MODEL_PATH = os.environ.get("MODEL_PATH", str(APP_DIR / "models" / "model.gguf"))
LLAMA_CLI = os.environ.get("LLAMA_CLI", str(APP_DIR / ".deps" / "llama" / "llama-cli"))
LLAMA_LIB = str(APP_DIR / ".deps" / "llama")

SYSTEM_PROMPT = """You are a helpful AI assistant running locally inside an erebus self-extracting binary.
You have no internet access and run completely offline.
Answer concisely and helpfully."""

def run_inference(prompt: str, max_tokens: int = 512) -> str:
    """Run llama.cpp inference and return the response."""
    try:
        # Build llama-cli command
        cmd = [
            LLAMA_CLI,
            "-m", MODEL_PATH,
            "-p", f"{SYSTEM_PROMPT}\n\nUser: {prompt}\n\nAssistant:",
            "-n", str(max_tokens),
            "--temp", "0.7",
            "--top-p", "0.9",
            "--repeat-penalty", "1.1",
            "-c", "2048",
            "-st",
            "--no-display-prompt",
        ]

        # GPU offload: the erebus stub probes the host at launch and exports
        # ERE_NGL (auto-tuned from VRAM) or the value pinned via --ngl.
        ngl = os.environ.get("ERE_NGL", "")
        if ngl.isdigit() and int(ngl) > 0:
            cmd += ["-ngl", ngl]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "LD_LIBRARY_PATH": LLAMA_LIB + ":" + os.environ.get("LD_LIBRARY_PATH", "")},
        )
        
        if result.returncode != 0:
            return f"Error: {result.stderr}"
        
        # Extract just the generated response (after the prompt)
        output = result.stdout.strip()
        marker = f"User: {prompt}\n\nAssistant:"
        if marker in output:
            output = output.split(marker, 1)[1]
            output = output.split("[ Prompt:", 1)[0]
        return output.strip()
    
    except subprocess.TimeoutExpired:
        return "Error: Inference timed out"
    except FileNotFoundError:
        return f"Error: llama-cli not found at {LLAMA_CLI}"
    except Exception as e:
        return f"Error: {str(e)}"

@app.route("/")
def index():
    return jsonify({
        "status": "ok",
        "agent": "erebus-real-agent",
        "model": os.environ.get("MODEL_PATH", "default"),
        "endpoints": {
            "health": "/health",
            "infer": "/infer (POST)"
        }
    })

@app.route("/health")
def health():
    # Check if model and llama-cli exist
    model_exists = Path(MODEL_PATH).exists()
    llama_exists = Path(LLAMA_CLI).exists() if LLAMA_CLI else False
    gpu = {
        "vendor": os.environ.get("ERE_GPU", "unknown"),
        "vram_mb": os.environ.get("ERE_VRAM_MB"),
        "ngl": os.environ.get("ERE_NGL"),
    }
    return jsonify({
        "status": "ok" if model_exists and llama_exists else "degraded",
        "model_exists": model_exists,
        "llama_cli_exists": llama_exists,
        "model_path": MODEL_PATH,
        "llama_cli_path": LLAMA_CLI,
        "gpu": gpu
    })

@app.route("/infer", methods=["POST"])
def infer():
    if not request.json or "prompt" not in request.json:
        return jsonify({"error": "Missing 'prompt' in request body"}), 400
    
    prompt = request.json["prompt"]
    max_tokens = request.json.get("max_tokens", 512)
    
    response = run_inference(prompt, max_tokens)
    
    return jsonify({
        "status": "ok",
        "prompt": prompt,
        "response": response
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting real AI agent on port {port}", flush=True)
    print(f"Model: {MODEL_PATH}", flush=True)
    print(f"llama-cli: {LLAMA_CLI}", flush=True)
    app.run(host="0.0.0.0", port=port)
