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

# Model path - can be overridden by env var
MODEL_PATH = os.environ.get("MODEL_PATH", "/app/models/model.gguf")
LLAMA_CLI = os.environ.get("LLAMA_CLI", "/usr/local/bin/llama-cli")

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
            "--no-display-prompt",
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode != 0:
            return f"Error: {result.stderr}"
        
        # Extract just the generated response (after the prompt)
        output = result.stdout.strip()
        return output
    
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
    return jsonify({
        "status": "ok" if model_exists and llama_exists else "degraded",
        "model_exists": model_exists,
        "llama_cli_exists": llama_exists,
        "model_path": MODEL_PATH,
        "llama_cli_path": LLAMA_CLI
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
