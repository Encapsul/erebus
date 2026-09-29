#!/usr/bin/env bash
# Send one real inference call; `serve --push` records and anchors it.
set -euo pipefail

STATE="${ERE_PILOT_STATE:-$HOME/.local/share/erebus/pilot}"
PORT="${ERE_PILOT_PORT:-8080}"
mkdir -p "$STATE/probes"

request="$(python3 -c 'import json,sys
question = " ".join(sys.argv[1:]) or "Explique en une phrase pourquoi une preuve d’exécution est utile."
print(json.dumps({
  "model": "local",
  "messages": [{"role": "user", "content": question}],
  "temperature": 0.4,
  "max_tokens": 96
}))' "$@")"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
response="$STATE/probes/$stamp.json"
curl -fsS --max-time 180 "http://127.0.0.1:$PORT/v1/chat/completions" \
  -H 'Content-Type: application/json' -d "$request" | tee "$response"
echo
echo "response: $response"
