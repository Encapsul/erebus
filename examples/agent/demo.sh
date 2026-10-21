#!/usr/bin/env bash
# One-command demo: fake LLM + fake MCP → attested agent run (+ stream).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
cd "$ROOT"

if [[ -z "${EREBUS:-}" ]]; then
  TARGET="$(cargo metadata --no-deps --format-version 1 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
  EREBUS="${TARGET}/debug/erebus"
  if [[ ! -x "$EREBUS" ]]; then
    cargo build -q -p erebus-cli
  fi
fi
if [[ ! -x "$EREBUS" ]]; then
  echo "cannot find erebus binary (set EREBUS=...)" >&2
  exit 1
fi

DIR="$(mktemp -d "${TMPDIR:-/tmp}/erebus-agent-demo.XXXXXX")"
cleanup() { kill "${LLM_PID:-}" 2>/dev/null || true; rm -rf "$DIR"; }
trap cleanup EXIT

python3 "$ROOT/examples/agent/fake_llm.py" >"$DIR/port" &
LLM_PID=$!
for _ in $(seq 1 50); do
  [[ -s "$DIR/port" ]] && break
  sleep 0.05
done
PORT="$(tr -d '[:space:]' <"$DIR/port")"
BASE="http://127.0.0.1:${PORT}"

"$EREBUS" keygen --key-dir "$DIR/keys" >/dev/null
KEY="$(find "$DIR/keys" -name '*.key' | head -1)"
MCP_SPEC="[\"python3\",\"$ROOT/examples/agent/fake_mcp.py\"]"

echo "[demo] LLM at $BASE; MCP stdio fake_mcp.py" >&2
echo "[demo] agent trail → $DIR/run.attest.d ; tool trail → $DIR/run.tools.attest.d" >&2
echo "[demo] Receipt proves execution/bytes/tools — NOT task success." >&2

"$EREBUS" agent run \
  --provider openai-compat \
  --base-url "$BASE" \
  --model fake \
  --task "What is the weather in Paris?" \
  --attest-key "$KEY" \
  --attest-log "$DIR/run.attest.d" \
  --tool-trail "$DIR/run.tools.attest.d" \
  --mcp-stdio "$MCP_SPEC" \
  --allow-mcp \
  --stream \
  --response-body "$DIR/last.json" \
  --require-tool-execution

echo "[demo] verify last receipt + tool trail:" >&2
LAST="$(ls "$DIR/run.attest.d"/*.json | sort | tail -1)"
"$EREBUS" verify-attest "$LAST" --trusted-dir "$DIR/keys" --response-body "$DIR/last.json"
"$EREBUS" verify-attest \
  --chain "$DIR/run.attest.d" \
  --trusted-dir "$DIR/keys" \
  --tool-trail "$DIR/run.tools.attest.d" \
  --require-tool-execution
echo "[demo] OK" >&2
