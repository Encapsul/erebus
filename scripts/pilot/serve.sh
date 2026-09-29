#!/usr/bin/env bash
# Run one T2 node: real model, per-call receipts, immediate registry proofs.
set -euo pipefail

STATE="${ERE_PILOT_STATE:-$HOME/.local/share/erebus/pilot}"
ERE="${ERE_BIN:-erebus}"
PORT="${ERE_PILOT_PORT:-8080}"
REGISTRY="${ERE_PILOT_REGISTRY_URL:-$(cat "$STATE/registry.url" 2>/dev/null || true)}"
TOKEN_FILE="${ERE_PILOT_TOKEN_FILE:-$STATE/registry.token}"
LLAMA_SERVER="${ERE_LLAMA_SERVER:-$(command -v llama-server || true)}"
PID_FILE="$STATE/serve.pid"
LOG_FILE="$STATE/serve.log"

running() {
  [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

set_args() {
  key="$(find "$STATE/keys" -name '*.key' -print -quit)"
  ARGS=(serve "$STATE/baguettotron.erebus" --host 127.0.0.1 --port "$PORT" \
    --ngl off --ctx-size 2048 --no-input --llama-server "$LLAMA_SERVER" \
    --attest-key "$key" --attest-log "$STATE/receipts" --push \
    --registry "$REGISTRY" --token-file "$TOKEN_FILE")
}

start() {
  running && { echo "pilot already running (pid $(cat "$PID_FILE"))"; return; }
  test -x "$LLAMA_SERVER" || { echo "llama-server not found" >&2; exit 1; }
  set_args
  nohup env ERE_MACHINE_DIR="$STATE/machine" ERE_VERBOSE=1 \
    "$ERE" "${ARGS[@]}" >"$LOG_FILE" 2>&1 &
  echo "$!" >"$PID_FILE"
  for _ in $(seq 1 90); do
    curl -fsS --max-time 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
    kill -0 "$(cat "$PID_FILE")" 2>/dev/null || { cat "$LOG_FILE"; exit 1; }
    sleep 1
  done
  curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null
  echo "pilot ready: http://127.0.0.1:$PORT/v1 (pid $(cat "$PID_FILE"))"
}

stop() {
  running && kill -TERM "$(cat "$PID_FILE")"
  rm -f "$PID_FILE"
}

foreground() {
  set_args
  ERE_MACHINE_DIR="$STATE/machine" ERE_VERBOSE=1 exec "$ERE" "${ARGS[@]}"
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) running && echo "running pid=$(cat "$PID_FILE") port=$PORT" || exit 1 ;;
  foreground) foreground ;;
  *) echo "usage: $0 {start|stop|restart|status|foreground}" >&2; exit 2 ;;
esac
