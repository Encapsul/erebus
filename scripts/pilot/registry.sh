#!/usr/bin/env bash
# Persistent T2 transparency registry. State and credentials stay outside git.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE="${ERE_PILOT_STATE:-$HOME/.local/share/erebus/pilot}"
HOST="${ERE_PILOT_REGISTRY_HOST:-127.0.0.1}"
PORT="${ERE_PILOT_REGISTRY_PORT:-8787}"
PUBLIC_URL="${ERE_PILOT_REGISTRY_URL:-http://127.0.0.1:$PORT}"
TSA_URL="${ERE_PILOT_TSA_URL:-https://freetsa.org/tsr}"
PID_FILE="$STATE/registry.pid"
TOKEN_FILE="$STATE/registry.token"
LOG_FILE="$STATE/registry.log"

running() {
  [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

wait_ready() {
  for _ in $(seq 1 60); do
    curl -fsS --max-time 2 "$PUBLIC_URL/health" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "registry did not become ready; see $LOG_FILE" >&2
  return 1
}

register_operator() {
  [ -s "$TOKEN_FILE" ] && return
  PILOT_REGISTRY="$PUBLIC_URL" PILOT_TOKEN_FILE="$TOKEN_FILE" python3 - <<'PY'
import json, os, secrets, urllib.request

url = os.environ["PILOT_REGISTRY"] + "/auth/register"
body = json.dumps({"username": "pilot", "password": secrets.token_urlsafe(32)}).encode()
req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
token = json.loads(urllib.request.urlopen(req, timeout=10).read())["token"]
path = os.environ["PILOT_TOKEN_FILE"]
with open(path, "w", encoding="utf-8") as handle:
    handle.write(token + "\n")
os.chmod(path, 0o600)
PY
}

start() {
  mkdir -p "$STATE/registry"
  if running; then
    echo "registry already running (pid $(cat "$PID_FILE"))"
    return
  fi
  nohup python3 "$ROOT/scripts/registry_server.py" \
    --dir "$STATE/registry" --host "$HOST" --port "$PORT" \
    --log-origin "erebus-t2-pilot" --tsa-url "$TSA_URL" --anchor-every 1 \
    >"$LOG_FILE" 2>&1 &
  echo "$!" >"$PID_FILE"
  wait_ready
  register_operator
  curl -fsS "$PUBLIC_URL/log/key" >"$STATE/registry-key.json"
  printf 'registry=%s\nstate=%s\ntoken_file=%s\n' "$PUBLIC_URL" "$STATE" "$TOKEN_FILE"
}

stop() {
  running && kill "$(cat "$PID_FILE")"
  rm -f "$PID_FILE"
}

case "${1:-status}" in
  start) start ;;
  stop) stop ;;
  restart) stop; start ;;
  status) running && echo "running pid=$(cat "$PID_FILE") url=$PUBLIC_URL" || exit 1 ;;
  *) echo "usage: $0 {start|stop|restart|status}" >&2; exit 2 ;;
esac
