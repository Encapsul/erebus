#!/usr/bin/env bash
# Enrol this host and build the pinned Baguettotron pilot bundle.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE="${ERE_PILOT_STATE:-$HOME/.local/share/erebus/pilot}"
ERE="${ERE_BIN:-erebus}"
REGISTRY="${ERE_PILOT_REGISTRY_URL:-http://127.0.0.1:8787}"
TOKEN_FILE="${ERE_PILOT_TOKEN_FILE:-$STATE/registry.token}"
MODEL="${ERE_PILOT_MODEL:-$HOME/.cache/erebus-pilot/models/Baguettotron-Q8_0.gguf}"
MODEL_SHA="ea9cb32db8fbfc173671980dbd06260fd1866eb5e2da09d5583e43b0aceab4b6"
MODEL_REV="417add62dcb9306db614d7dbb39d206c4c8f854b"
MODEL_URL="https://huggingface.co/PleIAs/Baguettotron-GGUF/resolve/$MODEL_REV/Baguettotron-Q8_0.gguf"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

download_model() {
  mkdir -p "$(dirname "$MODEL")"
  if [ ! -f "$MODEL" ] || [ "$(sha256 "$MODEL")" != "$MODEL_SHA" ]; then
    curl -fL --retry 3 -o "$MODEL.part" "$MODEL_URL"
    test "$(sha256 "$MODEL.part")" = "$MODEL_SHA"
    mv "$MODEL.part" "$MODEL"
  fi
}

create_app() {
  mkdir -p "$STATE/app"
  cat >"$STATE/app/app.py" <<'PY'
print("Baguettotron is served by `erebus serve`; this batch entrypoint is a placeholder.")
PY
}

operator_key() {
  mkdir -p "$STATE/keys" "$STATE/trusted"
  if ! compgen -G "$STATE/keys/*.key" >/dev/null; then
    "$ERE" keygen --key-dir "$STATE/keys"
  fi
  cp "$STATE"/keys/*.pub "$STATE/trusted/"
  find "$STATE/keys" -name '*.key' -print -quit
}

main() {
  # A service user often cannot read the caller's cwd (sudo -u from $HOME).
  cd "$ROOT"
  test -s "$TOKEN_FILE" || { echo "missing token: $TOKEN_FILE" >&2; exit 1; }
  download_model
  create_app
  export ERE_MACHINE_DIR="$STATE/machine"
  "$ERE" enroll --registry "$REGISTRY" --token-file "$TOKEN_FILE" --json >"$STATE/enroll.json"
  key="$(operator_key)"
  "$ERE" build "$STATE/app" --embed-model "$MODEL" \
    --force -o "$STATE/baguettotron.erebus"
  "$ERE" sign "$STATE/baguettotron.erebus" --key "$key"
  printf '%s\n' "$REGISTRY" >"$STATE/registry.url"
  printf '%s\n' "$MODEL_SHA" >"$STATE/model.sha256"
  echo "node ready: $STATE/baguettotron.erebus"
  echo "next: ERE_PILOT_STATE=$STATE $ROOT/scripts/pilot/serve.sh"
}

main "$@"
