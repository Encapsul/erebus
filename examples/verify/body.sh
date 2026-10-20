#!/usr/bin/env bash
# TrustNotch-style body binding smoke — offline.
#
# Verifies a served-call receipt against the plaintext request and response
# an auditor was handed (`--request-body` / `--response-body`), then refuses
# forged bodies (exit 2 / TAMPERED). Does not prove the model computed the
# answer — only that these bytes match the signed digests and tool fields.
#
# Usage:
#   ./body.sh
#   EREBUS=/path/to/erebus ./body.sh
#
# Fixtures live under body/ (public key + receipt + bodies; no private key).
set -euo pipefail

EREBUS="${EREBUS:-erebus}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BODY="$HERE/body"
RECEIPT="$BODY/call.attest"
REQ="$BODY/request.json"
RESP="$BODY/response.json"
TRUSTED="$BODY"

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && usage
command -v "$EREBUS" >/dev/null 2>&1 || {
  echo "erebus not on PATH (set EREBUS=…)" >&2
  exit 1
}
for f in "$RECEIPT" "$REQ" "$RESP" "$TRUSTED/operator.pub"; do
  [[ -f "$f" ]] || { echo "missing fixture: $f" >&2; exit 1; }
done

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

echo "+ honest: request + response bodies"
"$EREBUS" verify-attest "$RECEIPT" \
  --trusted-dir "$TRUSTED" \
  --request-body "$REQ" \
  --response-body "$RESP"

echo "+ forged response body must be refused"
python3 -c "
from pathlib import Path
import sys
src = Path(sys.argv[1]).read_text()
Path(sys.argv[2]).write_text(src.replace('get_weather', 'rm_rf', 1))
" "$RESP" "$tmpdir/forged-response.json"
set +e
out="$("$EREBUS" verify-attest "$RECEIPT" \
  --trusted-dir "$TRUSTED" \
  --response-body "$tmpdir/forged-response.json" 2>&1)"
rc=$?
set -e
echo "$out"
[[ "$rc" -eq 2 ]] || { echo "expected exit 2, got $rc" >&2; exit 1; }
echo "$out" | grep -q 'TAMPERED: response body mismatch' || {
  echo "expected TAMPERED: response body mismatch" >&2
  exit 1
}

echo "+ forged request body must be refused"
python3 -c "
from pathlib import Path
import sys
src = Path(sys.argv[1]).read_text()
Path(sys.argv[2]).write_text(src.replace('18C, sunny', '35C, storm', 1))
" "$REQ" "$tmpdir/forged-request.json"
set +e
out="$("$EREBUS" verify-attest "$RECEIPT" \
  --trusted-dir "$TRUSTED" \
  --request-body "$tmpdir/forged-request.json" 2>&1)"
rc=$?
set -e
echo "$out"
[[ "$rc" -eq 2 ]] || { echo "expected exit 2, got $rc" >&2; exit 1; }
echo "$out" | grep -q 'TAMPERED: request body mismatch' || {
  echo "expected TAMPERED: request body mismatch" >&2
  exit 1
}

echo "OK: body binding holds (honest accept, forged refuse)"
