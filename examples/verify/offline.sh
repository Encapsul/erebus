#!/usr/bin/env bash
# Offline verify pack — one command for a receipt + proof + pinned keys.
#
# Usage:
#   ./offline.sh RECEIPT [--bundle BUNDLE] [--log-key HEX] [--strict]
#   ./offline.sh --pack DIR [--bundle BUNDLE] [--log-key HEX] [--strict]
#
# Pack layout (DIR):
#   *.attest or *.json          receipt
#   *.proof.json                transparency-log proof (optional; enables --proof)
#   *.pub or operator.pem       trusted operator / registry keys
#
# Requires `erebus` on PATH (or set EREBUS=…). No network.
set -euo pipefail

EREBUS="${EREBUS:-erebus}"
PACK=""
RECEIPT=""
BUNDLE=""
LOG_KEY=""
STRICT=0
EXTRA=()

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pack) PACK="${2:?}"; shift 2 ;;
    --bundle) BUNDLE="${2:?}"; shift 2 ;;
    --log-key) LOG_KEY="${2:?}"; shift 2 ;;
    --strict) STRICT=1; shift ;;
    -h|--help) usage ;;
    --) shift; EXTRA+=("$@"); break ;;
    -*) echo "unknown flag: $1" >&2; usage ;;
    *)
      if [[ -z "$RECEIPT" && -z "$PACK" ]]; then RECEIPT="$1"; shift
      else EXTRA+=("$1"); shift; fi
      ;;
  esac
done

tmpdir=""
cleanup() { [[ -n "$tmpdir" ]] && rm -rf "$tmpdir"; }
trap cleanup EXIT

if [[ -n "$PACK" ]]; then
  [[ -d "$PACK" ]] || { echo "not a directory: $PACK" >&2; exit 1; }
  RECEIPT="$(find "$PACK" -maxdepth 1 \( -name '*.attest' -o -name '*.json' \) ! -name '*.proof.json' ! -name 'MANIFEST.json' | head -1)"
  [[ -n "$RECEIPT" ]] || { echo "no receipt in $PACK" >&2; exit 1; }
  trusted="$PACK"
else
  [[ -n "$RECEIPT" && -f "$RECEIPT" ]] || usage
  tmpdir="$(mktemp -d)"
  trusted="$tmpdir/trusted"
  mkdir -p "$trusted"
  # Sibling .pub / keys next to the receipt, if any
  rdir="$(cd "$(dirname "$RECEIPT")" && pwd)"
  shopt -s nullglob
  for f in "$rdir"/*.pub "$rdir"/operator.pem; do
    [[ -f "$f" ]] && cp "$f" "$trusted/"
  done
  shopt -u nullglob
fi

proof="${RECEIPT}.proof.json"
args=(verify-attest "$RECEIPT" --trusted-dir "$trusted")
[[ -n "$BUNDLE" ]] && args+=(--bundle "$BUNDLE")
[[ -n "$LOG_KEY" ]] && args+=(--log-key "$LOG_KEY")
[[ "$STRICT" -eq 1 ]] && args+=(--strict)
if [[ -f "$proof" ]]; then
  args+=(--proof --proof-file "$proof")
fi
args+=("${EXTRA[@]}")

echo "+ $EREBUS ${args[*]}"
exec "$EREBUS" "${args[@]}"
