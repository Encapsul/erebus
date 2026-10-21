#!/usr/bin/env bash
# Smoke: vendored site-packages/ without requirements.txt imports at runtime.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
OUT="${TMPDIR:-/tmp}/erebus-site-packages-only.erebus"
erebus build "${ROOT}/examples/site-packages-only" -o "${OUT}" --force
got="$("${OUT}")"
[[ "${got}" == "hello from vendored site-packages" ]] || {
  echo "FAIL: got '${got}'" >&2
  exit 1
}
echo "OK: site-packages PYTHONPATH smoke"
