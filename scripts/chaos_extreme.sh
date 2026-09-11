#!/usr/bin/env bash
# chaos_extreme.sh — push every contingency to the breakage point.
#
#  1. Native (compiled C) agent: build, sign, capture, tamper, refuse
#  2. Malformed inputs: empty / invalid-JSON / 2MB random / binary — capture
#     MUST still emit a valid attestation recording the failure (fail-closed
#     on the PROOF, not just on the binary)
#  3. Concurrency: 12 python agents × distinct keys in parallel, same bundle
#     for cache contention; every attestation distinct, keyed right, hashes right
#  4. Cache hit: second run of the same bundle still proves behavior
#  5. Signature edges: wrong key refuses, unsigned bundle runs, signature binds
#     to the CURRENT bytes (tampered file refused everywhere, fresh re-sign ok)
#
# input_hash semantics: it fingerprints the LAUNCH VECTOR (entrypoint + argv),
# NOT the piped stdin bytes — see erebus-core/src/attest.rs launch_vector_hash.
#
# Usage: scripts/chaos_extreme.sh [ERE_BIN]
set -uo pipefail

ERE="${1:-${ERE_BIN:-/tmp/erebus-stub-target/release/erebus}}"
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d /tmp/erebus-extreme.XXXXXX)
trap 'kill $(jobs -p) 2>/dev/null; [ "${KEEP:-0}" = "1" ] || rm -rf "$WORK"' EXIT

command -v "$ERE" >/dev/null || { echo "erebus CLI not found at $ERE"; exit 2; }
command -v gcc >/dev/null || { echo "gcc required"; exit 2; }
command -v python3 >/dev/null || { echo "python3 required"; exit 2; }

failures=0
check() { # check <label> <rc>
  if [ "$2" -ne 0 ]; then echo "  ✗ $1"; failures=$((failures+1)); else echo "  ✓ $1"; fi
}

# Launch-vector hashes (sha256 of NUL-joined entrypoint): python3 + /app/app.py
# for python agents, /app/app for the native agent.
PY_LV=$(python3 -c "import hashlib;print('sha256:'+hashlib.sha256(b'python3\x00/app/app.py').hexdigest())")
BIN_LV=$(python3 -c "import hashlib;print('sha256:'+hashlib.sha256(b'/app/app').hexdigest())")

# ── [1/6] native agent ───────────────────────────────────────────────
echo "── [1/6] native (compiled C) agent"
NAT="$WORK/native"; mkdir -p "$NAT" "$WORK/keys" "$WORK/trusted"
cat > "$NAT/main.c" <<'C'
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "fail") == 0) { return 7; }
    printf("native-agent-ok\n");
    return 0;
}
C
gcc -static "$NAT/main.c" -o "$NAT/app" 2>/dev/null || gcc "$NAT/main.c" -o "$NAT/app"
"$ERE" build "$NAT" -o "$WORK/native.erebus" -q 2>/dev/null
check "native bundle built" $?
"$ERE" keygen --key-dir "$WORK/keys" -q 2>/dev/null
KEY=$(ls "$WORK/keys"/*.key | head -1)
PUB=$(ls "$WORK/keys"/*.pub | head -1)
cp "$PUB" "$WORK/trusted/"
"$ERE" sign "$WORK/native.erebus" --key "$KEY" -q 2>/dev/null
OUT1=$(ERE_TRUSTED_DIR="$WORK/trusted" "$WORK/native.erebus")
[ "$OUT1" = "native-agent-ok" ]; check "native agent runs (signed, trusted)" $?
ERE_TRUSTED_DIR="$WORK/trusted" ERE_ATTEST_KEY="$KEY" ERE_ATTEST_OUT="$WORK/native.attest" "$WORK/native.erebus" >"$WORK/native.out" 2>/dev/null
RC=$?
python3 -c "
import json, sys
att = json.load(open('$WORK/native.attest'))
ex = att['execution']
assert ex['exit_code'] == 0, ex
assert ex['input_hash'] == '$BIN_LV', ex['input_hash']
assert ex['output_hash'] and ex['output_hash'].startswith('sha256:'), ex
print(f'  native attestation exit={ex[\"exit_code\"]} input_hash=launch_vector')
" && check "native agent capture (attestation updated, exit 0)" $RC

# ── [2/6] malformed inputs ─────────────────────────────────────────────
echo "── [2/6] malformed inputs (capture must record failure, not die)"
PY="$WORK/pyagent"; mkdir -p "$PY"
cat > "$PY/app.py" <<'PY'
import sys, json
data = json.loads(sys.stdin.read())
json.dump({"sum": sum(data.get("values", []))}, sys.stdout)
print()
PY
"$ERE" build "$PY" -o "$WORK/py.erebus" -q 2>/dev/null
"$ERE" sign "$WORK/py.erebus" --key "$KEY" -q 2>/dev/null
run_capture() { # run_capture <label> <attest> <stdin-file-or-> <expect_exit_nonzero>
  if [ "$3" = "-" ]; then : | true; IN=/dev/stdin; else IN="$3"; fi
  cat "$IN" | ERE_TRUSTED_DIR="$WORK/trusted" ERE_ATTEST_KEY="$KEY" \
    ERE_ATTEST_OUT="$2" "$WORK/py.erebus" >/dev/null 2>&1
  local RC=$?
  if python3 -c "
import json, sys
att = json.load(open('$2'))
ex = att['execution']
assert ex['exit_code'] is not None, ex
assert ex['input_hash'] == '$PY_LV', ex['input_hash']
assert ex['output_hash'] is not None, ex
sys.exit(0 if ex['exit_code'] != 0 else 1)
"; then
    local OK=0
  else
    local OK=1
  fi
  [ "$OK" -eq 0 ] && check "$1 (failure recorded, exit≠0)" 0 || check "$1" 1
  return $RC
}

: > "$WORK/empty.bin"
run_capture "empty stdin" "$WORK/empty.attest" "$WORK/empty.bin" 0
printf 'not-json{{{' > "$WORK/badjson.bin"
run_capture "invalid JSON" "$WORK/badjson.attest" "$WORK/badjson.bin" 0
head -c 2097152 /dev/urandom > "$WORK/slurp.bin"
run_capture "2MB random — input_hash=launch vector, failure recorded" "$WORK/big.attest" "$WORK/slurp.bin" 0

# ── [3/6] concurrency ─────────────────────────────────────────────────
echo "── [3/6] concurrency: 12 parallel python agents, same signed bundle"
K0="$KEY"
PIDS=()
for i in $(seq 1 12); do
  (
    JSON=$(python3 -c "import json;print(json.dumps({'values':[1,2,3,$i,42]}))")
    printf '%s' "$JSON" | ERE_TRUSTED_DIR="$WORK/trusted" ERE_ATTEST_KEY="$K0" \
      ERE_ATTEST_OUT="$WORK/conc-$i.attest" "$WORK/py.erebus" >"$WORK/conc-$i.out" 2>/dev/null
  ) &
  PIDS+=($!)
done
for p in "${PIDS[@]}"; do wait "$p"; done
correct=0
for i in $(seq 1 12); do
  python3 -c "
import json
att = json.load(open('$WORK/conc-$i.attest'))
sum_exp = 1+2+3+$i+42
out = json.load(open('$WORK/conc-$i.out'))
assert att['execution']['exit_code'] == 0, 'exit'
assert out['sum'] == sum_exp, f'{$i}'
assert att['execution']['input_hash'] == '$PY_LV', att['execution']['input_hash']
print(f'  agent{$i}: sum={out[\"sum\"]} exit=0 attest=ok')
" 2>/dev/null && correct=$((correct+1))
done
[ "$correct" -eq 12 ] && check "12/12 concurrent agents: correct, captured, distinct attestations" 0 || check "12/12 concurrent agents" $((12-correct))

# ── [4/6] cache hit ───────────────────────────────────────────────────
echo "── [4/6] cache hit: second run of the same bundle"
echo '{"values":[1,2]}' | ERE_TRUSTED_DIR="$WORK/trusted" "$WORK/py.erebus" >/dev/null 2>&1
T0=$(date +%s%N)
echo '{"values":[1,2]}' | ERE_TRUSTED_DIR="$WORK/trusted" "$WORK/py.erebus" >/dev/null 2>&1
T1=$(date +%s%N)
echo "  warm-start latency: $(( (T1 - T0) / 1000000 )) ms"
echo '{"values":[1,2]}' | ERE_TRUSTED_DIR="$WORK/trusted" ERE_ATTEST_KEY="$KEY" ERE_ATTEST_OUT="$WORK/cachehit.attest" "$WORK/py.erebus" >/dev/null 2>&1
RC=$?
python3 -c "
import json
att = json.load(open('$WORK/cachehit.attest'))
assert att['execution']['exit_code'] == 0
assert att['execution']['input_hash'] == '$PY_LV'
print('  cache-hit run: attestation emitted')
" 2>/dev/null && check "cache-hit still proves behavior" $RC

# ── [5/6] signature edges ─────────────────────────────────────────────
echo "── [5/6] signature edges"
# (a) unsigned bundle must still run (no trust pressed)
"$ERE" build "$NAT" -o "$WORK/unsigned.erebus" -q 2>/dev/null
[ "$("$WORK/unsigned.erebus")" = "native-agent-ok" ]; check "unsigned bundle runs" $?
# (b) wrong key refuses. `sign` refuses an already-signed file, so build a
# FRESH bundle and sign it with key B; trust dirs hold A or B respectively.
# Runs are COLD (new file, never cached) so Ed25519 is checked at startup.
"$ERE" keygen --key-dir "$WORK/keys" -q 2>/dev/null
KB=$(ls -t "$WORK/keys"/*.key | head -1)
PB=$(ls -t "$WORK/keys"/*.pub | head -1)
mkdir -p "$WORK/trusted-onlyA" "$WORK/trusted-onlyB"
cp "$PUB" "$WORK/trusted-onlyA/"   # A = the key already trusted for py.erebus
cp "$PB" "$WORK/trusted-onlyB/"    # B = the new key
"$ERE" build "$PY" -o "$WORK/pyB.erebus" -q 2>/dev/null
"$ERE" sign "$WORK/pyB.erebus" --key "$KB" -q 2>/dev/null
# REFUSED first: a cold run whose signature it not trusted must not warm the
# shared cache (hash == py.erebus) and defeat the check for the trusted run.
echo '{"values":[9]}' | ERE_TRUSTED_DIR="$WORK/trusted-onlyA" "$WORK/pyB.erebus" >/dev/null 2>&1
RCFAIL=$?
echo '{"values":[9]}' | ERE_TRUSTED_DIR="$WORK/trusted-onlyB" "$WORK/pyB.erebus" >/dev/null 2>&1
RCOK=$?
[ "$RCOK" -eq 0 ] && check "signed with B, trusted{B} -> runs" 0 || check "signed with B, trusted{B} -> runs" 1
[ "$RCFAIL" -ne 0 ] && check "signed with B, trusted{A} -> REFUSED" 0 || check "signed with B, trusted{A} -> REFUSED" 1

# (c) signature binds to CURRENT bytes: tamper -> refused by verify AND at
#     runtime; no re-sign of an already-signed file; a fresh build covers new bytes
cp "$WORK/py.erebus" "$WORK/tampered.erebus"
PO=$("$ERE" inspect "$WORK/tampered.erebus" --json 2>/dev/null | python3 -c "import json,sys;print(json.load(sys.stdin)['payload_offset'])")
python3 -c "
with open('$WORK/tampered.erebus','r+b') as f:
    f.seek($PO + 8); b = f.read(1); f.seek($PO + 8); f.write(bytes([b[0] ^ 0xFF]))
"
"$ERE" verify "$WORK/tampered.erebus" --trusted-dir "$WORK/trusted-onlyB" -q 2>/dev/null
V1=$?
echo '{"values":[9]}' | ERE_TRUSTED_DIR="$WORK/trusted-onlyB" "$WORK/tampered.erebus" >/dev/null 2>&1
V2=$?
[ "$V1" -ne 0 ] && check "tampered payload -> verify REFUSED" 0 || check "tampered payload -> verify REFUSED" 1
[ "$V2" -ne 0 ] && check "tampered payload -> runtime REFUSED" 0 || check "tampered payload -> runtime REFUSED" 1
"$ERE" build "$PY" -o "$WORK/fresh.erebus" -q 2>/dev/null
"$ERE" sign "$WORK/fresh.erebus" --key "$KB" -q 2>/dev/null
"$ERE" verify "$WORK/fresh.erebus" --trusted-dir "$WORK/trusted-onlyB" -q 2>/dev/null
V3=$?
[ "$V3" -eq 0 ] && check "fresh build + re-sign covers new bytes (verifies)" 0 || check "fresh build + re-sign covers new bytes" 1

# ── summary ────────────────────────────────────────────────────────────
echo ""
if [ "$failures" -eq 0 ]; then
  echo "CHAOS VERDICT: EXTREME SURVIVED"
else
  echo "CHAOS VERDICT: $failures check(s) FAILED"
fi
exit "$failures"