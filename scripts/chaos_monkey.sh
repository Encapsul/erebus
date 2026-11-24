#!/usr/bin/env bash
# chaos_monkey.sh — deterministic, fail-closed fuzz harness for erebus bundles.
#
# Builds a signed encrypted bundle, then hammers corrupted copies through the
# real stub and asserts:
#   1. Mutated authenticated bytes NEVER succeed (exit 0) — fail closed
#   2. The encryption key hex NEVER appears in stderr (no secret leakage)
#   3. No panic / sanitizer / core dump on any input
#   4. No mutated case hangs past the per-case timeout
#   5. Invalid inputs (empty/garbage/footer-only) are rejected cleanly
#   6. Footer magic corruption never produces a false positive
#   7. SIGKILL during startup never poisons subsequent runs (cache self-heal)
#   8. SISR delta bundles survive payload corruption without false positives
#   9. Tampering with the real metadata region is always detected
#  10. Concurrent runs do not corrupt the cache
#
# A clean run is bounded evidence for this seed and iteration count, not proof.
# Failing inputs are kept under the printed artifact directory.
#
# Usage: scripts/chaos_monkey.sh [iterations]
#        ERE_CHAOS_SEED=0xC0FFEE scripts/chaos_monkey.sh 50
set -euo pipefail

ERE="${ERE_BIN:-./target/release/erebus}"
ITER="${1:-50}"
SEED="${ERE_CHAOS_SEED:-0xC0FFEE}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK=$(mktemp -d /tmp/erebus-chaos.XXXXXX)
CASES="$WORK/cases"
FINDINGS="$WORK/findings"
mkdir -p "$CASES" "$FINDINGS"
export ERE_TRUSTED_DIR="$WORK/trust"
mkdir -p "$ERE_TRUSTED_DIR"

FAILURES=0
ABORTED=1
cleanup() { # keep artifacts on failure or abrupt exit
  if [ "$ABORTED" -eq 1 ] || [ "$FAILURES" -ne 0 ]; then
    echo "  artifacts kept at $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

command -v "$ERE" >/dev/null || { echo "erebus CLI not found at $ERE"; exit 2; }
command -v python3 >/dev/null || { echo "python3 required"; exit 2; }
python3 -c 'import ast,sys; ast.parse(open(sys.argv[1]).read())' \
  "$SCRIPT_DIR/chaos_mutators.py"

check() { # check <label> <count-of-violations>
  if [ "$2" -ne 0 ]; then
    echo "  ✗ $1 ($2)"
    FAILURES=$((FAILURES+1))
  else
    echo "  ✓ $1"
  fi
}

echo "── [1/7] building signed encrypted bundle in $WORK"
APP="$WORK/app"
mkdir -p "$APP"
printf 'print("chaos-target-ok")\n' > "$APP/app.py"
if ! "$ERE" build "$APP" --encrypt --isolation none -o "$WORK/target.erebus" >/dev/null 2>&1; then
  echo "  ✗ bundle build failed"
  exit 2
fi

echo "── [2/7] signing target and extracting key hex"
if ! "$ERE" keygen --key-dir "$WORK/keys" >/dev/null 2>&1; then
  echo "  ✗ keygen failed"
  exit 2
fi
KEY=$(find "$WORK/keys" -name '*.key' -print | head -1)
[ -n "$KEY" ] || { echo "  ✗ no signing key generated"; exit 2; }
cp "$WORK/keys"/*.pub "$ERE_TRUSTED_DIR/"
if ! "$ERE" sign "$WORK/target.erebus" --key "$KEY" --quiet --no-input >/dev/null 2>&1; then
  echo "  ✗ signing failed"
  exit 2
fi
KEY_HEX=$("$ERE" inspect "$WORK/target.erebus" --json | python3 -c \
  "import json,sys; print(json.load(sys.stdin)['meta']['crypto']['encryption_key_hex'])")
[ -n "$KEY_HEX" ] || { echo "  ✗ no key hex to check for leaks"; exit 2; }

echo "── [3/7] building SISR bundle"
if ! "$ERE" build "$APP" --enable-sisr -o "$WORK/sisr.erebus" >/dev/null 2>&1; then
  echo "  ✗ SISR bundle build failed"
  exit 2
fi

echo "── [4/7] mutation monkeys ($ITER iterations, seed $SEED)"
python3 - "$SCRIPT_DIR" "$WORK" "$ITER" "$KEY_HEX" "$((SEED))" > "$WORK/harness.log" 2>&1 <<'PY'
import os
import random
import sys

helper_dir, work, n_str, key_hex, seed = sys.argv[1:]
sys.path.insert(0, helper_dir)
from chaos_mutators import check_corrupt, fields, report, run_case, write_case

ctx = {"cases": os.path.join(work, "cases"),
       "findings": os.path.join(work, "findings"),
       "seed": int(seed)}
n = int(n_str)
blob = open(os.path.join(work, "target.erebus"), "rb").read()
layout = fields(blob)

# Positive control: one flipped bit in the authenticated region must be
# rejected, otherwise a broken oracle could pass the whole run vacuously.
bad = bytearray(blob)
bad[layout["signed_start"] + 17] ^= 0x01
data = bytes(bad)
path = write_case(ctx, "canary", 0, data)
result = run_case(path, data, ctx, "canary", 0, key_hex)
if result is None or result.returncode == 0:
    report(ctx, "canary", 0, data, "CANARY-FAIL")
os.unlink(path)
print("SUMMARY phase=canary runs=1")

KINDS = ("walk", "flip", "interesting", "arith", "block-del",
         "block-dup", "zero", "nibble", "truncate")
check_corrupt(ctx, "byteflip", blob, n, KINDS, key_hex, 1)
check_corrupt(ctx, "footer-magic", blob, 4, ("magic",), key_hex, 2)
check_corrupt(ctx, "metadata", blob, n, ("meta",), key_hex, 3)

# SISR bundles are unsigned at rest. Keep their mutants inside the payload
# region so a legitimate v2 layout is not misreported as fail-open.
sisr = open(os.path.join(work, "sisr.erebus"), "rb").read()
if sisr[-4:] != (0xBEEF_CAFE).to_bytes(4, "little"):
    print("SISR-FOOTER-MISSING")
else:
    check_corrupt(ctx, "sisr", sisr, n,
                  ("flip", "zero", "block-del", "nibble", "truncate"),
                  None, 4)

invalid = {
    "empty": b"",
    "one-byte": b"E",
    "header-only": blob[:16],
    "footer-only": blob[-92:],
    "garbage": bytes(random.Random(ctx["seed"] + 5).randrange(256) for _ in range(4096)),
}
for i, (name, data) in enumerate(invalid.items()):
    path = write_case(ctx, "invalid", i, data)
    result = run_case(path, data, ctx, "invalid", i, key_hex)
    if result is not None and result.returncode == 0:
        report(ctx, "invalid", i, data, "FAIL-CLOSED-VIOLATION", name)
    os.unlink(path)
print(f"SUMMARY phase=invalid runs={len(invalid)}")
PY

grep '^SUMMARY' "$WORK/harness.log" || true
grep -E 'VIOLATION|KEY-LEAK|SISR-FOOTER-MISSING' "$WORK/harness.log" || true
check "known-bad canary was rejected" \
  "$(grep -c 'CANARY-FAIL' "$WORK/harness.log" || true)"
check "mutated bundles always fail closed" \
  "$(grep -c 'FAIL-CLOSED-VIOLATION phase=byteflip' "$WORK/harness.log" || true)"
check "footer magic corruption never produces a false positive" \
  "$(grep -c 'FAIL-CLOSED-VIOLATION phase=footer-magic' "$WORK/harness.log" || true)"
check "metadata tampering always fails closed" \
  "$(grep -c 'FAIL-CLOSED-VIOLATION phase=metadata' "$WORK/harness.log" || true)"
check "SISR corruption always fails closed" \
  "$(grep -c 'FAIL-CLOSED-VIOLATION phase=sisr' "$WORK/harness.log" || true)"
check "SISR bundle was built with a valid footer" \
  "$(grep -c 'SISR-FOOTER-MISSING' "$WORK/harness.log" || true)"
check "invalid inputs are rejected" \
  "$(grep -c 'FAIL-CLOSED-VIOLATION phase=invalid' "$WORK/harness.log" || true)"
check "no panic, core dump or timeout" \
  "$(grep -cE 'PANIC-VIOLATION|TIMEOUT-VIOLATION' "$WORK/harness.log" || true)"
check "no encryption-key leakage" \
  "$(grep -c 'KEY-LEAK' "$WORK/harness.log" || true)"
check "every fuzz phase executed cases" \
  "$(grep -c 'SUMMARY .* runs=0' "$WORK/harness.log" || true)"
check "no mutant was a byte-identical no-op" \
  "$(grep -c 'NOOP-MUTANT' "$WORK/harness.log" || true)"

echo "── [5/7] SIGKILL monkey (15 kills) + concurrent runs"
kill_violations=0
for delay_ms in 5 15 30 50 80 100 150 200 300 400 500 600 700 900 1000; do
  chmod +x "$WORK/target.erebus"
  "$WORK/target.erebus" > /dev/null 2>&1 &
  PID=$!
  sleep "$(python3 -c "print($delay_ms/1000)")"
  kill -9 "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  # A fresh run after every violent death must still succeed.
  if ! "$WORK/target.erebus" > /dev/null 2>&1; then
    echo "  ✗ run after SIGKILL@${delay_ms}ms failed (cache poisoned?)"
    kill_violations=$((kill_violations+1))
  fi
done
check "cache self-heals after SIGKILL at every stage" "$kill_violations"

pids=()
for _ in 1 2 3; do
  "$WORK/target.erebus" > /dev/null 2>&1 &
  pids+=("$!")
done
concurrent=0
for pid in "${pids[@]}"; do
  if wait "$pid" 2>/dev/null; then :; else concurrent=$((concurrent+1)); fi
done
check "concurrent runs keep the cache consistent" "$concurrent"

echo "── [6/7] happy path sanity"
if "$WORK/target.erebus" 2>"$WORK/happy.err" | grep -q chaos-target-ok; then
  check "untampered bundle still works" 0
else
  check "untampered bundle still works" 1
fi
check "no panic noise on clean stderr" \
  "$(grep -ciE 'panicked|core dumped' "$WORK/happy.err" || true)"
if grep -qiF "$KEY_HEX" "$WORK/happy.err"; then
  check "no key leak on happy path" 1
else
  check "no key leak on happy path" 0
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
  ABORTED=0
  echo "CHAOS VERDICT: SURVIVED ($ITER mutants + 4 footer-magic + 15 SIGKILLs + SISR + metadata; seed $SEED)"
  echo "note: bounded evidence for this seed, not proof of absence"
else
  echo "CHAOS VERDICT: $FAILURES CHECK(S) FAILED — see log above"
  exit 1
fi
