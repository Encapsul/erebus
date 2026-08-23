#!/usr/bin/env bash
# chaos_monkey.sh — adversarial fuzzing of the erebus launcher fail-closed path.
#
# Builds an AES-256-GCM encrypted bundle, then hammers corrupted copies of it
# through the real stub binary and asserts:
#   1. Corrupted/truncated binaries NEVER succeed (exit 0) — fail closed
#   2. The encryption key hex NEVER appears in stderr (no secret leakage)
#   3. No crash dumps / panics with internal paths on the happy path
#   4. SIGKILL during startup never poisons subsequent runs (cache self-heal)
#
# Usage: scripts/chaos_monkey.sh [iterations]
set -euo pipefail

ERE="${ERE_BIN:-./target/release/erebus}"
ITER="${1:-30}"
WORK=$(mktemp -d /tmp/erebus-chaos.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

command -v "$ERE" >/dev/null || { echo "erebus CLI not found at $ERE"; exit 2; }
command -v python3 >/dev/null || { echo "python3 required"; exit 2; }

echo "── [1/5] building encrypted bundle in $WORK"
APP="$WORK/app"
mkdir -p "$APP"
cat > "$APP/app.py" <<'PY'
print("chaos-target-ok")
PY
"$ERE" build "$APP" --encrypt --isolation none -o "$WORK/target.erebus" >/dev/null 2>&1

echo "── [2/5] extracting key hex for leak detection"
KEY_HEX=$("$ERE" inspect "$WORK/target.erebus" --json | python3 -c \
  "import json,sys; print(json.load(sys.stdin)['meta']['crypto']['encryption_key_hex'])")

failures=0
check() { # check <label> <condition-result>
  if [ "$2" != "0" ]; then echo "  ✗ $1"; failures=$((failures+1)); else echo "  ✓ $1"; fi
}

echo "── [3/5] corruption monkey ($ITER iterations)"
python3 - "$WORK/target.erebus" "$ITER" "$KEY_HEX" > "$WORK/corpus.log" <<'PY'
import random, subprocess, sys, os
target, n, key_hex = sys.argv[1], int(sys.argv[2]), sys.argv[3]
blob = open(target, 'rb').read()
random.seed(0xC0FFEE)
leak = closed = runs = 0
for i in range(n):
    data = bytearray(blob)
    mode = random.choice(['flip', 'flip', 'truncate', 'zero-region'])
    if mode == 'flip':
        for _ in range(random.randint(1, 8)):
            data[random.randrange(len(data))] ^= 1 << random.randrange(8)
    elif mode == 'truncate':
        data = data[:random.randrange(1, len(data))]
    else:
        off = random.randrange(len(data) // 4, len(data))
        ln = min(random.randint(16, 4096), len(data) - off)
        data[off:off+ln] = bytes(ln)
    path = f'/tmp/erebus-chaos-case-{i}'
    open(path, 'wb').write(data)
    os.chmod(path, 0o755)
    r = subprocess.run([path], capture_output=True, text=True, timeout=60)
    runs += 1
    if r.returncode == 0:
        closed += 1
        print(f'FAIL-CLOSED-VIOLATION case={i} mode={mode}')
    if key_hex.lower() in r.stderr.lower():
        leak += 1
        print(f'KEY-LEAK case={i} mode={mode}')
    os.unlink(path)
print(f'SUMMARY runs={runs} exit0_on_corrupt={closed} leaks={leak}')
PY
grep -q "exit0_on_corrupt=0" "$WORK/corpus.log"; check "corrupted files always fail closed" $?
grep -q "leaks=0" "$WORK/corpus.log"; check "no encryption-key leakage in stderr" $?

echo "── [4/5] SIGKILL monkey (10 kills mid-startup)"
kill_violations=0
for delay_ms in 5 20 50 80 120 200 300 400 600 900; do
  chmod +x "$WORK/target.erebus"
  "$WORK/target.erebus" > /dev/null 2>&1 &
  PID=$!
  sleep "$(python3 -c "print($delay_ms/1000)")"
  kill -9 "$PID" 2>/dev/null || true
  wait "$PID" 2>/dev/null || true
  # A fresh run after every violent death must still succeed.
  if ! "$WORK/target.erebus" > /dev/null 2>&1; then
    echo "  ✗ run after SIGKILL@$delay_ms ms failed (cache poisoned?)"
    kill_violations=$((kill_violations+1))
  fi
done
check "cache self-heals after SIGKILL at every stage" "$kill_violations"

echo "── [5/5] happy path sanity"
if "$WORK/target.erebus" 2>"$WORK/happy.err" | grep -q chaos-target-ok; then
  check "untampered bundle still works" 0
else
  check "untampered bundle still works" 1
fi
if grep -qi "panicked\|core dumped" "$WORK/happy.err"; then
  check "no panic noise on clean stderr" 1
else
  check "no panic noise on clean stderr" 0
fi

echo ""
if [ "$failures" -eq 0 ]; then
  echo "CHAOS VERDICT: SURVIVED ($ITER corruptions + 10 SIGKILLs + leak scan)"
else
  echo "CHAOS VERDICT: $failures CHECK(S) FAILED — see log above"
  exit 1
fi
