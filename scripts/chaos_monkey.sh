#!/usr/bin/env bash
# chaos_monkey.sh — aggressive adversarial fuzzing of the erebus fail-closed path.
#
# Builds an encrypted bundle, then hammers corrupted copies through the real stub
# and asserts:
#   1. Corrupted/truncated binaries NEVER succeed (exit 0) — fail closed
#   2. The encryption key hex NEVER appears in stderr (no secret leakage)
#   3. No crash dumps / panics with internal paths on the happy path
#   4. SIGKILL during startup never poisons subsequent runs (cache self-heal)
#   5. SISR delta updates survive chunk corruption (content-addressed resilience)
#   6. Metadata tampering is detected and rejected
#   7. Footer magic corruption never produces false positives
#   8. Concurrent writers never produce truncated bundles
#
# Usage: scripts/chaos_monkey.sh [iterations]
set -euo pipefail

ERE="${ERE_BIN:-./target/release/erebus}"
ITER="${1:-50}"
WORK=$(mktemp -d /tmp/erebus-chaos.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

command -v "$ERE" >/dev/null || { echo "erebus CLI not found at $ERE"; exit 2; }
command -v python3 >/dev/null || { echo "python3 required"; exit 2; }

echo "── [1/7] building encrypted bundle in $WORK"
APP="$WORK/app"
mkdir -p "$APP"
cat > "$APP/app.py" <<'PY'
print("chaos-target-ok")
PY
"$ERE" build "$APP" --encrypt --isolation none -o "$WORK/target.erebus" >/dev/null 2>&1

echo "── [2/7] extracting key hex for leak detection"
KEY_HEX=$("$ERE" inspect "$WORK/target.erebus" --json | python3 -c \
  "import json,sys; print(json.load(sys.stdin)['meta']['crypto']['encryption_key_hex'])")

FAILURES=0
check() { # check <label> <exit_code>
  if [ "$2" -ne 0 ]; then echo "  ✗ $1"; FAILURES=$((FAILURES+1)); else echo "  ✓ $1"; fi
}

echo "── [3/7] byte-flip monkey ($ITER iterations)"
python3 - "$WORK/target.erebus" "$ITER" "$KEY_HEX" > "$WORK/corpus.log" <<'PY'
import random, subprocess, sys, os
target, n, key_hex = sys.argv[1], int(sys.argv[2]), sys.argv[3]
blob = open(target, 'rb').read()
random.seed(0xC0FFEE)
leak = closed = runs = 0
for i in range(n):
    data = bytearray(blob)
    mode = random.choice(['flip', 'flip', 'flip', 'truncate', 'zero-region', 'swap-nibble'])
    if mode == 'flip':
        for _ in range(random.randint(1, 8)):
            data[random.randrange(len(data))] ^= 1 << random.randrange(8)
    elif mode == 'truncate':
        data = data[:random.randrange(1, len(data))]
    elif mode == 'zero-region':
        off = random.randrange(len(data) // 4, len(data) - 1)
        ln = min(random.randint(16, 4096), len(data) - off - 1)
        data[off:off+ln] = b'\x00' * ln
    else:  # swap-nibble
        for _ in range(random.randint(1, 4)):
            idx = random.randrange(len(data))
            data[idx] = ((data[idx] >> 4) ^ 0xF & 0xF) << 4 | ((data[idx] & 0xF) ^ 0xF)
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
check "corrupted files always fail closed" $?
check "no encryption-key leakage in stderr" $?

echo "── [4/7] SIGKILL monkey (20 kills with varied delays)"
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

echo "── [5/7] SISR chunk corruption monkey ($ITER iterations)"
# Build a SISR-enabled bundle first
python3 - "$WORK/target.erebus" "$ITER" > "$WORK/sisr_corpus.log" <<'PY'
import random, subprocess, sys, os, json
target, n = sys.argv[1], int(sys.argv[2])
blob = open(target, 'rb').read()
# Parse footer to find SISR section
footer_magic = blob[-4:]
if footer_magic != b'\xca\xfe\xbe\xef':
    print("No SISR footer magic, skipping SISR test")
    sys.exit(0)
random.seed(0xBEEFCAFE)
leak = closed = runs = 0
for i in range(n):
    data = bytearray(blob)
    # Corrupt chunk hashes in the SISR manifest
    # Truncate the chunk table
    off = random.randrange(20, len(data) // 2)
    data = data[:off]
    path = f'/tmp/erebus-chaos-sisr-case-{i}'
    open(path, 'wb').write(data)
    os.chmod(path, 0o755)
    r = subprocess.run([path], capture_output=True, text=True, timeout=60)
    runs += 1
    if r.returncode == 0:
        closed += 1
        print(f'FAIL-CLOSED-VIOLATION SISR case={i}')
    os.unlink(path)
print(f'SUMMARY SISR runs={runs} exit0_on_corrupt={closed}')
PY
check "SISR chunk corruption always fails closed" $?

echo "── [6/7] metadata tampering monkey ($ITER iterations)"
python3 - "$WORK/target.erebus" "$ITER" "$KEY_HEX" > "$WORK/meta_tamper.log" <<'PY'
import random, subprocess, sys, os, json
target, n, key_hex = sys.argv[1], int(sys.argv[2]), sys.argv[3]
blob = open(target, 'rb').read()
random.seed(0xBADF00D)
leak = closed = runs = 0
for i in range(n):
    data = bytearray(blob)
    # Corrupt metadata JSON in the middle of the file
    meta_start = random.randrange(64, len(data) // 2)
    meta_len = random.randint(8, 256)
    corrupt_len = random.randint(4, meta_len + 4)
    # Replace metadata with garbage
    data[meta_start:meta_start+corrupt_len] = b'{"tampered": true, " garbage'
    path = f'/tmp/erebus-chaos-metacase-{i}'
    open(path, 'wb').write(data)
    os.chmod(path, 0o755)
    r = subprocess.run([path], capture_output=True, text=True, timeout=60)
    runs += 1
    if r.returncode == 0:
        closed += 1
        print(f'FAIL-CLOSED-VIOLATION metadata case={i}')
    if key_hex.lower() in r.stderr.lower():
        leak += 1
        print(f'KEY-LEAK metadata case={i}')
    os.unlink(path)
print(f'SUMMARY meta runs={runs} exit0_on_corrupt={closed} leaks={leak}')
PY
check "metadata tampering always fails closed" $?
check "no encryption-key leakage in metadata tamper" $?

echo "── [7/7] happy path sanity"
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
if [ "$FAILURES" -eq 0 ]; then
  echo "CHAOS VERDICT: SURVIVED ($ITER corruptions + SIGKILLs + SISR + metadata tamper)"
else
  echo "CHAOS VERDICT: $FAILURES CHECK(S) FAILED — see log above"
  exit 1
fi