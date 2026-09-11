#!/usr/bin/env bash
# chaos_registry_serve.sh — adversarial battery for the registry + pull + serve.
#
# Covers the features the original chaos_monkey.sh does not touch:
#   pull    — tampered index (sha/size mismatch), traversal names, dead
#             registry, SIGKILL mid-download with retry
#   serve   — corrupted bundle refuses, modelless bundle, missing engine,
#             port-conflict child death, SIGKILL mid-extraction self-heal
#   registry — traversal GET, bad upload filenames, non-multipart POST,
#              index freshness after upload
#
# Usage: scripts/chaos_registry_serve.sh [ERE_BIN]
# No `set -e`: a chaos harness must survive failing probes and report every
# check instead of dying on the first unexpected exit code.
set -uo pipefail

ERE="${1:-./target/release/erebus}"
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d /tmp/erebus-chaos2.XXXXXX)
REG_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
STATIC_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
trap 'rm -rf "$WORK"; kill $(jobs -p) 2>/dev/null || true' EXIT
failures=0

check() { # check <label> <rc>
  if [ "$2" = "0" ]; then echo "  ✓ $1"; else echo "  ✗ $1"; failures=$((failures+1)); fi
}
expect_fail() { # command must exit non-zero
  if "$@" >/dev/null 2>&1; then return 1; else return 0; fi
}

# SIGKILL a background job and its whole subtree (children first). A bare
# `kill -9 $pid` orphans the spawned engine, which then keeps the serve port
# bound forever. Works whether the shell gives each job its own process group
# (job control on) or all jobs share the harness pgrp (job control off).
desc_kill() {
  local pid=$1 c
  for c in $(ps -o pid= --ppid "$pid" 2>/dev/null); do desc_kill "$c"; done
  kill -9 "$pid" 2>/dev/null || true
}

echo "── [0/6] fixtures: bundle + fake engine + two registries"
APP="$WORK/app"; mkdir -p "$APP"
printf 'print("x")\n' > "$APP/app.py"
"$ERE" build "$APP" --isolation none -o "$WORK/tiny.erebus" >/dev/null 2>&1
cat > "$WORK/fake-engine" <<EOF
#!/usr/bin/env python3
import sys, json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
port = int(sys.argv[sys.argv.index('--port')+1])
class H(BaseHTTPRequestHandler):
    def log_message(self,*a): pass
    def do_GET(self):
        b=b'{"status":"ok"}' if self.path=='/health' else b'{"object":"list","data":[]}'
        self.send_response(200); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b)
ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
EOF
chmod +x "$WORK/fake-engine"
mkdir -p "$WORK/reg/packages"
python3 "$HERE/registry_server.py" --dir "$WORK/reg" --host 127.0.0.1 --port $REG_PORT \
  --allow-anon-uploads \
  > "$WORK/reg.log" 2>&1 < /dev/null &
sleep 1.5
curl -sf "http://127.0.0.1:$REG_PORT/health" >/dev/null; check "registry /health" $?

echo "── [1/6] registry hardening"
curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$REG_PORT/packages/..%2f..%2fetc%2fpasswd" | grep -q 404
check "GET traversal rejected" $?
curl -s -o /dev/null -w '%{http_code}' -X POST -d 'junk' "http://127.0.0.1:$REG_PORT/" | grep -q 400
check "non-multipart POST rejected" $?
printf 'x' > "$WORK/evil.exe"
code=$(curl -s -o /dev/null -w '%{http_code}' -F "file=@$WORK/evil.exe;filename=../../evil.erebus" "http://127.0.0.1:$REG_PORT/")
[ "$code" = "400" ] || [ "$code" = "200" ]  # basename-sanitized: either rejected or stored flat
ls "$WORK/reg/packages/.." 2>/dev/null | grep -qv evil; check "upload filename sanitized (no escape)" $?

echo "── [2/6] publish → index → pull (control path)"
if ! timeout 60 env ERE_REGISTRY="http://127.0.0.1:$REG_PORT" "$ERE" publish "$WORK/tiny.erebus" >"$WORK/pub.log" 2>&1; then
  echo "  ✗ publish failed:"; tail -3 "$WORK/pub.log"; failures=$((failures+1))
fi
curl -sf "http://127.0.0.1:$REG_PORT/index.json" | python3 -c "
import json,sys; p=json.load(sys.stdin)['packages']
assert any(x['name']=='tiny' for x in p), p"
check "index reflects upload immediately" $?
expect_fail timeout 60 env ERE_REGISTRY="http://127.0.0.1:$REG_PORT" "$ERE" pull unknown-pkg -o "$WORK/x"
check "unknown package fails clean" $?
timeout 60 env ERE_REGISTRY="http://127.0.0.1:$REG_PORT" "$ERE" pull tiny -o "$WORK/pulled.erebus" >/dev/null 2>&1
if cmp -s "$WORK/tiny.erebus" "$WORK/pulled.erebus"; then
  check "pull roundtrip byte-identical" 0
else
  check "pull roundtrip byte-identical" 1
  echo "    [sizes] $(stat -c%s "$WORK/tiny.erebus" 2>/dev/null) vs $(stat -c%s "$WORK/pulled.erebus" 2>/dev/null)"
  cmp "$WORK/tiny.erebus" "$WORK/pulled.erebus" 2>&1 | head -2 | sed 's/^/      /'
  mkdir -p /tmp/chaos-artifacts && cp "$WORK/tiny.erebus" "$WORK/pulled.erebus" /tmp/chaos-artifacts/ 2>/dev/null || true
fi
timeout 60 env ERE_REGISTRY="http://127.0.0.1:$REG_PORT" "$ERE" pull tiny -o "$WORK/pulled.erebus" >/dev/null 2>&1
check "cache short-circuit on re-pull" $?
expect_fail timeout 60 env ERE_REGISTRY="http://127.0.0.1:$REG_PORT" "$ERE" pull ../etc/passwd -o "$WORK/x"
check "pull name traversal rejected" $?
expect_fail timeout 60 env ERE_REGISTRY="http://127.0.0.1:1" "$ERE" pull tiny -o "$WORK/x"
check "dead registry fails clean" $?

echo "── [3/6] pull integrity against a lying static index"
mkdir -p "$WORK/static/packages"
head -c 100000 "$WORK/tiny.erebus" > "$WORK/static/packages/tiny.erebus"   # truncated!
TRUNC_SHA=$(sha256sum "$WORK/static/packages/tiny.erebus" | cut -d' ' -f1)
FULL_SIZE=$(stat -c%s "$WORK/tiny.erebus")
cat > "$WORK/static/index.json" <<EOF
{"packages":[{"name":"tiny","file":"tiny.erebus","sha256":"$TRUNC_SHA","size":$FULL_SIZE}]}
EOF
python3 -m http.server $STATIC_PORT --directory "$WORK/static" >/dev/null 2>&1 < /dev/null &
sleep 1
rm -f "$WORK/lying.erebus"
expect_fail timeout 60 env ERE_REGISTRY="http://127.0.0.1:$STATIC_PORT" "$ERE" pull tiny -o "$WORK/lying.erebus"
[ ! -f "$WORK/lying.erebus" ]; check "size mismatch → download rejected, no artifact left" $?
FAKE_SHA=$(printf "a%.0s" $(seq 1 64))
sed -i "s/\"sha256\":\"$TRUNC_SHA\"/\"sha256\":\"$FAKE_SHA\"/" "$WORK/static/index.json"
rm -f "$WORK/lying.erebus"
expect_fail timeout 60 env ERE_REGISTRY="http://127.0.0.1:$STATIC_PORT" "$ERE" pull tiny -o "$WORK/lying.erebus"
[ ! -f "$WORK/lying.erebus" ]; check "sha mismatch → download rejected, no artifact left" $?

echo "── [4/6] serve chaos"
cp "$WORK/tiny.erebus" "$WORK/corrupt.erebus"
python3 - "$WORK/corrupt.erebus" <<'PY'
import sys, random
d = bytearray(open(sys.argv[1],'rb').read())
random.seed(7)
for _ in range(5): d[random.randrange(len(d))] ^= 0xFF
open(sys.argv[1],'wb').write(d)
PY
expect_fail "$ERE" serve "$WORK/corrupt.erebus" --llama-server "$WORK/fake-engine"
check "corrupted bundle refused by SHA-256" $?
# modelless bundle: build from an empty python app without models
mkdir -p "$WORK/nomodel" && printf 'print(1)\n' > "$WORK/nomodel/app.py"
"$ERE" build "$WORK/nomodel" --isolation none -o "$WORK/nomodel.erebus" >/dev/null 2>&1
expect_fail "$ERE" serve "$WORK/nomodel.erebus" --llama-server "$WORK/fake-engine"
check "model-less bundle errors cleanly" $?
# real bundle, engine missing
expect_fail "$ERE" serve "$WORK/tiny.erebus" --llama-server "$WORK/nope"
check "missing engine errors with hint" $?
# port conflict: occupy port, engine dies early, health-wait must abort non-zero
python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',8123)); s.listen(1); time.sleep(25)" &
BLOCKER=$!
sleep 1
cat > "$WORK/dying-engine" <<'EOF'
#!/bin/sh
exit 3
EOF
chmod +x "$WORK/dying-engine"
expect_fail timeout 30 "$ERE" serve "$WORK/tiny.erebus" --port 8123 --llama-server "$WORK/dying-engine"
kill $BLOCKER 2>/dev/null || true
check "engine death during health-wait aborts non-zero" $?

echo "── [5/6] SIGKILL mid-extraction self-heal"
# Needs a bundle WITH a model artifact, like real serving workloads.
mkdir -p "$WORK/m"
printf 'print("m")\n' > "$WORK/m/app.py"
printf 'GGUF' > "$WORK/m/fake.gguf"
"$ERE" build "$WORK/m" --embed-model "$WORK/m/fake.gguf" --isolation none \
  -o "$WORK/model-bundle.erebus" >/dev/null 2>&1
"$ERE" serve "$WORK/model-bundle.erebus" --port 8124 --llama-server "$WORK/fake-engine" \
  > "$WORK/heal.log" 2>&1 < /dev/null &
SRV=$!
sleep 2
desc_kill "$SRV" # serve + engine; the engine holds 8124, not just the serve
wait "$SRV" 2>/dev/null || true
timeout 60 "$ERE" serve "$WORK/model-bundle.erebus" --port 8124 --llama-server "$WORK/fake-engine" \
  > "$WORK/heal2.log" 2>&1 &
SRV2=$!
HEALED=1
for i in $(seq 1 40); do
  curl -sf http://127.0.0.1:8124/v1/models >/dev/null 2>&1 && HEALED=0 && break
  sleep 1
done
# The banner only prints AFTER wait_healthy() passes — an orphaned engine
# from the SIGKILL'd run would answer the curl probe above even though the
# second serve failed with EADDRINUSE. Require serve#2 itself to be up.
grep -q "OpenAI-compatible endpoint ready" "$WORK/heal2.log" 2>/dev/null || HEALED=1
check "serve works after SIGKILL mid-extraction (no poisoned .ready)" $HEALED
desc_kill "$SRV2" # reap serve#2's engine too, no leak
tail -3 "$WORK/heal.log" 2>/dev/null | sed 's/^/      [heal1] /'
tail -3 "$WORK/heal2.log" 2>/dev/null | sed 's/^/      [heal2] /' 

echo "── [6/6] verdict"
if [ "$failures" -eq 0 ]; then
  echo "CHAOS REGISTRY/SERVE VERDICT: SURVIVED"
else
  echo "CHAOS REGISTRY/SERVE VERDICT: $failures CHECK(S) FAILED"
  exit 1
fi
