#!/usr/bin/env bash
# chaos_frontends.sh — adversarial battery for P3 protocol frontends.
#
# Starts a real erebus registry + each frontend, then hammers:
#   1. Auth bypass (no token, forged tokens)
#   2. Traversal + malformed paths
#   3. Bad digests / malformed bodies
#   4. Happy-path per protocol
#   5. Oversized payload resilience
#   6. Frontend still alive after stress
#   7. Concurrent mixed-protocol load (publish + S3 + HF + OCI)
#   8. Restart durability: SIGTERM registry + frontend, store survives
#
# Usage: scripts/chaos_frontends.sh [ERE_BIN]
set -uo pipefail

ERE="${1:-./target/release/erebus}"
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$HERE/host_tools.sh"
WORK=$(mktemp -d /tmp/erebus-chaos-frontends.XXXXXX)

REG_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
S3_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
HF_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
OCI_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
LFS_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
BAZEL_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
FAILURES=0

cleanup() {
  kill $(jobs -p) 2>/dev/null || true
  [ "${KEEP:-0}" = "1" ] || rm -rf "$WORK"
}
trap cleanup EXIT

check() {
  local label="$1" expected="$2" actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  ✓ $label"
  else
    echo "  ✗ $label (expected $expected, got $actual)"
    FAILURES=$((FAILURES+1))
  fi
}

http_code() {
  local url="$1" method="${2:-GET}" body_file="${3:-}"
  if [ -n "$body_file" ]; then
    curl -s -o /dev/null -w '%{http_code}' -X "$method" -d "@$body_file" "$url"
  else
    curl -s -o /dev/null -w '%{http_code}' -X "$method" "$url"
  fi
}

echo "══ [0/8] fixtures: registry (auth-required) + bundle + user"
APP="$WORK/app"; mkdir -p "$APP"
printf 'print("frontend-chaos-ok")\n' > "$APP/app.py"
"$ERE" build "$APP" --isolation none -o "$WORK/tiny.erebus" >/dev/null 2>&1

# Registry WITHOUT --allow-anon-uploads so auth is enforced
setsid python3 "$HERE/registry_server.py" --dir "$WORK/reg" --host 127.0.0.1 --port $REG_PORT \
  > "$WORK/reg.log" 2>&1 < /dev/null &
REG_PID=$!
sleep 1.5
curl -sf "http://127.0.0.1:$REG_PORT/health" >/dev/null
check "registry /health" 0 $?

# Register user + publish with auth
TOKEN=$(python3 -c "
import urllib.request, json
req = urllib.request.Request('http://127.0.0.1:$REG_PORT/auth/register',
  data=json.dumps({'username':'chaos','password':'chaos1234567890'}).encode(),
  headers={'Content-Type':'application/json'})
resp = urllib.request.urlopen(req)
print(json.loads(resp.read())['token'])
")
export ERE_REGISTRY="http://127.0.0.1:$REG_PORT"
timeout 60 env ERE_TOKEN="$TOKEN" "$ERE" publish "$WORK/tiny.erebus" >/dev/null 2>&1
check "publish with auth" 0 $?

# Start all frontends
python3 "$HERE/frontends/s3_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $S3_PORT --token "$TOKEN" \
  > "$WORK/s3.log" 2>&1 < /dev/null &
S3_PID=$!
python3 "$HERE/frontends/hf_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $HF_PORT --token "$TOKEN" \
  > "$WORK/hf.log" 2>&1 < /dev/null &
HF_PID=$!
python3 "$HERE/frontends/oci_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $OCI_PORT --token "$TOKEN" \
  > "$WORK/oci.log" 2>&1 < /dev/null &
OCI_PID=$!
python3 "$HERE/frontends/lfs_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $LFS_PORT --token "$TOKEN" \
  > "$WORK/lfs.log" 2>&1 < /dev/null &
LFS_PID=$!
python3 "$HERE/frontends/bazel_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $BAZEL_PORT --token "$TOKEN" \
  > "$WORK/bazel.log" 2>&1 < /dev/null &
BAZEL_PID=$!
sleep 1

# Verify frontends actually started
for port in $S3_PORT $HF_PORT $OCI_PORT $LFS_PORT $BAZEL_PORT; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/")
  if [ "$code" = "000" ]; then
    echo "  ✗ frontend on port $port did not start"
    FAILURES=$((FAILURES+1))
  else
    echo "  ✓ frontend listening on $port"
  fi
done

# LFS and Bazel don't handle / — verify with a valid path
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$LFS_PORT/objects/batch")
check "lfs frontend alive" "400" "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$BAZEL_PORT/cas/$(printf 'a%.0s' $(seq 1 64))")
check "bazel frontend alive" "404" "$code"

echo ""
echo "══ [1/8] auth bypass"
code=$(http_code "http://127.0.0.1:$S3_PORT/?list-type=2")
check "s3 public list no-token" "200" "$code"

code=$(http_code "http://127.0.0.1:$HF_PORT/api/models")
check "hf public list no-token" "200" "$code"

# Private package requires token
code=$(http_code "http://127.0.0.1:$REG_PORT/packages/tiny.erebus")
check "registry private without token" "401" "$code"

# Forged token rejected
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer forgedtoken12345" \
  "http://127.0.0.1:$S3_PORT/tiny.erebus")
check "s3 forged token -> 401" "401" "$code"

echo ""
echo "══ [2/8] traversal + malformed paths"
code=$(http_code "http://127.0.0.1:$S3_PORT/../../etc/passwd")
check "s3 traversal -> 404" "404" "$code"

code=$(http_code "http://127.0.0.1:$HF_PORT/api/models/../../../etc/passwd")
check "hf traversal -> 404" "404" "$code"

code=$(http_code "http://127.0.0.1:$OCI_PORT/v2/evil/blobs/sha256/../../etc/passwd")
check "oci traversal -> 404" "404" "$code"

echo ""
echo "══ [3/8] malformed requests"
printf 'GARBAGE' > "$WORK/garbage.bin"
code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$S3_PORT/evil.erebus" --data-binary "@$WORK/garbage.bin" 2>/dev/null)
check "s3 garbage PUT -> 200" "200" "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$OCI_PORT/v2/evil/blobs/sha256:$(printf 'a%.0s' $(seq 1 32))" \
  --data-binary "@$WORK/garbage.bin" 2>/dev/null)
check "oci short digest -> 400" "400" "$code"

echo ""
echo "══ [4/8] happy path per protocol"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$S3_PORT/tiny.erebus")
check "s3 GET tiny.erebus" "200" "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$HF_PORT/api/models/tiny/resolve/main/tiny.erebus")
check "hf resolve tiny" "200" "$code"

code=$(http_code "http://127.0.0.1:$OCI_PORT/v2/tiny/tags/list")
check "oci tags list" "200" "$code"

SHA=$(sha256sum "$WORK/tiny.erebus" | cut -d' ' -f1)
SIZE=$(file_bytes "$WORK/tiny.erebus")
printf '{"operation":"download","objects":[{"oid":"sha256:%s","size":%d}]}' "$SHA" "$SIZE" > "$WORK/lfs_req.json"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/vnd.git-lfs+json" \
  -d "@$WORK/lfs_req.json" "http://127.0.0.1:$LFS_PORT/objects/batch")
check "lfs batch download" "200" "$code"

# Bazel CAS get
SHA=$(sha256sum "$WORK/tiny.erebus" | cut -d' ' -f1)
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$BAZEL_PORT/cas/$SHA")
check "bazel cas get" "200" "$code"

echo ""
echo "══ [5/8] oversized payload"
dd if=/dev/urandom of="$WORK/big.bin" bs=1M count=10 2>/dev/null
code=$(timeout 30 curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$S3_PORT/huge.erebus" --data-binary "@$WORK/big.bin" 2>/dev/null)
check "s3 10MB PUT does not crash" "200" "$code"
rm -f "$WORK/big.bin"

sleep 1
code=$(http_code "http://127.0.0.1:$S3_PORT/?list-type=2")
check "s3 still alive after big PUT" "200" "$code"

echo ""
echo "══ [6/8] concurrent mixed-protocol load (3 workers x 8 iters)"
CONC_FAIL="$WORK/conc_failures.txt"
: > "$CONC_FAIL"
conc_cycle() {
  local w="$1" i code rc
  for i in $(seq 1 8); do
    # Hardlink: 24 full copies of the agent binary were exhausting /tmp on GHA.
    ln -f "$WORK/tiny.erebus" "$WORK/conc_${w}_${i}.erebus" 2>/dev/null \
      || cp "$WORK/tiny.erebus" "$WORK/conc_${w}_${i}.erebus"
    timeout 60 env ERE_TOKEN="$TOKEN" "$ERE" publish "$WORK/conc_${w}_${i}.erebus" >/dev/null 2>&1
    rc=$?
    [ "$rc" = "0" ] || echo "conc_${w}_${i} publish rc=$rc" >> "$CONC_FAIL"
    code=$(curl -s -o "$WORK/got_${w}_${i}.bin" -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$S3_PORT/tiny.erebus")
    if [ "$code" != "200" ]; then
      echo "conc_${w}_${i} s3_get code=$code" >> "$CONC_FAIL"
    elif [ "$(sha256sum "$WORK/got_${w}_${i}.bin" | cut -d' ' -f1)" != "$SHA" ]; then
      echo "conc_${w}_${i} s3_get sha mismatch" >> "$CONC_FAIL"
    fi
    rm -f "$WORK/got_${w}_${i}.bin"
    code=$(curl -s -o "$WORK/hf_${w}_${i}.bin" -w '%{http_code}' \
      -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$HF_PORT/api/models/tiny/resolve/main/tiny.erebus")
    if [ "$code" != "200" ]; then
      echo "conc_${w}_${i} hf_resolve code=$code" >> "$CONC_FAIL"
    elif [ "$(sha256sum "$WORK/hf_${w}_${i}.bin" | cut -d' ' -f1)" != "$SHA" ]; then
      echo "conc_${w}_${i} hf_resolve sha mismatch" >> "$CONC_FAIL"
    fi
    rm -f "$WORK/hf_${w}_${i}.bin" "$WORK/conc_${w}_${i}.erebus"
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$OCI_PORT/v2/tiny/tags/list")
    [ "$code" = "200" ] || echo "conc_${w}_${i} oci_tags code=$code" >> "$CONC_FAIL"
  done
}
conc_cycle 1 & W1=$!
conc_cycle 2 & W2=$!
conc_cycle 3 & W3=$!
wait "$W1" "$W2" "$W3"
nbad=$(wc -l < "$CONC_FAIL" 2>/dev/null | tr -d ' ')
check "24 mixed cycles: publish/S3/HF/OCI healthy, hashes intact" "0" "$nbad"
nconc=$(curl -sf "http://127.0.0.1:$REG_PORT/index.json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
conc = [p for p in d['packages'] if p['name'].startswith('conc_')]
ok = sum(1 for p in conc if p.get('integrity') == 'ok')
print('%d %d' % (ok, len(conc)))
" 2>/dev/null)
check "all 24 concurrent publishes landed, integrity ok" "24 24" "$nconc"
code=$(http_code "http://127.0.0.1:$REG_PORT/health")
check "registry /health after concurrent load" "200" "$code"
alive=0
for p in $REG_PID $S3_PID $HF_PID $OCI_PID $LFS_PID $BAZEL_PID; do
  kill -0 "$p" 2>/dev/null && alive=$((alive+1))
done
check "all 6 server processes still alive" "6" "$alive"
n5xx=$(cat "$WORK"/s3.log "$WORK"/hf.log "$WORK"/oci.log "$WORK"/lfs.log "$WORK"/bazel.log "$WORK"/reg.log \
  2>/dev/null | grep -E '" 5[0-9][0-9] ' | wc -l | tr -d ' ')
check "no 5xx status in server logs during load" "0" "$n5xx"
ntb=$(grep -l 'Traceback (most recent call last)' \
  "$WORK"/s3.log "$WORK"/hf.log "$WORK"/oci.log "$WORK"/lfs.log "$WORK"/bazel.log "$WORK"/reg.log \
  2>/dev/null | wc -l | tr -d ' ')
check "no tracebacks in server logs during load" "0" "$ntb"

echo ""
echo "══ [7/8] restore/restart durability (SIGTERM + same data dir)"
pkill -TERM -f "registry_server.py --dir $WORK/reg" 2>/dev/null || true
kill -TERM "$S3_PID" 2>/dev/null || true
DOWN=1
for _ in $(seq 1 50); do
  r=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "http://127.0.0.1:$REG_PORT/health")
  s=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "http://127.0.0.1:$S3_PORT/")
  if [ "$r" = "000" ] && [ "$s" = "000" ]; then DOWN=0; break; fi
  sleep 0.2
done
check "clean SIGTERM stops registry + s3 frontend" "0" "$DOWN"
litter=$(find "$WORK/reg" \( -name '.incoming.*' -o -name '*.tmp' -o -name '.uploading*' \) \
  2>/dev/null | wc -l | tr -d ' ')
check "no upload litter (.incoming/.tmp/.uploading) after SIGTERM" "0" "$litter"

setsid python3 "$HERE/registry_server.py" --dir "$WORK/reg" --host 127.0.0.1 --port $REG_PORT \
  > "$WORK/regr.log" 2>&1 < /dev/null &
REG_PID=$!
python3 "$HERE/frontends/s3_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $S3_PORT --token "$TOKEN" \
  > "$WORK/s3r.log" 2>&1 < /dev/null &
S3_PID=$!
sleep 1.5
code=$(http_code "http://127.0.0.1:$REG_PORT/health")
check "registry /health after restart" "200" "$code"
code=$(curl -s -o "$WORK/after_restart.bin" -w '%{http_code}' \
  -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$S3_PORT/tiny.erebus")
check "s3 GET tiny.erebus via restarted frontend" "200" "$code"
sha_ok=1
[ "$(sha256sum "$WORK/after_restart.bin" 2>/dev/null | cut -d' ' -f1)" = "$SHA" ] && sha_ok=0
check "fetched content hash unchanged across restart" "0" "$sha_ok"
stored_ok=1
[ "$(sha256sum "$WORK/reg/packages/tiny.erebus" 2>/dev/null | cut -d' ' -f1)" = "$SHA" ] && stored_ok=0
check "on-disk blob intact after restart (sha matches)" "0" "$stored_ok"
rm -f "$WORK/pulled2.erebus"
pull_ok=1
timeout 60 env ERE_TOKEN="$TOKEN" "$ERE" pull --registry "http://127.0.0.1:$REG_PORT" tiny -o "$WORK/pulled2.erebus" \
  >/dev/null 2>&1 \
  && [ "$(sha256sum "$WORK/pulled2.erebus" 2>/dev/null | cut -d' ' -f1)" = "$SHA" ] && pull_ok=0
check "erebus pull roundtrip via restarted registry" "0" "$pull_ok"
nconc=$(curl -sf "http://127.0.0.1:$REG_PORT/index.json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
conc = [p for p in d['packages'] if p['name'].startswith('conc_')]
ok = sum(1 for p in conc if p.get('integrity') == 'ok')
print('%d %d' % (ok, len(conc)))
" 2>/dev/null)
check "index survives restart: 24 conc publishes intact" "24 24" "$nconc"
litter2=$(find "$WORK/reg" \( -name '.incoming.*' -o -name '*.tmp' -o -name '.uploading*' \) \
  2>/dev/null | wc -l | tr -d ' ')
check "no upload litter after restart" "0" "$litter2"
alive=0
for p in $REG_PID $S3_PID $HF_PID $OCI_PID $LFS_PID $BAZEL_PID; do
  kill -0 "$p" 2>/dev/null && alive=$((alive+1))
done
check "all 6 server processes alive after restart" "6" "$alive"
n5xx=$(cat "$WORK"/reg.log "$WORK"/regr.log "$WORK"/s3.log "$WORK"/s3r.log "$WORK"/hf.log "$WORK"/oci.log \
  "$WORK"/lfs.log "$WORK"/bazel.log 2>/dev/null | grep -E '" 5[0-9][0-9] ' | wc -l | tr -d ' ')
check "no 5xx in server logs across whole run" "0" "$n5xx"
ntb=$(grep -l 'Traceback (most recent call last)' \
  "$WORK"/reg.log "$WORK"/regr.log "$WORK"/s3.log "$WORK"/s3r.log "$WORK"/hf.log "$WORK"/oci.log \
  "$WORK"/lfs.log "$WORK"/bazel.log 2>/dev/null | wc -l | tr -d ' ')
check "no tracebacks in server logs across whole run" "0" "$ntb"

echo ""
echo "══ [8/8] verdict"
if [ "$FAILURES" -eq 0 ]; then
  echo "FRONTEND CHAOS VERDICT: SURVIVED"
else
  echo "FRONTEND CHAOS VERDICT: $FAILURES CHECK(S) FAILED"
  exit 1
fi
