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
#
# Usage: scripts/chaos_frontends.sh [ERE_BIN]
set -uo pipefail

ERE="${1:-./target/release/erebus}"
HERE=$(cd "$(dirname "$0")" && pwd)
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
  echo "WORK=$WORK"
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

echo "══ [0/6] fixtures: registry (auth-required) + bundle + user"
APP="$WORK/app"; mkdir -p "$APP"
printf 'print("frontend-chaos-ok")\n' > "$APP/app.py"
"$ERE" build "$APP" --isolation none -o "$WORK/tiny.erebus" >/dev/null 2>&1

# Registry WITHOUT --allow-anon-uploads so auth is enforced
setsid python3 "$HERE/registry_server.py" --dir "$WORK/reg" --host 127.0.0.1 --port $REG_PORT \
  > "$WORK/reg.log" 2>&1 < /dev/null &
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
timeout 60 "$ERE" publish --token "$TOKEN" "$WORK/tiny.erebus" >/dev/null 2>&1
check "publish with auth" 0 $?

# Start all frontends
python3 "$HERE/frontends/s3_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $S3_PORT --token "$TOKEN" \
  > "$WORK/s3.log" 2>&1 < /dev/null &
python3 "$HERE/frontends/hf_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $HF_PORT --token "$TOKEN" \
  > "$WORK/hf.log" 2>&1 < /dev/null &
python3 "$HERE/frontends/oci_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $OCI_PORT --token "$TOKEN" \
  > "$WORK/oci.log" 2>&1 < /dev/null &
python3 "$HERE/frontends/lfs_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $LFS_PORT --token "$TOKEN" \
  > "$WORK/lfs.log" 2>&1 < /dev/null &
python3 "$HERE/frontends/bazel_frontend.py" --registry "http://127.0.0.1:$REG_PORT" --port $BAZEL_PORT --token "$TOKEN" \
  > "$WORK/bazel.log" 2>&1 < /dev/null &
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
echo "══ [1/6] auth bypass"
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
echo "══ [2/6] traversal + malformed paths"
code=$(http_code "http://127.0.0.1:$S3_PORT/../../etc/passwd")
check "s3 traversal -> 404" "404" "$code"

code=$(http_code "http://127.0.0.1:$HF_PORT/api/models/../../../etc/passwd")
check "hf traversal -> 404" "404" "$code"

code=$(http_code "http://127.0.0.1:$OCI_PORT/v2/evil/blobs/sha256/../../etc/passwd")
check "oci traversal -> 404" "404" "$code"

echo ""
echo "══ [3/6] malformed requests"
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
echo "══ [4/6] happy path per protocol"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$S3_PORT/tiny.erebus")
check "s3 GET tiny.erebus" "200" "$code"

code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$HF_PORT/api/models/tiny/resolve/main/tiny.erebus")
check "hf resolve tiny" "200" "$code"

code=$(http_code "http://127.0.0.1:$OCI_PORT/v2/tiny/tags/list")
check "oci tags list" "200" "$code"

SHA=$(sha256sum "$WORK/tiny.erebus" | cut -d' ' -f1)
SIZE=$(stat -c%s "$WORK/tiny.erebus")
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
echo "══ [5/6] oversized payload"
dd if=/dev/urandom of="$WORK/big.bin" bs=1M count=10 2>/dev/null
code=$(timeout 30 curl -s -o /dev/null -w '%{http_code}' -X PUT \
  -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$S3_PORT/huge.erebus" --data-binary "@$WORK/big.bin" 2>/dev/null)
check "s3 10MB PUT does not crash" "200" "$code"

sleep 1
code=$(http_code "http://127.0.0.1:$S3_PORT/?list-type=2")
check "s3 still alive after big PUT" "200" "$code"

echo ""
echo "══ [6/6] verdict"
if [ "$FAILURES" -eq 0 ]; then
  echo "FRONTEND CHAOS VERDICT: SURVIVED"
else
  echo "FRONTEND CHAOS VERDICT: $FAILURES CHECK(S) FAILED"
  exit 1
fi
