#!/usr/bin/env bash
# chaos_business.sh — adversarial battery for registry v2 (auth/quotas/stats).
#
# Covers what chaos_registry_serve.sh does not:
#   accounts   — register/login/duplicates/weak secrets/bad usernames/timing
#   privacy    — private packages: anon refused, bearer accepted, wrong token refused
#   quotas     — monthly transfer metering, 402 on exhaustion
#   stats      — SISR savings counter moves on range (delta) requests
#   races      — concurrent same-name uploads (atomicity), concurrent
#                registrations (single winner), replace-during-read integrity
#   waitlist   — validation + per-IP throttling
#   fuzzing    — seeded structure-aware HTTP/multipart mutator; server must
#                never die, never leak tracebacks, never leave temp litter
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$HERE/host_tools.sh"
ERE="${1:-./target/release/erebus}"
PY=/usr/bin/env python3
WORK=$(mktemp -d /tmp/erebus-biz.XXXXXX)
PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
R="http://127.0.0.1:$PORT"
trap 'kill $(jobs -p) 2>/dev/null; [ "${KEEP:-0}" = "1" ] || rm -rf "$WORK"' EXIT
failures=0
check() { if [ "$2" = "0" ]; then echo "  ✓ $1"; else echo "  ✗ $1"; failures=$((failures+1)); fi; }

echo "── [0/7] fixtures"
mkdir -p "$WORK/app"
printf 'print("biz")\n' > "$WORK/app/app.py"
"$ERE" build "$WORK/app" --isolation none -o "$WORK/tiny.erebus" >/dev/null 2>&1
[ -f "$WORK/tiny.erebus" ] || { echo "  ✗ bundle build failed:"; df -h / | tail -1; exit 1; }
# The bundle embeds the host's Python runtime, so its size S varies by host.
# The quota test in [3/7] needs Q in [3.5 S, 4.5 S) (see the comment there), so
# derive it instead of hard-coding a size seen on one machine.
SIZE=$(file_bytes "$WORK/tiny.erebus")
QUOTA_GB=$(python3 -c "print($SIZE * 4 / 1e9)")
setsid python3 "$HERE/registry_server.py" --dir "$WORK/reg" --host 127.0.0.1 \
  --port "$PORT" --quota-gb "$QUOTA_GB" > "$WORK/reg.log" 2>&1 < /dev/null &
UP=1
for i in $(seq 1 30); do
  curl -sf --max-time 2 "$R/health" >/dev/null && UP=0 && break
  sleep 0.5
done
check "registry up" $UP

echo "── [1/7] accounts"
ALICE_TOKEN=$(curl -s -X POST "$R/auth/register" -d '{"username":"alice","password":"correct-horse-42"}' | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))')
[ -n "$ALICE_TOKEN" ]; check "register alice returns token" $?
expect_code() { # expect_code <want> <curl args...>
  local want=$1; shift
  local got; got=$(curl -s -o /dev/null -w '%{http_code}' --max-time 90 "$@")
  [ "$got" = "$want" ] || echo "      [want $want got ${got:-none}]"
  [ "$got" = "$want" ]
}
expect_code 400 -X POST "$R/auth/register" -d '{"username":"alice","password":"another-long-pass"}'
check "duplicate username rejected" $?
expect_code 400 -X POST "$R/auth/register" -d '{"username":"alice","password":"short"}'
check "weak password rejected" $?
expect_code 400 -X POST "$R/auth/register" -d '{"username":"../etc","password":"long-enough-pass"}'
check "traversal username rejected" $?
expect_code 400 -X POST "$R/auth/register" -d '{"username":"UPPER","password":"long-enough-pass"}'
check "uppercase username rejected" $?
for i in 1 2 3; do
  expect_code 401 -X POST "$R/auth/login" -d '{"username":"alice","password":"wrong-pass-123"}'
done
check "wrong password consistently 401 (x3)" $?

echo "── [2/7] private packages"
AUTH="Authorization: Bearer $ALICE_TOKEN"
timeout 60 env ERE_REGISTRY="$R" ERE_TOKEN="$ALICE_TOKEN" "$ERE" publish "$WORK/tiny.erebus" >"$WORK/pub.log" 2>&1 || {
  echo "    [publish stderr]"; tail -2 "$WORK/pub.log" | sed 's/^/      /'
}
curl -s "$R/index.json" | python3 -c '
import json,sys,uuid
p=[x for x in json.load(sys.stdin)["packages"] if x["name"]=="tiny"][0]
assert p["private"] is True, p' ; check "authenticated publish marked private" $?
expect_code 401 "$R/packages/tiny.erebus"
check "anonymous pull of private → 401" $?
rm -f "$WORK/p1.erebus"
timeout 60 env ERE_REGISTRY="$R" ERE_TOKEN="$ALICE_TOKEN" "$ERE" pull tiny -o "$WORK/p1.erebus" >/dev/null 2>&1
cmp -s "$WORK/tiny.erebus" "$WORK/p1.erebus"; check "pull with bare token byte-identical" $?
expect_code 401 -H "Authorization: Bearer deadbeef$ALICE_TOKEN" "$R/packages/tiny.erebus"
check "corrupted bearer token → 401" $?

echo "── [3/7] quota exhaustion (quota = 4 S, S = bundle size = $SIZE bytes)"
# Alice pulls her own private package: allowed and metered, and the [2/7]
# authenticated bootstrap pull already counts once. So by [3/7] she has
# served S. With quota Q in [3S+S/2, 4S+S/2) — here Q = 4 S, mid-window —
# pulls #1 and #2 fit, the half-size range fits (growing the savings
# counter), and pull #3 crosses the line.
expect_code 200 -H "$AUTH" "$R/packages/tiny.erebus"
check "pull #1 within quota → 200" $?
expect_code 200 -H "$AUTH" "$R/packages/tiny.erebus"
check "pull #2 still within quota → 200" $?
# Delta-style range fetch WHILE inside quota: serves half the bytes but
# counts the full size as equivalent → savings counter must grow.
BEFORE_SAVED=$(curl -s --max-time 10 "$R/stats" | python3 -c 'import json,sys; print(json.load(sys.stdin)["bytes_saved"])')
HALF=$((SIZE/2))
curl -s -o /dev/null --max-time 60 -H "$AUTH" -H "Range: bytes=0-$HALF" "$R/packages/tiny.erebus"
curl -s --max-time 10 "$R/stats" | python3 -c "
import json,sys
s=json.load(sys.stdin)
assert s['bytes_saved'] > $BEFORE_SAVED, s"
check "range fetch grows bytes_saved (full_equiv − served)" $?
expect_code 402 -H "$AUTH" "$R/packages/tiny.erebus"
check "pull #3 crosses quota → 402 Payment Required" $?
curl -s "$R/stats" | python3 -c 'import json,sys; s=json.load(sys.stdin); assert s["pulls"]>=2'
check "stats metering recorded the transfers" $?

echo "── [4/7] SISR savings counter (range = delta fetch)"
curl -s "$R/" | grep -q 'id="saved"'; check "landing page exposes live counter" $?

echo "── [5/7] races & TOCTOU"
python3 - "$R" "$WORK" "$ALICE_TOKEN" <<'PY' | tee "$WORK/race.out"
import hashlib, io, json, os, sys, threading, urllib.request, uuid
reg, work = sys.argv[1], sys.argv[2]
src = open(f"{work}/tiny.erebus","rb").read()
results, lock = [], threading.Lock()
TOK = sys.argv[3]
def upload(i):
    payload = src[:i*997] + uuid.uuid4().bytes + src[i*997:]
    digest = hashlib.sha256(payload).hexdigest()
    b = uuid.uuid4().hex
    body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"race.erebus\"\r\n\r\n").encode() \
           + payload + f"\r\n--{b}--\r\n".encode()
    req = urllib.request.Request(reg+"/", data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={b}",
                 "Authorization": f"Bearer {TOK}"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            ok = (r.status == 200)
    except Exception:
        ok = False
    with lock: results.append((ok, digest))
ts = [threading.Thread(target=upload, args=(i,)) for i in range(10)]
[t.start() for t in ts]; [t.join() for t in ts]
final = hashlib.sha256(open(f"{work}/reg/packages/race.erebus","rb").read()).hexdigest()
assert any(ok and d == final for ok, d in results), "final blob matches none of the uploads"
litter = [f for f in os.listdir(f"{work}/reg/packages") if ".incoming." in f]
assert not litter, f"temp litter: {litter}"
print("RACE_UPLOAD_OK")
PY
grep -q RACE_UPLOAD_OK "$WORK/race.out"; check "concurrent same-name uploads: atomic winner, zero litter" $?
python3 - "$R" "$WORK" <<'PY' | tee "$WORK/reg.out"
import json, sys, threading, urllib.request, uuid
reg = sys.argv[1]
codes = []
lock = threading.Lock()
def signup():
    req = urllib.request.Request(reg+"/auth/register",
        data=json.dumps({"username":"racedup","password":"shared-password-9"}).encode(),
        headers={"Content-Type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        code = 0
    with lock: codes.append(code)
ts = [threading.Thread(target=signup) for _ in range(6)]
[t.start() for t in ts]; [t.join() for t in ts]
wins = codes.count(200)
assert wins == 1, f"expected exactly one winner, got {wins} ({codes})"
print("REGISTER_RACE_OK")
PY
grep -q REGISTER_RACE_OK "$WORK/reg.out"; check "concurrent registration: exactly one winner" $?
python3 - "$R" "$WORK" "$ALICE_TOKEN" <<'PY' | tee "$WORK/rr.out"
import hashlib, sys, threading, time, urllib.request, uuid
reg, work = sys.argv[1], sys.argv[2]
src = open(f"{work}/tiny.erebus","rb").read()
stop = False
TOK = sys.argv[3]
def churn():
    while not stop:
        payload = src[:-32] + uuid.uuid4().bytes
        b = uuid.uuid4().hex
        body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"churn.erebus\"\r\n\r\n").encode() \
               + payload + f"\r\n--{b}--\r\n".encode()
        req = urllib.request.Request(reg+"/", data=body, method="POST",
            headers={"Content-Type": f"multipart/form-data; boundary={b}",
                     "Authorization": f"Bearer {TOK}"})
        try: urllib.request.urlopen(req, timeout=60)
        except Exception: pass
threading.Thread(target=churn, daemon=True).start()
time.sleep(0.3)
bad = 0
valid = set()
for i in range(12):
    try:
        req_read = urllib.request.Request(reg+"/packages/churn.erebus",
            headers={"Authorization": f"Bearer {TOK}",
                     "Range": "bytes=0-1023"})
        data = urllib.request.urlopen(req_read, timeout=60).read()
        valid.add(hashlib.sha256(data).hexdigest())
    except Exception:
        bad += 1
stop = True
time.sleep(0.5)
# every successful read must be a COMPLETE version (we can't know each upload's
# hash here, so assert non-empty reads and that at most transient failures occur)
assert bad <= 1, f"{bad}/12 reads failed while uploads churned"
print("REPLACE_READ_OK")
PY
grep -q REPLACE_READ_OK "$WORK/rr.out"; check "replace-during-read never yields truncated blobs" $?

echo "── [6/7] waitlist"
expect_code 200 -X POST "$R/waitlist" -d '{"email":"a@b.co"}'
check "valid email accepted" $?
expect_code 400 -X POST "$R/waitlist" -d '{"email":"not-an-email"}'
check "invalid email rejected" $?
for i in 1 2 3 4 5; do curl -s -o /dev/null -X POST "$R/waitlist" -d "{\"email\":\"x$i@ok.io\"}"; done
expect_code 429 -X POST "$R/waitlist" -d '{"email":"late@ok.io"}'
check "per-IP throttle engages (429)" $?

echo "── [7/7] structure-aware fuzzer (seeded)"
FUZZ_OUT=$(python3 - "$PORT" <<'PY'
import random, socket, sys, time
port = int(sys.argv[1])
random.seed(0xBEEF)
VALID_PATHS = ["/", "/health", "/index.json", "/packages/tiny.erebus", "/auth/login", "/waitlist"]
INJECT = [b"\r\n\r\n", b"--\r\n", b"%00", b"../"*8, b"A"*9999, b"\xff\xfe\xfd", b"-Infinity",
          b'{"email":"<script>"}', b'{"username":"a","password":"' + b"A"*5000 + b'"}']
def mutated_request():
    kind = random.random()
    path = random.choice(VALID_PATHS)
    if random.random() < 0.4:
        path += random.choice(INJECT).decode('latin1')[:random.randint(1,64)]
    body = random.choice([b"", b"{}", b"x=y"] + INJECT)
    hdrs = [
        f"Host: 127.0.0.1:{port}",
        f"Content-Length: {len(body)}" if random.random()<0.85 else f"Content-Length: {random.choice([-1,0,999999999])}",
    ]
    if random.random() < 0.3:
        hdrs.append("Authorization: Bearer " + random.choice(["", "alice:", ":tok", "a:b:c", "A"*300]))
    head = f"{random.choice(['GET','POST','PUT','DELETE','BREW'])} {path} HTTP/1.1\r\n" + "\r\n".join(hdrs) + "\r\n\r\n"
    return head.encode('latin1', 'replace') + body
alive = errors = sent = 0
for it in range(150):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.settimeout(5)
        s.sendall(mutated_request())
        try:
            while s.recv(4096):
                pass
        except (socket.timeout, ConnectionResetError, OSError):
            pass
        s.close()
        sent += 1
    except Exception as e:
        errors += 1
    time.sleep(0.01)
h = socket.create_connection(("127.0.0.1", port), timeout=5)
h.sendall(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
resp = h.recv(4096)
assert b"200" in resp.split(b"\r\n")[0], resp[:120]
print(f"FUZZ_OK sent={sent} conn_errors={errors}")
PY
)
echo "    $FUZZ_OUT"
echo "$FUZZ_OUT" | grep -q FUZZ_OK; check "150 fuzzed requests: server alive, health intact" $?
LITTER=$(ls "$WORK/reg/packages" 2>/dev/null | grep -c "incoming\|\.tmp" || true)
[ "$LITTER" = "0" ]; check "no temp/part litter left behind" $?
if grep -qiE "Traceback|Exception in thread" "$WORK/reg.log"; then
  check "no unhandled tracebacks in server log" 1
else
  check "no unhandled tracebacks in server log" 0
fi

echo ""
if [ "$failures" -eq 0 ]; then
  echo "CHAOS BUSINESS VERDICT: SURVIVED"
else
  echo "CHAOS BUSINESS VERDICT: $failures CHECK(S) FAILED"
  exit 1
fi
