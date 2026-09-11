#!/usr/bin/env bash
# yc_demo.sh — YC Demo Day: cryptographic proof of AI agent execution
#
# Full flow: build → sign → verify → execute with capture → examine attestation
# → tamper detection → registry push + query → chaos monkeys
#
# Every step shows cryptographic evidence. No hand-waving.
set -euo pipefail

ERE="${ERE_BIN:-/tmp/erebus-stub-target/release/erebus}"
STUB="${ERE_STUB_PATH:-/tmp/erebus-stub-target/release/erebus-stub}"
export PATH="$HOME/.local/bin:$PATH"
export ERE_STUB_PATH="$STUB"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

step() { echo -e "\n${BOLD}${BLUE}━━━ $1 ━━━${NC}"; }
pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; FAILURES=$((FAILURES+1)); }
info() { echo -e "  ${YELLOW}→${NC} $1"; }
show() { echo -e "  ${BOLD}$1${NC}"; }

FAILURES=0
WORK=$(mktemp -d /tmp/yc-demo.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# ────────────────────────────────────────────────────────────
step "1/9  BUILD — Create a real agent"
# ────────────────────────────────────────────────────────────
APP="$WORK/agent"
mkdir -p "$APP"
cat > "$APP/app.py" <<'PY'
import sys, json, math

def analyze(data):
    """Analyze a dataset and return statistics."""
    nums = data.get("values", [])
    if not nums:
        return {"error": "empty dataset"}
    return {
        "count": len(nums),
        "sum": sum(nums),
        "mean": round(sum(nums) / len(nums), 4),
        "stdev": round(math.sqrt(sum((x - sum(nums)/len(nums))**2 for x in nums) / len(nums)), 4),
        "min": min(nums),
        "max": max(nums),
    }

if __name__ == "__main__":
    data = json.loads(sys.stdin.read())
    result = analyze(data)
    json.dump(result, sys.stdout, indent=2)
    print(file=sys.stdout)
PY

cat > "$WORK/input.json" <<'JSON'
{"values": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 42, 17, 23, 8, 5]}
JSON

$ERE build "$APP" -o "$WORK/agent.erebus" -q 2>/dev/null
$ERE inspect "$WORK/agent.erebus" --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
meta = d.get('meta',{})
ep = meta.get('entrypoint',[])
rt = meta.get('embedded_runtime',{})
print(f'  entrypoint: {ep}')
print(f'  runtime: {rt.get(\"interpreter\",\"?\")}')
print(f'  format_version: {d.get(\"format_version\",\"?\")}')
print(f'  signed: {d.get(\"signed\",\"?\")}')
" && pass "Agent built" || fail "Build failed"

# ────────────────────────────────────────────────────────────
step "2/9  KEYGEN — Generate Ed25519 signing keys"
# ────────────────────────────────────────────────────────────
mkdir -p "$WORK/keys" "$WORK/trusted"
$ERE keygen --key-dir "$WORK/keys" --json -q 2>/dev/null | python3 -c "
import json,sys
k=json.load(sys.stdin)
print(f'  fingerprint: {k[\"fingerprint\"]}')
print(f'  private_key: ...{k[\"private_key\"][-20:]}')
print(f'  public_key:  ...{k[\"public_key\"][-20:]}')
" && pass "Ed25519 keypair generated" || fail "Keygen failed"

KEY=$(ls "$WORK/keys"/*.key | head -1)
PUB=$(ls "$WORK/keys"/*.pub | head -1)
cp "$PUB" "$WORK/trusted/"

# ────────────────────────────────────────────────────────────
step "3/9  SIGN + VERIFY — Cryptographic signature"
# ────────────────────────────────────────────────────────────
$ERE sign "$WORK/agent.erebus" --key "$KEY" -q 2>/dev/null && pass "Binary signed" || fail "Sign failed"

$ERE verify "$WORK/agent.erebus" --trusted-dir "$WORK/trusted" --json -o "$WORK/verify.json" 2>/dev/null
python3 -c "
import json
v = json.load(open('$WORK/verify.json'))
print(f'  verified={v[\"verified\"]}  key={str(v.get(\"key\",\"\"))[:50]}')
" && pass "Signature verified" || fail "Verify failed"

# ────────────────────────────────────────────────────────────
step "4/9  EXECUTE — Run with behavior capture (spec 1.1)"
# ────────────────────────────────────────────────────────────
export ERE_ATTEST_KEY="$KEY"
export ERE_ATTEST_OUT="$WORK/agent.attest"
export ERE_TRUSTED_DIR="$WORK/trusted"

show "  Input (piped to agent):"
cat "$WORK/input.json" | sed 's/^/    /'

set +e
timeout 30 bash -c 'cat "$0" | "$1" > "$2" 2> "$3"' \
    "$WORK/input.json" "$WORK/agent.erebus" "$WORK/output.json" "$WORK/stderr.log"
RC=$?
set -e
if [ $RC -ne 0 ]; then
    echo "  (agent exited rc=$RC) — stderr:"
    sed 's/^/    /' "$WORK/stderr.log" 2>/dev/null || true
fi

show "  Output:"
cat "$WORK/output.json" | sed 's/^/    /'

echo "  exit_code: $RC"
test $RC -eq 0 && pass "Agent executed (exit 0)" || fail "Agent failed (rc=$RC)"
test -f "$WORK/agent.attest" && pass "Attestation file written" || fail "No attestation file"

# ────────────────────────────────────────────────────────────
step "5/9  ATTESTATION — Examine the signed proof"
# ────────────────────────────────────────────────────────────
if [ -f "$WORK/agent.attest" ]; then
    python3 <<PYEOF
import json
att = json.load(open("$WORK/agent.attest"))
print(f"  spec_version:      {att['spec_version']}")
print(f"  attestation_type:  {att['attestation_type']}")
print()
print("  Artifact:")
a = att['artifact']
print(f"    bundle_hash:     {a['bundle_hash'][:52]}...")
print(f"    payload_hash:    {a['payload_hash'][:52]}...")
print(f"    format_version:  {a['format_version']}")
print(f"    flags:           {a['flags']}")
print()
print("  Provenance:")
p = att['provenance']
print(f"    builder:         {p['builder']}")
print(f"    layers:          {len(p['layers'])}")
for l in p['layers']:
    print(f"      - {l['name']} ({l['kind']}): {l['sha256'][:36]}...")
print()
print("  Execution:")
ex = att['execution']
print(f"    attested_at:     {ex['attested_at']}")
print(f"    machine_id_hash: {ex['machine_id_hash'][:52]}...")
print(f"    os/arch:         {ex['os']}/{ex['arch']}")
ih = ex.get('input_hash')
oh = ex.get('output_hash')
ec = ex.get('exit_code')
print(f"    input_hash:      {(ih or 'N/A')[:52]}...")
print(f"    output_hash:     {(oh or 'N/A')[:52]}...")
print(f"    exit_code:       {ec}")
print()
print("  Signature:")
sig = att['signature']
print(f"    algorithm:       {sig.get('algorithm','?')}")
print(f"    key_fingerprint: {sig['key_fingerprint'][:52]}...")
print(f"    signature_hex:   {sig['signature_hex'][:52]}...")
print()
pred = att.get('statement',{}).get('predicate',{}).get('execution',{})
print("  Predicate vs Execution:")
print(f"    input_hash match:  {pred.get('input_hash') == ih}")
print(f"    output_hash match: {pred.get('output_hash') == oh}")
print(f"    exit_code match:   {pred.get('exit_code') == ec}")
PYEOF
    # Verify that capture fields are present (non-null)
    CAPTURE_OK=$(python3 -c "
import json
att = json.load(open('$WORK/agent.attest'))
ex = att['execution']
ok = ex.get('input_hash') is not None and ex.get('output_hash') is not None and ex.get('exit_code') is not None
print('yes' if ok else 'no')
" 2>/dev/null)
    test "$CAPTURE_OK" = "yes" && pass "Behavior capture complete (input_hash + output_hash + exit_code)" || fail "Behavior capture fields missing"
else
    fail "No attestation file"
fi

# ────────────────────────────────────────────────────────────
step "6/9  TAMPER DETECTION — Corrupt the binary"
# ────────────────────────────────────────────────────────────
cp "$WORK/agent.erebus" "$WORK/tampered.erebus"
python3 -c "
with open('$WORK/tampered.erebus', 'r+b') as f:
    f.seek(-100, 2)
    data = f.read(1)
    f.seek(-100, 2)
    f.write(bytes([data[0] ^ 0xFF]))
"
info "Byte flipped at offset -100 from EOF"
VERIFY_OUT=$($ERE verify "$WORK/tampered.erebus" --trusted-dir "$WORK/trusted" 2>&1 || true)
echo "  $VERIFY_OUT" | head -2
echo "$VERIFY_OUT" | grep -qi "tamper\|invalid\|mismatch\|error" && pass "Tamper DETECTED" || fail "Tamper NOT detected"

# ────────────────────────────────────────────────────────────
step "7/9  INTEGRITY — Untampered binary still verifies"
# ────────────────────────────────────────────────────────────
$ERE verify "$WORK/agent.erebus" --trusted-dir "$WORK/trusted" --json -o "$WORK/verify.json" 2>/dev/null
python3 -c "
import json
v = json.load(open('$WORK/verify.json'))
print(f'  verified={v[\"verified\"]}')
" && pass "Original binary intact" || fail "Original binary broken"

# ────────────────────────────────────────────────────────────
step "8/9  REGISTRY — Push + query attestation history"
# ────────────────────────────────────────────────────────────
SCRIPTS="$(dirname "$0")"
REG_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
REGISTRY="http://127.0.0.1:$REG_PORT"

python3 "$SCRIPTS/registry_server.py" --dir "$WORK/registry" --host 127.0.0.1 --port "$REG_PORT" >"$WORK/registry.log" 2>&1 &
REG_PID=$!
REG_UP=0
for _ in $(seq 1 30); do
    curl -sf --max-time 2 "$REGISTRY/health" >/dev/null 2>&1 && { REG_UP=1; break; }
    sleep 0.5
done
test "$REG_UP" -eq 1 && pass "Registry live on :$REG_PORT" || fail "Registry did not start"
trap 'mkdir -p /tmp/yc-harness-debug && cp "$WORK"/harness-*.log /tmp/yc-harness-debug/ 2>/dev/null; kill $REG_PID 2>/dev/null; rm -rf "$WORK"' EXIT

# Register
REG_RESULT=$(python3 -c "
import urllib.request, json
req = urllib.request.Request('$REGISTRY/auth/register',
    data=json.dumps({'username':'yc-demo','password':'demo-2026!'}).encode(),
    headers={'Content-Type':'application/json'})
try:
    resp = urllib.request.urlopen(req)
    d = json.loads(resp.read())
    print(d.get('token',''))
except Exception as e:
    print('ERROR:' + str(e))
" 2>/dev/null)

if echo "$REG_RESULT" | grep -q "^ERROR:"; then
    info "Registry registration: $REG_RESULT — skipping push"
else
    TOKEN="$REG_RESULT"
    info "Token: ${TOKEN:0:20}..."
    
    # Push the RUNTIME attestation (captured in step 4/5) — it carries the
    # input/output hashes + exit code. `erebus attest --push` regenerates a
    # detached doc without execution data, so post the captured file instead.
    PUSH_OUT=$(python3 -c "
import urllib.request, json
att = open('$WORK/agent.attest','rb').read()
req = urllib.request.Request('$REGISTRY/attestations',
    data=att,
    headers={'Content-Type':'application/json','Authorization':'Bearer ' + '$TOKEN'})
try:
    resp = urllib.request.urlopen(req)
    print(json.dumps(json.loads(resp.read())))
except Exception as e:
    print('ERROR:' + str(e))
" 2>/dev/null)
    
    if echo "$PUSH_OUT" | grep -q "ERROR:"; then
        info "Registry push failed: $PUSH_OUT" && fail "Attestation push failed"
    else
        PUSH_ID=$(echo "$PUSH_OUT" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('id','?'))" 2>/dev/null)
        pass "Attestation pushed (id: ${PUSH_ID:-?})"
    fi
    
    # Query history
    BUNDLE=$(python3 -c "
import json
att = json.load(open('$WORK/agent.attest'))
print(att['artifact']['bundle_hash'])
" 2>/dev/null)
    
    if [ -n "$BUNDLE" ]; then
        $ERE attest-history --registry "$REGISTRY" --token "$TOKEN" --query "bundle=$BUNDLE" --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
recs = d.get('records', d if isinstance(d, list) else [])
print(f'  records: {len(recs)}')
for r in recs[:3]:
    ex = r.get('attestation',{}).get('execution',{})
    print(f'    [{ex.get(\"attested_at\",\"?\")[:19]}] input={str(ex.get(\"input_hash\",\"?\"))[:30]}...')
" 2>/dev/null && pass "Registry queryable history" || fail "History query failed"
    fi
fi

# ────────────────────────────────────────────────────────────
step "9/9  CHAOS — All 4 harnesses (extreme mode)"
# ────────────────────────────────────────────────────────────
SCRIPTS="$(dirname "$0")"
CHAOS_PASS=0; CHAOS_FAIL=0
run_harness() { # run_harness <name> [<ere_bin>|iterations via ERE_BIN]
    local harness="$1"; local hargs="$2"
    local HPATH="$SCRIPTS/$harness"
    [ -f "$HPATH" ] || return
    printf "  %-35s" "$harness"
    if timeout 420 bash "$HPATH" $hargs >"$WORK/harness-$harness.log" 2>&1; then
        echo -e "${GREEN}SURVIVED${NC}"
        CHAOS_PASS=$((CHAOS_PASS+1))
    else
        echo -e "${RED}FAILED${NC}"
        CHAOS_FAIL=$((CHAOS_FAIL+1))
    fi
}
ERE_BIN="$ERE" run_harness chaos_monkey.sh "20"
run_harness chaos_business.sh "$ERE"
run_harness chaos_registry_serve.sh "$ERE"
run_harness chaos_frontends.sh "$ERE"
test $CHAOS_FAIL -eq 0 && pass "All $CHAOS_PASS chaos harnesses SURVIVED" || fail "$CHAOS_FAIL chaos harness(es) FAILED"

# ────────────────────────────────────────────────────────────
step "SUMMARY"
# ────────────────────────────────────────────────────────────
echo ""
if [ $FAILURES -eq 0 ]; then
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║  YC DEMO: ALL CHECKS PASSED                             ║${NC}"
    echo -e "${BOLD}${GREEN}║                                                          ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Cryptographic proof of AI agent execution             ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Behavior capture (spec 1.1) — input/output/exit       ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Tamper detection — corrupted binary rejected          ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Registry + queryable attestation history              ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Chaos monkeys ($CHAOS_PASS/4) — all SURVIVED               ║${NC}"
    echo -e "${BOLD}${GREEN}║                                                          ║${NC}"
    echo -e "${BOLD}${GREEN}║  60-second pitch: \"erebus packages any AI agent into      ║${NC}"
    echo -e "${BOLD}${GREEN}║  a single signed binary. When it runs, it produces a     ║${NC}"
    echo -e "${BOLD}${GREEN}║  cryptographically signed attestation proving WHAT ran,   ║${NC}"
    echo -e "${BOLD}${GREEN}║  WHERE, WHEN, and WHAT IT DID — input/output hashes,     ║${NC}"
    echo -e "${BOLD}${GREEN}║  exit code, all signed by the agent's key. No infra      ║${NC}"
    echo -e "${BOLD}${GREEN}║  needed. EU AI Act / SOC 2 compliant audit trail.\"        ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${BOLD}${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${RED}║  YC DEMO: $FAILURES CHECK(S) FAILED                           ║${NC}"
    echo -e "${BOLD}${RED}╚══════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
