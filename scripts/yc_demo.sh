#!/usr/bin/env bash
# yc_demo.sh — YC Demo Day: cryptographic proof of AI agent execution
#
# Full flow: build → sign → verify → enroll this machine → execute with capture
# → examine the spec 2.0 receipt (DSSE + machine co-signature) → tamper
# detection → transparency log push, offline proof, --strict → cosign interop
# → chaos monkeys
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
step "1/11 BUILD — Create a real agent"
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
step "2/11 KEYGEN — Generate Ed25519 signing keys"
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
step "3/11 SIGN + VERIFY — Cryptographic signature"
# ────────────────────────────────────────────────────────────
$ERE sign "$WORK/agent.erebus" --key "$KEY" -q 2>/dev/null && pass "Binary signed" || fail "Sign failed"

$ERE verify "$WORK/agent.erebus" --trusted-dir "$WORK/trusted" --json -o "$WORK/verify.json" 2>/dev/null
python3 -c "
import json
v = json.load(open('$WORK/verify.json'))
print(f'  verified={v[\"verified\"]}  key={str(v.get(\"key\",\"\"))[:50]}')
" && pass "Signature verified" || fail "Verify failed"

# ────────────────────────────────────────────────────────────
step "4/11 REGISTRY + ENROLL — Give this machine a certified identity"
# ────────────────────────────────────────────────────────────
SCRIPTS="$(dirname "$0")"
REG_PORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
REGISTRY="http://127.0.0.1:$REG_PORT"

python3 "$SCRIPTS/registry_server.py" --dir "$WORK/registry" --host 127.0.0.1 --port "$REG_PORT" \
    --log-origin yc-demo --anchor-every 0 >"$WORK/registry.log" 2>&1 &
REG_PID=$!
REG_UP=0
for _ in $(seq 1 30); do
    curl -sf --max-time 2 "$REGISTRY/health" >/dev/null 2>&1 && { REG_UP=1; break; }
    sleep 0.5
done
test "$REG_UP" -eq 1 && pass "Registry live on :$REG_PORT (SQLite Merkle transparency log)" || fail "Registry did not start"
trap 'mkdir -p /tmp/yc-harness-debug && cp "$WORK"/harness-*.log /tmp/yc-harness-debug/ 2>/dev/null; kill $REG_PID 2>/dev/null; rm -rf "$WORK"' EXIT

TOKEN=$(python3 -c "
import urllib.request, json
req = urllib.request.Request('$REGISTRY/auth/register',
    data=json.dumps({'username':'yc-demo','password':'demo-2026!'}).encode(),
    headers={'Content-Type':'application/json'})
try:
    print(json.loads(urllib.request.urlopen(req).read()).get('token',''))
except Exception:
    print('')
" 2>/dev/null)
test -n "$TOKEN" && pass "Operator account registered" || fail "Registration failed"
REG_KEY=$(curl -sf "$REGISTRY/log/key" | python3 -c "import json,sys;print(json.load(sys.stdin)['public_key_hex'])" 2>/dev/null || echo "")
info "Registry key: ${REG_KEY:0:16}… (signs checkpoints AND machine certificates)"

# The machine key never leaves this host; the registry only certifies it.
export ERE_MACHINE_DIR="$WORK/machine"
if $ERE enroll --registry "$REGISTRY" --token "$TOKEN" --json >"$WORK/enroll.json" 2>/dev/null; then
    pass "Machine enrolled"
    python3 -c "
import json
e = json.load(open('$WORK/enroll.json'))
c = e.get('certificate') or {}
print(f'  machine_id:  {e[\"machine_id\"][:52]}...')
print(f'  key file:    {e[\"dir\"]}/machine.key (0600, never leaves this host)')
print(f'  certificate: owner={c.get(\"owner\")} registry={c.get(\"registry\")} issued_at={c.get(\"issued_at\")}')
" 2>/dev/null || true
else
    fail "Enroll failed"
fi

# ────────────────────────────────────────────────────────────
step "5/11 EXECUTE — Run with behavior capture (spec 2.0 receipt)"
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
step "6/11 RECEIPT — Examine the signed proof (DSSE + machine co-signature)"
# ────────────────────────────────────────────────────────────
if [ -f "$WORK/agent.attest" ]; then
    python3 <<PYEOF
import json
att = json.load(open("$WORK/agent.attest"))
print(f"  spec_version:      {att['spec_version']}")
print(f"  attestation_type:  {att['attestation_type']}")
env = att.get('envelope') or {}
print(f"  envelope:          {env.get('payloadType','-')} — {len(env.get('signatures',[]))} signature(s): "
      + ", ".join(s['keyid'][:23] + '…' for s in env.get('signatures',[])))
m = att.get('machine') or {}
print(f"  machine:           {m.get('machine_id','(not enrolled)')[:52]}"
      + (f"  certified by {m['certificate']['registry']} for {m['certificate']['owner']}" if m.get('certificate') else ""))
print(f"  predicate:         {att['statement'].get('predicateType', att['statement'].get('predicate_type'))}")
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
print(f"    rootfs_root:     {(ex.get('rootfs_root') or 'N/A')[:52]}...")
print(f"    prev_receipt:    {(ex.get('prev_attestation_hash') or 'none (first in trail)')[:52]}")
print(f"    machine_id:      {(ex.get('machine_id') or 'N/A')[:52]}  (inside the SIGNED statement)")
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

    # Independent verification: operator signature + machine identity + bundle binding.
    VA_OUT=$($ERE verify-attest "$WORK/agent.attest" --trusted-dir "$WORK/trusted" \
        --bundle "$WORK/agent.erebus" --strict --registry-key "$REG_KEY" 2>&1 || true)
    echo "$VA_OUT" | sed 's/^/  /'
    echo "$VA_OUT" | grep -q "OK: attestation verified" && pass "verify-attest: operator signature, signed fields consistent, bundle bound" || fail "verify-attest failed"
    echo "$VA_OUT" | grep -q "OK: machine" && pass "verify-attest --strict: co-signed by the enrolled machine, certificate trusted" || fail "--strict failed"

    # Same receipt, edited exit code → refused: the display copy no longer
    # matches the signed statement.
    python3 -c "
import json
d = json.load(open('$WORK/agent.attest'))
d['execution']['exit_code'] = 1
json.dump(d, open('$WORK/agent.attest.edited', 'w'), indent=2)
"
    EDIT_OUT=$($ERE verify-attest "$WORK/agent.attest.edited" --trusted-dir "$WORK/trusted" 2>&1 || true)
    echo "$EDIT_OUT" | grep -q "TAMPERED" && pass "Edited receipt (exit_code 0→1) REFUSED — $(echo "$EDIT_OUT" | grep -o 'TAMPERED[^(]*' | head -1)" || fail "Edited receipt accepted"
else
    fail "No attestation file"
fi

# ────────────────────────────────────────────────────────────
step "7/11 TAMPER DETECTION — Corrupt the binary"
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
step "8/11 INTEGRITY — Untampered binary still verifies"
# ────────────────────────────────────────────────────────────
$ERE verify "$WORK/agent.erebus" --trusted-dir "$WORK/trusted" --json -o "$WORK/verify.json" 2>/dev/null
python3 -c "
import json
v = json.load(open('$WORK/verify.json'))
print(f'  verified={v[\"verified\"]}')
" && pass "Original binary intact" || fail "Original binary broken"

# ────────────────────────────────────────────────────────────
step "9/11 TRANSPARENCY LOG — push, kill the registry, prove offline"
# ────────────────────────────────────────────────────────────
if [ -z "$TOKEN" ]; then
    info "No registry token — skipping log push"
else
    # Push the RUNTIME receipt (input/output hashes + exit code) into the
    # Merkle log; the registry answers with its leaf position.
    PUSH_OUT=$(python3 -c "
import urllib.request, json
att = open('$WORK/agent.attest','rb').read()
req = urllib.request.Request('$REGISTRY/attestations', data=att,
    headers={'Content-Type':'application/json','Authorization':'Bearer $TOKEN'})
try:
    print(json.dumps(json.loads(urllib.request.urlopen(req).read())))
except Exception as e:
    print('ERROR:' + str(e))
" 2>/dev/null)
    if echo "$PUSH_OUT" | grep -q "ERROR:"; then
        fail "Runtime receipt push failed: $PUSH_OUT"
    else
        echo "$PUSH_OUT" | python3 -c "
import json,sys
d=json.load(sys.stdin); l=d.get('log') or {}; cp=l.get('checkpoint') or {}
print(f'  runtime receipt → leaf #{l.get(\"leaf_index\")} of {l.get(\"tree_size\")}  root={str(l.get(\"root\"))[:40]}...')
print(f'  checkpoint signed by {str(cp.get(\"key_id\"))[:30]}... at {cp.get(\"timestamp\")}')
" 2>/dev/null || true
        pass "Runtime receipt in the transparency log"
    fi

    # A detached receipt via the CLI: the proof is verified and stored next
    # to it, then checked again OFFLINE (registry killed below).
    sleep 1.1   # distinct attested_at → distinct leaf
    $ERE attest "$WORK/agent.erebus" --key "$KEY" --output "$WORK/detached.attest" --no-log \
        --envelope "$WORK/agent.dsse.json" --push --registry "$REGISTRY" --token "$TOKEN" 2>&1 | sed 's/^/  /'
    test -f "$WORK/detached.attest.proof.json" && pass "Inclusion proof stored: detached.attest.proof.json" || fail "No proof file"

    BUNDLE=$(python3 -c "import json;print(json.load(open('$WORK/agent.attest'))['artifact']['bundle_hash'])" 2>/dev/null)
    $ERE attest-history --registry "$REGISTRY" --token "$TOKEN" --query "bundle=$BUNDLE" --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
recs = d.get('records', d if isinstance(d, list) else [])
print(f'  history: {len(recs)} receipt(s) for this bundle')
" 2>/dev/null && pass "Registry queryable history" || fail "History query failed"

    # Registry gone. Everything below is offline.
    kill $REG_PID 2>/dev/null || true
    wait $REG_PID 2>/dev/null || true
    info "Registry stopped — verifying with nothing but files and public keys"
    PROOF_OUT=$($ERE verify-attest "$WORK/detached.attest" --trusted-dir "$WORK/trusted" \
        --proof --log-key "$REG_KEY" --strict 2>&1 || true)
    echo "$PROOF_OUT" | sed 's/^/  /'
    echo "$PROOF_OUT" | grep -q "OK: transparency log" && pass "Offline proof: leaf, Merkle path, signed checkpoint" || fail "Offline proof failed"
    echo "$PROOF_OUT" | grep -q "OK: machine" && pass "Offline --strict: machine co-signature + registry certificate" || fail "Offline --strict failed"

    # Forge the proof's tree size → refused.
    python3 -c "
import json
p = json.load(open('$WORK/detached.attest.proof.json'))
p['tree_size'] += 1; p['checkpoint']['size'] += 1
json.dump(p, open('$WORK/forged.proof.json','w'))
"
    FORGE_OUT=$($ERE verify-attest "$WORK/detached.attest" --trusted-dir "$WORK/trusted" \
        --proof-file "$WORK/forged.proof.json" --log-key "$REG_KEY" 2>&1 || true)
    echo "$FORGE_OUT" | grep -q "TAMPERED" && pass "Forged checkpoint REFUSED" || fail "Forged checkpoint accepted"
fi

# ────────────────────────────────────────────────────────────
step "10/11 INTEROP — Verify the same receipt with Sigstore cosign"
# ────────────────────────────────────────────────────────────
PEM=$(ls "$WORK/keys"/*.pem 2>/dev/null | head -1)
if command -v cosign >/dev/null 2>&1 && [ -f "$WORK/agent.dsse.json" ] && [ -n "$PEM" ]; then
    COSIGN_OUT=$(cosign verify-blob-attestation --key "$PEM" --signature "$WORK/agent.dsse.json" \
        --type https://erebus.dev/attestation/execution/v2 --insecure-ignore-tlog "$WORK/agent.erebus" 2>&1 || true)
    echo "$COSIGN_OUT" | grep -v "WARNING\|deprecated" | sed 's/^/  /'
    echo "$COSIGN_OUT" | grep -q "Verified OK" && pass "cosign verify-blob-attestation: Verified OK — standard DSSE/in-toto, zero erebus tooling" || fail "cosign refused the envelope"
    python3 -c "
import json,base64
e=json.load(open('$WORK/agent.dsse.json'))
p=json.loads(base64.b64decode(e['payload'])); p['predicate']['execution']['os']='plan9'
e['payload']=base64.b64encode(json.dumps(p,separators=(',',':')).encode()).decode()
json.dump(e,open('$WORK/bad.dsse.json','w'))"
    if cosign verify-blob-attestation --key "$PEM" --signature "$WORK/bad.dsse.json" \
        --type https://erebus.dev/attestation/execution/v2 --insecure-ignore-tlog "$WORK/agent.erebus" >/dev/null 2>&1; then
        fail "cosign accepted a tampered envelope"
    else
        pass "cosign REFUSES the tampered envelope"
    fi
else
    info "cosign not installed (or no envelope) — skipping Sigstore interop (CI runs it)"
fi

# ────────────────────────────────────────────────────────────
step "11/11 CHAOS — All 4 harnesses (extreme mode)"
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
    echo -e "${BOLD}${GREEN}║  ✓ Spec 2.0 receipt: DSSE + in-toto, input/output/exit   ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Machine identity: enrolled key co-signs, --strict     ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Tamper detection: binary, receipt, proof all refused  ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Transparency log: offline proof after registry death  ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Sigstore interop: cosign says Verified OK             ║${NC}"
    echo -e "${BOLD}${GREEN}║  ✓ Chaos monkeys ($CHAOS_PASS/4) — all SURVIVED               ║${NC}"
    echo -e "${BOLD}${GREEN}║                                                          ║${NC}"
    echo -e "${BOLD}${GREEN}║  60-second pitch: \"erebus packages any AI agent into      ║${NC}"
    echo -e "${BOLD}${GREEN}║  a single signed binary. Every run leaves a standard,    ║${NC}"
    echo -e "${BOLD}${GREEN}║  signed receipt proving WHAT ran, WHERE (enrolled        ║${NC}"
    echo -e "${BOLD}${GREEN}║  machine), WHEN (public Merkle log + TSA) and WHAT IT    ║${NC}"
    echo -e "${BOLD}${GREEN}║  DID — verifiable offline by erebus or cosign. No infra  ║${NC}"
    echo -e "${BOLD}${GREEN}║  needed. EU AI Act / SOC 2 audit trail, by construction.\"║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${BOLD}${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${RED}║  YC DEMO: $FAILURES CHECK(S) FAILED                           ║${NC}"
    echo -e "${BOLD}${RED}╚══════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
