#!/usr/bin/env bash
# ROADMAP P1-5: the macOS slice, run for real on the host it targets.
#
# Builds a native Mach-O agent into a signed bundle with the native stub, then
# checks launch, receipts, chain, tamper refusal, evidence export, output /
# stdin / exit capture and the Seatbelt filesystem sandbox.
#
# Usage: scripts/macos_slice.sh [path/to/erebus] [path/to/erebus-stub]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EREBUS="${1:-$ROOT/target/release/erebus}"
STUB="${2:-$ROOT/target/release/erebus-stub}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
PASS=0

ok() { PASS=$((PASS + 1)); echo "  ok  $*"; }
die() { echo "  FAIL $*" >&2; exit 1; }
run_agent() { # bundle stdin-text
  printf '%s' "$2" | ERE_TRUSTED_DIR="$W/trusted" XDG_CACHE_HOME="$W/cache" \
    ERE_ATTEST_KEY="$KEY" "$1"
}

[[ "$(uname -s)" == Darwin ]] || die "run this on macOS"
echo "macOS slice on $(uname -m) — $(sw_vers -productVersion)"
file "$STUB" | grep -q "Mach-O 64-bit executable $(uname -m)" || die "stub is not a native Mach-O"
ok "native stub: $(file -b "$STUB" | cut -d, -f1)"

mkdir -p "$W/app" "$W/canary-app" "$W/trusted"
cat >"$W/agent.c" <<'EOF'
#include <stdio.h>
int main(void) {
  char b[256]; size_t n = fread(b, 1, sizeof b - 1, stdin); b[n] = 0;
  printf("agent saw %zu bytes: %s\n", n, b);
  return 0;
}
EOF
cc -O2 -o "$W/app/app" "$W/agent.c"

cd "$W"
build_log="$(ERE_STUB_PATH="$STUB" "$EREBUS" build app -o agent.erebus 2>&1)"
grep -q "Detected runtime: binary" <<<"$build_log" || die "Mach-O agent not detected: $build_log"
! grep -q glibc <<<"$build_log" || die "glibc staged for a Mach-O payload"
ok "Mach-O agent detected as binary runtime, no Linux glibc staged"

"$EREBUS" keygen --key-dir keys >/dev/null 2>&1
KEY="$(ls keys/*.key)"
cp keys/*.pub trusted/
"$EREBUS" sign agent.erebus --key "$KEY" >/dev/null 2>&1
chmod +x agent.erebus

if printf x | XDG_CACHE_HOME="$W/cache" ERE_TRUSTED_DIR="$W/none" ./agent.erebus >/dev/null 2>&1; then
  die "signed bundle started without trusted keys"
fi
ok "signed bundle refuses to start without trusted keys (fail-cold)"

out="$(run_agent ./agent.erebus 'hello mac' 2>&1)"
grep -q "agent saw 9 bytes: hello mac" <<<"$out" || die "cold run: $out"
[[ -f agent.erebus.attest ]] || die "no receipt after cold run"
ok "cold run executes the agent and writes a receipt"

out="$(run_agent ./agent.erebus 'second' 2>&1)"
grep -q "agent saw 6 bytes" <<<"$out" || die "warm run: $out"
# Captured first: `cmd | grep -q` under pipefail fails at random when grep
# exits early and cmd gets EPIPE on its remaining lines.
chain="$("$EREBUS" verify-attest --chain agent.erebus.attest.d --trusted-dir trusted \
  --bundle agent.erebus 2>&1)" || die "chain verification failed: $chain"
grep -q "2 receipt(s)" <<<"$chain" || die "chain of 2 not verified: $chain"
"$EREBUS" verify-attest agent.erebus.attest --trusted-dir trusted \
  --bundle agent.erebus >/dev/null 2>&1 || die "latest receipt not verified"
ok "warm run chained: 2 receipts verified against the bundle"

first="$(ls agent.erebus.attest.d/000001-*.json)"
cp "$first" first.bak
python3 - "$first" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read()
i = s.index('"rootfs_root": "sha256:') + len('"rootfs_root": "sha256:')
s = s[:i] + ("0" if s[i] != "0" else "1") + s[i + 1:]
open(p, "w").write(s)
EOF
if "$EREBUS" verify-attest --chain agent.erebus.attest.d --trusted-dir trusted >/dev/null 2>&1; then
  die "edited receipt accepted"
fi
cp first.bak "$first"
ok "edited receipt refused by the chain"

cp agent.erebus pristine.erebus
python3 - "$(stat -f%z "$STUB")" <<'EOF'
import sys
stub = int(sys.argv[1])
b = bytearray(open("agent.erebus", "rb").read())
b[stub + (len(b) - stub) // 3] ^= 0xFF
open("agent.erebus", "wb").write(b)
EOF
if out="$(run_agent ./agent.erebus 'evil' 2>&1)"; then
  die "tampered bundle ran on a warm cache: $out"
fi
grep -q "signature verification failed" <<<"$out" || die "unexpected refusal: $out"
cp pristine.erebus agent.erebus
ok "payload byte flip refused on a warm cache (Ed25519)"

"$EREBUS" evidence export agent.erebus --trail agent.erebus.attest.d \
  --trusted-dir trusted -o ev.zip >/dev/null 2>&1 || die "evidence export"
fp="$(basename "$KEY" .key)"
"$EREBUS" verify-evidence ev.zip --bundle agent.erebus --operator-key "$fp" \
  >/dev/null 2>&1 || die "verify-evidence"
ok "evidence pack exported and verified with the pinned operator key"

# The last receipt is the warm run fed 'second': recompute every captured
# digest independently from what the agent printed and was given.
python3 - agent.erebus.attest <<'EOF' || die "captured digests do not match the run"
import hashlib, json, sys
h = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()
e = json.load(open(sys.argv[1]))["statement"]["predicate"]["execution"]
out = h(b"agent saw 6 bytes: second\n")
want = h((out + ":" + h(b"")).encode())
assert e["exit_code"] == 0, e
assert e["output_hash"] == want, (e["output_hash"], want)
assert e["stdin_hash"] == h(b"second"), e.get("stdin_hash")
EOF
ok "signed output_hash, stdin_hash and exit_code re-derived from the run"

cat >"$W/fail.c" <<'EOF'
#include <stdio.h>
int main(void) { fputs("failing\n", stderr); return 3; }
EOF
mkdir -p fail-app && cc -O2 -o fail-app/app "$W/fail.c"
ERE_STUB_PATH="$STUB" "$EREBUS" build fail-app -o fail.erebus >/dev/null 2>&1
chmod +x fail.erebus
set +e
run_agent ./fail.erebus '' >/dev/null 2>&1
rc=$?
set -e
code="$(python3 -c 'import json;print(json.load(open("fail.erebus.attest"))["statement"]["predicate"]["execution"]["exit_code"])')"
[[ $rc == 3 && $code == 3 ]] || die "exit 3 not relayed/signed (stub rc=$rc, signed=$code)"
ok "non-zero exit relayed by the stub and signed (exit_code 3)"

echo 'SECRET-CANARY' >"$W/canary.txt"
cat >"$W/canary.c" <<EOF
#include <stdio.h>
int main(void) { FILE *f = fopen("$W/canary.txt", "r"); puts(f ? "READ" : "BLOCKED"); return 0; }
EOF
cc -O2 -o canary-app/app "$W/canary.c"
ERE_STUB_PATH="$STUB" "$EREBUS" build canary-app -o canary.erebus --landlock >/dev/null 2>&1
ERE_STUB_PATH="$STUB" "$EREBUS" build canary-app -o open.erebus >/dev/null 2>&1
chmod +x canary.erebus open.erebus
out="$(XDG_CACHE_HOME="$W/cache" ./open.erebus 2>/dev/null)"
[[ "$out" == READ ]] || die "control: the unsandboxed canary could not read its file: $out"
out="$(XDG_CACHE_HOME="$W/cache" ./canary.erebus 2>/dev/null)"
[[ "$out" == BLOCKED ]] || die "sandbox: payload read a file outside its rootfs: $out"
out="$(run_agent ./canary.erebus '' 2>&1)"
grep -q BLOCKED <<<"$out" || die "sandbox lost under capture: $out"
ok "Seatbelt: canary outside the rootfs blocked (control without --landlock reads it), also under capture"

python3 -c '
import socket, sys, time
s = [socket.create_server(("127.0.0.1", 0)) for _ in range(2)]
open(sys.argv[1], "w").write(" ".join(str(x.getsockname()[1]) for x in s) + "\n")
time.sleep(300)' "$W/ports" &
LISTENERS=$!
trap 'kill $LISTENERS 2>/dev/null; wait $LISTENERS 2>/dev/null; rm -rf "$W"' EXIT
for _ in $(seq 50); do [[ -s "$W/ports" ]] && break; sleep 0.1; done
read -r PA PB <"$W/ports"
cat >"$W/net.c" <<'EOF'
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
static const char *try_port(int port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a; memset(&a, 0, sizeof a);
  a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int r = connect(s, (struct sockaddr *)&a, sizeof a); close(s);
  return r == 0 ? "OK" : "BLOCKED";
}
int main(void) { printf("A=%s B=%s\n", try_port(PA), try_port(PB)); return 0; }
EOF
mkdir -p net-app && cc -O2 -DPA="$PA" -DPB="$PB" -o net-app/app "$W/net.c"
ERE_STUB_PATH="$STUB" "$EREBUS" build net-app -o net.erebus >/dev/null 2>&1
chmod +x net.erebus
out="$(XDG_CACHE_HOME="$W/cache" ./net.erebus 2>/dev/null)"
[[ "$out" == "A=OK B=OK" ]] || die "control: unconfined agent could not reach both listeners: $out"
out="$(ERE_EGRESS="$PA" XDG_CACHE_HOME="$W/cache" ./net.erebus 2>/dev/null)"
[[ "$out" == "A=OK B=BLOCKED" ]] || die "egress: agent reached a port outside ERE_EGRESS: $out"
out="$(ERE_EGRESS="$PA" run_agent ./net.erebus '' 2>/dev/null)"
[[ "$out" == "A=OK B=BLOCKED" ]] || die "egress lost under capture: $out"
python3 - net.erebus.attest "$PA" <<'EOF' || die "egress policy not signed"
import json, sys
e = json.load(open(sys.argv[1]))["statement"]["predicate"]["execution"]
assert e["egress"] == {"tcp_ports": [int(sys.argv[2])], "scope": "loopback"}, e.get("egress")
EOF
if out="$(ERE_EGRESS="all" XDG_CACHE_HOME="$W/cache" ./net.erebus 2>&1)"; then
  die "invalid ERE_EGRESS ran unconfined: $out"
fi
grep -q "bad egress policy, refusing to run" <<<"$out" || die "unexpected egress refusal: $out"
ok "egress: only the ERE_EGRESS port reachable (control reaches both), signed in the receipt, invalid policy refused"

echo "VERDICT: macOS slice OK ($PASS checks)"
