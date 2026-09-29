#!/usr/bin/env bash
# ROADMAP P1-5: the macOS slice, run for real on the host it targets.
#
# Builds a native Mach-O agent into a signed bundle with the native stub, then
# checks launch, receipts, chain, tamper refusal and evidence export. Known
# gaps are printed as KNOWN GAP (they do not fail the run) until fixed.
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
"$EREBUS" verify-attest --chain agent.erebus.attest.d --trusted-dir trusted \
  --bundle agent.erebus 2>&1 | grep -q "2 receipt(s)" || die "chain of 2 not verified"
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

cap="$(python3 -c 'import json;e=json.load(open("agent.erebus.attest"))["statement"]["predicate"]["execution"];print(e.get("output_hash"), e.get("exit_code"))')"
if [[ "$cap" == "None None" ]]; then
  echo "  KNOWN GAP output_hash / exit_code not captured on macOS (Linux isolation ≥ 2 only)"
else
  ok "output_hash and exit_code captured: $cap"
fi

echo 'SECRET-CANARY' >"$W/canary.txt"
cat >"$W/canary.c" <<EOF
#include <stdio.h>
int main(void) { FILE *f = fopen("$W/canary.txt", "r"); puts(f ? "READ" : "BLOCKED"); return 0; }
EOF
cc -O2 -o canary-app/app "$W/canary.c"
ERE_STUB_PATH="$STUB" "$EREBUS" build canary-app -o canary.erebus --landlock >/dev/null 2>&1
chmod +x canary.erebus
if XDG_CACHE_HOME="$W/cache" ./canary.erebus 2>/dev/null | grep -q BLOCKED; then
  ok "sandbox: file outside the rootfs is blocked"
else
  echo "  KNOWN GAP sandbox: payload read a file outside its rootfs (Seatbelt not enforced)"
fi

echo "VERDICT: macOS slice OK ($PASS checks)"
