#!/usr/bin/env bash
# ERE_EGRESS end to end on Linux: a real bundle, the real stub, two loopback
# listeners. With Landlock ABI >= 4 only the listed port is reachable and the
# receipt signs the policy; on older kernels the launch must be refused.
#
# Usage: scripts/egress_e2e.sh [path/to/erebus] [path/to/erebus-stub]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EREBUS="${1:-$ROOT/target/release/erebus}"
STUB="${2:-$ROOT/target/release/erebus-stub}"
W="$(mktemp -d)"
LISTENERS=""
trap '[[ -n $LISTENERS ]] && kill $LISTENERS 2>/dev/null; rm -rf "$W"' EXIT

die() { echo "  FAIL $*" >&2; exit 1; }
[[ "$(uname -s)" == Linux ]] || die "run this on Linux"

cat >"$W/abi.c" <<'EOF'
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
int main(void) { long v = syscall(444, NULL, 0, 1); printf("%ld\n", v < 0 ? 0 : v); return 0; }
EOF
cc -o "$W/abi" "$W/abi.c"
ABI="$("$W/abi")"

cat >"$W/listen.c" <<'EOF'
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
  for (int i = 0; i < 2; i++) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t n = sizeof a;
    bind(s, (struct sockaddr *)&a, n); listen(s, 16);
    getsockname(s, (struct sockaddr *)&a, &n);
    printf("%d ", ntohs(a.sin_port));
  }
  printf("\n"); fflush(stdout); sleep(300); return 0;
}
EOF
cc -o "$W/listen" "$W/listen.c"
"$W/listen" >"$W/ports" &
LISTENERS=$!
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
int main(void) {
  int u = socket(AF_INET, SOCK_DGRAM, 0);
  printf("A=%s B=%s UDP=%s\n", try_port(PA), try_port(PB), u < 0 ? "BLOCKED" : "OK");
  return 0;
}
EOF
mkdir -p "$W/net-app"
cc -static -O2 -DPA="$PA" -DPB="$PB" -o "$W/net-app/app" "$W/net.c"
cd "$W"
ERE_STUB_PATH="$STUB" "$EREBUS" build net-app -o net.erebus >/dev/null 2>&1 || die "build"
chmod +x net.erebus
"$EREBUS" keygen --key-dir keys >/dev/null 2>&1
KEY="$(ls keys/*.key)"

out="$(XDG_CACHE_HOME="$W/cache" ./net.erebus 2>/dev/null)" || die "control run failed"
[[ "$out" == "A=OK B=OK UDP=OK" ]] || die "control: unconfined agent: $out"
echo "  ok  control: unconfined agent reaches both listeners and opens UDP"

if [[ "$ABI" -lt 4 ]]; then
  if out="$(ERE_EGRESS="$PA" XDG_CACHE_HOME="$W/cache" ./net.erebus 2>&1)"; then
    die "Landlock ABI $ABI cannot confine egress but the agent ran: $out"
  fi
  grep -q "egress confinement unavailable, refusing to run" <<<"$out" || die "refusal: $out"
  echo "  ok  Landlock ABI $ABI < 4: launch refused instead of running unconfined"
  echo "VERDICT: egress e2e OK (refusal path, kernel $(uname -r))"
  exit 0
fi

out="$(ERE_EGRESS="$PA" XDG_CACHE_HOME="$W/cache" ./net.erebus 2>/dev/null)" || die "confined run failed"
[[ "$out" == "A=OK B=BLOCKED UDP=BLOCKED" ]] || die "egress: $out"
out="$(ERE_EGRESS="$PA" ERE_ATTEST_KEY="$KEY" XDG_CACHE_HOME="$W/cache" ./net.erebus 2>/dev/null)" || die "captured run failed"
[[ "$out" == "A=OK B=BLOCKED UDP=BLOCKED" ]] || die "egress lost under capture: $out"
grep -q "\"egress\":{\"scope\":\"any_address\",\"tcp_ports\":\[$PA\]}" \
  <<<"$(tr -d ' \n' <net.erebus.attest)" || die "policy not signed: $(cat net.erebus.attest)"
echo "  ok  Landlock ABI $ABI: only port $PA reachable, UDP refused, policy signed"
echo "VERDICT: egress e2e OK (enforced, kernel $(uname -r))"
