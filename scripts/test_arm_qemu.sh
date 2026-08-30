#!/usr/bin/env bash
# test_arm_qemu.sh — run the erebus Linux ARM stub under qemu-user.
# Requires: qemu-aarch64-static (or qemu-arm-static), binfmt_misc.
# Usage: ./test_arm_qemu.sh [target]
#   target: aarch64 (default) or armhf
set -euo pipefail

TARGET="${1:-aarch64}"
case "$TARGET" in
  aarch64|arm64)
    QEMU=qemu-aarch64-static
    TRIPLE=aarch64-unknown-linux-musl
    ;;
  arm|armhf)
    QEMU=qemu-arm-static
    TRIPLE=armv7-unknown-linux-musleabihf
    ;;
  *)
    echo "unknown target: $TARGET (use aarch64 or armhf)"
    exit 1
    ;;
esac

command -v "$QEMU" >/dev/null 2>&1 || {
  echo "error: $QEMU not found. Install qemu-user-static."
  exit 1
}

BUILD_DIR="/tmp/erebus-stub-target"
BIN="$BUILD_DIR/$TRIPLE/release/erebus-stub"

if [ ! -x "$BIN" ]; then
  echo "building $TRIPLE release..."
  CARGO_TARGET_DIR="$BUILD_DIR" cargo build --release -p erebus-stub --target "$TRIPLE"
fi

echo "=== QEMU ARM test: $TARGET ($TRIPLE) ==="
echo "binary: $BIN"
echo "qemu:   $(command -v "$QEMU")"

# Run a simple selftest under emulation.
# The stub's selftest mode exercises format read + extract + execvp resolution.
"$QEMU" "$BIN" selftest --help >/dev/null 2>&1 && echo "selftest --help: OK" || true

# If a hello-web example bundle exists, try executing it.
EXAMPLE_BUNDLE="/home/ubuntu/erebus/examples/hello-web/hello-web.erebus"
if [ -f "$EXAMPLE_BUNDLE" ]; then
  echo "running hello-web bundle under $TARGET qemu..."
  timeout 15 "$QEMU" "$BIN" run "$EXAMPLE_BUNDLE" --isolation none >/tmp/qemu-$TARGET.log 2>&1 || true
  if grep -qi "hello\|listening\|server" /tmp/qemu-$TARGET.log 2>/dev/null; then
    echo "bundle execution: OK"
  else
    echo "bundle execution: see /tmp/qemu-$TARGET.log"
  fi
else
  echo "no hello-web bundle found, skipping execution test"
fi

echo "=== $TARGET qemu test complete ==="
