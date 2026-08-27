#!/usr/bin/env bash
# scripts/bench_sisr_model.sh — Measure SISR delta savings through the REAL engine.
#
# Builds and runs `erebus-core/examples/sisr_bench.rs`, which drives
# `SisrEngine::apply_update_with_stats` on an actual v1→v2 update and reports
# the bytes the engine truly fetched (the delta that would cross the wire).
# This replaces the former heuristic (shell-math) estimate.
#
# Usage:
#   bash scripts/bench_sisr_model.sh [model_size_mb] [change_pct]
#
# Defaults: 100 MB payload, 1% change. Writes the measured report to
# benchmarks/sisr-model-<ts>.md and prints it to stdout.

set -euo pipefail

MODEL_SIZE_MB="${1:-100}"
CHANGE_PCT="${2:-1}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUT_FILE="$REPO_ROOT/benchmarks/sisr-model-${TIMESTAMP}.md"

echo "=== SISR Model Benchmark (real engine) ==="
echo "Model size:   ${MODEL_SIZE_MB} MB"
echo "Change:       ${CHANGE_PCT}%"

echo ""
echo "--- Building sisr_bench (erebus-core example) ---"
cargo build --release --example sisr_bench --manifest-path "$REPO_ROOT/erebus-core/Cargo.toml"

BENCH_BIN="$(find /tmp/erebus-stub-target/release/examples -name sisr_bench -type f 2>/dev/null | head -n1)"
if [[ -z "${BENCH_BIN:-}" ]]; then
  echo "error: sisr_bench binary not found under /tmp/erebus-stub-target" >&2
  exit 1
fi

echo ""
echo "--- Running the engine measurement ---"
# /dev/shm when available so large bundles don't fill a tight root FS.
if [[ -d /dev/shm ]]; then
  export TMPDIR=/dev/shm
fi
"$BENCH_BIN" "$MODEL_SIZE_MB" "$CHANGE_PCT" | tee "$OUT_FILE"

echo ""
echo "Report saved to: $OUT_FILE"
echo "Done."
