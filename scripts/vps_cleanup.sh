#!/usr/bin/env bash
# erebus VPS disk cleanup — safe, idempotent.
# Removes reconstructible build artifacts and stale caches.
set -euo pipefail

echo "=== erebus disk cleanup $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="

clean_dir() {
  local label="$1" dir="$2" max_age="${3:-7}"
  if [ -d "$dir" ]; then
    local before after
    before=$(du -sh "$dir" 2>/dev/null | cut -f1 || echo "0")
    find "$dir" -type f -mtime +$max_age -delete 2>/dev/null || true
    find "$dir" -type d -empty -delete 2>/dev/null || true
    after=$(du -sh "$dir" 2>/dev/null | cut -f1 || echo "0")
    echo "  $label: $before -> $after (pruned files older than ${max_age}d)"
  fi
}

echo "-- cargo target (stub, in /tmp) --"
clean_dir "erebus-stub-target" "/tmp/erebus-stub-target" 3

echo "-- cargo registry cache --"
clean_dir "cargo-registry" "$HOME/.cargo/registry/cache" 14

echo "-- erebus runtime cache --"
clean_dir "erebus-cache" "$HOME/.cache/erebus" 7

echo "-- opencode tmp sessions --"
clean_dir "opencode" "/tmp/opencode" 3

echo "-- apt cache (system) --"
if [ -d /var/cache/apt/archives ]; then
  before=$(du -sh /var/cache/apt/archives 2>/dev/null | cut -f1 || echo "0")
  apt-get clean 2>/dev/null || true
  after=$(du -sh /var/cache/apt/archives 2>/dev/null | cut -f1 || echo "0")
  echo "  apt-cache: $before -> $after"
fi

echo "=== disk after cleanup ==="
df -h / | tail -1
