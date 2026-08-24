# Security validation — zeroization audit, crypto chaos, process chaos

## Zeroization audit (ANSSI pass)

Findings fixed in `fix(security)` + `fix(anssi)` commits:

| Finding | Fix |
|---|---|
| Private keys written default-mode then chmod 600 (TOCTOU window) | `OpenOptions::mode(0o600).create_new(true)` at creation; symlink-following refused |
| Same pattern in the `erebus-crypto` helper binary | same fix |
| `manifest.encoded_len()` / `DirectoryChunkFetcher::new` could `expect()`/panic on adversarial or failing I/O | converted to `io::Result`; stub SISR update path propagates |
| Hex form of master key flows through serde clones | documented threat model (`--encrypt` = tamper-evidence/obfuscation); raw key stays in `Zeroizing` |

Verified state: **zero** `unwrap/expect/panic!` outside `#[cfg(test)]` across
`erebus-core` + `erebus-cli` (one documented-infallible static-regex
`.expect("valid regex")`). Ed25519 seeds: `Zeroizing` chain +
`ed25519-dalek` `zeroize` feature (internal drop-wipe).

## Crypto chaos properties (`erebus-core/tests/chaos_crypto.rs`)

7 proptest suites × 64 cases + contract test — all green:

| Property | Guarantee |
|---|---|
| roundtrip_random | decrypt(encrypt(m)) == m for random keys/messages ≤4 KiB |
| single_bit_flip_fails_closed | any single-bit flip anywhere → `Err` (GCM auth) |
| truncation_fails_closed | any prefix cut → `Err` |
| wrong_key_never_decrypts | distinct key → `Err` |
| chunked_* variants | same three guarantees for SISR chunked mode |
| zeroize_scrubs_every_byte | `.zeroize()` contract on sizes 1/31/32/64/1024 |

Regression corpus committed: `chaos_crypto.proptest-regressions`.

## Process chaos monkey (`scripts/chaos_monkey.sh`)

```bash
scripts/chaos_monkey.sh 30
```

Latest verdict on an AES-256-GCM bundle:

```
✓ corrupted files always fail closed     (30 flips/truncations/zero-regions)
✓ no encryption-key leakage in stderr    (key-hex scan across all runs)
✓ cache self-heals after SIGKILL         (10 kills, 5 ms → 900 ms after start)
✓ untampered bundle still works
✓ no panic noise on clean stderr
CHAOS VERDICT: SURVIVED
```

Corruption modes: random bit-flips (1-8 bytes), truncation to arbitrary
prefix, zeroed regions up to 4 KiB at random offsets ≥25% into the file.
Every corrupted copy must exit non-zero and must never print the embedded
encryption key.

## Registry / pull / serve chaos (`scripts/chaos_registry_serve.sh`)

Second harness covering the #5/#6 features; 22 checks, latest verdict:

```
── registry hardening
✓ GET traversal rejected            ✓ non-multipart POST rejected
✓ upload filename sanitized
── publish → index → pull
✓ index reflects upload instantly   ✓ unknown package fails clean
✓ pull roundtrip byte-identical     ✓ cache short-circuit on re-pull
✓ pull name traversal rejected      ✓ dead registry fails clean
── lying static index
✓ size mismatch → rejected, no artifact left
✓ sha mismatch  → rejected, no artifact left
── serve chaos
✓ corrupted bundle refused by SHA-256
✓ model-less bundle errors cleanly  ✓ missing engine errors with hint
✓ engine death during health-wait aborts non-zero
── resilience
✓ SIGKILL mid-extraction → next run self-heals (no poisoned .ready)
CHAOS REGISTRY/SERVE VERDICT: SURVIVED
```

Bugs this battery caught in the harness itself (not the product):
`timeout VAR=x cmd` without `env` silently never runs the command, and a
self-heal probe needs a bundle that actually contains a model.

## Dependency audit

`cargo audit` → RC 0. Accepted warnings, documented:

- `paste` unmaintained (transitive)
- `lru 0.12.5` unsound advisories via ratatui — APIs (`LruCache::pop`,
  `IterMut`) never referenced by erebus code; blocked upstream on a ratatui
  release

## Registry / accounts / quotas chaos (`scripts/chaos_business.sh`)

Third harness covering registry v2 (accounts, private packages, quotas,
SISR stats, waitlist). 23 checks:

```
✓ accounts: register/login/duplicates/weak secrets/bad usernames/timing
✓ privacy: anon → 401 · bearer bare & user:token OK · corrupted token → 401
✓ quotas: monthly metering, third pull over line → 402 Payment Required
✓ stats: served/full-equivalent/saved move correctly; range (delta)
  fetch credits savings; landing exposes live counters
✓ races: concurrent same-name uploads leave exactly one atomic winner;
  registration race yields exactly one account; replace-during-read
  never serves truncated blobs
✓ fuzzer: 150 seeded structure-aware requests — server alive, health
  intact, no temp litter, no tracebacks leaked
CHAOS BUSINESS VERDICT: SURVIVED
```

Bugs this battery caught in the product before they shipped:
- users.json load/save shape asymmetry let duplicate registrations
  overwrite existing accounts
- streamed multipart uploads hung forever waiting for EOF on keep-alive
  connections (now bounded by Content-Length) and could leak unread body
  bytes into pipelined request parsing (connection now closed after
  upload responses)
- listen backlog 5 caused connection resets under fleet-style bursts
  (raised to 128)
- rate-limit stamps keyed by IP were self-overwriting (per-attempt keys)
