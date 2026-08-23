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

## Dependency audit

`cargo audit` → RC 0. Accepted warnings, documented:

- `paste` unmaintained (transitive)
- `lru 0.12.5` unsound advisories via ratatui — APIs (`LruCache::pop`,
  `IterMut`) never referenced by erebus code; blocked upstream on a ratatui
  release
