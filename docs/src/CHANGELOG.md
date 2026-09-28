# Changelog

All notable changes to erebus are documented here.

## [Unreleased] — 0.6.0-dev — the proof chain

### Added

- **Execution receipts spec 2.0** — DSSE envelope over the JCS (RFC 8785)
  canonical in-toto statement, predicate
  `https://erebus.dev/attestation/execution/v2`; `signature` mirrors the
  operator entry so 1.x consumers keep working. `verify-attest` accepts 1.x
  and 2.0. Spec: [`spec/attestation.md`](./spec/attestation.md).
- **Machine identity** — `erebus enroll [--registry]`: per-host Ed25519 key
  (0600), certificate signed by the registry key (`POST /machines/enroll`,
  `GET /machines`); every receipt produced on the host is co-signed;
  `verify-attest --strict [--registry-key]`.
- **Sigstore interop** — `erebus keygen` writes `<fp>.pem`,
  `erebus attest --envelope FILE` writes the bare envelope;
  `cosign verify-blob-attestation` verifies it (exercised in CI).
- **Transparency log** — registry `attestations/log.sqlite` Merkle tree
  (RFC 6962/9162) with signed checkpoints, `GET /log/{checkpoint,proof,
  consistency,key}`, RFC 3161 anchoring (`--tsa-url`, `--anchor-every`);
  `erebus attest --push` stores `<receipt>.proof.json`;
  `verify-attest --proof [--log-key]` verifies it offline.
- **Warm-cache re-verification** — `rootfs.merkle` manifest written at
  extraction; every warm start re-hashes the rootfs and re-extracts on drift;
  `execution.rootfs_root` is signed into receipts (`ERE_ROOTFS_CHECK=off|strict`).
- **Attesting reverse proxy** — `erebus serve --attest-key`: one hash-chained
  receipt per inference call (`execution.request`).
- **Hash-chained local trail** — `<bundle>.attest.d/`,
  `execution.prev_attestation_hash`, `verify-attest --chain`.
- `verify-attest` hardening: display-copy consistency check, `--bundle`
  binding, fingerprint check.
- **Proof chain in CI** — `.github/workflows/proof.yml` (README badge) runs
  `scripts/test_transparency_log.py`, the full `scripts/yc_demo.sh` (sandbox
  on, enroll, `--strict`, cosign, four chaos harnesses) and
  `scripts/chaos_extreme.sh` on every push and daily.

### Fixed

- `erebus serve --llama-server PATH` no longer requires a `llama-server` on
  PATH or a runtime pack: the given binary is used as the engine directly.

### Changed

- The in-toto statement now serializes `predicateType` (standard); the 1.x
  spelling `predicate_type` is still accepted and its signature bytes are
  reproduced for legacy verification.
- Registry attestations moved from JSONL to SQLite (old journal imported once).

## [1.0.0] — 2026-08-03 — SISR

First major release integrating SISR (Self-Incremental Sovereign
Reconstruction) end to end.

### Added

- **SISR delta self-updates** — binaries embed a content-addressed chunk
  manifest; `./app --erebus-update <url>` fetches only the changed chunks from
  the update channel and rebuilds the binary in place.
- **`erebus upgrade-binary`** — promote a legacy (v1, SISR-less) `.erebus` to the
  v2 format by injecting the delta manifest and `SISR` header, preserving
  every payload byte and the integrity hash.
- **Post-update health gate + automatic rollback** — a newly updated binary
  runs under supervision; a failed health check restores the previous version
  from a snapshot, and quarantined targets are refused.
- **Migration guide** — see [`migration/v1-to-v2.md`](./migration/v1-to-v2.md).

### Compatibility

- v1 (SISR-less) binaries run on the v2 runtime **unchanged and without
  warnings**: standard extraction only, zero startup penalty.
- Deployment scripts based on v1 remain 100 % valid.
- The `.erebus` footer format is frozen; new capabilities ship as flags and
  backwards-readable format-version bumps.

### Testing

- End-to-end suite against a mock HTTP update channel (`cargo test -p
  erebus-stub --test e2e_sisr_main`), network fault injection on the
  reconstruction engine, and property-based parser fuzzing via proptest.
- Cross-version tests prove legacy binaries load on the v2 runtime and that
  upgraded binaries gain auto-update.

## [0.3.0] — 2026-07-XX — Pre-SISR

Last release before the SISR integration. Classic `[stub][payload][metadata]
[footer]` binaries only; no delta updates.
