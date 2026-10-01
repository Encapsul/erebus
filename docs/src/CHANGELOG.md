# Changelog

All notable changes to erebus are documented here.

## [Unreleased]

### Added (registry)

- `scripts/erebus_registry/`: the registry's proof core (Ed25519, Merkle,
  RFC 3161, transparency log) as a stdlib-only package; byte formats
  unchanged and pinned against the reference implementations in the battery.
- Merkle roots and inclusion/consistency proofs are O(log n) over a cached
  append-only tree instead of O(n) list scans (200k leaves: ~0.3 ms vs
  ~0.5 s per query); leaf lookup is a hash map.

### Added

- Spec 2.1 action receipts: `erebus serve --attest-key` signs every tool
  call the engine returns (name and call id in clear, `sha256` of the
  arguments) into `execution.request.tool_calls`, for chat completions
  (JSON, SSE deltas, legacy `function_call`) and the Responses API. A
  response that cannot be fully parsed is flagged `tool_calls_incomplete`
  instead of being reported as "no calls". Receipts without tool calls stay
  byte-identical to 2.0.
- `erebus verify-attest <receipt> --response-body FILE`: an auditor holding
  the plaintext response checks it against the signed `output_hash` and
  re-derives the signed tool-call list (exit 2 on any mismatch). Human
  output lists the signed tool calls.
- Spec 2.1 tool linkage: the proxy also signs the request's tool context
  (`tools_offered`, replayed `tool_history`, `tool_results` as call id +
  content digest). `verify-attest --chain` links every result to the call
  that requested it and reports injected results, rewritten history,
  changed results and calls to unoffered tools; `--require-tool-linkage`
  makes them fatal (exit 2). `verify-attest <receipt> --request-body FILE`
  re-derives the request side from the request body.
- `erebus evidence export <bundle> -o pack.zip` and `erebus verify-evidence
  pack.zip [--bundle] [--json]`: a self-contained, offline-verifiable audit
  pack (receipts, inclusion proofs, checkpoints, RFC 3161 tokens, DSSE
  envelopes, signing keys). Export refuses an unverifiable trail; verify
  refuses any edited, missing, extra or path-traversing entry and a
  mismatched bundle (exit 2).
- `verify-evidence --operator-key <key> --log-key <hex>` pins the
  keys an auditor obtained out of band; any other key in the pack is
  refused, and the report lists every key as pinned or `NOT PINNED`.
- Evidence packs carry `anchors/<receipt>.checkpoint`, the exact bytes the
  RFC 3161 token covers, so `openssl ts -verify -data` checks the TSA
  signature without erebus.
- Docs: `guides/audit.md` (auditor walkthrough); proof-first introduction,
  problem, positioning and comparison pages, in English; CLI help leads
  with the proof commands.

### Fixed

- Health-check server (stub): on macOS/BSD an accepted socket inherits
  `O_NONBLOCK` from the listener, so a probe that had not yet written its
  request got a reset instead of `200`. Accepted sockets are now blocking
  with a 2 s read timeout.
- SISR e2e mock server: same inheritance made `e2e_sisr_main` and
  `upgrade_migration` fail randomly on macOS ("Peer disconnected").
- `erebus build` detects Mach-O (thin and universal) agents as the binary
  runtime; it only knew ELF and PE, so native macOS apps were refused. Java
  class files, which share the fat magic, are not mistaken for them.
- `erebus build` no longer stages a Linux glibc base (and warns about it)
  for non-ELF payloads.
- `verify-evidence --operator-key` accepts the public key hex that
  `erebus keygen` prints, as well as the `sha256:` fingerprint.
- `attest --push` also stores the inclusion proof beside the trail entry,
  so trails built with `attest` carry their proofs like `serve --push` ones.
- Spec and docs: a batch run's `input_hash` covers the launch vector
  (entrypoint + arguments), not stdin, and `output_hash` needs Linux
  isolation ≥ 2; the spec claimed stdin. Quickstart trusted-keys path fixed.

### Known gaps (macOS, ROADMAP P1-5)

- The Seatbelt sandbox is not enforced; receipts carry no output digest
  or exit code. `scripts/macos_slice.sh` reports both as KNOWN GAP; CI
  runs it on Apple Silicon.

## [0.6.1] — 2026-09-29 — internal pilot

### Added

- `erebus serve --push --registry …`: each inference receipt is published to
  the transparency log and its verified inclusion proof is stored beside the
  local trail entry; missing proofs are retried at the next start.
- Reproducible T2 harness under `scripts/pilot/`: pinned Baguettotron Q8,
  persistent RFC 3161-anchored registry, enrollment, real probe and
  evidence-derived report.

### Fixed

- `build --embed-model` now stages the model before payload compression.
  Previously metadata advertised the ModelLayer, but the assembled payload
  did not contain the model bytes.
- Attestation-trail enumeration ignores `.proof.json` sidecars, so publishing
  per-call proofs cannot corrupt sequence numbering or chain verification.
- Stub: a fresh bundle could fail its very first launch with `Invalid
  argument (os error 22)`. The cold-start rootfs hashing joins one worker per
  core, and the kernel wakes the joiner before the thread leaves the thread
  group, so the `unshare(CLONE_NEWUSER)` that follows was refused with
  EINVAL. `enter_userns` now waits for `/proc/self/task` to drain and retries
  the unshare; `scripts/chaos_extreme.sh` gained a 40-launch cold-start storm
  that reproduces the window under load.
- `erebus build` right after a release install: the CLI now finds the
  `erebus-stub` shipped next to the `erebus` binary (host-target builds).
  It used to search only source-tree build dirs and `PATH`, and failed with
  "erebus-stub not found".

## [0.6.0] — 2026-09-28 — the proof chain

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
