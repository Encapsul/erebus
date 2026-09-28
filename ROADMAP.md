# ROADMAP.md — erebus: the proof layer for AI execution

> **Rewritten 2026-09-17** after a full code audit (38 k lines Rust, 9 k Python/shell).
> Source of truth for product state, what is *actually* proven by the code,
> what is left, and in which order. Business model and pitch are condensed
> in §6–§7; technical decisions are archived in §8.
>
> One-liner: *« AI agents run everywhere. Nobody can prove what they did.
> We generate the cryptographic proof. »*

---

## 0. Where we are, in one paragraph

The **mechanism** is solid: a self-extracting `[stub][payload][metadata][footer]`
binary, Ed25519 signature covering payload‖metadata‖footer, fail-closed launcher,
Linux sandbox (userns + pivot_root + hermetic PID/procfs + seccomp + Landlock),
SISR delta updates, 547 tests, zero `unsafe` outside the stub. The **proof
chain** — the thing we sell — is ~1 000 lines out of 47 000 and has audit-grade
gaps (§2). Since 2026-08 the team shipped *breadth* (37 subcommands, billing,
SSO, five protocol frontends, MCP, webhooks, replication, mirror, CVE scanner,
TUIs). From now on we ship **depth on the proof chain only** until §3 P0 is
green. Everything else is frozen (§4).

---

## 1. Vision

**Erebus = the proof layer for AI execution.**

Every AI agent runs on a machine. Nobody can prove what it did, when, where,
with which model, unmodified. erebus is the *only point of execution* the
operator controls — the launcher — and that launcher emits a signed,
hash-chained, externally-anchored receipt of every run. Regulated buyers
(EU AI Act high-risk lifecycle documentation, SOC 2, ISO 27001, public
procurement, defense/air-gapped) need this evidence and have no tool that
produces it.

**The moat is not packaging, not SISR, not the registry.** It is the
execution-attestation chain: `.erebus` (signed artifact) + `.attest` receipts
(signed, chained) + transparency log (Merkle, anchored) = offline-verifiable
evidence. The bigger the trail, the stronger the lock-in.

**Three proof levels, honestly stated:**

| Level | Claim | erebus status |
|---|---|---|
| L1 — artifact integrity | this exact bundle/model ran, unmodified | ✅ SHA-256 + Ed25519 at cold start; ⚠️ warm cache not re-attested (P0-4) |
| L3 — non-repudiation / trace integrity | this key attested this run at this time; the trail cannot be silently edited | ✅ hash chain (P0-2), Merkle log + TSA (P0-5), machine co-signature (P0-6), DSSE (P0-7) |
| L2 — execution correctness | output = f(input, weights) | ❌ out of scope (TEE/zkML), stays a documented future option |

The pitch must say **"we prove the execution happened, unaltered, and the
trail is tamper-evident"** — never "we prove the agent did the right thing".

---

## 2. Audit 2026-09-17 — what the code proves vs what we claimed

Findings against v0.5.0, each mapped to a P0 item. Status column is updated
as items land.

| # | Finding | Impact | Fix | Status |
|---|---|---|---|---|
| A1 | `verify-attest` checks the signature over `statement` but prints and trusts the **unsigned** duplicate top-level fields (`artifact`, `provenance`, `execution`). Editing `execution.output_hash` in the JSON still yields "OK". | An auditor can be shown forged values under a valid signature | P0-1 | ✅ 2026-09-17 |
| A2 | No `--bundle`: an attestation is never compared to a real file; `key_fingerprint` is never checked. | Attestation of bundle X accepted as evidence for bundle Y | P0-1 | ✅ 2026-09-17 |
| A3 | Every run **overwrites** `<bundle>.attest`. "Every execution leaves a receipt" is false locally. | Trail = last run only | P0-2 | ✅ 2026-09-17 |
| A4 | Receipts are independent documents: no `prev_hash`, no sequence, no local chain. | Deletion/reordering undetectable | P0-2 | ✅ 2026-09-17 |
| A5 | Registry `/attestations` = JSONL append with `flock`; `_attestation_exists` rescans the whole file per POST; no Merkle tree, no signed tree head, no inclusion proof, no external anchoring. | The "compliance trail" is editable by the registry admin without trace; O(n) per write | P0-5 | ✅ 2026-09-17 |
| A6 | Signing key = raw 32-byte file on the executor host (`ERE_ATTEST_KEY`). The party that runs the agent holds the key that attests. | It is a signed journal, not third-party proof — acceptable **only** with anchoring (A5) and a per-machine identity (A7) | P0-5, P0-6 | ✅ 2026-09-17 (anchored + machine co-signature) |
| A7 | `machine_id_hash = SHA-256(hostname‖os‖arch)`: tiny input space, brute-forceable, no enrolled machine identity. | "500 PoS terminals" cannot be told apart reliably | P0-6 | ✅ 2026-09-17 |
| A8 | Warm start (`main.rs:463-487`) trusts `~/.cache/erebus/<hash>/rootfs` on size+mtime of the bundle; rootfs content is never re-hashed. With `isolation < 2` the payload can rewrite its own rootfs. | Attestation says "bundle X intact" while modified code runs | P0-4 | ✅ 2026-09-17 |
| A9 | Behavior capture hashes **argv** (`input_hash`) and **stdout‖stderr** (`output_hash`). For an HTTP-serving agent this is the engine's log noise. `erebus serve` launches `llama-server` directly, bypassing the stub — the main LLM path produces **no** attestation. | Capture exists but not where agent behavior lives | P0-3 | ✅ 2026-09-17 |
| A10 | Signature = Ed25519 over `serde_json::to_vec_pretty(statement)`. No DSSE envelope, no JCS/RFC 8785 canonicalization, predicate URI resolves to nothing. "in-toto compatible" is aspirational: cosign/in-toto-verify/Rekor cannot consume it. | No ecosystem interop, fragile canonical form | P0-7 | ✅ 2026-09-17 |
| A11 | CI runs `cargo test` + one HTTP smoke test. **None** of the chaos harnesses, `yc_demo.sh`, or an attestation e2e run in CI; "SURVIVED" verdicts are manual VPS runs. | Claims are not continuously proven | P1-1 | ✅ 2026-09-28 (`proof.yml`: demo + 4 harnesses + log battery + chaos_extreme, on push and daily) |
| A12 | `docs/src` (mdbook) has zero pages on attestation; README pitches "package anything → OpenAI API" while this file pitches "proof layer". | Two products, two stories | P1-3 | ⬜ |
| A13 | 37 subcommands; `registry_server.py` = 3 004 lines in one file with Stripe, SAML, webhooks, replication, mirror, MCP, CVE, web UI. Proof code ≈ 2 % of the codebase. | Dilution; every new surface is attack surface and maintenance | §4 freeze | ⬜ |

---

## 3. The plan

Order is strict. A P0 item is "done" only when its acceptance test is
automated (unit or CLI integration test in `cargo test --workspace`, or a
CI job).

### 🔴 P0 — Make the proof true (target: 6 weeks)

- [x] **P0-1 `verify-attest` hardening** (A1, A2) — landed 2026-09-17.
  - Signature check, then **consistency check**: unsigned `artifact` /
    `provenance` / `execution` must equal the signed `statement` (subjects +
    predicate); any drift → `TAMPERED: <field> differs from signed statement`.
  - `--bundle <file>`: recompute SHA-256, compare to the signed bundle subject.
  - `signature.key_fingerprint` must equal `sha256(verifying_key)` of the
    key that verified.
  - Human output prints **only** signed values. Exit 2 on any tamper.
  - Acceptance: `erebus-cli/tests/attest_e2e.rs` — attest → verify OK →
    flip unsigned field → exit 2 → `--bundle other` → exit 2.

- [x] **P0-2 Append-only, hash-chained local trail** (A3, A4) — landed 2026-09-17.
  - Spec 1.2 (additive): `execution.prev_attestation_hash` in the **signed**
    predicate = SHA-256 of the previous receipt file bytes (`None` for the
    first).
  - Store `<bundle>.attest.d/<seq:06>-<utc-compact>-<id8>.json`, atomic
    write (tmp+rename), `HEAD` = hash of last receipt. `<bundle>.attest`
    keeps the latest receipt for backward compatibility with demos.
  - Stub: final receipt (post-run with capture, or pre-launch without) is
    appended to the log; the provisional "start" receipt is not.
    `ERE_ATTEST_LOG=<dir>` overrides the location, `ERE_ATTEST_LOG=none`
    disables the trail.
  - `erebus verify-attest --chain <dir>`: verify every receipt's signature +
    fingerprint + consistency, and that `prev_attestation_hash` links to the
    previous file byte-for-byte; report count and head.
  - Acceptance: unit tests in `erebus-core/src/attest_log.rs` + CLI test:
    two attests → chain OK → delete/edit middle file → exit 2.

- [x] **P0-3 Capture behavior where it lives: the API boundary** (A9) — landed 2026-09-17.
  - `erebus serve --attest-key <key> [--attest-log <dir>]` (env
    `ERE_ATTEST_KEY` / `ERE_ATTEST_LOG`) is an **attesting reverse proxy**
    (`erebus-cli/src/commands/attest_proxy.rs`): the engine binds a private
    loopback port, the proxy owns `--host:--port`. Per `POST`, it hashes
    `METHOD path\n` + body (`input_hash`) and the **decoded** response body
    (`output_hash`; Content-Length, chunked/SSE, read-to-EOF) while
    streaming it unchanged, then appends one signed receipt to the trail
    with `execution.request = {method, path, status}` inside the signed
    predicate. `GET`s (health, `/v1/models`) pass through unrecorded.
  - Same receipt schema and same default trail (`<bundle>.attest.d/`) as
    `erebus run`: a bundle's runs and its API calls form one chain. Bundle
    facts are hashed once (`AttestationTemplate`); per call = one Ed25519
    signature + one atomic file write.
  - CLI agents keep stdout‖stderr capture; `input_hash` there is the launch
    vector (argv), not stdin.
  - Acceptance ✅: `erebus-cli/tests/serve_attest_e2e.rs` embeds a python
    `http.server` as `bin/llama-server`, runs the real `erebus serve
    --attest-key`, 3 calls → 3 chained receipts → `verify-attest --chain
    --bundle` OK; rewritten `output_hash` → `TAMPERED`. Unit tests cover
    chunked decoding, 411/400/502 paths and GET exclusion.
  - Known limits (documented, not hidden): HTTP/1.1 only, one request per
    connection (`Connection: close` both ways); chunked *request* bodies →
    411; request body buffered up to 64 MiB; a call whose relay fails
    mid-stream is logged to stderr but **not** attested (the client did not
    receive a complete response).

- [x] **P0-4 Warm cache re-attested** (A8) — landed 2026-09-17.
  - Cold extraction writes `<cache_root>/rootfs.merkle` (sorted
    `path → sha256`, RFC 6962 root; `erebus_core::rootfs_merkle`) and strips
    write bits from every tracked file. Receipts carry
    `execution.rootfs_root` (signed).
  - Warm start re-hashes the rootfs in parallel against the manifest before
    exec; a modified/deleted tracked file (or a cache predating the
    manifest) drops `.ready` and re-extracts from the verified bundle.
    Files the app creates at runtime are tolerated (`ERE_ROOTFS_CHECK=strict`
    rejects them; `=off` skips the check). Directories stay writable and the
    `ro` remount is deferred: GC and re-extraction must be able to remove
    the tree.
  - Acceptance: `extraction::warm_start_refuses_modified_rootfs_and_reextraction_restores_root`
    (same-size byte flip → refused → re-extract → identical root) plus
    `rootfs_merkle` unit tests (modified/deleted/added/symlink retarget).

- [x] **P0-5 Tamper-evident registry trail** (A5, A6) — landed 2026-09-17.
  - JSONL replaced by **SQLite** (`attestations/log.sqlite`, WAL, stdlib
    only; old journal auto-imported once). Leaf = `SHA-256(0x00 ‖ exact
    bytes the client posted)`, so the client re-derives it from its receipt
    file.
  - **Merkle transparency log** (RFC 6962/9162, pinned to the RFC test
    vectors on both sides): `GET /log/checkpoint` (Ed25519 signed tree head,
    pure-Python signer, log key `<dir>/log.key` or `--log-key`),
    `GET /log/proof?leaf=[&size=]` (inclusion + consistency to head for
    historical sizes), `GET /log/consistency?from=&to=`, `GET /log/key`.
    `POST /attestations` answers with the position, the checkpoint and the
    anchor.
  - **External anchoring**: `--tsa-url` + `--anchor-every N` (or
    `POST /log/anchor`) timestamp the checkpoint at an **RFC 3161 TSA**
    (DER built by hand, validated against freetsa.org + `openssl ts`); the
    token is stored and served with proofs. Rekor upload: not done (P1).
  - CLI: `erebus attest --push` verifies the returned proof and stores it as
    `<receipt>.proof.json`; `erebus verify-attest --proof [--log-key HEX]`
    checks leaf, inclusion path, checkpoint signature, key trust and the TSA
    token structurally, **offline**. Full CMS validation of the token is
    `openssl ts -verify` with the TSA chain (documented in the output).
  - Acceptance: `scripts/test_transparency_log.py` (41 checks: RFC vectors,
    Ed25519 RFC 8032 vector, proofs over HTTP, idempotent re-post, fake
    TSA, **SIGKILL during concurrent publishes → restart → every
    acknowledged leaf proves into the new head**);
    `erebus-cli/tests/attest_proof_e2e.rs` runs the real
    `registry_server.py` (cross-language signature/proof check) then
    verifies offline and rejects three tampers.
  - Still open from A6: the executor holds the receipt key → P0-6.

- [x] **P0-6 Machine identity** (A7) — landed 2026-09-17.
  - `erebus enroll [--registry URL --token T] [--dir] [--show]`: per-machine
    Ed25519 seed (`~/.local/share/erebus/machine/machine.key`, 0600,
    `create_new` → never rotated implicitly, `$ERE_MACHINE_DIR` override).
    With `--registry`, `POST /machines/enroll` returns a certificate signed
    by the registry **log key** over
    `erebus-machine-cert/v1\n{machine_id}\n{pubkey}\n{owner}\n{registry}\n{issued_at}\n`;
    the CLI checks it names our key and verifies before saving. Idempotent
    (200 + same cert); another user claiming the key → 409; `GET /machines`
    lists the owner's hosts (SQLite `machines` table).
  - Every producer (`attest`, launcher stub, attesting proxy) loads the host
    identity (`attest::host_machine`) and **co-signs the DSSE envelope**
    with the machine key; `execution.machine_id` (key fingerprint) is inside
    the signed statement. `machine_id_hash` kept for compatibility. No
    identity → operator-only receipt, never a failure.
  - `verify-attest --strict [--registry-key HEX]`: 2.0 receipt, signed
    `machine_id` == machine block, co-signature by that key, certificate
    for that key from a trusted registry key. Operator check looks trusted
    keys up **by fingerprint**, so a trusted machine key cannot pass as the
    operator.
  - Acceptance: `machine::tests` + `attest::spec2_machine_cosignature_is_signed_and_strictly_verifiable`
    (impostor machine block, untrusted registry, un-enrolled receipt);
    `erebus-cli/tests/attest_strict_e2e.rs` enrolls against the real
    registry, verifies `--strict` offline, rejects a grafted machine block
    and a forged certificate; `scripts/test_transparency_log.py` (+8 checks:
    auth, cert bytes/signature, idempotence, 409, listing).
  - Not done: TPM2 quote (P1, optional), certificate revocation list (P1).

- [x] **P0-7 Standard envelope** (A10) — landed 2026-09-17.
  - **Spec 2.0** (`docs/src/spec/attestation.md`, JSON Schema for predicate
    `https://erebus.dev/attestation/execution/v2`): `envelope` = DSSE v1
    `{payloadType: application/vnd.in-toto+json, payload: base64(JCS(statement)),
    signatures: [{keyid: fingerprint, sig}]}` with PAE (`dsse.rs`, spec
    vector pinned); JCS RFC 8785 (`jcs.rs`, §3.2.3 sorting vector pinned,
    floats rejected). `signature` mirrors the operator entry for 1.x
    consumers and the mirror is checked.
  - `verify-attest` accepts 1.x (legacy pretty-JSON signature) and 2.0
    (payload must equal `JCS(statement)`, then display-copy consistency with
    the statement's own predicate type). Output shows
    `format: spec 2.0 (DSSE envelope)`.
  - Interop: `erebus keygen` also writes `<fp>.pem` (RFC 8410 SPKI, vector
    pinned); `erebus attest --envelope FILE` writes the bare envelope;
    **`cosign verify-blob-attestation --key <pem> --signature <envelope>
    --type …/v2 <bundle>` → `Verified OK`** (subject digest = bundle
    sha256) and rejects a flipped payload byte. Exercised in
    `attest_strict_e2e.rs`; CI installs cosign (`sigstore/cosign-installer`).
  - Not done: Rekor upload (P1) — receipts are anchored in the erebus
    transparency log instead.

### 🟠 P1 — Make the claims continuously proven (parallel with late P0)

- [x] **P1-1 CI runs the demo** (A11) — landed 2026-09-28 as
  `.github/workflows/proof.yml` ("Proof chain" badge in the README): on every
  push/PR to `main`, daily (`cron`) and on demand, a fresh Ubuntu runner builds
  the musl stub + CLI and runs, in order, `scripts/test_transparency_log.py`
  (49 checks), `scripts/yc_demo.sh` (11 steps: build → sign → enroll → execute
  with the sandbox **on** → DSSE receipt → tamper refusals → transparency log →
  offline `--strict --proof` → `cosign … Verified OK` → `chaos_monkey` /
  `chaos_business` / `chaos_registry_serve` / `chaos_frontends`) and
  `scripts/chaos_extreme.sh`. Harness logs are uploaded as an artifact on
  failure. Fixes surfaced by the first Linux run: `serve --llama-server` now
  bypasses engine resolution (it used to demand a `llama-server` on PATH even
  when overridden), the quota harness derives its quota from the real bundle
  size, and the demo's exit trap no longer turns a green run into exit 1.
  Any red = no merge.
- [ ] **P1-2 Evidence export**: `erebus evidence export <bundle> -o pack.zip`
  = bundle hashes, receipts, inclusion proofs, checkpoints, TSA tokens,
  trusted public keys. `erebus verify-evidence pack.zip` verifies **offline**.
  This is the artifact an auditor receives.
- [ ] **P1-3 One story** (A12): README leads with proof (build → sign → run →
  receipt → verify → tamper), packaging/serve become "how it runs"; mdbook
  gets `concepts/proof.md`, `spec/attestation.md`, `guides/audit.md`.
- [ ] **P1-4 Registry hygiene**: split `registry_server.py` into a package
  (`store/`, `auth/`, `log/`, `http/`), SQLite everywhere, remove the O(n)
  scans, keep zero third-party deps.
- [ ] **P1-5 macOS slice validated on real Apple Silicon** (never run to date).

### 🟡 P2 — Differentiators once the chain is trustworthy

- [ ] `erebus policy`: YAML rules enforced by the stub before exec
  ("only signed by key X", "model layer sha256 ∈ allowlist", "isolation ≥ 2",
  "receipt must be written or refuse to run" = fail-closed attestation).
- [ ] EU AI Act Annex IV / SOC 2 evidence pack generator from the trail.
- [ ] Fleet dashboard on the registry: "all executions of agent X, region Y,
  last week", with proof status per row.
- [ ] Windows: real sandbox (AppContainer / job objects) — today minimal.

### ⚪ Out of scope (documented, not planned)

TEE remote attestation (SGX/TDX/SEV-SNP/Nitro), zkML, multi-party
consensus, hosting inference, healthcare ICP, hobbyist devs.

---

## 4. Frozen until P0 is green

These exist and keep passing their tests, but receive **no new features** and
are marked `experimental` in `--help`. Candidates to move to an `erebus-extras`
crate / separate repo after P0:

`billing`, `mirror`, `replicate`, `hf`, `layer`, `swap`, `dashboard` (TUI),
`chat` (TUI + web UI), `sbom` beyond what `audit` needs, `scan --cve`,
`backup`/`restore`, webhooks, SSO/SAML, K8s Helm chart, the five protocol
frontends (`scripts/frontends/`), MCP registry endpoints, waitlist/landing.

Rule: a PR touching a frozen surface must reference a P0/P1 item it unblocks.

---

## 5. The YC demo (2 minutes, every step green in CI — `proof.yml`)

```bash
erebus keygen                                   # Ed25519 key, 0600
erebus trust <fingerprint>.pub
erebus build ./agent -o agent.erebus            # sandboxed single binary
erebus sign agent.erebus --key <fingerprint>.key
erebus verify agent.erebus                      # OK: signature verified
ERE_ATTEST_KEY=<key> ./agent.erebus < prompt    # runs; receipt appended to agent.erebus.attest.d/
ERE_ATTEST_KEY=<key> ./agent.erebus < prompt    # second run → chained receipt
erebus serve agent.erebus --attest-key <key> &  # attesting proxy on :8080 (engine hidden on loopback)
curl :8080/v1/chat/completions -d '{...}'       # answer unchanged; 3rd receipt = {POST /v1/chat/completions, 200, req/resp hashes}
erebus verify-attest --chain agent.erebus.attest.d --bundle agent.erebus   # 3 receipts, chain OK
sed -i 's/"exit_code": 0/"exit_code": 1/' agent.erebus.attest.d/000001-*.json
erebus verify-attest --chain agent.erebus.attest.d   # TAMPERED: exit_code differs from signed statement
printf '\x00' | dd of=agent.erebus bs=1 seek=3000000 count=1 conv=notrunc
erebus verify agent.erebus                      # TAMPERED: signature does not match
```

Extended (P0-5): `erebus attest --push` → `erebus verify-attest --proof` shows
the receipt is included in a checkpoint timestamped by an independent TSA.

**Current state (2026-09-28):** the full `scripts/yc_demo.sh` (11 steps, incl.
enroll, `--strict`, cosign and the four chaos harnesses) runs green on a fresh
Ubuntu runner in `proof.yml` — ≈ 6 min. Earlier state (2026-09-17): steps 1–10 work (P0-1, P0-2, P0-3 landed:
`serve --attest-key` makes every chat call a chained receipt). The `--proof`
step works (P0-5): run the registry with `--tsa-url https://freetsa.org/tsr`,
`erebus attest agent.erebus --push --registry $ERE_REGISTRY --token $T`, then
`erebus verify-attest agent.erebus.attest --proof --log-key $(curl -s
$ERE_REGISTRY/log/key | jq -r .public_key_hex)` — offline. Warm starts are
re-verified against `rootfs.merkle` (P0-4).

---

## 6. Business model (condensed, decided 2026-08-26, unchanged)

Client **and** server stay MIT forever; we monetize the **hosted trail**.

| Tier | Price | Includes |
|---|---|---|
| Free | €0 | public packages, 10 GB/month, local receipts |
| Pro | $29/mo | private packages, hosted transparency log, anchored checkpoints, 1 TB SISR |
| Team | $99/mo | Pro + RBAC, audit log, evidence packs, webhooks, 5 TB |
| Enterprise | $24k/yr | air-gapped mirror + offline verifier, SSO, SLA, compliance reports |
| Enterprise+ | $50/node/yr | per-machine identity (P0-6), fleet dashboard, full history |

ICP: defense/administration (air-gapped by regulation), industrial edge
(kiosks, factories, vehicles), AI startups under the EU AI Act. Excluded:
healthcare, hobbyists. Forbidden: hosting inference, paywalling the client,
marketplace rev-share now.

Math: >95 % gross margin (no GPU), 10 enterprise × $24k = $240k ARR seed
viable; lock-in = accumulated anchored history.

---

## 7. Positioning and traction plan

### 7.1 The one-line slide

> *« Teams that deploy AI agents on machines they don't fully control cannot
> prove to an auditor what those agents ran. erebus is the launcher that emits
> a signed, externally anchored receipt of every execution — verifiable
> offline with erebus or stock cosign. MIT client and server; paid hosted,
> anchored proof trail. »*

Problem, solution, for whom — one breath. Never lead with platforms, engines,
SISR or the registry.

### 7.2 Category — say it right

erebus is **execution provenance for AI agents**: the Sigstore / SLSA /
in-toto model (signed statement, DSSE, transparency log, `cosign` interop)
applied to *runs* instead of *builds*. That is the category a technical
partner recognises, and it is why `cosign verify-blob-attestation → Verified
OK` matters: we are not a proprietary format.

**Do not claim the YC RFS "AI-Native Compliance Infrastructure" (Fall 2026)
as our slot.** Verified 2026-09-28: that RFS describes *financial* compliance
operations — state-by-state licensing, regulatory-change monitoring,
transaction anomaly detection, reporting headcount — and the companies cited
in it (Duna, TovenAI, Hadrius) are AI agents that *do* compliance work. We are
the evidence layer such agents, and any other, would run on. The RFS is an
**adjacent buyer** (its "tamper-evident audit trails" line), not our category;
frame it that way or not at all. Same for *DevTools for AI agents*: adjacent.

### 7.3 Traction — what we can produce ourselves, in order

The honest line today is *no production users*. Editing docs cannot change
that; the steps below can, and each yields a number we are allowed to cite.

| Step | Deliverable | Number we can cite | When |
|---|---|---|---|
| T1 | **P1-1**: `scripts/yc_demo.sh` + chaos batteries green in CI, public badge | "the whole proof chain is re-proven on every commit; N consecutive green runs" | next |
| T2 | **Internal pilot**: one real agent behind `serve --attest-key`, ≥ 3 enrolled machines, ≥ 4 weeks, registry with `--tsa-url` | receipts anchored, machines enrolled, `verify-attest --strict --proof` failures = 0, bytes of evidence per call | after T1 |
| T3 | **Design partner** in the ICP (defense / administration air-gapped, industrial edge): offline verifier delivered, letter of intent on the Enterprise tier | "1 LOI; air-gapped verification accepted by their auditor" | in parallel |
| T4 | **Third-party verification**: an auditor or consultancy verifies a trail with nothing but `erebus verify-attest` / `cosign` and public keys, in writing | "verified by someone who does not trust us" | after T2 |

Rules: cite only what CI or a third party proves; no star counts; the founder
story is told as *results* (proof chain complete, Python signer and Merkle
byte-compatible with Rust, cosign interop, SIGKILL chaos survived), never as a
module list.

---

## 8. Archives — technical decisions (kept, still binding)

### Format / invariants
- Layout `[stub][payload][metadata][footer]`; v2 plain · v3 signed · v4
  encrypted · v5 squashfs; `FLAG_SISR`, `SISR_FOOTER_EXT_SIZE = 110`.
- Signature covers payload‖metadata‖**footer** (anti-downgrade). Do not touch
  `format.rs` without bumping the version.
- v1→v2 invariant: v1 binaries execute unchanged; `upgrade_binary` copies
  segments byte-for-byte.
- SISR disabled ⇒ byte-identical legacy binary (tested).

### SISR / update
- HTTPS (`ureq` + rustls); trust is in the Ed25519 signature, not transport.
- `--key` with `--enable-sisr` signs the manifest, not the binary; both at
  once unsupported in a single build.
- Rollback snapshot `.erebus.bak`, health gate fork+waitpid, quarantine at
  `attempts >= ERE_HEALTH_MAX_ATTEMPTS` (3).
- Chunks content-addressed (SHA-256 enforced).

### Attestation (spec 1.x)
- Signature over the in-toto `statement` only; top-level duplicates are
  display fields and **must** be consistency-checked (P0-1).
- Pre-launch receipt written pre-pivot (host paths valid); post-run receipt
  overwrites it with `input_hash`/`output_hash`/`exit_code` (capture is
  Linux pivot path only, opt-in via `ERE_ATTEST_KEY`).
- `input_hash` = NUL-joined launch vector, **not** stdin.
- Ed25519 verification happens at cold start only; warm cache is keyed by
  footer hash + source size/mtime **and** re-hashed against
  `<cache_root>/rootfs.merkle` (P0-4). Receipts carry
  `execution.rootfs_root`.
- Registry log: `attestations/log.sqlite`; checkpoint bytes
  `erebus-log-checkpoint/v1\n{origin}\n{size}\n{root_hex}\n{ts}\n`; TSA
  imprint = SHA-256 of the same without the `ts` line. Proof file spec
  `erebus-log-proof/v1` (`erebus_core::log_proof`).

### Security / conventions
- Zero `unsafe` in core/CLI; stub only with `SAFETY` comments. No
  `panic!`/`unwrap` without context in library code; checked arithmetic;
  keys zeroized on drop; never print private keys.
- `--encrypt` is obfuscation only (key in metadata by design).
- Stable toolchain only; musl for the stub; clippy `-D warnings` per crate.

### Known constraints
- VPS disk chronically tight; purge `target/`, `~/.cache/erebus` before
  heavy builds. qemu-user: `unshare` → EINVAL (test ARM with
  `--isolation none`). Wine < 7 lacks WMI. macOS slice never run on
  hardware. `serve`: encrypted and squashfs bundles unsupported.

### Measured
- FastCDC ~390 MB/s, SHA-256 ~50 MB/s (i5-7300U). 100 MB payload, 1 %
  change → 1.28 MB delta (98.7 %). TinyLlama Q4_K_M CPU cold start < 45 s.
  Reproducible numbers: [`benchmarks/`](benchmarks/README.md).

---

## 9. Security posture & contributing (pointers)

- Vulnerabilities: confidential advisory on GitHub, 48 h response.
  Threat model: [`docs/src/security.md`](docs/src/security.md).
- Verification loop before any merge: `cargo fmt --check` → `cargo clippy
  -p <crate> --all-targets -- -D warnings` (×3) → `cargo test --workspace`.
- Branches `feat/*`, `fix/*`; conventional, signed commits; PRs target `dev`.
- Style: [`CODE_STYLE.md`](CODE_STYLE.md), ANSSI rules: [`RULES.md`](RULES.md),
  agent instructions: [`AGENTS.md`](AGENTS.md).

## 10. Changelog (condensed)

- **0.6.0-dev (2026-09-17)** — P0-1 `verify-attest` hardening (consistency
  check, `--bundle`, fingerprint); P0-2 hash-chained append-only local trail
  (`<bundle>.attest.d/`, `prev_attestation_hash`, `--chain`); P0-3 attesting
  reverse proxy in `erebus serve --attest-key` (one signed receipt per
  inference call, `execution.request`); P0-4 warm-cache re-verification
  (`rootfs.merkle`, `execution.rootfs_root`); P0-5 SQLite Merkle
  transparency log with signed checkpoints, RFC 3161 anchoring,
  `attest --push` proofs and offline `verify-attest --proof`; P0-6 machine
  identity (`erebus enroll`, registry certificates, machine co-signature,
  `verify-attest --strict`); P0-7 spec 2.0 DSSE/JCS envelope, `--envelope`,
  PEM export, cosign interop in CI; roadmap reset.
- **0.5.0** — SISR engine, universal 4-slice binaries, Windows PE stub,
  `serve`/`chat`, registry auth/quotas/attestations, behavior capture
  (spec 1.1), Landlock, hermetic `/proc`.
- **0.4.0** — hardened launcher, isolation fails closed, key zeroization.
- **0.3.0** — 100 % Rust CLI.
