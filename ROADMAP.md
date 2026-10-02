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

The proof chain is built and re-proven on every push (`proof.yml`: demo,
cosign, chaos). P0, P1, and buyer items R1–R5 and R7 are landed; their
write-ups are in §10, not repeated below. What is left is §3: finish the
internal pilot on the calendar, and Windows confinement. The TPM2 seal
is in: two swtpm instances, a copied key does not unseal. The Windows
test is in the tree and on `windows-latest`; it has not run yet.
`COMPLIANCE.json` stays a pointer; filling an Annex IV file is the
compliance team's job.
Breadth stays frozen (§4). No production users.

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
| L1 — artifact integrity | this exact bundle/model ran, unmodified | ✅ SHA-256 + Ed25519 at cold start; warm cache re-hashed (`rootfs.merkle`) |
| L3 — non-repudiation / trace integrity | this key attested this run at this time; the trail cannot be silently edited | ✅ hash chain (P0-2), Merkle log + TSA (P0-5), machine co-signature (P0-6), DSSE (P0-7) |
| L2 — execution correctness | output = f(input, weights) | ❌ out of scope (TEE/zkML), stays a documented future option |

The pitch must say **"we prove the execution happened, unaltered, and the
trail is tamper-evident"** — never "we prove the agent did the right thing".

---

## 2. Closed

The 2026-09-17 audit (A1–A12) is closed. P0 made the proof true, P1 made
the claims run in CI, and R1–R5 plus R7 answered the first buyer questions.
Acceptance tests are in `cargo test --workspace` and `proof.yml`. Do not
reopen those items. The dilution finding (A13: breadth beside a small proof
core) stays as the freeze in §4.

---

## 3. What is left

Order is strict. An item is done only when its acceptance test runs in CI,
or, for T2–T4, when the artifact named below exists. Nothing else is in
scope.

### T2 — calendar, not code

Internal pilot started 2026-09-29: one real agent behind `serve --attest-key
--push`, 2 enrolled machines (Linux VPS, macOS laptop), registry with
`--tsa-url`. Earliest complete **2026-10-13**, and only when
`scripts/pilot` writes a `pilot-report.json` that shows anchored receipts,
0 `verify-attest --strict --proof` failures, and bytes of evidence per
call. Do not describe T2 as complete before that file says so.

### T3 / T4 — a name, not a feature

- **T3.** One design partner in the ICP (defense, public administration,
  industrial edge) and a letter of intent on the Enterprise tier. The
  offline verifier is already what `verify-evidence` does.
- **T4.** One written verification by an auditor or consultancy that does
  not trust us, using `erebus verify-attest` / `cosign` and public keys
  obtained out of band. After T2.

### Code

1. **TPM2.** Done 2026-10-02. `erebus enroll --tpm` seals `machine.key`
   with `tpm2_create` (`erebus-tpm2-seal/v1`). Unseal uses
   `TPM2TOOLS_TCTI`. A blob sealed on swtpm A unseals on A and fails on
   swtpm B (`scripts/test_tpm2_swtpm.sh`,
   `swtpm_copied_blob_cannot_unseal`). Software enrollments keep the v1
   certificate bytes (`erebus-machine-cert/v1\n…`, no `key_storage`
   field). An already-sealed XOR blob (`erebus-tpm-seal/v1`) still
   unseals with `ERE_TPM_BINDING`. Proven here in Docker against two
   swtpm instances. The same script is a CI job; that job has not gone
   green on GitHub yet.
2. **Policy in the stub.** Done 2026-10-02. `erebus build --policy FILE`
   embeds the YAML. The stub calls `enforce_embedded` before extraction
   and again after a SISR update, so `./agent.erebus` refuses on its own.
   Acceptance: `embedded_policy_refuses_before_exec` (no `erebus run`).
   The signer fingerprint match against the trusted directory stays in
   `erebus run --policy`; the stub refuses an unsigned bundle when the
   policy lists signers, and enforces isolation, model allowlist and
   `require_receipt`.
3. **Fleet proof status.** Done 2026-10-02. `GET /fleet?bundle=&since=&until=`
   returns each receipt with `proof_status` `verified`, `missing` or
   `failed`. Acceptance: `scripts/test_transparency_log.py` (auth required,
   one-second window, status `verified`). No region column. No HTML page.
4. **Windows confinement that holds.** Not observed yet. Non-detached
   children with a working directory start in an AppContainer that is
   granted write on that directory only, then in a job with
   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. A job object cannot refuse a
   write, so the write jail is the AppContainer. If `userenv` has no
   AppContainer exports (Wine), the launch continues with the job only.
   Acceptance: on `windows-latest`,
   `sandbox_kills_child_and_blocks_outside_write` — a child still running
   when the launcher drops it is killed, and a write outside the payload
   directory is refused. This host is macOS and cannot run that test.

### Out of scope

TEE remote attestation, zkML, multi-party consensus, Rekor (the erebus
transparency log is the anchor), a full offline Merkle log (R1 seals the
local trail head only), proving a tool's effect on the outside world,
hosting inference, healthcare, hobbyist devs.

---

## 4. Frozen

P0 is green. These surfaces still get **no new features**. They keep their
tests and stay marked `experimental` in `--help`:

`billing`, `mirror`, `replicate`, `hf`, `layer`, `swap`, `dashboard` (TUI),
`chat` (TUI + web UI), `sbom` beyond what `audit` needs, `scan --cve`,
`backup`/`restore`, webhooks, SSO/SAML, K8s Helm chart, the five protocol
frontends (`scripts/frontends/`), MCP registry endpoints (the attested tool
boundary already shipped with R2), waitlist/landing.

Rule: a PR touching a frozen surface must name an open item in §3 that it
unblocks.

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

`scripts/yc_demo.sh` runs this, plus enroll, `--strict`, cosign and the
chaos harnesses, on every push in `proof.yml`.

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

**Re-read 2026-10-01 — the RFS that is our slot: "The Future of American
Defense"** (Secretary of the Army). It asks for "commercially developed,
modular open-system solutions", "software … that plugs directly into our
open system architecture", surviving "the most extreme climates". That is
the ICP of §6 (defense, air-gapped, edge) in the buyer's own words: AI on
drones, sensors and vehicles that must later prove what it ran. What it
implies for us: the trail-head seal (R1, landed) and a TPM2 key
(§3, sealed with tpm2-tools; a copied blob does not unseal on a second
swtpm), plus arm64/Jetson as a first-class target. Caveat: US Army procurement in
practice needs a US entity (ITAR/CMMC); the European route (AID/DGA, NATO
DIANA, UK MOD) takes the same pitch.

Adjacent, cite only as such:
- *New Operating Systems for the Physical World* — "how do you measure
  reliability?" across agents, robots and humans; "record all the work as
  it actually happens". We are the evidence layer under those OSes (R2, R3).
- *Proving You're Human* — "rebuilding the trust layer". Same problem for
  machines: knowing what an agent did. Human approvals fit in our receipt
  (R4); we do not do human identity.

### 7.3 Traction — what we can produce ourselves, in order

The honest line today is *no production users*. Editing docs cannot change
that; the steps below can, and each yields a number we are allowed to cite.

| Step | Deliverable | Number we can cite | When |
|---|---|---|---|
| T1 | **P1-1**: `scripts/yc_demo.sh` + chaos batteries green in CI, public badge | "the whole proof chain is re-proven on every commit" | done 2026-09-28 |
| T2 | **Internal pilot**: one real agent behind `serve --attest-key`, ≥ 2 enrolled machines, ≥ 14 days, registry with `--tsa-url` | receipts anchored, machines enrolled, `verify-attest --strict --proof` failures = 0, bytes of evidence per call | after T1 |
| T3 | **Design partner** in the ICP (defense / administration air-gapped, industrial edge): offline verifier delivered, letter of intent on the Enterprise tier | "1 LOI; air-gapped verification accepted by their auditor" | in parallel |
| T4 | **Third-party verification**: an auditor or consultancy verifies a trail with nothing but `erebus verify-attest` / `cosign` and public keys, in writing | "verified by someone who does not trust us" | after T2 |

**T2 running (started 2026-09-29, not complete):**

- `erebus serve --push` now publishes every per-inference receipt and stores a
  locally verified Merkle inclusion proof; missing proofs are repaired from
  the append-only trail on restart.
- Reproducible harness: [`scripts/pilot/`](scripts/pilot/README.md), pinned
  Apache-2.0 Baguettotron Q8 (321 M), persistent registry with RFC 3161
  anchoring, node enrollment, daily probe and evidence-derived JSON report.
- Public registry since 2026-09-29 (TLS, only log/attestation/machine routes
  exposed), systemd node + daily probe on the registry host. Baseline:
  2 enrolled machines (Linux VPS, macOS laptop), each with a real inference
  receipt that is strict+proof verified and RFC 3161-anchored, 0 failures,
  ~14.2 kB of evidence per call. Machine gate lowered to 2 on 2026-10-01
  (the two hosts we operate; no third box available).
- Gate still open: 14 elapsed days (started 2026-09-29 → earliest calendar
  complete ≈ 2026-10-13; registry host leased for 15). Do not describe T2
  as complete before `pilot-report.json` says so.

Rules: cite only what CI or a third party proves; no star counts; the founder
story is told as *results* (proof chain complete, Python signer and Merkle
byte-compatible with Rust, cosign interop, SIGKILL chaos survived), never as a
module list.

### 7.4 The boundary, and the three questions (2026-09-28)

Full text: [`docs/src/concepts/proof.md`](docs/src/concepts/proof.md). The
short form every pitch must respect:

- **We prove** what ran, where, when, with what / producing what, and that
  the record was never edited (L1 + L3 in §1). A flight recorder for agents.
- **We do not prove** the computation was faithful (L2 — TEE/zkML, roadmap
  option only if a customer asks), that the agent did the right thing (that is
  evaluation), the plaintext (digests only), or a root-compromised host
  (default enrollment is still a software key; `--tpm` seals to the TPM
  named by `TPM2TOOLS_TCTI`, so a root on that same machine can still ask
  the TPM to unseal — §3). Never let a slide imply otherwise.
- **Why this boundary is the product**: Certificate Transparency, Sigstore, a
  flight recorder, an accounting audit trail — none prove correctness, all
  make the record undeniable, all changed their industry. Regulators ask for
  record-keeping and traceability (EU AI Act Art. 12/19/26, SOC 2, ISO 42001),
  not proofs of correctness.
- **"And if the agent lies?"** → *We do not judge the agent; we make it
  impossible to lie about what it did.*

The three questions that decide the outcome, and the answers we hold:

1. *Who needs this now?* Teams deploying agents on machines they don't fully
   control, answerable to someone who doesn't trust them. Must be a **name**
   (T2/T3), not a sector.
2. *Why now?* Agents act without a human in the loop; record-keeping
   obligations for high-risk AI are becoming enforceable. Editable logs were
   tolerated for chatbots, not for systems that act.
3. *Why not a feature of Datadog / LangSmith?* An operator-run tool cannot
   produce evidence the operator does not control. Traces answer "what
   happened?" to the operator; an anchored receipt answers it to the auditor.
   The neutral log is the product; the launcher is where the signature is
   unbypassable.

What will get us refused is not L2. It is "No production users yet" with no
pilot or LOI beside it (§7.3).

### 7.5 The YC field, Fall 2025 → Summer 2027 (read 2026-10-01)

879 companies read from the public YC directory. **None ships signed,
anchored, offline-verifiable per-execution receipts for agents.** The
closest, and what each teaches:

| Company (batch) | What they do | Relation | Lesson |
|---|---|---|---|
| Caution (S26) | verifiable compute on AWS Nitro enclaves; proves prod = reviewed source via reproducible builds | nearest neighbour: proves *what is deployed*, cloud + TEE | link bundle to source (R5); their TPM 2.0 plans meet R6; we own edge / offline / per-run, they own cloud enclaves |
| Klaimee (Sp26), Mount (Sp26) | liability insurance for deployed agents | **buyer / channel** | they need evidence to underwrite and pay claims; their failure list maps to R2, R3, R7 |
| Valgo (W26) | risk pricing for physical AI, "historical data doesn't exist" | buyer / channel | an anchored trail *is* that loss history |
| Multifactor (F25), Agentic Fabriq (W26) | agent identity, permissions, audit logs | complement | their audit logs are operator-controlled: we are the tamper-evident back end |
| Salus (W26) | blocks agent actions before they execute | complement | pre-execution checks = our P2 `policy`; their verdicts belong in receipts |
| GrayPass (F26) | signed proof a human approved a key action | complement | carry signed approvals in the statement (R4) |
| Sentrial (W26) | "Datadog for agent reliability" | the operator tool we contrast against | — |
| Seeing Systems (W26) | AI-commanded strike drones; UK Royal Marines + 4 NATO forces | **T3 target** (European, NATO) | defense buyers sit in the batch |
| Arden (Sp26), Denki (F25) | AI-native audit firms | **T4 target** | a third party that verifies a trail in writing |

Rules: name neighbours by what they prove, never "no one else does this";
the batch is a pipeline (insurers as channel, drone and industrial
companies as T3, audit firms as T4), not just a competitor list.

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
  `--isolation none`). Wine < 7 lacks WMI. macOS: Seatbelt confines the
  filesystem (`--landlock`) and outbound network (`ERE_EGRESS`), but there
  is no syscall filter like seccomp: macOS has no public API for one
  (Endpoint Security observes and authorizes events, it needs an Apple
  entitlement and root, and does not filter arbitrary syscalls), so the
  seccomp layer has no macOS equivalent. Linux egress needs 6.7+ (Landlock
  ABI 4) and refuses to launch below. `serve`: encrypted and squashfs
  bundles unsupported.

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

- **2026-10-02** — R1–R5 and R7 landed (witness seal, tool-call receipts,
  stop receipts, signed approvals, SLSA sidecar, incident-window claim).
  Policy is enforced by the stub. Fleet returns `proof_status`.
  `erebus enroll --tpm` seals with TPM2; two swtpm instances, the copy
  does not unseal. `COMPLIANCE.json` stays a pointer. Windows
  AppContainer plus kill-on-job-close is written; the runner test has
  not executed. Roadmap cut down to §3.
- **0.6.1 (2026-09-29)** — T2 pilot tooling (`serve --push`, `scripts/pilot/`);
  fixes: `--embed-model` payload staging, cold-start `unshare` EINVAL race,
  `erebus build` finds the stub shipped with a release install.
- **0.6.0 (2026-09-28)** — P0-1 `verify-attest` hardening (consistency
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
