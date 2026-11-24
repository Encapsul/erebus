# ROADMAP.md — erebus: the trust center for AI agents

> Rewritten 2026-11-24 after a product review. This file is the source of truth
> for product state, the buyer, the 90-day plan, frozen surfaces and the
> technical invariants that must not move.
>
> One-liner: *« AI agents act in environments their vendor does not control.
> erebus gives every run a signed, offline-verifiable receipt, and gives the
> buyer a trust center to verify it. »*

---

## 0. Where we are, in one paragraph

The proof chain is built and re-proven on every push: signed bundles,
DSSE/in-toto receipts, hash-chained trails, machine co-signatures, a Merkle
transparency log with RFC 3161 anchoring, offline evidence packs and `cosign`
interop. The internal pilot is running. There are still **no production
customers**, and the product surface is too broad: packaging, model serving,
registry, chat, TUI, universal binaries and a long CLI all compete for
attention.

The reset is deliberate: **stop widening the runtime, start shipping the trust
center.** The next 90 days are about one buyer, one workflow and one proof of
demand — not another feature. The technical moat stays the proof chain. The
product becomes the place where an AI vendor publishes evidence and a regulated
buyer verifies it.

---

## 1. Vision

**Erebus is the trust center for AI agents.**

An AI vendor sells an agent into a regulated environment. The buyer asks:
*which exact code and model ran, on which machine, when, with what input and
output, and can I verify that without trusting the vendor's logs?* Today the
answer is a screenshot, a log export or a tracing account the vendor controls.
erebus answers with a signed receipt and a verification path that works
offline.

### 1.1 Three product layers

| Layer | Surface | Job | State |
|---|---|---|---|
| **Capture** | launcher, attested proxy, SDK | bind the receipt to the bytes and the machine that actually ran | launcher + proxy + Python and Node SDKs + LangChain.js root chains ship |
| **Prove** | receipts, transparency log, evidence pack | make the record independently verifiable | proof chain exists; self-hosted trust center anchors receipts in it |
| **Consume** | trust center, verification links, control mapping | let a buyer or auditor accept the evidence without a CLI | self-hosted MVP ships; hosted SaaS and control mapping not shipped |

The launcher is the high-assurance capture path. The proxy and SDK exist so a
team can adopt receipts without repackaging its agent. The trust center is the
product surface: search, verify, share, export, map to controls.

### 1.2 Buyer and wedge

**ICP:** AI vendors selling agents into regulated enterprises — defense,
public administration, critical infrastructure, financial services and
industrial edge.

- **Buyer:** CISO, Head of Compliance or CTO at the AI vendor.
- **Economic buyer:** the regulated customer or auditor who requires evidence.
- **User:** the platform/security engineer who instruments the agent.
- **Channel:** auditors, insurers, system integrators and procurement teams.

The first wedge is not "all AI agents". It is **one AI vendor, one regulated
buyer, one evidence pack that the buyer's auditor accepts**. Expand only after
that works.

Deployment lead: **on-prem / air-gapped edge**. Defense, public administration,
critical infrastructure and industrial buyers often forbid a call-home, so the
acceptance path must run inside their perimeter: self-hosted registry, evidence
zip, keys pinned out of band, `verify-evidence` / `cosign` and the `auditor/`
kit (no account, no network, no hosted service). This is a buyer/deployment
wedge, not a crypto claim — the signed-receipt category is crowded. Hosted
trust center remains unshipped.

### 1.3 Proof levels — keep the boundary honest

| Level | Claim | Status |
|---|---|---|
| **L1 — artifact integrity** | this exact bundle/model ran, unmodified | ✅ SHA-256 + Ed25519 at cold start; warm-cache rootfs re-hash |
| **L3 — non-repudiation / trail integrity** | this key attested this run at this time; the trail cannot be silently edited | ✅ hash chain, Merkle log + TSA, machine co-signature, DSSE |
| **L2 — execution correctness** | output = f(input, weights) | ❌ out of scope (TEE/zkML only if a customer asks) |

Never claim L2. The pitch is: **we prove the execution happened, unaltered,
and the record is tamper-evident.** We do not prove the agent did the right
thing.

### 1.4 Moat

The moat is not packaging, SISR or model serving. It is:

1. the **execution-attestation chain** (signed artifact + receipts + anchored
   log);
2. the **accumulated anchored history** a fork cannot recreate;
3. the **standard and auditor network** (DSSE, in-toto, `cosign`, offline
   verification);
4. the **capture point** the operator cannot silently bypass.

The bigger the trail, the stronger the lock-in.

---

## 2. Closed

The 2026-09-17 audit (A1–A12) is closed. P0 made the proof true, P1 made the
claims run in CI, and R1–R5 plus R7 answered the first buyer questions.
Acceptance tests are in `cargo test --workspace` and `proof.yml`. Do not
reopen those items. The dilution finding (A13: breadth beside a small proof
core) is enforced by the freeze in §4.

---

## 3. What is left

Order is strict. An item is done only when the acceptance test runs in CI, or
when the named artifact exists. Nothing else is in scope.

### 3.1 The 90-day plan

| Weeks | Focus | Deliverable | Done when |
|---|---|---|---|
| 1–2 | Customer discovery | one ICP, 5–10 buyer interviews, a written evidence checklist | the checklist names the exact artifacts an auditor accepts |
| 3–4 | Activation | install → `erebus init` → `erebus demo` → first receipt → verification link | fresh Linux VM, under 5 minutes, no cargo/Rust |
| 5–6 | Trust center MVP | org/project, API key, receipt search, public verification link, evidence export | a non-erebus user opens the link and verifies offline |
| 7–8 | Design partner pilot | one real agent, 14 days, strict + proof verification | zero failures, one case study with numbers |
| 9–12 | Traction | 3 design partners, 1 paid pilot or LOI, one external auditor verification | YC application can cite names and numbers |

### 3.2 Code workstreams

#### P0-1 — Activation: first receipt in under 5 minutes

Today the quickstart starts with `make stub`, Rust and musl. That is a
developer path, not a product path.

- `erebus demo`: create a temporary Python agent, build it, run it, emit a
  receipt, verify it, print a shareable verification path.
- `erebus init`: keep the scaffold, but make the first run one command.
- Release install is the default path; source build is for contributors.
- Acceptance: fresh Linux VM → install → `erebus demo` → `OK` in < 5 min,
  covered by an integration test that does not require a prebuilt repo.

#### P0-2 — Trust center MVP

The hosted product is the paid surface and is still not shipped. The shipped
MVP is self-hosted: it runs on the stdlib registry and reuses its users, orgs,
tokens, Merkle log, signed checkpoints, inclusion proofs, audit trail and admin
backup/restore.

- org/project, API key, pinned log origin;
- spec 2.x DSSE/JCS receipt ingestion with pinned-key signature, project chain
  and Merkle inclusion checks; search and status (`verified`, `missing`,
  `failed`);
- capability verification link for a receipt (HTML or JSON) and a one-receipt
  evidence pack, no erebus account required;
- project evidence zip with receipts, inclusion proofs, signed checkpoints and
  a manifest carrying the pinned keys;
- status page and audit events; backup/restore includes trust-center state and
  exact receipt bytes.
- `verified` means the receipt's signature, chain link and log inclusion
  re-check from stored bytes. It does not claim every execution was captured.
  Retention policy and control mapping are not implemented.
- Automated acceptance is green: 1,000 receipts, no-account verification,
  export, tamper rejection and restore (`scripts/test_trust_center.py`).
  Design-partner proof remains a P0-5 deliverable, not a shipped claim.

#### P0-3 — Integration without repackaging

The launcher is the high-assurance path, not the only path.

- attested proxy in front of OpenAI-compatible and Anthropic APIs;
- Python and Node SDKs for custom agents;
- MCP tool-call receipts;
- one framework integration (LangChain, LlamaIndex, CrewAI or AutoGen);
- Acceptance: a demo agent emits a receipt with three lines of code; the
  proxy emits one receipt per inference call; neither requires `erebus build`.
- Status: proxy, MCP tool receipts, both SDKs and the LangChain.js root-chain
  handler ship. A mixed Python + Node trail verifies with
  `verify-attest --chain`. SDK receipts use the operator key only: no bundle
  digest, no machine co-signature and no `--strict` acceptance. In-process
  adoption is not enforcement.

#### P0-4 — Completeness: every run, not just the runs that opt in

A receipt proves a run happened. It does not prove every run was captured.
This is the biggest audit objection and must be a first-class product claim.

- attested gateway / egress path for model and tool traffic;
- signed launch policy that requires receipts;
- heartbeat receipts and a coverage report in the evidence pack;
- independent monitor that flags a gap between traffic and receipts;
- Acceptance: a run outside the gateway is detectable; the evidence pack
  reports coverage explicitly; the limitation is documented in the proof page.

#### P0-5 — Design partner and paid pilot

- one named design partner in the ICP;
- 14-day pilot on a real agent;
- one evidence pack accepted by the partner's auditor;
- one LOI or paid pilot on the Enterprise tier;
- Acceptance: a case study with receipts/day, verification latency, bytes of
  evidence per call and the buyer's own words.

#### P0-6 — External verification

- an auditor or consultancy verifies a trail with only public keys,
  `verify-attest` / `verify-evidence` and `cosign`;
- written confirmation that the pack is sufficient;
- Acceptance: T4 evidence in the repo or a public write-up, with no erebus
  account and no network access.
- Status: the `auditor/` kit ships. `verify_pack.py` requires pinned keys,
  `verify-evidence` with a checked bundle and an inclusion proof per receipt,
  and checks the DSSE envelope with `cosign` and the RFC 3161 token with
  `openssl` when those tools are present. The offline proof runs in CI via
  `evidence_e2e.rs` (valid pack accepted, doctored pack refused). The **written
  third-party confirmation is still missing** — this is not T4 evidence yet.

### 3.3 Existing pilot gates

- **T2 internal pilot** (started 2026-09-29): one real agent behind
  `serve --attest-key`, at least two enrolled machines, a registry with
  `--tsa-url`, zero `verify-attest --strict --proof` failures. Running, not
  complete.
- **T3 design partner**: one named partner in the ICP, offline verifier
  delivered, LOI on the Enterprise tier.
- **T4 third-party verification**: an auditor verifies a trail in writing.

### 3.4 Out of scope

TEE remote attestation, zkML, multi-party consensus, Rekor (the erebus log is
the anchor), a full offline Merkle log, proving a tool's effect on the outside
world, hosting inference, healthcare, hobbyist developers, a marketplace.

---

## 4. Frozen

P0 is green. These surfaces keep their tests, stay hidden from the default
`--help`, and require `--experimental`; they receive **no new features**:

`billing`, `mirror`, `replicate`, `hf`, `layer`, `swap`, `dashboard` (TUI),
`chat` (TUI + web UI), `sbom` beyond what `audit` needs, `scan --cve`,
`backup`/`restore`, webhooks, SSO/SAML, K8s Helm chart, the five protocol
frontends (`scripts/frontends/`), MCP registry endpoints, waitlist/landing.

Rules:

- A PR touching a frozen surface must name an open item in §3 that it unblocks.
- Frozen commands are hidden from the default help and require
  `--experimental` (or `ERE_EXPERIMENTAL=1`).
- The default `erebus --help` should read like a product, not a toolbox.
- Packaging, SISR, universal binaries and model serving are **means**, not the
  product. They do not get new scope until §3 is done.

---

## 5. The end-to-end demo

### 5.1 Current developer demo (2 minutes)

```bash
erebus keygen                                   # Ed25519 key, 0600
erebus trust <fingerprint>.pub
erebus build ./agent -o agent.erebus            # sandboxed single binary
erebus sign agent.erebus --key <fingerprint>.key
erebus verify agent.erebus                      # OK: signature verified
ERE_ATTEST_KEY=<key> ./agent.erebus < prompt    # runs; receipt appended
erebus verify-attest --chain agent.erebus.attest.d --bundle agent.erebus
```

Extended proof chain: `erebus attest --push` → `erebus verify-attest --proof`
shows inclusion in a checkpoint timestamped by an independent TSA.

### 5.2 Target buyer demo (5 minutes)

```bash
curl -fsSL https://get.erebus.dev | bash
erebus demo
#  agent: hello-agent.erebus
#  receipt: hello-agent.erebus.attest
#  verify: https://verify.erebus.dev/r/<id>
#  OK: signature, chain, machine, transparency log
```

The buyer opens the link, sees `Verified OK`, downloads the evidence pack and
verifies it offline. No erebus account, no CLI, no trust in the vendor.

The demo must not depend on a repo clone or a local Rust toolchain.

---

## 6. Business model

Client **and** server stay MIT forever. We sell the **air-gapped evidence
deployment** now. A hosted trust center is a later tier and is not shipped.

| Tier | Price hypothesis | Includes |
|---|---|---|
| Free | €0 | public packages, local receipts, self-hosted registry, evidence export, `auditor/verify_pack.py` |
| Air-Gapped Evidence Deployment — sell now | **$25k/yr** | one deployment inside one perimeter (one agent family): self-hosted trust center, auditor handoff, SSO/SLA/retention as needed. Fixed annual invoice or PO; no seat count or usage meter |
| Team — hosted, not shipped | $1.5k/mo billed annually | hosted trust center, private receipts, verification links, evidence packs, RBAC |
| Enterprise+ | per protected agent/node | fleet identity, coverage monitoring, full history — not priced yet |

Verification stays free. Paywalling the verifier or the auditor kit would break
the trust claim. We do not charge per receipt or per token: value does not
scale with tokens, and per-receipt pricing would reward under-capture, the
exact audit objection we exist to close.

These are hypotheses, not validated prices. Public anchors on 2026-11-24:
AgentAudit Starter £24k/yr, Centurian Compliance-Anchor $25k+ monthly entry
point, APIR AUD 99/agent/month, SealedRun free and open source. Vendor-published
numbers, not realized prices. No paid pilots, no LOIs and no production
customers. Do not anchor the company on the current $29/$99 developer tiers.

**First paid pilot offer, not yet sold:** $12k fixed, 14 days, credited in full
against the first $25k year if an LOI is signed within 30 days. Deliverables:
one evidence zip with out-of-band pinned keys, a `verify_pack.py` run, an
explicit coverage statement, the buyer's written evidence checklist, and a
readout with receipts/day, verification latency and evidence bytes per call.

**Bottom-up math:** 50 AI vendors × $30k = $1.5M ARR; 500 × $30k = $15M ARR.
The first milestone is one paid pilot, not a pricing page.

Forbidden: hosting inference, paywalling the client, marketplace rev-share.

---

## 7. Positioning and traction plan

### 7.1 The one-line slide

> *« AI vendors selling agents into regulated environments cannot prove to
> their customers what the agent actually ran. erebus gives every execution a
> signed, externally anchored receipt, verifiable offline with erebus or stock
> cosign. MIT client and server; paid hosted trust center. »*

Problem, solution, for whom — one breath. Never lead with platforms, engines,
SISR or the registry.

### 7.2 Category — say it right

erebus is **execution provenance for AI agents**, packaged as a **trust
center** for the buyer. The technical category is the Sigstore / SLSA /
in-toto model (signed statement, DSSE, transparency log, `cosign` interop)
applied to *runs* instead of *builds*. The buyer category is the evidence
layer for AI procurement and audit.

Do not claim "AI-Native Compliance Infrastructure": that framing describes
agents that *do* compliance work, not the evidence layer they run on. It is an
adjacent buyer, not our category.

Do not claim "Datadog for agents": that is an operator-controlled
observability tool. We are the neutral evidence layer the operator cannot
rewrite.

### 7.3 Traction — what we can produce ourselves, in order

The honest line today is *no production users*. Editing docs cannot change
that; the steps below can, and each yields a number we are allowed to cite.

| Step | Deliverable | Number we can cite | When |
|---|---|---|---|
| T1 | **P1-1**: proof batteries green in CI, public badge | "the whole proof chain is re-proven on every commit" | done 2026-09-28 |
| T2 | **Internal pilot**: one real agent behind `serve --attest-key`, ≥ 2 enrolled machines, ≥ 14 days, registry with `--tsa-url` | receipts anchored, machines enrolled, strict+proof failures = 0, bytes of evidence per call | running; not complete |
| T3 | **Design partner** in the ICP: offline verifier delivered, LOI on the Enterprise tier | "1 LOI; air-gapped verification accepted by their auditor" | 90-day plan |
| T4 | **Third-party verification**: an auditor verifies a trail with only public keys and `verify-evidence` / `cosign`, in writing | "verified by someone who does not trust us" | after T2 |

Rules: cite only what CI or a third party proves; no star counts; tell the
founder story as results (proof chain complete, Python signer and Merkle
byte-compatible with Rust, cosign interop, SIGKILL chaos survived), never as a
module list.

### 7.4 The boundary, and the three questions

Full text: [`docs/src/concepts/proof.md`](docs/src/concepts/proof.md). The
short form every pitch must respect:

- **We prove** what ran, where, when, with what / producing what, and that
  the record was never edited (L1 + L3 in §1). A flight recorder for agents.
- **We do not prove** the computation was faithful (L2 — TEE/zkML only if a
  customer asks), that the agent did the right thing (that is evaluation), the
  plaintext (digests only), or a root-compromised host (default enrollment is
  a software key; `--tpm` seals to the TPM named by `TPM2TOOLS_TCTI`, so root
  on that machine can still ask the TPM to unseal).
- **We do not yet prove completeness**: a receipt proves a run happened, not
  that every run was captured. P0-4 is the workstream that closes this gap;
  until then the evidence pack must state coverage explicitly.
- **"And if the agent lies?"** → *We do not judge the agent; we make it
  impossible to lie about what it did.*

The three questions that decide the outcome:

1. *Who needs this now?* AI vendors selling into regulated enterprises,
   answerable to a buyer or auditor who does not trust their logs. Must be a
   **name** (T2/T3), not a sector.
2. *Why now?* Agents act without a human in the loop; procurement already asks
   for evidence; editable logs are not accepted for systems that act. The EU
   AI Act high-risk dates are staggered (Annex III from 2027-12-02, Annex I
   from 2028-08-02), so sell current procurement pain, not one deadline.
3. *Why not a feature of Datadog / LangSmith?* An operator-run tool cannot
   produce evidence the operator does not control. Traces answer "what
   happened?" to the operator; an anchored receipt answers it to the auditor.
   The neutral log is the product; the launcher is where the signature is
   unbypassable.

What will get us refused is not L2. It is "no production users" with no pilot
or LOI beside it.

### 7.5 The competitive field, Fall 2025 → Summer 2027

Among accelerator-backed peers surveyed publicly: **none ships signed,
anchored, offline-verifiable per-execution receipts for agents.** The closest,
and what each teaches:

| Company (batch) | What they do | Relation | Lesson |
|---|---|---|---|
| Caution (S26) | verifiable compute on AWS Nitro enclaves; proves prod = reviewed source via reproducible builds | nearest neighbour: proves *what is deployed*, cloud + TEE | link bundle to source; we own edge / offline / per-run, they own cloud enclaves |
| Klaimee (Sp26), Mount (Sp26) | liability insurance for deployed agents | **buyer / channel** | they need evidence to underwrite and pay claims |
| Valgo (W26) | risk pricing for physical AI, "historical data doesn't exist" | buyer / channel | an anchored trail *is* that loss history |
| Multifactor (F25), Agentic Fabriq (W26) | agent identity, permissions, audit logs | complement | their audit logs are operator-controlled: we are the tamper-evident back end |
| Salus (W26) | blocks agent actions before they execute | complement | pre-execution checks belong in receipts |
| GrayPass (F26) | signed proof a human approved a key action | complement | carry signed approvals in the statement |
| Sentrial (W26) | "Datadog for agent reliability" | the operator tool we contrast against | — |
| Seeing Systems (W26) | AI-commanded strike drones; UK Royal Marines + 4 NATO forces | **T3 target** (European, NATO) | defense buyers sit in the batch |
| Arden (Sp26), Denki (F25) | AI-native audit firms | **T4 target** | a third party that verifies a trail in writing |

Rules: name neighbours by what they prove, never "no one else does this"; the
batch is a pipeline (insurers as channel, drone and industrial companies as
T3, audit firms as T4), not just a competitor list.

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

- **2026-11-24** — Product reset: erebus is positioned as the **trust center
  for AI agents**; ICP narrowed to AI vendors selling into regulated
  enterprises; 90-day plan, completeness workstream, trust-center MVP and
  frozen-surface rule added. No production customers yet; one design partner
  and one paid pilot are the next proof points.
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
