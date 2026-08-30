# ROADMAP.md — erebus : single product, business & execution plan

> **Single consolidated document (2026-08-30).** Merges former `MISSION_LOG.md`,
> `HANDOFF.md`, `ROADMAP-CONSOLIDATED.md`, `BUSINESS.md` and `PITCH_DECK.md`.
> Source of truth: **ROADMAP.md** — real code state, what shipped, what's left,
> the business model and the pitch.
>
> Tagline: *« Sign. Track. Prove. — Ship AI agents with verifiable attestation. »*

---

## 1. Vision

**Erebus = the "git log" for AI in the physical world.**

Every erebus agent execution emits a signed attestation proving what ran, on
which machine, at what date, and that nothing was altered. Regulated
enterprises (EU AI Act, SOC 2, ISO 27001, public procurement, UNECE WP.29)
**need this proof** and have **no tool** that produces it today.

> **The real product is not packaging — it's the signed traceability chain.**
> Packaging is the demo. The proof is the business.

### The moat (not SISR)

SISR is commoditized (XetHub on HF, Ollama layers, Git LFS). Our moat is the
**execution-attestation chain**: each `.erebus` + `.erebus.attest` forms a
cryptographically verifiable offline proof. The bigger the registry grows, the
richer the compliance history → natural lock-in.

### Product comparison

| | erebus | ollama | llamafile | Docker |
|---|---|---|---|---|
| Distribution | one `.erebus` × 4 OS/arch | app store + models | single binary | images + daemons |
| Registry | self-hostable | proprietary cloud | none | image registry |
| Delta model updates (SISR) | ✅ content-defined | ❌ re-download | ❌ | ❌ (layers) |
| Signed attestation | ✅ Ed25519 chain | ❌ | ❌ | ❌ |
| Offline-first | ✅ | ✅ | ✅ | ❌ |
| Packaging | ✅ | ✅ | ✅ | ✅ |

**Target** : not a "Docker killer" — Docker stays for orchestration. The angle
is execution traceability, where nothing exists today.

---

## 2. Real code state (v0.5.0)

Rust workspace, 3 crates (`erebus-core`, `erebus-stub`, `erebus-cli`) + a
Python stdlib server (`scripts/registry_server.py`). Zero `unsafe` in core/CLI;
only the stub uses it (with `SAFETY` comments).

**Tests: 444 workspace green** (`cargo test --workspace --release`).
**Quality:** `cargo fmt`, clippy `-D warnings` per crate, `cargo audit` RC=0.
**Toolchain:** stable only (never nightly/beta), musl for the stub.

### Shipped and validated

| Feature | Proof |
|---|---|
| Universal binary `--universal` | 4 native slices in one 59 MB file, validated linux-x64 / arm64 (qemu) / win-x64 (Wine) |
| Windows PE stub port | MapViewOfFile, CreateProcessW, ProcessPrng shim |
| `erebus serve` | Multi-format engine resolution (`inference.rs`): GGUF → llama-server, safetensors/ONNX/TRT-LLM/MLX → vLLM; TinyLlama E2E |
| Registry + `pull`/`publish` | stdlib server, SHA-256 verify, bearer tokens, quotas, orgs/RBAC, audit log, Stripe billing |
| `Agentfile.yaml` | Same schema as `.erebus.toml`; CLI > file > detection |
| GPU auto-detect + `--ngl` | `gpu.rs`, env `ERE_GPU`/`ERE_VRAM_MB`/`ERE_NGL`, pins never overridden |
| Chat UI | ratatui TUI + browser UI (std-only proxy) |
| SISR delta updates | FastCDC content-defined chunking, Ed25519-signed manifests, Merkle, fail-cold verify at boot |
| Rollback + health gate | `.bak` snapshot, fork+waitpid supervisor, anti-loop quarantine |
| `erebus attest` | `.erebus.attest` (signed JSON, machine hash never in plaintext) |
| `erebus audit` | compliance report: SBOM → **CycloneDX**, attestation → **in-toto** |
| `erebus lifecycle` | policy-gated state machine: acquired → quarantined → trusted → revoked → deleted; only `trusted` served |
| Fail-closed registry auth | scrypt, default-deny, mutations blocked without token |
| MCP server registry | `/mcp`, `/mcp/<name>`, `/mcp/<name>/install` |
| SISR benchmarks | 100 MB payload, 1% change → 1.28 MB delta (**98.7%** measured through the real engine) |
| Security | zeroization, ANSSI, 2 chaos harnesses **SURVIVED** (30 corruptions + 10 SIGKILLs) |

Reproducible numbers: [`benchmarks/`](benchmarks/README.md).

### Known constraints / gotchas

- **VPS disk chronically tight** (~1–2 GB). Purge `target/{debug,win-gnu}`,
  `~/.cache/erebus`, old test bundles before heavy builds.
- **qemu-user**: `unshare` → EINVAL; test ARM with `--isolation none` inside docker.
- **Windows slice**: via git-bash/WSL for universal files; Wine <7 lacks WMI.
- **macOS slice**: cross-compiled + inspected, **never run** on real Apple Silicon (to validate).
- **`serve`**: encrypted and squashfs bundles unsupported (clear error).

### Execution / operations

- Commands: `erebus build/run/serve/chat/pull/publish/swap/inspect/layer/
  keygen/sign/verify/trust/attest/audit/lifecycle/dashboard/doctor/scan/env/
  clean/selftest/upgrade/migrate/completion/man`.
- Chaos: `scripts/chaos_monkey.sh 30` + `scripts/chaos_registry_serve.sh` (must print **SURVIVED**).

---

## 3. What's left to do

### 🔴 P0 — Immediate fixes / uncommitted debt

- [ ] **Commit the `scripts/registry_server.py` diff**: adds `verify_integrity()`
  (SHA-256 check of blobs `[payload‖meta]`, independent of the embedded state,
  fail-closed). Closes a hole: a corrupted blob must not "forget" its
  Trusted/Revoked state and be served as Acquired.
- [ ] **Docs Phase 1: standardize `.ere` → `.erebus`** across ~30 files
  (`docs/src/guides/*`, `docs/src/concepts/*`, `docs/src/reference/*`,
  `docs/src/architecture/*`, `docs/src/spec/*`, `docs/src/migration/*`,
  `docs/src/cli/erebus-build.md`, `docs/src/security.md`, `docs/src/CHANGELOG.md`).
  `.erebus` today appears in only 8 files.
- [ ] **Residual validation**: run the darwin-aarch64 slice on real Apple
  Silicon; automated QEMU CI for ARM slices.
- [ ] **Ops**: watch ratatui upstream; recurring VPS disk cleanup.

### 🟠 P1 — Close the monetization loop (Pro/Team tiers)

- [x] **Deploy the public registry behind nginx TLS** (completes Tier 1: auth,
  quotas, SISR counter, landing — code complete in `df27edc`).
- [x] **Stripe in prod** — Checkout + webhooks (Pro $29, Team $99) wired
  in server (`registry_server.py`) + CLI `erebus billing checkout` (`1c640fd`);
  production testing requires a live Stripe account + webhook endpoint.
- [x] **Downloadable audit log** — server `/audit/download` + client
  `erebus audit-log` (`32177ee`). End-to-end test requires deployed registry.

### 🟡 P2 — Registry functional gaps (competitor audit)

- [ ] **GGUF guard** — per-tensor manifest for GGUF models (tensor-level integrity).
- [ ] **Periodic integrity verification** — systemd timer re-checking hashes,
  auto-quarantine on mismatch.
- [ ] **Rich model metadata** — format, size, source, `scan_results` per artifact.
- [ ] **Soft-delete with audit trail** — retain metadata after delete.
- [ ] **Garbage collection** — bit-rot detection + unreachable blob reclamation.
- [ ] **Backup/restore manifest** — disaster recovery.
- [ ] **Pluggable auth: HMAC, Ed25519, OIDC, JWKS** — multi-provider.
- [ ] **Provider integration** — GitHub/GitLab/Gitea webhooks (token issuance + repo-scoped auth).
- [ ] **CVE scanning** of model artifacts (GGUF/safetensors).

### 🔵 P3 — Multi-protocol frontends (Shardline-like)

- [ ] **HuggingFace Hub API compat** — drop-in for `huggingface-cli`.
- [ ] **OCI Distribution frontend** — `docker push/pull`-compatible.
- [ ] **Git LFS frontend** — model versioning in Git.
- [ ] **S3-compatible frontend** — S3 API for lakehouse clients.
- [ ] **Bazel HTTP remote cache frontend** — CI build cache.

### 🟣 P4 — Enterprise + distribution

- [ ] **Air-gapped mirror** (Buncker-like, encrypted USB sync) under appliance license.
- [ ] **Signed embedded SBOM** per bundle.
- [ ] **SSO/SAML + SLA**.
- [ ] **Web UI** — compliance admin dashboard (the webchat is for chat, not a dashboard).
- [ ] **Kubernetes operator / Helm chart**.
- [ ] **Multi-node / cross-region replication** — high availability.
- [ ] **Webhooks** (on promote, quarantine, delete) — event-driven.

### ⚪ Ideas / unexplored (IDEAS.md)

- First-principles: safety requires human audit + sandbox (seccomp/landlock).
- Confirm a filmed real demo `build → sign → attest → run` for the launch comment.

---

## 4. Business model

> Decided 2026-08-26. **The client AND server code stay MIT forever**: we monetize
> the **hosted service**, never the software.

**Founding insight (revised):** AI packaging is a feature, not a business. The
real product is the **cryptographic proof** of what executed, on which machine,
at what date, unaltered. Generated in the background free in open source,
paid in compliance and audit trail.

### The tiers

| Tier | Price | Includes |
|---|---|---|
| **Free** | €0 | Public packages, 10 GB transfer/month |
| **Pro** | $29/mo | Unlimited private packages, 1 TB SISR CDN, signed SBOM, attestations |
| **Team** | $99/mo | All Pro + RBAC, audit log, compliance dashboard, webhooks, 5 TB |
| **Enterprise** | $24k/yr | Air-gapped mirror, SSO/SAML, SLA, automated compliance reports |
| **Enterprise+** | $50/node/yr | 50+ nodes, per-node attestation, full history |

### The real ICP

```
🛡️ Defense / admin           air-gapped by regulation (AANSSI, public procurement)
🏭 Industrial edge            retail kiosks, factories, vehicles — "500 machines, proof for the auditor"
📦 AI startups subject to     EU AI Act high-risk — mandatory lifecycle documentation
```

**Excluded**: healthcare (Lattice Health / Parachute / Wedge have the GTM lead),
OSS / hobbyist devs (they don't pay). Cross-industry + air-gapped + signed
attestation chain = our differentiator.

### The forbidden list

- ❌ Host inference — capital intensive, hyper-competitive zone
- ❌ Paywall the open-source client — kills trust and adoption
- ❌ Marketplace with rev-share now — wait for supply liquidity
- ❌ Sell to hobbyist devs — they don't pay for a registry

### The one-line YC slide

> *« We provide the cryptographic proof of what ran inside every AI agent, on
> every machine, at every moment. Regulated enterprises need this traceability
> to comply with the EU AI Act, SOC 2 and public procurement. Our binary format
> generates this proof in the background — free in open source, paid when
> hosted with compliance and audit trail. »*

### The business math

- **COGS**: SISR = ~50 MB transfer for an 8 GB model → CPU cost ~$0.001
- **Gross margin**: >95% on Pro/Team (no GPU to host)
- **Enterprise ACV**: $24k/yr × 10 clients = $240k ARR → seed viable
- **Expansion**: $50/node/yr for fleets → $25k/yr for 500 nodes
- **Lock-in**: attestation history is the accumulated data (no GPU capex)

### African context / Google Africa AI Lab

- 8 GB on 4G ≈ $5–10 of data; erebus delta ≈ $0.05. Offline-first = works
  through outages. Data sovereignty (weights never leave the device).
- **Lab deliverable**: `erebus build ./agent --gemini-model gemini-1.5-flash
  --gemma-fallback gemma-2b` → binary preferring Gemini API, local Gemma
  fallback offline. Attestation covers both paths.
- Flagship use case: Lagos fintech, anti-fraud agent on 500 PoS terminals, 50 MB
  delta per terminal, signed receipt per transaction, auditor verifies offline.

---

## 5. Condensed pitch (*Sign. Track. Prove.*)

**The problem**: `docker run` / `python app.py` → **zero proof** of what
executed. Updates = re-downloading 8 GB. No audit trail for EU AI Act / SOC 2 /
African regulators.

**The solution**: a self-contained binary + attestation chain. `erebus build
./my-agent → my-agent.erebus (18 MB)`, SISR delta (8 GB → ~50 MB), Ed25519 +
SHA-256 attestation + metadata, executes with seccomp/landlock sandbox, emits a
signed `.erebus.attest`.

**Why Africa, why now**: expensive bandwidth, unstable connectivity, data
sovereignty, regulatory compliance, edge ARM64/x86/RISC-V.

**Traction**: 3 Rust crates 0 unsafe core/CLI, 400+ tests, CSO audit 0 critical,
universal 4-slices, 98.7% SISR benchmark, auth+quotas+MCP registry.

**Live**: `cargo install erebus` → `erebus build ./agent --embed-gemma-2b -o agent.erebus`

**Final vision**: every AI agent execution leaves a cryptographic receipt. A
fleet operator queries: "show me all anti-fraud-model executions in Accra last
week". An auditor verifies offline. A regulator sees: zero tampering, offline
execution, data never left the device.

---

## 6. Archives — technical decisions (from MISSION_LOG, kept for reference)

These choices were RECORDED during the SISR initiative (missions 1–10,
completed 03/08/2026). They are **not set in stone** — revisit if a use case
demands it.

### SISR / auto-update
- **Stub network transport = HTTPS** (`ureq` + rustls). Trust in the Ed25519
  signature, not the transport; HTTPS anyway (ANSSI-friendly choice). The local
  `ERE_SISR_MANIFEST` path stays supported.
- **`--key` with `--enable-sisr` signs the SISR manifest**, not the binary
  (otherwise `sign_file` rebuilds and destroys `[manifest][ext]`). Binary
  signature + SISR simultaneously are unsupported in a single build.
- **Update URL**: `{base}/manifest` + `{base}/chunks/<sha256>`; resolution
  arg > env `ERE_UPDATE_URL` > meta `update_url`.
- **Rollback snapshot `.erebus.bak`** co-located (atomic rename); **health gate =
  fork+waitpid supervisor**; **failure counter not reset**; **quarantine** at
  `attempts >= ERE_HEALTH_MAX_ATTEMPTS` (default 3).
- **`/proc/self/exe`** can point to the pre-update inode after a rename → re-open
  the canonical path returned by `apply_update`.
- **Chunks content-addressed (SHA-256 enforced)**; source file mode copied to
  the `.tmp` before rename (else the exec bit is lost).

### Format / invariants
- **Layout**: `[stub][payload][metadata][footer]`; v2 plain · v3 signed ·
  v4 encrypted · v5 squashfs. `FLAG_SISR`, `SISR_FOOTER_EXT_SIZE=110`.
- **v1→v2 invariant**: a v1 binary is read/extracted/executed by the v2 runtime
  unchanged with no warning; `upgrade_binary` copies the segments
  byte-for-byte, never decompresses (hashes preserved).
- **SISR disabled ⇒ binary strictly identical** to the legacy format (tested).
- **Do not modify `format.rs` without bumping the version.**

### Security / conventions
- Zero `unsafe` in `erebus-core`/`erebus-cli`; stub only with `SAFETY` comments.
  No `panic!`/`unwrap` without context in library code; checked arithmetic; no
  memory leaks; keys zeroized on drop.
- **`--encrypt` is obfuscation only** (the AES-256-GCM key lives in the metadata
  by design). Use signing for authenticity.
- Never print private keys in CLI logs; warn when perms ≠ 0600 (no hard failure,
  to avoid breaking existing flows).

### Measured perf (i5-7300U @1.6 GHz, no SHA-NI)
- FastCDC scan ~390 MB/s; SHA-256 ~50 MB/s.
- 100 MiB target 64 KiB: 5.3 s (19 MiB/s), 812 chunks, 29 KiB manifest.
- Real SISR: 100 MB payload, 1% change → 1.28 MB delta (98.7%).

### Environment constraints
- `export PATH="$HOME/.cargo/bin:$PATH"` before `cargo`/`mdbook`.
- Verify before closing: `cargo fmt --check` → clippy per crate → `cargo test
  --workspace` → `mdbook build docs/`.

---

## 7. Security posture

> Condensed from the former `SECURITY.md`. Full threat model:
> [`docs/src/security.md`](docs/src/security.md).

**Reporting a vulnerability** : do not open a public issue. Email the
maintainer or open a
[confidential advisory](https://github.com/Tednoob17/erebus/security/advisories).
Response within 48h.

**Design principle** : *nothing touches disk before integrity is verified.* The
launcher reads the footer, validates SHA-256, and only then extracts. Verified
signatures precede integrity — no data is ever processed from an untrusted
source.

| Protection | Status | Details |
|---|---|---|
| SHA-256 integrity | ✅ | Payload hash verified before extraction |
| Atomic cache extraction | ✅ | `rename()` avoids TOCTOU races |
| `flock()` concurrency | ✅ | Advisory lock prevents duplicate extraction |
| Ed25519 signatures | ✅ | Footer v3, `keygen`/`sign`/`verify` |
| User namespaces | ✅ | `pivot_root` isolation without root |
| Seccomp filter | ✅ | Denylist blocks ~14 dangerous syscalls |
| AES-256-GCM encryption | ✅ | Optional payload encryption (v4) |

Scope: `erebus-core/`, `erebus-cli/`, `stub/`, and the format spec in
`docs/src/reference/format.md`. `examples/` are demo-only, not security-critical.

---

## 8. Changelog (condensed)

> Full history in the former `CHANGELOG.md` and git log. Highlights:

- **0.5.0** — SISR self-update engine (signed deltas, Merkle, health gate +
  automatic rollback + version quarantine); transparent v1→v2 migration;
  cross-compilation targets; Landlock sandbox; multi-platform release pipeline.
- **0.4.0** — PHP extension auto-download; shared-lib bundling; hardlined
  launcher (no panics on malicious input); isolation fails closed; key
  zeroization.
- **0.3.x** — cron, OpenTelemetry, tree-shaking, minify, health-port, persist,
  include, supervisor mode; execvp single-service path.
- **0.3.0** — **100% Rust CLI** (zero Python at runtime): build/inspect/scan/
  sign/verify/keygen/trust/doctor/env/clean/completion/man; `.erebus.toml`; man
  pages; shell completions; burned env-file bug.
- **≤ 0.2.x** — foundations: multi-arch releases, doctor/env, signing.

---

## 9. Contributing

> Condensed from the former `CONTRIBUTING.md`. Build/test/preflight wiring lives
> in the `Makefile`; the verification loop and ANSSI rules are in
> [`AGENTS.md`](AGENTS.md); style in [`CODE_STYLE.md`](CODE_STYLE.md) and
> [`RULES.md`](RULES.md).

- **Branching** : `main` (stable, tagged) ← integration via PRs; feature/fix
  branches off `dev`. Merge via squash/rebase, no merge commits.
- **Commits** : [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat` `fix` `chore` `docs` `refactor` `test` `ci` `perf`), imperative mood.
- **PRs** : target `dev`, CI must pass (lint, clippy, tests), one maintainer
  review, format changes must update `erebus-core/src/format.rs`.
- **Open asks** : squashfs + mmap direct read, LRU cache eviction, cold/warm
  start < 100 ms, distribution/discovery.
- **Questions** : GitHub Discussions, tag `@Tednoob17`.

---

## 10. Deprecated files — migration

The following documents have been **merged into this ROADMAP.md** and deleted
(see commit):

| Former file | Content destination |
|---|---|
| `MISSION_LOG.md` | §2, §6 (technical decisions), §3 |
| `HANDOFF.md` | §2 (state, gotchas, verification loop) |
| `ROADMAP-CONSOLIDATED.md` | §3 (competitor-audited gaps) |
| `BUSINESS.md` | §4 (business model) |
| `PITCH_DECK.md` | §1, §4, §5 (pitch) |
| `IDEAS.md` | §3 (unexplored levers) |
| `SECURITY.md` | §7 (security posture) |
| `CHANGELOG.md` | §8 (changelog, condensed) |
| `CONTRIBUTING.md` | §9 (contributing); AGENTS.md |
| `docs/ROADMAP.md` | this file (root `ROADMAP.md`) |
| `docs/AGENTS.md`, `docs/CLAUDE.md`, `docs/CODE_STYLE.md`, `docs/RULES.md` | root `AGENTS.md`/`CLAUDE.md`/`CODE_STYLE.md`/`RULES.md` (duplicates) |
| `research/*.md` (untracked) | key findings into §2 and §3; originals preserved in git/gstack |

References updated in `AGENTS.md`, `README.md` and `research/*.md` → now point
to `ROADMAP.md` (or the surviving root file).

**Kept in place** (not deprecated) : `CLAUDE.md`, `AGENTS.md` (agent configs,
root); `README.md` (public repo entry point); `CODE_STYLE.md`, `RULES.md`
(engineering conventions referenced by `AGENTS.md`); `docs/src/` (technical
mdbook documentation, incl. `docs/src/security.md`); `benchmarks/` (measured
evidence); `.opencode/`, `.github/actions/`, `node_modules`.

> **Recoverability** : a timestamped backup of every deleted file exists in
> `/tmp/opencode/erebus-docs-backup/` and in git history.
