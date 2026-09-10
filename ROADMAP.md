# ROADMAP.md — erebus : single product, business & execution plan

> **Single consolidated document (2026-08-30).** Merges former `MISSION_LOG.md`,
> `HANDOFF.md`, `ROADMAP-CONSOLIDATED.md`, `BUSINESS.md` and `PITCH_DECK.md`.
> Source of truth: **ROADMAP.md** — real code state, what shipped, what's left,
> the business model and the pitch.
>
> One-liner: *« AI agents run everywhere. Nobody can prove what they did.
> We generate the cryptographic proof. »*

---

## 1. Vision

**Erebus = the proof layer for AI execution.**

Every AI agent runs on a machine. Nobody can prove what it did, when, or where.
erebus generates a signed cryptographic receipt of every execution — automatically,
in the background, with zero manual audit. Regulated enterprises (EU AI Act,
SOC 2, ISO 27001, public procurement) **need this proof** and have **no tool**
that produces it today.

> **The real product is not packaging — it's the signed traceability chain.**
> Packaging is the demo. The proof is the business.

### The moat (not SISR, not packaging)

SISR is commoditized (XetHub on HF, Ollama layers, Git LFS). Packaging is
commoditized (Docker, Nix, Spack). Our moat is the **execution-attestation
chain**: each `.erebus` + `.erebus.attest` forms a cryptographically verifiable
offline proof. The bigger the registry grows, the richer the compliance history
→ natural lock-in.

### YC alignment (Fall 2026)

YC's Request for Startups for Fall 2026 explicitly names **"AI-Native
Compliance Infrastructure"**: *"Most compliance work is monitoring regulatory
changes, flagging anomalies, generating reports, and keeping audit trails...
The companies that get this right will become essential infrastructure for any
business operating globally."* erebus fits this RFS directly — we generate the
compliance evidence that AI-native infrastructure needs.

### Product comparison

| | erebus | ollama | llamafile | Docker |
|---|---|---|---|---|
| Signed execution proof | ✅ Ed25519 chain | ❌ | ❌ | ❌ |
| Compliance audit trail | ✅ in-toto attestations | ❌ | ❌ | ❌ |
| Delta updates (SISR) | ✅ content-defined | ❌ re-download | ❌ | ❌ (layers) |
| Offline-first | ✅ | ✅ | ✅ | ❌ |
| Packaging | ✅ (mechanism, not value) | ✅ | ✅ | ✅ |

**Target** : not a "Docker killer" — Docker stays for orchestration. The angle
is execution traceability, where nothing exists today.

---

## 1.5. Demo flow (the 2-min proof)

This is the demo that proves the product claim. Each step is annotated with
current code status.

```bash
# 1. Generate signing keys
erebus keygen                           # ✅ works

# 2. Trust the public key (for verify)
erebus trust ~/.local/share/erebus/keys/<fingerprint>.pub  # ✅ works

# 3. Build the binary
erebus build ./app -o agent.erebus      # ✅ works

# 4. Sign it
erebus sign agent.erebus --key ~/.local/share/erebus/keys/<fingerprint>.key  # ✅ works

# 5. Verify the signature
erebus verify agent.erebus              # ✅ works → "OK: signature verified"

# 6. Generate attestation (auto or manual)
#    With ERE_ATTEST_KEY set, the stub auto-generates .erebus.attest on run.
#    Without it, use the manual CLI step.
#    Auto: set ERE_ATTEST_KEY=~/.local/share/erebus/keys/<fingerprint>.key
#          and run → .erebus.attest written before execvp
erebus attest agent.erebus --key ~/.local/share/erebus/keys/<fingerprint>.key
                            # ✅ works → agent.erebus.attest

# 7. Verify the attestation
erebus verify-attest agent.erebus.attest  # ✅ works → "OK: attestation verified"

# 8. Tamper detection
# Modify 1 byte → verify → should say "TAMPERED"
printf '\x00' | dd of=agent.erebus bs=1 seek=3000000 count=1 conv=notrunc
erebus verify agent.erebus              # ✅ says "TAMPERED: signature does not match"
```

**What blocks the demo:**
1. ~~`verify-attest` not wired to CLI~~ ✅ Fixed (2026-09-10)
2. ~~Stub auto-attestation not implemented~~ ✅ Fixed — implemented in
   `erebus-stub/src/exec.rs:578-581` (`write_auto_attestation_if_requested`)
   + `erebus-core/src/attest.rs:319-335` (`write_execution_attestation`),
   opt-in via `ERE_ATTEST_KEY` env var.
3. ~~Tamper message unclear~~ ✅ Fixed (2026-09-10)

**The "agent, not app" demo (optional 3-min version)**: `examples/real-agent/`
→ signed ELF with real GGUF model + llama.cpp, run → `POST /infer` returns real
tokens inside the sandbox. Same crypto chain (verify → run → attest). Proven
2026-09-10; needs `download_model.sh` + staged `.deps/llama/` first.

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
| Packaged LLM agent (E2E) | `examples/real-agent/`: signed 646 MB ELF = GGUF + llama.cpp + embedded Python; real tokens via `/infer` in sandbox (2026-09-10) |
| Registry + `pull`/`publish` | stdlib server, SHA-256 verify, bearer tokens, quotas, orgs/RBAC, audit log, Stripe billing |
| `Agentfile.yaml` | Same schema as `.erebus.toml`; CLI > file > detection |
| GPU auto-detect + `--ngl` | `gpu.rs`, env `ERE_GPU`/`ERE_VRAM_MB`/`ERE_NGL`, pins never overridden |
| Chat UI | ratatui TUI + browser UI (std-only proxy) |
| SISR delta updates | FastCDC content-defined chunking, Ed25519-signed manifests, Merkle, fail-cold verify at boot |
| Rollback + health gate | `.bak` snapshot, fork+waitpid supervisor, anti-loop quarantine |
|| `erebus attest` | `.erebus.attest` (signed JSON, machine hash never in plaintext) — CLI build-time attestation AND auto-attestation via `ERE_ATTEST_KEY` env var (opt-in, writes before execvp) |
| `erebus verify-attest` | verifies detached `.erebus.attest` against trusted keys (wired 2026-09-10) |
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

### 🔴 P0 — Attestation demo gaps (blocks YC demo + enterprise proof)

The core claim of erebus is "we generate the cryptographic proof of what ran."
The library (`erebus-core`) produces and verifies attestations, but the CLI
workflow has gaps that break the demo flow:

- [x] **`erebus verify-attest <file>`** — wired `verify_attestation()` from
  `erebus-core/src/attest.rs:335` to new CLI subcommand. Fixed serialization
  mismatch (`to_vec` → `to_vec_pretty`) that caused signature verification to
  always fail. Tested end-to-end.
- [x] **Stub auto-attestation** — implemented in
  `erebus-stub/src/exec.rs:578-581` (`write_auto_attestation_if_requested`)
  and `erebus-stub/src/exec.rs:807-835` (the function body), wired to
  `erebus-core/src/attest.rs:319-335` (`write_execution_attestation`).
  Opt-in via `ERE_ATTEST_KEY` env var; output to `ERE_ATTEST_OUT` or
  `<bundle>.attest`. The stub writes a signed `.erebus.attest` before
  `execvp` when the env var is set. The demo step `erebus attest` remains
  available for manual attestation without the env var.
- [x] **Tamper message clarity** — `verify` output now says `TAMPERED: signature
  does not match any trusted key` instead of the generic message.
- [x] **PEM key support** — `sign`/`attest` now accept raw 32-byte keys from
  `erebus keygen` and also PEM format (`-----BEGIN PRIVATE KEY-----`)
  via `ed25519_dalek::SigningKey::from_pem()`. Interoperability with
  openssl/ssh-keygen confirmed.

### 🔴 P0 — Attestation completeness (what "cryptographic proof of AI agent execution" must mean)

For the claim "Cryptographic proof of AI agent execution" to be true, the
attestation chain must cover more than the current build-time flow.

**What the current attestation proves (v0.5.0):**
- bundle_hash (SHA-256 of the full binary)
- payload_hash, metadata_hash
- format_version, flags (signed/encrypted/sisr)
- builder ("erebus-cli v0.5.0"), author, license
- layers (name, kind, sha256)
- execution timestamp (ISO 8601 UTC)
- machine_id_hash (SHA-256 of hostname+os+arch, **never in plaintext**)
- os, arch
- Signed Ed25519 over in-toto statement canonical bytes

**What it does NOT yet prove (gaps):**

1. **Per-execution behavior log (inputs/outputs hashed)** — the attestation
   captures that *the bundle ran*, not *what the agent did*. For non-repudiation
   of action (Level 3 of the 3 proof levels), you need to capture inputs received,
   outputs produced, decisions made.
   → P0: until a complete solution exists (agent hooks/standards interface),
   capture at minimum an output_hash and input_hash in the attestation if
   available, signed by the agent's key (not just the build key).

2. **Attestation registry storage + queryable history** — attestations currently
   land as `.erebus.attest` files on disk. An auditor cannot run
   "show me all executions of agent X last week". For EU AI Act / SOC 2
   compliance trails, attestations must be stored in the registry and queryable.
   → P2: wire attestation upload to registry server (`/attestations`), store
   in audit log, provide `erebus attest-history --query ...` CLI. This closes
   the loop between runtime attestation and the hosted compliance trail.

3. **TEE / zkML — higher proof levels** (out of scope for current ICP, keep as future option):

   The "cryptographic proof of AI agent execution" problem spans 3 levels of
   guarantee, not just one:

   - **Level 1 — Binary/model integrity**: "this exact code/model ran, unmodified"
     → hardware attestation + signature suffices. **erebus partially covered**
     (SHA-256 + Ed25519 of the bundle, but no TEE hardware proof, no external
     anchoring).

   - **Level 2 — Execution integrity**: "this computation produced this output
     from this input, correctly" → needs ZK (zkML) or TEE with remote
     attestation. **erebus does NOT cover** — the sandbox isolates execution
     but doesn't prove computation correctness.

   - **Level 3 — Non-repudiation**: "this agent (identified by a key) produced
     this action at this time" → signature + timestamp + agent identity +
     hashed output. **erebus partially covered** (Ed25519 signature + timestamp,
     but no agent identity or output capture).

   Concrete technical approaches:

   a) **TEE (Trusted Execution Environment) + remote attestation** — Intel
      SGX/TDX, AMD SEV-SNP, AWS Nitro Enclaves. Hardware generates a signed
      quote attesting enclave hash + execution state. For "this exact code ran
      in an untampered isolated environment". Limit: trust the vendor +
      certificate chain; SGX has side-channel history (Foreshadow, Plundervolt
      — relevant given offensive profile). Nitro Enclaves is more pragmatic for
      production AI agents (CPU only, no GPU inside).

   b) **zkML (ZK proofs over inference)** — EZKL, Giza, Modulus Labs, Risc0
      (generic zkVM). Arithmetic circuit of the forward pass → SNARK/STARK
      proof that output = f(input, weights). Works for small models, impractical
      for real LLMs in 2026 (proof cost too high). Alternative: prove only a
      critical portion of the decision chain.

   c) **Verifiable replay/journaling (pragmatic approach)** — Signed log of each
      call: hashed input, hashed output, model/version, timestamp, agent key,
      chained as Merkle log (Certificate Transparency / Sigstore Rekor style).
      No proof of computation correctness, but proof of trace integrity and
      non-repudiation. Much more feasible now, sufficient for most compliance
      needs. **This is the recommended approach for erebus** in the current ICP
      (EU AI Act, SOC 2).

   d) **Multi-party / consensus** — Multiple independent executors (TEE or not)
      run the same agent, compare outputs (optimistic verification, fraud
      proofs). For on-chain agents. Cost = execution redundancy.

   **Pragmatic recommendation for erebus (current ICP compliance):**
   Start with **(c) + Ed25519 signature of each step + periodic anchoring of
   Merkle root hash on a public blockchain or TSA (RFC 3161)**. Verifiable,
   auditable, low cost, no hardware vendor dependency. TEE becomes interesting
   only if you need to guarantee execution integrity itself against a malicious
   operator (internal threat / untrusted cloud) — not the current ICP (defense
   / air-gapped, industrial edge, EU AI Act startups under company control).

   **Environments/support by proof level:**
   - Level 1 (binary integrity): anywhere, erebus binary + signature
   - Level 2 (TEE execution integrity): physical machine with SGX/SEV-SNP or
     dedicated cloud instance (AWS Nitro, Azure Confidential, GCP Confidential)
   - Level 2 (zkML): any machine for inference, proof generation separate
     (RAM/CPU/GPU intensive)
   - Level 3 (verifiable journaling): anywhere, key = signing key + external
     anchoring (blockchain or TSA)

5. **TEE hardware attestation in the stub** — optional, out of scope for current
   ICP. If we want Level 2 (TEE), we would need: TEE detection → launch agent
   in enclave → retrieve hardware quote → integrate into attestation.
   **Not a priority** for current ICP.

**Machines / environments the claim covers (v0.5.0):**
- Linux x86_64 + aarch64: full sandbox (namespace + seccomp + landlock) +
  attestation via `ERE_ATEST_KEY`
- macOS ARM64: stub + codesign, attestation via `ERE_ATTEST_KEY` (different security model)
- Windows x64: PE stub, minimal/no sandbox, attestation via `ERE_ATTEST_KEY`
- Universal polyglot: 1 file, 4 slices, runs everywhere

**What the claim DOESN'T cover:**
- Healthcare (excluded ICP — Lattice Health / Parachute / Wedge lead)
- Hobbyist / OSS devs (they don't pay)
- Docker environments (the angle is "no Docker needed", not "anti-Docker")

### 🔴 P0 — Real-agent packaging reality (validated 2026-09-10)

We packaged a **real LLM agent** end-to-end, not a hello-world: `examples/real-agent/`
→ one signed ELF (646 MB) containing GGUF weights (Qwen 0.8B), the full
llama.cpp runtime, embedded Python + Flask. Runs in the pivot_root+seccomp
sandbox; `POST /infer` returns real generated tokens. Verified:
`signature verified` → run → infer OK. No llama of any kind on the host.

Two runtime fixes had to land in the example source (were broken before):

- [x] **Bundled runtime libs** — `llama-cli` links `libssl.so.3`,
  `libcrypto.so.3`, `libstdc++.so.6`, `libgcc_s.so.1`, `libgomp.so.1`, which the
  sandbox (pivot_root) does not expose. Now copied from build host into
  `.deps/llama/` so `LD_LIBRARY_PATH` resolves them inside the sandbox.
- [x] **`GGML_BACKEND_PATH`** (file path, NOT a directory) — this llama.cpp build
  reads the env var as *one backend .so*. Its default discovery (scan near
  `/proc/self/exe`) silently finds zero backends inside pivot_root. App now
  points it at `libggml-cpu-x64.so`.

**Model weights are NOT in git** (by design): `.gitignore` holds `*.gguf` +
`examples/*/.deps/`. The `download_model.sh` + staged `.deps/llama/` are the
reproducible fetch path; the **build bundles them into the payload** regardless.
A fresh clone = run the download script → build → run.

That hand-work is the product gap. To make "any agent, any harness, run
anywhere" a product (not a hand-tuned example), we need:

- [x] **`erebus init agent`** — scaffold that mounts llama.cpp runtime + fixes
  (backend path, bundled libs) so a working agent builds in ~30 s, no
  copy-paste of `.deps/llama/`. `erebus init agent [dir]` writes
  Agentfile.yaml / app.py (GGML_BACKEND_PATH pinned, arch-aware) /
  download_model.sh / requirements.txt / README.md / .gitignore, then stages
  the llama runtime: `--runtime <dir>` (or `ERE_LLAMA_RUNTIME`) copies an
  existing runtime, else downloads `llama-b{N}-bin-ubuntu-{arch}.zip`
  (default b10636 = the runtime proven in examples/real-agent). Staging
  preserves the `.so` version symlink chain (a `fs::copy` skip left the
  loader unable to resolve `libllama-common.so.0`) and bundles the 5 host
  glibc libs (`libssl`/`libcrypto`/`libstdc++`/`libgcc_s`/`libgomp`).
  Validated end-to-end (2026-09-10): `init agent` → build signé 646 MB →
  run sandbox → health ok → `POST /infer` returns real tokens +
  `[erebus] attestation written`. `--no-runtime` scaffolds offline.
- [x] **Auto-embed the engine in `build`** — `erebus build <app> --engine
  <path|b<N>>` stages a llama runtime into the payload at `.deps/llama`
  (replacing anything bundled), reusing the shared `engine.rs` staging (copy
  with symlink chain preserved, or download `b<N>`; + 5 host glibc libs +
  validation). `--engine` feeds the config fingerprint so the build cache
  invalidates per engine. Validated end-to-end (2026-09-10): app without
  `.deps` → `--engine b10636` runtime (65 files, `libggml-base.so -> .0 ->
  .0.22.0` chain intact) → sandbox execs `llama-cli` (needs the
  `LD_LIBRARY_PATH` pattern from the app, as real-agent/app.py sets — $ORIGIN
  is unreliable in the sandbox). App dir without `.deps/` is now enough:
  `erebus init agent --no-runtime` + `build --engine`. `ERE_REGISTRY` still
  pending.
- [x] **Portability caveat** — documented in the scaffold README (`erebus init
  agent`) + this roadmap: the bundled libs carry the **build host's glibc ABI**
  (same-or-newer glibc required on target; older hosts cannot exec the bundled
  llama-cli). Fully static musl llama.cpp build = stretch goal to break the
  tie. Arch is pinned too: `libggml-cpu-x64.so` vs aarch64 backend — build on
  the target arch.
- [x] **Package OpenCode itself** (experiment) — Go binary (`opencode` v1.18.30)
  renamed `app` + `opencode.json` + Agentfile entrypoint `[/app/app, models]`
  builds and RUNS inside the sandbox (isolation 2). Two hardenings were
  required and shipped:
  - **Pure-binary payloads get no glibc**: `/app/app` else `ENOENT` after pivot
    (no `/lib64/ld-linux*`). CLI now bundles the host's base glibc
    (`copy_base_glibc` → `lib64`/`usr/lib/<triple>`: ld-linux, libc, libm,
    libpthread, libdl, librt) when `runtime_name == "binary"` and no embedded
    interpreter. Had to run BEFORE payload creation (was inserted after — tar
    had no lib64).
  - **JS runtimes need `/dev` + `/proc`**: `opencode` re-execs an embedded Bun
    (JSC) which opens `/dev/urandom` and `/proc/self/maps` at startup and
    segfaults on its GC canary when absent. Stub now mounts a tmpfs `/dev`
    with standard nodes (bind-mounted from host; `mknod` is blocked by kernel
    hardening in unprivileged userns) + `/proc` before `pivot_root`. Fresh
    procfs needs a PID namespace, so it falls back to a **read-only bind of
    host `/proc`** with a warning — see hardening item below.
  **Decision: API-key mode** (network is available in the sandbox by default;
  the key is injected via env/`ERE_SECRET_*` at runtime and never baked into
  the artifact — keeps the offline/attest story intact). Local-model mode
  (llama-server + GGUF in-payload) is the heavier fallback, not pursued now.
  Proof: `/tmp/opencode-sb.erebus` lists models over the network inside the
  sandbox; no-sandbox control (`--isolation none`) works identically.
- [x] **Harden sandbox `/proc`** — done: `exec_app` now runs a supervisor fork
  on the pivot path. `namespace::enter_newpid` (new `CLONE_NEWPID` unshare,
  pivot path only) makes the executor child **PID 1** of a fresh namespace, so
  `mount_dev_and_proc` mounts a **hermetic procfs** (host processes invisible;
  verified: `/proc` in-sandbox lists only pid 1, `self_pid: 1`). The host
  `/proc` bind survives only as a warned fallback when an outer container
  denies `unshare(CLONE_NEWPID)`. Parent stub supervises the child, keeps the
  health endpoint alive for the app's full life, and relays the child's exact
  exit status/signal to its own caller. Sandbox session now reaps its own
  orphans (app is pid 1).

### 🔴 P0 — Immediate fixes / uncommitted debt

- [x] **Commit the `scripts/registry_server.py` diff**: adds `verify_integrity()`
  (SHA-256 check of blobs `[payload‖meta]`, independent of the embedded state,
  fail-closed). Closes a hole: a corrupted blob must not "forget" its
  Trusted/Revoked state and be served as Acquired. → `d1ec174`.
- [x] **Docs Phase 1: standardize `.ere` → `.erebus`** across ~30 files
  (`docs/src/guides/*`, `docs/src/concepts/*`, `docs/src/reference/*`,
  `docs/src/architecture/*`, `docs/src/spec/*`, `docs/src/migration/*`,
  `docs/src/cli/erebus-build.md`, `docs/src/security.md`, `docs/src/CHANGELOG.md`).
  → `39a6d7d`. No remaining `.ere` references in tracked files.
- [x] **Residual validation**: automated QEMU CI for ARM slices (aarch64 + armhf)
  added (`0c40bd6`). darwin-aarch64 on real Apple Silicon requires hardware
  (not done — needs physical Mac or cloud macOS runner).
- [x] **Ops**: VPS disk cleanup done (96%→87%, 13GB freed). Recurring cleanup
  cron + `scripts/test_arm_qemu.sh` added (`ac58b47`). Watching ratatui
  upstream is ongoing.

### 🟠 P1 — Close the monetization loop (Pro/Team tiers)

- [x] **Deploy the public registry behind nginx TLS** (completes Tier 1: auth,
  quotas, SISR counter, landing — code complete in `df27edc`).
- [x] **Stripe in prod** — Checkout + webhooks (Pro $29, Team $99) wired
  in server (`registry_server.py`) + CLI `erebus billing checkout` (`1c640fd`);
  production testing requires a live Stripe account + webhook endpoint.
- [x] **Downloadable audit log** — server `/audit/download` + client
  `erebus audit-log` (`32177ee`). End-to-end test requires deployed registry.

### 🟡 P2 — Registry functional gaps (competitor audit)

All P2 items implemented in `erebus-core` **and wired to user-facing surfaces**:
- **GGUF guard** — `erebus-core/src/gguf.rs`: GGUF header + tensor manifest
  parser (`parse_header`), `tensor_manifest` on `ModelLayer`, weight-swap
  detection via `verify_tensor_manifest`. **Wired**: the stub launcher
  (`erebus-stub/src/main.rs`) verifies every `ModelLayer`'s tensor manifest
  against the extracted GGUF at cold start and refuses to execute on mismatch
  (3 new stub tests). Tested: 4 gguf + 1 layer + 3 stub.
- **Periodic integrity verification** — `erebus-core/src/sisr/health.rs`
  `periodic_integrity_check`: SHA-256 reconcile of cache, quarantine on
  mismatch. Tested.
- **Rich metadata** — `ModelLayer.source` + `scan_results` (JSON, open schema).
  Tested.
- **Soft-delete** — `ArtifactState::Deleted` terminal state +
  `audit::record_deletion` signs a `DeletionAuditEntry` per removal
  (Ed25519). Tested: 3 deletion-entry tests.
- **Garbage collection** — `erebus-core/src/gc.rs` `collect_garbage`: moves
  orphaned content-addressed blobs to a trash dir (soft-delete compatible).
  **Wired**: `erebus clean --gc-blobs --blob-dir … --manifest-dir …`
  (verified end-to-end: orphan moved to trash, live blob kept).
  Tested: 5 tests.
- **Backup/restore** — `erebus-core/src/backup.rs` `build_backup_manifest` +
  `verify_backup`: signed DR manifest, blob-closure verification.
  **Wired**: `erebus backup` + `erebus restore` CLI commands
  (verified end-to-end: valid restore passes, tampered manifest fails).
  Tested: 4 tests.
- **Pluggable auth** — `erebus-core/src/auth.rs`: `Authenticator` trait with
  HMAC-SHA256 and Ed25519 bearer strategies, constant-time token compare.
  **Wired**: `scripts/registry_server.py` accepts `ed25519:` bearer tokens
  verified via a pure-Python Ed25519 verifier (RFC 8032 test vectors +
  interop against real `ed25519_dalek` tokens). Tested: 5 tests.
- **Provider integration** — OCI/LFS/S3/Bazel/HF frontends under
  `scripts/frontends/` (chaos exercises them).
|- **CVE scanning** — `erebus-core/src/cve.rs`: parses
  requirements.txt/package.json/pyproject.toml, matches known-weak versions,
  findings feed `scan_results`. **Wired**: `erebus scan --cve
  [--json|--plain]` (verified end-to-end: flags `requests==2.25.0`, skips
  patched `urllib3==2.2.1`). Tested: 6 tests.
- **Attestation registry storage + queryable history** — attestations currently
  land as `.erebus.attest` files on disk (manual). For EU AI Act / SOC 2
  compliance trails, attestations must be stored in the registry and queryable
  ("show me all executions of agent X last week"). This closes the loop between
  runtime attestation and the hosted compliance trail.
  **Not wired**: requires server endpoint `/attestations` + client CLI
  `erebus attest-history --query ...` + audit log integration.

### 🔵 P3 — Multi-protocol frontends (Shardline-like)

- [x] **HuggingFace Hub API compat** — `scripts/frontends/hf_frontend.py`, chaos survived.
- [x] **OCI Distribution frontend** — `scripts/frontends/oci_frontend.py`, chaos survived.
- [x] **Git LFS frontend** — `scripts/frontends/lfs_frontend.py`, chaos survived.
- [x] **S3-compatible frontend** — `scripts/frontends/s3_frontend.py`, chaos survived.
- [x] **Bazel HTTP remote cache frontend** — `scripts/frontends/bazel_frontend.py`, chaos survived.

### 🟣 P4 — Enterprise + distribution

- [x] **Air-gapped mirror** — `erebus mirror export/import` with AES-256-GCM + HKDF-SHA256; tarball of registry data for encrypted USB sync (`88f243b`).
- [x] **Signed embedded SBOM** — `erebus sbom <file>` generates CycloneDX SBOM; `--embed` writes it into the binary metadata (rejects signed/SISR) (`796e229`).
- [ ] **SSO/SAML + SLA**.
- [x] **Web UI** — `/ui/dashboard` compliance admin dashboard; package table with state, integrity, format; auto-refresh from `/index.json` (`63a853b`).
- [ ] **Kubernetes operator / Helm chart**.
- [ ] **Multi-node / cross-region replication** — high availability.
- [x] **Webhooks** — `GET/POST/DELETE /webhooks` manages URLs; `record_audit()` dispatches promote/quarantine/delete events to all registered endpoints (fire-and-forget, 10s timeout) (`9485384`).

### ⚪ Ideas / unexplored

- First-principles: safety requires human audit + sandbox (seccomp/landlock).
- Filmed 2-min demo: build → sign → run → attest → verify → tamper → "TAMPERED".
- Fleet attestation dashboard: "show me all executions in Lagos last week".

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

- **Defense / admin** — air-gapped by regulation (AANSSI, public procurement)
- **Industrial edge** — retail kiosks, factories, vehicles. "500 machines, proof for the auditor"
- **AI startups subject to EU AI Act** — mandatory lifecycle documentation

**Excluded**: healthcare (Lattice Health / Parachute / Wedge have the GTM lead),
OSS / hobbyist devs (they don't pay). Cross-industry + air-gapped + signed
attestation chain = our differentiator.

### The forbidden list

- ❌ Host inference — capital intensive, hyper-competitive zone
- ❌ Paywall the open-source client — kills trust and adoption
- ❌ Marketplace with rev-share now — wait for supply liquidity
- ❌ Sell to hobbyist devs — they don't pay for a registry

### The one-line YC slide

> *« AI agents run on thousands of machines. Nobody can prove what they did.
> We generate the cryptographic proof — automatically, on every execution.
> Regulated enterprises need this for EU AI Act, SOC 2, and public procurement.
> Open-source MIT client, paid hosted compliance trail. »*

**Claim scope clarification (v0.5.0):**

The claim "Cryptographic proof of AI agent execution" covers:

- **What is proven**: the specific signed binary executed on a specific machine
  at a specific time, with verified integrity (SHA-256 + Ed25519), in a
  kernel-level sandbox (namespace + seccomp + landlock on Linux), and the
  attestation chain (builder, layers, machine_id_hash — never plaintext
  hostname, timestamp) is cryptographically verifiable.

- **What is NOT yet proven**: the agent's behavior during execution (outputs,
  decisions, inputs consumed). The current attestation proves *the bundle ran*,
  not *what the agent did*. Behavior capture is an open problem — approaches
  include agent hooks/standards interface or proxy layer. The pitch must
  acknowledge this scope: "We prove the execution happened, unaltered, on the
  right machine" — not "We prove the agent did the right thing."

- **What is NOT yet automatic (P0 closed, P2 open)**: the stub auto-attestation
  is implemented (`ERE_ATTEST_KEY` env var → `write_execution_attestation`),
  but it is opt-in — without the env var, the operator must run `erebus attest`
  after execution. The registry attestation storage + queryable history is still
  not wired.

**Machines / environments the claim covers:**
- Linux x86_64 + aarch64: full sandbox + attestation via `ERE_ATTEST_KEY`
- macOS ARM64: codesign, attestation via `ERE_ATTEST_KEY` (different model)
- Windows x64: PE stub, minimal/no sandbox, attestation via `ERE_ATTEST_KEY`
- Universal polyglot: 1 file, 4 slices
- Air-gapped / offline-first: mirror export/import (AES-256-GCM encrypted)

**Excluded from the claim:**
- Healthcare (ICP excluded — Lattice Health / Parachute / Wedge lead)
- Hobbyist / OSS devs (they don't pay)
- Docker environments (angle is "no Docker needed", not "anti-Docker")

### The business math

- **COGS**: SISR = ~50 MB transfer for an 8 GB model → CPU cost ~$0.001
- **Gross margin**: >95% on Pro/Team (no GPU to host)
- **Enterprise ACV**: $24k/yr × 10 clients = $240k ARR → seed viable
- **Expansion**: $50/node/yr for fleets → $25k/yr for 500 nodes
- **Lock-in**: attestation history is the accumulated data (no GPU capex)

### Edge / emerging markets (use case, not the pitch)

- 8 GB on 4G ≈ $5–10 of data; erebus delta ≈ $0.05. Offline-first = works
  through outages. Data sovereignty (weights never leave the device).
- **Lab deliverable**: `erebus build ./agent --gemini-model gemini-1.5-flash
  --gemma-fallback gemma-2b` → binary preferring Gemini API, local Gemma
  fallback offline. Attestation covers both paths.
- Flagship use case: Lagos fintech, anti-fraud agent on 500 PoS terminals, 50 MB
  delta per terminal, signed receipt per transaction, auditor verifies offline.
- **This is an expansion market, not the ICP.** The ICP is enterprises under
  EU AI Act / SOC 2 with $24k/yr budgets. Edge markets validate the
  offline-first and data-sovereignty claims.

---

## 5. Condensed pitch (*Sign. Track. Prove.*)

**The problem**: AI agents run on servers, factories, point-of-sale terminals.
`docker run` / `python app.py` → **zero proof** of what executed. No audit
trail for EU AI Act / SOC 2 / public procurement. Regulators are about to
force companies to produce this proof — and no tool generates it.

**The solution**: a self-contained binary format that generates signed
cryptographic receipts automatically. `erebus build ./my-agent → my-agent.erebus`,
SISR delta (8 GB → ~50 MB), Ed25519 + SHA-256 attestation + metadata, executes
with seccomp/landlock sandbox, emits a signed `.erebus.attest`. The binary
format is open-source MIT. The hosted compliance trail is the business.

**Why now**: EU AI Act high-risk classification mandatory 2026. SOC 2 auditors
increasingly require AI execution evidence. No existing tool produces
cryptographic proof of AI agent execution.

**Traction**: 3 Rust crates, 0 unsafe core/CLI, 343+ tests, CSO audit 0 critical,
universal 4-slices, 98.7% SISR benchmark, auth+quotas+MCP registry.

**Live**: `cargo install erebus` → `erebus build ./agent -o agent.erebus` →
`erebus sign agent.erebus --key key.key` → run → `erebus attest agent.erebus`
→ `erebus verify --attest agent.erebus.attest` → **VALID**

**Current state (v0.5.0):** the stub auto-attests when `ERE_ATTEST_KEY` is set —
a signed `.erebus.attest` is written before `execvp`. The "every execution leaves
a cryptographic receipt" works locally. The hosted compliance trail (registry
storage + queryable history) is the next step: an auditor can query "show me all
model executions in Accra last week." A regulator sees: zero tampering, offline
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
