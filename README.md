# erebus

[![CI](https://img.shields.io/github/actions/workflow/status/Encapsul/erebus/ci.yml?branch=main&label=build)](https://github.com/Encapsul/erebus/actions/workflows/ci.yml)
[![Proof chain](https://img.shields.io/github/actions/workflow/status/Encapsul/erebus/proof.yml?branch=main&label=proof%20chain)](https://github.com/Encapsul/erebus/actions/workflows/proof.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.6.3-green.svg)](https://github.com/Encapsul/erebus/releases)
[![Attestation](https://img.shields.io/badge/receipts-DSSE%20%2B%20in--toto%20%2B%20cosign-blueviolet.svg)](docs/src/spec/attestation.md)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Encapsul/erebus/pulls)

**erebus is the launcher that emits a signed, externally anchored receipt of
every execution, verifiable offline with `erebus` or stock `cosign`.**

The receipt proves this version ran, on this machine, at this time, and the
trail was not rewritten. `verify-attest --response-body` checks those bytes
and re-derived tool calls; `--expected-output-hash` pins a deterministic
tool's result digest. It does not prove the model computed them or that the
answer is right.

```bash
cosign verify-blob-attestation \
  --key examples/verify/operator.pem \
  --signature examples/verify/agent.dsse.json \
  --type https://erebus.dev/attestation/execution/v2 \
  --insecure-ignore-tlog examples/verify/agent.erebus
#  Verified OK
```

[`examples/verify/operator.pem`](examples/verify/operator.pem) is the public
key. [`examples/verify/agent.dsse.json`](examples/verify/agent.dsse.json) is
the envelope for [`examples/verify/agent.erebus`](examples/verify/agent.erebus).
`scripts/yc_demo.sh` emits the same envelope on a Linux host (stub, local
registry, cosign). The command checks the signature over this bundle; it does
not check that a model computed the output.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Encapsul/erebus/main/scripts/install.sh | bash
erebus doctor
```

---

Signed at the launcher — the only point the operator controls — the receipt
names the exact bundle and weights, the enrolled machine, and a Merkle
transparency log time (RFC 3161). Open-source MIT client and server; the paid
product is the hosted, anchored proof trail.

## What an auditor gets

Today, "what did the agent do?" is answered with application logs the operator
can edit, or with a tracing SaaS the operator controls. erebus answers it with
evidence that neither the operator, nor the machine, nor erebus itself can
silently rewrite:

| Question | Application logs | Tracing / observability SaaS | erebus receipt |
|---|---|---|---|
| Which exact code and weights ran? | ❌ | ❌ | ✅ bundle + payload SHA-256, rootfs Merkle root, signed |
| What went in, what came out? | text, editable | yes, in the vendor's DB | ✅ per inference call: request and response body digests, plus every tool call the model returned (name, call id, arguments digest); per batch run: arguments, piped stdin, stdout/stderr digests, exit code |
| Which machine? | hostname string | agent metadata | ✅ per-host key co-signs; certificate names the owner |
| Can the operator edit it after the fact? | yes | yes (their account) | ❌ hash chain + Merkle transparency log + RFC 3161 timestamp |
| Can I verify it without trusting the vendor? | — | ❌ | ✅ offline, with public keys; or with `cosign verify-blob-attestation` |
| Does it survive the vendor disappearing? | — | ❌ | ✅ proof files are self-contained |

## Prove what ran — in 60 seconds

```bash
erebus keygen --key-dir keys                      # operator key (+ <fp>.pem for cosign)
erebus enroll --registry $ERE_REGISTRY --token-file token # once per host: machine key, certified
erebus build ./agent -o agent.erebus && erebus sign agent.erebus --key keys/<fp>.key

ERE_ATTEST_KEY=keys/<fp>.key ./agent.erebus --task nightly # run → agent.erebus.attest (+ trail)
erebus verify-attest agent.erebus.attest --bundle agent.erebus --strict --registry-key $REG
#  OK: attestation verified (key: …)      format: spec 2.0 (DSSE envelope)
#  OK: machine sha256:… — enrolled by alice at https://registry (2026-09-17T…)

erebus attest agent.erebus --key keys/<fp>.key --push --envelope agent.dsse.json
erebus verify-attest agent.erebus.attest --proof --log-key $REG   # offline, forever
#  OK: transparency log — leaf #41 of 42 … anchor: RFC 3161 token from freetsa.org

cosign verify-blob-attestation --key keys/<fp>.pem --signature agent.dsse.json \
  --type https://erebus.dev/attestation/execution/v2 --insecure-ignore-tlog agent.erebus
#  Verified OK
```

Serving a model instead of running a batch agent? `erebus serve agent.erebus
--attest-key ops.key --push --registry $ERE_REGISTRY --token-file token`
exposes an OpenAI-compatible API and writes **one receipt per inference call**
(request and response bodies hashed, streaming relayed unchanged) to
`agent.erebus.attest.d/`, then publishes it and stores a verified inclusion
proof beside it. Missing proofs are retried at the next start;
`erebus verify-attest --chain` audits the whole local trail.

Driving any OpenAI-compatible or Anthropic HTTP API from the CLI?

```bash
erebus agent run --provider openai-compat --base-url http://127.0.0.1:11434 \
  --model llama3.2 --task "Summarize the logs" --attest-key ops.key \
  --mcp-stdio '["python3","tools/server.py"]' --allow-mcp --stream \
  --encapsulate --response-body /tmp/last.json
# Streaming display is unsigned; the receipt hashes the assembled final body.
# Execution proven (signed receipt). Task success is a separate layer —
# tests, human approve, or golden checks — not the crypto claim of the receipt.

# One-command local demo (fake LLM + fake MCP):
#   bash examples/agent/demo.sh
```

Handing it to an auditor is one file:

```bash
erebus evidence export agent.erebus --log-key $REG -o evidence.zip
erebus verify-evidence evidence.zip --bundle agent.erebus \
  --operator-key <fp> --log-key $REG                       # offline, no erebus account
#  OK: evidence pack verified (erebus-evidence/1)
#    receipts: 42, hash-chained, head sha256:…
```

The pack holds the receipts, inclusion proofs, signed checkpoints, RFC 3161
responses with the exact checkpoint bytes they cover (`openssl ts -verify`
passes on the pilot's freetsa.org tokens), DSSE envelopes (for `cosign`) and
only the public keys that signed them — which the auditor pins, obtained out
of band. Editing, deleting or adding any file, a key other than the pinned
ones, or another bundle is refused. Walkthrough:
[Auditing an erebus trail](docs/src/guides/audit.md).

What a receipt proves, layer by layer ([spec](docs/src/spec/attestation.md)):

| Layer | Proves | Signed by |
|---|---|---|
| in-toto statement | bundle + payload digests, provenance, `input_hash`/`output_hash`/`exit_code`, `tool_calls` (served calls), `rootfs_root`, `prev_attestation_hash` | — |
| DSSE envelope (JCS canonical) | the statement comes from the **operator key** | operator Ed25519 |
| Machine co-signature + certificate | it was produced **on an enrolled host** owned by `<owner>` | machine key, registry key |
| Transparency-log proof | it was published at leaf *i* of a signed Merkle tree, timestamped by a TSA | registry log key, RFC 3161 TSA |
| Local trail | receipts are append-only; editing one breaks every later hash | operator key |

Every value a verifier prints is read from the **signed** statement, never from
the human-readable copies. Legacy 1.x receipts stay verifiable.

The boundary is [What erebus proves — and what it does not](docs/src/concepts/proof.md).
Pricing for the hosted trail is [in the book](docs/src/pricing.md).

## Status — what the CI proves, nothing more

The **P0 proof chain is complete** (2026-09-17): hardened verifier, hash-chained
trail, attesting proxy, warm-cache re-verification, Merkle transparency log
with RFC 3161 anchoring, machine identity, standard DSSE/in-toto envelope with
cosign interop. 650+ Rust tests plus a stdlib Python battery (49 checks,
including SIGKILL during concurrent publishes → restart → every acknowledged
receipt still proves into the new tree head).

The **proof chain badge** above is the [`proof.yml`](.github/workflows/proof.yml)
workflow: on every commit and every day, a fresh Linux runner builds erebus
from source and runs the entire demo (`scripts/yc_demo.sh` — build, sign,
enroll, execute with the sandbox on, DSSE receipt, tamper refusals,
transparency log, offline `--strict --proof`, `cosign … Verified OK`, four
chaos harnesses) plus the transparency-log battery and the extreme chaos
battery (native C agent, malformed inputs, 12 concurrent agents). Green means
every one of those checks passed *today*, not once on a laptop.

**No production customers. T2 is not complete.**

---

## The launcher underneath

The receipts are only as good as the thing that produces them, so erebus is
also the runtime: it packages an agent — code, runtime, dependencies, model
weights, engine configuration — into a single self-contained, sandboxed
binary that verifies itself before it runs.

### Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/Encapsul/erebus/main/scripts/install.sh | bash
erebus doctor

cd your-app && erebus build . -o myapp.erebus
./myapp.erebus                       # run it like any executable
```

Serve a bundled LLM as an OpenAI-compatible endpoint and chat with it:

```bash
erebus build . --embed-model models/model.gguf -o agent.erebus
erebus serve agent.erebus --port 8080        # llama-server / vLLM / … launched for you
erebus chat agent.erebus                     # or talk to it in the terminal
erebus chat agent.erebus --web --port 8080   # or from the browser (embedded UI)
```

### Build — declaratively

```yaml
# Agentfile.yaml — CLI flags override this file
model:
  path: models/model.gguf     # embedded as a ModelLayer (SISR-aware chunking)
  ngl: auto                   # auto | off | <layers>
build:
  entrypoint: [python3, app.py]
  seccomp: true
  health_port: 8000
  env:
    LLAMA_CLI: /app/bin/llama-cli
```

```bash
erebus build . -o agent.erebus            # Agentfile picked up automatically
erebus build . --universal -o agent.erebus  # → 4 platform slices in one file
```

Legacy `.erebus.toml` still works. Precedence: **CLI > Agentfile > detection**.
One `--universal` file carries **4 native platform slices** (linux-x64,
linux-arm64, macos-arm64, windows-x64) behind a POSIX-shell polyglot loader —
the same 59 MB artifact runs natively on all four
([validated](benchmarks/universal.md) on real Linux, qemu-arm64 and Windows
under Wine).

### Run anywhere

The stub verifies its own SHA-256, extracts into a content-addressed cache,
records a Merkle manifest of the rootfs (`rootfs.merkle`, re-checked on every
warm start — any drift triggers re-extraction and the root is signed into the
receipt), exports GPU facts (`ERE_GPU`, `ERE_VRAM_MB`, `ERE_NGL`) and execs the
entrypoint inside Linux namespaces + seccomp/Landlock. GPU offload is
auto-tuned at launch: `nvidia-smi` probe → ROCm `/dev/kfd` → Metal; pins
always win (`--ngl off|N`).

### Serve OpenAI-compatible

```bash
erebus serve agent.erebus --port 8080 [--ngl auto] [--ctx-size 4096] [--web] [--attest-key ops.key]
```

erebus resolves the engine from the model format and launches it for you:

| Bundled artifacts | Format | Engine launched |
|---|---|---|
| `*.gguf` | GGUF | `llama-server` (static, golden path) |
| `*.safetensors` (incl. GPTQ/AWQ quant) | HF | vLLM (`python3 -m vllm…api_server`) |
| `*.onnx` | ONNX | vLLM ONNX backend |
| `*.engine` / `*.plan` | TensorRT-LLM | `trtllm-serve` |
| MLX weights + config | MLX | `mlx_lm.server` |

Missing engine on the target? If `ERE_REGISTRY` points at your registry,
`serve` transparently downloads `<engine>-<platform>.pack.tar.gz`, verifies its
SHA-256 sidecar and caches it — no llama.cpp install needed. Offline hosts can
pre-seed it with `erebus layer push llama-server.tar.gz --name runtime/llama-server`.
Measured on CPU: TinyLlama Q4_K_M cold-start < 45 s, warm completions ≈ 5 s —
full numbers in [benchmarks/serve.md](benchmarks/serve.md).

### Your own registry — packages and transparency log

```bash
python3 scripts/registry_server.py --dir ~/erebus-registry --host 0.0.0.0 --port 8787 \
  --tsa-url https://freetsa.org/tsr --anchor-every 100
export ERE_REGISTRY=http://your-vps:8787
erebus publish agent.erebus       # upload (multipart, optional bearer token)
erebus pull agent-agent           # streamed download, SHA-256 verified against index
erebus attest agent.erebus --push # receipt → Merkle log, proof stored next to it
```

Stdlib-only Python, no dependencies: `scripts/registry_server.py` plus its
proof-core package `scripts/erebus_registry/` (Ed25519, Merkle tree, RFC 3161,
transparency log — byte formats pinned by tests on both the Python and Rust
sides). Packages, accounts and quotas (HTTP 402 when exceeded, never silent
throttling), private packages, machine enrollment (`/machines/enroll`), and a
**SQLite Merkle transparency log** (RFC 6962) with Ed25519-signed checkpoints,
O(log n) inclusion/consistency proofs (`/log/*`) and RFC 3161 anchoring. Hardened against traversal, bad filenames,
tampered indexes; chaos-tested — concurrent same-name uploads leave one atomic
winner, replace-during-read never serves truncated blobs, SIGKILL mid-publish
loses no acknowledged receipt ([battery](benchmarks/security.md)).

### Update without re-shipping gigabytes

SISR (Self-Incremental Sovereign Reconstruction) splits payloads with
content-defined chunking; updates transfer only changed chunks. Signed delta
manifests verify fail-cold at boot.

## Command reference

| Command | Description |
|---------|-------------|
| `erebus attest / verify-attest` | Spec 2.0 execution receipts (DSSE + in-toto, JCS); `--envelope` for cosign, `--push` / `--proof` for the transparency log, `--strict` for machine identity, `--chain` for trails, `--response-body` / `--request-body` / `--expected-output-hash` for byte binding |
| `erebus enroll` | Per-machine Ed25519 key + registry certificate; every receipt from this host is co-signed |
| `erebus evidence export / verify-evidence` | One zip for the auditor: trail, proofs, TSA tokens, keys; verified offline |
| `erebus attest-tool http / stdio` | Put an HTTP tool or MCP server behind a signing boundary; `verify-attest --chain … --tool-trail DIR --require-tool-execution` proves every model call was executed and its real result relayed |
| `erebus attest-history` | Query your receipts on a registry (`--query bundle=…,until=…`) |
| `erebus audit` | Signed compliance report aggregating receipts, SBOM and integrity facts |
| `erebus keygen/sign/verify/trust` | Ed25519 signing workflow (`keygen` also writes a PEM for cosign/openssl) |
| `erebus build <dir>` | Package an app dir (`--universal`, `--embed-model`, `--ngl`, `--sign`, `--encrypt`, `--enable-sisr`, `--target`) |
| `erebus run <file>` | Execute a bundle (namespace isolation, health gate) |
| `erebus serve <file>` | OpenAI-compatible HTTP API (`--attest-key`: signed receipt per call; `--push`: registry proof per call) |
| `erebus agent run` / `agent build` | Provider-agnostic HTTP agent (`openai-compat` / `anthropic`); MCP stdio/HTTP tools (`--mcp`, `--mcp-stdio`, `--allow-mcp`); `--stream` (unsigned display, attested assembled body); `--encapsulate` / `agent build` packages the task into a `.erebus` subject. Execution proven; task success is a separate layer |
| `erebus chat <file>` | Terminal TUI chat; `--web` serves the embedded browser UI |
| `erebus pull / publish` | Registry download (integrity-checked, cached) / upload |
| `erebus swap <file> <path> --from <new>` | Replace a file inside an existing bundle (hot-swap) |
| `erebus inspect <file>` | Metadata, slice tables, JSON output |
| `erebus layer push/list` | Manage shared runtime packs & models (local CAS) |
| `erebus dashboard` | Interactive TUI: SISR benchmarks, cache status |
| `erebus doctor / scan / env / clean / selftest / upgrade / completion / man` | Ops & tooling |

## Binary format

```
[stub][payload][metadata][footer]
```

- **Stub** — static launcher per OS (musl ELF / Mach-O / PE32+): reads itself,
  verifies SHA-256, mmap-lazy-loads the payload, extracts, sandboxes, execs.
- **Payload** — zstd tar (or squashfs) of app + runtime + weights.
- **Metadata** — JSON: runtime, entrypoint, layers (runtime/model/tool/config),
  capabilities, env, crypto block.
- **Footer** — magic `0xBEEF_CAFE`, version flags, integrity digest.
  v2 plain · v3 signed · v4 encrypted · v5 squashfs.

Universal polyglot files prepend a 32 KiB `#!/bin/sh` loader plus a slice table;
each slice is a complete native bundle for its OS/arch.

## Supported runtimes & targets

| Runtime | Detection | Use case |
|---|---|---|
| Python | `requirements.txt`, `pyproject.toml`, … | FastAPI/Flask agents, orchestration, tools |
| Binary | ELF/executable present | llama.cpp engines, Go/Rust servers |

Cross-compiling the launcher stub uses [`cargo zigbuild`](https://github.com/rust-cross/cargo-zigbuild)
(zig as linker). Any host builds any target; universal builds need nothing else.

## Configuration

`Agentfile.yaml` (preferred) or legacy `.erebus.toml`:

```toml
[package]
version = "1.0.0"
author = "You"

[build]
isolation = "sandbox"
seccomp = true
env_file = ".env"
embed_model = "models/model.gguf"
ngl = "auto"
health_port = 8000
```

## Security model

- **Execution receipts** (spec 2.0): DSSE envelope over the JCS-canonical
  in-toto statement, operator + machine co-signature, hash-chained trail,
  Merkle transparency log with signed checkpoints and RFC 3161 anchoring;
  verifiers read only signed fields and refuse `TAMPERED` documents
  ([spec](docs/src/spec/attestation.md), [threat notes](docs/src/spec/attestation.md#8-threat-notes))
- **Ed25519 signatures**, fail-cold verification against `~/.erebus/trusted-keys/`
  (CVE-2023-48022 mitigated; ed25519-dalek ≥ 2.1 with `zeroize`)
- **SHA-256 integrity** over payload ‖ metadata at every launch; warm-cache
  rootfs re-verified against a Merkle manifest (`rootfs.merkle`)
- **`--encrypt` is obfuscation only** — the AES-256-GCM key lives in the file's
  metadata by design; use signing for authenticity. Mutually exclusive with SISR.
- **Isolation**: Linux namespaces + seccomp/Landlock; macOS App Sandbox;
  Windows process isolation. Secrets never baked silently (`.env` rejected unless
  explicit); keys written `0600` atomically; secrets zeroized on drop
  ([audit](benchmarks/security.md)).
- Known limits, stated plainly: the machine key is a software key (TPM2 quote
  is roadmap, optional); Rekor upload is roadmap; the TSA token is checked
  structurally by erebus and cryptographically by `openssl ts -verify`.
- `cargo audit`: clean (RC 0).

## Benchmarks

Reproducible numbers with exact commands live in [`benchmarks/`](benchmarks/):
cold start, warm latency, cross-build times, one-file-four-platforms proof,
crypto chaos properties, and two adversarial harnesses whose latest verdicts are
**SURVIVED** (30 corruptions + 10 SIGKILLs on encrypted bundles; 22 checks across
registry/pull/serve).

## Build from source

```bash
git clone https://github.com/Encapsul/erebus.git && cd erebus
cargo build --release          # CLI at target/release/erebus
cargo test --workspace         # 650+ tests (+ scripts/test_transparency_log.py, 49 checks)
```

| Crate | Purpose |
|-------|---------|
| `erebus-core` | Attestation (`attest`, `attest_log`, `dsse`, `jcs`, `merkle`, `log_proof`, `machine`, `rootfs_merkle`), format, compression, detection, encryption, inference-engine resolution, SISR, CAS |
| `erebus-stub` | Self-extracting launcher (ELF / Mach-O / PE32+) — the only crate with `unsafe` |
| `erebus-cli` | Everything you type: attest, verify-attest, enroll, build, serve, … |

Before contributing: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test --workspace`. Style: [CODE_STYLE.md](CODE_STYLE.md); ANSSI-Rust rules in
[RULES.md](RULES.md). Product priorities: [ROADMAP.md](ROADMAP.md).

## License

MIT — see [LICENSE](LICENSE).
