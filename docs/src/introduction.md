# erebus

> **The trust center for AI agents.**

AI agents run on machines their vendor does not control: customer sites, edge
fleets, factories, vehicles, air-gapped networks. The buyer, auditor or
regulator asks which version ran, where and when, and what it did. Application
logs and tracing dashboards cannot answer that question for the buyer. The
operator can edit them.

erebus signs a receipt for each run. The signed statement binds the bundle and
model-weight digests, the enrolled machine, the time, the input, output and
tool-call digests, and the previous receipt hash. A verifier checks it offline
with `erebus` or stock `cosign`. The verifier needs no account, no network call
to us and no trust in the operator's copy of the record.

The proof chain ships. erebus is also the trust center built on it: the place
where an AI vendor publishes evidence and a regulated buyer verifies it. The
shipped MVP is self-hosted. The hosted service is not shipped.

## What we are building

| Layer | Product surface | What it answers | State |
|---|---|---|---|
| **Capture** | launcher, attested proxy, SDK | which code, model and machine produced this run? | launcher, proxy, Python and Node SDKs, LangChain.js root chains ship |
| **Prove** | receipts, transparency log, evidence pack | can a third party verify it offline? | proof chain ships; self-hosted trust center anchors receipts in it |
| **Consume** | trust center, verification links, support for auditor review | can a buyer or auditor accept a pack without a CLI? | self-hosted MVP and auditor kit ship; hosted SaaS and control mapping do not |

## Who it is for

**AI vendors selling agents into regulated enterprises**: defense, public
administration, critical infrastructure, financial services and industrial
edge. The buyer is the vendor's CISO, compliance lead or CTO. The economic
buyer is the regulated customer or auditor who requires evidence.

The lead wedge is an **on-prem or air-gapped edge** deployment. Defense, public
administration, critical infrastructure and industrial buyers often forbid a
vendor call-home. Their acceptance path must stay inside the perimeter:
self-hosted registry, one evidence zip, keys pinned out of band,
`verify-evidence` or `cosign`, and the [auditor kit](../../auditor/README.md).
Verification needs no erebus account and no hosted service.

Not for: hobbyist developers, inference hosting, or teams that only need
application logs. erebus records digests, not prompts or model outputs.

## Why now

- Agents are moving from chat to actions: tool calls, approvals and data
  access now need a record.
- Enterprise procurement already asks which model version ran, on which
  machine, with what input and output. The vendor's logs are not evidence the
  buyer controls.
- The standards are mature: DSSE, in-toto, Ed25519, Merkle transparency logs,
  RFC 3161 and `cosign` interop.
- The EU AI Act high-risk obligations are staggered (Annex III from December
  2027, Annex I from August 2028). We sell the current procurement and audit
  pain, not a single deadline.
- YC's [Winter 2027 RFS, "AI for the Air-Gapped Economy"](https://www.ycombinator.com/rfs)
  names defense contractors, banks, hospitals and nuclear plants that keep AI
  behind walls with no internet. It calls that market slower to sell but home
  to the largest budgets and most defensible companies. Our offline
  verification path fits that constraint.
  The RFS is a buyer signal, not a request for our crypto primitives.

## What happens, and who does it

| Step | What happens | Who |
|---|---|---|
| `build` / `sign` | app, runtime, libraries and weights in one sandboxed binary; Ed25519 signature over SHA-256(payload ‖ metadata ‖ footer), anti-downgrade | developer |
| run / `serve --attest-key` | the launcher verifies the bundle, then signs a receipt: artifact hashes, `rootfs_root`, arguments, stdout/stderr digests and `exit_code` (or request/response body digests per inference call), previous receipt hash; co-signed by the enrolled machine key | automatic, on every run |
| `--push` | receipt published to the registry's transparency log; inclusion proof, signed checkpoint and RFC 3161 token stored beside it | automatic, or `attest --push` |
| `verify-attest` | one receipt or a whole trail: `--chain`, `--proof`, `--strict` — offline | anyone |
| `evidence export` / `verify-evidence` | one zip with receipts, proofs, TSA tokens and keys; verified offline against pinned keys | operator → auditor |

## How it runs

A receipt is only as good as the place it is produced. erebus signs at the
launcher, after verifying the bundle and before starting the agent.

- **Single binary** — `chmod +x && ./agent.erebus`; no daemon, no root.
  Runtimes: Python and native binaries.
- **Integrity at every launch** — SHA-256 over payload ‖ metadata, Ed25519
  against trusted keys, fail-cold; warm starts re-check the rootfs Merkle
  root.
- **Sandbox** — user namespaces, seccomp and Landlock on Linux.
- **Model serving** — `erebus serve` exposes an OpenAI-compatible API in
  front of the bundled engine (GGUF via llama.cpp) and writes one receipt per
  call, streaming relayed unchanged.
- **HTTP agent** — `erebus agent run` talks OpenAI-compatible or Anthropic
  HTTP (`--base-url` for Ollama, Azure, llama-server, …), MCP tools in the
  loop (`--mcp` / `--mcp-stdio`), optional `--stream` (display unsigned;
  receipt hashes the assembled body), and `--encapsulate` so the receipt
  subject is a task `.erebus` hash.
- **Chaos-tested** — the full proof chain and adversarial harnesses
  (SIGKILL, tampering, registry faults, cold-start storms) run in CI on every
  commit.

Advanced and optional: universal multi-platform binaries, SISR delta
updates, `Agentfile.yaml` declarative builds. They are documented in the
Architecture and Guides sections and are not needed for the proof chain.

## Status, 2026-11-24

- **Proof chain: complete.** Hardened verifier, hash-chained trail, attesting
  proxy, warm-cache re-verification, Merkle transparency log with RFC 3161
  anchoring, machine identity, DSSE/in-toto with `cosign` interop.
- **Evidence export: works.** One zip, offline verification, pinned keys.
- **Auditor kit: ships.** `auditor/verify_pack.py` checks one pack with pinned
  keys, `cosign` and optional TSA tokens. It is tooling, not written third-party
  confirmation.
- **Self-hosted trust center MVP: ships.** Projects, API keys, receipt status,
  search, share links, evidence export and tested backup/restore.
- **Completeness features: ship.** Attested gateway, signed launch policy,
  heartbeat receipts, `COVERAGE.json` and traffic monitor. Pilot proof is
  pending.
- **Internal pilot: running, not complete.** No production customers yet.
- **Hosted trust center: not shipped.** It remains a paid surface.
- **Next proof point:** one design partner with a paid pilot and one external
  auditor verification. The [T4 request brief](../../auditor/T4-request.md) is
  ready; the written confirmation is still missing.

The receipt proves this version ran, on this machine, at this time, and the
trail was not rewritten. It does not prove the model computed the output or
that the answer is right, and it does not prove that every run was captured.
See [What erebus proves — and what it does not](./concepts/proof.md).

## Get started

```bash
curl -fsSL https://raw.githubusercontent.com/Encapsul/erebus/main/scripts/install.sh | bash
erebus doctor
```

Then follow the [Quickstart](./guides/quickstart.md) or run the local agent
demo:

```bash
bash examples/agent/demo.sh
```
