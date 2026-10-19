# erebus

> **The proof layer for AI execution.**

**erebus** is the launcher that emits a signed, externally anchored receipt
of every execution — verifiable offline with erebus or stock `cosign`.

The receipt proves this version ran, on this machine, at this time, and the
trail was not rewritten. `verify-attest --response-body` checks those bytes
and re-derived tool calls. It does not prove the model computed them or that
the answer is right.

Each receipt (`.erebus.attest`, [spec 2.0](./spec/attestation.md): DSSE
envelope over an in-toto statement) states which exact code and weights ran,
on which enrolled machine, when, and with which input and output digests. It
is signed by the operator, co-signed by the machine, hash-chained to the
previous receipt, and logged in a Merkle transparency log whose checkpoints
are timestamped by an independent RFC 3161 authority.

```bash
erebus keygen --key-dir keys                            # operator key
erebus enroll --registry $ERE_REGISTRY --token-file token   # once per host
erebus build ./my-agent -o agent.erebus && erebus sign agent.erebus --key keys/<fp>.key

ERE_ATTEST_KEY=keys/<fp>.key ./agent.erebus --task nightly  # run → signed receipt
erebus serve agent.erebus --attest-key keys/<fp>.key --push # or: one receipt per inference call

erebus verify-attest agent.erebus.attest --bundle agent.erebus --strict --proof --log-key $REG
erebus evidence export agent.erebus --log-key $REG -o evidence.zip   # hand it to the auditor
erebus verify-evidence evidence.zip --bundle agent.erebus --operator-key <fp> --log-key $REG
```

Where to go next:

- [The problem](./concepts/problem.md) — the auditor's question erebus answers.
- [What erebus proves — and what it does not](./concepts/proof.md) — the
  honest boundary.
- [Auditing an erebus trail](./guides/audit.md) — for the person receiving
  the evidence.
- [Execution attestation — spec 2.0](./spec/attestation.md) — byte formats.

## What happens, and who does it

| Step | What happens | Who |
|---|---|---|
| `build` / `sign` | app, runtime, libraries and weights in one sandboxed binary; Ed25519 signature over SHA-256(payload ‖ metadata ‖ footer), anti-downgrade | developer |
| run / `serve --attest-key` | the launcher verifies the bundle, then signs a receipt: artifact hashes, `rootfs_root`, arguments, stdout/stderr digests and `exit_code` (or request/response body digests per inference call), previous receipt hash; co-signed by the enrolled machine key | automatic, on every run |
| `--push` | receipt published to the registry's transparency log; inclusion proof, signed checkpoint and RFC 3161 token stored beside it | automatic, or `attest --push` |
| `verify-attest` | one receipt or a whole trail: `--chain`, `--proof`, `--strict` — offline | anyone |
| `evidence export` / `verify-evidence` | one zip with receipts, proofs, TSA tokens and keys; verified offline against pinned keys | operator → auditor |

## How it runs

The receipt is only worth something if it is produced where the code runs,
by something the operator cannot silently bypass. That is why erebus is also
a launcher:

- **Single binary** — `chmod +x && ./agent.erebus`; no daemon, no root.
  Runtimes: Python and native binaries.
- **Integrity at every launch** — SHA-256 over payload ‖ metadata, Ed25519
  against trusted keys, fail-cold; warm starts re-check the rootfs Merkle
  root.
- **Sandbox** — user namespaces, seccomp and Landlock on Linux.
- **Model serving** — `erebus serve` exposes an OpenAI-compatible API in
  front of the bundled engine (GGUF via llama.cpp) and writes one receipt per
  call, streaming relayed unchanged.
- **Chaos-tested** — the full proof chain and adversarial harnesses
  (SIGKILL, tampering, registry faults, cold-start storms) run in CI on every
  commit.

Advanced and optional: universal multi-platform binaries, SISR delta
updates, `Agentfile.yaml` declarative builds. They are documented in the
Architecture and Guides sections and are not needed for the proof chain.

## Status

The P0 proof chain is replayed in CI on every commit (`proof.yml`). Evidence
export exists. T2 is not done. There are no production customers.

The receipt proves this version ran, on this machine, at this time, and the
trail was not rewritten. `verify-attest --response-body` checks those bytes
and re-derived tool calls. It does not prove the model computed them or that
the answer is right.

## Get started

```bash
git clone https://github.com/Encapsul/erebus.git && cd erebus
cargo build --release
./target/release/erebus doctor
```

Then follow the [Quickstart](./guides/quickstart.md).
