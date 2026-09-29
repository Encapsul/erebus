# What erebus proves — and what it does not

This page is the honest boundary of the product. Everything in the README,
the pitch and the sales deck must stay inside it.

## The five facts a receipt establishes

A spec 2.0 receipt ([format](../spec/attestation.md)) lets a verifier who
trusts nobody — not the operator, not the machine, not erebus — establish:

| # | Fact | Evidence in the signed statement |
|---|---|---|
| 1 | **What ran** — exactly this code and these weights, unmodified at launch | `artifact.bundle_hash`, `artifact.payload_hash`, `execution.rootfs_root` (Merkle root of the extracted rootfs, re-checked on every warm start) |
| 2 | **Where** — on a host whose key was enrolled and certified for a named owner | machine co-signature in the DSSE envelope + registry-signed certificate (`erebus enroll`, `verify-attest --strict`) |
| 3 | **When** — at a time nobody can backdate | leaf in a public Merkle transparency log, signed checkpoint, RFC 3161 timestamp from an independent TSA (`verify-attest --proof`) |
| 4 | **With what, producing what** — for a served model, one receipt per inference call with the SHA-256 of the request and response bodies; for a batch run, the launch arguments, stdout/stderr digests and exit code (stdin is not hashed; output capture needs Linux isolation ≥ 2) | `execution.input_hash`, `execution.output_hash`, `execution.exit_code`, `execution.request` |
| 5 | **That the trail is intact** — no receipt was deleted, reordered or edited afterwards | `execution.prev_attestation_hash` chain (`verify-attest --chain`) contradicted by the public log if anything changes |

In one sentence: **a flight recorder for AI agents** — non-repudiation of
what was executed, and tamper evidence for the record of it.

## What a receipt does not establish

| Claim | Why not | What covers it instead |
|---|---|---|
| The computation was *faithful*: output really is `f(input, weights)` | Proving this needs hardware enclaves (TEE attestation) or zkML, 100–1000× the cost of the inference; nobody runs it on production LLMs | Roadmap option: run inside a confidential VM and embed the TEE quote in the receipt. Not planned before a customer asks. |
| The agent did the *right* thing — correct, safe, within policy | That is a judgement about semantics, made *before* deployment by evaluations and guardrails. erebus records what happened; it does not grade it. | Your eval suite; the receipt then proves the graded version is the one that ran. |
| The *plaintext* of inputs and outputs | Receipts carry digests, not content. The operator keeps the data; the digest proves that what they hand the auditor is what was hashed at run time. | Retention is the operator's job; `erebus audit` bundles receipts + evidence. |
| A host with root compromised | The machine key is a software key in `~/.local/share/erebus/machine/machine.key` (0600). Root can copy it. | TPM2-bound key and quote (roadmap, optional per fleet). |
| The RFC 3161 token is cryptographically valid | erebus checks the token structurally (imprint, policy, time) and stores it | `openssl ts -verify` against the TSA chain, documented in the spec |
| Compliance with a given regulation | Mapping receipts to EU AI Act record-keeping, SOC 2 or ISO 42001 is the compliance team's work | erebus gives that team evidence instead of screenshots |

## Why this boundary is the right product, not a shortfall

Every piece of trust infrastructure that actually changed an industry stops
exactly here:

- **Certificate Transparency** does not prove a certificate is legitimate; it
  makes every issuance visible and impossible to erase. That was enough.
- **Sigstore / SLSA** prove who built what from which source, not that the
  code is bug-free.
- A **flight recorder** does not prevent the crash; it makes the investigation
  possible and the account undeniable.
- An **accounting audit trail** does not prove decisions were wise; it proves
  the books were not cooked afterwards.

And the buyer asks for exactly this. High-risk obligations under the EU AI Act
are about record-keeping and traceability (logging, Art. 12; obligations of
providers and deployers, Art. 19 and Art. 26), not about a mathematical proof
of correctness. SOC 2 and ISO 42001 are the same shape: show that the record
exists, is complete, and could not have been altered. Selling level-2 proof
would be selling something nobody requires and nobody can afford.

## The three questions every buyer (and every investor) asks

1. **Who needs this now?** Teams that deploy agents on machines they do not
   fully control and must answer to someone who does not trust them: defense
   and public administration (air-gapped by regulation), industrial edge,
   AI vendors selling into regulated buyers. The answer must be a name, not a
   sector — see the traction plan in `ROADMAP.md` §7.3.
2. **Why now?** Agents are starting to act without a human in the loop, and
   the record-keeping obligations for high-risk AI systems are becoming
   enforceable. Logs the operator can edit were tolerated for chatbots; they
   are not tolerated for systems that act.
3. **Why isn't this a feature of an observability or agent platform?**
   Because a tool operated by the operator cannot, by construction, produce
   evidence the operator does not control. Datadog, LangSmith or an in-house
   trace store answer "what happened?" *to the operator*. A receipt anchored
   in a neutral, externally timestamped log answers it *to the auditor*. The
   neutrality of the log is the product; the launcher is how we get the
   signature at the only point the operator cannot bypass.

## The one-sentence answer to "and if the agent lies?"

> We do not judge the agent. We make it impossible to lie about what it did —
> the way Certificate Transparency made it impossible to issue a certificate
> in secret.
