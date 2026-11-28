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
| 4 | **With what, producing what** — for a served model, one receipt per inference call with the SHA-256 of the request and response bodies; for a batch run, the launch arguments, piped stdin, stdout/stderr digests and exit code (capture on Linux isolation ≥ 2 and macOS) | `execution.input_hash`, `execution.stdin_hash`, `execution.output_hash`, `execution.exit_code`, `execution.request` |
| 5 | **That the trail is intact** — no receipt was deleted, reordered or edited afterwards | `execution.prev_attestation_hash` chain (`verify-attest --chain`) contradicted by the public log if anything changes |

In one sentence: a flight recorder for AI agents. It gives non-repudiation of
what was executed and tamper evidence for the record of it.

## What a receipt does not establish

| Claim | Why not | What covers it instead |
|---|---|---|
| The computation was *faithful*: output really is `f(input, weights)` | Proving this needs hardware enclaves (TEE attestation) or zkML, 100–1000× the cost of the inference; nobody runs it on production LLMs | Roadmap option: run inside a confidential VM and embed the TEE quote in the receipt. Not planned before a customer asks. |
| The agent did the *right* thing — correct, safe, within policy | That is a judgement about semantics, made *before* deployment by evaluations and guardrails. erebus records what happened; it does not grade it. | Your eval suite; the receipt then proves the graded version is the one that ran. |
| The *plaintext* of inputs and outputs | Receipts carry digests, not content. The operator keeps the data; the digest proves that what they hand the auditor is what was hashed at run time. | The self-hosted trust center can hide receipts under a logical retention policy, but does not purge their bytes; `erebus audit` bundles receipts + evidence. |
| A host with root compromised | The machine key is a software key in `~/.local/share/erebus/machine/machine.key` (0600). Root can copy it. | TPM2-bound key and quote (roadmap, optional per fleet). |
| That **every** run was captured | A receipt proves a run happened; an operator can choose not to route traffic through erebus. | Signed launch policy requiring a verified receipt for the exact artifact, attested gateway (`erebus serve --attest-key`), independent traffic/receipt monitor, heartbeat receipts and `COVERAGE.json` in every pack — see [Coverage is not completeness](#coverage-is-not-completeness). |
| The RFC 3161 token is cryptographically valid | erebus parses the TSTInfo structurally: the imprint must be `messageImprint`, and the displayed time is that TSTInfo's `genTime` (never the unsigned JSON hint) | `openssl ts -verify` against the TSA chain, documented in the spec |
| Compliance with a given regulation | Mapping receipts to EU AI Act record-keeping, SOC 2 or ISO 42001 is the compliance team's work | erebus gives that team evidence instead of screenshots |

## Coverage is not completeness

Every evidence pack now carries `COVERAGE.json`. It is derived from the
signed receipts in the trail and re-derived by `erebus verify-evidence`; a
packed copy that disagrees with the receipts is rejected. It reports:

- gateway-attested inference calls (`execution.request`);
- signed liveness ticks, their sequence range and the call deltas they sign;
- launcher-attested executions with no gateway request — **runs outside the
  gateway**, listed with their attested time;
- gaps: a missing heartbeat sequence, a call count that disagrees with the
  signed deltas, or calls left after the last tick.

`complete: true` means none of those gaps were found in the receipts examined.
It does **not** mean every run was captured. An operator who never routes an
agent through erebus leaves no signed trace for this report to count: the
report can see a run that produced a receipt outside the gateway, not traffic
that produced no receipt at all.

`erebus serve --attest-key` also writes a separate NDJSON traffic journal
before it signs each receipt. `erebus monitor --traffic-log … --trail …`
re-verifies the signed chain, then matches every journal entry to one receipt
by its signed request digest. It flags both a call with no receipt and a
receipt with no journal entry, and exits 2 when either appears. The monitor is
a separate command reading a separate journal, so a receipt-write failure is
visible; the journal and the receipts are still written by the same gateway
process, and traffic that never reached that gateway is invisible to both.
Do not present an evidence pack as proof of completeness.

## Launch policy: only attested artifacts run

A bundle can carry a `launch_policy` with `require_receipt: true`. The policy
lives in signed bundle metadata, so stripping it invalidates the signature.
`erebus policy check --trusted-dir …` and the launcher's embedded check refuse
to start unless:

- the bundle signature verifies against the trust root;
- at least one receipt in `<bundle>.attest.d` verifies against that trust root;
- that receipt names the exact bytes of this bundle (the whole trail is
  hash-chained and verified).

An unsigned bundle, an empty or foreign trail, and a doctored receipt all fail
closed. This gates *which artifact may run*; it does not make the launcher emit
a receipt on every execution. A run still needs the attested gateway or the
Python SDK to produce evidence, which is why coverage and the traffic monitor
matter.

## Python SDK receipts

The Python SDK signs JCS(canonical arguments) and JCS(canonical return value)
with the operator key, writes a spec 2.0 DSSE/JCS trail, and is verified by the
same `verify-attest --chain`. It does not bind a `.erebus` bundle or add a
machine co-signature, and a process that skips the decorator produces no
receipt. Use it for adoption without repackaging; use the launcher or attested
gateway when capture must be enforced outside the agent process.

## Self-hosted trust center status

The self-hosted trust center MVP is a product surface on the stdlib registry,
not a hosted service. It stores receipts under projects that pin operator
public keys, issues project API keys, and exposes search, status, share links
and evidence export. A receipt is labelled `verified` only when all three
checks re-run from the stored bytes: the DSSE/JCS spec 2.x signature under a
pinned key, the project chain link, and Merkle inclusion under a checkpoint
signed by the pinned log key. `missing` means no stored/logged receipt;
`failed` means one of those checks did not pass.

The hosted trust center is **not shipped** and remains the paid surface. The
self-hosted MVP does not map receipts to controls, physically purge receipts, or
claim that every execution was captured. Its retention policy hides receipts from
trust-center views after a server-side `ingested_at` window; legal hold overrides
expiry and the proof bytes stay intact. It accepts receipts that an agent or
gateway actually posted; the separate completeness story is the attested gateway,
signed launch policy, heartbeat receipts, `COVERAGE.json`, `erebus monitor` and
their shared limitation described above. See
[Self-hosted trust center (MVP)](../guides/self-hosted-trust-center.md).

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
exists, is complete, and could not have been altered. Proving the computation
itself would need TEE attestation or zkML at 100–1000× the cost of inference.
That is outside this product's boundary.

## The three questions every buyer asks

1. **Who needs this now?** Teams that deploy agents on machines they do not
   fully control and must answer to someone who does not trust them: defense
   and public administration (air-gapped by regulation), industrial edge,
   AI vendors selling into regulated buyers.
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

## If the agent lies

> We do not judge the agent. We make it impossible to lie about what it did.
> Certificate Transparency made it impossible to issue a certificate in secret.
