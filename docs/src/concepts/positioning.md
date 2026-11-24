# Positioning

## Who needs it

An **AI vendor selling an agent into a regulated environment** — defense,
public administration, critical infrastructure, financial services, industrial
edge — and the buyer or auditor who must accept the evidence without trusting
the vendor's logs.

| Segment | Why they need evidence, not logs |
|---|---|
| Defense and public administration | air-gapped by regulation; verification must work without calling a vendor; supply-chain traceability (SBOM, signatures) is already required |
| Industrial edge and vehicles | agents on hardware in the field; software update traceability (UNECE R156) |
| AI vendors under procurement | enterprise buyers ask which model/version ran, on which machine, with what input and output; the vendor's dashboard is not evidence the buyer controls |
| Regulated AI under the EU AI Act | high-risk systems must log events automatically (Art. 12) and keep those logs (Art. 19, 26); obligations are staggered to 2027–2028 |

Out of scope for now: healthcare, hobbyist developers and inference hosting.

## The category

**Execution provenance for AI agents**, packaged as a **trust center** for the
buyer. Build provenance (Sigstore, SLSA, in-toto) answers "who built this
artifact from which source". erebus answers the next question — "did *that*
artifact run, on which machine, when, with what" — using the same standards, so
a technical partner recognises it and a verifier can use `cosign` instead of
trusting our code. See [Comparison](../comparison.md).

## Why now

- Agents are moving from chat to actions: tool calls, approvals and data
  access now need a record.
- Enterprise procurement already asks for evidence; the vendor's logs are
  editable and the buyer knows it.
- The standards to do it properly (DSSE, in-toto, transparency logs,
  RFC 3161) are mature and have tooling auditors can run themselves.
- The EU AI Act high-risk obligations are staggered (Annex III from December
  2027, Annex I from August 2028). Sell the current procurement and audit
  pain, not a single deadline.

## Why the launcher

A receipt is only as good as the place it is produced. erebus signs at the
launcher: it verifies the bundle, starts the agent, and records the run, so
there is no step where the operator could substitute other code and keep a
clean record. The packaging (one sandboxed binary) exists to make that
possible on any Linux host, without a daemon or root.

The launcher is the high-assurance path. The attested proxy and SDK exist so a
team can adopt receipts without repackaging its agent; the trust center is
where a buyer verifies them.

## The completeness boundary

A receipt proves a run happened. It does **not** yet prove that every run was
captured: an operator can choose not to route traffic through erebus. This is
the biggest audit objection and is a first-class roadmap item (P0-4). Until it
is closed, the evidence pack must report coverage explicitly; never imply
completeness that the product cannot prove.

## What erebus is not

- **Not a tracing or observability tool** — it records digests, not content.
- **Not proof that the output is correct** — see
  [What erebus proves](./proof.md).
- **Not a replacement for Docker or Kubernetes** — it can run inside them.
- **Not an inference host** — we never run your models on our servers.

## Business model

MIT client and server, forever. Paid: the hosted trust center, anchored proof
trail, fleet features and air-gapped enterprise support. The tiers are on the
[pricing](../pricing.md) page.
