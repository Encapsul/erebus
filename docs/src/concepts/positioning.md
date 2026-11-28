# Positioning

## Who needs it

An **AI vendor selling an agent into a regulated environment**: defense,
public administration, critical infrastructure, financial services or
industrial edge. The buyer or auditor must accept the evidence without trusting
the vendor's logs.

| Segment | Why they need evidence, not logs |
|---|---|
| Defense and public administration | air-gapped by regulation; verification must work without calling a vendor; supply-chain traceability (SBOM, signatures) is already required |
| Industrial edge and vehicles | agents on hardware in the field; software update traceability (UNECE R156) |
| AI vendors under procurement | enterprise buyers ask which model/version ran, on which machine, with what input and output; the vendor's dashboard is not evidence the buyer controls |
| Regulated AI under the EU AI Act | high-risk systems must log events automatically (Art. 12) and keep those logs (Art. 19, 26); obligations are staggered to 2027–2028 |

Out of scope for now: healthcare, hobbyist developers and inference hosting.

## The wedge: on-prem / air-gapped edge

Lead with the constrained deployment. Several vendors already claim Ed25519,
hash chains, RFC 3161 and offline verification. Those primitives are table
stakes here. Defense, public administration,
critical infrastructure and industrial buyers often forbid a vendor call-home:
the verifier must run inside their perimeter, with no account and no network to
us. Our acceptance path already works that way: self-hosted registry, one
evidence zip, keys pinned out of band, `verify-evidence`, `cosign` and the
[auditor kit](../../../auditor/README.md).

YC's [Winter 2027 RFS, "AI for the Air-Gapped Economy"](https://www.ycombinator.com/rfs)
names defense contractors, banks, hospitals and nuclear plants that keep AI
behind walls with no internet, and says that is slower to sell but where the
largest budgets and most defensible companies are. That is a signal about the
buyer and the deployment. It is not a request for DSSE, Merkle logs or Ed25519.
Sell the buyer's ability to verify locally. Hosted SaaS is not shipped and is
not required for this wedge.

## The category

**Execution provenance for AI agents**, packaged as a **trust center** for the
buyer. Build provenance (Sigstore, SLSA, in-toto) answers who built which
artifact from which source. erebus answers the next question: did that artifact
run, on which machine, when, and with what? It uses the same standards, so a
technical partner recognises them and a verifier can use `cosign` instead of
trusting our code. See [Comparison](../comparison.md).

## Why now

- Agents are moving from chat to actions: tool calls, approvals and data
  access now need a record.
- Enterprise procurement already asks for evidence. The vendor's logs are
  editable and the buyer knows it.
- The standards to do it properly (DSSE, in-toto, transparency logs,
  RFC 3161) are mature and have tooling auditors can run themselves.
- The EU AI Act high-risk obligations are staggered (Annex III from December
  2027, Annex I from August 2028). Sell the current procurement and audit
  pain. A single deadline is not the pitch.

## Why the launcher

A receipt is only as good as the place it is produced. erebus signs at the
launcher: it verifies the bundle, starts the agent, and records the run. There
is no step where the operator could substitute other code and keep a clean
record. The packaging, one sandboxed binary, exists to make that possible on
any Linux host without a daemon or root.

The launcher is the high-assurance path. The attested proxy and SDK let a team
adopt receipts without repackaging its agent. The trust center is where a buyer
verifies them.

## The completeness boundary

A receipt proves a run happened. It does **not** prove that every run was
captured: an operator can choose not to route traffic through erebus. That is
the biggest audit objection. The attested gateway, signed launch policy,
heartbeat receipts, `COVERAGE.json` and traffic monitor ship,
but pilot proof of coverage is still pending. The evidence pack reports
coverage explicitly. Do not imply completeness that the product cannot prove.

## What erebus is not

- **Not a tracing or observability tool.** It records digests, not content.
- **Not proof that the output is correct.** See
  [What erebus proves](./proof.md).
- **Not a replacement for Docker or Kubernetes.** It can run inside them.
- **Not an inference host.** We never run your models on our servers.

## Business model

MIT client and server. For a deployment inside your perimeter or a pilot, see
[Pricing](../pricing.md).
