# Positioning

## Who needs it

An **AI operator** that runs agents on machines it does not fully control —
customer sites, edge fleets, kiosks, factories, vehicles, air-gapped
networks — and must **prove to an auditor** what ran, where, when, and that
the record was not edited afterwards.

| Segment | Why they need evidence, not logs |
|---|---|
| Defense and public administration | air-gapped by regulation; verification must work without calling a vendor; supply-chain traceability (SBOM, signatures) is already required |
| Industrial edge and vehicles | agents on hardware in the field; software update traceability (UNECE R156) |
| AI companies under the EU AI Act | high-risk systems must log events automatically (Art. 12) and keep those logs (Art. 19, 26) |

Out of scope for now: healthcare, and hobbyist developers.

## The category

**Execution provenance for AI agents.** Build provenance (Sigstore, SLSA,
in-toto) answers "who built this artifact from which source". erebus answers
the next question — "did *that* artifact run, on which machine, when, with
what" — using the same standards, so a technical partner recognises it and
a verifier can use `cosign` instead of trusting our code. See
[Comparison](../comparison.md).

## Why now

- The EU AI Act's record-keeping obligations for high-risk systems phase in
  over 2026–2027, and auditors are asking how logs are protected.
- Agents increasingly run outside the vendor's own cloud (on-prem, edge,
  customer VPCs), where the vendor's dashboards are not evidence.
- The standards to do it properly (DSSE, in-toto, transparency logs,
  RFC 3161) are mature and have tooling auditors can run themselves.

## Why the launcher

A receipt is only as good as the place it is produced. erebus signs at the
launcher: it verifies the bundle, starts the agent, and records the run, so
there is no step where the operator could substitute other code and keep a
clean record. The packaging (one sandboxed binary) exists to make that
possible on any Linux host, without a daemon or root.

## What erebus is not

- **Not a tracing or observability tool** — it records digests, not content.
- **Not proof that the output is correct** — see
  [What erebus proves](./proof.md).
- **Not a replacement for Docker or Kubernetes** — it can run inside them.
- **Not an inference host** — we never run your models on our servers.

## Business model

MIT client and server, forever. Paid: the hosted, anchored proof trail,
fleet features and air-gapped enterprise support. Details in the
[ROADMAP](https://github.com/Tednoob17/erebus/blob/main/ROADMAP.md) §6.
