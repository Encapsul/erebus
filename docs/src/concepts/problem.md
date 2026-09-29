# The Problem

## "Prove what ran"

A company runs an AI agent on 500 field machines. The agent is a GGUF model,
a Python server, a few tools and a configuration. An auditor asks:

> "Show me that the agent that ran on machine #247 on 15 September was
> exactly the version you validated in July, what it was given and what it
> answered — and that this record was not edited since."

Today the honest answer is a set of application logs and a tracing
dashboard. Both are controlled by the operator being audited: they can be
edited, filtered or regenerated, and neither ties the log line to the exact
bytes that executed or to a specific machine.

## Why the usual tools do not answer it

Each of these is good at what it does; none produces the evidence above on
its own.

| Tool | What it gives | What it does not give |
|---|---|---|
| Application logs | text lines written by the app | a signature, a binding to the executed bytes, protection from the operator |
| LLM tracing / observability (hosted or self-hosted) | rich traces in the vendor's or operator's database | tamper evidence against the account owner; offline verification by a third party |
| Build provenance (Sigstore, SLSA, in-toto) | who built which artifact from which source | anything about *runs*: when, where, with what input |
| Container signing (OCI + cosign) | the image was signed before deployment | that this image is what actually ran on a given host at a given time |
| Tamper-evident log stores | append-only, verifiable storage | what is appended: it records what the application tells it |
| TEE remote attestation | the platform and code measured by hardware | per-run records; it needs specific hardware and cloud support |

erebus reuses the first four's standards (DSSE, in-toto, transparency logs,
`cosign`) and applies them to **executions**, produced by the launcher
itself. See [Comparison](../comparison.md) for the full picture.

## Why it matters now

- **EU AI Act** — high-risk systems must automatically record events over
  their lifetime (Art. 12), and providers and deployers must keep those logs
  (Art. 19, Art. 26); obligations phase in over 2026–2027. erebus gives the
  compliance team evidence for these logs; it is not a certification.
- **SOC 2 / ISO 27001** — auditors ask for evidence of software integrity
  and change control on deployed systems.
- **Public procurement and defense** — air-gapped deployments must be
  verifiable without calling a vendor.
- **Vehicles and industry** — UNECE R156 requires traceability of software
  updates on embedded systems.

## The erebus answer

The auditor receives one file and verifies it without an account or network:

```bash
erebus evidence export agent.erebus --log-key $REG -o evidence.zip   # operator
erebus verify-evidence evidence.zip --bundle agent.erebus \
  --operator-key sha256:<fp> --log-key $REG                          # auditor
```

What that establishes, and its limits, are on
[What erebus proves](./proof.md); the auditor's walkthrough, including
checking the timestamps with `openssl` and the signatures with `cosign`, is
[Auditing an erebus trail](../guides/audit.md).
