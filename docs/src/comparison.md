# Comparison

erebus is **execution provenance for AI agents**: the Sigstore / SLSA /
in-toto model — signed statements, DSSE, transparency log, `cosign` interop
— applied to *runs* instead of *builds*, and produced by the launcher that
starts the agent. The table compares categories rather than products; most
teams will use erebus alongside several of them.

| Question an auditor asks | App logs | LLM tracing / observability | Build provenance (Sigstore, SLSA) | TEE attestation | erebus |
|---|---|---|---|---|---|
| Which exact code and weights ran? | ❌ | ❌ | built artifact only | ✅ measured at launch | ✅ bundle, payload and rootfs hashes, signed per run |
| On which machine? | hostname string | agent metadata | ❌ | ✅ hardware identity | ✅ enrolled machine key co-signs, certified by the registry |
| When, provably? | local clock | vendor clock | at build time | at attestation time | ✅ transparency log + RFC 3161 timestamp |
| With what input, producing what output? | text, editable | ✅ in a database | ❌ | ❌ | ✅ digests per run and per inference call |
| Can the operator rewrite it afterwards? | yes | yes (their account) | n/a | n/a | ❌ hash chain, public log, external timestamp |
| Verifiable offline by a third party? | ❌ | ❌ | ✅ | with vendor roots | ✅ `verify-evidence`, `cosign`, `openssl ts` |
| Proves the computation itself was faithful? | ❌ | ❌ | ❌ | partly (code identity, not semantics) | ❌ — see [the boundary](./concepts/proof.md) |
| Special hardware or cloud? | no | no | no | yes | no |

## Where the others are better

- **Observability tools** show *content*: prompts, tool calls, latencies.
  erebus stores digests, not content. Keep your tracing; erebus proves the
  trace refers to what really ran.
- **TEE attestation** measures code identity in hardware, which a software
  key cannot match against a root-compromised host. erebus can carry a TEE
  quote in a receipt later; today its machine key is a software key.
- **Sigstore / Rekor** is a public-good log with a large ecosystem. erebus
  envelopes already verify with `cosign`; Rekor upload is on the roadmap.

## The one-sentence answer

> *"Why not just logs and tracing?"* — Because the party being audited
> controls them. An erebus receipt is signed where the code runs, tied to the
> exact bytes and machine, chained, and anchored outside the operator's reach,
> so a third party can verify it offline.
