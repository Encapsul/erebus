# Roadmap

> **Source of truth:** [`ROADMAP.md`](https://github.com/Encapsul/erebus/blob/main/ROADMAP.md)
> at the repository root. This page is a summary and may lag behind it.

## The product

erebus is the **trust center for AI agents**: a signed, hash-chained,
externally anchored receipt for every agent run, plus the place where an AI
vendor publishes evidence and a regulated buyer verifies it offline.

The proof chain is complete. The next milestone is adoption: one ICP, one
design partner, one paid pilot and a trust-center MVP.

## Priorities are strict

| Priority | Theme | State |
|---|---|---|
| **P0-1** | Activation: install → `erebus demo` → first receipt → verification link in under 5 minutes | next |
| **P0-2** | Trust-center MVP: org, API key, receipt search, public verification link, evidence export | next |
| **P0-3** | Integration without repackaging: attested proxy, Python/Node SDK, MCP, one framework | next |
| **P0-4** | Completeness: attested gateway, signed policy, heartbeat/coverage report, monitor | next |
| **P0-5** | Design partner pilot: 14 days, zero strict failures, one case study, one LOI/paid pilot | next |
| **P0-6** | External verification: an auditor verifies a trail with public keys and `verify-evidence` / `cosign` | next |

The proof chain (P0 from 2026-09-17) is closed and stays green in CI. Do not
reopen it; do not add breadth beside it.

## Frozen until the trust-center milestone is done

`billing`, `mirror`, `replicate`, `hf`, `layer`, `swap`, `dashboard` (TUI),
`chat` (TUI + web UI), `sbom` beyond what `audit` needs, `scan --cve`,
`backup`/`restore`, webhooks, SSO/SAML, K8s Helm chart, protocol frontends,
MCP registry endpoints, waitlist/landing.

Packaging, SISR, universal binaries and model serving are means, not the
product. A change to a frozen surface must name the P0 item it unblocks.

## Traction plan

1. **T1** — the whole proof chain re-proven in CI on every commit. Done.
2. **T2** — internal pilot: a real agent behind `serve --attest-key --push`,
   several enrolled machines, a public TSA-anchored registry, zero
   verification failures. Running, not complete.
3. **T3** — a design partner in the ICP (AI vendor selling into defense /
   administration, industrial edge or financial services) with an LOI or paid
   pilot.
4. **T4** — a third party verifies a trail with only public keys and
   `verify-evidence` / `cosign`, in writing.

## Business model

MIT client and server, forever. Paid: the hosted trust center, anchored proof
trail, fleet features and air-gapped enterprise support. Pricing hypotheses
are on the [Pricing](./pricing.md) page; validate them with the pilot.
