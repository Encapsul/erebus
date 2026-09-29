# Roadmap

> **Source of truth:** [`ROADMAP.md`](https://github.com/Tednoob17/erebus/blob/main/ROADMAP.md)
> at the repository root: product state, audit findings, priorities and
> business model. This page is a summary and may lag behind it.

## Priorities are strict

| Priority | Theme | State |
|---|---|---|
| **P0** | Make the proof true: hardened verifier, hash-chained trail, attesting proxy (`serve --attest-key`), warm-cache re-verification, Merkle transparency log with RFC 3161 anchoring, machine identity, DSSE / in-toto with `cosign` interop | complete (2026-09-17) |
| **P1** | Make the claims continuously proven: demo and chaos batteries in CI (`proof.yml`), evidence export, one proof-first story, registry hygiene, macOS validated on Apple Silicon | in progress |
| **P2** | Differentiators: `erebus policy` (fail-closed rules enforced by the launcher), EU AI Act / SOC 2 evidence mapping, fleet dashboard, Windows sandbox | after P1 |

Out of scope: TEE remote attestation, zkML, hosting inference.

## Frozen until P0/P1 are done

Distribution features that already exist and keep passing their tests but
receive no new work: billing, mirror/replicate, Hugging Face import, layer
swap, TUI dashboard and chat, protocol frontends, webhooks, SSO, Helm chart.
A change to a frozen surface must name the P0/P1 item it unblocks.

## Traction plan

1. **T1** — the whole proof chain re-proven in CI on every commit. Done.
2. **T2** — internal pilot: a real agent behind `serve --attest-key --push`,
   several enrolled machines, a public TSA-anchored registry, zero
   verification failures. Running.
3. **T3** — a design partner in the target segments (defense /
   administration, industrial edge).
4. **T4** — a third party verifies a trail with only public keys and
   `verify-evidence` / `cosign`, in writing.
