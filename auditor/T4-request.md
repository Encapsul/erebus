# T4 — engagement brief for an independent verifier

**Status: NOT COMPLETE.** This is the request and the blank answer form. It is
not evidence until a named third party signs and dates it. Do not cite it as
T4 in the README, a YC application or a sales deck before that happens.

## Objective

Get one independent auditor or consultancy to write, on their own letterhead,
whether an erebus evidence pack is sufficient for an engagement where they
must accept evidence about an AI agent run without trusting the vendor's
dashboard.

## What we send the verifier

| Item | Channel | Why |
|---|---|---|
| `evidence.zip` from `erebus evidence export` | file transfer | receipts, inclusion proofs, anchors, DSSE envelopes, public keys |
| The bundle (unless embedded in the zip) | file transfer | the exact bytes the receipts cover |
| Operator public key (64 hex or `sha256:` fingerprint) | contract annex / signed email | trust root, never taken from the zip |
| Log key (64 hex from `GET /log/key`) | registry operator, out of band | second trust root |
| TSA CA chain (optional) | TSA site, pinned by the verifier | needed for `openssl ts -verify` |
| This kit and its output | repo / command log | reproducible offline check |

The verifier runs `python3 auditor/verify_pack.py evidence.zip --bundle … --operator-key … --log-key …` on a machine with no erebus account and no network access to our systems.

## Questions the verifier must answer

1. Did the pack verify offline, with no account and no network call to us?
2. Were both trust roots obtained independently of the pack, and did the pack contain only those keys?
3. Did every receipt's signature, chain link and Merkle inclusion proof check out?
4. What did the `cosign` and `openssl ts` checks add, and what did they not prove?
5. Which artifact would you still require before accepting this as evidence in your engagement?

## Written confirmation — blank form

> Auditor / firm: ______________________________
> Engagement reference: ________________________
> Date: ________________________________________
>
> We received the evidence pack and the out-of-band keys described above. We
> re-ran the checks on our own machine.
>
> Offline verification without an erebus account: ☐ yes ☐ no
> Operator and registry keys pinned out of band: ☐ yes ☐ no
> All receipts verified (signature, chain, inclusion): ☐ yes ☐ no
> `cosign` envelope check: ☐ verified ☐ skipped ☐ failed
> RFC 3161 token check (when CA supplied): ☐ verified ☐ skipped ☐ failed
>
> Conclusion on sufficiency for our engagement:
> ______________________________________________________________________
>
> Required additional artifacts:
> ______________________________________________________________________
>
> Signed: ______________________________  Date: ______________

## How we get there

1. Use the P0-5 design partner first: ask for **their** auditor contact. T4 is
   strongest when the buyer's own auditor accepts the pack.
2. If no partner is ready, approach independent AI-assurance / security
   consultancies with the brief above and a sample pack from the internal
   pilot. Ask for a paid, scoped review — not a testimonial.
3. Record the signed answer in this repository and update `ROADMAP.md`,
   `README.md` and `docs/src/roadmap.md` only then.

The CI proof in `evidence_e2e.rs` shows the kit works offline. It does **not**
replace this written confirmation.
