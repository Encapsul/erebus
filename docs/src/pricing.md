# Pricing

Client **and** server are MIT, forever. Anyone can run their own registry and
verify anything offline. The verifier and the auditor kit stay free. The paid
scope today is deploying that evidence path inside one perimeter and handing
the result to a buyer's auditor. The hosted trust center is a later tier and is
not shipped.

Prices below are indicative; a deployment is quoted per perimeter.

| Tier | Indicative price | Includes |
|---|---|---|
| Free | €0 | public packages, local receipts, self-hosted registry, evidence export, `auditor/verify_pack.py` |
| Air-Gapped Evidence Deployment | **$25k/yr** | one deployment inside one perimeter (one agent family): self-hosted trust center, logical retention, auditor handoff, existing registry auth; SSO/SLA scoped separately. Fixed annual invoice or PO; no seat count or usage meter |
| Team, hosted and not shipped | $1.5k/mo billed annually | hosted trust center, private receipts, verification links, evidence packs, RBAC |
| Enterprise+ | per protected agent/node | fleet identity, coverage monitoring, full history; not priced yet |

Verification stays free. Paywalling the verifier or the auditor kit would break
the trust claim. We do not charge per receipt or per token. Value does not
scale with tokens, and per-receipt pricing would reward under-capture, the
exact audit objection we exist to close.

**Pilot.** $12k fixed, 14 days, credited in full against the first $25k year
if the deployment follows within 30 days. One
real agent inside the buyer's perimeter. Deliverables: one evidence zip with
out-of-band pinned keys, a `verify_pack.py` run, an explicit coverage statement,
the buyer's written evidence checklist, and a readout with receipts/day,
verification latency and bytes of evidence per call. The Node SDK and
LangChain.js handler ship; custom framework work is separate. Not included in
the pilot fee: hosted SaaS, control mapping or any written auditor confirmation.

Who it is for: AI vendors selling agents into regulated enterprises, including
defense and public administration (air-gapped by regulation), industrial edge
(kiosks, factories, vehicles) and financial services. The buyer is usually the
CISO, compliance lead or CTO at the vendor; the economic buyer is the regulated
customer or auditor. Not for us: hosting inference, paywalling the client,
healthcare (for now).

An observability or agent platform cannot answer the audit question on its own.
A tool the operator runs cannot, by construction, produce evidence the operator
does not control. Traces in Datadog, LangSmith or an in-house store answer "what
happened?" *to the operator*. A receipt anchored in a neutral, externally
timestamped log answers it *to the auditor*. The launcher is the point where
the operator cannot bypass the signature.

Open source and the log. A fork can copy the code, but each deployment's
receipts point at that deployment's own anchored log key. The commercial scope
is the deployment, the auditor handoff and the evidence pack, not a claim that
a competitor cannot run the same verifier. That mirrors Certificate
Transparency and Sigstore's Rekor: the code is public, the value is in the
record buyers already rely on.
