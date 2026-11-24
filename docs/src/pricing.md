# Pricing

Client **and** server are MIT, forever. Anyone can run their own registry and
verify anything offline. What you pay for is the **hosted trust center** and
the enterprise operation around it.

These are hypotheses to validate with design partners, not settled prices.

| Tier | Price hypothesis | Includes |
|---|---|---|
| Free | €0 | public packages, local receipts, self-hosted registry |
| Team | $500–2k/mo | hosted trust center, private receipts, verification links, evidence packs, RBAC |
| Enterprise | $25k–100k/yr | air-gapped mirror + offline verifier, SSO, SLA, retention, compliance reports, external audit support |
| Enterprise+ | per protected agent/node | fleet identity, coverage monitoring, full history |

The first milestone is one paid pilot, not a pricing page. A pilot should test
whether the buyer pays for **evidence a customer or auditor accepts**, not
whether they like the CLI.

Who it is for: AI vendors selling agents into regulated enterprises — defense
and public administration (air-gapped by regulation), industrial edge (kiosks,
factories, vehicles), financial services, and AI startups selling into
regulated buyers. The buyer is usually the CISO, compliance lead or CTO at the
vendor; the economic buyer is the regulated customer or auditor. Not for us:
hosting inference, paywalling the client, healthcare (for now).

Why this is not a feature of your observability or agent platform: a tool the
operator runs cannot, by construction, produce evidence the operator does not
control. Traces in Datadog, LangSmith or an in-house store answer "what
happened?" *to the operator*; a receipt anchored in a neutral, externally
timestamped log answers it *to the auditor*. The launcher is simply the one
point the operator cannot bypass to get that signature.

Why this is defensible while being open source: a transparency log is worth
its **accumulated, externally timestamped history**. A fork can copy the code;
it cannot re-create three years of anchored checkpoints, and a customer's
auditors already trust the log key their receipts point at. Same dynamic as
Certificate Transparency and Sigstore's Rekor.
