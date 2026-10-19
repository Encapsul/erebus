# Pricing

Client **and** server are MIT, forever. Anyone can run their own registry and
verify anything offline. What you pay for is the **hosted, anchored history**:

| Tier | Includes |
|---|---|
| Free | public packages, local receipts, self-hosted registry |
| Pro · $29/mo | private packages, hosted transparency log, anchored checkpoints |
| Team · $99/mo | + RBAC, audit log, evidence packs, webhooks |
| Enterprise · $24k/yr | air-gapped mirror + offline verifier, SSO, SLA, compliance reports |
| Enterprise+ · $50/node/yr | per-machine identity at fleet scale, fleet dashboard, full history |

Who it is for: teams that must show an auditor which version ran, on which
machine, at what time — defense and public administration (air-gapped by
regulation), industrial edge (kiosks, factories, vehicles), AI startups
selling into regulated buyers. The buyer is usually the compliance or security
function; the user is the platform team that ships the agent. Not for us:
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
