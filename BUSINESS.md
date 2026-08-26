# BUSINESS.md — Modèle économique erebus

> Décidé le 2026-08-26. Le code client ET serveur restent MIT pour toujours :
> on monétise le **service hébergé**, jamais le logiciel.

## L'insight fondateur (révisé)

Le packaging d'IA est une feature, pas un business. Le vrai produit est la
**preuve cryptographique** de ce qui a exécuté, sur quelle machine, à quelle
date, et que rien n'a été altéré.

Les entreprises réglementées (EU AI Act, SOC 2, ISO 27001, marchés publics)
ont **besoin de cette preuve** et n'ont **aucun outil** qui la produit
aujourd'hui. Notre format binaire `.erebus` génère cette preuve en
arrière-plan — gratuitement en open source, payant en conformité et
audit trail.

**Le moat n'est pas SISR (commoditisé par XetHub/HF) — c'est la chaîne
d'attestation d'exécution** : plus le registre grossit, plus l'historique
de conformité est riche → lock-in naturel.

## Les tiers (révisés)

| Tier | Prix | Inclus |
|---|---|---|
| **Free** | 0 € | Packages publics, 10 GB transfert/mois |
| **Pro** | 29 $/mois | Packages privés illimités, 1 TB SISR CDN, SBOM signé, attestations |
| **Team** | 99 $/mois | TOUT Pro + RBAC, audit log, dashboard conformité, webhooks, 5 TB |
| **Enterprise** | 24 k$/an | Mirror air-gapped, SSO/SAML, SLA, rapport conformité automatisé |
| **Enterprise+** | 50 $/nœud/an | >50 nœuds, attestation par nœud, historique complet |

## L'ICP réel

```
🏥 Santé / défense / admin    air-gapped par réglementation
                              HAS/ANSM, AANSSI, UNECE WP.29
🏭 Edge industriel            kiosques retail, usines, véhicules
                              « 500 machines, preuve à l'auditeur »
📦 Startups IA soumises       EU AI Act high-risk
   à l'EU AI Act              documentation cycle de vie obligatoire
```

Pitch une ligne : *« Sign. Track. Prove. — Ship AI agents with verifiable
attestation. »*

## Les interdits

- ❌ Héberger de l'inférence — capital intensif, zone ultra-concurrentielle
- ❌ Paywaller le client open source — tuerait la confiance et l'adoption
- ❌ Marketplace à rev-share maintenant — attendre la liquidité de l'offre
- ❌ Vendre aux devs hobbyistes — ils ne paient pas pour un registry

## Le slide YC en une ligne (révisé)

> *« Nous fournissons la preuve cryptographique de ce qui a exécuté dans
> chaque agent IA, sur chaque machine, à chaque instant. Les entreprises
> réglementées ont besoin de cette traçabilité pour se conformer à
> l'EU AI Act, SOC 2 et aux marchés publics. Notre format binaire
> génère cette preuve en arrière-plan — gratuitement en open source,
> payant en hébergé avec conformité et audit trail. »*

## Les mathématiques du business

- **COGS** : SISR = ~50 MB transfert pour 8 GB de modèle → coût CPU ~$0.001
- **Marge brute** : >95% sur les tiers Pro/Team (pas de GPU à héberger)
- **ACV Enterprise** : $24k/an × 10 clients = $240k ARR → seed viable
- **Expansion** : $50/nœud/an pour les flottes → $25k/an pour 500 nœuds
- **Lock-in** : l'historique d'attestations est le données accumulée
