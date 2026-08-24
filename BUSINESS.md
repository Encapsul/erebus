# BUSINESS.md — Modèle économique erebus

> Décidé le 2026-08-24. Le code client ET serveur restent MIT pour toujours :
> on monétise le **service hébergé**, jamais le logiciel.

## L'insight fondateur

L'avantage structurel n'est pas le packaging — c'est **SISR**. Une mise à jour
de modèle de 8 GB coûte ~50 MB de bande passante via les deltas
content-defined, contre 8 GB chez un concurrent qui stocke bêtement sur S3.
**Notre coût marginal de distribution est ~100× inférieur** : c'est la COGS
protégée qu'on monétise.

## Les tiers

| Tier | Prix | Inclus |
|---|---|---|
| **Free** | 0 € | Packages publics, 20 GB transfert/mois |
| **Solo** | 9 $/mois | 3 packages privés, 500 GB transfert, SISR CDN inclus |
| **Team** | 49 $/mois | Privés illimités, organisations, RBAC, audit logs, webhooks, 2 TB |
| **Enterprise** | 15–50 k$/an | Mirror air-gapped (licence appliance), SSO/SAML, SLA, support |

## L'ICP réel (pas les gamers du llama local)

```
🏭 Edge/offline industriel   kiosques retail, usines, véhicules —
                             « pas d'internet, doit tourner partout »
🏥 Santé / défense / admin   air-gapped par réglementation
📦 Flottes internes          500 machines de terrain à updater sans rsync maison
```

Pitch une ligne : *« Sign once, ship everywhere, update for megabytes —
not gigabytes. »*

## Les interdits

- ❌ Héberger de l'inférence (modèle ollama cloud) — capital intensif, zone
  ultra-concurrentielle, incompatible avec notre stade
- ❌ Paywaller le client ou le serveur — tuerait la confiance ; le moat est
  la distribution, pas le lock-in
- ❌ Marketplace à rev-share maintenant — attendre la liquidité de l'offre

## Le slide YC en une ligne

> *« Docker Hub pour l'IA locale : les modèles pèsent 8 GB, nos mises à jour
> 50 MB, et le fichier tourne partout sans rien installer. Gratuit en open
> source, monétisé en hébergement privé — comme Docker, mais avec une
> technologie de delta qui rend notre coût marginal 100× inférieur. »*
