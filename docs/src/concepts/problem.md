# The Problem

## Comment prouver ce qui a exécuté?

Une entreprise déploie un agent IA sur 500 machines de terrain.
L'agent contient : un modèle GGUF (4 GB), un serveur Python (FastAPI),
des outils système, et une configuration.

**La question de l'auditeur :**

> « Prouvez-moi que l'agent exécuté sur la machine #247 le 15 septembre
> correspond exactement à la version que vous avez validée en juillet,
> et qu'aucun code n'a été altéré entre-temps. »

**La réponse aujourd'hui :** aucune. Il n'existe aucun outil qui produit
cette preuve automatiquement.

## Pourquoi les solutions existantes ne suffisent pas

| Outil | Ce qu'il fait | Ce qu'il ne fait PAS |
|---|---|---|
| Docker | Container avec layers signés | Daemon requis, pas d'attestation d'exécution, pas d'air-gap |
| Ollama | Store de modèles avec pull | Pas de signatures, pas de sandbox, pas de traçabilité |
| llamafile | Binaire unique portable | Pas de delta, pas d'audit trail, mono-runtime |
| Git LFS / rsync | Transfert de fichiers | Pas de format d'artefact, pas de signature, pas d'attestation |

Le problème n'est pas le packaging. Le problème est **l'absence de preuve**.

## Le contexte réglementaire

- **EU AI Act** : obligatoire pour les systèmes high-risk d'ici 2026-2027.
  Exige la documentation du cycle de vie complet de l'IA.
- **SOC 2 / ISO 27001** : exigent des preuves d'intégrité logicielle
  et de contrôle d'accès aux déploiements.
- **Marchés publics** (USA, UE) : imposent la SBOM (Software Bill of
  Materials) et la chaîne de traçabilité du modèle.
- **UNECE WP.29** (automobile) : traçabilité obligatoire des mises à jour
  logicielles embarquées.

## L'idée erebus

Un format binaire qui contient tout (runtime + modèle + code + config)
et qui génère **automatiquement** une preuve signée de ce qui a exécuté :

```bash
erebus build ./mon-agent --embed-model model.gguf -o agent.erebus
erebus sign agent.erebus --key keys/<fp>.key
erebus enroll --registry $ERE_REGISTRY --token $TOKEN   # une fois par machine
ERE_ATTEST_KEY=keys/<fp>.key ./agent.erebus < input.json  # → agent.erebus.attest
erebus attest agent.erebus --key keys/<fp>.key --push      # → <reçu>.proof.json
```

L'auditeur reçoit quatre fichiers :
1. `agent.erebus` — le bundle exécutable
2. `agent.erebus.attest` — le reçu signé (spec 2.0 : enveloppe DSSE sur un
   énoncé in-toto, co-signé par la clé machine de l'hôte enrôlé)
3. `agent.erebus.attest.proof.json` — la preuve d'inclusion dans le log de
   transparence du registre (checkpoint signé, jeton RFC 3161)
4. Les clés publiques — opérateur (`<fp>.pub` / `<fp>.pem`) et registre

Vérification offline, sans daemon, sans internet :

```bash
erebus verify agent.erebus --trusted-dir ./trusted
erebus verify-attest agent.erebus.attest --trusted-dir ./trusted \
  --bundle agent.erebus --strict --proof --registry-key <hex>
cosign verify-blob-attestation --key keys/<fp>.pem --signature agent.dsse.json \
  --type https://erebus.dev/attestation/execution/v2 --insecure-ignore-tlog agent.erebus
```

**Zéro installation. Zéro configuration. La preuve est le produit.**
