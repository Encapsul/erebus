# Positioning

## Customer profile

Un **opérateur d'IA** qui déploie des agents sur des **flottes de machines**
(edge, serveurs, kiosques, véhicules) et qui doit **prouver à un auditeur**
ce qui a exécuté, où, quand, et que le code n'a pas été altéré.

Il est soumis à des contraintes réglementaires (EU AI Act, SOC 2, ISO 27001,
marchés publics défense/santé) et n'a **aucun outil** qui produit cette
preuve automatiquement aujourd'hui.

## Le segment : conformité IA + flottes

| | Docker | Ollama | llamafile | **erebus** |
|---|---|---|---|---|
| Exécution signée | ❌ | ❌ | ❌ | **✅ Ed25519 + attestation** |
| Delta updates | Layer cache | Store layers | ❌ | **SISR content-defined** |
| Sandbox | Namespace | ❌ | ❌ | **seccomp + Landlock** |
| Audit trail | ❌ | ❌ | ❌ | **✅ attestation chain** |
| Portable format | Image OCI | Store pull | Single file | **Single .erebus file** |
| Offline verification | ❌ (daemon) | ❌ (daemon) | Partial | **✅ fully offline** |

### Qui a ce problème aujourd'hui?

1. **Hôpitaux / intégrateurs santé** : déploient des agents IA de diagnostic
   sur des postes médicaux. La HAS/ANSM exige la preuve que le logiciel
   exécuté correspond à la version validée. Aucun outil ne fournit cette
   preuve automatiquement.

2. **Intégrateurs défense / administration** : agents IA sur des systèmes
   air-gapped. L'AANSSI exige la traçabilité complète de la chaîne
   d'approvisionnement logicielle (SBOM + signatures + preuve d'exécution).

3. **Fabricants automobiles / industrie** : agents IA embarqués dans des
   véhicules ou des usines. La réglementation UNECE WP.29 impose la
   traçabilité des mises à jour logicielles.

4. **Startups IA soumises à l'EU AI Act** : tout système d'IA "high-risk"
   doit documenter son cycle de vie complet — modèle, code, dépendances,
   exécutions. Personne ne construit cet outil aujourd'hui.

## Pourquoi maintenant?

- **EU AI Act entre en vigueur** : obligatoire pour les systèmes high-risk
  d'ici 2026-2027. Les entreprises n'ont aucun outil de traçabilité IA.
- **SOC 2 + ISO 27001** exigent des preuves d'intégrité logicielle.
- **Marchés publics IA** ($4B+ USA, UE en explosion) imposent la chaîne
  de traçabilité du modèle.
- **Modèles GGUF 4-70 GB** : la distribution est le goulot, les deltas
  SISR réduisent le coût de 100×.
- **llamafile (25k★)** et **Ollama (176k★)** n'ont aucune功能 de
  traçabilité ou d'attestation d'exécution.

## Pourquoi erebus?

### Le format comme preuve

Chaque binaire `.erebus` contient :
- Un **SHA-256** du payload et des métadonnées (vérifié à chaque lancement)
- Une **signature Ed25519** (fail-cold, anti-downgrade)
- Un **Merkle tree** des chunks SISR (chaque byte est traçable)

erebus étend cela en générant un **document d'attestation détaché**
(`.erebus.attest`) qui prouve :
- quel bundle a été exécuté (hash)
- sur quel type de machine (OS, arch — jamais le hostname en clair)
- à quelle date (horodatage signé)
- par quel builder (clé publique)

### Against Ollama

Ollama est un daemon avec un store de modèles. Excellent pour le
développement local. Mais :
- Pas de signatures sur les bundles
- Pas d'attestation d'exécution
- Pas de sandbox (le modèle tourne avec les droits de l'utilisateur)
- Pas de delta updates content-defined (layer dedup, pas chunk-level)

### Against llamafile

llamafile = binaire C++ mono-runtime. Excellent pour la portabilité.
Mais :
- Pas de delta updates (fichier entier à chaque mise à jour)
- Pas de sandbox seccomp+Landlock
- Pas de multi-runtime (C++ only)
- Pas d'attestation ni de traçabilité

### Against Docker

Docker est fait pour l'orchestration, pas pour la distribution edge.
erebus = un fichier exécutable, extraction atomique, fonctionne sans
daemon, sans privilèges root, avec attestation d'exécution intégrée.

## Le format

Le format `.erebus` est :
- Un **ELF valide** (Linux) — `chmod +x && ./app.erebus` fonctionne
- Un **payload tar/zstd ou SquashFS** — décompressible avec `tar`
- Des **signatures Ed25519 standards** — vérifiables offline
- Un **rootfs POSIX** — pas de kernel features propriétaires
- Des **attestations détachées** (`.erebus.attest`) — preuve signée

Versions : v2 (plain) → v3 (signed) → v4 (encrypted) → v5 (squashfs).
Backward-compatible. Forward-compatible via attestation détachée.

## Ce que erebus n'est PAS

- **Pas un Docker killer** : Docker reste pour l'orchestration.
- **Pas un package manager** : la registry est optionnelle.
- **Pas un outil de dev local** : Ollama fait mieux pour ça.
- **Pas un hébergeur d'infèrement** : on ne touche pas au GPU côté serveur.
