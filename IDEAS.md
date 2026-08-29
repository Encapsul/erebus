# Ideas & Brainstorming (DRAFT — NOT ROADMAP)

## 🎯 SINGLE CLEAR POSITIONING

> **Le vrai produit n'est pas le packaging — c'est la chaîne de traçabilité signée.**
> Le packaging est la démo. La preuve est le business.

**ICP: Entreprises régulées et flottes air-gapped** (défense, industrie,
edge, kiosques) qui déploient des agents IA en production et doivent
**prouver à un auditeur** ce qui a exécuté, sur quelle machine, à quelle
date, et que rien n'a été altéré. Cross-industrie — Santé et devs OSS
exclus (voir ROADMAP.md / BUSINESS.md).

Pitch une ligne : *« Sign. Track. Prove. — Ship AI agents with verifiable
attestation. »*

Ce qu'erebus résout pour cet ICP:
- Chaque `.erebus` + `.erebus.attest` forme une **preuve cryptographique
  vérifiable offline** de ce qui a exécuté (attestation signée + SBOM +
  chaîne d'audit) — exigé par l'EU AI Act high-risk, SOC 2, ISO 27001,
  marchés publics
- Déploiement air-gapped en un seul binaire autonome: extraction + démarrage
  en 2s, sans runtime à installer
- Mise à jour de flotte (prompt change, tool ajouté, modèle) : delta SISR
  ~95% plus petit que redownload complet, sur réseaux à faible bande passante
- Conformité déléguée: le format binaire génère la preuve en arrière-plan —
  gratuit en open source, payant en hébergé avec conformité et audit trail

Pourquoi maintenant:
- L'EU AI Act high-risk (SG n°3) exige une **documentation du cycle de vie**
  des modèles — aucune chaîne d'attestation d'exécution signée n'existe encore
- Modèles GGUF: 4-70 GB → téléchargement = goulot pour les flottes air-gapped
- llamafile (25k★): C++ only, pas d'attestation signée, pas de delta, pas d'audit
- Écosystème agents IA en explosion mais pas de standard de traçabilité
  signée de ce qui a tourné en production

## 🛑 DÉPRÉCIÉ — NE PAS POURSUIVRE

- **Position B (Compiler --to OCI/AppImage/WASM)**: Déprécié. Single-file ELF est le format natif. OCI = Docker world, on ne le bat pas sur son terrain.
- **Position C (Bun for polyglot apps)**: Trop large, pas d'ICP. Bun existe déjà.
- **Desktop packaging (AppImage/Snap/Flatpak)**: Hors scope. AppImage/Snap font déjà ça.
- **Docker killer narrative**: Docker reste pour orchestration. On ne le "tue" pas.

## 🔬 USE CASES SECONDAIRES (traction, pas pitch principal)

| Use Case | ICP | Viabilité | Effort démo |
|----------|-----|-----------|-------------|
| Edge AI deployment | Fabricants dispositifs AI / flottes | Haute (marché réel, sales-intensive, air-gapped) | Moyenne |
| Flottes industrielles | Usines, véhicules, kiosques (preuve à l'auditeur) | Haute (50$/nœud/an) | Moyenne |
| Startups IA sous EU AI Act | Modèles high-risk, doc cycle de vie obligatoire | Moyenne-Haute | Basse |
| Tools MLOps/data science internes | Équipes MLOps régulées | Moyenne (ICP clair, pas de GGUF) | Basse |

## 📋 PRODUCT IMPROVEMENTS (backlog)

1. **SISR + encrypt incompatibilité** — Documentée clairement: `--encrypt` et `--enable-sisr` mutuellement exclusifs. Option 2 (résoudre) = Phase 3+.
2. **Demo agent IA réel** — examples/ avec FastAPI + modèle GGUF (1-2GB démo) + tools.
3. **Benchmark SISR réel** — Modèle 4-10GB, mesurer: extraction, taille artifact, delta 1% → 95% économie.
4. ~~**Layer metadata fix**~~ — Résolu/obsolète: `publish.rs` n'embarque plus de layers (registry stocke owner/private), et les layers ont un vrai hash/size depuis le fix SBOM/attest.
5. **Agentfile.yaml** — Config déclarative unique source de vérité (comme ollama Modelfile).
6. **GPU auto-detect** — Stub détecte `/dev/nvidia*`, `libcuda.so`, Metal, ROCm.
7. **Built-in Chat UI** — Terminal TUI + Web UI statique embarquée.

## 💰 BUSINESS MODEL (défini — cf. BUSINESS.md)

**OSS Tool + SaaS conformité** (monétise le service hébergé, jamais le logiciel)
- OSS Core (MIT): `erebus build/sign/verify/attest/audit` — gratuit, adoption
- SaaS: Registry privé, SISR delta hosting, SBOM signé, attestations,
  audit trail téléchargeable, rapport de conformité automatisé
- Pricing: Pro $29/mois, Team $99/mois, Enterprise $24k/an, Enterprise+
  $50/nœud/an (flottes >50 nœuds)
- Justification: la chaîne d'attestation + le registre grossissant = lock-in
  naturel (l'historique de conformité est la donnée accumulée)

## 🎯 YC PREPARATION CHECKLIST

- [ ] ICP unique défini et défendu (FAIT: Enterprise régulée / flottes air-gapped)
- [ ] Demo agent IA réel fonctionnel (EN COURS)
- [ ] 3 utilisateurs réels avec noms + métriques (TODO)
- [ ] Layer metadata pour --publish réparé (TODO)
- [ ] Benchmark SISR prouvé (FAIT: modèle GGUF réel 613MB → 1% = 6.27MB delta, 99% — voir benchmarks/sisr-model.md; reste: scale-up 4-10GB)
- [ ] Blog post / post communauté avec démo (TODO)
- [ ] Documentation guides étape par étape (TODO)
- [ ] Application YC 4 questions répondues (TODO)
