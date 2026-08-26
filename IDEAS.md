# Ideas & Brainstorming (DRAFT — NOT ROADMAP)

## 🎯 SINGLE CLEAR POSITIONING

**ICP: Développeurs d'agents IA locaux open-source qui distribuent leurs agents à des collègues/utilisateurs finaux sans Docker, sans installation de runtime.**

Ce qu'erebus résout pour cet ICP:
- Un agent IA = code Python (FastAPI/Flask) + modèle GGUF + serveur d'inférence (llama.cpp) + tools + config
- erebus build ./mon-agent --embed-interpreter python3 --enable-sisr -o mon-agent.erebus
- Utilisateur final: ./mon-agent.erebus → extraction + démarrage en 2s
- Mise à jour mineure (prompt change, tool ajouté): delta SISR 95% plus petit que redownload complet

Pourquoi maintenant:
- Modèles GGUF: 4-70 GB → téléchargement = goulot
- llamafile (25k★): C++ only, pas Python API, pas delta, pas sandbox
- Écosystème agents IA en explosion (LlamaIndex, LangGraph, Open Interpreter) mais pas de packaging standard

## 🛑 DÉPRÉCIÉ — NE PAS POURSUIVRE

- **Position B (Compiler --to OCI/AppImage/WASM)**: Déprécié. Single-file ELF est le format natif. OCI = Docker world, on ne le bat pas sur son terrain.
- **Position C (Bun for polyglot apps)**: Trop large, pas d'ICP. Bun existe déjà.
- **Desktop packaging (AppImage/Snap/Flatpak)**: Hors scope. AppImage/Snap font déjà ça.
- **Docker killer narrative**: Docker reste pour orchestration. On ne le "tue" pas.

## 🔬 USE CASES SECONDAIRES (traction, pas pitch principal)

| Use Case | ICP | Viabilité | Effort démo |
|----------|-----|-----------|-------------|
| Tools MLOps/data science internes | Data scientists, MLOps petites équipes | Haute (ICP clair, pas de GGUF) | Basse |
| Edge AI deployment | Fabricants petits dispositifs AI | Moyenne (marché réel, sales-intensive) | Moyenne |
| Agents autonomes workflows | Startups agents autonomes | Moyenne (segment en évolution) | Moyenne |
| Éducation / environnements reproductibles | Formateurs, bootcamps, doc open-source | Basse-Moyenne | Basse |
| Safe execution code non-fiable | Security researchers, équipes CI | Basse (niche) | Basse |

## 📋 PRODUCT IMPROVEMENTS (backlog)

1. **SISR + encrypt incompatibilité** — Documentée clairement: `--encrypt` et `--enable-sisr` mutuellement exclusifs. Option 2 (résoudre) = Phase 3+.
2. **Demo agent IA réel** — examples/ avec FastAPI + modèle GGUF (1-2GB démo) + tools.
3. **Benchmark SISR réel** — Modèle 4-10GB, mesurer: extraction, taille artifact, delta 1% → 95% économie.
4. **Layer metadata fix** — pipeline.rs:233-234 `--publish` génère `layers: []` — à réparer.
5. **Agentfile.yaml** — Config déclarative unique source de vérité (comme ollama Modelfile).
6. **GPU auto-detect** — Stub détecte `/dev/nvidia*`, `libcuda.so`, Metal, ROCm.
7. **Built-in Chat UI** — Terminal TUI + Web UI statique embarquée.

## 💰 BUSINESS MODEL (défini)

**OSS Tool + SaaS Registry**
- OSS Core (MIT): `erebus build/sign/verify/swap/layer` — gratuit, adoption dev
- SaaS Registry: Push/pull artifacts, SISR delta hosting, signature management, private repos, analytics
- Pricing: Pro $7/user/mois, Team $29/team/mois, Enterprise custom
- Justification: SISR nécessite serveur de chunks pour deltas distants → naturellement SaaS

## 🎯 YC PREPARATION CHECKLIST

- [ ] ICP unique défini et défendu (FAIT: Agent IA local)
- [ ] Demo agent IA réel fonctionnel (EN COURS)
- [ ] 3 utilisateurs réels avec noms + métriques (TODO)
- [ ] Layer metadata pour --publish réparé (TODO)
- [ ] Benchmark SISR avec modèle 4-10GB prouvant 95% (TODO)
- [ ] Blog post / post communauté avec démo (TODO)
- [ ] Documentation guides étape par étape (TODO)
- [ ] Application YC 4 questions répondues (TODO)


---

# Google Africa Applied AI Lab — candidature

> Deadline : **31 août 2026**. Source : https://labs.google/aifuturesfund/africaailab
> Verdict : OUI postuler, avec recadrage Afrique + Gemma du pitch.

## Ce qu'ils cherchent
1. Usage **matériel** de Gemini/Gemma/Veo (exigence explicite FAQ #9)
2. Impact **africain** (« uniquely African challenges ») — pas l'EU AI Act
3. Thèmes : travail, connaissance, **développement logiciel**, créativité, divertissement
4. Fondateurs full-time, démo day présentiel à Accra début décembre

## Fit erebus (recadré)

| Atout erebus | Angle africain |
|---|---|
| SISR : 8GB via ~50MB delta | Data plans chers + connectivité faible |
| Binaire unique offline | Déploiement offline-first, zones mal desservies |
| Attestation signée | Souveraineté données fintechs/banques/gouvernements |
| serve/chat inférence locale | **Gemma embarqué** = agent IA sans cloud ni GPU |

Pitch : *« Erebus déploie des agents IA propulsés par Gemma en Afrique comme
des binaires uniques vérifiables — offline, à faible bande passante, avec
preuve cryptographique de ce qui a tourné. Pendant le lab : intégration
Gemini API + Gemma on-device comme runtime packagé de première classe. »*

## Réponses formulaire

- **Company name** : Erebus (à confirmer : entité Cerco ?)
- **Website** : ⚠️ REQUIS — déployer landing / GH Pages docs
- **HQ Location** : Lomé, Togo
- **Field** : Future of Software Development
- **One sentence** :
  > Erebus turns any AI application into a single self-verifying binary — letting African companies deploy Gemma-powered agents offline, update them over low-bandwidth networks with 100× smaller deltas, and prove cryptographically exactly what code ran, where, and when.
- **Stage** : Pre-Launch · **ARR** : $0 · **MAU** : 0–1,000 · **Raised** : $0–100k
- **Open to raising from Google** : Yes

## TODO avant soumission
1. [ ] Pitch deck 10 slides (narratif Afrique + Gemma) — REQUIS
2. [ ] Site web en ligne — REQUIS
3. [ ] Démo CLI filmée (build → sign → attest → run agent Gemma) — gros plus
4. [ ] Confirmer entité légale + statut full-time
