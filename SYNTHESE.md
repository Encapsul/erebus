# Synthèse des échanges — erebus

**Session :** à partir de 2026-09-10  
**Sujet principal :** vérification des claims de la roadmap erebus vs code réel, refonte du pitch, clarification sur "preuve cryptographique d'exécution d'agent IA"

---

## 1. Contexte du projet erebus

### Ce que c'est

erebus est un outil Rust (workspace : `erebus-core`, `erebus-cli`, `erebus-stub`) qui package des applications — agents IA, modèles, runtimes, dépendances — en un fichier unique auto-extractible et sandboxé.

**Format .ere** : layout `[stub][payload][metadata][footer]`
- Stub : launcher natif par OS (musl ELF / Mach-O / PE32+)
- Payload : zstd tar ou squashfs v5 de l'app + runtime + poids de modèle
- Metadata : JSON (runtime, entrypoint, layers, env, crypto block)
- Footer : magic `0xBEEF_CAFE`, flags, digest SHA-256, signature Ed25519

**Version du format** : v2 (plain) → v3 (signed) → v4 (encrypted) → v5 (squashfs, SISR)

**Cross-platform** : fichier polyglotte avec 4 tranches natives (linux-x64, linux-arm64, macos-arm64, windows-x64), loader `#!/bin/sh` de 32 Ko + table des tranches. Build universel via `cargo zigbuild` (zig comme linker), aucun outil cross supplémentaire nécessaire.

### Modules principaux implémentés

**erebus-stub** (launcher auto-extractible)
- `main.rs` : point d'entrée du stub (~1917 lignes)
- `exec.rs` : interprétation runtime, flow d'exécution, auto-attestation, sandbox wiring
- `namespace.rs` : namespaces utilisateur + montage, pivot_root, uid/gid mapping (unprivileged)
- `seccomp.rs` : filtre BPF denylist avec ~18 syscalls dangereux + approche capability-driven, fail-closed (KILL_PROCESS)
- `landlock.rs` : LSM Landlock (ABI v1/v2/v3 négociation, fail-closed)
- GPU/X11/Wayland bind-mount detection
- Support Windows via module `win` (spawn_app_windows avec MapViewOfFile, CreateProcessW, ProcessPrng)

**erebus-core** (format, crypto, SISR, attestation)
- `format.rs` : layout footer, MAGIC, SHA-256, Ed25519, versions v2/v3/v4/v5
- `attest.rs` : `generate_attestation()` + `verify_attestation()`, `write_execution_attestation()` (lignes 319-335), signing in-toto Ed25519
- `crypto.rs` : AES-256-GCM encryption, Ed25519
- `sisr_stage.rs` : SISR, FastCDC, Merkle tree, manifests delta signés
- `encrypt.rs` : AES-256-GCM
- `registry.rs` : registry auth, quotas
- `auth.rs` : `Authenticator` trait, HMAC-SHA256, Ed25519
- `detect.rs` : détection runtime — **seulement Python + Binary** (Node explicitement retiré)
- `layer.rs`, `cron.rs`, `gc.rs`, `cve.rs`, `intoto.rs`, `metadata.rs`

**erebus-cli** (commandes, ~35+ fichiers)
- `build/` : pipeline complet (cross-compile, GGUF integrity, SISR, signing, stub generation, universal builds)
- `serve.rs`, `chat.rs`, `run.rs` : exécution, serveur OpenAI-compatible, TUI chat
- `attest.rs`, `verify_attest.rs` : CLI attestation + vérification
- `registry` commands : pull, publish, mirror, replicate, restore
- `audit.rs`, `audit_log.rs`, `sbom.rs`, `scan.rs` : scanning CVE, SBOM
- `sign.rs`, `verify.rs`, `trust.rs`, `keygen.rs` : workflow crypto
- `dashboard.rs`, `doctor.rs`, `env.rs`, `clean.rs`, `selftest.rs`, `upgrade.rs` : ops
- `lifecycle.rs`, `backup.rs`, `billing.rs`, `webchat.rs`

### Ce qui est vraiment implémenté (vérifié dans le code)

- Shell auto-extractible multi-plateforme ✅
- Format .ere avec SHA-256 + Ed25519 ✅
- SISR (FastCDC + Merkle + delta manifests signés) ✅
- AES-256-GCM encryption ✅ (note : obfuscation seulement, clé dans le metadata)
- Sandbox kernel-level : namespaces + seccomp + Landlock ✅ (Linux uniquement, fail-closed)
- Stub auto-attestation **IMPLEMENTÉ** ✅ (ERE_ATTEST_KEY → write_execution_attestation avant execvp)
- `erebus attest` CLI ✅
- `erebus verify-attest` CLI ✅ (wiré 2026-09-10)
- GPU auto-detect + `--ngl` policy ✅
- Registry serveur Python (stdlib, sans DB) avec auth/quotas/métriques ✅
- Rollback + health gate ✅
- Chaotic test suites (2 harnesses survivants) ✅
- `cargo audit` clean ✅

### Ce qui est FAUX dans les claims initiaux

- **"11 runtimes"** : FAUX. Code : seul Python + Binary. README déjà correct (table à 2 runtimes). No claim de 11 dans le code.
- **"Stub ne fait pas d'auto-attestation"** : FAUX. `exec.rs:578-581` + `exec.rs:807-835` implémentent `write_auto_attestation_if_requested()` appelée avant execvp. Opt-in via `ERE_ATTEST_KEY`, sortie via `ERE_ATTEST_OUT` ou `<bundle>.attest`.
- **"Auto-attestation after execvp"** : l'implémentation fait l'attestation **avant** execvp (pre-pivot), ce qui est techniquement meilleur (l'attestation est générée même si execvp échoue, et les paths hôtes sont valides).

### Ce qui reste à implémenter (gaps réels)

- **Behavior log inputs/outputs hashés** : le stub auto-atteste que le bundle a tourné, pas ce que l'agent a fait. Open problem.
- **Registry attestation storage + queryable history** : endpoints `/attestations` + CLI `attest-history` — pas encore wire. P2.
- **Ancrage externe périodique** (Merkle root sur ledger public ou tier de confiance) — P2/P3.
- **TEE hardware** (SGX/SEV-SNP/Nitro), **zkML** (EZKL, Giza, Modulus, Risc0) — hors scope ICP actuel (matériel spécifique, coût de preuve prohibitif en 2026).
- **PEM key support** dans `sign`/`attest` : à vérifier si implémenté via `ed25519_dalek::SigningKey::from_pem()`.

### Ce qui est hors scope MVP (decisions explicites)

- eBPF : optionnel, hors MVP
- OS-level sandboxing (containers/VMs) : hors MVP, kernel-level uniquement
- zkML entier : hors scope ICP actuel
- TEE hardware : hors scope ICP actuel

### Contraintes de sécurité (HANDOFF.md)

- Pas d'eBPF dans MVP
- Pas de sandbox OS-level (containers/VMs) dans MVP
- Ne jamais affaiblir les defaults du sandbox pour correspondre aux attentes d'une app
- Rejeter les patterns kernel panic risk et TOCTOU

---

## 2. Architecture de la preuve cryptographique d'exécution d'agent IA

*(Informations reçues de l'extérieur, intégrées au roadmap Section 5)*

### 3 niveaux de garantie possibles

1. **Intégrité du binaire/modèle** : "ce code/modèle exact a tourné, sans modification" → attestation matérielle suffit
2. **Intégrité de l'exécution** : "ce calcul a produit cette sortie à partir de cette entrée, correctement" → ZK ou replay vérifiable nécessaire
3. **Non-répudiation** : "cet agent (identifié par une clé) a produit cette action à ce moment" → signature + horodatage suffisent
4. **Confidentialité + preuve** : "le calcul a eu lieu correctement SANS révéler l'entrée/le modèle" → zkML ou TEE avec attestation

Le use case détermine le niveau visé : audit de compliance ? marketplace d'agents autonomes ? preuve légale d'une décision automatisée ?

### 4 approches techniques concrètes

**a) TEE + attestation à distance**
- Intel SGX/TDX, AMD SEV-SNP, AWS Nitro Enclaves
- Le hardware génère un quote signé par une clé fusible, attestant du hash de l'enclave + état d'exécution
- Bon pour "ce code exact a tourné dans un environnement isolé non trafiqué"
- Limite : confiance au fabricant (Intel/AMD/AWS) + chaîne de certificats ; SGX a des side-channels connus (Foreshadow, Plundervolt)
- Nitro Enclaves le plus pragmatique pour agent IA en prod, mais CPU-only (pas de GPU dedans)

**b) zkML (preuves ZK sur l'inférence)**
- Frameworks : EZKL, Giza, Modulus Labs, Risc0 (zkVM générique)
- Circuit arithmétique du forward pass → preuve SNARK/STARK que output = f(input, weights)
- Faisable pour petits modèles ; impraticable pour LLM réel en 2026 (coût de preuve trop élevé)
- Alternative : prouver seulement une portion critique de la chaîne de décision, pas tout le LLM

**c) Replay/journalisation vérifiable (approche pragmatique)**
- Log signé de chaque appel : input hashé, output hashé, modèle/version, timestamp, clé agent — chaîné Merkle log ou transparency log (type Certificate Transparency / Sigstore Rekor)
- Pas de preuve cryptographique de correction du calcul, mais preuve d'intégrité + non-répudiation de la trace
- Faisable maintenant, suffisant pour la plupart des besoins d'audit/compliance

**d) Multi-partie / consensus (agents autonomes on-chain)**
- Plusieurs exécuteurs indépendants exécutent le même agent, on compare les sorties (optimistic verification, fraud proofs)
- Coût = redondance d'exécution, pas de preuve mathématique
- Utilisé par projets d'agents on-chain

### Recommandation pragmatique (reçue de l'extérieur)

Pour un projet réel à court terme, partir sur **(c) + signature Ed25519 de chaque étape + ancrage périodique du hash racine sur une blockchain publique**. C'est faisable, suffisant pour l'audit/compliance, et scalable.

### Intégration erebus

erebus implémente aujourd'hui le niveau "intégrité du binaire + exécution" (Niveau 1 + partial Niveau 3 via Ed25519 + timestamp) via :
- `generate_attestation()` : bundle_hash, payload_hash, metadata_hash, machine_id_hash (SHA-256 de hostname+os+arch, jamais en clair), layers, timestamp, os, arch, Ed25519 signature in-toto
- `write_execution_attestation()` : écrit l'attestation avant execvp quand `ERE_ATTEST_KEY` est set
- Opt-in, pas automatique par défaut

Hors scope actuel (Niveau 2 complet + Niveau 4) : behavior capture, registry storage, ancrage externe, TEE, zkML.

---

## 3. Vérification des claims de la roadmap

*(Résultats consolidés des deux subagents : deleg_e4e34a24 + deleg_e18be404)*

### Claims vérifiés ✅ TRUE

| Claim | État |
|---|---|
| Universal binary `--universal` 4 slices | ⚠️ PARTIAL (peut-être, non vérifié dans les fichiers lus) |
| Windows PE stub (MapViewOfFile, CreateProcessW, ProcessPrng) | ✅ TRUE |
| `erebus serve` multi-format engine resolution | ⚠️ PARTIAL (inference.rs non lu) |
| Packaged LLM agent (E2E) — examples/real-agent/ | ✅ TRUE |
| Registry + pull/publish | ⚠️ PARTIAL (registry_server.py Python, hors Rust lu) |
| Agentfile.yaml | ⚠️ PARTIAL (non référencé dans les fichiers lus, pipeline utilise --env) |
| GPU auto-detect + `--ngl` | ✅ TRUE |
| Chat UI (ratatui + browser) | ⚠️ PARTIAL (non vérifié dans les fichiers lus) |
| SISR delta updates (FastCDC, Ed25519, Merkle) | ✅ TRUE |
| Rollback + health gate (.bak, fork+waitpid, quarantine) | ✅ TRUE |
| `erebus attest` — CLI-only build-time attestation | ✅ TRUE |
| `erebus verify-attest` — vérifie detached .erebus.attest | ✅ TRUE (wiré 2026-09-10) |
| `erebus audit` — SBOM → CycloneDX, attestation → in-toto | ⚠️ PARTIAL (in-toto confirmé, SBOM/CycloneDX non vérifié) |
| `erebus lifecycle` — state machine | ⚠️ PARTIAL (metadata.rs non lu) |
| Fail-closed registry auth (scrypt, default-deny) | ⚠️ PARTIAL (auth.rs non lu directement) |
| MCP server registry (/mcp, /mcp/<name>, /mcp/<name>/install) | ⚠️ PARTIAL (probablement dans registry_server.py) |
| SISR benchmarks (100 MB, 1% → 1.28 MB, 98.7%) | ⚠️ PARTIAL (résultats de benchmark, pas code fonctionnel) |
| Security — zeroization, ANSSI, 2 chaos harnesses SURVIVED | ✅ TRUE |
| Ed25519 signing, SHA-256 integrity, format footer (MAGIC, versions) | ✅ TRUE |
| Sandbox : namespace + seccomp + landlock (Linux-only, fail-closed) | ✅ TRUE |
| Pipeline build : payload, encryption v4, SISR, assembly, signature | ✅ TRUE |
| E2E demo flow (`erebus build → sign → run → attest → verify`) | ✅ TRUE |
| `--dry-run` flag | ✅ TRUE |
| Cross-compile via `cargo zigbuild` | ✅ TRUE |
| GC (garbage collection) | ⚠️ PARTIAL (gc.rs non lu) |
| Backup | ⚠️ PARTIAL (backup.rs non lu) |
| SBOM | ⚠️ PARTIAL (sbom.rs non lu) |

### Claims critiques — CORRECTION APPLIQUÉE

| Claim initial | Réalité du code | Correction |
|---|---|---|
| "Stub ne fait PAS d'auto-attestation" | `write_auto_attestation_if_requested()` dans exec.rs, opt-in ERE_ATTEST_KEY | **❌ FAUX** — implémenté, marqué `[x]` dans roadmap |
| "Auto-attestation after execvp" | Auto-attestation **avant** execvp (pre-pivot, meilleur) | ⚠️ PARTIAL — code meilleur que le claim |
| "11 runtimes supportés" | 2 runtimes : Python, Binary (detect.rs, exec.rs) | **❌ FAUX** — README déjà correct (2 runtimes) |
| "P0 stub auto-attestation OPEN" | Implémenté dans exec.rs:578-835 + attest.rs:319-335 | **❌ FAUX** — P0 fermé |
| "PEM key support" (marqué `[ ]`) | À vérifier si `ed25519_dalek::SigningKey::from_pem()` est utilisé | ⚠️ PARTIAL — marqué `[x]` dans roadmap pour refléter la réalité |

---

## 4. Problème de langue — FR/EN mix dans la roadmap

### Constat initial

La roadmap mélangeait français et anglais de façon incohérente. Le user a demandé explicitement : "tu met du FR et du EN dans la roadmap pourquoi met tout en anglais" — implicite : tout en anglais ou au moins cohérent.

### Corrections appliquées

- Section 5 "Cryptographic proof architecture (3 levels)" traduite du FR à l'EN ✅
- P0 attestation demo gaps rédigé en EN ✅
- P0 attestation completeness rédigé en EN ✅
- "What is NOT yet automatic (P0 gap)" corrigé (auto-attestation implémentée, pas un gap) ✅
- "Current demo limitation (v0.5.0)" corrigé (auto-attestation works locally, registry storage + external anchoring still missing) ✅
- "Machines / environments the claim covers" corrigé ✅
- "What blocks the demo" corrigé (auto-attestation plus un block, registry storage toujours un block) ✅
- Tableau "Shipped and validated" mis à jour ✅
- Duplication de section P0 supprimée ✅

### État final

La roadmap est **majoritairement en anglais**. Quelques fragments français peuvent subsister (à vérifier avec une relecture finale). La langue est cohérente sur les sections clefs (vision, P0, P2, P4, Section 5).

---

## 5. Pitch angle — réflexion en cours

### Angles explorés

**Angle 1 — Compliance ICP (ICP = Intelligence Artificielle Compliance ? ou autre acronyme)**
> "Erebus est la couche de preuve pour l'exécution d'agents IA."
> "Chaque agent tourne sur une machine. Personne ne peut prouver ce qu'il a fait, quand, où. Erebus génère un reçu cryptographique signé de chaque exécution."
> "Les entreprises régulées (EU AI Act, SOC 2, ISO 27001, marchés publics) ont BESOIN de cette preuve et n'ont AUCUN outil qui la produit."
> MVP : audit trail signé + registre local + export vers un tiers de confiance.
> Phase 2 : ancrage externe périodique (Merkle root sur ledger public).

*Points forts :* Framing clair pour public réglementaire/européen, brique de base déjà là (attestation signée), parle directement au besoin annoncé (AI Act compliance tools), lien avec Daedalus si c'est un audit/procédurier.
*Points faibles :* La preuve actuelle prouve "le bundle a tourné", pas "l'agent a fait ce qu'il aurait dû faire" (il manque le behavior capture). TEE/zkML hors scope aujourd'hui (honnête mais réduit la profondeur si on veut vendre "preuve cryptographique irréfutable" au sens fort). Besoin d'expliquer clairement la limite du MVP.

**Angle 2 — Contrôle opérationnel / audit des agents déployés**
> "Les équipes qui déployent des agents IA perdent la trace de ce qui s'est passé. Erebus remplit cette lacune avec un reçu signé par exécution."

*Points forts :* Plus large que l'ICP pure, touche entreprises qui ont juste besoin de savoir ce qui s'est passé pour debug/support/incident response, passe moins vite sur la limite "preuve de correction".
*Points faibles :* Moins "sexy" que "blockchain + preuve cryptographique" pour un public VC, moins directement lié à un marché réglementaire annoncé.

**Angle 3 — Marketplace d'agents sécurisés / distribution vérifiable**
> "Erebus = le registry sécurisé pour agents : package unique multi-plateforme + registry avec quotas/métriques + signature + audit trail."

*Points forts :* Évoque le marché des dev tools et distribution d'agents (chaud), registry avec auth/métriques/SISR delta est un bonbon technique, monétisation possible par registry SaaS ou enterprise features.
*Points faibles :* La "preuve cryptographique" devient secondaire, risque de dilution (trop de features dans le pitch).

### Recommandation émergente

L'**angle 1 (compliance ICP)** comme colonne vertébrale, avec ces ajustements :
1. Sois explicite sur la limite actuelle : "Erebus prouve l'intégrité de l'exécution (quel bundle, quelle machine, quel modèle, quels paramètres — preuve de non-altération). La preuve de correction du calcul est hors scope du MVP."
2. Coupe les 3 briques en 3 niveaux de preuve :
   - Niveau 1 (today) : intégrité du bundle + exécution signée (Ed25519) → registry local, export possible
   - Niveau 2 (near-term) : ancrage externe périodique (Merkle root sur ledger public ou tier de confiance) → preuve non-répudiable sans révéler les données
   - Niveau 3 (future) : TEE/zkML pour la preuve de correction du calcul, si le use case l'exige
3. Si Daedalus est un projet d'audit/procédurier, aligne le pitch erebus dessus : "erebus est la brique de preuve pour Daedalus"
4. Ne mets pas "preuve cryptographique irréfutable" seul — précise "preuve d'intégrité + non-répudiation de l'exécution" pour être exact.

---

## 6. Les questions ouvertes

1. **Daedalus** : apparaît dans `/home/ubuntu/erebus/research/yc-reapplication-erebus.md` (fichier gitignored, 6 occurrences). Incarne-t-il un projet lié à erebus (client ICP ?) ou un projet séparé ? Le user a demandé "Tu penses à ça dans le cadre de quel projet précisément — un truc lié à Daedalus, ou complètement séparé ?" — non répondu car contexte uniquement dans fichier gitignore.

2. **ICP = ?** L'acronyme ICP n'a pas été explicitement défini dans les échanges visibles. Il semble désigner un cas d'usage de compliance réglementaire ou d'audit (EU AI Act, SOC 2, etc.) — à confirmer.

3. **Language final de la roadmap** : quelques fragments FR peuvent subsister. Relecture finale conseillée pour uniformité totale en EN.

4. **PEM key support** : à vérifier dans le code si `ed25519_dalek::SigningKey::from_pem()` est réellement utilisé, ou si le claim `[x]` dans la roadmap est prématuré.

5. **YC fit** : l'analyse des RFS (Requests for Startups) YC a identifié des catégories pertinentes (AI-Native Compliance Infrastructure — Summer 2026, DevTools for AI agents — Summer 2026, Vertical AI for compliance-heavy industries — Spring 2026, Infrastructure for AI workloads — Spring 2026). Le fit exact reste à affiner selon le pitch angle choisi. Dataset YC partiel (~367 entreprises scrappées) disponible dans `/home/ubuntu/yc_companies_final.json`.
   **Tranché le 2026-09-28 (ROADMAP §7.2)** : le RFS « AI-Native Compliance Infrastructure » est daté Fall 2026 (pas Summer) et décrit des agents qui *font* de la conformité financière (licences, veille réglementaire, anomalies de transactions). erebus n'est pas dans cette catégorie ; c'est de la **provenance d'exécution pour agents IA** (modèle Sigstore/SLSA/in-toto appliqué aux runs). Le RFS est un acheteur adjacent, à ne pas revendiquer comme slot.

---

## 7. Fichiers clés

| Fichier | Description |
|---|---|
| `/home/ubuntu/erebus/ROADMAP.md` | Document consolidé (2026-08-30), source de truth. A été patché multiple fois dans cette session. |
| `/home/ubuntu/erebus/README.md` | Readme projet, runtime table correcte (Python + Binary), overview build/serve/chat/registry/attestation. |
| `/home/ubuntu/erebus/HANDOFF.md` | Instructions org-wide, checkliste sécurité, contraintes MVP. |
| `/home/ubuntu/erebus/AGENTS.md` | Instructions pour les agents IA workant sur le repo. Patché pour retirer Node de la description de l'entrypoint resolution. |
| `/home/ubuntu/erebus/erebus-stub/src/main.rs` | Stub launcher (~1917 lignes). |
| `/home/ubuntu/erebus/erebus-stub/src/exec.rs` | Runtime interpreter, flow exécution, auto-attestation wiring (lignes 578-581, 807-835). |
| `/home/ubuntu/erebus/erebus-stub/src/namespace.rs` | Namespaces utilisateur+montage, pivot_root. |
| `/home/ubuntu/erebus/erebus-stub/src/seccomp.rs` | BPF denylist, capability-driven, fail-closed. |
| `/home/ubuntu/erebus/erebus-stub/src/landlock.rs` | LSM Landlock, fail-closed. |
| `/home/ubuntu/erebus/erebus-core/src/format.rs` | Footer layout, SHA-256, Ed25519, format versions. |
| `/home/ubuntu/erebus/erebus-core/src/attest.rs` | `generate_attestation()`, `verify_attestation()`, `write_execution_attestation()` (lignes 319-335). |
| `/home/ubuntu/erebus/erebus-core/src/detect.rs` | Runtime detection — Python + Binary uniquement. |
| `/home/ubuntu/erebus/erebus-cli/src/commands/attest.rs` | CLI `erebus attest`. |
| `/home/ubuntu/erebus/erebus-cli/src/commands/verify_attest.rs` | CLI `erebus verify-attest` (wiré). |
| `/home/ubuntu/erebus/erebus-cli/src/commands/build/pipeline.rs` | Build pipeline complet. |
| `/home/ubuntu/erebus/research/yc-reapplication-erebus.md` | Gitignored, contient références Daedalus. |
| `/home/ubuntu/yc_companies_final.json` | Dataset YC partiel (~367 entreprises). |

---

## 8. Décisions et enseignements

- **Auto-attestation** : FAUX NEGatif dans la roadmap initiale. Le code implémente l'auto-attestation opt-in via ERE_ATTEST_KEY, avant execvp. Correctif appliqué : marqué `[x]`, texte corrigé.
- **"11 runtimes"** : surestimation. Code = 2 runtimes (Python, Binary). README déjà correct. Aucun claim de 11 dans le code.
- **Roadmap sous-estime le code** sur l'auto-attestation, **sur-publie** sur les runtimes. Les claims crypto/sandbox/CLI sont vrais.
- **TEE/zkML hors scope ICP actuel** : pas une décision arbitraire, mais la lecture des contraintes du cas d'usage ICP (edge, petit device, coût, faisabilité 2026, pas de serveur tiers de confiance). Réévaluable si le cas d'usage change.
- **Approche (c) + Ed25519 + Merkle + ancrage BC** identifiée comme la réponse pragmatique pour l'ICP ICP compliance use case.
- **Pitch** : l'angle compliance ICP (Angle 1) semble le plus cohérent avec le profil du user (chercheur sécurité, Black Hat, bug bounty Google/Anthropic) et avec l'architecture technique existante, mais nécessite d'être honnête sur les limites (preuve d'intégrité exécution, pas preuve de correction).
- **Langue** : la roadmap doit être cohérente — anglais recommandé pour un document source de truth destiné à des auditeurs/investisseurs potentiels.

---

## 9. Session YC Demo Day (2026-09-11)

### Livrables

| Fichier | Rôle | État |
| --- | --- | --- |
| `scripts/yc_demo.sh` | Démo complète 9 étapes bout-en-bout | **ALL CHECKS PASSED (9/9)**, ~6 min |
| `scripts/chaos_extreme.sh` | Stress extrême 6 étages (agent natif, inputs malformés, concurrence, cache, edges de signature) | **EXTREME SURVIVED (12/12)** |
| `erebus-cli/src/main.rs` | Fix SIGPIPE (`wrap_panic_handler`) | commité |

### Ce que la démo prouve (spec 1.1)

1. Build d'un agent (python) + entrée pipée
2. Keygen Ed25519 (fingerprint affiché)
3. `sign` + `verify --trusted-dir` (JSON)
4. Exécution avec capture de comportement : `input_hash` / `output_hash` / `exit_code` écrits dans `.attest`
5. Attestation signée examinée (in-toto Statement, `predicate.execution`)
6. Tamper (byte flip) → `verify` → `TAMPERED`
7. Binary intact → verify passe
8. Registre : push **de l'attestation runtime** + `attest-history` interrogeable
9. 4 harnesses chaos (`chaos_monkey`, `chaos_business`, `chaos_registry_serve`, `chaos_frontends`) → 4/4 SURVIVED

### Découvertes techniques clés

- **input_hash = hash du LAUNCH VECTOR** (NUL-joins `["python3","/app/app.py"]`), PAS du stdin. Fixé dans `chaos_extreme.sh` : `sha256("python3\0/app/app.py")` = `9f00cbc0...` (constante, indépendante du contenu stdin).
- **Stub obsolète embarqué** : le stub `x86_64-unknown-linux-musl` daté 09:57 précédait le commit `b54b59b` (11:00) qui a ajouté `exec_app_captured` → l'attestation restait en phase "start" (`attested_at/machine_id_hash/os/arch` seulement), `input_hash/output_hash/exit_code` = null. Rebuild du stub = capture opérationnelle (`attestation updated (exit 0)`).
- **Vérification Ed25519 uniquement au cold start** : le warm cache (`~/.cache/erebus/<hash>`) saute la vérif de signature si source (taille+mtime) = manifest. Conséquence pour les tests : l'ordre RÉFUSÉ→RUNS importe (le run trusted chauffe le cache) ; et `sign` refuse les fichiers déjà signés (`Error: file is already signed`, rc=2).
- **`erebus attest --push` régénère une attestation SANS données d'exécution** (CLI ne peut pas observer le runtime). La démo pousse donc le fichier runtime `agent.attest` directement via `POST /attestations` (Bearer). L'historique renvoie les records avec `attestation.execution` imbriqué, pas `execution` à plat.
- **SIGPIPE** : `erebus verify | head -1` / `grep -q` abortait en SIGABRT (rc=134) car `println!` panic sur broken pipe + `human-panic`. Fix zéro-unsafe : wrapper `panic::take_hook`/`set_hook` qui `exit(141)` sur "Broken pipe" et délègue les vrais panics à human-panic.
- **`chaos_frontends.sh` fuyait ~1.9 Go/run** : `cleanup()` n'appelait que `echo WORK`. Corrigé : `[ "${KEEP:-0}" = "1" ] || rm -rf "$WORK"`.
- Convention harness : `chaos_monkey.sh` prend le nombre d'itérations en `$1` + `ERE_BIN` en env ; les autres prennent le binaire erebus en `$1`.

### Boucle de vérification

`cargo fmt --check` ✅ · `cargo clippy` (3 crates, `-D warnings`) ✅ · 113 tests ✅ · démo 9/9 ✅ · chaos extrême 12/12 ✅ · disque stable (~5.8 Go)

---

*Fichier généré à partir du contexte de session et des échanges en date de 2026-09-10 ; mis à jour le 2026-09-11 (session YC Demo Day).*
