# IDEES — Compilation complete

## 1. Position A : Agent IA local (PRINCIPALE)

**Description** : Format `.erebus` pour agents IA locaux — un seul fichier qui contient
le stub + runtime + modèle GGUF + prompt + tools + config, signé Ed25519, avec delta
updates Sisir et sandbox seccomp+Landlock.

### Pourquoi c'est le bon angle

- Le code existe déjà pour ce cas : SISR content-defined chunking pour gros fichiers,
  encryption AES-256-GCM pour protéger les poids, sandbox seccomp+Landlock, multi-runtime
  detection (Python/Node/Go/Binary/etc.)
- Le concurrent direct (llamafile, Mozilla-Ocho 25k★) est faible : C++ only, pas de
  delta updates, pas de sandbox, pas de multi-runtime
- Le marché des agents IA locaux est réel et en croissance

---

## 2. Position B : Compilateur vers formats existants (--to flag) — DEPRECATED

**Statut** : **Déprécié.** Abandonné au profit de la focus agent IA.

**Raisons** :
- Dilution : le format `.erebus` existant répond déjà au besoin de distribution
- L'OCI n'est concurrent qu'au-delà du réseau (pas dans le segment local AI desktop)
- WASM/AppImage = features qui ne sont pas dans le segment prioritaire
- Personne ne paie pour "build once → deploy everywhere" ; le market value est dans
  le distribution sécurisé + delta updates pour les agents IA

### Code analysis findings
- `layer.rs` = DEAD CODE : `Layer` trait, `SerializableLayer`, `Capability`, `Entrypoint` — exists mais jamais branches dans le pipeline production
- `ArtifactMetadata` = DEAD CODE : importe seulement par `metadata.rs` tests, jamais par pipeline
- `Cas.rs` (CAS trait) = DEAD CODE : defini mais pas utilise par le stub/runtime
- `Metadata { runtime: String, entrypoint: Vec<String>, services }` = format PLAT, utilisé par vrai pipeline

### Status du code (verifié)
- `layer.rs` : 100 matches grep, mais imports only in `metadata.rs` tests (lignes 7, 358, 393)
- `ArtifactMetadata` : zero imports en dehors de `metadata.rs` tests
- `CAS trait` : defini mais jamais importe par le stub ou CLI production path
- Stub et CLI utilisent `build_meta_json()` → `AssemblyInput` → `assemble_erebus()` — format plat
- `cargo check` + `cargo clippy` + `cargo test` tous passes, zéro warnings

## Analyse concurrentielle — focus local AI (rechererch web 2025-2026)

### Tools existants dans le segment agent IA local

| Outil | Format | SISR | Sandbox | Multi-runtime |
|---|---|---|---|---|
| **llamafile (YC OSS)** | Fat C++ binary | None | None | C++ only |
| **Docker/BuildKit** | OCI image | zstd:chunked (partial) | Namespace | Yes (any runtime) |
| **PyInstaller** | Executable | None | None | Python only |
| **Bun** | Single binary | None | None | JS/TS only |
| **Nix** | Store | NAR deltas | Namespace | Yes |

## 4. Pourquoi erebus contre llamafile (le concurrent direct)

**llamafile** = un binaire C++ qui package llama.cpp + un modèle GGUF. C'est fait pour
tourner un modèle llama, pas pour packager un agent IA complet.

| Aspect | llamafile | **erebus** |
|---|---|---|
| Runtime | C++ llama.cpp only | Python/Node/Go/Binary + llama.cpp |
| Delta updates | None (full re-download) | **SISR content-defined delta** |
| Sandbox | None | **seccomp + Landlock** |
| Multi-language | No (C++ only) | **Yes** (Python API + C++ inference + Go tools) |
| Format | Single ELF | Single `.erebus` (décompressible) |
| Cross-arch | Rebuild nécessaire | **Universal binary project** |
| Web UI | Static HTML only | FastAPI/Flask/Node server |

## 5. Use case prioritaire : agent IA local

Packager un agent IA typique :

```
my-agent/
  app.py            ← FastAPI server (Python)
  requirements.txt  ← flask, requests, llama-cpp-python
  model.gguf        ← 4-30GB GGUF model weights
  tools/            ← Python tool scripts
  prompt.txt        ← system prompt
```

```bash
# Build une fois → un seul fichier
erebus build ./my-agent --embed-interpreter python3 -o agent.erebus

# Distribution → un seul fichier, marche partout
chmod +x agent.erebus && ./agent.erebus
# → Python runtime + deps + model + code extractés en 2s, server ready

# Mise à jour incrémentale → 15MB au lieu de 4GB
erebus build ./my-agent --update --enable-sisr
# → SISR delta : seuls les chunks modifiés sont téléchargés
```

## 6. Business model

- **Produit** : OSS tool (gratis) — `erebus build`, `erebus swap`, `erebus run`
- **Monetisation** : SaaS registry pour versioning de modèles + delta hosting
- **Pricing** :
  | Tier | Price | Features |
  |---|---|---|
  | Free | $0 | Local build, single-file |
  | Pro | $7/user/mois | Private registry, SISR |
  | Team | $29/team/mois | SSO, analytics |
  | Enterprise | Custom | Airgap, compliance |

## 7. Recommendation

### Angle principal : Agent IA local

- Focus sur le segment local AI / agents IA
- erebus = llamafile + delta updates + sandbox + multi-runtime
- Positionnement : "Distribution sécurisée pour agents IA locaux — un fichier,
  delta updates de 95% plus petites, sandbox pour exécuter des agents non-connus."

### Competitive moat

1. **SISR delta updates** — chunk-level content-defined; seul le delta est téléchargé
2. **Single-file self-extracting** — plus simple que Docker, no daemon
3. **Multi-runtime** — Python + C++ + Go + Binary dans un seul format
4. **Sandbox sécurité** — seccomp + Landlock + Ed25519 signing
5. **Open format** — interoperability ($tar$/unsquashfs pour décompresser)
```
| Outil | Format | SISR | SaaS | Business model |
|---|---|---|---|---|
| **Docker/BuildKit** | OCI only | zstd:chunked (partial) | ❌ local | Infra existante |
| **AppImageTool** | AppImage only | zsync delta | ❌ local | Communauté |
| **Wasmer + WAPM** | WASM only | WASM layer cache | ✅ (Wasmer Edge) | SaaS + OSS |
| **Nix/Flox/Determinate** | Multiple | Narhash deltas | ✅ (Flox Teams) | SaaS Enterprise |
| **Bazel remote cache** | Multiple | Remote cache | ❌ local | Google |
| **pkgforge/soar** | Package manager | zsync deltas | ❌ | OSS |
| **ocx** | OCI only | Content-addressed | ❌ | OSS |
| **Afterburner** | WASM | N/A | ✅ planned | WASM runtime |
| **adipo** | Fat binaries | N/A | ❌ | OSS |
| **Depot (YC W22)** | OCI only | Layer cache NVMe | ✅ SaaS | $15M+ ARR |
| **D4C/diffah** | OCI deltas | layer-level deltas | ❌ | OSS |
| **chunkah** | OCI content layers | N/A | ❌ | OSS |

### Le GAP (rien n'existe)
**Personne ne fait** : build-once → OCI + AppImage + WASM + SISR cross-format

- Docker/BuildKit → OCI only
- AppImageTool → AppImage only  
- Wasmer/WAPM → WASM only
- Nix → peut faire multi mais complexité Nix lang + pas SISR cross-format
- D4C/diffah → delta updates OCI only
- Depot → remote build acceleration, OCI only

### Depot comparison (YC W22, valué $1.5B+)
**Positionnement** : "40x faster Docker builds" via remote BuildKit VMs (16 CPU, 32GB RAM, NVMe cache)

**Business model** : SaaS subscription
**Clients** : PostHog, Wistia, Appsmith, Secoda
**ARR** : $15M+ est.

**xbin vs Depot** :
| Aspect | Depot | xbin |
|---|---|---|
| Probleme | Docker build lent | Deploy multi-format avec updates minces |
| Solution | Remote BuildKit VMs | OSS tool + multi-format + SISR |
| Formats | OCI only | OCI + AppImage + WASM + .erebus |
| Model | SaaS only | OSS tool + SaaS registry |
| SISR | Layer cache NVMe | Chunk-level delta across formats |
| Deploy | Cloud/SaaS | Local tool, self-contained |

**Conclusion** : complementaire, pas concurrent. Depot = build fast. xbin = deploy smart.

## 4. Angle MLOps (recherche validee)

### Le probleme
- Un modele IA fait 5-50 GB
- Besoin de deployer sur :
  - Cloud GPU (OCI containers)
  - Laptop (WASM inference)
  - Edge device (native binary)

### xbin value proposition
```bash
erebus build ./ai-model --to oci,wasm,app --target linux-x64,aarch64
# → OCI image for cloud, WASM module for browser, native binary for edge
# → next update: SISR cross-format, ne telecharge que ce qui a change
```

### Concurrent
- Docker : trop lourd pour edge/WASM
- AppImage : pas fait pour gros fichiers (50GB)
- PyInstaller : mono-language, pas de container/WASM

### Business model
- OSS tool gratis
- SaaS registry pour versioning de modeles + SISR
- Target : teams MLOps, ML startups

## 5. Angle Edge/IoT OTA

### Problem
- Bandwidth cellulaire $$$ pour fleets
- Devices heterogenes (ARM/x86/WASM)
- Updates doivent etre deltas

### xbin value proposition
- SISR cross-format + signatures Ed25519 + single-file
- Un artefact → tous device types

### Concurrent
- Mender, Foundries.io, Esolutions (embedded Linux OTA)
- Aucun ne gere WASM + native + container ensemble

### Business model
- SaaS OTA platform ($0.10/device/mois)
- Enterprise licensing

## 6. Business Models discutes

### OSS + SaaS (recommande)
```
erebus build . -o app.ere     # OSS gratis
erebus push registry/app:v1   # SaaS registry
```

### Tiered pricing
| Tier | Price | Features |
|---|---|---|
| Free | $0 | Local build, single-file |
| Pro | $7/user/mois | Private registry, SISR |
| Team | $29/team/mois | SSO, collaboration, analytics |
| Enterprise | Custom | Airgap, compliance, support |

### Alternative pricing
- Per-build : $0.01/build (GitHub Actions style)
- Per-device : $0.10/device/mois (IoT fleet)

## 7. Recommendation finale

### Angle principal : "Bun for polyglot apps"  
**Positionnement** : xbin = Bun mais pour tout langage. Build n'importe quelle stack, package en single file, run partout.

### Angle secondaire : MLOps/Edge
**Valeur differentielle** : SISR cross-format pour gros artefacts (modeles IA 5-50GB)

### Pitch YC
> "Erebus is the universal application packager — build once, deploy to containers, laptops, web, and edge as a single self-extracting file. While Docker needs a daemon and Depot only does containers, Erebus packages any runtime into one file that runs anywhere, with 95% smaller updates via SISR."

### Business model gagnant
- **Produit** : OSS tool (gratis, dev adoption)
- **Monetisation** : SaaS registry (SISR + signatures + private repos)
- **Target ARR** : $20M/year
  - 10K devs pro (Team plan $29) = $3.5M ARR
  - 100 MLOps/Edge startups = $15M ARR
  - 5 Enterprise deals (custom $1M) = $5M ARR

### Roadmap priorite
1. **Phase 1** : Completer `--to [oci|appimage|wasm]` (multi-format output)
2. **Phase 2** : SaaS registry publique (push/pull/sign + SISR)
3. **Phase 3** : Enterprise features (airgap, compliance, custom runtimes)

### Competitive moat
1. **SISR cross-format** — technologiquement unique
2. **Single-file self-extracting** — plus simple que Docker
3. **Multi-runtime** — pas besoin d'installer Python/Node/Go
4. **Open format** — interoperability (peut decompiler avec tar/unsquashfs)
```
