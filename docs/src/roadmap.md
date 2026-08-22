# Roadmap

## Vision

Un **format d'artefact exécutable universel pour agents IA** : `[polyglot-stub][payload][metadata][footer]`.
Un seul fichier `.erebus` qui contient le runtime Python + llama.cpp (binary) + modèle GGUF + tools + config,
signé Ed25519, avec delta updates SISR et sandbox seccomp+Landlock. Fonctionne sur Linux x86_64/ARM64,
macOS ARM64, Windows x64 — sans installer quoi que ce soit sur la cible.

**Use case unique :** Distribution d'agents IA locaux.

## Positioning YC

> "Nous aidons les développeurs qui construisent des agents IA locaux à distribuer
> leur modèle + code + runtime dans un seul fichier qui marche partout, sans Docker,
> sans Python, avec des mises à jour incrémentales de 95% plus petites."

### Qui a ce problème?

Un **développeur (solo ou petite équipe)** qui construit un **agent IA local** (llama.cpp + modèle
GGUF + serveur inference FastAPI/Flask + web UI) et veut le **distribuer à des collègues** qui n'ont que le
binaire — sans Docker, sans Python, sans rien installer.

### Pourquoi maintenant?

- Les modèles GGUF font 4-70 GB : le téléchargement est devenu le goulot d'étranglement
- llamafile (Mozilla-Ocho, 25k★) est le concurrent direct : C++ only, pas de delta updates,
  pas de sandbox, pas de multi-runtime
- Les équipes veulent partager des agents entre collègues / serveurs / laptops sans setup

### Pourquoi toi?

- Architecture conçue pour ce cas : SISR content-defined chunking pour les gros fichiers
- Sandbox sécurité (seccomp + Landlock) pour exécuter des agents non-connus
- Format ouvert : un `.erebus` peut être décompressé avec `tar`/`unsquashfs`
- Experience construire : 423 tests passent, code Rust 2021 stable, ANSSI-compliant

## Phase 1 — MVP agent IA ✅

- [x] `.erebus` format défini et stable (v2-v5 : plain, signed, encrypted, squashfs)
- [x] Stub ELF statique (musl), SHA-256 integrity verification, execvp entrypoint
- [x] Extraction atomique via `rename()` avec `flock()` pour concurrence
- [x] **Python runtime detection** + rootfs construction (FastAPI/Flask/Django)
- [x] **Binary runtime detection** (llama.cpp inference engine)
- [x] Ed25519 signatures (v3) + trust model (`erebus keygen/sign/verify/trust`)
- [x] Level 2 isolation : user namespaces + `pivot_root`
- [x] Smart `.so` deduplication
- [x] `/etc/hosts` dans rootfs
- [x] Payload encryption AES-256-GCM (v4)
- [x] SquashFS extraction (v5 format, `--squashfs`)
- [x] **2 runtimes supportés** : Python (API server), Binary (llama.cpp inference)
- [x] Framework auto-detection (FastAPI, Flask, Django)

## Phase 2 — Delta updates pour les modèles ✅

- [x] **SISR engine** : FastCDC content-defined chunking + Merkle delta manifest
- [x] Content-addressed build cache (runtime layer reused, rebuild ~25s → ~1s)
- [x] Chunk reuse entre apps partageant le meme runtime
- [x] Bandwidth reporting : `"12 MB delta vs 328 MB full — 96.4%"`
- [x] `--enable-sisr` flag + incremental rebuild via `erebus build --update`

## Phase 3 — Universal Binary (PRIORITY #1 — 3-4 days)

**Problème :** Aujourd'hui `erebus build` produit un binaire **architecture-specific**.
Le stub ELF x86_64 ne marche pas sur ARM64 — nécessite un rebuild par arch.

**Solution :** Polyglot launcher multi-format.

```
foo.erebus (universal file)
├─ [polyglot-stub]        ← valide ELF+PE+Mach-O (header overlap)
├─ [linux-x64-payload]    ← stub x64 + runtime x64 + model x64
├─ [linux-arm64-payload]  ← stub arm64 + runtime arm64 + model arm64
├─ [macos-arm64-payload]  ← Mach-O stub + runtime arm64
├─ [windows-x64-payload]  ← PE stub + runtime x64
├─ metadata (per-arch)
└─ footer + signatures
```

**Status :** Cross-compilation validée (zigbuild + fix seccomp.rs pour aarch64).
L'implémentation du wrapper polyglot est la priorité absolue.

## Phase 4 — Agent IA hot-swap (2-3 days)

`erebus swap <binary> <layer> <new-file>` — remplacer une couche sans rebuild.

Exemple : `erebus swap agent.erebus model ./new-gguf` — change le modèle, garde runtime+tools.

Brancher `examples/agent/` existant :
- `erebus build ./agent --publish ~/.erebus/registry` → génère layers: [RuntimeLayer, ModelLayer]
- Deux agents avec même runtime = même SHA256 → cache partagé → cold start < 200ms

## Phase 5 — Lazy loading (4-5 days)

mmap/FUSE pour ne pas charger le modèle (2-7 GB) au démarrage.
Chargé à la demande via SISR chunks.

## Phase 6 — Multi-agent & layer sharing (3-4 days)

Plusieurs agents IA dans un seul binaire, partageant le runtime layer.
Use case : `agent-code.erebus` + `agent-chat.erebus` partagent le même Python runtime +
les mêmes libs → seul le modèle diffère.

## Ce qui n'est PAS prioritaire

- ❌ Autres runtimes (Node, Deno, Java, Ruby, .NET, Go, PHP, Perl, Hugo, Wasm, Electron, Rust) — **SUPPRIMÉS**
- ❌ OCI/WASM/AppImage (`--to oci|appimage|wasm`) — abandonné
- ❌ Desktop packaging (flatpak/snap) — hors scope
- ❌ Monorepo Turborepo/Nx — nice-to-have, pas blocking pour le MVP agent IA
- ❌ 50 repos GitHub trending — integration testing, pas un feature produit
- ❌ Metrics Prometheus — nice-to-have ops, pas un feature produit
- ❌ Edge/IoT OTA channels — SISR le couvre déjà

## Section 7 — À NE PAS FAIRE (conflits résolus)

### OCI multi-format output (Position B deprecation)

Le `--to [oci|appimage|wasm]` est **déprécié**.
Raisons : dilution de focus, l'OCI n'est concurrent qu'au-delà du réseau (pas dans le
segment local AI desktop), et le format `.erebus` existant répond déjà au besoin.

Cibler le build once → deploy everywhere (OCI + WASM + AppImage) dilue l'ingénierie sur
un problème que personne n'a résolu (et le market ne le paie pas). Le concurrent
llamafile se concentre sur le binary local et domine ce segment — c'est le bon angle.

## Signaux de produit (comment on sait que c'est un vrai produit)

| Métrique | Objectif | Status |
|---|---|---|
| Cold start agent IA typique | < 2 secondes | à définir |
| Delta update size vs modèle full | < 5% | SISR fonctionnel |
| Nombre de .erebus exécutés | > buildés | à instrumenter |
| Agents packagés sans modification | > 90% | auto-detection frameworks |
| Cross-arch test via QEMU | x64+arm64 validated | ✅ |

## Stack technique (août 2026)

- **Rust 2021** stable, `opt-level="z"`, LTO, strip, `panic=abort`
- **stub** : musl static ELF, ~100KB, `unsafe` limité (FFI + seccomp BPF)
- **core/cli** : zero `unsafe`, ANSSI-Rust compliant
- **CI** : `cargo zigbuild` cross-compile, `cargo clippy -p {crate}`, `cargo test --workspace`
- **Tests** : 423 unit/integration/e2e, QEMU pour cross-arch validation