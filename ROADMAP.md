# erebus — ROADMAP (AI Agent Focus)

## Vision

Un **format d'artefact exécutable universel pour agents IA** : `[polyglot-stub][payload][metadata][footer]`.
Un seul fichier `.erebus` qui contient le runtime Python + llama.cpp (binary) + modèle GGUF + tools + config,
signé Ed25519, avec delta updates SISR et sandbox seccomp+Landlock. Marche sur Linux x86_64/ARM64,
macOS ARM64, Windows x64 — sans installer quoi que ce soit sur la cible.

**Use case unique :** Distribution d'agents IA locaux (llama.cpp + modèle GGUF + serveur inference Python + web UI).

## Positioning YC

> "Nous aidons les développeurs qui construisent des agents IA locaux à distribuer
> leur modèle + code + runtime dans un seul fichier qui marche partout, sans Docker,
> sans Python, avec des mises à jour incrémentales de 95% plus petites."

### Qui a ce problème?

Un **développeur (solo ou petite équipe)** qui construit un **agent IA local** (llama.cpp +
modèle GGUF + serveur inference FastAPI/Flask + web UI) et veut le **distribuer à des collègues**
qui n'ont que le binaire — sans Docker, sans Python, sans rien installer.

### Pourquoi maintenant?

- Les modèles GGUF font 4-70 GB : le téléchargement est le goulot d'étranglement
- llamafile (Mozilla-Ocho, 25k★) = concurrent direct, mais C++ only, pas de delta, pas de sandbox, pas de multi-runtime
- Les équipes veulent partager des agents entre collègues / serveurs sans setup

### Pourquoi toi?

- Architecture conçue pour ce cas : SISR FastCDC pour gros fichiers (modèles), encryption AES-256-GCM
  pour protéger les poids, sandbox seccomp+Landlock, dual-runtime (Python + Binary)
- Code existant: llama.cpp + FastAPI + GGUF dans un `.erebus` — fonctionne aujourd'hui
- Format ouvert : un `.erebus` peut être décompressé avec `tar`/`unsquashfs`

## Priorité du CEO

1. ~~Hot-swap modèle~~ ✅ livré (`erebus swap` + 10 tests chaos)
2. ~~Layer sharing entre agents~~ ✅ livré (`erebus layer push/list/pull/remove`)
3. ~~Lazy loading mmap~~ ✅ livré (RSS 7,6 Mo pour un binaire de 21 Mo)
4. **Universal binary** — un `.erebus` marche partout (x64/ARM64, Linux/macOS/Windows) — fait en dernier

## Ce qui est TERMINÉ (août 2026)

- ✅ Format binaire v2-v5 (plain, signed, encrypted, squashfs) + SHA-256 + Ed25519
- ✅ SISR delta engine (FastCDC content-defined chunking + Merkle delta manifest)
- ✅ Sandbox sécurité (seccomp 18 syscalls + Landlock + capabilités)
- ✅ **2 runtimes supportés** : Python (API server) + Binary (llama.cpp inference)
- ✅ Framework auto-detection (FastAPI, Flask, Django)
- ✅ Cross-compilation validée (cargo zigbuild + fix seccomp.rs pour aarch64)
- ⚠️ ~~Self-hosting : `erebus build self/`~~ — le dossier `self/` (copie Python CLI) a été
  supprimé en juillet 2026 ; le Rust CLI peut packager n'importe quel binaire statique mais
  n'a **pas** de workflow dédié pour se packager lui-même ni de test e2e correspondant
- ✅ Ed25519 signatures + trust model (`erebus keygen/sign/verify/trust`)
- ✅ Payload encryption AES-256-GCM (v4 format)
- ✅ Health checks + automatic rollback
- ✅ Persistent storage + data files
- ✅ 479 tests passent ✅, fmt/clippy clean, Rust 2021 stable, zero unsafe en dehors du stub

## Ce qui reste — PRIORITÉ ABSOLUE

### 0. Universal Binary (3-4 jours) — 🔥 Priorité #1 (fait en DERNIER)

**Problème :** Aujourd'hui `erebus build` produit un binaire **architecture-specific**.
Le stub x64 ne marche pas sur ARM64.

**Solution :** Polyglot launcher multi-format.

```
foo.erebus (universal file)
├─ [polyglot-stub]        ← ELF+PE+Mach-O header overlap
├─ [linux-x64-payload]    ← stub x64 + Python x64 + llama.cpp x64 + model
├─ [linux-arm64-payload]  ← stub arm64 + Python arm64 + llama.cpp arm64 + model
├─ [macos-arm64-payload]  ← Mach-O stub + Python arm64 + llama.cpp arm64 + model
├─ [windows-x64-payload]  ← PE stub + Python x64 + llama.cpp x64 + model
├─ metadata (per-arch)
└─ footer + signatures
```

**Implémentation :**
1. `--universal` flag → build matrix via `cargo zigbuild` pour chaque OS/arch
2. Assemble slices dans wrapper polyglot (MZ+ELF+Mach-O overlap header)
3. Runtime : detect `uname -s`/`uname -m` → extract right slice → `execve`
4. Test via Docker+QEMU (déjà installé : `qemu-aarch64` + `docker --platform linux/arm64/v8`)

**Status :** 30% — cross-compilation validée (seccomp.rs fix), wrapper polyglot pas implémenté.

## Ce qui est NOUVEAU — livré cette semaine

### ✅ Hot-swap modèle (`erebus swap`) — TERMINÉ

`erebus swap agent.erebus app/models/model.gguf --from new-model.gguf -o out.erebus`

- Remplace un fichier du payload sans rebuild complet : extract → replace → repack → reassemble (~1,2 s pour 3 Mo)
- L'entrée `ModelLayer` correspondante est mise à jour (size) par suffix-match de chemin
- Refuse les binaires chiffrés/squashfs, les chemins absolus et traversées `..`
- Préserve l'octet arch du footer ; droppe l'état signature/SISR (re-signer avec `--key`)
- Nettoyage post-swap : sidecar SISR périmé supprimé, re-signature optionnelle
- **10 tests chaos monkey** (`tests/swap_chaos.rs`) : troncature, corruption aléatoire ×40,
  garbage, traversal, chiffré, swaps concurrents, écriture interrompue (AtomicWriter),
  intégrité post-swap (SHA-256 + inspect), index registre corrompu, objet altéré

### ✅ Layer sharing (`erebus layer`) — TERMINÉ

Registre content-addressable local (`~/.cache/erebus/layers/`, overridable via `ERE_LAYERS_DIR`) :

- `layer push <fichier> --name X --kind model|runtime|tool|config`
- `layer list` / `layer pull <nom> -o <fichier>` / `layer remove <nom>`
- Stockage dédupliqué par SHA-256 (`objects/<hex>`), index JSON atomique (tmp+rename)
- Vérification du hash au pull/materialize — un objet altéré est détecté et refusé
- Deux agents partageant le même runtime → même blob → disque partagé, zéro duplication

### ✅ Lazy loading (mmap payload) — TERMINÉ

- Le stub mmap la plage payload au lieu de l'allouer sur le heap (`stub/src/mmap.rs`)
- RSS mesuré : **7,6 Mo** pour extraire un binaire de 21 Mo (avant : pic = taille payload)
- Fallback lecture classique si mmap indisponible ; kill switch `ERE_NO_MMAP=1`
- Limites anti-bombe ajustées : plafond relevé de la somme des `ModelLayer` déclarés
  (+64 MiB de marge), l'environnement `ERE_MAX_EXTRACT_SIZE` reste prioritaire s'il est plus grand
- 4 tests unitaires stub (roundtrip heap/mmap, kill switch, fichier tronqué)

### Validation E2E

- Binaire réel 21 Mo construit → hot-swap modèle 3 Mo → inspect/verify OK → exécution OK (« v1 »)
- Warm start OK ; `ERE_NO_MMAP=1` OK ; layer push/list/pull/remove roundtrip byte-identique

### 🔬 RISC-V 64 — support partiel (nouveau)

**Ce qui marche aujourd'hui :**

- ✅ Stub compile pour `riscv64gc-unknown-linux-musl` (statique, ~2 Mo)
  - `seccomp.rs` : `AUDIT_ARCH_RISCV64 = 0xC000_00F3` + pas de `fork`/`vfork` dans le
    deny-list exec (RISC-V n'a que `clone`/`clone3`, comme aarch64)
  - `landlock.rs` : numéros syscalls génériques 444-446
  - `main.rs` : `LD_PATHS` fallback sans dirs multiarch Debian
- ✅ Format : `ARCH_RISCV64 = 0x03` (`format.rs`), câblé dans assemble/inspect/hot-swap
- ✅ `--target riscv64gc-unknown-linux-musl` et `linux-riscv64` reconnus par `parse_target`
- ✅ E2E QEMU (`qemu-riscv64-static`) : build → hot-swap (arch préservée) → exécution OK
- ⚠️ Sandbox : `unshare(CLONE_NEWUSER)` échoue sous qemu-user (limitation émulateur,
  pas du code) → tester avec `--isolation none` sous QEMU

**Limitation connue — interpréteur embarqué cross-arch :**

`embed_interpreter` copie le `python3` **du host de build** (+ deps ldd) quelle que soit
la cible. Un agent `--target riscv64` embarque donc un interpréteur x86_64 qui ne
tournera que sur host x86_64 (ou via double émulation binfmt). C'est une validation
stub-level, pas un agent natif. Node n'a pas ce problème (téléchargement target-arch).

**Pour un support natif complet (~1-2 jours) :**

1. Source de téléchargement CPython riscv64 — python-build-standalone ne publie pas de
   builds riscv64 ; options : ports Debian riscv64, Alpine, ou cross-build CPython
2. Étendre `embed_interpreter` pour télécharger l'interpréteur de la cible (pattern
   `ensure_node()`)
3. CI matrix : ajouter riscv64 aux tests zigbuild+QEMU

## Ce qui n'est PAS prioritaire

- ❌ Autres runtimes (Node, Deno, Java, Ruby, .NET, Go, PHP, Perl, Hugo, Wasm, Electron) —
  **SUPPRIMÉS** (août 2026) : `Runtime` enum réduit à {Python, Binary}, détection + help text + pipeline + tests nettoyés.
- ❌ Flatpak/Snap (`flatpak.rs` 351 l., `snap.rs` 537 l.) — **SUPPRIMÉS** d'erebus-core + CLI flag `--package-format` retiré.
- ❌ OCI/WASM/AppImage output — non implémenté, ne pas faire
- ❌ Monorepo Turborepo/Nx — hors scope
- ❌ 50 repos GitHub trending — pas un feature produit
- ⚠️ Metrics Prometheus — `otel.rs` (121 l.) existe encore, non prioritaire
- ❌ Edge/IoT OTA channels — SISR le couvre déjà

## Risques & mitigations

| Risque | Mitigation | Status |
|---|---|---|
| llamafile ajoute delta updates | Priorité : livrer universal binary + hot-swap avant eux | Priorité #1 |
| Cross-arch embedding complexe | CI matrix zigbuild + QEMU test local | Validé |
| 2-runtime limitation | Suffisant pour 95% agents IA (Python API + llama.cpp) | Accepté |

## Stack technique (août 2026)

- **Rust 2021** stable, `opt-level="z"`, LTO, strip, `panic=abort`
- **stub** : musl static ELF, ~2 Mo (zstd+tar, seccomp BPF, Landlock), `unsafe` limité (FFI + seccomp BPF)
- **core/cli** : zero `unsafe`, ANSSI-Rust compliant
- **CI** : `cargo zigbuild` cross-compile, `cargo clippy -p {crate}`, `cargo test --workspace`
- **Tests** : 479 unit/integration/e2e/chaos, QEMU pour cross-arch validation (x86_64, aarch64, riscv64)