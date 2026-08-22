# Positioning

## Customer profile

Un **développeur (solo ou petite équipe)** qui construit un **agent IA local** (llama.cpp + modèle
GGUF + serveur inference + web UI) et veut le **distribuer à des collègues** ou le déployer sur
des serveurs où il ne contrôle pas l'environnement. Il ne veut pas demander à ses utilisateurs
d'installer Python, Node, un runtime, ou Docker. Il veut un fichier unique, auto-extractible, qu'il
peut signer pour prouver son origine, et mettre à jour de manière incrémentale.

## Le segment : local AI / agents IA

| | Docker | PyInstaller/pkg | llamafile | **erebus** |
|---|---|---|---|---|
| Runtime | Container daemon | Mono-language | C++ only | **Multi-runtime** |
| Delta updates | Layer cache (partial) | None | None | **SISR content-defined** |
| Sandbox | Namespace | None | None | **seccomp + Landlock** |
| Portable format | Image OCI | Executable | Single file | **Single .erebus file** |
| Self-contained | Needs daemon | Runtime bundled | All-in-one binary | **Stub + rootfs + model** |

### Qui a ce problème aujourd'hui?

1. **Développeurs d'agents IA open-source** : publient un GitHub repo avec `requirements.txt` + `model.gguf`, mais leurs utilisateurs doivent installer Python + télécharger 4GB de dépendances + le modèle. Temps de setup : 30+ minutes.

2. **Startups MLOps** : construisent des API d'inference avec llama.cpp + un serveur FastAPI, mais le déploiement sur des serveurs edge heterogènes (x64/ARM64, Linux/macOS/Windows) nécessite des builds par architecture.

3. **Équipes de prototypage** : veulent partager un agent IA expérimental entre collègues sans créer d'image Docker (trop lourd), sans PyInstaller (mono-language), sans setup manuel.

## Pourquoi maintenant?

- **Modèles GGUF font 4-70 GB** : le téléchargement est devenu le goulot d'étranglement.
- **llamafile (Mozilla-Ocho, 25k★)** : le concurrent direct, mais C++ only, pas de delta updates, pas de sandbox, pas de multi-runtime.
- **Écosystème agents IA en explosion** : LlamaIndex, LangChain, MCP — mais aucune solution de packaging pour les agent locaux.
- **Docker est trop lourd pour le laptop** : daemon, root, ressources. Un agent IA local devrait démarrer en 2 secondes, pas nécessiter un container engine.

## Pourquoi erebus?

### Against llamafile
llamafile = un binaire C++ qui package un modèle + un runtime llama.cpp. C'est fait pour tourner
un modèle, pas pour packager un agent IA complet avec serveur web + API + tools Python.

erebus = packager **n'importe quel runtime** (Python, Node, Go, Binary) + modèle + code + config
dans un format unifié, avec **delta updates Sisir** (llamafile télécharge le fichier entier à
chaque mise à jour) et **sandbox seccomp+Landlock** (llamafile n'a pas de isolation).

### Against Docker
Docker est fait pour l'orchestration, pas pour la distribution locale. Besoin d'un daemon,
de root (ou de user namespaces), de network pour pull l'image.

erebus = un fichier exécutable (`./agent.erebus`), extraction atomique, fonctionne sans daemon
et sans privilèges root (user namespaces).

### Against PyInstaller/pkg
Mono-language : PyInstaller marche pour Python, pkg pour Node. Mais un agent IA a souvent
besoin de **plusieurs langages** : llama.cpp (C++), un serveur web (Python/Node/Go), des
tools système (shell scripts), et potentiellement un modèle native binary.

erebus = multi-runtime dans un seul format. Un agent IA peut avoir un runtime Python pour l'API,
un binaire C++ pour llama.cpp, et un script Node pour un worker — le tout dans un `.erebus`.

## Pourquoi ce n'est PAS un "13e format"?

Nous ne créons pas un nouveau standard. Le format `.erebus` est :
- Un **ELF valide** (Linux) — `chmod +x && ./app.erebus` fonctionne
- Un **payload tar/zstd ou SquashFS** — décompressible avec `tar`/`unsquashfs`
- Des **signatures Ed25519 standards** — vérifiables avec la librarie crypto standard
- Un **rootfs POSIX** — pas de kernel features propriétaires

Le format existe depuis v2 (plain) → v3 (signed) → v4 (encrypted) → v5 (squashfs),
et lit les versions anciennes. Nous ne forkons jamais le format.

## Ce erebus n'est PAS

- **Pas un Docker killer** : Docker reste pour l'orchestration et multi-container.
- **Pas une VM** : on ne virtualise pas le kernel; l'app tourne sur le kernel host.
- **Pas un package manager** : pas de registry centrale requise (pour l'instant).
- **Pas desktop packaging** : AppImage/Snap/Flatpak gèrent l'intégration desktop (icônes,
  menus, X11/Wayland). erebus cible **headless web/server apps** — "je lance le binaire,
  un serveur démarre, j'ouvre mon navigateur."
- **Pas un format inter-language bridge** : erebus ne compile pas du Python vers du WASM.
  Chaque runtime marche dans son propre environnement (Python/venv, Node/node_modules, Go/binary).

## The most promising use case

Distributing **local AI models + agents** : packager `llama.cpp` + un modèle GGUF multi-GB +
un serveur web (FastAPI/Flask/Express) + des tools Python/Go, dans un seul fichier qui démarre
avec `./agent.erebus` et qui se met à jour via Sisir delta updates (15MB au lieu de 4GB).

Aujourd'hui ce cas a pas de solution clean :
- Docker : trop lourd, daemon requis, pas fait pour laptop
- AppImage : pas fait pour des gros fichiers (50GB modèles)
- PyInstaller : mono-language, peut pas gérer le binaire C++ llama.cpp + le serveur Python

erebus's architecture est naturellement adaptée : le SISR chunk engine est fait pour les gros
fichiers (FastCDC content-defined chunking), l'encryption AES-256-GCM protège les poids,
la sandbox seccomp+Landlock isole l'exécution.
