# Comparison

## erebus vs alternatives — l'angle traçabilité

| Critère | erebus | Docker | Ollama | llamafile |
|---|---|---|---|---|
| **Exécution signée** | **✅ Ed25519** | ❌ | ❌ | ❌ |
| **Attestation d'exécution** | **✅ détachée** | ❌ | ❌ | ❌ |
| **SBOM automatisé** | **✅** | ❌ | ❌ | ❌ |
| **Delta updates** | **✅ SISR** | Layer cache | Store layers | ❌ |
| **Sandbox** | **✅ seccomp+Landlock** | Namespace | ❌ | ❌ |
| **Offline verification** | **✅** | ❌ (daemon) | ❌ (daemon) | Partial |
| Fichier unique | ✅ | ❌ | ❌ | ✅ |
| Multi-runtime | ✅ Python+Binary | ✅ | ❌ (GGUF) | ❌ (C++) |

## Ce que erebus résout

Chaque outil existant résout une partie du problème. Aucun ne résout
**la traçabilité complète** :

```
                  Packaging   Delta   Sandbox   Signing   Attestation   Audit
Docker              ✅         ✅      ✅        ⚠️        ❌           ❌
Ollama              ✅         ✅      ❌        ❌        ❌           ❌
llamafile           ✅         ❌      ❌        ❌        ❌           ❌
erebus              ✅         ✅      ✅        ✅        ✅           ✅
```

## La question à toujours se poser

> *« Pourquoi pas Docker / Ollama / llamafile? »*

Réponse en une phrase : **Docker est un daemon, Ollama n'a pas de
signatures, llamafile est mono-runtime — erebus génère une preuve
signée de ce qui a exécuté, vérifiable offline, pour la conformité
réglementaire.**

## Le cas d'usage le plus prometteur

Déployer des **agents IA sur des flottes** (edge, industriel, santé,
défense) où chaque exécution doit être traçable et prouvable à un
auditeur. Aujourd'hui aucune solution ne fait ça.
