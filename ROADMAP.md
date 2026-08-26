# ROADMAP — Plan d'exécution

> Mis à jour le 2026-08-26. Le produit pivote vers la conformité IA.
>
> **Tagline :** *« Sign. Track. Prove. — Ship AI agents with verifiable attestation. »*

## 🎯 Vision long terme

**Erebus = le "git log" pour l'IA dans le monde physique.**

Chaque exécution d'agent erebus génère une attestation signée prouvant
ce qui a exécuté, où, quand, et que ce n'a pas été altéré. Les entreprises
réglementées ont besoin de cette traçabilité pour se conformer à
l'EU AI Act, SOC 2 et aux marchés publics.

**Le vrai produit n'est pas le packaging — c'est la chaîne de traçabilité signée.**
Le packaging est la démo. La preuve est le business.

### Le vrai moat (pas SISR)

SISR est commoditisé (XetHub sur HF, Ollama layers, Git LFS). Notre moat
est la **chaîne d'attestation d'exécution** : chaque `.erebus` + `.erebus.attest`
forme une preuve cryptographique vérifiable offline. Plus le registre grossit,
plus l'historique de conformité est riche → lock-in naturel.

### ICP cible

| Segment | Budget | Motion | Cycle |
|---|---|---|---|
| ~~Devs OSS / hobbyistes~~ | Free | Bottom-up | — |
| **Enterprise regulated** | $15–50k/an | Sales + design partners | 3–6 mois |
| **Flottes industrielles/edge** | $50/nœud/an | Ops management | 1–3 mois |
| **Pro (solos/équipes agiles)** | $29/mois | PLG | Immédiat |

---

## 📦 Ce qui est déjà livré (v0.5.0)

Les items #1–#9 du roadmap initial sont **terminés et validés** :

| Feature | Proof |
|---|---|
| Universal binary `--universal` | 4 native slices dans un fichier de 59 MB |
| Windows PE stub port | MapViewOfFile, CreateProcessW, ProcessPrng shim |
| `erebus serve` | Multi-format engine resolution, TinyLlama E2E |
| Registry + `pull`/`publish` | stdlib VPS server, SHA-256 verified |
| Agentfile.yaml | Même schéma que `.erebus.toml` |
| GPU auto-detect + `--ngl` | `core/gpu.rs`, env `ERE_GPU`/`ERE_VRAM_MB`/`ERE_NGL` |
| Chat UI | TUI ratatui + browser UI |
| Security passes | zeroization, ANSSI, chaos harnesses SURVIVED |
| Auth + quotas registry | scrypt, bearer tokens, quota mensuel |
| Compteur SISR public | `/stats` + landing page |

Voir [HANDOFF.md](HANDOFF.md) et [benchmarks/](benchmarks/README.md) pour les preuves.

---

## 🏗️ Phase 1 : Nettoyage identitaire (docs)

**Objectif :** une seule identité produit. Zéro contradiction.

### 1.1 Fixer l'ICP unique

- [ ] `docs/src/concepts/positioning.md` : Réécrire l'ICP autour de
  « opérateur d'IA qui déploie des agents sur des flottes et doit prouver
  à un auditeur ce qui a exécuté ». Garder llamafile/Docker comme
  comparaison mais cadrer sur traçabilité signée.
- [ ] `docs/src/concepts/problem.md` : Réécrire — le problème n'est pas
  « it works on my machine » mais « comment prouver à un auditeur que
  cet agent IA a tourné correctement sur cette machine ».
- [ ] `docs/src/comparison.md` : Supprimer « AI-powered dependency detection »
  (plus implémenté), supprimer « Phase 2 » pour les signatures (déjà faites).
  Réécrire autour de la traçabilité.
- [ ] `docs/src/introduction.md` : Supprimer l'aveu de contenu obsolète.

### 1.2 Uniformiser .erebus

- [ ] `docs/src/concepts/problem.md` : `.ere` → `.erebus`
- [ ] `docs/src/reference/format.md` : `.ere` → `.erebus`
- [ ] `docs/src/concepts/sisr-overview.md` : `.ere` → `.erebus`
- [ ] `docs/src/concepts/architecture.md` : `.ere` → `.erebus`
- [ ] `docs/src/SUMMARY.md` : `.ere` → `.erebus` dans les titres
- [ ] `CHANGELOG.md` : Renommer « x.bin » → « erebus »
- [ ] `MISSION_LOG.md` : Renommer « x.bin » → « erebus »

### 1.3 Fixer l'acronyme SISR

- [ ] `README.md:137` : « Self-Incremental Self-Repair » →
  « Self-Incremental Sovereign Reconstruction »

### 1.4 Supprimer les runtimes morts

- [ ] `docs/src/SUMMARY.md` : Supprimer les guides Node.js, Java, Ruby,
  .NET, Deno, PHP, Perl (garder Python + Binary)
- [ ] `docs/src/concepts/positioning.md` : Supprimer Node, Go de la liste
- [ ] `docs/src/concepts/problem.md` : Supprimer Node.js, Java, Ruby

### 1.5 Nouveau pitch BUSINESS.md

- [ ] Réécrire `BUSINESS.md` slide YC et ICP :
  « Nous fournissons la preuve cryptographique de ce qui a exécuté dans
  chaque agent IA, sur chaque machine, à chaque instant. Les entreprises
  réglementées ont besoin de cette traçabilité pour se conformer à
  l'EU AI Act, SOC 2 et aux marchés publics. Notre format binaire
  génère cette preuve en arrière-plan — gratuitement en open source,
  payant en hébergé avec conformité et audit trail. »

### 1.6 Nettoyage MISSION_LOG.md

- [ ] Ajouter en haut : « Ce document couvre les missions techniques initiales.
  Le produit a depuis pivoté vers la conformité IA — voir BUSINESS.md. »

---

## 🔐 Phase 2 : `erebus attest` — preuve d'exécution signée

**Objectif :** générer un artefact signé prouvant ce qui a exécuté.

### Architecture

```
erebus attest <file.erebus> [-o <output.json>] [--key <key>]

→ Lit le binaire
→ Extrait : hash_payload, metadata (runtime, entrypoint, layers)
→ Récupère : machine_id_hash (jamais hostname en clair), OS, arch, timestamp
→ Signe avec Ed25519
→ Écrit un fichier .erebus.attest (JSON signé, DÉTACHÉ du binaire)
```

### Structure du document d'attestation

```json
{
  "spec_version": "1.0",
  "attestation_type": "erebus-execution",
  "artifact": {
    "bundle_hash": "sha256:<hash binaire complet>",
    "payload_hash": "sha256:<payload_sha256 du footer>",
    "metadata_hash": "sha256:<hash metadata JSON>",
    "format_version": 3,
    "flags": ["signed", "sisr"]
  },
  "provenance": {
    "builder": "erebus-cli v0.5.0",
    "build_created": "2026-08-24T10:00:00Z",
    "author": "declared in metadata or null",
    "license": "declared in metadata or null",
    "layers": [
      {"name": "runtime/python3", "kind": "runtime", "sha256": "..."},
      {"name": "model/llama-3.1-8b", "kind": "model", "sha256": "..."}
    ]
  },
  "execution": {
    "attested_at": "2026-09-15T14:32:00Z",
    "machine_id_hash": "sha256:<SHA-256(hostname + os + arch)>",
    "os": "linux",
    "arch": "x86_64"
  },
  "signature": {
    "algorithm": "ed25519",
    "key_fingerprint": "sha256:<fingerprint clé publique>",
    "signature_hex": "<64 bytes hex>"
  }
}
```

### Fichiers

- [ ] `erebus-core/src/attest.rs` : **Nouveau module.** Types `Attestation`,
  `ArtifactInfo`, `ProvenanceInfo`, `ExecutionInfo`, `SignatureInfo`.
  Fonctions `generate_attestation()`, `serialize_attestation()`,
  `verify_attestation()`. Zéro unsafe.
- [ ] `erebus-core/src/lib.rs` : Ajouter `pub mod attest;`
- [ ] `erebus-cli/src/commands/attest.rs` : **Nouvelle commande.**
- [ ] `erebus-cli/src/commands/mod.rs` : Ajouter `pub mod attest;`
- [ ] `erebus-cli/src/main.rs` : Ajouter `Attest` au enum `Subcommand`

### Tests

- [ ] Unit core : roundtrip generate → serialize → parse → verify
- [ ] Unit core : signature corrompue → erreur
- [ ] Integration CLI : build → sign → attest → verify-attest
- [ ] Proptest : document valide après serialization

---

## 📋 Phase 3 : `erebus audit` — rapport de conformité

**Objectif :** agréger attestations + SBOM + chaos tests en un document signé.

### Architecture

```
erebus audit <file.erebus> [--attest-dir <dir>] [-o <output.json>]

→ Lit le binaire
→ Génère un SBOM (couches + hashes + licences)
→ Lit les attestations existantes
→ Agrège les résultats
→ Produit un document "audit report" structuré
→ Signe avec Ed25519
```

### Structure du rapport

```json
{
  "spec_version": "1.0",
  "report_type": "erebus-audit",
  "artifact": { "..." : "..." },
  "sbom": {
    "format": "erebus-sbom/v1",
    "components": [
      {"type": "runtime", "name": "python3", "hash": "sha256:...", "license": "PSF-2.0"},
      {"type": "model", "name": "llama-3.1-8b", "hash": "sha256:...", "license": "Llama-3.1"}
    ]
  },
  "attestation_chain": {
    "count": 5,
    "first": "2026-09-01T00:00:00Z",
    "last": "2026-09-15T14:32:00Z",
    "chain_hash": "sha256:..."
  },
  "integrity": {
    "payload_sha256": "sha256:...",
    "signed": true,
    "sisr_enabled": true
  },
  "resilience": {
    "chaos_test_available": true,
    "verdict": "SURVIVED"
  },
  "signature": { "..." : "..." }
}
```

### Fichiers

- [ ] `erebus-core/src/audit.rs` : **Nouveau module.** Types `AuditReport`,
  `SbomEntry`, `AttestationChain`. Fonctions `generate_sbom()`,
  `aggregate_attestations()`, `generate_audit_report()`.
- [ ] `erebus-core/src/lib.rs` : Ajouter `pub mod audit;`
- [ ] `erebus-cli/src/commands/audit.rs` : **Nouvelle commande.**
- [ ] `erebus-cli/src/commands/mod.rs` : Ajouter `pub mod audit;`
- [ ] `erebus-cli/src/main.rs` : Ajouter `Audit` au enum `Subcommand`

---

## 🌐 Phase 4 : Registry MCP servers

**Objectif :** premier registry public de MCP servers. Virale. Gratuit.

### Architecture

Extension du serveur existant (`scripts/registry_server.py`). Pas de
nouveau serveur. Les MCP servers sont des `.erebus` avec métadonnées MCP
dans `meta/<name>.mcp.json`.

### Nouveaux endpoints

| Endpoint | Méthode | Description |
|---|---|---|
| `GET /mcp` | GET | Liste tous les MCP servers |
| `GET /mcp/<name>` | GET | Détails (description, tools, transport) |
| `POST /mcp` | POST | Upload un MCP server |
| `GET /mcp/<name>/install` | GET | Script d'installation 1 ligne |

### Métadonnées MCP

```json
{
  "name": "my-mcp-server",
  "version": "1.0.0",
  "description": "MCP server for GitHub integration",
  "tools": ["create_issue", "list_repos"],
  "transport": "stdio",
  "runtime": "python",
  "tags": ["github", "dev-tools"]
}
```

### Fichiers

- [ ] `scripts/registry_server.py` : Ajouter routes `/mcp`, parsing MCP,
  champ `mcp` dans le package index
- [ ] `scripts/registry_server.py` : Étendre landing page avec section MCP

---

## 📊 Phase 5 : Benchmark SISR public

**Objectif :** prouver le delta SISR sur un vrai modèle 8GB.

### Métriques

| Mesure | Détail |
|---|---|
| Modèle | Llama 3.1 8B Q4_K_M (~4.5GB) ou Qwen 2.5 14B (~8GB) |
| Taille bundle complet | Mesurer |
| Taille delta (1% changement) | Mesurer avec SISR |
| Économie % | Calculer |
| vs HF Xet | Comparer si possible |
| vs Ollama pull | Comparer |
| Cold start / warm | Mesurer |

### Fichiers

- [ ] `benchmarks/sisr-model.md` : Benchmark complet avec repro
- [ ] `scripts/bench_sisr_model.sh` : Script automatisé

---

## 🔄 Business — étapes restantes

### Tier 1 : Registry monétisable

- [x] Auth + quotas (scrypt, bearer tokens, quota mensuel)
- [x] Compteur SISR public + landing page
- [ ] Déployer registry publique derrière nginx TLS

### Tier 2 : Facturation

- [ ] Stripe Checkout + webhooks (Pro $29, Team $99)
- [ ] Organisations : membres, RBAC
- [ ] Audit log téléchargeable

### Tier 3 : Enterprise

- [ ] Mirror air-gapped sous licence appliance
- [ ] SBOM signé embarqué par bundle
- [ ] SSO/SAML + SLA

---

## 🔬 Validation résiduelle

- [ ] Slice darwin-aarch64 exécutée sur vrai Apple Silicon
- [ ] CI QEMU automatique pour les slices ARM

## 🔧 Ops / dette

- [ ] Surveiller ratatui upstream
- [ ] Nettoyage disque récurrent du VPS
