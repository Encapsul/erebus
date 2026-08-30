# Roadmap — erebus

## Légende

| Status | Meaning |
|--------|---------|
| ✅ Done | Implémenté et testé |
| 🔄 In Progress | En cours de dev |
| ⏳ Pending | Planifié, pas commencé |
| 🆕 New | Nouvelle feature identifiée via audit concurrents |

---

# erebus — Roadmap

## P0 — Core CAS + AI-first features (MVP)

| # | Item | Status | Source | Notes |
|---|------|--------|--------|-------|
| 1 | Core CAS engine (content-addressed storage) | ✅ Done | core | `cas.rs`, `DiskObjectStore` existent |
| 2 | Chunk deduplication (FastCDC) | ✅ Done | core | `sisr_stage.rs` chunking |
| 3 | SHA-256 integrity verification | ✅ Done | core | Partout dans le codebase |
| 4 | Ed25519 signing | ✅ Done | core | `sign.rs`, `verify.rs` |
| 5 | HTTP registry server (push/pull/list) | ✅ Done | cli | `registry.rs`, `serve.rs` |
| 6 | Bearer token auth | ✅ Done | cli | Remote HTTP registry |

---

## P1 — Model lifecycle + governance (ai-model-registry, Shardline)

| # | Item | Status | Source | Competitor | Notes |
|---|------|--------|--------|------------|-------|
| 7 | Artifact states: acquired → quarantined → trusted → revoked → deleted | ✅ Done | Audit | ai-model-registry | Core trust model |
| 8 | Policy-gated promotion pipeline | ✅ Done | Audit | ai-model-registry | Only `trusted` artifacts served |
| 9 | Fail-closed auth (mutations blocked without token) | ✅ Done | Audit | ai-model-registry | Default-deny |
| 10 | Soft-delete with audit trail | 🆕 New | Audit | ai-model-registry | Metadata retained |
| 11 | GGUF guard integration (per-tensor manifest) | 🆕 New | Audit | ai-model-registry | For GGUF models |
| 12 | Model metadata: format, size, source, scan_results | 🆕 New | Audit | ai-model-registry | Rich artifact metadata |
| 13 | Periodic integrity verification (systemd timer) | 🆕 New | Audit | ai-model-registry | Auto-quarantine on hash mismatch |

---

## P2 — Multi-protocol frontends (Shardline)

| # | Item | Status | Source | Competitor | Notes |
|---|------|--------|--------|------------|-------|
| 14 | HuggingFace Hub API compatibility | 🆕 New | Audit | Shardline | Drop-in for `huggingface-cli` |
| 15 | OCI Distribution frontend | 🆕 New | Audit | Shardline | `docker push/pull` compatible |
| 16 | Git LFS frontend | 🆕 New | Audit | Shardline | For model versioning in Git |
| 17 | S3-compatible frontend | 🆕 New | Audit | Shardline | S3 API for lakehouse clients |
| 18 | Bazel HTTP remote cache frontend | 🆕 New | Audit | Shardline | For CI build caching |

---

## P3 — Security + operations (Shardline, Harbor)

| # | Item | Status | Source | Competitor | Notes |
|---|------|--------|--------|------------|-------|
| 19 | Pluggable auth: HMAC, Ed25519, OIDC, JWKS | 🆕 New | Audit | Shardline | Multi-provider auth |
| 20 | Provider integration (GitHub/GitLab/Gitea webhooks) | 🆕 New | Audit | Shardline | Token issuance + repo-scoped auth |
| 21 | RBAC (roles: admin, writer, reader, verifier) | 🆕 New | Audit | Harbor | Project-level isolation |
| 22 | CVE scanning for model artifacts | 🆕 New | Audit | Hanzo Registry | Scan GGUF/safetensors for vulnerabilities |
| 23 | Provenance attestations (SBOM, Sigstore) | 🆕 New | Audit | ai-model-registry | Signed provenance chain |
| 24 | Garbage collection (bit-rot detection + cleanup) | 🆕 New | Audit | Shardline | Unreachable object reclamation |
| 25 | Backup/restore manifest | 🆕 New | Audit | Shardline | Disaster recovery |
| 26 | Health checks + readiness probes | 🆕 New | Audit | Shardline | `/health`, `/ready` |
| 27 | Webhooks (on promote, quarantine, delete) | 🆕 New | Audit | Harbor | Event-driven workflows |

---

## P4 — Polish + distribution

| # | Item | Status | Source | Notes |
|---|------|--------|--------|-------|
| 28 | CLI: `erebus push/pull/list/search` | 🆕 New | Stratégie | User-friendly CLI |
| 29 | CLI: `erebus verify`, `erebus promote`, `erebus quarantine` | 🆕 New | Audit | ai-model-registry workflow |
| 30 | Web UI (minimal, dashboard) | 🆕 New | Stratégie | Browser-based management |
| 31 | Air-gap sync (encrypted USB transfer, like Buncker) | 🆕 New | Audit | Buncker delta sync |
| 32 | Kubernetes operator / Helm chart | 🆕 New | Audit | Shardline, Harbor | Production deploy |
| 33 | Replication (multi-node, cross-region) | 🆕 New | Audit | Harbor | High availability |
