# erebus — Ship AI Agents with Verifiable Attestation

**Google Africa Applied AI Lab Application**  
Ted Kouhouenou · Lomé, Togo · ted.kouhouenou@groupecerco.com  
`github.com/Tednoob17/erebus` · MIT licensed

---

## 1. The Problem: AI Agents Run Unverified

| Today's Reality | What Enterprises Need |
|---|---|
| `docker run` / `python app.py` → **zero proof** of what executed | **Cryptographic proof** of *what* ran, *where*, *when* |
| Model updates = re-download 8GB (expensive data plans, slow links) | **Delta updates** ~50MB for 1% change (100× bandwidth savings) |
| No audit trail for EU AI Act / SOC 2 / African regulators | **Tamper-evident attestation chain** per execution |
| Cloud-dependent inference → latency, privacy, connectivity issues | **Offline-first** single binary, runs anywhere (ARM64, x86, RISC-V) |

> **African context**: 8GB model on 4G costs ~$5–10 in data; erebus delta = ~$0.05. Offline execution = works during outages.

---

## 2. Solution: erebus = Single Binary + Attestation Chain

```
┌─────────────────────────────────────────────────────────┐
│  erebus build ./my-agent  →  my-agent.erebus (18 MB)   │
│                                                         │
│  • Python/Node/Go/binary → self-extracting ELF         │
│  • Embeds Gemma 2B/7B weights (GGUF) + llama.cpp       │
│  • SISR delta updates: 8GB model → 50MB patch          │
│  • Attestation: Ed25519 sig + SHA-256 chain + metadata │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│  ./my-agent.erebus                                      │
│  → Verifies integrity (SHA-256 + sig)                   │
│  → Extracts to ~/.cache/erebus/<hash>/                  │
│  → Executes with seccomp/landlock sandbox              │
│  → Emits .erebus.attest (signed receipt)               │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Why Africa? Why Now?

| Challenge | erebus Answer |
|---|---|
| **Bandwidth cost** | SISR delta: 1% model change = 50MB not 8GB |
| **Unreliable connectivity** | Single binary runs fully offline after first run |
| **Data sovereignty** | Model weights never leave device; attestation proves local execution |
| **Regulatory compliance** | Attestation chain = proof for AU Data Protection, GDPR, sector regulators |
| **Edge deployment** | ARM64 (Pi, Jetson) + x86 + RISC-V from one build |

> **Real use case**: Fintech in Lagos deploys fraud-detection agent to 500 PoS terminals. erebus delivers Gemma-powered model via 50MB delta, each terminal produces signed receipt per transaction. Auditor verifies offline.

---

## 4. Technical Moat: Not Packaging — Attestation

| Competitor | Packaging | Delta Updates | Attestation | Offline-First |
|---|---|---|---|---|
| Docker | ✅ | ❌ (layers) | ❌ | ❌ |
| llamafile | ✅ | ❌ | ❌ | ✅ |
| Ollama | ✅ | ⚠️ | ❌ | ✅ |
| **erebus** | ✅ | ✅ **SISR** | ✅ **Ed25519 chain** | ✅ |

**The lock-in**: Every execution appends to an immutable attestation chain. Fleet operators get a cryptographic ledger of *what ran where when* — impossible to forge, trivial to audit. The registry grows more valuable with each deployment.

---

## 5. Product: Three Tiers, Open Core Forever

| Tier | Price | Target | Includes |
|---|---|---|---|
| **Free** | $0 | OSS / hobbyists | Public packages, 10 GB/mo transfer |
| **Pro** | $29/mo | Solo devs / startups | Private packages, 1 TB SISR CDN, SBOM, attestations |
| **Team** | $99/mo | Companies / fleets | **All Pro + RBAC, audit log, webhooks, 5 TB** |
| **Enterprise** | $24k/yr | Regulated / air-gapped | Mirror, SSO/SAML, SLA, auto-compliance reports |
| **Enterprise+** | $50/node/yr | 50+ node fleets | Per-node attestation, full history |

> **MIT licensed forever** — client + server. We monetize the *hosted service* (registry, SISR CDN, compliance dashboard), not the software.

---

## 6. Traction & Technical Maturity

| Metric | Status |
|---|---|
| **Rust workspace** | 3 crates (core, CLI, stub) — 0 `unsafe` in core/CLI |
| **Tests** | 400+ unit + integration + chaos (SIGKILL mid-extraction, tampered bundles) |
| **Security** | CSO audit: 0 critical, 3 high fixed; Ed25519 v2.2 (CVE-2023-48022 mitigated) |
| **Binaries** | Universal: x86_64 + ARM64 (Linux/macOS) + Windows PE stub |
| **SISR benchmark** | Llama 3.1 8B Q4_K_M: 4.5 GB → 48 MB delta (99% savings) |
| **Registry** | Auth (scrypt), quotas, SISR stats, MCP server listing |

**Live**: `cargo install erebus` → `erebus build ./agent --embed-gemma-2b -o agent.erebus`

---

## 7. Google AI Integration: Material Usage

| Current | During Lab |
|---|---|
| Packaging runtime for local inference | **Gemma 2B/7B/27B as first-class embedded runtimes** |
| CLI `serve`/`chat` with llama.cpp | **Gemini API hybrid: cloud fallback + local Gemma** |
| No Google models | **erebus build --gemini-key → bundles API key securely** |

**Lab deliverable**: `erebus build ./agent --gemini-model gemini-1.5-flash --gemma-fallback gemma-2b` → single binary that prefers Gemini API, falls back to local Gemma offline. Attestation covers both paths.

---

## 8. Business Model: High Margin, Network Effects

| Metric | Value |
|---|---|
| **COGS** | SISR delta = ~50 MB CPU for 8 GB model ≈ $0.001 |
| **Gross margin** | >95% on Pro/Team (no GPU hosting) |
| **ARR target** | 10 Enterprise × $24k = $240k (seed viable) |
| **Expansion** | $50/node/yr × 500 nodes = $25k/yr per fleet |
| **Lock-in** | Attestation history = accumulated compliance data |

> **No GPU capex** — we're infrastructure, not inference. Our moat deepens with every deployed agent.

---

## 9. Team & Ask

**Ted Kouhouenou** — Founder/Engineer  
- 10+ yrs systems engineering (Rust, Go, distributed systems)  
- Built erebus solo: 15k+ lines Rust, 3 crates, full CI/CD, docs  
- Based in **Lomé, Togo** — full-time on erebus

**Ask from Google Africa AI Lab:**
- ✅ **Technical mentorship**: Gemini/Gemma integration, on-device optimization
- ✅ **Go-to-market**: Intro to African enterprise buyers (fintech, telco, gov)
- ✅ **Funding path**: Google AI Futures Fund + 4DX/Norrsken/Novastar/Ventures Platform
- ✅ **Credibility**: Lab participation = trust signal for regulated buyers

---

## 10. Vision: "Git Log for AI in the Physical World"

> **Every AI agent execution leaves a cryptographic receipt.**  
> Fleet operators query: "Show me all fraud-model executions in Accra last week."  
> Auditor verifies: "This binary hash matches the approved model; signature chain intact."  
> Regulator sees: "Zero tampering; full offline execution; data never left device."

**erebus makes this trivial.** One binary. One command. Verifiable everywhere.

---

**Contact**: ted.kouhouenou@groupecerco.com · `github.com/Tednoob17/erebus`  
**Demo**: `erebus build ./examples/llama-agent --gemma-2b -o agent.erebus && ./agent.erebus`  
**Deadline**: 31 Aug 2026 — ready to ship.