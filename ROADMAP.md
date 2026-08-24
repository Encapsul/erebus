# ROADMAP — ce qu'il reste à faire

> Les items #1–#9 du roadmap initial (runtime/model/SISR/universal, serve,
> registry, Agentfile, GPU, chat UI) sont **livrés et validés** — voir
> [HANDOFF.md](HANDOFF.md) pour l'état et [benchmarks/](benchmarks/README.md)
> pour les preuves. Ce fichier ne liste QUE le restant.

## 💼 Business — Phase 1 : registry monétisable (~2 semaines)

- [x] **Auth + quotas dans `registry_server.py`** : scrypt + tokens hashés
  (comparaison constant-time), bootstrap open→auth dès le 1er compte,
  quota transfert mensuel par user (402 au dépassement), mode privé par
  package, anti-traversal/anti-litter, uploads streamés bornés
- [x] **Compteur SISR public** : `/stats` + compteurs live sur la landing
  (bytes served / full-equivalent / saved — les Range fetch deltas
  créditent l'économie)
- [x] **Landing page + waitlist** embarquées dans la registry (throttle
  3 req/min/IP) — le domaine public reste à pointer dessus
- [ ] Déployer la registry publique du VPS derrière nginx TLS (+ `ERE_REGISTRY_TOKEN`
  déjà supporté côté serveur)

## 💼 Business — Phase 2 : facturation

- [ ] Stripe Checkout + webhooks (tiers Solo 9$ / Team 49$, cf. BUSINESS.md)
- [ ] Organisations : membres, RBAC lecture/écriture par package
- [ ] Audit log téléchargeable (qui a pull/publish quoi, quand)

## 💼 Business — Phase 3 : enterprise

- [ ] Mirror air-gapped sous licence appliance (tarball signé régénérable)
- [ ] SBOM signé embarqué par bundle (liste layers + hashes, vérifiable offline)
- [ ] SSO/SAML + SLA — à la demande des premiers clients Team convertis

## 🧪 Produit

- [ ] **Pre-flight RAM/VRAM** : ✅ fait — `gpu::check_fit` compare modèle+KV
  aux probes et prévient AVANT le crash obscur du moteur
- [ ] **Runtime packs** : publier `llama-server:linux-x64|arm64|macos|win`
  en build STATIQUE CPU (zéro dépendance côté cible) comme layers
  (`erebus layer push` existe) et faire proposer par `erebus serve` le
  `pull` automatique du moteur manquant → serve 100 % turnkey zéro-install
- [ ] Polyglot `.bat` natif cmd.exe pour l'universel Windows (git-bash/WSL OK
  aujourd'hui ; arms MINGW déjà générés dans le loader sh)
- [ ] mdBook (`docs/src/`) : refresh chapitre par chapitre — guides python/binary,
  concepts, spec SISR ; introduction + bandeau déjà à jour

## 🔬 Validation résiduelle

- [ ] Slice darwin-aarch64 exécutée sur vrai Apple Silicon (cross-compilée et
  inspectée seulement ; nécessite un Mac 5 minutes)
- [ ] CI QEMU automatique pour les slices ARM (matrice docker --platform)

## 🔧 Ops / dette

- [ ] Surveiller ratatui upstream (lru 0.18 est sain ; rien à faire tant que
  cargo audit reste RC=0)
- [ ] Nettoyage disque récurrent du VPS avant chaque démo (purge
  `/tmp/erebus-stub-target`, `~/.cache/erebus`, vieux bundles de test)
