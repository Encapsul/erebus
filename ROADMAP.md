# ROADMAP — ce qu'il reste à faire

> Les items #1–#9 du roadmap initial (runtime/model/SISR/universal, serve,
> registry, Agentfile, GPU, chat UI) sont **livrés et validés** — voir
> [HANDOFF.md](HANDOFF.md) pour l'état et [benchmarks/](benchmarks/README.md)
> pour les preuves. Ce fichier ne liste QUE le restant.

## 💼 Business — Phase 1 : registry monétisable (~2 semaines)

- [ ] **Auth + quotas dans `registry_server.py`** : comptes (hash local ou
  magic-link), token par user, quota transfert 20 GB/mois Free, compteur
  d'usage par package
- [ ] **Compteur SISR public** : « Go économisés par les deltas cette semaine »
  sur la home de la registry (l'argument de vente chiffré en live)
- [ ] **Landing page + waitlist** (`erebus.dev` ou équivalent) avec le pitch
  BUSINESS.md + lien démo GitHub
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

- [ ] **Runtime packs** : publier `llama-server:linux-x64|arm64|macos|win` comme
  layers (`erebus layer push` existe) et faire proposer par `erebus serve` le
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
