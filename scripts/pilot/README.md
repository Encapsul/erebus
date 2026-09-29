# T2 internal pilot

This is the operational harness for ROADMAP §7.3 T2. It runs a real
Apache-2.0 model, records one signed receipt per inference call, publishes
each receipt into the transparency log, stores the verified inclusion proof
beside it, and measures the pilot from those files.

The pilot is complete only when `report.py` observes all of:

- at least 3 independently enrolled machines;
- at least 28 elapsed days;
- at least one real inference receipt;
- zero `verify-attest --strict --proof` failures.

## Machine 1: registry and node

Build/install erebus and llama.cpp's `llama-server`, then:

```bash
scripts/pilot/registry.sh start
scripts/pilot/node-setup.sh
scripts/pilot/serve.sh start
scripts/pilot/probe.sh "Pourquoi une preuve d'exécution est-elle utile ?"
python3 scripts/pilot/report.py
```

The setup downloads the pinned
[`PleIAs/Baguettotron-GGUF`](https://huggingface.co/PleIAs/Baguettotron-GGUF)
Q8 model (321 M parameters, 344 MB), verifies its SHA-256, enrolls this host,
builds and signs the bundle, and keeps all mutable state under
`~/.local/share/erebus/pilot`. The model cache lives under
`~/.cache/erebus-pilot`; neither keys, tokens, models nor receipts enter git.

The local registry binds `127.0.0.1:8787`, anchors every receipt through
FreeTSA, and stores its SQLite database persistently. Use it for the first
node only. A real three-machine pilot needs the registry on a durable,
reachable host:

```bash
ERE_PILOT_REGISTRY_HOST=0.0.0.0 \
ERE_PILOT_REGISTRY_URL=https://proof.example.com \
ERE_PILOT_STATE=/var/lib/erebus-pilot \
scripts/pilot/registry.sh start
```

Put TLS/reverse-proxy authentication in front of the Python service. Never
commit or send `registry.token`, operator keys, or machine keys over an
untrusted channel.

## Machines 2 and 3

Copy only the registry token through a secure channel, then run on each host:

```bash
export ERE_PILOT_REGISTRY_URL=https://proof.example.com
export ERE_PILOT_TOKEN_FILE=/secure/path/registry.token
scripts/pilot/node-setup.sh
scripts/pilot/serve.sh start
scripts/pilot/probe.sh "Donne trois risques d'un agent autonome."
```

Each host generates its own machine key locally; that private key never
leaves the host. Do not copy machine directories between nodes.

## Server deployment (systemd + TLS)

[`deploy/`](deploy/) holds the units used on the pilot's registry host,
installed under `/opt/erebus-pilot` and run as a dedicated `erebus` system
user: `erebus-registry.service` (registry bound to `127.0.0.1:8787`, RFC 3161
anchoring on every receipt), `erebus-node.service` (`serve.sh foreground`),
and `erebus-probe.timer` (daily probe + `report.py`). `Caddyfile.example`
terminates TLS and exposes only `/health`, `/log/*`, `/attestations*` and
`/machines*`; every other registry surface answers 403. The host firewall
must allow inbound 80/443 for the ACME certificate.

## Daily probe and evidence

Run `probe.sh` from cron/launchd at least once a day. The inference response is
stored under `pilot/probes/`; the signed receipt and proof are stored under
`pilot/receipts/`. Publication is immediate. If the registry was temporarily
unreachable, the local receipt remains in the chain and `serve` retries every
missing proof on its next start.

```bash
scripts/pilot/serve.sh restart
python3 scripts/pilot/report.py
```

Only numbers printed by `report.py` should appear in a pitch. Until the gates
are met, say “pilot running”, not “T2 complete”.
