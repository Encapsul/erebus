# Real Execution Demo — llama.cpp inference inside a single .erebus binary

_Verification date: 2026-08-29. Runs a TinyLlama GGUF model through llama.cpp
entirely from one self-contained ELF bundle._

## What was proven

A single `agent-demo.erebus` file (640 MB), built from `examples/real-agent`,
contains the Python app, the TinyLlama weights (`model.gguf`, Q4_K), and a
bundled static `llama-cli`. Launching the file extracts the rootfs, verifies
the integrity hash, and runs real CPU inference **without any internet
access** — no pip install, no re-download of the model at runtime.

## The bundle

| Property | Value |
|---|---|
| File | `agent-demo.erebus` |
| Size | 640.6 MB |
| Format | v3 (signed, ed25519) |
| App layer | Python example + bundled llama.cpp |
| Model layer | `model.gguf` (643,728,768 B, SHA-256 `fdf50b4e…`) |
| Python runtime | SHA-256 `a33d8649…` |
| SBOM | CycloneDX 1.5 in `erebus audit` |
| Payload hash | `c2b3a4a0…` |

## Live inference (no network)

Prompt: `What is the capital of France?`

> The capital of France is Paris, located in the Île-de-France region.

Prompt: `In one sentence, what does a self-extracting binary do?`

> Self-extracting binary is an executable file that automatically unpacks
> itself into its own installation folder once it's downloaded or installed on
> a computer. It does not require any internet access or connectivity to
> function properly.

Measured ~2.3 tok/s generation, ~30 tok/s prompt processing (single CPU core,
Q4_K TinyLlama).

## Provenance (attest + audit)

- `erebus sign` — detached ed25519 signature baked into the file.
- `erebus attest` — detached `agent-demo.erebus.attest` (chain_hash
  `sha256:6bb2c472…`).
- `erebus audit` — signed report with integrity + SBOM + `attestation_chain`.

Bundle hash `sha256:5e3d4ddb…`, key fingerprint `sha256:eda789b4…`.

## Reproducing

```bash
# From examples/real-agent (host has llama-cli + model; or run download_model.sh)
/tmp/erebus-stub-target/release/erebus build . \
  -o /tmp/opencode/agent-demo.erebus --isolation none --no-install

erebus run /tmp/opencode/agent-demo.erebus &
curl -s localhost:8000/health
curl -s -X POST localhost:8000/infer -d '{"prompt":"What is the capital of France?"}'
```

> Note: this container lacks the privileges for the sandbox (isolation 2)
> pivot_root (`EINVAL`), so the demo ran with `--isolation none`. On a host
> with namespaces enabled the same bundle runs under the full sandbox.
> `examples/real-agent/Agentfile.yaml` requests `isolation: sandbox`.
