# Quickstart

## Prerequisites

- Linux x86_64
- Rust with musl target: `rustup target add x86_64-unknown-linux-musl`
- `zstd` (available on most distributions)
- C compiler (`gcc` or `musl-tools`) — required by `backhand` (squashfs)

Verify all prerequisites in one command:

```bash
make preflight      # or: erebus doctor
```

If anything is missing, auto-fix what can be installed:

```bash
erebus doctor --fix            # interactive (asks before each fix)
erebus doctor --fix --force    # non-interactive (for scripts and CI)
```

## 1. Build the launcher stub

```bash
make stub
# or: cd stub && cargo build --release --target x86_64-unknown-linux-musl
```

## 2. Build & run a Python web app

```bash
erebus build ./examples/hello-web -o hello-web.erebus

./hello-web.erebus
# Server listening on http://127.0.0.1:8080
```

Open http://127.0.0.1:8080 in your browser.

## 3. Build & run a Python app with dependencies

```bash
erebus build ./examples/bottle-web -o bottle-web.erebus

./bottle-web.erebus
# Server listening on http://127.0.0.1:8080
```

See the [Python guide](./python.md) for details on dependencies and `requirements.txt`.

## 4. Inspect a .erebus

```bash
erebus inspect hello-web.erebus
```

```
name:            hello-web
runtime:         python
entrypoint:      python3 /app/app.py
layers:
  - runtime   11.9MB compressed / 54.0MB raw
  - app        0.0MB compressed /  0.0MB raw
integrity sha256: 4232327e...
```

## 5. Sign & verify

```bash
# Generate a keypair
erebus keygen --key-dir $XDG_DATA_HOME/erebus/keys

# Sign a .erebus
erebus sign hello-web.erebus --key $XDG_DATA_HOME/erebus/keys/<fingerprint>.key

# Trust the public key (~/.erebus/trusted-keys, or $ERE_TRUSTED_DIR);
# a signed bundle refuses to start without it
erebus trust $XDG_DATA_HOME/erebus/keys/<fingerprint>.pub

# Verify
erebus verify hello-web.erebus
```

## 6. Prove what ran

```bash
KEY=$XDG_DATA_HOME/erebus/keys/<fingerprint>.key

# Run with a receipt: the launcher signs it and appends it to the trail
ERE_ATTEST_KEY=$KEY ./hello-web.erebus
# or sign one for the bundle without running it
erebus attest hello-web.erebus --key $KEY
#  output: hello-web.erebus.attest
#  trail:  hello-web.erebus.attest.d/000001-….json

erebus verify-attest hello-web.erebus.attest --bundle hello-web.erebus
#  OK: attestation verified (key: …)
erebus verify-attest --chain hello-web.erebus.attest.d
#  OK: chain verified — 1 receipt(s)
erebus verify-attest hello-web.erebus.attest --bundle other.erebus
#  TAMPERED: bundle mismatch (attestation covers sha256:…, file is sha256:…)

# One file for an auditor
erebus evidence export hello-web.erebus -o evidence.zip
erebus verify-evidence evidence.zip --bundle hello-web.erebus
```

Receipts become third-party evidence once the host is enrolled (`erebus
enroll`, machine co-signature, `--strict`) and receipts are pushed to a
registry transparency log (`--push`, `--proof`); `evidence export` then
needs the registry's `--log-key`. See
[Auditing an erebus trail](./audit.md) and the
[spec](../spec/attestation.md).

## Debug

```bash
EREBUS_VERBOSE=1 ./hello-web.erebus
# Shows cold/warm start, extraction, and cache status
```

## Incremental rebuild

The runtime layer (interpreter + stdlib + .so) is cached. Only app code is
recompressed on subsequent builds:

```bash
# First build  : ~25s (Python)
# Rebuild (code): ~1s
```