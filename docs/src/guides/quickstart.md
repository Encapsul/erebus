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

# Copy public key to trusted directory
cp $XDG_DATA_HOME/erebus/keys/<fingerprint>.pub $XDG_DATA_HOME/erebus/trusted-keys/

# Verify
erebus verify hello-web.erebus
```

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