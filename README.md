# erebus

[![CI](https://img.shields.io/github/actions/workflow/status/Tednoob17/erebus/ci.yml?branch=main&label=build)](https://github.com/Tednoob17/erebus/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.5.0-green.svg)](https://github.com/Tednoob17/erebus/releases)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![Runtimes](https://img.shields.io/badge/runtimes-2-purple.svg)](#supported-runtimes)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Tednoob17/erebus/pulls)

**Package any AI agent into a single self-extracting binary.**

erebus compiles AI agents (llama.cpp + GGUF model + Python API server) into a single self-contained executable. Supported runtimes: Python (FastAPI/Flask/Django), Binary (llama.cpp inference).

The binary format (`[stub][payload][metadata][footer]`) is a universal executable artifact — capable of transporting an AI agent, its model weights, and inference engine as a single portable unit.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/Tednoob17/erebus/main/scripts/install.sh | bash
erebus doctor
cd your-app && erebus build . -o myapp.erebus
./myapp.erebus
```

### Universal binary — one file, every platform

```bash
erebus build . --universal -o agent.erebus   # linux-x64 + linux-arm64 + macos-arm64 + windows-x64 slices
./agent.erebus                                # runs natively on any of them
```

The polyglot file starts with a `#!/bin/sh` loader that routes `uname -s`/`uname -m`
to the matching native `.erebus` slice (extract once to the OS cache dir, then exec).
Cross-platform Python builds embed only portable files and use the target's own interpreter.
Windows slices ship a native PE32+ stub (CreateProcessW + MapViewOfFile); running the
universal file directly requires a POSIX shell (git-bash/WSL) — or extract the slice with
`erebus inspect --json` and run it from cmd.exe.
Windows x64 requires the upcoming PE stub port.

## Overview

erebus transforms any AI agent directory into a portable, self-extracting binary that can run on target machines without requiring the host runtime. This includes:

- **Python applications** — FastAPI, Flask, Django (API server, orchestration, tools)
- **Binary executables** — llama.cpp inference engine (model runner)
- **Namespace isolation** — user/mount namespaces + optional seccomp (not full Docker sandboxing)
- **Delta updates (SISR)** — 95% smaller model updates via content-defined chunking

The tool handles runtime detection, dependency installation, compression, and signing through a unified, language-agnostic pipeline optimized for AI agents.

## Supported runtimes

| Runtime | Detection | Framework support |
|---------|-----------|-------------------|
| Python | `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py` | FastAPI, Flask, Django |
| Binary | ELF executable (llama.cpp, etc.) | Any static or dynamic binary |

Each runtime has specific detection logic and framework support that triggers when building.

## Binary format

The `.erebus` binary is structured as:

```
[stub][payload][metadata][footer]
```

- **Stub**: statically-linked launcher — Mach-O on macOS, PE on Windows, musl ELF on Linux — that reads its own binary, verifies integrity, extracts the payload, and `execvp`s the entrypoint
- **Payload**: zstd-compressed tar archive (or squashfs) of the application + runtime
- **Metadata**: JSON with runtime info, entrypoint, layers, capabilities, version
- **Footer**: 4-byte magic `0xBEEF_CAFE`, format version, integrity SHA-256 hash

Format versions: v2 (plain), v3 (signed), v4 (encrypted), v5 (squashfs).

## Target & host support

`erebus build --target <list>` packages one artifact **per target**. A comma-separated
list emits one `<name>-<target>.erebus` per target into the output directory. The
stubs and (where available) embedded runtimes are cross-selected by target.

| `--target` short form | Resolved triple | Stub | Runtime arch | Notes |
|-----------------------|-----------------|------|--------------|-------|
| *(none)* / `host`     | host triple     | host stub | host     | Native build |
| `linux-x64`           | `x86_64-unknown-linux-musl` | ELF (static) | node x64 linux | |
| `linux-arm64`         | `aarch64-unknown-linux-musl` | ELF (static) | node arm64 linux | |
| `darwin-x64`          | `x86_64-apple-darwin` | Mach-O | node x64 darwin | macOS host runs this |
| `darwin-arm64`        | `aarch64-apple-darwin` | Mach-O | node arm64 darwin | native Apple Silicon |
| `win-x64`             | `x86_64-pc-windows-gnu` | PE (.exe) | node x64 win | cross-OS from any host |
| `win-arm64`           | `aarch64-pc-windows-gnu` | PE (.exe) | node arm64 win | cross-OS from any host |

- The builder host can be any supported OS (Linux/macOS/Windows). Cross-OS packaging
  (e.g. building a Windows `.exe` on Linux) bundles the matching stub + runtime;
  the produced artifact runs only on its target OS.
- Full triples (`aarch64-apple-darwin`, `x86_64-unknown-linux-musl`) are also accepted.

## CLI commands

| Command | Description |
|---------|-------------|
| `erebus build <dir>` | Package an app directory into a `.erebus` file |
| `erebus inspect <file>` | Read metadata from a `.erebus` file |
| `erebus scan [dir]` | Find `.erebus` files recursively and display metadata |
| `erebus sign <file>` | Sign a `.erebus` with an Ed25519 private key |
| `erebus verify <file>` | Verify the signature of a `.erebus` against trusted keys |
| `erebus keygen` | Generate an Ed25519 keypair for signing |
| `erebus trust <keyfile>` | Add a public key to the trusted keys directory |
| `erebus doctor` | Check system prerequisites and report missing dependencies |
| `erebus upgrade` | Self-update the erebus binary |
| `erebus env` | Show erebus environment and build configuration |
| `erebus clean` | Remove erebus cache and build artifacts |
| `erebus completion <shell>` | Generate shell completions for bash, zsh, fish, elvish, or powershell |
| `erebus man [dir]` | Generate man pages to the specified directory |

### Key features
- **Global `--verbose`** flag for detailed output on any command
- **`--strict`** mode on `erebus doctor` for strict validation
- **`--dry-run`** flag on build, inspect, scan for preview operations
- **`.erebus.toml`** configuration file support
- **Rust-based CLI** with zero Python dependency at runtime
- **Self-updating** via `erebus upgrade`

### Advanced build options

```bash
# Basic build
erebus build ./myapp -o myapp.erebus

# Embed interpreter for self-contained binaries
erebus build ./myapp --embed-interpreter python3 -o myapp.erebus

# Multi-arch packaging: one artifact per target
erebus build ./myapp --target linux-x64,linux-arm64 -o out/app.erebus
#  -> out/app-linux-x64.erebus, out/app-linux-arm64.erebus

# Cross-OS packaging: Windows artifact built on Linux/macOS
erebus build ./myapp --target win-x64 -o out/app.erebus
#  -> out/app-win-x64.exe (stubs+runtime selected for the target OS)

# Sign and encrypt
# `--encrypt` is obfuscation only (AES key lives in the file metadata —
# possession of the binary decrypts it). Use `--sign` for authenticity.
# `--encrypt` and `--enable-sisr` are mutually exclusive.
erebus keygen --key-dir ~/.erebus/keys
erebus build ./myapp --sign --key ~/.erebus/keys/*.key -o myapp.erebus
erebus build ./myapp --encrypt --key ~/.erebus/keys/*.key -o myapp-secure.erebus

# Self-updating binary with SISR (delta updates)
# `--enable-sisr` and `--encrypt` cannot be combined (Sisir chunking is
# incompatible with full-payload AES-GCM). Use one or the other.
erebus build ./myapp --enable-sisr --update-url https://updates.example.com -o myapp.erebus
#  -> myapp.erebus + myapp.erebus.manifest

# Persistent storage
erebus build ./myapp --persist -o myapp.erebus
#  -> ERE_PERSIST_DIR injected into app environment

# Environment injection
erebus build ./myapp --env-file .env --env KEY=VALUE -o myapp.erebus
```

### Embedded Runtime Options

The `--embed-interpreter` flag bundles an interpreter into the binary:

| Option | Description |
|--------|-------------|
| `python3` | Embed Python 3 interpreter |
| `node` | Embed Node.js runtime |
| `deno` | Embed Deno runtime |
| `ruby` | Embed Ruby interpreter |
| `php` | Embed PHP interpreter |
| `perl` | Embed Perl interpreter |
| `java` | Embed Java runtime |
| `go` | Embed Go runtime |

### Build Cache

Intelligent caching skips extraction when the app hash matches:

```bash
# Use cache for faster rebuilds
erebus build ./myapp --use-cache

# Clear cache before building
erebus build ./myapp --clear-cache
```

## Support matrix

| Host → Target | linux-x64 | linux-arm64 | macos-x64 | macos-arm64 | win-x64 | win-arm64 |
|--------------|-----------|-------------|-----------|-------------|---------|-----------|
| linux-x64    | native | cross    | cross  | cross    | cross | cross |
| linux-arm64  | cross  | native   | cross  | cross    | cross | cross |
| macos-x64    | cross  | cross    | native | cross    | cross | cross |
| macos-arm64  | cross  | cross    | cross  | native   | cross | cross |
| win-x64      | —      | —        | —      | —        | native | cross |
| win-arm64    | —      | —        | —      | —        | cross | native |

- Cross-OS builds embed the target stub + runtime; the artifact runs only on its target OS
- Cross-arch builds require `cargo zigbuild` (zig as cc/linker) for the stub; the CLI itself builds with standard `cargo`

## Configuration

Place a `.erebus.toml` in your app directory. CLI flags override config file values.

```toml
[package]
version = "1.0.0"
author = "Your Name"
description = "My awesome app"
license = "MIT"

[build]
isolation = "sandbox"
seccomp = true
encrypt = false
squashfs = false
target = "x86_64"
no_install = false
env_file = ".env"
```

### Shell completion

```bash
# Bash
erebus completion bash >> ~/.bashrc

# Zsh
erebus completion zsh >> ~/.zshrc

# Fish
erebus completion fish > ~/.config/fish/completions/erebus.fish
```

### Man pages

```bash
erebus man /usr/local/share/man/man1/
```

## Build from source

Requires Rust toolchain and `cargo`.

```bash
git clone https://github.com/Tednoob17/erebus.git
cd erebus
cargo build --release
# Binary at target/release/erebus
```

### Cargo workspace

| Crate | Purpose |
|-------|---------|
| `erebus-core` | Shared library: format, compression, detection, signing, assembly, CAS, SISR |
| `erebus-stub` | Self-extracting launcher (Linux ELF / macOS Mach-O / Windows PE) |
| `erebus-cli` | CLI tool (cross-platform) |

## Security

- **Ed25519 signing**: binaries can be signed and verified against trusted keys (`~/.erebus/trusted-keys/`, or `$ERE_TRUSTED_DIR`)
- **Encryption (obfuscation only)**: `--encrypt` uses AES-256-GCM on the payload, but the key is stored in the file's own metadata — possession of the binary is sufficient to decrypt it. It deters casual inspection, **not** an attacker who holds the file. Byte authenticity is governed by `FLAG_SIGNED` + the trusted-keys directory; `--encrypt` and `--enable-sisr` are mutually exclusive.
- **SHA-256 integrity**: footer hash verifies payload tampering at runtime
- **Namespace isolation**: Linux builds use user/mount namespaces + optional seccomp (fail-closed); macOS uses App Sandbox (`macos_sandbox`); Windows uses process isolation (`win`/supervisor). `--isolation sandbox` must not silently degrade.
- **Delta updates (Sisir)**: the stub verifies an embedded Ed25519 `SisirFooterExt.signature` (of the delta manifest) at cold start — fail-closed, with `ERE_SISR_ALLOW_UNSIGNED=1` as an explicit escape hatch for air-gapped/untrusted-update scenarios.
- **CVE-2023-48022**: ed25519-dalek pinned to >= 2.1.0 to ensure Ed25519 bit is set

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Commit with signed commits (`git commit -S -m "feat: ..."`)
4. Push and open a pull request

Run checks before submitting:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

### Coding conventions

See [CODE_STYLE.md](CODE_STYLE.md) for Rust style guidelines, best practices, and formatting rules.

## License

MIT — see [LICENSE](LICENSE) for details.
