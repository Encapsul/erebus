# HANDOFF.md — erebus project status

> Living status doc for new sessions/contributors. Last updated: 2026-08-24.

## Current state

- **Version**: 0.5.0 — ROADMAP competitive-gap items **#1–#9 all DONE**
- **Runtimes**: Python + Binary only (Node/Deno/Java/… support was removed by design)
- **Tests**: 444 workspace tests green (`cargo test --workspace --release`)
- **Quality gates**: `cargo fmt`, clippy `-D warnings` per crate, `cargo audit` RC=0
  (lru advisories cleared by ratatui 0.30.2 → lru 0.18.2)
- **Toolchain**: stable only; targets installed: x86_64/aarch64 musl (+apple via
  `rustup target add` on demand — `ensure_stub` does it automatically)

## What shipped recently (all committed on `main`)

| Feature | Proof |
|---|---|
| Universal binary `--universal` | 4 native slices in one 59 MB file; validated linux-x64 native, arm64 under qemu/docker, win-x64 under Wine with real CPython win32 |
| Windows PE stub port | MapViewOfFile mmap, CreateProcessW + PATH resolution, ProcessPrng shim (Win7/Wine compatible) |
| `erebus serve` (#5) | Multi-format engine resolution (`core/src/inference.rs`); real TinyLlama served over `/v1/chat/completions` |
| Registry + `pull`/`publish` (#6) | stdlib VPS server (`scripts/registry_server.py`), SHA-256 verified downloads |
| Agentfile.yaml (#7) | Same schema as `.erebus.toml`; CLI > file > detection |
| GPU auto-detect + `--ngl` (#8) | `core/gpu.rs`, env `ERE_GPU`/`ERE_VRAM_MB`/`ERE_NGL`, pins never overridden |
| Chat UI (#9) | TUI (ratatui/crossterm) + embedded browser UI with std-only proxy |
| Security passes | zeroization fixes (TOCTOU key writes), ANSSI panic-path cleanup, crypto proptest chaos, two process-chaos harnesses — verdicts SURVIVED |

Numbers with reproduction commands: [`benchmarks/`](benchmarks/README.md).

## Known constraints / gotchas

- **VPS disk is chronically tight** (~1–2 GB free). Before heavy builds:
  purge `/tmp/erebus-stub-target/{debug,x86_64-pc-windows-gnu}`, `~/.cache/erebus`,
  and old test bundles. Docker images (~10 GB reclaimable) belong to other tenants.
- **qemu-user**: `unshare` returns EINVAL → test ARM bundles with
  `--isolation none` inside docker.
- **Windows slice**: runs via git-bash/WSL for universal files; cmd.exe-native
  `.bat` polyglot not implemented. Wine <7 lacks WMI → avoid `platform.machine()`.
- **macOS slice**: cross-compiled + inspected, never run on real Apple hardware.
- **serve**: encrypted bundles unsupported (clear error); squashfs bundles unsupported.

## Verification loop (mandatory)

```bash
cargo fmt --check
cargo clippy -p erebus-core    --all-targets --release -- -D warnings
cargo clippy -p erebus-stub    --all-targets --release -- -D warnings   # host + zigbuild windows
cargo clippy -p erebus-cli     --all-targets --release -- -D warnings
cargo test --workspace --release
```

Chaos harnesses (should both print SURVIVED):

```bash
scripts/chaos_monkey.sh 30            # encrypted stub runtime
scripts/chaos_registry_serve.sh       # registry + pull + serve battery
```

## Repo map

| Path | What |
|---|---|
| `benchmarks/` | measured results + exact repro commands |
| `docs/src/` | mdBook (deep refresh vs current state = open follow-up) |
| `examples/real-agent/` | Flask + llama.cpp agent, TinyLlama GGUF download script, example Agentfile.yaml |
| `scripts/` | install.sh, chaos harnesses, registry server |
