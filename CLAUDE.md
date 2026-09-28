# CLAUDE.md

This file provides guidance to Claude Code when working with the x.bin codebase.

## Project Overview

erebus is the proof layer for AI execution: it packages an agent into a single
self-extracting, sandboxed binary and emits a signed, hash-chained receipt of
every execution. Runtimes detected: Python and native Binary only.
**Read `ROADMAP.md` §0–§3 first** — priorities are strict (P0 proof chain),
everything in §4 is frozen.

## Architecture

- `erebus-core/` — Core library (format, detect, compress, encrypt, SISR, assembly; proof: `attest`, `attest_log`, `intoto`, `jcs`, `dsse`, `merkle`, `rootfs_merkle`, `log_proof`, `machine`)
- `erebus-cli/` — CLI tool (clap-based; proof commands: keygen/sign/verify/trust/attest/verify-attest/attest-history/enroll/audit)
- `scripts/registry_server.py` — stdlib-only registry: packages, auth, SQLite Merkle transparency log (`/log/*`), RFC 3161 anchoring, machine enrollment (`/machines/*`)
- `erebus-stub/` — Launcher (ELF/Mach-O/PE; the only crate with `unsafe`)

## Build Commands

```bash
make preflight    # Check toolchain
make stub         # Build stub for current arch
make build        # Full pipeline: preflight + stub + cargo build
make test         # Full verification: lint + fmt + clippy + cargo test + python test
make lint         # Run all linters (cargo fmt + clippy + ruff + black)
make fmt          # Auto-format all code
```

## Verification Loop (MANDATORY)

Before finishing any code change, run:
1. `cargo fmt --check`
2. `cargo clippy -p erebus-core --all-targets -- -D warnings` (then `erebus-cli`, `erebus-stub`)
3. `cargo test --workspace` (on macOS hosts the stub e2e / engine tests need a Linux stub and `llama-server`; the attestation suites `attest*`, `attest_log`, `jcs`, `dsse`, `machine`, `merkle*`, `log_proof`, `tests/attest_e2e.rs`, `tests/attest_proof_e2e.rs`, `tests/attest_strict_e2e.rs` must always pass) and `python3 scripts/test_transparency_log.py` (must print `VERDICT: SURVIVED`)
4. `erebus build examples/hello-web -o /tmp/test.erebus && erebus inspect /tmp/test.erebus`

## Claude Code Architecture (Command → Agent → Skill)

This project uses the **Command → Agent → Skill** orchestration pattern from the reference architecture:

### Commands (Entry Points)
| Command | Purpose |
|---------|---------|
| `/erebus-build` | Build a .erebus binary |
| `/erebus-verify` | Verify integrity |
| `/erebus-new-runtime` | Add new runtime |
| `/erebus-new-command` | Add new CLI command |
| `/erebus-security-audit` | Security audit |
| `/erebus-benchmark` | Performance benchmark |
| `/erebus-full-build` | Full build orchestration (Command → Agent → Skill) |
| `/erebus-test-app` | Test app from GitHub |
| `/erebus-new-runtime-full` | Add runtime with full orchestration |

### Agents (Specialized Workers)
| Agent | Purpose | Skills | Memory |
|-------|---------|--------|--------|
| `security-auditor` | ANSSI-Rust compliance | anssi-rust, security-audit | project |
| `runtime-detector` | Runtime detection logic | runtime-detection | project |
| `build-pipeline` | Build pipeline | erebus-format, verification-loop | project |
| `cli-command` | CLI command design | clig-conventions | project |
| `test-runner` | Verification loop | verification-loop | project |

### Skills (Knowledge Bundles)
| Skill | Purpose |
|-------|---------|
| `anssi-rust` | 41 ANSSI rules |
| `erebus-format` | Binary format specification |
| `runtime-detection` | Runtime detection rules |
| `verification-loop` | Verification checklist |
| `security-audit` | Security audit checklist |
| `clig-conventions` | CLI design conventions |
| `python-security` | Python security rules |

### Hooks (Automation)
- **PreToolUse**: Validates file edits for ANSSI-Rust compliance
- **PostToolUse**: Logs tool execution results
- **UserPromptSubmit**: Logs user prompts for audit trail
- **Stop**: Logs session stops
- **SubagentStart/SubagentStop**: Logs subagent invocations
- **SessionStart/SessionEnd**: Logs session lifecycle

### Agent Memory (Persistent)
All agents have `memory: project` — they remember findings across sessions:
- Security audit history
- Runtime detection accuracy
- Build performance trends
- CLI command evolution

### Context Forking
Use `context: fork` for isolated subagent contexts when running parallel tasks.

## Security Rules

- No `unsafe` in `erebus-core/` (only `stub/src/main.rs`)
- All `unsafe` blocks must have `SAFETY` comments
- Ed25519 keys must have the Ed25519 bit set (CVE-2023-48022)
- No hardcoded secrets anywhere in the codebase
- Use `cargo audit` periodically for dependency vulnerabilities

## Linting & Formatting

### Rust
- `cargo fmt --check` — formatting
- `cargo clippy --all-targets -- -D warnings` — linting
- Edition 2021, `opt-level = "z"`, LTO, strip, `panic = "abort"`

### Python (legacy CLI)
- `ruff check erebus/` — linting (E/W/F/I/UP/B/SIM/RUF)
- `black --check erebus/` — formatting (88-char line length)
- Type hints mandatory on all functions
- Function length ≤ 40 lines

### CI (GitHub Actions)
- `.github/workflows/ci.yml` runs on push/PR to main
- Jobs: preflight, rust, python, build (end-to-end)
- PRs that fail CI cannot be merged

## Benchmarking

Benchmarks in `benchmarks/` measure:
- Build time (seconds)
- Output size (MB)
- Peak RSS (MB)
- Cold/warm start time
- Native vs erebus comparison

Run: `bash benchmarks/run.sh`

Machine specs affect results:
- Xeon 32 cores: < 25s build
- Typical laptop: < 60s build
- Constrained hardware: < 2min build

## External References

- [clig.dev](https://clig.dev) — CLI design conventions
- [POSIX.1-2017 Ch.12](https://pubs.opengroup.org/onlinepubs/9799919797/) — Shell & Utilities
- [ANSSI-Rust](https://anssi-fr.github.io/rust-guide/) — Rust security guidelines
- [Google Doc Style](https://developers.google.com/style) — Documentation style
- [12-Factor CLI](https://medium.com/@jdxcode/12-factor-cli-apps-dd3c227a0e46) — CLI best practices
