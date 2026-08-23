# Universal binary — cross-build & one-file-many-platforms

## Stub cross-compilation times (cargo zigbuild, cold deps)

```bash
cargo zigbuild --release -p erebus-stub --target <triple>
```

| Target triple | Binary | Time (cold) | Size |
|---|---|---|---|
| `x86_64-unknown-linux-musl` | ELF, static | ~1 min 35 s | ~2 MB |
| `aarch64-unknown-linux-musl` | ELF, static | ~1 min 49 s | ~2 MB |
| `aarch64-apple-darwin` | Mach-O | ~4 min 55 s | ~2.5 MB |
| `x86_64-pc-windows-gnu` | **PE32+ console** | ~4-5 min (full) | 2 398 720 B |

Windows port notes: MapViewOfFile mmap with 64 KiB alignment adjustment,
CreateProcessW with PATH resolution (`python3`→`python.exe`), stdio handle
inheritance, local `ProcessPrng` shim (drops the Win10+ bcryptprimitives
dependency — runs on Win7/8 and Wine).

## Universal polyglot assembly

```bash
erebus build /tmp/uni-app --universal --isolation none -o universal.erebus
# ==> assembling universal binary (4 slices)
#   linux-x86_64     18.3 MB
#   linux-aarch64    13.6 MB
#   darwin-aarch64   13.3 MB
#   windows-x86_64   13.8 MB
# Built universal4.erebus (59.0 MB)
```

Layout: `[sh-loader 32KiB][header @32768][26-byte slice entries][4K-aligned slices][footer]`.
Slice extraction verified byte-exact against the table offsets.

## One file, three platforms — same 59 MB artifact

| Slice | Environment used for validation | Result |
|---|---|---|
| linux-x86_64 | native host | `UNIVERSAL OK sys=linux py=3.10.12` |
| linux-aarch64 | Docker `--platform linux/arm64` + qemu binfmt (`python:3.12-slim`) | `UNIVERSAL OK sys=linux py=3.12.14` |
| windows-x86_64 | Wine 6.0.3 + real CPython 3.12.10 win32 embeddable | `UNIVERSAL OK sys=win32 py=3.12.10` |

Cross-platform integrity: identical `sha256(b"erebus")` computed by an
embedded `.pyd`/stdlib on every platform → payload not corrupted per-slice.

Known limits (documented, honest):

- macOS slice never executed on real Apple hardware here (cross-compiled +
  structurally inspected only).
- Double-clicking the universal file needs a POSIX shell (git-bash/WSL on
  Windows; MINGW arms are generated in the loader). cmd.exe-native `.bat`
  polyglot is future work.
- Docker+qemu gotcha: `unshare` returns EINVAL under qemu-user — test with
  bundles built `--isolation none`.
