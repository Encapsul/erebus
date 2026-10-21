# Packaging a Native Binary

`erebus` can package a pre-compiled native binary into a self-extracting
executable. No runtime embedding is needed — just the binary and its shared
libraries (when dynamic).

## Detection

The builder detects a native binary when **exactly one** ELF, PE (`.exe`), or
Mach-O (thin or universal) executable is found at the app root and no Python
runtime is detected. Two or more native binaries (for example PE + ELF) is an
error: keep a single entry binary or add a Python entrypoint.

```
my-binary/
  my-app          ← ELF / PE / Mach-O (auto-detected)
  libfoo.so       ← optional shared library (ELF builds)
```

## Build

```bash
erebus build ./my-binary -o my-binary.erebus
```

The builder:

1. detects the binary via magic bytes (`\x7fELF`, `MZ`, Mach-O);
2. resolves shared library dependencies via the ELF analyzer (Linux ELF);
3. packages the binary + libraries into the app layer;
4. compresses and assembles the `.erebus`.

## How it works

No runtime interpreter is embedded. The launcher:

1. extracts the binary and its `.so` dependencies to the cache;
2. sets `LD_LIBRARY_PATH` to include the extracted library directories (Unix);
3. `execvp`s the binary directly.

## Shared library resolution

The Rust ELF analyzer reads `DT_NEEDED`, `DT_RPATH`, and `DT_RUNPATH`
entries from the ELF header to find all transitive shared library dependencies.
No host `ldd` is required.

```bash
erebus inspect my-binary.erebus
# layers:
#   - app    2.1MB compressed / 8.4MB raw  (binary + .so files)
```

## Cross-compilation

Native binaries cannot be cross-compiled by `erebus` — the binary must already be
built for the target architecture. Use `erebus build --target aarch64` only for
interpreted runtimes (Python) where the interpreter can be downloaded for
the target arch.

## Known limitations

- **Stub vs payload ABI**: the Linux launcher stub is a **musl static-pie**.
  A stale **glibc**-linked stub (or mixing a glibc payload interpreter with the
  wrong stub) fails at launch — rebuild with `make stub` /
  `--target $(uname -m)-unknown-linux-musl`. See `AGENTS.md`.
- Windows packaging of PE is build-host detection only; the production launcher
  path targeted in CI is Linux. Do not assume PE redistributables are supported
  end-to-end.
- Mach-O is detected for macOS agent binaries; sandbox/isolation differs from
  Linux `pivot_root`.
- Statically linked binaries (no `.so` dependencies) work — the smallest
  possible `.erebus`.
- Binaries with unusual loader paths (`/lib/ld-linux.so.2`) may need the
  loader embedded in the rootfs.
- **PyInstaller onefile** and **`.pyz` zipapps** are refused at detect time —
  package the Python sources (or a plain native binary) instead.
