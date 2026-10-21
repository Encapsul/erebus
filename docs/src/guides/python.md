# Building a Python App

## Expected structure

`erebus` detects a Python app by the presence of an entry point at the root:
`app.py`, `main.py`, `server.py`, `__main__.py`, `manage.py`, or an
**extensionless script** whose shebang is `python` / `python3`
(for example `#!/usr/bin/env python3`). Marker files `pyproject.toml`,
`setup.py`, and `requirements.txt` also select the Python runtime.

```
my_app/
  app.py            ← entry point, auto-detected
  ...               ← other modules, templates, assets
```

## Build

```bash
erebus build ./my_app -o my_app.erebus
```

The builder:

1. detects the `python` runtime and entrypoint (`/app/app.py`);
2. embeds the build machine's `python3` interpreter;
3. embeds the **stdlib** (`/usr/lib/pythonX.Y`);
4. resolves `.so` dependencies via the ELF analyzer (libc, etc.);
5. compresses and assembles the `.erebus`.

## Environment variables

The builder injects `PYTHONUNBUFFERED=1` (real-time logs) and
`PYTHONDONTWRITEBYTECODE=1` by default. Your app reads its own variables normally:

```python
import os
PORT = int(os.environ.get("PORT", "8080"))
```

```bash
PORT=9000 ./my_app.erebus
```

## Third-party dependencies (site-packages)

`erebus` embeds third-party dependencies from, in order of merge:

1. a vendored `site-packages/` directory at the app root (copied with the app);
2. a virtualenv `.venv/` or `venv/` at the app root → its
   `lib/pythonX.Y/site-packages` (or `Lib/site-packages` on Windows layouts).

The full `.venv` / `venv` tree is **not** copied into the payload (it is on the
skip list with `.git`, `__pycache__`, …). Only the install tree is staged into
`/app/site-packages`.

```
my_app/
  app.py
  .venv/                ← skipped as a tree; site-packages extracted
    lib/python3.12/site-packages/
      bottle.py
```

The builder:

- merges those packages into `/app/site-packages` in the rootfs;
- declares `PYTHONPATH=${ROOTFS}/app/site-packages` in metadata (the `${ROOTFS}`
  token is resolved by the launcher — see [Launcher](../reference/launcher.md));
- the stub also injects that `PYTHONPATH` at runtime when
  `app/site-packages` exists, so vendored-only apps work even without a
  prior metadata entry;
- runs the ELF analyzer on `.so` files from C extensions (numpy, pillow…) to
  embed their system dependencies.

If a `.venv` / `venv` is present **without** any Python entrypoint and without
`requirements.txt`, the build fails with a clear error (add `app.py` or
`requirements.txt`).

The example `examples/site-packages-only` has a vendored `site-packages/` and
**no** `requirements.txt`. `examples/bottle-web` can use either a vendored tree
or pip at build time.

```bash
erebus build ./examples/site-packages-only -o /tmp/sp.erebus
./sp.erebus   # → hello from vendored site-packages
```

## Requirements.txt → pip install at build time

If your app has a `requirements.txt` with non-empty content, the builder
automatically pip-installs the dependencies into the rootfs site-packages
layout (and they remain importable via the embedded interpreter paths and/or
`/app/site-packages`):

```bash
erebus build ./my_app -o my_app.erebus
# [erebus] pip install: ./my_app/requirements.txt → …/site-packages
```

## Supported entrypoints

The builder auto-detects the entrypoint in this priority order:

1. **Django** — `manage.py` → `python3 /app/manage.py runserver 0.0.0.0:8000`
2. **Streamlit** — `streamlit` in requirements → `streamlit run /app/app.py --server.port 8501 --server.address 0.0.0.0`
3. **FastAPI/ASGI** — `uvicorn`/`gunicorn` in requirements or `pyproject.toml` → `uvicorn module:app --host 0.0.0.0 --port 8000`
4. **PEP 621 `[project.scripts]`** — `start = "..."` in `pyproject.toml`
5. **Python module** — `pyproject.toml` with `tool.fastapi.entrypoint` or package with `__main__.py` → `python3 -m module`
6. **Named script** — first of `app.py`, `main.py`, `__main__.py`, `server.py` → `python3 /app/<script>`
7. **Shebang script** — extensionless file with `#!/usr/bin/env python3` (or `python`) → `python3 /app/<name>`

## Unsupported bundles

- **PyInstaller onefile** and **`.pyz` zipapps** are detected and **refused**
  (fail closed). Package the Python sources (or a plain native binary) instead
  of re-wrapping a frozen bundle inside erebus.

## Asyncio / multiprocessing under the sandbox

- **asyncio** (stdlib event loop, `asyncio.run`, simple `gather`) works under
  the default sandbox. See `examples/asyncio-smoke`.
- **multiprocessing** / heavy `fork` + shared memory is a **known limitation**
  under Linux isolation ≥ 2 (`pivot_root` + namespaces): some spawn methods
  fail or hang. Prefer threads or asyncio for packaged agents; do not claim
  full multiprocessing support.

## Current limitations

- **Cross-distro portability**: see [Isolation](../reference/isolation.md)
  — strongest when isolation uses user namespaces + `pivot_root`.
