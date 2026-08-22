# Python Agent (Registry demo — Phase 4)

Two minimal agents targeting the same Python 3 runtime:

- `chat.py` — chat agent (echo server on port 8765)
- `code.py` — code agent (eval sandbox on port 8766)

## Status

**NOTE**: `erebus build --publish` does NOT yet generate layer metadata.
The CLI always produces `layers: []` / `entrypoint_layer: None`
(pipeline.rs:233-234), so `--publish` finds no layers to push.

To use this demo, you must manually build a `.erebus` with layer metadata
using `erebus-core`'s `assemble_erebus` API and then publish with:

```bash
erebus registry push app.erebus --local ~/.erebus/registry
```

## Demo (manual layer workflow)

```bash
# Build with explicit layer metadata (requires custom tooling)
# Then publish to local CAS:
erebus registry push chat.erebus --local ~/.erebus/registry
erebus registry list --dir ~/.erebus/registry
```
