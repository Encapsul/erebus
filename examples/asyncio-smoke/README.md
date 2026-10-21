# asyncio-smoke

Documents expected behavior of a tiny `asyncio.run` app under erebus.

```bash
erebus build ./examples/asyncio-smoke -o /tmp/asyncio-smoke.erebus --force
/tmp/asyncio-smoke.erebus
# → ASYNC_OK
```

| Mode | Expected |
|------|----------|
| Default / sandbox isolation | Pass (`ASYNC_OK`) for this script |
| `multiprocessing` / heavy fork | **Known limitation** — not claimed supported under Linux isolation ≥ 2 |

No TEE / judgment / L2 hardware claims.
