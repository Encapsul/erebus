"""Minimal asyncio smoke for packaged Python under the erebus sandbox.

Expected: prints ASYNC_OK and exits 0 with isolation sandbox (Linux) or the
host default. This is not a claim of full asyncio feature coverage.

multiprocessing is intentionally not exercised here — fork/spawn under
pivot_root isolation is a known limitation (see docs/src/guides/python.md).
"""

from __future__ import annotations

import asyncio


async def _work(n: int) -> int:
    await asyncio.sleep(0)
    return n * 2


async def main() -> None:
    a, b = await asyncio.gather(_work(21), _work(10))
    if a + b != 62:
        raise SystemExit(f"unexpected gather result: {a}+{b}")
    print("ASYNC_OK", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
