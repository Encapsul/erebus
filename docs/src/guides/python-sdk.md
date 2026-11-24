# Python SDK — receipts without repackaging

`erebus-sdk` lets a Python agent append spec 2.0 receipts from inside its own
process. It needs no `erebus build`, no launcher and no daemon. The receipt is
the same DSSE envelope over a JCS in-toto statement that the Rust writer
produces, so `erebus verify-attest --chain` verifies it unchanged.

## Install and configure

From a checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e 'sdk/python[dev]'

erebus keygen --key-dir ~/.erebus/keys
export ERE_ATTEST_KEY="$(ls ~/.erebus/keys/*.key | head -1)"
export ERE_ATTEST_LOG="$PWD/agent.attest.d"
```

`ERE_ATTEST_KEY` is the raw 32-byte seed written by `erebus keygen`;
`ERE_ATTEST_LOG` is the trail directory. Both can be passed explicitly with
`Erebus(key=…, trail=…)` or `@attest(key=…, trail=…)`.

## Three lines

```python
from erebus import attest

@attest
def answer(question):
    return {"answer": question.upper()}

answer("hello")
```

The import, the decorator and the function definition are the instrumentation;
each call appends one receipt. Verify the trail with the public key from
`keygen`:

```bash
erebus verify-attest --chain agent.attest.d --trusted-dir ~/.erebus/keys
# OK: chain verified — 2 receipt(s) in agent.attest.d
```

## What is signed

- JCS of `{"args": [...], "kwargs": {...}}` → `execution.input_hash`;
- JCS of the return value → `execution.output_hash`;
- the function descriptor → the signed in-toto subject (`flags: ["agent"]`);
- the trail head → `execution.prev_attestation_hash`, so deletion or reordering
  breaks the chain.

Only digests are stored. The arguments and result stay in your process. Floats
are refused because the receipt canonicalizer rejects them by design.

## Boundaries — read before quoting the receipt

The SDK signs with the **operator key only**. There is no `.erebus` bundle
digest and no enrolled machine co-signature, so do not expect `--strict` to
accept these receipts. The decorator runs inside the agent: code that skips it
produces no evidence. For capture that an agent cannot opt out of, use
`erebus serve --attest-key` (with `--traffic-log` and `erebus monitor`) or a
signed launch policy on an `erebus build` artifact.

Lower-level API when a decorator is awkward:

```python
from erebus import Erebus

erebus = Erebus(name="my-agent")
path = erebus.record("sum", {"a": 1, "b": 2}, 3)
```
