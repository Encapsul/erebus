# Node SDK — receipts without repackaging

`erebus-sdk` lets a Node agent append spec 2.0 receipts from inside its own
process. It needs no `erebus build`, no launcher and no daemon. The receipt is
the same DSSE envelope over a JCS in-toto statement that the Rust and Python
writers produce, so `erebus verify-attest --chain` verifies it unchanged.

## Install and configure

From a checkout, build the SDK and install it into your agent project:

```bash
cd sdk/node
npm install && npm run build
cd ../..
npm install ./sdk/node

erebus keygen --key-dir ~/.erebus/keys
export ERE_ATTEST_KEY="$(ls ~/.erebus/keys/*.key | head -1)"
export ERE_ATTEST_LOG="$PWD/agent.attest.d"
```

`ERE_ATTEST_KEY` is the raw 32-byte seed written by `erebus keygen`;
`ERE_ATTEST_LOG` is the trail directory. Both can be passed explicitly with
`new Erebus({ key, trail })` or `attest(fn, { key, trail })`. The SDK never
generates keys, reads PEM files or talks to a KMS.

## Three lines

```js
import { attest } from 'erebus-sdk';
const answer = (question) => ({ answer: question.toUpperCase() });
await attest(answer, { name: 'answer' })('hello');
```

The import, the wrapper and the call are the instrumentation; each successful
call appends one receipt. A synchronous function records before returning; an
async function records after it resolves. A rejected or thrown call records
nothing. Verify the trail with the public key from `keygen`:

```bash
erebus verify-attest --chain agent.attest.d --trusted-dir ~/.erebus/keys
# OK: chain verified — 2 receipt(s) in agent.attest.d
```

## What is signed

- JCS of `{"args": [...], "kwargs": {}}` → `execution.input_hash`;
- JCS of the return value → `execution.output_hash`;
- the function descriptor → the signed in-toto subject (`flags: ["agent"]`);
- the trail head → `execution.prev_attestation_hash`, so deletion or reordering
  breaks the chain.

Only digests are stored. Arguments and results stay in your process. The
canonicalizer refuses floats, BigInt, `undefined`, class instances, unpaired
surrogates and cycles — receipt writing fails closed rather than signing a
value another language cannot reproduce byte-for-byte.

## LangChain.js (root chains only)

The optional integration uses public `BaseCallbackHandler` methods and
instruments only root chains (`parentRunId == null`). It never hooks LLM,
tool or retriever callbacks and has no LangSmith bridge.

```bash
npm install @langchain/core@1.5.1 ./sdk/node/integrations/langchain
```

```js
import { ErebusCallbackHandler } from 'erebus-langchain';

const chain = ...; // your @langchain/core chain
await chain.invoke({ question: 'hello' }, {
  callbacks: [new ErebusCallbackHandler({ name: 'langchain-root' })],
});
```

Nested chains produce no extra receipts; a failed root chain produces none.
Chain inputs and outputs must be canonicalizable, or the handler raises.

## Boundaries — read before quoting the receipt

The SDK signs with the **operator key only**. There is no `.erebus` bundle
digest and no enrolled machine co-signature, so do not expect `--strict` to
accept these receipts. In-process adoption is not enforcement: code that skips
`attest` or the handler produces no evidence. For capture an agent cannot opt
out of, use `erebus serve --attest-key` (with `--traffic-log` and
`erebus monitor`) or a signed launch policy on an `erebus build` artifact.

Lower-level API when a wrapper is awkward:

```js
import { Erebus } from 'erebus-sdk';

const erebus = new Erebus({ name: 'my-agent' });
const path = erebus.record('sum', { a: 1, b: 2 }, 3);
```
