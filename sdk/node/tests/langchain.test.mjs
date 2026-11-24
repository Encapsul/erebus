import assert from 'node:assert/strict';
import { existsSync, readdirSync } from 'node:fs';
import test from 'node:test';
import { BaseCallbackHandler } from '@langchain/core/callbacks/base';
import { RunnableLambda, RunnableSequence } from '@langchain/core/runnables';

import { ErebusCallbackHandler } from '../integrations/langchain/dist/ErebusCallbackHandler.js';
import { ErebusError } from '../dist/index.js';
import { keyFixture } from './support.mjs';

const count = (trail) =>
  existsSync(trail) ? readdirSync(trail).filter((name) => name.endsWith('.json')).length : 0;
const chain = { lc: 1, type: 'constructor', id: ['langchain', 'chains', 'Chain'] };

test('handler is a public LangChain callback handler without LLM hooks', () => {
  const fixture = keyFixture();
  const handler = new ErebusCallbackHandler({ key: fixture.keyPath, trail: fixture.trail });
  assert.ok(handler instanceof BaseCallbackHandler);
  assert.equal(handler.handleLLMStart, undefined);
  assert.equal(handler.handleLLMEnd, undefined);
});

test('only root chains produce receipts', () => {
  const fixture = keyFixture();
  const handler = new ErebusCallbackHandler({ key: fixture.keyPath, trail: fixture.trail });
  handler.handleChainStart(chain, { question: 'hello' }, 'root-1');
  handler.handleChainStart(chain, { child: true }, 'child-1', 'root-1');
  handler.handleChainEnd({ answer: 'HELLO' }, 'child-1', 'root-1');
  assert.equal(count(fixture.trail), 0);
  handler.handleChainEnd({ answer: 'HELLO' }, 'root-1');
  assert.equal(count(fixture.trail), 1);
});

test('a failed root chain produces no receipt', () => {
  const fixture = keyFixture();
  const handler = new ErebusCallbackHandler({ key: fixture.keyPath, trail: fixture.trail });
  handler.handleChainStart(chain, { question: 'hello' }, 'root-2');
  handler.handleChainError(new Error('model unavailable'), 'root-2');
  assert.equal(count(fixture.trail), 0);
});

test('a real LangChain sequence records only its root chain', async () => {
  const fixture = keyFixture();
  const handler = new ErebusCallbackHandler({ key: fixture.keyPath, trail: fixture.trail });
  const sequence = RunnableSequence.from([
    RunnableLambda.from((input) => ({ question: input.question.toUpperCase() })),
    RunnableLambda.from((input) => ({ answer: input.question })),
  ]);
  assert.deepEqual(
    await sequence.invoke({ question: 'hello' }, { callbacks: [handler] }),
    { answer: 'HELLO' },
  );
  assert.equal(count(fixture.trail), 1);
});

test('a real failing LangChain chain records nothing', async () => {
  const fixture = keyFixture();
  const handler = new ErebusCallbackHandler({ key: fixture.keyPath, trail: fixture.trail });
  const failing = RunnableLambda.from(() => {
    throw new Error('model unavailable');
  });
  await assert.rejects(
    failing.invoke({ question: 'hello' }, { callbacks: [handler] }),
    /model unavailable/,
  );
  assert.equal(count(fixture.trail), 0);
});

test('handler refuses non-canonical chain values', () => {
  const fixture = keyFixture();
  const handler = new ErebusCallbackHandler({ key: fixture.keyPath, trail: fixture.trail });
  assert.throws(
    () => handler.handleChainStart(chain, { score: 0.5 }, 'root-3'),
    ErebusError,
    /floating-point/,
  );
  assert.equal(count(fixture.trail), 0);
});
