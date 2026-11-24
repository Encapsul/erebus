import assert from 'node:assert/strict';
import { existsSync, readdirSync } from 'node:fs';
import test from 'node:test';

import { attest, ErebusError } from '../dist/index.js';
import { keyFixture } from './support.mjs';

const count = (trail) =>
  existsSync(trail) ? readdirSync(trail).filter((name) => name.endsWith('.json')).length : 0;

test('attest records a successful synchronous call', () => {
  const fixture = keyFixture();
  const wrapped = attest((question) => ({ answer: question.toUpperCase() }), {
    key: fixture.keyPath,
    trail: fixture.trail,
    name: 'sync.answer',
  });
  assert.deepEqual(wrapped('hello'), { answer: 'HELLO' });
  assert.equal(count(fixture.trail), 1);
});

test('attest records an async call only after it resolves', async () => {
  const fixture = keyFixture();
  const wrapped = attest(async (x) => ({ x }), {
    key: fixture.keyPath,
    trail: fixture.trail,
    name: 'async.answer',
  });
  const promise = wrapped({ b: 2, a: 1 });
  assert.equal(count(fixture.trail), 0);
  assert.deepEqual(await promise, { x: { b: 2, a: 1 } });
  assert.equal(count(fixture.trail), 1);
});

test('attest never records a failed call', async () => {
  const fixture = keyFixture();
  const rejected = attest(async () => {
    throw new Error('model unavailable');
  }, { key: fixture.keyPath, trail: fixture.trail });
  await assert.rejects(rejected(), /model unavailable/);
  assert.equal(count(fixture.trail), 0);

  const threw = attest(() => {
    throw new Error('bad input');
  }, { key: fixture.keyPath, trail: fixture.trail });
  assert.throws(threw, /bad input/);
  assert.equal(count(fixture.trail), 0);
});

test('attest fails closed on a non-canonical result', () => {
  const fixture = keyFixture();
  const wrapped = attest(() => ({ score: 0.5 }), {
    key: fixture.keyPath,
    trail: fixture.trail,
  });
  assert.throws(wrapped, ErebusError, /floating-point/);
  assert.equal(count(fixture.trail), 0);
});
