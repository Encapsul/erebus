import assert from 'node:assert/strict';
import test from 'node:test';

import { ErebusError, jcs } from '../dist/index.js';
import { readVectors } from './support.mjs';

test('JCS matches the shared cross-language vectors', () => {
  for (const vector of readVectors().jcs) {
    assert.equal(jcs(vector.value).toString('utf8'), vector.canonical, vector.name);
  }
});

test('JCS is a fixpoint on its own output', () => {
  const once = jcs({ k: ['v', { n: null, i: -7 }], emoji: '😀' });
  assert.deepEqual(jcs(JSON.parse(once.toString('utf8'))), once);
});

test('JCS fails closed on non-receipt values', () => {
  const cyclic = {};
  cyclic.self = cyclic;
  class Foo {
    constructor() {
      this.a = 1;
    }
  }
  const bad = [
    1.5,
    NaN,
    Infinity,
    1n,
    undefined,
    () => {},
    new Date(),
    new Map(),
    new Foo(),
    cyclic,
    '\ud800',
    { a: 1.5 },
    [undefined],
  ];
  for (const value of bad) {
    assert.throws(() => jcs(value), ErebusError, String(value));
  }
  assert.equal(jcs(-0).toString('utf8'), '0');
});

test('class instances nested inside objects are refused', () => {
  assert.throws(() => jcs({ outer: { inner: new (class X {})() } }), ErebusError);
});

test('symbol-keyed members are refused', () => {
  const value = { a: 1 };
  value[Symbol('hidden')] = 2;
  assert.throws(() => jcs(value), ErebusError, /symbol/);
});
