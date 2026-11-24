import assert from 'node:assert/strict';
import { createHash, verify } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

import { Erebus, ErebusError, jcs } from '../dist/index.js';
import { keyFixture, readVectors } from './support.mjs';

const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function receipts(trail) {
  return readdirSync(trail)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => {
      const bytes = readFileSync(join(trail, name));
      return { name, bytes, value: JSON.parse(bytes.toString('utf8')) };
    });
}

test('record writes a canonical spec 2.0 receipt and chains HEAD', () => {
  const fixture = keyFixture();
  const client = new Erebus({ key: fixture.keyPath, trail: fixture.trail, name: 'agent' });
  client.record('answer', { question: 'hello' }, { answer: 'HELLO' });
  client.record('answer', { question: 'world' }, { answer: 'WORLD' });

  const files = receipts(fixture.trail);
  assert.equal(files.length, 2);
  for (const file of files) {
    assert.match(file.name, /^\d{6}-\d{8}T\d{6}Z-[0-9a-f]{8}\.json$/);
  }

  const shape = readVectors().shape;
  assert.deepEqual(Object.keys(files[0].value), shape.topLevelKeys);
  assert.deepEqual(Object.keys(files[0].value.execution), shape.executionKeys);
  assert.deepEqual(Object.keys(files[0].value.statement.predicate), shape.predicateKeys);
  assert.equal(files[0].value.spec_version, '2.0');
  assert.equal(files[0].value.attestation_type, shape.attestationType);
  assert.equal(files[0].value.execution.prev_attestation_hash, null);
  assert.equal(files[1].value.execution.prev_attestation_hash, digest(files[0].bytes));
  assert.equal(readFileSync(join(fixture.trail, 'HEAD'), 'utf8'), `${digest(files[1].bytes)}\n`);
});

test('descriptor and DSSE signature match the Python SDK byte layout', () => {
  const fixture = keyFixture();
  const client = new Erebus({ key: fixture.keyPath, trail: fixture.trail });
  client.record('agent.check', { b: 1, a: 2 }, [true, null]);

  const receipt = receipts(fixture.trail)[0].value;
  const descriptor = { kind: 'agent', name: 'agent.check', sdk: readVectors().shape.descriptorSdk };
  const meta = jcs(descriptor);
  assert.equal(receipt.artifact.metadata_hash, digest(meta));
  assert.equal(receipt.artifact.bundle_hash, digest(meta));
  assert.equal(receipt.statement.subject[0].digest.sha256, digest(meta).slice(7));

  const canonical = Buffer.from(receipt.envelope.payload, 'base64');
  assert.deepEqual(canonical, jcs(receipt.statement));
  assert.equal(receipt.envelope.payloadType, 'application/vnd.in-toto+json');
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 28 application/vnd.in-toto+json ${canonical.length} `),
    canonical,
  ]);
  assert.ok(verify(null, pae, fixture.publicKey, Buffer.from(receipt.envelope.signatures[0].sig, 'base64')));
  assert.equal(
    receipt.signature.signature_hex,
    Buffer.from(receipt.envelope.signatures[0].sig, 'base64').toString('hex'),
  );
  assert.equal(receipt.signature.key_fingerprint, digest(fixture.pubRaw));
});

test('recordBytes signs caller-supplied canonical bytes', () => {
  const fixture = keyFixture();
  const client = new Erebus({ key: fixture.keyPath, trail: fixture.trail });
  const input = jcs({ x: 1 });
  const output = jcs({ y: 2 });
  client.recordBytes('manual', input, output);
  const receipt = receipts(fixture.trail)[0].value;
  assert.equal(receipt.execution.input_hash, digest(input));
  assert.equal(receipt.execution.output_hash, digest(output));
});

test('a missing key fails closed', () => {
  const fixture = keyFixture();
  const previous = process.env.ERE_ATTEST_KEY;
  delete process.env.ERE_ATTEST_KEY;
  try {
    assert.throws(() => new Erebus({ trail: fixture.trail }), ErebusError, /ERE_ATTEST_KEY/);
  } finally {
    if (previous === undefined) delete process.env.ERE_ATTEST_KEY;
    else process.env.ERE_ATTEST_KEY = previous;
  }
});
