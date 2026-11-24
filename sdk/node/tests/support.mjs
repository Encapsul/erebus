import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/** A raw `erebus keygen`-shaped seed plus its trusted public-key directory. */
export function keyFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'erebus-node-sdk-'));
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' });
  const seed = pkcs8.subarray(pkcs8.length - 32);
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  const pubRaw = spki.subarray(spki.length - 32);
  const keyPath = join(dir, 'ops.key');
  const keys = join(dir, 'keys');
  mkdirSync(keys, { recursive: true });
  writeFileSync(keyPath, seed);
  const fingerprint = createHash('sha256').update(pubRaw).digest('hex');
  writeFileSync(join(keys, `${fingerprint}.pub`), pubRaw);
  return { dir, keyPath, keys, publicKey, pubRaw, trail: join(dir, 'trail') };
}

export function readVectors() {
  return JSON.parse(readFileSync(new URL('../test-vectors/v1.json', import.meta.url), 'utf8'));
}
