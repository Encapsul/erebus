import { Buffer } from 'node:buffer';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from 'node:crypto';
import { readFileSync } from 'node:fs';

import { ErebusError } from './jcs.js';

/** PKCS#8 DER wrapper for a 32-byte Ed25519 seed (RFC 8410). */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SEED_BYTES = 32;
const PUBLIC_BYTES = 32;

export interface SigningIdentity {
  privateKey: KeyObject;
  publicKey: Buffer;
  fingerprint: string;
}

/** Load the raw seed written by `erebus keygen`; the seed buffer is wiped. */
export function loadSigningIdentity(keyPath: string): SigningIdentity {
  let seed: Buffer;
  try {
    seed = readFileSync(keyPath);
  } catch (error) {
    throw new ErebusError(`cannot read attestation key ${keyPath}: ${errorMessage(error)}`);
  }

  if (!Buffer.isBuffer(seed) || seed.length !== SEED_BYTES) {
    const length = Buffer.isBuffer(seed) ? seed.length : -1;
    seed.fill(0);
    throw new ErebusError(`attestation key ${keyPath} must be 32 bytes, got ${length}`);
  }

  const pkcs8 = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  try {
    const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
    const publicKey = Buffer.from(spki.subarray(spki.length - PUBLIC_BYTES));
    if (publicKey.length !== PUBLIC_BYTES) {
      throw new ErebusError('attestation key produced an invalid Ed25519 public key');
    }
    return {
      privateKey,
      publicKey,
      fingerprint: `sha256:${createHash('sha256').update(publicKey).digest('hex')}`,
    };
  } catch (error) {
    throw new ErebusError(`cannot load attestation key ${keyPath}: ${errorMessage(error)}`);
  } finally {
    seed.fill(0);
    pkcs8.fill(0);
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
