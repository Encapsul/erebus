import { Buffer } from 'node:buffer';
import { createHash, sign } from 'node:crypto';
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import { arch, hostname, platform } from 'node:os';
import { join } from 'node:path';

import { ErebusError, jcs } from './jcs.js';
import { loadSigningIdentity, type SigningIdentity } from './key.js';
import type { ErebusOptions } from './types.js';

export const VERSION = '0.1.0';

const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
const PREDICATE_TYPE = 'https://erebus.dev/attestation/execution/v2';
const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const ATTESTATION_TYPE = 'erebus-execution';

type JsonObject = Record<string, unknown>;

function digest(data: Uint8Array): string {
  return `sha256:${createHash('sha256').update(data).digest('hex')}`;
}

function utcNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function compact(iso: string): string {
  let out = '';
  for (const char of iso) {
    if (char === '.' || char === '+') break;
    if (/^[A-Za-z0-9]$/.test(char)) out += char;
  }
  return out || 'unknown';
}

function machineArch(): string {
  const value = arch();
  return value === 'x64' ? 'x86_64' : value === 'arm64' ? 'aarch64' : value;
}

function machineHash(): string {
  return digest(Buffer.from(`${hostname()}${platform()}${machineArch()}`, 'utf8'));
}

function pae(payload: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${PAYLOAD_TYPE.length} ${PAYLOAD_TYPE} ${payload.length} `, 'utf8'),
    Buffer.from(payload),
  ]);
}

function head(trail: string): string | null {
  try {
    return readFileSync(join(trail, 'HEAD'), 'utf8').trim() || null;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new ErebusError(`cannot read trail HEAD: ${String(error)}`);
  }
}

function nextSeq(trail: string): number {
  return (
    readdirSync(trail).filter(
      (name) =>
        name.endsWith('.json') &&
        !name.endsWith('.proof.json') &&
        !name.endsWith('.witness.json'),
    ).length + 1
  );
}

function writeAtomic(path: string, data: Uint8Array): void {
  writeFileSync(`${path}.tmp`, data);
  renameSync(`${path}.tmp`, path);
}

function buildAttestation(
  identity: SigningIdentity,
  label: string,
  version: string,
  inputBytes: Uint8Array,
  outputBytes: Uint8Array,
  previous: string | null,
  now: string,
): JsonObject {
  const descriptor: JsonObject = {
    kind: 'agent',
    name: label,
    sdk: `erebus-node-sdk ${version}`,
  };
  const meta = jcs(descriptor);
  const subject = digest(meta);
  const artifact: JsonObject = {
    bundle_hash: subject,
    payload_hash: subject,
    metadata_hash: digest(meta),
    format_version: 0,
    flags: ['agent'],
  };
  const provenance: JsonObject = {
    builder: `erebus node-sdk ${version}`,
    author: null,
    license: null,
    layers: [],
  };
  const execution: JsonObject = {
    attested_at: now,
    machine_id_hash: machineHash(),
    os: platform(),
    arch: machineArch(),
    input_hash: digest(inputBytes),
    output_hash: digest(outputBytes),
    exit_code: null,
    prev_attestation_hash: previous,
    request: null,
    rootfs_root: null,
    machine_id: null,
  };
  const statement = buildStatement(artifact, provenance, execution);
  const canonical = jcs(statement);
  const signature = sign(null, pae(canonical), identity.privateKey);
  const keyId = identity.fingerprint;
  return {
    spec_version: '2.0',
    attestation_type: ATTESTATION_TYPE,
    artifact,
    provenance,
    execution,
    statement,
    signature: {
      algorithm: 'ed25519',
      key_fingerprint: keyId,
      signature_hex: signature.toString('hex'),
    },
    envelope: {
      payloadType: PAYLOAD_TYPE,
      payload: canonical.toString('base64'),
      signatures: [{ keyid: keyId, sig: signature.toString('base64') }],
    },
    machine: null,
  };
}

function buildStatement(
  artifact: JsonObject,
  provenance: JsonObject,
  execution: JsonObject,
): JsonObject {
  return {
    _type: STATEMENT_TYPE,
    subject: [
      { name: 'bundle', digest: { sha256: (artifact.bundle_hash as string).slice(7) } },
      { name: 'payload', digest: { sha256: (artifact.payload_hash as string).slice(7) } },
    ],
    predicateType: PREDICATE_TYPE,
    predicate: {
      builder: provenance.builder,
      author: provenance.author,
      license: provenance.license,
      layers: provenance.layers,
      execution,
      artifact: {
        metadata_hash: artifact.metadata_hash,
        format_version: artifact.format_version,
        flags: artifact.flags,
      },
    },
  };
}

/** Append signed receipts to a hash-chained directory. */
export class Erebus {
  readonly keyPath: string;
  readonly trail: string;
  readonly name: string;
  readonly version: string;
  private readonly identity: SigningIdentity;

  constructor(options: ErebusOptions = {}) {
    const configured = options.key ?? process.env.ERE_ATTEST_KEY;
    if (!configured) {
      throw new ErebusError('set ERE_ATTEST_KEY or pass key= to Erebus/attest');
    }
    this.keyPath = configured;
    this.trail = options.trail ?? process.env.ERE_ATTEST_LOG ?? 'agent.run.attest.d';
    this.name = options.name ?? 'agent';
    this.version = options.version ?? VERSION;
    this.identity = loadSigningIdentity(configured);
  }

  /** Sign one JSON-serializable call; digests only, never plaintext. */
  record(name: string | null | undefined, input: unknown, output: unknown): string {
    return this.recordBytes(name, jcs(input), jcs(output));
  }

  /** Append a receipt whose signed digests are already canonical bytes. */
  recordBytes(name: string | null | undefined, inputBytes: Uint8Array, outputBytes: Uint8Array): string {
    mkdirSync(this.trail, { recursive: true });
    const previous = head(this.trail);
    const now = utcNow();
    const attestation = buildAttestation(
      this.identity,
      name ?? this.name,
      this.version,
      inputBytes,
      outputBytes,
      previous,
      now,
    );
    return this.append(attestation, now);
  }

  private append(attestation: JsonObject, now: string): string {
    const data = Buffer.from(JSON.stringify(attestation, null, 2), 'utf8');
    const hash = digest(data);
    const label = `${String(nextSeq(this.trail)).padStart(6, '0')}-${compact(now)}-${hash.slice(7, 15)}.json`;
    const path = join(this.trail, label);
    writeAtomic(path, data);
    writeAtomic(join(this.trail, 'HEAD'), Buffer.from(`${hash}\n`, 'utf8'));
    return path;
  }
}
