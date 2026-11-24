import { Buffer } from 'node:buffer';

/** Configuration or receipt-writing failure. Never silently ignored. */
export class ErebusError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ErebusError';
  }
}

/**
 * RFC 8785 canonical bytes without floats, the same subset the Rust and
 * Python writers use. Only null, booleans, safe integers, strings, arrays
 * and plain objects are canonicalizable.
 */
export function jcs(value: unknown): Buffer {
  const out: string[] = [];
  write(value, out, new Set<object>());
  return Buffer.from(out.join(''), 'utf8');
}

function write(value: unknown, out: string[], ancestors: Set<object>): void {
  if (value === null) {
    out.push('null');
  } else if (typeof value === 'boolean') {
    out.push(value ? 'true' : 'false');
  } else if (typeof value === 'number') {
    // Covers NaN, Infinity and every non-integer; also refuses integers that
    // JS cannot spell exactly, rather than silently signing a rounded value.
    if (!Number.isSafeInteger(value)) {
      throw new ErebusError('JCS refuses floating-point values in receipts');
    }
    out.push(String(value));
  } else if (typeof value === 'string') {
    out.push(quote(value));
  } else if (Array.isArray(value)) {
    if (ancestors.has(value)) {
      throw new ErebusError('JCS refuses cyclic values');
    }
    ancestors.add(value);
    out.push('[');
    value.forEach((item, index) => {
      if (index > 0) out.push(',');
      write(item, out, ancestors);
    });
    out.push(']');
    ancestors.delete(value);
  } else if (isPlainObject(value)) {
    if (ancestors.has(value)) {
      throw new ErebusError('JCS refuses cyclic values');
    }
    ancestors.add(value);
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new ErebusError('JCS refuses symbol-keyed members');
    }
    out.push('{');
    const keys = Object.keys(value).sort(compareUtf16);
    keys.forEach((key, index) => {
      if (index > 0) out.push(',');
      out.push(quote(key), ':');
      write(value[key], out, ancestors);
    });
    out.push('}');
    ancestors.delete(value);
  } else {
    throw new ErebusError(
      `value of type ${describe(value)} is not canonicalizable`,
    );
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function compareUtf16(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function quote(value: string): string {
  let out = '"';
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code === 0x22) {
      out += '\\"';
    } else if (code === 0x5c) {
      out += '\\\\';
    } else if (code === 0x08) {
      out += '\\b';
    } else if (code === 0x09) {
      out += '\\t';
    } else if (code === 0x0a) {
      out += '\\n';
    } else if (code === 0x0c) {
      out += '\\f';
    } else if (code === 0x0d) {
      out += '\\r';
    } else if (code < 0x20) {
      out += `\\u${code.toString(16).padStart(4, '0')}`;
    } else if (code >= 0xd800 && code <= 0xdfff) {
      throw new ErebusError('JCS refuses unpaired surrogates');
    } else {
      out += char;
    }
  }
  return `${out}"`;
}

function describe(value: unknown): string {
  if (value === undefined) return 'undefined';
  if (typeof value === 'bigint') return 'bigint';
  if (typeof value === 'function') return 'function';
  if (typeof value === 'object' && value !== null) {
    return value.constructor?.name ?? 'object';
  }
  return typeof value;
}
