import { jcs } from './jcs.js';
import { Erebus } from './receipt.js';
import type { AttestOptions } from './types.js';

/**
 * Wrap a function so each successful call appends one receipt. Async calls
 * record after resolution; a rejection never produces evidence.
 */
export function attest<Args extends unknown[], Result>(
  fn: (...args: Args) => Result,
  options: AttestOptions = {},
): (...args: Args) => Result {
  const client = new Erebus(options);
  const label = options.name ?? fn.name ?? 'agent';

  function wrapped(this: unknown, ...args: Args): Result {
    const inputBytes = jcs({ args, kwargs: {} });
    const result = Reflect.apply(fn, this, args) as Result;
    if (isThenable(result)) {
      return Promise.resolve(result).then((value) => {
        client.recordBytes(label, inputBytes, jcs(value));
        return value;
      }) as Result;
    }
    client.recordBytes(label, inputBytes, jcs(result));
    return result;
  }

  Object.defineProperty(wrapped, 'name', { value: label });
  return wrapped;
}

function isThenable(value: unknown): boolean {
  return (
    value !== null &&
    (typeof value === 'object' || typeof value === 'function') &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}
