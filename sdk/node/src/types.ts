/** Values the receipt canonicalizer can represent. Floats are refused at runtime. */
export type JcsValue =
  | null
  | boolean
  | number
  | string
  | JcsValue[]
  | { [key: string]: JcsValue };

/** Options shared by the client and the `attest` wrapper. */
export interface ErebusOptions {
  /** Path to the raw 32-byte seed written by `erebus keygen`. */
  key?: string;
  /** Trail directory; defaults to `ERE_ATTEST_LOG` then `agent.run.attest.d`. */
  trail?: string;
  /** Descriptor name when a call does not supply one. */
  name?: string;
  /** SDK version recorded in the descriptor and builder string. */
  version?: string;
}

export interface AttestOptions extends ErebusOptions {}
