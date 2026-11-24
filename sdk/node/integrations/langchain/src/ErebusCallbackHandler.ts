import { BaseCallbackHandler } from '@langchain/core/callbacks/base';
import type { Serialized } from '@langchain/core/load/serializable';
import type { ChainValues } from '@langchain/core/utils/types';
import { Erebus, ErebusError, jcs, type ErebusOptions } from 'erebus-sdk';

export interface ErebusCallbackHandlerOptions extends ErebusOptions {}

/**
 * Appends one receipt per root LangChain chain, using only public callback
 * methods. Nested chains, LLM calls and other run types are not instrumented.
 */
export class ErebusCallbackHandler extends BaseCallbackHandler {
  override name = 'erebus-langchain';
  private readonly client: Erebus;
  private readonly receiptName: string;
  private readonly inputs = new Map<string, Uint8Array>();

  constructor(options: ErebusCallbackHandlerOptions = {}) {
    super({ ignoreLLM: true, raiseError: true, _awaitHandler: true });
    this.client = new Erebus(options);
    this.receiptName = options.name ?? 'langchain-root';
  }

  override handleChainStart(
    _chain: Serialized,
    inputs: ChainValues,
    runId: string,
    _runType?: string,
    _tags?: string[],
    _metadata?: Record<string, unknown>,
    _runName?: string,
    _parentRunId?: string,
    _extra?: Record<string, unknown>,
  ): void {
    // The pinned @langchain/core 1.5.1 runtime passes parentRunId as the
    // fourth argument, although its declaration lists it eighth (where a
    // root run carries its string runName). Read the runtime position.
    const parentRunId = arguments[3] as string | undefined;
    if (parentRunId != null) return;
    this.inputs.set(runId, jcs(inputs));
  }

  override handleChainEnd(
    outputs: ChainValues,
    runId: string,
    parentRunId?: string,
    _tags?: string[],
    _kwargs?: { inputs?: Record<string, unknown> },
  ): void {
    if (parentRunId != null) return;
    const inputBytes = this.inputs.get(runId);
    if (!inputBytes) {
      throw new ErebusError(`no canonical inputs recorded for root chain ${runId}`);
    }
    this.inputs.delete(runId);
    this.client.recordBytes(this.receiptName, inputBytes, jcs(outputs));
  }

  override handleChainError(
    _err: Error,
    runId: string,
    parentRunId?: string,
    _tags?: string[],
    _kwargs?: { inputs?: Record<string, unknown> },
  ): void {
    if (parentRunId != null) return;
    this.inputs.delete(runId);
  }
}
