/**
 * Web Worker that runs all heavy crypto operations off the main thread.
 *
 * Import via Vite's worker syntax:
 *   import ParanoiaWorkerUrl from './workers/crypto.worker?worker';
 *
 * Or use the `ParanoiaWorker` helper class in index.ts which wraps the
 * message-passing protocol.
 */

import { Paranoia } from '../Paranoia';

// Cast self to a minimal worker interface so postMessage has the right overloads.
interface WorkerSelf {
  onmessage: ((e: MessageEvent) => void) | null;
  postMessage(message: unknown, transfer?: Transferable[]): void;
}
const ctx = self as unknown as WorkerSelf;
const paranoia = new Paranoia();

type Req =
  | { id: string; op: 'seal'; data: Uint8Array; passphrase: string; options?: object }
  | { id: string; op: 'unseal'; sealed: Uint8Array; passphrase: string }
  | { id: string; op: 'sealTo'; data: Uint8Array; pubKey: object }
  | { id: string; op: 'unsealWith'; sealed: Uint8Array; keyPair: object }
  | { id: string; op: 'generateKeyPair' };

type Res = { id: string; ok: true; result: unknown } | { id: string; ok: false; error: string };

function transfer(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

ctx.onmessage = async (e: MessageEvent<Req>) => {
  const { id } = e.data;
  try {
    let result: unknown;

    switch (e.data.op) {
      case 'seal': {
        result = await paranoia.seal(e.data.data, e.data.passphrase, e.data.options as never);
        const buf = transfer(result as Uint8Array);
        ctx.postMessage({ id, ok: true, result } satisfies Res, [buf]);
        return;
      }
      case 'unseal': {
        result = await paranoia.unseal(e.data.sealed, e.data.passphrase);
        const buf = transfer(result as Uint8Array);
        ctx.postMessage({ id, ok: true, result } satisfies Res, [buf]);
        return;
      }
      case 'sealTo': {
        result = await paranoia.sealTo(e.data.data, e.data.pubKey as never);
        const buf = transfer(result as Uint8Array);
        ctx.postMessage({ id, ok: true, result } satisfies Res, [buf]);
        return;
      }
      case 'unsealWith': {
        result = await paranoia.unsealWith(e.data.sealed, e.data.keyPair as never);
        const buf = transfer(result as Uint8Array);
        ctx.postMessage({ id, ok: true, result } satisfies Res, [buf]);
        return;
      }
      case 'generateKeyPair':
        result = await paranoia.generateKeyPair();
        ctx.postMessage({ id, ok: true, result } satisfies Res);
        return;

      default:
        // L5: do not reflect the attacker-controlled op value in the message
        throw new Error('Unknown operation requested');
    }
  } catch (err) {
    ctx.postMessage({
      id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    } satisfies Res);
  }
};
