import type { HybridKeyPair, HybridPublicKey, SealOptions } from '../types';

type Res = { id: string; ok: true; result: unknown } | { id: string; ok: false; error: string };

/**
 * Proxy class that mirrors the `Paranoia` API but runs every operation inside
 * a dedicated Web Worker, keeping the main thread responsive during expensive
 * Argon2id / ML-KEM operations.
 *
 * Usage:
 *   import ParanoiaWorkerUrl from './workers/crypto.worker?worker';
 *   const pw = new ParanoiaWorker(new ParanoiaWorkerUrl());
 *   const sealed = await pw.seal(data, passphrase);
 */
export class ParanoiaWorker {
  private readonly worker: Worker;
  private readonly pending = new Map<
    string,
    {
      resolve: (v: unknown) => void;
      reject: (e: Error) => void;
    }
  >();
  private idCounter = 0;

  constructor(worker: Worker) {
    this.worker = worker;
    this.worker.onmessage = (e: MessageEvent<Res>) => {
      const p = this.pending.get(e.data.id);
      if (!p) return;
      this.pending.delete(e.data.id);
      if (e.data.ok) p.resolve(e.data.result);
      else p.reject(new Error(e.data.error));
    };
    this.worker.onerror = (e: ErrorEvent) => {
      // Reject all pending promises on unrecoverable worker error
      const msg = e.message ?? 'Worker error';
      for (const [id, p] of this.pending) {
        this.pending.delete(id);
        p.reject(new Error(msg));
      }
    };
  }

  private post<T>(msg: Record<string, unknown>, transfer?: Transferable[]): Promise<T> {
    const id = String(++this.idCounter);
    return new Promise<T>((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (v: unknown) => void,
        reject,
      });
      if (transfer?.length) this.worker.postMessage({ ...msg, id }, transfer);
      else this.worker.postMessage({ ...msg, id });
    });
  }

  seal(data: Uint8Array, passphrase: string, options?: SealOptions): Promise<Uint8Array> {
    return this.post({ op: 'seal', data, passphrase, options }, [data.buffer]);
  }

  unseal(sealed: Uint8Array, passphrase: string): Promise<Uint8Array> {
    return this.post({ op: 'unseal', sealed, passphrase }, [sealed.buffer]);
  }

  sealTo(data: Uint8Array, pubKey: HybridPublicKey): Promise<Uint8Array> {
    return this.post({ op: 'sealTo', data, pubKey }, [data.buffer]);
  }

  unsealWith(sealed: Uint8Array, keyPair: HybridKeyPair): Promise<Uint8Array> {
    return this.post({ op: 'unsealWith', sealed, keyPair }, [sealed.buffer]);
  }

  generateKeyPair(): Promise<HybridKeyPair> {
    return this.post({ op: 'generateKeyPair' });
  }

  /** Terminate the underlying worker. */
  terminate(): void {
    this.worker.terminate();
  }
}
