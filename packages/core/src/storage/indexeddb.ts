import { aesGcmEncrypt, aesGcmDecrypt } from '../core/symmetric';
import { getSecureRandom } from '../core/entropy';
import { wipe } from '../core/memory';
import { SIZES, type HybridKeyPair } from '../types';

const DB_NAME    = 'paranoia-ts-keystore';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

// ─── IndexedDB helpers ────────────────────────────────────────────────────────

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE_NAME);
    req.onsuccess = () => resolve(req.result);
    req.onerror   = () => reject(req.error);
  });
}

// ─── Keypair storage ──────────────────────────────────────────────────────────

/**
 * Serialize, encrypt with `wrappingKey`, and persist a keypair in IndexedDB.
 *
 * Layout on disk:
 *   [12 bytes nonce] [serialized keypair ciphertext + 16-byte auth tag]
 */
export async function storeKeyPair(
  keyPair: HybridKeyPair,
  wrappingKey: Uint8Array,
  id = 'default',
): Promise<void> {
  const serialized = serializeKeyPair(keyPair);
  const nonce = getSecureRandom(12);
  const aad   = new TextEncoder().encode(`paranoia.ts keystore:${id}`);

  const encrypted = await aesGcmEncrypt(serialized, wrappingKey, nonce, aad);
  wipe(serialized);

  const blob = new Uint8Array(12 + encrypted.length);
  blob.set(nonce);
  blob.set(encrypted, 12);

  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(blob, id);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror    = () => { db.close(); reject(tx.error); };
  });
}

/**
 * Load and decrypt a keypair from IndexedDB.
 * Throws if no entry exists for `id` or if decryption fails.
 */
export async function loadKeyPair(
  wrappingKey: Uint8Array,
  id = 'default',
): Promise<HybridKeyPair> {
  const db = await openDB();
  const blob: Uint8Array | undefined = await new Promise((resolve, reject) => {
    const tx  = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(id);
    req.onsuccess = () => { db.close(); resolve(req.result as Uint8Array | undefined); };
    req.onerror   = () => { db.close(); reject(req.error); };
  });

  if (!blob) throw new Error(`No keypair stored with id "${id}"`);

  const nonce     = blob.subarray(0, 12);
  const encrypted = blob.subarray(12);
  const aad       = new TextEncoder().encode(`paranoia.ts keystore:${id}`);

  const decrypted = await aesGcmDecrypt(encrypted, wrappingKey, nonce, aad);
  const keyPair   = deserializeKeyPair(decrypted);
  wipe(decrypted);
  return keyPair;
}

/** Delete a stored keypair from IndexedDB. */
export async function deleteKeyPair(id = 'default'): Promise<void> {
  const db = await openDB();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(id);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror    = () => { db.close(); reject(tx.error); };
  });
}

// ─── Session key store ────────────────────────────────────────────────────────

/**
 * Thin wrapper around sessionStorage for short-lived symmetric keys.
 *
 * Keys are encrypted with an in-memory AES-GCM key that is never persisted
 * and is lost when the tab closes.  This provides defence-in-depth against
 * XSS that can read sessionStorage but not access the JS heap.
 */
export class SessionKeyStore {
  private readonly memKey: Uint8Array;

  constructor() {
    this.memKey = getSecureRandom(32);
  }

  async set(id: string, sessionKey: Uint8Array): Promise<void> {
    const nonce = getSecureRandom(12);
    const ct    = await aesGcmEncrypt(sessionKey, this.memKey, nonce);
    const blob  = new Uint8Array(12 + ct.length);
    blob.set(nonce);
    blob.set(ct, 12);
    sessionStorage.setItem(
      `paranoia:${id}`,
      btoa(String.fromCharCode(...blob)),
    );
  }

  async get(id: string): Promise<Uint8Array | null> {
    const raw = sessionStorage.getItem(`paranoia:${id}`);
    if (!raw) return null;
    const blob  = Uint8Array.from(atob(raw), c => c.charCodeAt(0));
    const nonce = blob.subarray(0, 12);
    const ct    = blob.subarray(12);
    return aesGcmDecrypt(ct, this.memKey, nonce);
  }

  remove(id: string): void {
    sessionStorage.removeItem(`paranoia:${id}`);
  }

  /** Wipe the in-memory encryption key and clear all session entries. */
  destroy(): void {
    wipe(this.memKey);
    const keysToRemove: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k?.startsWith('paranoia:')) keysToRemove.push(k);
    }
    for (const k of keysToRemove) sessionStorage.removeItem(k);
  }
}

// ─── Keypair serialisation ────────────────────────────────────────────────────

const KEYPAIR_SIZE = SIZES.MLKEM_PK + SIZES.MLKEM_SK + SIZES.P521_PK + SIZES.P521_SK;

function serializeKeyPair(kp: HybridKeyPair): Uint8Array {
  const buf = new Uint8Array(KEYPAIR_SIZE);
  let off = 0;
  buf.set(kp.publicKey.mlkem,  off); off += SIZES.MLKEM_PK;
  buf.set(kp.privateKey.mlkem, off); off += SIZES.MLKEM_SK;
  buf.set(kp.publicKey.p521,   off); off += SIZES.P521_PK;
  buf.set(kp.privateKey.p521,  off);
  return buf;
}

function deserializeKeyPair(data: Uint8Array): HybridKeyPair {
  if (data.length !== KEYPAIR_SIZE) {
    throw new Error(`Corrupted keypair blob: expected ${KEYPAIR_SIZE} bytes, got ${data.length}`);
  }
  let off = 0;
  const mlkemPk = data.slice(off, off += SIZES.MLKEM_PK);
  const mlkemSk = data.slice(off, off += SIZES.MLKEM_SK);
  const p521Pk  = data.slice(off, off += SIZES.P521_PK);
  const p521Sk  = data.slice(off, off += SIZES.P521_SK);
  return {
    publicKey:  { mlkem: mlkemPk, p521: p521Pk },
    privateKey: { mlkem: mlkemSk, p521: p521Sk },
  };
}
