/**
 * keys.json format.
 *
 * All crypto comes from the library: deriveKeyPairAndWrapKey, aesGcmEncrypt,
 * aesGcmDecrypt, wipe. No reimplementation.
 */

import { readFileSync, writeFileSync } from 'fs';
import {
  deriveKeyPairAndWrapKey,
  aesGcmEncrypt,
  aesGcmDecrypt,
  getSecureRandom,
  wipe,
} from 'paranoia-ts';
import type { HybridKeyPair, HybridPrivateKey, Argon2Params } from 'paranoia-ts';

// ─── Types ────────────────────────────────────────────────────────────────────

export type KeyAlgorithm = 'hybrid-mlkem1024-p521' | 'pqc-mlkem1024' | 'classical-p521';

export interface KeysJson {
  version:         1;
  algorithm:       KeyAlgorithm;
  created:         string;
  /** base64(32B) — random nonce, public, stored here and used as Argon2id salt */
  derivationNonce: string;
  public: {
    mlkem?: string; // base64(1568B)
    p521?:  string; // base64(67B)
  };
  private: {
    /** base64(12B) AES-GCM nonce for the encrypted private key blob */
    nonce:      string;
    /** base64( private_key_bytes + 16B auth tag ) */
    ciphertext: string;
    /** Argon2id parameters used — stored so open can re-derive with same settings */
    argon2: { iterations: number; memoryKiB: number; parallelism: number };
  };
}

// ─── Base64 helpers ───────────────────────────────────────────────────────────

const b64e = (u: Uint8Array) => Buffer.from(u).toString('base64');
const b64d = (s: string)     => new Uint8Array(Buffer.from(s, 'base64'));

// ─── Private key serialisation ────────────────────────────────────────────────

function serializePrivKey(pk: HybridPrivateKey, algo: KeyAlgorithm): Uint8Array {
  if (algo === 'hybrid-mlkem1024-p521') {
    const buf = new Uint8Array(3168 + 66);
    buf.set(pk.mlkem);
    buf.set(pk.p521, 3168);
    return buf;
  }
  if (algo === 'pqc-mlkem1024')  return new Uint8Array(pk.mlkem);
  return new Uint8Array(pk.p521); // classical-p521
}

function deserializePrivKey(buf: Uint8Array, algo: KeyAlgorithm): HybridPrivateKey {
  if (algo === 'hybrid-mlkem1024-p521')
    return { mlkem: buf.slice(0, 3168), p521: buf.slice(3168, 3234) };
  if (algo === 'pqc-mlkem1024')
    return { mlkem: new Uint8Array(buf), p521: new Uint8Array(0) };
  return { mlkem: new Uint8Array(0), p521: new Uint8Array(buf) };
}

// ─── Argon2 param bridge (library uses `memory`, keys.json stores `memoryKiB`) ─

function toLibParams(argon2: KeysJson['private']['argon2']): Partial<Argon2Params> {
  return { iterations: argon2.iterations, memory: argon2.memoryKiB, parallelism: argon2.parallelism };
}

// ─── Build ────────────────────────────────────────────────────────────────────

/**
 * Derive a keypair + wrapping key, encrypt the private key, and assemble keys.json.
 * Uses `deriveKeyPairAndWrapKey` from the library — one Argon2id call only.
 */
export async function buildKeysJson(
  algo:      KeyAlgorithm,
  passphrase: string,
  nonce:     Uint8Array,
  argon2Params: Argon2Params,
): Promise<{ keysJson: KeysJson; keyPair: HybridKeyPair }> {
  const { keyPair, wrapKey } = await deriveKeyPairAndWrapKey(
    passphrase, nonce, argon2Params,
  );

  const privBlob  = serializePrivKey(keyPair.privateKey, algo);
  const wrapNonce = getSecureRandom(12);
  const encrypted = await aesGcmEncrypt(privBlob, wrapKey, wrapNonce);
  wipe(privBlob, wrapKey);

  const keysJson: KeysJson = {
    version:         1,
    algorithm:       algo,
    created:         new Date().toISOString(),
    derivationNonce: b64e(nonce),
    public: {
      ...(algo !== 'classical-p521'  && { mlkem: b64e(keyPair.publicKey.mlkem) }),
      ...(algo !== 'pqc-mlkem1024'   && { p521:  b64e(keyPair.publicKey.p521)  }),
    },
    private: {
      nonce:      b64e(wrapNonce),
      ciphertext: b64e(encrypted),
      argon2: {
        iterations:  argon2Params.iterations,
        memoryKiB:   argon2Params.memory,
        parallelism: argon2Params.parallelism,
      },
    },
  };

  return { keysJson, keyPair };
}

// ─── Load / Save ──────────────────────────────────────────────────────────────

export function saveKeys(path: string, kj: KeysJson): void {
  writeFileSync(path, JSON.stringify(kj, null, 2) + '\n', 'utf8');
}

export function loadKeys(path: string): KeysJson {
  const kj = JSON.parse(readFileSync(path, 'utf8')) as KeysJson;
  if (kj.version !== 1) throw new Error(`Unsupported keys.json version: ${kj.version}`);
  return kj;
}

// ─── Public key accessors ─────────────────────────────────────────────────────

export function detectMode(kj: KeysJson): 'hybrid' | 'pqc' | 'p521' {
  const hasPQC  = Boolean(kj.public.mlkem);
  const hasP521 = Boolean(kj.public.p521);
  if (hasPQC && hasP521) return 'hybrid';
  if (hasPQC)  return 'pqc';
  if (hasP521) return 'p521';
  throw new Error('keys.json contains no usable public keys');
}

export function getPublicKeyBytes(kj: KeysJson): { mlkem: Uint8Array; p521: Uint8Array } {
  return {
    mlkem: kj.public.mlkem ? b64d(kj.public.mlkem) : new Uint8Array(0),
    p521:  kj.public.p521  ? b64d(kj.public.p521)  : new Uint8Array(0),
  };
}

// ─── Unlock private key ───────────────────────────────────────────────────────

/**
 * Re-derive the wrapping key from the passphrase, then AES-decrypt the stored
 * private key blob. Uses library functions exclusively.
 */
export async function unlockPrivateKey(kj: KeysJson, passphrase: string): Promise<HybridPrivateKey> {
  const nonce = b64d(kj.derivationNonce);

  // Re-derive: we only need wrapKey; discard keyPair immediately
  const { keyPair: discarded, wrapKey } = await deriveKeyPairAndWrapKey(
    passphrase, nonce, toLibParams(kj.private.argon2),
  );
  wipe(discarded.privateKey.mlkem, discarded.privateKey.p521);

  const wrapNonce    = b64d(kj.private.nonce);
  const encryptedBlob = b64d(kj.private.ciphertext);
  const privBlob = await aesGcmDecrypt(encryptedBlob, wrapKey, wrapNonce);
  wipe(wrapKey);

  const privKey = deserializePrivKey(privBlob, kj.algorithm);
  wipe(privBlob);
  return privKey;
}
