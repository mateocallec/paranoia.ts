/**
 * Deterministic keypair derivation from a master password.
 *
 * Security model:
 *  - The derivation_nonce is a per-user random value stored server-side.
 *    It is NOT a secret, but makes pre-computation attacks against the
 *    master password infeasible.
 *  - Argon2id (STRONG_ARGON2_PARAMS) provides memory-hard key stretching.
 *  - HKDF-SHA384 expands the Argon2id output deterministically into
 *    separate ML-KEM and P-521 key material.
 *  - The same (masterPassword, username, derivationNonce) triple always
 *    produces the same keypair — so the private key never needs to be stored.
 */

import { ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { secp521r1 as p521 } from '@noble/curves/p521';
import { hkdf } from '@noble/hashes/hkdf';
import { sha384 } from '@noble/hashes/sha2';
import { deriveKey } from './kdf';
import { wipe } from './memory';
import { STRONG_ARGON2_PARAMS, type Argon2Params, type HybridKeyPair } from '../types';

const ENC = new TextEncoder();
const KDF_INFO = ENC.encode('paranoia.ts:v1:keypair-expansion');
const P521_INFO = ENC.encode('paranoia.ts:v1:p521-sk');

// ─── Internal: expand a 32-byte seed → full HybridKeyPair via HKDF-SHA384 ────

async function expandKeypairFromSeed(seed: Uint8Array, salt: Uint8Array): Promise<HybridKeyPair> {
  // [0..64)   → ML-KEM-1024 keygen seed
  // [64..130) → P-521 private key material
  const expanded = hkdf(sha384, seed, salt, KDF_INFO, 130);

  const mlkemSeed = expanded.slice(0, 64);
  const { publicKey: mlkemPk, secretKey: mlkemSk } = ml_kem1024.keygen(mlkemSeed);
  wipe(mlkemSeed);

  const p521Material = expanded.slice(64);
  wipe(expanded);

  let p521Sk: Uint8Array | undefined;
  for (let ctr = 0; ctr < 256; ctr++) {
    const candidate = hkdf(sha384, p521Material, new Uint8Array([ctr]), P521_INFO, 66);
    // P-521 order n ≈ 2^521.  HKDF produces 528 bits (66 bytes); a random
    // 528-bit integer only lands in [1, n-1] with probability ≈ 1/128, so the
    // loop would exhaust its budget ~13 % of the time.
    // Masking the top 7 bits clamps the value to 521 bits, making
    // P(valid) = (n-1)/2^521 ≈ 1 − 2^−260.  The first iteration always works.
    candidate[0] = (candidate[0] ?? 0) & 0x01;
    try {
      p521.getPublicKey(candidate);
      p521Sk = candidate;
      break;
    } catch {
      wipe(candidate);
    }
  }
  wipe(p521Material);

  if (!p521Sk) throw new Error('P-521 key derivation exhausted 256 attempts — internal error');

  return {
    publicKey: { mlkem: mlkemPk, p521: p521.getPublicKey(p521Sk, true) },
    privateKey: { mlkem: mlkemSk, p521: p521Sk },
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Derive a hybrid keypair deterministically from a master password.
 * Used by the web app: binds derivation to a specific user via `username`.
 *
 * @param username        Domain-separates the Argon2id salt across users.
 * @param derivationNonce 32-byte random value stored server-side (public, like a salt).
 */
export async function deriveKeyPairFromMasterPassword(
  masterPassword: string,
  username: string,
  derivationNonce: Uint8Array,
  params?: Partial<Argon2Params>,
): Promise<HybridKeyPair> {
  // L3: length-prefixed encoding prevents collisions where different
  // (username, nonce) pairs share the same byte sequence.
  // Format: [4B big-endian username_len][username_bytes][nonce_bytes]
  const usernameBytes = ENC.encode(username);
  const saltInput = new Uint8Array(4 + usernameBytes.length + derivationNonce.length);
  new DataView(saltInput.buffer).setUint32(0, usernameBytes.length, false);
  saltInput.set(usernameBytes, 4);
  saltInput.set(derivationNonce, 4 + usernameBytes.length);
  const salt = new Uint8Array(
    await crypto.subtle.digest(
      'SHA-256',
      saltInput.buffer.slice(
        saltInput.byteOffset,
        saltInput.byteOffset + saltInput.byteLength,
      ) as ArrayBuffer,
    ),
  );

  const seed = await deriveKey(masterPassword, salt, { ...STRONG_ARGON2_PARAMS, ...params });
  const keyPair = await expandKeypairFromSeed(seed, salt);
  wipe(seed);
  return keyPair;
}

/**
 * Derive a keypair AND a separate AES-256 wrapping key from one Argon2id call.
 * Used by the CLI to both generate the keypair and encrypt the private key blob
 * for storage in keys.json — without running Argon2id twice.
 *
 *   argon2id(password, SHA-256(nonce), 64 bytes)
 *     [0..32)  → HKDF seed for keypair expansion
 *     [32..64) → AES-256-GCM wrapping key (encrypts the stored private key)
 *
 * @param derivationNonce 32-byte random value (stored in keys.json, public).
 */
export async function deriveKeyPairAndWrapKey(
  masterPassword: string,
  derivationNonce: Uint8Array,
  params?: Partial<Argon2Params>,
): Promise<{ keyPair: HybridKeyPair; wrapKey: Uint8Array }> {
  const saltBuf = await crypto.subtle.digest(
    'SHA-256',
    derivationNonce.buffer.slice(
      derivationNonce.byteOffset,
      derivationNonce.byteOffset + derivationNonce.byteLength,
    ) as ArrayBuffer,
  );
  const salt = new Uint8Array(saltBuf);

  const seed64 = await deriveKey(masterPassword, salt, { ...STRONG_ARGON2_PARAMS, ...params }, 64);

  const kpSeed = seed64.slice(0, 32);
  const wrapKey = new Uint8Array(seed64.slice(32, 64));
  wipe(seed64);

  const keyPair = await expandKeypairFromSeed(kpSeed, salt);
  wipe(kpSeed);

  return { keyPair, wrapKey };
}
