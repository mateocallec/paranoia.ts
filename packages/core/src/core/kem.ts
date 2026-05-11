/**
 * Hybrid KEM — ML-KEM-1024 + P-521 ECDH.
 *
 * Security upgrades applied in this version:
 *
 *  P-521 ECDH   → SubtleCrypto crypto.subtle.deriveBits
 *                  Constant-time guaranteed by the browser vendor (BoringSSL /
 *                  OpenSSL). Replaces @noble/curves for the secret-dependent
 *                  scalar multiplication. @noble/curves is kept only for the
 *                  public-data operations (point compression / decompression).
 *
 *  HKDF-SHA-384 → SubtleCrypto crypto.subtle.deriveBits
 *                  Native, hardware-accelerated, no JIT exposure.
 *
 *  P-521 keygen → SubtleCrypto crypto.subtle.generateKey
 *                  Guaranteed valid private scalar without rejection-sampling.
 *
 *  ML-KEM-1024  → @noble/post-quantum (pure TypeScript).
 *                  NOTE: A JavaScript runtime cannot guarantee constant-time
 *                  lattice arithmetic. For critical deployments this should be
 *                  replaced with a WASM binary compiled from the NIST reference
 *                  C implementation (pqclean/ml-kem) when a production-ready
 *                  npm package becomes available.
 */

import { ml_kem1024 } from '@noble/post-quantum/ml-kem';
import { secp521r1 as p521 } from '@noble/curves/p521'; // point compression / decompression only
import { concat, wipe } from './memory';
import { getSecureRandom } from './entropy';
import { SIZES, type HybridKeyPair, type HybridPublicKey, type HybridPrivateKey } from '../types';

// ─── SubtleCrypto helpers ─────────────────────────────────────────────────────

const toAB = (u: Uint8Array): ArrayBuffer =>
  u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

/**
 * M3: loop-based btoa avoids spread-argument stack overflow on large inputs.
 * Used only for the JWK `d` extraction in generateP521KeyPair (SubtleCrypto export).
 */
const toB64url = (u: Uint8Array): string => {
  let s = '';
  for (const b of u) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

const fromB64url = (s: string): Uint8Array =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

/**
 * M2: Build a PKCS#8 DER-encoded P-521 private key.
 * Binary-only — no base64 string materialises the private scalar.
 *
 * Structure (98 bytes, fixed for P-521):
 *   SEQUENCE { version=0, AlgorithmIdentifier { id-ecPublicKey, secp521r1 },
 *              OCTET STRING { ECPrivateKey { version=1, privateKey(66B) } } }
 */
function buildP521Pkcs8(privKeyBytes: Uint8Array): Uint8Array {
  const buf = new Uint8Array(98);
  let o = 0;
  buf[o++] = 0x30; buf[o++] = 0x60; // SEQUENCE (96 B)
  buf[o++] = 0x02; buf[o++] = 0x01; buf[o++] = 0x00; // INTEGER version=0
  buf[o++] = 0x30; buf[o++] = 0x10; // AlgorithmIdentifier SEQUENCE (16 B)
  buf.set([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01], o); o += 9; // OID id-ecPublicKey
  buf.set([0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23], o); o += 7;             // OID secp521r1
  buf[o++] = 0x04; buf[o++] = 0x49; // OCTET STRING (73 B)
  buf[o++] = 0x30; buf[o++] = 0x47; // ECPrivateKey SEQUENCE (71 B)
  buf[o++] = 0x02; buf[o++] = 0x01; buf[o++] = 0x01; // INTEGER version=1
  buf[o++] = 0x04; buf[o++] = 0x42; // privateKey OCTET STRING (66 B)
  // Left-pad scalar to exactly 66 bytes
  buf.set(privKeyBytes, o + (SIZES.P521_SK - privKeyBytes.length));
  return buf;
}

/** HKDF-SHA-384 via SubtleCrypto — native, hardware-accelerated. */
async function hkdfSHA384(
  ikm:  Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  len:  number,
): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', toAB(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-384', salt: toAB(salt), info: toAB(info) },
    base,
    len * 8,
  );
  return new Uint8Array(bits);
}

// ─── P-521 via SubtleCrypto ───────────────────────────────────────────────────

/**
 * Generate a P-521 key pair using SubtleCrypto.
 * Returns the raw private scalar (66 B) and compressed public key (67 B).
 * @noble/curves is used only for point compression — no secret data involved.
 */
async function generateP521KeyPair(): Promise<{ privKey: Uint8Array; pubKey: Uint8Array }> {
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-521' },
    true,
    ['deriveBits'],
  );

  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey) as JsonWebKey & { d?: string };
  if (!jwk.d) throw new Error('P-521 JWK missing d field');

  const dBytes = fromB64url(jwk.d);
  const privKey = new Uint8Array(SIZES.P521_SK); // left-pad to exactly 66 bytes
  privKey.set(dBytes, SIZES.P521_SK - dBytes.length);

  const pubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)); // 133 B uncompressed
  const pubKey = p521.ProjectivePoint.fromHex(pubRaw).toRawBytes(true); // 67 B compressed

  return { privKey, pubKey };
}

/**
 * P-521 ECDH via SubtleCrypto.
 *
 * M2: The private key is imported as PKCS#8 binary (no base64url string).
 * The peer public key is imported as raw uncompressed bytes.
 * Neither path materialises the private scalar as a JS string.
 *
 * @noble/curves is used only to decompress the peer public key — a public-data
 * operation with no timing-sensitive material.
 */
async function ecdhP521(privKeyBytes: Uint8Array, peerPubCompressed: Uint8Array): Promise<Uint8Array> {
  // Decompress peer public key: 67 B compressed → 133 B uncompressed (public data)
  const peerUncompressed = p521.ProjectivePoint.fromHex(peerPubCompressed).toRawBytes(false);

  // Import private key as PKCS#8 binary — no JS string for the private scalar
  const pkcs8  = buildP521Pkcs8(privKeyBytes);
  const privCk = await crypto.subtle.importKey(
    'pkcs8', toAB(pkcs8),
    { name: 'ECDH', namedCurve: 'P-521' },
    false,
    ['deriveBits'],
  );
  wipe(pkcs8);

  // Import peer public key as raw uncompressed point (no JWK string needed)
  const peerCk = await crypto.subtle.importKey(
    'raw', toAB(peerUncompressed),
    { name: 'ECDH', namedCurve: 'P-521' },
    false,
    [],
  );

  // Constant-time ECDH — 528 bits = 66 bytes for P-521
  const bits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerCk },
    privCk,
    528,
  );

  return new Uint8Array(bits);
}

// ─── Key generation ───────────────────────────────────────────────────────────

export async function generateHybridKeyPair(): Promise<HybridKeyPair> {
  const mlkemSeed = getSecureRandom(64);
  const { publicKey: mlkemPk, secretKey: mlkemSk } = ml_kem1024.keygen(mlkemSeed);
  wipe(mlkemSeed);

  const { privKey: p521Sk, pubKey: p521Pk } = await generateP521KeyPair();

  return {
    publicKey:  { mlkem: mlkemPk, p521: p521Pk },
    privateKey: { mlkem: mlkemSk, p521: p521Sk },
  };
}

// ─── Hybrid KEM ───────────────────────────────────────────────────────────────

export interface EncapsulateResult {
  ciphertext:   Uint8Array;
  sharedSecret: Uint8Array;
}

export async function hybridEncapsulate(recipientPubKey: HybridPublicKey): Promise<EncapsulateResult> {
  const mlkemSeed = getSecureRandom(32);
  const { cipherText: mlkemCt, sharedSecret: mlkemSs } =
    ml_kem1024.encapsulate(recipientPubKey.mlkem, mlkemSeed);
  wipe(mlkemSeed);

  const { privKey: ephSk, pubKey: ephPk } = await generateP521KeyPair();
  const p521Raw = await ecdhP521(ephSk, recipientPubKey.p521);
  wipe(ephSk);

  const sharedSecret = await combineSecrets(mlkemSs, p521Raw, ephPk);
  wipe(mlkemSs as Uint8Array);
  wipe(p521Raw);

  return { ciphertext: concat(mlkemCt, ephPk), sharedSecret };
}

export async function hybridDecapsulate(
  ciphertext: Uint8Array,
  recipientPrivKey: HybridPrivateKey,
): Promise<Uint8Array> {
  const expectedLen = SIZES.MLKEM_CT + SIZES.P521_EPH_PK;
  if (ciphertext.length !== expectedLen) {
    throw new Error(`Hybrid KEM ciphertext: expected ${expectedLen} B, got ${ciphertext.length}`);
  }

  const mlkemCt = ciphertext.subarray(0, SIZES.MLKEM_CT);
  const ephPk   = ciphertext.subarray(SIZES.MLKEM_CT);

  const mlkemSs = ml_kem1024.decapsulate(mlkemCt, recipientPrivKey.mlkem);
  const p521Raw  = await ecdhP521(recipientPrivKey.p521, ephPk);

  const sharedSecret = await combineSecrets(mlkemSs, p521Raw, ephPk);
  wipe(mlkemSs as Uint8Array);
  wipe(p521Raw);

  return sharedSecret;
}

// ─── Single-algorithm variants ────────────────────────────────────────────────

const PQC_INFO  = new TextEncoder().encode('paranoia.ts v1 pqc-only kem');
const P521_INFO = new TextEncoder().encode('paranoia.ts v1 p521-only kem');

export async function encapsulatePqc(mlkemPublicKey: Uint8Array): Promise<EncapsulateResult> {
  const seed = getSecureRandom(32);
  const { cipherText, sharedSecret: ss } = ml_kem1024.encapsulate(mlkemPublicKey, seed);
  wipe(seed);
  const key = await hkdfSHA384(ss, cipherText.subarray(0, 32), PQC_INFO, 32);
  wipe(ss as Uint8Array);
  return { ciphertext: cipherText, sharedSecret: key };
}

export async function decapsulatePqc(
  ciphertext:     Uint8Array,
  mlkemSecretKey: Uint8Array,
): Promise<Uint8Array> {
  const ss  = ml_kem1024.decapsulate(ciphertext, mlkemSecretKey);
  const key = await hkdfSHA384(ss, ciphertext.subarray(0, 32), PQC_INFO, 32);
  wipe(ss as Uint8Array);
  return key;
}

export interface P521EncapsulateResult {
  ephemeralPublicKey: Uint8Array; // 67 B compressed
  sharedSecret:       Uint8Array; // 32 B
}

export async function encapsulateP521(p521PublicKey: Uint8Array): Promise<P521EncapsulateResult> {
  const { privKey: ephSk, pubKey: ephPk } = await generateP521KeyPair();
  const sharedRaw = await ecdhP521(ephSk, p521PublicKey);
  wipe(ephSk);
  const key = await hkdfSHA384(sharedRaw, ephPk, P521_INFO, 32);
  wipe(sharedRaw);
  return { ephemeralPublicKey: ephPk, sharedSecret: key };
}

export async function decapsulateP521(
  ephemeralPublicKey: Uint8Array,
  p521SecretKey:      Uint8Array,
): Promise<Uint8Array> {
  const sharedRaw = await ecdhP521(p521SecretKey, ephemeralPublicKey);
  const key = await hkdfSHA384(sharedRaw, ephemeralPublicKey, P521_INFO, 32);
  wipe(sharedRaw);
  return key;
}

// ─── Key combination ──────────────────────────────────────────────────────────

async function combineSecrets(
  mlkemSs: Uint8Array,
  p521Raw: Uint8Array,
  ephPk:   Uint8Array,
): Promise<Uint8Array> {
  const ikm  = concat(mlkemSs, p521Raw);
  const info = new TextEncoder().encode('paranoia.ts v1 hybrid kem');
  const key  = await hkdfSHA384(ikm, ephPk, info, 32);
  wipe(ikm);
  return key;
}

export type { HybridKeyPair, HybridPublicKey, HybridPrivateKey };
