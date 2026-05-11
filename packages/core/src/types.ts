// ─── Public key types ─────────────────────────────────────────────────────────

export interface HybridPublicKey {
  /** ML-KEM-1024 public key — 1568 bytes */
  mlkem: Uint8Array;
  /** P-521 public key — 67 bytes (compressed) */
  p521: Uint8Array;
}

export interface HybridPrivateKey {
  /** ML-KEM-1024 secret key — 3168 bytes */
  mlkem: Uint8Array;
  /** P-521 private key — 66 bytes */
  p521: Uint8Array;
}

export interface HybridKeyPair {
  publicKey: HybridPublicKey;
  privateKey: HybridPrivateKey;
}

// ─── WebAuthn ─────────────────────────────────────────────────────────────────

export interface WebAuthnCredential {
  /** Credential ID as returned by the authenticator */
  id: Uint8Array;
}

// ─── Argon2id parameters ──────────────────────────────────────────────────────

export interface Argon2Params {
  /** Time cost — number of iterations (default: 3) */
  iterations: number;
  /** Memory cost in KB (default: 65536 = 64 MB) */
  memory: number;
  /** Parallelism factor (default: 4) */
  parallelism: number;
}

export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  iterations: 3,
  memory: 65536,
  parallelism: 4,
};

export const STRONG_ARGON2_PARAMS: Argon2Params = {
  iterations: 5,
  memory: 524288, // 512 MB
  parallelism: 4,
};

// ─── Seal options ─────────────────────────────────────────────────────────────

export interface SealOptions {
  argon2?: Partial<Argon2Params>;
}

// ─── Packet format constants ──────────────────────────────────────────────────

export const PACKET_VERSION = 0x01;
export const MODE_PASSPHRASE = 0x01;
export const MODE_ASYMMETRIC = 0x02;

/** Fixed sizes for layout parsing */
export const SIZES = {
  VERSION: 1,
  MODE: 1,
  ARGON2_SALT: 32,
  ARGON2_ITERATIONS: 3, // big-endian uint24
  ARGON2_MEMORY: 4,     // big-endian uint32
  ARGON2_PARALLELISM: 1,
  NONCE: 12,
  AUTH_TAG: 16,
  MLKEM_CT: 1568,
  P521_EPH_PK: 67,
  MLKEM_PK: 1568,
  MLKEM_SK: 3168,
  P521_PK: 67,
  P521_SK: 66,
} as const;

// Passphrase packet header size (before ciphertext)
export const PASSPHRASE_HEADER_SIZE =
  SIZES.VERSION + SIZES.MODE + SIZES.ARGON2_SALT +
  SIZES.ARGON2_ITERATIONS + SIZES.ARGON2_MEMORY + SIZES.ARGON2_PARALLELISM +
  SIZES.NONCE;

// Asymmetric packet header size (before ciphertext)
export const ASYMMETRIC_HEADER_SIZE =
  SIZES.VERSION + SIZES.MODE + SIZES.MLKEM_CT + SIZES.P521_EPH_PK + SIZES.NONCE;
