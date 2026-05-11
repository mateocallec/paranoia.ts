// ─── Main entry point ─────────────────────────────────────────────────────────

export { Paranoia } from './Paranoia';
export { ParanoiaWorker } from './workers/ParanoiaWorker';

// ─── Types ────────────────────────────────────────────────────────────────────

export type {
  HybridKeyPair,
  HybridPublicKey,
  HybridPrivateKey,
  WebAuthnCredential,
  Argon2Params,
  SealOptions,
} from './types';

export { DEFAULT_ARGON2_PARAMS, STRONG_ARGON2_PARAMS } from './types';

// ─── Low-level primitives (for advanced users) ────────────────────────────────

export {
  getSecureRandom,
  enableWebcamEntropy,
  disableWebcamEntropy,
  isWebcamEntropyActive,
  injectEntropy,
} from './core/entropy';
export {
  generateHybridKeyPair,
  hybridEncapsulate,
  hybridDecapsulate,
  encapsulatePqc,
  decapsulatePqc,
  encapsulateP521,
  decapsulateP521,
} from './core/kem';
export type { P521EncapsulateResult } from './core/kem';
export { deriveKey } from './core/kdf';
export { deriveKeyPairFromMasterPassword, deriveKeyPairAndWrapKey } from './core/derive';
export { aesGcmEncrypt, aesGcmDecrypt } from './core/symmetric';
export { wipe, constantTimeEqual, concat } from './core/memory';
export { storeKeyPair, loadKeyPair, deleteKeyPair, SessionKeyStore } from './storage/indexeddb';
export {
  registerWebAuthnCredential,
  deriveWebAuthnWrappingKey,
  registerWebAuthnPRF,
  getWebAuthnPRFKey,
} from './storage/webauthn';
