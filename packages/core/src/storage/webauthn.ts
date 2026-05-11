import { type WebAuthnCredential } from '../types';
import { wipe } from '../core/memory';

const WRAPPING_INFO = new TextEncoder().encode('paranoia.ts webauthn key-wrapping v1');

// Fixed PRF evaluation input — same value on every assertion produces the same key.
// Changing this string would invalidate all stored keypairs.
const PRF_EVAL_INPUT = new TextEncoder().encode('paranoia.ts:v1:keypair-prf-key');

function rpId(): string {
  return typeof window !== 'undefined' ? window.location.hostname : 'localhost';
}

/**
 * Register a new platform authenticator credential for key-wrapping.
 * User verification is required so biometrics / PIN must pass.
 */
export async function registerWebAuthnCredential(userId: string): Promise<WebAuthnCredential> {
  const challenge    = new Uint8Array(32);
  const userIdBytes  = new TextEncoder().encode(userId);
  crypto.getRandomValues(challenge);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: rpId(), name: 'paranoia.ts' },
      user: { id: userIdBytes, name: userId, displayName: userId },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7   }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        userVerification:        'required',
        residentKey:             'required',
      },
      timeout: 60_000,
    },
  }) as PublicKeyCredential | null;

  if (!credential) throw new Error('WebAuthn credential creation was cancelled or failed');

  return { id: new Uint8Array(credential.rawId) };
}

/**
 * Perform a WebAuthn assertion and derive a 32-byte key-wrapping key from
 * the authenticator data + signature via HKDF-SHA-384.
 *
 * The wrapping key is bound to:
 *  - The specific credential (credentialId as HKDF salt)
 *  - The specific authenticator session (authData + signature as IKM)
 *
 * This means the derived key changes each assertion.  Callers must use it
 * immediately to unwrap a stored symmetric key and then discard it.
 */
export async function deriveWebAuthnWrappingKey(credentialId: Uint8Array): Promise<Uint8Array> {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: rpId(),
      allowCredentials: [{ type: 'public-key', id: credentialId.buffer.slice(credentialId.byteOffset, credentialId.byteOffset + credentialId.byteLength) as ArrayBuffer }],
      userVerification: 'required',
      timeout: 60_000,
    },
  }) as PublicKeyCredential | null;

  if (!assertion) throw new Error('WebAuthn assertion was cancelled or failed');

  const resp = assertion.response as AuthenticatorAssertionResponse;
  const authData = new Uint8Array(resp.authenticatorData);
  const sig      = new Uint8Array(resp.signature);

  // IKM = authData || sig  (both are session-unique when UP/UV bits are set)
  const ikm = new Uint8Array(authData.length + sig.length);
  ikm.set(authData);
  ikm.set(sig, authData.length);

  const toAB = (u: Uint8Array) => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
  const baseKey = await crypto.subtle.importKey('raw', toAB(ikm), 'HKDF', false, ['deriveKey']);
  wipe(ikm); // L1: wipe authenticator signature material immediately after importKey
  const wrappingCryptoKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-384', salt: toAB(credentialId), info: toAB(WRAPPING_INFO) },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );

  const raw = await crypto.subtle.exportKey('raw', wrappingCryptoKey);
  return new Uint8Array(raw);
}

// ─── WebAuthn PRF — deterministic keypair unlock ───────────────────────────────
//
// The PRF (Pseudo-Random Function) extension lets the authenticator compute a
// stable 32-byte output from a fixed input.  Unlike signatures, this output is
// the SAME across every assertion for the same credential, making it usable as
// a persistent AES-256 wrapping key for the stored private keypair.
//
// Browser support: Chrome 116+, Firefox 122+, Safari 18+ (partial).
// Requires a platform authenticator (Touch ID, Windows Hello, Android biometrics).

type PRFExtOutput = { prf?: { results?: { first?: ArrayBuffer } } };
type PRFExtInput  = { prf: { eval: { first: BufferSource } } };

function toAB(u: Uint8Array): ArrayBuffer {
  return u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;
}

/**
 * Register a platform authenticator credential with the PRF extension.
 *
 * Returns the credential ID (store in localStorage) and the PRF key (use once
 * immediately to encrypt the keypair via `storeKeyPair`, then wipe it).
 *
 * Throws if the authenticator does not support PRF — callers should fall back
 * to asking the master password in that case.
 */
export async function registerWebAuthnPRF(userId: string): Promise<{
  credentialId: Uint8Array;
  prfKey:       Uint8Array;
}> {
  const challenge   = new Uint8Array(32);
  const userIdBytes = new TextEncoder().encode(userId);
  crypto.getRandomValues(challenge);

  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: rpId(), name: 'paranoia.ts' },
      user: { id: userIdBytes, name: userId, displayName: userId },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7   }, // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        // No authenticatorAttachment restriction — allows both platform
        // authenticators (Touch ID, Windows Hello) and roaming authenticators
        // (YubiKey and other FIDO2 security keys).
        userVerification: 'required',
        residentKey:      'preferred',
      },
      extensions: { prf: { eval: { first: PRF_EVAL_INPUT } } } as unknown as PRFExtInput,
      timeout: 60_000,
    },
  }) as PublicKeyCredential | null;

  if (!cred) throw new Error('WebAuthn credential creation was cancelled');

  const ext = cred.getClientExtensionResults() as PRFExtOutput;
  const prfBuf = ext.prf?.results?.first;

  if (!prfBuf) {
    throw new Error(
      'This authenticator does not support the PRF extension. ' +
      'Try a FIDO2 security key (YubiKey 5+) or a platform authenticator ' +
      '(Touch ID, Windows Hello, Android biometrics).',
    );
  }

  return {
    credentialId: new Uint8Array(cred.rawId),
    prfKey:       new Uint8Array(prfBuf),
  };
}

/**
 * Authenticate with an existing PRF credential and retrieve the deterministic
 * 32-byte key.  The key is identical to the one returned at registration.
 *
 * Use this key immediately to decrypt the keypair via `loadKeyPair`, then wipe it.
 */
export async function getWebAuthnPRFKey(credentialId: Uint8Array): Promise<Uint8Array> {
  const challenge = new Uint8Array(32);
  crypto.getRandomValues(challenge);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: rpId(),
      allowCredentials: [{ type: 'public-key', id: toAB(credentialId) }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: PRF_EVAL_INPUT } } } as unknown as PRFExtInput,
      timeout: 60_000,
    },
  }) as PublicKeyCredential | null;

  if (!assertion) throw new Error('WebAuthn authentication was cancelled');

  const ext = assertion.getClientExtensionResults() as PRFExtOutput;
  const prfBuf = ext.prf?.results?.first;

  if (!prfBuf) {
    throw new Error(
      'PRF output not available. ' +
      'Your authenticator may not support this feature, or registration was done on a different device.',
    );
  }

  return new Uint8Array(prfBuf);
}
