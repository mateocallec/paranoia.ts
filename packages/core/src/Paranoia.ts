import {
  getSecureRandom,
  enableWebcamEntropy,
  disableWebcamEntropy,
  isWebcamEntropyActive,
} from './core/entropy';
import { deriveKey } from './core/kdf';
import { generateHybridKeyPair, hybridEncapsulate, hybridDecapsulate } from './core/kem';
import { aesGcmEncrypt, aesGcmDecrypt } from './core/symmetric';
import {
  wipe,
  concat,
  writeUint24BE,
  writeUint32BE,
  readUint24BE,
  readUint32BE,
} from './core/memory';
import { storeKeyPair, loadKeyPair, deleteKeyPair, SessionKeyStore } from './storage/indexeddb';
import { registerWebAuthnCredential, deriveWebAuthnWrappingKey } from './storage/webauthn';
import {
  PACKET_VERSION,
  MODE_PASSPHRASE,
  MODE_ASYMMETRIC,
  DEFAULT_ARGON2_PARAMS,
  SIZES,
  type HybridKeyPair,
  type HybridPublicKey,
  type WebAuthnCredential,
  type SealOptions,
  type Argon2Params,
} from './types';

// ─── AAD helpers ─────────────────────────────────────────────────────────────

/**
 * Build the 42-byte AAD used for passphrase-mode packets.
 * Covers: version, mode, Argon2id salt and cost parameters.
 * Any bit-flip in the header will cause AES-GCM to reject the packet.
 */
function buildPassphraseAAD(salt: Uint8Array, params: Argon2Params): Uint8Array {
  const aad = new Uint8Array(42);
  aad[0] = PACKET_VERSION;
  aad[1] = MODE_PASSPHRASE;
  aad.set(salt, 2);
  writeUint24BE(aad, 34, params.iterations);
  writeUint32BE(aad, 37, params.memory);
  aad[41] = params.parallelism & 0xff;
  return aad;
}

/**
 * Build a 32-byte AAD for asymmetric-mode packets by hashing the recipient's
 * public key. Binds the ciphertext to the intended recipient — any key
 * substitution attempt will cause AES-GCM to reject the packet.
 */
async function buildRecipientAAD(pubKey: HybridPublicKey): Promise<Uint8Array> {
  const combined = concat(pubKey.mlkem, pubKey.p521);
  const hash = await crypto.subtle.digest(
    'SHA-256',
    combined.buffer.slice(
      combined.byteOffset,
      combined.byteOffset + combined.byteLength,
    ) as ArrayBuffer,
  );
  return new Uint8Array(hash);
}

// ─── Packet encoding helpers ──────────────────────────────────────────────────

/**
 * Passphrase-mode packet layout (all integers big-endian):
 *
 *   Offset   Size   Field
 *   0        1      Version (0x01)
 *   1        1      Mode (0x01)
 *   2        32     Argon2id salt
 *   34       3      Argon2id iterations (uint24)
 *   37       4      Argon2id memory KB  (uint32)
 *   41       1      Argon2id parallelism
 *   42       12     AES-GCM nonce
 *   54       n+16   AES-GCM ciphertext + auth-tag
 */
function encodePassphrasePacket(
  salt: Uint8Array,
  params: Argon2Params,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const hdr = new Uint8Array(54);
  hdr[0] = PACKET_VERSION;
  hdr[1] = MODE_PASSPHRASE;
  hdr.set(salt, 2);
  writeUint24BE(hdr, 34, params.iterations);
  writeUint32BE(hdr, 37, params.memory);
  hdr[41] = params.parallelism & 0xff;
  hdr.set(nonce, 42);
  return concat(hdr, ciphertext);
}

function decodePassphrasePacket(packet: Uint8Array): {
  salt: Uint8Array;
  params: Argon2Params;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
} {
  if (packet.length < 54 + 16 + 1) throw new Error('Passphrase packet too short');
  return {
    salt: packet.slice(2, 34),
    params: {
      iterations: readUint24BE(packet, 34),
      memory: readUint32BE(packet, 37),
      parallelism: packet[41] as number,
    },
    nonce: packet.slice(42, 54),
    ciphertext: packet.slice(54),
  };
}

/**
 * Asymmetric-mode packet layout:
 *
 *   Offset   Size    Field
 *   0        1       Version (0x01)
 *   1        1       Mode (0x02)
 *   2        1568    ML-KEM-1024 ciphertext
 *   1570     67      P-521 ephemeral public key (compressed)
 *   1637     12      AES-GCM nonce
 *   1649     n+16    AES-GCM ciphertext + auth-tag
 */
const ASYM_HDR = 2 + SIZES.MLKEM_CT + SIZES.P521_EPH_PK + SIZES.NONCE; // 1649

function encodeAsymmetricPacket(
  kemCt: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  const hdr = new Uint8Array(ASYM_HDR);
  hdr[0] = PACKET_VERSION;
  hdr[1] = MODE_ASYMMETRIC;
  hdr.set(kemCt, 2);
  hdr.set(nonce, 2 + SIZES.MLKEM_CT + SIZES.P521_EPH_PK);
  return concat(hdr, ciphertext);
}

function decodeAsymmetricPacket(packet: Uint8Array): {
  kemCt: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
} {
  if (packet.length < ASYM_HDR + 16 + 1) throw new Error('Asymmetric packet too short');
  const kemCtEnd = 2 + SIZES.MLKEM_CT + SIZES.P521_EPH_PK;
  return {
    kemCt: packet.slice(2, kemCtEnd),
    nonce: packet.slice(kemCtEnd, kemCtEnd + SIZES.NONCE),
    ciphertext: packet.slice(kemCtEnd + SIZES.NONCE),
  };
}

// ─── Main class ───────────────────────────────────────────────────────────────

export class Paranoia {
  // ── Entropy ──────────────────────────────────────────────────────────────

  /** Start mixing webcam pixel noise into every `getSecureRandom` call. */
  async enableWebcamEntropy(stream: MediaStream): Promise<void> {
    return enableWebcamEntropy(stream);
  }

  disableWebcamEntropy(): void {
    disableWebcamEntropy();
  }

  isWebcamEntropyActive(): boolean {
    return isWebcamEntropyActive();
  }

  // ── Key generation ────────────────────────────────────────────────────────

  /**
   * Generate a fresh hybrid ML-KEM-1024 + P-521 keypair.
   * Private key material should be stored immediately with `storeKeyPair` and
   * then wiped from memory.
   */
  generateKeyPair(): Promise<HybridKeyPair> {
    return generateHybridKeyPair();
  }

  // ── Passphrase-based seal / unseal ────────────────────────────────────────

  /**
   * Encrypt `data` with a passphrase.
   *
   * Key derivation:  Argon2id(passphrase, random_salt) → 32-byte AES key
   * Encryption:      AES-256-GCM with random 12-byte nonce
   *
   * The output packet is self-contained — it includes the salt and all Argon2id
   * parameters needed for decryption.
   *
   * AES-256 provides 128-bit post-quantum security (Grover halves key length;
   * 256/2 = 128 bits classical equivalent).
   */
  async seal(data: Uint8Array, passphrase: string, options?: SealOptions): Promise<Uint8Array> {
    const params: Argon2Params = { ...DEFAULT_ARGON2_PARAMS, ...options?.argon2 };
    const salt = getSecureRandom(SIZES.ARGON2_SALT);
    const nonce = getSecureRandom(SIZES.NONCE);

    // Build header prefix used as AAD — authenticates the Argon2 cost params so
    // an attacker cannot downgrade them (e.g. memory=1) to speed up brute-force.
    const aad = buildPassphraseAAD(salt, params);

    const aesKey = await deriveKey(passphrase, salt, params);
    const ciphertext = await aesGcmEncrypt(data, aesKey, nonce, aad);
    wipe(aesKey);

    return encodePassphrasePacket(salt, params, nonce, ciphertext);
  }

  /**
   * Decrypt a passphrase-sealed packet.  Throws on wrong passphrase or
   * tampered ciphertext (including tampered Argon2 cost parameters).
   */
  async unseal(sealed: Uint8Array, passphrase: string): Promise<Uint8Array> {
    if (sealed[1] !== MODE_PASSPHRASE) {
      throw new Error('Packet is not in passphrase mode — use unsealWith() instead');
    }
    const { salt, params, nonce, ciphertext } = decodePassphrasePacket(sealed);

    // Validate before running Argon2 — prevents resource-exhaustion via crafted header
    if (params.iterations < 1 || params.iterations > 1_000)
      throw new Error('Invalid Argon2id iterations in packet (1–1000 allowed)');
    if (params.memory < 8 || params.memory > 4_194_304)
      throw new Error('Invalid Argon2id memory in packet (8 KiB–4 GiB allowed)');
    if (params.parallelism < 1 || params.parallelism > 64)
      throw new Error('Invalid Argon2id parallelism in packet (1–64 allowed)');

    const aad = buildPassphraseAAD(salt, params);

    const aesKey = await deriveKey(passphrase, salt, params);
    const plaintext = await aesGcmDecrypt(ciphertext, aesKey, nonce, aad);
    wipe(aesKey);

    return plaintext;
  }

  // ── Hybrid asymmetric seal / unseal ───────────────────────────────────────

  /**
   * Encrypt `data` to a recipient's hybrid public key.
   *
   * Key agreement:  ML-KEM-1024 encapsulate  +  P-521 ephemeral ECDH
   * KDF:            HKDF-SHA-384(mlkem_ss ∥ p521_ss)  →  32-byte AES key
   * Encryption:     AES-256-GCM
   *
   * Both KEM layers must be broken simultaneously for confidentiality to fail.
   */
  async sealTo(data: Uint8Array, recipientPubKey: HybridPublicKey): Promise<Uint8Array> {
    const nonce = getSecureRandom(SIZES.NONCE);

    // AAD = SHA-256(recipientPubKey) — binds ciphertext to the intended recipient.
    // Any key-substitution or forwarding attack will fail the AES-GCM tag check.
    const aad = await buildRecipientAAD(recipientPubKey);

    const { ciphertext: kemCt, sharedSecret } = await hybridEncapsulate(recipientPubKey);
    const aesCt = await aesGcmEncrypt(data, sharedSecret, nonce, aad);
    wipe(sharedSecret);

    return encodeAsymmetricPacket(kemCt, nonce, aesCt);
  }

  /**
   * Decrypt an asymmetric-sealed packet using the recipient's keypair.
   */
  async unsealWith(sealed: Uint8Array, keyPair: HybridKeyPair): Promise<Uint8Array> {
    if (sealed[1] !== MODE_ASYMMETRIC) {
      throw new Error('Packet is not in asymmetric mode — use unseal() instead');
    }
    const { kemCt, nonce, ciphertext } = decodeAsymmetricPacket(sealed);

    // Reconstruct the same AAD used during sealing
    const aad = await buildRecipientAAD(keyPair.publicKey);

    const sharedSecret = await hybridDecapsulate(kemCt, keyPair.privateKey);
    const plaintext = await aesGcmDecrypt(ciphertext, sharedSecret, nonce, aad);
    wipe(sharedSecret);

    return plaintext;
  }

  // ── Key storage helpers ───────────────────────────────────────────────────

  /**
   * Encrypt `keyPair` with `wrappingKey` and persist in IndexedDB.
   * Obtain `wrappingKey` via `getWebAuthnWrappingKey()` for hardware backing.
   */
  async storeKeyPair(keyPair: HybridKeyPair, wrappingKey: Uint8Array, id?: string): Promise<void> {
    return storeKeyPair(keyPair, wrappingKey, id);
  }

  async loadKeyPair(wrappingKey: Uint8Array, id?: string): Promise<HybridKeyPair> {
    return loadKeyPair(wrappingKey, id);
  }

  async deleteKeyPair(id?: string): Promise<void> {
    return deleteKeyPair(id);
  }

  // ── WebAuthn helpers ──────────────────────────────────────────────────────

  /** Register a platform authenticator credential. Call once per device. */
  async registerWebAuthn(userId: string): Promise<WebAuthnCredential> {
    return registerWebAuthnCredential(userId);
  }

  /**
   * Authenticate with WebAuthn and derive a session-scoped key-wrapping key.
   * The returned 32-byte key is different on every call — use it immediately
   * to wrap/unwrap and then wipe it.
   */
  async getWebAuthnWrappingKey(credentialId: Uint8Array): Promise<Uint8Array> {
    return deriveWebAuthnWrappingKey(credentialId);
  }

  // ── Utility ───────────────────────────────────────────────────────────────

  /** Create an ephemeral in-tab session key store backed by sessionStorage. */
  createSessionKeyStore(): SessionKeyStore {
    return new SessionKeyStore();
  }

  /** Overwrite a sensitive buffer with zeros. */
  wipe(...bufs: Uint8Array[]): void {
    wipe(...bufs);
  }

  /** Return `n` bytes of entropy-enhanced secure random data. */
  random(n: number): Uint8Array {
    return getSecureRandom(n);
  }
}
