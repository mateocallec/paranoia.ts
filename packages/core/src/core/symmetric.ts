/**
 * AES-256-GCM helpers backed by the browser's SubtleCrypto API.
 * Hardware acceleration is used automatically where available.
 *
 * The 16-byte authentication tag is appended to ciphertext by SubtleCrypto
 * on encrypt and consumed transparently on decrypt.  Decryption throws a
 * generic error on tag mismatch to avoid oracle leakage.
 */

// TypeScript 5.5+ made Uint8Array generic; SubtleCrypto needs ArrayBuffer-backed views.
const b = (u: Uint8Array): ArrayBuffer => u.buffer.slice(u.byteOffset, u.byteOffset + u.byteLength) as ArrayBuffer;

export async function aesGcmEncrypt(
  plaintext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== 32)   throw new Error('AES-256-GCM requires a 32-byte key');
  if (nonce.length !== 12) throw new Error('AES-GCM requires a 12-byte nonce');

  const cryptoKey = await crypto.subtle.importKey(
    'raw', b(key), { name: 'AES-GCM' }, false, ['encrypt'],
  );

  const params: AesGcmParams = { name: 'AES-GCM', iv: b(nonce), tagLength: 128 };
  if (aad !== undefined) params.additionalData = b(aad);

  const buf = await crypto.subtle.encrypt(params, cryptoKey, b(plaintext));
  return new Uint8Array(buf);
}

export async function aesGcmDecrypt(
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== 32)   throw new Error('AES-256-GCM requires a 32-byte key');
  if (nonce.length !== 12) throw new Error('AES-GCM requires a 12-byte nonce');

  const cryptoKey = await crypto.subtle.importKey(
    'raw', b(key), { name: 'AES-GCM' }, false, ['decrypt'],
  );

  const params: AesGcmParams = { name: 'AES-GCM', iv: b(nonce), tagLength: 128 };
  if (aad !== undefined) params.additionalData = b(aad);

  try {
    const buf = await crypto.subtle.decrypt(params, cryptoKey, b(ciphertext));
    return new Uint8Array(buf);
  } catch {
    // Deliberately vague — don't leak whether failure was tag or padding
    throw new Error('Decryption failed: ciphertext is invalid or has been tampered with');
  }
}
