# paranoia-ts

**Hybrid post-quantum end-to-end encryption for frontend applications.**

ML-KEM-1024 (NIST FIPS 203) + P-521 ECDH + AES-256-GCM + Argon2id — built for the browser and Node.js.

[![npm](https://img.shields.io/npm/v/paranoia-ts?style=flat-square&color=black)](https://www.npmjs.com/package/paranoia-ts)
[![License: MIT](https://img.shields.io/badge/license-MIT-black?style=flat-square)](https://github.com/mateocallec/paranoia.ts/blob/main/LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5+-black?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20(ML--KEM)-black?style=flat-square)](https://csrc.nist.gov/pubs/fips/203/final)

> Full documentation and source: [github.com/mateocallec/paranoia.ts](https://github.com/mateocallec/paranoia.ts)

---

## Installation

```bash
npm install paranoia-ts
```

**Requirements:** Browser with SubtleCrypto + WebAssembly, or Node.js ≥ 18.

---

## Core concept

paranoia-ts uses a **hybrid KEM construction** — both ML-KEM-1024 (post-quantum) and P-521 (classical) must be broken simultaneously to compromise any sealed message. If a mathematical flaw is discovered in either algorithm, the other one still protects your data.

---

## Usage

### Passphrase encryption

Derive an AES key from a passphrase via Argon2id, then encrypt with AES-256-GCM. The Argon2id parameters are embedded in the sealed packet so decryption is always self-contained.

```typescript
import { Paranoia } from 'paranoia-ts';

const paranoia = new Paranoia();

const sealed = await paranoia.seal(
  new TextEncoder().encode('secret message'),
  'my-strong-passphrase',
);

const plain = await paranoia.unseal(sealed, 'my-strong-passphrase');
console.log(new TextDecoder().decode(plain)); // secret message
```

### Hybrid asymmetric encryption

Encrypt to a recipient's public key. The AES session key is wrapped with ML-KEM-1024 + P-521 ECDH combined via HKDF-SHA-384.

```typescript
// Generate a hybrid keypair (ML-KEM-1024 + P-521)
const keyPair = await paranoia.generateKeyPair();

// Encrypt to recipient's public key
const sealed = await paranoia.sealTo(plaintext, keyPair.publicKey);

// Decrypt with private key
const plain = await paranoia.unsealWith(sealed, keyPair);

// Wipe private key material from memory when done
paranoia.wipe(keyPair.privateKey.mlkem, keyPair.privateKey.p521);
```

### Deterministic keypair derivation

Derive a reproducible keypair from a master password using Argon2id + HKDF. The same inputs always produce the same keypair — the private key never needs to be stored.

```typescript
import { deriveKeyPairFromMasterPassword, getSecureRandom } from 'paranoia-ts';

// derivationNonce is a per-user random value stored server-side (public, like a salt)
const nonce   = getSecureRandom(32);
const keyPair = await deriveKeyPairFromMasterPassword('master-password', 'username', nonce);
```

### WebAuthn PRF — biometric keypair unlock

Store the encrypted keypair in IndexedDB and unlock it with a single biometric touch (Touch ID, Windows Hello, YubiKey). Requires a FIDO2 authenticator that supports the PRF extension.

```typescript
import { registerWebAuthnPRF, getWebAuthnPRFKey, storeKeyPair, loadKeyPair, wipe } from 'paranoia-ts';

// Registration — once per device
const { credentialId, prfKey } = await registerWebAuthnPRF('user-id');
await storeKeyPair(keyPair, prfKey, 'my-keypair');
localStorage.setItem('cred', btoa(String.fromCharCode(...credentialId)));
wipe(prfKey);

// Unlock — one biometric touch on every page load
const credId = Uint8Array.from(atob(localStorage.getItem('cred')!), c => c.charCodeAt(0));
const prf    = await getWebAuthnPRFKey(credId);
const kp     = await loadKeyPair(prf, 'my-keypair');
wipe(prf);
```

### Webcam TRNG

Harvest pixel noise from the webcam, hash with SHA-3-256, and mix with the system CSPRNG via HMAC. Additive only — cannot reduce entropy even if the camera feed is static or dark.

```typescript
const stream = await navigator.mediaDevices.getUserMedia({ video: true });
await paranoia.enableWebcamEntropy(stream);

// All subsequent getSecureRandom() calls use the enhanced entropy pool
const sealed = await paranoia.sealTo(data, recipientPublicKey);

paranoia.disableWebcamEntropy();
stream.getTracks().forEach(t => t.stop());
```

---

## API

### Class `Paranoia`

| Method | Description |
|---|---|
| `generateKeyPair()` | Generate hybrid ML-KEM-1024 + P-521 keypair |
| `seal(data, passphrase, opts?)` | Passphrase encrypt (Argon2id + AES-256-GCM) |
| `unseal(sealed, passphrase)` | Passphrase decrypt |
| `sealTo(data, pubKey)` | Hybrid KEM encrypt to public key |
| `unsealWith(sealed, keyPair)` | Hybrid KEM decrypt |
| `enableWebcamEntropy(stream)` | Mix webcam noise into CSPRNG pool |
| `disableWebcamEntropy()` | Stop and wipe webcam pool |
| `storeKeyPair(kp, wrappingKey, id?)` | Encrypt keypair to IndexedDB |
| `loadKeyPair(wrappingKey, id?)` | Load keypair from IndexedDB |
| `wipe(...buffers)` | Zero-fill sensitive `Uint8Array` buffers |
| `random(n)` | Return `n` bytes of secure random data |

### Standalone exports

```typescript
import {
  // KEM
  hybridEncapsulate, hybridDecapsulate,
  encapsulatePqc,   decapsulatePqc,
  encapsulateP521,  decapsulateP521,
  // KDF
  deriveKey,
  deriveKeyPairFromMasterPassword,
  deriveKeyPairAndWrapKey,
  // AES
  aesGcmEncrypt, aesGcmDecrypt,
  // Entropy
  getSecureRandom, injectEntropy,
  enableWebcamEntropy, disableWebcamEntropy,
  // Memory
  wipe, constantTimeEqual,
  // WebAuthn
  registerWebAuthnPRF, getWebAuthnPRFKey,
  // Storage
  storeKeyPair, loadKeyPair, deleteKeyPair,
} from 'paranoia-ts';
```

---

## Security

- P-521 ECDH and HKDF run via `crypto.subtle` — constant-time guaranteed by the browser vendor
- AES-256-GCM authentication is hardware-accelerated via SubtleCrypto
- Argon2id parameters are authenticated as AAD — tampering is detected
- Private key material is wiped after use with `wipe()` (best-effort in JS)

See [SECURITY.md](https://github.com/mateocallec/paranoia.ts/blob/main/SECURITY.md) for the full threat model and vulnerability reporting process.

---

## License

MIT © [Matéo Florian Callec](mailto:mateo@callec.net)
