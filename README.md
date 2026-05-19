<div align="center">
  <img src="documentation/logo.png" alt="paranoia.ts logo" width="180" />
  <h1>Paranoia.ts</h1>
  <p><strong>Hybrid post-quantum end-to-end encryption for frontend applications.</strong></p>

  [![npm](https://img.shields.io/npm/v/paranoia-ts?style=flat-square&color=black)](https://www.npmjs.com/package/paranoia-ts)
  [![License: MIT](https://img.shields.io/badge/license-MIT-black?style=flat-square)](LICENSE)
  [![TypeScript](https://img.shields.io/badge/TypeScript-5.5+-black?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
  [![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A518-black?style=flat-square&logo=node.js)](https://nodejs.org/)
  [![FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20(ML--KEM)-black?style=flat-square)](https://csrc.nist.gov/pubs/fips/203/final)
  [![WebAuthn PRF](https://img.shields.io/badge/WebAuthn-PRF%20Extension-black?style=flat-square)](https://www.w3.org/TR/webauthn-3/)
  [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-black?style=flat-square)](CONTRIBUTING.md)
</div>

---

**Paranoia.ts** is a TypeScript-first cryptography library that combines classical and post-quantum algorithms in a hybrid construction, ensuring your data remains protected even against quantum computers — while staying compatible with every modern JavaScript runtime.

> **"If one algorithm is broken, the other still holds."**

---

## Reference implementation

A full end-to-end encrypted messaging application built with Paranoia.ts is available as a reference implementation:

**[paranoia-messaging](https://github.com/mateocallec/paranoia-messaging)** — E2EE chat app (NestJS · React · Docker) demonstrating hybrid PQC encryption, WebAuthn PRF biometric unlock, and double-authentication.

---

## Table of Contents

- [Why Paranoia.ts?](#why-paranoia-ts)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Reference](#api-reference)
- [CLI](#cli)
- [Security Model](#security-model)
- [Known Limitations](#known-limitations)
- [Browser & Runtime Support](#browser--runtime-support)
- [Contributing](#contributing)
- [License](#license)

---

## Why paranoia.ts?

Most cryptography libraries make you choose between classical security and post-quantum security. Paranoia.ts does both — simultaneously.

| Threat | Classical only | PQC only | **Paranoia.ts** |
|---|---|---|---|
| Classical adversary | ✅ | ⚠️ (unproven) | ✅ |
| Quantum adversary | ❌ | ✅ | ✅ |
| Mathematical flaw in ML-KEM | ❌ | ❌ | ✅ (P-521 still holds) |
| Mathematical flaw in P-521 | ✅ | ❌ | ✅ (ML-KEM still holds) |

---

## Features

- 🔐 **Hybrid KEM** — ML-KEM-1024 (NIST FIPS 203) + P-521 ECDH, combined via HKDF-SHA-384
- 🔒 **AES-256-GCM** symmetric encryption via SubtleCrypto (hardware-accelerated)
- 🧂 **Argon2id** key derivation via WebAssembly (memory-hard, brute-force resistant)
- 📷 **Webcam TRNG** — harvest pixel noise, hash with SHA-3-256, mix with CSPRNG via HMAC
- 🔑 **WebAuthn PRF** — biometric/security-key unlock for stored keypairs (no master password re-entry)
- 🧹 **Memory wiping** — `wipe()` zeros sensitive buffers immediately after use
- ⏱️ **Constant-time operations** — P-521 ECDH and HKDF via SubtleCrypto (vendor-guaranteed)
- 🌐 **Vanilla-first** — Promise-based API, works in any JS environment
- 🛠️ **CLI** — `paranoia keygen`, `seal`, `open`, `entropy` commands

---

## Architecture

```
paranoia.ts/
├── packages/
│   ├── core/               ← Library (ESM + UMD)
│   │   └── src/
│   │       ├── core/
│   │       │   ├── entropy.ts      CSPRNG + webcam TRNG pool
│   │       │   ├── kem.ts          Hybrid KEM (ML-KEM-1024 + P-521)
│   │       │   ├── kdf.ts          Argon2id key derivation
│   │       │   ├── symmetric.ts    AES-256-GCM
│   │       │   ├── derive.ts       Deterministic keypair from password
│   │       │   └── memory.ts       wipe(), constant-time compare
│   │       ├── storage/
│   │       │   ├── indexeddb.ts    Encrypted keypair storage
│   │       │   └── webauthn.ts     WebAuthn PRF unlock
│   │       └── workers/
│   │           └── crypto.worker   Web Worker bridge
│   └── cli/                ← CLI binary (Node.js CJS)
│       └── src/
│           ├── commands/   keygen · entropy · seal · open
│           └── lib/        keys.json · .para format · webcam (ffmpeg)
```

### Packet wire format (`.seal()` / `.sealTo()`)

```
Passphrase mode:
  [1B version][1B mode=0x01][32B argon2_salt][3B iterations]
  [4B memory_kib][1B parallelism][12B nonce][n+16B ciphertext+tag]

Asymmetric mode:
  [1B version][1B mode=0x02][1568B ml-kem-1024_ct]
  [67B p521_ephemeral_pk][12B nonce][n+16B ciphertext+tag]
```

---

## Installation

```bash
npm install paranoia-ts
```

**Requirements:** Browser with SubtleCrypto + WebAssembly, or Node.js ≥ 18.

---

## Quick Start

### Passphrase encryption (symmetric)

```typescript
import { Paranoia } from 'paranoia-ts';

const paranoia = new Paranoia();

// Encrypt
const sealed = await paranoia.seal(
  new TextEncoder().encode('top secret'),
  'correct-horse-battery-staple',
);

// Decrypt
const plain = await paranoia.unseal(sealed, 'correct-horse-battery-staple');
console.log(new TextDecoder().decode(plain)); // top secret
```

### Hybrid asymmetric encryption (post-quantum)

```typescript
// Generate a hybrid ML-KEM-1024 + P-521 keypair
const keyPair = await paranoia.generateKeyPair();

// Encrypt to recipient's public key
const sealed = await paranoia.sealTo(data, keyPair.publicKey);

// Decrypt with private key
const plain = await paranoia.unsealWith(sealed, keyPair);

// Always wipe private key material after use
paranoia.wipe(keyPair.privateKey.mlkem, keyPair.privateKey.p521);
```

### Webcam TRNG entropy

```typescript
const stream = await navigator.mediaDevices.getUserMedia({ video: true });

// Mix webcam pixel noise into every getSecureRandom() call
await paranoia.enableWebcamEntropy(stream);

// All subsequent crypto operations use the enhanced entropy
const sealed = await paranoia.sealTo(data, recipientPublicKey);

paranoia.disableWebcamEntropy();
stream.getTracks().forEach(t => t.stop());
```

### WebAuthn PRF — biometric keypair unlock

```typescript
import { registerWebAuthnPRF, getWebAuthnPRFKey, storeKeyPair, loadKeyPair, wipe } from 'paranoia-ts';

// Registration (once per device)
const { credentialId, prfKey } = await registerWebAuthnPRF();
await storeKeyPair(keyPair, prfKey, 'my-key');
localStorage.setItem('prf-cred', btoa(String.fromCharCode(...credentialId)));
wipe(prfKey);

// Unlock on every page load — one biometric touch
const credId = Uint8Array.from(atob(localStorage.getItem('prf-cred')!), c => c.charCodeAt(0));
const prf    = await getWebAuthnPRFKey(credId);
const kp     = await loadKeyPair(prf, 'my-key');
wipe(prf);
```

---

## API Reference

### `new Paranoia()`

Main facade. All methods are async.

| Method | Description |
|---|---|
| `generateKeyPair()` | Generate a hybrid ML-KEM-1024 + P-521 keypair |
| `seal(data, passphrase, options?)` | Encrypt with Argon2id + AES-256-GCM |
| `unseal(sealed, passphrase)` | Decrypt a passphrase-sealed packet |
| `sealTo(data, pubKey)` | Hybrid KEM encrypt to a public key |
| `unsealWith(sealed, keyPair)` | Hybrid KEM decrypt |
| `enableWebcamEntropy(stream)` | Mix webcam noise into CSPRNG |
| `disableWebcamEntropy()` | Stop and wipe the webcam entropy pool |
| `storeKeyPair(kp, wrappingKey, id?)` | Encrypt and persist to IndexedDB |
| `loadKeyPair(wrappingKey, id?)` | Load and decrypt from IndexedDB |
| `wipe(...buffers)` | Zero-fill sensitive Uint8Arrays |
| `random(n)` | Return n bytes of secure entropy |

### Low-level primitives

All primitives are individually exported for advanced use:

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
  // Symmetric
  aesGcmEncrypt, aesGcmDecrypt,
  // Entropy
  getSecureRandom, injectEntropy,
  enableWebcamEntropy, disableWebcamEntropy,
  // Memory
  wipe, constantTimeEqual, concat,
  // Storage
  storeKeyPair, loadKeyPair, deleteKeyPair,
  // WebAuthn
  registerWebAuthnPRF, getWebAuthnPRFKey,
} from 'paranoia-ts';
```

---

## CLI

The `paranoia` CLI is bundled at `packages/cli/`. Install globally:

```bash
cd packages/core && npm link
```

### Commands

```bash
# Generate a hybrid keypair (prompted for master passphrase)
paranoia keygen                         # ML-KEM-1024 + P-521 (default)
paranoia keygen --pqc                   # ML-KEM-1024 only
paranoia keygen --trad                  # P-521 only
paranoia keygen --webcam -o alice.json  # TRNG-enhanced nonce

# Entropy generation
paranoia entropy 32                     # 32 bytes → hex stdout
paranoia entropy 64 --webcam            # Mix webcam pixel noise

# File encryption (.para format)
paranoia seal secret.txt -k keys.json
paranoia open secret.txt.para -k keys.json
```

### `.para` file format

```
[4B magic "PARA"][1B version][1B mode]
[4B header length][JSON header: originalName, mlkemCt?, p521EphPk?, nonce]
[AES-256-GCM ciphertext + 16B auth tag]
```

---

## Security Model

### What Paranoia.ts guarantees

- **Hybrid security** — requires simultaneous breaks of both ML-KEM-1024 (lattice) and P-521 (elliptic curve) to recover any plaintext
- **Constant-time P-521 ECDH** — SubtleCrypto `deriveBits` (vendor-guaranteed, BoringSSL/OpenSSL)
- **Constant-time HKDF-SHA-384** — SubtleCrypto `deriveBits`
- **Memory reduction** — `wipe()` zeros all `Uint8Array` key material immediately after use
- **No plaintext persistence** — private keys never written to localStorage or cookies; only encrypted blobs in IndexedDB

### Known limitations

JavaScript's garbage collector may copy buffers before `wipe()` is called. The wipe reduces the exposure window but **cannot guarantee** that no copy remains in the JS heap. For critical deployments where hard memory guarantees are required, the ML-KEM and P-521 operations should be moved to a WASM module with direct memory control.

**Strings cannot be wiped.** If the master passphrase is passed as a JavaScript `string`, it lives in the V8 heap until GC. Callers who need zeroing should pass a `Uint8Array` directly to the `deriveKey` primitive.

See [SECURITY.md](SECURITY.md) for the full threat model and vulnerability reporting process.

---

## Browser & Runtime Support

| Environment | Support |
|---|---|
| Chrome / Edge 116+ | ✅ Full (WebAuthn PRF, SubtleCrypto, WASM) |
| Firefox 122+ | ✅ Full |
| Safari 18+ | ✅ Full |
| Node.js ≥ 18 | ✅ Full (CLI + library) |
| Older browsers | ⚠️ Passphrase mode only (no WebAuthn PRF) |

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

```bash
git clone https://github.com/mateocallec/paranoia.ts
cd paranoia.ts
npm install
npm run build
```

---

## License

MIT © [Matéo Florian Callec](mailto:mateo@callec.net)

See [LICENSE](LICENSE) for the full text.
