# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-05-10

### Added

#### Core library (`paranoia.ts`)
- **Hybrid KEM** — ML-KEM-1024 (NIST FIPS 203) + P-521 ECDH combined via HKDF-SHA-384; both algorithms must be broken simultaneously to compromise any session
- **AES-256-GCM** symmetric encryption backed by SubtleCrypto (hardware-accelerated, hardware-verified authentication tag)
- **Argon2id** passphrase key derivation via WebAssembly (hash-wasm); memory-hard, configurable cost parameters embedded in every sealed packet
- **Deterministic keypair derivation** — `deriveKeyPairFromMasterPassword()` and `deriveKeyPairAndWrapKey()` for reproducible keypairs from a master passphrase + derivation nonce
- **Single-algorithm KEM variants** — `encapsulatePqc` / `decapsulatePqc` (ML-KEM-1024 only) and `encapsulateP521` / `decapsulateP521` (P-521 only) for backward-compatible deployments
- **Webcam TRNG** — `enableWebcamEntropy()` harvests pixel noise from camera frames, hashes with SHA-3-256 and mixes into the CSPRNG pool via HMAC-SHA3-256; cannot decrease entropy even if the feed is static
- **`injectEntropy()`** — environment-agnostic entropy injection for Node.js and other non-browser runtimes
- **Memory safety** — `wipe()` zeros all `Uint8Array` key material; `constantTimeEqual()` for authentication tag comparison
- **Self-describing packets** — passphrase packets embed Argon2id parameters; asymmetric packets embed KEM ciphertext and ephemeral public key; both are forward-compatible
- **IndexedDB keypair storage** — `storeKeyPair()` / `loadKeyPair()` encrypt private keys at rest with AES-256-GCM
- **WebAuthn key-wrapping** — `registerWebAuthnCredential()` / `deriveWebAuthnWrappingKey()` for hardware-backed key wrapping (signature-derived, session-unique)
- **WebAuthn PRF unlock** — `registerWebAuthnPRF()` / `getWebAuthnPRFKey()` use the PRF extension for deterministic biometric unlock; the private keypair is stored encrypted in IndexedDB and unlocked with a single touch (Touch ID, Windows Hello, FIDO2 security key)
- **SessionKeyStore** — in-memory AES-GCM wrapper for ephemeral session keys in sessionStorage
- **Web Worker bridge** — `ParanoiaWorker` offloads crypto operations to a dedicated worker to keep the main thread responsive

#### CLI (`paranoia-cli`)
- `paranoia keygen [--pqc | --trad | --both] [--webcam]` — generate and save an encrypted keypair to `keys.json`
- `paranoia entropy <bytes> [--webcam]` — generate CSPRNG bytes (optionally webcam-enhanced) as hex
- `paranoia seal <file> [-k keys.json]` — smart-mode file encryption; auto-detects hybrid / PQC-only / P-521-only from the key file
- `paranoia open <file> [-k keys.json]` — decrypt a `.para` file; prompts for master passphrase
- `.para` binary container format with JSON header (originalName, mlkemCt, p521EphPk, nonce)
- Bootstrap guard — enforces Node.js ≥ 18 and validates SubtleCrypto availability at startup
- ffmpeg-based webcam entropy for Node.js (cross-platform: Linux v4l2, macOS avfoundation, Windows dshow)

#### Security improvements
- **P-521 ECDH** migrated to SubtleCrypto `crypto.subtle.deriveBits` — constant-time guarantee from the browser vendor (BoringSSL / OpenSSL), eliminating JIT timing risk
- **HKDF-SHA-384** migrated to SubtleCrypto `crypto.subtle.deriveBits` — native, hardware-accelerated
- **P-521 key generation** migrated to SubtleCrypto `crypto.subtle.generateKey` — guaranteed valid private scalar, no rejection-sampling loop

#### PoC web application (`website/`)
- NestJS backend with Prisma ORM and PostgreSQL
- Double-authentication: site password (bcrypt, server-side) + master password (Argon2id, client-side only)
- End-to-end encrypted chat — messages sealed with hybrid KEM; sender and recipient each receive their own sealed copy of the AES session key
- HttpOnly JWT cookie authentication; automatic session restoration on page refresh
- Storage choice on first unlock: WebAuthn PRF biometrics / sessionStorage session / re-entry on each refresh
- Webcam TRNG button during registration
- Real-time message delivery via Server-Sent Events (SSE)
- Docker Compose one-command deployment

---

[1.0.0]: https://github.com/mateocallec/paranoia.ts/releases/tag/v1.0.0
