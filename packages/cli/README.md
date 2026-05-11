# paranoia-cli

**Post-quantum hybrid encryption CLI** — seal and open files with ML-KEM-1024 + P-521 + AES-256-GCM, generate entropy, and manage keypairs from the terminal.

[![npm](https://img.shields.io/npm/v/paranoia-cli?style=flat-square&color=black)](https://www.npmjs.com/package/paranoia-cli)
[![License: MIT](https://img.shields.io/badge/license-MIT-black?style=flat-square)](https://github.com/mateocallec/paranoia.ts/blob/main/LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-%E2%89%A518-black?style=flat-square&logo=node.js)](https://nodejs.org/)

> Powered by [paranoia-ts](https://www.npmjs.com/package/paranoia-ts) · Source: [github.com/mateocallec/paranoia.ts](https://github.com/mateocallec/paranoia.ts)

---

## Installation

```bash
npm install -g paranoia-cli
```

**Requirements:** Node.js ≥ 18. ffmpeg is optional (only needed for `--webcam` entropy).

---

## Commands

### `keygen` — generate a keypair

```bash
paranoia keygen [options]
```

Derives a hybrid keypair from a master passphrase via Argon2id and saves it to `keys.json`. The private key is encrypted — the passphrase is never stored.

| Option                | Description                                                        |
| --------------------- | ------------------------------------------------------------------ |
| `--both`              | ML-KEM-1024 + P-521 hybrid (default)                               |
| `--pqc`               | ML-KEM-1024 only                                                   |
| `--trad`              | P-521 only                                                         |
| `--webcam`            | Mix webcam pixel noise into the derivation nonce (requires ffmpeg) |
| `-o, --output <path>` | Output path (default: `keys.json`)                                 |

```bash
paranoia keygen                          # hybrid, interactive passphrase prompt
paranoia keygen --pqc -o alice.json      # ML-KEM-1024 only
paranoia keygen --webcam                 # TRNG-enhanced derivation nonce
```

---

### `seal` — encrypt a file

```bash
paranoia seal <file> [options]
```

Encrypts a file to a `.para` container. The algorithm is **auto-detected** from the keys in `keys.json`:

- Both keys present → **Hybrid** (ML-KEM-1024 + P-521)
- ML-KEM key only → **PQC-only**
- P-521 key only → **Classical ECDH**

| Option                | Description                                  |
| --------------------- | -------------------------------------------- |
| `-k, --keys <path>`   | Path to keys.json (default: `keys.json`)     |
| `-o, --output <path>` | Output `.para` path (default: `<file>.para`) |

```bash
paranoia seal secret.txt
paranoia seal document.pdf -k alice.json -o document.para
```

---

### `open` — decrypt a file

```bash
paranoia open <file> [options]
```

Decrypts a `.para` file. You will be prompted for the master passphrase to unlock the private key.

| Option                | Description                                                           |
| --------------------- | --------------------------------------------------------------------- |
| `-k, --keys <path>`   | Path to keys.json (default: `keys.json`)                              |
| `-o, --output <path>` | Output file path (default: original filename from the `.para` header) |

```bash
paranoia open secret.txt.para
paranoia open document.para -k alice.json -o recovered.pdf
```

---

### `entropy` — generate random bytes

```bash
paranoia entropy <bytes> [options]
```

Outputs `<bytes>` bytes of cryptographically secure entropy as a hex string.

| Option                | Description                                                          |
| --------------------- | -------------------------------------------------------------------- |
| `--webcam`            | Mix webcam pixel noise via HMAC-SHA3-256 (additive, requires ffmpeg) |
| `-o, --output <path>` | Write to file instead of stdout                                      |

```bash
paranoia entropy 32                      # 32 bytes → hex on stdout
paranoia entropy 64 --webcam             # webcam TRNG mixed in
paranoia entropy 32 -o seed.hex          # write to file
```

---

## The `.para` file format

Sealed files use a binary container with a self-describing JSON header:

```
[4B magic "PARA"][1B version][1B mode][4B header length]
[JSON header: originalName, mlkemCt?, p521EphPk?, nonce]
[AES-256-GCM ciphertext + 16-byte auth tag]
```

Mode values: `0x01` = PQC-only, `0x02` = P-521-only, `0x03` = Hybrid.

---

## The `keys.json` format

```json
{
  "version": 1,
  "algorithm": "hybrid-mlkem1024-p521",
  "created": "2026-05-11T...",
  "derivationNonce": "<base64>",
  "public": {
    "mlkem": "<base64 — 1568 bytes>",
    "p521": "<base64 — 67 bytes>"
  },
  "private": {
    "algorithm": "argon2id-aes256gcm",
    "argon2": { "iterations": 5, "memoryKiB": 524288, "parallelism": 4 },
    "nonce": "<base64>",
    "ciphertext": "<base64>"
  }
}
```

The private key material is AES-256-GCM encrypted with a key derived from the master passphrase via Argon2id. The plaintext private key is never written to disk.

---

## Webcam entropy (Linux / macOS / Windows)

When `--webcam` is passed, the CLI captures 8 frames from the default camera via ffmpeg, hashes the pixel data with SHA-3-256, and mixes the result into the system CSPRNG via HMAC-SHA3-256. The output entropy can only be _stronger_ than the base CSPRNG — webcam data cannot reduce it.

---

## License

MIT © [Matéo Florian Callec](mailto:mateo@callec.net)
