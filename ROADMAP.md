# Roadmap

This document outlines the direction of paranoia.ts. It is intentionally lightweight — the project is in active use and the roadmap evolves based on real feedback.

---

## Current focus

The project just reached **v1.0.2**. The immediate priorities are:

- **Bug fixes** — address issues reported by users as the library sees broader adoption
- **Feedback integration** — incorporate suggestions from early adopters, particularly around API ergonomics and edge cases

---

## Under consideration

Nothing is committed yet. The following areas may be explored depending on community feedback:

- **ML-KEM WASM backend** — replace `@noble/post-quantum` with a WASM binary compiled from the NIST reference C implementation for constant-time lattice arithmetic
- **Streaming encryption** — a chunked seal/unseal API for large files without loading everything into memory
- **React hooks package** — official `paranoia.ts/react` sub-package with `useCrypto`, `useWebAuthn`
- **Additional KDF options** — scrypt as an alternative to Argon2id for environments where WASM is restricted
- **Formal audit** — third-party security audit of the core library

---

## How to influence the roadmap

Open an issue on [GitHub](https://github.com/mateocallec/paranoia.ts/issues) describing your use case. Feature requests backed by real-world scenarios carry the most weight.

---

*Last updated: 2026-05-10*
