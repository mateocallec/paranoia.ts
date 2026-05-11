# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active |

Only the latest release receives security patches. Users are encouraged to stay on the latest version.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Send a report to **mateo@callec.net** with:

- A description of the vulnerability and the component affected
- Steps to reproduce or a proof-of-concept (no live targets)
- Your assessment of severity and exploitability
- Your name / handle if you would like to be credited

You will receive an acknowledgement within **72 hours** and a resolution timeline within **7 days**. Critical vulnerabilities affecting key material confidentiality are treated as highest priority.

---

## Threat Model

### In scope

- Confidentiality of plaintext encrypted with `seal()` / `sealTo()`
- Integrity and authenticity of sealed packets (AES-GCM tag verification)
- Forward secrecy of individual message sessions
- Security of the hybrid KEM construction
- Correctness of the Argon2id key derivation

### Out of scope

- Side-channel attacks that require physical access to the machine
- Attacks that require the adversary to have already compromised the JavaScript runtime
- Timing attacks on JavaScript string operations (strings are immutable; master passphrases passed as strings cannot be wiped — this is a documented limitation)
- GC-retained copies of sensitive buffers before `wipe()` is called (documented limitation of managed-memory runtimes)

---

## Known Limitations

These are documented design constraints, not vulnerabilities:

1. **Master passphrase as JavaScript string** — strings are immutable in V8 and cannot be zeroed. Callers who need zeroing should pass a `Uint8Array` directly to `deriveKey()`.

2. **GC copies** — the garbage collector may copy `Uint8Array` backing stores before `wipe()` is called. `wipe()` reduces the exposure window but is not a cryptographic guarantee.

3. **ML-KEM constant-time** — `@noble/post-quantum` is pure TypeScript; the JIT compiler cannot provide constant-time guarantees for lattice arithmetic. A future WASM backend will address this.

4. **OS swap** — there is no `mlock()` equivalent in browser or Node.js environments. The OS may write memory pages containing key material to disk under memory pressure.

---

## Disclosure Policy

Once a fix is ready, the process is:

1. A patch is merged to `main` without public mention of the vulnerability
2. A new version is released
3. A security advisory is published on GitHub
4. Credit is given to the reporter (unless they request anonymity)

The minimum embargo period before public disclosure is **14 days** from the release of the fix, or earlier if the reporter agrees.
