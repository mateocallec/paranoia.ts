# Contributing to paranoia.ts

Thank you for your interest in contributing. This document explains how to get started and what to expect during the review process.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Security Issues](#security-issues)
- [Code Style](#code-style)

---

## Development Setup

**Requirements:** Node.js ≥ 18, npm ≥ 9

```bash
git clone https://github.com/mateocallec/paranoia.ts
cd paranoia.ts
npm install          # installs all workspace dependencies
npm run build        # builds packages/core then packages/cli
npm run typecheck    # type-checks all packages
```

The repository is an npm workspace with two packages:

| Package | Path | Purpose |
|---|---|---|
| `paranoia.ts` | `packages/core/` | Browser / Node.js library |
| `paranoia-cli` | `packages/cli/` | `paranoia` terminal binary |

---

## Project Structure

```
packages/
├── core/
│   ├── src/core/         Cryptographic primitives
│   ├── src/storage/      IndexedDB + WebAuthn storage
│   ├── src/workers/      Web Worker bridge
│   └── src/index.ts      Public API surface
└── cli/
    ├── src/commands/     keygen · entropy · seal · open
    └── src/lib/          keys.json · .para format · webcam
```

---

## Making Changes

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b fix/your-description
   # or
   git checkout -b feat/your-description
   ```

2. **Make your changes** and ensure the build passes:
   ```bash
   npm run build
   npm run typecheck
   ```

3. **Test manually** — there is no automated test suite yet; please describe your manual testing steps in the pull request.

4. **Commit** using conventional commit messages:
   ```
   fix: correct P-521 key derivation bit masking
   feat: add streaming encryption API
   docs: expand WebAuthn PRF example
   ```

5. **Open a pull request** against `main` with a clear description of the change and why it is needed.

---

## Pull Request Guidelines

- Keep pull requests focused — one logical change per PR
- Include a description of the problem your change solves
- For cryptographic changes, cite the relevant standard or paper
- Do not bump version numbers in a PR — releases are managed by the maintainer
- Breaking API changes require prior discussion in an issue

---

## Security Issues

**Do not open a public GitHub issue for security vulnerabilities.**

Please follow the process described in [SECURITY.md](SECURITY.md).

---

## Code Style

- TypeScript strict mode is enforced (`noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`)
- No comments that describe *what* code does — only *why* when non-obvious
- Sensitive buffers must be wiped with `wipe()` after use
- Any function that produces key material must be `async` and use SubtleCrypto where possible
- Avoid `any` casts; prefer explicit type assertions with a comment when unavoidable
