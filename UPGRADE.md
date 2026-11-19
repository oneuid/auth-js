# OneUID Auth JS SDK - Upgrade Log

> **Repository**: `uid.one/auth-js` (`@oneuid-auth-js/core` Headless TypeScript Authentication, Passkey & PKCS#7 SDK)
> **Ecosystem**: OneUID
> **Current version**: `v0.1.28` (2026-11-19)
> **Release policy**: Updated automatically via `python3 /home/s/Projects/getding.io/scripts/release.py` and verified by `gate.py` before every release push.

## Feature inventory

| Module | Surface | Core capabilities |
| :--- | :--- | :--- |
| **Passkeys** | `src/` | Headless WebAuthn FIDO2 biometric registration & login, PKCE `S256` OIDC authorization flow, concise LEXICON SDK method aliases |
| **Challenges** | `src/` | Zero-trust cross-device QR login challenge polling and direct email OTP fallback orchestration |
| **Button** | `src/` | Cryptographic Minimal `renderButton` widget with `currentColor` vector mark and built-in 14-locale + Arabic RTL layout support |
| **Signatures** | `src/` | Client-side RSA HSM keypair helpers (`node-forge`) and detached PKCS#7 document signature verification |
| **Adapters** | `src/` | Pluggable `LocalStorageAdapter`, `MemoryStorageAdapter`, and custom React Native `AsyncStorage` / Secure Enclave storage interfaces |

## Release log

### Unreleased

- **[ADDED]** `"prepublishOnly": "npm run build && npm run lint"` release safety guard in `package.json` and rebuilt fresh `51.08 KB` ESM `dist/` bundle synced across all 8 frontend repositories.

### Version 0.1.28 - 2026-11-15

- **[ADDED]** Cryptographic Minimal `renderButton` component with 14-locale translations, automatic RTL directionality, and `currentColor` OneUID Shield-Key SVG.

### Version 0.1.27 - 2026-11-08

- **[ADDED]** PKCE `S256` `authorize` options and backward-compatible concise LEXICON SDK method aliases (`2026-11-06`).
- **[UPDATED]** Upgraded embedded OneUID Shield-Key (`1`) vector mark to golden ratio (`phi = 1.618`) and enforced Sentence case across SDK prompts.
