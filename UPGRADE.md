# OneUID Auth JS SDK - Upgrade Log

> **Repository**: `uid.one/auth-js` (`@oneuid-auth-js/core` Headless TypeScript Authentication, Passkey & PKCS#7 SDK)
> **Ecosystem**: OneUID
> **Current version**: `v0.1.29` (2026-11-20)
> **Release policy**: Updated automatically via `python3 /home/s/Projects/getding.io/scripts/release.py` and verified by `gate.py` before every release push.

## Feature inventory

| Module | Surface | Core capabilities |
| :--- | :--- | :--- |
| **Passkeys & OIDC** | `src/` | Headless WebAuthn FIDO2 biometric registration & login, OIDC discovery, PKCE `S256` `startAuthorization` + `handleRedirectCallback`, JWKS signature & claims verification, concise LEXICON SDK method aliases |
| **Challenges** | `src/` | Cross-device QR and extension challenge metadata inspection (`get`), `matchNumber` approval confirmation, terminal status handling, timeout/AbortSignal polling, and retry resilience |
| **Button** | `src/` | Cryptographic Minimal `renderButton` widget with `currentColor` vector mark, 14-locale + Arabic RTL layout support, 44px minimum hit targets, PKCE `S256` authorize redirect, and inline loading/error states |
| **KMS & Signatures** | `src/` | Server-side AES-GCM envelope encryption (`KMSClient`) with explicit KEK/keyProvider enforcement, non-extractable Ed25519 Web Crypto keys, and detached PKCS#7 verification helpers |
| **Adapters** | `src/` | `clientId`-namespaced storage defaulting to `MemoryStorageAdapter` with explicit `LocalStorageAdapter` XSS warnings and custom Secure Enclave interfaces |

## Release log

### Version 0.1.29 - 2026-11-20

- **[SECURITY]** Implemented OIDC discovery (`discover`), PKCE `S256` `startAuthorization` + `handleRedirectCallback` with `state` and `nonce` binding, fail-closed `loginWithCode` `code_verifier` requirement for public clients, and HTTPS/loopback validation for `baseURL` and `redirectUri`.
- **[SECURITY]** Added zero-dependency Web Crypto JWKS verification (`RS256/384/512`, `PS256/384/512`, `ES256/384/512`, `EdDSA`), explicitly rejecting `alg=none`, `HS*`, wrong `iss`/`aud`, expired `exp`, and mismatched `nonce` before persisting tokens.
- **[SECURITY]** Changed default token storage to `MemoryStorageAdapter` (keeping refresh tokens out of `localStorage`), namespaced storage keys by `clientId`, added automatic refresh on near-expired tokens in `getAccessToken()`, and updated `logout()` to revoke both `refresh_token` and `access_token`.
- **[SECURITY]** Disabled direct password grants (`loginWithPassword`) by default so 2FA cannot be bypassed, stripped `clientSecret` in browser runtimes, removed `client_secret` from `loginWithProvider`, and made `getSocialRedirectUrl` throw.
- **[SECURITY]** Removed `process.env.VAULT_MASTER_KEY` auto-loading in `OneUID`, blocked static KEK initialization of `KMSClient` in browser runtimes, enforced 1h/24h DEK cache TTL bounds, and set `extractable: false` on Ed25519 keys in `src/web3.ts`.
- **[FIXED]** Updated `renderButton` (`provider: 'uid'`) to start the OIDC PKCE `S256` authorize flow instead of navigating to `/login/` (404), enforced >=44px hit targets across all sizes, and added loading/disabled and inline retryable error states across all 14 locales.
- **[FIXED]** Hardened `SessionClient` (`get`, `approve` with `matchNumber`, `pollForApproval` with `REJECTED`/`DENIED`/`EXPIRED`/`CONSUMED`, `timeoutMs`, `AbortSignal`, and transient 5xx retries), fixed `verify2FA` token-shape persistence, ensured `register` never persists tokens, and redacted sensitive data from `AuthError` messages.
- **[ADDED]** Added Node test suite (`tests/auth-sdk.test.mjs`) and updated `README.md` with safe PKCE, 2FA, session exchange, social login, and server-only KMS guidance.

### Version 0.1.28 - 2026-11-15

- **[ADDED]** Cryptographic Minimal `renderButton` component with 14-locale translations, automatic RTL directionality, and `currentColor` OneUID Shield-Key SVG.

### Version 0.1.27 - 2026-11-08

- **[ADDED]** PKCE `S256` `authorize` options and backward-compatible concise LEXICON SDK method aliases (`2026-11-06`).
- **[UPDATED]** Upgraded embedded OneUID Shield-Key (`1`) vector mark to golden ratio (`phi = 1.618`) and enforced Sentence case across SDK prompts.
