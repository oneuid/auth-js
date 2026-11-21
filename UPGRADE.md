# OneUID Auth JS SDK - Upgrade Log

> **Repository**: `oneuid/auth-js` (`@oneuid-auth-js/core` Headless TypeScript Authentication & Passkey SDK)
> **Ecosystem**: OneUID
> **Current version**: `v0.1.31` (2026-11-21)
> **Release policy**: Updated automatically via `python3 /home/s/Projects/getding.io/scripts/release.py` and verified by `gate.py` before every release push.

## Feature inventory

| Module | Surface | Core capabilities |
| :--- | :--- | :--- |
| **Passkeys & OIDC** | `src/` | Headless WebAuthn FIDO2 biometric registration & login, OIDC discovery (`issuer` / `apiURL` / `baseURL`), PKCE `S256` `startAuthorization` + `handleRedirectCallback`, JWKS signature & claims verification, concise LEXICON SDK method aliases |
| **Challenges & Sessions** | `src/` | Cross-device QR and extension challenge metadata inspection (`get`), `matchNumber` approval confirmation, terminal status handling, timeout/AbortSignal polling, active session listing (`session.list()`), session revocation (`revokeSession`/`revoke`), and fail-closed `deleteAccount`/`exportData` stubs |
| **Errors & i18n** | `src/` | Typed `AuthError` (`code`, `status`, `safeMessage`) across all SDK modules, sensitive JWT/secret redaction, and 14-locale `getAuthErrorMessage` recovery copy |
| **Button** | `src/` | Cryptographic Minimal `renderButton` widget (`dark` / `light` / `brand`) with `#2563EB` / `#FFFFFF` shield mark, 14-locale + Arabic RTL translations across `uid`/`google`/`facebook`/`apple`, 44px minimum hit targets, PKCE `S256` authorize redirect, and inline loading/error states |
| **KMS & Web3** | `src/` | Server-side AES-GCM envelope encryption (`KMSClient`) with explicit KEK/keyProvider enforcement and non-extractable Ed25519 `did:key` Web Crypto helpers (`src/web3.ts`) |
| **Adapters** | `src/` | `clientId`-namespaced storage defaulting to `MemoryStorageAdapter` with exported `LocalStorageAdapter` (XSS warning) and custom `StorageAdapter` interfaces |

## Release log

### Version 0.1.31 - 2026-11-21

- **[FIXED]** Pinned `"packageManager": "pnpm@10.26.2"` in `package.json`, added `pnpm-workspace.yaml` with `onlyBuiltDependencies: [esbuild]`, and switched `.github/workflows/ci.yml` and `.github/workflows/publish.yml` to `pnpm/action-setup@v4` (`version: 10.26.2`) with `actions/setup-node@v4` `cache: "pnpm"` to resolve `ERR_PNPM_IGNORED_BUILDS` on `esbuild` (`#13`).

### Version 0.1.30 - 2026-11-21

- **[ADDED]** Added `AuthConfig.apiURL` and defaulted `baseURL` / OIDC discovery base to `https://auth.uid.one` with issuer-aware fallback endpoints so OIDC discovery and resource API hosts stay cleanly separated (`#6`).
- **[ADDED]** Added `session.list()` / `auth.listSessions()` (`GET /v1/auth/sessions/`), `AuthCallbackState` type, `AuthError.safeMessage`, 14-locale `getAuthErrorMessage()` recovery copy, and fail-closed `deleteAccount()` / `exportData()` (`AuthError('not_implemented', ..., 501)`) stubs (`#11`).
- **[ADDED]** Added `.github/workflows/ci.yml` to run `pnpm run build`, `pnpm run lint`, and `pnpm test` on all pull requests and pushes to `main`, and added `pnpm test` to `publish.yml` (`#9`).
- **[UPDATED]** Localized `renderButton` labels for `google`, `facebook`, and `apple` across all 14 canonical locales (including Arabic `dir="rtl"`), and documented `theme: 'light' | 'dark' | 'brand'` and button options in `README.md` (`#12`).
- **[FIXED]** Converted remaining `PasskeyClient`, `DevicesClient`, and `RecoveryClient` error throws from untyped `Error` to typed, redacted `AuthError` (`#11`).
- **[FIXED]** Removed inaccurate PKCS#7, `node-forge`, `currentColor`, and trust-badge claims from `README.md` and `UPGRADE.md`, fixed `repository` to `oneuid/auth-js`, fixed vault default `'note'`, and documented the Account & Sessions settings surface (`#9`, `#11`).

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

- **[ADDED]** Cryptographic Minimal `renderButton` component with 14-locale translations, automatic RTL directionality, and OneUID Shield-Key SVG.

### Version 0.1.27 - 2026-11-08

- **[ADDED]** PKCE `S256` `authorize` options and backward-compatible concise LEXICON SDK method aliases (`2026-11-06`).
- **[UPDATED]** Upgraded embedded OneUID Shield-Key (`1`) vector mark to golden ratio (`phi = 1.618`) and enforced Sentence case across SDK prompts.
