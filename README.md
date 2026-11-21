# @oneuid-auth-js/core

[![npm version](https://img.shields.io/npm/v/@oneuid-auth-js/core.svg?style=flat-square)](https://www.npmjs.com/package/@oneuid-auth-js/core)
[![TypeScript](https://img.shields.io/badge/%3C%2F%3E-TypeScript-blue.svg?style=flat-square)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**@oneuid-auth-js/core** is the official authentication SDK for the **OneUID** Sovereign Identity Ecosystem.

Designed for maximum flexibility across web (React, Vue, Next.js) and mobile (React Native, Expo), the SDK provides a headless client with pluggable storage adapters and an optional localized `renderButton` widget.

## Features

- **Headless core with optional widget:** Bring your own UI, or drop in `auth.renderButton(...)` for an accessible `>= 44px` sign-in button in 14 locales (with Arabic RTL).
- **OIDC Authorization Code + PKCE (`S256`):** `startAuthorization()` and `handleRedirectCallback()` with random `state`, `nonce`, and Web Crypto JWKS verification.
- **Passkey (FIDO2) first:** Passwordless biometric authentication via `@simplewebauthn/browser`.
- **Cross-device auth (QR / extension):** Zero-trust QR challenges with `matchNumber` inspection and bounded polling.
- **Sovereign device & Web3 primitives:** Register device public keys (`auth.devices`), manage encrypted vault records, and sign Ed25519 `did:key` Verifiable Credentials (`src/web3.ts`).
- **Pluggable storage adapters:** Exports `MemoryStorageAdapter` (default, keeps refresh tokens out of `localStorage`) and `LocalStorageAdapter`, plus a `StorageAdapter` interface for `expo-secure-store`.
- **Ecosystem session exchange:** Verify OneUID JWTs locally against JWKS on your backend to issue `httpOnly` app sessions.

## Decentralized availability

Unlike providers that require a live introspection call on every request, OneUID uses asymmetric JWTs verifiable against the issuer's public JWKS:

1. **Signed assertion:** OneUID signs the `id_token` / `access_token` with its rotating asymmetric key pair.
2. **Local verification:** Your backend verifies the signature and claims (`iss`, `aud`, `exp`, `nonce`) against the JWKS endpoint.
3. **Autonomous sessions:** Once verified and exchanged for your app's `httpOnly` session cookie, active sessions continue working even if the identity server is temporarily unreachable.

## Installation

```bash
npm install @oneuid-auth-js/core
# or
yarn add @oneuid-auth-js/core
# or
pnpm add @oneuid-auth-js/core
```

## Quick start

### 1. Initialization

Create a singleton `OneUID` client. `baseURL` defaults to the canonical OIDC issuer `https://auth.uid.one`, and storage defaults to `MemoryStorageAdapter` so refresh tokens are never persisted to `localStorage`.

```typescript
import { OneUID } from '@oneuid-auth-js/core';

export const auth = new OneUID({
  baseURL: 'https://auth.uid.one',
  clientId: 'your-client-id-here',
});
```

#### Issuer vs. resource API host

- **`https://auth.uid.one`** is the canonical OIDC issuer (`/.well-known/openid-configuration`, `/oauth/authorize`, `/oauth/token`, `/oauth/certs`, `/oauth/revoke`).
- **`https://api.uid.one`** serves `/v1/*` resource endpoints and also publishes OIDC discovery pointing back to `https://auth.uid.one`.
- If you separate hosts explicitly, pass `{ issuer: 'https://auth.uid.one', apiURL: 'https://api.uid.one', clientId: '...' }`. Otherwise, `discover()` resolves OIDC endpoints from `/.well-known/openid-configuration` automatically.
- **URL security:** `baseURL`, `apiURL`, `issuer`, `jwksUri`, and `redirectUri` require `https://` (`http://localhost` and `http://127.0.0.1` are permitted for local development only — never deploy plain `http://` in production). Never configure `clientSecret` in browser bundles; any `clientSecret` supplied in a browser runtime is ignored.

### 1.1 Pre-styled sign-in button (`renderButton`)

The SDK provides an optional DOM widget that renders a responsive sign-in button (`>= 44x44px` hit target, loading/disabled lock, inline retryable error feedback, and 14-locale translations including Arabic `dir="rtl"` for `uid`, `google`, `facebook`, and `apple`).

**HTML container:**
```html
<div id="uid-login-container"></div>
```

**SDK initialization:**
```typescript
// Starts an OIDC Authorization Code + PKCE (S256) flow with random state and nonce
auth.renderButton('uid-login-container', {
  provider: 'uid',
  redirectUri: 'https://trip.express/auth/callback',
  theme: 'brand',
  size: 'medium',
});
```

#### Button options

| Option | Type | Default | Notes |
|---|---|---|---|
| `provider` | `'uid' \| 'google' \| 'facebook' \| 'apple'` | `'uid'` | All 4 providers are localized across 14 canonical locales. |
| `redirectUri` | `string` | Required | HTTPS callback URL (`http://localhost` allowed in dev). |
| `theme` | `'light' \| 'dark' \| 'brand'` | `'dark'` | `'light'` (white), `'dark'` (`#0B1220`), `'brand'` (OneUID `#2563EB` surface with white shield mark). |
| `size` | `'small' \| 'medium' \| 'large'` | `'medium'` | All sizes enforce at least `44px` height for touch accessibility. |
| `locale` | `string` | Auto-detected | Overrides `document.documentElement.lang` / `navigator.language`; `'ar'` sets `dir="rtl"`. |
| `label` | `string` | Localized default | Optional custom label override. |
| `scope` | `string` | `'openid profile email'` | OIDC scopes requested during `startAuthorization`. |
| `onProviderClick` | `(provider: string) => void \| Promise<void>` | `undefined` | Required handler when `provider` is `'google'`, `'facebook'`, or `'apple'`. |

### 1.2 OIDC Authorization Code + PKCE flow and callback state

Use `startAuthorization()` and `handleRedirectCallback()` as the primary web login flow, with typed `AuthCallbackState` and `AuthError` recovery:

```typescript
import { AuthCallbackState, AuthError, getAuthErrorMessage } from '@oneuid-auth-js/core';

// 1. Start authorization (generates S256 code_challenge, state, and nonce)
async function beginSignIn() {
  const { url } = await auth.startAuthorization('https://app.example.com/auth/callback');
  window.location.href = url;
}

// 2. On /auth/callback, render a "Completing sign-in..." state while exchanging the code
async function completeSignIn(locale?: string): Promise<AuthCallbackState> {
  try {
    const tokens = await auth.handleRedirectCallback();
    return { status: 'authenticated', tokens };
  } catch (err) {
    if (err instanceof AuthError) {
      const ui = getAuthErrorMessage(err.code, locale);
      return {
        status: 'error',
        code: err.code,
        message: ui.message,
        retryable: ui.action === 'retry' || ui.action === 'reauth',
      };
    }
    return {
      status: 'error',
      code: 'unavailable',
      message: getAuthErrorMessage('unavailable', locale).message,
      retryable: true,
    };
  }
}
```

### 2. Passwordless authentication (Passkey)

OneUID defaults to passwordless FIDO2 biometrics:

```typescript
import { AuthError } from '@oneuid-auth-js/core';

try {
  await auth.passkey.login();
} catch (error) {
  if (error instanceof AuthError) {
    console.error('Passkey sign-in failed:', error.code, error.safeMessage);
  }
}
```

### 3. Application integration (Session Exchange Pattern)

Keep refresh tokens out of `localStorage` and exchange only the verified `id_token` (or `access_token`) with your backend to mint an `httpOnly` session cookie. Never log raw tokens.

**Frontend (Client Component):**
```typescript
const session = await auth.passkey.login();
const assertionToken = session.id_token || session.access_token;

await fetch('/api/auth/session', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token: assertionToken }),
});
```

**Backend (Next.js Server Action / API Route):**
```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';

export async function verifyUidSession(token: string) {
  try {
    const issuer = process.env.UID_ONE_ISSUER_URL || 'https://auth.uid.one';
    const JWKS = createRemoteJWKSet(new URL(`${issuer}/oauth/certs`));

    const { payload } = await jwtVerify(token, JWKS, {
      issuer,
      audience: process.env.UID_ONE_CLIENT_ID,
      algorithms: ['RS256'],
    });

    const localUser = await syncShadowProfileWithDatabase(payload.sub, payload.email);
    await createLocalHttpOnlySession(localUser);

    return { success: true };
  } catch {
    return { success: false };
  }
}
```

### 3.1 Native social authentication (Authorization Code + PKCE)

Social login must use the provider's **Authorization Code + PKCE (`S256`)** flow with random `state` and `nonce`. Never use `response_type=token` (implicit flow) or pass a `clientSecret` from browser code.

```typescript
import { generateCodeVerifier, deriveCodeChallengeS256, generateRandomToken } from '@oneuid-auth-js/core';

const startGoogleAuth = async () => {
  const redirectUri = `${window.location.origin}/auth/callback`;
  const verifier = generateCodeVerifier();
  const challenge = await deriveCodeChallengeS256(verifier);
  const state = generateRandomToken(32);
  const nonce = generateRandomToken(32);

  sessionStorage.setItem('oauth_tx', JSON.stringify({ provider: 'google', verifier, state, nonce }));

  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', 'YOUR_GOOGLE_CLIENT_ID');
  url.searchParams.set('redirect_uri', redirectUri);
  url.searchParams.set('scope', 'openid email profile');
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);

  window.location.href = url.toString();
};
```

On the callback route, verify `state` and exchange the code via `auth.loginWithProvider`:

```typescript
const params = new URLSearchParams(window.location.search);
const code = params.get('code');
const returnedState = params.get('state');
const stored = JSON.parse(sessionStorage.getItem('oauth_tx') || 'null');
sessionStorage.removeItem('oauth_tx');

if (code && stored && returnedState === stored.state) {
  await auth.loginWithProvider(stored.provider, code, {
    nonce: stored.nonce,
    codeVerifier: stored.verifier,
    redirectUri: `${window.location.origin}/auth/callback`,
  });
}
```

### 4. Password login fallback (Two-step with 2FA)

Prefer `auth.startAuthorization()` (PKCE) or passkeys for user login. Direct password grants (`loginWithPassword`) are deprecated and disabled by default because they bypass 2FA. When a password fallback is required, use `verifyPassword` + `verify2FA`:

```typescript
const step1 = await auth.verifyPassword('user@example.com', passwordInput);

if (step1.status === 'PENDING_2FA' && step1.session_token) {
  await auth.verify2FA({
    session_token: step1.session_token,
    method: 'totp',
    code: totpCodeInput,
  });
} else if (step1.status === 'SETUP_REQUIRED') {
  // Prompt the user to enroll 2FA using step1.setup_token before completing sign-in
}
```

### 4.1 Account discovery & registration notes

- `auth.identify(email)` queries `/v1/auth/identify/` and can reveal whether an account exists and which authentication factors are enabled. Enforce strict rate limiting on login forms and never treat `session_token` from `identify()` as a session credential.
- `auth.register(email, password)` creates an unverified account (`{ verification_required: true }`) and never persists session tokens. Complete email or passcode verification (`auth.verifyPasscode`) before signing in.

### 4.2 Cross-device auth (QR / extension challenges)

`session_id` is a bearer secret — never place it in predictable URLs without origin binding. Approvers must inspect challenge metadata via `auth.session.get(sessionId)` and confirm the displayed `matchNumber` before calling `approve()`:

```typescript
// Requestor (web)
const challenge = await auth.session.create('QR', 'app.example.com');
const ac = new AbortController();
await auth.session.pollForApproval(challenge.session_id, {
  intervalMs: 2000,
  timeoutMs: 120_000,
  signal: ac.signal,
});

// Approver (authenticated mobile device)
const details = await auth.session.get(challenge.session_id);
await auth.session.approve(details.session_id, { matchNumber: userConfirmedCode });
```

## Account and sessions (Settings surface)

Host applications should expose an account-security settings screen backed by these SDK methods:

| Settings action | SDK method | Status |
|---|---|---|
| Load signed-in user profile | `await auth.getProfile()` | Live (`GET /v1/auth/me/`) |
| List active sessions | `await auth.listSessions()` (or `auth.session.list()`) | Live (`GET /v1/auth/sessions/`) |
| Revoke a single session | `await auth.session.revokeSession(sessionId)` | Live (`DELETE /v1/auth/sessions/<id>/`) |
| Sign out everywhere (OIDC back-channel) | `await auth.revoke({ includeCurrent: true })` | Live (`POST /v1/auth/revoke/`) |
| Sign out current device | `await auth.logout()` | Live (`POST /oauth/revoke` + local clear) |
| Export personal data | `await auth.exportData()` | **API not available yet** — throws `AuthError('not_implemented', ..., 501)`; tracked in [oneuid/api.uid.one#9](https://github.com/oneuid/api.uid.one/issues/9) |
| Delete account | `await auth.deleteAccount()` | **API not available yet** — throws `AuthError('not_implemented', ..., 501)`; tracked in [oneuid/api.uid.one#9](https://github.com/oneuid/api.uid.one/issues/9) |

```typescript
import { AuthError } from '@oneuid-auth-js/core';

// 1. Load profile and active sessions for settings UI
const [profile, sessions] = await Promise.all([
  auth.getProfile(),
  auth.listSessions(),
]);

// 2. Revoke a specific device session
await auth.session.revokeSession(sessions[0].id);

// 3. Sign out current session (revokes refresh + access tokens)
await auth.logout();

// 4. Delete account (handle not_implemented cleanly until backend API ships)
try {
  await auth.deleteAccount();
} catch (err) {
  if (err instanceof AuthError && err.code === 'not_implemented') {
    // Show "Account deletion is not available yet" or link to support
  }
}
```

## Storage adapters (Web, React Native & Expo)

The package exports `MemoryStorageAdapter` (default) and `LocalStorageAdapter`. On web, keep tokens in `MemoryStorageAdapter` paired with an `httpOnly` backend session. On React Native or Expo, pass a `SecureStore` adapter via `config.storage` (or as the second constructor argument, which takes precedence if both are passed):

```typescript
import { OneUID, StorageAdapter } from '@oneuid-auth-js/core';
import * as SecureStore from 'expo-secure-store';

class SecureEnclaveStorage implements StorageAdapter {
  async getItem(key: string): Promise<string | null> {
    return await SecureStore.getItemAsync(key);
  }
  async setItem(key: string, value: string): Promise<void> {
    await SecureStore.setItemAsync(key, value);
  }
  async removeItem(key: string): Promise<void> {
    await SecureStore.deleteItemAsync(key);
  }
}

const auth = new OneUID({
  baseURL: 'https://auth.uid.one',
  clientId: 'your-client-id',
  storage: new SecureEnclaveStorage(),
});
```

### 5. Sovereign device registration

Register a device's public key with OneUID using your platform's hardware-backed keystore or Web Crypto API:

```typescript
import { auth } from './auth';

// Generate a non-extractable ECDSA P-256 key pair with Web Crypto and export SPKI PEM
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  false,
  ['sign', 'verify']
);
const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
const b64 = btoa(String.fromCharCode(...spki));
const publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${b64.match(/.{1,64}/g)?.join('\n')}\n-----END PUBLIC KEY-----`;

await auth.devices.register({
  deviceId: 'unique-device-uuid',
  deviceName: 'Primary browser key',
  publicKey: publicKeyPem,
});
```

Verify a new device using an already verified device's private key signature:

```typescript
await auth.devices.verify({
  targetDeviceId: 'target-device-uuid',
  verifyingDeviceId: 'trusted-device-uuid',
  signature: 'BASE64_CRYPTOGRAPHIC_SIGNATURE',
});
```

### 6. Vault & sovereign encryption

#### Retrieve recipient's active device public key
```typescript
const recipientPubKeyInfo = await auth.getUserPublicKey('recipient@trip.express');
```

#### Save a record to the user's vault
```typescript
const record = await auth.addVaultRecord(
  'My Secure Ticket',
  'ENCRYPTED_PAYLOAD_HERE',
  'TICKET',              // See supported types below
  null,                  // sessionKey (optional)
  'COMPLETED',           // syncStatus (optional)
  'trip_express_core',   // issuer (optional, OIDC client ID or domain)
  'SIGNATURE_PROOF_PEM'  // signature (optional, cryptographic signature)
);
```

Supported record types (`type` parameter):

| Value | Description |
|---|---|
| `'note'` | Secure notes or generic text (default) |
| `'TICKET'` | Travel tickets, bookings, or vouchers |
| `'CARD'` | Payment card details |
| `'WALLET'` | Cryptographic wallet credentials or keys |
| `'PASSKEY'` | Backup passkey credentials |
| `'PASSWORD'` | Legacy credentials |
| `'API_KEY'` | Access tokens or API keys |
| `'SIGNATURE'` | Document signature verifications |
| `'DOCUMENT'` | Document metadata or encrypted PDFs |
| `'OTHER'` | Generic encrypted data fallback |

#### Transfer ownership of a vault record
```typescript
await auth.transferVaultRecord(
  'record-id-uuid',
  'recipient@trip.express',
  'NEW_ENCRYPTED_PAYLOAD',
  'WRAPPED_SESSION_KEY_FOR_RECIPIENT'
);
```

#### Manage device-bound Master Vault Keys (MVK)
```typescript
await auth.registerDeviceVaultKey('unique-device-id', 'WRAPPED_MVK_PEM');
const keys = await auth.getDeviceVaultKeys();
```

## KMS & envelope encryption (Server-side)

For server-side applications requiring envelope encryption, `KMSClient` uses Web Crypto (`AES-GCM`) with an explicit KEK (`initKMS({ kekB64 })`). `OneUID` never auto-loads `VAULT_MASTER_KEY` from `process.env`, and `initKMS` refuses static KEKs in browser runtimes (browser callers must provide an explicit non-env `keyProvider`).

```typescript
import { OneUID } from '@oneuid-auth-js/core';

// Server-side only (never pass kekB64 or clientSecret to browser code)
const auth = new OneUID({
  baseURL: 'https://auth.uid.one',
  apiURL: 'https://api.uid.one',
  clientId: 'your-server-client-id',
});

const kms = auth.initKMS({
  kekB64: process.env.VAULT_MASTER_KEY,
  keyringStorage: {
    async getItem(key) {
      const record = await db.cipher.findUnique({ where: { versionKey: key } });
      return record?.keyMaterial || null;
    },
    async setItem(key, wrappedDek) {
      const version = parseInt(key.replace('cipher_version_', ''), 10);
      await db.cipher.upsert({
        where: { version },
        update: { keyMaterial: wrappedDek },
        create: { version, keyMaterial: wrappedDek },
      });
    },
  },
});

const { ciphertext, version } = await kms.encrypt('Sensitive payload');
const plaintext = await kms.decrypt(ciphertext, version);
```

### Key cache TTL & offline behavior

- **Active cache (1 hour):** Unwrapped DEKs are cached in memory for up to `3600` seconds for both `encrypt()` and `decrypt()`.
- **Read-only fallback (24 hours):** If the remote KMS is unreachable during `decrypt(ciphertext, version)`, cached or `keyringStorage` DEKs remain usable for up to `86400` seconds (24 hours). Keys older than 24 hours are evicted.
- **Fail-closed writes:** If the remote KMS is unreachable during `encrypt()`, `KMSClient` throws `AuthError('kms_unreachable')` instead of writing with an unverified active cipher version.

## Production web server tuning (Nginx / Apache)

When using the **Session Exchange Pattern**, backend session cookies storing JWTs can exceed 4KB or 8KB. Increase reverse-proxy header buffer limits to prevent `502 Bad Gateway` errors:

### Nginx
```nginx
location / {
    proxy_pass http://localhost:3000;
    proxy_buffer_size   128k;
    proxy_buffers       4 256k;
    proxy_busy_buffers_size 256k;
}
```

### Apache (`mod_proxy`)
```apache
<VirtualHost *:443>
    ProxyIOBufferSize 65536
</VirtualHost>
```

## Browser extension compatibility

When instantiated in a browser environment, `OneUID` injects `<meta name="uid-passkey-native" content="true">` into `<head>` so the OneUID Browser Extension disables duplicate WebAuthn prompts on native-integrated apps. For SSR (e.g., Next.js `layout.tsx`), include it in `<head>`:

```html
<head>
  <meta name="uid-passkey-native" content="true" />
</head>
```

## Security notes

- All authentication errors thrown by the SDK use `AuthError` (`code`, `status`, `safeMessage`) with JWTs and credential fields redacted before formatting `Error.message`.
- Self-service account deletion and data export endpoints are tracked in [oneuid/api.uid.one#9](https://github.com/oneuid/api.uid.one/issues/9); `auth.deleteAccount()` and `auth.exportData()` fail closed with `AuthError('not_implemented', ..., 501)` until the server routes ship.

## License

MIT © UID.ONE Ecosystem
