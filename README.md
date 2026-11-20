# @oneuid-auth-js/core

[![npm version](https://img.shields.io/npm/v/@oneuid-auth-js/core.svg?style=flat-square)](https://www.npmjs.com/package/@oneuid-auth-js/core)
[![TypeScript](https://img.shields.io/badge/%3C%2F%3E-TypeScript-blue.svg?style=flat-square)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**@oneuid-auth-js/core** is the official headless authentication SDK for the **UID.ONE** Sovereign Identity Ecosystem.

Designed for maximum flexibility, this SDK provides a headless authentication client that works seamlessly across modern web applications (React, Vue, Next.js) and mobile frameworks (React Native, Expo) by relying on a pluggable storage architecture.

## ✨ Features

- **Headless Architecture:** No forced UI components. Bring your own design system.
- **Passkey (FIDO2) First:** Full support for passwordless authentication via biometric passkeys.
- **Cross-Device Auth (QR):** Seamlessly authenticate across devices using Zero-Trust QR Challenges.
- **Zero-Trust Digital Signatures:** Initiate and verify PKCS#7 document signatures without exposing the document payload to the server.
- **Sovereign Device (HSM) Integration:** Transform mobile apps into Hardware Security Modules (HSM) via on-device RSA keypair generation (`node-forge`).
- **Pluggable Storage Adapters:** Defaults to `MemoryStorageAdapter` (never persists refresh tokens in `localStorage`); supports custom Secure Enclave (`expo-secure-store`) or explicit `LocalStorageAdapter` integrations.
- **Ecosystem Session Exchange:** Securely exchange UID.ONE tokens for local shadow profile sessions in your applications (e.g., Trip.Express) using JWKS local verification.

## 🛡 Decentralized Availability (Zero-Trust Autonomy)

Unlike traditional OAuth providers that force your app to verify tokens via their servers continuously, UID.ONE uses a **Cryptographic Zero-Trust Architecture**.

1. **The Passport Stamp:** UID.ONE signs a mathematical proof (JWT) upon login and hands it to your Application.
2. **Local Verification:** Your Application uses UID.ONE's public JWKS to verify the signature locally—no network call required.
3. **Decentralized Survival:** If UID.ONE servers go offline, your logged-in users **will not be affected**. Your application continues to operate autonomously with 100% uptime using the local session until the cryptographic token organically expires.

## 📦 Installation

```bash
npm install @oneuid-auth-js/core
# or
yarn add @oneuid-auth-js/core
# or
pnpm add @oneuid-auth-js/core
```

## 🚀 Quick Start

### 1. Initialization

Create a singleton instance of the `OneUID` client. By default, it uses `MemoryStorageAdapter` across all runtimes so refresh tokens are never persisted in `localStorage`.

```typescript
import { OneUID } from '@oneuid-auth-js/core';

export const auth = new OneUID({
  baseURL: 'https://auth.uid.one',
  clientId: 'your-client-id-here', // Contact UID.ONE to get your client ID
});
```

> **URL security:** `baseURL` and `redirectUri` require `https://` (`http://localhost` and `http://127.0.0.1` are permitted for local development only). Never configure `clientSecret` in browser bundles; any `clientSecret` supplied in a browser runtime is ignored.

### 1.1 Embedding Pre-Styled Buttons (Zero-Code Integration)

For developers looking to integrate sign-in controls with minimal footprint, the SDK provides a built-in DOM-rendering engine to embed responsive, brand-consistent buttons (all sizes enforce at least a `44x44px` hit target, loading/disabled lock, and inline retryable error feedback):

**HTML Container:**
```html
<div id="uid-login-container"></div>
```

**SDK Initialization:**
```typescript
// Starts an OIDC Authorization Code + PKCE (S256) flow with random state and nonce
auth.renderButton('uid-login-container', {
  provider: 'uid', // Options: 'uid' | 'google' | 'facebook' | 'apple'
  redirectUri: 'https://trip.express/auth/callback',
  theme: 'dark', // Options: 'light' | 'dark' | 'brand'
  size: 'medium', // Options: 'small' | 'medium' | 'large' (all >= 44px height)
});
```

### 1.2 OIDC Authorization Code + PKCE Flow (Recommended for Web & SPAs)

```typescript
// 1. Start authorization (generates S256 code_challenge, state, and nonce)
const { url } = await auth.startAuthorization('https://app.example.com/auth/callback');
window.location.href = url;

// 2. On /auth/callback, verify state, exchange code with code_verifier, and verify JWTs via JWKS
const tokens = await auth.handleRedirectCallback();
```

### 2. Passwordless Authentication (Passkey)

UID.ONE defaults to Sovereign Identity (Passwordless).

```typescript
// Triggers OS biometrics and verifies returned JWTs against the issuer JWKS
try {
  await auth.passkey.login();
} catch (error) {
  console.error('Passkey authentication failed');
}
```

### 3. Application Integration (Session Exchange Pattern)

For ecosystem applications, keep refresh tokens out of `localStorage` and exchange only the verified `id_token` (or `access_token`) with your backend to mint a local `httpOnly` session cookie.

**Frontend (Client Component):**
```typescript
const session = await auth.passkey.login();
const assertionToken = session.id_token || session.access_token;

// Send only the ID/access assertion token (never the refresh token)
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
    const jwksUrl = new URL(`${process.env.UID_ONE_ISSUER_URL}/oauth/certs`);
    const JWKS = createRemoteJWKSet(jwksUrl);

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: process.env.UID_ONE_ISSUER_URL, // e.g. 'https://auth.uid.one'
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

### 3.1 Native Social Authentication (Authorization Code + PKCE)

Social login must use the provider's **Authorization Code + PKCE (`S256`)** flow with a cryptographically random `state` (and `nonce` for OIDC providers). Never use `response_type=token` (implicit flow) or pass a `clientSecret` from browser code.

#### 1. Redirect to Provider (Client-side with PKCE + random state/nonce)
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

#### 2. Verify `state` and Exchange Authorization Code
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

### 4. Password Login Fallback (Two-Step with 2FA)

Prefer `auth.startAuthorization()` (PKCE) or Passkeys for user login. Direct password grants (`loginWithPassword`) are deprecated and disabled by default because they bypass 2FA. When a password fallback is required, use the two-step `verifyPassword` + `verify2FA` flow:

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

### 4.1 Account Discovery & Registration Notes

- `auth.identify(email)` queries `/v1/auth/identify/` and can reveal whether an account exists and which authentication factors are enabled. Enforce strict rate limiting on login forms and never treat `session_token` from `identify()` as a session credential.
- `auth.register(email, password)` creates an unverified account (`{ verification_required: true }`) and never persists session tokens. Complete email or passcode verification (`auth.verifyPasscode`) before signing in.

### 4.2 Cross-Device Auth (QR / Extension Challenges)

`session_id` is a bearer secret — never place it in predictable URLs without origin binding. Approvers must inspect challenge metadata via `auth.session.get(sessionId)` and confirm the displayed `matchNumber` before calling `approve()`:

```typescript
// Requestor (web)
const challenge = await auth.session.create('QR', 'app.example.com');
const ac = new AbortController();
const tokens = await auth.session.pollForApproval(challenge.session_id, {
  intervalMs: 2000,
  timeoutMs: 120_000,
  signal: ac.signal,
});

// Approver (authenticated mobile device)
const details = await auth.session.get(challenge.session_id);
await auth.session.approve(details.session_id, { matchNumber: userConfirmedCode });
```

## 🛠 Advanced: Custom Storage Adapters (React Native & Mobile)

On web, keep tokens in the default `MemoryStorageAdapter` (paired with an `httpOnly` backend session). On React Native or Expo, inject a hardware-backed adapter such as `expo-secure-store` (do not store refresh tokens in unencrypted `localStorage`):

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

### 5. Sovereign Device Registration (Phase 3 Zero-Trust)

To elevate your application's security to Zero-Trust, you can register the user's physical device as a Hardware Security Module (HSM). The device generates an RSA key pair locally, protects the private key using the device's Secure Enclave (FaceID/TouchID), and sends the public key to UID.ONE.

```typescript
import { auth } from './auth';
import forge from 'node-forge';

// Generate 2048-bit RSA KeyPair (Powered by node-forge)
const keypair = forge.pki.rsa.generateKeyPair(2048);
const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);

// 1. Save privateKeyPem to your OS Secure Enclave (e.g., expo-secure-store)
// 2. Register device with UID.ONE CA Server
await auth.devices.register({
    deviceId: 'unique-device-uuid',
    deviceName: 'Johns iPhone 15',
    publicKey: publicKeyPem
});

// The device is now a Sovereign Identity Authority!
```

#### 2.1 Cryptographic Device Verification (Circle of Trust)
Verify a new device using an already verified device's private key signature:
```typescript
await auth.devices.verify({
    targetDeviceId: 'target-device-uuid',
    verifyingDeviceId: 'trusted-device-uuid',
    signature: 'BASE64_CRYPTOGRAPHIC_SIGNATURE'
});
```

### 6. Vault & Sovereign Encryption (Zero-Knowledge & Hybrid Transfer)

The SDK provides direct APIs for Zero-Knowledge Vault storage and secure asymmetric record transfer using Sovereign Device keys.

#### Retrieve Recipient's Active Device Public Key
```typescript
// Query the active device public key of the recipient by their email, username, or UID
const recipientPubKeyInfo = await auth.getUserPublicKey('recipient@trip.express');
```

#### Save a Record to the User's Vault (AES-GCM encrypted local payload)
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

##### Supported Record Types (`type` parameter):
| Value | Description |
|---|---|
| `'NOTE'` | Secure notes or generic text (Default) |
| `'TICKET'` | Travel tickets, bookings, or vouchers |
| `'CARD'` | Payment card details |
| `'WALLET'` | Cryptographic wallet credentials / keys |
| `'PASSKEY'` | Backup passkey credentials |
| `'PASSWORD'` | Legacy credentials |
| `'API_KEY'` | Access tokens / API keys |
| `'SIGNATURE'`| Document signature verifications |
| `'DOCUMENT'` | Document metadata / encrypted PDFs |
| `'OTHER'` | Generic encrypted data fallback |

#### Transfer ownership of a Vault Record (Hybrid asymmetric wrapping)
```typescript
await auth.transferVaultRecord(
  'record-id-uuid',
  'recipient@trip.express',           // Recipient identifier
  'NEW_ENCRYPTED_PAYLOAD',            // Encrypted with session key
  'WRAPPED_SESSION_KEY_FOR_RECIPIENT' // Session key encrypted using recipient's public key
);
```

#### Manage Device-bound Master Vault Keys (MVK)
```typescript
await auth.registerDeviceVaultKey('unique-device-id', 'WRAPPED_MVK_PEM');
const keys = await auth.getDeviceVaultKeys();
```

## 🔑 KMS & Envelope Encryption (Server-Side)

For server-side applications requiring envelope encryption, `KMSClient` uses the Web Crypto API (`AES-GCM`) with an explicit KEK (`initKMS({ kekB64 })`). `OneUID` never auto-loads `VAULT_MASTER_KEY` from `process.env`, and `initKMS` refuses static KEKs in browser runtimes (browser callers must provide an explicit non-env `keyProvider`).

### Server-Only KMS Integration

```typescript
import { OneUID } from '@oneuid-auth-js/core';

// Server-side only (never pass kekB64 or clientSecret to browser code)
const auth = new OneUID({
  baseURL: 'https://api.uid.one',
  clientId: 'your-server-client-id',
});

const kms = auth.initKMS({
  kekB64: process.env.VAULT_MASTER_KEY, // Explicit 256-bit base64 key on the server
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

// 1. Encrypt data using active DEK
const { ciphertext, version } = await kms.encrypt('Sensitive payload');

// 2. Decrypt data using wrapped DEK version
const plaintext = await kms.decrypt(ciphertext, version);
```

### Key Cache TTL & Offline Behavior

- **Active Cache (1 hour):** Unwrapped DEKs are cached in memory for up to `3600` seconds for both `encrypt()` and `decrypt()`.
- **Read-Only Fallback (24 hours):** If the remote KMS is unreachable during `decrypt(ciphertext, version)`, cached or `keyringStorage` DEKs remain usable for up to `86400` seconds (24 hours). Keys older than 24 hours are evicted.
- **Fail-Closed Writes:** If the remote KMS is unreachable during `encrypt()`, `KMSClient` throws an `AuthError` (`kms_unreachable`) instead of writing with an unverified active cipher version.

## ⚙️ Production Web Server Tuning (Nginx / Apache)

When using the **Session Exchange Pattern**, your application's backend will issue a local session cookie that stores cryptographic tokens (JWTs) and user profile information. This often results in a relatively large `Set-Cookie` header size (exceeding 4KB or 8KB).

By default, web proxies like **Nginx** or **Apache** have small header buffer limits. If a response header exceeds these limits, the proxy will terminate the connection and return a **502 Bad Gateway** or **500 Internal Server Error** (with Nginx reporting `upstream sent too big header while reading response header from upstream` in its logs).

To prevent this in production, you must increase the proxy buffer sizes:

### Nginx Configuration
Add the following directives inside your Next.js/application `location /` proxy block:

```nginx
location / {
    proxy_pass http://localhost:3000;
    
    # Increase proxy buffers to handle large session cookies/headers
    proxy_buffer_size   128k;
    proxy_buffers       4 256k;
    proxy_busy_buffers_size 256k;
    
    # Other proxy settings...
}
```

### Apache Configuration (mod_proxy)
Add the following directive inside your virtual host configuration:

```apache
<VirtualHost *:443>
    # Increase I/O buffer size (default is 8192 bytes)
    ProxyIOBufferSize 65536
    
    # Other settings...
</VirtualHost>
```

## 🧩 Browser Extension Compatibility

The UID.ONE Browser Extension is designed to upgrade legacy applications that do not natively support Passkeys. If you are integrating this SDK into your application, your app is considered "Native".

When you instantiate the `OneUID` client in a browser environment, the SDK automatically injects a `<meta name="uid-passkey-native" content="true">` tag into the document `<head>`. This signals the UID.ONE Browser Extension to **disable itself** on your domain to prevent UI conflicts (e.g., duplicate Passkey buttons or injected fingerprint icons).

**For Next.js / Server-Side Rendering (SSR):**
To prevent any UI flickering (FOUC) before the JavaScript SDK initializes, it is highly recommended to manually add the meta tag to your server-rendered HTML head (e.g., in `layout.tsx` or `index.html`):

```html
<head>
  <meta name="uid-passkey-native" content="true" />
</head>
```

## 🛡 Security & Compliance

When implementing this SDK in consumer-facing applications, ensure that you display the UID.ONE trust badge on your authentication screens. 
All identity payloads are processed and secured in compliance with global data privacy regulations via the UID.ONE infrastructure.

## 📄 License

MIT © UID.ONE Ecosystem
