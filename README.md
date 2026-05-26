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
- **Pluggable Storage Adapters:** Built-in `LocalStorageAdapter` and `MemoryStorageAdapter`. Easily write your own adapter for `AsyncStorage` (React Native) or Secure Enclaves.
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

Create a singleton instance of the `OneUID` client. By default, it uses `MemoryStorageAdapter` if `window` is undefined, and `LocalStorageAdapter` in the browser.

```typescript
import { OneUID } from '@oneuid-auth-js/core';

export const auth = new OneUID({
  baseURL: 'https://auth.uid.one',
  clientId: 'your-client-id-here', // Contact UID.ONE to get your client ID
});
```

### 1.1 Embedding Pre-Styled Buttons (Zero-Code Integration)

For developers looking to integrate sign-in controls with minimal footprint, the SDK provides a built-in DOM-rendering engine to embed responsive, brand-consistent buttons (using native elements, preventing external CSS collisions or bundle bloat):

**HTML Container:**
```html
<div id="uid-login-container"></div>
```

**SDK Initialization:**
```typescript
// Render standard Passkey / UID.ONE authentication button
auth.renderButton('uid-login-container', {
  provider: 'uid', // Options: 'uid' | 'google' | 'facebook' | 'apple'
  redirectUri: 'https://trip.express/auth/callback',
  theme: 'dark', // Options: 'light' | 'dark'
  size: 'medium', // Options: 'small' | 'medium' | 'large'
});
```

### 2. Passwordless Authentication (Passkey)

UID.ONE defaults to Sovereign Identity (Passwordless).

```typescript
// Triggers the OS Biometrics (FaceID/TouchID) and handles the full challenge-response loop securely
try {
  const session = await auth.passkey.login();
  console.log('Passkey login successful!', session.access_token);
} catch (error) {
  console.error('Passkey authentication failed:', error);
}
```

### 3. Application Integration (Session Exchange Pattern)

For ecosystem applications (like `Trip.Express` or local clients), you should not rely solely on the UID.ONE token in the browser. Instead, use the SDK to get the UID.ONE Identity Token, and exchange it with your own backend to issue a local HTTP-Only Session Cookie.

**Frontend (Client Component):**
```typescript
// Get token via Passkey, Social, or Email/Password
const session = await auth.passkey.login();
const uidToken = `${session.access_token}:::${session.refresh_token || ""}`;

// Send to your App's backend for Session Exchange
await fetch('/api/auth/social', {
    method: 'POST',
    body: JSON.stringify({ provider: 'passkey', token: uidToken })
});
```

**Backend (Next.js Server Action / API Route):**
```typescript
import { createRemoteJWKSet, jwtVerify } from 'jose';

export async function verifyUidSession(token: string) {
    try {
        // 1. Fetch the JWKS from UID.ONE to verify the token asynchronously
        // UID_ONE_ISSUER_URL should be: https://auth.uid.one
        const jwksUrl = new URL(`${process.env.UID_ONE_ISSUER_URL}/oauth/certs`);
        const JWKS = createRemoteJWKSet(jwksUrl);
        
        // 2. Verify the Token Signature (Zero-Trust Cryptographic Verification)
        const { payload } = await jwtVerify(token, JWKS, {
            issuer: process.env.UID_ONE_ISSUER_URL,
            audience: process.env.UID_ONE_CLIENT_ID, // e.g., 'trip-express'
        });
        
        // 3. Sync Shadow Profile & Issue Local Session
        const localUser = await syncShadowProfileWithDatabase(payload.sub, payload.email);
        await createLocalHttpOnlySession(localUser);
        
        return { success: true };
    } catch (error) {
        console.error("Token verification failed:", error);
        return { success: false };
    }
}
```

### 3.1 Delegated Social Authentication (Google, Facebook, Apple)

Instead of integrating individual SDKs for Google, Facebook, or Apple on your client application, UID.ONE delegates this complexity. 

Your application only needs to redirect the user to the UID.ONE auth portal. UID.ONE processes the third-party token exchange, verifies the cryptographic signature, and redirects back to your application with the unified UID.ONE session token.

**Redirect Flow:**
```typescript
const handleSocialAuth = (provider: 'google' | 'facebook' | 'apple') => {
  const redirectUri = encodeURIComponent(`${window.location.origin}/auth/callback`);
  window.location.href = `https://auth.uid.one/login?provider=${provider}&redirect_uri=${redirectUri}&client_id=your-client-id`;
};
```

**Callback Handling (Next.js/SPA Client):**
Once the user completes social authentication on the UID.ONE gateway, they are redirected back to your callback page (e.g. `/auth/callback?provider=google&access_token=...`). Your application exchanges the token for a local session using the standard Session Exchange Pattern shown above.

### 4. Standard Login (Email/Password) - Legacy Fallback

Authenticate users using standard credentials if they haven't migrated to Passkeys yet.

```typescript
try {
  const data = await auth.loginWithPassword('user@trip.express', 'supersecretpassword');
  console.log('Login successful!', data.access_token);
} catch (error) {
  console.error('Login failed:', error);
}
```

## 🛠 Advanced: Custom Storage Adapters (React Native)

If you are building for React Native or Expo, you can inject a custom `StorageAdapter` during initialization.

```typescript
import { OneUID, StorageAdapter } from '@oneuid-auth-js/core';
import AsyncStorage from '@react-native-async-storage/async-storage';

class ReactNativeStorage implements StorageAdapter {
  async getItem(key: string): Promise<string | null> {
    return await AsyncStorage.getItem(key);
  }
  async setItem(key: string, value: string): Promise<void> {
    await AsyncStorage.setItem(key, value);
  }
  async removeItem(key: string): Promise<void> {
    await AsyncStorage.removeItem(key);
  }
}

const auth = new OneUID({
  baseURL: 'https://api.uid.one',
  clientId: 'your-client-id',
  storage: new ReactNativeStorage()
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

### 6. Vault & Sovereign Encryption (Zero-Knowledge & Hybrid Transfer)

The SDK provides direct APIs for Zero-Knowledge Vault storage and secure asymmetric record transfer using Sovereign Device keys.

#### Retrieve Recipient's Active Device Public Key
```typescript
// Query the active device public key of the recipient by their email, username, or UID
const recipientPubKeyInfo = await auth.getUserPublicKey('recipient@trip.express');
console.log('Public Key:', recipientPubKeyInfo.public_key);
```

#### Save a Record to the User's Vault (AES-GCM encrypted local payload)
```typescript
// Add a new encrypted record with optional Signed Provenance
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
// 1. Decrypt locally with your Master Vault Key (MVK)
// 2. Encrypt the record session key using the recipient's public key (Key Wrapping)
// 3. Encrypt the record payload using the session key
// 4. Send the payload and wrapped session key to the server to initiate transfer
await auth.transferVaultRecord(
  'record-id-uuid',
  'recipient@trip.express',           // Recipient identifier
  'NEW_ENCRYPTED_PAYLOAD',            // Encrypted with session key
  'WRAPPED_SESSION_KEY_FOR_RECIPIENT' // Session key encrypted using recipient's public key
);
```

#### Manage Device-bound Master Vault Keys (MVK)
To support multi-device access without storing raw vault keys on the server, you encrypt the Master Vault Key (MVK) with each device's public key (Key Wrapping) and register it:
```typescript
// Register a wrapped MVK for a new device
await auth.registerDeviceVaultKey('unique-device-id', 'WRAPPED_MVK_PEM');

// Retrieve all wrapped MVKs for the current user
const keys = await auth.getDeviceVaultKeys();
```

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
