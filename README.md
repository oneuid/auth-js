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
- **Pluggable Storage Adapters:** Built-in `LocalStorageAdapter` and `MemoryStorageAdapter`. Easily write your own adapter for `AsyncStorage` (React Native) or Secure Enclaves.
- **Ecosystem Session Exchange:** Securely exchange UID.ONE tokens for local shadow profile sessions in your applications (e.g., Trip.Express).

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
  baseURL: 'https://api.uid.one',
  clientId: 'your-client-id-here', // Contact UID.ONE to get your client ID
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

For ecosystem applications (like `Trip.Express` or local Agents), you should not rely solely on the UID.ONE token in the browser. Instead, use the SDK to get the UID.ONE Identity Token, and exchange it with your own backend to issue a local HTTP-Only Session Cookie.

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
        const jwksUrl = new URL(`${process.env.UID_ONE_API_URL}/.well-known/jwks.json`);
        const JWKS = createRemoteJWKSet(jwksUrl);
        
        // 2. Verify the Token Signature
        const { payload } = await jwtVerify(token, JWKS, {
            issuer: process.env.UID_ONE_API_URL,
            audience: process.env.UID_ONE_CLIENT_ID,
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
