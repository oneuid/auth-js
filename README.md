# @oneuid-auth-js/core

[![npm version](https://img.shields.io/npm/v/@oneuid-auth-js/core.svg?style=flat-square)](https://www.npmjs.com/package/@oneuid-auth-js/core)
[![TypeScript](https://img.shields.io/badge/%3C%2F%3E-TypeScript-blue.svg?style=flat-square)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**@oneuid-auth-js/core** is the official headless authentication SDK for the **UID.ONE** Sovereign Identity Ecosystem.

Designed for maximum flexibility, this SDK provides a headless authentication client that works seamlessly across modern web applications (React, Vue, Next.js) and mobile frameworks (React Native, Expo) by relying on a pluggable storage architecture.

## ✨ Features

- **Headless Architecture:** No forced UI components. Bring your own design system.
- **Passkey (FIDO2) First:** Full support for passwordless authentication via biometric passkeys.
- **Cross-Device Sessions (QR):** Seamlessly authenticate across devices using QR codes.
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
// 1. Fetch Challenge
const options = await auth.passkey.login.getOptions();

// 2. Trigger OS Biometrics (FaceID/TouchID)
const credential = await navigator.credentials.get({ publicKey: options.publicKey });

// 3. Verify and Issue Token
const session = await auth.passkey.login.verify({
  auth_session_id: options.auth_session_id,
  credential: credential
});

console.log('Passkey login successful!', session.access_token);
```

### 3. Application Integration (Session Exchange Pattern)

For ecosystem applications (like `Trip.Express` or local Agents), you should not rely solely on the UID.ONE token. Instead, use the SDK to get the UID.ONE Identity Token, and exchange it with your own backend to issue a local HTTP-Only Session Cookie.

**Frontend (Client Component):**
```typescript
// Get token via Passkey, Social, or Email/Password
const uidToken = session.access_token;

// Send to your App's backend for Session Exchange
await fetch('/api/auth/social', {
    method: 'POST',
    body: JSON.stringify({ provider: 'one', token: uidToken })
});
```

**Backend (Next.js Server Action / API Route):**
```typescript
import { OneUID } from '@oneuid-auth-js/core';

export async function exchangeTokenForSession(provider: string, token: string) {
    if (provider === "one" || provider === "uid.one") {
        const auth = new OneUID({
            baseURL: process.env.UID_ONE_API_URL,
            clientId: process.env.UID_ONE_CLIENT_ID,
        });
        
        // 1. Verify the incoming token with UID.ONE
        const data = await auth.loginWithProvider("uid.one", token);
        const exchangeToken = data.id_token || data.access_token;
        
        // 2. Sync Shadow Profile & Issue Local Session
        const localUser = await syncShadowProfileWithDatabase(exchangeToken);
        await createLocalHttpOnlySession(localUser);
        
        return { success: true };
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

## 🛡 Security & Compliance

When implementing this SDK in consumer-facing applications, ensure that you display the UID.ONE trust badge on your authentication screens. 
All identity payloads are processed and secured in compliance with global data privacy regulations via the UID.ONE infrastructure.

## 📄 License

MIT © UID.ONE Ecosystem
