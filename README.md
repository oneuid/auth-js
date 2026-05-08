# @oneuid-auth-js/core

[![npm version](https://img.shields.io/npm/v/@oneuid-auth-js/core.svg?style=flat-square)](https://www.npmjs.com/package/@oneuid-auth-js/core)
[![TypeScript](https://img.shields.io/badge/%3C%2F%3E-TypeScript-blue.svg?style=flat-square)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**@oneuid-auth-js/core** is the official headless authentication SDK for the **UID.ONE** Personal OS and Identity Ecosystem. 

Designed for maximum flexibility, this SDK provides a headless authentication client that works seamlessly across modern web applications (React, Vue, Svelte, Next.js) and mobile frameworks (React Native) by relying on a pluggable storage architecture.

## ✨ Features

- **Headless Architecture:** No forced UI components. Bring your own design system.
- **Isomorphic & Universal:** Works in Browser, Node.js, and Mobile environments.
- **Pluggable Storage Adapters:** Built-in `LocalStorageAdapter` and `MemoryStorageAdapter`. Easily write your own adapter for `AsyncStorage` (React Native) or Secure Enclaves.
- **Social Token Exchange:** Securely exchange Google, Facebook, or Apple tokens for UID.ONE credentials.
- **TypeScript First:** 100% strongly typed with full autocompletion support.

## 📦 Installation

Install the package via your favorite package manager:

```bash
npm install @oneuid-auth-js/core
# or
yarn add @oneuid-auth-js/core
# or
pnpm add @oneuid-auth-js/core
```

## 🚀 Quick Start

### 1. Initialization

Create a singleton instance of the `OneUID` client. By default, it will use `MemoryStorageAdapter` if `window` is undefined, and `LocalStorageAdapter` in the browser.

```typescript
import { OneUID } from '@oneuid-auth-js/core';

export const auth = new OneUID({
  baseURL: 'https://api.uid.one',
  clientId: 'your-client-id-here', // Contact UID.ONE to get your client ID
});
```

### 2. Standard Login (Email/Password)

Authenticate users using standard credentials. The SDK automatically manages the Access and Refresh tokens.

```typescript
try {
  await auth.login('user@trip.express', 'supersecretpassword');
  console.log('Login successful!');
} catch (error) {
  console.error('Login failed:', error);
}
```

### 3. Fetching User Data

Once authenticated, retrieve the securely verified identity of the current user.

```typescript
const user = await auth.getMe();
console.log('Welcome back,', user.first_name);
```

### 4. Logging Out

Securely clear local storage and terminate the session.

```typescript
await auth.logout();
```

## 🔗 Social Login (OIDC Token Exchange)

UID.ONE supports headless social authentication. Instead of redirecting users away from your app, simply retrieve an ID Token from your provider (e.g., Google Identity Services) and exchange it for a UID.ONE session.

```typescript
// 1. Get the token from Google (using Google SDK or similar)
const googleIdToken = "eyJhbGciOiJSUzI1..."; 

// 2. Exchange the token with UID.ONE
await auth.loginWithProvider('google', googleIdToken);

// 3. User is now authenticated globally!
const user = await auth.getMe();
```

## 🛠 Advanced: Custom Storage Adapters

If you are building for React Native or prefer an encrypted local storage, you can inject a custom `StorageAdapter` during initialization.

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
