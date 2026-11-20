import { StorageAdapter } from './types';

let localStorageWarned = false;

/**
 * Default in-memory storage adapter. Keeps tokens out of browser localStorage.
 */
export class MemoryStorageAdapter implements StorageAdapter {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }
}

/**
 * Browser localStorage adapter.
 * Not recommended for refresh tokens in web applications due to XSS exposure;
 * prefer MemoryStorageAdapter with an httpOnly backend session exchange or native Secure Enclave.
 */
export class LocalStorageAdapter implements StorageAdapter {
  constructor() {
    if (typeof window !== 'undefined' && !localStorageWarned) {
      localStorageWarned = true;
      console.warn(
        '[OneUID] LocalStorageAdapter stores tokens in browser localStorage, which is accessible to XSS scripts. Prefer MemoryStorageAdapter with an httpOnly session-exchange backend.'
      );
    }
  }

  getItem(key: string): string | null {
    if (typeof window === 'undefined' || !window.localStorage) return null;
    return window.localStorage.getItem(key);
  }

  setItem(key: string, value: string): void {
    if (typeof window === 'undefined' || !window.localStorage) return;
    window.localStorage.setItem(key, value);
  }

  removeItem(key: string): void {
    if (typeof window === 'undefined' || !window.localStorage) return;
    window.localStorage.removeItem(key);
  }
}

/**
 * Returns default in-memory storage so refresh tokens are never placed in localStorage by default.
 */
export const getDefaultStorage = (): StorageAdapter => {
  return new MemoryStorageAdapter();
};

/**
 * Returns browser sessionStorage wrapper for short-lived PKCE redirect transactions, if available.
 */
export const getBrowserSessionStorage = (): StorageAdapter | null => {
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      return {
        getItem: (key: string) => window.sessionStorage.getItem(key),
        setItem: (key: string, value: string) => window.sessionStorage.setItem(key, value),
        removeItem: (key: string) => window.sessionStorage.removeItem(key),
      };
    }
  } catch {
    // Ignore restricted sessionStorage access (e.g., sandboxed iframes)
  }
  return null;
};
