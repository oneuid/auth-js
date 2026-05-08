import { StorageAdapter } from './types';

// Default in-memory storage fallback if no storage is provided and no window is available
class MemoryStorage implements StorageAdapter {
  private store = new Map<string, string>();

  getItem(key: string) { return this.store.get(key) || null; }
  setItem(key: string, value: string) { this.store.set(key, value); }
  removeItem(key: string) { this.store.delete(key); }
}

export const getDefaultStorage = (): StorageAdapter => {
  if (typeof window !== 'undefined' && window.localStorage) {
    return {
      getItem: (key) => window.localStorage.getItem(key),
      setItem: (key, value) => window.localStorage.setItem(key, value),
      removeItem: (key) => window.localStorage.removeItem(key)
    };
  }
  return new MemoryStorage();
};
