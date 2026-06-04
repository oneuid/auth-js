import { AuthConfig } from './types';
import { OneUID } from './client';

// Cross-platform helper to resolve Web Crypto API
function getCrypto(): Crypto {
  const globalObj = typeof globalThis !== 'undefined' ? globalThis as any : {};
  if (globalObj.crypto) {
    return globalObj.crypto;
  }
  if (typeof window !== 'undefined' && window.crypto) {
    return window.crypto;
  }
  try {
    const globalRequire = typeof globalThis !== 'undefined' ? (globalThis as any).require : undefined;
    if (globalRequire) {
      return globalRequire('crypto').webcrypto as Crypto;
    }
  } catch {
    // Ignore and throw generic error below
  }
  throw new Error("Web Crypto API is not available in this environment.");
}

// Convert base64 string to Uint8Array
function base64ToBytes(b64: string): Uint8Array {
  const globalBuffer = typeof globalThis !== 'undefined' ? (globalThis as any).Buffer : undefined;
  if (globalBuffer) {
    return new Uint8Array(globalBuffer.from(b64, 'base64'));
  }
  const binString = atob(b64);
  return Uint8Array.from(binString, (m) => m.charCodeAt(0));
}

// Convert Uint8Array to base64 string
function bytesToBase64(bytes: Uint8Array): string {
  const globalBuffer = typeof globalThis !== 'undefined' ? (globalThis as any).Buffer : undefined;
  if (globalBuffer) {
    return globalBuffer.from(bytes).toString('base64');
  }
  const binString = Array.from(bytes, (x) => String.fromCharCode(x)).join("");
  return btoa(binString);
}

// Convert string to Uint8Array
function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// Convert Uint8Array to string
function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export interface KeyringStorageAdapter {
  getItem(key: string): Promise<string | null> | string | null;
  setItem(key: string, value: string): Promise<void> | void;
}

export class KMSClient {
  private keyCache: Map<number, { rawDek: Uint8Array; fetchedAt: Date }> = new Map();
  private kekBytes: Uint8Array;
  private keyringStorage?: KeyringStorageAdapter;

  constructor(
    private config: AuthConfig,
    private root: OneUID,
    options: { kekB64?: string; keyringStorage?: KeyringStorageAdapter } = {}
  ) {
    const globalProcess = typeof globalThis !== 'undefined' ? (globalThis as any).process : undefined;
    const kekStr = options.kekB64 || (globalProcess && globalProcess.env ? globalProcess.env.VAULT_MASTER_KEY : undefined);
    if (!kekStr) {
      throw new Error("Master Key (VAULT_MASTER_KEY) is required to initialize KMSClient");
    }
    this.kekBytes = base64ToBytes(kekStr);
    this.keyringStorage = options.keyringStorage;
  }

  /**
   * Decrypts the DEK locally using the KEK (Master Key)
   */
  private async unwrapDek(wrappedB64: string): Promise<Uint8Array> {
    try {
      const crypto = getCrypto();
      const combined = base64ToBytes(wrappedB64);
      if (combined.length < 12) {
        throw new Error("Invalid wrapped key format.");
      }
      
      const nonce = combined.slice(0, 12);
      const encrypted = combined.slice(12);

      // Import KEK (Master Key)
      const kekKey = await crypto.subtle.importKey(
        "raw",
        this.kekBytes as any,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
      );

      // Decrypt DEK
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce as any },
        kekKey,
        encrypted as any
      );

      return new Uint8Array(decrypted);
    } catch (e) {
      throw new Error(`Failed to unwrap DEK. KEK might be invalid or corrupted: ${e}`);
    }
  }

  /**
   * Retrieves raw DEK and its version from memory cache, local keyring storage, or uid.one KMS.
   */
  async getDek(version?: number, operation: 'encrypt' | 'decrypt' = 'decrypt'): Promise<{ rawDek: Uint8Array; version: number }> {
    const now = new Date();

    // 1. Check Memory Cache
    if (version !== undefined) {
      const cached = this.keyCache.get(version);
      if (cached) {
        const age = (now.getTime() - cached.fetchedAt.getTime()) / 1000;
        if (age <= 3600 || (operation === 'decrypt' && age <= 86400)) {
          return { rawDek: cached.rawDek, version };
        }
      }
    } else {
      // Find latest active entry in memory
      let activeVer: number | null = null;
      let activeCached: { rawDek: Uint8Array; fetchedAt: Date } | null = null;

      for (const [v, entry] of this.keyCache.entries()) {
        if (!activeCached || entry.fetchedAt > activeCached.fetchedAt) {
          activeVer = v;
          activeCached = entry;
        }
      }

      if (activeVer !== null && activeCached !== null) {
        const age = (now.getTime() - activeCached.fetchedAt.getTime()) / 1000;
        if (age <= 3600 || (operation === 'decrypt' && age <= 86400)) {
          return { rawDek: activeCached.rawDek, version: activeVer };
        }
      }
    }

    // 2. Check Local Keyring Storage (e.g. database, local storage)
    if (this.keyringStorage && version !== undefined) {
      try {
        const storedWrapped = await this.keyringStorage.getItem(`cipher_version_${version}`);
        if (storedWrapped) {
          const rawDek = await this.unwrapDek(storedWrapped);
          this.keyCache.set(version, { rawDek, fetchedAt: now });
          return { rawDek, version };
        }
      } catch (e) {
        console.warn(`Failed to read version ${version} from local keyring storage:`, e);
      }
    }

    // 3. Fetch from Remote KMS API
    try {
      const token = await this.root.getAccessToken();
      if (!token) {
        throw new Error("Must be authenticated to fetch KMS ciphers");
      }

      const url = version === undefined
        ? `${this.config.baseURL}/v1/vault/ciphers/active/`
        : `${this.config.baseURL}/v1/vault/ciphers/?version=${version}`;

      const res = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!res.ok) {
        throw new Error(`Failed to fetch cipher: ${res.statusText}`);
      }

      const data = await res.json();
      let cipherData: { version: number; key_material: string };

      if (version === undefined) {
        cipherData = data;
      } else {
        const results = data.results || data;
        if (!results || results.length === 0) {
          throw new Error(`Cipher version ${version} not found.`);
        }
        cipherData = results[0];
      }

      const rawDek = await this.unwrapDek(cipherData.key_material);

      // Save to Local Keyring Storage for Offline Fallback
      if (this.keyringStorage) {
        try {
          await this.keyringStorage.setItem(`cipher_version_${cipherData.version}`, cipherData.key_material);
        } catch (dbErr) {
          console.error(`Failed to persist cipher version ${cipherData.version} to local keyring:`, dbErr);
        }
      }

      this.keyCache.set(cipherData.version, { rawDek, fetchedAt: now });
      return { rawDek, version: cipherData.version };
    } catch (e) {
      // 4. Fallback to Local Keyring Storage if remote KMS is unreachable
      if (this.keyringStorage) {
        try {
          if (version !== undefined) {
            const storedWrapped = await this.keyringStorage.getItem(`cipher_version_${version}`);
            if (storedWrapped) {
              const rawDek = await this.unwrapDek(storedWrapped);
              this.keyCache.set(version, { rawDek, fetchedAt: now });
              return { rawDek, version };
            }
          } else {
            // Find highest version in local keyring storage
            // In Node/React, let's scan or fail gracefully depending on environment
            if (operation === 'encrypt') {
              throw new Error("KMS is unreachable. Cannot verify active encryption cipher version for writes.");
            }
          }
        } catch (fallbackErr) {
          console.error("Local keyring fallback failed:", fallbackErr);
        }
      }

      // 5. Memory Cache Fallback
      if (version !== undefined) {
        const cached = this.keyCache.get(version);
        if (cached) {
          return { rawDek: cached.rawDek, version };
        }
      }

      throw new Error(`KMS is unreachable and key version is not cached locally: ${e}`);
    }
  }

  /**
   * Encrypts plaintext using active DEK.
   * Returns `{ ciphertext: string, version: number }`.
   */
  async encrypt(plaintext: string): Promise<{ ciphertext: string; version: number }> {
    if (!plaintext) return { ciphertext: "", version: 0 };

    const { rawDek, version } = await this.getDek(undefined, 'encrypt');
    const crypto = getCrypto();
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const key = await crypto.subtle.importKey(
      "raw",
      rawDek as any,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce as any },
      key,
      stringToBytes(plaintext) as any
    );

    const encryptedBytes = new Uint8Array(encrypted);
    const combined = new Uint8Array(12 + encryptedBytes.length);
    combined.set(nonce, 0);
    combined.set(encryptedBytes, 12);

    return {
      ciphertext: bytesToBase64(combined),
      version
    };
  }

  /**
   * Decrypts base64 ciphertext using the specific cipher version.
   */
  async decrypt(ciphertextStr: string, version: number): Promise<string> {
    if (!ciphertextStr || version === undefined) return ciphertextStr;

    const { rawDek } = await this.getDek(version, 'decrypt');
    const crypto = getCrypto();
    const combined = base64ToBytes(ciphertextStr);
    if (combined.length < 12) {
      throw new Error("Invalid ciphertext format.");
    }

    const nonce = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const key = await crypto.subtle.importKey(
      "raw",
      rawDek as any,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce as any },
      key,
      ciphertext as any
    );

    return bytesToString(new Uint8Array(decrypted));
  }
}
