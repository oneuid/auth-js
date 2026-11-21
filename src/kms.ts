import { AuthConfig } from './types';
import { OneUID } from './client';
import { AuthError } from './errors';
import { getWebCrypto, isBrowserRuntime } from './pkce';

type BufferLike = {
  from(input: string | Uint8Array, encoding?: string): Uint8Array & { toString(encoding: string): string };
};

// Convert base64 string to Uint8Array
function base64ToBytes(b64: string): Uint8Array {
  const globalBuffer = typeof globalThis !== 'undefined' ? (globalThis as { Buffer?: BufferLike }).Buffer : undefined;
  if (globalBuffer) {
    return new Uint8Array(globalBuffer.from(b64, 'base64'));
  }
  const binString = atob(b64);
  return Uint8Array.from(binString, (m) => m.charCodeAt(0));
}

// Convert Uint8Array to base64 string
function bytesToBase64(bytes: Uint8Array): string {
  const globalBuffer = typeof globalThis !== 'undefined' ? (globalThis as { Buffer?: BufferLike }).Buffer : undefined;
  if (globalBuffer) {
    return globalBuffer.from(bytes).toString('base64');
  }
  const binString = Array.from(bytes, (x) => String.fromCharCode(x)).join('');
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

export type KMSKeyProvider = () => Promise<Uint8Array | string> | Uint8Array | string;

export interface KMSOptions {
  /** Base64-encoded 128/192/256-bit KEK for server-side environments. */
  kekB64?: string;
  /** Explicit non-env key provider (required if used in browser runtimes). */
  keyProvider?: KMSKeyProvider;
  /** Optional local keyring storage for offline read-only fallback. */
  keyringStorage?: KeyringStorageAdapter;
}

const ACTIVE_ENCRYPT_TTL_SEC = 3600; // 1 hour
const READ_FALLBACK_TTL_SEC = 86400; // 24 hours

export class KMSClient {
  private keyCache: Map<number, { rawDek: Uint8Array; fetchedAt: Date }> = new Map();
  private staticKekBytes?: Uint8Array;
  private keyProvider?: KMSKeyProvider;
  private keyringStorage?: KeyringStorageAdapter;

  constructor(
    private config: AuthConfig & { baseURL: string },
    private root: OneUID,
    options: KMSOptions = {}
  ) {
    const inBrowser = isBrowserRuntime();

    if (inBrowser) {
      if (typeof options.keyProvider !== 'function') {
        throw new AuthError(
          'kms_browser_forbidden',
          'KMS cannot be initialized in a browser runtime without an explicit non-env keyProvider. Run KMS on the server with initKMS({ kekB64 }).'
        );
      }
      if (options.kekB64) {
        throw new AuthError(
          'kms_browser_forbidden',
          'Static kekB64 is not permitted in a browser runtime. Supply an explicit non-env keyProvider or run KMS on the server.'
        );
      }
      this.keyProvider = options.keyProvider;
    } else if (typeof options.keyProvider === 'function') {
      this.keyProvider = options.keyProvider;
    } else if (options.kekB64 && typeof options.kekB64 === 'string') {
      const decoded = base64ToBytes(options.kekB64.trim());
      if (decoded.length !== 16 && decoded.length !== 24 && decoded.length !== 32) {
        throw new AuthError('kms_invalid_key', 'kekB64 must decode to a 128-, 192-, or 256-bit AES key.');
      }
      this.staticKekBytes = decoded;
    } else {
      throw new AuthError(
        'kms_missing_key',
        'Explicit kekB64 or keyProvider is required to initialize KMSClient.'
      );
    }

    this.keyringStorage = options.keyringStorage;
  }

  private async resolveKekBytes(): Promise<Uint8Array> {
    if (this.staticKekBytes) {
      return this.staticKekBytes;
    }
    if (!this.keyProvider) {
      throw new AuthError('kms_missing_key', 'No KEK provider configured.');
    }
    const provided = await this.keyProvider();
    const bytes = typeof provided === 'string' ? base64ToBytes(provided.trim()) : provided;
    if (!(bytes instanceof Uint8Array) || (bytes.length !== 16 && bytes.length !== 24 && bytes.length !== 32)) {
      throw new AuthError('kms_invalid_key', 'keyProvider must resolve to a 16-, 24-, or 32-byte AES key.');
    }
    return bytes;
  }

  /**
   * Decrypts the DEK locally using the KEK (Master Key).
   */
  private async unwrapDek(wrappedB64: string): Promise<Uint8Array> {
    try {
      const crypto = getWebCrypto();
      const combined = base64ToBytes(wrappedB64);
      if (combined.length < 12) {
        throw new Error('Invalid wrapped key format.');
      }

      const nonce = combined.slice(0, 12);
      const encrypted = combined.slice(12);
      const kekBytes = await this.resolveKekBytes();

      const kekKey = await crypto.subtle.importKey(
        'raw',
        kekBytes as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce as BufferSource },
        kekKey,
        encrypted as BufferSource
      );

      return new Uint8Array(decrypted);
    } catch (e) {
      if (e instanceof AuthError) throw e;
      throw new AuthError('kms_unwrap_failed', 'Failed to unwrap DEK with the configured KEK.');
    }
  }

  /**
   * Retrieves raw DEK and its version from memory cache (up to 1h encrypt / 24h decrypt),
   * local keyring storage, or uid.one KMS.
   */
  async getDek(version?: number, operation: 'encrypt' | 'decrypt' = 'decrypt'): Promise<{ rawDek: Uint8Array; version: number }> {
    const now = new Date();
    const maxAgeSec = operation === 'encrypt' ? ACTIVE_ENCRYPT_TTL_SEC : READ_FALLBACK_TTL_SEC;

    // 1. Check Memory Cache within active TTL
    if (version !== undefined) {
      const cached = this.keyCache.get(version);
      if (cached) {
        const age = (now.getTime() - cached.fetchedAt.getTime()) / 1000;
        if (age <= ACTIVE_ENCRYPT_TTL_SEC) {
          return { rawDek: cached.rawDek, version };
        }
        if (age > READ_FALLBACK_TTL_SEC) {
          this.keyCache.delete(version);
        }
      }
    } else {
      let activeVer: number | null = null;
      let activeCached: { rawDek: Uint8Array; fetchedAt: Date } | null = null;

      for (const [v, entry] of this.keyCache.entries()) {
        const age = (now.getTime() - entry.fetchedAt.getTime()) / 1000;
        if (age > READ_FALLBACK_TTL_SEC) {
          this.keyCache.delete(v);
          continue;
        }
        if (!activeCached || entry.fetchedAt > activeCached.fetchedAt) {
          activeVer = v;
          activeCached = entry;
        }
      }

      if (activeVer !== null && activeCached !== null) {
        const age = (now.getTime() - activeCached.fetchedAt.getTime()) / 1000;
        if (age <= ACTIVE_ENCRYPT_TTL_SEC) {
          return { rawDek: activeCached.rawDek, version: activeVer };
        }
      }
    }

    // 2. Check Local Keyring Storage for explicit version reads
    if (this.keyringStorage && version !== undefined && operation === 'decrypt') {
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
        throw new AuthError('unauthenticated', 'Must be authenticated to fetch KMS ciphers.');
      }

      const baseURL = this.config.baseURL.replace(/\/$/, '');
      const url = version === undefined
        ? `${baseURL}/v1/vault/ciphers/active/`
        : `${baseURL}/v1/vault/ciphers/?version=${version}`;

      const res = await fetch(url, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (!res.ok) {
        throw new AuthError('kms_fetch_failed', `Failed to fetch cipher (${res.status}).`, res.status);
      }

      const data = await res.json();
      let cipherData: { version: number; key_material: string };

      if (version === undefined) {
        cipherData = data;
      } else {
        const results = data.results || data;
        if (!results || results.length === 0) {
          throw new AuthError('kms_cipher_not_found', `Cipher version ${version} not found.`);
        }
        cipherData = results[0];
      }

      const rawDek = await this.unwrapDek(cipherData.key_material);

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
      // 4. Read-only fallback up to 24h when remote KMS is unreachable
      if (operation === 'encrypt') {
        if (e instanceof AuthError) throw e;
        throw new AuthError('kms_unreachable', 'KMS is unreachable. Cannot verify active encryption cipher version for writes.');
      }

      if (this.keyringStorage && version !== undefined) {
        try {
          const storedWrapped = await this.keyringStorage.getItem(`cipher_version_${version}`);
          if (storedWrapped) {
            const rawDek = await this.unwrapDek(storedWrapped);
            this.keyCache.set(version, { rawDek, fetchedAt: now });
            return { rawDek, version };
          }
        } catch (fallbackErr) {
          console.error('Local keyring fallback failed:', fallbackErr);
        }
      }

      if (version !== undefined) {
        const cached = this.keyCache.get(version);
        if (cached) {
          const age = (now.getTime() - cached.fetchedAt.getTime()) / 1000;
          if (age <= maxAgeSec) {
            return { rawDek: cached.rawDek, version };
          }
          this.keyCache.delete(version);
        }
      }

      throw new AuthError('kms_unavailable', 'KMS is unreachable and key version is not cached within its 24-hour TTL.');
    }
  }

  /**
   * Encrypts plaintext using the active DEK.
   */
  async encrypt(plaintext: string): Promise<{ ciphertext: string; version: number }> {
    if (!plaintext) return { ciphertext: '', version: 0 };

    const { rawDek, version } = await this.getDek(undefined, 'encrypt');
    const crypto = getWebCrypto();
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const key = await crypto.subtle.importKey(
      'raw',
      rawDek as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      key,
      stringToBytes(plaintext) as BufferSource
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
    const crypto = getWebCrypto();
    const combined = base64ToBytes(ciphertextStr);
    if (combined.length < 12) {
      throw new AuthError('invalid_ciphertext', 'Invalid ciphertext format.');
    }

    const nonce = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const key = await crypto.subtle.importKey(
      'raw',
      rawDek as BufferSource,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      key,
      ciphertext as BufferSource
    );

    return bytesToString(new Uint8Array(decrypted));
  }
}
