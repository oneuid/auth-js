import { AuthError } from './errors';

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * Returns true when running inside a browser DOM environment.
 */
export function isBrowserRuntime(): boolean {
  return typeof window !== 'undefined' && typeof document !== 'undefined';
}

/**
 * Resolves the standard Web Crypto API across browsers and Node 20+.
 */
export function getWebCrypto(): Crypto {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    return window.crypto;
  }
  throw new AuthError('crypto_unavailable', 'Web Crypto API is not available in this environment.');
}

type BufferLike = {
  from(input: string | Uint8Array, encoding?: string): Uint8Array & { toString(encoding: string): string };
};

/**
 * Encodes bytes as unpadded base64url (RFC 4648 Section 5).
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  const globalBuffer = typeof globalThis !== 'undefined' ? (globalThis as { Buffer?: BufferLike }).Buffer : undefined;
  let b64: string;
  if (globalBuffer) {
    b64 = globalBuffer.from(bytes).toString('base64');
  } else {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    b64 = btoa(bin);
  }
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/**
 * Decodes unpadded or padded base64url into bytes.
 */
export function base64UrlDecode(input: string): Uint8Array {
  let b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) {
    b64 += '=';
  }
  const globalBuffer = typeof globalThis !== 'undefined' ? (globalThis as { Buffer?: BufferLike }).Buffer : undefined;
  if (globalBuffer) {
    return new Uint8Array(globalBuffer.from(b64, 'base64'));
  }
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generates a cryptographically random base64url token (default 256 bits).
 */
export function generateRandomToken(byteLength: number = 32): string {
  const crypto = getWebCrypto();
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * Generates a high-entropy RFC 7636 PKCE code_verifier (86 characters).
 */
export function generateCodeVerifier(): string {
  return generateRandomToken(64);
}

/**
 * Derives an RFC 7636 S256 code_challenge from a code_verifier.
 */
export async function deriveCodeChallengeS256(verifier: string): Promise<string> {
  if (!verifier || verifier.length < 43 || verifier.length > 128) {
    throw new AuthError('invalid_code_verifier', 'PKCE code_verifier must be between 43 and 128 characters.');
  }
  const crypto = getWebCrypto();
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return base64UrlEncode(new Uint8Array(digest));
}

/**
 * Validates that a URL uses HTTPS, with an explicit localhost/loopback HTTP exception for local development.
 */
export function assertSafeUrl(rawUrl: string, label: string): URL {
  if (!rawUrl || typeof rawUrl !== 'string') {
    throw new AuthError('invalid_url', `${label} must be a non-empty URL.`);
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new AuthError('invalid_url', `${label} is not a valid URL.`);
  }

  if (parsed.protocol === 'https:') {
    return parsed;
  }
  if (parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase())) {
    return parsed;
  }

  throw new AuthError(
    'insecure_url',
    `${label} must use HTTPS (http:// is permitted only for localhost/127.0.0.1 development).`
  );
}
