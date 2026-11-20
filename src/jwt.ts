import { AuthError } from './errors';
import { base64UrlDecode, getWebCrypto } from './pkce';

export interface JwkKey extends JsonWebKey {
  kid?: string;
  use?: string;
  alg?: string;
  kty: string;
}

export interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

export interface JwtPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  nonce?: string;
  [key: string]: unknown;
}

export interface VerifyJwtOptions {
  jwksUri: string;
  expectedIssuers: string[];
  expectedAudience: string;
  expectedNonce?: string;
  clockToleranceSec?: number;
}

const ALLOWED_ASYMMETRIC_ALGS = new Set([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]);

function getImportAlgorithm(alg: string, jwk: JwkKey): { importAlg: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams; verifyAlg: AlgorithmIdentifier | RsaPssParams | EcdsaParams } {
  switch (alg) {
    case 'RS256':
      return { importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, verifyAlg: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'RS384':
      return { importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }, verifyAlg: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'RS512':
      return { importAlg: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }, verifyAlg: { name: 'RSASSA-PKCS1-v1_5' } };
    case 'PS256':
      return { importAlg: { name: 'RSA-PSS', hash: 'SHA-256' }, verifyAlg: { name: 'RSA-PSS', saltLength: 32 } };
    case 'PS384':
      return { importAlg: { name: 'RSA-PSS', hash: 'SHA-384' }, verifyAlg: { name: 'RSA-PSS', saltLength: 48 } };
    case 'PS512':
      return { importAlg: { name: 'RSA-PSS', hash: 'SHA-512' }, verifyAlg: { name: 'RSA-PSS', saltLength: 64 } };
    case 'ES256':
      return { importAlg: { name: 'ECDSA', namedCurve: jwk.crv || 'P-256' }, verifyAlg: { name: 'ECDSA', hash: 'SHA-256' } };
    case 'ES384':
      return { importAlg: { name: 'ECDSA', namedCurve: jwk.crv || 'P-384' }, verifyAlg: { name: 'ECDSA', hash: 'SHA-384' } };
    case 'ES512':
      return { importAlg: { name: 'ECDSA', namedCurve: jwk.crv || 'P-521' }, verifyAlg: { name: 'ECDSA', hash: 'SHA-512' } };
    case 'EdDSA':
      return { importAlg: { name: 'Ed25519' }, verifyAlg: { name: 'Ed25519' } };
    default:
      throw new AuthError('unsupported_jwt_alg', `Unsupported JWT algorithm: ${alg}`);
  }
}

function expectedKtyForAlg(alg: string): string {
  if (alg.startsWith('RS') || alg.startsWith('PS')) return 'RSA';
  if (alg.startsWith('ES')) return 'EC';
  if (alg === 'EdDSA') return 'OKP';
  return '';
}

function decodeJsonSegment<T>(segment: string, label: string): T {
  try {
    const bytes = base64UrlDecode(segment);
    const json = new TextDecoder().decode(bytes);
    const parsed = JSON.parse(json);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Expected JSON object');
    }
    return parsed as T;
  } catch {
    throw new AuthError('invalid_jwt', `Malformed JWT ${label}.`);
  }
}

/**
 * Checks whether a token string has a 3-segment compact JWS structure.
 */
export function isJwtShape(token: string): boolean {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [headerPart, payloadPart, sigPart] = parts;
  if (!headerPart || !payloadPart) return false;
  if (!/^[A-Za-z0-9_-]+$/.test(headerPart) || !/^[A-Za-z0-9_-]+$/.test(payloadPart)) {
    return false;
  }
  return sigPart.length === 0 || /^[A-Za-z0-9_-]+$/.test(sigPart);
}

/**
 * Parses a JWT header and payload without trusting its signature.
 * Used only for reading expiry or kid prior to verification.
 */
export function parseJwtUnverified(token: string): {
  header: JwtHeader;
  payload: JwtPayload;
  signingInput: string;
  signature: Uint8Array;
} {
  if (!token || typeof token !== 'string') {
    throw new AuthError('invalid_jwt', 'Token must be a non-empty string.');
  }
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1]) {
    throw new AuthError('invalid_jwt', 'Token is not a valid compact JWS.');
  }
  const [headerB64, payloadB64, sigB64] = parts;
  const header = decodeJsonSegment<JwtHeader>(headerB64, 'header');
  const payload = decodeJsonSegment<JwtPayload>(payloadB64, 'payload');
  const signature = sigB64 ? base64UrlDecode(sigB64) : new Uint8Array(0);

  return {
    header,
    payload,
    signingInput: `${headerB64}.${payloadB64}`,
    signature,
  };
}

export class JWKSCache {
  private keys: JwkKey[] = [];
  private fetchedAtMs = 0;
  private inflight: Promise<JwkKey[]> | null = null;
  private readonly ttlMs = 5 * 60 * 1000;

  async getKeys(jwksUri: string, forceRefresh: boolean = false): Promise<JwkKey[]> {
    const now = Date.now();
    if (!forceRefresh && this.keys.length > 0 && now - this.fetchedAtMs < this.ttlMs) {
      return this.keys;
    }
    if (this.inflight && !forceRefresh) {
      return this.inflight;
    }

    const promise = (async () => {
      const response = await fetch(jwksUri, {
        method: 'GET',
        headers: { Accept: 'application/json' },
      });
      if (!response.ok) {
        throw new AuthError('jwks_fetch_failed', `Failed to fetch JWKS (${response.status}).`, response.status);
      }
      const data = (await response.json()) as { keys?: unknown };
      if (!data || !Array.isArray(data.keys)) {
        throw new AuthError('invalid_jwks', 'JWKS response does not contain a keys array.');
      }
      this.keys = data.keys as JwkKey[];
      this.fetchedAtMs = Date.now();
      return this.keys;
    })();

    this.inflight = promise;
    try {
      return await promise;
    } finally {
      if (this.inflight === promise) {
        this.inflight = null;
      }
    }
  }

  clear(): void {
    this.keys = [];
    this.fetchedAtMs = 0;
  }
}

/**
 * Verifies a JWT signature against the issuer JWKS and validates standard OIDC/JWT claims.
 */
export async function verifyJwt(
  token: string,
  jwksCache: JWKSCache,
  options: VerifyJwtOptions
): Promise<JwtPayload> {
  const { header, payload, signingInput, signature } = parseJwtUnverified(token);

  if (!header.alg || typeof header.alg !== 'string') {
    throw new AuthError('invalid_jwt_alg', 'JWT header is missing alg.');
  }
  const normalizedAlg = header.alg.trim();
  if (normalizedAlg.toLowerCase() === 'none' || normalizedAlg.startsWith('HS')) {
    throw new AuthError('disallowed_jwt_alg', `JWT algorithm "${normalizedAlg}" is not permitted for public clients.`);
  }
  if (!ALLOWED_ASYMMETRIC_ALGS.has(normalizedAlg)) {
    throw new AuthError('unsupported_jwt_alg', `JWT algorithm "${normalizedAlg}" is not supported.`);
  }
  if (signature.length === 0) {
    throw new AuthError('invalid_jwt_signature', 'JWT signature is empty.');
  }

  // Validate claims before/alongside crypto verification
  const expectedIssuers = options.expectedIssuers.map((iss) => iss.replace(/\/$/, ''));
  const tokenIssuer = typeof payload.iss === 'string' ? payload.iss.replace(/\/$/, '') : '';
  if (!tokenIssuer || !expectedIssuers.includes(tokenIssuer)) {
    throw new AuthError('invalid_jwt_iss', 'JWT issuer (iss) does not match expected issuer.');
  }

  const audMatches = Array.isArray(payload.aud)
    ? payload.aud.includes(options.expectedAudience)
    : payload.aud === options.expectedAudience;
  if (!audMatches) {
    throw new AuthError('invalid_jwt_aud', 'JWT audience (aud) does not match clientId.');
  }

  const nowSec = Math.floor(Date.now() / 1000);
  const tolerance = options.clockToleranceSec ?? 0;

  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
    throw new AuthError('invalid_jwt_exp', 'JWT is missing a valid expiration (exp) claim.');
  }
  if (nowSec >= payload.exp + tolerance) {
    throw new AuthError('token_expired', 'JWT has expired.');
  }

  if (payload.nbf !== undefined) {
    if (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf)) {
      throw new AuthError('invalid_jwt_nbf', 'JWT nbf claim is invalid.');
    }
    if (nowSec + Math.max(tolerance, 5) < payload.nbf) {
      throw new AuthError('token_not_active', 'JWT is not yet valid (nbf).');
    }
  }

  if (options.expectedNonce !== undefined) {
    if (typeof payload.nonce !== 'string' || payload.nonce !== options.expectedNonce) {
      throw new AuthError('invalid_jwt_nonce', 'JWT nonce does not match authorization request.');
    }
  }

  // Resolve matching JWK
  const requiredKty = expectedKtyForAlg(normalizedAlg);
  const findCandidateKeys = (keys: JwkKey[]): JwkKey[] =>
    keys.filter((k) => {
      if (k.kty !== requiredKty) return false;
      if (k.use && k.use !== 'sig') return false;
      if (k.alg && k.alg !== normalizedAlg) return false;
      if (header.kid) return k.kid === header.kid;
      return true;
    });

  let keys = await jwksCache.getKeys(options.jwksUri, false);
  let candidates = findCandidateKeys(keys);
  if (candidates.length === 0 && header.kid) {
    // Handle key rotation by refreshing JWKS once
    keys = await jwksCache.getKeys(options.jwksUri, true);
    candidates = findCandidateKeys(keys);
  }

  if (candidates.length === 0) {
    throw new AuthError('jwks_key_not_found', 'No matching verification key found in JWKS.');
  }

  const crypto = getWebCrypto();
  const signingBytes = new TextEncoder().encode(signingInput);

  for (const jwk of candidates) {
    try {
      const { importAlg, verifyAlg } = getImportAlgorithm(normalizedAlg, jwk);
      const cryptoKey = await crypto.subtle.importKey('jwk', jwk, importAlg, false, ['verify']);
      const verified = await crypto.subtle.verify(
        verifyAlg,
        cryptoKey,
        signature as BufferSource,
        signingBytes as BufferSource
      );
      if (verified) {
        return payload;
      }
    } catch {
      // Try remaining candidates if multiple keys matched without kid
    }
  }

  throw new AuthError('invalid_jwt_signature', 'JWT signature verification failed.');
}
