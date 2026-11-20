import {
  AuthConfig,
  AuthorizationStartResult,
  AuthorizeOptions,
  ButtonOptions,
  DeviceVaultKey,
  IdentifyResponse,
  OIDCDiscoveryDocument,
  RegisterResponse,
  StorageAdapter,
  TokenResponse,
  UserProfile,
  UserPublicKey,
  VaultRecord,
  Verify2FAResponse,
  VerifyPasswordResult,
  VerifyResponse,
} from './types';
import { AuthError, parseError } from './errors';
import { JWKSCache, isJwtShape, parseJwtUnverified, verifyJwt } from './jwt';
import {
  assertSafeUrl,
  deriveCodeChallengeS256,
  generateCodeVerifier,
  generateRandomToken,
  isBrowserRuntime,
} from './pkce';
import { getBrowserSessionStorage, getDefaultStorage } from './storage';
import { PasskeyClient } from './passkey';
import { SessionClient } from './session';
import { RecoveryClient } from './recovery';
import { DevicesClient } from './devices';
import { KMSClient, KMSOptions } from './kms';

const BUTTON_LABELS: Record<string, string> = {
  ar: 'تسجيل الدخول باستخدام OneUID',
  de: 'Mit OneUID anmelden',
  en: 'Sign in with OneUID',
  es: 'Iniciar sesión con OneUID',
  fr: 'Se connecter avec OneUID',
  it: 'Accedi con OneUID',
  ja: 'OneUIDでサインイン',
  ko: 'OneUID로 로그인',
  pt: 'Entrar com OneUID',
  ru: 'Войти через OneUID',
  th: 'เข้าสู่ระบบด้วย OneUID',
  vi: 'Đăng nhập bằng OneUID',
  'zh-hans': '使用 OneUID 登录',
  'zh-hant': '使用 OneUID 登入',
};

const REDIRECTING_LABELS: Record<string, string> = {
  ar: 'جارٍ التوجيه إلى OneUID...',
  de: 'Weiterleitung zu OneUID...',
  en: 'Redirecting to OneUID...',
  es: 'Redirigiendo a OneUID...',
  fr: 'Redirection vers OneUID...',
  it: 'Reindirizzamento a OneUID...',
  ja: 'OneUIDへリダイレクト中...',
  ko: 'OneUID로 이동 중...',
  pt: 'Redirecionando para OneUID...',
  ru: 'Перенаправление в OneUID...',
  th: 'กำลังนำทางไปยัง OneUID...',
  vi: 'Đang chuyển hướng đến OneUID...',
  'zh-hans': '正在跳转到 OneUID...',
  'zh-hant': '正在跳轉至 OneUID...',
};

const UNAVAILABLE_LABELS: Record<string, string> = {
  ar: 'تسجيل الدخول غير متاح حاليًا.',
  de: 'Anmeldung ist nicht verfügbar.',
  en: 'Sign-in is unavailable.',
  es: 'El inicio de sesión no está disponible.',
  fr: 'La connexion est indisponible.',
  it: 'Accesso non disponibile.',
  ja: 'サインインは現在利用できません。',
  ko: '로그인을 사용할 수 없습니다.',
  pt: 'O login está indisponível.',
  ru: 'Вход недоступен.',
  th: 'ไม่สามารถเข้าสู่ระบบได้ในขณะนี้',
  vi: 'Đăng nhập hiện không khả dụng.',
  'zh-hans': '登录暂不可用。',
  'zh-hant': '登入暫不可用。',
};

const RETRY_LABELS: Record<string, string> = {
  ar: 'إعادة المحاولة',
  de: 'Erneut versuchen',
  en: 'Retry',
  es: 'Reintentar',
  fr: 'Réessayer',
  it: 'Riprova',
  ja: '再試行',
  ko: '다시 시도',
  pt: 'Tentar novamente',
  ru: 'Повторить',
  th: 'ลองอีกครั้ง',
  vi: 'Thử lại',
  'zh-hans': '重试',
  'zh-hant': '重試',
};

const SHIELD_PATH =
  'M 256 24 L 444 101 C 458.5 107 468 121 468 137 V 248 C 468 370 378 449 256 488 C 134 449 44 370 44 248 V 137 C 44 121 53.5 107 68 101 L 256 24 Z M 256 142.0 C 285.8 142.0 310.0 166.2 310.0 196.0 C 310.0 216.9 298.1 235.0 282.24 243.2 L 289.37 334.6 C 289.37 353.0 274.4 368.0 256.0 368.0 C 237.6 368.0 222.63 353.0 222.63 334.6 L 229.76 243.2 C 213.9 235.0 202.0 216.9 202.0 196.0 C 202.0 166.2 226.2 142.0 256.0 142.0 Z';

const STYLE_ID = 'oneuid-sdk-styles';

const BUTTON_CSS = `
.oneuid-btn-wrap {
  display: inline-flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
  max-width: 100%;
}
.oneuid-btn {
  box-sizing: border-box;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 44px;
  min-width: 44px;
  max-width: 100%;
  border-radius: 10px;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-weight: 600;
  line-height: 1;
  letter-spacing: -0.01em;
  white-space: nowrap;
  cursor: pointer;
  user-select: none;
  -webkit-user-select: none;
  touch-action: manipulation;
  -webkit-tap-highlight-color: transparent;
  text-decoration: none;
  transition: background-color 150ms ease, border-color 150ms ease, transform 120ms cubic-bezier(0.23, 1, 0.32, 1), box-shadow 150ms ease;
}
.oneuid-btn:active:not(:disabled) {
  transform: scale(0.98);
}
.oneuid-btn:disabled {
  opacity: 0.72;
  cursor: not-allowed;
}
.oneuid-btn:focus-visible,
.oneuid-btn-retry:focus-visible {
  outline: 2px solid #2563EB;
  outline-offset: 2px;
}
.oneuid-btn--small {
  min-height: 44px;
  height: 44px;
  padding: 0 12px;
  font-size: 14px;
  gap: 8px;
}
.oneuid-btn--medium {
  min-height: 44px;
  height: 44px;
  padding: 0 16px;
  font-size: 14px;
  gap: 10px;
}
.oneuid-btn--large {
  min-height: 44px;
  height: 48px;
  padding: 0 20px;
  font-size: 15px;
  gap: 10px;
}
.oneuid-btn--brand {
  background-color: #2563EB;
  color: #FFFFFF;
  border: 1px solid #2563EB;
  box-shadow: 0 1px 2px rgba(11, 18, 32, 0.12);
}
.oneuid-btn--brand:hover:not(:disabled) {
  background-color: #1D4ED8;
  border-color: #1D4ED8;
}
.oneuid-btn--dark {
  background-color: #0B1220;
  color: #F8FAFC;
  border: 1px solid rgba(255, 255, 255, 0.14);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.24);
}
.oneuid-btn--dark:hover:not(:disabled) {
  background-color: #111827;
  border-color: rgba(255, 255, 255, 0.22);
}
.oneuid-btn--light {
  background-color: #FFFFFF;
  color: #0F172A;
  border: 1px solid #E2E8F0;
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
}
.oneuid-btn--light:hover:not(:disabled) {
  background-color: #F8FAFC;
  border-color: #CBD5E1;
}
.oneuid-btn-error {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 13px;
  color: #DC2626;
}
.oneuid-btn-retry {
  display: inline-flex;
  align-items: center;
  min-height: 44px;
  min-width: 44px;
  padding: 0 6px;
  background: transparent;
  border: none;
  color: #2563EB;
  font-family: inherit;
  font-size: 13px;
  font-weight: 600;
  text-decoration: underline;
  cursor: pointer;
}
.oneuid-spinner {
  display: inline-block;
  width: 14px;
  height: 14px;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 9999px;
  animation: oneuid-spin 0.7s linear infinite;
}
@keyframes oneuid-spin {
  to { transform: rotate(360deg); }
}
@media (prefers-reduced-motion: reduce) {
  .oneuid-btn {
    transition: background-color 150ms ease, border-color 150ms ease, box-shadow 150ms ease;
  }
  .oneuid-btn:active:not(:disabled) {
    transform: none;
  }
  .oneuid-spinner {
    animation: none;
  }
}
`;

const AUTH_TX_TTL_MS = 15 * 60 * 1000;
const REFRESH_SKEW_SEC = 30;

let browserSecretWarned = false;

interface StoredAuthTransaction {
  state: string;
  codeVerifier: string;
  nonce: string;
  redirectUri: string;
  createdAt: number;
}

function resolveLocale(locale?: string): string {
  const raw = (
    locale ||
    (typeof document !== 'undefined' ? document.documentElement?.lang : '') ||
    (typeof navigator !== 'undefined' ? navigator.language : '') ||
    'en'
  )
    .trim()
    .toLowerCase()
    .replace(/_/g, '-');

  if (!raw) return 'en';
  if (BUTTON_LABELS[raw]) return raw;

  if (raw.startsWith('zh')) {
    if (raw.includes('hant') || raw.includes('tw') || raw.includes('hk') || raw.includes('mo')) {
      return 'zh-hant';
    }
    return 'zh-hans';
  }

  const base = raw.split('-')[0];
  return BUTTON_LABELS[base] ? base : 'en';
}

function isTokenResponseObject(value: unknown): value is TokenResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const obj = value as Record<string, unknown>;
  return typeof obj.access_token === 'string' && obj.access_token.trim().length > 0;
}

export class OneUID {
  private config: AuthConfig;
  private storage: StorageAdapter;
  private txStorage: StorageAdapter;
  private jwksCache = new JWKSCache();
  private discoveryPromise: Promise<OIDCDiscoveryDocument> | null = null;
  private cachedDiscovery: OIDCDiscoveryDocument | null = null;
  private pendingAuthTx = new Map<string, StoredAuthTransaction>();
  private inflightRefresh: Promise<TokenResponse> | null = null;

  private readonly TOKEN_KEY: string;
  private readonly REFRESH_KEY: string;
  private readonly ID_TOKEN_KEY: string;
  private readonly EXPIRES_AT_KEY: string;
  private readonly AUTH_TX_PREFIX: string;

  public passkey: PasskeyClient;
  public session: SessionClient;
  public recovery: RecoveryClient;
  public devices: DevicesClient;
  public kms?: KMSClient;

  constructor(config: AuthConfig, storage?: StorageAdapter) {
    if (!config || typeof config.clientId !== 'string' || !config.clientId.trim()) {
      throw new AuthError('invalid_config', 'AuthConfig.clientId is required.');
    }

    const safeBase = assertSafeUrl(config.baseURL, 'baseURL');
    const normalizedBaseURL = safeBase.toString().replace(/\/$/, '');

    if (config.issuer) {
      assertSafeUrl(config.issuer, 'issuer');
    }
    if (config.jwksUri) {
      assertSafeUrl(config.jwksUri, 'jwksUri');
    }

    const inBrowser = isBrowserRuntime();
    let clientSecret = config.clientSecret;
    if (inBrowser && clientSecret) {
      clientSecret = undefined;
      if (!browserSecretWarned) {
        browserSecretWarned = true;
        console.warn('[OneUID] clientSecret is forbidden in browser runtimes and has been ignored.');
      }
    }

    this.config = {
      ...config,
      clientId: config.clientId.trim(),
      baseURL: normalizedBaseURL,
      clientSecret,
      allowUnsafePasswordGrant: inBrowser ? false : Boolean(config.allowUnsafePasswordGrant),
    };

    this.storage = storage || config.storage || getDefaultStorage();
    this.txStorage = getBrowserSessionStorage() || this.storage;

    const ns = `oneuid:${this.config.clientId}`;
    this.TOKEN_KEY = `${ns}:access_token`;
    this.REFRESH_KEY = `${ns}:refresh_token`;
    this.ID_TOKEN_KEY = `${ns}:id_token`;
    this.EXPIRES_AT_KEY = `${ns}:expires_at`;
    this.AUTH_TX_PREFIX = `${ns}:auth_tx:`;

    this.passkey = new PasskeyClient(this.config, this);
    this.session = new SessionClient(this.config, this);
    this.recovery = new RecoveryClient(this.config, this);
    this.devices = new DevicesClient(this.config, this);

    this.injectNativeMetaTag();
  }

  /**
   * Explicitly initializes KMS envelope encryption.
   * Must be called with an explicit `kekB64` on the server or a non-env `keyProvider`.
   */
  public initKMS(options: KMSOptions = {}): KMSClient {
    this.kms = new KMSClient(this.config, this, options);
    return this.kms;
  }

  private injectNativeMetaTag() {
    if (typeof document !== 'undefined' && typeof document.querySelector === 'function' && document.head) {
      const existing = document.querySelector('meta[name="uid-passkey-native"]');
      if (!existing) {
        const meta = document.createElement('meta');
        meta.name = 'uid-passkey-native';
        meta.content = 'true';
        document.head.appendChild(meta);
      }
    }
  }

  private injectStyles() {
    if (typeof document === 'undefined' || !document.head) return;
    if (document.getElementById(STYLE_ID)) return;
    const style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = BUTTON_CSS;
    document.head.appendChild(style);
  }

  private getFallbackDiscovery(): OIDCDiscoveryDocument {
    const base = this.config.baseURL;
    return {
      issuer: this.config.issuer ? this.config.issuer.replace(/\/$/, '') : base,
      authorization_endpoint: `${base}/oauth/authorize`,
      token_endpoint: `${base}/oauth/token`,
      jwks_uri: this.config.jwksUri || `${base}/oauth/certs`,
      revocation_endpoint: `${base}/oauth/revoke`,
      userinfo_endpoint: `${base}/oauth/userinfo`,
      code_challenge_methods_supported: ['S256'],
    };
  }

  /**
   * Fetches and caches OIDC discovery metadata from `/.well-known/openid-configuration`.
   */
  async discover(forceRefresh: boolean = false): Promise<OIDCDiscoveryDocument> {
    if (this.cachedDiscovery && !forceRefresh) {
      return this.cachedDiscovery;
    }
    if (this.discoveryPromise && !forceRefresh) {
      return this.discoveryPromise;
    }

    const promise = (async (): Promise<OIDCDiscoveryDocument> => {
      const fallback = this.getFallbackDiscovery();
      try {
        const res = await fetch(`${this.config.baseURL}/.well-known/openid-configuration`, {
          method: 'GET',
          headers: { Accept: 'application/json' },
        });
        if (!res.ok) {
          this.cachedDiscovery = fallback;
          return fallback;
        }
        const doc = (await res.json()) as Partial<OIDCDiscoveryDocument>;
        const safeEndpoint = (url: unknown, def: string) => {
          if (typeof url === 'string' && url.trim()) {
            return assertSafeUrl(url, 'discovery endpoint').toString();
          }
          return def;
        };

        const resolved: OIDCDiscoveryDocument = {
          issuer: this.config.issuer
            ? this.config.issuer.replace(/\/$/, '')
            : typeof doc.issuer === 'string' && doc.issuer.trim()
              ? assertSafeUrl(doc.issuer, 'discovery issuer').toString().replace(/\/$/, '')
              : fallback.issuer,
          authorization_endpoint: safeEndpoint(doc.authorization_endpoint, fallback.authorization_endpoint),
          token_endpoint: safeEndpoint(doc.token_endpoint, fallback.token_endpoint),
          jwks_uri: this.config.jwksUri || safeEndpoint(doc.jwks_uri, fallback.jwks_uri),
          revocation_endpoint: safeEndpoint(doc.revocation_endpoint, fallback.revocation_endpoint || `${this.config.baseURL}/oauth/revoke`),
          userinfo_endpoint: safeEndpoint(doc.userinfo_endpoint, fallback.userinfo_endpoint || `${this.config.baseURL}/oauth/userinfo`),
          code_challenge_methods_supported: Array.isArray(doc.code_challenge_methods_supported)
            ? doc.code_challenge_methods_supported
            : fallback.code_challenge_methods_supported,
        };
        this.cachedDiscovery = resolved;
        return resolved;
      } catch {
        this.cachedDiscovery = fallback;
        return fallback;
      }
    })();

    this.discoveryPromise = promise;
    try {
      return await promise;
    } finally {
      if (this.discoveryPromise === promise) {
        this.discoveryPromise = null;
      }
    }
  }

  private getExpectedIssuers(discovery: OIDCDiscoveryDocument, flow: 'oidc' | 'first_party'): string[] {
    if (this.config.issuer) {
      return [this.config.issuer.replace(/\/$/, '')];
    }
    const issuers = new Set<string>([discovery.issuer.replace(/\/$/, '')]);
    if (flow === 'first_party') {
      issuers.add(this.config.baseURL);
      if (discovery.issuer.replace(/\/$/, '') === 'https://auth.uid.one') {
        issuers.add('https://api.uid.one');
      }
    }
    return Array.from(issuers);
  }

  private getServerClientSecret(): string | undefined {
    if (isBrowserRuntime()) {
      return undefined;
    }
    return this.config.clientSecret;
  }

  /**
   * Starts an Authorization Code + PKCE S256 flow with random state and nonce.
   */
  async startAuthorization(redirectUri: string, options: AuthorizeOptions = {}): Promise<AuthorizationStartResult> {
    const safeRedirect = assertSafeUrl(redirectUri, 'redirectUri').toString();

    if ((options as Record<string, unknown>).codeChallengeMethod === 'plain') {
      throw new AuthError('unsupported_pkce_method', 'Plain PKCE is not supported; S256 is required.');
    }
    if ((options as Record<string, unknown>).responseType && (options as Record<string, unknown>).responseType !== 'code') {
      throw new AuthError('unsupported_response_type', 'Only authorization code flow (response_type=code) is supported.');
    }

    const discovery = await this.discover();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await deriveCodeChallengeS256(codeVerifier);
    const state = options.state && options.state.trim().length >= 16 ? options.state.trim() : generateRandomToken(32);
    const nonce = options.nonce && options.nonce.trim().length >= 16 ? options.nonce.trim() : generateRandomToken(32);

    const tx: StoredAuthTransaction = {
      state,
      codeVerifier,
      nonce,
      redirectUri: safeRedirect,
      createdAt: Date.now(),
    };
    this.pendingAuthTx.set(state, tx);
    await this.txStorage.setItem(`${this.AUTH_TX_PREFIX}${state}`, JSON.stringify(tx));

    const authUrl = new URL(discovery.authorization_endpoint);
    authUrl.searchParams.set('client_id', this.config.clientId);
    authUrl.searchParams.set('redirect_uri', safeRedirect);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', options.scope || 'openid profile email');
    authUrl.searchParams.set('code_challenge', codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('state', state);
    authUrl.searchParams.set('nonce', nonce);
    if (options.prompt) {
      authUrl.searchParams.set('prompt', options.prompt);
    }

    return {
      url: authUrl.toString(),
      state,
      nonce,
      codeChallenge,
    };
  }

  /**
   * Handles the OAuth redirect callback, verifies state (CSRF protection),
   * and exchanges the authorization code using the stored PKCE code_verifier.
   */
  async handleRedirectCallback(callbackUrl?: string): Promise<TokenResponse> {
    const rawUrl =
      callbackUrl ||
      (typeof window !== 'undefined' && window.location ? window.location.href : '');
    if (!rawUrl) {
      throw new AuthError('invalid_callback', 'Callback URL is required.');
    }

    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      throw new AuthError('invalid_callback', 'Malformed callback URL.');
    }

    const errorParam = parsed.searchParams.get('error');
    if (errorParam) {
      const desc = parsed.searchParams.get('error_description') || errorParam;
      throw new AuthError('oauth_error', parseError({ error: desc }, 'Authorization failed.'));
    }

    const code = parsed.searchParams.get('code');
    const state = parsed.searchParams.get('state');
    if (!code || !state) {
      throw new AuthError('invalid_callback', 'Callback URL is missing required code or state parameter.');
    }

    const txKey = `${this.AUTH_TX_PREFIX}${state}`;
    let tx = this.pendingAuthTx.get(state) || null;
    this.pendingAuthTx.delete(state);

    const rawStored = await this.txStorage.getItem(txKey);
    await this.txStorage.removeItem(txKey);

    if (!tx && rawStored) {
      try {
        tx = JSON.parse(rawStored) as StoredAuthTransaction;
      } catch {
        tx = null;
      }
    }

    if (!tx || tx.state !== state || !tx.codeVerifier || !tx.redirectUri) {
      throw new AuthError('state_mismatch', 'Invalid or missing OAuth state; refusing code exchange.');
    }

    if (Date.now() - tx.createdAt > AUTH_TX_TTL_MS) {
      throw new AuthError('state_expired', 'Authorization transaction expired.');
    }

    return this.loginWithCode(code, tx.redirectUri, {
      codeVerifier: tx.codeVerifier,
      expectedNonce: tx.nonce,
    });
  }

  /**
   * @deprecated Use `loginWithPassword` only if explicitly enabled on a confidential server.
   * For user-facing apps, use `startAuthorization()` (PKCE) or `verifyPassword()` + `verify2FA()`.
   * Fails closed when 2FA is required or when `allowUnsafePasswordGrant` is not enabled.
   */
  async loginWithPassword(username: string, password: string): Promise<TokenResponse> {
    if (isBrowserRuntime() || !this.config.allowUnsafePasswordGrant) {
      throw new AuthError(
        'password_grant_disabled',
        'Direct password grant is disabled because it bypasses 2FA. Use startAuthorization() (PKCE) or verifyPassword() + verify2FA().'
      );
    }

    // Even when server escape hatch is enabled, enforce 2FA verification gate first
    const step1 = await this.verifyPassword(username, password);
    if (step1.status === 'PENDING_2FA' || step1.status === 'SETUP_REQUIRED') {
      throw new AuthError(
        'two_factor_required',
        'Account requires two-factor authentication. Complete login via verify2FA().',
        403
      );
    }

    const discovery = await this.discover();
    const formData = new URLSearchParams();
    formData.append('grant_type', 'password');
    formData.append('username', username);
    formData.append('password', password);
    formData.append('client_id', this.config.clientId);
    formData.append('scope', 'openid profile email');

    const secret = this.getServerClientSecret();
    if (secret) {
      formData.append('client_secret', secret);
    }

    const response = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError('login_failed', parseError(errorData, `Login failed (${response.status}).`), response.status);
    }

    const data: TokenResponse = await response.json();
    await this.persistTokens(data, { flow: 'oidc' });
    return data;
  }

  /**
   * Exchanges an OIDC authorization code for tokens.
   * Requires `codeVerifier` for public clients (PKCE S256).
   */
  async loginWithCode(
    code: string,
    redirectUri: string,
    codeVerifierOrOptions?: string | { codeVerifier?: string; expectedNonce?: string }
  ): Promise<TokenResponse> {
    if (!code || typeof code !== 'string') {
      throw new AuthError('invalid_code', 'Authorization code is required.');
    }
    const safeRedirect = assertSafeUrl(redirectUri, 'redirectUri').toString();

    const opts =
      typeof codeVerifierOrOptions === 'string'
        ? { codeVerifier: codeVerifierOrOptions }
        : codeVerifierOrOptions || {};

    const serverSecret = this.getServerClientSecret();
    if (!serverSecret && (!opts.codeVerifier || !opts.codeVerifier.trim())) {
      throw new AuthError(
        'missing_code_verifier',
        'PKCE code_verifier is required for public-client authorization code exchange.'
      );
    }

    const discovery = await this.discover();
    const formData = new URLSearchParams();
    formData.append('grant_type', 'authorization_code');
    formData.append('code', code);
    formData.append('redirect_uri', safeRedirect);
    formData.append('client_id', this.config.clientId);
    if (opts.codeVerifier) {
      formData.append('code_verifier', opts.codeVerifier.trim());
    }
    if (serverSecret) {
      formData.append('client_secret', serverSecret);
    }

    const response = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'code_exchange_failed',
        parseError(errorData, `Code exchange failed (${response.status}).`),
        response.status
      );
    }

    const data: TokenResponse = await response.json();
    await this.persistTokens(data, { flow: 'oidc', expectedNonce: opts.expectedNonce });
    return data;
  }

  /**
   * Step 1 of password login with 2FA support. Does not persist tokens.
   */
  async verifyPassword(email: string, password: string): Promise<VerifyPasswordResult> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/verify-password/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password,
        client_id: this.config.clientId,
      }),
    });

    const data = await response.json().catch(() => ({}));
    if (response.status === 403 && data && data.status === 'SETUP_REQUIRED') {
      return data as VerifyPasswordResult;
    }

    if (!response.ok) {
      throw new AuthError(
        'verify_password_failed',
        parseError(data, `Password verification failed (${response.status}).`),
        response.status
      );
    }

    return data as VerifyPasswordResult;
  }

  /**
   * Step 2 of password login with 2FA support.
   * Persists tokens only when a valid `TokenResponse` (with `access_token`) is returned and verified.
   */
  async verify2FA(params: {
    session_token: string;
    method: 'totp' | 'passkey' | 'backup_code';
    code?: string;
    assertion?: unknown;
  }): Promise<Verify2FAResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/verify-2fa/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...params,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'verify_2fa_failed',
        parseError(errorData, `2FA verification failed (${response.status}).`),
        response.status
      );
    }

    const data = (await response.json()) as Verify2FAResponse;
    const tokenPayload = isTokenResponseObject(data)
      ? data
      : isTokenResponseObject(data?.token)
        ? data.token
        : null;

    if (tokenPayload) {
      await this.persistTokens(tokenPayload, { flow: 'first_party' });
    }

    return data;
  }

  /**
   * Exchanges a provider authorization code (or server-verified OIDC id_token with nonce)
   * for a OneUID session. Never sends `client_secret` from the client.
   */
  async loginWithProvider(
    provider: string,
    tokenOrCode: string,
    options?: { nonce?: string; codeVerifier?: string; redirectUri?: string }
  ): Promise<TokenResponse> {
    const body: Record<string, unknown> = {
      provider,
      token: tokenOrCode,
      client_id: this.config.clientId,
    };
    if (options?.nonce) body.nonce = options.nonce;
    if (options?.codeVerifier) body.code_verifier = options.codeVerifier;
    if (options?.redirectUri) {
      body.redirect_uri = assertSafeUrl(options.redirectUri, 'redirectUri').toString();
    }

    const response = await fetch(`${this.config.baseURL}/v1/auth/social-login/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'social_login_failed',
        parseError(errorData, `Social login failed (${response.status}).`),
        response.status
      );
    }

    const data: TokenResponse = await response.json();
    await this.persistTokens(data, { flow: 'first_party' });
    return data;
  }

  /**
   * Identifies an email address and determines the authentication flow.
   * Note: This endpoint can reveal account existence and configured MFA factors;
   * enforce server-side and edge rate limiting. Never persists session tokens.
   */
  async identify(email: string): Promise<IdentifyResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/identify/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'identify_failed',
        parseError(errorData, `Identify failed (${response.status}).`),
        response.status
      );
    }

    return (await response.json()) as IdentifyResponse;
  }

  /**
   * Verifies the 6-digit numeric passcode sent via email.
   */
  async verifyPasscode(email: string, code: string, purpose: 'register' | 'login' = 'register'): Promise<VerifyResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/verify-passcode/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        code,
        purpose,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'verify_passcode_failed',
        parseError(errorData, `Passcode verification failed (${response.status}).`),
        response.status
      );
    }

    const data: VerifyResponse = await response.json();
    await this.persistTokens(data, { flow: 'first_party' });
    return data;
  }

  /**
   * Verifies the one-time cryptographic nonce token from a login link.
   */
  async verifyNonce(token: string): Promise<VerifyResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/verify-nonce/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'verify_nonce_failed',
        parseError(errorData, `Nonce verification failed (${response.status}).`),
        response.status
      );
    }

    const data: VerifyResponse = await response.json();
    await this.persistTokens(data, { flow: 'first_party' });
    return data;
  }

  /**
   * Verifies a WebAuthn assertion for biometric login.
   */
  async verifyWebAuthn(userId: string, assertion: unknown): Promise<VerifyResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/verify-webauthn/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: userId,
        assertion,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'verify_webauthn_failed',
        parseError(errorData, `WebAuthn verification failed (${response.status}).`),
        response.status
      );
    }

    const data: VerifyResponse = await response.json();
    await this.persistTokens(data, { flow: 'first_party' });
    return data;
  }

  /**
   * Creates an unverified account. Does not establish a session or persist tokens;
   * callers must complete email/passcode verification before signing in.
   */
  async register(email: string, password: string, recaptcha?: string): Promise<RegisterResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/register/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password,
        recaptcha,
        client_id: this.config.clientId,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'registration_failed',
        parseError(errorData, `Registration failed (${response.status}).`),
        response.status
      );
    }

    const raw = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    return {
      user_id: typeof raw.user_id === 'string' ? raw.user_id : undefined,
      email: typeof raw.email === 'string' ? raw.email : email,
      verification_required: true,
      message: typeof raw.message === 'string' ? raw.message : 'Account created. Verification is required before signing in.',
    };
  }

  /**
   * Refreshes the access token using a refresh token.
   */
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    if (!refreshToken || typeof refreshToken !== 'string') {
      throw new AuthError('invalid_refresh_token', 'Refresh token is required.');
    }

    const discovery = await this.discover();
    const formData = new URLSearchParams();
    formData.append('grant_type', 'refresh_token');
    formData.append('refresh_token', refreshToken);
    formData.append('client_id', this.config.clientId);
    formData.append('scope', 'openid profile email');

    const secret = this.getServerClientSecret();
    if (secret) {
      formData.append('client_secret', secret);
    }

    const response = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'refresh_failed',
        parseError(errorData, `Token refresh failed (${response.status}).`),
        response.status
      );
    }

    const data: TokenResponse = await response.json();
    await this.persistTokens(data, { flow: 'oidc' });
    return data;
  }

  /**
   * Revokes both refresh and access tokens at the OIDC revocation endpoint and clears local storage.
   */
  async logout(): Promise<void> {
    const [accessToken, refreshToken] = await Promise.all([
      this.storage.getItem(this.TOKEN_KEY),
      this.storage.getItem(this.REFRESH_KEY),
    ]);

    if (accessToken || refreshToken) {
      const discovery = await this.discover().catch(() => this.getFallbackDiscovery());
      const revokeUrl = discovery.revocation_endpoint || `${this.config.baseURL}/oauth/revoke`;
      const secret = this.getServerClientSecret();

      const revokeOne = async (token: string, hint: 'refresh_token' | 'access_token') => {
        const formData = new URLSearchParams();
        formData.append('token', token);
        formData.append('token_type_hint', hint);
        formData.append('client_id', this.config.clientId);
        if (secret) {
          formData.append('client_secret', secret);
        }
        await fetch(revokeUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString(),
        }).catch(() => {
          /* Ignore network errors on logout */
        });
      };

      const tasks: Promise<void>[] = [];
      if (refreshToken) {
        tasks.push(revokeOne(refreshToken, 'refresh_token'));
      }
      if (accessToken) {
        tasks.push(revokeOne(accessToken, 'access_token'));
      }
      await Promise.allSettled(tasks);
    }

    await this.clearTokens();
  }

  async getProfile(): Promise<UserProfile> {
    const token = await this.getAccessToken();
    if (!token) throw new AuthError('unauthenticated', 'Not authenticated.');

    const response = await fetch(`${this.config.baseURL}/v1/auth/me/`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'profile_fetch_failed',
        parseError(errorData, `Failed to fetch profile (${response.status}).`),
        response.status
      );
    }

    return response.json();
  }

  /**
   * Disconnects the user from this application by revoking active tokens.
   */
  async disconnect(): Promise<void> {
    await this.logout();
  }

  /**
   * Revokes active sessions across Relying Parties via POST /v1/auth/revoke/.
   */
  async revoke(options: { applicationId?: string; reason?: string; includeCurrent?: boolean } = {}) {
    return this.session.revoke(options);
  }

  /**
   * Returns a valid access token, automatically refreshing via refresh_token if expired or near expiry.
   * Clears the session and returns null if expired and refresh fails or is unavailable.
   */
  async getAccessToken(): Promise<string | null> {
    const token = await this.storage.getItem(this.TOKEN_KEY);
    if (!token) return null;

    const nowSec = Math.floor(Date.now() / 1000);
    let expiresAt: number | null = null;

    const storedExp = await this.storage.getItem(this.EXPIRES_AT_KEY);
    if (storedExp) {
      const parsed = Number(storedExp);
      if (Number.isFinite(parsed)) {
        expiresAt = parsed;
      }
    }

    if (isJwtShape(token)) {
      try {
        const { payload } = parseJwtUnverified(token);
        if (typeof payload.exp === 'number' && Number.isFinite(payload.exp)) {
          expiresAt = expiresAt !== null ? Math.min(expiresAt, payload.exp) : payload.exp;
        }
      } catch {
        await this.clearTokens();
        return null;
      }
    }

    if (expiresAt !== null && nowSec >= expiresAt - REFRESH_SKEW_SEC) {
      const storedRefresh = await this.storage.getItem(this.REFRESH_KEY);
      if (!storedRefresh) {
        await this.clearTokens();
        return null;
      }

      try {
        if (!this.inflightRefresh) {
          this.inflightRefresh = this.refreshToken(storedRefresh);
        }
        const refreshed = await this.inflightRefresh;
        return refreshed.access_token;
      } catch {
        await this.clearTokens();
        return null;
      } finally {
        this.inflightRefresh = null;
      }
    }

    return token;
  }

  /**
   * Verifies JWT signatures & claims (iss, aud, exp, nbf, nonce, asymmetric alg) against JWKS
   * before persisting tokens to the configured StorageAdapter.
   */
  public async persistTokens(
    data: TokenResponse,
    options: { flow?: 'oidc' | 'first_party'; expectedNonce?: string } = {}
  ): Promise<void> {
    if (!isTokenResponseObject(data)) {
      throw new AuthError('invalid_token_response', 'Token response is missing a valid access_token.');
    }

    const discovery = await this.discover();
    const expectedIssuers = this.getExpectedIssuers(discovery, options.flow || 'oidc');

    let verifiedAccessExp: number | undefined;
    let verifiedIdExp: number | undefined;

    if (options.expectedNonce && !data.id_token) {
      throw new AuthError('missing_id_token', 'ID token is required to verify authorization nonce.');
    }

    if (data.id_token) {
      const idClaims = await verifyJwt(data.id_token, this.jwksCache, {
        jwksUri: discovery.jwks_uri,
        expectedIssuers,
        expectedAudience: this.config.clientId,
        expectedNonce: options.expectedNonce,
        clockToleranceSec: this.config.clockToleranceSec,
      });
      if (typeof idClaims.exp === 'number') {
        verifiedIdExp = idClaims.exp;
      }
    }

    if (isJwtShape(data.access_token)) {
      const accessClaims = await verifyJwt(data.access_token, this.jwksCache, {
        jwksUri: discovery.jwks_uri,
        expectedIssuers,
        expectedAudience: this.config.clientId,
        clockToleranceSec: this.config.clockToleranceSec,
      });
      if (typeof accessClaims.exp === 'number') {
        verifiedAccessExp = accessClaims.exp;
      }
    }

    const nowSec = Math.floor(Date.now() / 1000);
    const expiresAt =
      verifiedAccessExp ??
      verifiedIdExp ??
      (typeof data.expires_in === 'number' && data.expires_in > 0 ? nowSec + Math.floor(data.expires_in) : nowSec + 3600);

    await this.storage.setItem(this.TOKEN_KEY, data.access_token);
    await this.storage.setItem(this.EXPIRES_AT_KEY, String(expiresAt));
    if (data.refresh_token) {
      await this.storage.setItem(this.REFRESH_KEY, data.refresh_token);
    }
    if (data.id_token) {
      await this.storage.setItem(this.ID_TOKEN_KEY, data.id_token);
    }
  }

  public async clearTokens(): Promise<void> {
    await Promise.all([
      this.storage.removeItem(this.TOKEN_KEY),
      this.storage.removeItem(this.REFRESH_KEY),
      this.storage.removeItem(this.ID_TOKEN_KEY),
      this.storage.removeItem(this.EXPIRES_AT_KEY),
    ]);
  }

  /**
   * Builds an OIDC authorization code + PKCE S256 URL synchronously when the caller
   * manages PKCE parameters. Prefer `startAuthorization()` for automatic verifier/state/nonce handling.
   */
  getAuthorizeUrl(
    redirectUri: string,
    options: { codeChallenge: string; codeChallengeMethod?: 'S256'; state: string; nonce: string; scope?: string }
  ): string {
    const safeRedirect = assertSafeUrl(redirectUri, 'redirectUri').toString();
    if (!options || !options.codeChallenge || !options.state || !options.nonce) {
      throw new AuthError(
        'missing_pkce_params',
        'codeChallenge (S256), state, and nonce are required. Prefer startAuthorization().'
      );
    }
    if ((options as Record<string, unknown>).codeChallengeMethod === 'plain') {
      throw new AuthError('unsupported_pkce_method', 'Plain PKCE is not supported; S256 is required.');
    }

    const authEndpoint = this.cachedDiscovery?.authorization_endpoint || `${this.config.baseURL}/oauth/authorize`;
    const authUrl = new URL(authEndpoint);
    authUrl.searchParams.set('client_id', this.config.clientId);
    authUrl.searchParams.set('redirect_uri', safeRedirect);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', options.scope || 'openid profile email');
    authUrl.searchParams.set('code_challenge', options.codeChallenge);
    authUrl.searchParams.set('code_challenge_method', 'S256');
    authUrl.searchParams.set('state', options.state);
    authUrl.searchParams.set('nonce', options.nonce);
    return authUrl.toString();
  }

  /**
   * @deprecated Social redirect views have been permanently removed.
   */
  getSocialRedirectUrl(_provider: 'google' | 'facebook' | 'apple', _redirectUri: string): never {
    throw new AuthError(
      'deprecated_method',
      'getSocialRedirectUrl has been removed. Use authorization-code + PKCE with loginWithProvider().'
    );
  }

  /**
   * Renders a Cryptographic Minimal OneUID sign-in button inside a DOM container.
   * Uses authorization code + PKCE S256 (`startAuthorization`) with >=44px hit targets,
   * loading state, and inline retryable error feedback.
   */
  renderButton(containerId: string, options: ButtonOptions) {
    if (typeof document === 'undefined') return;
    const container = document.getElementById(containerId);
    if (!container) {
      console.warn(`[OneUID] Container #${containerId} not found.`);
      return;
    }

    this.injectStyles();

    const {
      provider = 'uid',
      redirectUri,
      theme = 'dark',
      size = 'medium',
      locale,
      label: custom,
      scope,
      onProviderClick,
    } = options;

    const lang = resolveLocale(locale);
    const isRtl = lang === 'ar';
    const tone = theme === 'light' || theme === 'brand' ? theme : 'dark';
    const scale = size === 'small' || size === 'large' ? size : 'medium';
    const iconPx = scale === 'small' ? 16 : scale === 'large' ? 20 : 18;

    const wrapper = document.createElement('div');
    wrapper.className = 'oneuid-btn-wrap';
    if (isRtl) {
      wrapper.dir = 'rtl';
    }

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `oneuid-btn oneuid-btn--${tone} oneuid-btn--${scale}`;
    btn.lang = lang;
    if (isRtl) {
      btn.dir = 'rtl';
    }

    let iconSvg = '';
    let defaultText = BUTTON_LABELS[lang] || BUTTON_LABELS.en;

    if (provider === 'google') {
      iconSvg = `<svg width="${iconPx}" height="${iconPx}" viewBox="0 0 24 24" aria-hidden="true" focusable="false" style="flex-shrink:0" xmlns="http://www.w3.org/2000/svg"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>`;
      defaultText = 'Sign in with Google';
    } else if (provider === 'facebook') {
      const fbFill = tone === 'brand' ? '#FFFFFF' : '#1877F2';
      iconSvg = `<svg width="${iconPx}" height="${iconPx}" viewBox="0 0 24 24" fill="${fbFill}" aria-hidden="true" focusable="false" style="flex-shrink:0" xmlns="http://www.w3.org/2000/svg"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.469h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.469h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>`;
      defaultText = 'Sign in with Facebook';
    } else if (provider === 'apple') {
      const fill = tone === 'light' ? '#0F172A' : '#FFFFFF';
      iconSvg = `<svg width="${iconPx}" height="${iconPx}" viewBox="0 0 24 24" fill="${fill}" aria-hidden="true" focusable="false" style="flex-shrink:0" xmlns="http://www.w3.org/2000/svg"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-.1.77-1.07 1.25-.8 2.63-.73 3.58-.29.39.17 1.5.54 2.21 1.58-.57.35-1.71 1.01-1.71 2.37 0 1.63 1.33 2.2 1.34 2.2-.01.04-.21.72-.71 1.45zM15.97 4.17c.6-1.03.37-2.35-.33-3.17-.68-.8-1.92-1.05-3-.33-.66.69-.4 2.02.26 2.82.68.79 1.99.78 3.07-.32z"/></svg>`;
      defaultText = 'Sign in with Apple';
    } else {
      const fill = tone === 'brand' ? '#FFFFFF' : '#2563EB';
      iconSvg = `<svg width="${iconPx}" height="${iconPx}" viewBox="0 0 512 512" fill="none" aria-hidden="true" focusable="false" style="flex-shrink:0" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" fill="${fill}" d="${SHIELD_PATH}"/></svg>`;
    }

    const visibleLabel = custom !== undefined ? custom.trim() : defaultText;
    if (!visibleLabel) {
      btn.setAttribute('aria-label', defaultText);
    }

    const iconWrap = document.createElement('span');
    iconWrap.style.cssText = 'display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;';
    iconWrap.innerHTML = iconSvg;

    const labelEl = document.createElement('span');
    labelEl.textContent = visibleLabel;

    btn.appendChild(iconWrap);
    if (visibleLabel) {
      btn.appendChild(labelEl);
    }

    const errorEl = document.createElement('div');
    errorEl.className = 'oneuid-btn-error';
    errorEl.setAttribute('role', 'alert');
    errorEl.style.display = 'none';

    const errorTextEl = document.createElement('span');
    errorTextEl.textContent = UNAVAILABLE_LABELS[lang] || UNAVAILABLE_LABELS.en;

    const retryBtn = document.createElement('button');
    retryBtn.type = 'button';
    retryBtn.className = 'oneuid-btn-retry';
    retryBtn.textContent = RETRY_LABELS[lang] || RETRY_LABELS.en;

    errorEl.appendChild(errorTextEl);
    errorEl.appendChild(retryBtn);

    let inFlight = false;

    const setIdleState = () => {
      inFlight = false;
      btn.disabled = false;
      btn.removeAttribute('aria-busy');
      iconWrap.innerHTML = iconSvg;
      labelEl.textContent = visibleLabel;
    };

    const setLoadingState = (loadingText: string) => {
      inFlight = true;
      btn.disabled = true;
      btn.setAttribute('aria-busy', 'true');
      errorEl.style.display = 'none';
      iconWrap.innerHTML = '<span class="oneuid-spinner" aria-hidden="true"></span>';
      labelEl.textContent = loadingText;
      if (!labelEl.parentNode) {
        btn.appendChild(labelEl);
      }
    };

    const showInlineError = () => {
      setIdleState();
      if (!visibleLabel && labelEl.parentNode) {
        btn.removeChild(labelEl);
      }
      errorTextEl.textContent = UNAVAILABLE_LABELS[lang] || UNAVAILABLE_LABELS.en;
      errorEl.style.display = 'flex';
    };

    const executeAction = async () => {
      if (inFlight) return;

      if (provider === 'uid') {
        setLoadingState(REDIRECTING_LABELS[lang] || REDIRECTING_LABELS.en);
        try {
          const { url } = await this.startAuthorization(redirectUri, { scope });
          if (typeof window !== 'undefined' && window.location) {
            window.location.href = url;
          }
        } catch {
          showInlineError();
        }
        return;
      }

      if (typeof onProviderClick === 'function') {
        setLoadingState(REDIRECTING_LABELS[lang] || REDIRECTING_LABELS.en);
        try {
          await onProviderClick(provider);
          setIdleState();
          if (!visibleLabel && labelEl.parentNode) {
            btn.removeChild(labelEl);
          }
        } catch {
          showInlineError();
        }
        return;
      }

      console.warn(
        `[OneUID] Social login for "${provider}" requires a client authorization-code + PKCE flow via options.onProviderClick("${provider}").`
      );
      showInlineError();
    };

    btn.addEventListener('click', () => {
      void executeAction();
    });

    retryBtn.addEventListener('click', () => {
      void executeAction();
    });

    wrapper.appendChild(btn);
    wrapper.appendChild(errorEl);

    container.innerHTML = '';
    container.appendChild(wrapper);
  }

  /**
   * Retrieves the active sovereign device public key of a recipient user.
   */
  async getUserPublicKey(identifier: string): Promise<UserPublicKey> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/users/${encodeURIComponent(identifier)}/pubkey/`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'pubkey_fetch_failed',
        parseError(errorData, `Failed to fetch public key (${response.status}).`),
        response.status
      );
    }

    return response.json();
  }

  /**
   * Adds an encrypted record to the current user's Vault.
   */
  async addVaultRecord(
    title: string,
    payload: string,
    type: string = 'note',
    sessionKey: string | null = null,
    syncStatus: 'PENDING' | 'COMPLETED' = 'COMPLETED',
    issuer: string | null = null,
    signature: string | null = null
  ): Promise<VaultRecord> {
    const token = await this.getAccessToken();
    if (!token) {
      throw new AuthError('unauthenticated', 'Authentication required to save vault records.');
    }

    const response = await fetch(`${this.config.baseURL}/v1/vault/records/`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        title,
        payload,
        type,
        session_key: sessionKey,
        sync_status: syncStatus,
        issuer,
        signature,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'vault_create_failed',
        parseError(errorData, `Failed to create vault record (${response.status}).`),
        response.status
      );
    }

    return response.json();
  }

  /**
   * Transfers ownership of a vault record to another user.
   */
  async transferVaultRecord(
    recordId: string,
    recipient: string,
    payload: string,
    sessionKey: string,
    title?: string
  ): Promise<{ status: string; message: string }> {
    const token = await this.getAccessToken();
    if (!token) {
      throw new AuthError('unauthenticated', 'Authentication required to transfer vault records.');
    }

    const response = await fetch(`${this.config.baseURL}/v1/vault/records/${encodeURIComponent(recordId)}/transfer/`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        recipient,
        payload,
        session_key: sessionKey,
        title,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'vault_transfer_failed',
        parseError(errorData, `Failed to transfer vault record (${response.status}).`),
        response.status
      );
    }

    return response.json();
  }

  /**
   * Retrieves all wrapped Master Vault Keys (MVK) registered for the user's devices.
   */
  async getDeviceVaultKeys(): Promise<DeviceVaultKey[]> {
    const token = await this.getAccessToken();
    if (!token) {
      throw new AuthError('unauthenticated', 'Authentication required to get device vault keys.');
    }

    const response = await fetch(`${this.config.baseURL}/v1/vault/keys/`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'vault_keys_fetch_failed',
        parseError(errorData, `Failed to fetch device vault keys (${response.status}).`),
        response.status
      );
    }

    return response.json();
  }

  /**
   * Registers a new wrapped Master Vault Key (MVK) for a device.
   */
  async registerDeviceVaultKey(deviceId: string, wrappedMVK: string): Promise<DeviceVaultKey> {
    const token = await this.getAccessToken();
    if (!token) {
      throw new AuthError('unauthenticated', 'Authentication required to register a device vault key.');
    }

    const response = await fetch(`${this.config.baseURL}/v1/vault/keys/`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        device: deviceId,
        wrapped_mvk: wrappedMVK,
      }),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new AuthError(
        'vault_key_register_failed',
        parseError(errorData, `Failed to register device vault key (${response.status}).`),
        response.status
      );
    }

    return response.json();
  }

  // --- CONCISE SDK METHOD ALIASES ---

  /** @deprecated Use `startAuthorization()` (PKCE) or `verifyPassword()` + `verify2FA()`. */
  async loginPassword(username: string, password: string): Promise<TokenResponse> {
    return this.loginWithPassword(username, password);
  }

  async loginCode(
    code: string,
    redirectUri: string,
    codeVerifierOrOptions?: string | { codeVerifier?: string; expectedNonce?: string }
  ): Promise<TokenResponse> {
    return this.loginWithCode(code, redirectUri, codeVerifierOrOptions);
  }

  async loginSocial(
    provider: string,
    token: string,
    options?: { nonce?: string; codeVerifier?: string; redirectUri?: string }
  ): Promise<TokenResponse> {
    return this.loginWithProvider(provider, token, options);
  }

  async getPublicKey(identifier: string): Promise<UserPublicKey> {
    return this.getUserPublicKey(identifier);
  }

  async addRecord(
    title: string,
    payload: string,
    type: string = 'note',
    sessionKey: string | null = null,
    syncStatus: 'PENDING' | 'COMPLETED' = 'COMPLETED',
    issuer: string | null = null,
    signature: string | null = null
  ): Promise<VaultRecord> {
    return this.addVaultRecord(title, payload, type, sessionKey, syncStatus, issuer, signature);
  }

  async transferRecord(
    recordId: string,
    recipient: string,
    payload: string,
    sessionKey: string,
    title?: string
  ): Promise<{ status: string; message: string }> {
    return this.transferVaultRecord(recordId, recipient, payload, sessionKey, title);
  }

  async getVaultKeys(): Promise<DeviceVaultKey[]> {
    return this.getDeviceVaultKeys();
  }

  async registerVaultKey(deviceId: string, wrappedMVK: string): Promise<DeviceVaultKey> {
    return this.registerDeviceVaultKey(deviceId, wrappedMVK);
  }
}

export { parseError };
