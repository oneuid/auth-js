import { AuthConfig, StorageAdapter, TokenResponse, UserProfile, IdentifyResponse, VerifyResponse, VaultRecord, UserPublicKey, DeviceVaultKey, ButtonOptions } from './types';
import { getDefaultStorage } from './storage';
import { PasskeyClient } from './passkey';
import { SessionClient } from './session';
import { RecoveryClient } from './recovery';
import { DevicesClient } from './devices';
import { KMSClient, KeyringStorageAdapter } from './kms';

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

const SHIELD_PATH =
  'M 256 24 L 444 101 C 458.5 107 468 121 468 137 V 248 C 468 370 378 449 256 488 C 134 449 44 370 44 248 V 137 C 44 121 53.5 107 68 101 L 256 24 Z M 256 142.0 C 285.8 142.0 310.0 166.2 310.0 196.0 C 310.0 216.9 298.1 235.0 282.24 243.2 L 289.37 334.6 C 289.37 353.0 274.4 368.0 256.0 368.0 C 237.6 368.0 222.63 353.0 222.63 334.6 L 229.76 243.2 C 213.9 235.0 202.0 216.9 202.0 196.0 C 202.0 166.2 226.2 142.0 256.0 142.0 Z';

const STYLE_ID = 'oneuid-sdk-styles';

const BUTTON_CSS = `
.oneuid-btn {
  box-sizing: border-box;
  display: inline-flex;
  align-items: center;
  justify-content: center;
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
.oneuid-btn:focus-visible {
  outline: 2px solid #2563EB;
  outline-offset: 2px;
}
.oneuid-btn--small {
  height: 32px;
  padding: 0 12px;
  font-size: 13px;
  gap: 8px;
}
.oneuid-btn--medium {
  height: 40px;
  padding: 0 16px;
  font-size: 14px;
  gap: 10px;
}
.oneuid-btn--large {
  height: 44px;
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
@media (prefers-reduced-motion: reduce) {
  .oneuid-btn {
    transition: background-color 150ms ease, border-color 150ms ease, box-shadow 150ms ease;
  }
  .oneuid-btn:active:not(:disabled) {
    transform: none;
  }
}
`;

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

export class OneUID {
  private config: AuthConfig;
  private storage: StorageAdapter;
  private readonly TOKEN_KEY = 'oneuid_access_token';
  private readonly REFRESH_KEY = 'oneuid_refresh_token';

  public passkey: PasskeyClient;
  public session: SessionClient;
  public recovery: RecoveryClient;
  public devices: DevicesClient;
  public kms?: KMSClient;

  constructor(config: AuthConfig, storage?: StorageAdapter) {
    this.config = config;
    this.storage = storage || getDefaultStorage();
    
    this.passkey = new PasskeyClient(this.config, this);
    this.session = new SessionClient(this.config, this);
    this.recovery = new RecoveryClient(this.config, this);
    this.devices = new DevicesClient(this.config, this);

    // Auto-initialize KMS if KEK exists in env
    const globalProcess = typeof globalThis !== 'undefined' ? (globalThis as any).process : undefined;
    if (globalProcess && globalProcess.env && globalProcess.env.VAULT_MASTER_KEY) {
      try {
        this.initKMS();
      } catch (e) {
        // Silent catch during initialization
      }
    }

    this.injectNativeMetaTag();
  }

  public initKMS(options: { kekB64?: string; keyringStorage?: KeyringStorageAdapter } = {}): KMSClient {
    this.kms = new KMSClient(this.config, this, options);
    return this.kms;
  }

  private injectNativeMetaTag() {
    if (typeof document !== 'undefined' && typeof document.querySelector === 'function') {
      const existing = document.querySelector('meta[name="uid-passkey-native"]');
      if (!existing) {
        const meta = document.createElement('meta');
        meta.name = "uid-passkey-native";
        meta.content = "true";
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

  private getOidcEndpoint(type: 'token' | 'certs' | 'revoke' | 'userinfo'): string {
    const baseURL = this.config.baseURL.replace(/\/$/, '');
    return `${baseURL}/oauth/${type === 'certs' ? 'certs' : type}`;
  }

  /**
   * Logs in using Resource Owner Password Credentials Grant
   */
  async loginWithPassword(username: string, password: string): Promise<TokenResponse> {
    const formData = new URLSearchParams();
    formData.append('grant_type', 'password');
    formData.append('username', username);
    formData.append('password', password);
    formData.append('client_id', this.config.clientId);
    formData.append('scope', 'openid profile email');
    
    if (this.config.clientSecret) {
      formData.append('client_secret', this.config.clientSecret);
    }

    const tokenUrl = this.getOidcEndpoint('token');

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString()
    });

    if (!response.ok) {
      throw new Error(`Login failed: ${response.statusText}`);
    }

    const data: TokenResponse = await response.json();
    await this.persistTokens(data);
    return data;
  }

  /**
   * Exchanges an OIDC authorization code for tokens
   */
  async loginWithCode(code: string, redirectUri: string): Promise<TokenResponse> {
    const formData = new URLSearchParams();
    formData.append('grant_type', 'authorization_code');
    formData.append('code', code);
    formData.append('redirect_uri', redirectUri);
    formData.append('client_id', this.config.clientId);
    
    if (this.config.clientSecret) {
      formData.append('client_secret', this.config.clientSecret);
    }

    const tokenUrl = this.getOidcEndpoint('token');

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString()
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => '');
      throw new Error(`Code exchange failed: ${response.statusText}. Details: ${errText}`);
    }

    const data: TokenResponse = await response.json();
    await this.persistTokens(data);
    return data;
  }

  /**
   * Step 1 of Password login with 2FA support.
   */
  async verifyPassword(email: string, password: string): Promise<any> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/verify-password/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        password,
        client_id: this.config.clientId
      })
    });

    if (!response.ok && response.status !== 403) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `Password verification failed: ${response.statusText}`));
    }

    return response.json();
  }

  /**
   * Step 2 of Password login with 2FA support.
   */
  async verify2FA(params: {
    session_token: string;
    method: 'totp' | 'passkey' | 'backup_code';
    code?: string;
    assertion?: any;
  }): Promise<any> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/verify-2fa/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...params,
        client_id: this.config.clientId
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `2FA verification failed: ${response.statusText}`));
    }

    const data = await response.json();
    if (data.token) {
      await this.persistTokens(data.token);
    }
    return data;
  }


  /**
   * Logs in using a third-party provider's token (e.g. Google ID Token)
   */
  async loginWithProvider(provider: string, token: string): Promise<TokenResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/social-login/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider,
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret
      })
    });

    if (!response.ok) {
      throw new Error(`Social login failed: ${response.statusText}`);
    }

    const data: TokenResponse = await response.json();
    await this.persistTokens(data);
    return data;
  }

  /**
   * Single entry point to identify an email address and determine the authentication flow.
   */
  async identify(email: string): Promise<IdentifyResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/identify/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `Identify failed: ${response.statusText}`));
    }

    return response.json();
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
        client_id: this.config.clientId
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `Passcode verification failed: ${response.statusText}`));
    }

    const data: VerifyResponse = await response.json();
    await this.persistTokens(data);
    return data;
  }

  /**
   * Verifies the one-time cryptographic nonce token from login link.
   */
  async verifyNonce(token: string): Promise<VerifyResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/verify-nonce/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        client_id: this.config.clientId
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `Nonce verification failed: ${response.statusText}`));
    }

    const data: VerifyResponse = await response.json();
    await this.persistTokens(data);
    return data;
  }

  /**
   * Verifies the WebAuthn assertion for biometric login.
   */
  async verifyWebAuthn(userId: string, assertion: any): Promise<VerifyResponse> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/verify-webauthn/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: userId,
        assertion,
        client_id: this.config.clientId
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `WebAuthn verification failed: ${response.statusText}`));
    }

    const data: VerifyResponse = await response.json();
    await this.persistTokens(data);
    return data;
  }

  /**
   * Registers a new user
   */
  async register(email: string, password: string, recaptcha?: string): Promise<any> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/register/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        email, 
        password,
        recaptcha,
        client_id: this.config.clientId 
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `Registration failed: ${response.statusText}`));
    }

    return response.json();
  }

  /**
   * Refreshes the access token using a refresh token
   */
  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const formData = new URLSearchParams();
    formData.append('grant_type', 'refresh_token');
    formData.append('refresh_token', refreshToken);
    formData.append('client_id', this.config.clientId);
    formData.append('scope', 'openid profile email');
    
    if (this.config.clientSecret) {
      formData.append('client_secret', this.config.clientSecret);
    }

    const tokenUrl = this.getOidcEndpoint('token');

    const response = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString()
    });

    if (!response.ok) {
      throw new Error(`Refresh failed: ${response.statusText}`);
    }

    const data: TokenResponse = await response.json();
    await this.persistTokens(data);
    return data;
  }

  async logout(): Promise<void> {
    const token = await this.storage.getItem(this.TOKEN_KEY);
    
    if (token) {
      const formData = new URLSearchParams();
      formData.append('token', token);
      formData.append('client_id', this.config.clientId);
      if (this.config.clientSecret) {
        formData.append('client_secret', this.config.clientSecret);
      }

      const revokeUrl = this.getOidcEndpoint('revoke');

      await fetch(revokeUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
      }).catch(() => {/* Ignore network errors on logout */});
    }

    await this.clearTokens();
  }

  async getProfile(): Promise<UserProfile> {
    const token = await this.getAccessToken();
    if (!token) throw new Error("Not authenticated");

    const response = await fetch(`${this.config.baseURL}/v1/auth/me/`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch profile: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Disconnects the user from this application by revoking the access token.
   * Note: This does NOT delete the user's global OneUID account.
   * You should delete the local Shadow Profile in your application before calling this.
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

  async getAccessToken(): Promise<string | null> {
    // In a production scenario, we should decode the JWT to check expiry 
    // and automatically use the refresh token if expired.
    return this.storage.getItem(this.TOKEN_KEY);
  }

  public async persistTokens(data: TokenResponse) {
    await this.storage.setItem(this.TOKEN_KEY, data.access_token);
    if (data.refresh_token) {
      await this.storage.setItem(this.REFRESH_KEY, data.refresh_token);
    }
  }

  public async clearTokens() {
    await this.storage.removeItem(this.TOKEN_KEY);
    await this.storage.removeItem(this.REFRESH_KEY);
  }

  getAuthorizeUrl(
    redirectUri: string,
    options?: { codeChallenge?: string; codeChallengeMethod?: 'S256'; state?: string; scope?: string }
  ): string {
    const baseURL = this.config.baseURL.replace(/\/$/, '');
    const authUrl = `${baseURL}/oauth/authorize`;
    const encodedRedirect = encodeURIComponent(redirectUri);
    const scopeParam = encodeURIComponent(options?.scope || 'openid profile email').replace(/%20/g, '+');
    let url = `${authUrl}?client_id=${this.config.clientId}&redirect_uri=${encodedRedirect}&response_type=code&scope=${scopeParam}`;
    if (options?.codeChallenge) {
      url += `&code_challenge=${encodeURIComponent(options.codeChallenge)}&code_challenge_method=${options.codeChallengeMethod || 'S256'}`;
    }
    if (options?.state) {
      url += `&state=${encodeURIComponent(options.state)}`;
    }
    return url;
  }

  /**
   * Generates the OAuth redirect URL for a social login provider on the OneUID Gateway.
   * @deprecated Social redirect views have been decommissioned. Use native client flows instead.
   */
  getSocialRedirectUrl(provider: 'google' | 'facebook' | 'apple', redirectUri: string): string {
    console.warn("getSocialRedirectUrl is deprecated. Please perform native OAuth redirects directly from your client application.");
    const encodedRedirect = encodeURIComponent(redirectUri);
    return `${this.config.baseURL}/v1/auth/social/?provider=${provider}&redirect_uri=${encodedRedirect}&client_id=${this.config.clientId}`;
  }

  /**
   * Renders a Cryptographic Minimal OneUID sign-in button inside a DOM container.
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
      onProviderClick,
    } = options;

    const lang = resolveLocale(locale);
    const isRtl = lang === 'ar';
    const tone = theme === 'light' || theme === 'brand' ? theme : 'dark';
    const scale = size === 'small' || size === 'large' ? size : 'medium';
    const iconPx = scale === 'small' ? 16 : scale === 'large' ? 20 : 18;

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `oneuid-btn oneuid-btn--${tone} oneuid-btn--${scale}`;
    btn.lang = lang;
    if (isRtl) {
      btn.dir = 'rtl';
    }

    let iconSvg = '';
    let text = BUTTON_LABELS[lang] || BUTTON_LABELS.en;

    if (provider === 'google') {
      iconSvg = `<svg width="${iconPx}" height="${iconPx}" viewBox="0 0 24 24" aria-hidden="true" focusable="false" style="flex-shrink:0" xmlns="http://www.w3.org/2000/svg"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>`;
      text = 'Sign in with Google';
    } else if (provider === 'facebook') {
      const fbFill = tone === 'brand' ? '#FFFFFF' : '#1877F2';
      iconSvg = `<svg width="${iconPx}" height="${iconPx}" viewBox="0 0 24 24" fill="${fbFill}" aria-hidden="true" focusable="false" style="flex-shrink:0" xmlns="http://www.w3.org/2000/svg"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.469h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.469h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>`;
      text = 'Sign in with Facebook';
    } else if (provider === 'apple') {
      const fill = tone === 'light' ? '#0F172A' : '#FFFFFF';
      iconSvg = `<svg width="${iconPx}" height="${iconPx}" viewBox="0 0 24 24" fill="${fill}" aria-hidden="true" focusable="false" style="flex-shrink:0" xmlns="http://www.w3.org/2000/svg"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-.1.77-1.07 1.25-.8 2.63-.73 3.58-.29.39.17 1.5.54 2.21 1.58-.57.35-1.71 1.01-1.71 2.37 0 1.63 1.33 2.2 1.34 2.2-.01.04-.21.72-.71 1.45zM15.97 4.17c.6-1.03.37-2.35-.33-3.17-.68-.8-1.92-1.05-3-.33-.66.69-.4 2.02.26 2.82.68.79 1.99.78 3.07-.32z"/></svg>`;
      text = 'Sign in with Apple';
    } else {
      const fill = tone === 'brand' ? '#FFFFFF' : '#2563EB';
      iconSvg = `<svg width="${iconPx}" height="${iconPx}" viewBox="0 0 512 512" fill="none" aria-hidden="true" focusable="false" style="flex-shrink:0" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" clip-rule="evenodd" fill="${fill}" d="${SHIELD_PATH}"/></svg>`;
    }

    const iconWrap = document.createElement('span');
    iconWrap.style.cssText = 'display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;';
    iconWrap.innerHTML = iconSvg;

    const labelEl = document.createElement('span');
    labelEl.textContent = custom || text;

    btn.appendChild(iconWrap);
    btn.appendChild(labelEl);

    btn.addEventListener('click', () => {
      if (provider === 'uid') {
        const base = this.config.baseURL.replace(/\/$/, '');
        window.location.href = `${base}/login/?client_id=${encodeURIComponent(this.config.clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
      } else if (typeof onProviderClick === 'function') {
        onProviderClick(provider);
      } else {
        console.warn(
          `[OneUID] Social login for "${provider}" requires a native client OAuth flow. Provide options.onProviderClick("${provider}") to handle this action.`
        );
      }
    });

    container.innerHTML = '';
    container.appendChild(btn);
  }

  /**
   * Retrieves the active sovereign device public key of a recipient user.
   * Can be queried by User ID (OIDC sub), email, or username.
   */
  async getUserPublicKey(identifier: string): Promise<UserPublicKey> {
    const response = await fetch(`${this.config.baseURL}/v1/auth/users/${encodeURIComponent(identifier)}/pubkey/`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.message || `Failed to fetch public key: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Adds an encrypted record to the current user's Vault.
   * Requires an authenticated session.
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
      throw new Error("Authentication required to save vault records.");
    }

    const response = await fetch(`${this.config.baseURL}/v1/vault/records/`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        title,
        payload,
        type,
        session_key: sessionKey,
        sync_status: syncStatus,
        issuer,
        signature
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `Failed to create vault record: ${response.statusText}`));
    }

    return response.json();
  }

  /**
   * Transfers ownership of a vault record to another user.
   * The payload must be re-encrypted using the recipient's public key beforehand.
   * Requires an authenticated session.
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
      throw new Error("Authentication required to transfer vault records.");
    }

    const response = await fetch(`${this.config.baseURL}/v1/vault/records/${recordId}/transfer/`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        recipient,
        payload,
        session_key: sessionKey,
        title
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `Failed to transfer vault record: ${response.statusText}`));
    }

    return response.json();
  }

  /**
   * Retrieves all wrapped Master Vault Keys (MVK) registered for the user's devices.
   */
  async getDeviceVaultKeys(): Promise<DeviceVaultKey[]> {
    const token = await this.getAccessToken();
    if (!token) {
      throw new Error("Authentication required to get device vault keys.");
    }

    const response = await fetch(`${this.config.baseURL}/v1/vault/keys/`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `Failed to fetch device vault keys: ${response.statusText}`));
    }

    return response.json();
  }

  /**
   * Registers a new wrapped Master Vault Key (MVK) for a device.
   */
  async registerDeviceVaultKey(deviceId: string, wrappedMVK: string): Promise<DeviceVaultKey> {
    const token = await this.getAccessToken();
    if (!token) {
      throw new Error("Authentication required to register a device vault key.");
    }

    const response = await fetch(`${this.config.baseURL}/v1/vault/keys/`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        device: deviceId,
        wrapped_mvk: wrappedMVK
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(parseError(errorData, `Failed to register device vault key: ${response.statusText}`));
    }

    return response.json();
  }

  // --- CONCISE SDK METHOD ALIASES (100% Backward Compatible) ---

  async loginPassword(username: string, password: string): Promise<TokenResponse> {
    return this.loginWithPassword(username, password);
  }

  async loginCode(code: string, redirectUri: string): Promise<TokenResponse> {
    return this.loginWithCode(code, redirectUri);
  }

  async loginSocial(provider: string, token: string): Promise<TokenResponse> {
    return this.loginWithProvider(provider, token);
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

export function parseError(errorData: any, fallback: string): string {
  if (!errorData) return fallback;
  if (typeof errorData === 'string') return errorData;
  if (errorData.detail && typeof errorData.detail === 'string') return errorData.detail;
  if (errorData.error && typeof errorData.error === 'string') return errorData.error;
  if (errorData.message && typeof errorData.message === 'string') return errorData.message;
  
  if (typeof errorData === 'object') {
    for (const key of Object.keys(errorData)) {
      const val = errorData[key];
      if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'string') {
        return val[0];
      }
      if (typeof val === 'string') {
        return val;
      }
    }
  }
  return fallback;

}
