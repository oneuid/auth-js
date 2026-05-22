import { AuthConfig, StorageAdapter, TokenResponse, UserProfile, IdentifyResponse, VerifyResponse } from './types';
import { getDefaultStorage } from './storage';
import { PasskeyClient } from './passkey';
import { SessionClient } from './session';
import { RecoveryClient } from './recovery';

export class OneUID {
  private config: AuthConfig;
  private storage: StorageAdapter;
  private readonly TOKEN_KEY = 'oneuid_access_token';
  private readonly REFRESH_KEY = 'oneuid_refresh_token';

  public passkey: PasskeyClient;
  public session: SessionClient;
  public recovery: RecoveryClient;

  constructor(config: AuthConfig, storage?: StorageAdapter) {
    this.config = config;
    this.storage = storage || getDefaultStorage();
    
    this.passkey = new PasskeyClient(this.config, this);
    this.session = new SessionClient(this.config, this);
    this.recovery = new RecoveryClient(this.config, this);

    this.injectNativeMetaTag();
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

  /**
   * Logs in using Resource Owner Password Credentials Grant
   */
  async loginWithPassword(username: string, password: string): Promise<TokenResponse> {
    const formData = new URLSearchParams();
    formData.append('grant_type', 'password');
    formData.append('username', username);
    formData.append('password', password);
    formData.append('client_id', this.config.clientId);
    
    if (this.config.clientSecret) {
      formData.append('client_secret', this.config.clientSecret);
    }

    const response = await fetch(`${this.config.baseURL}/o/token/`, {
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
      throw new Error(errorData.detail || errorData.error || `Password verification failed: ${response.statusText}`);
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
      throw new Error(errorData.detail || errorData.error || `2FA verification failed: ${response.statusText}`);
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
      throw new Error(errorData.detail || errorData.error || `Identify failed: ${response.statusText}`);
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
      throw new Error(errorData.detail || errorData.error || `Passcode verification failed: ${response.statusText}`);
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
      throw new Error(errorData.detail || errorData.error || `Nonce verification failed: ${response.statusText}`);
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
      throw new Error(errorData.detail || errorData.error || `WebAuthn verification failed: ${response.statusText}`);
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
      throw new Error(errorData.detail || errorData.error || `Registration failed: ${response.statusText}`);
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
    
    if (this.config.clientSecret) {
      formData.append('client_secret', this.config.clientSecret);
    }

    const response = await fetch(`${this.config.baseURL}/o/token/`, {
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

      await fetch(`${this.config.baseURL}/o/revoke_token/`, {
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
   * Note: This does NOT delete the user's global UID.ONE account.
   * You should delete the local Shadow Profile in your application before calling this.
   */
  async disconnect(): Promise<void> {
    await this.logout();
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

  /**
   * Generates the OAuth redirect URL for a social login provider on the UID.ONE Gateway.
   */
  getSocialRedirectUrl(provider: 'google' | 'facebook' | 'apple', redirectUri: string): string {
    const encodedRedirect = encodeURIComponent(redirectUri);
    return `${this.config.baseURL}/v1/auth/social-redirect/?provider=${provider}&redirect_uri=${encodedRedirect}&client_id=${this.config.clientId}`;
  }

  /**
   * Renders a premium, pre-styled UID.ONE Login Button inside a DOM container.
   */
  renderButton(containerId: string, options: {
    provider: 'google' | 'facebook' | 'apple' | 'uid';
    redirectUri: string;
    theme?: 'light' | 'dark';
    size?: 'small' | 'medium' | 'large';
  }) {
    if (typeof document === 'undefined') return;
    const container = document.getElementById(containerId);
    if (!container) {
      console.warn(`[OneUID] Container #${containerId} not found.`);
      return;
    }

    const { provider, redirectUri, theme = 'dark', size = 'medium' } = options;
    const btn = document.createElement('button');
    btn.type = 'button';
    
    const isDark = theme === 'dark';
    const bg = isDark ? '#111111' : '#ffffff';
    const color = isDark ? '#ffffff' : '#111111';
    const border = isDark ? '1px solid #222222' : '1px solid #e2e8f0';
    const hoverBg = isDark ? '#222222' : '#f8fafc';
    
    let padding = '10px 16px';
    let fontSize = '14px';
    if (size === 'small') {
      padding = '6px 12px';
      fontSize = '12px';
    } else if (size === 'large') {
      padding = '14px 24px';
      fontSize = '16px';
    }

    btn.style.cssText = `
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      padding: ${padding};
      font-size: ${fontSize};
      font-family: 'Inter', -apple-system, sans-serif;
      font-weight: 500;
      background: ${bg};
      color: ${color};
      border: ${border};
      border-radius: 6px;
      cursor: pointer;
      transition: all 0.2s ease;
      box-shadow: 0 1px 2px rgba(0,0,0,0.05);
    `;

    btn.onmouseover = () => {
      btn.style.background = hoverBg;
    };
    btn.onmouseout = () => {
      btn.style.background = bg;
    };

    let iconSvg = '';
    let label = 'UID.ONE';

    if (provider === 'google') {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>`;
      label = 'Sign in with Google';
    } else if (provider === 'facebook') {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="#1877F2" xmlns="http://www.w3.org/2000/svg"><path d="M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.469h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.469h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z"/></svg>`;
      label = 'Sign in with Facebook';
    } else if (provider === 'apple') {
      iconSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="${isDark ? '#ffffff' : '#000000'}" xmlns="http://www.w3.org/2000/svg"><path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-.1.77-1.07 1.25-.8 2.63-.73 3.58-.29.39.17 1.5.54 2.21 1.58-.57.35-1.71 1.01-1.71 2.37 0 1.63 1.33 2.2 1.34 2.2-.01.04-.21.72-.71 1.45zM15.97 4.17c.6-1.03.37-2.35-.33-3.17-.68-.8-1.92-1.05-3-.33-.66.69-.4 2.02.26 2.82.68.79 1.99.78 3.07-.32z"/></svg>`;
      label = 'Sign in with Apple';
    } else {
      iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="icon icon-tabler icons-tabler-outline icon-tabler-fingerprint"><path d="M18.9 7a8 8 0 0 1 1.1 5v1a6 6 0 0 0 .8 3M8 11a4 4 0 0 1 8 0v1a10 10 0 0 0 .8 4M12 11v2a14 14 0 0 0 .8 4.5M3 12a10 10 0 0 1 13.7-9.3M5.8 15a7 7 0 0 1 6.2-11.3M8.8 17.8A4 4 0 0 1 8 12a5 5 0 0 1 .2-1.5M10.8 20.2a2 2 0 0 1-1.8-3.2"/></svg>`;
      label = 'Sign in with UID.ONE';
    }

    btn.innerHTML = `${iconSvg} <span>${label}</span>`;
    btn.onclick = () => {
      if (provider === 'uid') {
        window.location.href = `${this.config.baseURL}/login/?client_id=${this.config.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}`;
      } else {
        window.location.href = this.getSocialRedirectUrl(provider, redirectUri);
      }
    };

    container.innerHTML = '';
    container.appendChild(btn);
  }
}
