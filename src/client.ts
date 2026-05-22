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
}
