import { AuthConfig, StorageAdapter, TokenResponse, UserProfile } from './types';
import { getDefaultStorage } from './storage';

export class OneUID {
  private config: AuthConfig;
  private storage: StorageAdapter;
  private readonly TOKEN_KEY = 'oneuid_access_token';
  private readonly REFRESH_KEY = 'oneuid_refresh_token';

  constructor(config: AuthConfig, storage?: StorageAdapter) {
    this.config = config;
    this.storage = storage || getDefaultStorage();
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
    const response = await fetch(`${this.config.baseURL}/api/v1/auth/social-login/`, {
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

    const response = await fetch(`${this.config.baseURL}/api/v1/auth/me/`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch profile: ${response.statusText}`);
    }

    return response.json();
  }

  async getAccessToken(): Promise<string | null> {
    // In a production scenario, we should decode the JWT to check expiry 
    // and automatically use the refresh token if expired.
    return this.storage.getItem(this.TOKEN_KEY);
  }

  private async persistTokens(data: TokenResponse) {
    await this.storage.setItem(this.TOKEN_KEY, data.access_token);
    if (data.refresh_token) {
      await this.storage.setItem(this.REFRESH_KEY, data.refresh_token);
    }
  }

  private async clearTokens() {
    await this.storage.removeItem(this.TOKEN_KEY);
    await this.storage.removeItem(this.REFRESH_KEY);
  }
}
