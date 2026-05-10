import { AuthConfig, TokenResponse } from './types';
import { OneUID } from './client';

export class RecoveryClient {
  constructor(private config: AuthConfig, private root: OneUID) {}

  /**
   * Generates 10 backup codes (Requires user to be authenticated)
   * Note: This replaces any unused existing codes.
   */
  async generate(): Promise<string[]> {
    const token = await this.root.getAccessToken();
    if (!token) throw new Error("Must be authenticated to generate recovery codes");

    const res = await fetch(`${this.config.baseURL}/v1/auth/recovery/generate/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Failed to generate recovery codes");
    }

    const data = await res.json();
    return data.codes;
  }

  /**
   * Login using a recovery code
   */
  async login(email: string, code: string): Promise<TokenResponse> {
    const res = await fetch(`${this.config.baseURL}/v1/auth/recovery/login/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        code,
        client_id: this.config.clientId
      })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Invalid recovery code or email");
    }

    const tokens: TokenResponse = await res.json();
    await (this.root as any).persistTokens(tokens);
    return tokens;
  }
}
