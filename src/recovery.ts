import { AuthConfig, TokenResponse } from './types';
import { OneUID } from './client';
import { AuthError, parseError } from './errors';

export class RecoveryClient {
  constructor(private config: AuthConfig & { baseURL: string }, private root: OneUID) {}

  /**
   * Generates 10 backup codes (requires user to be authenticated).
   * Note: This replaces any unused existing codes.
   */
  async generate(): Promise<string[]> {
    const token = await this.root.getAccessToken();
    if (!token) throw new AuthError('unauthenticated', 'Must be authenticated to generate recovery codes.');

    const res = await fetch(`${this.config.baseURL}/v1/auth/recovery/generate/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new AuthError(
        'recovery_generate_failed',
        parseError(err, `Failed to generate recovery codes (${res.status}).`),
        res.status
      );
    }

    const data = await res.json();
    return data.codes;
  }

  /**
   * Signs in using a single-use recovery code.
   */
  async login(email: string, code: string): Promise<TokenResponse> {
    const res = await fetch(`${this.config.baseURL}/v1/auth/recovery/login/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email,
        code,
        client_id: this.config.clientId,
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new AuthError(
        'recovery_login_failed',
        parseError(err, `Invalid recovery code or email (${res.status}).`),
        res.status
      );
    }

    const tokens: TokenResponse = await res.json();
    await this.root.persistTokens(tokens, { flow: 'first_party' });
    return tokens;
  }
}
