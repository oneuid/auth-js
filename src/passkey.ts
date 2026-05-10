import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import { AuthConfig, TokenResponse } from './types';
import { OneUID } from './client';

export class PasskeyClient {
  constructor(private config: AuthConfig, private root: OneUID) {}

  /**
   * Register a new passkey (requires user to be already authenticated)
   */
  async register(name: string): Promise<void> {
    const token = await this.root.getAccessToken();
    if (!token) throw new Error("Must be authenticated to register a passkey");

    // 1. Get challenge
    const challengeRes = await fetch(`${this.config.baseURL}/v1/auth/passkey/register/challenge/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ name })
    });
    
    if (!challengeRes.ok) throw new Error("Failed to get registration challenge");
    const options = await challengeRes.json();

    // 2. Browser WebAuthn prompt
    let authResp;
    try {
      authResp = await startRegistration({ optionsJSON: options });
    } catch (error) {
      throw new Error(`Passkey registration cancelled or failed: ${error}`);
    }

    // 3. Verify
    const verifyRes = await fetch(`${this.config.baseURL}/v1/auth/passkey/register/verify/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(authResp)
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json().catch(() => ({}));
      throw new Error(err.error || "Failed to verify passkey registration");
    }
  }

  /**
   * Login using a passkey (Passwordless)
   */
  async login(email?: string): Promise<TokenResponse> {
    // 1. Get challenge
    const challengeRes = await fetch(`${this.config.baseURL}/v1/auth/passkey/login/challenge/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    if (!challengeRes.ok) throw new Error("Failed to get login challenge");
    const options = await challengeRes.json();

    // 2. Browser WebAuthn prompt
    let authResp;
    try {
      authResp = await startAuthentication({ optionsJSON: options });
    } catch (error) {
      throw new Error(`Passkey login cancelled or failed: ${error}`);
    }

    // 3. Verify and get tokens
    const verifyRes = await fetch(`${this.config.baseURL}/v1/auth/passkey/login/verify/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...authResp,
        client_id: this.config.clientId
      })
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json().catch(() => ({}));
      throw new Error(err.error || "Failed to verify passkey login");
    }

    const tokens: TokenResponse = await verifyRes.json();
    await (this.root as any).persistTokens(tokens);
    return tokens;
  }
}
