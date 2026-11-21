import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import { AuthConfig, TokenResponse } from './types';
import { OneUID } from './client';
import { AuthError, parseError } from './errors';

export class PasskeyClient {
  constructor(private config: AuthConfig & { baseURL: string }, private root: OneUID) {}

  /**
   * Registers a new passkey (requires user to be already authenticated).
   */
  async register(name: string): Promise<void> {
    const token = await this.root.getAccessToken();
    if (!token) throw new AuthError('unauthenticated', 'Must be authenticated to register a passkey.');

    const challengeRes = await fetch(`${this.config.baseURL}/v1/auth/passkey/register/challenge/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ name }),
    });

    if (!challengeRes.ok) {
      const err = await challengeRes.json().catch(() => ({}));
      throw new AuthError(
        'passkey_challenge_failed',
        parseError(err, `Failed to get passkey registration challenge (${challengeRes.status}).`),
        challengeRes.status
      );
    }
    const options = await challengeRes.json();

    let authResp;
    try {
      authResp = await startRegistration({ optionsJSON: options });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Passkey registration cancelled or failed.';
      throw new AuthError('passkey_cancelled', parseError(msg, 'Passkey registration cancelled or failed.'));
    }

    const verifyRes = await fetch(`${this.config.baseURL}/v1/auth/passkey/register/verify/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        credential: authResp,
        device_name: name,
      }),
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json().catch(() => ({}));
      throw new AuthError(
        'passkey_register_failed',
        parseError(err, `Failed to verify passkey registration (${verifyRes.status}).`),
        verifyRes.status
      );
    }
  }

  /**
   * Authenticates using a passwordless WebAuthn passkey.
   */
  async login(email?: string): Promise<TokenResponse> {
    const challengeRes = await fetch(`${this.config.baseURL}/v1/auth/passkey/login/challenge/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });

    if (!challengeRes.ok) {
      const err = await challengeRes.json().catch(() => ({}));
      throw new AuthError(
        'passkey_challenge_failed',
        parseError(err, `Failed to get passkey login challenge (${challengeRes.status}).`),
        challengeRes.status
      );
    }
    const options = await challengeRes.json();

    let authResp;
    try {
      authResp = await startAuthentication({ optionsJSON: options });
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Passkey authentication cancelled or failed.';
      throw new AuthError('passkey_cancelled', parseError(msg, 'Passkey authentication cancelled or failed.'));
    }

    const verifyRes = await fetch(`${this.config.baseURL}/v1/auth/passkey/login/verify/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        auth_session_id: options.auth_session_id,
        credential: authResp,
        client_id: this.config.clientId,
      }),
    });

    if (!verifyRes.ok) {
      const err = await verifyRes.json().catch(() => ({}));
      throw new AuthError(
        'passkey_login_failed',
        parseError(err, `Failed to verify passkey login (${verifyRes.status}).`),
        verifyRes.status
      );
    }

    const tokens: TokenResponse = await verifyRes.json();
    await this.root.persistTokens(tokens, { flow: 'first_party' });
    return tokens;
  }
}
