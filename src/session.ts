import {
  AuthConfig,
  ChallengeApproveOptions,
  ChallengeMetadata,
  ChallengePollOptions,
  TokenResponse,
} from './types';
import { OneUID } from './client';
import { AuthError, parseError } from './errors';
import { assertSafeUrl } from './pkce';

const DEFAULT_POLL_INTERVAL_MS = 2000;
const DEFAULT_POLL_TIMEOUT_MS = 300_000;

function validateChallengeDomain(domain: string): string {
  const trimmed = domain.trim();
  if (!trimmed) {
    throw new AuthError('invalid_domain', 'Challenge domain must not be empty.');
  }
  if (trimmed.includes('://')) {
    return assertSafeUrl(trimmed, 'domain').hostname;
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(trimmed) && trimmed !== 'localhost') {
    throw new AuthError('invalid_domain', 'Challenge domain must be a valid hostname or HTTPS URL.');
  }
  return trimmed;
}

export class SessionClient {
  private inspectedChallenges = new Map<string, ChallengeMetadata>();

  constructor(private config: AuthConfig, private root: OneUID) {}

  private get baseURL(): string {
    return this.config.baseURL.replace(/\/$/, '');
  }

  /**
   * Generates a new challenge session for QR Code display or Extension login.
   * Note: `session_id` is a bearer secret; do not expose it in predictable URLs without origin binding.
   */
  async create(
    method: 'QR' | 'EXTENSION' = 'QR',
    domain?: string,
    options?: { codeChallenge?: string }
  ): Promise<{ session_id: string; expires_at: string; status: string; method?: string; match_number?: string }> {
    const validatedDomain = domain !== undefined ? validateChallengeDomain(domain) : undefined;

    const body: Record<string, unknown> = { method, domain: validatedDomain };
    if (options?.codeChallenge) {
      body.code_challenge = options.codeChallenge;
    }

    const res = await fetch(`${this.baseURL}/v1/auth/challenges/request/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new AuthError('challenge_create_failed', parseError(err, 'Failed to create challenge session.'), res.status);
    }

    const data = await res.json();
    return {
      session_id: data.token,
      expires_at: data.expires_at,
      status: data.status,
      method: data.method,
      match_number: data.match_number,
    };
  }

  /**
   * Fetches challenge metadata (app, origin, scopes, expiry, and match number)
   * so the approver can verify context before approving.
   */
  async get(sessionId: string): Promise<ChallengeMetadata> {
    if (!sessionId || typeof sessionId !== 'string') {
      throw new AuthError('invalid_session_id', 'sessionId is required.');
    }
    const token = await this.root.getAccessToken();
    if (!token) {
      throw new AuthError('unauthenticated', 'Must be authenticated to inspect a challenge.');
    }

    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    };

    const singleRes = await fetch(`${this.baseURL}/v1/auth/challenges/${encodeURIComponent(sessionId)}/`, {
      method: 'GET',
      headers,
    });

    let raw: Record<string, unknown> | undefined;
    if (singleRes.ok) {
      raw = (await singleRes.json()) as Record<string, unknown>;
    } else if (singleRes.status === 404 || singleRes.status === 405) {
      const listRes = await fetch(`${this.baseURL}/v1/auth/challenges/`, {
        method: 'GET',
        headers,
      });
      if (!listRes.ok) {
        const err = await listRes.json().catch(() => ({}));
        throw new AuthError('challenge_fetch_failed', parseError(err, 'Failed to fetch challenge metadata.'), listRes.status);
      }
      const listData = (await listRes.json()) as { results?: Array<Record<string, unknown>> };
      raw = (listData.results || []).find((item) => String(item.token || item.session_id) === sessionId);
      if (!raw) {
        throw new AuthError('challenge_not_found', 'Challenge not found or expired.', 404);
      }
    } else {
      const err = await singleRes.json().catch(() => ({}));
      throw new AuthError('challenge_fetch_failed', parseError(err, 'Failed to fetch challenge metadata.'), singleRes.status);
    }

    const nestedMeta = (raw.metadata && typeof raw.metadata === 'object' ? raw.metadata : {}) as Record<string, unknown>;
    const matchNumber =
      typeof raw.match_number === 'string' || typeof raw.match_number === 'number'
        ? String(raw.match_number)
        : typeof nestedMeta.match_number === 'string' || typeof nestedMeta.match_number === 'number'
          ? String(nestedMeta.match_number)
          : undefined;

    const scopesRaw = raw.scopes ?? nestedMeta.scopes;
    const scopes = Array.isArray(scopesRaw) ? scopesRaw.map((s) => String(s)) : undefined;

    const metadata: ChallengeMetadata = {
      session_id: String(raw.token || raw.session_id || sessionId),
      method: String(raw.method || 'QR'),
      domain: raw.domain != null ? String(raw.domain) : null,
      origin: raw.origin != null ? String(raw.origin) : nestedMeta.origin != null ? String(nestedMeta.origin) : null,
      device: raw.device != null ? String(raw.device) : null,
      app_name: raw.app_name != null ? String(raw.app_name) : nestedMeta.app_name != null ? String(nestedMeta.app_name) : null,
      scopes,
      expires_at: String(raw.expires_at || ''),
      match_number: matchNumber,
      metadata: nestedMeta,
    };

    this.inspectedChallenges.set(sessionId, metadata);
    return metadata;
  }

  /**
   * Approves a session challenge after metadata inspection and explicit user match-number confirmation.
   */
  async approve(sessionId: string, options: ChallengeApproveOptions): Promise<void> {
    if (!sessionId || typeof sessionId !== 'string') {
      throw new AuthError('invalid_session_id', 'sessionId is required.');
    }

    const inspected = this.inspectedChallenges.get(sessionId);
    if (!inspected) {
      throw new AuthError(
        'challenge_not_inspected',
        'Challenge metadata must be fetched via session.get(sessionId) and shown to the user before approving.'
      );
    }

    const confirmedMatch = options?.matchNumber?.trim();
    if (!confirmedMatch) {
      throw new AuthError(
        'match_number_required',
        'A user-confirmed matchNumber is required to approve a challenge.'
      );
    }

    if (inspected.match_number && confirmedMatch !== inspected.match_number.trim()) {
      throw new AuthError(
        'match_number_mismatch',
        'Confirmed matchNumber does not match the challenge metadata.'
      );
    }

    const token = await this.root.getAccessToken();
    if (!token) {
      throw new AuthError('unauthenticated', 'Must be authenticated to approve a session.');
    }

    const payload: Record<string, unknown> = {
      match_number: confirmedMatch,
    };
    if (options.encryptedPayload !== undefined) payload.encrypted_payload = options.encryptedPayload;
    if (options.signatureBlock !== undefined) payload.signature_block = options.signatureBlock;
    if (options.zkMode !== undefined) payload.zk_mode = options.zkMode;
    if (options.locationEnabled !== undefined) payload.location_enabled = options.locationEnabled;

    const res = await fetch(`${this.baseURL}/v1/auth/challenges/${encodeURIComponent(sessionId)}/approve/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new AuthError('challenge_approve_failed', parseError(err, 'Failed to approve session challenge.'), res.status);
    }

    this.inspectedChallenges.delete(sessionId);
  }

  /**
   * Rejects a session challenge (requires the caller to be authenticated, e.g., mobile app).
   */
  async reject(sessionId: string): Promise<void> {
    if (!sessionId || typeof sessionId !== 'string') {
      throw new AuthError('invalid_session_id', 'sessionId is required.');
    }
    const token = await this.root.getAccessToken();
    if (!token) {
      throw new AuthError('unauthenticated', 'Must be authenticated to reject a session.');
    }

    const res = await fetch(`${this.baseURL}/v1/auth/challenges/${encodeURIComponent(sessionId)}/reject/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new AuthError('challenge_reject_failed', parseError(err, 'Failed to reject session challenge.'), res.status);
    }

    this.inspectedChallenges.delete(sessionId);
  }

  /**
   * Polls the session challenge status until approved, rejected, expired, consumed, timed out, or aborted.
   * Transient network and 5xx errors are retried until timeoutMs.
   */
  async pollForApproval(
    sessionId: string,
    optionsOrIntervalMs: number | ChallengePollOptions = DEFAULT_POLL_INTERVAL_MS
  ): Promise<TokenResponse> {
    const opts: ChallengePollOptions =
      typeof optionsOrIntervalMs === 'number' ? { intervalMs: optionsOrIntervalMs } : optionsOrIntervalMs;

    const intervalMs = Math.max(10, opts.intervalMs ?? DEFAULT_POLL_INTERVAL_MS);
    const timeoutMs = Math.max(10, opts.timeoutMs ?? DEFAULT_POLL_TIMEOUT_MS);
    const signal = opts.signal;

    if (signal?.aborted) {
      throw new AuthError('aborted', 'Challenge polling was aborted.');
    }

    const deadline = Date.now() + timeoutMs;

    return new Promise((resolve, reject) => {
      let timerId: ReturnType<typeof setTimeout> | null = null;
      let settled = false;

      const cleanup = () => {
        if (timerId !== null) {
          clearTimeout(timerId);
          timerId = null;
        }
        if (signal) {
          signal.removeEventListener('abort', onAbort);
        }
      };

      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err);
      };

      const succeed = (tokens: TokenResponse) => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(tokens);
      };

      const onAbort = () => {
        fail(new AuthError('aborted', 'Challenge polling was aborted.'));
      };

      if (signal) {
        signal.addEventListener('abort', onAbort, { once: true });
      }

      const scheduleNext = () => {
        if (settled) return;
        const remaining = deadline - Date.now();
        if (remaining <= 0) {
          fail(new AuthError('timeout', 'Challenge approval timed out.'));
          return;
        }
        timerId = setTimeout(() => {
          void pollOnce();
        }, Math.min(intervalMs, remaining));
      };

      const pollOnce = async () => {
        if (settled) return;
        if (signal?.aborted) {
          onAbort();
          return;
        }
        if (Date.now() >= deadline) {
          fail(new AuthError('timeout', 'Challenge approval timed out.'));
          return;
        }

        try {
          const body: Record<string, unknown> = { client_id: this.config.clientId };
          if (opts.codeVerifier) {
            body.code_verifier = opts.codeVerifier;
          }

          const res = await fetch(`${this.baseURL}/v1/auth/challenges/${encodeURIComponent(sessionId)}/status/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          });

          if (!res.ok) {
            if (res.status >= 500 || res.status === 429) {
              scheduleNext();
              return;
            }
            const errData = await res.json().catch(() => ({}));
            fail(new AuthError('challenge_status_failed', parseError(errData, 'Failed to check session status.'), res.status));
            return;
          }

          const data = (await res.json()) as Record<string, unknown>;
          const status = typeof data.status === 'string' ? data.status.toUpperCase() : '';

          if (status === 'APPROVED') {
            if (typeof data.access_token !== 'string' || !data.access_token.trim()) {
              fail(new AuthError('invalid_token_response', 'Challenge approved without a valid access_token.'));
              return;
            }
            try {
              const tokenPayload: TokenResponse = {
                access_token: data.access_token,
                refresh_token: typeof data.refresh_token === 'string' ? data.refresh_token : undefined,
                expires_in: typeof data.expires_in === 'number' ? data.expires_in : undefined,
                token_type: typeof data.token_type === 'string' ? data.token_type : undefined,
                scope: typeof data.scope === 'string' ? data.scope : undefined,
                id_token: typeof data.id_token === 'string' ? data.id_token : undefined,
              };
              await this.root.persistTokens(tokenPayload, { flow: 'first_party' });
              succeed(tokenPayload);
            } catch (verifyErr) {
              fail(verifyErr instanceof Error ? verifyErr : new AuthError('token_verification_failed', 'Approved token verification failed.'));
            }
            return;
          }

          if (status === 'REJECTED' || status === 'DENIED') {
            fail(new AuthError('challenge_rejected', 'Challenge was rejected by the user.'));
            return;
          }
          if (status === 'EXPIRED') {
            fail(new AuthError('challenge_expired', 'Challenge session expired.'));
            return;
          }
          if (status === 'CONSUMED') {
            fail(new AuthError('challenge_consumed', 'Challenge session has already been consumed.'));
            return;
          }

          // PENDING or non-terminal state -> continue polling until timeout/abort
          scheduleNext();
        } catch {
          // Transient network error -> retry until deadline/abort
          scheduleNext();
        }
      };

      scheduleNext();
    });
  }

  /**
   * Revokes all active sessions across all Relying Parties (or a specific application)
   * and triggers OIDC Back-Channel Logout fan-out via POST /v1/auth/revoke/.
   */
  async revoke(options: { applicationId?: string; reason?: string; includeCurrent?: boolean } = {}): Promise<{
    status: string;
    subject: string;
    revoked_access: number;
    revoked_refresh: number;
    notified_apps: number;
  }> {
    const token = await this.root.getAccessToken();
    if (!token) throw new AuthError('unauthenticated', 'Must be authenticated to revoke sessions.');

    const res = await fetch(`${this.baseURL}/v1/auth/revoke/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({
        application_id: options.applicationId,
        reason: options.reason || 'user_revoke',
        include_current: Boolean(options.includeCurrent),
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new AuthError('revoke_failed', parseError(err, 'Failed to revoke sessions.'), res.status);
    }

    if (options.includeCurrent) {
      await this.root.clearTokens();
    }

    return res.json();
  }

  /**
   * Revokes a single session by ID (or 'all') via DELETE /v1/auth/sessions/<id>/.
   */
  async revokeSession(sessionId: string): Promise<void> {
    const token = await this.root.getAccessToken();
    if (!token) throw new AuthError('unauthenticated', 'Must be authenticated to revoke a session.');

    const res = await fetch(`${this.baseURL}/v1/auth/sessions/${encodeURIComponent(sessionId)}/`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });

    if (!res.ok && res.status !== 204) {
      const err = await res.json().catch(() => ({}));
      throw new AuthError('revoke_session_failed', parseError(err, 'Failed to revoke session.'), res.status);
    }
  }
}
