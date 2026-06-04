import { AuthConfig, TokenResponse } from './types';
import { OneUID } from './client';

export class SessionClient {
  constructor(private config: AuthConfig, private root: OneUID) {}

  /**
   * Generates a new challenge session for QR Code display or Extension login
   */
  async create(method: 'QR' | 'EXTENSION' = 'QR', domain?: string): Promise<{ session_id: string; expires_at: string; status: string }> {
    const res = await fetch(`${this.config.baseURL}/v1/auth/challenges/request/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ method, domain })
    });
    
    if (!res.ok) throw new Error("Failed to create challenge session");
    const data = await res.json();
    return {
      session_id: data.token,
      expires_at: data.expires_at,
      status: data.status
    };
  }

  /**
   * Approves a session challenge (requires the caller to be authenticated, e.g., mobile app)
   */
  async approve(sessionId: string): Promise<void> {
    const token = await this.root.getAccessToken();
    if (!token) throw new Error("Must be authenticated to approve a session");

    const res = await fetch(`${this.config.baseURL}/v1/auth/challenges/${sessionId}/approve/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Failed to approve session challenge");
    }
  }

  /**
   * Rejects a session challenge (requires the caller to be authenticated, e.g., mobile app)
   */
  async reject(sessionId: string): Promise<void> {
    const token = await this.root.getAccessToken();
    if (!token) throw new Error("Must be authenticated to reject a session");

    const res = await fetch(`${this.config.baseURL}/v1/auth/challenges/${sessionId}/reject/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      }
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || "Failed to reject session challenge");
    }
  }

  /**
   * Polls the session challenge status until it is approved or expired
   */
  async pollForApproval(sessionId: string, intervalMs: number = 2000): Promise<TokenResponse> {
    return new Promise((resolve, reject) => {
      const intervalId = setInterval(async () => {
        try {
          const res = await fetch(`${this.config.baseURL}/v1/auth/challenges/${sessionId}/status/`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id: this.config.clientId })
          });

          if (!res.ok) {
            clearInterval(intervalId);
            const err = await res.json().catch(() => ({}));
            reject(new Error(err.error || "Failed to check session status"));
            return;
          }

          const data = await res.json();
          
          if (data.status === 'APPROVED' && data.access_token) {
            clearInterval(intervalId);
            await (this.root as any).persistTokens(data);
            resolve(data);
          } else if (data.status === 'EXPIRED') {
            clearInterval(intervalId);
            reject(new Error("Session expired"));
          }
          // If PENDING, keep polling
        } catch (e) {
          clearInterval(intervalId);
          reject(e);
        }
      }, intervalMs);
    });
  }
}
