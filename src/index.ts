export interface UIDConfig {
  clientId: string;
  baseUrl?: string;
}

export interface UserProfile {
  first_name: string;
  last_name: string;
  avatar: string;
  locale: string;
  timezone: string;
  metadata: Record<string, any>;
}

export interface User {
  id: string;
  email: string;
  phone: string | null;
  verified: boolean;
  created_at: string;
  profile: UserProfile;
}

export class UID {
  private clientId: string;
  private baseUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;

  constructor(config: UIDConfig) {
    this.clientId = config.clientId;
    // Default to the local Docker container in dev, or the production URL later
    this.baseUrl = config.baseUrl || 'http://localhost:8001';
  }

  /**
   * Logs the user in using the standard OAuth2 Password Grant flow
   */
  async login(email: string, password: string): Promise<{ access_token: string, refresh_token: string }> {
    const params = new URLSearchParams();
    params.append('grant_type', 'password');
    params.append('client_id', this.clientId);
    params.append('username', email);
    params.append('password', password);

    const response = await fetch(`${this.baseUrl}/o/token/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params,
    });

    if (!response.ok) {
      throw new Error('Authentication failed');
    }

    const data = await response.json();
    this.accessToken = data.access_token;
    this.refreshToken = data.refresh_token;
    
    return data;
  }

  /**
   * Fetches the logged-in user's data and profile from the /me/ API
   */
  async me(): Promise<User> {
    if (!this.accessToken) {
      throw new Error('You must login first. No access token found.');
    }
    
    const response = await fetch(`${this.baseUrl}/v1/auth/me/`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${this.accessToken}`,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error('Failed to fetch user profile');
    }
    
    return response.json();
  }

  /**
   * Manually sets the access token (e.g. if loaded from localStorage)
   */
  setToken(token: string) {
    this.accessToken = token;
  }
}
