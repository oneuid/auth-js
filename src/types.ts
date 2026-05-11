export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  scope: string;
}

export interface UserProfile {
  id: string;
  uid: string;
  email: string;
  username: string;
  first_name: string;
  last_name: string;
}

export interface AuthConfig {
  clientId: string;
  clientSecret?: string; // Optional for public clients
  baseURL: string; // e.g., 'http://localhost:8001' or 'https://api.uid.one'
}

export interface StorageAdapter {
  getItem(key: string): Promise<string | null> | string | null;
  setItem(key: string, value: string): Promise<void> | void;
  removeItem(key: string): Promise<void> | void;
}
