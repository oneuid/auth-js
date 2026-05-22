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

export interface IdentifyResponse {
  flow: 'SSO_REDIRECT' | 'REGISTER' | 'LOGIN_PASSKEY' | 'LOGIN_FALLBACK';
  next?: 'EMAIL_OTP' | 'MAGIC_LINK' | 'WEBAUTHN_CHALLENGE';
  redirect_url?: string;
  org_name?: string;
  challenge?: any;
  user_id?: string;
  fallback?: string;
  methods?: string[];
  message?: string;
}

export interface VerifyResponse extends TokenResponse {
  user_id: string;
  suggest_passkey?: boolean;
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
