export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  scope?: string;
  id_token?: string;
}

export interface OIDCDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  revocation_endpoint?: string;
  userinfo_endpoint?: string;
  code_challenge_methods_supported?: string[];
}

export interface AuthorizeOptions {
  scope?: string;
  state?: string;
  nonce?: string;
  prompt?: string;
}

export interface AuthorizationStartResult {
  url: string;
  state: string;
  nonce: string;
  codeChallenge: string;
}

export interface UserProfile {
  id: string;
  uid: string;
  sovereign_id: string;
  email?: string;
  username: string;
  first_name: string;
  last_name: string;
  zk_mode?: boolean;
  is_accredited_investor?: boolean;
  accreditation_level?: string;
}

export interface IdentifyChallenge {
  challenge: string;
  rpId?: string;
  timeout?: number;
  userVerification?: string;
  allowCredentials?: Array<{
    id: string;
    type: string;
    transports?: string[];
  }>;
  auth_session_id?: string;
}

export interface IdentifyResponse {
  flow: 'SSO_REDIRECT' | 'REGISTER' | 'LOGIN_PASSKEY' | 'LOGIN_FALLBACK' | 'LOGIN_TOTP';
  next?: 'EMAIL_OTP' | 'MAGIC_LINK' | 'WEBAUTHN_CHALLENGE';
  redirect_url?: string;
  org_name?: string;
  challenge?: IdentifyChallenge;
  user_id?: string;
  /** Ephemeral challenge or 2FA flow token, not a persistent session credential. */
  token?: string;
  fallback?: string;
  methods?: string[];
  message?: string;
  /** Ephemeral 2FA session token, not a persistent session credential. */
  session_token?: string;
}

export interface VerifyResponse extends TokenResponse {
  user_id: string;
  suggest_passkey?: boolean;
}

export interface VerifyPasswordResult {
  status: 'PENDING_2FA' | 'SETUP_REQUIRED';
  session_token?: string;
  setup_token?: string;
  available_methods?: Array<'passkey' | 'totp' | 'backup_code'>;
  preferred_method?: 'passkey' | 'totp' | 'backup_code';
  message?: string;
  passkey_options?: IdentifyChallenge;
}

export interface Verify2FAResponse {
  token?: TokenResponse | string;
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  scope?: string;
  id_token?: string;
  user_id?: string;
  suggest_passkey?: boolean;
  message?: string;
}

export interface RegisterResponse {
  user_id?: string;
  email: string;
  verification_required: boolean;
  message?: string;
}

export interface ChallengeMetadata {
  session_id: string;
  method: string;
  domain?: string | null;
  origin?: string | null;
  device?: string | null;
  app_name?: string | null;
  scopes?: string[];
  expires_at: string;
  match_number?: string;
  metadata?: Record<string, unknown>;
}

export interface ChallengeApproveOptions {
  matchNumber: string;
  encryptedPayload?: string;
  signatureBlock?: string;
  zkMode?: boolean;
  locationEnabled?: boolean;
}

export interface ChallengePollOptions {
  intervalMs?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
  codeVerifier?: string;
}

export interface ActiveSession {
  id: string;
  application: string;
  client_id: string;
  scope: string;
  created_at: string;
  expires_at: string | null;
  is_current: boolean;
}

export type AuthCallbackState =
  | { status: 'idle' }
  | { status: 'completing' }
  | { status: 'authenticated'; tokens: TokenResponse }
  | { status: 'error'; code: string; message: string; retryable: boolean };

export interface AuthConfig {
  clientId: string;
  /**
   * Optional for confidential server-side clients only.
   * Ignored and never transmitted in browser runtimes.
   */
  clientSecret?: string;
  /**
   * HTTPS base URL (defaults to 'https://auth.uid.one').
   * Plain HTTP is allowed only for localhost/127.0.0.1 development.
   */
  baseURL?: string;
  /** Optional resource API host override (e.g., 'https://api.uid.one'). Defaults to baseURL. */
  apiURL?: string;
  /** Optional explicit OIDC issuer override (defaults to discovered issuer or 'https://auth.uid.one'). */
  issuer?: string;
  /** Optional explicit JWKS URI override (defaults to discovered jwks_uri). */
  jwksUri?: string;
  /** Optional storage adapter override. Defaults to in-memory storage. */
  storage?: StorageAdapter;
  /** Optional JWT clock tolerance in seconds (default: 0). */
  clockToleranceSec?: number;
  /**
   * Server-only escape hatch for legacy password grant.
   * Ignored in browser runtimes; never bypasses 2FA checks.
   */
  allowUnsafePasswordGrant?: boolean;
}

export type ButtonTheme = 'dark' | 'light' | 'brand';
export type ButtonSize = 'small' | 'medium' | 'large';
export type ButtonProvider = 'uid' | 'google' | 'facebook' | 'apple';

export interface ButtonOptions {
  provider?: ButtonProvider;
  redirectUri: string;
  theme?: ButtonTheme;
  size?: ButtonSize;
  locale?: string;
  label?: string;
  scope?: string;
  onProviderClick?: (provider: string) => void | Promise<void>;
}

export interface StorageAdapter {
  getItem(key: string): Promise<string | null> | string | null;
  setItem(key: string, value: string): Promise<void> | void;
  removeItem(key: string): Promise<void> | void;
}

export interface VaultRecord {
  id: string;
  title: string;
  type: string;
  payload: string;
  session_key?: string | null;
  sync_status: 'PENDING' | 'COMPLETED';
  issuer?: string | null;
  signature?: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface DeviceVaultKey {
  id: string;
  device: string;
  wrapped_mvk: string;
  created_at: string;
}

export interface UserPublicKey {
  status: 'success' | 'error';
  user_id: string;
  device_id: string;
  device_name: string;
  public_key: string;
}
