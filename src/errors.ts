const SENSITIVE_JWT_REGEX = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b/g;
const SENSITIVE_FIELD_REGEX = /("(?:access_token|refresh_token|id_token|client_secret|kekB64|password)"\s*:\s*)"[^"]*"/gi;

/**
 * Redacts JWTs and credential fields from error messages so secrets are never leaked into logs.
 */
export function redactSensitive(message: string): string {
  return message
    .replace(SENSITIVE_FIELD_REGEX, '$1"[REDACTED]"')
    .replace(SENSITIVE_JWT_REGEX, '[REDACTED_JWT]');
}

/**
 * Typed authentication error without raw response bodies or token material.
 */
export class AuthError extends Error {
  public readonly code: string;
  public readonly status?: number;

  constructor(code: string, message: string, status?: number) {
    super(redactSensitive(message));
    this.name = 'AuthError';
    this.code = code;
    this.status = status;
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}

/**
 * Extracts a safe, sanitized human-readable error message from a structured API error payload.
 */
export function parseError(errorData: unknown, fallback: string): string {
  if (!errorData) return fallback;
  let candidate: string | undefined;

  if (typeof errorData === 'string') {
    candidate = errorData;
  } else if (typeof errorData === 'object') {
    const obj = errorData as Record<string, unknown>;
    if (typeof obj.error_description === 'string') {
      candidate = obj.error_description;
    } else if (typeof obj.detail === 'string') {
      candidate = obj.detail;
    } else if (typeof obj.message === 'string') {
      candidate = obj.message;
    } else if (typeof obj.error === 'string') {
      candidate = obj.error;
    } else {
      for (const key of Object.keys(obj)) {
        if (key === 'access_token' || key === 'refresh_token' || key === 'id_token' || key === 'client_secret') {
          continue;
        }
        const val = obj[key];
        if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'string') {
          candidate = val[0];
          break;
        }
        if (typeof val === 'string') {
          candidate = val;
          break;
        }
      }
    }
  }

  if (!candidate || !candidate.trim()) {
    return fallback;
  }

  const sanitized = redactSensitive(candidate.trim());
  return sanitized.length > 200 ? `${sanitized.slice(0, 197)}...` : sanitized;
}
