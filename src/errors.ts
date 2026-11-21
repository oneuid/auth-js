const SENSITIVE_JWT_REGEX = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b/g;
const SENSITIVE_FIELD_REGEX = /("(?:access_token|refresh_token|id_token|client_secret|kekB64|password)"\s*:\s*)"[^"]*"/gi;

export const SUPPORTED_LOCALES = [
  'ar',
  'de',
  'en',
  'es',
  'fr',
  'it',
  'ja',
  'ko',
  'pt',
  'ru',
  'th',
  'vi',
  'zh-hans',
  'zh-hant',
] as const;

export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];

export type AuthErrorCode =
  | 'access_denied'
  | 'state_mismatch'
  | 'state_expired'
  | 'invalid_callback'
  | 'oauth_error'
  | 'two_factor_required'
  | 'unauthenticated'
  | 'network_error'
  | 'not_implemented'
  | 'unavailable'
  | (string & {});

/**
 * Resolves a BCP-47 locale tag to one of the 14 canonical OneUID locales.
 */
export function resolveLocale(locale?: string): SupportedLocale {
  const raw = (
    locale ||
    (typeof document !== 'undefined' ? document.documentElement?.lang : '') ||
    (typeof navigator !== 'undefined' ? navigator.language : '') ||
    'en'
  )
    .trim()
    .toLowerCase()
    .replace(/_/g, '-');

  if (!raw) return 'en';
  if ((SUPPORTED_LOCALES as readonly string[]).includes(raw)) {
    return raw as SupportedLocale;
  }

  if (raw.startsWith('zh')) {
    if (raw.includes('hant') || raw.includes('tw') || raw.includes('hk') || raw.includes('mo')) {
      return 'zh-hant';
    }
    return 'zh-hans';
  }

  const base = raw.split('-')[0];
  if ((SUPPORTED_LOCALES as readonly string[]).includes(base)) {
    return base as SupportedLocale;
  }
  return 'en';
}

export const RETRY_LABELS: Record<SupportedLocale, string> = {
  ar: 'إعادة المحاولة',
  de: 'Erneut versuchen',
  en: 'Retry',
  es: 'Reintentar',
  fr: 'Réessayer',
  it: 'Riprova',
  ja: '再試行',
  ko: '다시 시도',
  pt: 'Tentar novamente',
  ru: 'Повторить',
  th: 'ลองอีกครั้ง',
  vi: 'Thử lại',
  'zh-hans': '重试',
  'zh-hant': '重試',
};

export const AUTH_ERROR_MESSAGES: Record<
  'access_denied' | 'expired' | 'invalid_state' | 'mfa_required' | 'unauthenticated' | 'network' | 'not_implemented' | 'unavailable',
  Record<SupportedLocale, string>
> = {
  access_denied: {
    ar: 'تم رفض طلب تسجيل الدخول.',
    de: 'Anmeldeanfrage wurde abgelehnt.',
    en: 'Sign-in request was denied.',
    es: 'Se denegó la solicitud de inicio de sesión.',
    fr: 'La demande de connexion a été refusée.',
    it: 'La richiesta di accesso è stata rifiutata.',
    ja: 'サインインのリクエストが拒否されました。',
    ko: '로그인 요청이 거부되었습니다.',
    pt: 'A solicitação de login foi negada.',
    ru: 'Запрос на вход был отклонен.',
    th: 'คำขอเข้าสู่ระบบถูกปฏิเสธ',
    vi: 'Yêu cầu đăng nhập đã bị từ chối.',
    'zh-hans': '登录请求已被拒绝。',
    'zh-hant': '登入請求已被拒絕。',
  },
  expired: {
    ar: 'انتهت صلاحية جلسة تسجيل الدخول. يرجى المحاولة مرة أخرى.',
    de: 'Die Anmeldesitzung ist abgelaufen. Bitte versuchen Sie es erneut.',
    en: 'Your sign-in session has expired. Please try again.',
    es: 'Tu sesión de inicio de sesión ha caducado. Inténtalo de nuevo.',
    fr: 'Votre session de connexion a expiré. Veuillez réessayer.',
    it: 'La sessione di accesso è scaduta. Riprova.',
    ja: 'サインインの有効期限が切れました。もう一度お試しください。',
    ko: '로그인 세션이 만료되었습니다. 다시 시도해 주세요.',
    pt: 'Sua sessão de login expirou. Tente novamente.',
    ru: 'Срок действия сеанса входа истек. Повторите попытку.',
    th: 'เซสชันการเข้าสู่ระบบหมดอายุแล้ว โปรดลองอีกครั้ง',
    vi: 'Phiên đăng nhập đã hết hạn. Vui lòng thử lại.',
    'zh-hans': '登录会话已过期，请重试。',
    'zh-hant': '登入工作階段已過期，請重試。',
  },
  invalid_state: {
    ar: 'تعذر التحقق من طلب تسجيل الدخول. يرجى البدء من جديد.',
    de: 'Die Anmeldeanfrage konnte nicht verifiziert werden. Bitte starten Sie erneut.',
    en: 'Could not verify the sign-in request. Please start again.',
    es: 'No se pudo verificar la solicitud de inicio de sesión. Empieza de nuevo.',
    fr: 'Impossible de vérifier la demande de connexion. Veuillez recommencer.',
    it: 'Impossibile verificare la richiesta di accesso. Ricomincia.',
    ja: 'サインインリクエストを検証できませんでした。最初からやり直してください。',
    ko: '로그인 요청을 확인할 수 없습니다. 다시 시작해 주세요.',
    pt: 'Não foi possível verificar a solicitação de login. Comece novamente.',
    ru: 'Не удалось проверить запрос на вход. Начните заново.',
    th: 'ไม่สามารถตรวจสอบคำขอเข้าสู่ระบบได้ โปรดเริ่มต้นใหม่',
    vi: 'Không thể xác minh yêu cầu đăng nhập. Vui lòng bắt đầu lại.',
    'zh-hans': '无法验证登录请求，请重新开始。',
    'zh-hant': '無法驗證登入請求，請重新開始。',
  },
  mfa_required: {
    ar: 'مطلوب التحقق بخطوتين لإكمال تسجيل الدخول.',
    de: 'Für die Anmeldung ist eine Zwei-Faktor-Authentifizierung erforderlich.',
    en: 'Two-factor verification is required to complete sign-in.',
    es: 'Se requiere verificación en dos pasos para completar el inicio de sesión.',
    fr: 'La vérification en deux étapes est requise pour terminer la connexion.',
    it: 'È richiesta la verifica in due passaggi per completare l’accesso.',
    ja: 'サインインを完了するには2段階認証が必要です。',
    ko: '로그인을 완료하려면 2단계 인증이 필요합니다.',
    pt: 'A verificação em duas etapas é necessária para concluir o login.',
    ru: 'Для завершения входа требуется двухфакторная проверка.',
    th: 'ต้องยืนยันตัวตนสองขั้นตอนเพื่อเข้าสู่ระบบให้เสร็จสมบูรณ์',
    vi: 'Cần xác minh hai bước để hoàn tất đăng nhập.',
    'zh-hans': '需要完成两步验证才能继续登录。',
    'zh-hant': '需要完成兩步驟驗證才能繼續登入。',
  },
  unauthenticated: {
    ar: 'يرجى تسجيل الدخول للمتابعة.',
    de: 'Bitte melden Sie sich an, um fortzufahren.',
    en: 'Please sign in to continue.',
    es: 'Inicia sesión para continuar.',
    fr: 'Veuillez vous connecter pour continuer.',
    it: 'Accedi per continuare.',
    ja: '続行するにはサインインしてください。',
    ko: '계속하려면 로그인해 주세요.',
    pt: 'Faça login para continuar.',
    ru: 'Войдите, чтобы продолжить.',
    th: 'โปรดเข้าสู่ระบบเพื่อดำเนินการต่อ',
    vi: 'Vui lòng đăng nhập để tiếp tục.',
    'zh-hans': '请先登录以继续。',
    'zh-hant': '請先登入以繼續。',
  },
  network: {
    ar: 'خطأ في الشبكة. يرجى التحقق من اتصالك والمحاولة مرة أخرى.',
    de: 'Netzwerkfehler. Bitte überprüfen Sie Ihre Verbindung und versuchen Sie es erneut.',
    en: 'Network error. Please check your connection and try again.',
    es: 'Error de red. Comprueba tu conexión e inténtalo de nuevo.',
    fr: 'Erreur réseau. Vérifiez votre connexion et réessayez.',
    it: 'Errore di rete. Controlla la connessione e riprova.',
    ja: 'ネットワークエラーです。接続を確認してもう一度お試しください。',
    ko: '네트워크 오류입니다. 연결을 확인한 후 다시 시도해 주세요.',
    pt: 'Erro de rede. Verifique sua conexão e tente novamente.',
    ru: 'Ошибка сети. Проверьте подключение и повторите попытку.',
    th: 'เกิดข้อผิดพลาดของเครือข่าย โปรดตรวจสอบการเชื่อมต่อแล้วลองอีกครั้ง',
    vi: 'Lỗi mạng. Vui lòng kiểm tra kết nối và thử lại.',
    'zh-hans': '网络错误，请检查连接后重试。',
    'zh-hant': '網路錯誤，請檢查連線後重試。',
  },
  not_implemented: {
    ar: 'هذه الميزة غير متوفرة بعد في الخادم.',
    de: 'Diese Funktion ist auf dem Server noch nicht verfügbar.',
    en: 'This feature is not available on the server yet.',
    es: 'Esta función aún no está disponible en el servidor.',
    fr: 'Cette fonctionnalité n’est pas encore disponible sur le serveur.',
    it: 'Questa funzione non è ancora disponibile sul server.',
    ja: 'この機能はまだサーバーで利用できません。',
    ko: '이 기능은 아직 서버에서 사용할 수 없습니다.',
    pt: 'Este recurso ainda não está disponível no servidor.',
    ru: 'Эта функция пока недоступна на сервере.',
    th: 'ฟีเจอร์นี้ยังไม่พร้อมใช้งานบนเซิร์ฟเวอร์',
    vi: 'Tính năng này hiện chưa khả dụng trên máy chủ.',
    'zh-hans': '服务器暂不支持此功能。',
    'zh-hant': '伺服器暫不支援此功能。',
  },
  unavailable: {
    ar: 'تسجيل الدخول غير متاح حاليًا.',
    de: 'Anmeldung ist nicht verfügbar.',
    en: 'Sign-in is unavailable.',
    es: 'El inicio de sesión no está disponible.',
    fr: 'La connexion est indisponible.',
    it: 'Accesso non disponibile.',
    ja: 'サインインは現在利用できません。',
    ko: '로그인을 사용할 수 없습니다.',
    pt: 'O login está indisponível.',
    ru: 'Вход недоступен.',
    th: 'ไม่สามารถเข้าสู่ระบบได้ในขณะนี้',
    vi: 'Đăng nhập hiện không khả dụng.',
    'zh-hans': '登录暂不可用。',
    'zh-hant': '登入暫不可用。',
  },
};

/**
 * Returns a localized, user-safe error message, retry button label, and recovery action
 * for common `AuthError.code` values across all 14 canonical locales.
 */
export function getAuthErrorMessage(
  code: string,
  locale?: string
): { message: string; retryLabel: string; action: 'retry' | 'reauth' | 'contact_support' } {
  const lang = resolveLocale(locale);
  const retryLabel = RETRY_LABELS[lang] || RETRY_LABELS.en;
  const normalized = (code || '').toLowerCase();

  if (normalized === 'access_denied' || normalized === 'challenge_rejected') {
    return { message: AUTH_ERROR_MESSAGES.access_denied[lang], retryLabel, action: 'reauth' };
  }
  if (normalized === 'state_expired' || normalized === 'challenge_expired' || normalized === 'token_expired' || normalized === 'timeout') {
    return { message: AUTH_ERROR_MESSAGES.expired[lang], retryLabel, action: 'reauth' };
  }
  if (normalized === 'state_mismatch' || normalized === 'invalid_callback' || normalized === 'invalid_jwt_nonce') {
    return { message: AUTH_ERROR_MESSAGES.invalid_state[lang], retryLabel, action: 'reauth' };
  }
  if (normalized === 'two_factor_required') {
    return { message: AUTH_ERROR_MESSAGES.mfa_required[lang], retryLabel, action: 'retry' };
  }
  if (normalized === 'unauthenticated') {
    return { message: AUTH_ERROR_MESSAGES.unauthenticated[lang], retryLabel, action: 'reauth' };
  }
  if (normalized === 'network_error' || normalized === 'kms_unreachable' || normalized === 'kms_unavailable') {
    return { message: AUTH_ERROR_MESSAGES.network[lang], retryLabel, action: 'retry' };
  }
  if (normalized === 'not_implemented') {
    return { message: AUTH_ERROR_MESSAGES.not_implemented[lang], retryLabel, action: 'contact_support' };
  }

  return { message: AUTH_ERROR_MESSAGES.unavailable[lang], retryLabel, action: 'retry' };
}

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
  public readonly code: AuthErrorCode;
  public readonly status?: number;
  public readonly safeMessage: string;

  constructor(code: AuthErrorCode, message: string, status?: number) {
    const sanitized = redactSensitive(message);
    super(sanitized);
    this.name = 'AuthError';
    this.code = code;
    this.status = status;
    this.safeMessage = sanitized;
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
