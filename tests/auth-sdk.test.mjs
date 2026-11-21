import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import {
  OneUID,
  AuthError,
  getAuthErrorMessage,
  SUPPORTED_LOCALES,
  MemoryStorageAdapter,
  LocalStorageAdapter,
  importPublicKey,
  importPrivateKey,
} from '../dist/index.mjs';

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function signRs256(privateKeyPem, header, payload) {
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const input = `${h}.${p}`;
  const sig = crypto.sign('RSA-SHA256', Buffer.from(input), privateKeyPem);
  return `${input}.${b64url(sig)}`;
}

function signHs256(secret, header, payload) {
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(payload));
  const input = `${h}.${p}`;
  const sig = crypto.createHmac('sha256', secret).update(input).digest();
  return `${input}.${b64url(sig)}`;
}

function createMockServer(handlers) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const rawBody = Buffer.concat(chunks).toString('utf8');
    const url = new URL(req.url, `http://${req.headers.host}`);
    requests.push({
      method: req.method,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams.entries()),
      headers: req.headers,
      body: rawBody,
    });

    const key = `${req.method} ${url.pathname}`;
    const handler = handlers[key] || handlers[url.pathname];
    if (!handler) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }
    await handler({ req, res, url, rawBody, requests });
  });

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        baseURL: `http://127.0.0.1:${addr.port}`,
        requests,
        close: () => new Promise((r) => server.close(r)),
      });
    });
  });
}

function generateTestRsaKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  const jwk = publicKey.export({ format: 'jwk' });
  jwk.kid = 'test-key-1';
  jwk.use = 'sig';
  jwk.alg = 'RS256';
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  return { jwk, privatePem };
}

function createMockDom() {
  const elementsById = new Map();
  const styles = [];
  const metas = [];

  class MockElement {
    constructor(tagName) {
      this.tagName = tagName.toUpperCase();
      this.children = [];
      this.parentNode = null;
      this.attributes = new Map();
      this.listeners = new Map();
      this.style = {};
      this.className = '';
      this.id = '';
      this.type = '';
      this.lang = '';
      this.dir = '';
      this.disabled = false;
      this._textContent = '';
      this._innerHTML = '';
    }
    set textContent(v) {
      this._textContent = String(v);
    }
    get textContent() {
      if (this.children.length > 0 && !this._textContent) {
        return this.children.map((c) => c.textContent).join(' ');
      }
      return this._textContent;
    }
    set innerHTML(v) {
      this._innerHTML = String(v);
      if (v === '') this.children = [];
    }
    get innerHTML() {
      return this._innerHTML;
    }
    appendChild(child) {
      child.parentNode = this;
      this.children.push(child);
      if (child.tagName === 'STYLE') styles.push(child);
      if (child.tagName === 'META') metas.push(child);
      return child;
    }
    removeChild(child) {
      this.children = this.children.filter((c) => c !== child);
      child.parentNode = null;
    }
    setAttribute(k, v) {
      this.attributes.set(k, String(v));
    }
    getAttribute(k) {
      return this.attributes.get(k) ?? null;
    }
    removeAttribute(k) {
      this.attributes.delete(k);
    }
    addEventListener(type, fn) {
      if (!this.listeners.has(type)) this.listeners.set(type, []);
      this.listeners.get(type).push(fn);
    }
    click() {
      if (this.disabled) return;
      for (const fn of this.listeners.get('click') || []) {
        fn();
      }
    }
  }

  const head = new MockElement('head');
  const doc = {
    documentElement: { lang: 'en' },
    head,
    createElement: (tag) => new MockElement(tag),
    getElementById: (id) => elementsById.get(id) || styles.find((s) => s.id === id) || null,
    querySelector: (sel) => {
      if (sel.includes('uid-passkey-native')) {
        return metas.find((m) => m.name === 'uid-passkey-native') || null;
      }
      return null;
    },
  };

  const localStore = new Map();
  const sessionStore = new Map();
  const win = {
    location: { href: 'https://app.example.com/' },
    crypto: globalThis.crypto,
    localStorage: {
      getItem: (k) => localStore.get(k) ?? null,
      setItem: (k, v) => localStore.set(k, v),
      removeItem: (k) => localStore.delete(k),
    },
    sessionStorage: {
      getItem: (k) => sessionStore.get(k) ?? null,
      setItem: (k, v) => sessionStore.set(k, v),
      removeItem: (k) => sessionStore.delete(k),
    },
  };

  return {
    window: win,
    document: doc,
    registerContainer: (id) => {
      const el = new MockElement('div');
      el.id = id;
      elementsById.set(id, el);
      return el;
    },
    styles,
    localStore,
    sessionStore,
  };
}

async function withMockBrowser(dom, fn) {
  const prevWin = globalThis.window;
  const prevDoc = globalThis.document;
  globalThis.window = dom.window;
  globalThis.document = dom.document;
  try {
    return await fn();
  } finally {
    if (prevWin === undefined) delete globalThis.window;
    else globalThis.window = prevWin;
    if (prevDoc === undefined) delete globalThis.document;
    else globalThis.document = prevDoc;
  }
}

test('Issue #1: PKCE S256 startAuthorization, handleRedirectCallback, state mismatch, missing verifier, and HTTPS enforcement', async () => {
  const { jwk, privatePem } = generateTestRsaKeypair();
  let lastTokenBody = null;
  let capturedNonce = null;

  const mock = await createMockServer({
    'GET /.well-known/openid-configuration': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          issuer: mock.baseURL,
          authorization_endpoint: `${mock.baseURL}/oauth/authorize`,
          token_endpoint: `${mock.baseURL}/oauth/token`,
          jwks_uri: `${mock.baseURL}/oauth/certs`,
          revocation_endpoint: `${mock.baseURL}/oauth/revoke`,
        })
      );
    },
    'GET /oauth/certs': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
    },
    'POST /oauth/token': ({ res, rawBody }) => {
      lastTokenBody = Object.fromEntries(new URLSearchParams(rawBody).entries());
      const now = Math.floor(Date.now() / 1000);
      const idToken = signRs256(
        privatePem,
        { alg: 'RS256', kid: jwk.kid, typ: 'JWT' },
        {
          iss: mock.baseURL,
          sub: 'user-1',
          aud: 'app-client',
          exp: now + 300,
          iat: now,
          nonce: capturedNonce,
        }
      );
      const accessToken = signRs256(
        privatePem,
        { alg: 'RS256', kid: jwk.kid, typ: 'JWT' },
        {
          iss: mock.baseURL,
          sub: 'user-1',
          aud: 'app-client',
          exp: now + 300,
          iat: now,
        }
      );
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          access_token: accessToken,
          refresh_token: 'refresh-123',
          id_token: idToken,
          expires_in: 300,
          token_type: 'Bearer',
          scope: 'openid profile email',
        })
      );
    },
  });

  try {
    // Reject non-HTTPS non-localhost baseURL & redirectUri
    assert.throws(
      () => new OneUID({ baseURL: 'http://auth.example.com', clientId: 'app-client' }),
      (err) => err instanceof AuthError && err.code === 'insecure_url'
    );

    const storage = new MemoryStorageAdapter();
    const auth = new OneUID({ baseURL: mock.baseURL, clientId: 'app-client' }, storage);

    await assert.rejects(
      () => auth.startAuthorization('http://evil.example.com/cb'),
      (err) => err instanceof AuthError && err.code === 'insecure_url'
    );

    // Reject loginWithCode without code_verifier for public client
    await assert.rejects(
      () => auth.loginWithCode('code-123', 'https://app.example.com/cb'),
      (err) => err instanceof AuthError && err.code === 'missing_code_verifier'
    );

    // Reject plain PKCE
    await assert.rejects(
      () => auth.startAuthorization('https://app.example.com/cb', { codeChallengeMethod: 'plain' }),
      (err) => err instanceof AuthError && err.code === 'unsupported_pkce_method'
    );

    // Start valid PKCE S256 authorization
    const started = await auth.startAuthorization('https://app.example.com/cb');
    const parsed = new URL(started.url);
    assert.equal(parsed.searchParams.get('response_type'), 'code');
    assert.equal(parsed.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(parsed.searchParams.get('code_challenge'));
    assert.equal(parsed.searchParams.get('state'), started.state);
    assert.equal(parsed.searchParams.get('nonce'), started.nonce);

    // Mismatched state fails closed without calling /oauth/token
    const countBefore = mock.requests.length;
    await assert.rejects(
      () => auth.handleRedirectCallback('https://app.example.com/cb?code=abc&state=wrong-state'),
      (err) => err instanceof AuthError && err.code === 'state_mismatch'
    );
    assert.equal(mock.requests.length, countBefore);

    // Valid callback exchanges code with code_verifier and verifies nonce
    capturedNonce = started.nonce;
    const tokens = await auth.handleRedirectCallback(
      `https://app.example.com/cb?code=auth-code-1&state=${encodeURIComponent(started.state)}`
    );
    assert.ok(tokens.access_token);
    assert.ok(lastTokenBody.code_verifier && lastTokenBody.code_verifier.length >= 43);
    assert.equal(lastTokenBody.client_secret, undefined);

    // Nonce mismatch on id_token fails closed
    const started2 = await auth.startAuthorization('https://app.example.com/cb');
    capturedNonce = 'wrong-nonce-from-attacker';
    await assert.rejects(
      () =>
        auth.handleRedirectCallback(
          `https://app.example.com/cb?code=auth-code-2&state=${encodeURIComponent(started2.state)}`
        ),
      (err) => err instanceof AuthError && err.code === 'invalid_jwt_nonce'
    );
  } finally {
    await mock.close();
  }
});

test('Issue #2: loginWithPassword fails closed when 2FA is required; verifyPassword + verify2FA persists only after step 2', async () => {
  const { jwk, privatePem } = generateTestRsaKeypair();
  const mock = await createMockServer({
    'GET /.well-known/openid-configuration': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          issuer: mock.baseURL,
          authorization_endpoint: `${mock.baseURL}/oauth/authorize`,
          token_endpoint: `${mock.baseURL}/oauth/token`,
          jwks_uri: `${mock.baseURL}/oauth/certs`,
        })
      );
    },
    'GET /oauth/certs': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
    },
    'POST /v1/auth/verify-password/': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'PENDING_2FA',
          session_token: 'sess-2fa-1',
          available_methods: ['totp'],
          preferred_method: 'totp',
        })
      );
    },
    'POST /v1/auth/verify-2fa/': ({ res }) => {
      const now = Math.floor(Date.now() / 1000);
      const accessToken = signRs256(
        privatePem,
        { alg: 'RS256', kid: jwk.kid, typ: 'JWT' },
        { iss: mock.baseURL, sub: 'u-1', aud: 'app-client', exp: now + 300, iat: now }
      );
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          token: {
            access_token: accessToken,
            refresh_token: 'rt-2fa',
            expires_in: 300,
            token_type: 'Bearer',
            scope: 'openid',
          },
          user_id: 'u-1',
        })
      );
    },
  });

  try {
    const storage = new MemoryStorageAdapter();
    const auth = new OneUID({ baseURL: mock.baseURL, clientId: 'app-client' }, storage);

    await assert.rejects(
      () => auth.loginWithPassword('user@example.com', 'test-pass'),
      (err) => err instanceof AuthError && err.code === 'password_grant_disabled'
    );
    assert.equal(await auth.getAccessToken(), null);

    // Even with server escape hatch, 2FA challenge blocks password-only grant
    const serverAuth = new OneUID(
      { baseURL: mock.baseURL, clientId: 'app-client', allowUnsafePasswordGrant: true },
      storage
    );
    await assert.rejects(
      () => serverAuth.loginWithPassword('user@example.com', 'test-pass'),
      (err) => err instanceof AuthError && err.code === 'two_factor_required'
    );
    assert.equal(await serverAuth.getAccessToken(), null);

    // Two-step path persists only after verify2FA
    const step1 = await auth.verifyPassword('user@example.com', 'test-pass');
    assert.equal(step1.status, 'PENDING_2FA');
    assert.equal(await auth.getAccessToken(), null);

    await auth.verify2FA({
      session_token: step1.session_token,
      method: 'totp',
      code: '123456',
    });
    assert.ok(await auth.getAccessToken());
  } finally {
    await mock.close();
  }
});

test('Issue #3: JWKS rejects forged/HS256/none/wrong-iss/wrong-aud/expired tokens; auto-refreshes expired token; logout revokes refresh token', async () => {
  const { jwk, privatePem } = generateTestRsaKeypair();
  const { privatePem: roguePem } = generateTestRsaKeypair();
  let refreshCount = 0;
  const revokedTokens = [];

  const mock = await createMockServer({
    'GET /.well-known/openid-configuration': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          issuer: mock.baseURL,
          authorization_endpoint: `${mock.baseURL}/oauth/authorize`,
          token_endpoint: `${mock.baseURL}/oauth/token`,
          jwks_uri: `${mock.baseURL}/oauth/certs`,
          revocation_endpoint: `${mock.baseURL}/oauth/revoke`,
        })
      );
    },
    'GET /oauth/certs': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
    },
    'POST /oauth/token': ({ res, rawBody }) => {
      const form = Object.fromEntries(new URLSearchParams(rawBody).entries());
      if (form.grant_type === 'refresh_token') {
        refreshCount += 1;
        if (form.refresh_token === 'bad-refresh') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant' }));
          return;
        }
        const now = Math.floor(Date.now() / 1000);
        const freshAccess = signRs256(
          privatePem,
          { alg: 'RS256', kid: jwk.kid, typ: 'JWT' },
          { iss: mock.baseURL, sub: 'u-1', aud: 'app-client', exp: now + 600, iat: now, tag: 'refreshed' }
        );
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            access_token: freshAccess,
            refresh_token: 'rt-new',
            expires_in: 600,
          })
        );
      }
    },
    'POST /oauth/revoke': ({ res, rawBody }) => {
      const form = Object.fromEntries(new URLSearchParams(rawBody).entries());
      revokedTokens.push({ token: form.token, hint: form.token_type_hint });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'revoked' }));
    },
  });

  try {
    const storage = new MemoryStorageAdapter();
    const auth = new OneUID({ baseURL: mock.baseURL, clientId: 'app-client' }, storage);
    const now = Math.floor(Date.now() / 1000);

    // 1. Reject alg=none
    const noneJwt = `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(
      JSON.stringify({ iss: mock.baseURL, aud: 'app-client', exp: now + 300 })
    )}.`;
    await assert.rejects(() => auth.persistTokens({ access_token: noneJwt }), (e) => e.code === 'disallowed_jwt_alg');

    // 2. Reject HS256
    const hsJwt = signHs256('secret', { alg: 'HS256', typ: 'JWT' }, { iss: mock.baseURL, aud: 'app-client', exp: now + 300 });
    await assert.rejects(() => auth.persistTokens({ access_token: hsJwt }), (e) => e.code === 'disallowed_jwt_alg');

    // 3. Reject wrong signature
    const badSigJwt = signRs256(roguePem, { alg: 'RS256', kid: jwk.kid, typ: 'JWT' }, { iss: mock.baseURL, aud: 'app-client', exp: now + 300 });
    await assert.rejects(() => auth.persistTokens({ access_token: badSigJwt }), (e) => e.code === 'invalid_jwt_signature');

    // 4. Reject wrong iss & wrong aud & expired exp
    const wrongIss = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: 'https://evil.example', aud: 'app-client', exp: now + 300 });
    await assert.rejects(() => auth.persistTokens({ access_token: wrongIss }), (e) => e.code === 'invalid_jwt_iss');

    const wrongAud = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'other-client', exp: now + 300 });
    await assert.rejects(() => auth.persistTokens({ access_token: wrongAud }), (e) => e.code === 'invalid_jwt_aud');

    const expiredJwt = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'app-client', exp: now - 10 });
    await assert.rejects(() => auth.persistTokens({ access_token: expiredJwt }), (e) => e.code === 'token_expired');

    assert.equal(await auth.getAccessToken(), null);

    // 5. Near-expired access token refreshes once via getAccessToken
    const nearExpiryJwt = signRs256(
      privatePem,
      { alg: 'RS256', kid: jwk.kid, typ: 'JWT' },
      { iss: mock.baseURL, sub: 'u-1', aud: 'app-client', exp: now + 5, iat: now - 55 }
    );
    await auth.persistTokens({ access_token: nearExpiryJwt, refresh_token: 'rt-initial', expires_in: 5 });

    // Storage keys are namespaced by clientId
    assert.ok(storage.getItem('oneuid:app-client:access_token'));
    assert.equal(storage.getItem('oneuid_access_token'), null);

    const activeToken = await auth.getAccessToken();
    assert.ok(activeToken && activeToken !== nearExpiryJwt);
    assert.equal(refreshCount, 1);

    // 6. Logout revokes BOTH refresh_token and access_token
    await auth.logout();
    assert.ok(revokedTokens.some((r) => r.hint === 'refresh_token' && r.token === 'rt-new'));
    assert.ok(revokedTokens.some((r) => r.hint === 'access_token' && r.token === activeToken));
    assert.equal(await auth.getAccessToken(), null);

    // 7. Failed refresh clears session
    await auth.persistTokens({ access_token: nearExpiryJwt, refresh_token: 'bad-refresh', expires_in: 5 });
    const afterFailedRefresh = await auth.getAccessToken();
    assert.equal(afterFailedRefresh, null);
    assert.equal(storage.getItem('oneuid:app-client:refresh_token'), null);

    // 8. Default browser storage never touches localStorage
    const dom = createMockDom();
    await withMockBrowser(dom, async () => {
      const browserAuth = new OneUID({ baseURL: mock.baseURL, clientId: 'browser-app' });
      const validJwt = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'browser-app', exp: now + 300 });
      await browserAuth.persistTokens({ access_token: validJwt, refresh_token: 'rt-mem', expires_in: 300 });
      assert.equal(dom.localStore.size, 0);
      assert.ok(new LocalStorageAdapter());
    });
  } finally {
    await mock.close();
  }
});

test('Issue #4: client_secret is stripped in browser runtime, omitted from loginWithProvider, and getSocialRedirectUrl throws', async () => {
  const { jwk, privatePem } = generateTestRsaKeypair();
  let capturedTokenForm = null;
  let capturedSocialBody = null;

  const mock = await createMockServer({
    'GET /.well-known/openid-configuration': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          issuer: mock.baseURL,
          token_endpoint: `${mock.baseURL}/oauth/token`,
          jwks_uri: `${mock.baseURL}/oauth/certs`,
        })
      );
    },
    'GET /oauth/certs': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
    },
    'POST /oauth/token': ({ res, rawBody }) => {
      capturedTokenForm = Object.fromEntries(new URLSearchParams(rawBody).entries());
      const now = Math.floor(Date.now() / 1000);
      const access = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'spa-app', exp: now + 300 });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ access_token: access, refresh_token: 'rt-1', expires_in: 300 }));
    },
    'POST /v1/auth/social-login/': ({ res, rawBody }) => {
      capturedSocialBody = JSON.parse(rawBody);
      const now = Math.floor(Date.now() / 1000);
      const access = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'spa-app', exp: now + 300 });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ access_token: access, refresh_token: 'rt-social', expires_in: 300 }));
    },
  });

  try {
    const dom = createMockDom();
    await withMockBrowser(dom, async () => {
      const auth = new OneUID({ baseURL: mock.baseURL, clientId: 'spa-app', clientSecret: 'should-never-ship' });

      assert.throws(
        () => auth.getSocialRedirectUrl('google', 'https://app.example.com/cb'),
        (err) => err instanceof AuthError && err.code === 'deprecated_method'
      );

      await auth.loginWithCode('code-1', 'https://app.example.com/cb', { codeVerifier: 'a'.repeat(48) });
      assert.equal(capturedTokenForm.client_secret, undefined);

      await auth.loginWithProvider('google', 'auth-code-google', { nonce: 'n-123' });
      assert.equal(capturedSocialBody.client_secret, undefined);
      assert.equal(capturedSocialBody.nonce, 'n-123');
    });
  } finally {
    await mock.close();
  }
});

test('Issue #5: Session challenge get/approve matchNumber enforcement and pollForApproval reject/timeout/abort/retry/missing-token', async () => {
  const { jwk, privatePem } = generateTestRsaKeypair();
  let pollMode = 'reject';
  let transientCount = 0;

  const mock = await createMockServer({
    'GET /.well-known/openid-configuration': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ issuer: mock.baseURL, jwks_uri: `${mock.baseURL}/oauth/certs` }));
    },
    'GET /oauth/certs': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
    },
    'GET /v1/auth/challenges/sess-1/': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          token: 'sess-1',
          method: 'EXTENSION',
          domain: 'app.example.com',
          expires_at: new Date(Date.now() + 60000).toISOString(),
          metadata: { match_number: '42', app_name: 'Trip Express' },
        })
      );
    },
    'POST /v1/auth/challenges/sess-1/approve/': ({ res, rawBody }) => {
      const body = JSON.parse(rawBody);
      assert.equal(body.match_number, '42');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'success' }));
    },
    'POST /v1/auth/challenges/sess-1/status/': ({ res }) => {
      if (pollMode === 'reject') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'REJECTED' }));
      } else if (pollMode === 'approved-no-token') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'APPROVED' }));
      } else if (pollMode === 'pending') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'PENDING' }));
      } else if (pollMode === 'retry-then-approve') {
        transientCount += 1;
        if (transientCount < 2) {
          res.writeHead(503, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'unavailable' }));
          return;
        }
        const now = Math.floor(Date.now() / 1000);
        const access = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'app-client', exp: now + 300 });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'APPROVED', access_token: access, refresh_token: 'rt-qr', expires_in: 300 }));
      }
    },
  });

  try {
    const storage = new MemoryStorageAdapter();
    const auth = new OneUID({ baseURL: mock.baseURL, clientId: 'app-client' }, storage);
    const now = Math.floor(Date.now() / 1000);
    const approverJwt = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'app-client', exp: now + 300 });
    await auth.persistTokens({ access_token: approverJwt, expires_in: 300 });

    // Approve without prior get() fails closed
    await assert.rejects(
      () => auth.session.approve('sess-1', { matchNumber: '42' }),
      (err) => err instanceof AuthError && err.code === 'challenge_not_inspected'
    );

    // Fetch metadata, then test wrong matchNumber vs right matchNumber
    const meta = await auth.session.get('sess-1');
    assert.equal(meta.match_number, '42');
    await assert.rejects(
      () => auth.session.approve('sess-1', { matchNumber: '99' }),
      (err) => err instanceof AuthError && err.code === 'match_number_mismatch'
    );
    await auth.session.approve('sess-1', { matchNumber: '42' });

    // Poll REJECTED
    pollMode = 'reject';
    await assert.rejects(
      () => auth.session.pollForApproval('sess-1', { intervalMs: 15, timeoutMs: 1000 }),
      (err) => err instanceof AuthError && err.code === 'challenge_rejected'
    );

    // Poll APPROVED without token
    pollMode = 'approved-no-token';
    await assert.rejects(
      () => auth.session.pollForApproval('sess-1', { intervalMs: 15, timeoutMs: 1000 }),
      (err) => err instanceof AuthError && err.code === 'invalid_token_response'
    );

    // Poll timeout
    pollMode = 'pending';
    await assert.rejects(
      () => auth.session.pollForApproval('sess-1', { intervalMs: 15, timeoutMs: 50 }),
      (err) => err instanceof AuthError && err.code === 'timeout'
    );

    // Poll AbortSignal
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 25);
    await assert.rejects(
      () => auth.session.pollForApproval('sess-1', { intervalMs: 15, timeoutMs: 2000, signal: ac.signal }),
      (err) => err instanceof AuthError && err.code === 'aborted'
    );

    // Poll transient 503 retry -> APPROVED with verified JWT
    pollMode = 'retry-then-approve';
    transientCount = 0;
    const polled = await auth.session.pollForApproval('sess-1', { intervalMs: 15, timeoutMs: 1000 });
    assert.ok(polled.access_token);
    assert.equal(transientCount, 2);
  } finally {
    await mock.close();
  }
});

test('Issue #7: verify2FA token shape, register never persists tokens, and errors redact raw response bodies', async () => {
  const { jwk, privatePem } = generateTestRsaKeypair();
  let twoFaMode = 'string-token';

  const mock = await createMockServer({
    'GET /.well-known/openid-configuration': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ issuer: mock.baseURL, token_endpoint: `${mock.baseURL}/oauth/token`, jwks_uri: `${mock.baseURL}/oauth/certs` }));
    },
    'GET /oauth/certs': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
    },
    'POST /v1/auth/verify-2fa/': ({ res }) => {
      if (twoFaMode === 'string-token') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token: 'abc', user_id: 'u-1' }));
        return;
      }
      const now = Math.floor(Date.now() / 1000);
      const access = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'app-client', exp: now + 300 });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ token: { access_token: access, refresh_token: 'rt-ok', expires_in: 300 }, user_id: 'u-1' }));
    },
    'POST /v1/auth/register/': ({ res }) => {
      const now = Math.floor(Date.now() / 1000);
      const access = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'app-client', exp: now + 300 });
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ access_token: access, refresh_token: 'rt-reg', user_id: 'u-reg', email: 'new@example.com' }));
    },
    'POST /oauth/token': ({ res }) => {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('SECRET_LEAK_BODY eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig');
    },
  });

  try {
    const storage = new MemoryStorageAdapter();
    const auth = new OneUID({ baseURL: mock.baseURL, clientId: 'app-client' }, storage);

    // 1. register does not persist tokens even if API returns them
    const reg = await auth.register('new@example.com', 'Password!123');
    assert.equal(reg.verification_required, true);
    assert.equal(await auth.getAccessToken(), null);

    // 2. verify2FA with { token: "abc" } does NOT store "undefined"
    twoFaMode = 'string-token';
    await auth.verify2FA({ session_token: 's1', method: 'totp', code: '123456' });
    assert.equal(storage.getItem('oneuid:app-client:access_token'), null);

    // 3. verify2FA with full TokenResponse persists verified token
    twoFaMode = 'full-object';
    await auth.verify2FA({ session_token: 's1', method: 'totp', code: '123456' });
    assert.ok(await auth.getAccessToken());

    // 4. loginWithCode error does not include raw response body
    await assert.rejects(
      () => auth.loginWithCode('bad-code', 'https://app.example.com/cb', 'v'.repeat(48)),
      (err) => err instanceof AuthError && !err.message.includes('SECRET_LEAK_BODY')
    );
  } finally {
    await mock.close();
  }
});

test('Issue #8: KMS does not auto-load process.env.VAULT_MASTER_KEY, refuses browser static KEK, and imports non-extractable Ed25519 keys', async () => {
  const prevEnv = process.env.VAULT_MASTER_KEY;
  const testKek = crypto.randomBytes(32);
  process.env.VAULT_MASTER_KEY = testKek.toString('base64');

  try {
    const auth = new OneUID({ baseURL: 'https://auth.uid.one', clientId: 'app-client' });
    assert.equal(auth.kms, undefined);

    // Browser init without keyProvider is refused
    const dom = createMockDom();
    await withMockBrowser(dom, async () => {
      assert.throws(
        () => auth.initKMS({ kekB64: process.env.VAULT_MASTER_KEY }),
        (err) => err instanceof AuthError && err.code === 'kms_browser_forbidden'
      );
      assert.throws(
        () => auth.initKMS(),
        (err) => err instanceof AuthError && err.code === 'kms_browser_forbidden'
      );
    });

    // Server init with explicit kekB64 works and can encrypt/decrypt via mock cipher API
    const { jwk, privatePem } = generateTestRsaKeypair();
    const rawDek = crypto.randomBytes(32);
    const dekNonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', testKek, dekNonce);
    const encryptedDek = Buffer.concat([cipher.update(rawDek), cipher.final(), cipher.getAuthTag()]);
    const wrappedDekB64 = Buffer.concat([dekNonce, encryptedDek]).toString('base64');

    const mock = await createMockServer({
      'GET /.well-known/openid-configuration': ({ res }) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ issuer: mock.baseURL, jwks_uri: `${mock.baseURL}/oauth/certs` }));
      },
      'GET /oauth/certs': ({ res }) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ keys: [jwk] }));
      },
      'GET /v1/vault/ciphers/active/': ({ res }) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ version: 1, key_material: wrappedDekB64 }));
      },
    });

    try {
      const kmsAuth = new OneUID({ baseURL: mock.baseURL, clientId: 'app-client' });
      const now = Math.floor(Date.now() / 1000);
      const access = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'app-client', exp: now + 300 });
      await kmsAuth.persistTokens({ access_token: access, expires_in: 300 });

      const kms = kmsAuth.initKMS({ kekB64: process.env.VAULT_MASTER_KEY });
      const { ciphertext, version } = await kms.encrypt('sensitive-note');
      assert.equal(version, 1);
      const decrypted = await kms.decrypt(ciphertext, version);
      assert.equal(decrypted, 'sensitive-note');
    } finally {
      await mock.close();
    }

    // Ed25519 keys are non-extractable
    const { publicKey: edPub, privateKey: edPriv } = crypto.generateKeyPairSync('ed25519');
    const rawEdPub = new Uint8Array(edPub.export({ format: 'der', type: 'spki' }).subarray(-32));
    const rawEdPriv = new Uint8Array(edPriv.export({ format: 'der', type: 'pkcs8' }).subarray(-32));
    const importedPub = await importPublicKey(rawEdPub);
    const importedPriv = await importPrivateKey(rawEdPriv);
    assert.equal(importedPub.extractable, false);
    assert.equal(importedPriv.extractable, false);
  } finally {
    if (prevEnv === undefined) delete process.env.VAULT_MASTER_KEY;
    else process.env.VAULT_MASTER_KEY = prevEnv;
  }
});

test('Issue #10: renderButton uses OIDC PKCE authorize flow (not /login/), enforces >=44px hit targets, loading/disabled state, and inline error + retry', async () => {
  const mock = await createMockServer({
    'GET /.well-known/openid-configuration': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          issuer: 'https://auth.uid.one',
          authorization_endpoint: `${mock.baseURL}/oauth/authorize`,
          token_endpoint: `${mock.baseURL}/oauth/token`,
          jwks_uri: `${mock.baseURL}/oauth/certs`,
        })
      );
    },
  });

  try {
    const dom = createMockDom();
    await withMockBrowser(dom, async () => {
      const auth = new OneUID({ baseURL: mock.baseURL, clientId: 'ui-client' });
      const container = dom.registerContainer('uid-login');

      // Render small Arabic RTL button
      auth.renderButton('uid-login', {
        provider: 'uid',
        redirectUri: 'https://app.example.com/auth/callback',
        size: 'small',
        theme: 'brand',
        locale: 'ar',
      });

      const styleTag = dom.styles.find((s) => s.id === 'oneuid-sdk-styles');
      assert.ok(styleTag);
      assert.match(styleTag.textContent, /\.oneuid-btn--small\s*\{[^}]*min-height:\s*44px/);
      assert.match(styleTag.textContent, /\.oneuid-btn--medium\s*\{[^}]*min-height:\s*44px/);
      assert.match(styleTag.textContent, /focus-visible/);
      assert.match(styleTag.textContent, /prefers-reduced-motion/);

      const wrap = container.children[0];
      assert.equal(wrap.dir, 'rtl');
      const btn = wrap.children[0];
      assert.equal(btn.disabled, false);

      // Click triggers loading state + PKCE S256 redirect (never /login/)
      btn.click();
      assert.equal(btn.disabled, true);
      assert.equal(btn.getAttribute('aria-busy'), 'true');

      // Wait for async startAuthorization
      await new Promise((r) => setTimeout(r, 40));
      const navigated = new URL(dom.window.location.href);
      assert.equal(navigated.pathname, '/oauth/authorize');
      assert.equal(navigated.searchParams.get('response_type'), 'code');
      assert.equal(navigated.searchParams.get('code_challenge_method'), 'S256');
      assert.ok(navigated.searchParams.get('state'));
      assert.ok(navigated.searchParams.get('nonce'));

      // Invalid redirectUri shows inline error + Retry button
      const errContainer = dom.registerContainer('uid-err');
      auth.renderButton('uid-err', {
        provider: 'uid',
        redirectUri: 'http://insecure.example.com/cb',
        theme: 'light',
      });
      const errWrap = errContainer.children[0];
      const errBtn = errWrap.children[0];
      const alertBox = errWrap.children[1];
      assert.equal(alertBox.getAttribute('role'), 'alert');
      assert.equal(alertBox.style.display, 'none');

      errBtn.click();
      await new Promise((r) => setTimeout(r, 20));
      assert.equal(alertBox.style.display, 'flex');
      assert.equal(errBtn.disabled, false);

      // Social provider without onProviderClick shows inline error instead of silent no-op
      const socialContainer = dom.registerContainer('uid-social');
      auth.renderButton('uid-social', {
        provider: 'google',
        redirectUri: 'https://app.example.com/cb',
        theme: 'dark',
      });
      const socialWrap = socialContainer.children[0];
      socialWrap.children[0].click();
      assert.equal(socialWrap.children[1].style.display, 'flex');
    });
  } finally {
    await mock.close();
  }
});

test('Issue #6: config-object storage, second-arg override, named adapters, and issuer/apiURL separation', async () => {
  const { jwk, privatePem } = generateTestRsaKeypair();
  let apiCalls = 0;

  const issuerMock = await createMockServer({
    'GET /.well-known/openid-configuration': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          issuer: issuerMock.baseURL,
          authorization_endpoint: `${issuerMock.baseURL}/oauth/authorize`,
          token_endpoint: `${issuerMock.baseURL}/oauth/token`,
          jwks_uri: `${issuerMock.baseURL}/oauth/certs`,
          revocation_endpoint: `${issuerMock.baseURL}/oauth/revoke`,
        })
      );
    },
    'GET /oauth/certs': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
    },
  });

  const apiMock = await createMockServer({
    'GET /v1/auth/me/': ({ res }) => {
      apiCalls += 1;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id: 'u-1', uid: 'u-1', sovereign_id: 'sov-1', username: 'alice', first_name: 'Alice', last_name: 'One' }));
    },
  });

  try {
    const now = Math.floor(Date.now() / 1000);
    const jwt = signRs256(
      privatePem,
      { alg: 'RS256', kid: jwk.kid },
      { iss: issuerMock.baseURL, sub: 'u-1', aud: 'cfg-client', exp: now + 300 }
    );

    // 1. Storage passed in AuthConfig object is honored
    const configStorage = new MemoryStorageAdapter();
    const authFromConfig = new OneUID({
      issuer: issuerMock.baseURL,
      apiURL: apiMock.baseURL,
      clientId: 'cfg-client',
      storage: configStorage,
    });
    await authFromConfig.persistTokens({ access_token: jwt, expires_in: 300 });
    assert.equal(await authFromConfig.getAccessToken(), jwt);
    assert.equal(configStorage.getItem('oneuid:cfg-client:access_token'), jwt);

    // OIDC discovery uses issuerMock while resource API uses apiMock
    const started = await authFromConfig.startAuthorization('https://app.example.com/cb');
    assert.ok(started.url.startsWith(`${issuerMock.baseURL}/oauth/authorize`));
    const profile = await authFromConfig.getProfile();
    assert.equal(profile.username, 'alice');
    assert.equal(apiCalls, 1);

    // 2. Explicit second constructor argument overrides config.storage
    const overrideStorage = new MemoryStorageAdapter();
    const authOverridden = new OneUID(
      { baseURL: issuerMock.baseURL, clientId: 'cfg-client', storage: configStorage },
      overrideStorage
    );
    await authOverridden.persistTokens({ access_token: jwt, expires_in: 300 });
    assert.equal(overrideStorage.getItem('oneuid:cfg-client:access_token'), jwt);
  } finally {
    await issuerMock.close();
    await apiMock.close();
  }
});

test('Issue #11: typed AuthError.safeMessage across subclients, session.list(), not_implemented stubs, and 14-locale error copy', async () => {
  const { jwk, privatePem } = generateTestRsaKeypair();
  const mock = await createMockServer({
    'GET /.well-known/openid-configuration': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ issuer: mock.baseURL, jwks_uri: `${mock.baseURL}/oauth/certs` }));
    },
    'GET /oauth/certs': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: [jwk] }));
    },
    'GET /v1/auth/sessions/': ({ res }) => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          results: [
            {
              id: 'sess-1',
              application: 'Trip Express',
              client_id: 'trip-web',
              scope: 'openid profile email',
              created_at: '2026-11-21T00:00:00Z',
              expires_at: '2026-12-21T00:00:00Z',
              is_current: true,
            },
          ],
        })
      );
    },
    'POST /v1/auth/devices/register/': ({ res }) => {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ detail: 'Invalid public key; access_token: "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig"' }));
    },
    'POST /v1/auth/recovery/login/': ({ res }) => {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid recovery code' }));
    },
  });

  try {
    const auth = new OneUID({ baseURL: mock.baseURL, clientId: 'settings-client' });

    // Unauthenticated passkey/recovery/devices throw typed AuthError
    await assert.rejects(
      () => auth.passkey.register('MacBook'),
      (err) => err instanceof AuthError && err.code === 'unauthenticated' && err.safeMessage.length > 0
    );
    await assert.rejects(
      () => auth.recovery.generate(),
      (err) => err instanceof AuthError && err.code === 'unauthenticated'
    );

    const now = Math.floor(Date.now() / 1000);
    const jwt = signRs256(privatePem, { alg: 'RS256', kid: jwk.kid }, { iss: mock.baseURL, aud: 'settings-client', exp: now + 300 });
    await auth.persistTokens({ access_token: jwt, expires_in: 300 });

    // session.list() returns active sessions
    const sessions = await auth.listSessions();
    assert.equal(sessions.length, 1);
    assert.equal(sessions[0].application, 'Trip Express');
    assert.equal(sessions[0].is_current, true);

    // devices.register and recovery.login throw typed AuthError with redacted safeMessage
    await assert.rejects(
      () => auth.devices.register({ deviceId: 'd1', deviceName: 'Phone', publicKey: 'bad' }),
      (err) => err instanceof AuthError && err.code === 'device_register_failed' && err.status === 400 && !err.safeMessage.includes('eyJ')
    );
    await assert.rejects(
      () => auth.recovery.login('u@example.com', '000000'),
      (err) => err instanceof AuthError && err.code === 'recovery_login_failed' && err.status === 401
    );

    // deleteAccount and exportData fail closed with stable not_implemented code
    await assert.rejects(
      () => auth.deleteAccount(),
      (err) => err instanceof AuthError && err.code === 'not_implemented' && err.status === 501
    );
    await assert.rejects(
      () => auth.exportData(),
      (err) => err instanceof AuthError && err.code === 'not_implemented' && err.status === 501
    );

    // 14-locale error recovery copy
    assert.equal(SUPPORTED_LOCALES.length, 14);
    for (const loc of SUPPORTED_LOCALES) {
      const ui = getAuthErrorMessage('access_denied', loc);
      assert.ok(ui.message.length > 0);
      assert.ok(ui.retryLabel.length > 0);
    }
  } finally {
    await mock.close();
  }
});

test('Issue #12: renderButton localizes google, facebook, apple, and uid across all 14 locales with Arabic RTL and brand theme', async () => {
  const dom = createMockDom();
  await withMockBrowser(dom, async () => {
    const auth = new OneUID({ baseURL: 'https://auth.uid.one', clientId: 'i18n-client' });

    const providers = ['uid', 'google', 'facebook', 'apple'];
    for (const provider of providers) {
      const seenLabels = new Set();
      for (const locale of SUPPORTED_LOCALES) {
        const id = `btn-${provider}-${locale}`;
        const container = dom.registerContainer(id);
        auth.renderButton(id, {
          provider,
          redirectUri: 'https://app.example.com/cb',
          locale,
          theme: locale === 'ar' ? 'dark' : 'light',
        });
        const wrap = container.children[0];
        const btn = wrap.children[0];
        const text = btn.children[1].textContent;
        assert.ok(text.length > 0, `Missing label for ${provider} in ${locale}`);
        seenLabels.add(text);
        if (locale === 'ar') {
          assert.equal(wrap.dir, 'rtl');
          assert.equal(btn.dir, 'rtl');
        } else {
          assert.equal(wrap.dir, '');
        }
      }
      // Every locale has localized text (not stuck on English)
      assert.ok(seenLabels.size >= 12, `Expected localized labels for ${provider}`);
    }

    // Verify vi & ar buttons in light, dark, and brand themes + custom label override
    for (const locale of ['vi', 'ar']) {
      for (const theme of ['light', 'dark', 'brand']) {
        const id = `btn-check-${locale}-${theme}`;
        const container = dom.registerContainer(id);
        auth.renderButton(id, {
          provider: 'google',
          redirectUri: 'https://app.example.com/cb',
          locale,
          theme,
        });
        const btn = container.children[0].children[0];
        assert.ok(btn.className.includes(`oneuid-btn--${theme}`));
      }
    }

    const customContainer = dom.registerContainer('btn-custom');
    auth.renderButton('btn-custom', {
      provider: 'apple',
      redirectUri: 'https://app.example.com/cb',
      locale: 'vi',
      label: 'Tiếp tục với Apple',
    });
    assert.equal(customContainer.children[0].children[0].children[1].textContent, 'Tiếp tục với Apple');
  });
});

