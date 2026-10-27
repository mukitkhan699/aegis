import { createHash, randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { chmodSync, mkdirSync, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCallback);
const rootDir = dirname(fileURLToPath(import.meta.url));
const publicDir = join(rootDir, 'public');

const PORT = parsePort(process.env.PORT, 3000);
const HOST = process.env.HOST || '127.0.0.1';
const DB_PATH = process.env.DATABASE_PATH || join(rootDir, 'data', 'auth.db');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const TRUST_PROXY_HOPS = Math.max(0, Number.parseInt(process.env.TRUST_PROXY_HOPS || '1', 10) || 1);
const PUBLIC_HOST = (process.env.PUBLIC_HOST || '').trim().toLowerCase();
const COOKIE_SECURE = process.env.COOKIE_SECURE;
const COOKIE_NAME = isSecureRequestGlobal() ? '__Host-sid' : 'sid';
const COOKIE_NAME_FALLBACK = 'sid';
const MAX_BODY_BYTES = 8 * 1024;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const ANON_SESSION_TTL_MS = 60 * 60 * 1000;
const SCRYPT_N = 32768;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEY_LENGTH = 64;
const SCRYPT_MAX_MEMORY = 64 * 1024 * 1024;
const MAX_HEADER_VALUE_BYTES = 4096;
const SCRYPT_MAX_CONCURRENT = Math.max(1, Number.parseInt(process.env.SCRYPT_MAX_CONCURRENT || '4', 10) || 4);

const USERNAME_PATTERN = /^[A-Za-z0-9_]{3,32}$/;

class HttpError extends Error {
  constructor(status, message, code = 'REQUEST_FAILED', headers = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

class SlidingWindowLimiter {
  constructor(limit, windowMs, maxKeys = 10_000) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.maxKeys = maxKeys;
    this.buckets = new Map();
  }

  check(key) {
    const now = Date.now();
    const entries = this.buckets.get(key);

    if (!entries) return 0;

    while (entries.length > 0 && entries[0] <= now - this.windowMs) {
      entries.shift();
    }

    if (entries.length === 0) {
      this.buckets.delete(key);
      return 0;
    }

    if (entries.length < this.limit) return 0;

    return Math.max(1, Math.ceil((entries[0] + this.windowMs - now) / 1000));
  }

  record(key) {
    const now = Date.now();
    let entries = this.buckets.get(key);

    if (!entries) {
      if (this.buckets.size >= this.maxKeys) {
        const oldestKey = this.buckets.keys().next().value;
        this.buckets.delete(oldestKey);
      }
      entries = [];
      this.buckets.set(key, entries);
    }

    entries.push(now);
    if (entries.length > this.limit) {
      entries.splice(0, entries.length - this.limit);
    }
  }

  clear(key) {
    this.buckets.delete(key);
  }

  sweep() {
    const cutoff = Date.now() - this.windowMs;
    for (const [key, entries] of this.buckets) {
      if (entries.length === 0 || entries[entries.length - 1] <= cutoff) {
        this.buckets.delete(key);
      }
    }
  }
}

const loginByIp = new SlidingWindowLimiter(30, 15 * 60 * 1000);
const loginByAccount = new SlidingWindowLimiter(6, 15 * 60 * 1000);
const registrationByIp = new SlidingWindowLimiter(8, 60 * 60 * 1000);
const sessionCreationByIp = new SlidingWindowLimiter(60, 60 * 60 * 1000);

try {
  process.umask(0o077);
} catch {}

mkdirSync(dirname(DB_PATH), { recursive: true, mode: 0o700 });
try {
  chmodSync(dirname(DB_PATH), 0o700);
} catch {}

const db = new DatabaseSync(DB_PATH);
try {
  chmodSync(DB_PATH, 0o600);
} catch {}

try {
  const walPath = `${DB_PATH}-wal`;
  const shmPath = `${DB_PATH}-shm`;
  try {
    statSync(walPath);
    chmodSync(walPath, 0o600);
  } catch {}
  try {
    statSync(shmPath);
    chmodSync(shmPath, 0o600);
  } catch {}
} catch {}

db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 5000;
  PRAGMA secure_delete = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`);

const statements = {
  insertUser: db.prepare(
    'INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)',
  ),
  userByUsername: db.prepare(
    'SELECT id, username, password_hash, created_at FROM users WHERE username = ? COLLATE NOCASE',
  ),
  insertSession: db.prepare(
    'INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
  ),
  sessionByHash: db.prepare(`
    SELECT
      s.token_hash,
      s.user_id,
      s.csrf_token,
      s.expires_at,
      u.username,
      u.created_at AS user_created_at
    FROM sessions s
    LEFT JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ?
  `),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  deleteExpiredSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
};

class Semaphore {
  constructor(max) {
    this.max = max;
    this.active = 0;
    this.queue = [];
  }

  acquire() {
    if (this.active < this.max) {
      this.active++;
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      const entry = { resolve, timeout: null };
      entry.timeout = setTimeout(() => {
        const idx = this.queue.indexOf(entry);
        if (idx >= 0) this.queue.splice(idx, 1);
        reject(new HttpError(503, 'Service temporarily unavailable.', 'SERVICE_BUSY'));
      }, 5000);
      this.queue.push(entry);
    }).then(() => {
      this.active++;
    });
  }

  release() {
    this.active = Math.max(0, this.active - 1);
    const next = this.queue.shift();
    if (next) {
      if (next.timeout) clearTimeout(next.timeout);
      next.resolve();
    }
  }
}

const scryptSemaphore = new Semaphore(SCRYPT_MAX_CONCURRENT);

const DUMMY_PASSWORD_HASH = await (async () => {
  await scryptSemaphore.acquire();
  try {
    const salt = randomBytes(16);
    const derivedKey = await scrypt(randomBytes(32).toString('base64url'), salt, SCRYPT_KEY_LENGTH, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      maxmem: SCRYPT_MAX_MEMORY,
    });
    return [
      'scrypt',
      SCRYPT_N,
      SCRYPT_R,
      SCRYPT_P,
      salt.toString('base64url'),
      derivedKey.toString('base64url'),
    ].join('$');
  } finally {
    scryptSemaphore.release();
  }
})();
const staticFiles = await loadStaticFiles();
const sessionSweepTimer = setInterval(() => {
  statements.deleteExpiredSessions.run(Date.now());
  loginByIp.sweep();
  loginByAccount.sweep();
  registrationByIp.sweep();
  sessionCreationByIp.sweep();
}, 5 * 60 * 1000);
sessionSweepTimer.unref();

statements.deleteExpiredSessions.run(Date.now());

const server = createServer(async (req, res) => {
  applySecurityHeaders(req, res);

  try {
    await routeRequest(req, res);
  } catch (error) {
    if (res.headersSent) {
      res.destroy();
      return;
    }

    if (error instanceof HttpError) {
      for (const [name, value] of Object.entries(error.headers)) {
        res.setHeader(name, value);
      }
      sendJson(res, error.status, { error: error.message, code: error.code });
      return;
    }

    console.error('Unexpected request error:', error);
    sendJson(res, 500, {
      error: 'Something went wrong. Please try again.',
      code: 'INTERNAL_ERROR',
    });
  }
});

server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 100;

server.listen(PORT, HOST, () => {
  console.log(`Aegis is running at http://${HOST}:${PORT}`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    clearInterval(sessionSweepTimer);
    server.close(() => {
      db.close();
      process.exit(0);
    });
  });
}

async function routeRequest(req, res) {
  const url = new URL(req.url || '/', 'http://localhost');
  const pathname = url.pathname;

  if (pathname.startsWith('/api/')) {
    await routeApi(req, res, pathname);
    return;
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    throw new HttpError(405, 'Method not allowed.', 'METHOD_NOT_ALLOWED', {
      Allow: 'GET, HEAD',
    });
  }

  const file = staticFiles.get(pathname);
  if (!file) {
    throw new HttpError(404, 'Not found.', 'NOT_FOUND');
  }

  res.statusCode = 200;
  res.setHeader('Content-Type', file.contentType);
  res.setHeader('Content-Length', file.body.length);
  res.setHeader('Cache-Control', 'no-cache');
  res.end(req.method === 'HEAD' ? undefined : file.body);
}

async function routeApi(req, res, pathname) {
  if (pathname === '/api/session' && req.method === 'GET') {
    await handleSession(req, res);
    return;
  }

  if (pathname === '/api/login' && req.method === 'POST') {
    await handleLogin(req, res);
    return;
  }

  if (pathname === '/api/register' && req.method === 'POST') {
    await handleRegister(req, res);
    return;
  }

  if (pathname === '/api/logout' && req.method === 'POST') {
    await handleLogout(req, res);
    return;
  }

  const knownPaths = new Set(['/api/session', '/api/login', '/api/register', '/api/logout']);
  if (knownPaths.has(pathname)) {
    throw new HttpError(405, 'Method not allowed.', 'METHOD_NOT_ALLOWED', {
      Allow: pathname === '/api/session' ? 'GET' : 'POST',
    });
  }

  throw new HttpError(404, 'Not found.', 'NOT_FOUND');
}

async function handleSession(req, res) {
  let session = getSessionFromRequest(req);

  if (!session) {
    // Do not create server-side sessions on unauthenticated GET (per #6)
    // Return anonymous state without creating DB row
    throw new HttpError(401, 'No active session.', 'SESSION_REQUIRED');
  }

  const user = session.userId
    ? {
        id: session.userId,
        username: session.username,
        createdAt: session.userCreatedAt,
      }
    : null;

  sendJson(res, 200, {
    authenticated: Boolean(user),
    user,
    csrfToken: session.csrfToken,
    expiresAt: session.expiresAt,
  });
}

async function handleLogin(req, res) {
  validateStateChangingRequest(req);
  const session = requireSessionWithCsrf(req);
  const body = await readJsonBody(req);

  const username = normalizeUsername(body?.username);
  const password = body?.password;

  if (
    !USERNAME_PATTERN.test(username) ||
    typeof password !== 'string' ||
    password.length < 1 ||
    password.length > 1024
  ) {
    throw invalidCredentialsError();
  }

  const clientIp = getClientIp(req);
  const ipKey = hashLimiterKey(`ip:${clientIp}`);
  const accountKey = hashLimiterKey(`account:${username.toLowerCase()}`);
  const retryAfter = Math.max(
    loginByIp.check(ipKey),
    loginByAccount.check(accountKey),
  );

  if (retryAfter > 0) {
    throw new HttpError(
      429,
      'Too many sign-in attempts. Please try again later.',
      'RATE_LIMITED',
      { 'Retry-After': String(retryAfter) },
    );
  }

  const user = statements.userByUsername.get(username);
  const passwordHash = user?.password_hash ?? DUMMY_PASSWORD_HASH;
  const passwordMatches = await verifyPassword(password, passwordHash);

  if (!user || !passwordMatches) {
    loginByIp.record(ipKey);
    loginByAccount.record(accountKey);
    throw invalidCredentialsError();
  }

  loginByAccount.clear(accountKey);

  const logoutClientIp = getClientIp(req);
  const anonKey = hashLimiterKey(`anon:${logoutClientIp}`);
  const retryAfterAnon = sessionCreationByIp.check(anonKey);
  if (retryAfterAnon > 0) {
    throw new HttpError(
      429,
      'Too many requests. Please try again later.',
      'RATE_LIMITED',
      { 'Retry-After': String(retryAfterAnon) },
    );
  }

  statements.deleteSession.run(session.tokenHash);
  sessionCreationByIp.record(anonKey);
  const newSession = createSession(user);
  setSessionCookie(req, res, newSession);

  sendJson(res, 200, {
    authenticated: true,
    user: {
      id: user.id,
      username: user.username,
      createdAt: user.created_at,
    },
    csrfToken: newSession.csrfToken,
    expiresAt: newSession.expiresAt,
  });
}

async function handleRegister(req, res) {
  validateStateChangingRequest(req);
  const session = requireSessionWithCsrf(req);
  const body = await readJsonBody(req);

  const username = normalizeUsername(body?.username);
  const password = body?.password;

  if (!USERNAME_PATTERN.test(username)) {
    throw new HttpError(
      400,
      'Username must be 3-32 characters using letters, numbers, or underscores.',
      'INVALID_USERNAME',
    );
  }

  if (typeof password !== 'string' || password.length < 12 || password.length > 1024) {
    throw new HttpError(
      400,
      'Password must be between 12 and 1024 characters.',
      'INVALID_PASSWORD',
    );
  }

  const clientIp = getClientIp(req);
  const registrationKey = hashLimiterKey(`register:${clientIp}`);
  const retryAfter = registrationByIp.check(registrationKey);

  if (retryAfter > 0) {
    throw new HttpError(
      429,
      'Too many accounts created from this network. Please try again later.',
      'RATE_LIMITED',
      { 'Retry-After': String(retryAfter) },
    );
  }

  registrationByIp.record(registrationKey);
  const passwordHash = await hashPassword(password);

  let userId;
  try {
    const result = statements.insertUser.run(username, passwordHash, Date.now());
    userId = Number(result.lastInsertRowid);
  } catch (error) {
    if (String(error?.message).includes('UNIQUE constraint failed')) {
      throw new HttpError(409, 'That username is already taken.', 'USERNAME_TAKEN');
    }
    throw error;
  }

  const user = {
    id: userId,
    username,
    created_at: Date.now(),
  };

  const logoutClientIp = getClientIp(req);
  const anonKey = hashLimiterKey(`anon:${logoutClientIp}`);
  const retryAfterAnon = sessionCreationByIp.check(anonKey);
  if (retryAfterAnon > 0) {
    throw new HttpError(
      429,
      'Too many requests. Please try again later.',
      'RATE_LIMITED',
      { 'Retry-After': String(retryAfterAnon) },
    );
  }

  statements.deleteSession.run(session.tokenHash);
  sessionCreationByIp.record(anonKey);
  const newSession = createSession(user);
  setSessionCookie(req, res, newSession);

  sendJson(res, 201, {
    authenticated: true,
    user: {
      id: user.id,
      username: user.username,
      createdAt: user.created_at,
    },
    csrfToken: newSession.csrfToken,
    expiresAt: newSession.expiresAt,
  });
}

async function handleLogout(req, res) {
  validateStateChangingRequest(req);
  const session = requireSessionWithCsrf(req);

  const clientIp = getClientIp(req);
  const anonKey = hashLimiterKey(`anon:${clientIp}`);
  const retryAfterAnon = sessionCreationByIp.check(anonKey);
  if (retryAfterAnon > 0) {
    throw new HttpError(
      429,
      'Too many requests. Please try again later.',
      'RATE_LIMITED',
      { 'Retry-After': String(retryAfterAnon) },
    );
  }

  statements.deleteSession.run(session.tokenHash);
  sessionCreationByIp.record(anonKey);
  const anonymousSession = createSession(null);
  setSessionCookie(req, res, anonymousSession);

  sendJson(res, 200, {
    authenticated: false,
    user: null,
    csrfToken: anonymousSession.csrfToken,
    expiresAt: anonymousSession.expiresAt,
  });
}

function invalidCredentialsError() {
  return new HttpError(
    401,
    'Invalid username or password.',
    'INVALID_CREDENTIALS',
  );
}

function validateStateChangingRequest(req) {
  const contentType = String(req.headers['content-type'] || '')
    .split(';')[0]
    .trim()
    .toLowerCase();

  if (contentType !== 'application/json') {
    throw new HttpError(415, 'Content-Type must be application/json.', 'INVALID_CONTENT_TYPE');
  }

  const origin = req.headers.origin;
  const fetchSite = req.headers['sec-fetch-site'];
  if (typeof origin !== 'string' && typeof fetchSite !== 'string') {
    throw new HttpError(403, 'Request origin rejected.', 'ORIGIN_REJECTED');
  }

  if (typeof origin === 'string') {
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      throw new HttpError(403, 'Request origin rejected.', 'ORIGIN_REJECTED');
    }

    const expectedHost = getRequestHost(req);
    if (
      (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') ||
      parsed.host.toLowerCase() !== expectedHost
    ) {
      throw new HttpError(403, 'Request origin rejected.', 'ORIGIN_REJECTED');
    }
  }

  if (typeof fetchSite === 'string' && fetchSite !== 'same-origin' && fetchSite !== 'none') {
    throw new HttpError(403, 'Cross-site request rejected.', 'ORIGIN_REJECTED');
  }
}

function requireSessionWithCsrf(req) {
  const session = getSessionFromRequest(req);
  if (!session) {
    throw new HttpError(
      403,
      'Your session has expired. Refresh the page and try again.',
      'SESSION_REQUIRED',
    );
  }

  const csrfToken = req.headers['x-csrf-token'];
  if (!safeEqual(csrfToken, session.csrfToken)) {
    throw new HttpError(
      403,
      'Security token is invalid. Refresh the page and try again.',
      'CSRF_INVALID',
    );
  }

  return session;
}

function getSessionFromRequest(req) {
  const token = getCookie(req) || getCookie(req, COOKIE_NAME_FALLBACK) || getCookie(req, '__Host-sid');
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    return null;
  }

  const tokenHash = hashToken(token);
  const row = statements.sessionByHash.get(tokenHash);

  if (!row) return null;

  if (row.expires_at <= Date.now()) {
    statements.deleteSession.run(row.token_hash);
    return null;
  }

  if (row.user_id !== null && row.username === null) {
    statements.deleteSession.run(row.token_hash);
    return null;
  }

  return {
    token,
    tokenHash: row.token_hash,
    userId: row.user_id,
    username: row.username,
    userCreatedAt: row.user_created_at,
    csrfToken: row.csrf_token,
    expiresAt: row.expires_at,
  };
}

function createSession(user) {
  const token = randomBytes(32).toString('base64url');
  const csrfToken = randomBytes(32).toString('base64url');
  const createdAt = Date.now();
  const expiresAt = createdAt + (user ? SESSION_TTL_MS : ANON_SESSION_TTL_MS);

  statements.insertSession.run(
    hashToken(token),
    user?.id ?? null,
    csrfToken,
    createdAt,
    expiresAt,
  );

  return {
    token,
    tokenHash: hashToken(token),
    userId: user?.id ?? null,
    username: user?.username ?? null,
    userCreatedAt: user?.created_at ?? null,
    csrfToken,
    expiresAt,
  };
}

function setSessionCookie(req, res, session) {
  const maxAge = Math.max(0, Math.floor((session.expiresAt - Date.now()) / 1000));
  const secure = isSecureRequest(req);
  const cookieName = secure ? '__Host-sid' : COOKIE_NAME_FALLBACK;
  const attributes = [
    `${cookieName}=${encodeURIComponent(session.token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAge}`,
  ];

  if (secure) {
    attributes.push('Secure');
  }

  res.setHeader('Set-Cookie', attributes.join('; '));
}

function getCookie(req, name) {
  const header = req.headers.cookie;
  if (typeof header !== 'string' || header.length > 8192) return null;

  // try specific name if provided, else try common names
  const namesToTry = name ? [name] : ['__Host-sid', COOKIE_NAME_FALLBACK, COOKIE_NAME];

  for (const tryName of namesToTry) {
    for (const part of header.split(';')) {
      const separator = part.indexOf('=');
      if (separator === -1) continue;

      const key = part.slice(0, separator).trim();
      if (key !== tryName) continue;

      try {
        return decodeURIComponent(part.slice(separator + 1).trim());
      } catch {
        return null;
      }
    }
  }

  return null;
}

function getClientIp(req) {
  if (TRUST_PROXY) {
    const forwardedFor = req.headers['x-forwarded-for'];
    if (typeof forwardedFor === 'string') {
      if (forwardedFor.length > MAX_HEADER_VALUE_BYTES) {
        return req.socket.remoteAddress || 'unknown';
      }
      const parts = forwardedFor.split(',').map((p) => p.trim()).filter(Boolean);
      if (parts.length === 0) {
        // fall through
      } else {
        const hopIndex = parts.length - Math.max(1, TRUST_PROXY_HOPS);
        const candidate = parts[hopIndex >= 0 ? hopIndex : 0];
        if (isIP(candidate)) {
          return candidate;
        }
        // if not valid IP, fall back to socket address
      }
    }
  }

  const remote = req.socket.remoteAddress || 'unknown';
  if (isIP(remote)) return remote;
  if (remote === 'unknown') return 'unknown';
  // try to normalize IPv6 mapped etc not necessary
  return remote;
}

function getRequestHost(req) {
  if (PUBLIC_HOST) {
    return PUBLIC_HOST;
  }

  if (TRUST_PROXY) {
    // Do not trust X-Forwarded-Host blindly; prefer configured allowlist
    // Fall through to Host header only if no PUBLIC_HOST
  }

  return String(req.headers.host || '').toLowerCase();
}

function isSecureRequest(req) {
  if (COOKIE_SECURE === 'true') return true;
  if (COOKIE_SECURE === 'false') return false;
  if (req.socket.encrypted) return true;

  if (TRUST_PROXY) {
    const forwardedProto = req.headers['x-forwarded-proto'];
    if (typeof forwardedProto === 'string') {
      if (forwardedProto.length > MAX_HEADER_VALUE_BYTES) {
        return req.socket.encrypted === true;
      }
      const remote = req.socket.remoteAddress;
      // Only trust proto if immediate peer is trusted? We don't know proxy allowlist
      // but per best practice, only trust when explicitly behind trusted proxy; still validate
      const parts = forwardedProto.split(',').map((p) => p.trim().toLowerCase());
      if (parts.length > 0) {
        return parts[parts.length - Math.max(1, TRUST_PROXY_HOPS)] === 'https' || parts[0] === 'https';
      }
    }
  }

  return false;
}

function applySecurityHeaders(req, res) {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  );
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (isSecureRequest(req)) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
}

function sendJson(res, status, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Length', body.length);
  res.setHeader('Cache-Control', 'no-store');
  res.end(body);
}

async function readJsonBody(req) {
  const declaredLength = Number(req.headers['content-length'] || 0);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_BODY_BYTES) {
    try {
      req.resume();
    } catch {}
    throw new HttpError(413, 'Request body is too large.', 'BODY_TOO_LARGE');
  }

  const chunks = [];
  let total = 0;

  try {
    for await (const chunk of req) {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        try {
          req.resume();
        } catch {}
        throw new HttpError(413, 'Request body is too large.', 'BODY_TOO_LARGE');
      }
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof HttpError) throw err;
    try {
      req.resume();
    } catch {}
    throw new HttpError(400, 'Invalid JSON request body.', 'INVALID_JSON');
  }

  if (total === 0) {
    try {
      req.resume();
    } catch {}
    throw new HttpError(400, 'A JSON request body is required.', 'INVALID_JSON');
  }

  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Body must be an object.');
    }
    return parsed;
  } catch {
    try {
      req.resume();
    } catch {}
    throw new HttpError(400, 'Invalid JSON request body.', 'INVALID_JSON');
  }
}

async function hashPassword(password) {
  await scryptSemaphore.acquire();
  try {
    const salt = randomBytes(16);
    const derivedKey = await scrypt(password, salt, SCRYPT_KEY_LENGTH, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      maxmem: SCRYPT_MAX_MEMORY,
    });

    return [
      'scrypt',
      SCRYPT_N,
      SCRYPT_R,
      SCRYPT_P,
      salt.toString('base64url'),
      derivedKey.toString('base64url'),
    ].join('$');
  } finally {
    scryptSemaphore.release();
  }
}

async function hashPasswordWithSemaphore(password) {
  return hashPassword(password);
}

async function verifyPassword(password, storedHash) {
  await scryptSemaphore.acquire();
  try {
    const [scheme, n, r, p, saltValue, hashValue] = String(storedHash).split('$');

    if (
      scheme !== 'scrypt' ||
      Number(n) !== SCRYPT_N ||
      Number(r) !== SCRYPT_R ||
      Number(p) !== SCRYPT_P ||
      typeof saltValue !== 'string' ||
      typeof hashValue !== 'string'
    ) {
      return false;
    }

    const salt = Buffer.from(saltValue, 'base64url');
    const expected = Buffer.from(hashValue, 'base64url');
    if (salt.length < 16 || expected.length !== SCRYPT_KEY_LENGTH) return false;

    const actual = await scrypt(password, salt, SCRYPT_KEY_LENGTH, {
      N: SCRYPT_N,
      r: SCRYPT_R,
      p: SCRYPT_P,
      maxmem: SCRYPT_MAX_MEMORY,
    });

    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  } finally {
    scryptSemaphore.release();
  }
}

function normalizeUsername(value) {
  return typeof value === 'string' ? value.trim() : '';
}

function hashToken(token) {
  return createHash('sha256').update(token).digest('base64url');
}

function normalizeLimiterKey(value) {
  if (typeof value !== 'string') return 'invalid';
  if (value.length > 64) return value.slice(0, 64);
  return value;
}

function hashLimiterKey(value) {
  const normalized = normalizeLimiterKey(value);
  return createHash('sha256').update(normalized).digest('base64url');
}

function isSecureRequestGlobal() {
  if (COOKIE_SECURE === 'true') return true;
  if (COOKIE_SECURE === 'false') return false;
  if (process.env.FORCE_SECURE === '1') return true;
  return false;
}

function safeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;

  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function parsePort(value, fallback) {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isInteger(parsed) && parsed > 0 && parsed < 65536 ? parsed : fallback;
}

async function loadStaticFiles() {
  const definitions = [
    ['/', 'index.html', 'text/html; charset=utf-8'],
    ['/index.html', 'index.html', 'text/html; charset=utf-8'],
    ['/styles.css', 'styles.css', 'text/css; charset=utf-8'],
    ['/app.js', 'app.js', 'text/javascript; charset=utf-8'],
    ['/favicon.svg', 'favicon.svg', 'image/svg+xml'],
  ];

  const files = new Map();

  for (const [route, filename, contentType] of definitions) {
    const body = await readFile(join(publicDir, filename));
    files.set(route, { body, contentType });
  }

  return files;
}
