'use strict';

// ─── DEPENDENCIES ─────────────────────────────────────────────────────────────
const express      = require('express');
const sqlite3      = require('sqlite3').verbose();
const bcrypt       = require('bcrypt');
const speakeasy    = require('speakeasy');
const cors         = require('cors');
const jwt          = require('jsonwebtoken');
const path         = require('path');
const axios        = require('axios');
const rateLimit    = require('express-rate-limit');
const helmet       = require('helmet');
const crypto       = require('crypto');
const nodemailer   = require('nodemailer');

// ─── CONFIGURATION ────────────────────────────────────────────────────────────
const PORT               = parseInt(process.env.PORT || '8080', 10);
const NODE_ENV           = process.env.NODE_ENV || 'development';
const IS_PROD            = NODE_ENV === 'production';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (IS_PROD) { console.error('FATAL: JWT_SECRET required'); process.exit(1); }
  else console.warn('WARNING: JWT_SECRET not set — using insecure dev default');
}
const EFFECTIVE_JWT_SECRET = JWT_SECRET || 'dev-only-insecure-secret-change-me';
const JWT_EXPIRY           = process.env.JWT_EXPIRY || '8h';
const BCRYPT_ROUNDS        = parseInt(process.env.BCRYPT_ROUNDS || '12', 10);
const DB_PATH              = process.env.DB_PATH || path.join(__dirname, 'users.db');
const FACEBOOK_APP_ID      = process.env.FACEBOOK_APP_ID || '';
const FACEBOOK_APP_SECRET  = process.env.FACEBOOK_APP_SECRET;
const FACEBOOK_GROUP_ID    = process.env.FACEBOOK_GROUP_ID;
const FB_BASE_URL          = 'https://graph.facebook.com/v25.0';
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || 'http://localhost:8080,http://localhost:3000')
  .split(',').map(o => o.trim());

// ─── LOGGER ───────────────────────────────────────────────────────────────────
let log;
try {
  const pino = require('pino');
  log = pino({ level: IS_PROD ? 'info' : 'debug' });
} catch {
  const fmt = (level, obj, msg) => {
    const line = JSON.stringify({ time: new Date().toISOString(), level, ...obj, msg });
    level === 'error' ? console.error(line) : console.log(line);
  };
  log = {
    info:  (o, m) => typeof o === 'string' ? fmt('info',  {}, o) : fmt('info',  o, m),
    warn:  (o, m) => typeof o === 'string' ? fmt('warn',  {}, o) : fmt('warn',  o, m),
    error: (o, m) => typeof o === 'string' ? fmt('error', {}, o) : fmt('error', o, m),
    debug: (o, m) => IS_PROD ? null : typeof o === 'string' ? fmt('debug', {}, o) : fmt('debug', o, m),
    child: () => log,
  };
}

// ─── DATABASE ─────────────────────────────────────────────────────────────────
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) { log.error({ err: err.message }, 'DB connection failed'); process.exit(1); }
  log.info({ path: DB_PATH }, 'SQLite connected');
});
db.run('PRAGMA journal_mode=WAL');
db.run('PRAGMA busy_timeout=5000');
db.run('PRAGMA foreign_keys=ON');

const dbRun  = (sql, params = []) => new Promise((resolve, reject) =>
  db.run(sql, params, function (err) { err ? reject(err) : resolve(this); }));
const dbGet  = (sql, params = []) => new Promise((resolve, reject) =>
  db.get(sql, params, (err, row) => err ? reject(err) : resolve(row)));
const dbAll  = (sql, params = []) => new Promise((resolve, reject) =>
  db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows)));

// ─── SCHEMA ───────────────────────────────────────────────────────────────────
async function initDb() {
  // Users — roles: 'admin' | 'user'
  await dbRun(`CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    UNIQUE NOT NULL COLLATE NOCASE,
    email            TEXT    UNIQUE,
    full_name        TEXT,
    password_hash    TEXT    NOT NULL,
    role             TEXT    NOT NULL DEFAULT 'user',
    is_active        INTEGER NOT NULL DEFAULT 1,
    totp_secret      TEXT,
    is_2fa_enabled   INTEGER DEFAULT 0,
    created_at       INTEGER DEFAULT (strftime('%s','now')),
    created_by       INTEGER REFERENCES users(id),
    last_login_at    INTEGER,
    last_login_ip    TEXT,
    login_count      INTEGER DEFAULT 0,
    failed_logins    INTEGER DEFAULT 0,
    locked_until     INTEGER
  )`);

  // Active JWT sessions (for forced-logout / token revocation)
  await dbRun(`CREATE TABLE IF NOT EXISTS sessions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash       TEXT    NOT NULL UNIQUE,
    ip               TEXT,
    user_agent       TEXT,
    created_at       INTEGER DEFAULT (strftime('%s','now')),
    expires_at       INTEGER NOT NULL,
    revoked          INTEGER DEFAULT 0
  )`);

  // Audit / activity log — every meaningful action
  await dbRun(`CREATE TABLE IF NOT EXISTS audit_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER REFERENCES users(id),
    username         TEXT,
    action           TEXT    NOT NULL,
    resource         TEXT,
    resource_id      INTEGER,
    ip               TEXT,
    user_agent       TEXT,
    detail           TEXT,
    created_at       INTEGER DEFAULT (strftime('%s','now'))
  )`);

  // Client cases — each case belongs to a user (the app user managing the case)
  await dbRun(`CREATE TABLE IF NOT EXISTS client_cases (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id         INTEGER NOT NULL REFERENCES users(id),
    client_name      TEXT    NOT NULL,
    client_email     TEXT,
    client_phone     TEXT,
    tax_year         INTEGER,
    status           TEXT    DEFAULT 'active',
    irs_balance      REAL    DEFAULT 0,
    analysis_data    TEXT,
    created_at       INTEGER DEFAULT (strftime('%s','now')),
    updated_at       INTEGER DEFAULT (strftime('%s','now'))
  )`);

  // Notes on each case
  await dbRun(`CREATE TABLE IF NOT EXISTS case_notes (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id          INTEGER NOT NULL REFERENCES client_cases(id) ON DELETE CASCADE,
    author_id        INTEGER NOT NULL REFERENCES users(id),
    content          TEXT    NOT NULL,
    pinned           INTEGER DEFAULT 0,
    created_at       INTEGER DEFAULT (strftime('%s','now')),
    updated_at       INTEGER DEFAULT (strftime('%s','now'))
  )`);

  // Files attached to cases
  await dbRun(`CREATE TABLE IF NOT EXISTS case_files (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id          INTEGER NOT NULL REFERENCES client_cases(id) ON DELETE CASCADE,
    uploaded_by      INTEGER NOT NULL REFERENCES users(id),
    filename         TEXT    NOT NULL,
    mime_type        TEXT,
    size_bytes       INTEGER,
    storage_key      TEXT    NOT NULL UNIQUE,
    created_at       INTEGER DEFAULT (strftime('%s','now'))
  )`);

  // ── Contacts — standalone client list (used when no case exists)
  await dbRun(`CREATE TABLE IF NOT EXISTS contacts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    full_name        TEXT    NOT NULL,
    email            TEXT,
    phone            TEXT,
    address          TEXT,
    company          TEXT,
    notes            TEXT,
    created_at       INTEGER DEFAULT (strftime('%s','now')),
    updated_at       INTEGER DEFAULT (strftime('%s','now'))
  )`);

  await dbRun(`CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_id)`);

  // ── Email settings — one row per user (SMTP outbound + optional IMAP)
  await dbRun(`CREATE TABLE IF NOT EXISTS email_settings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    -- SMTP outbound
    smtp_host        TEXT,
    smtp_port        INTEGER DEFAULT 587,
    smtp_secure      INTEGER DEFAULT 0,
    smtp_user        TEXT,
    smtp_pass        TEXT,
    smtp_from_name   TEXT,
    smtp_from_email  TEXT,
    -- IMAP inbound (optional, for "Sent" folder sync)
    imap_host        TEXT,
    imap_port        INTEGER DEFAULT 993,
    imap_secure      INTEGER DEFAULT 1,
    imap_user        TEXT,
    imap_pass        TEXT,
    -- Business identity stamped on invoices / emails
    business_name    TEXT,
    business_address TEXT,
    business_phone   TEXT,
    business_website TEXT,
    business_logo_url TEXT,
    updated_at       INTEGER DEFAULT (strftime('%s','now'))
  )`);

  // ── Invoices
  await dbRun(`CREATE TABLE IF NOT EXISTS invoices (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_number   TEXT    NOT NULL,
    owner_id         INTEGER NOT NULL REFERENCES users(id),
    case_id          INTEGER REFERENCES client_cases(id) ON DELETE SET NULL,
    -- Client billing info (may differ from case client)
    client_name      TEXT    NOT NULL,
    client_email     TEXT,
    client_address   TEXT,
    client_phone     TEXT,
    -- Amounts
    subtotal         REAL    DEFAULT 0,
    tax_rate         REAL    DEFAULT 0,
    tax_amount       REAL    DEFAULT 0,
    discount         REAL    DEFAULT 0,
    total            REAL    DEFAULT 0,
    amount_paid      REAL    DEFAULT 0,
    balance_due      REAL    DEFAULT 0,
    -- Dates
    issue_date       TEXT,
    due_date         TEXT,
    -- Status: draft | sent | paid | overdue | cancelled
    status           TEXT    DEFAULT 'draft',
    -- Custom per-client fields
    notes            TEXT,
    terms            TEXT,
    footer           TEXT,
    custom_fields    TEXT,
    -- Email tracking
    last_sent_at     INTEGER,
    sent_count       INTEGER DEFAULT 0,
    created_at       INTEGER DEFAULT (strftime('%s','now')),
    updated_at       INTEGER DEFAULT (strftime('%s','now'))
  )`);

  // ── Invoice line items
  await dbRun(`CREATE TABLE IF NOT EXISTS invoice_items (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice_id       INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    sort_order       INTEGER DEFAULT 0,
    description      TEXT    NOT NULL,
    quantity         REAL    DEFAULT 1,
    unit_price       REAL    DEFAULT 0,
    amount           REAL    DEFAULT 0,
    taxable          INTEGER DEFAULT 1
  )`);

  // ── Email send log
  await dbRun(`CREATE TABLE IF NOT EXISTS email_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER REFERENCES users(id),
    recipient        TEXT,
    subject          TEXT,
    invoice_id       INTEGER REFERENCES invoices(id) ON DELETE SET NULL,
    status           TEXT    DEFAULT 'sent',
    error_msg        TEXT,
    created_at       INTEGER DEFAULT (strftime('%s','now'))
  )`);

  // Safe migrations — ignore if column already exists
  const migrations = [
    `ALTER TABLE users ADD COLUMN email TEXT`,
    `ALTER TABLE users ADD COLUMN full_name TEXT`,
    `ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`,
    `ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1`,
    `ALTER TABLE users ADD COLUMN last_login_ip TEXT`,
    `ALTER TABLE users ADD COLUMN login_count INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN failed_logins INTEGER DEFAULT 0`,
    `ALTER TABLE users ADD COLUMN locked_until INTEGER`,
    `ALTER TABLE users ADD COLUMN created_by INTEGER`,
    // email_settings additions
    `ALTER TABLE email_settings ADD COLUMN business_email TEXT`,
    `ALTER TABLE email_settings ADD COLUMN business_footer TEXT`,
  ];
  for (const m of migrations) await dbRun(m).catch(() => {});

  // New indexes
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_invoices_owner  ON invoices(owner_id)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_invoices_case   ON invoices(case_id)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_items_invoice   ON invoice_items(invoice_id)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_email_log_user  ON email_log(user_id)`);

  // Seed first admin if no users exist
  const count = await dbGet('SELECT COUNT(*) AS n FROM users');
  if (count.n === 0) {
    const defaultPass = process.env.DEFAULT_ADMIN_PASSWORD || 'ChangeMe@First!';
    const hash = await bcrypt.hash(defaultPass, BCRYPT_ROUNDS);
    await dbRun(
      `INSERT INTO users (username, full_name, password_hash, role) VALUES (?,?,?,?)`,
      ['admin', 'System Administrator', hash, 'admin']
    );
    log.warn('Default admin account seeded — CHANGE THE PASSWORD IMMEDIATELY after first login');
  }

  // Indexes for performance
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_audit_user    ON audit_log(user_id)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_audit_time    ON audit_log(created_at)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_cases_owner   ON client_cases(owner_id)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_notes_case    ON case_notes(case_id)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
  await dbRun(`CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions(token_hash)`);

  log.info('DB: schema ready');
}

// ─── AUDIT HELPER ─────────────────────────────────────────────────────────────
async function audit(userId, username, action, resource, resourceId, ip, ua, detail) {
  await dbRun(
    `INSERT INTO audit_log (user_id,username,action,resource,resource_id,ip,user_agent,detail)
     VALUES (?,?,?,?,?,?,?,?)`,
    [userId||null, username||null, action, resource||null, resourceId||null, ip||null, ua||null, detail||null]
  ).catch(e => log.warn({ err: e.message }, 'audit write failed'));
}

// ─── FACEBOOK CLIENT ──────────────────────────────────────────────────────────
const fbAxios = axios.create({ baseURL: FB_BASE_URL, timeout: 10_000 });
let fbAccessToken = null, fbTokenExpiresAt = 0;

async function getFbToken() {
  if (fbAccessToken && Date.now() < fbTokenExpiresAt) return fbAccessToken;
  if (!FACEBOOK_APP_SECRET) throw new Error('FACEBOOK_APP_SECRET not configured');
  const { data } = await fbAxios.get('/oauth/access_token', {
    params: { client_id: FACEBOOK_APP_ID, client_secret: FACEBOOK_APP_SECRET, grant_type: 'client_credentials' },
  });
  fbAccessToken    = data.access_token;
  fbTokenExpiresAt = Date.now() + ((data.expires_in || 5_184_000) - 300) * 1000;
  return fbAccessToken;
}
async function fbGet(ep, p = {})  { const t = await getFbToken(); const { data } = await fbAxios.get(ep, { params: { ...p, access_token: t } }); return data; }
async function fbPost(ep, p = {}) { const t = await getFbToken(); const { data } = await fbAxios.post(ep, null, { params: { ...p, access_token: t } }); return data; }

// ─── EXPRESS APP ──────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);

app.use(helmet({ contentSecurityPolicy: IS_PROD }));
app.use(cors({
  origin: (origin, cb) => {
    // Allow same-origin requests (no Origin header), and any listed origin.
    // Also allow any request that comes through nginx on the same host
    // (nginx strips/rewrites Origin for proxied API calls).
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    // Permissive fallback: allow any private-network IP origin in development,
    // or any origin matching the server's own IP range
    const privateNet = /^http:\/\/(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(origin);
    if (privateNet) return cb(null, true);
    log.warn({ origin }, 'CORS: rejected origin');
    // Return a proper 403 response instead of throwing (which causes a 500)
    return cb(null, false);
  },
  credentials: true,
}));

// Explicit CORS rejection handler (catches the false case above cleanly)
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && res.getHeader('Access-Control-Allow-Origin') === undefined) {
    return res.status(403).json({ error: 'CORS: origin not allowed' });
  }
  next();
});
app.use(express.json({ limit: '2mb' }));

// Request logger (no sensitive headers)
app.use((req, _res, next) => {
  log.debug({ method: req.method, url: req.url, ip: req.ip }, 'req');
  next();
});

// Static files
app.use(express.static(path.join(__dirname, 'public'), { maxAge: IS_PROD ? '1d' : 0, etag: true }));

// ─── RATE LIMITERS ────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts — try again in 15 minutes' },
  skip: () => !IS_PROD,
});
const apiLimiter  = rateLimit({
  windowMs: 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false,
  skip: () => !IS_PROD,
});
app.use('/api/', apiLimiter);

// ─── VALIDATION ───────────────────────────────────────────────────────────────
const validateUsername = (u) => {
  if (typeof u !== 'string') return 'Username must be a string';
  if (u.trim().length < 3)  return 'Username must be at least 3 characters';
  if (u.trim().length > 64) return 'Username must be at most 64 characters';
  if (!/^[a-zA-Z0-9_@.\-]+$/.test(u.trim())) return 'Username contains invalid characters';
  return null;
};
const validatePassword = (p) => {
  if (typeof p !== 'string') return 'Password must be a string';
  if (p.length < 8)   return 'Password must be at least 8 characters';
  if (p.length > 128) return 'Password too long';
  return null;
};

// ─── TOKEN HELPERS ────────────────────────────────────────────────────────────
function tokenHash(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function issueToken(user) {
  return jwt.sign(
    { userId: user.id, username: user.username, role: user.role },
    EFFECTIVE_JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }
  const raw = header.slice(7);
  try {
    const payload = jwt.verify(raw, EFFECTIVE_JWT_SECRET);
    // Check token is not revoked
    const session = await dbGet('SELECT * FROM sessions WHERE token_hash=? AND revoked=0', [tokenHash(raw)]);
    if (!session) return res.status(401).json({ error: 'Session expired or revoked — please log in again' });
    if (session.expires_at < Math.floor(Date.now()/1000)) {
      await dbRun('UPDATE sessions SET revoked=1 WHERE id=?', [session.id]);
      return res.status(401).json({ error: 'Token expired' });
    }
    // Check user is still active
    const user = await dbGet('SELECT id,username,role,is_active FROM users WHERE id=?', [payload.userId]);
    if (!user || !user.is_active) return res.status(401).json({ error: 'Account disabled' });
    req.user = { ...payload, role: user.role };
    req.rawToken = raw;
    next();
  } catch (err) {
    return res.status(401).json({ error: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────

// Health
app.get('/healthz', (_req, res) => {
  db.get('SELECT 1', (err) => err
    ? res.status(503).json({ status: 'unhealthy', db: 'error' })
    : res.json({ status: 'ok', uptime: Math.round(process.uptime()), env: NODE_ENV })
  );
});

// ── Register (admin-only in production; open in dev for seeding)
app.post('/api/register', authLimiter, async (req, res) => {
  // In production, only admins may create accounts via POST /api/admin/users
  // This endpoint is kept for development convenience
  if (IS_PROD) return res.status(403).json({ error: 'Self-registration is disabled. Contact an administrator.' });

  const { username, password, email, full_name, role } = req.body ?? {};
  const uErr = validateUsername(username); if (uErr) return res.status(400).json({ error: uErr });
  const pErr = validatePassword(password); if (pErr) return res.status(400).json({ error: pErr });

  try {
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const r = await dbRun(
      `INSERT INTO users (username, email, full_name, password_hash, role) VALUES (?,?,?,?,?)`,
      [username.trim().toLowerCase(), email||null, full_name||null, hash, role === 'admin' ? 'admin' : 'user']
    );
    log.info({ username }, 'user registered');
    res.status(201).json({ success: true, userId: r.lastID });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Username already taken' });
    log.error({ err: err.message }, 'register failed');
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ── Login
app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const ip = req.ip;
  const ua = req.headers['user-agent'] || '';

  try {
    const user = await dbGet('SELECT * FROM users WHERE username=? COLLATE NOCASE', [String(username).trim()]);

    // Timing-safe: always run bcrypt
    const dummy = '$2b$12$invalidhashpaddingtoensureconstanttimex';
    const match  = await bcrypt.compare(String(password), user?.password_hash ?? dummy);

    if (!user || !match) {
      if (user) await dbRun('UPDATE users SET failed_logins=failed_logins+1 WHERE id=?', [user.id]);
      await audit(user?.id, user?.username, 'login_failed', 'auth', null, ip, ua, 'Invalid credentials');
      log.warn({ username, ip }, 'login failed');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.is_active) {
      await audit(user.id, user.username, 'login_blocked', 'auth', null, ip, ua, 'Account disabled');
      return res.status(403).json({ error: 'Account disabled — contact an administrator' });
    }

    if (user.locked_until && user.locked_until > Math.floor(Date.now()/1000)) {
      return res.status(429).json({ error: 'Account temporarily locked — try again later' });
    }

    // Reset failed logins + update last login
    await dbRun(
      `UPDATE users SET failed_logins=0, login_count=login_count+1,
       last_login_at=strftime('%s','now'), last_login_ip=? WHERE id=?`,
      [ip, user.id]
    );

    if (user.is_2fa_enabled) {
      await audit(user.id, user.username, 'login_2fa_pending', 'auth', null, ip, ua, null);
      return res.json({ require2fa: true, userId: user.id });
    }

    const token = issueToken(user);
    const expiresAt = Math.floor(Date.now()/1000) + 8*3600;
    await dbRun(
      `INSERT INTO sessions (user_id,token_hash,ip,user_agent,expires_at) VALUES (?,?,?,?,?)`,
      [user.id, tokenHash(token), ip, ua, expiresAt]
    );
    await audit(user.id, user.username, 'login_success', 'auth', null, ip, ua, null);
    log.info({ userId: user.id, ip }, 'login success');
    res.json({ token, role: user.role, username: user.username, userId: user.id });
  } catch (err) {
    log.error({ err: err.message }, 'login error');
    res.status(500).json({ error: 'Login failed' });
  }
});

// ── Logout (revoke token)
app.post('/api/logout', requireAuth, async (req, res) => {
  try {
    await dbRun('UPDATE sessions SET revoked=1 WHERE token_hash=?', [tokenHash(req.rawToken)]);
    await audit(req.user.userId, req.user.username, 'logout', 'auth', null, req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) {
    log.error({ err: err.message }, 'logout error');
    res.status(500).json({ error: 'Logout failed' });
  }
});

// ── Enable 2FA
app.post('/api/enable-2fa', requireAuth, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ name: `IRS Calculator (${req.user.username})` });
    await dbRun('UPDATE users SET totp_secret=?, is_2fa_enabled=1 WHERE id=?', [secret.base32, req.user.userId]);
    await audit(req.user.userId, req.user.username, 'enable_2fa', 'user', req.user.userId, req.ip, req.headers['user-agent'], null);
    res.json({ otpauth_url: secret.otpauth_url, base32: secret.base32 });
  } catch (err) {
    log.error({ err: err.message }, 'enable-2fa failed');
    res.status(500).json({ error: 'Failed to enable 2FA' });
  }
});

// ── Verify 2FA
app.post('/api/verify-2fa', authLimiter, async (req, res) => {
  const { userId, token: totpToken } = req.body ?? {};
  if (!userId || !totpToken) return res.status(400).json({ error: 'userId and token required' });
  const ip = req.ip, ua = req.headers['user-agent'] || '';
  try {
    const user = await dbGet('SELECT * FROM users WHERE id=?', [userId]);
    if (!user?.totp_secret) return res.status(401).json({ error: '2FA not enabled' });
    const ok = speakeasy.totp.verify({ secret: user.totp_secret, encoding: 'base32', token: String(totpToken), window: 1 });
    if (!ok) {
      await audit(user.id, user.username, '2fa_failed', 'auth', null, ip, ua, null);
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }
    const token = issueToken(user);
    const expiresAt = Math.floor(Date.now()/1000) + 8*3600;
    await dbRun(`INSERT INTO sessions (user_id,token_hash,ip,user_agent,expires_at) VALUES (?,?,?,?,?)`,
      [user.id, tokenHash(token), ip, ua, expiresAt]);
    await audit(user.id, user.username, 'login_success_2fa', 'auth', null, ip, ua, null);
    res.json({ token, role: user.role, username: user.username, userId: user.id });
  } catch (err) {
    log.error({ err: err.message }, 'verify-2fa error');
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ── My Profile
app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const user = await dbGet(
      `SELECT id,username,email,full_name,role,is_active,is_2fa_enabled,
              created_at,last_login_at,last_login_ip,login_count FROM users WHERE id=?`,
      [req.user.userId]
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Change own password
app.put('/api/profile/password', requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body ?? {};
  if (!current_password || !new_password) return res.status(400).json({ error: 'Both passwords required' });
  const pErr = validatePassword(new_password); if (pErr) return res.status(400).json({ error: pErr });
  try {
    const user = await dbGet('SELECT * FROM users WHERE id=?', [req.user.userId]);
    const ok = await bcrypt.compare(current_password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Current password incorrect' });
    const hash = await bcrypt.hash(new_password, BCRYPT_ROUNDS);
    await dbRun('UPDATE users SET password_hash=? WHERE id=?', [hash, req.user.userId]);
    // Revoke all other sessions
    await dbRun('UPDATE sessions SET revoked=1 WHERE user_id=? AND token_hash!=?',
      [req.user.userId, tokenHash(req.rawToken)]);
    await audit(req.user.userId, req.user.username, 'password_change', 'user', req.user.userId, req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) {
    log.error({ err: err.message }, 'password change failed');
    res.status(500).json({ error: 'Password change failed' });
  }
});

// ── Active Sessions (own)
app.get('/api/sessions', requireAuth, async (req, res) => {
  try {
    const sessions = await dbAll(
      `SELECT id, ip, user_agent, created_at, expires_at,
              (token_hash = ?) AS is_current
       FROM sessions WHERE user_id=? AND revoked=0 ORDER BY created_at DESC`,
      [tokenHash(req.rawToken), req.user.userId]
    );
    res.json(sessions);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Revoke a specific session
app.delete('/api/sessions/:id', requireAuth, async (req, res) => {
  try {
    const session = await dbGet('SELECT * FROM sessions WHERE id=? AND user_id=?',
      [req.params.id, req.user.userId]);
    if (!session) return res.status(404).json({ error: 'Session not found' });
    await dbRun('UPDATE sessions SET revoked=1 WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke session' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ── User list
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const users = await dbAll(
      `SELECT id, username, email, full_name, role, is_active, is_2fa_enabled,
              created_at, last_login_at, last_login_ip, login_count, failed_logins
       FROM users ORDER BY created_at DESC`
    );
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ── Create user (admin)
app.post('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, email, full_name, role } = req.body ?? {};
  const uErr = validateUsername(username); if (uErr) return res.status(400).json({ error: uErr });
  const pErr = validatePassword(password); if (pErr) return res.status(400).json({ error: pErr });
  try {
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const r = await dbRun(
      `INSERT INTO users (username,email,full_name,password_hash,role,created_by) VALUES (?,?,?,?,?,?)`,
      [username.trim().toLowerCase(), email||null, full_name||null, hash,
       role === 'admin' ? 'admin' : 'user', req.user.userId]
    );
    await audit(req.user.userId, req.user.username, 'create_user', 'user', r.lastID, req.ip, req.headers['user-agent'],
      `Created ${role||'user'}: ${username}`);
    log.info({ by: req.user.username, newUser: username }, 'admin created user');
    res.status(201).json({ success: true, userId: r.lastID });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Username already taken' });
    log.error({ err: err.message }, 'admin create user failed');
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// ── Update user (admin)
app.put('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { email, full_name, role, is_active } = req.body ?? {};
  const targetId = parseInt(req.params.id, 10);
  try {
    const existing = await dbGet('SELECT * FROM users WHERE id=?', [targetId]);
    if (!existing) return res.status(404).json({ error: 'User not found' });
    await dbRun(
      `UPDATE users SET email=?, full_name=?, role=?, is_active=? WHERE id=?`,
      [email ?? existing.email, full_name ?? existing.full_name,
       role ?? existing.role, is_active !== undefined ? (is_active ? 1 : 0) : existing.is_active,
       targetId]
    );
    // If disabling, revoke all their sessions
    if (is_active === false || is_active === 0) {
      await dbRun('UPDATE sessions SET revoked=1 WHERE user_id=?', [targetId]);
    }
    await audit(req.user.userId, req.user.username, 'update_user', 'user', targetId, req.ip, req.headers['user-agent'],
      JSON.stringify({ role, is_active }));
    res.json({ success: true });
  } catch (err) {
    log.error({ err: err.message }, 'admin update user failed');
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// ── Reset user password (admin)
app.post('/api/admin/users/:id/reset-password', requireAuth, requireAdmin, async (req, res) => {
  const { new_password } = req.body ?? {};
  const pErr = validatePassword(new_password); if (pErr) return res.status(400).json({ error: pErr });
  const targetId = parseInt(req.params.id, 10);
  try {
    const hash = await bcrypt.hash(new_password, BCRYPT_ROUNDS);
    await dbRun('UPDATE users SET password_hash=? WHERE id=?', [hash, targetId]);
    await dbRun('UPDATE sessions SET revoked=1 WHERE user_id=?', [targetId]);
    await audit(req.user.userId, req.user.username, 'reset_password', 'user', targetId, req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// ── Delete user (admin) — prevent self-deletion
app.delete('/api/admin/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.user.userId) return res.status(400).json({ error: 'Cannot delete your own account' });
  try {
    await dbRun('UPDATE sessions SET revoked=1 WHERE user_id=?', [targetId]);
    await dbRun('DELETE FROM users WHERE id=?', [targetId]);
    await audit(req.user.userId, req.user.username, 'delete_user', 'user', targetId, req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ── Audit log (admin)
app.get('/api/admin/audit', requireAuth, requireAdmin, async (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit  || '100', 10), 500);
  const offset = parseInt(req.query.offset || '0', 10);
  const userId = req.query.user_id ? parseInt(req.query.user_id, 10) : null;
  try {
    const rows = await dbAll(
      `SELECT * FROM audit_log
       ${userId ? 'WHERE user_id=?' : ''}
       ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      userId ? [userId, limit, offset] : [limit, offset]
    );
    const total = await dbGet(
      `SELECT COUNT(*) AS n FROM audit_log ${userId ? 'WHERE user_id=?' : ''}`,
      userId ? [userId] : []
    );
    res.json({ rows, total: total.n, limit, offset });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// ── Analytics (admin)
app.get('/api/admin/analytics', requireAuth, requireAdmin, async (req, res) => {
  try {
    const [
      totalUsers, activeUsers, adminCount,
      totalCases, activeCases, totalNotes,
      recentLogins, loginsByDay, topUsers, failedLogins
    ] = await Promise.all([
      dbGet(`SELECT COUNT(*) AS n FROM users`),
      dbGet(`SELECT COUNT(*) AS n FROM users WHERE is_active=1`),
      dbGet(`SELECT COUNT(*) AS n FROM users WHERE role='admin'`),
      dbGet(`SELECT COUNT(*) AS n FROM client_cases`),
      dbGet(`SELECT COUNT(*) AS n FROM client_cases WHERE status='active'`),
      dbGet(`SELECT COUNT(*) AS n FROM case_notes`),
      dbAll(`SELECT u.username, s.ip, s.created_at, s.user_agent
             FROM sessions s JOIN users u ON u.id=s.user_id
             WHERE s.revoked=0 ORDER BY s.created_at DESC LIMIT 20`),
      dbAll(`SELECT date(created_at,'unixepoch') AS day, COUNT(*) AS logins
             FROM audit_log WHERE action='login_success'
             AND created_at > strftime('%s','now','-30 days')
             GROUP BY day ORDER BY day`),
      dbAll(`SELECT username, login_count FROM users ORDER BY login_count DESC LIMIT 10`),
      dbGet(`SELECT COUNT(*) AS n FROM audit_log WHERE action='login_failed'
             AND created_at > strftime('%s','now','-24 hours')`),
    ]);
    res.json({
      users: { total: totalUsers.n, active: activeUsers.n, admins: adminCount.n },
      cases: { total: totalCases.n, active: activeCases.n, notes: totalNotes.n },
      security: { failedLoginsLast24h: failedLogins.n },
      recentLogins,
      loginsByDay,
      topUsers,
    });
  } catch (err) {
    log.error({ err: err.message }, 'analytics failed');
    res.status(500).json({ error: 'Failed to fetch analytics' });
  }
});

// ── All sessions (admin)
app.get('/api/admin/sessions', requireAuth, requireAdmin, async (req, res) => {
  try {
    const rows = await dbAll(
      `SELECT s.id, u.username, s.ip, s.user_agent, s.created_at, s.expires_at, s.revoked
       FROM sessions s JOIN users u ON u.id=s.user_id
       WHERE s.revoked=0 AND s.expires_at > strftime('%s','now')
       ORDER BY s.created_at DESC LIMIT 200`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Force-logout a user (revoke all their sessions)
app.delete('/api/admin/users/:id/sessions', requireAuth, requireAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  try {
    await dbRun('UPDATE sessions SET revoked=1 WHERE user_id=?', [targetId]);
    await audit(req.user.userId, req.user.username, 'force_logout', 'user', targetId, req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to revoke sessions' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CLIENT CASES
// ═══════════════════════════════════════════════════════════════════════════════

// List cases (own for users, all for admins)
app.get('/api/cases', requireAuth, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const cases = await dbAll(
      isAdmin
        ? `SELECT c.*, u.username AS owner_username FROM client_cases c
           JOIN users u ON u.id=c.owner_id ORDER BY c.updated_at DESC`
        : `SELECT * FROM client_cases WHERE owner_id=? ORDER BY updated_at DESC`,
      isAdmin ? [] : [req.user.userId]
    );
    res.json(cases);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch cases' });
  }
});

// Create case
app.post('/api/cases', requireAuth, async (req, res) => {
  const { client_name, client_email, client_phone, tax_year, irs_balance, analysis_data } = req.body ?? {};
  if (!client_name?.trim()) return res.status(400).json({ error: 'client_name is required' });
  try {
    const r = await dbRun(
      `INSERT INTO client_cases (owner_id,client_name,client_email,client_phone,tax_year,irs_balance,analysis_data)
       VALUES (?,?,?,?,?,?,?)`,
      [req.user.userId, client_name.trim(), client_email||null, client_phone||null,
       tax_year||null, irs_balance||0, analysis_data ? JSON.stringify(analysis_data) : null]
    );
    await audit(req.user.userId, req.user.username, 'create_case', 'case', r.lastID, req.ip, req.headers['user-agent'],
      `Client: ${client_name}`);
    res.status(201).json({ success: true, caseId: r.lastID });
  } catch (err) {
    log.error({ err: err.message }, 'create case failed');
    res.status(500).json({ error: 'Failed to create case' });
  }
});

// Get single case
app.get('/api/cases/:id', requireAuth, async (req, res) => {
  try {
    const c = await dbGet('SELECT * FROM client_cases WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Case not found' });
    if (req.user.role !== 'admin' && c.owner_id !== req.user.userId)
      return res.status(403).json({ error: 'Access denied' });
    res.json(c);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch case' });
  }
});

// Update case
app.put('/api/cases/:id', requireAuth, async (req, res) => {
  try {
    const c = await dbGet('SELECT * FROM client_cases WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Case not found' });
    if (req.user.role !== 'admin' && c.owner_id !== req.user.userId)
      return res.status(403).json({ error: 'Access denied' });
    const { client_name, client_email, client_phone, tax_year, status, irs_balance, analysis_data } = req.body ?? {};
    await dbRun(
      `UPDATE client_cases SET client_name=?, client_email=?, client_phone=?, tax_year=?,
       status=?, irs_balance=?, analysis_data=?, updated_at=strftime('%s','now') WHERE id=?`,
      [client_name ?? c.client_name, client_email ?? c.client_email, client_phone ?? c.client_phone,
       tax_year ?? c.tax_year, status ?? c.status, irs_balance ?? c.irs_balance,
       analysis_data ? JSON.stringify(analysis_data) : c.analysis_data, req.params.id]
    );
    await audit(req.user.userId, req.user.username, 'update_case', 'case', parseInt(req.params.id), req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update case' });
  }
});

// Delete case
app.delete('/api/cases/:id', requireAuth, async (req, res) => {
  try {
    const c = await dbGet('SELECT * FROM client_cases WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Case not found' });
    if (req.user.role !== 'admin' && c.owner_id !== req.user.userId)
      return res.status(403).json({ error: 'Access denied' });
    await dbRun('DELETE FROM client_cases WHERE id=?', [req.params.id]);
    await audit(req.user.userId, req.user.username, 'delete_case', 'case', parseInt(req.params.id), req.ip, req.headers['user-agent'],
      `Client: ${c.client_name}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete case' });
  }
});

// ── Case Notes
app.get('/api/cases/:id/notes', requireAuth, async (req, res) => {
  try {
    const c = await dbGet('SELECT owner_id FROM client_cases WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Case not found' });
    if (req.user.role !== 'admin' && c.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    const notes = await dbAll(
      `SELECT n.*, u.username AS author_username FROM case_notes n
       JOIN users u ON u.id=n.author_id WHERE n.case_id=? ORDER BY n.pinned DESC, n.created_at DESC`,
      [req.params.id]
    );
    res.json(notes);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch notes' }); }
});

app.post('/api/cases/:id/notes', requireAuth, async (req, res) => {
  const { content, pinned } = req.body ?? {};
  if (!content?.trim()) return res.status(400).json({ error: 'content is required' });
  try {
    const c = await dbGet('SELECT owner_id FROM client_cases WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Case not found' });
    if (req.user.role !== 'admin' && c.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    const r = await dbRun(
      `INSERT INTO case_notes (case_id,author_id,content,pinned) VALUES (?,?,?,?)`,
      [req.params.id, req.user.userId, content.trim(), pinned ? 1 : 0]
    );
    await dbRun(`UPDATE client_cases SET updated_at=strftime('%s','now') WHERE id=?`, [req.params.id]);
    res.status(201).json({ success: true, noteId: r.lastID });
  } catch (err) { res.status(500).json({ error: 'Failed to add note' }); }
});

app.put('/api/cases/:caseId/notes/:noteId', requireAuth, async (req, res) => {
  const { content, pinned } = req.body ?? {};
  try {
    const note = await dbGet('SELECT * FROM case_notes WHERE id=? AND case_id=?', [req.params.noteId, req.params.caseId]);
    if (!note) return res.status(404).json({ error: 'Note not found' });
    if (req.user.role !== 'admin' && note.author_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    await dbRun(`UPDATE case_notes SET content=?, pinned=?, updated_at=strftime('%s','now') WHERE id=?`,
      [content ?? note.content, pinned !== undefined ? (pinned ? 1 : 0) : note.pinned, req.params.noteId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update note' }); }
});

app.delete('/api/cases/:caseId/notes/:noteId', requireAuth, async (req, res) => {
  try {
    const note = await dbGet('SELECT * FROM case_notes WHERE id=? AND case_id=?', [req.params.noteId, req.params.caseId]);
    if (!note) return res.status(404).json({ error: 'Note not found' });
    if (req.user.role !== 'admin' && note.author_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    await dbRun('DELETE FROM case_notes WHERE id=?', [req.params.noteId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete note' }); }
});

// ── Case Files (metadata only — file content stored on disk/volume)
app.get('/api/cases/:id/files', requireAuth, async (req, res) => {
  try {
    const c = await dbGet('SELECT owner_id FROM client_cases WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Case not found' });
    if (req.user.role !== 'admin' && c.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    const files = await dbAll(
      `SELECT f.*, u.username AS uploader FROM case_files f
       JOIN users u ON u.id=f.uploaded_by WHERE f.case_id=? ORDER BY f.created_at DESC`,
      [req.params.id]
    );
    res.json(files);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch files' }); }
});

app.post('/api/cases/:id/files', requireAuth, async (req, res) => {
  const { filename, mime_type, size_bytes } = req.body ?? {};
  if (!filename?.trim()) return res.status(400).json({ error: 'filename required' });
  try {
    const c = await dbGet('SELECT owner_id FROM client_cases WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Case not found' });
    if (req.user.role !== 'admin' && c.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    const storageKey = `${req.params.id}/${Date.now()}_${crypto.randomBytes(8).toString('hex')}_${filename}`;
    const r = await dbRun(
      `INSERT INTO case_files (case_id,uploaded_by,filename,mime_type,size_bytes,storage_key) VALUES (?,?,?,?,?,?)`,
      [req.params.id, req.user.userId, filename.trim(), mime_type||null, size_bytes||null, storageKey]
    );
    await audit(req.user.userId, req.user.username, 'upload_file', 'file', r.lastID, req.ip, req.headers['user-agent'],
      `File: ${filename} for case ${req.params.id}`);
    res.status(201).json({ success: true, fileId: r.lastID, storageKey });
  } catch (err) { res.status(500).json({ error: 'Failed to register file' }); }
});

app.delete('/api/cases/:caseId/files/:fileId', requireAuth, async (req, res) => {
  try {
    const f = await dbGet('SELECT * FROM case_files WHERE id=? AND case_id=?', [req.params.fileId, req.params.caseId]);
    if (!f) return res.status(404).json({ error: 'File not found' });
    if (req.user.role !== 'admin' && f.uploaded_by !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    await dbRun('DELETE FROM case_files WHERE id=?', [req.params.fileId]);
    await audit(req.user.userId, req.user.username, 'delete_file', 'file', parseInt(req.params.fileId), req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete file' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FACEBOOK
// ═══════════════════════════════════════════════════════════════════════════════
app.get('/api/facebook/configure', requireAuth, (_req, res) => {
  res.json({ appId: FACEBOOK_APP_ID, groupIdConfigured: !!FACEBOOK_GROUP_ID, hasSecret: !!FACEBOOK_APP_SECRET });
});
app.get('/api/facebook/group/info', requireAuth, async (_req, res) => {
  if (!FACEBOOK_GROUP_ID) return res.status(503).json({ error: 'Facebook group not configured' });
  try { res.json(await fbGet(`/${FACEBOOK_GROUP_ID}`, { fields: 'name,description,member_count,privacy' })); }
  catch (err) { res.status(502).json({ error: 'Failed to fetch group info' }); }
});
app.get('/api/facebook/group/posts', requireAuth, async (req, res) => {
  if (!FACEBOOK_GROUP_ID) return res.status(503).json({ error: 'Facebook group not configured' });
  try { res.json(await fbGet(`/${FACEBOOK_GROUP_ID}/feed`, { limit: Math.min(parseInt(req.query.limit||'25'),100) })); }
  catch (err) { res.status(502).json({ error: 'Failed to fetch posts' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// USAGE REPORTS  (admin only)
// ═══════════════════════════════════════════════════════════════════════════════

// Per-user usage report
app.get('/api/admin/reports/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const rows = await dbAll(`
      SELECT
        u.id,
        u.username,
        u.full_name,
        u.role,
        u.is_active,
        u.login_count,
        u.last_login_at,
        u.last_login_ip,
        u.created_at,
        (SELECT COUNT(*) FROM client_cases  WHERE owner_id = u.id)                         AS cases_total,
        (SELECT COUNT(*) FROM client_cases  WHERE owner_id = u.id AND status='active')      AS cases_active,
        (SELECT COUNT(*) FROM case_notes    WHERE author_id = u.id)                         AS notes_written,
        (SELECT COUNT(*) FROM case_files    WHERE uploaded_by = u.id)                       AS files_uploaded,
        (SELECT COUNT(*) FROM audit_log     WHERE user_id = u.id)                           AS actions_total,
        (SELECT COUNT(*) FROM audit_log     WHERE user_id = u.id AND action='login_success') AS logins_total,
        (SELECT COUNT(*) FROM audit_log     WHERE user_id = u.id AND action='login_failed')  AS login_failures,
        (SELECT COUNT(*) FROM audit_log     WHERE user_id = u.id
          AND created_at > strftime('%s','now','-7 days'))                                  AS actions_7d,
        (SELECT COUNT(*) FROM sessions      WHERE user_id = u.id AND revoked=0
          AND expires_at > strftime('%s','now'))                                            AS active_sessions
      FROM users u
      ORDER BY u.login_count DESC
    `);
    res.json(rows);
  } catch (err) {
    log.error({ err: err.message }, 'usage report failed');
    res.status(500).json({ error: 'Failed to generate report' });
  }
});

// Login activity over time (per-user breakdown by day, last 30 days)
app.get('/api/admin/reports/logins', requireAuth, requireAdmin, async (req, res) => {
  try {
    const rows = await dbAll(`
      SELECT
        date(a.created_at, 'unixepoch') AS day,
        a.username,
        COUNT(*) AS logins
      FROM audit_log a
      WHERE a.action IN ('login_success','login_success_2fa')
        AND a.created_at > strftime('%s','now','-30 days')
      GROUP BY day, a.username
      ORDER BY day DESC, logins DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate login report' });
  }
});

// Case activity summary
app.get('/api/admin/reports/cases', requireAuth, requireAdmin, async (req, res) => {
  try {
    const rows = await dbAll(`
      SELECT
        c.id,
        c.client_name,
        c.client_email,
        c.tax_year,
        c.irs_balance,
        c.status,
        c.created_at,
        c.updated_at,
        u.username     AS owner,
        (SELECT COUNT(*) FROM case_notes WHERE case_id=c.id)  AS note_count,
        (SELECT COUNT(*) FROM case_files WHERE case_id=c.id)  AS file_count
      FROM client_cases c
      JOIN users u ON u.id = c.owner_id
      ORDER BY c.updated_at DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate cases report' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DATABASE VIEWER  (admin only — read all tables, edit rows, never drop tables)
// ═══════════════════════════════════════════════════════════════════════════════

// List all user-created tables
app.get('/api/admin/db/tables', requireAuth, requireAdmin, async (req, res) => {
  try {
    const tables = await dbAll(
      `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`
    );
    res.json(tables.map(t => t.name));
  } catch (err) {
    res.status(500).json({ error: 'Failed to list tables' });
  }
});

// Get schema (columns) for a table
app.get('/api/admin/db/tables/:table/schema', requireAuth, requireAdmin, async (req, res) => {
  const table = req.params.table.replace(/[^a-z0-9_]/gi, '');
  try {
    const cols = await dbAll(`PRAGMA table_info(${table})`);
    const count = await dbGet(`SELECT COUNT(*) AS n FROM ${table}`);
    res.json({ table, columns: cols, rowCount: count.n });
  } catch (err) {
    res.status(500).json({ error: `Failed to get schema for ${table}` });
  }
});

// Browse rows with pagination + optional search
app.get('/api/admin/db/tables/:table/rows', requireAuth, requireAdmin, async (req, res) => {
  const table  = req.params.table.replace(/[^a-z0-9_]/gi, '');
  const limit  = Math.min(parseInt(req.query.limit  || '50',  10), 200);
  const offset = parseInt(req.query.offset || '0', 10);
  const search = req.query.search ? String(req.query.search) : null;
  const sortBy = req.query.sort   ? req.query.sort.replace(/[^a-z0-9_]/gi,'') : 'rowid';
  const sortDir= req.query.dir === 'asc' ? 'ASC' : 'DESC';

  try {
    // Get columns to build a safe search query
    const cols = await dbAll(`PRAGMA table_info(${table})`);
    const colNames = cols.map(c => c.name);
    if (!colNames.includes(sortBy) && sortBy !== 'rowid') {
      return res.status(400).json({ error: 'Invalid sort column' });
    }

    let whereClause = '';
    let params = [];
    if (search) {
      // Search across all TEXT columns
      const textCols = cols.filter(c => c.type.toLowerCase().includes('text') || c.type === '').map(c => c.name);
      if (textCols.length > 0) {
        whereClause = 'WHERE ' + textCols.map(c => `CAST(${c} AS TEXT) LIKE ?`).join(' OR ');
        params = textCols.map(() => `%${search}%`);
      }
    }

    const rows  = await dbAll(
      `SELECT * FROM ${table} ${whereClause} ORDER BY ${sortBy} ${sortDir} LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    const total = await dbGet(
      `SELECT COUNT(*) AS n FROM ${table} ${whereClause}`,
      params
    );

    await audit(req.user.userId, req.user.username, 'db_view', table, null, req.ip, req.headers['user-agent'],
      `table=${table} offset=${offset} search=${search||''}`);

    res.json({ table, columns: colNames, rows, total: total.n, limit, offset });
  } catch (err) {
    log.error({ err: err.message }, 'db viewer rows failed');
    res.status(500).json({ error: `Failed to read ${table}` });
  }
});

// Update a single row by rowid
app.put('/api/admin/db/tables/:table/rows/:rowid', requireAuth, requireAdmin, async (req, res) => {
  const table = req.params.table.replace(/[^a-z0-9_]/gi, '');
  const rowid = parseInt(req.params.rowid, 10);

  // Safety: never allow editing sessions or audit_log from this interface
  const READONLY_TABLES = ['sessions', 'audit_log'];
  if (READONLY_TABLES.includes(table)) {
    return res.status(403).json({ error: `Table "${table}" is read-only` });
  }

  const updates = req.body ?? {};
  const keys = Object.keys(updates).filter(k => /^[a-z0-9_]+$/i.test(k));
  if (keys.length === 0) return res.status(400).json({ error: 'No fields to update' });

  // Never allow updating password_hash or totp_secret via this interface
  const PROTECTED_FIELDS = ['password_hash', 'totp_secret'];
  if (keys.some(k => PROTECTED_FIELDS.includes(k))) {
    return res.status(403).json({ error: 'Cannot update protected fields via DB viewer' });
  }

  try {
    const setClause = keys.map(k => `${k} = ?`).join(', ');
    const values    = keys.map(k => updates[k]);
    await dbRun(`UPDATE ${table} SET ${setClause} WHERE rowid = ?`, [...values, rowid]);
    await audit(req.user.userId, req.user.username, 'db_edit', table, rowid, req.ip, req.headers['user-agent'],
      `Updated fields: ${keys.join(',')}`);
    res.json({ success: true });
  } catch (err) {
    log.error({ err: err.message }, 'db edit failed');
    res.status(500).json({ error: 'Failed to update row' });
  }
});

// Delete a single row by rowid
app.delete('/api/admin/db/tables/:table/rows/:rowid', requireAuth, requireAdmin, async (req, res) => {
  const table = req.params.table.replace(/[^a-z0-9_]/gi, '');
  const rowid = parseInt(req.params.rowid, 10);

  const READONLY_TABLES = ['sessions', 'audit_log'];
  if (READONLY_TABLES.includes(table)) {
    return res.status(403).json({ error: `Table "${table}" is read-only` });
  }
  // Never allow deleting the last admin user
  if (table === 'users') {
    const target = await dbGet('SELECT role FROM users WHERE rowid=?', [rowid]);
    if (target?.role === 'admin') {
      const adminCount = await dbGet(`SELECT COUNT(*) AS n FROM users WHERE role='admin'`);
      if (adminCount.n <= 1) return res.status(400).json({ error: 'Cannot delete the last admin account' });
    }
  }

  try {
    await dbRun(`DELETE FROM ${table} WHERE rowid = ?`, [rowid]);
    await audit(req.user.userId, req.user.username, 'db_delete', table, rowid, req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete row' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// EMAIL SETTINGS
// ═══════════════════════════════════════════════════════════════════════════════

// Get current user's email settings (passwords masked)
app.get('/api/email/settings', requireAuth, async (req, res) => {
  try {
    const row = await dbGet('SELECT * FROM email_settings WHERE user_id=?', [req.user.userId]);
    if (!row) return res.json({});
    const safe = { ...row };
    // Mask passwords
    if (safe.smtp_pass) safe.smtp_pass = '••••••••';
    if (safe.imap_pass) safe.imap_pass = '••••••••';
    // If the logo is a large base64 data URL (stored from file upload),
    // strip it from the response to avoid sending 100KB+ on every settings load.
    // The frontend will re-upload or use the URL field instead.
    if (safe.business_logo_url && safe.business_logo_url.startsWith('data:')) {
      safe.business_logo_url = '';  // don't send base64 back — too large
      safe._has_logo = true;        // let the client know a logo exists
    }
    res.json(safe);
  } catch (err) { res.status(500).json({ error: 'Failed to load settings' }); }
});

// Save/update email settings
app.put('/api/email/settings', requireAuth, async (req, res) => {
  const {
    smtp_host, smtp_port, smtp_secure, smtp_user, smtp_pass,
    smtp_from_name, smtp_from_email,
    imap_host, imap_port, imap_secure, imap_user, imap_pass,
    business_name, business_address, business_phone, business_website,
    business_logo_url, business_email, business_footer
  } = req.body ?? {};

  try {
    const existing = await dbGet('SELECT * FROM email_settings WHERE user_id=?', [req.user.userId]);
    const finalSmtpPass = (smtp_pass && smtp_pass !== '••••••••') ? smtp_pass : (existing?.smtp_pass || null);
    const finalImapPass = (imap_pass && imap_pass !== '••••••••') ? imap_pass : (existing?.imap_pass || null);

    if (existing) {
      await dbRun(`UPDATE email_settings SET
        smtp_host=?,smtp_port=?,smtp_secure=?,smtp_user=?,smtp_pass=?,
        smtp_from_name=?,smtp_from_email=?,
        imap_host=?,imap_port=?,imap_secure=?,imap_user=?,imap_pass=?,
        business_name=?,business_address=?,business_phone=?,business_website=?,
        business_logo_url=?,business_email=?,business_footer=?,
        updated_at=strftime('%s','now') WHERE user_id=?`,
        [smtp_host||null, smtp_port||587, smtp_secure?1:0, smtp_user||null, finalSmtpPass,
         smtp_from_name||null, smtp_from_email||null,
         imap_host||null, imap_port||993, imap_secure?1:0, imap_user||null, finalImapPass,
         business_name||null, business_address||null, business_phone||null, business_website||null,
         business_logo_url||null, business_email||null, business_footer||null,
         req.user.userId]);
    } else {
      await dbRun(`INSERT INTO email_settings
        (user_id,smtp_host,smtp_port,smtp_secure,smtp_user,smtp_pass,smtp_from_name,smtp_from_email,
         imap_host,imap_port,imap_secure,imap_user,imap_pass,
         business_name,business_address,business_phone,business_website,
         business_logo_url,business_email,business_footer)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [req.user.userId, smtp_host||null, smtp_port||587, smtp_secure?1:0, smtp_user||null, finalSmtpPass,
         smtp_from_name||null, smtp_from_email||null,
         imap_host||null, imap_port||993, imap_secure?1:0, imap_user||null, finalImapPass,
         business_name||null, business_address||null, business_phone||null, business_website||null,
         business_logo_url||null, business_email||null, business_footer||null]);
    }
    await audit(req.user.userId, req.user.username, 'update_email_settings', 'email_settings', null, req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) {
    log.error({ err: err.message }, 'save email settings failed');
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// Test SMTP connection
app.post('/api/email/test', requireAuth, async (req, res) => {
  try {
    const cfg = await dbGet('SELECT * FROM email_settings WHERE user_id=?', [req.user.userId]);
    if (!cfg?.smtp_host) return res.status(400).json({ error: 'No SMTP settings configured' });

    const transporter = nodemailer.createTransport({
      host: cfg.smtp_host, port: cfg.smtp_port || 587,
      secure: !!cfg.smtp_secure,
      auth: { user: cfg.smtp_user, pass: cfg.smtp_pass },
      tls: { rejectUnauthorized: false }
    });
    await transporter.verify();
    res.json({ success: true, message: 'SMTP connection successful' });
  } catch (err) {
    res.status(400).json({ error: `SMTP test failed: ${err.message}` });
  }
});

// Send a free-form email to a customer (supports cc, bcc, multiple recipients)
app.post('/api/email/send', requireAuth, async (req, res) => {
  const { to, cc, bcc, subject, body_html, body_text } = req.body ?? {};
  if (!to || !subject) return res.status(400).json({ error: 'to and subject are required' });

  try {
    const cfg = await dbGet('SELECT * FROM email_settings WHERE user_id=?', [req.user.userId]);
    if (!cfg?.smtp_host) return res.status(400).json({ error: 'Configure SMTP settings before sending' });

    const transporter = nodemailer.createTransport({
      host: cfg.smtp_host, port: cfg.smtp_port || 587,
      secure: !!cfg.smtp_secure,
      auth: { user: cfg.smtp_user, pass: cfg.smtp_pass },
      tls: { rejectUnauthorized: false }
    });

    const from = cfg.smtp_from_email
      ? `"${cfg.smtp_from_name || cfg.business_name || 'IRS Calculator'}" <${cfg.smtp_from_email}>`
      : cfg.smtp_user;

    const mailOptions = { from, to, subject, html: body_html || body_text, text: body_text || body_html };
    if (cc)  mailOptions.cc  = cc;
    if (bcc) mailOptions.bcc = bcc;

    await transporter.sendMail(mailOptions);
    const allRecipients = [to, cc, bcc].filter(Boolean).join(', ');
    await dbRun('INSERT INTO email_log (user_id,recipient,subject,status) VALUES (?,?,?,?)',
      [req.user.userId, allRecipients, subject, 'sent']);
    await audit(req.user.userId, req.user.username, 'send_email', 'email', null, req.ip, req.headers['user-agent'], `To: ${allRecipients}`);
    res.json({ success: true });
  } catch (err) {
    await dbRun('INSERT INTO email_log (user_id,recipient,subject,status,error_msg) VALUES (?,?,?,?,?)',
      [req.user.userId, to, subject, 'failed', err.message]).catch(()=>{});
    log.error({ err: err.message }, 'send email failed');
    res.status(500).json({ error: `Failed to send email: ${err.message}` });
  }
});

// Email send history
app.get('/api/email/log', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit||'50',10),200);
    const rows = await dbAll(
      `SELECT * FROM email_log WHERE user_id=? ORDER BY created_at DESC LIMIT ?`,
      [req.user.userId, limit]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to load email log' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// INVOICES
// ═══════════════════════════════════════════════════════════════════════════════

function nextInvoiceNumber(userId) {
  const now = new Date();
  const y = now.getFullYear(), m = String(now.getMonth()+1).padStart(2,'0');
  const rand = Math.floor(Math.random()*9000)+1000;
  return `INV-${y}${m}-${rand}`;
}

function calcInvoiceTotals(items, taxRate, discount) {
  const subtotal = items.reduce((s, i) => s + (parseFloat(i.quantity||1) * parseFloat(i.unit_price||0)), 0);
  const taxableSubtotal = items.filter(i => i.taxable !== false && i.taxable !== 0)
    .reduce((s, i) => s + (parseFloat(i.quantity||1) * parseFloat(i.unit_price||0)), 0);
  const tax = Math.round(taxableSubtotal * (parseFloat(taxRate||0)/100) * 100) / 100;
  const disc = parseFloat(discount||0);
  const total = Math.round((subtotal + tax - disc) * 100) / 100;
  return { subtotal: Math.round(subtotal*100)/100, tax_amount: tax, total, balance_due: total };
}

// List invoices (own, or all for admin)
app.get('/api/invoices', requireAuth, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const rows = await dbAll(
      isAdmin
        ? `SELECT i.*, u.username AS owner_username FROM invoices i JOIN users u ON u.id=i.owner_id ORDER BY i.updated_at DESC`
        : `SELECT * FROM invoices WHERE owner_id=? ORDER BY updated_at DESC`,
      isAdmin ? [] : [req.user.userId]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch invoices' }); }
});

// Get single invoice with line items
app.get('/api/invoices/:id', requireAuth, async (req, res) => {
  try {
    const inv = await dbGet('SELECT * FROM invoices WHERE id=?', [req.params.id]);
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    if (req.user.role !== 'admin' && inv.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    const items = await dbAll('SELECT * FROM invoice_items WHERE invoice_id=? ORDER BY sort_order,id', [req.params.id]);
    res.json({ ...inv, items });
  } catch (err) { res.status(500).json({ error: 'Failed to fetch invoice' }); }
});

// Create invoice
app.post('/api/invoices', requireAuth, async (req, res) => {
  const {
    case_id, client_name, client_email, client_address, client_phone,
    issue_date, due_date, tax_rate, discount, notes, terms, footer, custom_fields,
    items = []
  } = req.body ?? {};
  if (!client_name?.trim()) return res.status(400).json({ error: 'client_name is required' });

  try {
    const invNum = nextInvoiceNumber(req.user.userId);
    const totals = calcInvoiceTotals(items, tax_rate, discount);

    const r = await dbRun(`INSERT INTO invoices
      (invoice_number,owner_id,case_id,client_name,client_email,client_address,client_phone,
       subtotal,tax_rate,tax_amount,discount,total,balance_due,
       issue_date,due_date,notes,terms,footer,custom_fields,status)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [invNum, req.user.userId, case_id||null, client_name.trim(), client_email||null,
       client_address||null, client_phone||null,
       totals.subtotal, parseFloat(tax_rate||0), totals.tax_amount,
       parseFloat(discount||0), totals.total, totals.balance_due,
       issue_date||new Date().toISOString().slice(0,10),
       due_date||null, notes||null, terms||null, footer||null,
       custom_fields ? JSON.stringify(custom_fields) : null, 'draft']);

    const invId = r.lastID;
    for (let idx = 0; idx < items.length; idx++) {
      const it = items[idx];
      const amt = Math.round(parseFloat(it.quantity||1) * parseFloat(it.unit_price||0) * 100) / 100;
      await dbRun('INSERT INTO invoice_items (invoice_id,sort_order,description,quantity,unit_price,amount,taxable) VALUES (?,?,?,?,?,?,?)',
        [invId, idx, it.description||'', parseFloat(it.quantity||1), parseFloat(it.unit_price||0), amt, it.taxable!==false?1:0]);
    }
    await audit(req.user.userId, req.user.username, 'create_invoice', 'invoice', invId, req.ip, req.headers['user-agent'], `${invNum} for ${client_name}`);
    res.status(201).json({ success: true, invoiceId: invId, invoiceNumber: invNum });
  } catch (err) {
    log.error({ err: err.message }, 'create invoice failed');
    res.status(500).json({ error: 'Failed to create invoice' });
  }
});

// Update invoice (replaces all line items)
app.put('/api/invoices/:id', requireAuth, async (req, res) => {
  try {
    const inv = await dbGet('SELECT * FROM invoices WHERE id=?', [req.params.id]);
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    if (req.user.role !== 'admin' && inv.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    if (inv.status === 'paid') return res.status(400).json({ error: 'Cannot edit a paid invoice' });

    const {
      client_name, client_email, client_address, client_phone,
      issue_date, due_date, tax_rate, discount, notes, terms, footer, custom_fields,
      status, amount_paid, items = []
    } = req.body ?? {};

    const totals  = calcInvoiceTotals(items, tax_rate ?? inv.tax_rate, discount ?? inv.discount);
    const paid    = parseFloat(amount_paid ?? inv.amount_paid ?? 0);
    const balance = Math.round((totals.total - paid) * 100) / 100;

    await dbRun(`UPDATE invoices SET
      client_name=?,client_email=?,client_address=?,client_phone=?,
      subtotal=?,tax_rate=?,tax_amount=?,discount=?,total=?,amount_paid=?,balance_due=?,
      issue_date=?,due_date=?,notes=?,terms=?,footer=?,custom_fields=?,status=?,
      updated_at=strftime('%s','now') WHERE id=?`,
      [client_name??inv.client_name, client_email??inv.client_email,
       client_address??inv.client_address, client_phone??inv.client_phone,
       totals.subtotal, parseFloat(tax_rate??inv.tax_rate), totals.tax_amount,
       parseFloat(discount??inv.discount), totals.total, paid, balance,
       issue_date??inv.issue_date, due_date??inv.due_date,
       notes??inv.notes, terms??inv.terms, footer??inv.footer,
       custom_fields ? JSON.stringify(custom_fields) : inv.custom_fields,
       status??inv.status, req.params.id]);

    // Replace line items
    await dbRun('DELETE FROM invoice_items WHERE invoice_id=?', [req.params.id]);
    for (let idx = 0; idx < items.length; idx++) {
      const it = items[idx];
      const amt = Math.round(parseFloat(it.quantity||1) * parseFloat(it.unit_price||0) * 100) / 100;
      await dbRun('INSERT INTO invoice_items (invoice_id,sort_order,description,quantity,unit_price,amount,taxable) VALUES (?,?,?,?,?,?,?)',
        [req.params.id, idx, it.description||'', parseFloat(it.quantity||1), parseFloat(it.unit_price||0), amt, it.taxable!==false?1:0]);
    }
    await audit(req.user.userId, req.user.username, 'update_invoice', 'invoice', parseInt(req.params.id), req.ip, req.headers['user-agent'], null);
    res.json({ success: true });
  } catch (err) {
    log.error({ err: err.message }, 'update invoice failed');
    res.status(500).json({ error: 'Failed to update invoice' });
  }
});

// Delete invoice
app.delete('/api/invoices/:id', requireAuth, async (req, res) => {
  try {
    const inv = await dbGet('SELECT * FROM invoices WHERE id=?', [req.params.id]);
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    if (req.user.role !== 'admin' && inv.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    await dbRun('DELETE FROM invoices WHERE id=?', [req.params.id]);
    await audit(req.user.userId, req.user.username, 'delete_invoice', 'invoice', parseInt(req.params.id), req.ip, req.headers['user-agent'], inv.invoice_number);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete invoice' }); }
});

// Send invoice by email
app.post('/api/invoices/:id/send', requireAuth, async (req, res) => {
  try {
    const inv = await dbGet('SELECT * FROM invoices WHERE id=?', [req.params.id]);
    if (!inv) return res.status(404).json({ error: 'Invoice not found' });
    if (req.user.role !== 'admin' && inv.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });

    const items = await dbAll('SELECT * FROM invoice_items WHERE invoice_id=? ORDER BY sort_order,id', [req.params.id]);
    const cfg   = await dbGet('SELECT * FROM email_settings WHERE user_id=?', [req.user.userId]);
    if (!cfg?.smtp_host) return res.status(400).json({ error: 'Configure SMTP settings before sending invoices' });

    const { to, cc, bcc, subject, message } = req.body ?? {};
    const recipient = to || inv.client_email;
    if (!recipient) return res.status(400).json({ error: 'No recipient email address — provide "to" or set client_email on invoice' });

    const emailSubject = subject || `Invoice ${inv.invoice_number} from ${cfg.business_name || 'IRS Calculator'}`;

    // Build HTML invoice
    const htmlInvoice = buildInvoiceHtml(inv, items, cfg, message);

    const transporter = nodemailer.createTransport({
      host: cfg.smtp_host, port: cfg.smtp_port || 587,
      secure: !!cfg.smtp_secure,
      auth: { user: cfg.smtp_user, pass: cfg.smtp_pass },
      tls: { rejectUnauthorized: false }
    });

    const from = cfg.smtp_from_email
      ? `"${cfg.smtp_from_name || cfg.business_name || 'IRS Calculator'}" <${cfg.smtp_from_email}>`
      : cfg.smtp_user;

    const mailOptions = { from, to: recipient, subject: emailSubject, html: htmlInvoice };
    if (cc)  mailOptions.cc  = cc;
    if (bcc) mailOptions.bcc = bcc;

    await transporter.sendMail(mailOptions);

    const allRecipients = [recipient, cc, bcc].filter(Boolean).join(', ');
    // Update invoice status and send count
    await dbRun(`UPDATE invoices SET status=CASE WHEN status='draft' THEN 'sent' ELSE status END,
      last_sent_at=strftime('%s','now'), sent_count=sent_count+1, updated_at=strftime('%s','now') WHERE id=?`,
      [req.params.id]);
    await dbRun('INSERT INTO email_log (user_id,recipient,subject,invoice_id,status) VALUES (?,?,?,?,?)',
      [req.user.userId, allRecipients, emailSubject, req.params.id, 'sent']);
    await audit(req.user.userId, req.user.username, 'send_invoice', 'invoice', parseInt(req.params.id), req.ip, req.headers['user-agent'], `To: ${allRecipients}`);
    res.json({ success: true });
  } catch (err) {
    log.error({ err: err.message }, 'send invoice failed');
    await dbRun('INSERT INTO email_log (user_id,recipient,subject,invoice_id,status,error_msg) VALUES (?,?,?,?,?,?)',
      [req.user.userId, req.body?.to||'', `Invoice ${req.params.id}`, req.params.id, 'failed', err.message]).catch(()=>{});
    res.status(500).json({ error: `Failed to send invoice: ${err.message}` });
  }
});

// ── Invoice HTML builder
function buildInvoiceHtml(inv, items, cfg, customMessage) {
  const fmt = (n) => `$${(parseFloat(n)||0).toLocaleString('en-US',{minimumFractionDigits:2})}`;
  const logo = cfg?.business_logo_url
    ? `<img src="${cfg.business_logo_url}" style="max-height:60px;max-width:200px;margin-bottom:8px">`
    : '';
  const bizName    = cfg?.business_name    || 'IRS Financial Calculator';
  const bizAddress = cfg?.business_address ? cfg.business_address.replace(/\n/g,'<br>') : '';
  const bizPhone   = cfg?.business_phone   || '';
  const statusColors = { draft:'#888', sent:'#2563eb', paid:'#16a34a', overdue:'#dc2626', cancelled:'#6b7280' };
  const statusColor = statusColors[inv.status] || '#888';

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<style>
  body{font-family:Arial,sans-serif;color:#333;margin:0;padding:0;background:#f5f5f5}
  .wrap{max-width:700px;margin:30px auto;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.1)}
  .header{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;padding:32px 40px;display:flex;justify-content:space-between;align-items:flex-start}
  .header .biz{font-size:.9rem;opacity:.85}
  .header h1{font-size:2rem;margin:0;color:#a8a7ff}
  .meta{padding:28px 40px;display:grid;grid-template-columns:1fr 1fr;gap:24px;border-bottom:1px solid #eee}
  .meta-box h4{font-size:.72rem;text-transform:uppercase;letter-spacing:.5px;color:#888;margin-bottom:6px}
  .meta-box p{margin:2px 0;font-size:.9rem}
  .status-badge{display:inline-block;padding:4px 12px;border-radius:100px;font-size:.78rem;font-weight:700;color:#fff;background:${statusColor}}
  .items{padding:0 40px}
  table{width:100%;border-collapse:collapse;margin:20px 0}
  th{background:#f8f9fa;padding:10px 12px;text-align:left;font-size:.78rem;text-transform:uppercase;letter-spacing:.4px;color:#555}
  td{padding:10px 12px;border-bottom:1px solid #f0f0f0;font-size:.9rem}
  .text-right{text-align:right}
  .totals{padding:16px 40px;background:#f8f9fa}
  .total-row{display:flex;justify-content:space-between;padding:5px 0;font-size:.9rem}
  .total-row.grand{font-size:1.1rem;font-weight:700;border-top:2px solid #e0e0e0;margin-top:8px;padding-top:8px}
  .total-row.balance{color:${inv.balance_due > 0 ? '#dc2626' : '#16a34a'};font-weight:700}
  .footer-section{padding:24px 40px;border-top:1px solid #eee;font-size:.82rem;color:#666}
  .msg-box{padding:16px 40px;background:#fffbe6;border-left:4px solid #f59e0b;font-size:.88rem;color:#555}
</style>
</head>
<body><div class="wrap">
  <div class="header">
    <div>
      ${logo}
      <div style="font-size:1.1rem;font-weight:700">${bizName}</div>
      <div class="biz">${bizAddress}</div>
      ${bizPhone ? `<div class="biz">${bizPhone}</div>` : ''}
    </div>
    <div style="text-align:right">
      <h1>INVOICE</h1>
      <div style="font-size:1rem;opacity:.9">${inv.invoice_number}</div>
      <div style="margin-top:8px"><span class="status-badge">${inv.status.toUpperCase()}</span></div>
    </div>
  </div>

  ${customMessage ? `<div class="msg-box">${customMessage}</div>` : ''}

  <div class="meta">
    <div class="meta-box">
      <h4>Bill To</h4>
      <p><strong>${inv.client_name}</strong></p>
      ${inv.client_email ? `<p>${inv.client_email}</p>` : ''}
      ${inv.client_phone ? `<p>${inv.client_phone}</p>` : ''}
      ${inv.client_address ? `<p>${inv.client_address.replace(/\n/g,'<br>')}</p>` : ''}
    </div>
    <div class="meta-box">
      <h4>Invoice Details</h4>
      <p>Invoice #: <strong>${inv.invoice_number}</strong></p>
      <p>Issue Date: ${inv.issue_date||'—'}</p>
      ${inv.due_date ? `<p>Due Date: <strong>${inv.due_date}</strong></p>` : ''}
    </div>
  </div>

  <div class="items">
    <table>
      <thead><tr><th>Description</th><th class="text-right">Qty</th><th class="text-right">Unit Price</th><th class="text-right">Amount</th></tr></thead>
      <tbody>
        ${items.map(it => `
          <tr>
            <td>${it.description}</td>
            <td class="text-right">${it.quantity}</td>
            <td class="text-right">${fmt(it.unit_price)}</td>
            <td class="text-right">${fmt(it.amount)}</td>
          </tr>`).join('')}
      </tbody>
    </table>
  </div>

  <div class="totals">
    <div class="total-row"><span>Subtotal</span><span>${fmt(inv.subtotal)}</span></div>
    ${inv.tax_rate > 0 ? `<div class="total-row"><span>Tax (${inv.tax_rate}%)</span><span>${fmt(inv.tax_amount)}</span></div>` : ''}
    ${inv.discount > 0 ? `<div class="total-row"><span>Discount</span><span>-${fmt(inv.discount)}</span></div>` : ''}
    <div class="total-row grand"><span>Total</span><span>${fmt(inv.total)}</span></div>
    ${inv.amount_paid > 0 ? `<div class="total-row"><span>Amount Paid</span><span style="color:#16a34a">-${fmt(inv.amount_paid)}</span></div>` : ''}
    <div class="total-row balance"><span>Balance Due</span><span>${fmt(inv.balance_due)}</span></div>
  </div>

  ${inv.notes || inv.terms || inv.footer ? `
  <div class="footer-section">
    ${inv.notes  ? `<p><strong>Notes:</strong> ${inv.notes}</p>` : ''}
    ${inv.terms  ? `<p><strong>Terms:</strong> ${inv.terms}</p>` : ''}
    ${inv.footer ? `<p>${inv.footer}</p>` : ''}
  </div>` : ''}

  <div style="padding:16px 40px;text-align:center;font-size:.75rem;color:#bbb;border-top:1px solid #f0f0f0">
    Generated by IRS Financial Calculator · ${new Date().toLocaleDateString()}
  </div>
</div></body></html>`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTACTS
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/contacts', requireAuth, async (req, res) => {
  try {
    const isAdmin = req.user.role === 'admin';
    const rows = await dbAll(
      isAdmin
        ? `SELECT c.*, u.username AS owner_username FROM contacts c JOIN users u ON u.id=c.owner_id ORDER BY c.full_name`
        : `SELECT * FROM contacts WHERE owner_id=? ORDER BY full_name`,
      isAdmin ? [] : [req.user.userId]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed to fetch contacts' }); }
});

app.post('/api/contacts', requireAuth, async (req, res) => {
  const { full_name, email, phone, address, company, notes } = req.body ?? {};
  if (!full_name?.trim()) return res.status(400).json({ error: 'full_name is required' });
  try {
    const r = await dbRun(
      `INSERT INTO contacts (owner_id,full_name,email,phone,address,company,notes) VALUES (?,?,?,?,?,?,?)`,
      [req.user.userId, full_name.trim(), email||null, phone||null, address||null, company||null, notes||null]
    );
    await audit(req.user.userId, req.user.username, 'create_contact', 'contact', r.lastID, req.ip, req.headers['user-agent'], full_name.trim());
    res.status(201).json({ success: true, contactId: r.lastID });
  } catch (err) {
    log.error({ err: err.message }, 'create contact failed');
    res.status(500).json({ error: 'Failed to create contact' });
  }
});

app.put('/api/contacts/:id', requireAuth, async (req, res) => {
  try {
    const c = await dbGet('SELECT * FROM contacts WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Contact not found' });
    if (req.user.role !== 'admin' && c.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    const { full_name, email, phone, address, company, notes } = req.body ?? {};
    await dbRun(
      `UPDATE contacts SET full_name=?,email=?,phone=?,address=?,company=?,notes=?,updated_at=strftime('%s','now') WHERE id=?`,
      [full_name??c.full_name, email??c.email, phone??c.phone, address??c.address, company??c.company, notes??c.notes, req.params.id]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update contact' }); }
});

app.delete('/api/contacts/:id', requireAuth, async (req, res) => {
  try {
    const c = await dbGet('SELECT * FROM contacts WHERE id=?', [req.params.id]);
    if (!c) return res.status(404).json({ error: 'Contact not found' });
    if (req.user.role !== 'admin' && c.owner_id !== req.user.userId) return res.status(403).json({ error: 'Access denied' });
    await dbRun('DELETE FROM contacts WHERE id=?', [req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete contact' }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// BACKUP & RESTORE  (admin only)
// ═══════════════════════════════════════════════════════════════════════════════
const zlib = require('zlib');

// ── Full JSON backup — all tables + settings exported as compressed JSON
app.get('/api/admin/backup', requireAuth, requireAdmin, async (req, res) => {
  try {
    const tables = await dbAll(
      `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`
    );

    const backup = {
      version: '1.0',
      created_at: new Date().toISOString(),
      app: 'irs-financial-calculator',
      tables: {}
    };

    for (const { name } of tables) {
      // Never export raw passwords or TOTP secrets
      let rows;
      if (name === 'users') {
        rows = await dbAll(`SELECT id,username,email,full_name,role,is_active,is_2fa_enabled,
          created_at,created_by,last_login_at,last_login_ip,login_count,failed_logins,locked_until
          FROM users`);
      } else if (name === 'email_settings') {
        rows = await dbAll(`SELECT id,user_id,smtp_host,smtp_port,smtp_secure,smtp_user,
          smtp_from_name,smtp_from_email,imap_host,imap_port,imap_secure,imap_user,
          business_name,business_address,business_phone,business_website,business_logo_url,
          business_email,business_footer,updated_at FROM email_settings`);
      } else {
        rows = await dbAll(`SELECT * FROM ${name}`);
      }
      backup.tables[name] = rows;
    }

    const json    = JSON.stringify(backup, null, 2);
    const filename = `irs-backup-${new Date().toISOString().slice(0,10)}.json`;

    await audit(req.user.userId, req.user.username, 'backup_export', 'system', null, req.ip, req.headers['user-agent'],
      `Tables: ${tables.map(t=>t.name).join(', ')}`);

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(json);
  } catch (err) {
    log.error({ err: err.message }, 'backup failed');
    res.status(500).json({ error: 'Backup failed: ' + err.message });
  }
});

// ── SQLite raw database file backup (binary .db download)
app.get('/api/admin/backup/db', requireAuth, requireAdmin, async (req, res) => {
  try {
    const fs = require('fs');
    const dbPath = process.env.DB_PATH || '/data/users.db';

    // Use SQLite VACUUM INTO to get a clean consistent snapshot
    const tmpPath = dbPath + '.backup.tmp';
    await dbRun(`VACUUM INTO '${tmpPath}'`);

    const filename = `irs-database-${new Date().toISOString().slice(0,10)}.db`;
    await audit(req.user.userId, req.user.username, 'backup_db_export', 'system', null, req.ip, req.headers['user-agent'], 'SQLite raw DB');

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    const stream = fs.createReadStream(tmpPath);
    stream.pipe(res);
    stream.on('end', () => fs.unlink(tmpPath, () => {}));
    stream.on('error', (e) => { fs.unlink(tmpPath, () => {}); res.status(500).end(); });
  } catch (err) {
    log.error({ err: err.message }, 'db backup failed');
    res.status(500).json({ error: 'DB backup failed: ' + err.message });
  }
});

// ── Restore raw .db file — multipart upload, replaces database file
// Uses express raw body parsing on this one route only
app.post('/api/admin/restore/db', requireAuth, requireAdmin, (req, res) => {
  const fs     = require('fs');
  const path   = require('path');
  const dbPath = process.env.DB_PATH || '/data/users.db';
  const tmpPath = dbPath + '.restore.tmp';

  // Safety: only accept application/octet-stream or multipart
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/octet-stream') && !contentType.includes('multipart/form-data')) {
    return res.status(400).json({ error: 'Send the .db file as application/octet-stream body' });
  }

  const writeStream = fs.createWriteStream(tmpPath);
  let size = 0;
  const MAX_SIZE = 500 * 1024 * 1024; // 500 MB max

  req.on('data', chunk => {
    size += chunk.length;
    if (size > MAX_SIZE) {
      writeStream.destroy();
      fs.unlink(tmpPath, () => {});
      return res.status(413).json({ error: 'File too large (max 500 MB)' });
    }
    writeStream.write(chunk);
  });

  req.on('end', async () => {
    writeStream.end();
    writeStream.on('finish', async () => {
      try {
        // Validate it is actually a SQLite file (magic bytes: 53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00)
        const header = Buffer.alloc(16);
        const fd = fs.openSync(tmpPath, 'r');
        fs.readSync(fd, header, 0, 16, 0);
        fs.closeSync(fd);
        const magic = 'SQLite format 3\x00';
        if (header.toString('ascii') !== magic) {
          fs.unlink(tmpPath, () => {});
          return res.status(400).json({ error: 'File is not a valid SQLite database' });
        }

        // ── Backup current DB before overwriting
        const backupPath = dbPath + '.pre-restore-' + Date.now() + '.bak';
        try { fs.copyFileSync(dbPath, backupPath); } catch(e) { /* best-effort */ }

        // ── Safe DB file restore strategy:
        // 1. WAL checkpoint to flush any pending writes
        // 2. Copy uploaded file over existing DB while DB is still open (SQLite handles this safely)
        // 3. Send SIGTERM to self — Docker restart policy will bring it back immediately
        //    with the new DB file. This is the cleanest way to hot-swap SQLite in Node.js.

        // Step 1: Flush WAL
        await new Promise(resolve => db.run('PRAGMA wal_checkpoint(TRUNCATE)', resolve));

        // Step 2: Atomic rename — both files are in /data so same filesystem.
        // rename() is atomic and works even if dbPath is owned by a different user
        // as long as we own the DIRECTORY (which appuser does for /data).
        // This avoids the EPERM error from copyFileSync trying to overwrite a root-owned file.
        try {
          fs.renameSync(tmpPath, dbPath);
        } catch(renameErr) {
          // Fallback: if rename fails (cross-device), try copy then unlink
          fs.copyFileSync(tmpPath, dbPath);
          fs.unlinkSync(tmpPath);
        }
        fs.chmodSync(dbPath, 0o666);

        log.info({ by: req.user.username, size: size }, 'DB restore from file complete — restarting process');

        // Step 3: Send response BEFORE restarting
        res.json({
          success: true,
          message: 'Database file replaced. Server is restarting to load the restored database (takes ~10 seconds).',
          fileSize: size,
          preRestoreBackup: path.basename(backupPath),
          restarting: true
        });

        // Step 4: Graceful restart — Docker restart policy brings us back with new DB
        setTimeout(() => {
          log.info('Initiating process restart for DB file restore');
          process.exit(0);
        }, 500);
      } catch (err) {
        fs.unlink(tmpPath, () => {});
        log.error({ err: err.message }, 'DB file restore failed');
        res.status(500).json({ error: 'DB restore failed: ' + err.message });
      }
    });
  });

  req.on('error', err => {
    writeStream.destroy();
    fs.unlink(tmpPath, () => {});
    res.status(500).json({ error: 'Upload error: ' + err.message });
  });
});

// ── Restore from JSON backup
app.post('/api/admin/restore', requireAuth, requireAdmin, async (req, res) => {
  try {
    const backup = req.body;
    if (!backup?.version || !backup?.tables || backup?.app !== 'irs-financial-calculator') {
      return res.status(400).json({ error: 'Invalid backup file — must be an IRS Calculator backup JSON' });
    }

    const RESTORABLE = [
      'client_cases', 'case_notes', 'case_files',
      'contacts', 'invoices', 'invoice_items',
      'email_settings', 'email_log'
    ];
    // Users table is intentionally NOT auto-restored to prevent privilege escalation
    // It can be restored manually via the DB viewer if needed

    const results = {};
    for (const table of RESTORABLE) {
      const rows = backup.tables[table];
      if (!rows || !Array.isArray(rows)) { results[table] = 'skipped (not in backup)'; continue; }
      if (rows.length === 0) { results[table] = 'empty'; continue; }

      const cols = Object.keys(rows[0]);
      let inserted = 0, skipped = 0;
      for (const row of rows) {
        const vals = cols.map(c => row[c]);
        const placeholders = cols.map(() => '?').join(',');
        await dbRun(
          `INSERT OR IGNORE INTO ${table} (${cols.join(',')}) VALUES (${placeholders})`,
          vals
        ).then(() => inserted++).catch(() => skipped++);
      }
      results[table] = `${inserted} inserted, ${skipped} skipped (duplicates)`;
    }

    await audit(req.user.userId, req.user.username, 'restore_backup', 'system', null, req.ip, req.headers['user-agent'],
      `From backup: ${backup.created_at}`);

    log.info({ by: req.user.username }, 'backup restored');
    res.json({ success: true, results, backup_date: backup.created_at });
  } catch (err) {
    log.error({ err: err.message }, 'restore failed');
    res.status(500).json({ error: 'Restore failed: ' + err.message });
  }
});

// ── Backup status — last backup time from audit log
app.get('/api/admin/backup/status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const lastBackup = await dbGet(
      `SELECT created_at, username FROM audit_log
       WHERE action IN ('backup_export','backup_db_export')
       ORDER BY created_at DESC LIMIT 1`
    );
    const lastRestore = await dbGet(
      `SELECT created_at, username FROM audit_log
       WHERE action = 'restore_backup'
       ORDER BY created_at DESC LIMIT 1`
    );
    const dbSize = await new Promise((resolve) => {
      require('fs').stat(process.env.DB_PATH || '/data/users.db', (err, stat) => {
        resolve(err ? 0 : stat.size);
      });
    });
    const tableCounts = {};
    const tables = await dbAll(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`);
    for (const { name } of tables) {
      const r = await dbGet(`SELECT COUNT(*) AS n FROM ${name}`);
      tableCounts[name] = r.n;
    }
    res.json({ lastBackup, lastRestore, dbSizeBytes: dbSize, tableCounts });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get backup status' });
  }
});

// ─── ERROR HANDLERS ───────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  log.error({ err: err.message }, 'unhandled error');
  res.status(500).json({ error: IS_PROD ? 'Internal server error' : err.message });
});

// ─── STARTUP ──────────────────────────────────────────────────────────────────
async function start() {
  await initDb();
  // Clean up expired sessions daily
  setInterval(async () => {
    const r = await dbRun(`DELETE FROM sessions WHERE expires_at < strftime('%s','now') OR revoked=1`).catch(()=>({}));
    if (r.changes) log.info({ removed: r.changes }, 'expired sessions cleaned');
  }, 6 * 60 * 60 * 1000);

  const server = app.listen(PORT, () => log.info({ port: PORT, env: NODE_ENV }, 'Server started'));

  const shutdown = (sig) => {
    log.info({ sig }, 'shutting down');
    server.close(() => db.close(() => { log.info('clean shutdown'); process.exit(0); }));
    setTimeout(() => process.exit(1), 10_000);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('uncaughtException',  (e) => log.error({ err: e.message }, 'uncaught'));
  process.on('unhandledRejection', (e) => log.warn({ err: String(e) }, 'unhandled rejection'));
}

start().catch((e) => { console.error('Startup failed:', e.message); process.exit(1); });
