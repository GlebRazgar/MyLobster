const express = require('express');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-change-me';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PUBLISHABLE_KEY = process.env.STRIPE_PUBLISHABLE_KEY || '';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;
const DATABASE_URL = process.env.DATABASE_URL || '';

const APP_BASE_URL = process.env.APP_BASE_URL || '';
const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER || 'no-reply@yourclaw.space';

const mailer = SMTP_HOST && SMTP_USER && SMTP_PASS
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS }
    })
  : null;

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is required.');
}

const db = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

const TIERS = {
  lite: { name: 'Lite', amount: 1900, currency: 'usd' },
  pro: { name: 'Pro', amount: 3900, currency: 'usd' },
  max: { name: 'Max', amount: 7900, currency: 'usd' }
};

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function signSession(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
}

function setSession(res, user) {
  const token = signSession(user);
  res.cookie('easyclaw_session', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60 * 24 * 30
  });
}

async function getAuthUser(req) {
  const token = req.cookies.easyclaw_session;
  if (!token) return null;

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const r = await db.query('SELECT * FROM users WHERE id = $1 LIMIT 1', [payload.sub]);
    return r.rows[0] || null;
  } catch {
    return null;
  }
}

function getBaseUrl(req) {
  if (APP_BASE_URL) return APP_BASE_URL.replace(/\/$/, '');
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${proto}://${host}`;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

async function sendResetEmail(to, resetUrl) {
  if (!mailer) {
    console.log(`[password-reset] Mailer not configured. Link for ${to}: ${resetUrl}`);
    return;
  }

  const info = await mailer.sendMail({
    from: SMTP_FROM,
    to,
    subject: 'Reset your YourClaw password',
    text: `Reset your password using this link (valid for 30 minutes):\n${resetUrl}`,
    html: `<p>Reset your password using this link (valid for 30 minutes):</p><p><a href="${resetUrl}">${resetUrl}</a></p>`
  });

  console.log(`[password-reset] Email sent to ${to}; messageId=${info && info.messageId ? info.messageId : 'unknown'}`);
}

async function initDb() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_login_at TIMESTAMPTZ,
      status TEXT NOT NULL DEFAULT 'active',
      stripe_customer_id TEXT,
      subscription_status TEXT NOT NULL DEFAULT 'none',
      tier TEXT,
      password_reset_at TIMESTAMPTZ
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS subscriptions (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      plan TEXT,
      status TEXT NOT NULL DEFAULT 'none',
      stripe_customer_id TEXT,
      stripe_subscription_id TEXT,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS billing_events (
      id BIGSERIAL PRIMARY KEY,
      stripe_event_id TEXT UNIQUE,
      event_type TEXT,
      payload_json JSONB,
      processed_at TIMESTAMPTZ,
      status TEXT,
      error TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

async function migrateLegacyUsersFromJson() {
  if (!fs.existsSync(USERS_FILE)) return;
  let legacy = [];
  try {
    const parsed = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    legacy = Array.isArray(parsed.users) ? parsed.users : [];
  } catch {
    legacy = [];
  }

  for (const u of legacy) {
    if (!u?.id || !u?.email || !u?.passwordHash) continue;

    await db.query(
      `INSERT INTO users (id, email, password_hash, created_at, stripe_customer_id, subscription_status, tier, password_reset_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (id) DO NOTHING`,
      [
        u.id,
        normalizeEmail(u.email),
        u.passwordHash,
        u.createdAt || new Date().toISOString(),
        u.stripeCustomerId || null,
        u.subscriptionStatus || 'none',
        u.tier || null,
        u.passwordResetAt || null
      ]
    );

    await db.query(
      `INSERT INTO subscriptions (user_id, plan, status, stripe_customer_id, stripe_subscription_id, updated_at)
       VALUES ($1, $2, $3, $4, $5, now())
       ON CONFLICT (user_id)
       DO UPDATE SET plan = EXCLUDED.plan, status = EXCLUDED.status, stripe_customer_id = EXCLUDED.stripe_customer_id, updated_at = now()`,
      [u.id, u.tier || null, u.subscriptionStatus || 'none', u.stripeCustomerId || null, null]
    );
  }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

if (mailer) {
  mailer.verify()
    .then(() => console.log('[smtp] Transport verified successfully'))
    .catch((e) => console.error('[smtp] Transport verify failed:', e && e.message ? e.message : e));
} else {
  console.warn('[smtp] Mailer is not configured (SMTP_* env vars missing)');
}

app.get('/api/config', (_req, res) => {
  res.json({ stripePublishableKey: STRIPE_PUBLISHABLE_KEY, stripeEnabled: Boolean(stripe) });
});

app.get('/api/debug/smtp', async (_req, res) => {
  try {
    if (!mailer) return res.status(400).json({ ok: false, error: 'Mailer not configured' });
    await mailer.verify();
    return res.json({ ok: true, host: SMTP_HOST, port: SMTP_PORT, user: SMTP_USER, from: SMTP_FROM });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e && e.message ? e.message : 'SMTP verify failed' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 chars' });

    const existing = await db.query('SELECT id FROM users WHERE email = $1 LIMIT 1', [email]);
    if (existing.rowCount > 0) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: Date.now().toString(36),
      email
    };

    await db.query(
      `INSERT INTO users (id, email, password_hash, subscription_status, status)
       VALUES ($1, $2, $3, 'none', 'active')`,
      [user.id, user.email, hash]
    );

    await db.query(
      `INSERT INTO subscriptions (user_id, plan, status)
       VALUES ($1, NULL, 'none')
       ON CONFLICT (user_id) DO NOTHING`,
      [user.id]
    );

    setSession(res, user);
    return res.json({ ok: true, user: { id: user.id, email: user.email } });
  } catch {
    return res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');

    const r = await db.query('SELECT * FROM users WHERE email = $1 LIMIT 1', [email]);
    const user = r.rows[0];
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password', code: 'INVALID_PASSWORD' });

    await db.query('UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1', [user.id]);
    setSession(res, user);

    return res.json({
      ok: true,
      user: {
        id: user.id,
        email: user.email,
        tier: user.tier,
        subscriptionStatus: user.subscription_status,
        paid: user.subscription_status === 'active'
      }
    });
  } catch {
    return res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/request-password-reset', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });

    const r = await db.query('SELECT id, email FROM users WHERE email = $1 LIMIT 1', [email]);
    const user = r.rows[0];

    if (!user) return res.json({ ok: true });

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000).toISOString();

    await db.query(
      `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, $3)`,
      [user.id, tokenHash, expiresAt]
    );

    const resetUrl = `${getBaseUrl(req)}/reset-password.html?token=${encodeURIComponent(token)}&email=${encodeURIComponent(email)}`;
    await sendResetEmail(email, resetUrl);

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: 'Could not send reset email' });
  }
});

app.post('/api/auth/perform-password-reset', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const token = String(req.body.token || '');
    const newPassword = String(req.body.newPassword || '');

    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
    if (!token) return res.status(400).json({ error: 'Reset token required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 chars' });

    const tokenHash = hashToken(token);

    const r = await db.query(
      `SELECT prt.id AS token_id, u.id AS user_id
       FROM password_reset_tokens prt
       JOIN users u ON u.id = prt.user_id
       WHERE u.email = $1
         AND prt.token_hash = $2
         AND prt.used_at IS NULL
         AND prt.expires_at > now()
       ORDER BY prt.created_at DESC
       LIMIT 1`,
      [email, tokenHash]
    );

    const row = r.rows[0];
    if (!row) return res.status(400).json({ error: 'Invalid or expired reset link' });

    const newHash = await bcrypt.hash(newPassword, 10);

    await db.query('UPDATE users SET password_hash = $1, password_reset_at = now(), updated_at = now() WHERE id = $2', [newHash, row.user_id]);
    await db.query('UPDATE password_reset_tokens SET used_at = now() WHERE id = $1', [row.token_id]);

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: 'Password reset failed' });
  }
});

app.get('/api/auth/me', async (req, res) => {
  const user = await getAuthUser(req);
  if (!user) return res.status(401).json({ authenticated: false });

  return res.json({
    authenticated: true,
    user: {
      id: user.id,
      email: user.email,
      tier: user.tier,
      subscriptionStatus: user.subscription_status,
      paid: user.subscription_status === 'active'
    }
  });
});

app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('easyclaw_session');
  res.json({ ok: true });
});

app.post('/api/payments/create-checkout-session', async (req, res) => {
  try {
    const user = await getAuthUser(req);
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    if (!stripe) return res.status(400).json({ error: 'Stripe not configured on server' });

    const tier = String(req.body.tier || '').toLowerCase();
    const plan = TIERS[tier];
    if (!plan) return res.status(400).json({ error: 'Invalid tier' });

    let customerId = user.stripe_customer_id;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email, metadata: { userId: user.id } });
      customerId = customer.id;

      await db.query('UPDATE users SET stripe_customer_id = $1, updated_at = now() WHERE id = $2', [customerId, user.id]);
      await db.query(
        `INSERT INTO subscriptions (user_id, plan, status, stripe_customer_id, updated_at)
         VALUES ($1, $2, $3, $4, now())
         ON CONFLICT (user_id)
         DO UPDATE SET stripe_customer_id = EXCLUDED.stripe_customer_id, updated_at = now()`,
        [user.id, user.tier || null, user.subscription_status || 'none', customerId]
      );
    }

    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
    const host = req.headers['x-forwarded-host'] || req.get('host');
    const returnUrl = `${proto}://${host}/payment-success.html?session_id={CHECKOUT_SESSION_ID}`;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      ui_mode: 'embedded',
      customer: customerId,
      line_items: [
        {
          price_data: {
            currency: plan.currency,
            recurring: { interval: 'month' },
            unit_amount: plan.amount,
            product_data: { name: `EasyClaw ${plan.name}` }
          },
          quantity: 1
        }
      ],
      metadata: { userId: user.id, tier },
      return_url: returnUrl
    });

    return res.json({ clientSecret: session.client_secret });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Checkout session failed' });
  }
});

app.post('/api/payments/confirm-session', async (req, res) => {
  try {
    const user = await getAuthUser(req);
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    if (!stripe) return res.status(400).json({ error: 'Stripe not configured on server' });

    const sessionId = String(req.body.sessionId || '');
    if (!sessionId) return res.status(400).json({ error: 'sessionId required' });

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== 'paid' && session.status !== 'complete') {
      return res.status(400).json({ error: 'Payment not complete' });
    }

    const tier = (session.metadata && session.metadata.tier) || null;
    const stripeSubId = session.subscription || null;

    await db.query(
      'UPDATE users SET subscription_status = $1, tier = $2, updated_at = now() WHERE id = $3',
      ['active', tier, user.id]
    );

    await db.query(
      `INSERT INTO subscriptions (user_id, plan, status, stripe_customer_id, stripe_subscription_id, updated_at)
       VALUES ($1, $2, 'active', $3, $4, now())
       ON CONFLICT (user_id)
       DO UPDATE SET plan = EXCLUDED.plan, status = EXCLUDED.status, stripe_customer_id = EXCLUDED.stripe_customer_id, stripe_subscription_id = EXCLUDED.stripe_subscription_id, updated_at = now()`,
      [user.id, tier, session.customer || user.stripe_customer_id || null, stripeSubId]
    );

    return res.json({ ok: true, tier });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Could not confirm payment' });
  }
});

async function requirePaidUser(req, res) {
  const user = await getAuthUser(req);
  if (!user) {
    res.redirect('/index.html');
    return null;
  }
  if (user.subscription_status !== 'active') {
    res.redirect('/index.html');
    return null;
  }
  return user;
}

app.get(['/dashboard', '/dashboard.html'], async (req, res) => {
  const user = await requirePaidUser(req, res);
  if (!user) return;
  res.sendFile(path.join(__dirname, 'landing-clone', 'dashboard.html'));
});

app.use(express.static(path.join(__dirname, 'landing-clone')));

async function start() {
  await initDb();
  await migrateLegacyUsersFromJson();

  app.listen(PORT, () => {
    console.log(`EasyClaw server running on http://0.0.0.0:${PORT}`);
  });
}

start().catch((e) => {
  console.error('Failed to start server:', e);
  process.exit(1);
});
