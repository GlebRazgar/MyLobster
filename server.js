const express = require('express');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');

const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-change-me';
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || '';
const STRIPE_PUBLISHABLE_KEY = process.env.STRIPE_PUBLISHABLE_KEY || '';
const stripe = STRIPE_SECRET_KEY ? new Stripe(STRIPE_SECRET_KEY) : null;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify({ users: [] }, null, 2));

const TIERS = {
  lite: { name: 'Lite', amount: 1900, currency: 'usd' },
  pro: { name: 'Pro', amount: 3900, currency: 'usd' },
  max: { name: 'Max', amount: 7900, currency: 'usd' }
};

function readUsers() {
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')).users || [];
}
function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify({ users }, null, 2));
}
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
function getAuthUser(req) {
  const token = req.cookies.easyclaw_session;
  if (!token) return null;
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = readUsers().find(u => u.id === payload.sub);
    return user || null;
  } catch {
    return null;
  }
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/api/config', (req, res) => {
  res.json({ stripePublishableKey: STRIPE_PUBLISHABLE_KEY, stripeEnabled: Boolean(stripe) });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || '');
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 chars' });

    const users = readUsers();
    if (users.some(u => u.email === email)) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);
    const user = {
      id: Date.now().toString(36),
      email,
      passwordHash: hash,
      createdAt: new Date().toISOString(),
      subscriptionStatus: 'none',
      tier: null,
      stripeCustomerId: null
    };
    users.push(user);
    writeUsers(users);

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
    const user = readUsers().find(u => u.email === email);
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password', code: 'INVALID_PASSWORD' });

    setSession(res, user);
    return res.json({ ok: true, user: { id: user.id, email: user.email } });
  } catch {
    return res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const newPassword = String(req.body.newPassword || '');
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 chars' });

    const users = readUsers();
    const i = users.findIndex(u => u.email === email);
    if (i < 0) return res.status(404).json({ error: 'No account found for this email' });

    users[i].passwordHash = await bcrypt.hash(newPassword, 10);
    users[i].passwordResetAt = new Date().toISOString();
    writeUsers(users);

    return res.json({ ok: true });
  } catch {
    return res.status(500).json({ error: 'Password reset failed' });
  }
});

app.get('/api/auth/me', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ authenticated: false });
  return res.json({
    authenticated: true,
    user: {
      id: user.id,
      email: user.email,
      tier: user.tier,
      subscriptionStatus: user.subscriptionStatus,
      paid: user.subscriptionStatus === 'active'
    }
  });
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('easyclaw_session');
  res.json({ ok: true });
});

app.post('/api/payments/create-checkout-session', async (req, res) => {
  try {
    const user = getAuthUser(req);
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    if (!stripe) return res.status(400).json({ error: 'Stripe not configured on server' });

    const tier = String(req.body.tier || '').toLowerCase();
    const plan = TIERS[tier];
    if (!plan) return res.status(400).json({ error: 'Invalid tier' });

    let customerId = user.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({ email: user.email, metadata: { userId: user.id } });
      customerId = customer.id;
      const users = readUsers();
      const i = users.findIndex(u => u.id === user.id);
      if (i >= 0) {
        users[i].stripeCustomerId = customerId;
        writeUsers(users);
      }
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
    const user = getAuthUser(req);
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    if (!stripe) return res.status(400).json({ error: 'Stripe not configured on server' });

    const sessionId = String(req.body.sessionId || '');
    if (!sessionId) return res.status(400).json({ error: 'sessionId required' });

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    if (session.payment_status !== 'paid' && session.status !== 'complete') {
      return res.status(400).json({ error: 'Payment not complete' });
    }

    const tier = (session.metadata && session.metadata.tier) || null;
    const users = readUsers();
    const i = users.findIndex(u => u.id === user.id);
    if (i >= 0) {
      users[i].subscriptionStatus = 'active';
      users[i].tier = tier;
      writeUsers(users);
    }

    return res.json({ ok: true, tier });
  } catch (e) {
    return res.status(500).json({ error: e.message || 'Could not confirm payment' });
  }
});

app.use(express.static(path.join(__dirname, 'landing-clone')));

app.listen(PORT, () => {
  console.log(`EasyClaw server running on http://0.0.0.0:${PORT}`);
});
