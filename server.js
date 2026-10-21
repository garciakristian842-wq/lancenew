const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === 'production';
const OTP_TTL_MS = 5 * 60 * 1000, RESEND_MS = 30 * 1000, MAX_TRIES = 5, SESSION_DAYS = 30;
const DATABASE_URL = process.env.DATABASE_URL;
// EmailJS IDs and the public key are not secrets. Render env vars override these if set.
const EMAILJS_SERVICE_ID  = process.env.EMAILJS_SERVICE_ID  || 'service_7ceyq8r';
const EMAILJS_TEMPLATE_ID = process.env.EMAILJS_TEMPLATE_ID || 'template_rgbn19r';
const EMAILJS_PUBLIC_KEY  = process.env.EMAILJS_PUBLIC_KEY  || 'deyj_x1nuMJdotNPe';
// The private key is a secret: set it ONLY as a Render environment variable, never in this file.
const EMAILJS_PRIVATE_KEY = process.env.EMAILJS_PRIVATE_KEY;

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL && !/localhost|127\.0\.0\.1/.test(DATABASE_URL) ? { rejectUnauthorized: false } : false
});
const q = (text, params) => pool.query(text, params);
const rand = n => crypto.randomBytes(n).toString('hex');
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 64, (e, k) => e ? no(e) : ok(k.toString('hex'))));
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const normEmail = v => String(v || '').trim().toLowerCase().slice(0, 254);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

async function init() {
  await q(`
    create table if not exists users(
      id serial primary key, email text unique not null, name text not null,
      pw_salt text not null, pw_hash text not null,
      data jsonb not null default '{}', created_at timestamptz not null default now());
    create table if not exists pending(
      email text primary key, name text not null, pw_salt text not null, pw_hash text not null,
      otp_salt text, otp_hash text, exp bigint default 0, tries int default 0, last_sent bigint default 0);
    create table if not exists sessions(
      token text primary key, user_id int not null references users(id) on delete cascade, exp bigint not null);
  `);
}

const hits = new Map();
const limit = (max, windowMs) => (req, res, next) => {
  const key = req.ip + req.path, now = Date.now();
  const arr = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (arr.length >= max) return res.status(429).json({ error: 'Too many attempts. Try again in a few minutes.' });
  arr.push(now); hits.set(key, arr); next();
};
const h = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); });

async function issueOtp(email) {
  if (!EMAILJS_SERVICE_ID || !EMAILJS_TEMPLATE_ID || !EMAILJS_PUBLIC_KEY || !EMAILJS_PRIVATE_KEY)
    return { status: 500, error: 'Email sending is not configured on the server.' };
  const p = (await q('select name, last_sent from pending where email=$1', [email])).rows[0];
  if (!p) return { status: 400, error: 'Start sign-up again.' };
  const wait = RESEND_MS - (Date.now() - Number(p.last_sent || 0));
  if (wait > 0) return { status: 429, error: `Wait ${Math.ceil(wait / 1000)}s before requesting another code.` };

  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0'), salt = rand(8);
  await q('update pending set otp_salt=$2, otp_hash=$3, exp=$4, tries=0, last_sent=$5 where email=$1',
    [email, salt, sha(salt + code), Date.now() + OTP_TTL_MS, Date.now()]);

  const r = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      service_id: EMAILJS_SERVICE_ID, template_id: EMAILJS_TEMPLATE_ID,
      user_id: EMAILJS_PUBLIC_KEY, accessToken: EMAILJS_PRIVATE_KEY,
      template_params: {
        to_email: email, email, to_name: p.name, name: p.name,
        otp_code: code, passcode: code, expires_in: '5 minutes', time: '5 minutes',
        app_name: 'Daily Time Record'
      }
    })
  });
  const replyText = await r.text();
  console.log('EmailJS reply:', r.status, replyText, '| to:', email);
  if (!r.ok) {
    console.error('EmailJS error', r.status, replyText);
    await q('update pending set last_sent=0 where email=$1', [email]);
    return { status: 502, error: 'Could not send the code email. Please try again shortly.' };
  }
  return null;
}

async function startSession(res, userId) {
  const token = rand(32);
  await q('delete from sessions where exp < $1', [Date.now()]);
  await q('insert into sessions(token, user_id, exp) values($1,$2,$3)', [sha(token), userId, Date.now() + SESSION_DAYS * 864e5]);
  res.setHeader('Set-Cookie',
    `dtr_sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${PROD ? '; Secure' : ''}`);
}
const cookieToken = req => (/(?:^|;\s*)dtr_sid=([a-f0-9]+)/.exec(req.headers.cookie || '') || [])[1];

async function auth(req, res, next) {
  try {
    const t = cookieToken(req);
    if (!t) return res.status(401).json({ error: 'Not logged in.' });
    const r = await q(`select u.id, u.name, u.email from sessions s join users u on u.id=s.user_id
                       where s.token=$1 and s.exp > $2`, [sha(t), Date.now()]);
    if (!r.rows[0]) return res.status(401).json({ error: 'Not logged in.' });
    req.user = r.rows[0]; next();
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error.' }); }
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'same-origin'); next(); });

app.post('/api/signup/start', limit(8, 10 * 60 * 1000), h(async (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 80);
  const email = normEmail(req.body.email), pw = String(req.body.password || '');
  if (name.length < 2) return res.status(400).json({ error: 'Enter your full name.' });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (pw.length < 8 || pw.length > 200) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if ((await q('select 1 from users where email=$1', [email])).rowCount)
    return res.status(409).json({ error: 'This email already has an account. Use the Log in tab.' });

  const salt = rand(16), hash = await scrypt(pw, salt);
  await q(`insert into pending(email, name, pw_salt, pw_hash) values($1,$2,$3,$4)
           on conflict(email) do update set name=$2, pw_salt=$3, pw_hash=$4`, [email, name, salt, hash]);
  const err = await issueOtp(email);
  if (err) return res.status(err.status).json({ error: err.error });
  res.json({ ok: true });
}));

app.post('/api/signup/resend', limit(8, 10 * 60 * 1000), h(async (req, res) => {
  const err = await issueOtp(normEmail(req.body.email));
  if (err) return res.status(err.status).json({ error: err.error });
  res.json({ ok: true });
}));

app.post('/api/signup/verify', limit(20, 10 * 60 * 1000), h(async (req, res) => {
  const email = normEmail(req.body.email), code = String(req.body.code || '').trim();
  const p = (await q('select * from pending where email=$1', [email])).rows[0];
  if (!p || !p.otp_hash) return res.status(400).json({ error: 'Start sign-up again.' });
  if (Date.now() > Number(p.exp)) return res.status(400).json({ error: 'This code has expired. Send a new one.' });
  if (p.tries >= MAX_TRIES) return res.status(429).json({ error: 'Too many wrong attempts. Send a new code.' });
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the 6-digit code.' });
  if (!same(sha(p.otp_salt + code), p.otp_hash)) {
    await q('update pending set tries = tries + 1 where email=$1', [email]);
    return res.status(400).json({ error: `Wrong code. ${MAX_TRIES - p.tries - 1} tries left.` });
  }
  const u = await q(`insert into users(email, name, pw_salt, pw_hash) values($1,$2,$3,$4)
                     on conflict(email) do nothing returning id`, [email, p.name, p.pw_salt, p.pw_hash]);
  if (!u.rows[0]) return res.status(409).json({ error: 'This email already has an account. Use the Log in tab.' });
  await q('delete from pending where email=$1', [email]);
  await startSession(res, u.rows[0].id);
  res.json({ ok: true });
}));

app.post('/api/login', limit(15, 10 * 60 * 1000), h(async (req, res) => {
  const email = normEmail(req.body.email), pw = String(req.body.password || '').slice(0, 200);
  const u = (await q('select id, pw_salt, pw_hash from users where email=$1', [email])).rows[0];
  const hash = await scrypt(pw, u ? u.pw_salt : 'x'.repeat(32));
  if (!u || !same(hash, u.pw_hash)) return res.status(401).json({ error: 'Email or password is incorrect.' });
  await startSession(res, u.id);
  res.json({ ok: true });
}));

app.post('/api/logout', h(async (req, res) => {
  const t = cookieToken(req);
  if (t) await q('delete from sessions where token=$1', [sha(t)]);
  res.setHeader('Set-Cookie', 'dtr_sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
}));

app.get('/api/me', auth, (req, res) => res.json({ name: req.user.name, email: req.user.email }));

app.get('/api/data', auth, h(async (req, res) => {
  const r = await q('select data from users where id=$1', [req.user.id]);
  res.json({ data: r.rows[0].data });
}));

app.put('/api/data', auth, h(async (req, res) => {
  const d = req.body && req.body.data;
  if (!d || typeof d !== 'object' || Array.isArray(d)) return res.status(400).json({ error: 'Invalid data.' });
  await q('update users set data=$2 where id=$1', [req.user.id, JSON.stringify(d)]);
  res.json({ ok: true });
}));

app.get('/healthz', (req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public')));

init().then(() => app.listen(PORT, () => console.log('Listening on ' + PORT)))
  .catch(e => { console.error('Database init failed', e); process.exit(1); });
