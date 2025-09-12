// Cloudflare Pages/Workers function: /api/users
// Supports: GET (list users), POST (create user)
// Admin-only with JWT cookie auth and token_version guard

const COOKIE_CANDIDATES = ['cesw_token','auth','token','jwt','session','sid'];
const HASH_ITERATIONS = 100000;          // per platform cap
const HASH_ALGO = 'PBKDF2';
const DIGEST = 'SHA-256';
const KEY_ALGO = 'HMAC';
const HASH_FORMAT = 'colon';             // 'colon' => pbkdf2:100000:<saltB64url>:<hashB64url>
// If your login verifier expects a different format, adapt `formatPasswordHash()`.

export async function onRequestGet(ctx) {
  try {
    const me = await requireAdmin(ctx, true);
    const withStats = new URL(ctx.request.url).searchParams.get('with_signin_stats') === '1';

    // Basic user fields
    const base = await ctx.env.POSTS_DB
      .prepare(`SELECT id, email, role, first_name, last_name, last_sign_in, last_sign_ip
                FROM users`)
      .all();
    const users = base.results || [];

    if (withStats) {
      // Distinct IPs in last 24h
      const statRows = await ctx.env.POSTS_DB
        .prepare(`SELECT user_id, COUNT(DISTINCT ip) AS distinct_ips_24h
                  FROM user_signins
                  WHERE at >= datetime('now','-1 day')
                  GROUP BY user_id`)
        .all();

      const map = new Map((statRows.results || []).map(r => [String(r.user_id), Number(r.distinct_ips_24h) || 0]));
      for (const u of users) {
        u.distinct_ips_24h = map.get(String(u.id)) || 0;
      }
    }

    // Client sorts; we just return everything (admin UI limits to 10)
    return json(users);
  } catch (err) {
    return errorToResponse(err);
  }
}

export async function onRequestPost(ctx) {
  try {
    const me = await requireAdmin(ctx, true);

    const body = await readJson(ctx.request);
    const first_name = (body.first_name || '').trim();
    const last_name  = (body.last_name || '').trim();
    const email      = (body.email || '').trim().toLowerCase();
    const role       = (body.role || '').trim();
    let   password   = (body.password || '').trim();
    const send_welcome = !!body.send_welcome;
    const welcome_name = (body.welcome_name || first_name || '').trim();

    if (!first_name || !last_name || !email || !role)
      return badRequest('first_name, last_name, email and role are required.');
    if (!/^[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}$/.test(email))
      return badRequest('Invalid email.');
    if (!['user','admin'].includes(role))
      return badRequest('Invalid role.');

    if (!password) password = makeRandomPassword();

    // Ensure unique email
    const existing = await ctx.env.POSTS_DB
      .prepare('SELECT id FROM users WHERE lower(email)=?')
      .bind(email)
      .first();
    if (existing) return conflict('Email already exists.');

    // Hash password
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await pbkdf2(password, salt, HASH_ITERATIONS);
    const password_hash = formatPasswordHash(salt, hash, HASH_ITERATIONS);

    // Insert
    const result = await ctx.env.POSTS_DB
      .prepare(`INSERT INTO users (first_name,last_name,email,role,password_hash,failed_attempts,lockout_until,token_version)
                VALUES (?,?,?,?,?,0,NULL,0)`)
      .bind(first_name, last_name, email, role, password_hash)
      .run();

    const newId = result.lastRowId;

    // Optionally send welcome email
    if (send_welcome) {
      await trySendWelcome(ctx.env, {
        to: email,
        name: welcome_name || first_name || '',
        role
      }).catch(() => {});
    }

    // Return created user (without password)
    return json({ id: newId, first_name, last_name, email, role }, 201);
  } catch (err) {
    return errorToResponse(err);
  }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

async function requireAdmin(ctx, checkTokenVersion = true) {
  const { payload } = await verifyJWTFromCookie(ctx.request, ctx.env);
  if (!payload || payload.role !== 'admin') throw unauthorized();
  if (checkTokenVersion && typeof payload.token_version === 'number') {
    const row = await ctx.env.POSTS_DB
      .prepare('SELECT token_version FROM users WHERE id=?')
      .bind(payload.sub)
      .first();
    if (!row || Number(row.token_version) !== Number(payload.token_version)) {
      throw unauthorized('Session invalidated. Please sign in again.');
    }
  }
  return payload;
}

async function readJson(req) {
  try { return await req.json(); }
  catch { throw badRequest('Invalid JSON.'); }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' }
  });
}
function badRequest(msg='Bad Request'){ return new HttpError(400, msg); }
function unauthorized(msg='Unauthorized'){ return new HttpError(401, msg); }
function conflict(msg='Conflict'){ return new HttpError(409, msg); }
function HttpError(status, message){ this.status=status; this.message=message; }
function errorToResponse(err){
  if (err instanceof HttpError) return json({ error: err.message }, err.status);
  console.error(err);
  return json({ error:'Internal Server Error' }, 500);
}

/* ---------- Password hashing ---------- */

async function pbkdf2(password, saltU8, iterations) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: HASH_ALGO }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: HASH_ALGO, hash: DIGEST, salt: saltU8, iterations },
    key, 256
  );
  return new Uint8Array(bits);
}

function b64url(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  // base64url
  return s.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

function formatPasswordHash(saltU8, hashU8, iterations) {
  const salt = b64url(saltU8);
  const h = b64url(hashU8);
  if (HASH_FORMAT === 'colon') {
    return `pbkdf2:${iterations}:${salt}:${h}`;
  }
  // Add other formats here if your login verifier expects them,
  // e.g. 'pbkdf2$100000$<salt>$<hash>'
  return `pbkdf2:${iterations}:${salt}:${h}`;
}

function makeRandomPassword() {
  // Simple, meets typical complexity (adapt if you enforce stricter policy)
  const chunk = Math.random().toString(36).slice(-8);
  const num = Math.floor(100 + Math.random() * 900);
  return `${chunk}!${num}`;
}

/* ---------- JWT verify from cookie ---------- */

async function verifyJWTFromCookie(request, env) {
  const cookie = request.headers.get('cookie') || '';
  const token = extractJwtFromCookie(cookie);
  if (!token) throw unauthorized();

  const [h64, p64, s64] = token.split('.');
  if (!h64 || !p64 || !s64) throw unauthorized();

  const enc = new TextEncoder();
  const data = `${h64}.${p64}`;
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(env.JWT_SECRET || ''), { name: KEY_ALGO, hash: DIGEST }, false, ['sign']
  );
  const sig = await crypto.subtle.sign(KEY_ALGO, key, new TextEncoder().encode(data));
  const sigB64url = b64url(new Uint8Array(sig));
  if (!timingSafeEqual(sigB64url, s64)) throw unauthorized();

  const payloadJson = atob(p64.replace(/-/g,'+').replace(/_/g,'/'));
  const payload = JSON.parse(payloadJson);

  // Optional exp/iat checks
  const now = Math.floor(Date.now()/1000);
  if (payload.exp && now >= payload.exp) throw unauthorized('Session expired.');

  return { payload };
}

function extractJwtFromCookie(cookie) {
  // Try plausible cookie names; if none, fall back to first JWT-looking token
  const parts = cookie.split(/;\s*/);
  for (const name of COOKIE_CANDIDATES) {
    const m = parts.find(p => p.startsWith(name + '='));
    if (m) {
      const v = m.slice(name.length + 1);
      if (v.split('.').length === 3) return v;
    }
  }
  // Fallback: find first "xxx.yyy.zzz" in cookies
  for (const p of parts) {
    const idx = p.indexOf('=');
    const v = idx >= 0 ? p.slice(idx+1) : p;
    if (v.split('.').length === 3) return v;
  }
  return null;
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let res = 0;
  for (let i=0; i<a.length; i++) res |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return res === 0;
}

/* ---------- Optional welcome email ---------- */

async function trySendWelcome(env, { to, name, role }) {
  const subject = 'Welcome to CESW Hub';
  const greeting = name ? `Hello ${name},` : 'Hello,';
  const html =
`<p>${greeting}</p>
<p>Your ${role === 'admin' ? 'administrator' : 'staff'} account has been created.</p>
<p>You can now sign in to the CESW Staff Hub.</p>
<p>Kind regards,<br>CESW ICT</p>`;

  // Prefer RESEND if configured
  if (env.RESEND_API_KEY && env.FROM_EMAIL) {
    const r = await fetch('https://api.resend.com/emails', {
      method:'POST',
      headers:{
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type':'application/json'
      },
      body: JSON.stringify({
        from: env.FROM_EMAIL,
        to: [to],
        subject,
        html
      })
    });
    if (!r.ok) {
      const t = await r.text().catch(()=> '');
      console.warn('RESEND send failed', r.status, t);
    }
    return;
  }

  // Fallback: Mailgun (requires domain + key)
  if (env.MAILGUN_API_KEY && env.MAILGUN_DOMAIN && env.FROM_EMAIL) {
    const form = new URLSearchParams();
    form.set('from', env.FROM_EMAIL);
    form.set('to', to);
    form.set('subject', subject);
    form.set('html', html);

    const r = await fetch(`https://api.mailgun.net/v3/${env.MAILGUN_DOMAIN}/messages`, {
      method:'POST',
      headers:{ 'Authorization': 'Basic ' + btoa('api:' + env.MAILGUN_API_KEY) },
      body: form
    });
    if (!r.ok) {
      const t = await r.text().catch(()=> '');
      console.warn('MAILGUN send failed', r.status, t);
    }
    return;
  }

  // No email service configured — safe no-op
  console.info('Welcome email skipped (no email provider configured).');
}
