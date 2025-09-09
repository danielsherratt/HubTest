// functions/api/auth/login.js (TEMP DEBUG)
import { pbkdf2Hash, signJWT } from '../../lib/auth.js';

function cookieAttrs(request) {
  const isHttps = new URL(request.url).protocol === 'https:';
  return `Path=/; HttpOnly; ${isHttps ? 'Secure; ' : ''}SameSite=Lax; Max-Age=${60 * 60 * 24 * 7}`;
}

export async function onRequest({ request, env }) {
  const dbg = { step: 'start' };
  try {
    const db = env.POSTS_DB;
    if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

    if (!env.JWT_SECRET) throw new Error('Missing JWT_SECRET');
    if (!db || !db.prepare) throw new Error('Missing D1 binding POSTS_DB');

    dbg.step = 'read-body';
    const body = await request.json().catch(() => ({}));
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'Email and password are required.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });
    }

    dbg.step = 'select-user';
    const row = await db.prepare(`
      SELECT id, email, password_algo, password_salt, password_hash, role,
             failed_attempts, lockout_until
        FROM users WHERE email = ?
    `).bind(email).first();

    if (!row) {
      return new Response(JSON.stringify({ error: 'Invalid credentials (no user).', dbg }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }

    dbg.row = { id: row.id, email: row.email, algo: row.password_algo, role: row.role, fa: row.failed_attempts, lu: row.lockout_until };

    dbg.step = 'lockout-check';
    const nowIso = new Date().toISOString();
    if (row.lockout_until && row.lockout_until > nowIso) {
      return new Response(JSON.stringify({ error: 'Account locked. Try again later.', dbg }), { status: 423, headers: { 'Content-Type': 'application/json' } });
    }

    if (row.password_algo !== 'pbkdf2-sha256') throw new Error('Unsupported password algorithm: ' + row.password_algo);

    dbg.step = 'pbkdf2';
    const derived = await pbkdf2Hash(password, row.password_salt, 100000, 32);
    dbg.derivedPrefix = derived.slice(0, 12);
    dbg.storedPrefix  = (row.password_hash || '').slice(0, 12);

    if (derived !== row.password_hash) {
      dbg.step = 'bad-password';
      const attempts = (row.failed_attempts || 0) + 1;
      if (attempts >= 5) {
        const lockoutUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        await db.prepare(`UPDATE users SET failed_attempts = 0, lockout_until = ? WHERE id = ?`).bind(lockoutUntil, row.id).run();
        return new Response(JSON.stringify({ error: 'Too many attempts. Account locked for 15 minutes.', dbg }), { status: 423, headers: { 'Content-Type': 'application/json' } });
      } else {
        await db.prepare(`UPDATE users SET failed_attempts = ? WHERE id = ?`).bind(attempts, row.id).run();
        return new Response(JSON.stringify({ error: 'Invalid credentials (bad password).', dbg }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
    }

    dbg.step = 'audit-update';
    await db.prepare(`
      UPDATE users
         SET failed_attempts = 0,
             lockout_until   = NULL,
             last_sign_in    = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
             last_sign_ip    = ?
       WHERE id = ?
    `).bind(
      request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '',
      row.id
    ).run();

    dbg.step = 'jwt';
    const token = await signJWT({ sub: email, role: row.role }, env.JWT_SECRET);
    const res = new Response(JSON.stringify({ ok: true, role: row.role, dbg }), { headers: { 'Content-Type': 'application/json' } });
    res.headers.append('Set-Cookie', `token=${token}; ${cookieAttrs(request)}`);
    return res;

  } catch (e) {
    return new Response(JSON.stringify({ error: 'Server error in /api/auth/login', step: dbg.step, dbg, detail: String(e), stack: e?.stack }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }
}
