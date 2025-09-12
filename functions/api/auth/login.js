// functions/api/auth/login.js
import { pbkdf2Hash, signJWT } from '../../lib/auth.js';

function cookieAttrs(request, maxAgeSec = 60 * 60 * 24 * 2) { // 2 days
  const isHttps = new URL(request.url).protocol === 'https:';
  return `Path=/; HttpOnly; ${isHttps ? 'Secure; ' : ''}SameSite=Lax; Max-Age=${maxAgeSec}`;
}

export async function onRequest({ request, env }) {
  try {
    if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

    const db = env.POSTS_DB;
    if (!db?.prepare) return new Response(JSON.stringify({ error: 'DB not configured.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    if (!env.JWT_SECRET) return new Response(JSON.stringify({ error: 'JWT secret not configured.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });

    const body = await request.json().catch(() => ({}));
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!email || !password) return new Response(JSON.stringify({ error: 'Email and password are required.' }), { status: 400, headers: { 'Content-Type': 'application/json' } });

    const row = await db.prepare(`
      SELECT id, email, password_algo, password_salt, password_hash, role,
             failed_attempts, lockout_until
        FROM users WHERE email = ?`).bind(email).first();

    if (!row) return new Response(JSON.stringify({ error: 'Invalid credentials.' }), { status: 401, headers: { 'Content-Type': 'application/json' } });

    const nowIso = new Date().toISOString();
    if (row.lockout_until && row.lockout_until > nowIso) {
      return new Response(JSON.stringify({ error: 'Account locked. Try again later.' }), { status: 423, headers: { 'Content-Type': 'application/json' } });
    }

    if (row.password_algo !== 'pbkdf2-sha256') {
      return new Response(JSON.stringify({ error: 'Unsupported password algorithm.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    const derived = await pbkdf2Hash(password, row.password_salt, 100000, 32);
    const ok = derived === row.password_hash;

    if (!ok) {
      const attempts = (row.failed_attempts || 0) + 1;
      if (attempts >= 5) {
        const lockoutUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        await db.prepare(`UPDATE users SET failed_attempts = 0, lockout_until = ? WHERE id = ?`).bind(lockoutUntil, row.id).run();
        return new Response(JSON.stringify({ error: 'Too many attempts. Account locked for 15 minutes.' }), { status: 423, headers: { 'Content-Type': 'application/json' } });
      } else {
        await db.prepare(`UPDATE users SET failed_attempts = ? WHERE id = ?`).bind(attempts, row.id).run();
        return new Response(JSON.stringify({ error: 'Invalid credentials.' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
      }
    }

    // Success: reset attempts + update last sign-in
    const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
    await db.prepare(`
      UPDATE users
         SET failed_attempts = 0,
             lockout_until   = NULL,
             last_sign_in    = ?,
             last_sign_ip    = ?
       WHERE id = ?`).bind(nowIso, ip, row.id).run();

    // (Optional) sign-in audit
    try {
      await db.prepare(`INSERT INTO user_signins (user_id, ip, at) VALUES (?, ?, ?)`).bind(row.id, ip, nowIso).run();
      await db.prepare(`DELETE FROM user_signins WHERE at < datetime('now','-30 days')`).run();
    } catch {}

    // Create a DB-backed session (2 days)
    const sid = crypto.randomUUID();
    const expiresIso = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString();
    const ua = request.headers.get('User-Agent') || '';
    await db.prepare(`
      INSERT INTO sessions (id, user_id, created_at, expires_at, user_agent, ip)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(sid, row.id, nowIso, expiresIso, ua, ip).run();

    // Issue JWT referencing the session (include exp too)
    const exp = Math.floor(Date.now() / 1000) + (60 * 60 * 24 * 2);
    const token = await signJWT({ sub: row.email, role: row.role, sid, exp }, env.JWT_SECRET);

    const res = new Response(JSON.stringify({ ok: true, role: row.role }), { headers: { 'Content-Type': 'application/json' } });
    res.headers.append('Set-Cookie', `token=${token}; ${cookieAttrs(request, 60 * 60 * 24 * 2)}`);
    return res;

  } catch (e) {
    return new Response(JSON.stringify({ error: 'Server error.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}
