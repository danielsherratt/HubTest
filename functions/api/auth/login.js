// functions/api/auth/login.js
import { pbkdf2Hash, signJWT } from '../../lib/auth.js';

// Cookie helper: mark Secure only when on HTTPS so local dev on http://localhost works.
function cookieAttrs(request) {
  const isHttps = new URL(request.url).protocol === 'https:';
  // 7 days
  return `Path=/; HttpOnly; ${isHttps ? 'Secure; ' : ''}SameSite=Lax; Max-Age=${60 * 60 * 24 * 7}`;
}

export async function onRequest({ request, env }) {
  try {
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    const db = env.POSTS_DB;
    if (!db || !db.prepare) {
      return new Response(JSON.stringify({ error: 'Database not configured (POSTS_DB).' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }
    if (!env.JWT_SECRET) {
      return new Response(JSON.stringify({ error: 'JWT secret not configured.' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }

    // Parse input
    const body = await request.json().catch(() => ({}));
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'Email and password are required.' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // Lookup user
    const row = await db.prepare(
      `SELECT id, email, password_algo, password_salt, password_hash, role,
              failed_attempts, lockout_until
         FROM users
        WHERE email = ?`
    ).bind(email).first();

    // Avoid user enumeration
    if (!row) {
      return new Response(JSON.stringify({ error: 'Invalid credentials.' }), {
        status: 401, headers: { 'Content-Type': 'application/json' }
      });
    }

    // Lockout check
    const nowIso = new Date().toISOString();
    if (row.lockout_until && row.lockout_until > nowIso) {
      return new Response(JSON.stringify({ error: 'Account locked. Try again later.' }), {
        status: 423, headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify password (PBKDF2-SHA256 @ 100,000 iters, 32 bytes)
    if (row.password_algo !== 'pbkdf2-sha256') {
      return new Response(JSON.stringify({ error: 'Unsupported password algorithm.' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }

    // IMPORTANT: Workers cap PBKDF2 at 100,000 iterations
    const derived = await pbkdf2Hash(password, row.password_salt, 100000, 32);
    const ok = derived === row.password_hash;

    if (!ok) {
      const attempts = (row.failed_attempts || 0) + 1;
      if (attempts >= 5) {
        const lockoutUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutes
        await db.prepare(`UPDATE users SET failed_attempts = 0, lockout_until = ? WHERE id = ?`)
          .bind(lockoutUntil, row.id).run();
        return new Response(JSON.stringify({ error: 'Too many attempts. Account locked for 15 minutes.' }), {
          status: 423, headers: { 'Content-Type': 'application/json' }
        });
      } else {
        await db.prepare(`UPDATE users SET failed_attempts = ? WHERE id = ?`)
          .bind(attempts, row.id).run();
        return new Response(JSON.stringify({ error: 'Invalid credentials.' }), {
          status: 401, headers: { 'Content-Type': 'application/json' }
        });
      }
    }

    // Success → reset attempts/lockout, update last_sign_in/IP
    const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
    await db.prepare(
      `UPDATE users
          SET failed_attempts = 0,
              lockout_until   = NULL,
              last_sign_in    = ?,
              last_sign_ip    = ?
        WHERE id = ?`
    ).bind(nowIso, ip, row.id).run();

    // (Optional but recommended) log this sign-in in an audit table if present
    try {
      await db.prepare(`INSERT INTO user_signins (user_id, ip, at) VALUES (?, ?, ?)`)
        .bind(row.id, ip, nowIso).run();
      // Light cleanup of very old audit rows
      await db.prepare(`DELETE FROM user_signins WHERE at < datetime('now','-30 days')`).run();
    } catch (_) {
      // ignore if the table doesn't exist — the rest of login still works
    }

    // Issue JWT cookie
    const token = await signJWT({ sub: email, role: row.role }, env.JWT_SECRET);
    const res = new Response(JSON.stringify({ ok: true, role: row.role }), {
      headers: { 'Content-Type': 'application/json' }
    });
    res.headers.append('Set-Cookie', `token=${token}; ${cookieAttrs(request)}`);
    return res;

  } catch (e) {
    // Generic error to client
    return new Response(JSON.stringify({ error: 'Server error.' }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }
}
