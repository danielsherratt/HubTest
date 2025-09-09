// functions/api/auth/login.js
import { pbkdf2Hash, verifyJWT, signJWT } from '../../lib/auth';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const { email, password } = await request.json().catch(() => ({}));
  if (!email || !password) {
    return new Response(JSON.stringify({ error: 'Email and password are required.' }), {
      status: 400, headers: { 'Content-Type': 'application/json' }
    });
  }
  const normEmail = String(email).trim().toLowerCase();

  // Lookup user
  // Lockout check
  const attempt = await db.prepare(`SELECT fails, locked_until FROM login_attempts WHERE email = ?`).bind(normEmail).first();
  const nowISO = new Date().toISOString();
  if(attempt && attempt.locked_until && attempt.locked_until > nowISO){
    return new Response(JSON.stringify({ error: 'Account locked. Try again later.' }), { status: 403, headers: { 'Content-Type': 'application/json' } });
  }

  const row = await db.prepare(
    `SELECT id, email, password_algo, password_salt, password_hash, role, failed_attempts, lockout_until
       FROM users WHERE email = ?`
  ).bind(normEmail).first();

  
  // Check lockout
  const nowIso = new Date().toISOString();
  if (row.lockout_until && row.lockout_until > nowIso) {
    return new Response(JSON.stringify({ error: 'Account locked. Try again later.' }), {
      status: 423, headers: { 'Content-Type': 'application/json' }
    });
  }
  if (!row) {
    // Same error to prevent user enumeration
    
    // Record failed attempt
    if(attempt){
      const fails = attempt.fails + 1;
      const locked_until = fails >= 5 ? new Date(Date.now()+15*60*1000).toISOString() : null;
      await db.prepare(`UPDATE login_attempts SET fails=?, locked_until=? WHERE email=?`).bind(fails, locked_until, normEmail).run();
    } else {
      await db.prepare(`INSERT INTO login_attempts (email,fails,locked_until) VALUES (?,?,NULL)`).bind(normEmail,1).run();
    }
    return new Response(JSON.stringify({ error: 'Invalid credentials.' }), {
      status: 401, headers: { 'Content-Type': 'application/json' }
    });
  }

  // Verify password
  if (row.password_algo !== 'pbkdf2-sha256') {
    return new Response(JSON.stringify({ error: 'Unsupported password algorithm.' }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }

  const hashB64 = await pbkdf2Hash(password, row.password_salt, 150000, 32);
  const ok = hashB64 === row.password_hash;
  if (!ok) {
    const attempts = (row.failed_attempts || 0) + 1;
    if (attempts >= 5) {
      const lockoutUntil = new Date(Date.now() + 15*60*1000).toISOString();
      await db.prepare(`UPDATE users SET failed_attempts = 0, lockout_until = ? WHERE id = ?`).bind(lockoutUntil, row.id).run();
      return new Response(JSON.stringify({ error: 'Too many attempts. Account locked for 15 minutes.' }), {
        status: 423, headers: { 'Content-Type': 'application/json' }
      });
    } else {
      await db.prepare(`UPDATE users SET failed_attempts = ? WHERE id = ?`).bind(attempts, row.id).run();
      return new Response(JSON.stringify({ error: 'Invalid credentials.' }), {
        status: 401, headers: { 'Content-Type': 'application/json' }
      });
    }
  
    
    // Record failed attempt
    if(attempt){
      const fails = attempt.fails + 1;
      const locked_until = fails >= 5 ? new Date(Date.now()+15*60*1000).toISOString() : null;
      await db.prepare(`UPDATE login_attempts SET fails=?, locked_until=? WHERE email=?`).bind(fails, locked_until, normEmail).run();
    } else {
      await db.prepare(`INSERT INTO login_attempts (email,fails,locked_until) VALUES (?,?,NULL)`).bind(normEmail,1).run();
    }
    return new Response(JSON.stringify({ error: 'Invalid credentials.' }), {
      status: 401, headers: { 'Content-Type': 'application/json' }
    });
  }

  
  // Reset fails on success
  await db.prepare(`DELETE FROM login_attempts WHERE email=?`).bind(normEmail).run();
  // Reset attempts/lockout on success
  await db.prepare(`UPDATE users SET failed_attempts = 0, lockout_until = NULL WHERE id = ?`).bind(row.id).run();

  // Update last_sign_in and ip
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '';
  await db.prepare(`UPDATE users SET last_sign_in = strftime('%Y-%m-%dT%H:%M:%fZ','now'), last_sign_ip = ? WHERE id = ?`)
    .bind(ip, row.id).run();

  // Create JWT
  const token = await signJWT({ sub: normEmail, role: row.role }, env.JWT_SECRET);

  const res = new Response(JSON.stringify({ ok: true, role: row.role }), {
    headers: { 'Content-Type': 'application/json' }
  });
  res.headers.append('Set-Cookie',
    `token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60*60*24*7}`
  );
  return res;
}
