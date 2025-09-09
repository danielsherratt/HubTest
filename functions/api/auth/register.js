// functions/api/auth/register.js
import { randomSalt, pbkdf2Hash, signJWT } from '../../lib/auth';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  if (request.method !== 'POST') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const { email, password, role } = await request.json().catch(() => ({}));
  if (!email || !password) {
    return new Response(JSON.stringify({ error: 'Email and password are required.' }), {
      status: 400, headers: { 'Content-Type': 'application/json' }
    });
  }

  // Basic normalize
  const normEmail = String(email).trim().toLowerCase();

  // Hash password
  const saltB64 = randomSalt(16);
  const hashB64 = await pbkdf2Hash(password, saltB64, 150000, 32);

  // Insert
  try {
    await db.prepare(
      `INSERT INTO users (email, password_algo, password_salt, password_hash, role)
       VALUES (?, 'pbkdf2-sha256', ?, ?, ?)`
    ).bind(normEmail, saltB64, hashB64, role ?? 'user').run();
  } catch (e) {
    const msg = (e && e.message || '').toLowerCase();
    if (msg.includes('unique') || msg.includes('constraint')) {
      return new Response(JSON.stringify({ error: 'Email already exists.' }), {
        status: 409, headers: { 'Content-Type': 'application/json' }
      });
    }
    return new Response(JSON.stringify({ error: 'Failed to create user.' }), {
      status: 500, headers: { 'Content-Type': 'application/json' }
    });
  }

  // Issue token
  const token = await signJWT({ sub: normEmail, role: role ?? 'user' }, env.JWT_SECRET);
  const res = new Response(JSON.stringify({ ok: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
  res.headers.append('Set-Cookie',
    `token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60*60*24*7}`
  );
  return res;
}
