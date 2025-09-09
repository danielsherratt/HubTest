// functions/api/users/index.js
import { verifyJWT, pbkdf2Hash } from '../../lib/auth.js';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];
  const me = token && await verifyJWT(token, env.JWT_SECRET);
  if (!me) return new Response('Unauthorized', { status: 401 });
  if (me.role !== 'admin') return new Response('Forbidden', { status: 403 });

  if (request.method === 'GET') {
    const { results } = await db.prepare(`
      SELECT id, email, role, last_sign_in, last_sign_ip, created_at
        FROM users
       ORDER BY created_at DESC
    `).all();
    return new Response(JSON.stringify(results), { headers: { 'Content-Type': 'application/json' } });
  }

  if (request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const role = (String(body.role || 'user').trim().toLowerCase() === 'admin') ? 'admin' : 'user';
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'Email and password are required.' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }
    const salt = new Uint8Array(16); crypto.getRandomValues(salt);
    const saltB64 = btoa(String.fromCharCode(...salt));
    const hashB64 = await pbkdf2Hash(password, saltB64, 100000, 32);

    try {
      await db.prepare(`
        INSERT INTO users (email, password_algo, password_salt, password_hash, role)
        VALUES (?, 'pbkdf2-sha256', ?, ?, ?)
      `).bind(email, saltB64, hashB64, role).run();
    } catch (e) {
      const msg = (e?.message || '').toLowerCase();
      if (msg.includes('unique') || msg.includes('constraint')) {
        return new Response(JSON.stringify({ error: 'Email already exists.' }), {
          status: 409, headers: { 'Content-Type': 'application/json' }
        });
      }
      return new Response(JSON.stringify({ error: 'Failed to create user.' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }
    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  return new Response('Method Not Allowed', { status: 405 });
}