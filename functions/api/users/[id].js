// functions/api/users/[id].js
import { verifyJWT, pbkdf2Hash } from '../../lib/auth.js';
import { passwordPolicyError } from '../../lib/validators.js';

function getTokenFromCookie(request) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  return m && m[1];
}

export async function onRequest({ request, env, params }) {
  const db = env.POSTS_DB;
  const token = getTokenFromCookie(request);
  const me = token && await verifyJWT(token, env.JWT_SECRET);
  if (!me) return new Response('Unauthorized', { status: 401 });
  if (me.role !== 'admin') return new Response('Forbidden', { status: 403 });

  const id = params.id;
  if (!/^\d+$/.test(String(id))) return new Response('Bad Request', { status: 400 });

  if (request.method === 'PUT') {
    // Admin reset password
    const body = await request.json().catch(() => ({}));
    const password = String(body.password || '');

    const perr = passwordPolicyError(password);
    if (perr) {
      return new Response(JSON.stringify({ error: perr }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    const salt = new Uint8Array(16); crypto.getRandomValues(salt);
    const saltB64 = btoa(String.fromCharCode(...salt));
    const hashB64 = await pbkdf2Hash(password, saltB64, 100000, 32);

    const res = await db.prepare(`
      UPDATE users
         SET password_algo = 'pbkdf2-sha256',
             password_salt = ?,
             password_hash = ?
       WHERE id = ?
    `).bind(saltB64, hashB64, id).run();

    if (res.success === false) {
      return new Response(JSON.stringify({ error: 'Failed to update password.' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }
    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  if (request.method === 'DELETE') {
    // Optional: prevent deleting self
    const row = await db.prepare(`SELECT email FROM users WHERE id = ?`).bind(id).first();
    if (!row) return new Response('Not Found', { status: 404 });
    if (row.email === me.sub) {
      return new Response(JSON.stringify({ error: 'You cannot delete your own account.' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }
    await db.prepare(`DELETE FROM users WHERE id = ?`).bind(id).run();
    return new Response(null, { status: 204 });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
