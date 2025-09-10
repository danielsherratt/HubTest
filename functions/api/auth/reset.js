// functions/api/auth/reset.js
import { sha256Base64Url } from '../../lib/tokens.js';
import { pbkdf2Hash } from '../../lib/auth.js';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;

  if (request.method === 'POST') {
    let token = '', password = '';
    try {
      const body = await request.json();
      token = String(body.token || '');
      password = String(body.password || '');
    } catch {}
    if (!token || password.length < 6) {
      return new Response(JSON.stringify({ error: 'Invalid token or weak password.' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    const tokenHash = await sha256Base64Url(token);
    const nowIso = new Date().toISOString();

    const rec = await db.prepare(`
      SELECT pr.id, pr.user_id, pr.expires_at, pr.used
      FROM password_resets pr
      WHERE pr.token_hash = ?
      LIMIT 1
    `).bind(tokenHash).first();

    if (!rec || rec.used) {
      return new Response(JSON.stringify({ error: 'Invalid or used token.' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }
    if (rec.expires_at <= nowIso) {
      return new Response(JSON.stringify({ error: 'Token expired.' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // Update user password (PBKDF2-SHA256 @ 100k, 32 bytes)
    const saltBytes = new Uint8Array(16); crypto.getRandomValues(saltBytes);
    const saltB64 = btoa(String.fromCharCode(...saltBytes));
    const hashB64 = await pbkdf2Hash(password, saltB64, 100000, 32);

    await db.prepare(`
      UPDATE users
         SET password_algo = 'pbkdf2-sha256',
             password_salt = ?,
             password_hash = ?
       WHERE id = ?
    `).bind(saltB64, hashB64, rec.user_id).run();

    // Mark token used (single-use)
    await db.prepare(`UPDATE password_resets SET used = 1 WHERE id = ?`).bind(rec.id).run();

    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
