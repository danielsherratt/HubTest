// functions/api/auth/logout.js
import { verifyJWT } from '../../lib/auth.js';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];

  try {
    const me = token && await verifyJWT(token, env.JWT_SECRET);
    if (me?.sid) {
      await db.prepare(`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`)
        .bind(new Date().toISOString(), me.sid).run();
    }
  } catch {}

  const isHttps = new URL(request.url).protocol === 'https:';
  const kill = `token=; Path=/; HttpOnly; ${isHttps ? 'Secure; ' : ''}SameSite=Lax; Max-Age=0`;
  return new Response(JSON.stringify({ ok: true }), {
    headers: { 'Set-Cookie': kill, 'Content-Type': 'application/json' }
  });
}
