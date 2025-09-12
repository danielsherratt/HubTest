// functions/api/auth/me.js
import { verifyJWT } from '../../lib/auth.js';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];

  try {
    const me = token && await verifyJWT(token, env.JWT_SECRET);
    if (!me?.sub || !me?.sid) return new Response('Unauthorized', { status: 401 });

    // Check the session row
    const s = await db.prepare(`SELECT user_id, expires_at, revoked_at FROM sessions WHERE id = ?`).bind(me.sid).first();
    if (!s) return new Response('Unauthorized', { status: 401 });

    const nowIso = new Date().toISOString();
    if (s.revoked_at) return new Response('Unauthorized', { status: 401 });
    if (s.expires_at <= nowIso) return new Response('Unauthorized', { status: 401 });

    // Look up role/email from users (optional; your token has role)
    const u = await db.prepare(`SELECT email, role FROM users WHERE email = ?`).bind(me.sub).first();
    if (!u) return new Response('Unauthorized', { status: 401 });

    return new Response(JSON.stringify({ email: u.email, role: u.role }), { headers: { 'Content-Type': 'application/json' } });
  } catch {
    return new Response('Unauthorized', { status: 401 });
  }
}
