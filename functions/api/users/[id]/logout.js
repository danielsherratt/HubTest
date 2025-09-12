// functions/api/users/[id]/logout.js
import { verifyJWT } from '../../../lib/auth.js';

export async function onRequest({ request, env, params }) {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });

  const db = env.POSTS_DB;

  // Admin auth
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];
  const me = token && await verifyJWT(token, env.JWT_SECRET);
  if (!me) return new Response('Unauthorized', { status: 401 });
  if (me.role !== 'admin') return new Response('Forbidden', { status: 403 });

  const id = Number(params.id);
  if (!Number.isFinite(id)) return new Response('Bad Request', { status: 400 });

  await db.prepare(`UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`)
    .bind(new Date().toISOString(), id).run();

  return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
}
