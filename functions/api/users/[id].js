// functions/api/users/[id].js
import { verifyJWT } from '../../lib/auth.js';

export async function onRequest({ request, env, params }) {
  const db = env.POSTS_DB;
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\\s*)token=([^;]+)/);
  const token = m && m[1];
  const me = token && await verifyJWT(token, env.JWT_SECRET);
  if (!me) return new Response('Unauthorized', { status: 401 });
  if (me.role !== 'admin') return new Response('Forbidden', { status: 403 });

  if (request.method !== 'DELETE') {
    return new Response('Method Not Allowed', { status: 405 });
  }

  const id = params.id;
  if (!/^\\d+$/.test(String(id))) return new Response('Bad Request', { status: 400 });

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
