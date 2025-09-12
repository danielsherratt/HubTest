// PUT { body }     → edit (author or admin)
// DELETE           → soft delete (author or admin)
import { getMe } from '../../lib/me.js';

export async function onRequest({ request, env, params }) {
  const db = env.POSTS_DB;
  const me = await getMe(env, request);
  if (!me) return new Response('Unauthorized', { status: 401 });

  const id = Number(params.id);
  if (!Number.isFinite(id)) return new Response('Bad Request', { status: 400 });

  const current = await db.prepare(`SELECT id, user_id, deleted_at FROM comments WHERE id = ?`).bind(id).first();
  if (!current) return new Response('Not Found', { status: 404 });
  const canEdit = me.role === 'admin' || current.user_id === me.id;
  if (!canEdit) return new Response('Forbidden', { status: 403 });

  if (request.method === 'PUT') {
    const body = await request.json().catch(() => ({}));
    const text = String(body.body || '').trim();
    if (!text) return new Response('Bad Request', { status: 400 });
    const now = new Date().toISOString();
    await db.prepare(`UPDATE comments SET body = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`)
      .bind(text, now, id).run();
    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  if (request.method === 'DELETE') {
    await db.prepare(`UPDATE comments SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`)
      .bind(new Date().toISOString(), id).run();
    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
