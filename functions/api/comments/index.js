// GET ?post_id=123   → list comments (flat) for a post
// POST { post_id, body, parent_id? } → create comment
import { getMe } from '../../lib/me.js';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  const url = new URL(request.url);

  if (request.method === 'GET') {
    const postId = Number(url.searchParams.get('post_id'));
    if (!Number.isFinite(postId)) return new Response('Bad Request', { status: 400 });

    const rows = await db.prepare(`
      SELECT c.id, c.post_id, c.user_id, u.email AS author_email, u.role AS author_role,
             c.parent_id, c.body, c.created_at, c.updated_at, c.deleted_at
        FROM comments c
        JOIN users u ON u.id = c.user_id
       WHERE c.post_id = ?
       ORDER BY COALESCE(c.parent_id, c.id), c.created_at
    `).bind(postId).all();

    return new Response(JSON.stringify(rows.results || []), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (request.method === 'POST') {
    const me = await getMe(env, request);
    if (!me) return new Response('Unauthorized', { status: 401 });

    const body = await request.json().catch(() => ({}));
    const post_id   = Number(body.post_id);
    const parent_id = body.parent_id != null ? Number(body.parent_id) : null;
    const text      = String(body.body || '').trim();
    if (!Number.isFinite(post_id) || !text) return new Response('Bad Request', { status: 400 });

    const now = new Date().toISOString();
    const { success, error } = await db.prepare(`
      INSERT INTO comments (post_id, user_id, parent_id, body, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(post_id, me.id, parent_id, text, now, now).run();

    if (!success) return new Response(JSON.stringify({ error: String(error) }), { status: 500 });

    // Return the inserted row (minimal)
    const row = await db.prepare(`
      SELECT c.id, c.post_id, c.user_id, u.email AS author_email, u.role AS author_role,
             c.parent_id, c.body, c.created_at, c.updated_at, c.deleted_at
        FROM comments c JOIN users u ON u.id = c.user_id
       WHERE c.rowid = last_insert_rowid()
    `).first();

    return new Response(JSON.stringify(row), { headers: { 'Content-Type': 'application/json' } });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
