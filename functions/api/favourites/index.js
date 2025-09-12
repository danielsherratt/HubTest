// GET ?type=post|resource         → [ids]
// POST { entity_type, entity_id, on }  → add/remove
import { getMe } from '../../../lib/me.js';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  const me = await getMe(env, request);
  if (!me) return new Response('Unauthorized', { status: 401 });

  if (request.method === 'GET') {
    const type = new URL(request.url).searchParams.get('type');
    if (!['post','resource'].includes(type)) return new Response('Bad Request', { status: 400 });
    const rows = await db.prepare(
      `SELECT entity_id FROM favourites WHERE user_id = ? AND entity_type = ?`
    ).bind(me.id, type).all();
    return new Response(JSON.stringify((rows.results || []).map(r => Number(r.entity_id))), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  if (request.method === 'POST') {
    const body = await request.json().catch(()=>({}));
    const { entity_type, entity_id, on } = body;
    if (!['post','resource'].includes(entity_type)) return new Response('Bad Request', { status: 400 });
    const id = Number(entity_id);
    if (!Number.isFinite(id)) return new Response('Bad Request', { status: 400 });

    if (on) {
      await db.prepare(`INSERT OR IGNORE INTO favourites (user_id, entity_type, entity_id, created_at) VALUES (?, ?, ?, ?)`)
        .bind(me.id, entity_type, id, new Date().toISOString()).run();
    } else {
      await db.prepare(`DELETE FROM favourites WHERE user_id = ? AND entity_type = ? AND entity_id = ?`)
        .bind(me.id, entity_type, id).run();
    }
    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
