import { jwt } from '@tsndr/cloudflare-worker-jwt';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;

  // Helper: extract & verify JWT from cookie
  async function requireAuth() {
    const cookie = request.headers.get('Cookie') || '';
    const match  = cookie.match(/(?:^|;\s*)token=([^;]+)/);
    const token  = match && match[1];
    if (!token || !(await jwt.verify(token, env.JWT_SECRET))) {
      throw new Response('Unauthorized', { status: 401 });
    }
  }

  // 1) GET — public
  if (request.method === 'GET') {
    const { results } = await db
      .prepare(`SELECT id, title, category, body, pinned, created_at
                FROM posts
               ORDER BY pinned DESC, created_at DESC`)
      .all();
    return new Response(JSON.stringify(results), { headers: {'Content-Type':'application/json'} });
  }

  // 2) POST — create (requires auth)
  if (request.method === 'POST') {
    await requireAuth();
    const { title, category, body, pinned } = await request.json();
    if (!title || !category || !body) {
      return new Response('Missing fields', { status: 400 });
    }
    const { lastInsertRowId } = await db
      .prepare(`INSERT INTO posts (title, category, body, pinned)
                VALUES (?, ?, ?, ?)`)
      .bind(title, category, body, pinned ? 1 : 0)
      .run();
    return new Response(JSON.stringify({ id: lastInsertRowId }), {
      status: 201, headers: {'Content-Type':'application/json'}
    });
  }

  // 3) PUT — update (requires auth)
  if (request.method === 'PUT') {
    await requireAuth();
    const id = new URL(request.url).pathname.split('/').pop();
    const { category, pinned } = await request.json();
    await db
      .prepare(`UPDATE posts SET category = ?, pinned = ? WHERE id = ?`)
      .bind(category, pinned ? 1 : 0, id)
      .run();
    return new Response(null, { status: 204 });
  }

  // 4) DELETE — remove (requires auth)
  if (request.method === 'DELETE') {
    await requireAuth();
    const id = new URL(request.url).pathname.split('/').pop();
    await db.prepare(`DELETE FROM posts WHERE id = ?`).bind(id).run();
    return new Response(null, { status: 204 });
  }

  // 5) fallback
  return new Response('Method Not Allowed', { status: 405 });
}
