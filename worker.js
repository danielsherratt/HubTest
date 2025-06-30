/**
 * Cloudflare Worker
 * Bind your D1 database in the Dashboard as binding name "POSTS_DB"
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const db  = env.POSTS_DB;

    // GET /api/posts
    if (request.method === 'GET' && url.pathname === '/api/posts') {
      const { results } = await db.prepare(
        `SELECT * FROM posts ORDER BY created_at DESC`
      ).all();
      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // POST /api/posts
    if (request.method === 'POST' && url.pathname === '/api/posts') {
      const { title, category, body, video_url } = await request.json();
      const stmt = db.prepare(`
        INSERT INTO posts (title, category, body, video_url)
        VALUES (?, ?, ?, ?)
      `);
      const { lastInsertRowId } = await stmt
        .bind(title, category, body, video_url || null)
        .run();
      return new Response(JSON.stringify({ id: lastInsertRowId }), {
        status: 201,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // DELETE /api/posts/:id
    const deleteMatch = url.pathname.match(/^\/api\/posts\/(\d+)$/);
    if (request.method === 'DELETE' && deleteMatch) {
      await db.prepare(`DELETE FROM posts WHERE id = ?`)
              .bind(deleteMatch[1]).run();
      return new Response(null, { status: 204 });
    }

    return new Response('Not found', { status: 404 });
  }
};