export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const db = env.CARDS;

    // GET /api/cards
    if (url.pathname === '/api/cards' && request.method === 'GET') {
      const { results } = await db.prepare(
        `SELECT id, title, body, category, video_url, created_at FROM cards ORDER BY created_at DESC`
      ).all();
      return new Response(JSON.stringify(results), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // POST /api/cards
    if (url.pathname === '/api/cards' && request.method === 'POST') {
      const { title, body, category, video_url } = await request.json();
      if (!title || !body || !category) {
        return new Response('Missing fields', { status: 400 });
      }
      const stmt = db.prepare(
        `INSERT INTO cards (title, body, category, video_url) VALUES (?, ?, ?, ?)`
      );
      const info = await stmt.bind(title, body, category, video_url || null).run();
      return new Response(JSON.stringify({ id: info.lastInsertRowid }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not found', { status: 404 });
  }
}