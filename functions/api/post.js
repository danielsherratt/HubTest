export async function onRequest({ request, env }) {
  const db = env.POSTS_DB; // bind your D1 in Pages settings as POSTS_DB

  // GET all posts
  if (request.method === 'GET') {
    const { results } = await db
      .prepare(`SELECT * FROM posts ORDER BY created_at DESC`)
      .all();
    return new Response(JSON.stringify(results), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // CREATE a new post
  if (request.method === 'POST') {
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

  return new Response('Method Not Allowed', { status: 405 });
}