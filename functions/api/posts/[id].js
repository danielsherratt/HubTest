export async function onRequest({ request, env, params }) {
  const db = env.POSTS_DB;
  const id = params.id;

  if (request.method === 'PUT') {
    const { category, pinned } = await request.json();
    await db
      .prepare(`
        UPDATE posts
           SET category = ?, pinned = ?
         WHERE id = ?
      `)
      .bind(category, pinned ? 1 : 0, id)
      .run();
    return new Response(null, { status: 204 });
  }

  if (request.method === 'DELETE') {
    await db.prepare(`DELETE FROM posts WHERE id = ?`).bind(id).run();
    return new Response(null, { status: 204 });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
