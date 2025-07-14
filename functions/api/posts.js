// functions/api/posts.js

export async function GET(request, env) {
  const { results } = await env.CARDS.prepare(`
    SELECT id, title, body, category, pinned
      FROM posts
     ORDER BY created_at DESC
  `).all();

  return new Response(JSON.stringify(results), {
    headers: { 'Content-Type': 'application/json' }
  });
}

export async function POST(request, env) {
  const auth = request.headers.get('authorization') || '';
  if (auth !== `Bearer ${env.API_TOKEN}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  const { title, category, body, pinned } = await request.json();
  if (!title || !category || !body) {
    return new Response('Missing fields', { status: 400 });
  }

  const stmt = env.CARDS.prepare(`
    INSERT INTO posts (title, category, body, pinned)
         VALUES (?, ?, ?, ?)
  `);
  const info = await stmt.bind(title, category, body, pinned ? 1 : 0).run();

  return new Response(JSON.stringify({ id: info.lastInsertRowid }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

export async function PUT(request, env) {
  const auth = request.headers.get('authorization') || '';
  if (auth !== `Bearer ${env.API_TOKEN}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  const url = new URL(request.url);
  const id = url.pathname.split('/').pop();
  const { category, pinned } = await request.json();

  const stmt = env.CARDS.prepare(`
    UPDATE posts
       SET category = ?, pinned = ?
     WHERE id = ?
  `);
  await stmt.bind(category, pinned ? 1 : 0, id).run();

  return new Response(null, { status: 204 });
}

export async function DELETE(request, env) {
  const auth = request.headers.get('authorization') || '';
  if (auth !== `Bearer ${env.API_TOKEN}`) {
    return new Response('Unauthorized', { status: 401 });
  }

  const url = new URL(request.url);
  const id = url.pathname.split('/').pop();

  const stmt = env.CARDS.prepare(`
    DELETE FROM posts
     WHERE id = ?
  `);
  await stmt.bind(id).run();

  return new Response(null, { status: 204 });
}
