
export async function GET(request, env) {
  const { results } = await env.CARDS.prepare(
    `SELECT id, title, body, category, video_url, created_at
     FROM cards
     ORDER BY created_at DESC`
  ).all();
  return new Response(JSON.stringify(results), {
    headers: { 'Content-Type': 'application/json' }
  });
}

export async function POST(request, env) {
  const { title, body, category, video_url } = await request.json();
  if (!title || !body || !category) {
    return new Response('Missing fields', { status: 400 });
  }
  const stmt = env.CARDS.prepare(
    `INSERT INTO cards (title, body, category, video_url)
     VALUES (?, ?, ?, ?)`
  );
  const info = await stmt.bind(title, body, category, video_url || null).run();
  return new Response(JSON.stringify({ id: info.lastInsertRowid }), {
    headers: { 'Content-Type': 'application/json' }
  });
}