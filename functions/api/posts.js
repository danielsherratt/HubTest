// functions/api/posts.js

// Helpers for base64url and JWT verify
function base64urlToUint8Array(str) {
  // pad and replace
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = 4 - (str.length % 4);
  if (pad !== 4) str += '='.repeat(pad);
  const raw = atob(str);
  return new Uint8Array([...raw].map(ch => ch.charCodeAt(0)));
}
async function verifyJWT(token, secret) {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) return null;
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['verify']
  );
  const data = new TextEncoder().encode(`${h}.${p}`);
  const sig  = base64urlToUint8Array(s);
  const ok   = await crypto.subtle.verify('HMAC', key, sig, data);
  if (!ok) return null;

  const payloadJson = new TextDecoder().decode(base64urlToUint8Array(p));
  const pl = JSON.parse(payloadJson);
  if (pl.exp < Math.floor(Date.now() / 1000)) return null;
  return pl;
}

export async function onRequest({ request, env }) {
  const db  = env.POSTS_DB;
  const cookie = request.headers.get('Cookie') || '';
  const tokenMatch = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = tokenMatch && tokenMatch[1];

  // Public GET
  if (request.method === 'GET') {
    const { results } = await db
      .prepare(`
        SELECT id,title,category,body,pinned,created_at
          FROM posts
         ORDER BY pinned DESC, created_at DESC
      `).all();
    return new Response(JSON.stringify(results), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Require auth for POST/PUT/DELETE
  if (['POST','PUT','DELETE'].includes(request.method)) {
    const user = token && await verifyJWT(token, env.JWT_SECRET);
    if (!user) {
      return new Response('Unauthorized', {
        status: 401,
        headers: { 'WWW-Authenticate': 'Bearer' }
      });
    }
  }

  // Create
  if (request.method === 'POST') {
    const { title, category, body, pinned } = await request.json();
    if (!title||!category||!body) {
      return new Response('Missing fields', { status: 400 });
    }
    const { lastInsertRowId } = await db
      .prepare(`
        INSERT INTO posts (title, category, body, pinned)
        VALUES (?, ?, ?, ?)
      `)
      .bind(title, category, body, pinned ? 1 : 0)
      .run();
    return new Response(JSON.stringify({ id: lastInsertRowId }), {
      status: 201, headers: { 'Content-Type': 'application/json' }
    });
  }

  // Update
  if (request.method === 'PUT') {
    const id = new URL(request.url).pathname.split('/').pop();
    const { category, pinned } = await request.json();
    await db
      .prepare(`
        UPDATE posts SET category = ?, pinned = ?
         WHERE id = ?
      `)
      .bind(category, pinned ? 1 : 0, id)
      .run();
    return new Response(null, { status: 204 });
  }

  // Delete
  if (request.method === 'DELETE') {
    const id = new URL(request.url).pathname.split('/').pop();
    await db.prepare(`DELETE FROM posts WHERE id = ?`).bind(id).run();
    return new Response(null, { status: 204 });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
