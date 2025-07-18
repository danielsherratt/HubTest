// functions/api/posts.js

// Helpers for JWT verification via Web Crypto
function base64urlToUint8Array(str) {
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
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const signature = base64urlToUint8Array(s);
  const data = new TextEncoder().encode(`${h}.${p}`);
  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) return null;

  const payloadJson = new TextDecoder().decode(base64urlToUint8Array(p));
  const pl = JSON.parse(payloadJson);
  if (pl.exp < Math.floor(Date.now() / 1000)) return null;
  return pl;
}

export async function onRequest({ request, env }) {
  const db      = env.POSTS_DB;
  const cookie  = request.headers.get('Cookie') || '';
  const match   = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token   = match && match[1];
  const url     = new URL(request.url);
  const method  = request.method;
  const isAdmin = url.searchParams.has('admin');

  // 1) GET — public except when admin=true
  if (method === 'GET') {
    if (isAdmin) {
      const user = token && await verifyJWT(token, env.JWT_SECRET);
      if (!user) return new Response('Unauthorized', { status: 401 });
    }
    const { results } = await db
      .prepare(`
        SELECT id, title, url, pinned, created_date
          FROM resources
         ORDER BY pinned DESC, created_date DESC
      `)
      .all();
    return new Response(JSON.stringify(results), {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // 2) All mutating methods require a valid JWT
  if (['POST', 'PUT', 'DELETE'].includes(method)) {
    const user = token && await verifyJWT(token, env.JWT_SECRET);
    if (!user) {
      return new Response('Unauthorized', { status: 401 });
    }
  }

  // 3) POST → create
  if (method === 'POST') {
    const { title, category, body, pinned } = await request.json();
    if (!title || !category || !body) {
      return new Response('Missing fields', { status: 400 });
    }
    const { lastInsertRowId } = await db
      .prepare(`
        INSERT INTO resources (title, url, pinned)
        VALUES (?, ?, ?)
      `)
      .bind(title, url, pinned ? 1 : 0)
      .run();
    return new Response(JSON.stringify({ id: lastInsertRowId }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  }


  // 5) DELETE → remove
  if (method === 'DELETE') {
    const id = url.pathname.split('/').pop();
    await db
      .prepare(`DELETE FROM resources WHERE id = ?`)
      .bind(id)
      .run();
    return new Response(null, { status: 204 });
  }

  // 6) Fallback
  return new Response('Method Not Allowed', { status: 405 });
}
