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

export async function onRequest({ request, env, params }) {
  const method = request.method.toUpperCase();
  const id = params.id;
  if (!id) return new Response('Missing ID', { status: 400 });

  // Only DELETE and PUT require auth
  if (method === 'DELETE' || method === 'PUT') {
    const cookie = request.headers.get('Cookie') || '';
    const match = cookie.match(/(?:^|;\\s*)token=([^;]+)/);
    const token = match && match[1];
    const user = token && await verifyJWT(token, env.JWT_SECRET);
    if (!user) {
      return new Response('Unauthorized', { status: 401 });
    }
  }

  try {
    if (method === 'DELETE') {
      const { results } = await env.POSTS_DB.prepare(`
        SELECT url FROM resources WHERE id = ?
      `).bind(id).all();

      if (results.length === 0) {
        return new Response('Resource not found', { status: 404 });
      }

      const key = results[0].url.replace('https://files.danieltesting.space/', '');
      await env.MY_BUCKET.delete(key);
      await env.POSTS_DB.prepare(`DELETE FROM resources WHERE id = ?`).bind(id).run();

      return new Response(null, { status: 204 });
    }

    if (method === 'PUT') {
      const { pinned } = await request.json();
      await env.POSTS_DB.prepare(`
        UPDATE resources
           SET pinned = ?
         WHERE id = ?
      `)
      .bind(pinned ? 1 : 0, id)
      .run();

      return new Response(null, { status: 204 });
    }

    return new Response('Method Not Allowed', { status: 405 });
  } catch (err) {
    console.error('Error handling resource:', err);
    return new Response('Server Error', { status: 500 });
  }
}
