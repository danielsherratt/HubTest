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

  const data = new TextEncoder().encode(`${h}.${p}`);
  const signature = base64urlToUint8Array(s);
  const valid = await crypto.subtle.verify('HMAC', key, signature, data);
  if (!valid) return null;

  const payload = JSON.parse(
    new TextDecoder().decode(base64urlToUint8Array(p))
  );
  if (payload.exp < Math.floor(Date.now() / 1000)) return null;

  return payload;
}

export async function onRequest({ request, env }) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = match && match[1];

  if (!token) return new Response('Unauthorized', { status: 401 });

  const user = await verifyJWT(token, env.JWT_SECRET);
  if (!user) return new Response('Unauthorized', { status: 401 });

  return new Response(JSON.stringify({ role: user.sub }), {
    headers: { 'Content-Type': 'application/json' }
  });
}
