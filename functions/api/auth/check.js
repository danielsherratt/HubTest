function parseJwt(cookie) {
  const token = (cookie.match(/token=([^;]+)/) || [])[1];
  if (!token) return null;
  return token;
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function verifyJwt(token, secret) {
  const [header, payload, sig] = token.split('.');
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    base64urlDecode(sig),
    enc.encode(`${header}.${payload}`)
  );
  if (!valid) return null;
  return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
}

export async function onRequestGet({ request, env }) {
  const cookie = request.headers.get('cookie') || '';
  const token = parseJwt(cookie);
  if (!token) return new Response('Missing token', { status: 401 });

  try {
    const decoded = await verifyJwt(token, env.JWT_SECRET);
    if (!decoded || !decoded.sub) throw new Error('Invalid JWT');
    return new Response(JSON.stringify({ role: decoded.sub }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch {
    return new Response('Unauthorized', { status: 401 });
  }
}
