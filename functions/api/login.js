// functions/api/login.js

// Helpers for base64url
function base64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function encodeUTF8(str) {
  return new TextEncoder().encode(str);
}

export async function onRequestPost({ request, env }) {
  const { user, pass } = await request.json();

  // 1) Validate credentials
  if (user !== env.ADMIN_USER || pass !== env.ADMIN_PASS) {
    return new Response('Unauthorized', { status: 401 });
  }

  // 2) Build JWT
  const header = { alg: 'HS256', typ: 'JWT' };
  const iat    = Math.floor(Date.now() / 1000);
  const exp    = iat + 3600; // 1h
  const payload = { sub: user, iat, exp };

  // 3) Sign with HMAC-SHA256
  const keyData = encodeUTF8(env.JWT_SECRET);
  const key     = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const encHeader  = base64url(encodeUTF8(JSON.stringify(header)));
  const encPayload = base64url(encodeUTF8(JSON.stringify(payload)));
  const toSign     = encodeUTF8(`${encHeader}.${encPayload}`);
  const sigBuffer  = await crypto.subtle.sign('HMAC', key, toSign);
  const encSig     = base64url(sigBuffer);

  const token = `${encHeader}.${encPayload}.${encSig}`;

  // 4) Set HttpOnly, Secure cookie
  const res = new Response(null, { status: 200 });
  res.headers.set('Set-Cookie',
    `token=${token}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=3600`
  );
  return res;
}
