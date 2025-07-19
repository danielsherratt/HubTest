// functions/api/login.js

function base64url(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function encodeUTF8(str) {
  return new TextEncoder().encode(str);
}

export async function onRequestPost({ request, env }) {
  const { pass } = await request.json();

  // Determine role
  let role;
  if (pass === env.ADMIN_PASS) {
    role = 'admin';
  } else if (pass === env.USER_PASS) {
    role = 'user';
  } else {
    return new Response('Unauthorized', { status: 401 });
  }

  const header = { alg: 'HS256', typ: 'JWT' };
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;
  const payload = { sub: role, iat, exp };

  const key = await crypto.subtle.importKey(
    'raw', encodeUTF8(env.JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );

  const encHeader = base64url(encodeUTF8(JSON.stringify(header)));
  const encPayload = base64url(encodeUTF8(JSON.stringify(payload)));
  const toSign = encodeUTF8(`${encHeader}.${encPayload}`);
  const sigBuffer = await crypto.subtle.sign('HMAC', key, toSign);
  const encSig = base64url(sigBuffer);

  const token = `${encHeader}.${encPayload}.${encSig}`;

  const res = new Response(JSON.stringify({ role }), { status: 200 });
  res.headers.set('Set-Cookie',
    `token=${token}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=3600`
  );
  res.headers.set('Content-Type', 'application/json');
  return res;
}
