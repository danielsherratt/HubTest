// functions/api/comments/[id].js

function base64urlToUint8Array(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = 4 - (str.length % 4);
  if (pad !== 4) str += '='.repeat(pad);
  const raw = atob(str);
  return new Uint8Array([...raw].map(ch => ch.charCodeAt(0)));
}
function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function importHmac(secret) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign','verify']);
}
async function signJWT(payload, secret, maxAgeSec=172800) {
  const header = { alg:'HS256', typ:'JWT' };
  const iat = Math.floor(Date.now()/1000);
  const exp = iat + maxAgeSec;
  const key = await importHmac(secret);
  const encH = base64url(new TextEncoder().encode(JSON.stringify(header)));
  const encP = base64url(new TextEncoder().encode(JSON.stringify({...payload, iat, exp})));
  const data = new TextEncoder().encode(`${encH}.${encP}`);
  const sig  = await crypto.subtle.sign('HMAC', key, data);
  const encS = base64url(sig);
  return `${encH}.${encP}.${encS}`;
}
async function verifyJWT(token, secret) {
  const [h,p,s] = token.split('.');
  if (!h || !p || !s) return null;
  const key = await importHmac(secret);
  const ok = await crypto.subtle.verify('HMAC', key, base64urlToUint8Array(s), new TextEncoder().encode(`${h}.${p}`));
  if (!ok) return null;
  const payload = JSON.parse(new TextDecoder().decode(base64urlToUint8Array(p)));
  if (payload.exp < Math.floor(Date.now()/1000)) return null;
  return payload;
}


export async function onRequest({ request, env, params }) {
  const db = env.POSTS_DB;
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];
  const me = token && await verifyJWT(token, env.JWT_SECRET);
  if (!me) return new Response('Unauthorized', { status:401 });

  const id = Number(params.id);
  const method = request.method;

  // Fetch comment
  const row = await db.prepare(`SELECT id, user_id FROM comments WHERE id=?`).bind(id).first();
  if (!row) return new Response('Not Found', { status:404 });

  if (method === 'PUT') {
    const body = await request.json();
    const canEdit = (me.role === 'admin') || (row.user_id === me.sub);
    if (!canEdit) return new Response('Forbidden', { status:403 });
    await db.prepare(`UPDATE comments SET body=? WHERE id=?`).bind(String(body.body||''), id).run();
    return new Response(null, { status:204 });
  }

  if (method === 'DELETE') {
    const canDel = (me.role === 'admin') || (row.user_id === me.sub);
    if (!canDel) return new Response('Forbidden', { status:403 });
    await db.prepare(`UPDATE comments SET deleted_at = datetime('now') WHERE id=?`).bind(id).run();
    return new Response(null, { status:204 });
  }

  return new Response('Method Not Allowed', { status:405 });
}
