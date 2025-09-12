// functions/api/comments.js

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


export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];
  const me = token && await verifyJWT(token, env.JWT_SECRET);
  if (!me) return new Response('Unauthorized', { status:401 });

  const url = new URL(request.url);
  const method = request.method;

  if (method === 'GET') {
    const postId = Number(url.searchParams.get('post_id'));
    if (!postId) return new Response('Bad Request', { status:400 });
    const rows = await db.prepare(`
      SELECT c.id, c.post_id, c.parent_id, c.body, c.created_at, c.deleted_at,
             u.email as author_email, u.first_name, u.last_name
        FROM comments c
        JOIN users u ON u.id = c.user_id
       WHERE c.post_id = ?
       ORDER BY c.created_at ASC
    `).bind(postId).all();
    // Shape name
    const items = rows.results.map(r => ({...r, author_name: (r.first_name||'').trim()+' '+(r.last_name||'').trim()}));
    return new Response(JSON.stringify(items), { headers:{'Content-Type':'application/json'} });
  }

  if (method === 'POST') {
    const body = await request.json();
    const postId = Number(body.post_id);
    if (!postId || !body.body) return new Response('Bad Request', { status:400 });
    const parent = body.parent_id ? Number(body.parent_id) : null;
    await db.prepare(`INSERT INTO comments (post_id, parent_id, user_id, body, created_at) VALUES (?,?,?,?, datetime('now'))`)
      .bind(postId, parent, me.sub, String(body.body)).run();
    return new Response(JSON.stringify({ ok:true }), { status:201, headers:{'Content-Type':'application/json'} });
  }

  return new Response('Method Not Allowed', { status:405 });
}
