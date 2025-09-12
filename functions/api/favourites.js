// functions/api/favourites.js

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
    const t = (url.searchParams.get('type') || '').toLowerCase();
    if (!['post','resource'].includes(t)) return new Response('Bad Request', { status:400 });
    const rows = await db.prepare(`SELECT entity_id FROM favourites WHERE user_id=? AND entity_type=?`).bind(me.sub, t).all();
    return new Response(JSON.stringify(rows.results.map(r=>r.entity_id)), { headers:{'Content-Type':'application/json'} });
  }

  if (method === 'POST') {
    const b = await request.json();
    const t = (b.entity_type || '').toLowerCase();
    const id = Number(b.entity_id);
    const on = !!b.on;
    if (!['post','resource'].includes(t) || !id) return new Response('Bad Request', { status:400 });
    if (on) {
      await db.prepare(`INSERT OR IGNORE INTO favourites (user_id, entity_type, entity_id) VALUES (?,?,?)`).bind(me.sub, t, id).run();
    } else {
      await db.prepare(`DELETE FROM favourites WHERE user_id=? AND entity_type=? AND entity_id=?`).bind(me.sub, t, id).run();
    }
    return new Response(null, { status:204 });
  }

  return new Response('Method Not Allowed', { status:405 });
}
