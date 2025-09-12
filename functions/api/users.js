// functions/api/users.js

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


async function pbkdf2Hash(password, salt, iterations=100000) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), {name:'PBKDF2'}, false, ['deriveBits']);
  const params = { name:'PBKDF2', salt: enc.encode(salt), iterations: Math.min(iterations, 100000), hash:'SHA-256' };
  const bits = await crypto.subtle.deriveBits(params, key, 256);
  return Array.from(new Uint8Array(bits)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function randomSalt(len=16){
  const a = new Uint8Array(len); crypto.getRandomValues(a);
  return Array.from(a).map(b=>b.toString(16).padStart(2,'0')).join('');
}


export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];
  const me = token && await verifyJWT(token, env.JWT_SECRET);
  if (!me || me.role !== 'admin') return new Response('Forbidden', { status:403 });

  const url = new URL(request.url);
  const method = request.method;

  if (method === 'GET') {
    const q = (url.searchParams.get('q') || '').toLowerCase();
    const sort = (url.searchParams.get('sort') || 'created_at');
    const dir = (url.searchParams.get('dir') || 'desc').toUpperCase() === 'ASC' ? 'ASC' : 'DESC';
    const rows = await db.prepare(`
      SELECT id, email, role, first_name, last_name, last_sign_in, last_sign_ip, created_at
        FROM users
       WHERE (email LIKE ? OR first_name LIKE ? OR last_name LIKE ?)
       ORDER BY CASE WHEN ?='email' THEN email
                     WHEN ?='role' THEN role
                     WHEN ?='last_sign_in' THEN last_sign_in
                     ELSE created_at END ${dir}
    `).bind(f'%{q}%', f'%{q}%', f'%{q}%', sort, sort, sort).all();
    // attach multi-IP alert metric (last 24h, requires user_signins table if present)
    let results = rows.results;
    try {
      for (const r of results) {
        const one = await db.prepare(`SELECT COUNT(DISTINCT ip) as c FROM user_signins WHERE user_id = ? AND at >= datetime('now','-1 day')`).bind(r.id).first();
        r.distinct_ips_24h = one?.c || 0;
      }
    } catch { /* ignore if table missing */ }
    return new Response(JSON.stringify(results), { headers:{'Content-Type':'application/json'} });
  }

  if (method === 'POST') {
    const body = await request.json();
    const email = String(body.email || '').toLowerCase().trim();
    const password = String(body.password || '');
    const role = body.role === 'admin' ? 'admin' : 'user';
    const first = String(body.first_name || '').trim();
    const last  = String(body.last_name || '').trim();
    if (!email || !password) return new Response('Missing', { status:400 });
    const exists = await db.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
    if (exists) return new Response(JSON.stringify({ error:'Email exists' }), { status:409, headers:{'Content-Type':'application/json'} });
    const salt = randomSalt(16);
    const hash = await pbkdf2Hash(password, salt, 100000);
    await db.prepare(`INSERT INTO users (email, role, password_hash, password_salt, first_name, last_name, created_at) VALUES (?,?,?,?,?,?, datetime('now'))`)
      .bind(email, role, hash, salt, first, last).run();
    return new Response(JSON.stringify({ ok:true }), { status:201, headers:{'Content-Type':'application/json'} });
  }

  return new Response('Method Not Allowed', { status:405 });
}
