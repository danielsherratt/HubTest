// functions/api/auth/login.js

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


export async function onRequestPost({ request, env }) {
  const db = env.POSTS_DB;
  let body = {}
  try { body = await request.json(); } catch { return new Response('Bad JSON', { status:400 }); }
  const { email, password } = body;
  if(!email || !password) return new Response(JSON.stringify({ error:'Email and password required' }), {status:400, headers:{'Content-Type':'application/json'}});

  // Find user
  const row = await db.prepare(`SELECT id, email, role, password_hash, password_salt, first_name, last_name FROM users WHERE email = ?`).bind(email.toLowerCase()).first();
  if(!row) return new Response(JSON.stringify({ error:'Invalid credentials' }), { status:401, headers:{'Content-Type':'application/json'} });

  const hash = await pbkdf2Hash(password, row.password_salt, 100000);
  if (hash !== row.password_hash) return new Response(JSON.stringify({ error:'Invalid credentials' }), { status:401, headers:{'Content-Type':'application/json'} });

  // Update last_sign_in and IP
  const ip = (new URL(request.url)).hostname; // best-effort; in production read CF-Connecting-IP
  await db.prepare(`UPDATE users SET last_sign_in = datetime('now'), last_sign_ip = ? WHERE id = ?`).bind(ip, row.id).run();

  const token = await signJWT({ sub: row.id, role: row.role, email: row.email, first_name: row.first_name, last_name: row.last_name }, env.JWT_SECRET, 172800);

  const res = new Response(JSON.stringify({ ok:true, role: row.role }), { status:200, headers:{'Content-Type':'application/json'} });
  res.headers.set('Set-Cookie', `token=${token}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=172800`);
  return res;
}
