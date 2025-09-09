// functions/lib/auth.js
// Utilities for PBKDF2 password hashing and JWT creation/verification using Workers Web Crypto

export async function pbkdf2Hash(password, saltB64, iterations = 100000, keylen = 32) {
  const enc = new TextEncoder();
  const pwKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    pwKey,
    keylen * 8
  );
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

export function randomSalt(bytes = 16) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b));
}

function base64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
}
function encodeUTF8(str){ return new TextEncoder().encode(str); }
function decodeB64Url(str){
  str = str.replace(/-/g,'+').replace(/_/g,'/');
  const pad = 4 - (str.length % 4);
  if (pad !== 4) str += '='.repeat(pad);
  const raw = atob(str);
  return new Uint8Array([...raw].map(ch => ch.charCodeAt(0)));
}

export async function signJWT(payload, secret, maxAgeSec = 60*60*24*7) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now()/1000);
  const body = { iat: now, exp: now + maxAgeSec, ...payload };
  const headerB64 = base64url(encodeUTF8(JSON.stringify(header)));
  const payloadB64 = base64url(encodeUTF8(JSON.stringify(body)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await crypto.subtle.importKey(
    'raw', encodeUTF8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encodeUTF8(data));
  const sigB64 = base64url(sig);
  return `${data}.${sigB64}`;
}

export async function verifyJWT(token, secret) {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) return null;
  const key = await crypto.subtle.importKey(
    'raw', encodeUTF8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify('HMAC', key, decodeB64Url(s), encodeUTF8(`${h}.${p}`));
  if (!valid) return null;
  const payload = JSON.parse(new TextDecoder().decode(decodeB64Url(p)));
  if (payload.exp && Math.floor(Date.now()/1000) > payload.exp) return null;
  return payload;
}
