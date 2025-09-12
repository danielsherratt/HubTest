// functions/lib/me.js
import { verifyJWT } from './auth.js';

export async function getMe(env, request) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];
  if (!token) return null;
  const jwt = await verifyJWT(token, env.JWT_SECRET).catch(() => null);
  if (!jwt?.sub) return null;
  const u = await env.POSTS_DB.prepare(
    'SELECT id, email, role FROM users WHERE email = ?'
  ).bind(jwt.sub).first();
  return u || null;
}
