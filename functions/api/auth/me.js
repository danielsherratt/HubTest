// functions/api/auth/me.js
import { verifyJWT } from '../../lib/auth';

export async function onRequest({ request, env }) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];
  if (!token) return new Response('Unauthorized', { status: 401 });

  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return new Response('Unauthorized', { status: 401 });

  return new Response(JSON.stringify({ email: payload.sub, role: payload.role }), {
    headers: { 'Content-Type': 'application/json' }
  });
}
