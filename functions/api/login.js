import { jwt } from '@tsndr/cloudflare-worker-jwt';

export async function onRequestPost({ request, env }) {
  const { user, pass } = await request.json();

  // 1) Validate credentials
  if (user !== env.ADMIN_USER || pass !== env.ADMIN_PASS) {
    return new Response('Unauthorized', { status: 401 });
  }

  // 2) Sign a JWT (expires in 1 hour)
  const token = await jwt.sign({ sub: user }, env.JWT_SECRET, { expiresIn: '1h' });

  // 3) Set HttpOnly, Secure cookie
  const res = new Response(null, { status: 200 });
  res.headers.set(
    'Set-Cookie',
    `token=${token}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=3600`
  );
  return res;
}