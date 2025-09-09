// functions/api/users/index.js
import { verifyJWT, pbkdf2Hash } from '../../lib/auth.js';

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;

  // AuthZ: admin only
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];
  const me = token && await verifyJWT(token, env.JWT_SECRET);
  if (!me) return new Response('Unauthorized', { status: 401 });
  if (me.role !== 'admin') return new Response('Forbidden', { status: 403 });

  const method = request.method;

  if (method === 'GET') {
    // Search/sort params
    const url = new URL(request.url);
    const q   = (url.searchParams.get('q') || '').trim().toLowerCase();
    const sort = (url.searchParams.get('sort') || 'created_at').toLowerCase();
    const dir  = (url.searchParams.get('dir') || 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
    const limit = 10;

    const allowedSort = new Set(['email', 'role', 'last_sign_in', 'created_at']);
    const orderCol = allowedSort.has(sort) ? sort : 'created_at';

    let where = '';
    let binds = [];
    if (q) { where = 'WHERE LOWER(email) LIKE ?'; binds.push(`%${q}%`); }

    // Return most recent by chosen sort, plus distinct IPs in last 24h
    const stmt = `
      SELECT
        u.id, u.email, u.role, u.last_sign_in, u.last_sign_ip, u.created_at,
        COALESCE((
          SELECT COUNT(DISTINCT s.ip)
          FROM user_signins s
          WHERE s.user_id = u.id
            AND s.at > datetime('now','-1 day')
        ), 0) AS distinct_ips_24h
      FROM users u
      ${where}
      ORDER BY ${orderCol} ${dir}
      LIMIT ${limit}
    `;

    const { results } = await db.prepare(stmt).bind(...binds).all();
    return new Response(JSON.stringify(results), { headers: { 'Content-Type': 'application/json' } });
  }

  if (method === 'POST') {
    // Create user
    const body = await request.json().catch(() => ({}));
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const role = (String(body.role || 'user').trim().toLowerCase() === 'admin') ? 'admin' : 'user';
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'Email and password are required.' }), {
        status: 400, headers: { 'Content-Type': 'application/json' }
      });
    }

    // salt: 16 bytes
    const salt = new Uint8Array(16); crypto.getRandomValues(salt);
    const saltB64 = btoa(String.fromCharCode(...salt));
    const hashB64 = await pbkdf2Hash(password, saltB64, 100000, 32);

    try {
      await db.prepare(`
        INSERT INTO users (email, password_algo, password_salt, password_hash, role)
        VALUES (?, 'pbkdf2-sha256', ?, ?, ?)
      `).bind(email, saltB64, hashB64, role).run();
    } catch (e) {
      const msg = (e?.message || '').toLowerCase();
      if (msg.includes('unique') || msg.includes('constraint')) {
        return new Response(JSON.stringify({ error: 'Email already exists.' }), {
          status: 409, headers: { 'Content-Type': 'application/json' }
        });
      }
      return new Response(JSON.stringify({ error: 'Failed to create user.' }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
