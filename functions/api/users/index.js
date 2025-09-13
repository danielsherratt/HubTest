// functions/api/users/index.js
// Cloudflare Pages Functions / Workers style

const COOKIE_NAME = 'session'; // change if your auth cookie is named differently

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method;

  try {
    // ----- GET /api/users -----
    if (method === 'GET' && pathname === '/api/users') {
      await requireAdmin(request, env);

      const rows = await env.DB.prepare(`
        SELECT id, email, role, first_name, last_name, last_sign_in, last_ip, created_at
        FROM users
        ORDER BY COALESCE(last_sign_in, created_at) DESC
      `).all();

      return json(rows.results || []);
    }

    // ----- POST /api/users -----
    if (method === 'POST' && pathname === '/api/users') {
      await requireAdmin(request, env);

      const body = await safeJson(request);
      const first_name = (body.first_name || '').trim();
      const last_name  = (body.last_name  || '').trim();
      const email      = (body.email      || '').trim().toLowerCase();
      const role       = (body.role       || 'user').trim();

      if (!first_name || !last_name || !email || !role) {
        return json({ ok:false, error:'Missing required fields' }, 400);
      }

      const exists = await env.DB.prepare(
        'SELECT id FROM users WHERE email = ?'
      ).bind(email).first();
      if (exists) return json({ ok:false, error:'Email already exists' }, 400);

      const now = new Date().toISOString();
      const res = await env.DB.prepare(`
        INSERT INTO users (first_name, last_name, email, role, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).bind(first_name, last_name, email, role, now).run();

      return json({ ok:true, id: res.lastRowId, first_name, last_name, email, role });
    }

    // ----- DELETE /api/users/:id -----
    const delMatch = pathname.match(/^\/api\/users\/(\d+)$/);
    if (method === 'DELETE' && delMatch) {
      await requireAdmin(request, env);

      const id = Number(delMatch[1]);
      if (!Number.isFinite(id)) return json({ ok:false, error:'Bad user id' }, 400);

      const hard = url.searchParams.get('hard') === '1';

      // Ensure FK enforcement is on (D1/SQLite)
      await env.DB.prepare('PRAGMA foreign_keys = ON').run();

      // SOFT DELETE (default): disable account + revoke sessions
      if (!hard) {
        try {
          await env.DB.batch([
            env.DB.prepare('BEGIN'),
            // Revoke all sessions for this user (adjust table name if needed)
            env.DB.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(id),
            // Mark user disabled; add deleted_at if you have that column
            // If you don't have these columns yet, you can change this to a hard delete
            env.DB.prepare(`
              UPDATE users
              SET disabled = 1,
                  deleted_at = COALESCE(deleted_at, ?)
              WHERE id = ?
            `).bind(new Date().toISOString(), id),
            env.DB.prepare('COMMIT'),
          ]);
        } catch (e) {
          try { await env.DB.prepare('ROLLBACK').run(); } catch {}
          return json({ ok:false, error: e.message || 'Delete failed' }, 500);
        }

        return json({ ok:true, id, soft:true });
      }

      // HARD DELETE (optional via ?hard=1): remove dependents first, then the user.
      try {
        await env.DB.batch([
          env.DB.prepare('BEGIN'),
          // Adjust these table/column names to match your schema.
          env.DB.prepare('DELETE FROM comments      WHERE user_id = ?').bind(id),
          env.DB.prepare('DELETE FROM user_signins  WHERE user_id = ?').bind(id),
          env.DB.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(id),
          env.DB.prepare('DELETE FROM users         WHERE id = ?').bind(id),
          env.DB.prepare('COMMIT'),
        ]);
      } catch (e) {
        try { await env.DB.prepare('ROLLBACK').run(); } catch {}
        return json({ ok:false, error: e.message || 'Delete failed' }, 500);
      }

      return json({ ok:true, id, soft:false });
    }

    return json({ ok:false, error:'Method Not Allowed' }, 405);
  } catch (err) {
    return json({ ok:false, error: err.message || 'Server error' }, 500);
  }
}

/* ---------------- Utilities ---------------- */

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json', ...headers }
  });
}

async function safeJson(request) {
  try { return await request.json(); } catch { return {}; }
}

// --- Minimal admin check using a JWT in cookie "session" (HS256) ---
async function requireAdmin(request, env) {
  const rawCookie = request.headers.get('Cookie') || '';
  const token = getCookie(rawCookie, COOKIE_NAME);
  if (!token) throw new Error('Unauthorized');

  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) throw new Error('Unauthorized');

  // If the token already carries the role:
  if (payload.role === 'admin') return payload;

  // Otherwise look up user by id from payload
  const uid = Number(payload.sub || payload.user_id || payload.id);
  if (!Number.isFinite(uid)) throw new Error('Unauthorized');
  const row = await env.DB.prepare('SELECT id, role FROM users WHERE id = ?').bind(uid).first();
  if (!row || row.role !== 'admin') throw new Error('Forbidden');
  return row;
}

function getCookie(header, name) {
  for (const part of header.split(/; */)) {
    if (!part) continue;
    const i = part.indexOf('=');
    const k = i === -1 ? part : part.slice(0, i);
    if (k === name) return decodeURIComponent(i === -1 ? '' : part.slice(i + 1));
  }
  return null;
}

async function verifyJWT(token, secret) {
  const [h, p, s] = token.split('.');
  if (!h || !p || !s) return null;

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('HMAC', key, base64urlToBytes(s), enc.encode(`${h}.${p}`));
  if (!ok) return null;

  let payload;
  try { payload = JSON.parse(b64urlDecode(p)); } catch { return null; }
  if (payload.exp && Date.now()/1000 > payload.exp) return null;
  return payload;
}

function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4; if (pad) str += '='.repeat(4 - pad);
  return atob(str);
}
function base64urlToBytes(str) {
  const bin = b64urlDecode(str);
  const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}
