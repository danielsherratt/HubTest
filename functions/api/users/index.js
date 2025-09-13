// Cloudflare Pages Functions / Workers — Users API
// Supports:
//   GET    /api/users[?with_signin_stats=1]
//   POST   /api/users
//   DELETE /api/users/:id[?hard=1]

const COOKIE_NAME = 'session'; // change if your auth cookie name differs

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const { pathname, searchParams } = url;
  const method = request.method;

  try {
    // ---------- GET /api/users ----------
    if (method === 'GET' && pathname === '/api/users') {
      await requireAdmin(request, env);

      const wantStats = searchParams.get('with_signin_stats') === '1';
      const limit = Math.max(1, Math.min(Number(searchParams.get('limit') || 100), 1000));

      if (!wantStats) {
        const rows = await env.DB.prepare(`
          SELECT id, email, role, first_name, last_name, last_sign_in, last_ip, created_at
          FROM users
          ORDER BY COALESCE(last_sign_in, created_at) DESC
          LIMIT ?
        `).bind(limit).all();
        return json(rows.results || []);
      }

      // with_signin_stats=1 → try to include aggregated info from user_signins
      // If the table doesn't exist, we will gracefully fall back.
      const hasSignins = await tableExists(env.DB, 'user_signins');

      if (!hasSignins) {
        const rows = await env.DB.prepare(`
          SELECT id, email, role, first_name, last_name, last_sign_in, last_ip, created_at
          FROM users
          ORDER BY COALESCE(last_sign_in, created_at) DESC
          LIMIT ?
        `).bind(limit).all();

        const out = (rows.results || []).map(r => ({
          ...r,
          signin_count: 0,
          unique_ips: 0,
          ips_7d: 0,
          signins_7d: 0
        }));
        return json(out);
      }

      // Aggregate stats (SQLite/D1)
      // - total signins
      // - unique IPs overall
      // - signins in last 7 days
      // - unique IPs in last 7 days
      const rows = await env.DB.prepare(`
        SELECT
          u.id,
          u.email,
          u.role,
          u.first_name,
          u.last_name,
          u.last_sign_in,
          u.last_ip,
          u.created_at,
          COUNT(s.id) AS signin_count,
          COUNT(DISTINCT s.ip) AS unique_ips,
          SUM(CASE WHEN s.at >= datetime('now','-7 days') THEN 1 ELSE 0 END) AS signins_7d,
          COUNT(DISTINCT CASE WHEN s.at >= datetime('now','-7 days') THEN s.ip END) AS ips_7d
        FROM users u
        LEFT JOIN user_signins s ON s.user_id = u.id
        GROUP BY u.id
        ORDER BY COALESCE(u.last_sign_in, u.created_at) DESC
        LIMIT ?
      `).bind(limit).all();

      return json(rows.results || []);
    }

    // ---------- POST /api/users ----------
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

    // ---------- DELETE /api/users/:id ----------
    const delMatch = pathname.match(/^\/api\/users\/(\d+)$/);
    if (method === 'DELETE' && delMatch) {
      await requireAdmin(request, env);

      const id = Number(delMatch[1]);
      if (!Number.isFinite(id)) return json({ ok:false, error:'Bad user id' }, 400);

      const hard = url.searchParams.get('hard') === '1';

      // Make sure FK enforcement is on (D1/SQLite)
      await env.DB.prepare('PRAGMA foreign_keys = ON').run();

      if (!hard) {
        // SOFT delete: revoke sessions + mark user disabled (and deleted_at if column exists)
        try {
          const hasDisabled = await columnExists(env.DB, 'users', 'disabled');
          const hasDeletedAt = await columnExists(env.DB, 'users', 'deleted_at');

          const updates = [];
          updates.push(env.DB.prepare('BEGIN'));
          updates.push(env.DB.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(id));

          if (hasDisabled || hasDeletedAt) {
            const parts = [];
            const binds = [];
            if (hasDisabled) { parts.push('disabled = 1'); }
            if (hasDeletedAt) { parts.push('deleted_at = COALESCE(deleted_at, ?)'); binds.push(new Date().toISOString()); }
            const sql = `UPDATE users SET ${parts.join(', ')} WHERE id = ?`;
            binds.push(id);
            updates.push(env.DB.prepare(sql).bind(...binds));
          }

          updates.push(env.DB.prepare('COMMIT'));
          await env.DB.batch(updates);
        } catch (e) {
          try { await env.DB.prepare('ROLLBACK').run(); } catch {}
          return json({ ok:false, error: e.message || 'Delete failed' }, 500);
        }
        return json({ ok:true, id, soft:true });
      }

      // HARD delete: remove dependents first, then the user
      try {
        const ops = [env.DB.prepare('BEGIN')];

        // conditionally delete from tables if they exist, to avoid "no such table" 500s
        if (await tableExists(env.DB, 'comments')) {
          ops.push(env.DB.prepare('DELETE FROM comments WHERE user_id = ?').bind(id));
        }
        if (await tableExists(env.DB, 'user_signins')) {
          ops.push(env.DB.prepare('DELETE FROM user_signins WHERE user_id = ?').bind(id));
        }
        if (await tableExists(env.DB, 'user_sessions')) {
          ops.push(env.DB.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(id));
        }

        ops.push(env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id));
        ops.push(env.DB.prepare('COMMIT'));
        await env.DB.batch(ops);
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

async function tableExists(DB, name) {
  const row = await DB.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name = ?"
  ).bind(name).first();
  return !!row;
}

async function columnExists(DB, table, column) {
  const res = await DB.prepare(`PRAGMA table_info(${table})`).all();
  const cols = (res.results || []).map(r => (r.name || r.cid_name || r.column || '').toString().toLowerCase());
  return cols.includes(column.toLowerCase());
}

// --- Minimal admin check using a JWT in cookie "session" (HS256) ---
async function requireAdmin(request, env) {
  const rawCookie = request.headers.get('Cookie') || '';
  const token = getCookie(rawCookie, COOKIE_NAME);
  if (!token) throw new Error('Unauthorized');

  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) throw new Error('Unauthorized');

  if (payload.role === 'admin') return payload;

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
