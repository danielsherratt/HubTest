// Cloudflare Pages Functions — Users API
// Routes:
//   GET    /api/users[?with_signin_stats=1&limit=N&__probe=1]
//   POST   /api/users
//   DELETE /api/users/:id[?hard=1]

const COOKIE_NAMES = ['session', 'JWT_Token', 'jwt', 'token']; // accepts common cookie names

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const { pathname, searchParams } = url;
  const method = request.method;

  try {
    // ---- PROBE: quick check route is hitting THIS file ----
    if (method === 'GET' && pathname === '/api/users' && searchParams.get('__probe') === '1') {
      return json({ ok: true, route: 'functions/api/users/index.js' });
    }

    // ---------- GET /api/users ----------
    if (method === 'GET' && pathname === '/api/users') {
      try { await requireAdmin(request, env); }
      catch (e) { return authError(e); }

      const wantStats = searchParams.get('with_signin_stats') === '1';
      const limit = Math.max(1, Math.min(Number(searchParams.get('limit') || 100), 1000));

      // Basic list
      const baseRows = await env.DB.prepare(`
        SELECT
          id,
          email,
          role,
          first_name,
          last_name,
          last_sign_in,
          last_ip AS last_sign_ip,
          created_at
        FROM users
        ORDER BY COALESCE(last_sign_in, created_at) DESC
        LIMIT ?
      `).bind(limit).all();
      const users = baseRows.results || [];

      if (!wantStats) return json(users);

      // If user_signins table doesn't exist, return zeros for stats
      if (!await tableExists(env.DB, 'user_signins')) {
        return json(users.map(u => ({
          ...u,
          signin_count: 0,
          unique_ips: 0,
          signins_7d: 0,
          ips_7d: 0,
          distinct_ips_24h: 0,
        })));
      }

      // For reliability across SQLite versions, compute stats via subqueries
      const out = [];
      for (const u of users) {
        const id = u.id;

        const total = await env.DB.prepare(
          'SELECT COUNT(*) AS c FROM user_signins WHERE user_id = ?'
        ).bind(id).first();

        const uniqAll = await env.DB.prepare(
          'SELECT COUNT(DISTINCT ip) AS c FROM user_signins WHERE user_id = ?'
        ).bind(id).first();

        const total7 = await env.DB.prepare(
          "SELECT COUNT(*) AS c FROM user_signins WHERE user_id = ? AND at >= datetime('now','-7 days')"
        ).bind(id).first();

        const uniq7 = await env.DB.prepare(
          "SELECT COUNT(DISTINCT ip) AS c FROM user_signins WHERE user_id = ? AND at >= datetime('now','-7 days')"
        ).bind(id).first();

        const uniq24 = await env.DB.prepare(
          "SELECT COUNT(DISTINCT ip) AS c FROM user_signins WHERE user_id = ? AND at >= datetime('now','-1 day')"
        ).bind(id).first();

        out.push({
          ...u,
          signin_count: Number(total?.c || 0),
          unique_ips: Number(uniqAll?.c || 0),
          signins_7d: Number(total7?.c || 0),
          ips_7d: Number(uniq7?.c || 0),
          distinct_ips_24h: Number(uniq24?.c || 0),
        });
      }

      return json(out);
    }

    // ---------- POST /api/users ----------
    if (method === 'POST' && pathname === '/api/users') {
      try { await requireAdmin(request, env); }
      catch (e) { return authError(e); }

      const body = await safeJson(request);
      const first_name = (body.first_name || '').trim();
      const last_name  = (body.last_name  || '').trim();
      const email      = (body.email      || '').trim().toLowerCase();
      const role       = (body.role       || 'user').trim();

      if (!first_name || !last_name || !email || !role) {
        return json({ ok:false, error:'Missing required fields' }, 400);
      }

      const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
        .bind(email).first();
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
      try { await requireAdmin(request, env); }
      catch (e) { return authError(e); }

      const id = Number(delMatch[1]);
      if (!Number.isFinite(id)) return json({ ok:false, error:'Bad user id' }, 400);

      const hard = url.searchParams.get('hard') === '1';
      await env.DB.prepare('PRAGMA foreign_keys = ON').run();

      if (!hard) {
        // Soft delete: revoke sessions + mark disabled/deleted_at if columns exist
        try {
          const hasDisabled  = await columnExists(env.DB, 'users', 'disabled');
          const hasDeletedAt = await columnExists(env.DB, 'users', 'deleted_at');
          const ops = [ env.DB.prepare('BEGIN') ];

          if (await tableExists(env.DB, 'user_sessions')) {
            ops.push(env.DB.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(id));
          }

          if (hasDisabled || hasDeletedAt) {
            const sets = [];
            const binds = [];
            if (hasDisabled)  sets.push('disabled = 1');
            if (hasDeletedAt) { sets.push('deleted_at = COALESCE(deleted_at, ?)'); binds.push(new Date().toISOString()); }
            const sql = `UPDATE users SET ${sets.join(', ')} WHERE id = ?`;
            binds.push(id);
            ops.push(env.DB.prepare(sql).bind(...binds));
          }

          ops.push(env.DB.prepare('COMMIT'));
          await env.DB.batch(ops);
        } catch (e) {
          try { await env.DB.prepare('ROLLBACK').run(); } catch {}
          return json({ ok:false, error: e.message || 'Delete failed' }, 500);
        }
        return json({ ok:true, id, soft:true });
      }

      // Hard delete: remove dependents first, then the user
      try {
        const ops = [ env.DB.prepare('BEGIN') ];
        if (await tableExists(env.DB, 'comments'))      ops.push(env.DB.prepare('DELETE FROM comments WHERE user_id = ?').bind(id));
        if (await tableExists(env.DB, 'user_signins'))  ops.push(env.DB.prepare('DELETE FROM user_signins WHERE user_id = ?').bind(id));
        if (await tableExists(env.DB, 'user_sessions')) ops.push(env.DB.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(id));
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
    if (/unauthorized/i.test(err.message)) return json({ ok:false, error:'Unauthorized' }, 401);
    if (/forbidden/i.test(err.message))    return json({ ok:false, error:'Forbidden' }, 403);
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
  const row = await DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?")
                      .bind(name).first();
  return !!row;
}
async function columnExists(DB, table, column) {
  const res = await DB.prepare(`PRAGMA table_info(${table})`).all();
  const cols = (res.results || []).map(r => (r.name || r.cid_name || r.column || '').toString().toLowerCase());
  return cols.includes(column.toLowerCase());
}

/* -------- Admin check that works with JWT or opaque session -------- */
async function requireAdmin(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');

  for (const name of COOKIE_NAMES) {
    const val = cookies[name];
    if (!val) continue;

    // JWT token?
    if (val.includes('.')) {
      const payload = await verifyJWT(val, env.JWT_SECRET);
      if (payload) {
        if (payload.role === 'admin') return payload;
        const uid = Number(payload.sub || payload.user_id || payload.id);
        if (!Number.isFinite(uid)) throw new Error('Unauthorized');
        const row = await env.DB.prepare('SELECT id, role FROM users WHERE id = ?').bind(uid).first();
        if (row && row.role === 'admin') return row;
        throw new Error('Forbidden');
      }
    }

    // Opaque session id via user_sessions
    if (await tableExists(env.DB, 'user_sessions')) {
      let row = await env.DB.prepare(`
        SELECT u.id, u.role
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.session_id = ?
          AND (s.expires_at IS NULL OR s.expires_at > CURRENT_TIMESTAMP)
      `).bind(val).first();

      if (!row) {
        row = await env.DB.prepare(`
          SELECT u.id, u.role
          FROM user_sessions s
          JOIN users u ON u.id = s.user_id
          WHERE s.token = ?
            AND (s.expires_at IS NULL OR s.expires_at > CURRENT_TIMESTAMP)
        `).bind(val).first();
      }

      if (row && row.role === 'admin') return row;
      if (row) throw new Error('Forbidden');
    }
  }

  throw new Error('Unauthorized');
}

function parseCookies(header) {
  const out = {};
  header.split(/; */).forEach(part => {
    if (!part) return;
    const i = part.indexOf('=');
    const k = i === -1 ? part : part.slice(0, i);
    const v = i === -1 ? '' : part.slice(i + 1);
    out[k] = decodeURIComponent(v);
  });
  return out;
}

async function verifyJWT(token, secret) {
  if (!secret) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

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
