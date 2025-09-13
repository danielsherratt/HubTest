// functions/api/users/[id].js
// Handles: PUT (reset password), DELETE (delete user)
// Notes:
// - Uses D1 binding, preferring env.POSTS_DB
// - Deletes dependent rows first to avoid FK failures
// - Returns clear JSON errors

import { verifyJWT, pbkdf2Hash } from '../../lib/auth.js';
import { passwordPolicyError } from '../../lib/validators.js';

export async function onRequest(ctx) {
  const { request, env, params } = ctx;
  const url = new URL(request.url);
  const idRaw = params.id;
  const method = request.method;

  // CORS/preflight (if you need it)
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  // ---- Auth (admin only) ----
  const token = getTokenFromCookies(request.headers.get('Cookie') || '');
  const me = token ? await verifyJWT(token, env.JWT_SECRET) : null;
  if (!me) return json({ ok: false, error: 'Unauthorized' }, 401);
  if (me.role !== 'admin') return json({ ok: false, error: 'Forbidden' }, 403);

  // ---- Validate id ----
  if (!/^\d+$/.test(String(idRaw))) {
    return json({ ok: false, error: 'Bad user id' }, 400);
  }
  const id = Number(idRaw);

  // ---- DB binding ----
  let db;
  try {
    db = getDB(env);
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }

  try {
    if (method === 'PUT') {
      // Admin reset password
      const body = await safeJson(request);
      const password = String(body.password || '');

      const perr = passwordPolicyError(password);
      if (perr) return json({ ok: false, error: perr }, 400);

      // Use 100k iterations (supported by your worker PBKDF2)
      const salt = new Uint8Array(16);
      crypto.getRandomValues(salt);
      const saltB64 = btoa(String.fromCharCode(...salt));
      const hashB64 = await pbkdf2Hash(password, saltB64, 100000, 32);

      const res = await db.prepare(`
        UPDATE users
           SET password_algo = 'pbkdf2-sha256',
               password_salt = ?,
               password_hash = ?
         WHERE id = ?
      `).bind(saltB64, hashB64, id).run();

      if (res?.success === false) {
        return json({ ok: false, error: 'Failed to update password' }, 500);
      }
      return json({ ok: true });
    }

    if (method === 'DELETE') {
      // Prevent deleting self
      const meRow = await db.prepare(`SELECT email FROM users WHERE id = ?`).bind(id).first();
      if (!meRow) return json({ ok: false, error: 'Not found' }, 404);
      if (String(meRow.email || '') === String(me.sub || '')) {
        return json({ ok: false, error: 'You cannot delete your own account.' }, 400);
      }

      // Best-effort cascade delete dependents
      await db.prepare('PRAGMA foreign_keys = ON').run();

      try {
        const ops = [ db.prepare('BEGIN') ];

        if (await tableExists(db, 'user_sessions')) {
          ops.push(db.prepare('DELETE FROM user_sessions WHERE user_id = ?').bind(id));
        }
        if (await tableExists(db, 'user_signins')) {
          ops.push(db.prepare('DELETE FROM user_signins WHERE user_id = ?').bind(id));
        }
        if (await tableExists(db, 'comments')) {
          ops.push(db.prepare('DELETE FROM comments WHERE user_id = ?').bind(id));
        }
        // If you ever allow users to author posts, you could also remove them here:
        // if (await tableHasColumn(db, 'posts', 'user_id')) {
        //   ops.push(db.prepare('DELETE FROM posts WHERE user_id = ?').bind(id));
        // }

        ops.push(db.prepare('DELETE FROM users WHERE id = ?').bind(id));
        ops.push(db.prepare('COMMIT'));
        await db.batch(ops);
      } catch (e) {
        try { await db.prepare('ROLLBACK').run(); } catch {}
        return json({ ok: false, error: `Delete failed: ${e.message || e}` }, 500);
      }

      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    return json({ ok: false, error: 'Method Not Allowed' }, 405);
  } catch (e) {
    return json({ ok: false, error: e.message || 'Server error' }, 500);
  }
}

/* ---------------- helpers ---------------- */

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json', ...corsHeaders(), ...extraHeaders }
  });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'content-type,authorization,cookie',
  };
}

async function safeJson(request) {
  try { return await request.json(); } catch { return {}; }
}

function getTokenFromCookies(cookie) {
  // accept several cookie names you use elsewhere
  const names = ['token', 'JWT_Token', 'jwt', 'session'];
  for (const n of names) {
    const m = cookie.match(new RegExp(`(?:^|;\\s*)${n}=([^;]+)`));
    if (m) return m[1];
  }
  return null;
}

function getDB(env) {
  // Prefer your known binding name first
  const preferred = ['POSTS_DB', 'DB', 'D1', 'DB_MAIN', 'DATABASE', 'CESW_DB'];
  for (const name of preferred) {
    if (env[name]) {
      const db = env[name];
      if (typeof db.prepare !== 'function') {
        throw new Error(`Binding "${name}" exists but is not a D1 database (missing .prepare). Check Pages → Settings → Functions → D1 bindings.`);
      }
      db.__name = name;
      return db;
    }
  }
  // Fallback scan
  for (const [name, val] of Object.entries(env)) {
    if (val && typeof val.prepare === 'function') { val.__name = name; return val; }
  }
  throw new Error('No D1 database binding found.');
}

async function tableExists(db, name) {
  const row = await db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?").bind(name).first();
  return !!row;
}

async function tableHasColumn(db, table, column) {
  const res = await db.prepare(`PRAGMA table_info(${table})`).all();
  const cols = (res.results || []).map(r => (r.name || '').toString().toLowerCase());
  return cols.includes(column.toLowerCase());
}
