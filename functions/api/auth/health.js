// functions/api/auth/health.js
export async function onRequest({ env }) {
  try {
    const db = env.POSTS_DB;
    if (!db || !db.prepare) {
      return new Response(JSON.stringify({ ok: false, error: 'Missing D1 binding: POSTS_DB' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }

    const t = await db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='users'`).all();
    const userCount = await db.prepare(`SELECT COUNT(*) AS n FROM users`).first();

    return new Response(JSON.stringify({
      ok: true,
      hasUsersTable: !!t.results?.length,
      userCount: userCount?.n ?? 0,
      needsJWT_SECRET: !env.JWT_SECRET
    }), { headers: { 'Content-Type': 'application/json' } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: String(e) }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}
