// functions/api/users/index.js
import { verifyJWT, pbkdf2Hash } from '../../lib/auth.js';
import { generateResetToken, sha256Base64Url } from '../../lib/tokens.js';
import { sendEmail } from '../../lib/email.js';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function getTokenFromCookie(request) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  return m && m[1];
}

export async function onRequest({ request, env }) {
  const db = env.POSTS_DB;
  if (!db || !db.prepare) return json({ error: 'Database not configured (POSTS_DB).' }, 500);
  if (!env.JWT_SECRET) return json({ error: 'JWT secret not configured.' }, 500);

  // Admin auth
  const token = getTokenFromCookie(request);
  const me = token && await verifyJWT(token, env.JWT_SECRET);
  if (!me) return new Response('Unauthorized', { status: 401 });
  if (me.role !== 'admin') return new Response('Forbidden', { status: 403 });

  const { method } = request;

  // ───────────────────────────────── GET /api/users ─────────────────────────────────
  if (method === 'GET') {
    const url = new URL(request.url);
    const q   = (url.searchParams.get('q') || '').trim().toLowerCase();
    const sortParam = (url.searchParams.get('sort') || 'created_at').toLowerCase();
    const dirParam  = (url.searchParams.get('dir')  || 'desc').toLowerCase();
    const dir = dirParam === 'asc' ? 'ASC' : 'DESC';

    // Allowlist to avoid SQL injection in ORDER BY
    const allowedSort = new Set(['email', 'role', 'last_sign_in', 'created_at']);
    const orderCol = allowedSort.has(sortParam) ? sortParam : 'created_at';

    let where = '';
    let binds = [];
    if (q) { where = 'WHERE LOWER(u.email) LIKE ?'; binds.push(`%${q}%`); }

    // Note: requires optional table user_signins for distinct IPs metric (safe if absent -> 0 via COALESCE with subquery guarded)
    const stmt = `
      SELECT
        u.id,
        u.email,
        u.role,
        u.last_sign_in,
        u.last_sign_ip,
        u.created_at,
        COALESCE((
          SELECT COUNT(DISTINCT s.ip)
          FROM user_signins s
          WHERE s.user_id = u.id
            AND s.at > datetime('now','-1 day')
        ), 0) AS distinct_ips_24h
      FROM users u
      ${where}
      ORDER BY ${orderCol} ${dir}
      LIMIT 10
    `;

    const { results } = await db.prepare(stmt).bind(...binds).all();
    return json(results || []);
  }

  // ───────────────────────────────── POST /api/users ────────────────────────────────
  // Create user, email temp password + 3h reset link
  if (method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const email = String(body.email || '').trim().toLowerCase();
    let password = String(body.password || ''); // if not provided, we will generate one
    const role = (String(body.role || 'user').trim().toLowerCase() === 'admin') ? 'admin' : 'user';

    if (!email) return json({ error: 'Email is required.' }, 400);

    // Generate a strong temp password if none provided
    if (!password) {
      const bytes = new Uint8Array(12);
      crypto.getRandomValues(bytes);
      const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      password = Array.from(bytes, b => alphabet[b % alphabet.length]).join('');
    }

    // Hash password (PBKDF2-SHA256 @ 100k, 32 bytes)
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
        return json({ error: 'Email already exists.' }, 409);
      }
      return json({ error: 'Failed to create user.' }, 500);
    }

    // Create a 3-hour password reset token and email user
    try {
      const userRow = await db.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
      if (userRow?.id) {
        const token = generateResetToken();
        const tokenHash = await sha256Base64Url(token);
        const now = new Date();
        const expires = new Date(now.getTime() + 3 * 60 * 60 * 1000); // 3 hours

        // Optional: invalidate previous unused tokens for this user (uncomment if desired)
        // await db.prepare(`UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0`).bind(userRow.id).run();

        await db.prepare(`
          INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at)
          VALUES (?, ?, ?, 0, ?)
        `).bind(userRow.id, tokenHash, expires.toISOString(), now.toISOString()).run();

        const origin = new URL(request.url).origin;
        const link = `${origin}/reset.html?token=${encodeURIComponent(token)}`;

        const subject = 'Welcome to CESW Hub';
        const text = `Welcome to CESW Hub.

Your temporary password is: ${password}

Please set your own password within 3 hours using this link:
${link}

If you didn’t expect this, you can ignore the email.`;
        const html = `
          <p>Welcome to CESW Hub.</p>
          <p>Your temporary password is: <code>${password}</code></p>
          <p>Please reset your password within <b>3 hours</b> using the link below:</p>
          <p><a href="${link}" style="display:inline-block;padding:10px 14px;background:#00625f;color:#fff;border-radius:6px;text-decoration:none">Set a new password</a></p>
          <p>If the button doesn't work, paste this link:<br><a href="${link}">${link}</a></p>
        `;

        // Will use RESEND_API_KEY / FROM_EMAIL if configured; otherwise logs as mock
        await sendEmail({ env, to: email, subject, html, text });
      }
    } catch (e) {
      // Don't fail user creation if email fails; just log
      console.error('Create user: email/reset link creation failed', e);
    }

    return json({ ok: true });
  }

  return new Response('Method Not Allowed', { status: 405 });
}
