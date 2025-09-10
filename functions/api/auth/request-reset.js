// functions/api/auth/request-reset.js
import { generateResetToken, sha256Base64Url } from '../../lib/tokens.js';
import { sendEmail } from '../../lib/email.js';

export async function onRequest({ request, env }) {
  if (request.method !== 'POST') return new Response('Method Not Allowed', { status: 405 });
  const db = env.POSTS_DB;

  let email = '';
  try {
    const body = await request.json();
    email = String(body.email || '').trim().toLowerCase();
  } catch {}
  if (!email) {
    // Generic response to avoid enumeration
    return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
  }

  // Try find user; always return ok even if not found
  const user = await db.prepare(`SELECT id, email FROM users WHERE email = ?`).bind(email).first();

  if (user) {
    // create a token valid for 3 hours
    const token = generateResetToken();
    const tokenHash = await sha256Base64Url(token);
    const now = new Date();
    const expires = new Date(now.getTime() + 3 * 60 * 60 * 1000); // 3h

    await db.prepare(`
      INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at)
      VALUES (?, ?, ?, 0, ?)
    `).bind(user.id, tokenHash, expires.toISOString(), now.toISOString()).run();

    // Send email with link
    const origin = new URL(request.url).origin;
    const link = `${origin}/reset.html?token=${encodeURIComponent(token)}`;
    const subject = 'Reset your CESW Hub password';
    const text = `If you requested a password reset, click this link within 3 hours:\n\n${link}\n\nIf you didn’t request this, ignore this email.`;
    const html = `
      <p>If you requested a password reset, click the button below within <b>3 hours</b>.</p>
      <p><a href="${link}" style="display:inline-block;padding:10px 14px;background:#00625f;color:#fff;border-radius:6px;text-decoration:none">Reset Password</a></p>
      <p>Or paste this link in your browser: <br><a href="${link}">${link}</a></p>
      <p>If you didn’t request this, you can ignore this email.</p>
    `;
    try {
      await sendEmail({ env, to: email, subject, html, text });
    } catch (e) {
      // Do not leak email state; still return ok
      console.error('sendEmail failed', e);
    }
  }

  return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
}
