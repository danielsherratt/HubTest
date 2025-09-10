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
  // Always return ok to avoid user enumeration
  if (!email) return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });

  const user = await db.prepare(`SELECT id, email FROM users WHERE email = ?`).bind(email).first();
  if (user) {
    const token = generateResetToken();
    const tokenHash = await sha256Base64Url(token);
    const now = new Date();
    const expires = new Date(now.getTime() + 3 * 60 * 60 * 1000); // 3h

    // optional: invalidate previous tokens
    // await db.prepare(`UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0`).bind(user.id).run();

    await db.prepare(`
      INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at)
      VALUES (?, ?, ?, 0, ?)
    `).bind(user.id, tokenHash, expires.toISOString(), now.toISOString()).run();

    const origin = new URL(request.url).origin;
    const link = `${origin}/reset.html?token=${encodeURIComponent(token)}`;
    const subject = 'Reset your CESW Hub password';
    const text = `CESW Hub Password Reset. If you requested a password reset, use this link within 3 hours:\n\n${link}\n\nOtherwise, ignore this email.`;
    const html = `
    <h1>CESW Hub Password Reset</h1>  
    <p>If you requested a password reset, click the button below within</p>
      <p><a href="${link}" style="display:inline-block;padding:10px 14px;background:#00625f;color:#fff;border-radius:6px;text-decoration:none">Reset Password</a></p>
      <p>Note the link will expire in 3 hours</p>
      <p>If this wasn't you, ignore this email.</p>
      <br>
      <p>Contact <a href="mailto:ITSupport@kotakureo.school.nz">ITSupport@kotakureo.school.nz</a> for assistance if required</p>
    `;
    try { await sendEmail({ env, to: email, subject, html, text }); }
    catch (e) { console.error('sendEmail failed', e); /* still return ok */ }
  }

  return new Response(JSON.stringify({ ok: true }), { headers: { 'Content-Type': 'application/json' } });
}
