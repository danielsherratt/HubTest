// functions/lib/email.js
export async function sendEmail({ env, to, subject, html, text }) {
  const key = env.RESEND_API_KEY;
  const from = env.FROM_EMAIL || 'no-reply@example.com';
  if (!key) {
    // Fallback: log instead of failing hard
    console.log('[EMAIL MOCK]', { to, subject, text, html });
    return { ok: true, mock: true };
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${key}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ from, to, subject, html, text })
  });
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`Email send failed: ${t}`);
  }
  return res.json();
}
