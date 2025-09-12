// functions/api/auth/logout.js
export async function onRequestPost() {
  const res = new Response(null, { status:204 });
  res.headers.set('Set-Cookie', 'token=; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=0');
  return res;
}
