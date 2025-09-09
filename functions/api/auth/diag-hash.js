// functions/api/auth/diag-hash.js
import { pbkdf2Hash } from '../../lib/auth.js';

export async function onRequest() {
  try {
    const password = 'kotakureo';
    const saltB64  = 'IokB0YqD6JUXWhdY7rFOiw=='; // the salt you inserted
    const derived  = await pbkdf2Hash(password, saltB64, 150000, 32);
    return new Response(JSON.stringify({ ok: true, expected: 'NqQzYvFDTUlUQCMu/cRFwRz7/xU9sI8H+Q9YOv3VGnQ=', derived }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: String(e), stack: e?.stack }), { status: 500, headers: { 'Content-Type': 'application/json' } });
  }
}
