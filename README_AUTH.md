# Email + Password Auth Upgrade

This updates your Cloudflare Pages Functions project to support **email + password** authentication backed by **Cloudflare D1**.

## What's included

- `schema/users.sql` — D1 table for users (email, hash, role, last sign in, IP, created_at).
- `functions/lib/auth.js` — PBKDF2 password hashing + JWT helpers (Workers Web Crypto).
- `functions/api/auth/register.js` — create user with email/password; sets a cookie.
- `functions/api/auth/login.js` — verify credentials; updates last sign-in & IP; sets a cookie.
- `functions/api/auth/me.js` — returns the current user's email/role if the cookie is valid.
- `logintest.html` — now posts to `/api/auth/login`.

## Database schema

```sql
-- D1 schema for users
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT NOT NULL UNIQUE,
  password_algo TEXT NOT NULL DEFAULT 'pbkdf2-sha256',
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',
  last_sign_in  TEXT,
  last_sign_ip  TEXT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Helpful index
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

```

Apply it to your D1 database:

```bash
# Create or open your existing DB binding (example name: POSTS_DB)
# wrangler d1 execute <DB_NAME> --file=./schema/users.sql --remote
```

## Seeding an admin user

Use the **register** endpoint once to create your first admin:

```bash
curl -X POST https://<your-domain>/api/auth/register \
  -H "Content-Type: application/json" \
  --data '{"email":"admin@example.com","password":"ChangeMe!","role":"admin"}'
```

This will set an HttpOnly cookie named `token` on success.

## Checking current user

```bash
curl -i https://<your-domain>/api/auth/me
```

## Protecting endpoints

In your existing API handlers, verify the cookie and assert role:

```js
import { verifyJWT } from '../lib/auth';

export async function onRequest({ request, env }) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(/(?:^|;\s*)token=([^;]+)/);
  const token = m && m[1];
  const user = token && await verifyJWT(token, env.JWT_SECRET);
  if (!user || user.role !== 'admin') return new Response('Unauthorized', { status: 401 });

  // ... protected logic ...
}
```

## Environment

Set `JWT_SECRET` in your Pages project settings. Keep it at least 32 chars.

