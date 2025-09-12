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
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  lockout_until  TEXT,
  created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Helpful index
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);


-- Track failed login attempts
CREATE TABLE IF NOT EXISTS login_attempts (
  email TEXT PRIMARY KEY,
  fails INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT
);
