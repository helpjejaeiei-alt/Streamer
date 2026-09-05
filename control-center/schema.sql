CREATE TABLE IF NOT EXISTS installs (
  token_hash TEXT PRIMARY KEY,
  license_cipher TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  state INTEGER NOT NULL DEFAULT 0,
  download_hash TEXT UNIQUE,
  download_expires INTEGER
);
CREATE INDEX IF NOT EXISTS installs_expiry ON installs(expires_at);
