CREATE TABLE IF NOT EXISTS control_sessions(token_hash TEXT PRIMARY KEY, license_id TEXT NOT NULL, license_cipher TEXT NOT NULL, kind TEXT NOT NULL, expires INTEGER NOT NULL, checked INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS control_settings(license_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, config TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS control_devices(token_hash TEXT PRIMARY KEY, license_id TEXT NOT NULL, seen INTEGER NOT NULL, applied INTEGER NOT NULL, actual TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS control_devices_license ON control_devices(license_id);
CREATE TABLE IF NOT EXISTS control_limits(id TEXT PRIMARY KEY, count INTEGER NOT NULL, expires INTEGER NOT NULL);
