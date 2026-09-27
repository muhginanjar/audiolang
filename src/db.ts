import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

export type DB = Database.Database;

export function openDb(file: string): DB {
  if (file !== ':memory:') {
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  }
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  db.pragma('busy_timeout = 5000');
  db.pragma('secure_delete = ON'); // overwrite deleted content on disk

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id              TEXT PRIMARY KEY,
      email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash   TEXT NOT NULL,
      role            TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer','uploader','admin')),
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until    INTEGER,
      created_at      INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS refresh_tokens (
      token_hash  TEXT PRIMARY KEY,
      user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      family_id   TEXT NOT NULL,
      expires_at  INTEGER NOT NULL,
      used_at     INTEGER,
      revoked     INTEGER NOT NULL DEFAULT 0,
      created_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens(family_id);
    CREATE INDEX IF NOT EXISTS idx_rt_user ON refresh_tokens(user_id);

    CREATE TABLE IF NOT EXISTS api_keys (
      id           TEXT PRIMARY KEY,
      user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      key_hash     TEXT NOT NULL UNIQUE,
      prefix       TEXT NOT NULL,
      name         TEXT NOT NULL,
      created_at   INTEGER NOT NULL,
      last_used_at INTEGER,
      revoked      INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_keys_user ON api_keys(user_id);

    CREATE TABLE IF NOT EXISTS files (
      id            TEXT PRIMARY KEY,         -- random, unguessable
      user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      stored_name   TEXT NOT NULL UNIQUE,     -- <id>.<ext> on disk
      original_name TEXT NOT NULL,            -- display only, never used as a path
      mime          TEXT NOT NULL,
      size          INTEGER NOT NULL,
      sha256        TEXT NOT NULL,
      created_at    INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_files_user ON files(user_id);
  `);

  // Additive migrations for databases created by earlier versions
  const hasColumn = (table: string, col: string) =>
    (db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]).some((c) => c.name === col);
  if (!hasColumn('users', 'folders')) {
    // JSON array of folders an uploader may write to, e.g. ["ar","ar_old"]; admins may write anywhere
    db.exec(`ALTER TABLE users ADD COLUMN folders TEXT NOT NULL DEFAULT '[]'`);
  }
  if (!hasColumn('files', 'vpath')) {
    // Public virtual path, e.g. "ar/voice01001.mp3" served at /ar/voice01001.mp3 (NULL = /f/<uuid> only)
    db.exec('ALTER TABLE files ADD COLUMN vpath TEXT');
  }
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_files_vpath ON files(vpath)');

  if (file !== ':memory:') {
    try { fs.chmodSync(file, 0o600); } catch { /* ignore on non-POSIX */ }
  }
  return db;
}
