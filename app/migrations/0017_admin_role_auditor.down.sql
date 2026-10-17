-- Rebuilding without the auditor role removes auditor accounts, which the old
-- constraint cannot hold, and with them their sessions. `sessions` is rebuilt
-- after the swap for the same reason as in the up migration, so every
-- remaining session survives with a foreign key on the rebuilt `admins`.
CREATE TABLE admins_role_backup (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'root'
    CHECK (role IN ('root', 'admin', 'member', 'ai_agent')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO admins_role_backup (id, email, password_hash, role, created_at, updated_at)
  SELECT id, email, password_hash, role, created_at, updated_at FROM admins
  WHERE role <> 'auditor';

ALTER TABLE admins RENAME TO admins_auditor_role;
ALTER TABLE admins_role_backup RENAME TO admins;

CREATE TABLE sessions_role_backup (
  id TEXT PRIMARY KEY,
  admin_id TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('browser', 'cli')),
  token_hash BLOB NOT NULL UNIQUE,
  csrf_hash BLOB,
  created_at TEXT NOT NULL,
  last_used_at TEXT NOT NULL,
  recent_auth_at TEXT NOT NULL,
  idle_expires_at TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL,
  revoked_at TEXT
);
INSERT INTO sessions_role_backup (id, admin_id, kind, token_hash, csrf_hash, created_at, last_used_at, recent_auth_at, idle_expires_at, absolute_expires_at, revoked_at)
  SELECT id, admin_id, kind, token_hash, csrf_hash, created_at, last_used_at, recent_auth_at, idle_expires_at, absolute_expires_at, revoked_at FROM sessions
  WHERE admin_id IN (SELECT id FROM admins);

DROP TABLE sessions;
ALTER TABLE sessions_role_backup RENAME TO sessions;
DROP TABLE admins_auditor_role;

CREATE UNIQUE INDEX admins_root_idx ON admins(role) WHERE role = 'root';
CREATE INDEX sessions_token_hash_idx ON sessions(token_hash);
CREATE INDEX sessions_revoked_retention_idx ON sessions(revoked_at);
CREATE INDEX sessions_idle_retention_idx ON sessions(idle_expires_at);
CREATE INDEX sessions_absolute_retention_idx ON sessions(absolute_expires_at);
