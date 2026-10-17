-- Widen the role check so the read-only auditor role can be stored. SQLite
-- cannot alter a CHECK constraint, so the table is rebuilt. With foreign keys
-- enabled a rename rewrites every other table's reference to the renamed
-- name, so `sessions` is rebuilt after the swap: its rows survive and its
-- foreign key points at the rebuilt `admins`.
CREATE TABLE admins_auditor_role (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'root'
    CHECK (role IN ('root', 'admin', 'member', 'auditor', 'ai_agent')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
INSERT INTO admins_auditor_role (id, email, password_hash, role, created_at, updated_at)
  SELECT id, email, password_hash, role, created_at, updated_at FROM admins;

ALTER TABLE admins RENAME TO admins_role_backup;
ALTER TABLE admins_auditor_role RENAME TO admins;

-- Created after the swap: the rename above would rewrite the foreign key of
-- any table that already referenced `admins`.
CREATE TABLE sessions_auditor_role (
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
INSERT INTO sessions_auditor_role (id, admin_id, kind, token_hash, csrf_hash, created_at, last_used_at, recent_auth_at, idle_expires_at, absolute_expires_at, revoked_at)
  SELECT id, admin_id, kind, token_hash, csrf_hash, created_at, last_used_at, recent_auth_at, idle_expires_at, absolute_expires_at, revoked_at FROM sessions;

DROP TABLE sessions;
ALTER TABLE sessions_auditor_role RENAME TO sessions;
DROP TABLE admins_role_backup;

CREATE UNIQUE INDEX admins_root_idx ON admins(role) WHERE role = 'root';
CREATE INDEX sessions_token_hash_idx ON sessions(token_hash);
CREATE INDEX sessions_revoked_retention_idx ON sessions(revoked_at);
CREATE INDEX sessions_idle_retention_idx ON sessions(idle_expires_at);
CREATE INDEX sessions_absolute_retention_idx ON sessions(absolute_expires_at);
