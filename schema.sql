CREATE TABLE lightning_ids (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  display_name TEXT,
  backend_url TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active'
    CHECK (status IN ('active', 'inactive', 'retired')),
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  lightning_id INTEGER,
  action TEXT NOT NULL,
  old_backend_url TEXT,
  new_backend_url TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lightning_id)
    REFERENCES lightning_ids(id)
    ON DELETE SET NULL
);

CREATE TABLE admin_login_attempts (
  ip_hash TEXT PRIMARY KEY,
  fail_count INTEGER NOT NULL DEFAULT 0,
  window_started_at INTEGER NOT NULL,
  blocked_until INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
  session_id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
