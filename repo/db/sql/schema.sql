CREATE TABLE IF NOT EXISTS sessions (
  idx INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL,
  starttime TEXT NOT NULL,
  ip TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_id ON sessions(id);

CREATE TABLE IF NOT EXISTS last_slack_update (
  id INTEGER PRIMARY KEY,
  last_update TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS slack_synced_messages (
  session_id TEXT PRIMARY KEY
);
