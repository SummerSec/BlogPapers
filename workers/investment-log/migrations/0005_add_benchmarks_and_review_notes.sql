CREATE TABLE IF NOT EXISTS benchmark_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  benchmark_key TEXT NOT NULL,
  benchmark_name TEXT NOT NULL,
  snapshot_date TEXT NOT NULL,
  close_value REAL NOT NULL,
  captured_at TEXT NOT NULL,
  source_kind TEXT NOT NULL DEFAULT 'platform',
  source_path TEXT,
  UNIQUE(benchmark_key, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_benchmark_snapshots_date
  ON benchmark_snapshots(snapshot_date DESC, benchmark_key);

CREATE TABLE IF NOT EXISTS investment_review_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  note_key TEXT NOT NULL UNIQUE,
  review_date TEXT NOT NULL,
  account_key TEXT NOT NULL DEFAULT 'all',
  account_name TEXT,
  thesis TEXT,
  action TEXT,
  evidence TEXT,
  invalidation TEXT,
  tags TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_investment_review_notes_date
  ON investment_review_notes(review_date DESC, updated_at DESC);
