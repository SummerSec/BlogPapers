CREATE TABLE IF NOT EXISTS cash_flow_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  flow_key TEXT NOT NULL UNIQUE,
  occurred_at TEXT NOT NULL,
  account_key TEXT NOT NULL DEFAULT 'all',
  account_name TEXT,
  account_type TEXT,
  direction TEXT NOT NULL,
  category TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT NOT NULL DEFAULT 'CNY',
  source_kind TEXT NOT NULL,
  confidence REAL NOT NULL,
  status TEXT NOT NULL,
  source_path TEXT,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cash_flow_events_date
  ON cash_flow_events (occurred_at DESC, account_key);

CREATE INDEX IF NOT EXISTS idx_cash_flow_events_status
  ON cash_flow_events (status, source_kind, occurred_at DESC);
