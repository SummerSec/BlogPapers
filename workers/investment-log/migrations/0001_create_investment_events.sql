CREATE TABLE IF NOT EXISTS investment_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_key TEXT NOT NULL UNIQUE,
  occurred_at TEXT NOT NULL,
  operation TEXT NOT NULL,
  instrument_code TEXT,
  instrument_name TEXT,
  side TEXT,
  quantity REAL,
  price REAL,
  amount REAL,
  note TEXT,
  source_path TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_investment_events_occurred_at
  ON investment_events (occurred_at DESC);
