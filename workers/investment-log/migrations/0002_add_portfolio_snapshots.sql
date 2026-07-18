CREATE TABLE IF NOT EXISTS portfolio_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_date TEXT NOT NULL,
  account_key TEXT NOT NULL DEFAULT 'all',
  account_name TEXT,
  total_asset REAL,
  market_value REAL,
  cash REAL,
  day_pnl REAL,
  total_pnl REAL,
  total_return REAL,
  source_path TEXT,
  captured_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (snapshot_date, account_key)
);

CREATE INDEX IF NOT EXISTS idx_portfolio_snapshots_date
  ON portfolio_snapshots (snapshot_date DESC);

CREATE TABLE IF NOT EXISTS holding_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  snapshot_date TEXT NOT NULL,
  account_key TEXT NOT NULL DEFAULT 'all',
  account_name TEXT,
  asset_type TEXT NOT NULL DEFAULT 'stock',
  holding_key TEXT NOT NULL,
  instrument_code TEXT,
  instrument_name TEXT,
  quantity REAL,
  cost_price REAL,
  current_price REAL,
  market_value REAL,
  pnl REAL,
  pnl_rate REAL,
  weight REAL,
  source_path TEXT,
  captured_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (snapshot_date, account_key, asset_type, holding_key)
);

CREATE INDEX IF NOT EXISTS idx_holding_snapshots_date
  ON holding_snapshots (snapshot_date DESC, account_key);
