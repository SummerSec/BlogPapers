ALTER TABLE portfolio_snapshots ADD COLUMN account_type TEXT;
ALTER TABLE portfolio_snapshots ADD COLUMN account_order INTEGER;
ALTER TABLE portfolio_snapshots ADD COLUMN day_return REAL;

ALTER TABLE holding_snapshots ADD COLUMN account_type TEXT;
ALTER TABLE holding_snapshots ADD COLUMN day_pnl REAL;
ALTER TABLE holding_snapshots ADD COLUMN day_pnl_rate REAL;
ALTER TABLE holding_snapshots ADD COLUMN total_pnl REAL;
ALTER TABLE holding_snapshots ADD COLUMN total_pnl_rate REAL;
ALTER TABLE holding_snapshots ADD COLUMN week_pnl REAL;
ALTER TABLE holding_snapshots ADD COLUMN month_pnl REAL;
ALTER TABLE holding_snapshots ADD COLUMN year_pnl REAL;
ALTER TABLE holding_snapshots ADD COLUMN holding_days INTEGER;
ALTER TABLE holding_snapshots ADD COLUMN latest_change_rate REAL;

ALTER TABLE investment_events ADD COLUMN account_key TEXT NOT NULL DEFAULT 'all';
ALTER TABLE investment_events ADD COLUMN account_name TEXT;
ALTER TABLE investment_events ADD COLUMN account_type TEXT;
ALTER TABLE investment_events ADD COLUMN fee REAL;

CREATE INDEX IF NOT EXISTS idx_investment_events_account
  ON investment_events (account_key, occurred_at DESC);
