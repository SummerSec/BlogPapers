const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization,Content-Type',
  'Access-Control-Max-Age': '86400',
};

const JSON_HEADERS = {
  ...CORS_HEADERS,
  'Content-Type': 'application/json; charset=utf-8',
  'X-Content-Type-Options': 'nosniff',
};

const TEXT_LIMITS = {
  event_key: 128,
  occurred_at: 40,
  operation: 40,
  instrument_code: 32,
  instrument_name: 80,
  side: 16,
  note: 240,
  source_path: 160,
  snapshot_date: 10,
  account_key: 64,
  account_name: 80,
  account_type: 24,
  asset_type: 16,
  holding_key: 128,
  captured_at: 40,
};

const TRADE_HISTORY_PATH = '/caishen_fund/pc/account/v1/get_money_history';
const ASSET_TREND_PATH = '/caishen_fund/pc/asset/v1/asset_trend';
const CURRENT_SNAPSHOT_PATHS = new Set([
  '/caishen_fund/pc/asset/v1/stock_position',
  '/caishen_fund/pc/account/v1/stock_card',
  '/caishen_fund/pc/account/v1/init',
]);

const READ_SESSION_TTL_SECONDS = 12 * 60 * 60;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...extraHeaders },
  });
}

function cleanText(value, field) {
  if (value === undefined || value === null) return null;
  const text = String(value).replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return text ? text.slice(0, TEXT_LIMITS[field]) : null;
}

function cleanNumber(value) {
  if (value === undefined || value === null || value === '') return null;
  const number = Number(String(value).replace(/[%,$￥,]/g, ''));
  return Number.isFinite(number) ? number : null;
}

function isValidIsoDate(value) {
  return Boolean(value) && !Number.isNaN(Date.parse(value));
}

function isValidSnapshotDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(value || '') && !Number.isNaN(Date.parse(`${value}T00:00:00Z`));
}

function shanghaiToday() {
  return new Date(Date.now() + 8 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

function previousBusinessDate(value) {
  const date = new Date(`${value}T12:00:00Z`);
  do {
    date.setUTCDate(date.getUTCDate() - 1);
  } while (date.getUTCDay() === 0 || date.getUTCDay() === 6);
  return date.toISOString().slice(0, 10);
}

function currentSnapshotDateForCapture(value) {
  const capturedDate = shanghaiDateFromIso(value);
  const day = new Date(`${capturedDate}T12:00:00Z`).getUTCDay();
  return day === 0 || day === 6 ? previousBusinessDate(capturedDate) : capturedDate;
}

function shanghaiDateFromIso(value) {
  return new Date(Date.parse(value) + 8 * 60 * 60 * 1000).toISOString().slice(0, 10);
}

function shanghaiHourFromIso(value) {
  return new Date(Date.parse(value) + 8 * 60 * 60 * 1000).getUTCHours();
}

function hasConsistentSnapshotDate(record) {
  const capturedDate = shanghaiDateFromIso(record.captured_at);
  if (record.snapshot_date === capturedDate && shanghaiHourFromIso(record.captured_at) < 18) return false;
  if (!CURRENT_SNAPSHOT_PATHS.has(record.source_path)) return true;
  return record.snapshot_date === currentSnapshotDateForCapture(record.captured_at);
}

async function hashValue(value) {
  const bytes = new TextEncoder().encode(String(value));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function textToBase64Url(value) {
  return bytesToBase64Url(new TextEncoder().encode(value));
}

function base64UrlToText(value) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(normalized + padding);
  return new TextDecoder().decode(Uint8Array.from(binary, (character) => character.charCodeAt(0)));
}

async function constantTimeEqual(left, right) {
  const [leftHash, rightHash] = await Promise.all([hashValue(left), hashValue(right)]);
  let difference = 0;
  for (let index = 0; index < leftHash.length; index += 1) {
    difference |= leftHash.charCodeAt(index) ^ rightHash.charCodeAt(index);
  }
  return difference === 0;
}

async function signReadSession(payload, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return bytesToBase64Url(new Uint8Array(signature));
}

async function createReadSession(env) {
  const payload = textToBase64Url(JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + READ_SESSION_TTL_SECONDS,
  }));
  return `${payload}.${await signReadSession(payload, env.SESSION_SECRET)}`;
}

async function isReadAuthorized(request, env) {
  if (!env.SESSION_SECRET) return false;
  const authorization = request.headers.get('Authorization') || '';
  const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : '';
  const parts = token.split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) return false;

  try {
    const expectedSignature = await signReadSession(parts[0], env.SESSION_SECRET);
    if (!(await constantTimeEqual(parts[1], expectedSignature))) return false;
    const payload = JSON.parse(base64UrlToText(parts[0]));
    return Number.isFinite(payload.exp) && payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function login(request, env) {
  if (!env.READ_PASSWORD || !env.SESSION_SECRET) {
    return json({ error: 'read access is not configured' }, 503, { 'Cache-Control': 'no-store' });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid JSON body' }, 400, { 'Cache-Control': 'no-store' });
  }
  const password = typeof body.password === 'string' ? body.password : '';
  if (!password || password.length > 200 || !(await constantTimeEqual(password, env.READ_PASSWORD))) {
    return json({ error: 'invalid password' }, 401, { 'Cache-Control': 'no-store' });
  }

  return json({
    token: await createReadSession(env),
    expires_in: READ_SESSION_TTL_SECONDS,
  }, 200, { 'Cache-Control': 'no-store' });
}

async function normalizeOperation(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const occurredAt = cleanText(input.occurred_at, 'occurred_at');
  const operation = cleanText(input.operation, 'operation');
  if (!operation || !isValidIsoDate(occurredAt)) return null;

  const record = {
    occurred_at: new Date(occurredAt).toISOString(),
    operation,
    account_key: cleanText(input.account_key, 'account_key') || 'all',
    account_name: cleanText(input.account_name, 'account_name'),
    account_type: cleanText(input.account_type, 'account_type'),
    instrument_code: cleanText(input.instrument_code, 'instrument_code'),
    instrument_name: cleanText(input.instrument_name, 'instrument_name'),
    side: cleanText(input.side, 'side'),
    quantity: cleanNumber(input.quantity),
    price: cleanNumber(input.price),
    amount: cleanNumber(input.amount),
    fee: cleanNumber(input.fee),
    note: cleanText(input.note, 'note'),
    source_path: cleanText(input.source_path, 'source_path'),
  };
  const hasTradeDetail = Boolean(record.instrument_code || record.instrument_name
    || record.quantity !== null || record.price !== null || record.amount !== null);
  const isTradeHistory = record.source_path === TRADE_HISTORY_PATH;
  const isInferredFundCashFlow = record.source_path === ASSET_TREND_PATH
    && record.account_type === 'fund'
    && record.amount !== null
    && record.note === '根据相邻交易日总资产变化扣除当日盈亏推算，非平台原始交易流水'
    && (record.operation === '赎回/资金转出（推算）' || record.operation === '申购/资金转入（推算）');
  if ((!isTradeHistory && !isInferredFundCashFlow) || !hasTradeDetail) return null;
  record.event_key = cleanText(input.event_key, 'event_key') || await hashValue(JSON.stringify(record));
  return record;
}

function normalizePortfolioSnapshot(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const snapshotDate = cleanText(input.snapshot_date, 'snapshot_date');
  if (!isValidSnapshotDate(snapshotDate)) return null;
  const capturedAt = cleanText(input.captured_at, 'captured_at');
  const record = {
    snapshot_date: snapshotDate,
    account_key: cleanText(input.account_key, 'account_key') || 'all',
    account_name: cleanText(input.account_name, 'account_name'),
    account_type: cleanText(input.account_type, 'account_type'),
    account_order: cleanNumber(input.account_order),
    total_asset: cleanNumber(input.total_asset),
    market_value: cleanNumber(input.market_value),
    cash: cleanNumber(input.cash),
    day_pnl: cleanNumber(input.day_pnl),
    day_return: cleanNumber(input.day_return),
    total_pnl: cleanNumber(input.total_pnl),
    total_return: cleanNumber(input.total_return),
    source_path: cleanText(input.source_path, 'source_path'),
    captured_at: isValidIsoDate(capturedAt) ? new Date(capturedAt).toISOString() : new Date().toISOString(),
  };
  const hasMetric = ['total_asset', 'market_value', 'cash', 'day_pnl', 'day_return', 'total_pnl', 'total_return']
    .some((field) => record[field] !== null);
  return hasMetric ? record : null;
}

async function normalizeHoldingSnapshot(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  const snapshotDate = cleanText(input.snapshot_date, 'snapshot_date');
  if (!isValidSnapshotDate(snapshotDate)) return null;
  const instrumentCode = cleanText(input.instrument_code, 'instrument_code');
  const instrumentName = cleanText(input.instrument_name, 'instrument_name');
  if (!instrumentCode && !instrumentName) return null;
  const capturedAt = cleanText(input.captured_at, 'captured_at');
  const holdingKey = cleanText(input.holding_key, 'holding_key')
    || (await hashValue(`${instrumentCode || ''}|${instrumentName || ''}`)).slice(0, 32);

  return {
    snapshot_date: snapshotDate,
    account_key: cleanText(input.account_key, 'account_key') || 'all',
    account_name: cleanText(input.account_name, 'account_name'),
    account_type: cleanText(input.account_type, 'account_type'),
    asset_type: cleanText(input.asset_type, 'asset_type') || 'stock',
    holding_key: holdingKey,
    instrument_code: instrumentCode,
    instrument_name: instrumentName,
    quantity: cleanNumber(input.quantity),
    cost_price: cleanNumber(input.cost_price),
    current_price: cleanNumber(input.current_price),
    market_value: cleanNumber(input.market_value),
    pnl: cleanNumber(input.pnl),
    pnl_rate: cleanNumber(input.pnl_rate),
    day_pnl: cleanNumber(input.day_pnl),
    day_pnl_rate: cleanNumber(input.day_pnl_rate),
    total_pnl: cleanNumber(input.total_pnl),
    total_pnl_rate: cleanNumber(input.total_pnl_rate),
    week_pnl: cleanNumber(input.week_pnl),
    month_pnl: cleanNumber(input.month_pnl),
    year_pnl: cleanNumber(input.year_pnl),
    holding_days: cleanNumber(input.holding_days),
    latest_change_rate: cleanNumber(input.latest_change_rate),
    weight: cleanNumber(input.weight),
    source_path: cleanText(input.source_path, 'source_path'),
    captured_at: isValidIsoDate(capturedAt) ? new Date(capturedAt).toISOString() : new Date().toISOString(),
  };
}

function isAuthorized(request, env) {
  if (!env.INGEST_TOKEN) return false;
  return request.headers.get('Authorization') === `Bearer ${env.INGEST_TOKEN}`;
}

async function ingestOperations(request, env) {
  if (!isAuthorized(request, env)) return json({ error: 'unauthorized' }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid JSON body' }, 400);
  }

  const inputs = Array.isArray(body.records) ? body.records : [body];
  if (inputs.length === 0 || inputs.length > 100) {
    return json({ error: 'records must contain between 1 and 100 items' }, 400);
  }
  const normalized = (await Promise.all(inputs.map(normalizeOperation))).filter(Boolean);
  if (normalized.length === 0) return json({ error: 'no valid records' }, 400);

  const statement = env.DB.prepare(`
    INSERT OR IGNORE INTO investment_events (
      event_key, occurred_at, operation, account_key, account_name, account_type,
      instrument_code, instrument_name, side, quantity, price, amount, fee, note, source_path
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const results = await env.DB.batch(normalized.map((record) => statement.bind(
    record.event_key, record.occurred_at, record.operation, record.account_key,
    record.account_name, record.account_type, record.instrument_code,
    record.instrument_name, record.side, record.quantity, record.price, record.amount,
    record.fee, record.note, record.source_path,
  )));
  const inserted = results.reduce((total, result) => total + (result.meta?.changes || 0), 0);
  return json({ accepted: normalized.length, inserted, duplicates: normalized.length - inserted }, 202);
}

async function ingestSnapshots(request, env) {
  if (!isAuthorized(request, env)) return json({ error: 'unauthorized' }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'invalid JSON body' }, 400);
  }

  const portfolioInputs = Array.isArray(body.portfolio_snapshots) ? body.portfolio_snapshots : [];
  const holdingInputs = Array.isArray(body.holdings) ? body.holdings : [];
  if (portfolioInputs.length > 500 || holdingInputs.length > 500) {
    return json({ error: 'snapshot batch is too large' }, 400);
  }

  const settlementCutoff = shanghaiToday();
  const portfolio = portfolioInputs.map(normalizePortfolioSnapshot)
    .filter((record) => record && record.snapshot_date <= settlementCutoff && hasConsistentSnapshotDate(record));
  const holdings = (await Promise.all(holdingInputs.map(normalizeHoldingSnapshot)))
    .filter((record) => record && record.snapshot_date <= settlementCutoff && hasConsistentSnapshotDate(record));
  if (portfolio.length === 0 && holdings.length === 0) {
    return json({ error: 'no valid snapshots' }, 400);
  }

  const portfolioStatement = env.DB.prepare(`
    INSERT INTO portfolio_snapshots (
      snapshot_date, account_key, account_name, account_type, account_order,
      total_asset, market_value, cash, day_pnl, day_return, total_pnl, total_return,
      source_path, captured_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(snapshot_date, account_key) DO UPDATE SET
      account_name = COALESCE(excluded.account_name, account_name),
      account_type = COALESCE(excluded.account_type, account_type),
      account_order = COALESCE(excluded.account_order, account_order),
      total_asset = COALESCE(excluded.total_asset, total_asset),
      market_value = COALESCE(excluded.market_value, market_value),
      cash = COALESCE(excluded.cash, cash),
      day_pnl = COALESCE(excluded.day_pnl, day_pnl),
      day_return = COALESCE(excluded.day_return, day_return),
      total_pnl = COALESCE(excluded.total_pnl, total_pnl),
      total_return = COALESCE(excluded.total_return, total_return),
      source_path = excluded.source_path,
      captured_at = excluded.captured_at
  `);
  const holdingStatement = env.DB.prepare(`
    INSERT INTO holding_snapshots (
      snapshot_date, account_key, account_name, account_type, asset_type, holding_key,
      instrument_code, instrument_name, quantity, cost_price, current_price,
      market_value, pnl, pnl_rate, day_pnl, day_pnl_rate, total_pnl, total_pnl_rate,
      week_pnl, month_pnl, year_pnl, holding_days, latest_change_rate,
      weight, source_path, captured_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(snapshot_date, account_key, asset_type, holding_key) DO UPDATE SET
      account_name = COALESCE(excluded.account_name, account_name),
      account_type = COALESCE(excluded.account_type, account_type),
      instrument_code = COALESCE(excluded.instrument_code, instrument_code),
      instrument_name = COALESCE(excluded.instrument_name, instrument_name),
      quantity = COALESCE(excluded.quantity, quantity),
      cost_price = COALESCE(excluded.cost_price, cost_price),
      current_price = COALESCE(excluded.current_price, current_price),
      market_value = COALESCE(excluded.market_value, market_value),
      pnl = COALESCE(excluded.pnl, pnl),
      pnl_rate = COALESCE(excluded.pnl_rate, pnl_rate),
      day_pnl = COALESCE(excluded.day_pnl, day_pnl),
      day_pnl_rate = COALESCE(excluded.day_pnl_rate, day_pnl_rate),
      total_pnl = COALESCE(excluded.total_pnl, total_pnl),
      total_pnl_rate = COALESCE(excluded.total_pnl_rate, total_pnl_rate),
      week_pnl = COALESCE(excluded.week_pnl, week_pnl),
      month_pnl = COALESCE(excluded.month_pnl, month_pnl),
      year_pnl = COALESCE(excluded.year_pnl, year_pnl),
      holding_days = COALESCE(excluded.holding_days, holding_days),
      latest_change_rate = COALESCE(excluded.latest_change_rate, latest_change_rate),
      weight = COALESCE(excluded.weight, weight),
      source_path = excluded.source_path,
      captured_at = excluded.captured_at
  `);

  const statements = [
    ...portfolio.map((record) => portfolioStatement.bind(
      record.snapshot_date, record.account_key, record.account_name, record.account_type,
      record.account_order, record.total_asset, record.market_value, record.cash, record.day_pnl,
      record.day_return, record.total_pnl, record.total_return, record.source_path,
      record.captured_at,
    )),
    ...holdings.map((record) => holdingStatement.bind(
      record.snapshot_date, record.account_key, record.account_name, record.account_type,
      record.asset_type, record.holding_key, record.instrument_code, record.instrument_name,
      record.quantity, record.cost_price, record.current_price, record.market_value,
      record.pnl, record.pnl_rate, record.day_pnl, record.day_pnl_rate, record.total_pnl,
      record.total_pnl_rate, record.week_pnl, record.month_pnl, record.year_pnl,
      record.holding_days, record.latest_change_rate, record.weight, record.source_path,
      record.captured_at,
    )),
  ];
  await env.DB.batch(statements);
  return json({ portfolio_snapshots: portfolio.length, holdings: holdings.length }, 202);
}

async function listOperations(url, env) {
  const days = Math.min(Math.max(Number.parseInt(url.searchParams.get('days') || '90', 10), 1), 3650);
  const limit = Math.min(Math.max(Number.parseInt(url.searchParams.get('limit') || '1000', 10), 1), 5000);
  const since = new Date(Date.now() - days * 86400000).toISOString();
  const settlementCutoff = previousBusinessDate(shanghaiToday());
  const result = await env.DB.prepare(`
    SELECT occurred_at, operation, account_key, account_name, account_type,
           instrument_code, instrument_name, side, quantity, price, amount, fee, note
    FROM investment_events
    WHERE occurred_at >= ? AND substr(occurred_at, 1, 10) <= ?
    ORDER BY occurred_at DESC, id DESC
    LIMIT ?
  `).bind(since, settlementCutoff, limit).all();
  return json({ generated_at: new Date().toISOString(), operations: result.results || [] }, 200, { 'Cache-Control': 'no-store' });
}

async function getPortfolio(url, env) {
  const days = Math.min(Math.max(Number.parseInt(url.searchParams.get('days') || '365', 10), 1), 3650);
  const since = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  const latestSettledDate = previousBusinessDate(shanghaiToday());
  const requestedDate = url.searchParams.get('date');
  if (requestedDate && !isValidSnapshotDate(requestedDate)) {
    return json({ error: 'date must use YYYY-MM-DD format' }, 400, { 'Cache-Control': 'no-store' });
  }
  if (requestedDate && requestedDate > latestSettledDate) {
    return json({ error: 'date is not settled yet', latest_settled_date: latestSettledDate }, 400, { 'Cache-Control': 'no-store' });
  }
  const selectionCutoff = requestedDate || latestSettledDate;
  const [portfolioResult, latestDateResult, latestHoldingDateResult] = await env.DB.batch([
    env.DB.prepare(`
      SELECT snapshot_date, account_key, account_name, account_type, account_order, total_asset, market_value,
             cash, day_pnl, day_return, total_pnl, total_return, captured_at
      FROM portfolio_snapshots
      WHERE snapshot_date >= ? AND snapshot_date <= ?
        AND strftime('%w', snapshot_date) NOT IN ('0', '6')
      ORDER BY snapshot_date DESC, account_name, account_key
    `).bind(since, selectionCutoff),
    env.DB.prepare(`
      SELECT MAX(snapshot_date) AS latest_date
      FROM portfolio_snapshots
      WHERE snapshot_date <= ? AND strftime('%w', snapshot_date) NOT IN ('0', '6')
    `)
      .bind(selectionCutoff),
    env.DB.prepare(`
      SELECT MAX(snapshot_date) AS latest_date
      FROM holding_snapshots
      WHERE snapshot_date <= ? AND strftime('%w', snapshot_date) NOT IN ('0', '6')
    `).bind(selectionCutoff),
  ]);

  const latestDate = latestDateResult.results?.[0]?.latest_date || null;
  const latestHoldingDate = latestHoldingDateResult.results?.[0]?.latest_date || null;
  const resolvedDate = latestDate || latestHoldingDate || null;
  const operationsStatement = requestedDate && resolvedDate
    ? env.DB.prepare(`
      SELECT occurred_at, operation, account_key, account_name, account_type,
             instrument_code, instrument_name, side, quantity, price, amount, fee, note
      FROM investment_events
      WHERE substr(occurred_at, 1, 10) = ?
      ORDER BY occurred_at DESC, id DESC
      LIMIT 100
    `).bind(resolvedDate)
    : env.DB.prepare(`
      SELECT occurred_at, operation, account_key, account_name, account_type,
             instrument_code, instrument_name, side, quantity, price, amount, fee, note
      FROM investment_events
      WHERE substr(occurred_at, 1, 10) <= ?
      ORDER BY occurred_at DESC, id DESC
      LIMIT 100
    `).bind(selectionCutoff);
  const operationsResult = await operationsStatement.all();

  let holdings = [];
  if (latestHoldingDate) {
    const specificResult = await env.DB.prepare(`
      WITH latest_account_dates AS (
        SELECT account_key, MAX(snapshot_date) AS snapshot_date
        FROM holding_snapshots
        WHERE snapshot_date <= ?
          AND strftime('%w', snapshot_date) NOT IN ('0', '6')
          AND account_key <> 'all'
        GROUP BY account_key
      )
      SELECT h.snapshot_date, h.account_key, h.account_name, h.account_type, h.asset_type,
             h.instrument_code, h.instrument_name, h.quantity, h.cost_price,
             h.current_price, h.market_value, h.pnl, h.pnl_rate, h.day_pnl, h.day_pnl_rate,
             h.total_pnl, h.total_pnl_rate, h.week_pnl, h.month_pnl, h.year_pnl,
             h.holding_days, h.latest_change_rate, h.weight, h.captured_at
      FROM holding_snapshots h
      INNER JOIN latest_account_dates latest
        ON latest.account_key = h.account_key AND latest.snapshot_date = h.snapshot_date
      ORDER BY h.account_name, h.market_value DESC, h.instrument_name, h.instrument_code
    `).bind(selectionCutoff).all();
    holdings = specificResult.results || [];

    if (holdings.length === 0) {
      const aggregateResult = await env.DB.prepare(`
        SELECT snapshot_date, account_key, account_name, account_type, asset_type,
               instrument_code, instrument_name, quantity, cost_price,
               current_price, market_value, pnl, pnl_rate, day_pnl, day_pnl_rate,
               total_pnl, total_pnl_rate, week_pnl, month_pnl, year_pnl,
               holding_days, latest_change_rate, weight, captured_at
        FROM holding_snapshots
        WHERE snapshot_date = ? AND account_key = 'all'
        ORDER BY market_value DESC, instrument_name, instrument_code
      `).bind(latestHoldingDate).all();
      holdings = aggregateResult.results || [];
    }
  }

  return json({
    generated_at: new Date().toISOString(),
    requested_date: requestedDate || null,
    selection_cutoff: selectionCutoff,
    latest_settled_date: latestSettledDate,
    resolved_snapshot_date: resolvedDate,
    latest_snapshot_date: latestDate,
    latest_holding_date: latestHoldingDate,
    portfolio_snapshots: portfolioResult.results || [],
    holdings,
    operations: operationsResult.results || [],
  }, 200, { 'Cache-Control': 'no-store' });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS_HEADERS });
    if (request.method === 'GET' && url.pathname === '/health') {
      return json({ ok: true, service: 'sumsec-investment-log' });
    }
    if (request.method === 'POST' && url.pathname === '/api/login') return login(request, env);
    if (request.method === 'GET' && url.pathname === '/api/operations') {
      if (!(await isReadAuthorized(request, env))) return json({ error: 'unauthorized' }, 401, { 'Cache-Control': 'no-store' });
      return listOperations(url, env);
    }
    if (request.method === 'POST' && url.pathname === '/api/operations') return ingestOperations(request, env);
    if (request.method === 'POST' && url.pathname === '/api/snapshots') return ingestSnapshots(request, env);
    if (request.method === 'GET' && url.pathname === '/api/portfolio') {
      if (!(await isReadAuthorized(request, env))) return json({ error: 'unauthorized' }, 401, { 'Cache-Control': 'no-store' });
      return getPortfolio(url, env);
    }
    return json({ error: 'not found' }, 404);
  },
};
