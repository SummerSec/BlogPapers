---
layout: default
title: 投资复盘
comments: false
---

<div class="investment-ledger" id="investment-ledger">
  <header class="investment-ledger__header">
    <p class="investment-ledger__eyebrow">PORTFOLIO LEDGER / LIVE</p>
    <h1>投资复盘</h1>
    <p>账户、持仓与交易记录由本地投资账本同步至 Cloudflare D1。</p>
    <div class="investment-ledger__status" id="investment-status" role="status">正在读取最新数据...</div>
  </header>

  <section class="investment-ledger__section" id="investment-overview" hidden>
    <div class="investment-metrics" id="investment-metrics"></div>
  </section>

  <section class="investment-ledger__section" id="investment-accounts-section" hidden>
    <div class="investment-ledger__section-head">
      <h2>分类账户</h2>
      <span id="investment-account-date"></span>
    </div>
    <div class="investment-account-tabs" id="investment-account-tabs" role="tablist" aria-label="投资账户"></div>
    <div class="investment-table-wrap">
      <table class="investment-table investment-table--accounts">
        <thead>
          <tr><th>账户</th><th>总资产</th><th>持有盈亏</th><th>持有盈亏率</th><th>当日盈亏</th><th>当日盈亏率</th><th>持仓市值</th><th>现金</th></tr>
        </thead>
        <tbody id="investment-accounts"></tbody>
      </table>
    </div>
  </section>

  <section class="investment-ledger__section" id="investment-detail-section" hidden>
    <div class="investment-view-tabs" role="tablist" aria-label="投资明细">
      <button type="button" class="is-active" data-view="holdings" role="tab" aria-selected="true">持仓列表</button>
      <button type="button" data-view="trades" role="tab" aria-selected="false">交易记录</button>
    </div>

    <div id="investment-holdings-panel" role="tabpanel">
      <div class="investment-ledger__section-head investment-ledger__section-head--compact">
        <h2 id="investment-holdings-title">汇总持仓</h2>
        <span id="investment-holding-count"></span>
      </div>
      <div class="investment-table-wrap">
        <table class="investment-table investment-table--holdings">
          <thead>
            <tr>
              <th>账户</th><th>代码</th><th>名称</th><th>持有盈亏率</th><th>持有金额</th>
              <th>当日盈亏</th><th>当日盈亏率</th><th>持有盈亏</th><th>累计盈亏</th>
              <th>本周盈亏</th><th>本月盈亏</th><th>今年盈亏</th><th>仓位占比</th>
              <th>持有数量</th><th>持仓天数</th><th>最新价</th><th>单位成本</th>
            </tr>
          </thead>
          <tbody id="investment-holdings"></tbody>
        </table>
      </div>
      <p class="investment-empty" id="investment-holdings-empty" hidden>当前账户尚未同步持仓明细。</p>
    </div>

    <div id="investment-trades-panel" role="tabpanel" hidden>
      <div class="investment-ledger__section-head investment-ledger__section-head--compact">
        <h2 id="investment-trades-title">交易记录</h2>
        <span id="investment-trade-count"></span>
      </div>
      <div class="investment-table-wrap">
        <table class="investment-table investment-table--trades">
          <thead>
            <tr><th>日期</th><th>账户</th><th>类型</th><th>代码</th><th>名称</th><th>成交价格</th><th>成交数量</th><th>成交金额</th><th>交易费用</th><th>备注</th></tr>
          </thead>
          <tbody id="investment-trades"></tbody>
        </table>
      </div>
      <p class="investment-empty" id="investment-trades-empty" hidden>当前账户尚未同步交易记录。</p>
    </div>
  </section>

  <details class="investment-ledger__history" id="investment-history-section" hidden>
    <summary>历史资产快照</summary>
    <div class="investment-table-wrap">
      <table class="investment-table investment-table--history">
        <thead><tr><th>日期</th><th>账户</th><th>总资产</th><th>持有盈亏</th><th>收益率</th><th>当日盈亏</th><th>当日收益率</th></tr></thead>
        <tbody id="investment-history"></tbody>
      </table>
    </div>
  </details>

  <p class="investment-ledger__disclaimer">公开数据仅用于个人记录，不构成任何投资建议。</p>
</div>

<style>
.investment-ledger { max-width: var(--wide-max); margin: 0 auto; }
.investment-ledger__header { padding: 1rem 0 1.5rem; border-bottom: 1px solid var(--border-strong); }
.investment-ledger__header h1 { margin: .25rem 0 .5rem; font-size: 2rem; letter-spacing: 0; }
.investment-ledger__header > p:not(.investment-ledger__eyebrow) { margin: 0; color: var(--text-muted); }
.investment-ledger__eyebrow { margin: 0; color: var(--color-signal); font: 700 .76rem/1.4 var(--font-code); }
.investment-ledger__status { margin-top: 1rem; color: var(--text-muted); font-family: var(--font-code); }
.investment-ledger__status.is-error { color: var(--color-amber); }
.investment-ledger__section { margin-top: 2rem; }
.investment-ledger__section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: .75rem; }
.investment-ledger__section-head--compact { margin-top: 1.25rem; }
.investment-ledger__section-head h2 { margin: 0; font-size: 1.15rem; letter-spacing: 0; }
.investment-ledger__section-head span { color: var(--text-muted); font: .8rem/1.4 var(--font-code); }
.investment-metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid var(--border-strong); border-radius: 6px; overflow: hidden; }
.investment-metric { min-width: 0; padding: 1rem; border-right: 1px solid var(--border-strong); }
.investment-metric:last-child { border-right: 0; }
.investment-metric span { display: block; color: var(--text-muted); font-size: .78rem; }
.investment-metric strong { display: block; margin-top: .35rem; font: 650 1.2rem/1.2 var(--font-code); overflow-wrap: anywhere; }
.investment-account-tabs, .investment-view-tabs { display: flex; align-items: center; gap: 0; overflow-x: auto; border-bottom: 1px solid var(--border-strong); }
.investment-account-tabs { margin-bottom: 1rem; }
.investment-account-tabs button, .investment-view-tabs button { flex: 0 0 auto; min-height: 38px; padding: .55rem .9rem; border: 0; border-bottom: 2px solid transparent; border-radius: 0; background: transparent; color: var(--text-muted); font: 600 .88rem/1 var(--font-body); cursor: pointer; }
.investment-account-tabs button:hover, .investment-view-tabs button:hover { color: var(--text-main); }
.investment-account-tabs button.is-active, .investment-view-tabs button.is-active { color: var(--color-signal); border-bottom-color: var(--color-signal); }
.investment-table-wrap { overflow-x: auto; border: 1px solid var(--border-strong); border-radius: 6px; }
.investment-table { width: 100%; margin: 0; font-size: .84rem; }
.investment-table th, .investment-table td { white-space: nowrap; text-align: right; }
.investment-table th:first-child, .investment-table td:first-child { padding-left: .75rem; }
.investment-table--accounts { min-width: 900px; }
.investment-table--holdings { min-width: 1900px; }
.investment-table--trades { min-width: 1120px; }
.investment-table--history { min-width: 850px; }
.investment-table--holdings th:nth-child(-n+3), .investment-table--holdings td:nth-child(-n+3),
.investment-table--trades th:nth-child(-n+5), .investment-table--trades td:nth-child(-n+5),
.investment-table--accounts th:first-child, .investment-table--accounts td:first-child,
.investment-table--history th:nth-child(-n+2), .investment-table--history td:nth-child(-n+2) { text-align: left; }
.investment-ledger .is-positive { color: #d84b57; }
.investment-ledger .is-negative { color: #268a63; }
.investment-empty { margin: .9rem 0 0; color: var(--text-muted); }
.investment-ledger__history { margin-top: 2rem; border-top: 1px solid var(--border-strong); padding-top: 1rem; }
.investment-ledger__history summary { margin-bottom: .75rem; cursor: pointer; font-weight: 650; }
.investment-ledger__disclaimer { margin-top: 2rem; color: var(--text-dim); font-size: .82rem; }
@media (max-width: 760px) {
  .investment-ledger__header h1 { font-size: 1.65rem; }
  .investment-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .investment-metric { border-bottom: 1px solid var(--border-strong); }
  .investment-metric:nth-child(2) { border-right: 0; }
  .investment-metric:nth-child(n+3) { border-bottom: 0; }
  .investment-ledger__section-head { align-items: flex-start; flex-direction: column; gap: .25rem; }
}
</style>

<script>
(function () {
  var endpoint = 'https://sumsec-investment-log.sumsec.workers.dev/api/portfolio?days=3650';
  var status = document.getElementById('investment-status');
  var state = { data: null, accounts: [], selectedAccount: 'all', selectedView: 'holdings' };

  function escapeHtml(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  function number(value) {
    var parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  function formatNumber(value, digits) {
    var parsed = number(value);
    if (parsed === null) return '-';
    return parsed.toLocaleString('zh-CN', { minimumFractionDigits: digits, maximumFractionDigits: digits });
  }

  function formatMoney(value) { return formatNumber(value, 2); }
  function formatQuantity(value) { return formatNumber(value, 2); }
  function formatRate(value) {
    var parsed = number(value);
    return parsed === null ? '-' : (parsed > 0 ? '+' : '') + formatNumber(parsed, 2) + '%';
  }
  function formatSigned(value) {
    var parsed = number(value);
    return parsed === null ? '-' : (parsed > 0 ? '+' : '') + formatMoney(parsed);
  }
  function valueClass(value) {
    var parsed = number(value);
    return parsed === null || parsed === 0 ? '' : (parsed > 0 ? 'is-positive' : 'is-negative');
  }
  function cell(value, formatter) {
    return '<td class="' + valueClass(value) + '">' + formatter(value) + '</td>';
  }
  function sum(items, field) {
    var found = false;
    var total = items.reduce(function (result, item) {
      var value = number(item[field]);
      if (value !== null) { found = true; return result + value; }
      return result;
    }, 0);
    return found ? total : null;
  }

  function latestAccounts(data) {
    var snapshots = Array.isArray(data.portfolio_snapshots) ? data.portfolio_snapshots : [];
    var latest = snapshots.reduce(function (date, item) { return item.snapshot_date > date ? item.snapshot_date : date; }, '');
    var rows = snapshots.filter(function (item) { return item.snapshot_date === latest; });
    var specific = rows.filter(function (item) { return item.account_key !== 'all'; });
    if (specific.length) rows = specific;
    return rows.sort(function (a, b) {
      var ao = number(a.account_order); var bo = number(b.account_order);
      if (ao !== null || bo !== null) return (ao === null ? 999 : ao) - (bo === null ? 999 : bo);
      return String(a.account_name || '').localeCompare(String(b.account_name || ''), 'zh-CN');
    });
  }

  function accountLabel(key) {
    if (key === 'all') return '汇总持仓';
    var account = state.accounts.find(function (item) { return item.account_key === key; });
    return account ? (account.account_name || '未命名账户') : '未命名账户';
  }

  function selectedHoldings() {
    var holdings = Array.isArray(state.data.holdings) ? state.data.holdings : [];
    if (state.selectedAccount !== 'all') return holdings.filter(function (item) { return item.account_key === state.selectedAccount; });
    var aggregate = holdings.filter(function (item) { return item.account_key === 'all'; });
    return aggregate.length ? aggregate : holdings.filter(function (item) { return item.account_key !== 'all'; });
  }

  function selectedTrades() {
    var trades = Array.isArray(state.data.operations) ? state.data.operations : [];
    return state.selectedAccount === 'all' ? trades : trades.filter(function (item) { return item.account_key === state.selectedAccount; });
  }

  function renderMetrics() {
    var holdings = selectedHoldings();
    var totalAsset = sum(state.accounts, 'total_asset');
    var totalPnl = sum(state.accounts, 'total_pnl');
    var dayPnl = sum(state.accounts, 'day_pnl');
    var metrics = [
      ['账户总资产', formatMoney(totalAsset), ''],
      ['持有盈亏', formatSigned(totalPnl), valueClass(totalPnl)],
      ['当日盈亏', formatSigned(dayPnl), valueClass(dayPnl)],
      ['当前持仓', holdings.length + ' 项', ''],
    ];
    document.getElementById('investment-metrics').innerHTML = metrics.map(function (item) {
      return '<div class="investment-metric"><span>' + item[0] + '</span><strong class="' + item[2] + '">' + item[1] + '</strong></div>';
    }).join('');
    document.getElementById('investment-overview').hidden = false;
  }

  function renderAccountTabs() {
    var tabs = [{ account_key: 'all', account_name: '汇总持仓' }].concat(state.accounts);
    document.getElementById('investment-account-tabs').innerHTML = tabs.map(function (item) {
      var active = item.account_key === state.selectedAccount;
      return '<button type="button" role="tab" data-account="' + escapeHtml(item.account_key) + '" class="' + (active ? 'is-active' : '') + '" aria-selected="' + active + '">' + escapeHtml(item.account_name || '未命名账户') + '</button>';
    }).join('');
  }

  function renderAccounts() {
    var body = document.getElementById('investment-accounts');
    body.innerHTML = state.accounts.map(function (item) {
      return '<tr><td>' + escapeHtml(item.account_name || '未命名账户') + '</td>'
        + '<td>' + formatMoney(item.total_asset) + '</td>'
        + cell(item.total_pnl, formatSigned) + cell(item.total_return, formatRate)
        + cell(item.day_pnl, formatSigned) + cell(item.day_return, formatRate)
        + '<td>' + formatMoney(item.market_value) + '</td><td>' + formatMoney(item.cash) + '</td></tr>';
    }).join('');
    document.getElementById('investment-account-date').textContent = state.accounts[0] ? state.accounts[0].snapshot_date : '';
    document.getElementById('investment-accounts-section').hidden = false;
  }

  function renderHoldings() {
    var rows = selectedHoldings().slice().sort(function (a, b) { return (number(b.market_value) || 0) - (number(a.market_value) || 0); });
    document.getElementById('investment-holdings-title').textContent = accountLabel(state.selectedAccount);
    document.getElementById('investment-holding-count').textContent = rows.length + ' 项持仓';
    document.getElementById('investment-holdings').innerHTML = rows.map(function (item) {
      return '<tr><td>' + escapeHtml(item.account_name || accountLabel(item.account_key)) + '</td>'
        + '<td>' + escapeHtml(item.instrument_code || '-') + '</td><td>' + escapeHtml(item.instrument_name || '-') + '</td>'
        + cell(item.pnl_rate, formatRate) + '<td>' + formatMoney(item.market_value) + '</td>'
        + cell(item.day_pnl, formatSigned) + cell(item.day_pnl_rate, formatRate)
        + cell(item.pnl, formatSigned) + cell(item.total_pnl, formatSigned)
        + cell(item.week_pnl, formatSigned) + cell(item.month_pnl, formatSigned) + cell(item.year_pnl, formatSigned)
        + '<td>' + formatRate(item.weight) + '</td><td>' + formatQuantity(item.quantity) + '</td>'
        + '<td>' + (number(item.holding_days) === null ? '-' : formatNumber(item.holding_days, 0) + '天') + '</td>'
        + '<td>' + formatNumber(item.current_price, 4) + '</td><td>' + formatNumber(item.cost_price, 4) + '</td></tr>';
    }).join('');
    document.getElementById('investment-holdings-empty').hidden = rows.length > 0;
  }

  function renderTrades() {
    var rows = selectedTrades();
    document.getElementById('investment-trades-title').textContent = accountLabel(state.selectedAccount) + '交易记录';
    document.getElementById('investment-trade-count').textContent = rows.length + ' 条';
    document.getElementById('investment-trades').innerHTML = rows.map(function (item) {
      var date = item.occurred_at ? String(item.occurred_at).slice(0, 10) : '-';
      return '<tr><td>' + date + '</td><td>' + escapeHtml(item.account_name || accountLabel(item.account_key)) + '</td>'
        + '<td>' + escapeHtml(item.operation || item.side || '-') + '</td><td>' + escapeHtml(item.instrument_code || '-') + '</td>'
        + '<td>' + escapeHtml(item.instrument_name || '-') + '</td><td>' + formatNumber(item.price, 4) + '</td>'
        + '<td>' + formatQuantity(item.quantity) + '</td><td>' + formatMoney(item.amount) + '</td>'
        + '<td>' + formatMoney(item.fee) + '</td><td>' + escapeHtml(item.note || '-') + '</td></tr>';
    }).join('');
    document.getElementById('investment-trades-empty').hidden = rows.length > 0;
  }

  function renderHistory() {
    var snapshots = Array.isArray(state.data.portfolio_snapshots) ? state.data.portfolio_snapshots : [];
    var specific = snapshots.some(function (item) { return item.account_key !== 'all'; });
    if (specific) snapshots = snapshots.filter(function (item) { return item.account_key !== 'all'; });
    document.getElementById('investment-history').innerHTML = snapshots.map(function (item) {
      return '<tr><td>' + escapeHtml(item.snapshot_date) + '</td><td>' + escapeHtml(item.account_name || accountLabel(item.account_key)) + '</td>'
        + '<td>' + formatMoney(item.total_asset) + '</td>' + cell(item.total_pnl, formatSigned)
        + cell(item.total_return, formatRate) + cell(item.day_pnl, formatSigned) + cell(item.day_return, formatRate) + '</tr>';
    }).join('');
    document.getElementById('investment-history-section').hidden = snapshots.length === 0;
  }

  function renderDetail() {
    renderMetrics(); renderAccountTabs(); renderHoldings(); renderTrades();
    document.getElementById('investment-holdings-panel').hidden = state.selectedView !== 'holdings';
    document.getElementById('investment-trades-panel').hidden = state.selectedView !== 'trades';
    document.querySelectorAll('.investment-view-tabs button').forEach(function (button) {
      var active = button.getAttribute('data-view') === state.selectedView;
      button.classList.toggle('is-active', active); button.setAttribute('aria-selected', String(active));
    });
    document.getElementById('investment-detail-section').hidden = false;
  }

  document.getElementById('investment-account-tabs').addEventListener('click', function (event) {
    var button = event.target.closest('button[data-account]');
    if (!button) return;
    state.selectedAccount = button.getAttribute('data-account'); renderDetail();
  });
  document.querySelector('.investment-view-tabs').addEventListener('click', function (event) {
    var button = event.target.closest('button[data-view]');
    if (!button) return;
    state.selectedView = button.getAttribute('data-view'); renderDetail();
  });

  fetch(endpoint, { headers: { 'Accept': 'application/json' } })
    .then(function (response) { if (!response.ok) throw new Error('HTTP ' + response.status); return response.json(); })
    .then(function (data) {
      state.data = data; state.accounts = latestAccounts(data);
      if (!state.accounts.length) { status.textContent = '尚无账户快照'; return; }
      renderAccounts(); renderHistory(); renderDetail();
      var latestDate = state.accounts[0].snapshot_date;
      status.textContent = '已同步至 ' + latestDate;
      if (state.accounts.length === 1 && state.accounts[0].account_key === 'all') status.textContent += '，等待分类账户明细';
    })
    .catch(function (error) {
      status.textContent = '数据读取失败：' + error.message; status.classList.add('is-error');
    });
})();
</script>
