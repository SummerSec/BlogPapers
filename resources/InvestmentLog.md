---
layout: default
title: 投资复盘
comments: false
---

<div class="investment-ledger" id="investment-ledger">
  <header class="investment-ledger__header">
    <p class="investment-ledger__eyebrow">PORTFOLIO LEDGER / LIVE</p>
    <h1>投资复盘</h1>
    <p>账户、持仓与交易记录由本地投资账本按 T+1 已结算口径同步至 Cloudflare D1。</p>
    <div class="investment-ledger__auth" id="investment-auth">
      <form id="investment-login-form">
        <label for="investment-password">访问密码</label>
        <div class="investment-ledger__auth-row">
          <input id="investment-password" name="password" type="password" autocomplete="current-password" required>
          <button type="submit">进入</button>
        </div>
        <p id="investment-login-error" role="alert" hidden></p>
      </form>
    </div>
    <div class="investment-ledger__session" id="investment-session" hidden>
      <div class="investment-ledger__status" id="investment-status" role="status">正在读取最新数据...</div>
      <button type="button" id="investment-logout">退出访问</button>
    </div>
    <div class="investment-ledger__date-filter" id="investment-date-filter" aria-label="历史快照日期" hidden>
      <div class="investment-ledger__date-copy">
        <strong>历史回看</strong>
        <span id="investment-date-resolution">选择一个交易日查看历史快照</span>
      </div>
      <div class="investment-ledger__date-actions">
        <div class="investment-ledger__date-cluster" role="group" aria-label="切换交易日">
          <button class="investment-ledger__date-step" type="button" id="investment-date-prev" aria-label="查看上一交易日">‹</button>
          <label class="investment-ledger__date-picker" for="investment-date">
            <span>选择日期</span>
            <time id="investment-date-display">最新快照</time>
            <input id="investment-date" type="date" aria-describedby="investment-date-resolution">
          </label>
          <button class="investment-ledger__date-step" type="button" id="investment-date-next" aria-label="查看下一交易日">›</button>
        </div>
        <button class="investment-ledger__date-latest" type="button" id="investment-date-latest">回到最新</button>
      </div>
    </div>
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

  <section class="investment-ledger__section investment-ledger__history" id="investment-history-section" hidden>
    <div class="investment-ledger__section-head">
      <h2>历史资产走势</h2>
      <span>汇总资产与各平台资产，单位：元</span>
    </div>
    <div class="investment-history-legend" id="investment-history-legend" aria-label="资产曲线图例"></div>
    <div class="investment-history-chart">
      <svg id="investment-history-chart" viewBox="0 0 1120 420" role="img" aria-label="横轴为日期、纵轴为资产金额的历史资产曲线"></svg>
      <div class="investment-history-tooltip" id="investment-history-tooltip" role="status" aria-live="polite" hidden></div>
    </div>
  </section>

  <p class="investment-ledger__disclaimer">数据仅用于个人记录，不构成任何投资建议。</p>
</div>

<style>
.investment-ledger { max-width: var(--wide-max); margin: 0 auto; }
.investment-ledger__header { padding: 1rem 0 1.5rem; border-bottom: 1px solid var(--border-strong); }
.investment-ledger__header h1 { margin: .25rem 0 .5rem; font-size: 2rem; letter-spacing: 0; }
.investment-ledger__header > p:not(.investment-ledger__eyebrow) { margin: 0; color: var(--text-muted); }
.investment-ledger__eyebrow { margin: 0; color: var(--color-signal); font: 700 .76rem/1.4 var(--font-code); }
.investment-ledger__status { margin-top: 1rem; color: var(--text-muted); font-family: var(--font-code); }
.investment-ledger__status.is-error { color: var(--color-amber); }
.investment-ledger__auth { max-width: 25rem; margin-top: 1.25rem; }
.investment-ledger__auth label { display: block; margin-bottom: .45rem; color: var(--text-muted); font-size: .82rem; }
.investment-ledger__auth-row { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: .5rem; }
.investment-ledger__auth input { min-width: 0; height: 40px; padding: 0 .75rem; border: 1px solid var(--border-strong); border-radius: 4px; background: var(--bg-elevated); color: var(--text); font: .9rem/1 var(--font-code); }
.investment-ledger__auth input:focus { outline: 2px solid var(--color-signal); outline-offset: 1px; }
.investment-ledger__auth button, .investment-ledger__session button { min-height: 40px; padding: .55rem .9rem; border: 1px solid var(--border-strong); border-radius: 4px; background: transparent; color: var(--text); cursor: pointer; }
.investment-ledger__auth button:hover, .investment-ledger__session button:hover { border-color: var(--color-signal); color: var(--color-signal); }
.investment-ledger__auth button:disabled { cursor: wait; opacity: .6; }
.investment-ledger__auth p { margin: .55rem 0 0; color: var(--color-amber); font-size: .82rem; }
.investment-ledger__session { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-top: 1rem; }
.investment-ledger__session[hidden] { display: none; }
.investment-ledger__session .investment-ledger__status { margin-top: 0; }
.investment-ledger__date-filter { display: grid; grid-template-columns: minmax(10rem, 1fr) auto; align-items: center; gap: 1rem; margin-top: 1rem; padding: .8rem 0; border-top: 1px solid var(--border-strong); border-bottom: 1px solid var(--border-strong); }
.investment-ledger__date-filter[hidden] { display: none; }
.investment-ledger__date-copy strong { display: block; color: var(--text-strong); font: 650 .86rem/1.3 var(--font-heading); }
.investment-ledger__date-copy span { display: block; margin-top: .2rem; color: var(--text-muted); font: .76rem/1.4 var(--font-code); }
.investment-ledger__date-actions { display: flex; align-items: stretch; gap: .5rem; }
.investment-ledger__date-cluster { display: grid; grid-template-columns: 2.5rem minmax(10.75rem, 1fr) 2.5rem; overflow: hidden; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--bg-elevated); }
.investment-ledger__date-step, .investment-ledger__date-latest { border: 0; background: transparent; color: var(--text); cursor: pointer; transition: color .16s ease, background-color .16s ease, transform .12s ease; }
.investment-ledger__date-step { min-width: 2.5rem; padding: 0; color: var(--text-muted); font: 500 1.45rem/1 var(--font-body); }
.investment-ledger__date-step:first-child { border-right: 1px solid var(--border-strong); }
.investment-ledger__date-step:last-child { border-left: 1px solid var(--border-strong); }
.investment-ledger__date-picker { position: relative; display: flex; min-height: 42px; padding: .35rem .8rem; align-items: center; justify-content: center; flex-direction: column; cursor: pointer; }
.investment-ledger__date-picker span { color: var(--text-muted); font: .65rem/1.2 var(--font-body); }
.investment-ledger__date-picker time { margin-top: .1rem; color: var(--text-strong); font: 650 .82rem/1.25 var(--font-code); white-space: nowrap; }
.investment-ledger__date-picker input { position: absolute; inset: 0; width: 100%; height: 100%; margin: 0; opacity: 0; color-scheme: dark; cursor: pointer; }
.investment-ledger__date-latest { min-height: 44px; padding: .5rem .8rem; border: 1px solid var(--border-strong); border-radius: 6px; color: var(--text-muted); font: 600 .78rem/1 var(--font-body); white-space: nowrap; }
.investment-ledger__date-step:hover, .investment-ledger__date-latest:hover, .investment-ledger__date-picker:hover { background: var(--bg-subtle); color: var(--color-signal); }
.investment-ledger__date-picker:hover time { color: var(--color-signal); }
.investment-ledger__date-step:active, .investment-ledger__date-latest:active { transform: scale(.97); }
.investment-ledger__date-step:focus-visible, .investment-ledger__date-latest:focus-visible, .investment-ledger__date-picker:focus-within { outline: 2px solid var(--color-signal); outline-offset: -2px; }
.investment-ledger__date-actions input:disabled, .investment-ledger__date-actions button:disabled { cursor: wait; opacity: .45; }
.investment-ledger__date-actions button:disabled:hover { background: transparent; color: var(--text-muted); }
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
.investment-table--holdings th:nth-child(-n+3), .investment-table--holdings td:nth-child(-n+3),
.investment-table--trades th:nth-child(-n+5), .investment-table--trades td:nth-child(-n+5),
.investment-table--accounts th:first-child, .investment-table--accounts td:first-child { text-align: left; }
.investment-ledger .is-positive { color: #d84b57; }
.investment-ledger .is-negative { color: #268a63; }
.investment-empty { margin: .9rem 0 0; color: var(--text-muted); }
.investment-ledger__history { border-top: 1px solid var(--border-strong); padding-top: 1.5rem; }
.investment-history-legend { display: flex; flex-wrap: wrap; gap: .55rem 1.25rem; margin-bottom: .75rem; color: var(--text-muted); font-size: .82rem; }
.investment-history-legend span { display: inline-flex; align-items: center; gap: .45rem; }
.investment-history-legend i { width: 1.5rem; height: 0; border-top: 2px solid var(--series-color); }
.investment-history-legend span:first-child i { border-top-width: 3px; }
.investment-history-legend strong { color: var(--text-strong); font: 600 .82rem/1.3 var(--font-code); }
.investment-history-chart { position: relative; width: 100%; min-height: 260px; aspect-ratio: 8 / 3; }
.investment-history-chart svg { display: block; width: 100%; height: 100%; min-height: 260px; overflow: visible; }
.investment-history-chart .history-grid { stroke: var(--border); stroke-width: 1; vector-effect: non-scaling-stroke; }
.investment-history-chart .history-axis { fill: var(--text-dim); font: 12px/1 var(--font-code); }
.investment-history-chart .history-axis-title { fill: var(--text-muted); font: 12px/1 var(--font-body); }
.investment-history-chart .history-line { fill: none; stroke: var(--series-color); stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; vector-effect: non-scaling-stroke; }
.investment-history-chart .history-line--total { stroke-width: 3; }
.investment-history-chart .history-point { fill: var(--bg); stroke: var(--series-color); stroke-width: 2; vector-effect: non-scaling-stroke; }
.investment-history-chart .history-guide { stroke: var(--border-strong); stroke-width: 1; vector-effect: non-scaling-stroke; }
.investment-history-tooltip { position: absolute; z-index: 2; min-width: 10rem; max-width: min(18rem, calc(100% - 1rem)); padding: .55rem .65rem; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--bg-elevated); color: var(--text); box-shadow: 0 8px 24px rgba(0, 0, 0, .12); pointer-events: none; font-size: .78rem; }
.investment-history-tooltip strong { display: block; margin-bottom: .25rem; color: var(--text-strong); font-family: var(--font-code); }
.investment-history-tooltip span { display: flex; justify-content: space-between; gap: 1.5rem; }
.investment-history-tooltip em { font-style: normal; }
.investment-history-tooltip b { color: var(--text-strong); font-family: var(--font-code); }
.investment-ledger__disclaimer { margin-top: 2rem; color: var(--text-dim); font-size: .82rem; }
@media (max-width: 760px) {
  .investment-ledger__header h1 { font-size: 1.65rem; }
  .investment-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .investment-metric { border-bottom: 1px solid var(--border-strong); }
  .investment-metric:nth-child(2) { border-right: 0; }
  .investment-metric:nth-child(n+3) { border-bottom: 0; }
  .investment-ledger__section-head { align-items: flex-start; flex-direction: column; gap: .25rem; }
  .investment-ledger__date-filter { grid-template-columns: 1fr; align-items: stretch; }
  .investment-ledger__date-actions { display: grid; grid-template-columns: minmax(0, 1fr) auto; }
  .investment-ledger__date-cluster { grid-template-columns: 2.75rem minmax(0, 1fr) 2.75rem; }
  .investment-ledger__date-latest { padding-inline: .7rem; }
  .investment-history-chart { aspect-ratio: 4 / 3; }
  .investment-history-chart .history-axis { font-size: 36px; }
  .investment-history-chart .history-axis-title { display: none; }
}
</style>

<script>
(function () {
  var apiBase = 'https://sumsec-investment-log.sumsec.workers.dev';
  var endpoint = apiBase + '/api/portfolio?days=3650';
  var sessionKey = 'sumsec-investment-read-session';
  var status = document.getElementById('investment-status');
  var auth = document.getElementById('investment-auth');
  var loginForm = document.getElementById('investment-login-form');
  var passwordInput = document.getElementById('investment-password');
  var loginError = document.getElementById('investment-login-error');
  var session = document.getElementById('investment-session');
  var dateFilter = document.getElementById('investment-date-filter');
  var dateInput = document.getElementById('investment-date');
  var dateDisplay = document.getElementById('investment-date-display');
  var dateResolution = document.getElementById('investment-date-resolution');
  var datePrev = document.getElementById('investment-date-prev');
  var dateNext = document.getElementById('investment-date-next');
  var dateLatest = document.getElementById('investment-date-latest');
  var state = { data: null, accounts: [], selectedAccount: 'all', selectedView: 'holdings', requestedDate: '', latestSettledDate: '', requestSequence: 0, loading: false };

  function escapeHtml(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  function number(value) {
    if (value === null || value === undefined || value === '') return null;
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
    var specific = holdings.filter(function (item) { return item.account_key !== 'all'; });
    if (specific.length) return specific;
    var aggregate = holdings.filter(function (item) { return item.account_key === 'all'; });
    return aggregate;
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

  function historySeries() {
    var snapshots = Array.isArray(state.data.portfolio_snapshots) ? state.data.portfolio_snapshots : [];
    var specific = snapshots.some(function (item) { return item.account_key !== 'all'; });
    if (specific) snapshots = snapshots.filter(function (item) { return item.account_key !== 'all'; });
    function isWeekday(date) {
      var parts = String(date || '').split('-').map(Number);
      if (parts.length !== 3 || parts.some(function (part) { return !Number.isFinite(part); })) return false;
      var day = new Date(Date.UTC(parts[0], parts[1] - 1, parts[2])).getUTCDay();
      return day !== 0 && day !== 6;
    }
    var dates = Array.from(new Set(snapshots.map(function (item) { return item.snapshot_date; })
      .filter(function (date) { return isWeekday(date); }))).sort();
    var identities = [];
    var labels = {};
    var lookup = {};
    var captured = {};

    function identity(item) {
      var name = String(item.account_name || '').trim();
      return name ? 'name:' + name : 'key:' + item.account_key;
    }

    state.accounts.forEach(function (item) {
      if (item.account_key === 'all') return;
      var id = identity(item);
      if (identities.indexOf(id) === -1) identities.push(id);
      labels[id] = item.account_name || accountLabel(item.account_key);
    });
    snapshots.forEach(function (item) {
      var id = identity(item);
      if (identities.indexOf(id) === -1) identities.push(id);
      labels[id] = item.account_name || labels[id] || accountLabel(item.account_key);
      var value = number(item.total_asset);
      var pointKey = item.snapshot_date + '|' + id;
      var capturedAt = String(item.captured_at || '');
      if (value !== null && (!captured[pointKey] || capturedAt >= captured[pointKey])) {
        lookup[pointKey] = value;
        captured[pointKey] = capturedAt;
      }
    });
    var accounts = identities.map(function (id) {
      return {
        key: id,
        label: labels[id] || '未命名账户',
        values: dates.map(function (date) {
          var value = lookup[date + '|' + id];
          return value === undefined ? null : value;
        }),
      };
    }).filter(function (series) {
      return series.values.some(function (value) { return value !== null; });
    });
    var total = dates.map(function (_, index) {
      var values = accounts.map(function (series) { return series.values[index]; });
      if (!values.length || values.some(function (value) { return value === null; })) return null;
      return values.reduce(function (result, value) { return result + value; }, 0);
    });
    return { dates: dates, series: [{ key: 'total', label: '汇总资产', values: total }].concat(accounts) };
  }

  function renderHistory() {
    var chartData = historySeries();
    var section = document.getElementById('investment-history-section');
    var svg = document.getElementById('investment-history-chart');
    if (!chartData.dates.length) { section.hidden = true; return; }

    var colors = ['var(--color-signal)', 'var(--color-blue)', 'var(--color-amber)', 'color-mix(in srgb, var(--color-blue) 58%, var(--color-amber))', 'var(--text-muted)', 'var(--color-primary-light)'];
    chartData.series.forEach(function (series, index) { series.color = colors[index % colors.length]; });
    var allValues = chartData.series.reduce(function (result, series) {
      return result.concat(series.values.filter(function (value) { return value !== null; }));
    }, []);
    if (!allValues.length) { section.hidden = true; return; }

    var width = 1120; var height = 420;
    var margin = { top: 22, right: 28, bottom: 54, left: 156 };
    var plotWidth = width - margin.left - margin.right;
    var plotHeight = height - margin.top - margin.bottom;
    var minimum = Math.min.apply(null, allValues);
    var maximum = Math.max.apply(null, allValues);
    var padding = Math.max((maximum - minimum) * .08, Math.abs(maximum || 1) * .015, 1);
    var yMin = minimum >= 0 ? 0 : minimum - padding; var yMax = maximum + padding;
    function x(index) {
      return chartData.dates.length === 1 ? margin.left + plotWidth / 2 : margin.left + index * plotWidth / (chartData.dates.length - 1);
    }
    function y(value) { return margin.top + (yMax - value) * plotHeight / (yMax - yMin); }
    function compactMoney(value) {
      return new Intl.NumberFormat('zh-CN', { notation: 'compact', maximumFractionDigits: 1 }).format(value);
    }
    function pathFor(values) {
      var path = ''; var open = false;
      values.forEach(function (value, index) {
        if (value === null) { open = false; return; }
        path += (open ? ' L ' : ' M ') + x(index).toFixed(2) + ' ' + y(value).toFixed(2);
        open = true;
      });
      return path.trim();
    }

    var markup = '<title>历史资产走势</title><desc>横轴为日期，纵轴为资产金额，包含汇总资产和各平台资产曲线。曲线断点代表该日期未同步完整数据。</desc>';
    for (var tick = 0; tick < 5; tick += 1) {
      var tickY = margin.top + tick * plotHeight / 4;
      var tickValue = yMax - tick * (yMax - yMin) / 4;
      markup += '<line class="history-grid" x1="' + margin.left + '" y1="' + tickY + '" x2="' + (width - margin.right) + '" y2="' + tickY + '"></line>';
      markup += '<text class="history-axis" x="' + (margin.left - 12) + '" y="' + (tickY + 4) + '" text-anchor="end">' + compactMoney(tickValue) + '</text>';
    }
    var xTickCount = Math.min(6, chartData.dates.length);
    var xIndexes = [];
    for (var xTick = 0; xTick < xTickCount; xTick += 1) {
      var xIndex = xTickCount === 1 ? 0 : Math.round(xTick * (chartData.dates.length - 1) / (xTickCount - 1));
      if (xIndexes.indexOf(xIndex) === -1) xIndexes.push(xIndex);
    }
    xIndexes.forEach(function (index) {
      var anchor = index === 0 ? 'start' : (index === chartData.dates.length - 1 ? 'end' : 'middle');
      markup += '<text class="history-axis" x="' + x(index) + '" y="' + (height - 24) + '" text-anchor="' + anchor + '">' + escapeHtml(chartData.dates[index].slice(5)) + '</text>';
    });
    markup += '<text class="history-axis-title" x="' + (margin.left + plotWidth / 2) + '" y="' + (height - 3) + '" text-anchor="middle">日期</text>';
    markup += '<text class="history-axis-title" transform="translate(18 ' + (margin.top + plotHeight / 2) + ') rotate(-90)" text-anchor="middle">资产（元）</text>';
    chartData.series.forEach(function (series, seriesIndex) {
      var path = pathFor(series.values);
      if (!path) return;
      markup += '<path class="history-line ' + (seriesIndex === 0 ? 'history-line--total' : '') + '" style="--series-color:' + series.color + '" d="' + path + '"></path>';
      if (chartData.dates.length <= 31) {
        series.values.forEach(function (value, index) {
          if (value !== null) markup += '<circle class="history-point" style="--series-color:' + series.color + '" cx="' + x(index) + '" cy="' + y(value) + '" r="3"></circle>';
        });
      }
    });
    markup += '<line id="investment-history-guide" class="history-guide" y1="' + margin.top + '" y2="' + (height - margin.bottom) + '" hidden></line>';
    markup += '<g id="investment-history-hover-points"></g>';
    markup += '<rect id="investment-history-hit" x="' + margin.left + '" y="' + margin.top + '" width="' + plotWidth + '" height="' + plotHeight + '" fill="transparent"></rect>';
    svg.innerHTML = markup;

    document.getElementById('investment-history-legend').innerHTML = chartData.series.map(function (series) {
      var latest = null;
      for (var i = series.values.length - 1; i >= 0; i -= 1) { if (series.values[i] !== null) { latest = series.values[i]; break; } }
      return '<span style="--series-color:' + series.color + '"><i aria-hidden="true"></i>' + escapeHtml(series.label) + '<strong>' + formatMoney(latest) + '</strong></span>';
    }).join('');

    var hit = document.getElementById('investment-history-hit');
    var guide = document.getElementById('investment-history-guide');
    var hoverPoints = document.getElementById('investment-history-hover-points');
    var tooltip = document.getElementById('investment-history-tooltip');
    function hideTooltip() { guide.hidden = true; hoverPoints.innerHTML = ''; tooltip.hidden = true; }
    hit.addEventListener('pointerleave', hideTooltip);
    hit.addEventListener('pointermove', function (event) {
      var bounds = svg.getBoundingClientRect();
      var svgX = (event.clientX - bounds.left) * width / bounds.width;
      var index = chartData.dates.length === 1 ? 0 : Math.round((svgX - margin.left) * (chartData.dates.length - 1) / plotWidth);
      index = Math.max(0, Math.min(chartData.dates.length - 1, index));
      var guideX = x(index);
      guide.hidden = false; guide.setAttribute('x1', guideX); guide.setAttribute('x2', guideX);
      hoverPoints.innerHTML = chartData.series.map(function (series) {
        var value = series.values[index];
        return value === null ? '' : '<circle class="history-point" style="--series-color:' + series.color + '" cx="' + guideX + '" cy="' + y(value) + '" r="5"></circle>';
      }).join('');
      tooltip.innerHTML = '<strong>' + escapeHtml(chartData.dates[index]) + '</strong>' + chartData.series.map(function (series) {
        return '<span><em>' + escapeHtml(series.label) + '</em><b>' + formatMoney(series.values[index]) + '</b></span>';
      }).join('');
      tooltip.hidden = false;
      var chartBounds = tooltip.parentElement.getBoundingClientRect();
      var left = (guideX / width) * chartBounds.width + 12;
      if (left + tooltip.offsetWidth > chartBounds.width) left = (guideX / width) * chartBounds.width - tooltip.offsetWidth - 12;
      tooltip.style.left = Math.max(0, left) + 'px';
      tooltip.style.top = Math.max(0, (margin.top / height) * chartBounds.height) + 'px';
    });
    section.hidden = false;
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

  function hideData() {
    ['investment-overview', 'investment-accounts-section', 'investment-detail-section', 'investment-history-section'].forEach(function (id) {
      document.getElementById(id).hidden = true;
    });
  }

  function showLogin(message) {
    hideData();
    session.hidden = true;
    dateFilter.hidden = true;
    auth.hidden = false;
    loginError.textContent = message || '';
    loginError.hidden = !message;
    passwordInput.focus();
  }

  function showSession() {
    auth.hidden = true;
    session.hidden = false;
    status.classList.remove('is-error');
    status.textContent = '正在读取最新数据...';
  }

  function parseCalendarDate(value) {
    var match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value || ''));
    if (!match) return null;
    var date = new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function calendarDateValue(date) {
    function pad(value) { return String(value).padStart(2, '0'); }
    return date.getFullYear() + '-' + pad(date.getMonth() + 1) + '-' + pad(date.getDate());
  }

  function formatCalendarDate(value) {
    var date = parseCalendarDate(value);
    if (!date) return '选择日期';
    var weekdays = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];
    return date.getFullYear() + '年' + (date.getMonth() + 1) + '月' + date.getDate() + '日 ' + weekdays[date.getDay()];
  }

  function adjacentBusinessDate(value, direction) {
    var date = parseCalendarDate(value);
    if (!date) return '';
    do { date.setDate(date.getDate() + direction); }
    while (date.getDay() === 0 || date.getDay() === 6);
    return calendarDateValue(date);
  }

  function updateDateNavigation() {
    var current = dateInput.value || state.latestSettledDate;
    var next = adjacentBusinessDate(current, 1);
    dateDisplay.textContent = current ? formatCalendarDate(current) : '选择日期';
    dateDisplay.dateTime = current || '';
    datePrev.disabled = state.loading || !current;
    dateNext.disabled = state.loading || !current || !state.latestSettledDate || current >= state.latestSettledDate || next > state.latestSettledDate;
    dateLatest.disabled = state.loading || !state.requestedDate;
    dateInput.disabled = state.loading;
  }

  function setDateLoading(loading) {
    state.loading = loading;
    updateDateNavigation();
  }

  function loadPortfolio(token, requestedDate) {
    var requestId = ++state.requestSequence;
    var requestUrl = endpoint + (requestedDate ? '&date=' + encodeURIComponent(requestedDate) : '');
    state.requestedDate = requestedDate || '';
    setDateLoading(true);
    showSession();
    return fetch(requestUrl, { headers: { 'Accept': 'application/json', 'Authorization': 'Bearer ' + token } })
      .then(function (response) {
        if (response.status === 401) {
          sessionStorage.removeItem(sessionKey);
          showLogin('访问已过期，请重新输入密码。');
          return null;
        }
        if (!response.ok) return response.json().catch(function () { return {}; }).then(function (body) {
          throw new Error(body.error || ('HTTP ' + response.status));
        });
        return response.json();
      })
    .then(function (data) {
      if (!data || requestId !== state.requestSequence) return;
      state.data = data; state.accounts = latestAccounts(data); state.selectedAccount = 'all';
      state.latestSettledDate = data.latest_settled_date || '';
      dateInput.max = data.latest_settled_date || '';
      dateInput.value = requestedDate || data.latest_snapshot_date || '';
      dateFilter.hidden = false;
      var actualDate = data.resolved_snapshot_date || data.latest_snapshot_date || data.latest_holding_date;
      if (requestedDate && actualDate && requestedDate !== actualDate) {
        dateResolution.textContent = '选择 ' + requestedDate + '，实际回退到 ' + actualDate;
      } else if (actualDate) {
        dateResolution.textContent = '当前数据日期 ' + actualDate;
      } else {
        dateResolution.textContent = '该日期之前暂无快照';
      }
      if (!state.accounts.length) { status.textContent = '尚无账户快照'; return; }
      renderAccounts(); renderHistory(); renderDetail();
      var latestDate = state.accounts[0].snapshot_date;
      status.textContent = requestedDate ? '正在查看 ' + latestDate : '已同步至 ' + latestDate;
      if (state.accounts.length === 1 && state.accounts[0].account_key === 'all') status.textContent += '，等待分类账户明细';
    })
    .catch(function (error) {
      if (requestId !== state.requestSequence) return;
      status.textContent = '数据读取失败：' + error.message; status.classList.add('is-error');
    }).finally(function () {
      if (requestId !== state.requestSequence) return;
      setDateLoading(false);
    });
  }

  dateInput.addEventListener('change', function () {
    var token = sessionStorage.getItem(sessionKey);
    if (token && dateInput.value) loadPortfolio(token, dateInput.value);
  });

  datePrev.addEventListener('click', function () {
    var token = sessionStorage.getItem(sessionKey);
    var target = adjacentBusinessDate(dateInput.value || state.latestSettledDate, -1);
    if (token && target) loadPortfolio(token, target);
  });

  dateNext.addEventListener('click', function () {
    var token = sessionStorage.getItem(sessionKey);
    var target = adjacentBusinessDate(dateInput.value || state.latestSettledDate, 1);
    if (target > state.latestSettledDate) target = state.latestSettledDate;
    if (token && target) loadPortfolio(token, target);
  });

  dateLatest.addEventListener('click', function () {
    var token = sessionStorage.getItem(sessionKey);
    if (!token) return;
    dateInput.value = '';
    loadPortfolio(token, '');
  });

  loginForm.addEventListener('submit', function (event) {
    event.preventDefault();
    var button = loginForm.querySelector('button[type="submit"]');
    var password = passwordInput.value;
    button.disabled = true;
    loginError.hidden = true;
    fetch(apiBase + '/api/login', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: password }),
    }).then(function (response) {
      if (response.status === 401) throw new Error('密码不正确。');
      if (!response.ok) throw new Error('登录服务暂时不可用（HTTP ' + response.status + '）。');
      return response.json();
    }).then(function (data) {
      if (!data.token) throw new Error('登录响应无效。');
      sessionStorage.setItem(sessionKey, data.token);
      passwordInput.value = '';
      return loadPortfolio(data.token);
    }).catch(function (error) {
      showLogin(error.message);
    }).finally(function () {
      button.disabled = false;
    });
  });

  document.getElementById('investment-logout').addEventListener('click', function () {
    sessionStorage.removeItem(sessionKey);
    state.data = null; state.accounts = [];
    showLogin('已退出访问。');
  });

  var storedToken = sessionStorage.getItem(sessionKey);
  if (storedToken) loadPortfolio(storedToken, '');
  else showLogin('');
})();
</script>
