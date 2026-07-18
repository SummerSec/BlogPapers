---
layout: default
title: 投资复盘
comments: false
---

<div class="investment-records" id="investment-records">
  <header class="investment-records__header">
    <p class="investment-records__eyebrow">PORTFOLIO LEDGER / LIVE</p>
    <h1>投资复盘</h1>
    <p>账户与持仓数据由本地投资账本同步至 Cloudflare D1，本页直接读取最新快照。</p>
    <div class="investment-records__status" id="investment-status" role="status">正在读取最新数据...</div>
  </header>

  <section class="investment-records__section" id="investment-overview" hidden>
    <div class="investment-metrics" id="investment-metrics"></div>
  </section>

  <section class="investment-records__section" id="investment-accounts-section" hidden>
    <div class="investment-records__section-head">
      <h2>账户投资情况</h2>
      <span id="investment-account-date"></span>
    </div>
    <div class="investment-table-wrap">
      <table>
        <thead><tr><th>账户</th><th>总资产</th><th>持仓市值</th><th>现金</th><th>当日盈亏</th><th>累计盈亏</th><th>收益率</th></tr></thead>
        <tbody id="investment-accounts"></tbody>
      </table>
    </div>
  </section>

  <section class="investment-records__section" id="investment-holdings-section" hidden>
    <div class="investment-records__section-head">
      <h2>最新持仓汇总</h2>
      <span id="investment-holding-date"></span>
    </div>
    <div class="investment-table-wrap">
      <table>
        <thead><tr><th>标的</th><th>类型</th><th>数量</th><th>成本价</th><th>现价</th><th>市值</th><th>盈亏</th><th>收益率</th><th>仓位</th></tr></thead>
        <tbody id="investment-holdings"></tbody>
      </table>
    </div>
  </section>

  <section class="investment-records__section" id="investment-history-section" hidden>
    <div class="investment-records__section-head"><h2>历史资产快照</h2><span>按日期倒序</span></div>
    <div class="investment-table-wrap">
      <table>
        <thead><tr><th>日期</th><th>账户</th><th>总资产</th><th>持仓市值</th><th>现金</th><th>累计盈亏</th><th>收益率</th></tr></thead>
        <tbody id="investment-history"></tbody>
      </table>
    </div>
  </section>

  <details class="investment-records__operations" id="investment-operations-section" hidden>
    <summary>操作明细</summary>
    <div class="investment-table-wrap">
      <table>
        <thead><tr><th>时间</th><th>操作</th><th>标的</th><th>方向</th><th>数量</th><th>价格</th><th>金额</th></tr></thead>
        <tbody id="investment-operations"></tbody>
      </table>
    </div>
  </details>

  <p class="investment-records__disclaimer">公开数据仅用于个人记录，不构成任何投资建议。</p>
</div>

<style>
.investment-records { max-width: var(--wide-max); margin: 0 auto; }
.investment-records__header { padding: 1rem 0 1.5rem; border-bottom: 1px solid var(--border-strong); }
.investment-records__header h1 { margin: .25rem 0 .5rem; font-size: 2rem; letter-spacing: 0; }
.investment-records__header > p:not(.investment-records__eyebrow) { margin: 0; color: var(--text-muted); }
.investment-records__eyebrow { margin: 0; color: var(--color-signal); font: 700 .76rem/1.4 var(--font-code); }
.investment-records__status { margin-top: 1rem; color: var(--text-muted); font-family: var(--font-code); }
.investment-records__status.is-error { color: var(--color-amber); }
.investment-records__section { margin-top: 2rem; }
.investment-records__section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: .75rem; }
.investment-records__section-head h2 { margin: 0; font-size: 1.2rem; letter-spacing: 0; }
.investment-records__section-head span { color: var(--text-muted); font: .8rem/1.4 var(--font-code); }
.investment-metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border-top: 1px solid var(--border-strong); border-bottom: 1px solid var(--border-strong); }
.investment-metric { min-width: 0; padding: 1rem; border-right: 1px solid var(--border); }
.investment-metric:last-child { border-right: 0; }
.investment-metric span { display: block; color: var(--text-muted); font-size: .8rem; }
.investment-metric strong { display: block; margin-top: .3rem; overflow-wrap: anywhere; font: 650 1.2rem/1.35 var(--font-code); }
.investment-table-wrap { overflow-x: auto; }
.investment-records table { width: 100%; min-width: 760px; margin: 0; font-size: .88rem; }
.investment-records th, .investment-records td { white-space: nowrap; }
.investment-records td:first-child, .investment-records th:first-child { padding-left: .75rem; }
.investment-records .is-positive { color: #e05d5d; }
.investment-records .is-negative { color: #36a874; }
.investment-records__operations { margin-top: 2rem; border-top: 1px solid var(--border-strong); padding-top: 1rem; }
.investment-records__operations summary { cursor: pointer; font-weight: 650; }
.investment-records__operations[open] summary { margin-bottom: .75rem; }
.investment-records__disclaimer { margin-top: 2rem; color: var(--text-dim); font-size: .82rem; }
@media (max-width: 720px) {
  .investment-records__header h1 { font-size: 1.65rem; }
  .investment-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .investment-metric:nth-child(2) { border-right: 0; }
  .investment-metric:nth-child(-n+2) { border-bottom: 1px solid var(--border); }
  .investment-records__section-head { align-items: flex-start; flex-direction: column; gap: .25rem; }
}
</style>

<script>
(function () {
  'use strict';
  var API = 'https://sumsec-investment-log.sumsec.workers.dev/api/portfolio?days=3650';
  var status = document.getElementById('investment-status');
  var money = new Intl.NumberFormat('zh-CN', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  var number = new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 4 });

  function value(input, formatter) {
    if (input === null || input === undefined || input === '') return '-';
    var parsed = Number(input);
    return Number.isFinite(parsed) ? formatter.format(parsed) : String(input);
  }
  function percent(input) {
    if (input === null || input === undefined || input === '') return '-';
    var parsed = Number(input);
    return Number.isFinite(parsed) ? number.format(parsed) + '%' : String(input);
  }
  function pnlClass(input) {
    var parsed = Number(input);
    return !Number.isFinite(parsed) || parsed === 0 ? '' : parsed > 0 ? 'is-positive' : 'is-negative';
  }
  function cell(row, text, className) {
    var td = document.createElement('td');
    td.textContent = text;
    if (className) td.className = className;
    row.appendChild(td);
  }
  function labelAccount(item) {
    return item.account_name || (item.account_key === 'all' ? '全部账户' : '账户 ' + String(item.account_key || '').slice(0, 6));
  }
  function metric(label, display, className) {
    var item = document.createElement('div');
    item.className = 'investment-metric';
    var caption = document.createElement('span');
    caption.textContent = label;
    var strong = document.createElement('strong');
    strong.textContent = display;
    if (className) strong.className = className;
    item.appendChild(caption);
    item.appendChild(strong);
    return item;
  }

  fetch(API, { headers: { Accept: 'application/json' }, cache: 'no-store' })
    .then(function (response) {
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return response.json();
    })
    .then(function (data) {
      var snapshots = Array.isArray(data.portfolio_snapshots) ? data.portfolio_snapshots : [];
      var holdings = Array.isArray(data.holdings) ? data.holdings : [];
      var operations = Array.isArray(data.operations) ? data.operations : [];
      if (!snapshots.length && !holdings.length) {
        status.textContent = '暂无已同步的账户或持仓快照';
        return;
      }

      var latestDate = data.latest_snapshot_date || (snapshots[0] && snapshots[0].snapshot_date) || '-';
      var latestAccounts = snapshots.filter(function (item) { return item.snapshot_date === latestDate; });
      if (!latestAccounts.length && snapshots.length) {
        latestDate = snapshots[0].snapshot_date;
        latestAccounts = snapshots.filter(function (item) { return item.snapshot_date === latestDate; });
      }
      var aggregate = latestAccounts.find(function (item) { return item.account_key === 'all'; }) || latestAccounts[0] || {};
      var metrics = document.getElementById('investment-metrics');
      metrics.appendChild(metric('快照日期', latestDate));
      metrics.appendChild(metric('总资产', value(aggregate.total_asset, money)));
      metrics.appendChild(metric('累计盈亏', value(aggregate.total_pnl, money), pnlClass(aggregate.total_pnl)));
      metrics.appendChild(metric('最新持仓', holdings.length + ' 项'));
      document.getElementById('investment-overview').hidden = false;

      if (latestAccounts.length) {
        var accountBody = document.getElementById('investment-accounts');
        latestAccounts.forEach(function (item) {
          var row = document.createElement('tr');
          cell(row, labelAccount(item));
          cell(row, value(item.total_asset, money));
          cell(row, value(item.market_value, money));
          cell(row, value(item.cash, money));
          cell(row, value(item.day_pnl, money), pnlClass(item.day_pnl));
          cell(row, value(item.total_pnl, money), pnlClass(item.total_pnl));
          cell(row, percent(item.total_return), pnlClass(item.total_return));
          accountBody.appendChild(row);
        });
        document.getElementById('investment-account-date').textContent = latestDate;
        document.getElementById('investment-accounts-section').hidden = false;
      }

      if (holdings.length) {
        var holdingBody = document.getElementById('investment-holdings');
        holdings.forEach(function (item) {
          var row = document.createElement('tr');
          var instrument = item.instrument_name || item.instrument_code || '-';
          if (item.instrument_name && item.instrument_code) instrument += ' (' + item.instrument_code + ')';
          cell(row, instrument);
          cell(row, item.asset_type === 'fund' ? '基金' : '股票');
          cell(row, value(item.quantity, number));
          cell(row, value(item.cost_price, number));
          cell(row, value(item.current_price, number));
          cell(row, value(item.market_value, money));
          cell(row, value(item.pnl, money), pnlClass(item.pnl));
          cell(row, percent(item.pnl_rate), pnlClass(item.pnl_rate));
          cell(row, percent(item.weight));
          holdingBody.appendChild(row);
        });
        document.getElementById('investment-holding-date').textContent = data.latest_snapshot_date || latestDate;
        document.getElementById('investment-holdings-section').hidden = false;
      }

      if (snapshots.length) {
        var historyBody = document.getElementById('investment-history');
        snapshots.slice(0, 365).forEach(function (item) {
          var row = document.createElement('tr');
          cell(row, item.snapshot_date || '-');
          cell(row, labelAccount(item));
          cell(row, value(item.total_asset, money));
          cell(row, value(item.market_value, money));
          cell(row, value(item.cash, money));
          cell(row, value(item.total_pnl, money), pnlClass(item.total_pnl));
          cell(row, percent(item.total_return), pnlClass(item.total_return));
          historyBody.appendChild(row);
        });
        document.getElementById('investment-history-section').hidden = false;
      }

      if (operations.length) {
        var operationBody = document.getElementById('investment-operations');
        operations.forEach(function (item) {
          var row = document.createElement('tr');
          var instrument = item.instrument_name || item.instrument_code || '-';
          if (item.instrument_name && item.instrument_code) instrument += ' (' + item.instrument_code + ')';
          cell(row, item.occurred_at ? new Date(item.occurred_at).toLocaleString('zh-CN', { hour12: false }) : '-');
          cell(row, item.operation || '-');
          cell(row, instrument);
          cell(row, item.side || '-');
          cell(row, value(item.quantity, number));
          cell(row, value(item.price, number));
          cell(row, value(item.amount, money));
          operationBody.appendChild(row);
        });
        document.getElementById('investment-operations-section').hidden = false;
      }
      status.textContent = '已同步至 ' + latestDate;
    })
    .catch(function (error) {
      status.textContent = '数据读取失败：' + error.message;
      status.classList.add('is-error');
    });
})();
</script>
