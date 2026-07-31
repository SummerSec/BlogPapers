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
    <nav class="investment-workspace-nav" id="investment-workspace-nav" aria-label="投资复盘视图">
      <a href="?view=overview" data-workspace-view="overview">概览</a>
      <a href="?view=performance" data-workspace-view="performance">绩效</a>
      <a href="?view=holdings" data-workspace-view="holdings">持仓</a>
      <a href="?view=activity" data-workspace-view="activity">流水</a>
      <a href="?view=review" data-workspace-view="review">复盘</a>
    </nav>
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
          <button class="investment-ledger__date-picker" type="button" id="investment-date-trigger" aria-haspopup="dialog" aria-expanded="false" aria-controls="investment-date-menu">
            <span>快速选择</span>
            <time id="investment-date-display">最新快照</time>
          </button>
          <button class="investment-ledger__date-step" type="button" id="investment-date-next" aria-label="查看下一交易日">›</button>
        </div>
        <button class="investment-ledger__date-latest" type="button" id="investment-date-latest">回到最新</button>
        <div class="investment-ledger__date-menu" id="investment-date-menu" role="dialog" aria-label="快速选择历史日期" hidden>
          <div class="investment-ledger__date-menu-head">
            <strong>选择日期</strong>
            <span>最近 10 个交易日</span>
          </div>
          <div class="investment-ledger__quick-dates" id="investment-quick-dates" role="listbox" aria-label="最近交易日"></div>
          <label class="investment-ledger__exact-date" for="investment-date">
            <span>其他日期</span>
            <input id="investment-date" type="date" aria-describedby="investment-date-resolution">
          </label>
        </div>
      </div>
    </div>
  </header>

  <div class="investment-account-context" id="investment-account-context" hidden>
    <span>账户范围</span>
    <div class="investment-account-tabs" id="investment-account-tabs" role="tablist" aria-label="投资账户"></div>
  </div>

  <section class="investment-ledger__section" id="investment-overview" hidden>
    <div class="investment-metrics" id="investment-metrics"></div>
    <div class="investment-daily-brief" id="investment-daily-brief"></div>
  </section>

  <section class="investment-ledger__section" id="investment-accounts-section" hidden>
    <div class="investment-ledger__section-head">
      <h2>分类账户</h2>
      <span id="investment-account-date"></span>
    </div>
    <div class="investment-table-wrap">
      <table class="investment-table investment-table--accounts">
        <thead>
          <tr><th>账户</th><th>总资产</th><th>较上个交易日</th><th>持有盈亏</th><th>持有盈亏率</th><th>当日盈亏</th><th>当日盈亏率</th><th>持仓市值</th><th>现金</th></tr>
        </thead>
        <tbody id="investment-accounts"></tbody>
      </table>
    </div>
  </section>

  <section class="investment-ledger__section investment-ledger__performance" id="investment-performance-section" hidden>
    <div class="investment-ledger__section-head">
      <div>
        <h2>资金与收益</h2>
        <p>资产变化拆分为外部资金流动与投资盈亏；买卖和逆回购不计入资金流入流出。</p>
      </div>
      <span id="investment-performance-scope"></span>
    </div>
    <div class="investment-analysis-strip" id="investment-performance-summary"></div>
    <div class="investment-benchmark" id="investment-benchmark">
      <div class="investment-ledger__section-head investment-ledger__section-head--compact">
        <div>
          <h3>比较基准</h3>
          <p>只在同一日期区间比较组合与基准，避免把资金流误当成超额收益。</p>
        </div>
        <label for="investment-benchmark-select">基准
          <select id="investment-benchmark-select"></select>
        </label>
      </div>
      <div class="investment-analysis-strip" id="investment-benchmark-summary"></div>
      <p class="investment-performance-note" id="investment-benchmark-note"></p>
    </div>
    <div class="investment-performance-tabs" role="tablist" aria-label="收益统计周期">
      <button type="button" class="is-active" data-period="day" role="tab" aria-selected="true">按日</button>
      <button type="button" data-period="month" role="tab" aria-selected="false">按月</button>
      <button type="button" data-period="year" role="tab" aria-selected="false">按年</button>
    </div>
    <div class="investment-table-wrap">
      <table class="investment-table investment-table--performance">
        <thead>
          <tr><th>期间</th><th>期末资产</th><th>资金流入</th><th>资金流出</th><th>净流入</th><th>投资收益</th><th>收益率</th><th>数据覆盖</th></tr>
        </thead>
        <tbody id="investment-performance"></tbody>
      </table>
    </div>
    <p class="investment-performance-note" id="investment-performance-note"></p>
  </section>

  <section class="investment-ledger__section" id="investment-detail-section" hidden>
    <div id="investment-holdings-panel" role="tabpanel">
      <div class="investment-ledger__section-head investment-ledger__section-head--compact">
        <h2 id="investment-holdings-title">汇总持仓</h2>
        <span id="investment-holding-count"></span>
      </div>
      <div class="investment-analysis-block" id="investment-allocation-summary"></div>
      <div class="investment-table-wrap">
        <table class="investment-table investment-table--holdings">
          <thead>
            <tr>
              <th>账户</th><th>数据日期</th><th>代码</th><th>名称</th><th>持有盈亏率</th><th>持有金额</th>
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
        <h2 id="investment-trades-title">账户流水</h2>
        <span id="investment-trade-count"></span>
      </div>
      <div class="investment-analysis-block" id="investment-activity-summary"></div>
      <div class="investment-ledger__section-head investment-ledger__section-head--compact">
        <h3>外部资金流</h3>
        <span id="investment-cash-flow-count"></span>
      </div>
      <div class="investment-table-wrap">
        <table class="investment-table investment-table--cash-flows">
          <thead><tr><th>日期</th><th>账户</th><th>方向</th><th>类别</th><th>金额</th><th>来源</th><th>状态</th><th>备注</th></tr></thead>
          <tbody id="investment-cash-flows"></tbody>
        </table>
      </div>
      <p class="investment-empty" id="investment-cash-flows-empty" hidden>尚未采集到独立的外部资金流水。</p>
      <div class="investment-ledger__section-head investment-ledger__section-head--compact">
        <h3>买卖与账户交易</h3>
        <span>不计入外部资金流入流出</span>
      </div>
      <div class="investment-table-wrap">
        <table class="investment-table investment-table--trades">
          <thead>
            <tr><th>日期</th><th>账户</th><th>类型</th><th>代码</th><th>名称</th><th>成交价格</th><th>成交数量</th><th>成交金额</th><th>交易费用</th><th>来源</th><th>备注</th></tr>
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

  <section class="investment-ledger__section investment-ledger__review" id="investment-review-section" hidden>
    <div class="investment-ledger__section-head">
      <div>
        <h2>复盘线索</h2>
        <p>把数据转换成需要检查的问题，而不是再重复一遍数字。</p>
      </div>
      <span id="investment-review-scope"></span>
    </div>
    <div class="investment-review-grid" id="investment-review-summary"></div>
    <div class="investment-review-alerts">
      <h3>本期需要确认</h3>
      <ul id="investment-review-alerts"></ul>
    </div>
    <div class="investment-review-journal">
      <div class="investment-ledger__section-head investment-ledger__section-head--compact">
        <div>
          <h3>决策日志</h3>
          <p>记录当时的判断、行动、证据和失效条件，之后才能区分运气与决策质量。</p>
        </div>
        <button type="button" id="investment-review-compose">记录本次判断</button>
      </div>
      <form class="investment-review-form" id="investment-review-form" hidden>
        <label>判断<textarea name="thesis" maxlength="600" placeholder="我现在相信什么？"></textarea></label>
        <label>行动<textarea name="action" maxlength="600" placeholder="因此做什么，或明确不做什么？"></textarea></label>
        <label>证据<textarea name="evidence" maxlength="1000" placeholder="哪些数据或事实支持这个判断？"></textarea></label>
        <label>失效条件<textarea name="invalidation" maxlength="600" placeholder="出现什么情况说明判断错了？"></textarea></label>
        <label>标签<input name="tags" maxlength="240" placeholder="例：再平衡, 风险控制"></label>
        <label>编辑密码<input name="write_token" type="password" maxlength="200" autocomplete="current-password" required></label>
        <div class="investment-review-form__actions">
          <button type="submit">保存日志</button>
          <button type="button" id="investment-review-cancel">取消</button>
          <span id="investment-review-form-status" role="status"></span>
        </div>
      </form>
      <div class="investment-review-notes" id="investment-review-notes"></div>
      <p class="investment-empty" id="investment-review-notes-empty">当前日期之前还没有决策日志。</p>
    </div>
    <div class="investment-review-quality">
      <h3>数据质量</h3>
      <p>逐账户检查资产、盈亏、持仓和流水是否来自同一结算日。</p>
      <div class="investment-table-wrap">
        <table class="investment-table investment-table--quality">
          <thead><tr><th>账户</th><th>资产快照</th><th>当日盈亏</th><th>持仓快照</th><th>现金</th><th>流水来源</th></tr></thead>
          <tbody id="investment-review-quality"></tbody>
        </table>
      </div>
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
.investment-workspace-nav { display: flex; gap: 1.5rem; margin-top: 1.4rem; overflow-x: auto; border-bottom: 1px solid var(--border-strong); }
.investment-workspace-nav a { position: relative; flex: 0 0 auto; padding: .65rem 0 .75rem; color: var(--text-muted); font: 650 .88rem/1 var(--font-body); text-decoration: none; }
.investment-workspace-nav a::after { position: absolute; right: 0; bottom: -1px; left: 0; height: 2px; background: var(--color-signal); content: ''; opacity: 0; transform: scaleX(.35); transition: opacity .16s ease, transform .16s ease; }
.investment-workspace-nav a:hover { color: var(--text-strong); }
.investment-workspace-nav a.is-active { color: var(--color-signal); }
.investment-workspace-nav a.is-active::after { opacity: 1; transform: scaleX(1); }
.investment-account-context { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: center; gap: 1rem; margin-top: 1rem; }
.investment-account-context[hidden] { display: none; }
.investment-account-context > span { color: var(--text-dim); font: 650 .7rem/1 var(--font-code); letter-spacing: .06em; text-transform: uppercase; }
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
.investment-ledger__date-actions { position: relative; display: flex; align-items: stretch; gap: .5rem; }
.investment-ledger__date-cluster { display: grid; grid-template-columns: 2.5rem minmax(10.75rem, 1fr) 2.5rem; overflow: hidden; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--bg-elevated); }
.investment-ledger__date-step, .investment-ledger__date-picker, .investment-ledger__date-latest { border: 0; background: transparent; color: var(--text); cursor: pointer; transition: color .16s ease, background-color .16s ease, transform .12s ease; }
.investment-ledger__date-step { min-width: 2.5rem; padding: 0; color: var(--text-muted); font: 500 1.45rem/1 var(--font-body); }
.investment-ledger__date-step:first-child { border-right: 1px solid var(--border-strong); }
.investment-ledger__date-step:last-child { border-left: 1px solid var(--border-strong); }
.investment-ledger__date-picker { position: relative; display: flex; min-height: 42px; padding: .35rem .8rem; align-items: center; justify-content: center; flex-direction: column; cursor: pointer; }
.investment-ledger__date-picker span { color: var(--text-muted); font: .65rem/1.2 var(--font-body); }
.investment-ledger__date-picker time { margin-top: .1rem; color: var(--text-strong); font: 650 .82rem/1.25 var(--font-code); white-space: nowrap; }
.investment-ledger__date-latest { min-height: 44px; padding: .5rem .8rem; border: 1px solid var(--border-strong); border-radius: 6px; color: var(--text-muted); font: 600 .78rem/1 var(--font-body); white-space: nowrap; }
.investment-ledger__date-step:hover, .investment-ledger__date-latest:hover, .investment-ledger__date-picker:hover { background: var(--bg-subtle); color: var(--color-signal); }
.investment-ledger__date-picker:hover time { color: var(--color-signal); }
.investment-ledger__date-step:active, .investment-ledger__date-picker:active, .investment-ledger__date-latest:active { transform: scale(.97); }
.investment-ledger__date-step:focus-visible, .investment-ledger__date-latest:focus-visible, .investment-ledger__date-picker:focus-within { outline: 2px solid var(--color-signal); outline-offset: -2px; }
.investment-ledger__date-actions input:disabled, .investment-ledger__date-actions button:disabled { cursor: wait; opacity: .45; }
.investment-ledger__date-actions button:disabled:hover { background: transparent; color: var(--text-muted); }
.investment-ledger__date-menu { position: absolute; z-index: 4; top: calc(100% + .55rem); right: 0; width: min(22rem, calc(100vw - 2rem)); padding: .8rem; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--bg-elevated); box-shadow: 0 14px 36px rgba(12, 18, 20, .18); }
.investment-ledger__date-menu[hidden] { display: none; }
.investment-ledger__date-menu-head { display: flex; align-items: baseline; justify-content: space-between; gap: .75rem; }
.investment-ledger__date-menu-head strong { color: var(--text-strong); font: 650 .84rem/1.3 var(--font-heading); }
.investment-ledger__date-menu-head span { color: var(--text-muted); font: .7rem/1.3 var(--font-code); }
.investment-ledger__quick-dates { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .35rem; margin-top: .65rem; }
.investment-ledger__quick-dates button { display: flex; min-width: 0; min-height: 38px; align-items: center; justify-content: space-between; gap: .5rem; padding: .45rem .6rem; border: 1px solid transparent; border-radius: 4px; background: var(--bg-subtle); color: var(--text); cursor: pointer; }
.investment-ledger__quick-dates button span { color: var(--text-strong); font: 650 .78rem/1 var(--font-code); }
.investment-ledger__quick-dates button small { color: var(--text-muted); font: .68rem/1 var(--font-body); }
.investment-ledger__quick-dates button:hover { border-color: var(--border-strong); color: var(--color-signal); }
.investment-ledger__quick-dates button.is-active { border-color: var(--color-signal); background: transparent; }
.investment-ledger__quick-dates button.is-active span, .investment-ledger__quick-dates button.is-active small { color: var(--color-signal); }
.investment-ledger__quick-dates button:active { transform: scale(.98); }
.investment-ledger__quick-dates button:focus-visible { outline: 2px solid var(--color-signal); outline-offset: 1px; }
.investment-ledger__exact-date { display: grid; grid-template-columns: auto minmax(0, 1fr); align-items: center; gap: .75rem; margin-top: .75rem; padding-top: .75rem; border-top: 1px solid var(--border-strong); }
.investment-ledger__exact-date span { color: var(--text-muted); font: .76rem/1.3 var(--font-body); }
.investment-ledger__exact-date input { min-width: 0; height: 38px; padding: 0 .6rem; border: 1px solid var(--border-strong); border-radius: 4px; background: var(--bg-subtle); color: var(--text-strong); color-scheme: light dark; font: .8rem/1 var(--font-code); }
.investment-ledger__exact-date input:focus { outline: 2px solid var(--color-signal); outline-offset: 1px; }
.investment-ledger__section { margin-top: 2rem; }
.investment-ledger__section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; margin-bottom: .75rem; }
.investment-ledger__section-head--compact { margin-top: 1.25rem; }
.investment-ledger__section-head h2 { margin: 0; font-size: 1.15rem; letter-spacing: 0; }
.investment-ledger__section-head h3 { margin: 0; color: var(--text-strong); font-size: .92rem; letter-spacing: 0; }
.investment-ledger__section-head span { color: var(--text-muted); font: .8rem/1.4 var(--font-code); }
.investment-ledger__section-head p { margin: .25rem 0 0; color: var(--text-muted); font-size: .78rem; }
.investment-metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid var(--border-strong); border-radius: 6px; overflow: hidden; }
.investment-metric { min-width: 0; padding: 1rem; border-right: 1px solid var(--border-strong); }
.investment-metric:last-child { border-right: 0; }
.investment-metric span { display: block; color: var(--text-muted); font-size: .78rem; }
.investment-metric strong { display: block; margin-top: .35rem; font: 650 1.2rem/1.2 var(--font-code); overflow-wrap: anywhere; }
.investment-metric small { display: block; min-height: 1.3em; margin-top: .35rem; color: var(--text-muted); font: .68rem/1.3 var(--font-code); }
.investment-account-tabs { display: flex; align-items: center; gap: .35rem; overflow-x: auto; }
.investment-account-tabs button { flex: 0 0 auto; min-height: 34px; padding: .45rem .72rem; border: 1px solid transparent; border-radius: 4px; background: transparent; color: var(--text-muted); font: 600 .8rem/1 var(--font-body); cursor: pointer; }
.investment-account-tabs button:hover { border-color: var(--border-strong); color: var(--text-main); }
.investment-account-tabs button.is-active { border-color: var(--border-strong); background: var(--bg-subtle); color: var(--color-signal); }
.investment-daily-brief { margin-top: 1rem; border: 1px solid var(--border-strong); border-radius: 6px; overflow: hidden; }
.investment-daily-brief__head { display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; padding: .85rem 1rem; border-bottom: 1px solid var(--border-strong); }
.investment-daily-brief__head span, .investment-daily-brief__head small { display: block; color: var(--text-muted); font: .72rem/1.35 var(--font-code); }
.investment-daily-brief__head strong { display: block; margin-top: .15rem; color: var(--text-strong); font-size: .95rem; }
.investment-quality { flex: 0 0 auto; padding: .24rem .42rem; border: 1px solid var(--border-strong); border-radius: 3px; color: var(--text-muted); font: 650 .67rem/1 var(--font-code); }
.investment-quality.is-complete { border-color: color-mix(in srgb, #268a63 45%, var(--border-strong)); color: #268a63; }
.investment-quality.is-partial { border-color: color-mix(in srgb, var(--color-amber) 55%, var(--border-strong)); color: var(--color-amber); }
.investment-equation { display: grid; grid-template-columns: minmax(0, 1fr) auto minmax(0, 1fr) auto minmax(0, 1fr) auto minmax(0, 1fr); align-items: center; gap: .6rem; padding: 1rem; }
.investment-equation div { min-width: 0; }
.investment-equation small { display: block; color: var(--text-muted); font-size: .72rem; }
.investment-equation strong { display: block; margin-top: .25rem; color: var(--text-strong); font: 650 1rem/1.2 var(--font-code); overflow-wrap: anywhere; }
.investment-equation > b { color: var(--text-dim); font: 400 1rem/1 var(--font-code); }
.investment-daily-brief__foot { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: .75rem 1rem; border-top: 1px solid var(--border-strong); background: var(--bg-subtle); }
.investment-daily-brief__foot p { margin: 0; color: var(--text-muted); font-size: .74rem; }
.investment-daily-brief__links { display: flex; flex: 0 0 auto; gap: .8rem; }
.investment-daily-brief__links a { color: var(--color-signal); font-size: .75rem; text-decoration: none; }
.investment-analysis-strip { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-bottom: 1rem; border: 1px solid var(--border-strong); border-radius: 6px; overflow: hidden; }
.investment-analysis-item { min-width: 0; padding: .85rem 1rem; border-right: 1px solid var(--border-strong); }
.investment-analysis-item:last-child { border-right: 0; }
.investment-analysis-item span, .investment-analysis-item small { display: block; color: var(--text-muted); font-size: .7rem; }
.investment-analysis-item strong { display: block; margin-top: .25rem; color: var(--text-strong); font: 650 1rem/1.25 var(--font-code); overflow-wrap: anywhere; }
.investment-analysis-item small { margin-top: .28rem; color: var(--text-dim); line-height: 1.35; }
.investment-analysis-block { margin-bottom: 1rem; }
.investment-allocation-bar { display: flex; height: 7px; overflow: hidden; border-radius: 4px; background: var(--bg-subtle); }
.investment-allocation-bar i { display: block; min-width: 2px; background: var(--segment-color); }
.investment-allocation-legend { display: flex; flex-wrap: wrap; gap: .45rem 1rem; margin-top: .55rem; color: var(--text-muted); font-size: .72rem; }
.investment-allocation-legend span { display: inline-flex; align-items: center; gap: .35rem; }
.investment-allocation-legend i { width: .45rem; height: .45rem; border-radius: 50%; background: var(--segment-color); }
.investment-source-badge, .investment-quality-badge { display: inline-flex; align-items: center; min-height: 1.4rem; padding: .15rem .38rem; border: 1px solid var(--border-strong); border-radius: 3px; color: var(--text-muted); font: 650 .65rem/1 var(--font-code); }
.investment-source-badge.is-platform, .investment-quality-badge.is-complete { color: #268a63; }
.investment-source-badge.is-inferred, .investment-quality-badge.is-partial { color: var(--color-amber); }
.investment-quality-badge.is-missing { color: var(--text-dim); }
.investment-table-wrap { overflow-x: auto; border: 1px solid var(--border-strong); border-radius: 6px; }
.investment-table { width: 100%; margin: 0; font-size: .84rem; }
.investment-table th, .investment-table td { white-space: nowrap; text-align: right; }
.investment-table th:first-child, .investment-table td:first-child { padding-left: .75rem; }
.investment-table--accounts { min-width: 1080px; }
.investment-table--holdings { min-width: 2000px; }
.investment-table--trades { min-width: 1220px; }
.investment-table--cash-flows { min-width: 900px; }
.investment-table--performance { min-width: 880px; }
.investment-table--quality { min-width: 720px; }
.investment-table--holdings th:nth-child(-n+4), .investment-table--holdings td:nth-child(-n+4),
.investment-table--trades th:nth-child(-n+5), .investment-table--trades td:nth-child(-n+5),
.investment-table--cash-flows th:nth-child(-n+4), .investment-table--cash-flows td:nth-child(-n+4),
.investment-table--accounts th:first-child, .investment-table--accounts td:first-child { text-align: left; }
.investment-ledger .is-positive { color: #d84b57; }
.investment-ledger .is-negative { color: #268a63; }
.investment-account-change strong, .investment-account-change small { display: block; }
.investment-account-change strong { font: 600 .82rem/1.25 var(--font-code); }
.investment-account-change small { margin-top: .18rem; color: var(--text-muted); font: .68rem/1.25 var(--font-code); }
.investment-ledger__performance { border-top: 1px solid var(--border-strong); padding-top: 1.5rem; }
.investment-performance-tabs { display: inline-flex; margin-bottom: .75rem; border: 1px solid var(--border-strong); border-radius: 5px; overflow: hidden; }
.investment-performance-tabs button { min-width: 4.5rem; padding: .52rem .9rem; border: 0; border-right: 1px solid var(--border-strong); background: transparent; color: var(--text-muted); font: 600 .8rem/1 var(--font-body); cursor: pointer; }
.investment-performance-tabs button:last-child { border-right: 0; }
.investment-performance-tabs button:hover { color: var(--color-signal); background: var(--bg-subtle); }
.investment-performance-tabs button.is-active { color: var(--color-signal); background: var(--bg-subtle); }
.investment-performance-tabs button:focus-visible { outline: 2px solid var(--color-signal); outline-offset: -2px; }
.investment-benchmark { margin: 1rem 0; padding: 1rem; border: 1px solid var(--border-strong); border-radius: 6px; background: var(--bg-subtle); }
.investment-benchmark .investment-ledger__section-head { margin-bottom: .8rem; }
.investment-benchmark label { display: grid; gap: .25rem; color: var(--text-muted); font-size: .7rem; }
.investment-benchmark select { min-width: 9rem; padding: .45rem .6rem; border: 1px solid var(--border-strong); border-radius: 4px; background: var(--bg-elevated); color: var(--text-strong); font: 600 .75rem/1.2 var(--font-body); }
.investment-performance-coverage { color: var(--text-muted); font: .72rem/1.25 var(--font-code); }
.investment-performance-note { margin: .65rem 0 0; color: var(--text-dim); font-size: .76rem; }
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
.investment-ledger__review { border-top: 1px solid var(--border-strong); padding-top: 1.5rem; }
.investment-review-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); border: 1px solid var(--border-strong); border-radius: 6px; overflow: hidden; }
.investment-review-item { min-width: 0; padding: 1rem; border-right: 1px solid var(--border-strong); }
.investment-review-item:last-child { border-right: 0; }
.investment-review-item span { display: block; color: var(--text-muted); font-size: .72rem; }
.investment-review-item strong { display: block; margin-top: .3rem; color: var(--text-strong); font: 650 1rem/1.25 var(--font-code); overflow-wrap: anywhere; }
.investment-review-item small { display: block; margin-top: .35rem; color: var(--text-dim); font-size: .7rem; }
.investment-review-alerts { margin-top: 1rem; padding: 1rem; border: 1px solid var(--border-strong); border-radius: 6px; }
.investment-review-alerts h3 { margin: 0 0 .65rem; color: var(--text-strong); font-size: .9rem; }
.investment-review-alerts ul { display: grid; gap: .45rem; margin: 0; padding: 0; list-style: none; }
.investment-review-alerts li { position: relative; padding-left: 1rem; color: var(--text-muted); font-size: .8rem; }
.investment-review-alerts li::before { position: absolute; top: .55em; left: 0; width: .35rem; height: .35rem; border-radius: 50%; background: var(--text-dim); content: ''; }
.investment-review-alerts li.is-warning::before { background: var(--color-amber); }
.investment-review-alerts li.is-ok::before { background: #268a63; }
.investment-review-journal { margin-top: 1rem; padding: 1rem; border: 1px solid var(--border-strong); border-radius: 6px; }
.investment-review-journal h3 { margin: 0; color: var(--text-strong); font-size: .9rem; }
.investment-review-journal button { padding: .5rem .72rem; border: 1px solid var(--border-strong); border-radius: 4px; background: transparent; color: var(--text-strong); font: 600 .75rem/1 var(--font-body); cursor: pointer; }
.investment-review-journal button:hover { border-color: var(--color-signal); color: var(--color-signal); }
.investment-review-form { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; margin: 1rem 0; padding: 1rem; background: var(--bg-subtle); border-radius: 5px; }
.investment-review-form[hidden] { display: none; }
.investment-review-form label { display: grid; gap: .3rem; color: var(--text-muted); font-size: .72rem; }
.investment-review-form textarea, .investment-review-form input { box-sizing: border-box; width: 100%; padding: .55rem .65rem; border: 1px solid var(--border-strong); border-radius: 4px; background: var(--bg-elevated); color: var(--text-strong); font: 400 .78rem/1.5 var(--font-body); }
.investment-review-form textarea { min-height: 5rem; resize: vertical; }
.investment-review-form__actions { grid-column: 1 / -1; display: flex; align-items: center; gap: .6rem; }
.investment-review-form__actions span { color: var(--text-muted); font-size: .72rem; }
.investment-review-notes { display: grid; gap: .7rem; }
.investment-review-note { padding: .8rem 0; border-top: 1px solid var(--border-strong); }
.investment-review-note:first-child { border-top: 0; }
.investment-review-note__meta { display: flex; flex-wrap: wrap; gap: .4rem .8rem; color: var(--text-dim); font: 600 .68rem/1.3 var(--font-code); }
.investment-review-note dl { display: grid; grid-template-columns: auto 1fr; gap: .3rem .7rem; margin: .55rem 0 0; }
.investment-review-note dt { color: var(--text-dim); font-size: .7rem; }
.investment-review-note dd { margin: 0; color: var(--text-muted); font-size: .78rem; white-space: pre-wrap; }
.investment-review-quality { margin-top: 1rem; }
.investment-review-quality h3 { margin: 0; color: var(--text-strong); font-size: .9rem; }
.investment-review-quality > p { margin: .25rem 0 .65rem; color: var(--text-muted); font-size: .74rem; }
.investment-table--quality th, .investment-table--quality td { text-align: left; }
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
  .investment-ledger__date-menu { right: 0; }
  .investment-account-context { grid-template-columns: 1fr; gap: .4rem; }
  .investment-equation { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .investment-equation > b { display: none; }
  .investment-daily-brief__foot { align-items: flex-start; flex-direction: column; }
  .investment-review-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .investment-review-item:nth-child(2) { border-right: 0; }
  .investment-review-item:nth-child(-n+2) { border-bottom: 1px solid var(--border-strong); }
  .investment-analysis-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .investment-analysis-item:nth-child(2) { border-right: 0; }
  .investment-analysis-item:nth-child(-n+2) { border-bottom: 1px solid var(--border-strong); }
  .investment-review-form { grid-template-columns: 1fr; }
  .investment-review-form__actions { grid-column: 1; }
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
  var dateActions = dateFilter.querySelector('.investment-ledger__date-actions');
  var dateInput = document.getElementById('investment-date');
  var dateTrigger = document.getElementById('investment-date-trigger');
  var dateMenu = document.getElementById('investment-date-menu');
  var quickDates = document.getElementById('investment-quick-dates');
  var dateDisplay = document.getElementById('investment-date-display');
  var dateResolution = document.getElementById('investment-date-resolution');
  var datePrev = document.getElementById('investment-date-prev');
  var dateNext = document.getElementById('investment-date-next');
  var dateLatest = document.getElementById('investment-date-latest');
  var workspaceViews = ['overview', 'performance', 'holdings', 'activity', 'review'];
  var requestedWorkspaceView = new URL(window.location.href).searchParams.get('view');
  var state = {
    data: null,
    accounts: [],
    selectedAccount: 'all',
    workspaceView: workspaceViews.indexOf(requestedWorkspaceView) >= 0 ? requestedWorkspaceView : 'overview',
    performanceView: 'day',
    selectedBenchmark: '',
    requestedDate: '',
    latestSettledDate: '',
    requestSequence: 0,
    loading: false,
  };

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
  function formatPercent(value) {
    var parsed = number(value);
    return parsed === null ? '-' : formatNumber(parsed, 2) + '%';
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

  function analysisItemsMarkup(items) {
    return items.map(function (item) {
      return '<div class="investment-analysis-item"><span>' + escapeHtml(item[0]) + '</span>'
        + '<strong class="' + escapeHtml(item[2] || '') + '">' + escapeHtml(item[1]) + '</strong>'
        + '<small>' + escapeHtml(item[3] || '') + '</small></div>';
    }).join('');
  }
  function completeSum(items, field) {
    if (!items.length) return null;
    var values = items.map(function (item) { return number(item[field]); });
    if (values.some(function (value) { return value === null; })) return null;
    return values.reduce(function (result, value) { return result + value; }, 0);
  }

  function fieldCoverage(items, field) {
    var known = []; var missing = [];
    items.forEach(function (item) {
      var value = number(item[field]);
      if (value === null) missing.push(item.account_name || '未命名账户');
      else known.push(value);
    });
    return {
      value: known.length ? known.reduce(function (result, value) { return result + value; }, 0) : null,
      known: known.length,
      total: items.length,
      missing: missing,
      complete: items.length > 0 && known.length === items.length,
    };
  }

  function previousAccountSnapshot(account) {
    var snapshots = Array.isArray(state.data.portfolio_snapshots) ? state.data.portfolio_snapshots : [];
    var currentDate = String(account.snapshot_date || '');
    var accountName = String(account.account_name || '').trim();
    var candidates = snapshots.filter(function (item) {
      return item.account_key === account.account_key
        && item.snapshot_date < currentDate
        && number(item.total_asset) !== null;
    });
    if (!candidates.length && accountName) {
      candidates = snapshots.filter(function (item) {
        return String(item.account_name || '').trim() === accountName
          && item.snapshot_date < currentDate
          && number(item.total_asset) !== null;
      });
    }
    return candidates.sort(function (a, b) {
      if (a.snapshot_date !== b.snapshot_date) return a.snapshot_date < b.snapshot_date ? 1 : -1;
      return String(a.captured_at || '') < String(b.captured_at || '') ? 1 : -1;
    })[0] || null;
  }

  function accountChangeCell(account) {
    var previous = previousAccountSnapshot(account);
    var currentAsset = number(account.total_asset);
    var previousAsset = previous ? number(previous.total_asset) : null;
    if (currentAsset === null || previousAsset === null) return '<td class="investment-account-change">-</td>';
    var change = currentAsset - previousAsset;
    var rate = previousAsset === 0 ? null : change / Math.abs(previousAsset) * 100;
    return '<td class="investment-account-change ' + valueClass(change) + '"><strong>' + formatSigned(change) + '</strong>'
      + '<small>' + formatRate(rate) + ' · 较 ' + escapeHtml(previous.snapshot_date.slice(5)) + '</small></td>';
  }

  function latestAccounts(data) {
    var snapshots = Array.isArray(data.portfolio_snapshots) ? data.portfolio_snapshots : [];
    var latest = snapshots.reduce(function (date, item) { return item.snapshot_date > date ? item.snapshot_date : date; }, '');
    var rows = snapshots.filter(function (item) { return item.snapshot_date === latest; });
    var specific = rows.filter(function (item) { return item.account_key !== 'all'; });
    if (specific.length) rows = specific;
    var latestByIdentity = {};
    rows.forEach(function (item) {
      var name = String(item.account_name || '').trim();
      var identity = name ? 'name:' + name : 'key:' + item.account_key;
      var current = latestByIdentity[identity];
      if (!current || String(item.captured_at || '') >= String(current.captured_at || '')) latestByIdentity[identity] = item;
    });
    return Object.keys(latestByIdentity).map(function (identity) { return latestByIdentity[identity]; }).sort(function (a, b) {
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

  function selectedAccounts() {
    if (state.selectedAccount === 'all') return state.accounts;
    return state.accounts.filter(function (item) { return item.account_key === state.selectedAccount; });
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
    trades = trades.filter(function (item) { return !isInferredOperation(item); });
    return state.selectedAccount === 'all' ? trades : trades.filter(function (item) { return item.account_key === state.selectedAccount; });
  }

  function selectedCashFlows() {
    var records = Array.isArray(state.data.cash_flows) ? state.data.cash_flows.slice() : [];
    var legacy = (Array.isArray(state.data.operations) ? state.data.operations : []).filter(isInferredOperation).map(function (item) {
      var outflow = String(item.operation || '').indexOf('转出') >= 0 || String(item.operation || '').indexOf('赎回') >= 0 || item.side === 'sell';
      return {
        occurred_at: item.occurred_at,
        account_key: item.account_key,
        account_name: item.account_name,
        account_type: item.account_type,
        direction: outflow ? 'out' : 'in',
        category: outflow ? 'fund_redemption' : 'fund_subscription',
        amount: item.amount,
        currency: 'CNY',
        source_kind: 'inferred',
        confidence: 0.5,
        status: 'pending',
        note: item.note,
      };
    });
    var seen = {};
    records.concat(legacy).forEach(function (item) {
      var key = [String(item.occurred_at || '').slice(0, 10), item.account_key, item.direction, number(item.amount)].join('|');
      var existing = seen[key];
      if (!existing || (existing.source_kind === 'inferred' && item.source_kind !== 'inferred')) seen[key] = item;
    });
    records = Object.keys(seen).map(function (key) { return seen[key]; }).filter(function (item) { return item.status !== 'rejected'; });
    if (state.selectedAccount !== 'all') records = records.filter(function (item) { return item.account_key === state.selectedAccount; });
    return records.sort(function (a, b) { return String(a.occurred_at || '') < String(b.occurred_at || '') ? 1 : -1; });
  }

  function renderMetrics() {
    var holdings = selectedHoldings();
    var accounts = selectedAccounts();
    var totalAsset = completeSum(accounts, 'total_asset');
    var totalPnl = completeSum(accounts, 'total_pnl');
    var dayPnl = fieldCoverage(accounts, 'day_pnl');
    var dayPnlDetail = dayPnl.complete
      ? dayPnl.known + '/' + dayPnl.total + ' 个账户已确认'
      : (dayPnl.known ? '已采集 ' + dayPnl.known + '/' + dayPnl.total + ' · 缺少 ' + dayPnl.missing.join('、') : '暂无账户返回当日盈亏');
    var metrics = [
      ['账户总资产', formatMoney(totalAsset), '', ''],
      ['持有盈亏', formatSigned(totalPnl), valueClass(totalPnl), ''],
      ['当日盈亏', formatSigned(dayPnl.value), valueClass(dayPnl.value), dayPnlDetail],
      ['当前持仓', holdings.length + ' 项', '', '分账户按最近可用日期'],
    ];
    document.getElementById('investment-metrics').innerHTML = metrics.map(function (item) {
      return '<div class="investment-metric"><span>' + item[0] + '</span><strong class="' + item[2] + '">' + item[1] + '</strong><small>' + escapeHtml(item[3] || '') + '</small></div>';
    }).join('');
  }

  function renderDailyBrief() {
    var accounts = selectedAccounts();
    var previous = accounts.map(previousAccountSnapshot);
    var endingAsset = completeSum(accounts, 'total_asset');
    var openingAsset = previous.length && previous.every(Boolean) ? completeSum(previous, 'total_asset') : null;
    var dayPnl = fieldCoverage(accounts, 'day_pnl');
    var date = state.data.resolved_snapshot_date || state.data.latest_snapshot_date || (accounts[0] && accounts[0].snapshot_date) || '-';
    var cashFlows = selectedCashFlows().filter(function (item) { return String(item.occurred_at || '').slice(0, 10) === date; });
    var recordedNetFlow = cashFlows.length ? cashFlows.reduce(function (sum, item) {
      var amount = number(item.amount) || 0;
      return sum + (item.direction === 'out' ? -amount : amount);
    }, 0) : null;
    var derivedNetFlow = endingAsset !== null && openingAsset !== null && dayPnl.complete
      ? endingAsset - openingAsset - dayPnl.value : null;
    if (derivedNetFlow !== null && Math.abs(derivedNetFlow) < 100) derivedNetFlow = 0;
    var netFlow = recordedNetFlow !== null ? recordedNetFlow : derivedNetFlow;
    var residual = recordedNetFlow !== null && derivedNetFlow !== null ? derivedNetFlow - recordedNetFlow : null;
    var complete = endingAsset !== null && openingAsset !== null && dayPnl.complete && (residual === null || Math.abs(residual) < 100);
    var hasConfirmedFlow = cashFlows.length && cashFlows.every(function (item) { return item.status === 'confirmed' && item.source_kind !== 'inferred'; });
    var qualityLabel = !complete ? '数据待补齐' : (hasConfirmedFlow ? '原始流水可核对' : '推算口径可核对');
    var detail = !complete
      ? '当前缺少期初资产、部分账户盈亏，或原始资金流与资产变化无法勾稽。'
      : hasConfirmedFlow
        ? '外部净流入来自已确认资金流水；等式差额低于 100 元视为估值与舍入误差。'
      : '当前缺少期初资产或部分账户当日盈亏，资金流与收益无法完整拆分。';
    if (complete && !hasConfirmedFlow) detail = '外部净流入仍按资产变化扣除投资盈亏推算，不等同银行或平台原始流水。';
    document.getElementById('investment-daily-brief').innerHTML = ''
      + '<div class="investment-daily-brief__head"><div><span>资产变化解释</span><strong>' + escapeHtml(accountLabel(state.selectedAccount)) + ' · ' + escapeHtml(date) + '</strong></div>'
      + '<span class="investment-quality ' + (complete ? 'is-complete' : 'is-partial') + '">' + qualityLabel + '</span></div>'
      + '<div class="investment-equation">'
      + '<div><small>期初资产</small><strong>' + formatMoney(openingAsset) + '</strong></div><b>+</b>'
      + '<div><small>外部净流入</small><strong class="' + valueClass(netFlow) + '">' + formatSigned(netFlow) + '</strong></div><b>+</b>'
      + '<div><small>投资盈亏</small><strong class="' + valueClass(dayPnl.value) + '">' + formatSigned(dayPnl.value) + '</strong></div><b>=</b>'
      + '<div><small>期末资产</small><strong>' + formatMoney(endingAsset) + '</strong></div></div>'
      + '<div class="investment-daily-brief__foot"><p>' + escapeHtml(detail) + '</p><nav class="investment-daily-brief__links" aria-label="继续分析">'
      + '<a href="?view=performance" data-workspace-view="performance">看绩效</a><a href="?view=holdings" data-workspace-view="holdings">查持仓</a><a href="?view=review" data-workspace-view="review">看线索</a></nav></div>';
  }

  function renderAccountTabs() {
    var tabs = [{ account_key: 'all', account_name: '汇总持仓' }].concat(state.accounts);
    document.getElementById('investment-account-tabs').innerHTML = tabs.map(function (item) {
      var active = item.account_key === state.selectedAccount;
      return '<button type="button" role="tab" data-account="' + escapeHtml(item.account_key) + '" class="' + (active ? 'is-active' : '') + '" aria-selected="' + active + '">' + escapeHtml(item.account_name || '未命名账户') + '</button>';
    }).join('');
    document.getElementById('investment-account-context').hidden = false;
  }

  function renderAccounts() {
    var body = document.getElementById('investment-accounts');
    var rows = selectedAccounts();
    body.innerHTML = rows.map(function (item) {
      return '<tr><td>' + escapeHtml(item.account_name || '未命名账户') + '</td>'
        + '<td>' + formatMoney(item.total_asset) + '</td>'
        + accountChangeCell(item)
        + cell(item.total_pnl, formatSigned) + cell(item.total_return, formatRate)
        + cell(item.day_pnl, formatSigned) + cell(item.day_return, formatRate)
        + '<td>' + formatMoney(item.market_value) + '</td><td>' + formatMoney(item.cash) + '</td></tr>';
    }).join('');
    document.getElementById('investment-account-date').textContent = rows[0] ? rows[0].snapshot_date : '';
  }

  function performanceIdentity(item) {
    var name = String(item.account_name || '').trim();
    return name ? 'name:' + name : 'key:' + item.account_key;
  }

  function performanceDailyRows() {
    var snapshots = Array.isArray(state.data.portfolio_snapshots) ? state.data.portfolio_snapshots : [];
    if (snapshots.some(function (item) { return item.account_key !== 'all'; })) {
      snapshots = snapshots.filter(function (item) { return item.account_key !== 'all'; });
    }
    if (state.selectedAccount !== 'all') {
      var selected = state.accounts.find(function (item) { return item.account_key === state.selectedAccount; });
      var selectedName = String(selected && selected.account_name || '').trim();
      snapshots = snapshots.filter(function (item) {
        return item.account_key === state.selectedAccount
          || (selectedName && String(item.account_name || '').trim() === selectedName);
      });
    }

    var latestByPoint = {};
    snapshots.forEach(function (item) {
      if (!item.snapshot_date || number(item.total_asset) === null) return;
      var key = item.snapshot_date + '|' + performanceIdentity(item);
      var current = latestByPoint[key];
      if (!current || String(item.captured_at || '') >= String(current.captured_at || '')) latestByPoint[key] = item;
    });
    var records = Object.keys(latestByPoint).map(function (key) { return latestByPoint[key]; });
    var identities = Array.from(new Set(records.map(performanceIdentity)));
    var dates = Array.from(new Set(records.map(function (item) { return item.snapshot_date; }))).sort();
    var byIdentity = {};
    identities.forEach(function (identity) { byIdentity[identity] = []; });
    records.forEach(function (item) { byIdentity[performanceIdentity(item)].push(item); });
    identities.forEach(function (identity) {
      byIdentity[identity].sort(function (a, b) { return a.snapshot_date < b.snapshot_date ? -1 : 1; });
    });
    var cashFlowsByPoint = {};
    selectedCashFlows().forEach(function (item) {
      var date = String(item.occurred_at || '').slice(0, 10);
      if (!date) return;
      var key = date + '|' + performanceIdentity(item);
      if (!cashFlowsByPoint[key]) cashFlowsByPoint[key] = [];
      cashFlowsByPoint[key].push(item);
    });

    return dates.map(function (date) {
      var asset = 0; var assetKnown = 0;
      var profit = 0; var profitKnown = 0;
      var inflow = 0; var outflow = 0; var flowKnown = 0; var flowConfirmed = 0; var flowInferred = 0;
      identities.forEach(function (identity) {
        var series = byIdentity[identity];
        var currentIndex = -1; var latest = null;
        for (var index = 0; index < series.length; index += 1) {
          if (series[index].snapshot_date <= date) latest = series[index];
          if (series[index].snapshot_date === date) currentIndex = index;
          if (series[index].snapshot_date > date) break;
        }
        if (latest && number(latest.total_asset) !== null) {
          asset += number(latest.total_asset); assetKnown += 1;
        }
        if (currentIndex < 0) return;
        var current = series[currentIndex];
        var dayPnl = number(current.day_pnl);
        if (dayPnl !== null) { profit += dayPnl; profitKnown += 1; }
        var previous = currentIndex > 0 ? series[currentIndex - 1] : null;
        var currentAsset = number(current.total_asset);
        var previousAsset = previous ? number(previous.total_asset) : null;
        var observedFlows = cashFlowsByPoint[date + '|' + identity] || [];
        if (observedFlows.length) {
          observedFlows.forEach(function (flowRecord) {
            var amount = number(flowRecord.amount) || 0;
            if (flowRecord.direction === 'out') outflow += amount; else inflow += amount;
          });
          flowKnown += 1;
          if (observedFlows.every(function (flowRecord) { return flowRecord.status === 'confirmed' && flowRecord.source_kind !== 'inferred'; })) flowConfirmed += 1;
          else flowInferred += 1;
          return;
        }
        if (dayPnl === null || currentAsset === null || previousAsset === null) return;
        var flow = currentAsset - previousAsset - dayPnl;
        if (Math.abs(flow) < 100) flow = 0;
        if (flow >= 0) inflow += flow; else outflow += Math.abs(flow);
        flowKnown += 1;
        flowInferred += 1;
      });
      return {
        date: date,
        asset: assetKnown === identities.length && identities.length ? asset : null,
        inflow: flowKnown ? inflow : null,
        outflow: flowKnown ? outflow : null,
        netFlow: flowKnown ? inflow - outflow : null,
        profit: profitKnown ? profit : null,
        profitKnown: profitKnown,
        flowKnown: flowKnown,
        flowConfirmed: flowConfirmed,
        flowInferred: flowInferred,
        total: identities.length,
      };
    });
  }

  function performanceRows(view) {
    var daily = performanceDailyRows();
    var referenceDate = state.data.resolved_snapshot_date || state.data.latest_snapshot_date || (daily.length ? daily[daily.length - 1].date : '');
    if (view === 'day' && referenceDate) daily = daily.filter(function (row) { return row.date.slice(0, 7) === referenceDate.slice(0, 7); });
    if (view === 'month' && referenceDate) daily = daily.filter(function (row) { return row.date.slice(0, 4) === referenceDate.slice(0, 4); });
    var grouped = {};
    daily.forEach(function (row) {
      var key = view === 'day' ? row.date : (view === 'month' ? row.date.slice(0, 7) : row.date.slice(0, 4));
      if (!grouped[key]) grouped[key] = {
        period: key, asset: null, inflow: 0, outflow: 0, profit: 0,
        profitKnown: 0, flowKnown: 0, flowConfirmed: 0, flowInferred: 0, profitTotal: 0, flowTotal: 0,
      };
      var result = grouped[key];
      if (row.asset !== null) result.asset = row.asset;
      if (row.inflow !== null) result.inflow += row.inflow;
      if (row.outflow !== null) result.outflow += row.outflow;
      if (row.profit !== null) result.profit += row.profit;
      result.profitKnown += row.profitKnown;
      result.flowKnown += row.flowKnown;
      result.flowConfirmed += row.flowConfirmed;
      result.flowInferred += row.flowInferred;
      result.profitTotal += row.total;
      result.flowTotal += row.total;
    });
    return Object.keys(grouped).sort().map(function (key) {
      var row = grouped[key];
      row.inflow = row.flowKnown ? row.inflow : null;
      row.outflow = row.flowKnown ? row.outflow : null;
      row.netFlow = row.flowKnown ? row.inflow - row.outflow : null;
      row.profit = row.profitKnown ? row.profit : null;
      var base = row.asset !== null && row.netFlow !== null && row.profit !== null
        ? row.asset - row.netFlow - row.profit : null;
      row.returnRate = base === null || base === 0 ? null : row.profit / Math.abs(base) * 100;
      return row;
    });
  }

  function performancePeriodDailyRows(view) {
    var rows = performanceDailyRows();
    var referenceDate = state.data.resolved_snapshot_date || state.data.latest_snapshot_date || (rows.length ? rows[rows.length - 1].date : '');
    if (view === 'day' && referenceDate) return rows.filter(function (row) { return row.date.slice(0, 7) === referenceDate.slice(0, 7); });
    if (view === 'month' && referenceDate) return rows.filter(function (row) { return row.date.slice(0, 4) === referenceDate.slice(0, 4); });
    return rows;
  }

  function renderPerformanceSummary() {
    var daily = performancePeriodDailyRows(state.performanceView);
    var valid = daily.map(function (row) {
      if (row.asset === null || row.profit === null || row.netFlow === null || row.profitKnown !== row.total || row.flowKnown !== row.total) return null;
      var base = row.asset - row.netFlow - row.profit;
      if (!Number.isFinite(base) || base === 0) return null;
      return { date: row.date, rate: row.profit / Math.abs(base) };
    }).filter(Boolean);
    var nav = 1; var peak = 1; var maxDrawdown = 0;
    valid.forEach(function (row) {
      nav *= 1 + row.rate;
      peak = Math.max(peak, nav);
      maxDrawdown = Math.min(maxDrawdown, nav / peak - 1);
    });
    var sorted = valid.slice().sort(function (a, b) { return b.rate - a.rate; });
    var best = sorted[0] || null;
    var worst = sorted.length ? sorted[sorted.length - 1] : null;
    var wins = valid.filter(function (row) { return row.rate > 0; }).length;
    var hitRate = valid.length ? wins / valid.length * 100 : null;
    var cumulative = valid.length ? (nav - 1) * 100 : null;
    document.getElementById('investment-performance-summary').innerHTML = analysisItemsMarkup([
      ['有效日复合收益', formatRate(cumulative), valueClass(cumulative), '仅使用账户覆盖完整的交易日'],
      ['区间最大回撤', formatRate(maxDrawdown * 100), valueClass(maxDrawdown), '按有效日收益构建净值曲线'],
      ['上涨日占比', formatPercent(hitRate), valueClass(hitRate), valid.length ? wins + '/' + valid.length + ' 个有效日' : '暂无完整收益日'],
      ['最好 / 最差日', best ? formatRate(best.rate * 100) + ' / ' + formatRate(worst.rate * 100) : '-', '', best ? best.date.slice(5) + ' / ' + worst.date.slice(5) : '覆盖 ' + valid.length + '/' + daily.length],
    ]);
    renderBenchmarkSummary(valid, daily);
  }

  function renderBenchmarkSummary(validPortfolioDays, scopedDailyRows) {
    var records = Array.isArray(state.data.benchmarks) ? state.data.benchmarks : [];
    var byKey = {};
    records.forEach(function (item) {
      if (!item.benchmark_key || number(item.close_value) === null || !item.snapshot_date) return;
      if (!byKey[item.benchmark_key]) byKey[item.benchmark_key] = [];
      byKey[item.benchmark_key].push(item);
    });
    var keys = Object.keys(byKey);
    var select = document.getElementById('investment-benchmark-select');
    if (!keys.length) {
      state.selectedBenchmark = '';
      select.innerHTML = '<option value="">尚未配置</option>';
      select.disabled = true;
      document.getElementById('investment-benchmark-summary').innerHTML = analysisItemsMarkup([
        ['组合收益', '-', '', '等待完整收益日'],
        ['基准收益', '-', '', '尚未同步基准净值'],
        ['几何超额', '-', '', '需要同区间组合与基准数据'],
        ['重合交易日', '0 天', '', '不会用错位日期强行比较'],
      ]);
      document.getElementById('investment-benchmark-note').textContent = '基准表已准备好；在同步沪深 300、标普 500 或自定义基准前，不显示虚假的超额收益。';
      return;
    }
    keys.forEach(function (key) { byKey[key].sort(function (a, b) { return a.snapshot_date < b.snapshot_date ? -1 : 1; }); });
    if (!state.selectedBenchmark || keys.indexOf(state.selectedBenchmark) < 0) state.selectedBenchmark = keys[0];
    select.disabled = false;
    select.innerHTML = keys.map(function (key) {
      var label = byKey[key][0].benchmark_name || key;
      return '<option value="' + escapeHtml(key) + '"' + (key === state.selectedBenchmark ? ' selected' : '') + '>' + escapeHtml(label) + '</option>';
    }).join('');
    var validByDate = {};
    validPortfolioDays.forEach(function (item) { validByDate[item.date] = item.rate; });
    var scopeDates = new Set(scopedDailyRows.map(function (item) { return item.date; }));
    var overlap = byKey[state.selectedBenchmark].filter(function (item) {
      return scopeDates.has(item.snapshot_date) && validByDate[item.snapshot_date] !== undefined;
    });
    var portfolioNav = 1;
    overlap.forEach(function (item) { portfolioNav *= 1 + validByDate[item.snapshot_date]; });
    var portfolioReturn = overlap.length ? (portfolioNav - 1) * 100 : null;
    var benchmarkReturn = overlap.length > 1
      ? (number(overlap[overlap.length - 1].close_value) / number(overlap[0].close_value) - 1) * 100 : null;
    var excess = portfolioReturn === null || benchmarkReturn === null
      ? null : ((1 + portfolioReturn / 100) / (1 + benchmarkReturn / 100) - 1) * 100;
    document.getElementById('investment-benchmark-summary').innerHTML = analysisItemsMarkup([
      ['组合收益', formatRate(portfolioReturn), valueClass(portfolioReturn), '仅使用与基准重合的完整收益日'],
      ['基准收益', formatRate(benchmarkReturn), valueClass(benchmarkReturn), byKey[state.selectedBenchmark][0].benchmark_name || state.selectedBenchmark],
      ['几何超额', formatRate(excess), valueClass(excess), '组合净值 ÷ 基准净值 − 1'],
      ['重合交易日', overlap.length + ' 天', '', overlap.length ? overlap[0].snapshot_date + ' 至 ' + overlap[overlap.length - 1].snapshot_date : '当前周期无可比日期'],
    ]);
    document.getElementById('investment-benchmark-note').textContent = overlap.length > 1
      ? '组合与基准严格使用同一组有效交易日；缺失日期不会前向填充。'
      : '至少需要两个重合且组合数据完整的交易日，才能计算基准收益与超额。';
  }

  function renderPerformance() {
    var rows = performanceRows(state.performanceView).reverse();
    var labels = { day: '按日', month: '按月', year: '按年' };
    document.querySelectorAll('.investment-performance-tabs button').forEach(function (button) {
      var active = button.getAttribute('data-period') === state.performanceView;
      button.classList.toggle('is-active', active); button.setAttribute('aria-selected', String(active));
    });
    document.getElementById('investment-performance-scope').textContent = accountLabel(state.selectedAccount) + ' · ' + labels[state.performanceView];
    document.getElementById('investment-performance').innerHTML = rows.map(function (row) {
      var profitCoverage = row.profitKnown + '/' + row.profitTotal;
      var flowCoverage = row.flowKnown + '/' + row.flowTotal;
      var flowSource = row.flowConfirmed ? '原始 ' + row.flowConfirmed : '';
      if (row.flowInferred) flowSource += (flowSource ? ' / ' : '') + '推算 ' + row.flowInferred;
      var rateText = formatRate(row.returnRate);
      if (row.returnRate !== null && (row.profitKnown < row.profitTotal || row.flowKnown < row.flowTotal)) rateText = '≈' + rateText;
      return '<tr><td>' + escapeHtml(row.period) + '</td><td>' + formatMoney(row.asset) + '</td>'
        + cell(row.inflow, formatSigned) + cell(row.outflow === null ? null : -row.outflow, formatSigned)
        + cell(row.netFlow, formatSigned) + cell(row.profit, formatSigned) + '<td class="' + valueClass(row.returnRate) + '">' + rateText + '</td>'
        + '<td class="investment-performance-coverage">盈亏 ' + profitCoverage + ' · 资金 ' + flowCoverage + (flowSource ? '（' + flowSource + '）' : '') + '</td></tr>';
    }).join('');
    var note = state.performanceView === 'day'
      ? '当前显示所选日期所在月份。资金流动按“资产变化 − 当日盈亏”推算；低于 100 元的差额视为估值与舍入误差。'
      : '区间收益率采用期末资产、净流入和已采集投资收益的简单口径；覆盖不足时结果仅代表已采集部分。';
    document.getElementById('investment-performance-note').textContent = note;
    document.getElementById('investment-performance-section').dataset.hasData = rows.length ? 'true' : 'false';
    renderPerformanceSummary();
  }

  function renderAllocationSummary(rows) {
    var valued = rows.filter(function (item) { return number(item.market_value) !== null && number(item.market_value) > 0; });
    var holdingValue = valued.reduce(function (sum, item) { return sum + number(item.market_value); }, 0);
    var sorted = valued.slice().sort(function (a, b) { return number(b.market_value) - number(a.market_value); });
    var topOne = holdingValue && sorted.length ? number(sorted[0].market_value) / holdingValue * 100 : null;
    var topFive = holdingValue ? sorted.slice(0, 5).reduce(function (sum, item) { return sum + number(item.market_value); }, 0) / holdingValue * 100 : null;
    var accounts = selectedAccounts();
    var cash = completeSum(accounts, 'cash');
    var totalAsset = completeSum(accounts, 'total_asset');
    var cashRate = totalAsset && cash !== null ? cash / totalAsset * 100 : null;
    var dates = Array.from(new Set(rows.map(function (item) { return item.snapshot_date; }).filter(Boolean))).sort().reverse();
    var groups = {};
    valued.forEach(function (item) {
      var key = item.asset_type === 'fund' ? '基金' : '证券';
      groups[key] = (groups[key] || 0) + number(item.market_value);
    });
    if (cash !== null && cash > 0) groups['现金'] = cash;
    var colors = { '证券': 'var(--color-blue)', '基金': 'var(--color-signal)', '现金': 'var(--color-amber)' };
    var allocationTotal = Object.keys(groups).reduce(function (sum, key) { return sum + groups[key]; }, 0);
    var segments = Object.keys(groups).map(function (key) {
      var rate = allocationTotal ? groups[key] / allocationTotal * 100 : 0;
      return { key: key, value: groups[key], rate: rate, color: colors[key] || 'var(--text-muted)' };
    });
    document.getElementById('investment-allocation-summary').innerHTML = '<div class="investment-analysis-strip">'
      + analysisItemsMarkup([
        ['持仓市值', formatMoney(holdingValue), '', valued.length + ' 项有市值持仓'],
        ['第一大持仓', formatPercent(topOne), '', sorted[0] ? (sorted[0].instrument_name || sorted[0].instrument_code || '-') : '暂无持仓'],
        ['前五集中度', formatPercent(topFive), '', topFive !== null && topFive >= 70 ? '集中度较高' : '按当前持仓市值计算'],
        ['现金仓位', formatPercent(cashRate), '', cash === null ? '账户未返回现金字段' : formatMoney(cash) + ' 元'],
      ]) + '</div>'
      + (segments.length ? '<div class="investment-allocation-bar" aria-label="资产类型配置">' + segments.map(function (item) {
        return '<i style="width:' + item.rate.toFixed(3) + '%;--segment-color:' + item.color + '"></i>';
      }).join('') + '</div><div class="investment-allocation-legend">' + segments.map(function (item) {
        return '<span style="--segment-color:' + item.color + '"><i></i>' + escapeHtml(item.key) + ' ' + formatPercent(item.rate) + '</span>';
      }).join('') + (dates.length ? '<span>数据日 ' + escapeHtml(dates.join(' / ')) + '</span>' : '') + '</div>' : '');
  }

  function renderHoldings() {
    var rows = selectedHoldings().slice().sort(function (a, b) { return (number(b.market_value) || 0) - (number(a.market_value) || 0); });
    document.getElementById('investment-holdings-title').textContent = accountLabel(state.selectedAccount);
    var holdingDates = Array.from(new Set(rows.map(function (item) { return item.snapshot_date; }))).sort().reverse();
    document.getElementById('investment-holding-count').textContent = rows.length + ' 项持仓' + (holdingDates.length ? ' · 数据日期 ' + holdingDates.join(' / ') : '');
    document.getElementById('investment-holdings').innerHTML = rows.map(function (item) {
      return '<tr><td>' + escapeHtml(item.account_name || accountLabel(item.account_key)) + '</td>'
        + '<td>' + escapeHtml(item.snapshot_date || '-') + '</td><td>' + escapeHtml(item.instrument_code || '-') + '</td><td>' + escapeHtml(item.instrument_name || '-') + '</td>'
        + cell(item.pnl_rate, formatRate) + '<td>' + formatMoney(item.market_value) + '</td>'
        + cell(item.day_pnl, formatSigned) + cell(item.day_pnl_rate, formatRate)
        + cell(item.pnl, formatSigned) + cell(item.total_pnl, formatSigned)
        + cell(item.week_pnl, formatSigned) + cell(item.month_pnl, formatSigned) + cell(item.year_pnl, formatSigned)
        + '<td>' + formatRate(item.weight) + '</td><td>' + formatQuantity(item.quantity) + '</td>'
        + '<td>' + (number(item.holding_days) === null ? '-' : formatNumber(item.holding_days, 0) + '天') + '</td>'
        + '<td>' + formatNumber(item.current_price, 4) + '</td><td>' + formatNumber(item.cost_price, 4) + '</td></tr>';
    }).join('');
    document.getElementById('investment-holdings-empty').hidden = rows.length > 0;
    renderAllocationSummary(rows);
  }

  function isInferredOperation(item) {
    return String(item.operation || '').indexOf('推算') >= 0 || String(item.note || '').indexOf('推算') >= 0;
  }

  function normalizedSelectedTrades() {
    var raw = selectedTrades();
    var rows = []; var indexByKey = {}; var duplicates = 0;
    raw.forEach(function (item) {
      var key = [
        String(item.occurred_at || '').slice(0, 10), item.account_key, item.operation || item.side,
        item.instrument_code, number(item.quantity), number(item.price), number(item.amount), isInferredOperation(item),
      ].join('|');
      var existingIndex = indexByKey[key];
      if (existingIndex === undefined) {
        indexByKey[key] = rows.length;
        rows.push(item);
        return;
      }
      var existing = rows[existingIndex];
      var existingFee = number(existing.fee) || 0;
      var candidateFee = number(item.fee) || 0;
      var sameFee = existingFee === candidateFee;
      var oneFeeMissing = (existingFee === 0) !== (candidateFee === 0);
      if (!sameFee && !oneFeeMissing) {
        indexByKey[key + '|variant|' + rows.length] = rows.length;
        rows.push(item);
        return;
      }
      duplicates += 1;
      if (candidateFee > existingFee || (!existing.note && item.note)) rows[existingIndex] = item;
    });
    return { rows: rows, rawCount: raw.length, duplicates: duplicates };
  }

  function renderActivitySummary(result, cashFlows) {
    var inferred = cashFlows.filter(function (item) { return item.source_kind === 'inferred'; }).length;
    var confirmedFlows = cashFlows.filter(function (item) { return item.status === 'confirmed' && item.source_kind !== 'inferred'; }).length;
    var platform = result.rows.length;
    var accounts = Array.from(new Set(result.rows.map(function (item) { return item.account_name || accountLabel(item.account_key); }))).length;
    document.getElementById('investment-activity-summary').innerHTML = '<div class="investment-analysis-strip">'
      + analysisItemsMarkup([
        ['平台原始流水', platform + ' 条', '', '来自投资账本交易历史接口'],
        ['外部资金事件', cashFlows.length + ' 条', '', confirmedFlows + ' 条已确认 · ' + inferred + ' 条推算'],
        ['重复采集合并', result.duplicates + ' 条', '', result.duplicates ? '相同日期、账户、类型、标的、价格与数量' : '未发现重复经济记录'],
        ['覆盖账户', accounts + ' 个', '', accountLabel(state.selectedAccount)],
      ]) + '</div>';
  }

  function renderCashFlows(rows) {
    var categoryLabels = {
      fund_redemption: '基金赎回 / 转出',
      fund_subscription: '基金申购 / 转入',
      deposit: '资金转入',
      withdrawal: '资金转出',
      transfer: '账户划转',
    };
    document.getElementById('investment-cash-flow-count').textContent = rows.length + ' 条 · 原始与推算分开展示';
    document.getElementById('investment-cash-flows').innerHTML = rows.map(function (item) {
      var inferred = item.source_kind === 'inferred';
      var direction = item.direction === 'out' ? '流出' : '流入';
      var signedAmount = item.direction === 'out' ? -(number(item.amount) || 0) : number(item.amount);
      return '<tr><td>' + escapeHtml(String(item.occurred_at || '').slice(0, 10) || '-') + '</td>'
        + '<td>' + escapeHtml(item.account_name || accountLabel(item.account_key)) + '</td>'
        + '<td class="' + valueClass(signedAmount) + '">' + direction + '</td>'
        + '<td>' + escapeHtml(categoryLabels[item.category] || item.category || '-') + '</td>'
        + '<td class="' + valueClass(signedAmount) + '">' + formatSigned(signedAmount) + '</td>'
        + '<td><span class="investment-source-badge ' + (inferred ? 'is-inferred' : 'is-platform') + '">' + (inferred ? '推算' : (item.source_kind === 'manual' ? '人工确认' : '平台')) + '</span></td>'
        + '<td>' + qualityBadge(item.status === 'confirmed' ? '已确认' : '待核对', item.status === 'confirmed' ? 'complete' : 'partial') + '</td>'
        + '<td>' + escapeHtml(item.note || '-') + '</td></tr>';
    }).join('');
    document.getElementById('investment-cash-flows-empty').hidden = rows.length > 0;
  }

  function renderTrades() {
    var result = normalizedSelectedTrades();
    var rows = result.rows;
    var cashFlows = selectedCashFlows();
    document.getElementById('investment-trades-title').textContent = accountLabel(state.selectedAccount) + '账户流水';
    document.getElementById('investment-trade-count').textContent = cashFlows.length + ' 条资金事件 · ' + rows.length + ' 条交易' + (result.duplicates ? ' · 已合并 ' + result.duplicates + ' 条重复采集' : '');
    document.getElementById('investment-trades').innerHTML = rows.map(function (item) {
      var date = item.occurred_at ? String(item.occurred_at).slice(0, 10) : '-';
      var inferred = isInferredOperation(item);
      return '<tr><td>' + date + '</td><td>' + escapeHtml(item.account_name || accountLabel(item.account_key)) + '</td>'
        + '<td>' + escapeHtml(item.operation || item.side || '-') + '</td><td>' + escapeHtml(item.instrument_code || '-') + '</td>'
        + '<td>' + escapeHtml(item.instrument_name || '-') + '</td><td>' + formatNumber(item.price, 4) + '</td>'
        + '<td>' + formatQuantity(item.quantity) + '</td><td>' + formatMoney(item.amount) + '</td>'
        + '<td>' + formatMoney(item.fee) + '</td><td><span class="investment-source-badge ' + (inferred ? 'is-inferred' : 'is-platform') + '">' + (inferred ? '推算' : '平台') + '</span></td>'
        + '<td>' + escapeHtml(item.note || '-') + '</td></tr>';
    }).join('');
    document.getElementById('investment-trades-empty').hidden = rows.length > 0;
    renderCashFlows(cashFlows);
    renderActivitySummary(result, cashFlows);
  }

  function renderReview() {
    var holdings = selectedHoldings();
    var accounts = selectedAccounts();
    var referenceDate = state.data.resolved_snapshot_date || state.data.latest_snapshot_date || '';
    var valued = holdings.filter(function (item) { return number(item.market_value) !== null && number(item.market_value) > 0; })
      .sort(function (a, b) { return number(b.market_value) - number(a.market_value); });
    var holdingValue = valued.reduce(function (sum, item) { return sum + number(item.market_value); }, 0);
    var topOneRate = holdingValue && valued.length ? number(valued[0].market_value) / holdingValue * 100 : null;
    var topThreeRate = holdingValue ? valued.slice(0, 3).reduce(function (sum, item) { return sum + number(item.market_value); }, 0) / holdingValue * 100 : null;
    var pnlRows = holdings.filter(function (item) { return number(item.day_pnl) !== null; }).sort(function (a, b) { return number(b.day_pnl) - number(a.day_pnl); });
    var winner = pnlRows[0] || null;
    var drag = pnlRows.length ? pnlRows[pnlRows.length - 1] : null;
    var totalAsset = completeSum(accounts, 'total_asset');
    var cash = completeSum(accounts, 'cash');
    var cashRate = totalAsset && cash !== null ? cash / totalAsset * 100 : null;
    var dailyRows = performanceDailyRows().filter(function (row) { return !referenceDate || row.date <= referenceDate; });
    var latestFlow = dailyRows.length ? dailyRows[dailyRows.length - 1] : null;
    var flow = latestFlow ? latestFlow.netFlow : null;

    var cards = [
      ['最大正贡献', winner ? (winner.instrument_name || winner.instrument_code || '-') : '-', winner ? formatSigned(winner.day_pnl) : '暂无持仓级当日盈亏'],
      ['最大拖累', drag ? (drag.instrument_name || drag.instrument_code || '-') : '-', drag ? formatSigned(drag.day_pnl) : '暂无持仓级当日盈亏'],
      ['持仓集中度', formatPercent(topThreeRate), topOneRate === null ? '暂无持仓市值' : '第一大持仓 ' + formatPercent(topOneRate)],
      ['现金仓位', formatPercent(cashRate), cash === null ? '账户未返回现金字段' : formatMoney(cash) + ' 元'],
    ];
    document.getElementById('investment-review-summary').innerHTML = cards.map(function (item) {
      return '<div class="investment-review-item"><span>' + escapeHtml(item[0]) + '</span><strong>' + escapeHtml(item[1]) + '</strong><small>' + escapeHtml(item[2]) + '</small></div>';
    }).join('');

    var alerts = [];
    var pnlCoverage = fieldCoverage(accounts, 'day_pnl');
    if (!pnlCoverage.complete) alerts.push({ level: 'warning', text: '当日盈亏仍缺少：' + (pnlCoverage.missing.join('、') || '全部账户') + '；当天收益结论只能视为部分数据。' });
    var staleDates = Array.from(new Set(holdings.filter(function (item) { return referenceDate && item.snapshot_date && item.snapshot_date < referenceDate; }).map(function (item) { return item.account_name + ' ' + item.snapshot_date; })));
    if (staleDates.length) alerts.push({ level: 'warning', text: '持仓不是同一数据日：' + staleDates.join('、') + '；比较贡献前应先确认是否只是 T+1 到达时间不同。' });
    if (topOneRate !== null && topOneRate >= 20) alerts.push({ level: 'warning', text: '第一大持仓占 ' + formatPercent(topOneRate) + '，单一标的波动会明显影响组合。' });
    if (flow !== null && totalAsset !== null && Math.abs(flow) >= Math.max(5000, totalAsset * .03)) alerts.push({ level: 'warning', text: '本期推算外部净流入为 ' + formatSigned(flow) + '，请核对申购、赎回、转入或转出是否完整记录。' });
    if (!alerts.length) alerts.push({ level: 'ok', text: '当前没有触发集中度、资金异动或数据缺口提醒。仍建议结合交易动机做人工复盘。' });
    document.getElementById('investment-review-alerts').innerHTML = alerts.map(function (item) {
      return '<li class="is-' + item.level + '">' + escapeHtml(item.text) + '</li>';
    }).join('');
    document.getElementById('investment-review-scope').textContent = accountLabel(state.selectedAccount) + (referenceDate ? ' · ' + referenceDate : '');
    renderReviewNotes(referenceDate);
    renderReviewQuality(referenceDate);
  }

  function renderReviewNotes(referenceDate) {
    var notes = Array.isArray(state.data.review_notes) ? state.data.review_notes.slice() : [];
    notes = notes.filter(function (item) {
      if (referenceDate && item.review_date > referenceDate) return false;
      return state.selectedAccount === 'all' || item.account_key === 'all' || item.account_key === state.selectedAccount;
    }).sort(function (a, b) {
      if (a.review_date !== b.review_date) return a.review_date < b.review_date ? 1 : -1;
      return String(a.updated_at || '') < String(b.updated_at || '') ? 1 : -1;
    });
    document.getElementById('investment-review-notes').innerHTML = notes.map(function (item) {
      var fields = [
        ['判断', item.thesis], ['行动', item.action], ['证据', item.evidence], ['失效条件', item.invalidation],
      ].filter(function (field) { return field[1]; });
      var statusLabels = { open: '待验证', validated: '已验证', invalidated: '已失效' };
      return '<article class="investment-review-note"><div class="investment-review-note__meta">'
        + '<span>' + escapeHtml(item.review_date) + '</span><span>' + escapeHtml(item.account_name || accountLabel(item.account_key)) + '</span>'
        + '<span>' + escapeHtml(statusLabels[item.status] || item.status || '待验证') + '</span>'
        + (item.tags ? '<span>' + escapeHtml(item.tags) + '</span>' : '') + '</div><dl>'
        + fields.map(function (field) { return '<dt>' + field[0] + '</dt><dd>' + escapeHtml(field[1]) + '</dd>'; }).join('')
        + '</dl></article>';
    }).join('');
    document.getElementById('investment-review-notes-empty').hidden = notes.length > 0;
  }

  function qualityBadge(text, level) {
    return '<span class="investment-quality-badge is-' + level + '">' + escapeHtml(text) + '</span>';
  }

  function renderReviewQuality(referenceDate) {
    var allHoldings = Array.isArray(state.data.holdings) ? state.data.holdings : [];
    var allOperations = Array.isArray(state.data.operations) ? state.data.operations : [];
    var allCashFlows = Array.isArray(state.data.cash_flows) ? state.data.cash_flows : [];
    document.getElementById('investment-review-quality').innerHTML = selectedAccounts().map(function (account) {
      var holdings = allHoldings.filter(function (item) { return item.account_key === account.account_key; });
      var holdingDates = holdings.map(function (item) { return item.snapshot_date; }).filter(Boolean).sort().reverse();
      var holdingDate = holdingDates[0] || '';
      var cashOnly = number(account.market_value) === 0 || (number(account.cash) !== null && number(account.cash) === number(account.total_asset));
      var operations = allOperations.filter(function (item) { return item.account_key === account.account_key; });
      var inferred = operations.filter(isInferredOperation).length;
      var platform = operations.length - inferred;
      var cashFlows = allCashFlows.filter(function (item) { return item.account_key === account.account_key && item.status !== 'rejected'; });
      var confirmedCashFlows = cashFlows.filter(function (item) { return item.status === 'confirmed' && item.source_kind !== 'inferred'; }).length;
      var inferredCashFlows = cashFlows.length - confirmedCashFlows;
      var assetLevel = account.snapshot_date === referenceDate ? 'complete' : 'partial';
      var pnlLevel = number(account.day_pnl) !== null ? 'complete' : 'missing';
      var holdingLevel = cashOnly && !holdings.length ? 'complete' : (!holdingDate ? 'missing' : (holdingDate === referenceDate ? 'complete' : 'partial'));
      var cashLevel = number(account.cash) !== null ? 'complete' : 'missing';
      var operationLevel = platform || confirmedCashFlows ? 'complete' : (inferred || inferredCashFlows ? 'partial' : 'missing');
      return '<tr><td>' + escapeHtml(account.account_name || '未命名账户') + '</td>'
        + '<td>' + qualityBadge(account.snapshot_date || '缺失', assetLevel) + '</td>'
        + '<td>' + qualityBadge(pnlLevel === 'complete' ? '已采集' : '缺失', pnlLevel) + '</td>'
        + '<td>' + qualityBadge(holdingDate || (cashOnly ? '现金账户' : '缺失'), holdingLevel) + '</td>'
        + '<td>' + qualityBadge(cashLevel === 'complete' ? '已采集' : '缺失', cashLevel) + '</td>'
        + '<td>' + qualityBadge(platform || confirmedCashFlows
          ? '平台 ' + (platform + confirmedCashFlows)
          : (inferred || inferredCashFlows ? '推算 ' + (inferred + inferredCashFlows) : '未见流水'), operationLevel) + '</td></tr>';
    }).join('');
  }

  function historySeries() {
    var snapshots = Array.isArray(state.data.portfolio_snapshots) ? state.data.portfolio_snapshots : [];
    var specific = snapshots.some(function (item) { return item.account_key !== 'all'; });
    if (specific) snapshots = snapshots.filter(function (item) { return item.account_key !== 'all'; });
    if (state.selectedAccount !== 'all') {
      var selected = state.accounts.find(function (item) { return item.account_key === state.selectedAccount; });
      var selectedName = String(selected && selected.account_name || '').trim();
      snapshots = snapshots.filter(function (item) {
        return item.account_key === state.selectedAccount || (selectedName && String(item.account_name || '').trim() === selectedName);
      });
    }
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

    selectedAccounts().forEach(function (item) {
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
    return { dates: dates, series: state.selectedAccount === 'all' ? [{ key: 'total', label: '汇总资产', values: total }].concat(accounts) : accounts };
  }

  function renderHistory() {
    var chartData = historySeries();
    var section = document.getElementById('investment-history-section');
    var svg = document.getElementById('investment-history-chart');
    if (!chartData.dates.length) { section.dataset.hasData = 'false'; return; }
    section.dataset.hasData = 'true';

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
  }

  function applyWorkspaceView() {
    var sectionIds = ['investment-overview', 'investment-accounts-section', 'investment-performance-section', 'investment-detail-section', 'investment-history-section', 'investment-review-section'];
    sectionIds.forEach(function (id) { document.getElementById(id).hidden = true; });
    document.querySelectorAll('[data-workspace-view]').forEach(function (link) {
      var active = link.getAttribute('data-workspace-view') === state.workspaceView;
      link.classList.toggle('is-active', active);
      if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    });
    if (!state.data || !state.accounts.length) return;
    document.getElementById('investment-account-context').hidden = false;
    if (state.workspaceView === 'overview') {
      document.getElementById('investment-overview').hidden = false;
      document.getElementById('investment-accounts-section').hidden = false;
    } else if (state.workspaceView === 'performance') {
      document.getElementById('investment-performance-section').hidden = false;
      if (document.getElementById('investment-history-section').dataset.hasData === 'true') document.getElementById('investment-history-section').hidden = false;
    } else if (state.workspaceView === 'holdings' || state.workspaceView === 'activity') {
      document.getElementById('investment-detail-section').hidden = false;
      document.getElementById('investment-holdings-panel').hidden = state.workspaceView !== 'holdings';
      document.getElementById('investment-trades-panel').hidden = state.workspaceView !== 'activity';
    } else if (state.workspaceView === 'review') {
      document.getElementById('investment-review-section').hidden = false;
    }
  }

  function setWorkspaceView(view, replace) {
    if (workspaceViews.indexOf(view) < 0) view = 'overview';
    state.workspaceView = view;
    var url = new URL(window.location.href);
    url.searchParams.set('view', view);
    window.history[replace ? 'replaceState' : 'pushState']({ view: view }, '', url.toString());
    applyWorkspaceView();
  }

  function renderWorkspace() {
    renderMetrics();
    renderDailyBrief();
    renderAccountTabs();
    renderAccounts();
    renderPerformance();
    renderHoldings();
    renderTrades();
    renderHistory();
    renderReview();
    applyWorkspaceView();
  }

  document.getElementById('investment-account-tabs').addEventListener('click', function (event) {
    var button = event.target.closest('button[data-account]');
    if (!button) return;
    state.selectedAccount = button.getAttribute('data-account'); renderWorkspace();
  });
  document.getElementById('investment-ledger').addEventListener('click', function (event) {
    var link = event.target.closest('a[data-workspace-view]');
    if (!link) return;
    event.preventDefault();
    setWorkspaceView(link.getAttribute('data-workspace-view'), false);
  });
  window.addEventListener('popstate', function () {
    var view = new URL(window.location.href).searchParams.get('view');
    state.workspaceView = workspaceViews.indexOf(view) >= 0 ? view : 'overview';
    applyWorkspaceView();
  });
  document.querySelector('.investment-performance-tabs').addEventListener('click', function (event) {
    var button = event.target.closest('button[data-period]');
    if (!button) return;
    state.performanceView = button.getAttribute('data-period'); renderPerformance(); applyWorkspaceView();
  });
  document.getElementById('investment-benchmark-select').addEventListener('change', function (event) {
    state.selectedBenchmark = event.target.value;
    renderPerformanceSummary();
  });

  var reviewForm = document.getElementById('investment-review-form');
  var reviewFormStatus = document.getElementById('investment-review-form-status');
  document.getElementById('investment-review-compose').addEventListener('click', function () {
    reviewForm.hidden = false;
    reviewFormStatus.textContent = '';
    reviewForm.querySelector('textarea').focus();
  });
  document.getElementById('investment-review-cancel').addEventListener('click', function () {
    reviewForm.hidden = true;
    reviewFormStatus.textContent = '';
  });
  reviewForm.addEventListener('submit', function (event) {
    event.preventDefault();
    if (!state.data) return;
    var formData = new FormData(reviewForm);
    var button = reviewForm.querySelector('button[type="submit"]');
    var account = state.accounts.find(function (item) { return item.account_key === state.selectedAccount; });
    var payload = {
      review_date: state.data.resolved_snapshot_date || state.data.latest_snapshot_date,
      account_key: state.selectedAccount,
      account_name: account ? account.account_name : accountLabel(state.selectedAccount),
      thesis: formData.get('thesis'),
      action: formData.get('action'),
      evidence: formData.get('evidence'),
      invalidation: formData.get('invalidation'),
      tags: formData.get('tags'),
      status: 'open',
    };
    button.disabled = true;
    reviewFormStatus.textContent = '正在保存...';
    fetch(apiBase + '/api/review-notes', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'X-Review-Token': formData.get('write_token') },
      body: JSON.stringify(payload),
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (body) {
        if (!response.ok) throw new Error(response.status === 401 ? '编辑密码不正确。' : (body.error || '保存失败（HTTP ' + response.status + '）。'));
        return body;
      });
    }).then(function (body) {
      var note = body.note;
      if (!note) throw new Error('保存响应无效。');
      note.updated_at = new Date().toISOString();
      if (!Array.isArray(state.data.review_notes)) state.data.review_notes = [];
      state.data.review_notes = state.data.review_notes.filter(function (item) { return item.note_key !== note.note_key; });
      state.data.review_notes.unshift(note);
      reviewForm.reset();
      reviewForm.hidden = true;
      renderReviewNotes(payload.review_date);
    }).catch(function (error) {
      reviewFormStatus.textContent = error.message;
    }).finally(function () {
      button.disabled = false;
    });
  });

  function hideData() {
    ['investment-account-context', 'investment-overview', 'investment-accounts-section', 'investment-performance-section', 'investment-detail-section', 'investment-history-section', 'investment-review-section'].forEach(function (id) {
      document.getElementById(id).hidden = true;
    });
  }

  function showLogin(message) {
    hideData();
    session.hidden = true;
    dateFilter.hidden = true;
    setDateMenu(false, false);
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
    function pad(value) { return String(value).padStart(2, '0'); }
    return date.getFullYear() + '.' + pad(date.getMonth() + 1) + '.' + pad(date.getDate()) + ' ' + weekdays[date.getDay()];
  }

  function calendarWeekday(value) {
    var date = parseCalendarDate(value);
    return date ? ['周日', '周一', '周二', '周三', '周四', '周五', '周六'][date.getDay()] : '';
  }

  function adjacentBusinessDate(value, direction) {
    var date = parseCalendarDate(value);
    if (!date) return '';
    do { date.setDate(date.getDate() + direction); }
    while (date.getDay() === 0 || date.getDay() === 6);
    return calendarDateValue(date);
  }

  function renderQuickDates() {
    var cursor = state.latestSettledDate || dateInput.value;
    var activeDate = dateInput.value || state.latestSettledDate;
    var dates = [];
    while (cursor && dates.length < 10) {
      dates.push(cursor);
      cursor = adjacentBusinessDate(cursor, -1);
    }
    quickDates.innerHTML = dates.map(function (value) {
      var active = value === activeDate;
      return '<button type="button" role="option" data-date="' + value + '" class="' + (active ? 'is-active' : '') + '" aria-selected="' + active + '">'
        + '<span>' + value.slice(5).replace('-', '.') + '</span><small>' + calendarWeekday(value) + '</small></button>';
    }).join('');
  }

  function setDateMenu(open, returnFocus) {
    if (open && state.loading) return;
    dateMenu.hidden = !open;
    dateTrigger.setAttribute('aria-expanded', String(open));
    if (open) {
      renderQuickDates();
      var activeButton = quickDates.querySelector('button.is-active');
      (activeButton || dateInput).focus();
    } else if (returnFocus) {
      dateTrigger.focus();
    }
  }

  function updateDateNavigation() {
    var current = dateInput.value || state.latestSettledDate;
    var next = adjacentBusinessDate(current, 1);
    dateDisplay.textContent = current ? formatCalendarDate(current) : '选择日期';
    dateDisplay.dateTime = current || '';
    datePrev.disabled = state.loading || !current;
    dateNext.disabled = state.loading || !current || !state.latestSettledDate || current >= state.latestSettledDate || next > state.latestSettledDate;
    dateLatest.disabled = state.loading || !state.requestedDate;
    dateTrigger.disabled = state.loading;
    dateInput.disabled = state.loading;
    if (!dateMenu.hidden) renderQuickDates();
  }

  function setDateLoading(loading) {
    if (loading) setDateMenu(false, false);
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
      if (!state.accounts.length) { hideData(); status.textContent = '尚无账户快照'; return; }
      renderWorkspace();
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
    if (token && dateInput.value) {
      setDateMenu(false, true);
      loadPortfolio(token, dateInput.value);
    }
  });

  dateTrigger.addEventListener('click', function () {
    setDateMenu(dateMenu.hidden, false);
  });

  quickDates.addEventListener('click', function (event) {
    var button = event.target.closest('button[data-date]');
    var token = sessionStorage.getItem(sessionKey);
    if (!button || !quickDates.contains(button) || !token) return;
    var target = button.getAttribute('data-date');
    dateInput.value = target;
    setDateMenu(false, true);
    loadPortfolio(token, target);
  });

  datePrev.addEventListener('click', function () {
    var token = sessionStorage.getItem(sessionKey);
    var target = adjacentBusinessDate(dateInput.value || state.latestSettledDate, -1);
    if (token && target) {
      setDateMenu(false, false);
      loadPortfolio(token, target);
    }
  });

  dateNext.addEventListener('click', function () {
    var token = sessionStorage.getItem(sessionKey);
    var target = adjacentBusinessDate(dateInput.value || state.latestSettledDate, 1);
    if (target > state.latestSettledDate) target = state.latestSettledDate;
    if (token && target) {
      setDateMenu(false, false);
      loadPortfolio(token, target);
    }
  });

  dateLatest.addEventListener('click', function () {
    var token = sessionStorage.getItem(sessionKey);
    if (!token) return;
    setDateMenu(false, false);
    dateInput.value = '';
    loadPortfolio(token, '');
  });

  document.addEventListener('click', function (event) {
    if (!dateMenu.hidden && !dateActions.contains(event.target)) setDateMenu(false, false);
  });

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && !dateMenu.hidden) {
      event.preventDefault();
      setDateMenu(false, true);
    }
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

  applyWorkspaceView();
  var storedToken = sessionStorage.getItem(sessionKey);
  if (storedToken) loadPortfolio(storedToken, '');
  else showLogin('');
})();
</script>
