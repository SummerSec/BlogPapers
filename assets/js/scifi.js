(function () {
  'use strict';

  var reduceMotion = typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // --- Normalize pathname for nav active matching ---
  function normalizePathForNav(p) {
    if (!p) return '/';
    p = p.replace(/\/$/, '') || '/';
    if (p === '/index.html' || p === '/index') return '/';
    if (p.endsWith('/index.html')) {
      p = p.slice(0, -10) || '/';
      return p;
    }
    if (p.endsWith('.html')) {
      p = p.slice(0, -5);
    }
    if (p.endsWith('/index')) {
      p = p.slice(0, -6) || '/';
    }
    return p || '/';
  }

  // --- Rewrite in-site .md links to .html (Markdown sources unchanged) ---
  function shouldSkipHref(href) {
    if (!href || href.charAt(0) === '#') return true;
    var lower = href.trim().toLowerCase();
    if (lower.indexOf('mailto:') === 0 || lower.indexOf('javascript:') === 0 || lower.indexOf('tel:') === 0) return true;
    return false;
  }

  function rewriteMdToHtmlHref(href) {
    if (shouldSkipHref(href)) return null;
    var u;
    try {
      u = new URL(href, window.location.href);
    } catch (e) {
      return null;
    }
    if (u.hostname && u.hostname !== window.location.hostname) return null;
    if (u.hostname === 'github.com' || u.hostname === 'raw.githubusercontent.com') return null;

    var path = u.pathname;
    if (!/\.md$/i.test(path)) return null;

    if (/\/README\.md$/i.test(path)) {
      u.pathname = path.replace(/\/README\.md$/i, '/');
    } else {
      u.pathname = path.replace(/\.md$/i, '.html');
    }

    return u.pathname + u.search + u.hash;
  }

  function applyMdToHtmlLinks(root) {
    var scope = root || document;
    scope.querySelectorAll('a[href]').forEach(function (a) {
      if (a.closest('.site-nav')) return;
      var href = a.getAttribute('href');
      var next = rewriteMdToHtmlHref(href);
      if (next !== null) a.setAttribute('href', next);
    });
  }

  function runMdRewrite() {
    applyMdToHtmlLinks(document.getElementById('main-content') || document.body);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runMdRewrite);
  } else {
    runMdRewrite();
  }

  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest && e.target.closest('a[href]');
    if (!a || a.closest('.site-nav')) return;
    var href = a.getAttribute('href');
    var next = rewriteMdToHtmlHref(href);
    if (next !== null) {
      e.preventDefault();
      window.location.href = next;
    }
  }, true);

  // --- 浏览量：优先 meta stats-endpoint（Cloudflare Worker），否则 CountAPI ---
  var STATS_NS_EL = document.querySelector('meta[name="stats-namespace"]');
  var STATS_NS = (STATS_NS_EL && STATS_NS_EL.getAttribute('content')) || 'sumsecme';
  var STATS_SITE_KEY = 'site-total';
  var STATS_EP_EL = document.querySelector('meta[name="stats-endpoint"]');
  var STATS_ENDPOINT =
    (STATS_EP_EL && STATS_EP_EL.getAttribute('content')) ||
    (document.body && document.body.getAttribute('data-stats-endpoint')) ||
    (typeof window.__BLOG_STATS_EP === 'string' ? window.__BLOG_STATS_EP : '') ||
    '';
  STATS_ENDPOINT = String(STATS_ENDPOINT).replace(/^\s+|\s+$/g, '').replace(/\/$/, '');

  function statsParseDataValue(data) {
    if (!data || data.value === undefined || data.value === null) return null;
    var v = data.value;
    if (typeof v === 'number' && !isNaN(v)) return Math.floor(v);
    if (typeof v === 'string') {
      var n = parseInt(v, 10);
      if (!isNaN(n)) return n;
    }
    return null;
  }

  function statsFormatNum(n) {
    if (n == null || typeof n !== 'number' || isNaN(n)) return '—';
    return String(Math.floor(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  function statsPageKey() {
    var p = window.location.pathname.replace(/\/$/, '') || '/';
    if (p === '/' || p === '/index.html' || /\/index\.html$/i.test(p)) {
      return 'page-home';
    }
    var raw = p.replace(/^\/+/, '').replace(/\.html$/i, '');
    var k = raw.replace(/[^a-zA-Z0-9]+/g, '-').toLowerCase().replace(/^-+|-+$/g, '');
    if (!k) k = 'root';
    if (k.length > 60) k = k.slice(0, 60);
    return 'pv-' + k;
  }

  function countapiJsonp(ns, key, done) {
    var base = 'https://api.countapi.xyz/hit/' + encodeURIComponent(ns) + '/' + encodeURIComponent(key);
    var cb = 'countapi_cb_' + String(Date.now()) + '_' + Math.floor(Math.random() * 1e6);
    var script = document.createElement('script');
    script.async = true;
    var fired = false;
    function once(val) {
      if (fired) return;
      fired = true;
      window.clearTimeout(slow);
      try {
        delete window[cb];
      } catch (e0) { /* ignore */ }
      if (script.parentNode) script.parentNode.removeChild(script);
      done(val);
    }
    var slow = window.setTimeout(function () {
      once(null);
    }, 12000);
    window[cb] = function (data) {
      once(statsParseDataValue(data));
    };
    script.onerror = function () {
      once(null);
    };
    script.src = base + '?callback=' + encodeURIComponent(cb);
    document.head.appendChild(script);
  }

  function countapiHit(ns, key, done) {
    var url = 'https://api.countapi.xyz/hit/' + encodeURIComponent(ns) + '/' + encodeURIComponent(key);
    var finished = false;
    function doneOnce(v) {
      if (finished) return;
      finished = true;
      window.clearTimeout(fallbackTimer);
      done(v);
    }
    var fallbackTimer = window.setTimeout(function () {
      countapiJsonp(ns, key, doneOnce);
    }, 10000);

    if (typeof fetch !== 'function') {
      window.clearTimeout(fallbackTimer);
      countapiJsonp(ns, key, doneOnce);
      return;
    }

    var opts = { mode: 'cors', cache: 'no-store' };
    try {
      if (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) {
        opts.signal = AbortSignal.timeout(8000);
      }
    } catch (eT) { /* ignore */ }

    fetch(url, opts)
      .then(function (r) { return r.text(); })
      .then(function (text) {
        var d;
        try {
          d = JSON.parse(text);
        } catch (eJ) {
          doneOnce(null);
          return;
        }
        doneOnce(statsParseDataValue(d));
      })
      .catch(function () {
        window.clearTimeout(fallbackTimer);
        countapiJsonp(ns, key, doneOnce);
      });
  }

  /** 无 fetch 环境（极少）才用 JSONP；正常路径用 fetch，避免 capi 脚本被 CSP 拦截导致「本文浏览 —」 */
  function workerJsonp(ns, key, done) {
    if (!STATS_ENDPOINT) {
      done(null);
      return;
    }
    var base =
      STATS_ENDPOINT +
      '/hit?ns=' +
      encodeURIComponent(ns) +
      '&key=' +
      encodeURIComponent(key) +
      '&_=' +
      String(Date.now());
    var cb = 'worker_stats_cb_' + String(Date.now()) + '_' + Math.floor(Math.random() * 1e6);
    var script = document.createElement('script');
    script.async = true;
    var fired = false;
    function once(val) {
      if (fired) return;
      fired = true;
      window.clearTimeout(slow);
      try {
        delete window[cb];
      } catch (e0) { /* ignore */ }
      if (script.parentNode) script.parentNode.removeChild(script);
      done(val);
    }
    var slow = window.setTimeout(function () {
      once(null);
    }, 12000);
    window[cb] = function (data) {
      once(statsParseDataValue(data));
    };
    script.onerror = function () {
      once(null);
    };
    script.src = base + '&callback=' + encodeURIComponent(cb);
    document.head.appendChild(script);
  }

  function workerHit(ns, key, done) {
    if (!STATS_ENDPOINT) {
      done(null);
      return;
    }
    var url =
      STATS_ENDPOINT +
      '/hit?ns=' +
      encodeURIComponent(ns) +
      '&key=' +
      encodeURIComponent(key) +
      '&_=' +
      String(Date.now());
    if (typeof fetch !== 'function') {
      workerJsonp(ns, key, done);
      return;
    }
    /* 不设 AbortSignal：超时中止可能导致请求已在 Worker 计数后仍走 JSONP，重复 +1；由浏览器自然超时即可 */
    var opts = { method: 'GET', mode: 'cors', credentials: 'omit', cache: 'no-store' };
    fetch(url, opts)
      .then(function (r) {
        if (!r.ok) throw new Error('stats http');
        return r.text();
      })
      .then(function (text) {
        var d;
        try {
          d = JSON.parse(text);
        } catch (eJ) {
          /* 服务端已 /hit 计数，勿再 JSONP 以免二次 +1 */
          done(null);
          return;
        }
        done(statsParseDataValue(d));
      })
      .catch(function () {
        /* 多为网络或 connect-src 拦截（未命中服务端），可再试 JSONP */
        workerJsonp(ns, key, done);
      });
  }

  function statsHit(ns, key, done) {
    if (STATS_ENDPOINT) {
      workerHit(ns, key, function (v) {
        if (typeof v === 'number' && !isNaN(v)) {
          done(v);
          return;
        }
        countapiHit(ns, key, done);
      });
      return;
    }
    countapiHit(ns, key, done);
  }

  function statsApplyValue(el, val) {
    if (!el) return;
    el.textContent = statsFormatNum(val);
    el.classList.remove('view-stats__value--loading');
  }

  /* ---- Sparkline (纯 SVG，30 天趋势) ---- */

  function fetchTrend(ns, key, days, done) {
    if (!STATS_ENDPOINT || typeof fetch !== 'function') { done(null); return; }
    var url = STATS_ENDPOINT + '/trend?ns=' + encodeURIComponent(ns) +
      '&key=' + encodeURIComponent(key) + '&days=' + days +
      '&_=' + Date.now();
    fetch(url, { mode: 'cors', credentials: 'omit', cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { done(d && d.points ? d : null); })
      .catch(function () { done(null); });
  }

  function renderSparkline(container, points, isPage) {
    if (!container || !points || points.length < 2) return;
    var vals = points.map(function (p) { return p.value; });
    var prev = vals[0];
    var daily = [0];
    for (var i = 1; i < vals.length; i++) {
      var diff = vals[i] - prev;
      daily.push(diff > 0 ? diff : 0);
      prev = vals[i];
    }

    var W = 80, H = 22, pad = 1;
    var max = Math.max.apply(null, daily) || 1;
    var n = daily.length;
    var stepX = (W - pad * 2) / (n - 1);
    var coords = [];
    for (var j = 0; j < n; j++) {
      var x = pad + j * stepX;
      var y = H - pad - ((daily[j] / max) * (H - pad * 2));
      coords.push(x.toFixed(1) + ',' + y.toFixed(1));
    }
    var lineColor = isPage ? 'rgba(148,168,232,0.9)' : 'rgba(92,219,207,0.9)';
    var fillColor = isPage ? 'rgba(148,168,232,0.14)' : 'rgba(92,219,207,0.14)';
    var fillCoords = coords.concat([
      (pad + (n - 1) * stepX).toFixed(1) + ',' + H,
      pad + ',' + H
    ]);
    var svg = '<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H +
      '" fill="none" xmlns="http://www.w3.org/2000/svg">' +
      '<polygon points="' + fillCoords.join(' ') + '" fill="' + fillColor + '"/>' +
      '<polyline points="' + coords.join(' ') + '" stroke="' + lineColor +
      '" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" fill="none"/>' +
      '</svg>';
    container.innerHTML = svg;
    container.title = '最近 ' + n + ' 天每日增量趋势';
  }

  function runViewStats() {
    var banner = document.getElementById('view-stats-banner');
    var siteEl = document.getElementById('stat-site-total');
    var pageEl = document.getElementById('stat-page-views');
    var sparkEl = document.getElementById('stat-sparkline');
    if (!banner || (!siteEl && !pageEl)) return;

    var isHome = document.body.classList.contains('page-front');
    var trendKey = isHome ? STATS_SITE_KEY : statsPageKey();

    statsHit(STATS_NS, STATS_SITE_KEY, function (siteVal) {
      if (isHome && siteEl) {
        statsApplyValue(siteEl, siteVal);
      }
    });

    statsHit(STATS_NS, statsPageKey(), function (pageVal) {
      if (!isHome && pageEl) {
        statsApplyValue(pageEl, pageVal);
      }
    });

    fetchTrend(STATS_NS, trendKey, 30, function (data) {
      renderSparkline(sparkEl, data && data.points, !isHome);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runViewStats);
  } else {
    runViewStats();
  }

  // --- Matrix rain ---
  var canvas = document.getElementById('matrix-canvas');
  if (canvas && !reduceMotion) {
    var ctx = canvas.getContext('2d');
    var W, H, cols, drops;
    var CHARS = '01ABCDEFΣ◇▣⟨⟩∴×÷アイウエオカキクケコサシスセソタチツテト';

    function resizeCanvas() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
      cols = Math.floor(W / 16);
      drops = [];
      for (var i = 0; i < cols; i++) drops[i] = Math.random() * -H;
    }

    var NEON = [
      'rgba(92, 219, 207, 0.22)',
      'rgba(148, 168, 232, 0.2)',
      'rgba(125, 215, 160, 0.18)',
      'rgba(140, 180, 220, 0.16)'
    ];

    function drawMatrix() {
      ctx.fillStyle = 'rgba(5, 6, 12, 0.055)';
      ctx.fillRect(0, 0, W, H);
      ctx.font = '14px "JetBrains Mono", "Noto Sans SC", monospace';
      for (var i = 0; i < cols; i++) {
        ctx.fillStyle = NEON[i % NEON.length];
        var ch = CHARS[Math.floor(Math.random() * CHARS.length)];
        ctx.fillText(ch, i * 16, drops[i]);
        if (drops[i] > H && Math.random() > 0.97) drops[i] = 0;
        drops[i] += 16;
      }
    }

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    setInterval(drawMatrix, 60);
  } else if (canvas && reduceMotion) {
    canvas.style.opacity = '0.12';
  }

  // --- 侧栏 HUD 信号槽彩蛋（chan + code 竖排展示，点击底部广播条） ---
  var EGG_POOL = [
    { chan: 'NET', code: 'UPLINK', msg: '链路稳定。带宽易得，清醒难得。' },
    { chan: 'SYS', code: 'SYN_OK', msg: '握手完成。你正在正确的时区阅读。' },
    { chan: 'SEC', code: 'AES256', msg: '有些内容值得用最笨、最稳的锁。' },
    { chan: 'OPS', code: 'LOSS0', msg: '零丢包是理想；零幻觉是底线。' },
    { chan: 'MEM', code: 'CAFE', msg: '0xCAFEBABE — 魔数对齐，直觉也要对齐。' },
    { chan: 'FW', code: 'CLR', msg: '今日无告警。无事发生，往往是好事。' },
    { chan: 'TRACE', code: 'LOOP', msg: '127.0.0.1：追到最后，常是自己。' },
    { chan: 'PROC', code: '1337', msg: 'PID 体面，进程也要体面地活着。' },
    { chan: 'CHK', code: 'PASS', msg: '校验通过。写下来，比记在脑子里安全。' },
    { chan: 'ROOT', code: 'SUDO', msg: '权限够了，咖啡可能还不够。' },
    { chan: 'HTTP', code: '404Z', msg: 'sleep.exe 未找到：缺觉不算漏洞，算债。' },
    { chan: 'CODE', code: 'LIVE', msg: 'while(alive) 里别忘了 break 去晒太阳。' },
    { chan: 'CVE', code: 'COFF', msg: 'CVSS 不高，但咖啡因严重度是 Critical。' },
    { chan: 'DEV', code: 'NULL', msg: '/dev/null 收好疑虑，stdout 留给结论。' },
    { chan: 'FS', code: 'RMRF', msg: '递归删除犹豫前，先 git status 一下人生。' },
    { chan: 'VCS', code: 'SLEEP', msg: 'commit 了 sleep，但忘了 push 到枕头。' },
    { chan: 'HEAP', code: '64P', msg: '堆还有余量。脑子也是，别塞满缓存。' },
    { chan: 'LAT', code: '3MS', msg: '延迟够低，说明你还在场。' },
    { chan: 'RAD', code: '7G', msg: '扇区扫完。留白处往往最诚实。' },
    { chan: 'TCP', code: 'ACK', msg: 'ACK 收到。下一步：动手验证。' },
    { chan: 'IP', code: 'TTL', msg: 'TTL 还够跳几跳。别在每一跳都停下来内耗。' },
    { chan: 'TLS', code: '443', msg: '443 在听。明文情绪请线下消化。' },
    { chan: 'RNG', code: 'HIGH', msg: '熵够高才好玩；写文也是。' },
    { chan: 'IO', code: 'EOF', msg: '文件还没结束，你的故事同理。' },
    { chan: 'AUD', code: 'TRUST', msg: 'Trust but verify — 对链接、对结论、对自己。' },
    { chan: 'LOG', code: 'NOTE', msg: '没有后门，只有复盘与勘误表。' },
  ];

  function shuffleArray(arr) {
    for (var i = arr.length - 1; i > 0; i--) {
      var j = Math.floor(Math.random() * (i + 1));
      var tmp = arr[i]; arr[i] = arr[j]; arr[j] = tmp;
    }
    return arr;
  }

  /** 从池里无放回取前 n 条（用于两侧 6 个槽位互不重复） */
  function sampleUniqueEggs(n) {
    if (n <= 0) return [];
    var copy = EGG_POOL.slice();
    shuffleArray(copy);
    return copy.slice(0, Math.min(n, copy.length));
  }

  /** 单次随机一条（点击播报用，可与槽位展示不同） */
  function pickRandomEgg() {
    if (!EGG_POOL.length) return { chan: 'SIG', code: '\u2014', msg: '' };
    return EGG_POOL[Math.floor(Math.random() * EGG_POOL.length)];
  }

  function buildEggButton(el, entry) {
    while (el.firstChild) el.removeChild(el.firstChild);
    var inner = document.createElement('span');
    inner.className = 'side-egg__inner';
    var led = document.createElement('span');
    led.className = 'side-egg__led';
    led.setAttribute('aria-hidden', 'true');
    var codeEl = document.createElement('span');
    codeEl.className = 'side-egg__code';
    codeEl.textContent = entry.code;
    inner.appendChild(led);
    inner.appendChild(codeEl);
    el.appendChild(inner);
    el.setAttribute('title', entry.msg);
    el.setAttribute('data-egg-msg', entry.msg);
    el.setAttribute('aria-label', '播报信号 ' + entry.chan + '/' + entry.code + '：' + entry.msg);
  }

  function initSideEggs() {
    var root = document.querySelector('.side-eggs');
    if (!root || root.getAttribute('data-egg-ready') === '1') return;
    var eggs = root.querySelectorAll('.side-egg');
    if (!eggs.length) return;
    root.setAttribute('data-egg-ready', '1');
    var picked = sampleUniqueEggs(eggs.length);
    eggs.forEach(function (el, i) {
      var entry = picked[i] || pickRandomEgg();
      buildEggButton(el, entry);
      el.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        showHudToast(pickRandomEgg());
      });
    });
  }

  function showHudToast(entry) {
    var toast = document.getElementById('hud-toast');
    if (!toast) return;
    var meta = toast.querySelector('.hud-toast__meta');
    var body = toast.querySelector('.hud-toast__body');
    var line = '[' + (entry.chan || 'SIG') + '] \u00b7 ' + (entry.code || '\u2014') + ' \u00b7 BROADCAST';
    if (meta && body) {
      meta.textContent = line;
      body.textContent = entry.msg || '';
    } else {
      toast.textContent = '\u25b6 ' + line + ' \u2014 ' + (entry.msg || '');
    }
    toast.classList.add('visible');
    if (toast._timer) clearTimeout(toast._timer);
    toast._timer = setTimeout(function () {
      toast.classList.remove('visible');
    }, 4200);
  }

  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    var toast = document.getElementById('hud-toast');
    if (!toast || !toast.classList.contains('visible')) return;
    toast.classList.remove('visible');
    if (toast._timer) clearTimeout(toast._timer);
  });

  function runInitSideEggs() {
    initSideEggs();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runInitSideEggs);
  } else {
    runInitSideEggs();
  }
  window.addEventListener('load', runInitSideEggs);

  // --- Glitch effect on site title hover ---
  var titleEl = document.querySelector('.title-main');
  if (titleEl && !reduceMotion) {
    var glitchTimer = null;
    titleEl.addEventListener('mouseenter', function () {
      titleEl.classList.add('glitch-active');
      clearTimeout(glitchTimer);
      glitchTimer = setTimeout(function () {
        titleEl.classList.remove('glitch-active');
      }, 600);
    });
  }

  // --- Typewriter on terminal prompt ---
  var promptEl = document.querySelector('.terminal-prompt');
  if (promptEl && !reduceMotion) {
    var fullText = promptEl.textContent;
    promptEl.textContent = '';
    var idx = 0;
    var tw = setInterval(function () {
      promptEl.textContent += fullText[idx];
      idx++;
      if (idx >= fullText.length) clearInterval(tw);
    }, 60);
  }

  // --- Nav link active state ---
  var navLinks = document.querySelectorAll('.site-nav .nav-link');
  var path = normalizePathForNav(window.location.pathname);
  navLinks.forEach(function (a) {
    if (!a.href) return;
    try {
      var ap = normalizePathForNav(new URL(a.href).pathname);
      if (ap === path || (path === '/' && (ap === '/' || ap === '/index.html'))) {
        a.classList.add('nav-active');
        a.setAttribute('aria-current', 'page');
      }
    } catch (err) { /* ignore */ }
  });

  // --- 文章页：鼠标所在「视觉行」高亮（按 line-height 分行，非首页） ---
  function getLineHeightPx(el) {
    var cs = getComputedStyle(el);
    var lh = cs.lineHeight;
    if (lh === 'normal') {
      var fs = parseFloat(cs.fontSize);
      if (isNaN(fs)) fs = 16;
      return fs * 1.55;
    }
    var n = parseFloat(lh);
    return isNaN(n) ? parseFloat(cs.fontSize) * 1.55 : n;
  }

  function skipArticleLineHover(el) {
    if (!el || !el.closest) return true;
    if (el.closest('pre, table, .view-stats')) return true;
    return false;
  }

  function paintLineHover(el, e) {
    var lh = getLineHeightPx(el);
    var rect = el.getBoundingClientRect();
    var padTop = parseFloat(getComputedStyle(el).paddingTop) || 0;
    var y = e.clientY - rect.top - padTop;
    if (y < 0) y = 0;
    var idx = Math.floor(y / lh);
    el.style.setProperty('--article-lh', lh + 'px');
    el.style.setProperty('--hover-line', String(idx));
    el.style.setProperty('--line-active', '1');
    el.classList.add('article-line-hover--active');
  }

  function initArticleLineHover() {
    if (typeof document.body.classList !== 'undefined' && document.body.classList.contains('page-front')) return;
    /* 许多触控笔记本会报 (hover: none)，但仍可用鼠标；仅在「主要输入为粗指针」时跳过 */
    if (typeof window.matchMedia === 'function') {
      var mqNoHover = window.matchMedia('(hover: none)');
      var mqCoarse = window.matchMedia('(pointer: coarse)');
      if (mqNoHover.matches && mqCoarse.matches) return;
    }
    var root = document.querySelector('.terminal-body');
    if (!root) return;

    var sel = 'p, li, h1, h2, h3, h4, h5, h6';
    root.querySelectorAll(sel).forEach(function (el) {
      if (skipArticleLineHover(el)) return;
      el.classList.add('article-line-hover-target');
      var raf = 0;
      var pendingEv = null;
      function flushLineHover() {
        raf = 0;
        var ev = pendingEv;
        pendingEv = null;
        if (ev) paintLineHover(el, ev);
      }
      el.addEventListener('mousemove', function (e) {
        pendingEv = e;
        if (!raf) raf = requestAnimationFrame(flushLineHover);
      });
      el.addEventListener('mouseleave', function () {
        pendingEv = null;
        if (raf) cancelAnimationFrame(raf);
        raf = 0;
        el.style.setProperty('--line-active', '0');
        el.classList.remove('article-line-hover--active');
      });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initArticleLineHover);
  } else {
    initArticleLineHover();
  }

  // --- Reading progress bar ---
  var progressBar = document.getElementById('read-progress');
  if (progressBar) {
    window.addEventListener('scroll', function () {
      var scrollTop = window.scrollY || document.documentElement.scrollTop;
      var docHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
      var pct = docHeight > 0 ? (scrollTop / docHeight * 100) : 0;
      progressBar.style.width = Math.min(pct, 100) + '%';
    }, { passive: true });
  }

  // --- Back to top button ---
  var backTop = document.getElementById('back-to-top');
  if (backTop) {
    window.addEventListener('scroll', function () {
      if (window.scrollY > 300) {
        backTop.classList.add('visible');
      } else {
        backTop.classList.remove('visible');
      }
    }, { passive: true });
    backTop.addEventListener('click', function () {
      window.scrollTo({ top: 0, behavior: reduceMotion ? 'auto' : 'smooth' });
    });
  }

  // --- 文章 + 配套 PPT：阅读模式切换、断点默认、同源轻量探测 ---
  function initArticleReadingMode() {
    var readingRoot = document.getElementById('article-reading-mode');
    if (!readingRoot) return;

    var frame = document.getElementById('article-ppt-frame');
    var standalone = document.getElementById('ppt-standalone-link');
    var pptUrlAttr = readingRoot.getAttribute('data-ppt-url') || '';

    var userChosen = false;
    var pptOk = true;
    var mq = typeof window.matchMedia === 'function'
      ? window.matchMedia('(min-width: 768px)')
      : null;

    function normalizeMode(m) {
      m = String(m || '').toLowerCase().trim();
      if (m === 'split' || m === 'article' || m === 'ppt') return m;
      return 'article';
    }

    function defaultModeFromData() {
      var isDesktop = mq ? mq.matches : (window.innerWidth >= 768);
      var d = readingRoot.dataset || {};
      var desk = normalizeMode(d.readingDefaultDesktop || 'split');
      var mob = normalizeMode(d.readingDefaultMobile || 'article');
      var pick = isDesktop ? desk : mob;
      if (!pptOk && (pick === 'split' || pick === 'ppt')) return 'article';
      return pick;
    }

    function resolvePptUrl() {
      if (!pptUrlAttr || !String(pptUrlAttr).trim()) return null;
      try {
        return new URL(pptUrlAttr, window.location.href);
      } catch (e) {
        return null;
      }
    }

    var pptResolved = resolvePptUrl();

    function syncPptScrollbarSkin() {
      if (!frame || !pptResolved || pptResolved.origin !== window.location.origin) return;
      try {
        var doc = frame.contentDocument;
        if (!doc) return;
        var host = doc.head || doc.documentElement;
        if (!host) return;
        var scrollRoot = doc.scrollingElement || doc.documentElement;
        var style = doc.getElementById('sumsec-ppt-scrollbar-skin');
        if (!style) {
          style = doc.createElement('style');
          style.id = 'sumsec-ppt-scrollbar-skin';
          host.appendChild(style);
        }

        if (scrollRoot && scrollRoot.classList) scrollRoot.classList.add('sumsec-scroll-root');
        if (doc.documentElement && doc.documentElement.classList) {
          doc.documentElement.classList.add('sumsec-scroll-root');
          doc.documentElement.style.scrollbarWidth = 'thin';
          doc.documentElement.style.scrollbarColor = 'rgba(92, 219, 207, 0.25) #05060c';
        }
        if (doc.body) {
          if (doc.body.classList) doc.body.classList.add('sumsec-scroll-root');
          doc.body.style.scrollbarWidth = 'thin';
          doc.body.style.scrollbarColor = 'rgba(92, 219, 207, 0.25) #05060c';
        }

        style.textContent =
          '.sumsec-scroll-root, html, body {' +
          'scrollbar-width: thin;' +
          'scrollbar-color: rgba(92, 219, 207, 0.25) #05060c;' +
          '}' +
          '.sumsec-scroll-root::-webkit-scrollbar, html::-webkit-scrollbar, body::-webkit-scrollbar { width: 8px; height: 8px; }' +
          '.sumsec-scroll-root::-webkit-scrollbar-track, html::-webkit-scrollbar-track, body::-webkit-scrollbar-track { background: #05060c; }' +
          '.sumsec-scroll-root::-webkit-scrollbar-thumb, html::-webkit-scrollbar-thumb, body::-webkit-scrollbar-thumb { background: rgba(92, 219, 207, 0.25); border-radius: 4px; }' +
          '.sumsec-scroll-root::-webkit-scrollbar-thumb:hover, html::-webkit-scrollbar-thumb:hover, body::-webkit-scrollbar-thumb:hover { background: rgba(92, 219, 207, 0.45); }';
      } catch (eSkin) {
        /* ignore same-origin iframe styling failures */
      }
    }

    function getMode() {
      if (readingRoot.classList.contains('mode-split')) return 'split';
      if (readingRoot.classList.contains('mode-ppt')) return 'ppt';
      if (readingRoot.classList.contains('mode-article')) return 'article';
      return '';
    }

    function syncAria(mode) {
      var buttons = readingRoot.querySelectorAll(
        '.reading-mode-switcher__btn[data-reading-mode]'
      );
      buttons.forEach(function (btn) {
        var m = btn.getAttribute('data-reading-mode');
        if (btn.style.display === 'none') {
          btn.setAttribute('aria-pressed', 'false');
          return;
        }
        btn.setAttribute('aria-pressed', m === mode ? 'true' : 'false');
      });
    }

    function setMode(mode, opts) {
      opts = opts || {};
      mode = normalizeMode(mode);
      if (!pptOk && (mode === 'split' || mode === 'ppt')) mode = 'article';
      readingRoot.classList.remove('mode-split', 'mode-article', 'mode-ppt');
      readingRoot.classList.add('mode-' + mode);
      if (document.body && document.body.classList) {
        document.body.classList.toggle('reading-mode-shell-article', mode === 'article');
      }
      syncPptScrollbarSkin();
      syncAria(mode);
      if (opts.fromUser) userChosen = true;
    }

    function applyViewportDefault() {
      if (userChosen) return;
      setMode(defaultModeFromData(), { fromUser: false });
    }

    function onReadingMqChange() {
      applyViewportDefault();
    }

    function applyPptUnavailable() {
      pptOk = false;
      readingRoot.setAttribute('data-ppt-probe', 'fail');

      if (frame) {
        try {
          frame.removeAttribute('src');
          frame.setAttribute('src', 'about:blank');
        } catch (eF) { /* ignore */ }
      }
      if (standalone) standalone.style.display = 'none';
      var buttons = readingRoot.querySelectorAll(
        '.reading-mode-switcher__btn[data-reading-mode]'
      );
      buttons.forEach(function (btn) {
        var m = btn.getAttribute('data-reading-mode');
        if (m === 'split' || m === 'ppt') {
          btn.style.display = 'none';
          btn.setAttribute('aria-hidden', 'true');
          btn.setAttribute('tabindex', '-1');
        } else {
          btn.style.display = '';
          btn.removeAttribute('aria-hidden');
          btn.removeAttribute('tabindex');
        }
      });

      var cur = getMode();
      if (cur === 'split' || cur === 'ppt' || !cur) {
        setMode('article', { fromUser: false });
      } else {
        syncAria(getMode());
      }
    }

    function runSameOriginProbe() {
      if (!pptResolved || pptResolved.origin !== window.location.origin) return;

      if (typeof fetch !== 'function') {
        readingRoot.setAttribute('data-ppt-probe', 'skip-no-fetch');
        return;
      }

      var href = pptResolved.href;
      var ac = typeof AbortController !== 'undefined' ? new AbortController() : null;
      var to = 0;
      if (ac) {
        to = window.setTimeout(function () {
          try {
            ac.abort();
          } catch (eA) { /* ignore */ }
        }, 8000);
      }

      function clearTo() {
        if (to) window.clearTimeout(to);
      }

      function tryGet() {
        return fetch(href, {
          method: 'GET',
          cache: 'no-store',
          credentials: 'same-origin',
          signal: ac ? ac.signal : undefined,
          headers: { Range: 'bytes=0-0' }
        }).then(function (r) {
          return r.ok || r.status === 206;
        });
      }

      function tryHead() {
        return fetch(href, {
          method: 'HEAD',
          cache: 'no-store',
          credentials: 'same-origin',
          signal: ac ? ac.signal : undefined
        }).then(function (r) {
          if (r.ok) return true;
          return tryGet();
        }).catch(function () {
          return tryGet();
        });
      }

      tryHead()
        .then(function (ok) {
          clearTo();
          if (ok) {
            readingRoot.setAttribute('data-ppt-probe', 'ok');
            return;
          }
          applyPptUnavailable();
        })
        .catch(function () {
          clearTo();
          applyPptUnavailable();
        });
    }

    setMode(defaultModeFromData(), { fromUser: false });

    readingRoot.addEventListener('click', function (e) {
      var btn = e.target && e.target.closest &&
        e.target.closest('.reading-mode-switcher__btn[data-reading-mode]');
      if (!btn || !readingRoot.contains(btn)) return;
      if (btn.style.display === 'none') return;
      var m = normalizeMode(btn.getAttribute('data-reading-mode'));
      setMode(m, { fromUser: true });
    });

    if (mq) {
      if (mq.addEventListener) mq.addEventListener('change', onReadingMqChange);
      else if (mq.addListener) mq.addListener(onReadingMqChange);
    }

    if (frame) {
      frame.addEventListener('load', function () {
        syncPptScrollbarSkin();
        window.setTimeout(syncPptScrollbarSkin, 120);
        window.setTimeout(syncPptScrollbarSkin, 600);
      });
      window.setTimeout(syncPptScrollbarSkin, 0);
    }

    if (!pptResolved) {
      applyPptUnavailable();
    } else if (pptResolved.origin !== window.location.origin) {
      /* 跨域：不因 CORS 误判，不在此发 fetch；由 iframe / 独立页承担加载结果 */
      readingRoot.setAttribute('data-ppt-probe', 'skip-cross-origin');
    } else {
      runSameOriginProbe();
    }
  }

  function runInitArticleReadingMode() {
    initArticleReadingMode();
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', runInitArticleReadingMode);
  } else {
    runInitArticleReadingMode();
  }

  // --- Tag：按标签文字哈希自动配色，无需改 JS；新文章只要在表格末列写 甲/乙/丙 ---
  var TAG_PALETTE = [
    '45, 212, 191',
    '192, 132, 252',
    '74, 222, 128',
    '251, 146, 60',
    '244, 114, 182',
    '96, 165, 250',
    '251, 191, 36',
    '250, 82, 170'
  ];

  function hashTagLabel(s) {
    var h = 5381;
    for (var i = 0; i < s.length; i++) {
      h = ((h << 5) + h) + s.charCodeAt(i);
      h |= 0;
    }
    return h === 0 ? 0 : Math.abs(h);
  }

  /** 同一标签全文颜色稳定；同一格内若与左侧相邻同色则顺延调色板 */
  function paletteIndexForTag(label, prevIdx) {
    var n = TAG_PALETTE.length;
    var idx = hashTagLabel(label) % n;
    var guard = 0;
    while (idx === prevIdx && guard < n) {
      idx = (idx + 1) % n;
      guard++;
    }
    return idx;
  }

  // --- 过长页面标题：标签页内循环滚动（尊重 reduced-motion 则无动画）---
  var titleFullMeta = document.querySelector('meta[name="doc-title-full"]');
  var marqueeAt = parseInt(document.documentElement.getAttribute('data-title-marquee-at') || '34', 10);
  if (titleFullMeta && titleFullMeta.content && !reduceMotion) {
    var fullTitle = titleFullMeta.content;
    if (fullTitle.length > marqueeAt) {
      var gap = '  ·  ';
      var loop = fullTitle + gap;
      var vis = Math.max(14, Math.min(28, marqueeAt - 2));
      var pos = 0;
      setInterval(function () {
        var L = loop.length;
        var out = '';
        for (var c = 0; c < vis; c++) {
          out += loop.charAt((pos + c) % L);
        }
        document.title = out;
        pos = (pos + 1) % L;
      }, 300);
    }
  }

  var bodyTables = document.querySelectorAll('.terminal-body table');
  bodyTables.forEach(function (table) {
    var rows = table.querySelectorAll('tbody tr');
    if (!rows.length) {
      rows = table.querySelectorAll('tr');
    }
    rows.forEach(function (row) {
      if (row.parentElement && row.parentElement.tagName === 'THEAD') return;
      var td = row.querySelector('td:last-child');
      if (!td) return;
      var raw = td.textContent.trim();
      if (!raw || td.querySelector('a')) return;
      var parts = raw.split('/').map(function (x) { return x.trim(); }).filter(Boolean);
      if (!parts.length) return;
      td.textContent = '';
      var prevIdx = -1;
      parts.forEach(function (t) {
        var idx = paletteIndexForTag(t, prevIdx);
        prevIdx = idx;
        var span = document.createElement('span');
        span.className = 'tag-badge';
        span.style.setProperty('--tag-rgb', TAG_PALETTE[idx]);
        span.textContent = t;
        td.appendChild(span);
      });
    });
  });
})();
