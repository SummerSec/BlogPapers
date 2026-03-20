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
    var lineColor = isPage ? 'rgba(192,132,252,0.9)' : 'rgba(45,212,191,0.9)';
    var fillColor = isPage ? 'rgba(192,132,252,0.15)' : 'rgba(45,212,191,0.15)';
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
      'rgba(72, 255, 228, 0.34)',
      'rgba(200, 150, 255, 0.3)',
      'rgba(94, 255, 150, 0.26)',
      'rgba(255, 120, 210, 0.24)'
    ];

    function drawMatrix() {
      ctx.fillStyle = 'rgba(6, 7, 13, 0.065)';
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

  // --- 宽屏两侧彩蛋：点击后在控制台输出（无弹窗） ---
  document.querySelectorAll('.side-egg[data-egg-msg]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      var msg = el.getAttribute('data-egg-msg');
      if (!msg || typeof console === 'undefined' || !console.log) return;
      console.log('%c■ SUMSEC.EGG', 'color:#2dd4bf;font-weight:bold;font-size:12px', '\n' + msg);
    });
  });

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
