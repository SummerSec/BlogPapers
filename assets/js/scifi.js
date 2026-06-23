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

  // --- Theme toggle (feei.cn style) ---
  function applyTheme(theme) {
    var root = document.documentElement;
    var meta = document.querySelector('meta[name="theme-color"]');
    if (theme === 'dark') {
      root.setAttribute('data-theme', 'dark');
      if (meta) meta.setAttribute('content', '#1b1b1d');
    } else {
      root.removeAttribute('data-theme');
      if (meta) meta.setAttribute('content', '#fafafa');
    }
    try {
      localStorage.setItem('sumsec-theme', theme);
    } catch (eStore) { /* ignore */ }
  }

  var themeBtn = document.getElementById('theme-toggle');
  if (themeBtn) {
    themeBtn.addEventListener('click', function () {
      var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      applyTheme(isDark ? 'light' : 'dark');
      refreshSignalFieldColors();
    });
  }

  // --- Mobile nav toggle ---
  var navToggle = document.getElementById('nav-toggle');
  var siteNav = document.querySelector('.site-nav');
  if (navToggle && siteNav) {
    navToggle.addEventListener('click', function () {
      var open = siteNav.classList.toggle('is-open');
      navToggle.setAttribute('aria-expanded', open ? 'true' : 'false');
    });
    siteNav.querySelectorAll('.nav-link').forEach(function (link) {
      link.addEventListener('click', function () {
        siteNav.classList.remove('is-open');
        navToggle.setAttribute('aria-expanded', 'false');
      });
    });
  }

  // --- Signal field hero background ---
  var signalCanvas = document.getElementById('signal-field-canvas');
  var signalHost = document.getElementById('signal-field-host');
  var signalCtx = null;
  var signalAnim = 0;
  var signalNodes = [];
  var signalSize = { width: 0, height: 0 };
  var signalStart = Date.now();

  function signalPalette() {
    var dark = document.documentElement.getAttribute('data-theme') === 'dark';
    return dark
      ? { line: 'rgba(255, 121, 72, 0.18)', dot: 'rgba(255, 174, 124, 0.68)' }
      : { line: 'rgba(64, 224, 202, 0.18)', dot: 'rgba(144, 255, 232, 0.72)' };
  }

  function refreshSignalFieldColors() {
    drawSignalField((Date.now() - signalStart) / 1000);
  }

  function initSignalNodes() {
    signalNodes = [];
    var w = signalSize.width;
    var h = signalSize.height;
    var count = Math.max(24, Math.min(62, Math.round(w * h / 24000)));
    for (var i = 0; i < count; i++) {
      signalNodes.push({
        x: Math.random() * w,
        y: h * 0.12 + Math.random() * h * 0.72,
        vx: (Math.random() - 0.5) * 0.18,
        vy: (Math.random() - 0.5) * 0.12,
        r: 1.2 + Math.random() * 1.9,
        phase: Math.random() * Math.PI * 2
      });
    }
  }

  function resizeSignalCanvas() {
    if (!signalCanvas || !signalHost) return;
    var dpr = window.devicePixelRatio || 1;
    var rect = signalHost.getBoundingClientRect();
    signalSize = { width: rect.width, height: rect.height };
    signalCanvas.width = rect.width * dpr;
    signalCanvas.height = rect.height * dpr;
    signalCanvas.style.width = rect.width + 'px';
    signalCanvas.style.height = rect.height + 'px';
    if (signalCtx) signalCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
    initSignalNodes();
    drawSignalField(0);
  }

  function updateSignalNodes() {
    var w = signalSize.width;
    var h = signalSize.height;
    signalNodes.forEach(function (node) {
      node.x += node.vx;
      node.y += node.vy;
      if (node.x < -20) node.x = w + 20;
      if (node.x > w + 20) node.x = -20;
      if (node.y < h * 0.08 || node.y > h * 0.86) node.vy *= -1;
    });
  }

  function withAlpha(rgba, alpha) {
    return rgba.replace(/rgba\(([^,]+),([^,]+),([^,]+),[^)]+\)/, 'rgba($1,$2,$3,' + alpha + ')');
  }

  function drawSignalField(t) {
    if (!signalCtx || !signalCanvas) return;
    var w = signalSize.width;
    var h = signalSize.height;
    var palette = signalPalette();
    signalCtx.clearRect(0, 0, w, h);

    signalCtx.save();
    signalCtx.lineWidth = 1;
    for (var i = 0; i < signalNodes.length; i++) {
      for (var j = i + 1; j < signalNodes.length; j++) {
        var a = signalNodes[i];
        var b = signalNodes[j];
        var dx = a.x - b.x;
        var dy = a.y - b.y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist > 148) continue;
        var alpha = (1 - dist / 148) * 0.55;
        signalCtx.strokeStyle = withAlpha(palette.line, alpha.toFixed(3));
        signalCtx.beginPath();
        signalCtx.moveTo(a.x, a.y);
        signalCtx.lineTo(b.x, b.y);
        signalCtx.stroke();
      }
    }

    signalNodes.forEach(function (node) {
      var pulse = 0.65 + Math.sin(t * 2.2 + node.phase) * 0.35;
      signalCtx.fillStyle = palette.dot;
      signalCtx.shadowColor = palette.dot;
      signalCtx.shadowBlur = 10 * pulse;
      signalCtx.beginPath();
      signalCtx.arc(node.x, node.y, node.r + pulse * 0.8, 0, Math.PI * 2);
      signalCtx.fill();
    });
    signalCtx.restore();
  }

  function runSignalLoop() {
    var t = (Date.now() - signalStart) / 1000;
    updateSignalNodes();
    drawSignalField(t);
    signalAnim = requestAnimationFrame(runSignalLoop);
  }

  if (signalCanvas && signalHost) {
    signalCtx = signalCanvas.getContext('2d');
    resizeSignalCanvas();
    if (!reduceMotion) runSignalLoop();
    var signalResizeTimer = 0;
    window.addEventListener('resize', function () {
      clearTimeout(signalResizeTimer);
      signalResizeTimer = setTimeout(function () {
        cancelAnimationFrame(signalAnim);
        resizeSignalCanvas();
        if (!reduceMotion) runSignalLoop();
      }, 100);
    });
  }

  // --- Hero typewriter (feei.cn TextType, vanilla) ---
  function initHeroTypewriter() {
    var el = document.getElementById('hero-typewriter');
    if (!el || reduceMotion) return;
    var raw = el.getAttribute('data-typewriter');
    var texts = [];
    try {
      texts = JSON.parse(raw || '[]');
    } catch (eParse) {
      texts = [el.textContent || ''];
    }
    if (!texts.length) return;
    var textIndex = 0;
    var charIndex = 0;
    var deleting = false;
    var cursor = document.createElement('span');
    cursor.className = 'type-cursor';
    cursor.textContent = '_';
    el.textContent = '';

    function tick() {
      var current = texts[textIndex] || '';
      if (!deleting) {
        el.textContent = current.slice(0, charIndex + 1);
        charIndex++;
        if (charIndex >= current.length) {
          deleting = true;
          setTimeout(tick, 1500);
          return;
        }
        setTimeout(tick, 75);
      } else {
        el.textContent = current.slice(0, charIndex - 1);
        charIndex--;
        if (charIndex <= 0) {
          deleting = false;
          textIndex = (textIndex + 1) % texts.length;
          setTimeout(tick, 400);
          return;
        }
        setTimeout(tick, 50);
      }
      el.appendChild(cursor);
    }

    tick();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initHeroTypewriter);
  } else {
    initHeroTypewriter();
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
          doc.documentElement.style.scrollbarColor = 'rgba(46, 133, 85, 0.35) #fafafa';
        }
        if (doc.body) {
          if (doc.body.classList) doc.body.classList.add('sumsec-scroll-root');
          doc.body.style.scrollbarWidth = 'thin';
          doc.body.style.scrollbarColor = 'rgba(46, 133, 85, 0.35) #fafafa';
        }

        style.textContent =
          '.sumsec-scroll-root, html, body {' +
          'scrollbar-width: thin;' +
          'scrollbar-color: rgba(46, 133, 85, 0.35) #fafafa;' +
          '}' +
          '.sumsec-scroll-root::-webkit-scrollbar, html::-webkit-scrollbar, body::-webkit-scrollbar { width: 8px; height: 8px; }' +
          '.sumsec-scroll-root::-webkit-scrollbar-track, html::-webkit-scrollbar-track, body::-webkit-scrollbar-track { background: #fafafa; }' +
          '.sumsec-scroll-root::-webkit-scrollbar-thumb, html::-webkit-scrollbar-thumb, body::-webkit-scrollbar-thumb { background: rgba(46, 133, 85, 0.35); border-radius: 4px; }' +
          '.sumsec-scroll-root::-webkit-scrollbar-thumb:hover, html::-webkit-scrollbar-thumb:hover, body::-webkit-scrollbar-thumb:hover { background: rgba(46, 133, 85, 0.55); }';
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

  var bodyTables = document.querySelectorAll('.page-body table');
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
