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

  // --- Matrix rain ---
  var canvas = document.getElementById('matrix-canvas');
  if (canvas && !reduceMotion) {
    var ctx = canvas.getContext('2d');
    var W, H, cols, drops;
    var CHARS = '01ABCDEFabcdef0123456789アイウエオカキクケコサシスセソタチツテト';

    function resizeCanvas() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
      cols = Math.floor(W / 16);
      drops = [];
      for (var i = 0; i < cols; i++) drops[i] = Math.random() * -H;
    }

    var NEON = [
      'rgba(56, 250, 220, 0.3)',
      'rgba(232, 121, 249, 0.26)',
      'rgba(74, 222, 128, 0.22)',
      'rgba(255, 100, 200, 0.2)'
    ];

    function drawMatrix() {
      ctx.fillStyle = 'rgba(9, 10, 15, 0.07)';
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
