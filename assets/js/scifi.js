(function () {
  'use strict';

  var reduceMotion = typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // --- Normalize pathname for nav active matching ---
  function normalizePathForNav(p) {
    if (!p) return '/';
    p = p.replace(/\/$/, '') || '/';
    if (p === '/index.html') return '/';
    if (p.endsWith('/index.html')) return p.slice(0, -10) || '/';
    if (p.endsWith('.html')) {
      var noExt = p.slice(0, -5);
      if (noExt.endsWith('/index')) return noExt.slice(0, -6) || '/';
    }
    return p;
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

    function drawMatrix() {
      ctx.fillStyle = 'rgba(5, 5, 8, 0.07)';
      ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = '#00f5ff18';
      ctx.font = '14px "JetBrains Mono", "Noto Sans SC", monospace';
      for (var i = 0; i < cols; i++) {
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

  // --- Tag badge coloring ---
  var SECURITY_TAGS = ['漏洞分析', '命令执行', 'RCE', 'SpEL', 'SSRF', 'XSS', 'SQL', 'bypass', 'Injection', 'injection', 'CVE', 'shell'];
  var JAVA_TAGS = ['Java', 'CodeQL', 'go', 'Spark', 'MongoDB', 'Spring', 'JVM', 'Kotlin'];
  var AI_TAGS = ['AI', 'SKILL', 'LLM', '语义', '大模型', 'GPT', '机器学习', '算法'];

  function tagCategory(t) {
    var u = t.trim();
    if (SECURITY_TAGS.some(function (k) { return u.indexOf(k) !== -1; })) return 'security';
    if (JAVA_TAGS.some(function (k) { return u.indexOf(k) !== -1; })) return 'java';
    if (AI_TAGS.some(function (k) { return u.indexOf(k) !== -1; })) return 'ai';
    return 'default';
  }

  document.querySelectorAll('.terminal-body table td:last-child').forEach(function (td) {
    var raw = td.textContent.trim();
    if (!raw || td.querySelector('a')) return;
    var tags = raw.split('/');
    if (tags.length < 1) return;
    td.textContent = '';
    tags.forEach(function (t) {
      if (!t.trim()) return;
      var span = document.createElement('span');
      span.className = 'tag-badge tag-' + tagCategory(t);
      span.textContent = t.trim();
      td.appendChild(span);
    });
  });
})();
