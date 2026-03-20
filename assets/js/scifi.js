(function () {
  'use strict';

  // --- Matrix rain ---
  var canvas = document.getElementById('matrix-canvas');
  if (canvas) {
    var ctx = canvas.getContext('2d');
    var W, H, cols, drops;
    var CHARS = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホ';

    function resizeCanvas() {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
      cols = Math.floor(W / 18);
      drops = [];
      for (var i = 0; i < cols; i++) drops[i] = Math.random() * -H;
    }

    function drawMatrix() {
      ctx.fillStyle = 'rgba(5, 5, 8, 0.07)';
      ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = '#00f5ff18';
      ctx.font = '13px "Fira Code", monospace';
      for (var i = 0; i < cols; i++) {
        var ch = CHARS[Math.floor(Math.random() * CHARS.length)];
        ctx.fillText(ch, i * 18, drops[i]);
        if (drops[i] > H && Math.random() > 0.97) drops[i] = 0;
        drops[i] += 18;
      }
    }

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    setInterval(drawMatrix, 60);
  }

  // --- Glitch effect on site title hover ---
  var titleEl = document.querySelector('.title-main');
  if (titleEl) {
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
  if (promptEl) {
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
  var navLinks = document.querySelectorAll('.nav-link');
  var path = window.location.pathname.replace(/\/$/, '') || '/';
  navLinks.forEach(function (a) {
    if (a.href && a.href.indexOf(window.location.hostname) !== -1) {
      var ap = new URL(a.href).pathname.replace(/\/$/, '') || '/';
      if (ap === path || (path === '/' && (ap === '/' || ap === '/index.html'))) {
        a.classList.add('nav-active');
        a.setAttribute('aria-current', 'page');
      }
    }
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
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // --- Tag badge coloring ---
  var SECURITY_TAGS = ['漏洞分析','命令执行','RCE','SpEL','SSRF','XSS','SQL','bypass','Injection','injection','CVE','shell'];
  var JAVA_TAGS     = ['Java','CodeQL','go','Spark','MongoDB','Spring','JVM','Kotlin'];
  var AI_TAGS       = ['AI','SKILL','LLM','语义','大模型','GPT','机器学习','算法'];

  function tagCategory(t) {
    var u = t.trim();
    if (SECURITY_TAGS.some(function(k){ return u.indexOf(k) !== -1; })) return 'security';
    if (JAVA_TAGS.some(function(k){ return u.indexOf(k) !== -1; })) return 'java';
    if (AI_TAGS.some(function(k){ return u.indexOf(k) !== -1; })) return 'ai';
    return 'default';
  }

  document.querySelectorAll('table td:last-child').forEach(function (td) {
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
