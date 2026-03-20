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
  var path = window.location.pathname;
  navLinks.forEach(function (a) {
    if (a.href && a.href.indexOf(window.location.hostname) !== -1) {
      var ap = new URL(a.href).pathname;
      if (ap === path || (path === '/' && ap === '/')) {
        a.classList.add('nav-active');
      }
    }
  });
})();
