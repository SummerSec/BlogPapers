/**
 * 文章 / 全站浏览计数（Cloudflare Worker + KV）
 * API: GET /hit?ns=命名空间&key=键名  →  { "value": <递增后的整数> }
 * 与博客端 scifi.js 中 CountAPI 的 key 规则一致（ns + key 存入 KV）。
 */

function parseAllowedOrigins(env) {
  var raw = env.ALLOW_ORIGINS || 'https://sumsec.me,https://www.sumsec.me';
  return raw.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
}

function corsHeaders(request, env) {
  var origin = request.headers.get('Origin');
  var list = parseAllowedOrigins(env);
  var allow = null;
  if (list.indexOf('*') !== -1) {
    allow = '*';
  } else if (origin && list.indexOf(origin) !== -1) {
    allow = origin;
  } else if (!origin && list.length) {
    /* 无 Origin（如 curl）：仍返回 JSON，便于自检；浏览器跨域必须有合法 Origin */
    allow = list[0];
  }
  var h = {
    'Access-Control-Allow-Methods': 'GET,HEAD,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
  };
  if (allow) {
    h['Access-Control-Allow-Origin'] = allow;
    if (allow !== '*') h.Vary = 'Origin';
  }
  return h;
}

function rejectJson(status, msg) {
  return new Response(JSON.stringify({ error: msg }), {
    status: status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

function sanitizeSegment(s, max) {
  max = max || 128;
  return String(s || '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .slice(0, max);
}

function kvKey(ns, key) {
  return 'v1:' + sanitizeSegment(ns, 64) + ':' + sanitizeSegment(key, 200);
}

export default {
  async fetch(request, env, ctx) {
    var url = new URL(request.url);
    var path = url.pathname.replace(/\/$/, '') || '/';

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return rejectJson(405, 'method not allowed');
    }

    var origin = request.headers.get('Origin');
    var list = parseAllowedOrigins(env);
    if (list.indexOf('*') === -1 && origin && list.indexOf(origin) === -1) {
      return rejectJson(403, 'origin not allowed');
    }

    if (path !== '/hit' && path !== '/hit/') {
      return new Response(JSON.stringify({ ok: true, service: 'page-stats' }), {
        headers: Object.assign(
          { 'content-type': 'application/json; charset=utf-8' },
          corsHeaders(request, env)
        ),
      });
    }

    var ns = sanitizeSegment(url.searchParams.get('ns') || 'default', 64);
    var key = sanitizeSegment(url.searchParams.get('key') || 'page', 200);
    if (!env.STATS) {
      return rejectJson(500, 'KV binding STATS missing');
    }

    var name = kvKey(ns, key);
    var prev = await env.STATS.get(name);
    var n = parseInt(prev, 10);
    if (isNaN(n) || n < 0) n = 0;
    n += 1;
    ctx.waitUntil(env.STATS.put(name, String(n)));

    var body = JSON.stringify({ value: n });
    return new Response(body, {
      headers: Object.assign(
        { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
        corsHeaders(request, env)
      ),
    });
  },
};
