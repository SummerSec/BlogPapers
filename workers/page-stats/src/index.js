/**
 * 文章 / 全站浏览计数（Cloudflare Worker + KV）
 * API: GET /hit?ns=命名空间&key=键名  →  { "value": <递增后的整数> }
 * 与博客端 scifi.js 中 CountAPI 的 key 规则一致（ns + key 存入 KV）。
 */

function parseAllowedOrigins(env) {
  var raw = env.ALLOW_ORIGINS || '';
  return raw.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
}

/**
 * 是否允许该 Origin。除显式列表外，还可通过 ALLOW_HOST_SUFFIX（默认 sumsec.me）
 * 放行同一主域下任意 https 子域（如 www / 根域 / 其他子域），避免漏配导致 CORS 403。
 */
function isOriginAllowed(origin, env) {
  if (!origin) return false;
  var list = parseAllowedOrigins(env);
  if (list.indexOf('*') !== -1) return true;
  if (list.indexOf(origin) !== -1) return true;

  var suf = env.ALLOW_HOST_SUFFIX;
  if (suf === undefined || suf === null) suf = 'sumsec.me';
  suf = String(suf).trim();
  if (!suf) return false;

  try {
    var u = new URL(origin);
    var h = u.hostname;
    if (h === suf) return true;
    if (h.endsWith('.' + suf)) return true;
  } catch (e) { /* ignore */ }
  return false;
}

function corsHeaders(request, env) {
  var origin = request.headers.get('Origin');
  var list = parseAllowedOrigins(env);
  var allow = null;
  if (list.indexOf('*') !== -1) {
    allow = '*';
  } else if (origin && isOriginAllowed(origin, env)) {
    allow = origin;
  } else if (!origin && list.length) {
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
    if (origin && !isOriginAllowed(origin, env)) {
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
        {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store, private',
          'CDN-Cache-Control': 'no-store',
        },
        corsHeaders(request, env)
      ),
    });
  },
};
