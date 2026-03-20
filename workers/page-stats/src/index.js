/**
 * 文章 / 全站浏览计数（Cloudflare Worker + KV）
 * GET /hit?ns=&key=            →  JSON { "value": n }
 * GET /hit?...&callback=cb     →  application/javascript  cb({"value":n});
 * GET /trend?ns=&key=&days=30  →  JSON { "points": [...], "total": n }
 */

var OPEN_CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,HEAD,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cross-Origin-Resource-Policy': 'cross-origin',
};

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

function sanitizeJsonpCallback(name) {
  if (!name || typeof name !== 'string') return null;
  name = name.trim();
  if (name.length > 64) return null;
  if (!/^[$A-Za-z_][$\w]*$/.test(name)) return null;
  return name;
}

function kvKey(ns, key) {
  return 'v1:' + sanitizeSegment(ns, 64) + ':' + sanitizeSegment(key, 200);
}

function todayUTC() {
  return new Date().toISOString().slice(0, 10);
}

/* ---- /hit handler ---- */

async function handleHit(url, env, ctx) {
  var ns = sanitizeSegment(url.searchParams.get('ns') || 'default', 64);
  var key = sanitizeSegment(url.searchParams.get('key') || 'page', 200);
  var cbName = sanitizeJsonpCallback(url.searchParams.get('callback'));

  if (!env.capi) return rejectJson(500, 'KV binding capi missing');

  var name = kvKey(ns, key);
  var prev = await env.capi.get(name);
  var n = parseInt(prev, 10);
  if (isNaN(n) || n < 0) n = 0;
  n += 1;

  var dayKey = name + ':d:' + todayUTC();
  ctx.waitUntil(Promise.all([
    env.capi.put(name, String(n)),
    env.capi.put(dayKey, String(n)),
  ]));

  if (cbName) {
    return new Response(cbName + '(' + JSON.stringify({ value: n }) + ');', {
      headers: Object.assign({
        'content-type': 'application/javascript; charset=utf-8',
        'cache-control': 'no-store, private',
        'CDN-Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      }, OPEN_CORS),
    });
  }

  return new Response(JSON.stringify({ value: n }), {
    headers: Object.assign({
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store, private',
      'CDN-Cache-Control': 'no-store',
    }, OPEN_CORS),
  });
}

/* ---- /trend handler ---- */

async function handleTrend(url, env) {
  var ns = sanitizeSegment(url.searchParams.get('ns') || 'default', 64);
  var key = sanitizeSegment(url.searchParams.get('key') || 'page', 200);
  var days = Math.min(Math.max(parseInt(url.searchParams.get('days'), 10) || 30, 1), 90);

  if (!env.capi) return rejectJson(500, 'KV binding capi missing');

  var prefix = kvKey(ns, key) + ':d:';
  var listed = await env.capi.list({ prefix: prefix, limit: 1000 });
  var allKeys = (listed.keys || []).map(function (k) { return k.name; });
  allKeys.sort();
  var recent = allKeys.slice(-days);

  var points = await Promise.all(recent.map(function (k) {
    return env.capi.get(k).then(function (v) {
      var date = k.slice(prefix.length);
      var val = parseInt(v, 10);
      return { date: date, value: isNaN(val) ? 0 : val };
    });
  }));

  var totalRaw = await env.capi.get(kvKey(ns, key));
  var total = parseInt(totalRaw, 10);
  if (isNaN(total)) total = 0;

  return new Response(JSON.stringify({ points: points, total: total }), {
    headers: Object.assign({
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'public, max-age=300',
    }, OPEN_CORS),
  });
}

/* ---- main fetch ---- */

export default {
  async fetch(request, env, ctx) {
    var url = new URL(request.url);
    var path = url.pathname.replace(/\/$/, '') || '/';

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: Object.assign({ 'Access-Control-Max-Age': '86400' }, OPEN_CORS),
      });
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return rejectJson(405, 'method not allowed');
    }

    if (path === '/hit') return handleHit(url, env, ctx);
    if (path === '/trend') return handleTrend(url, env);

    return new Response(JSON.stringify({ ok: true, service: 'page-stats' }), {
      headers: Object.assign(
        { 'content-type': 'application/json; charset=utf-8' },
        OPEN_CORS
      ),
    });
  },
};
