/**
 * 文章 / 全站浏览计数（Cloudflare Worker + KV）
 * GET /hit?ns=&key=  →  JSON { "value": n }
 * GET /hit?...&callback=cb  →  application/javascript  cb({"value":n});
 */

function parseAllowedOrigins(env) {
  var raw = env.ALLOW_ORIGINS || '';
  return raw.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
}

/** 浏览器可能发字面量 "null"；无效则当未携带 */
function normalizeOriginHeader(request) {
  var o = request.headers.get('Origin');
  if (!o || o === 'null') return null;
  return o;
}

/** 用于放行判断：优先 Origin，否则从 Referer 推导（curl 常无 Origin 仅有 Referer） */
function effectiveOriginForPolicy(request) {
  var o = normalizeOriginHeader(request);
  if (o) return o;
  var ref = request.headers.get('Referer');
  if (!ref) return null;
  try {
    return new URL(ref).origin;
  } catch (e) {
    return null;
  }
}

function isOriginAllowed(origin, env) {
  if (!origin) return false;
  var list = parseAllowedOrigins(env);
  if (list.indexOf('*') !== -1) return true;
  if (list.indexOf(origin) !== -1) return true;

  /* 未设置或显式空字符串：仍默认按 sumsec.me 后缀放行，避免 Dashboard 误配空串导致整站 403 */
  var sufRaw = env.ALLOW_HOST_SUFFIX;
  var suf =
    sufRaw === undefined || sufRaw === null || String(sufRaw).trim() === ''
      ? 'sumsec.me'
      : String(sufRaw).trim();

  try {
    var u = new URL(origin);
    var h = u.hostname;
    /* 后缀配成 www.xxx 时仍放行 apex（如 Referer 为 https://sumsec.me/） */
    var apex = suf.replace(/^www\./, '');
    if (h === suf || h === apex) return true;
    if (h.endsWith('.' + apex)) return true;
  } catch (e) { /* ignore */ }
  return false;
}

function corsHeaders(request, env) {
  var origin = normalizeOriginHeader(request);
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
    var cbName = sanitizeJsonpCallback(url.searchParams.get('callback'));

    var eff = effectiveOriginForPolicy(request);
    if (!cbName) {
      if (eff && !isOriginAllowed(eff, env)) {
        return rejectJson(403, 'origin not allowed');
      }
    }

    if (!env.capi) {
      return rejectJson(500, 'KV binding capi missing');
    }

    var name = kvKey(ns, key);
    var prev = await env.capi.get(name);
    var n = parseInt(prev, 10);
    if (isNaN(n) || n < 0) n = 0;
    n += 1;
    ctx.waitUntil(env.capi.put(name, String(n)));

    if (cbName) {
      var js = cbName + '(' + JSON.stringify({ value: n }) + ');';
      return new Response(js, {
        headers: {
          'content-type': 'application/javascript; charset=utf-8',
          'cache-control': 'no-store, private',
          'CDN-Cache-Control': 'no-store',
          'X-Content-Type-Options': 'nosniff',
        },
      });
    }

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
