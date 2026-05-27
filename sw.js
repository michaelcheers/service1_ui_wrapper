// Service1 UI wrapper service worker.
// Proxies same-origin requests from ui.service1.app to ui-raw.service1.app
// and rewrites HTML responses to inject the Trusted Types bootstrap + CSP.

const VERSION = 'v1.0.0';
const RAW_ORIGIN = 'https://ui-raw.service1.app';
const CACHE_NAME = 's1-ui-' + VERSION;
const SHELL_FILES = new Set(['/sw.js', '/404.html', '/policy/bootstrap.js', '/unsupported.html', '/CNAME', '/.nojekyll']);

const UNSUPPORTED_CLIENTS = new Map();

// Browser-capability verification. The gate page proves the engine enforces
// Trusted Types (incl. javascript: URLs) and posts TT_VERIFIED; we record it and
// from then on serve the real proxied app. Persisted in the versioned cache so a
// new SW VERSION transparently forces re-verification.
let TT_VERIFIED_MEM = false;
const VERIFIED_KEY = '/__s1_tt_verified__';

async function isVerified() {
  if (TT_VERIFIED_MEM) return true;
  try {
    const c = await caches.open(CACHE_NAME);
    if (await c.match(VERIFIED_KEY)) { TT_VERIFIED_MEM = true; return true; }
  } catch (_) {}
  return false;
}
async function setVerified() {
  TT_VERIFIED_MEM = true;
  try { const c = await caches.open(CACHE_NAME); await c.put(VERIFIED_KEY, new Response('1')); } catch (_) {}
}

function gateHtml() {
  return '<!doctype html><html><head><meta charset="utf-8">'
       + '<meta name="viewport" content="width=device-width,initial-scale=1">'
       + '<title>Checking browser\u2026</title>'
       + '<script>window.__S1_GATE__=1;<\/script>'
       + '<script src="/policy/bootstrap.js"><\/script>'
       + '<style>body{font:14px Inter,system-ui;padding:40px;max-width:560px;color:#333}</style>'
       + '</head><body><p>Checking browser security\u2026</p></body></html>';
}
async function serveGate() {
  return new Response(gateHtml(), { status: 200, headers: hardenedHeaders(new Headers(), 'text/html; charset=utf-8') });
}

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    try {
      await cache.addAll(['/policy/bootstrap.js', '/unsupported.html', '/404.html']);
    } catch (_) {}
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('message', (event) => {
  const data = event.data || {};
  const cid = event.source && event.source.id;
  if (data.type === 'CLAIM') {
    self.clients.claim();
    if (cid && data.supported === false) UNSUPPORTED_CLIENTS.set(cid, true);
  }
  if (data.type === 'TT_PROBE' && cid) {
    if (data.supported === false) UNSUPPORTED_CLIENTS.set(cid, true);
    else UNSUPPORTED_CLIENTS.delete(cid);
  }
  if (data.type === 'TT_VERIFIED') {
    const port = event.ports && event.ports[0];
    event.waitUntil(setVerified().then(() => { if (port) { try { port.postMessage({ ok: true }); } catch (_) {} } }));
  }
});

function cspHeader() {
  return "script-src 'self' 'unsafe-inline' https://maps.googleapis.com; "
       + "require-trusted-types-for 'script'; "
       + "trusted-types s1-policy default s1-pass;";
}

function hardenedHeaders(srcHeaders, contentType) {
  const h = new Headers();
  // Copy a safe subset of upstream headers.
  for (const [k, v] of srcHeaders.entries()) {
    const lk = k.toLowerCase();
    if (lk === 'content-encoding' || lk === 'content-length' || lk === 'transfer-encoding') continue;
    if (lk === 'content-security-policy') continue;
    h.set(k, v);
  }
  if (contentType) h.set('Content-Type', contentType);
  h.set('Content-Security-Policy', cspHeader());
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('Cache-Control', 'no-store');
  h.set('Cross-Origin-Resource-Policy', 'same-origin');
  return h;
}

function rewriteHtml(text) {
  // Strip any inline CSP <meta http-equiv> tags so the SW's CSP header is authoritative.
  let out = text.replace(/<meta[^>]+http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*>/gi, '');
  const inject = '<script src="/policy/bootstrap.js"></script>';
  if (/<head[^>]*>/i.test(out)) {
    out = out.replace(/<head[^>]*>/i, (m) => m + inject);
  } else if (/<html[^>]*>/i.test(out)) {
    out = out.replace(/<html[^>]*>/i, (m) => m + '<head>' + inject + '</head>');
  } else {
    out = inject + out;
  }
  return out;
}

async function serveUnsupported() {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match('/unsupported.html');
  if (cached) {
    const body = await cached.text();
    return new Response(body, { status: 200, headers: hardenedHeaders(new Headers(), 'text/html; charset=utf-8') });
  }
  return new Response('<!doctype html><meta charset=utf-8><title>Unsupported</title><p>Browser not supported.',
    { status: 200, headers: hardenedHeaders(new Headers(), 'text/html; charset=utf-8') });
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  const path = url.pathname;

  // Shell-owned files: let the network/GH Pages serve directly.
  if (SHELL_FILES.has(path)) return;

  const cid = event.clientId || event.resultingClientId;
  if (cid && UNSUPPORTED_CLIENTS.get(cid)) {
    event.respondWith(serveUnsupported());
    return;
  }

  // Until the browser has passed the gate, every top-level navigation gets the
  // gate page instead of the real app. The real proxied app is never served to an
  // unverified engine.
  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      if (await isVerified()) return proxyApp(url, path);
      return serveGate();
    })());
    return;
  }

  event.respondWith(proxyApp(url, path));
});

async function proxyApp(url, path) {
  {
    const rawUrl = RAW_ORIGIN + path + url.search;
    let resp;
    try {
      resp = await fetch(rawUrl, { mode: 'cors', credentials: 'omit', redirect: 'follow' });
    } catch (e) {
      const cache = await caches.open(CACHE_NAME);
      const cached = await cache.match(rawUrl);
      if (cached) return cached;
      return new Response('Upstream unavailable', { status: 502, headers: { 'Content-Type': 'text/plain' } });
    }

    const ct = (resp.headers.get('content-type') || '').toLowerCase();
    let body;
    if (ct.includes('text/html')) {
      body = await resp.text();
      body = rewriteHtml(body);
      const out = new Response(body, { status: resp.status, headers: hardenedHeaders(resp.headers, 'text/html; charset=utf-8') });
      try {
        const cache = await caches.open(CACHE_NAME);
        cache.put(rawUrl, out.clone());
      } catch (_) {}
      return out;
    } else {
      body = await resp.arrayBuffer();
      const out = new Response(body, { status: resp.status, headers: hardenedHeaders(resp.headers, resp.headers.get('content-type') || 'application/octet-stream') });
      try {
        const cache = await caches.open(CACHE_NAME);
        cache.put(rawUrl, out.clone());
      } catch (_) {}
      return out;
    }
  }
}
