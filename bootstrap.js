// /policy/bootstrap.js — Trusted Types bootstrap injected by the SW.
//
// Runs in one of two modes:
//   GATE MODE  (window.__S1_GATE__ set by the SW's gate page): verify the browser
//              — synchronous sink probe + async javascript:-URL canary — then tell
//              the SW it passed and reload into the real proxied app. Creates NO
//              app policies; the gate page never renders untrusted content.
//   APP MODE   (real proxied page): the engine was already verified by the gate, so
//              just (re-)run the cheap sync probe as defence-in-depth and install
//              the Trusted Types policies the app runs under.
//
// Why a gate page instead of an in-page async check: javascript:-URL execution can
// only be observed asynchronously (it happens at navigation time). Running that
// check on a dedicated gate page — and not serving the real app until it passes —
// makes the async check a genuine pre-execution gate rather than an after-the-fact
// detector. The app HTML never reaches a browser whose engine hasn't been proven.
(function () {
  // ---- shared: probe helpers ----------------------------------------------
  function ttThrows(fn) { try { fn(); return false; } catch (e) { return e instanceof TypeError; } }
  function anyThrows(fn) { try { fn(); return false; } catch (e) { return true; } }

  function ttEnforced() {
    if (typeof window.trustedTypes !== 'object'
        || typeof trustedTypes.createPolicy !== 'function'
        || typeof window.TrustedHTML !== 'function'
        || typeof window.TrustedScript !== 'function'
        || typeof window.TrustedScriptURL !== 'function') return false;

    var inert = document.implementation.createHTMLDocument('');
    var div   = inert.createElement('div');
    var ifr   = inert.createElement('iframe');
    var img   = inert.createElement('img');
    var scr   = inert.createElement('script');

    // TrustedHTML sinks
    var htmlOk =
        ttThrows(function () { div.innerHTML = '<b>x</b>'; })
     && ttThrows(function () { div.outerHTML = '<b>x</b>'; })
     && ttThrows(function () { div.insertAdjacentHTML('beforeend', '<b>x</b>'); })
     && ttThrows(function () { ifr.srcdoc = '<b>x</b>'; })
     && ttThrows(function () { ifr.setAttribute('srcdoc', '<b>x</b>'); })
     && ttThrows(function () { inert.body.innerHTML = '<b>x</b>'; })
     && ttThrows(function () { new DOMParser().parseFromString('<b>x</b>', 'text/html'); })
     && ttThrows(function () { document.createRange().createContextualFragment('<b>x</b>'); });
    if (typeof div.setHTMLUnsafe === 'function')
      htmlOk = htmlOk && ttThrows(function () { div.setHTMLUnsafe('<b>x</b>'); });

    // TrustedScript sinks — event-handler content attributes via setAttribute, script text
    var scriptOk =
        ttThrows(function () { div.setAttribute('onclick', 'void 0'); })
     && ttThrows(function () { img.setAttribute('onerror', 'void 0'); })
     && ttThrows(function () { div.setAttribute('onmouseover', 'void 0'); })
     && ttThrows(function () { scr.text = 'void 0'; })
     && ttThrows(function () { scr.textContent = 'void 0'; });

    // eval / Function / string timers — must not be executable (any throw accepted,
    // since a no-'unsafe-eval' CSP may reject them before TT is consulted)
    var evalOk =
        anyThrows(function () { window.eval('void 0'); })
     && anyThrows(function () { return new Function('return 0'); })
     && anyThrows(function () { var id = setTimeout('void 0', 0); if (id) { clearTimeout(id); throw 0; } });

    // TrustedScriptURL sinks
    var urlOk =
        ttThrows(function () { scr.src = 'probe.js'; })
     && ttThrows(function () { scr.setAttribute('src', 'probe.js'); });
    try {
      var svgScr = inert.createElementNS('http://www.w3.org/2000/svg', 'script');
      urlOk = urlOk && ttThrows(function () { svgScr.setAttribute('href', 'probe.js'); });
    } catch (e) {}

    // sink-map introspection (supplementary)
    var mapOk = true;
    if (typeof trustedTypes.getPropertyType === 'function') {
      mapOk = mapOk
        && trustedTypes.getPropertyType('div', 'innerHTML') === 'TrustedHTML'
        && trustedTypes.getPropertyType('script', 'text')   === 'TrustedScript'
        && trustedTypes.getPropertyType('script', 'src')     === 'TrustedScriptURL';
    }
    if (typeof trustedTypes.getAttributeType === 'function') {
      mapOk = mapOk
        && trustedTypes.getAttributeType('div', 'onclick')   === 'TrustedScript'
        && trustedTypes.getAttributeType('iframe', 'srcdoc')  === 'TrustedHTML'
        && trustedTypes.getAttributeType('script', 'src')     === 'TrustedScriptURL';
    }

    return htmlOk && scriptOk && evalOk && urlOk && mapOk;
  }

  function renderUnsupported(detail) {
    while (document.documentElement.firstChild) document.documentElement.removeChild(document.documentElement.firstChild);
    document.title = 'Browser not supported';
    document.documentElement.appendChild(document.createElement('head'));
    var body = document.documentElement.appendChild(document.createElement('body'));
    body.style.font = '14px Inter,system-ui'; body.style.padding = '40px'; body.style.maxWidth = '560px';
    var h1 = document.createElement('h1'); h1.textContent = 'Your browser is not supported';
    var p = document.createElement('p');
    p.textContent = 'Service1 UI requires full Trusted Types enforcement to prevent XSS. '
                  + 'Please use a recent Chromium-based browser (Chrome, Edge, Brave, Opera), '
                  + 'Safari 26+, or Firefox with Trusted Types enabled.';
    body.appendChild(h1); body.appendChild(p);
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.controller)
        navigator.serviceWorker.controller.postMessage({ type: 'TT_PROBE', supported: false, detail: detail || '' });
    } catch (e) {}
  }

  // Async canary: does the engine route a javascript: URL navigation through
  // Trusted Types? Sandboxed (no parent reach) but allow-scripts so the URL gets a
  // genuine chance to fire; same-origin so we can read the flag. With no default
  // policy in the child realm, a conformant engine blocks the navigation and the
  // flag stays unset. Resolves leaked=true if it executed. Generous wait — this is
  // the only thing happening on the gate page.
  function jsUrlGate() {
    return new Promise(function (resolve) {
      var f, settled = false;
      function finish() {
        if (settled) return; settled = true;
        var leaked = false;
        try {
          var cd = f && f.contentDocument;
          leaked = !!(cd && cd.documentElement && cd.documentElement.getAttribute('data-leak') === '1');
        } catch (e) {}
        try { f && f.remove(); } catch (e) {}
        resolve(leaked);
      }
      try {
        f = document.createElement('iframe');
        f.style.display = 'none';
        f.setAttribute('sandbox', 'allow-scripts allow-same-origin');
        f.addEventListener('load', function () { setTimeout(finish, 0); }, { once: true });
        f.src = 'javascript:try{document.documentElement.setAttribute("data-leak","1")}catch(e){}';
        (document.body || document.documentElement).appendChild(f);
      } catch (e) { resolve(false); return; }
      setTimeout(finish, 400); // reasonable max wait for the flag
    });
  }

  function markVerifiedThenReload() {
    function reload() { try { location.reload(); } catch (e) {} }
    try {
      if (!(navigator.serviceWorker && navigator.serviceWorker.ready)) { reload(); return; }
      navigator.serviceWorker.ready.then(function (reg) {
        var target = navigator.serviceWorker.controller || (reg && reg.active);
        if (!target) { reload(); return; }
        var ch = new MessageChannel(), done = false;
        ch.port1.onmessage = function () { if (done) return; done = true; reload(); };
        target.postMessage({ type: 'TT_VERIFIED' }, [ch.port2]);
        setTimeout(function () { if (done) return; done = true; reload(); }, 1500); // ack fallback
      }, reload);
    } catch (e) { reload(); }
  }

  // ---- GATE MODE ----------------------------------------------------------
  if (window.__S1_GATE__) {
    if (!ttEnforced()) { renderUnsupported('synchronous Trusted Types sink probe failed'); return; }
    jsUrlGate().then(function (leaked) {
      if (leaked) { renderUnsupported('javascript: URL executed under enforcement'); return; }
      markVerifiedThenReload();
    });
    return;
  }

  // ---- APP MODE -----------------------------------------------------------
  // Engine already verified by the gate; sync probe kept as cheap defence-in-depth.
  if (!ttEnforced()) {
    renderUnsupported('synchronous Trusted Types sink probe failed');
    throw new Error('s1-bootstrap: Trusted Types not fully enforced, aborting page load');
  }

  var INERT = document.implementation.createHTMLDocument('');

  var passPolicy = trustedTypes.createPolicy('s1-pass', {
    createHTML:      function (s) { return s; },
    createScript:    function () { throw new TypeError('s1-pass: createScript blocked'); },
    createScriptURL: function () { throw new TypeError('s1-pass: createScriptURL blocked'); }
  });

  function wrap(s) {
    s = s == null ? '' : String(s);
    if (s === '') return '';
    var ifr = INERT.createElement('iframe');
    ifr.setAttribute('data-s1-wrap', '1');
    ifr.setAttribute('sandbox', 'allow-same-origin');
    ifr.setAttribute('style', 'border:0;display:block;width:100%;background:transparent');
    ifr.srcdoc = passPolicy.createHTML(s);
    return ifr.outerHTML;
  }

  function fit(ifr) {
    try {
      var doc = ifr.contentDocument;
      if (!doc || !doc.documentElement) return;
      var h = Math.max(doc.documentElement.scrollHeight, doc.body ? doc.body.scrollHeight : 0);
      ifr.style.height = (h || 0) + 'px';
    } catch (e) {}
  }
  function watch(ifr) {
    fit(ifr);
    var ro = (typeof ResizeObserver !== 'undefined') ? new ResizeObserver(function () { fit(ifr); }) : null;
    try {
      var d = ifr.contentDocument;
      if (d && ro && d.documentElement) ro.observe(d.documentElement);
      if (d) {
        var mo = new MutationObserver(function () { fit(ifr); });
        mo.observe(d, { subtree: true, childList: true, characterData: true, attributes: true });
      }
      if (d) {
        var imgs = d.querySelectorAll('img');
        for (var i = 0; i < imgs.length; i++) imgs[i].addEventListener('load', function () { fit(ifr); });
      }
    } catch (e) {}
  }
  function discover(root) {
    var list = (root.nodeType === 1 && root.matches && root.matches('iframe[data-s1-wrap]'))
      ? [root]
      : (root.querySelectorAll ? root.querySelectorAll('iframe[data-s1-wrap]') : []);
    for (var i = 0; i < list.length; i++) {
      var ifr = list[i];
      if (ifr.__s1_watched) continue;
      ifr.__s1_watched = true;
      if (ifr.contentDocument && ifr.contentDocument.readyState === 'complete') watch(ifr);
      else ifr.addEventListener('load', function (e) { watch(e.currentTarget); }, { once: true });
    }
  }
  function start() {
    discover(document);
    new MutationObserver(function (records) {
      for (var i = 0; i < records.length; i++) {
        var added = records[i].addedNodes;
        for (var j = 0; j < added.length; j++) if (added[j].nodeType === 1) discover(added[j]);
      }
    }).observe(document.documentElement, { subtree: true, childList: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();

  trustedTypes.createPolicy('s1-policy', {
    createHTML: wrap,
    createScript: function () { throw new TypeError('s1-policy: createScript blocked'); },
    createScriptURL: function (u) {
      var url = new URL(u, location.href);
      if (url.origin !== location.origin && url.origin !== 'https://ui-raw.service1.app')
        throw new TypeError('s1-policy: cross-origin script URL blocked');
      return url.toString();
    }
  });

  trustedTypes.createPolicy('default', {
    createHTML: wrap,
    createScript: function () { throw new TypeError('default: dynamic script blocked'); },
    createScriptURL: function (u) {
      var url = new URL(u, location.href);
      if (url.origin !== location.origin && url.origin !== 'https://ui-raw.service1.app')
        throw new TypeError('default: cross-origin script URL blocked');
      return url.toString();
    }
  });
})();
