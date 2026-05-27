// /policy/bootstrap.js — Trusted Types bootstrap injected by the SW
// into every proxied HTML response. Loaded synchronously before module scripts.
(function () {
  function ttEnforced() {
    if (typeof window.trustedTypes !== 'object'
        || typeof trustedTypes.createPolicy !== 'function'
        || typeof window.TrustedHTML !== 'function') return false;
    function mustThrow(fn) {
      try { fn(); return false; } catch (e) { return e instanceof TypeError; }
    }
    // createHTMLDocument: DOMParser.parseFromString is itself TT-enforced in
    // modern Chromium and would throw before we can probe.
    var inert = document.implementation.createHTMLDocument('');
    return mustThrow(function () { document.createElement('div').innerHTML = '<b>x</b>'; })
        && mustThrow(function () { document.createElement('div').outerHTML = '<b>x</b>'; })
        && mustThrow(function () { document.createElement('div').insertAdjacentHTML('beforeend','<b>x</b>'); })
        && mustThrow(function () { document.createElement('iframe').srcdoc = '<b>x</b>'; })
        && mustThrow(function () { inert.body.innerHTML = '<b>x</b>'; })
        && mustThrow(function () { inert.createElement('iframe').srcdoc = '<b>x</b>'; })
        && mustThrow(function () { inert.createElement('div').insertAdjacentHTML('beforeend','<b>x</b>'); });
  }
  if (!ttEnforced()) {
    while (document.documentElement.firstChild) document.documentElement.removeChild(document.documentElement.firstChild);
    document.title = 'Browser not supported';
    document.documentElement.appendChild(document.createElement('head'));
    var body = document.documentElement.appendChild(document.createElement('body'));
    body.style.font = '14px Inter,system-ui'; body.style.padding = '40px'; body.style.maxWidth = '560px';
    var h1 = document.createElement('h1'); h1.textContent = 'Your browser is not supported';
    var p = document.createElement('p');
    p.textContent = 'Service1 UI requires the Trusted Types feature to prevent XSS. '
                  + 'Please use a recent Chromium-based browser (Chrome, Edge, Brave, Opera).';
    body.appendChild(h1); body.appendChild(p);
    try {
      if (navigator.serviceWorker && navigator.serviceWorker.controller) {
        navigator.serviceWorker.controller.postMessage({ type: 'TT_PROBE', supported: false });
      }
    } catch (e) {}
    throw new Error('s1-bootstrap: Trusted Types not supported, aborting page load');
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
      var h = Math.max(
        doc.documentElement.scrollHeight,
        doc.body ? doc.body.scrollHeight : 0
      );
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
