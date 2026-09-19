/* ============================================================
   CROVIA · shared shell behaviors
   - nav burger toggle, dropdown close-on-outside-click
   - hourly polling of /api/registry/stats for the status pill
   - tiny copy-to-clipboard helper (window.cvCopy)
   - tiny toast helper          (window.cvToast)

   Pages opt-in by including a `.cv-nav-status` element with
   `<span class="dot"></span><span data-cv-status></span>`.
   Pages without a status pill silently skip the polling.
   ============================================================ */
(function () {
  "use strict";

  var ORIGIN_REGISTRY = "https://registry.croviatrust.com";
  var ORIGIN_PUBLIC   = "https://croviatrust.com";

  var IS_CROVIA_ROOT = (location.hostname === "croviatrust.com" || location.hostname === "www.croviatrust.com");
  var STATS_URL      = IS_CROVIA_ROOT ? "/api/registry/stats" : ORIGIN_PUBLIC + "/api/registry/stats";

  // ---- toast ----
  function ensureToast() {
    var t = document.getElementById("cv-toast");
    if (!t) {
      t = document.createElement("div");
      t.id = "cv-toast";
      t.className = "cv-toast";
      document.body.appendChild(t);
    }
    return t;
  }
  function toast(msg) {
    var t = ensureToast();
    t.textContent = msg;
    t.classList.add("is-on");
    clearTimeout(toast._t);
    toast._t = setTimeout(function () { t.classList.remove("is-on"); }, 1400);
  }
  window.cvToast = toast;

  // ---- copy ----
  async function copy(text, label) {
    if (!text) return;
    try { await navigator.clipboard.writeText(text); toast((label || "copied") + " ✓"); }
    catch { toast("copy failed"); }
  }
  window.cvCopy = copy;

  // ---- nav: burger ----
  document.addEventListener("click", function (e) {
    var burger = e.target.closest("[data-cv-burger]");
    if (burger) {
      var links = document.getElementById("cv-nav-links");
      if (links) links.classList.toggle("is-open");
      return;
    }
    // close 'More' dropdown when clicking outside
    var more = document.querySelector(".cv-nav-more.is-open");
    if (more && !more.contains(e.target)) more.classList.remove("is-open");
  });

  // ---- nav: more dropdown ----
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-cv-more]");
    if (!btn) return;
    var p = btn.parentElement;
    if (p) p.classList.toggle("is-open");
  });

  // ---- status pill ----
  function setPill(state, text) {
    var pill = document.getElementById("cv-nav-status");
    if (!pill) return;
    pill.classList.remove("is-ok", "is-warn", "is-down");
    if (state) pill.classList.add("is-" + state);
    var label = pill.querySelector("[data-cv-status]");
    if (label && text) label.textContent = text;
  }

  function minutesSince(iso) {
    if (!iso) return null;
    var d = new Date(iso);
    if (isNaN(d.getTime())) return null;
    return Math.round((Date.now() - d.getTime()) / 60000);
  }

  var TACET_URL = IS_CROVIA_ROOT ? "/registry/data/tacet/latest.json" : ORIGIN_PUBLIC + "/registry/data/tacet/latest.json";

  async function probe() {
    if (!document.getElementById("cv-nav-status")) return;
    // Primary signal: the TACET log. One sheet per hour; >2h without a sheet is a warning.
    try {
      var rt = await fetch(TACET_URL, { cache: "no-store", headers: { "Accept": "application/json" } });
      if (!rt.ok) throw new Error("HTTP " + rt.status);
      var t = await rt.json();
      var sh = t.latest_sheet || {};
      var sinceEnd = minutesSince(sh.epoch_end);
      var label = "epoch #" + t.latest_epoch;
      if (sinceEnd != null && sinceEnd > 125) setPill("warn", label + " · " + Math.round(sinceEnd / 60) + "h ago");
      else setPill("ok", label + " · live");
      return;
    } catch (e0) { /* fall through to the legacy registry stats */ }
    try {
      var r = await fetch(STATS_URL, { cache: "no-store", headers: { "Accept": "application/json" } });
      if (!r.ok) throw new Error("HTTP " + r.status);
      var s = await r.json();
      var ageMin = minutesSince(s.updated_at);
      if (ageMin != null && ageMin > 240) setPill("warn", "stale " + ageMin + "m");
      else setPill("ok", ageMin != null ? "live · " + ageMin + "m" : "live");
    } catch (e) {
      try {
        var r2 = await fetch("/data/substrate/stats.json", { cache: "no-store" });
        if (!r2.ok) throw new Error("HTTP " + r2.status);
        var s2 = await r2.json();
        var age2 = minutesSince(s2.latest_issued_at);
        if (age2 != null && age2 > 1440) setPill("warn", "stale " + Math.round(age2 / 60) + "h");
        else setPill("ok", "live");
      } catch (e2) {
        setPill("down", "offline");
      }
    }
  }
  probe();
  setInterval(probe, 60 * 1000);

  // ===== CroviaProof — reusable "every claim is provable" popover =====
  var Proof = (function () {
    var back = null, card = null, lastFocus = null;
    function esc(s) {
      return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
      });
    }
    function onKey(e) { if (e.key === "Escape") close(); }
    function ensure() {
      if (back) return;
      back = document.createElement("div");
      back.className = "cv-proof-backdrop";
      card = document.createElement("div");
      card.className = "cv-proof";
      card.setAttribute("role", "dialog");
      card.setAttribute("aria-modal", "true");
      back.appendChild(card);
      document.body.appendChild(back);
      back.addEventListener("click", function (e) { if (e.target === back) close(); });
      card.addEventListener("click", function (e) {
        var cp = e.target.closest("[data-proof-copy]");
        if (cp) { copy(cp.getAttribute("data-proof-copy"), "copied"); return; }
        if (e.target.closest("[data-proof-close]")) close();
      });
    }
    function rowHtml(r) {
      var k = r[0], v = r[1], o = r[2] || {};
      var cls = "cv-proof-v" + (o.mono ? " is-mono" : "") + (o.accent ? " is-accent" : "");
      var copyBtn = o.copy ? '<button class="cv-proof-copy" data-proof-copy="' + esc(o.copy === true ? v : o.copy) + '">copy</button>' : "";
      return '<div class="cv-proof-row"><div class="cv-proof-k">' + esc(k) + '</div>' +
             '<div class="' + cls + '">' + esc(v) + copyBtn + '</div></div>';
    }
    function open(data) {
      ensure();
      data = data || {};
      var rows = (data.rows || []).map(rowHtml).join("");
      var acts = (data.actions || []).map(function (a) {
        var c = "cv-proof-btn" + (a.primary ? " is-primary" : "");
        if (a.href) return '<a class="' + c + '" href="' + esc(a.href) + '"' + (a.external ? ' target="_blank" rel="noopener"' : "") + '>' + esc(a.label) + '</a>';
        return '<button class="' + c + '" data-proof-act>' + esc(a.label) + '</button>';
      }).join("");
      card.innerHTML =
        '<div class="cv-proof-head"><div><div class="cv-proof-eyebrow">Cryptographic proof</div>' +
        '<div class="cv-proof-title">' + esc(data.title || "Signed observation") + '</div>' +
        (data.subtitle ? '<div class="cv-proof-sub">' + esc(data.subtitle) + '</div>' : "") + '</div>' +
        '<button class="cv-proof-x" data-proof-close aria-label="Close">&times;</button></div>' +
        '<div class="cv-proof-rows">' + rows + '</div>' +
        (acts ? '<div class="cv-proof-actions">' + acts + '</div>' : "");
      // wire button-style actions (onClick)
      (data.actions || []).forEach(function (a, i) {
        if (a.onClick && !a.href) {
          var btns = card.querySelectorAll("[data-proof-act]");
          if (btns[i]) btns[i].addEventListener("click", a.onClick);
        }
      });
      lastFocus = document.activeElement;
      back.classList.add("is-on");
      document.addEventListener("keydown", onKey);
      var x = card.querySelector("[data-proof-close]"); if (x) x.focus();
    }
    function close() {
      if (!back) return;
      back.classList.remove("is-on");
      document.removeEventListener("keydown", onKey);
      if (lastFocus && lastFocus.focus) lastFocus.focus();
    }
    return { open: open, close: close };
  })();
  window.CroviaProof = Proof;

  // ---- nav v2: unify registry pages with homepage verbs ----
  (function injectNavV2() {
    var el = document.getElementById('cv-nav-links');
    if (!el || el.getAttribute('data-nav-v2') === '1') return;
    var p = location.pathname;
    function isActive(href) {
      if (href === 'https://croviatrust.com/') return p === '/' || p === '/index.html';
      if (href === '/registry/seal/verify/') return p.indexOf('/registry/seal/verify') === 0;
      if (href === '/registry/seal/log/') return p.indexOf('/registry/seal/log') === 0;
      if (href === '/registry/seal/') return p.indexOf('/registry/seal') === 0 && p.indexOf('/registry/seal/verify') !== 0 && p.indexOf('/registry/seal/log') !== 0;
      if (href === '/registry/lacuna/') return p.indexOf('/registry/lacuna') === 0;
      if (href === '/registry/tacet/') return p.indexOf('/registry/tacet') === 0;
      if (href === '/registry/') return p === '/registry/' || p === '/registry/index.html';
      if (href === '/registry/embed/') return p.indexOf('/registry/embed') === 0;
      return false;
    }
    function a(href, label, ext) {
      var cls = isActive(href) ? ' class="is-active"' : '';
      var extAttr = ext ? ' target="_blank" rel="noopener"' : '';
      return '<a href="' + href + '"' + cls + extAttr + '>' + label + '</a>';
    }
    el.innerHTML =
      a('https://croviatrust.com/', 'Verify') +
      a('/registry/tacet/', 'TACET') +
      a('/registry/lacuna/', 'LACUNA') +
      a('/registry/seal/', 'Seal') +
      a('/registry/', 'Registry') +
      a('https://causari.dev', 'Causari &#8599;', true) +
      '<div class="cv-nav-more">' +
      '<button class="cv-nav-more-btn" data-cv-more>More' +
      '<svg viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 4.5l3 3 3-3"/></svg></button>' +
      '<div class="cv-nav-dropdown">' +
      '<a href="/registry/explore/">Evidence Explorer</a>' +
      '<a href="/registry/compliance/">Compliance Hub</a>' +
      '<a href="/registry/api/">Data &amp; API</a>' +
      '<a href="/registry/embed/hf.html">Hugging Face overlay</a>' +
      '<a href="/registry/embed/silence.html">Silence Index embed</a>' +
      '<a href="https://croviatrust.com/#ledger">How it works</a>' +
      '<a href="https://croviatrust.com/#archive">2026 archive</a>' +
      '<a href="https://croviatrust.com/whitepaper.html">Whitepaper</a>' +
      '<a href="https://croviatrust.com/#about">Forensic &amp; EU AI Act</a>' +
      '<a href="https://croviatrust.com/#sustain">Sustain</a>' +
      '<div class="sep"></div>' +
      '<a href="/registry/seal/verify/">Seal Verifier</a>' +
      '<a href="/registry/seal/log/">Seal Transparency Log</a>' +
      '<a href="/registry/seal/spec/">Seal spec &#8599;</a>' +
      '<a href="https://datatracker.ietf.org/doc/draft-crovia-seal/" target="_blank" rel="noopener">IETF draft &#8599;</a>' +
      '<a href="https://github.com/croviatrust/countersign/blob/main/tacet/SPEC.md" target="_blank" rel="noopener">TACET spec &#8599;</a>' +
      '<a href="https://github.com/croviatrust" target="_blank" rel="noopener">GitHub &#8599;</a>' +
      '<a href="mailto:info@croviatrust.com">Contact &#9993;</a>' +
      '</div></div>';
    el.setAttribute('data-nav-v2', '1');
  })();
})();
