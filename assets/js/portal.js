/* ============================================================================
   Cherubim live pentest portal
   Talks directly to the Xalgorix public API from the browser.
   NOTE: this is a static site, so the API key below ships to the client.
   Rotate it from one place (PORTAL.key). To hide it, put a proxy in front.
   ============================================================================ */
(function () {
  "use strict";

  /* -------- auth gate (shared with the marketing sign in) -------- */
  try {
    if (sessionStorage.getItem("cb_s") !== "1") { location.replace("../login.html"); return; }
  } catch (e) {}

  var USER = { name: "Aaron Ang", email: "aaron@hesedemet.asia", initials: "AA" };
  try { var u = JSON.parse(atob(sessionStorage.getItem("cb_u") || "") || "null"); if (u && u.name) USER = u; } catch (e) {}

  /* -------- config -------- */
  var PORTAL = {
    base: "https://www.xalgorix.com/api/public/v1",
    key: "xlg_live_1196967b25f012412ab2e74526672950ba908096341c0751",
    pollMs: 6000
  };
  // allow an operator override without editing source (kept per browser)
  try { var k = localStorage.getItem("cb_key"); if (k) PORTAL.key = k; } catch (e) {}

  var PHASES = [
    "Reconnaissance & scope mapping", "Subdomain & asset discovery", "Technology fingerprinting",
    "TLS & transport security", "Authentication testing", "Session management",
    "Access control & IDOR", "SQL & NoSQL injection", "Cross-site scripting",
    "Server-side request forgery", "Command & code injection", "File upload & path traversal",
    "XXE & deserialization", "API security testing", "Business logic abuse",
    "Rate limiting & safety", "Secrets & info disclosure", "Cloud & infra misconfig",
    "CORS & security headers", "Client-side & DOM analysis", "Exploit verification",
    "Reporting & remediation"
  ];
  var SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

  /* -------- tiny dom helpers -------- */
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var esc = function (s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); };

  /* -------- api -------- */
  function api(path, opts) {
    opts = opts || {};
    var headers = { "Authorization": "Bearer " + PORTAL.key };
    if (opts.body) headers["Content-Type"] = "application/json";
    return fetch(PORTAL.base + path, {
      method: opts.method || "GET",
      headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok || (j && j.error)) { throw new Error((j && (j.error || j.detail)) || ("HTTP " + r.status)); }
        return j;
      }).catch(function (e) {
        if (e instanceof SyntaxError) throw new Error("Bad response from API (HTTP " + r.status + ")");
        throw e;
      });
    });
  }
  function createScan(target, mode, sev) { return api("/scans", { method: "POST", body: { target: target, mode: mode, severity_filter: sev } }); }
  function scanStatus(id) { return api("/scans?id=" + encodeURIComponent(id)); }
  function listFindings(scanId, limit) {
    var q = "/findings?limit=" + (limit || 100) + "&offset=0&order=newest";
    if (scanId) q += "&scan_id=" + encodeURIComponent(scanId);
    return api(q);
  }

  /* -------- state -------- */
  var state = { scan: null, counts: null, findings: [], poll: null, t0: 0, done: false };

  /* -------- toasts -------- */
  function toast(title, msg, kind) {
    var t = document.createElement("div");
    t.className = "toast" + (kind ? " " + kind : "");
    t.innerHTML = "<b>" + esc(title) + "</b>" + (msg ? "<br>" + esc(msg) : "");
    $("#toasts").appendChild(t);
    setTimeout(function () { t.style.transition = "opacity .4s"; t.style.opacity = "0"; setTimeout(function () { t.remove(); }, 400); }, 5200);
  }

  /* -------- rendering: launcher -------- */
  function renderLauncher() {
    return '<div class="pt-launch card-p">' +
      '<div class="pl-head"><span class="eyebrow">Live engagement</span><h2>Run a proven pentest</h2>' +
      '<p class="sub">Point Cherubim at a target. It works through 22 phases, verifies every finding with a real exploit, and streams results here as they land.</p></div>' +
      '<form id="scanForm" class="pl-form">' +
      '<div class="pl-row"><label>Target</label><input id="scanTarget" type="text" autocomplete="off" spellcheck="false" placeholder="https://app.example.com  ·  hostname  ·  *.example.com" required></div>' +
      '<div class="pl-grid">' +
      '<div class="pl-row"><label>Mode</label><select id="scanMode"><option value="single">Single target</option><option value="wildcard">Wildcard (discover &amp; scan subdomains)</option></select></div>' +
      '<div class="pl-row"><label>Report from severity</label><select id="scanSev"><option value="info">Info and above</option><option value="low" selected>Low and above</option><option value="medium">Medium and above</option><option value="high">High and above</option><option value="critical">Critical only</option></select></div>' +
      '</div>' +
      '<div class="pl-actions"><button class="btn-mini lg" id="scanGo" type="submit">Launch pentest</button>' +
      '<span class="pl-note mono">Non-destructive payloads · safe for production · 10-30 min typical</span></div>' +
      '</form></div>';
  }

  /* -------- rendering: active scan -------- */
  function sevPill(sev, n) {
    return '<div class="sev-pill sev-' + sev + '"><b>' + n + '</b><span>' + SEV_LABEL[sev] + '</span></div>';
  }
  function fmtElapsed(ms) {
    var s = Math.floor(ms / 1000);
    return String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0");
  }
  function renderScanPanel() {
    if (!state.scan) return "";
    var sc = state.scan, cn = state.counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    var ph = Math.max(1, Math.min(22, sc.current_phase || 1));
    var pct = state.done ? 100 : Math.round((ph / 22) * 100);
    var running = sc.status === "running" || sc.status === "queued";
    var statusTxt = state.done ? "Completed" : (sc.status || "running");
    var total = SEV_ORDER.reduce(function (a, s) { return a + (cn[s] || 0); }, 0);
    return '<div class="pt-scan card-p" id="scanPanel">' +
      '<div class="ps-top"><div><span class="eyebrow">' + (running ? '<span class="live-dot"></span> Live scan' : 'Scan complete') + '</span>' +
      '<h3 class="mono">' + esc(sc.target) + '</h3><p class="sub mono">' + esc(sc.mode || "single") + ' · scan ' + esc((sc.id || "").slice(0, 8)) + ' · ' + fmtElapsed(Date.now() - state.t0) + '</p></div>' +
      '<div class="ps-status"><span class="st-badge ' + (state.done ? "ok" : "run") + '">' + esc(statusTxt) + '</span></div></div>' +
      '<div class="ps-phase"><div class="pp-label"><span>Phase <b>' + ph + '</b> of 22 · ' + esc(PHASES[ph - 1] || "") + '</span><span class="mono">' + pct + '%</span></div>' +
      '<div class="pp-bar"><i style="width:' + pct + '%"></i></div>' +
      '<div class="pp-track">' + PHASES.map(function (_, i) {
        var cls = state.done || (i + 1) < ph ? "done" : (i + 1) === ph ? "on" : "";
        return '<span class="pp-tick ' + cls + '" title="' + esc(PHASES[i]) + '"></span>';
      }).join("") + '</div></div>' +
      '<div class="ps-counts">' + SEV_ORDER.map(function (s) { return sevPill(s, cn[s] || 0); }).join("") +
      '<div class="sev-pill total"><b>' + total + '</b><span>Proven</span></div></div>' +
      (running ? '<p class="ps-hint mono">Streaming tool calls, agent reasoning and verified findings. This view refreshes automatically.</p>' : '<p class="ps-hint mono">Engagement sealed. Every finding below was reproduced with a working exploit.</p>') +
      '</div>';
  }

  /* -------- rendering: findings -------- */
  function findingCard(f) {
    var sev = (f.severity || "info").toLowerCase();
    var proven = f.evidence && f.evidence.tags && f.evidence.tags.indexOf("exploit-proven") >= 0;
    return '<div class="find-card clk" data-fid="' + esc(f.id) + '">' +
      '<div class="fc-top"><span class="tag sev-' + sev + '">' + (SEV_LABEL[sev] || sev) + '</span>' +
      (f.cvss != null ? '<span class="fc-cvss mono">CVSS ' + esc(f.cvss) + '</span>' : '') +
      (proven ? '<span class="fc-proven">✓ exploit proven</span>' : '') +
      '<span class="fc-phase mono">Phase ' + esc(f.phase || "?") + '</span></div>' +
      '<div class="fc-title">' + esc(cleanTitle(f.title)) + '</div>' +
      '<div class="fc-meta mono">' + esc(f.scan_target || "") + (f.evidence && f.evidence.cwe_id ? ' · ' + esc(f.evidence.cwe_id) : "") + (f.evidence && f.evidence.owasp ? ' · ' + esc(f.evidence.owasp) : "") + '</div>' +
      '</div>';
  }
  function cleanTitle(t) { return String(t || "Finding").split(" — ")[0].replace(/\s*\((attribute-context|execution proof[^)]*)\)/gi, ""); }

  function renderFindings() {
    var list = state.findings;
    if (!list.length) {
      return '<div class="pt-findings"><div class="fh"><h3>Findings</h3><span class="mono st-mut" id="findCount">0</span></div>' +
        '<div class="find-empty" id="findEmpty">' + (state.scan && !state.done ? 'No proven findings yet. Cherubim only reports what it can reproduce.' : 'Findings will appear here once a scan runs.') + '</div></div>';
    }
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    var sorted = list.slice().sort(function (a, b) {
      var d = (order[(a.severity || "info").toLowerCase()] || 9) - (order[(b.severity || "info").toLowerCase()] || 9);
      return d !== 0 ? d : (new Date(b.created_at) - new Date(a.created_at));
    });
    return '<div class="pt-findings"><div class="fh"><h3>Findings</h3><span class="mono st-mut" id="findCount">' + list.length + ' proven</span></div>' +
      '<div class="find-grid" id="findGrid">' + sorted.map(findingCard).join("") + '</div></div>';
  }

  function openFinding(id) {
    var f = state.findings.filter(function (x) { return x.id === id; })[0];
    if (!f) return;
    var sev = (f.severity || "info").toLowerCase();
    var ev = f.evidence || {};
    var extra = [];
    Object.keys(ev).forEach(function (k) {
      if (["tags", "cwe_id", "owasp", "fix"].indexOf(k) >= 0) return;
      var v = ev[k]; if (v == null || v === "" ) return;
      if (typeof v === "object") v = JSON.stringify(v);
      extra.push([k, v]);
    });
    $("#drawerBody").innerHTML =
      '<button class="x" data-x>&times;</button>' +
      '<span class="dr-eyebrow mono">[ ' + esc((f.id || "").slice(0, 8)) + ' · Phase ' + esc(f.phase || "?") + ' ]</span>' +
      '<h3>' + esc(cleanTitle(f.title)) + '</h3>' +
      '<div class="meta"><span class="tag sev-' + sev + '">' + (SEV_LABEL[sev] || sev) + '</span>' +
      (f.cvss != null ? '<span class="tag" style="border:1px solid rgba(63,185,132,.4);color:#3FB984">CVSS ' + esc(f.cvss) + '</span>' : "") +
      (ev.cwe_id ? '<span class="tag sev-med">' + esc(ev.cwe_id) + '</span>' : "") +
      (ev.owasp ? '<span class="tag sev-low">' + esc(ev.owasp) + '</span>' : "") +
      (ev.tags && ev.tags.indexOf("exploit-proven") >= 0 ? '<span class="tag" style="border:1px solid rgba(63,185,132,.5);color:#3FB984">✓ exploit proven</span>' : "") +
      '</div>' +
      '<h5>Target</h5><p class="mono" style="font-size:12.5px">' + esc(f.scan_target || "") + ' · ' + esc(f.scan_mode || "") + '</p>' +
      '<h5>Evidence &amp; proof of concept</h5><div class="code find-desc">' + esc(f.description || "No description provided.") + '</div>' +
      (f.remediation || ev.fix ? '<h5>Remediation</h5><p>' + esc(f.remediation || ev.fix) + '</p>' : '') +
      (extra.length ? '<h5>Metadata</h5><div class="code" style="white-space:pre">' + extra.map(function (p) { return esc(p[0]) + " = " + esc(p[1]); }).join("\n") + '</div>' : '') +
      '<h5>Reported</h5><p class="mono" style="font-size:12px">' + esc(f.created_at || "") + '</p>';
    $("#scrim").classList.add("open"); $("#drawer").classList.add("open");
    $("[data-x]").onclick = closeDrawer;
  }
  function closeDrawer() { $("#scrim").classList.remove("open"); $("#drawer").classList.remove("open"); }

  /* -------- compose main view -------- */
  function paint() {
    $("#main").innerHTML = renderLauncher() + renderScanPanel() + renderFindings();
    bind();
  }
  function bind() {
    var form = $("#scanForm");
    if (form) form.onsubmit = function (e) { e.preventDefault(); launch(); };
    $$(".find-card.clk").forEach(function (c) { c.onclick = function () { openFinding(c.getAttribute("data-fid")); }; });
    // prefill last target
    try { var lt = localStorage.getItem("cb_last_target"); if (lt && $("#scanTarget") && !$("#scanTarget").value) $("#scanTarget").value = lt; } catch (e) {}
  }

  /* -------- launch + poll -------- */
  function normTarget(v) {
    v = v.trim();
    if (!v) return v;
    if (/^\*\./.test(v)) return v;              // wildcard
    if (/^https?:\/\//i.test(v)) return v;      // full url
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return v; // bare hostname ok
    return "https://" + v;
  }
  function launch() {
    var raw = $("#scanTarget").value || "";
    var target = normTarget(raw);
    var mode = $("#scanMode").value, sev = $("#scanSev").value;
    if (!target) { toast("Enter a target", "Add a URL, hostname or wildcard to scan.", "err"); return; }
    if (mode === "wildcard" && !/^\*\./.test(target) && /^https?:/i.test(target)) {
      // wildcard prefers a bare domain; leave as-is, API will validate
    }
    var btn = $("#scanGo"); if (btn) { btn.disabled = true; btn.textContent = "Launching…"; }
    try { localStorage.setItem("cb_last_target", raw.trim()); } catch (e) {}

    createScan(target, mode, sev).then(function (r) {
      state.scan = { id: r.id, target: r.target || target, mode: mode, status: r.status || "running", current_phase: 1, web_url: r.web_url };
      state.counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      state.findings = [];
      state.done = false;
      state.t0 = Date.now();
      toast("Scan started", "Cherubim is working through 22 phases against " + target + ".");
      paint();
      startPoll();
    }).catch(function (err) {
      if (btn) { btn.disabled = false; btn.textContent = "Launch pentest"; }
      toast("Could not start scan", String(err.message || err), "err");
    });
  }

  function startPoll() {
    if (state.poll) clearInterval(state.poll);
    tick();
    state.poll = setInterval(tick, PORTAL.pollMs);
  }
  function stopPoll() { if (state.poll) { clearInterval(state.poll); state.poll = null; } }

  function tick() {
    if (!state.scan) return;
    var id = state.scan.id;
    scanStatus(id).then(function (r) {
      if (!r.scan) return;
      var prevPhase = state.scan.current_phase, prevTotal = state.findings.length;
      state.scan.status = r.scan.status;
      state.scan.current_phase = r.scan.current_phase || state.scan.current_phase;
      state.scan.mode = r.scan.mode || state.scan.mode;
      state.counts = r.counts || state.counts;
      var finished = r.scan.status === "completed" || r.scan.status === "failed" || r.scan.completed_at;
      // pull findings for this scan
      return listFindings(id, 100).then(function (fr) {
        state.findings = (fr.findings || []);
        // update just the dynamic parts without nuking the form
        refreshScanArea();
        if (state.findings.length > prevTotal) {
          var newest = state.findings[0];
          if (newest) toast("Finding proven", (SEV_LABEL[(newest.severity||"info").toLowerCase()] || "") + " · " + cleanTitle(newest.title));
        } else if (state.scan.current_phase > prevPhase) {
          // quiet phase advance
        }
        if (finished) {
          state.done = true;
          stopPoll();
          refreshScanArea();
          var c = state.counts || {};
          toast("Engagement complete", (c.critical||0) + " critical · " + (c.high||0) + " high · " + (c.medium||0) + " medium, all proven.");
        }
      });
    }).catch(function (err) {
      // transient errors: keep polling, surface only once
      if (!state._warned) { state._warned = true; toast("Live update hiccup", String(err.message || err), "warn"); }
    });
  }

  function refreshScanArea() {
    var panel = $("#scanPanel");
    if (panel) panel.outerHTML = renderScanPanel();
    var fWrap = $(".pt-findings");
    if (fWrap) fWrap.outerHTML = renderFindings();
    bind();
    var btn = $("#scanGo"); if (btn) { btn.disabled = false; btn.textContent = "Launch pentest"; }
  }

  /* -------- history (recent findings across account) -------- */
  function loadRecent() {
    listFindings(null, 100).then(function (fr) {
      var all = fr.findings || [];
      if (!state.scan && all.length) {
        // show account-wide findings as a starting point (demo has real history)
        state.findings = all;
        var fWrap = $(".pt-findings");
        if (fWrap) { fWrap.outerHTML = renderFindings(); bind(); }
        var badge = $("#histBadge"); if (badge) badge.textContent = (fr.total || all.length) + " findings on file";
      }
    }).catch(function () {});
  }

  /* -------- boot -------- */
  document.addEventListener("DOMContentLoaded", function () {
    var dy = $("#dyear"); if (dy) dy.textContent = new Date().getFullYear();
    var ini = USER.initials || (USER.name || "AA").split(" ").map(function (w) { return w[0]; }).join("").slice(0, 2).toUpperCase();
    if ($("#uAv")) $("#uAv").textContent = ini;
    if ($("#uName")) $("#uName").textContent = USER.name;
    if ($("#uMail")) $("#uMail").textContent = USER.email;

    paint();
    loadRecent();

    $("#scrim").onclick = closeDrawer;
    var um = $("#userMenu"), up = $("#userPop");
    if (um && up) {
      um.onclick = function (e) { e.stopPropagation(); up.classList.toggle("open"); };
      document.addEventListener("click", function () { up.classList.remove("open"); });
    }
    var lo = $("#logout"); if (lo) lo.onclick = function () { try { sessionStorage.removeItem("cb_s"); sessionStorage.removeItem("cb_u"); } catch (e) {} location.href = "../login.html"; };
  });
})();
