(function () {
  "use strict";

  try {
    if (sessionStorage.getItem("cb_s") !== "1") { location.replace("../login.html"); return; }
  } catch (e) {}

  var USER = { name: "Aaron Ang", email: "aaron@hesedemet.asia", initials: "AA" };
  try { var u = JSON.parse(atob(sessionStorage.getItem("cb_u") || "") || "null"); if (u && u.name) USER = u; } catch (e) {}

  var PORTAL = {
    base: "https://cherubim-api.cyber-leaders-nexus.workers.dev/v1",
    key: "",
    pollMs: 6000
  };

  var PHASES = [
    "Reconnaissance", "Subdomain discovery", "Fingerprinting", "Transport security",
    "Authentication", "Session management", "Access control & IDOR", "SQL / NoSQL injection",
    "Cross-site scripting", "Server-side request forgery", "Command injection", "Upload & traversal",
    "XXE & deserialization", "API security", "Business logic", "Rate limiting",
    "Information disclosure", "Cloud & infrastructure", "Headers & CORS", "Client-side",
    "Exploit validation", "Reporting"
  ];
  var SEV = ["critical", "high", "medium", "low", "info"];
  var SEV_ABBR = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  var SEV_COLOR = { critical: "#FC2B32", high: "#FF7A1A", medium: "#FFC400", low: "#3B9EFF", info: "#8A94A6" };
  var SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var esc = function (s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); };

  function api(path, opts) {
    opts = opts || {};
    var headers = {};
    if (PORTAL.key) headers["Authorization"] = "Bearer " + PORTAL.key;
    if (opts.body) headers["Content-Type"] = "application/json";
    return fetch(PORTAL.base + path, {
      method: opts.method || "GET", headers: headers,
      body: opts.body ? JSON.stringify(opts.body) : undefined
    }).then(function (r) {
      return r.json().then(function (j) {
        if (!r.ok || (j && j.error)) throw new Error((j && (j.error || j.detail)) || ("HTTP " + r.status));
        return j;
      }).catch(function (e) {
        if (e instanceof SyntaxError) throw new Error("Bad response (HTTP " + r.status + ")");
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

  var state = { scan: null, counts: null, findings: [], filter: "all", poll: null, t0: 0, done: false, warned: false };

  function toast(title, msg, kind) {
    var t = document.createElement("div");
    t.className = "toast" + (kind ? " " + kind : "");
    t.innerHTML = "<b>" + esc(title) + "</b>" + (msg ? esc(msg) : "");
    $("#toasts").appendChild(t);
    setTimeout(function () { t.style.transition = "opacity .4s"; t.style.opacity = "0"; setTimeout(function () { t.remove(); }, 400); }, 5200);
  }

  function cleanTitle(t) { return String(t || "Finding").split(" — ")[0].replace(/\s*\((attribute-context|execution proof[^)]*)\)/gi, "").trim(); }
  function elapsed(ms) { var s = Math.floor(ms / 1000); return String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0"); }
  function normTarget(v) {
    v = v.trim();
    if (!v) return v;
    if (/^\*\./.test(v) || /^https?:\/\//i.test(v)) return v;
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return v;
    return "https://" + v;
  }

  function launcher() {
    return '<div class="launch" id="launcher">' +
      '<h2>Run a pentest</h2>' +
      '<p class="sub">Set a target and Cherubim works all 22 phases, lands the exploit for each finding, and reports only what it can reproduce.</p>' +
      '<form class="lform" id="scanForm">' +
      '<div class="lrow"><label>Target</label><input id="scanTarget" type="text" autocomplete="off" spellcheck="false" placeholder="https://app.example.com   ·   host.example.com   ·   *.example.com" required></div>' +
      '<div class="lgrid">' +
      '<div class="lrow"><label>Mode</label><select id="scanMode"><option value="single">Single target</option><option value="wildcard">Wildcard — discover &amp; test subdomains</option></select></div>' +
      '<div class="lrow"><label>Report from severity</label><select id="scanSev"><option value="info">Info and above</option><option value="low" selected>Low and above</option><option value="medium">Medium and above</option><option value="high">High and above</option><option value="critical">Critical only</option></select></div>' +
      '</div>' +
      '<div class="lactions"><button class="b b-primary" id="scanGo" type="submit">Launch engagement</button>' +
      '<span class="lnote">Non-destructive · rate-aware · safe against production</span></div>' +
      '</form></div>';
  }

  function donut(counts) {
    var total = SEV.reduce(function (a, s) { return a + (counts[s] || 0); }, 0);
    var r = 34, c = 2 * Math.PI * r, off = 0, arcs = "";
    if (total > 0) {
      SEV.forEach(function (s) {
        var v = counts[s] || 0; if (!v) return;
        var len = c * (v / total);
        arcs += '<circle cx="44" cy="44" r="' + r + '" fill="none" stroke="' + SEV_COLOR[s] + '" stroke-width="12" ' +
          'stroke-dasharray="' + len.toFixed(1) + ' ' + (c - len).toFixed(1) + '" stroke-dashoffset="' + (-off).toFixed(1) + '" transform="rotate(-90 44 44)"/>';
        off += len;
      });
    }
    return '<svg class="donut" width="88" height="88" viewBox="0 0 88 88">' +
      '<circle cx="44" cy="44" r="' + r + '" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="12"/>' + arcs +
      '<text x="44" y="42" text-anchor="middle" fill="#fff" font-family="Space Grotesk" font-size="20" font-weight="700">' + total + '</text>' +
      '<text x="44" y="56" text-anchor="middle" fill="#9AA0AA" font-family="JetBrains Mono" font-size="7" letter-spacing="1">FINDINGS</text></svg>';
  }

  function scanPanel() {
    if (!state.scan) return "";
    var sc = state.scan, cn = state.counts || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    var ph = Math.max(1, Math.min(22, sc.current_phase || 1));
    var pct = state.done ? 100 : Math.round((ph / 22) * 100);
    var running = !state.done && (sc.status === "running" || sc.status === "queued");

    var ticks = "";
    for (var i = 0; i < 22; i++) {
      var cls = state.done || i + 1 < ph ? "done" : (i + 1 === ph ? "on" : "");
      ticks += '<div class="ptick ' + cls + '" title="' + esc(PHASES[i]) + '">' + (i + 1) + '</div>';
    }

    var legend = SEV.map(function (s) {
      return '<div class="lg"><i class="i-' + SEV_ABBR[s] + '"></i>' + SEV_LABEL[s] + '<b>' + (cn[s] || 0) + '</b></div>';
    }).join("");

    return '<div class="scan" id="scanPanel">' +
      '<div class="scan-top"><div>' +
      '<div class="eyebrow-min">' + (running ? '<span class="live-dot"></span> Live engagement' : 'Engagement complete') + '</div>' +
      '<div class="tgt">' + esc(sc.target) + '</div>' +
      '<div class="meta">' + esc(sc.mode || "single") + ' · ' + esc((sc.id || "").slice(0, 8)) + ' · ' + elapsed(Date.now() - state.t0) + '</div></div>' +
      '<span class="stbadge ' + (state.done ? "ok" : "run") + '">' + esc(state.done ? "completed" : (sc.status || "running")) + '</span></div>' +
      '<div class="scan-body">' +
      '<div class="scan-main">' +
      '<div class="phase-head"><span class="nm">Phase <b>' + ph + '</b> / 22 — ' + esc(PHASES[ph - 1] || "") + '</span><span class="pct">' + pct + '%</span></div>' +
      '<div class="pbar"><i style="width:' + pct + '%"></i></div>' +
      '<div class="ptrack">' + ticks + '</div>' +
      '<div class="phase-log">' + phaseLog(ph) + '</div>' +
      '</div>' +
      '<div class="scan-side">' +
      '<div class="sevsum">' + donut(cn) + '<div class="sevlegend">' + legend + '</div></div>' +
      '<div class="metricline"><span>Reproduced</span><b>' + SEV.reduce(function (a, s) { return a + (cn[s] || 0); }, 0) + ' / ' + SEV.reduce(function (a, s) { return a + (cn[s] || 0); }, 0) + '</b></div>' +
      '<div class="metricline"><span>Elapsed</span><b>' + elapsed(Date.now() - state.t0) + '</b></div>' +
      '<div class="metricline"><span>Mode</span><b>' + esc(sc.mode || "single") + '</b></div>' +
      '</div></div></div>';
  }

  function phaseLog(ph) {
    var rows = [];
    for (var i = Math.max(0, ph - 5); i < ph; i++) {
      var proven = state.findings.filter(function (f) { return +f.phase === i + 1; });
      var line = proven.length
        ? '<span class="hit">phase ' + String(i + 1).padStart(2, "0") + '  ' + esc(cleanTitle(proven[0].title)).slice(0, 46) + '</span>'
        : 'phase ' + String(i + 1).padStart(2, "0") + '  ' + esc(PHASES[i]);
      rows.push('<div>' + line + '</div>');
    }
    return rows.join("") || '<div>initializing engagement…</div>';
  }

  function findingsSection() {
    var list = state.filter === "all" ? state.findings : state.findings.filter(function (f) { return (f.severity || "info").toLowerCase() === state.filter; });
    list = list.slice().sort(function (a, b) {
      var d = (SEV_RANK[(a.severity || "info").toLowerCase()] || 9) - (SEV_RANK[(b.severity || "info").toLowerCase()] || 9);
      return d !== 0 ? d : (new Date(b.created_at) - new Date(a.created_at));
    });
    var counts = {}; state.findings.forEach(function (f) { var s = (f.severity || "info").toLowerCase(); counts[s] = (counts[s] || 0) + 1; });
    var chips = ["all"].concat(SEV).map(function (s) {
      var n = s === "all" ? state.findings.length : (counts[s] || 0);
      return '<button class="chip' + (state.filter === s ? " on" : "") + '" data-filter="' + s + '">' + (s === "all" ? "All" : SEV_LABEL[s]) + ' ' + n + '</button>';
    }).join("");

    var body;
    if (!list.length) {
      body = '<div class="fempty">' + (state.scan && !state.done ? "No reproduced findings yet. Cherubim reports only what it can prove." : "Findings will appear here once an engagement runs.") + '</div>';
    } else {
      body = '<table class="ftable"><thead><tr><th>Severity</th><th>Finding</th><th>CVSS</th><th>Phase</th><th>Target</th><th>Status</th></tr></thead><tbody>' +
        list.map(function (f) {
          var s = (f.severity || "info").toLowerCase(), ab = SEV_ABBR[s];
          var proven = f.evidence && f.evidence.tags && f.evidence.tags.indexOf("exploit-proven") >= 0;
          return '<tr data-fid="' + esc(f.id) + '">' +
            '<td><span class="sevtag ' + ab + '"><span class="d"></span>' + SEV_LABEL[s] + '</span></td>' +
            '<td class="ftitle">' + esc(cleanTitle(f.title)) + '</td>' +
            '<td class="fcvss">' + (f.cvss != null ? f.cvss : "—") + '</td>' +
            '<td class="fmono">' + esc(f.phase || "—") + '</td>' +
            '<td class="fmono">' + esc(f.scan_target || "") + '</td>' +
            '<td>' + (proven ? '<span class="fproven">exploit proven</span>' : '<span class="fmono">reported</span>') + '</td></tr>';
        }).join("") + '</tbody></table>';
    }

    return '<div id="findings"><div class="fsection-head"><h3>Findings</h3><span class="cnt">' + state.findings.length + ' total</span></div>' +
      '<div class="fchips">' + chips + '</div>' + body + '</div>';
  }

  function paint() {
    $("#content").innerHTML = launcher() + scanPanel() + findingsSection();
    bind();
    var ct = $("#navFindCt"); if (ct) ct.textContent = state.findings.length ? String(state.findings.length) : "";
  }

  function refreshDynamic() {
    var p = $("#scanPanel"); if (p) p.outerHTML = scanPanel(); else if (state.scan) { var l = $("#launcher"); if (l) l.insertAdjacentHTML("afterend", scanPanel()); }
    var f = $("#findings"); if (f) f.outerHTML = findingsSection();
    bind();
    var b = $("#scanGo"); if (b) { b.disabled = false; b.textContent = "Launch engagement"; }
    var ct = $("#navFindCt"); if (ct) ct.textContent = state.findings.length ? String(state.findings.length) : "";
  }

  function bind() {
    var form = $("#scanForm");
    if (form) form.onsubmit = function (e) { e.preventDefault(); launch(); };
    $$(".ftable tbody tr").forEach(function (r) { r.onclick = function () { openFinding(r.getAttribute("data-fid")); }; });
    $$(".chip[data-filter]").forEach(function (c) { c.onclick = function () { state.filter = c.getAttribute("data-filter"); refreshDynamic(); }; });
    try { var lt = localStorage.getItem("cb_last_target"), ti = $("#scanTarget"); if (lt && ti && !ti.value) ti.value = lt; } catch (e) {}
  }

  function openFinding(id) {
    var f = state.findings.filter(function (x) { return x.id === id; })[0]; if (!f) return;
    var s = (f.severity || "info").toLowerCase(), ab = SEV_ABBR[s], ev = f.evidence || {};
    var extra = [];
    Object.keys(ev).forEach(function (k) {
      if (["tags", "cwe_id", "owasp", "fix"].indexOf(k) >= 0) return;
      var v = ev[k]; if (v == null || v === "") return;
      if (typeof v === "object") v = JSON.stringify(v);
      extra.push(k + " = " + v);
    });
    var proven = ev.tags && ev.tags.indexOf("exploit-proven") >= 0;
    $("#drawerBody").innerHTML =
      '<button class="x" data-x>&times;</button>' +
      '<div class="dr-eyebrow">' + esc((f.id || "").slice(0, 8)) + ' · Phase ' + esc(f.phase || "?") + '</div>' +
      '<h3>' + esc(cleanTitle(f.title)) + '</h3>' +
      '<div class="meta"><span class="tag ' + ab + '">' + SEV_LABEL[s] + '</span>' +
      (f.cvss != null ? '<span class="tag ok">CVSS ' + esc(f.cvss) + '</span>' : "") +
      (ev.cwe_id ? '<span class="tag">' + esc(ev.cwe_id) + '</span>' : "") +
      (ev.owasp ? '<span class="tag">' + esc(ev.owasp) + '</span>' : "") +
      (proven ? '<span class="tag ok">exploit proven</span>' : "") + '</div>' +
      '<h5>Target</h5><p class="mono" style="font-size:12px">' + esc(f.scan_target || "") + ' · ' + esc(f.scan_mode || "") + '</p>' +
      '<h5>Evidence &amp; proof of concept</h5><div class="code">' + esc(f.description || "No description provided.") + '</div>' +
      (f.remediation || ev.fix ? '<h5>Remediation</h5><p>' + esc(f.remediation || ev.fix) + '</p>' : '') +
      (extra.length ? '<h5>Metadata</h5><div class="code">' + esc(extra.join("\n")) + '</div>' : '') +
      '<h5>Reported</h5><p class="mono" style="font-size:12px">' + esc(f.created_at || "") + '</p>';
    $("#scrim").classList.add("open"); $("#drawer").classList.add("open");
    $("[data-x]").onclick = closeDrawer;
  }
  function closeDrawer() { $("#scrim").classList.remove("open"); $("#drawer").classList.remove("open"); }

  function launch() {
    var target = normTarget($("#scanTarget").value || "");
    var mode = $("#scanMode").value, sev = $("#scanSev").value;
    if (!target) { toast("Enter a target", "Add a URL, host or wildcard to test.", "err"); return; }
    var btn = $("#scanGo"); if (btn) { btn.disabled = true; btn.textContent = "Launching…"; }
    try { localStorage.setItem("cb_last_target", $("#scanTarget").value.trim()); } catch (e) {}

    createScan(target, mode, sev).then(function (r) {
      state.scan = { id: r.id, target: r.target || target, mode: mode, status: r.status || "running", current_phase: 1 };
      state.counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      state.findings = []; state.done = false; state.warned = false; state.t0 = Date.now(); state.filter = "all";
      toast("Engagement started", "Working " + target + " across 22 phases.");
      paint();
      var p = $("#scanPanel"); if (p) p.scrollIntoView({ behavior: "smooth", block: "start" });
      startPoll();
    }).catch(function (err) {
      if (btn) { btn.disabled = false; btn.textContent = "Launch engagement"; }
      toast("Could not start", String(err.message || err), "err");
    });
  }

  function startPoll() { if (state.poll) clearInterval(state.poll); tick(); state.poll = setInterval(tick, PORTAL.pollMs); }
  function stopPoll() { if (state.poll) { clearInterval(state.poll); state.poll = null; } }

  function tick() {
    if (!state.scan) return;
    var id = state.scan.id, prev = state.findings.length;
    scanStatus(id).then(function (r) {
      if (!r.scan) return;
      state.scan.status = r.scan.status;
      state.scan.current_phase = r.scan.current_phase || state.scan.current_phase;
      state.scan.mode = r.scan.mode || state.scan.mode;
      state.counts = r.counts || state.counts;
      var finished = r.scan.status === "completed" || r.scan.status === "failed" || r.scan.completed_at;
      return listFindings(id, 100).then(function (fr) {
        state.findings = fr.findings || [];
        if (state.findings.length > prev) {
          var n = state.findings[0];
          if (n) toast("Finding proven", SEV_LABEL[(n.severity || "info").toLowerCase()] + " · " + cleanTitle(n.title), "ok");
        }
        if (finished) {
          state.done = true; stopPoll();
          var c = state.counts || {};
          toast("Engagement complete", (c.critical || 0) + " critical, " + (c.high || 0) + " high, " + (c.medium || 0) + " medium — all reproduced.", "ok");
        }
        refreshDynamic();
      });
    }).catch(function (err) {
      if (!state.warned) { state.warned = true; toast("Live update interrupted", String(err.message || err), "warn"); }
    });
  }

  function loadRecent() {
    listFindings(null, 100).then(function (fr) {
      if (!state.scan && fr.findings && fr.findings.length) {
        state.findings = fr.findings;
        refreshDynamic();
      }
    }).catch(function () {});
  }

  document.addEventListener("DOMContentLoaded", function () {
    var ini = USER.initials || (USER.name || "AA").split(" ").map(function (w) { return w[0]; }).join("").slice(0, 2).toUpperCase();
    if ($("#uAv")) $("#uAv").textContent = ini;
    if ($("#uName")) $("#uName").textContent = USER.name;
    if ($("#uMail")) $("#uMail").textContent = USER.email;

    paint();
    loadRecent();

    $("#scrim").onclick = closeDrawer;
    var lo = $("#logout"); if (lo) lo.onclick = function () { try { sessionStorage.removeItem("cb_s"); sessionStorage.removeItem("cb_u"); } catch (e) {} location.href = "../login.html"; };
    var mb = $("#menuBtn"); if (mb) mb.onclick = function () { $("#rail").classList.toggle("open"); };
    $$(".rail-item[data-nav]").forEach(function (b) {
      b.onclick = function () {
        $$(".rail-item").forEach(function (x) { x.classList.remove("on"); });
        b.classList.add("on");
        var t = b.getAttribute("data-nav") === "findings" ? $("#findings") : $("#launcher");
        if (t) t.scrollIntoView({ behavior: "smooth", block: "start" });
        $("#rail").classList.remove("open");
        if (b.getAttribute("data-nav") === "scan") { var ti = $("#scanTarget"); if (ti) ti.focus(); }
      };
    });
  });
})();
