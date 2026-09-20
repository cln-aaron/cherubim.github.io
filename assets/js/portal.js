(function () {
  "use strict";

  // Cloudflare Access gates /console and /api. Identity comes from the Access
  // session; there is no separate in-app login.
  var USER = { name: "Operator", email: "", initials: "OP" };

  var PORTAL = {
    base: "/api/v1",
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
  var FREQ = { daily: "Daily", weekly: "Weekly", monthly: "Monthly" };

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
  function listScans() { return api("/scanlist"); }
  function deleteScan(id) { return api("/scanlist?id=" + encodeURIComponent(id), { method: "DELETE" }); }
  function listSchedules() { return api("/schedules"); }
  function createSchedule(s) { return api("/schedules", { method: "POST", body: s }); }
  function deleteSchedule(id) { return api("/schedules?id=" + encodeURIComponent(id), { method: "DELETE" }); }

  var state = { view: "new", scan: null, counts: null, findings: [], filter: "all", poll: null, clockIv: null, t0: 0, endT: 0, done: false, warned: false, scans: [], schedules: [], activity: [], lastPhase: 0, seenFinds: {} };

  function pushAct(kind, text) {
    state.activity.push({ t: new Date().toLocaleTimeString([], { hour12: false }), kind: kind, text: text });
    if (state.activity.length > 100) state.activity.shift();
  }
  function activityRows() {
    if (!state.activity.length) return '<div class="lf">initializing engagement…</div>';
    return state.activity.map(function (a) { return '<div class="lf ' + a.kind + '"><span class="t">' + a.t + '</span>' + esc(a.text) + '</div>'; }).join("");
  }
  function scrollFeed() { var f = $("#liveFeed"); if (f) f.scrollTop = f.scrollHeight; }
  function showLoad(on) { var o = $("#loadOverlay"); if (o) o.classList.toggle("open", !!on); }
  function curElapsed() { return elapsed(((state.done && state.endT) ? state.endT : Date.now()) - state.t0); }
  function startClock() {
    stopClock();
    state.clockIv = setInterval(function () {
      if (!state.scan || state.done) { stopClock(); return; }
      var e = curElapsed(), a = $("#cbElapsed"), b = $("#cbElapsed2");
      if (a) a.textContent = e; if (b) b.textContent = e;
    }, 1000);
  }
  function stopClock() { if (state.clockIv) { clearInterval(state.clockIv); state.clockIv = null; } }

  function toast(title, msg, kind) {
    var t = document.createElement("div");
    t.className = "toast" + (kind ? " " + kind : "");
    t.innerHTML = "<b>" + esc(title) + "</b>" + (msg ? esc(msg) : "");
    $("#toasts").appendChild(t);
    setTimeout(function () { t.style.transition = "opacity .4s"; t.style.opacity = "0"; setTimeout(function () { t.remove(); }, 400); }, 5200);
  }

  function cleanTitle(t) { return String(t || "Finding").split(" — ")[0].replace(/\s*\((attribute-context|execution proof[^)]*)\)/gi, "").trim(); }
  function elapsed(ms) { var s = Math.floor(ms / 1000); return String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0"); }
  function ago(ts) {
    if (!ts) return "—";
    var s = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
    if (s < 0) return "in " + fmtDur(-s);
    if (s < 60) return "just now";
    return fmtDur(s) + " ago";
  }
  function fmtDur(s) {
    if (s < 3600) return Math.floor(s / 60) + "m";
    if (s < 86400) return Math.floor(s / 3600) + "h";
    return Math.floor(s / 86400) + "d";
  }
  function when(ts) { if (!ts) return "—"; try { return new Date(ts).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); } catch (e) { return String(ts); } }
  function normTarget(v) {
    v = v.trim();
    if (!v) return v;
    if (/^\*\./.test(v) || /^https?:\/\//i.test(v)) return v;
    if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return v;
    return "https://" + v;
  }

  /* ---------- scan view ---------- */
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
    if (total > 0) SEV.forEach(function (s) {
      var v = counts[s] || 0; if (!v) return;
      var len = c * (v / total);
      arcs += '<circle cx="44" cy="44" r="' + r + '" fill="none" stroke="' + SEV_COLOR[s] + '" stroke-width="12" stroke-dasharray="' + len.toFixed(1) + ' ' + (c - len).toFixed(1) + '" stroke-dashoffset="' + (-off).toFixed(1) + '" transform="rotate(-90 44 44)"/>';
      off += len;
    });
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
    var total = SEV.reduce(function (a, s) { return a + (cn[s] || 0); }, 0);
    var ticks = "";
    for (var i = 0; i < 22; i++) {
      var cls = state.done || i + 1 < ph ? "done" : (i + 1 === ph ? "on" : "");
      ticks += '<div class="ptick ' + cls + '" title="' + esc(PHASES[i]) + '">' + (i + 1) + '</div>';
    }
    var legend = SEV.map(function (s) { return '<div class="lg"><i class="i-' + SEV_ABBR[s] + '"></i>' + SEV_LABEL[s] + '<b>' + (cn[s] || 0) + '</b></div>'; }).join("");
    return '<div class="scan" id="scanPanel">' +
      '<div class="scan-top"><div>' +
      '<div class="eyebrow-min">' + (running ? '<span class="live-dot"></span> Live engagement' : 'Engagement complete') + '</div>' +
      '<div class="tgt">' + esc(sc.target) + '</div>' +
      '<div class="meta">' + esc(sc.mode || "single") + ' · ' + esc((sc.id || "").slice(0, 8)) + ' · <span id="cbElapsed">' + curElapsed() + '</span></div></div>' +
      '<span class="stbadge ' + (state.done ? "ok" : "run") + '">' + esc(state.done ? "completed" : (sc.status || "running")) + '</span></div>' +
      '<div class="scan-body"><div class="scan-main">' +
      '<div class="phase-head"><span class="nm">Phase <b>' + ph + '</b> / 22 — ' + esc(PHASES[ph - 1] || "") + '</span><span class="pct">' + pct + '%</span></div>' +
      '<div class="pbar"><i style="width:' + pct + '%"></i></div>' +
      '<div class="ptrack">' + ticks + '</div>' +
      '<div class="lf-head">Live activity</div><div class="live-feed" id="liveFeed">' + activityRows() + '</div></div>' +
      '<div class="scan-side">' +
      '<div class="sevsum">' + donut(cn) + '<div class="sevlegend">' + legend + '</div></div>' +
      '<div class="metricline"><span>Reproduced</span><b>' + total + '</b></div>' +
      '<div class="metricline"><span>Elapsed</span><b id="cbElapsed2">' + curElapsed() + '</b></div>' +
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

  /* ---------- scans list view ---------- */
  function scansView() {
    var rows;
    if (!state.scans.length) {
      rows = '<div class="fempty">No scans recorded yet. Launch one from New scan and it will appear here.</div>';
    } else {
      rows = '<table class="ftable"><thead><tr><th>Target</th><th>Mode</th><th>Status</th><th>Findings</th><th>Started</th><th></th></tr></thead><tbody>' +
        state.scans.map(function (s) {
          var st = s.status || "—", stcls = st === "completed" ? "ok" : (st === "running" || st === "queued" ? "run" : "");
          var total = s.counts ? SEV.reduce(function (a, k) { return a + (s.counts[k] || 0); }, 0) : null;
          return '<tr data-scan="' + esc(s.id) + '">' +
            '<td class="ftitle">' + esc(s.target) + '</td>' +
            '<td class="fmono">' + esc(s.mode || "single") + '</td>' +
            '<td>' + (stcls ? '<span class="stbadge ' + stcls + '" style="font-size:10px;padding:3px 9px">' + esc(st) + '</span>' : '<span class="fmono">' + esc(st) + '</span>') + '</td>' +
            '<td class="fmono">' + (total == null ? "—" : total) + '</td>' +
            '<td class="fmono">' + when(s.createdAt || s.started_at) + '</td>' +
            '<td class="row-act"><button class="dots" data-scanmenu="' + esc(s.id) + '" title="More" aria-label="More">&#8943;</button></td></tr>';
        }).join("") + '</tbody></table>';
    }
    return '<div class="fsection-head"><h3>Scans</h3><span class="cnt">' + state.scans.length + ' recorded</span></div>' +
      '<p class="lnote" style="margin:2px 0 14px">Every engagement you launch is recorded here. Click one to open its findings.</p>' + rows;
  }

  /* ---------- scheduled view ---------- */
  function scheduledView() {
    var form = '<div class="launch" id="schedForm"><h2>Schedule a recurring scan</h2>' +
      '<p class="sub">Cherubim re-tests the target on a cadence and records each run under Scans. Scheduled runs respect the same allowed-target list.</p>' +
      '<form class="lform" id="schedFormEl">' +
      '<div class="lrow"><label>Target</label><input id="schTarget" type="text" autocomplete="off" spellcheck="false" placeholder="https://app.example.com   ·   *.example.com" required></div>' +
      '<div class="lgrid">' +
      '<div class="lrow"><label>Mode</label><select id="schMode"><option value="single">Single target</option><option value="wildcard">Wildcard</option></select></div>' +
      '<div class="lrow"><label>Frequency</label><select id="schFreq"><option value="daily">Daily</option><option value="weekly" selected>Weekly</option><option value="monthly">Monthly</option></select></div>' +
      '</div>' +
      '<div class="lgrid">' +
      '<div class="lrow"><label>Report from severity</label><select id="schSev"><option value="info">Info and above</option><option value="low" selected>Low and above</option><option value="medium">Medium and above</option><option value="high">High and above</option><option value="critical">Critical only</option></select></div>' +
      '<div class="lrow"><label>Time (UTC)</label><input id="schTime" type="time" value="02:00"></div>' +
      '</div>' +
      '<div class="lactions"><button class="b b-primary" id="schGo" type="submit">Create schedule</button>' +
      '<span class="lnote">Each run spends one credit at the scheduled time</span></div>' +
      '</form></div>';

    var list;
    if (!state.schedules.length) {
      list = '<div class="fempty">No schedules yet. Create one above to re-test a target automatically.</div>';
    } else {
      list = '<table class="ftable"><thead><tr><th>Target</th><th>Mode</th><th>Frequency</th><th>Next run</th><th>Last run</th><th></th></tr></thead><tbody>' +
        state.schedules.map(function (s) {
          return '<tr>' +
            '<td class="ftitle">' + esc(s.target) + '</td>' +
            '<td class="fmono">' + esc(s.mode || "single") + '</td>' +
            '<td class="fmono">' + (FREQ[s.frequency] || esc(s.frequency)) + ' · ' + String(s.hour).padStart(2, "0") + ':' + String(s.minute || 0).padStart(2, "0") + ' UTC</td>' +
            '<td class="fmono">' + when(s.nextRun) + '</td>' +
            '<td class="fmono">' + (s.lastRun ? ago(s.lastRun) : "—") + '</td>' +
            '<td><button class="b b-ghost b-sm" data-delsched="' + esc(s.id) + '">Delete</button></td></tr>';
        }).join("") + '</tbody></table>';
    }
    return form +
      '<div class="fsection-head" style="margin-top:8px"><h3>Active schedules</h3><span class="cnt">' + state.schedules.length + '</span></div>' +
      '<div style="margin-top:12px">' + list + '</div>';
  }

  /* ---------- render ---------- */
  function currentView() {
    if (!state.scan) return '<div class="cur-empty"><b>No scan open</b><span>Start one from New scan, or open a past run from Scans.</span></div>';
    return scanPanel() + findingsSection();
  }
  function render() {
    var c = $("#content");
    if (state.view === "scans") c.innerHTML = scansView();
    else if (state.view === "scheduled") c.innerHTML = scheduledView();
    else if (state.view === "current") c.innerHTML = currentView();
    else c.innerHTML = launcher();
    bind();
    scrollFeed();
    $("#crumb").textContent = state.view === "scans" ? "/ scans" : state.view === "scheduled" ? "/ scheduled" : state.view === "current" ? "/ current scan" : "";
  }
  function refreshDynamic() {
    if (state.view !== "current") return;
    var p = $("#scanPanel"); if (p) p.outerHTML = scanPanel(); else { render(); return; }
    var f = $("#findings"); if (f) f.outerHTML = findingsSection();
    bind();
    scrollFeed();
  }

  function bind() {
    var form = $("#scanForm"); if (form) form.onsubmit = function (e) { e.preventDefault(); launch(); };
    $$(".ftable tbody tr[data-fid]").forEach(function (r) { r.onclick = function () { openFinding(r.getAttribute("data-fid")); }; });
    $$(".chip[data-filter]").forEach(function (c) { c.onclick = function () { state.filter = c.getAttribute("data-filter"); refreshDynamic(); }; });
    $$(".ftable tbody tr[data-scan]").forEach(function (r) { r.onclick = function () { openScan(r.getAttribute("data-scan")); }; });
    $$("[data-scanmenu]").forEach(function (b) { b.onclick = function (e) { e.stopPropagation(); openRowMenu(b.getAttribute("data-scanmenu"), b); }; });
    var sf = $("#schedFormEl"); if (sf) sf.onsubmit = function (e) { e.preventDefault(); submitSchedule(); };
    $$("[data-delsched]").forEach(function (b) { b.onclick = function () { removeSchedule(b.getAttribute("data-delsched")); }; });
    try { var lt = localStorage.getItem("cb_last_target"), ti = $("#scanTarget"); if (lt && ti && !ti.value) ti.value = lt; } catch (e) {}
  }

  /* ---------- row menu: download report / delete ---------- */
  function closeRowMenu() { var m = $("#rowMenu"); if (m) { m.classList.remove("open"); m.innerHTML = ""; } }
  function openRowMenu(id, btn) {
    var m = $("#rowMenu"); if (!m) return;
    var scan = state.scans.filter(function (s) { return s.id === id; })[0] || { id: id };
    m.innerHTML =
      '<button class="rm-item" data-act="report">Download report</button>' +
      '<button class="rm-item danger" data-act="delete">Delete scan</button>';
    var r = btn.getBoundingClientRect();
    m.style.top = (r.bottom + 6) + "px";
    m.style.left = Math.max(12, r.right - 168) + "px";
    m.classList.add("open");
    $(".rm-item[data-act='report']", m).onclick = function () { closeRowMenu(); downloadReport(scan); };
    $(".rm-item[data-act='delete']", m).onclick = function () { closeRowMenu(); doDeleteScan(scan); };
  }

  function doDeleteScan(scan) {
    if (!window.confirm("Remove this scan from the list? The engagement record is deleted from your console.")) return;
    deleteScan(scan.id).then(function () {
      state.scans = state.scans.filter(function (s) { return s.id !== scan.id; });
      render();
      var ct = $("#navScanCt"); if (ct) ct.textContent = state.scans.length ? String(state.scans.length) : "";
      toast("Scan removed", "", "ok");
    }).catch(function (err) { toast("Could not delete", String(err.message || err), "err"); });
  }

  function downloadReport(scan) {
    toast("Building report", "Compiling findings for " + scan.target + "…");
    Promise.all([scanStatus(scan.id), listFindings(scan.id, 200)]).then(function (res) {
      var st = res[0].scan || scan, cn = res[0].counts || {}, finds = res[1].findings || [];
      var html = buildReportHtml(st, cn, finds);
      var name = "cherubim-report-" + String(st.target || "scan").replace(/^https?:\/\//, "").replace(/[^a-z0-9.-]+/gi, "-").replace(/^-+|-+$/g, "") + "-" + new Date().toISOString().slice(0, 10) + ".html";
      var blob = new Blob([html], { type: "text/html" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob); a.download = name;
      document.body.appendChild(a); a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
      toast("Report ready", finds.length + " findings · open the file and print to PDF if needed.", "ok");
    }).catch(function (err) { toast("Could not build report", String(err.message || err), "err"); });
  }

  function buildReportHtml(scan, counts, finds) {
    var order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    var sorted = finds.slice().sort(function (a, b) { return (order[(a.severity || "info").toLowerCase()] || 9) - (order[(b.severity || "info").toLowerCase()] || 9); });
    var sevRow = SEV.map(function (s) { return '<span class="pill ' + s + '">' + SEV_LABEL[s] + ' ' + (counts[s] || 0) + '</span>'; }).join(" ");
    var body = sorted.length ? sorted.map(function (f) {
      var s = (f.severity || "info").toLowerCase(), ev = f.evidence || {};
      return '<section class="f"><div class="fh"><span class="sev ' + s + '">' + SEV_LABEL[s] + '</span>' +
        '<h3>' + esc(cleanTitle(f.title)) + '</h3></div>' +
        '<div class="tags">' + (f.cvss != null ? '<span>CVSS ' + esc(f.cvss) + '</span>' : "") + (ev.cwe_id ? '<span>' + esc(ev.cwe_id) + '</span>' : "") + (ev.owasp ? '<span>' + esc(ev.owasp) + '</span>' : "") + '<span>Phase ' + esc(f.phase || "?") + '</span></div>' +
        '<h4>Evidence &amp; proof of concept</h4><pre>' + esc(f.description || "") + '</pre>' +
        (f.remediation || ev.fix ? '<h4>Remediation</h4><p>' + esc(f.remediation || ev.fix) + '</p>' : "") + '</section>';
    }).join("") : '<p class="none">No findings were reproduced for this engagement.</p>';
    return '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Cherubim report — ' + esc(scan.target || "") + '</title>' +
      '<style>*{box-sizing:border-box}body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#15181d;max-width:840px;margin:0 auto;padding:48px 32px;line-height:1.55}' +
      'h1{font-size:26px;margin:0 0 4px}.sub{color:#667085;font-family:ui-monospace,Menlo,monospace;font-size:13px}' +
      '.summary{margin:22px 0 30px;padding:18px;border:1px solid #e6e8ec;border-radius:10px}' +
      '.pill{display:inline-block;font-size:12px;font-weight:600;padding:4px 10px;border-radius:20px;margin:3px 4px 3px 0;border:1px solid #e0e0e0}' +
      '.pill.critical{background:#fdecec;color:#c0261d;border-color:#f4bcbc}.pill.high{background:#fff0e6;color:#c25a12;border-color:#f6cfae}' +
      '.pill.medium{background:#fff8e1;color:#9a7400;border-color:#f0dda0}.pill.low{background:#eaf2fe;color:#245ec0;border-color:#c3d8f6}.pill.info{background:#f1f3f5;color:#555}' +
      '.f{border-top:1px solid #e6e8ec;padding:22px 0}.fh{display:flex;align-items:center;gap:10px}.fh h3{font-size:17px;margin:0}' +
      '.sev{font-size:11px;font-weight:700;text-transform:uppercase;padding:3px 8px;border-radius:5px;color:#fff}' +
      '.sev.critical{background:#e0342a}.sev.high{background:#e8720f}.sev.medium{background:#caa000;color:#1a1a1a}.sev.low{background:#2f6fd6}.sev.info{background:#8a94a6}' +
      '.tags{margin:8px 0}.tags span{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:#667085;border:1px solid #e6e8ec;border-radius:5px;padding:2px 7px;margin-right:6px}' +
      'h4{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#98a2b3;margin:16px 0 6px}' +
      'pre{background:#0c0e12;color:#e6e8ec;padding:14px;border-radius:8px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}' +
      '.none{color:#667085}footer{margin-top:40px;border-top:1px solid #e6e8ec;padding-top:16px;color:#98a2b3;font-size:12px}' +
      '@media print{body{padding:0}}</style></head><body>' +
      '<h1>Cherubim penetration test report</h1>' +
      '<div class="sub">' + esc(scan.target || "") + ' · ' + esc(scan.mode || "single") + ' · ' + (scan.status || "") + ' · generated ' + new Date().toLocaleString() + '</div>' +
      '<div class="summary"><b>Severity summary</b><div style="margin-top:10px">' + sevRow + '</div></div>' +
      '<h2 style="font-size:18px">Findings</h2>' + body +
      '<footer>Cherubim by Hesed &amp; Emet · exploit-validated findings · authorized security testing only</footer>' +
      '</body></html>';
  }

  /* ---------- finding drawer ---------- */
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

  /* ---------- launch + poll ---------- */
  function launch() {
    var target = normTarget($("#scanTarget").value || "");
    var mode = $("#scanMode").value, sev = $("#scanSev").value;
    if (!target) { toast("Enter a target", "Add a URL, host or wildcard to test.", "err"); return; }
    var btn = $("#scanGo"); if (btn) { btn.disabled = true; btn.textContent = "Launching…"; }
    showLoad(true);
    try { localStorage.setItem("cb_last_target", $("#scanTarget").value.trim()); } catch (e) {}
    createScan(target, mode, sev).then(function (r) {
      state.scan = { id: r.id, target: r.target || target, mode: mode, status: r.status || "running", current_phase: 1 };
      state.counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      state.findings = []; state.done = false; state.warned = false; state.t0 = Date.now(); state.endT = 0; state.filter = "all";
      state.activity = []; state.lastPhase = 0; state.seenFinds = {};
      pushAct("start", "engagement started · " + target);
      showLoad(false);
      toast("Engagement started", "Working " + target + " across 22 phases.", "ok");
      setView("current");
      startPoll();
      startClock();
    }).catch(function (err) {
      showLoad(false);
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
      var np = r.scan.current_phase || state.scan.current_phase;
      if (np > state.lastPhase) {
        for (var pn = state.lastPhase + 1; pn <= np; pn++) pushAct("phase", "phase " + String(pn).padStart(2, "0") + " — " + (PHASES[pn - 1] || ""));
        state.lastPhase = np;
      }
      state.scan.current_phase = np;
      state.scan.mode = r.scan.mode || state.scan.mode;
      state.counts = r.counts || state.counts;
      var finished = r.scan.status === "completed" || r.scan.status === "failed" || r.scan.completed_at;
      return listFindings(id, 100).then(function (fr) {
        state.findings = fr.findings || [];
        state.findings.slice().reverse().forEach(function (f) {
          if (!state.seenFinds[f.id]) {
            state.seenFinds[f.id] = 1;
            pushAct("find", "proven · " + SEV_LABEL[(f.severity || "info").toLowerCase()] + " — " + cleanTitle(f.title) + (f.cvss != null ? " · CVSS " + f.cvss : ""));
          }
        });
        if (state.findings.length > prev) {
          var n = state.findings[0];
          if (n) toast("Finding proven", SEV_LABEL[(n.severity || "info").toLowerCase()] + " · " + cleanTitle(n.title), "ok");
        }
        if (finished) {
          state.done = true; state.endT = r.scan.completed_at ? new Date(r.scan.completed_at).getTime() : Date.now();
          stopPoll(); stopClock();
          var c = state.counts || {};
          var tot = SEV.reduce(function (a, k) { return a + (c[k] || 0); }, 0);
          pushAct("done", "engagement complete · " + tot + " findings reproduced");
          toast("Engagement complete", (c.critical || 0) + " critical, " + (c.high || 0) + " high, " + (c.medium || 0) + " medium — all reproduced.", "ok");
        }
        updateCurCt();
        refreshDynamic();
      });
    }).catch(function (err) {
      if (!state.warned) { state.warned = true; toast("Live update interrupted", String(err.message || err), "warn"); }
    });
  }

  /* ---------- open a recorded scan ---------- */
  function openScan(id) {
    showLoad(true);
    Promise.all([scanStatus(id), listFindings(id, 100)]).then(function (res) {
      var st = res[0], fr = res[1];
      showLoad(false);
      if (!st.scan) { toast("Scan not found", "", "err"); return; }
      state.scan = { id: st.scan.id, target: st.scan.target, mode: st.scan.mode, status: st.scan.status, current_phase: st.scan.current_phase };
      state.counts = st.counts || {}; state.findings = fr.findings || []; state.filter = "all";
      state.done = st.scan.status === "completed" || !!st.scan.completed_at;
      state.t0 = st.scan.started_at ? new Date(st.scan.started_at).getTime() : Date.now();
      state.endT = st.scan.completed_at ? new Date(st.scan.completed_at).getTime() : 0;
      state.lastPhase = st.scan.current_phase || 22; state.seenFinds = {};
      state.activity = [];
      pushAct("start", "opened engagement · " + state.scan.target);
      state.findings.slice().reverse().forEach(function (f) {
        state.seenFinds[f.id] = 1;
        pushAct("find", "proven · " + SEV_LABEL[(f.severity || "info").toLowerCase()] + " — " + cleanTitle(f.title) + (f.cvss != null ? " · CVSS " + f.cvss : ""));
      });
      if (state.done) { var tot = SEV.reduce(function (a, k) { return a + (state.counts[k] || 0); }, 0); pushAct("done", "engagement complete · " + tot + " findings reproduced"); }
      setView("current");
      if (!state.done) { startPoll(); startClock(); }
    }).catch(function (err) { showLoad(false); toast("Could not open scan", String(err.message || err), "err"); });
  }

  /* ---------- schedules ---------- */
  function submitSchedule() {
    var target = normTarget($("#schTarget").value || "");
    if (!target) { toast("Enter a target", "Add a target to schedule.", "err"); return; }
    var time = ($("#schTime").value || "02:00").split(":");
    var s = { target: target, mode: $("#schMode").value, severity_filter: $("#schSev").value, frequency: $("#schFreq").value, hour: +time[0] || 0, minute: +time[1] || 0 };
    var btn = $("#schGo"); if (btn) { btn.disabled = true; btn.textContent = "Creating…"; }
    createSchedule(s).then(function () {
      toast("Schedule created", FREQ[s.frequency] + " scan of " + target + " scheduled.", "ok");
      loadSchedules();
    }).catch(function (err) {
      if (btn) { btn.disabled = false; btn.textContent = "Create schedule"; }
      toast("Could not create schedule", String(err.message || err), "err");
    });
  }
  function removeSchedule(id) {
    deleteSchedule(id).then(function () { toast("Schedule removed", "", "ok"); loadSchedules(); })
      .catch(function (err) { toast("Could not delete", String(err.message || err), "err"); });
  }

  /* ---------- data loaders ---------- */
  function loadScans() {
    return listScans().then(function (r) {
      var scans = r.scans || [];
      state.scans = scans;
      var ct = $("#navScanCt"); if (ct) ct.textContent = scans.length ? String(scans.length) : "";
      if (state.view === "scans") render();
      // enrich with live status/counts (best effort, capped)
      scans.slice(0, 25).forEach(function (s) {
        scanStatus(s.id).then(function (st) {
          if (st.scan) { s.status = st.scan.status; s.counts = st.counts; s.mode = st.scan.mode || s.mode; if (state.view === "scans") render(); }
        }).catch(function () {});
      });
    }).catch(function () {});
  }
  function loadSchedules() {
    return listSchedules().then(function (r) {
      state.schedules = r.schedules || [];
      var ct = $("#navSchedCt"); if (ct) ct.textContent = state.schedules.length ? String(state.schedules.length) : "";
      if (state.view === "scheduled") render();
    }).catch(function () {});
  }
  function updateCurCt() {
    var ct = $("#navCurCt");
    if (ct) ct.textContent = state.scan ? (state.done ? "done" : "live") : "";
  }

  /* ---------- view switching ---------- */
  function setView(v) {
    state.view = v;
    $$(".rail-item[data-nav]").forEach(function (b) { b.classList.toggle("on", b.getAttribute("data-nav") === v); });
    $("#rail").classList.remove("open");
    render();
    updateCurCt();
    if (v === "scans") loadScans();
    if (v === "scheduled") loadSchedules();
    if (v === "new") { var ti = $("#scanTarget"); if (ti) ti.focus(); }
  }

  /* ---------- identity ---------- */
  function initialsFor(name, email) {
    var s = name && name !== email ? name : (email || "").split("@")[0];
    var parts = s.split(/[ ._-]+/).filter(Boolean);
    var ini = parts.length > 1 ? parts[0][0] + parts[1][0] : s.slice(0, 2);
    return (ini || "OP").toUpperCase();
  }
  function applyUser(o) {
    var email = (o && o.email) || "";
    var name = (o && o.name) || (email ? email.split("@")[0] : "Operator");
    USER = { name: name, email: email, initials: initialsFor(name, email) };
    if ($("#uAv")) $("#uAv").textContent = USER.initials;
    if ($("#uName")) $("#uName").textContent = USER.name;
    if ($("#uMail")) $("#uMail").textContent = USER.email || "operator";
  }

  document.addEventListener("DOMContentLoaded", function () {
    applyUser(USER);
    fetch("/cdn-cgi/access/get-identity", { credentials: "include" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { if (j && (j.email || j.name)) applyUser({ name: j.name, email: j.email }); })
      .catch(function () {});

    render();
    loadScans();
    loadSchedules();

    $("#scrim").onclick = closeDrawer;
    document.addEventListener("click", function () { closeRowMenu(); });
    window.addEventListener("scroll", function () { closeRowMenu(); }, true);
    var lo = $("#logout"); if (lo) lo.onclick = function () { location.href = "/cdn-cgi/access/logout"; };
    var mb = $("#menuBtn"); if (mb) mb.onclick = function () { $("#rail").classList.toggle("open"); };
    $$(".rail-item[data-nav]").forEach(function (b) { b.onclick = function () { setView(b.getAttribute("data-nav")); }; });
  });
})();
