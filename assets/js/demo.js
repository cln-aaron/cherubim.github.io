(function () {
  "use strict";

  // ---- gate ----
  try {
    if (sessionStorage.getItem("cherubim_demo") !== "1") {
      sessionStorage.setItem("cherubim_demo", "1");
    }
  } catch (e) {}

  // ---------------- DATA (simulated client: Northwind Capital) ----------------
  var ORG = "Northwind Capital";

  var stats = { posture: 72, findings: 38, critical: 4, surface: 1284, paths: 6, humanRisk: 18 };

  var surface = [
    ["api-gw.northwind.io", "External API", "Cloud / AWS", "Critical", "Exposed"],
    ["vpn.northwind.io", "Remote access", "Network edge", "High", "Monitored"],
    ["10.4.0.0/16", "Internal subnet", "Network", "Medium", "Segmented"],
    ["nw-corp.local", "Active Directory", "Identity", "Critical", "Monitored"],
    ["payments.northwind.io", "Web app", "Application", "Critical", "Exposed"],
    ["s3://nw-statements", "Object store", "Cloud / AWS", "High", "Misconfig"],
    ["nw-prod-eks", "Kubernetes", "Cloud / AWS", "High", "Exposed"],
    ["WIFI-NW-CORP", "Wireless", "Network", "Medium", "In range"],
    ["okta.northwind.io", "Identity provider", "Identity", "Critical", "Monitored"],
    ["jenkins.int.northwind.io", "CI / CD", "Supply chain", "High", "Exposed"]
  ];

  var campaigns = [
    ["CMP-2041", "Full stack assumed breach", "Network, Cloud, Identity", "Completed", "100%", "4 critical"],
    ["CMP-2039", "External perimeter", "Web, API", "Completed", "100%", "9 high"],
    ["CMP-2044", "Omnichannel social engineering", "People", "Running", "63%", "live"],
    ["CMP-2037", "Cloud and Kubernetes", "AWS, EKS", "Completed", "100%", "6 high"],
    ["CMP-2031", "Active Directory to domain admin", "Identity", "Completed", "100%", "1 critical"]
  ];

  var findings = [
    { id: "F-3301", t: "Unauthenticated path to domain administrator", sev: "Critical", surf: "Identity", att: "T1556 / T1078",
      d: "An exposed Jenkins instance leaked CI credentials reused by a service account with unconstrained delegation, allowing escalation to Domain Admin.",
      poc: "$ curl -s https://jenkins.int.northwind.io/script\n<span class='c'># reused service credential</span>\n$ impacket-getST -spn HTTP/dc1 -impersonate Administrator \\\n   nw-corp.local/svc_ci:<span class='g'>[recovered]</span>\n<span class='ok'>[+] Domain Admin TGT obtained. Validated in sandbox.</span>",
      fix: "Rotate svc_ci, remove unconstrained delegation, isolate Jenkins behind SSO and network policy." },
    { id: "F-3302", t: "Public object store exposes customer statements", sev: "Critical", surf: "Cloud", att: "T1530",
      d: "Bucket policy on s3://nw-statements allows anonymous list and get. 41,200 PDF statements containing PII were enumerable.",
      poc: "$ aws s3 ls s3://nw-statements --no-sign-request\n2026-04 statement_8841.pdf ... <span class='g'>(41,200 objects)</span>\n<span class='ok'>[+] Read access proven on sampled objects. Not exfiltrated.</span>",
      fix: "Apply Block Public Access, scope bucket policy, enable access logging and alerting." },
    { id: "F-3303", t: "Payments app business logic bypass", sev: "Critical", surf: "Application", att: "T1190",
      d: "Negative quantity in the settlement endpoint inverts the ledger entry, allowing balance manipulation without authentication checks on the second step.",
      poc: "POST /api/v2/settle\n{ \"amount\": <span class='g'>-50000</span>, \"acct\": \"...\" }\n<span class='ok'>[+] Ledger delta applied in sandbox tenant. Reproduced 3x.</span>",
      fix: "Server side invariant checks, signed multi step transactions, fuzz the settlement state machine." },
    { id: "F-3304", t: "EKS pod can reach node IMDS", sev: "High", surf: "Cloud", att: "T1552.005",
      d: "A workload pod can reach the instance metadata service and assume the node role, broadening blast radius across the cluster.",
      poc: "$ kubectl exec web-7f -- curl 169.254.169.254/latest/...\n<span class='g'>nw-eks-node-role</span>\n<span class='ok'>[+] Node role creds retrieved in sandbox.</span>",
      fix: "Enforce IMDSv2 hop limit, apply network policy, use IRSA scoped roles per workload." },
    { id: "F-3305", t: "VPN allows password spray without lockout", sev: "High", surf: "Network", att: "T1110.003",
      d: "No throttling on the VPN portal enabled a low and slow spray that recovered two valid credentials.",
      poc: "<span class='c'># 1 attempt / account / 30 min</span>\n<span class='ok'>[+] 2 valid credentials recovered. MFA held and stopped entry.</span>",
      fix: "Rate limit, lockout policy, alert on spray patterns, enforce phishing resistant MFA." },
    { id: "F-3306", t: "Wireless guest network reaches corp VLAN", sev: "High", surf: "Network", att: "T1021",
      d: "Guest SSID is not isolated from the corporate VLAN, exposing internal services from the lobby.",
      poc: "<span class='ok'>[+] Reached 10.4.12.0/24 from guest SSID. Path proven.</span>",
      fix: "Enforce VLAN isolation and client isolation on guest SSID, restrict inter VLAN routing." }
  ];

  var pathNodes = [
    ["01", "Edge", "Exposed Jenkins on supply chain surface", "Initial Access  T1190"],
    ["02", "Foothold", "Leaked CI credential recovered from build logs", "Credential Access  T1552"],
    ["03", "Pivot", "Lateral movement into internal identity subnet", "Lateral Movement  T1021"],
    ["04", "Escalate", "Unconstrained delegation abused for Domain Admin", "Privilege Escalation  T1078"],
    ["05", "Impact", "Reached customer statement store, exfiltration proven then stopped", "Impact  T1530"]
  ];

  var social = [
    ["Phishing email", 412, "31%", "9%", "Reported in 6 min"],
    ["SMS / smishing", 180, "24%", "n/a", "Low report rate"],
    ["WhatsApp pretext", 64, "19%", "n/a", "Moved off channel"],
    ["Voice clone (vishing)", 22, "41%", "n/a", "Process unlocked"],
    ["Live deepfake on Teams", 8, "50%", "n/a", "Executive impersonation held by 4"],
    ["Slack follow up", 36, "28%", "n/a", "Trusted internal tool"]
  ];

  var frameworks = [
    ["NIST CSF 2.0", 86, "good"], ["Cybersecurity Act", 79, "warn"], ["CSA Cyber Trust", 78, "warn"],
    ["CSA Cyber Essentials", 92, "good"], ["ISO/IEC 27001", 83, "warn"], ["MAS TRM", 74, "warn"],
    ["PDPA", 88, "good"], ["MITRE ATT&CK", 81, "warn"], ["CIS Controls", 69, "bad"]
  ];

  var activity = [
    "agent.recon mapped 1,284 assets across 7 surfaces",
    "agent.web confirmed business logic flaw on payments.northwind.io",
    "validator reproduced F-3303 in isolated sandbox (3x)",
    "agent.identity recovered service credential from CI logs",
    "agent.cloud assumed node role via IMDS on nw-prod-eks",
    "narrative.engine escalated vishing scenario on engagement",
    "agent.network proven guest VLAN reaches corp subnet",
    "compliance.map tagged F-3301 to NIST PR.AC, Cyber Trust",
    "validator marked F-3306 PROVEN, evidence pack updated",
    "agent.identity reached Domain Admin, campaign stopped safely"
  ];

  // ---------------- HELPERS ----------------
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var sevClass = { Critical: "sev-crit", High: "sev-high", Medium: "sev-med", Low: "sev-low" };

  function toast(title, msg) {
    var w = $("#toasts");
    var t = document.createElement("div");
    t.className = "toast";
    t.innerHTML = "<b>" + title + "</b><br>" + msg;
    w.appendChild(t);
    setTimeout(function () { t.style.transition = "opacity .4s"; t.style.opacity = "0";
      setTimeout(function () { t.remove(); }, 400); }, 4200);
  }

  function rows(arr, cls) {
    return arr.map(function (r) {
      return "<tr" + (cls ? " class='" + cls + "'" : "") + ">" +
        r.map(function (c) { return "<td>" + c + "</td>"; }).join("") + "</tr>";
    }).join("");
  }

  // ---------------- RENDER VIEWS ----------------
  function render() {
    // Overview
    $("#v-overview").innerHTML =
      '<div class="view-head"><span class="eyebrow">Command center</span>' +
      '<h1>Security posture at a glance</h1><p>Live state of every engagement across ' + ORG + "'s connected stack.</p></div>" +
      '<div class="stat-row">' +
        statCard("Posture score", stats.posture + " / 100", "up", "+6 this quarter") +
        statCard("Open findings", stats.findings, "down", "12 remediated this month") +
        statCard("Critical", stats.critical, "down", "all with proof attached") +
        statCard("Assets in scope", stats.surface.toLocaleString(), "up", "7 surfaces connected") +
      '</div>' +
      '<div class="grid-2">' +
        '<div class="card-p"><h3>Live agent activity</h3><p class="sub">Autonomous agents working across the connected stack</p><div class="ticker" id="ticker"></div></div>' +
        '<div class="card-p"><h3>Posture by surface</h3><p class="sub">Validated resilience, higher is better</p>' +
          surfBar("Network", 74) + surfBar("Cloud / Kubernetes", 61) + surfBar("Identity / AD", 58) +
          surfBar("Application / API", 67) + surfBar("People", 70) + surfBar("Supply chain", 55) +
        '</div></div>' +
      '<div class="card-p span2" style="margin-top:16px"><h3>Latest critical findings</h3><p class="sub">Click a row for evidence and remediation</p>' +
        '<table class="tbl"><thead><tr><th>ID</th><th>Finding</th><th>Surface</th><th>ATT&CK</th><th>Severity</th><th>Status</th></tr></thead><tbody id="ovFind"></tbody></table></div>';

    var ov = findings.slice(0, 4).map(function (f) {
      return "<tr class='clk' data-f='" + f.id + "'><td>" + f.id + "</td><td>" + f.t +
        "</td><td>" + f.surf + "</td><td><span class='att' style='font-family:JetBrains Mono;font-size:11px;color:var(--gold)'>" + f.att +
        "</span></td><td><span class='tag " + sevClass[f.sev] + "'>" + f.sev +
        "</span></td><td class='st-ok'>Proven</td></tr>";
    }).join("");
    $("#ovFind").innerHTML = ov;

    // Attack surface
    $("#v-surface").innerHTML =
      '<div class="view-head"><span class="eyebrow">Attack surface</span><h1>Connected stack inventory</h1>' +
      '<p>Everything Cherubim discovered when ' + ORG + ' connected its network and stack.</p></div>' +
      '<div class="stat-row">' + statCard("Assets", "1,284", "", "auto discovered") +
        statCard("Internet facing", "97", "", "continuously monitored") +
        statCard("Misconfigured", "23", "down", "tracked to owners") +
        statCard("Surfaces", "7", "", "network to supply chain") + '</div>' +
      '<div class="card-p"><h3>Discovered assets</h3><p class="sub">A representative slice of the live inventory</p>' +
      '<table class="tbl"><thead><tr><th>Asset</th><th>Type</th><th>Surface</th><th>Exposure</th><th>State</th></tr></thead><tbody>' +
      rows(surface) + '</tbody></table></div>';

    // Campaigns
    $("#v-campaigns").innerHTML =
      '<div class="view-head"><span class="eyebrow">Campaigns</span><h1>Engagements</h1>' +
      '<p>Autonomous campaigns across the stack and the human layer. Launch a new one any time.</p></div>' +
      '<div class="card-p"><h3>All campaigns</h3><p class="sub">' + ORG + ' connected environment</p>' +
      '<table class="tbl"><thead><tr><th>ID</th><th>Campaign</th><th>Scope</th><th>Status</th><th>Progress</th><th>Result</th></tr></thead><tbody id="cmpBody">' +
      campaigns.map(function (c) {
        var st = c[3] === "Running" ? "st-run" : "st-ok";
        return "<tr><td>" + c[0] + "</td><td>" + c[1] + "</td><td>" + c[2] +
          "</td><td class='" + st + "'>" + c[3] + "</td><td>" + c[4] + "</td><td>" + c[5] + "</td></tr>";
      }).join("") + '</tbody></table></div>';

    // Attack paths
    $("#v-paths").innerHTML =
      '<div class="view-head"><span class="eyebrow">Attack paths</span><h1>Proven attack path</h1>' +
      '<p>One continuous kill chain from an exposed edge to customer data. Reproduced and validated, not theoretical.</p></div>' +
      '<div class="card-p"><h3>Edge to impact</h3><p class="sub">CMP-2041  Full stack assumed breach  Reproduced 3 times</p><div class="path">' +
      pathNodes.map(function (n) {
        return '<div class="node"><div class="ring">' + n[0] + '</div><div><h4>' + n[1] + " &middot; " + n[2] +
          '</h4><p>' + n[3] + '</p></div><div class="att">PROVEN</div></div>';
      }).join("") + '</div></div>';

    // Findings
    $("#v-findings").innerHTML =
      '<div class="view-head"><span class="eyebrow">Findings</span><h1>Validated findings</h1>' +
      '<p>Every finding here was reproduced by a deterministic validator. No proof, no finding.</p></div>' +
      '<div class="chips" id="sevChips">' +
        ['All', 'Critical', 'High'].map(function (s, i) {
          return "<span class='chip" + (i === 0 ? " on" : "") + "' data-s='" + s + "'>" + s + "</span>";
        }).join("") + '</div>' +
      '<div class="card-p"><table class="tbl"><thead><tr><th>ID</th><th>Finding</th><th>Surface</th><th>ATT&CK</th><th>Severity</th><th>Status</th></tr></thead><tbody id="findBody"></tbody></table></div>';
    renderFindings("All");

    // Social
    $("#v-social").innerHTML =
      '<div class="view-head"><span class="eyebrow">Social engineering</span><h1>Omnichannel campaign</h1>' +
      '<p>CMP-2044, orchestrated across every channel a real attacker would use, with one consistent narrative.</p></div>' +
      '<div class="stat-row">' + statCard("Targets", "722", "", "scoped roster") +
        statCard("Engaged", "29%", "down", "across all channels") +
        statCard("Reported", "38%", "up", "improving vs last run") +
        statCard("Channels", "6", "", "email to live deepfake") + '</div>' +
      '<div class="card-p"><h3>Channel performance</h3><p class="sub">Engagement and report rates by channel</p>' +
      '<table class="tbl"><thead><tr><th>Channel</th><th>Targets</th><th>Engaged</th><th>Credentialed</th><th>Notable</th></tr></thead><tbody>' +
      rows(social) + '</tbody></table></div>';

    // Compliance
    $("#v-compliance").innerHTML =
      '<div class="view-head"><span class="eyebrow">Compliance</span><h1>Framework coverage</h1>' +
      '<p>Findings mapped in real time to the frameworks ' + ORG + ' is held to. One click exports the evidence pack.</p></div>' +
      '<div style="margin-bottom:20px"><button class="btn-mini" id="auditBtn">Generate one click audit pack</button></div>' +
      '<div class="heat">' + frameworks.map(function (f) {
        return "<div class='hcell " + f[2] + "'><div class='nm'>" + f[0] + "</div><div class='pct'>" +
          f[1] + "%</div><div class='lbl'>control coverage</div></div>";
      }).join("") + '</div>';

    // Executive report
    $("#v-report").innerHTML =
      '<div class="view-head"><span class="eyebrow">Executive reporting</span><h1>Board pack</h1>' +
      '<p>One truth, told the way each room needs to hear it. Generated from the same campaign that proved the findings.</p></div>' +
      '<div style="margin-bottom:20px"><button class="btn-mini" id="expBtn">Export board pack</button> ' +
      '<button class="btn-mini ghost" id="expAudit">Export auditor evidence</button></div>' +
      '<div class="grid-2 even"><div class="card-p"><h3>Posture and risk</h3><p class="sub">Defensible numbers with evidence behind them</p>' +
        kv("Posture score", "72 / 100", 72) + kv("Residual critical risk", "Trending down", 22) +
        kv("Mean time to validated proof", "28 min", 88) + kv("Remediation rate", "76%", 76) + '</div>' +
      '<div class="card-p"><h3>What the board needs to decide</h3><p class="sub">Tied to owners and impact</p>' +
        '<table class="tbl"><tbody>' +
        '<tr><td>Isolate Jenkins, rotate svc_ci</td><td class="st-bad">Critical</td><td>Platform</td></tr>' +
        '<tr><td>Block public access on statement store</td><td class="st-bad">Critical</td><td>Cloud</td></tr>' +
        '<tr><td>Settlement invariant checks</td><td class="st-bad">Critical</td><td>Payments</td></tr>' +
        '<tr><td>Phishing resistant MFA rollout</td><td class="st-run">High</td><td>IT Security</td></tr>' +
        '</tbody></table></div></div>';

    bindRows();
    if ($("#auditBtn")) $("#auditBtn").onclick = function () {
      toast("Audit pack generated", "Evidence mapped to 9 frameworks. Auditor ready export prepared.");
    };
    if ($("#expBtn")) $("#expBtn").onclick = function () {
      toast("Board pack exported", "One page narrative with owners and decisions is ready.");
      fakeDownload("cherubim-board-pack.txt", "Cherubim board pack for " + ORG + "\\nPosture 72/100. 4 critical findings, all proven.\\nGenerated from CMP-2041.");
    };
    if ($("#expAudit")) $("#expAudit").onclick = function () {
      toast("Auditor evidence exported", "Proofs, chain of custody, and control mapping bundled.");
    };
  }

  function statCard(k, v, dir, d) {
    return '<div class="stat"><div class="k">' + k + '</div><div class="v">' + v +
      '</div><div class="d ' + (dir || "") + '">' + (d || "") + '</div></div>';
  }
  function surfBar(n, p) {
    return '<div class="kv"><span>' + n + '</span><b>' + p + '</b></div><div class="bar"><i style="width:' + p + '%"></i></div>';
  }
  function kv(n, v, p) {
    return '<div class="kv"><span>' + n + '</span><b>' + v + '</b></div><div class="bar"><i style="width:' + p + '%"></i></div>';
  }

  function renderFindings(filter) {
    var list = filter === "All" ? findings : findings.filter(function (f) { return f.sev === filter; });
    $("#findBody").innerHTML = list.map(function (f) {
      return "<tr class='clk' data-f='" + f.id + "'><td>" + f.id + "</td><td>" + f.t +
        "</td><td>" + f.surf + "</td><td style='font-family:JetBrains Mono;font-size:11px;color:var(--gold)'>" + f.att +
        "</td><td><span class='tag " + sevClass[f.sev] + "'>" + f.sev + "</span></td><td class='st-ok'>Proven</td></tr>";
    }).join("");
    bindRows();
  }

  function bindRows() {
    document.querySelectorAll("tr.clk").forEach(function (tr) {
      tr.onclick = function () { openDrawer(tr.getAttribute("data-f")); };
    });
    var chips = $("#sevChips");
    if (chips) chips.querySelectorAll(".chip").forEach(function (c) {
      c.onclick = function () {
        chips.querySelectorAll(".chip").forEach(function (x) { x.classList.remove("on"); });
        c.classList.add("on"); renderFindings(c.getAttribute("data-s"));
      };
    });
  }

  // ---------------- DRAWER ----------------
  function openDrawer(id) {
    var f = findings.filter(function (x) { return x.id === id; })[0];
    if (!f) return;
    $("#drawerBody").innerHTML =
      '<button class="x" id="drawerX">&times;</button>' +
      '<span class="eyebrow mono" style="color:var(--gold);font-size:11px;letter-spacing:.16em">[ ' + f.id + ' ]</span>' +
      '<h3>' + f.t + '</h3>' +
      '<div class="meta"><span class="tag ' + sevClass[f.sev] + '">' + f.sev +
        '</span><span class="tag sev-low">' + f.surf + '</span><span class="tag sev-med">' + f.att +
        '</span><span class="tag" style="border:1px solid var(--line);color:#3FB984">PROVEN</span></div>' +
      '<h5>Summary</h5><p>' + f.d + '</p>' +
      '<h5>Validated proof of concept</h5><div class="code">' + f.poc + '</div>' +
      '<h5>Remediation</h5><p>' + f.fix + '</p>' +
      '<h5>Evidence</h5><p>Sandbox recording, request and response capture, and chain of custody timestamps are attached to the evidence pack. Mapped to NIST CSF 2.0, the Singapore Cybersecurity Act, and the CSA Cyber Trust mark.</p>';
    $("#scrim").classList.add("open");
    $("#drawer").classList.add("open");
    $("#drawerX").onclick = closeDrawer;
  }
  function closeDrawer() {
    $("#scrim").classList.remove("open");
    $("#drawer").classList.remove("open");
  }

  // ---------------- LAUNCH CAMPAIGN ----------------
  var launchSteps = [
    "agent.recon  mapping connected stack",
    "agent.network  enumerating internal subnets",
    "agent.cloud  auditing AWS and EKS roles",
    "agent.identity  probing Active Directory",
    "agent.web  testing application business logic",
    "validator  reproducing candidate findings",
    "compliance.map  tagging to frameworks",
    "report.engine  assembling evidence pack"
  ];

  function launchModal() {
    $("#modalScrim").classList.add("open");
    var log = $("#runLog"), prog = $("#runProg"), bar = $("#runBar"), go = $("#runGo");
    log.innerHTML = ""; prog.classList.remove("show"); bar.style.width = "0%";
    go.disabled = false; go.textContent = "Launch campaign";
    go.onclick = function () {
      go.disabled = true; go.textContent = "Running";
      prog.classList.add("show");
      var i = 0;
      var iv = setInterval(function () {
        if (i < launchSteps.length) {
          var line = document.createElement("div");
          line.innerHTML = "<span class='ok'>[ok]</span> " + launchSteps[i];
          log.appendChild(line); log.scrollTop = log.scrollHeight;
          bar.style.width = Math.round(((i + 1) / launchSteps.length) * 100) + "%";
          i++;
        } else {
          clearInterval(iv);
          var cid = "CMP-" + (2045 + Math.floor(Math.random() * 9));
          campaigns.unshift([cid, "Full stack assumed breach", "Network, Cloud, Identity", "Completed", "100%", "2 high  1 critical"]);
          stats.findings += 3; stats.critical += 1;
          findings.unshift({
            id: "F-33" + (10 + Math.floor(Math.random() * 80)), t: "Over scoped CI token enables lateral movement",
            sev: "Critical", surf: "Supply chain", att: "T1078 / T1552",
            d: "A long lived CI token discovered during this campaign grants write access across three production namespaces.",
            poc: "$ curl -H 'Authorization: Bearer <span class='g'>[recovered]</span>' ...\n<span class='ok'>[+] Cross namespace write proven in sandbox.</span>",
            fix: "Short lived OIDC tokens, scope per pipeline, rotate and alert on token reuse."
          });
          setTimeout(function () {
            $("#modalScrim").classList.remove("open");
            toast("Campaign " + cid + " complete", "1 critical and 2 high findings proven and mapped to your frameworks.");
            render(); route(location.hash || "#/overview");
          }, 700);
        }
      }, 520);
    };
  }

  // ---------------- ROUTER ----------------
  var views = ["overview", "surface", "campaigns", "paths", "findings", "social", "compliance", "report"];
  function route(hash) {
    var key = (hash || "").replace("#/", "") || "overview";
    if (views.indexOf(key) < 0) key = "overview";
    views.forEach(function (v) {
      $("#v-" + v).classList.toggle("active", v === key);
    });
    document.querySelectorAll(".nav-item").forEach(function (n) {
      n.classList.toggle("active", n.getAttribute("data-r") === key);
    });
    $("#side") && $("#side").classList.remove("open");
    if (key === "overview") startTicker();
    window.scrollTo(0, 0);
  }

  // ---------------- TICKER ----------------
  var tickerIv;
  function startTicker() {
    var box = $("#ticker");
    if (!box) return;
    clearInterval(tickerIv);
    box.innerHTML = "";
    var i = 0;
    function add() {
      var t = new Date(Date.now() - (10 - (i % 10)) * 3000)
        .toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      var ln = document.createElement("div");
      ln.className = "ln";
      ln.innerHTML = "<span class='t'>" + t + "</span><b>" + activity[i % activity.length] + "</b>";
      box.insertBefore(ln, box.firstChild);
      while (box.children.length > 9) box.removeChild(box.lastChild);
      i++;
    }
    for (var k = 0; k < 7; k++) add();
    tickerIv = setInterval(add, 3200);
  }

  // ---------------- INIT ----------------
  document.addEventListener("DOMContentLoaded", function () {
    render();
    route(location.hash);
    window.addEventListener("hashchange", function () { route(location.hash); });

    document.querySelectorAll(".nav-item").forEach(function (n) {
      n.onclick = function () { location.hash = "#/" + n.getAttribute("data-r"); };
    });
    $("#scrim").onclick = closeDrawer;
    $("#launchBtn").onclick = launchModal;
    $("#launchBtn2") && ($("#launchBtn2").onclick = launchModal);
    $("#modalScrim").onclick = function (e) {
      if (e.target === $("#modalScrim")) $("#modalScrim").classList.remove("open");
    };
    $("#modalX").onclick = function () { $("#modalScrim").classList.remove("open"); };
    $("#logout").onclick = function () {
      try { sessionStorage.removeItem("cherubim_demo"); } catch (e) {}
      location.href = "../login.html";
    };
    var mb = $("#menuBtn");
    if (mb) mb.onclick = function () { $("#side").classList.toggle("open"); };
  });

  function fakeDownload(name, text) {
    try {
      var a = document.createElement("a");
      a.href = "data:text/plain;charset=utf-8," + encodeURIComponent(text.replace(/\\n/g, "\n"));
      a.download = name; a.click();
    } catch (e) {}
  }
})();
