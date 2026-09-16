# Cherubim

Marketing site and live console for **Cherubim**, autonomous AI penetration
testing by Hesed &amp; Emet Advisory.

Cherubim points at an application, runs a full 22-phase pentest, and proves
every finding with a working exploit before it reaches your report. No proof,
no finding.

## What it does

1. **Exploit verification** &mdash; each candidate vulnerability is reproduced
   in an isolated sandbox and attached to the finding as a proof of concept.
   Findings that can't be reproduced are never reported.
2. **22-phase methodology** &mdash; reconnaissance through reporting, covering
   injection, XSS, SSRF, IDOR and access control, API testing, file uploads,
   cloud and infrastructure, and more.
3. **Live observability** &mdash; a real-time view of tool calls, agent
   reasoning, HTTP activity, phase transitions, and findings as they land.
4. **Integrations** &mdash; REST API, GitHub app, CI/CD severity gating,
   scheduled scans, and an open-source CLI.
5. **Reports** &mdash; branded output with executive summary, severity
   breakdown, proof of concept, and remediation, plus signed share links.

## Stack

Static site, no build step. Served at https://cherubim.hesedemet.asia

- `index.html` &mdash; marketing single page
- `login.html` &mdash; console sign in (hash-gated)
- `console/` &mdash; the live pentest portal
- `assets/js/portal.js` &mdash; the portal; calls the scanning API and streams results
- `assets/js/main.js` &mdash; marketing page interactions
- `assets/js/auth.js` &mdash; sign in
- `proxy/` &mdash; optional Cloudflare Worker that hides the API key server-side

## The scanning backend

The console calls a scanning API directly from the browser. Configuration lives
in one place at the top of `assets/js/portal.js` (`PORTAL.base` and
`PORTAL.key`).

**Because this is a static site, the API key in `portal.js` is visible in
view-source.** That is fine for a demo but not for a public production site. To
hide the key, deploy the Cloudflare Worker in `proxy/` (about 3 minutes, free
tier) and point `PORTAL.base` at it with `PORTAL.key = ""`. See
`proxy/README.md`.

## Run locally

```
python3 -m http.server
```

Then open http://localhost:8000/. Sign in leads to the console.

Built for authorized security testing only.
