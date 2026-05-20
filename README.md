# Cherubim

Marketing site for **Cherubim**, the flagship autonomous adversary platform by
Hesed &amp; Emet Advisory.

Cherubim unifies three attack surfaces in one authorized, evidence graded
campaign:

1. **Autonomous Offensive Engine** &mdash; a swarm of reasoning agents that
   exploits and chains weaknesses across web, API, cloud, and identity, with
   deterministic validation so no finding ships without proof.
2. **Full Stack Attack Coverage** &mdash; agentic AI automated penetration
   testing across network, web, API, mobile, cloud, Kubernetes, identity,
   Active Directory, wireless, OT, and supply chain, run as one continuous
   kill chain rather than disconnected reports.
3. **Orchestrated Omnichannel Social Engineering** &mdash; coordinated phishing,
   smishing, WhatsApp, voice cloning, live deepfake video on Zoom, Teams, and
   Meet, plus Slack and Teams follow up, driven by a narrative state engine.

Findings are delivered with truth for the board and kindness for the people who
were tested, the principle behind the Hesed (mercy) and Emet (truth) name.

**Compliance and reporting.** Every validated finding is mapped in real time to
NIST CSF 2.0 and SP 800-53, the Singapore Cybersecurity Act, the CSA Cyber
Trust and Cyber Essentials marks, ISO/IEC 27001, MAS TRM, PDPA, MITRE ATT&CK,
and CIS Controls, then assembled into a one click auditor ready evidence pack.
Executive reporting produces board, CISO, engineering, and audit views from one
source of truth.

## Stack

Static site, no build step. Served at https://cherubim.hesedemet.asia

- `index.html` &mdash; marketing single page
- `login.html` &mdash; console sign in
- `console/` &mdash; the operating console
- `assets/css/styles.css` &mdash; brand system and layout
- `assets/js/main.js` &mdash; mobile nav and scroll reveal
- `assets/js/i18n.js` &mdash; language switcher (EN, zh-Hans, zh-Hant, ko)
- `assets/img/favicon.svg` &mdash; mark

## Run locally

Open `index.html` directly, or serve the folder:

```
python3 -m http.server
```

Built for authorized adversary simulation only.
