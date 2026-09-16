# Cherubim API proxy (optional, recommended)

The portal talks to a backend scanning API. On a static site (GitHub Pages)
there is no server, so by default the API key ships inside
`assets/js/portal.js` and anyone can read it from view-source. That is fine for
a quick demo, but not for a public production site — someone could copy the key
and spend your credits or scan arbitrary targets.

This folder holds a tiny **Cloudflare Worker** that fixes that. The browser
calls the Worker, the Worker adds the secret key and forwards to the real API.
The key and the upstream brand never reach the client.

## Why a Worker

- Free tier is plenty (100k requests/day).
- No servers to run, deploys in a few minutes.
- Same-shape JSON, so the portal code barely changes.

Vercel/Netlify functions work the same way if you prefer them; the logic in
`cloudflare-worker.js` ports directly.

## Deploy (about 3 minutes)

```bash
npm i -g wrangler
wrangler login

# create a project, drop cloudflare-worker.js in as src/worker.js
wrangler secret put XLG_KEY        # paste your xlg_live_... key when prompted
# set an allowed origin (Settings → Variables, or wrangler.toml [vars]):
#   ALLOW_ORIGIN = https://cherubim.hesedemet.asia
wrangler deploy                    # → https://<name>.<account>.workers.dev
```

You can also paste the file straight into the Cloudflare dashboard
(**Workers & Pages → Create → Worker**), then add the `XLG_KEY` secret and
`ALLOW_ORIGIN` variable under the Worker's **Settings → Variables**.

## Point the portal at the proxy

In `assets/js/portal.js`:

```js
var PORTAL = {
  base: "https://<name>.<account>.workers.dev/v1",  // your Worker
  key: "",                                          // no key in the client
  pollMs: 6000
};
```

That's it. The Worker only forwards the four paths the portal uses
(`/scans` POST + GET, `/findings`, `/share`), rejects everything else, and
strips the upstream hostname out of every response, so no backend detail is
exposed to the browser. Rotate the key any time with
`wrangler secret put XLG_KEY` — no site redeploy needed.
