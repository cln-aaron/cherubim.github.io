/**
 * Cherubim API proxy — Cloudflare Worker
 * ---------------------------------------------------------------------------
 * Hides the upstream API key and the upstream brand from the browser.
 * The portal calls THIS worker; the worker adds the secret Authorization
 * header and forwards to the real API. The key never ships to the client.
 *
 * DEPLOY (takes ~3 minutes, free tier):
 *   1. npm i -g wrangler   &&   wrangler login
 *   2. Put this file at src/worker.js of a new Worker project, or paste it
 *      into the Cloudflare dashboard editor (Workers & Pages → Create → Worker).
 *   3. Set the secret (never hard-code it):
 *        wrangler secret put XLG_KEY
 *      then paste:  xlg_live_...     (your live key)
 *   4. Set ALLOW_ORIGIN as a plain var to your site origin, e.g.
 *        https://cherubim.hesedemet.asia
 *      (dashboard: Settings → Variables, or wrangler.toml [vars]).
 *   5. Deploy:  wrangler deploy    → you get https://<name>.<acct>.workers.dev
 *   6. In assets/js/portal.js set:
 *        PORTAL.base = "https://<name>.<acct>.workers.dev/v1"
 *        PORTAL.key  = ""            // no key in the client any more
 *      (optionally map a custom domain like api.cherubim.hesedemet.asia)
 *
 * The worker only forwards the small set of paths the portal needs and strips
 * the upstream host out of any response body, so nothing downstream leaks.
 */

const UPSTREAM = "https://www.xalgorix.com/api/public/v1";

// Only these upstream paths may be reached through the proxy.
const ALLOW = [
  { method: "POST", re: /^\/v1\/scans$/ },
  { method: "GET",  re: /^\/v1\/scans$/ },      // ?id=...
  { method: "GET",  re: /^\/v1\/findings$/ },   // ?limit=&offset=&order=&scan_id=
  { method: "GET",  re: /^\/v1\/share$/ },      // ?token=...
];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const allowOrigin = env.ALLOW_ORIGIN || "*";
    const cors = {
      "Access-Control-Allow-Origin": allowOrigin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
    };

    // Preflight
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    // Optional origin allow-list (leave ALLOW_ORIGIN as * to skip)
    if (allowOrigin !== "*" && origin && origin !== allowOrigin) {
      return json({ error: "forbidden_origin" }, 403, cors);
    }

    // Path allow-list
    const match = ALLOW.find((a) => a.method === request.method && a.re.test(url.pathname));
    if (!match) return json({ error: "not_found" }, 404, cors);

    // Build upstream request
    const upstreamUrl = UPSTREAM + url.pathname.replace(/^\/v1/, "") + url.search;
    const init = {
      method: request.method,
      headers: {
        "Authorization": "Bearer " + env.XLG_KEY,
        "Content-Type": "application/json",
      },
      body: request.method === "POST" ? await request.text() : undefined,
    };

    let upstream;
    try {
      upstream = await fetch(upstreamUrl, init);
    } catch (e) {
      return json({ error: "upstream_unreachable" }, 502, cors);
    }

    // Strip the upstream host out of the body so nothing leaks downstream.
    let body = await upstream.text();
    body = body.split("https://www.xalgorix.com").join(url.origin)
               .split("xalgorix.com").join(url.host);

    return new Response(body, {
      status: upstream.status,
      headers: { ...cors, "Content-Type": "application/json" },
    });
  },
};

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });
}
