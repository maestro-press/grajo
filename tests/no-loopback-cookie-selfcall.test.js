/**
 * No Crow gateway module may make a loopback/self HTTP request that forwards the dashboard
 * session — tests/no-loopback-cookie-selfcall.test.js
 *
 * Why this exists. The "Restart the browser add-on" Fix-it remedy used to re-POST the
 * owner's own dashboard request to this gateway's own listener on plain-HTTP loopback,
 * carrying the forwarded Cookie and CSRF token. Since the dashboard session cookie became
 * `__Host-crow_session` (HTTPS-only) that self-call went out with the wrong cookie and the
 * route answered 403/302 — it could never work. It is also a hazard in general: a request
 * that carries the owner's session into this gateway's own routes is a second, unaudited
 * way in. The remedy now calls the route's code in process (routes/bundles.js
 * `restartBundleInProcess`), and this scan keeps the pattern from coming back.
 *
 * A heuristic, not a proof — per FILE (no data flow):
 *   (1) it has a request call against a loopback/self target:
 *       fetch( / http.request( / https.request(  AND
 *       127.0.0.1 / localhost / [::1] / selfOrigin / gatewayBackendPort(
 *   (2) it forwards a cookie/session in that neighbourhood:
 *       headers.cookie / headers?.cookie / a `cookie` or "cookie" header key /
 *       x-crow-csrf / csrfToken
 * Both in one file flags it. Being a heuristic, a file that legitimately does both (a
 * proxy forwarding the browser's own cookie upstream, the CSRF fetch wrapper, a client-side
 * template) is listed in ALLOW with the exact path and a one-line reason, so anything NEW
 * fails here instead of shipping. An ALLOW entry that no longer matches also fails, so the
 * list cannot rot.
 *
 * Out of scope: browser code under a `public/` directory, and `client.js` files under
 * `dashboard/` — they run in the browser, where a same-origin fetch with the session is the
 * normal thing. The skip is scoped to `dashboard/` for that reason: a `client.js` anywhere
 * else (servers/gateway/satellites/client.js) is gateway code and is scanned like any other
 * module. `node_modules` is not scanned (third-party code, and not ours to hold to this rule).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const GATEWAY = fileURLToPath(new URL("../servers/gateway", import.meta.url));

/** A request call (case-insensitive: `Fetch(` / `HTTP.request(` are the same call). */
const REQUEST_CALL = /fetch\(|http\.request\(|https\.request\(/i;
/** A loopback or self-dial target. */
const LOOPBACK_SELF = /127\.0\.0\.1|localhost|\[::1\]|selfOrigin|gatewayBackendPort\(/i;
/** A cookie or CSRF token being put on a request (any capitalisation of `Cookie` too). */
const COOKIE_FORWARD = /headers\.cookie|headers\?\.cookie|\bcookie\s*:|["']cookie["']\s*:|x-crow-csrf|csrfToken|headers\s*:\s*\{[^}]*\bcookie\b/is;

/**
 * Files that legitimately have BOTH a loopback/self request and a cookie in them, with the
 * reason. Exact gateway-relative path → why it is not the pattern this test forbids.
 */
const ALLOW = new Map([
  ["dashboard/auth.js", "the only outbound request is the hosted-mode lockout alert to CROW_HOSTING_API_URL; `localhost`/`[::1]` appear in host classification and `req.headers.cookie` is the INCOMING jar — nothing is called on loopback"],
  ["first-admin/vaultwarden-invite.js", "talks to the Vaultwarden container on 127.0.0.1 and carries that app's OWN admin session (VW_ADMIN) back to it — never a Crow dashboard session"],
  ["dashboard/index.js", "no loopback request at all: `localhost` appears only in a comment about the first-run login, and `csrfToken` is a value handed to a page render"],
  ["routes/extension-proxy.js", "the /proxy/<id> reverse proxy: its one loopback target is the app's own backend and Crow's session/CSRF cookies are STRIPPED before the request leaves (stripCrowCookiesForBackend) — the `fetch()` and `X-Crow-Csrf` it matches are prose in its comments"],
  ["routes/models.js", "no request of its own carries a cookie: `fetch()` and `X-Crow-Csrf` are prose in the module doc, and `localhost` matches only the identifier `requireLocalhost` named there"],
]);

/**
 * Does this source contain a loopback/self request call that carries a cookie/session?
 * Deliberately simple and readable: three text matches in the same file.
 */
export function selfCallForwardsSession(text) {
  return REQUEST_CALL.test(text) && LOOPBACK_SELF.test(text) && COOKIE_FORWARD.test(text);
}

/** Every gateway-relative `.js`/`.mjs` path this scan looks at, sorted. */
function gatewaySources(dir = GATEWAY, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    const rel = relative(GATEWAY, full).split("\\").join("/");
    if (entry.isDirectory()) {
      // Browser code and third-party trees are out of scope (see the header).
      if (entry.name === "public" || entry.name === "node_modules") continue;
      gatewaySources(full, out);
      continue;
    }
    if (!/\.(js|mjs)$/.test(entry.name)) continue;
    // The dashboard's own clients run in the browser: a same-origin fetch there is the norm.
    // The skip is scoped to `dashboard/` on purpose — a `client.js` elsewhere
    // (satellites/client.js) is gateway code and is scanned like any other module.
    if (rel.startsWith("dashboard/") && /(^|\/)client\.js$/.test(rel)) continue;
    out.push(rel);
  }
  return out.sort();
}

/** The gateway-relative paths that trip the heuristic, ignoring the allowlist. */
function flagged(allow = new Set()) {
  const hits = [];
  for (const rel of gatewaySources()) {
    if (allow.has(rel)) continue;
    let text = "";
    try { text = readFileSync(join(GATEWAY, rel), "utf8"); } catch { continue; }
    if (selfCallForwardsSession(text)) hits.push(rel);
  }
  return hits;
}

test("the scan flags a self-call that forwards the session, and leaves clean code alone", () => {
  // The exact shape the remedy used to have: a loopback self-call with the owner's cookie.
  const selfCall = "const res = await fetch(`${selfOrigin()}/dashboard/bundles/api/start`, {\n"
    + "  method: \"POST\",\n  headers: { \"content-type\": \"application/json\", cookie },\n"
    + "});\n";
  assert.equal(selfCallForwardsSession(selfCall), true, "the old remedy's self-call is exactly what this forbids");

  // …and the same call with the CSRF token instead of a cookie, and with the explicit keys.
  assert.equal(selfCallForwardsSession("fetch(`http://127.0.0.1:${port}/x`, { headers: { \"x-crow-csrf\": csrf } })"), true);
  assert.equal(selfCallForwardsSession("http.request({ host: \"localhost\", headers: { \"cookie\": c } })"), true);
  assert.equal(selfCallForwardsSession("fetch(url, { headers: { \"Cookie\": c } })"), false, "no loopback/self target");
  // A capitalised header name is the same header: `headers: { Cookie: x }` on a loopback
  // call is flagged too (the regexes are case-insensitive).
  assert.equal(selfCallForwardsSession("fetch(`http://127.0.0.1:${port}/x`, { headers: { Cookie: session } })"), true, "`headers: { Cookie: x }` on a loopback call is the same pattern");
  assert.equal(selfCallForwardsSession("fetch(`https://api.example.com/x`, { headers: { cookie } })"), false, "not a self-call");
  assert.equal(selfCallForwardsSession("const base = \"http://localhost:11434\";\nconst models = await listModels(base);\n"), false, "a loopback URL alone is not a session-carrying call");
  assert.equal(selfCallForwardsSession("export function readCookie(header) { return header.get(\"cookie\"); }"), false, "cookie text alone is not a call");
});

test("the scan reaches a client.js outside dashboard/, and not the dashboard's own", () => {
  const sources = gatewaySources();
  assert.ok(sources.includes("satellites/client.js"), "gateway code named client.js is scanned");
  assert.ok(
    !sources.some((rel) => rel.startsWith("dashboard/") && /(^|\/)client\.js$/.test(rel)),
    "the dashboard's browser clients stay out of scope",
  );
});

test("no Crow gateway module makes a loopback/self request that carries a cookie", () => {
  const allowPaths = new Set(ALLOW.keys());
  const hits = flagged(allowPaths);
  assert.deepEqual(
    hits,
    [],
    "a gateway module makes a loopback/self HTTP request and forwards a cookie/session in the same file.\n"
      + "Call the route's code in process instead; if this file really must forward the browser's own\n"
      + "cookie, add it to ALLOW with a one-line reason. Files:\n  " + hits.join("\n  "),
  );
});

test("every ALLOW entry still describes a real match (the list cannot rot)", () => {
  const stale = [];
  for (const [rel, reason] of ALLOW) {
    assert.ok(typeof reason === "string" && reason.trim().length > 0, `${rel}: an allowlist entry needs a reason`);
    if (!existsSync(join(GATEWAY, rel))) { stale.push(`${rel}: no such file`); continue; }
    if (!selfCallForwardsSession(readFileSync(join(GATEWAY, rel), "utf8"))) stale.push(`${rel}: no longer matches (drop the entry)`);
  }
  assert.deepEqual(stale, [], `allowlist entries that no longer apply:\n  ${stale.join("\n  ")}`);
});