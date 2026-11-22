// Crow Mail plan 5, Task 4b: the OAuth wizard's routes and the callback
// (servers/gateway/routes/mail-api-oauth.js), registered from the mail API router.
//
// Harness: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR / CROW_HOME in a temp dir,
// so nothing can touch ~/.crow), an ephemeral express app wired the way the dashboard mounts the mail
// router (the dashboard's real CSRF middleware, then the router, with a session stub in place of
// dashboardAuth), the real account store, the real sealed keychain reader, the real flow store, an
// in-memory fake mail adapter and a recording supervisor. The OAuth provider is the local fake in
// tests/fixtures/fake-oauth-provider.mjs, reached through the loopback-only `endpoints` override, so
// nothing here touches the internet. No address at a personal mail domain appears: the preset fallback
// is exercised through example.test, whose provider hosts come from the provider's own preset.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";

const root = mkdtempSync(join(tmpdir(), "mail-oauth-routes-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { default: express } = await import("express");
const { createDbClient } = await import("../servers/db.js");
const { csrfMiddleware, csrfTokenForSession } = await import("../servers/gateway/dashboard/shared/csrf.js");
const { mailApiRouter, clearMailApiRuntime, MAIL_API_PREFIX } = await import("../servers/gateway/routes/mail-api.js");
const {
  MAIL_OAUTH_CALLBACK_PATH,
  MAIL_OAUTH_HINT_KEYS,
  MAIL_OAUTH_STATUS_KEYS,
} = await import("../servers/gateway/routes/mail-api-oauth.js");
const { MailError } = await import("../servers/gateway/mail/errors.js");
const { createMailCredentials } = await import("../servers/gateway/mail/credentials.js");
const { createFlowStore } = await import("../servers/gateway/mail/oauth/state.js");
const { getOauthMeta } = await import("../servers/gateway/mail/oauth/meta.js");
const { createAccount, getAccount, listAccounts } = await import("../servers/gateway/mail/store/accounts.js");
const { upsertFolders } = await import("../servers/gateway/mail/store/messages.js");
const { checkClaim } = await import("../servers/gateway/mail/claims.js");
const { createFakeMailAdapter } = await import("./fixtures/fake-mail-adapter.mjs");
const { startFakeOAuthProvider } = await import("./fixtures/fake-oauth-provider.mjs");

const OWNER = "owner-local-password-session";
const SECOND = "second-owner-session";
const ADDRESS = "alex@example.test";
const OTHER_ADDRESS = "sam@example.test";
const LABEL = "Personal";
const CLIENT_SECRET = "client-secret-9d3c51aa";
const GOOGLE_CLIENT_ID = "123456789012-crowmailtest.apps.googleusercontent.com";
const MICROSOFT_CLIENT_ID = "8b1c7f4e-2a3d-4c5b-9e6f-0a1b2c3d4e5f";
const CODE = "auth-code-7c1e2d90";
const REFRESH_TOKEN = "fake-refresh-token";
const ACCESS_TOKEN = "fake-access-token";
const OLD_REFRESH_TOKEN = "refresh-token-old-5a2b";

const DASHBOARD = "https://crow.example.test";
const REDIRECT_URI = `${DASHBOARD}${MAIL_OAUTH_CALLBACK_PATH}`;

const IMAP = { host: "mail.example.test", port: 993, security: "ssl" };
const SMTP = { host: "mail.example.test", port: 465, security: "ssl" };

const open = [];
const servers = [];
const fakes = [];

after(async () => {
  clearMailApiRuntime();
  for (const s of servers) s.close();
  for (const fake of fakes) await fake.close();
  for (const c of open) { try { c.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
});

beforeEach(() => {
  clearMailApiRuntime();
  process.env.CROW_MAIL = "1";
  // A configured dashboard address: the redirect URI every flow in this file is minted against. The
  // branch with no address deletes these itself.
  process.env.CROW_GATEWAY_URL = DASHBOARD;
  delete process.env.CROW_OAUTH_ISSUER_URL;
  delete process.env.RENDER_EXTERNAL_URL;
});

const flush = (rounds = 40) => (async () => {
  for (let i = 0; i < rounds; i += 1) await new Promise((r) => setImmediate(r));
})();

/* ------------------------------------------------------------------ HTTP */

function parseCookies(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

let server = null;

/** One request. `token: null` sends no session cookie; `csrf: null` sends no CSRF header. */
function call(method, path, { body, headers = {}, token = OWNER, csrf = token ? csrfTokenForSession(token) : null } = {}) {
  const payload = body === undefined ? null : (typeof body === "string" ? body : JSON.stringify(body));
  const h = { ...(payload === null ? {} : { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }) };
  if (token) h.cookie = "crow_session=" + token;
  if (token && csrf) h["x-crow-csrf"] = csrf;
  Object.assign(h, headers);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: server.address().port, method, path, headers: h }, (res) => {
      let text = "";
      res.on("data", (c) => { text += c; });
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, location: res.headers.location, text, json });
      });
    });
    req.on("error", reject);
    req.end(payload === null ? undefined : payload);
  });
}

const get = (path, opts) => call("GET", path, opts);
const post = (path, body, opts) => call("POST", path, { body, ...opts });

const redirectUriPath = `${MAIL_API_PREFIX}/oauth/redirect-uri`;
const checkPath = `${MAIL_API_PREFIX}/oauth/check`;
const startPath = `${MAIL_API_PREFIX}/oauth/start`;
const selftestPath = (id) => `${MAIL_API_PREFIX}/accounts/${id}/selftest`;
const callbackPath = (query) => `${MAIL_OAUTH_CALLBACK_PATH}${query ? `?${query}` : ""}`;

/** Capture console.warn while `fn` runs: a log line must carry no value. */
async function warnings(fn) {
  const lines = [];
  const original = console.warn;
  console.warn = (...args) => { lines.push(args.map((a) => String(a)).join(" ")); };
  try {
    return { lines, result: await fn() };
  } finally {
    console.warn = original;
  }
}

/* ----------------------------------------------------------------- setup */

let n = 0;

/**
 * The flow store with a spy around it: `calls` counts `begin` and `take` (so a refused callback proves
 * `take` never ran) and `size()` still reports the real store's entries.
 */
function recordingStore({ now = Date.now, ttlMs, perSessionCap } = {}) {
  const options = { now };
  if (ttlMs !== undefined) options.ttlMs = ttlMs;
  if (perSessionCap !== undefined) options.perSessionCap = perSessionCap;
  const inner = createFlowStore(options);
  const calls = { begin: 0, take: 0 };
  return {
    calls,
    inner,
    begin(args) { calls.begin += 1; return inner.begin(args); },
    take(state, sessionId) { calls.take += 1; return inner.take(state, sessionId); },
    size() { return inner.size(); },
  };
}

async function fakeProvider() {
  const fake = await startFakeOAuthProvider();
  fakes.push(fake);
  return fake;
}

/**
 * One test's world: a fresh copy of the schema, the real keychain reader over its own client, a fake
 * mail adapter behind the OAuth probe factory, a recording supervisor, an in-memory masking recorder
 * and a flow store with a spy. `deps` is exactly what `mailApiRouter` takes.
 */
async function setup(options = {}) {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");

  const db = createDbClient(crow);
  const credDb = createDbClient(crow);
  open.push(db, credDb);
  const credentials = options.credentials ?? createMailCredentials({ db: credDb, crowHome: process.env.CROW_HOME });

  const supervisorCalls = [];
  const supervisor = options.supervisor !== undefined
    ? options.supervisor
    : {
      async syncNow(id) { supervisorCalls.push(["syncNow", id]); },
      async restartAccount(id) { supervisorCalls.push(["restartAccount", id]); },
    };

  const probeCalls = [];
  const adapters = [];
  const oauthAdapterFactory = options.oauthAdapterFactory ?? ((args) => {
    probeCalls.push(args);
    const adapter = createFakeMailAdapter();
    adapters.push(adapter);
    return adapter;
  });

  const recorded = [];
  const forgets = [];
  const registryAsks = [];
  const flowStore = options.flowStore ?? recordingStore();

  const deps = {
    openDb: () => createDbClient(crow),
    credentials,
    supervisor,
    localInstance: { instanceId: "instA", instanceName: "Delta" },
    recordSecrets: options.recordSecrets ?? ((values) => { recorded.push(values); }),
    ownerCheck: options.ownerCheck ?? (async () => true),
    oauthAdapterFactory,
    fetchImpl: fetch,
    ...(options.endpoints ? { endpoints: options.endpoints } : {}),
    ...(options.forgetTokenProvider
      ? { forgetTokenProvider: options.forgetTokenProvider }
      : { forgetTokenProvider: (id) => { forgets.push(id); } }),
    ...(options.tokenProviderFor ? { tokenProviderFor: (id) => { registryAsks.push(id); return null; } } : {}),
    flowStore,
  };

  // The dashboard's own session rail, stubbed at the same point the dashboard installs dashboardAuth:
  // it sets `req.dashboardSession` for the private API prefix. A request with no cookie gets a 401 from
  // it (the callback is NOT under that prefix, so its own guard is what a session-less callback meets).
  const sessionGate = (req, res, next) => {
    const token = parseCookies(req.headers.cookie).crow_session;
    if (!token) return res.status(401).json({ error: "unauthorized" });
    req.dashboardSession = token;
    next();
  };

  const app = express();
  app.use("/dashboard", csrfMiddleware);
  app.use(mailApiRouter(sessionGate, deps));

  server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);

  const keychainRows = async (accountId) => (await db.execute({
    sql: "SELECT env_key FROM crow_keychain WHERE connection_uuid = ? ORDER BY env_key",
    args: [accountId],
  })).rows.map((row) => row.env_key);

  return { db, crow, credentials, deps, flowStore, supervisorCalls, supervisor, probeCalls, adapters, recorded, forgets, registryAsks, keychainRows };
}

/** A Google start body (the fields a wizard sends for the OAuth path). */
const START_BODY = {
  provider: "google",
  address: ADDRESS,
  label: LABEL,
  clientId: GOOGLE_CLIENT_ID,
  clientSecret: CLIENT_SECRET,
};

/** POST /oauth/start and read the state back out of the authorization URL. */
async function begin(opts = {}, overrides = {}) {
  const r = await post(startPath, { ...START_BODY, ...overrides }, opts);
  let state = null;
  if (r.status === 200 && r.json?.authUrl) state = new URL(r.json.authUrl).searchParams.get("state");
  return { ...r, state };
}

/** A signed-in callback for one state. */
const callback = (state, opts = {}) => get(callbackPath(`code=${encodeURIComponent(CODE)}&state=${encodeURIComponent(state)}`), opts);

/** The status key a callback redirect carries. */
function statusOf(r) {
  assert.equal(r.status, 302, r.text);
  const url = new URL(r.location, DASHBOARD);
  assert.equal(url.pathname + url.search.split("&mailStatus=")[0], "/dashboard/mail?view=settings");
  return url.searchParams.get("mailStatus");
}

/* ------------------------------------------------------------- the flag */

test("with CROW_MAIL unset every route is a 404, the callback included and before any session check", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl } });
  process.env.CROW_MAIL = "0";
  delete process.env.CROW_MAIL;
  try {
    for (const [what, r] of [
      ["redirect-uri", await get(redirectUriPath)],
      ["check", await post(checkPath, { step: "client_id", provider: "google", clientId: GOOGLE_CLIENT_ID })],
      ["start", await post(startPath, START_BODY)],
      ["selftest", await post(selftestPath("ma-0123456789abcdef"), {})],
      ["callback", await get(callbackPath("code=x&state=y"), { token: null })],
    ]) {
      assert.equal(r.status, 404, `${what}: ${r.text}`);
      assert.deepEqual(r.json, { error: "not_found", message: "Not found." }, what);
      assert.equal(r.text.includes(ADDRESS), false, what);
    }
    assert.equal(w.flowStore.calls.begin, 0, "no flow was minted");
    assert.equal(w.flowStore.calls.take, 0, "and none was spent");
  } finally {
    process.env.CROW_MAIL = "1";
  }
});

/* ------------------------------------------------------------ redirect-uri */

test("GET /oauth/redirect-uri answers this instance's own callback address", async () => {
  const w = await setup();
  const r = await get(redirectUriPath);
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json, { redirectUri: REDIRECT_URI });
  assert.equal(r.headers["cache-control"], "no-store", "a configuration read is never cached");

  // The other branch: no dashboard address configured (the issuer degrades to localhost, which no
  // provider can redirect a browser to).
  delete process.env.CROW_GATEWAY_URL;
  delete process.env.CROW_OAUTH_ISSUER_URL;
  delete process.env.RENDER_EXTERNAL_URL;
  const none = await get(redirectUriPath);
  assert.equal(none.status, 200, none.text);
  assert.deepEqual(none.json, { redirectUri: null, reason: "no_dashboard_address" });
  assert.equal(none.text.includes("localhost"), false, "no localhost address is offered as a redirect");
  assert.equal(w.flowStore.calls.begin, 0);
});

test("a wizard opened over Tailscale Funnel is told there is no dashboard address OAuth can use", async () => {
  const w = await setup();
  // The gateway's own marker on a request that arrived through Funnel. The callback path is refused for
  // a funneled request by this same module's guard, so a redirect URI on that origin can never complete:
  // the wizard hides the OAuth path instead of sending the person to a provider that cannot come back.
  const funnel = { headers: { "tailscale-funnel-request": "1" } };

  const r = await get(redirectUriPath, funnel);
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json, { redirectUri: null, reason: "no_dashboard_address" });

  const step = await post(checkPath, { step: "redirect", provider: "google", pastedRedirectUri: REDIRECT_URI }, funnel);
  assert.deepEqual(step.json, { ok: false, hint: "no_dashboard_address" });

  const started = await post(startPath, START_BODY, funnel);
  assert.equal(started.status, 409, started.text);
  assert.equal(started.json.error, "no_dashboard_address");
  assert.equal(w.flowStore.calls.begin, 0, "no flow was minted for a Funnel-served wizard");

  // The same requests without the marker still answer the real callback address.
  assert.deepEqual((await get(redirectUriPath)).json, { redirectUri: REDIRECT_URI });
  assert.equal((await begin()).status, 200);
});

test("POST /oauth/start refuses with no_dashboard_address when this machine has none", async () => {
  const w = await setup();
  delete process.env.CROW_GATEWAY_URL;
  delete process.env.CROW_OAUTH_ISSUER_URL;
  delete process.env.RENDER_EXTERNAL_URL;
  const r = await post(startPath, START_BODY);
  assert.equal(r.status, 409, r.text);
  assert.equal(r.json.error, "no_dashboard_address");
  assert.equal(r.json.message, "Set this machine's dashboard address first.");
  assert.equal(w.flowStore.calls.begin, 0, "no flow was minted");
});

/* ----------------------------------------------------------------- check */

test("POST /oauth/check maps each step to a fixed hint key and nothing else", async () => {
  await setup();

  const good = await post(checkPath, { step: "client_id", provider: "google", clientId: GOOGLE_CLIENT_ID });
  assert.equal(good.status, 200, good.text);
  assert.deepEqual(good.json, { ok: true, hint: null });
  assert.deepEqual(Object.keys(good.json).sort(), ["hint", "ok"]);

  for (const clientId of ["not-a-google-id", "x.apps.googleusercontent.com.evil.test", "  ", 42]) {
    const r = await post(checkPath, { step: "client_id", provider: "google", clientId });
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.json, { ok: false, hint: "client_id_shape" });
  }
  const ms = await post(checkPath, { step: "client_id", provider: "microsoft", clientId: MICROSOFT_CLIENT_ID });
  assert.deepEqual(ms.json, { ok: true, hint: null });
  const msBad = await post(checkPath, { step: "client_id", provider: "microsoft", clientId: GOOGLE_CLIENT_ID });
  assert.deepEqual(msBad.json, { ok: false, hint: "client_id_shape" });

  // Redirect equality: the URI the person says they pasted, against the one this instance really uses.
  const match = await post(checkPath, { step: "redirect", provider: "google", pastedRedirectUri: REDIRECT_URI });
  assert.deepEqual(match.json, { ok: true, hint: null });
  const spaced = await post(checkPath, { step: "redirect", provider: "google", pastedRedirectUri: ` ${REDIRECT_URI} ` });
  assert.deepEqual(spaced.json, { ok: true, hint: null }, "surrounding spaces from a paste are trimmed");
  for (const pasted of ["https://elsewhere.example.test/callback", `${REDIRECT_URI}/`, "", 42]) {
    const r = await post(checkPath, { step: "redirect", provider: "google", pastedRedirectUri: pasted });
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.json, { ok: false, hint: "redirect_mismatch" }, String(pasted));
  }

  // No dashboard address: the redirect step says so instead of comparing against a localhost URI.
  delete process.env.CROW_GATEWAY_URL;
  delete process.env.CROW_OAUTH_ISSUER_URL;
  delete process.env.RENDER_EXTERNAL_URL;
  const none = await post(checkPath, { step: "redirect", provider: "google", pastedRedirectUri: REDIRECT_URI });
  assert.deepEqual(none.json, { ok: false, hint: "no_dashboard_address" });
  process.env.CROW_GATEWAY_URL = DASHBOARD;

  const scopes = await post(checkPath, { step: "scopes", provider: "google" });
  assert.deepEqual(scopes.json, { ok: true, hint: null });

  for (const body of [
    { step: "unknown", provider: "google" },
    { step: "client_id", provider: "gmail", clientId: GOOGLE_CLIENT_ID },
    { step: "client_id", provider: "constructor", clientId: GOOGLE_CLIENT_ID },
    { provider: "google" },
  ]) {
    const r = await post(checkPath, body);
    assert.equal(r.status, 400, `${JSON.stringify(body)}: ${r.text}`);
    assert.equal(r.json.error, "bad_input");
  }

  // Every key the wizard can be handed is one of the fixed ones.
  for (const hint of [...MAIL_OAUTH_HINT_KEYS]) assert.equal(typeof hint, "string");
  assert.equal(new Set(MAIL_OAUTH_HINT_KEYS).size, MAIL_OAUTH_HINT_KEYS.length);
});

/* --------------------------------------------------------------- callback guards */

test("a callback with no session is refused before any flow is spent", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl } });
  const started = await begin();
  assert.equal(started.status, 200, started.text);

  const r = await get(callbackPath(`code=${CODE}&state=${started.state}`), { token: null });
  assert.equal(r.status, 401, r.text);
  assert.equal(r.headers["cache-control"], "no-store", "a callback is never cached");
  assert.equal(r.headers["referrer-policy"], "no-referrer", "the URL carries a code and a state");
  assert.equal(w.flowStore.calls.take, 0, "take() never ran for a session-less callback");
  assert.equal(w.flowStore.size(), 1, "and the flow is still there for the session that began it");

  // The same request with its session still completes: the refusal was the session, not the flow.
  assert.equal(statusOf(await callback(started.state)), "oauth_connected");
});

/* --------------------------------------------------------------- the callback */

test("wrong, expired, reused and other-session states each store nothing and answer oauth_expired", async () => {
  const fake = await fakeProvider();
  let clock = 1_000_000;
  const store = recordingStore({ now: () => clock, ttlMs: 60_000 });
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl }, flowStore: store });

  const assertNothingStored = async (label) => {
    assert.equal((await listAccounts(w.db)).filter((a) => a.authKind === "xoauth2").length, 0, `${label}: no account`);
    assert.equal((await w.db.execute({ sql: "SELECT COUNT(*) AS n FROM crow_keychain", args: [] })).rows[0].n, 0, `${label}: no secret`);
    assert.deepEqual(await w.probeCalls.map((call) => call.account.address), [], `${label}: nothing was dialled`);
  };

  // A state nobody minted.
  assert.equal(statusOf(await callback("unknown-state-token")), "oauth_expired");
  await assertNothingStored("wrong state");

  // An expired flow: past its TTL it is gone, and a callback for it stores nothing.
  const expired = await begin();
  clock += 60_001;
  assert.equal(statusOf(await callback(expired.state)), "oauth_expired");
  await assertNothingStored("expired state");

  // Single use: a live flow works once, and the second callback for it is the expired answer.
  const live = await begin();
  assert.equal(statusOf(await callback(live.state)), "oauth_connected");
  assert.equal((await listAccounts(w.db)).filter((a) => a.authKind === "xoauth2").length, 1, "the first callback connected");
  const again = await callback(live.state);
  assert.equal(statusOf(again), "oauth_expired");
  assert.equal((await listAccounts(w.db)).filter((a) => a.authKind === "xoauth2").length, 1, "nothing new was stored");

  // Another session cannot spend it, and the attempt BURNS the token for the real session too.
  const stolen = await begin();
  const wrongSession = await callback(stolen.state, { token: SECOND });
  assert.equal(statusOf(wrongSession), "oauth_expired");
  assert.equal(statusOf(await callback(stolen.state)), "oauth_expired", "the token was burned by the wrong session");
});

test("error=access_denied stores nothing and answers oauth_denied", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl } });
  const started = await begin();
  assert.equal(started.status, 200, started.text);

  const r = await get(callbackPath(`error=access_denied&state=${encodeURIComponent(started.state)}`));
  assert.equal(statusOf(r), "oauth_denied");
  assert.equal(fake.requests.length, 0, "no code was ever traded");
  assert.equal((await listAccounts(w.db)).length, 0);
  assert.equal((await w.db.execute({ sql: "SELECT COUNT(*) AS n FROM crow_keychain", args: [] })).rows[0].n, 0);
  assert.equal(w.flowStore.size(), 0, "the flow was spent by the refusal");
});

test("a probe failure after the code was traded stores nothing and answers oauth_probe_failed", async () => {
  const fake = await fakeProvider();
  const w = await setup({
    endpoints: { tokenUrl: fake.tokenUrl },
    oauthAdapterFactory: () => {
      const adapter = createFakeMailAdapter();
      adapter.failNext("connect", new MailError("AUTH_FAILED"));
      return adapter;
    },
  });
  const started = await begin();
  assert.equal(started.status, 200, started.text);

  const { lines, result: r } = await warnings(() => callback(started.state));
  assert.equal(statusOf(r), "oauth_probe_failed");
  assert.equal(fake.requests.length, 1, "the code really was traded (and its tokens are what the probe used)");
  assert.equal((await listAccounts(w.db)).length, 0, "the connect's undo removed the account");
  assert.equal((await w.db.execute({ sql: "SELECT COUNT(*) AS n FROM crow_keychain", args: [] })).rows[0].n, 0, "and its secret");
  assert.deepEqual(
    await checkClaim(w.db, ADDRESS, { localInstanceId: "instC" }),
    { ok: true },
    "the claim was released: the address is free for another instance",
  );
  for (const text of [r.text, r.location, lines.join("\n")]) {
    assert.equal(String(text).includes(CODE), false, "the code is not printed");
    assert.equal(String(text).includes(started.state), false, "the state is not printed");
    assert.equal(String(text).includes(REFRESH_TOKEN), false, "the refresh token is not printed");
    assert.equal(String(text).includes(CLIENT_SECRET), false, "the client secret is not printed");
  }
});

test("a refused code exchange stores nothing and answers oauth_failed", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl } });
  const started = await begin();
  assert.equal(started.status, 200, started.text);
  fake.queueResponse({
    status: 400,
    // A real provider echoes the request in error_description; none of it may travel.
    body: (form) => ({ error: "invalid_client", error_description: `code ${form.code} secret ${form.client_secret}` }),
  });

  const r = await callback(started.state);
  assert.equal(statusOf(r), "oauth_failed");
  assert.equal((await listAccounts(w.db)).length, 0, "nothing was stored");
  assert.deepEqual(w.probeCalls, [], "nothing was dialled");
  for (const text of [r.text, String(r.location)]) {
    assert.equal(text.includes(CLIENT_SECRET), false, "the provider's echo stayed out of the answer");
    assert.equal(text.includes(CODE), false);
  }
});

test("a grant with no refresh token stores nothing and answers oauth_no_refresh", async () => {
  const fake = await fakeProvider();
  fake.queueResponse({ status: 200, body: { access_token: "short-lived-access", expires_in: 3600 } });
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl } });
  const started = await begin();
  assert.equal(started.status, 200, started.text);

  assert.equal(statusOf(await callback(started.state)), "oauth_no_refresh");
  assert.equal((await listAccounts(w.db)).length, 0);
  assert.deepEqual(w.probeCalls, [], "nothing was dialled");
  assert.equal((await w.db.execute({ sql: "SELECT COUNT(*) AS n FROM crow_keychain", args: [] })).rows[0].n, 0);
});

test("success stores exactly the three OAuth secrets for that account, sets the meta and starts the first sync", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl } });
  // Another account on the same Crow: the callback must not touch a single row of it.
  const other = await createAccount(w.db, {
    label: "Other", address: OTHER_ADDRESS, username: OTHER_ADDRESS, authKind: "password", imap: IMAP, smtp: SMTP,
  });
  await w.credentials.saveSecret(other.id, "MAIL_PASSWORD", "other-password");

  const started = await begin();
  assert.equal(started.status, 200, started.text);
  const authUrl = new URL(started.json.authUrl);
  assert.equal(authUrl.searchParams.get("client_id"), GOOGLE_CLIENT_ID);
  assert.equal(authUrl.searchParams.get("redirect_uri"), REDIRECT_URI);
  assert.equal(authUrl.searchParams.get("login_hint"), ADDRESS);
  assert.equal(authUrl.searchParams.get("code_challenge_method"), "S256");
  assert.equal(started.text.includes(CLIENT_SECRET), false, "the client secret never travels to the page");
  assert.equal(w.flowStore.size(), 1, "the client pair lives in the flow store until the callback");

  const r = await callback(started.state);
  assert.equal(statusOf(r), "oauth_connected");
  assert.ok(MAIL_OAUTH_STATUS_KEYS.includes("oauth_connected"));
  assert.equal(w.flowStore.calls.take, 1, "the callback spent exactly one state token");

  const accounts = (await listAccounts(w.db)).filter((a) => a.authKind === "xoauth2");
  assert.equal(accounts.length, 1);
  const account = accounts[0];
  assert.equal(account.address, ADDRESS);
  assert.equal(account.provider, "gmail", "the provider preset the fallback chose");
  assert.equal(account.sentCopy, "provider", "Gmail files its own Sent copy");
  assert.equal(account.imap.host, "imap.gmail.com", "the provider's own hosts, not the address's domain");
  assert.equal(account.smtp.host, "smtp.gmail.com");
  assert.deepEqual(await w.keychainRows(account.id), [
    "MAIL_OAUTH_CLIENT_ID", "MAIL_OAUTH_CLIENT_SECRET", "MAIL_REFRESH_TOKEN",
  ], "exactly the three OAuth secrets, one row each");
  assert.deepEqual(await w.credentials.getSecrets(account.id), {
    MAIL_OAUTH_CLIENT_ID: GOOGLE_CLIENT_ID,
    MAIL_OAUTH_CLIENT_SECRET: CLIENT_SECRET,
    MAIL_REFRESH_TOKEN: REFRESH_TOKEN,
  });

  assert.deepEqual(await w.keychainRows(other.id), ["MAIL_PASSWORD"], "the other account kept only its own secret");
  assert.deepEqual(await w.credentials.getSecrets(other.id), { MAIL_PASSWORD: "other-password" });

  const meta = await getOauthMeta(w.db, account.id);
  assert.equal(meta.publishing, "unknown");
  assert.equal(meta.provider, "google");
  assert.equal(meta.tenant, undefined, "Google's grant carries no tenant");
  assert.ok(Number.isInteger(meta.grantedAt) && meta.grantedAt > 0);
  assert.equal(await getOauthMeta(w.db, other.id), null, "no meta on the account that was not involved");

  // The probe ran with the ONE-SHOT token (never the registry's), on the row the wizard drafted.
  assert.equal(w.probeCalls.length, 1);
  assert.equal(typeof w.probeCalls[0].tokenProvider, "function");
  assert.equal(w.probeCalls[0].account.authKind, "xoauth2");
  assert.equal(w.probeCalls[0].account.id, "probe", "the probe runs before the account exists");

  await flush();
  assert.deepEqual(w.supervisorCalls, [["syncNow", account.id]], "the new account gets its first sync");
  assert.deepEqual(w.registryAsks, [], "the account registry was never asked for a provider");

  // Every secret joined the masking set, before any store or socket saw it.
  const masked = w.recorded.flat();
  for (const value of [CLIENT_SECRET, REFRESH_TOKEN, ACCESS_TOKEN, CODE]) {
    assert.ok(masked.includes(value), `${value} was recorded for masking`);
  }

  // Nothing the wizard or the redirect answered carries a value from the exchange. The start response
  // carries the state inside its authorization URL on purpose; the callback's redirect carries none.
  for (const secret of [CLIENT_SECRET, REFRESH_TOKEN, ACCESS_TOKEN, CODE]) {
    assert.equal(JSON.stringify(started.json).includes(secret), false, `the start response carried ${secret}`);
  }
  for (const text of [r.text, String(r.location)]) {
    for (const secret of [CLIENT_SECRET, REFRESH_TOKEN, ACCESS_TOKEN, CODE, started.state]) {
      assert.equal(text.includes(secret), false, `the callback response carried ${secret}`);
    }
  }
  assert.equal(w.flowStore.size(), 0, "the client secret is gone from the store after take()");
});

test("a Microsoft flow records its tenant and stores the tenant's preset hosts", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl } });
  const started = await begin({}, { provider: "microsoft", clientId: MICROSOFT_CLIENT_ID, clientSecret: CLIENT_SECRET, tenant: "contoso.example" });
  assert.equal(started.status, 200, started.text);
  assert.match(new URL(started.json.authUrl).pathname, /\/contoso\.example\/oauth2\/v2\.0\/authorize$/);

  assert.equal(statusOf(await callback(started.state)), "oauth_connected");
  const [account] = (await listAccounts(w.db)).filter((a) => a.authKind === "xoauth2");
  assert.equal(account.provider, "outlook");
  assert.equal(account.imap.host, "outlook.office365.com");
  const meta = await getOauthMeta(w.db, account.id);
  assert.equal(meta.provider, "microsoft");
  assert.equal(meta.tenant, "contoso.example");
});

test("a reconnect only reuses the stored client secret for the SAME client id", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl }, tokenProviderFor: true });
  const existing = await createAccount(w.db, {
    label: LABEL, address: ADDRESS, username: ADDRESS, authKind: "xoauth2",
    provider: "gmail", imap: IMAP, smtp: SMTP,
  });
  await w.credentials.saveSecret(existing.id, "MAIL_OAUTH_CLIENT_ID", GOOGLE_CLIENT_ID);
  await w.credentials.saveSecret(existing.id, "MAIL_OAUTH_CLIENT_SECRET", CLIENT_SECRET);
  await w.credentials.saveSecret(existing.id, "MAIL_REFRESH_TOKEN", OLD_REFRESH_TOKEN);

  // A different registration's client id. The stored secret belongs to the OLD registration and must
  // not be sent with the new id: the pair would not be a pair, and the old secret would travel to a
  // sign-in it was never issued for.
  const SECOND_CLIENT_ID = "987654321098-crowmailsecond.apps.googleusercontent.com";
  const noSecret = await begin({}, { reconnectAccountId: existing.id, clientId: SECOND_CLIENT_ID, clientSecret: undefined });
  assert.equal(noSecret.status, 200, noSecret.text);
  assert.equal(statusOf(await callback(noSecret.state)), "oauth_connected");
  assert.equal(fake.requests.length, 1);
  assert.equal(
    Object.hasOwn(fake.requests[0].form, "client_secret"),
    false,
    "the old registration's secret was not sent with the new client id",
  );

  // The page's own secret, for the id the page asked for, is what goes out.
  const pageSecret = "client-secret-from-the-page-4a7d";
  const withSecret = await begin({}, {
    reconnectAccountId: existing.id, clientId: SECOND_CLIENT_ID, clientSecret: pageSecret,
  });
  assert.equal(withSecret.status, 200, withSecret.text);
  assert.equal(statusOf(await callback(withSecret.state)), "oauth_connected");
  assert.equal(fake.requests[1].form.client_secret, pageSecret, "the page's own secret is used as given");
});

test("a reconnect start with no client secret on the page and the same id still uses the stored one", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl }, tokenProviderFor: true });
  const existing = await createAccount(w.db, {
    label: LABEL, address: ADDRESS, username: ADDRESS, authKind: "xoauth2",
    provider: "gmail", imap: IMAP, smtp: SMTP,
  });
  await w.credentials.saveSecret(existing.id, "MAIL_OAUTH_CLIENT_ID", GOOGLE_CLIENT_ID);
  await w.credentials.saveSecret(existing.id, "MAIL_OAUTH_CLIENT_SECRET", CLIENT_SECRET);
  await w.credentials.saveSecret(existing.id, "MAIL_REFRESH_TOKEN", OLD_REFRESH_TOKEN);

  const started = await begin({}, { reconnectAccountId: existing.id, clientSecret: undefined });
  assert.equal(started.status, 200, started.text);
  assert.equal(statusOf(await callback(started.state)), "oauth_connected");
  assert.equal(fake.requests[0].form.client_id, GOOGLE_CLIENT_ID);
  assert.equal(fake.requests[0].form.client_secret, CLIENT_SECRET, "the stored pair is kept together");
});

test("a reconnect that names NO client id at all signs in with the stored registration (the card's one-tap Reconnect)", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl }, tokenProviderFor: true });
  const existing = await createAccount(w.db, {
    label: LABEL, address: ADDRESS, username: ADDRESS, authKind: "xoauth2",
    provider: "gmail", imap: IMAP, smtp: SMTP,
  });
  await w.credentials.saveSecret(existing.id, "MAIL_OAUTH_CLIENT_ID", GOOGLE_CLIENT_ID);
  await w.credentials.saveSecret(existing.id, "MAIL_OAUTH_CLIENT_SECRET", CLIENT_SECRET);
  await w.credentials.saveSecret(existing.id, "MAIL_REFRESH_TOKEN", OLD_REFRESH_TOKEN);

  // Exactly what the settings card's Reconnect posts: the account, the address it shows and the
  // provider — no registration, no secret. Both are read from the sealed keychain server-side.
  const started = await begin({}, { reconnectAccountId: existing.id, clientId: undefined, clientSecret: undefined });
  assert.equal(started.status, 200, started.text);
  const authUrl = new URL(started.json.authUrl);
  assert.equal(authUrl.searchParams.get("client_id"), GOOGLE_CLIENT_ID, "the stored registration is the one used");
  assert.equal(started.text.includes(CLIENT_SECRET), false, "nothing secret travels to the page");
  assert.equal(statusOf(await callback(started.state)), "oauth_connected");
  assert.equal(fake.requests.length, 1);
  assert.equal(fake.requests[0].form.client_id, GOOGLE_CLIENT_ID);
  assert.equal(fake.requests[0].form.client_secret, CLIENT_SECRET);

  // An account with no stored registration, and a page that names none either: nothing to sign in with.
  const bare = await createAccount(w.db, {
    label: "Bare", address: OTHER_ADDRESS, username: OTHER_ADDRESS, authKind: "xoauth2",
    provider: "gmail", imap: IMAP, smtp: SMTP,
  });
  const refused = await begin({}, {
    reconnectAccountId: bare.id, address: OTHER_ADDRESS, clientId: undefined, clientSecret: undefined,
  });
  assert.equal(refused.status, 400, refused.text);
  assert.equal(refused.json.error, "bad_input");
  assert.equal(w.flowStore.calls.begin, 1, "no flow was minted for the second reconnect");
});

test("the callback stores the grant's meta before the first sync, tenant included", async () => {
  const fake = await fakeProvider();
  const seen = [];
  const w = await setup({
    endpoints: { tokenUrl: fake.tokenUrl },
    // The first sync is what reads the meta (a Microsoft refresh takes its tenant from it): what it sees
    // at that instant is the finding.
    supervisor: {
      async syncNow(id) { seen.push(await getOauthMeta(w.db, id)); },
      async restartAccount() {},
    },
  });

  const started = await begin({}, { provider: "microsoft", clientId: MICROSOFT_CLIENT_ID, clientSecret: CLIENT_SECRET, tenant: "contoso.example" });
  assert.equal(started.status, 200, started.text);
  assert.equal(statusOf(await callback(started.state)), "oauth_connected");
  await flush();

  assert.equal(seen.length, 1, "the account got its first sync");
  assert.ok(seen[0], "the meta was already stored when that sync started");
  assert.equal(seen[0].provider, "microsoft");
  assert.equal(seen[0].tenant, "contoso.example", "the first refresh can use the grant's own tenant, never \"common\"");
});

/* ------------------------------------------------------------- reconnect */

test("a reconnect replaces the refresh token, keeps the account and its mail, and retires the provider", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl }, tokenProviderFor: true });
  const existing = await createAccount(w.db, {
    label: LABEL, address: ADDRESS, username: ADDRESS, authKind: "xoauth2",
    provider: "gmail", imap: IMAP, smtp: SMTP,
  });
  await w.credentials.saveSecret(existing.id, "MAIL_OAUTH_CLIENT_ID", GOOGLE_CLIENT_ID);
  await w.credentials.saveSecret(existing.id, "MAIL_OAUTH_CLIENT_SECRET", CLIENT_SECRET);
  await w.credentials.saveSecret(existing.id, "MAIL_REFRESH_TOKEN", OLD_REFRESH_TOKEN);
  // Some mail of the account's, so "keeps its mail" is about real rows.
  await upsertFolders(w.db, existing.id, [
    { path: "INBOX", name: "INBOX", specialUse: "\\Inbox", delimiter: "/" },
  ]);
  const before = await getAccount(w.db, existing.id);

  // The page sends no client secret: the wizard reads the stored one server-side, never from the body.
  const started = await begin({}, { reconnectAccountId: existing.id, clientSecret: undefined });
  assert.equal(started.status, 200, started.text);
  assert.equal(fake.requests.length, 0, "no exchange yet");

  assert.equal(statusOf(await callback(started.state)), "oauth_connected");
  assert.equal(fake.requests.length, 1);
  assert.equal(fake.requests[0].form.client_secret, CLIENT_SECRET, "the stored secret was the one sent");
  assert.equal(fake.requests[0].form.code_verifier.length, 43);

  const accounts = await listAccounts(w.db);
  assert.equal(accounts.length, 1, "the account was re-keyed, not duplicated");
  const after = accounts[0];
  assert.equal(after.id, existing.id, "the id is kept");
  assert.equal(after.address, ADDRESS);
  assert.equal(after.createdAt, before.createdAt);
  assert.equal(after.status, "active");
  assert.deepEqual(await w.credentials.getSecrets(existing.id), {
    MAIL_OAUTH_CLIENT_ID: GOOGLE_CLIENT_ID,
    MAIL_OAUTH_CLIENT_SECRET: CLIENT_SECRET,
    MAIL_REFRESH_TOKEN: REFRESH_TOKEN,
  }, "only the refresh token changed");
  assert.equal((await w.db.execute({ sql: "SELECT COUNT(*) AS n FROM mail_folders WHERE account_id = ?", args: [existing.id] })).rows[0].n, 1, "its mail stayed");
  assert.ok(w.forgets.includes(existing.id), "the cached provider was retired before the swap");
  await flush();
  assert.deepEqual(w.supervisorCalls, [["restartAccount", existing.id]], "the worker was restarted");
});

test("a reconnect start refuses a mismatched account, address or provider, and a password account", async () => {
  const w = await setup();
  const google = await createAccount(w.db, {
    label: LABEL, address: ADDRESS, username: ADDRESS, authKind: "xoauth2", provider: "gmail", imap: IMAP, smtp: SMTP,
  });
  const password = await createAccount(w.db, {
    label: "Password", address: OTHER_ADDRESS, username: OTHER_ADDRESS, authKind: "password", imap: IMAP, smtp: SMTP,
  });

  const wrongAddress = await begin({}, { reconnectAccountId: google.id, address: "someone@example.test" });
  assert.equal(wrongAddress.status, 400, wrongAddress.text);
  const wrongProvider = await begin({}, {
    reconnectAccountId: google.id, provider: "microsoft", clientId: MICROSOFT_CLIENT_ID,
  });
  assert.equal(wrongProvider.status, 400, wrongProvider.text);
  const passwordAccount = await begin({}, { reconnectAccountId: password.id, address: OTHER_ADDRESS });
  assert.equal(passwordAccount.status, 400, passwordAccount.text);
  const missing = await begin({}, { reconnectAccountId: "ma-0123456789abcdef" });
  assert.equal(missing.status, 404, missing.text);
  const badId = await begin({}, { reconnectAccountId: "not-an-account" });
  assert.equal(badId.status, 404, badId.text);
  assert.equal(w.flowStore.calls.begin, 0, "no flow was minted for any refused reconnect");
});

/* ------------------------------------------------------- start's validation */

test("POST /oauth/start refuses a bad provider, address, label, client id or secret with bad_input", async () => {
  const w = await setup();
  for (const over of [
    { provider: "gmail" },
    { provider: "constructor" },
    { provider: undefined },
    { address: "not-an-address" },
    { address: "two@at@example.test" },
    { address: "<alex@example.test>" },
    { label: "" },
    { label: "x".repeat(200) },
    { clientId: "not-a-google-id" },
    { clientId: undefined },
    { clientSecret: 42 },
    { clientSecret: "x".repeat(2000) },
    { tenant: "../../evil" },
  ]) {
    const r = await begin({}, over);
    assert.equal(r.status, 400, `${JSON.stringify(over)}: ${r.text}`);
    assert.equal(r.json.error, "bad_input");
  }
  assert.equal(w.flowStore.calls.begin, 0, "nothing was minted");
});

test("a Microsoft tenant is a directory GUID or a domain, carried in the authorization URL; anything else never starts a flow", async () => {
  const w = await setup();
  const TENANT_GUID = "f2b9c3d4-1a2b-4c5d-8e9f-0a1b2c3d4e5f";
  const microsoft = { provider: "microsoft", clientId: MICROSOFT_CLIENT_ID, clientSecret: CLIENT_SECRET };
  const authorizePath = (r) => new URL(r.json.authUrl).pathname;

  // A directory (tenant) GUID, exactly as Entra shows it.
  const guid = await begin({}, { ...microsoft, tenant: TENANT_GUID });
  assert.equal(guid.status, 200, guid.text);
  assert.equal(authorizePath(guid), `/f2b9c3d4-1a2b-4c5d-8e9f-0a1b2c3d4e5f/oauth2/v2.0/authorize`);

  // A verified domain name.
  const domain = await begin({}, { ...microsoft, tenant: "contoso.example" });
  assert.equal(domain.status, 200, domain.text);
  assert.equal(authorizePath(domain), "/contoso.example/oauth2/v2.0/authorize");

  // Nothing named, and an empty field (the person left it alone): both are Microsoft's "common".
  for (const tenant of [undefined, "", "   "]) {
    const none = await begin({}, { ...microsoft, tenant });
    assert.equal(none.status, 200, `${JSON.stringify(tenant)}: ${none.text}`);
    assert.equal(authorizePath(none), "/common/oauth2/v2.0/authorize", `${JSON.stringify(tenant)}: the server's own default`);
  }

  // Google has no tenant in its URLs; a valid one is accepted and carries nothing.
  const google = await begin({}, { tenant: "contoso.example" });
  assert.equal(google.status, 200, google.text);
  assert.equal(new URL(google.json.authUrl).host, "accounts.google.com");
  assert.equal(authorizePath(google), "/o/oauth2/v2/auth");

  // A single label is still a DNS label, so the SERVER takes it ("contoso" is the short form of a
  // verified domain); the wizard's own field asks for a dot, so a person names a full domain there.
  const single = await begin({}, { ...microsoft, tenant: "contoso" });
  assert.equal(single.status, 200, single.text);
  assert.equal(authorizePath(single), "/contoso/oauth2/v2.0/authorize");

  // Every value that is neither a GUID nor a hostname-shaped domain is refused before anything is
  // minted: tenantFor() is the one rule, and it is reused here, not re-implemented. (Its three
  // multi-tenant words — "common", "consumers", "organizations" — are valid tenants, so they are NOT
  // in this list; the wizard's own field takes only a GUID or a domain, because naming "common" there
  // is the same as leaving the field empty.)
  for (const tenant of [
    "../evil", "a..b", ".contoso.example", "contoso.example.",
    "-bad.example", "bad-.example", "two words.example", "contoso/example", "x".repeat(300),
  ]) {
    const r = await begin({}, { ...microsoft, tenant });
    assert.equal(r.status, 400, `${JSON.stringify(tenant)}: ${r.text}`);
    assert.equal(r.json.error, "bad_input");
  }
  assert.equal(w.flowStore.calls.begin, 7, "exactly the seven valid starts minted a flow");
});

/* --------------------------------------------------------------- the flow store cap */

test("the flow store's per-session cap evicts the oldest, and each state works exactly once", async () => {
  const fake = await fakeProvider();
  const w = await setup({ endpoints: { tokenUrl: fake.tokenUrl } });
  const states = [];
  for (let i = 0; i < 21; i += 1) {
    const r = await begin();
    assert.equal(r.status, 200, r.text);
    states.push(r.state);
  }
  assert.equal(w.flowStore.size(), 20, "one session holds twenty flows at most");
  assert.equal(new Set(states).size, 21, "every start minted a fresh state");

  // The 21st begin evicted the oldest: its callback is the expired answer, and stores nothing.
  assert.equal(statusOf(await callback(states[0])), "oauth_expired");
  assert.equal((await listAccounts(w.db)).length, 0);
  // The newest is live, and single use.
  assert.equal(statusOf(await callback(states[20])), "oauth_connected");
  assert.equal(statusOf(await callback(states[20])), "oauth_expired");
  assert.equal((await listAccounts(w.db)).length, 1);
});

/* --------------------------------------------------------------- the self-test */

test("POST /accounts/:id/selftest sends one message from the account to itself, and changes nothing", async () => {
  const adapter = createFakeMailAdapter();
  const w = await setup({
    supervisor: { async withAdapter(_id, work) { return work(adapter); } },
  });
  const account = await createAccount(w.db, {
    label: LABEL, address: ADDRESS, username: ADDRESS, authKind: "password", imap: IMAP, smtp: SMTP,
  });
  const before = await getAccount(w.db, account.id);
  assert.equal(adapter.calls.filter((c) => c.method === "send").length, 0, "nothing is sent before the tap");

  const r = await post(selftestPath(account.id), {});
  assert.equal(r.status, 200, r.text);
  assert.deepEqual(r.json, { ok: true });
  assert.equal(adapter.sent.length, 1);
  const sent = adapter.sent[0];
  assert.equal(sent.to[0].address, ADDRESS);
  assert.equal(sent.from.address, ADDRESS);
  assert.equal(sent.subject, "Crow mail self-test");

  const after = await getAccount(w.db, account.id);
  assert.deepEqual(after, before, "the self-test changes no account field");
});

test("a failed self-test answers a fixed code, never a sentence; a GET is not the route", async () => {
  const adapter = createFakeMailAdapter();
  const w = await setup({
    supervisor: { async withAdapter(_id, work) { return work(adapter); } },
  });
  const account = await createAccount(w.db, {
    label: LABEL, address: ADDRESS, username: ADDRESS, authKind: "password", imap: IMAP, smtp: SMTP,
  });

  adapter.failNext("send", new MailError("AUTH_FAILED"));
  const { lines, result: refused } = await warnings(() => post(selftestPath(account.id), {}));
  assert.equal(refused.status, 200, refused.text);
  assert.deepEqual(refused.json, { ok: false, error: "AUTH_FAILED" });
  assert.equal(refused.text.includes("sign in"), false, "no sentence travels, only the code");
  assert.equal(lines.join("\n").includes(ADDRESS), false, "the log carries no address");

  // Every recipient refused: its own fixed code.
  adapter.send = async () => ({ messageId: "<x@example.test>", accepted: [], rejected: [ADDRESS] });
  assert.deepEqual((await post(selftestPath(account.id), {})).json, { ok: false, error: "all_rejected" });

  // No supervisor at all: the check cannot run.
  const bare = await setup({ supervisor: null });
  const second = await createAccount(bare.db, {
    label: LABEL, address: ADDRESS, username: ADDRESS, authKind: "password", imap: IMAP, smtp: SMTP,
  });
  const unavailable = await post(selftestPath(second.id), {});
  assert.equal(unavailable.status, 503, unavailable.text);
  assert.deepEqual(unavailable.json, { ok: false, error: "unavailable" });

  // POST only: a GET reaches no route at all.
  const read = await get(selftestPath(account.id));
  assert.ok([404, 405].includes(read.status), `a GET is 404/405, got ${read.status}`);
  assert.equal(adapter.calls.filter((c) => c.method === "send").length, 1, "the GET sent nothing");

  // An id that names no account, or is not an account id, is a 404.
  assert.equal((await post(selftestPath("ma-0123456789abcdef"), {})).status, 404);
  assert.equal((await post(selftestPath("not-an-account"), {})).status, 404);
});

/* --------------------------------------------------------------- fixed keys */

test("every status key the redirect can carry is one of the fixed ones", () => {
  assert.deepEqual([...MAIL_OAUTH_STATUS_KEYS], [
    "oauth_connected", "oauth_denied", "oauth_expired", "oauth_failed", "oauth_no_refresh", "oauth_probe_failed",
  ]);
});