/**
 * The Stock prices (Tiingo) routes of the Trading panel: the four routes, the one keychain row
 * they seal on the standing Coinbase connection, the two engine calls they make, the state they
 * answer (a paused allowance is a connected token, not a refusal), and the reconnect that carries
 * the sealed token onto the connection replacing the one it lived on, per the stock-prices contract.
 *
 * This file is built the way `coinbase-connect.test.js` builds its routes: a scratch Crow home
 * with an install token, one init-db database per test, a real express app over
 * `createConnectRoutes`, and a fake trading engine on loopback that checks the owner MAC on every
 * privileged route (including `/tiingo/check`, `POST /tiingo` and `DELETE /tiingo`) and records
 * which key each request was signed with. The step-up gate is the same fake the connect tests use,
 * and the keychain is the real one: the sealed row is read back through the same store the
 * product reads it with.
 *
 * `tiingoStore` is the keychain seam the contract names: `save(uuid, token)`, `read(uuid)` and
 * `remove(uuid)` over the real `saveServiceSecret` / `serviceSecretsFor` / `deleteServiceSecret`,
 * with each call recorded. The assertions read the database rows themselves, so they hold whether
 * the routes reach the keychain through this seam or their own default wrappers; the recorded
 * calls are only used where "nothing was sealed" is the point. Every value here is synthetic and
 * built at run time.
 *
 * The reconnect's project id (the contract's own "not a positive integer" refusal) is tested at
 * the boundary the routes stand on, since `carrySealedTiingo` is a closure inside
 * `createConnectRoutes` with no way in: the route's own refusal of an unusable id, and the carry
 * that still works, and is narrowed to its own project, on the option-free path (no `tiingoStore`
 * handed in at all, so the routes build their own seam).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { rmScratch } from "./helpers/safe-rm.js";
import { csrfTokenFor } from "./helpers/csrf-token.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = mkdtempSync(join(tmpdir(), "crow-coinbase-tiingo-home-"));
const DATA = mkdtempSync(join(tmpdir(), "crow-coinbase-tiingo-data-"));
const TOKEN_DIR = join(HOME, "coinbase", "install");
mkdirSync(TOKEN_DIR, { recursive: true, mode: 0o700 });
// The install token the installer publishes for the engine: 43 base64url characters.
const INSTALL_TOKEN = randomBytes(32).toString("base64url");
writeFileSync(join(TOKEN_DIR, "install_token"), INSTALL_TOKEN + "\n", { mode: 0o644 });

process.env.CROW_APP_ROOT = REPO;
process.env.CROW_HOME = HOME;
process.env.CROW_DATA_DIR = DATA;
delete process.env.CROW_DB_PATH;
process.env.CROW_AUTO_UPDATE = "0";
process.env.CROW_DISABLE_HEALTH_MONITOR = "1";
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
process.env.CROW_DISABLE_NOSTR = "1";

const { createDbClient } = await import("../servers/db.js");
const K = await import("../servers/gateway/keychain/store.js");
const { macSignature } = await import("../bundles/coinbase/server/mac.js");
const { createEngineClient } = await import("../bundles/coinbase/server/engine-client.js");
const { createConnectRoutes } = await import("../bundles/coinbase/panel/connect.js");

const ENGINE_TOKEN = "test-token-coinbase-tiingo-engine-4b17";
const KEY_NAME = "organizations/test-org/apiKeys/test-key-2291c";
const TOTP = "123456";
const SESSION = "coinbase-tiingo-session-1";

const TIINGO_TOKEN = "tiingo" + randomBytes(16).toString("hex");
// A second pasted value, so a test can tell one seal from the next.
const TIINGO_TOKEN_2 = "tiingo" + randomBytes(16).toString("hex");
// The string every answer, audit row and sealed row is scanned for.
const CANARY = "canary" + randomBytes(16).toString("hex");

const TIINGO_ENV_KEY = "TIINGO_TOKEN";
const MESSAGE_ACCEPTED = "Tiingo accepted the token.";
const MESSAGE_DISCONNECTED = "Stock prices disconnected.";
const MESSAGE_PENDING =
  "Saved. Crow will send it to the trading engine as soon as it answers.";
const MESSAGE_CONNECT_FIRST = "Connect Coinbase first.";
const MESSAGE_PICK_PROJECT = "Pick a project first.";
const MESSAGE_PASTE = "Paste the Tiingo token.";
const MESSAGE_TOKEN_SHAPE = "The Tiingo token must be one line of letters and digits.";
const MESSAGE_REJECTED = "Tiingo did not accept the token.";
// The sentence the state route answers while Tiingo is limiting Crow: the token is fine.
const MESSAGE_PRICES_PAUSED =
  "Stock prices are paused for now (Tiingo is limiting requests); they will resume on their own.";

const STATE = "/api/coinbase/tiingo/state";
const TEST_ROUTE = "/api/coinbase/tiingo/test";
const SAVE_ROUTE = "/api/coinbase/tiingo";
const DISCONNECT_ROUTE = "/api/coinbase/tiingo/disconnect";

// A PEM-shaped key built at run time: the header is assembled from parts, never written whole.
const PEM_HEADER = ["-----BEGIN", "EC PRIVATE KEY-----"].join(" ");
const PEM_FOOTER = ["-----END", "EC PRIVATE KEY-----"].join(" ");
function buildPrivateKey() {
  const body = randomBytes(96).toString("base64").replace(/(.{64})/g, "$1\n").trim();
  return [PEM_HEADER, body, PEM_FOOTER].join("\n");
}
const PRIVATE_KEY = buildPrivateKey();

// ---- scratch databases and projects ----------------------------------------------------------

const DIRS = [HOME, DATA];
let dbN = 0;

async function freshDb() {
  const dir = mkdtempSync(join(tmpdir(), `crow-coinbase-tiingo-db${++dbN}-`));
  DIRS.push(dir);
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir },
    stdio: "pipe",
    cwd: REPO,
  });
  return { dir, path: join(dir, "crow.db") };
}

async function mkProject(db, name) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  const r = await db.execute({
    sql: "INSERT INTO project_spaces (slug, name) VALUES (?, ?) RETURNING id",
    args: [slug, name],
  });
  const id = Number(r.rows[0].id);
  await db.execute({
    sql: "INSERT INTO project_members (project_id, contact_id, role) VALUES (?, NULL, 'owner')",
    args: [id],
  });
  return id;
}

function closeServer(server) {
  return new Promise((resolve) => {
    if (!server) return resolve();
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(); } };
    try { server.close(finish); } catch { finish(); }
    setTimeout(finish, 2000).unref();
  });
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let text = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => { text += chunk; });
    req.on("end", () => resolve(text));
    req.on("error", reject);
  });
}

/** Await a request, but never forever: a stalled route fails its own test, not the run. */
function within(promise, label, ms = 20000) {
  let timer = null;
  const guard = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: no answer within ${ms} ms`)), ms);
    if (timer && typeof timer.unref === "function") timer.unref();
  });
  return Promise.race([promise, guard]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

// ---- the fake trading engine -----------------------------------------------------------------

/**
 * One fake engine on loopback. The credentials routes are the connect tests' own fake, thin: a
 * pin, an epoch, a check and a push. The three Tiingo routes are behind the same owner MAC, and
 * `tiingoCheckDown`, `tiingoSetDown` and `tiingoDeleteDown` drop a socket instead of answering, so
 * a test can show what the panel does with an engine that is not answering.
 */
async function createFakeEngine() {
  const state = {
    pinned: false,
    pinSecret: null,
    credentials: "not_ready",
    epoch: "engine-epoch-0",
    requests: [],
    nextCheck: [],
    nextPush: [],
    nextForget: [],
    nextTiingoCheck: [],
    priceState: "missing",
    priceMessage: null,
    tiingoCheckDown: false,
    tiingoSetDown: false,
    tiingoDeleteDown: false,
  };
  let server = null;
  let port = 0;

  /** Which key this request's MAC was signed with: "install", "owner" or "none". */
  function macUsed(record) {
    const signature = record.headers["x-crow-signature"];
    if (!signature) return "none";
    const ts = record.headers["x-crow-timestamp"];
    const nonce = record.headers["x-crow-nonce"];
    if (!ts || !nonce) return "none";
    const candidates = [["install", INSTALL_TOKEN]];
    if (state.pinSecret) candidates.push(["owner", state.pinSecret]);
    for (const [kind, key] of candidates) {
      let expected;
      try {
        expected = macSignature({
          key,
          method: record.method,
          pathWithQuery: record.path,
          ts,
          nonce,
          body: record.body,
        });
      } catch { continue; }
      if (expected === signature) return kind;
    }
    return "none";
  }

  async function handle(req, res) {
    const body = await readBody(req);
    const record = { method: req.method, path: req.url, headers: req.headers, body };
    record.mac = macUsed(record);
    state.requests.push(record);
    const send = (status, payload, headers = {}) => {
      res.writeHead(status, { "content-type": "application/json", ...headers });
      res.end(JSON.stringify(payload));
    };
    const drop = () => { try { res.destroy(); } catch { /* the socket is already gone */ } };

    if (req.method === "GET" && record.path === "/health") {
      return send(200, { ok: true, credentials: state.credentials, pinned: state.pinned });
    }

    if (req.method === "GET" && record.path === "/status") {
      return send(200, {
        halted: false,
        halted_books: { dry: false, live: false },
        halt_reasons: { dry: null, live: null },
        bots: [],
        recent_alerts: [],
        live_switches: { live_enabled: false, ai_live_enabled: false, ceiling: true },
        drawdown: { dry: null, live: null },
        products: ["BTC-USDC"],
        equity: {
          enabled: true,
          prices: state.priceState,
          prices_message: state.priceMessage,
        },
      });
    }

    if (req.method === "POST" && record.path === "/credentials/check") {
      const scripted = state.nextCheck.shift();
      if (scripted) return send(scripted.status, scripted.body);
      return send(200, { state: "ok", key_last4: "9137", portfolio_last4: "5678" });
    }

    if (req.method === "POST" && record.path === "/credentials") {
      const wanted = state.pinned ? "owner" : "install";
      if (record.mac !== wanted) return send(403, { detail: "SECRET_MISMATCH" });
      const scripted = state.nextPush.shift();
      if (scripted) return send(scripted.status, scripted.body);
      let parsed = {};
      try { parsed = JSON.parse(body) || {}; } catch { parsed = {}; }
      if (!state.pinned) {
        state.pinSecret = typeof parsed.approve_secret === "string" ? parsed.approve_secret : null;
        state.pinned = true;
        state.epoch = "engine-epoch-" + randomBytes(6).toString("hex");
      }
      state.credentials = "ready";
      return send(200, {
        state: "ok",
        pinned: true,
        engine_epoch: state.epoch,
        key_last4: "9137",
        portfolio_last4: "5678",
      });
    }

    if (req.method === "POST" && record.path === "/credentials/forget") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      const scripted = state.nextForget.shift();
      if (scripted) return send(scripted.status, scripted.body);
      state.pinned = false;
      state.pinSecret = null;
      state.credentials = "not_ready";
      return send(200, { ok: true });
    }

    if (req.method === "DELETE" && record.path === "/credentials") {
      const wanted = state.pinned ? "owner" : "install";
      if (record.mac !== wanted) return send(403, { detail: "SECRET_MISMATCH" });
      state.credentials = "not_ready";
      return send(200, { ok: true });
    }

    // ---- the three Tiingo routes: every one of them takes the owner's MAC --------------------

    if (req.method === "POST" && record.path === "/tiingo/check") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      if (state.tiingoCheckDown) return drop();
      const scripted = state.nextTiingoCheck.shift();
      if (scripted) return send(scripted.status, scripted.body, scripted.headers || {});
      return send(200, { state: "ok" });
    }

    if (req.method === "POST" && record.path === "/tiingo") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      if (state.tiingoSetDown) return drop();
      return send(200, { state: "connected" });
    }

    if (req.method === "DELETE" && record.path === "/tiingo") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      if (state.tiingoDeleteDown) return drop();
      return send(200, { state: "missing" });
    }

    return send(404, { detail: "NOT_FOUND" });
  }

  async function listen() {
    server = http.createServer((req, res) => {
      handle(req, res).catch(() => { try { res.destroy(); } catch { /* gone */ } });
    });
    await new Promise((resolve, reject) => {
      const onError = (err) => { server.removeListener("listening", onListening); reject(err); };
      const onListening = () => { server.removeListener("error", onError); resolve(); };
      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(port, "127.0.0.1");
    });
    port = server.address().port;
  }

  await listen();

  return {
    get baseUrl() { return `http://127.0.0.1:${port}`; },
    state,
    calls: (method, path) => state.requests.filter((r) => r.method === method && r.path === path),
    nextTiingoCheck: (answer) => state.nextTiingoCheck.push(answer),
    nextPush: (answer) => state.nextPush.push(answer),
    close: () => closeServer(server),
  };
}

// ---- the fake step-up gate (the connect tests' own) -------------------------------------------

/** `verify` answers `{ok}` for the right code and records every call, so a test can show none. */
function createFakeStepUpGate() {
  const state = { calls: [] };
  return {
    state,
    async verify(token, { totp_code: code } = {}) {
      state.calls.push({ token, code });
      if (code === TOTP) return { ok: true, method: "totp" };
      return { ok: false, method: "totp", error: "That code is not valid." };
    },
  };
}

// ---- the keychain seam the contract names -----------------------------------------------------

/**
 * `tiingoStore` over the real keychain functions: `save(uuid, token)`, `read(uuid)` and
 * `remove(uuid)`, each recorded. It seals exactly what the contract seals — the token under the
 * connection's uuid, bundle `coinbase`, env key `TIINGO_TOKEN` — so a route that reaches the
 * keychain through it writes the same row the default wrappers write.
 */
function tiingoStoreFor(db, loadKey) {
  const calls = { save: [], read: [], remove: [] };
  const store = {
    async save(uuid, token) {
      calls.save.push({ uuid: String(uuid), token });
      return K.saveServiceSecret(db, await loadKey(), {
        connectionUuid: String(uuid),
        bundleId: "coinbase",
        envKey: TIINGO_ENV_KEY,
        label: "Coinbase \u2014 Stock prices \u2014 TIINGO_TOKEN",
        secret: String(token),
      });
    },
    async read(uuid) {
      calls.read.push(String(uuid));
      const secrets = await K.serviceSecretsFor(db, await loadKey(), String(uuid), {
        allowedKeys: [TIINGO_ENV_KEY],
      });
      const value = secrets ? secrets[TIINGO_ENV_KEY] : null;
      return typeof value === "string" && value ? value : null;
    },
    async remove(uuid) {
      calls.remove.push(String(uuid));
      return K.deleteServiceSecret(db, String(uuid), TIINGO_ENV_KEY, { bundleId: "coinbase" });
    },
  };
  return { calls, store };
}

/**
 * The same seam, with two extras a reconnect test needs: `snapshots` receives the connection table
 * as it stood at each save (so a test can say the token was copied while the old connection was
 * still active), and `failCopy` makes the next save throw, so a test can show a copy that cannot
 * happen leaves the connect itself standing.
 */
function observingTiingoStore(getDb, { snapshots = [], failCopy = () => false } = {}) {
  const loadKey = () => K.ensureWriteKey(getDb(), { crowHome: HOME });
  return {
    async save(uuid, token) {
      if (failCopy()) throw new Error("the keychain is not writable");
      snapshots.push((await getDb().execute({
        sql: "SELECT uuid, status FROM service_connections WHERE service_id = 'coinbase' ORDER BY id",
        args: [],
      })).rows.map((row) => ({ uuid: String(row.uuid), status: String(row.status) })));
      return K.saveServiceSecret(getDb(), await loadKey(), {
        connectionUuid: String(uuid),
        bundleId: "coinbase",
        envKey: TIINGO_ENV_KEY,
        label: "Coinbase \u2014 Stock prices \u2014 TIINGO_TOKEN",
        secret: String(token),
      });
    },
    async read(uuid) {
      const secrets = await K.serviceSecretsFor(getDb(), await loadKey(), String(uuid), {
        allowedKeys: [TIINGO_ENV_KEY],
      });
      const value = secrets ? secrets[TIINGO_ENV_KEY] : null;
      return typeof value === "string" && value ? value : null;
    },
    async remove(uuid) {
      return K.deleteServiceSecret(getDb(), String(uuid), TIINGO_ENV_KEY, { bundleId: "coinbase" });
    },
  };
}

// ---- one panel harness per test ----------------------------------------------------------------

async function scaffold(overrides = {}) {
  const options = overrides || {};
  const ctx = await freshDb();
  const db = createDbClient(ctx.path);
  const projectId = await mkProject(db, `Trading tiingo ${dbN}`);
  const fake = await createFakeEngine();
  const flags = { twoFactor: true, local: true };
  const stepUpGate = options.stepUpGate || createFakeStepUpGate();
  const loadKey = () => K.ensureWriteKey(db, { crowHome: HOME });
  const tiingo = tiingoStoreFor(db, loadKey);
  // The keychain seam these routes seal and read through: a caller's own when it hands one in, so
  // the handle below is the store the routes really wrote to.
  const tiingoStore = options.routes && options.routes.tiingoStore ? options.routes.tiingoStore : tiingo.store;

  const routes = createConnectRoutes({
    db,
    crowHome: HOME,
    engineClientFactory: ({ secretProvider }) =>
      createEngineClient({ baseUrl: fake.baseUrl, token: ENGINE_TOKEN, secretProvider }),
    authMiddleware: (req, _res, next) => {
      req.dashboardSession = SESSION;
      next();
    },
    isLocalSession: async () => flags.local === true,
    is2faEnabled: async () => flags.twoFactor === true,
    stepUpGate,
    loadKey,
    tiingoStore,
    ...(options.routes || {}),
  });

  const app = express();
  app.use(routes.router);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  /**
   * One request. No cookie and no CSRF header by default (the connect tests' shape: with no
   * dashboard session the CSRF middleware has nothing to bind a token to). `cookie: true` sends
   * one, and `csrf: true` also echoes this session's token.
   */
  async function call(method, path, body, opts = {}) {
    const headers = {};
    if (opts.cookie === true) headers.cookie = `crow_session=${SESSION}`;
    if (opts.csrf === true) headers["x-crow-csrf"] = csrfTokenFor(SESSION);
    let payload;
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(body);
    }
    const res = await fetch(base + path, { method, headers, body: payload });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, text, json };
  }

  async function connectionRows() {
    return (await db.execute({
      sql: `SELECT uuid, project_id, service_id, status, config
              FROM service_connections WHERE service_id = 'coinbase' ORDER BY id`,
      args: [],
    })).rows;
  }

  async function activeConnection() {
    const rows = await connectionRows();
    return rows.filter((row) => row.status === "active")[0] || null;
  }

  async function keychainRows() {
    return (await db.execute({
      sql: "SELECT kind, env_key, status, bundle_id, connection_uuid FROM crow_keychain ORDER BY id",
      args: [],
    })).rows;
  }

  async function sealedToken(uuid) {
    const secrets = await K.serviceSecretsFor(db, await loadKey(), String(uuid), {
      allowedKeys: [TIINGO_ENV_KEY],
    });
    const value = secrets ? secrets[TIINGO_ENV_KEY] : null;
    return typeof value === "string" && value ? value : null;
  }

  return {
    db,
    projectId,
    fake,
    flags,
    stepUpGate,
    tiingoStore,
    tiingoCalls: tiingo.calls,
    connection: routes.connection,
    get: (path, opts) => call("GET", path, undefined, opts),
    post: (path, body, opts) => call("POST", path, body, opts),
    connect: (extra = {}) =>
      call("POST", "/api/coinbase/connect", {
        key_name: KEY_NAME,
        private_key: PRIVATE_KEY,
        project_id: projectId,
        totp: TOTP,
        ...extra,
      }),
    disconnect: () => call("POST", "/api/coinbase/disconnect", { totp: TOTP }),
    tiingoTest: (token, opts) => call("POST", TEST_ROUTE, { token }, opts),
    tiingoSave: (token, opts) => call("POST", SAVE_ROUTE, { token }, opts),
    tiingoDisconnect: (opts) => call("POST", DISCONNECT_ROUTE, {}, opts),
    tiingoState: (opts) => call("GET", STATE, undefined, opts),
    connections: connectionRows,
    activeConnection,
    keychain: keychainRows,
    sealedToken,
    audit: async () => (await db.execute({
      sql: "SELECT id, project_id, action, target, payload FROM project_audit_log ORDER BY id",
      args: [],
    })).rows,
    close: async () => {
      await closeServer(server);
      await fake.close();
      try { db.close(); } catch { /* already closed */ }
    },
  };
}

/**
 * Connect Coinbase and seal the token through the save route, on a scaffold the caller already
 * owns (so its `finally` closes the app and the fake engine whatever these assertions do).
 */
async function connectAndSave(h, token = TIINGO_TOKEN) {
  const connected = await within(h.connect(), "connect");
  assert.equal(connected.status, 200, connected.text);
  const saved = await within(h.tiingoSave(token), "save the token");
  assert.equal(saved.status, 200, saved.text);
  const row = await h.activeConnection();
  assert.ok(row, "the connection stands");
  return row;
}

after(async () => {
  for (const dir of DIRS) {
    try { rmScratch(dir); } catch { /* already gone */ }
  }
});

// ---- 1. a peer session gets nothing at all ----------------------------------------------------

test("tiingo_routes_refuse_a_peer_session", async () => {
  const h = await scaffold();
  try {
    h.flags.local = false;
    const attempts = [
      ["GET", STATE, undefined],
      ["POST", TEST_ROUTE, { token: TIINGO_TOKEN }],
      ["POST", SAVE_ROUTE, { token: TIINGO_TOKEN }],
      ["POST", DISCONNECT_ROUTE, {}],
    ];
    for (const [method, path, body] of attempts) {
      const r = method === "GET" ? await h.get(path) : await h.post(path, body);
      assert.equal(r.status, 403, `${method} ${path}: ${r.text}`);
      assert.equal(r.json && r.json.ok, false, `${method} ${path}`);
      assert.equal(r.json && r.json.code, "local_login_required", `${method} ${path}`);
    }
    assert.equal(h.fake.state.requests.length, 0, "the engine was never asked");
    assert.equal((await h.keychain()).length, 0, "nothing was sealed");
  } finally {
    await h.close();
  }
});

// ---- 2. no 2FA and no code: the routes are local-session only --------------------------------

test("tiingo_routes_need_no_2fa_and_no_code", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    const askedForConnect = h.stepUpGate.state.calls.length;
    assert.equal(askedForConnect, 1, "the Connect itself asked the gate once");

    // Two-factor off, and no code in any body: the token still tests, saves and disconnects.
    h.flags.twoFactor = false;

    const tested = await h.tiingoTest(TIINGO_TOKEN);
    assert.equal(tested.status, 200, tested.text);
    assert.equal(tested.json && tested.json.ok, true);
    assert.equal(tested.json && tested.json.message, MESSAGE_ACCEPTED);

    const saved = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(saved.status, 200, saved.text);
    assert.equal(saved.json && saved.json.ok, true);

    const state = await h.tiingoState();
    assert.equal(state.status, 200, state.text);
    assert.equal(state.json && state.json.sealed, true);

    const gone = await h.tiingoDisconnect();
    assert.equal(gone.status, 200, gone.text);
    assert.equal(gone.json && gone.json.message, MESSAGE_DISCONNECTED);

    assert.equal(
      h.stepUpGate.state.calls.length,
      askedForConnect,
      "no Tiingo route asked the step-up gate for a code",
    );
  } finally {
    await h.close();
  }
});

// ---- 3. the CSRF header every state-changing request carries --------------------------------

test("tiingo_post_refused_without_csrf", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);

    const refused = await h.tiingoTest(TIINGO_TOKEN, { cookie: true });
    assert.equal(refused.status, 403, refused.text);
    assert.match(refused.text, /CSRF/i, "the CSRF middleware's own refusal");
    assert.equal(h.fake.calls("POST", "/tiingo/check").length, 0, "nothing reached the engine");

    const accepted = await h.tiingoTest(TIINGO_TOKEN, { cookie: true, csrf: true });
    assert.equal(accepted.status, 200, accepted.text);
    assert.equal(accepted.json && accepted.json.ok, true);
    assert.equal(h.fake.calls("POST", "/tiingo/check").length, 1);

    // A refusal the session can answer for is a refusal for the save route too.
    const saveRefused = await h.tiingoSave(TIINGO_TOKEN, { cookie: true });
    assert.equal(saveRefused.status, 403, saveRefused.text);
    assert.equal(h.fake.calls("POST", "/tiingo").length, 0);
    const tiingoRows = (await h.keychain()).filter((entry) => entry.env_key === TIINGO_ENV_KEY);
    assert.equal(tiingoRows.length, 0, "no Tiingo row was sealed");
  } finally {
    await h.close();
  }
});

// ---- 4. the Test route asks the engine and seals nothing ------------------------------------

test("tiingo_test_route_seals_nothing", async () => {
  const h = await scaffold();
  try {
    const row = await connectAndSave(h);
    const before = h.fake.calls("POST", "/tiingo/check").length;
    const tested = await h.tiingoTest(TIINGO_TOKEN_2);
    assert.equal(tested.status, 200, tested.text);
    assert.equal(tested.json && tested.json.ok, true);
    assert.equal(tested.json && tested.json.message, MESSAGE_ACCEPTED);
    assert.equal(tested.text.includes(TIINGO_TOKEN_2), false, "the answer carries no token");

    const checks = h.fake.calls("POST", "/tiingo/check");
    assert.equal(checks.length, before + 1, "one check reached the engine");
    assert.equal(checks[checks.length - 1].mac, "owner", "the check is the owner's own request");
    assert.deepEqual(JSON.parse(checks[checks.length - 1].body), { token: TIINGO_TOKEN_2 });

    assert.equal(h.fake.calls("POST", "/tiingo").length, 1, "only the earlier save stored anything");
    const sealed = await h.sealedToken(row.uuid);
    assert.equal(sealed, TIINGO_TOKEN, "the Test route replaced no sealed value");
    const rows = (await h.keychain()).filter((entry) => entry.env_key === TIINGO_ENV_KEY);
    assert.equal(rows.length, 1, "one sealed row, from the save");

    // A body with no token is refused in the route's own words, before the engine hears of it.
    const empty = await h.tiingoTest("");
    assert.equal(empty.status, 400, empty.text);
    assert.equal(empty.json && empty.json.ok, false);
    assert.equal(empty.json && empty.json.code, "bad_request");
    assert.equal(empty.json && empty.json.message, MESSAGE_PASTE);
    assert.equal(h.fake.calls("POST", "/tiingo/check").length, checks.length, "nothing was sent");
  } finally {
    await h.close();
  }
});

// ---- 5. Save needs a Coinbase connection first ----------------------------------------------

test("tiingo_save_needs_coinbase_connected", async () => {
  const h = await scaffold();
  try {
    const refused = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(refused.status, 409, refused.text);
    assert.equal(refused.json && refused.json.ok, false);
    assert.equal(refused.json && refused.json.code, "not_connected");
    assert.equal(refused.json && refused.json.message, MESSAGE_CONNECT_FIRST);

    // The same answer for the Disconnect route: there is nothing to forget, and nothing sealed.
    const gone = await h.tiingoDisconnect();
    assert.ok(gone.status === 200 || gone.status === 409, gone.text);
    assert.equal(h.fake.calls("DELETE", "/tiingo").length, 0, "no engine call with nothing connected");

    assert.equal(h.fake.state.requests.length, 0, "the engine was never asked");
    assert.equal((await h.keychain()).length, 0, "nothing was sealed");
  } finally {
    await h.close();
  }
});

// ---- 6. Save seals one row under the connection, then pushes it ------------------------------

test("tiingo_save_seals_once_then_pushes", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    const row = await h.activeConnection();
    assert.ok(row);

    const saved = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(saved.status, 200, saved.text);
    assert.equal(saved.json && saved.json.ok, true);
    assert.notEqual(saved.json && saved.json.pending, true, "the engine answered, so nothing is pending");
    assert.equal(saved.text.includes(TIINGO_TOKEN), false, "the answer carries no token");

    // The engine was asked to test it and then told to keep it, in that order.
    const order = h.fake.state.requests.map((request) => `${request.method} ${request.path}`);
    const atCheck = order.lastIndexOf("POST /tiingo/check");
    const atSet = order.lastIndexOf("POST /tiingo");
    assert.ok(atCheck !== -1, "the token was tested first");
    assert.ok(atSet > atCheck, "the seal happens after the engine accepted the token");
    const setCall = h.fake.calls("POST", "/tiingo")[0];
    assert.equal(setCall.mac, "owner");
    assert.deepEqual(JSON.parse(setCall.body), { token: TIINGO_TOKEN });

    // One row, on the standing Coinbase connection, holding the pasted value.
    const sealedRows = (await h.keychain()).filter((entry) => entry.env_key === TIINGO_ENV_KEY);
    assert.equal(sealedRows.length, 1, "exactly one sealed Tiingo row");
    assert.equal(sealedRows[0].kind, "service");
    assert.equal(sealedRows[0].bundle_id, "coinbase");
    assert.equal(sealedRows[0].status, "active");
    assert.equal(sealedRows[0].connection_uuid, row.uuid, "the row lives on the Coinbase connection");
    assert.equal(await h.sealedToken(row.uuid), TIINGO_TOKEN, "the sealed value is the pasted value");
    assert.ok(h.tiingoCalls.save.length <= 1, "no second seal for one save");

    // Saving another value replaces that one row rather than adding a second.
    const again = await h.tiingoSave(TIINGO_TOKEN_2);
    assert.equal(again.status, 200, again.text);
    const after = (await h.keychain()).filter((entry) => entry.env_key === TIINGO_ENV_KEY);
    assert.equal(after.length, 1, "still one row");
    assert.equal(after[0].connection_uuid, row.uuid);
    assert.equal(await h.sealedToken(row.uuid), TIINGO_TOKEN_2);
  } finally {
    await h.close();
  }
});

// ---- 7. an engine refusal seals nothing -----------------------------------------------------

test("tiingo_save_refused_by_the_engine_seals_nothing", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    const row = await h.activeConnection();

    h.fake.nextTiingoCheck({
      status: 200,
      body: { state: "refused", code: "TOKEN_REJECTED", message: MESSAGE_REJECTED },
    });
    const refused = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(refused.json && refused.json.ok, false, refused.text);
    assert.equal(refused.json && refused.json.code, "TOKEN_REJECTED");
    assert.equal(refused.json && refused.json.message, MESSAGE_REJECTED);
    assert.equal(refused.text.includes(TIINGO_TOKEN), false, "the answer carries no token");

    assert.equal(h.fake.calls("POST", "/tiingo").length, 0, "the engine was never told to keep it");
    assert.equal((await h.keychain()).filter((entry) => entry.env_key === TIINGO_ENV_KEY).length, 0);
    assert.equal(await h.sealedToken(row.uuid), null);
    assert.equal(h.tiingoCalls.save.length, 0, "nothing was sealed");

    // The engine's own shape refusal reaches the owner in the engine's fixed sentence.
    h.fake.nextTiingoCheck({
      status: 200,
      body: { state: "refused", code: "TOKEN_SHAPE", message: MESSAGE_TOKEN_SHAPE },
    });
    const shaped = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(shaped.json && shaped.json.ok, false);
    assert.equal(shaped.json && shaped.json.code, "TOKEN_SHAPE");
    assert.equal(shaped.json && shaped.json.message, MESSAGE_TOKEN_SHAPE);
    assert.equal((await h.keychain()).filter((entry) => entry.env_key === TIINGO_ENV_KEY).length, 0);
  } finally {
    await h.close();
  }
});

// ---- 8. an engine that is down after the seal keeps it, and the answer says so --------------

test("tiingo_save_pending_when_the_engine_is_down_after_the_seal", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    const row = await h.activeConnection();

    // The check is answered; the push is not.
    h.fake.state.tiingoSetDown = true;
    const saved = await within(h.tiingoSave(TIINGO_TOKEN), "save with the engine down");
    assert.equal(saved.status, 200, saved.text);
    assert.equal(saved.json && saved.json.ok, true, "the token is saved even though the push failed");
    assert.equal(saved.json && saved.json.pending, true);
    assert.equal(saved.json && saved.json.message, MESSAGE_PENDING);
    assert.equal(saved.text.includes(TIINGO_TOKEN), false, "the answer carries no token");

    assert.equal(await h.sealedToken(row.uuid), TIINGO_TOKEN, "the sealed token stays for the next push");
    assert.equal(h.fake.calls("POST", "/tiingo").length, 1, "the push was attempted");
  } finally {
    await h.close();
  }
});

// ---- 9. Disconnect drops the sealed row, then tells the engine ------------------------------

test("tiingo_disconnect_removes_the_row_then_clears_the_engine", async () => {
  const h = await scaffold();
  try {
    const row = await connectAndSave(h);
    const done = await h.tiingoDisconnect();
    assert.equal(done.status, 200, done.text);
    assert.equal(done.json && done.json.ok, true);
    assert.equal(done.json && done.json.message, MESSAGE_DISCONNECTED);

    const clears = h.fake.calls("DELETE", "/tiingo");
    assert.equal(clears.length, 1, "the engine was told to forget the token");
    assert.equal(clears[0].mac, "owner", "the forget is the owner's own request");
    assert.equal(clears[0].body, "", "a forget carries no body");

    assert.equal((await h.keychain()).filter((entry) => entry.env_key === TIINGO_ENV_KEY).length, 0);
    assert.equal(await h.sealedToken(row.uuid), null, "no sealed token is left to read");
    assert.ok(h.tiingoCalls.remove.length <= 1, "one removal for one Disconnect");

    // The state says it too, and carries no token.
    const state = await h.tiingoState();
    assert.equal(state.status, 200, state.text);
    assert.equal(state.json && state.json.sealed, false);
    assert.equal(state.text.includes(TIINGO_TOKEN), false);

    // The engine is not answering: the sealed row still goes, and the owner is told so.
    const saved = await h.tiingoSave(TIINGO_TOKEN_2);
    assert.equal(saved.status, 200, saved.text);
    h.fake.state.tiingoDeleteDown = true;
    const gone = await within(h.tiingoDisconnect(), "disconnect with the engine down");
    assert.equal(gone.status, 200, gone.text);
    assert.equal(gone.json && gone.json.ok, true);
    assert.equal(gone.json && gone.json.message, MESSAGE_DISCONNECTED);
    assert.equal(
      (await h.keychain()).filter((entry) => entry.env_key === TIINGO_ENV_KEY && entry.status === "active").length,
      0,
      "the sealed row is gone even though the engine never answered",
    );
    assert.equal(await h.sealedToken(row.uuid), null);
  } finally {
    await h.close();
  }
});

// ---- 10. the state route answers four flags and no token ------------------------------------

test("tiingo_state_answers_exactly_the_contract", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    const row = await h.activeConnection();

    const fresh = await h.tiingoState();
    assert.equal(fresh.status, 200, fresh.text);
    assert.deepEqual(
      Object.keys(fresh.json || {}).sort(),
      ["connected", "message", "ok", "rejected", "sealed"],
      "exactly the five keys the contract names",
    );
    assert.equal(fresh.json.ok, true);
    assert.equal(fresh.json.connected, false);
    assert.equal(fresh.json.sealed, false);
    assert.equal(fresh.json.rejected, false);
    assert.equal(fresh.json.message === null || typeof fresh.json.message === "string", true);

    const saved = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(saved.status, 200, saved.text);

    // The engine reports the token connected: the state says so and still names no token.
    h.fake.state.priceState = "connected";
    const connecting = await h.tiingoState();
    assert.equal(connecting.json.sealed, true);
    assert.equal(connecting.json.connected, true);
    assert.equal(connecting.json.rejected, false);
    assert.equal(connecting.text.includes(TIINGO_TOKEN), false);
    assert.equal(JSON.stringify(connecting.json).includes(TIINGO_TOKEN), false);
    assert.equal(Object.hasOwn(connecting.json, "token"), false, "no token field, ever");
    assert.equal(Object.hasOwn(connecting.json, "last4"), false, "not even a fingerprint");

    // The engine reports the token refused: rejected, and not connected.
    h.fake.state.priceState = "rejected";
    const rejected = await h.tiingoState();
    assert.equal(rejected.json.sealed, true);
    assert.equal(rejected.json.rejected, true);
    assert.equal(rejected.json.connected, false);

    // A last4 of the sealed value never reaches the answer either.
    assert.equal(String(rejected.json.message || "").includes(TIINGO_TOKEN.slice(-4)), false);
    assert.equal(row.uuid, (await h.activeConnection()).uuid);
  } finally {
    await h.close();
  }
});

// ---- 11. a re-push sends the sealed token and keeps the credentials result ------------------

test("tiingo_token_rides_along_on_a_credentials_repush", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    const saved = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(saved.status, 200, saved.text);
    const setsAfterSave = h.fake.calls("POST", "/tiingo").length;

    // A successful credentials push also hands the token to the engine.
    const repushed = await h.connection.repush();
    assert.equal(repushed.ok, true, JSON.stringify(repushed));
    const sets = h.fake.calls("POST", "/tiingo");
    assert.equal(sets.length, setsAfterSave + 1, "the re-push sent the sealed token once");
    const pushed = sets[sets.length - 1];
    assert.deepEqual(JSON.parse(pushed.body), { token: TIINGO_TOKEN });
    assert.equal(pushed.mac, "owner");
    assert.equal(JSON.stringify(repushed).includes(TIINGO_TOKEN), false, "the result carries no token");

    // A failing setTiingo never changes the credentials result.
    h.fake.state.tiingoSetDown = true;
    const attempted = h.fake.calls("POST", "/tiingo").length;
    const stillFine = await within(h.connection.repush(), "re-push with the Tiingo push refused");
    assert.equal(stillFine.ok, true, JSON.stringify(stillFine));
    assert.equal(h.fake.calls("POST", "/tiingo").length, attempted + 1, "the token push was attempted");
    h.fake.state.tiingoSetDown = false;

    // A missing sealed token changes nothing about the credentials result, and sends nothing.
    await h.db.execute({ sql: "DELETE FROM crow_keychain WHERE env_key = ?", args: [TIINGO_ENV_KEY] });
    const beforeMissing = h.fake.calls("POST", "/tiingo").length;
    const missing = await h.connection.repush();
    assert.equal(missing.ok, true, JSON.stringify(missing));
    assert.equal(h.fake.calls("POST", "/tiingo").length, beforeMissing, "nothing is sent with no sealed token");

    // A FAILED credentials push sends no token at all.
    const resealed = await h.tiingoSave(TIINGO_TOKEN_2);
    assert.equal(resealed.status, 200, resealed.text);
    h.fake.nextPush({ status: 403, body: { detail: "APPROVAL_INVALID" } });
    const beforeFailed = h.fake.calls("POST", "/tiingo").length;
    const failed = await h.connection.repush();
    assert.equal(failed.ok, false, JSON.stringify(failed));
    assert.equal(failed.code, "APPROVAL_INVALID");
    assert.equal(
      h.fake.calls("POST", "/tiingo").length,
      beforeFailed,
      "a credentials push the engine refused is never followed by a token",
    );
    assert.equal(JSON.stringify(failed).includes(TIINGO_TOKEN_2), false);
  } finally {
    await h.close();
  }
});

// ---- 12. Coinbase Disconnect also clears the prices token -----------------------------------

test("coinbase_disconnect_also_clears_the_prices_token", async () => {
  const h = await scaffold();
  try {
    const row = await connectAndSave(h);
    const clearsBefore = h.fake.calls("DELETE", "/tiingo").length;
    const done = await h.disconnect();
    assert.equal(done.status, 200, done.text);

    const clears = h.fake.calls("DELETE", "/tiingo");
    assert.equal(clears.length, clearsBefore + 1, "the engine is told to forget the token");

    const left = (await h.keychain()).filter(
      (entry) => entry.env_key === TIINGO_ENV_KEY && entry.status === "active",
    );
    assert.equal(left.length, 0, "no active sealed token survives the Disconnect");
    assert.equal(await h.sealedToken(row.uuid), null);

    const state = await h.tiingoState();
    assert.equal(state.status, 200, state.text);
    assert.equal(state.json && state.json.sealed, false);
  } finally {
    await h.close();
  }
});

// ---- 1a. a paused allowance: the token is fine, the prices wait ---------------------------------

test("tiingo_state_says_paused_while_tiingo_is_limiting_crow", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    const saved = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(saved.status, 200, saved.text);

    h.fake.state.priceState = "paused";
    h.fake.state.priceMessage = CANARY;
    const paused = await h.tiingoState();
    assert.equal(paused.status, 200, paused.text);
    assert.deepEqual(
      Object.keys(paused.json || {}).sort(),
      ["connected", "message", "ok", "rejected", "sealed"],
      "a paused state still answers exactly the five keys",
    );
    assert.equal(paused.json.connected, true, "the token is fine; only the prices are waiting");
    assert.equal(paused.json.rejected, false, "a pause is not a refusal");
    assert.equal(paused.json.sealed, true);
    assert.equal(paused.json.message, MESSAGE_PRICES_PAUSED);
    assert.equal(paused.text.includes(TIINGO_TOKEN), false, "the answer carries no token");
    assert.equal(paused.text.includes(CANARY), false, "the engine's own sentence is not repeated");

    // A pause is a steady state: the same connection answers the same way twice.
    const again = await h.tiingoState();
    assert.deepEqual(again.json, paused.json);
  } finally {
    await h.close();
  }
});

// ---- 1b. a reconnect carries the sealed token onto the new connection --------------------------

test("reconnect_copies_the_sealed_token_onto_the_new_connection", async () => {
  const snapshots = [];
  let db = null;
  const h = await scaffold({ routes: { tiingoStore: observingTiingoStore(() => db, { snapshots }) } });
  db = h.db;
  try {
    const first = await h.connect();
    assert.equal(first.status, 200, first.text);
    const firstRow = await h.activeConnection();
    assert.ok(firstRow, "the first connection stands");
    const saved = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(saved.status, 200, saved.text);
    assert.equal(await h.sealedToken(firstRow.uuid), TIINGO_TOKEN);
    const setsAfterSave = h.fake.calls("POST", "/tiingo").length;
    // Only the reconnect's own copy is of interest from here.
    snapshots.length = 0;

    // The engine lost its pin: this Connect replaces the connection, and the token has to come
    // with it or the owner pastes it again.
    h.fake.state.pinned = false;
    h.fake.state.pinSecret = null;
    h.fake.state.credentials = "not_ready";
    const again = await within(h.connect(), "reconnect over the standing connection");
    assert.equal(again.status, 200, again.text);
    assert.equal(again.json && again.json.ok, true);
    assert.equal(again.text.includes(TIINGO_TOKEN), false, "the connect answer carries no token");

    const rows = await h.connections();
    const active = rows.filter((row) => row.status === "active");
    assert.equal(active.length, 1, "one connection stands");
    const newRow = active[0];
    assert.notEqual(newRow.uuid, firstRow.uuid, "the reconnect made a new connection");
    assert.equal(await h.sealedToken(newRow.uuid), TIINGO_TOKEN, "the sealed token came with the reconnect");

    // The token was copied while the row it came from still stood: the copy is made before the
    // other active rows are disconnected.
    const copy = snapshots[0];
    assert.ok(copy, "the token was copied with tiingoStore.save");
    const oldAtCopy = copy.find((row) => row.uuid === firstRow.uuid);
    assert.ok(oldAtCopy, `the old connection was still there at the copy: ${JSON.stringify(copy)}`);
    assert.equal(oldAtCopy.status, "active", "the copy comes before the old connection is let go");
    assert.ok(
      copy.some((row) => row.uuid === newRow.uuid && row.status === "active"),
      "the copy lands on the connection that stands",
    );

    // Then the engine is handed it with the new client's setTiingo.
    const sets = h.fake.calls("POST", "/tiingo");
    assert.equal(sets.length, setsAfterSave + 1, "the token is pushed once more after the reconnect");
    const pushed = sets[sets.length - 1];
    assert.equal(pushed.mac, "owner");
    assert.deepEqual(JSON.parse(pushed.body), { token: TIINGO_TOKEN });

    // And the token is in no answer and no audit row.
    assert.equal(again.text.includes(TIINGO_TOKEN), false);
    assert.equal(JSON.stringify(await h.audit()).includes(TIINGO_TOKEN), false, "no audit row carries it");
  } finally {
    await h.close();
  }
});

test("a_reconnect_that_cannot_copy_the_token_still_connects", async () => {
  let failing = false;
  let db = null;
  const h = await scaffold({ routes: { tiingoStore: observingTiingoStore(() => db, { failCopy: () => failing }) } });
  db = h.db;
  try {
    const first = await h.connect();
    assert.equal(first.status, 200, first.text);
    const firstRow = await h.activeConnection();
    assert.ok(firstRow);
    const saved = await h.tiingoSave(TIINGO_TOKEN);
    assert.equal(saved.status, 200, saved.text);
    assert.equal(await h.sealedToken(firstRow.uuid), TIINGO_TOKEN);
    const setsBefore = h.fake.calls("POST", "/tiingo").length;

    // The keychain will not take the copy: the connection is the answer, the token is a maybe.
    failing = true;
    h.fake.state.pinned = false;
    h.fake.state.pinSecret = null;
    h.fake.state.credentials = "not_ready";
    const again = await within(h.connect(), "reconnect with a copy that cannot be sealed");
    assert.equal(again.status, 200, again.text);
    assert.equal(again.json && again.json.ok, true, "the connection stands although the token was not copied");
    assert.equal(again.text.includes(TIINGO_TOKEN), false, "the answer carries no token");

    const active = (await h.connections()).filter((row) => row.status === "active");
    assert.equal(active.length, 1);
    const newRow = active[0];
    assert.notEqual(newRow.uuid, firstRow.uuid);
    assert.equal(await h.sealedToken(newRow.uuid), null, "nothing was sealed on the new connection");
    const pushes = h.fake.calls("POST", "/tiingo").length - setsBefore;
    assert.ok(pushes <= 1, `at most one attempt with no token to copy (found ${pushes})`);
    assert.equal(JSON.stringify(await h.audit()).includes(TIINGO_TOKEN), false, "no audit row carries it");
  } finally {
    await h.close();
  }
});

// ---- 1c. the carry is scoped to the connection's own project ---------------------------------

/**
 * One active Coinbase row of the service, written the way the connect route writes it:
 * `createPanelConnection` inserts the row (`owner_contact_id` NULL, method and bundle of a panel
 * service, one label slug) and flips it to 'active', then `finishConnect` puts the engine epoch in
 * the config. `readActiveRow` reads the newest such row as the standing connection and
 * `otherActiveRows` finds it beside the one a reconnect makes.
 */
async function insertActiveConnection(db, projectId, { engineEpoch, accountLabel = "Crow portfolio" }) {
  const uuid = randomBytes(16).toString("hex");
  const slug = accountLabel.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  await db.execute({
    sql: `INSERT INTO service_connections
            (uuid, project_id, owner_contact_id, service_id, bundle_id, method, account_label,
             label_slug, config, status, source_connection_id, last_error)
          VALUES (?, ?, NULL, 'coinbase', 'coinbase', 'panel', ?, ?, ?, 'active', NULL, NULL)`,
    args: [uuid, projectId, accountLabel, slug, JSON.stringify({ engine_epoch: engineEpoch })],
  });
  return uuid;
}

test("reconnect_carries_only_the_token_of_its_own_project", async () => {
  const h = await scaffold();
  try {
    // Project A: a connection the panel made, with its own sealed token.
    const firstRow = await connectAndSave(h, TIINGO_TOKEN);
    assert.equal(Number(firstRow.project_id), h.projectId);
    const setsAfterSave = h.fake.calls("POST", "/tiingo").length;

    // Project B: an active row of the same service standing in ANOTHER project, holding the token
    // the reconnect below has to carry, because that reconnect is made in project B.
    const otherProject = await mkProject(h.db, "Trading tiingo another project");
    const ownUuid = await insertActiveConnection(h.db, otherProject, {
      engineEpoch: "engine-epoch-other-project",
    });
    await h.tiingoStore.save(ownUuid, TIINGO_TOKEN_2);
    assert.equal(await h.sealedToken(ownUuid), TIINGO_TOKEN_2, "the row in project B holds its own token");

    // The engine lost its pin: the project B connection is replaced, and only a token sealed in
    // that same project may come with it.
    h.fake.state.pinned = false;
    h.fake.state.pinSecret = null;
    h.fake.state.credentials = "not_ready";
    const again = await within(h.connect({ project_id: otherProject }), "reconnect in the other project");
    assert.equal(again.status, 200, again.text);
    assert.equal(again.json && again.json.ok, true);
    assert.equal(again.text.includes(TIINGO_TOKEN), false, "the connect answer carries no token");
    assert.equal(again.text.includes(TIINGO_TOKEN_2), false, "the connect answer carries no token");

    const rows = await h.connections();
    const active = rows.filter((row) => row.status === "active");
    assert.equal(active.length, 1, "one connection stands");
    const newRow = active[0];
    assert.equal(Number(newRow.project_id), otherProject, "the connection stands in its own project");
    assert.notEqual(newRow.uuid, ownUuid, "the reconnect made a new connection");

    // The token of the connection this one replaces is carried over; the one sealed in project A is
    // not, even though that row comes first in the table.
    assert.equal(
      await h.sealedToken(newRow.uuid),
      TIINGO_TOKEN_2,
      "the token on the new connection is the one sealed in its own project",
    );
    const carried = h.fake.calls("POST", "/tiingo").slice(setsAfterSave);
    assert.equal(carried.length, 1, "the engine was handed one carried token after the reconnect");
    assert.deepEqual(JSON.parse(carried[0].body), { token: TIINGO_TOKEN_2 });
    assert.equal(
      carried.some((call) => String(call.body).includes(TIINGO_TOKEN)),
      false,
      "the token of the project A connection never reached the engine",
    );

    // Letting go of every other active row of the service still crosses projects.
    const statusOf = (uuid) =>
      String((rows.find((row) => String(row.uuid) === String(uuid)) || {}).status || "");
    assert.equal(statusOf(firstRow.uuid), "disconnected", "the row in project A is disconnected too");
    assert.equal(statusOf(ownUuid), "disconnected", "the row being replaced is disconnected");

    assert.equal(JSON.stringify(await h.audit()).includes(TIINGO_TOKEN), false, "no audit row carries a token");
    assert.equal(JSON.stringify(await h.audit()).includes(TIINGO_TOKEN_2), false, "no audit row carries a token");
  } finally {
    await h.close();
  }
});

// ---- 1d. the project id a reconnect can name ------------------------------------------------

/**
 * The carry's own argument is the contract's item 3: a `projectId` that is not a positive integer
 * carries nothing. `carrySealedTiingo` is a closure inside `createConnectRoutes` — not exported,
 * and with no seam option — so the routes are the only way to it, and what a test can show is the
 * boundary they stand on: an unusable id makes no connection, seals nothing and carries nothing,
 * and a standing connection's carry stays inside its own project. Both run on the option-free
 * path: `tiingoStore: null` hands the routes no seam at all, so they build and use their own.
 */

const BAD_PROJECT_IDS = [0, -3, 2.5, "abc", "", null, true];

test("connect_naming_no_positive_integer_project_id_is_refused_before_anything_is_carried", async () => {
  const h = await scaffold({ routes: { tiingoStore: null } });
  try {
    for (const projectId of BAD_PROJECT_IDS) {
      const refused = await h.connect({ project_id: projectId });
      const label = JSON.stringify(projectId);
      assert.equal(refused.status, 400, `${label}: ${refused.text}`);
      assert.equal(refused.json && refused.json.ok, false, label);
      assert.equal(refused.json && refused.json.code, "bad_request", label);
      assert.equal(refused.json && refused.json.message, MESSAGE_PICK_PROJECT, label);
    }

    // No project_id at all is the same refusal (an undefined value never reaches the body).
    const omitted = await h.post("/api/coinbase/connect", {
      key_name: KEY_NAME,
      private_key: PRIVATE_KEY,
      totp: TOTP,
    });
    assert.equal(omitted.status, 400, omitted.text);
    assert.equal(omitted.json && omitted.json.code, "bad_request");
    assert.equal(omitted.json && omitted.json.message, MESSAGE_PICK_PROJECT);

    assert.equal((await h.connections()).length, 0, "no connection row was made");
    assert.equal((await h.keychain()).length, 0, "nothing was sealed");
    assert.equal(h.tiingoCalls.save.length, 0, "nothing was carried onto a connection");
    assert.equal(h.fake.state.requests.length, 0, "the engine was never asked");
  } finally {
    await h.close();
  }
});

test("reconnect_carries_the_same_project_token_on_the_option_free_path", async () => {
  const h = await scaffold({ routes: { tiingoStore: null } });
  try {
    const firstRow = await connectAndSave(h, TIINGO_TOKEN);
    assert.equal(h.tiingoCalls.save.length, 0, "the routes sealed the paste through their own seam");
    assert.equal(await h.sealedToken(firstRow.uuid), TIINGO_TOKEN);
    const setsAfterSave = h.fake.calls("POST", "/tiingo").length;

    h.fake.state.pinned = false;
    h.fake.state.pinSecret = null;
    h.fake.state.credentials = "not_ready";
    const again = await within(h.connect(), "reconnect with no seam handed in");
    assert.equal(again.status, 200, again.text);
    assert.equal(again.json && again.json.ok, true);
    assert.equal(again.text.includes(TIINGO_TOKEN), false, "the connect answer carries no token");

    const rows = await h.connections();
    const active = rows.filter((row) => row.status === "active");
    assert.equal(active.length, 1, "one connection stands");
    const newRow = active[0];
    assert.notEqual(newRow.uuid, firstRow.uuid, "the reconnect made a new connection");
    assert.equal(Number(newRow.project_id), h.projectId, "the reconnect stays in its own project");
    assert.equal(await h.sealedToken(newRow.uuid), TIINGO_TOKEN, "the project's own token came with it");

    const carried = h.fake.calls("POST", "/tiingo").slice(setsAfterSave);
    assert.equal(carried.length, 1, "one carried token after the reconnect");
    assert.equal(carried[0].mac, "owner", "the carried token is the owner's own push");
    assert.deepEqual(JSON.parse(carried[0].body), { token: TIINGO_TOKEN });

    const old = rows.find((row) => String(row.uuid) === String(firstRow.uuid));
    assert.ok(old, "the replaced row is kept, not deleted");
    assert.equal(String(old.status), "disconnected", "the reconnect lets the replaced row go as well");
    assert.equal(h.tiingoCalls.save.length, 0, "the carry wrote through the routes' own seam too");
  } finally {
    await h.close();
  }
});

test("reconnect_naming_no_positive_integer_project_id_carries_only_its_own_project_token", async () => {
  // 0 and null stand for the whole list: the route turns every unusable id into the same null.
  for (const projectId of [0, null]) {
    const label = JSON.stringify(projectId);
    const h = await scaffold({ routes: { tiingoStore: null } });
    try {
      // Project A, the connection the panel made: it holds the token.
      const firstRow = await connectAndSave(h, TIINGO_TOKEN);
      assert.equal(Number(firstRow.project_id), h.projectId, label);

      // Project B: an active row of the same service holding its own sealed token. It is the bait
      // a carry would find first if an unusable id widened its read beyond the standing project.
      const otherProject = await mkProject(h.db, "Trading tiingo foreign project");
      const foreignUuid = await insertActiveConnection(h.db, otherProject, {
        engineEpoch: "engine-epoch-foreign",
      });
      await h.tiingoStore.save(foreignUuid, TIINGO_TOKEN_2);
      assert.equal(await h.sealedToken(foreignUuid), TIINGO_TOKEN_2, label);

      // A newer row of project A stands, so the connection this reconnect replaces is project A's.
      const standingUuid = await insertActiveConnection(h.db, h.projectId, {
        engineEpoch: "engine-epoch-standing",
        accountLabel: "Crow portfolio two",
      });
      const setsAfterSave = h.fake.calls("POST", "/tiingo").length;

      h.fake.state.pinned = false;
      h.fake.state.pinSecret = null;
      h.fake.state.credentials = "not_ready";
      const again = await within(h.connect({ project_id: projectId }), `reconnect naming ${label}`);
      assert.equal(again.status, 200, `${label}: ${again.text}`);
      assert.equal(again.json && again.json.ok, true, label);
      assert.equal(again.text.includes(TIINGO_TOKEN), false, `${label}: the answer carries no token`);
      assert.equal(again.text.includes(TIINGO_TOKEN_2), false, `${label}: the answer carries no token`);

      const rows = await h.connections();
      const active = rows.filter((row) => row.status === "active");
      assert.equal(active.length, 1, `${label}: one connection stands`);
      const newRow = active[0];
      assert.equal(Number(newRow.project_id), h.projectId, `${label}: the reconnect stayed in the standing project`);
      assert.notEqual(newRow.uuid, standingUuid, label);
      assert.equal(
        await h.sealedToken(newRow.uuid),
        TIINGO_TOKEN,
        `${label}: the token of the standing project came with it`,
      );

      const carried = h.fake.calls("POST", "/tiingo").slice(setsAfterSave);
      assert.equal(carried.length, 1, `${label}: one carried token after the reconnect`);
      assert.deepEqual(JSON.parse(carried[0].body), { token: TIINGO_TOKEN }, label);
      assert.equal(
        carried.some((call) => String(call.body).includes(TIINGO_TOKEN_2)),
        false,
        `${label}: the token sealed in the other project never reached the engine`,
      );

      // Every other active row of the service is let go whatever project it stands in: only the
      // carry is narrowed, never the disconnect.
      const statusOf = (uuid) =>
        String((rows.find((row) => String(row.uuid) === String(uuid)) || {}).status || "");
      assert.equal(statusOf(firstRow.uuid), "disconnected", label);
      assert.equal(statusOf(foreignUuid), "disconnected", `${label}: the other project's row goes too`);
      assert.equal(statusOf(standingUuid), "disconnected", label);

      // Only the bait went through the harness's seam: every carry and seal was the routes' own.
      assert.equal(h.tiingoCalls.save.length, 1, `${label}: the harness seam sealed the bait and nothing else`);
    } finally {
      await h.close();
    }
  }
});

// ---- 13. the audit rows the Tiingo routes file ----------------------------------------------

test("tiingo_audit_rows_carry_only_ok_and_code", async () => {
  const h = await scaffold();
  try {
    await connectAndSave(h);
    const tested = await h.tiingoTest(TIINGO_TOKEN_2);
    assert.equal(tested.status, 200, tested.text);
    const gone = await h.tiingoDisconnect();
    assert.equal(gone.status, 200, gone.text);

    const rows = (await h.audit()).filter((entry) => String(entry.action).startsWith("coinbase.tiingo"));
    const actions = rows.map((entry) => String(entry.action));
    assert.ok(actions.includes("coinbase.tiingo_connect"), `an audit row for a save: ${actions.join(", ")}`);
    assert.ok(actions.includes("coinbase.tiingo_disconnect"), `an audit row for a Disconnect: ${actions.join(", ")}`);

    for (const entry of rows) {
      const payload = JSON.parse(String(entry.payload || "{}"));
      for (const name of Object.keys(payload)) {
        assert.ok(
          name === "ok" || name === "code",
          `${entry.action}: the payload carries ${name}, and it may carry only ok and code`,
        );
      }
      const text = JSON.stringify(entry);
      for (const value of [TIINGO_TOKEN, TIINGO_TOKEN_2, CANARY]) {
        assert.equal(text.includes(value), false, `${entry.action}: an audit row carries no token`);
      }
    }
  } finally {
    await h.close();
  }
});

// ---- 14. the token never reaches an answer, an audit row or a thrown message ---------------

test("tiingo_canary_never_leaves_the_server", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);

    const answers = [];
    const thrown = [];
    const run = async (label, promise) => {
      try {
        const answer = await promise;
        answers.push({ label, answer });
        return answer;
      } catch (err) {
        thrown.push({ label, err });
        return null;
      }
    };

    // A check that passes, a save, another save whose engine sentence echoes the canary, the
    // state, a Disconnect and a Save the route itself refuses.
    h.fake.nextTiingoCheck({
      status: 200,
      body: { state: "refused", code: "TOKEN_REJECTED", message: `Tiingo did not accept ${CANARY}.` },
    });
    await run("save refused with an echoing sentence", h.tiingoSave(CANARY));
    await run("test", h.tiingoTest(CANARY));
    await run("save", h.tiingoSave(CANARY));
    await run("state", h.tiingoState());
    await run("save with no token", h.tiingoSave(""));
    await run("disconnect", h.tiingoDisconnect());
    await run("state after disconnect", h.tiingoState());

    assert.deepEqual(thrown.map((entry) => entry.label), [], "no route throws");
    assert.equal(answers.length, 7);

    // The engine did receive the value (the test is about the answers, not the request).
    assert.ok(
      h.fake.state.requests.some((request) => String(request.body).includes(CANARY)),
      "the canary reached the engine's request body",
    );

    for (const { label, answer } of answers) {
      assert.equal(answer.text.includes(CANARY), false, `${label}: the answer carries no token`);
      if (answer.json) {
        assert.equal(JSON.stringify(answer.json).includes(CANARY), false, `${label}: no answer field carries it`);
      }
    }

    const auditText = JSON.stringify(await h.audit());
    assert.equal(auditText.includes(CANARY), false, "no audit row carries the token");
    assert.equal(auditText.includes(TIINGO_TOKEN), false);
  } finally {
    await h.close();
  }
});