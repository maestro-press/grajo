/**
 * The Coinbase Trading panel's Connect flow: the three POSTs and the state GET, the key and
 * the approval secret sealed on one connection, the MAC every engine push is signed with, the
 * forget the Disconnect route asks the engine for, the copy the panel shows, and the owner's
 * audit rows.
 *
 * A scratch Crow home (an install token under coinbase/install/), an init-db database per test, and a
 * fake trading engine on loopback that keeps the pin, the epoch and the MAC each request was
 * signed with. The fake engine can drop the answer to a push after taking (or refusing) it,
 * refuse a forget, or be wiped and restarted. The step-up gate is a fake too: the real one is
 * about time steps and the browser, and its own test file holds it. The service catalog is the
 * real registry entry (service id "coinbase"); every secret here is a synthetic value built at
 * run time.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import express from "express";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import { rmScratch } from "./helpers/safe-rm.js";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = mkdtempSync(join(tmpdir(), "crow-coinbase-connect-home-"));
const DATA = mkdtempSync(join(tmpdir(), "crow-coinbase-connect-data-"));
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
const { panelSecretsFor } = await import("../servers/shared/service-connections.js");
const { createConnectRoutes, createConnectionStore, COPY_STEPS, fixit } =
  await import("../bundles/coinbase/panel/connect.js");
const { startLoops } = await import("../bundles/coinbase/server/loops.js");

const ENGINE_TOKEN = "test-token-coinbase-panel-engine-2f9c";
const KEY_NAME = "organizations/test-org/apiKeys/test-key-9137b";
const TOTP = "123456";
const APPROVE_SECRET_CHARS = 43;

const CONNECT = "/api/coinbase/connect";
const CONNECT_TEST = "/api/coinbase/connect/test";
const CONNECT_STATE = "/api/coinbase/connect/state";
const DISCONNECT = "/api/coinbase/disconnect";

const SECRET_NAMES = ["COINBASE_KEY_NAME", "COINBASE_PRIVATE_KEY", "COINBASE_APPROVE_SECRET"];

const STEPS =
  "1. In Coinbase, create a portfolio named Crow and move only the money you want the bot to use. " +
  "2. Create an API key for the Crow portfolio with View and Trade. Do not tick Transfer. " +
  "3. Paste the key name and private key here. 4. Press Test connection.";
const DEFAULT_PORTFOLIO_MESSAGE =
  "This key is for your main Coinbase portfolio. Create a key for the Crow portfolio instead.";
const WRONG_PORTFOLIO_MESSAGE =
  "This key is for a different portfolio than the one Crow trades. Create a key for the Crow portfolio.";
const GENERIC_MESSAGE = "Crow could not connect to Coinbase. Try again.";
const TWO_FACTOR_MESSAGE = "Turn on two-factor sign-in first (Settings \u2192 Security)";
const ACCEPTED_MESSAGE = "Key accepted \u2014 Crow portfolio \u20265678";
const CONNECTED_MESSAGE = "Connected \u2014 Crow portfolio \u20265678";
const STORE_KEYS = ["projectId", "engineEpoch", "needsReconnect", "disconnecting"];
const TOTP_REQUIRED_MESSAGE = "Enter your current 2FA code.";
const STEP_UP_LOCKED_MESSAGE = "Too many wrong codes. Try again in 15 minutes.";
const LIVE_ORDERS_MESSAGE = "Pause or stop live bots first";
const LIVE_BOTS_MESSAGE = "Switch live bots back to practice mode first.";
const DISCONNECTED_MESSAGE = "Disconnected.";
const ENGINE_UNREACHABLE_MESSAGE =
  "The trading engine isn't answering. Check that the Coinbase add-on is running.";
// The sentence a pin this install never made earns: ask for help, do not guess at a secret.
const ENGINE_PINNED_MESSAGE =
  "The trading engine still holds your earlier Coinbase connection. Ask for help resetting it.";

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
  const dir = mkdtempSync(join(tmpdir(), `crow-coinbase-connect-db${++dbN}-`));
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
  const r = await db.execute({ sql: "INSERT INTO project_spaces (slug, name) VALUES (?, ?) RETURNING id", args: [slug, name] });
  const id = Number(r.rows[0].id);
  await db.execute({ sql: "INSERT INTO project_members (project_id, contact_id, role) VALUES (?, NULL, 'owner')", args: [id] });
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

// ---- the fake trading engine -----------------------------------------------------------------

function readBody(req) {
  return new Promise((resolve, reject) => {
    let text = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => { text += chunk; });
    req.on("end", () => resolve(text));
    req.on("error", reject);
  });
}

async function createFakeEngine() {
  const state = {
    pinned: false,
    pinSecret: null,
    credentials: "not_ready",
    epoch: "engine-epoch-0",
    keyLast4: "1234",
    portfolioLast4: "5678",
    requests: [],
    nextCheck: [],
    nextPush: [],
    nextDelete: [],
    nextForget: [],
    // One entry per push whose answer is dropped instead of sent: { pin } says whether the
    // engine kept the credentials it was given before the socket went away.
    dropPush: [],
  };
  let server = null;
  let port = 0;

  // Which key this request's MAC was signed with, if either: "install", "owner" or "none".
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
        expected = macSignature({ key, method: record.method, pathWithQuery: record.path, ts, nonce, body: record.body });
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
    const send = (status, payload) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    };

    if (req.method === "GET" && record.path === "/health") {
      return send(200, { ok: true, credentials: state.credentials, pinned: state.pinned });
    }

    if (req.method === "POST" && record.path === "/credentials/check") {
      const scripted = state.nextCheck.shift();
      if (scripted && scripted.status >= 400) return send(scripted.status, scripted.body);
      return send(200, (scripted && scripted.body) || {
        state: "ok", key_last4: state.keyLast4, portfolio_last4: state.portfolioLast4,
      });
    }

    if (req.method === "POST" && record.path === "/credentials") {
      const wanted = state.pinned ? "owner" : "install";
      if (record.mac !== wanted) return send(403, { detail: "SECRET_MISMATCH" });
      const scripted = state.nextPush.shift();
      if (scripted && scripted.status >= 400) return send(scripted.status, scripted.body);
      let parsed = {};
      try { parsed = JSON.parse(body) || {}; } catch { parsed = {}; }
      if (!state.pinned) {
        state.pinSecret = typeof parsed.approve_secret === "string" ? parsed.approve_secret : null;
        state.pinned = true;
        state.epoch = "engine-epoch-" + randomBytes(6).toString("hex");
      }
      state.credentials = "ready";
      const dropped = state.dropPush.shift();
      if (dropped) {
        // The answer is lost in flight. Whether the engine kept what it was given is the one
        // thing the client cannot know, so a test decides it here.
        if (dropped.pin !== true) {
          state.pinned = false;
          state.pinSecret = null;
          state.credentials = "not_ready";
        }
        try { res.destroy(); } catch { /* the socket is already gone */ }
        return undefined;
      }
      return send(200, {
        state: "ok", pinned: true, engine_epoch: state.epoch,
        key_last4: state.keyLast4, portfolio_last4: state.portfolioLast4,
      });
    }

    if (req.method === "POST" && record.path === "/credentials/forget") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      const scripted = state.nextForget.shift();
      if (scripted && scripted.status >= 400) return send(scripted.status, scripted.body);
      // The pin is gone for good: the next push is an install-token push with a new secret.
      state.pinned = false;
      state.pinSecret = null;
      state.credentials = "not_ready";
      return send(200, { ok: true });
    }

    if (req.method === "DELETE" && record.path === "/credentials") {
      const wanted = state.pinned ? "owner" : "install";
      if (record.mac !== wanted) return send(403, { detail: "SECRET_MISMATCH" });
      const scripted = state.nextDelete.shift();
      if (scripted && scripted.status >= 400) return send(scripted.status, scripted.body);
      state.credentials = "not_ready";
      return send(200, { ok: true });
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
    nextCheck: (result) => state.nextCheck.push(result),
    nextPush: (result) => state.nextPush.push(result),
    nextDelete: (result) => state.nextDelete.push(result),
    nextForget: (result) => state.nextForget.push(result),
    // The next push is taken (pin true, the default) or refused (pin false) and its answer is
    // dropped, so the client reads the call as one the engine never answered.
    dropNextPush: ({ pin = true } = {}) => state.dropPush.push({ pin }),
    // The engine's volume is gone: no pin, nothing ready, same address.
    wipe() {
      state.pinned = false;
      state.pinSecret = null;
      state.credentials = "not_ready";
    },
    // A restart: the same address answers again with the pin kept and no key in memory.
    async restart() {
      await closeServer(server);
      state.credentials = "not_ready";
      let lastError = null;
      for (let attempt = 0; attempt < 6; attempt += 1) {
        try { await listen(); lastError = null; break; } catch (err) { lastError = err; await new Promise((r) => setTimeout(r, 25)); }
      }
      if (lastError) throw lastError;
      // One plain read first, so a pooled socket left over from before the restart is replaced.
      for (let attempt = 0; attempt < 20; attempt += 1) {
        try {
          const res = await fetch(`http://127.0.0.1:${port}/health`);
          await res.text();
          return;
        } catch { await new Promise((r) => setTimeout(r, 10)); }
      }
    },
    close: () => closeServer(server),
  };
}

// ---- one panel harness per test ----------------------------------------------------------------

function spyConsole() {
  const lines = [];
  const originals = { log: console.log, info: console.info, warn: console.warn, error: console.error };
  const record = (...args) => {
    lines.push(args.map((arg) => {
      if (typeof arg === "string") return arg;
      try { return JSON.stringify(arg); } catch { return String(arg); }
    }).join(" "));
  };
  console.log = record;
  console.info = record;
  console.warn = record;
  console.error = record;
  return {
    lines,
    restore() {
      console.log = originals.log;
      console.info = originals.info;
      console.warn = originals.warn;
      console.error = originals.error;
    },
  };
}

// ---- the fake step-up gate --------------------------------------------------------------------

/**
 * The gate the routes call. `verify(session, { totp_code })` answers what the shared gate answers:
 * `{ ok }`, or `{ locked: true }` once a test says the session is out of tries. A code `TOTP`
 * passes unless a test says otherwise; every call is recorded, so a test can prove the Test route
 * asks for no code at all.
 */
function createFakeStepUpGate(options = {}) {
  const settings = options || {};
  const state = {
    calls: [],
    locked: settings.locked === true,
    accepted: typeof settings.accepted === "function" ? settings.accepted : (code) => code === TOTP,
  };
  return {
    state,
    async verify(token, { totp_code: code } = {}) {
      state.calls.push({ token, code });
      if (state.locked) {
        return { ok: false, locked: true, method: "totp", error: "Too many wrong attempts. Try again later." };
      }
      if (state.accepted(code)) return { ok: true, method: "totp" };
      return { ok: false, method: "totp", error: "That code is not valid." };
    },
  };
}

async function scaffold(overrides = {}) {
  const ctx = await freshDb();
  const db = createDbClient(ctx.path);
  const projectId = await mkProject(db, `Trading ${dbN}`);
  const otherProjectId = await mkProject(db, `Spare ${dbN}`);
  const fake = await createFakeEngine();
  const connected = [];
  const stepUpGate = overrides.stepUpGate ?? createFakeStepUpGate();

  const { router, connection, getStepUpGate } = createConnectRoutes({
    db,
    crowHome: HOME,
    engineClientFactory: ({ secretProvider }) =>
      createEngineClient({ baseUrl: fake.baseUrl, token: ENGINE_TOKEN, secretProvider }),
    authMiddleware: (_req, _res, next) => next(),
    isLocalSession: async () => true,
    is2faEnabled: async () => true,
    stepUpGate,
    loadKey: () => K.ensureWriteKey(db, { crowHome: HOME }),
    onConnected: async () => { connected.push(1); },
    ...overrides,
  });

  const app = express();
  app.use((req, _res, next) => { req.dashboardSession = "S1"; next(); });
  app.use(router);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  async function call(method, path, body) {
    const init = { method };
    if (body !== undefined) {
      init.headers = { "content-type": "application/json" };
      init.body = JSON.stringify(body);
    }
    const res = await fetch(base + path, init);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, text, json };
  }

  const key = () => K.ensureWriteKey(db, { crowHome: HOME });

  async function rowConfig(uuid) {
    const row = (await db.execute({
      sql: "SELECT config FROM service_connections WHERE uuid = ?",
      args: [uuid],
    })).rows[0];
    try { return JSON.parse(String(row?.config ?? "{}")) || {}; } catch { return {}; }
  }

  return {
    db,
    projectId,
    otherProjectId,
    fake,
    connection,
    connected,
    stepUpGate,
    getStepUpGate,
    get: (path) => call("GET", path),
    post: (path, body) => call("POST", path, body),
    connect: (extra = {}) =>
      call("POST", CONNECT, { key_name: KEY_NAME, private_key: PRIVATE_KEY, project_id: projectId, totp: TOTP, ...extra }),
    testKey: (extra = {}) => call("POST", CONNECT_TEST, { key_name: KEY_NAME, private_key: PRIVATE_KEY, totp: TOTP, ...extra }),
    disconnect: () => call("POST", DISCONNECT, { totp: TOTP }),
    connections: async () => (await db.execute({
      sql: `SELECT uuid, project_id, service_id, status, account_label, config
              FROM service_connections WHERE service_id = 'coinbase' ORDER BY id`,
      args: [],
    })).rows,
    // The stored config of one row, exactly as the module keeps it, and a way to leave it in a
    // state only a crash could produce.
    rowConfig,
    setRowConfig: async (uuid, patch) => {
      const next = { ...(await rowConfig(uuid)), ...patch };
      await db.execute({
        sql: "UPDATE service_connections SET config = ?, updated_at = datetime('now') WHERE uuid = ?",
        args: [JSON.stringify(next), uuid],
      });
      return next;
    },
    keychain: async () => (await db.execute({
      sql: "SELECT kind, env_key, status, connection_uuid FROM crow_keychain ORDER BY id",
      args: [],
    })).rows,
    audit: async () => (await db.execute({
      sql: "SELECT id, project_id, action, target, payload FROM project_audit_log ORDER BY id",
      args: [],
    })).rows,
    secretsFor: async (uuid) => panelSecretsFor(db, await key(), uuid, { crowHome: HOME }),
    close: async () => {
      await closeServer(server);
      await fake.close();
      try { db.close(); } catch { /* already closed */ }
    },
  };
}

// ---- scratch-home text, for the "no secret on disk" assertions --------------------------------

function filesUnder(dir) {
  const out = [];
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...filesUnder(full));
    else if (entry.isFile()) out.push(full);
  }
  return out;
}

function textUnder(dir) {
  const parts = [];
  for (const file of filesUnder(dir)) {
    try {
      if (statSync(file).size > 512 * 1024) continue;
      parts.push(readFileSync(file, "utf8"));
    } catch { /* unreadable */ }
  }
  return parts.join("\n");
}

async function waitFor(predicate, { timeoutMs = 5000, stepMs = 10 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
  return predicate();
}

/**
 * Await a request, but never forever: a route that waits for a lock it already holds stalls the
 * answer, and a stalled request should fail its own test instead of the whole run.
 */
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

/** The reset notices one test's `notify` collected. */
function resetNotices(notifications) {
  return (Array.isArray(notifications) ? notifications : []).filter(
    (note) => /reset/i.test(String(note && note.title)) || /reset/i.test(String(note && note.body)),
  );
}

/**
 * Run the loops' own ticks until an asynchronous predicate holds, or time out.
 *
 * A tick a still-running run has already claimed answers at once, so the pump asks again rather
 * than trusting one call: both the lease and the re-push ticks read the engine's health, and a
 * predicate about what a health read did is the test's, never a timer's, to observe.
 */
async function pumpLoops(loops, predicate, { timeoutMs = 5000, stepMs = 25 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((await predicate()) === true) return true;
    await loops.ticks.repush();
    await loops.ticks.lease();
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
  return (await predicate()) === true;
}

/** The loops over one panel harness: no real timers, nothing notified but this test's list. */
function startTestLoops(h, notifications) {
  return startLoops({
    client: createEngineClient({
      baseUrl: h.fake.baseUrl,
      token: ENGINE_TOKEN,
      secretProvider: async (kind) => (kind === "install" ? INSTALL_TOKEN : null),
    }),
    connection: h.connection,
    db: h.db,
    holder: "gw-test-holder",
    notify: async (payload) => {
      notifications.push(payload);
      return null;
    },
    now: () => Date.now(),
    timers: { setInterval: () => ({ unref() {} }), clearInterval: () => {} },
    intervalsMs: { lease: 60 * 60 * 1000, repush: 60 * 60 * 1000, notify: 60 * 60 * 1000 },
  });
}

after(async () => {
  for (const dir of DIRS) {
    try { rmScratch(dir); } catch { /* already gone */ }
  }
});

// ---- 1. a transfer-capable key is refused before anything is written --------------------------

test("test_connect_rejects_transfer_key", async () => {
  const h = await scaffold();
  try {
    h.fake.nextCheck({ status: 422, body: { code: "KEY_CAN_TRANSFER", message: "x" } });
    const r = await h.connect();
    assert.equal(r.status, 422, r.text);
    assert.equal(r.json?.ok, false);
    assert.equal(r.json?.code, "KEY_CAN_TRANSFER");
    assert.ok(String(r.json?.message).includes("Transfer"), String(r.json?.message));

    assert.equal((await h.connections()).length, 0, "no connection row");
    assert.equal((await h.keychain()).length, 0, "no keychain row");
    assert.equal(h.fake.calls("POST", "/credentials").length, 0, "nothing was pushed");
    assert.equal(h.connected.length, 0, "the connect callback did not run");
  } finally {
    await h.close();
  }
});

// ---- 2. the portfolio refusals carry their own words ------------------------------------------

test("test_connect_wrong_portfolio_message", async () => {
  const h = await scaffold();
  try {
    h.fake.nextCheck({ status: 422, body: { code: "KEY_DEFAULT_PORTFOLIO", message: "x" } });
    const mainPortfolio = await h.connect();
    assert.equal(mainPortfolio.status, 422, mainPortfolio.text);
    assert.equal(mainPortfolio.json?.message, DEFAULT_PORTFOLIO_MESSAGE);

    h.fake.nextCheck({ status: 422, body: { code: "KEY_WRONG_PORTFOLIO", message: "x" } });
    const otherPortfolio = await h.connect();
    assert.equal(otherPortfolio.status, 422, otherPortfolio.text);
    assert.equal(otherPortfolio.json?.code, "KEY_WRONG_PORTFOLIO");
    assert.equal(otherPortfolio.json?.message, WRONG_PORTFOLIO_MESSAGE);
    assert.notEqual(WRONG_PORTFOLIO_MESSAGE, DEFAULT_PORTFOLIO_MESSAGE, "each code has its own words");

    assert.equal((await h.connections()).length, 0, "no connection row");
    assert.equal((await h.keychain()).length, 0, "no keychain row");
    assert.equal(h.fake.calls("POST", "/credentials").length, 0, "nothing was pushed");
  } finally {
    await h.close();
  }
});

// ---- 3. Test connection asks the engine and installs nothing ----------------------------------

test("test_test_connection_check_only", async () => {
  const h = await scaffold();
  try {
    const first = await h.testKey();
    assert.equal(first.status, 200, first.text);
    assert.equal(first.json?.message, ACCEPTED_MESSAGE);

    const checks = h.fake.calls("POST", "/credentials/check");
    assert.equal(checks.length, 1, "one check reached the engine");
    assert.equal(checks[0].mac, "install", "an unpinned engine is asked with the install token");
    assert.equal(h.fake.calls("POST", "/credentials").length, 0, "a test installs nothing");
    assert.equal((await h.connections()).length, 0, "no connection row");
    assert.equal((await h.keychain()).length, 0, "no keychain row");

    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);

    const second = await h.testKey();
    assert.equal(second.status, 200, second.text);
    const allChecks = h.fake.calls("POST", "/credentials/check");
    assert.equal(allChecks.length, 3, "one check per test and one for the connect");
    assert.equal(allChecks[2].mac, "owner", "a pinned engine is asked with the owner secret");
  } finally {
    await h.close();
  }
});

// ---- 4. the connect seals the key and the approval secret -------------------------------------

test("test_connect_seals_key_and_secret", async () => {
  const h = await scaffold();
  const spy = spyConsole();
  try {
    const r = await h.connect();
    spy.restore();
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json?.ok, true);
    assert.equal(r.json?.message, CONNECTED_MESSAGE);
    assert.equal(h.connected.length, 1, "the connect callback ran once");

    const rows = await h.connections();
    assert.equal(rows.length, 1);
    const row = rows[0];
    assert.equal(row.service_id, "coinbase");
    assert.equal(row.status, "active");
    assert.equal(Number(row.project_id), h.projectId);

    const keys = await h.keychain();
    assert.equal(keys.length, SECRET_NAMES.length, "one keychain row per declared secret");
    assert.deepEqual(keys.map((k) => k.kind), ["service", "service", "service"]);
    assert.deepEqual(keys.map((k) => k.env_key).sort(), [...SECRET_NAMES].sort());
    assert.ok(keys.every((k) => k.status === "active"), "every sealed row is active");
    assert.ok(keys.every((k) => k.connection_uuid === row.uuid), "every row belongs to the connection");

    const secrets = await h.secretsFor(row.uuid);
    const approveSecret = secrets.COINBASE_APPROVE_SECRET;
    assert.equal(approveSecret.length, APPROVE_SECRET_CHARS, "the approval secret is 43 characters");
    const canaries = [PRIVATE_KEY, KEY_NAME, approveSecret];

    // The engine got them (that is the push); nothing else did.
    const pushes = h.fake.calls("POST", "/credentials");
    assert.equal(pushes.length, 1);
    const pushed = JSON.parse(pushes[0].body);
    assert.equal(pushed.private_key, PRIVATE_KEY);
    assert.equal(pushed.key_name, KEY_NAME);
    assert.equal(pushed.approve_secret, approveSecret);

    const configText = String(row.config ?? "");
    assert.equal(canaries.some((c) => configText.includes(c)), false, "the connection config carries no secret");

    const auditText = JSON.stringify(await h.audit());
    assert.equal(canaries.some((c) => auditText.includes(c)), false, "no audit row carries a secret");

    assert.equal(canaries.some((c) => r.text.includes(c)), false, "the answer carries no secret");

    const logged = spy.lines.join("\n");
    assert.equal(canaries.some((c) => logged.includes(c)), false, "the log carries no secret");

    // The Crow home (the bundle's own env file, any child config) and the install token's folder.
    const homeText = textUnder(HOME);
    assert.equal(canaries.some((c) => homeText.includes(c)), false, "no file on disk carries a secret");
  } finally {
    spy.restore();
    await h.close();
  }
});

// ---- 5. the first pin is signed with the install token ----------------------------------------

test("test_first_pin_uses_install_token", async () => {
  const h = await scaffold();
  try {
    const r = await h.connect();
    assert.equal(r.status, 200, r.text);

    const pushes = h.fake.calls("POST", "/credentials");
    assert.equal(pushes.length, 1);
    assert.equal(pushes[0].mac, "install", "the first pin is signed with the install token");

    const [row] = await h.connections();
    const config = JSON.parse(row.config || "{}");
    assert.equal(String(config.engine_epoch), String(h.fake.state.epoch), "the connection keeps the engine's epoch");

    const secrets = await h.secretsFor(row.uuid);
    assert.equal(h.fake.state.pinSecret, secrets.COINBASE_APPROVE_SECRET, "the engine pinned the approval secret");
    assert.equal(String(h.fake.state.pinSecret).length, APPROVE_SECRET_CHARS);
  } finally {
    await h.close();
  }
});

// ---- 6. a wiped engine is reconnected with the install token ----------------------------------

test("test_reconnect_after_wipe_uses_install_token", async () => {
  const h = await scaffold();
  try {
    const first = await h.connect();
    assert.equal(first.status, 200, first.text);
    const [oldRow] = await h.connections();
    const firstEpoch = String(JSON.parse(oldRow.config || "{}").engine_epoch);
    assert.ok(firstEpoch.length > 0);

    const refused = await h.connect();
    assert.equal(refused.status, 409, refused.text);
    assert.equal(refused.json?.code, "already_connected");

    const beforeMark = await h.connection.get();
    assert.equal(beforeMark.needsReconnect, false);

    h.fake.wipe();
    await h.connection.markNeedsReconnect();
    const flagged = await h.connection.get();
    assert.equal(flagged.needsReconnect, true, "the store reports the wiped engine");
    assert.equal(String(flagged.engineEpoch), firstEpoch, "the epoch is kept");

    const pushesBefore = h.fake.calls("POST", "/credentials").length;
    const reconnected = await h.connect();
    assert.equal(reconnected.status, 200, reconnected.text);

    const pushes = h.fake.calls("POST", "/credentials");
    assert.equal(pushes.length, pushesBefore + 1);
    assert.equal(pushes[pushes.length - 1].mac, "install", "the reconnect is signed with the install token");

    const rows = await h.connections();
    assert.equal(rows.length, 2, "the old row and the new one");
    assert.equal(rows[0].status, "disconnected", "the old connection is disconnected");
    assert.equal(rows[1].status, "active", "the new connection is active");
    assert.equal(Number(rows[1].project_id), h.projectId);

    const newEpoch = String(JSON.parse(rows[1].config || "{}").engine_epoch);
    assert.equal(newEpoch, String(h.fake.state.epoch), "the new connection keeps the new epoch");
    assert.notEqual(newEpoch, firstEpoch, "a reconnect is a new epoch");
  } finally {
    await h.close();
  }
});

// ---- 7. a restarted engine takes the owner's re-push ------------------------------------------

test("test_repush_after_engine_restart", async () => {
  const h = await scaffold();
  try {
    const r = await h.connect();
    assert.equal(r.status, 200, r.text);

    await h.fake.restart();
    assert.equal(h.fake.state.credentials, "not_ready", "the restarted engine holds no key");
    assert.equal(h.fake.state.pinned, true, "the restart keeps the pin");

    const pushesBefore = h.fake.calls("POST", "/credentials").length;
    const result = await h.connection.repush();
    assert.equal(result.ok, true, JSON.stringify(result));

    const pushes = h.fake.calls("POST", "/credentials");
    assert.equal(pushes.length, pushesBefore + 1);
    assert.equal(pushes[pushes.length - 1].mac, "owner", "the re-push is signed with the owner secret");
    assert.equal(h.fake.state.credentials, "ready", "the engine holds the key again");
  } finally {
    await h.close();
  }
});

// ---- 8. a disconnect the engine refuses for its own reasons is refused, and the row stays -----

test("test_disconnect_refused_with_live_orders", async () => {
  const h = await scaffold();
  try {
    const r = await h.connect();
    assert.equal(r.status, 200, r.text);
    const [row] = await h.connections();

    h.fake.nextForget({ status: 409, body: { detail: "LIVE_ORDERS_OPEN" } });
    const refused = await h.disconnect();
    assert.equal(refused.status, 409, refused.text);
    assert.equal(refused.json?.code, "live_orders_open");
    assert.equal(refused.json?.message, LIVE_ORDERS_MESSAGE);

    let rows = await h.connections();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "active", "the connection stays connected");
    assert.equal((await h.rowConfig(row.uuid)).disconnecting === true, false, "the halfway flag is cleared");
    assert.equal(h.fake.state.pinned, true, "the engine keeps the pin");

    h.fake.nextForget({ status: 409, body: { detail: "LIVE_BOTS" } });
    const busyBots = await h.disconnect();
    assert.equal(busyBots.status, 409, busyBots.text);
    assert.equal(busyBots.json?.code, "live_bots");
    assert.equal(busyBots.json?.message, LIVE_BOTS_MESSAGE);
    rows = await h.connections();
    assert.equal(rows[0].status, "active");

    const done = await h.disconnect();
    assert.equal(done.status, 200, done.text);
    assert.equal(done.json?.message, DISCONNECTED_MESSAGE);
    rows = await h.connections();
    assert.equal(rows[0].status, "disconnected");
    assert.equal(h.fake.state.pinned, false, "a disconnect unpins the engine");
    assert.equal(
      h.fake.calls("DELETE", "/credentials").length,
      0,
      "the old clear route is never used for a disconnect",
    );

    const keys = await h.keychain();
    assert.equal(keys.length, SECRET_NAMES.length);
    assert.ok(keys.every((k) => k.status !== "active"), "no sealed row stays active");
  } finally {
    await h.close();
  }
});

// ---- 9. the project picker locks once connected ------------------------------------------------

test("test_project_picker_locked_after_connect", async () => {
  const h = await scaffold();
  try {
    const before = await h.get(CONNECT_STATE);
    assert.equal(before.status, 200, before.text);
    assert.equal(before.json?.project_locked, false);
    assert.equal(before.json?.connected, false);
    assert.equal(before.json?.project_id, null);
    assert.equal(before.json?.key_last4, null);
    assert.equal(before.json?.portfolio_last4, null);

    const r = await h.connect();
    assert.equal(r.status, 200, r.text);

    const after = await h.get(CONNECT_STATE);
    assert.equal(after.status, 200, after.text);
    assert.equal(after.json?.project_locked, true, "the picker is locked");
    assert.equal(after.json?.connected, true);
    assert.equal(after.json?.project_id, h.projectId);
    assert.equal(after.json?.key_last4, "1234");
    assert.equal(after.json?.portfolio_last4, "5678");

    const moved = await h.connect({ project_id: h.otherProjectId });
    assert.equal(moved.status, 409, moved.text);
    assert.equal(moved.json?.code, "project_locked");
    assert.equal((await h.connections()).length, 1, "the connection stays where it is");
  } finally {
    await h.close();
  }
});

// ---- 10. every privileged POST refuses without 2FA, a code or a local session -----------------

test("test_connect_refused_without_2fa", async () => {
  const allBodies = () => [
    [CONNECT, { key_name: KEY_NAME, private_key: PRIVATE_KEY, project_id: 1, totp: TOTP }],
    [CONNECT_TEST, { key_name: KEY_NAME, private_key: PRIVATE_KEY, totp: TOTP }],
    [DISCONNECT, { totp: TOTP }],
  ];
  // The Test route installs nothing, so it takes no code: only these two are gated on one.
  const codeGated = () => allBodies().filter(([path]) => path !== CONNECT_TEST);

  const off = await scaffold({ is2faEnabled: async () => false });
  try {
    for (const [path, body] of allBodies()) {
      const r = await off.post(path, body);
      assert.equal(r.status, 403, `${path}: ${r.text}`);
      assert.equal(r.json?.code, "two_factor_required", path);
      assert.equal(r.json?.message, TWO_FACTOR_MESSAGE, path);
    }
    assert.equal(off.stepUpGate.state.calls.length, 0, "a refusal on 2FA never asks the gate");
    assert.equal((await off.connections()).length, 0, "nothing was created");
    assert.equal((await off.keychain()).length, 0, "nothing was sealed");
    assert.equal(off.fake.state.requests.length, 0, "the engine was not asked");
  } finally {
    await off.close();
  }

  const wrongCode = await scaffold({ stepUpGate: createFakeStepUpGate({ accepted: () => false }) });
  try {
    for (const [path, body] of codeGated()) {
      const r = await wrongCode.post(path, body);
      assert.equal(r.status, 403, `${path}: ${r.text}`);
      assert.equal(r.json?.code, "totp_required", path);
      assert.equal(r.json?.message, TOTP_REQUIRED_MESSAGE, path);
    }
    assert.equal((await wrongCode.connections()).length, 0);
    assert.equal((await wrongCode.keychain()).length, 0);
    assert.equal(wrongCode.fake.state.requests.length, 0, "the engine was not asked");
  } finally {
    await wrongCode.close();
  }

  const peer = await scaffold({ isLocalSession: async () => false });
  try {
    for (const [path, body] of allBodies()) {
      const r = await peer.post(path, body);
      assert.equal(r.status, 403, `${path}: ${r.text}`);
      assert.equal(r.json?.code, "local_login_required", path);
    }
    assert.equal((await peer.connections()).length, 0);
    assert.equal((await peer.keychain()).length, 0);
    assert.equal(peer.fake.state.requests.length, 0, "the engine was not asked");
  } finally {
    await peer.close();
  }
});

// ---- 11. no answer, no log line and no audit row carries a secret -----------------------------

test("test_connect_secret_never_in_response_or_logs", async () => {
  const h = await scaffold();
  const spy = spyConsole();
  try {
    const responses = [];

    h.fake.nextCheck({ status: 422, body: { code: "KEY_INVALID", message: "x" } });
    responses.push(await h.connect());          // refused: the key the engine would not take
    h.fake.nextCheck({ status: 200, body: { state: "ok", key_last4: "1234", portfolio_last4: "5678" } });
    responses.push(await h.testKey());          // no project is named yet, so nothing is installed
    const connected = await h.connect();        // the real connect
    responses.push(connected);

    const [row] = await h.connections();
    assert.equal(connected.status, 200, connected.text);
    const secrets = await h.secretsFor(row.uuid);
    const approveSecret = secrets.COINBASE_APPROVE_SECRET;

    responses.push(await h.testKey());          // a test on the pinned engine
    responses.push(await h.disconnect());
    spy.restore();

    assert.equal(responses[0].status, 422);
    assert.equal(responses[0].json?.code, "KEY_INVALID");
    assert.equal(responses[1].status, 200, responses[1].text);
    assert.equal(responses[3].status, 200, responses[3].text);
    assert.equal(responses[4].status, 200, responses[4].text);

    const audit = await h.audit();
    const actions = audit.map((r) => String(r.action));
    for (const wanted of ["coinbase.connect", "coinbase.connect_test", "coinbase.disconnect"]) {
      assert.ok(actions.includes(wanted), `an audit row for ${wanted}`);
    }

    const canaries = [PRIVATE_KEY, KEY_NAME, approveSecret];
    for (const response of responses) {
      assert.equal(canaries.some((c) => response.text.includes(c)), false, `${response.status} answer carries no secret`);
    }
    const logged = spy.lines.join("\n");
    assert.equal(canaries.some((c) => logged.includes(c)), false, "the log carries no secret");
    const auditText = JSON.stringify(audit);
    assert.equal(canaries.some((c) => auditText.includes(c)), false, "no audit row carries a secret");
    assert.equal(canaries.some((c) => textUnder(HOME).includes(c)), false, "no file on disk carries a secret");
  } finally {
    spy.restore();
    await h.close();
  }
});

// ---- 12. the store the loops take -------------------------------------------------------------

test("test_connection_store_contract", async () => {
  const h = await scaffold();
  try {
    const store = createConnectionStore({
      db: h.db,
      crowHome: HOME,
      engineClient: createEngineClient({
        baseUrl: h.fake.baseUrl,
        token: ENGINE_TOKEN,
        secretProvider: async (kind) => (kind === "install" ? INSTALL_TOKEN : null),
      }),
      loadKey: () => K.ensureWriteKey(h.db, { crowHome: HOME }),
    });
    assert.equal(await store.get(), null, "no connection reads null");

    const pushesBefore = h.fake.calls("POST", "/credentials").length;
    const none = await store.repush();
    assert.equal(none.ok, false);
    assert.equal(none.code, "NOT_CONNECTED");
    assert.equal(h.fake.calls("POST", "/credentials").length, pushesBefore, "nothing is pushed without a connection");

    const r = await h.connect();
    assert.equal(r.status, 200, r.text);
    const [row] = await h.connections();
    const approveSecret = (await h.secretsFor(row.uuid)).COINBASE_APPROVE_SECRET;

    const got = await h.connection.get();
    assert.deepEqual(Object.keys(got || {}).sort(), [...STORE_KEYS].sort(), "the store's own keys, no more");
    assert.equal(got.projectId, h.projectId);
    assert.equal(got.needsReconnect, false);
    assert.equal(got.disconnecting, false, "a settled connection is not half-disconnected");
    assert.equal(String(got.engineEpoch), String(h.fake.state.epoch));

    await h.connection.markNeedsReconnect();
    const flagged = await h.connection.get();
    assert.equal(flagged.needsReconnect, true);
    assert.equal(String(flagged.engineEpoch), String(got.engineEpoch), "the epoch is kept");

    // The state a disconnect leaves behind when it could not finish: the row is still there, and
    // the loops have to leave it alone.
    await h.setRowConfig(row.uuid, { disconnecting: true });
    const halfway = await h.connection.get();
    assert.deepEqual(Object.keys(halfway || {}).sort(), [...STORE_KEYS].sort(), "and still only the store's keys");
    assert.equal(halfway.disconnecting, true, "a disconnect left halfway is reported");

    const blob = JSON.stringify([got, flagged, halfway, none]);
    for (const canary of [PRIVATE_KEY, KEY_NAME, approveSecret]) {
      assert.equal(blob.includes(canary), false, "a store result carries no secret");
    }
  } finally {
    await h.close();
  }
});

// ---- 13. one audit row per POST, none with a secret -------------------------------------------

test("test_audit_every_post", async () => {
  const h = await scaffold();
  try {
    const r = await h.connect();
    assert.equal(r.status, 200, r.text);
    const [row] = await h.connections();
    const approveSecret = (await h.secretsFor(row.uuid)).COINBASE_APPROVE_SECRET;

    assert.equal((await h.testKey()).status, 200);
    assert.equal((await h.disconnect()).status, 200);

    const rows = (await h.audit()).filter((entry) => String(entry.action).startsWith("coinbase."));
    assert.deepEqual(
      rows.map((entry) => entry.action),
      ["coinbase.connect", "coinbase.connect_test", "coinbase.disconnect"],
      "one row per POST, in the order they were made",
    );
    const text = JSON.stringify(rows);
    for (const canary of [PRIVATE_KEY, KEY_NAME, approveSecret]) {
      assert.equal(text.includes(canary), false, "an audit row carries no secret");
    }
  } finally {
    await h.close();
  }
});

// ---- 14. the Test route installs nothing, so it asks for no code ------------------------------

test("test_connect_test_needs_no_code", async () => {
  const h = await scaffold();
  try {
    const tested = await h.post(CONNECT_TEST, { key_name: KEY_NAME, private_key: PRIVATE_KEY });
    assert.equal(tested.status, 200, tested.text);
    assert.equal(tested.json?.message, ACCEPTED_MESSAGE);
    assert.equal(h.stepUpGate.state.calls.length, 0, "the route that installs nothing asks for no code");
    assert.equal(h.fake.calls("POST", "/credentials").length, 0, "and pushes nothing");
    assert.equal((await h.connections()).length, 0, "and creates no row");
    const askedSoFar = h.fake.state.requests.length;

    const connected = await h.post(CONNECT, {
      key_name: KEY_NAME, private_key: PRIVATE_KEY, project_id: h.projectId,
    });
    assert.equal(connected.status, 403, connected.text);
    assert.equal(connected.json?.code, "totp_required");
    assert.equal(connected.json?.message, TOTP_REQUIRED_MESSAGE);

    const disconnected = await h.post(DISCONNECT, {});
    assert.equal(disconnected.status, 403, disconnected.text);
    assert.equal(disconnected.json?.code, "totp_required");

    assert.equal(h.stepUpGate.state.calls.length, 2, "only the two writes asked the gate, and stopped there");
    assert.equal(h.fake.state.requests.length, askedSoFar, "the engine was not asked either");

    // A code on the Test route is not needed, and is not a refusal.
    const testedWithCode = await h.testKey();
    assert.equal(testedWithCode.status, 200, testedWithCode.text);

    const done = await h.connect();
    assert.equal(done.status, 200, done.text);
    assert.equal((await h.connections()).length, 1);
  } finally {
    await h.close();
  }
});

// ---- 15. the gate's own lockout is a 429 with its own words --------------------------------

test("test_step_up_lockout_returns_429", async () => {
  const h = await scaffold({ stepUpGate: createFakeStepUpGate({ locked: true }) });
  try {
    const bodies = [
      [CONNECT, { key_name: KEY_NAME, private_key: PRIVATE_KEY, project_id: h.projectId, totp: TOTP }],
      [DISCONNECT, { totp: TOTP }],
    ];
    for (const [path, body] of bodies) {
      const r = await h.post(path, body);
      assert.equal(r.status, 429, `${path}: ${r.text}`);
      assert.equal(r.json?.ok, false, path);
      assert.equal(r.json?.code, "step_up_locked", path);
      assert.equal(r.json?.message, STEP_UP_LOCKED_MESSAGE, path);
    }
    assert.equal((await h.connections()).length, 0, "nothing was created");
    assert.equal((await h.keychain()).length, 0, "nothing was sealed");
    assert.equal(h.fake.state.requests.length, 0, "the engine was not asked");
  } finally {
    await h.close();
  }
});

// ---- 16. a push whose answer was lost is settled by asking the engine what it did ------------

test("test_push_timeout_after_pin_recovers", async () => {
  const pinned = await scaffold();
  try {
    // The engine pinned what it was handed, then the answer was lost in flight.
    pinned.fake.dropNextPush({ pin: true });
    const r = await within(pinned.connect(), "connect after a dropped push answer");
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json?.ok, true, "a pin that happened is a connection");
    assert.equal(r.json?.message, CONNECTED_MESSAGE);

    const pushes = pinned.fake.calls("POST", "/credentials");
    assert.equal(pushes.length, 2, "the lost push, then the re-push");
    assert.equal(pushes[0].mac, "install", "the first push is the install token's");
    assert.equal(pushes[1].mac, "owner", "the recovery re-push is the sealed secret's");

    const rows = await pinned.connections();
    assert.equal(rows.length, 1, "one row");
    assert.equal(rows[0].status, "active");
    const config = await pinned.rowConfig(rows[0].uuid);
    assert.equal(String(config.engine_epoch), String(pinned.fake.state.epoch), "the row keeps the pinned epoch");
    assert.equal(config.pending_pin === true, false, "the pending pin is settled");
    assert.equal(config.key_last4, "1234");
    assert.equal(config.portfolio_last4, "5678");
    assert.equal(pinned.connected.length, 1, "the connect callback ran once");

    const state = await pinned.get(CONNECT_STATE);
    assert.equal(state.json?.connected, true);
    assert.equal(state.json?.pending, false, "nothing is left pending");
    assert.equal(state.json?.needs_reconnect, false);

    const connectRows = (await pinned.audit()).filter((entry) => String(entry.action) === "coinbase.connect");
    assert.equal(connectRows.length, 1);
    assert.equal(JSON.parse(String(connectRows[0].payload)).ok, true, "the audit row says it succeeded");
  } finally {
    await pinned.close();
  }

  // The same lost answer, but this time the engine never took the key.
  const lost = await scaffold();
  try {
    lost.fake.dropNextPush({ pin: false });
    const r = await within(lost.connect(), "connect after a dropped push answer");
    assert.equal(r.status, 503, r.text);
    assert.equal(r.json?.ok, false);
    assert.equal(String(r.json?.code).toLowerCase(), "engine_unreachable", r.text);
    assert.equal(r.json?.message, ENGINE_UNREACHABLE_MESSAGE);

    const rows = await lost.connections();
    assert.equal(rows.filter((row) => row.status === "active").length, 0, "the half-made row is rolled back");
    const keys = await lost.keychain();
    assert.equal(keys.filter((row) => row.status === "active").length, 0, "nothing stays sealed");
    assert.equal(lost.connected.length, 0, "the connect callback never ran");
    assert.equal(lost.fake.state.pinned, false, "the engine holds nothing");

    const state = await lost.get(CONNECT_STATE);
    assert.equal(state.json?.connected, false);
    assert.equal(state.json?.project_id, null);

    // And a later Connect, on the same install, starts from nothing and works.
    const again = await within(lost.connect(), "the connect after a rollback");
    assert.equal(again.status, 200, again.text);
    assert.equal((await lost.connections()).filter((row) => row.status === "active").length, 1);
  } finally {
    await lost.close();
  }
});

// ---- 17. a disconnect against a restarted engine re-pushes before it forgets ----------------

test("test_disconnect_after_restart", async () => {
  const h = await scaffold();
  try {
    const r = await h.connect();
    assert.equal(r.status, 200, r.text);

    await h.fake.restart();
    assert.equal(h.fake.state.pinned, true, "the restart keeps the pin");
    assert.equal(h.fake.state.credentials, "not_ready", "the restarted engine holds no key");

    const pushesBefore = h.fake.calls("POST", "/credentials").length;
    const done = await within(h.disconnect(), "disconnect after a restart");
    assert.equal(done.status, 200, done.text);
    assert.equal(done.json?.message, DISCONNECTED_MESSAGE);

    const pushes = h.fake.calls("POST", "/credentials");
    assert.equal(pushes.length, pushesBefore + 1, "the sealed key is pushed back first");
    assert.equal(pushes[pushes.length - 1].mac, "owner", "with the owner's secret");

    const forgets = h.fake.calls("POST", "/credentials/forget");
    assert.equal(forgets.length, 1, "the pin is forgotten once");
    assert.equal(forgets[0].mac, "owner", "the forget is the owner's own request");

    const order = h.fake.state.requests.map((request) => `${request.method} ${request.path}`);
    assert.ok(
      order.lastIndexOf("POST /credentials") < order.lastIndexOf("POST /credentials/forget"),
      "the key is in place before the pin is forgotten",
    );

    const rows = await h.connections();
    assert.equal(rows[0].status, "disconnected");
    assert.equal(h.fake.state.pinned, false);
    assert.equal(h.fake.state.credentials, "not_ready");
  } finally {
    await h.close();
  }
});

// ---- 18. a disconnect against an engine that lost its volume just drops the row ------------

test("test_disconnect_after_wipe", async () => {
  const h = await scaffold();
  try {
    const r = await h.connect();
    assert.equal(r.status, 200, r.text);

    h.fake.wipe();
    assert.equal(h.fake.state.pinned, false);

    const done = await h.disconnect();
    assert.equal(done.status, 200, done.text);
    assert.equal(done.json?.message, DISCONNECTED_MESSAGE);
    assert.equal(
      h.fake.calls("POST", "/credentials/forget").length,
      0,
      "an unpinned engine has nothing to forget",
    );
    assert.equal(h.fake.calls("DELETE", "/credentials").length, 0, "the old clear route is not used");

    const rows = await h.connections();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "disconnected");
    assert.ok((await h.keychain()).every((row) => row.status !== "active"), "no sealed row stays active");

    const state = await h.get(CONNECT_STATE);
    assert.equal(state.json?.connected, false);
  } finally {
    await h.close();
  }
});

// ---- 19. after a disconnect a new key is a fresh connect, never a help request ---------------

test("test_disconnect_then_connect_new_key", async () => {
  const h = await scaffold();
  try {
    const first = await h.connect();
    assert.equal(first.status, 200, first.text);
    const [firstRow] = await h.connections();
    const firstSecret = (await h.secretsFor(firstRow.uuid)).COINBASE_APPROVE_SECRET;
    assert.equal(h.fake.state.pinSecret, firstSecret, "the engine pinned the first approval secret");

    const gone = await h.disconnect();
    assert.equal(gone.status, 200, gone.text);
    assert.equal(h.fake.state.pinned, false, "the engine is unpinned");

    const pushesBefore = h.fake.calls("POST", "/credentials").length;
    const second = await h.connect();
    assert.equal(second.status, 200, second.text);
    assert.equal(second.json?.message, CONNECTED_MESSAGE, "a fresh connection, not a help request");
    assert.equal(String(second.json?.message).includes("Ask for help"), false);

    const pushes = h.fake.calls("POST", "/credentials");
    assert.equal(pushes.length, pushesBefore + 1, "one push: no re-push was needed");
    assert.equal(pushes[pushes.length - 1].mac, "install", "a brand new pin is the install token's");

    const rows = await h.connections();
    assert.equal(rows.length, 2);
    assert.equal(rows[0].status, "disconnected");
    assert.equal(rows[1].status, "active");
    const secondSecret = (await h.secretsFor(rows[1].uuid)).COINBASE_APPROVE_SECRET;
    assert.notEqual(secondSecret, firstSecret, "a new connection gets a new approval secret");
    assert.equal(h.fake.state.pinSecret, secondSecret, "the engine pinned the new secret");
  } finally {
    await h.close();
  }
});

// ---- 20. a disconnect left halfway is not an engine reset ------------------------------------

test("test_disconnect_crash_midway_no_reset_alert", async () => {
  const h = await scaffold();
  const notifications = [];
  try {
    const r = await h.connect();
    assert.equal(r.status, 200, r.text);
    const [row] = await h.connections();

    // The state a process death leaves behind right after the engine forgot the pin: the row
    // still says it is disconnecting, and the engine holds nothing.
    await h.setRowConfig(row.uuid, { disconnecting: true });
    h.fake.wipe();
    assert.equal((await h.connection.get()).disconnecting, true, "the store sees the halfway row");

    const healthBefore = h.fake.calls("GET", "/health").length;
    const loops = startLoops({
      client: createEngineClient({
        baseUrl: h.fake.baseUrl,
        token: ENGINE_TOKEN,
        secretProvider: async (kind) => (kind === "install" ? INSTALL_TOKEN : null),
      }),
      connection: h.connection,
      db: h.db,
      holder: "gw-test-holder",
      notify: async (payload) => {
        notifications.push(payload);
        return null;
      },
      now: () => Date.now(),
      timers: { setInterval: () => ({ unref() {} }), clearInterval: () => {} },
      intervalsMs: { lease: 60 * 60 * 1000, repush: 60 * 60 * 1000, notify: 60 * 60 * 1000 },
    });
    try {
      // The ticks startLoops runs on its own have each read health once; let them finish.
      await waitFor(() => h.fake.calls("GET", "/health").length >= healthBefore + 2);
      await loops.ticks.repush();
    } finally {
      loops.stop();
    }

    const resets = notifications.filter(
      (note) => /reset/i.test(String(note && note.title)) || /reset/i.test(String(note && note.body)),
    );
    assert.equal(resets.length, 0, "a half-finished disconnect is not an engine reset");
    assert.equal((await h.connection.get()).needsReconnect, false, "the row is not flagged for a reconnect");

    const done = await h.disconnect();
    assert.equal(done.status, 200, done.text);
    const rows = await h.connections();
    assert.equal(rows[0].status, "disconnected", "a second Disconnect finishes it");
  } finally {
    await h.close();
  }
});

// ---- 21. a pasted key is cleaned the way the keychain cleans a pasted value ------------------

test("test_crlf_pem_connects", async () => {
  const h = await scaffold();
  try {
    // A control character other than LF is refused before anything reaches the engine.
    const withTab = PRIVATE_KEY.replace(/\n/, "\n\t");
    const refused = await h.post(CONNECT, {
      key_name: KEY_NAME, private_key: withTab, project_id: h.projectId, totp: TOTP,
    });
    assert.equal(refused.status, 400, refused.text);
    assert.equal(refused.json?.ok, false);
    assert.equal(refused.json?.code, "bad_request");
    assert.equal(refused.json?.message, fixit("KEY_INVALID"), "the key copy, not a crash");
    assert.equal(h.fake.state.requests.length, 0, "nothing was sent to the engine");
    assert.equal((await h.connections()).length, 0, "no row was made");

    // A PEM that came through a Windows clipboard: CRLF line ends, stray spaces around it.
    const crlf = `  ${PRIVATE_KEY.replace(/\n/g, "\r\n")}  `;
    const r = await h.post(CONNECT, {
      key_name: KEY_NAME, private_key: crlf, project_id: h.projectId, totp: TOTP,
    });
    assert.equal(r.status, 200, r.text);

    const pushes = h.fake.calls("POST", "/credentials");
    assert.equal(pushes.length, 1);
    const pushed = JSON.parse(pushes[0].body);
    assert.equal(pushed.private_key, PRIVATE_KEY, "the engine is given LF text with no padding");
    assert.equal(String(pushed.private_key).includes("\r"), false, "no carriage return survives");

    const [row] = await h.connections();
    const sealed = (await h.secretsFor(row.uuid)).COINBASE_PRIVATE_KEY;
    assert.equal(sealed, pushed.private_key, "the sealed value is the pushed value");
  } finally {
    await h.close();
  }
});

// ---- 22. the routes refuse to be built without an auth middleware ------------------------

test("test_missing_auth_middleware_throws", async () => {
  const h = await scaffold();
  try {
    assert.throws(
      () => createConnectRoutes({
        db: h.db,
        crowHome: HOME,
        engineClientFactory: ({ secretProvider }) =>
          createEngineClient({ baseUrl: h.fake.baseUrl, token: ENGINE_TOKEN, secretProvider }),
        isLocalSession: async () => true,
        is2faEnabled: async () => true,
        stepUpGate: createFakeStepUpGate(),
      }),
      TypeError,
      "a route set with no auth middleware is never built",
    );
  } finally {
    await h.close();
  }
});

// ---- 23. two Connects at once make one connection ------------------------------------------

test("test_concurrent_connects_one_row", async () => {
  const h = await scaffold();
  try {
    const [a, b] = await Promise.all([h.connect(), h.connect()]);
    const statuses = [a.status, b.status].sort((x, y) => x - y);
    assert.deepEqual(statuses, [200, 409], `one connect wins and one is refused: ${a.text} / ${b.text}`);
    const refused = a.status === 409 ? a : b;
    assert.equal(refused.json?.code, "already_connected");

    const rows = await h.connections();
    assert.equal(rows.length, 1, "exactly one connection row");
    assert.equal(rows.filter((row) => row.status === "active").length, 1);
    assert.equal(h.fake.calls("POST", "/credentials").length, 1, "exactly one pin");
  } finally {
    await h.close();
  }
});

// ---- 24. a gate refusal is filed against the bound project, or not at all ------------------

test("test_gate_refusal_audit_only_bound_project", async () => {
  const fresh = await scaffold();
  try {
    const r = await fresh.post(CONNECT, {
      key_name: KEY_NAME, private_key: PRIVATE_KEY, project_id: fresh.projectId, totp: "000000",
    });
    assert.equal(r.status, 403, r.text);
    assert.equal(r.json?.code, "totp_required");
    assert.equal((await fresh.audit()).length, 0, "a refusal with no connection writes no audit row");
  } finally {
    await fresh.close();
  }

  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);

    const refused = await h.post(CONNECT, {
      key_name: KEY_NAME, private_key: PRIVATE_KEY, project_id: h.otherProjectId, totp: "000000",
    });
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.json?.code, "totp_required");

    const rows = await h.audit();
    assert.equal(
      rows.filter((row) => Number(row.project_id) === h.otherProjectId).length,
      0,
      "the body's project is never where a gate refusal is filed",
    );
    const refusals = rows.filter(
      (row) => String(row.action) === "coinbase.connect" && String(row.payload).includes("totp_required"),
    );
    assert.equal(refusals.length, 1, "the refusal is audited");
    assert.equal(Number(refusals[0].project_id), h.projectId, "against the bound project");
  } finally {
    await h.close();
  }
});

// ---- 25. an engine that lost its pin while a connection stands is a reconnect ---------------

test("test_reset_while_connected_is_reconnect", async () => {
  const h = await scaffold();
  try {
    const first = await h.connect();
    assert.equal(first.status, 200, first.text);
    const [oldRow] = await h.connections();
    const oldEpoch = String((await h.rowConfig(oldRow.uuid)).engine_epoch);
    assert.ok(oldEpoch.length > 0);
    assert.equal(
      (await h.connection.get()).needsReconnect,
      false,
      "a wipe nobody has reported yet leaves the flag alone",
    );

    h.fake.wipe();

    const again = await h.connect();
    assert.equal(again.status, 200, again.text);

    const pushes = h.fake.calls("POST", "/credentials");
    assert.equal(pushes[pushes.length - 1].mac, "install", "an unpinned engine takes the install token");

    const rows = await h.connections();
    assert.equal(rows.length, 2, "the old row and the new one");
    assert.equal(rows[0].status, "disconnected", "the old connection is let go");
    assert.equal(rows[1].status, "active");
    const newEpoch = String((await h.rowConfig(rows[1].uuid)).engine_epoch);
    assert.notEqual(newEpoch, oldEpoch, "the new pin is a new epoch");
    assert.equal(h.fake.state.pinned, true);
  } finally {
    await h.close();
  }
});

// ---- 26. the copy the panel shows -------------------------------------------------------------

test("test_copy_table", () => {
  assert.ok(fixit("KEY_CAN_TRANSFER").includes("Transfer"), fixit("KEY_CAN_TRANSFER"));
  assert.equal(fixit("KEY_DEFAULT_PORTFOLIO"), DEFAULT_PORTFOLIO_MESSAGE);
  assert.equal(fixit("KEY_WRONG_PORTFOLIO"), WRONG_PORTFOLIO_MESSAGE);
  assert.equal(COPY_STEPS, STEPS);
  assert.equal(fixit("SOMETHING_CROW_NEVER_HEARD_OF"), GENERIC_MESSAGE);
});

// ---- 27. a stale Disconnect flag never hides a real reset --------------------------------------

test("test_stale_disconnecting_flag_does_not_hide_reset", async () => {
  const h = await scaffold();
  const notifications = [];
  let loops = null;
  try {
    const r = await h.connect();
    assert.equal(r.status, 200, r.text);
    const [row] = await h.connections();

    // The state a process death can leave behind: the flag says a Disconnect is in flight, but
    // the engine still holds its pin, so nothing was actually in flight any more.
    await h.setRowConfig(row.uuid, { disconnecting: true });
    assert.equal(h.fake.state.pinned, true, "the engine still holds the pin");
    const flagged = await h.get(CONNECT_STATE);
    assert.equal(flagged.status, 200, flagged.text);
    assert.equal(flagged.json?.disconnect_unfinished, true, "the state says the Disconnect is unfinished");

    loops = startTestLoops(h, notifications);

    const cleared = await pumpLoops(loops, async () => (await h.connection.get())?.disconnecting === false);
    assert.equal(cleared, true, "a health read showing the pin clears the stale flag");
    assert.equal((await h.rowConfig(row.uuid)).disconnecting, undefined, "the row's config holds no flag any more");
    const settled = await h.get(CONNECT_STATE);
    assert.equal(settled.json?.disconnect_unfinished, false, "nothing is unfinished once the flag is gone");
    assert.equal(settled.json?.connected, true);
    assert.equal(resetNotices(notifications).length, 0, "a pin that is there is not a reset");

    // The flag cannot hide a real reset any more: this time the engine lost its pin for real.
    h.fake.wipe();
    const detected = await pumpLoops(
      loops,
      async () => resetNotices(notifications).length > 0 && (await h.connection.get())?.needsReconnect === true,
    );
    assert.equal(detected, true, "the reset is detected once the stale flag is gone");
    assert.equal(resetNotices(notifications).length, 1, "one reset notice, not one a tick");
    assert.equal((await h.connection.get()).needsReconnect, true, "the row asks the owner to reconnect");
    assert.equal(h.fake.state.pinned, false, "the engine holds nothing now");

    const afterReset = await h.get(CONNECT_STATE);
    assert.equal(afterReset.json?.needs_reconnect, true);
    assert.equal(afterReset.json?.disconnect_unfinished, false, "the wipe is not an unfinished Disconnect");
  } finally {
    if (loops) loops.stop();
    await h.close();
  }
});

// ---- 28. a pending pin that is somebody else's is rolled back, never settled -------------------

test("test_pending_pin_foreign_pin_rolls_back", async () => {
  const h = await scaffold();
  try {
    const first = await h.connect();
    assert.equal(first.status, 200, first.text);
    const [row] = await h.connections();
    const sealed = await h.secretsFor(row.uuid);

    // The state a lost push leaves behind: the row is pending, and the engine holds a pin this
    // install never made — its approval secret is not the one sealed here.
    await h.setRowConfig(row.uuid, { pending_pin: true });
    h.fake.state.pinSecret = randomBytes(32).toString("base64url");
    const pushesBefore = h.fake.calls("POST", "/credentials").length;

    const settled = await within(h.connect(), "connect against a foreign pin");
    assert.equal(settled.status, 409, settled.text);
    assert.equal(settled.json?.ok, false);
    assert.equal(settled.json?.code, "engine_pinned", settled.text);
    assert.equal(settled.json?.message, ENGINE_PINNED_MESSAGE);
    for (const canary of [PRIVATE_KEY, KEY_NAME, sealed.COINBASE_APPROVE_SECRET, sealed.COINBASE_KEY_NAME]) {
      assert.equal(settled.text.includes(canary), false, "the answer carries no key material");
    }

    const pushes = h.fake.calls("POST", "/credentials").slice(pushesBefore);
    assert.equal(pushes.length, 1, "one re-push of the sealed secret, and no second seal");
    assert.equal(pushes[0].mac, "none", "the engine refused it: the pin is not this install's");

    const rows = await h.connections();
    assert.equal(
      rows.filter((entry) => entry.status === "active").length,
      0,
      "the pending row is rolled back: there is nothing here to settle with a foreign pin",
    );
    assert.equal(
      (await h.keychain()).filter((entry) => entry.status === "active").length,
      0,
      "its sealed values go with it",
    );
    const state = await h.get(CONNECT_STATE);
    assert.equal(state.json?.connected, false);
  } finally {
    await h.close();
  }
});

// ---- 29. one active coinbase connection, whatever else is in the table -------------------------

test("test_never_two_active_rows", async () => {
  const h = await scaffold();
  try {
    const first = await h.connect();
    assert.equal(first.status, 200, first.text);
    const [firstRow] = await h.connections();

    // A second active coinbase row this install did not make — something left by an earlier
    // connection — carrying the same sealed values and a remembered install.
    const { createPanelConnection } = await import("../servers/shared/service-connections.js");
    const key = await K.ensureWriteKey(h.db, { crowHome: HOME });
    const stale = await createPanelConnection(
      h.db,
      {
        projectId: h.projectId,
        serviceId: "coinbase",
        accountLabel: "Earlier Crow portfolio",
        config: {},
        secrets: await h.secretsFor(firstRow.uuid),
      },
      { key, actor: "local", crowHome: HOME },
    );
    await h.setRowConfig(stale.uuid, { engine_epoch: "engine-epoch-earlier" });

    const before = await h.connections();
    assert.equal(before.filter((entry) => entry.status === "active").length, 2, "two active rows to start with");

    // The engine lost its pin while the connection remembers an install, so this Connect is a
    // reconnect — and the row it replaces is the newest one, not the other active row.
    h.fake.wipe();
    const reconnected = await within(h.connect(), "reconnect over a stale active row");
    assert.equal(reconnected.status, 200, reconnected.text);
    assert.equal(reconnected.json?.ok, true);

    const rows = await h.connections();
    const active = rows.filter((entry) => entry.status === "active");
    assert.equal(
      active.length,
      1,
      `exactly one active coinbase row: ${JSON.stringify(rows.map((entry) => [entry.account_label, entry.status]))}`,
    );
    assert.equal(active[0].uuid, rows[rows.length - 1].uuid, "the connection this Connect made is the one that stands");
    assert.notEqual(active[0].uuid, firstRow.uuid, "the row it did not know about is let go too");
    assert.notEqual(active[0].uuid, stale.uuid);
    assert.equal(Number(active[0].project_id), h.projectId);

    const disconnected = rows.filter((entry) => entry.status === "disconnected").map((entry) => entry.uuid);
    assert.ok(disconnected.includes(firstRow.uuid), "the stale row is disconnected, not deleted");
    assert.ok(disconnected.includes(stale.uuid));
  } finally {
    await h.close();
  }
});
