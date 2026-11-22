/**
 * Shared harness for the Trading panel's route tests.
 *
 * One scaffold is one scratch Crow home's database (init-db, a real keychain, real sealed
 * service connections), one real express app over the panel's own router (so the real JSON body
 * parser, the real auth seam and the real CSRF middleware are in the path), and one fake trading
 * engine on loopback.
 *
 * The fake engine answers the routes the engine client calls and enforces the approval MAC the way
 * the engine does: a privileged request has to carry a signature the pinned approval secret
 * produces, an install-time request the one the install token produces. Every request is logged
 * with the key it was signed with (`record.mac`: "owner", "install" or "none"), so a test can show
 * which key signed a call and that a refused action never reached the engine at all.
 *
 * An engine holding no pin has nothing to check an owner's signature against, so it refuses one on
 * every privileged route (403 `APPROVAL_INVALID`, `record.ownerRefused`) exactly as the real engine
 * does, and `record.mac` never says "owner" while it is unpinned.
 *
 * The step-up gate is the real one (`servers/gateway/dashboard/step-up.js`), with its two seams
 * (the secret and the time-step matcher) injected, so its own replay guard and its own lockout are
 * what the routes meet. `nextCode()` mints a code that matches a later time step; the first one is
 * "123456" and every later one is a fresh number, so a code used twice is refused by the guard
 * exactly as a typed code would be.
 *
 * Nothing here is a real key, a real amount or a real person: the PEM-shaped key is assembled from
 * parts at run time, and every amount is a test figure.
 */
import express from "express";
import http from "node:http";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

import { rmScratch } from "./safe-rm.js";
import { csrfTokenFor } from "./csrf-token.mjs";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
export { REPO };

// The panel's routes file, as a URL, so a test can import a fresh copy (a cache-busting query
// makes Node hand back a second module instance of the same file).
const ROUTES_HREF = new URL("../../bundles/coinbase/panel/routes.js", import.meta.url).href;

/** A fresh copy of the panel's routes module; a query string makes it a second instance. */
export function importPanelRoutes(query = "") {
  return import(query ? `${ROUTES_HREF}?${query}` : ROUTES_HREF);
}

// ---- synthetic values, built at run time ------------------------------------------------------

export const ENGINE_TOKEN = "test-token-coinbase-panel-7a41";
// The install token the installer publishes for the engine: 43 base64url characters.
export const INSTALL_TOKEN = randomBytes(32).toString("base64url");
export const KEY_NAME = "organizations/test-org/apiKeys/test-key-9137b";
export const TOTP = "123456";
export const SESSION = "coinbase-panel-session-1";
export const TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
// A PEM-shaped key built at run time: the header is assembled from parts, never written whole.
const PEM_HEADER = ["-----BEGIN", "EC PRIVATE KEY-----"].join(" ");
const PEM_FOOTER = ["-----END", "EC PRIVATE KEY-----"].join(" ");
function buildPrivateKey() {
  const body = randomBytes(96).toString("base64").replace(/(.{64})/g, "$1\n").trim();
  return [PEM_HEADER, body, PEM_FOOTER].join("\n");
}
export const PRIVATE_KEY = buildPrivateKey();

// The copy the panel and the routes answer with, in one place.
export const TWO_FACTOR_MESSAGE = "Turn on two-factor sign-in first (Settings \u2192 Security)";
export const TOTP_REQUIRED_MESSAGE = "Enter your current 2FA code.";
export const STEP_UP_LOCKED_MESSAGE = "Too many wrong codes. Try again in 15 minutes.";
export const LOCAL_LOGIN_CODE = "local_login_required";
export const LOCAL_LOGIN_MESSAGE =
  "Sign in on this Crow with your password to connect Coinbase (peer sign-in is not enough).";
export const KILL_CONFIRM_MESSAGE = "Press the kill switch again to confirm.";
export const KILL_SUCCESS_MESSAGE =
  "Stopped. Every Crow order is being cancelled and every bot is stopped. " +
  "Press Resume trading when you are ready.";
// Nobody was reached: nothing stopped, and the owner has to cancel at Coinbase by hand.
export const KILL_ENGINE_DOWN_MESSAGE =
  "Nothing was stopped: the trading engine is down. Cancel open orders by hand in the Coinbase app: Crow portfolio \u2192 Open orders.";
// The engine answered and refused Crow's own token (401/403): still nothing stopped.
export const KILL_ENGINE_REFUSED_MESSAGE =
  "Nothing was stopped: Crow couldn't reach the trading engine. Cancel open orders by hand in the Coinbase app: Crow portfolio \u2192 Open orders.";
// The engine answered, and some of its own steps failed.
export const KILL_PARTIAL_MESSAGE = "Trading is halted, but some orders may still be resting on Coinbase.";
// The two sentences a switch save can earn besides a change: nothing to send, and no pin.
export const SWITCH_UNCHANGED_MESSAGE = "Those switches are already set that way.";
export const SWITCH_NOT_CONNECTED_MESSAGE = "Coinbase isn't connected, so nothing was switched.";
// The one sentence each switch change earns, in the owner's words.
export const SWITCH_MESSAGE = {
  LIVE_ON: "Bots can now trade with real money.",
  LIVE_OFF: "Bots are back to practice only.",
  AI_ON: "The AI can now place real orders after you approve them.",
  AI_OFF: "The AI can no longer place real orders.",
};
export const KILL_NOT_READY_MESSAGE =
  "The kill switch can only cancel orders on Coinbase once the engine reconnects.";
export const WOULD_HALT_MESSAGE = "This halts live trading now. Press Save again to confirm.";
export const WOULD_HALT_PRACTICE_MESSAGE = "This halts practice trading now. Press Save again to confirm.";
export const DISCONNECT_UNFINISHED_MESSAGE = "Disconnect didn't finish \u2014 press Disconnect again";
export const ENGINE_DOWN_NOTE = "Trading engine is not responding.";
export const CONFIRM_LIVE_MESSAGE = "Confirm that this bot will trade with real money.";
export const CONNECTED_PREFIX = "Connected \u2014 Crow portfolio \u2026";
export const GRID_NOTE = "No edge on average: it behaves like holding about half in the coin.";

// The nine caps the panel reads and writes, by the variable that sets them.
export const CAP = {
  DAILY: "CROW_COINBASE_DAILY_NOTIONAL_USD",
  ORDERS: "CROW_COINBASE_ORDERS_PER_HOUR",
  DRAWDOWN: "CROW_COINBASE_PORTFOLIO_DRAWDOWN_PCT",
  BOT_ORDER: "CROW_COINBASE_BOT_MAX_ORDER_USD",
  BOT_CAPITAL: "CROW_COINBASE_MAX_BOT_CAPITAL_USD",
  AI_ORDER: "CROW_COINBASE_AI_MAX_ORDER_USD",
  AI_DAILY: "CROW_COINBASE_AI_DAILY_NOTIONAL_USD",
  AI_ORDERS: "CROW_COINBASE_AI_ORDERS_PER_HOUR",
  AI_CAPITAL: "CROW_COINBASE_AI_CAPITAL_USD",
};

/** The ceilings the engine was started with: money and percentages as text, counts as integers. */
export function defaultCeilings() {
  return {
    [CAP.DAILY]: "200",
    [CAP.ORDERS]: 30,
    [CAP.DRAWDOWN]: "20",
    [CAP.BOT_ORDER]: "50",
    [CAP.BOT_CAPITAL]: "100",
    [CAP.AI_ORDER]: "25",
    [CAP.AI_DAILY]: "50",
    [CAP.AI_ORDERS]: 10,
    [CAP.AI_CAPITAL]: "25",
  };
}

/** The caps in force: each starts at its own ceiling. */
export function defaultCaps() {
  return { ...defaultCeilings() };
}

/** One book's use today, in the engine's own shape. */
export function defaultUsedToday() {
  const book = () => ({
    daily_notional_usd: "0",
    ai_daily_notional_usd: "0",
    orders_last_hour: 0,
    ai_orders_last_hour: 0,
  });
  return { dry: book(), live: book() };
}

// ---- the scratch home and data dir, one per test file -----------------------------------------

const HOME = mkdtempSync(join(tmpdir(), "crow-coinbase-panel-home-"));
const DATA = mkdtempSync(join(tmpdir(), "crow-coinbase-panel-data-"));
const SCRATCH_DBS = [];

export const CROW_HOME = HOME;

mkdirSync(join(HOME, "coinbase", "install"), { recursive: true, mode: 0o700 });
writeFileSync(join(HOME, "coinbase", "install", "install_token"), INSTALL_TOKEN + "\n", { mode: 0o644 });
// The bundle `.env` the default router's real engine client reads its bearer token from.
mkdirSync(join(HOME, "bundles", "coinbase"), { recursive: true });
writeFileSync(
  join(HOME, "bundles", "coinbase", ".env"),
  `CROW_COINBASE_ENGINE_TOKEN=${ENGINE_TOKEN}\n`,
  { mode: 0o644 },
);

process.env.CROW_APP_ROOT = REPO;
process.env.CROW_HOME = HOME;
process.env.CROW_DATA_DIR = DATA;
delete process.env.CROW_DB_PATH;
process.env.CROW_AUTO_UPDATE = "0";
process.env.CROW_DISABLE_HEALTH_MONITOR = "1";
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
process.env.CROW_DISABLE_NOSTR = "1";

const { createDbClient } = await import("../../servers/db.js");
const K = await import("../../servers/gateway/keychain/store.js");
const { macHeaders, macSignature } = await import("../../bundles/coinbase/server/mac.js");
const { createEngineClient } = await import("../../bundles/coinbase/server/engine-client.js");
const { createStepUpGate } = await import("../../servers/gateway/dashboard/step-up.js");
const { startLoops: realStartLoops } = await import("../../bundles/coinbase/server/loops.js");

// ---- scratch databases and projects -----------------------------------------------------------

let dbN = 0;

async function freshDb() {
  const dir = mkdtempSync(join(tmpdir(), `crow-coinbase-panel-db${++dbN}-`));
  SCRATCH_DBS.push(dir);
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir },
    stdio: "pipe",
    cwd: REPO,
  });
  return { dir, path: join(dir, "crow.db") };
}

async function mkProject(db, name) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  const created = await db.execute({
    sql: "INSERT INTO project_spaces (slug, name) VALUES (?, ?) RETURNING id",
    args: [slug, name],
  });
  const id = Number(created.rows[0].id);
  await db.execute({
    sql: "INSERT INTO project_members (project_id, contact_id, role) VALUES (?, NULL, 'owner')",
    args: [id],
  });
  return id;
}

/** The scratch dirs one test file created; call it from `after()`. */
export function cleanupScratch() {
  for (const dir of SCRATCH_DBS) {
    try { rmScratch(dir); } catch { /* already gone */ }
  }
  SCRATCH_DBS.length = 0;
  for (const dir of [HOME, DATA]) {
    try { rmScratch(dir); } catch { /* already gone */ }
  }
}

// ---- small shared utilities -------------------------------------------------------------------

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

function parseJson(text) {
  if (typeof text !== "string" || text === "") return null;
  try { return JSON.parse(text); } catch { return null; }
}

function splitPath(pathWithQuery) {
  const at = pathWithQuery.indexOf("?");
  if (at === -1) return { path: pathWithQuery, query: new URLSearchParams() };
  return { path: pathWithQuery.slice(0, at), query: new URLSearchParams(pathWithQuery.slice(at + 1)) };
}

/** Await a promise, but never forever: a route that stalls should fail its own test. */
export function within(promise, label, ms = 20000) {
  let timer = null;
  const guard = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: no answer within ${ms} ms`)), ms);
    if (timer && typeof timer.unref === "function") timer.unref();
  });
  return Promise.race([promise, guard]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

/** Poll a predicate until it holds, or the budget runs out. */
export async function waitFor(predicate, { timeoutMs = 5000, stepMs = 10 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
  return (await predicate()) === true;
}

/**
 * The MAC headers of one request signed with `key`, in the shape the engine client sends them.
 *
 * A test that drives the fake engine directly (rather than through a routes file) can then show
 * what an engine does with a signature it holds no pin to approve — and which key it read it as.
 */
export function signedHeaders(key, { method = "POST", path, body = "" } = {}) {
  return macHeaders({ key, method, pathWithQuery: path, body });
}

// ---- fake engine rows -------------------------------------------------------------------------

/** One bot row in the shape GET /bots answers. */
export function fakeBot(overrides = {}) {
  return {
    id: "bot-test-1",
    product: "BTC-USDC",
    strategy: "rebalance",
    params: { target_base_pct: 50 },
    status: "ACTIVE",
    init_done: true,
    mode: "dry",
    capital_quote: "10.00",
    capital_base: "0",
    live_capital_quote: null,
    live_capital_base: null,
    created_at: 1710000000,
    ...overrides,
  };
}

/** One resting order in the shape GET /orders answers. */
export function fakeOrder(overrides = {}) {
  return {
    client_order_id: "cid-test-1",
    bot: "bot-test-1",
    product: "BTC-USDC",
    side: "BUY",
    size: "0.0010",
    price: "60000.00",
    status: "OPEN",
    created_at: 1710000000,
    book: "dry",
    ...overrides,
  };
}

/** One AI preview in the shape GET /ai/previews answers. */
export function fakePreview(overrides = {}) {
  const nowS = Math.floor(Date.now() / 1000);
  return {
    preview_id: "pv-test-1",
    hash: "a".repeat(64),
    state: "pending",
    book: "dry",
    product: "BTC-USDC",
    side: "BUY",
    size: "0.0010",
    limit_price: "60000",
    requested_limit_price: "60000",
    notional: "60.00",
    limits: [{ name: "ai_max_order_usd", limit: "25.00", used_after: "60.00" }],
    expires_at: nowS + 600,
    created_at: nowS,
    refusal: null,
    message: null,
    ...overrides,
  };
}

// ---- the fake trading engine -----------------------------------------------------------------

/** Whether this request is one the engine only carries out for the owner's approval. */
function needsOwnerApproval(method, path) {
  const verb = String(method).toUpperCase();
  if (verb === "DELETE") return path === "/credentials";
  if (verb !== "POST") return false;
  return (
    path === "/switches" ||
    path === "/caps" ||
    path === "/halt/clear" ||
    path === "/credentials/forget" ||
    /^\/bots\/[^/]+\/mode$/.test(path) ||
    /^\/ai\/previews\/[^/]+\/approve$/.test(path)
  );
  // Resume and recenter are privileged only for a bot on the live book, so they are refused in
  // the action branch, where the bot's own book is known.
}

/**
 * One fake engine on loopback.
 *
 * `state` is the scriptable side: the pin, the health fields, the bots, the pnl entries, the caps,
 * the switches, the halt flags, the previews and the fills. Tests may rewrite any of it between
 * requests. `next(method, path, {status, body})` answers one request from a script.
 */
export async function createFakeEngine() {
  const state = {
    pinned: false,
    pinSecret: null,
    credentials: "not_ready",
    epoch: "engine-epoch-0",
    keyLast4: "7b21",
    portfolioLast4: "4c9d",
    requests: [],
    scripted: [],
    holds: [],
    halted: false,
    haltedBooks: { dry: false, live: false },
    haltReason: null,
    haltReasons: { dry: null, live: null },
    alerts: [],
    bots: [],
    pnl: { bots: {} },
    fills: {},
    previews: [],
    caps: defaultCaps(),
    ceilings: defaultCeilings(),
    usedToday: defaultUsedToday(),
    switches: { live_enabled: false, ai_live_enabled: false, ceiling: true },
    // The engine's own per-book drawdown report: decimal strings, or null for no reading.
    drawdown: {
      dry: { equity: null, hwm: null, pct: null },
      live: { equity: null, hwm: null, pct: null },
    },
    products: ["BTC-USDC", "ETH-USDC", "XRP-USDC"],
    // What GET /orders?book= answers, by book.
    orders: { dry: [], live: [] },
    events: { events: [], last_id: 0 },
    killStatus: 200,
  };
  let server = null;
  let port = 0;

  // Which key this request's MAC was signed with, and whether it was an owner MAC the engine
  // holds no pin to approve. `mac` is "install", "owner" or "none"; an owner's signature on an
  // unpinned engine is never the owner's (`ownerRefused`), because the engine cannot check it.
  function macUsed(record) {
    const signature = record.headers["x-crow-signature"];
    const ts = record.headers["x-crow-timestamp"];
    const nonce = record.headers["x-crow-nonce"];
    if (!signature || !ts || !nonce) return { mac: "none", ownerRefused: false };
    const candidates = [["install", INSTALL_TOKEN]];
    if (state.pinSecret) candidates.push(["owner", state.pinSecret]);
    let ownerSigned = false;
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
      if (expected !== signature) continue;
      if (kind === "install") return { mac: "install", ownerRefused: false };
      ownerSigned = true;
    }
    if (!ownerSigned) return { mac: "none", ownerRefused: false };
    if (state.pinned !== true) return { mac: "none", ownerRefused: true };
    return { mac: "owner", ownerRefused: false };
  }

  /** A hold a test releases: the request is recorded first, then waits here. */
  function takeHold(record) {
    const index = state.holds.findIndex(
      (hold) => !hold.taken && hold.method === record.method && hold.path === record.path,
    );
    if (index < 0) return null;
    const hold = state.holds[index];
    hold.taken = true;
    return hold.promise;
  }

  function scriptedFor(method, path) {
    const index = state.scripted.findIndex((entry) => !entry.taken && entry.method === method && entry.path === path);
    if (index < 0) return null;
    const entry = state.scripted[index];
    entry.taken = true;
    return entry;
  }

  function bearerOk(req) {
    return String(req.headers.authorization || "") === `Bearer ${ENGINE_TOKEN}`;
  }

  function botById(id) {
    return state.bots.find((bot) => bot.id === id) || null;
  }

  /**
   * The refusal a live bot's action earns: an owner MAC this engine cannot approve is refused as
   * such, and a call with no owner signature at all is the one that simply needs the owner.
   */
  function liveNeedsOwner(record) {
    return record.ownerRefused === true ? "APPROVAL_INVALID" : "LIVE_NEEDS_OWNER";
  }

  async function handle(req, res) {
    const body = await readBody(req);
    const record = { method: req.method, path: req.url, headers: req.headers, body };
    const mac = macUsed(record);
    record.mac = mac.mac;
    record.ownerRefused = mac.ownerRefused;
    state.requests.push(record);

    const send = (status, payload) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    };

    const held = takeHold(record);
    if (held) await held;

    const scripted = scriptedFor(record.method, String(record.path));
    if (scripted) return send(scripted.status, scripted.body);

    const { path, query } = splitPath(record.path);
    const parsed = parseJson(body) || {};

    // ---- health (anonymous), credentials (their own MAC rules) --------------------------------

    if (req.method === "GET" && path === "/health") {
      return send(200, {
        ok: true,
        credentials: state.credentials,
        pinned: state.pinned,
        live_enabled: state.switches.live_enabled,
      });
    }

    if (!bearerOk(req)) return send(401, { detail: "unauthorized" });

    // A pin is the only thing an owner MAC can be checked against. Holding none, the engine
    // refuses such a call on every privileged route before it acts on any of it.
    if (record.ownerRefused === true && needsOwnerApproval(req.method, path)) {
      return send(403, { detail: "APPROVAL_INVALID" });
    }

    if (req.method === "POST" && path === "/credentials/check") {
      const wanted = state.pinned ? "owner" : "install";
      if (record.mac !== wanted) return send(403, { detail: "SECRET_MISMATCH" });
      return send(200, {
        state: "ok",
        key_last4: state.keyLast4,
        portfolio_last4: state.portfolioLast4,
      });
    }

    if (req.method === "POST" && path === "/credentials") {
      const wanted = state.pinned ? "owner" : "install";
      if (record.mac !== wanted) return send(403, { detail: "SECRET_MISMATCH" });
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
        key_last4: state.keyLast4,
        portfolio_last4: state.portfolioLast4,
      });
    }

    if (req.method === "POST" && path === "/credentials/forget") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      state.pinned = false;
      state.pinSecret = null;
      state.credentials = "not_ready";
      state.switches = { live_enabled: false, ai_live_enabled: false, ceiling: state.switches.ceiling };
      return send(200, { ok: true, state: "missing", pinned: false });
    }

    if (req.method === "DELETE" && path === "/credentials") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      state.credentials = "not_ready";
      return send(200, { ok: true, state: "missing", pinned: state.pinned });
    }

    // ---- reads -------------------------------------------------------------------------------

    if (req.method === "GET" && path === "/status") {
      return send(200, {
        halted: state.halted || state.haltedBooks.dry === true || state.haltedBooks.live === true,
        halted_books: state.haltedBooks,
        halt_reason: state.haltReason,
        halt_reasons: state.haltReasons,
        heartbeat: { ts: Math.floor(Date.now() / 1000) },
        bots: state.bots.map((bot) => ({
          id: bot.id,
          product: bot.product,
          strategy: bot.strategy,
          status: bot.status,
          init_done: bot.init_done,
        })),
        recent_alerts: state.alerts,
        live_switches: { ...state.switches },
        drawdown: state.drawdown,
        products: state.products,
      });
    }

    if (req.method === "GET" && path === "/events") {
      return send(200, state.events);
    }

    if (req.method === "GET" && path === "/bots") {
      return send(200, state.bots);
    }

    if (req.method === "GET" && path === "/pnl") {
      return send(200, { bots: state.pnl.bots });
    }

    const fillsMatch = path.match(/^\/bots\/([^/]+)\/fills$/);
    if (req.method === "GET" && fillsMatch) {
      return send(200, state.fills[fillsMatch[1]] || []);
    }

    if (req.method === "GET" && path === "/caps") {
      return send(200, {
        caps: state.caps,
        ceilings: state.ceilings,
        used_today: state.usedToday,
      });
    }

    if (req.method === "GET" && path === "/ai/previews") {
      const wanted = query.get("state");
      return send(200, wanted ? state.previews.filter((preview) => preview.state === wanted) : state.previews);
    }

    if (req.method === "GET" && path === "/orders") {
      const book = query.get("book");
      if (book !== null && book !== "dry" && book !== "live") {
        return send(422, { code: "INVALID", message: "book must be dry or live" });
      }
      if (book === null) return send(200, [...state.orders.dry, ...state.orders.live]);
      return send(200, state.orders[book] || []);
    }

    // ---- bots --------------------------------------------------------------------------------

    if (req.method === "POST" && path === "/bots") {
      const created = fakeBot({
        id: typeof parsed.id === "string" && parsed.id ? parsed.id : "bot-created",
        product: String(parsed.product ?? "BTC-USDC"),
        strategy: String(parsed.strategy ?? "rebalance"),
        params: parsed.params && typeof parsed.params === "object" ? parsed.params : {},
        mode: "dry",
        status: "ACTIVE",
        capital_quote: String(parsed.capital_quote ?? "0"),
        capital_base: String(parsed.capital_base ?? "0"),
      });
      state.bots.push(created);
      return send(201, created);
    }

    const actionMatch = path.match(/^\/bots\/([^/]+)\/(pause|stop|resume|recenter|mode)$/);
    if (req.method === "POST" && actionMatch) {
      const [, id, action] = actionMatch;
      const bot = botById(id);
      if (!bot) return send(404, { detail: "no such bot" });

      if (action === "pause" || action === "stop") {
        if (action === "pause" && bot.status !== "ACTIVE") {
          return send(409, { detail: `bot ${id} is ${bot.status}, not ACTIVE` });
        }
        bot.status = action === "pause" ? "PAUSED" : "STOPPED";
        return send(200, bot);
      }

      if (action === "resume") {
        if (bot.mode === "live" && record.mac !== "owner") {
          return send(403, { detail: liveNeedsOwner(record) });
        }
        if (parsed.acknowledge_rebase !== true) return send(409, { detail: "RESUME_ACK" });
        bot.status = "ACTIVE";
        return send(200, bot);
      }

      if (action === "recenter") {
        if (bot.mode === "live" && record.mac !== "owner") {
          return send(403, { detail: liveNeedsOwner(record) });
        }
        bot.params = { ...(bot.params || {}), center: String(parsed.center ?? "") };
        return send(200, bot);
      }

      // action === "mode": privileged.
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      if (parsed.mode !== "dry" && parsed.mode !== "live") return send(422, { code: "INVALID" });
      if (parsed.mode === "live") {
        if (state.switches.ceiling === false) {
          return send(409, { detail: "LIVE_DISABLED: the live ceiling is off" });
        }
        if (parsed.acknowledge_live !== true) {
          return send(409, { detail: "live needs acknowledge_live: true" });
        }
        if (parsed.capital_quote !== undefined) bot.live_capital_quote = String(parsed.capital_quote);
        if (parsed.capital_base !== undefined) bot.live_capital_base = String(parsed.capital_base);
      }
      bot.mode = parsed.mode;
      return send(200, bot);
    }

    // ---- the switches and the caps -----------------------------------------------------------

    if (req.method === "POST" && path === "/switches") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      const wanted = {};
      if (parsed.live_enabled !== undefined) wanted.live_enabled = parsed.live_enabled;
      if (parsed.ai_live_enabled !== undefined) wanted.ai_live_enabled = parsed.ai_live_enabled;
      if (Object.keys(wanted).length === 0) return send(422, { code: "INVALID" });
      if (state.switches.ceiling === false && Object.values(wanted).some((value) => value === true)) {
        return send(409, { detail: "LIVE_DISABLED: the live ceiling is off" });
      }
      Object.assign(state.switches, wanted);
      return send(200, { ...state.switches });
    }

    if (req.method === "POST" && path === "/caps") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      const wanted = parsed.caps && typeof parsed.caps === "object" ? parsed.caps : null;
      if (!wanted) return send(422, { code: "INVALID" });
      for (const [name, value] of Object.entries(wanted)) {
        const ceiling = state.ceilings[name];
        if (ceiling === undefined) return send(422, { code: "INVALID", message: `unknown cap ${name}` });
        if (Number(String(value)) > Number(String(ceiling))) {
          return send(422, { code: "ABOVE_CEILING", message: `above the ceiling of ${name}` });
        }
      }
      for (const [name, value] of Object.entries(wanted)) {
        state.caps[name] = typeof state.ceilings[name] === "number" ? Math.trunc(Number(value)) : String(value);
      }
      return send(200, { caps: state.caps, ceilings: state.ceilings });
    }

    // ---- kill and halt clear -----------------------------------------------------------------

    if (req.method === "POST" && path === "/kill") {
      // Bearer only, by design: stopping is never blocked by an approval.
      state.halted = true;
      state.haltReason = "kill switch";
      for (const bot of state.bots) bot.status = "STOPPED";
      if (state.killStatus >= 400) {
        return send(state.killStatus, { detail: "the sweep failed", halted: true });
      }
      return send(200, { halted: true, cancelled: 1, stopped: state.bots.map((bot) => bot.id) });
    }

    if (req.method === "POST" && path === "/halt/clear") {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      if (parsed.acknowledge_rebase !== true) return send(409, { detail: "HALT_CLEAR_ACK" });
      state.halted = false;
      state.haltReason = null;
      state.haltedBooks = { dry: false, live: false };
      state.haltReasons = { dry: null, live: null };
      return send(200, { halted: false, rebased: {}, reinitialised: [] });
    }

    // ---- AI previews -------------------------------------------------------------------------

    const approveMatch = path.match(/^\/ai\/previews\/([^/]+)\/approve$/);
    if (req.method === "POST" && approveMatch) {
      if (record.mac !== "owner") return send(403, { detail: "APPROVAL_INVALID" });
      const preview = state.previews.find((row) => row.preview_id === approveMatch[1]);
      if (!preview) return send(404, { code: "NOT_FOUND", message: "That proposal is gone. Ask again." });
      if (preview.state !== "pending") {
        return send(409, { code: "NOT_PENDING", message: "That proposal is no longer waiting for you." });
      }
      if (String(parsed.hash) !== preview.hash) {
        return send(409, { code: "HASH_MISMATCH", message: "That proposal changed." });
      }
      preview.state = "placed";
      return send(200, {
        preview_id: preview.preview_id,
        state: "placed",
        cid: "cid-test-1",
        book: preview.book,
      });
    }

    const rejectMatch = path.match(/^\/ai\/previews\/([^/]+)\/reject$/);
    if (req.method === "POST" && rejectMatch) {
      const preview = state.previews.find((row) => row.preview_id === rejectMatch[1]);
      if (!preview) return send(404, { code: "NOT_FOUND", message: "That proposal is gone. Ask again." });
      if (preview.state !== "pending" && preview.state !== "approved") {
        return send(409, { code: "NOT_PENDING", message: "That proposal is no longer waiting for you." });
      }
      preview.state = "rejected";
      return send(200, { preview_id: preview.preview_id, state: "rejected", refusal: "REJECTED" });
    }

    // ---- the lease (the panel's loops) -------------------------------------------------------

    if (req.method === "POST" && path === "/lease") {
      if (record.mac === "none") return send(403, { detail: "APPROVAL_INVALID" });
      return send(200, { held: true, cursor: state.events.last_id });
    }

    if (req.method === "POST" && path === "/lease/cursor") {
      if (record.mac === "none") return send(403, { detail: "APPROVAL_INVALID" });
      return send(200, { cursor: Number(parsed.cursor) || 0 });
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
    callsMatching: (method, prefix) =>
      state.requests.filter((r) => r.method === method && String(r.path).startsWith(prefix)),
    last: (method, path) => {
      const found = state.requests.filter((r) => r.method === method && r.path === path);
      return found.length ? found[found.length - 1] : null;
    },
    /** Answer the next matching request from a script instead of the default handler. */
    next: (method, path, answer) => state.scripted.push({ method, path, taken: false, ...answer }),
    /** Record the next matching request, then hold it until `release()`. */
    holdNext(method, path) {
      let release = () => {};
      const promise = new Promise((resolve) => { release = () => resolve(); });
      state.holds.push({ method, path, taken: false, promise });
      return { release };
    },
    /** The engine's volume is gone: no pin, nothing ready, same address. */
    wipe() {
      state.pinned = false;
      state.pinSecret = null;
      state.credentials = "not_ready";
    },
    close: () => closeServer(server),
  };
}

// ---- the real step-up gate, with its two seams injected ---------------------------------------

/**
 * The gate the routes meet: `createStepUpGate` from the dashboard, with the TOTP secret and the
 * time-step matcher supplied here. Its own replay guard (a step at or below the last accepted one
 * is refused, on any session) and its own per-session lockout are unchanged.
 *
 * `nextCode()` mints a code for a later step, so a test can make several successful privileged
 * calls in a row; the first one is `TOTP` and reusing any code is refused.
 */
export function createPanelStepUpGate() {
  const steps = new Map([[TOTP, 1]]);
  let issued = 0;
  const gate = createStepUpGate({
    getTotpSecret: async () => TOTP_SECRET,
    verifyTotpStep: async (code) => {
      const text = typeof code === "string" ? code.trim() : String(code === undefined || code === null ? "" : code).trim();
      const step = steps.get(text);
      return Number.isInteger(step) ? step : null;
    },
    is2faEnabled: async () => true,
  });
  gate.nextCode = () => {
    issued += 1;
    if (issued === 1) return TOTP;
    const step = issued;
    const code = String(123456 + step - 1).padStart(6, "0");
    steps.set(code, step);
    return code;
  };
  gate.steps = steps;
  return gate;
}

// ---- one panel scaffold per test --------------------------------------------------------------

let routesModule = null;
async function panelRoutes() {
  if (!routesModule) routesModule = await import("../../bundles/coinbase/panel/routes.js");
  return routesModule;
}

/**
 * One scratch install with the panel's routes mounted in a real express app.
 *
 * Options: `isLocal` and `twoFactor` seed the mutable `h.flags` the seams read (a test may flip
 * either at run time), `fake` reuses an engine the caller made, `saveBundleEnv`, `startLoopsImpl`,
 * `stepUpGate` and `notify` replace those seams, and `mode: "default"` mounts the router's default
 * export (the boot-time one that starts the loops) instead of `createPanelRoutes`.
 *
 * `engineClientFactory: null` means no factory at all: the routes fall back to their own real
 * client, which reads its bearer token from this scratch home's installed-bundle `.env` and is
 * pointed at the fake engine by the `engineBaseUrl` seam (`routes.js` hands it to
 * `createEngineClient`; unset would mean the client's own default address). `realLoops: true`
 * starts the bundle's real `startLoops` on short intervals instead of the spy, so a test can see
 * the lease and the event feed; `routesModule` mounts a caller-made copy of the routes file.
 *
 * `seams` is an additive escape hatch: every key it carries is handed to `createPanelRoutes` (or
 * to the module's default export) beside the ones above, so a test can inject a seam this scaffold
 * does not name itself — the routes' `now` clock, for instance. Without it nothing changes.
 */
export async function scaffold(options = {}) {
  const settings = options || {};
  const ctx = await freshDb();
  const db = createDbClient(ctx.path);
  const projectId = await mkProject(db, `Trading ${dbN}`);
  const fake = settings.fake || await createFakeEngine();

  const flags = {
    isLocal: settings.isLocal !== false,
    twoFactor: settings.twoFactor !== false,
  };

  const saveBundleEnvCalls = [];
  const givenSave = typeof settings.saveBundleEnv === "function" ? settings.saveBundleEnv : null;
  const saveBundleEnv = async (bundleId, envVars) => {
    saveBundleEnvCalls.push({ bundleId, envVars });
    if (givenSave) return givenSave(bundleId, envVars);
    return { status: 200, body: { ok: true } };
  };

  const startLoopsCalls = [];
  const loopsHandles = [];
  const wantRealLoops = settings.realLoops === true;
  const startLoopsImpl = typeof settings.startLoopsImpl === "function"
    ? settings.startLoopsImpl
    : wantRealLoops
      ? (loopsOptions) => {
        startLoopsCalls.push(loopsOptions);
        const inner = realStartLoops({
          ...loopsOptions,
          intervalsMs: { lease: 20, repush: 20, notify: 20 },
        });
        const handle = {
          stopped: false,
          stop() {
            handle.stopped = true;
            try { inner.stop(); } catch { /* already stopped */ }
          },
        };
        loopsHandles.push(handle);
        return handle;
      }
      : (loopsOptions) => {
        startLoopsCalls.push(loopsOptions);
        const handle = { stopped: false, stop() { handle.stopped = true; } };
        loopsHandles.push(handle);
        return handle;
      };

  const stepUpGate = settings.stepUpGate || createPanelStepUpGate();
  const notifications = [];
  const notify = typeof settings.notify === "function"
    ? settings.notify
    : async (payload) => { notifications.push(payload); return null; };

  const authMiddleware = typeof settings.authMiddleware === "function"
    ? settings.authMiddleware
    : (req, _res, next) => { req.dashboardSession = SESSION; next(); };

  // `null` asks for no factory at all: the routes' own real client is the one under test.
  const noEngineClientFactory = settings.engineClientFactory === null;
  const engineClientFactory = typeof settings.engineClientFactory === "function"
    ? settings.engineClientFactory
    : ({ secretProvider }) => createEngineClient({ baseUrl: fake.baseUrl, token: ENGINE_TOKEN, secretProvider });

  const seams = {
    db,
    crowHome: HOME,
    authMiddleware,
    isLocalSession: async () => flags.isLocal === true,
    is2faEnabled: async () => flags.twoFactor === true,
    stepUpGate,
    loadKey: () => K.ensureWriteKey(db, { crowHome: HOME }),
    saveBundleEnv,
    startLoopsImpl,
    notify,
    // Where a client built by the routes' own default factory should call.
    engineBaseUrl: typeof settings.engineBaseUrl === "string" && settings.engineBaseUrl
      ? settings.engineBaseUrl
      : fake.baseUrl,
    ...(noEngineClientFactory ? {} : { engineClientFactory }),
    ...(settings.seams && typeof settings.seams === "object" ? settings.seams : {}),
  };

  const module = settings.routesModule || await panelRoutes();
  let panel = null;
  let router;
  if (settings.mode === "default") {
    router = module.default(authMiddleware, seams);
  } else {
    if (typeof module.createPanelRoutes !== "function") {
      throw new TypeError("bundles/coinbase/panel/routes.js has no createPanelRoutes export");
    }
    panel = await module.createPanelRoutes(seams);
    router = panel.router;
  }

  const app = express();
  app.use(router);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  // Every request/answer pair, so a test can scan what the browser was sent.
  const exchanges = [];

  async function call(method, path, body, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (opts.session !== false) {
      headers.cookie = `crow_session=${SESSION}`;
      if (opts.csrf !== false && method !== "GET") headers["x-crow-csrf"] = csrfTokenFor(SESSION);
    }
    let payload;
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(body);
    }
    const res = await fetch(base + path, { method, headers, body: payload });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not JSON */ }
    exchanges.push({ method, path, requestBody: payload === undefined ? "" : payload, status: res.status, responseText: text });
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

  const h = {
    db,
    projectId,
    fake,
    flags,
    stepUpGate,
    saveBundleEnvCalls,
    startLoopsCalls,
    loopsHandles,
    notifications,
    panel,
    exchanges,
    get: (path, opts) => call("GET", path, undefined, opts),
    post: (path, body, opts) => call("POST", path, body, opts),
    freshCode: () => stepUpGate.nextCode(),
    connect: (extra = {}) => call("POST", "/api/coinbase/connect", {
      key_name: KEY_NAME,
      private_key: PRIVATE_KEY,
      project_id: projectId,
      totp: stepUpGate.nextCode(),
      ...extra,
    }),
    testKey: (extra = {}) => call("POST", "/api/coinbase/connect/test", {
      key_name: KEY_NAME,
      private_key: PRIVATE_KEY,
      totp: stepUpGate.nextCode(),
      ...extra,
    }),
    disconnect: (extra = {}) => call("POST", "/api/coinbase/disconnect", {
      totp: stepUpGate.nextCode(),
      ...extra,
    }),
    connections: async () => (await db.execute({
      sql: `SELECT uuid, project_id, service_id, status, account_label, config
              FROM service_connections WHERE service_id = 'coinbase' ORDER BY id`,
      args: [],
    })).rows,
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
    /** One `dashboard_settings` value, JSON-decoded when it is JSON, else as stored. */
    setting: async (name) => {
      const row = (await db.execute({
        sql: "SELECT value FROM dashboard_settings WHERE key = ?",
        args: [name],
      })).rows[0];
      if (!row) return null;
      const value = String(row.value ?? "");
      try { return JSON.parse(value); } catch { return value; }
    },
    close: async () => {
      await closeServer(server);
      for (const handle of loopsHandles) {
        try { handle.stop(); } catch { /* already stopped */ }
      }
      if (panel && typeof panel.stopLoops === "function") {
        try { await panel.stopLoops(); } catch { /* already stopped */ }
      }
      await fake.close();
      try { db.close(); } catch { /* already closed */ }
    },
  };
  h.key = key;
  return h;
}

// ---- the panel page, rendered through its own handler -----------------------------------------

/**
 * Call the panel file's handler with a layout that returns what it was given, so a test reads the
 * content and the script as rendered. No engine call is made by the handler.
 */
export async function renderPanelPage(options = {}) {
  const settings = options || {};
  const module = await import("../../bundles/coinbase/panel/coinbase.js");
  const panel = module.default;
  const captured = [];
  const layout = typeof settings.layout === "function"
    ? settings.layout
    : (args) => { captured.push(args); return args; };
  const req = {
    query: settings.query || {},
    headers: {},
    method: "GET",
    dashboardSession: SESSION,
  };
  const answer = await panel.handler(req, {}, { layout, lang: settings.lang || "en" });
  const rendered = answer || captured[0] || {};
  return {
    panel,
    answer,
    rendered,
    title: String(rendered.title ?? ""),
    content: String(rendered.content ?? ""),
    scripts: String(rendered.scripts ?? ""),
  };
}