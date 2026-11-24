/**
 * The Trading panel's own routes.
 *
 * The Connect flow lives in `panel/connect.js` and keeps its four routes; this module mounts them
 * and adds everything the page does once a key is in place:
 *
 *   GET  /api/coinbase/panel                    one aggregated read for the whole page
 *   GET  /api/coinbase/projects                 the project picker (only before a connection)
 *   POST /api/coinbase/bots                     a new bot, always Practice
 *   POST /api/coinbase/bots/:id/pause|stop      pause and stop
 *   POST /api/coinbase/bots/:id/mode            Practice ↔ Live
 *   POST /api/coinbase/bots/:id/resume|recenter
 *   POST /api/coinbase/switches                 the two live switches
 *   POST /api/coinbase/caps                     the limits form (with the drawdown warning)
 *   POST /api/coinbase/kill                     the kill switch
 *   POST /api/coinbase/halt/clear               "Resume trading"
 *   POST /api/coinbase/previews/:id/approve     approve one AI proposal (panel/approve.js)
 *   POST /api/coinbase/previews/:id/reject      "Not now"
 *
 * Gates, in plain terms (the Connect routes own them and hand them over; the kill switch's own
 * local-session check lives in this file, so stopping never depends on that module loading):
 *
 *   - a local password session on this Crow is required everywhere;
 *   - a privileged action also needs 2FA switched on and a fresh code from the one step-up gate
 *     this process has, so a code already used is never used again;
 *   - the kill switch, pausing and stopping a bot, moving a bot back to practice, "Not now",
 *     turning a live switch OFF, making a bot and reading the page need the local session only —
 *     nothing that stops trading is ever held up by a code;
 *   - nothing here signs an engine call itself: the engine client signs every privileged call
 *     with the sealed owner secret, so no browser field ever reaches a signature.
 *
 * State is the engine's: the two live switches, each book's drawdown, the products and each book's
 * resting orders are read from the engine's own answers, and this module keeps no copy of any of
 * them, so reading the page writes nothing to the database.
 *
 * Privacy is a rule of the module: no key name, private key, approval secret, engine token or
 * install token is read, logged, audited or answered here. Only the last four characters of a
 * fingerprint, plain sentences and machine codes reach the page.
 *
 * Installed-copy rule: this file runs from `<CROW_HOME>/panels/coinbase-routes.js`, so it never
 * imports a sibling statically. Its own modules load through `bundleImport`, app code through
 * `appImport` with literal paths, both at call time.
 */
import { createHash, randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

// ---- express, from the app root ----------------------------------------------------------------

/**
 * The app root this copy resolves app code and packages from.
 *
 * An installed copy of this file runs as `<CROW_HOME>/panels/coinbase-routes.js`, beside the
 * gateway and with no `node_modules` of its own, so express is loaded from the app root's own
 * package tree by name rather than from a relative node_modules.
 */
const APP_ROOT = process.env.CROW_APP_ROOT || join(homedir(), "crow");

/** One package of the app root, by name, as the app itself resolves it. */
const appPackage = (name) =>
  import(pathToFileURL(createRequire(join(APP_ROOT, "package.json")).resolve(name)).href);

const express = (await appPackage("express")).default;
const { Router, json } = express;

const PREFIX = "/api/coinbase";
const SERVICE_ID = "coinbase";
const ACTOR_TYPE = "local";

const CAP_DRAWDOWN = "CROW_COINBASE_PORTFOLIO_DRAWDOWN_PCT";

const ACTIVITY_PANEL = "coinbase.panel";
const ACTIVITY_PROJECTS = "coinbase.projects";
const ACTIVITY_BOTS_CREATE = "coinbase.bots_create";
const ACTIVITY_BOTS_PAUSE = "coinbase.bots_pause";
const ACTIVITY_BOTS_STOP = "coinbase.bots_stop";
const ACTIVITY_BOTS_MODE = "coinbase.bots_mode";
const ACTIVITY_BOTS_RESUME = "coinbase.bots_resume";
const ACTIVITY_BOTS_RECENTER = "coinbase.bots_recenter";
const ACTIVITY_SWITCHES = "coinbase.switches";
const ACTIVITY_CAPS = "coinbase.caps";
const ACTIVITY_KILL = "coinbase.kill";
const ACTIVITY_HALT_CLEAR = "coinbase.halt_clear";
const ACTIVITY_PREVIEW_APPROVE = "coinbase.previews_approve";
const ACTIVITY_PREVIEW_REJECT = "coinbase.previews_reject";

const MESSAGE_GENERIC = "Crow could not do that. Try again.";
const MESSAGE_NOT_READY = "The Trading routes are not ready yet. Try again in a moment.";
const MESSAGE_ENGINE_UNREACHABLE =
  "The trading engine isn't answering. Check that the Coinbase add-on is running.";
const MESSAGE_KILL_CONFIRM = "Press the kill switch again to confirm.";
const MESSAGE_KILL_SUCCESS =
  "Stopped. Every Crow order is being cancelled and every bot is stopped. " +
  "Press Resume trading when you are ready.";
const MESSAGE_KILL_NOT_READY =
  "The kill switch can only cancel orders on Coinbase once the engine reconnects.";
// Nobody was reached: nothing stopped, and the owner has to cancel at Coinbase by hand.
const MESSAGE_KILL_ENGINE_DOWN =
  "Nothing was stopped: the trading engine is down. " +
  "Cancel open orders by hand in the Coinbase app: Crow portfolio \u2192 Open orders.";
// The engine answered, and refused Crow's own token: it was reached but will take no call.
const MESSAGE_KILL_ENGINE_REFUSED =
  "Nothing was stopped: Crow couldn't reach the trading engine. " +
  "Cancel open orders by hand in the Coinbase app: Crow portfolio \u2192 Open orders.";
// The engine answered, and some of its own steps failed.
const MESSAGE_KILL_PARTIAL = "Trading is halted, but some orders may still be resting on Coinbase.";
const MESSAGE_HALT_CLEARED =
  "Resumed. Crow may trade again. Bots that were stopped stay stopped; " +
  "create a new bot to trade again.";
const MESSAGE_CONFIRM_LIVE = "Confirm that this bot will trade with real money.";
const MESSAGE_CONFIRM_RESUME = "Confirm that this bot may start again from the prices now.";
const MESSAGE_WOULD_HALT_LIVE = "This halts live trading now. Press Save again to confirm.";
const MESSAGE_WOULD_HALT_PRACTICE = "This halts practice trading now. Press Save again to confirm.";
const MESSAGE_ENGINE_DOWN_NOTE = "Trading engine is not responding.";
const MESSAGE_DISCONNECT_UNFINISHED = "Disconnect didn't finish \u2014 press Disconnect again";
const MESSAGE_NEEDS_RECONNECT = "Crow lost its link to the trading engine. Press Connect again.";
const MESSAGE_CONNECTED_PREFIX = "Connected \u2014 Crow portfolio \u2026";
// The Stock prices card's own five sentences, one per state the panel can be in. They are fixed
// here rather than taken from the engine's answer, so the engine's own words never reach the page.
// "paused" is Tiingo limiting Crow, not a refused token: the token is fine and the prices wait on
// their own, so the sentence says that and the card keeps Disconnect.
const MESSAGE_PRICES_CONNECTED = "Stock prices are connected (Tiingo).";
const MESSAGE_PRICES_MISSING =
  "Stock prices are not connected, so practice stock orders will not fill. " +
  "Paste your free Tiingo token below.";
const MESSAGE_PRICES_REJECTED = "Tiingo did not accept the token. Paste it again.";
const MESSAGE_PRICES_PAUSED =
  "Stock prices are paused for now (Tiingo is limiting requests); they will resume on their own.";
const MESSAGE_PRICES_COINBASE_OFF = "Connect Coinbase first, then add stock prices.";
const MESSAGE_NO_BOT = "That bot is gone. Open the Trading page again.";
const MESSAGE_NO_PRODUCT = "Pick what to trade first.";
const MESSAGE_GRID_FIELDS =
  "Fill in the grid: a centre price, a step, how many levels each way and how much each buy spends.";
const MESSAGE_BAD_NUMBER = "That is not a number Crow can use.";
const MESSAGE_BAD_MODE = "Choose Practice or Live.";
const MESSAGE_BAD_CAPITAL_BASE = "Starting coin must be zero or more.";
const MESSAGE_NO_SWITCH = "Pick a switch first.";
const MESSAGE_NO_LIMITS = "Type the new limits first.";
const MESSAGE_UNKNOWN_LIMIT = "Crow does not know that limit.";
const MESSAGE_BOT_CREATED = "Created. It practises with pretend money until you take it live.";
const MESSAGE_BOT_PAUSED =
  "Paused. Its waiting orders on Coinbase were cancelled, and it places no new ones until you resume.";
// The pause went through but a waiting order could not be cancelled: the owner presses Pause again.
const MESSAGE_BOT_PAUSE_INCOMPLETE =
  "Paused, but Crow couldn't cancel every waiting order on Coinbase. Press Pause again, or cancel " +
  "them in the Coinbase app: Crow portfolio \u2192 Open orders.";
// Pause pressed again moments after the last one: one plain sentence, and nothing was swept.
const MESSAGE_BOT_PAUSE_TOO_SOON =
  "Pause was just pressed for this bot. Wait a few seconds and press Pause again.";
// The two races a pause can lose keep the engine's code and status and get this file's sentence:
// one plain line, and never the engine's own words for the owner to read.
const MESSAGE_PAUSE_IN_PROGRESS = "This bot is being paused. Wait a few seconds and try again.";
const MESSAGE_PAUSE_CHANGED =
  "This bot changed while it was being paused. Check it, and press Pause again if it still needs it.";
const MESSAGE_BOT_STOPPED = "Stopped.";
const MESSAGE_BOT_LIVE = "Live. It now trades with real money.";
const MESSAGE_BOT_PRACTICE =
  "Back to practice. The bot's orders waiting on Coinbase were cancelled and it now trades with " +
  "pretend money. Nothing was sold.";
const MESSAGE_BOT_RESUMED = "Started again from the prices now.";
const MESSAGE_BOT_RECENTERED = "Centre moved.";
const MESSAGE_CAPS_SAVED = "Saved.";
const MESSAGE_LOCAL_LOGIN =
  "Sign in on this Crow with your password to connect Coinbase (peer sign-in is not enough).";

/** The word each live switch is about, in the order two changed switches read in one answer. */
const SWITCH_ORDER = ["live_enabled", "ai_live_enabled"];

/** The one sentence each switch change earns, in the owner's words. */
const SWITCH_MESSAGES = {
  live_enabled: {
    true: "Bots can now trade with real money.",
    false: "Bots are back to practice only.",
  },
  ai_live_enabled: {
    true: "The AI can now place real orders after you approve them.",
    false: "The AI can no longer place real orders.",
  },
};
const MESSAGE_SWITCH_UNCHANGED = "Those switches are already set that way.";
// The engine's switches sit behind its pin: with nothing connected there is nothing to switch.
const MESSAGE_SWITCH_NOT_CONNECTED = "Coinbase isn't connected, so nothing was switched.";

const NOTE_NEEDS_ATTENTION = "This bot needs attention: the trading engine paused it.";
const NOTE_GRID = "No edge on average: it behaves like holding about half in the coin.";

/** The plain name of each limit, so a refusal can say what it is about. */
const CAP_LABELS = {
  CROW_COINBASE_DAILY_NOTIONAL_USD: "How much Crow may trade each day",
  CROW_COINBASE_ORDERS_PER_HOUR: "How many orders Crow may place each hour",
  CROW_COINBASE_PORTFOLIO_DRAWDOWN_PCT: "How far the portfolio may fall before trading stops",
  CROW_COINBASE_BOT_MAX_ORDER_USD: "The most one bot order may be",
  CROW_COINBASE_MAX_BOT_CAPITAL_USD: "The most capital one bot may use",
  CROW_COINBASE_AI_MAX_ORDER_USD: "The most one AI order may be",
  CROW_COINBASE_AI_DAILY_NOTIONAL_USD: "How much the AI may trade each day",
  CROW_COINBASE_AI_ORDERS_PER_HOUR: "How many AI orders may be placed each hour",
  CROW_COINBASE_AI_CAPITAL_USD: "The most capital the AI may use",
};

// ---- installed copy: its own modules and the app's ---------------------------------------------

const CROW_HOME = () => process.env.CROW_HOME || join(homedir(), ".crow");

/** The bundle directory this copy belongs to: the installed one when it holds the file, else the app's. */
function bundleDir() {
  const installed = join(CROW_HOME(), "bundles", SERVICE_ID);
  if (existsSync(join(installed, "panel", "connect.js"))) return installed;
  return join(process.env.CROW_APP_ROOT || join(homedir(), "crow"), "bundles", SERVICE_ID);
}

const bundleImport = (rel) => import(pathToFileURL(join(bundleDir(), rel)).href);
const appImport = (rel) =>
  import(pathToFileURL(join(process.env.CROW_APP_ROOT || join(homedir(), "crow"), rel)).href);

/** One import per process, retried after a failure (an installed copy can be refreshed in place). */
function lazy(load) {
  let pending = null;
  return () => {
    if (!pending) {
      pending = Promise.resolve().then(load);
      pending.catch(() => {
        pending = null;
      });
    }
    return pending;
  };
}

const connectModule = lazy(() => bundleImport("panel/connect.js"));
const approveModule = lazy(() => bundleImport("panel/approve.js"));
const engineClientModule = lazy(() => bundleImport("server/engine-client.js"));
const loopsModule = lazy(() => bundleImport("server/loops.js"));
const notifierModule = lazy(() => bundleImport("server/notifier.js"));
const notificationsModule = lazy(() => appImport("servers/shared/notifications.js"));
const aclModule = lazy(() => appImport("servers/shared/project-acl.js"));
const totpModule = lazy(() => appImport("servers/gateway/dashboard/totp.js"));
const localSessionModule = lazy(() => appImport("servers/gateway/dashboard/local-session.js"));
const csrfModule = lazy(() => appImport("servers/gateway/dashboard/shared/csrf.js"));
const bundlesRoutesModule = lazy(() => appImport("servers/gateway/routes/bundles.js"));

// ---- plain helpers -----------------------------------------------------------------------------

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseConfig(text) {
  if (!text) return {};
  try {
    const parsed = JSON.parse(String(text));
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

/** The last four characters of a value the engine reported, and never more. */
function last4(value) {
  if (value === undefined || value === null) return null;
  const text = String(value);
  return text === "" ? null : text.slice(-4);
}

/** A numeric value as a plain decimal string, or null when it is not one. */
function decimalText(value) {
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : null;
  if (typeof value !== "string") return null;
  const text = value.trim();
  return /^-?\d+(?:\.\d+)?$/.test(text) ? text : null;
}

/** A money value as text (money stays text end to end), or null. */
function moneyText(value) {
  return decimalText(value);
}

/**
 * A capital value as plain non-negative fixed-notation text: undefined when the field was not
 * given at all (missing, null or blank), the text itself when it is such a number, and null when
 * it was given but is not one. Exponent forms, negatives, NaN, Infinity, "+1" and ".5" are all
 * not.
 */
function capitalText(value) {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "number") {
    const text = String(value);
    return /^\d+(?:\.\d+)?$/.test(text) ? text : null;
  }
  if (typeof value !== "string") return null;
  const text = value.trim();
  if (text === "") return undefined;
  return /^\d+(?:\.\d+)?$/.test(text) ? text : null;
}

function fractionDigits(text) {
  const at = text.indexOf(".");
  return at === -1 ? 0 : text.length - at - 1;
}

function toScaled(text, scale) {
  const negative = text.startsWith("-");
  const body = negative ? text.slice(1) : text;
  const at = body.indexOf(".");
  const whole = at === -1 ? body : body.slice(0, at);
  const fraction = at === -1 ? "" : body.slice(at + 1);
  const digits = `${whole}${fraction.padEnd(scale, "0").slice(0, scale)}`.replace(/^0+(?=\d)/, "");
  const value = BigInt(digits === "" ? "0" : digits);
  return negative ? -value : value;
}

/**
 * Compare two decimal strings by value, never as floats and never as text: "200.00" equals "200"
 * and "200.01" is above it. null when either side is not a number.
 */
function compareDecimals(a, b) {
  const left = decimalText(a);
  const right = decimalText(b);
  if (left === null || right === null) return null;
  const scale = Math.max(fractionDigits(left), fractionDigits(right));
  const x = toScaled(left, scale);
  const y = toScaled(right, scale);
  if (x === y) return 0;
  return x < y ? -1 : 1;
}

function wholeNumber(value) {
  const text = decimalText(value);
  if (text === null) return null;
  const number = Number(text);
  return Number.isFinite(number) ? Math.trunc(number) : null;
}

/** A fresh Practice bot id: "bot-" and six hex characters. */
function newBotId() {
  return `bot-${randomBytes(3).toString("hex")}`;
}

/** The lease holder id for one Crow home, in the shape server/loops.js uses. */
function holderFor(crowHome) {
  const digest = createHash("sha256").update(String(crowHome ?? ""), "utf8").digest("hex");
  return `gw-${digest.slice(0, 24)}`;
}

/** Every method the engine client has: the default client is the whole client, never a part. */
const CLIENT_METHODS = Object.freeze([
  "health",
  "status",
  "events",
  "balances",
  "caps",
  "bots",
  "botFills",
  "pnl",
  "aiPreviews",
  "createBot",
  "botPause",
  "botStop",
  "kill",
  "aiPreview",
  "aiReject",
  "aiCancel",
  "botResume",
  "botRecenter",
  "setMode",
  "setSwitches",
  "setCaps",
  "clearHalt",
  "approve",
  "clearCredentials",
  "forgetCredentials",
  "lease",
  "leaseCursor",
  "checkCredentials",
  "pushCredentials",
  "orders",
]);

/** The answer a call this process cannot make reads as: an engine that did not answer. */
function unreachable() {
  return { ok: false, status: 0, code: "ENGINE_UNREACHABLE", message: MESSAGE_ENGINE_UNREACHABLE };
}

/**
 * One engine call that never throws and never invents a method: a client without it, a client that
 * is not there at all and a call that throws all read as an engine that did not answer, which every
 * handler then refuses in plain words.
 */
async function callClient(client, name, ...args) {
  if (!client || typeof client[name] !== "function") return unreachable();
  try {
    return await client[name](...args);
  } catch {
    return unreachable();
  }
}

/** The two live switches as the page shows them: the engine's own status, or all off and unknown. */
function switchesOf(status) {
  const live = status && isPlainObject(status.live_switches) ? status.live_switches : null;
  return {
    live_enabled: live ? live.live_enabled === true : false,
    ai_live_enabled: live ? live.ai_live_enabled === true : false,
    ceiling: live && typeof live.ceiling === "boolean" ? live.ceiling : null,
  };
}

/**
 * What the Stock prices card says: whether Coinbase is connected at all, then the engine's own
 * `equity.prices` when it answered.
 *
 * The engine's own `prices_message` is never read, let alone repeated: each state reads this
 * file's fixed sentence, so nothing the engine carried can reach the page through this field. An
 * engine that did not answer is the same state as one that reported no token: prices missing.
 * A "paused" engine keeps its own state here (the token is fine; Tiingo is limiting Crow), so the
 * card says the prices wait on their own instead of asking for the token again.
 */
function pricesOf(connected, reachable, status) {
  if (!connected) return { state: "coinbase_off", message: MESSAGE_PRICES_COINBASE_OFF };
  const equity = status && isPlainObject(status.equity) ? status.equity : null;
  const reported = equity && typeof equity.prices === "string" ? equity.prices : null;
  if (reachable && reported === "connected") {
    return { state: "connected", message: MESSAGE_PRICES_CONNECTED };
  }
  if (reachable && reported === "rejected") {
    return { state: "rejected", message: MESSAGE_PRICES_REJECTED };
  }
  if (reachable && reported === "paused") {
    return { state: "paused", message: MESSAGE_PRICES_PAUSED };
  }
  return { state: "missing", message: MESSAGE_PRICES_MISSING };
}

/**
 * Whether stock trading is configured at all, which is what decides if the Stock prices card is on
 * the page: the engine's own `equity.enabled`, and false when it did not answer (an engine that is
 * not there enables no stock trading).
 */
function equityEnabledOf(reachable, status) {
  if (!reachable) return false;
  const equity = status && isPlainObject(status.equity) ? status.equity : null;
  return Boolean(equity && equity.enabled === true);
}

/** Each book's fall from its own high-water mark, exactly as the engine reports it (null = none). */
function drawdownOf(status) {
  const reported = status && isPlainObject(status.drawdown) ? status.drawdown : {};
  const out = { dry: null, live: null };
  for (const book of ["dry", "live"]) {
    const entry = isPlainObject(reported[book]) ? reported[book] : null;
    out[book] = entry ? decimalText(entry.pct) : null;
  }
  return out;
}

/** The products the engine trades, for the new-bot form: its own list, never one kept here. */
function productsOf(status) {
  const listed = status && Array.isArray(status.products) ? status.products : [];
  return listed.filter((product) => typeof product === "string" && product !== "");
}

/** One book's resting orders, with no client order id and no book column (the box is the book). */
function openOrdersOf(rows) {
  return (Array.isArray(rows) ? rows : [])
    .filter(isPlainObject)
    .map((row) => ({
      bot: row.bot ?? null,
      product: row.product ?? null,
      side: row.side ?? null,
      size: moneyText(row.size),
      price: moneyText(row.price),
      created_at: row.created_at ?? null,
    }));
}

/** The engine's successful answer body, when it has one. */
function dataOf(result) {
  return result && result.ok && isPlainObject(result.data) ? result.data : null;
}

/** The engine's successful answer list, when it has one. */
function listOf(result) {
  return result && result.ok && Array.isArray(result.data) ? result.data : [];
}

/**
 * The refusals whose copy this file owns: the engine's code and status are kept, and the sentence
 * is always this file's, so none of the engine's own wording reaches the owner. Mapped here, once,
 * so the pause, resume, recenter and mode routes all answer a race the same way.
 */
const ENGINE_REFUSAL_SENTENCES = {
  PAUSE_IN_PROGRESS: MESSAGE_PAUSE_IN_PROGRESS,
  PAUSE_CHANGED: MESSAGE_PAUSE_CHANGED,
};

/** The refusal an engine result earns: its own status, its own code and this file's sentence. */
function engineRefusal(result) {
  const status = result && Number.isFinite(result.status) && result.status >= 400 ? result.status : 502;
  const code = result && typeof result.code === "string" && result.code ? result.code : "engine_unreachable";
  const own = Object.hasOwn(ENGINE_REFUSAL_SENTENCES, code) ? ENGINE_REFUSAL_SENTENCES[code] : null;
  const message =
    own ??
    (result && typeof result.message === "string" && result.message
      ? result.message
      : MESSAGE_ENGINE_UNREACHABLE);
  return { status, code, message };
}

/**
 * The book one bot row trades on. Only a row that says exactly "dry" is Practice: a row with any
 * other mode, no mode at all, or no row at all is Live, so an unknown book is never mistaken for
 * the one that trades no real money.
 */
function bookOf(bot) {
  return bot && bot.mode === "dry" ? "dry" : "live";
}

/** The badge a book reads as. */
function badgeOf(book) {
  return book === "live" ? "LIVE" : "PRACTICE";
}

/**
 * The sentence one bot row earns about itself, or null.
 *
 * A pause the owner asked for needs no attention, so `paused_reason` decides: the engine's own
 * rows carry it (`"owner"`, `"drawdown"`, `"strategy"` or nothing), and only a pause the owner did
 * not ask for gets the note. An owner-paused bot falls through to the rest of the grid logic.
 */
function noteOf(bot) {
  if (!bot) return null;
  if (bot.status === "PAUSED" && bot.paused_reason !== "owner") return NOTE_NEEDS_ATTENTION;
  if (bot.strategy === "grid") return NOTE_GRID;
  return null;
}

/** A fill's moment as a number, for ordering only. */
function timeRank(fill) {
  const raw = fill && (fill.time ?? fill.ts ?? fill.at);
  if (typeof raw === "number" && Number.isFinite(raw)) return raw;
  const parsed = Date.parse(String(raw ?? ""));
  return Number.isFinite(parsed) ? parsed : 0;
}

// ---- the routes --------------------------------------------------------------------------------

/**
 * The Trading panel's routes over one Crow instance.
 *
 * Every seam defaults to the real thing: `db` is the instance's database client, `crowHome` the
 * Crow home this install lives in, `authMiddleware` the dashboard's own auth, `isLocalSession` and
 * `is2faEnabled` the dashboard's own checks, `stepUpGate` the one step-up gate, `loadKey` the
 * keychain's write key, `saveBundleEnv` the bundle-env writer and `notify` the notification
 * writer. `engineClientFactory` builds an engine client; `startLoopsImpl` starts the boot loops;
 * `now` answers epoch milliseconds.
 *
 * The Connect routes and their store come from `createConnectRoutes`, and so do the gates, the
 * audit writer and the engine-client builder: one set of rules, one gate, one lock. That module is
 * a sibling in the bundle, so it is loaded at call time rather than imported, and the pieces this
 * module needs at mount (`connection`, the loops' engine client) are reached through it.
 *
 * Returns `{ router, connection, secretProvider, startLoops(), stopLoops(), loops }`.
 */
export function createPanelRoutes(options = {}) {
  const config = isPlainObject(options) ? options : {};
  const db = config.db;
  const crowHome = typeof config.crowHome === "string" && config.crowHome ? config.crowHome : CROW_HOME();
  const authMiddleware = config.authMiddleware;
  const now = typeof config.now === "function" ? config.now : Date.now;

  if (typeof authMiddleware !== "function") {
    throw new TypeError("createPanelRoutes needs an auth middleware");
  }

  const is2faEnabled = typeof config.is2faEnabled === "function"
    ? config.is2faEnabled
    : async () => {
      try {
        const module = await totpModule();
        return module.is2faEnabled() === true;
      } catch {
        return false;
      }
    };

  /**
   * The local password session on this Crow: read here, not through the Connect routes, so an
   * action that must never be held up (the kill switch) still works when that module will not load.
   */
  const isLocalSession = typeof config.isLocalSession === "function"
    ? config.isLocalSession
    : async (database, req) => {
      try {
        const module = await localSessionModule();
        return module.isLocalPasswordSessionOn(database, req) === true;
      } catch {
        return false;
      }
    };

  const saveBundleEnv = typeof config.saveBundleEnv === "function"
    ? config.saveBundleEnv
    : async (bundleId, envVars) => {
      const module = await bundlesRoutesModule();
      return module.saveBundleEnv(bundleId, envVars, { owner: true });
    };

  const notify = typeof config.notify === "function" ? config.notify : null;
  const startLoopsImpl = typeof config.startLoopsImpl === "function" ? config.startLoopsImpl : null;

  // ---- the Connect routes, loaded at call time and reached through these seams ----------------

  /**
   * The Connect routes: the gates, the audit writer, the connection store and the engine-client
   * builder. Loaded once, before any request is answered (the router below waits for it), and
   * never twice.
   */
  const connectReady = (async () => {
    const module = await connectModule();
    return module.createConnectRoutes({
      db,
      crowHome,
      authMiddleware,
      engineClientFactory,
      isLocalSession,
      is2faEnabled: config.is2faEnabled,
      stepUpGate: config.stepUpGate,
      loadKey: config.loadKey,
      onConnected: (info) => onConnected(info),
      onDisconnected: (info) => onDisconnected(info),
    });
  })();
  connectReady.catch((err) => {
    console.warn("[coinbase] the Connect routes did not load:", err && err.name ? err.name : "error");
  });

  async function connectRoutes() {
    try {
      return await connectReady;
    } catch {
      return null;
    }
  }

  // ---- the engine client ----------------------------------------------------------------------

  /**
   * The real client: the engine's bearer token from this install and the sealed owner secret,
   * asked for per call, so a call always signs with the connection as it stands now.
   */
  async function realClient() {
    const module = await engineClientModule();
    let token = "";
    try {
      token = module.readEngineToken(crowHome);
    } catch {
      token = "";
    }
    return module.createEngineClient(clientOptions(token));
  }

  /** The options every client built here takes: the token, the sealed secret, the engine's address. */
  function clientOptions(token) {
    const built = { token, secretProvider };
    if (typeof config.engineBaseUrl === "string" && config.engineBaseUrl) built.baseUrl = config.engineBaseUrl;
    return built;
  }

  /**
   * The whole real client, with every method the engine has, built from this install's own token
   * and the sealed owner secret.
   *
   * Each method loads the real client on first use, so the Connect routes and the boot loops can be
   * handed one at mount, before a module load has finished, and every call it makes still signs
   * with the connection as it stands at that moment. A method the client does not have, and a call
   * that throws, answer as an engine that did not answer — never as a thrown error and never as a
   * partial client a handler cannot use.
   */
  function fullClient() {
    const client = {};
    for (const name of CLIENT_METHODS) {
      client[name] = async (...args) => {
        let real;
        try {
          real = await realClient();
        } catch {
          return unreachable();
        }
        return callClient(real, name, ...args);
      };
    }
    return client;
  }

  const engineClientFactory = typeof config.engineClientFactory === "function"
    ? config.engineClientFactory
    : () => fullClient();

  /**
   * A bearer-only client, built here without the Connect routes: the kill switch trades no
   * signature, so it must work even when that module never loaded.
   */
  async function bearerClient() {
    try {
      const module = await engineClientModule();
      let token = "";
      try {
        token = module.readEngineToken(crowHome);
      } catch {
        token = "";
      }
      return module.createEngineClient(clientOptions(token));
    } catch {
      return null;
    }
  }

  /** The key the engine client signs with: the Connect route's own provider (sealed secret). */
  async function secretProvider(kind) {
    const connect = await connectRoutes();
    if (connect && typeof connect.secretProvider === "function") return connect.secretProvider(kind);
    return null;
  }

  /** One engine client for one panel route, built the way the Connect routes build theirs. */
  async function routeClient() {
    try {
      const connect = await connectRoutes();
      if (connect && typeof connect.buildClient === "function") {
        const built = await connect.buildClient();
        if (built) return built;
      }
    } catch {
      // A Connect module that will not load leaves the routes' own client to answer.
    }
    try {
      const built = engineClientFactory({ secretProvider });
      return built && typeof built.then === "function" ? await built : built;
    } catch {
      return null;
    }
  }

  // ---- the gates and the audit writer (the Connect routes own both) ---------------------------

  /** The gate every route passes: false means the refusal is already answered. */
  async function gates(req, res, action, gateOptions) {
    const connect = await connectRoutes();
    if (!connect || typeof connect.gates !== "function") {
      res.status(503).json({ ok: false, code: "unavailable", message: MESSAGE_NOT_READY });
      return false;
    }
    return connect.gates(req, res, action, gateOptions);
  }

  /**
   * The local password session alone, read in this file rather than through the Connect routes:
   * the gate of everything that stops trading. false means the refusal is already answered.
   */
  async function localSessionGate(req, res, action) {
    let local = false;
    try {
      local = (await isLocalSession(db, req)) === true;
    } catch {
      local = false;
    }
    if (local) return true;
    await refuse(res, action, 403, "local_login_required", MESSAGE_LOCAL_LOGIN);
    return false;
  }

  async function boundProjectId() {
    const connect = await connectRoutes();
    return connect && typeof connect.boundProjectId === "function" ? connect.boundProjectId() : boundProjectFromRow();
  }

  async function boundProjectFromRow() {
    const row = await readConnectionRow();
    return row ? Number(row.project_id) : null;
  }

  /** One audit row, filed against the project this install is bound to. */
  async function audit(action, target, payload) {
    let projectId = null;
    try {
      projectId = await boundProjectId();
    } catch {
      projectId = null;
    }
    try {
      const connect = await connectRoutes();
      if (connect && typeof connect.writeAudit === "function") {
        await connect.writeAudit(projectId, action, target ?? null, payload ?? { ok: true });
        return;
      }
      const project = Number(projectId);
      if (!Number.isInteger(project) || project <= 0) return;
      const { appendAudit } = await aclModule();
      await appendAudit(db, {
        project_id: project,
        actor_type: ACTOR_TYPE,
        action,
        target: target ?? null,
        payload: payload ?? { ok: true },
      });
    } catch {
      // An audit writer that fails never changes the answer.
    }
  }

  /**
   * The connection store the loops read, in the shape `startLoops` expects. It is a thin front on
   * the Connect routes' own store (one store, one lock), so a loop tick and a Connect share what
   * they know about the connection.
   */
  const connection = {
    async get() {
      const connect = await connectRoutes();
      if (connect && connect.connection && typeof connect.connection.get === "function") {
        return connect.connection.get();
      }
      return null;
    },
    async markNeedsReconnect() {
      const connect = await connectRoutes();
      if (connect && connect.connection && typeof connect.connection.markNeedsReconnect === "function") {
        return connect.connection.markNeedsReconnect();
      }
      return false;
    },
    async clearDisconnecting() {
      const connect = await connectRoutes();
      if (connect && connect.connection && typeof connect.connection.clearDisconnecting === "function") {
        return connect.connection.clearDisconnecting();
      }
      return false;
    },
    async repush() {
      const connect = await connectRoutes();
      if (connect && connect.connection && typeof connect.connection.repush === "function") {
        return connect.connection.repush();
      }
      return { ok: false, status: 0, code: "NOT_CONNECTED", message: "" };
    },
    async repushUnlocked() {
      const connect = await connectRoutes();
      if (connect && connect.connection && typeof connect.connection.repushUnlocked === "function") {
        return connect.connection.repushUnlocked();
      }
      return { ok: false, status: 0, code: "NOT_CONNECTED", message: "" };
    },
  };

  // ---- the database read this module owns -----------------------------------------------------

  /** The standing connection's row, as the Connect routes keep it: read only, never written here. */
  async function readConnectionRow() {
    try {
      const result = await db.execute({
        sql: `SELECT uuid, project_id, config FROM service_connections
              WHERE service_id = ? AND status = 'active' AND owner_contact_id IS NULL
              ORDER BY id DESC LIMIT 1`,
        args: [SERVICE_ID],
      });
      const rows = result && Array.isArray(result.rows) ? result.rows : [];
      return rows[0] || null;
    } catch {
      return null;
    }
  }

  // ---- the two listeners the Connect routes call ---------------------------------------------

  /**
   * Write (or clear) the project id this install's bundle environment carries, and log a writer
   * that answered anything but 200 by its status alone: the body is never read, never logged, and
   * a writer that fails changes nothing about the connection or the Disconnect answer.
   */
  async function writeProjectId(value) {
    let answer;
    try {
      answer = await saveBundleEnv(SERVICE_ID, { CROW_COINBASE_PROJECT_ID: value });
    } catch (err) {
      console.warn("[coinbase] the project id could not be saved:", err && err.name ? err.name : "error");
      return;
    }
    if (answer && answer.status === 200) return;
    const status = answer && Number.isFinite(answer.status) ? answer.status : "no status";
    console.warn(`[coinbase] the project id was not saved: status ${status}`);
  }

  /**
   * A connection stands: the project id is the one thing the bundle's own environment carries, so
   * a worker that needs it finds it.
   */
  async function onConnected(info) {
    const projectId = info && info.projectId !== undefined ? info.projectId : null;
    if (projectId === null || projectId === undefined || projectId === "") return;
    await writeProjectId(String(projectId));
  }

  /**
   * A connection went: the project id goes with it. The live switches are the engine's own, so
   * there is no copy of them here to clear.
   */
  async function onDisconnected() {
    await writeProjectId("");
  }

  // ---- answers --------------------------------------------------------------------------------

  /**
   * One refusal: the machine code and a plain sentence, and — on a POST — one audit row that is
   * filed even though nothing happened.
   */
  async function refuse(res, action, status, code, message, extra = {}) {
    const payload = { ok: false, code };
    if (Array.isArray(extra.names) && extra.names.length > 0) payload.names = extra.names;
    if (typeof extra.book === "string") payload.book = extra.book;
    if (typeof extra.preview_id === "string") payload.preview_id = extra.preview_id;
    await audit(action, extra.target ?? null, payload);
    const body = { ok: false, code, message };
    if (typeof extra.book === "string") body.book = extra.book;
    return res.status(status).json(body);
  }

  /** One refusal the engine itself answered: its status, its code, its own sentence. */
  async function refuseEngine(res, action, result, extra = {}) {
    const { status, code, message } = engineRefusal(result);
    return refuse(res, action, status, code, message, extra);
  }

  /** Every route: the work, and never a thrown error as the answer. */
  const wrap = (action, handler) => async (req, res) => {
    try {
      await connectReady;
    } catch {
      // The handler answers "not ready" through its own gate.
    }
    try {
      await handler(req, res);
    } catch (err) {
      if (res.headersSent) return;
      console.warn(`[coinbase] ${action}:`, err && err.name ? err.name : "error");
      if (req.method !== "GET") await audit(action, null, { ok: false, code: "failed" });
      try {
        res.status(500).json({ ok: false, code: "failed", message: MESSAGE_GENERIC });
      } catch {
        // The answer is already gone.
      }
    }
  };

  // ---- the panel state -----------------------------------------------------------------------
  /** What the page shows about the connection, read from the row the Connect routes keep. */
  async function connectionInfo() {
    const row = await readConnectionRow();
    if (!row) {
      return {
        connected: false,
        project_id: null,
        needs_reconnect: false,
        pending: false,
        disconnect_unfinished: false,
        key_last4: null,
        portfolio_last4: null,
        message: null,
      };
    }
    const stored = parseConfig(row.config);
    const needsReconnect = stored.needs_reconnect === true;
    const pending = stored.pending_pin === true;
    const unfinished = stored.disconnecting === true;
    const keyLast4 = last4(stored.key_last4);
    const portfolioLast4 = last4(stored.portfolio_last4);
    let message;
    if (unfinished) message = MESSAGE_DISCONNECT_UNFINISHED;
    else if (needsReconnect) message = MESSAGE_NEEDS_RECONNECT;
    else message = MESSAGE_CONNECTED_PREFIX + (portfolioLast4 === null ? "" : portfolioLast4);
    return {
      connected: true,
      project_id: Number(row.project_id),
      needs_reconnect: needsReconnect,
      pending,
      disconnect_unfinished: unfinished,
      key_last4: keyLast4,
      portfolio_last4: portfolioLast4,
      message,
    };
  }

  /**
   * The whole page in one read.
   *
   * Nothing here is stored: the switches, each book's drawdown and the products are the engine's
   * own last answer, and the open orders are its own list per book. The Stock prices card's state
   * is the engine's equity block reduced to one of five states and this file's own sentence, and
   * `equity_enabled` says whether stock trading is configured at all. An engine that is down is a
   * state the page shows, never a failed page, and this read writes nothing to the database.
   */
  async function handlePanel(req, res) {
    if (!(await gates(req, res, ACTIVITY_PANEL, { needsCode: false, needs2fa: false }))) return;

    const client = await routeClient();
    /** One read that never throws: a method the client does not have reads as "no answer". */
    const readOne = (name, ...args) => callClient(client, name, ...args);

    const [healthR, statusR, botsR, pnlR, capsR, pendingR, allR, dryOrdersR, liveOrdersR, twoFactor] =
      await Promise.all([
        readOne("health"),
        readOne("status"),
        readOne("bots"),
        readOne("pnl"),
        readOne("caps"),
        readOne("aiPreviews", { state: "pending" }),
        readOne("aiPreviews"),
        readOne("orders", { book: "dry" }),
        readOne("orders", { book: "live" }),
        Promise.resolve()
          .then(() => is2faEnabled())
          .then((value) => value === true)
          .catch(() => false),
      ]);

    const health = dataOf(healthR) || {};
    const status = dataOf(statusR) || {};
    const reachable = Boolean(healthR && healthR.ok);
    const bots = listOf(botsR).filter(isPlainObject);
    const pnl = dataOf(pnlR);
    const pnlBots = pnl && isPlainObject(pnl.bots) ? pnl.bots : {};
    const pinState = reachable ? health.pinned === true : null;

    // The bots, with what each one's book is worth and what happened behind simply holding.
    const shownBots = bots.map((bot) => {
      const id = String(bot.id ?? "");
      const entry = isPlainObject(pnlBots[id]) ? pnlBots[id] : {};
      const row = {
        id,
        product: bot.product ?? null,
        strategy: bot.strategy ?? null,
        status: bot.status ?? null,
        mode: bot.mode ?? null,
        badge: badgeOf(bookOf(bot)),
        value: moneyText(entry.equity),
        vs_hold: moneyText(entry.vs_hold),
        realized: moneyText(entry.realized),
        fees: moneyText(entry.fees),
      };
      const note = noteOf(bot);
      if (note !== null) row.note = note;
      return row;
    });

    // Newest fills across every bot, at most twenty, and no order ids.
    const fillLists = await Promise.all(
      bots.map((bot) => {
        const id = String(bot.id ?? "");
        return id ? callClient(client, "botFills", id) : Promise.resolve(null);
      }),
    );
    let fills = [];
    bots.forEach((bot, index) => {
      const id = String(bot.id ?? "");
      for (const fill of listOf(fillLists[index])) {
        if (!isPlainObject(fill)) continue;
        fills.push({
          bot_id: id,
          product: fill.product ?? bot.product ?? null,
          side: fill.side ?? null,
          price: moneyText(fill.price),
          size: moneyText(fill.size),
          time: fill.time ?? fill.ts ?? null,
        });
      }
    });
    fills.sort((a, b) => timeRank(b) - timeRank(a));
    fills = fills.slice(0, 20);

    // The proposals waiting for the owner, in the words approve.js uses for the card.
    const nowSeconds = Math.floor(Number(now()) / 1000);
    const { describePreview } = await approveModule();
    const describe = (row) => {
      const shown = describePreview(row, { now: nowSeconds });
      return {
        summary: String(shown && shown.summary ? shown.summary : ""),
        lines: Array.isArray(shown && shown.lines) ? shown.lines.map(String) : [],
        expired: Boolean(shown && shown.expired),
        seconds_left: Number.isFinite(shown && shown.seconds_left) ? shown.seconds_left : 0,
      };
    };

    const previews = listOf(pendingR)
      .filter(isPlainObject)
      .map((row) => {
        const described = describe(row);
        // A preview names its book itself ("dry" or "live"); it is not a bot row.
        const book = String(row.book ?? "").toLowerCase() === "live" ? "live" : "dry";
        return {
          preview_id: String(row.preview_id ?? ""),
          hash: row.hash ?? null,
          state: row.state ?? "pending",
          book,
          badge: badgeOf(book),
          summary: described.summary,
          lines: described.lines,
          seconds_left: described.seconds_left,
          can_approve: !described.expired,
        };
      });

    const settled = listOf(allR)
      .filter((row) => isPlainObject(row) && row.state !== "pending")
      .sort((a, b) => Number(b.created_at ?? 0) - Number(a.created_at ?? 0));
    const recentPreviews = settled.slice(0, 5).map((row) => ({
      preview_id: String(row.preview_id ?? ""),
      state: String(row.state ?? ""),
      summary: describe(row).summary,
    }));

    // The limits, in the engine's own shape: money as text, counts as whole numbers.
    const limitsData = dataOf(capsR);
    const limits = limitsData
      ? {
        caps: limitsData.caps ?? null,
        ceilings: limitsData.ceilings ?? null,
        used_today: limitsData.used_today ?? null,
      }
      : { caps: null, ceilings: null, used_today: null };

    const drawdown = drawdownOf(status);

    let note = null;
    if (!reachable) note = MESSAGE_ENGINE_DOWN_NOTE;
    else if (health.credentials === "not_ready") note = MESSAGE_KILL_NOT_READY;

    const connection = await connectionInfo();

    return res.json({
      ok: true,
      connection,
      two_factor: twoFactor,
      engine: {
        reachable,
        credentials: reachable && typeof health.credentials === "string" ? health.credentials : null,
        pinned: pinState,
        halted: status.halted === true,
        halted_books: isPlainObject(status.halted_books) ? status.halted_books : null,
        halt_reasons: isPlainObject(status.halt_reasons) ? status.halt_reasons : null,
        note,
      },
      bots: shownBots,
      fills,
      previews,
      recent_previews: recentPreviews,
      alerts: (Array.isArray(status.recent_alerts) ? status.recent_alerts : [])
        .filter(isPlainObject)
        .map((alert) => ({ ts: alert.ts ?? null, message: String(alert.message ?? "") })),
      limits,
      products: productsOf(status),
      prices: pricesOf(connection.connected === true, reachable, status),
      equity_enabled: equityEnabledOf(reachable, status),
      switches: switchesOf(status),
      drawdown,
      open_orders: {
        dry: openOrdersOf(listOf(dryOrdersR)),
        live: openOrdersOf(listOf(liveOrdersR)),
      },
    });
  }

  // ---- projects ------------------------------------------------------------------------------

  async function handleProjects(req, res) {
    if (!(await gates(req, res, ACTIVITY_PROJECTS, { needsCode: false, needs2fa: false }))) return;
    const result = await db.execute({
      sql: "SELECT id, name FROM project_spaces WHERE archived_at IS NULL ORDER BY name, id",
      args: [],
    });
    const rows = result && Array.isArray(result.rows) ? result.rows : [];
    return res.json({
      ok: true,
      projects: rows.map((row) => ({ id: Number(row.id), name: String(row.name ?? "") })),
    });
  }

  // ---- bots ----------------------------------------------------------------------------------

  async function handleCreateBot(req, res) {
    if (!(await gates(req, res, ACTIVITY_BOTS_CREATE, { needsCode: false, needs2fa: false }))) return;
    const body = isPlainObject(req.body) ? req.body : {};
    const product = typeof body.product === "string" && body.product.trim() ? body.product.trim() : "";
    if (!product) return refuse(res, ACTIVITY_BOTS_CREATE, 400, "invalid", MESSAGE_NO_PRODUCT);

    const strategy = body.strategy === "grid" ? "grid" : "rebalance";
    // The panel always makes the id itself: an id a browser sent is never used.
    const id = newBotId();
    const capitalQuote = decimalText(body.capital_quote) ?? "0";

    let params;
    if (strategy === "grid") {
      const given = isPlainObject(body.params) ? body.params : {};
      const grid = {
        center: decimalText(given.center),
        step_pct: decimalText(given.step_pct),
        levels_below: wholeNumber(given.levels_below),
        levels_above: wholeNumber(given.levels_above),
        quote_per_buy: decimalText(given.quote_per_buy),
        rebuy_sizing: given.rebuy_sizing === "fixed" ? "fixed" : "proceeds",
      };
      if (
        grid.center === null ||
        grid.step_pct === null ||
        grid.levels_below === null ||
        grid.levels_above === null ||
        grid.quote_per_buy === null
      ) {
        return refuse(res, ACTIVITY_BOTS_CREATE, 400, "invalid", MESSAGE_GRID_FIELDS);
      }
      params = grid;
    } else {
      const given = isPlainObject(body.params) ? decimalText(body.params.target_base_pct) : null;
      params = { target_base_pct: Number(given === null ? 50 : given) };
    }

    const client = await routeClient();
    // Always Practice: the engine's own default, and the panel never names a book here.
    const result = await callClient(client, "createBot", {
      id,
      product,
      strategy,
      params,
      capital_quote: capitalQuote,
      capital_base: "0",
    });
    if (!result || !result.ok) {
      return refuseEngine(res, ACTIVITY_BOTS_CREATE, result, { names: [strategy] });
    }
    await audit(ACTIVITY_BOTS_CREATE, id, { ok: true, names: [strategy] });
    return res.json({ ok: true, message: MESSAGE_BOT_CREATED, bot: dataOf(result) || null });
  }

  async function handleBotAction(req, res, action) {
    const activity = action === "pause" ? ACTIVITY_BOTS_PAUSE : ACTIVITY_BOTS_STOP;
    if (!(await gates(req, res, activity, { needsCode: false, needs2fa: false }))) return;
    const id = String(req.params.id || "");
    const client = await routeClient();
    const result = await callClient(client, action === "pause" ? "botPause" : "botStop", id);
    if (!result || !result.ok) {
      // A pause the engine could not finish kept the bot paused and left orders waiting: the
      // page gets this file's own sentence, never the engine's detail, and Pause can be pressed
      // again. Every other refusal is the engine's own answer, unchanged.
      const refusal = engineRefusal(result);
      if (action === "pause" && refusal.code === "PAUSE_INCOMPLETE" && refusal.status >= 500) {
        return refuse(res, activity, refusal.status, "PAUSE_INCOMPLETE", MESSAGE_BOT_PAUSE_INCOMPLETE);
      }
      // A pause asked for again within the engine's debounce window is answered in this
      // file's own words too: the engine's detail says nothing the owner needs, and Pause
      // works again in a few seconds.
      if (action === "pause" && refusal.code === "PAUSE_TOO_SOON" && refusal.status === 429) {
        return refuse(res, activity, refusal.status, "PAUSE_TOO_SOON", MESSAGE_BOT_PAUSE_TOO_SOON);
      }
      return refuseEngine(res, activity, result);
    }
    await audit(activity, id, { ok: true });
    return res.json({
      ok: true,
      message: action === "pause" ? MESSAGE_BOT_PAUSED : MESSAGE_BOT_STOPPED,
      bot: dataOf(result) || null,
    });
  }

  async function handleBotMode(req, res) {
    const body = isPlainObject(req.body) ? req.body : {};
    const mode = body.mode === "live" ? "live" : body.mode === "dry" ? "dry" : null;

    // Only a move onto the live book is privileged: a switch back to practice takes real money out
    // of the bot's hands, so the local password session alone is its gate. A mode that is neither
    // is answered after that same check, so a peer session never learns anything else.
    const gateOptions = mode === "live" ? undefined : { needsCode: false, needs2fa: false };
    if (!(await gates(req, res, ACTIVITY_BOTS_MODE, gateOptions))) return;

    const id = String(req.params.id || "");
    if (mode === null) return refuse(res, ACTIVITY_BOTS_MODE, 400, "invalid", MESSAGE_BAD_MODE);

    // The engine takes a practice book's capital from the live book's own value: a switch to
    // practice carries no capital at all, and its own route refuses one.
    let payload = { mode };
    if (mode === "live") {
      if (body.acknowledge_live !== true) {
        return refuse(res, ACTIVITY_BOTS_MODE, 400, "confirm_required", MESSAGE_CONFIRM_LIVE);
      }
      payload.acknowledge_live = true;
      // A capital value is a plain non-negative decimal or nothing at all: anything else is
      // refused here, in this file's own words, before any engine call.
      const capitalQuote = capitalText(body.capital_quote);
      if (capitalQuote === null) {
        return refuse(res, ACTIVITY_BOTS_MODE, 400, "invalid", MESSAGE_BAD_NUMBER);
      }
      if (capitalQuote !== undefined) payload.capital_quote = capitalQuote;
      const capitalBase = capitalText(body.capital_base);
      if (capitalBase === null) {
        // A starting coin amount is a quantity of the coin, never a debt.
        return refuse(res, ACTIVITY_BOTS_MODE, 400, "invalid", MESSAGE_BAD_CAPITAL_BASE);
      }
      if (capitalBase !== undefined) payload.capital_base = capitalBase;
    }

    const client = await routeClient();
    const result = await callClient(client, "setMode", id, payload);
    if (!result || !result.ok) return refuseEngine(res, ACTIVITY_BOTS_MODE, result, { names: [mode] });
    await audit(ACTIVITY_BOTS_MODE, id, { ok: true, names: [mode] });
    return res.json({
      ok: true,
      message: mode === "live" ? MESSAGE_BOT_LIVE : MESSAGE_BOT_PRACTICE,
      bot: dataOf(result) || null,
    });
  }

  /**
   * Resume and recenter: a bot on the Practice book needs the local session only; a bot on the
   * Live book is privileged, because those calls are signed with the owner secret. The local
   * sign-in check comes first, so a session that may not act never reaches the engine at all;
   * two-factor sign-in and the fresh code are asked for once the engine has said which book the
   * bot is on, and only for a Live bot.
   *
   * The gate in this file is the real control for resume/recenter of Live bots: the engine only
   * needs the owner's MAC, which this file signs after the local-session and fresh-code checks.
   */
  async function handleBotLiveAction(req, res, action) {
    const activity = action === "resume" ? ACTIVITY_BOTS_RESUME : ACTIVITY_BOTS_RECENTER;
    if (!(await gates(req, res, activity, { needsCode: false, needs2fa: false }))) return;

    const id = String(req.params.id || "");
    const body = isPlainObject(req.body) ? req.body : {};

    let payload;
    if (action === "resume") {
      if (body.acknowledge_rebase !== true) {
        return refuse(res, activity, 400, "confirm_required", MESSAGE_CONFIRM_RESUME);
      }
      payload = { acknowledge_rebase: true };
    } else {
      const center = decimalText(body.center);
      if (center === null) return refuse(res, activity, 400, "invalid", MESSAGE_BAD_NUMBER);
      payload = { center };
    }

    const client = await routeClient();

    // The bot's own row says which book it trades on; the panel never guesses one.
    const bots = listOf(await callClient(client, "bots"));
    const bot = bots.filter(isPlainObject).find((row) => String(row.id ?? "") === id) || null;
    if (!bot) return refuse(res, activity, 404, "not_found", MESSAGE_NO_BOT);

    const book = bookOf(bot);
    if (book === "live" && !(await gates(req, res, activity))) return;

    const result = await callClient(client, action === "resume" ? "botResume" : "botRecenter", id, payload);
    if (!result || !result.ok) return refuseEngine(res, activity, result, { names: [book] });
    await audit(activity, id, { ok: true, names: [book] });
    return res.json({
      ok: true,
      message: action === "resume" ? MESSAGE_BOT_RESUMED : MESSAGE_BOT_RECENTERED,
      bot: dataOf(result) || null,
    });
  }

  // ---- the switches ---------------------------------------------------------------------------

  /**
   * The two live switches, read and written as the engine's own state.
   *
   * The engine's `/status` is what a switch is, so this file keeps no copy of them. It is read for
   * one thing only: whether an ON this body asks for still has to happen. An OFF is always sent —
   * a switch the body puts to false is no longer a change to compare, it is the owner stopping
   * something, and nothing that stops trading is ever answered with "nothing to do". A status read
   * that fails decides nothing: the requested values are sent and the engine's own answer decides,
   * with the full gate in front of any ON because nobody could check it is already on.
   *
   * An ON needs a pin: with nothing pinned there is no key to switch them with and no book they
   * could trade, so an ON is refused in plain words whether or not this install still holds a
   * connection row. The engine client's own "nothing to sign with" answer is the same state and
   * earns the same plain refusal, never a 502 and never the client's own wording.
   */
  async function handleSwitches(req, res) {
    const body = isPlainObject(req.body) ? req.body : {};
    const wanted = {};
    for (const name of SWITCH_ORDER) {
      if (typeof body[name] === "boolean") wanted[name] = body[name];
    }
    const names = Object.keys(wanted);
    if (names.length === 0) return refuse(res, ACTIVITY_SWITCHES, 400, "invalid", MESSAGE_NO_SWITCH);

    // A body that only asks for ON is the privileged case whatever the engine holds, so two-factor
    // sign-in is checked before the engine is asked anything: a refusal never costs a request.
    const onlyTurnsOn = names.every((name) => wanted[name] === true);
    if (onlyTurnsOn && !(await gates(req, res, ACTIVITY_SWITCHES, { needsCode: false }))) return undefined;

    const client = await routeClient();
    // Read only to decide whether an ON is still a change; a failed read is "unknown", never "off".
    const status = dataOf(await callClient(client, "status"));
    const current = status === null ? null : switchesOf(status);

    // An OFF is always sent. An ON is sent when the engine does not have it on, and always when
    // the engine could not say what it has.
    const toSend = {};
    const sendNames = [];
    for (const name of names) {
      if (wanted[name] === true && current !== null && current[name] === true) continue;
      toSend[name] = wanted[name];
      sendNames.push(name);
    }

    // Only ONs that were already on: there is nothing to send, and nothing to ask a code for.
    if (sendNames.length === 0) {
      if (!(await gates(req, res, ACTIVITY_SWITCHES, { needsCode: false, needs2fa: false }))) {
        return undefined;
      }
      await audit(ACTIVITY_SWITCHES, null, { ok: true, names });
      return res.json({ ok: true, message: MESSAGE_SWITCH_UNCHANGED, switches: current });
    }

    // Turning one ON is privileged; a body of OFFs only is the local session only.
    const turningOn = sendNames.some((name) => toSend[name] === true);
    if (!(await gates(req, res, ACTIVITY_SWITCHES, turningOn ? {} : { needsCode: false, needs2fa: false }))) {
      return undefined;
    }

    // The switches belong to the connection the engine's pin made: with nothing pinned there is no
    // key to switch them with and no book they could trade. An ON is refused in plain words whether
    // or not a connection row stands; an OFF still goes to the engine, and its own answer is what
    // the page reports.
    if (turningOn) {
      const health = dataOf(await callClient(client, "health")) || {};
      if (health.pinned === false) {
        return refuse(
          res,
          ACTIVITY_SWITCHES,
          409,
          "not_connected",
          MESSAGE_SWITCH_NOT_CONNECTED,
          { names },
        );
      }
    }

    const result = await callClient(client, "setSwitches", toSend);
    if (!result || !result.ok) {
      // No sealed owner secret to sign with is the same "nothing is connected" state, so it is
      // answered in the same plain switch words rather than as an unreachable engine.
      if (result && result.status === 0 && result.code === "NOT_CONNECTED") {
        return refuse(
          res,
          ACTIVITY_SWITCHES,
          409,
          "not_connected",
          MESSAGE_SWITCH_NOT_CONNECTED,
          { names },
        );
      }
      return refuseEngine(res, ACTIVITY_SWITCHES, result, { names });
    }

    const data = dataOf(result) || {};
    const shown = {
      live_enabled: data.live_enabled === true,
      ai_live_enabled: data.ai_live_enabled === true,
      ceiling: typeof data.ceiling === "boolean"
        ? data.ceiling
        : current && typeof current.ceiling === "boolean"
          ? current.ceiling
          : null,
    };
    await audit(ACTIVITY_SWITCHES, null, { ok: true, names });
    return res.json({
      ok: true,
      message: sendNames.map((name) => SWITCH_MESSAGES[name][String(toSend[name])]).join(" "),
      switches: shown,
    });
  }

  // ---- the limits -----------------------------------------------------------------------------

  /** Each book's fall from its own high-water mark, from the engine's own status answer. */
  async function engineDrawdown(client) {
    const status = dataOf(await callClient(client, "status")) || {};
    return drawdownOf(status);
  }

  async function handleCaps(req, res) {
    if (!(await gates(req, res, ACTIVITY_CAPS))) return;
    const body = isPlainObject(req.body) ? req.body : {};
    const wanted = isPlainObject(body.caps) ? body.caps : null;
    if (!wanted || Object.keys(wanted).length === 0) {
      return refuse(res, ACTIVITY_CAPS, 400, "invalid", MESSAGE_NO_LIMITS);
    }
    const names = Object.keys(wanted);

    const client = await routeClient();

    const current = await callClient(client, "caps");
    const currentData = dataOf(current);
    if (!currentData) return refuseEngine(res, ACTIVITY_CAPS, current, { names });
    const ceilings = isPlainObject(currentData.ceilings) ? currentData.ceilings : {};

    // 1. Nothing may go above the ceiling this install was started with.
    for (const [name, value] of Object.entries(wanted)) {
      if (!Object.hasOwn(ceilings, name)) {
        return refuse(res, ACTIVITY_CAPS, 422, "invalid", MESSAGE_UNKNOWN_LIMIT, { names });
      }
      const verdict = compareDecimals(value, ceilings[name]);
      if (verdict === null) return refuse(res, ACTIVITY_CAPS, 422, "invalid", MESSAGE_BAD_NUMBER, { names });
      if (verdict > 0) {
        const label = CAP_LABELS[name] || "This limit";
        return refuse(
          res,
          ACTIVITY_CAPS,
          422,
          "above_ceiling",
          `${label}: that is above the limit of ${String(ceilings[name])} set in Crow's add-on settings.`,
          { names },
        );
      }
    }

    // 2. A drawdown limit that today's fall already reaches stops a book the moment it is saved.
    if (Object.hasOwn(wanted, CAP_DRAWDOWN) && body.confirm_halt !== true) {
      const wantedDrop = decimalText(wanted[CAP_DRAWDOWN]);
      if (wantedDrop !== null) {
        const nowDrops = await engineDrawdown(client);
        for (const book of ["live", "dry"]) {
          const drop = nowDrops[book];
          // A null drawdown pct skips the warning on purpose: the engine's halt cannot fire
          // without a mark, so saving a cap cannot halt that book.
          if (drop === null) continue;
          const verdict = compareDecimals(wantedDrop, drop);
          if (verdict === null || verdict > 0) continue;
          return refuse(
            res,
            ACTIVITY_CAPS,
            409,
            "would_halt",
            book === "live" ? MESSAGE_WOULD_HALT_LIVE : MESSAGE_WOULD_HALT_PRACTICE,
            { names, book },
          );
        }
      }
    }

    const result = await callClient(client, "setCaps", wanted);
    if (!result || !result.ok) return refuseEngine(res, ACTIVITY_CAPS, result, { names });
    const data = dataOf(result) || {};
    await audit(ACTIVITY_CAPS, null, { ok: true, names });
    return res.json({
      ok: true,
      message: MESSAGE_CAPS_SAVED,
      caps: data.caps ?? null,
      ceilings: data.ceilings ?? ceilings,
    });
  }

  // ---- the kill switch and Resume trading ------------------------------------------------------

  /**
   * The kill switch: stopping is never behind a code, never behind two-factor sign-in, and never
   * behind the Connect flow.
   *
   * The local password session on this Crow is the whole gate, read here rather than through the
   * Connect routes, and the client is bearer-only: a kill trades no signature, so a Connect module
   * that will not load cannot stop it. The answer is always JSON — a kill that cannot be carried
   * out says so in plain words, never as a 500 stack. A token the engine refused (401 or 403) has
   * its own sentence: the engine was reached but would take no call from Crow.
   */
  async function handleKill(req, res) {
    /** One refusal, filed, and never a thrown error. */
    const killRefusal = async (code, message) => {
      await audit(ACTIVITY_KILL, null, { ok: false, code });
      if (res.headersSent) return undefined;
      return res.status(502).json({ ok: false, code, message });
    };

    try {
      if (!(await localSessionGate(req, res, ACTIVITY_KILL))) return undefined;
      const body = isPlainObject(req.body) ? req.body : {};
      if (body.confirm !== true) {
        return refuse(res, ACTIVITY_KILL, 400, "confirm_required", MESSAGE_KILL_CONFIRM);
      }

      let client = await routeClient();
      if (!client || typeof client.kill !== "function") client = await bearerClient();
      if (!client || typeof client.kill !== "function") {
        return killRefusal("engine_unreachable", MESSAGE_KILL_ENGINE_DOWN);
      }

      const result = await callClient(client, "kill");
      if (!result || result.ok !== true) {
        // Only a failure whose own body said `halted: true` means trading stopped while orders may
        // still be resting on Coinbase. Every other failure — no answer, a 500 without that flag,
        // a thrown call — left everything as it was, and says so. An engine that answered 401 or
        // 403 refused Crow's own token: nobody was reached, so its own sentence says that.
        if (result && result.halted === true) return killRefusal("kill_partial", MESSAGE_KILL_PARTIAL);
        const refusedToken = Boolean(result) && (result.status === 401 || result.status === 403);
        return killRefusal(
          "engine_unreachable",
          refusedToken ? MESSAGE_KILL_ENGINE_REFUSED : MESSAGE_KILL_ENGINE_DOWN,
        );
      }

      // The engine's own health says whether it can reach Coinbase to cancel what is resting there.
      const health = dataOf(await callClient(client, "health"));
      const notReady = Boolean(health) && health.credentials === "not_ready";
      await audit(ACTIVITY_KILL, null, { ok: true });
      return res.json({
        ok: true,
        message: notReady ? `${MESSAGE_KILL_SUCCESS} ${MESSAGE_KILL_NOT_READY}` : MESSAGE_KILL_SUCCESS,
      });
    } catch {
      return killRefusal("engine_unreachable", MESSAGE_KILL_ENGINE_DOWN);
    }
  }

  async function handleHaltClear(req, res) {
    if (!(await gates(req, res, ACTIVITY_HALT_CLEAR))) return;
    const client = await routeClient();
    const result = await callClient(client, "clearHalt", { acknowledge_rebase: true });
    if (!result || !result.ok) return refuseEngine(res, ACTIVITY_HALT_CLEAR, result);
    await audit(ACTIVITY_HALT_CLEAR, null, { ok: true });
    return res.json({ ok: true, message: MESSAGE_HALT_CLEARED });
  }

  // ---- the AI proposals -----------------------------------------------------------------------

  async function handleApprove(req, res) {
    if (!(await gates(req, res, ACTIVITY_PREVIEW_APPROVE))) return;
    const previewId = String(req.params.id || "");
    const body = isPlainObject(req.body) ? req.body : {};
    const hash = typeof body.hash === "string" ? body.hash : "";

    const client = await routeClient();
    if (!client) {
      return refuse(res, ACTIVITY_PREVIEW_APPROVE, 502, "engine_unreachable", MESSAGE_ENGINE_UNREACHABLE, {
        target: previewId,
        preview_id: previewId,
      });
    }

    // approval is one hash, checked against the listing, and never a price of Crow's own.
    const { approvePreview } = await approveModule();
    const answer = await approvePreview({ client, previewId, hash, now: Math.floor(Number(now()) / 1000) });
    if (answer && answer.ok) {
      await audit(ACTIVITY_PREVIEW_APPROVE, previewId, { ok: true, preview_id: previewId });
      return res.json({ ok: true, message: answer.message, preview: answer.preview ?? null });
    }
    return refuse(
      res,
      ACTIVITY_PREVIEW_APPROVE,
      Number.isInteger(answer && answer.status) ? answer.status : 502,
      answer && typeof answer.code === "string" && answer.code ? answer.code : "failed",
      answer && typeof answer.message === "string" && answer.message ? answer.message : MESSAGE_GENERIC,
      { target: previewId, preview_id: previewId },
    );
  }

  async function handleReject(req, res) {
    // "Not now" is a local session, nothing more.
    if (!(await gates(req, res, ACTIVITY_PREVIEW_REJECT, { needsCode: false, needs2fa: false }))) return;
    const previewId = String(req.params.id || "");

    const client = await routeClient();
    if (!client) {
      return refuse(res, ACTIVITY_PREVIEW_REJECT, 502, "engine_unreachable", MESSAGE_ENGINE_UNREACHABLE, {
        target: previewId,
        preview_id: previewId,
      });
    }

    const { rejectPreview } = await approveModule();
    const answer = await rejectPreview({ client, previewId });
    if (answer && answer.ok) {
      await audit(ACTIVITY_PREVIEW_REJECT, previewId, { ok: true, preview_id: previewId });
      return res.json({ ok: true, message: answer.message });
    }
    return refuse(
      res,
      ACTIVITY_PREVIEW_REJECT,
      Number.isInteger(answer && answer.status) ? answer.status : 502,
      answer && typeof answer.code === "string" && answer.code ? answer.code : "failed",
      answer && typeof answer.message === "string" && answer.message ? answer.message : MESSAGE_GENERIC,
      { target: previewId, preview_id: previewId },
    );
  }

  // ---- the loops -------------------------------------------------------------------------------

  let loopsHandle = null;
  let loopsPending = null;

  /** The notification writer the loops use: the seam a test supplies, or the real one. */
  async function writeNotification(payload) {
    if (notify) return notify(payload);
    try {
      const [{ makeNotify }, { createNotification }] = await Promise.all([
        notifierModule(),
        notificationsModule(),
      ]);
      return await makeNotify(db, createNotification)(payload);
    } catch (err) {
      console.warn("[coinbase] a notification was not sent:", err && err.name ? err.name : "error");
      return null;
    }
  }

  /** The options `startLoops` takes, built without waiting for a module to load. */
  function loopOptions() {
    let factoryClient = null;
    try {
      factoryClient = engineClientFactory({ secretProvider });
    } catch {
      factoryClient = null;
    }
    // The loops get the same whole client the routes use, with every method on it.
    const client = factoryClient && typeof factoryClient.then !== "function" ? factoryClient : fullClient();
    return {
      client,
      notify: writeNotification,
      connection,
      db,
      holder: holderFor(crowHome),
      getProjectId: async () => {
        try {
          const store = await connection.get();
          return store && store.projectId !== undefined ? store.projectId : null;
        } catch {
          return null;
        }
      },
      appendAudit: (database, entry) => aclModule().then((module) => module.appendAudit(database, entry)),
      auditExists: (target) => loopsModule().then((module) => module.auditExistsFor(db)(target)),
    };
  }

  /**
   * Start the loops once for this routes object. The seams that need a client synchronously get a
   * lazy one, so the loops start at mount rather than after a module load; a start that fails is
   * logged without secrets and never stops the routes.
   */
  function startLoops() {
    if (loopsHandle) return loopsHandle;
    if (loopsPending) return null;

    let options;
    try {
      options = loopOptions();
    } catch (err) {
      console.warn("[coinbase] the trading loops did not start:", err && err.name ? err.name : "error");
      return null;
    }

    if (startLoopsImpl) {
      try {
        loopsHandle = startLoopsImpl(options) || null;
      } catch (err) {
        console.warn("[coinbase] the trading loops did not start:", err && err.name ? err.name : "error");
        loopsHandle = null;
      }
      return loopsHandle;
    }

    loopsPending = loopsModule()
      .then((module) => {
        loopsHandle = module.startLoops(options) || null;
        return loopsHandle;
      })
      .catch((err) => {
        console.warn("[coinbase] the trading loops did not start:", err && err.name ? err.name : "error");
        return null;
      })
      .finally(() => {
        loopsPending = null;
      });
    return null;
  }

  function stopLoops() {
    const handle = loopsHandle;
    loopsHandle = null;
    if (handle && typeof handle.stop === "function") {
      try {
        handle.stop();
      } catch {
        // Already stopped.
      }
    }
    if (loopsPending) {
      loopsPending
        .then((late) => {
          if (late && typeof late.stop === "function") late.stop();
        })
        .catch(() => {});
    }
  }

  // ---- the router ------------------------------------------------------------------------------

  const router = typeof config.router === "function" ? config.router : Router();

  let csrfLoaded = typeof config.csrfMiddleware === "function" ? config.csrfMiddleware : null;
  async function csrfMiddleware(req, res, next) {
    try {
      if (!csrfLoaded) {
        const module = await csrfModule();
        csrfLoaded = module.csrfMiddleware;
      }
      return csrfLoaded(req, res, next);
    } catch (err) {
      return next(err);
    }
  }

  router.use(PREFIX, json({ limit: "64kb" }));
  router.use(PREFIX, (req, res, next) => authMiddleware(req, res, next));
  router.use(PREFIX, csrfMiddleware);

  router.get(`${PREFIX}/panel`, wrap(ACTIVITY_PANEL, handlePanel));
  router.get(`${PREFIX}/projects`, wrap(ACTIVITY_PROJECTS, handleProjects));
  router.post(`${PREFIX}/bots`, wrap(ACTIVITY_BOTS_CREATE, handleCreateBot));
  router.post(`${PREFIX}/bots/:id/pause`, wrap(ACTIVITY_BOTS_PAUSE, (req, res) => handleBotAction(req, res, "pause")));
  router.post(`${PREFIX}/bots/:id/stop`, wrap(ACTIVITY_BOTS_STOP, (req, res) => handleBotAction(req, res, "stop")));
  router.post(`${PREFIX}/bots/:id/mode`, wrap(ACTIVITY_BOTS_MODE, handleBotMode));
  router.post(
    `${PREFIX}/bots/:id/resume`,
    wrap(ACTIVITY_BOTS_RESUME, (req, res) => handleBotLiveAction(req, res, "resume")),
  );
  router.post(
    `${PREFIX}/bots/:id/recenter`,
    wrap(ACTIVITY_BOTS_RECENTER, (req, res) => handleBotLiveAction(req, res, "recenter")),
  );
  router.post(`${PREFIX}/switches`, wrap(ACTIVITY_SWITCHES, handleSwitches));
  router.post(`${PREFIX}/caps`, wrap(ACTIVITY_CAPS, handleCaps));
  router.post(`${PREFIX}/kill`, wrap(ACTIVITY_KILL, handleKill));
  router.post(`${PREFIX}/halt/clear`, wrap(ACTIVITY_HALT_CLEAR, handleHaltClear));
  router.post(`${PREFIX}/previews/:id/approve`, wrap(ACTIVITY_PREVIEW_APPROVE, handleApprove));
  router.post(`${PREFIX}/previews/:id/reject`, wrap(ACTIVITY_PREVIEW_REJECT, handleReject));

  // The Connect routes answer their own four paths; they are mounted as soon as their module is
  // there, which is before any request is served (the wrapper above waits for it).
  connectReady
    .then((connect) => {
      if (connect && connect.router) router.use(connect.router);
    })
    .catch(() => {
      // A Connect flow that cannot load leaves its routes unanswered rather than ungated.
    });

  return {
    router,
    connection,
    secretProvider,
    startLoops,
    stopLoops,
    get loops() {
      return loopsHandle;
    },
  };
}

// ---- what the gateway mounts -------------------------------------------------------------------

/**
 * The panel whose loops are running, held on `globalThis` under a symbol so two copies of this
 * file in one process (a reloaded gateway, a panel mounted twice from two module instances) still
 * leave exactly one set of loops behind: the last mount stops the one before it.
 */
const MOUNTED_LOOPS = Symbol.for("crow.coinbase.panel.mountedLoops");

/** Start this mount's loops, stopping the previous mount's first. */
function startMountedLoops(panel) {
  const previous = globalThis[MOUNTED_LOOPS];
  if (previous && previous !== panel) {
    try {
      previous.stopLoops();
    } catch {
      // Already stopped.
    }
  }
  globalThis[MOUNTED_LOOPS] = panel;
  try {
    panel.startLoops();
  } catch (err) {
    console.warn("[coinbase] the trading loops did not start:", err && err.name ? err.name : "error");
  }
}

/**
 * The router the gateway mounts. Synchronous by contract: it builds the database client (the
 * app's own, unless `seams.db`), the routes and the loops at mount, before any request is served.
 *
 * Without `seams.db` the database client comes from the app root, which is asynchronous: the
 * routes are then mounted and their loops started as soon as it answers, and every request waits
 * for that one promise before it is served.
 */
export default function coinbaseRouter(authMiddleware, seams = {}) {
  const options = isPlainObject(seams) ? seams : {};
  const router = Router();
  let panel = null;
  let mountError = null;

  const mountWith = (db) => {
    // The auth middleware is the argument the gateway mounts this router with; a seam may replace
    // it, and every other seam comes from the same object.
    panel = createPanelRoutes({
      ...options,
      authMiddleware: options.authMiddleware || authMiddleware,
      db,
      router,
    });
    return panel;
  };

  if (options.db) {
    // A routes object that cannot be built is a defect in the gateway mount, not a state the page
    // can show, so it is thrown here instead of being read as "no Trading panel".
    mountWith(options.db);
    startMountedLoops(panel);
  } else {
    const ready = appImport("servers/db.js")
      .then((module) => module.createDbClient())
      .then((db) => {
        mountWith(db);
        startMountedLoops(panel);
        return null;
      })
      .catch((err) => {
        mountError = err;
        console.warn("[coinbase] the Trading routes did not mount:", err && err.name ? err.name : "error");
        return null;
      });
    router.use(PREFIX, (req, res, next) => {
      ready.then(() => next(mountError || undefined)).catch(next);
    });
  }

  return router;
}