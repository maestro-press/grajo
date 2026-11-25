/**
 * The Trading panel's Connect flow.
 *
 * One connection of the panel-only service `coinbase` holds everything the engine needs: the key
 * name, the private key and the approval secret, all sealed in the keychain under the connection's
 * uuid. This module is their only reader: the routes here seal them once (createPanelConnection) and
 * the boot loops re-push them through `connection.repush()` after an engine restart.
 *
 * Four routes, all answering JSON:
 *
 *   POST /api/coinbase/connect/test    asks the engine about a key and installs nothing
 *   POST /api/coinbase/connect         seals the key with a fresh approval secret, then pushes it
 *   POST /api/coinbase/disconnect      has the engine forget the pin, then drops the connection
 *   GET  /api/coinbase/connect/state   what the panel shows, read only
 *
 * Four routes hold the Stock prices token (Tiingo) on that same connection. They are
 * LOCAL-SESSION-ONLY: a local password session on this Crow, no 2FA switch check and no code, because
 * the token only reads public prices and can neither spend nor move money. Every route that can trade
 * or reveal still wants both. They refuse a peer session and want the CSRF header like the rest.
 *
 *   POST /api/coinbase/tiingo/test         asks the engine about a pasted token, seals nothing
 *   POST /api/coinbase/tiingo              tests it, seals it on the connection, then pushes it
 *   POST /api/coinbase/tiingo/disconnect   drops the sealed token, then has the engine forget it
 *   GET  /api/coinbase/tiingo/state        what the Stock prices card shows, read only
 *
 * The token is one keychain row (`TIINGO_TOKEN`) on the standing Coinbase connection, so it needs
 * Coinbase connected first and a Coinbase Disconnect takes it with the rest. No route, audit payload
 * or answer ever carries it, and no answer carries even its last four characters.
 *
 * A Connect that replaces the standing connection carries that sealed token onto the new row: the
 * token is read from the connection being let go while it still stands, sealed on the connection
 * that replaces it, and then handed to the engine with the new client — best effort, never part of
 * the answer, and a copy that cannot be made leaves the connection itself untouched. Only a row of
 * the new connection's own project is read for that copy: every other active row of the service is
 * still let go, but a token sealed in another project stays with the row it was pasted on.
 *
 * The state route reads the engine's own view of the prices: `connected`, `missing`, `rejected`, or
 * `paused` while Tiingo is limiting Crow. A pause is not a refusal — the token is fine and the
 * prices resume on their own — so it answers `connected: true` with the pause sentence, keeping the
 * five keys every reader of that route depends on.
 *
 * Every POST sits behind a local password session on this Crow and 2FA switched on; the two that
 * write anything (Connect and Disconnect) also want a fresh code, checked by the one step-up gate
 * this process has, so a code already used is never used again. That code is proof of who is here
 * and nothing more: it leaves no keychain grant behind, so connecting never opens saved secrets
 * for reveal, copy or export. The Test route installs nothing and takes no code. A refusal is
 * `{ok:false, code, message}`; the message is the fix-it copy for the engine's own refusal code.
 *
 * A push whose answer never came back is not a failed push: the engine may have kept the key. The
 * row then says `pending_pin` and the next step (a re-push with the sealed secret, or the engine's
 * own health answer) settles it — never a second seal of a different secret behind a pin.
 *
 * Privacy is a rule of the module: the private key, the key name and the approval secret never
 * reach an answer, a log line, an audit payload or a thrown message. The engine reports the last
 * four characters of the key name and of the portfolio, and only those are kept.
 *
 * The app pieces are reached through the bundle's own app-root, by literal paths, so an installed
 * copy loads the same modules the gateway holds (never a second SQLite build).
 */
import { randomBytes } from "node:crypto";

import { appImport, appPackage } from "../server/app-root.js";
import { readInstallToken } from "../server/engine-client.js";

// Express comes from the app root's own install: a bundle copied into
// <CROW_HOME>/bundles/<id>/ has no node_modules of its own, and connect.js runs from there
// (and from an installed panel copy) as well as from the repo.
const express = (await appPackage("express")).default;
const { Router, json } = express;

const PREFIX = "/api/coinbase";
const SERVICE_ID = "coinbase";
const ACTOR_TYPE = "local";
const ACCOUNT_LABEL = "Crow portfolio";
const LABEL_TRIES = 9;
// The keychain's own ceiling for a pasted value, so what is sealed here is what it would seal.
const FIELD_MAX_CHARS = 4096;
const CONTROL_RE = /\p{Cc}/u;
const APPROVE_SECRET_BYTES = 32;

const SECRET_KEY_NAME = "COINBASE_KEY_NAME";
const SECRET_PRIVATE_KEY = "COINBASE_PRIVATE_KEY";
const SECRET_APPROVE = "COINBASE_APPROVE_SECRET";
// The Stock prices token: one more sealed row on the same connection, deliberately NOT a declared
// panel secret (a declared one is required of every existing connection, which would break them).
const SECRET_TIINGO_TOKEN = "TIINGO_TOKEN";
const TIINGO_LABEL = "Coinbase \u2014 Stock prices \u2014 TIINGO_TOKEN";

const ACTION_CONNECT = "coinbase.connect";
const ACTION_TEST = "coinbase.connect_test";
const ACTION_DISCONNECT = "coinbase.disconnect";
const ACTION_TIINGO_TEST = "coinbase.tiingo_test";
const ACTION_TIINGO_CONNECT = "coinbase.tiingo_connect";
const ACTION_TIINGO_DISCONNECT = "coinbase.tiingo_disconnect";

const CODE_OK = "ok";
const CODE_BAD_REQUEST = "bad_request";
const CODE_LOCAL_LOGIN = "local_login_required";
const CODE_TWO_FACTOR = "two_factor_required";
const CODE_TOTP = "totp_required";
const CODE_STEP_UP_LOCKED = "step_up_locked";
const CODE_ALREADY_CONNECTED = "already_connected";
const CODE_PROJECT_LOCKED = "project_locked";
const CODE_PROJECT_NOT_FOUND = "project_not_found";
const CODE_NOT_CONNECTED = "not_connected";
const CODE_LIVE_ORDERS = "live_orders_open";
const CODE_LIVE_BOTS = "live_bots";
const CODE_ENGINE_PINNED = "engine_pinned";
const CODE_ENGINE_UNREACHABLE = "engine_unreachable";
const CODE_LABEL_TAKEN = "label_taken";
const CODE_FAILED = "connect_failed";

const MESSAGE_LOCAL_LOGIN =
  "Sign in on this Crow with your password to connect Coinbase (peer sign-in is not enough).";
const MESSAGE_TWO_FACTOR = "Turn on two-factor sign-in first (Settings \u2192 Security)";
const MESSAGE_TOTP = "Enter your current 2FA code.";
const MESSAGE_STEP_UP_LOCKED = "Too many wrong codes. Try again in 15 minutes.";
const MESSAGE_BAD_BODY = "Crow could not read that request. Try again.";
const MESSAGE_PICK_PROJECT = "Pick a project first.";
const MESSAGE_ALREADY_CONNECTED = "Already connected. Disconnect first to use a different key.";
const MESSAGE_PROJECT_LOCKED = "This connection stays with its project. Disconnect first to move it.";
const MESSAGE_PROJECT_NOT_FOUND = "That project was not found.";
const MESSAGE_NOT_CONNECTED = "Coinbase is not connected.";
const MESSAGE_LIVE_ORDERS = "Pause or stop live bots first";
const MESSAGE_LIVE_BOTS = "Switch live bots back to practice mode first.";
const MESSAGE_DISCONNECTED = "Disconnected.";
const MESSAGE_ENGINE_UNREACHABLE =
  "The trading engine isn't answering. Check that the Coinbase add-on is running.";
const MESSAGE_ENGINE_NOT_ANSWERING =
  "The trading engine isn't answering. Try Connect again in a minute.";
const MESSAGE_SIGNING =
  "Crow could not sign this request. Check that the Coinbase add-on is installed and running.";
const MESSAGE_RATE_LIMITED = "Too many tries. Wait a minute and try again.";
const MESSAGE_GENERIC = "Crow could not connect to Coinbase. Try again.";
// Only a pin this install never made earns this sentence; a pin an unfinished Connect may have
// left is settled by the recovery below, not by asking for help.
const MESSAGE_ENGINE_PINNED =
  "The trading engine still holds your earlier Coinbase connection. Ask for help resetting it.";

const ACCEPTED_PREFIX = "Key accepted \u2014 Crow portfolio \u2026";
const CONNECTED_PREFIX = "Connected \u2014 Crow portfolio \u2026";

// The Stock prices card's own words. The engine's fixed sentences are for a token it refused; the
// four sentences below are what the card says about the state it read, so the engine's own words
// never reach the page through this field.
const MESSAGE_PASTE_TIINGO = "Paste the Tiingo token.";
const MESSAGE_TIINGO_ACCEPTED = "Tiingo accepted the token.";
const MESSAGE_TIINGO_SAVED = "Stock prices connected.";
const MESSAGE_TIINGO_PENDING =
  "Saved. Crow will send it to the trading engine as soon as it answers.";
const MESSAGE_TIINGO_DISCONNECTED = "Stock prices disconnected.";
const MESSAGE_CONNECT_COINBASE_FIRST = "Connect Coinbase first.";
const MESSAGE_PRICES_CONNECTED = "Stock prices are connected (Tiingo).";
const MESSAGE_PRICES_MISSING =
  "Stock prices are not connected, so practice stock orders will not fill. " +
  "Paste your free Tiingo token below.";
const MESSAGE_PRICES_REJECTED = "Tiingo did not accept the token. Paste it again.";
// A paused allowance: Tiingo is limiting Crow's requests, so the prices wait. The token is fine,
// which is why the state route answers this as connected.
const MESSAGE_PRICES_PAUSED =
  "Stock prices are paused for now (Tiingo is limiting requests); they will resume on their own.";

/** The setup steps the panel shows above the two fields. */
export const COPY_STEPS =
  "1. In Coinbase, create a portfolio named Crow and move only the money you want the bot to use. " +
  "2. Create an API key for the Crow portfolio with View and Trade. Do not tick Transfer. " +
  "3. Paste the key name and private key here. 4. Press Test connection.";

// What to do about an engine refusal, in plain words. Unknown codes take the generic sentence.
const FIX_IT = {
  KEY_CAN_TRANSFER:
    "This key can move money out of Coinbase. Create a new key and leave Transfer unticked (View and Trade only).",
  KEY_NOT_PORTFOLIO_SCOPED:
    "This key is not limited to one portfolio. Create the key for the Crow portfolio only.",
  KEY_DEFAULT_PORTFOLIO:
    "This key is for your main Coinbase portfolio. Create a key for the Crow portfolio instead.",
  KEY_WRONG_PORTFOLIO:
    "This key is for a different portfolio than the one Crow trades. Create a key for the Crow portfolio.",
  KEY_CANNOT_TRADE: "This key can only view. Create a key with View and Trade.",
  KEY_INVALID:
    "Coinbase did not accept this key. Check that you pasted the key name and the whole private key, with nothing added or missing.",
  SECRET_MISMATCH: MESSAGE_GENERIC,
  RATE_LIMITED: MESSAGE_RATE_LIMITED,
  ENGINE_UNREACHABLE: MESSAGE_ENGINE_UNREACHABLE,
  NOT_CONNECTED: MESSAGE_SIGNING,
  NOT_ALLOWED: MESSAGE_SIGNING,
  ENGINE_AUTH: MESSAGE_SIGNING,
  LIVE_ORDERS_OPEN: MESSAGE_LIVE_ORDERS,
  LIVE_BOTS: MESSAGE_LIVE_BOTS,
};

/** The sentence a person sees for an engine refusal code. */
export function fixit(code) {
  const key = typeof code === "string" ? code : "";
  return Object.hasOwn(FIX_IT, key) ? FIX_IT[key] : MESSAGE_GENERIC;
}

/** The HTTP status an engine refusal earns. */
function statusForCode(code) {
  if (code === "RATE_LIMITED") return 429;
  if (code === "ENGINE_UNREACHABLE") return 503;
  if (code === "SECRET_MISMATCH") return 409;
  if (code === "LIVE_ORDERS_OPEN" || code === "LIVE_BOTS") return 409;
  if (code === "NOT_CONNECTED" || code === "NOT_ALLOWED" || code === "ENGINE_AUTH") return 502;
  if (typeof code === "string" && code.startsWith("KEY_")) return 422;
  return 502;
}

/** The code the panel shows: the engine's own, except a foreign pin, which is a state. */
function publicCode(code, { foreignPin = false } = {}) {
  const raw = typeof code === "string" && code ? code : "ENGINE_UNREACHABLE";
  if (raw === "SECRET_MISMATCH" && foreignPin) return CODE_ENGINE_PINNED;
  return raw;
}

/** The sentence for an engine refusal; a pin nobody here made gets the help one. */
function messageForCode(code, { foreignPin = false } = {}) {
  if (code === "SECRET_MISMATCH") return foreignPin ? MESSAGE_ENGINE_PINNED : MESSAGE_GENERIC;
  return fixit(code);
}

/** Refusals that mean the engine looked at the push and said no: the row must go. */
const DEFINITE_REFUSALS = new Set([
  "SECRET_MISMATCH",
  "APPROVAL_INVALID",
  "RATE_LIMITED",
  "INVALID",
  "NOT_ALLOWED",
  "NOT_CONNECTED",
  "ENGINE_AUTH",
]);

function isDefiniteRefusal(result) {
  const code = result && typeof result.code === "string" ? result.code : "";
  if (code.startsWith("KEY_")) return true;
  return DEFINITE_REFUSALS.has(code);
}

/** A push the engine may or may not have taken: the answer never came back. */
function isUncertainFailure(result) {
  if (!result) return true;
  if (result.code === "ENGINE_UNREACHABLE") return true;
  const status = Number.isFinite(result.status) ? result.status : 0;
  return status === 0 || status >= 500;
}

// ---- lazy app modules (one import per process, retried after a failure) -----------------------

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

const services = lazy(() => appImport("servers/shared/service-connections.js"));
const acl = lazy(() => appImport("servers/shared/project-acl.js"));
const keychainStore = lazy(() => appImport("servers/gateway/keychain/store.js"));
const localSession = lazy(() => appImport("servers/gateway/dashboard/local-session.js"));
const totp = lazy(() => appImport("servers/gateway/dashboard/totp.js"));
const stepUp = lazy(() => appImport("servers/gateway/dashboard/step-up.js"));

// ---- small helpers ----------------------------------------------------------------------------

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseConfig(text) {
  if (!text) return {};
  try {
    const parsed = JSON.parse(text);
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

function positiveProjectId(value) {
  const number = typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  return Number.isInteger(number) && number > 0 ? number : null;
}

/**
 * A pasted key name or private key, cleaned exactly the way the keychain cleans a panel secret:
 * CRLF line ends become LF, every other control character (a lone CR, a tab, a NUL) is refused,
 * the text is trimmed, and it must be non-empty and no longer than the keychain's own ceiling.
 * null when the value cannot be used, so the caller sends nothing to the engine.
 *
 * The cleaned bytes are what is checked, what is pushed and what is sealed, so the sealed value is
 * the pushed value.
 */
function cleanPastedValue(value) {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/\r\n/g, "\n");
  if (CONTROL_RE.test(normalized.replace(/\n/g, ""))) return null;
  const text = normalized.trim();
  if (text === "") return null;
  if (text.length > FIELD_MAX_CHARS) return null;
  return text;
}

/**
 * A pasted Stock prices token, cleaned the same way a pasted key is: CRLF line ends become LF, the
 * text is trimmed and it must be one line with no spaces or control characters. null when the value
 * cannot be used, so nothing is sent to the engine. The shape rules a token must satisfy (printable
 * ASCII only, at most 256 characters) stay the engine's own: it answers TOKEN_SHAPE, in its own
 * words, for anything this cleaner let through.
 */
function cleanTiingoToken(value) {
  if (typeof value !== "string") return null;
  const normalized = value.replace(/\r\n/g, "\n");
  if (CONTROL_RE.test(normalized)) return null;
  const text = normalized.trim();
  if (text === "") return null;
  if (text.length > FIELD_MAX_CHARS) return null;
  if (/\s/.test(text)) return null;
  return text;
}

/**
 * A promise-chain mutex: each task starts after the one before it settled, and a task that throws
 * does not break the chain for the next one. Not reentrant — a task that already holds it must
 * call the unlocked form of whatever it needs.
 */
function createMutex() {
  let tail = Promise.resolve();
  return function runExclusive(task) {
    const answer = tail.then(() => task());
    tail = answer.then(
      () => undefined,
      () => undefined,
    );
    return answer;
  };
}

/**
 * The sealed Stock prices token on one connection, or null. `row` is the connection row (or its
 * uuid). Exported for tests that read the keychain the way the panel does; its answer is never
 * handed to a response, an audit row or a log line.
 */
export async function sealedTiingoToken(db, loadKey, row) {
  const uuid = row && typeof row === "object" ? row.uuid : row;
  if (typeof uuid !== "string" || uuid === "") return null;
  const { serviceSecretsFor } = await keychainStore();
  const key = typeof loadKey === "function" ? await loadKey() : null;
  const secrets = await serviceSecretsFor(db, key, String(uuid), {
    allowedKeys: [SECRET_TIINGO_TOKEN],
  });
  const value = secrets ? secrets[SECRET_TIINGO_TOKEN] : null;
  return typeof value === "string" && value ? value : null;
}

/**
 * The keychain seam the Tiingo work goes through: `save(uuid, token)`, `read(uuid)` and
 * `remove(uuid)` over the real sealing functions, on the same connection and under the same key as
 * its key name and private key. A read that cannot open the keychain answers null (nothing to
 * push) rather than guessing at a token.
 */
function createTiingoStore(db, loadKey) {
  return {
    async save(uuid, token) {
      const { saveServiceSecret } = await keychainStore();
      return saveServiceSecret(db, await loadKey(), {
        connectionUuid: String(uuid),
        bundleId: SERVICE_ID,
        envKey: SECRET_TIINGO_TOKEN,
        label: TIINGO_LABEL,
        secret: String(token),
      });
    },
    async read(uuid) {
      try {
        return await sealedTiingoToken(db, loadKey, { uuid });
      } catch {
        return null;
      }
    },
    async remove(uuid) {
      const { deleteServiceSecret } = await keychainStore();
      return deleteServiceSecret(db, String(uuid), SECRET_TIINGO_TOKEN, { bundleId: SERVICE_ID });
    },
  };
}

/** The newest active connection of a service, or null. */
async function readActiveRow(db, serviceId) {
  const result = await db.execute({
    sql: `SELECT uuid, project_id, config FROM service_connections
          WHERE service_id = ? AND status = 'active' AND owner_contact_id IS NULL
          ORDER BY id DESC LIMIT 1`,
    args: [serviceId],
  });
  const rows = result && Array.isArray(result.rows) ? result.rows : [];
  return rows[0] || null;
}

async function writeConfig(db, uuid, config) {
  await db.execute({
    sql: "UPDATE service_connections SET config = ?, updated_at = datetime('now') WHERE uuid = ?",
    args: [JSON.stringify(config), uuid],
  });
}

// ---- the connection store the boot loops read --------------------------------------------------

/**
 * The store `startLoops` takes as `connection`.
 *
 * `get()` answers which project this install is bound to, which engine epoch the sealed
 * credentials belong to, whether the panel is already asking for a reconnect, and whether a
 * Disconnect is still in flight; null when nothing is connected. (`pending` is settled through
 * `repush()`, which is what a pending row is waiting for.) `markNeedsReconnect()` sets that flag
 * in the row's config, keeping the rest of it. `clearDisconnecting()` drops the halfway flag
 * again, for a health read that shows the Disconnect never went through. `repush()` reads the
 * sealed secrets and pushes them again with the owner's MAC, answering the engine client's result
 * unchanged; no secret is ever in one. A successful re-push settles a `pending_pin`.
 *
 * `repush()` runs inside `lock`, the mutex the Connect routes share with it; `repushUnlocked()` is
 * the same work for a caller that already holds the lock (the lock is not reentrant).
 */
export function createConnectionStore(options = {}) {
  const config = options || {};
  const db = config.db;
  const crowHome = config.crowHome;
  const serviceId = typeof config.serviceId === "string" && config.serviceId ? config.serviceId : SERVICE_ID;
  const engineClient = config.engineClient;
  const loadKey = typeof config.loadKey === "function" ? config.loadKey : null;
  const lock = typeof config.lock === "function" ? config.lock : createMutex();
  const keyLoader = loadKey || (async () => {
    const { ensureWriteKey } = await keychainStore();
    return ensureWriteKey(db, { crowHome });
  });
  // The same keychain seam the Connect routes use, so a re-push sends the sealed token whether the
  // routes handed one in or the defaults sealed it.
  const tiingoStore = isPlainObject(config.tiingoStore) ? config.tiingoStore : createTiingoStore(db, keyLoader);

  const notConnected = () => ({
    ok: false,
    status: 0,
    code: "NOT_CONNECTED",
    message: "Coinbase is not connected.",
  });

  async function get() {
    try {
      const row = await readActiveRow(db, serviceId);
      if (!row) return null;
      const stored = parseConfig(row.config);
      return {
        projectId: Number(row.project_id),
        engineEpoch: stored.engine_epoch === undefined || stored.engine_epoch === null
          ? null
          : String(stored.engine_epoch),
        needsReconnect: stored.needs_reconnect === true,
        disconnecting: stored.disconnecting === true,
      };
    } catch {
      return null;
    }
  }

  async function markNeedsReconnect() {
    try {
      const row = await readActiveRow(db, serviceId);
      if (!row) return false;
      const stored = parseConfig(row.config);
      stored.needs_reconnect = true;
      await writeConfig(db, row.uuid, stored);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Drop the "a Disconnect is in flight" flag: the engine still holds the pin, so no Disconnect
   * was in flight after all, and the flag must not hide the next real reset. A row without the
   * flag is left untouched (no write). Never throws.
   * @returns {Promise<boolean>} whether the flag was there and is now gone
   */
  async function clearDisconnecting() {
    try {
      const row = await readActiveRow(db, serviceId);
      if (!row) return false;
      const stored = parseConfig(row.config);
      if (stored.disconnecting !== true) return false;
      delete stored.disconnecting;
      await writeConfig(db, row.uuid, stored);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Hand the sealed Stock prices token back to the engine, if one is sealed.
   *
   * The same restart that lost the key lost the token, so a successful credentials push is also the
   * moment to send it. Never throws and never changes the caller's result: a token the engine never
   * answered for stays sealed here, so the next re-push sends it again, and its value is never in a
   * result.
   */
  async function pushSealedTiingo(uuid) {
    if (!engineClient || typeof engineClient.setTiingo !== "function") return;
    let token = null;
    try {
      token = await tiingoStore.read(uuid);
    } catch {
      return;
    }
    if (typeof token !== "string" || token === "") return;
    try {
      await engineClient.setTiingo({ token });
    } catch {
      // A token the engine never answered for is still sealed here.
    }
  }

  async function repushUnlocked() {
    let row;
    let secrets;
    try {
      row = await readActiveRow(db, serviceId);
      if (!row) return notConnected();
      const key = loadKey ? await loadKey() : null;
      const { panelSecretsFor } = await services();
      secrets = await panelSecretsFor(db, key, row.uuid, { crowHome });
    } catch {
      return notConnected();
    }
    if (!secrets || typeof secrets[SECRET_PRIVATE_KEY] !== "string" || !secrets[SECRET_PRIVATE_KEY]) {
      return notConnected();
    }
    if (!engineClient || typeof engineClient.pushCredentials !== "function") return notConnected();

    const result = await engineClient.pushCredentials(
      {
        key_name: secrets[SECRET_KEY_NAME],
        private_key: secrets[SECRET_PRIVATE_KEY],
        approve_secret: secrets[SECRET_APPROVE],
      },
      { keyKind: "owner" },
    );

    if (result && result.ok) {
      const data = isPlainObject(result.data) ? result.data : {};
      const epoch = data.engine_epoch;
      try {
        const stored = parseConfig(row.config);
        if (epoch !== undefined && epoch !== null && epoch !== "") stored.engine_epoch = String(epoch);
        const keyLast4 = last4(data.key_last4);
        if (keyLast4 !== null) stored.key_last4 = keyLast4;
        const portfolioLast4 = last4(data.portfolio_last4);
        if (portfolioLast4 !== null) stored.portfolio_last4 = portfolioLast4;
        // The engine holds the key it was given, so a pin this install was unsure about is settled.
        delete stored.pending_pin;
        await writeConfig(db, row.uuid, stored);
      } catch {
        // A config write that fails changes nothing about the push the engine accepted.
      }
      await pushSealedTiingo(row.uuid);
    }
    return result;
  }

  async function repush() {
    return lock(() => repushUnlocked());
  }

  return { get, markNeedsReconnect, clearDisconnecting, repush, repushUnlocked };
}

// ---- the routes --------------------------------------------------------------------------------

/**
 * The Connect routes and the store they share with the boot loops. Task 10 mounts the router; this
 * module mounts nothing.
 *
 * `authMiddleware` is required: a route set built without one is refused here rather than served
 * ungated. `stepUpGate` is the step-up gate; without one the shared process-wide gate is loaded on
 * first use and `getStepUpGate()` answers it. `lock` is the in-process mutex Connect, Disconnect and
 * `connection.repush()` share (a fresh one is made when the caller has none). `onConnected({
 * projectId, connectionUuid })` runs after a successful Connect and `onDisconnected({ projectId,
 * connectionUuid })` after a successful Disconnect; both are awaited and neither can fail the
 * answer.
 *
 * Besides `router` and `connection`, the answer carries the pieces the panel's own routes use:
 * `secretProvider(kind)` (the sealed owner secret, or the install token), `gates(req, res, action,
 * { needsCode, needs2fa })`, `writeAudit(projectId, action, target, payload)`, `buildClient()` and
 * `boundProjectId()`. None of them ever answers with a secret.
 *
 * `tiingoStore` is the keychain seam the four Stock prices routes seal, read and drop the token
 * through: `{save(uuid, token), read(uuid), remove(uuid)}`, all async. The defaults wrap
 * `saveServiceSecret` / `serviceSecretsFor` (allowed key `TIINGO_TOKEN`) / `deleteServiceSecret`
 * with the key from `loadKey`; the connection store takes the same seam for its re-push, so a row is
 * read back the way it was written whichever way the routes reached it.
 */
export function createConnectRoutes(options = {}) {
  const config = options || {};
  const db = config.db;
  const crowHome = config.crowHome;
  const serviceId = typeof config.serviceId === "string" && config.serviceId ? config.serviceId : SERVICE_ID;
  const engineClientFactory = typeof config.engineClientFactory === "function"
    ? config.engineClientFactory
    : null;

  if (typeof config.authMiddleware !== "function") {
    throw new TypeError("createConnectRoutes needs an auth middleware");
  }
  const authMiddleware = config.authMiddleware;
  let csrfLoaded = typeof config.csrfMiddleware === "function" ? config.csrfMiddleware : null;

  const lock = typeof config.lock === "function" ? config.lock : createMutex();

  const givenStepUpGate =
    config.stepUpGate && typeof config.stepUpGate.verify === "function" ? config.stepUpGate : null;
  let sharedGate = null;

  /** The step-up gate these routes use: the one given, or this process's single gate. */
  async function getStepUpGate() {
    if (givenStepUpGate) return givenStepUpGate;
    if (!sharedGate) {
      sharedGate = stepUp().then((module) => module.sharedStepUpGate());
      sharedGate.catch(() => {
        sharedGate = null;
      });
    }
    return sharedGate;
  }

  const loadKey = typeof config.loadKey === "function"
    ? config.loadKey
    : async () => {
      const { ensureWriteKey } = await keychainStore();
      return ensureWriteKey(db, { crowHome });
    };

  // The local-session loader this route set reads through, overridable so a test can supply it.
  const loadLocalSession =
    typeof config.localSessionModule === "function" ? config.localSessionModule : localSession;

  const isLocalSession = typeof config.isLocalSession === "function"
    ? config.isLocalSession
    : async (database, req) => {
      const { isLocalPasswordSessionOn } = await loadLocalSession();
      return isLocalPasswordSessionOn(database, req);
    };

  const is2faEnabled = typeof config.is2faEnabled === "function"
    ? config.is2faEnabled
    : async () => {
      const module = await totp();
      return module.is2faEnabled();
    };

  const onConnected = typeof config.onConnected === "function" ? config.onConnected : async () => {};
  // Told once a Disconnect has dropped the row, so the panel can clear what it had stored about
  // the connection. A listener that fails changes nothing about the answer.
  const onDisconnected = typeof config.onDisconnected === "function" ? config.onDisconnected : async () => {};

  // ---- the engine client, built per request ---------------------------------------------------

  async function ownerApprovalSecret() {
    const row = await readActiveRow(db, serviceId);
    if (!row) return null;
    const { panelSecretsFor } = await services();
    const secrets = await panelSecretsFor(db, await loadKey(), row.uuid, { crowHome });
    const secret = secrets ? secrets[SECRET_APPROVE] : null;
    return typeof secret === "string" && secret ? secret : null;
  }

  async function secretProvider(kind) {
    if (kind === "install") return readInstallToken(crowHome);
    if (kind !== "owner") return null;
    return ownerApprovalSecret();
  }

  async function buildClient() {
    if (!engineClientFactory) return null;
    return engineClientFactory({ secretProvider });
  }

  // The store's client: one fresh engine client per push, so a re-push always signs with the
  // owner's secret as the connection stands now.
  const storeClient = {
    async pushCredentials(body, pushOptions) {
      const client = await buildClient();
      if (!client || typeof client.pushCredentials !== "function") {
        return { ok: false, status: 0, code: "ENGINE_UNREACHABLE", message: "" };
      }
      return client.pushCredentials(body, pushOptions);
    },
    /** The Stock prices token rides along on a credentials push, one fresh client per call. */
    async setTiingo(body) {
      const client = await buildClient();
      if (!client || typeof client.setTiingo !== "function") {
        return { ok: false, status: 0, code: "ENGINE_UNREACHABLE", message: "" };
      }
      return client.setTiingo(body);
    },
  };

  // The keychain seam the four Stock prices routes seal, read and drop the token through. A caller
  // may hand one in (the tests do), so the rows are the same rows either way.
  const tiingoStore = isPlainObject(config.tiingoStore)
    ? config.tiingoStore
    : createTiingoStore(db, loadKey);

  const connection = createConnectionStore({
    db,
    crowHome,
    serviceId,
    engineClient: storeClient,
    loadKey,
    lock,
    tiingoStore,
  });

  // ---- audit ----------------------------------------------------------------------------------

  async function writeAudit(projectId, action, target, payload) {
    const project = positiveProjectId(projectId);
    if (project === null) return;
    try {
      const { appendAudit } = await acl();
      await appendAudit(db, {
        project_id: project,
        actor_type: ACTOR_TYPE,
        action,
        target: target ?? null,
        payload,
      });
    } catch {
      // An audit writer that fails never changes the answer.
    }
  }

  /** The project the standing connection belongs to, or null when nothing is connected. */
  async function boundProjectId() {
    try {
      const row = await readActiveRow(db, serviceId);
      return row ? Number(row.project_id) : null;
    } catch {
      return null;
    }
  }

  /** The project an answer is about: the bound one, or the body's before anything is bound. */
  async function projectHint(req) {
    const fromBody = isPlainObject(req.body) ? positiveProjectId(req.body.project_id) : null;
    if (fromBody !== null) return fromBody;
    return boundProjectId();
  }

  // ---- answers --------------------------------------------------------------------------------

  function answerRefusal(res, status, code, message) {
    return res.status(status).json({ ok: false, code, message });
  }

  async function refuse(res, action, projectId, status, code, message, target = null) {
    await writeAudit(projectId, action, target, { ok: false, code });
    return answerRefusal(res, status, code, message);
  }

  /**
   * A refusal written against the connection's own project, or against no project at all when
   * nothing is connected. The request body never picks where a gate refusal is filed: a caller who
   * cannot get past the gate does not get to name the project the refusal lands in.
   */
  async function refuseGate(res, action, status, code, message) {
    await writeAudit(await boundProjectId(), action, null, { ok: false, code });
    return answerRefusal(res, status, code, message);
  }

  /** Answer for a refusal the engine client returned. No field of it reaches the answer. */
  async function refuseEngine(res, action, projectId, target, result, refusal = {}) {
    const raw = result && typeof result.code === "string" && result.code ? result.code : "ENGINE_UNREACHABLE";
    const foreignPin = refusal.foreignPin === true && raw === "SECRET_MISMATCH";
    const code = publicCode(raw, { foreignPin });
    await writeAudit(projectId, action, target, { ok: false, code });
    return answerRefusal(res, statusForCode(raw), code, messageForCode(raw, { foreignPin }));
  }

  async function refuseUnreachable(res, action, projectId, target = null) {
    await writeAudit(projectId, action, target, { ok: false, code: CODE_ENGINE_UNREACHABLE });
    return answerRefusal(res, 503, CODE_ENGINE_UNREACHABLE, MESSAGE_ENGINE_UNREACHABLE);
  }

  // ---- the gates every POST passes --------------------------------------------------------------

  /**
   * true when the caller may go on. Otherwise the refusal has been answered (filed against the
   * bound project, or nowhere) and the handler stops.
   *
   * Order: a local password session on this Crow, then 2FA switched on, then — for a route that
   * writes something — a fresh code from the step-up gate. A route that installs nothing passes
   * `needsCode: false` and stops after the 2FA check. `needs2fa: false` drops only the 2FA-on
   * check (the kill switch and the other stopping actions must work with 2FA off); the local
   * session check always stands, and a route that still wants a code still gets one.
   */
  async function gates(req, res, action, { needsCode = true, needs2fa = true } = {}) {
    const body = isPlainObject(req.body) ? req.body : {};

    let local = false;
    try {
      local = (await isLocalSession(db, req)) === true;
    } catch {
      local = false;
    }
    if (!local) {
      await refuseGate(res, action, 403, CODE_LOCAL_LOGIN, MESSAGE_LOCAL_LOGIN);
      return false;
    }

    if (needs2fa) {
      let twoFactorOn = false;
      try {
        twoFactorOn = (await is2faEnabled()) === true;
      } catch {
        twoFactorOn = false;
      }
      if (!twoFactorOn) {
        await refuseGate(res, action, 403, CODE_TWO_FACTOR, MESSAGE_TWO_FACTOR);
        return false;
      }
    }

    if (!needsCode) return true;

    let stepped = null;
    try {
      const gate = await getStepUpGate();
      // `grant: false`: this code proves who is here, it does not open the keychain for reveal,
      // copy or export. The failure counting, the lockout and the replay guard all still apply.
      stepped = await gate.verify(req.dashboardSession, { totp_code: body.totp, grant: false });
    } catch {
      stepped = null; // a gate that cannot answer is a refusal, never a pass
    }
    if (stepped && stepped.ok === true) return true;
    if (stepped && stepped.locked === true) {
      await refuseGate(res, action, 429, CODE_STEP_UP_LOCKED, MESSAGE_STEP_UP_LOCKED);
      return false;
    }
    await refuseGate(res, action, 403, CODE_TOTP, MESSAGE_TOTP);
    return false;
  }

  // ---- the routes ---------------------------------------------------------------------------------

  const router = Router();

  router.use(PREFIX, json({ limit: "64kb" }));

  async function csrfMiddleware(req, res, next) {
    try {
      if (!csrfLoaded) {
        const module = await appImport("servers/gateway/dashboard/shared/csrf.js");
        csrfLoaded = module.csrfMiddleware;
      }
      return csrfLoaded(req, res, next);
    } catch (err) {
      return next(err);
    }
  }

  router.use(PREFIX, (req, res, next) => authMiddleware(req, res, next));
  router.use(PREFIX, csrfMiddleware);

  const wrap = (action, handler, gateOptions) => async (req, res) => {
    try {
      await lock(async () => {
        if (!(await gates(req, res, action, gateOptions))) return undefined;
        return handler(req, res);
      });
      return undefined;
    } catch {
      if (res.headersSent) return undefined;
      const projectId = await boundProjectId();
      await writeAudit(projectId, action, null, { ok: false, code: CODE_FAILED });
      try {
        return answerRefusal(res, 500, CODE_FAILED, MESSAGE_GENERIC);
      } catch {
        return undefined;
      }
    }
  };

  // ---- POST /api/coinbase/connect/test -----------------------------------------------------------

  async function handleTest(req, res) {
    if (!isPlainObject(req.body)) {
      return refuse(res, ACTION_TEST, await boundProjectId(), 400, CODE_BAD_REQUEST, MESSAGE_BAD_BODY);
    }
    const keyName = cleanPastedValue(req.body.key_name);
    const privateKey = cleanPastedValue(req.body.private_key);
    if (!keyName || !privateKey) {
      return refuse(res, ACTION_TEST, await boundProjectId(), 400, CODE_BAD_REQUEST, fixit("KEY_INVALID"));
    }
    const projectId = await projectHint(req);

    const client = await buildClient();
    if (!client) return refuseUnreachable(res, ACTION_TEST, projectId);

    const health = await client.health();
    if (!health || !health.ok) return refuseUnreachable(res, ACTION_TEST, projectId);
    const healthData = isPlainObject(health.data) ? health.data : {};
    const keyKind = healthData.pinned === false ? "install" : "owner";

    const probe = await client.checkCredentials({ key_name: keyName, private_key: privateKey }, { keyKind });
    if (!probe || !probe.ok) return refuseEngine(res, ACTION_TEST, projectId, null, probe);

    const probeData = isPlainObject(probe.data) ? probe.data : {};
    if (probeData.state && probeData.state !== CODE_OK) {
      return refuseEngine(res, ACTION_TEST, projectId, null, { code: probeData.code || "KEY_INVALID" });
    }

    const keyLast4 = last4(probeData.key_last4);
    const portfolioLast4 = last4(probeData.portfolio_last4);
    await writeAudit(projectId, ACTION_TEST, null, {
      ok: true,
      key_last4: keyLast4,
      portfolio_last4: portfolioLast4,
    });
    return res.json({
      ok: true,
      message: ACCEPTED_PREFIX + (portfolioLast4 === null ? "" : portfolioLast4),
      key_last4: keyLast4,
      portfolio_last4: portfolioLast4,
    });
  }

  // ---- POST /api/coinbase/connect ----------------------------------------------------------------

  async function createConnectionRow({ projectId, keyName, privateKey, secret }) {
    const { createPanelConnection } = await services();
    const key = await loadKey();
    let lastError = null;
    for (let attempt = 0; attempt < LABEL_TRIES; attempt += 1) {
      const accountLabel = attempt === 0 ? ACCOUNT_LABEL : `${ACCOUNT_LABEL} ${attempt + 1}`;
      try {
        return await createPanelConnection(
          db,
          {
            projectId,
            serviceId,
            accountLabel,
            config: {},
            secrets: {
              [SECRET_KEY_NAME]: keyName,
              [SECRET_PRIVATE_KEY]: privateKey,
              [SECRET_APPROVE]: secret,
            },
          },
          { key, actor: "local", crowHome },
        );
      } catch (err) {
        lastError = err;
        if (err && err.code === "label_taken") continue;
        throw err;
      }
    }
    throw lastError;
  }

  /**
   * The other active connections of this service, oldest first: every row that stands beside
   * `rowUuid` and has to go, and the one a Connect that replaces a connection reads first.
   *
   * `projectId` narrows the read to the rows of one project, and only the carry ever names one: a
   * sealed token belongs to the connection it was pasted on, so a Connect that replaces a
   * connection in one project reads the token of that project's row and never a token sealed in
   * another. A caller that names no project — `disconnectOtherActiveRows` — still gets every other
   * active row of the service, whatever project it stands in.
   */
  async function otherActiveRows(rowUuid, projectId) {
    const project = positiveProjectId(projectId);
    try {
      const result = project === null
        ? await db.execute({
          sql: `SELECT uuid FROM service_connections
                WHERE service_id = ? AND status = 'active' AND uuid <> ?
                ORDER BY id`,
          args: [serviceId, String(rowUuid)],
        })
        : await db.execute({
          sql: `SELECT uuid FROM service_connections
                WHERE service_id = ? AND status = 'active' AND uuid <> ? AND project_id = ?
                ORDER BY id`,
          args: [serviceId, String(rowUuid), project],
        });
      return result && Array.isArray(result.rows) ? result.rows : [];
    } catch {
      return [];
    }
  }

  /**
   * The sealed Stock prices token of the connection that is being let go, copied onto the row that
   * replaces it, and only then returned so the engine can be handed it after the swap.
   *
   * The copy happens while the old connection still stands, because that is the only moment its
   * sealed row can be read. Only a row of `projectId` — the new connection's own project — is read:
   * a token sealed on a connection of another project stays where it was pasted, and every other
   * active row of the service is let go below without its token being carried.
   *
   * A read that cannot open the keychain, and a copy that cannot be sealed, both answer null: the
   * token is then simply pasted again, and the connection itself is unaffected. The value never
   * leaves this function towards an answer, an audit payload or a log line.
   *
   * `projectId` is the carry's whole scope, so a value that is not a positive integer (a string,
   * null, undefined, 0, a negative, NaN) carries nothing and reads nothing at all: without a
   * project there is no row this copy is allowed to come from.
   */
  async function carrySealedTiingo(rowUuid, projectId) {
    if (!Number.isInteger(projectId) || projectId <= 0) return null;
    let rows = [];
    try {
      rows = await otherActiveRows(rowUuid, projectId);
    } catch {
      return null;
    }
    for (const row of rows) {
      let token = null;
      try {
        token = await tiingoStore.read(row.uuid);
      } catch {
        token = null;
      }
      if (typeof token !== "string" || token === "") continue;
      try {
        await tiingoStore.save(rowUuid, token);
      } catch {
        return null;
      }
      return token;
    }
    return null;
  }

  /**
   * Hand a carried token to the engine with the new connection's own client. Best effort: a token
   * the engine never answered for stays sealed on the row, so the next successful re-push sends it
   * again, and nothing about the Connect answer depends on this call.
   */
  async function pushCarriedTiingo(token) {
    if (typeof token !== "string" || token === "") return;
    try {
      const client = await buildClient();
      if (client && typeof client.setTiingo === "function") await client.setTiingo({ token });
    } catch {
      // The sealed copy is what the next re-push sends; this attempt is not the answer.
    }
  }

  /**
   * Every other active connection of this service goes, whatever made it.
   *
   * One active connection per service is the rule, and a row this request never heard of — left
   * by an earlier connection — cannot stand beside the one just made. Each row is disconnected
   * (kept, never deleted, so its masked secrets and history stay); one that will not go is left
   * for the next pass rather than failing the connect.
   */
  async function disconnectOtherActiveRows(rowUuid) {
    const rows = await otherActiveRows(rowUuid);
    if (rows.length === 0) return;
    let disconnectConnection;
    try {
      ({ disconnectConnection } = await services());
    } catch {
      return;
    }
    for (const row of rows) {
      try {
        await disconnectConnection(db, row.uuid, { actor: "local" });
      } catch {
        // The new connection is the live one; a row that will not go is left for the next pass.
      }
    }
  }

  /**
   * The connection stands: keep the epoch and the two fingerprints on the row, carry a sealed Stock
   * prices token over from the connection this one replaces, let go of every other active row of
   * this service (the one this Connect replaces, and any stale one), hand the engine the carried
   * token, tell the panel, and file the one audit row that says it worked. Also the end of a settled
   * `pending_pin`: the config is rewritten whole, so the flag is gone.
   */
  async function finishConnect(res, { projectId, rowUuid, data, probeData, previous }) {
    const pushedData = isPlainObject(data) ? data : {};
    const probe = isPlainObject(probeData) ? probeData : {};
    const before = isPlainObject(previous) ? previous : {};

    const keyLast4 = last4(pushedData.key_last4) ?? last4(probe.key_last4) ?? (before.key_last4 ?? null);
    const portfolioLast4 =
      last4(pushedData.portfolio_last4) ?? last4(probe.portfolio_last4) ?? (before.portfolio_last4 ?? null);
    const engineEpoch = pushedData.engine_epoch === undefined || pushedData.engine_epoch === null
      ? (before.engine_epoch ?? null)
      : String(pushedData.engine_epoch);

    try {
      await writeConfig(db, rowUuid, {
        engine_epoch: engineEpoch,
        key_last4: keyLast4,
        portfolio_last4: portfolioLast4,
      });
    } catch {
      // The connection stands; the panel reads what it can.
    }

    // The token lived on the connection that is about to go, so it is read and copied while that
    // row still stands, before anything is disconnected.
    const carriedToken = await carrySealedTiingo(rowUuid, projectId);

    await disconnectOtherActiveRows(rowUuid);

    // The new connection stands: the engine gets the carried token with the new client's own MAC.
    await pushCarriedTiingo(carriedToken);

    try {
      await onConnected({ projectId, connectionUuid: rowUuid });
    } catch {
      // A listener that fails changes nothing about the connection.
    }

    await writeAudit(projectId, ACTION_CONNECT, rowUuid, {
      ok: true,
      key_last4: keyLast4,
      portfolio_last4: portfolioLast4,
    });
    return res.json({
      ok: true,
      message: CONNECTED_PREFIX + (portfolioLast4 === null ? "" : portfolioLast4),
      key_last4: keyLast4,
      portfolio_last4: portfolioLast4,
      project_id: projectId,
    });
  }

  async function rollbackRow(uuid) {
    const { rollbackNewConnection } = await services();
    await rollbackNewConnection(db, uuid);
  }

  async function handleConnect(req, res) {
    if (!isPlainObject(req.body)) {
      return refuse(res, ACTION_CONNECT, await boundProjectId(), 400, CODE_BAD_REQUEST, MESSAGE_BAD_BODY);
    }
    const keyName = cleanPastedValue(req.body.key_name);
    const privateKey = cleanPastedValue(req.body.private_key);
    if (!keyName || !privateKey) {
      return refuse(res, ACTION_CONNECT, await boundProjectId(), 400, CODE_BAD_REQUEST, fixit("KEY_INVALID"));
    }

    const askedProjectId = positiveProjectId(req.body.project_id);

    let existing = await readActiveRow(db, serviceId);
    let existingConfig = existing ? parseConfig(existing.config) : {};
    const existingProjectId = existing ? Number(existing.project_id) : null;

    if (existing && askedProjectId !== null && askedProjectId !== existingProjectId) {
      return refuse(
        res, ACTION_CONNECT, existingProjectId, 409, CODE_PROJECT_LOCKED, MESSAGE_PROJECT_LOCKED, existing.uuid,
      );
    }

    let projectId = existing ? existingProjectId : askedProjectId;
    if (projectId === null) {
      return refuse(res, ACTION_CONNECT, null, 400, CODE_BAD_REQUEST, MESSAGE_PICK_PROJECT);
    }

    try {
      const { assertLocalCapability } = await acl();
      // This only confirms the project exists and is not archived. The real gate is the local
      // dashboard session plus 2FA above (plus a fresh code for this route).
      await assertLocalCapability(db, projectId, "read_sources");
    } catch {
      return refuse(res, ACTION_CONNECT, projectId, 404, CODE_PROJECT_NOT_FOUND, MESSAGE_PROJECT_NOT_FOUND);
    }

    const client = await buildClient();
    if (!client) return refuseUnreachable(res, ACTION_CONNECT, projectId, existing ? existing.uuid : null);

    const health = await client.health();
    if (!health || !health.ok) {
      return refuseUnreachable(res, ACTION_CONNECT, projectId, existing ? existing.uuid : null);
    }
    const healthData = isPlainObject(health.data) ? health.data : {};
    // A pin that matches no connection here is the only case that earns the "ask for help" copy.
    const foreignPin = () => !existing && healthData.pinned !== false;

    // A push whose answer was lost left this row here. The engine's own health says what happened
    // to it: a pin to settle with the sealed secret, or a key the engine never took.
    if (existing && existingConfig.pending_pin === true) {
      if (healthData.pinned === true) {
        const settled = await connection.repushUnlocked();
        if (!settled || !settled.ok) {
          if (settled && settled.code === "SECRET_MISMATCH") {
            // The engine holds a pin this install never made: the pending row can never be
            // settled with it, so it goes (with its sealed values) instead of standing there.
            try {
              await rollbackRow(existing.uuid);
            } catch {
              // The refusal is the answer either way; the row never reaches the panel.
            }
            return refuseEngine(res, ACTION_CONNECT, projectId, existing.uuid, settled, { foreignPin: true });
          }
          return refuseEngine(res, ACTION_CONNECT, projectId, existing.uuid, settled);
        }
        return finishConnect(res, {
          projectId,
          rowUuid: existing.uuid,
          data: settled.data,
          previous: existingConfig,
        });
      }
      try {
        await rollbackRow(existing.uuid);
      } catch {
        return refuse(res, ACTION_CONNECT, projectId, 500, CODE_FAILED, MESSAGE_GENERIC, existing.uuid);
      }
      existing = null;
      existingConfig = {};
    }

    // A standing connection is only reconnected when the panel flagged it, or when the engine has
    // plainly lost its pin while this row still remembers an install it made.
    const reconnect = Boolean(existing) && (
      existingConfig.needs_reconnect === true ||
      (healthData.pinned === false && Boolean(existingConfig.engine_epoch))
    );

    if (existing && !reconnect) {
      return refuse(
        res, ACTION_CONNECT, projectId, 409, CODE_ALREADY_CONNECTED, MESSAGE_ALREADY_CONNECTED, existing.uuid,
      );
    }

    const keyKind = healthData.pinned === false ? "install" : "owner";

    const probe = await client.checkCredentials({ key_name: keyName, private_key: privateKey }, { keyKind });
    if (!probe || !probe.ok) {
      return refuseEngine(res, ACTION_CONNECT, projectId, null, probe, { foreignPin: foreignPin() });
    }
    const probeData = isPlainObject(probe.data) ? probe.data : {};
    if (probeData.state && probeData.state !== CODE_OK) {
      return refuseEngine(
        res, ACTION_CONNECT, projectId, null, { code: probeData.code || "KEY_INVALID" }, { foreignPin: foreignPin() },
      );
    }

    const secret = randomBytes(APPROVE_SECRET_BYTES).toString("base64url");

    let created;
    try {
      created = await createConnectionRow({ projectId, keyName, privateKey, secret });
    } catch (err) {
      const failure = err && typeof err.code === "string" ? err.code : "";
      if (failure === "unknown_project") {
        return refuse(res, ACTION_CONNECT, projectId, 404, CODE_PROJECT_NOT_FOUND, MESSAGE_PROJECT_NOT_FOUND);
      }
      if (failure === "label_taken") {
        return refuse(res, ACTION_CONNECT, projectId, 409, CODE_LABEL_TAKEN, MESSAGE_GENERIC);
      }
      return refuse(res, ACTION_CONNECT, projectId, 500, CODE_FAILED, MESSAGE_GENERIC);
    }

    const pushed = await client.pushCredentials(
      { key_name: keyName, private_key: privateKey, approve_secret: secret },
      { keyKind },
    );

    if (pushed && pushed.ok) {
      return finishConnect(res, {
        projectId,
        rowUuid: created.uuid,
        data: pushed.data,
        probeData,
      });
    }

    if (!isDefiniteRefusal(pushed) && isUncertainFailure(pushed)) {
      // The engine may have kept the key: the row stays, marked, until the engine says which.
      try {
        await writeConfig(db, created.uuid, { pending_pin: true });
      } catch {
        // The health read below still settles it; the flag only matters if this request dies.
      }

      const after = await client.health();
      if (!after || !after.ok) {
        return refuse(
          res, ACTION_CONNECT, projectId, 503, CODE_ENGINE_UNREACHABLE, MESSAGE_ENGINE_NOT_ANSWERING, created.uuid,
        );
      }
      const afterData = isPlainObject(after.data) ? after.data : {};

      if (afterData.pinned === true) {
        // It pinned what it was given; the same sealed secret takes the pin back into our hands.
        const settled = await connection.repushUnlocked();
        if (!settled || !settled.ok) {
          return refuseEngine(res, ACTION_CONNECT, projectId, created.uuid, settled);
        }
        return finishConnect(res, {
          projectId,
          rowUuid: created.uuid,
          data: settled.data,
          probeData,
          previous: { pending_pin: true },
        });
      }

      // It never took the key, so the half-made connection goes.
      try {
        await rollbackRow(created.uuid);
      } catch {
        return refuse(res, ACTION_CONNECT, projectId, 500, CODE_FAILED, MESSAGE_GENERIC, created.uuid);
      }
      return refuseEngine(res, ACTION_CONNECT, projectId, null, { status: 0, code: "ENGINE_UNREACHABLE" });
    }

    try {
      await rollbackRow(created.uuid);
    } catch {
      // The refusal is the answer either way; the row never reaches the panel.
    }
    return refuseEngine(res, ACTION_CONNECT, projectId, created.uuid, pushed, { foreignPin: foreignPin() });
  }

  // ---- POST /api/coinbase/disconnect --------------------------------------------------------------

  /**
   * Mark the row as a Disconnect in flight. The boot loops read this flag and leave an unpinned
   * engine alone: a pin that went away because the owner asked is not an engine reset.
   * @returns {Promise<boolean>} whether the flag is now written
   */
  async function setDisconnecting(uuid, value) {
    try {
      const row = await readActiveRow(db, serviceId);
      if (!row || row.uuid !== uuid) return true;
      const stored = parseConfig(row.config);
      if (value) stored.disconnecting = true;
      else delete stored.disconnecting;
      await writeConfig(db, uuid, stored);
      return true;
    } catch {
      return false;
    }
  }

  /** Drop the row and its sealed secrets: the engine holds nothing worth forgetting. */
  async function dropConnection(res, projectId, uuid) {
    // The Stock prices token lived on this connection, so the engine's copy goes first: once the
    // sealed secrets are dropped there is no owner secret left to sign the forget with. Best effort
    // only — a token the engine keeps reads public prices and can do nothing else.
    try {
      const client = await buildClient();
      if (client && typeof client.clearTiingo === "function") await client.clearTiingo();
    } catch {
      // The Disconnect stands whatever the engine answered for its stock prices token.
    }
    try {
      const { disconnectConnection } = await services();
      await disconnectConnection(db, uuid, { actor: "local" });
    } catch {
      return refuse(res, ACTION_DISCONNECT, projectId, 500, CODE_FAILED, MESSAGE_GENERIC, uuid);
    }
    try {
      await onDisconnected({ projectId, connectionUuid: uuid });
    } catch {
      // A listener that fails changes nothing about the Disconnect.
    }
    await writeAudit(projectId, ACTION_DISCONNECT, uuid, { ok: true });
    return res.json({ ok: true, message: MESSAGE_DISCONNECTED });
  }

  async function handleDisconnect(req, res) {
    if (!isPlainObject(req.body)) {
      return refuse(res, ACTION_DISCONNECT, await boundProjectId(), 400, CODE_BAD_REQUEST, MESSAGE_BAD_BODY);
    }

    const existing = await readActiveRow(db, serviceId);
    if (!existing) {
      return refuse(res, ACTION_DISCONNECT, null, 404, CODE_NOT_CONNECTED, MESSAGE_NOT_CONNECTED);
    }
    const projectId = Number(existing.project_id);

    const client = await buildClient();
    if (!client) return refuseUnreachable(res, ACTION_DISCONNECT, projectId, existing.uuid);

    // What the engine holds decides the whole path: nothing to forget is a plain drop, a key it
    // lost to a restart has to be pushed back before it can be told to forget the pin.
    const health = await client.health();
    if (!health || !health.ok) return refuseUnreachable(res, ACTION_DISCONNECT, projectId, existing.uuid);
    const healthData = isPlainObject(health.data) ? health.data : {};

    if (healthData.pinned === false) return dropConnection(res, projectId, existing.uuid);

    if (healthData.credentials === "not_ready") {
      const repushed = await connection.repushUnlocked();
      if (!repushed || !repushed.ok) {
        return refuseEngine(res, ACTION_DISCONNECT, projectId, existing.uuid, repushed);
      }
    }

    // From here the engine's pin may go away before this request finishes; the flag says so.
    if (!(await setDisconnecting(existing.uuid, true))) {
      return refuse(res, ACTION_DISCONNECT, projectId, 500, CODE_FAILED, MESSAGE_GENERIC, existing.uuid);
    }

    const forgotten = await client.forgetCredentials();
    if (!forgotten || !forgotten.ok) {
      const raw = forgotten && typeof forgotten.code === "string" && forgotten.code
        ? forgotten.code
        : "ENGINE_UNREACHABLE";
      const status = forgotten && Number.isFinite(forgotten.status) ? forgotten.status : 0;

      if (raw === "LIVE_ORDERS_OPEN") {
        await setDisconnecting(existing.uuid, false);
        return refuse(res, ACTION_DISCONNECT, projectId, 409, CODE_LIVE_ORDERS, MESSAGE_LIVE_ORDERS, existing.uuid);
      }
      if (raw === "LIVE_BOTS") {
        await setDisconnecting(existing.uuid, false);
        return refuse(res, ACTION_DISCONNECT, projectId, 409, CODE_LIVE_BOTS, MESSAGE_LIVE_BOTS, existing.uuid);
      }
      if (raw === "ENGINE_UNREACHABLE" || status === 0 || status >= 500) {
        // The engine may have forgotten the pin and lost the answer: the flag stays, so a retry
        // finishes it and the loops do not read the missing pin as a reset.
        return refuseUnreachable(res, ACTION_DISCONNECT, projectId, existing.uuid);
      }
      await setDisconnecting(existing.uuid, false);
      return refuseEngine(res, ACTION_DISCONNECT, projectId, existing.uuid, forgotten);
    }

    return dropConnection(res, projectId, existing.uuid);
  }

  // ---- the Stock prices (Tiingo) routes -----------------------------------------------------------

  /** The standing Coinbase connection, or null: the sealed token lives on it and nowhere else. */
  async function tiingoConnection() {
    try {
      return await readActiveRow(db, serviceId);
    } catch {
      return null;
    }
  }

  /**
   * The pasted token, asked of the engine once.
   *
   * The engine's own refusal keeps its own code and its own fixed sentence; a shape it refuses is
   * `TOKEN_SHAPE`, a token it will not take is `TOKEN_REJECTED`, and so on. Everything else — no
   * client, an engine that did not answer, a client that cannot sign — is the engine unreachable.
   * The token is in the request body only, and the client redacts it out of whatever came back.
   */
  async function checkTiingoToken(token) {
    const client = await buildClient();
    if (!client || typeof client.checkTiingo !== "function") {
      return { ok: false, status: 503, code: CODE_ENGINE_UNREACHABLE, message: MESSAGE_ENGINE_UNREACHABLE };
    }
    const result = await client.checkTiingo({ token });
    if (!result || !result.ok) {
      return { ok: false, status: 503, code: CODE_ENGINE_UNREACHABLE, message: MESSAGE_ENGINE_UNREACHABLE };
    }
    const data = isPlainObject(result.data) ? result.data : {};
    if (data.state === CODE_OK) return { ok: true };
    const code = typeof data.code === "string" && data.code ? data.code : CODE_ENGINE_UNREACHABLE;
    const message = typeof data.message === "string" && data.message ? data.message : MESSAGE_GENERIC;
    return { ok: false, status: 422, code, message };
  }

  /** What the engine says about the token it holds, or "missing" when it cannot be asked. */
  async function pricesState() {
    try {
      const client = await buildClient();
      if (!client || typeof client.status !== "function") return "missing";
      const result = await client.status();
      const data = result && result.ok ? result.data : null;
      const equity = isPlainObject(data) ? data.equity : null;
      const reported = isPlainObject(equity) ? equity.prices : null;
      if (
        reported === "connected" ||
        reported === "rejected" ||
        reported === "paused" ||
        reported === "missing"
      ) {
        return reported;
      }
      return "missing";
    } catch {
      return "missing";
    }
  }

  async function handleTiingoTest(req, res) {
    const token = cleanTiingoToken(isPlainObject(req.body) ? req.body.token : null);
    if (!token) {
      return refuse(res, ACTION_TIINGO_TEST, await boundProjectId(), 400, CODE_BAD_REQUEST, MESSAGE_PASTE_TIINGO);
    }
    const row = await tiingoConnection();
    if (!row) {
      return refuse(res, ACTION_TIINGO_TEST, null, 409, CODE_NOT_CONNECTED, MESSAGE_CONNECT_COINBASE_FIRST);
    }
    const checked = await checkTiingoToken(token);
    if (!checked.ok) {
      await writeAudit(Number(row.project_id), ACTION_TIINGO_TEST, row.uuid, { ok: false, code: checked.code });
      return answerRefusal(res, checked.status, checked.code, checked.message);
    }
    return res.json({ ok: true, message: MESSAGE_TIINGO_ACCEPTED });
  }

  async function handleTiingoSave(req, res) {
    const token = cleanTiingoToken(isPlainObject(req.body) ? req.body.token : null);
    if (!token) {
      return refuse(res, ACTION_TIINGO_CONNECT, await boundProjectId(), 400, CODE_BAD_REQUEST, MESSAGE_PASTE_TIINGO);
    }
    const row = await tiingoConnection();
    if (!row) {
      return refuse(res, ACTION_TIINGO_CONNECT, null, 409, CODE_NOT_CONNECTED, MESSAGE_CONNECT_COINBASE_FIRST);
    }
    const projectId = Number(row.project_id);

    // Nothing is sealed behind a token the engine has not just accepted.
    const checked = await checkTiingoToken(token);
    if (!checked.ok) {
      await writeAudit(projectId, ACTION_TIINGO_CONNECT, row.uuid, { ok: false, code: checked.code });
      return answerRefusal(res, checked.status, checked.code, checked.message);
    }

    try {
      await tiingoStore.save(row.uuid, token);
    } catch {
      return refuse(res, ACTION_TIINGO_CONNECT, projectId, 500, CODE_FAILED, MESSAGE_GENERIC, row.uuid);
    }

    // From here the token is sealed. An engine that is not answering keeps it: the next successful
    // credentials re-push sends it again, so the owner is told it is saved, not lost.
    let pushed = null;
    try {
      const client = await buildClient();
      if (client && typeof client.setTiingo === "function") pushed = await client.setTiingo({ token });
    } catch {
      pushed = null;
    }
    if (pushed && pushed.ok) {
      await writeAudit(projectId, ACTION_TIINGO_CONNECT, row.uuid, { ok: true });
      return res.json({ ok: true, message: MESSAGE_TIINGO_SAVED });
    }
    const reason = pushed && typeof pushed.code === "string" && pushed.code ? pushed.code : CODE_ENGINE_UNREACHABLE;
    await writeAudit(projectId, ACTION_TIINGO_CONNECT, row.uuid, { ok: true, code: reason });
    return res.json({ ok: true, pending: true, message: MESSAGE_TIINGO_PENDING });
  }

  async function handleTiingoDisconnect(req, res) {
    const row = await tiingoConnection();
    if (!row) {
      return refuse(res, ACTION_TIINGO_DISCONNECT, null, 409, CODE_NOT_CONNECTED, MESSAGE_CONNECT_COINBASE_FIRST);
    }
    const projectId = Number(row.project_id);
    try {
      await tiingoStore.remove(row.uuid);
    } catch {
      return refuse(res, ACTION_TIINGO_DISCONNECT, projectId, 500, CODE_FAILED, MESSAGE_GENERIC, row.uuid);
    }
    // The sealed row is gone, so the engine's copy goes too. Best effort: an engine that is not
    // answering still loses the token on its next restart, and the owner is told it is disconnected.
    try {
      const client = await buildClient();
      if (client && typeof client.clearTiingo === "function") await client.clearTiingo();
    } catch {
      // The sealed token is gone either way.
    }
    await writeAudit(projectId, ACTION_TIINGO_DISCONNECT, row.uuid, { ok: true });
    return res.json({ ok: true, message: MESSAGE_TIINGO_DISCONNECTED });
  }

  async function handleTiingoState(req, res) {
    let local = false;
    try {
      local = (await isLocalSession(db, req)) === true;
    } catch {
      local = false;
    }
    if (!local) return answerRefusal(res, 403, CODE_LOCAL_LOGIN, MESSAGE_LOCAL_LOGIN);

    const row = await tiingoConnection();
    if (!row) {
      return res.json({ ok: true, connected: false, sealed: false, rejected: false, message: null });
    }

    // Whether the token is sealed here is the keychain's answer; whether the engine took it is the
    // engine's. Neither is repeated: the answer carries four flags and one fixed sentence.
    let sealed = false;
    try {
      sealed = (await tiingoStore.read(row.uuid)) !== null;
    } catch {
      sealed = false;
    }
    const prices = await pricesState();
    const rejected = prices === "rejected";
    // A pause is the token working while the allowance is used up, so it reads as connected: the
    // five keys stay exactly as they are and only the sentence says the prices are waiting.
    const paused = prices === "paused";
    const connected = prices === "connected" || paused;
    const message = rejected
      ? MESSAGE_PRICES_REJECTED
      : paused
        ? MESSAGE_PRICES_PAUSED
        : connected
          ? MESSAGE_PRICES_CONNECTED
          : MESSAGE_PRICES_MISSING;
    return res.json({ ok: true, connected, sealed, rejected, message });
  }

  // ---- GET /api/coinbase/connect/state ------------------------------------------------------------

  async function handleState(req, res) {
    let local = false;
    try {
      local = (await isLocalSession(db, req)) === true;
    } catch {
      local = false;
    }
    if (!local) return answerRefusal(res, 403, CODE_LOCAL_LOGIN, MESSAGE_LOCAL_LOGIN);

    let row = null;
    try {
      row = await readActiveRow(db, serviceId);
    } catch {
      row = null;
    }
    if (!row) {
      return res.json({
        ok: true,
        connected: false,
        project_id: null,
        project_locked: false,
        needs_reconnect: false,
        pending: false,
        disconnect_unfinished: false,
        key_last4: null,
        portfolio_last4: null,
      });
    }

    const stored = parseConfig(row.config);
    const needsReconnect = stored.needs_reconnect === true;
    const pending = stored.pending_pin === true;
    // A Disconnect that never finished: the engine may hold nothing because the owner asked.
    const disconnectUnfinished = stored.disconnecting === true;
    const keyLast4 = last4(stored.key_last4);
    const portfolioLast4 = last4(stored.portfolio_last4);
    const state = {
      ok: true,
      connected: true,
      project_id: Number(row.project_id),
      project_locked: true,
      needs_reconnect: needsReconnect,
      pending,
      disconnect_unfinished: disconnectUnfinished,
      key_last4: keyLast4,
      portfolio_last4: portfolioLast4,
    };
    if (!needsReconnect) {
      state.message = CONNECTED_PREFIX + (portfolioLast4 === null ? "" : portfolioLast4);
    }
    return res.json(state);
  }

  router.post(`${PREFIX}/connect/test`, wrap(ACTION_TEST, handleTest, { needsCode: false }));
  router.post(`${PREFIX}/connect`, wrap(ACTION_CONNECT, handleConnect));
  router.post(`${PREFIX}/disconnect`, wrap(ACTION_DISCONNECT, handleDisconnect));
  // The Stock prices routes: a local password session only, no 2FA switch check and no code (the
  // token reads public prices and can neither spend nor move money). The two writes still pass the
  // CSRF middleware above and still refuse a peer session.
  router.post(
    `${PREFIX}/tiingo/test`,
    wrap(ACTION_TIINGO_TEST, handleTiingoTest, { needsCode: false, needs2fa: false }),
  );
  router.post(
    `${PREFIX}/tiingo`,
    wrap(ACTION_TIINGO_CONNECT, handleTiingoSave, { needsCode: false, needs2fa: false }),
  );
  router.post(
    `${PREFIX}/tiingo/disconnect`,
    wrap(ACTION_TIINGO_DISCONNECT, handleTiingoDisconnect, { needsCode: false, needs2fa: false }),
  );
  router.get(`${PREFIX}/tiingo/state`, (req, res) => {
    handleTiingoState(req, res).catch(() => {
      try {
        answerRefusal(res, 500, CODE_FAILED, MESSAGE_GENERIC);
      } catch {
        // The answer is already gone.
      }
    });
  });
  router.get(`${PREFIX}/connect/state`, (req, res) => {
    handleState(req, res).catch(() => {
      try {
        answerRefusal(res, 500, CODE_FAILED, MESSAGE_GENERIC);
      } catch {
        // The answer is already gone.
      }
    });
  });

  return {
    router,
    connection,
    getStepUpGate,
    // The pieces the panel's own routes borrow: the sealed-key reader the engine client signs
    // with, the one gate every privileged action passes, the audit writer, the client builder and
    // the project this install is bound to. Nothing here hands a secret back.
    secretProvider,
    gates,
    writeAudit,
    buildClient,
    boundProjectId,
  };
}