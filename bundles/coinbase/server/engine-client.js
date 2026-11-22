/**
 * The client Crow's own processes use to reach the Coinbase trading engine.
 *
 * The engine listens on loopback and answers JSON.  Every route but GET /health
 * wants the engine's bearer token; a privileged route (or the lease gate, or an
 * install-key credentials push) also wants the owner's MAC over the request.
 *
 * No method here throws: a failure is a result object `{ok:false, status, code,
 * message}`, with `retryAfterS` on a 429, `fields` when the engine named the
 * body fields it refused, and `halted: true` only when the engine's own body
 * said `halted: true` (trading stopped, but orders may still be resting).  A network failure, a timeout and any other fetch
 * rejection all read the same way (`ENGINE_UNREACHABLE`).
 *
 * A call that cannot be shaped into a safe request is refused before it is sent:
 * an id that does not fit a path segment, a product that is not a trading pair, a
 * book the engine does not have, and a body JSON cannot carry, all answer
 * `INVALID` without a fetch.
 *
 * Redaction is part of the contract: the bearer token, the MAC key of a call,
 * and the key material a credentials body carries are never repeated in a
 * result.  A message that would carry one has it replaced by `[hidden]`.
 */
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { macHeaders } from "./mac.js";

const DEFAULT_BASE_URL = "http://127.0.0.1:3062";
const DEFAULT_TIMEOUT_MS = 10_000;
// Installing the owner's key runs behind the engine's own key check, which waits
// on Coinbase, so that one call gets its own longer bound.
const CREDENTIALS_TIMEOUT_MS = 30_000;
const MAX_MESSAGE_CHARS = 300;
const HIDDEN = "[hidden]";

const UNREACHABLE_CODE = "ENGINE_UNREACHABLE";
const UNREACHABLE_MESSAGE = "The trading engine is not responding";
const AUTH_CODE = "ENGINE_AUTH";
const AUTH_MESSAGE = "The engine did not accept Crow's token";
const NOT_ALLOWED_CODE = "NOT_ALLOWED";
const NOT_ALLOWED_MESSAGE = "This client cannot make that change";
const NOT_CONNECTED_CODE = "NOT_CONNECTED";
const NOT_CONNECTED_MESSAGE = "Trading is not connected";
const RATE_LIMITED_CODE = "RATE_LIMITED";
const DEFAULT_RETRY_AFTER_S = 60;
const GENERIC_ERROR_MESSAGE = "The trading engine could not complete that request";
const INVALID_CODE = "INVALID";
const INVALID_ID_MESSAGE = "That id is not valid";
const INVALID_BODY_MESSAGE = "That request body cannot be sent";

const ENGINE_TOKEN_NAME = "CROW_COINBASE_ENGINE_TOKEN";
const ENGINE_ENV_PARTS = ["bundles", "coinbase", ".env"];
const INSTALL_TOKEN_PARTS = ["coinbase", "install", "install_token"];
const ENGINE_TOKEN_MISSING = "Coinbase engine token not found";
const INSTALL_TOKEN_MISSING = "Coinbase install token not found";

const DETAIL_CODE_RE = /^([A-Z][A-Z0-9_]+)(.*)$/;
// What the engine accepts as a bot id, a preview id or a client order id.  An id
// outside this shape is refused here instead of being pasted into a path.
const PATH_ID_RE = /^[A-Za-z0-9._:-]+$/;
// What the engine accepts as a product on GET /price.  A product outside this shape
// is refused here instead of being sent as a price query.
const PRODUCT_RE = /^[A-Z0-9]+-[A-Z0-9]+$/;

/** The conventional Crow home, or the one CROW_HOME names. */
export function crowHomeDefault() {
  const named = process.env.CROW_HOME;
  return named ? named : join(homedir(), ".crow");
}

/** KEY=VALUE lines, with a leading `export` and one pair of surrounding quotes allowed. */
function parseEnvFile(text) {
  const values = {};
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const body = line.startsWith("export ") ? line.slice("export ".length).trim() : line;
    const equals = body.indexOf("=");
    if (equals <= 0) continue;
    const name = body.slice(0, equals).trim();
    let value = body.slice(equals + 1).trim();
    const quoted =
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")));
    if (quoted) value = value.slice(1, -1);
    values[name] = value;
  }
  return values;
}

/** The engine's bearer token from the installed bundle's `.env`. */
export function readEngineToken(crowHome = crowHomeDefault()) {
  const path = join(crowHome, ...ENGINE_ENV_PARTS);
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new Error(ENGINE_TOKEN_MISSING);
  }
  const token = parseEnvFile(text)[ENGINE_TOKEN_NAME];
  if (typeof token !== "string" || token.length === 0) {
    throw new Error(ENGINE_TOKEN_MISSING);
  }
  return token;
}

/** The install token the installer publishes at <CROW_HOME>/coinbase/install/install_token. */
export function readInstallToken(crowHome = crowHomeDefault()) {
  const path = join(crowHome, ...INSTALL_TOKEN_PARTS);
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new Error(INSTALL_TOKEN_MISSING);
  }
  const token = String(text).trim();
  if (token.length === 0) {
    throw new Error(INSTALL_TOKEN_MISSING);
  }
  return token;
}

/** Replace every secret a call knows about with the placeholder. */
function redactText(value, secrets) {
  let out = typeof value === "string" ? value : String(value === undefined || value === null ? "" : value);
  for (const secret of secrets) {
    if (typeof secret !== "string" || secret.length === 0) continue;
    if (out.includes(secret)) out = out.split(secret).join(HIDDEN);
  }
  return out;
}

/** The same replacement through every string of a value. */
function redactValue(value, secrets) {
  if (secrets.length === 0) return value;
  if (typeof value === "string") return redactText(value, secrets);
  if (Array.isArray(value)) return value.map((item) => redactValue(item, secrets));
  if (value && typeof value === "object") {
    const out = {};
    for (const [name, item] of Object.entries(value)) out[name] = redactValue(item, secrets);
    return out;
  }
  return value;
}

function clampMessage(text) {
  const text_ = typeof text === "string" ? text : String(text ?? "");
  return text_.length > MAX_MESSAGE_CHARS ? text_.slice(0, MAX_MESSAGE_CHARS) : text_;
}

/** One refusal result, with every known secret kept out of it. */
function failureResult(secrets, { status, code, message, fields, retryAfterS, halted }) {
  const out = {
    ok: false,
    status,
    code: redactText(code, secrets),
    message: clampMessage(redactText(message, secrets)),
  };
  if (retryAfterS !== undefined) out.retryAfterS = retryAfterS;
  if (fields !== undefined) out.fields = fields.map((field) => redactText(field, secrets));
  // A failure body may say trading DID stop while orders could still be resting.
  // Only a body that says so keeps the flag; every other failure carries none.
  if (halted === true) out.halted = true;
  return out;
}

function notAllowed() {
  return { ok: false, status: 0, code: NOT_ALLOWED_CODE, message: NOT_ALLOWED_MESSAGE };
}

function notConnected() {
  return { ok: false, status: 0, code: NOT_CONNECTED_CODE, message: NOT_CONNECTED_MESSAGE };
}

function invalidId() {
  return { ok: false, status: 0, code: INVALID_CODE, message: INVALID_ID_MESSAGE };
}

/** Whether a value may be pasted into a path segment of a route. */
function idInPath(value) {
  const text = typeof value === "string" ? value : String(value === undefined || value === null ? "" : value);
  if (text === "." || text === "..") return false;
  return PATH_ID_RE.test(text);
}

/** A header off a Headers object or a plain object, case-insensitively. */
function headerValue(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === "function") {
    const found = headers.get(name);
    if (found !== undefined && found !== null) return String(found);
  }
  const wanted = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== wanted) continue;
    const found = headers[key];
    if (found !== undefined && found !== null) return String(found);
  }
  return null;
}

/** Retry-After as whole seconds, or the default when absent or unreadable. */
function retryAfterSeconds(header) {
  if (header === null || header === undefined) return DEFAULT_RETRY_AFTER_S;
  const parsed = Number.parseInt(String(header).trim(), 10);
  if (!Number.isFinite(parsed) || parsed < 0) return DEFAULT_RETRY_AFTER_S;
  return parsed;
}

/** The refusal body of the engine, in either of its shapes. */
function errorShape(status, payload, retryAfterHeader) {
  if (status === 401) return { status, code: AUTH_CODE, message: AUTH_MESSAGE };
  const body =
    payload && typeof payload === "object" && !Array.isArray(payload) ? payload : null;
  const bodyCode = body && typeof body.code === "string" && body.code ? body.code : null;
  const bodyMessage = body && typeof body.message === "string" && body.message ? body.message : null;
  const detail = body && typeof body.detail === "string" ? body.detail.trim() : null;

  let detailCode = null;
  let detailMessage = null;
  if (detail) {
    const match = DETAIL_CODE_RE.exec(detail);
    if (match) {
      detailCode = match[1];
      const rest = match[2].trim();
      detailMessage = rest.startsWith(":") ? rest.slice(1).trim() || detail : rest || detail;
    } else {
      detailMessage = detail;
    }
  }

  const code =
    status === 429
      ? bodyCode || detailCode || RATE_LIMITED_CODE
      : bodyCode || detailCode || `HTTP_${status}`;
  const message = bodyMessage || detailMessage || GENERIC_ERROR_MESSAGE;
  const shape = { status, code, message };
  if (status === 429) shape.retryAfterS = retryAfterSeconds(retryAfterHeader);
  if (body && Array.isArray(body.fields)) shape.fields = body.fields.map((field) => String(field));
  if (body && body.halted === true) shape.halted = true;
  return shape;
}

/**
 * A client over one engine.
 *
 * `secretProvider` is asked for a key by kind when a call needs one; a client
 * without one can still make every bearer-only call.  `source` is sent as
 * `X-Crow-Source` on every call when it is set.  `now` answers epoch
 * milliseconds and dates the MAC's stamp.
 */
export function createEngineClient(options = {}) {
  const config = options || {};
  const baseUrl = typeof config.baseUrl === "string" && config.baseUrl ? config.baseUrl : DEFAULT_BASE_URL;
  const base = baseUrl.replace(/\/+$/, "");
  const token = typeof config.token === "string" ? config.token : "";
  const secretProvider = typeof config.secretProvider === "function" ? config.secretProvider : null;
  const fetchImpl = typeof config.fetchImpl === "function" ? config.fetchImpl : fetch;
  const timeoutMs = Number.isFinite(config.timeoutMs) ? config.timeoutMs : DEFAULT_TIMEOUT_MS;
  const source = typeof config.source === "string" && config.source ? config.source : null;
  const now = typeof config.now === "function" ? config.now : Date.now;
  const baseSecrets = token ? [token] : [];

  async function providerKey(kind) {
    if (!secretProvider) return null;
    try {
      const value = await secretProvider(kind);
      return typeof value === "string" && value.length > 0 ? value : null;
    } catch {
      return null;
    }
  }

  async function send(spec) {
    const {
      method = "GET",
      pathWithQuery,
      hasBody = false,
      body,
      auth = true,
      macKey = null,
      extraSecrets = [],
      bodyIsAnswer = false,
      timeoutMs: timeoutOverride,
    } = spec;

    const secrets = [...baseSecrets];
    if (typeof macKey === "string" && macKey.length > 0) secrets.push(macKey);
    for (const secret of extraSecrets) {
      if (typeof secret === "string" && secret.length > 0) secrets.push(secret);
    }

    const verb = String(method).toUpperCase();
    let text = "";
    if (hasBody) {
      try {
        const built = JSON.stringify(body === undefined ? null : body);
        if (typeof built !== "string") throw new Error("the body has no JSON form");
        text = built;
      } catch {
        // A body JSON cannot carry (a cycle, a bigint) never reaches the engine.
        return failureResult(secrets, {
          status: 0,
          code: INVALID_CODE,
          message: INVALID_BODY_MESSAGE,
        });
      }
    }

    const headers = {};
    if (auth) headers.Authorization = `Bearer ${token}`;
    if (hasBody) headers["Content-Type"] = "application/json";
    if (source) headers["X-Crow-Source"] = source;
    if (typeof macKey === "string" && macKey.length > 0) {
      Object.assign(headers, macHeaders({ key: macKey, method: verb, pathWithQuery, body: text, now }));
    }

    const init = { method: verb, headers };
    if (hasBody) init.body = text;

    let response;
    let raw = "";
    let preParsed;
    let preParsedOk = false;
    const waitMs = Number.isFinite(timeoutOverride) ? timeoutOverride : timeoutMs;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(0, waitMs));
    try {
      response = await fetchImpl(base + pathWithQuery, { ...init, signal: controller.signal });
      if (response && typeof response.text === "function") {
        raw = String(await response.text());
      } else if (response && typeof response.json === "function") {
        preParsed = await response.json();
        preParsedOk = true;
      }
    } catch {
      return failureResult(secrets, {
        status: 0,
        code: UNREACHABLE_CODE,
        message: UNREACHABLE_MESSAGE,
      });
    } finally {
      clearTimeout(timer);
    }

    const status = response && Number.isInteger(response.status) ? response.status : null;
    if (status === null) {
      // An answer with no status is not an answer: fail closed.
      return failureResult(secrets, {
        status: 0,
        code: UNREACHABLE_CODE,
        message: UNREACHABLE_MESSAGE,
      });
    }
    const ok =
      response && typeof response.ok === "boolean" ? response.ok : status >= 200 && status < 300;

    let payload = preParsed;
    let parsed = preParsedOk;
    if (!parsed && raw.length > 0) {
      try {
        payload = JSON.parse(raw);
        parsed = true;
      } catch {
        payload = null;
        parsed = false;
      }
    }

    const bodyObject =
      parsed && payload && typeof payload === "object" && !Array.isArray(payload) ? payload : null;

    if (ok) {
      return { ok: true, data: redactValue(payload === undefined ? null : payload, secrets) };
    }
    if (bodyIsAnswer && status === 503 && bodyObject && typeof bodyObject.ok === "boolean") {
      // Some routes answer a question about the engine itself even when the
      // answer is "not well": the body is the report, not a refusal.
      return { ok: true, data: redactValue(bodyObject, secrets) };
    }
    return failureResult(secrets, errorShape(status, parsed ? payload : null, headerValue(response && response.headers, "retry-after")));
  }

  function get(pathWithQuery) {
    return send({ method: "GET", pathWithQuery, auth: true });
  }

  function post(pathWithQuery, body, hasBody = true) {
    return send({ method: "POST", pathWithQuery, hasBody, body, auth: true });
  }

  async function privileged(method, pathWithQuery, body, hasBody = true) {
    if (!secretProvider) return notAllowed();
    const key = await providerKey("owner");
    if (!key) return notConnected();
    return send({ method, pathWithQuery, hasBody, body, auth: true, macKey: key });
  }

  async function gated(method, pathWithQuery, body, keyKind, extraSecrets = []) {
    if (!secretProvider) return notAllowed();
    const key = await providerKey(keyKind);
    if (!key) return notConnected();
    return send({
      method,
      pathWithQuery,
      hasBody: true,
      body,
      auth: true,
      macKey: key,
      extraSecrets,
    });
  }

  async function signedIfConnected(method, pathWithQuery, body) {
    const key = secretProvider ? await providerKey("owner") : null;
    return send({ method, pathWithQuery, hasBody: true, body, auth: true, macKey: key });
  }

  const client = {
    // ---- bearer only
    health() {
      return send({ method: "GET", pathWithQuery: "/health", auth: false, bodyIsAnswer: true });
    },
    status() {
      return get("/status");
    },
    events(params = {}) {
      const after = params && params.after !== undefined ? params.after : 0;
      const limit = params ? params.limit : undefined;
      const parts = [`after=${encodeURIComponent(String(after))}`];
      if (limit !== undefined && limit !== null) parts.push(`limit=${encodeURIComponent(String(limit))}`);
      return get(`/events?${parts.join("&")}`);
    },
    balances() {
      return get("/balances");
    },
    /**
     * The engine's own current price for one trading pair. `product` is a pair such as
     * "BTC-USDC"; anything else is refused before the engine sees it.
     */
    getPrice(product) {
      if (typeof product !== "string" || !PRODUCT_RE.test(product)) return invalidId();
      return get(`/price?product=${encodeURIComponent(product)}`);
    },
    caps() {
      return get("/caps");
    },
    bots() {
      return get("/bots");
    },
    botFills(botId) {
      if (!idInPath(botId)) return invalidId();
      return get(`/bots/${encodeURIComponent(String(botId))}/fills`);
    },
    pnl() {
      return get("/pnl");
    },
    /**
     * The orders resting on the engine, per book. `params.book` is "dry" or "live";
     * left out, the engine answers every book. The book is checked here, so a name
     * the engine does not have never reaches it.
     */
    orders(params = {}) {
      const book = params ? params.book : undefined;
      if (book !== undefined && book !== null && book !== "dry" && book !== "live") {
        return {
          ok: false,
          status: 0,
          code: INVALID_CODE,
          message: INVALID_BODY_MESSAGE,
        };
      }
      const suffix = book === undefined || book === null ? "" : `?book=${book}`;
      return get(`/orders${suffix}`);
    },
    aiPreviews(params = {}) {
      const state = params ? params.state : undefined;
      const suffix =
        state === undefined || state === null || state === ""
          ? ""
          : `?state=${encodeURIComponent(String(state))}`;
      return get(`/ai/previews${suffix}`);
    },
    createBot(body) {
      return post("/bots", body);
    },
    botPause(id) {
      if (!idInPath(id)) return invalidId();
      return send({ method: "POST", pathWithQuery: `/bots/${encodeURIComponent(String(id))}/pause`, auth: true });
    },
    botStop(id) {
      if (!idInPath(id)) return invalidId();
      return send({ method: "POST", pathWithQuery: `/bots/${encodeURIComponent(String(id))}/stop`, auth: true });
    },
    kill() {
      return send({ method: "POST", pathWithQuery: "/kill", auth: true });
    },
    aiPreview(body) {
      return post("/ai/previews", body);
    },
    aiReject(id) {
      if (!idInPath(id)) return invalidId();
      return send({
        method: "POST",
        pathWithQuery: `/ai/previews/${encodeURIComponent(String(id))}/reject`,
        auth: true,
      });
    },
    aiCancel(cid) {
      if (!idInPath(cid)) return invalidId();
      return send({
        method: "POST",
        pathWithQuery: `/ai/orders/${encodeURIComponent(String(cid))}/cancel`,
        auth: true,
      });
    },
    botResume(id, body) {
      if (!idInPath(id)) return invalidId();
      return signedIfConnected("POST", `/bots/${encodeURIComponent(String(id))}/resume`, body);
    },
    botRecenter(id, body) {
      if (!idInPath(id)) return invalidId();
      return signedIfConnected("POST", `/bots/${encodeURIComponent(String(id))}/recenter`, body);
    },

    // ---- privileged (the owner's key)
    setMode(botId, body) {
      if (!idInPath(botId)) return invalidId();
      return privileged("POST", `/bots/${encodeURIComponent(String(botId))}/mode`, body);
    },
    setSwitches(body) {
      return privileged("POST", "/switches", body);
    },
    setCaps(caps) {
      return privileged("POST", "/caps", { caps });
    },
    clearHalt(body = { acknowledge_rebase: true }) {
      return privileged("POST", "/halt/clear", body);
    },
    approve(previewId, hash) {
      if (!idInPath(previewId)) return invalidId();
      return privileged("POST", `/ai/previews/${encodeURIComponent(String(previewId))}/approve`, { hash });
    },
    clearCredentials() {
      return privileged("DELETE", "/credentials", undefined, false);
    },
    forgetCredentials() {
      return privileged("POST", "/credentials/forget", undefined, false);
    },

    // ---- the lease gate
    lease(holder, options_ = {}) {
      const keyKind = (options_ && options_.keyKind) || "owner";
      return gated("POST", "/lease", { holder }, keyKind);
    },
    leaseCursor(holder, cursor, options_ = {}) {
      const keyKind = (options_ && options_.keyKind) || "owner";
      return gated("POST", "/lease/cursor", { holder, cursor }, keyKind);
    },
    checkCredentials(body, options_ = {}) {
      const keyKind = (options_ && options_.keyKind) || "owner";
      const extraSecrets = body && typeof body.private_key === "string" ? [body.private_key] : [];
      return gated("POST", "/credentials/check", body, keyKind, extraSecrets);
    },

    // ---- installing the owner's key: its own MAC rule
    async pushCredentials(body, options_ = {}) {
      const keyKind = (options_ && options_.keyKind) || "owner";
      const extraSecrets = [];
      if (body && typeof body === "object") {
        if (typeof body.private_key === "string") extraSecrets.push(body.private_key);
        if (typeof body.approve_secret === "string") extraSecrets.push(body.approve_secret);
      }
      let key;
      if (keyKind === "install") {
        if (!secretProvider) return notAllowed();
        key = await providerKey("install");
        if (!key) return notConnected();
      } else {
        key = body && typeof body.approve_secret === "string" ? body.approve_secret : null;
        if (!key) return notConnected();
      }
      return send({
        method: "POST",
        pathWithQuery: "/credentials",
        hasBody: true,
        body,
        auth: true,
        macKey: key,
        extraSecrets,
        timeoutMs: CREDENTIALS_TIMEOUT_MS,
      });
    },
  };

  return client;
}