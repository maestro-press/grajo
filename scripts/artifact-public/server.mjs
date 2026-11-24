#!/usr/bin/env node
/**
 * The public-link listener: the only HTTP surface a mailed report link touches.
 *
 * WHY IT IS A SEPARATE, TINY PROCESS: a recipient has no Crow account and no place on this instance's
 * network, so the page their link opens is served by a listener that knows nothing about Crow — no
 * database, no session, no storage, no repo module. This file imports `node:` built-ins only, and a test
 * pins that, so the process the public front door reaches cannot be talked into reading an instance file
 * or answering from anywhere but the door below.
 *
 * WHY IT TALKS TO A DOOR AND NOT TO THE DATABASE: everything that decides what a link opens (the token
 * lookup, the version, the threads, the fixed copy, the form nonce) lives behind one unix socket the
 * gateway owns, speaking newline-delimited JSON with ONE request per connection. The listener therefore
 * has no state to leak between two readers and nothing to keep in sync; it opens a fresh connection per
 * request, writes one line, reads one line, and closes.
 *
 * WHY THE TOKEN IS ONLY EVER A SHAPE: the URL is the whole credential, so the path is matched as exactly
 * 43 base64url characters and NOTHING else — no query string (not even an empty `?`), no trailing slash,
 * no suffix, no `..`. A path that does not match is the same fixed "this link doesn't open a report"
 * page every unknown token gets, so a stranger learns nothing from probing. The raw token is forwarded to
 * the door and is never hashed here, never stored on disk, and never written to a log line: the only
 * token-shaped thing this process keeps is an in-memory count for the per-token rate limit, and it holds
 * no path and no reader.
 *
 * WHY EVERY RESPONSE IS SANDBOXED: the pages come from a mailbox, so even the listener's own two-line
 * notice is served under a CSP that forbids scripts, forbids every external source, and puts the document
 * in an opaque origin. The ONE relaxation is the comment page, and the DOOR says which page that is: a
 * reply carrying `form: true` (a page this instance rendered with a real comment form) also gets
 * `allow-forms` and `form-action 'self'` to post back to its own URL. A page is never searched for a
 * marker, because a stored report's own text could carry one; only the door's boolean decides.
 * Every response also carries `no-store`, `no-referrer`, `noindex` and `nosniff`, and no response ever
 * sets a cookie or redirects: a reader's browser keeps nothing from a link.
 *
 * WHY THE LIMITS ARE SHAPED THIS WAY: a public URL is cheap to hammer, so there are three ceilings — a
 * per-token count, a process-wide request count and a process-wide response-byte budget — and all three
 * answer the same fixed "unavailable" page with `Retry-After`. There is deliberately NO per-IP limit and
 * NO forwarding header is read (`X-Forwarded-For` means nothing here), because the front door decides who
 * reaches this port and this process must not be talked into believing a client's own claim about itself.
 * The per-token map is pruned every window and capped, and a token past the cap is counted against the
 * global budget only, so a flood of distinct tokens costs memory nothing. A fourth ceiling bounds the
 * sockets themselves: the server holds at most `maxConnections` of them, which is what keeps the 256M
 * working-set limit of the unit true however hard the port is hammered.
 *
 * WHY A REQUEST NODE ITSELF REFUSES STILL GETS AN ANSWER: a malformed request line or an oversized header
 * is refused by the parser before a request object exists, so `clientError` writes the same fixed page and
 * the same fixed headers by hand (431 for a header that would not fit, 408 for a timeout, 400 otherwise)
 * and then closes the socket. Nothing about the error is logged or described.
 *
 * WHAT IT SAYS WHEN IT CANNOT REACH THE DOOR: connection refused, a missing socket, a timeout, a bare 503
 * or a reply it cannot parse are all the same "this report is unavailable right now" page with 503. A
 * door that comes back is picked up by the very next request, because there is no pool to rebuild.
 */
import { createServer } from "node:http";
import { connect, isIPv4 } from "node:net";
import { pathToFileURL } from "node:url";

/** Where the gateway's door listens unless the environment names another path. */
export const DEFAULT_DOOR_PATH = "/run/crow-report-readers/door.sock";

/** The port a production install publishes this listener on (docs/developers/port-allocation.md). */
export const DEFAULT_PORT = 3093;

/** The only token shape a path may carry: 32 random bytes in base64url. */
const TOKEN_RE = "[A-Za-z0-9_-]{43}";
const VIEW_PATH = new RegExp(`^/r/(${TOKEN_RE})$`);
const COMMENT_PATH = new RegExp(`^/r/(${TOKEN_RE})/comment$`);

/** The sandbox every response carries. The comment page adds the two form permissions. */
export const BASE_CSP =
  "sandbox allow-popups allow-popups-to-escape-sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'";
export const FORM_CSP =
  "sandbox allow-popups allow-popups-to-escape-sandbox allow-forms; default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'";


/**
 * The two lines this process may write itself, in both languages, character for character as approved.
 * Nothing else here is copy: every other page a reader sees is the door's html, unmodified.
 */
const COPY = Object.freeze({
  en: Object.freeze({
    unknown: "This link doesn't open a report. Ask the sender for a new one.",
    unavailable: "This report is unavailable right now. Try again in a few minutes.",
  }),
  es: Object.freeze({
    unknown: "Este enlace no abre ningún informe. Pide uno nuevo a quien te lo envió.",
    unavailable: "Este informe no está disponible ahora. Inténtalo de nuevo en unos minutos.",
  }),
});

/** Defaults for the three ceilings, the window they count over and the door timeout. */
const PER_TOKEN_LIMIT = 60;
const GLOBAL_LIMIT = 600;
const GLOBAL_BYTE_LIMIT = 64 * 1024 * 1024;
const WINDOW_MS = 60_000;
const DOOR_TIMEOUT_MS = 5_000;

/** The most a comment form body may weigh, and the most a door reply may weigh. */
const MAX_BODY_BYTES = 8_192;
const MAX_REPLY_BYTES = 16 * 1024 * 1024;

/** The per-token count map's ceiling, and the request/headers ceilings of the http server. */
const MAX_TOKEN_KEYS = 10_000;
const TIMEOUT_MS = 10_000;

/** The media type a comment POST must carry. */
const FORM_TYPE = "application/x-www-form-urlencoded";

/** The most sockets one process will hold open (the `maxConnections` default). */
const MAX_CONNECTIONS = 64;

/** A path that is not one of the two routes. */
const NONE = Object.freeze({ kind: "none", token: "" });

const escapeText = (value) => String(value == null ? "" : value)
  .replace(/&/g, "&amp;")
  .replace(/</g, "&lt;")
  .replace(/>/g, "&gt;");

/**
 * The listener's own page: the approved sentence twice (title and paragraph) and nothing else.
 *
 * @param {"unknown"|"unavailable"} kind which approved line
 * @param {"en"|"es"} lang
 * @returns {string} one complete HTML document
 */
function noticePage(kind, lang) {
  const line = COPY[lang === "es" ? "es" : "en"][kind === "unavailable" ? "unavailable" : "unknown"];
  return `<!doctype html><html lang="${lang === "es" ? "es" : "en"}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeText(line)}</title><body><p>${escapeText(line)}</p></body></html>`;
}

/**
 * The headers every response carries, whatever its status.
 *
 * One place, so the fixed set cannot be forgotten on a new path: the sandbox CSP (relaxed only when the
 * page really carries the comment form), the no-store/no-referrer/noindex/nosniff quartet and the content
 * type. `answer` adds the length; the refused-request reply below adds it itself.
 *
 * @param {boolean} form whether the page carries the comment form
 * @returns {Record<string, string>}
 */
function fixedHeaders(form) {
  return {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": form === true ? FORM_CSP : BASE_CSP,
    "Cache-Control": "no-store, private",
    "Referrer-Policy": "no-referrer",
    "X-Robots-Tag": "noindex",
    "X-Content-Type-Options": "nosniff",
  };
}

/** The reason phrase of each status a request refused by the parser may be answered with. */
const CLIENT_ERROR_REASONS = Object.freeze({
  400: "Bad Request",
  408: "Request Timeout",
  431: "Request Header Fields Too Large",
});

/**
 * The status for a request the parser refused: 431 for a header that would not fit, 408 for a timeout and
 * 400 for everything else. Only the code is compared, never read out, described or logged.
 */
function clientErrorStatus(err) {
  const code = err != null && typeof err.code === "string" ? err.code : "";
  if (code.includes("HEADER") && code.includes("OVERFLOW")) return 431;
  if (code.includes("TIME")) return 408;
  return 400;
}

/** The language of a request: a header that starts with `es` (trimmed, any case) is Spanish. */
function langOf(acceptLanguage) {
  return /^es/i.test(String(acceptLanguage == null ? "" : acceptLanguage).trim()) ? "es" : "en";
}

/** One request header as a string (an array is joined, a missing one is empty). */
function headerText(req, name) {
  const value = req.headers == null ? undefined : req.headers[name];
  if (Array.isArray(value)) return value.join(", ");
  return typeof value === "string" ? value : "";
}

/** The lowercase media type of a `Content-Type` value, without its parameters. */
function mediaTypeOf(value) {
  return String(value == null ? "" : value).split(";")[0].trim().toLowerCase();
}

/**
 * Which route a request is, decided from the RAW request target.
 *
 * The raw target is used on purpose: `new URL()` would normalise `..` and refuse to see an empty query,
 * and both of those are answers a stranger must not be able to tell apart from an unknown token. Any `?`
 * at all — even a bare one — is not a route, and a method other than the route's own is not a route.
 *
 * @param {import("node:http").IncomingMessage} req
 * @returns {{kind: "none"}|{kind: "view"|"comment", token: string}}
 */
function routeOf(req) {
  const raw = typeof req.url === "string" ? req.url : "";
  if (raw.includes("?")) return NONE;
  if (req.method === "GET") {
    const match = VIEW_PATH.exec(raw);
    return match ? { kind: "view", token: match[1] } : NONE;
  }
  if (req.method === "POST") {
    const match = COMMENT_PATH.exec(raw);
    return match ? { kind: "comment", token: match[1] } : NONE;
  }
  return NONE;
}

/**
 * Ask the door one request over a fresh unix connection.
 *
 * One line out, one line back, then the socket is gone. Every failure mode — a missing socket, a refused
 * connection, a timeout, a reply that does not parse, a reply that is not an object — resolves to null,
 * which the caller turns into the fixed unavailable page. Nothing about the failure is captured.
 *
 * The reply is read as BYTES, and only the NEW chunk is searched for the newline: a door that never sends
 * one would otherwise make this process rescan its whole buffer per chunk, and a cap counted in characters
 * would be a different cap for a multi-byte page. Chunks stay Buffers until the one newline arrives.
 *
 * @param {{doorPath: string, payload: object, timeoutMs: number}} input
 * @returns {Promise<object|null>} the door's reply, or null when there is no usable one
 */
function askDoor({ doorPath, payload, timeoutMs }) {
  return new Promise((resolve) => {
    let settled = false;
    let socket = null;
    let timer = null;
    const chunks = [];
    let size = 0;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      try { socket?.destroy(); } catch { /* already gone */ }
      resolve(value);
    };
    timer = setTimeout(() => finish(null), timeoutMs);
    timer.unref?.();

    let line;
    try {
      line = `${JSON.stringify(payload)}\n`;
    } catch {
      finish(null);
      return;
    }
    try {
      socket = connect(String(doorPath));
    } catch {
      finish(null);
      return;
    }
    socket.on("connect", () => {
      try { socket.write(line); } catch { finish(null); }
    });
    socket.on("data", (chunk) => {
      const at = chunk.indexOf(0x0a);
      const head = at >= 0 ? chunk.subarray(0, at) : chunk;
      chunks.push(head);
      size += head.length;
      if (size > MAX_REPLY_BYTES) {
        finish(null);
        return;
      }
      if (at < 0) return;
      let reply;
      try {
        reply = JSON.parse(Buffer.concat(chunks, size).toString("utf8"));
      } catch {
        finish(null);
        return;
      }
      finish(reply != null && typeof reply === "object" && !Array.isArray(reply) ? reply : null);
    });
    socket.on("error", () => finish(null));
    socket.on("close", () => finish(null));
  });
}

/** The door's html when it is a page (a string), or null. */
const htmlOf = (reply) => (typeof reply.html === "string" ? reply.html : null);

/**
 * Whether a reply says its page really carries the comment form: the door's own boolean, and nothing else.
 *
 * Strictly `true`: a missing field, `"true"`, `1` and `false` are all "no form", so a reply that cannot say
 * so (a notice page, a page built without a nonce) can never hand out `allow-forms`.
 */
const formsAllowed = (reply) => reply != null && reply.form === true;

/**
 * The view answer to give a reader, from the door's reply.
 *
 * 200 is the door's page under its own status, with the door's own word about its form; 410 is the door's
 * expired page (never a form); 404 is the door's approved unknown-link page (or, if it somehow carries
 * none, this process's own); a bare 400 is the unknown-link page; a bare 503 is the unavailable page. An
 * unexpected status is treated like a malformed reply, never relayed.
 *
 * @returns {{status: number, html: string, form: boolean}|null} null means "no usable reply"
 */
function viewOutcome(reply, lang) {
  if (reply == null) return null;
  const status = Number(reply.status);
  if (status === 200) {
    const html = htmlOf(reply);
    return html == null ? null : { status, html, form: formsAllowed(reply) };
  }
  if (status === 410) {
    const html = htmlOf(reply);
    return html == null ? null : { status, html, form: false };
  }
  if (status === 404) {
    return { status: 404, html: htmlOf(reply) ?? noticePage("unknown", lang), form: false };
  }
  if (status === 400) return { status: 404, html: noticePage("unknown", lang), form: false };
  if (status === 503) return { status: 503, html: noticePage("unavailable", lang), form: false };
  return null;
}

/**
 * The answer to give for a comment POST, from the door's reply: the re-rendered page under 200 (a sent
 * comment and a refused one alike, carrying the door's own word about its form), or the door's refusal page
 * under its own status with no form permission. Same "no usable reply" contract as a view.
 */
function commentOutcome(reply, lang) {
  if (reply == null) return null;
  const status = Number(reply.status);
  if (status === 200) {
    const html = htmlOf(reply);
    return html == null ? null : { status: 200, html, form: formsAllowed(reply) };
  }
  if (status === 404) {
    return { status: 404, html: htmlOf(reply) ?? noticePage("unknown", lang), form: false };
  }
  if (status === 410) {
    return { status: 410, html: htmlOf(reply) ?? noticePage("unavailable", lang), form: false };
  }
  if (status === 400) return { status: 404, html: noticePage("unknown", lang), form: false };
  if (status === 503) return { status: 503, html: noticePage("unavailable", lang), form: false };
  return null;
}

/**
 * Read a request body, up to a cap.
 *
 * A body over the cap is swallowed (not kept) until the client finishes, so the 413 page is answered on a
 * connection that is still being written to instead of a reset one; a body beyond a multiple of the cap is
 * not read any further at all, because the point of the cap is that no reader can make this process hold
 * or parse more than a form.
 *
 * @param {import("node:http").IncomingMessage} req
 * @param {number} maxBytes
 * @returns {Promise<{tooLarge: boolean, text: string}|null>} null when the body could not be read
 */
function readBody(req, maxBytes) {
  return new Promise((resolve) => {
    const chunks = [];
    const hardMax = maxBytes * 8;
    let size = 0;
    let tooLarge = false;
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    req.on("data", (chunk) => {
      if (settled) return;
      size += chunk.length;
      if (size <= maxBytes) {
        chunks.push(chunk);
        return;
      }
      tooLarge = true;
      chunks.length = 0;
      if (size > hardMax) finish({ tooLarge: true, text: "" });
    });
    req.on("end", () => finish(tooLarge
      ? { tooLarge: true, text: "" }
      : { tooLarge: false, text: Buffer.concat(chunks, size).toString("utf8") }));
    req.on("error", () => finish(null));
    req.on("aborted", () => finish(null));
  });
}

/** The default fault logger: the class of the fault and nothing else. */
const defaultLog = (cls) => {
  try { process.stderr.write(`artifact-public: ${cls}\n`); } catch { /* a closed stderr */ }
};

/**
 * The listener, built and not listening.
 *
 * Everything a test needs to bend is a parameter: the door's path, the clock the rate limits count over,
 * the three ceilings, the socket ceiling and the door timeout. `log` receives ONE WORD per fault (never a
 * path, a token or a header) and nothing else; the start line is written by the entry point below.
 *
 * @param {{doorPath?: string, now?: Function, log?: Function, perTokenLimit?: number,
 *   globalLimit?: number, globalByteLimit?: number, windowMs?: number, doorTimeoutMs?: number,
 *   maxBodyBytes?: number, maxTokenKeys?: number, maxConnections?: number}} [input]
 * @returns {import("node:http").Server} an http server that is not listening yet
 */
export function createListener({
  doorPath = DEFAULT_DOOR_PATH,
  now = Date.now,
  log = defaultLog,
  perTokenLimit = PER_TOKEN_LIMIT,
  globalLimit = GLOBAL_LIMIT,
  globalByteLimit = GLOBAL_BYTE_LIMIT,
  windowMs = WINDOW_MS,
  doorTimeoutMs = DOOR_TIMEOUT_MS,
  maxBodyBytes = MAX_BODY_BYTES,
  maxTokenKeys = MAX_TOKEN_KEYS,
  maxConnections = MAX_CONNECTIONS,
} = {}) {
  const clockOf = () => {
    let value = NaN;
    try { value = Number(now()); } catch { value = NaN; }
    return Number.isFinite(value) ? value : Date.now();
  };
  const perToken = Number.isFinite(Number(perTokenLimit)) ? Number(perTokenLimit) : PER_TOKEN_LIMIT;
  const globalMax = Number.isFinite(Number(globalLimit)) ? Number(globalLimit) : GLOBAL_LIMIT;
  const byteMax = Number.isFinite(Number(globalByteLimit)) ? Number(globalByteLimit) : GLOBAL_BYTE_LIMIT;
  const windowOf = Number.isFinite(Number(windowMs)) && Number(windowMs) > 0 ? Number(windowMs) : WINDOW_MS;
  const doorTimeout = Number.isFinite(Number(doorTimeoutMs)) && Number(doorTimeoutMs) > 0
    ? Number(doorTimeoutMs)
    : DOOR_TIMEOUT_MS;
  const bodyMax = Number.isFinite(Number(maxBodyBytes)) && Number(maxBodyBytes) > 0
    ? Number(maxBodyBytes)
    : MAX_BODY_BYTES;
  const keyMax = Number.isFinite(Number(maxTokenKeys)) && Number(maxTokenKeys) > 0
    ? Number(maxTokenKeys)
    : MAX_TOKEN_KEYS;
  const connMax = Number.isFinite(Number(maxConnections)) && Number(maxConnections) > 0
    ? Number(maxConnections)
    : MAX_CONNECTIONS;

  /** token -> {bucket, count}: the only thing this process keeps per reader, and never for long. */
  const tokens = new Map();
  let prunedFor = -1;
  let global = { bucket: -1, count: 0, bytes: 0 };

  const globalFor = (bucket) => {
    if (global.bucket !== bucket) global = { bucket, count: 0, bytes: 0 };
    return global;
  };

  /** Drop every token counted in an older window. Runs once per window, so a bucket is bounded. */
  const pruneTokens = (bucket) => {
    if (prunedFor === bucket) return;
    prunedFor = bucket;
    for (const [key, value] of tokens) if (value.bucket !== bucket) tokens.delete(key);
  };

  /**
   * Count one request for its token. Past the map's cap a token nobody has seen is not stored, so it is
   * limited by the global budget alone — bounded memory in exchange for a ceiling that is still shared.
   */
  const allowedToken = (token, bucket) => {
    pruneTokens(bucket);
    const entry = tokens.get(token);
    if (entry && entry.bucket === bucket) {
      if (entry.count >= perToken) return false;
      entry.count += 1;
      return true;
    }
    if (!entry && tokens.size >= keyMax) return true;
    tokens.set(token, { bucket, count: 1 });
    return true;
  };

  /**
   * Write one response. Every response in this file goes through here, which is what makes the sandbox
   * headers, the no-store/no-referrer/noindex trio and the byte accounting impossible to forget.
   *
   * `form` is the door's boolean relayed by the outcome, so only a page the door says carries its comment
   * form gets the two form permissions.
   */
  const answer = (res, { status, html, retryAfter = null, budget = null, form = false, close = false }) => {
    if (budget) budget.bytes += Buffer.byteLength(html, "utf8");
    if (res.headersSent) {
      try { res.end(); } catch { /* already gone */ }
      return;
    }
    const headers = {
      ...fixedHeaders(form === true),
      "Content-Length": Buffer.byteLength(html, "utf8"),
    };
    if (retryAfter != null) headers["Retry-After"] = String(retryAfter);
    if (close) headers.Connection = "close";
    try {
      res.writeHead(status, headers);
      res.end(html);
    } catch {
      try { res.destroy(); } catch { /* already gone */ }
    }
  };

  /** A fault the reader must not learn about: one word to the log, the fixed unavailable page. */
  const fault = (res, lang, budget, cls) => {
    try { log(cls); } catch { /* a logger that throws changes nothing */ }
    answer(res, { status: 503, html: noticePage("unavailable", lang), budget });
  };

  const rateLimited = (res, lang, budget) => {
    answer(res, { status: 429, html: noticePage("unavailable", lang), retryAfter: 60, budget });
  };

  const handleComment = async (req, res, token, acceptLanguage, lang, budget) => {
    if (mediaTypeOf(headerText(req, "content-type")) !== FORM_TYPE) {
      answer(res, { status: 404, html: noticePage("unknown", lang), budget, close: true });
      return;
    }
    const body = await readBody(req, bodyMax);
    if (body == null) {
      fault(res, lang, budget, "body");
      return;
    }
    if (body.tooLarge) {
      answer(res, { status: 413, html: noticePage("unknown", lang), budget, close: true });
      return;
    }
    let form;
    try {
      form = new URLSearchParams(body.text);
    } catch {
      answer(res, { status: 404, html: noticePage("unknown", lang), budget });
      return;
    }
    const formNonce = form.get("formNonce");
    const text = form.get("text");
    if (typeof formNonce !== "string" || typeof text !== "string") {
      answer(res, { status: 404, html: noticePage("unknown", lang), budget });
      return;
    }
    const reply = await askDoor({
      doorPath,
      timeoutMs: doorTimeout,
      payload: { op: "comment", token, formNonce, text, acceptLanguage },
    });
    const outcome = commentOutcome(reply, lang);
    if (outcome == null) {
      fault(res, lang, budget, "door");
      return;
    }
    answer(res, { ...outcome, budget });
  };

  const handle = async (req, res) => {
    req.on("error", () => { /* a client that went away is not a fault of ours */ });
    const acceptLanguage = headerText(req, "accept-language").slice(0, 64);
    const lang = langOf(acceptLanguage);
    const bucket = Math.floor(clockOf() / windowOf);
    const budget = globalFor(bucket);

    if (budget.count >= globalMax || budget.bytes >= byteMax) {
      rateLimited(res, lang, budget);
      return;
    }
    budget.count += 1;

    const route = routeOf(req);
    if (route.kind === "none") {
      answer(res, { status: 404, html: noticePage("unknown", lang), budget });
      return;
    }
    if (!allowedToken(route.token, bucket)) {
      rateLimited(res, lang, budget);
      return;
    }
    if (route.kind === "comment") {
      await handleComment(req, res, route.token, acceptLanguage, lang, budget);
      return;
    }
    const reply = await askDoor({
      doorPath,
      timeoutMs: doorTimeout,
      payload: { op: "view", token: route.token, acceptLanguage },
    });
    const outcome = viewOutcome(reply, lang);
    if (outcome == null) {
      fault(res, lang, budget, "door");
      return;
    }
    answer(res, { ...outcome, budget });
  };

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      try { log("request"); } catch { /* a logger that throws changes nothing */ }
      if (res.headersSent) {
        try { res.end(); } catch { /* already gone */ }
        return;
      }
      answer(res, { status: 503, html: noticePage("unavailable", "en") });
    });
  });
  // Node's own parser refused the request, so there is no `ServerResponse` to answer with: the fixed page
  // and the fixed headers are written to the socket by hand, and the socket goes. Nothing about the error
  // is logged or relayed, and a socket that cannot be written is only destroyed.
  server.on("clientError", (err, socket) => {
    if (socket == null) return;
    if (!socket.writable) {
      try { socket.destroy(); } catch { /* already gone */ }
      return;
    }
    const status = clientErrorStatus(err);
    const html = noticePage("unknown", "en");
    const headers = {
      ...fixedHeaders(false),
      "Content-Length": Buffer.byteLength(html, "utf8"),
      Connection: "close",
    };
    const lines = Object.entries(headers).map(([name, value]) => `${name}: ${value}\r\n`).join("");
    const raw = `HTTP/1.1 ${status} ${CLIENT_ERROR_REASONS[status]}\r\n${lines}\r\n${html}`;
    try {
      socket.end(raw, () => {
        try { socket.destroy(); } catch { /* already gone */ }
      });
    } catch {
      try { socket.destroy(); } catch { /* already gone */ }
    }
  });
  server.requestTimeout = TIMEOUT_MS;
  server.headersTimeout = TIMEOUT_MS;
  server.maxHeadersCount = 50;
  // The sockets themselves are the fourth ceiling: with one line per connection and a bounded reply, this
  // is what keeps the unit's 256M working set true however hard the port is hammered.
  server.maxConnections = connMax;
  return server;
}

/**
 * The production entry: read the bind, the port and the door's path from the environment, listen, and
 * close on SIGTERM/SIGINT.
 *
 * REFUSES TO RUN WITHOUT AN IPv4 BIND, AND REFUSES THE WILDCARD: this port is the one surface a stranger
 * reaches, so the address it binds is never guessed and never widened — an unset, non-IPv4 or all-zero
 * value is one line on stderr and exit 1, before a socket exists.
 *
 * @param {{env?: object, exit?: Function}} [input]
 * @returns {import("node:http").Server|null}
 */
function main({ env = process.env, exit = (code) => process.exit(code) } = {}) {
  const bind = String(env.CROW_ARTIFACT_PUBLIC_BIND == null ? "" : env.CROW_ARTIFACT_PUBLIC_BIND).trim();
  if (!isIPv4(bind)) {
    process.stderr.write("artifact-public: CROW_ARTIFACT_PUBLIC_BIND must be an IPv4 address\n");
    exit(1);
    return null;
  }
  // Every octet zero is the wildcard bind: the front door decides who reaches this port, so this process
  // never listens on every interface. The address is compared as four parsed octets and is never written
  // as a literal here.
  if (bind.split(".").every((octet) => Number(octet) === 0)) {
    process.stderr.write("artifact-public: CROW_ARTIFACT_PUBLIC_BIND must name one address, not the wildcard\n");
    exit(1);
    return null;
  }
  const port = Number.parseInt(String(env.CROW_ARTIFACT_PUBLIC_PORT == null ? DEFAULT_PORT : env.CROW_ARTIFACT_PUBLIC_PORT).trim(), 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    process.stderr.write("artifact-public: CROW_ARTIFACT_PUBLIC_PORT must be a port number\n");
    exit(1);
    return null;
  }
  const doorPath = String(env.CROW_REPORT_DOOR_SOCKET == null ? "" : env.CROW_REPORT_DOOR_SOCKET).trim()
    || DEFAULT_DOOR_PATH;
  const log = (line) => {
    try { process.stdout.write(`${line}\n`); } catch { /* a closed stdout */ }
  };
  const server = createListener({ doorPath, log });
  server.on("error", () => {
    process.stderr.write("artifact-public: could not listen\n");
    exit(1);
  });
  server.listen(port, bind, () => log(`artifact-public: listening on ${bind}:${port}`));
  const stop = () => {
    server.close(() => exit(0));
    const timer = setTimeout(() => exit(0), 3_000);
    timer.unref?.();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
  return server;
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) main();

export default createListener;