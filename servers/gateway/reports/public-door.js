/**
 * The public reports door: the one way a person who was MAILED a report reaches it.
 *
 * WHY ITS OWN LISTENER, AND ITS OWN SOCKET: a recipient has no Crow account, no dashboard session and no
 * place on this instance's network. The page a link opens is therefore served by a door of its own, on a
 * systemd-owned unix socket (`crow-report-readers.socket`), exactly the shape the gateway's Caddy proxy
 * socket already has (servers/gateway/proxy-socket.js): systemd creates the socket, this process takes
 * the inherited fd by socket activation and never creates, chmods or unlinks a path. That is what keeps
 * the door off the dashboard's TCP listener and off every Funnel path: the only thing that can reach it
 * is whatever the operator's front door is configured to be, and this module mints nothing that a mail
 * did not already carry.
 *
 * WHY THE PROTOCOL IS ONE JSON LINE PER CONNECTION: the door is reached over a unix socket by a small
 * front end, not by a browser, so the whole contract is a line of JSON in and a line of JSON out. One
 * request per connection means there is no session to keep, no state between two readers and no way for
 * a half-sent request to be answered after another one; the handler is a pure `request -> reply` function
 * so the same code is exercised by a test with plain objects (no socket at all).
 *
 * WHY THE TOKEN SHAPE IS CHECKED FIRST: the token in the URL is the only credential here, so it is held
 * to exactly one shape, 43 base64url characters (32 random bytes, the shape `links.js` mints), BEFORE any
 * lookup. A wrong shape is the same 404 page an unknown token gets: no database read, no timing
 * difference between "not a token" and "no such token", and no way for a suffix (`?v=1`, `/x`), an
 * encoded separator or a stored 64-hex `token_hash` to mean anything. There is no version parameter and
 * no other way to choose a version: the token row stores the one version it opens.
 *
 * WHY A FORM NONCE: the comment form is rendered into a page that lives outside this instance, and the
 * link token alone cannot say whether the page a form came from was ours or an attacker's copy. Every
 * comment-scope page therefore carries a nonce keyed by this instance's keychain seed (`formNonceFor` in
 * ./seal.js), bound to that one token's hash and to a ten-minute window, and accepted for one window
 * after it. That is not a session (the token is still the identity); it is only "a page this instance
 * rendered recently".
 *
 * THE FORM IS ONLY OFFERED WHILE THE VERSION STILL TAKES COMMENTS: a report's verified comment window
 * says how many of its newest runs still accept them (`commentOpenFor` in ./recipient-comments.js), so a
 * page for an older run shows its threads and NO form, and a post to it answers the same fixed line a
 * view-only link gets. The page and the post read one window, so they can never disagree.
 *
 * WHAT A READER IS TOLD: every refusal is one of the fixed lines in ./recipient-copy.js, in the
 * language the mail client asked for (`acceptLanguage`, `pickLang`). An internal failure (the artifacts
 * runtime missing, the version unreadable, no keychain seed) is the fixed "unavailable" page with no
 * detail, and a malformed request is a bare 400, because a reader is never shown a database message and a
 * caller is never told what it got wrong.
 *
 * THE RAW TOKEN NEVER LEAVES: replies carry the page (and the page carries no token: its form posts back
 * to the page's own URL), errors carry a code, and nothing here logs a request body. The only token fact
 * that travels anywhere is the hash the form nonce is bound to, and that hash is not secret anyway.
 *
 * EVERY PAGE REPLY SAYS WHETHER IT CARRIES THE COMMENT FORM: a 200 carries `form: true` or `form: false`,
 * so the front end that serves this door can relax its sandbox for exactly the pages that need a form
 * rather than searching the html. A notice page (404/410/503) carries no `form` at all, because a refusal
 * is never something a reader can post from.
 *
 * Node built-ins only, plus the reports modules this door is the front of.
 */
import { createServer } from "node:net";
import { pickActivatedFd } from "../proxy-socket.js";
import { hashToken, resolveLinkToken } from "./links.js";
import { copyFor, pickLang } from "./recipient-copy.js";
import {
  buildRecipientView, loadVersionForView, renderRecipientNotice,
} from "./recipient-view.js";
import {
  commentErrorLine, commentOpenFor, postRecipientComment, visibleThreadsFor,
} from "./recipient-comments.js";
import { formNonceFor, verifyFormNonce } from "./seal.js";

/**
 * The socket unit a later PR's systemd unit must use, and the name this process picks its inherited fd
 * by (`LISTEN_FDNAMES`). Nothing in this module creates the socket, and no path is assumed here: the unit
 * owns the path, so the one place it is named is the log line below.
 */
export const REPORTS_DOOR_SOCKET_UNIT = "crow-report-readers.socket";

/** The one token shape a URL may carry: 32 random bytes in base64url, exactly as `links.js` mints them. */
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

/** The two operations a line may ask for. */
const OPS = Object.freeze(["view", "comment"]);

/** The comment refusals `postRecipientComment` raises, and the one word any other failure becomes. */
const COMMENT_CODES = Object.freeze([
  "view_only", "empty", "too_long", "rate_limited", "too_many_threads", "other",
]);

/** The longest request line a connection may send, and how long it may take to send it. */
const MAX_LINE_BYTES = 65_536;
const IDLE_MS = 10_000;

/** A reply for a request that made no sense: status and nothing else. */
const BAD_REQUEST = Object.freeze({ status: 400 });

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** A plain object, which is the only shape a request may be (an array or null is a bad request). */
function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

/** One of the three notice pages, under the status that says which answer it is. */
function notice(status, kind, lang) {
  return { status, html: renderRecipientNotice({ kind, lang }) };
}

/** The injected clock, falling back to `Date.now` for a missing or unusable one. */
function nowOf(given) {
  const value = typeof given.now === "function" ? Number(given.now()) : NaN;
  return Number.isFinite(value) ? value : Date.now();
}

let approvalsInternalsModule = null;

/**
 * The approvals internals, loaded on first use.
 *
 * The door reads the keychain seed through the SAME seam `approvals.js` uses (`seedOf` over a resolved
 * `loadSeed`), never by opening the key file itself, so an install's keychain is read one way in this
 * codebase. Loaded lazily because `approvals.js` is the heavy module of this tree (the block registry,
 * the store, the model resolver) and a boot that never has an activation fd should not pay for it. The
 * import cannot fail into anything worse than the unavailable page.
 *
 * @returns {Promise<{approvalInternals: {seedOf: Function, resolveDeps: Function}}>}
 */
function loadApprovalsInternals() {
  if (!approvalsInternalsModule) approvalsInternalsModule = import("./approvals.js");
  return approvalsInternalsModule;
}

/**
 * The keychain seed, through the approvals seam.
 *
 * @param {object} given the door's deps
 * @returns {Promise<Buffer|Uint8Array>}
 * @throws {Error} `keychain_key_missing` when this instance has no usable seed
 */
async function seedOf(given) {
  const { approvalInternals } = await loadApprovalsInternals();
  const resolved = approvalInternals.resolveDeps({ loadSeed: given.loadSeed, now: given.now });
  return approvalInternals.seedOf(resolved);
}

/**
 * The deps `resolveLinkToken` takes, built from the door's own.
 *
 * A caller injects the seed and the clock at the TOP level (that is this module's seam), while the links
 * module reads them from `deps.approvals` (that is its seam). Bridging them here means a test injects one
 * object and both modules see the same seed and the same clock, which is what makes a seal verify and an
 * expiry land at a test's chosen moment. Anything the caller passed for links itself still wins.
 *
 * @param {object} given the door's deps
 * @returns {object}
 */
function linksDepsOf(given) {
  const approvals = isPlainObject(given.approvals) ? given.approvals : {};
  const merged = { ...approvals };
  if (merged.loadSeed === undefined) merged.loadSeed = given.loadSeed;
  if (merged.now === undefined) merged.now = given.now;
  return { ...given, approvals: merged };
}

/**
 * The http(s) URLs the version's own items carried (`report_versions.allowed_links_json`).
 *
 * This is what decides which inert anchors of a stored page become clickable again (see
 * ./recipient-view.js): a body a source wrote can never hand a reader a destination the report never
 * offered. A missing row, an unreadable one and a JSON value that is not an array all answer the empty
 * set, which is the safe side: every link stays inert.
 *
 * @param {object} db
 * @param {string} artifactId
 * @param {number} n
 * @returns {Promise<string[]>}
 */
async function allowedLinksOf(db, artifactId, n) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT allowed_links_json FROM report_versions WHERE artifact_id = ? AND n = ?",
      args: [artifactId, n],
    });
    const parsed = JSON.parse(text(rows[0] == null ? "" : rows[0].allowed_links_json) || "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((url) => typeof url === "string");
  } catch {
    return [];
  }
}

/**
 * The recipient page for one resolved token: the version it opens, its visible threads and, for a
 * comment-scope link, a fresh form nonce (plus the caller's notice line when there is one).
 *
 * NO FORM ON A CLOSED PAGE: a version older than the report's verified comment window stays readable and
 * closed (see ./recipient-comments.js), so its page carries the threads and no form. That is the same
 * answer a post gets (`view_only`), read from the same place, so a page a reader can see and a post a
 * reader can make never disagree.
 *
 * Returns null when there is no page to build: a version the artifacts store will not serve, an artifact
 * that is not a document, or a comment-scope page whose nonce cannot be made (no seed, or a seed this
 * process cannot use). The caller turns null into the fixed unavailable page, so nothing about why is
 * ever shown to a reader.
 *
 * THE PAGE AND ITS FORM ARE REPORTED TOGETHER, as `{html, form}`: `form` is true only when this page really
 * carries the comment form (a `commentForm` with a string nonce was rendered into it), which is the one
 * fact the front end needs to relax its sandbox. Saying it here, where the page is built, is what lets the
 * front end stop searching the html for a marker: a stored report's own text could contain one.
 *
 * @param {object} db
 * @param {object} given the door's deps
 * @param {{resolved: object, token: string, lang: string, notice: object|null}} input `notice` is the
 *   fixed line a refusal or a sent comment puts above the form, or null for a plain page
 * @returns {Promise<{html: string, form: boolean}|null>} one complete HTML document and whether it has the
 *   comment form
 */
async function renderPage(db, given, {
  resolved, token, lang, notice: line = null,
} = {}) {
  const artifactId = text(resolved.token.artifactId);
  const versionN = Number(resolved.token.versionN);
  const version = await loadVersionForView(db, given, { artifactId, n: versionN });
  if (!version) return null;
  const threads = await visibleThreadsFor(db, given, {
    report: resolved.report,
    recipient: resolved.recipient,
    artifactId,
    versionN,
    lang,
  });
  let commentForm = null;
  if (resolved.token.scope === "comment") {
    if (await commentOpenFor(db, given, { report: resolved.report, versionN })) {
      try {
        commentForm = { nonce: formNonceFor(hashToken(token), await seedOf(given), nowOf(given)) };
      } catch {
        return null;
      }
      if (line) commentForm.notice = line;
    } else if (line) {
      // A closed page has no form to offer, so its refusal carries the fixed line alone (the view
      // builder renders a commentForm without a nonce as a notice without a form).
      commentForm = { notice: line };
    }
  } else if (line) {
    // A view-scope link has no form to offer, so its refusal carries the fixed line alone.
    commentForm = { notice: line };
  }
  const allowedLinks = await allowedLinksOf(db, artifactId, versionN);
  const html = await buildRecipientView({
    indexHtml: version.indexHtml,
    readAsset: version.readAsset,
    allowedLinks,
    threads,
    commentForm,
    lang,
  });
  return { html, form: commentForm != null && typeof commentForm.nonce === "string" };
}

/**
 * The `view` operation: the page one token opens, or the refusal page that says why not.
 *
 * Every 200 carries `form`, the page's own answer about the comment form; a notice page carries none (and
 * never a true one), because a refusal is never a page a reader can post from.
 *
 * @returns {Promise<{status: number, html: string, form?: boolean}>}
 */
async function viewReply(db, given, { token, lang }) {
  const resolved = await resolveLinkToken(db, linksDepsOf(given), token);
  if (resolved.status === "expired") return notice(410, "expired", lang);
  if (resolved.status !== "ok") return notice(404, "unknown", lang);
  const page = await renderPage(db, given, { resolved, token, lang });
  if (page == null) return notice(503, "unavailable", lang);
  return { status: 200, html: page.html, form: page.form };
}

/**
 * The `comment` operation: post one comment from the page it was written on, and answer with the page
 * re-rendered so the reader sees either the sent line or the one fixed refusal line.
 *
 * THE ORDER: the resolve first (a dead link is a dead link whatever was posted to it), then the scope (a
 * view-only link has no form, so a hand-made request must never reach a thread), then the form nonce,
 * then the comment itself. Every refusal keeps the fixed line and the code, and nothing else: the
 * reader's text is never echoed back except inside the re-rendered thread, where the view escapes it.
 *
 * Every 200 — the sent comment and a refusal alike — carries `form`, the re-rendered page's own answer
 * about the comment form, so a refusal on a page that still offers one keeps it (a reader who mistyped
 * has to be able to try again) while a refusal with no form to offer says so.
 *
 * @returns {Promise<object>} a 404/410 notice page, or `{status: 200, ok, error?, line, html, form}`
 */
async function commentReply(db, given, {
  token, formNonce, body, lang,
} = {}) {
  const table = copyFor(lang);
  const resolved = await resolveLinkToken(db, linksDepsOf(given), token);
  if (resolved.status === "expired") return notice(410, "expired", lang);
  if (resolved.status !== "ok") return notice(404, "unknown", lang);

  const refused = async (code, line) => {
    const page = await renderPage(db, given, {
      resolved, token, lang, notice: { kind: "error", text: line },
    });
    if (page == null) return notice(503, "unavailable", lang);
    return { status: 200, ok: false, error: code, line, html: page.html, form: page.form };
  };

  if (resolved.token.scope !== "comment") return refused("view_only", table.errViewOnly);
  // A version past the verified comment window is readable and closed: no form was offered for it, and a
  // hand-made post gets the same fixed line a view-only link gets rather than the form-expired one, which
  // would read as "just reload the page". `postRecipientComment` checks the same window again below.
  if (!(await commentOpenFor(db, given, {
    report: resolved.report, versionN: Number(resolved.token.versionN),
  }))) {
    return refused("view_only", table.errViewOnly);
  }

  let seed;
  try {
    seed = await seedOf(given);
  } catch {
    return notice(503, "unavailable", lang);
  }
  if (!verifyFormNonce(formNonce, hashToken(token), seed, nowOf(given))) {
    return refused("form_expired", table.errFormExpired);
  }

  try {
    await postRecipientComment(db, given, { resolved, text: body });
  } catch (err) {
    const raised = text(err == null ? "" : err.code);
    const code = COMMENT_CODES.includes(raised) ? raised : "other";
    return refused(code, commentErrorLine(code, lang));
  }

  const line = table.sent;
  const page = await renderPage(db, given, {
    resolved, token, lang, notice: { kind: "ok", text: line },
  });
  if (page == null) return notice(503, "unavailable", lang);
  return { status: 200, ok: true, line, html: page.html, form: page.form };
}

/**
 * The door's one request handler: a plain object in, a plain JSON-safe object out.
 *
 * @param {object} db a libsql-shaped client (the gateway's own)
 * @param {object} [deps] the seam: `artifacts` (the artifacts runtime), `comments` (the bundle's
 *   comments module), `loadSeed`, `now`, `notify`, `approvals` (the links seam, passed through)
 * @returns {(request: object) => Promise<object>} the handler
 */
export function createDoorHandler(db, deps = {}) {
  const given = isPlainObject(deps) ? deps : {};
  return async function handleRequest(request) {
    const lang = pickLang(isPlainObject(request) ? request.acceptLanguage : undefined);
    try {
      if (!isPlainObject(request)) return BAD_REQUEST;
      const op = request.op;
      if (typeof op !== "string" || !OPS.includes(op)) return BAD_REQUEST;
      const token = request.token;
      // The shape first, before any lookup: anything else is the same 404 an unknown token gets.
      if (typeof token !== "string" || !TOKEN_RE.test(token)) return notice(404, "unknown", lang);
      if (op === "comment"
        && (typeof request.formNonce !== "string" || typeof request.text !== "string")) {
        return BAD_REQUEST;
      }
      return op === "view"
        ? await viewReply(db, given, { token, lang })
        : await commentReply(db, given, { token, formNonce: request.formNonce, body: request.text, lang });
      // Anything that escaped a module below (a database that will not open, a renderer that threw) is
      // the fixed unavailable page: no detail, no stack, and never the token.
    } catch {
      return notice(503, "unavailable", lang);
    }
  };
}

/** The live sockets of one door server, so a forced close can sever them (a net.Server has no
 *  `closeAllConnections` of its own). */
const SOCKETS = Symbol.for("crow.report-readers.sockets");

/**
 * The listen gate of one door server: `typeChecked` is flipped only by `checkDoorListener`, once the bound
 * listener's own kind is known (see there). Until then nothing is served.
 */
const GATE = Symbol.for("crow.report-readers.gate");

/**
 * The door as a stream server: newline-delimited JSON, one request per connection.
 *
 * A reader of this protocol sends one line and reads one line back, so nothing has to be framed beyond
 * the first `\n`. Every failure is a bare `{"status":400}` (a line over `maxLineBytes`, a line that is not
 * JSON, a connection that goes idle) or `{"status":503}` (the handler itself threw): no detail, and never
 * a throw out of a socket callback, because an exception in a `net` event handler is an uncaught
 * exception that would take the gateway down with it.
 *
 * Not listening: the caller decides (`listenDoor` for a path, `startActivatedDoor` for the systemd fd).
 *
 * @param {{db?: object, deps?: object, maxLineBytes?: number, idleMs?: number, log?: Function}} [input]
 * @returns {import("node:net").Server}
 */
export function createDoorServer({
  db = null, deps = {}, maxLineBytes = MAX_LINE_BYTES, idleMs = IDLE_MS, log = () => {},
} = {}) {
  const handle = createDoorHandler(db, deps);
  const limit = Number.isFinite(Number(maxLineBytes)) && Number(maxLineBytes) > 0
    ? Number(maxLineBytes)
    : MAX_LINE_BYTES;
  const idle = Number.isFinite(Number(idleMs)) && Number(idleMs) > 0 ? Number(idleMs) : IDLE_MS;
  const sockets = new Set();
  const gate = { typeChecked: false };

  const server = createServer({ allowHalfOpen: false }, (socket) => {
    // NOTHING IS SERVED BEFORE THE LISTENER'S OWN KIND IS KNOWN (see checkDoorListener): a connection
    // accepted on a TCP fd would otherwise be answered in the window between accept and the post-listen
    // check. A unix-socket peer has no remote family at all, so a socket that carries one is TCP and is
    // refused here too, whatever the flag says.
    if (!gate.typeChecked || socket.remoteFamily) {
      try { socket.destroy(); } catch { /* the peer is already gone */ }
      return;
    }
    let closed = false;
    let busy = false;
    let timer = null;
    const chunks = [];
    let size = 0;
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));

    const stopTimer = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
    };

    const reply = (payload) => {
      if (closed) return;
      closed = true;
      stopTimer();
      let line;
      try {
        line = `${JSON.stringify(payload)}\n`;
      } catch {
        line = '{"status":400}\n';
      }
      try {
        socket.end(line);
      } catch {
        try { socket.destroy(); } catch { /* the peer is already gone */ }
      }
    };

    // A request WE refuse: answer it, but keep reading so a peer still sending a long or idle line gets
    // the reply instead of a reset, then let the socket finish on its own.
    const refuse = (payload) => {
      if (closed) return;
      try { socket.resume(); } catch { /* a destroyed socket has nothing to drain */ }
      reply(payload);
    };

    const settle = () => {
      closed = true;
      stopTimer();
    };

    socket.on("error", () => {
      settle();
      try { socket.destroy(); } catch { /* already gone */ }
    });
    socket.on("close", settle);

    timer = setTimeout(() => refuse(BAD_REQUEST), idle);
    timer.unref?.();

    socket.on("data", (chunk) => {
      if (closed || busy) return;
      const at = chunk.indexOf(0x0a);
      const head = at >= 0 ? chunk.subarray(0, at) : chunk;
      chunks.push(head);
      size += head.length;
      if (size > limit) {
        refuse(BAD_REQUEST);
        return;
      }
      if (at < 0) return;
      stopTimer();
      let request;
      try {
        request = JSON.parse(Buffer.concat(chunks, size).toString("utf8"));
      } catch {
        refuse(BAD_REQUEST);
        return;
      }
      // One request per connection: nothing more is read while this one is answered.
      busy = true;
      Promise.resolve()
        .then(() => handle(request))
        .then((payload) => {
          busy = false;
          reply(payload);
        })
        .catch(() => {
          busy = false;
          // A genuine fault, said out loud without any detail: no request body, no token, no stack.
          try { log("[report-readers] a request failed"); } catch { /* a logger that throws */ }
          reply({ status: 503 });
        });
    });
  });
  try { server[SOCKETS] = sockets; } catch { /* frozen server: a forced close cannot sever it */ }
  try { server[GATE] = gate; } catch { /* frozen server: nothing will be served on it */ }
  return server;
}

/**
 * Decide a listener's kind, BEFORE any connection can be served: a unix socket is the reports door, and
 * anything carrying a TCP port is refused and closed.
 *
 * WHY THIS IS SAFE AFTER `listen()` AND BEFORE ANY ACCEPT: `net` fills in the handle (and its address)
 * synchronously inside `listen()`, and it only dispatches a connection on a later event loop turn, so this
 * check runs in the same turn as the bind with no accepted socket in between. The connection handler
 * refuses everything until `typeChecked` is set (`createDoorServer`), which is the second half: even a
 * caller that never runs this helper serves nothing.
 *
 * A TCP listener is closed here and the flag is deliberately left unset: closing is the removal of the
 * surface, and the gate keeps refusing anything already queued on it. Never throws.
 *
 * @param {import("node:net").Server} server
 * @param {string} where a log-safe name for the listener (an fd number or a path)
 * @param {Function} log
 * @returns {boolean} true when the listener is a unix socket and may serve
 */
function checkDoorListener(server, where, log) {
  let addr = null;
  try { addr = server.address(); } catch { addr = null; }
  if (addr && typeof addr === "object" && "port" in addr) {
    try {
      log(`[report-readers] REFUSED: ${where} is a TCP socket, not the reports door; closing it`);
    } catch { /* a logger that throws must not leave the listener up */ }
    try { server.close(); } catch { /* already closing */ }
    return false;
  }
  const gate = server[GATE];
  if (gate) gate.typeChecked = true;
  return true;
}

/**
 * TEST AND ACTIVATION helper: listen the door server on a unix path or an already-listening fd.
 *
 * It never creates, chmods or unlinks a path itself: a caller that passes a path is the one that owns it
 * (a test passes one inside its own temp directory and removes it), and production passes an fd systemd
 * opened (see `startActivatedDoor`).
 *
 * @param {import("node:net").Server} server
 * @param {string|number} target a unix socket path, or an fd number
 * @returns {import("node:net").Server} the same server
 */
export function listenDoor(server, target) {
  if (server == null) return server;
  // A path is a unix socket by construction, and an fd is asked what it is once it is bound (the same
  // check the activation path makes, so both listeners open the gate the same way).
  const opened = () => checkDoorListener(server, typeof target === "number" ? `fd ${target}` : `${target}`,
    () => {});
  if (typeof target === "number") server.listen({ fd: target }, opened);
  else server.listen(target, opened);
  return server;
}

/**
 * The production path: listen on the fd systemd handed us for `crow-report-readers.socket`.
 *
 * Returns null when there is no activation fd (a dev run, `node servers/gateway/index.js` by hand, an
 * install whose door unit is not there yet): in that case this listens on NOTHING and logs nothing at
 * warn level, because a missing door is not a fault in a mode where nobody configured one. Never throws:
 * a door that cannot start costs the recipient pages, never the gateway.
 *
 * A TCP fd is refused and closed, exactly as `startActivatedProxySocket` refuses one: a recipient page is
 * not something this process may serve on a port nobody asked it to open. The refusal happens BEFORE
 * anything is accepted (`checkDoorListener` runs in the same turn as the bind), so no connection on a TCP
 * fd is ever read or answered.
 *
 * @param {{db?: object, deps?: object, env?: object, pid?: number, log?: Function}} [input]
 * @returns {import("node:net").Server|null}
 */
export function startActivatedDoor({
  db = null, deps = {}, env = process.env, pid = process.pid, log = console.log,
} = {}) {
  let fd;
  try {
    fd = pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, env, pid);
  } catch {
    return null;
  }
  if (fd == null) return null;
  try {
    const server = createDoorServer({ db, deps, log });
    server.on("error", (err) => log(`[report-readers] WARN fd ${fd}: ${err?.message || err}`));
    try {
      server.listen({ fd });
    } catch (err) {
      try { log(`[report-readers] WARN fd ${fd}: ${err?.message || err}`); } catch { /* a logger that throws */ }
      return null;
    }
    // The kind is known now, and nothing has been accepted: a unix socket is the door, a TCP fd is closed
    // (and the gate stays shut, so nothing queued on it is ever served).
    if (!server.listening) return server;
    if (!checkDoorListener(server, `fd ${fd}`, log)) return server;
    log(`[report-readers] listening on ${REPORTS_DOOR_SOCKET_UNIT}`);
    return server;
  } catch (err) {
    try {
      log(`[report-readers] WARN could not prepare the activation listener: ${err?.message || err}`);
    } catch { /* a logger that throws must not take boot down */ }
    return null;
  }
}

const CLOSED = Symbol.for("crow.report-readers.closed");

/**
 * Close the door listener and return a promise for its `close` event, the way `closeProxySocket` does for
 * the proxy socket (the gateway's drain waits on every listener it started). Idempotent; never throws.
 * `force` additionally severs live connections, which are at most one line each.
 *
 * @param {import("node:net").Server|null} server
 * @param {{force?: boolean}} [options]
 * @returns {Promise<void>}
 */
export function closeDoorServer(server, { force = false } = {}) {
  if (!server) return Promise.resolve();
  let closed = server[CLOSED];
  if (!closed) {
    closed = new Promise((resolve) => {
      try {
        server.once("close", () => resolve());
        server.close();
      } catch { resolve(); }
    });
    try { server[CLOSED] = closed; } catch { /* frozen server: the promise still settles */ }
  }
  if (force) {
    let live = [];
    try { live = [...(server[SOCKETS] ?? [])]; } catch { live = []; }
    for (const socket of live) {
      try { socket.destroy(); } catch { /* already gone */ }
    }
    try { server.closeAllConnections?.(); } catch { /* not an http server */ }
  }
  return closed;
}

export default createDoorHandler;