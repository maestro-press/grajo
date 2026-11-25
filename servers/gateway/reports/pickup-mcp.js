/**
 * A report pickup's door: a narrow MCP server at `/report-pickup/mcp` — the THREE tools a pickup turn may
 * call, and nothing else.
 *
 * A pickup is a bot turn that reads a batch of new comments on one report's artifact and answers them.
 * The comments come from people OUTSIDE Crow (a recipient who opened a mailed link, the owner's own
 * notes), so the turn's whole reach is deliberately three verbs:
 *
 *   report_reply(threadId, text)   a reply in one thread of THIS pickup's batch, as the report's bot
 *   report_make_card(title, description)   a card on the report's bot's board, tagged with the report
 *   report_propose_change(summary, recipePatch)   one suggested change, which lands as the report's
 *                                  pending free change for the owner's one-tap Apply
 *
 * There is no send, schedule, apply, fetch or credential tool here, and the card and the change are done
 * through functions boot injects (see `createPickupMcpServer`), never imported. The module imports no
 * mail send path, no schedule service, no delivery seam, no run engine, no approvals-deps builder and no
 * schedule hook, and nothing in its import closure reaches `scripts/pi-bots/bridge.mjs`, the sharing
 * identity module or `secret-box.js`: tests/mail-no-tap-invariant.test.js case (d) reads that from the
 * source. That is also why the report row is re-read with one narrow SELECT (see `reportColumns`) rather
 * than through `./store.js`, whose block registry reaches the sharing identity module — do not "tidy"
 * that import back in without re-reading that test. A reply is a row in the artifacts bundle's own
 * comment table and nothing more; a recipient sees it only when they reopen their own link.
 *
 * TWO CREDENTIALS, BOTH REQUIRED (the mount guard below, installed by boot/mcp-mounts.js in front of the
 * MCP mount exactly as the sharing and reports doors' guards are):
 *
 *   1. an `rpk_` bearer that `verifyPickupToken` knows (reports/pickup-token.js). It is minted in this
 *      process's memory for one pickup, names the report, the pickup, the bot the turn runs as, the exact
 *      thread/comment batch and the artifact that batch lives on, and is revoked when the turn ends. No
 *      other token family opens this mount, and this token opens no other mount.
 *   2. `X-Crow-Actor-*` headers carrying a `report-pickup` signature (scripts/pi-bots/actor-sig.mjs) over
 *      the SAME `<pickupId>:<turnId>`, so a block signed for another pickup or another turn of the same
 *      pickup admits nothing. The actor id must equal the token's own `botId` before the signature is
 *      checked, so another bot's valid signature admits nothing either.
 *
 * An unsigned or unverified caller is refused with 401 on EVERY path of the mount, tools/list included,
 * and there is no "unattributed bot" mode. The claims the guard pinned reach a handler as
 * `authInfo.extra`, so a tool's report, pickup, bot, artifact and thread set never come from its
 * arguments: there is no argument for a report, an artifact, an author, a taint flag or a bot at all, and
 * a handler with no claims fails closed.
 *
 * WHAT A REPLY IS CHECKED AGAINST, in this order, every refusal the same fixed short code
 * (`not_found`) so the door is no oracle for another report's ids:
 *
 *   a. the thread is one of THIS pickup's threads (exact string match, after a trim);
 *   b. the report row still names this pickup's artifact and this pickup's bot, and is still `live`
 *      (read fresh, as three columns);
 *   c. the thread really belongs to that artifact (the artifacts bundle's own thread list) and is not
 *      `resolved` — a closed thread takes no answer;
 *   d. this pickup has not already answered that thread: its own in-memory reply ledger (see
 *      `reserveReplySlot` in reports/pickup-token.js) allows ONE reply per thread per pickup, because a
 *      pickup turn reads the whole batch at once and would otherwise be one turn talking twice;
 *   e. the reply is written through the bundle's `addComment` as `{kind: "bot", id: <the report's bot>}`
 *      with `tainted: true`, ALWAYS. A pickup turn reads a MIXED batch — comments from people outside
 *      Crow beside the owner's own notes — so nothing a thread's own rows say can prove this turn's
 *      context clean, and only the turn that read a mixed batch could claim otherwise. That is the same
 *      rule the artifacts bundle applies to its own locked replies (R3-H1: a reply by a turn with no
 *      clean session record is untrusted text), applied here to every pickup reply, in every thread.
 *
 * THE BUNDLE IS LOADED AT RUNTIME, NOT IMPORTED: Crow Artifacts is a bundle installed at runtime, so its
 * `comments.js` is imported by PATH from the installed copy (recipient-comments.js's own precedent) and
 * cached per process. `deps.comments` wins, so a test drives the bundle module from this repo without an
 * installed copy.
 */
import { z } from "zod";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createDbClient } from "../../db.js";
import { resolveCrowHome } from "../../shared/crow-home.js";
import {
  verifyPickupToken, reserveReplySlot, releaseReplySlot, reserveCardSlot, releaseCardSlot, NO_THREAD_KEY,
  reserveProposalSlot, releaseProposalSlot,
} from "./pickup-token.js";
import { applyProposablePatch } from "./pickup-proposable.js";
import { verifyReportPickupActorSig } from "../../../scripts/pi-bots/actor-sig.mjs";

/** The mount prefix and the one path a bot's config names. */
export const PICKUP_MCP_PREFIX = "/report-pickup";
export const PICKUP_DOOR_PATH = "/report-pickup/mcp";

/** The actor-signature kind this mount accepts; its own MAC domain in actor-sig.mjs. */
export const PICKUP_ACTOR_KIND = "report-pickup";

/** The token scope a request carries once the guard admitted it (local-token.js's path scope). */
export const PICKUP_TOKEN_SCOPE = "report-pickup";

/** The three tools, and the whole surface of this mount. Nothing here matches a send or schedule verb. */
export const PICKUP_TOOL_NAMES = Object.freeze(["report_reply", "report_make_card", "report_propose_change"]);

/** The most characters a card's title and description may hold. */
export const MAX_CARD_TITLE_CHARS = 200;
export const MAX_CARD_DESCRIPTION_CHARS = 4000;

/**
 * The tags every pickup card carries: `report-pickup` is the marker the bot's own turns key on (its board
 * context leaves such a card out, and a dispatch brief quotes its text as untrusted), then the report.
 * Spelled the same in scripts/pi-bots/tracker.mjs and card-brief.mjs (tests/reports-pickup-card-isolation).
 * ACCEPTED LIMIT: a later UNLOCKED bot turn can edit a card's tags through the board tools; that is the
 * same class as bots' existing tasks.db write access, and this tag is a guard, not a boundary.
 */
export const PICKUP_CARD_TAG = "report-pickup";

/** The most characters a suggested change's summary may hold. */
export const MAX_SUMMARY_CHARS = 1000;

/**
 * Copy C3: the last line of every card a pickup makes, in the owner's language. Appended by THIS module
 * (never by the model), on its own line, after whatever the model wrote.
 */
export const CARD_C3_LINE = Object.freeze({
  en: "Anything submitted outside Crow must be done by a person.",
  es: "Todo lo que se envíe fuera de Crow debe hacerlo una persona.",
});

/** The most characters one reply may hold. Mirrors the bundle's `LIMITS.commentChars`. */
export const MAX_REPLY_CHARS = 4000;

/**
 * The one report status word a pickup may answer: `REPORT_LIVE` (`"live"`) in
 * servers/gateway/reports/approvals.js, spelled out here instead of imported — that module's dependency
 * chain reaches the sharing identity module, which this door must never reach
 * (tests/mail-no-tap-invariant.test.js case (d)). A draft or paused report delivers nothing, so its
 * comment batch is not live either and takes no reply.
 */
const REPORT_LIVE = "live";

/* ------------------------------------------------------------------------- results */

/** One MCP text block holding `data` as JSON. Never HTML, never a second block. */
function ok(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

/** A refusal carrying a fixed short code only: never a value from the call, never a library message. */
function failed(code) {
  return { content: [{ type: "text", text: JSON.stringify({ error: code }) }], isError: true };
}

/** A column as a string; null and undefined are the empty string, like every reader in this tree. */
function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** An Error carrying one of this module's own codes (`artifacts_missing`). */
function fail(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

/* -------------------------------------------------------------------- mount guard */

function headerValue(headers, name) {
  const value = headers ? headers[name] : undefined;
  const first = Array.isArray(value) ? value[0] : value;
  return first == null ? null : String(first);
}

function bearerOf(req) {
  const header = req?.headers?.authorization;
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return null;
  const token = header.slice("Bearer ".length).trim();
  return token || null;
}

function unauthorized(res) {
  res.status(401).json({ jsonrpc: "2.0", id: null, error: { code: -32001, message: "unauthorized" } });
}

/**
 * The scoped `req.auth` a pickup request carries once the guard admitted it: the same shape
 * `localOperatorAuth` in servers/gateway/local-token.js builds (token and client id `local-mcp`, the
 * one operator scope list, the claims in `extra`, and `tokenScope` written LAST so a claims object can
 * never restate or widen the scope), written here rather than imported.
 *
 * WHY NOT JUST IMPORT IT: `local-token.js` statically imports the settings registry, which reaches
 * `servers/sharing/instance-sync.js` and through it the sharing identity module. This door must reach
 * neither that nor `secret-box.js` — a pickup answers outside people's comments and nothing else — and
 * tests/mail-no-tap-invariant.test.js walks this module's whole import closure to prove it, so the
 * handful of fields below are spelled out instead. `applyLocalTokenAuth` (boot's shared middleware) sees
 * a same-scope `req.auth` on this request and keeps it, claims included.
 *
 * @param {object} claims the token's claims, already copied
 * @returns {object} a `req.auth` the MCP mount hands a handler as `authInfo`
 */
function scopedLocalAuth(claims) {
  return {
    token: "local-mcp",
    clientId: "local-mcp",
    scopes: ["mcp:tools"],
    expiresAt: Math.floor(Date.now() / 1000) + 300,
    extra: { ...claims, tokenScope: PICKUP_TOKEN_SCOPE },
  };
}

/**
 * The auth wrapper `boot/mcp-mounts.js` installs in front of
 * `mountMcpServer(app, "/report-pickup", …)`. A request is admitted when BOTH hold:
 *
 *   1. its bearer is a live `rpk_` pickup token (`verifyPickupToken`), which names the report, the
 *      pickup, the turn and the bot the turn runs as;
 *   2. `x-crow-actor-kind: report-pickup` with `x-crow-actor-id` and `x-crow-actor-sig`, the signature
 *      computed over `<pickupId>:<turnId>` of THAT token for that same bot.
 *
 * The signature is made over the token's own pickup and turn, so a block signed for pickup B — or for
 * another turn of this pickup, or for another bot — is refused even when its bearer is a live token for
 * pickup A. The guard re-verifies the bearer itself rather than trusting `req.localTokenAuth` alone, so
 * no other token family (and no other path that sets a local-token flag) can open this mount.
 *
 * On success it pins the claims for the MCP mount: `req.localTokenAuth` (what
 * `applyLocalTokenAuth` reads) and `req.auth` (for a `--no-auth` gateway where nothing else would build
 * it). The arrays are COPIES, so nothing downstream can widen the batch the token proved.
 *
 * @param {{verifyToken?: (token: string) => object|null, verifyActor?: Function}} [deps] test seams
 * @returns {(req: object, res: object, next: Function) => unknown}
 */
export function pickupMountAuth(deps = {}) {
  const verifyToken = typeof deps.verifyToken === "function" ? deps.verifyToken : verifyPickupToken;
  const verifyActor = typeof deps.verifyActor === "function" ? deps.verifyActor : verifyReportPickupActorSig;
  const log = typeof deps.log === "function" ? deps.log : (line) => console.log(line);
  // One operator line per pickup the first time its signed caller reaches the door (bounded; value-free).
  const seen = new Set();

  return (req, res, next) => {
    const token = bearerOf(req);
    const pickup = token ? verifyToken(token) : null;
    if (!pickup || typeof pickup.turnId !== "string" || pickup.turnId === "") return unauthorized(res);

    const headers = req.headers || {};
    const kind = headerValue(headers, "x-crow-actor-kind");
    const botId = headerValue(headers, "x-crow-actor-id");
    const sig = headerValue(headers, "x-crow-actor-sig");
    // The token names the bot its turn runs as: any other actor id is not this turn's caller, whatever
    // signature it carries.
    if (botId == null || botId !== pickup.botId) return unauthorized(res);
    let signed = false;
    try {
      signed = kind === PICKUP_ACTOR_KIND && Boolean(sig)
        && verifyActor({
          botId, pickupId: pickup.pickupId, turnId: pickup.turnId, sig,
        }) === true;
    } catch {
      signed = false;
    }
    if (!signed) return unauthorized(res);

    if (!seen.has(pickup.pickupId)) {
      if (seen.size >= 1000) seen.clear();
      seen.add(pickup.pickupId);
      try { log(`[report-pickup] door session opened ${pickup.pickupId}`); } catch { /* logging never blocks the door */ }
    }
    req.localTokenAuth = {
      token: "local-mcp",
      scope: PICKUP_TOKEN_SCOPE,
      reportId: pickup.reportId,
      pickupId: pickup.pickupId,
    };
    req.auth = scopedLocalAuth({
      reportId: pickup.reportId,
      pickupId: pickup.pickupId,
      botId: pickup.botId,
      artifactId: pickup.artifactId,
      threadIds: [...pickup.threadIds],
      commentIds: [...pickup.commentIds],
    });
    return next();
  };
}

/* ------------------------------------------------------------------------ claims */

/** A claim that must be a non-empty string, or null. */
function claimId(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

/** A claim that must be a list of non-empty strings (copied, trimmed), or null. */
function claimIds(value) {
  if (!Array.isArray(value)) return null;
  const out = [];
  for (const entry of value) {
    const id = claimId(entry);
    if (id === null) return null;
    out.push(id);
  }
  return out;
}

/**
 * The claims the guard pinned on this request, or null. Fail closed: a handler with no claims refuses
 * rather than guessing which report, artifact or bot to act as.
 */
export function claimsOf(extra) {
  const auth = extra?.authInfo;
  if (!auth || auth.clientId !== "local-mcp") return null;
  const claims = auth.extra;
  if (!claims || claims.tokenScope !== PICKUP_TOKEN_SCOPE) return null;
  const reportId = claimId(claims.reportId);
  const pickupId = claimId(claims.pickupId);
  const botId = claimId(claims.botId);
  const artifactId = claimId(claims.artifactId);
  if (!reportId || !pickupId || !botId || !artifactId) return null;
  const threadIds = claimIds(claims.threadIds);
  const commentIds = claimIds(claims.commentIds);
  if (!threadIds || !commentIds) return null;
  return { reportId, pickupId, botId, artifactId, threadIds, commentIds };
}

/* --------------------------------------------------------- the artifacts comments */

let cachedComments = null;

/**
 * The artifacts bundle's `comments.js`: the functions that own threads and comments, caps included.
 *
 * `deps.comments` wins (a test passes the bundle module from this repo), then the installed copy,
 * imported by PATH the way the artifact bridge loads `store.js`. An instance with no installed bundle
 * answers `artifacts_missing`, which a caller maps to `other`: a reply that did not go through says so
 * rather than inventing a thread.
 *
 * @param {object} [deps]
 * @returns {Promise<object>} `{addThread, addComment, setThreadStatus, listThreads}`
 * @throws {Error} `artifacts_missing`
 */
async function commentsRuntime(deps = {}) {
  const given = deps == null ? {} : deps;
  if (given.comments) return given.comments;
  if (cachedComments) return cachedComments;
  const dir = join(resolveCrowHome(), "bundles", "artifacts", "server");
  if (!existsSync(join(dir, "comments.js"))) throw fail("artifacts_missing");
  cachedComments = await import(pathToFileURL(join(dir, "comments.js")).href);
  return cachedComments;
}

/** Test seam: forget the comments module this process cached. */
export function _resetCommentsRuntimeForTest() {
  cachedComments = null;
}

/**
 * The status word of one thread, read by the narrowest query. Only used when the bundle's own thread list
 * did not carry a status (an alternate `deps.comments` seam): the bundle's `listThreads` selects the whole
 * row, so an installed copy answers this without the extra read. Null when it cannot be read, which the
 * caller refuses on.
 *
 * @param {object} db
 * @param {string} artifactId
 * @param {number} threadId
 * @returns {Promise<string|null>}
 */
async function readThreadStatus(db, artifactId, threadId) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT status FROM artifact_threads WHERE id = ? AND artifact_id = ?",
      args: [threadId, artifactId],
    });
    const value = Array.isArray(rows) && rows[0] ? rows[0].status : null;
    return typeof value === "string" ? value : null;
  } catch {
    return null;
  }
}

/* --------------------------------------------------------------------- the reply */

/**
 * The three columns a pickup re-reads from the report row before it writes: the artifact the report
 * currently presents, the bot it currently belongs to, and its status. All three are read FRESH, because
 * any may have moved since the token was minted (a report can be re-pointed, handed to another bot, or
 * paused/back to draft while a pickup is in flight).
 *
 * ONE NARROW SELECT, NOT `store.js`'s `getReport`: that module's block registry reaches the approvals
 * module's provider resolver and, through it, the sharing identity module. This door answers outside
 * people's comments, so its import closure must reach neither that nor `secret-box.js` (pinned by
 * tests/mail-no-tap-invariant.test.js case (d), the same rule the reports door's send/schedule
 * exclusion has). Nothing else on the row is read here — no recipe, no address, no credential.
 *
 * @param {object} db
 * @param {string} reportId
 * @returns {Promise<{artifact_id: string|null, bot_id: string|null, status: string|null}|null>}
 */
async function reportColumns(db, reportId) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT artifact_id, bot_id, status, project_id, recipe_rev, pending_free_change, live_rev, sources_hash FROM reports WHERE id = ?",
      args: [reportId],
    });
    return rows[0] ?? null;
  } catch {
    return null;
  }
}

/**
 * The whole of `report_reply`, without the MCP plumbing, so a test drives the same code the tool does.
 *
 * @param {object} db the libsql-style client
 * @param {{reportId: string, pickupId: string, botId: string, artifactId: string, threadIds: string[],
 *   commentIds: string[]}} claims the pickup token's claims
 * @param {{threadId?: unknown, text?: unknown}} args
 * @param {{comments?: object}} [deps] the `deps.comments` seam
 * @returns {Promise<object>} an MCP tool result
 */
export async function replyFromPickup(db, claims, args = {}, deps = {}) {
  const threadId = typeof args.threadId === "string" ? args.threadId.trim() : "";
  // (a) The thread must be one THIS pickup was minted for. A thread that exists on the artifact but is
  // not in the batch answers exactly what a nonexistent one answers: `not_found`, no oracle.
  if (!threadId || !claims.threadIds.includes(threadId)) return failed("not_found");

  // (b) The report row must still be the pickup's: same artifact, same bot, still live. A report
  // re-pointed at another artifact (or handed to another bot) since the token was minted refuses every
  // reply, and so does one that is no longer delivering.
  const report = await reportColumns(db, claims.reportId);
  if (!report) return failed("not_found");
  if (text(report.artifact_id) !== claims.artifactId) return failed("not_found");
  if (text(report.bot_id) !== claims.botId) return failed("not_found");
  // A batch of comments belongs to a report that is delivering. A draft was never sent and a paused one
  // is stopped, so neither has a live batch to answer: both answer exactly what a nonexistent report does.
  if (text(report.status) !== REPORT_LIVE) return failed("not_found");

  const numericId = Number(threadId);
  if (!Number.isInteger(numericId) || numericId < 1) return failed("not_found");

  let comments;
  try {
    comments = await commentsRuntime(deps);
  } catch {
    return failed("other");
  }

  // (c) The thread really belongs to that artifact, read through the bundle's own thread list. A thread
  // on ANOTHER artifact is answered as missing, so a token can never write outside its own report. The
  // list carries the thread's status; a seam that does not is read once, by the narrowest query.
  let belongs = false;
  let status = null;
  try {
    const threads = await comments.listThreads(db, claims.artifactId);
    const mine = Array.isArray(threads) ? threads.find((thread) => Number(thread?.id) === numericId) : null;
    belongs = Boolean(mine);
    status = typeof mine?.status === "string" ? mine.status : null;
  } catch {
    return failed("not_found");
  }
  if (!belongs) return failed("not_found");
  if (status === null) status = await readThreadStatus(db, claims.artifactId, numericId);
  // A resolved thread is closed: its reader is done with it, and an answer would land where nobody is
  // looking. An unreadable status is not "open" either (fail closed), and both answer `not_found`.
  if (status === null || status === "resolved") return failed("not_found");

  const body = typeof args.text === "string" ? args.text.trim() : "";
  // The schema refuses an empty or oversized body; a direct caller that skips it still writes nothing.
  if (!body || body.length > MAX_REPLY_CHARS) return failed("other");

  // (d) One reply per thread per pickup. The slot is taken AFTER every check and BEFORE the write, and
  // given back when the write itself fails, so a failed reply can be retried but a written one cannot be
  // answered twice by the same pickup.
  if (!reserveReplySlot(claims.pickupId, threadId)) return failed("already_replied");
  let added;
  try {
    added = await comments.addComment(db, {
      threadId: numericId,
      text: body,
      // The author is the report's own bot, from the token — never from a call.
      author: { kind: "bot", id: claims.botId },
      // ALWAYS tainted: this turn read the whole batch, recipients' words beside the owner's own, so it
      // cannot claim a clean context for any reply it writes (the bundle's R3-H1 rule for a locked turn).
      tainted: true,
    });
  } catch (err) {
    releaseReplySlot(claims.pickupId, threadId);
    const code = String(err && err.code);
    if (code === "rate_limited") return failed("rate_limited");
    if (code === "not_found") return failed("not_found");
    return failed("other");
  }
  return ok({ ok: true, commentId: Number(added?.commentId) });
}


/* ---------------------------------------------------------------- the report's own state */

/**
 * The report row, checked the way a reply checks it: the same artifact and bot the token was minted for,
 * and still live. Every refusal is `not_found`, the one code that is no oracle for another report's ids.
 *
 * @returns {Promise<object|null>} the narrow row, or null
 */
async function liveReportOf(db, claims) {
  const report = await reportColumns(db, claims.reportId);
  if (!report) return null;
  report.id = claims.reportId;
  if (text(report.artifact_id) !== claims.artifactId) return null;
  if (text(report.bot_id) !== claims.botId) return null;
  if (text(report.status) !== REPORT_LIVE) return null;
  return report;
}

/** The owner's dashboard language (`es` or else `en`), read from the setting the bundle alerts read. */
async function ownerLanguageOf(db) {
  try {
    const { rows } = await db.execute({ sql: "SELECT value FROM dashboard_settings WHERE key = 'language'", args: [] });
    return text(rows[0] == null ? "" : rows[0].value) === "es" ? "es" : "en";
  } catch {
    return "en";
  }
}

/**
 * The head revision: its recipe (parsed), who saved it and its sources hash, and the LIVE revision's sources
 * hash, or null. Narrow SELECTs on the revision table only.
 */
async function headOf(db, report) {
  const headRev = Number(report.recipe_rev);
  if (!Number.isInteger(headRev) || headRev < 1) return null;
  try {
    const { rows } = await db.execute({
      sql: "SELECT recipe_json, author_kind, sources_hash FROM report_recipe_revisions WHERE report_id = ? AND rev = ?",
      args: [text(report.id), headRev],
    });
    const row = rows[0];
    const recipe = row ? JSON.parse(text(row.recipe_json)) : null;
    if (recipe == null || typeof recipe !== "object" || Array.isArray(recipe)) return null;
    let liveSources = null;
    const liveRev = Number(report.live_rev);
    if (Number.isInteger(liveRev) && liveRev >= 1) {
      const live = await db.execute({
        sql: "SELECT sources_hash FROM report_recipe_revisions WHERE report_id = ? AND rev = ?",
        args: [text(report.id), liveRev],
      });
      liveSources = live.rows[0] ? text(live.rows[0].sources_hash) : null;
    }
    return { rev: headRev, recipe, authorKind: text(row.author_kind), sourcesHash: text(row.sources_hash), liveRev, liveSources };
  } catch {
    return null;
  }
}

/* ---------------------------------------------------------------------- the card */

/**
 * The whole of `report_make_card`, without the MCP plumbing.
 *
 * The card goes on the report's bot's own board (`actions.createCard`, injected by boot — this module
 * must not import the board service, whose closure reaches the bot runtime). It is tagged
 * `report:<reportId>`, refused unless the bot's home project IS the report's project, and its
 * description always ends with the C3 line in the owner's language, appended here.
 *
 * @param {object} db
 * @param {object} claims the pickup token's claims
 * @param {{title?: unknown, description?: unknown, threadId?: unknown}} args
 * @param {{actions?: {createCard?: Function}}} [deps]
 */
export async function cardFromPickup(db, claims, args = {}, deps = {}) {
  const createCard = deps.actions && typeof deps.actions.createCard === "function" ? deps.actions.createCard : null;
  if (!createCard) return failed("other");
  const title = typeof args.title === "string" ? args.title.trim() : "";
  const description = typeof args.description === "string" ? args.description.trim() : "";
  if (!title || title.length > MAX_CARD_TITLE_CHARS) return failed("other");
  if (!description || description.length > MAX_CARD_DESCRIPTION_CHARS) return failed("other");
  let threadKey = NO_THREAD_KEY;
  if (args.threadId !== undefined) {
    const threadId = typeof args.threadId === "string" ? args.threadId.trim() : "";
    if (!threadId || !claims.threadIds.includes(threadId)) return failed("not_found");
    threadKey = threadId;
  }
  const report = await liveReportOf(db, claims);
  if (!report) return failed("not_found");

  if (!reserveCardSlot(claims.pickupId, threadKey)) return failed("card_limit");
  let made;
  try {
    const lang = await ownerLanguageOf(db);
    made = await createCard(db, {
      botId: claims.botId,
      reportId: claims.reportId,
      reportProjectId: report.project_id,
      title,
      // The C3 line is the server's, on its own last line, after everything the model wrote.
      description: `${description}\n\n${CARD_C3_LINE[lang]}`,
      tags: `${PICKUP_CARD_TAG},report:${claims.reportId}`,
    });
  } catch (err) {
    releaseCardSlot(claims.pickupId, threadKey);
    const code = err && err.code;
    return failed(code === "project_mismatch" || code === "card_limit" ? code : "other");
  }
  return ok({ ok: true, cardId: Number(made?.cardId) });
}

/* ------------------------------------------------------------- the suggested change */

/**
 * The whole of `report_propose_change`, without the MCP plumbing.
 *
 * The patch is judged by the ALLOW-list in `pickup-proposable.js`, merged over the report's CURRENT head
 * recipe, and saved by `actions.saveBotRecipe` (`botSaveRecipe` in approvals.js, injected by boot for the
 * same reason as the card). It lands as the report's pending free change, which the owner applies with
 * one tap on the report card; nothing here applies, sends or schedules anything. A pending change that
 * is already there is never overwritten (`change_pending`), and a pickup suggests at most once.
 *
 * @param {object} db
 * @param {object} claims
 * @param {{summary?: unknown, recipePatch?: unknown}} args
 * @param {{actions?: {saveBotRecipe?: Function, notifyChange?: Function}}} [deps]
 */
export async function proposeFromPickup(db, claims, args = {}, deps = {}) {
  const actions = deps.actions || {};
  if (typeof actions.saveBotRecipe !== "function") return failed("other");
  const summary = typeof args.summary === "string" ? args.summary.trim() : "";
  if (!summary || summary.length > MAX_SUMMARY_CHARS) return failed("other");
  const report = await liveReportOf(db, claims);
  if (!report) return failed("not_found");
  if (Number(report.pending_free_change) === 1) return failed("change_pending");

  const head = await headOf(db, report);
  if (!head) return failed("other");
  const judged = applyProposablePatch(args.recipePatch, head.recipe);
  if (!judged.ok) return failed("not_proposable");
  // A head the owner has not applied yet is a change waiting too, whoever saved it: a bot revision newer
  // than the live one (it needs a go-live, so no Apply is offered), or any head whose sources differ from
  // the live set's. Merging on top of either would bury it, so the pickup waits.
  if (head.authorKind === "bot" && !(head.liveRev >= head.rev)) return failed("change_pending");
  if (head.liveSources !== null && head.sourcesHash !== head.liveSources) return failed("change_pending");

  if (!reserveProposalSlot(claims.pickupId)) return failed("already_proposed");
  let saved;
  try {
    // `expectedRev` is the head this recipe was merged from: a save that landed since refuses this one.
    saved = await actions.saveBotRecipe(db, { reportId: claims.reportId, recipe: judged.recipe, expectedRev: head.rev });
  } catch (err) {
    releaseProposalSlot(claims.pickupId);
    const code = err && err.code;
    return failed(code === "bad_recipe" ? "not_proposable" : code === "conflict" ? "change_pending" : "other");
  }
  // The owner is told only of a change they can apply with one tap.
  if (saved?.pendingFreeChange === true && typeof actions.notifyChange === "function") {
    try {
      await actions.notifyChange(db, { reportId: claims.reportId, lang: await ownerLanguageOf(db) });
    } catch { /* the change is saved; a missed notice is not a failed suggestion */ }
  }
  return ok({ ok: true, rev: Number(saved?.rev), pendingFreeChange: saved?.pendingFreeChange === true });
}

/* --------------------------------------------------------------------- the server */

/**
 * One reply's argument object, `.strict()`: a `reportId`, an `artifactId`, an `author`, a `botId` or a
 * `tainted` flag is not merely ignored, it is refused. The tool cannot name another report, write as
 * another author, or claim its own text is clean.
 */
const REPLY_SCHEMA = z.object({
  threadId: z.string().describe("The thread to reply in: one of this pickup's threads"),
  text: z.string().trim().min(1).max(MAX_REPLY_CHARS)
    .describe("The reply itself, 1 to 4,000 characters"),
}).strict();

const CARD_SCHEMA = z.object({
  title: z.string().trim().min(1).max(MAX_CARD_TITLE_CHARS).describe("The card's title, 1 to 200 characters"),
  description: z.string().trim().min(1).max(MAX_CARD_DESCRIPTION_CHARS)
    .describe("What the owner should do and why, 1 to 4,000 characters"),
  threadId: z.string().optional().describe("Optional: the thread this card is about; one card per thread"),
}).strict();

/** `recipePatch` is checked by the allow-list, not by this schema, so a refused patch answers `not_proposable`. */
const PROPOSE_SCHEMA = z.object({
  summary: z.string().trim().min(1).max(MAX_SUMMARY_CHARS).describe("One or two sentences on what the change is for"),
  recipePatch: z.unknown().describe("{blocks: [{id, settings}]}: new settings for blocks the report already has"),
}).strict();

/**
 * Build the `crow-report-pickup` door server. Every handler runs on a db client it opens for the call
 * and closes in `finally`, reads the claims the guard pinned, and answers one JSON text block.
 *
 * `verifyActor` is the door's OWN credential (the `report-pickup` actor signature), and it is checked by
 * the MOUNT GUARD (`pickupMountAuth`), never here: boot hands the guard and this factory the same dep
 * object (boot/mcp-mounts.js), so the verifier that makes `/report-pickup` a SIGNED bot door is named
 * where the mount is. It is taken here so the dep set is one object, and a caller that passes something
 * other than a function is told.
 *
 * @param {{createDb?: Function, verifyActor?: Function, comments?: object, actions?: object}} [options]
 *   `comments` is the test/alternate seam for the artifacts bundle's own `comments.js`; `actions` is what
 *   the card and the suggested change are done WITH (`createCard`, `saveBotRecipe`, `notifyChange`,
 *   built in servers/gateway/reports/pickup-actions.js and handed in by boot/mcp-mounts.js). They are
 *   injected, never imported, because the board service and the approvals module reach the bot runtime
 *   and the sharing identity module, which this door must not (tests/mail-no-tap-invariant.test.js (d)).
 */
export function createPickupMcpServer(options = {}) {
  if (options.verifyActor !== undefined && typeof options.verifyActor !== "function") {
    throw new TypeError("createPickupMcpServer: verifyActor must be the door's actor verifier (pickupMountAuth runs it)");
  }
  const openDb = typeof options.createDb === "function" ? options.createDb : createDbClient;
  const commentsDep = options.comments ?? null;
  const actionsDep = options.actions ?? null;

  const server = new McpServer({ name: "crow-report-pickup", version: "0.1.0" });

  server.registerTool("report_reply", {
    description: "Reply in one thread of this pickup's comment batch, as the report's own bot. `threadId` must be one of the threads this pickup was given and `text` is the reply the thread's reader will see. Nothing is emailed, and no other thread, report or author can be named.",
    inputSchema: REPLY_SCHEMA,
  }, async (args, extra) => {
    const claims = claimsOf(extra);
    if (!claims) return failed("unauthorized");
    const db = openDb();
    try {
      return await replyFromPickup(db, claims, args || {}, { comments: commentsDep });
    } catch {
      return failed("other");
    } finally {
      try { db.close(); } catch { /* already closed */ }
    }
  });

  server.registerTool("report_make_card", {
    description: "Make a card on this report's bot's board for work a comment asks the owner to do. `title` and `description` are plain text; the card is tagged with this report, and a person must do anything that has to be submitted outside Crow. At most 3 cards per pickup, one per thread (`threadId`, optional, names the thread it is about).",
    inputSchema: CARD_SCHEMA,
  }, async (args, extra) => {
    const claims = claimsOf(extra);
    if (!claims) return failed("unauthorized");
    const db = openDb();
    try {
      return await cardFromPickup(db, claims, args || {}, { actions: actionsDep });
    } catch {
      return failed("other");
    } finally {
      try { db.close(); } catch { /* already closed */ }
    }
  });

  server.registerTool("report_propose_change", {
    description: "Suggest, once, a change to how this report is laid out: `summary` says why, `recipePatch` is {blocks: [{id, settings}]} with new settings for blocks the report already has (text, table, cards, sort, filter and map blocks only). The owner reviews it and applies it with one tap; nothing changes until then. Sources, recipients, hosts, credentials and the schedule cannot be changed this way.",
    inputSchema: PROPOSE_SCHEMA,
  }, async (args, extra) => {
    const claims = claimsOf(extra);
    if (!claims) return failed("unauthorized");
    const db = openDb();
    try {
      return await proposeFromPickup(db, claims, args || {}, { actions: actionsDep });
    } catch {
      return failed("other");
    } finally {
      try { db.close(); } catch { /* already closed */ }
    }
  });

  return server;
}