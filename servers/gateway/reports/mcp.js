/**
 * The bot reports door: a narrow MCP server at `/reports/mcp` — the bots' tools for BUILDING a report,
 * and nothing else.
 *
 * A report is the owner's: it reads the owner's sources, mails the owner's recipients and can go live
 * only behind an owner approval (reports/approvals.js, reports/steps.js, reports/source-approvals.js).
 * So this door proposes; it never approves. Nine tools, and nothing else:
 *
 *   crow_report_create               a draft report in the bot's own project
 *   crow_report_set_recipe           a draft revision of its recipe (a bot save)
 *   crow_report_set_schedule         a schedule PROPOSAL in the report's state, never a schedules row
 *   crow_report_propose_recipient    a proposed recipient row, never an approved one
 *   crow_report_propose_host         a proposed host row
 *   crow_report_propose_step         a proposed revision of one custom step
 *   crow_report_request_credential   the LABEL a bot hands to crow_request_secret, never a secret
 *   crow_report_preview              a preview request in the run queue, answered as an id and nothing more
 *   crow_report_status               status and counts only: no content, no address, no secret
 *
 * There is no approve, no go live, no apply, no add recipient, no credential read and no project id:
 * every tool's input is a closed object (`z.object({...}).strict()`), and a caller that names a project
 * is refused by validation before a handler runs. The project a call lands in is derived ONLY from the
 * verified bot (`homeProjectOf`), and a `reportId` that belongs to another project answers exactly what
 * a missing or a malformed id answers (`not_found`), so the door is no oracle for other projects' ids.
 *
 * TWO CREDENTIALS, BOTH REQUIRED (the mount guard below, installed by boot/mcp-mounts.js in front of the
 * MCP mount exactly as the sharing door's guard is):
 *
 *   1. an `REPORTS_TOKEN` bearer — a path-scoped family token (servers/gateway/local-token.js), rotated
 *      at every gateway boot, accepted on `/reports/(mcp|sse|messages)` and nowhere else. No other token
 *      family opens this door, and this token opens no other mount.
 *   2. a signed actor of kind `"reports"` (scripts/pi-bots/actor-sig.mjs) over
 *      (bot, thread, gateway) — the same per-boot in-memory key the board, artifacts and sharing doors
 *      use, with its own MAC domain so none of those signatures replays here, nor this one there.
 *
 * An unsigned or unverified caller is refused with 401 on EVERY path of the mount, tools/list included,
 * and there is no "unattributed bot" mode. The claims the guard pinned reach a handler as
 * `authInfo.extra` (`{botId, threadId, gatewayType, tokenScope}`), so a tool never takes the bot's
 * identity from its arguments, and a handler with no claims fails closed.
 *
 * WHAT THE DOOR DOES NOT REACH: no mail send path, no delivery seam, no run engine, no schedule hook and
 * no approvals-deps builder. `requestRun` only leaves a row in `report_run_requests`, which the
 * scheduler hook claims on its next tick; results come back to a bot as status and counts, never as
 * content. The import closure is pinned by tests/mail-no-tap-invariant.test.js case (d).
 *
 * THE THREE RATE CAPS, all answered with one fixed sentence code (`rate_limited`): `crow_report_create`
 * refuses a bot that already made ten reports in the last day; `crow_report_preview` refuses a report
 * whose queue already holds three unclaimed requests, or that was previewed twenty times in the last
 * day. Each is counted on this instance's own rows, and a count that cannot be read refuses rather than
 * waving the call through.
 *
 * WHAT A STATUS ANSWER WITHHOLDS: a pause reads as `paused` and one code out of a closed set
 * (`settings_changed` or `paused`), never the owner's own reason text; a PREVIEW run reads as `queued`,
 * `running`, `finished` (its `ok` and `empty` alike) or `failed`, with no warning count, because telling
 * `ok` from `empty` would say how much an unapproved revision read. `crow_report_request_credential`
 * answers `not_found` for a report another bot made, exactly as it does for a foreign report: the secret
 * target accepts that label only from the report's own bot.
 *
 * The deps this module hands the stores are always a literal object: the module defaults (this
 * instance's keychain seed, the server's own block registry) are the production seam, and there is no
 * caller-supplied seam here that a bot's arguments could reach.
 */
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createDbClient } from "../../db.js";
import { REPORTS_TOKEN, localOperatorAuth } from "../local-token.js";
import { verifyReportsActorSig } from "../../../scripts/pi-bots/actor-sig.mjs";
import { SETTINGS_CHANGED_PAUSE_REASON, botSaveRecipe, isLive, listRecipients, proposeRecipient } from "./approvals.js";
import {
  credentialSpecLabel, hostApproved, listCredentials, listHosts, listSteps, proposeHost, proposeStep,
} from "./steps.js";
import { createReport, getReport, getState, setState } from "./store.js";
import { requestRun } from "./run-requests.js";
import { listDraftSources } from "./source-approvals.js";
import { cronNext } from "../../shared/schedule-core.js";
import { validTimeZone } from "../../shared/relative-dates.js";
import { readVerifiedBotDef } from "../../shared/bot-def-store.js";

/** The mount prefix and the one path a bot's config names. */
export const REPORTS_MCP_PREFIX = "/reports";
export const REPORTS_DOOR_PATH = "/reports/mcp";

/** The actor-signature kind this mount accepts; its own MAC domain in actor-sig.mjs. */
export const REPORTS_ACTOR_KIND = "reports";

/** The token scope a request carries once the guard admitted it (local-token.js's path scope). */
export const REPORTS_TOKEN_SCOPE = "reports";

/** The report id shape reports/store.js mints. Anything else is answered as a missing report. */
const REPORT_ID_RE = /^rpt-[0-9a-f]{16}$/;

/** How many runs a status answer lists. */
const STATUS_RUN_LIMIT = 5;

/** The window the request and create caps are counted over: one day, in milliseconds. */
const RATE_WINDOW_MS = 24 * 60 * 60 * 1000;

/** How many unclaimed run requests one report may already hold before a preview is refused. */
const PREVIEW_PENDING_MAX = 3;

/** How many preview requests one report may make in the window. */
const PREVIEW_WINDOW_MAX = 20;

/** How many reports one bot may create in the window. */
const CREATE_WINDOW_MAX = 10;

/**
 * The two run status words a preview hides behind one another. A preview's `ok` and `empty` are the same
 * answer to a bot (it produced a document or it did not), and telling them apart would say how much the
 * report read. Any other stored word is `failed`: a closed set, so nothing a run row holds travels out.
 */
const PREVIEW_STATUS_WORDS = Object.freeze({
  queued: "queued",
  running: "running",
  ok: "finished",
  empty: "finished",
  failed: "failed",
});

/**
 * The pause codes a status answer may carry: a closed set of two, never the stored reason's own words.
 * `settings_changed` is the fixed sentence a live-set settings change leaves; anything else (an owner's
 * own pause word, a system pause's text) is `paused` and says nothing more.
 */
const PAUSE_CODES = Object.freeze({
  settings_changed: "settings_changed",
  paused: "paused",
});

/** The nine tools and the whole surface of this mount. */
export const REPORTS_TOOL_NAMES = Object.freeze([
  "crow_report_create",
  "crow_report_set_recipe",
  "crow_report_set_schedule",
  "crow_report_propose_recipient",
  "crow_report_propose_host",
  "crow_report_propose_step",
  "crow_report_request_credential",
  "crow_report_preview",
  "crow_report_status",
]);

/**
 * The fixed sentence a refusal carries, per code. Never a value from the call and never a library
 * message: a bot's tool result is read by a model, and a fixed sentence cannot carry a recipe, an
 * address, a host or a secret back out of the instance.
 */
const REFUSAL_TEXT = Object.freeze({
  unauthorized: "This call is not signed by a bot, so nothing happened.",
  no_project: "This bot has no project of its own, so nothing happened. The owner adds the bot to a project in Bot Builder.",
  not_found: "Not found.",
  bad_recipe: "That recipe was refused, so nothing was saved.",
  bad_schedule: "That schedule was refused, so nothing was proposed.",
  bad_input: "That request was refused, so nothing happened.",
  too_large: "That request is too large, so nothing was saved.",
  bad_credential: "That credential request could not be built, so nothing was asked.",
  host_not_approved: "The owner has not approved that host yet, so nothing was asked.",
  rate_limited: "That was asked too often, so nothing was done. Try again later.",
  error: "Something went wrong on the Crow side, so nothing was saved.",
});

/** The fixed sentence that says what happens next. Read by a bot, so plain words and no value echoed. */
const NEXT_TEXT = Object.freeze({
  recipe: "The owner approves this from the report card.",
  credential: "Call crow_request_secret with target report-credential and exactly this label.",
});

/**
 * The `report_state` keys this door may write, and nothing else. Every other key is somebody's
 * approval bookkeeping (`revision_author:*`, `sender_seal`, `source_approval:*`), which only the
 * owner's own routes and the stores write.
 */
const WRITABLE_STATE_KEYS = Object.freeze(["chat_thread", "schedule_proposal"]);

/** The `report_state` key a report's chat thread is remembered under (the card reads it back). */
const CHAT_THREAD_KEY = "chat_thread";

/* ------------------------------------------------------------------------- results */

/** A column as a string; null and undefined are the empty string, like every reader in this tree. */
function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** One MCP text block holding `data` as JSON. Never HTML, never a second block. */
function ok(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

/**
 * A refusal: the code and its fixed sentence. `isError` so a bot does not read it as success. A `detail`
 * is only ever a validated error PATH from the recipe store (see `badRecipeResult`), never free text.
 */
function failed(code, detail) {
  const body = { error: code, message: REFUSAL_TEXT[code] || REFUSAL_TEXT.error };
  if (detail) body.detail = detail;
  return { content: [{ type: "text", text: JSON.stringify(body) }], isError: true };
}

/** A store's error path as the only detail a refusal may carry. */
const STORE_PATH_RE = /^[A-Za-z0-9_.\[\]-]{1,80}$/;

/** The store codes this door has a sentence for; anything else is `error`. */
const STORE_CODE = Object.freeze({
  bad_recipe: "bad_recipe",
  bad_schedule: "bad_schedule",
  bad_input: "bad_input",
  too_large: "too_large",
  bad_credential: "bad_credential",
  host_not_approved: "host_not_approved",
  not_found: "not_found",
});

/** The refusal for a store error: a known code, otherwise `error`. */
function refusalFor(err) {
  const code = STORE_CODE[String(err && err.code)] || "error";
  return failed(code);
}

/** The refusal for a recipe the store refused: the fixed sentence, plus the path when it is a path. */
function badRecipeResult(err) {
  const detail = err && typeof err.detail === "string" && STORE_PATH_RE.test(err.detail) ? err.detail : null;
  return failed("bad_recipe", detail);
}

/* --------------------------------------------------------------------- mount guard */

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
 * The auth wrapper `boot/mcp-mounts.js` installs in front of `mountMcpServer(app, "/reports", ...)`.
 *
 * A request is admitted when BOTH hold:
 *
 *   1. its bearer is a live `REPORTS_TOKEN` (the path-scoped family token, rotated at boot). The guard
 *      validates it itself rather than trusting `req.localTokenAuth` alone, so no other token family
 *      can open this mount;
 *   2. `x-crow-actor-kind: reports` with `x-crow-actor-id` and `x-crow-actor-sig`, the signature
 *      computed over (bot, thread, gateway) for that bot.
 *
 * Everything else, including a signed actor with no token of this family, a token of this family with
 * no signature, and a signature for another bot, is 401 before any handler runs.
 *
 * @param {{createDb?: Function, validateToken?: (req: object, token: string) => Promise<boolean>,
 *   verifyActor?: Function}} [deps]
 * @returns {(req: object, res: object, next: Function) => unknown}
 */
export function reportsMountAuth(deps = {}) {
  const createDb = typeof deps.createDb === "function" ? deps.createDb : createDbClient;
  const verifyActor = typeof deps.verifyActor === "function" ? deps.verifyActor : verifyReportsActorSig;

  return async (req, res, next) => {
    const token = bearerOf(req);
    if (!token) return unauthorized(res);
    let valid = false;
    try {
      if (typeof deps.validateToken === "function") valid = (await deps.validateToken(req, token)) === true;
      else {
        const db = createDb();
        try {
          valid = (await REPORTS_TOKEN.validate(db, token)) === true;
        } finally {
          try { db.close(); } catch { /* already closed */ }
        }
      }
    } catch {
      valid = false;
    }
    if (!valid) return unauthorized(res);

    const headers = req.headers || {};
    const kind = headerValue(headers, "x-crow-actor-kind");
    const botId = headerValue(headers, "x-crow-actor-id");
    const threadId = headerValue(headers, "x-crow-actor-thread");
    const gatewayType = headerValue(headers, "x-crow-actor-gateway");
    const sig = headerValue(headers, "x-crow-actor-sig");
    let signed = false;
    try {
      signed = kind === REPORTS_ACTOR_KIND && Boolean(botId) && Boolean(sig)
        && verifyActor({ botId, threadId, gatewayType, sig }) === true;
    } catch {
      signed = false;
    }
    if (!signed) return unauthorized(res);

    const claims = { botId, threadId, gatewayType, tokenScope: REPORTS_TOKEN_SCOPE };
    req.localTokenAuth = { token: "local-mcp", scope: REPORTS_TOKEN_SCOPE };
    req.auth = localOperatorAuth(REPORTS_TOKEN_SCOPE, claims);
    return next();
  };
}

/* ------------------------------------------------------------------------ claims */

/**
 * The claims the guard pinned on this request, or null. Fail closed: a handler with no claims refuses
 * rather than guessing whose project to use.
 */
export function claimsOf(extra) {
  const auth = extra?.authInfo;
  if (!auth || auth.clientId !== "local-mcp") return null;
  const claims = auth.extra;
  if (!claims || claims.tokenScope !== REPORTS_TOKEN_SCOPE) return null;
  const botId = typeof claims.botId === "string" ? claims.botId.trim() : "";
  if (!botId) return null;
  return {
    botId,
    threadId: claims.threadId == null || claims.threadId === "" ? null : String(claims.threadId),
    gatewayType: claims.gatewayType == null || claims.gatewayType === "" ? null : String(claims.gatewayType),
  };
}

/* ---------------------------------------------------------------------- the project */

/**
 * The project a verified bot works in: its own home project, and nothing a request can name. The row
 * is read through the store's VERIFIED read (round C, item E4): this decides which project this door
 * may reach, so it is authority, and an unverified row answers null exactly like a missing one — a
 * definition changed outside Crow never picks the project. Null when the bot has no project, when the
 * project is archived, or when the row is gone.
 *
 * @param {object} db
 * @param {string} botId
 * @returns {Promise<number|null>}
 */
async function homeProjectOf(db, botId) {
  if (typeof botId !== "string" || !botId) return null;
  try {
    const read = await readVerifiedBotDef(db, botId);
    if (!read.ok) {
      if (read.reason !== "unknown-bot") {
        console.warn(`[bot-def] ${botId} settings could not be verified (${read.reason}); the reports door used no project`);
      }
      return null;
    }
    if (read.row?.project_id == null) return null;
    const { rows } = await db.execute({
      sql: `SELECT p.id FROM project_spaces p WHERE p.id = ? AND p.archived_at IS NULL
               AND (p.status IS NULL OR p.status != 'archived') LIMIT 1`,
      args: [Number(read.row.project_id)],
    });
    if (!rows[0]) return null;
    const id = Number(rows[0].id);
    return Number.isInteger(id) ? id : null;
  } catch {
    return null;
  }
}

/**
 * One report of THIS project, or null. A malformed id, a missing id and another project's id all answer
 * null, so every caller answers them with the same `not_found` result: the door is no oracle.
 */
async function reportInProject(db, projectId, reportId) {
  if (typeof reportId !== "string" || !REPORT_ID_RE.test(reportId)) return null;
  let report;
  try {
    report = await getReport(db, reportId);
  } catch {
    return null;
  }
  if (!report) return null;
  if (Number(report.project_id) !== Number(projectId)) return null;
  return report;
}

/* ------------------------------------------------------------------- state writes */

/**
 * Write one `report_state` value this door may carry. The key is checked against the closed list, so no
 * call can ever land on a reserved approval key even if a later edit passes one by mistake.
 */
async function writeState(db, reportId, key, value) {
  if (!WRITABLE_STATE_KEYS.includes(key)) throw Object.assign(new Error("reserved_state_key"), { code: "error" });
  return setState(db, reportId, key, value);
}

/** Remember the thread a report was made in, when the signed actor carried one. Never fails a call. */
async function rememberThread(db, reportId, claims) {
  if (!claims || !claims.threadId) return;
  try {
    await writeState(db, reportId, CHAT_THREAD_KEY, claims.threadId);
  } catch {
    // The card simply has no thread to answer into; the call itself already succeeded.
  }
}

/* ------------------------------------------------------------------- argument shapes */

const CREATE = z.object({
  title: z.string().describe("The report title, 1 to 200 characters"),
}).strict();

const SET_RECIPE = z.object({
  reportId: z.string().describe("The report id"),
  recipe: z.record(z.string(), z.unknown()).describe("The whole recipe, as the report page would save it"),
}).strict();

const SET_SCHEDULE = z.object({
  reportId: z.string().describe("The report id"),
  cron: z.string().describe("A five field cron expression"),
  tz: z.string().describe("The IANA time zone the expression is read in"),
}).strict();

const PROPOSE_RECIPIENT = z.object({
  reportId: z.string().describe("The report id"),
  address: z.string().describe("The email address to propose"),
  displayName: z.string().optional().describe("The name to show beside the address"),
  commentTier: z.enum(["a", "b", "c"]).optional().describe("The comment tier, when it is not the report default"),
}).strict();

const PROPOSE_HOST = z.object({
  reportId: z.string().describe("The report id"),
  host: z.string().describe("An exact lower case host name, or a wildcard like *.example.com"),
}).strict();

const PROPOSE_STEP = z.object({
  reportId: z.string().describe("The report id"),
  stepKey: z.string().describe("The step key the recipe's custom block names"),
  language: z.enum(["python", "node"]).describe("The runtime the step runs in"),
  entry: z.string().describe("The file inside the bundle that runs"),
  files: z.record(z.string(), z.string()).describe("Relative path to file text"),
  requirements: z.string().optional().describe("A requirements text"),
  assets: z.array(z.string()).optional().describe("The names of the report assets the step binds"),
}).strict();

const REQUEST_CREDENTIAL = z.object({
  reportId: z.string().describe("The report id"),
  host: z.string().describe("The exact host the credential belongs to"),
  header: z.string().optional().describe("The header the credential is attached to"),
  query: z.string().optional().describe("The query parameter the credential is attached to"),
  format: z.string().optional().describe("The header value with one {} placeholder"),
  paths: z.array(z.string()).describe("The path prefixes the rule covers"),
  methods: z.array(z.string()).optional().describe("The methods the rule covers"),
}).strict();

const REPORT_ONLY = z.object({
  reportId: z.string().describe("The report id"),
}).strict();

/* ------------------------------------------------------------------------ handlers */

/** `bot:<id>` as the provenance word a proposal row carries. */
function proposedByOf(claims) {
  return `bot:${claims.botId}`;
}

/**
 * One handling call: the report it names (already checked against the bot's own project) and the
 * arguments. Every handler answers `ok(...)` or `failed(...)`; a throw becomes the store refusal it
 * carries.
 */
const HANDLERS = {
  async crow_report_create(db, ctx, args) {
    const title = typeof args.title === "string" ? args.title.trim() : "";
    if (!title || title.length > 200) return failed("bad_input");
    if (await createRateLimited(db, ctx.claims.botId)) return failed("rate_limited");
    const { id } = await createReport(db, {
      projectId: ctx.projectId,
      owner: "owner",
      botId: ctx.claims.botId,
      title,
    });
    await rememberThread(db, id, ctx.claims);
    return ok({ reportId: id, status: "draft" });
  },

  async crow_report_set_recipe(db, ctx, args) {
    const report = await reportInProject(db, ctx.projectId, args.reportId);
    if (!report) return failed("not_found");
    let saved;
    try {
      saved = await botSaveRecipe(db, {}, { reportId: report.id, recipe: args.recipe });
    } catch (err) {
      if (err && err.code === "bad_recipe") return badRecipeResult(err);
      return refusalFor(err);
    }
    await rememberThread(db, report.id, ctx.claims);
    return ok({
      rev: saved.rev,
      pendingFreeChange: saved.pendingFreeChange === true,
      needsGoLive: saved.needsGoLive === true,
      next: NEXT_TEXT.recipe,
    });
  },

  async crow_report_set_schedule(db, ctx, args) {
    const report = await reportInProject(db, ctx.projectId, args.reportId);
    if (!report) return failed("not_found");
    const tz = validTimeZone(args.tz);
    if (!tz) return failed("bad_schedule");
    const cron = typeof args.cron === "string" ? args.cron.trim() : "";
    if (!cron || cron.split(/\s+/).length !== 5) return failed("bad_schedule");
    if (cronNext(cron, tz, Date.now()) === null) return failed("bad_schedule");
    try {
      await writeState(db, report.id, "schedule_proposal", {
        cron,
        tz,
        proposedBy: proposedByOf(ctx.claims),
        at: Date.now(),
      });
    } catch (err) {
      return refusalFor(err);
    }
    return ok({ proposed: true, needsGoLive: true });
  },

  async crow_report_propose_recipient(db, ctx, args) {
    const report = await reportInProject(db, ctx.projectId, args.reportId);
    if (!report) return failed("not_found");
    let row;
    try {
      row = await proposeRecipient(db, {}, {
        reportId: report.id,
        address: args.address,
        displayName: args.displayName,
        commentTier: args.commentTier,
        proposedBy: proposedByOf(ctx.claims),
      });
    } catch (err) {
      return refusalFor(err);
    }
    return ok({ recipientId: row.id, state: row.state });
  },

  async crow_report_propose_host(db, ctx, args) {
    const report = await reportInProject(db, ctx.projectId, args.reportId);
    if (!report) return failed("not_found");
    let row;
    try {
      row = await proposeHost(db, {}, { reportId: report.id, host: args.host });
    } catch (err) {
      return refusalFor(err);
    }
    return ok({ host: row.host, state: row.state });
  },

  async crow_report_propose_step(db, ctx, args) {
    const report = await reportInProject(db, ctx.projectId, args.reportId);
    if (!report) return failed("not_found");
    let row;
    try {
      row = await proposeStep(db, {}, {
        reportId: report.id,
        stepKey: args.stepKey,
        language: args.language,
        entry: args.entry,
        files: args.files,
        assets: args.assets,
        requirements: args.requirements,
        proposedBy: proposedByOf(ctx.claims),
      });
    } catch (err) {
      return refusalFor(err);
    }
    return ok({ stepKey: row.stepKey, rev: row.rev, state: row.state });
  },

  async crow_report_request_credential(db, ctx, args) {
    const report = await reportInProject(db, ctx.projectId, args.reportId);
    if (!report) return failed("not_found");
    // The secret target accepts a label only from the bot that made the report, so any other bot gets
    // the same answer a foreign report gets: the door is no oracle for another bot's report.
    if (text(report.bot_id) !== ctx.claims.botId) return failed("not_found");
    const label = credentialSpecLabel({
      reportId: report.id,
      host: args.host,
      header: args.header,
      query: args.query,
      format: args.format,
      paths: args.paths,
      methods: args.methods,
    });
    if (!label) return failed("bad_credential");
    if (!(await hostApproved(db, {}, report.id, args.host))) return failed("host_not_approved");
    return ok({ label, next: NEXT_TEXT.credential });
  },

  async crow_report_preview(db, ctx, args) {
    const report = await reportInProject(db, ctx.projectId, args.reportId);
    if (!report) return failed("not_found");
    if (await previewRateLimited(db, report)) return failed("rate_limited");
    let queued;
    try {
      queued = await requestRun(db, {
        reportId: report.id,
        kind: "preview",
        requestedBy: proposedByOf(ctx.claims),
      });
    } catch (err) {
      return refusalFor(err);
    }
    return ok({ queued: true, runId: queued.id });
  },

  async crow_report_status(db, ctx, args) {
    const report = await reportInProject(db, ctx.projectId, args.reportId);
    if (!report) return failed("not_found");
    return ok(await statusOf(db, report));
  },
};

/* ---------------------------------------------------------------------- the rate caps */

/**
 * Is this report's preview queue already as full as the cap allows?
 *
 * Two counts, both about THIS report and nothing else. The first is what is still waiting: three or more
 * requests the run hook has not claimed yet means the bot is queueing work nobody has started, so one
 * more request would only lengthen the queue. The second is how often the report was previewed in the
 * window (`kind = 'preview'`, `created_at` inside the last day).
 *
 * A count this instance cannot read answers `true`: nothing was done, which is the safe side of a cap
 * that cannot be enforced.
 */
async function previewRateLimited(db, report) {
  try {
    const pending = await db.execute({
      sql: `SELECT COUNT(*) AS n FROM report_run_requests
             WHERE report_id = ? AND claimed_at IS NULL`,
      args: [report.id],
    });
    if (Number(pending.rows[0]?.n) >= PREVIEW_PENDING_MAX) return true;
    const recent = await db.execute({
      sql: `SELECT COUNT(*) AS n FROM report_run_requests
             WHERE report_id = ? AND kind = 'preview' AND created_at >= ?`,
      args: [report.id, Date.now() - RATE_WINDOW_MS],
    });
    return Number(recent.rows[0]?.n) >= PREVIEW_WINDOW_MAX;
  } catch {
    return true;
  }
}

/**
 * Has this bot created as many reports in the window as the cap allows? Counted on the rows it owns
 * (`reports.bot_id`) with `created_at` inside the last day, so the count is the bot's own and nothing a
 * call names. An unreadable count answers `true`, as for the preview cap.
 */
async function createRateLimited(db, botId) {
  if (typeof botId !== "string" || !botId) return true;
  try {
    const { rows } = await db.execute({
      sql: "SELECT COUNT(*) AS n FROM reports WHERE bot_id = ? AND created_at >= ?",
      args: [botId, Date.now() - RATE_WINDOW_MS],
    });
    return Number(rows[0]?.n) >= CREATE_WINDOW_MAX;
  } catch {
    return true;
  }
}

/* ----------------------------------------------------------------------- the status */

/** The four recipient states a status answer counts. */
const RECIPIENT_STATE_WORDS = Object.freeze(["proposed", "approved", "refused", "revoked"]);

/** How many warning entries a stored block log holds. Parsed only to count them, never returned. */
function warningsCount(blockLogJson) {
  if (typeof blockLogJson !== "string" || !blockLogJson) return 0;
  try {
    const parsed = JSON.parse(blockLogJson);
    const warnings = parsed != null && typeof parsed === "object" && Array.isArray(parsed.warnings)
      ? parsed.warnings
      : [];
    return warnings.length;
  } catch {
    return 0;
  }
}

/** The newest runs of one report: ids, a trigger, a status and counts. No log, no error text. */
async function recentRuns(db, reportId) {
  let rows;
  try {
    ({ rows } = await db.execute({
      sql: `SELECT id, "trigger", status, recipe_rev, late, created_at, ended_at, block_log_json
              FROM report_runs WHERE report_id = ?
             ORDER BY created_at DESC, id DESC LIMIT ?`,
      args: [reportId, STATUS_RUN_LIMIT],
    }));
  } catch {
    return [];
  }
  return rows.map((row) => {
    const preview = row.trigger === "preview";
    const out = {
      id: row.id,
      trigger: row.trigger,
      // A preview answers one of four words, never the stored one: `ok` and `empty` both read
      // `finished`, so a preview does not say how much the report read, and a word this build does not
      // know reads `failed` rather than travelling out as it is.
      status: preview ? (PREVIEW_STATUS_WORDS[String(row.status)] || "failed") : row.status,
      recipeRev: row.recipe_rev == null ? null : Number(row.recipe_rev),
      late: Number(row.late) === 1,
      createdAt: row.created_at == null ? null : Number(row.created_at),
      endedAt: row.ended_at == null ? null : Number(row.ended_at),
    };
    // A preview carries no warning count at all: it is a count of what a block noticed while reading,
    // which is content about a revision the owner has not approved.
    if (!preview) out.warnings = warningsCount(row.block_log_json);
    return out;
  });
}

/** The schedule proposal an owner has not decided on yet, or null. */
async function scheduleProposalOf(db, reportId) {
  const stored = await getState(db, reportId, "schedule_proposal");
  if (stored == null || typeof stored !== "object" || Array.isArray(stored)) return null;
  const cron = typeof stored.cron === "string" ? stored.cron : "";
  const tz = typeof stored.tz === "string" ? stored.tz : "";
  return cron && tz ? { cron, tz } : null;
}

/**
 * The fix pause code for a stored reason, from the closed set: `settings_changed` for the sentence a
 * live-set settings change leaves, `paused` for anything else. The stored text itself never leaves: a
 * reason is a free-text field the owner wrote, and this answer is read by a model.
 */
function pauseCodeOf(reason) {
  return text(reason) === SETTINGS_CHANGED_PAUSE_REASON ? PAUSE_CODES.settings_changed : PAUSE_CODES.paused;
}

/**
 * One report as a bot may read it: the status word, the two live flags, the recipe head, the proposal,
 * and COUNTS of what the owner has decided. Never an address, a connection reference, an inject rule, an
 * artifact id, a run log, an error text, a token or a secret. Everything here is read through the
 * modules that own each row, except the runs, which are one SELECT that keeps its columns to itself.
 *
 * The pause reads as `paused` and one code out of two, never the reason's own text.
 */
async function statusOf(db, report) {
  const live = (await isLive(db, {}, report)) === true;
  const recipients = { proposed: 0, approved: 0, refused: 0, revoked: 0 };
  try {
    for (const row of await listRecipients(db, report.id, {})) {
      const state = String(row.state);
      if (RECIPIENT_STATE_WORDS.includes(state)) recipients[state] += 1;
    }
  } catch {
    // A recipient list this instance cannot read counts nothing.
  }
  const steps = [];
  try {
    for (const row of await listSteps(db, report.id)) {
      steps.push({ stepKey: row.step_key, rev: Number(row.rev), state: row.state });
    }
  } catch {
    // No steps to report.
  }
  const hosts = [];
  try {
    for (const row of await listHosts(db, report.id, {})) {
      hosts.push({ host: row.host, state: row.state });
    }
  } catch {
    // No hosts to report.
  }
  const credentials = [];
  try {
    for (const row of await listCredentials(db, report.id, {})) {
      credentials.push({ host: row.host, state: row.state });
    }
  } catch {
    // No credential bindings to report.
  }
  const sources = [];
  try {
    for (const row of await listDraftSources(db, {}, report.id)) {
      sources.push({ blockId: row.blockId, type: row.type, approved: row.approved === true });
    }
  } catch {
    // No readable recipe, so no draft sources.
  }
  return {
    status: report.status,
    live,
    paused: report.status === "paused",
    pauseCode: pauseCodeOf(report.pause_reason),
    recipeRev: Number(report.recipe_rev) || 0,
    liveRev: report.live_rev == null ? null : Number(report.live_rev),
    pendingFreeChange: Number(report.pending_free_change) === 1,
    scheduleProposal: await scheduleProposalOf(db, report.id),
    recipients,
    steps,
    hosts,
    credentials,
    sources,
    runs: await recentRuns(db, report.id),
  };
}

/* --------------------------------------------------------------------- the server */

/**
 * Build the `crow-reports` door server.
 *
 * Every handler runs on a db client it opens for the call and closes in `finally`, reads the claims the
 * guard pinned, derives the bot's project, and answers one MCP result. Nothing here takes a project, a
 * bot, an actor or an approval.
 *
 * `verifyActor` is the door's OWN credential (the `reports` actor signature), and it is checked by the
 * MOUNT GUARD (`reportsMountAuth`), never here: boot hands the guard and this factory the same dep
 * object (boot/mcp-mounts.js), so the verifier that makes `/reports` a SIGNED bot door is named where
 * the mount is. It is taken here so the dep set is one object, and a caller that passes something other
 * than a function is told.
 *
 * @param {{createDb?: Function, verifyActor?: Function}} [options]
 */
export function createReportsMcpServer(options = {}) {
  if (options.verifyActor !== undefined && typeof options.verifyActor !== "function") {
    throw new TypeError("createReportsMcpServer: verifyActor must be the door's actor verifier (reportsMountAuth runs it)");
  }
  const openDb = typeof options.createDb === "function" ? options.createDb : createDbClient;

  const server = new McpServer({ name: "crow-reports", version: "0.1.0" });

  /**
   * One tool call's whole rule: the claims check, the project read, the db lifetime and the MCP shape of
   * the answer, so a handler is only the call it makes. Every tool below registers its own literal name,
   * which is what the door's name scan reads.
   */
  const handle = async (name, args, extra) => {
    const claims = claimsOf(extra);
    if (!claims) return failed("unauthorized");
    const db = openDb();
    try {
      const projectId = await homeProjectOf(db, claims.botId);
      if (projectId == null) return failed("no_project");
      return await HANDLERS[name](db, { projectId, claims }, args || {});
    } catch (err) {
      return refusalFor(err);
    } finally {
      try { db.close(); } catch { /* already closed */ }
    }
  };

  server.registerTool("crow_report_create", {
    description: "Create a draft report in this bot's own project. Nothing is read and nothing is sent: the owner builds it up from the draft, approves it and takes it live.",
    inputSchema: CREATE,
  }, (args, extra) => handle("crow_report_create", args, extra));

  server.registerTool("crow_report_set_recipe", {
    description: "Save a draft revision of the report's recipe. Your save never approves anything and never re-stamps a live report: the owner approves the newer revision from the report card.",
    inputSchema: SET_RECIPE,
  }, (args, extra) => handle("crow_report_set_recipe", args, extra));

  server.registerTool("crow_report_set_schedule", {
    description: "Propose when the report should run. This only leaves a proposal for the owner, who sets the real schedule from the report page when the report goes live.",
    inputSchema: SET_SCHEDULE,
  }, (args, extra) => handle("crow_report_set_schedule", args, extra));

  server.registerTool("crow_report_propose_recipient", {
    description: "Propose one recipient for the report. The row waits as a proposal until the owner approves it; a proposal never adds an approved recipient and never moves an existing approval.",
    inputSchema: PROPOSE_RECIPIENT,
  }, (args, extra) => handle("crow_report_propose_recipient", args, extra));

  server.registerTool("crow_report_propose_host", {
    description: "Propose one site the report's steps may reach. The owner checks the site and approves it.",
    inputSchema: PROPOSE_HOST,
  }, (args, extra) => handle("crow_report_propose_host", args, extra));

  server.registerTool("crow_report_propose_step", {
    description: "Propose one revision of a custom step: its files, its entry file, its requirements text and the report assets it binds. The owner reads and approves it before it ever runs.",
    inputSchema: PROPOSE_STEP,
  }, (args, extra) => handle("crow_report_propose_step", args, extra));

  server.registerTool("crow_report_request_credential", {
    description: "Build the exact label for a credential the report needs. This tool reads no secret and sends none: it hands back a label to pass to crow_request_secret, and only for a host the owner has already approved.",
    inputSchema: REQUEST_CREDENTIAL,
  }, (args, extra) => handle("crow_report_request_credential", args, extra));

  server.registerTool("crow_report_preview", {
    description: "Ask for a preview run of the report. It is queued for the owner's instance and answered as a queued flag and a run id; read what happened with crow_report_status.",
    inputSchema: REPORT_ONLY,
  }, (args, extra) => handle("crow_report_preview", args, extra));

  server.registerTool("crow_report_status", {
    description: "The report's status and counts: whether it is live or paused, its recipe revision, its pending proposal, how many recipients are in each state, its steps, hosts, credentials and sources, and its newest runs. It carries no content, no addresses and no secrets.",
    inputSchema: REPORT_ONLY,
  }, (args, extra) => handle("crow_report_status", args, extra));

  return server;
}