/**
 * Crow Recurring Reports' private JSON API: `/dashboard/api/reports`, owner only.
 *
 * Mounted inside the dashboard router (servers/gateway/dashboard/index.js), not in boot/feature-
 * mounts.js, because the dashboard's `csrfMiddleware` guards every unsafe method under `/dashboard`
 * and a router mounted at app root runs before it. Funnel is refused upstream, on every private path.
 *
 * Every request passes the same chain, in this order, and each step refuses before the next can read
 * anything:
 *
 *   1. `dashboardAuth` on this router's own prefix, so the API is closed wherever it is mounted.
 *   2. `Cache-Control: no-store`: a report names sources, a sender and a schedule.
 *   3. a byte-size guard, then the owner: `isLocalPasswordSessionOn` (this machine's own password
 *      sign-in, from the owner's own client). A peer's single-sign-on session, a session minted by a
 *      login on this machine, a signed peer call and this machine's own console all get 403
 *      `{error:"owner_only"}` with no data, and no report row is read before the verdict.
 *   4. this router's own `express.json({limit:"256kb"})`. No report body is large: a recipe is blocks
 *      and settings, and a settings write is a handful of words. The guard in step 3 refuses an
 *      over-size body by its `Content-Length` too, because a body under the gateway's global 1 MB
 *      parser could otherwise reach a route already parsed.
 *
 * Errors are JSON `{error, message}` with a fixed sentence per code: a library message, a database
 * message and a value never reach a response or a log line. A failure that is not one of the named
 * codes answers 500 `{error:"internal"}` and logs only its code.
 *
 * A report is answered without its `live_seal` and `live_nonce` columns: the seal is the gate's own
 * secret state, and the owner's card reads `live` (whether it verifies) instead. That boolean is the
 * approvals module's `isLive`, so a report a direct UPDATE or a repointed provider stopped reads
 * `live: false` here.
 *
 * NOTHING ON THIS ROUTER SENDS MAIL, and it never imports the send door or a delivery module. An owner
 * add of a recipient is a propose plus an approve in one tap; "Send to the rest" only writes `pending`
 * `report_sends` rows for a run (reports/send-log.js); the delivery seam is somebody else's, and it
 * takes those row ids, never an address from here. No answer on this router ever carries a
 * `report_recipients` seal or nonce: the recipient view is the approvals module's own, which drops
 * both.
 */
import { Router, json as jsonParserOf, raw as rawParserOf } from "express";
import { createDbClient } from "../../db.js";
import { isLocalPasswordSessionOn } from "../dashboard/local-session.js";
import {
  approveGoLive, approveRecipient, isLive, listRecipients, ownerSaveRecipe, pauseReport,
  proposeRecipient, refuseRecipient, resumeReport, revokeRecipient, updateSettings,
} from "../reports/approvals.js";
import { buildApprovalsDeps } from "../reports/approvals-deps.js";
import { listRuns } from "../reports/run.js";
import { requestRun } from "../reports/run-requests.js";
import { kickReportsHook } from "../reports/schedule-hook.js";
import { createSendToRest, listSends } from "../reports/send-log.js";
import {
  ASSET_NAME_RE, ASSET_MAX_BYTES, STEP_KEY_RE, approveCredential, approveHost, approveStep,
  listAssets, listCredentials, listHosts, listStepsForPage, normalizeHost, proposeCredential,
  proposeHost, proposeStep, refuseStep, revokeCredential, revokeHost, revokeStep, saveAsset,
  stepDetail, stepDiff,
} from "../reports/steps.js";
import { createReport, getReport, listReports } from "../reports/store.js";

/** The mount point. */
export const REPORTS_API_PREFIX = "/dashboard/api/reports";

/**
 * The owner of a report made through this route: the instance owner. Not a person's name, not a bot
 * id, and never a value a caller sends: a report is always the owner's.
 */
export const OWNER_LABEL = "owner";

/** A report id, exactly what the store mints. Anything else is a 404 here. */
export const REPORT_ID_RE = /^rpt-[0-9a-f]{16}$/;

/** A recipient id, exactly what approvals.js mints. A malformed one is a 404 here. */
export const RECIPIENT_ID_RE = /^rrc-[0-9a-f]{16}$/;

/** A run id, exactly what run.js mints. A malformed one in a path is a 404 here. */
export const RUN_ID_RE = /^rrn-[0-9a-f]{16}$/;

/** A credential reference in a path: the connection uuid the row names. */
export const CREDENTIAL_REF_RE = /^[A-Za-z0-9-]{8,80}$/;

/** The rule digest an owner's view carries into the approval, exactly what `injectHashOf` writes. */
const INJECT_HASH_RE = /^[0-9a-f]{64}$/;

/** The bundle hash an owner's view carries into a step approval, exactly what `bundleHashOf` writes. */
const BUNDLE_HASH_RE = /^[0-9a-f]{64}$/;

/** A step revision in a path. */
const STEP_REV_RE = /^\d{1,7}$/;

/** The largest body this router accepts. */
const BODY_LIMIT_BYTES = 256 * 1024;
const JSON_LIMIT = "256kb";

/** The fixed sentence per code. Plain words, no dash. */
const FIXED_TEXT = Object.freeze({
  owner_only: "Only the owner can see this.",
  not_found: "Not found.",
  bad_input: "That request is not valid.",
  bad_recipe: "That report recipe is not valid.",
  bad_seal_field: "That approval could not be sealed.",
  too_large: "That request is too large.",
  preview_missing: "Preview this report before going live.",
  preview_stale: "The recipe changed since that preview. Preview it again.",
  preview_failed: "That preview did not finish, so this report cannot go live yet.",
  go_live_needed: "Preview and go live again.",
  conflict: "That report changed while this request was in flight. Try again.",
  recipient_changed: "That report changed while this request was in flight. Try again.",
  step_changed: "That step changed while this request was in flight. Try again.",
  host_changed: "That host changed while this request was in flight. Try again.",
  credential_changed: "That credential changed while this request was in flight. Try again.",
  bad_inject: "A credential needs a header or a query name and at least one path it may be sent to.",
  host_not_approved: "Approve that site for this report first.",
  no_schedule: "Choose when this report runs before going live.",
  sender_not_ready: "Choose a mail account that is ready to send.",
  model_unresolved: "Crow could not work out which model this report uses, so it cannot go live.",
  keychain_key_missing: "The keychain key for this password is not on this machine.",
  internal: "Something went wrong.",
});

/** The status a refusal answers with, by its code. Everything else is a 500. */
const STATUS_BY_CODE = Object.freeze({
  owner_only: 403,
  not_found: 404,
  bad_input: 400,
  bad_recipe: 400,
  bad_seal_field: 400,
  too_large: 413,
  preview_missing: 409,
  preview_stale: 409,
  preview_failed: 409,
  go_live_needed: 409,
  conflict: 409,
  recipient_changed: 409,
  step_changed: 409,
  host_changed: 409,
  credential_changed: 409,
  bad_inject: 400,
  host_not_approved: 409,
  no_schedule: 409,
  sender_not_ready: 409,
  model_unresolved: 409,
  keychain_key_missing: 409,
});

function messageFor(code) {
  return FIXED_TEXT[code] || FIXED_TEXT.internal;
}

/** One JSON error. The message is a fixed sentence, never an error's own text. */
function sendError(res, status, code, message = null) {
  if (res.headersSent) return;
  res.status(status).json({ error: code, message: message || messageFor(code) });
}

/** A thrown failure as its own code and sentence, or 500 internal. */
function sendFailure(res, err) {
  const code = err && typeof err.code === "string" ? err.code : "";
  const status = STATUS_BY_CODE[code];
  if (!status) return sendError(res, 500, "internal");
  return sendError(res, status, code);
}

/** A route's failure in the log: the code only, so no value can travel with it. */
function logCode(route, err) {
  try {
    const code = err && typeof err.code === "string" && err.code ? err.code : "internal";
    console.warn(`[reports-api] ${route}: ${code}`);
  } catch {
    // A log line is never worth failing a request over.
  }
}

/* --------------------------------------------------------------------- validation */

function isReportId(value) {
  return typeof value === "string" && REPORT_ID_RE.test(value);
}

/** A project id from a query string or a JSON body: a positive integer, or null. */
function readProjectId(value) {
  if (typeof value === "number") return Number.isSafeInteger(value) && value > 0 ? value : null;
  if (typeof value !== "string" || !/^\d+$/.test(value.trim())) return null;
  const number = Number(value.trim());
  return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function readTitle(value) {
  if (typeof value !== "string") return null;
  const title = value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return title ? title : null;
}

/** A report row as this API answers it: no seal, no nonce, and whether the approval verifies. */
async function reportView(db, approvalsDeps, report) {
  if (!report) return null;
  const { live_seal: _seal, live_nonce: _nonce, ...rest } = report;
  return { ...rest, live: await isLive(db, approvalsDeps, report) };
}

/* ------------------------------------------------------------------------- router */

/**
 * The reports API router.
 *
 * @param {Function} dashboardAuth the dashboard's auth middleware
 * @param {{openDb?: Function, ownerCheck?: Function, approvalsDeps?: object}} [deps]
 *   `openDb` mints the request's crow.db client; `ownerCheck` defaults to `isLocalPasswordSessionOn`;
 *   `approvalsDeps` is handed to the approvals module through `buildApprovalsDeps` (reports/
 *   approvals-deps.js): the real sender reader (reports/sender-ready.js), the real run reader
 *   (reports/run.js's `getRunForApproval`) and the real model resolver are the base, because
 *   approvals.js imports nothing under `mail/` and its own defaults fail closed. A member the caller
 *   injects (`loadSeed`, `now`, `getSchedule`, `registry`, or any of those three) wins over the base.
 * @returns {import("express").Router}
 */
export function reportsApiRouter(dashboardAuth, deps = {}) {
  const router = Router();
  const openDb = typeof deps.openDb === "function" ? deps.openDb : () => createDbClient();
  const ownerCheck = typeof deps.ownerCheck === "function" ? deps.ownerCheck : isLocalPasswordSessionOn;
  const givenDeps = deps.approvalsDeps == null ? {} : deps.approvalsDeps;
  const approvalsDeps = buildApprovalsDeps(givenDeps);
  const jsonParser = jsonParserOf({ limit: JSON_LIMIT });

  /** One client per request, closed in `finally`; a handler that throws answers its own code. */
  const route = (label, handler) => async (req, res) => {
    const db = openDb();
    try {
      await handler(db, req, res);
    } catch (err) {
      logCode(label, err);
      sendFailure(res, err);
    } finally {
      try {
        db.close();
      } catch {
        // Already closed is the only failure a per-request client has here.
      }
    }
  };

  router.use(REPORTS_API_PREFIX, dashboardAuth);

  /** Never cached: a report names its sources and its sender. */
  const guardHeaders = (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  };

  /** A body above the limit is refused by its declared size, whichever parser would read it. */
  const guardSize = (req, res, next) => {
    const declared = Number(req.headers?.["content-length"]);
    if (Number.isFinite(declared) && declared > BODY_LIMIT_BYTES) {
      return sendError(res, 413, "too_large");
    }
    next();
  };

  /** The owner: this instance's own password session, from the owner's own client. No row is read
   *  before the verdict, so a refused request carries no data at all. */
  const ownerGuard = async (req, res, next) => {
    const db = openDb();
    try {
      let owner = false;
      try {
        owner = (await ownerCheck(db, req)) === true;
      } catch {
        owner = false;
      }
      if (!owner) return sendError(res, 403, "owner_only");
      next();
    } finally {
      try {
        db.close();
      } catch {
        // Already closed is the only failure a per-request client has here.
      }
    }
  };

  /** A body this router's own parser refuses: too large is 413, anything else is 400. */
  const bodyParser = (req, res, next) => jsonParser(req, res, (err) => {
    if (!err) return next();
    const status = Number(err.status || err.statusCode || 0);
    if (status === 413 || err.type === "entity.too.large") return sendError(res, 413, "too_large");
    return sendError(res, 400, "bad_input");
  });

  /**
   * The one route whose body is not JSON: an asset upload carries the file's raw bytes, up to one
   * asset's cap. It is registered BEFORE the shared guards below, because those guards install this
   * router's 256 KB JSON parser for every path under the prefix. It therefore carries the three that
   * matter itself, in the same order: the no-store header, the owner check and a parser bounded to the
   * asset cap. Nothing else on this router is reachable without the shared chain.
   */
  const assetParser = rawParserOf({ type: () => true, limit: ASSET_MAX_BYTES });

  router.put(
    `${REPORTS_API_PREFIX}/:id/assets/:name`,
    guardHeaders,
    ownerGuard,
    (req, res, next) => assetParser(req, res, (err) => {
      if (!err) return next();
      const status = Number(err.status || err.statusCode || 0);
      if (status === 413 || err.type === "entity.too.large") return sendError(res, 413, "too_large");
      return sendError(res, 400, "bad_input");
    }),
    route("PUT /:id/assets/:name", async (db, req, res) => {
      const id = String(req.params?.id ?? "");
      const name = String(req.params?.name ?? "");
      if (!isReportId(id) || !ASSET_NAME_RE.test(name)) return sendError(res, 404, "not_found");
      if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
      if (!Buffer.isBuffer(req.body) || req.body.length === 0) return sendError(res, 400, "bad_input");
      const asset = await saveAsset(db, approvalsDeps, { reportId: id, name, bytes: req.body });
      res.status(201).json({ asset });
    }),
  );

  router.use(REPORTS_API_PREFIX, guardHeaders);
  router.use(REPORTS_API_PREFIX, ownerGuard);
  router.use(REPORTS_API_PREFIX, guardSize);
  router.use(REPORTS_API_PREFIX, bodyParser);

  /** Every route's id check: a malformed id is a 404 before anything is read. */
  const idOf = (req, res) => {
    const id = String(req.params?.id ?? "");
    if (!isReportId(id)) {
      sendError(res, 404, "not_found");
      return null;
    }
    return id;
  };

  /** A recipient id in a path: a malformed one is a 404 before anything is read. */
  const recipientIdOf = (req, res) => {
    const rid = String(req.params?.rid ?? "");
    if (!RECIPIENT_ID_RE.test(rid)) {
      sendError(res, 404, "not_found");
      return null;
    }
    return rid;
  };

  /**
   * One recipient of THIS report, or a 404. The recipient list is the approvals module's (it carries
   * no seal and no nonce), so a rid of another report is simply not in it.
   */
  const recipientInReport = async (db, res, reportId, recipientId) => {
    const recipients = await listRecipients(db, reportId, approvalsDeps);
    const found = recipients.find((row) => row.id === recipientId) ?? null;
    if (!found) {
      sendError(res, 404, "not_found");
      return null;
    }
    return found;
  };

  /* -------------------------------------------------------------------------- reads */

  // GET /?project=<id> — one project's reports, newest first, without their recipe bodies.
  router.get(REPORTS_API_PREFIX, route("GET /", async (db, req, res) => {
    const projectId = readProjectId(req.query?.project);
    if (projectId == null) return sendError(res, 400, "bad_input");
    const rows = await listReports(db, { projectId });
    const reports = [];
    for (const row of rows) reports.push(await reportView(db, approvalsDeps, row));
    res.json({ reports });
  }));

  // POST / — a new report, in draft, with an empty recipe. The owner is always the instance owner.
  router.post(REPORTS_API_PREFIX, route("POST /", async (db, req, res) => {
    const body = req.body == null ? {} : req.body;
    if (typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");
    const projectId = readProjectId(body.projectId);
    const title = readTitle(body.title);
    if (projectId == null || !title) return sendError(res, 400, "bad_input");
    let botId = null;
    if (body.botId !== undefined && body.botId !== null && body.botId !== "") {
      if (typeof body.botId !== "string" || !body.botId.trim() || body.botId.length > 120) {
        return sendError(res, 400, "bad_input");
      }
      botId = body.botId.trim();
    }
    const { id } = await createReport(db, { projectId, owner: OWNER_LABEL, botId, title });
    const row = await getReport(db, id);
    res.status(201).json({ report: await reportView(db, approvalsDeps, row) });
  }));

  // GET /:id — one report, with its recipe body, and whether its approval still verifies.
  router.get(`${REPORTS_API_PREFIX}/:id`, route("GET /:id", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const row = await getReport(db, id);
    if (!row) return sendError(res, 404, "not_found");
    res.json({ report: await reportView(db, approvalsDeps, row) });
  }));

  /* ------------------------------------------------------------------------- writes */

  // PUT /:id/recipe — the owner's save. A live report is re-stamped only when nothing it approved
  // moved (the same sources hash and the same model-call status); otherwise it stays on its sealed
  // revision and the answer says a go-live is needed.
  router.put(`${REPORTS_API_PREFIX}/:id/recipe`, route("PUT /:id/recipe", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const body = req.body == null ? {} : req.body;
    if (typeof body !== "object" || Array.isArray(body) || body.recipe == null) {
      return sendError(res, 400, "bad_input");
    }
    const saved = await ownerSaveRecipe(db, approvalsDeps, {
      reportId: id,
      recipe: body.recipe,
      actor: { kind: "owner" },
    });
    res.json(saved);
  }));

  // PUT /:id/settings — the sender, the delivery rule, the comment defaults, the AI switch, the title
  // and the notify switch. A live-set change on a live report pauses it with a fixed sentence.
  router.put(`${REPORTS_API_PREFIX}/:id/settings`, route("PUT /:id/settings", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const body = req.body == null ? {} : req.body;
    if (typeof body !== "object" || Array.isArray(body) || body.settings == null) {
      return sendError(res, 400, "bad_input");
    }
    const row = await updateSettings(db, approvalsDeps, {
      reportId: id,
      settings: body.settings,
      actor: { kind: "owner" },
    });
    res.json({ report: await reportView(db, approvalsDeps, row) });
  }));

  // POST /:id/go-live — seal the live set over the head revision the preview ran against.
  router.post(`${REPORTS_API_PREFIX}/:id/go-live`, route("POST /:id/go-live", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const body = req.body == null ? {} : req.body;
    if (typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");
    const result = await approveGoLive(db, approvalsDeps, {
      reportId: id,
      previewRunId: body.previewRunId,
      actor: { kind: "owner" },
    });
    res.json(result);
  }));

  // POST /:id/pause — the report stops. The seal stays on the row, for a resume.
  router.post(`${REPORTS_API_PREFIX}/:id/pause`, route("POST /:id/pause", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const body = req.body == null ? {} : req.body;
    if (typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");
    const row = await pauseReport(db, approvalsDeps, {
      reportId: id,
      reason: body.reason,
      actor: { kind: "owner" },
    });
    res.json({ report: await reportView(db, approvalsDeps, row) });
  }));

  // POST /:id/resume — back to live only while the seal still verifies, else `go_live_needed`.
  router.post(`${REPORTS_API_PREFIX}/:id/resume`, route("POST /:id/resume", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const row = await resumeReport(db, approvalsDeps, { reportId: id, actor: { kind: "owner" } });
    res.json({ report: await reportView(db, approvalsDeps, row) });
  }));

  /* -------------------------------------------------------------------------- runs */

  // POST /:id/preview — ask the scheduler hook for a preview run. A preview runs whatever the
  // report's status is (a draft is exactly what go-live needs to see), so nothing about the live set
  // is checked here; the request queue is the one path a run is ever asked for, and the hook queues it.
  router.post(`${REPORTS_API_PREFIX}/:id/preview`, route("POST /:id/preview", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    await requestRun(db, { reportId: id, kind: "preview", requestedBy: "owner" });
    kickReportsHook();
    res.status(202).json({ requested: true });
  }));

  // POST /:id/run-now — ask for a full run now. Only a live report whose approval still verifies
  // may run, and that is decided here as well as in the run engine: a 409 says to go live again.
  router.post(`${REPORTS_API_PREFIX}/:id/run-now`, route("POST /:id/run-now", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const row = await getReport(db, id);
    if (!row) return sendError(res, 404, "not_found");
    if (row.status !== "live" || !(await isLive(db, approvalsDeps, row))) {
      return sendError(res, 409, "go_live_needed");
    }
    await requestRun(db, { reportId: id, kind: "run_now", requestedBy: "owner" });
    kickReportsHook();
    res.status(202).json({ requested: true });
  }));

  // GET /:id/runs — this report's runs, newest first. A list row carries no gateway run id (that is
  // the boot sweep's own bookkeeping).
  router.get(`${REPORTS_API_PREFIX}/:id/runs`, route("GET /:id/runs", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    const runs = await listRuns(db, id);
    res.json({ runs });
  }));

  /* -------------------------------------------------------------------- recipients */

  // GET /:id/recipients — who this report goes to. The approval seal and its nonce never leave the
  // approvals module, so no answer here can carry them; each row carries `verified` (whether its seal
  // still matches the row as it is now) instead.
  router.get(`${REPORTS_API_PREFIX}/:id/recipients`, route("GET /:id/recipients", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    res.json({ recipients: await listRecipients(db, id, approvalsDeps) });
  }));

  // POST /:id/recipients — the owner adds one person: propose, then approve, in this one tap. A bot's
  // propose-only path is elsewhere; this route is the owner's, so `proposedBy` is always `owner`.
  router.post(`${REPORTS_API_PREFIX}/:id/recipients`, route("POST /:id/recipients", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const body = req.body == null ? {} : req.body;
    if (typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");
    const proposed = await proposeRecipient(db, approvalsDeps, {
      reportId: id,
      address: body.address,
      displayName: body.displayName,
      commentTier: body.commentTier,
      proposedBy: OWNER_LABEL,
    });
    const approved = await approveRecipient(db, approvalsDeps, {
      recipientId: proposed.id,
      actor: { kind: "owner" },
    });
    res.status(201).json({ recipient: approved });
  }));

  /** The shared body of approve, refuse and revoke: the same path, one decision each. */
  const decide = (label, action) => route(label, async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const rid = recipientIdOf(req, res);
    if (!rid) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    const row = await recipientInReport(db, res, id, rid);
    if (!row) return;
    const recipient = await action(db, rid);
    res.json({ recipient });
  });

  // POST /:id/recipients/:rid/approve — the owner's approval, with a fresh nonce and seal.
  router.post(`${REPORTS_API_PREFIX}/:id/recipients/:rid/approve`, decide(
    "POST /:id/recipients/:rid/approve",
    (db, rid) => approveRecipient(db, approvalsDeps, { recipientId: rid, actor: { kind: "owner" } }),
  ));

  // POST /:id/recipients/:rid/refuse — the state and a NULLED seal, so an old approval cannot return.
  router.post(`${REPORTS_API_PREFIX}/:id/recipients/:rid/refuse`, decide(
    "POST /:id/recipients/:rid/refuse",
    (db, rid) => refuseRecipient(db, approvalsDeps, { recipientId: rid, actor: { kind: "owner" } }),
  ));

  // POST /:id/recipients/:rid/revoke — the same for an approval already given.
  router.post(`${REPORTS_API_PREFIX}/:id/recipients/:rid/revoke`, decide(
    "POST /:id/recipients/:rid/revoke",
    (db, rid) => revokeRecipient(db, approvalsDeps, { recipientId: rid, actor: { kind: "owner" } }),
  ));

  /* ------------------------------------------------------------------- the send log */

  // GET /:id/sends?run=<runId> — this report's send log, or one run's, bounded to 200 rows. Claim
  // tokens and gateway run ids stay out of it: they are delivery's own bookkeeping.
  router.get(`${REPORTS_API_PREFIX}/:id/sends`, route("GET /:id/sends", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    const runId = req.query?.run;
    if (runId !== undefined && (typeof runId !== "string" || !RUN_ID_RE.test(runId))) {
      return sendError(res, 400, "bad_input");
    }
    res.json({ sends: await listSends(db, { reportId: id, runId: runId ?? null }) });
  }));

  // POST /:id/runs/:runId/send-rest — the owner's "Send to the rest": a `pending` row for every
  // approved recipient this run has not sent to, is not sending to, and holds no row for. It SENDS
  // nothing; delivery picks the rows up. A malformed run id is a 404, like every other path id here.
  router.post(`${REPORTS_API_PREFIX}/:id/runs/:runId/send-rest`, route(
    "POST /:id/runs/:runId/send-rest",
    async (db, req, res) => {
      const id = idOf(req, res);
      if (!id) return;
      const runId = String(req.params?.runId ?? "");
      if (!RUN_ID_RE.test(runId)) return sendError(res, 404, "not_found");
      if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
      const out = await createSendToRest(db, { approvals: approvalsDeps }, {
        reportId: id,
        runId,
        actor: { kind: "owner" },
      });
      res.status(201).json(out);
    },
  ));

  /* ------------------------------------------------------------------------- steps */

  /** A step key and revision in a path: a malformed one is a 404 before anything is read. */
  const stepPathOf = (req, res) => {
    const key = String(req.params?.key ?? "");
    const rev = String(req.params?.rev ?? "");
    if (!STEP_KEY_RE.test(key) || !STEP_REV_RE.test(rev)) {
      sendError(res, 404, "not_found");
      return null;
    }
    return { key, rev: Number(rev) };
  };

  // GET /:id/steps — every step key at its newest revision: the state, whether the approval still
  // verifies, and its files as paths, sizes and hashes. No file text, no seal, no nonce.
  router.get(`${REPORTS_API_PREFIX}/:id/steps`, route("GET /:id/steps", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    res.json({ steps: await listStepsForPage(db, id, approvalsDeps) });
  }));

  // GET /:id/steps/:key/:rev — one revision, with its files' text and the per-file line diff against
  // the previous APPROVED revision (that is what the owner reads before a tap).
  router.get(`${REPORTS_API_PREFIX}/:id/steps/:key/:rev`, route(
    "GET /:id/steps/:key/:rev",
    async (db, req, res) => {
      const id = idOf(req, res);
      if (!id) return;
      const step = stepPathOf(req, res);
      if (!step) return;
      if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
      const detail = await stepDetail(db, id, step.key, step.rev, approvalsDeps);
      if (!detail) return sendError(res, 404, "not_found");
      res.json({ step: detail, diff: await stepDiff(db, id, step.key, step.rev) });
    },
  ));

  // POST /:id/steps — the owner proposes a revision of one step. A proposal approves nothing: the
  // answer is `proposed` and the step runs only after an approval of that revision.
  router.post(`${REPORTS_API_PREFIX}/:id/steps`, route("POST /:id/steps", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const body = req.body == null ? {} : req.body;
    if (typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");
    const step = await proposeStep(db, approvalsDeps, {
      reportId: id,
      stepKey: body.stepKey,
      language: body.language,
      entry: body.entry,
      files: body.files,
      assets: body.assets,
      requirements: body.requirements,
      proposedBy: OWNER_LABEL,
    });
    res.status(201).json({ step });
  }));

  /** One step decision: the same path shape for approve, refuse and revoke. */
  const decideStep = (label, action) => route(label, async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const step = stepPathOf(req, res);
    if (!step) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    const row = await action(db, id, step.key, step.rev);
    res.json({ step: row });
  });

  // POST /:id/steps/:key/:rev/approve — a fresh nonce and seal over the bundle hash recomputed now,
  // for the bundle the owner was shown: the body carries the hash that view displayed, and a bundle
  // that moved since then (a file, a requirement, an asset) answers 409.
  router.post(`${REPORTS_API_PREFIX}/:id/steps/:key/:rev/approve`, route(
    "POST /:id/steps/:key/:rev/approve",
    async (db, req, res) => {
      const id = idOf(req, res);
      if (!id) return;
      const step = stepPathOf(req, res);
      if (!step) return;
      const body = req.body == null ? {} : req.body;
      if (typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");
      const bundleHash = body.bundleHash;
      if (typeof bundleHash !== "string" || !BUNDLE_HASH_RE.test(bundleHash)) {
        return sendError(res, 400, "bad_input");
      }
      if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
      const row = await approveStep(db, approvalsDeps, {
        reportId: id, stepKey: step.key, rev: step.rev, bundleHash, actor: { kind: "owner" },
      });
      res.json({ step: row });
    },
  ));

  // POST /:id/steps/:key/:rev/refuse — the state and a NULLED seal, so an old approval cannot return.
  router.post(`${REPORTS_API_PREFIX}/:id/steps/:key/:rev/refuse`, decideStep(
    "POST /:id/steps/:key/:rev/refuse",
    (db, id, key, rev) => refuseStep(db, approvalsDeps, {
      reportId: id, stepKey: key, rev, actor: { kind: "owner" },
    }),
  ));

  // POST /:id/steps/:key/:rev/revoke — the same for an approval already given.
  router.post(`${REPORTS_API_PREFIX}/:id/steps/:key/:rev/revoke`, decideStep(
    "POST /:id/steps/:key/:rev/revoke",
    (db, id, key, rev) => revokeStep(db, approvalsDeps, {
      reportId: id, stepKey: key, rev, actor: { kind: "owner" },
    }),
  ));

  /* ------------------------------------------------------------------------- hosts */

  /** A host in a path, as the row stores it (an exact name or a `*.suffix` wildcard), or a 404. */
  const hostPathOf = (req, res) => {
    const raw = String(req.params?.host ?? "");
    try {
      return normalizeHost(raw);
    } catch {
      sendError(res, 404, "not_found");
      return null;
    }
  };

  // GET /:id/hosts — every host of this report, with whether its approval still verifies.
  router.get(`${REPORTS_API_PREFIX}/:id/hosts`, route("GET /:id/hosts", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    res.json({ hosts: await listHosts(db, id, approvalsDeps) });
  }));

  // POST /:id/hosts — the owner adds one site: propose and approve in this one tap. The answer carries
  // the sentence about automated access, which is the owner's responsibility to check.
  router.post(`${REPORTS_API_PREFIX}/:id/hosts`, route("POST /:id/hosts", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const body = req.body == null ? {} : req.body;
    if (typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");
    const host = normalizeHost(body.host);
    await proposeHost(db, approvalsDeps, { reportId: id, host });
    const approved = await approveHost(db, approvalsDeps, {
      reportId: id, host, actor: { kind: "owner" },
    });
    res.status(201).json(approved);
  }));

  /** One host decision, addressed by the host itself (URL-encoded). */
  const decideHost = (label, action) => route(label, async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const host = hostPathOf(req, res);
    if (!host) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    res.json(await action(db, id, host));
  });

  // POST /:id/hosts/:host/approve — a fresh nonce and seal, and the same sentence as an add.
  router.post(`${REPORTS_API_PREFIX}/:id/hosts/:host/approve`, decideHost(
    "POST /:id/hosts/:host/approve",
    (db, id, host) => approveHost(db, approvalsDeps, { reportId: id, host, actor: { kind: "owner" } }),
  ));

  // POST /:id/hosts/:host/revoke — a NULLED seal, and every credential bound to that host stops.
  router.post(`${REPORTS_API_PREFIX}/:id/hosts/:host/revoke`, decideHost(
    "POST /:id/hosts/:host/revoke",
    async (db, id, host) => ({ host: await revokeHost(db, approvalsDeps, { reportId: id, host, actor: { kind: "owner" } }) }),
  ));

  /* ------------------------------------------------------------------- credentials */

  /**
   * The host of one credential of THIS report, looked up by the connection reference the path names, or
   * a 404. The list is the module's own (it carries no secret and no seal), so a reference of another
   * report is simply not in it.
   */
  const credentialHostOf = async (db, res, reportId, ref) => {
    const rows = await listCredentials(db, reportId, approvalsDeps);
    const found = rows.find((row) => row.connectionUuid === ref) ?? null;
    if (!found) {
      sendError(res, 404, "not_found");
      return null;
    }
    return found.host;
  };

  // GET /:id/credentials — the bindings this report holds: the host, the keychain reference, the rule
  // and the digest of that rule (which is what an approval hands back), and never the secret, the seal
  // or the nonce.
  router.get(`${REPORTS_API_PREFIX}/:id/credentials`, route("GET /:id/credentials", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    res.json({ credentials: await listCredentials(db, id, approvalsDeps) });
  }));

  /** The revoke decision, addressed by the connection reference in the path. */
  const decideCredential = (label, action) => route(label, async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    const ref = String(req.params?.uuid ?? "");
    if (!CREDENTIAL_REF_RE.test(ref)) return sendError(res, 404, "not_found");
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    const host = await credentialHostOf(db, res, id, ref);
    if (!host) return;
    res.json({ credential: await action(db, id, host) });
  });

  // POST /:id/credentials/:uuid/approve — a fresh nonce and seal over the report, the reference and the
  // host, for the row the owner was shown: the body carries the rule digest that view displayed and the
  // path carries the reference it displayed, and a row that moved since then answers 409. A credential
  // also needs an approved host: `injectRulesFor` re-checks it at run time.
  router.post(`${REPORTS_API_PREFIX}/:id/credentials/:uuid/approve`, route(
    "POST /:id/credentials/:uuid/approve",
    async (db, req, res) => {
      const id = idOf(req, res);
      if (!id) return;
      const ref = String(req.params?.uuid ?? "");
      if (!CREDENTIAL_REF_RE.test(ref)) return sendError(res, 404, "not_found");
      const body = req.body == null ? {} : req.body;
      if (typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");
      const injectHash = body.injectHash;
      if (typeof injectHash !== "string" || !INJECT_HASH_RE.test(injectHash)) {
        return sendError(res, 400, "bad_input");
      }
      if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
      const host = await credentialHostOf(db, res, id, ref);
      if (!host) return;
      const credential = await approveCredential(db, approvalsDeps, {
        reportId: id, host, connectionUuid: ref, injectHash, actor: { kind: "owner" },
      });
      res.json({ credential });
    },
  ));

  // POST /:id/credentials/:uuid/revoke — a NULLED seal, and the keychain row it named stops being served.
  router.post(`${REPORTS_API_PREFIX}/:id/credentials/:uuid/revoke`, decideCredential(
    "POST /:id/credentials/:uuid/revoke",
    (db, id, host) => revokeCredential(db, approvalsDeps, {
      reportId: id, host, actor: { kind: "owner" },
    }),
  ));

  /* ------------------------------------------------------------------------ assets */

  // GET /:id/assets — the named inputs of this report: name, hash, size and whether the file on disk
  // still hashes to the row. The bytes are never in the answer; an upload is the raw-body route above.
  router.get(`${REPORTS_API_PREFIX}/:id/assets`, route("GET /:id/assets", async (db, req, res) => {
    const id = idOf(req, res);
    if (!id) return;
    if (!(await getReport(db, id))) return sendError(res, 404, "not_found");
    res.json({ assets: await listAssets(db, id, approvalsDeps) });
  }));

  return router;
}

export default reportsApiRouter;