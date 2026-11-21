/**
 * The run engine: what makes one attempt at running a report happen, and what it leaves behind.
 *
 * `startRun` writes a `queued` row and nothing else; `executeRun` claims it and does the work. The claim
 * is the whole concurrency story: a guarded UPDATE from `queued` to `running` that also requires the
 * report row to still be there, and a caller that changes no row does nothing at all (a second executor,
 * a run a boot sweep already failed, or a run whose report has been deleted never runs twice and never
 * starts on a report that is gone). The finish is guarded the same way (`status = 'running' AND
 * gateway_run_id = ?`), so a late finish cannot overwrite a run the sweep has already closed.
 *
 * WHAT A SCHEDULED OR MANUAL RUN EXECUTES, and why it is not "the report": a run of a live report
 * executes the SEALED live revision's recipe, with the bot, project, artifact and sender from the
 * verified live set (`verifyLive`), never from a fresh read of the row. Saving a newer head recipe does
 * not change what a live report runs; it changes what the next go-live would approve. A report that is
 * not live, whose seal no longer verifies, or whose status was changed outside the approvals module
 * does not run at all: it is recorded `failed` with one sentence the owner can act on. A preview is the
 * one trigger that reads a revision by number and needs no live report, because a preview of a draft is
 * exactly what go-live needs.
 *
 * NOTHING HERE SENDS ANYTHING BY ITSELF. This module imports no delivery module and no mail module: the
 * one outgoing step is `deps.deliver`, which a caller injects (the scheduler hook, or the reports API)
 * and which every scheduled and manual run requires. A run whose caller did not wire it is recorded
 * `failed` with "Delivery is not wired." and its blocks are not run at all, so a missing seam can never
 * turn into a half-run report. A preview never calls `deliver`, and neither does any run without a
 * VERIFIED live set: a run refused because the report is not live (or because the report row is gone)
 * sends nothing at all, because it never happened. The report row is read AGAIN immediately before the
 * one outgoing step, so a report deleted while its blocks were working is not delivered: that run is
 * finished `failed` instead. The owner hears about such a run from the scheduler hook's own queue
 * wrapper (`notify`), not from the delivery seam.
 *
 * Every reason text and the block log pass through `redactSecrets` with this instance's secret values
 * (`deps.getSecrets`, the same reader the approvals module uses) and are capped: a source that echoes a
 * credential into an error message cannot put it in the database.
 *
 * STATE IS THE RECIPE'S MEMORY, AND A RUN WRITES IT LAST: a block that dedupes across runs
 * (`dedupe_seen`, `diff_last`) buffers a `report_state` value as it works; this module applies those
 * writes only AFTER the version write, and only for a run that ends not-`failed` and whose trigger is not
 * `preview`. A failed run, a failed version write and every preview therefore leave `report_state`
 * exactly as it was: a preview is unapproved text and must not move the report's memory either. A block
 * cannot reach the keys the artifact bridge owns: `isReservedStateKey` refuses them where it buffers, and
 * this module refuses them AGAIN here, so a buffered list that arrived any other way cannot write one.
 * Every write lands in ONE `runTransaction`, so a state write that cannot be applied leaves none of them
 * applied.
 *
 * `deps` is the seam:
 *   - `approvals`: the deps `verifyLive` takes (`loadSeed`, `getSchedule`, `resolveModelRef`,
 *     `registry`, ...). Absent, no seal verifies and no scheduled or manual run happens.
 *   - `runBlocks({report, recipe, run, live, state, db})`: runs the recipe and answers
 *     `{items, sections, warnings, sourceErrors, stateWrites, document?, allowedLinks?}`. The default is
 *     the block registry's executor (`blocks/run-recipe.js`), handed this module's own deps so a custom
 *     block reaches `custom-step.js`. Warnings are recorded beside the source errors and NEVER as one
 *     (a shape block's own trouble, a model block's `ai_fallback`): the status rule below is about source
 *     errors, so an advisory note fails no run.
 *   - `deliver(db, {report, run, live, status, artifactVersion})`: required for `schedule` and `manual`.
 *   - `writeVersion(db, {report, run, live, result})` -> `{artifactVersion}`: optional; absent, the run
 *     keeps no artifact version.
 *   - `getSecrets()`: literal secret values to scrub. Absent, this instance's display list.
 *   - `now()`: epoch ms for every row this module writes, so a test's clock moves them.
 *
 * Status rule: any source error is `failed` and the text names each source ("Couldn't reach <source>");
 * no errors and no items is `empty`; otherwise `ok`. A throw from a block run, from the version write or
 * from reading the revision is `failed` with its own message. A throw from `deliver` does NOT change the
 * status: the run did happen, and its error text gains "Delivery failed: <message>".
 *
 * Times are epoch ms. `trigger` is an SQL keyword, so it is quoted in every statement here.
 */
import { randomBytes } from "node:crypto";
import { getReport, getRevision } from "./store.js";
import { isReservedStateKey } from "./artifact-bridge.js";
import { runRecipeBlocks } from "./blocks/run-recipe.js";
import { canonicalJson } from "./recipe-hash.js";
import { verifyLive } from "./approvals.js";
import { gatewayRunId } from "../run-id.js";
import { redactSecrets } from "../../shared/redact-secrets.js";
import { getSecretValues } from "../../shared/secret-values.js";

/** What made a run happen. */
export const RUN_TRIGGERS = Object.freeze(["schedule", "manual", "preview"]);

/** What a run's status may say: queued and running while it is in hand, then one of the three ends. */
export const RUN_STATUSES = Object.freeze(["queued", "running", "ok", "empty", "failed"]);

/** The sentence a report that may not run is recorded with. */
export const NOT_LIVE_TEXT = "This report is not live. Check it and go live again.";

/** The sentence a scheduled or manual run with no `deps.deliver` is recorded with. */
export const DELIVERY_NOT_WIRED_TEXT = "Delivery is not wired.";

/** The sentence a boot sweep writes over a run whose gateway process went away. */
export const RESTARTED_TEXT = "Crow restarted during this run";

/** The sentence a run left `queued` for a report that no longer exists is finished with. */
export const REPORT_GONE_TEXT = "This report no longer exists.";

/** How long a reason text or a block log may be. */
const TEXT_MAX = 2000;

/** How long one source error's message may be before the block log would be a wall of text. */
const MESSAGE_MAX = 300;

const RUN_COLUMNS = `id, report_id, "trigger", requested_by, scheduled_for, late, started_at, ended_at,
  status, recipe_rev, artifact_version, block_log_json, error_text, gateway_run_id, created_at`;

/** A list row is the same row without the gateway id: a reader listing runs does not need it. */
const RUN_LIST_COLUMNS = `id, report_id, "trigger", requested_by, scheduled_for, late, started_at,
  ended_at, status, recipe_rev, artifact_version, block_log_json, error_text, created_at`;

const ID_RE = /^rpt-[0-9a-f]{16}$/;
const BOT_REQUESTER_RE = /^bot:.+$/;

function fail(code, detail) {
  const err = new Error(detail ? `${code}: ${detail}` : code);
  err.code = code;
  if (detail) err.detail = detail;
  return err;
}

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

function clock(deps) {
  const value = Number(deps.now());
  return Number.isFinite(value) ? value : Date.now();
}

/* ------------------------------------------------------------------------- the seam */

function defaultGetSecrets() {
  try {
    return getSecretValues();
  } catch {
    return [];
  }
}

/**
 * The seam one recipe block gets: this module's own resolved deps, the approvals deps (a custom step's
 * verification needs the seal seed, which lives there), and whatever else the caller injected (a step
 * runner, an env builder, the report's home). Nothing from a recipe is in here.
 */
function blockSeam(given, resolved) {
  return { ...(given.approvals ?? {}), ...given, ...resolved };
}

/** `deps` with every member present; a member that is absent falls back to the real thing. */
function resolveDeps(deps) {
  const given = deps == null ? {} : deps;
  const fn = (key, fallback) => (typeof given[key] === "function" ? given[key] : fallback);
  const resolved = {
    approvals: given.approvals ?? null,
    runBlocks: null,
    deliver: typeof given.deliver === "function" ? given.deliver : null,
    writeVersion: typeof given.writeVersion === "function" ? given.writeVersion : null,
    getSecrets: fn("getSecrets", defaultGetSecrets),
    now: fn("now", Date.now),
  };
  // The default executor is the block registry's, handed a block seam: a custom block needs the step
  // runner and the seal seed, and a caller that injects `runBlocks` still owns the whole seam.
  resolved.runBlocks = fn("runBlocks", (args) => runRecipeBlocks({ ...args, deps: blockSeam(given, resolved) }));
  return resolved;
}

function secretsOf(deps) {
  try {
    const values = deps.getSecrets();
    return Array.isArray(values) ? values : [];
  } catch {
    return [];
  }
}

/** Redact first, then cut: no prefix of a secret survives the cap. */
function redactedText(value, secrets, cap = TEXT_MAX) {
  const scrubbed = redactSecrets(text(value), secrets);
  return scrubbed.length > cap ? scrubbed.slice(0, cap) : scrubbed;
}

/* ---------------------------------------------------------------------- the run row */

/** One row as a reader wants it: camelCase, the block log parsed back into an object. */
function mapRun(row) {
  if (!row) return null;
  let blockLog = null;
  if (typeof row.block_log_json === "string" && row.block_log_json) {
    try {
      blockLog = JSON.parse(row.block_log_json);
    } catch {
      blockLog = null;
    }
  }
  return {
    id: row.id,
    reportId: row.report_id,
    trigger: row.trigger,
    requestedBy: row.requested_by,
    scheduledFor: row.scheduled_for == null ? null : Number(row.scheduled_for),
    late: Number(row.late) === 1 ? 1 : 0,
    startedAt: row.started_at == null ? null : Number(row.started_at),
    endedAt: row.ended_at == null ? null : Number(row.ended_at),
    status: row.status,
    recipeRev: row.recipe_rev == null ? null : Number(row.recipe_rev),
    artifactVersion: row.artifact_version == null ? null : Number(row.artifact_version),
    blockLog,
    errorText: row.error_text,
    gatewayRunId: row.gateway_run_id ?? null,
    createdAt: row.created_at == null ? null : Number(row.created_at),
  };
}

/**
 * One run, camelCase, or null when there is no such run. The row carries `gatewayRunId` because the boot
 * sweep and the guarded finish compare it; a list row does not (see `listRuns`).
 *
 * @param {object} db
 * @param {string} runId
 * @returns {Promise<object|null>}
 */
export async function getRun(db, runId) {
  if (typeof runId !== "string" || !runId) return null;
  const { rows } = await db.execute({
    sql: `SELECT ${RUN_COLUMNS} FROM report_runs WHERE id = ?`,
    args: [runId],
  });
  return mapRun(rows[0]);
}

/**
 * The scheduled run for one window, or null: the row the run table's unique
 * (report_id, scheduled_for) index allows at most one of per report.
 *
 * A pass that finds `startRun` answering `duplicate` reads the row through this: when it is still
 * `queued`, nobody has executed it (the earlier pass that wrote it lost its window claim, or its claim
 * threw), so the pass that holds the window queues it.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {number} scheduledFor epoch ms of the window
 * @returns {Promise<object|null>}
 */
export async function getScheduledRun(db, reportId, scheduledFor) {
  if (typeof reportId !== "string" || !reportId) return null;
  const window = Number(scheduledFor);
  if (!Number.isFinite(window)) return null;
  const { rows } = await db.execute({
    sql: `SELECT ${RUN_COLUMNS} FROM report_runs
           WHERE report_id = ? AND scheduled_for = ? AND "trigger" = 'schedule'
           LIMIT 1`,
    args: [reportId, window],
  });
  return mapRun(rows[0]);
}

/**
 * One report's runs, newest first.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {{limit?: number}} [opts]
 * @returns {Promise<object[]>}
 */
export async function listRuns(db, reportId, { limit = 50 } = {}) {
  if (typeof reportId !== "string" || !reportId) return [];
  const pageSize = Number.isInteger(limit) && limit > 0 ? limit : 50;
  const { rows } = await db.execute({
    sql: `SELECT ${RUN_LIST_COLUMNS} FROM report_runs
           WHERE report_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`,
    args: [reportId, pageSize],
  });
  return rows.map((row) => {
    const run = mapRun(row);
    delete run.gatewayRunId;
    return run;
  });
}

/**
 * A run as the approvals module reads one: `{id, reportId, kind: "preview"|"run", status, recipeRev}`, or
 * null. `kind` is what go-live checks: only a `preview` may approve a report, and a full run never may.
 *
 * @param {object} db
 * @param {string} runId
 * @returns {Promise<{id: string, reportId: string, kind: "preview"|"run", status: string,
 *   recipeRev: number}|null>}
 */
export async function getRunForApproval(db, runId) {
  const run = await getRun(db, runId);
  if (!run) return null;
  return {
    id: run.id,
    reportId: run.reportId,
    kind: run.trigger === "preview" ? "preview" : "run",
    status: run.status,
    recipeRev: run.recipeRev,
  };
}

/* ------------------------------------------------------------------ the status audit */

/**
 * The status-audit rule: `status` is NOT a sealed field (see approvals.js), so a direct UPDATE that flips
 * a paused report back to `live` would otherwise leave a report whose seal still verifies. What the
 * approvals module does seal is the DECISION: it writes an `approved` audit row on go-live, on resume and
 * on a re-stamp, and a `refused` row on every pause (owner or system) and on a settings change that
 * pauses. So a report may run only when the NEWEST live-kind audit row is `approved`. No row at all is
 * not an approval either: a report nobody took live does not run because a column says `live`.
 *
 * Never throws: a broken audit read is a refusal (fail closed).
 *
 * @param {object} db
 * @param {string} reportId
 * @returns {Promise<boolean>}
 */
export async function statusAuditOk(db, reportId) {
  if (typeof reportId !== "string" || !reportId) return false;
  try {
    const { rows } = await db.execute({
      sql: `SELECT decided FROM report_approvals_audit
             WHERE report_id = ? AND kind = 'live' ORDER BY id DESC LIMIT 1`,
      args: [reportId],
    });
    return rows[0]?.decided === "approved";
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------------ startRun */

/** Who may ask for a run: the owner, the schedule, or a bot acting in the report's project. */
function validRequestedBy(value) {
  if (value === "owner" || value === "schedule") return true;
  return typeof value === "string" && BOT_REQUESTER_RE.test(value);
}

function isUniqueViolation(err) {
  const code = err?.code ?? "";
  return code === "SQLITE_CONSTRAINT_UNIQUE" || code === "SQLITE_CONSTRAINT"
    || /UNIQUE constraint failed/i.test(String(err?.message ?? ""));
}

/**
 * Put one run in the queue.
 *
 * A `preview` records the report's head revision on the run, because the preview is of what the owner (or
 * a bot) has just saved; every other trigger leaves `recipe_rev` NULL and the executor fills it from the
 * sealed live revision. A scheduled window that already has a run for this report is not an error: the
 * unique index refuses the duplicate and this answers `{runId: null, duplicate: true}`, so a tick that
 * overlaps another can never make the same window run twice.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, trigger: "schedule"|"manual"|"preview",
 *   requestedBy: "owner"|"schedule"|string, scheduledFor?: number|null, late?: boolean}} input
 * @returns {Promise<{runId: string|null, duplicate?: boolean}>}
 * @throws {Error} `bad_input` or `not_found`
 */
export async function startRun(db, deps, { reportId, trigger, requestedBy, scheduledFor = null, late = false } = {}) {
  const d = resolveDeps(deps);
  if (!RUN_TRIGGERS.includes(trigger)) throw fail("bad_input", "trigger");
  if (!validRequestedBy(requestedBy)) throw fail("bad_input", "requestedBy");
  if (typeof reportId !== "string" || !ID_RE.test(reportId)) throw fail("bad_input", "reportId");
  if (scheduledFor != null && !Number.isFinite(Number(scheduledFor))) {
    throw fail("bad_input", "scheduledFor");
  }
  const report = await getReport(db, reportId);
  if (!report) throw fail("not_found", "report");

  const id = "rrn-" + randomBytes(8).toString("hex");
  const window = scheduledFor == null ? null : Number(scheduledFor);
  try {
    await db.execute({
      sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, scheduled_for, late,
              status, recipe_rev, gateway_run_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)`,
      args: [
        id, report.id, trigger, requestedBy, window, late ? 1 : 0,
        trigger === "preview" ? Number(report.recipe_rev) : null, gatewayRunId(), clock(d),
      ],
    });
  } catch (err) {
    if (trigger === "schedule" && window != null && isUniqueViolation(err)) {
      return { runId: null, duplicate: true };
    }
    throw err;
  }
  return { runId: id };
}

/* ---------------------------------------------------------------------- executeRun */

/**
 * Run one queued run to its end. Never throws for a run failure: a run that cannot happen is recorded
 * `failed` with a redacted reason and answered with that status, and an unexpected throw anywhere after
 * the claim fails the run the same way rather than leaving a `running` row behind (a run the owner
 * could only ever see as "still going").
 *
 * The steps, in order (and see the header for why each one is what it is):
 *   1. Claim: `queued` -> `running` in one guarded UPDATE, which also requires the report row to still
 *      be there. No row changed means somebody else owns this run (a second executor, a sweep that
 *      closed it), or its report is gone while the row is still `queued`; that second case is finished
 *      here with `REPORT_GONE_TEXT` in one more guarded UPDATE (`WHERE id = ? AND status = 'queued'`),
 *      so a run nobody can execute is not left waiting forever. Either way the answer is the run's
 *      current state and nothing runs.
 *   2. A preview reads its revision by the number the run recorded. No live check: a draft previews.
 *   3. A scheduled or manual run needs a live report whose seal verifies AND whose newest live-kind audit
 *      decision is `approved`; otherwise `failed`, and no block runs.
 *   4. Run the blocks. Source errors give `failed`, no items gives `empty`, anything else gives `ok`.
 *   5. Write the version, when the caller injects `writeVersion`.
 *   6. Apply the blocks' buffered `stateWrites`, but only when the run ends not-failed and is not a
 *      preview (see STATE IS THE RECIPE'S MEMORY above).
 *   7. Deliver, but only for a run that has a verified live set AND whose report row is still there: a
 *      preview, a refused run and a run whose report was deleted mid-flight send nothing. A delivery
 *      throw keeps the status and is appended to the error text.
 *   8. Finish in one guarded UPDATE, so a run a sweep has already closed is left as the sweep left it.
 *
 * @param {object} db
 * @param {object} deps
 * @param {string} runId
 * @returns {Promise<{status: string|null, artifactVersion: number|null}>}
 */
export async function executeRun(db, deps, runId) {
  const d = resolveDeps(deps);
  const processRunId = gatewayRunId();
  const claimedAt = clock(d);
  const claim = await db.execute({
    sql: `UPDATE report_runs SET status = 'running', started_at = ?, gateway_run_id = ?
           WHERE id = ? AND status = 'queued'
             AND EXISTS (SELECT 1 FROM reports WHERE id = report_id)`,
    args: [claimedAt, processRunId, runId],
  });
  if (claim.rowsAffected !== 1) {
    await finishOrphanedQueuedRun(db, d, runId);
    return answerFor(db, runId);
  }

  try {
    return await runClaimed(db, d, runId, processRunId);
  } catch (err) {
    // Nothing after the claim is expected to throw (every seam below is guarded), but a read the
    // database refuses is not something to leave a `running` row over. The finish is guarded exactly
    // like the normal one, so a sweep that already closed the run keeps the row it wrote.
    const secrets = secretsOf(d);
    const errorText = redactedText(err?.message || "This run failed.", secrets);
    try {
      await db.execute({
        sql: `UPDATE report_runs SET status = 'failed', ended_at = ?, error_text = ?
               WHERE id = ? AND status = 'running' AND gateway_run_id = ?`,
        args: [clock(d), errorText, runId, processRunId],
      });
    } catch {
      // The row cannot be written at all: there is nothing more this executor can do about it.
    }
    return { status: "failed", artifactVersion: null };
  }
}

/** Is the run's report row still there? One read, immediately before the one outgoing step. */
async function reportExists(db, reportId) {
  if (typeof reportId !== "string" || !reportId) return false;
  const { rows } = await db.execute({ sql: "SELECT id FROM reports WHERE id = ?", args: [reportId] });
  return rows.length > 0;
}

/**
 * A claim that changed no row and left the run `queued` means its report row is gone: the guarded UPDATE
 * hands the run back as `failed` with `REPORT_GONE_TEXT`, in one more guarded UPDATE that a concurrent
 * executor or sweep still wins. Never throws: a row that cannot be read or written is a run left as it
 * was, and the answer is the run's current state either way.
 */
async function finishOrphanedQueuedRun(db, d, runId) {
  try {
    const row = await getRun(db, runId);
    if (!row || row.status !== "queued") return;
    if (await reportExists(db, row.reportId)) return;
    await db.execute({
      sql: `UPDATE report_runs SET status = 'failed', ended_at = ?, error_text = ?
             WHERE id = ? AND status = 'queued'`,
      args: [clock(d), REPORT_GONE_TEXT, runId],
    });
  } catch {
    // The row cannot be read or written: there is nothing more this executor can do about it.
  }
}

/** The claimed run's work, from the row read to the guarded finish. Throws only on a database failure. */
async function runClaimed(db, d, runId, processRunId) {
  const run = await getRun(db, runId);
  if (!run) return { status: null, artifactVersion: null };

  const secrets = secretsOf(d);
  const report = await getReport(db, run.reportId);

  let status = "ok";
  let errorText = null;
  let blockLog = null;
  let artifactVersion = null;
  let recipeRev = run.recipeRev;
  let live = null;
  let recipe = null;
  let result = null;

  if (!report) {
    status = "failed";
    errorText = REPORT_GONE_TEXT;
  } else if (run.trigger === "preview") {
    // A preview of a draft or a paused report is exactly what go-live needs, so nothing about the live
    // set is checked here: only that the revision the run recorded can still be read.
    const revision = Number.isInteger(run.recipeRev)
      ? await getRevision(db, run.reportId, run.recipeRev)
      : null;
    if (!revision) {
      status = "failed";
      errorText = "The saved revision for this preview is missing.";
    } else {
      try {
        recipe = JSON.parse(revision.recipe_json);
      } catch {
        status = "failed";
        errorText = "The saved recipe for this preview could not be read.";
      }
    }
  } else {
    // Scheduled or manual: the report must be live NOW, and its live approval must still be the newest
    // decision on record. Everything this run uses comes from the verified live set.
    live = await verifyLive(db, d.approvals, report);
    const auditOk = await statusAuditOk(db, run.reportId);
    if (!live || !auditOk) {
      status = "failed";
      errorText = NOT_LIVE_TEXT;
    } else if (!d.deliver) {
      // Checked before any block runs: a run that cannot be delivered must not read the owner's sources.
      status = "failed";
      errorText = DELIVERY_NOT_WIRED_TEXT;
    } else {
      recipe = live.recipe;
      recipeRev = live.rev;
    }
  }

  if (status === "ok" && recipe) {
    try {
      result = await d.runBlocks({ report, recipe, run, live, state: {}, db });
    } catch (err) {
      status = "failed";
      errorText = redactedText(err?.message || "This run failed.", secrets);
    }
    if (status === "ok") {
      const items = Array.isArray(result?.items) ? result.items : [];
      const sourceErrors = (Array.isArray(result?.sourceErrors) ? result.sourceErrors : [])
        .map((entry) => ({
          source: redactedText(entry?.source, secrets, MESSAGE_MAX),
          message: redactedText(entry?.message, secrets, MESSAGE_MAX),
        }))
        .filter((entry) => entry.source || entry.message);
      // A block's own advisory note (`chart_rows_dropped`, a model block's `ai_fallback`) is recorded
      // beside the source errors and never as one: an advisory note fails no run. The key is absent on a
      // run that had no note, so a run's log keeps the shape it always had.
      const warnings = (Array.isArray(result?.warnings) ? result.warnings : [])
        .map((entry) => ({
          source: redactedText(entry?.source, secrets, MESSAGE_MAX),
          message: redactedText(entry?.message, secrets, MESSAGE_MAX),
        }))
        .filter((entry) => entry.source || entry.message);
      blockLog = warnings.length
        ? { items: items.length, sourceErrors, warnings }
        : { items: items.length, sourceErrors };
      if (sourceErrors.length) {
        status = "failed";
        errorText = redactedText(sourceErrors
          .map((entry) => `Couldn't reach ${entry.source || "a source"}.`)
          .join(" "), secrets);
      } else {
        status = items.length ? "ok" : "empty";
      }
    }
  }

  // The version write: optional, injected by the caller that owns artifacts.
  if (d.writeVersion && recipe && status !== "failed") {
    try {
      const written = await d.writeVersion(db, {
        report,
        run: { ...run, recipeRev, status, blockLog },
        live,
        result,
      });
      const version = Number(written?.artifactVersion);
      artifactVersion = Number.isFinite(version) ? version : null;
    } catch (err) {
      status = "failed";
      errorText = redactedText(err?.message || "The report version could not be written.", secrets);
    }
  }

  // State: buffered by the blocks, applied here, and only for a run that ends well. A failed run (a
  // source error, a failed version write), and every preview, leave `report_state` as it was. A key the
  // artifact bridge owns is not written (and does not change the run's status), and every remaining
  // write lands in one transaction, so a state write that cannot be applied applies none of them.
  const stateWrites = result && Array.isArray(result.stateWrites) ? result.stateWrites : [];
  if (status !== "failed" && run.trigger !== "preview" && report && stateWrites.length) {
    const writes = stateWrites.filter((write) => write != null
      && typeof write.key === "string" && write.key
      && !isReservedStateKey(write.key));
    try {
      if (writes.length) {
        const at = clock(d);
        await db.runTransaction((runStatement) => {
          // The report must still be there, the same check the store's own `setState` makes: a report
          // removed under a run (a direct SQL delete) must not collect rows nobody can reach.
          const found = runStatement({ sql: "SELECT id FROM reports WHERE id = ?", args: [report.id] });
          if (!found.rows[0]) throw fail("not_found", "report");
          for (const write of writes) {
            runStatement({
              sql: `INSERT INTO report_state (report_id, key, value_json, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(report_id, key) DO UPDATE SET value_json = excluded.value_json,
                      updated_at = excluded.updated_at`,
              args: [report.id, write.key, canonicalJson(write.value === undefined ? null : write.value), at],
            });
          }
        });
      }
    } catch {
      // A state write that cannot land is not a run that did not happen: the version is already written,
      // so the run keeps its status and says what went wrong in a code word.
      errorText = redactedText(errorText ? `${errorText} state_write_failed` : "state_write_failed", secrets);
    }
  }

  const blockLogJson = blockLog ? cappedBlockLog(blockLog, secrets) : null;

  // Delivery: never for a preview, and only for a run that executed a VERIFIED live set AND whose
  // report is still there when the one outgoing step is reached. A refused run (not live, report gone)
  // never happened, so nothing leaves the instance for it; the owner's notice for such a run is the
  // scheduler hook's, through its own `notify`.
  const deliverTo = run.trigger !== "preview" && live && d.deliver ? d.deliver : null;
  // A report removed while the blocks were working (deleted between the claim and here) is not
  // delivered: the row is read again right before delivery, and the run is finished failed instead.
  const reportGone = deliverTo ? !(await reportExists(db, run.reportId)) : false;
  if (reportGone) {
    status = "failed";
    errorText = REPORT_GONE_TEXT;
  } else if (deliverTo) {
    const finished = {
      ...run,
      status,
      recipeRev,
      artifactVersion,
      blockLog,
      errorText,
    };
    try {
      await d.deliver(db, { report, run: finished, live, status, artifactVersion });
    } catch (err) {
      const note = `Delivery failed: ${redactedText(err?.message || "unknown error", secrets, MESSAGE_MAX)}`;
      errorText = redactedText(errorText ? `${errorText} ${note}` : note, secrets);
    }
  }

  const endedAt = clock(d);
  const finish = await db.execute({
    sql: `UPDATE report_runs
             SET status = ?, ended_at = ?, artifact_version = ?, block_log_json = ?, error_text = ?,
                 recipe_rev = ?
           WHERE id = ? AND status = 'running' AND gateway_run_id = ?`,
    args: [
      status, endedAt, artifactVersion, blockLogJson, errorText, recipeRev,
      run.id, processRunId,
    ],
  });
  // A sweep that closed this run while it was working owns the row now: answer what is stored, not what
  // this executor would have written.
  if (finish.rowsAffected !== 1) return answerFor(db, run.id);
  return { status, artifactVersion };
}

/** The run's current status and artifact version, as the row holds them. */
async function answerFor(db, runId) {
  const current = await getRun(db, runId);
  return {
    status: current ? current.status : null,
    artifactVersion: current ? current.artifactVersion : null,
  };
}

/**
 * The block log as JSON text: every string already redacted, the source-error list trimmed from the end
 * until the text fits, so the result is always valid JSON (a truncated JSON body would be worse than a
 * shorter list).
 */
function cappedBlockLog(blockLog, secrets) {
  let current = blockLog;
  let json = redactSecrets(JSON.stringify(current), secrets);
  while (json.length > TEXT_MAX && current.sourceErrors.length) {
    current = { ...current, sourceErrors: current.sourceErrors.slice(0, -1) };
    json = redactSecrets(JSON.stringify(current), secrets);
  }
  return json;
}