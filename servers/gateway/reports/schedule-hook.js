/**
 * The reports scheduler hook: the one place a scheduled report run, a bot's (or the owner's) run
 * request and the "the box was off across a window" catch-up actually happen.
 *
 * The gateway's scheduler calls this hook once a minute (scheduler-hooks.js) and NEVER waits for a run.
 * That matters: scheduler.js awaits every hook inside the same tick that drives the `mail-send` hold, so
 * a hook that awaited a report run would stall every other reminder for as long as the report took.
 * `tick` therefore only CLAIMS and DISPATCHES: it takes the lease, guards the live reports, claims the
 * due `report:` rows, drains the request queue, and hands each run to a per-process queue that runs at
 * most `reports.max_concurrent_runs` at a time (default 1). The queue is fire-and-forget.
 *
 * What the tick does, in this order, and why the order:
 *
 *   1. The lease (reports/lease.js). Only the primary gateway runs reports; a companion `--no-auth`
 *      gateway never even registers this hook. A live lease held by another process means another
 *      primary is on this crow.db, so this tick waits and the next one tries again.
 *   2. The row guard and the broken seal, for every report with status `live`. A live report must have
 *      its schedule row, with the task `report:<reportId>` and `enabled = 1`; and its seal must verify
 *      with the newest live-kind approval decision still `approved`. Either failure pauses the report
 *      with a reason the owner can act on, and notifies ONCE: the pause is ONE guarded UPDATE
 *      (`WHERE id = ? AND status = 'live'`), so exactly one overlapping pass changes the row and only
 *      that pass writes the audit row and sends the notice.
 *   3. The due rows: `schedules` where the task matches REPORT_TASK_GLOB (the SQL twin of
 *      schedule-core's REPORT_TASK_RE), `enabled = 1` and `next_run <= now`. A draft or paused report
 *      only has its window advanced. For a live report the `report_runs` row is written FIRST (so a
 *      refused database write leaves the window to retry), then the window is CLAIMED with a guarded
 *      UPDATE (only the winner continues), and it makes exactly ONE run however many windows were
 *      missed (`scheduledFor` is the latest missed window, `late` is set when it is past the grace)
 *      with its `next_run` moved past now. The claim winner ALWAYS queues exactly the one run row the
 *      window's unique index allows: its own, or (when `startRun` answered `duplicate`) the still
 *      `queued` row an earlier pass wrote and never queued. A pass that LOSES the claim queues
 *      nothing and closes nothing: the run row it wrote stays `queued` for the winner, so a window is
 *      never lost to the startRun-then-claim order. A stray row that names no report is ignored and
 *      said once.
 *   4. The run requests (report_run_requests): a preview runs as a preview, a run now runs only for a
 *      live report whose seal verifies. A request for a report that is gone is dropped.
 *   5. The pending sends (`deliverPending`): the `pending` `report_sends` rows the owner's "Send to the
 *      rest" wrote (`send-log.js`) go out here, at most one pair of (report, run) per row of a bounded
 *      batch, oldest first, and only for a run that has FINISHED in a sendable status
 *      (`SENDABLE_RUN_STATUSES`) and once a row is older than `pendingGraceMs` (so this never races a
 *      delivery that is writing its own pending rows right now). A pair whose report is gone, not live,
 *      or whose seal no longer verifies is never handed over: its rows settle `refused` / `not_live`
 *      (`refusePendingSends` in send-sweep.js), exactly as the send door refuses a row for that reason.
 *      A report that cannot be read at all is a third answer (`unknown`): that pair is skipped, nothing
 *      is settled and nothing is remembered, because a database that burped is not a report that
 *      stopped. The command's guarded pending -> sending claim is what makes a row go at most once,
 *      whatever overlaps, and this pass remembers the (report, run, pending row ids) set it OFFERED to
 *      the seam so the same set is not offered again while its rows are still pending: the rows the
 *      seam SETTLES (no link, a recipient no longer approved, a recipient already spoken for) leave
 *      `pending` and are never offered again at all, and a set the seam THREW on is forgotten so the
 *      next pass offers it again (those rows are still owed a send). That memory is also what keeps a
 *      set the seam cannot move from blocking the pairs behind it: the query takes the oldest eligible
 *      ROWS (a generous cap, `PENDING_ROW_SCAN`), the pass skips every pair it already offered, and it
 *      offers at most `PENDING_SEND_BATCH` new ones, so the next pass reaches the rest. This step is in
 *      BOTH the full and the light pass and sits under the lease the pass already holds.
 *
 * A report that is queued or running is not queued again for the same schedule window: the run table's
 * unique (report_id, scheduled_for) index refuses the duplicate and `startRun` answers
 * `{duplicate: true}`.
 *
 * ONE PASS AT A TIME (`runTick`'s promise chain): a scheduler tick, a `kick` from a run route and a
 * `runNow` from the Schedule page share one chain, so their lease refreshes and their claims never
 * interleave. Two passes that did would read the same window and the same lease and fight over both.
 *
 * The owner's notice for a run that did not happen is the QUEUE WRAPPER's (`notifyRefused`): a run
 * refused because its report is not live delivers nothing (`run.js` calls no delivery seam without a
 * verified live set), so without this the owner would never hear about it.
 *
 * THE BOOT SWEEP (`sweep`): any `report_runs` row still `queued` or `running` whose `gateway_run_id` is
 * not this process's was cut off by a restart (an auto-update restart included, which is why the id is
 * minted per process and not the kernel's boot id). One guarded UPDATE ... RETURNING marks them
 * `failed` with "Crow restarted during this run", so only the process that marked a row notifies, and
 * a second sweep marks nothing. Runs are never resumed: the owner's Run now starts a fresh one.
 *
 * The same sweep then hands the send log to `reports/send-sweep.js`, under the same lease and the same
 * process id: a `report_sends` row still `sending` from another process becomes `unknown` (never
 * resent), and the owner hears the run's counts once. That step carries its OWN flag
 * (`state.sendSwept`): it is not reached through the run sweep, so a run-sweep throw cannot skip it, and
 * the flag is set only when it succeeded, so a throwing send sweep is retried by the next tick in this
 * process rather than waiting for a restart.
 *
 * The lease is also the sweep's gate: a boot with another live primary on the database waits (and the
 * first tick that takes the lease sweeps once), so a fresh process and the process it replaced can
 * never both sweep.
 *
 * NOTHING HERE SENDS ANYTHING BY ITSELF. This module imports no delivery module and nothing under
 * `mail/`: `deps.deliver` and `deps.deliverPending` are injected by the caller. Boot wires the first to
 * `reports/delivery.js`'s `makeDeliver` and the second to its `makeDeliverPending` (the real seam, which
 * is the reports-only send door's one caller), so the one path from a run or from a "Send to the rest"
 * row to a mail is the caller's injection and never a bot door's.
 *
 * `deps`:
 *   - `deliver(db, payload)`: the one outgoing seam, passed to `executeRun`. Absent, a live run is
 *     recorded `failed` with "Delivery is not wired." and its blocks do not run.
 *   - `deliverPending(db, {reportId, runId})`: sends the `pending` rows one run already holds. Absent,
 *     this hook sends none of them and says nothing about it.
 *   - `pendingGraceMs`: how old a `pending` row has to be before this pass sends it (default 30 s).
 *   - `runBlocks`, `writeVersion`: passed through to `executeRun`.
 *   - `approvals`: the approvals deps (`verifyLive` reads them, and the model-change sentence resolves
 *     the new model through `approvals.resolveModelRef`). In production they come from
 *     reports/approvals-deps.js's `buildApprovalsDeps`.
 *   - `notify(db, notification)`: defaults to `createNotification`.
 *   - `now()`: epoch ms.
 *   - `concurrency`: the queue's width; default the `reports.max_concurrent_runs` setting, else 1.
 *   - `instanceZone(db)`: defaults to schedule-store's reader.
 *   - `graceMs()`: how late a window may still be "on time"; defaults to schedule-core's rule.
 *   - `lease`: the lease deps (`now`, `pid`, `isPidAlive`, `kernelBootId`, `runId`).
 */
import { createNotification } from "../../shared/notifications.js";
import { redactSecrets } from "../../shared/redact-secrets.js";
import { getSecretValues } from "../../shared/secret-values.js";
import {
  REPORT_PREFIX, REPORT_TASK_GLOB, cronNext, cronPrev, graceMs as defaultGraceMs, zoneFor,
} from "../../shared/schedule-core.js";
import { hasRunsTable, hasTzColumn, instanceZone } from "../../shared/schedule-store.js";
import { registerSchedulerHook, unregisterSchedulerHook } from "../scheduler-hooks.js";
import { gatewayRunId } from "../run-id.js";
import { modelRoleOfRecipe, verifyLive, REPORT_LIVE } from "./approvals.js";
import { releaseLease, takeLease } from "./lease.js";
import { executeRun, getRun, getScheduledRun, NOT_LIVE_TEXT, RESTARTED_TEXT, startRun, statusAuditOk } from "./run.js";
import { claimRunRequests, pruneRunRequests } from "./run-requests.js";
// The run statuses a send may start from. `send-log.js` owns the list and imports no mail module, so the
// hook takes it from there rather than keeping a second copy of it.
import { SENDABLE_RUN_STATUSES } from "./send-log.js";
import { sweepStaleSends, refusePendingSends } from "./send-sweep.js";
import { getReport, getRevision, recordAudit } from "./store.js";

/** The hook id the gateway's scheduler knows this by. */
export const REPORTS_HOOK_ID = "reports";

/** Where every notice this module writes sends the owner. */
export const REPORTS_PAGE = "/dashboard/reports";

/** How long a claimed run request is kept before the tick may prune it. */
const REQUEST_RETENTION_MS = 24 * 60 * 60 * 1000;

/** The `dashboard_settings` key that caps how many runs this process works on at once. */
const CONCURRENCY_KEY = "reports.max_concurrent_runs";

/** How old a `pending` send row has to be before a pass sends it, unless the caller says otherwise. */
export const DEFAULT_PENDING_GRACE_MS = 30_000;

/** How many distinct (report, run) pairs one pass hands to `deliverPending` at most. */
export const PENDING_SEND_BATCH = 20;

/**
 * How many pending ROWS one pass reads at most. The batch above bounds how many pairs are offered;
 * this only bounds the read, so a pass sees the pairs behind the ones it already offered.
 */
export const PENDING_ROW_SCAN = 2000;

/**
 * How many run ids the "its pending sends could not be sent" warning remembers before it is cleared. The
 * set exists to say a failure once, not to grow for the life of the process.
 */
const PENDING_WARNED_MAX = 1000;

/**
 * What a report's liveness question may answer. `not_live` is a certainty (the row is gone, its status is
 * not live, or its seal or audit says no); `unknown` is a fault (a read threw, or there are no approvals
 * deps to read the seal with). Only a certainty may settle a row.
 */
const MAY_SEND_LIVE = "live";
const MAY_SEND_NOT_LIVE = "not_live";
const MAY_SEND_UNKNOWN = "unknown";

/** The pause reason when a live-set column (or the status) moved outside the report page. */
export const SETTINGS_CHANGED_TEXT = "Settings changed outside Crow. Check and go live again.";

/** The longest pause reason kept: the same cap approvals.js puts on one (it is shown on a card). */
const PAUSE_REASON_MAX = 300;

const iso = (ms) => new Date(ms).toISOString();

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** The registered hook of this process, if any: `kickReportsHook` reads it. */
let activeHook = null;

function resolveDeps(deps) {
  const given = deps == null ? {} : deps;
  const fn = (key, fallback) => (typeof given[key] === "function" ? given[key] : fallback);
  return {
    deliver: typeof given.deliver === "function" ? given.deliver : null,
    deliverPending: typeof given.deliverPending === "function" ? given.deliverPending : null,
    pendingGraceMs: Number.isFinite(given.pendingGraceMs) && given.pendingGraceMs >= 0
      ? given.pendingGraceMs
      : DEFAULT_PENDING_GRACE_MS,
    runBlocks: fn("runBlocks", undefined),
    writeVersion: fn("writeVersion", undefined),
    approvals: given.approvals ?? null,
    notify: fn("notify", createNotification),
    now: fn("now", Date.now),
    concurrency: Number.isInteger(given.concurrency) && given.concurrency > 0 ? given.concurrency : null,
    instanceZone: fn("instanceZone", instanceZone),
    graceMs: fn("graceMs", defaultGraceMs),
    getSecrets: fn("getSecrets", defaultGetSecrets),
    lease: given.lease ?? {},
  };
}

/** This instance's literal secret values, for scrubbing a pause reason. Never throws. */
function defaultGetSecrets() {
  try {
    return getSecretValues();
  } catch {
    return [];
  }
}

function secretsOf(d) {
  try {
    const values = d.getSecrets();
    return Array.isArray(values) ? values : [];
  } catch {
    return [];
  }
}

function clock(d) {
  const value = Number(d.now());
  return Number.isFinite(value) ? value : Date.now();
}

/** A report row's title as it may appear in a notice: one line, and never empty. */
function titleOf(report) {
  const title = text(report?.title).replace(/\s+/g, " ").trim();
  return title || "This report";
}

/**
 * A pause reason as the row stores it: one line, no control characters, scrubbed of this instance's
 * secret values and capped. The same shape approvals.js gives the reasons it writes.
 */
function pauseReasonText(reason, secrets) {
  const flat = redactSecrets(text(reason), secrets)
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return flat.length > PAUSE_REASON_MAX ? flat.slice(0, PAUSE_REASON_MAX) : flat;
}

/** The report's stored model reference (`{providerId, model, ...}` canonical JSON), or null. */
function storedModelRef(report) {
  const raw = report?.model_ref;
  if (typeof raw !== "string" || !raw) return null;
  try {
    const value = JSON.parse(raw);
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * Take or refresh the reports lease.
 *
 * @param {object} db
 * @param {object} [deps]
 * @returns {Promise<{held: boolean, reason: string}>}
 */
export async function acquireReportsLease(db, deps = {}) {
  return takeLease(db, deps);
}

/**
 * Register this process's reports hook: one scheduler hook (`tick`, `runNow`), one run queue, one
 * lease holder.
 *
 * @param {object} database the crow.db client the hook works through. The caller keeps it open for the
 *   life of the hook; this module never closes it.
 * @param {object} [deps] see the module header
 * @returns {{stop: Function, tick: Function, runNow: Function, sweep: Function, kick: Function}}
 */
export function registerReportsHook(database, deps = {}) {
  const d = resolveDeps(deps);
  const state = {
    concurrency: d.concurrency,
    running: 0,
    queue: [],
    inFlight: new Set(),
    strays: new Set(),
    pendingWarned: new Set(),
    pendingAttempted: new Set(),
    warnedNotPrimary: false,
    warnedSweepSkipped: false,
    swept: false,
    sendSwept: false,
  };

  /* ------------------------------------------------------------------- the run queue */

  function pump() {
    const width = state.concurrency ?? 1;
    while (state.running < width && state.queue.length) {
      const job = state.queue.shift();
      state.running += 1;
      // Fire and forget: nothing in a tick may wait for a run.
      Promise.resolve()
        .then(() => executeRun(job.db ?? database, d, job.runId))
        .then((outcome) => notifyRefused(job, outcome))
        .catch((err) => console.warn(`[reports] run ${job.runId} could not execute: ${err?.message || err}`))
        .finally(() => {
          state.running -= 1;
          state.inFlight.delete(job.reportId);
          pump();
        });
    }
  }

  function enqueue(job) {
    if (!job?.runId) return false;
    if (state.queue.some((queued) => queued.runId === job.runId)) return false;
    state.queue.push(job);
    state.inFlight.add(job.reportId);
    pump();
    return true;
  }

  /** The queue's width: the injected number, else the instance setting, else one. */
  async function ensureConcurrency(db) {
    if (state.concurrency !== null) return state.concurrency;
    let width = 1;
    try {
      const { rows } = await db.execute({
        sql: "SELECT value FROM dashboard_settings WHERE key = ?",
        args: [CONCURRENCY_KEY],
      });
      const value = Number(rows[0]?.value);
      if (Number.isInteger(value) && value > 0) width = Math.min(value, 8);
    } catch {
      width = 1;
    }
    state.concurrency = width;
    return width;
  }

  /* -------------------------------------------------------------------- the notice */

  async function notifyOwner(db, { title, body = null, reportId }) {
    try {
      await d.notify(db, {
        title,
        body,
        type: "system",
        source: "reports",
        priority: "high",
        action_url: REPORTS_PAGE,
        metadata: { essential: true, reportId },
      });
    } catch (err) {
      console.warn(`[reports] notice not written for ${reportId}: ${err?.message || err}`);
    }
  }

  /**
   * The owner's notice for a run that did not happen at all. `run.js` calls no delivery seam without a
   * verified live set, so a run refused because the report is not live (or whose report row is gone)
   * sends nothing: this wrapper is where the owner hears about it, once per refused run.
   */
  async function notifyRefused(job, outcome) {
    if (outcome?.status !== "failed" || !job?.runId) return;
    let run = null;
    try {
      run = await getRun(job.db ?? database, job.runId);
    } catch {
      return;
    }
    if (!run || run.errorText !== NOT_LIVE_TEXT) return;
    let report = null;
    try {
      report = await getReport(job.db ?? database, run.reportId ?? job.reportId);
    } catch {
      report = null;
    }
    await notifyOwner(job.db ?? database, {
      title: `${titleOf(report)} did not run`,
      body: NOT_LIVE_TEXT,
      reportId: run.reportId ?? job.reportId,
    });
  }

  /** Pause a still-live report and notify once: only the call that flipped the status notifies. */
  async function pauseWithNotice(db, report, reason) {
    // ONE guarded statement, so two overlapping guard passes cannot both "win": the loser changes no
    // row, writes no audit row and sends no notice.
    const at = clock(d);
    const pauseReason = pauseReasonText(reason, secretsOf(d));
    let changed = 0;
    try {
      const result = await db.execute({
        sql: `UPDATE reports SET status = 'paused', pause_reason = ?, updated_at = ?
               WHERE id = ? AND status = 'live'`,
        args: [pauseReason, at, report.id],
      });
      changed = Number(result?.rowsAffected ?? 0);
    } catch (err) {
      console.warn(`[reports] ${report.id} could not be paused: ${err?.message || err}`);
      return false;
    }
    if (changed !== 1) return false;
    // The audit row says the approval is refused for as long as the pause lasts (the same vocabulary
    // approvals.js uses), and it is written only by the pass that changed the row.
    try {
      await recordAudit(db, {
        reportId: report.id,
        kind: "live",
        subject: null,
        actor: "system",
        decided: "refused",
        at,
      });
    } catch (err) {
      console.warn(`[reports] ${report.id}: the pause could not be audited: ${err?.message || err}`);
    }
    await notifyOwner(db, {
      title: `${titleOf(report)}: paused`,
      body: pauseReason,
      reportId: report.id,
    });
    return true;
  }

  /* ------------------------------------------------------------------ the guards */

  /** The schedule row an id names, or null. */
  async function scheduleRowOf(db, report) {
    const raw = report?.schedule_id;
    if (raw == null || raw === "") return null;
    const id = Number(raw);
    if (!Number.isInteger(id)) return null;
    try {
      const { rows } = await db.execute({
        sql: "SELECT id, task, enabled FROM schedules WHERE id = ?",
        args: [id],
      });
      return rows[0] ?? null;
    } catch {
      return null;
    }
  }

  /**
   * The model the report resolves to NOW, or null when nothing injected can say. A recipe whose AI block
   * names a role resolves THAT role (the same reference `liveSetFor` seals), so the model-change sentence
   * names the model the report would use next rather than the bot's own.
   */
  async function freshModelName(db, report) {
    const role = await sealedRoleOf(db, report);
    const resolver = !d.approvals ? null
      : role
        ? (typeof d.approvals.resolveRoleModelRef === "function" ? d.approvals.resolveRoleModelRef : null)
        : (typeof d.approvals.resolveModelRef === "function" ? d.approvals.resolveModelRef : null);
    if (!resolver) return null;
    try {
      const resolved = role ? await resolver(db, role) : await resolver(db, report);
      return resolved && text(resolved.model) ? text(resolved.model) : null;
    } catch {
      return null;
    }
  }

  /** The role the report's sealed revision names for its AI block, or null. Never throws. */
  async function sealedRoleOf(db, report) {
    try {
      const rev = Number(report?.live_rev);
      if (!Number.isInteger(rev) || rev < 1) return null;
      const revision = await getRevision(db, report.id, rev);
      if (!revision || typeof revision.recipe_json !== "string") return null;
      return modelRoleOfRecipe(JSON.parse(revision.recipe_json));
    } catch {
      return null;
    }
  }

  async function guardLiveReports(db) {
    let rows;
    try {
      ({ rows } = await db.execute({
        sql: "SELECT * FROM reports WHERE status = 'live'",
        args: [],
      }));
    } catch (err) {
      console.warn(`[reports] the live reports could not be read: ${err?.message || err}`);
      return;
    }
    for (const report of rows) {
      try {
        await guardOne(db, report);
      } catch (err) {
        console.warn(`[reports] ${report.id}: ${err?.message || err}`);
      }
    }
  }

  async function guardOne(db, report) {
    const title = titleOf(report);
    const row = await scheduleRowOf(db, report);
    if (!row || text(row.task) !== REPORT_PREFIX + report.id) {
      await pauseWithNotice(db, report, `${title} lost its schedule and is paused`);
      return;
    }
    if (Number(row.enabled) !== 1) {
      await pauseWithNotice(db, report, `${title} was paused outside the report page`);
      return;
    }
    const live = await verifyLive(db, d.approvals, report);
    const auditOk = await statusAuditOk(db, report.id);
    if (live && auditOk) return;
    let reason = SETTINGS_CHANGED_TEXT;
    if (!live) {
      // Was the model resolution the only thing that moved? Re-verify with the model the row stored:
      // when that verifies, nothing the owner approved changed except which model the report resolves
      // to. Both seams are pinned, because a report's model comes from the bot OR from the role its
      // recipe names, and either one moving is that same one thing.
      const stored = storedModelRef(report);
      if (stored) {
        const pinned = {
          ...(d.approvals ?? {}),
          resolveModelRef: async () => stored,
          resolveRoleModelRef: async () => stored,
        };
        if (await verifyLive(db, pinned, report)) {
          const oldName = text(stored.model) || "unavailable";
          const newName = (await freshModelName(db, report)) || "unavailable";
          reason = `The bot's model changed (${oldName} -> ${newName}). Check and go live again.`;
        }
      }
    }
    await pauseWithNotice(db, report, reason);
  }

  /* -------------------------------------------------------------------- the rows */

  async function dispatchDue(db) {
    const now = clock(d);
    const zone = await d.instanceZone(db);
    const tz = (await hasTzColumn(db)) ? "tz" : "NULL AS tz";
    let rows;
    try {
      ({ rows } = await db.execute({
        sql: `SELECT id, task, cron_expression, next_run, ${tz} FROM schedules
               WHERE task GLOB ? AND length(task) = 27 AND enabled = 1 AND next_run IS NOT NULL
                 AND julianday(next_run) <= julianday(?)`,
        args: [REPORT_TASK_GLOB, iso(now)],
      }));
    } catch (err) {
      console.warn(`[reports] the due report rows could not be read: ${err?.message || err}`);
      return;
    }
    for (const row of rows) {
      try {
        await dispatchOne(db, row, now, zone);
      } catch (err) {
        console.warn(`[reports] schedule #${row.id}: ${err?.message || err}`);
      }
    }
  }

  async function dispatchOne(db, row, now, instanceZoneValue) {
    const reportId = text(row.task).trim().slice(REPORT_PREFIX.length);
    let report = null;
    try {
      const { rows } = await db.execute({
        sql: "SELECT * FROM reports WHERE id = ? AND schedule_id = ?",
        args: [reportId, row.id],
      });
      report = rows[0] ?? null;
    } catch {
      report = null;
    }
    if (!report) {
      // A stray row: it names no report on this schedule. Say it once, then leave it alone (the row
      // itself is the owner's to remove, and a repeated log line every minute would be noise).
      if (!state.strays.has(Number(row.id))) {
        state.strays.add(Number(row.id));
        console.warn(`[reports] schedule #${row.id} names no report; it is ignored`);
      }
      return;
    }

    // A report that already has a run queued or running here is not given a second one for a new
    // window: the row stays due untouched, so the next tick after that run makes the ONE catch-up run
    // (R10) instead of stacking a run per missed minute.
    if (report.status === REPORT_LIVE && state.inFlight.has(report.id)) return;

    const zone = zoneFor(row.tz, instanceZoneValue);
    const next = cronNext(row.cron_expression, zone, now);
    const nextText = next === null ? null : iso(next);
    const runs = await hasRunsTable(db);

    // A draft or a paused report only has its window advanced: nothing runs, and the schedule does
    // not fire in a burst the moment the owner takes the report live.
    if (report.status !== REPORT_LIVE) {
      await db.execute({
        sql: `UPDATE schedules SET next_run = ?, updated_at = datetime('now')
               WHERE id = ? AND next_run IS ? AND enabled = 1`,
        args: [nextText, row.id, row.next_run],
      });
      return;
    }

    // One run for however many windows were missed (R10): the LATEST missed window is the run's
    // window, it is marked late when it is past the grace, and next_run is about to be past now.
    const previous = cronPrev(row.cron_expression, zone, now);
    const stored = Date.parse(row.next_run ?? "");
    const scheduledFor = previous ?? (Number.isFinite(stored) ? stored : now);
    const lateMs = now - scheduledFor;
    const late = lateMs > d.graceMs();

    // 1. The run row FIRST. A database that refuses it throws out of here with `next_run` untouched,
    // so the next tick retries the same window instead of losing it. A window another pass already
    // used comes back `duplicate` (the run table's unique index), which is not a failure: the claim
    // below still advances the window, and step 3 queues that window's row when it is still `queued`.
    const started = await startRun(db, d, {
      reportId: report.id,
      trigger: "schedule",
      requestedBy: "schedule",
      scheduledFor,
      late,
    });
    let runId = started?.runId ?? null;
    const duplicate = started?.duplicate === true;

    // 2. The guarded claim: only the pass that moved this exact `next_run` continues.
    const claim = await db.execute({
      sql: `UPDATE schedules SET next_run = ?, last_run = ?, updated_at = datetime('now')
             WHERE id = ? AND next_run IS ? AND enabled = 1`,
      args: [nextText, iso(now), row.id, row.next_run],
    });
    if (Number(claim.rowsAffected) !== 1) {
      // Another pass claimed the window, so it owns the window and the run for it. A run row this pass
      // wrote stays `queued`: it must NOT be closed (the winner is about to queue that very row, its
      // own startRun having come back `duplicate`), and it must NOT be queued here (the winner does
      // that). A throw from this UPDATE lands in the same place, and the next tick's duplicate path
      // picks the run up.
      return;
    }

    // 3. The window is this pass's, and it queues exactly one run for it. The unique index allows one
    // scheduled row per (report, window), so a `duplicate` means the row already exists: when it is
    // still `queued`, nobody executed it (the pass that wrote it lost its claim, or its claim threw)
    // and this pass queues it (executeRun's queued -> running claim makes a double queue harmless).
    // Any other status means that window's run is already in hand or done: it is only advanced.
    if (duplicate) {
      const existing = await getScheduledRun(db, report.id, scheduledFor);
      runId = existing && existing.status === "queued" ? existing.id : null;
    }
    if (!runId) return;

    // 4. The run history row, written only by the pass that won the claim AND has a run to make.
    if (runs) {
      await db.execute({
        sql: `INSERT OR IGNORE INTO schedule_runs (schedule_id, scheduled_for, ran_at, status, source, detail)
              VALUES (?, ?, ?, ?, 'clock', ?)`,
        args: [
          row.id, iso(scheduledFor), iso(now), late ? "late" : "ok",
          JSON.stringify({ late_ms: lateMs }),
        ],
      });
    }

    enqueue({ reportId: report.id, runId, db });
  }

  /* ---------------------------------------------------------------- the requests */

  async function drainRequests(db) {
    const now = clock(d);
    let claimed = [];
    try {
      claimed = await claimRunRequests(db, { now });
    } catch (err) {
      console.warn(`[reports] the run requests could not be claimed: ${err?.message || err}`);
      return;
    }
    for (const request of claimed) {
      try {
        const report = await getReport(db, request.reportId);
        if (!report) continue; // a request for a report that is gone is dropped
        if (request.kind === "preview") {
          const started = await startRun(db, d, {
            reportId: report.id, trigger: "preview", requestedBy: request.requestedBy,
          });
          if (started?.runId) enqueue({ reportId: report.id, runId: started.runId, db });
          continue;
        }
        if (request.kind !== "run_now") continue;
        // A run now is a full run: it needs a live report whose seal verifies now.
        if (report.status !== REPORT_LIVE) continue;
        if (!(await verifyLive(db, d.approvals, report))) continue;
        const started = await startRun(db, d, {
          reportId: report.id, trigger: "manual", requestedBy: request.requestedBy,
        });
        if (started?.runId) enqueue({ reportId: report.id, runId: started.runId, db });
      } catch (err) {
        console.warn(`[reports] request ${request.id}: ${err?.message || err}`);
      }
    }
    try {
      await pruneRunRequests(db, { olderThanMs: REQUEST_RETENTION_MS, now });
    } catch {
      // A prune that cannot run is not worth a log line; the next tick tries again.
    }
  }

  /* ------------------------------------------------------------- the pending sends */

  /**
   * Whether one report may still send, as one of three answers:
   *   - `live`: the row exists, its status is live, and the same two checks a run now makes hold — its
   *     seal verifies and its newest live-kind decision is an approval;
   *   - `not_live`: the report row is certainly gone, or its status is not live, or `verifyLive` or
   *     `statusAuditOk` answered false. Its pending rows may settle;
   *   - `unknown`: the question could not be answered — a read threw, or there are no approvals deps to
   *     read the seal with. A caller must settle NOTHING on this answer and must not remember the pair:
   *     a database that burped is not a report that stopped, and its rows are still owed a send.
   */
  async function reportMaySend(db, reportId) {
    // No approvals deps (or none that could read anything) means no way to read the seal at all: that is
    // not a report that stopped, so nothing may settle on it.
    const approvals = d.approvals;
    const readable = approvals != null && typeof approvals === "object"
      && Object.values(approvals).some((member) => typeof member === "function");
    if (!readable) return MAY_SEND_UNKNOWN;
    let report = null;
    try {
      report = await getReport(db, reportId);
    } catch {
      return MAY_SEND_UNKNOWN;
    }
    if (!report || report.status !== REPORT_LIVE) return MAY_SEND_NOT_LIVE;
    try {
      if (!(await verifyLive(db, approvals, report))) return MAY_SEND_NOT_LIVE;
      return (await statusAuditOk(db, report.id)) ? MAY_SEND_LIVE : MAY_SEND_NOT_LIVE;
    } catch {
      return MAY_SEND_UNKNOWN;
    }
  }

  /**
   * Send the `pending` rows "Send to the rest" wrote: the distinct (report, run) pairs whose run has
   * FINISHED in a sendable status and whose oldest pending row is past the grace, oldest first, at most
   * one batch per pass, and the same set of pending row ids at most ONCE per process.
   *
   * A pair whose report is gone, not live, or whose seal no longer verifies is NEVER handed to the seam:
   * its pending rows settle `refused` / `not_live` (`refusePendingSends`, the twin of the send door's own
   * refusal) and write no notice. Those rows leave `pending`, so the pair is gone for good. A pair whose
   * report cannot be read at all is skipped instead: nothing settles and nothing is remembered, so the
   * next pass asks again (see `reportMaySend`).
   *
   * The query reads the oldest eligible ROWS, not the oldest pairs, and the pass skips the pairs it has
   * already offered: a set the seam could not move while its rows are still pending is remembered (see
   * `state.pendingAttempted`) instead of being re-read as one of the batch every tick, so the pairs
   * behind it are reached by a later pass.
   *
   * It writes no row of its own and never touches a `sending` or `unknown` one: each pair is handed to
   * the injected `deliverPending`, whose door claim makes a row go at most once however many passes
   * overlap. The pair's key (report, run and the sorted ids of the rows it would send) is remembered
   * BEFORE the seam is called, so a row set the seam could not move is not offered again on every tick.
   * A seam that THREW has its key deleted again (`read_failed` on a recipient list is a fault, not an
   * answer about the rows): those rows are still owed a send, so the next pass offers the set again,
   * while the warning about that run id stays one per process. The rows the seam itself SETTLES leave
   * `pending`, so their key is pruned from that memory by the next uncapped pass, and a new "Send to the
   * rest" tap writes new row ids and so a new key. A pair that throws (a report deleted between the row
   * and the pass, say) is logged once per run id in this process and never breaks the pass.
   */
  async function drainPendingSends(db) {
    if (typeof d.deliverPending !== "function") return;
    const now = clock(d);
    const cutoff = now - d.pendingGraceMs;
    const sendable = SENDABLE_RUN_STATUSES.map(() => "?").join(", ");
    let pending = [];
    try {
      // One statement: every pending row a pair may still send, oldest first, bounded by a row cap so
      // the pairs a previous pass already offered cannot hide the ones behind them (the batch below is
      // what limits how many pairs one pass OFFERS).
      ({ rows: pending } = await db.execute({
        sql: `SELECT s.report_id AS report_id, s.run_id AS run_id, s.id AS id
                FROM report_sends s
               WHERE s.status = 'pending' AND s.created_at <= ?
                 AND EXISTS (SELECT 1 FROM report_runs r
                              WHERE r.id = s.run_id AND r.status IN (${sendable}))
               ORDER BY s.created_at ASC, s.id ASC
               LIMIT ?`,
        args: [cutoff, ...SENDABLE_RUN_STATUSES, PENDING_ROW_SCAN],
      }));
    } catch (err) {
      console.warn(`[reports] the pending sends could not be read: ${err?.message || err}`);
      return;
    }

    // The rows arrive oldest first, so the pairs come out in the order of their oldest row.
    const pairs = new Map();
    for (const row of pending) {
      const reportId = text(row.report_id);
      const runId = text(row.run_id);
      const rowId = text(row.id);
      if (!reportId || !runId || !rowId) continue;
      const groupKey = `${reportId}|${runId}`;
      const pair = pairs.get(groupKey) ?? { reportId, runId, ids: [] };
      pair.ids.push(rowId);
      pairs.set(groupKey, pair);
    }

    // Every pair's key for this pass, computed before the loop: the pass's memory of offered sets is
    // pruned against ALL of them, not only against the ones it got to before its batch was full.
    const pairKeys = new Set();
    for (const pair of pairs.values()) {
      pair.key = `${pair.reportId}:${pair.runId}:${[...pair.ids].sort().join(",")}`;
      pairKeys.add(pair.key);
    }

    // One liveness answer per report per pass, however many runs its rows name.
    const liveByReport = new Map();
    // One refusal per report per pass: `refusePendingSends` settles every pending row of the report in
    // ONE statement, so a report with a thousand pairs costs one write, not a thousand.
    const refusedReports = new Set();
    let offered = 0;
    for (const pair of pairs.values()) {
      if (offered >= PENDING_SEND_BATCH) break;
      if (state.pendingAttempted.has(pair.key)) continue;
      if (!liveByReport.has(pair.reportId)) {
        liveByReport.set(pair.reportId, reportMaySend(db, pair.reportId));
      }
      const answer = await liveByReport.get(pair.reportId);
      if (answer === MAY_SEND_UNKNOWN) {
        // The report could not be read at all: this is a fault, not a refusal. Nothing settles, nothing
        // is remembered and nothing is counted, so the next pass asks again and finds the rows pending.
        continue;
      }
      if (answer !== MAY_SEND_LIVE) {
        // Nothing goes out for a report that is not live now. Its rows settle terminally, and it is
        // not remembered as offered (the rows are gone from `pending`, or the write failed and the
        // next pass tries again). A refusal counts for nothing in this pass's batch: it sends nothing.
        if (refusedReports.has(pair.reportId)) continue;
        refusedReports.add(pair.reportId);
        try {
          await refusePendingSends(db, { reportId: pair.reportId, now });
        } catch (err) {
          console.warn(`[reports] ${pair.reportId}: its pending sends could not be refused: ${err?.code || err?.message || err}`);
        }
        continue;
      }
      // Only a pair actually handed to the seam is one of this pass's batch, and it is remembered
      // BEFORE the call: a concurrent pass cannot offer this set again while the call is in hand.
      offered += 1;
      state.pendingAttempted.add(pair.key);
      try {
        await d.deliverPending(db, { reportId: pair.reportId, runId: pair.runId });
      } catch (err) {
        // The seam could not do its work for this pair (a recipient list it could not read, a run that
        // moved underneath it): its rows are still owed a send, so the key is forgotten and the next
        // pass offers this very set again. The warning stays one per run id.
        state.pendingAttempted.delete(pair.key);
        if (state.pendingWarned.has(pair.runId)) continue;
        state.pendingWarned.add(pair.runId);
        if (state.pendingWarned.size > PENDING_WARNED_MAX) state.pendingWarned.clear();
        console.warn(`[reports] run ${pair.runId}: its pending sends could not be sent: ${err?.code || err?.message || err}`);
      }
    }

    // An UNCAPPED scan read every pending row there is, so a remembered key that is not among this
    // pass's pairs names rows that are no longer pending (settled, or deleted): it is forgotten, and the
    // set cannot grow into a list of every pair this process ever offered. A capped scan says nothing
    // about the rows it did not read, so it prunes nothing.
    if (pending.length < PENDING_ROW_SCAN) {
      for (const key of state.pendingAttempted) {
        if (!pairKeys.has(key)) state.pendingAttempted.delete(key);
      }
    }
  }

  /* -------------------------------------------------------------------- the sweep */

  /** The run rows a restart cut off, marked once. Its flag is set only by the pass that marked them. */
  async function sweepStaleRuns(db) {
    let rows = [];
    try {
      ({ rows } = await db.execute({
        sql: `UPDATE report_runs
                 SET status = 'failed', error_text = ?, ended_at = ?
               WHERE status IN ('queued', 'running')
                 AND (gateway_run_id IS NULL OR gateway_run_id <> ?)
              RETURNING id, report_id`,
        args: [RESTARTED_TEXT, clock(d), gatewayRunId()],
      }));
    } catch (err) {
      console.warn(`[reports] the stale run sweep failed: ${err?.message || err}`);
      return 0;
    }
    state.swept = true;
    for (const row of rows) {
      let report = null;
      try {
        report = await getReport(db, row.report_id);
      } catch {
        report = null;
      }
      await notifyOwner(db, {
        title: `${titleOf(report)}: ${RESTARTED_TEXT}`,
        body: null,
        reportId: row.report_id,
      });
    }
    return rows.length;
  }

  /**
   * The send log's own sweep: the same lease gate and the same process id, and its own flag, so it runs
   * whether or not the run sweep could. A throw leaves the flag unset, so the next tick tries again.
   */
  async function sweepStaleSending(db) {
    if (state.sendSwept) return;
    try {
      await sweepStaleSends(db, {
        gatewayRunId: gatewayRunId(),
        now: clock(d),
        notify: (note) => notifyOwner(db, note),
      });
    } catch (err) {
      console.warn(`[reports] the stale send sweep failed: ${err?.message || err}`);
      return;
    }
    state.sendSwept = true;
  }

  async function sweepOwned(db) {
    const marked = state.swept ? 0 : await sweepStaleRuns(db);
    // Independent of the run sweep: a run-sweep throw above changes nothing here.
    await sweepStaleSending(db);
    return { marked };
  }

  async function sweep(database2) {
    const db = database2 ?? database;
    const lease = await takeLease(db, d.lease);
    if (!lease.held) {
      if (!state.warnedSweepSkipped) {
        state.warnedSweepSkipped = true;
        console.warn(`[reports] sweep waits: another gateway holds the reports lease (${lease.reason})`);
      }
      return { marked: 0, skipped: true };
    }
    state.warnedSweepSkipped = false;
    return sweepOwned(db);
  }

  /* --------------------------------------------------------------------- the tick */

  // One pass at a time. A scheduler tick, a `kick` from a run route and a `runNow` from the Schedule
  // page each read the lease and claim schedule rows, so two of them overlapping would read the same
  // window, fight over the lease and (at best) log a lost race that was never another gateway's. The
  // chain makes every pass start after the previous one finished; a failure never breaks it.
  let passChain = Promise.resolve();

  function serialized(work) {
    const run = passChain.then(work, work);
    passChain = run.then(() => {}, () => {});
    return run;
  }

  async function runTick(db, { light = false } = {}) {
    await ensureConcurrency(db);
    const lease = await takeLease(db, d.lease);
    if (!lease.held) {
      if (!state.warnedNotPrimary) {
        state.warnedNotPrimary = true;
        console.warn(`[reports] reports wait: another gateway holds the reports lease (${lease.reason})`);
      }
      return;
    }
    state.warnedNotPrimary = false;
    if (!light) {
      // The boot sweep's second chance: a boot that found another live primary sweeps here instead,
      // on the first tick that takes the lease. The flag is per sweep, so a run sweep that succeeded
      // does not keep a failed (or unlucky) send sweep from being retried.
      if (!state.swept || !state.sendSwept) await sweepOwned(db);
      await guardLiveReports(db);
    }
    await dispatchDue(db);
    await drainRequests(db);
    await drainPendingSends(db);
  }

  async function tick(database2) {
    const db = database2 ?? database;
    try {
      await serialized(() => runTick(db));
    } catch (err) {
      console.warn(`[reports] tick failed: ${err?.message || err}`);
    }
  }

  /**
   * Called by scheduler.runNow for a report row: the owner's Run now from the Schedule page.
   *
   * It runs a full report run, so the same rule the executor applies is applied here first: the report
   * must be live, its seal must verify now, and its newest live-kind decision must be an approval. A
   * draft or a paused report answers `not live` and starts nothing, so the owner is never told a run
   * happened that could only be recorded `failed`.
   */
  async function runNow(database2, schedule) {
    const db = database2 ?? database;
    if (!schedule || schedule.id == null) return { ok: false, error: "not found" };
    const reportId = text(schedule.task).trim().slice(REPORT_PREFIX.length);
    if (!reportId) return { ok: false, error: "not found" };
    return serialized(async () => {
      const lease = await takeLease(db, d.lease);
      if (!lease.held) return { ok: false, error: "reports are not running here" };
      let report = null;
      try {
        const { rows } = await db.execute({
          sql: "SELECT * FROM reports WHERE id = ? AND schedule_id = ?",
          args: [reportId, schedule.id],
        });
        report = rows[0] ?? null;
      } catch {
        report = null;
      }
      if (!report) return { ok: false, error: "not found" };
      if (report.status !== REPORT_LIVE) return { ok: false, error: "not live" };
      if (!(await verifyLive(db, d.approvals, report))) return { ok: false, error: "not live" };
      if (!(await statusAuditOk(db, report.id))) return { ok: false, error: "not live" };
      await ensureConcurrency(db);
      try {
        const started = await startRun(db, d, {
          reportId: report.id, trigger: "manual", requestedBy: "schedule",
        });
        if (started?.runId) enqueue({ reportId: report.id, runId: started.runId, db });
        return { ok: true };
      } catch (err) {
        return { ok: false, error: err?.code === "not_found" ? "not found" : "could not start" };
      }
    });
  }

  /** A route just wrote something for the next pass (a run request, a set of pending sends): run one
   *  now, light, instead of waiting for the next tick. */
  function kick() {
    try {
      serialized(() => runTick(database, { light: true })).catch((err) => {
        console.warn(`[reports] kick failed: ${err?.message || err}`);
      });
    } catch (err) {
      console.warn(`[reports] kick failed: ${err?.message || err}`);
    }
  }

  const hook = {
    tick,
    runNow,
    sweep,
    kick,
    async stop() {
      unregisterSchedulerHook(REPORTS_HOOK_ID);
      if (activeHook === hook) activeHook = null;
      return releaseLease(database, d.lease);
    },
  };

  registerSchedulerHook(REPORTS_HOOK_ID, { tick, runNow });
  activeHook = hook;
  return hook;
}

/**
 * Wake the registered hook in this process, if there is one: drain the request queue, the due rows and
 * the pending sends now, fire-and-forget. A process with no hook (a `--no-auth` companion, a test
 * harness) does nothing.
 *
 * @returns {boolean} whether a hook was woken
 */
export function kickReportsHook() {
  if (!activeHook) return false;
  activeHook.kick();
  return true;
}

/** Test seam: forget the hook this process registered, without touching the lease. */
export function _setReportsHookForTest(hook) {
  activeHook = hook ?? null;
}

/**
 * The boot wiring post-listen.js uses, in one place so a test can drive exactly what boot does.
 *
 * A `--no-auth` gateway is a loopback companion that shares crow.db: it never registers the hook, so
 * it never sweeps and never takes the lease. Nothing here looks at instance sync: `CROW_DISABLE_INSTANCE_SYNC=1`
 * is a sync setting, not a reports one.
 *
 * @param {{noAuth?: boolean, db?: object, deps?: object, dbFactory?: Function}} [opts]
 * @returns {Promise<{started: boolean, reason?: string, hook?: object, swept?: object}>}
 */
export async function startReportsAtBoot({ noAuth = false, db = null, deps = {}, dbFactory = null } = {}) {
  if (noAuth) return { started: false, reason: "no-auth" };
  let client = db;
  if (!client) {
    if (typeof dbFactory !== "function") return { started: false, reason: "no-database" };
    try {
      client = dbFactory();
    } catch (err) {
      console.warn(`[reports] scheduler hook not started: ${err?.message || err}`);
      return { started: false, reason: "no-database" };
    }
  }
  try {
    const hook = registerReportsHook(client, deps);
    const swept = await hook.sweep(client);
    return { started: true, hook, swept };
  } catch (err) {
    console.warn(`[reports] scheduler hook not started: ${err?.message || err}`);
    return { started: false, reason: "error" };
  }
}

/**
 * The delivery seam a caller that wants no mail passes: a live report run records its result and sends
 * nothing. `run.js` requires a `deliver` for a scheduled or manual run, so this is what a harness hands
 * the hook when it wants the runs recorded and no mail sent. Boot wires the real one
 * (`reports/delivery.js`'s `makeDeliver`), so nothing in production uses this.
 *
 * @returns {Promise<{delivered: boolean}>}
 */
export async function deliverNotWired() {
  return { delivered: false };
}