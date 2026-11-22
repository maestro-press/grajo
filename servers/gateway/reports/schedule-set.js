/**
 * Crow Recurring Reports: the owner's schedule write.
 *
 * A report runs on its own `schedules` row, and that row is the one its page owns: the task is exactly
 * `report:<reportId>` (schedule-core's REPORT_TASK_RE), `enabled = 1`, and the cron, the zone and the
 * row id the report points at are part of the go-live seal (`liveSetFor` seals all three,
 * `defaultGetSchedule` reads the cron and the zone). The memory server's schedule tools refuse a row of
 * that shape outright, so this is the one writer.
 *
 * What the write does, in order:
 *
 *   1. The owner only, and a report that exists (`owner_only`, `not_found`).
 *   2. The cron and the zone are validated before anything is written: `cron` is a string of 1 to 50
 *      characters that is not `@once` and that `cronNext` can place on the grid in the given zone;
 *      `tz` is a required IANA zone name (`validTimeZone`). Any failure is `bad_input` with the field
 *      as its detail, and nothing is written.
 *   3. The row is found or made, in the order the report's own pointer suggests: a `schedule_id` that
 *      names a row whose task is exactly this report's is updated; otherwise a row already carrying
 *      that exact task is updated; otherwise one is inserted. A pointer to a missing row, or to a row
 *      that is some other schedule's, therefore moves the pointer to a row of this report's own and
 *      leaves that other row exactly as it was. `next_run` is recomputed from now when the cron or the
 *      zone changed, and ALSO when the row it found is off (`enabled != 1`) or its stored window is
 *      empty, unreadable or no longer ahead of now: a row switched back on must never fire the window
 *      it missed while it was off (see THE STALE WINDOW below). An identical cron and zone on an ON
 *      row whose window is still ahead leave `next_run` alone, because the window it holds is still
 *      the next one. `enabled` is set to 1 in every case. The row is written FIRST and the report's
 *      `schedule_id` second, so a write that stops between them leaves a row a later call reuses
 *      instead of a pointer to nothing.
 *   4. One row per report task: once the row to keep is settled, every OTHER `schedules` row whose task
 *      is exactly `report:<id>` is switched off (`enabled = 0`). The reports hook's due query matches
 *      every row of that shape, so a stale duplicate would otherwise keep firing forever.
 *   5. The live-set rule, the same one `updateSettings` applies to its own live-set columns. The seal
 *      (`liveSetFor` in approvals.js) covers the cron, the zone AND the row id the report points at,
 *      so a LIVE report is paused in the same UPDATE that writes the pointer when EITHER the cron or
 *      the zone moved OR the row id this write ended up using is not the one the report pointed at (a
 *      missing row, another report's row, no pointer at all, or a different row of the same task). It
 *      is paused with the fixed pause sentence and a nulled seal and nonce, and the `live`/`refused`
 *      audit row a pause writes. Either change on a PAUSED report that still carries a seal nulls that
 *      seal and its nonce and leaves the status and the pause reason untouched. A report that is live
 *      and whose cron, zone and row id all stayed put is not paused: the seal still describes what the
 *      report does. A DRAFT is never paused by its own schedule, and a first-time schedule (a null
 *      pointer on a draft) is the ordinary case, not a re-point.
 *
 * THE STALE WINDOW (step 3's second rule): `enabled` and `next_run` are NOT sealed columns, so a fresh
 * window is not a live-set change and never pauses anything. It exists only so that switching a report
 * back on writes a window from now instead of one already past, which the hook would fire at once as a
 * late run.
 *
 * The pointer change and the cron/zone change are tracked as two separate flags: only the second one
 * ("the cron or the zone moved") decides whether `next_run` is recomputed, while the live-set rule
 * below treats either of them as a change.
 *
 * The answer is the report row after the writes. Nothing here sends mail, and nothing here imports a
 * delivery module.
 */
import { REPORT_PREFIX, cronNext } from "../../shared/schedule-core.js";
import { validTimeZone } from "../../shared/relative-dates.js";
import {
  REPORT_LIVE, REPORT_PAUSED, SETTINGS_CHANGED_PAUSE_REASON, approvalInternals,
} from "./approvals.js";
import { getReport, recordAudit, updateReportColumns } from "./store.js";

const fail = approvalInternals.fail;
const text = approvalInternals.text;

/** The longest cron expression kept, the same ceiling `crow_create_schedule` puts on one. */
export const CRON_MAX = 50;

/** An epoch ms as the ISO text `crow_create_schedule` writes into `next_run`. */
const isoOf = (ms) => new Date(ms).toISOString();

/**
 * Whether a stored `next_run` is a real instant still ahead of `now`. An empty, null, unreadable or
 * already-passed window is not one: a row holding it needs a fresh one before it is switched on.
 */
function windowIsAhead(value, now) {
  const at = Date.parse(text(value));
  return Number.isFinite(at) && at > now;
}

/** The schedule columns this module reads back: what it compares against and what it writes. */
const ROW_COLUMNS = "id, task, cron_expression, tz, enabled, next_run";

/** A cron expression as this module stores it, or `bad_input` with `cron` as its detail. */
function readExpression(value) {
  if (typeof value !== "string") throw fail("bad_input", "cron");
  const cron = value.trim();
  if (!cron || cron.length > CRON_MAX) throw fail("bad_input", "cron");
  // `@once` is a one-shot's absolute time, never a repeating window a report can be given.
  if (cron === "@once") throw fail("bad_input", "cron");
  return cron;
}

/** A required IANA zone name, or `bad_input` with `tz` as its detail. */
function readZone(value) {
  if (typeof value !== "string") throw fail("bad_input", "tz");
  const tz = value.trim();
  if (!tz || !validTimeZone(tz)) throw fail("bad_input", "tz");
  return tz;
}

/** One `schedules` row by id, or null (an unset, non-integer or dead pointer included). Never throws. */
async function rowById(db, id) {
  if (id == null || id === "") return null;
  const value = Number(id);
  if (!Number.isInteger(value) || value <= 0) return null;
  try {
    const { rows } = await db.execute({
      sql: `SELECT ${ROW_COLUMNS} FROM schedules WHERE id = ?`,
      args: [value],
    });
    return rows[0] ?? null;
  } catch {
    return null;
  }
}

/** The first `schedules` row carrying this exact task, or null. Never throws. */
async function rowByTask(db, task) {
  try {
    const { rows } = await db.execute({
      sql: `SELECT ${ROW_COLUMNS} FROM schedules WHERE task = ? ORDER BY id LIMIT 1`,
      args: [task],
    });
    return rows[0] ?? null;
  } catch {
    return null;
  }
}

/**
 * Set one report's schedule: the cron and the zone it runs in, written to the report's own `schedules`
 * row, with the live-set rule applied to the report row in the same pointer write.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} deps the approvals seam (`now` is the clock the next window is computed from, behind
 *   `resolveDeps`; nothing else here is needed)
 * @param {{reportId: string, cron: string, tz: string, actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the report row after the writes
 * @throws {Error} `owner_only`, `not_found`, `bad_input`
 */
export async function setReportSchedule(db, deps, { reportId, cron, tz, actor } = {}) {
  approvalInternals.requireOwner(actor);
  const d = approvalInternals.resolveDeps(deps);
  const report = await approvalInternals.requireReport(db, reportId);

  const expression = readExpression(cron);
  const zone = readZone(tz);
  const read = Number(d.now());
  const now = Number.isFinite(read) ? read : Date.now();
  const next = cronNext(expression, zone, now);
  if (next === null) throw fail("bad_input", "cron");
  const nextRun = isoOf(next);

  // The report's own row: the one its pointer names when that row really is this report's, else one
  // already carrying this exact task. A pointer to somebody else's schedule is not followed.
  const task = REPORT_PREFIX + report.id;
  const pointed = await rowById(db, report.schedule_id);
  const previous = pointed && text(pointed.task) === task ? pointed : await rowByTask(db, task);
  // The cron or the zone moved (a first-time schedule counts), which is what recomputes the window and
  // what the live-set rule below reads. The row id is judged separately, further down.
  const moved = previous === null
    || text(previous.cron_expression) !== expression
    || text(previous.tz) !== zone;

  let rowId = null;
  if (previous === null) {
    await db.execute({
      sql: `INSERT INTO schedules (task, cron_expression, tz, enabled, next_run)
            VALUES (?, ?, ?, 1, ?)`,
      args: [task, expression, zone, nextRun],
    });
    const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
    rowId = Number(rows[0]?.id);
  } else {
    rowId = Number(previous.id);
    // The window a row holds is kept only while the row is ON and that window is still ahead: an OFF
    // row (or one whose `next_run` is empty, unreadable or already past) gets a fresh one from now, so
    // switching a report back on never fires the window it missed. Neither `enabled` nor `next_run` is
    // sealed, so this is not a live-set change and never pauses a live report.
    const stale = Number(previous.enabled) !== 1 || !windowIsAhead(previous.next_run, now);
    const writeWindow = moved || stale;
    // Both writes switch the row on, because a report's own row is one the reports page runs.
    await db.execute({
      sql: writeWindow
        ? `UPDATE schedules SET cron_expression = ?, tz = ?, enabled = 1, next_run = ?,
             updated_at = datetime('now') WHERE id = ?`
        : `UPDATE schedules SET cron_expression = ?, tz = ?, enabled = 1,
             updated_at = datetime('now') WHERE id = ?`,
      args: writeWindow ? [expression, zone, nextRun, rowId] : [expression, zone, rowId],
    });
  }
  if (!Number.isInteger(rowId) || rowId <= 0) throw fail("bad_input", "schedule");

  // One row per report task: every OTHER row carrying this exact task is switched off, because the
  // hook's due query matches every row of that shape and a stale duplicate would keep firing. The
  // rows are not deleted and nothing about their cron or zone moves: this touches `enabled` only.
  await db.execute({
    sql: `UPDATE schedules SET enabled = 0, updated_at = datetime('now')
           WHERE task = ? AND id <> ?`,
    args: [task, rowId],
  });

  // The pointer, and the live-set rule with it: the cron, the zone and the row id are all inside the
  // seal, so a live report that moves any of them is paused here, exactly as a live-set settings
  // change pauses it. The id is compared as a number, so a pointer already at this row (as text or as
  // a number) is not a move.
  const repointed = Number(report.schedule_id) !== rowId;
  const liveSetMoved = moved || repointed;
  const patch = { schedule_id: rowId };
  const liveChanged = text(report.status) === REPORT_LIVE && liveSetMoved;
  const pausedSealDropped = text(report.status) === REPORT_PAUSED && liveSetMoved
    && typeof report.live_seal === "string" && report.live_seal !== "";
  if (liveChanged) {
    patch.status = REPORT_PAUSED;
    patch.pause_reason = SETTINGS_CHANGED_PAUSE_REASON;
    patch.live_seal = null;
    patch.live_nonce = null;
  } else if (pausedSealDropped) {
    // Already paused: its status and its reason stay as they are, and only the approval goes.
    patch.live_seal = null;
    patch.live_nonce = null;
  }

  await updateReportColumns(db, report.id, patch);
  if (liveChanged) {
    await recordAudit(db, {
      reportId: report.id,
      kind: "live",
      subject: null,
      actor: "owner",
      decided: "refused",
      at: d.now(),
    });
  }
  return getReport(db, report.id);
}

export default setReportSchedule;