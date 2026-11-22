/**
 * Crow Recurring Reports: the owner's schedule clear, and the boot repair for a pointer to nothing.
 *
 * `clearReportSchedule` is the counterpart of `setReportSchedule` (schedule-set.js): it takes a report's
 * schedule away instead of writing it. The owner only, and a report that exists (`owner_only`,
 * `not_found`), exactly like the write.
 *
 * What it removes is the report's own row and the pointer to it, in ONE `db.batch` (one transaction):
 *
 *   - every `schedules` row whose task is exactly `report:<reportId>`, and no other task's row. A
 *     report's row is the one its page owns, so a duplicate a stale write left behind goes with it.
 *   - the report's `schedule_id`, with `updated_at` written the way `updateReportColumns` writes it.
 *
 * The live-set rule rides the same transaction, because the row id the report points at is part of the
 * go-live seal (`liveSetFor` in approvals.js): a LIVE report is paused here exactly as the schedule
 * write pauses it when the live set moves — the fixed pause sentence, a nulled seal and nonce, and the
 * `live`/`refused` audit row a pause writes, all in that one batch so a write that fails leaves the row,
 * the pointer and the audit trail exactly as they were. A PAUSED report that still carries a seal has
 * the seal and its nonce dropped and keeps its status and its pause reason. A DRAFT is only unpointed.
 *
 * A report with nothing to clear (no pointer and no row) is answered as it stands: the call is
 * idempotent, it writes nothing and audits nothing. A LIVE report is paused even then, and a PAUSED
 * report's seal is still dropped, because neither state survives a schedule that is not there.
 *
 * `repairDanglingSchedulePointers` is the boot-side repair: a report whose `schedule_id` names no
 * `schedules` row (a database restore, a row removed outside the app, an interrupted delete) has that
 * pointer nulled. It touches no schedule row, no status and no seal, and it never throws: a box that
 * cannot run it boots the reports hook anyway.
 */
import { REPORT_PREFIX } from "../../shared/schedule-core.js";
import {
  REPORT_LIVE, REPORT_PAUSED, SETTINGS_CHANGED_PAUSE_REASON, approvalInternals,
} from "./approvals.js";
import { getReport } from "./store.js";

const text = approvalInternals.text;

/** Whether an unset pointer is unset: null, undefined or the empty string. */
function unpointed(value) {
  return value == null || value === "";
}

/**
 * Clear one report's schedule: its own `schedules` rows and the pointer to them, with the live-set rule
 * applied to the report row in the same transaction.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} deps the approvals seam (`now` is the clock the audit row is stamped with, behind
 *   `resolveDeps`)
 * @param {{reportId: string, actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the report row after the writes
 * @throws {Error} `owner_only`, `not_found`
 */
export async function clearReportSchedule(db, deps, { reportId, actor } = {}) {
  approvalInternals.requireOwner(actor);
  const d = approvalInternals.resolveDeps(deps);
  const report = await approvalInternals.requireReport(db, reportId);
  const task = REPORT_PREFIX + report.id;

  // The rows this report's task owns. A read of the ids only: the delete below names the task, so a row
  // of any other task is never in reach. A read that throws is not answered as "no rows": the report's
  // schedule would then be silently left in place.
  const { rows } = await db.execute({
    sql: "SELECT id FROM schedules WHERE task = ?",
    args: [task],
  });

  const status = text(report.status);
  const pointed = !unpointed(report.schedule_id);
  const sealedWhilePaused = status === REPORT_PAUSED
    && typeof report.live_seal === "string" && report.live_seal !== "";
  // The live set no longer describes the report once the row it seals is gone: a live report is paused
  // whether or not a row was found (a pointer at nothing is already a broken live set).
  const liveChanged = status === REPORT_LIVE;

  // Nothing to clear and nothing the disappearance of the schedule changes in the report's own state.
  if (!rows.length && !pointed && !liveChanged && !sealedWhilePaused) return report;

  const read = Number(d.now());
  const at = Number.isFinite(read) ? read : Date.now();
  // The `updated_at` an `updateReportColumns` write leaves, so the two write paths agree on the column.
  const updatedAt = Date.now();

  const assignments = ["schedule_id = NULL", "updated_at = ?"];
  const args = [updatedAt];
  if (liveChanged) {
    assignments.push("status = 'paused'", "pause_reason = ?", "live_seal = NULL", "live_nonce = NULL");
    args.push(SETTINGS_CHANGED_PAUSE_REASON);
  } else if (sealedWhilePaused) {
    // Already paused: its status and its reason stay as they are, and only the approval goes.
    assignments.push("live_seal = NULL", "live_nonce = NULL");
  }
  args.push(report.id);

  const statements = [
    { sql: "DELETE FROM schedules WHERE task = ?", args: [task] },
    { sql: `UPDATE reports SET ${assignments.join(", ")} WHERE id = ?`, args },
  ];
  if (liveChanged) {
    // The row a pause writes, in the same transaction: the columns `recordAudit` writes, with the same
    // words a schedule change leaves (kind `live`, no subject, the owner asked, the approval refused).
    statements.push({
      sql: `INSERT INTO report_approvals_audit (report_id, kind, subject, actor, decided, at)
            VALUES (?, 'live', NULL, 'owner', 'refused', ?)`,
      args: [report.id, at],
    });
  }
  await db.batch(statements);
  return getReport(db, report.id);
}

/**
 * Null every report pointer that names no `schedules` row. The rows themselves, the report's status and
 * its seal are left exactly as they are, and a failure is answered as "nothing repaired".
 *
 * @param {object} db a libsql-shaped client
 * @returns {Promise<number>} how many report rows were changed
 */
export async function repairDanglingSchedulePointers(db) {
  try {
    const result = await db.execute({
      sql: `UPDATE reports SET schedule_id = NULL
             WHERE schedule_id IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM schedules s WHERE s.id = reports.schedule_id)`,
      args: [],
    });
    const changed = Number(result?.rowsAffected ?? 0);
    return Number.isFinite(changed) && changed > 0 ? changed : 0;
  } catch {
    return 0;
  }
}

export default clearReportSchedule;