/**
 * Crow Recurring Reports: deleting one report.
 *
 * A report owns more than its row: a keychain connection behind every credential, its own `schedules`
 * row, runs, run requests, sends, recipients, steps, assets, hosts and state, and a directory under
 * `<CROW_HOME>/reports/`. `deleteReport` takes them in one fixed order, so a refusal never leaves a
 * report half deleted and a success leaves nothing that still names it:
 *
 *   1. The owner only, and a report that exists (`owner_only`, `not_found`). A report id this instance
 *      never minted is `not_found` too, so a repeated delete is idempotent.
 *   2. The report's own directory is RESOLVED and confined to `<CROW_HOME>/reports/` before anything
 *      is written. A `<id>` that is a symlink, or whose real path does not stay under the reports root,
 *      is `bad_input` and nothing is touched. The check runs first so the refusal cannot happen after
 *      the rows are already gone.
 *   3. ONE transaction, before a single thing is torn down, settles the runs: a run still `running`
 *      refuses `report_busy` (its process is writing a version for this report), and otherwise every run
 *      still `queued` becomes `failed` with "This report was deleted." (one guarded UPDATE,
 *      `WHERE status = 'queued'`) and every unclaimed `report_run_requests` row goes. A run cancelled
 *      here can never start work after this delete. IF THE TEARDOWN THEN ABORTS (step 4's keychain that
 *      cannot be reached) the report keeps every row it had and the runs it cancelled stay cancelled:
 *      that is accepted, because a run working for a report its owner just deleted is worse than a run
 *      the owner has to ask for again. A run CLAIMED between this settle and the final row delete is not
 *      caught here: it may still write its artifact version, which belongs to the report's project and
 *      not to the report, and the deliver re-check before the one outgoing step (`run.js`,
 *      `reportExists`) is what stops it from sending anything.
 *   4. Every credential binding is REVOKED through `revokeCredential` from steps.js, and the keychain
 *      rows behind them are removed through the keychain's own function (`deleteServiceSecrets`, the
 *      same one Crow Mail's delete path uses; no SQL against the keychain tables is written here).
 *      ONLY A REPORTS CREDENTIAL'S OWN ROWS GO: for each credential row's `connection_uuid` the keychain
 *      row is read first, and a connection whose row is not this bundle's `REPORT_CREDENTIAL` (another
 *      bundle's secret, a row of another kind) is SKIPPED and named in the answer, while a connection
 *      with no row at all is SKIPPED and named `already_gone`. All the candidates are checked before the
 *      first delete, so one this module must not touch neither stops nor changes the rest. A skipped
 *      connection's row is left in the keychain, and the revoke above is told to leave it alone
 *      (`revokeCredential`'s `skipDisconnect`): a `report_credentials` row that points somewhere else
 *      can never disconnect, let alone delete, another bundle's secret. A keychain row that is already
 *      gone needs no disconnect either. The credential row itself goes with the report. The bindings are
 *      revoked first, so a keychain that then fails answers `keychain_disconnect_failed` with every
 *      report row still in place, the bindings it revoked still revoked (nothing is rolled back) and
 *      every keychain row it did not reach still there: the owner retries the same delete, which skips
 *      what is already gone.
 *   5. The `report:<id>` schedule rows go through the shared schedule writer (schedule-store's
 *      `deleteSchedule`), which removes the row and its run history. The Schedule page's own writer
 *      (`schedule-actions.js` `deleteScheduleRow`) refuses a report row with `report-owned`; that
 *      guard is the page's, and this module neither goes through it nor weakens it.
 *   6. ONE transaction deletes the report's rows in every `report_*` table that keys on `report_id`
 *      (children first, `reports` last). `report_versions` rows go with them, but the ARTIFACT and its
 *      versions do NOT: the artifact belongs to the report's project, not to the report, so the answer
 *      carries `artifactId` for the caller to say so.
 *   7. The confined directory (assets, step env, bundle) is removed recursively. A directory that
 *      cannot be removed is a leftover, not a failed delete: the rows are gone and a repeated delete
 *      finds nothing left to remove.
 *   8. Nothing is written to `report_approvals_audit` afterwards: its rows went in step 6, and a row
 *      cannot be audited once the report it names is gone. The route writes the gateway's own
 *      `audit_log` line instead, where a deleted report can still be named.
 *
 * `deps` is the seam, and every member falls back to the real thing:
 *   - `crowHome()` or `crowHome`: this instance's home; the report directory is under `<home>/reports/`.
 *   - `deleteKeychainSecrets(db, connectionUuid)`: the keychain removal, so a test can make it fail.
 *   - everything else is handed to `revokeCredential` unchanged (`loadSeed`, `now`). `now` is also the
 *     end time the cancelled runs are marked with; absent, this instance's clock is used.
 *
 * Every refusal is an Error with a `code`: `owner_only`, `not_found`, `bad_input`, `report_busy`,
 * `keychain_disconnect_failed`. The answer is `{ok, artifactId}`, plus `keychainSkipped` (one
 * `{connectionUuid, code}` per connection this module refused to remove) when there is one.
 */
import { lstatSync, realpathSync, rmSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { resolveCrowHome } from "../../shared/crow-home.js";
import { REPORT_PREFIX } from "../../shared/schedule-core.js";
import { deleteSchedule } from "../../shared/schedule-store.js";
import { deleteServiceSecrets, REPORTS_BUNDLE } from "../keychain/store.js";
import { approvalInternals } from "./approvals.js";
import { REPORT_CREDENTIAL_ENV_KEY, listCredentials, revokeCredential } from "./steps.js";

const fail = approvalInternals.fail;
const text = approvalInternals.text;

/** The refusal a report with a run in hand answers. */
export const REPORT_BUSY = "report_busy";

/** The refusal a keychain that cannot be reached answers: nothing was deleted. */
export const KEYCHAIN_DISCONNECT_FAILED = "keychain_disconnect_failed";

/** Why one credential's keychain connection was left alone: it is not a reports credential. */
export const NOT_A_REPORTS_CREDENTIAL = "not_a_reports_credential";

/** Why one credential's keychain connection was left alone: there is no row behind it any more. */
export const ALREADY_GONE = "already_gone";

/** The error text a run still queued for a deleted report is left with. */
export const RUN_DELETED_TEXT = "This report was deleted.";

/** The directory the report areas live under, and the shape a report id must have inside it. */
const REPORTS_AREA = "reports";

function clock(d) {
  const value = typeof d.now === "function" ? Number(d.now()) : NaN;
  return Number.isFinite(value) ? value : Date.now();
}

function resolveDeps(deps) {
  const given = deps == null ? {} : deps;
  const home = given.crowHome;
  const crowHome = () => {
    if (typeof home === "function") {
      const value = home();
      if (typeof value === "string" && value) return value;
    }
    if (typeof home === "string" && home) return home;
    return resolveCrowHome();
  };
  const removeSecrets = typeof given.deleteKeychainSecrets === "function"
    ? given.deleteKeychainSecrets
    : deleteServiceSecrets;
  return { ...given, crowHome, deleteKeychainSecrets: removeSecrets };
}

/* ---------------------------------------------------------------------- the directory */

/** The report's area, `{root, target}`, refused unless it is exactly one segment under the root. */
function areaOf(d, reportId) {
  const root = resolve(d.crowHome(), REPORTS_AREA);
  const target = resolve(root, reportId);
  if (target !== join(root, reportId) || !target.startsWith(root + sep)) {
    throw fail("bad_input", "report dir");
  }
  return { root, target };
}

/**
 * The real path `areaOf` names, or null when there is nothing there. A symlink at the report's own
 * name, a real path outside the reports root, and a non-directory are all refused: the recursive remove
 * only ever runs on a directory that resolves inside this instance's own reports area.
 */
function confinedArea(area) {
  let rootReal;
  try {
    rootReal = realpathSync(area.root);
  } catch {
    return null; // no reports area at all: nothing was ever written here
  }
  let entry;
  try {
    entry = lstatSync(area.target);
  } catch {
    return null;
  }
  if (entry.isSymbolicLink()) throw fail("bad_input", "report dir");
  let targetReal;
  try {
    targetReal = realpathSync(area.target);
  } catch {
    throw fail("bad_input", "report dir");
  }
  if (!targetReal.startsWith(rootReal + sep)) throw fail("bad_input", "report dir");
  if (!entry.isDirectory()) throw fail("bad_input", "report dir");
  return targetReal;
}

function removeArea(path) {
  if (!path) return false;
  try {
    rmSync(path, { recursive: true, force: true });
    return true;
  } catch {
    return false; // a leftover directory is not a failed delete
  }
}

/* -------------------------------------------------------------------------- the rows */

/**
 * May this credential's keychain connection be removed, and may its row be disconnected? Only when the
 * keychain row behind it is this bundle's own `REPORT_CREDENTIAL` (kind 'service'): a `connection_uuid`
 * is a reference a row can be made to name, so the keychain row itself is the guard, never the
 * reference alone. A row that is not there answers `already_gone`: there is nothing of this report's to
 * remove, and nothing of this report's to disconnect.
 *
 * @returns {Promise<"removable"|"already_gone"|"not_a_reports_credential">}
 */
async function reportsCredentialKind(db, connectionUuid) {
  try {
    const { rows } = await db.execute({
      sql: `SELECT bundle_id, env_key FROM crow_keychain
             WHERE kind = 'service' AND connection_uuid = ?`,
      args: [connectionUuid],
    });
    if (rows.length === 0) return ALREADY_GONE;
    return rows.some((row) => text(row.bundle_id) === REPORTS_BUNDLE
      && text(row.env_key) === REPORT_CREDENTIAL_ENV_KEY)
      ? "removable"
      : NOT_A_REPORTS_CREDENTIAL;
  } catch {
    return NOT_A_REPORTS_CREDENTIAL;
  }
}

/**
 * The runs, settled in ONE transaction before any teardown.
 *
 * A run in hand refuses `report_busy` and changes nothing: the throw rolls the whole transaction back,
 * so not even a sibling's queued row is marked. Otherwise every run still `queued` for this report is
 * marked `failed` with `RUN_DELETED_TEXT` (guarded on the status, so a run some executor claimed between
 * reads is left to its executor) and every unclaimed `report_run_requests` row is dropped: a request
 * still waiting asked for a report that is about to be gone, and nothing would answer it.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {number} at epoch ms for the cancelled runs' `ended_at`
 * @throws {Error} `report_busy`
 */
async function settleRuns(db, reportId, at) {
  await db.runTransaction((run) => {
    let running = [];
    try {
      ({ rows: running } = run({
        sql: "SELECT 1 AS busy FROM report_runs WHERE report_id = ? AND status = 'running' LIMIT 1",
        args: [reportId],
      }));
    } catch {
      running = []; // no runs table: there is no run in hand
    }
    if (running.length > 0) throw fail(REPORT_BUSY);
    try {
      run({
        sql: `UPDATE report_runs SET status = 'failed', ended_at = ?, error_text = ?
               WHERE report_id = ? AND status = 'queued'`,
        args: [at, RUN_DELETED_TEXT, reportId],
      });
    } catch {
      // Same as above: no runs table, no queued run to cancel.
    }
    try {
      run({
        sql: "DELETE FROM report_run_requests WHERE report_id = ? AND claimed_at IS NULL",
        args: [reportId],
      });
    } catch {
      // No request queue: there is nothing pending to drop.
    }
  });
}

/** Every `report_*` table that keys on `report_id`. The `reports` head has no underscore and keys on
 *  `id`, so the transaction names it itself. */
async function reportIdTables(db) {
  let names;
  try {
    const { rows } = await db.execute({
      sql: "SELECT name FROM sqlite_master WHERE type = 'table' AND name GLOB ? ORDER BY name",
      args: ["report_*"],
    });
    names = rows.map((row) => text(row.name));
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    // The name comes from sqlite_master, and this keeps the quoted identifier to a known alphabet.
    if (!/^report_[A-Za-z0-9_]+$/.test(name)) continue;
    let columns;
    try {
      columns = (await db.execute(`PRAGMA table_info("${name}")`)).rows;
    } catch {
      continue;
    }
    if (columns.some((column) => text(column.name) === "report_id")) out.push(name);
  }
  return out;
}

/** The `report:<id>` schedule rows of one report. */
async function reportScheduleIds(db, report) {
  const ids = new Set();
  const task = REPORT_PREFIX + report.id;
  try {
    const { rows } = await db.execute({
      sql: "SELECT id, task FROM schedules WHERE task = ?",
      args: [task],
    });
    for (const row of rows) {
      const id = Number(row.id);
      if (Number.isInteger(id) && id > 0) ids.add(id);
    }
  } catch {
    // No schedules table: there is no schedule row to remove.
  }
  // A report row can also point at its schedule by id; only a row that is THIS report's is taken.
  const pointed = Number(report.schedule_id);
  if (Number.isInteger(pointed) && pointed > 0) {
    try {
      const { rows } = await db.execute({
        sql: "SELECT id FROM schedules WHERE id = ? AND task = ?",
        args: [pointed, task],
      });
      if (rows.length > 0) ids.add(pointed);
    } catch {
      // Same as above.
    }
  }
  return [...ids];
}

/* ---------------------------------------------------------------------------- delete */

/**
 * Delete one report, and everything that belongs to it, in the order the header spells out.
 *
 * @param {object} db
 * @param {object} [deps] `crowHome`, `deleteKeychainSecrets`, and whatever `revokeCredential` needs
 * @param {{reportId: string, actor: {kind: "owner"}}} input
 * @returns {Promise<{ok: true, artifactId: string|null,
 *   keychainSkipped?: {connectionUuid: string, code: string}[]}>}
 * @throws {Error} `owner_only`, `bad_input`, `not_found`, `report_busy`, `keychain_disconnect_failed`
 */
export async function deleteReport(db, deps, { reportId, actor } = {}) {
  approvalInternals.requireOwner(actor);
  const d = resolveDeps(deps);
  const report = await approvalInternals.requireReport(db, reportId);

  // Confined first: a path this instance must not remove refuses before a single row is touched.
  const area = areaOf(d, report.id);
  const dir = confinedArea(area);

  // The runs are settled in one transaction before anything is torn down: a report with a run in hand
  // refuses `report_busy`, and every run still queued is cancelled here so it cannot start work later.
  await settleRuns(db, report.id, clock(d));

  // Every credential's binding is revoked, then the keychain rows are checked before any of them is
  // removed: a connection that is not this bundle's REPORT_CREDENTIAL is skipped and named, and a
  // keychain that cannot be reached aborts the delete with the report's rows all still in place.
  const credentials = await listCredentials(db, report.id, d);
  const connections = [];
  for (const row of credentials) {
    const uuid = text(row.connectionUuid);
    if (uuid && !connections.includes(uuid)) connections.push(uuid);
  }
  const removable = [];
  const leaveAlone = new Set();
  const keychainSkipped = [];
  for (const uuid of connections) {
    const kind = await reportsCredentialKind(db, uuid);
    if (kind === "removable") removable.push(uuid);
    else {
      leaveAlone.add(uuid);
      keychainSkipped.push({ connectionUuid: uuid, code: kind });
    }
  }
  for (const row of credentials) {
    // A connection this report does not own is not even disconnected: the revoke keeps its own row's
    // state and leaves somebody else's keychain row exactly as it was.
    const skipDisconnect = leaveAlone.has(text(row.connectionUuid));
    await revokeCredential(db, d, { reportId: report.id, host: row.host, actor, skipDisconnect });
  }
  for (const uuid of removable) {
    try {
      await d.deleteKeychainSecrets(db, uuid);
    } catch {
      // The keychain's own text is not repeated: it could carry a value, and the code is the answer.
      throw fail(KEYCHAIN_DISCONNECT_FAILED);
    }
  }

  for (const scheduleId of await reportScheduleIds(db, report)) await deleteSchedule(db, scheduleId);

  const tables = await reportIdTables(db);
  await db.runTransaction((run) => {
    for (const table of tables) {
      run({ sql: `DELETE FROM "${table}" WHERE report_id = ?`, args: [report.id] });
    }
    run({ sql: "DELETE FROM reports WHERE id = ?", args: [report.id] });
  });

  removeArea(dir);

  const answer = { ok: true, artifactId: report.artifact_id == null ? null : text(report.artifact_id) };
  if (keychainSkipped.length) answer.keychainSkipped = keychainSkipped;
  return answer;
}

export default deleteReport;