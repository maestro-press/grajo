/**
 * boot/trigger-inventory.js — every trigger in crow.db and tasks.db, checked against the set Crow
 * installs (item I3).
 *
 * WHY. A SQLite trigger runs inside every write to its table with no code of ours in between, and
 * crow.db is bound read-write into every contained bot: a bot can create a trigger on `pi_bot_defs`
 * that rewrites the row after the MAC signed it, or one on `memories` that quietly copies, drops or
 * rewrites rows. Nothing else in Crow looks at the trigger list as a whole, so this pass does: it
 * LISTS every trigger of both stores and compares NAME AND WHITESPACE-NORMALISED SQL with the set
 * derived from code (`servers/shared/trigger-catalog.js` — the history module's generated capture and
 * guard triggers, init-db's FTS triggers, the mail schema's, and each installed bundle's own
 * `server/` CREATE TRIGGER text).
 *
 * IT REPORTS, IT NEVER REACTS. A trigger this pass does not recognise is one log line and one audit
 * row; nothing is ever dropped, disabled or rewritten. Dropping somebody's trigger on a schedule is
 * the wrong direction for tables this important, and an operator may legitimately have put one there
 * (a debugging trigger, an extension of their own).
 *
 *   `[trigger-inventory] foreign trigger <name> on <table> in <db>`
 *
 * ONE LINE PER TRIGGER PER PROCESS, keyed by db + name + a hash of its SQL: an hourly pass must not
 * repeat itself, and a body that CHANGES again is a new fact and is reported again. The audit row goes
 * to `audit_log` in crow.db (event `trigger_inventory`) for a finding in either store — crow.db is the
 * instance's own book, and the details name the store. There is no bell and no user-facing sentence:
 * this is a log/audit fact, not an owner action.
 *
 * ONE OTHER WRITER, SAME BOOK. `servers/shared/history/ensure.js` records the repair it makes when a
 * capture trigger's stored body is not the body Crow generates (it drops and re-creates it): the same
 * event and details shape, `reason: "history-trigger-recreated"` and the replaced body's SHA-256. That
 * is the evidence this pass would otherwise be the only one to keep — a silent repair would erase it.
 *
 * RUN AT BOOT AND HOURLY. `startTriggerInventory` runs one pass immediately (after the listen
 * callback, so the boot itself is never delayed by filesystem work) and then every hour on an
 * unref'd timer, so it cannot hold the process open. Every cycle is fully caught: an inventory is
 * never a reason for an outage.
 *
 * The comparison itself lives in `servers/shared/trigger-catalog.js`; this module owns only the
 * reading, the de-duplication, the line and the audit row.
 */
import { existsSync } from "node:fs";
import { createHash } from "node:crypto";

import { auditLog, createDbClient } from "../../db.js";
import { tasksDbPath as instanceTasksDbPath } from "../../../scripts/pi-bots/instance-paths.mjs";
import {
  expectedTriggerIndex, normalizeTriggerSql, readTriggerRows, unexpectedTriggers,
} from "../../shared/trigger-catalog.js";

/** This process's already-reported findings: `${db}\0${name}\0${sql hash}`. */
const reported = new Set();

/** Test seam: forget what this process has already reported. */
export function forgetTriggerInventory() {
  reported.clear();
}

/** A trigger name is bot-written text: only printable ASCII reaches the log line. */
const printable = (value) => String(value ?? "").replace(/[^\x20-\x7e]/g, "?");

/**
 * One database's triggers, compared with the catalogue.
 *
 * @param {object} db a Crow db client (`{execute}`)
 * @param {{dbName: string, expected: Map, log: Function, audit: Function, auditDb: object,
 *          findings: Array}} opts
 * @returns {Promise<Array<{name: string, table: string, reason: string}>>} every offender found
 *   (reported or already reported), so a caller/test can see the pass's whole answer
 */
async function scanOne(db, { dbName, expected, log, audit, auditDb, findings }) {
  const { rows, error } = await readTriggerRows(db);
  if (error) {
    // Cannot tell is not "none there", but this pass does not refuse anything: it says so once per
    // process (there is no line, no audit row per trigger when the list cannot even be read).
    if (!reported.has(`${dbName}\0(list-unreadable)`)) {
      reported.add(`${dbName}\0(list-unreadable)`);
      log(`[trigger-inventory] ${dbName}: the trigger list could not be read (${error?.message ?? error})`);
    }
    return [];
  }
  const offenders = unexpectedTriggers(rows, expected);
  const sqlByName = new Map((rows || []).map((row) => [String(row?.name ?? ""), String(row?.sql ?? "")]));
  for (const offender of offenders) {
    const sql = sqlByName.get(offender.name) ?? "";
    const slot = `${dbName}\0${offender.name}\0${createHash("sha256").update(normalizeTriggerSql(sql)).digest("hex")}`;
    if (reported.has(slot)) continue;
    reported.add(slot);
    const why = offender.reason === "body-changed" ? " (body changed)" : "";
    log(
      `[trigger-inventory] foreign trigger ${printable(offender.name)} on `
      + `${printable(offender.table || "?")} in ${dbName}${why}`,
    );
    findings.push({ db: dbName, name: offender.name, table: offender.table || null, reason: offender.reason });
    // LOG-ONLY: an audit row, never a bell and never a user-facing sentence. The audit row goes to
    // crow.db (the instance's own book) even for a finding in tasks.db, which has no audit_log.
    try {
      await audit(auditDb, "trigger_inventory", {
        details: { db: dbName, trigger: offender.name, table: offender.table || null, reason: offender.reason },
      });
    } catch { /* an audit failure never becomes the inventory's failure */ }
  }
  return offenders;
}

/**
 * One inventory pass over this instance's two stores.
 *
 * @param {{dbFactory?: (path?: string) => object, log?: Function, audit?: Function,
 *          tasksPath?: string}} [opts] `dbFactory` opens a handle (the gateway's `createDbClient`);
 *   `audit` is this module's audit seam (a test injects one); `tasksPath` defaults to the instance's
 *   own tasks.db and is only opened when that file already exists (opening it would CREATE it).
 * @returns {Promise<{crow: Array, tasks: Array, findings: Array}>} `crow`/`tasks` are the offenders
 *   per store, `findings` the ones THIS pass reported (an empty pass reports nothing)
 */
export async function runTriggerInventory({ dbFactory = createDbClient, log = console.warn, audit = auditLog, tasksPath } = {}) {
  const expected = expectedTriggerIndex();
  const result = { crow: [], tasks: [], findings: [] };
  let crowDb = null;
  try {
    try {
      crowDb = dbFactory();
    } catch (err) {
      log(`[trigger-inventory] crow.db could not be opened: ${err?.message ?? err}`);
      return result;
    }
    result.crow = await scanOne(crowDb, {
      dbName: "crow.db", expected, log, audit, auditDb: crowDb, findings: result.findings,
    });

    const path = tasksPath || instanceTasksDbPath();
    if (path && existsSync(path)) {
      let tasksDb = null;
      try {
        tasksDb = dbFactory(path);
        result.tasks = await scanOne(tasksDb, {
          dbName: "tasks.db", expected, log, audit, auditDb: crowDb, findings: result.findings,
        });
      } catch (err) {
        // A busy or half-created card store must not fail the pass: the next hour retries.
        log(`[trigger-inventory] tasks.db: the trigger list could not be read (${err?.message ?? err})`);
      } finally {
        try { tasksDb?.close?.(); } catch { /* a stuck close must not fail the pass */ }
      }
    }
    return result;
  } finally {
    try { crowDb?.close?.(); } catch { /* a stuck close must not fail the pass */ }
  }
}

/**
 * Arm the boot pass and the hourly one. The first run is `setImmediate` (nothing on the listen path
 * awaits it), the interval is unref'd, and an in-flight guard keeps two passes from overlapping.
 *
 * @param {{dbFactory?: Function, intervalMs?: number, log?: Function, audit?: Function,
 *          tasksPath?: string, immediate?: boolean}} [opts]
 * @returns {{stop: () => void, timer: object|null, cycle: () => Promise<object|null>}}
 */
export function startTriggerInventory({
  dbFactory = createDbClient, intervalMs = 60 * 60 * 1000, log = console.warn, audit = auditLog,
  tasksPath, immediate = true,
} = {}) {
  let inFlight = false;
  const cycle = async () => {
    if (inFlight) return null;
    inFlight = true;
    try {
      return await runTriggerInventory({ dbFactory, log, audit, tasksPath });
    } catch (err) {
      log(`[trigger-inventory] cycle failed: ${err?.message ?? err}`);
      return null;
    } finally {
      inFlight = false;
    }
  };
  if (immediate) setImmediate(() => { cycle(); });
  const timer = setInterval(() => { cycle(); }, intervalMs);
  timer.unref?.();
  return { timer, cycle, stop: () => { try { clearInterval(timer); } catch { /* already gone */ } } };
}