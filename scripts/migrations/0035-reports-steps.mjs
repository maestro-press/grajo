// scripts/migrations/0035-reports-steps.mjs
//
// Crow Recurring Reports' custom-step half: report_custom_steps (one row per report, step key and
// revision, its file bundle, its bundle hash, its state word and the owner's approval nonce and seal),
// report_assets (one row per named input with its sha256 and size; the bytes live under the instance's
// own reports directory), report_hosts (the exact names or `*.suffix` wildcards a report may reach, one
// row per report and host) and report_credentials (one host of one report bound to one keychain row,
// with where the relay attaches it and the path prefixes and methods the rule covers). Epoch-ms times.
// States, host shapes and inject rules are validated in servers/gateway/reports/steps.js, never by a
// CHECK. No foreign keys: the reports store removes one report's rows itself. LOCAL ONLY: all four names
// are in instance-sync's LOCAL_ONLY_TABLES, because a step bundle, an asset, a host and a credential
// binding all describe one report, and a report never leaves the instance holding it.
//
// ADDITIVE, no SCHEMA_GENERATION bump: init-db.js carries the same DDL as REPORTS_STEPS_DDL
// (servers/shared/reports-schema.js) on its own rail, so a co-hosted instance converging on its own
// restart gets it too. DDL only: there is nothing to backfill, and no schema object or row is removed.
// The earlier reports constants (0031's REPORTS_DDL, 0032's REPORTS_RUNS_DDL, 0033's
// REPORTS_VERSIONS_DDL, 0034's REPORTS_SEND_DDL) are untouched, because those migrations execute them
// and their approved shapes stay as they are.
import Database from "better-sqlite3";
import { REPORTS_STEPS_DDL, REPORTS_STEPS_TABLES } from "../../servers/shared/reports-schema.js";

export const id = "0035-reports-steps";

// rollbackSafe: four new local-only tables and one index only; older code never reads them.
export const rollbackSafe = true;

export function run({ dbPath, log = () => {} }) {
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 10000");
  try {
    db.exec(REPORTS_STEPS_DDL);
    // CREATE TABLE/INDEX IF NOT EXISTS, so a re-run after a partial apply finds whatever is already
    // there and says the same thing.
    for (const table of REPORTS_STEPS_TABLES) log(`  ${table}: ensured`);
    return { applied: true, results: REPORTS_STEPS_TABLES.map((t) => `${t}: ensured`) };
  } finally {
    db.close();
  }
}