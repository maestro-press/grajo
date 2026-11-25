// scripts/migrations/0042-reports-pickup.mjs
//
// Crow Recurring Reports' pickup half: one row per pickup, the bot turn that works through a batch of
// new comments on a report.
//
// report_pickups names the batch (`thread_ids_json`, `comment_ids_json`), when the pickup started and
// ended, the minutes its turn spent (`bot_ms`, the same day counter report_usage counts) and how it
// ended (`outcome`). A row id uses `rpu-` and never the `rpk_` prefix, which is the per-turn bearer
// token's (servers/gateway/reports/pickup-token.js). Outcomes are validated in the modules, never by a
// CHECK. No foreign keys: the reports store removes one report's rows itself. LOCAL ONLY: the name is in
// instance-sync's LOCAL_ONLY_TABLES, because a pickup names the comments a report's readers left and a
// report never leaves the instance holding it.
//
// ADDITIVE, no SCHEMA_GENERATION bump: one new local-only table and one index, and every step is safe to
// re-run, because a store that already has them says so and changes nothing.
//
// A MISSING `reports` is not a deferral: this table does not depend on `reports` existing, so a database
// that never had the reports family (a paired instance, a fresh store) gets the pickup table all the
// same, and recording applied is correct, because there is nothing left for a retry to find (the rule
// 0039-reports-links.mjs states).
import Database from "better-sqlite3";
import { REPORTS_PICKUP_DDL, REPORTS_PICKUP_TABLES } from "../../servers/shared/reports-schema.js";

export const id = "0042-reports-pickup";

// rollbackSafe: one new local-only table and one index; older code never selects either.
export const rollbackSafe = true;

export function run({ dbPath, log = () => {} }) {
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 10000");
  try {
    db.exec(REPORTS_PICKUP_DDL);
    // CREATE TABLE/INDEX IF NOT EXISTS, so a re-run after a partial apply finds whatever is already
    // there and says the same thing.
    for (const name of REPORTS_PICKUP_TABLES) log(`  ${name}: ensured`);
    return { applied: true, results: REPORTS_PICKUP_TABLES.map((name) => `${name}: ensured`) };
  } finally {
    db.close();
  }
}