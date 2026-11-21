// scripts/migrations/0037-bot-sharing-audit.mjs
//
// The bot sharing door's audit trail: bot_sharing_audit, one row per call to the narrow MCP mount at
// /sharing-bot/mcp — which bot, on which thread and gateway, which tool, who it aimed at, whether it
// was allowed, and the draft (or the ids a read returned) it left behind. Times are epoch ms. The
// outcome words (`drafted`, `revised`, `read`, `refused:<code>`) carry no CHECK:
// servers/gateway/sharing-bot/audit.js owns them in JS. No foreign keys: a draft row outlives its
// conversation and a refused call names no draft at all. NEVER message text — the table has no
// column for it, on purpose (a bot's words land in message_drafts). LOCAL ONLY: the name is in
// instance-sync's LOCAL_ONLY_TABLES, because the allow-list a call is judged against lives in this
// instance's secrets directory and its targets are this instance's contacts.
//
// NUMBERING: 0036 is Crow Messages' saved drafts (its PR A), so the door's table takes the next free
// number. The runner applies a migration by its `id`, in file-name order, and never requires the
// numbers to be contiguous (0012 is an older gap), so a gap costs nothing.
//
// ADDITIVE, no SCHEMA_GENERATION bump: init-db.js carries the same DDL as BOT_SHARING_AUDIT_DDL
// (servers/shared/bot-sharing-schema.js) on its own rail, so a co-hosted instance converging on its
// own restart gets it too. DDL only: there is nothing to backfill, and no schema object or row is
// removed. rollbackSafe: older code never reads the table, so a rollback leaves it as a harmless
// leftover.
import Database from "better-sqlite3";
import { BOT_SHARING_AUDIT_DDL, BOT_SHARING_AUDIT_TABLES } from "../../servers/shared/bot-sharing-schema.js";

export const id = "0037-bot-sharing-audit";

// rollbackSafe: one new local-only table and three indexes only; older code never reads them.
export const rollbackSafe = true;

export function run({ dbPath, log = () => {} }) {
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 10000");
  try {
    db.exec(BOT_SHARING_AUDIT_DDL);
    // CREATE TABLE/INDEX IF NOT EXISTS, so a re-run after a partial apply finds whatever is already
    // there and says the same thing.
    for (const table of BOT_SHARING_AUDIT_TABLES) log(`  ${table}: ensured`);
    return { applied: true, results: BOT_SHARING_AUDIT_TABLES.map((t) => `${t}: ensured`) };
  } finally {
    db.close();
  }
}