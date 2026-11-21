// scripts/migrations/0038-message-drafts-chat-thread.mjs
//
// message_drafts.chat_thread_id: the Perch session a BOT drafted in (null for an owner's draft, a job
// turn, or a bot turn that arrived over another channel). It is what the chat's own card lists
// (`GET /interactive/:sid/msg-drafts`), what the `msg_draft` frame is matched against, and where the
// fixed outcome note is queued when the owner sends or discards the draft. Never sealed: it is this
// instance's chat id, not part of who the message reaches.
//
// WHY ITS OWN NUMBER, and not an edit to 0036: 0036 is already applied on every live install, and the
// runner applies a migration by its `id` and never re-runs an id that is on file in
// `schema_migrations`. The column added to 0036's DDL would therefore have reached fresh installs
// only — a live install keeps the table it already made, because `CREATE TABLE IF NOT EXISTS` never
// adds a column — and the new code would fail on a column that is not there. So the column arrives
// here, under its own id, on every install that has 0036 on file. (0037's numbering note applies: the
// runner needs unique numbers in file-name order, never contiguous ones, so the next free number is
// the right one.)
//
// ADDITIVE, no SCHEMA_GENERATION bump: one nullable ADD COLUMN and one index, nothing to backfill and
// no schema object or row removed. init-db.js carries the same guarded ALTER and the same index on
// its own rail (servers/shared/message-drafts-schema.js), so a co-hosted instance converging on its
// own restart gets both too. rollbackSafe: older code never selects the column, so a rollback leaves
// it as a harmless leftover.
//
// A MISSING message_drafts is not a deferral: under the runner 0036 sorts before this file and
// creates the table in the same pass, so an "absent" read is reachable only by a direct call made
// outside the runner — and recording applied is then correct, because there is nothing left for a
// retry to find (the rule 0029-mail-account-send-columns.mjs states).
import Database from "better-sqlite3";
import {
  MESSAGE_DRAFTS_CHAT_THREAD_COLUMN,
  MESSAGE_DRAFTS_CHAT_THREAD_INDEX_DDL,
} from "../../servers/shared/message-drafts-schema.js";

export const id = "0038-message-drafts-chat-thread";

// rollbackSafe: one nullable column and one index on message_drafts; older code never selects it.
export const rollbackSafe = true;

export function run({ dbPath, log = () => {} }) {
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 10000");
  const { table, column, ddl } = MESSAGE_DRAFTS_CHAT_THREAD_COLUMN;
  try {
    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) {
      log(`  ${table}: absent — nothing to add`);
      return { applied: true, results: [`${table}: absent`] };
    }

    // Guarded: a store restored from a backup can lose the bookkeeping row while keeping the change,
    // so the ALTER is its own shape check. A store that already has the column says so and adds
    // nothing.
    const columns = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
    const had = columns.includes(column);
    if (!had) db.exec(ddl);
    log(`  ${table}.${column}: ${had ? "present" : "added"}`);

    // AFTER the column, never before: on an install whose table predates it, this CREATE INDEX would
    // fail with "no such column" (which is why it is deliberately not part of MESSAGE_DRAFTS_DDL).
    db.exec(MESSAGE_DRAFTS_CHAT_THREAD_INDEX_DDL);
    log("  idx_message_drafts_chat_thread: ensured");

    return {
      applied: true,
      results: [`${table}.${column}: ${had ? "present" : "added"}`, "idx_message_drafts_chat_thread: ensured"],
    };
  } finally {
    db.close();
  }
}