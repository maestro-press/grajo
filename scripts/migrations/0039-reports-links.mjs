// scripts/migrations/0039-reports-links.mjs
//
// Crow Recurring Reports' reader half, and the one late column it needs on `reports`.
//
// report_link_tokens is the per-recipient, per-run link: a token minted for one run and one recipient,
// stored only as its SHA-256 (`token_hash`, UNIQUE), naming the artifact version it opens (stored at mint,
// so a resolve never re-derives it), the scope of page it opens (`view` or `comment`), the send row it
// went out in, the approval nonce it was bound to, when it expires and whether it was revoked. There is no
// unique key over (report, run, recipient): a mint is per send, and the mint revokes the earlier unrevoked
// rows of the same send. report_recipient_comments is what a reader wrote through that link: the
// artifacts comment id (`comment_id`) and thread id (as TEXT), the report, the run and the recipient it
// belongs to, `via` (how they got there) and when. Scopes and `via` words are validated in the reports
// modules, never by a CHECK. No foreign keys: the reports store removes one report's rows itself. LOCAL
// ONLY: both names are in instance-sync's LOCAL_ONLY_TABLES, because a token is a way into one report and a
// comment is somebody's words about it, and a report never leaves the instance holding it.
//
// reports.comment_window_runs (how many runs back a reader may still comment on) is a guarded ADD
// COLUMN, not part of REPORTS_LINKS_DDL: 0031 already executes REPORTS_DDL and a store created from that
// string has the table already, where `CREATE TABLE IF NOT EXISTS` never adds a column. It is its own
// constant (REPORTS_COMMENT_WINDOW_COLUMN in servers/shared/reports-schema.js) so init-db.js runs the
// same ALTER, byte for byte, on its own rail.
//
// ADDITIVE, no SCHEMA_GENERATION bump: two new local-only tables, five indexes and one NOT NULL column
// with a default, so an existing row gets 4 without a backfill. Nothing is dropped or removed, which is
// why every step here is safe to re-run: a store that already has the tables or the column says so and
// changes nothing.
//
// A MISSING `reports` is not a deferral: under the runner 0031 sorts before this file and creates the
// table in the same pass, so an "absent" read is reachable only by a direct call made outside the
// runner, and recording applied is then correct, because there is nothing left for a retry to find (the
// rule 0029-mail-account-send-columns.mjs states). The two link tables are created either way: they do
// not depend on `reports` existing.
import Database from "better-sqlite3";
import {
  REPORTS_COMMENT_WINDOW_COLUMN,
  REPORTS_LINKS_DDL,
  REPORTS_LINKS_TABLES,
} from "../../servers/shared/reports-schema.js";

export const id = "0039-reports-links";

// rollbackSafe: two new local-only tables, five indexes and one column with a default; older code never
// selects any of them.
export const rollbackSafe = true;

export function run({ dbPath, log = () => {} }) {
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 10000");
  const { table, column, ddl } = REPORTS_COMMENT_WINDOW_COLUMN;
  try {
    db.exec(REPORTS_LINKS_DDL);
    // CREATE TABLE/INDEX IF NOT EXISTS, so a re-run after a partial apply finds whatever is already
    // there and says the same thing.
    for (const name of REPORTS_LINKS_TABLES) log(`  ${name}: ensured`);

    const results = REPORTS_LINKS_TABLES.map((name) => `${name}: ensured`);

    if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?").get(table)) {
      log(`  ${table}: absent, nothing to add`);
      return { applied: true, results: [...results, `${table}: absent`] };
    }

    // Guarded: a store restored from a backup can lose the bookkeeping row while keeping the change, so
    // the ALTER is its own shape check. A store that already has the column says so and adds nothing.
    const columns = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
    const had = columns.includes(column);
    if (!had) db.exec(ddl);
    log(`  ${table}.${column}: ${had ? "present" : "added"}`);

    return {
      applied: true,
      results: [...results, `${table}.${column}: ${had ? "present" : "added"}`],
    };
  } finally {
    db.close();
  }
}