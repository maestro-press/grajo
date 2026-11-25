// scripts/migrations/0041-bot-def-mac.mjs
//
// pi_bot_defs.def_mac / def_generation: the tamper evidence over a bot definition.
//
// A bot definition is AUTHORITY — tools.crow_mcp, permission_policy, write_paths, project_id,
// remote servers — and crow.db is bound read-write into every contained bot, so a bot that edits
// its own row raises its own policy at its next spawn. `def_mac` holds a keyed MAC over the WHOLE
// definition (under <CROW_HOME>/secrets/token-hmac.key, the one key a bot cannot read) and
// `def_generation` holds a monotonic counter kept OUTSIDE crow.db
// (<CROW_HOME>/secrets/bot-def-generations.json) so a bot cannot replay an older, valid pair of
// its own. See servers/shared/bot-def-mac.js.
//
// ADDITIVE, no SCHEMA_GENERATION bump: two nullable columns, nothing to backfill here and no
// schema object or row removed. init-db.js carries the same two guarded ALTERs on its own rail (so
// a fresh install has them in the CREATE body and a pre-existing one converges on any init-db run),
// and this file carries them for an instance that converges onto this checkout on its own restart
// without a schema-generation crossing — the 0005/0006 bot_sessions precedent.
//
// Filling them is NOT this migration's job: the values need the HMAC key, so they are written by
// the pre-listen boot converter (servers/gateway/boot/bot-def-mac.js), which snapshots every row
// first and marks the era only after the commit. Until that boot, a row with a NULL def_mac is
// accepted as "pre-era" only while the host era record says pre-era (otherwise it is refused) — which
// is what makes this migration safe to apply on a box whose gateway has not started yet.
//
// rollbackSafe: older code never selects either column, so a rollback leaves two harmless leftovers.
import Database from "better-sqlite3";

export const id = "0041-bot-def-mac";

// rollbackSafe: two nullable pi_bot_defs columns; older code ignores them.
export const rollbackSafe = true;

/** "added" | "no-op" | "absent" — never throws on a missing table. */
export function addColumnIfMissing(db, table, column, ddl) {
  const t = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table);
  if (!t) return "absent";
  const have = db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
  if (have.includes(column)) return "no-op";
  db.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${ddl}`).run();
  return "added";
}

export function run({ dbPath, log = () => {} }) {
  const results = [];
  const db = new Database(dbPath);
  db.pragma("busy_timeout = 10000");
  try {
    // DDL matches init-db.js's own addColumnIfMissing calls verbatim — one shape, two rails.
    for (const [column, ddl] of [["def_mac", "TEXT"], ["def_generation", "INTEGER"]]) {
      const r = addColumnIfMissing(db, "pi_bot_defs", column, ddl);
      log(`  pi_bot_defs.${column}: ${r}`);
      results.push(r);
    }
  } finally {
    db.close();
  }
  // pi_bot_defs is a CORE crow.db table (init-db creates it on every instance), so an "absent"
  // read here is a store that predates the bot tables entirely — recording applied is correct:
  // when init-db creates the table it carries both columns in the CREATE body.
  return { applied: true, results };
}