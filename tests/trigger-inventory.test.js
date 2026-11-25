/**
 * THE TRIGGER INVENTORY (round I, item I3).
 *
 * A SQLite trigger runs inside every write to its table with no code of ours in between, and crow.db
 * is bound read-write into every contained bot — so "which triggers does this database have, and are
 * they the ones Crow installs?" is a question nothing else in Crow asks. `servers/gateway/boot/
 * trigger-inventory.js` asks it at boot and hourly over crow.db and tasks.db, comparing NAME AND
 * WHITESPACE-NORMALISED SQL with the set derived from code (`servers/shared/trigger-catalog.js`).
 *
 * This file pins the three answers that matter:
 *   - a FOREIGN trigger (one Crow does not install) is reported once per process — one warning line
 *     naming only the trigger, its table and the database, plus one audit row — and is never dropped;
 *   - a trigger whose NAME Crow installs but whose BODY changed is reported the same way;
 *   - Crow's own set, on a fresh scratch home with init-db + the history migrations, reports NOTHING
 *     (a false positive here would teach the operator to ignore the line).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { createDbClient } from "../servers/db.js";
import { forgetTokenMacKey } from "../servers/shared/token-mac.js";
import { expectedTriggerIndex, normalizeTriggerSql, triggerBlocksIn, unexpectedTriggers } from "../servers/shared/trigger-catalog.js";
import {
  forgetTriggerInventory, runTriggerInventory, startTriggerInventory,
} from "../servers/gateway/boot/trigger-inventory.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

const roots = [];
const SAVED = {};
for (const key of ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH", "CROW_TASKS_DB_PATH"]) SAVED[key] = process.env[key];
after(() => {
  for (const root of roots) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  for (const [key, value] of Object.entries(SAVED)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

/**
 * A fresh scratch instance with the REAL schema: init-db, then migration 0025 (the history capture
 * and guard triggers on crow.db AND tasks.db) — the state an upgraded install is in.
 */
function scratch() {
  const home = mkdtempSync(join(tmpdir(), "crow-trigger-inventory-"));
  roots.push(home);
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, "instance-id"), "0123456789abcdef0123456789abcdef", { mode: 0o600 });
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = join(dataDir, "crow.db");
  delete process.env.CROW_TASKS_DB_PATH;
  forgetTokenMacKey();
  forgetTriggerInventory();
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: process.env, cwd: ROOT, stdio: "pipe", timeout: 120_000,
  });
  const db = createDbClient(process.env.CROW_DB_PATH);
  return { home, dataDir, db, close: () => { try { db.close(); } catch { /* closed */ } } };
}

/** The history migration, so the capture and guard triggers exist in both stores. */
async function withHistory(s) {
  const { run } = await import("../scripts/migrations/0025-item-versions-more.mjs");
  run({ dbPath: process.env.CROW_DB_PATH, tasksDbPath: join(s.dataDir, "tasks.db"), log: () => {} });
  return s;
}

/** One inventory pass with this instance's own handles and a captured log. */
async function inventory() {
  const warns = [];
  const result = await runTriggerInventory({
    dbFactory: (path) => createDbClient(path),
    log: (m) => warns.push(String(m)),
  });
  return { result, warns };
}

async function auditRows(db) {
  const { rows } = await db.execute({
    sql: "SELECT details FROM audit_log WHERE event_type = 'trigger_inventory' ORDER BY id",
    args: [],
  });
  return rows.map((row) => JSON.parse(String(row.details)));
}

test("I3: the catalogue derives Crow's own triggers from code (history, FTS, bundles)", () => {
  const index = expectedTriggerIndex();
  // The history layer's three capture triggers on pi_bot_defs and its three append-only guards.
  for (const name of ["hist_pi_bot_defs_ai", "hist_pi_bot_defs_au", "hist_pi_bot_defs_ad",
    "hist_item_versions_guard_bi", "hist_item_versions_guard_au", "hist_item_versions_guard_ad"]) {
    assert.ok(index.has(name), `${name} is expected`);
  }
  // init-db's FTS triggers and the contact_groups uid trigger, lifted from the file's own SQL.
  for (const name of ["memories_ai", "memories_au", "memories_ad", "sources_ai", "blog_posts_au",
    "glasses_photos_ai", "contact_groups_group_uid_ai"]) {
    assert.ok(index.has(name), `${name} is expected`);
  }
  // A bundle's own trigger text is expected too (the KB bundle owns kb_articles).
  assert.ok(index.has("kb_articles_ai"), "a bundle-installed FTS trigger is expected");
  assert.ok(index.has("ramble_marks_ai"), "so is another bundle's");
  // …and a name nobody installs is not.
  assert.equal(index.has("spy_ai"), false);

  // The comparison is name AND whitespace-normalised SQL: a source block re-indented is the same
  // trigger, a body that changed is not.
  const blocks = triggerBlocksIn("CREATE TRIGGER IF NOT EXISTS t_ai AFTER INSERT ON t BEGIN\n  SELECT 1;\nEND;");
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].name, "t_ai");
  assert.equal(blocks[0].table, "t");
  assert.equal(normalizeTriggerSql(blocks[0].sql), "CREATE TRIGGER t_ai AFTER INSERT ON t BEGIN SELECT 1; END");
  assert.equal(normalizeTriggerSql("  a\n\t b  ;  "), "a b");
});

test("J3: a name-only catalogue entry must still be the trigger it describes (its table, and `ON <table>` in its body)", () => {
  // A bundle trigger built by JS interpolation cannot be reconstructed from source, so the catalogue
  // accepts it BY NAME (`sqlSource: "name-only"`) — the name alone must not be enough (item J3): a
  // same-named trigger on ANOTHER table, or one whose body no longer fires on its own table, is a
  // trigger Crow did not install as it now stands and is reported.
  const expected = new Map([[
    "interp_ai",
    { table: "kb_articles", sql: null, sqlSource: "name-only", source: "bundles/x/server/y.js" },
  ]]);
  const row = (table, sql) => [{ name: "interp_ai", tbl_name: table, sql }];
  const body = "CREATE TRIGGER interp_ai AFTER INSERT ON kb_articles BEGIN "
    + "INSERT INTO kb_articles_fts(rowid) VALUES (new.id); END";
  assert.deepEqual(unexpectedTriggers(row("kb_articles", body), expected), [], "the trigger as installed is accepted");
  assert.deepEqual(unexpectedTriggers(row("KB_ARTICLES", body), expected), [],
    "the table name's case does not make it another table");
  assert.deepEqual(
    unexpectedTriggers(row("some_other_table", body), expected),
    [{ name: "interp_ai", table: "some_other_table", reason: "foreign" }],
    "the same name on another table is not that bundle's trigger",
  );
  assert.deepEqual(
    unexpectedTriggers(row("kb_articles", "CREATE TRIGGER interp_ai AFTER INSERT ON other_table BEGIN SELECT 1; END"), expected),
    [{ name: "interp_ai", table: "kb_articles", reason: "body-changed" }],
    "a body that fires on another table is a body somebody changed",
  );
  // A quoted identifier is the same table (the bundle may quote it).
  assert.deepEqual(
    unexpectedTriggers(row("kb_articles", "CREATE TRIGGER interp_ai AFTER INSERT ON \"kb_articles\" BEGIN SELECT 1; END"), expected),
    [],
  );
});

test("I3: a fresh Crow home (init-db + history) reports NOTHING for either store", async () => {
  const s = await withHistory(scratch());
  try {
    const { result, warns } = await inventory();
    assert.deepEqual(result.crow, [], "crow.db's triggers are all Crow's own");
    assert.deepEqual(result.tasks, [], "and so are tasks.db's");
    assert.deepEqual(result.findings, []);
    assert.deepEqual(warns, [], `no line for a healthy store, got ${warns.join(" | ")}`);
    assert.deepEqual(await auditRows(s.db), [], "and no audit row");
  } finally {
    s.close();
  }
});

test("I3: a foreign trigger is reported ONCE (line + audit row), and never dropped", async () => {
  const s = await withHistory(scratch());
  try {
    await s.db.execute({ sql: "CREATE TABLE spy (id INTEGER PRIMARY KEY, body TEXT)", args: [] });
    await s.db.execute({
      sql: "CREATE TRIGGER spy_ai AFTER INSERT ON spy BEGIN UPDATE spy SET body = 'rewritten'; END",
      args: [],
    });

    const first = await inventory();
    const lines = first.warns.filter((m) => m.includes("[trigger-inventory]"));
    assert.deepEqual(lines, ["[trigger-inventory] foreign trigger spy_ai on spy in crow.db"], first.warns.join(" | "));
    assert.deepEqual(first.result.crow.map((t) => t.name), ["spy_ai"]);
    assert.equal(first.result.crow[0].reason, "foreign");

    // The audit row: an existing audit table, one row, naming the trigger — no bell, no user text.
    const audited = await auditRows(s.db);
    assert.equal(audited.length, 1);
    assert.deepEqual(audited[0], { db: "crow.db", trigger: "spy_ai", table: "spy", reason: "foreign" });

    // A second pass in the same process says nothing more (the finding was already reported), and
    // writes no second audit row — an hourly pass must not repeat itself.
    const second = await inventory();
    assert.deepEqual(second.warns.filter((m) => m.includes("[trigger-inventory]")), []);
    assert.equal((await auditRows(s.db)).length, 1);

    // Never dropped: the trigger is exactly as it was.
    const { rows } = await s.db.execute({
      sql: "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'spy_ai'", args: [],
    });
    assert.equal(rows.length, 1);
    assert.match(String(rows[0].sql), /rewritten/);
  } finally {
    s.close();
  }
});

test("I3: a Crow trigger whose BODY changed is reported as well (and a changed body again re-reports)", async () => {
  const s = await withHistory(scratch());
  try {
    // A real Crow trigger — `hist_pi_bot_defs_au` (migration 0025) — rewritten with the same name and a
    // different body.
    await s.db.execute({ sql: "DROP TRIGGER hist_pi_bot_defs_au", args: [] });
    await s.db.execute({
      sql: "CREATE TRIGGER hist_pi_bot_defs_au AFTER UPDATE ON pi_bot_defs WHEN 0 BEGIN SELECT 1; END",
      args: [],
    });
    const first = await inventory();
    const lines = first.warns.filter((m) => m.includes("[trigger-inventory]"));
    assert.equal(lines.length, 1, first.warns.join(" | "));
    assert.match(lines[0], /^\[trigger-inventory\] foreign trigger hist_pi_bot_defs_au on pi_bot_defs in crow\.db \(body changed\)$/);
    assert.equal(first.result.crow[0].reason, "body-changed");

    // A DIFFERENT body is a new fact: reported again.
    await s.db.execute({ sql: "DROP TRIGGER hist_pi_bot_defs_au", args: [] });
    await s.db.execute({
      sql: "CREATE TRIGGER hist_pi_bot_defs_au AFTER UPDATE ON pi_bot_defs WHEN 0 BEGIN SELECT 2; END",
      args: [],
    });
    const second = await inventory();
    assert.equal(second.warns.filter((m) => m.includes("[trigger-inventory]")).length, 1);
    assert.equal((await auditRows(s.db)).length, 2);
  } finally {
    s.close();
  }
});

test("I3: tasks.db is covered too, and its finding is audited into crow.db", async () => {
  const s = await withHistory(scratch());
  try {
    const tasks = createDbClient(join(s.dataDir, "tasks.db"));
    try {
      await tasks.execute({ sql: "CREATE TABLE card_spy (id INTEGER PRIMARY KEY)", args: [] });
      await tasks.execute({
        sql: "CREATE TRIGGER card_spy_ai AFTER INSERT ON card_spy BEGIN SELECT 1; END", args: [],
      });
    } finally {
      try { tasks.close(); } catch { /* closed */ }
    }
    const { result, warns } = await inventory();
    assert.deepEqual(result.crow, [], "crow.db stays clean");
    assert.deepEqual(result.tasks.map((t) => t.name), ["card_spy_ai"]);
    assert.ok(warns.some((m) => m === "[trigger-inventory] foreign trigger card_spy_ai on card_spy in tasks.db"));
    const audited = await auditRows(s.db);
    assert.deepEqual(audited, [{ db: "tasks.db", trigger: "card_spy_ai", table: "card_spy", reason: "foreign" }],
      "the card store's finding lands in crow.db's audit log (tasks.db has none)");
  } finally {
    s.close();
  }
});

test("I3: the hourly timer is unref'd, and a failing pass never throws", async () => {
  forgetTriggerInventory();
  const warns = [];
  const started = startTriggerInventory({
    dbFactory: () => { throw new Error("no database today"); },
    intervalMs: 60_000,
    immediate: false,
    log: (m) => warns.push(String(m)),
  });
  try {
    assert.equal(typeof started.timer?.unref, "function", "the interval can be unref'd");
    assert.equal(started.timer.hasRef?.(), false, "and it IS unref'd (it must never hold the process open)");
    const result = await started.cycle();
    assert.deepEqual(result, { crow: [], tasks: [], findings: [] }, "an unopenable store is reported, not thrown");
    assert.ok(warns.some((m) => m.includes("crow.db could not be opened")), warns.join(" | "));
  } finally {
    started.stop();
  }
});