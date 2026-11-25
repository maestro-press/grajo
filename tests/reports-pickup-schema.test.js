// 0042-reports-pickup: Crow Recurring Reports' pickup half on both rails, init-db.js's "reports pickup
// tables" block plus this numbered migration, both built from REPORTS_PICKUP_DDL
// (servers/shared/reports-schema.js): report_pickups, one row per pickup (the batch of comment and thread
// ids it is about, when it started and ended, the minutes its bot turn spent and how it ended). Additive,
// no SCHEMA_GENERATION bump. The table is local-only: a pickup names the comments a report's readers left,
// and a report never replicates to a paired instance. A pickup row id uses `rpu-`, never `rpk_`, which is
// the per-turn token's prefix. The earlier reports constants are untouched, because those migrations
// execute them and their approved shapes stay as they are.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import * as mod from "../scripts/migrations/0042-reports-pickup.mjs";
import { discoverMigrations } from "../scripts/migrations/runner.mjs";
import { REPORTS_PICKUP_DDL, REPORTS_PICKUP_TABLES } from "../servers/shared/reports-schema.js";

const { run, id } = mod;
const REPO = new URL("..", import.meta.url).pathname;
const SYNC = await import("../servers/sharing/instance-sync.js");

/** The one index the pickup table is read by: a report's pickups, oldest first. */
const INDEXES = Object.freeze({
  idx_report_pickups_report: /report_pickups\(report_id, started_at\)/,
});

/** The table's columns, in the order the plan fixes them. */
const COLUMNS = Object.freeze([
  "id", "report_id", "thread_ids_json", "comment_ids_json", "started_at", "ended_at", "bot_ms", "outcome",
]);

const dirs = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function tmp(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

function freshDb(prefix) {
  const dbPath = join(tmp(prefix), "crow.db");
  new Database(dbPath).close();
  return dbPath;
}

/** Run init-db.js against one data dir (twice in one test, so it must be callable repeatedly). */
function runInitDb(dir) {
  mkdirSync(dir, { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"],
    { env: { ...process.env, CROW_DATA_DIR: dir, CROW_DB_PATH: "" }, stdio: "pipe", cwd: REPO });
  return join(dir, "crow.db");
}

/** The DB scripts/init-db.js builds on its own rail, in a throwaway data dir. */
let initDir = null;
function initDbDir() {
  if (!initDir) {
    initDir = tmp("reports-pickup-init-");
    runInitDb(initDir);
  }
  return initDir;
}

/** Every sqlite_master object that belongs to the pickup table (the table and its indexes). */
function pickupObjects(dbPath) {
  const d = new Database(dbPath, { readonly: true });
  try {
    return d.prepare(
      `SELECT type, name, tbl_name, sql FROM sqlite_master
       WHERE tbl_name IN (${REPORTS_PICKUP_TABLES.map(() => "?").join(", ")})
       ORDER BY type, name`,
    ).all(...REPORTS_PICKUP_TABLES);
  } finally {
    d.close();
  }
}

function tableInfo(dbPath, table) {
  const d = new Database(dbPath, { readonly: true });
  try {
    return d.prepare(`PRAGMA table_info(${table})`).all();
  } finally {
    d.close();
  }
}

function columns(dbPath, table) {
  return Object.fromEntries(tableInfo(dbPath, table).map((c) => [c.name, c]));
}

function tableNames(dbPath) {
  const d = new Database(dbPath, { readonly: true });
  try {
    return d.prepare(
      `SELECT name FROM sqlite_master WHERE type = 'table'
        AND name IN (${REPORTS_PICKUP_TABLES.map(() => "?").join(", ")})
       ORDER BY name`,
    ).all(...REPORTS_PICKUP_TABLES).map((r) => r.name);
  } finally {
    d.close();
  }
}

test("the module id matches its filename", () => {
  assert.equal(id, "0042-reports-pickup");
  assert.ok(discoverMigrations(join(REPO, "scripts", "migrations"))
    .some((p) => p.endsWith("/0042-reports-pickup.mjs")));
  assert.equal(mod.rollbackSafe, true);
});

test("discoverMigrations sorts it right after the bot-def-mac migration", () => {
  const found = discoverMigrations(join(REPO, "scripts", "migrations")).map((p) => p.split("/").pop());
  const at = found.indexOf("0042-reports-pickup.mjs");
  assert.ok(at > 0, `0042 is discovered; found ${JSON.stringify(found.slice(-3))}`);
  assert.equal(found[at - 1], "0041-bot-def-mac.mjs", "0042 sorts immediately after 0041");
  assert.equal(found[at + 1], undefined, "0042 is the newest migration");
});

test("on an empty DB the migration creates the table and its index", () => {
  const dbPath = freshDb("reports-pickup-fresh-");
  const result = run({ dbPath, log: () => {} });
  assert.equal(result.applied, true);
  assert.deepEqual(tableNames(dbPath), [...REPORTS_PICKUP_TABLES].sort());
  assert.deepEqual(result.results, ["report_pickups: ensured"]);

  const objects = new Map(pickupObjects(dbPath).map((o) => [o.name, o]));
  for (const [name, pattern] of Object.entries(INDEXES)) {
    assert.ok(objects.has(name), `${name} exists`);
    assert.match(objects.get(name).sql, pattern, `${name} covers its key`);
  }
  assert.equal(objects.get("report_pickups").type, "table");
});

test("the migration succeeds on a DB with no reports table, and creates no reports table", () => {
  const dbPath = freshDb("reports-pickup-no-reports-");
  const db = new Database(dbPath);
  const before = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all()
    .map((r) => r.name);
  db.close();
  assert.deepEqual(before, [], "nothing but the empty sqlite file");

  const result = run({ dbPath, log: () => {} });
  assert.equal(result.applied, true, "no deferral: the pickup table does not depend on `reports`");
  const after = new Database(dbPath, { readonly: true });
  try {
    const names = after.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all()
      .map((r) => r.name);
    assert.deepEqual(names, ["report_pickups"], "the pickup table only, no reports family");
    assert.equal(after.prepare(
      "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'reports'").get(), undefined,
    "the migration must not conjure a reports table");
  } finally {
    after.close();
  }
});

test("the columns are the plan's, in its order, with the time and default shapes the file uses", () => {
  const dbPath = freshDb("reports-pickup-columns-");
  run({ dbPath, log: () => {} });

  const cols = columns(dbPath, "report_pickups");
  assert.deepEqual(Object.keys(cols), COLUMNS, "the exact column list, in order");
  assert.equal(cols.id.pk, 1, "the row id is the primary key");
  assert.equal(cols.id.type, "TEXT", "the row id is text (an `rpu-…` value, never an `rpk_` token)");
  for (const required of ["report_id", "thread_ids_json", "comment_ids_json", "started_at", "bot_ms"]) {
    assert.equal(cols[required].notnull, 1, `${required} is required`);
  }
  for (const nullable of ["ended_at", "outcome"]) {
    assert.equal(cols[nullable].notnull, 0, `${nullable} starts NULL`);
  }
  for (const time of ["started_at", "ended_at"]) {
    assert.equal(cols[time].type, "INTEGER", `${time} is epoch ms, like every reports time column`);
  }
  assert.equal(cols.bot_ms.type, "INTEGER");
  assert.equal(cols.bot_ms.dflt_value, "0", "a pickup starts at zero minutes");
  assert.equal(cols.thread_ids_json.dflt_value, "'[]'");
  assert.equal(cols.comment_ids_json.dflt_value, "'[]'");
  const d = new Database(dbPath, { readonly: true });
  try {
    assert.equal(d.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'reports'").get(),
      undefined, "the migration creates no reports table of its own");
  } finally {
    d.close();
  }
});

test("run is idempotent and keeps a row", () => {
  const dbPath = freshDb("reports-pickup-idem-");
  const first = run({ dbPath, log: () => {} });
  const db = new Database(dbPath);
  db.prepare(`INSERT INTO report_pickups
    (id, report_id, thread_ids_json, comment_ids_json, started_at, ended_at, bot_ms, outcome)
    VALUES ('rpu-0011223344556677', 'rpt-0011223344556677', '["7"]', '[12]', 1, 2, 40, 'answered')`).run();
  db.close();
  const before = pickupObjects(dbPath);
  const second = run({ dbPath, log: () => {} });
  assert.deepEqual(pickupObjects(dbPath), before, "a second run changes nothing");
  const check = new Database(dbPath, { readonly: true });
  const kept = check.prepare(
    "SELECT count(*) AS n, max(outcome) AS outcome, max(bot_ms) AS bot_ms FROM report_pickups").get();
  check.close();
  assert.equal(first.applied, true);
  assert.equal(second.applied, true);
  assert.deepEqual(kept, { n: 1, outcome: "answered", bot_ms: 40 });
});

test("the shape matches what init-db produces, once both rails are applied", () => {
  const master = join(initDbDir(), "crow.db");
  assert.deepEqual(tableNames(master), [...REPORTS_PICKUP_TABLES].sort(),
    "init-db created the pickup table");

  const dbPath = freshDb("reports-pickup-shape-");
  assert.equal(run({ dbPath, log: () => {} }).applied, true);

  assert.deepEqual(pickupObjects(dbPath), pickupObjects(master), "the same sqlite_master rows, byte for byte");
  for (const table of REPORTS_PICKUP_TABLES) {
    assert.deepEqual(tableInfo(dbPath, table), tableInfo(master, table),
      `${table} has the same columns on both rails`);
  }
});

test("init-db twice is fine, and running the migration over its result changes nothing", () => {
  const dir = tmp("reports-pickup-init-twice-");
  const dbPath = runInitDb(dir);
  const before = pickupObjects(dbPath);
  runInitDb(dir);
  assert.deepEqual(pickupObjects(dbPath), before, "a second init-db changes nothing");

  const result = run({ dbPath, log: () => {} });
  assert.equal(result.applied, true);
  assert.deepEqual(pickupObjects(dbPath), before, "the migration over an init-db'd store changes nothing either");
});

test("the pickup table is local-only and never synced", () => {
  for (const t of REPORTS_PICKUP_TABLES) {
    assert.ok(SYNC.LOCAL_ONLY_TABLES.includes(t), `${t} is in LOCAL_ONLY_TABLES`);
    assert.ok(!SYNC.SYNCED_TABLES.includes(t), `${t} is not in SYNCED_TABLES`);
    assert.equal(SYNC.shouldSyncRowForTest(t, { report_id: "rpt-0011223344556677" }), false);
  }
  assert.doesNotThrow(() => SYNC.assertLocalOnlyDisjoint(SYNC.SYNCED_TABLES, SYNC.LOCAL_ONLY_TABLES));
  assert.throws(() => SYNC.assertLocalOnlyDisjoint(["report_pickups"], SYNC.LOCAL_ONLY_TABLES), /local-only/);
});

test("init-db runs the same DDL through initTable, right after the comment-window column", () => {
  const init = readFileSync(new URL("../scripts/init-db.js", import.meta.url), "utf8");
  assert.match(init,
    /import \{[^}]*\bREPORTS_PICKUP_DDL\b[^}]*\} from "\.\.\/servers\/shared\/reports-schema\.js";/);
  assert.ok(init.includes('await initTable("reports pickup tables", REPORTS_PICKUP_DDL);'));
  assert.ok(init.indexOf('await initTable("reports pickup tables", REPORTS_PICKUP_DDL);')
    > init.indexOf("await ensureSchemaColumn(REPORTS_COMMENT_WINDOW_COLUMN);"),
  "the pickup block follows the comment-window column");
  assert.ok(init.indexOf('await initTable("reports pickup tables", REPORTS_PICKUP_DDL);')
    < init.indexOf('await initTable("message draft tables", MESSAGE_DRAFTS_DDL);'),
  "and sits with the reports family, before the message drafts block");
});

test("there is no CHECK and no foreign key (outcomes are validated in the modules)", () => {
  assert.doesNotMatch(REPORTS_PICKUP_DDL, /CHECK/i);
  assert.doesNotMatch(REPORTS_PICKUP_DDL, /REFERENCES/i);
  assert.equal((REPORTS_PICKUP_DDL.match(/CREATE TABLE/g) ?? []).length, 1, "one table");
  assert.equal((REPORTS_PICKUP_DDL.match(/CREATE (UNIQUE )?INDEX/g) ?? []).length, 1, "one index");
  assert.equal((REPORTS_PICKUP_DDL.match(/IF NOT EXISTS/g) ?? []).length,
    (REPORTS_PICKUP_DDL.match(/CREATE (TABLE|UNIQUE INDEX|INDEX)/g) ?? []).length,
    "every object is created IF NOT EXISTS");
  assert.doesNotMatch(REPORTS_PICKUP_DDL, /\bDROP\s+(TABLE|INDEX|TRIGGER|VIEW|COLUMN)\b/i);
  assert.doesNotMatch(REPORTS_PICKUP_DDL, /\bDELETE\s+FROM\b/i);
  const migration = readFileSync(
    new URL("../scripts/migrations/0042-reports-pickup.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(migration, /\bDROP\b/);
  assert.doesNotMatch(migration, /\bDELETE\b/);
  assert.match(migration, /import \{[^}]*REPORTS_PICKUP_DDL[^}]*\} from/s);
  assert.equal(Object.isFrozen(REPORTS_PICKUP_TABLES), true);
});

test("the earlier reports DDL constants are left exactly as they were", () => {
  const schema = readFileSync(new URL("../servers/shared/reports-schema.js", import.meta.url), "utf8");
  for (const [from, to] of [
    ["export const REPORTS_DDL", "export const REPORTS_TABLES"],
    ["export const REPORTS_RUNS_DDL", "export const REPORTS_RUNS_TABLES"],
    ["export const REPORTS_VERSIONS_DDL", "export const REPORTS_VERSIONS_TABLES"],
    ["export const REPORTS_SEND_DDL", "export const REPORTS_SEND_TABLES"],
    ["export const REPORTS_STEPS_DDL", "export const REPORTS_STEPS_TABLES"],
    ["export const REPORTS_LINKS_DDL", "export const REPORTS_LINKS_TABLES"],
  ]) {
    const block = schema.slice(schema.indexOf(from), schema.indexOf(to));
    assert.doesNotMatch(block, /report_pickups/, `${from} is untouched`);
  }
});