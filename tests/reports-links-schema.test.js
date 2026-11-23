// 0039-reports-links: Crow Recurring Reports' reader half on both rails, init-db.js's "reports links
// tables" block plus its reports.comment_window_runs ALTER, and this numbered migration, both built from
// REPORTS_LINKS_DDL and REPORTS_COMMENT_WINDOW_COLUMN (servers/shared/reports-schema.js):
// report_link_tokens (the per-recipient, per-run link, stored only as its token hash) and
// report_recipient_comments (what a reader wrote through that link). Additive, no SCHEMA_GENERATION
// bump. Both tables are local-only: a token is a way into one report and a comment is somebody's words
// about it, and a report never replicates to a paired instance. The earlier reports constants
// (REPORTS_DDL from 0031 through REPORTS_STEPS_DDL from 0035) are untouched, because those migrations
// execute them and their approved shapes stay as they are.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import * as mod from "../scripts/migrations/0039-reports-links.mjs";
import { discoverMigrations } from "../scripts/migrations/runner.mjs";
import {
  REPORTS_COMMENT_WINDOW_COLUMN, REPORTS_DDL, REPORTS_LINKS_DDL, REPORTS_LINKS_TABLES,
} from "../servers/shared/reports-schema.js";

const { run, id } = mod;
const REPO = new URL("..", import.meta.url).pathname;
const SYNC = await import("../servers/sharing/instance-sync.js");

/** The five indexes the plan fixes, with the key each one covers. */
const INDEXES = Object.freeze({
  idx_report_link_tokens_recipient: /report_link_tokens\(recipient_id\)/,
  idx_report_link_tokens_report: /report_link_tokens\(report_id\)/,
  idx_report_link_tokens_send: /report_link_tokens\(send_id\)/,
  idx_report_recipient_comments_thread: /report_recipient_comments\(thread_id\)/,
  idx_report_recipient_comments_report: /report_recipient_comments\(report_id, recipient_id\)/,
});

/** The two tables' columns, in the order the plan fixes them (a mint stores its version on the row). */
const COLUMNS = Object.freeze({
  report_link_tokens: [
    "id", "report_id", "recipient_id", "run_id", "send_id", "artifact_id", "version_n", "token_hash",
    "scope", "approval_nonce", "created_at", "revoked_at", "expires_at",
  ],
  report_recipient_comments: [
    "comment_id", "thread_id", "report_id", "recipient_id", "run_id", "via", "created_at",
  ],
});

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

/** A reports table in the shape 0031 shipped: REPORTS_DDL, with no comment_window_runs column yet. */
function oldReportsTable(dbPath, { rows = [] } = {}) {
  const db = new Database(dbPath);
  try {
    db.exec(REPORTS_DDL);
    const insert = db.prepare(`INSERT INTO reports
      (id, project_id, owner, title, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`);
    for (const row of rows) insert.run(...row);
  } finally {
    db.close();
  }
  return dbPath;
}

/** The DB scripts/init-db.js builds on its own rail, in a throwaway data dir. */
let initDir = null;
function initDbDir() {
  if (!initDir) {
    initDir = tmp("reports-links-init-");
    runInitDb(initDir);
  }
  return initDir;
}

/** Run init-db.js against one data dir (twice in one test, so it must be callable repeatedly). */
function runInitDb(dir) {
  mkdirSync(dir, { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"],
    { env: { ...process.env, CROW_DATA_DIR: dir, CROW_DB_PATH: "" }, stdio: "pipe", cwd: REPO });
  return join(dir, "crow.db");
}

/** Every sqlite_master object that belongs to the link tables (the tables and their indexes). */
function linkObjects(dbPath) {
  const d = new Database(dbPath, { readonly: true });
  try {
    return d.prepare(
      `SELECT type, name, tbl_name, sql FROM sqlite_master
       WHERE tbl_name IN (${REPORTS_LINKS_TABLES.map(() => "?").join(", ")})
       ORDER BY type, name`,
    ).all(...REPORTS_LINKS_TABLES);
  } finally {
    d.close();
  }
}

/** The `reports` row itself: an ALTER rewrites the stored CREATE TABLE text, so it is compared too. */
function reportsObject(dbPath) {
  const d = new Database(dbPath, { readonly: true });
  try {
    return d.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name = 'reports'").get();
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

function indexNames(dbPath) {
  const d = new Database(dbPath, { readonly: true });
  try {
    return d.prepare(
      `SELECT name FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL
        AND tbl_name IN (${REPORTS_LINKS_TABLES.map(() => "?").join(", ")})
       ORDER BY name`,
    ).all(...REPORTS_LINKS_TABLES).map((r) => r.name);
  } finally {
    d.close();
  }
}

function tableNames(dbPath) {
  const d = new Database(dbPath, { readonly: true });
  try {
    return d.prepare(
      `SELECT name FROM sqlite_master WHERE type = 'table'
        AND name IN (${REPORTS_LINKS_TABLES.map(() => "?").join(", ")})
       ORDER BY name`,
    ).all(...REPORTS_LINKS_TABLES).map((r) => r.name);
  } finally {
    d.close();
  }
}

function hasColumn(dbPath, table, column) {
  return Object.hasOwn(columns(dbPath, table), column);
}

test("the module id matches its filename", () => {
  assert.equal(id, "0039-reports-links");
  assert.ok(discoverMigrations(join(REPO, "scripts", "migrations"))
    .some((p) => p.endsWith("/0039-reports-links.mjs")));
  assert.equal(mod.rollbackSafe, true);
});

test("discoverMigrations sorts 0039 right after 0038", () => {
  const found = discoverMigrations(join(REPO, "scripts", "migrations")).map((p) => p.split("/").pop());
  const at = found.indexOf("0039-reports-links.mjs");
  assert.ok(at > 0, `0039 is discovered; found ${JSON.stringify(found.slice(-3))}`);
  assert.equal(found[at - 1], "0038-message-drafts-chat-thread.mjs", "0039 sorts immediately after 0038");
});

test("on an empty DB the migration creates both tables and the five named indexes", () => {
  const dbPath = freshDb("reports-links-fresh-");
  const result = run({ dbPath, log: () => {} });
  assert.equal(result.applied, true);
  assert.deepEqual(tableNames(dbPath), [...REPORTS_LINKS_TABLES].sort());
  assert.deepEqual(indexNames(dbPath), Object.keys(INDEXES).sort(), "exactly the five named indexes");

  const objects = new Map(linkObjects(dbPath).map((o) => [o.name, o]));
  for (const [name, pattern] of Object.entries(INDEXES)) {
    assert.match(objects.get(name).sql, pattern, `${name} covers its key`);
  }

  // No `reports` table here, so the column step says so and still applies the tables.
  assert.ok(result.results.includes("reports: absent"), JSON.stringify(result.results));
  assert.ok(result.results.includes("report_link_tokens: ensured"));
  assert.ok(result.results.includes("report_recipient_comments: ensured"));
});

test("the columns are the plan's, in its order, with the approval nonce the review added", () => {
  const dbPath = freshDb("reports-links-columns-");
  run({ dbPath, log: () => {} });

  const tokens = columns(dbPath, "report_link_tokens");
  assert.deepEqual(Object.keys(tokens), COLUMNS.report_link_tokens, "the exact column list, in order");
  assert.equal(tokens.id.pk, 1, "the row id is the primary key");
  for (const required of [
    "report_id", "recipient_id", "run_id", "artifact_id", "version_n", "token_hash", "scope",
    "approval_nonce", "created_at", "expires_at",
  ]) {
    assert.equal(tokens[required].notnull, 1, `${required} is required`);
  }
  for (const nullable of ["send_id", "revoked_at"]) {
    assert.equal(tokens[nullable].notnull, 0, `${nullable} starts NULL`);
  }
  assert.equal(tokens.version_n.type, "INTEGER", "the version is a number, not a name");
  const unique = new Database(dbPath, { readonly: true });
  let tableSql = "";
  let uniqueKeys = [];
  try {
    tableSql = unique.prepare(
      "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'report_link_tokens'").get().sql;
    // The inline UNIQUE and nothing else over the hash: the only other unique key is the primary key.
    uniqueKeys = unique.prepare("PRAGMA index_list(report_link_tokens)").all()
      .filter((index) => Number(index.unique) === 1)
      .map((index) => unique.prepare(`PRAGMA index_info(${JSON.stringify(index.name)})`).all()
        .map((column) => column.name).join(","))
      .sort();
  } finally {
    unique.close();
  }
  assert.deepEqual(uniqueKeys, ["id", "token_hash"],
    "the hash is UNIQUE inline, and no unique key covers the old (report, run, recipient) triple");
  assert.match(tableSql, /token_hash TEXT NOT NULL UNIQUE/, "no second row can repeat a token hash");
  for (const name of ["report_id", "recipient_id", "run_id", "artifact_id", "token_hash", "scope",
    "approval_nonce"]) {
    assert.equal(tokens[name].type, "TEXT", `${name} is text`);
  }

  const comments = columns(dbPath, "report_recipient_comments");
  assert.deepEqual(Object.keys(comments), COLUMNS.report_recipient_comments,
    "the exact column list, in order");
  assert.equal(comments.comment_id.pk, 1, "the artifacts comment id is the primary key");
  assert.equal(comments.comment_id.type, "INTEGER", "the bundle's comment ids are integers");
  for (const required of ["thread_id", "report_id", "recipient_id", "run_id", "via", "created_at"]) {
    assert.equal(comments[required].notnull, 1, `${required} is required`);
  }
  assert.equal(comments.thread_id.type, "TEXT", "the thread id is held as text");
  for (const column of Object.values(comments)) {
    assert.equal(column.dflt_value, null, "no default: this table's rows are written by one module");
  }
});

test("the unique keys really refuse a second row", () => {
  const dbPath = freshDb("reports-links-unique-");
  run({ dbPath, log: () => {} });
  const db = new Database(dbPath);
  try {
    const insert = db.prepare(`INSERT INTO report_link_tokens
      (id, report_id, recipient_id, run_id, send_id, artifact_id, version_n, token_hash, scope,
       approval_nonce, created_at, expires_at)
      VALUES (?, 'rpt-0011223344556677', ?, 'rrn-0011223344556677', 'rsd-0011223344556677',
              'art-0011223344556677', 1, ?, 'comment', ?, 1, 99)`);
    insert.run("rlt-0011223344556677", "rrc-0011223344556677", "a".repeat(64), "e".repeat(32));
    assert.throws(() => insert.run("rlt-8899aabbccddeeff", "rrc-8899aabbccddeeff", "a".repeat(64),
      "e".repeat(32)), /UNIQUE/, "one token hash is one row");
    // Two live tokens for one (report, run, recipient) are allowed by the SHAPE: a mint is per send and
    // the mint itself revokes the earlier rows of the send, so the table carries no key over that triple.
    insert.run("rlt-8899aabbccddeeff", "rrc-0011223344556677", "b".repeat(64), "e".repeat(32));
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM report_link_tokens").get().n, 2);

    // A comment is keyed by its artifacts comment id, and one reader may leave several on one run.
    const comment = db.prepare(`INSERT INTO report_recipient_comments
      (comment_id, thread_id, report_id, recipient_id, run_id, via, created_at)
      VALUES (?, ?, 'rpt-0011223344556677', 'rrc-0011223344556677', 'rrn-0011223344556677', 'link', 1)`);
    comment.run(1, "7");
    comment.run(2, "7");
    assert.throws(() => comment.run(1, "9"), /UNIQUE/, "the artifacts comment id is the primary key");
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM report_recipient_comments").get().n, 2);
  } finally {
    db.close();
  }
});

test("the shape matches what init-db produces, once both rails are applied", () => {
  const master = join(initDbDir(), "crow.db");
  assert.deepEqual(tableNames(master), [...REPORTS_LINKS_TABLES].sort(),
    "init-db created both link tables");
  assert.equal(hasColumn(master, "reports", "comment_window_runs"), true,
    "init-db added the comment window column");

  // A fresh DB with the reports table in 0031's shape, then 0039: that is the same pair of steps
  // init-db runs, so every object must come out byte for byte the same.
  const dbPath = oldReportsTable(freshDb("reports-links-shape-"));
  assert.equal(run({ dbPath, log: () => {} }).applied, true);

  assert.deepEqual(linkObjects(dbPath), linkObjects(master), "the same sqlite_master rows, byte for byte");
  assert.deepEqual(reportsObject(dbPath), reportsObject(master),
    "the altered reports table reads the same on both rails");
  for (const table of REPORTS_LINKS_TABLES) {
    assert.deepEqual(tableInfo(dbPath, table), tableInfo(master, table),
      `${table} has the same columns on both rails`);
  }
  assert.deepEqual(tableInfo(dbPath, "reports"), tableInfo(master, "reports"));
});

test("the comment window column defaults to four and is required", () => {
  const master = join(initDbDir(), "crow.db");
  const report = columns(master, "reports").comment_window_runs;
  assert.equal(report.dflt_value, "4");
  assert.equal(report.notnull, 1);
  assert.equal(report.type, "INTEGER");
});

test("a reports table without the column gains it from the migration, and rows get four", () => {
  const dbPath = oldReportsTable(freshDb("reports-links-old-migration-"), {
    rows: [["rpt-0011223344556677", 1, "owner", "Weekly listings", 1, 1]],
  });
  assert.equal(hasColumn(dbPath, "reports", "comment_window_runs"), false, "the old shape, as 0031 left it");

  const result = run({ dbPath, log: () => {} });
  assert.equal(result.applied, true);
  assert.ok(result.results.includes("reports.comment_window_runs: added"), JSON.stringify(result.results));
  assert.equal(hasColumn(dbPath, "reports", "comment_window_runs"), true);
  const db = new Database(dbPath, { readonly: true });
  try {
    assert.equal(db.prepare("SELECT comment_window_runs FROM reports").get().comment_window_runs, 4,
      "the existing row took the default");
  } finally {
    db.close();
  }
});

test("a reports table without the column gains it from init-db, and rows get four", () => {
  const dir = tmp("reports-links-old-init-");
  const dbPath = oldReportsTable(join(dir, "crow.db"), {
    rows: [["rpt-0011223344556677", 1, "owner", "Weekly listings", 1, 1]],
  });
  assert.equal(hasColumn(dbPath, "reports", "comment_window_runs"), false);

  runInitDb(dir);
  assert.equal(hasColumn(dbPath, "reports", "comment_window_runs"), true,
    "init-db's ensureSchemaColumn added it");
  const db = new Database(dbPath, { readonly: true });
  try {
    assert.equal(db.prepare("SELECT comment_window_runs FROM reports").get().comment_window_runs, 4);
  } finally {
    db.close();
  }
});

test("init-db twice is fine, and running the migration over its result changes nothing", () => {
  const dir = tmp("reports-links-init-twice-");
  const dbPath = runInitDb(dir);
  const before = { links: linkObjects(dbPath), reports: reportsObject(dbPath) };
  runInitDb(dir);
  assert.deepEqual({ links: linkObjects(dbPath), reports: reportsObject(dbPath) }, before,
    "a second init-db changes nothing");

  const result = run({ dbPath, log: () => {} });
  assert.equal(result.applied, true);
  assert.ok(result.results.includes("reports.comment_window_runs: present"), JSON.stringify(result.results));
  assert.deepEqual({ links: linkObjects(dbPath), reports: reportsObject(dbPath) }, before,
    "the migration over an init-db'd store changes nothing either");
});

test("run is idempotent and keeps a row", () => {
  const dbPath = oldReportsTable(freshDb("reports-links-idem-"));
  const first = run({ dbPath, log: () => {} });
  const db = new Database(dbPath);
  db.prepare(`INSERT INTO report_link_tokens
    (id, report_id, recipient_id, run_id, send_id, artifact_id, version_n, token_hash, scope,
     approval_nonce, created_at, expires_at)
    VALUES ('rlt-0011223344556677', 'rpt-0011223344556677', 'rrc-0011223344556677',
            'rrn-0011223344556677', 'rsd-0011223344556677', 'art-0011223344556677', 1, ?, 'view', ?, 1, 99)`)
    .run("c".repeat(64), "e".repeat(32));
  db.prepare(`INSERT INTO report_recipient_comments
    (comment_id, thread_id, report_id, recipient_id, run_id, via, created_at)
    VALUES (12, '7', 'rpt-0011223344556677', 'rrc-0011223344556677', 'rrn-0011223344556677', 'link', 1)`)
    .run();
  db.close();
  const before = { links: linkObjects(dbPath), reports: reportsObject(dbPath) };
  const second = run({ dbPath, log: () => {} });
  assert.deepEqual({ links: linkObjects(dbPath), reports: reportsObject(dbPath) }, before,
    "a second run changes nothing");
  const check = new Database(dbPath, { readonly: true });
  const kept = {
    tokens: check.prepare("SELECT count(*) AS n, max(scope) AS scope FROM report_link_tokens").get(),
    comments: check.prepare("SELECT count(*) AS n, max(thread_id) AS thread FROM report_recipient_comments")
      .get(),
    window: check.prepare("SELECT count(*) AS n FROM reports").get(),
  };
  check.close();
  assert.equal(first.applied, true);
  assert.equal(second.applied, true);
  assert.deepEqual(kept, {
    tokens: { n: 1, scope: "view" },
    comments: { n: 1, thread: "7" },
    window: { n: 0 },
  });
});

test("both link tables are local-only and never synced", () => {
  for (const t of REPORTS_LINKS_TABLES) {
    assert.ok(SYNC.LOCAL_ONLY_TABLES.includes(t), `${t} is in LOCAL_ONLY_TABLES`);
    assert.ok(!SYNC.SYNCED_TABLES.includes(t), `${t} is not in SYNCED_TABLES`);
    assert.equal(SYNC.shouldSyncRowForTest(t, { report_id: "rpt-0011223344556677" }), false);
  }
  assert.doesNotThrow(() => SYNC.assertLocalOnlyDisjoint(SYNC.SYNCED_TABLES, SYNC.LOCAL_ONLY_TABLES));
  assert.throws(() => SYNC.assertLocalOnlyDisjoint(["report_link_tokens"], SYNC.LOCAL_ONLY_TABLES),
    /local-only/);
});

test("init-db runs the same DDL through initTable, right after the steps block", () => {
  const init = readFileSync(new URL("../scripts/init-db.js", import.meta.url), "utf8");
  assert.match(init,
    /import \{[^}]*\bREPORTS_LINKS_DDL\b[^}]*\} from "\.\.\/servers\/shared\/reports-schema\.js";/);
  assert.ok(init.includes('await initTable("reports links tables", REPORTS_LINKS_DDL);'));
  assert.ok(init.indexOf('await initTable("reports links tables", REPORTS_LINKS_DDL);')
    > init.indexOf('await initTable("reports steps tables", REPORTS_STEPS_DDL);'),
  "the links block follows the steps block");
  // The column comes after the tables, from the one constant, so the two rails cannot drift.
  assert.ok(init.indexOf("await ensureSchemaColumn(REPORTS_COMMENT_WINDOW_COLUMN);")
    > init.indexOf('await initTable("reports links tables", REPORTS_LINKS_DDL);'),
  "the ALTER follows the links block");
  assert.match(init, /\bREPORTS_COMMENT_WINDOW_COLUMN\b[^;]*\} from "\.\.\/servers\/shared\/reports-schema\.js";/);
});

test("the column is its own constant and the ALTER is not in the DDL string", () => {
  assert.deepEqual({ ...REPORTS_COMMENT_WINDOW_COLUMN }, {
    table: "reports",
    column: "comment_window_runs",
    ddl: "ALTER TABLE reports ADD COLUMN comment_window_runs INTEGER NOT NULL DEFAULT 4",
  });
  assert.ok(Object.isFrozen(REPORTS_COMMENT_WINDOW_COLUMN));
  assert.doesNotMatch(REPORTS_LINKS_DDL, /ALTER TABLE/i, "0031's table shape stays what it is");
  assert.doesNotMatch(REPORTS_DDL, /comment_window_runs/,
    "the late column is never folded into the DDL 0031 executes");
  const migration = readFileSync(
    new URL("../scripts/migrations/0039-reports-links.mjs", import.meta.url), "utf8");
  assert.match(migration, /import \{[^}]*REPORTS_COMMENT_WINDOW_COLUMN[^}]*\} from/s);
});

test("there is no CHECK and no foreign key (validated in the reports modules)", () => {
  assert.doesNotMatch(REPORTS_LINKS_DDL, /CHECK/i);
  assert.doesNotMatch(REPORTS_LINKS_DDL, /REFERENCES/i);
  assert.equal((REPORTS_LINKS_DDL.match(/CREATE TABLE/g) ?? []).length, 2);
  assert.equal((REPORTS_LINKS_DDL.match(/CREATE (UNIQUE )?INDEX/g) ?? []).length, 5);
  assert.equal((REPORTS_LINKS_DDL.match(/IF NOT EXISTS/g) ?? []).length,
    (REPORTS_LINKS_DDL.match(/CREATE (TABLE|UNIQUE INDEX|INDEX)/g) ?? []).length,
    "every object is created IF NOT EXISTS");
  assert.doesNotMatch(REPORTS_LINKS_DDL, /\bDROP\s+(TABLE|INDEX|TRIGGER|VIEW|COLUMN)\b/i);
  assert.doesNotMatch(REPORTS_LINKS_DDL, /\bDELETE\s+FROM\b/i);
  const migration = readFileSync(
    new URL("../scripts/migrations/0039-reports-links.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(migration, /\bDROP\b/);
  assert.doesNotMatch(migration, /\bDELETE\b/);
});

test("the earlier reports DDL constants are left exactly as they were", () => {
  const schema = readFileSync(new URL("../servers/shared/reports-schema.js", import.meta.url), "utf8");
  for (const [from, to] of [
    ["export const REPORTS_DDL", "export const REPORTS_TABLES"],
    ["export const REPORTS_RUNS_DDL", "export const REPORTS_RUNS_TABLES"],
    ["export const REPORTS_VERSIONS_DDL", "export const REPORTS_VERSIONS_TABLES"],
    ["export const REPORTS_SEND_DDL", "export const REPORTS_SEND_TABLES"],
    ["export const REPORTS_STEPS_DDL", "export const REPORTS_STEPS_TABLES"],
  ]) {
    const block = schema.slice(schema.indexOf(from), schema.indexOf(to));
    assert.doesNotMatch(block, /report_link_tokens|report_recipient_comments|comment_window_runs/,
      `${from} is untouched`);
  }
});