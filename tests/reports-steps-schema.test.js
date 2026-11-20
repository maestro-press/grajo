// 0035-reports-steps: Crow Recurring Reports' custom-step half on both rails — init-db.js's "reports
// steps tables" block and this numbered migration, both built from REPORTS_STEPS_DDL
// (servers/shared/reports-schema.js): report_custom_steps (one row per report, step key and revision),
// report_assets (one row per named input, with its sha256 and size), report_hosts (one row per report
// and approved site) and report_credentials (one host of one report bound to one keychain row). DDL
// only; additive, no SCHEMA_GENERATION bump. All four tables are local-only: every row describes one
// report, and a report never replicates to a paired instance. The earlier reports constants
// (REPORTS_DDL from 0031, REPORTS_RUNS_DDL from 0032, REPORTS_VERSIONS_DDL from 0033, REPORTS_SEND_DDL
// from 0034) are untouched.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import Database from "better-sqlite3";
import * as mod from "../scripts/migrations/0035-reports-steps.mjs";
import { discoverMigrations } from "../scripts/migrations/runner.mjs";
import { REPORTS_STEPS_DDL, REPORTS_STEPS_TABLES } from "../servers/shared/reports-schema.js";

const { run, id } = mod;
const REPO = new URL("..", import.meta.url).pathname;
const SYNC = await import("../servers/sharing/instance-sync.js");

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

/** The DB scripts/init-db.js builds on its own rail, in a throwaway data dir. */
let initDir = null;
function initDbDir() {
  if (!initDir) {
    initDir = tmp("reports-steps-init-");
    execFileSync(process.execPath, ["scripts/init-db.js"],
      { env: { ...process.env, CROW_DATA_DIR: initDir, CROW_DB_PATH: "" }, stdio: "pipe", cwd: REPO });
  }
  return initDir;
}

/** Every sqlite_master object that belongs to the step tables (the tables and their indexes). */
function stepObjects(dbPath) {
  const d = new Database(dbPath, { readonly: true });
  try {
    return d.prepare(
      `SELECT type, name, tbl_name, sql FROM sqlite_master
       WHERE tbl_name IN (${REPORTS_STEPS_TABLES.map(() => "?").join(", ")})
       ORDER BY type, name`,
    ).all(...REPORTS_STEPS_TABLES);
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
        AND name IN (${REPORTS_STEPS_TABLES.map(() => "?").join(", ")})
       ORDER BY name`,
    ).all(...REPORTS_STEPS_TABLES).map((r) => r.name);
  } finally {
    d.close();
  }
}

test("the module id matches its filename", () => {
  assert.equal(id, "0035-reports-steps");
  assert.ok(discoverMigrations(join(REPO, "scripts", "migrations"))
    .some((p) => p.endsWith("/0035-reports-steps.mjs")));
  assert.equal(mod.rollbackSafe, true);
});

test("the shape matches what init-db produces", () => {
  const master = join(initDbDir(), "crow.db");
  assert.deepEqual(tableNames(master), [...REPORTS_STEPS_TABLES].sort(),
    "init-db created all four step tables");

  const dbPath = freshDb("reports-steps-fresh-");
  assert.equal(run({ dbPath, log: () => {} }).applied, true);

  assert.deepEqual(stepObjects(dbPath), stepObjects(master), "the same sqlite_master rows, byte for byte");
  for (const table of REPORTS_STEPS_TABLES) {
    assert.deepEqual(tableInfo(dbPath, table), tableInfo(master, table),
      `${table} has the same columns on both rails`);
  }
});

test("the columns and the keys are the ones the plan fixes", () => {
  const master = join(initDbDir(), "crow.db");

  const steps = columns(master, "report_custom_steps");
  for (const required of [
    "report_id", "step_key", "rev", "language", "entry", "files_json", "requirements", "proposed_by",
    "state", "created_at",
  ]) {
    assert.equal(steps[required].notnull, 1, `${required} is required`);
  }
  for (const nullable of ["bundle_hash", "approval_nonce", "approval_seal", "approved_at"]) {
    assert.equal(steps[nullable].notnull, 0, `${nullable} starts NULL`);
  }
  assert.equal(steps.state.dflt_value, "'proposed'");
  assert.deepEqual(
    tableInfo(master, "report_custom_steps").filter((c) => c.pk > 0).sort((a, b) => a.pk - b.pk).map((c) => c.name),
    ["report_id", "step_key", "rev"],
    "one row per report, step key and revision",
  );

  const assets = columns(master, "report_assets");
  for (const required of ["report_id", "name", "sha256", "bytes", "created_at"]) {
    assert.equal(assets[required].notnull, 1, `asset ${required} is required`);
  }
  assert.deepEqual(
    tableInfo(master, "report_assets").filter((c) => c.pk > 0).map((c) => c.name).sort(),
    ["name", "report_id"],
  );

  const hosts = columns(master, "report_hosts");
  assert.equal(hosts.state.dflt_value, "'proposed'");
  assert.deepEqual(
    tableInfo(master, "report_hosts").filter((c) => c.pk > 0).map((c) => c.name).sort(),
    ["host", "report_id"],
  );
  for (const nullable of ["approval_nonce", "approval_seal", "approved_at"]) {
    assert.equal(hosts[nullable].notnull, 0, `${nullable} starts NULL`);
  }

  const credentials = columns(master, "report_credentials");
  for (const required of ["connection_uuid", "inject_json", "state", "created_at"]) {
    assert.equal(credentials[required].notnull, 1, `credential ${required} is required`);
  }
  assert.equal(credentials.state.dflt_value, "'proposed'");
  assert.deepEqual(
    tableInfo(master, "report_credentials").filter((c) => c.pk > 0).map((c) => c.name).sort(),
    ["host", "report_id"],
    "one binding per report and host",
  );

  const objects = new Map(stepObjects(master).map((o) => [o.name, o]));
  assert.match(objects.get("idx_report_custom_steps_report").sql,
    /report_custom_steps\(report_id, step_key, rev\)/,
    "the newest revision of a key is an indexed read");
});

test("a second row for the same key is refused", () => {
  const dbPath = freshDb("reports-steps-keys-");
  run({ dbPath, log: () => {} });
  const db = new Database(dbPath);
  try {
    const insertStep = db.prepare(`INSERT INTO report_custom_steps
      (report_id, step_key, rev, language, entry, files_json, proposed_by, created_at)
      VALUES (?, ?, ?, 'python', 'run.py', '{"files":{"run.py":""},"assets":[]}', 'owner', 1)`);
    insertStep.run("rpt-0011223344556677", "fetch", 1);
    assert.throws(() => insertStep.run("rpt-0011223344556677", "fetch", 1), /UNIQUE/,
      "the same revision is one row");
    insertStep.run("rpt-0011223344556677", "fetch", 2);

    const insertHost = db.prepare(`INSERT INTO report_hosts (report_id, host, created_at) VALUES (?, ?, 1)`);
    insertHost.run("rpt-0011223344556677", "example.com");
    assert.throws(() => insertHost.run("rpt-0011223344556677", "example.com"), /UNIQUE/);

    const insertAsset = db.prepare(
      "INSERT INTO report_assets (report_id, name, sha256, bytes, created_at) VALUES (?, ?, ?, 1, 1)",
    );
    insertAsset.run("rpt-0011223344556677", "data.json", "a".repeat(64));
    assert.throws(() => insertAsset.run("rpt-0011223344556677", "data.json", "b".repeat(64)), /UNIQUE/,
      "an asset name is one row, so a replacement changes its hash in place");

    const insertCredential = db.prepare(`INSERT INTO report_credentials
      (report_id, host, connection_uuid, inject_json, created_at)
      VALUES (?, ?, ?, '{"header":"Authorization","format":"{}","pathPrefixes":["/v1"],"methods":["GET"]}', 1)`);
    insertCredential.run("rpt-0011223344556677", "example.com", "11111111-1111-1111-1111-111111111111");
    assert.throws(
      () => insertCredential.run("rpt-0011223344556677", "example.com", "22222222-2222-2222-2222-222222222222"),
      /UNIQUE/,
    );
  } finally {
    db.close();
  }
});

test("init-db runs the same DDL through initTable, right after the send block", () => {
  const init = readFileSync(new URL("../scripts/init-db.js", import.meta.url), "utf8");
  assert.match(init,
    /import \{[^}]*\bREPORTS_STEPS_DDL\b[^}]*\} from "\.\.\/servers\/shared\/reports-schema\.js";/);
  assert.ok(init.includes('await initTable("reports steps tables", REPORTS_STEPS_DDL);'));
  assert.ok(init.indexOf('await initTable("reports steps tables", REPORTS_STEPS_DDL);')
    > init.indexOf('await initTable("reports send tables", REPORTS_SEND_DDL);'),
  "the steps block follows the send block");
});

test("there is no CHECK and no foreign key (validated in the module)", () => {
  assert.doesNotMatch(REPORTS_STEPS_DDL, /CHECK/i);
  assert.doesNotMatch(REPORTS_STEPS_DDL, /REFERENCES/i);
  assert.equal((REPORTS_STEPS_DDL.match(/CREATE TABLE/g) ?? []).length, 4);
  assert.equal((REPORTS_STEPS_DDL.match(/IF NOT EXISTS/g) ?? []).length,
    (REPORTS_STEPS_DDL.match(/CREATE (TABLE|UNIQUE INDEX|INDEX)/g) ?? []).length,
    "every object is created IF NOT EXISTS");
  const migration = readFileSync(
    new URL("../scripts/migrations/0035-reports-steps.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(migration, /\bDROP\b/);
  assert.doesNotMatch(migration, /\bDELETE\b/);
  assert.doesNotMatch(REPORTS_STEPS_DDL, /\bDROP\s+(TABLE|INDEX|TRIGGER|VIEW|COLUMN)\b/i);
  assert.doesNotMatch(REPORTS_STEPS_DDL, /\bDELETE\s+FROM\b/i);
});

test("the earlier reports DDL constants are left exactly as they were", () => {
  const schema = readFileSync(new URL("../servers/shared/reports-schema.js", import.meta.url), "utf8");
  for (const [from, to] of [
    ["export const REPORTS_DDL", "export const REPORTS_TABLES"],
    ["export const REPORTS_RUNS_DDL", "export const REPORTS_RUNS_TABLES"],
    ["export const REPORTS_VERSIONS_DDL", "export const REPORTS_VERSIONS_TABLES"],
    ["export const REPORTS_SEND_DDL", "export const REPORTS_SEND_TABLES"],
  ]) {
    const block = schema.slice(schema.indexOf(from), schema.indexOf(to));
    assert.doesNotMatch(block, /report_custom_steps|report_hosts|report_credentials|report_assets/,
      `${from} is untouched`);
  }
  assert.match(readFileSync(
    new URL("../scripts/migrations/0034-reports-send.mjs", import.meta.url), "utf8"),
  /import \{ REPORTS_SEND_DDL, REPORTS_SEND_TABLES \}/);
});

test("run is idempotent and keeps a row", () => {
  const dbPath = freshDb("reports-steps-idem-");
  const first = run({ dbPath, log: () => {} });
  const db = new Database(dbPath);
  db.prepare(`INSERT INTO report_custom_steps
    (report_id, step_key, rev, language, entry, files_json, requirements, bundle_hash, proposed_by,
     state, approval_nonce, approval_seal, approved_at, created_at)
    VALUES ('rpt-0011223344556677', 'fetch', 1, 'node', 'run.mjs', '{"files":{"run.mjs":""},"assets":[]}',
            '', ?, 'owner', 'approved', ?, ?, 5, 5)`)
    .run("f".repeat(64), "a".repeat(32), "b".repeat(64));
  db.prepare(`INSERT INTO report_hosts
    (report_id, host, state, approval_nonce, approval_seal, approved_at, created_at)
    VALUES ('rpt-0011223344556677', 'example.com', 'approved', ?, ?, 5, 5)`)
    .run("c".repeat(32), "d".repeat(64));
  db.close();
  const before = stepObjects(dbPath);
  const second = run({ dbPath, log: () => {} });
  const afterSecond = stepObjects(dbPath);
  const check = new Database(dbPath, { readonly: true });
  const kept = {
    steps: check.prepare("SELECT count(*) AS n, max(state) AS state FROM report_custom_steps").get(),
    hosts: check.prepare("SELECT count(*) AS n, max(state) AS state FROM report_hosts").get(),
  };
  check.close();
  assert.equal(first.applied, true);
  assert.equal(second.applied, true);
  assert.deepEqual(kept, {
    steps: { n: 1, state: "approved" },
    hosts: { n: 1, state: "approved" },
  });
  assert.deepEqual(afterSecond, before, "a second run changes nothing");
});

test("all four step tables are local-only and never synced", () => {
  for (const t of REPORTS_STEPS_TABLES) {
    assert.ok(SYNC.LOCAL_ONLY_TABLES.includes(t), `${t} is in LOCAL_ONLY_TABLES`);
    assert.ok(!SYNC.SYNCED_TABLES.includes(t), `${t} is not in SYNCED_TABLES`);
    assert.equal(SYNC.shouldSyncRowForTest(t, { report_id: "rpt-0011223344556677" }), false);
  }
  const master = join(initDbDir(), "crow.db");
  assert.deepEqual(tableNames(master), [...REPORTS_STEPS_TABLES].sort());
  assert.doesNotThrow(() => SYNC.assertLocalOnlyDisjoint(SYNC.SYNCED_TABLES, SYNC.LOCAL_ONLY_TABLES));
  assert.throws(() => SYNC.assertLocalOnlyDisjoint(["report_credentials"], SYNC.LOCAL_ONLY_TABLES),
    /local-only/);
});