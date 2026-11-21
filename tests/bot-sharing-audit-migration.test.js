// Migration 0037 (bot_sharing_audit): additive, local-only, rollback-safe, and the same shape on both
// rails (the migration and init-db's mirror).
//
// The contract this file pins, in the words the repo's migration convention uses:
//   - it CREATES one table and its indexes, and removes nothing (rollbackSafe: an older build never
//     reads it, so a rollback leaves a harmless leftover);
//   - it needs no SCHEMA_GENERATION bump (init-db carries the same DDL constant);
//   - it is idempotent (CREATE ... IF NOT EXISTS, so a re-run after a partial apply is a no-op);
//   - the table is LOCAL ONLY — in instance-sync's LOCAL_ONLY_TABLES and never in SYNCED_TABLES — because
//     the allow-list it is judged against lives in this instance's secrets/ and its targets are this
//     instance's contacts;
//   - it stores IDs only: there is no column for message text.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

import * as migration from "../scripts/migrations/0037-bot-sharing-audit.mjs";
import { BOT_SHARING_AUDIT_DDL, BOT_SHARING_AUDIT_TABLES } from "../servers/shared/bot-sharing-schema.js";
import { LOCAL_ONLY_TABLES, SYNCED_TABLES } from "../servers/sharing/instance-sync.js";

const root = mkdtempSync(join(tmpdir(), "bot-sharing-migration-"));
after(() => rmSync(root, { recursive: true, force: true }));

const DB = join(root, "crow.db");

before(() => {
  const db = new Database(DB);
  db.exec("CREATE TABLE contacts (id INTEGER PRIMARY KEY AUTOINCREMENT, crow_id TEXT)");
  db.close();
});

const columns = (path) => {
  const db = new Database(path);
  try {
    return db.prepare("PRAGMA table_info(bot_sharing_audit)").all().map((row) => row.name);
  } finally {
    db.close();
  }
};

test("the migration is additive and rollback-safe, and creates the table init-db also creates", () => {
  assert.equal(migration.id, "0037-bot-sharing-audit");
  assert.equal(migration.rollbackSafe, true);
  assert.deepEqual([...BOT_SHARING_AUDIT_TABLES], ["bot_sharing_audit"]);

  const out = migration.run({ dbPath: DB, log: () => {} });
  assert.equal(out.applied, true);
  assert.deepEqual(out.results, ["bot_sharing_audit: ensured"]);

  const got = columns(DB);
  assert.deepEqual(got, [
    "id", "bot_id", "thread", "gateway", "tool", "target", "outcome", "draft_id", "refs_json", "ts",
  ]);
  // IDs only: no column can hold a message body, a subject or a recipient name.
  for (const forbidden of ["body", "content", "message", "text", "body_hash", "subject"]) {
    assert.equal(got.includes(forbidden), false, `no ${forbidden} column`);
  }

  const db = new Database(DB);
  try {
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").all().map((row) => row.name);
    assert.ok(tables.includes("contacts"), "the pre-existing table is untouched (nothing is removed)");
    const indexes = db.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'bot_sharing_audit' ORDER BY name").all().map((row) => row.name);
    assert.deepEqual(indexes, [
      "idx_bot_sharing_audit_bot_ts", "idx_bot_sharing_audit_draft", "idx_bot_sharing_audit_outcome",
    ]);
  } finally {
    db.close();
  }
});

test("re-running the migration is idempotent (a partial apply re-runs safely)", () => {
  const again = migration.run({ dbPath: DB, log: () => {} });
  assert.equal(again.applied, true);
  assert.deepEqual(columns(DB).length, 10);
  // And the DDL constant itself is idempotent.
  const db = new Database(DB);
  try {
    db.exec(BOT_SHARING_AUDIT_DDL);
    db.exec(BOT_SHARING_AUDIT_DDL);
  } finally {
    db.close();
  }
});

test("the table is LOCAL ONLY: in LOCAL_ONLY_TABLES, never in SYNCED_TABLES", () => {
  assert.ok(LOCAL_ONLY_TABLES.includes("bot_sharing_audit"), "the door's trail never leaves the instance");
  assert.equal(SYNCED_TABLES.includes("bot_sharing_audit"), false);
});

test("init-db (the other rail) builds the same table, so a co-hosted instance converges on its own restart", () => {
  const dir = join(root, "fresh");
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir, CROW_HOME: join(root, "home") },
    cwd: join(import.meta.dirname, ".."),
    stdio: "pipe",
  });
  const fresh = join(dir, "crow.db");
  assert.deepEqual(columns(fresh), columns(DB), "the two rails agree on the shape");
});

test("a row can be written and read back with ids only", () => {
  const db = new Database(DB);
  try {
    db.prepare(`INSERT INTO bot_sharing_audit (bot_id, thread, gateway, tool, target, outcome, draft_id, refs_json, ts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run("hank", "perch-1", "perch", "crow_send_message", "crow:peer", "drafted", "msgd-" + "0".repeat(32), null, 1);
    const row = db.prepare("SELECT * FROM bot_sharing_audit").get();
    assert.equal(row.bot_id, "hank");
    assert.equal(row.outcome, "drafted");
    assert.equal(row.refs_json, null);
  } finally {
    db.close();
  }
});