// Migration 0038 (message_drafts.chat_thread_id): the column a LIVE install is missing.
//
// The bug this pins: `chat_thread_id` was first delivered by editing 0036's DDL, which is useless on
// every install that has already applied 0036 — the runner applies a migration by `id` and never
// re-runs one that is on file, and `CREATE TABLE IF NOT EXISTS` never adds a column to a table that
// exists. So the fixture here is exactly a live install: message_drafts in 0036's OLD shape (no
// chat_thread_id), a real draft row in it, and 0036 recorded in schema_migrations. 0038 must be what
// brings the column and its index, and a second run must change nothing.
//
// The shape contract: 0038 adds one nullable column and one index, removes nothing, and declares
// rollbackSafe = true (an older build never selects the column). Both rails converge: init-db's
// "message draft tables" block ensures the same column and index from the same constants, including
// on an existing store whose table predates the column.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

import * as mod from "../scripts/migrations/0038-message-drafts-chat-thread.mjs";
import { runMigrations, discoverMigrations } from "../scripts/migrations/runner.mjs";
import {
  MESSAGE_DRAFTS_DDL,
  MESSAGE_DRAFTS_CHAT_THREAD_COLUMN,
  MESSAGE_DRAFTS_CHAT_THREAD_INDEX_DDL,
} from "../servers/shared/message-drafts-schema.js";

const REPO = new URL("..", import.meta.url).pathname;
const MIGRATIONS_DIR = join(REPO, "scripts", "migrations");
const ID = "0038-message-drafts-chat-thread";

const DIRS = [];
after(() => { for (const d of DIRS) rmSync(d, { recursive: true, force: true }); });

function tmp(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  DIRS.push(dir);
  return dir;
}

/** 0036's shape BEFORE chat_thread_id existed: the same DDL, one column line fewer. */
const OLD_SHAPE_DDL = MESSAGE_DRAFTS_DDL.replace(/^\s*chat_thread_id TEXT,\n/m, "");

const SEEDED = `
  INSERT INTO message_drafts
    (id, conversation_kind, conversation_id, origin, bot_id, state, version, body, body_hash,
     recipients_json, recipients_seal, created_at, updated_at)
  VALUES ('msgd-0123456789abcdef', 'contact', 7, 'owner', NULL, 'open', 2, 'Hello there',
          'hash-of-the-body', '["crow:peer"]', 'seal', 1, 2);
`;

/** A live install: 0036 applied long ago, its table in the old shape, one real draft in it. */
function liveInstall(prefix) {
  const root = tmp(prefix);
  const dbPath = join(root, "crow.db");
  const tasksDbPath = join(root, "tasks.db");
  new Database(tasksDbPath).close();

  assert.notEqual(OLD_SHAPE_DDL, MESSAGE_DRAFTS_DDL, "the fixture must really be the older shape");
  const db = new Database(dbPath);
  try {
    db.exec(OLD_SHAPE_DDL);
    assert.ok(!columnsOf(db, "message_drafts").includes("chat_thread_id"),
      "the fixture table predates chat_thread_id");
    db.exec(SEEDED);
    db.exec("CREATE TABLE schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL, sha TEXT)");
    db.prepare("INSERT INTO schema_migrations (id, applied_at) VALUES (?, datetime('now'))")
      .run("0036-message-drafts");
  } finally { db.close(); }

  return { root, dbPath, tasksDbPath };
}

function columnsOf(db, table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
}

function columns(dbPath, table = "message_drafts") {
  const db = new Database(dbPath, { readonly: true });
  try { return columnsOf(db, table); } finally { db.close(); }
}

function indexes(dbPath, table = "message_drafts") {
  const db = new Database(dbPath, { readonly: true });
  try {
    return db.prepare(
      "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL ORDER BY name",
    ).all(table).map((r) => r.name);
  } finally { db.close(); }
}

/** Every sqlite_master object in the database, as a comparable {type, name, sql} list. */
function objects(dbPath) {
  const db = new Database(dbPath, { readonly: true });
  try {
    return db.prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").all();
  } finally { db.close(); }
}

function recorded(dbPath) {
  const db = new Database(dbPath, { readonly: true });
  try {
    return db.prepare("SELECT id FROM schema_migrations ORDER BY id").all().map((r) => r.id);
  } finally { db.close(); }
}

test("0038 delivers chat_thread_id to a store that already applied 0036", async () => {
  const f = liveInstall("msgd-chat-thread-live-");

  const res = await runMigrations({ migrationsDir: MIGRATIONS_DIR, dbPath: f.dbPath, tasksDbPath: f.tasksDbPath });

  assert.ok(res.skipped.includes("0036-message-drafts"),
    `0036 is on file, so the runner skips it (applied: ${JSON.stringify(res.applied)})`);
  assert.ok(!res.applied.includes("0036-message-drafts"), "0036 must not be re-applied");
  assert.ok(res.applied.includes(ID), `0038 is what brings the column (applied: ${JSON.stringify(res.applied)})`);
  assert.ok(!res.deferred.includes(ID), "0038 needs no deferral: 0036 made (or found) the table");

  assert.ok(columns(f.dbPath).includes("chat_thread_id"), "the column now exists on the live store");
  assert.ok(indexes(f.dbPath).includes("idx_message_drafts_chat_thread"), "and so does its index");

  const db = new Database(f.dbPath);
  try {
    assert.deepEqual(db.prepare("SELECT id, chat_thread_id FROM message_drafts").get(),
      { id: "msgd-0123456789abcdef", chat_thread_id: null },
      "the draft that was already there survives, with a null chat thread");
  } finally { db.close(); }

  assert.ok(recorded(f.dbPath).includes(ID), "0038 is recorded in schema_migrations");
});

test("a second registry pass is a no-op, and so is a direct re-run of the body", async () => {
  const f = liveInstall("msgd-chat-thread-idem-");
  await runMigrations({ migrationsDir: MIGRATIONS_DIR, dbPath: f.dbPath, tasksDbPath: f.tasksDbPath });

  // (a) through the runner: recorded, so skipped rather than applied.
  const shape = objects(f.dbPath);
  const idsBefore = recorded(f.dbPath);
  const again = await runMigrations({ migrationsDir: MIGRATIONS_DIR, dbPath: f.dbPath, tasksDbPath: f.tasksDbPath });
  assert.ok(again.skipped.includes(ID), "an applied migration is skipped, never re-run");
  assert.ok(!again.applied.includes(ID));
  assert.deepEqual(recorded(f.dbPath), idsBefore, "and its record is not duplicated");
  assert.deepEqual(objects(f.dbPath), shape, "the shape is unchanged: no object, index or column added");

  // (b) the body itself, with the record gone (a store restored from a backup loses the row while
  // keeping the schema): the guard is what makes it safe, so it must not throw and must add nothing.
  const out = mod.run({ dbPath: f.dbPath, log: () => {} });
  assert.equal(out.applied, true);
  assert.deepEqual(out.results, [
    "message_drafts.chat_thread_id: present", "idx_message_drafts_chat_thread: ensured",
  ]);
  assert.deepEqual(objects(f.dbPath), shape, "a re-run without its record changes nothing");
});

test("the fresh-DB rail: init-db creates the column and its index", () => {
  const dir = tmp("msgd-chat-thread-init-");
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir, CROW_HOME: join(dir, "home") },
    cwd: REPO,
    stdio: "pipe",
  });
  const dbPath = join(dir, "crow.db");

  assert.ok(columns(dbPath).includes("chat_thread_id"), "init-db's fresh shape has the column");
  assert.ok(indexes(dbPath).includes("idx_message_drafts_chat_thread"), "and the chat's own read is indexed");
});

test("init-db ALSO upgrades a store whose message_drafts table predates the column", () => {
  // The reason the index is not part of MESSAGE_DRAFTS_DDL: init-db executes that whole string BEFORE
  // its late-column ALTERs, so a CREATE INDEX on chat_thread_id there would exit init-db non-zero on
  // every live install. Both steps must therefore be ordered column-then-index.
  const dir = tmp("msgd-chat-thread-upgrade-");
  const dbPath = join(dir, "crow.db");
  const db = new Database(dbPath);
  try {
    db.exec(OLD_SHAPE_DDL);
    db.exec(SEEDED);
  } finally { db.close(); }

  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir, CROW_HOME: join(dir, "home") },
    cwd: REPO,
    stdio: "pipe",
  });

  assert.ok(columns(dbPath).includes("chat_thread_id"), "the column was added to the existing table");
  assert.ok(indexes(dbPath).includes("idx_message_drafts_chat_thread"), "and then indexed");
  const after = new Database(dbPath, { readonly: true });
  try {
    assert.equal(after.prepare("SELECT body FROM message_drafts WHERE id = ?")
      .get("msgd-0123456789abcdef").body, "Hello there", "the existing draft is untouched");
  } finally { after.close(); }
});

test("an absent message_drafts is recorded as applied, never as a deferral", () => {
  // Only reachable outside the runner (0036 sorts before 0038 and creates the table), and then there
  // is nothing left for a retry to find — 0029's rule.
  const dbPath = join(tmp("msgd-chat-thread-absent-"), "crow.db");
  new Database(dbPath).close();

  const out = mod.run({ dbPath, log: () => {} });
  assert.equal(out.applied, true);
  assert.deepEqual(out.results, ["message_drafts: absent"]);
  assert.deepEqual(objects(dbPath), [], "and nothing was created on the way");
});

test("the module's contract: id, rollbackSafe, and additive DDL only", () => {
  const files = discoverMigrations(MIGRATIONS_DIR).map((p) => p.split("/").pop());
  assert.ok(files.includes(`${ID}.mjs`), "the registry discovers the file");
  assert.equal(mod.id, ID, "the module id matches its filename");
  assert.equal(files.indexOf("0037-bot-sharing-audit.mjs") < files.indexOf(`${ID}.mjs`), true,
    "it sorts after the bot-door audit migration it follows");
  assert.equal(mod.rollbackSafe, true, "older code never selects the column, so a rollback is safe");

  // The constants both rails share, and the guard that keeps the ALTER idempotent.
  assert.deepEqual({ ...MESSAGE_DRAFTS_CHAT_THREAD_COLUMN }, {
    table: "message_drafts",
    column: "chat_thread_id",
    ddl: "ALTER TABLE message_drafts ADD COLUMN chat_thread_id TEXT",
  });
  assert.equal(MESSAGE_DRAFTS_CHAT_THREAD_INDEX_DDL,
    "CREATE INDEX IF NOT EXISTS idx_message_drafts_chat_thread ON message_drafts(chat_thread_id)");
  assert.doesNotMatch(MESSAGE_DRAFTS_DDL, /idx_message_drafts_chat_thread/,
    "the index must NOT live in the shared DDL: that string runs before the column can exist");

  const src = readFileSync(new URL("../scripts/migrations/0038-message-drafts-chat-thread.mjs", import.meta.url), "utf8");
  const code = src.split("\n").filter((line) => !/^\s*\/\//.test(line)).join("\n");
  assert.doesNotMatch(code, /\bDROP\b/, "it removes no schema object");
  assert.doesNotMatch(code, /\bDELETE\b/, "and no row");
  assert.match(code, /CREATE INDEX IF NOT EXISTS|MESSAGE_DRAFTS_CHAT_THREAD_INDEX_DDL/,
    "the index is created with IF NOT EXISTS, from the shared constant");
});