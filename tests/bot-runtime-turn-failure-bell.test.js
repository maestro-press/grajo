// Gmail owner bell: a failed Gmail turn raises exactly one bell per bot+thread per UTC day,
// with fixed text (no mail content), and a notifier fault never breaks the tick.
import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import Database from "better-sqlite3";

import { initBotRuntime, botRuntimeStatus, _resetBotRuntimeForTest } from "../servers/gateway/bot-runtime.js";

function makeConn() {
  const d = new Database(":memory:");
  d.exec(`
    CREATE TABLE dashboard_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE dashboard_settings_overrides (key TEXT, instance_id TEXT, value TEXT,
      updated_at TEXT DEFAULT (datetime('now')), lamport_ts INTEGER DEFAULT 0, PRIMARY KEY(key, instance_id));
    CREATE TABLE pi_bot_defs (bot_id TEXT PRIMARY KEY, display_name TEXT, definition TEXT,
      project_id INTEGER, enabled INTEGER DEFAULT 1, updated_at TEXT DEFAULT (datetime('now')));
  `);
  d.prepare("INSERT INTO dashboard_settings (key, value) VALUES ('feature_flags', ?)").run(JSON.stringify({ bot_runtime: true }));
  return d;
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let conns = [];
beforeEach(() => { _resetBotRuntimeForTest(); conns = []; });
afterEach(() => { _resetBotRuntimeForTest(); for (const c of conns) { try { c.close(); } catch {} } });

async function setup({ results, notify, now }) {
  const conn = makeConn(); conns.push(conn);
  let fire;
  let i = 0;
  await initBotRuntime({
    env: {},
    _conn: conn,
    _runBridgeTick: async () => results[Math.min(i++, results.length - 1)],
    ...(notify ? { _notifyTurnFailure: notify } : {}),
    ...(now ? { _now: now } : {}),
    _superviseProcess: () => ({ live: true, stop: async () => {} }),
    _setIntervalFn: (fn) => { fire = fn; return 1; },
    _clearIntervalFn: () => {},
    _setTimeoutFn: () => 1,
    _clearTimeoutFn: () => {},
    _bus: new EventEmitter(),
    _pollMs: 10,
  });
  await wait(30);
  return () => fire();
}

const tickWith = (failures, handled = 1, errors = []) => ({ ok: true, bots: 1, handled, errors, failures });

test("a turn-error failure raises one notice carrying ids and kind only", async () => {
  const calls = [];
  const fire = await setup({ results: [tickWith([{ bot_id: "alpha", thread_id: "t1", kind: "turn-error" }])], notify: async (f) => { calls.push(f); } });
  await fire();
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], { bot_id: "alpha", thread_id: "t1", kind: "turn-error" });
});

test("a failure payload to the notifier seam carries no mail content", async () => {
  const calls = [];
  const fire = await setup({ results: [tickWith([{ bot_id: "alpha", thread_id: "t1", kind: "exception" }], 0, ["secret mail text"])], notify: async (f) => { calls.push(f); } });
  await fire();
  assert.equal(calls.length, 1);
  assert.equal(JSON.stringify(calls[0]).includes("secret"), false);
});

test("same bot+thread twice in a day notifies once; another thread notifies again; next day notifies again", async () => {
  const calls = [];
  let t = Date.parse("2026-11-25T10:00:00Z");
  const f1 = { bot_id: "alpha", thread_id: "t1", kind: "turn-error" };
  const f2 = { bot_id: "alpha", thread_id: "t2", kind: "turn-error" };
  const fire = await setup({
    results: [tickWith([f1]), tickWith([f1]), tickWith([f2]), tickWith([f1])],
    notify: async (f) => { calls.push(f); },
    now: () => t,
  });
  await fire(); await fire();
  assert.equal(calls.length, 1);
  await fire();
  assert.equal(calls.length, 2);
  assert.equal(calls[1].thread_id, "t2");
  t = Date.parse("2026-11-26T10:00:00Z");
  await fire();
  assert.equal(calls.length, 3);
});

test("a throwing notifier does not break the tick", async () => {
  const fire = await setup({
    results: [tickWith([{ bot_id: "alpha", thread_id: "t1", kind: "turn-error" }])],
    notify: async () => { throw new Error("db down with secret"); },
  });
  await fire();
  const st = botRuntimeStatus();
  assert.ok(st.bridge.lastTickAt);
  assert.equal(st.bridge.breaker.open, false);
  assert.equal(st.bridge.breaker.failures, 0);
});

test("a tick with no failures notifies nothing", async () => {
  const calls = [];
  const fire = await setup({ results: [tickWith([]), { ok: true, bots: 0, handled: 0, errors: [] }], notify: async (f) => { calls.push(f); } });
  await fire(); await fire();
  assert.equal(calls.length, 0);
});

test("default notifier writes one fixed-text attention notification to the scratch DB", async () => {
  const { execFileSync } = await import("node:child_process");
  const { mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = mkdtempSync(join(tmpdir(), "crow-turnfail-bell-"));
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env, CROW_DATA_DIR: dir }, stdio: "pipe" });
  const prevDir = process.env.CROW_DATA_DIR, prevDb = process.env.CROW_DB_PATH;
  delete process.env.CROW_DB_PATH;
  process.env.CROW_DATA_DIR = dir;
  try {
    const fire = await setup({
      results: [tickWith([{ bot_id: "alpha", thread_id: "t1", kind: "turn-error" }], 1, ["SECRET mail text"])],
      notify: undefined,
    });
    await fire();
    const d = new Database(join(dir, "crow.db"));
    try {
      const rows = d.prepare("SELECT * FROM notifications WHERE source = 'pi-bots'").all();
      assert.equal(rows.length, 1);
      const n = rows[0];
      assert.equal(n.type, "attention");
      assert.equal(n.title, "alpha's turn failed");
      assert.equal(n.body, "A Gmail reply could not be sent: the bot's turn failed. The bot will try again on the next message in that thread.");
      assert.equal(n.action_url, "/dashboard/bot-builder?bot=alpha");
      assert.deepEqual(JSON.parse(n.metadata), { bot_id: "alpha", kind: "turn-error" });
      assert.equal(JSON.stringify(n).includes("SECRET"), false);
    } finally { d.close(); }
  } finally {
    if (prevDir === undefined) delete process.env.CROW_DATA_DIR; else process.env.CROW_DATA_DIR = prevDir;
    if (prevDb !== undefined) process.env.CROW_DB_PATH = prevDb;
    rmSync(dir, { recursive: true, force: true });
  }
});
