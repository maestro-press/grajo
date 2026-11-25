/**
 * M6, queue door: the stdio outbox (emitOrQueue) stamps a synced setting with
 * this Crow's origin on a live write, carries it in the queued row, and never
 * restamps the origin on a preserve-lamport re-queue.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDbClient } from "../servers/db.js";
import { InstanceSyncManager } from "../servers/sharing/instance-sync.js";
import { drainOnce } from "../servers/sharing/sync-outbox-drain.js";
import * as ed from "../node_modules/@noble/ed25519/index.js";
import { emitOrQueue, _setEligibilityForTest } from "../servers/shared/sync-emit.js";
import { getOrCreateLocalInstanceId } from "../servers/gateway/instance-registry.js";

const idDir = mkdtempSync(join(tmpdir(), "crow-m6q-id-"));
const prevDataDir = process.env.CROW_DATA_DIR;
process.env.CROW_DATA_DIR = idDir;
const dir = mkdtempSync(join(tmpdir(), "crow-m6q-db-"));
execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env, CROW_DATA_DIR: dir }, stdio: "pipe" });
const db = createDbClient(join(dir, "crow.db"));
const KEY = "profile_display_name";
const OTHER = "zzzzzzzz-0000-4000-8000-00000000000f";

test.after(() => {
  db.close();
  rmSync(dir, { recursive: true, force: true });
  rmSync(idDir, { recursive: true, force: true });
  if (prevDataDir === undefined) delete process.env.CROW_DATA_DIR; else process.env.CROW_DATA_DIR = prevDataDir;
  _setEligibilityForTest(null);
});

test("live queued write stamps + queues this Crow's origin; preserve re-queue keeps the original", async () => {
  _setEligibilityForTest(() => true);
  const me = getOrCreateLocalInstanceId();
  await db.execute({ sql: "INSERT INTO dashboard_settings (key, value, updated_at) VALUES (?, 'v', datetime('now'))", args: [KEY] });

  const live = await emitOrQueue(null, db, "dashboard_settings", "update", { key: KEY, value: "v", instance_id: null });
  assert.equal(live.queued, true);
  let r = (await db.execute({ sql: "SELECT lamport_ts, lamport_origin FROM dashboard_settings WHERE key = ?", args: [KEY] })).rows[0];
  assert.equal(r.lamport_origin, me);
  assert.equal(Number(r.lamport_ts), live.lamport);
  let q = (await db.execute("SELECT row_json FROM sync_outbox ORDER BY id DESC LIMIT 1")).rows[0];
  assert.equal(JSON.parse(q.row_json).lamport_origin, me);

  // A row that arrived from another instance, re-queued in preserve mode: origin untouched, row keeps the writer.
  await db.execute({ sql: "UPDATE dashboard_settings SET lamport_ts = 3, lamport_origin = ? WHERE key = ?", args: [OTHER, KEY] });
  await emitOrQueue(null, db, "dashboard_settings", "update", { key: KEY, value: "v", instance_id: null, lamport_origin: OTHER }, { lamportTs: 3 });
  r = (await db.execute({ sql: "SELECT lamport_ts, lamport_origin FROM dashboard_settings WHERE key = ?", args: [KEY] })).rows[0];
  assert.equal(r.lamport_origin, OTHER, "the local row is not restamped to this Crow");
  q = (await db.execute("SELECT row_json FROM sync_outbox ORDER BY id DESC LIMIT 1")).rows[0];
  assert.equal(JSON.parse(q.row_json).lamport_origin, OTHER);
});

test("QUEUE PATH: emitOrQueue -> outbox -> drain -> emitChange carries the writer's origin, and a second instance converges", async () => {
  _setEligibilityForTest(() => true);
  const me = getOrCreateLocalInstanceId();
  const priv = Buffer.alloc(32, 0xAB);
  const identity = { ed25519Priv: priv, ed25519Pubkey: Buffer.from(await ed.getPublicKey(priv)).toString("hex") };
  await db.execute("DELETE FROM sync_outbox");
  await db.execute({ sql: "INSERT OR REPLACE INTO dashboard_settings (key, value, updated_at) VALUES (?, 'queued', datetime('now'))", args: [KEY] });
  const q = await emitOrQueue(null, db, "dashboard_settings", "update", { key: KEY, value: "queued", instance_id: null });

  const mgr = new InstanceSyncManager(identity, db, me);
  mgr.feedsDisabled = false;
  await db.execute({ sql: "INSERT OR IGNORE INTO crow_instances (id, name, crow_id, status, trusted) VALUES ('peer-q', 'peer-q', 'crow:stub', 'active', 1)" });
  const captured = [];
  mgr.outFeeds.set("peer-q", { append: async (e) => captured.push(JSON.parse(JSON.stringify(e))) });
  const res = await drainOnce(mgr, db, {});
  assert.equal(res.deleted, 1);
  assert.equal(captured.length, 1);
  assert.equal(captured[0].lamport_ts, q.lamport, "preserve-mode: the write-time lamport");
  assert.equal(captured[0].row.lamport_origin, me, "the drained entry names the queuing writer");

  // A second instance (a fresh scratch DB, lesser/greater id irrelevant) applies it through the real apply.
  const dir2 = mkdtempSync(join(tmpdir(), "crow-m6q-db2-"));
  try {
    execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env, CROW_DATA_DIR: dir2 }, stdio: "pipe" });
    const db2 = createDbClient(join(dir2, "crow.db"));
    const other = new InstanceSyncManager(identity, db2, "other-instance");
    other.feedsDisabled = false;
    await other._applyEntry(me, captured[0]);
    const r = (await db2.execute({ sql: "SELECT value, lamport_ts, lamport_origin FROM dashboard_settings WHERE key = ?", args: [KEY] })).rows[0];
    assert.deepEqual({ ...r }, { value: "queued", lamport_ts: q.lamport, lamport_origin: me });
    db2.close();
  } finally { rmSync(dir2, { recursive: true, force: true }); }
});
