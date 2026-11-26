/**
 * The default job-failure notifier against a real scratch crow.db (init-db), read back
 * from the notifications table. Separate file: it needs its own CROW_DB_PATH and a
 * schema-complete database.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import Database from "better-sqlite3";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const dir = mkdtempSync(join(tmpdir(), "botjob-bell-real-"));
execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env, CROW_DATA_DIR: dir }, stdio: "pipe" });
const dbPath = join(dir, "crow.db");
process.env.CROW_DB_PATH = dbPath;
delete process.env.CROW_DATA_DIR;
after(() => { try { rmSync(dir, { recursive: true, force: true }); } catch {} });

test("default notifier writes one fixed-text attention notification, no error text anywhere", async () => {
  const runner = await import("../scripts/pi-bots/job_runner.mjs");
  const job_id = runner.enqueueJob({ bot_id: "real-bot", goal: "g", source: "schedule" });
  const bridge = { loadBot: () => { throw new Error("contain refused: SECRET-ERROR-TEXT"); } };
  const r = await runner.runOnce({ bridge, now: () => Date.parse("2026-11-25T10:00:00Z") });
  assert.equal(r.status, "failed");
  const d = new Database(dbPath);
  try {
    const rows = d.prepare("SELECT * FROM notifications WHERE source = 'pi-bots'").all();
    assert.equal(rows.length, 1);
    const n = rows[0];
    assert.equal(n.type, "attention");
    assert.equal(n.priority, "normal");
    assert.equal(n.title, "real-bot's turn failed");
    assert.ok(n.body === "" || n.body == null);
    assert.equal(n.action_url, "/dashboard/bot-builder?bot=real-bot");
    assert.deepEqual(JSON.parse(n.metadata), { bot_id: "real-bot", kind: "job-failed", job_id });
    assert.equal(JSON.stringify(n).includes("SECRET"), false);
    assert.equal(JSON.stringify(n).includes("refused"), false);
  } finally { d.close(); }
});
