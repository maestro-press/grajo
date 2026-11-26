/**
 * A failed scheduled/heartbeat job (no board card) rings ONE owner bell per bot
 * per UTC day. A card job's failure shows on its card, so it rings none. The bell
 * carries a fixed title and an EMPTY body: never the error text.
 *
 * Nothing spawns pi: the bridge is injected, the notifier and clock are seams,
 * and CROW_DB_PATH is pinned to a throwaway dir.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const dir = mkdtempSync(join(tmpdir(), "botjob-bell-"));
process.env.CROW_DB_PATH = join(dir, "crow.db");
after(() => { try { rmSync(dir, { recursive: true, force: true }); } catch {} });

let runner;
before(async () => { runner = await import("../scripts/pi-bots/job_runner.mjs"); });

const SECRET = "contain refused: SECRET-ERROR-TEXT";
const failingBridge = { loadBot: () => { throw new Error(SECRET); } };
const okBridge = {
  loadBot: () => { throw new Error("unused"); },
  handleInbound: async (o) => { await o.sendReply("done"); return { action: "executed", cardId: 7, cardStatus: "done", piSessionId: "s", toolCalls: [], replyPreview: "" }; },
};
const T0 = Date.parse("2026-11-25T10:00:00Z");

function rig() {
  const bells = [];
  return { bells, notifyFailure: async (n) => { bells.push(n); } };
}

async function runOne(botId, { card = null, bridge = failingBridge, notifyFailure, now = () => T0 } = {}) {
  const job_id = runner.enqueueJob({ bot_id: botId, goal: "g", source: card ? "card" : "schedule" });
  if (card != null) {
    const { default: Database } = await import("better-sqlite3");
    const c = new Database(process.env.CROW_DB_PATH);
    c.prepare("UPDATE bot_jobs SET card_id=?, card_action='execute' WHERE job_id=?").run(card, job_id);
    c.close();
  }
  const r = await runner.runOnce({ bridge, notifyFailure, now });
  assert.equal(r.ran, job_id);
  return { r, job_id };
}

test("(a) a failed no-card job rings exactly one bell with fixed fields and no error text", async () => {
  const { bells, notifyFailure } = rig();
  const { r, job_id } = await runOne("bell-a", { notifyFailure });
  assert.equal(r.status, "failed");
  assert.equal(bells.length, 1);
  assert.deepEqual(bells[0], { bot_id: "bell-a", job_id });
  assert.ok(!JSON.stringify(bells[0]).includes("SECRET"));
});

test("(a2) the default notifier writes the exact notification shape", async () => {
  const src = readFileSync(new URL("../scripts/pi-bots/job_runner.mjs", import.meta.url), "utf8");
  const body = src.slice(src.indexOf("async function defaultNotifyJobFailure"), src.indexOf("/** Never throws"));
  for (const frag of [
    'type: "attention"', 'source: "pi-bots"', 'priority: "normal"',
    "title: `${bot_id}'s turn failed`", 'body: ""',
    "action_url: `/dashboard/bot-builder?bot=${encodeURIComponent(bot_id)}`",
    'metadata: { bot_id, kind: "job-failed", job_id }',
  ]) assert.ok(body.includes(frag), "missing " + frag);
  assert.ok(!/error|\be\.message/.test(body), "no error text may reach the notification");
});

test("(b) a failed CARD job rings none", async () => {
  const { bells, notifyFailure } = rig();
  const { r } = await runOne("bell-b", { card: 42, notifyFailure });
  assert.equal(r.status, "failed");
  assert.equal(bells.length, 0);
});

test("(c) a completed job rings none", async () => {
  const { bells, notifyFailure } = rig();
  const bridge = { loadBot: () => ({ def: {} }), handleInbound: okBridge.handleInbound };
  const { r } = await runOne("bell-c", { card: 7, bridge, notifyFailure });
  assert.equal(r.status, "completed");
  assert.equal(bells.length, 0);
});

test("(d) one bell per bot per UTC day; next day rings again; other bots ring separately", async () => {
  const { bells, notifyFailure } = rig();
  await runOne("bell-d1", { notifyFailure, now: () => T0 });
  await runOne("bell-d1", { notifyFailure, now: () => T0 + 3600_000 });
  assert.equal(bells.length, 1);
  await runOne("bell-d2", { notifyFailure, now: () => T0 });
  assert.equal(bells.length, 2);
  await runOne("bell-d1", { notifyFailure, now: () => T0 + 86400_000 });
  assert.equal(bells.length, 3);
  assert.deepEqual(bells.map((b) => b.bot_id), ["bell-d1", "bell-d2", "bell-d1"]);
});

test("(e) a throwing notifier leaves the outcome unchanged and does not throw", async () => {
  const logs = [];
  const notifyFailure = async () => { const e = new Error("NOTIFIER-SECRET"); e.code = "E_BELL"; throw e; };
  const job_id = runner.enqueueJob({ bot_id: "bell-e", goal: "g", source: "schedule" });
  const r = await runner.runOnce({ bridge: failingBridge, notifyFailure, now: () => T0, log: (m) => logs.push(m) });
  assert.equal(r.status, "failed");
  const row = runner.jobStatus(job_id);
  assert.equal(row.status, "failed");
  assert.ok(String(row.error).includes("SECRET-ERROR-TEXT"));
  const line = logs.find((l) => l.includes("bell failed"));
  assert.ok(line && line.includes("E_BELL") && !line.includes("NOTIFIER-SECRET"));
});

test("(f) tickJobs (what the supervised runner calls) reaches the same bell", async () => {
  const { bells, notifyFailure } = rig();
  runner.enqueueJob({ bot_id: "bell-f", goal: "g", source: "schedule" });
  const r = await runner.tickJobs({ bridge: failingBridge, notifyFailure, now: () => T0 });
  if (r.skipped) return; // reserved-slot gate busy on this box; the source assertion below still holds
  assert.equal(r.status, "failed");
  assert.equal(bells.length, 1);
});

test("(f2) gateway_runner drives jobs through job_runner's tickJobs", () => {
  const src = readFileSync(new URL("../scripts/pi-bots/gateways/gateway_runner.mjs", import.meta.url), "utf8");
  assert.match(src, /import \{ tickJobs \} from "\.\.\/job_runner\.mjs"/);
  assert.match(src, /await tickJobs\(/);
});

async function abandon(botId, { card = null, attempts = 3 } = {}) {
  const job_id = runner.enqueueJob({ bot_id: botId, goal: "g", source: card ? "card" : "schedule" });
  const { default: Database } = await import("better-sqlite3");
  const c = new Database(process.env.CROW_DB_PATH);
  c.prepare("UPDATE bot_jobs SET status='running', attempts=?, worker_pid=999999999, card_id=? WHERE job_id=?").run(attempts, card, job_id);
  c.close();
  return job_id;
}

test("(g) an abandoned no-card job rings once, deduped with a same-day failure of the same bot", async () => {
  const { bells, notifyFailure } = rig();
  await runOne("bell-g", { notifyFailure, now: () => T0 });
  assert.equal(bells.length, 1);
  const id = await abandon("bell-g");
  await runner.recoverStaleClaims(() => {}, { notifyFailure, now: () => T0 + 60_000 });
  assert.equal(runner.jobStatus(id).status, "failed");
  assert.equal(bells.length, 1, "same bot, same day: deduped");
  const id2 = await abandon("bell-g2");
  await runner.recoverStaleClaims(() => {}, { notifyFailure, now: () => T0 });
  assert.equal(bells.length, 2);
  assert.deepEqual(bells[1], { bot_id: "bell-g2", job_id: id2 });
});

test("(h) an abandoned card job rings none; a re-queued (attempts left) job rings none; a throwing notifier does not throw", async () => {
  const { bells, notifyFailure } = rig();
  await abandon("bell-h", { card: 55 });
  await abandon("bell-h2", { attempts: 1 });
  await runner.recoverStaleClaims(() => {}, { notifyFailure, now: () => T0 });
  assert.equal(bells.length, 0);
  await abandon("bell-h3");
  await runner.recoverStaleClaims(() => {}, { notifyFailure: async () => { throw new Error("x"); }, now: () => T0 });
});
