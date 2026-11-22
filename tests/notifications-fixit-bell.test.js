/**
 * The bell's `attention` number counts pending Fix-it cards as well as health
 * issues — each side in its own try/catch, so a broken signal reader cannot zero
 * the cards (and vice versa) — and the push a new urgent card raises now lands on
 * the Attention sheet.
 */
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = join(import.meta.dirname, "..");
const dir = mkdtempSync(join(tmpdir(), "notifications-fixit-bell-"));
process.env.CROW_DATA_DIR = dir;
mkdirSync(join(dir, "home"), { recursive: true });
process.env.CROW_HOME = join(dir, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");

const ISSUE = (n) => ({
  id: `issue-${n}`,
  severity: "warn",
  label: `Issue ${n}`,
  actionLabel: "Open",
  actionHref: "/dashboard/settings",
  ack: null,
});

let server, base, db, store, idx, registry;
let signalsMode = "ok";

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env }, stdio: "pipe", cwd: REPO,
  });
  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient();
  store = await import("../servers/shared/fix-it/store.js");
  idx = await import("../servers/gateway/fix-it/index.js");
  registry = await import("../servers/shared/fix-it/registry.js");

  const { default: express } = await import("express");
  const { default: notificationsRouter } = await import("../servers/gateway/routes/notifications.js");
  const app = express();
  app.use(notificationsRouter((req, res, next) => next(), {
    collectSignals: async () => {
      if (signalsMode === "throw") throw new Error("signals down");
      return { ok: false, issues: [ISSUE(1), ISSUE(2), ISSUE(3)], details: [], links: [] };
    },
  }));
  await new Promise((resolve) => { server = app.listen(0, "127.0.0.1", resolve); });
  base = "http://127.0.0.1:" + server.address().port;
});

after(() => {
  if (server) server.close();
  try { db.close(); } catch {}
  try { rmSync(dir, { recursive: true, force: true }); } catch {}
});

beforeEach(async () => {
  signalsMode = "ok";
  await db.execute("DELETE FROM fix_it_items");
  await db.execute("DELETE FROM notifications");
});

async function pendingCards(n) {
  for (let i = 0; i < n; i += 1) {
    await store.upsertItem(db, {
      source: "remote-exposure",
      dedupKey: `expose|cap-${i}|peer-bell`,
      title: `Card ${i}`,
      why: "why",
      severity: "warn",
      remedies: [],
      context: { capability: `cap-${i}`, requestingInstance: "peer-bell" },
    });
  }
}

async function attention() {
  const res = await fetch(base + "/api/notifications/count");
  assert.equal(res.status, 200);
  const json = await res.json();
  assert.equal(typeof json.count, "number");
  return json.attention;
}

test("3 issues + 2 pending cards counts 5", async () => {
  await pendingCards(2);
  assert.equal(await attention(), 5);
});

test("a failing signal reader still leaves the pending cards counted", async () => {
  await pendingCards(2);
  signalsMode = "throw";
  assert.equal(await attention(), 2, "the fix-it half is computed in its own try/catch");
});

test("no pending cards leaves the issues alone", async () => {
  assert.equal(await attention(), 3);
});

test("an urgent card's push points at the Attention sheet", async () => {
  registry.registerDetector({
    source: "test-fix-it-push",
    events: ["test-fix-it-push"],
    async onEvent(_eventName, _payload, bound) {
      await bound.upsertItem({
        source: "test-fix-it-push",
        dedupKey: "push-1",
        title: "A card that rings the bell",
        why: "why",
        severity: "urgent",
        remedies: [],
        context: {},
      });
    },
  });
  idx.wireFixIt();
  await idx.emitFixIt(db, "test-fix-it-push", {});

  const { rows } = await db.execute({
    sql: "SELECT action_url, source, priority FROM notifications WHERE source = 'fix-it'",
    args: [],
  });
  assert.equal(rows.length, 1, "one push for one new urgent card");
  assert.equal(rows[0].action_url, "/dashboard/attention",
    "the push opens the Attention sheet, not the Nest");
  assert.equal(rows[0].priority, "high");
});

test("the card push no longer hard-codes the Nest URL (source shape)", () => {
  const src = readFileSync(join(REPO, "servers/gateway/fix-it", "index.js"), "utf8");
  assert.ok(/action_url:\s*"\/dashboard\/attention"/.test(src),
    "boundStore's push must carry action_url: \"/dashboard/attention\"");
  assert.equal(src.includes('"/dashboard/nest?open=1"'), false,
    "the old action_url is gone from fix-it/index.js");
});