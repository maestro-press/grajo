/**
 * Essential notifications (createNotification's `essential: true`): the reports' failed and empty run
 * notices and the restart notices are written whatever notification_prefs says, so switching a type off
 * cannot silence what the owner asked to always hear about. Everything else about such a notice is
 * unchanged: its text is masked, its bell badge refreshes and the deliver seam is called. A notice
 * without `essential` keeps the type gate exactly as before.
 */
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDbClient } from "../servers/db.js";
import { createNotification } from "../servers/shared/notifications.js";

const REPO = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const SECRET_LOOKING_VALUE = "abcd1234efgh5678";
const SOURCE = "reports";

let dir;
let db;

before(() => {
  dir = mkdtempSync(join(tmpdir(), "notif-essential-"));
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_HOME: dir, CROW_DATA_DIR: dir }, stdio: "pipe", cwd: REPO,
  });
  db = createDbClient(join(dir, "crow.db"));
});
after(() => {
  try { db.close(); } catch {}
  rmSync(dir, { recursive: true, force: true });
});
// Every test starts from an empty bell, so the rows it reads are the rows it wrote.
beforeEach(async () => {
  await db.execute({ sql: "DELETE FROM notifications", args: [] });
});

/** notification_prefs with only "system" enabled: a "reports" notice is switched off. */
async function reportsSwitchedOff() {
  await db.execute({
    sql: "INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('notification_prefs', ?)",
    args: [JSON.stringify({ types_enabled: ["system"] })],
  });
}
async function prefsCleared() {
  await db.execute({ sql: "DELETE FROM dashboard_settings WHERE key = 'notification_prefs'", args: [] });
}
async function rowsForReports() {
  const { rows } = await db.execute({
    sql: "SELECT * FROM notifications WHERE source = ? ORDER BY id",
    args: [SOURCE],
  });
  return rows;
}

const base = (extra) => ({
  type: "reports",
  source: SOURCE,
  title: "A report run failed",
  priority: "high",
  action_url: "/dashboard/project/demo/reports/rpt-00000000000000ff",
  ...extra,
});

test("a failed-run notice is written even when types_enabled excludes reports", async () => {
  await reportsSwitchedOff();
  const delivered = [];
  try {
    const made = await createNotification(db, base({
      body: "Morning brief did not finish.",
      essential: true,
      deliver: async (_db, payload) => { delivered.push(payload); },
    }));
    assert.ok(made, "an essential notice is written whatever the type preferences say");
    assert.equal(delivered.length, 1, "the deliver seam is still called");
    const rows = await rowsForReports();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].type, "reports");
    assert.equal(rows[0].priority, "high");
    assert.equal(rows[0].body, "Morning brief did not finish.");
  } finally {
    await prefsCleared();
  }
});

test("a non-essential reports notice still honours types_enabled", async () => {
  await reportsSwitchedOff();
  const delivered = [];
  try {
    const made = await createNotification(db, base({
      body: "Morning brief ran.",
      deliver: async (_db, payload) => { delivered.push(payload); },
    }));
    assert.equal(made, null, "the type gate still answers null");
    assert.equal((await rowsForReports()).length, 0, "and no row is written");
    assert.equal(delivered.length, 0, "and nothing is delivered");
  } finally {
    await prefsCleared();
  }
});

test("an essential notice still gets masked text", async () => {
  await reportsSwitchedOff();
  try {
    await createNotification(db, base({
      title: "A report run failed",
      body: `The feed answered X_API_KEY=${SECRET_LOOKING_VALUE}`,
      essential: true,
      deliver: false,
    }));
    const rows = await rowsForReports();
    assert.equal(rows.length, 1);
    assert.ok(!rows[0].body.includes(SECRET_LOOKING_VALUE), "the value is masked before the row is written");
    assert.match(rows[0].body, /\[REDACTED\]/);
  } finally {
    await prefsCleared();
  }
});

test("the type gate still lets an enabled type through with or without essential", async () => {
  await prefsCleared();
  const delivered = [];
  const plain = await createNotification(db, base({
    body: "Morning brief ran.",
    deliver: async (_db, payload) => { delivered.push(payload); },
  }));
  assert.ok(plain && plain.id, "an enabled type is written");
  assert.equal(delivered.length, 1);
  assert.equal((await rowsForReports()).length, 1);
});