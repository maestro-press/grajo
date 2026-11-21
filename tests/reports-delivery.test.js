// Delivery: one run of one report becoming mail, and the owner's notices about it.
//
// Harness: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR under a temp dir, so nothing
// can touch a real Crow data dir), a report made live through the approvals module's own `approveGoLive`,
// real recipients through `proposeRecipient`/`approveRecipient`, a real mail account row, a real run row
// through `startRun`, and every outgoing seam injected: the send door's own caller is faked except in the
// one test that drives the real door behind a fake adapter, which is how `tests/reports-door.test.js`
// does it. No mail leaves this file.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-delivery-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const {
  DEFAULT_LINK_DAYS, LINK_DAYS_KEY, deliver, deliverPending, makeDeliver, makeDeliverPending,
} = await import("../servers/gateway/reports/delivery.js");
const { DEFAULT_EMPTY_TEXT } = await import("../servers/gateway/reports/document.js");
const { STORAGE_NEARLY_FULL_TEXT } = await import("../servers/gateway/reports/artifact-bridge.js");
const { EMAILS_SKIPPED_BODY } = await import("../servers/gateway/reports/email/copy.js");
const {
  approveGoLive, approveRecipient, proposeRecipient, revokeRecipient,
} = await import("../servers/gateway/reports/approvals.js");
const {
  createReport, getReport, saveRecipe, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { startRun } = await import("../servers/gateway/reports/run.js");
const { createSendToRest, listSends } = await import("../servers/gateway/reports/send-log.js");
const { registerReportsHook } = await import("../servers/gateway/reports/schedule-hook.js");
const { createAccount } = await import("../servers/gateway/mail/store/accounts.js");
const { MailError } = await import("../servers/gateway/mail/errors.js");
const { initArtifactsTables } = await import("../bundles/artifacts/server/init-tables.js");

const OWNER = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 7);
const PROJECT = 7;
const T0 = 1_700_000_000_000;
const BASE = "https://crow.example.ts.net";
const DAY_MS = 86_400_000;
const FOOTER = "Open this report: ";

/** The block registry stub these recipes need (the server's own registry validates them for real). */
const REGISTRY = Object.freeze({ filter: { sourceBearing: false } });

const RECIPE = {
  blocks: [{ id: "b1", type: "filter", settings: { field: "title", op: "exists" } }],
};

const open = [];

after(() => {
  for (const db of open) { try { db.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
});

beforeEach(() => {
  delete process.env.CROW_GATEWAY_URL;
});

/* ------------------------------------------------------------------- the harness */

let n = 0;

async function freshDb() {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  return db;
}

function approvalsDeps(over = {}) {
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    getRun: async () => null,
    senderReady: async () => true,
    registry: REGISTRY,
    getSecrets: () => [],
    ...over,
  };
}

async function addSchedule(db, { cron = "0 7 * * 1", tz = "Europe/Berlin" } = {}) {
  await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, tz) VALUES ('weekly-report', ?, ?)",
    args: [cron, tz],
  });
  const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
  return Number(rows[0].id);
}

async function addProject(db, { id = PROJECT, slug = "weekly-listings" } = {}) {
  await db.execute({
    sql: "INSERT INTO project_spaces (id, uuid, slug, name) VALUES (?, ?, ?, ?)",
    args: [id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", slug, slug],
  });
}

/**
 * A live report with a schedule, a sender account, a project (so a tier `c` link resolves) and the owner's
 * own manual run row. The run OBJECT handed to `deliver` is the mapped row a finished run has.
 */
async function world({ address = "reports@example.com", title = "Weekly listings" } = {}) {
  const db = await freshDb();
  const scheduleId = await addSchedule(db);
  await addProject(db);
  const account = await createAccount(db, {
    address,
    label: "Reports",
    username: address,
    authKind: "password",
    imap: { host: "imap.example.com", port: 993, security: "ssl" },
    smtp: { host: "smtp.example.com", port: 465, security: "ssl" },
  });
  const { id } = await createReport(db, { projectId: PROJECT, owner: "owner", botId: "bot-1", title });
  const saved = await saveRecipe(db, {
    reportId: id, recipe: RECIPE, authorKind: "owner", registry: REGISTRY,
  });
  await updateReportColumns(db, id, {
    schedule_id: scheduleId,
    sender_account_id: account.id,
    delivery_mode: "email_link",
    comment_tier_default: "c",
    comment_visibility: "own",
    ai_commentary: 0,
  });
  const preview = { id: "prv-1", reportId: id, kind: "preview", status: "ok", recipeRev: saved.rev };
  await approveGoLive(db, approvalsDeps({
    getRun: async (_db, runId) => (runId === "prv-1" ? preview : null),
  }), { reportId: id, previewRunId: "prv-1", actor: OWNER });
  const { runId } = await startRun(db, { now: () => T0 }, {
    reportId: id, trigger: "manual", requestedBy: "owner",
  });
  const report = await getReport(db, id);
  const run = {
    id: runId, reportId: id, trigger: "manual", requestedBy: "owner", status: "ok",
    recipeRev: saved.rev, blockLog: { items: 1, sourceErrors: [] }, errorText: null, late: 0,
  };
  return { db, reportId: id, account, runId, preview, report, run };
}

async function recipientFor(db, reportId, { address = "alex@example.com", tier = null, approve = true } = {}) {
  const proposed = await proposeRecipient(db, approvalsDeps(), {
    reportId, address, displayName: "Alex", commentTier: tier, proposedBy: "owner",
  });
  if (!approve) return proposed;
  return approveRecipient(db, approvalsDeps(), { recipientId: proposed.id, actor: OWNER });
}

/** The deps delivery takes, with every outgoing seam a recorder. */
function deliveryDeps(over = {}) {
  const base = {
    approvals: approvalsDeps(),
    now: () => T0,
    getSecrets: () => [],
    baseUrl: BASE,
    notify: async () => null,
    holdVersion: async () => ({}),
    sendMail: async () => ({ status: "sent" }),
  };
  for (const [key, value] of Object.entries(over)) {
    if (value === undefined) delete base[key];
    else base[key] = value;
  }
  return base;
}

/**
 * A fake send door: every mail it is handed lands in `calls`. With `settle` it also moves the row the way
 * the real door does before it answers, so a test can drive a row that a later delivery must leave alone.
 */
function recorder({ status = "sent", throws = null, settle = false } = {}) {
  const calls = [];
  const sendMail = async (db, _doorDeps, input) => {
    calls.push(input);
    if (settle) {
      await db.execute({
        sql: "UPDATE report_sends SET status = ?, updated_at = ? WHERE id = ?",
        args: [status, T0, input.sendId],
      });
    }
    if (throws) throw throws;
    return { status };
  };
  return { calls, sendMail };
}

/** A fake notify: every notice lands in `notes`. */
function notes() {
  const list = [];
  return { list, notify: async (_db, note) => { list.push(note); } };
}

const rowsOf = async (db, sql, args = []) => (await db.execute({ sql, args })).rows;

const sendRows = (db, runId) => rowsOf(
  db, "SELECT * FROM report_sends WHERE run_id = ? ORDER BY attempt ASC", [runId],
);

/** One `report_sends` row, written the way send-log.js or an earlier attempt writes it. */
async function addSendRow(db, {
  id, runId, reportId, recipientId, attempt, accountId = null, status = "pending", reason = null,
}) {
  await db.execute({
    sql: `INSERT INTO report_sends
            (id, run_id, report_id, recipient_id, attempt, account_id, status, reason,
             created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [id, runId, reportId, recipientId, attempt, accountId, status, reason, T0, T0],
  });
  return id;
}

/** The run is finished, so "Send to the rest" may write a row for it. */
async function finishRun(db, runId) {
  await db.execute({
    sql: "UPDATE report_runs SET status = 'ok', ended_at = ? WHERE id = ?",
    args: [T0, runId],
  });
}

const noticeRows = (db) => rowsOf(db, "SELECT * FROM notifications WHERE source = 'reports' ORDER BY id");

async function prefsOff(db) {
  await db.execute({
    sql: "INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('notification_prefs', ?)",
    args: [JSON.stringify({ types_enabled: ["system"] })],
  });
}

/* ------------------------------------------------------------------- honest runs */

test("an empty run still mails every approved recipient the honest line", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const mail = recorder();
  const counts = await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: w.report, run: { ...w.run, status: "empty" }, live: null, status: "empty",
    artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 1, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.equal(mail.calls.length, 1, "one mail for one approved recipient");
  assert.ok(mail.calls[0].text.includes(DEFAULT_EMPTY_TEXT), "the honest line is in the body");
  assert.ok(mail.calls[0].text.includes(FOOTER), "and the link is in the footer");
  const [row] = await sendRows(w.db, w.runId);
  assert.equal(row.status, "pending", "the fake door never settles a row, so it stays pending");
});

test("a failed run's email names the source and carries no half report", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const mail = recorder();
  const counts = await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: { ...w.report, delivery_mode: "email_full" },
    run: { ...w.run, status: "failed", errorText: "Couldn't reach Mail." },
    live: null,
    status: "failed",
    artifactVersion: null,
    // The document the blocks had assembled before the source failed: a failed run never mails it.
    result: { document: { markdown: "# Big table\n\n| a | b |\n| --- | --- |\n| 1 | 2 |" } },
  });
  assert.equal(counts.sent, 1);
  assert.ok(mail.calls[0].text.includes("Couldn't reach Mail."), "the source is named");
  assert.ok(!mail.calls[0].html.includes("Big table"), "no half report in the html");
  assert.ok(!mail.calls[0].text.includes("Big table"), "no half report in the text");
  assert.ok(mail.calls[0].text.includes(FOOTER), "the reader still gets a way to the report");
});

test("every email carries the dashboard link into the run it is about", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const mail = recorder();
  await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  const url = `${BASE}/dashboard/project/weekly-listings/reports/${w.reportId}/runs/${w.runId}`;
  assert.ok(mail.calls[0].text.includes(url), mail.calls[0].text);
  assert.ok(mail.calls[0].html.includes(`href="${url}"`), "the html carries it as the footer's link");
});

/* ------------------------------------------------------- who gets a row and a mail */

test("one send row per approved recipient, and none for a proposed or revoked one", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId, { address: "alex@example.com" });
  await recipientFor(w.db, w.reportId, { address: "sam@example.com" });
  const proposed = await recipientFor(w.db, w.reportId, { address: "nim@example.com", approve: false });
  const revoked = await recipientFor(w.db, w.reportId, { address: "old@example.com" });
  await revokeRecipient(w.db, approvalsDeps(), { recipientId: revoked.id, actor: OWNER });
  assert.equal(proposed.state, "proposed");

  const mail = recorder();
  const counts = await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 2, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.equal(mail.calls.length, 2);
  const rows = await sendRows(w.db, w.runId);
  assert.equal(rows.length, 2, "one row per approved recipient");
  assert.equal(new Set(rows.map((row) => row.recipient_id)).size, 2, "one row each, not two for one");
  for (const row of rows) {
    assert.equal(row.status, "pending");
    assert.equal(row.attempt, 1);
    assert.equal(row.account_id, w.account.id, "the report's own sender account");
    assert.equal(row.report_id, w.reportId);
  }
});

test("a recipient with no link kind is skipped, with no row and no mail", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId, { address: "outside@example.com", tier: "a" });
  const mail = recorder();
  const counts = await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 1 });
  assert.equal(mail.calls.length, 0);
  assert.equal((await sendRows(w.db, w.runId)).length, 0, "nothing was claimed");
});

test("a preview delivers nothing and notifies nothing", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const mail = recorder();
  const bell = notes();
  const counts = await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail, notify: bell.notify }), {
    report: w.report,
    run: { ...w.run, trigger: "preview", status: "ok" },
    live: null,
    status: "ok",
    artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.equal(mail.calls.length, 0, "a preview is not an approved run");
  assert.equal((await sendRows(w.db, w.runId)).length, 0, "and it writes no row");
  assert.deepEqual(bell.list, [], "and the owner is told nothing");
});

/* ------------------------------------------------------------------- crow_only */

test("crow_only sends no email but still notifies the owner", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const report = { ...w.report, delivery_mode: "crow_only" };

  for (const status of ["empty", "failed"]) {
    const mail = recorder();
    const bell = notes();
    const counts = await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail, notify: bell.notify }), {
      report,
      run: status === "failed" ? { ...w.run, status, errorText: "Couldn't reach Mail." } : { ...w.run, status },
      live: null,
      status,
      artifactVersion: null,
    });
    assert.deepEqual(counts, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 0 }, status);
    assert.equal(mail.calls.length, 0, `${status}: no email at all`);
    assert.equal(bell.list.length, 1, `${status}: one notice`);
    assert.equal(bell.list[0].type, "reports");
    assert.equal(bell.list[0].source, "reports");
    assert.equal(bell.list[0].essential, true);
    assert.equal(bell.list[0].priority, status === "failed" ? "high" : "normal");
  }
  assert.equal((await sendRows(w.db, w.runId)).length, 0, "and no send row");
});

test("crow_only has no mail: its pending rows settle refused and nothing is sent", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  await updateReportColumns(w.db, w.reportId, { delivery_mode: "crow_only" });
  await finishRun(w.db, w.runId);
  const made = await createSendToRest(w.db, { approvals: approvalsDeps(), now: () => T0 }, {
    reportId: w.reportId, runId: w.runId, actor: OWNER,
  });
  assert.equal(made.created.length, 1, "the tap writes the row it would write for any report");

  const mail = recorder();
  const bell = notes();
  const counts = await deliverPending(w.db, deliveryDeps({ sendMail: mail.sendMail, notify: bell.notify }), {
    reportId: w.reportId, runId: w.runId,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.deepEqual(mail.calls, [], "a crow_only report sends no email at all");
  assert.deepEqual(bell.list, [], "and rings nothing about it");
  // Nothing will ever claim a row for a report with no mail, so it settles terminally instead of
  // sitting in the hook's scan for the life of the log.
  const row = (await sendRows(w.db, w.runId)).find((entry) => entry.id === made.created[0]);
  assert.equal(row.status, "refused");
  assert.equal(row.reason, "not_live");
  assert.equal(Number(row.updated_at), T0);
});

/* --------------------------------------------------------------- the pinned version */

/** A live world with an artifact whose newest recipient-safe version (3) is not the current one (7). */
async function artifactWorld() {
  const w = await world();
  await initArtifactsTables(w.db);
  await w.db.execute({
    sql: "INSERT INTO artifacts (id, title, type, current_version) VALUES ('art-1', 'Weekly listings', 'document', 7)",
    args: [],
  });
  for (const version of [3, 7]) {
    await w.db.execute({
      sql: `INSERT INTO artifact_versions (artifact_id, n, state, files_json, size, content_hash, made_by)
            VALUES ('art-1', ?, 'past', '[]', 0, 'abc', 'user')`,
      args: [version],
    });
  }
  return { ...w, report: { ...w.report, artifact_id: "art-1" } };
}

test("a version sent by a dashboard link is held, and it is never the artifact's current version", async () => {
  const w = await artifactWorld();
  await recipientFor(w.db, w.reportId);
  // A run row of an earlier attempt is on the artifact: version 3 is the newest a recipient may be shown,
  // while the artifact's current version is 7.
  await w.db.execute({
    sql: `INSERT INTO report_versions (artifact_id, n, report_id, run_id, "trigger", allowed_links_json, created_at)
          VALUES ('art-1', 3, ?, ?, 'schedule', '[]', ?)`,
    args: [w.reportId, w.runId, T0],
  });
  const held = [];
  const mail = recorder();
  const counts = await deliver(w.db, deliveryDeps({
    sendMail: mail.sendMail,
    holdVersion: async (args) => { held.push(args); return args; },
  }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.equal(counts.sent, 1);
  const [row] = await sendRows(w.db, w.runId);
  assert.equal(held.length, 1, "one hold for one sent version");
  assert.deepEqual(held[0], {
    artifactId: "art-1",
    n: 3,
    holder: `report-send:${row.id}`,
    until: T0 + DEFAULT_LINK_DAYS * DAY_MS,
  });
  assert.notEqual(held[0].n, 7, "never the artifact's current version");
});

test("the hold lasts the instance's own reports.link_days when one is set", async () => {
  const w = await artifactWorld();
  await recipientFor(w.db, w.reportId);
  await w.db.execute({
    sql: `INSERT INTO report_versions (artifact_id, n, report_id, run_id, "trigger", allowed_links_json, created_at)
          VALUES ('art-1', 3, ?, ?, 'schedule', '[]', ?)`,
    args: [w.reportId, w.runId, T0],
  });
  await w.db.execute({
    sql: `INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES (?, ?)`,
    args: [LINK_DAYS_KEY, "30"],
  });
  const held = [];
  await deliver(w.db, deliveryDeps({ holdVersion: async (args) => { held.push(args); return args; } }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.equal(held[0].until, T0 + 30 * DAY_MS);
});

test("an unknown outcome is held and is never resent by a later delivery", async () => {
  const w = await artifactWorld();
  await recipientFor(w.db, w.reportId);
  await w.db.execute({
    sql: `INSERT INTO report_versions (artifact_id, n, report_id, run_id, "trigger", allowed_links_json, created_at)
          VALUES ('art-1', 3, ?, ?, 'schedule', '[]', ?)`,
    args: [w.reportId, w.runId, T0],
  });
  const held = [];
  const mail = recorder({ status: "unknown", settle: true });
  const deps = deliveryDeps({ sendMail: mail.sendMail, holdVersion: async (args) => { held.push(args); } });
  const first = await deliver(w.db, deps, {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(first, { sent: 0, refused: 0, failed: 0, unknown: 1, skipped: 0 });
  assert.equal(held.length, 1, "an unknown send is held too: nobody knows whether it arrived");

  const second = await deliver(w.db, deps, {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(second, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 1 });
  assert.equal(mail.calls.length, 1, "an unknown row is never retried automatically");
  assert.equal((await sendRows(w.db, w.runId)).length, 1, "and no second row was written");
});

test("a pending row from Send to the rest is reused, not duplicated", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  // "Send to the rest" needs a finished run: the row is ok in the database, as a delivered run's is.
  await w.db.execute({
    sql: "UPDATE report_runs SET status = 'ok', ended_at = ? WHERE id = ?",
    args: [T0, w.runId],
  });
  const made = await createSendToRest(w.db, { approvals: approvalsDeps(), now: () => T0 }, {
    reportId: w.reportId, runId: w.runId, actor: OWNER,
  });
  assert.equal(made.created.length, 1);

  const mail = recorder();
  const counts = await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.equal(counts.sent, 1);
  assert.equal(mail.calls.length, 1);
  assert.equal(mail.calls[0].sendId, made.created[0], "the owner's own pending row is the one sent");
  const rows = await listSends(w.db, { reportId: w.reportId, runId: w.runId });
  assert.equal(rows.length, 1, "one row, not two");
});

/* ---------------------------------------------------------------- owner notices */

test("a failed notice is written even when the owner's type settings exclude reports", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  await prefsOff(w.db);
  // The real createNotification against this database: `essential` is what gets it past the type gate.
  const counts = await deliver(w.db, deliveryDeps({ notify: undefined }), {
    report: w.report,
    run: { ...w.run, status: "failed", errorText: "Couldn't reach Mail." },
    live: null,
    status: "failed",
    artifactVersion: null,
  });
  assert.equal(counts.sent, 1);
  const notices = await noticeRows(w.db);
  const failed = notices.filter((row) => /this run failed/.test(row.title));
  assert.equal(failed.length, 1, "the failed-run notice is written whatever the type settings say");
  assert.equal(failed[0].priority, "high");
  assert.equal(failed[0].action_url, `/dashboard/project/weekly-listings/reports/${w.reportId}`);
});

test("an ok run notifies only when notify_every_run is on, and that notice is not essential", async () => {
  const quiet = await world();
  await recipientFor(quiet.db, quiet.reportId);
  await prefsOff(quiet.db);
  await deliver(quiet.db, deliveryDeps({ notify: undefined }), {
    report: quiet.report, run: quiet.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(await noticeRows(quiet.db), [], "a quiet report says nothing about an ok run");

  const asked = await world();
  await recipientFor(asked.db, asked.reportId);
  await prefsOff(asked.db);
  await updateReportColumns(asked.db, asked.reportId, { notify_every_run: 1 });
  const report = await getReport(asked.db, asked.reportId);
  await deliver(asked.db, deliveryDeps({ notify: undefined }), {
    report, run: asked.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(await noticeRows(asked.db), [],
    "the notify-every-run notice is NOT essential, so a switched-off type still drops it");
});

test("the notify-every-run notice is written, normal priority, when the type is on", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  await updateReportColumns(w.db, w.reportId, { notify_every_run: 1 });
  const report = await getReport(w.db, w.reportId);
  const bell = notes();
  await deliver(w.db, deliveryDeps({ notify: bell.notify }), {
    report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.equal(bell.list.length, 1);
  assert.match(bell.list[0].title, /is ready$/);
  assert.equal(bell.list[0].priority, "normal");
  assert.equal(bell.list[0].essential, false);
});

test("a storage nearly full failure reaches the owner's notice", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const bell = notes();
  await deliver(w.db, deliveryDeps({ notify: bell.notify }), {
    report: w.report,
    run: { ...w.run, status: "failed", errorText: STORAGE_NEARLY_FULL_TEXT },
    live: null,
    status: "failed",
    artifactVersion: null,
    // No version was written: the run failed before the version step.
    result: null,
  });
  assert.equal(bell.list.length, 1);
  assert.equal(bell.list[0].title, "Weekly listings: this run failed");
  assert.equal(bell.list[0].body, STORAGE_NEARLY_FULL_TEXT, "the sentence the owner can act on");
});

test("a failure notice body is one redacted line, bounded", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const bell = notes();
  const secret = "swordfish-value";
  const long = `line one\r\n${secret} ${"x".repeat(900)}`;
  await deliver(w.db, deliveryDeps({
    notify: bell.notify,
    getSecrets: () => [secret],
  }), {
    report: w.report,
    run: { ...w.run, status: "failed", errorText: long },
    live: null,
    status: "failed",
    artifactVersion: null,
  });
  const body = bell.list[0].body;
  assert.ok(!body.includes(secret), "a secret never reaches a notice");
  assert.ok(!body.includes("\n") && !body.includes("\r"), "one line");
  assert.ok(body.length <= 300, `bounded (${body.length})`);
});

test("every email that did not go out is counted in one more owner notice", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId, { address: "alex@example.com" });
  await recipientFor(w.db, w.reportId, { address: "sam@example.com" });
  await recipientFor(w.db, w.reportId, { address: "outside@example.com", tier: "a" });
  const mail = recorder({ status: "failed" });
  const bell = notes();
  const counts = await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail, notify: bell.notify }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 2, unknown: 0, skipped: 1 });
  const notSent = bell.list.filter((note) => /some emails were not sent/.test(note.title));
  assert.equal(notSent.length, 1, "exactly one notice about the emails");
  assert.equal(notSent[0].essential, true);
  assert.equal(notSent[0].priority, "high");
  assert.equal(notSent[0].body, "0 sent, 0 unknown, 2 not sent.", "plain counts");
});

test("one recipient's throw is a failed send for that recipient only", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId, { address: "alex@example.com" });
  await recipientFor(w.db, w.reportId, { address: "sam@example.com" });
  let seen = 0;
  const sendMail = async () => {
    seen += 1;
    if (seen === 1) throw new Error("the mail server refused");
    return { status: "sent" };
  };
  const counts = await deliver(w.db, deliveryDeps({ sendMail }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 1, refused: 0, failed: 1, unknown: 0, skipped: 0 });
  assert.equal(seen, 2, "the second recipient was still tried");
});

/* ------------------------------------------------------------ the outgoing body */

test("a whole-URL table cell the run's items do not carry is not a live link in the mail", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const markdown = "| Site | Link |\n| --- | --- |\n| Listings | https://listings.example.com/42 |";
  const report = { ...w.report, delivery_mode: "email_full" };

  const withoutLink = recorder();
  await deliver(w.db, deliveryDeps({ sendMail: withoutLink.sendMail }), {
    report, run: w.run, live: null, status: "ok", artifactVersion: null,
    result: { document: { markdown }, allowedLinks: [] },
  });
  const html = withoutLink.calls[0].html;
  assert.ok(!html.includes(`href="https://listings.example.com/42"`), "not clickable");
  assert.ok(!html.includes("https://listings.example.com/42"), "and not written out as a URL either");
  assert.match(html, /\[link removed\]/);

  // The same cell IS a link when the run's own items carry that URL, so the rule is the allowed set.
  const withLink = recorder();
  await deliver(w.db, deliveryDeps({ sendMail: withLink.sendMail }), {
    report, run: w.run, live: null, status: "ok", artifactVersion: null,
    result: { document: { markdown }, allowedLinks: ["https://listings.example.com/42"] },
  });
  assert.ok(withLink.calls[0].html.includes(`href="https://listings.example.com/42"`));
});

test("a custom email template cannot drop the footer", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const mail = recorder();
  await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: { ...w.report, delivery_mode: "email_full" },
    run: w.run,
    live: null,
    status: "ok",
    artifactVersion: null,
    result: {
      document: { markdown: "# The report body" },
      email: { html: "<p>Our own words</p>", text: "Our own words" },
    },
  });
  const { html, text } = mail.calls[0];
  assert.ok(html.includes("Our own words"), "the template is the body");
  assert.ok(!html.includes("The report body"), "and it replaces the report content");
  assert.match(html, /Open this report: <a href="https:\/\/crow\.example\.ts\.net\/dashboard\//);
  assert.ok(text.trimEnd().endsWith(`${FOOTER}${BASE}/dashboard/project/weekly-listings/reports/${w.reportId}/runs/${w.runId}`),
    "the footer is the last thing in the text");
});

test("a custom template's links that the items do not carry are neutralised", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const mail = recorder();
  await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: { ...w.report, delivery_mode: "email_full" },
    run: w.run,
    live: null,
    status: "ok",
    artifactVersion: null,
    result: {
      document: { markdown: "# Body" },
      allowedLinks: [],
      email: {
        html: '<p><a href="https://other.example.com/page">other</a></p>',
        text: "see https://other.example.com/page",
      },
    },
  });
  const { html, text } = mail.calls[0];
  assert.ok(!html.includes(`href="https://other.example.com/page"`), "not a live link");
  assert.match(html, /\[link removed\]/);
  assert.ok(!text.includes("https://other.example.com/page"), "and not in the text either");
});

test("a run's own email body is sanitised, and the footer still ends both halves", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const mail = recorder();
  await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: { ...w.report, delivery_mode: "email_full" },
    run: w.run,
    live: null,
    status: "ok",
    artifactVersion: null,
    result: {
      document: { markdown: "# The report body" },
      email: {
        html: [
          "<p>Our own words</p>",
          '<script>alert("x")</script>',
          '<p onclick="steal()">tap here</p>',
          '<form action="https://evil.example/post"><input name="q"></form>',
          '<iframe src="https://evil.example/frame"></iframe>',
          '<p><a href="javascript:alert(1)">bad link</a></p>',
        ].join(""),
        text: "Our own words",
      },
    },
  });
  const { html, text } = mail.calls[0];
  assert.ok(html.includes("<p>Our own words</p>"), "the step's own body is the mail body");
  assert.ok(!html.includes("The report body"), "and it replaces the document");
  for (const raw of ["<script", "onclick", "<form", "<iframe", "javascript:"]) {
    assert.ok(!html.toLowerCase().includes(raw), `${raw} does not survive: ${html}`);
  }
  assert.ok(html.includes("tap here"), "the words of the stripped element stay");
  const url = `${BASE}/dashboard/project/weekly-listings/reports/${w.reportId}/runs/${w.runId}`;
  assert.ok(html.endsWith(`<p>${FOOTER}<a href="${url}">${url}</a></p>`),
    "the footer is the last thing in the html");
  assert.ok(text.includes("Our own words"));
  assert.ok(text.endsWith(`${FOOTER}${url}`), "the footer is the last thing in the text");
});

test("a link in a run's own email body is live only when the run's items carry it", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const kept = "https://listings.example.com/a";
  const mail = recorder();
  await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: { ...w.report, delivery_mode: "email_full" },
    run: w.run,
    live: null,
    status: "ok",
    artifactVersion: null,
    result: {
      document: { markdown: "# Body" },
      allowedLinks: [kept],
      email: {
        html: '<p><a href="https://other.example.com/page">other</a> and '
          + `<a href="${kept}">ours</a></p>`,
        text: `other https://other.example.com/page ours ${kept}`,
      },
    },
  });
  const { html, text } = mail.calls[0];
  assert.ok(html.includes(`href="${kept}"`), "the run's own URL is a live link");
  assert.ok(!html.includes('href="https://other.example.com/page"'), "a URL it does not carry is not");
  assert.match(html, /\[link removed\]/, "the refused link becomes the plain marker");
  assert.ok(text.includes(kept), "the run's own URL stays in the text");
  assert.ok(!text.includes("https://other.example.com/page"), "the other one is not in the text either");
  assert.match(text, /\[link removed\]/);
});

test("an empty or invalid run email falls back to the document body", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const url = `${BASE}/dashboard/project/weekly-listings/reports/${w.reportId}/runs/${w.runId}`;
  for (const email of [null, {}, { html: "", text: "" }, "not a body"]) {
    const mail = recorder();
    await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
      report: { ...w.report, delivery_mode: "email_full" },
      run: w.run,
      live: null,
      status: "ok",
      artifactVersion: null,
      result: { document: { markdown: "# The report body" }, allowedLinks: [], email },
    });
    const { html, text } = mail.calls[0];
    assert.ok(html.includes("The report body"), `${JSON.stringify(email)}: the default layout is used`);
    assert.ok(text.includes("The report body"), `${JSON.stringify(email)}: in the text too`);
    assert.ok(text.endsWith(`${FOOTER}${url}`), `${JSON.stringify(email)}: and the footer still ends it`);
  }
});

/* ----------------------------------------------------------------- the real door */

test("an app-password Crow Mail account can be the sender", async () => {
  const w = await world();
  const recipient = await recipientFor(w.db, w.reportId);
  const sent = [];
  // The real door, behind a fake adapter: the door builds and claims the message, the adapter is the
  // only thing that would have reached a server.
  const counts = await deliver(w.db, deliveryDeps({
    sendMail: undefined,
    adapterFor: async (account, fn) => {
      assert.equal(account.id, w.account.id, "the report's own sender");
      return fn({
        send: async (message) => {
          sent.push(message);
          return { messageId: "<provider-1@example.com>", accepted: [{ address: recipient.address }], rejected: [] };
        },
      });
    },
  }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 1, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.equal(sent.length, 1);
  assert.equal(sent[0].to.length, 1);
  assert.equal(sent[0].to[0].address, recipient.address);
  assert.equal(sent[0].from.address, w.account.address);
  assert.match(sent[0].subject, /Weekly listings/);
  assert.match(sent[0].text, /Open this report: /);

  const [row] = await sendRows(w.db, w.runId);
  assert.equal(row.status, "sent", "the door settled the row");
  assert.match(row.message_id, /^<[0-9a-f]{32}@example\.com>$/);
  assert.equal(row.provider_message_id, "<provider-1@example.com>");
});

/* ------------------------------------------------------------------ the seam */

test("makeDeliver hands run.js's payload and its own deps to deliver", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const mail = recorder();
  const seam = makeDeliver({
    approvals: approvalsDeps(),
    now: () => T0,
    getSecrets: () => [],
    baseUrl: BASE,
    notify: async () => null,
    holdVersion: async () => ({}),
    sendMail: mail.sendMail,
  });
  assert.equal(typeof seam, "function");
  const counts = await seam(w.db, {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null, result: null,
  });
  assert.equal(counts.sent, 1);
  assert.equal(mail.calls.length, 1);
});

/* --------------------------------------------------- a recipient with no link */

test("a recipient with no resolvable dashboard base is skipped, and the owner hears there was no link", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId, { address: "alex@example.com" });
  await recipientFor(w.db, w.reportId, { address: "sam@example.com" });
  const mail = recorder();
  const bell = notes();
  // No base URL, no CROW_DASHBOARD_URL and no CROW_GATEWAY_URL: links.js answers null, because a mail
  // client cannot open a path.
  const counts = await deliver(w.db, deliveryDeps({
    sendMail: mail.sendMail, notify: bell.notify, baseUrl: undefined,
  }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 2 });
  assert.equal(mail.calls.length, 0, "nothing was mailed");
  assert.equal((await sendRows(w.db, w.runId)).length, 0, "and nothing was claimed");
  assert.equal(bell.list.length, 1, "one notice for the run, not one per recipient");
  assert.equal(bell.list[0].title, "Weekly listings: some emails could not be sent, no link");
  assert.equal(bell.list[0].body, EMAILS_SKIPPED_BODY);
  assert.equal(bell.list[0].essential, true, "nothing else records that the mail did not go");
  assert.equal(bell.list[0].priority, "high");
  assert.equal(bell.list[0].action_url, `/dashboard/project/weekly-listings/reports/${w.reportId}`);
});

test("a recipient already spoken for on an earlier call is skipped without a skip notice", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const mail = recorder({ settle: true }); // the door settles the row it was handed
  const bell = notes();
  const deps = deliveryDeps({ sendMail: mail.sendMail, notify: bell.notify });

  const first = await deliver(w.db, deps, {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(first, { sent: 1, refused: 0, failed: 0, unknown: 0, skipped: 0 });

  const second = await deliver(w.db, deps, {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(second, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 1 },
    "this run and this recipient are already spoken for");
  assert.equal(mail.calls.length, 1, "nothing was mailed twice");
  assert.deepEqual(bell.list, [], "a settled row is not a miss: no skip notice, and no other notice either");
});

/* --------------------------------------------------- no mail supervisor, no "unknown" */

test("a delivery whose adapter source says stopped counts failed and holds nothing", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  const held = [];
  const bell = notes();
  // The real door, with boot's own answer for a gateway that runs no supervisor.
  const counts = await deliver(w.db, deliveryDeps({
    sendMail: undefined,
    adapterFor: () => Promise.reject(new MailError("NETWORK", "stopped")),
    holdVersion: async (args) => { held.push(args); },
    notify: bell.notify,
  }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 1, unknown: 0, skipped: 0 });
  assert.deepEqual(held, [], "nothing was sent, so no version is held");
  const [row] = await sendRows(w.db, w.runId);
  assert.equal(row.status, "failed", "mail that never left is not left as possibly sent");
  assert.equal(row.reason, "no_adapter");
  const notSent = bell.list.filter((note) => /some emails were not sent/.test(note.title));
  assert.equal(notSent.length, 1, "the owner hears that the email did not go");
  assert.equal(notSent[0].body, "0 sent, 0 unknown, 1 not sent.");
});

/* ------------------------------------------------- a pending row next to a failed one */

/** A finished run with a failed attempt 1 and the pending attempt 2 "Send to the rest" wrote. */
async function pendingAfterFailure(w, recipient) {
  await finishRun(w.db, w.runId);
  await addSendRow(w.db, {
    id: "rsd-failed-00000001",
    runId: w.runId,
    reportId: w.reportId,
    recipientId: recipient.id,
    attempt: 1,
    accountId: w.account.id,
    status: "failed",
    reason: "network",
  });
  const made = await createSendToRest(w.db, { approvals: approvalsDeps(), now: () => T0 }, {
    reportId: w.reportId, runId: w.runId, actor: OWNER,
  });
  assert.equal(made.created.length, 1, "the owner's tap wrote the second attempt");
  return made.created[0];
}

test("deliver sends the pending row written after a failed attempt, and writes no third", async () => {
  const w = await world();
  const recipient = await recipientFor(w.db, w.reportId);
  const pendingId = await pendingAfterFailure(w, recipient);

  const mail = recorder();
  const counts = await deliver(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    report: w.report, run: w.run, live: null, status: "ok", artifactVersion: null,
  });
  assert.deepEqual(counts, { sent: 1, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.equal(mail.calls.length, 1);
  assert.equal(mail.calls[0].sendId, pendingId, "the pending row is the one that goes");
  const rows = await sendRows(w.db, w.runId);
  assert.equal(rows.length, 2, "no third attempt was written");
});

test("deliverPending sends the pending row written after a failed attempt, and writes no row", async () => {
  const w = await world();
  const recipient = await recipientFor(w.db, w.reportId);
  const pendingId = await pendingAfterFailure(w, recipient);

  const mail = recorder({ settle: true });
  const counts = await deliverPending(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    reportId: w.reportId, runId: w.runId,
  });
  assert.deepEqual(counts, { sent: 1, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.equal(mail.calls.length, 1);
  assert.equal(mail.calls[0].sendId, pendingId, "the row the owner's tap wrote is the one that goes");
  assert.ok(mail.calls[0].text.includes(
    `${BASE}/dashboard/project/weekly-listings/reports/${w.reportId}/runs/${w.runId}`,
  ), "the mail carries the run's link, built the way deliver builds it");
  const rows = await sendRows(w.db, w.runId);
  assert.equal(rows.length, 2, "deliverPending made no row of its own");
  assert.equal(rows.find((row) => row.id === pendingId).status, "sent");
});

test("deliverPending writes no row for a recipient this run has none for", async () => {
  const w = await world();
  await recipientFor(w.db, w.reportId);
  await finishRun(w.db, w.runId);

  const mail = recorder();
  const counts = await deliverPending(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    reportId: w.reportId, runId: w.runId,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.equal(mail.calls.length, 0, "nothing to send");
  assert.equal((await sendRows(w.db, w.runId)).length, 0, "an approved recipient is not written to here");
});

test("deliverPending never sends beside a row that already went", async () => {
  const w = await world();
  const recipient = await recipientFor(w.db, w.reportId);
  await finishRun(w.db, w.runId);
  await addSendRow(w.db, {
    id: "rsd-sent-0000000001", runId: w.runId, reportId: w.reportId, recipientId: recipient.id,
    attempt: 1, accountId: w.account.id, status: "sent",
  });
  await addSendRow(w.db, {
    id: "rsd-pending-0000001", runId: w.runId, reportId: w.reportId, recipientId: recipient.id,
    attempt: 2, accountId: w.account.id, status: "pending",
  });

  const mail = recorder();
  const counts = await deliverPending(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    reportId: w.reportId, runId: w.runId,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 1 });
  assert.equal(mail.calls.length, 0, "a sent row is the answer never again");
  const rows = await sendRows(w.db, w.runId);
  const beside = rows.find((row) => row.id === "rsd-pending-0000001");
  assert.equal(beside.status, "refused", "the row can never go, so it settles instead of waiting");
  assert.equal(beside.reason, "not_pending", "the door's own word for a row that lost its turn");
  assert.equal(rows.find((row) => row.id === "rsd-sent-0000000001").status, "sent",
    "and the row that went is never rewritten");
});

test("a no-link pending row settles failed, and the owner's next tap is not blocked by it", async () => {
  const w = await world();
  // A tier `a` recipient has no link kind yet, so nothing can be claimed or mailed for it.
  await recipientFor(w.db, w.reportId, { tier: "a" });
  await finishRun(w.db, w.runId);
  const tap = { approvals: approvalsDeps(), now: () => T0 };
  const made = await createSendToRest(w.db, tap, { reportId: w.reportId, runId: w.runId, actor: OWNER });
  assert.equal(made.created.length, 1);

  const mail = recorder();
  const bell = notes();
  const counts = await deliverPending(w.db, deliveryDeps({ sendMail: mail.sendMail, notify: bell.notify }), {
    reportId: w.reportId, runId: w.runId,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 1 },
    "a row with no link is a skip, not a failed send");
  assert.equal(mail.calls.length, 0, "nothing was mailed");
  const settled = (await sendRows(w.db, w.runId)).find((row) => row.id === made.created[0]);
  assert.equal(settled.status, "failed");
  assert.equal(settled.reason, "no_link");
  assert.equal(bell.list.length, 1, "and still exactly one notice");
  assert.match(bell.list[0].title, /no link$/);

  // The settled row no longer reads as "pending", so the owner's next tap writes a new attempt.
  const again = await createSendToRest(w.db, tap, { reportId: w.reportId, runId: w.runId, actor: OWNER });
  assert.equal(again.created.length, 1, "a settled row no longer blocks the next tap");
  assert.notEqual(again.created[0], made.created[0]);
  assert.deepEqual((await sendRows(w.db, w.runId)).map((row) => row.attempt), [1, 2],
    "a new attempt beside the settled one");
});

/* --------------------------------------------------- a recipient read that fails */

test("a recipient read that throws settles nothing and rejects read_failed", async () => {
  const w = await world();
  const recipient = await recipientFor(w.db, w.reportId);
  await finishRun(w.db, w.runId);
  const pendingId = await addSendRow(w.db, {
    id: "rsd-readfail-0000001", runId: w.runId, reportId: w.reportId, recipientId: recipient.id,
    attempt: 1, accountId: w.account.id, status: "pending",
  });

  const mail = recorder();
  const bell = notes();
  // The recipients table is the read `listRecipients` goes through: a database that cannot answer it
  // knows nothing about who may be mailed, so no row may be settled on that answer.
  const broken = {
    async execute(arg) {
      const sql = typeof arg === "string" ? arg : String(arg?.sql ?? "");
      if (/FROM report_recipients/.test(sql)) throw new Error("report_recipients is busy");
      return w.db.execute(arg);
    },
  };

  await assert.rejects(
    deliverPending(broken, deliveryDeps({ sendMail: mail.sendMail, notify: bell.notify }), {
      reportId: w.reportId, runId: w.runId,
    }),
    (err) => err.code === "read_failed",
  );
  assert.deepEqual(mail.calls, [], "nothing was mailed");
  assert.deepEqual(bell.list, [], "and nothing was said about a question nobody could answer");
  const row = (await sendRows(w.db, w.runId)).find((entry) => entry.id === pendingId);
  assert.equal(row.status, "pending", "no row is settled on a read that failed");
  assert.equal(row.reason, null);

  // The next call, with a database that answers, sends the row: it was never given up.
  const counts = await deliverPending(w.db, deliveryDeps({ sendMail: mail.sendMail, notify: bell.notify }), {
    reportId: w.reportId, runId: w.runId,
  });
  assert.deepEqual(counts, { sent: 1, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.equal(mail.calls.length, 1);
  assert.equal(mail.calls[0].sendId, pendingId);
});

test("a preview run is never sent by deliverPending", async () => {
  const w = await world();
  const recipient = await recipientFor(w.db, w.reportId);
  const preview = await startRun(w.db, { now: () => T0 }, {
    reportId: w.reportId, trigger: "preview", requestedBy: "owner",
  });
  await finishRun(w.db, preview.runId);
  await addSendRow(w.db, {
    id: "rsd-preview-0000001", runId: preview.runId, reportId: w.reportId, recipientId: recipient.id,
    attempt: 1, accountId: w.account.id, status: "pending",
  });

  const mail = recorder();
  const counts = await deliverPending(w.db, deliveryDeps({ sendMail: mail.sendMail }), {
    reportId: w.reportId, runId: preview.runId,
  });
  assert.deepEqual(counts, { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 0 });
  assert.equal(mail.calls.length, 0, "a preview is never approved mail");
  const [row] = await sendRows(w.db, preview.runId);
  assert.equal(row.status, "pending", "and its row is left as it was");
});

/* --------------------------------------------------- one row goes at most once */

test("concurrent deliverPending calls and hook passes send one pending row exactly once", async () => {
  const w = await world();
  const recipient = await recipientFor(w.db, w.reportId);
  await finishRun(w.db, w.runId);
  // The report's schedule row names the report, so the hook's row guard leaves the report live.
  await w.db.execute({
    sql: "UPDATE schedules SET task = ? WHERE id = (SELECT schedule_id FROM reports WHERE id = ?)",
    args: [`report:${w.reportId}`, w.reportId],
  });
  const pendingId = await addSendRow(w.db, {
    id: "rsd-once-0000000001", runId: w.runId, reportId: w.reportId, recipientId: recipient.id,
    attempt: 1, accountId: w.account.id, status: "pending",
  });

  // The real door, behind a fake adapter: the door's own pending -> sending claim is what can make the
  // row go once, so the adapter is the only thing that counts what left.
  const messages = [];
  const seam = makeDeliverPending(deliveryDeps({
    sendMail: undefined,
    now: () => T0,
    adapterFor: async (account, fn) => {
      assert.equal(account.id, w.account.id, "the report's own sender");
      return fn({
        send: async (message) => {
          messages.push(message);
          return {
            messageId: "<provider-once@example.com>",
            accepted: [{ address: recipient.address }],
            rejected: [],
          };
        },
      });
    },
  }));
  // The pending row was written at T0: the hook reads it well past its 30 s grace.
  const later = T0 + 60_000;
  const hook = registerReportsHook(w.db, {
    approvals: approvalsDeps(),
    now: () => later,
    notify: async () => null,
    instanceZone: async () => "UTC",
    getSecrets: () => [],
    lease: {
      now: () => later, pid: 4331, isPidAlive: () => true,
      kernelBootId: () => "boot-delivery", runId: "run-delivery",
    },
    deliverPending: seam,
  });
  const settle = () => new Promise((resolve) => setTimeout(resolve, 200));
  try {
    await Promise.all([
      seam(w.db, { reportId: w.reportId, runId: w.runId }),
      seam(w.db, { reportId: w.reportId, runId: w.runId }),
    ]);
    await hook.tick(w.db);
    hook.kick();
    await settle();

    assert.equal(messages.length, 1, "one row, one message, whatever overlapped");
    const rows = await sendRows(w.db, w.runId);
    assert.equal(rows.length, 1, "no second row was written");
    assert.equal(rows[0].id, pendingId);
    assert.equal(rows[0].status, "sent", "the one row ends sent");

    await hook.tick(w.db);
    await settle();
    assert.equal(messages.length, 1, "a later pass sends nothing beside it");
    assert.equal((await sendRows(w.db, w.runId))[0].status, "sent");
  } finally {
    await hook.stop();
  }
});