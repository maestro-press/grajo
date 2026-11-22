// Crow Recurring Reports' owner schedule clear (`DELETE /dashboard/api/reports/:id/schedule`) and the
// boot repair for a pointer to a schedule row that is not there.
//
// The route takes the report's own `schedules` rows and the pointer to them away in one transaction,
// applies the live-set rule to the report row in that same transaction, and answers the report without
// its seal. The repair nulls a pointer that names no `schedules` row and touches nothing else.
//
// Harness: the same world tests/reports-schedule-route.test.js builds — a real init-db'd scratch crow.db
// copied per test (CROW_DATA_DIR under a temp dir), an ephemeral express app wired the way the gateway
// and the dashboard wire it (the global JSON parser skipped by index.js's own `_hasOwnParser` list, read
// from its source; a session stub, the dashboard's real CSRF middleware, the real reports API router),
// the real report store and approvals module with an injected preview-run reader and a fixed clock, and
// the real owner rule with the request marked as coming from the owner's own client
// (tests/helpers/off-box.js).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import Database from "better-sqlite3";
import { markFromLaptop } from "./helpers/off-box.js";
import { csrfTokenFor } from "./helpers/csrf-token.mjs";

const root = mkdtempSync(join(tmpdir(), "reports-clear-schedule-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { default: express, json: expressJson } = await import("express");
const { createDbClient } = await import("../servers/db.js");
const { csrfMiddleware } = await import("../servers/gateway/dashboard/shared/csrf.js");
const { reportsApiRouter, REPORTS_API_PREFIX, OWNER_LABEL } =
  await import("../servers/gateway/routes/reports-api.js");
const { SETTINGS_CHANGED_PAUSE_REASON, updateSettings } = await import("../servers/gateway/reports/approvals.js");
const { createReport, getReport, saveRecipe, updateReportColumns } =
  await import("../servers/gateway/reports/store.js");
const { repairDanglingSchedulePointers } = await import("../servers/gateway/reports/schedule-clear.js");
const { startReportsAtBoot, _setReportsHookForTest } =
  await import("../servers/gateway/reports/schedule-hook.js");
const { unregisterSchedulerHook } = await import("../servers/gateway/scheduler-hooks.js");
const { REPORT_PREFIX } = await import("../servers/shared/schedule-core.js");

const OWNER = "owner-local-password-session";
const SSO = "peer-sso-session";
const SEED = Buffer.alloc(32, 5);
const PROJECT = 7;
const SENDER = "ma-0011223344556677";
const REGISTRY = { http_json: { sourceBearing: true }, filter: { sourceBearing: false } };
const RECIPE = {
  blocks: [
    { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=1" } },
    { id: "b2", type: "filter", settings: { field: "title", op: "exists" } },
  ],
};

/** The clock every world runs on: Monday 26 October 2026, 15:00 UTC. */
const T0 = Date.parse("2026-10-26T15:00:00.000Z");
const CRON = "0 9 * * 1";
const TZ = "America/Chicago";
const OTHER_CRON = "30 6 * * 2";

const hashToken = (t) => createHash("sha256").update(t).digest("hex");

let clock = T0;
const open = [];
const servers = [];
let server = null;

after(() => {
  for (const s of servers) s.close();
  for (const c of open) { try { c.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
  const raw = new Database(MASTER);
  const insert = raw.prepare(
    "INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at) VALUES (?, 'access', 'dashboard', ?, datetime('now','+1 day'))",
  );
  insert.run(hashToken(OWNER), "dashboard");
  insert.run(hashToken(SSO), "dashboard sso src:peer-1");
  raw.pragma("wal_checkpoint(TRUNCATE)");
  raw.close();
});

/* -------------------------------------------------------------------------- HTTP */

function parseCookies(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/** One request. `token: null` sends no session cookie; `csrf: null` sends no CSRF header (the default
 *  sends the server-bound token for THIS session); `laptop: false` leaves the request classified as
 *  coming from this machine. */
function call(method, path, { body, headers = {}, token = OWNER, csrf = true, laptop = true } = {}) {
  const payload = body === undefined ? null : (typeof body === "string" ? body : JSON.stringify(body));
  const h = { ...(payload === null ? {} : { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }) };
  if (token) h.cookie = "crow_session=" + token;
  if (token && csrf) h["x-crow-csrf"] = csrf === true ? csrfTokenFor(token) : String(csrf);
  if (laptop) h["x-test-from"] = "laptop";
  Object.assign(h, headers);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: server.address().port, method, path, headers: h }, (res) => {
      let text = "";
      res.on("data", (c) => { text += c; });
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on("error", reject);
    req.end(payload === undefined || payload === null ? undefined : payload);
  });
}

const del = (path, opts) => call("DELETE", path, opts);
const post = (path, body, opts) => call("POST", path, { body, ...opts });
const put = (path, body, opts) => call("PUT", path, { body, ...opts });

const reportPath = (id) => `${REPORTS_API_PREFIX}/${encodeURIComponent(id)}`;
const schedulePath = (id) => `${reportPath(id)}/schedule`;

/* ------------------------------------------------------------------------- setup */

let n = 0;

/** One test's world: a copied crow.db, a router over it, and the approvals seams it was built with. */
async function setup() {
  clock = T0;
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");
  const db = createDbClient(crow);
  open.push(db);

  const opened = { n: 0, closed: 0 };
  const openDb = () => {
    opened.n++;
    const c = createDbClient(crow);
    const close = c.close.bind(c);
    c.close = () => { opened.closed++; return close(); };
    return c;
  };

  const runTable = {};
  const approvalsDeps = {
    loadSeed: () => ({ seed: SEED }),
    now: () => clock,
    registry: REGISTRY,
    getRun: async (_db, runId) => runTable[runId] ?? null,
    senderReady: async () => true,
  };

  const app = express();
  const indexSrc = readFileSync(join(REPO, "servers/gateway/index.js"), "utf8");
  const predicate = /const _hasOwnParser = \(p\) => ([^\n]*\n[^\n]*);/.exec(indexSrc);
  assert.ok(predicate, "index.js's _hasOwnParser is where it was");
  const hasOwnParser = new Function("p", `return ${predicate[1]};`);
  const globalJson = expressJson({ limit: "1mb" });
  app.use((req, res, next) => (hasOwnParser(req.path) ? next() : globalJson(req, res, next)));

  const sessionGate = (req, res, next) => {
    const token = parseCookies(req.headers.cookie).crow_session;
    if (!token) return res.status(401).json({ error: "unauthorized" });
    req.dashboardSession = token;
    if (req.headers["x-test-from"] === "laptop") markFromLaptop(req);
    next();
  };
  const dash = express.Router();
  dash.use("/dashboard", csrfMiddleware);
  dash.use(reportsApiRouter(sessionGate, { openDb, approvalsDeps }));
  app.use(dash);

  server = await new Promise((r) => { const s = app.listen(0, "127.0.0.1", () => r(s)); });
  servers.push(server);

  return { db, crow, opened, runTable, approvalsDeps, hasOwnParser };
}

/** A saved report. `schedule` points it at a schedule row of its own that is NOT a report's row, which
 *  is what a report has before the page ever sets one. The sender is sealed the way the owner's settings
 *  save seals it, because go-live trusts the row's sender only behind that seal. */
async function prepareReport(db, { schedule = true, recipe = RECIPE } = {}) {
  let scheduleId = null;
  if (schedule) {
    await db.execute({
      sql: "INSERT INTO schedules (task, cron_expression, tz) VALUES ('weekly-report', '0 7 * * 1', 'Europe/Berlin')",
      args: [],
    });
    const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
    scheduleId = Number(rows[0].id);
  }
  const { id } = await createReport(db, { projectId: PROJECT, owner: OWNER_LABEL, botId: "bot-1", title: "Weekly listings" });
  const saved = await saveRecipe(db, { reportId: id, recipe, authorKind: "owner", registry: REGISTRY });
  await updateReportColumns(db, id, {
    schedule_id: scheduleId,
    sender_account_id: SENDER,
    delivery_mode: "email_link",
    comment_tier_default: "c",
    comment_visibility: "own",
    ai_commentary: 0,
  });
  await updateSettings(db, { loadSeed: () => ({ seed: SEED }), senderReady: async () => true }, {
    reportId: id, settings: { sender_account_id: SENDER }, actor: { kind: "owner" },
  });
  return { id, rev: saved.rev, foreignScheduleId: scheduleId };
}

/** Add an approved preview run of one report's current revision to a world's run table. */
function addPreviewRun(world, report, runId = "prv-1", over = {}) {
  world.runTable[runId] = {
    id: runId, reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev, ...over,
  };
  return runId;
}

/** The report's own schedule rows, as the hook's due query finds them. */
async function ownRows(db, reportId) {
  const { rows } = await db.execute({
    sql: "SELECT * FROM schedules WHERE task = ? ORDER BY id",
    args: [`${REPORT_PREFIX}${reportId}`],
  });
  return rows;
}

/** Every schedule row in the database, oldest first. */
async function allRows(db) {
  const { rows } = await db.execute({ sql: "SELECT * FROM schedules ORDER BY id", args: [] });
  return rows;
}

/** The newest approval audit row of one report, or null. */
async function newestAudit(db, reportId) {
  const { rows } = await db.execute({
    sql: "SELECT kind, subject, actor, decided FROM report_approvals_audit WHERE report_id = ? ORDER BY id DESC LIMIT 1",
    args: [reportId],
  });
  return rows[0] ?? null;
}

/** How many approval audit rows one report carries. */
async function auditCount(db, reportId) {
  const { rows } = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_approvals_audit WHERE report_id = ?",
    args: [reportId],
  });
  return Number(rows[0].n);
}

/** A report with its own schedule row, taken live through the real preview and go-live flow. */
async function liveReport(world) {
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const runId = addPreviewRun(world, report);
  assert.equal((await post(`${reportPath(report.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER })).status, 200);
  const live = await getReport(world.db, report.id);
  assert.equal(live.status, "live");
  assert.match(live.live_seal, /^[0-9a-f]{64}$/);
  return { report, live, runId };
}

/* ------------------------------------------------------------------- the clear */

test("the route clears the report's own row and its pointer, and leaves the report itself alone", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(Number((await getReport(world.db, report.id)).schedule_id), Number(row.id));

  const cleared = await del(schedulePath(report.id));
  assert.equal(cleared.status, 200, cleared.text);
  assert.equal(cleared.headers["cache-control"], "no-store");
  assert.equal(cleared.text.includes("live_seal"), false, "no seal column in the answer");
  assert.equal(cleared.text.includes("live_nonce"), false, "no nonce column in the answer");

  assert.equal((await ownRows(world.db, report.id)).length, 0, "the row is gone");
  assert.equal((await getReport(world.db, report.id)).schedule_id, null, "and the pointer with it");
  assert.equal(cleared.json.report.schedule_id, null);
  assert.equal(cleared.json.report.status, "draft", "a draft is not paused by losing its schedule");

  // The delete route for the report is a different path: the report is still here.
  assert.ok(await getReport(world.db, report.id), "DELETE /:id/schedule did not delete the report");
  assert.equal(await newestAudit(world.db, report.id),
    null, "a draft's clear writes no audit row");
});

test("the clear is one transaction: a refused report write leaves the schedule row in place", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const [row] = await ownRows(world.db, report.id);

  await world.db.executeMultiple(
    "CREATE TRIGGER reports_update_abort BEFORE UPDATE ON reports BEGIN SELECT RAISE(ABORT, 'x'); END",
  );
  try {
    const failed = await del(schedulePath(report.id));
    assert.equal(failed.status, 500, failed.text);
    assert.deepEqual(failed.json, { error: "internal", message: "Something went wrong." });
  } finally {
    await world.db.executeMultiple("DROP TRIGGER IF EXISTS reports_update_abort");
  }

  const rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1, "the schedule row the batch deleted first was rolled back");
  assert.equal(Number(rows[0].id), Number(row.id));
  assert.equal(rows[0].cron_expression, CRON);
  assert.equal(Number((await getReport(world.db, report.id)).schedule_id), Number(row.id),
    "and so was the pointer write");

  // With the refusal gone, the same call clears both.
  const cleared = await del(schedulePath(report.id));
  assert.equal(cleared.status, 200, cleared.text);
  assert.equal((await ownRows(world.db, report.id)).length, 0);
  assert.equal((await getReport(world.db, report.id)).schedule_id, null);
});

test("another task's rows and another report's row are left exactly as they were", async () => {
  const world = await setup();
  const report = await prepareReport(world.db);
  const bystander = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  assert.equal((await put(schedulePath(bystander.id), { cron: OTHER_CRON, tz: TZ })).status, 200);
  const [otherRow] = await ownRows(world.db, bystander.id);
  const before = await allRows(world.db);

  const cleared = await del(schedulePath(report.id));
  assert.equal(cleared.status, 200, cleared.text);

  const after = await allRows(world.db);
  assert.equal(after.length, before.length - 1, "only this report's own row went");
  const kept = after.filter((row) => Number(row.id) !== Number(before.find(
    (r) => String(r.task) === `${REPORT_PREFIX}${report.id}`,
  ).id));
  assert.deepEqual(kept, before.filter((row) => String(row.task) !== `${REPORT_PREFIX}${report.id}`),
    "every other row is untouched");

  // A row of a task that is not a report's at all (the one the report pointed at before the page set
  // its own) is still there, with its own cron and zone.
  const { rows: foreign } = await world.db.execute({
    sql: "SELECT * FROM schedules WHERE id = ?", args: [report.foreignScheduleId],
  });
  assert.equal(foreign.length, 1);
  assert.equal(foreign[0].task, "weekly-report");
  assert.equal(foreign[0].tz, "Europe/Berlin");

  // The other report keeps its own row and its pointer at it.
  const theirs = await ownRows(world.db, bystander.id);
  assert.equal(theirs.length, 1);
  assert.equal(Number(theirs[0].id), Number(otherRow.id));
  assert.equal(theirs[0].cron_expression, OTHER_CRON);
  assert.equal(Number(theirs[0].enabled), 1);
  assert.equal(Number((await getReport(world.db, bystander.id)).schedule_id), Number(otherRow.id));
});

/* ------------------------------------------------------------------- the rails */

test("a non-owner session is 403 owner_only and changes nothing, and an unknown id is a 404", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const [row] = await ownRows(world.db, report.id);

  for (const [label, opts] of [
    ["a peer's single-sign-on session", { token: SSO }],
    ["a request from this machine", { token: OWNER, laptop: false }],
  ]) {
    const r = await del(schedulePath(report.id), opts);
    assert.equal(r.status, 403, `${label}: ${r.status} ${r.text}`);
    assert.deepEqual(r.json, { error: "owner_only", message: "Only the owner can see this." }, label);
    assert.equal(r.text.includes(report.id), false, `${label}: no id in the answer`);
  }
  const noCsrf = await del(schedulePath(report.id), { csrf: null });
  assert.equal(noCsrf.status, 403, noCsrf.text);
  assert.match(noCsrf.text, /CSRF/i, "the dashboard rail answers, not this router");

  const rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1, "a refused call removed nothing");
  assert.equal(Number(rows[0].id), Number(row.id));
  assert.equal(Number((await getReport(world.db, report.id)).schedule_id), Number(row.id));

  for (const id of ["rpt-ffffffffffffffff", "rpt-xyz", "not-a-report"]) {
    const r = await del(schedulePath(id));
    assert.equal(r.status, 404, `${id}: ${r.status} ${r.text}`);
    assert.deepEqual(r.json, { error: "not_found", message: "Not found." }, id);
  }
  assert.equal((await ownRows(world.db, report.id)).length, 1);
});

/* --------------------------------------------------------------- the live set */

test("a live report is paused by the clear, with the seal, the nonce and the audit row", async () => {
  const world = await setup();
  const { report, live } = await liveReport(world);
  const [own] = await ownRows(world.db, report.id);

  const cleared = await del(schedulePath(report.id));
  assert.equal(cleared.status, 200, cleared.text);
  assert.equal(cleared.json.report.status, "paused");
  assert.equal(cleared.json.report.pause_reason, SETTINGS_CHANGED_PAUSE_REASON);
  assert.equal(cleared.json.report.live, false);
  assert.equal(cleared.text.includes(live.live_seal), false, "no seal in the answer");

  const after = await getReport(world.db, report.id);
  assert.equal(after.status, "paused");
  assert.equal(after.pause_reason, SETTINGS_CHANGED_PAUSE_REASON);
  assert.equal(after.live_seal, null, "the seal went with the pause");
  assert.equal(after.live_nonce, null);
  assert.equal(after.schedule_id, null);
  assert.deepEqual(await newestAudit(world.db, report.id),
    { kind: "live", subject: null, actor: "owner", decided: "refused" });

  const { rows } = await world.db.execute({
    sql: "SELECT COUNT(*) AS n FROM schedules WHERE id = ? OR task = ?",
    args: [own.id, `${REPORT_PREFIX}${report.id}`],
  });
  assert.equal(Number(rows[0].n), 0, "the row the report ran on is gone");

  // A resume cannot put an approval back on a report with no schedule: only a fresh one and go-live.
  const resumed = await post(`${reportPath(report.id)}/resume`, {});
  assert.equal(resumed.status, 409, resumed.text);
  assert.deepEqual(resumed.json, { error: "go_live_needed", message: "Preview and go live again." });
});

test("a live report with no schedule row is paused and audited, and the pointer stays null", async () => {
  const world = await setup();
  const { report, live } = await liveReport(world);
  assert.equal((await ownRows(world.db, report.id)).length, 1);

  // Raw SQL, outside the app: the row the live set sealed is gone and no pointer names it.
  await world.db.execute({
    sql: "DELETE FROM schedules WHERE task = ?", args: [`${REPORT_PREFIX}${report.id}`],
  });
  await world.db.execute({
    sql: "UPDATE reports SET schedule_id = NULL WHERE id = ?", args: [report.id],
  });
  assert.equal((await ownRows(world.db, report.id)).length, 0, "no row left to clear");
  const dangling = await getReport(world.db, report.id);
  assert.equal(dangling.schedule_id, null);
  assert.equal(dangling.status, "live");

  const cleared = await del(schedulePath(report.id));
  assert.equal(cleared.status, 200, cleared.text);
  assert.equal(cleared.json.report.status, "paused");
  assert.equal(cleared.json.report.pause_reason, SETTINGS_CHANGED_PAUSE_REASON);
  assert.equal(cleared.text.includes(live.live_seal), false, "no seal in the answer");

  const after = await getReport(world.db, report.id);
  assert.equal(after.status, "paused");
  assert.equal(after.pause_reason, SETTINGS_CHANGED_PAUSE_REASON);
  assert.equal(after.live_seal, null);
  assert.equal(after.live_nonce, null);
  assert.equal(after.schedule_id, null);
  assert.deepEqual(await newestAudit(world.db, report.id),
    { kind: "live", subject: null, actor: "owner", decided: "refused" });
});

test("a paused report that still carries a seal loses the seal and keeps its status and reason", async () => {
  const world = await setup();
  const { report } = await liveReport(world);
  const paused = await post(`${reportPath(report.id)}/pause`, { reason: "Starting over" });
  assert.equal(paused.status, 200, paused.text);
  const withSeal = await getReport(world.db, report.id);
  assert.equal(withSeal.status, "paused");
  assert.match(withSeal.live_seal, /^[0-9a-f]{64}$/);
  const auditsBefore = await auditCount(world.db, report.id);

  const cleared = await del(schedulePath(report.id));
  assert.equal(cleared.status, 200, cleared.text);
  assert.equal(cleared.json.report.status, "paused", "the status is unchanged");
  assert.equal(cleared.json.report.pause_reason, "Starting over", "so is the reason");
  assert.equal(cleared.json.report.live, false);

  const after = await getReport(world.db, report.id);
  assert.equal(after.live_seal, null, "the approval no longer describes the report");
  assert.equal(after.live_nonce, null);
  assert.equal(after.schedule_id, null);
  assert.equal((await ownRows(world.db, report.id)).length, 0);
  assert.equal(await auditCount(world.db, report.id), auditsBefore,
    "a report that was already paused is not audited again");
});

/* --------------------------------------------------------------- idempotent */

test("a second clear, and a clear on a report that never had a schedule, change nothing", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);

  const first = await del(schedulePath(report.id));
  assert.equal(first.status, 200, first.text);
  const auditsAfterFirst = await auditCount(world.db, report.id);
  const second = await del(schedulePath(report.id));
  assert.equal(second.status, 200, second.text);
  assert.equal(second.json.report.schedule_id, null);
  assert.equal(await auditCount(world.db, report.id), auditsAfterFirst, "no audit row on the second call");
  assert.equal((await ownRows(world.db, report.id)).length, 0);

  const bare = await prepareReport(world.db, { schedule: false });
  const auditsBefore = await auditCount(world.db, bare.id);
  const rowsBefore = await allRows(world.db);
  const never = await del(schedulePath(bare.id));
  assert.equal(never.status, 200, never.text);
  assert.equal(never.json.report.schedule_id, null);
  assert.equal(await auditCount(world.db, bare.id), auditsBefore, "no audit row for a report with no schedule");
  assert.deepEqual(await allRows(world.db), rowsBefore, "and no schedule row was touched");
});

/* --------------------------------------------------------------- boot repair */

test("the boot repair nulls only the pointer that names no row, and leaves the rows alone", async () => {
  const world = await setup();
  const dangling = await prepareReport(world.db, { schedule: false });
  const valid = await prepareReport(world.db, { schedule: false });
  const bare = await prepareReport(world.db, { schedule: false });

  // One report's row is deleted underneath it: the pointer stays, the schedule does not exist.
  assert.equal((await put(schedulePath(dangling.id), { cron: CRON, tz: TZ })).status, 200);
  const [gone] = await ownRows(world.db, dangling.id);
  await world.db.execute({ sql: "DELETE FROM schedules WHERE id = ?", args: [gone.id] });
  assert.equal(Number((await getReport(world.db, dangling.id)).schedule_id), Number(gone.id));

  // One report has a valid row, and one has no pointer at all.
  assert.equal((await put(schedulePath(valid.id), { cron: OTHER_CRON, tz: TZ })).status, 200);
  const [keptRow] = await ownRows(world.db, valid.id);
  const schedulesBefore = await allRows(world.db);
  assert.equal(schedulesBefore.length, 1, "one schedule row in this world");

  const cleared = await repairDanglingSchedulePointers(world.db);
  assert.equal(cleared, 1, "exactly the dangling pointer");

  const afterDangling = await getReport(world.db, dangling.id);
  assert.equal(afterDangling.schedule_id, null);
  assert.equal(afterDangling.status, "draft", "the status is untouched");
  assert.equal((await getReport(world.db, valid.id)).schedule_id !== null, true);
  assert.equal(Number((await getReport(world.db, valid.id)).schedule_id), Number(keptRow.id),
    "a valid pointer is untouched");
  assert.equal((await getReport(world.db, bare.id)).schedule_id, null);
  assert.deepEqual(await allRows(world.db), schedulesBefore, "no schedule row was touched");

  // Nothing is left to repair.
  assert.equal(await repairDanglingSchedulePointers(world.db), 0);
});

test("a gateway boot clears a dangling pointer before the reports hook starts", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  await world.db.execute({
    sql: "UPDATE reports SET schedule_id = ? WHERE id = ?", args: [987654, report.id],
  });

  let result = null;
  try {
    result = await startReportsAtBoot({
      db: world.db,
      deps: {
        approvals: world.approvalsDeps,
        now: () => clock,
        notify: async () => {},
        instanceZone: async () => "UTC",
        lease: {
          now: () => clock, pid: 4242, isPidAlive: () => true,
          kernelBootId: () => "boot-clear-schedule", runId: "run-clear-schedule",
        },
      },
    });
    assert.equal(result.started, true, JSON.stringify(result));
    assert.equal((await getReport(world.db, report.id)).schedule_id, null,
      "the boot cleared the pointer to a row that is not there");
    assert.ok(result.hook, "and the hook started anyway");
  } finally {
    if (result?.hook) await result.hook.stop();
    _setReportsHookForTest(null);
    unregisterSchedulerHook("reports");
  }
});