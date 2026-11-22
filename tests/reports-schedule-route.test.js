// Crow Recurring Reports' owner schedule route (`PUT /dashboard/api/reports/:id/schedule`): the
// `schedules` row it makes or moves, the checks it refuses with, the live-set rule it shares with a
// settings write, the reports hook reading the row it wrote, and the delete that takes it away.
//
// Harness: the same world tests/reports-api.test.js builds — a real init-db'd scratch crow.db copied
// per test (CROW_DATA_DIR under a temp dir), an ephemeral express app wired the way the gateway and the
// dashboard wire it (the global JSON parser skipped by index.js's own `_hasOwnParser` list, read from
// its source; a session stub, the dashboard's real CSRF middleware, the real reports API router), the
// real report store and approvals module with an injected preview-run reader and a fixed clock, and the
// real owner rule with the request marked as coming from the owner's own client
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

const root = mkdtempSync(join(tmpdir(), "reports-schedule-route-"));
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
const { SETTINGS_CHANGED_PAUSE_REASON, updateSettings } =
  await import("../servers/gateway/reports/approvals.js");
const { createReport, getReport, saveRecipe, updateReportColumns } =
  await import("../servers/gateway/reports/store.js");
const { REPORT_PREFIX, REPORT_TASK_GLOB, REPORT_TASK_RE, cronNext } =
  await import("../servers/shared/schedule-core.js");
const { registerReportsHook, _setReportsHookForTest } =
  await import("../servers/gateway/reports/schedule-hook.js");
const { unregisterSchedulerHook } = await import("../servers/gateway/scheduler-hooks.js");

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
/** What `crow_create_schedule` writes into `next_run`: an ISO instant with its milliseconds. */
const ISO_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

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

const get = (path, opts) => call("GET", path, opts);
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

/** A saved report, set up the way go-live needs it: a schedule row and a sender the owner sealed. */
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
  // Go-live trusts the row's sender only behind the seal the owner's settings save writes, so a report
  // that is going to be taken live is sealed here (tests/reports-api.test.js does the same).
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
    sql: `SELECT * FROM schedules WHERE task GLOB ? AND length(task) = 27 ORDER BY id`,
    args: [REPORT_TASK_GLOB],
  });
  return rows.filter((row) => String(row.task) === `${REPORT_PREFIX}${reportId}`);
}

/** The newest approval audit row of one report, or null. */
async function newestAudit(db, reportId) {
  const { rows } = await db.execute({
    sql: "SELECT kind, subject, actor, decided FROM report_approvals_audit WHERE report_id = ? ORDER BY id DESC LIMIT 1",
    args: [reportId],
  });
  return rows[0] ?? null;
}

/* ---------------------------------------------------------------------- the row */

test("the route makes the report's own row, and a second write moves that same row", async () => {
  const world = await setup();
  const report = await prepareReport(world.db);

  const made = await put(schedulePath(report.id), { cron: CRON, tz: TZ });
  assert.equal(made.status, 200, made.text);
  assert.equal(made.headers["cache-control"], "no-store");
  assert.equal(made.text.includes("live_seal"), false, "no seal column in the answer");
  assert.equal(made.text.includes("live_nonce"), false, "no nonce column in the answer");

  let rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1, "one row for this report");
  const row = rows[0];
  assert.equal(row.task, `${REPORT_PREFIX}${report.id}`);
  assert.equal(row.task, `report:${report.id}`);
  assert.ok(REPORT_TASK_RE.test(row.task), "the task is exactly a report row's");
  assert.equal(row.task.length, 27);
  assert.equal(Number(row.enabled), 1);
  assert.equal(row.cron_expression, CRON);
  assert.equal(row.tz, TZ);
  assert.match(row.next_run, ISO_MS, "the same ISO format crow_create_schedule writes");
  assert.equal(row.next_run, new Date(cronNext(CRON, TZ, T0)).toISOString());
  assert.ok(Date.parse(row.next_run) > T0, "a future window");

  // The report points at that row, and only at that row.
  assert.equal(Number(made.json.report.schedule_id), Number(row.id));
  assert.equal(Number((await getReport(world.db, report.id)).schedule_id), Number(row.id));

  // The row the report used to point at is somebody else's schedule, and it is untouched.
  const { rows: foreign } = await world.db.execute({
    sql: "SELECT * FROM schedules WHERE id = ?", args: [report.foreignScheduleId],
  });
  assert.equal(foreign.length, 1);
  assert.equal(foreign[0].task, "weekly-report");
  assert.equal(foreign[0].tz, "Europe/Berlin");

  // A second write with a different cron moves the SAME row and recomputes its window.
  const moved = await put(schedulePath(report.id), { cron: OTHER_CRON, tz: TZ });
  assert.equal(moved.status, 200, moved.text);
  rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1, "no second row");
  assert.equal(Number(rows[0].id), Number(row.id));
  assert.equal(rows[0].cron_expression, OTHER_CRON);
  assert.equal(rows[0].next_run, new Date(cronNext(OTHER_CRON, TZ, T0)).toISOString());
  assert.notEqual(rows[0].next_run, row.next_run);
  assert.equal(Number(rows[0].enabled), 1);

  // The same cron and zone on an ON row whose window is still ahead keeps the window it holds: the
  // window it holds is still the next one.
  await world.db.execute({
    sql: "UPDATE schedules SET next_run = ? WHERE id = ?",
    args: ["2027-01-04T15:00:00.000Z", row.id],
  });
  const same = await put(schedulePath(report.id), { cron: OTHER_CRON, tz: TZ });
  assert.equal(same.status, 200, same.text);
  rows = await ownRows(world.db, report.id);
  assert.equal(rows[0].next_run, "2027-01-04T15:00:00.000Z", "the window was left alone");
  assert.equal(Number(rows[0].enabled), 1, "and the row is on");
  assert.equal(Number(same.json.report.schedule_id), Number(row.id));

  // A row that is OFF (here with the window it missed while it was off) gets a window from now, so
  // switching a report back on never fires the window it missed. This is not a live-set change.
  await world.db.execute({
    sql: "UPDATE schedules SET next_run = ?, enabled = 0 WHERE id = ?",
    args: ["2026-10-19T11:30:00.000Z", row.id],
  });
  const reenabled = await put(schedulePath(report.id), { cron: OTHER_CRON, tz: TZ });
  assert.equal(reenabled.status, 200, reenabled.text);
  rows = await ownRows(world.db, report.id);
  assert.equal(Number(rows[0].enabled), 1, "the row is on again");
  assert.equal(rows[0].next_run, new Date(cronNext(OTHER_CRON, TZ, T0)).toISOString(),
    "the missed window was replaced with the next one from now");
  assert.ok(Date.parse(rows[0].next_run) > T0, "a future window");
});

test("a report with no row gets one, and a pointer to a row this report does not own is not followed", async () => {
  const world = await setup();
  const bare = await prepareReport(world.db, { schedule: false });

  const made = await put(schedulePath(bare.id), { cron: CRON, tz: TZ });
  assert.equal(made.status, 200, made.text);
  const rows = await ownRows(world.db, bare.id);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].task, `${REPORT_PREFIX}${bare.id}`);
  assert.equal(Number(made.json.report.schedule_id), Number(rows[0].id));

  // A pointer at a schedule row whose task is somebody else's: the route makes this report its own row
  // and moves the pointer, leaving the other row where it is.
  const other = await prepareReport(world.db);
  await world.db.execute({
    sql: "UPDATE reports SET schedule_id = ? WHERE id = ?", args: [other.foreignScheduleId, other.id],
  });
  const pointed = await put(schedulePath(other.id), { cron: CRON, tz: TZ });
  assert.equal(pointed.status, 200, pointed.text);
  const theirs = await ownRows(world.db, other.id);
  assert.equal(theirs.length, 1);
  assert.notEqual(Number(theirs[0].id), Number(other.foreignScheduleId));
  const { rows: left } = await world.db.execute({
    sql: "SELECT task FROM schedules WHERE id = ?", args: [other.foreignScheduleId],
  });
  assert.equal(left[0].task, "weekly-report", "the other row still belongs to its own task");
});

/* ------------------------------------------------------------------ bad input */

test("a bad cron, a bad zone and a body that is not an object are 400 bad_input and write nothing", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  const path = schedulePath(report.id);
  const badInput = { error: "bad_input", message: "That request is not valid." };

  const badCrons = ["not a cron", "", "   ", "@once", "0".repeat(51), 7, null, ["0 9 * * 1"]];
  for (const cron of badCrons) {
    const r = await put(path, { cron, tz: TZ });
    assert.equal(r.status, 400, `${JSON.stringify(cron)}: ${r.status} ${r.text}`);
    assert.deepEqual(r.json, badInput, `${JSON.stringify(cron)}: the fixed sentence`);
  }
  const badZones = ["Mars/Olympus", "", "   ", 7, null, undefined, "Not/AZone"];
  for (const tz of badZones) {
    const body = tz === undefined ? { cron: CRON } : { cron: CRON, tz };
    const r = await put(path, body);
    assert.equal(r.status, 400, `${JSON.stringify(tz)}: ${r.status} ${r.text}`);
    assert.deepEqual(r.json, badInput, `${JSON.stringify(tz)}: the fixed sentence`);
  }
  // A body that is not a plain object never reaches the module: an array and an object with no cron.
  for (const body of [[], {}]) {
    const r = await put(path, body);
    assert.equal(r.status, 400, `${JSON.stringify(body)}: ${r.status} ${r.text}`);
    assert.deepEqual(r.json, badInput);
  }
  // A body that is not JSON at all is refused before this router parses it (the gateway's own parser
  // reads it here), so only its status is this router's to promise.
  for (const body of [JSON.stringify("a string"), "just some text"]) {
    const r = await put(path, body);
    assert.equal(r.status, 400, `${JSON.stringify(body)}: ${r.status} ${r.text}`);
  }

  assert.equal((await ownRows(world.db, report.id)).length, 0, "no schedule row was written");
  assert.equal((await getReport(world.db, report.id)).schedule_id, null, "and the pointer is unchanged");

  // With a row already in place, a refused write leaves its cron and its window exactly as they were.
  assert.equal((await put(path, { cron: CRON, tz: TZ })).status, 200);
  const [before] = await ownRows(world.db, report.id);
  for (const body of [{ cron: "not a cron", tz: TZ }, { cron: CRON, tz: "Mars/Olympus" }, { cron: CRON }]) {
    const r = await put(path, body);
    assert.equal(r.status, 400, `${JSON.stringify(body)}: ${r.status} ${r.text}`);
  }
  const rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].cron_expression, before.cron_expression);
  assert.equal(rows[0].tz, before.tz);
  assert.equal(rows[0].next_run, before.next_run);
});

/* ------------------------------------------------------------------- the rails */

test("a non-owner session is 403 owner_only with no data, and a missing or malformed id is a 404", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });

  for (const [label, opts] of [
    ["a peer's single-sign-on session", { token: SSO }],
    ["a request from this machine", { token: OWNER, laptop: false }],
  ]) {
    const r = await put(schedulePath(report.id), { cron: CRON, tz: TZ }, opts);
    assert.equal(r.status, 403, `${label}: ${r.status} ${r.text}`);
    assert.deepEqual(r.json, { error: "owner_only", message: "Only the owner can see this." }, label);
    assert.equal(r.text.includes(report.id), false, `${label}: no id in the answer`);
    assert.equal(r.text.includes(CRON), false, `${label}: no cron in the answer`);
  }
  const noCsrf = await put(schedulePath(report.id), { cron: CRON, tz: TZ }, { csrf: null });
  assert.equal(noCsrf.status, 403, noCsrf.text);
  assert.match(noCsrf.text, /CSRF/i, "the dashboard rail answers, not this router");
  assert.equal((await ownRows(world.db, report.id)).length, 0, "a refused write wrote nothing");
  assert.equal((await getReport(world.db, report.id)).schedule_id, null);

  for (const id of ["rpt-ffffffffffffffff", "rpt-xyz", "not-a-report"]) {
    const r = await put(schedulePath(id), { cron: CRON, tz: TZ });
    assert.equal(r.status, 404, `${id}: ${r.status} ${r.text}`);
    assert.deepEqual(r.json, { error: "not_found", message: "Not found." }, id);
  }
  const { rows } = await world.db.execute({
    sql: "SELECT COUNT(*) AS n FROM schedules WHERE task GLOB ?", args: [REPORT_TASK_GLOB],
  });
  assert.equal(Number(rows[0].n), 0, "and no report row was made for any of them");
});

/* -------------------------------------------------------------------- go live */

test("a preview that failed with no_schedule goes live once the route sets the schedule", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  const runId = addPreviewRun(world, report);

  const refused = await post(`${reportPath(report.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER });
  assert.equal(refused.status, 409, refused.text);
  assert.deepEqual(refused.json, {
    error: "no_schedule", message: "Choose when this report runs before going live.",
  });
  assert.equal((await getReport(world.db, report.id)).status, "draft");

  const set = await put(schedulePath(report.id), { cron: CRON, tz: TZ });
  assert.equal(set.status, 200, set.text);
  assert.equal(set.json.report.status, "draft", "a draft is not paused by its own schedule");

  const live = await post(`${reportPath(report.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER });
  assert.equal(live.status, 200, live.text);
  assert.deepEqual(live.json, { ok: true, liveRev: report.rev });

  const stored = await getReport(world.db, report.id);
  assert.equal(stored.status, "live");
  const view = await get(reportPath(report.id));
  assert.equal(view.json.report.live, true, "the seal verifies over the schedule the route wrote");
});

/* --------------------------------------------------------------- the live set */

test("the identical cron and zone leave a live report live, and a moved one pauses it", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const runId = addPreviewRun(world, report);
  assert.equal((await post(`${reportPath(report.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER })).status, 200);
  const live = await getReport(world.db, report.id);
  assert.equal(live.status, "live");
  assert.match(live.live_seal, /^[0-9a-f]{64}$/);

  const same = await put(schedulePath(report.id), { cron: CRON, tz: TZ });
  assert.equal(same.status, 200, same.text);
  assert.equal(same.json.report.status, "live", "nothing moved, so nothing paused");
  assert.equal(same.json.report.live, true);
  assert.equal((await getReport(world.db, report.id)).live_seal, live.live_seal, "the seal is untouched");

  // The same cron read in another zone is a different live set.
  const movedZone = await put(schedulePath(report.id), { cron: CRON, tz: "Europe/Berlin" });
  assert.equal(movedZone.status, 200, movedZone.text);
  assert.equal(movedZone.json.report.status, "paused");
  assert.equal(movedZone.json.report.pause_reason, SETTINGS_CHANGED_PAUSE_REASON);
  assert.equal(movedZone.json.report.live, false);
  assert.equal(movedZone.text.includes(live.live_seal), false, "no seal in the answer");

  const after = await getReport(world.db, report.id);
  assert.equal(after.status, "paused");
  assert.equal(after.live_seal, null, "the seal went with the pause");
  assert.equal(after.live_nonce, null);
  assert.deepEqual(await newestAudit(world.db, report.id),
    { kind: "live", subject: null, actor: "owner", decided: "refused" });

  // The row itself kept the new zone: the pause did not undo the schedule write.
  const rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].tz, "Europe/Berlin");
  assert.equal(rows[0].cron_expression, CRON);

  const resumed = await post(`${reportPath(report.id)}/resume`, {});
  assert.equal(resumed.status, 409, resumed.text);
  assert.deepEqual(resumed.json, { error: "go_live_needed", message: "Preview and go live again." });
});

test("a live report whose only move is the cron is paused, with the seal, the nonce and the audit row", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const runId = addPreviewRun(world, report);
  assert.equal((await post(`${reportPath(report.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER })).status, 200);
  const live = await getReport(world.db, report.id);
  assert.equal(live.status, "live");
  assert.match(live.live_seal, /^[0-9a-f]{64}$/);
  const [own] = await ownRows(world.db, report.id);

  // The zone is untouched: only the cron moves, and the cron is inside the seal.
  const changed = await put(schedulePath(report.id), { cron: OTHER_CRON, tz: TZ });
  assert.equal(changed.status, 200, changed.text);
  assert.equal(changed.json.report.status, "paused");
  assert.equal(changed.json.report.pause_reason, SETTINGS_CHANGED_PAUSE_REASON);
  assert.equal(changed.json.report.live, false);
  assert.equal(changed.text.includes(live.live_seal), false, "no seal in the answer");

  const after = await getReport(world.db, report.id);
  assert.equal(after.status, "paused");
  assert.equal(after.live_seal, null, "the seal went with the pause");
  assert.equal(after.live_nonce, null);
  assert.deepEqual(await newestAudit(world.db, report.id),
    { kind: "live", subject: null, actor: "owner", decided: "refused" });

  // The row itself took the new cron, on the same row, and the pointer still names it.
  const rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1);
  assert.equal(Number(rows[0].id), Number(own.id));
  assert.equal(rows[0].cron_expression, OTHER_CRON);
  assert.equal(rows[0].tz, TZ);
  assert.equal(rows[0].next_run, new Date(cronNext(OTHER_CRON, TZ, T0)).toISOString());
  assert.equal(Number(after.schedule_id), Number(own.id));
});

test("a row switched off with the same cron and zone gets a window from now, and a live report stays live", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const runId = addPreviewRun(world, report);
  assert.equal((await post(`${reportPath(report.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER })).status, 200);
  const live = await getReport(world.db, report.id);
  assert.equal(live.status, "live");
  const [own] = await ownRows(world.db, report.id);

  // Somebody switched the row off, and left the window it missed while it was off.
  await world.db.execute({
    sql: "UPDATE schedules SET enabled = 0, next_run = ? WHERE id = ?",
    args: ["2026-10-19T14:00:00.000Z", own.id],
  });

  const same = await put(schedulePath(report.id), { cron: CRON, tz: TZ });
  assert.equal(same.status, 200, same.text);
  assert.equal(same.json.report.status, "live", "switching the row on is not a live-set change");
  assert.equal(same.json.report.pause_reason, null);
  assert.equal(same.json.report.live, true, "the seal still verifies over the row");

  const after = await getReport(world.db, report.id);
  assert.equal(after.status, "live");
  assert.equal(after.live_seal, live.live_seal, "the seal is untouched");
  assert.equal(after.live_nonce, live.live_nonce);
  assert.equal(Number(after.schedule_id), Number(own.id), "the pointer did not move");

  const rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1);
  assert.equal(Number(rows[0].id), Number(own.id));
  assert.equal(Number(rows[0].enabled), 1, "the row is on again");
  assert.equal(rows[0].next_run, new Date(cronNext(CRON, TZ, T0)).toISOString());
  assert.ok(Date.parse(rows[0].next_run) > T0, "a window from now, not the one it missed");
  assert.deepEqual(await newestAudit(world.db, report.id),
    { kind: "live", subject: null, actor: "owner", decided: "approved" }, "no pause was audited");
});

test("a live report pointing at a missing row is paused when the route writes its own, same cron and zone", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const runId = addPreviewRun(world, report);
  assert.equal((await post(`${reportPath(report.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER })).status, 200);
  const live = await getReport(world.db, report.id);
  assert.equal(live.status, "live");
  const [own] = await ownRows(world.db, report.id);

  // The pointer names a row that is gone. The report's own row still carries the cron and zone the
  // owner approved, so the cron and the zone are not what moves here: the row id is.
  await world.db.execute({
    sql: "UPDATE reports SET schedule_id = 999999 WHERE id = ?", args: [report.id],
  });

  const repointed = await put(schedulePath(report.id), { cron: CRON, tz: TZ });
  assert.equal(repointed.status, 200, repointed.text);
  assert.equal(repointed.json.report.status, "paused");
  assert.equal(repointed.json.report.pause_reason, SETTINGS_CHANGED_PAUSE_REASON);
  assert.equal(repointed.json.report.live, false);

  const after = await getReport(world.db, report.id);
  assert.equal(after.live_seal, null, "the seal went with the pause");
  assert.equal(after.live_nonce, null);
  assert.equal(Number(after.schedule_id), Number(own.id), "the pointer is the report's own row");
  assert.deepEqual(await newestAudit(world.db, report.id),
    { kind: "live", subject: null, actor: "owner", decided: "refused" });

  // No row was made for the dead pointer, and the cron and zone on the row did not move.
  const rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 1);
  assert.equal(Number(rows[0].id), Number(own.id));
  assert.equal(rows[0].cron_expression, CRON);
  assert.equal(rows[0].tz, TZ);
  assert.equal(rows[0].next_run, new Date(cronNext(CRON, TZ, T0)).toISOString());
});

test("a live report pointing at another report's row is paused when the route moves it back, same cron and zone", async () => {
  const world = await setup();
  const mine = await prepareReport(world.db, { schedule: false });
  const theirs = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(mine.id), { cron: CRON, tz: TZ })).status, 200);
  assert.equal((await put(schedulePath(theirs.id), { cron: OTHER_CRON, tz: TZ })).status, 200);
  const runId = addPreviewRun(world, mine);
  assert.equal((await post(`${reportPath(mine.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER })).status, 200);
  assert.equal((await getReport(world.db, mine.id)).status, "live");
  const [own] = await ownRows(world.db, mine.id);
  const [otherRow] = await ownRows(world.db, theirs.id);

  // The pointer is moved onto another report's own row. The route does not follow it (that row is not
  // this report's task), so the row the cron and zone are identical to is this report's own.
  await world.db.execute({
    sql: "UPDATE reports SET schedule_id = ? WHERE id = ?", args: [otherRow.id, mine.id],
  });

  const repointed = await put(schedulePath(mine.id), { cron: CRON, tz: TZ });
  assert.equal(repointed.status, 200, repointed.text);
  assert.equal(repointed.json.report.status, "paused");
  assert.equal(repointed.json.report.pause_reason, SETTINGS_CHANGED_PAUSE_REASON);

  const after = await getReport(world.db, mine.id);
  assert.equal(after.live_seal, null);
  assert.equal(after.live_nonce, null);
  assert.equal(Number(after.schedule_id), Number(own.id), "the pointer is this report's own row");
  assert.deepEqual(await newestAudit(world.db, mine.id),
    { kind: "live", subject: null, actor: "owner", decided: "refused" });

  // The other report's row is left exactly as it was, and still the only row of its task that is on.
  const theirsRows = await ownRows(world.db, theirs.id);
  assert.equal(theirsRows.length, 1);
  assert.equal(Number(theirsRows[0].id), Number(otherRow.id));
  assert.equal(Number(theirsRows[0].enabled), 1);
  assert.equal(theirsRows[0].cron_expression, OTHER_CRON);
  assert.equal((await ownRows(world.db, mine.id)).length, 1);
});

test("two rows carrying the same report task: the route keeps the one it points at and switches the other off", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const [kept] = await ownRows(world.db, report.id);

  // A stale duplicate of the very same task, on and due: the hook's due query matches it too.
  await world.db.execute({
    sql: `INSERT INTO schedules (task, cron_expression, tz, enabled, next_run) VALUES (?, ?, ?, 1, ?)`,
    args: [`${REPORT_PREFIX}${report.id}`, CRON, TZ, "2026-10-19T14:00:00.000Z"],
  });
  const { rows: made } = await world.db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
  const duplicateId = Number(made[0].id);
  assert.equal((await ownRows(world.db, report.id)).length, 2);

  const again = await put(schedulePath(report.id), { cron: CRON, tz: TZ });
  assert.equal(again.status, 200, again.text);
  assert.equal(Number(again.json.report.schedule_id), Number(kept.id));

  const rows = await ownRows(world.db, report.id);
  assert.equal(rows.length, 2, "the duplicate is switched off, not deleted");
  const on = rows.filter((row) => Number(row.enabled) === 1);
  assert.equal(on.length, 1, "exactly one row of this task is on");
  assert.equal(Number(on[0].id), Number(kept.id), "and it is the row the report points at");
  assert.equal(on[0].next_run, kept.next_run, "an ON row ahead of now keeps its window");
  const off = rows.find((row) => Number(row.id) === duplicateId);
  assert.equal(Number(off.enabled), 0, "the stale duplicate cannot fire");
  assert.equal(off.cron_expression, CRON, "its own columns are left alone");
  assert.equal(off.tz, TZ);
});

test("a paused report that still carries a seal loses the seal on a change and keeps its status and reason", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const runId = addPreviewRun(world, report);
  assert.equal((await post(`${reportPath(report.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER })).status, 200);

  // An owner pause keeps the seal on purpose, so a resume can prove nothing moved.
  const paused = await post(`${reportPath(report.id)}/pause`, { reason: "Starting over" });
  assert.equal(paused.status, 200, paused.text);
  const withSeal = await getReport(world.db, report.id);
  assert.equal(withSeal.status, "paused");
  assert.match(withSeal.live_seal, /^[0-9a-f]{64}$/);

  const changed = await put(schedulePath(report.id), { cron: OTHER_CRON, tz: TZ });
  assert.equal(changed.status, 200, changed.text);
  assert.equal(changed.json.report.status, "paused", "the status is unchanged");
  assert.equal(changed.json.report.pause_reason, "Starting over", "so is the reason");
  assert.equal(changed.json.report.live, false);

  const after = await getReport(world.db, report.id);
  assert.equal(after.live_seal, null, "the approval no longer describes the report");
  assert.equal(after.live_nonce, null);
  assert.equal((await ownRows(world.db, report.id))[0].cron_expression, OTHER_CRON);

  const resumed = await post(`${reportPath(report.id)}/resume`, {});
  assert.equal(resumed.status, 409, resumed.text);
  assert.equal(resumed.json.error, "go_live_needed");
});

/* ------------------------------------------------------------- the reports hook */

test("the reports hook's row guard accepts the row the route wrote", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  const runId = addPreviewRun(world, report);
  assert.equal((await post(`${reportPath(report.id)}/go-live`, { previewRunId: runId, expectedSenderAccountId: SENDER })).status, 200);
  assert.equal((await getReport(world.db, report.id)).status, "live");

  const notes = [];
  const hook = registerReportsHook(world.db, {
    approvals: world.approvalsDeps,
    now: () => clock,
    concurrency: 1,
    notify: async (_db, note) => { notes.push(note); },
    instanceZone: async () => "UTC",
    graceMs: () => 5 * 60 * 1000,
    getSecrets: () => [],
    lease: {
      now: () => clock, pid: 4242, isPidAlive: () => true,
      kernelBootId: () => "boot-reports-schedule", runId: "run-reports-schedule",
    },
    deliver: async () => {},
    runBlocks: async () => ({ items: [] }),
  });
  try {
    await hook.tick(world.db);
  } finally {
    _setReportsHookForTest(null);
    unregisterSchedulerHook("reports");
  }

  const after = await getReport(world.db, report.id);
  assert.equal(after.status, "live", "the row guard found the row the route wrote and left the report live");
  assert.equal(after.pause_reason, null);
  assert.equal(notes.length, 0, "the owner was told nothing");
  const { rows: system } = await world.db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_approvals_audit WHERE report_id = ? AND actor = 'system'",
    args: [report.id],
  });
  assert.equal(Number(system[0].n), 0, "no system pause was audited");
  // The window the route computed is still ahead of the hook's clock, so nothing was due.
  const { rows: runs } = await world.db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_runs WHERE report_id = ?", args: [report.id],
  });
  assert.equal(Number(runs[0].n), 0);
});

/* ---------------------------------------------------------------------- delete */

test("deleting the report removes the schedule row the route wrote, and nobody else's", async () => {
  const world = await setup();
  const report = await prepareReport(world.db, { schedule: false });
  const bystander = await prepareReport(world.db, { schedule: false });
  assert.equal((await put(schedulePath(report.id), { cron: CRON, tz: TZ })).status, 200);
  assert.equal((await put(schedulePath(bystander.id), { cron: OTHER_CRON, tz: TZ })).status, 200);

  const [row] = await ownRows(world.db, report.id);
  assert.equal((await ownRows(world.db, report.id)).length, 1, "the only row for that task");

  const deleted = await call("DELETE", reportPath(report.id));
  assert.equal(deleted.status, 200, deleted.text);
  assert.equal(await getReport(world.db, report.id), null);

  const { rows: gone } = await world.db.execute({
    sql: "SELECT COUNT(*) AS n FROM schedules WHERE id = ? OR task = ?",
    args: [row.id, `${REPORT_PREFIX}${report.id}`],
  });
  assert.equal(Number(gone[0].n), 0, "the report's schedule row went with it");

  const kept = await ownRows(world.db, bystander.id);
  assert.equal(kept.length, 1, "another report's own row is untouched");
  assert.equal(kept[0].cron_expression, OTHER_CRON);
});