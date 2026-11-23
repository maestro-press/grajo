// Crow Recurring Reports: deleting one report revokes everything it owns.
//
// Harness: a real init-db'd scratch crow.db per test, a real keychain key file under a temp CROW_HOME
// (so a `service` keychain row is sealed and can be reopened), and a fixed approvals seed injected
// through `deps.loadSeed`. Every report_* table is seeded for the report under test and for a second
// report, so a delete can be read as "this report's rows are gone, and that report's are untouched".
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-delete-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");
const HOME = process.env.CROW_HOME;

const { createDbClient } = await import("../servers/db.js");
const { createKeychainKey, loadKeychainKey } = await import("../servers/gateway/keychain/key.js");
const { REPORTS_BUNDLE, saveServiceSecret, serviceSecretsFor } = await import(
  "../servers/gateway/keychain/store.js"
);
const {
  approveCredential, approveHost, injectHashOf, proposeCredential, proposeHost,
} = await import("../servers/gateway/reports/steps.js");
const { deleteReport } = await import("../servers/gateway/reports/delete.js");
const { requestRun } = await import("../servers/gateway/reports/run-requests.js");
const {
  createReport, getReport, recordAudit, saveRecipe, setState, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { deleteScheduleRow } = await import("../servers/gateway/schedule-actions.js");

const OWNER = Object.freeze({ kind: "owner" });
const BOT_ACTOR = Object.freeze({ kind: "bot" });
const T0 = 1_700_000_000_000;
const UUID_A = "11111111-1111-4111-8111-111111111111";
const UUID_B = "22222222-2222-4222-8222-222222222222";
const SECRET_A = "credential-value-aaaaaaaaaaaaaaaa";
const SECRET_B = "credential-value-bbbbbbbbbbbbbbbb";
const RULE = Object.freeze({
  header: "Authorization",
  format: "Bearer {}",
  pathPrefixes: ["/v1/issues"],
  methods: ["GET", "HEAD"],
});

const key = createKeychainKey({ crowHome: HOME });

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

/** The test's world: a copy of master, plus its own reports area under the shared temp home. */
async function world() {
  const db = await freshDb();
  const home = join(root, "home" + n);
  mkdirSync(join(home, "reports"), { recursive: true });
  return { db, home };
}

function deps(home, over = {}) {
  return {
    loadSeed: () => ({ seed: key.seed }),
    loadKeychainKey: () => loadKeychainKey({ crowHome: HOME }),
    now: () => T0,
    crowHome: home,
    ...over,
  };
}

async function makeReport(db, title = "Weekly listings") {
  const { id } = await createReport(db, { projectId: 7, owner: "owner", botId: "bot-1", title });
  return id;
}

/** One approved host and one approved credential with its own keychain row. */
async function credentialFor(db, home, reportId, { host = "example.com", connectionUuid, secret } = {}) {
  await saveServiceSecret(db, key, {
    connectionUuid,
    bundleId: REPORTS_BUNDLE,
    envKey: "REPORT_CREDENTIAL",
    label: "report credential",
    secret,
  });
  await proposeHost(db, deps(home), { reportId, host });
  await approveHost(db, deps(home), { reportId, host, actor: OWNER });
  await proposeCredential(db, deps(home), {
    reportId, host, connectionUuid, inject: RULE, proposedBy: "bot:bot-1",
  });
  const { rows } = await db.execute({
    sql: "SELECT * FROM report_credentials WHERE report_id = ? AND host = ?", args: [reportId, host],
  });
  const row = rows[0];
  await approveCredential(db, deps(home), {
    reportId,
    host,
    connectionUuid: row.connection_uuid,
    injectHash: injectHashOf(JSON.parse(row.inject_json)),
    actor: OWNER,
  });
}

/** Every report_* table a report id can be keyed on, plus the `reports` row itself. */
async function reportTables(db) {
  const { rows } = await db.execute({
    sql: "SELECT name FROM sqlite_master WHERE type = 'table' AND name GLOB 'report*' ORDER BY name",
    args: [],
  });
  const out = [];
  for (const row of rows) {
    const name = String(row.name);
    const columns = (await db.execute(`PRAGMA table_info("${name}")`)).rows.map((c) => String(c.name));
    if (name === "reports" && columns.includes("id")) out.push({ name, column: "id" });
    else if (columns.includes("report_id")) out.push({ name, column: "report_id" });
  }
  return out;
}

async function rowsFor(db, table, column, value) {
  const { rows } = await db.execute({
    sql: `SELECT COUNT(*) AS n FROM "${table}" WHERE ${column} = ?`, args: [value],
  });
  return Number(rows[0].n);
}

/** One row of every report table, plus a `report:<id>` schedule row and a file in the report area. */
async function seedReport(db, home, reportId, label) {
  await saveRecipe(db, {
    reportId, recipe: { blocks: [{ id: "b1", type: "text", settings: {} }] },
    authorKind: "owner",
  });
  await setState(db, reportId, "baseline", { at: T0 });
  await recordAudit(db, { reportId, kind: "live", subject: null, actor: "owner", decided: "approved", at: T0 });
  await requestRun(db, { reportId, kind: "preview", requestedBy: "owner", now: T0 });

  const runId = `rrn-${label.repeat(16).slice(0, 16)}`;
  const recipientId = `rrc-${label.repeat(16).slice(0, 16)}`;
  await db.execute({
    sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, status, created_at)
          VALUES (?, ?, 'manual', 'owner', 'ok', ?)`,
    args: [runId, reportId, T0],
  });
  await db.execute({
    sql: `INSERT INTO report_versions (artifact_id, n, report_id, run_id, "trigger", created_at)
          VALUES (?, 1, ?, ?, 'manual', ?)`,
    args: [`art-${label}`, reportId, runId, T0],
  });
  await db.execute({
    sql: `INSERT INTO report_recipients (id, report_id, address, state, proposed_by, created_at)
          VALUES (?, ?, ?, 'approved', 'owner', ?)`,
    args: [recipientId, reportId, `${label}@example.com`, T0],
  });
  await db.execute({
    sql: `INSERT INTO report_sends (id, run_id, report_id, recipient_id, status, created_at, updated_at)
          VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
    args: [`rsd-${label}`, runId, reportId, recipientId, T0, T0],
  });
  // The reader half: the link that recipient's mail carried, and the comment they left through it.
  await db.execute({
    sql: `INSERT INTO report_link_tokens
            (id, report_id, recipient_id, run_id, send_id, artifact_id, version_n, token_hash, scope,
             approval_nonce, created_at, expires_at)
          VALUES (?, ?, ?, ?, ?, ?, 1, ?, 'comment', ?, ?, ?)`,
    args: [`rlt-${label}`, reportId, recipientId, runId, `rsd-${label}`, `art-${label}`,
      label.repeat(64), "e".repeat(32), T0, T0 + 86_400_000],
  });
  await db.execute({
    sql: `INSERT INTO report_recipient_comments
            (comment_id, thread_id, report_id, recipient_id, run_id, via, created_at)
          VALUES (?, '3', ?, ?, ?, 'link', ?)`,
    args: [label === "a" ? 1 : 2, reportId, recipientId, runId, T0],
  });
  await db.execute({
    sql: `INSERT INTO report_custom_steps (report_id, step_key, rev, language, entry, files_json, proposed_by, created_at)
          VALUES (?, 'fetch', 1, 'python', 'run.py', ?, 'owner', ?)`,
    args: [reportId, JSON.stringify({ files: { "run.py": "print(1)" }, assets: [] }), T0],
  });
  await db.execute({
    sql: "INSERT INTO report_assets (report_id, name, sha256, bytes, created_at) VALUES (?, 'data.json', ?, 2, ?)",
    args: [reportId, "c".repeat(64), T0],
  });
  await db.execute({
    sql: "INSERT INTO report_usage (report_id, day, emails, bot_ms, extra_step_runs) VALUES (?, '2026-01-01', 1, 10, 0)",
    args: [reportId],
  });
  await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, tz, enabled) VALUES (?, '0 7 * * 1', 'UTC', 1)",
    args: [`report:${reportId}`],
  });
  const schedule = (await db.execute({
    sql: "SELECT id FROM schedules WHERE task = ?", args: [`report:${reportId}`],
  })).rows[0];
  await updateReportColumns(db, reportId, {
    schedule_id: Number(schedule.id),
    artifact_id: `art-${label}`,
  });
  const area = join(home, "reports", reportId);
  mkdirSync(join(area, "assets"), { recursive: true });
  writeFileSync(join(area, "assets", "c".repeat(64)), "{}");
  return { runId, scheduleId: Number(schedule.id), area };
}

/* ------------------------------------------------------------------ the whole delete */

test("deleting a report revokes its keychain rows and removes every row it owns", async () => {
  const { db, home } = await world();
  const gone = await makeReport(db, "Weekly listings");
  const kept = await makeReport(db, "Monthly numbers");
  const goneAreas = await seedReport(db, home, gone, "a");
  const keptAreas = await seedReport(db, home, kept, "b");
  await credentialFor(db, home, gone, { connectionUuid: UUID_A, secret: SECRET_A });
  await credentialFor(db, home, kept, { connectionUuid: UUID_B, secret: SECRET_B });

  // Before: every report table really holds a row for each report.
  const tables = await reportTables(db);
  assert.ok(tables.length >= 12, `the report tables were really found (${tables.length})`);
  const beforeGone = [];
  for (const table of tables) {
    const count = await rowsFor(db, table.name, table.column, gone);
    if (count > 0) beforeGone.push(table.name);
  }
  for (const name of [
    "reports", "report_recipe_revisions", "report_state", "report_usage", "report_approvals_audit",
    "report_runs", "report_run_requests", "report_versions", "report_recipients", "report_sends",
    "report_link_tokens", "report_recipient_comments",
    "report_custom_steps", "report_assets", "report_hosts", "report_credentials",
  ]) {
    assert.ok(beforeGone.includes(name), `${name} held a row for the report before the delete`);
  }

  const out = await deleteReport(db, deps(home), { reportId: gone, actor: OWNER });
  assert.deepEqual(out, { ok: true, artifactId: "art-a" }, "the artifact is named, never deleted");

  // The keychain rows behind the report's credential are gone, and the secret is no longer served.
  const left = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM crow_keychain WHERE connection_uuid = ?", args: [UUID_A],
  });
  assert.equal(Number(left.rows[0].n), 0, "the report's keychain rows are removed");
  assert.deepEqual(
    await serviceSecretsFor(db, key, UUID_A, { allowedKeys: ["REPORT_CREDENTIAL"] }),
    {},
    "nothing reads the removed keychain row",
  );
  const other = await serviceSecretsFor(db, key, UUID_B, { allowedKeys: ["REPORT_CREDENTIAL"] });
  assert.equal(other.REPORT_CREDENTIAL, SECRET_B, "the other report's keychain row is untouched");

  // The report's schedule row and its run history are gone; its directory is gone.
  const schedules = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM schedules WHERE task = ?", args: [`report:${gone}`],
  });
  assert.equal(Number(schedules.rows[0].n), 0, "the report's schedule row is removed");
  const runHistory = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM schedule_runs WHERE schedule_id = ?", args: [goneAreas.scheduleId],
  });
  assert.equal(Number(runHistory.rows[0].n), 0, "and its schedule's run history with it");
  assert.equal(existsSync(goneAreas.area), false, "the report's own directory is removed");

  // No report table has a row for the deleted id, and the report row itself is gone.
  for (const table of tables) {
    const count = await rowsFor(db, table.name, table.column, gone);
    assert.equal(count, 0, `${table.name} still holds a row for the deleted report`);
  }
  assert.equal(await getReport(db, gone), null);

  // The other report is exactly as it was.
  assert.ok((await getReport(db, kept)) !== null, "the other report stays");
  for (const table of tables) {
    const count = await rowsFor(db, table.name, table.column, kept);
    assert.ok(count > 0, `${table.name} still holds the other report's row`);
  }
  assert.equal(existsSync(keptAreas.area), true, "and the other report's directory stays");
  const keptSchedules = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM schedules WHERE task = ?", args: [`report:${kept}`],
  });
  assert.equal(Number(keptSchedules.rows[0].n), 1, "and its schedule row");

  // The Schedule page's own writer still refuses a report row: this path did not weaken it.
  const pageGuard = await deleteScheduleRow(db, keptAreas.scheduleId);
  assert.deepEqual(pageGuard, { ok: false, code: "report-owned" }, "the page guard is untouched");
});

/* ------------------------------------------------------------------- the keychain */

test("a keychain failure aborts the delete with every report row and the directory still in place", async () => {
  const { db, home } = await world();
  const reportId = await makeReport(db);
  const seeded = await seedReport(db, home, reportId, "c");
  await credentialFor(db, home, reportId, { connectionUuid: UUID_A, secret: SECRET_A });

  const failing = deps(home, {
    deleteKeychainSecrets: async () => {
      throw new Error(`keychain locked while removing ${SECRET_A}`);
    },
  });
  await assert.rejects(
    () => deleteReport(db, failing, { reportId, actor: OWNER }),
    (err) => {
      assert.equal(err.code, "keychain_disconnect_failed");
      assert.equal(String(err.message).includes(SECRET_A), false, "no secret in the refusal");
      assert.equal(String(err.detail || "").includes(SECRET_A), false, "no secret in the detail");
      return true;
    },
  );

  // The bindings were revoked before the keychain was touched, and nothing is rolled back: the
  // credential stays revoked, its keychain row is left in place (marked disconnected by the revoke) and
  // every row of the report stays.
  assert.ok((await getReport(db, reportId)) !== null, "the report row stays");
  const credential = await db.execute({
    sql: "SELECT state FROM report_credentials WHERE report_id = ? AND host = 'example.com'", args: [reportId],
  });
  assert.equal(credential.rows[0]?.state, "revoked", "the binding was revoked and stays revoked");
  const keychain = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM crow_keychain WHERE connection_uuid = ?", args: [UUID_A],
  });
  assert.equal(Number(keychain.rows[0].n), 1, "the keychain row is not removed");
  assert.deepEqual(
    await serviceSecretsFor(db, key, UUID_A, { allowedKeys: ["REPORT_CREDENTIAL"] }),
    {},
    "the revoked binding's secret is no longer served",
  );
  assert.equal(existsSync(seeded.area), true, "the report's directory stays");
  const schedules = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM schedules WHERE task = ?", args: [`report:${reportId}`],
  });
  assert.equal(Number(schedules.rows[0].n), 1, "the schedule row stays");
  for (const table of await reportTables(db)) {
    // The pending run request is the one row that does NOT come back: it was dropped before the
    // teardown (see the cancellation test below), and a request for a report its owner deleted is not
    // worth restoring.
    if (table.name === "report_run_requests") continue;
    const count = await rowsFor(db, table.name, table.column, reportId);
    assert.ok(count > 0, `${table.name} still holds a row`);
  }
});

/* ----------------------------------------------------------------- the queued runs */

test("a queued run is cancelled and the pending requests dropped before any teardown", async () => {
  const { db, home } = await world();
  const reportId = await makeReport(db);
  const seeded = await seedReport(db, home, reportId, "h");
  await credentialFor(db, home, reportId, { connectionUuid: UUID_A, secret: SECRET_A });
  const queuedId = "rrn-1111111111111111";
  await db.execute({
    sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, status, gateway_run_id, created_at)
          VALUES (?, ?, 'manual', 'owner', 'queued', 'another-process', ?)`,
    args: [queuedId, reportId, T0],
  });
  await requestRun(db, { reportId, kind: "run_now", requestedBy: "bot:bot-1", now: T0 });

  // A teardown that aborts at the keychain leaves the rows in place, and the run it cancelled stays
  // cancelled: that is the accepted trade, and the reason the cancellation happens first.
  await assert.rejects(
    () => deleteReport(db, deps(home, {
      deleteKeychainSecrets: async () => { throw new Error("keychain locked"); },
    }), { reportId, actor: OWNER }),
    { code: "keychain_disconnect_failed" },
  );
  const cancelled = await db.execute({
    sql: "SELECT status, error_text, ended_at FROM report_runs WHERE id = ?", args: [queuedId],
  });
  assert.equal(cancelled.rows[0].status, "failed", "the queued run is not left for an executor");
  assert.equal(cancelled.rows[0].error_text, "This report was deleted.");
  assert.equal(Number(cancelled.rows[0].ended_at), T0, "and it has an end");
  const finished = await db.execute({
    sql: "SELECT status, error_text FROM report_runs WHERE id = ?", args: [seeded.runId],
  });
  assert.equal(finished.rows[0].status, "ok", "a finished run is left exactly as it was");
  assert.equal(finished.rows[0].error_text, null);
  const pending = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_run_requests WHERE report_id = ? AND claimed_at IS NULL",
    args: [reportId],
  });
  assert.equal(Number(pending.rows[0].n), 0, "the pending requests are dropped");
  assert.ok((await getReport(db, reportId)) !== null, "the report itself is still there");

  const out = await deleteReport(db, deps(home), { reportId, actor: OWNER });
  assert.equal(out.ok, true);
  for (const table of await reportTables(db)) {
    assert.equal(await rowsFor(db, table.name, table.column, reportId), 0, `${table.name} is empty`);
  }
});

test("a credential row that names another bundle's keychain row does not remove it", async () => {
  const { db, home } = await world();
  const reportId = await makeReport(db);
  await seedReport(db, home, reportId, "g");
  // A keychain row that belongs to an add-on, not to reports. A `connection_uuid` is only a reference a
  // row can be made to name, so the row behind it is the guard, never the reference alone.
  await saveServiceSecret(db, key, {
    connectionUuid: UUID_B,
    bundleId: "some-addon",
    envKey: "ADDON_TOKEN",
    label: "an add-on's own secret",
    secret: SECRET_B,
  });
  await db.execute({
    sql: `INSERT INTO report_credentials (report_id, host, connection_uuid, inject_json, state, created_at)
          VALUES (?, 'example.com', ?, ?, 'approved', ?)`,
    args: [reportId, UUID_B, JSON.stringify(RULE), T0],
  });

  const out = await deleteReport(db, deps(home), { reportId, actor: OWNER });
  assert.equal(out.ok, true);
  assert.deepEqual(out.keychainSkipped,
    [{ connectionUuid: UUID_B, code: "not_a_reports_credential" }],
    "the connection is named as skipped");
  const left = await db.execute({
    sql: "SELECT bundle_id, env_key, status FROM crow_keychain WHERE connection_uuid = ?", args: [UUID_B],
  });
  assert.equal(left.rows.length, 1, "the add-on's keychain row is not removed");
  assert.equal(left.rows[0].bundle_id, "some-addon");
  assert.equal(left.rows[0].env_key, "ADDON_TOKEN");
  assert.equal(left.rows[0].status, "active", "the tampered row did not disconnect the add-on's connection");
  const served = await serviceSecretsFor(db, key, UUID_B, { allowedKeys: ["ADDON_TOKEN"] });
  assert.equal(served.ADDON_TOKEN, SECRET_B, "and the add-on's secret is still served to it");
});

test("a credential row whose keychain connection is already gone reports already_gone", async () => {
  const { db, home } = await world();
  const reportId = await makeReport(db);
  await seedReport(db, home, reportId, "i");
  const goneUuid = "33333333-3333-4333-8333-333333333333";
  await db.execute({
    sql: `INSERT INTO report_credentials (report_id, host, connection_uuid, inject_json, state, created_at)
          VALUES (?, 'example.com', ?, ?, 'approved', ?)`,
    args: [reportId, goneUuid, JSON.stringify(RULE), T0],
  });

  const out = await deleteReport(db, deps(home), { reportId, actor: OWNER });
  assert.equal(out.ok, true);
  assert.deepEqual(out.keychainSkipped, [{ connectionUuid: goneUuid, code: "already_gone" }],
    "a connection with no row is not reported as somebody else's");
  assert.equal(await getReport(db, reportId), null);
});

/* --------------------------------------------------------------------- the guard */
test("a report with a run in hand refuses report_busy, and deletes once it is done", async () => {
  const { db, home } = await world();
  const reportId = await makeReport(db);
  const seeded = await seedReport(db, home, reportId, "d");
  await db.execute({
    sql: "UPDATE report_runs SET status = 'running' WHERE id = ?", args: [seeded.runId],
  });
  // A sibling still queued: the refusal must change nothing at all, that row included.
  const queuedId = "rrn-2222222222222222";
  await db.execute({
    sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, status, created_at)
          VALUES (?, ?, 'manual', 'owner', 'queued', ?)`,
    args: [queuedId, reportId, T0],
  });

  await assert.rejects(
    () => deleteReport(db, deps(home), { reportId, actor: OWNER }),
    { code: "report_busy" },
  );
  assert.ok((await getReport(db, reportId)) !== null, "nothing was deleted");
  assert.equal(existsSync(seeded.area), true, "and the directory stays");
  const stillQueued = await db.execute({
    sql: "SELECT status, error_text FROM report_runs WHERE id = ?", args: [queuedId],
  });
  assert.equal(stillQueued.rows[0].status, "queued", "the busy refusal cancels nothing");
  assert.equal(stillQueued.rows[0].error_text, null);

  // The queued sibling does not block the delete either, once the running one is done.
  await db.execute({
    sql: "UPDATE report_runs SET status = 'ok' WHERE id = ?", args: [seeded.runId],
  });
  const out = await deleteReport(db, deps(home), { reportId, actor: OWNER });
  assert.equal(out.ok, true);
  assert.equal(await getReport(db, reportId), null);
});

test("only the owner may delete, and an unknown report is not_found", async () => {
  const { db, home } = await world();
  const reportId = await makeReport(db);
  await seedReport(db, home, reportId, "e");

  await assert.rejects(
    () => deleteReport(db, deps(home), { reportId, actor: BOT_ACTOR }),
    { code: "owner_only" },
  );
  await assert.rejects(() => deleteReport(db, deps(home), { reportId }), { code: "owner_only" });
  assert.ok((await getReport(db, reportId)) !== null, "a refused delete removed nothing");

  await assert.rejects(
    () => deleteReport(db, deps(home), { reportId: "rpt-ffffffffffffffff", actor: OWNER }),
    { code: "not_found" },
  );
  const out = await deleteReport(db, deps(home), { reportId, actor: OWNER });
  assert.equal(out.ok, true);
  // Idempotent: the same delete again is not found, not a crash.
  await assert.rejects(
    () => deleteReport(db, deps(home), { reportId, actor: OWNER }),
    { code: "not_found" },
  );
});

/* -------------------------------------------------------------------- the directory */

test("a report area that resolves outside the reports root is refused, and nothing is deleted", async () => {
  const { db, home } = await world();
  const reportId = await makeReport(db);
  await seedReport(db, home, reportId, "f");
  await credentialFor(db, home, reportId, { connectionUuid: UUID_A, secret: SECRET_A });

  // The report's own directory is a symlink out of the reports area, with a file at its target.
  rmSync(join(home, "reports", reportId), { recursive: true, force: true });
  const outside = join(root, "outside" + n);
  mkdirSync(outside, { recursive: true });
  writeFileSync(join(outside, "keep.txt"), "keep");
  symlinkSync(outside, join(home, "reports", reportId));

  await assert.rejects(
    () => deleteReport(db, deps(home), { reportId, actor: OWNER }),
    { code: "bad_input" },
  );

  assert.equal(existsSync(join(outside, "keep.txt")), true, "nothing outside the reports area was removed");
  assert.ok((await getReport(db, reportId)) !== null, "and the report row stays");
  const keychain = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM crow_keychain WHERE connection_uuid = ?", args: [UUID_A],
  });
  assert.equal(Number(keychain.rows[0].n), 1, "and so do the keychain rows");
});