// The recipe executor and the run engine's state rule: a run walks the registry's blocks, buffers
// `report_state` writes, and applies them only for a run that ends well and is not a preview. The M8
// rule (a custom block's trigger is the run row's) is exercised by counting the day's extra step runs.
//
// Harness: a real init-db'd scratch crow.db copied per test, real report/revision/step rows, the seal
// seed injected through the approvals deps, and a stubbed step runner (no sandbox needed).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-run-recipe-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");
const HOME = process.env.CROW_HOME;

const { createDbClient } = await import("../servers/db.js");
const {
  createReport, getReport, getState, saveRecipe, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { approveStep, proposeStep } = await import("../servers/gateway/reports/steps.js");
const { getUsage } = await import("../servers/gateway/reports/caps.js");
const { createKeychainKey } = await import("../servers/gateway/keychain/key.js");
const { REPORTS_BUNDLE, saveServiceSecret } = await import("../servers/gateway/keychain/store.js");
const {
  approveCredential, approveHost, injectHashOf, proposeCredential, proposeHost,
} = await import("../servers/gateway/reports/steps.js");
const { approveGoLive } = await import("../servers/gateway/reports/approvals.js");
const { executeRun, getRun, startRun } = await import("../servers/gateway/reports/run.js");
const { makeStateAccess, runRecipe } = await import(
  "../servers/gateway/reports/blocks/run-recipe.js"
);
const { approveSource, settingsHashOf } = await import(
  "../servers/gateway/reports/source-approvals.js"
);

const OWNER = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 23);
const PROJECT = 7;
const SENDER = "ma-0011223344556677";
const T0 = 1_700_000_000_000;
const DAY = "2026-01-02";

const STEP_FILES = Object.freeze({ "run.py": "print('{}')\n" });
const ITEMS = Object.freeze([{ id: "a", title: "One" }, { id: "b", title: "Two" }]);

/** The keychain key this instance really has (written under the temp home), and the secret it seals. */
const key = createKeychainKey({ crowHome: HOME });
const CREDENTIAL_SECRET = "report-credential-value";
const CREDENTIAL_UUID = "22222222-2222-4222-8222-222222222222";
const CREDENTIAL_HOST = "api.example.com";
const CREDENTIAL_RULE = Object.freeze({
  header: "Authorization", format: "Bearer {}", pathPrefixes: ["/v1/items"], methods: ["GET"],
});

/** A custom step, then the block that remembers what was already shown. */
const CUSTOM_RECIPE = Object.freeze({
  blocks: [
    {
      id: "fetch",
      type: "custom",
      // `trigger` in settings is bait: the run row decides, never the recipe (M8).
      settings: { step: "fetch", params: { limit: 3 }, trigger: "schedule" },
    },
    { id: "seen", type: "dedupe_seen", settings: { keyField: "id", refreshFields: ["title"] } },
  ],
});

/** The same, plus a source block this build cannot read: the run buffers a write and then fails. */
const FAILING_RECIPE = Object.freeze({
  blocks: [
    CUSTOM_RECIPE.blocks[0],
    CUSTOM_RECIPE.blocks[1],
    { id: "feed", type: "rss", settings: { url: "https://example.com/feed.xml" } },
  ],
});

const dirs = [];
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

/** The steps module's deps: the seal seed, the clock, this instance's home and the cap day. */
function stepDeps(over = {}) {
  return { loadSeed: () => ({ seed: SEED }), now: () => T0, crowHome: HOME, day: DAY, ...over };
}

/** The executor's deps for a custom step: a stubbed env, a stubbed walled runner, and the seal seed. */
function blockDeps(over = {}) {
  const envDir = join(HOME, "reports", "env", "python");
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    day: DAY,
    crowHome: HOME,
    getSecrets: () => [],
    ensureEnv: async () => ({
      ok: true, dir: envDir, hash: "c".repeat(64), cacheDir: join(HOME, "cache"), built: false,
    }),
    runStep: async () => ({ ok: true, output: { items: ITEMS } }),
    ...over,
  };
}

/** The approvals deps: the seed, the clock, the sender reader and the injected preview run row. */
function approvalsDeps(report, over = {}) {
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    senderReady: async () => true,
    getRun: async (_db, runId) => (runId === "prv-1"
      ? { id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev }
      : null),
    ...over,
  };
}

/**
 * The run engine's deps. The block executor is the engine's own default one (so this file exercises what
 * production runs); the step seam travels through the engine deps, the way a caller injects one.
 */
function runDeps(over = {}) {
  return {
    ...blockDeps(),
    deliver: async () => {},
    ...over,
  };
}

async function addSchedule(db) {
  await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, tz) VALUES ('weekly-report', '0 7 * * 1', 'Europe/Berlin')",
    args: [],
  });
  const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
  return Number(rows[0].id);
}

async function prepare(db, { recipe = CUSTOM_RECIPE, registry } = {}) {
  const scheduleId = await addSchedule(db);
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: "owner", botId: "bot-1", title: "Weekly listings",
  });
  const saved = await saveRecipe(db, {
    reportId: id,
    recipe,
    authorKind: "owner",
    ...(registry === undefined ? {} : { registry }),
  });
  await updateReportColumns(db, id, {
    schedule_id: scheduleId,
    sender_account_id: SENDER,
    delivery_mode: "email_link",
    comment_tier_default: "c",
    comment_visibility: "own",
    ai_commentary: 0,
  });
  return { id, rev: saved.rev };
}

async function approveStepFor(db, reportId) {
  const step = await proposeStep(db, stepDeps(), {
    reportId,
    stepKey: "fetch",
    language: "python",
    entry: "run.py",
    files: STEP_FILES,
    requirements: "",
    proposedBy: "owner",
  });
  await approveStep(db, stepDeps(), {
    reportId, stepKey: "fetch", rev: step.rev, bundleHash: step.bundleHash, actor: OWNER,
  });
}

/** A live report with its step approved: the world a scheduled or manual run starts from. */
async function liveReport({ recipe = CUSTOM_RECIPE } = {}) {
  const db = await freshDb();
  const report = await prepare(db, { recipe });
  await approveStepFor(db, report.id);
  const deps = approvalsDeps(report);
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor: OWNER });
  return { db, report, deps };
}

/** A guarded-request seam that records every URL and answers one JSON array. */
function fetchStub(urls, items = ITEMS) {
  return async (url) => {
    urls.push(url);
    return {
      final_url: url,
      http_status: 200,
      content_type: "application/json",
      charset: "utf-8",
      buffer: Buffer.from(JSON.stringify(items), "utf8"),
    };
  };
}

/** One approved credential of one report, through the real keychain row and the owner's tap. */
async function approveCredentialFor(db, reportId, { host = CREDENTIAL_HOST } = {}) {
  const deps = stepDeps();
  await proposeHost(db, deps, { reportId, host });
  await approveHost(db, deps, { reportId, host, actor: OWNER });
  await saveServiceSecret(db, key, {
    connectionUuid: CREDENTIAL_UUID,
    bundleId: REPORTS_BUNDLE,
    envKey: "REPORT_CREDENTIAL",
    label: "report credential",
    secret: CREDENTIAL_SECRET,
  });
  await proposeCredential(db, deps, { reportId, host, connectionUuid: CREDENTIAL_UUID, inject: CREDENTIAL_RULE });
  const { rows } = await db.execute({
    sql: "SELECT connection_uuid, inject_json FROM report_credentials WHERE report_id = ? AND host = ?",
    args: [reportId, host],
  });
  await approveCredential(db, deps, {
    reportId,
    host,
    connectionUuid: rows[0].connection_uuid,
    injectHash: injectHashOf(JSON.parse(rows[0].inject_json)),
    actor: OWNER,
  });
}

async function queueRun(db, reportId, over = {}) {
  const { runId } = await startRun(db, { now: () => T0 }, {
    reportId, trigger: "manual", requestedBy: "owner", ...over,
  });
  return runId;
}

async function stateRows(db, reportId) {
  const { rows } = await db.execute({
    sql: "SELECT key FROM report_state WHERE report_id = ? ORDER BY key",
    args: [reportId],
  });
  return rows.map((row) => row.key);
}

/* ---------------------------------------------------------------- the executor's ctx */

test("a source reads files from the report's own project workspace, never a caller's directory", async () => {
  const db = await freshDb();
  const report = await prepare(db);
  const dir = mkdtempSync(join(root, "ws-project-"));
  writeFileSync(join(dir, "items.json"), JSON.stringify([{ id: "a" }]));
  await db.execute({
    sql: "INSERT INTO project_spaces (id, slug, name, workspace_dir) VALUES (?, ?, ?, ?)",
    args: [PROJECT, "listings", "Listings", dir],
  });
  const recipe = { blocks: [{ id: "file", type: "workspace_file", settings: { path: "items.json" } }] };
  const read = (deps) => runRecipe(db, deps, {
    report: { id: report.id, project_id: PROJECT }, recipe, run: { trigger: "manual" },
  });

  // The report's project owns `dir`, so the file is read with no seam injected at all.
  const out = await read({});
  assert.deepEqual(out.items, [{ id: "a" }]);
  assert.deepEqual(out.sourceErrors, []);

  // A caller's own directory is not a seam: the project's folder is still the one read.
  const other = mkdtempSync(join(root, "ws-caller-"));
  assert.deepEqual((await read({ workspaceDir: other })).items, [{ id: "a" }]);

  // A test harness's override counts only under `testSeams`.
  const harness = await read({ testSeams: true, workspaceDirFor: async () => other });
  assert.deepEqual(harness.sourceErrors, [{ source: "file", message: "file_not_found" }]);
});

/* ------------------------------------------------------------- the named source errors */

test("a source block that cannot read is a named source error, not a silent skip", async () => {
  const out = await runRecipe(null, {}, {
    report: { id: "rpt-0000000000000000" },
    recipe: { blocks: [{ id: "feed", type: "rss", settings: { url: "https://example.com/feed.xml" } }] },
    run: { trigger: "manual" },
  });
  // The rss block has a run now: with no database there is no host approval, so it refuses by name.
  assert.deepEqual(out.sourceErrors, [{ source: "feed", message: "host_unapproved" }]);
  assert.deepEqual(out.items, []);
  assert.deepEqual(out.stateWrites, []);
});

test("a present block is skipped, because rendering is a later round", async () => {
  const out = await runRecipe(null, {}, {
    report: { id: "rpt-0000000000000000" },
    recipe: { blocks: [
      { id: "table1", type: "table", settings: { columns: ["title"] } },
      { id: "text1", type: "text", settings: { body: "hello" } },
    ] },
    run: { trigger: "manual" },
  });
  assert.deepEqual(out.sourceErrors, []);
  assert.deepEqual(out.warnings, []);
  assert.deepEqual(out.items, []);
});

test("an unknown block type in a stored revision fails closed at run", async () => {
  const db = await freshDb();
  const report = await prepare(db);
  // A stored revision the registry no longer knows: written straight into the revision row, because the
  // store refuses to save it (the real registry validates every save).
  await db.execute({
    sql: "UPDATE report_recipe_revisions SET recipe_json = ? WHERE report_id = ? AND rev = ?",
    args: [JSON.stringify({ blocks: [{ id: "gone", type: "something_new", settings: { url: "https://example.com" } }] }), report.id, report.rev],
  });
  await db.execute({
    sql: "UPDATE reports SET recipe_json = ? WHERE id = ?",
    args: [JSON.stringify({ blocks: [{ id: "gone", type: "something_new", settings: { url: "https://example.com" } }] }), report.id],
  });
  const runId = await queueRun(db, report.id, { trigger: "preview" });
  const out = await executeRun(db, runDeps(), runId);
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  const row = await getRun(db, runId);
  assert.deepEqual(row.blockLog.sourceErrors, [{ source: "gone", message: "unknown_block_type" }]);
});

/* ---------------------------------------------------------------------- the state rule */

test("a source error does not stop a later block that does not depend on it", async () => {
  const db = await freshDb();
  const report = await prepare(db);
  await approveStepFor(db, report.id);
  const out = await runRecipe(db, blockDeps(), {
    report: await getReport(db, report.id),
    recipe: { blocks: [{ id: "feed", type: "rss", settings: {} }, CUSTOM_RECIPE.blocks[0]] },
    run: { trigger: "manual" },
  });
  assert.deepEqual(out.sourceErrors, [{ source: "feed", message: "bad_settings" }]);
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 1,
    "the custom block after the failed source still ran");
  assert.deepEqual(out.items, ITEMS);
});

test("a shape block that fails is a warning, not a source error", async () => {
  const out = await runRecipe(null, {}, {
    report: { id: "rpt-0000000000000000" },
    recipe: { blocks: [
      { id: "join1", type: "enrich_lookup", settings: { source: "feed", joinField: "id", lookupKey: "id", fields: ["score"] } },
    ] },
    run: { trigger: "manual" },
  });
  assert.deepEqual(out.warnings, [{ source: "join1", message: "source_not_found" }]);
  assert.deepEqual(out.sourceErrors, []);
});

test("failed run leaves report_state unchanged", async () => {
  const { db, report, deps } = await liveReport({ recipe: FAILING_RECIPE });
  const runId = await queueRun(db, report.id);
  const out = await executeRun(db, runDeps({ approvals: deps }), runId);
  assert.equal(out.status, "failed", "the unreadable source fails the run");
  assert.equal(await getState(db, report.id, "seen:seen"), null,
    "the buffered dedupe write never landed");
  assert.deepEqual(await stateRows(db, report.id), []);
});

test("a preview never writes state", async () => {
  const db = await freshDb();
  const report = await prepare(db);
  await approveStepFor(db, report.id);
  assert.equal((await getReport(db, report.id)).status, "draft");
  const runId = await queueRun(db, report.id, { trigger: "preview" });
  const out = await executeRun(db, runDeps(), runId);
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  assert.equal(await getState(db, report.id, "seen:seen"), null);
  assert.deepEqual(await stateRows(db, report.id), []);
});

test("a successful scheduled run applies its buffered writes once", async () => {
  const { db, report, deps } = await liveReport();
  const runId = await queueRun(db, report.id, {
    trigger: "schedule", requestedBy: "schedule", scheduledFor: T0,
  });
  const out = await executeRun(db, runDeps({ approvals: deps }), runId);
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  const seen = await getState(db, report.id, "seen:seen");
  assert.deepEqual(Object.keys(seen).sort(), ["a", "b"], "both items were recorded");
  assert.deepEqual(await stateRows(db, report.id), ["seen:seen"], "one write, one row");

  // The next run sees the remembered keys: nothing new is shown, and the stored value is replaced by the
  // identical one rather than piling up.
  const second = await queueRun(db, report.id, {
    trigger: "schedule", requestedBy: "schedule", scheduledFor: T0 + 1000,
  });
  assert.equal((await executeRun(db, runDeps({ approvals: deps }), second)).status, "empty");
  assert.deepEqual(await getState(db, report.id, "seen:seen"), seen);
  assert.deepEqual(await stateRows(db, report.id), ["seen:seen"]);
});

/* -------------------------------------------------------------- the reserved state keys */

test("setState refuses the keys the artifact bridge owns", () => {
  const stateWrites = [];
  const { setState } = makeStateAccess({ stateWrites, buffered: new Map() });
  for (const key of ["preview_artifact_id", "source_approval:x", "source_approval:"]) {
    assert.throws(() => setState(key, { artifactId: "art-1" }), (err) => err.code === "reserved_state_key", key);
  }
  assert.equal(stateWrites.length, 0, "a refused key is not buffered");
  setState("seen:b1", { a: "hash" });
  assert.deepEqual(stateWrites, [{ key: "seen:b1", value: { a: "hash" } }]);
});

test("the run engine refuses a reserved state key a buffered list carries, and writes the rest", async () => {
  const { db, report, deps } = await liveReport();
  const runId = await queueRun(db, report.id);
  const out = await executeRun(db, runDeps({
    approvals: deps,
    runBlocks: async () => ({
      items: [{ id: "a" }],
      stateWrites: [
        { key: "preview_artifact_id", value: { artifactId: "art-under-a-recipe" } },
        { key: "seen:b1", value: { a: "hash" } },
        { key: "source_approval:feed", value: { settingsHash: "a".repeat(64) } },
      ],
    }),
  }), runId);
  assert.deepEqual(out, { status: "ok", artifactVersion: null }, "the run's status is unchanged");
  assert.equal(await getState(db, report.id, "preview_artifact_id"), null, "the bridge's key is not written");
  assert.equal(await getState(db, report.id, "source_approval:feed"), null, "nor the approvals prefix");
  assert.deepEqual(await getState(db, report.id, "seen:b1"), { a: "hash" }, "the block's own key lands");
  assert.deepEqual(await stateRows(db, report.id), ["seen:b1"]);
  assert.equal((await getRun(db, runId)).errorText, null, "nothing about it is an error");
});

/* ------------------------------------------------------------------------- M8, the trigger */

test("a recipe cannot name a custom block's trigger: a manual run still counts one extra step run", async () => {
  const { db, report, deps } = await liveReport();
  const manual = await queueRun(db, report.id);
  const out = await executeRun(db, runDeps({ approvals: deps }), manual);
  assert.deepEqual(out, { status: "ok", artifactVersion: null }, "the settings said schedule; the run row said manual");
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 1);

  // The same recipe under a scheduled run spends nothing, which is what proves the row was read.
  const scheduled = await queueRun(db, report.id, {
    trigger: "schedule", requestedBy: "schedule", scheduledFor: T0,
  });
  const second = await executeRun(db, runDeps({ approvals: deps }), scheduled);
  assert.equal(second.status, "empty", "the dedupe block saw the same items again");
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 1, "a scheduled run is not an extra run");
});

/* ------------------------------------------------------- S2, one extra step run per run */

/** A credentialed `http_json` block: a source that spends the day's extra step run. */
const CREDENTIALED_FEED = Object.freeze({
  id: "feed",
  type: "http_json",
  settings: { url: "https://api.example.com/items", credential: { host: "api.example.com" } },
});

/** The same block at the path the test's approved credential rule covers. */
const CREDENTIALED_ITEMS = Object.freeze({
  id: "feed",
  type: "http_json",
  settings: { url: "https://api.example.com/v1/items", credential: { host: "api.example.com" } },
});

test("a manual run with one custom block counts one extra step run, not two", async () => {
  const { db, report, deps } = await liveReport();
  const out = await executeRun(db, runDeps({ approvals: deps }), await queueRun(db, report.id));
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 1,
    "the run's one claim went through the step, and the step did not claim another");
});

test("a manual run with only an approved credentialed http_json block counts one extra step run", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [CREDENTIALED_ITEMS] } });
  const deps = approvalsDeps(report);
  await approveCredentialFor(db, report.id);
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor: OWNER });

  const urls = [];
  const out = await executeRun(
    db,
    runDeps({ approvals: deps, testSeams: true, testFetch: fetchStub(urls) }),
    await queueRun(db, report.id),
  );
  assert.equal(out.status, "ok", JSON.stringify(out));
  assert.deepEqual(urls, ["https://api.example.com/v1/items"], "the credentialed request was made");
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 1);

  // A scheduled run of the same recipe spends nothing.
  const scheduled = await queueRun(db, report.id, {
    trigger: "schedule", requestedBy: "schedule", scheduledFor: T0,
  });
  await executeRun(db, runDeps({ approvals: deps, testSeams: true, testFetch: fetchStub([]) }), scheduled);
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 1, "the schedule is not an extra run");
});

test("a credentialed http_json block whose credential is refused spends nothing", async () => {
  const { db, report, deps } = await liveReport({ recipe: { blocks: [CREDENTIALED_FEED] } });
  const runId = await queueRun(db, report.id);
  const out = await executeRun(db, runDeps({ approvals: deps }), runId);
  // The host is not approved, so the credential rule is never resolved and no request is sent: the
  // claim comes after the rule, so the day's cap was not touched.
  assert.equal(out.status, "failed");
  assert.deepEqual((await getRun(db, runId)).blockLog.sourceErrors,
    [{ source: "feed", message: "host_unapproved" }]);
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 0,
    "a request whose credential was refused reads nothing, so it costs nothing");
});

/* ------------------------------------------------- the extra step cap is claimed lazily */

const UNAPPROVED_CUSTOM = Object.freeze({
  id: "fetch",
  type: "custom",
  settings: { step: "fetch", params: { limit: 3 } },
});

/** Save a recipe as a bot, so every block in it is bot-introduced. */
async function botSave(db, reportId, blocks) {
  await saveRecipe(db, { reportId, recipe: { blocks }, authorKind: "bot" });
}

/** Run one preview and answer the run's status, its source errors and the day's extra step count. */
async function previewUsage(db, reportId) {
  const runId = await queueRun(db, reportId, { trigger: "preview", requestedBy: "bot:bot-1" });
  const out = await executeRun(db, runDeps(), runId);
  const row = await getRun(db, runId);
  return {
    out,
    sourceErrors: row.blockLog ? row.blockLog.sourceErrors : [],
    extraStepRuns: (await getUsage(db, reportId, DAY)).extraStepRuns,
  };
}

test("a preview whose gate blocks an unapproved custom block claims no extra step run", async () => {
  const db = await freshDb();
  const report = await prepare(db);
  await approveStepFor(db, report.id);
  await botSave(db, report.id, [UNAPPROVED_CUSTOM]);

  const blocked = await previewUsage(db, report.id);
  assert.equal(blocked.out.status, "failed");
  assert.deepEqual(blocked.sourceErrors, [{ source: "fetch", message: "Source fetch is waiting for your OK" }]);
  assert.equal(blocked.extraStepRuns, 0, "a block that never ran spends nothing");

  // The owner approves the exact settings: the same preview now spends the run's one claim, once.
  await approveSource(db, stepDeps(), {
    reportId: report.id,
    blockId: "fetch",
    expectedSettingsHash: settingsHashOf(UNAPPROVED_CUSTOM),
    actor: OWNER,
  });
  const approved = await previewUsage(db, report.id);
  assert.equal(approved.out.status, "ok");
  assert.deepEqual(approved.sourceErrors, []);
  assert.equal(approved.extraStepRuns, 1, "an approved block counts once, not twice");
});

test("a preview whose gate blocks an unapproved credentialed http_json block claims no extra step run", async () => {
  const db = await freshDb();
  const report = await prepare(db);
  await botSave(db, report.id, [CREDENTIALED_FEED]);

  const blocked = await previewUsage(db, report.id);
  assert.equal(blocked.out.status, "failed");
  assert.deepEqual(blocked.sourceErrors, [{ source: "feed", message: "Source feed is waiting for your OK" }]);
  assert.equal(blocked.extraStepRuns, 0, "the gate refused it before anything was read");

  // Approved content, but the credential rule is still refused (the host is not approved): the rule is
  // resolved before the claim, so a request that can never carry the credential costs nothing.
  await approveSource(db, stepDeps(), {
    reportId: report.id,
    blockId: "feed",
    expectedSettingsHash: settingsHashOf(CREDENTIALED_FEED),
    actor: OWNER,
  });
  const approved = await previewUsage(db, report.id);
  assert.equal(approved.out.status, "failed", "the host is not approved, so the block itself refuses");
  assert.deepEqual(approved.sourceErrors, [{ source: "feed", message: "host_unapproved" }]);
  assert.equal(approved.extraStepRuns, 0, "a refused credential spends nothing");
});

test("a run with a custom block plus a credentialed http_json block claims one extra step run in total", async () => {
  const db = await freshDb();
  const recipe = { blocks: [CREDENTIALED_ITEMS, UNAPPROVED_CUSTOM] };
  const report = await prepare(db, { recipe });
  const deps = approvalsDeps(report);
  await approveStepFor(db, report.id);
  await approveCredentialFor(db, report.id);
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor: OWNER });

  const urls = [];
  const runId = await queueRun(db, report.id);
  const out = await executeRun(
    db,
    runDeps({ approvals: deps, testSeams: true, testFetch: fetchStub(urls) }),
    runId,
  );
  assert.equal(out.status, "ok", JSON.stringify(out));
  assert.deepEqual(urls, ["https://api.example.com/v1/items"], "the credentialed source read once");
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 1,
    "the http_json claim and the step's claim are the run's one");
});

test("a preview whose step is still waiting claims no extra step run", async () => {
  const db = await freshDb();
  const report = await prepare(db);
  // Nothing approves the step, so `runnableStep` answers step_waiting: the claim comes after it.
  let ran = 0;
  const runId = await queueRun(db, report.id, { trigger: "preview", requestedBy: "owner" });
  const out = await executeRun(db, runDeps({
    runStep: async () => { ran += 1; return { ok: true, output: { items: [] } }; },
  }), runId);
  assert.equal(out.status, "failed");
  assert.deepEqual((await getRun(db, runId)).blockLog.sourceErrors,
    [{ source: "fetch", message: "Step fetch is waiting for your OK" }]);
  assert.equal(ran, 0, "the step never reached the runner");
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 0, "a step that never ran spends nothing");
});

test("a reached extra step cap fails the run and spends nothing", async () => {
  const { db, report, deps } = await liveReport();
  await db.execute({
    sql: `INSERT INTO dashboard_settings (key, value) VALUES ('reports.max_extra_step_runs_per_report_day', '0')
          ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    args: [],
  });
  const runId = await queueRun(db, report.id);
  const out = await executeRun(db, runDeps({ approvals: deps }), runId);
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  // The claim happens where the spend does, so the refusal is the custom block's own error.
  assert.deepEqual((await getRun(db, runId)).blockLog.sourceErrors,
    [{ source: "fetch", message: "cap_reached" }]);
  assert.deepEqual(await stateRows(db, report.id), [], "no state was written");
  assert.equal((await getUsage(db, report.id, DAY)).extraStepRuns, 0, "a refused claim leaves the count alone");
});

test("a preview gate stays shut on settings a bot put back after the owner removed them", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [CREDENTIALED_FEED] } });

  // The owner removes the block, then a bot re-adds the identical settings under the same id: the
  // owner's run of revisions carrying them ended at the removal, and the bot's re-add starts none.
  await saveRecipe(db, { reportId: report.id, recipe: { blocks: [] }, authorKind: "owner" });
  await botSave(db, report.id, [CREDENTIALED_FEED]);

  const blocked = await previewUsage(db, report.id);
  assert.equal(blocked.out.status, "failed");
  assert.deepEqual(blocked.sourceErrors, [{ source: "feed", message: "Source feed is waiting for your OK" }]);
  assert.equal(blocked.extraStepRuns, 0, "a block the gate refused spends nothing");
});

/* ------------------------------------------------------------------------ the save rules */

test("recipe save rejects an unknown block type", async () => {
  const db = await freshDb();
  const { id } = await createReport(db, { projectId: PROJECT, owner: "owner", title: "Listings" });
  await assert.rejects(
    () => saveRecipe(db, {
      reportId: id,
      recipe: { blocks: [{ id: "b1", type: "nope", settings: {} }] },
      authorKind: "owner",
    }),
    (err) => {
      assert.equal(err.code, "bad_recipe");
      assert.equal(err.detail, "blocks[0].type_unknown");
      return true;
    },
  );
  assert.equal((await getReport(db, id)).recipe_rev, 0, "a refused save writes nothing");
});

test("recipe save rejects a repeated block id and a bad setting", async () => {
  const db = await freshDb();
  const { id } = await createReport(db, { projectId: PROJECT, owner: "owner", title: "Listings" });
  const recipe = (blocks) => ({ blocks });
  await assert.rejects(
    () => saveRecipe(db, {
      reportId: id,
      recipe: recipe([
        { id: "keep", type: "filter", settings: { field: "title", op: "exists" } },
        { id: "keep", type: "sort", settings: { field: "title", direction: "asc" } },
      ]),
      authorKind: "owner",
    }),
    (err) => err.code === "bad_recipe" && err.detail === "blocks[1].id_duplicate",
  );
  await assert.rejects(
    () => saveRecipe(db, {
      reportId: id,
      recipe: recipe([{ id: "sort1", type: "sort", settings: { field: "title", direction: "up" } }]),
      authorKind: "owner",
    }),
    (err) => err.code === "bad_recipe" && err.detail === "blocks[0].direction",
  );
  assert.equal((await getReport(db, id)).recipe_rev, 0);
});

test("sourcesHash ignores a filter change and moves on a custom settings change", async () => {
  const db = await freshDb();
  const { id } = await createReport(db, { projectId: PROJECT, owner: "owner", title: "Listings" });
  const custom = { id: "fetch", type: "custom", settings: { step: "fetch", params: { limit: 3 } } };
  const filter = { id: "keep", type: "filter", settings: { field: "title", op: "exists" } };
  const base = await saveRecipe(db, {
    reportId: id, recipe: { blocks: [custom, filter] }, authorKind: "owner",
  });

  const filterEdit = await saveRecipe(db, {
    reportId: id,
    recipe: { blocks: [custom, { id: "keep", type: "filter", settings: { field: "title", op: "contains", value: "flat" } }] },
    authorKind: "owner",
  });
  assert.equal(filterEdit.sourcesHash, base.sourcesHash, "a filter setting is free");
  assert.notEqual(filterEdit.hash, base.hash, "but it is still a different recipe");

  const customEdit = await saveRecipe(db, {
    reportId: id,
    recipe: { blocks: [{ ...custom, settings: { step: "fetch", params: { limit: 5 } } }, filter] },
    authorKind: "owner",
  });
  assert.notEqual(customEdit.sourcesHash, base.sourcesHash, "a custom block's settings need the owner's tap");
});