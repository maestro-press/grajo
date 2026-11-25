// Crow Recurring Reports' approvals: the go-live seal over the live set, what breaks it, what may
// re-stamp it (and what never may), and pause/resume.
//
// Harness: a real init-db'd scratch crow.db, copied per test (CROW_DATA_DIR under a temp dir, so
// nothing can touch a real Crow data dir), real report and revision rows, a fixed keychain seed
// injected through `deps.loadSeed`, and injected preview runs (`getRun`; the run tables arrive in a
// later PR). The schedules, mail accounts, keychain, providers and bot rows are real tables, so the
// module's own defaults are exercised too.
import { markBotDefPreEra } from "./helpers/bot-def-pre-era.mjs";
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-approvals-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
markBotDefPreEra(process.env.CROW_HOME);
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
// Go-live asks `linkFor` about every approved recipient, and a dashboard link needs a base URL a reader
// could open: this stands in for the operator's private dashboard address.
process.env.CROW_DASHBOARD_URL = "https://crow.example.ts.net:8444";
delete process.env.CROW_GATEWAY_URL;
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const {
  SETTINGS_CHANGED_PAUSE_REASON, applyPendingFreeChange, approveGoLive, approveRecipient, botSaveRecipe,
  isLive, liveSetFor, ownerSaveRecipe, pauseReport, pauseReportSystem, proposeRecipient, resumeReport,
  updateSettings, verifiedCommentSettings, verifyLive,
} = await import("../servers/gateway/reports/approvals.js");
const { senderReady } = await import("../servers/gateway/reports/sender-ready.js");
const { saveCustomRole, setBinding } = await import("../servers/shared/model-roles-store.js");
const {
  createReport, getReport, getRevision, getState, saveRecipe, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { verifyApprovalSeal } = await import("../servers/gateway/reports/seal.js");
const { sealFor } = await import("../servers/gateway/mail/drafts/seal.js");
const { createAccount, updateAccount } = await import("../servers/gateway/mail/store/accounts.js");
const { createMailCredentials } = await import("../servers/gateway/mail/credentials.js");

const OWNER = Object.freeze({ kind: "owner" });
const BOT_ACTOR = Object.freeze({ kind: "bot" });
const SEED = Buffer.alloc(32, 3);
const PROJECT = 7;
const SENDER = "ma-0011223344556677";
const T0 = 1_700_000_000_000;

/** The block registry a later PR ships; here it is a stub that marks the two free block types. */
const REGISTRY = Object.freeze({
  http_json: { sourceBearing: true },
  filter: { sourceBearing: false },
});

const SOURCE_RECIPE = {
  blocks: [
    { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=1" } },
    { id: "b2", type: "filter", settings: { field: "title", op: "exists" } },
  ],
};

/** The same recipe with only the free block's settings changed. */
const FREE_EDIT_RECIPE = {
  blocks: [
    { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=1" } },
    { id: "b2", type: "filter", settings: { field: "title", op: "contains", value: "listing" } },
  ],
};

/** The same recipe with the source-bearing block's settings changed. */
const SOURCE_EDIT_RECIPE = {
  blocks: [
    { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=2" } },
    { id: "b2", type: "filter", settings: { field: "title", op: "exists" } },
  ],
};

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
  return { db, crow, dir };
}

/** The module's deps, with the run reader and anything a test wants to change. */
function depsWith(over = {}) {
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    getRun: async () => null,
    senderReady: async () => true,
    registry: REGISTRY,
    ...over,
  };
}

/** A preview run reader answering from a table of runs. */
function runReader(runs) {
  return async (_db, runId) => runs[runId] ?? null;
}

async function addSchedule(db, { cron = "0 7 * * 1", tz = "Europe/Berlin" } = {}) {
  await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, tz) VALUES ('weekly-report', ?, ?)",
    args: [cron, tz],
  });
  const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
  return Number(rows[0].id);
}

/**
 * One report, saved once at rev 1 and set up the way go-live needs it: a schedule row, a sender, the
 * live-set settings. `schedule: false` leaves no schedule (the `no_schedule` case); `sealSender: false`
 * leaves the sender a plain column write (the never-sealed case).
 */
async function prepare(db, {
  recipe = SOURCE_RECIPE, registry = REGISTRY, ai = 0, schedule = true, sealSender = true,
} = {}) {
  const scheduleId = schedule ? await addSchedule(db) : null;
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: "owner", botId: "bot-1", title: "Weekly listings",
  });
  const saved = await saveRecipe(db, { reportId: id, recipe, authorKind: "owner", registry });
  await updateReportColumns(db, id, {
    schedule_id: scheduleId,
    sender_account_id: SENDER,
    delivery_mode: "email_link",
    comment_tier_default: "c",
    comment_visibility: "own",
    ai_commentary: ai,
  });
  if (sealSender) {
    await updateSettings(db, depsWith(), {
      reportId: id, settings: { sender_account_id: SENDER }, actor: OWNER,
    });
  }
  return { id, rev: saved.rev, sourcesHash: saved.sourcesHash, scheduleId };
}

/** Approve one report live, with a preview run of its current revision. */
async function goLive(db, report, { deps = depsWith(), runId = "prv-1", run = {} } = {}) {
  const runs = {
    [runId]: { id: runId, reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev, ...run },
  };
  const inner = { getRun: runReader(runs) };
  for (const key of Object.keys(deps)) if (key !== "getRun") inner[key] = deps[key];
  const result = await approveGoLive(db, inner, { reportId: report.id, previewRunId: runId, actor: OWNER });
  return { result, deps: inner };
}

/** A live report: the world most tests here start from. */
async function liveReport(options = {}) {
  const { db } = await freshDb();
  const report = await prepare(db, options);
  const runs = { "prv-1": { id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev } };
  const deps = depsWith({ ...(options.deps || {}), getRun: runReader(runs) });
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor: OWNER });
  return { db, report, deps };
}

async function row(db, id) {
  return getReport(db, id);
}

/* ------------------------------------------------------- the model a role names */

/**
 * One provider row and one custom role bound to one of its models, through the roles store (which
 * invalidates its own memoized context, so the next resolution sees the write).
 *
 * @returns {Promise<string>} the role id
 */
async function bindRole(db, { label = "Finance", model = "local-chat/m1", provider = {
  id: "local-chat", baseUrl: "http://127.0.0.1:8013/v1", host: "local",
} } = {}) {
  await db.execute({
    sql: "INSERT OR REPLACE INTO providers (id, base_url, host, models, disabled) VALUES (?, ?, ?, ?, 0)",
    args: [provider.id, provider.baseUrl, provider.host, JSON.stringify([{ id: "m1" }, { id: "m2" }])],
  });
  const made = await saveCustomRole(db, { label, job: "", capability: "chat" });
  assert.equal(made.ok, true, JSON.stringify(made));
  const bound = await setBinding(db, made.id, { model }, {});
  assert.equal(bound.ok, true, JSON.stringify(bound));
  return made.id;
}

/** The recipe of a report whose AI block names a role. */
function roleRecipe(roleId) {
  return {
    blocks: [
      { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=1" } },
      { id: "ai1", type: "ai_commentary", settings: { modelRole: `role:${roleId}` } },
    ],
  };
}

async function auditRows(db, reportId) {
  const { rows } = await db.execute({
    sql: "SELECT kind, actor, decided FROM report_approvals_audit WHERE report_id = ? ORDER BY id",
    args: [reportId],
  });
  return rows;
}

/* --------------------------------------------------------------- the live set */

test("a fresh conversation: liveSetFor reads the sealed revision's hashes, not the head's", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  const row0 = await row(db, report.id);
  // Move the head to a second revision with a different recipe: the sealed revision's row is what the
  // live set must keep naming.
  await saveRecipe(db, { reportId: report.id, recipe: SOURCE_EDIT_RECIPE, authorKind: "owner", registry: REGISTRY });
  await updateReportColumns(db, report.id, { live_rev: report.rev, live_nonce: "a".repeat(32) });
  const live = await row(db, report.id);
  const fields = await liveSetFor(db, depsWith(), live);
  const sealed = await getRevision(db, report.id, report.rev);
  assert.equal(fields.rev, report.rev);
  assert.equal(fields.recipeHash, sealed.recipe_hash);
  assert.equal(fields.sourcesHash, sealed.sources_hash);
  assert.equal(fields.sourcesHash, report.sourcesHash, "the sealed revision's own sources hash");
  assert.notEqual(fields.sourcesHash, live.sources_hash, "not the head's");
  assert.deepEqual(Object.keys(fields).sort(), [
    "aiCommentary", "artifactId", "botId", "commentTierDefault", "commentVisibility",
    "commentWindowRuns", "cron", "deliveryMode", "modelRef", "nonce", "projectId", "recipeHash",
    "reportId", "rev", "scheduleId", "senderAccountId", "sourcesHash", "tz",
  ]);
  assert.equal(fields.commentWindowRuns, 4, "the comment window seals as its number");
  assert.equal(fields.cron, "0 7 * * 1");
  assert.equal(fields.tz, "Europe/Berlin");
  assert.equal(fields.botId, "bot-1", "the bot the seal was made for");
  assert.equal(fields.projectId, PROJECT);
  assert.equal(fields.artifactId, "", "no artifact yet, so the empty string");
  assert.equal(fields.scheduleId, report.scheduleId);
  assert.equal(fields.modelRef, "", "no model is called, so no model reference");
  assert.equal(fields.aiCommentary, 0);
  assert.equal(row0.status, "draft");
});

test("go live seals the live set and the report runs", async () => {
  const { db, report, deps } = await liveReport();
  const live = await row(db, report.id);
  assert.equal(live.status, "live");
  assert.equal(Number(live.live_rev), report.rev);
  assert.equal(live.approved_preview_run, "prv-1");
  assert.match(live.live_seal, /^[0-9a-f]{64}$/);
  assert.match(live.live_nonce, /^[0-9a-f]{32}$/);
  assert.equal(live.pause_reason, null);
  assert.equal(Number(live.pending_free_change), 0);
  assert.equal(await isLive(db, deps, live), true);

  // The seal verifies over exactly the fields liveSetFor builds.
  const fields = await liveSetFor(db, deps, live);
  assert.equal(verifyApprovalSeal("live", fields, live.live_seal, SEED), true);
  assert.deepEqual((await auditRows(db, report.id)).map((r) => [r.kind, r.actor, r.decided]), [
    ["live", "owner", "approved"],
  ]);
});

test("verifyLive answers the live set it verified, and null for a report that may not run", async () => {
  const { db, report, deps } = await liveReport();
  const live = await row(db, report.id);
  const verified = await verifyLive(db, deps, live);
  assert.ok(verified, "a live report with a good seal");
  assert.equal(verified.rev, report.rev);
  assert.equal(verified.senderAccountId, SENDER);
  assert.equal(verified.deliveryMode, "email_link");
  assert.equal(verified.cron, "0 7 * * 1");
  assert.equal(verified.tz, "Europe/Berlin");
  assert.equal(verified.botId, "bot-1");
  assert.equal(verified.liveSet.nonce, live.live_nonce);
  assert.equal(verifyApprovalSeal("live", verified.liveSet, live.live_seal, SEED), true,
    "the liveSet half is exactly what the seal covers");
  assert.deepEqual(verified.recipe, SOURCE_RECIPE,
    "the parsed recipe of the revision both hashes came from");
  assert.deepEqual(verified, { ...verified.liveSet, liveSet: verified.liveSet, recipe: verified.recipe });

  // A later save moves the head without re-blessing the seal: the recipe is the SEALED revision's, never
  // the head's.
  await saveRecipe(db, {
    reportId: report.id, recipe: SOURCE_EDIT_RECIPE, authorKind: "owner", registry: REGISTRY,
  });
  const stillLive = await verifyLive(db, deps, await row(db, report.id));
  assert.ok(stillLive, "the seal still verifies over the sealed revision");
  assert.equal(stillLive.rev, report.rev, "at the revision the owner approved");
  assert.deepEqual(stillLive.recipe, SOURCE_RECIPE, "never the head's recipe");

  assert.equal(await verifyLive(db, deps, null), null, "no row");
  assert.equal(await isLive(db, deps, live), true);
  const paused = await pauseReport(db, deps, { reportId: report.id, actor: OWNER });
  assert.equal(await verifyLive(db, deps, paused), null, "a pause is not a live answer");
  assert.equal(await verifyLive(db, deps, { ...live, sender_account_id: "ma-8899aabbccddeeff" }), null,
    "a sender the owner never approved");
});

test("a direct UPDATE of live_rev stops the report without touching its status", async () => {
  const { db, report, deps } = await liveReport();
  await db.execute({ sql: "UPDATE reports SET live_rev = ? WHERE id = ?", args: [report.rev + 5, report.id] });
  const live = await row(db, report.id);
  assert.equal(live.status, "live", "the status word is not the gate");
  assert.equal(await isLive(db, deps, live), false);
});

test("a direct UPDATE of any live-set column makes isLive false", async () => {
  const cases = [
    ["sender_account_id", "ma-8899aabbccddeeff"],
    ["delivery_mode", "email_full"],
    ["comment_tier_default", "a"],
    ["comment_visibility", "all"],
    ["comment_window_runs", 10],
    ["ai_commentary", 1],
  ];
  for (const [column, value] of cases) {
    const { db, report, deps } = await liveReport();
    assert.equal(await isLive(db, deps, await row(db, report.id)), true, `${column}: starts live`);
    await db.execute({ sql: `UPDATE reports SET ${column} = ? WHERE id = ?`, args: [value, report.id] });
    assert.equal(await isLive(db, deps, await row(db, report.id)), false, `${column}: stopped`);
  }
});

test("a direct UPDATE of the sealed revision's recipe text stops the report", async () => {
  // Two kinds of content the stored hashes are supposed to name, each swapped in by a hand-written
  // UPDATE that leaves the hash columns exactly as they were.
  const edits = [
    ["a source's own settings", (recipe) => ({
      ...recipe,
      blocks: recipe.blocks.map((block) => (block.id === "b1"
        ? { ...block, settings: { ...block.settings, url: "https://feeds.example.test/other.xml" } }
        : block)),
    })],
    ["a model block", (recipe) => ({
      ...recipe,
      blocks: [...recipe.blocks, { id: "b3", type: "ai_commentary", settings: {} }],
    })],
  ];
  for (const [label, edit] of edits) {
    const { db, report, deps } = await liveReport();
    assert.equal(await isLive(db, deps, await row(db, report.id)), true, `${label}: starts live`);
    const revision = await getRevision(db, report.id, report.rev);
    await db.execute({
      sql: "UPDATE report_recipe_revisions SET recipe_json = ? WHERE report_id = ? AND rev = ?",
      args: [JSON.stringify(edit(JSON.parse(revision.recipe_json))), report.id, report.rev],
    });
    assert.equal(await isLive(db, deps, await row(db, report.id)), false, `${label}: stopped`);
  }

  // The same when the hash columns move and the text does not.
  const third = await liveReport();
  await third.db.execute({
    sql: "UPDATE report_recipe_revisions SET sources_hash = ? WHERE report_id = ? AND rev = ?",
    args: ["c".repeat(64), third.report.id, third.report.rev],
  });
  assert.equal(await isLive(third.db, third.deps, await row(third.db, third.report.id)), false,
    "a hash column the text does not agree with");
});

test("a direct UPDATE of the report's bot, project, artifact or schedule row stops it", async () => {
  const cases = [
    ["bot_id", "bot-2"],
    ["project_id", PROJECT + 1],
    ["artifact_id", "art-0011223344556677"],
  ];
  for (const [column, value] of cases) {
    const { db, report, deps } = await liveReport();
    assert.equal(await isLive(db, deps, await row(db, report.id)), true, `${column}: starts live`);
    await db.execute({ sql: `UPDATE reports SET ${column} = ? WHERE id = ?`, args: [value, report.id] });
    assert.equal(await isLive(db, deps, await row(db, report.id)), false, `${column}: stopped`);
  }

  // Another schedule row with the SAME cron and zone: cron and tz do not move, only the row id does.
  const { db, report, deps } = await liveReport();
  const otherId = await addSchedule(db);
  await db.execute({ sql: "UPDATE reports SET schedule_id = ? WHERE id = ?", args: [otherId, report.id] });
  const moved = await row(db, report.id);
  assert.equal(Number(moved.schedule_id), otherId);
  assert.equal(await isLive(db, deps, moved), false, "another schedule row");
});

test("an id column is live only as the number the seal was made over, never a text spelling of it", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  await db.execute({ sql: "UPDATE reports SET project_id = 12 WHERE id = ?", args: [report.id] });
  const runs = {
    "prv-1": { id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev },
  };
  const deps = depsWith({ getRun: runReader(runs) });
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor: OWNER });
  const live = await row(db, report.id);
  assert.equal(live.project_id, 12);
  assert.equal(await isLive(db, deps, live), true, "sealed over project 12");

  // A text spelling in the column is not the number, even where Number() reads it as 12.
  await db.execute({ sql: "UPDATE reports SET project_id = '0x0c' WHERE id = ?", args: [report.id] });
  const spelled = await row(db, report.id);
  assert.equal(typeof spelled.project_id, "string", "stored as text");
  assert.equal(await isLive(db, deps, spelled), false, "text that spells 12 is not the id 12");

  // The same at the row boundary, for every spelling an id column cannot hold.
  const bad = [
    ["project_id", "12"], ["project_id", "12.0"], ["project_id", "0x0c"],
    ["project_id", 0], ["project_id", -12], ["project_id", 12.5], ["project_id", 1e30],
    ["project_id", true],
    ["schedule_id", String(live.schedule_id)], ["schedule_id", "0x0c"],
  ];
  for (const [column, value] of bad) {
    assert.equal(await verifyLive(db, deps, { ...live, [column]: value }), null,
      `${column} = ${JSON.stringify(value)}`);
  }
  assert.ok(await verifyLive(db, deps, { ...live, project_id: 12 }), "the sealed number still verifies");
  assert.ok(await verifyLive(db, deps, { ...live, project_id: 12n }),
    "a bigint in the safe range reads back as that number");
});

test("a live report with no revision row for live_rev, or no schedule, is not live", async () => {
  const first = await liveReport();
  await first.db.execute({
    sql: "DELETE FROM report_recipe_revisions WHERE report_id = ? AND rev = ?",
    args: [first.report.id, first.report.rev],
  });
  assert.equal(await isLive(first.db, first.deps, await row(first.db, first.report.id)), false);

  const second = await liveReport();
  await second.db.execute({ sql: "UPDATE schedules SET cron_expression = '' WHERE id = ?", args: [second.report.scheduleId] });
  assert.equal(await isLive(second.db, second.deps, await row(second.db, second.report.id)), false, "no cron");
});

test("a changed model resolution stops the report, including the same provider at another host", async () => {
  const first = { providerId: "crow-chat", model: "big", locality: "local", baseUrlHost: "127.0.0.1:9100" };
  let current = first;
  const resolver = async () => current;
  const { db, report, deps } = await liveReport({ ai: 1, deps: { resolveModelRef: resolver } });
  const live = await row(db, report.id);
  assert.equal(await isLive(db, deps, live), true, "the same resolution verifies");
  assert.equal(JSON.parse(live.model_ref).providerId, "crow-chat", "the resolved model is on the row");

  current = { ...first, providerId: "crow-other" };
  assert.equal(await isLive(db, deps, await row(db, report.id)), false, "another provider");

  current = { ...first, model: "small" };
  assert.equal(await isLive(db, deps, await row(db, report.id)), false, "another model");

  current = { ...first, baseUrlHost: "api.example-cloud.test" };
  assert.equal(await isLive(db, deps, await row(db, report.id)), false, "same provider, another host");

  current = null;
  assert.equal(await isLive(db, deps, await row(db, report.id)), false, "no resolution at all");
});

test("a seal made under the mail tap domain never verifies as a reports live seal", async () => {
  const { db, report, deps } = await liveReport();
  const tapSeal = sealFor({
    draftId: report.id,
    headHash: "a".repeat(64),
    action: "send",
    when: T0,
    attachDigest: "b".repeat(64),
    accountId: SENDER,
    fromAddress: "alex@example.com",
    tapId: "c".repeat(32),
  }, SEED);
  await db.execute({ sql: "UPDATE reports SET live_seal = ? WHERE id = ?", args: [tapSeal, report.id] });
  assert.equal(await isLive(db, deps, await row(db, report.id)), false);
});

/* ------------------------------------------------------------ go live refusals */

test("go live refuses a non-owner actor before it reads anything", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  const deps = depsWith({ getRun: async () => { throw new Error("getRun should not be called"); } });
  for (const actor of [BOT_ACTOR, undefined, null, { kind: "system" }, "owner"]) {
    await assert.rejects(
      () => approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor }),
      (err) => {
        assert.equal(err.code, "owner_only");
        return true;
      },
      String(actor),
    );
  }
  assert.equal((await row(db, report.id)).status, "draft");
});

test("go live refuses a missing preview, another report's run, a stale one, a failed one", async () => {
  const cases = [
    ["no run at all", {}, null, "preview_missing"],
    ["another report's run", {}, { reportId: "rpt-ffffffffffffffff" }, "preview_missing"],
    ["a full run, not a preview", {}, { kind: "run" }, "preview_missing"],
    ["an older revision", {}, { recipeRev: 99 }, "preview_stale"],
    ["a failed preview", {}, { status: "failed" }, "preview_failed"],
    ["a preview still running", {}, { status: "running" }, "preview_failed"],
  ];
  for (const [label, opts, run, code] of cases) {
    const { db } = await freshDb();
    const report = await prepare(db);
    const runs = run == null ? {} : {
      "prv-1": { id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev, ...run },
    };
    const deps = depsWith({ getRun: runReader(runs) });
    await assert.rejects(
      () => approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor: OWNER }),
      (err) => {
        assert.equal(err.code, code, label);
        return true;
      },
      label,
    );
    assert.equal((await row(db, report.id)).status, "draft", `${label}: nothing written`);
  }
});

test("go live refuses a report with no schedule, and one whose sender is not ready", async () => {
  const noSchedule = await freshDb();
  const unscheduled = await prepare(noSchedule.db, { schedule: false });
  await assert.rejects(
    () => approveGoLive(noSchedule.db, depsWith({
      getRun: async () => ({ id: "prv-1", reportId: unscheduled.id, kind: "preview", status: "ok", recipeRev: unscheduled.rev }),
    }), { reportId: unscheduled.id, previewRunId: "prv-1", actor: OWNER }),
    (err) => { assert.equal(err.code, "no_schedule"); return true; },
  );

  for (const senderCase of [
    ["not ready", { senderReady: async () => false }, SENDER],
    ["no sender account", {}, null],
  ]) {
    const [label, over, sender] = senderCase;
    const world = await freshDb();
    const report = await prepare(world.db);
    if (sender == null) await updateReportColumns(world.db, report.id, { sender_account_id: null });
    await assert.rejects(
      () => approveGoLive(world.db, depsWith({
        ...over,
        getRun: async () => ({ id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev }),
      }), { reportId: report.id, previewRunId: "prv-1", actor: OWNER }),
      (err) => { assert.equal(err.code, "sender_not_ready", label); return true; },
    );
    assert.equal((await row(world.db, report.id)).status, "draft", `${label}: nothing written`);
  }
});

test("go live refuses to seal when the model a model-calling recipe needs does not resolve", async () => {
  const { db } = await freshDb();
  const report = await prepare(db, { ai: 1 });
  await assert.rejects(
    () => approveGoLive(db, depsWith({
      getRun: async () => ({ id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev }),
      resolveModelRef: async () => null,
    }), { reportId: report.id, previewRunId: "prv-1", actor: OWNER }),
    (err) => { assert.equal(err.code, "model_unresolved"); return true; },
  );
  assert.equal((await row(db, report.id)).status, "draft");
});

test("a missing keychain seed is its own code, and nothing is written", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  await assert.rejects(
    () => approveGoLive(db, depsWith({
      loadSeed: () => null,
      getRun: async () => ({ id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev }),
    }), { reportId: report.id, previewRunId: "prv-1", actor: OWNER }),
    (err) => { assert.equal(err.code, "keychain_key_missing"); return true; },
  );
  assert.equal((await row(db, report.id)).status, "draft");
  assert.equal((await row(db, report.id)).live_seal, null);
});

test("go live refuses while an outside recipient has no link kind, and writes nothing", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  // One approved recipient at tier a: the public link kinds (and their tokens) arrive with PR 6a, so
  // this report's mail would point nowhere.
  const proposed = await proposeRecipient(db, depsWith(), {
    reportId: report.id, address: "alex@example.com", commentTier: "a", proposedBy: "owner",
  });
  const approved = await approveRecipient(db, depsWith(), { recipientId: proposed.id, actor: OWNER });
  assert.equal(approved.state, "approved");

  await assert.rejects(
    () => goLive(db, report),
    (err) => {
      assert.equal(err.code, "link_unavailable");
      assert.equal(err.message, "link_unavailable:alex@example.com");
      assert.equal(err.detail, "alex@example.com");
      return true;
    },
  );
  const after1 = await row(db, report.id);
  assert.equal(after1.status, "draft", "nothing was written");
  assert.equal(after1.live_seal, null);
  assert.equal(after1.live_nonce, null);
});

test("go live still works with only tier c recipients", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  // The dashboard link is keyed by the project's slug, so the report's project row has to exist.
  await db.execute({
    sql: "INSERT INTO project_spaces (id, uuid, slug, name) VALUES (?, ?, ?, ?)",
    args: [PROJECT, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "weekly-listings", "weekly-listings"],
  });
  const proposed = await proposeRecipient(db, depsWith(), {
    reportId: report.id, address: "alex@example.com", commentTier: "c", proposedBy: "owner",
  });
  await approveRecipient(db, depsWith(), { recipientId: proposed.id, actor: OWNER });

  const { result } = await goLive(db, report);
  assert.equal(result.ok, true);
  const after1 = await row(db, report.id);
  assert.equal(after1.status, "live");
  assert.match(after1.live_seal, /^[0-9a-f]{64}$/);
});

/* -------------------------------------------------------------- pause / resume */

test("pause then resume re-activates a report whose seal still verifies", async () => {
  const { db, report, deps } = await liveReport();
  const sealBefore = (await row(db, report.id)).live_seal;

  const paused = await pauseReport(db, deps, { reportId: report.id, reason: "Paused by hand", actor: OWNER });
  assert.equal(paused.status, "paused");
  assert.equal(paused.pause_reason, "Paused by hand");
  assert.equal(paused.live_seal, sealBefore, "a pause keeps the seal");
  assert.equal(await isLive(db, deps, paused), false, "paused is not live");

  const resumed = await resumeReport(db, deps, { reportId: report.id, actor: OWNER });
  assert.equal(resumed.status, "live");
  assert.equal(resumed.pause_reason, null);
  assert.equal(await isLive(db, deps, resumed), true);
  assert.deepEqual((await auditRows(db, report.id)).map((r) => [r.actor, r.decided]), [
    ["owner", "approved"], ["owner", "refused"], ["owner", "approved"],
  ]);
});

test("resume after a direct UPDATE refuses with go_live_needed and leaves the report paused", async () => {
  const { db, report, deps } = await liveReport();
  await pauseReportSystem(db, deps, { reportId: report.id, reason: "System paused this" });
  await db.execute({ sql: "UPDATE reports SET delivery_mode = 'both' WHERE id = ?", args: [report.id] });
  await assert.rejects(
    () => resumeReport(db, deps, { reportId: report.id, actor: OWNER }),
    (err) => { assert.equal(err.code, "go_live_needed"); return true; },
  );
  const after1 = await row(db, report.id);
  assert.equal(after1.status, "paused", "still paused");
  assert.equal(after1.pause_reason, "System paused this");
});

test("the system pause needs no actor, keeps the seal, and scrubs a secret out of the reason", async () => {
  const { db, report } = await liveReport();
  const sealBefore = (await row(db, report.id)).live_seal;
  const deps = depsWith({ getSecrets: () => ["swordfish-value"] });
  const paused = await pauseReportSystem(db, deps, {
    reportId: report.id, reason: "Provider said swordfish-value\nand more",
  });
  assert.equal(paused.status, "paused");
  assert.equal(paused.live_seal, sealBefore, "the seal is unchanged");
  assert.equal(paused.pause_reason.includes("swordfish-value"), false);
  assert.equal(paused.pause_reason.includes("[redacted]"), true);
  assert.equal(paused.pause_reason.includes("\n"), false, "one line");
  assert.deepEqual((await auditRows(db, report.id)).map((r) => r.actor), ["owner", "system"]);
});

/* ------------------------------------------------------------- recipe saves */

test("the owner's free change re-stamps the live seal at the new revision", async () => {
  const { db, report, deps } = await liveReport();
  const before = await row(db, report.id);

  const saved = await ownerSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT_RECIPE, actor: OWNER });
  assert.deepEqual(saved, {
    rev: before.recipe_rev + 1, hash: saved.hash, sourcesHash: before.sources_hash,
    restamped: true, needsGoLive: false, authorSealed: true,
  });
  const after1 = await row(db, report.id);
  assert.equal(Number(after1.live_rev), saved.rev, "the seal names the new revision");
  assert.notEqual(after1.live_nonce, before.live_nonce, "a fresh nonce");
  assert.notEqual(after1.live_seal, before.live_seal, "a fresh seal");
  assert.equal(Number(after1.pending_free_change), 0);
  assert.equal(after1.status, "live");
  assert.equal(await isLive(db, deps, after1), true);
  const sealed = await getRevision(db, report.id, saved.rev);
  assert.equal(sealed.recipe_hash, saved.hash, "the seal covers the new recipe's hash");
});

test("a re-stamp seals the live set it verified, not a schedule re-read a moment later", async () => {
  const { db, report, deps } = await liveReport();
  // Verification reads the schedule twice (a fail-closed pre-check and the sealer's own read). A reader
  // that answers a different cron from the third read on is exactly the read a re-stamp used to make.
  let reads = 0;
  const flakySchedule = async () => {
    reads += 1;
    return reads >= 3
      ? { cron: "0 9 * * 5", tz: "Europe/Berlin" }
      : { cron: "0 7 * * 1", tz: "Europe/Berlin" };
  };
  const saving = depsWith({ ...deps, getSchedule: flakySchedule });
  const saved = await ownerSaveRecipe(db, saving, {
    reportId: report.id, recipe: FREE_EDIT_RECIPE, actor: OWNER,
  });
  assert.equal(saved.restamped, true);
  assert.equal(reads, 2, "the re-stamp does not read the schedule again");

  const after1 = await row(db, report.id);
  assert.equal(Number(after1.live_rev), saved.rev);
  const verified = await verifyLive(db, depsWith(), after1);
  assert.ok(verified, "the fresh seal verifies over the schedule row");
  assert.equal(verified.cron, "0 7 * * 1", "the cron the verification read, never the later one");
});

test("the owner's source-bearing change does not re-stamp: the report stays on its sealed revision", async () => {
  const { db, report, deps } = await liveReport();
  const before = await row(db, report.id);

  const saved = await ownerSaveRecipe(db, deps, { reportId: report.id, recipe: SOURCE_EDIT_RECIPE, actor: OWNER });
  assert.equal(saved.restamped, false);
  assert.equal(saved.needsGoLive, true);
  assert.notEqual(saved.sourcesHash, before.sources_hash, "the sources hash moved");

  const after1 = await row(db, report.id);
  assert.equal(Number(after1.live_rev), before.live_rev, "still sealed at the old revision");
  assert.equal(after1.live_seal, before.live_seal, "the seal is untouched");
  assert.equal(Number(after1.recipe_rev), saved.rev, "the head moved");
  assert.equal(await isLive(db, deps, after1), true, "the old seal still verifies");
});

test("with no block registry every block counts, so even a free edit needs a go-live", async () => {
  const { db } = await freshDb();
  const report = await prepare(db, { registry: null });
  // The registry that saved the recipe and the one that verifies it are the same (the server's own).
  const deps = depsWith({
    registry: null,
    getRun: async () => ({ id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev }),
  });
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor: OWNER });
  const saved = await ownerSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT_RECIPE, actor: OWNER });
  assert.equal(saved.restamped, false);
  assert.equal(saved.needsGoLive, true);
});

test("the owner's save on a draft never re-stamps and never asks for a go-live", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  const deps = depsWith();
  const saved = await ownerSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT_RECIPE, actor: OWNER });
  assert.equal(saved.restamped, false);
  assert.equal(saved.needsGoLive, false);
  assert.equal((await row(db, report.id)).live_seal, null);
});

test("the owner's save needs the owner", async () => {
  const { db, report } = await liveReport();
  for (const actor of [BOT_ACTOR, undefined, { kind: "system" }]) {
    await assert.rejects(
      () => ownerSaveRecipe(db, depsWith(), { reportId: report.id, recipe: FREE_EDIT_RECIPE, actor }),
      (err) => { assert.equal(err.code, "owner_only"); return true; },
    );
  }
  assert.equal(Number((await row(db, report.id)).recipe_rev), report.rev, "nothing was saved");
});

test("a bot's free change marks pending_free_change and never re-stamps", async () => {
  const { db, report, deps } = await liveReport();
  const before = await row(db, report.id);

  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT_RECIPE });
  assert.equal(saved.pendingFreeChange, true);
  assert.equal(saved.needsGoLive, false);
  const after1 = await row(db, report.id);
  assert.equal(Number(after1.pending_free_change), 1);
  assert.equal(Number(after1.live_rev), before.live_rev, "the seal did not move");
  assert.equal(after1.live_seal, before.live_seal);
  assert.equal(await isLive(db, deps, after1), true);
});

test("a bot's source-bearing change leaves a head revision only", async () => {
  const { db, report, deps } = await liveReport();
  const before = await row(db, report.id);
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: SOURCE_EDIT_RECIPE });
  assert.equal(saved.pendingFreeChange, false);
  assert.equal(saved.needsGoLive, true);
  const after1 = await row(db, report.id);
  assert.equal(Number(after1.pending_free_change), 0);
  assert.equal(Number(after1.live_rev), before.live_rev);
  assert.equal(await isLive(db, deps, after1), true, "the sealed revision is unchanged");
});

test("a bot save cannot bring its own block registry, so a source change never looks free", async () => {
  const { db, report, deps } = await liveReport();
  // A registry that calls every block free. If a bot's save honoured it, the new source would hash the
  // same as the old one and the save would land pending_free_change for a one-tap Apply.
  const freeRegistry = { http_json: { sourceBearing: false }, filter: { sourceBearing: false } };
  const saved = await botSaveRecipe(db, deps, {
    reportId: report.id, recipe: SOURCE_EDIT_RECIPE, registry: freeRegistry,
  });
  assert.equal(saved.pendingFreeChange, false, "the caller's registry is ignored");
  assert.equal(saved.needsGoLive, true);
  assert.equal(Number((await row(db, report.id)).pending_free_change), 0);

  // Even forced pending, Apply recomputes both revisions' sources hashes and refuses.
  await updateReportColumns(db, report.id, { pending_free_change: 1 });
  await assert.rejects(
    () => applyPendingFreeChange(db, deps, { reportId: report.id, actor: OWNER }),
    (err) => { assert.equal(err.code, "go_live_needed"); return true; },
  );
  assert.equal(await isLive(db, deps, await row(db, report.id)), true, "still on its sealed revision");
});

test("a bot's save on a draft asks for nothing", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  const saved = await botSaveRecipe(db, depsWith(), { reportId: report.id, recipe: FREE_EDIT_RECIPE });
  assert.equal(saved.pendingFreeChange, false);
  assert.equal(saved.needsGoLive, false);
});

test("applyPendingFreeChange re-stamps the bot's free change, and needs the owner", async () => {
  const { db, report, deps } = await liveReport();
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT_RECIPE });

  await assert.rejects(
    () => applyPendingFreeChange(db, deps, { reportId: report.id, actor: BOT_ACTOR }),
    (err) => { assert.equal(err.code, "owner_only"); return true; },
  );

  const applied = await applyPendingFreeChange(db, deps, { reportId: report.id, actor: OWNER });
  assert.deepEqual(applied, { ok: true, liveRev: saved.rev });
  const after1 = await row(db, report.id);
  assert.equal(Number(after1.live_rev), saved.rev);
  assert.equal(Number(after1.pending_free_change), 0);
  assert.equal(await isLive(db, deps, after1), true);
  const audit = await auditRows(db, report.id);
  assert.deepEqual(audit.at(-1), { kind: "live", actor: "owner", decided: "approved" });
});

test("applyPendingFreeChange refuses with nothing pending, and when the sources moved", async () => {
  const { db, report, deps } = await liveReport();
  await assert.rejects(
    () => applyPendingFreeChange(db, deps, { reportId: report.id, actor: OWNER }),
    (err) => { assert.equal(err.code, "bad_input"); return true; },
  );

  // A bot's source-bearing save, forced pending: the head revision's own sources hash no longer matches
  // the seal, so there is nothing to apply and a real go-live is needed.
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: SOURCE_EDIT_RECIPE });
  await updateReportColumns(db, report.id, { pending_free_change: 1 });
  await assert.rejects(
    () => applyPendingFreeChange(db, deps, { reportId: report.id, actor: OWNER }),
    (err) => { assert.equal(err.code, "go_live_needed"); return true; },
  );
  assert.equal(await isLive(db, deps, await row(db, report.id)), true, "still on its sealed revision");
});

test("applyPendingFreeChange reads the revision text, so an edited head revision refuses the Apply", async () => {
  const { db, report, deps } = await liveReport();
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT_RECIPE });
  assert.equal(saved.pendingFreeChange, true);
  assert.equal(Number((await row(db, report.id)).pending_free_change), 1);

  // The head revision's text becomes a source change while its hash columns (and the head's) are left
  // alone: the columns still read "free", the content says otherwise.
  await db.execute({
    sql: "UPDATE report_recipe_revisions SET recipe_json = ? WHERE report_id = ? AND rev = ?",
    args: [JSON.stringify(SOURCE_EDIT_RECIPE), report.id, saved.rev],
  });
  await assert.rejects(
    () => applyPendingFreeChange(db, deps, { reportId: report.id, actor: OWNER }),
    (err) => { assert.equal(err.code, "go_live_needed"); return true; },
  );
  const after1 = await row(db, report.id);
  assert.equal(Number(after1.live_rev), report.rev, "still sealed at the old revision");
  assert.equal(Number(after1.pending_free_change), 1, "nothing was applied");
});

/* ------------------------------------------------------------------- settings */

test("a live-set settings change on a live report pauses it with the fixed sentence", async () => {
  const cases = [
    ["delivery_mode", "email_full"],
    ["comment_tier_default", "a"],
    ["comment_visibility", "all"],
    ["comment_window_runs", 10],
    ["ai_commentary", 1],
    ["sender_account_id", "ma-8899aabbccddeeff"],
  ];
  for (const [key, value] of cases) {
    const { db, report, deps } = await liveReport();
    const updated = await updateSettings(db, deps, { reportId: report.id, settings: { [key]: value }, actor: OWNER });
    assert.equal(updated.status, "paused", `${key}: paused`);
    assert.equal(updated.pause_reason, SETTINGS_CHANGED_PAUSE_REASON, `${key}: the sentence`);
    assert.equal(String(updated[key]), String(value), `${key}: written`);
    assert.equal(await isLive(db, deps, updated), false, `${key}: not live`);
    assert.deepEqual((await auditRows(db, report.id)).at(-1), { kind: "live", actor: "owner", decided: "refused" });
  }
});

test("a comment-window change on a live report pauses it, and a go-live re-approval seals the new value", async () => {
  const { db, report, deps } = await liveReport();
  const before = await row(db, report.id);
  assert.equal(Number(before.comment_window_runs), 4, "the schema's own default");
  const oldSeal = before.live_seal;
  assert.equal((await liveSetFor(db, deps, before)).commentWindowRuns, 4);

  const paused = await updateSettings(db, deps, {
    reportId: report.id, settings: { comment_window_runs: 10 }, actor: OWNER,
  });
  assert.equal(paused.status, "paused", "the window is part of the live set");
  assert.equal(paused.pause_reason, SETTINGS_CHANGED_PAUSE_REASON, "the same fixed sentence");
  assert.equal(Number(paused.comment_window_runs), 10, "written");
  assert.equal(paused.live_seal, null, "the approval no longer describes the report");
  assert.equal(paused.live_nonce, null);
  assert.equal(await isLive(db, deps, paused), false);
  assert.deepEqual((await auditRows(db, report.id)).map((r) => [r.kind, r.actor, r.decided]), [
    ["live", "owner", "approved"], ["live", "owner", "refused"],
  ]);

  // The seal the owner approved with the old window does not verify over the fields as they are now.
  const fieldsAfter = await liveSetFor(db, deps, paused);
  assert.equal(fieldsAfter.commentWindowRuns, 10, "the live set carries the new window");
  assert.equal(verifyApprovalSeal("live", fieldsAfter, oldSeal, SEED), false,
    "a seal made over another window is not this report's approval");

  // Only a fresh preview and go-live re-approve it, and the new seal CARRIES the new value: setting the
  // column back is a different report to approve again.
  const relive = await goLive(db, report);
  assert.deepEqual(relive.result, { ok: true, liveRev: report.rev });
  const live = await row(db, report.id);
  assert.equal(live.status, "live");
  assert.notEqual(live.live_seal, oldSeal, "a new approval, not the old seal");
  const sealed = await liveSetFor(db, deps, live);
  assert.equal(sealed.commentWindowRuns, 10);
  assert.equal(verifyApprovalSeal("live", sealed, live.live_seal, SEED), true);
  assert.equal(verifyApprovalSeal("live", { ...sealed, commentWindowRuns: 4 }, live.live_seal, SEED), false,
    "the seal names the window it was made over");
});

test("a direct UPDATE of comment_window_runs stops a live report without touching its status", async () => {
  const { db, report, deps } = await liveReport();
  const live = await row(db, report.id);
  assert.equal(await isLive(db, deps, live), true, "starts live");
  await db.execute({
    sql: "UPDATE reports SET comment_window_runs = ? WHERE id = ?",
    args: [10, report.id],
  });
  const moved = await row(db, report.id);
  assert.equal(moved.status, "live", "the status word is not the gate");
  assert.equal(await isLive(db, deps, moved), false, "the sealed window moved");
  assert.equal(await verifyLive(db, deps, moved), null);
});

test("verifiedCommentSettings answers the SEALED comment settings, or null", async () => {
  const { db, report, deps } = await liveReport();
  // Before a go-live the same values sit on the row, but nothing approved them.
  const draft = await prepare(db);
  assert.equal(await verifiedCommentSettings(db, depsWith(), await row(db, draft.id)), null);

  const live = await row(db, report.id);
  assert.deepEqual(await verifiedCommentSettings(db, depsWith(), live),
    { commentVisibility: "own", commentWindowRuns: 4 }, "a sealed report answers its own values");

  // The columns moved, the seal did not: nothing a reader may then rely on.
  await db.execute({
    sql: "UPDATE reports SET comment_visibility = 'all', comment_window_runs = 9 WHERE id = ?",
    args: [report.id],
  });
  assert.equal(await verifiedCommentSettings(db, depsWith(), await row(db, report.id)), null,
    "a direct UPDATE of either field is not an approval");

  // Re-approved over other values, it answers exactly what was sealed.
  const widened = await updateSettings(db, depsWith(), {
    reportId: report.id,
    settings: { comment_visibility: "all", comment_window_runs: 10 },
    actor: OWNER,
  });
  assert.equal(widened.status, "paused", "a live-set change stops the report");
  await goLive(db, report);
  assert.deepEqual(await verifiedCommentSettings(db, depsWith(), await row(db, report.id)),
    { commentVisibility: "all", commentWindowRuns: 10 });

  // A missing seed, a null row and garbage are the same answer: null, and never a throw.
  assert.equal(await verifiedCommentSettings(db, depsWith({ loadSeed: () => null }), live), null);
  assert.equal(await verifiedCommentSettings(db, depsWith(), null), null);
  assert.equal(await verifiedCommentSettings(db, depsWith(), {}), null);
  assert.equal(await verifiedCommentSettings(db, depsWith(), { id: report.id, live_rev: "1.5" }), null);
});

test("the comment window accepts only a whole number in range", async () => {
  const { db, report, deps } = await liveReport();
  for (const value of [0, 51, 2.5, "4", -1, null, true, Number.NaN]) {
    await assert.rejects(
      () => updateSettings(db, deps, {
        reportId: report.id, settings: { comment_window_runs: value }, actor: OWNER,
      }),
      (err) => { assert.equal(err.code, "bad_input", `value ${JSON.stringify(value)}`); return true; },
    );
  }
  const untouched = await row(db, report.id);
  assert.equal(untouched.status, "live", "a refused window changed nothing");
  assert.equal(Number(untouched.comment_window_runs), 4);
  assert.equal(await isLive(db, deps, untouched), true);

  // The two ends of the range are accepted, on a draft so nothing pauses.
  const { db: draftDb } = await freshDb();
  const draft = await prepare(draftDb);
  for (const value of [1, 50]) {
    const updated = await updateSettings(draftDb, depsWith(), {
      reportId: draft.id, settings: { comment_window_runs: value }, actor: OWNER,
    });
    assert.equal(Number(updated.comment_window_runs), value, `value ${value} is written`);
  }
});

test("a live report keeps running through a settings change that is not in the live set", async () => {
  const { db, report, deps } = await liveReport();
  const updated = await updateSettings(db, deps, {
    reportId: report.id, settings: { title: "Weekly listings, renamed", notify_every_run: true }, actor: OWNER,
  });
  assert.equal(updated.status, "live");
  assert.equal(updated.pause_reason, null);
  assert.equal(updated.title, "Weekly listings, renamed");
  assert.equal(Number(updated.notify_every_run), 1);
  assert.equal(await isLive(db, deps, updated), true);
});

test("a settings change that sets the same value on a live report does not pause it", async () => {
  const { db, report, deps } = await liveReport();
  const updated = await updateSettings(db, deps, {
    reportId: report.id, settings: { delivery_mode: "email_link", ai_commentary: false }, actor: OWNER,
  });
  assert.equal(updated.status, "live");
  assert.equal(Number(updated.ai_commentary), 0);
});

test("a live-set settings change drops the seal, so putting the value back cannot revive it", async () => {
  const { db, report, deps } = await liveReport();
  const before = await row(db, report.id);
  assert.match(before.live_seal, /^[0-9a-f]{64}$/);

  const paused = await updateSettings(db, deps, {
    reportId: report.id, settings: { delivery_mode: "both" }, actor: OWNER,
  });
  assert.equal(paused.status, "paused");
  assert.equal(paused.live_seal, null, "the old approval is gone with the pause");
  assert.equal(paused.live_nonce, null);

  // Setting the column back is not an approval: the report stays paused, and a resume needs a go-live.
  await db.execute({ sql: "UPDATE reports SET delivery_mode = 'email_link' WHERE id = ?", args: [report.id] });
  assert.equal(await isLive(db, deps, await row(db, report.id)), false);
  await assert.rejects(
    () => resumeReport(db, deps, { reportId: report.id, actor: OWNER }),
    (err) => { assert.equal(err.code, "go_live_needed"); return true; },
  );
  const after1 = await row(db, report.id);
  assert.equal(after1.status, "paused");
  assert.equal(after1.live_seal, null, "nothing revived the seal");
  assert.equal(await verifyLive(db, deps, after1), null);
});

test("a live-set change while paused drops the seal, so a resume needs a go-live", async () => {
  const { db, report, deps } = await liveReport();
  const pausedRow = await pauseReport(db, deps, {
    reportId: report.id, reason: "Paused before the change", actor: OWNER,
  });
  assert.match(pausedRow.live_seal, /^[0-9a-f]{64}$/, "a pause keeps the seal");

  const changed = await updateSettings(db, deps, {
    reportId: report.id, settings: { sender_account_id: "ma-8899aabbccddeeff" }, actor: OWNER,
  });
  assert.equal(changed.status, "paused", "still paused");
  assert.equal(changed.pause_reason, "Paused before the change", "the owner's reason is left alone");
  assert.equal(changed.sender_account_id, "ma-8899aabbccddeeff");
  assert.equal(changed.live_seal, null, "the approval no longer describes the report");
  assert.equal(changed.live_nonce, null);

  // Putting the value back is not an approval: the report stays paused and a resume refuses.
  const back = await updateSettings(db, deps, {
    reportId: report.id, settings: { sender_account_id: SENDER }, actor: OWNER,
  });
  assert.equal(back.status, "paused");
  assert.equal(back.live_seal, null);
  await assert.rejects(
    () => resumeReport(db, deps, { reportId: report.id, actor: OWNER }),
    (err) => { assert.equal(err.code, "go_live_needed"); return true; },
  );
  const after1 = await row(db, report.id);
  assert.equal(after1.status, "paused");
  assert.equal(after1.pause_reason, "Paused before the change");
  assert.equal(after1.live_seal, null);
  assert.deepEqual((await auditRows(db, report.id)).map((r) => [r.actor, r.decided]), [
    ["owner", "approved"], ["owner", "refused"],
  ], "no new decision was recorded");

  // A paused report's seal survives a setting that is not in the live set, and the resume works.
  const second = await liveReport();
  await pauseReport(second.db, second.deps, { reportId: second.report.id, actor: OWNER });
  const sealBefore = (await row(second.db, second.report.id)).live_seal;
  const renamed = await updateSettings(second.db, second.deps, {
    reportId: second.report.id, settings: { title: "Weekly listings, renamed" }, actor: OWNER,
  });
  assert.equal(renamed.status, "paused");
  assert.equal(renamed.live_seal, sealBefore, "a setting outside the live set keeps the seal");
  const resumed = await resumeReport(second.db, second.deps, {
    reportId: second.report.id, actor: OWNER,
  });
  assert.equal(resumed.status, "live");
});

test("a draft takes a settings change without a pause and without an audit row", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  const deps = depsWith();
  const updated = await updateSettings(db, deps, {
    reportId: report.id, settings: { delivery_mode: "both", comment_tier_default: "b", ai_commentary: true }, actor: OWNER,
  });
  assert.equal(updated.status, "draft");
  assert.equal(updated.pause_reason, null);
  assert.equal(updated.delivery_mode, "both");
  assert.equal(updated.comment_tier_default, "b");
  assert.equal(Number(updated.ai_commentary), 1);
  assert.deepEqual(await auditRows(db, report.id), []);
});

test("settings refuse an unknown key, a bad enum, a bad flag and a sender that is not ready", async () => {
  const { db, report } = await liveReport();
  const bad = [
    { live_seal: "x" },
    { recipe: {} },
    { delivery_mode: "carrier_pigeon" },
    { comment_tier_default: "d" },
    { comment_visibility: "some" },
    { ai_commentary: "yes" },
    { notify_every_run: 2 },
    { title: "" },
    { title: "x".repeat(500) },
  ];
  for (const settings of bad) {
    await assert.rejects(
      () => updateSettings(db, depsWith(), { reportId: report.id, settings, actor: OWNER }),
      (err) => { assert.equal(err.code, "bad_input", JSON.stringify(settings)); return true; },
    );
  }
  await assert.rejects(
    () => updateSettings(db, depsWith({ senderReady: async () => false }), {
      reportId: report.id, settings: { sender_account_id: "ma-8899aabbccddeeff" }, actor: OWNER,
    }),
    (err) => { assert.equal(err.code, "sender_not_ready"); return true; },
  );
  await assert.rejects(
    () => updateSettings(db, depsWith(), { reportId: report.id, settings: {}, actor: OWNER }),
    (err) => { assert.equal(err.code, "bad_input"); return true; },
  );
  const untouched = await row(db, report.id);
  assert.equal(untouched.status, "live", "a refused settings write changed nothing");
  assert.equal(untouched.delivery_mode, "email_link");
  assert.equal(untouched.title, "Weekly listings");
});

test("settings need the owner", async () => {
  const { db, report } = await liveReport();
  await assert.rejects(
    () => updateSettings(db, depsWith(), { reportId: report.id, settings: { title: "Mine" }, actor: BOT_ACTOR }),
    (err) => { assert.equal(err.code, "owner_only"); return true; },
  );
  assert.equal((await row(db, report.id)).title, "Weekly listings");
});

/* -------------------------------------------------------------------- defaults */

test("the default schedule reader answers the report's own schedules row, or null", async () => {
  const { db, report } = await liveReport();
  const live = await row(db, report.id);
  const fields = await liveSetFor(db, depsWith(), live);
  assert.equal(fields.cron, "0 7 * * 1");
  assert.equal(fields.tz, "Europe/Berlin");

  await db.execute({ sql: "DELETE FROM schedules WHERE id = ?", args: [report.scheduleId] });
  assert.equal((await liveSetFor(db, depsWith(), live)).cron, "");
});

test("a disabled schedule row is no schedule, so the report is not live", async () => {
  const { db, report, deps } = await liveReport();
  const live = await row(db, report.id);
  assert.equal(await isLive(db, deps, live), true, "starts live");
  await db.execute({ sql: "UPDATE schedules SET enabled = 0 WHERE id = ?", args: [report.scheduleId] });
  assert.equal((await liveSetFor(db, depsWith(), live)).cron, "", "a switched-off row resolves to nothing");
  assert.equal(await isLive(db, deps, await row(db, report.id)), false);
});

test("the injected sender reader wants an active account with its credential on this machine", async () => {
  const { db } = await freshDb();
  const endpoint = { host: "mail.example.test", port: 993, security: "ssl" };
  const account = await createAccount(db, {
    label: "Personal", address: "alex@example.com", username: "alex", authKind: "password",
    imap: endpoint, smtp: { ...endpoint, port: 465 },
  });
  const credentials = createMailCredentials({ db, crowHome: process.env.CROW_HOME });
  await credentials.saveSecret(account.id, "MAIL_PASSWORD", "app-password-value");

  const report = await prepare(db);
  await updateSettings(db, { loadSeed: () => ({ seed: SEED }), senderReady }, {
    reportId: report.id, settings: { sender_account_id: account.id }, actor: OWNER,
  });
  const runs = { "prv-1": { id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev } };
  // The sender half of go-live reads the real Crow Mail state here: reports/sender-ready.js is the reader
  // the routes inject, and this module's own default is a fail-closed false.
  await approveGoLive(db, { loadSeed: () => ({ seed: SEED }), getRun: runReader(runs), senderReady, registry: REGISTRY }, {
    reportId: report.id, previewRunId: "prv-1", actor: OWNER,
  });
  assert.equal((await row(db, report.id)).status, "live");

  // The same account after a refused sign-in, and an account id that is nobody's: both refuse go-live.
  await updateAccount(db, account.id, { status: "auth_failed" });
  for (const sender of [account.id, "ma-8899aabbccddeeff"]) {
    const second = await prepare(db);
    await updateReportColumns(db, second.id, { sender_account_id: sender });
    const secondRuns = { "prv-2": { id: "prv-2", reportId: second.id, kind: "preview", status: "ok", recipeRev: second.rev } };
    await assert.rejects(
      () => approveGoLive(db, { loadSeed: () => ({ seed: SEED }), getRun: runReader(secondRuns), senderReady, registry: REGISTRY }, {
        reportId: second.id, previewRunId: "prv-2", actor: OWNER,
      }),
      (err) => { assert.equal(err.code, "sender_not_ready", sender); return true; },
    );
    assert.equal((await row(db, second.id)).status, "draft");
  }
});

test("with no sender reader injected, go live fails closed", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  const runs = { "prv-1": { id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev } };
  await assert.rejects(
    () => approveGoLive(db, { loadSeed: () => ({ seed: SEED }), getRun: runReader(runs) }, {
      reportId: report.id, previewRunId: "prv-1", actor: OWNER,
    }),
    (err) => { assert.equal(err.code, "sender_not_ready"); return true; },
  );
  assert.equal((await row(db, report.id)).status, "draft");
  assert.equal((await row(db, report.id)).live_seal, null);
});

/* ------------------------------------------------------- the sender seal at go live */

test("go-live is refused when the sender was never sealed", async () => {
  const { db } = await freshDb();
  const report = await prepare(db, { sealSender: false });
  assert.equal(await getState(db, report.id, "sender_seal"), null, "the row names an account, nothing proves it");
  await assert.rejects(
    () => goLive(db, report),
    (err) => { assert.equal(err.code, "sender_not_ready"); return true; },
  );
  const after1 = await row(db, report.id);
  assert.equal(after1.status, "draft", "the status is unchanged");
  assert.equal(after1.live_seal, null, "nothing was sealed");
  assert.equal(await getState(db, report.id, "sender_seal"), null);
});

test("go-live is refused when the sender column was tampered after the seal", async () => {
  const { db } = await freshDb();
  const report = await prepare(db);
  assert.equal((await getState(db, report.id, "sender_seal")).accountId, SENDER);
  await db.execute({
    sql: "UPDATE reports SET sender_account_id = ? WHERE id = ?",
    args: ["ma-8899aabbccddeeff", report.id],
  });
  await assert.rejects(
    () => goLive(db, report),
    (err) => { assert.equal(err.code, "sender_not_ready"); return true; },
  );
  const after1 = await row(db, report.id);
  assert.equal(after1.status, "draft", "the status is unchanged");
  assert.equal(after1.live_seal, null, "the seal names the account the owner chose, not this one");
});

test("go-live is allowed after an owner settings save sealed the sender", async () => {
  const { db } = await freshDb();
  const report = await prepare(db, { sealSender: false });
  const sealed = await updateSettings(db, depsWith(), {
    reportId: report.id, settings: { sender_account_id: SENDER }, actor: OWNER,
  });
  assert.equal(sealed.sender_account_id, SENDER);
  assert.equal((await getState(db, report.id, "sender_seal")).accountId, SENDER);

  const { result } = await goLive(db, report);
  assert.equal(result.ok, true);
  const after1 = await row(db, report.id);
  assert.equal(after1.status, "live");
  assert.match(after1.live_seal, /^[0-9a-f]{64}$/);
  assert.equal(await isLive(db, depsWith(), after1), true);
});

test("a bot path cannot satisfy the sender seal", async () => {
  const { db } = await freshDb();
  const report = await prepare(db, { sealSender: false });
  const saved = await botSaveRecipe(db, depsWith(), { reportId: report.id, recipe: FREE_EDIT_RECIPE });
  const proposed = await proposeRecipient(db, depsWith(), {
    reportId: report.id, address: "alex@example.com", proposedBy: "bot:bot-1",
  });
  assert.equal(proposed.state, "proposed");
  assert.equal(await getState(db, report.id, "sender_seal"), null, "no bot path writes the seal");

  await assert.rejects(
    () => goLive(db, report, { run: { recipeRev: saved.rev } }),
    (err) => { assert.equal(err.code, "sender_not_ready"); return true; },
  );
  assert.equal((await row(db, report.id)).status, "draft");
  assert.equal(await getState(db, report.id, "sender_seal"), null, "and the refusal wrote none");
});

test("the default model reader resolves the bot's own key through the provider row", async () => {
  const { db } = await freshDb();
  await db.execute({
    sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition) VALUES ('bot-1', 'Reporter', ?)",
    args: [JSON.stringify({ models: { default: "crow-chat/m1" } })],
  });
  await db.execute({
    sql: `INSERT INTO providers (id, base_url, api_key, models, disabled, host)
          VALUES ('crow-chat', 'http://127.0.0.1:9100/v1', 'none', ?, 0, 'local')`,
    args: [JSON.stringify([{ id: "m1" }])],
  });
  const report = await prepare(db, { ai: 1 });
  const deps = { loadSeed: () => ({ seed: SEED }), senderReady: async () => true, registry: REGISTRY };
  const runs = { "prv-1": { id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev } };
  await approveGoLive(db, { ...deps, getRun: runReader(runs) }, {
    reportId: report.id, previewRunId: "prv-1", actor: OWNER,
  });
  const live = await row(db, report.id);
  const sealedModel = JSON.parse(live.model_ref);
  assert.deepEqual(sealedModel, {
    providerId: "crow-chat", model: "m1", locality: "local", baseUrlHost: "127.0.0.1:9100",
  });
  assert.equal(await isLive(db, deps, live), true);

  // The same provider id, repointed at another endpoint: the seal covers the host, so the report stops.
  await db.execute({
    sql: "UPDATE providers SET base_url = 'https://api.example-cloud.test/v1' WHERE id = 'crow-chat'",
    args: [],
  });
  assert.equal(await isLive(db, deps, await row(db, report.id)), false);

  // The bot names another model: also a different seal.
  await db.execute({
    sql: "UPDATE providers SET base_url = 'http://127.0.0.1:9100/v1' WHERE id = 'crow-chat'",
    args: [],
  });
  await db.execute({
    sql: "UPDATE pi_bot_defs SET definition = ? WHERE bot_id = 'bot-1'",
    args: [JSON.stringify({ models: { default: "crow-chat/m2" } })],
  });
  assert.equal(await isLive(db, deps, await row(db, report.id)), false);
});

/* --------------------------------------------- the model an AI block's role names */

test("go live seals the RESOLVED reference of the role a recipe names", async () => {
  const { db } = await freshDb();
  const roleId = await bindRole(db);
  const report = await prepare(db, { recipe: roleRecipe(roleId) });
  const runs = { "prv-1": { id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev } };
  const deps = { loadSeed: () => ({ seed: SEED }), senderReady: async () => true, registry: REGISTRY, getRun: runReader(runs) };
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor: OWNER });

  const live = await row(db, report.id);
  assert.equal(live.status, "live");
  assert.deepEqual(JSON.parse(live.model_ref), {
    providerId: "local-chat", model: "m1", locality: "local", baseUrlHost: "127.0.0.1:8013",
  }, "the role's own resolved reference, not the bot's model");
  assert.equal(await isLive(db, deps, live), true);

  // The seal covers exactly that reference.
  const verified = await verifyLive(db, deps, live);
  assert.equal(verified.liveSet.modelRef, live.model_ref);
});

test("a role rebound to another model breaks the seal, like a bot's model switch", async () => {
  const { db } = await freshDb();
  const roleId = await bindRole(db);
  const report = await prepare(db, { recipe: roleRecipe(roleId) });
  const runs = { "prv-1": { id: "prv-1", reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev } };
  const deps = { loadSeed: () => ({ seed: SEED }), senderReady: async () => true, registry: REGISTRY, getRun: runReader(runs) };
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: "prv-1", actor: OWNER });
  assert.equal(await isLive(db, deps, await row(db, report.id)), true);

  // The owner rebinds the role: a different model is a different live set.
  assert.equal((await setBinding(db, roleId, { model: "local-chat/m2" }, {})).ok, true);
  const moved = await row(db, report.id);
  assert.equal(await isLive(db, deps, moved), false);
  assert.equal(await verifyLive(db, deps, moved), null);
  assert.equal(moved.status, "live", "the row is not written here; the guard is what pauses it");

  // Putting the SAME model back approves nothing again on its own: the seal was never re-made, and it
  // verifies only because every field it covers is the one the owner approved.
  assert.equal((await setBinding(db, roleId, { model: "local-chat/m1" }, {})).ok, true);
  assert.equal(await isLive(db, deps, await row(db, report.id)), true);
});

test("an unresolved role and a role that is not local are both model_unresolved at go live", async () => {
  const { db } = await freshDb();
  const roleId = await bindRole(db);
  const runs = {};
  const deps = { loadSeed: () => ({ seed: SEED }), senderReady: async () => true, registry: REGISTRY, getRun: runReader(runs) };

  // No model bound: nothing resolves, so there is no reference to seal.
  const unbound = await prepare(db, { recipe: roleRecipe(roleId) });
  assert.equal((await setBinding(db, roleId, { model: null }, {})).ok, true);
  runs["prv-1"] = { id: "prv-1", reportId: unbound.id, kind: "preview", status: "ok", recipeRev: unbound.rev };
  await assert.rejects(
    () => approveGoLive(db, deps, { reportId: unbound.id, previewRunId: "prv-1", actor: OWNER }),
    (err) => err.code === "model_unresolved",
  );
  assert.equal((await row(db, unbound.id)).status, "draft");
  assert.equal((await row(db, unbound.id)).live_seal, null);

  // A cloud provider behind the role: the report's items may not go there, so no live set either.
  await db.execute({
    sql: "INSERT OR REPLACE INTO providers (id, base_url, host, models, disabled) VALUES (?, ?, 'cloud', ?, 0)",
    args: ["cloud-chat", "https://api.example.com/v1", JSON.stringify([{ id: "m1" }])],
  });
  assert.equal((await setBinding(db, roleId, { model: "cloud-chat/m1" }, {})).ok, true);
  const cloud = await prepare(db, { recipe: roleRecipe(roleId) });
  runs["prv-2"] = { id: "prv-2", reportId: cloud.id, kind: "preview", status: "ok", recipeRev: cloud.rev };
  await assert.rejects(
    () => approveGoLive(db, deps, { reportId: cloud.id, previewRunId: "prv-2", actor: OWNER }),
    (err) => err.code === "model_unresolved",
  );
  assert.equal((await row(db, cloud.id)).status, "draft");
});

test("a role that is not a chat model and a role behind a lazy loader are both model_unresolved", async () => {
  const { db } = await freshDb();
  const runs = {};
  const deps = { loadSeed: () => ({ seed: SEED }), senderReady: async () => true, registry: REGISTRY, getRun: runReader(runs) };

  // An embedding endpoint, bound to the core embed role: a report's block writes, so it may not go live.
  await db.execute({
    sql: "INSERT OR REPLACE INTO providers (id, base_url, host, models, disabled) VALUES (?, ?, 'local', ?, 0)",
    args: ["embed-chat", "http://127.0.0.1:8015/v1", JSON.stringify([{ id: "e1", task: "embed" }])],
  });
  assert.equal((await setBinding(db, "embed", { model: "embed-chat/e1" }, {})).ok, true);
  const embedded = await prepare(db, { recipe: roleRecipe("embed") });
  runs["prv-1"] = { id: "prv-1", reportId: embedded.id, kind: "preview", status: "ok", recipeRev: embedded.rev };
  await assert.rejects(
    () => approveGoLive(db, deps, { reportId: embedded.id, previewRunId: "prv-1", actor: OWNER }),
    (err) => err.code === "model_unresolved",
  );
  assert.equal((await row(db, embedded.id)).status, "draft");

  // A provider that loads its model on the first request: the completion refuses it, so go-live does too.
  await db.execute({
    sql: `INSERT OR REPLACE INTO providers (id, base_url, host, models, disabled, provider_type)
          VALUES (?, ?, 'local', ?, 0, 'ollama')`,
    args: ["ollama-chat", "http://127.0.0.1:11434/v1", JSON.stringify([{ id: "m1" }])],
  });
  const roleId = await bindRole(db);
  assert.equal((await setBinding(db, roleId, { model: "ollama-chat/m1" }, {})).ok, true);
  const lazy = await prepare(db, { recipe: roleRecipe(roleId) });
  runs["prv-2"] = { id: "prv-2", reportId: lazy.id, kind: "preview", status: "ok", recipeRev: lazy.rev };
  await assert.rejects(
    () => approveGoLive(db, deps, { reportId: lazy.id, previewRunId: "prv-2", actor: OWNER }),
    (err) => err.code === "model_unresolved",
  );
  assert.equal((await row(db, lazy.id)).status, "draft");
});

test("a recipe mixing a role-naming model block with one that names none is refused at save", async () => {
  const { db } = await freshDb();
  const roleId = await bindRole(db);
  const report = await prepare(db);
  const mixed = {
    blocks: [
      { id: "ai1", type: "ai_commentary", settings: { modelRole: `role:${roleId}` } },
      { id: "an1", type: "annotate", settings: {} },
    ],
  };
  await assert.rejects(
    () => saveRecipe(db, { reportId: report.id, recipe: mixed, authorKind: "owner", registry: REGISTRY }),
    (err) => err.code === "bad_recipe" && err.detail === "blocks[1].modelRole",
  );
});

test("a recipe naming two different roles is refused, and the AI block's own validate refuses a bad one", async () => {
  const { db } = await freshDb();
  const roleId = await bindRole(db);
  const recipe = {
    blocks: [
      { id: "ai1", type: "ai_commentary", settings: { modelRole: `role:${roleId}` } },
      { id: "an1", type: "annotate", settings: { modelRole: "role:everyday" } },
    ],
  };
  await assert.rejects(
    () => saveRecipe(db, { reportId: "rpt-0123456789abcdef", recipe, authorKind: "owner", registry: REGISTRY }),
    () => true,
  );
  const report = await prepare(db);
  await assert.rejects(
    () => saveRecipe(db, { reportId: report.id, recipe, authorKind: "owner", registry: REGISTRY }),
    (err) => err.code === "bad_recipe" && err.detail === "blocks[1].modelRole",
  );
  const malformed = {
    blocks: [{ id: "ai1", type: "ai_commentary", settings: { modelRole: "finance" } }],
  };
  await assert.rejects(
    () => saveRecipe(db, { reportId: report.id, recipe: malformed, authorKind: "owner", registry: REGISTRY }),
    (err) => err.code === "bad_recipe" && err.detail === "blocks[0].modelRole",
  );
});