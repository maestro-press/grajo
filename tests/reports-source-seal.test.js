// Sealed source approvals: the owner's OK for one draft source's exact settings, and the rule that a
// bot's preview reads only sources in the report's verified live set (or ones the owner approved).
//
// Harness: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR and CROW_HOME under a temp
// dir, so nothing reaches a real Crow), real report, revision, schedule, host and mail account rows, the
// keychain seed and clock injected through the approvals deps, and stubbed `testFetch` and `mail` seams
// (a preview or a run here never opens a socket or a mailbox). The fetch fake is a `testSeams` seam:
// the executor binds the guarded request itself, so a plain `deps.fetch` is not read.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-source-seal-"));
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
  applyPendingFreeChange, approveGoLive, botSaveRecipe, isLive, ownerAuthorSealerFor, ownerSaveRecipe,
  updateSettings, verifyLive,
} = await import("../servers/gateway/reports/approvals.js");
const { SEAL_FIELDS } = await import("../servers/gateway/reports/seal.js");
const {
  SOURCE_APPROVAL_PREFIX, approveSource, isSourceApprovedForBot, listDraftSources, revokeSource,
  settingsHashOf, verifySourceApproval, waitingForOkText,
} = await import("../servers/gateway/reports/source-approvals.js");
const { blockRegistry } = await import("../servers/gateway/reports/blocks/index.js");
const { makeStateAccess } = await import("../servers/gateway/reports/blocks/run-recipe.js");
const { sourcesHash } = await import("../servers/gateway/reports/recipe-hash.js");
const { approveHost, approveStep, proposeHost, proposeStep } = await import("../servers/gateway/reports/steps.js");
const { executeRun, getRun, startRun } = await import("../servers/gateway/reports/run.js");
const {
  createReport, getReport, getState, saveRecipe, setState, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { createAccount } = await import("../servers/gateway/mail/store/accounts.js");

const OWNER = Object.freeze({ kind: "owner" });
const BOT_ACTOR = Object.freeze({ kind: "bot" });
const SEED = Buffer.alloc(32, 41);
/**
 * The sealer an owner save in this harness writes: the real one over the harness seed, so an owner
 * revision carries the author seal the source gate's owner-history path reads.
 */
const sealAuthor = ownerAuthorSealerFor({ loadSeed: () => ({ seed: SEED }) });
const PROJECT = 7;
const T0 = 1_700_000_000_000;
const PREVIEW = "prv-1";
const HOST = "api.example.com";
const SENDER = "ma-0011223344556677";
const FEED_URL = "https://api.example.com/items?page=1";
const BOT = "bot:bot-1";

/** One http_json source, and the filter the free-change tests edit. */
const FEED_BLOCK = Object.freeze({ id: "feed", type: "http_json", settings: { url: FEED_URL } });
const FILTER_BLOCK = Object.freeze({
  id: "keep", type: "filter", settings: { field: "title", op: "contains", value: "one" },
});
const FEED_ITEMS = Object.freeze([{ title: "one" }, { title: "two" }]);

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

/** The approvals deps: the seal seed, the clock, the block registry, the sender and the preview run. */
function approvalDeps(report, over = {}) {
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    senderReady: async () => true,
    registry: blockRegistry,
    getRun: async (_db, runId) => (runId === PREVIEW
      ? { id: PREVIEW, reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev }
      : null),
    ...over,
  };
}

/** The run engine's deps: the approvals seam, a delivery stub and whatever a block needs. */
function runDeps(approvals, over = {}) {
  return {
    approvals,
    deliver: async () => {},
    now: () => T0,
    getSecrets: () => [],
    ...over,
  };
}

/** A guarded-request seam that records every URL and answers one JSON array. */
function fetchStub(urls, items = FEED_ITEMS) {
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

/**
 * The executor's fetch seam for a harness: `testFetch` is read only under `testSeams`, and a plain
 * `fetch` in the deps is no seam at all (run-recipe.js binds the guarded request itself).
 */
function fakeFetch(urls, items = FEED_ITEMS) {
  return { testSeams: true, testFetch: fetchStub(urls, items) };
}

/** A mail seam that records the folder every read names and answers no messages. */
function mailStub(folders) {
  return async (_account, fn) => fn({
    listFolders: async () => [
      { path: "INBOX/Alerts", name: "Alerts" },
      { path: "INBOX/Other", name: "Other" },
    ],
    list: async (folder) => {
      folders.push(folder);
      return { items: [] };
    },
    get: async () => [],
  });
}

async function addSchedule(db) {
  await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, tz) VALUES ('weekly-report', '0 7 * * 1', 'Europe/Berlin')",
    args: [],
  });
  const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
  return Number(rows[0].id);
}

/** One mail account, so a mail_alerts block has a real account row to read. */
async function addMailAccount(db, address = "alex@example.com") {
  const endpoint = { host: "mail.example.test", port: 993, security: "ssl" };
  const account = await createAccount(db, {
    label: "Personal",
    address,
    username: address.split("@")[0],
    authKind: "password",
    imap: endpoint,
    smtp: { ...endpoint, port: 465 },
  });
  return account.id;
}

/** One saved report with a schedule, a sender and the live-set settings a go-live needs. */
async function prepare(db, { recipe, sender = SENDER, authorKind = "owner" } = {}) {
  const scheduleId = await addSchedule(db);
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: "owner", botId: "bot-1", title: "Weekly listings",
  });
  const saved = await saveRecipe(db, {
    reportId: id,
    recipe,
    authorKind,
    registry: blockRegistry,
    // An owner save seals its revision, the way the owner's own route does; a bot save never does.
    authorSeal: authorKind === "owner" ? sealAuthor : undefined,
  });
  await updateReportColumns(db, id, {
    schedule_id: scheduleId,
    sender_account_id: sender,
    delivery_mode: "email_link",
    comment_tier_default: "c",
    comment_visibility: "own",
    ai_commentary: 0,
  });
  await updateSettings(db, approvalDeps({ id }), {
    reportId: id, settings: { sender_account_id: sender }, actor: OWNER,
  });
  return { id, rev: saved.rev, sourcesHash: saved.sourcesHash };
}

/** Approve one host for one report, through the reports steps module's own rail. */
async function approveHostFor(db, reportId, host = HOST) {
  const deps = { loadSeed: () => ({ seed: SEED }), now: () => T0, crowHome: HOME };
  await proposeHost(db, deps, { reportId, host });
  await approveHost(db, deps, { reportId, host, actor: OWNER });
}

/** A live report: a draft whose reported revision was previewed and sealed. */
async function liveReport(db, options = {}) {
  const report = await prepare(db, options);
  const deps = approvalDeps(report);
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: PREVIEW, actor: OWNER });
  return { report, deps };
}

/** One approved custom step of one report, through the steps module's own rail. */
async function approveStepFor(db, reportId) {
  const deps = { loadSeed: () => ({ seed: SEED }), now: () => T0, crowHome: HOME };
  const step = await proposeStep(db, deps, {
    reportId,
    stepKey: "fetch",
    language: "python",
    entry: "run.py",
    files: { "run.py": "print('{}')\n" },
    requirements: "",
    proposedBy: "owner",
  });
  await approveStep(db, deps, {
    reportId, stepKey: "fetch", rev: step.rev, bundleHash: step.bundleHash, actor: OWNER,
  });
}

/** The step seam a custom block needs: an env that is already built and a runner that answers items. */
function stepSeam(over = {}) {
  return {
    ensureEnv: async () => ({
      ok: true, dir: join(HOME, "reports", "env", "python"), hash: "c".repeat(64),
      cacheDir: join(HOME, "cache"), built: false,
    }),
    runStep: async () => ({ ok: true, output: { items: [{ id: "a" }] } }),
    ...over,
  };
}

async function queueRun(db, reportId, { trigger = "manual", requestedBy = "owner", scheduledFor = null } = {}) {
  const { runId } = await startRun(db, { now: () => T0 }, {
    reportId, trigger, requestedBy, scheduledFor,
  });
  return runId;
}

/** Ask for a preview as a bot and execute it, answering the run's status and its source errors. */
async function botPreview(db, reportId, deps, over = {}) {
  const runId = await queueRun(db, reportId, { trigger: "preview", requestedBy: BOT });
  const out = await executeRun(db, runDeps(deps, over), runId);
  const row = await getRun(db, runId);
  return { runId, out, sourceErrors: row.blockLog ? row.blockLog.sourceErrors : [] };
}

function waiting(blockId) {
  return { source: blockId, message: waitingForOkText(blockId) };
}

/* ------------------------------------------------------- a live report's sealed revision */

test("bot changes mail_alerts label on a live report and the scheduled run uses the last sealed revision", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const sealed = { blocks: [{ id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 } }] };
  const { report, deps } = await liveReport(db, { recipe: sealed, sender: accountId });
  const before = await getReport(db, report.id);

  const saved = await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [{ id: "mail", type: "mail_alerts", settings: { accountId, label: "Other", sinceDays: 7 } }] },
  });
  assert.equal(saved.pendingFreeChange, false);
  assert.equal(saved.needsGoLive, true);
  assert.notEqual(saved.sourcesHash, before.sources_hash, "a mail label is part of what the owner sealed");
  assert.equal(Number((await getReport(db, report.id)).live_rev), before.live_rev, "the seal did not move");

  const folders = [];
  const runId = await queueRun(db, report.id, {
    trigger: "schedule", requestedBy: "schedule", scheduledFor: T0,
  });
  const out = await executeRun(db, runDeps(deps, { mail: mailStub(folders) }), runId);
  assert.deepEqual(out, { status: "empty", artifactVersion: null });
  assert.deepEqual(folders, ["INBOX/Alerts"], "the sealed label, not the one the bot saved");
});

test("bot changes http_json url query on a live report and the manual run uses the last sealed revision", async () => {
  const db = await freshDb();
  const { report, deps } = await liveReport(db, { recipe: { blocks: [FEED_BLOCK] } });
  await approveHostFor(db, report.id);

  const saved = await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [{ ...FEED_BLOCK, settings: { url: "https://api.example.com/items?page=2" } }] },
  });
  assert.equal(saved.pendingFreeChange, false);
  assert.equal(saved.needsGoLive, true);

  const urls = [];
  const runId = await queueRun(db, report.id, { trigger: "manual", requestedBy: "owner" });
  const out = await executeRun(db, runDeps(deps, fakeFetch(urls)), runId);
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  assert.deepEqual(urls, [FEED_URL], "the sealed query, not the one the bot saved");
});

/* --------------------------------------------------------------- a bot's preview gate */

test("bot preview of a mail_alerts block on an unapproved account is refused, and the mail seam is never called", async () => {
  const db = await freshDb();
  const sealedAccount = await addMailAccount(db);
  const otherAccount = await addMailAccount(db, "sam@example.com");
  const { report, deps } = await liveReport(db, {
    recipe: { blocks: [{ id: "mail", type: "mail_alerts", settings: { accountId: sealedAccount, label: "Alerts", sinceDays: 7 } }] },
    sender: sealedAccount,
  });

  const head = { id: "mail", type: "mail_alerts", settings: { accountId: otherAccount, label: "Alerts", sinceDays: 7 } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [head] } });
  // The owner approves the block's settings, so the account rule is the only thing left refusing it.
  await approveSource(db, deps, {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(head), actor: OWNER,
  });
  const verdict = await isSourceApprovedForBot(db, deps, await getReport(db, report.id), head);
  assert.deepEqual(verdict, { ok: false, text: waitingForOkText("mail") });

  const folders = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, { mail: mailStub(folders) });
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual(sourceErrors, [waiting("mail")]);
  assert.deepEqual(folders, [], "no mailbox was read");
});

test("bot preview of an approved source runs", async () => {
  const db = await freshDb();
  const { report, deps } = await liveReport(db, { recipe: { blocks: [FEED_BLOCK] } });
  await approveHostFor(db, report.id);

  const verdict = await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK);
  assert.deepEqual(verdict, { ok: true }, "the block's own settings are in the sealed revision");

  const urls = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, fakeFetch(urls));
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  assert.deepEqual(sourceErrors, []);
  assert.deepEqual(urls, [FEED_URL]);
});

test("an owner's preview of a draft source runs with no approval, because the owner is the approver", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  await approveHostFor(db, report.id);
  const urls = [];
  const runId = await queueRun(db, report.id, { trigger: "preview", requestedBy: "owner" });
  const out = await executeRun(db, runDeps(approvalDeps(report), fakeFetch(urls)), runId);
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  assert.deepEqual(urls, [FEED_URL]);
});

test("a bot preview of a draft source waits for approveSource, runs after it, and stops after the settings change", async () => {
  const db = await freshDb();
  // The bot introduced this block: its first appearance is not the owner's, so its content is gated.
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] }, authorKind: "bot" });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);

  // 1. Draft, never approved: the block waits for the owner and no request is made.
  const firstUrls = [];
  const first = await botPreview(db, report.id, deps, fakeFetch(firstUrls));
  assert.deepEqual(first.out, { status: "failed", artifactVersion: null });
  assert.deepEqual(first.sourceErrors, [waiting("feed")]);
  assert.deepEqual(firstUrls, [], "no request was made");

  // 2. The owner approves these exact settings: the same preview now runs the source.
  await approveSource(db, deps, {
    reportId: report.id, blockId: "feed", expectedSettingsHash: settingsHashOf(FEED_BLOCK), actor: OWNER,
  });
  assert.equal(await verifySourceApproval(db, deps, report.id, FEED_BLOCK), true);
  const secondUrls = [];
  const second = await botPreview(db, report.id, deps, fakeFetch(secondUrls));
  assert.deepEqual(second.out, { status: "ok", artifactVersion: null });
  assert.deepEqual(second.sourceErrors, []);
  assert.deepEqual(secondUrls, [FEED_URL]);

  // 3. The bot changes the URL query: the approval named the old settings, so nothing runs.
  await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [{ ...FEED_BLOCK, settings: { url: "https://api.example.com/items?page=2" } }] },
  });
  const changed = { ...FEED_BLOCK, settings: { url: "https://api.example.com/items?page=2" } };
  assert.equal(await verifySourceApproval(db, deps, report.id, changed), false,
    "the approval named the old settings");
  const thirdUrls = [];
  const third = await botPreview(db, report.id, deps, fakeFetch(thirdUrls));
  assert.deepEqual(third.out, { status: "failed", artifactVersion: null });
  assert.deepEqual(third.sourceErrors, [waiting("feed")]);
  assert.deepEqual(thirdUrls, []);
});

test("a settings change after approval does not run", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const block = { id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 } };
  const report = await prepare(db, { recipe: { blocks: [block] }, sender: accountId });
  const deps = approvalDeps(report);
  await approveSource(db, deps, {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(block), actor: OWNER,
  });
  assert.equal(await verifySourceApproval(db, deps, report.id, block), true);

  const edited = { ...block, settings: { ...block.settings, sinceDays: 30 } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [edited] } });
  assert.equal(await verifySourceApproval(db, deps, report.id, edited), false, "one setting moved");
  const folders = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, { mail: mailStub(folders) });
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual(sourceErrors, [waiting("mail")]);
  assert.deepEqual(folders, []);
});

/* ------------------------------------------------- http_json: the owner's User-Agent */

test("a userAgent setting moves the sources hash, and a bot's preview of it is gated", async () => {
  const db = await freshDb();
  const { report, deps } = await liveReport(db, { recipe: { blocks: [FEED_BLOCK] } });
  await approveHostFor(db, report.id);

  const plain = { blocks: [FEED_BLOCK] };
  const withAgent = {
    blocks: [{
      ...FEED_BLOCK,
      settings: { ...FEED_BLOCK.settings, userAgent: "Example Reader contact@example.com" },
    }],
  };
  assert.equal(sourcesHash(plain, blockRegistry), report.sourcesHash);
  assert.notEqual(sourcesHash(withAgent, blockRegistry), report.sourcesHash,
    "the agent is a source setting, so it is inside the sealed sources hash");

  // A bot's save of it may not ride the owner's approval: this is not a free change.
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: withAgent });
  assert.equal(saved.needsGoLive, true);
  assert.equal(saved.pendingFreeChange, false);

  // And a bot's preview of the changed block reads nothing: the block is waiting for the owner's OK.
  const urls = [];
  const preview = await botPreview(db, report.id, deps, fakeFetch(urls));
  assert.deepEqual(preview.sourceErrors, [waiting("feed")]);
  assert.deepEqual(urls, [], "no request was made for content the owner never approved");
});

/* ------------------------------------------- the block log's own advisory code */

test("a run whose model was down records the ai_fallback code in its block log", async () => {
  const db = await freshDb();
  const recipe = {
    blocks: [FEED_BLOCK, { id: "ai1", type: "ai_commentary", settings: {} }],
  };
  const report = await prepare(db, { recipe });
  await updateReportColumns(db, report.id, { ai_commentary: 1 });
  await approveHostFor(db, report.id);
  const model = { providerId: "local-chat", model: "m1", locality: "local", baseUrlHost: "127.0.0.1:8013" };
  const deps = approvalDeps(report, { resolveModelRef: async () => model });
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: PREVIEW, actor: OWNER });

  const runId = await queueRun(db, report.id, { trigger: "manual", requestedBy: "owner" });
  const out = await executeRun(db, runDeps(deps, {
    ...fakeFetch([]),
    complete: async () => { throw new Error("model down"); },
  }), runId);
  assert.equal(out.status, "ok", "a model that is down fails no run");
  const row = await getRun(db, runId);
  assert.deepEqual(row.blockLog.sourceErrors, []);
  assert.deepEqual(row.blockLog.warnings, [{ source: "ai1", message: "ai_fallback" }]);
});

/* ------------------------------------------------- the mail account rule on a draft */

test("an owner preview of a draft mail_alerts block they wrote reads the report's own sender account", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const block = { id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 } };
  // A draft has no live set at all, so the account a mail block is measured against is the report row's
  // own sender behind the owner's sender seal (the settings save below). Without that fallback this block
  // could never preview, and so the report could never go live.
  const report = await prepare(db, { recipe: { blocks: [block] }, sender: accountId });
  const deps = approvalDeps(report);
  await updateSettings(db, deps, {
    reportId: report.id, settings: { sender_account_id: accountId }, actor: OWNER,
  });
  assert.deepEqual(await isSourceApprovedForBot(db, deps, await getReport(db, report.id), block), { ok: true });

  const folders = [];
  const runId = await queueRun(db, report.id, { trigger: "preview", requestedBy: "owner" });
  const out = await executeRun(db, runDeps(deps, { mail: mailStub(folders) }), runId);
  assert.deepEqual(out, { status: "empty", artifactVersion: null });
  assert.deepEqual((await getRun(db, runId)).blockLog.sourceErrors, []);
  assert.deepEqual(folders, ["INBOX/Alerts"], "the draft's mail block really read the owner's account");
});

test("a bot-authored mail_alerts block on the owner's own account still waits on a draft", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const report = await prepare(db, { recipe: { blocks: [FILTER_BLOCK] }, sender: accountId });
  const deps = approvalDeps(report);

  // The bot introduces the mail block: the owner never put these settings there, so the content gate
  // waits, however legitimate the account is.
  const head = { id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [FILTER_BLOCK, head] } });
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), head),
    { ok: false, text: waitingForOkText("mail") },
  );

  const folders = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, { mail: mailStub(folders) });
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual(sourceErrors, [waiting("mail")]);
  assert.deepEqual(folders, [], "no mailbox was read");
});

test("a draft mail_alerts block naming another account than the report's sender waits", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const otherAccount = await addMailAccount(db, "sam@example.com");
  // The owner wrote this block, so its content is not gated: the account rule is the only thing left
  // refusing it, and it does.
  const block = {
    id: "mail", type: "mail_alerts", settings: { accountId: otherAccount, label: "Alerts", sinceDays: 7 },
  };
  const report = await prepare(db, { recipe: { blocks: [block] }, sender: accountId });
  const deps = approvalDeps(report);
  // The owner's own sender is sealed, so the only thing refusing the block is the account it names.
  await updateSettings(db, deps, {
    reportId: report.id, settings: { sender_account_id: accountId }, actor: OWNER,
  });
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), block),
    { ok: false, text: waitingForOkText("mail") },
  );

  const folders = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, { mail: mailStub(folders) });
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual(sourceErrors, [waiting("mail")]);
  assert.deepEqual(folders, [], "no mailbox was read");
});

/* ------------------------------------------- one paged pass over the revisions for a whole run */

test("a preview pages the report's revisions once, however many gated blocks it has", async () => {
  const db = await freshDb();
  // Both blocks are bot-introduced, so both are gated and both need the owner-history answer.
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] }, authorKind: "bot" });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);
  const second = { id: "feed2", type: "http_json", settings: { url: "https://api.example.com/items?page=2" } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [FEED_BLOCK, second] } });

  const execute = db.execute.bind(db);
  let revisionReads = 0;
  let readsHashColumn = 0;
  db.execute = async (arg) => {
    const sql = typeof arg === "string" ? arg : arg && arg.sql;
    if (typeof sql === "string" && sql.includes("report_recipe_revisions") && sql.includes("rev <=")) {
      // The owner-history pass reads the revision rows in keyset pages and carries `recipe_hash` in the
      // same SELECT, so the per-row seal check needs no second pass over the same rows.
      revisionReads += 1;
      if (sql.includes("recipe_hash")) readsHashColumn += 1;
    }
    return execute(arg);
  };
  try {
    const urls = [];
    const { out, sourceErrors } = await botPreview(db, report.id, deps, fakeFetch(urls));
    assert.deepEqual(out, { status: "failed", artifactVersion: null });
    assert.deepEqual(sourceErrors, [waiting("feed"), waiting("feed2")], "both blocks are gated");
    assert.deepEqual(urls, [], "no request was made");
  } finally {
    db.execute = execute;
  }
  assert.equal(revisionReads, 1, "one page of the report's revisions for the whole run, not one read per block");
  assert.equal(readsHashColumn, 1, "and that one page carries what the owner-seal check needs");
});

/* ------------------------------------------------- the gate follows the content, not the author */

test("an owner's preview of a bot-authored head reads only approved content, whoever saved it last", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const sealed = { id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 } };
  const { report, deps } = await liveReport(db, { recipe: { blocks: [sealed] }, sender: accountId });

  // The bot writes a new label into the head; the owner presses Preview on that head.
  const head = { id: "mail", type: "mail_alerts", settings: { accountId, label: "Other", sinceDays: 7 } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [head] } });
  const runId = await queueRun(db, report.id, { trigger: "preview", requestedBy: "owner" });
  const folders = [];
  const out = await executeRun(db, runDeps(deps, { mail: mailStub(folders) }), runId);
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual((await getRun(db, runId)).blockLog.sourceErrors, [waiting("mail")]);
  assert.deepEqual(folders, [], "no mailbox was read for content the owner never put there");

  // The owner saves the same head themselves: the id carried these settings in the bot's revision, so
  // this save starts no owner run of its own, and the block waits.
  await ownerSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [head] }, actor: OWNER });
  const secondRun = await queueRun(db, report.id, { trigger: "preview", requestedBy: "owner" });
  const secondFolders = [];
  const second = await executeRun(db, runDeps(deps, { mail: mailStub(secondFolders) }), secondRun);
  assert.deepEqual(second, { status: "failed", artifactVersion: null }, "a later owner save is not an approval");
  assert.deepEqual(secondFolders, []);

  // The owner's own approval of those settings is what lets it run.
  await approveSource(db, deps, {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(head), actor: OWNER,
  });
  const thirdRun = await queueRun(db, report.id, { trigger: "preview", requestedBy: "owner" });
  const thirdFolders = [];
  const third = await executeRun(db, runDeps(deps, { mail: mailStub(thirdFolders) }), thirdRun);
  assert.deepEqual(third, { status: "empty", artifactVersion: null });
  assert.deepEqual(thirdFolders, ["INBOX/Other"], "the approved label runs");
});

test("an owner-authored block unchanged by a later bot revision stays ungated", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK, FILTER_BLOCK] } });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);

  // The bot edits the filter only: the feed block is the same settings the owner first saved.
  await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [FEED_BLOCK, { ...FILTER_BLOCK, settings: { field: "title", op: "exists" } }] },
  });
  const urls = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, fakeFetch(urls));
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  assert.deepEqual(sourceErrors, []);
  assert.deepEqual(urls, [FEED_URL], "the owner's own content ran on a bot-requested preview");
});

test("a label a bot introduced stays gated after the owner saves the whole recipe again", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const sealed = { id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 } };
  const { report, deps } = await liveReport(db, { recipe: { blocks: [sealed] }, sender: accountId });

  // Rev N is the bot's: a label the owner never wrote.
  const botLabel = { id: "mail", type: "mail_alerts", settings: { accountId, label: "Bot label", sinceDays: 7 } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [botLabel] } });
  // Rev N+1 is the owner's, saved as a whole recipe with the same block: it is still the bot's content.
  const saved = await ownerSaveRecipe(db, deps, {
    reportId: report.id, recipe: { blocks: [botLabel] }, actor: OWNER,
  });
  assert.equal(saved.restamped, false, "a mail label is a live-set change, not a free one");
  const runId = await queueRun(db, report.id, { trigger: "preview", requestedBy: "owner" });
  const folders = [];
  const out = await executeRun(db, runDeps(deps, { mail: mailStub(folders) }), runId);
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual((await getRun(db, runId)).blockLog.sourceErrors, [waiting("mail")]);
  assert.deepEqual(folders, [], "the bot's label is still waiting for the owner's OK");
});

test("a block the owner introduced, a bot edited, and the owner reverted is ungated", async () => {
  const db = await freshDb();
  const first = { blocks: [FEED_BLOCK] };
  const report = await prepare(db, { recipe: first });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);

  // The bot changes the settings, then the owner saves the identical settings back.
  const edited = { ...FEED_BLOCK, settings: { url: "https://api.example.com/items?page=2" } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [edited] } });
  await ownerSaveRecipe(db, deps, { reportId: report.id, recipe: first, actor: OWNER });

  // The owner's own save put these settings here, and the owner's own save put them back, so the run of
  // revisions that carries them is the owner's again.
  const urls = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, fakeFetch(urls));
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  assert.deepEqual(sourceErrors, []);
  assert.deepEqual(urls, [FEED_URL], "the owner's own content, reverted to, runs");
});

test("a block the owner added, removed, and a bot re-added under the same id is gated", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);

  // The owner takes the block out, and a bot puts the identical settings back under the same id. No
  // revision between the owner's add and this head carries the block, so the owner's history of it ended.
  await ownerSaveRecipe(db, deps, {
    reportId: report.id, recipe: { blocks: [FILTER_BLOCK] }, actor: OWNER,
  });
  await botSaveRecipe(db, deps, {
    reportId: report.id, recipe: { blocks: [FEED_BLOCK, FILTER_BLOCK] },
  });

  const verdict = await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK);
  assert.deepEqual(verdict, { ok: false, text: waitingForOkText("feed") });

  const urls = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, fakeFetch(urls));
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual(sourceErrors, [waiting("feed")]);
  assert.deepEqual(urls, [], "no request was made for settings a bot put back");
});

test("a bot editing the settings away and back to the identical settings leaves the block gated", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);

  // Both moves are the bot's: the owner's run of revisions carrying these settings ended at the edit, and
  // nothing the owner wrote starts another one.
  const edited = { ...FEED_BLOCK, settings: { url: "https://api.example.com/items?page=2" } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [edited] } });
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [FEED_BLOCK] } });

  const verdict = await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK);
  assert.deepEqual(verdict, { ok: false, text: waitingForOkText("feed") });

  const urls = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, fakeFetch(urls));
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual(sourceErrors, [waiting("feed")]);
  assert.deepEqual(urls, [], "no request was made for settings a bot moved back");
});

test("a block the owner added and later owner and bot revisions leave untouched stays ungated", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK, FILTER_BLOCK] } });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);

  // Two later revisions keep the block exactly as the owner saved it: one of them the owner's, one a
  // bot's. Every revision in the range carries the block, so the run of revisions is unbroken.
  await ownerSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [FEED_BLOCK, { ...FILTER_BLOCK, settings: { field: "title", op: "exists" } }] },
    actor: OWNER,
  });
  await botSaveRecipe(db, deps, {
    reportId: report.id, recipe: { blocks: [FEED_BLOCK, FILTER_BLOCK] },
  });

  const urls = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, fakeFetch(urls));
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  assert.deepEqual(sourceErrors, []);
  assert.deepEqual(urls, [FEED_URL], "the owner's content, untouched since, runs");
});

test("an owner re-adding a block a bot removed is ungated again", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK, FILTER_BLOCK] } });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);

  // The bot removes the block; the owner's own save puts the identical settings back. A chain may restart
  // at an owner revision that re-adds the block where it was missing, so this head is the owner's content.
  await botSaveRecipe(db, deps, {
    reportId: report.id, recipe: { blocks: [FILTER_BLOCK] },
  });
  await ownerSaveRecipe(db, deps, {
    reportId: report.id, recipe: { blocks: [FEED_BLOCK, FILTER_BLOCK] }, actor: OWNER,
  });

  const urls = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, fakeFetch(urls));
  assert.deepEqual(out, { status: "ok", artifactVersion: null });
  assert.deepEqual(sourceErrors, []);
  assert.deepEqual(urls, [FEED_URL], "the owner's re-add runs without a second tap");
});

test("a bot's change to a custom block's params waits for approveSource, and runs after it", async () => {
  const db = await freshDb();
  const step = { id: "fetch", type: "custom", settings: { step: "fetch", params: { limit: 3 } } };
  const report = await prepare(db, { recipe: { blocks: [step] } });
  const deps = approvalDeps(report);
  await approveStepFor(db, report.id);

  // The bot widens what the step is asked to do: a different step input to approve.
  const head = { ...step, settings: { step: "fetch", params: { limit: 50 } } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [head] } });

  let ran = 0;
  const counting = stepSeam({ runStep: async () => { ran += 1; return { ok: true, output: { items: [{ id: "a" }] } }; } });
  const first = await botPreview(db, report.id, deps, counting);
  assert.deepEqual(first.out, { status: "failed", artifactVersion: null });
  assert.deepEqual(first.sourceErrors, [waiting("fetch")]);
  assert.equal(ran, 0, "the step never ran");

  await approveSource(db, deps, {
    reportId: report.id, blockId: "fetch", expectedSettingsHash: settingsHashOf(head), actor: OWNER,
  });
  const second = await botPreview(db, report.id, deps, counting);
  assert.deepEqual(second.out, { status: "ok", artifactVersion: null });
  assert.deepEqual(second.sourceErrors, []);
  assert.equal(ran, 1, "the approval let the same step run");
});

/* -------------------------------------------------------------- free changes and Apply */

test("an owner free change applies with an auto preview, so the next scheduled run uses it", async () => {
  const db = await freshDb();
  const sealedFilter = { id: "keep", type: "filter", settings: { field: "title", op: "exists" } };
  const editedFilter = { id: "keep", type: "filter", settings: { field: "title", op: "contains", value: "zzz" } };
  const { report, deps } = await liveReport(db, { recipe: { blocks: [FEED_BLOCK, sealedFilter] } });
  await approveHostFor(db, report.id);
  const before = await getReport(db, report.id);

  const saved = await ownerSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [FEED_BLOCK, editedFilter] },
    actor: OWNER,
  });
  assert.equal(saved.restamped, true, "a filter edit is free, so the seal is re-stamped at it");
  assert.equal(saved.needsGoLive, false);
  const after1 = await getReport(db, report.id);
  assert.equal(Number(after1.live_rev), saved.rev);
  assert.notEqual(after1.live_seal, before.live_seal);

  const runId = await queueRun(db, report.id, {
    trigger: "schedule", requestedBy: "schedule", scheduledFor: T0,
  });
  const out = await executeRun(db, runDeps(deps, fakeFetch([], FEED_ITEMS)), runId);
  assert.deepEqual(out, { status: "empty", artifactVersion: null },
    "the edited filter keeps nothing, so the run says so");
});

test("a bot free change waits for Apply and never re-stamps the seal on its own", async () => {
  const db = await freshDb();
  const sealedFilter = { id: "keep", type: "filter", settings: { field: "title", op: "exists" } };
  const botFilter = { id: "keep", type: "filter", settings: { field: "title", op: "contains", value: "zzz" } };
  const { report, deps } = await liveReport(db, { recipe: { blocks: [FEED_BLOCK, sealedFilter] } });
  await approveHostFor(db, report.id);
  const before = await getReport(db, report.id);

  const saved = await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [FEED_BLOCK, botFilter] },
  });
  assert.equal(saved.pendingFreeChange, true);
  assert.equal(saved.needsGoLive, false);
  const afterBot = await getReport(db, report.id);
  assert.equal(afterBot.live_seal, before.live_seal, "the seal is the owner's and did not move");
  assert.equal(Number(afterBot.live_rev), before.live_rev);
  assert.equal(Number(afterBot.pending_free_change), 1);

  // Before Apply, a scheduled run still executes the SEALED filter, which keeps both items.
  const firstRun = await queueRun(db, report.id, {
    trigger: "schedule", requestedBy: "schedule", scheduledFor: T0,
  });
  const first = await executeRun(db, runDeps(deps, fakeFetch([], FEED_ITEMS)), firstRun);
  assert.deepEqual(first, { status: "ok", artifactVersion: null });

  // One owner tap applies the bot's change, and the next run executes it: nothing passes the filter now.
  const applied = await applyPendingFreeChange(db, deps, { reportId: report.id, actor: OWNER });
  assert.deepEqual(applied, { ok: true, liveRev: saved.rev });
  const secondRun = await queueRun(db, report.id, {
    trigger: "schedule", requestedBy: "schedule", scheduledFor: T0 + 60_000,
  });
  const out = await executeRun(db, runDeps(deps, fakeFetch([], FEED_ITEMS)), secondRun);
  assert.deepEqual(out, { status: "empty", artifactVersion: null });
  assert.equal(Number((await getReport(db, report.id)).live_rev), saved.rev);
  assert.equal(await isLive(db, deps, await getReport(db, report.id)), true);
});

/* ------------------------------------------------------------------------- the hashes */

test("sourcesHash ignores filter, sort and present changes and moves on any source setting", async () => {
  const db = await freshDb();
  const { id } = await createReport(db, { projectId: PROJECT, owner: "owner", title: "Listings" });
  const base = {
    blocks: [
      FEED_BLOCK,
      FILTER_BLOCK,
      { id: "order", type: "sort", settings: { field: "title", direction: "asc" } },
      { id: "table1", type: "table", settings: { columns: ["title"] } },
    ],
  };
  const saved = await saveRecipe(db, { reportId: id, recipe: base, authorKind: "owner" });
  const save = (blocks) => saveRecipe(db, { reportId: id, recipe: { blocks }, authorKind: "owner" });

  const filterEdit = await save([
    FEED_BLOCK,
    { ...FILTER_BLOCK, settings: { field: "title", op: "exists" } },
    base.blocks[2],
    base.blocks[3],
  ]);
  assert.equal(filterEdit.sourcesHash, saved.sourcesHash, "a filter setting is free");

  const sortEdit = await save([
    FEED_BLOCK,
    FILTER_BLOCK,
    { id: "order", type: "sort", settings: { field: "title", direction: "desc" } },
    base.blocks[3],
  ]);
  assert.equal(sortEdit.sourcesHash, saved.sourcesHash, "a sort setting is free");

  const presentEdit = await save([
    FEED_BLOCK,
    FILTER_BLOCK,
    base.blocks[2],
    { id: "table1", type: "table", settings: { columns: ["title", "link"] } },
  ]);
  assert.equal(presentEdit.sourcesHash, saved.sourcesHash, "a present setting is free");

  for (const [label, settings] of [
    ["url query", { url: "https://api.example.com/items?page=2" }],
    ["url host", { url: "https://listing.example.com/items?page=1" }],
    ["itemsPath", { url: FEED_URL, itemsPath: "data.items" }],
  ]) {
    const edit = await save([
      { ...FEED_BLOCK, settings },
      FILTER_BLOCK,
      base.blocks[2],
      base.blocks[3],
    ]);
    assert.notEqual(edit.sourcesHash, saved.sourcesHash, `the ${label} is part of the source`);
  }
});

test("adding an ai_commentary block changes sourcesHash", async () => {
  const db = await freshDb();
  const { id } = await createReport(db, { projectId: PROJECT, owner: "owner", title: "Listings" });
  const plain = await saveRecipe(db, {
    reportId: id, recipe: { blocks: [FEED_BLOCK, FILTER_BLOCK] }, authorKind: "owner",
  });
  const withAi = await saveRecipe(db, {
    reportId: id,
    recipe: { blocks: [FEED_BLOCK, FILTER_BLOCK, { id: "ai", type: "ai_commentary", settings: {} }] },
    authorKind: "owner",
  });
  assert.notEqual(withAi.sourcesHash, plain.sourcesHash, "a block that sends data to a model is source-bearing");
});

test("a bot cannot turn ai_commentary on: it is a live-set change", async () => {
  const db = await freshDb();
  const { report, deps } = await liveReport(db, { recipe: { blocks: [FEED_BLOCK] } });
  await approveHostFor(db, report.id);

  // The column is part of the sealed live set, and the switch is off.
  assert.equal(SEAL_FIELDS.live.includes("aiCommentary"), true);
  const live = await verifyLive(db, deps, await getReport(db, report.id));
  assert.equal(live.aiCommentary, 0);

  // A bot's save that adds a model-calling block is a live-set change: it needs a go-live.
  const saved = await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [FEED_BLOCK, { id: "ai", type: "ai_commentary", settings: {} }] },
  });
  assert.equal(saved.pendingFreeChange, false);
  assert.equal(saved.needsGoLive, true);
  assert.equal(Number((await getReport(db, report.id)).live_rev), report.rev, "still on the sealed revision");

  // Turning the column on without the owner's rail breaks the seal, so the report is not live.
  await db.execute({ sql: "UPDATE reports SET ai_commentary = 1 WHERE id = ?", args: [report.id] });
  assert.equal(await verifyLive(db, deps, await getReport(db, report.id)), null);
  assert.equal(await isLive(db, deps, await getReport(db, report.id)), false);

  // And the owner's own settings write pauses the report with the fixed sentence.
  const other = await freshDb();
  const fresh = await liveReport(other, { recipe: { blocks: [FEED_BLOCK] } });
  const paused = await updateSettings(other, fresh.deps, {
    reportId: fresh.report.id, settings: { ai_commentary: 1 }, actor: OWNER,
  });
  assert.equal(paused.status, "paused");
  assert.equal(paused.live_seal, null);
});

/* ------------------------------------------------------------ the state seam and forgeries */

test("the block-level setState refuses the source_approval prefix, and the store accepts the gateway's own write", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });

  const stateWrites = [];
  const { setState: blockSetState } = makeStateAccess({ stateWrites, buffered: new Map() });
  for (const key of [`${SOURCE_APPROVAL_PREFIX}feed`, SOURCE_APPROVAL_PREFIX]) {
    assert.throws(
      () => blockSetState(key, { settingsHash: "a".repeat(64) }),
      (err) => err.code === "reserved_state_key",
      key,
    );
  }
  assert.deepEqual(stateWrites, [], "a refused key is not buffered");

  await setState(db, report.id, `${SOURCE_APPROVAL_PREFIX}feed`, { settingsHash: "a".repeat(64) });
  assert.deepEqual(await getState(db, report.id, `${SOURCE_APPROVAL_PREFIX}feed`), {
    settingsHash: "a".repeat(64),
  }, "the gateway's own write path is not the block seam");
});

test("a forged source_approval row with a wrong seal does not approve, and no request is made", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] }, authorKind: "bot" });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);

  await db.execute({
    sql: `INSERT INTO report_state (report_id, key, value_json, updated_at) VALUES (?, ?, ?, ?)`,
    args: [
      report.id,
      `${SOURCE_APPROVAL_PREFIX}feed`,
      JSON.stringify({ settingsHash: settingsHashOf(FEED_BLOCK), nonce: "a".repeat(32), seal: "b".repeat(64) }),
      T0,
    ],
  });
  assert.equal(await verifySourceApproval(db, deps, report.id, FEED_BLOCK), false);

  const urls = [];
  const { out, sourceErrors } = await botPreview(db, report.id, deps, fakeFetch(urls));
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual(sourceErrors, [waiting("feed")]);
  assert.deepEqual(urls, []);
});

test("a source_approval row sealed for another block id does not approve this one", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);
  // A real approval of one block id, copied onto another block id's key.
  const other = { id: "other", type: "http_json", settings: { url: FEED_URL } };
  await saveRecipe(db, {
    reportId: report.id,
    recipe: { blocks: [FEED_BLOCK, other] },
    authorKind: "owner",
  });
  await approveSource(db, deps, {
    reportId: report.id, blockId: "other", expectedSettingsHash: settingsHashOf(other), actor: OWNER,
  });
  const row = await getState(db, report.id, `${SOURCE_APPROVAL_PREFIX}other`);
  await setState(db, report.id, `${SOURCE_APPROVAL_PREFIX}feed`, row);
  assert.equal(await verifySourceApproval(db, deps, report.id, FEED_BLOCK), false,
    "the block id is inside the seal");
});

/* ------------------------------------------------------------------- approve and revoke */

test("approveSource and revokeSource are the owner's, cover source and custom blocks, and audit each decision", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const mail = { id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 } };
  const step = { id: "step1", type: "custom", settings: { step: "fetch" } };
  const report = await prepare(db, {
    recipe: { blocks: [mail, FILTER_BLOCK, step] },
    sender: accountId,
  });
  const deps = approvalDeps(report);

  for (const actor of [BOT_ACTOR, undefined, { kind: "system" }]) {
    await assert.rejects(
      () => approveSource(db, deps, { reportId: report.id, blockId: "mail", actor }),
      (err) => err.code === "owner_only",
    );
    await assert.rejects(
      () => revokeSource(db, deps, { reportId: report.id, blockId: "mail", actor }),
      (err) => err.code === "owner_only",
    );
  }

  // A block that reads nothing worth approving, and an id that names no block, are refused before the
  // settings hash is looked at.
  for (const blockId of ["keep", "missing"]) {
    await assert.rejects(
      () => approveSource(db, deps, { reportId: report.id, blockId, actor: OWNER }),
      (err) => (blockId === "missing" ? err.code === "not_found" : err.code === "bad_input"),
      blockId,
    );
  }
  await assert.rejects(
    () => approveSource(db, deps, { reportId: report.id, blockId: "Mail", actor: OWNER }),
    (err) => err.code === "bad_input",
    "a block id is lower case",
  );

  // A custom block is approvable at its exact settings now, on top of its own step rail.
  const approvedStep = await approveSource(db, deps, {
    reportId: report.id, blockId: "step1", expectedSettingsHash: settingsHashOf(step), actor: OWNER,
  });
  assert.equal(approvedStep.ok, true);

  const approved = await approveSource(db, deps, {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(mail), actor: OWNER,
  });
  assert.equal(approved.ok, true);
  assert.equal(approved.settingsHash.length, 64);
  const row = await getState(db, report.id, `${SOURCE_APPROVAL_PREFIX}mail`);
  assert.deepEqual(Object.keys(row).sort(), ["nonce", "seal", "settingsHash"]);
  assert.match(row.seal, /^[0-9a-f]{64}$/);
  assert.match(row.nonce, /^[0-9a-f]{32}$/);

  const revoked = await revokeSource(db, deps, { reportId: report.id, blockId: "mail", actor: OWNER });
  assert.deepEqual(revoked, { ok: true, blockId: "mail" });
  assert.equal(await getState(db, report.id, `${SOURCE_APPROVAL_PREFIX}mail`), null, "the seal is nulled");

  const { rows } = await db.execute({
    sql: "SELECT kind, subject, actor, decided FROM report_approvals_audit WHERE report_id = ? ORDER BY id",
    args: [report.id],
  });
  assert.deepEqual(rows.map((r) => [r.kind, r.subject, r.actor, r.decided]), [
    ["source", "step1", "owner", "approved"],
    ["source", "mail", "owner", "approved"],
    ["source", "mail", "owner", "revoked"],
  ]);
});

test("an approval is for the settings the owner's view showed, so a save since then answers source_changed", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  await approveHostFor(db, report.id);
  const deps = approvalDeps(report);

  // The view the owner reads: the block, its type, the hash the tap hands back, and no approval yet.
  const [view] = await listDraftSources(db, deps, report.id);
  assert.deepEqual(view, {
    blockId: "feed",
    type: "http_json",
    settingsHash: settingsHashOf(FEED_BLOCK),
    approved: false,
  });

  // A bot saves other settings before the owner's tap lands.
  const moved = { ...FEED_BLOCK, settings: { url: "https://api.example.com/items?page=9" } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [moved] } });
  await assert.rejects(
    () => approveSource(db, deps, {
      reportId: report.id, blockId: "feed", expectedSettingsHash: view.settingsHash, actor: OWNER,
    }),
    (err) => err.code === "source_changed",
  );
  assert.equal(await getState(db, report.id, `${SOURCE_APPROVAL_PREFIX}feed`), null, "nothing was sealed");

  // A tap with no hash at all is the same refusal: an approval must be about a view.
  await assert.rejects(
    () => approveSource(db, deps, { reportId: report.id, blockId: "feed", actor: OWNER }),
    (err) => err.code === "source_changed",
  );

  // The view the owner reads NOW is the one that works, and it approves only those settings.
  const [fresh] = await listDraftSources(db, deps, report.id);
  assert.notEqual(fresh.settingsHash, view.settingsHash);
  await approveSource(db, deps, {
    reportId: report.id, blockId: "feed", expectedSettingsHash: fresh.settingsHash, actor: OWNER,
  });
  assert.equal(await verifySourceApproval(db, deps, report.id, moved), true);
  assert.equal((await listDraftSources(db, deps, report.id))[0].approved, true);
});

test("a source approval needs a saved revision to name its block", async () => {
  const db = await freshDb();
  const { id } = await createReport(db, { projectId: PROJECT, owner: "owner", title: "Listings" });
  await assert.rejects(
    () => approveSource(db, approvalDeps({ id, rev: 0 }), {
      reportId: id, blockId: "feed", expectedSettingsHash: settingsHashOf(FEED_BLOCK), actor: OWNER,
    }),
    (err) => err.code === "not_found",
    "no revision row, so no block to approve",
  );
});

test("an approval follows the settings and the block id, so a renamed block starts unapproved", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  const deps = approvalDeps(report);
  await approveSource(db, deps, {
    reportId: report.id, blockId: "feed", expectedSettingsHash: settingsHashOf(FEED_BLOCK), actor: OWNER,
  });

  // The same settings, saved again under a different id: the hash is unchanged, the key is not.
  const renamed = { ...FEED_BLOCK, id: "feed2" };
  await saveRecipe(db, { reportId: report.id, recipe: { blocks: [renamed] }, authorKind: "owner" });
  assert.equal(await verifySourceApproval(db, deps, report.id, renamed), false, "a new id is a new key");
  assert.equal(await verifySourceApproval(db, deps, report.id, FEED_BLOCK), true,
    "the old key still names the settings the owner approved");
});

test("a renamed id does not change the settings hash", () => {
  assert.equal(
    settingsHashOf({ id: "one", type: "http_json", settings: { url: FEED_URL } }),
    settingsHashOf({ id: "two", type: "http_json", settings: { url: FEED_URL } }),
  );
  assert.notEqual(
    settingsHashOf({ id: "one", type: "http_json", settings: { url: FEED_URL } }),
    settingsHashOf({ id: "one", type: "rss", settings: { url: FEED_URL } }),
    "the block type is part of it",
  );
  assert.equal(
    settingsHashOf({ id: "one", type: "rss" }),
    settingsHashOf({ id: "one", type: "rss", settings: {} }),
    "absent settings and an empty object are one thing to approve",
  );
});

test("sourcesHash and the settings hash move together on a source setting, and only sourcesHash moves on a rename", () => {
  const one = { blocks: [FEED_BLOCK] };
  const renamed = { blocks: [{ ...FEED_BLOCK, id: "renamed" }] };
  const other = { blocks: [{ ...FEED_BLOCK, settings: { url: "https://api.example.com/items?page=2" } }] };
  assert.equal(
    settingsHashOf(renamed.blocks[0]),
    settingsHashOf(one.blocks[0]),
    "the approval follows the settings, not the id",
  );
  assert.notEqual(sourcesHash(one, blockRegistry), sourcesHash(renamed, blockRegistry),
    "sourcesHash covers the whole block object, so a renamed id is a different sealed revision");
  assert.notEqual(sourcesHash(one, blockRegistry), sourcesHash(other, blockRegistry));
  assert.notEqual(settingsHashOf(other.blocks[0]), settingsHashOf(one.blocks[0]));
});