// The report's sender seal: proof that the OWNER chose the mail account a report is about.
//
// A live report's sender is inside the go-live seal. A report that was never live (or whose live seal no
// longer verifies) has no such proof, so the owner's settings save seals the account it writes
// (sender-seal.js), and the approval rails trust the row's `sender_account_id` only behind that seal —
// never because of how the head revision was written.
//
// Harness: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR and CROW_HOME under a temp
// dir, so nothing reaches a real Crow), real report, revision, schedule and mail account rows, the
// keychain seed and clock injected through the approvals deps, and a stubbed `mail` seam (a refused
// preview here never opens a mailbox).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-sender-seal-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const {
  botSaveRecipe, ownerSaveRecipe, updateSettings,
} = await import("../servers/gateway/reports/approvals.js");
const { verifyApprovalSeal } = await import("../servers/gateway/reports/seal.js");
const { SENDER_SEAL_KEY, sealSender, senderSealVerifies } = await import(
  "../servers/gateway/reports/sender-seal.js"
);
const {
  approveSource, approvedSenderAccount, isSourceApprovedForBot, settingsHashOf, waitingForOkText,
} = await import("../servers/gateway/reports/source-approvals.js");
const { blockRegistry } = await import("../servers/gateway/reports/blocks/index.js");
const { makeStateAccess } = await import("../servers/gateway/reports/blocks/run-recipe.js");
const { isReservedStateKey } = await import("../servers/gateway/reports/artifact-bridge.js");
const { executeRun, getRun, startRun } = await import("../servers/gateway/reports/run.js");
const {
  createReport, getReport, getState, saveRecipe, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { createAccount } = await import("../servers/gateway/mail/store/accounts.js");

const OWNER = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 71);
const OTHER_SEED = Buffer.alloc(32, 72);
const PROJECT = 7;
const T0 = 1_700_000_000_000;
const BOT = "bot:bot-1";

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

/** The approvals deps: the keychain seed, the clock, the block registry and the send-ready sender. */
function approvalDeps(report = {}, over = {}) {
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    senderReady: async () => true,
    registry: blockRegistry,
    ...over,
  };
}

/** The run engine's deps: the approvals seam, a delivery stub and whatever a run needs. */
function runDeps(approvals, over = {}) {
  return { approvals, deliver: async () => {}, now: () => T0, getSecrets: () => [], ...over };
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

/**
 * One saved report whose sender is set the way a direct column write sets it: no sender seal yet.
 *
 * `authorKind` picks who saved the first revision, and `sealed` whether an owner save carried the author
 * seal, because neither of those is what a draft preview leans on for the account.
 */
async function prepare(db, { recipe, sender, authorKind = "owner", sealed = true } = {}) {
  const scheduleId = await addSchedule(db);
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: "owner", botId: "bot-1", title: "Weekly listings",
  });
  let saved;
  if (sealed && authorKind === "owner") {
    saved = await ownerSaveRecipe(db, approvalDeps({ id }), { reportId: id, recipe, actor: OWNER });
  } else {
    saved = await saveRecipe(db, { reportId: id, recipe, authorKind, registry: blockRegistry });
  }
  await updateReportColumns(db, id, {
    schedule_id: scheduleId,
    sender_account_id: sender,
    delivery_mode: "email_link",
    comment_tier_default: "c",
    comment_visibility: "own",
    ai_commentary: 0,
  });
  return { id, rev: saved.rev };
}

/** The owner's settings route, the one writer of the sender seal. */
async function saveSender(db, reportId, accountId, over = {}) {
  return updateSettings(db, approvalDeps({ id: reportId }, over), {
    reportId, settings: { sender_account_id: accountId }, actor: OWNER,
  });
}

async function queuePreview(db, reportId) {
  const { runId } = await startRun(db, { now: () => T0 }, {
    reportId, trigger: "preview", requestedBy: BOT,
  });
  return runId;
}

/** A mail seam that records the folder every read names and answers no messages. */
function mailStub(folders) {
  return async (_account, fn) => {
    folders.push("seam");
    return fn({
      listFolders: async () => [{ path: "INBOX/Alerts", name: "Alerts" }],
      list: async (folder) => {
        folders.push(folder);
        return { items: [] };
      },
      get: async () => [],
    });
  };
}

/** One mail block naming one account. */
function mailBlock(accountId) {
  return {
    id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 },
  };
}

/** Queue a bot's preview of a report and answer what the run recorded. */
async function preview(db, reportId, deps, over = {}) {
  const runId = await queuePreview(db, reportId);
  const out = await executeRun(db, runDeps(deps, over), runId);
  const row = await getRun(db, runId);
  return { runId, out, sourceErrors: row.blockLog ? row.blockLog.sourceErrors : [] };
}

/* ------------------------------------------------------------- the seal a save writes */

test("the owner's settings save seals the sender it writes, and another setting leaves that seal alone", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const otherAccount = await addMailAccount(db, "sam@example.com");
  const report = await prepare(db, { recipe: { blocks: [mailBlock(accountId)] }, sender: accountId });

  // The column alone is not a seal.
  assert.equal(await senderSealVerifies(db, SEED, await getReport(db, report.id)), false);
  assert.equal(await getState(db, report.id, SENDER_SEAL_KEY), null);

  const updated = await saveSender(db, report.id, accountId);
  assert.equal(updated.sender_account_id, accountId);
  const row = await getState(db, report.id, SENDER_SEAL_KEY);
  assert.deepEqual(Object.keys(row).sort(), ["accountId", "nonce", "seal"]);
  assert.equal(row.accountId, accountId);
  assert.match(row.nonce, /^[0-9a-f]{32}$/);
  assert.match(row.seal, /^[0-9a-f]{64}$/);
  assert.equal(verifyApprovalSeal("sender", {
    reportId: report.id, accountId, nonce: row.nonce,
  }, row.seal, SEED), true, "the seal is over this report and this account");
  assert.equal(verifyApprovalSeal("sender", {
    reportId: report.id, accountId, nonce: row.nonce,
  }, row.seal, OTHER_SEED), false, "another keychain key is another seal");
  assert.equal(await senderSealVerifies(db, SEED, await getReport(db, report.id)), true);
  assert.equal(await senderSealVerifies(db, OTHER_SEED, await getReport(db, report.id)), false);

  // A settings save of another key writes nothing here.
  await updateSettings(db, approvalDeps({ id: report.id }), {
    reportId: report.id, settings: { title: "Weekly listings, renamed" }, actor: OWNER,
  });
  assert.deepEqual(await getState(db, report.id, SENDER_SEAL_KEY), row,
    "a setting that is not the sender leaves the sender seal exactly as it was");

  // The same sender saved again is a fresh seal (a fresh nonce), still over the same account.
  await saveSender(db, report.id, accountId);
  const again = await getState(db, report.id, SENDER_SEAL_KEY);
  assert.equal(again.accountId, accountId);
  assert.notEqual(again.nonce, row.nonce, "one save, one nonce");
  assert.equal(await senderSealVerifies(db, SEED, await getReport(db, report.id)), true);

  // A new sender is a new seal, and it is the only account the report may read.
  await saveSender(db, report.id, otherAccount);
  const moved = await getReport(db, report.id);
  assert.equal(moved.sender_account_id, otherAccount);
  assert.equal((await getState(db, report.id, SENDER_SEAL_KEY)).accountId, otherAccount);
  assert.equal(await senderSealVerifies(db, SEED, moved), true);
  assert.equal(await approvedSenderAccount(db, approvalDeps({ id: report.id }), null, moved),
    otherAccount);
});

test("sealSender binds the report id and the account", () => {
  const proof = sealSender(SEED, { reportId: "rpt-0011223344556677", accountId: "ma-0011223344556677" });
  const fields = {
    reportId: "rpt-0011223344556677", accountId: "ma-0011223344556677", nonce: proof.nonce,
  };
  assert.equal(verifyApprovalSeal("sender", fields, proof.seal, SEED), true);
  assert.equal(
    verifyApprovalSeal("sender", { ...fields, accountId: "ma-8899aabbccddeeff" }, proof.seal, SEED),
    false,
    "another account is another seal",
  );
  assert.equal(
    verifyApprovalSeal("sender", { ...fields, reportId: "rpt-8899aabbccddeeff" }, proof.seal, SEED),
    false,
    "another report is another seal",
  );
});

/* ------------------------------------------------- a sender that moved under its own seal */

test("a sender that moves to an account no seal can be made for clears the old seal, so moving back trusts nothing", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const otherAccount = await addMailAccount(db, "sam@example.com");
  const report = await prepare(db, { recipe: { blocks: [mailBlock(accountId)] }, sender: accountId });
  const deps = approvalDeps({ id: report.id });

  // A, sealed by the owner's settings save.
  await saveSender(db, report.id, accountId);
  assert.equal(await senderSealVerifies(db, SEED, await getReport(db, report.id)), true);

  // The sender moves to B, and no seal for B can be made (there is no keychain key to read).
  const moved = await saveSender(db, report.id, otherAccount, { loadSeed: () => null });
  assert.equal(moved.sender_account_id, otherAccount, "the settings were saved");
  assert.equal(await getState(db, report.id, SENDER_SEAL_KEY), null,
    "the seal left by A is cleared, not left behind naming A");
  assert.equal(await senderSealVerifies(db, SEED, moved), false);

  // A direct UPDATE of the column back to A must not find A's old seal still there to verify against.
  await db.execute({
    sql: "UPDATE reports SET sender_account_id = ? WHERE id = ?",
    args: [accountId, report.id],
  });
  const back = await getReport(db, report.id);
  assert.equal(back.sender_account_id, accountId, "the column really moved back");
  assert.equal(await senderSealVerifies(db, SEED, back), false, "the seal is gone, not merely stale");
  assert.equal(await approvedSenderAccount(db, deps, null, back), "");

  // And a never-live report's mail block naming A is refused, with no mailbox read. The block's own
  // content is approved, so the sender rule is the only thing left refusing it.
  const block = mailBlock(accountId);
  await approveSource(db, deps, {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(block), actor: OWNER,
  });
  assert.deepEqual(await isSourceApprovedForBot(db, deps, back, block),
    { ok: false, text: waitingForOkText("mail") });

  const folders = [];
  const out = await preview(db, report.id, deps, { mail: mailStub(folders) });
  assert.deepEqual(out.out, { status: "failed", artifactVersion: null });
  assert.deepEqual(out.sourceErrors, [{ source: "mail", message: waitingForOkText("mail") }]);
  assert.deepEqual(folders, [], "no mailbox was read");
});

test("a sender moved by a direct UPDATE is not trusted, and a preview of a never-live report reads no mailbox", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const otherAccount = await addMailAccount(db, "sam@example.com");
  const report = await prepare(db, { recipe: { blocks: [mailBlock(otherAccount)] }, sender: accountId });
  const deps = approvalDeps({ id: report.id });
  await saveSender(db, report.id, accountId);

  // The column moves to the account the block names, and no new seal is written with it.
  await db.execute({
    sql: "UPDATE reports SET sender_account_id = ? WHERE id = ?",
    args: [otherAccount, report.id],
  });
  const moved = await getReport(db, report.id);
  assert.equal(moved.sender_account_id, otherAccount, "the column really moved");
  assert.equal(await senderSealVerifies(db, SEED, moved), false, "the seal names the account it was made over");
  assert.equal(await approvedSenderAccount(db, deps, null, moved), "");

  // The block's own content is approved, so the account rule is the only thing left refusing it.
  const block = mailBlock(otherAccount);
  await approveSource(db, deps, {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(block), actor: OWNER,
  });
  assert.deepEqual(await isSourceApprovedForBot(db, deps, moved, block),
    { ok: false, text: waitingForOkText("mail") });

  const folders = [];
  const out = await preview(db, report.id, deps, { mail: mailStub(folders) });
  assert.deepEqual(out.out, { status: "failed", artifactVersion: null });
  assert.deepEqual(out.sourceErrors, [{ source: "mail", message: waitingForOkText("mail") }]);
  assert.deepEqual(folders, [], "no mailbox was read");
});

test("before the owner's settings save a never-live report's mail block waits, and after it the same preview reads", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const block = mailBlock(accountId);
  // A BOT head revision: the revision says nothing about the sender, and never did.
  const report = await prepare(db, { recipe: { blocks: [block] }, sender: accountId, authorKind: "bot" });
  const deps = approvalDeps({ id: report.id });

  // (d) The row names the account, but no settings save sealed it yet.
  const head = await getReport(db, report.id);
  assert.equal(await senderSealVerifies(db, SEED, head), false);
  const refusedFolders = [];
  const refused = await preview(db, report.id, deps, { mail: mailStub(refusedFolders) });
  assert.deepEqual(refused.out, { status: "failed", artifactVersion: null });
  assert.deepEqual(refused.sourceErrors, [{ source: "mail", message: waitingForOkText("mail") }]);
  assert.deepEqual(refusedFolders, [], "no mailbox was read");

  // (c) The owner saves the sender in settings and approves the block's settings as a draft source.
  await saveSender(db, report.id, accountId);
  const sealedHead = await getReport(db, report.id);
  assert.equal(await senderSealVerifies(db, SEED, sealedHead), true);
  await approveSource(db, deps, {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(block), actor: OWNER,
  });
  assert.deepEqual(await isSourceApprovedForBot(db, deps, sealedHead, block), { ok: true });

  const folders = [];
  const unblocked = await preview(db, report.id, deps, { mail: mailStub(folders) });
  assert.deepEqual(unblocked.out, { status: "empty", artifactVersion: null });
  assert.deepEqual(unblocked.sourceErrors, []);
  assert.deepEqual(folders, ["seam", "INBOX/Alerts"], "the mailbox the owner chose was read");
});

/* ------------------------------------------------------------------ copied and broken seals */

test("a copied or broken sender seal verifies nothing, and a missing seed is a refusal", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const otherAccount = await addMailAccount(db, "sam@example.com");
  const report = await prepare(db, { recipe: { blocks: [mailBlock(accountId)] }, sender: accountId });
  await saveSender(db, report.id, accountId);
  const genuine = await getState(db, report.id, SENDER_SEAL_KEY);
  const head = await getReport(db, report.id);
  assert.equal(await senderSealVerifies(db, SEED, head), true);

  // One character of the seal changed.
  const flipped = { ...genuine, seal: `${genuine.seal[0] === "0" ? "1" : "0"}${genuine.seal.slice(1)}` };
  await db.execute({
    sql: "UPDATE report_state SET value_json = ? WHERE report_id = ? AND key = ?",
    args: [JSON.stringify(flipped), report.id, SENDER_SEAL_KEY],
  });
  assert.equal(await senderSealVerifies(db, SEED, head), false);

  // Another report's seal, made by the same keychain: the report id is inside it.
  const other = await prepare(db, { recipe: { blocks: [mailBlock(accountId)] }, sender: accountId });
  await saveSender(db, other.id, accountId);
  const otherSeal = await getState(db, other.id, SENDER_SEAL_KEY);
  await db.execute({
    sql: "UPDATE report_state SET value_json = ? WHERE report_id = ? AND key = ?",
    args: [JSON.stringify(otherSeal), report.id, SENDER_SEAL_KEY],
  });
  assert.equal(await senderSealVerifies(db, SEED, head), false);

  // The right seal, left behind by an earlier sender: the account id is inside it too.
  await db.execute({
    sql: "UPDATE report_state SET value_json = ? WHERE report_id = ? AND key = ?",
    args: [JSON.stringify(genuine), report.id, SENDER_SEAL_KEY],
  });
  await db.execute({
    sql: "UPDATE reports SET sender_account_id = ? WHERE id = ?",
    args: [otherAccount, report.id],
  });
  assert.equal(await senderSealVerifies(db, SEED, await getReport(db, report.id)), false,
    "a stale accountId seals no account of the row");

  // A row that is not the seal shape, and a missing or empty seed.
  assert.equal(await senderSealVerifies(db, SEED, { id: report.id, sender_account_id: "" }), false);
  assert.equal(await senderSealVerifies(db, SEED, { id: report.id }), false);
  assert.equal(await senderSealVerifies(db, SEED, null), false);
  assert.equal(await senderSealVerifies(db, null, head), false);
  assert.equal(await senderSealVerifies(db, Buffer.alloc(0), head), false);
  assert.equal(await senderSealVerifies(db, SEED, { id: "rpt-0011223344556677", sender_account_id: accountId }),
    false, "no row, no seal");
  await assert.doesNotReject(async () => senderSealVerifies(db, null, head));
});

/* ------------------------------------------------------------------- who may write the seal */

test("no bot path writes the sender seal: a block's setState refuses the key and a bot's save leaves the row alone", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const report = await prepare(db, { recipe: { blocks: [mailBlock(accountId)] }, sender: accountId });
  await saveSender(db, report.id, accountId);
  const sealed = await getState(db, report.id, SENDER_SEAL_KEY);

  assert.equal(isReservedStateKey(SENDER_SEAL_KEY), true);
  assert.equal(isReservedStateKey(`${SENDER_SEAL_KEY} `), false, "no trimming: a near miss is another key");
  const stateWrites = [];
  const { setState: blockSetState } = makeStateAccess({ stateWrites, buffered: new Map() });
  assert.throws(
    () => blockSetState(SENDER_SEAL_KEY, { accountId, nonce: "a".repeat(32), seal: "b".repeat(64) }),
    (err) => err.code === "reserved_state_key",
  );
  assert.deepEqual(stateWrites, [], "a refused key is not buffered");

  // A bot's save moves the head revision and leaves the seal row untouched.
  const saved = await botSaveRecipe(db, approvalDeps({ id: report.id }), {
    reportId: report.id, recipe: { blocks: [mailBlock(accountId)] },
  });
  assert.equal(saved.authorSealed, false);
  assert.deepEqual(await getState(db, report.id, SENDER_SEAL_KEY), sealed);
  assert.equal(await senderSealVerifies(db, SEED, await getReport(db, report.id)), true);

  // And the owner's Apply path (a re-stamp of the live seal) is not one of the writers either: it needs a
  // live report, and this one is a draft, so the only writer left is the settings save.
  assert.equal((await getReport(db, report.id)).status, "draft");
});

test("a missing keychain key saves the settings with no seal, and the preview is refused", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const block = mailBlock(accountId);
  const report = await prepare(db, { recipe: { blocks: [block] }, sender: accountId });
  const deps = approvalDeps({ id: report.id }, { loadSeed: () => null });

  const updated = await saveSender(db, report.id, accountId, { loadSeed: () => null });
  assert.equal(updated.sender_account_id, accountId, "the settings were saved");
  assert.equal(await getState(db, report.id, SENDER_SEAL_KEY), null, "and no seal was written");
  assert.equal(await senderSealVerifies(db, SEED, await getReport(db, report.id)), false);

  // The approval itself is made with a keychain key (an approval is a seal); the preview is the read that
  // has none, and it trusts neither the sender nor the block.
  await approveSource(db, approvalDeps({ id: report.id }), {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(block), actor: OWNER,
  });
  const folders = [];
  const out = await preview(db, report.id, deps, { mail: mailStub(folders) });
  assert.deepEqual(out.out, { status: "failed", artifactVersion: null });
  assert.deepEqual(out.sourceErrors, [{ source: "mail", message: waitingForOkText("mail") }]);
  assert.deepEqual(folders, []);
});

/* ------------------------------------------------------------- the save answer's own flag */

test("the save answer says whether it wrote the revision's author seal", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const report = await prepare(db, { recipe: { blocks: [mailBlock(accountId)] }, sender: accountId });

  const sealed = await ownerSaveRecipe(db, approvalDeps({ id: report.id }), {
    reportId: report.id, recipe: { blocks: [mailBlock(accountId)] }, actor: OWNER,
  });
  assert.equal(sealed.authorSealed, true, "an owner save with a keychain key seals its revision");

  const seedless = await ownerSaveRecipe(db, approvalDeps({ id: report.id }, { loadSeed: () => null }), {
    reportId: report.id, recipe: { blocks: [mailBlock(accountId)] }, actor: OWNER,
  });
  assert.equal(seedless.authorSealed, false, "no keychain key, no author seal, and the save still lands");

  const bot = await botSaveRecipe(db, approvalDeps({ id: report.id }), {
    reportId: report.id, recipe: { blocks: [mailBlock(accountId)] },
  });
  assert.equal(bot.authorSealed, false, "a bot save writes no author seal");
});