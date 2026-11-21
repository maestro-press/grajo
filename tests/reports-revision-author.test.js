// The revision author seal: proof that the OWNER saved one recipe revision, and the source gate's
// owner-history path, which is the one place that leans on it.
//
// Harness: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR and CROW_HOME under a temp
// dir, so nothing reaches a real Crow), real report, revision, schedule and mail account rows, the
// keychain seed and clock injected through the approvals deps, and a stubbed `mail` seam (a preview here
// never opens a mailbox).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-revision-author-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const {
  approveGoLive, botSaveRecipe, ownerSaveRecipe, updateSettings, verifyLive,
} = await import("../servers/gateway/reports/approvals.js");
const {
  REVISION_AUTHOR_PREFIX, ownerSealedRevisions, sealAuthorRevision,
} = await import("../servers/gateway/reports/revision-author.js");
const { SENDER_SEAL_KEY, senderSealVerifies } = await import(
  "../servers/gateway/reports/sender-seal.js"
);
const { verifyApprovalSeal } = await import("../servers/gateway/reports/seal.js");
const {
  approveSource, approvedSenderAccount, isSourceApprovedForBot, ownerChainAnswers, settingsHashOf,
  verifySourceApproval, waitingForOkText,
} = await import("../servers/gateway/reports/source-approvals.js");
const { blockRegistry } = await import("../servers/gateway/reports/blocks/index.js");
const { makeStateAccess, runRecipe } = await import(
  "../servers/gateway/reports/blocks/run-recipe.js"
);
const { isReservedStateKey } = await import("../servers/gateway/reports/artifact-bridge.js");
const { executeRun, getRun, startRun } = await import("../servers/gateway/reports/run.js");
const {
  createReport, getReport, getRevision, getState, saveRecipe, setState, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { createAccount } = await import("../servers/gateway/mail/store/accounts.js");

const OWNER = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 53);
const PROJECT = 7;
const T0 = 1_700_000_000_000;
const PREVIEW = "prv-1";
const BOT = "bot:bot-1";

const FEED_BLOCK = Object.freeze({
  id: "feed", type: "http_json", settings: { url: "https://api.example.com/items?page=1" },
});
const FILTER_BLOCK = Object.freeze({
  id: "keep", type: "filter", settings: { field: "title", op: "contains", value: "one" },
});

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
function approvalDeps(report = {}, over = {}) {
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
 * One saved report with a schedule, a sender and the live-set settings a go-live needs.
 *
 * `sealed` decides how the first revision is saved: through the owner's own route (which writes the
 * author seal), or through the bare store call an older build made (which writes none).
 */
async function prepare(db, { recipe, sender = "ma-0011223344556677", authorKind = "owner", sealed = true } = {}) {
  const scheduleId = await addSchedule(db);
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: "owner", botId: "bot-1", title: "Weekly listings",
  });
  let saved;
  if (sealed && authorKind === "owner") {
    saved = await ownerSaveRecipe(db, approvalDeps(), { reportId: id, recipe, actor: OWNER });
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

/**
 * Seal one report's sender the way the owner's settings route does, so a draft's mail block has an
 * account the approval rails will measure against (`updateSettings` is the only writer of that seal).
 */
async function sealSenderViaSettings(db, reportId, accountId) {
  await updateSettings(db, approvalDeps({ id: reportId }), {
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

/* -------------------------------------------------------- the seal a save writes */

test("an owner save writes a revision_author state row the author seal verifies over, and a bot save writes none", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  const revision = await getRevision(db, report.id, report.rev);
  assert.equal(revision.author_kind, "owner");

  const row = await getState(db, report.id, `${REVISION_AUTHOR_PREFIX}${report.rev}`);
  assert.deepEqual(Object.keys(row).sort(), ["nonce", "seal"]);
  assert.match(row.nonce, /^[0-9a-f]{32}$/);
  assert.match(row.seal, /^[0-9a-f]{64}$/);
  assert.equal(verifyApprovalSeal("author", {
    reportId: report.id,
    rev: report.rev,
    recipeHash: revision.recipe_hash,
    authorKind: "owner",
    nonce: row.nonce,
  }, row.seal, SEED), true, "the seal is over this report, this revision and this recipe hash");
  assert.equal(verifyApprovalSeal("author", {
    reportId: report.id,
    rev: report.rev,
    recipeHash: revision.recipe_hash,
    authorKind: "owner",
    nonce: row.nonce,
  }, row.seal, Buffer.alloc(32, 54)), false, "another seed is another key");

  // The reader proves the head, and only up to the revision it was asked about.
  assert.deepEqual([...(await ownerSealedRevisions(db, SEED, report.id, report.rev))], [report.rev]);
  assert.deepEqual([...(await ownerSealedRevisions(db, SEED, report.id, report.rev - 1))], []);

  // A bot's save writes a revision and no seal, so the head stops being provably the owner's.
  const saved = await botSaveRecipe(db, approvalDeps(), {
    reportId: report.id, recipe: { blocks: [FEED_BLOCK, FILTER_BLOCK] },
  });
  assert.equal(await getState(db, report.id, `${REVISION_AUTHOR_PREFIX}${saved.rev}`), null);
  assert.deepEqual([...(await ownerSealedRevisions(db, SEED, report.id, saved.rev))], [report.rev],
    "the bot's head carries no seal of its own");
});

test("sealAuthorRevision binds the revision number and the author kind", () => {
  const fields = {
    reportId: "rpt-0011223344556677", rev: 3, recipeHash: "a".repeat(64), authorKind: "owner",
  };
  const proof = sealAuthorRevision(SEED, fields);
  assert.equal(verifyApprovalSeal("author", { ...fields, nonce: proof.nonce }, proof.seal, SEED), true);
  assert.equal(
    verifyApprovalSeal("author", { ...fields, rev: 4, nonce: proof.nonce }, proof.seal, SEED), false,
    "another revision is another seal",
  );
  assert.equal(
    verifyApprovalSeal("author", { ...fields, authorKind: "bot", nonce: proof.nonce }, proof.seal, SEED),
    false,
    "another author kind is another seal",
  );
});

/* --------------------------------------------- the owner-history path, and forgeries */

test("an owner-sealed revision starts the owner history, and a later bot revision that keeps it identical stays approved", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  const deps = approvalDeps();
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK),
    { ok: true },
  );

  // The bot touches the filter only: the feed block is the owner's own content, untouched.
  await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [FEED_BLOCK, { ...FILTER_BLOCK, settings: { field: "title", op: "exists" } }] },
  });
  const answers = await ownerChainAnswers(db, report.id, report.rev + 1, deps);
  assert.equal(
    answers.get(`${FEED_BLOCK.id}\u0000${settingsHashOf(FEED_BLOCK)}`), true,
    "the run started at the sealed owner revision and nothing dropped the block",
  );
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK),
    { ok: true },
  );
});

test("a deleted revision between two others ends the owner history, so a bot's re-add stays gated", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  const deps = approvalDeps();

  // Rev 1 is the owner's (sealed), rev 2 the bot removing the block, rev 3 the bot putting the identical
  // settings back under the same id.
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [FILTER_BLOCK] } });
  const readded = await botSaveRecipe(db, deps, {
    reportId: report.id, recipe: { blocks: [FEED_BLOCK] },
  });
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK),
    { ok: false, text: waitingForOkText("feed") },
    "the owner's run ended at the revision that dropped the block",
  );

  // The revision that dropped it is deleted straight out of the table, and its author state row with it
  // (a bot's save writes none; the delete clears it either way). The two rows left carry the block
  // identically, so only the missing revision number still says the history is not one unbroken stretch.
  await db.execute({
    sql: "DELETE FROM report_recipe_revisions WHERE report_id = ? AND rev = ?",
    args: [report.id, report.rev + 1],
  });
  await db.execute({
    sql: "DELETE FROM report_state WHERE report_id = ? AND key = ?",
    args: [report.id, `${REVISION_AUTHOR_PREFIX}${report.rev + 1}`],
  });
  assert.equal((await getRevision(db, report.id, report.rev + 1)), null, "the row is really gone");

  const head = await getReport(db, report.id);
  assert.equal(Number(head.recipe_rev), readded.rev);
  const chain = await ownerChainAnswers(db, report.id, head.recipe_rev, deps);
  assert.equal(chain.get(`${FEED_BLOCK.id}\u0000${settingsHashOf(FEED_BLOCK)}`), false,
    "a missing revision number ends every run");
  assert.deepEqual(await isSourceApprovedForBot(db, deps, head, FEED_BLOCK),
    { ok: false, text: waitingForOkText("feed") });

  // And a preview of that head is gated before the block is entered: no request is made.
  const urls = [];
  const out = await runRecipe(db, {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    registry: blockRegistry,
    testSeams: true,
    testFetch: async (url) => { urls.push(url); throw new Error("no request expected"); },
  }, {
    report: head,
    recipe: { blocks: [FEED_BLOCK] },
    run: { trigger: "preview" },
    live: null,
    state: {},
  });
  assert.deepEqual(out.sourceErrors, [{ source: "feed", message: waitingForOkText("feed") }]);
  assert.deepEqual(urls, [], "the block never read anything");
});

test("a bot revision whose author_kind column was flipped to owner is not owner-written evidence", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] }, authorKind: "bot" });
  const deps = approvalDeps();
  assert.equal(await getState(db, report.id, `${REVISION_AUTHOR_PREFIX}${report.rev}`), null);

  await db.execute({
    sql: "UPDATE report_recipe_revisions SET author_kind = 'owner' WHERE report_id = ? AND rev = ?",
    args: [report.id, report.rev],
  });
  assert.equal((await getRevision(db, report.id, report.rev)).author_kind, "owner");
  assert.deepEqual([...(await ownerSealedRevisions(db, SEED, report.id, report.rev))], [],
    "a flipped column proves nothing");
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK),
    { ok: false, text: waitingForOkText("feed") },
  );
});

test("a seal copied onto another revision is not owner-written evidence", async () => {
  const db = await freshDb();
  // Rev 1 is the owner's save of one recipe, rev 2 the owner's save of another: both are genuinely
  // sealed, and each seal names its own revision and its own recipe hash.
  const report = await prepare(db, { recipe: { blocks: [FILTER_BLOCK] } });
  const deps = approvalDeps(report);
  const second = await ownerSaveRecipe(db, deps, {
    reportId: report.id, recipe: { blocks: [FEED_BLOCK] }, actor: OWNER,
  });
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK),
    { ok: true },
  );

  // The first revision's proof, put under the second revision's own key: the revision number is inside
  // the seal, so it proves nothing here, and the owner history for the feed block starts nowhere.
  await setState(db, report.id, `${REVISION_AUTHOR_PREFIX}${second.rev}`,
    await getState(db, report.id, `${REVISION_AUTHOR_PREFIX}${report.rev}`));
  assert.deepEqual([...(await ownerSealedRevisions(db, SEED, report.id, second.rev))], [report.rev],
    "the copied seal proves no revision");
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK),
    { ok: false, text: waitingForOkText("feed") },
  );
});

test("a seal with one character changed, and another report's seal, are not owner-written evidence", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  const deps = approvalDeps();
  const head = await getReport(db, report.id);

  const genuine = await getState(db, report.id, `${REVISION_AUTHOR_PREFIX}${head.recipe_rev}`);
  const flipped = `${genuine.seal[0] === "0" ? "1" : "0"}${genuine.seal.slice(1)}`;
  await setState(db, report.id, `${REVISION_AUTHOR_PREFIX}${head.recipe_rev}`,
    { nonce: genuine.nonce, seal: flipped });
  assert.deepEqual([...(await ownerSealedRevisions(db, SEED, report.id, head.recipe_rev))], [],
    "one changed character proves nothing");
  assert.deepEqual(await isSourceApprovedForBot(db, deps, head, FEED_BLOCK),
    { ok: false, text: waitingForOkText("feed") });

  // A seal the same keychain made for another report: the report id is inside the seal too.
  const other = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  const otherProof = await getState(db, other.id, `${REVISION_AUTHOR_PREFIX}${other.rev}`);
  await setState(db, report.id, `${REVISION_AUTHOR_PREFIX}${head.recipe_rev}`, otherProof);
  assert.deepEqual([...(await ownerSealedRevisions(db, SEED, report.id, head.recipe_rev))], [],
    "another report's seal proves nothing here");
  assert.deepEqual(await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK),
    { ok: false, text: waitingForOkText("feed") });
});

test("a recipe body tampered under an intact hash column is not owner-written evidence", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  const deps = approvalDeps(report);
  const savedRow = await getRevision(db, report.id, report.rev);
  const moved = { blocks: [{ ...FEED_BLOCK, settings: { url: "https://api.example.com/items?page=9" } }] };
  await db.execute({
    sql: "UPDATE report_recipe_revisions SET recipe_json = ? WHERE report_id = ? AND rev = ?",
    args: [JSON.stringify(moved), report.id, report.rev],
  });
  // The hash column still names the text that was saved there, which is no longer the body on the row.
  assert.equal((await getRevision(db, report.id, report.rev)).recipe_hash, savedRow.recipe_hash);
  assert.deepEqual([...(await ownerSealedRevisions(db, SEED, report.id, report.rev))], [],
    "a tampered body under an intact hash column proves nothing");
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), moved.blocks[0]),
    { ok: false, text: waitingForOkText("feed") },
  );
});

test("an owner revision saved without an author seal is not evidence, and approveSource is the way forward", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] }, sealed: false });
  const deps = approvalDeps();
  assert.equal((await getRevision(db, report.id, report.rev)).author_kind, "owner",
    "the column still says the owner saved it");
  assert.equal(await getState(db, report.id, `${REVISION_AUTHOR_PREFIX}${report.rev}`), null);
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK),
    { ok: false, text: waitingForOkText("feed") },
    "a revision saved before the seal existed is not owner-chain evidence",
  );

  // The owner's own approval of those settings (path b) is what lets the block run.
  await approveSource(db, deps, {
    reportId: report.id, blockId: "feed", expectedSettingsHash: settingsHashOf(FEED_BLOCK), actor: OWNER,
  });
  assert.equal(await verifySourceApproval(db, deps, report.id, FEED_BLOCK), true);
  assert.deepEqual(
    await isSourceApprovedForBot(db, deps, await getReport(db, report.id), FEED_BLOCK),
    { ok: true },
  );
});

test("with no keychain seed no revision is proved and nothing throws", async () => {
  const db = await freshDb();
  const report = await prepare(db, { recipe: { blocks: [FEED_BLOCK] } });
  const seedless = approvalDeps({}, { loadSeed: () => null });
  const head = await getReport(db, report.id);

  const answers = await ownerChainAnswers(db, report.id, head.recipe_rev, seedless);
  assert.ok(answers instanceof Map);
  assert.equal([...answers.values()].some((answer) => answer === true), false,
    "no pair is answered as owned with no seed");
  assert.deepEqual([...(await ownerSealedRevisions(db, null, report.id, head.recipe_rev))], []);
  assert.equal(await approvedSenderAccount(db, seedless, null, head), "");
  assert.deepEqual(await isSourceApprovedForBot(db, seedless, head, FEED_BLOCK),
    { ok: false, text: waitingForOkText("feed") });
});

/* --------------------------------------------------- the mail account a block is measured against */

test("a live report's sealed sender wins, and a tampered row is never the account on its own", async () => {
  const db = await freshDb();
  const sealedAccount = await addMailAccount(db);
  const otherAccount = await addMailAccount(db, "sam@example.com");
  const block = {
    id: "mail", type: "mail_alerts", settings: { accountId: sealedAccount, label: "Alerts", sinceDays: 7 },
  };
  const report = await prepare(db, { recipe: { blocks: [block] }, sender: sealedAccount });
  const deps = approvalDeps(report);
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: PREVIEW, actor: OWNER });

  const liveHead = await getReport(db, report.id);
  const live = await verifyLive(db, deps, liveHead);
  assert.equal(await approvedSenderAccount(db, deps, live, liveHead), sealedAccount,
    "the verified live set's sealed sender");
  assert.equal(
    await approvedSenderAccount(db, deps, live, { ...liveHead, sender_account_id: otherAccount }),
    sealedAccount,
    "and it comes first: a row column that moved is not the account when the live set verifies",
  );

  // The head is the bot's now, and the row names another account: a direct UPDATE of it is not an
  // approval, so a preview has no account to measure a mail block against.
  const tampered = { ...block, settings: { ...block.settings, accountId: otherAccount } };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks: [tampered] } });
  await db.execute({
    sql: "UPDATE reports SET sender_account_id = ? WHERE id = ?",
    args: [otherAccount, report.id],
  });
  const after = await getReport(db, report.id);
  assert.equal(after.sender_account_id, otherAccount, "the column really moved");
  assert.equal(await verifyLive(db, deps, after), null, "and the live seal no longer verifies");
  assert.equal(await approvedSenderAccount(db, deps, null, after), "",
    "the row column is not trusted without a sender seal");
  assert.deepEqual(await isSourceApprovedForBot(db, deps, after, tampered),
    { ok: false, text: waitingForOkText("mail") },
    "a block naming the other account does not pass the gate");
});

test("a never-live report whose sender the owner saved in settings previews its mail block", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const block = {
    id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 },
  };
  // The revision is saved by the bare store call, so it carries no author seal: the account a preview may
  // read hangs on the owner's settings save, not on how the head revision was written.
  const report = await prepare(db, { recipe: { blocks: [block] }, sender: accountId, sealed: false });
  const deps = approvalDeps(report);
  await sealSenderViaSettings(db, report.id, accountId);
  const head = await getReport(db, report.id);

  assert.equal(await senderSealVerifies(db, SEED, head), true, "the settings save sealed the sender");
  assert.equal(await approvedSenderAccount(db, deps, null, head), accountId);
  // The block's content needs its own approval, because this revision is not owner-chain evidence.
  await approveSource(db, deps, {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(block), actor: OWNER,
  });
  assert.deepEqual(await isSourceApprovedForBot(db, deps, head, block), { ok: true });

  const folders = [];
  const runId = await queuePreview(db, report.id);
  const out = await executeRun(db, runDeps(deps, { mail: mailStub(folders) }), runId);
  assert.deepEqual(out, { status: "empty", artifactVersion: null });
  assert.deepEqual(folders, ["seam", "INBOX/Alerts"], "the draft's mail block read the owner's account");
});

test("a never-live report whose sender was never sealed is refused, whatever its head revision is", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const block = {
    id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 },
  };

  // A bot's head revision, over a row that names the very account the block names, with no sender seal.
  const bot = await prepare(db, { recipe: { blocks: [block] }, sender: accountId, authorKind: "bot" });
  const deps = approvalDeps(bot);
  const botHead = await getReport(db, bot.id);
  assert.equal(await senderSealVerifies(db, SEED, botHead), false);
  assert.equal(await approvedSenderAccount(db, deps, null, botHead), "");
  assert.deepEqual(await isSourceApprovedForBot(db, deps, botHead, block),
    { ok: false, text: waitingForOkText("mail") });
  const botFolders = [];
  const botRun = await queuePreview(db, bot.id);
  const botOut = await executeRun(db, runDeps(deps, { mail: mailStub(botFolders) }), botRun);
  assert.deepEqual(botOut, { status: "failed", artifactVersion: null });
  assert.deepEqual(botFolders, [], "no mailbox was read");

  // An owner revision saved before the author seal existed, and a sender set by a column write: the same
  // refusal. The owner's settings save is what seals the sender (the test above).
  const bare = await prepare(db, { recipe: { blocks: [block] }, sender: accountId, sealed: false });
  const bareHead = await getReport(db, bare.id);
  assert.equal(await senderSealVerifies(db, SEED, bareHead), false);
  assert.equal(await approvedSenderAccount(db, deps, null, bareHead), "");
  assert.deepEqual(await isSourceApprovedForBot(db, deps, bareHead, block),
    { ok: false, text: waitingForOkText("mail") });
});

test("the mail block itself refuses account_not_approved when the row names an account nothing proves", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const otherAccount = await addMailAccount(db, "sam@example.com");
  const block = {
    id: "mail", type: "mail_alerts", settings: { accountId: otherAccount, label: "Alerts", sinceDays: 7 },
  };
  // A bot's head revision, and a row moved to the account the block names with no sender seal: the
  // content is approved as a draft source, so the account rule is the only thing left, and the block
  // reads no row itself.
  const report = await prepare(db, { recipe: { blocks: [block] }, sender: accountId, authorKind: "bot" });
  const deps = approvalDeps();
  await db.execute({
    sql: "UPDATE reports SET sender_account_id = ? WHERE id = ?",
    args: [otherAccount, report.id],
  });
  await approveSource(db, deps, {
    reportId: report.id, blockId: "mail", expectedSettingsHash: settingsHashOf(block), actor: OWNER,
  });
  assert.equal(await verifySourceApproval(db, deps, report.id, block), true);

  let seamCalls = 0;
  const out = await runRecipe(db, {
    now: () => T0,
    mail: async () => { seamCalls += 1; return []; },
  }, {
    report: await getReport(db, report.id),
    recipe: { blocks: [block] },
    run: { trigger: "manual" },
    live: null,
  });
  assert.deepEqual(out.sourceErrors, [{ source: "mail", message: "account_not_approved" }]);
  assert.equal(seamCalls, 0, "an unproved account never reaches the seam");
});

test("a preview of a live report whose head is a bot's free change reads the sealed sender's mailbox", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const mail = {
    id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 },
  };
  const report = await prepare(db, { recipe: { blocks: [mail, FILTER_BLOCK] }, sender: accountId });
  const deps = approvalDeps(report);
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: PREVIEW, actor: OWNER });
  assert.equal((await getReport(db, report.id)).status, "live");

  // The bot edits the filter only: a free change, so the report stays live on its sealed revision while
  // the HEAD revision is the bot's own save.
  const saved = await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [mail, { ...FILTER_BLOCK, settings: { field: "title", op: "exists" } }] },
  });
  assert.equal(saved.pendingFreeChange, true);
  const head = await getReport(db, report.id);
  assert.equal(head.status, "live");
  assert.equal(Number(head.recipe_rev), saved.rev);
  assert.notEqual(Number(head.recipe_rev), Number(head.live_rev), "the head is the bot's revision");

  // A preview is handed no live set (`run.js` passes `live = null`), and this report still has one: the
  // account a mail block is measured against is the sealed sender, not a fallback for a report with none.
  assert.equal(await approvedSenderAccount(db, deps, null, head), accountId);

  const folders = [];
  const runId = await queuePreview(db, report.id);
  const out = await executeRun(db, runDeps(deps, { mail: mailStub(folders) }), runId);
  assert.deepEqual(out, { status: "empty", artifactVersion: null });
  assert.deepEqual((await getRun(db, runId)).blockLog.sourceErrors, [], "no account_not_approved");
  assert.deepEqual(folders, ["seam", "INBOX/Alerts"], "the mailbox was read");
});

test("tampering the sender on that live report breaks the seal, so its preview reads no mailbox", async () => {
  const db = await freshDb();
  const accountId = await addMailAccount(db);
  const otherAccount = await addMailAccount(db, "sam@example.com");
  const mail = {
    id: "mail", type: "mail_alerts", settings: { accountId, label: "Alerts", sinceDays: 7 },
  };
  const report = await prepare(db, { recipe: { blocks: [mail, FILTER_BLOCK] }, sender: accountId });
  const deps = approvalDeps(report);
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: PREVIEW, actor: OWNER });
  await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [mail, { ...FILTER_BLOCK, settings: { field: "title", op: "exists" } }] },
  });

  // The sender is a sealed field, so moving the column drops the live set: the head is a bot's revision,
  // nothing carries an owner seal, and the block names no account a preview may read.
  await db.execute({
    sql: "UPDATE reports SET sender_account_id = ? WHERE id = ?",
    args: [otherAccount, report.id],
  });
  const head = await getReport(db, report.id);
  assert.equal(await verifyLive(db, deps, head), null, "the sealed sender moved");
  assert.equal(await approvedSenderAccount(db, deps, null, head), "");

  const folders = [];
  const runId = await queuePreview(db, report.id);
  const out = await executeRun(db, runDeps(deps, { mail: mailStub(folders) }), runId);
  assert.deepEqual(out, { status: "failed", artifactVersion: null });
  assert.deepEqual((await getRun(db, runId)).blockLog.sourceErrors,
    [{ source: "mail", message: waitingForOkText("mail") }]);
  assert.deepEqual(folders, [], "no mailbox was read");
});

/* ---------------------------------------------------------------- the reserved prefix */

test("the revision_author prefix is reserved: a block's setState refuses it", async () => {
  assert.equal(isReservedStateKey("revision_author:3"), true);
  assert.equal(isReservedStateKey(REVISION_AUTHOR_PREFIX), true);
  assert.equal(isReservedStateKey("revision_author"), false, "the bare word is not a key the rails use");
  assert.equal(isReservedStateKey(SENDER_SEAL_KEY), true, "the sender seal is reserved for the owner's save");
  assert.equal(isReservedStateKey("dedupe_seen"), false);

  const stateWrites = [];
  const { setState: blockSetState } = makeStateAccess({ stateWrites, buffered: new Map() });
  assert.throws(
    () => blockSetState("revision_author:3", { nonce: "a".repeat(32), seal: "b".repeat(64) }),
    (err) => err.code === "reserved_state_key",
  );
  assert.deepEqual(stateWrites, [], "a refused key is not buffered");
});