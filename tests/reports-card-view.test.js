// The report card's one owner-only read (servers/gateway/reports/card-view.js), its two owner routes,
// and the Perch chat's report list.
//
// Harness: one init-db'd scratch crow.db (CROW_DATA_DIR under a temp dir, so nothing can touch a real
// Crow data dir), ephemeral express apps holding the real reports API router and the real perch-api
// router, the real report store, approvals, source approvals and steps modules with an injected
// keychain seed, and a stub dashboardAuth/ownerCheck per router. A settings object is compared
// whole in the tests that care about it, because the card's point is that the owner reads everything.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";

const root = mkdtempSync(join(tmpdir(), "reports-card-view-"));
mkdirSync(join(root, "data"), { recursive: true });
mkdirSync(join(root, "home"), { recursive: true });
process.env.CROW_DATA_DIR = join(root, "data");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "tasks.db");
const REPO = new URL("..", import.meta.url).pathname;
const HOME = process.env.CROW_HOME;

const { default: express } = await import("express");
const { createDbClient } = await import("../servers/db.js");
const { reportsApiRouter, REPORTS_API_PREFIX } = await import("../servers/gateway/routes/reports-api.js");
const { default: perchInteractiveApiRouter } = await import(
  "../servers/gateway/routes/perch-interactive-api.js"
);
const {
  approveGoLive, approveRecipient, botSaveRecipe, isLive, ownerSaveRecipe, proposeRecipient, updateSettings,
} = await import("../servers/gateway/reports/approvals.js");
const { buildReportCardView, changesHashOf } = await import("../servers/gateway/reports/card-view.js");
const {
  createReport, getReport, getState, saveRecipe, setState, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { settingsHashOf } = await import("../servers/gateway/reports/source-approvals.js");
const {
  HOST_APPROVAL_LINE, approveCredential, approveHost, injectHashOf, proposeCredential, proposeHost,
  proposeStep,
} = await import("../servers/gateway/reports/steps.js");
const { createAccount } = await import("../servers/gateway/mail/store/accounts.js");
const { createKeychainKey } = await import("../servers/gateway/keychain/key.js");
const { REPORTS_BUNDLE, saveServiceSecret, serviceSecretsFor } = await import(
  "../servers/gateway/keychain/store.js"
);

const OWNER_ACTOR = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 7);
const T0 = 1_700_000_000_000;
const PROJECT = 7;
const SENDER = "ma-0011223344556677";
const PERCH = "/dashboard/perch-api";
const UUID = "33333333-3333-4333-8333-333333333333";
const APPROVED_UUID = "44444444-4444-4444-8444-444444444444";
const CREDENTIAL_SECRET = "card-view-credential-value-0123456789";
const ACCOUNT = { host: "mail.example.test", port: 993, security: "ssl" };
/** The fixed sentence a `conflict` carries, which is the one an Apply and a go-live tap answer. */
const CONFLICT = "That report changed while this request was in flight. Try again.";

const RECIPE = {
  blocks: [
    { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=1" } },
    { id: "b2", type: "filter", settings: { field: "title", op: "exists" } },
  ],
};

const FREE_EDIT = {
  blocks: [
    { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=1" } },
    { id: "b2", type: "filter", settings: { field: "title", op: "contains", value: "listing" } },
  ],
};

const SOURCE_EDIT = {
  blocks: [
    { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=2" } },
    { id: "b2", type: "filter", settings: { field: "title", op: "exists" } },
  ],
};

const RULE = Object.freeze({
  header: "Authorization",
  format: "Bearer {}",
  pathPrefixes: ["/v1/issues"],
  methods: ["GET", "HEAD"],
});

let db = null;
let server = null;
let ownerAllowed = true;
const runs = {};

/** The approvals seam every direct call and both routers share. */
const deps = {
  loadSeed: () => ({ seed: SEED }),
  now: () => T0,
  senderReady: async () => true,
  getRun: async (_db, runId) => runs[runId] ?? null,
};

/** The instance's own keychain key, for the one test that seeds a real credential secret. */
const keychainKey = createKeychainKey({ crowHome: HOME });

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: process.env.CROW_DATA_DIR },
    stdio: "pipe",
    cwd: REPO,
  });
  db = createDbClient();

  const app = express();
  const sessionGate = (req, res, next) => { req.dashboardSession = "test"; next(); };
  const ownerCheck = async () => ownerAllowed;
  app.use(reportsApiRouter(sessionGate, { ownerCheck, approvalsDeps: deps }));
  app.use(perchInteractiveApiRouter(sessionGate, {
    engine: () => ({ message: async () => ({ turnId: "t1" }) }),
    annotate: async (m) => m,
    providerModels: () => [],
    piProviders: () => null,
    ownerCheck,
    stagedGmail: () => null,
  }));
  await new Promise((resolve) => { server = app.listen(0, "127.0.0.1", resolve); });
});

after(async () => {
  if (server) { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
  try { db && db.close(); } catch { /* closed */ }
  rmSync(root, { recursive: true, force: true });
});

/* ------------------------------------------------------------------------- the harness */

function request(method, path, body) {
  const payload = body === undefined ? null : JSON.stringify(body);
  const headers = payload === null ? {} : {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  };
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: server.address().port, method, path, headers }, (res) => {
      let text = "";
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on("error", reject);
    req.end(payload === null ? undefined : payload);
  });
}

const get = (path) => request("GET", path);
const post = (path, body) => request("POST", path, body);
const cardPath = (id) => `${REPORTS_API_PREFIX}/${id}/card`;

/** One report's card, through the owner route. */
async function cardOf(id) {
  const answer = await get(cardPath(id));
  assert.equal(answer.status, 200, answer.text);
  return answer.json.card;
}

/** The two revisions' stored `recipe_hash` values, as the card's own digest folds them. */
async function recipeHashes(reportId, headRev, liveRev) {
  const read = async (rev) => {
    const { rows } = await db.execute({
      sql: "SELECT recipe_hash FROM report_recipe_revisions WHERE report_id = ? AND rev = ?",
      args: [reportId, rev],
    });
    return rows[0] ? rows[0].recipe_hash : "";
  };
  return { head: await read(headRev), live: await read(liveRev) };
}

async function addSchedule() {
  await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, tz) VALUES ('weekly-report', '0 7 * * 1', 'Europe/Berlin')",
    args: [],
  });
  const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
  return Number(rows[0].id);
}

/** One saved report, set up the way go-live needs it: a schedule row and a sender. */
async function makeReport({ title = "Weekly listings", recipe = RECIPE, authorKind = "owner" } = {}) {
  const scheduleId = await addSchedule();
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: "owner", botId: "bot-1", title,
  });
  const saved = await saveRecipe(db, { reportId: id, recipe, authorKind });
  await updateReportColumns(db, id, {
    schedule_id: scheduleId,
    sender_account_id: SENDER,
    delivery_mode: "email_link",
    comment_tier_default: "c",
    comment_visibility: "own",
    ai_commentary: 0,
  });
  await updateSettings(db, deps, {
    reportId: id, settings: { sender_account_id: SENDER }, actor: OWNER_ACTOR,
  });
  return { id, rev: saved.rev, scheduleId };
}

let runCount = 0;

/** One report taken live the way the owner's own go-live does it. */
async function liveReport(options = {}) {
  const report = await makeReport(options);
  runCount += 1;
  const runId = `prv-${String(runCount).padStart(4, "0")}`;
  runs[runId] = { id: runId, reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev };
  await approveGoLive(db, deps, { reportId: report.id, previewRunId: runId, actor: OWNER_ACTOR });
  return { ...report, runId };
}

/** One report whose own finished preview is registered: a go-live tap over it can succeed. */
async function previewedReport(options = {}) {
  const report = await makeReport(options);
  runCount += 1;
  const runId = `prv-${String(runCount).padStart(4, "0")}`;
  runs[runId] = { id: runId, reportId: report.id, kind: "preview", status: "ok", recipeRev: report.rev };
  return { ...report, runId };
}

/** One finished preview run row, for the card's preview lookup. */
async function addPreviewRun(id, reportId, status, recipeRev, createdAt, trigger = "preview") {
  await db.execute({
    sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, status, recipe_rev, created_at)
          VALUES (?, ?, ?, 'owner', ?, ?, ?)`,
    args: [id, reportId, trigger, status, recipeRev, createdAt],
  });
}

/* --------------------------------------------------------- the full settings of what it offers */

test("card view carries the full settings of a draft source", async () => {
  const settings = {
    url: "https://api.example.com/items?page=1",
    itemsPath: "data.items",
    userAgent: "Crow Reports/1.0",
  };
  const report = await makeReport({
    title: "Listings",
    recipe: { blocks: [{ id: "feed", type: "http_json", settings }] },
    authorKind: "bot",
  });

  const card = await cardOf(report.id);
  assert.equal(card.sources.length, 1);
  const [source] = card.sources;
  assert.equal(source.blockId, "feed");
  assert.equal(source.type, "http_json");
  assert.deepEqual(source.settings, settings, "the whole settings object, not a summary");
  assert.equal(source.settingsHash, settingsHashOf({ id: "feed", type: "http_json", settings }));
  assert.equal(Object.hasOwn(source, "truncated"), false);

  // The existing approval route takes the hash the card carried, and the block drops out of the list.
  const approved = await post(`${REPORTS_API_PREFIX}/${report.id}/sources/feed/approve`, {
    settingsHash: source.settingsHash,
  });
  assert.equal(approved.status, 200, approved.text);
  assert.deepEqual((await cardOf(report.id)).sources, []);
});

test("card view lists a pending free change with before and after settings", async () => {
  const report = await liveReport();
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT });
  assert.equal(saved.pendingFreeChange, true);

  const card = await cardOf(report.id);
  assert.equal(card.report.live, true);
  assert.equal(card.report.pendingFreeChange, true);
  assert.equal(Object.hasOwn(card, "changesUnreadable"), false);
  assert.equal(card.changes.length, 1, "one block moved");
  const [change] = card.changes;
  assert.equal(change.blockId, "b2");
  assert.equal(change.change, "changed");
  assert.equal(change.kind, "free");
  assert.deepEqual(change.before, RECIPE.blocks[1].settings, "the settings the owner sealed");
  assert.deepEqual(change.after, FREE_EDIT.blocks[1].settings, "the settings Apply would put under it");

  // Nothing is pending on a report the bot has not touched, so there is nothing to Apply.
  const untouched = await liveReport();
  const plain = await cardOf(untouched.id);
  assert.deepEqual(plain.changes, []);
  assert.equal(plain.report.pendingFreeChange, false);
});

test("card view shows a source change as kind source, and a custom step as kind custom", async () => {
  const report = await liveReport();
  const recipe = {
    blocks: [
      { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=2" } },
      { id: "b2", type: "filter", settings: { field: "title", op: "exists" } },
      { id: "step", type: "custom", settings: { step: "fetch_prices" } },
    ],
  };
  await botSaveRecipe(db, deps, { reportId: report.id, recipe });
  // A source change does not land `pending_free_change` on its own; the card's classification is what
  // this test is about, so the flag is set the way a report already carrying it would read.
  await updateReportColumns(db, report.id, { pending_free_change: 1 });

  const card = await cardOf(report.id);
  const byId = new Map(card.changes.map((change) => [change.blockId, change]));
  assert.equal(byId.get("b1").kind, "source", "a source block is never shown as free");
  assert.equal(byId.get("b1").change, "changed");
  assert.deepEqual(byId.get("b1").after, { url: "https://api.example.com/items?page=2" });
  assert.equal(byId.get("step").kind, "custom");
  assert.equal(byId.get("step").change, "added");
  assert.equal(byId.get("step").before, null, "nothing on the sealed side");
  assert.deepEqual(byId.get("step").after, { step: "fetch_prices" });
  assert.equal(card.changes.some((change) => change.kind === "free"), false);
});

test("a source-bearing shape block is shown as a source change", async () => {
  /** A recipe whose `enrich_lookup` block is a shape block that READS another source. */
  const enrichRecipe = (extra = {}) => ({
    blocks: [
      { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=1" } },
      { id: "b2", type: "filter", settings: { field: "title", op: "exists" } },
      {
        id: "b3",
        type: "enrich_lookup",
        settings: { source: "b1", joinField: "id", lookupKey: "id", fields: ["title"], ...extra },
      },
    ],
  });
  const report = await liveReport({ recipe: enrichRecipe() });
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: enrichRecipe({ prefix: "lookup_" }) });
  // A source-bearing change never lands `pending_free_change` on its own; the classification is what
  // this test is about, so the flag is set the way a report already carrying it would read.
  await updateReportColumns(db, report.id, { pending_free_change: 1 });

  const card = await cardOf(report.id);
  const entry = card.changes.find((change) => change.blockId === "b3");
  assert.equal(entry.type, "enrich_lookup");
  assert.equal(entry.change, "changed");
  assert.equal(entry.kind, "source", "a shape block that reads another source is never shown as free");
  assert.equal(entry.after.prefix, "lookup_");
  assert.equal(Object.hasOwn(entry.before, "prefix"), false, "the sealed side names no prefix");
});

test("an emptyText-only change shows on the card and changes the hash", async () => {
  const report = await liveReport();
  const saved = await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { ...RECIPE, emptyText: "Nothing new this week." },
  });
  assert.equal(saved.pendingFreeChange, true, "a top-level recipe key is a free change");

  const card = await cardOf(report.id);
  assert.equal(card.headRev, saved.rev);
  assert.equal(card.report.liveRev, report.rev);
  const recipeEntries = card.changes.filter((change) => change.type === "recipe");
  assert.equal(recipeEntries.length, 1, "one entry for the one key that moved");
  const [entry] = recipeEntries;
  assert.equal(entry.blockId, null, "a recipe key belongs to no block");
  assert.equal(entry.kind, "free");
  assert.equal(entry.change, "changed");
  assert.deepEqual(entry.before, { emptyText: null }, "the sealed recipe names no empty text");
  assert.deepEqual(entry.after, { emptyText: "Nothing new this week." });
  assert.equal(card.changes.some((change) => change.blockId !== null), false, "no block moved");

  const hashes = await recipeHashes(report.id, card.headRev, card.report.liveRev);
  assert.equal(card.changesHash, changesHashOf(card.headRev, card.report.liveRev, card.changes, hashes),
    "the recipe-level entry is part of the digest the card is drawn from");
  assert.notEqual(card.changesHash,
    changesHashOf(card.headRev, card.report.liveRev, [], hashes),
    "a diff without the recipe-level entry is a different digest");
});

test("a block reorder shows on the card and changes the hash", async () => {
  const report = await liveReport();
  const saved = await botSaveRecipe(db, deps, {
    reportId: report.id,
    recipe: { blocks: [RECIPE.blocks[1], RECIPE.blocks[0]] },
  });
  assert.equal(saved.pendingFreeChange, true, "the same source-bearing blocks, in another order");

  const card = await cardOf(report.id);
  assert.equal(card.changes.length, 1, "the reorder is the one thing that changed");
  const [entry] = card.changes;
  assert.equal(entry.blockId, null);
  assert.equal(entry.type, "order");
  assert.equal(entry.kind, "free");
  assert.equal(entry.change, "changed");
  assert.deepEqual(entry.before, { order: ["b1", "b2"] }, "the order the owner sealed");
  assert.deepEqual(entry.after, { order: ["b2", "b1"] }, "the order Apply would put under it");

  const hashes = await recipeHashes(report.id, card.headRev, card.report.liveRev);
  assert.equal(card.changesHash, changesHashOf(card.headRev, card.report.liveRev, card.changes, hashes));
  assert.notEqual(card.changesHash, changesHashOf(card.headRev, card.report.liveRev, [], hashes),
    "the same two revisions with no order entry is a different digest");

  // An unchanged order has no entry at all, whatever else the save did.
  const plain = await liveReport();
  await botSaveRecipe(db, deps, { reportId: plain.id, recipe: FREE_EDIT });
  const quiet = await cardOf(plain.id);
  assert.equal(quiet.changes.some((change) => change.type === "order"), false);
  assert.equal(quiet.changes.some((change) => change.type === "recipe"), false, "no key moved either");
});

/* ---------------------------------------------------------------- what it must never carry */

test("card view has no seal, nonce, token or secret", async () => {
  const report = await liveReport();
  // A recipient approval.
  const proposed = await proposeRecipient(db, deps, {
    reportId: report.id, address: "sam@example.com", proposedBy: "owner",
  });
  await approveRecipient(db, deps, { recipientId: proposed.id, actor: OWNER_ACTOR });
  // An approved host holding an approval, and a second host whose binding is what the card lists: it
  // names a real keychain row, whose secret the card never reads.
  await proposeHost(db, deps, { reportId: report.id, host: "api.example.com" });
  await approveHost(db, deps, { reportId: report.id, host: "api.example.com", actor: OWNER_ACTOR });
  await proposeCredential(db, deps, {
    reportId: report.id,
    host: "api.example.com",
    connectionUuid: APPROVED_UUID,
    inject: RULE,
    proposedBy: "owner",
  });
  await approveCredential(db, deps, {
    reportId: report.id,
    host: "api.example.com",
    connectionUuid: APPROVED_UUID,
    injectHash: injectHashOf(RULE),
    actor: OWNER_ACTOR,
  });
  await proposeHost(db, deps, { reportId: report.id, host: "api2.example.com" });
  await approveHost(db, deps, { reportId: report.id, host: "api2.example.com", actor: OWNER_ACTOR });
  await saveServiceSecret(db, keychainKey, {
    connectionUuid: UUID,
    bundleId: REPORTS_BUNDLE,
    envKey: "REPORT_CREDENTIAL",
    label: "report credential",
    secret: CREDENTIAL_SECRET,
  });
  await proposeCredential(db, deps, {
    reportId: report.id,
    host: "api2.example.com",
    connectionUuid: UUID,
    inject: RULE,
    proposedBy: "bot:bot-1",
  });
  // A proposed step and a host still waiting, so a step's own row is in the tables too.
  await proposeStep(db, deps, {
    reportId: report.id,
    stepKey: "prices",
    language: "node",
    entry: "main.js",
    files: { "main.js": "console.log(1)\n" },
    proposedBy: "bot:bot-1",
  });
  await proposeHost(db, deps, { reportId: report.id, host: "*.example.org" });

  const answer = await get(cardPath(report.id));
  assert.equal(answer.status, 200, answer.text);
  const card = answer.json.card;
  const stored = await getReport(db, report.id);
  assert.match(stored.live_seal, /^[0-9a-f]{64}$/);
  assert.match(stored.live_nonce, /^[0-9a-f]{32}$/);

  const recipientSeal = (await db.execute({
    sql: "SELECT approval_seal, approval_nonce FROM report_recipients WHERE report_id = ?",
    args: [report.id],
  })).rows[0];
  const credentialSeal = (await db.execute({
    sql: "SELECT approval_seal, approval_nonce FROM report_credentials WHERE report_id = ? AND state = 'approved'",
    args: [report.id],
  })).rows[0];
  assert.match(recipientSeal.approval_seal, /^[0-9a-f]{64}$/, "the recipient really carries a seal");
  assert.match(credentialSeal.approval_seal, /^[0-9a-f]{64}$/, "the credential really carries one too");
  const opened = await serviceSecretsFor(db, keychainKey, UUID, { allowedKeys: ["REPORT_CREDENTIAL"] });
  assert.equal(opened.REPORT_CREDENTIAL, CREDENTIAL_SECRET, "the keychain row really holds the secret");

  for (const value of [
    stored.live_seal,
    stored.live_nonce,
    recipientSeal.approval_seal,
    recipientSeal.approval_nonce,
    credentialSeal.approval_seal,
    credentialSeal.approval_nonce,
    CREDENTIAL_SECRET,
  ]) {
    assert.equal(answer.text.includes(value), false, "no sealed value in the answer");
  }
  for (const word of ["live_seal", "live_nonce", "approval_seal", "approval_nonce", "secret_sealed"]) {
    assert.equal(answer.text.includes(word), false, `no ${word} column in the answer`);
  }

  // What it does carry: the people, the sites, the step's diff and the credential's rule.
  assert.deepEqual(card.recipients.map((row) => [row.address, row.state]), [["sam@example.com", "approved"]]);
  assert.deepEqual(card.hosts, [{ host: "*.example.org", notice: HOST_APPROVAL_LINE }]);
  assert.equal(card.steps.length, 1);
  assert.equal(card.steps[0].stepKey, "prices");
  assert.equal(card.steps[0].files[0].path, "main.js");
  assert.equal(card.steps[0].files[0].status, "added");
  assert.deepEqual(card.steps[0].files[0].lines.map((line) => line.op), ["+"]);
  assert.equal(card.credentials.length, 1);
  assert.equal(card.credentials[0].connectionUuid, UUID);
  assert.deepEqual(card.credentials[0].inject, {
    header: "Authorization",
    format: "Bearer {}",
    pathPrefixes: ["/v1/issues"],
    methods: ["GET", "HEAD"],
  });
  assert.match(card.credentials[0].injectHash, /^[0-9a-f]{64}$/);
});

test("card view names the sender account", async () => {
  const report = await makeReport();
  const account = await createAccount(db, {
    label: "Alex",
    address: "alex@example.com",
    authKind: "password",
    imap: ACCOUNT,
    smtp: { ...ACCOUNT, port: 465 },
  });
  await updateReportColumns(db, report.id, { sender_account_id: account.id });

  const card = await cardOf(report.id);
  assert.deepEqual(card.sender, {
    accountId: account.id,
    address: "alex@example.com",
    kind: "crow_mail",
  });

  // A report with no sender names none.
  await updateReportColumns(db, report.id, { sender_account_id: null });
  assert.equal((await cardOf(report.id)).sender, null);

  // The transport a reports-only Google account is marked with is read through the injected reader.
  await updateReportColumns(db, report.id, { sender_account_id: account.id });
  const row = await getReport(db, report.id);
  const gmail = await buildReportCardView(db, {
    ...deps,
    getAccount: async (_db, accountId) => ({ id: accountId, address: "reports@example.com", transport: "gmail_api" }),
  }, row);
  assert.deepEqual(gmail.sender, {
    accountId: account.id,
    address: "reports@example.com",
    kind: "google_reports",
  });
});

test("card view preview is current only for the head revision", async () => {
  const report = await liveReport();
  assert.equal((await cardOf(report.id)).preview, null, "no preview run yet");

  await addPreviewRun("rrn-0000000000000001", report.id, "ok", report.rev, T0 + 1);
  let card = await cardOf(report.id);
  assert.deepEqual(card.preview, {
    runId: "rrn-0000000000000001", status: "ok", recipeRev: report.rev, current: true,
  });

  // A later head revision makes that preview a preview of something else.
  await ownerSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT, actor: OWNER_ACTOR });
  const headRev = Number((await getReport(db, report.id)).recipe_rev);
  card = await cardOf(report.id);
  assert.equal(card.preview.runId, "rrn-0000000000000001", "still the newest preview");
  assert.equal(card.preview.recipeRev, report.rev);
  assert.equal(card.preview.current, false, "of a revision the report no longer holds");

  // An empty preview of the head is current; a failed one is not.
  await addPreviewRun("rrn-0000000000000002", report.id, "empty", headRev, T0 + 2);
  card = await cardOf(report.id);
  assert.deepEqual(card.preview, {
    runId: "rrn-0000000000000002", status: "empty", recipeRev: headRev, current: true,
  });
  await addPreviewRun("rrn-0000000000000003", report.id, "failed", headRev, T0 + 3);
  card = await cardOf(report.id);
  assert.equal(card.preview.runId, "rrn-0000000000000003");
  assert.equal(card.preview.current, false, "a failed preview approves nothing");

  // A full run of the head revision is not a preview.
  const second = await liveReport();
  await addPreviewRun("rrn-0000000000000004", second.id, "ok", second.rev, T0 + 4, "manual");
  assert.equal((await cardOf(second.id)).preview, null);
});

/* ------------------------------------------------------------------------- the apply route */

/** The two fields an Apply carries: the head revision and the diff digest the card was drawn from. */
function applyBody(card) {
  return { expectedRev: card.headRev, changesHash: card.changesHash };
}

test("apply route: owner only, and a pending free change is re-stamped and cleared", async () => {
  const report = await liveReport();
  const path = `${REPORTS_API_PREFIX}/${report.id}/apply`;
  const firstCard = await cardOf(report.id);

  ownerAllowed = false;
  try {
    const refused = await post(path, applyBody(firstCard));
    assert.equal(refused.status, 403, refused.text);
    assert.deepEqual(refused.json, { error: "owner_only", message: "Only the owner can see this." });
    assert.equal(refused.text.includes(report.id), false, "no id in the answer");
  } finally {
    ownerAllowed = true;
  }

  // Nothing pending: the module's own refusal, and nothing written. The body is the one this report's
  // card carries, so the 400 is the module's (no pending change), not the route's own validation.
  const nothing = await post(path, applyBody(await cardOf(report.id)));
  assert.equal(nothing.status, 400, nothing.text);
  assert.deepEqual(nothing.json, { error: "bad_input", message: "That request is not valid." });
  assert.equal(Number((await getReport(db, report.id)).pending_free_change), 0);

  // A bot's free change: one owner tap re-stamps the live seal at the head and clears the flag.
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT });
  assert.equal(saved.pendingFreeChange, true);
  const applied = await post(path, applyBody(await cardOf(report.id)));
  assert.equal(applied.status, 200, applied.text);
  assert.deepEqual(applied.json, { ok: true, liveRev: saved.rev });
  const after1 = await getReport(db, report.id);
  assert.equal(Number(after1.pending_free_change), 0);
  assert.equal(Number(after1.live_rev), saved.rev);
  assert.equal(await isLive(db, deps, after1), true);

  // A change that moved a source is never applied: 409 go_live_needed.
  const second = await liveReport();
  await botSaveRecipe(db, deps, { reportId: second.id, recipe: SOURCE_EDIT });
  await updateReportColumns(db, second.id, { pending_free_change: 1 });
  const refused = await post(`${REPORTS_API_PREFIX}/${second.id}/apply`, applyBody(await cardOf(second.id)));
  assert.equal(refused.status, 409, refused.text);
  assert.deepEqual(refused.json, { error: "go_live_needed", message: "Preview and go live again." });
  assert.equal(Number((await getReport(db, second.id)).live_rev), second.rev, "nothing was re-stamped");
  assert.equal(Number((await getReport(db, second.id)).pending_free_change), 1);

  // A report that is not live needs a go-live, whatever is pending.
  const paused = await liveReport();
  await botSaveRecipe(db, deps, { reportId: paused.id, recipe: FREE_EDIT });
  await updateReportColumns(db, paused.id, { pending_free_change: 1, status: "paused" });
  const notLive = await post(`${REPORTS_API_PREFIX}/${paused.id}/apply`, applyBody(await cardOf(paused.id)));
  assert.equal(notLive.status, 409, notLive.text);
  assert.equal(notLive.json.error, "go_live_needed");

  // A well-formed id that names no report is a 404.
  const missing = await post(`${REPORTS_API_PREFIX}/rpt-ffffffffffffffff/apply`, {
    expectedRev: 1, changesHash: "a".repeat(64),
  });
  assert.equal(missing.status, 404, missing.text);
  assert.deepEqual(missing.json, { error: "not_found", message: "Not found." });
});

test("apply refuses when a bot saves again after the card was read", async () => {
  const report = await liveReport();
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT });
  assert.equal(saved.pendingFreeChange, true);
  const card = await cardOf(report.id);
  assert.equal(card.changes.length, 1);

  // The bot saves again between the card read and the tap: another free edit, a newer head.
  const again = {
    blocks: [
      RECIPE.blocks[0],
      { id: "b2", type: "filter", settings: { field: "title", op: "ne", value: "sold" } },
    ],
  };
  const moved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: again });
  assert.equal(moved.pendingFreeChange, true);
  assert.equal(moved.rev, card.headRev + 1);

  const refused = await post(`${REPORTS_API_PREFIX}/${report.id}/apply`, applyBody(card));
  assert.equal(refused.status, 409, refused.text);
  assert.deepEqual(refused.json, { error: "conflict", message: CONFLICT });
  const row = await getReport(db, report.id);
  assert.equal(Number(row.live_rev), report.rev, "live_rev unchanged");
  assert.equal(Number(row.pending_free_change), 1);
});

test("apply needs expectedRev and changesHash", async () => {
  const report = await liveReport();
  const path = `${REPORTS_API_PREFIX}/${report.id}/apply`;
  const card = await cardOf(report.id);
  const bodies = [
    undefined,
    {},
    { expectedRev: card.headRev },
    { changesHash: card.changesHash },
    { expectedRev: String(card.headRev), changesHash: card.changesHash },
    { expectedRev: card.headRev, changesHash: "not-a-hash" },
  ];
  for (const body of bodies) {
    const refused = await post(path, body);
    assert.equal(refused.status, 400, `${JSON.stringify(body)}: ${refused.text}`);
    assert.deepEqual(refused.json, { error: "bad_input", message: "That request is not valid." });
  }
  assert.equal(Number((await getReport(db, report.id)).live_rev), report.rev);
});

test("apply refuses a hash that does not match the diff", async () => {
  const report = await liveReport();
  await botSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT });
  const card = await cardOf(report.id);
  assert.match(card.changesHash, /^[0-9a-f]{64}$/);

  const refused = await post(`${REPORTS_API_PREFIX}/${report.id}/apply`, {
    expectedRev: card.headRev, changesHash: "b".repeat(64),
  });
  assert.equal(refused.status, 409, refused.text);
  assert.deepEqual(refused.json, { error: "conflict", message: CONFLICT });
  const row = await getReport(db, report.id);
  assert.equal(Number(row.live_rev), report.rev, "nothing was re-stamped");
  assert.equal(Number(row.pending_free_change), 1);
});

test("a truncated diff refuses apply", async () => {
  const report = await liveReport();
  const blocks = [RECIPE.blocks[0], RECIPE.blocks[1]];
  // One entry past the settings bound, then enough free blocks to overflow the card's change list.
  blocks.push({
    id: "big",
    type: "filter",
    settings: { field: "title", op: "exists", note: "x".repeat(17 * 1024) },
  });
  for (let i = 0; i < 41; i += 1) {
    blocks.push({ id: `f${i}`, type: "filter", settings: { field: "title", op: "exists", tag: `t${i}` } });
  }
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: { blocks } });
  assert.equal(saved.pendingFreeChange, true);

  const card = await cardOf(report.id);
  assert.equal(card.changesTruncated, true);
  assert.equal(card.changes.length, 40, "the card lists only what fits");
  assert.equal(card.changes.some((change) => change.truncated === true), true,
    "the oversized entry says its settings were cut");
  assert.notEqual(card.changesHash,
    changesHashOf(card.headRev, card.report.liveRev, card.changes,
      await recipeHashes(report.id, card.headRev, card.report.liveRev)),
    "the digest is of the whole diff, never of the cut list");

  const refused = await post(`${REPORTS_API_PREFIX}/${report.id}/apply`, applyBody(card));
  assert.equal(refused.status, 409, refused.text);
  assert.deepEqual(refused.json, { error: "conflict", message: CONFLICT });
  const row = await getReport(db, report.id);
  assert.equal(Number(row.live_rev), report.rev, "nothing was re-stamped");
  assert.equal(Number(row.pending_free_change), 1);
});

test("apply with the matching rev and hash re-stamps that revision", async () => {
  const report = await liveReport();
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: FREE_EDIT });
  const card = await cardOf(report.id);
  assert.equal(card.headRev, saved.rev);
  assert.equal(card.changesHash,
    changesHashOf(card.headRev, card.report.liveRev, card.changes,
      await recipeHashes(report.id, card.headRev, card.report.liveRev)),
    "a diff the card carries whole hashes to the same digest");

  const applied = await post(`${REPORTS_API_PREFIX}/${report.id}/apply`, applyBody(card));
  assert.equal(applied.status, 200, applied.text);
  assert.deepEqual(applied.json, { ok: true, liveRev: card.headRev });
  const row = await getReport(db, report.id);
  assert.equal(Number(row.live_rev), card.headRev, "the revision the card showed");
  assert.equal(Number(row.pending_free_change), 0);
  assert.equal(await isLive(db, deps, row), true);
});

/* -------------------------------------------------------------------- the go-live tap */

test("go-live refuses a sender that is not the one the card showed", async () => {
  const report = await previewedReport();
  const account = await createAccount(db, {
    label: "Sender",
    address: "sender@example.com",
    authKind: "password",
    imap: ACCOUNT,
    smtp: { ...ACCOUNT, port: 465 },
  });
  await updateReportColumns(db, report.id, { sender_account_id: account.id });
  const card = await cardOf(report.id);
  assert.equal(card.sender.accountId, account.id);

  // The row's sender moves after the card was read: the tap was over another sender than this report.
  await updateReportColumns(db, report.id, { sender_account_id: "ma-8899aabbccddeeff" });
  const refused = await post(`${REPORTS_API_PREFIX}/${report.id}/go-live`, {
    previewRunId: report.runId,
    expectedSenderAccountId: card.sender.accountId,
  });
  assert.equal(refused.status, 409, refused.text);
  assert.deepEqual(refused.json, { error: "conflict", message: CONFLICT });
  const row = await getReport(db, report.id);
  assert.equal(row.status, "draft", "nothing was sealed");
  assert.equal(row.live_seal, null);
  assert.equal(row.live_rev, null);
});

test("go-live needs expectedSenderAccountId", async () => {
  const report = await previewedReport();
  const path = `${REPORTS_API_PREFIX}/${report.id}/go-live`;
  for (const body of [
    { previewRunId: report.runId },
    {},
    { previewRunId: report.runId, expectedSenderAccountId: 7 },
    { previewRunId: report.runId, expectedSenderAccountId: null },
  ]) {
    const refused = await post(path, body);
    assert.equal(refused.status, 400, `${JSON.stringify(body)}: ${refused.text}`);
    assert.deepEqual(refused.json, { error: "bad_input", message: "That request is not valid." });
  }
  const untouched = await getReport(db, report.id);
  assert.equal(untouched.status, "draft", "nothing was sealed");
  assert.equal(untouched.live_seal, null);

  // The sender the card showed goes live; a report the card showed no sender for is bound to "".
  const live = await post(path, { previewRunId: report.runId, expectedSenderAccountId: SENDER });
  assert.equal(live.status, 200, live.text);
  assert.deepEqual(live.json, { ok: true, liveRev: report.rev });

  const none = await previewedReport();
  await updateReportColumns(db, none.id, { sender_account_id: null });
  const noSender = await post(`${REPORTS_API_PREFIX}/${none.id}/go-live`, {
    previewRunId: none.runId,
    expectedSenderAccountId: "",
  });
  assert.equal(noSender.status, 409, noSender.text);
  assert.equal(noSender.json.error, "sender_not_ready", "the empty string is the sender the card showed");
});

/* ------------------------------------------------------------------------ source hashes */

test("approve source with a stale settings hash refuses", async () => {
  const report = await makeReport({ title: "Sources", authorKind: "bot" });
  const card = await cardOf(report.id);
  assert.equal(card.sources.length, 1);
  const [source] = card.sources;
  assert.equal(source.blockId, "b1");

  // A bot saves again after the card was read: the head settings are not the ones the card showed.
  const moved = {
    blocks: [
      { id: "b1", type: "http_json", settings: { url: "https://api.example.com/items?page=9" } },
      RECIPE.blocks[1],
    ],
  };
  const saved = await botSaveRecipe(db, deps, { reportId: report.id, recipe: moved });
  assert.equal(saved.rev, report.rev + 1);

  const refused = await post(`${REPORTS_API_PREFIX}/${report.id}/sources/b1/approve`, {
    settingsHash: source.settingsHash,
  });
  assert.equal(refused.status, 409, refused.text);
  assert.deepEqual(refused.json, {
    error: "source_changed",
    message: "That report changed while this request was in flight. Try again.",
  });
  assert.equal(await getState(db, report.id, "source_approval:b1"), null, "nothing was sealed");
});

/* ------------------------------------------------------------------------- the two rails */

test("card route and chat list are owner only and no-store", async () => {
  const report = await makeReport();
  const sid = "perchlive-cardowner1";
  await setState(db, report.id, "chat_thread", sid);
  const listPath = `${PERCH}/interactive/${sid}/reports`;

  ownerAllowed = false;
  try {
    const card = await get(cardPath(report.id));
    assert.equal(card.status, 403, card.text);
    assert.deepEqual(card.json, { error: "owner_only", message: "Only the owner can see this." });
    assert.equal(card.text.includes(report.id), false, "no id for a non-owner");
    const list = await get(listPath);
    assert.equal(list.status, 403, list.text);
    assert.deepEqual(list.json, { error: "owner_only" });
    assert.equal(list.text.includes(report.id), false);
  } finally {
    ownerAllowed = true;
  }

  const card = await get(cardPath(report.id));
  assert.equal(card.status, 200, card.text);
  assert.equal(card.headers["cache-control"], "no-store");
  const list = await get(listPath);
  assert.equal(list.status, 200, list.text);
  assert.equal(list.headers["cache-control"], "no-store");
  assert.deepEqual(list.json, { reports: [{ id: report.id }] });

  // A malformed id is a 404 on the card route too, like every other path id here.
  for (const id of ["rpt-xyz", "rpt-0123456789abcdef0", "not-a-report"]) {
    const answer = await get(`${REPORTS_API_PREFIX}/${id}/card`);
    assert.equal(answer.status, 404, `${id}: ${answer.text}`);
    assert.deepEqual(answer.json, { error: "not_found", message: "Not found." });
  }
  const missing = await get(cardPath("rpt-ffffffffffffffff"));
  assert.equal(missing.status, 404, missing.text);
});

test("chat list returns the reports whose chat_thread is this sid, and only those", async () => {
  const sid = "perchlive-card0001";
  const first = await makeReport({ title: "First" });
  const second = await makeReport({ title: "Second" });
  const elsewhere = await makeReport({ title: "Elsewhere" });
  const unattached = await makeReport({ title: "Unattached" });
  await setState(db, first.id, "chat_thread", sid);
  await setState(db, second.id, "chat_thread", sid);
  await setState(db, elsewhere.id, "chat_thread", "perchlive-other0001");
  // The list is newest report first; the store's own clock is not the thing under test.
  await db.execute({ sql: "UPDATE reports SET created_at = ? WHERE id = ?", args: [T0 + 1, first.id] });
  await db.execute({ sql: "UPDATE reports SET created_at = ? WHERE id = ?", args: [T0 + 2, second.id] });
  await db.execute({ sql: "UPDATE reports SET created_at = ? WHERE id = ?", args: [T0 + 3, elsewhere.id] });
  await db.execute({ sql: "UPDATE reports SET created_at = ? WHERE id = ?", args: [T0 + 4, unattached.id] });

  const answer = await get(`${PERCH}/interactive/${sid}/reports`);
  assert.equal(answer.status, 200, answer.text);
  assert.deepEqual(answer.json.reports, [{ id: second.id }, { id: first.id }], "this chat's, newest first");
  for (const row of answer.json.reports) {
    assert.deepEqual(Object.keys(row), ["id"], "ids only: the card reads each report from its own route");
  }
  assert.equal(answer.text.includes(elsewhere.id), false);
  assert.equal(answer.text.includes(unattached.id), false);

  // A sid of another shape names no chat.
  for (const bad of ["bad sid", "a".repeat(121), "perch/../live"]) {
    const refused = await get(`${PERCH}/interactive/${encodeURIComponent(bad)}/reports`);
    assert.equal(refused.status, 404, `${bad}: ${refused.text}`);
    assert.deepEqual(refused.json, { error: "not_found" });
  }
});