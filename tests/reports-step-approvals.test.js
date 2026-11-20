// Crow Recurring Reports' custom steps: propose, approve, refuse, revoke, verify, the newest-revision
// rule, the diff an owner reads, and the bundle hash's framing.
//
// Harness: a real init-db'd scratch crow.db, copied per test (CROW_DATA_DIR under a temp dir, so nothing
// can touch a real Crow data dir), real report rows, a fixed keychain seed injected through
// `deps.loadSeed`, and a CROW_HOME under the same temp dir so an asset file is written and swapped for
// real. Raw rows are read back where a test is about what a column holds (a NULL seal, a stored nonce).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-step-approvals-"));
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
  ASSET_MAX_BYTES, STEP_MAX_BUNDLE_BYTES, STEP_MAX_FILES, approveStep, bundleHashOf, listStepsForPage,
  newestStep, proposeStep, refuseStep, removeAsset, revokeStep, runnableStep, saveAsset, stepDetail,
  stepDiff, verifyAssetOnDisk, verifyStep,
} = await import("../servers/gateway/reports/steps.js");
const { createReport } = await import("../servers/gateway/reports/store.js");

const OWNER = Object.freeze({ kind: "owner" });
const BOT_ACTOR = Object.freeze({ kind: "bot" });
const SEED = Buffer.alloc(32, 23);
const T0 = 1_700_000_000_000;

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

function deps(over = {}) {
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    crowHome: HOME,
    ...over,
  };
}

async function makeReport(db) {
  const { id } = await createReport(db, { projectId: 7, owner: "owner", botId: "bot-1", title: "Weekly listings" });
  return id;
}

const FILES = Object.freeze({
  "run.py": "print('hello')\n",
  "templates/report.html": "<h1>{{ title }}</h1>\n",
});

async function propose(db, reportId, over = {}) {
  return proposeStep(db, deps(), {
    reportId,
    stepKey: "fetch",
    language: "python",
    entry: "run.py",
    files: FILES,
    requirements: "jinja2==3.1.4\n",
    proposedBy: "owner",
    ...over,
  });
}

async function storedStep(db, reportId, stepKey, rev) {
  const { rows } = await db.execute({
    sql: "SELECT * FROM report_custom_steps WHERE report_id = ? AND step_key = ? AND rev = ?",
    args: [reportId, stepKey, rev],
  });
  return rows[0];
}

async function auditRows(db, reportId) {
  const { rows } = await db.execute({
    sql: "SELECT kind, subject, actor, decided FROM report_approvals_audit WHERE report_id = ? ORDER BY id",
    args: [reportId],
  });
  return rows;
}

/** An approved revision, through the real approve path. */
async function approvedStep(db, reportId, over = {}) {
  const proposed = await propose(db, reportId, over);
  return approveStep(db, deps(), {
    reportId, stepKey: proposed.stepKey, rev: proposed.rev, bundleHash: proposed.bundleHash, actor: OWNER,
  });
}

/* ------------------------------------------------------------------------- the hash */

test("the bundle hash frames every value: a re-cut path and content cannot collide", () => {
  const assetHashes = [{ name: "data.json", sha256: "a".repeat(64) }];
  const one = bundleHashOf({ files: { ab: "c" }, requirements: "", assetHashes });
  const two = bundleHashOf({ files: { a: "bc" }, requirements: "", assetHashes });
  assert.notEqual(one, two, "a longer path with a shorter file is a different bundle");

  const three = bundleHashOf({ files: { a: "b", c: "d" }, requirements: "", assetHashes });
  const four = bundleHashOf({ files: { a: "bc", d: "" }, requirements: "", assetHashes });
  assert.notEqual(three, four);

  // A requirements text that looks like a file list stays the requirements text.
  const asFiles = bundleHashOf({ files: { run: "x" }, requirements: "", assetHashes: [] });
  const asText = bundleHashOf({ files: {}, requirements: "run", assetHashes: [] });
  assert.notEqual(asFiles, asText);

  // Deterministic and order-insensitive.
  assert.equal(bundleHashOf({ files: FILES, requirements: "r", assetHashes }), bundleHashOf({ files: { ...FILES }, requirements: "r", assetHashes }));
  assert.equal(
    bundleHashOf({ files: { b: "1", a: "2" }, requirements: "" }),
    bundleHashOf({ files: { a: "2", b: "1" }, requirements: "" }),
  );
  // A second bound asset changes the hash even when the files do not.
  assert.notEqual(
    bundleHashOf({ files: FILES, requirements: "", assetHashes: [] }),
    bundleHashOf({ files: FILES, requirements: "", assetHashes }),
  );
});

/* -------------------------------------------------------------------- the proposal */

test("a proposal is stored proposed, hashed, and approves nothing", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);

  const step = await propose(db, reportId);
  assert.equal(step.reportId, reportId);
  assert.equal(step.stepKey, "fetch");
  assert.equal(step.rev, 1);
  assert.equal(step.language, "python");
  assert.equal(step.entry, "run.py");
  assert.equal(step.state, "proposed");
  assert.equal(step.proposedBy, "owner");
  assert.equal(step.approvedAt, null);
  assert.equal(step.createdAt, T0);
  assert.match(step.bundleHash, /^[0-9a-f]{64}$/);
  assert.deepEqual(step.assets, []);
  assert.deepEqual(step.files.map((f) => f.path), ["run.py", "templates/report.html"]);
  assert.ok(!("contents" in step), "the list view carries no file text");
  assert.ok(!("approvalSeal" in step) && !("approval_seal" in step), "no seal in the answer");

  const raw = await storedStep(db, reportId, "fetch", 1);
  assert.equal(raw.approval_seal, null, "a proposal carries no seal");
  assert.equal(raw.approval_nonce, null);
  assert.equal(raw.bundle_hash, step.bundleHash);
  assert.equal(await verifyStep(db, deps(), raw), false, "a proposal is not an approval");
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });

  const second = await propose(db, reportId, { files: { "run.py": "print('hi')\n" } });
  assert.equal(second.rev, 2, "a proposal of the same key is the next revision");
});

test("approve seals the bundle and the runnable step carries the files", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const approved = await approvedStep(db, reportId);

  assert.equal(approved.state, "approved");
  assert.equal(approved.verified, true);
  assert.equal(approved.approvedAt, T0);
  assert.deepEqual(approved.contents.map((f) => f.path), ["run.py", "templates/report.html"]);

  const raw = await storedStep(db, reportId, "fetch", 1);
  assert.match(raw.approval_nonce, /^[0-9a-f]{32}$/);
  assert.match(raw.approval_seal, /^[0-9a-f]{64}$/);
  assert.equal(await verifyStep(db, deps(), raw), true);

  const runnable = await runnableStep(db, deps(), reportId, "fetch");
  assert.equal(runnable.ok, true, JSON.stringify(runnable));
  assert.equal(runnable.step.stepKey, "fetch");
  assert.equal(runnable.step.rev, 1);
  assert.equal(runnable.step.entry, "run.py");
  assert.equal(runnable.step.requirements, "jinja2==3.1.4\n");
  assert.equal(runnable.step.files["run.py"], "print('hello')\n");
  assert.equal(runnable.step.files["templates/report.html"], "<h1>{{ title }}</h1>\n");

  assert.deepEqual(await auditRows(db, reportId), [
    { kind: "step", subject: "fetch:1", actor: "owner", decided: "approved" },
  ]);

  // A repeated tap is not a second approval.
  const again = await approveStep(db, deps(), {
    reportId, stepKey: "fetch", rev: 1, bundleHash: approved.bundleHash, actor: OWNER,
  });
  assert.equal(again.verified, true);
  assert.equal((await auditRows(db, reportId)).length, 1);
});

test("the newest revision is the one that runs: an older approval does not carry a newer proposal", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedStep(db, reportId);

  const proposed = await propose(db, reportId, { files: { "run.py": "print('changed')\n" } });
  assert.equal(proposed.rev, 2);
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" },
    "a newer unapproved revision stops the run even though rev 1 is approved");
  assert.equal(await verifyStep(db, deps(), await storedStep(db, reportId, "fetch", 1)), true,
    "rev 1's own seal still verifies");

  const approved = await approveStep(db, deps(), {
    reportId, stepKey: "fetch", rev: 2, bundleHash: proposed.bundleHash, actor: OWNER,
  });
  assert.equal(approved.verified, true);
  const runnable = await runnableStep(db, deps(), reportId, "fetch");
  assert.equal(runnable.ok, true);
  assert.equal(runnable.step.rev, 2);
  assert.equal(runnable.step.files["run.py"], "print('changed')\n");
  assert.equal((await newestStep(db, reportId, "fetch")).rev, 2);
});

/* -------------------------------------------------------- tampering after an approval */

test("a bundle file changed by a direct UPDATE is not run", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedStep(db, reportId);
  assert.equal((await runnableStep(db, deps(), reportId, "fetch")).ok, true);

  const raw = await storedStep(db, reportId, "fetch", 1);
  const envelope = JSON.parse(raw.files_json);
  envelope.files["run.py"] = "import os\nos.system('echo taken over')\n";
  await db.execute({
    sql: "UPDATE report_custom_steps SET files_json = ? WHERE report_id = ? AND step_key = ? AND rev = ?",
    args: [JSON.stringify(envelope), reportId, "fetch", 1],
  });

  const after = await storedStep(db, reportId, "fetch", 1);
  assert.equal(after.state, "approved", "the state word was never touched");
  assert.equal(await verifyStep(db, deps(), after), false, "the recomputed hash no longer matches the seal");
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });
  assert.equal((await listStepsForPage(db, reportId, deps()))[0].verified, false);
});

test("a requirements change after approval fails verification", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedStep(db, reportId);

  await db.execute({
    sql: "UPDATE report_custom_steps SET requirements = ? WHERE report_id = ? AND step_key = ? AND rev = ?",
    args: ["requests\n", reportId, "fetch", 1],
  });
  assert.equal(await verifyStep(db, deps(), await storedStep(db, reportId, "fetch", 1)), false);
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });
});

test("a language or entry changed by a direct UPDATE after approval is not run", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedStep(db, reportId);
  assert.equal((await runnableStep(db, deps(), reportId, "fetch")).ok, true);

  // The other file of the same approved bundle: the entry decides which one runs.
  await db.execute({
    sql: "UPDATE report_custom_steps SET entry = ? WHERE report_id = ? AND step_key = ? AND rev = ?",
    args: ["templates/report.html", reportId, "fetch", 1],
  });
  const movedEntry = await storedStep(db, reportId, "fetch", 1);
  assert.equal(movedEntry.entry, "templates/report.html", "the column really moved");
  assert.equal(await verifyStep(db, deps(), movedEntry), false, "the entry is under the seal");
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });
  assert.equal((await listStepsForPage(db, reportId, deps()))[0].verified, false);

  // The entry is still a file of the bundle, so only the seal can tell the two apart: put it back.
  await db.execute({
    sql: "UPDATE report_custom_steps SET entry = ? WHERE report_id = ? AND step_key = ? AND rev = ?",
    args: ["run.py", reportId, "fetch", 1],
  });
  assert.equal(await verifyStep(db, deps(), await storedStep(db, reportId, "fetch", 1)), true,
    "the same content is the same approval");

  // The runtime the entry is run in is sealed too.
  await db.execute({
    sql: "UPDATE report_custom_steps SET language = ? WHERE report_id = ? AND step_key = ? AND rev = ?",
    args: ["node", reportId, "fetch", 1],
  });
  const movedLanguage = await storedStep(db, reportId, "fetch", 1);
  assert.equal(movedLanguage.language, "node");
  assert.equal(await verifyStep(db, deps(), movedLanguage), false, "the language is under the seal");
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });
});

test("an asset swapped on disk after approval is not run", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const saved = await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: '[{"id":1}]' });
  assert.match(saved.sha256, /^[0-9a-f]{64}$/);
  assert.equal(saved.bytes, 10);
  await approvedStep(db, reportId, { assets: ["ways.json"] });
  assert.equal((await runnableStep(db, deps(), reportId, "fetch")).ok, true);

  const file = join(HOME, "reports", reportId, "assets", saved.sha256);
  writeFileSync(file, '[{"id":2}]');
  assert.equal(await verifyAssetOnDisk(deps(), {
    report_id: reportId, name: "ways.json", sha256: saved.sha256,
  }), false);
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" },
    "the row still verifies; the file on disk does not");
});

test("replacing an asset changes the hash of every step that binds it", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: "first" });
  await approvedStep(db, reportId, { assets: ["ways.json"] });
  assert.equal(await verifyStep(db, deps(), await storedStep(db, reportId, "fetch", 1)), true);

  await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: "second" });
  assert.equal(await verifyStep(db, deps(), await storedStep(db, reportId, "fetch", 1)), false,
    "the same asset name with different content is a different bundle");
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });

  // And a named asset that has no row at all fails closed too.
  await db.execute({
    sql: "DELETE FROM report_assets WHERE report_id = ? AND name = ?", args: [reportId, "ways.json"],
  });
  assert.equal(await verifyStep(db, deps(), await storedStep(db, reportId, "fetch", 1)), false);
});

/* ------------------------------------------------------------- refuse, revoke, owner */

test("refuse and revoke both NULL the seal and the nonce", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);

  const approved = await approvedStep(db, reportId);
  assert.ok((await storedStep(db, reportId, "fetch", 1)).approval_seal, "approved first");
  const refused = await refuseStep(db, deps(), { reportId, stepKey: "fetch", rev: 1, actor: OWNER });
  assert.equal(refused.state, "refused");
  assert.equal(refused.approvedAt, null);
  const afterRefuse = await storedStep(db, reportId, "fetch", approved.rev);
  assert.equal(afterRefuse.approval_seal, null);
  assert.equal(afterRefuse.approval_nonce, null);
  assert.equal(await verifyStep(db, deps(), afterRefuse), false);

  await approveStep(db, deps(), {
    reportId, stepKey: "fetch", rev: 1, bundleHash: approved.bundleHash, actor: OWNER,
  });
  const revoked = await revokeStep(db, deps(), { reportId, stepKey: "fetch", rev: 1, actor: OWNER });
  assert.equal(revoked.state, "revoked");
  const afterRevoke = await storedStep(db, reportId, "fetch", 1);
  assert.equal(afterRevoke.approval_seal, null);
  assert.equal(afterRevoke.approval_nonce, null);

  assert.deepEqual((await auditRows(db, reportId)).map((r) => r.decided),
    ["approved", "refused", "approved", "revoked"]);
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });

  // A revoked row flipped back to approved by direct SQL is still not an approval: the seal is NULL.
  await db.execute({
    sql: "UPDATE report_custom_steps SET state = 'approved' WHERE report_id = ? AND step_key = ? AND rev = 1",
    args: [reportId, "fetch"],
  });
  assert.equal(await verifyStep(db, deps(), await storedStep(db, reportId, "fetch", 1)), false);
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });
});

test("approve, refuse and revoke are owner only", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const proposed = await propose(db, reportId);

  for (const actor of [BOT_ACTOR, undefined, null, { kind: "system" }, "owner"]) {
    await assert.rejects(
      () => approveStep(db, deps(), { reportId, stepKey: "fetch", rev: proposed.rev, bundleHash: proposed.bundleHash, actor }),
      { code: "owner_only" }, String(actor),
    );
    await assert.rejects(
      () => refuseStep(db, deps(), { reportId, stepKey: "fetch", rev: proposed.rev, actor }),
      { code: "owner_only" },
    );
    await assert.rejects(
      () => revokeStep(db, deps(), { reportId, stepKey: "fetch", rev: proposed.rev, actor }),
      { code: "owner_only" },
    );
  }
  const raw = await storedStep(db, reportId, "fetch", 1);
  assert.equal(raw.state, "proposed", "nothing was written");
  assert.equal(raw.approval_seal, null);
  assert.deepEqual(await auditRows(db, reportId), []);
});

test("a re-proposal after a refusal needs a fresh approval", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedStep(db, reportId);
  await refuseStep(db, deps(), { reportId, stepKey: "fetch", rev: 1, actor: OWNER });

  const again = await propose(db, reportId, { files: { "run.py": "print('v2')\n" } });
  assert.equal(again.rev, 2);
  assert.equal(again.state, "proposed");
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });
});

/* ---------------------------------------------------------------- validation and caps */

test("path traversal, absolute paths and duplicate paths are refused", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const bad = [
    { files: { "../escape.py": "x" } },
    { files: { "/etc/passwd": "x" } },
    { files: { "a/../../escape.py": "x" } },
    { files: { "run.py": "x", "sub\\run.py": "y" } },
    { files: { "run.py\u0000.py": "x" } },
    { files: { "./run.py": "x" } },
    { files: { "dir/": "x" } },
    { files: { "": "x" } },
    { files: [] },
    { files: {} },
    { files: { "run.py": 42 } },
  ];
  for (const over of bad) {
    await assert.rejects(() => propose(db, reportId, over), { code: "bad_input" }, JSON.stringify(over));
  }
  const { rows } = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_custom_steps WHERE report_id = ?", args: [reportId],
  });
  assert.equal(Number(rows[0].n), 0, "nothing was stored");
});

test("the step key, the language, the entry and the requirements are validated", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  for (const stepKey of ["", "Fetch", "1fetch", "fetch!", "a".repeat(33), "-fetch"]) {
    await assert.rejects(() => propose(db, reportId, { stepKey }), { code: "bad_input" }, stepKey);
  }
  await assert.rejects(() => propose(db, reportId, { language: "ruby" }), { code: "bad_input" });
  await assert.rejects(() => propose(db, reportId, { entry: "missing.py" }), { code: "bad_input" },
    "the entry must be one of the files");
  await assert.rejects(() => propose(db, reportId, { entry: "/run.py" }), { code: "bad_input" });
  await assert.rejects(() => propose(db, reportId, { requirements: "a".repeat(64 * 1024 + 1) }),
    { code: "too_large" });
  await assert.rejects(() => propose(db, reportId, { proposedBy: "someone" }), { code: "bad_input" });
  await assert.rejects(
    () => propose(db, reportId, { proposedBy: undefined }),
    { code: "bad_input" },
    "a proposal always names who made it",
  );
  // The boundaries themselves are accepted.
  assert.equal((await propose(db, reportId, { stepKey: "a" })).rev, 1);
  assert.equal((await propose(db, reportId, { stepKey: "a-b_c9" })).rev, 1);
  assert.equal((await propose(db, reportId, { requirements: "a".repeat(64 * 1024), stepKey: "a" })).rev, 2);
});

test("a step may only bind assets that already exist, by name", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);

  await assert.rejects(() => propose(db, reportId, { assets: ["absent.json"] }), { code: "bad_input" });
  await assert.rejects(() => propose(db, reportId, { assets: ["../escape.json"] }), { code: "bad_input" });
  await assert.rejects(() => propose(db, reportId, { assets: "ways.json" }), { code: "bad_input" });

  const saved = await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: "payload" });
  const step = await propose(db, reportId, { assets: ["ways.json", "ways.json"] });
  assert.deepEqual(step.assets, ["ways.json"], "a repeated name is one binding");
  const raw = await storedStep(db, reportId, "fetch", step.rev);
  const envelope = JSON.parse(raw.files_json);
  assert.deepEqual(envelope.assets, ["ways.json"], "the bound assets are part of the sealed content");
  assert.equal(step.bundleHash,
    bundleHashOf({ files: FILES, requirements: "jinja2==3.1.4\n", assetHashes: [{ name: saved.name, sha256: saved.sha256 }] }),
    "the hash covers the asset's hash");
});

test("the 2 MB bundle cap and the 200 file cap are refused before anything is written", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const big = { "run.py": "a".repeat(STEP_MAX_BUNDLE_BYTES + 1) };
  await assert.rejects(() => propose(db, reportId, { files: big }), { code: "too_large" });

  const many = {};
  for (let i = 0; i < STEP_MAX_FILES + 1; i += 1) many[`f${i}.py`] = "x";
  await assert.rejects(() => propose(db, reportId, { files: many, entry: "f0.py" }), { code: "too_large" });

  const allowed = {};
  for (let i = 0; i < STEP_MAX_FILES; i += 1) allowed[`f${i}.py`] = "x";
  const step = await propose(db, reportId, { files: allowed, entry: "f0.py" });
  assert.equal(step.files.length, STEP_MAX_FILES);
});

test("an asset name and the 20 MB per-report total are enforced", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  for (const name of ["", "..", ".", "a/b", "a b", "a".repeat(101), "spr\u00e4ch"]) {
    await assert.rejects(() => saveAsset(db, deps(), { reportId, name, bytes: "x" }), { code: "bad_input" }, name);
  }
  await assert.rejects(() => saveAsset(db, deps(), { reportId, name: "a.json", bytes: "" }),
    { code: "bad_input" });

  // A row standing in for a full report: the next byte is refused without writing anything.
  await db.execute({
    sql: "INSERT INTO report_assets (report_id, name, sha256, bytes, created_at) VALUES (?, ?, ?, ?, ?)",
    args: [reportId, "full.json", "e".repeat(64), ASSET_MAX_BYTES, T0],
  });
  await assert.rejects(() => saveAsset(db, deps(), { reportId, name: "small.json", bytes: "x" }),
    { code: "too_large" });
  const { rows } = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_assets WHERE report_id = ? AND name = 'small.json'", args: [reportId],
  });
  assert.equal(Number(rows[0].n), 0, "no row was written");

  // Replacing the full asset with a smaller one is allowed: the cap is a total, not a per-name limit.
  const replaced = await saveAsset(db, deps(), { reportId, name: "full.json", bytes: "small" });
  assert.equal(replaced.bytes, 5);
});

test("the asset file lands under this instance's home with mode 0600", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const saved = await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: "payload" });
  const file = join(HOME, "reports", reportId, "assets", saved.sha256);
  assert.equal(readFileSync(file, "utf8"), "payload");
  const { statSync } = await import("node:fs");
  assert.equal(statSync(file).mode & 0o777, 0o600, "only this user reads an asset");
  assert.equal(await verifyAssetOnDisk(deps(), { report_id: reportId, sha256: saved.sha256 }), true);
});

test("an asset re-uploaded between the owner's view and the tap is a step_changed", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: "first" });
  const proposed = await propose(db, reportId, { assets: ["ways.json"] });
  const shown = await stepDetail(db, reportId, "fetch", proposed.rev, deps());
  assert.match(shown.bundleHash, /^[0-9a-f]{64}$/, "the view carries the bundle hash the tap hands back");

  // The asset moves under the view: the bundle the owner saw is not the bundle that is here.
  await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: "second" });
  await assert.rejects(
    () => approveStep(db, deps(), {
      reportId, stepKey: "fetch", rev: proposed.rev, bundleHash: shown.bundleHash, actor: OWNER,
    }),
    { code: "step_changed" },
  );
  assert.equal((await storedStep(db, reportId, "fetch", proposed.rev)).state, "proposed", "nothing was sealed");

  // A fresh view shows the bundle that would run, and that tap is the approval.
  const again = await stepDetail(db, reportId, "fetch", proposed.rev, deps());
  assert.notEqual(again.bundleHash, shown.bundleHash);
  const approved = await approveStep(db, deps(), {
    reportId, stepKey: "fetch", rev: proposed.rev, bundleHash: again.bundleHash, actor: OWNER,
  });
  assert.equal(approved.state, "approved");
  assert.equal(approved.bundleHash, again.bundleHash);
  assert.equal((await runnableStep(db, deps(), reportId, "fetch")).ok, true, "the approved bundle is the one that runs");

  // A body that names no bundle hash, or something that is not one, is a bad_input.
  for (const bundleHash of [undefined, null, "", "nope", 42]) {
    await assert.rejects(
      () => approveStep(db, deps(), { reportId, stepKey: "fetch", rev: proposed.rev, bundleHash, actor: OWNER }),
      { code: "bad_input" }, String(bundleHash),
    );
  }
});

test("a replaced or removed asset's file is gone, unless another name still names it", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const dir = join(HOME, "reports", reportId, "assets");
  const first = await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: "first" });
  const second = await saveAsset(db, deps(), { reportId, name: "ways.json", bytes: "second" });
  assert.equal(existsSync(join(dir, first.sha256)), false, "the content the name replaced is gone");
  assert.equal(existsSync(join(dir, second.sha256)), true);

  // Two names, one content: replacing one leaves the file the other still names.
  const shared = await saveAsset(db, deps(), { reportId, name: "a.json", bytes: "shared" });
  await saveAsset(db, deps(), { reportId, name: "b.json", bytes: "shared" });
  await saveAsset(db, deps(), { reportId, name: "a.json", bytes: "other" });
  assert.equal(existsSync(join(dir, shared.sha256)), true, "b.json still names that hash");

  // Removing the last row that names a hash removes its file too.
  assert.deepEqual(await removeAsset(db, deps(), { reportId, name: "b.json" }), {
    name: "b.json", removed: true, sha256: shared.sha256,
  });
  assert.equal(existsSync(join(dir, shared.sha256)), false, "nothing names it any more");
  const lone = await saveAsset(db, deps(), { reportId, name: "c.json", bytes: "alone" });
  assert.equal((await removeAsset(db, deps(), { reportId, name: "c.json" })).removed, true);
  assert.equal(existsSync(join(dir, lone.sha256)), false);
  assert.equal((await removeAsset(db, deps(), { reportId, name: "c.json" })).removed, false,
    "removing twice is an answer, not a throw");
  await assert.rejects(() => removeAsset(db, deps(), { reportId, name: "../x" }), { code: "bad_input" });
});

/* --------------------------------------------------------------------------- the diff */

test("the diff compares a revision against the previous APPROVED one", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedStep(db, reportId, {
    files: { "run.py": "a\nb\nc\n", "templates/report.html": "<p>x</p>\n" },
  });

  const next = await propose(db, reportId, {
    files: { "run.py": "a\nB\nc\nd\n", "extra.py": "print(1)\n" },
  });
  const diff = await stepDiff(db, reportId, "fetch", next.rev);
  assert.equal(diff.reportId, reportId);
  assert.equal(diff.stepKey, "fetch");
  assert.equal(diff.rev, 2);
  assert.equal(diff.previousRev, 1, "the approved revision, not the previous one");
  assert.deepEqual(diff.files.map((f) => f.path), ["extra.py", "run.py", "templates/report.html"]);
  const byPath = Object.fromEntries(diff.files.map((f) => [f.path, f]));
  assert.equal(byPath["extra.py"].status, "added");
  assert.equal(byPath["run.py"].status, "changed");
  assert.equal(byPath["templates/report.html"].status, "removed");
  assert.equal(byPath["run.py"].added, 2, "B and d are added");
  assert.equal(byPath["run.py"].removed, 1, "b is removed");
  assert.deepEqual(
    byPath["run.py"].lines.filter((l) => l.op !== " ").map((l) => `${l.op}${l.text}`),
    ["-b", "+B", "+d"],
  );
  assert.equal(diff.added, 3);
  assert.equal(diff.removed, 2);
  assert.equal(typeof byPath["run.py"].capped, "boolean");

  // The first revision has no earlier approval: every file reads as added.
  const firstDiff = await stepDiff(db, reportId, "fetch", 1);
  assert.equal(firstDiff.previousRev, null);
  assert.deepEqual(firstDiff.files.map((f) => f.status), ["added", "added"]);

  await assert.rejects(() => stepDiff(db, reportId, "fetch", 99), { code: "not_found" });
  await assert.rejects(() => stepDiff(db, reportId, "Nope", 1), { code: "bad_input" });
});

/* ------------------------------------------------------------------------- the modules */

test("a report that does not exist is refused, and a bad key waits rather than throwing", async () => {
  const db = await freshDb();
  await assert.rejects(() => propose(db, "rpt-ffffffffffffffff", {}), { code: "not_found" });
  const reportId = await makeReport(db);
  assert.deepEqual(await runnableStep(db, deps(), reportId, "nothing"), { ok: false, reason: "step_waiting" });
  assert.deepEqual(await runnableStep(db, deps(), reportId, "BAD KEY"), { ok: false, reason: "step_waiting" });
  assert.deepEqual(await runnableStep(db, deps(), reportId, "fetch"), { ok: false, reason: "step_waiting" });
});

test("no seed means no seal, and the proposal is still stored", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const proposed = await propose(db, reportId);
  await assert.rejects(
    () => approveStep(db, { loadSeed: () => null, now: () => T0, crowHome: HOME },
      { reportId, stepKey: "fetch", rev: proposed.rev, bundleHash: proposed.bundleHash, actor: OWNER }),
    { code: "keychain_key_missing" },
  );
  assert.equal((await storedStep(db, reportId, "fetch", 1)).state, "proposed");
});