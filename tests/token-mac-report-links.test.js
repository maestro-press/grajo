/**
 * §8 PR 5a of the keyed-token-hashes design: the report-link store
 * (`report_link_tokens.token_hash`) becomes a keyed verifier, family `report:link`.
 *
 * A contained bot has read-write crow.db, so with `token_hash = sha256(token)` it could INSERT a
 * link row for an approved recipient (the approval nonce is readable) and read the report and
 * comment as that recipient through the PUBLIC door. This file pins, against the real schema,
 * store, validator and public door:
 *   - every live link keeps working across the conversion with its SAME raw token (resolve AND the
 *     door's GET); revoked/expired rows convert and stay refused by their own columns;
 *   - after conversion a planted sha256 row, and an h1 copied from another family, are refused
 *     (resolve, door GET and comment POST) with `token_legacy_form` audited for the former;
 *   - the converter: happy path, second boot, crash rerun that never launders a post-snapshot
 *     write, an EMPTY snapshot is pending, a failed family refuses in-process, no table;
 *   - mint stores the keyed form; the comment-form nonce (bound to sha256 of the RAW token) is
 *     unchanged across the conversion;
 *   - `--reset` revokes every link (and sends nothing); `--rollback` ignores a report snapshot;
 *   - the dry run: PASS, STOP, and "live links verifying: before N, after M".
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = mkdtempSync(join(tmpdir(), "report-link-token-mac-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const BUNDLE = join(REPO, "bundles", "artifacts", "server");
const bundleImport = (file) => import(pathToFileURL(join(BUNDLE, file)).href);
const bundleStore = await bundleImport("store.js");
const bundleComments = await bundleImport("comments.js");
const bundleLimits = await bundleImport("limits.js");
const { initArtifactsTables } = await bundleImport("init-tables.js");
const { createBlobStore } = await bundleImport("blob-store-minio.js");
const { markdownBlocks } = await import("../servers/blog/renderer.js");

const { createDbClient } = await import("../servers/db.js");
const { createNotification } = await import("../servers/shared/notifications.js");
const { createDoorHandler } = await import("../servers/gateway/reports/public-door.js");
const {
  forgetTokenMacAlarms, forgetTokenMacKey, macToken, readState,
} = await import("../servers/shared/token-mac.js");
const { readSetting } = await import("../servers/gateway/dashboard/settings/registry.js");
const {
  REPORT_LINK_FAMILY, forgetForcedReportLinkLegacyRefusal, forgetReportLinkEvidence, isLegacyStored,
} = await import("../servers/gateway/reports/link-token.js");
const {
  REPORT_LINK_ROLLBACK_PREFIX, runReportLinkTokenHmacBoot,
} = await import("../servers/gateway/boot/token-hmac-reports.js");
const {
  hashToken, mintLinkToken, resolveLinkToken, revokeLinkTokens,
} = await import("../servers/gateway/reports/links.js");
const {
  approveRecipient, liveSetFor, proposeRecipient, revokeRecipient,
} = await import("../servers/gateway/reports/approvals.js");
const {
  createReport, getReport, saveRecipe, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { copyFor } = await import("../servers/gateway/reports/recipient-copy.js");
const { postRecipientComment } = await import("../servers/gateway/reports/recipient-comments.js");
const {
  FORM_NONCE_WINDOW_MS, approvalSeal, approvalSealKey, formNonceFor, formNonceKey, newApprovalNonce,
  verifyFormNonce,
} = await import("../servers/gateway/reports/seal.js");

const PROJECT = 7;
const BOT = "bot-1";
const OWNER = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 11);
const OTHER_SEED = Buffer.alloc(32, 22);
const T0 = 1_700_000_000_000;
const DAY_MS = 86_400_000;
const DOC_TEXT = "The weekly listings are in.";
const RUN = "rrn-00000000000000a1";
const SEND = "rsd-00000000000000a1";
const PREVIEW_RUN = "rrn-00000000000000b2";
const PREVIEW_SEND = "rsd-00000000000000b2";

let clock = T0;
let blobs = 0;
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

let copies = 0;
const dbPaths = new Map();

async function freshDb() {
  const dir = join(root, "t" + (++copies));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  dbPaths.set(db, crow);
  // The dry run attributes a copied DB by the instance id beside it.
  writeFileSync(join(dir, "instance-id"), "0123456789abcdef0123456789abcdef\n", { mode: 0o600 });
  await initArtifactsTables(db);
  return db;
}

/** The keychain seed and the clock, the seam `approvals.js` and this door both read. */
function approvalsDeps(over = {}) {
  return { loadSeed: () => ({ seed: SEED }), now: () => clock, getSecrets: () => [], ...over };
}

/** The links seam: the real artifacts store (holds), the injection seed, the test clock. */
function linksDeps(runtime, over = {}) {
  return { artifacts: runtime, approvals: approvalsDeps(), now: () => clock, ...over };
}

/** The notification seam: the real row, with the network fan-out turned off. */
const notifyQuietly = (db, opts) => createNotification(db, { ...opts, deliver: false });

/** The door's own deps: one object a test injects, which the door bridges to both seams. */
function doorDeps(world, over = {}) {
  return {
    artifacts: world.runtime,
    comments: bundleComments,
    loadSeed: () => ({ seed: SEED }),
    now: () => clock,
    notify: notifyQuietly,
    ...over,
  };
}

/** One document artifact version with a readable index.html, written by the bundle's own store. */
async function artifactVersion(db, { markdown = DOC_TEXT } = {}) {
  const dataDir = join(root, "blobs", String(++blobs));
  mkdirSync(dataDir, { recursive: true });
  const store = await createBlobStore(db, dataDir, { forceKind: "local" });
  const runtime = {
    store: bundleStore,
    initArtifactsTables,
    blobs: store,
    markdownBlocks,
    limits: bundleLimits.LIMITS,
  };
  const { id, versionN } = await bundleStore.createArtifact(db, store, {
    title: "Weekly listings",
    type: "document",
    source: { markdown, title: "Weekly listings" },
    actor: { kind: "session" },
  }, { markdownBlocks });
  return { artifactId: id, versionN, runtime };
}

async function addRun(db, { id, reportId, trigger = "manual" }) {
  await db.execute({
    sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, status, created_at)
          VALUES (?, ?, ?, 'owner', 'ok', ?)`,
    args: [id, reportId, trigger, T0],
  });
}

async function addVersionRow(db, { artifactId, n, reportId, runId, trigger = "schedule" }) {
  await db.execute({
    sql: `INSERT INTO report_versions
            (artifact_id, n, report_id, run_id, "trigger", allowed_links_json, created_at)
          VALUES (?, ?, ?, ?, ?, '[]', ?)`,
    args: [artifactId, n, reportId, runId, trigger, T0],
  });
}

async function addSend(db, { id, runId, reportId, recipientId, status = "sent" }) {
  await db.execute({
    sql: `INSERT INTO report_sends
            (id, run_id, report_id, recipient_id, attempt, status, created_at, updated_at)
          VALUES (?, ?, ?, ?, 1, ?, ?, ?)`,
    args: [id, runId, reportId, recipientId, status, T0, T0],
  });
}

async function currentNonce(db, recipientId) {
  const { rows } = await db.execute({
    sql: "SELECT approval_nonce FROM report_recipients WHERE id = ?",
    args: [recipientId],
  });
  return String(rows[0]?.approval_nonce ?? "");
}

/**
 * One report, one approved recipient, one document version with a readable page, the run and send rows,
 * and a real token minted for that send: the whole world one mailed link is. The report is sealed LIVE
 * before the token is minted, because a token only opens a report that is live over a seal that still
 * verifies (see THE REPORT'S OWN STANDING in links.js).
 */
async function world({
  tier = "a", address = "alex@example.com", markdown = DOC_TEXT, linkDays = null,
} = {}) {
  const db = await freshDb();
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: "owner", botId: BOT, title: "Weekly listings",
  });
  await updateReportColumns(db, id, {
    comment_tier_default: tier, comment_visibility: "own", comment_window_runs: 4,
  });
  const proposed = await proposeRecipient(db, approvalsDeps(), {
    reportId: id, address, displayName: "Alex", commentTier: null, proposedBy: "owner",
  });
  const recipient = await approveRecipient(db, approvalsDeps(), {
    recipientId: proposed.id, actor: OWNER,
  });
  const version = await artifactVersion(db, { markdown });
  await addRun(db, { id: RUN, reportId: id });
  await addVersionRow(db, {
    artifactId: version.artifactId, n: version.versionN, reportId: id, runId: RUN,
  });
  await addSend(db, { id: SEND, runId: RUN, reportId: id, recipientId: recipient.id });
  if (linkDays != null) {
    await db.execute({
      sql: "INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('reports.link_days', ?)",
      args: [String(linkDays)],
    });
  }
  const report = await goLiveReport(db, await getReport(db, id));
  const minted = await mintLinkToken(db, linksDeps(version.runtime), {
    report, recipient, run: { id: RUN }, sendId: SEND,
  });
  assert.ok(minted, "the harness mints a real token");
  return {
    db,
    report,
    recipient,
    runtime: version.runtime,
    artifactId: version.artifactId,
    versionN: version.versionN,
    token: minted.token,
    minted,
  };
}

function handlerFor(w, over = {}) {
  return createDoorHandler(w.db, doorDeps(w, over));
}

/**
 * Seal one report live over the values its row holds now: the write `approveGoLive` makes, minus the
 * preview run and the sender a go-live insists on. What this door reads is the seal over the live set
 * (its comment visibility and its comment window), so a real seal over the current row is the whole
 * world those two settings come from.
 *
 * @param {object} db
 * @param {object} row the report row to seal
 * @returns {Promise<object>} the report row after the write
 */
async function goLiveReport(db, row) {
  if (row.schedule_id == null) {
    await db.execute({
      sql: `INSERT INTO schedules (task, cron_expression, tz)
            VALUES ('weekly-report', '0 7 * * 1', 'UTC')`,
      args: [],
    });
    const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
    await updateReportColumns(db, row.id, { schedule_id: Number(rows[0].id) });
  }
  const saved = await saveRecipe(db, {
    reportId: row.id, recipe: { blocks: [] }, authorKind: "owner",
  });
  const fresh = await getReport(db, row.id);
  const nonce = newApprovalNonce();
  const fields = await liveSetFor(db, approvalsDeps(), fresh, { rev: saved.rev, nonce });
  await updateReportColumns(db, row.id, {
    status: "live",
    live_rev: saved.rev,
    live_nonce: nonce,
    live_seal: approvalSeal("live", fields, SEED),
  });
  return getReport(db, row.id);
}

/**
 * One more run of a public world: a new version of the same artifact (written by the bundle's own store,
 * so it has a readable page), its run and send rows, and a real token minted for that send.
 *
 * @returns {Promise<{token: string, versionN: number}>} the raw token the mail for that run would carry,
 *   and the version the bundle numbered it
 */
async function addRunLink(w, { runId, sendId }) {
  const made = await bundleStore.addVersion(w.db, w.runtime.blobs, {
    artifactId: w.artifactId,
    source: { markdown: DOC_TEXT, title: "Weekly listings" },
    actor: { kind: "session" },
  }, { markdownBlocks });
  const versionN = Number(made.n);
  await addRun(w.db, { id: runId, reportId: w.report.id, trigger: "schedule" });
  await addVersionRow(w.db, {
    artifactId: w.artifactId, n: versionN, reportId: w.report.id, runId, trigger: "schedule",
  });
  await addSend(w.db, { id: sendId, runId, reportId: w.report.id, recipientId: w.recipient.id });
  const report = await getReport(w.db, w.report.id);
  const minted = await mintLinkToken(w.db, linksDeps(w.runtime), {
    report, recipient: w.recipient, run: { id: runId }, sendId,
  });
  assert.ok(minted, `the harness mints a real token for run ${runId}`);
  assert.equal(minted.versionN, versionN, "the token opens the version the run wrote");
  return { token: minted.token, versionN };
}

/** The nonce the page carries, as a form would post it back. */
function nonceIn(html) {
  const found = /name="formNonce" value="([0-9a-f]{64})"/.exec(html);
  assert.ok(found, "the page carries a form nonce");
  return found[1];
}

/* ------------------------------------------------------------- scratch + helpers for this file */

const H1 = /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/;
const SCRIPT_RESET = join(REPO, "scripts", "token-hmac.mjs");
const DRYRUN = join(REPO, "scripts", "ops", "report-token-hmac-dryrun.mjs");
let homes = 0;

/** A fresh CROW_HOME (its own key and era state) with every in-process cache forgotten. */
function newHome() {
  const home = join(root, `home-${++homes}`);
  mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
  process.env.CROW_HOME = home;
  forgetTokenMacKey();
  forgetTokenMacAlarms();
  forgetReportLinkEvidence();
  forgetForcedReportLinkLegacyRefusal();
  return home;
}

const reportSnapshots = (home) => {
  try {
    return readdirSync(join(home, "secrets")).filter((n) => n.startsWith(REPORT_LINK_ROLLBACK_PREFIX));
  } catch {
    return [];
  }
};

const rowsOf = async (db) => (await db.execute({
  sql: "SELECT id, token_hash, revoked_at, expires_at FROM report_link_tokens ORDER BY created_at, id", args: [],
})).rows;
const storedFor = async (db, id) => (await db.execute({
  sql: "SELECT token_hash FROM report_link_tokens WHERE id = ?", args: [id],
})).rows[0]?.token_hash ?? null;

/** Put every minted token back into the PRE-conversion form: sha256(raw), as the old code stored it. */
async function makeLegacy(w, raws) {
  for (const raw of raws) {
    // eslint-disable-next-line no-await-in-loop -- a handful of rows
    await w.db.execute({
      sql: "UPDATE report_link_tokens SET token_hash = ? WHERE token_hash = ?",
      args: [hashToken(raw), macToken(REPORT_LINK_FAMILY, raw)],
    });
  }
}

/** A hand-made link row beside a world's own, as a contained bot (or the old code) would write it. */
async function insertRow(w, { id, stored, revokedAt = null, expiresAt = T0 + 30 * DAY_MS }) {
  const [own] = (await w.db.execute({ sql: "SELECT * FROM report_link_tokens LIMIT 1", args: [] })).rows;
  await w.db.execute({
    sql: `INSERT INTO report_link_tokens
            (id, report_id, recipient_id, run_id, send_id, artifact_id, version_n, token_hash, scope,
             approval_nonce, created_at, revoked_at, expires_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [id, own.report_id, own.recipient_id, own.run_id, own.send_id, own.artifact_id, own.version_n,
      stored, own.scope, own.approval_nonce, T0, revokedAt, expiresAt],
  });
}

const newRaw = () => randomBytes(32).toString("base64url");
const legacyAudits = async (db) => (await db.execute({
  sql: "SELECT details FROM audit_log WHERE event_type = 'token_legacy_form'", args: [],
})).rows;

/** The alarm's audit row is fire-and-forget, so wait for it instead of racing it. */
async function auditCountAtLeast(db, n, ms = 2_000) {
  const deadline = Date.now() + ms;
  for (;;) {
    // eslint-disable-next-line no-await-in-loop -- a bounded poll
    const count = (await legacyAudits(db)).length;
    if (count >= n || Date.now() > deadline) return count;
    // eslint-disable-next-line no-await-in-loop -- a bounded poll
    await new Promise((r) => { setTimeout(r, 20); });
  }
}

const resolveWith = (w, raw) => resolveLinkToken(w.db, linksDeps(w.runtime), raw);

/* ----------------------------------------------------------------------- live links keep working */

test("every live link keeps working across the conversion with its SAME raw token (resolve and the door's GET)", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  const b = await addRunLink(w, { runId: "rrn-00000000000000c1", sendId: "rsd-00000000000000c1" });
  const c = await addRunLink(w, { runId: "rrn-00000000000000c2", sendId: "rsd-00000000000000c2" });
  const d = await addRunLink(w, { runId: "rrn-00000000000000c3", sendId: "rsd-00000000000000c3" });
  const live = [w.token, b.token];
  // c is expired, d is revoked: both convert and both stay refused by their own columns.
  await w.db.execute({ sql: "UPDATE report_link_tokens SET expires_at = ? WHERE send_id = ?", args: [T0 - 1, "rsd-00000000000000c2"] });
  await w.db.execute({ sql: "UPDATE report_link_tokens SET revoked_at = ? WHERE send_id = ?", args: [T0, "rsd-00000000000000c3"] });

  // The PRE-conversion store: every verifier is sha256(raw), nothing converted yet.
  await makeLegacy(w, [w.token, b.token, c.token, d.token]);
  assert.equal((await rowsOf(w.db)).every((r) => isLegacyStored(r.token_hash)), true);
  for (const raw of live) assert.equal((await resolveWith(w, raw)).status, "ok", "works before");

  const boot = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal(boot.family.state, "converted");
  assert.equal(boot.converted, 4, "expired and revoked rows convert too");
  assert.equal(boot.alarms, 0);
  assert.equal((await rowsOf(w.db)).every((r) => H1.test(r.token_hash)), true, "every row is keyed now");

  for (const raw of live) {
    const resolved = await resolveWith(w, raw);
    assert.equal(resolved.status, "ok", "the SAME raw token resolves after the conversion");
    const page = await handlerFor(w)({ op: "view", token: raw });
    assert.equal(page.status, 200, "and the public door's GET serves it");
    assert.ok(page.html.includes(DOC_TEXT));
  }
  assert.equal((await resolveWith(w, c.token)).status, "expired");
  assert.equal((await handlerFor(w)({ op: "view", token: c.token })).status, 410);
  assert.equal((await resolveWith(w, d.token)).status, "unknown");
  assert.equal((await handlerFor(w)({ op: "view", token: d.token })).status, 404);

  // The second boot is a no-op and the era is recorded in both places.
  const again = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal(again.converted, 0);
  assert.equal(again.alarms, 0);
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at, "state file");
  assert.ok(await readSetting(w.db, `token_hmac_era:${REPORT_LINK_FAMILY}`), "DB mirror");
  assert.equal(reportSnapshots(process.env.CROW_HOME).length, 1, "one rollback snapshot, in its own prefix");
});

test("mint after conversion stores the keyed form and the link resolves with its raw token", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  await runReportLinkTokenHmacBoot({ db: w.db });
  const b = await addRunLink(w, { runId: "rrn-00000000000000d1", sendId: "rsd-00000000000000d1" });
  const rows = await rowsOf(w.db);
  assert.equal(rows.length, 2);
  for (const row of rows) assert.match(row.token_hash, H1);
  assert.ok(rows.some((r) => r.token_hash === macToken(REPORT_LINK_FAMILY, b.token)));
  assert.equal((await resolveWith(w, b.token)).status, "ok");
  assert.equal((await resolveWith(w, w.token)).status, "ok");
});

/* --------------------------------------------------------------------------- the headline forgery */

test("after conversion a bot-planted sha256 row is refused by resolve, the door GET and the comment POST", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  await runReportLinkTokenHmacBoot({ db: w.db });
  const legit = await handlerFor(w)({ op: "view", token: w.token });
  const nonce = nonceIn(legit.html);

  const own = newRaw();
  await insertRow(w, { id: "rlt-planted00000001", stored: hashToken(own) });
  assert.deepEqual(await resolveWith(w, own), { status: "unknown" });
  assert.ok(await auditCountAtLeast(w.db, 1) >= 1, "token_legacy_form is audited");
  assert.ok((await legacyAudits(w.db)).some((r) => JSON.parse(r.details).row === "rlt-planted00000001"));
  const get = await handlerFor(w)({ op: "view", token: own });
  assert.equal(get.status, 404);
  assert.ok(get.html.includes(copyFor("en").unknownLink), "the door's existing answer, unchanged");
  const post = await handlerFor(w)({ op: "comment", token: own, text: "forged", formNonce: nonce });
  assert.equal(post.status, 404, "the comment POST is refused too");
  const { rows: comments } = await w.db.execute({ sql: "SELECT COUNT(*) AS n FROM report_recipient_comments", args: [] });
  assert.equal(Number(comments[0].n), 0, "nothing was written");
});

test("an h1 value copied from another family is refused (the family is inside the MAC)", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  await runReportLinkTokenHmacBoot({ db: w.db });
  for (const [i, family] of ["peer:inbound", "oauth:access"].entries()) {
    const own = newRaw();
    const foreign = macToken(family, own);
    // eslint-disable-next-line no-await-in-loop -- two rows
    await insertRow(w, { id: `rlt-foreign0000000${i}`, stored: foreign });
    // eslint-disable-next-line no-await-in-loop -- two rows
    assert.deepEqual(await resolveWith(w, own), { status: "unknown" });
    // eslint-disable-next-line no-await-in-loop -- two rows
    assert.equal((await handlerFor(w)({ op: "view", token: own })).status, 404);
  }
});

test("a key that is lost refuses every link (fail closed): resolve answers unknown", async () => {
  clock = T0;
  const keyFile = join(newHome(), "secrets", "token-hmac.key");
  const w = await world({ tier: "a" });
  await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal((await resolveWith(w, w.token)).status, "ok");
  rmSync(keyFile);
  forgetTokenMacKey();
  assert.deepEqual(await resolveWith(w, w.token), { status: "unknown" });
});

/* ---------------------------------------------------------------------------------- the converter */

test("converter: a crash re-run converts only the snapshot's rows and never launders a later legacy write", async () => {
  clock = T0;
  const home = newHome();
  const w = await world({ tier: "a" });
  await makeLegacy(w, [w.token]);
  const failing = await runReportLinkTokenHmacBoot({
    db: w.db, runTransaction: async () => { throw new Error("simulated crash"); },
  });
  assert.equal(failing.family.state, "failed");
  assert.equal(reportSnapshots(home).length, 1, "the snapshot was taken before the crash");
  assert.equal((await resolveWith(w, w.token)).status, "unknown", "a failed family refuses legacy in THIS process");

  const planted = newRaw();
  await insertRow(w, { id: "rlt-planted00000002", stored: hashToken(planted) });
  forgetForcedReportLinkLegacyRefusal();
  const rerun = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal(rerun.family.state, "converted");
  assert.equal(rerun.converted, 1, "only the snapshot row");
  assert.equal(rerun.alarms, 1, "the post-snapshot write is alarmed");
  assert.ok(isLegacyStored(await storedFor(w.db, "rlt-planted00000002")), "and left unconverted");
  assert.deepEqual(await resolveWith(w, planted), { status: "unknown" });
  assert.equal((await resolveWith(w, w.token)).status, "ok", "the real link works");
});

test("converter: an EMPTY snapshot is still pending, so a later legacy write is not laundered", async () => {
  clock = T0;
  const home = newHome();
  const w = await world({ tier: "a" }); // its row is already keyed: nothing legacy to snapshot
  const failing = await runReportLinkTokenHmacBoot({
    db: w.db, runTransaction: async () => { throw new Error("simulated crash"); },
  });
  assert.equal(failing.family.state, "failed");
  assert.equal(reportSnapshots(home).length, 1);
  const planted = newRaw();
  await insertRow(w, { id: "rlt-planted00000003", stored: hashToken(planted) });
  forgetForcedReportLinkLegacyRefusal();
  const rerun = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal(rerun.converted, 0, "the empty snapshot converts nothing");
  assert.equal(rerun.alarms, 1);
  assert.ok(isLegacyStored(await storedFor(w.db, "rlt-planted00000003")));
  assert.deepEqual(await resolveWith(w, planted), { status: "unknown" });
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at, "and the family is marked");
});

test("converter: a store with no report_link_tokens table is marked converted with 0 rows", async () => {
  newHome();
  const db = await freshDb();
  await db.execute({ sql: "DROP TABLE report_link_tokens", args: [] });
  const boot = await runReportLinkTokenHmacBoot({ db });
  assert.equal(boot.key, "ok");
  assert.equal(boot.family.state, "converted");
  assert.equal(boot.converted, 0);
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at);
  assert.equal((await runReportLinkTokenHmacBoot({ db })).alarms, 0);
});

/* ------------------------------------------------------------------------ comment-form compatibility */

test("a comment form minted BEFORE the conversion still verifies after it, and a fresh one verifies too", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  await makeLegacy(w, [w.token]);
  const before = await handlerFor(w)({ op: "view", token: w.token });
  const oldNonce = nonceIn(before.html);
  assert.equal(oldNonce, formNonceFor(hashToken(w.token), SEED, clock), "bound to sha256 of the RAW token");

  await runReportLinkTokenHmacBoot({ db: w.db });
  assert.match(await storedFor(w.db, (await rowsOf(w.db))[0].id), H1);
  const afterView = await handlerFor(w)({ op: "view", token: w.token });
  assert.equal(nonceIn(afterView.html), oldNonce, "the nonce input is unchanged");

  const posted = await handlerFor(w)({ op: "comment", token: w.token, text: "from the old form", formNonce: oldNonce });
  assert.equal(posted.status, 200);
  assert.equal(posted.ok, true, "the pre-conversion form verifies on the converted row");
  const fresh = await handlerFor(w)({
    op: "comment", token: w.token, text: "from a fresh form", formNonce: nonceIn(afterView.html),
  });
  assert.equal(fresh.ok, true, "and a fresh one verifies too");
});

/* ------------------------------------------------------------------------------ --reset / --rollback */

function runTool(args, w, env = {}) {
  const home = process.env.CROW_HOME;
  return execFileSync(process.execPath, [SCRIPT_RESET, ...args, "--yes", "--force-while-running"], {
    cwd: REPO,
    env: {
      ...process.env,
      CROW_HOME: home,
      CROW_DATA_DIR: join(root, "master"),
      CROW_DB_PATH: dbPaths.get(w.db),
      ...env,
    },
    encoding: "utf8",
    stdio: "pipe",
    timeout: 120_000,
  });
}

test("--reset revokes every report link (sending nothing), keeps the era, and a planted legacy row is refused", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  const b = await addRunLink(w, { runId: "rrn-00000000000000e1", sendId: "rsd-00000000000000e1" });
  await runReportLinkTokenHmacBoot({ db: w.db });
  await w.db.execute({ sql: "UPDATE report_link_tokens SET revoked_at = ? WHERE send_id = ?", args: [123, "rsd-00000000000000e1"] });
  const out = runTool(["--reset"], w);
  assert.match(out, /1 report link\(s\) revoked; recipients get new links on the next scheduled run/);
  forgetTokenMacKey();
  forgetTokenMacAlarms();
  forgetReportLinkEvidence();
  const rows = await rowsOf(w.db);
  assert.equal(rows.length, 2, "rows are stamped, never deleted");
  assert.equal(rows.every((r) => r.revoked_at != null), true);
  assert.equal(Number(rows.find((r) => r.revoked_at === 123)?.revoked_at), 123, "an earlier revocation keeps its own stamp");
  assert.deepEqual(await resolveWith(w, w.token), { status: "unknown" });
  assert.deepEqual(await resolveWith(w, b.token), { status: "unknown" });
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at, "the family stays converted");
  assert.ok(await readSetting(w.db, `token_hmac_era:${REPORT_LINK_FAMILY}`));
  const planted = newRaw();
  await insertRow(w, { id: "rlt-planted00000004", stored: hashToken(planted) });
  assert.deepEqual(await resolveWith(w, planted), { status: "unknown" }, "a planted legacy row is refused");
  const { rows: sends } = await w.db.execute({ sql: "SELECT COUNT(*) AS n FROM report_sends WHERE status != 'sent'", args: [] });
  assert.equal(Number(sends[0].n), 0, "nothing was queued or sent");
});

test("--rollback neither crashes on a report:link snapshot nor deletes it, and says so", async () => {
  clock = T0;
  const home = newHome();
  const w = await world({ tier: "a" });
  await makeLegacy(w, [w.token]);
  await runReportLinkTokenHmacBoot({ db: w.db });
  const [snapshot] = reportSnapshots(home);
  assert.ok(snapshot, "the converter wrote its snapshot");
  const out = runTool(["--rollback"], w);
  assert.match(out, /report:link\s+1 snapshot file\(s\) left in place: not restored by this tool yet/);
  assert.ok(existsSync(join(home, "secrets", snapshot)), "the snapshot file is still there, untouched");
  assert.equal(reportSnapshots(home).length, 1);
});

/* --------------------------------------------------------------------------------------- dry run */

function dryrun(w, home) {
  try {
    const out = execFileSync(process.execPath, [
      DRYRUN, "--db", `crow=${dbPaths.get(w.db)}`, "--files-from", join(root, "master", ".."), "--home", home,
    ], { cwd: REPO, encoding: "utf8", stdio: "pipe", timeout: 120_000 });
    return { code: 0, out };
  } catch (err) {
    return { code: err.status ?? 1, out: `${err.stdout || ""}${err.stderr || ""}` };
  }
}

test("the dry run: PASS on a clean copy with 'live links verifying' counts, STOP when a value would be refused", async () => {
  clock = Date.now();
  newHome();
  const w = await world({ tier: "a", linkDays: 30 });
  const b = await addRunLink(w, { runId: "rrn-00000000000000f1", sendId: "rsd-00000000000000f1" });
  await makeLegacy(w, [w.token, b.token]);
  await w.db.execute({ sql: "UPDATE report_link_tokens SET revoked_at = 5 WHERE send_id = ?", args: ["rsd-00000000000000f1"] });
  const scratchHome = mkdtempSync(join(tmpdir(), "crow-report-dryrun-"));
  const pass = dryrun(w, scratchHome);
  assert.equal(pass.code, 0, pass.out);
  assert.match(pass.out, /^PASS:/m);
  assert.match(pass.out, /2 row\(s\) would be converted, 0 old-style value\(s\) refused/);
  assert.match(pass.out, /rows: 2 \(non-revoked 1, revoked 1, expired 0\)/);
  assert.match(pass.out, /live links verifying: before 1, after 1/);
  assert.equal(/[0-9a-f]{64}/.test(pass.out), false, "no hash and no token on stdout");
  assert.equal(pass.out.includes("rlt-"), false, "and no row id");
  assert.ok(isLegacyStored((await rowsOf(w.db))[0].token_hash), "the source row is untouched");
  assert.equal(readState().families[REPORT_LINK_FAMILY], undefined, "and so is the source era");

  // A converted store carrying a planted old-style value: the rehearsal STOPS.
  await runReportLinkTokenHmacBoot({ db: w.db });
  await insertRow(w, { id: "rlt-planted00000005", stored: hashToken(newRaw()), expiresAt: Date.now() + DAY_MS });
  const stop = dryrun(w, mkdtempSync(join(tmpdir(), "crow-report-dryrun-")));
  assert.equal(stop.code, 1, stop.out);
  assert.match(stop.out, /^STOP:/m);
  assert.match(stop.out, /1 old-style value\(s\) refused/);
  assert.equal(/[0-9a-f]{64}/.test(stop.out), false);
});

/* ------------------------------------------------------------------------------------- source facts */

test("source: the converter runs before listen, and the public-link listener never imports token-mac", () => {
  const index = readFileSync(join(REPO, "servers/gateway/index.js"), "utf8");
  const peer = index.indexOf("runPeerTokenHmacBoot");
  const report = index.indexOf("runReportLinkTokenHmacBoot");
  assert.ok(peer > 0 && report > peer, "after the peer converter");
  assert.ok(report < index.indexOf("app.listen(PORT, BIND"), "before the gateway listens");
  const listener = readFileSync(join(REPO, "scripts", "artifact-public", "server.mjs"), "utf8");
  assert.equal(/token-mac|link-token|links\.js/.test(listener), false, "the minimal listener gains no key import");
});

/* ------------------------------------------------------------------------------------ round 2 */

test("H1: an era recorded ONLY in the database is adopted into the state file; a sha256 row planted after the mirror is deleted stays refused and is never converted", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  const { eraSettingKey } = await import("../servers/shared/token-mac.js");
  const { writeSetting } = await import("../servers/gateway/dashboard/settings/registry.js");
  await writeSetting(w.db, eraSettingKey(REPORT_LINK_FAMILY), new Date().toISOString(), { scope: "local" });
  assert.equal(readState().families[REPORT_LINK_FAMILY], undefined, "precondition: the state file has no era");
  const first = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal(first.key, "ok");
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at, "the era is now in the state file");
  assert.deepEqual(reportSnapshots(process.env.CROW_HOME), [], "adopted, not converted: no snapshot");
  assert.ok(await auditCountAtLeast(w.db, 1) >= 1);
  assert.ok((await legacyAudits(w.db)).some((r) => JSON.parse(r.details).mirror === true));

  await w.db.execute({
    sql: "DELETE FROM dashboard_settings_overrides WHERE key = ?", args: [`token_hmac_era:${REPORT_LINK_FAMILY}`],
  });
  forgetTokenMacAlarms();
  const own = newRaw();
  await insertRow(w, { id: "rlt-planted00000006", stored: hashToken(own) });
  assert.deepEqual(await resolveWith(w, own), { status: "unknown" }, "refused at runtime");
  const second = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.ok(isLegacyStored(await storedFor(w.db, "rlt-planted00000006")), "not converted");
  assert.ok(second.alarms >= 1, "and alarmed");
  assert.deepEqual(await resolveWith(w, own), { status: "unknown" });
});

test("M1: a keyed value copied onto another row no longer aborts the conversion; the copy is revoked and the era recorded", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  await makeLegacy(w, [w.token]);
  const failing = await runReportLinkTokenHmacBoot({
    db: w.db, runTransaction: async () => { throw new Error("simulated crash"); },
  });
  assert.equal(failing.family.state, "failed");
  // The bot copies the keyed value the real row WILL get onto a new row.
  await insertRow(w, { id: "rlt-copy000000000001", stored: macToken(REPORT_LINK_FAMILY, w.token) });
  forgetForcedReportLinkLegacyRefusal();
  forgetTokenMacAlarms();
  const rerun = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal(rerun.family.state, "converted", "no abort");
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at, "the era is recorded");
  assert.equal(rerun.family.copies, 1);
  assert.ok(rerun.alarms >= 1);
  const copy = (await rowsOf(w.db)).find((r) => r.id === "rlt-copy000000000001");
  assert.notEqual(copy.revoked_at, null, "the copy is revoked");
  assert.equal(isLegacyStored(copy.token_hash) || String(copy.token_hash).startsWith("h1."), false, "and its value is freed");
  assert.equal((await resolveWith(w, w.token)).status, "ok", "the genuine link still opens");
});

test("M1: an uppercase and a lowercase legacy twin of one token convert without aborting; the live one survives", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  const b = await addRunLink(w, { runId: "rrn-00000000000000g1", sendId: "rsd-00000000000000g1" });
  // Two rows, one underlying token: lowercase (live) and its UPPERCASE twin (revoked).
  await w.db.execute({ sql: "UPDATE report_link_tokens SET token_hash = ? WHERE token_hash = ?", args: [hashToken(b.token), macToken(REPORT_LINK_FAMILY, b.token)] });
  await insertRow(w, { id: "rlt-twin0000000001", stored: hashToken(b.token).toUpperCase(), revokedAt: 7 });
  const boot = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal(boot.family.state, "converted", "no abort");
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at);
  assert.equal((await resolveWith(w, b.token)).status, "ok", "the live twin survives");
  const twin = (await rowsOf(w.db)).find((r) => r.id === "rlt-twin0000000001");
  assert.notEqual(twin.revoked_at, null);
});

test("L2: a mint that cannot compute its verifier leaves the send's current link alive and returns null", async () => {
  clock = T0;
  const home = newHome();
  const w = await world({ tier: "a" });
  assert.equal((await resolveWith(w, w.token)).status, "ok");
  // A lost key (the era is on record, so nothing recreates it).
  await runReportLinkTokenHmacBoot({ db: w.db });
  rmSync(join(home, "secrets", "token-hmac.key"));
  forgetTokenMacKey();
  const again = await mintLinkToken(w.db, linksDeps(w.runtime), {
    report: await getReport(w.db, w.report.id), recipient: w.recipient, run: { id: RUN }, sendId: SEND,
  });
  assert.equal(again, null, "the mint failed");
  const rows = await rowsOf(w.db);
  assert.equal(rows.length, 1, "no second row");
  assert.equal(rows[0].revoked_at, null, "the current link was NOT revoked");
});

/** A db whose reads of the era mirror throw a NON-"no such table" error (the bot's "unreadable mirror"). */
function withUnreadableMirror(db) {
  return new Proxy(db, {
    get(target, prop) {
      if (prop !== "execute") return target[prop];
      return (statement) => {
        const sql = String(typeof statement === "string" ? statement : statement?.sql ?? "");
        const args = Array.isArray(statement?.args) ? statement.args : [];
        if (/^\s*SELECT/i.test(sql) && args.some((a) => String(a).startsWith("token_hmac_era:"))) {
          throw new Error("disk I/O error (simulated)");
        }
        return target.execute(statement);
      };
    },
  });
}

const failingMark = async () => { throw new Error("state write failed (simulated)"); };
const adoptWithFailingMark = (family, opts) => adoptMirrorOnlyEra(family, { ...opts, mark: failingMark });
const { adoptMirrorOnlyEra } = await import("../servers/gateway/boot/token-hmac-era-adopt.js");

async function plantMirror(db) {
  const { eraSettingKey } = await import("../servers/shared/token-mac.js");
  const { writeSetting } = await import("../servers/gateway/dashboard/settings/registry.js");
  await writeSetting(db, eraSettingKey(REPORT_LINK_FAMILY), new Date().toISOString(), { scope: "local" });
}

/* ------------------------------------------------------------------------------------ round 3 */

test("M-A: a bot cannot pre-insert the tombstone value and make the conversion abort", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  const [genuine] = await rowsOf(w.db);
  await makeLegacy(w, [w.token]);
  await insertRow(w, { id: "rlt-twinU000000001", stored: hashToken(w.token).toUpperCase() });
  // The values the old (predictable) tombstone would have written.
  await insertRow(w, { id: "rlt-bait000000001", stored: `revoked:${genuine.id}` });
  await insertRow(w, { id: "rlt-bait000000002", stored: "revoked:rlt-twinU000000001" });
  const boot = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal(boot.family.state, "converted", "the boot did not abort");
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at);
  const rows = await rowsOf(w.db);
  assert.match(rows.find((r) => r.id === genuine.id).token_hash, H1, "the genuine lowercase row survives");
  assert.match(rows.find((r) => r.id === "rlt-twinU000000001").token_hash, /^revoked:rlt-twinU000000001:[0-9a-f]{16}$/);
  assert.equal((await resolveWith(w, w.token)).status, "ok");
  assert.equal(boot.converted, 1, "a tombstoned row is not counted as converted");
});

test("M-B: an unreadable mirror does not postpone the era: with no marker the boot converts and records it", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  await makeLegacy(w, [w.token]);
  const boot = await runReportLinkTokenHmacBoot({ db: withUnreadableMirror(w.db) });
  assert.equal(boot.family.state, "converted");
  assert.equal(boot.converted, 1);
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at, "the state file has the marker");
  assert.match((await rowsOf(w.db))[0].token_hash, H1);
});

test("M-B: a failed adoption write still takes the conversion path", async () => {
  clock = T0;
  newHome();
  const w = await world({ tier: "a" });
  await makeLegacy(w, [w.token]);
  await plantMirror(w.db);
  const boot = await runReportLinkTokenHmacBoot({ db: w.db, adoptEra: adoptWithFailingMark });
  assert.equal(boot.family.state, "converted");
  assert.equal(boot.converted, 1, "converted, not scanned");
  assert.ok(readState().families[REPORT_LINK_FAMILY]?.converted_at);
});

test("L-B: a pending snapshot beats adoption: its rows convert and the real count and file are recorded", async () => {
  clock = T0;
  const home = newHome();
  const w = await world({ tier: "a" });
  await makeLegacy(w, [w.token]);
  const failing = await runReportLinkTokenHmacBoot({
    db: w.db, runTransaction: async () => { throw new Error("simulated crash"); },
  });
  assert.equal(failing.family.state, "failed");
  const [snapshot] = reportSnapshots(home);
  await plantMirror(w.db);
  forgetForcedReportLinkLegacyRefusal();
  const boot = await runReportLinkTokenHmacBoot({ db: w.db });
  assert.equal(boot.converted, 1, "the snapshot's genuine row converted");
  const era = readState().families[REPORT_LINK_FAMILY];
  assert.equal(era.count, 1);
  assert.equal(era.rollback_file, snapshot);
  assert.equal((await resolveWith(w, w.token)).status, "ok");
});

for (const [name, genuineFirst] of [["a later rowid", true], ["an earlier rowid", false]]) {
  test(`L-C: of an upper/lowercase twin pair the LOWERCASE row survives, whatever the bot's row's order (${name})`, async () => {
    clock = T0;
    newHome();
    const w = await world({ tier: "a" });
    const [own] = await rowsOf(w.db);
    const legacy = hashToken(w.token);
    if (genuineFirst) {
      await w.db.execute({ sql: "UPDATE report_link_tokens SET token_hash = ? WHERE id = ?", args: [legacy, own.id] });
      await insertRow(w, { id: "rlt-botU0000000001", stored: legacy.toUpperCase() }); // live, later
    } else {
      await w.db.execute({ sql: "UPDATE report_link_tokens SET token_hash = ? WHERE id = ?", args: [legacy.toUpperCase(), own.id] });
      await insertRow(w, { id: "rlt-genuineL000001", stored: legacy });
    }
    const boot = await runReportLinkTokenHmacBoot({ db: w.db });
    assert.equal(boot.family.state, "converted");
    assert.equal(boot.converted, 1);
    const rows = await rowsOf(w.db);
    const upper = rows.find((r) => r.id === (genuineFirst ? "rlt-botU0000000001" : own.id));
    const lower = rows.find((r) => r.id === (genuineFirst ? own.id : "rlt-genuineL000001"));
    assert.match(lower.token_hash, H1, "the lowercase row converted and survives");
    assert.match(upper.token_hash, /^revoked:/, "the uppercase twin is the copy");
    assert.notEqual(upper.revoked_at, null);
  });
}
