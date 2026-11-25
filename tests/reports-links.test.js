// Where a report email's link points: the link kind a recipient's comment tier earns, the URL, and the
// token a public link carries.
//
// Harness: a real init-db'd scratch crow.db (so `project_spaces` is the real table, with its own slug
// column) copied per test, with the project rows a report names written by hand, the artifacts bundle's
// own tables added by its own `initArtifactsTables` (a version hold is a bundle row), real recipient
// seals through the approvals module, and the run, version and send rows written by hand so a test says
// exactly which version and which send a token opens. Nothing here sends anything and nothing starts a
// server.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { macToken } from "../servers/shared/token-mac.js";

const root = mkdtempSync(join(tmpdir(), "reports-links-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const BUNDLE = join(REPO, "bundles", "artifacts", "server");
const bundleImport = (f) => import(pathToFileURL(join(BUNDLE, f)).href);
const bundleStore = await bundleImport("store.js");
const { initArtifactsTables } = await bundleImport("init-tables.js");

const { createDbClient } = await import("../servers/db.js");
const {
  REPORTS_PUBLIC_ORIGIN_KEY, baseUrlOf, commentTierOf, hashToken, isAbsoluteHttpUrl, linkFor,
  mintLinkToken, projectSlug, publicLinkFor, publicOriginOf, reportPagePath, resolveLinkToken,
  revokeLinkTokens,
} = await import("../servers/gateway/reports/links.js");
const {
  approveRecipient, listRecipients, liveSetFor, proposeRecipient, revokeRecipient,
} = await import("../servers/gateway/reports/approvals.js");
const {
  createReport, getReport, saveRecipe, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { approvalSeal, newApprovalNonce } = await import("../servers/gateway/reports/seal.js");

const PROJECT = 7;
const BASE = "https://crow.example.ts.net";
const REPORT_ID = "rpt-0123456789abcdef";
const RUN_ID = "rrn-0123456789abcdef";
const OWNER = Object.freeze({ kind: "owner" });
const SEED = Buffer.alloc(32, 11);
const T0 = 1_700_000_000_000;
const DAY_MS = 86_400_000;
const ARTIFACT = "art-report-1";
const ORIGIN = "https://reports.example.com";
const RUN_A = "rrn-00000000000000a1";
const SEND_A = "rsd-00000000000000a1";
const RUN_B = "rrn-00000000000000b2";
const SEND_B = "rsd-00000000000000b2";

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
  // The artifacts tables are bundle-owned, so init-db does not make them: a version hold needs them.
  await initArtifactsTables(db);
  return db;
}

async function addProject(db, { id = PROJECT, slug = "weekly-listings" } = {}) {
  await db.execute({
    sql: "INSERT INTO project_spaces (id, uuid, slug, name) VALUES (?, ?, ?, ?)",
    args: [id, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", slug, slug],
  });
}

function reportRow(over = {}) {
  return {
    id: REPORT_ID,
    project_id: PROJECT,
    comment_tier_default: "c",
    ...over,
  };
}

function runRow(over = {}) {
  return { id: RUN_ID, reportId: REPORT_ID, status: "ok", ...over };
}

function recipientRow(over = {}) {
  return { id: "rrc-0123456789abcdef", state: "approved", commentTier: null, ...over };
}

/* ------------------------------------------------------- the token harness */

/** The approvals seam: a fixed seed and clock, and no secret values to scrub. */
function approvalsDeps(over = {}) {
  return { loadSeed: () => ({ seed: SEED }), now: () => T0, getSecrets: () => [], ...over };
}

/** The link seam: the real artifacts store (holds), the real approval seed, and a fixed clock. */
function linksDeps(over = {}) {
  return { artifacts: { store: bundleStore }, approvals: approvalsDeps(), now: () => T0, ...over };
}

async function createReportRow(db, { title = "Weekly listings" } = {}) {
  const { id } = await createReport(db, { projectId: PROJECT, owner: "owner", botId: "bot-1", title });
  return getReport(db, id);
}

/** A real approved recipient: `listRecipients` reports it `verified`, so a token can open it. */
async function approvedRecipient(db, reportId, { address = "alex@example.com", tier = null } = {}) {
  const proposed = await proposeRecipient(db, approvalsDeps(), {
    reportId, address, displayName: "Alex", commentTier: tier, proposedBy: "owner",
  });
  return approveRecipient(db, approvalsDeps(), { recipientId: proposed.id, actor: OWNER });
}

async function addRun(db, { id, reportId, trigger = "manual" }) {
  await db.execute({
    sql: `INSERT INTO report_runs (id, report_id, "trigger", requested_by, status, created_at)
          VALUES (?, ?, ?, 'owner', 'ok', ?)`,
    args: [id, reportId, trigger, T0],
  });
}

/** The artifact, its version and the run-to-version map row, which is what a token pins. */
async function addVersion(db, { artifactId = ARTIFACT, n, reportId, runId, trigger = "schedule" }) {
  await db.execute({
    sql: "INSERT OR IGNORE INTO artifacts (id, title, type) VALUES (?, 'Weekly listings', 'document')",
    args: [artifactId],
  });
  await db.execute({
    sql: `INSERT INTO artifact_versions (artifact_id, n, state, files_json, size, content_hash, made_by)
          VALUES (?, ?, 'past', '[]', 0, 'abc', 'user')`,
    args: [artifactId, n],
  });
  await db.execute({
    sql: `INSERT INTO report_versions (artifact_id, n, report_id, run_id, "trigger", allowed_links_json, created_at)
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

async function setOrigin(db, value) {
  await db.execute({
    sql: "INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES (?, ?)",
    args: [REPORTS_PUBLIC_ORIGIN_KEY, value],
  });
}

async function tokenRows(db) {
  return (await db.execute({
    sql: `SELECT id, report_id, recipient_id, run_id, send_id, artifact_id, version_n, token_hash,
                 scope, approval_nonce, created_at, revoked_at, expires_at
            FROM report_link_tokens ORDER BY created_at ASC, id ASC`,
    args: [],
  })).rows;
}

async function holdsFor(db, tokenId) {
  return (await db.execute({
    sql: "SELECT artifact_id, n, holder, until FROM artifact_version_holds WHERE holder = ?",
    args: [`report-link:${tokenId}`],
  })).rows;
}

/**
 * Seal one report live over the values its row holds now: the write `approveGoLive` makes, minus the
 * preview run and the sender a go-live insists on. A token only opens a report that is live over a seal
 * that still verifies (see THE REPORT'S OWN STANDING in links.js), so a test's world has to carry a real
 * seal or every resolve below would answer `unknown`.
 *
 * @param {object} db
 * @param {object} row the report row to seal (`id` and its current live-set values)
 * @returns {Promise<object>} the report row after the write
 */
async function goLive(db, row) {
  const saved = await saveRecipe(db, { reportId: row.id, recipe: { blocks: [] }, authorKind: "owner" });
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

/** One schedule row, which a live report's seal covers (`getSchedule` has to resolve it). */
async function addSchedule(db) {
  await db.execute({
    sql: `INSERT INTO schedules (task, cron_expression, tz)
          VALUES ('weekly-report', '0 7 * * 1', 'Europe/Berlin')`,
    args: [],
  });
  const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
  return Number(rows[0].id);
}

/**
 * One report, one approved recipient, one finished run with the version it wrote, and the send row that
 * mail went out in. The report is made LIVE (see `goLive`): a token of a draft report is `unknown`.
 */
async function world({
  tier = "b", address = "alex@example.com", versionN = 1, runId = RUN_A, sendId = SEND_A,
  trigger = "schedule",
} = {}) {
  const db = await freshDb();
  const scheduleId = await addSchedule(db);
  const draft = await createReportRow(db);
  await updateReportColumns(db, draft.id, { schedule_id: scheduleId });
  const report = await goLive(db, await getReport(db, draft.id));
  const recipient = await approvedRecipient(db, report.id, { address, tier });
  await addRun(db, { id: runId, reportId: report.id });
  await addVersion(db, { n: versionN, reportId: report.id, runId, trigger });
  await addSend(db, { id: sendId, runId, reportId: report.id, recipientId: recipient.id });
  return { db, report, recipient, runId, sendId, run: { id: runId, reportId: report.id } };
}

/** Mint one token for a world's own run and send, the way delivery will once it mints. */
function mintFor(w, over = {}, deps = null) {
  return mintLinkToken(w.db, deps ?? linksDeps(), {
    report: w.report, recipient: w.recipient, run: { id: w.runId }, sendId: w.sendId, ...over,
  });
}

/**
 * Move one approved recipient to another tier and RE-MAKE its seal over the tier it now holds, keeping its
 * approval nonce. That is the shape a stored row has when a tier moved under a live token: the seal covers
 * the tier, so a test that measures the SCOPE rule alone re-seals, while the nonce binding stays out of the
 * way (a real owner's tier change through `proposeRecipient` also issues a fresh nonce, which kills the
 * token a second way).
 */
async function retierRecipient(db, recipientId, tier) {
  const { rows } = await db.execute({
    sql: "SELECT id, report_id, address, approval_nonce FROM report_recipients WHERE id = ?",
    args: [recipientId],
  });
  const row = rows[0];
  assert.ok(row && row.approval_nonce, "the row carries the nonce the token is bound to");
  const seal = approvalSeal("recipient", {
    reportId: String(row.report_id),
    recipientId: String(row.id),
    address: String(row.address),
    commentTier: tier == null ? "" : tier,
    nonce: String(row.approval_nonce),
  }, SEED);
  await db.execute({
    sql: "UPDATE report_recipients SET comment_tier = ?, approval_seal = ? WHERE id = ?",
    args: [tier, seal, row.id],
  });
}

/** Mint for one world's own run and send, with the REPORT row as it stands now (a default may have moved). */
async function mintForReportNow(w) {
  return mintLinkToken(w.db, linksDeps(), {
    report: await getReport(w.db, w.report.id),
    recipient: w.recipient,
    run: { id: w.runId },
    sendId: w.sendId,
  });
}

/* ------------------------------------------------------------------------ the URL */

test("tier c gets the dashboard run page, with every odd character encoded", async () => {
  const db = await freshDb();
  await addProject(db);
  const link = await linkFor(db, {
    report: reportRow(),
    recipient: recipientRow(),
    run: runRow({ id: "rrn-a b/c?d#e" }),
    sendId: null,
    baseUrl: `${BASE}/`,
  });
  assert.deepEqual(link, {
    kind: "dashboard",
    url: `${BASE}/dashboard/project/weekly-listings/reports/${REPORT_ID}/runs/rrn-a%20b%2Fc%3Fd%23e`,
  });
});

test("tier c on a missing project row is no link at all", async () => {
  const db = await freshDb();
  await addProject(db);
  const link = await linkFor(db, {
    report: reportRow({ project_id: PROJECT + 1 }),
    recipient: recipientRow(),
    run: runRow(),
    baseUrl: BASE,
  });
  assert.equal(link, null, "a report whose project this instance does not have has no page");
  assert.equal(await projectSlug(db, reportRow({ project_id: null })), null, "no project, no slug");
});

test("tiers a and b have no link without a public origin, and the public kinds are the seam this fills", async () => {
  const db = await freshDb();
  await addProject(db);
  for (const tier of ["a", "b"]) {
    assert.equal(await linkFor(db, {
      report: reportRow(),
      recipient: recipientRow({ commentTier: tier }),
      run: runRow(),
      baseUrl: BASE,
    }), null, `tier ${tier}`);
  }
  assert.equal(await publicLinkFor(), null, "no database, no setting, no origin, no link");
  // The tier a reader has when their own row names none: the report's default, which may itself be a or b.
  assert.equal(await linkFor(db, {
    report: reportRow({ comment_tier_default: "a" }),
    recipient: recipientRow({ commentTier: null }),
    run: runRow(),
    baseUrl: BASE,
  }), null);
});

test("a recipient with no tier of their own takes the report's default", async () => {
  const db = await freshDb();
  await addProject(db);
  const link = await linkFor(db, {
    report: reportRow({ comment_tier_default: "c" }),
    recipient: recipientRow({ commentTier: null }),
    run: runRow(),
    baseUrl: BASE,
  });
  assert.equal(link.kind, "dashboard");

  // A stored (snake_case) recipient row reads the same way, and an empty tier is "the report's default".
  const stored = await linkFor(db, {
    report: reportRow(),
    recipient: { id: "rrc-0123456789abcdef", state: "approved", comment_tier: "" },
    run: runRow(),
    baseUrl: BASE,
  });
  assert.equal(stored.kind, "dashboard");
  assert.equal(commentTierOf(reportRow(), null), "c", "no recipient and no default is tier c");
  assert.equal(commentTierOf(reportRow({ comment_tier_default: "b" }), null), "b");
});

test("with no base URL there is no link at all: never a relative path in an email", async () => {
  const db = await freshDb();
  await addProject(db);
  const saved = process.env.CROW_GATEWAY_URL;
  const savedDashboard = process.env.CROW_DASHBOARD_URL;
  delete process.env.CROW_GATEWAY_URL;
  delete process.env.CROW_DASHBOARD_URL;
  try {
    // This instance's own row carries no address, so no base resolves anywhere.
    const link = await linkFor(db, {
      report: reportRow(),
      recipient: recipientRow(),
      run: runRow(),
      baseUrl: "",
    });
    assert.equal(link, null, "a mail client cannot open a path, so there is no link to mail");
    assert.equal(isAbsoluteHttpUrl("/dashboard/x"), false, "a path is still not a URL delivery may mail");
  } finally {
    if (saved !== undefined) process.env.CROW_GATEWAY_URL = saved;
    if (savedDashboard !== undefined) process.env.CROW_DASHBOARD_URL = savedDashboard;
  }
});

test("the base URL is the caller's, else this instance's own address, with trailing slashes trimmed", async () => {
  const db = await freshDb();
  await addProject(db);
  const saved = process.env.CROW_GATEWAY_URL;
  try {
    process.env.CROW_GATEWAY_URL = "https://crow.example.ts.net///";
    assert.equal(baseUrlOf(null), "https://crow.example.ts.net");
    const link = await linkFor(db, {
      report: reportRow(), recipient: recipientRow(), run: runRow(), baseUrl: null,
    });
    assert.ok(link.url.startsWith("https://crow.example.ts.net/dashboard/project/"), link.url);
    assert.equal(baseUrlOf("http://127.0.0.1:8080/"), "http://127.0.0.1:8080");
    assert.equal(baseUrlOf(undefined), "https://crow.example.ts.net", "the instance's own address is the fallback");
  } finally {
    if (saved === undefined) delete process.env.CROW_GATEWAY_URL;
    else process.env.CROW_GATEWAY_URL = saved;
  }
});

test("only an absolute http or https URL is a link delivery may mail", () => {
  for (const good of ["https://crow.example.ts.net/x", "http://127.0.0.1:8080/x", " https://a.example/x "]) {
    assert.equal(isAbsoluteHttpUrl(good), true, good);
  }
  for (const bad of ["/dashboard/x", "", null, undefined, 7, "javascript:alert(1)", "mailto:alex@example.com",
    "//crow.example.ts.net/x", "ftp://crow.example.ts.net/x", "not a url"]) {
    assert.equal(isAbsoluteHttpUrl(bad), false, String(bad));
  }
});

/* --------------------------------------------------------------- the report's page */

test("the owner's notice for a report goes to its page, or the reports list", async () => {
  const db = await freshDb();
  await addProject(db);
  assert.equal(await reportPagePath(db, reportRow()), `/dashboard/project/weekly-listings/reports/${REPORT_ID}`);
  assert.equal(await reportPagePath(db, reportRow({ project_id: 999 })), "/dashboard/reports");
  assert.equal(await reportPagePath(db, null), "/dashboard/reports");
});

/* --------------------------------------------------------------- the tokens */

test("a token cannot reach a preview version", async () => {
  const w = await world();
  // A run whose only version is a preview has nothing a recipient may be shown, so no token exists for it.
  const previewRun = RUN_B;
  const previewSend = SEND_B;
  await addRun(w.db, { id: previewRun, reportId: w.report.id, trigger: "preview" });
  await addVersion(w.db, { n: 2, reportId: w.report.id, runId: previewRun, trigger: "preview" });
  await addSend(w.db, {
    id: previewSend, runId: previewRun, reportId: w.report.id, recipientId: w.recipient.id,
  });
  assert.equal(await mintLinkToken(w.db, linksDeps(), {
    report: w.report, recipient: w.recipient, run: { id: previewRun }, sendId: previewSend,
  }), null, "no version a recipient may be shown, no token");
  assert.equal((await tokenRows(w.db)).length, 0, "and no row was written for it");

  // A hand-written row pointing at that same preview run resolves to nothing, even though its send went.
  const forged = randomBytes(32).toString("base64url");
  await w.db.execute({
    sql: `INSERT INTO report_link_tokens
            (id, report_id, recipient_id, run_id, send_id, artifact_id, version_n, token_hash, scope,
             approval_nonce, created_at, expires_at)
          VALUES ('rlt-forged0000000001', ?, ?, ?, ?, ?, 2, ?, 'view', ?, ?, ?)`,
    args: [w.report.id, w.recipient.id, previewRun, previewSend, ARTIFACT, hashToken(forged),
      "e".repeat(32), T0, T0 + DAY_MS],
  });
  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), forged), { status: "unknown" });
});

test("a token opens exactly its own version", async () => {
  const w = await world({ versionN: 1, runId: RUN_A, sendId: SEND_A });
  // A later run of the same report and the same recipient writes version 2 of the same artifact.
  await addRun(w.db, { id: RUN_B, reportId: w.report.id });
  await addVersion(w.db, { n: 2, reportId: w.report.id, runId: RUN_B });
  await addSend(w.db, {
    id: SEND_B, runId: RUN_B, reportId: w.report.id, recipientId: w.recipient.id,
  });

  const first = await mintFor(w);
  const second = await mintFor(w, { run: { id: RUN_B }, sendId: SEND_B });
  assert.ok(first && second, "one token per send");
  assert.notEqual(first.tokenId, second.tokenId, "two runs are two rows");

  const opened = await resolveLinkToken(w.db, linksDeps(), first.token);
  assert.equal(opened.status, "ok");
  assert.equal(opened.token.artifactId, ARTIFACT);
  assert.equal(opened.token.versionN, 1, "the first run's own version");
  assert.equal(opened.token.runId, RUN_A);
  assert.equal(opened.token.sendId, SEND_A);

  const later = await resolveLinkToken(w.db, linksDeps(), second.token);
  assert.equal(later.status, "ok");
  assert.equal(later.token.versionN, 2, "the second run's own version");

  // The older mail is not rewritten by a newer version existing: it still opens the version it was sent for.
  const again = await resolveLinkToken(w.db, linksDeps(), first.token);
  assert.equal(again.status, "ok");
  assert.equal(again.token.versionN, 1);
  const [held] = await holdsFor(w.db, first.tokenId);
  assert.equal(held.artifact_id, ARTIFACT, "the older version stays held for its own link");
  assert.equal(held.n, 1);

  // The version is STORED on the token row, never re-derived from its run: a later version the same run
  // maps to (written by hand here) cannot move a page that is already in somebody's inbox.
  await addVersion(w.db, { n: 3, reportId: w.report.id, runId: RUN_A });
  const stored = await resolveLinkToken(w.db, linksDeps(), first.token);
  assert.equal(stored.status, "ok", "the link still opens after its run gained a newer version");
  assert.equal(stored.token.versionN, 1, "and it opens the version the mint stored, not the newest");
});

test("a token whose send failed is unknown", async () => {
  const w = await world();
  const minted = await mintFor(w);
  for (const status of ["failed", "refused", "sending", "pending"]) {
    await w.db.execute({
      sql: "UPDATE report_sends SET status = ? WHERE id = ?",
      args: [status, w.sendId],
    });
    assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), minted.token), { status: "unknown" },
      `a ${status} send never had a working link in front of a reader`);
  }
  // A mail that went, and one nobody can decide about, are the two a reader may open.
  for (const status of ["sent", "unknown"]) {
    await w.db.execute({
      sql: "UPDATE report_sends SET status = ? WHERE id = ?",
      args: [status, w.sendId],
    });
    const opened = await resolveLinkToken(w.db, linksDeps(), minted.token);
    assert.equal(opened.status, "ok", status);
    assert.equal(opened.token.id, minted.tokenId);
  }
  // A missing send row is no better than a failed one.
  await w.db.execute({ sql: "DELETE FROM report_sends WHERE id = ?", args: [w.sendId] });
  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), minted.token), { status: "unknown" });
});

test("revoked recipient: every token is unknown on the next resolve", async () => {
  const w = await world();
  const minted = await mintFor(w);
  assert.equal((await holdsFor(w.db, minted.tokenId)).length, 1, "a live token holds its version");

  // The owner's own revoke path, with the artifacts runtime mounted so the hold release reaches the store.
  await revokeRecipient(w.db, { ...approvalsDeps(), artifacts: { store: bundleStore } }, {
    recipientId: w.recipient.id, actor: OWNER,
  });

  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), minted.token), { status: "unknown" });
  const [row] = await tokenRows(w.db);
  assert.ok(row.revoked_at != null, "the token row is stamped revoked, never deleted");
  assert.equal((await holdsFor(w.db, minted.tokenId)).length, 0, "and its version hold is released");
});

test("a recipient re-approved by direct UPDATE stays unknown", async () => {
  const w = await world();
  await mintFor(w);
  await revokeRecipient(w.db, { ...approvalsDeps(), artifacts: { store: bundleStore } }, {
    recipientId: w.recipient.id, actor: OWNER,
  });
  // The seal and its nonce were NULLed by the revoke; flipping only the state word back is not an approval.
  await w.db.execute({
    sql: "UPDATE report_recipients SET state = 'approved' WHERE id = ?",
    args: [w.recipient.id],
  });
  const minted = await mintFor(w);
  assert.equal(minted, null, "a row with no nonce is no approval to bind a token to");
  const [listed] = await listRecipients(w.db, w.report.id, approvalsDeps());
  assert.equal(listed.state, "approved");
  assert.equal(listed.verified, false, "the seal check is what says so");
});

test("expired token resolves expired and releases its hold", async () => {
  const w = await world();
  await w.db.execute({
    sql: "INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('reports.link_days', '1')",
    args: [],
  });
  const minted = await mintFor(w);
  assert.equal(minted.expiresAt, T0 + DAY_MS, "the link lasts the instance's own reports.link_days");
  assert.equal((await holdsFor(w.db, minted.tokenId)).length, 1);

  const later = { ...linksDeps(), now: () => T0 + 2 * DAY_MS };
  assert.deepEqual(await resolveLinkToken(w.db, later, minted.token), { status: "expired" });
  assert.equal((await holdsFor(w.db, minted.tokenId)).length, 0, "the hold goes with the expiry");
  const [row] = await tokenRows(w.db);
  assert.equal(row.revoked_at, null, "an expired link is not a revoked one: the row is kept, unstamped");

  // Resolving it again is the same answer, so the release is idempotent.
  assert.deepEqual(await resolveLinkToken(w.db, later, minted.token), { status: "expired" });
});

test("a stored token_hash sent as the token is unknown", async () => {
  const w = await world();
  const minted = await mintFor(w);
  const [row] = await tokenRows(w.db);
  assert.match(row.token_hash, /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/, "the stored verifier is the keyed form");
  assert.equal(row.token_hash, macToken("report:link", minted.token));
  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), row.token_hash), { status: "unknown" },
    "a hash is not a token: it hashes to something else");
  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), minted.token.slice(0, 42)), { status: "unknown" });
  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), ""), { status: "unknown" });
  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), null), { status: "unknown" });
});

test("raw token is never stored", async () => {
  const w = await world();
  const minted = await mintFor(w);
  // A comment written through that link, so the scan covers both tables a reader can reach.
  await w.db.execute({
    sql: `INSERT INTO report_recipient_comments
            (comment_id, thread_id, report_id, recipient_id, run_id, via, created_at)
          VALUES (41, '9', ?, ?, ?, 'link', ?)`,
    args: [w.report.id, w.recipient.id, w.runId, T0],
  });

  const columns = {
    report_link_tokens: [
      "id", "report_id", "recipient_id", "run_id", "send_id", "artifact_id", "version_n",
      "token_hash", "scope", "approval_nonce", "created_at", "revoked_at", "expires_at",
    ],
    report_recipient_comments: [
      "comment_id", "thread_id", "report_id", "recipient_id", "run_id", "via", "created_at",
    ],
  };
  for (const [table, names] of Object.entries(columns)) {
    const { rows } = await w.db.execute({ sql: `SELECT ${names.join(", ")} FROM ${table}`, args: [] });
    assert.equal(rows.length, 1, `${table} has the one row this test made`);
    for (const row of rows) {
      for (const [name, value] of Object.entries(row)) {
        const dump = typeof value === "string" ? value : JSON.stringify(value ?? null);
        assert.equal(dump.includes(minted.token), false, `${table}.${name} holds no raw token`);
      }
    }
  }
  const [row] = await tokenRows(w.db);
  assert.equal(row.token_hash, macToken("report:link", minted.token), "the token column is the keyed verifier and nothing else");
});

test("mint is per send: a second mint for the same send revokes the first", async () => {
  const w = await world();
  const first = await mintFor(w);
  const second = await mintFor(w);
  assert.ok(second, "a retried send mints again");
  assert.notEqual(second.token, first.token, "a fresh token every mint");
  assert.notEqual(second.tokenId, first.tokenId, "a mint writes a fresh row: the old one is the send's log");
  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), first.token), { status: "unknown" },
    "the token the retry replaced never opens anything again");
  assert.equal((await resolveLinkToken(w.db, linksDeps(), second.token)).status, "ok");

  const rows = await tokenRows(w.db);
  assert.equal(rows.length, 2, "both rows are kept: revoking is a stamp, never a delete");
  const byId = new Map(rows.map((row) => [row.id, row]));
  assert.ok(byId.get(first.tokenId).revoked_at != null, "the replaced token is stamped revoked");
  assert.equal(byId.get(second.tokenId).revoked_at, null, "and only the new one is live");
  assert.equal((await holdsFor(w.db, first.tokenId)).length, 0, "the dead link's hold is released");
  assert.equal((await holdsFor(w.db, second.tokenId)).length, 1, "one hold, for the live token");

  // The explicit door: a report's own tokens, idempotent on the second call.
  assert.equal(await revokeLinkTokens(w.db, linksDeps(), { reportId: w.report.id, sendId: SEND_A }), 1);
  assert.equal(await revokeLinkTokens(w.db, linksDeps(), { reportId: w.report.id, sendId: SEND_A }), 0);
  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), second.token), { status: "unknown" });
  assert.equal((await holdsFor(w.db, second.tokenId)).length, 0);
  await assert.rejects(() => revokeLinkTokens(w.db, linksDeps(), {}), (err) => {
    assert.equal(err.code, "bad_input");
    return true;
  });
});

test("scope is comment for tier a and view for tier b", async () => {
  for (const [tier, scope, kind] of [["a", "comment", "public-comment"], ["b", "view", "public-view"]]) {
    const w = await world({ tier, address: `${tier}@example.com` });
    await setOrigin(w.db, ORIGIN);
    const minted = await mintFor(w);
    assert.equal(minted.scope, scope, `tier ${tier}`);
    const [row] = await tokenRows(w.db);
    assert.equal(row.scope, scope, "the row stores the scope it was minted for");
    assert.equal(row.artifact_id, ARTIFACT, "and the artifact version it opens");
    assert.equal(row.version_n, 1);
    const opened = await resolveLinkToken(w.db, linksDeps(), minted.token);
    assert.equal(opened.status, "ok");
    assert.equal(opened.token.scope, scope, "the resolve reads the scope back from the row");
    const link = await linkFor(w.db, {
      report: w.report, recipient: w.recipient, run: { id: w.runId }, sendId: null, deps: linksDeps(),
    });
    assert.equal(link.kind, kind, "and the link a probe answers names the page the scope opens");
  }
});

/* ------------------------------------------------- the scope and the approval it is bound to */

test("a comment token whose recipient drops to tier b can view but not comment", async () => {
  const w = await world({ tier: "a" });
  const minted = await mintFor(w);
  assert.equal(minted.scope, "comment");
  assert.equal((await resolveLinkToken(w.db, linksDeps(), minted.token)).token.scope, "comment");

  // The recipient's own tier, lowered to b. The row keeps its nonce, so only the tier in force moved.
  await retierRecipient(w.db, w.recipient.id, "b");
  const view = await resolveLinkToken(w.db, linksDeps(), minted.token);
  assert.equal(view.status, "ok", "the page still opens");
  assert.equal(view.token.scope, "view", "but a tier b reader may only view");
  assert.equal(view.token.storedScope, "comment", "the row still says what the mail was minted as");

  // The same lowering through the REPORT default, for a recipient that has no tier of its own.
  const d = await world({ tier: null, address: "sam@example.com" });
  await d.db.execute({
    sql: "UPDATE reports SET comment_tier_default = 'a' WHERE id = ?", args: [d.report.id],
  });
  const byDefault = await mintForReportNow(d);
  assert.equal(byDefault.scope, "comment", "the report default gave the comment page");
  await d.db.execute({
    sql: "UPDATE reports SET comment_tier_default = 'b' WHERE id = ?", args: [d.report.id],
  });
  const lowered = await resolveLinkToken(d.db, linksDeps(), byDefault.token);
  assert.equal(lowered.status, "ok");
  assert.equal(lowered.token.scope, "view", "the lowered default narrows the link too");
});

test("a comment token whose recipient drops to tier c is unknown", async () => {
  const w = await world({ tier: "a" });
  const minted = await mintFor(w);
  assert.equal(minted.scope, "comment");
  await retierRecipient(w.db, w.recipient.id, "c");
  assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), minted.token), { status: "unknown" },
    "tier c has no public page, so the link is as dead as one that never existed");

  // The report's own default is the other way a recipient with no tier of their own loses their page.
  const d = await world({ tier: null, address: "sam@example.com" });
  await d.db.execute({
    sql: "UPDATE reports SET comment_tier_default = 'a' WHERE id = ?", args: [d.report.id],
  });
  const byDefault = await mintForReportNow(d);
  assert.equal(byDefault.scope, "comment");
  await d.db.execute({
    sql: "UPDATE reports SET comment_tier_default = 'c' WHERE id = ?", args: [d.report.id],
  });
  assert.deepEqual(await resolveLinkToken(d.db, linksDeps(), byDefault.token), { status: "unknown" });
});

test("a view token never rises to comment when the tier is raised to a", async () => {
  const w = await world({ tier: "b" });
  const minted = await mintFor(w);
  assert.equal(minted.scope, "view");
  await retierRecipient(w.db, w.recipient.id, "a");
  const raised = await resolveLinkToken(w.db, linksDeps(), minted.token);
  assert.equal(raised.status, "ok", "the link still opens its page");
  assert.equal(raised.token.scope, "view", "a stored view token stays a view token");
  assert.equal(raised.token.storedScope, "view");
});

test("tokens minted before a revoke and re-approve are unknown even when revokeLinkTokens throws",
  async () => {
    const w = await world({ tier: "a" });
    const before = await mintFor(w);
    assert.equal((await resolveLinkToken(w.db, linksDeps(), before.token)).status, "ok");

    // The explicit sweep a refusal or a revocation runs cannot land: the seam is stubbed to throw, which
    // is exactly the failure the nonce binding has to cover on its own.
    const broken = {
      ...approvalsDeps(),
      artifacts: { store: bundleStore },
      revokeLinkTokens: async () => { throw new Error("the link log would not move"); },
    };
    await revokeRecipient(w.db, broken, { recipientId: w.recipient.id, actor: OWNER });
    const [stamped] = await tokenRows(w.db);
    assert.equal(stamped.revoked_at, null, "the stubbed sweep really left the token row live");

    // The owner re-approves the recipient: a fresh nonce and a fresh seal over the same row.
    await approveRecipient(w.db, approvalsDeps(), { recipientId: w.recipient.id, actor: OWNER });
    const current = (await w.db.execute({
      sql: "SELECT approval_nonce FROM report_recipients WHERE id = ?", args: [w.recipient.id],
    })).rows[0].approval_nonce;
    assert.notEqual(current, stamped.approval_nonce, "the re-approval wrote a new nonce");

    assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), before.token), { status: "unknown" },
      "the old token names the nonce the re-approval replaced");

    // A token minted after the re-approval is bound to the fresh nonce and opens.
    const after = await mintFor(w);
    assert.ok(after);
    const opened = await resolveLinkToken(w.db, linksDeps(), after.token);
    assert.equal(opened.status, "ok");
    assert.equal(opened.token.scope, "comment");
  });

test("a token whose stored approval_nonce differs from the recipient's current nonce is unknown",
  async () => {
    const w = await world({ tier: "b" });
    const minted = await mintFor(w);
    const [row] = await tokenRows(w.db);
    assert.match(row.approval_nonce, /^[0-9a-f]{32}$/, "the row is bound to an approval nonce");
    await w.db.execute({
      sql: "UPDATE report_link_tokens SET approval_nonce = ? WHERE id = ?",
      args: ["0".repeat(32), row.id],
    });
    assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), minted.token), { status: "unknown" },
      "a token bound to another approval opens nothing");
  });

test("mint stores the recipient's current approval nonce", async () => {
  const w = await world({ tier: "a" });
  const current = (await w.db.execute({
    sql: "SELECT approval_nonce FROM report_recipients WHERE id = ?", args: [w.recipient.id],
  })).rows[0].approval_nonce;
  assert.match(current, /^[0-9a-f]{32}$/);
  await mintFor(w);
  const [row] = await tokenRows(w.db);
  assert.equal(row.approval_nonce, current, "the token is bound to the approval the recipient holds now");

  // A row whose nonce was NULLed (never approved, or revoked and not re-approved since) has no approval to
  // bind to, so nothing is minted and no row is written.
  const other = await world({ tier: "a", address: "sam@example.com" });
  await other.db.execute({
    sql: "UPDATE report_recipients SET approval_nonce = NULL WHERE id = ?", args: [other.recipient.id],
  });
  assert.equal(await mintFor(other), null, "no approval nonce, no token");
  assert.equal((await tokenRows(other.db)).length, 0, "and no row was written for it");
});

test("publicOriginOf accepts only a clean https origin", async () => {
  const db = await freshDb();
  // Unset, blank, and a row that is not a URL at all.
  assert.equal(await publicOriginOf(db), null, "unset");
  for (const value of ["", "   ", "not a url", "reports.example.com"]) {
    await setOrigin(db, value);
    assert.equal(await publicOriginOf(db), null, JSON.stringify(value));
  }
  await setOrigin(db, ORIGIN);
  assert.equal(await publicOriginOf(db), ORIGIN, "a bare https origin");
  await setOrigin(db, `${ORIGIN}/`);
  assert.equal(await publicOriginOf(db), ORIGIN, "a trailing slash is the same origin");
  for (const bad of [
    "http://reports.example.com",
    `${ORIGIN}/r`,
    `${ORIGIN}/?a=1`,
    `${ORIGIN}/#top`,
    "https://example-user:example-pass@reports.example.com",
    "ftp://reports.example.com",
    "javascript:alert(1)",
  ]) {
    await setOrigin(db, bad);
    assert.equal(await publicOriginOf(db), null, bad);
  }
});

test("publicLinkFor is null without an origin and a link with one", async () => {
  const w = await world({ tier: "a" });
  const ask = (sendId) => linkFor(w.db, {
    report: w.report, recipient: w.recipient, run: { id: w.runId }, sendId, deps: linksDeps(),
  });
  // No setting: a tier a or b recipient has no link, exactly as before the tokens existed.
  assert.equal(await ask(null), null);
  assert.equal(await ask(w.sendId), null);
  assert.equal((await tokenRows(w.db)).length, 0, "and nothing was minted trying");

  await setOrigin(w.db, ORIGIN);
  // The probe (the go-live check and delivery's pre-claim question) says a link can be made, and writes nothing.
  assert.deepEqual(await ask(null), { kind: "public-comment", url: `${ORIGIN}/r/` });
  assert.equal((await tokenRows(w.db)).length, 0, "a probe mints nothing");

  const link = await ask(w.sendId);
  assert.equal(link.kind, "public-comment");
  assert.ok(link.url.startsWith(`${ORIGIN}/r/`), link.url);
  const raw = link.url.slice(`${ORIGIN}/r/`.length);
  assert.match(raw, /^[A-Za-z0-9_-]{43}$/, "a 32 byte token, base64url");
  assert.equal(link.url.includes("?"), false);

  const rows = await tokenRows(w.db);
  assert.equal(rows.length, 1, "one row for one sent link");
  const holds = await holdsFor(w.db, rows[0].id);
  assert.equal(holds.length, 1, "the version the link opens is held");
  assert.equal(holds[0].artifact_id, ARTIFACT);
  assert.equal(holds[0].n, 1);
  assert.ok(holds[0].until, "until the link runs out");

  // Tier b asks for the view page, minted the same way.
  const view = await world({ tier: "b", address: "sam@example.com" });
  await setOrigin(view.db, ORIGIN);
  const viewLink = await linkFor(view.db, {
    report: view.report, recipient: view.recipient, run: { id: view.runId }, sendId: null, deps: linksDeps(),
  });
  assert.deepEqual(viewLink, { kind: "public-view", url: `${ORIGIN}/r/` });
});

test("mint failure throws link_mint_failed without the token", async () => {
  const w = await world();
  await setOrigin(w.db, ORIGIN);

  // A run with no version a recipient may be shown cannot mint anything.
  await assert.rejects(
    () => linkFor(w.db, {
      report: w.report, recipient: w.recipient, run: { id: "rrn-00000000000000ff" }, sendId: SEND_B,
      deps: linksDeps(),
    }),
    (err) => {
      assert.equal(err.code, "link_mint_failed");
      assert.equal(err.message, "link_mint_failed", "the message names no token");
      return true;
    },
  );
  assert.equal((await tokenRows(w.db)).length, 0);

  // A hold that will not take is the same answer, and the token it had made is revoked again.
  const failing = linksDeps({ holdVersion: async () => { throw new Error("no hold for this version"); } });
  await assert.rejects(
    () => linkFor(w.db, {
      report: w.report, recipient: w.recipient, run: { id: w.runId }, sendId: w.sendId, deps: failing,
    }),
    (err) => {
      assert.equal(err.code, "link_mint_failed");
      assert.doesNotMatch(err.message, /[A-Za-z0-9_-]{43}/, "no raw token in the error");
      return true;
    },
  );
  for (const row of await tokenRows(w.db)) {
    assert.ok(row.revoked_at != null, "a token whose version could not be held is revoked, not handed out");
  }
});

/* ----------------------------------- the report's own standing: live, paused, or nothing */
//
// A link in a mail is a promise about an APPROVED report. The token's own bindings say which version and
// which recipient it opens; the report's status says whether there is a report a reader may act on at all.
// `live` over a seal that still verifies behaves as every other test above says, `paused` keeps the page
// readable and takes no comment, and any other word is the same 404 an unknown token gets.

test("live: the token opens its version with the comment scope", async () => {
  const w = await world({ tier: "a" });
  assert.equal(w.report.status, "live");
  const minted = await mintFor(w);
  const opened = await resolveLinkToken(w.db, linksDeps(), minted.token);
  assert.equal(opened.status, "ok");
  assert.equal(opened.token.scope, "comment", "a live report's tier a link still takes comments");
  assert.equal(opened.report.id, w.report.id);
});

test("paused: the token opens the report as view only", async () => {
  const w = await world({ tier: "a" });
  const minted = await mintFor(w);
  // The owner's own pause: the status word moves and the seal STAYS (that is what makes a resume provable).
  await w.db.execute({ sql: "UPDATE reports SET status = 'paused' WHERE id = ?", args: [w.report.id] });

  const opened = await resolveLinkToken(w.db, linksDeps(), minted.token);
  assert.equal(opened.status, "ok", "a paused report's page is still readable");
  assert.equal(opened.token.scope, "view", "but it takes no comment any more");
  assert.equal(opened.token.storedScope, "comment", "the row still says what the mail was minted as");
  assert.equal(opened.token.versionN, 1, "and it still opens exactly the version the mail carried");
});

test("live by status over a broken seal is read as paused", async () => {
  const w = await world({ tier: "a" });
  const minted = await mintFor(w);
  // A direct UPDATE of a live-set column: the word still says live, the approval behind it is gone.
  await w.db.execute({
    sql: "UPDATE reports SET delivery_mode = 'email_full' WHERE id = ?",
    args: [w.report.id],
  });
  assert.equal((await getReport(w.db, w.report.id)).status, "live", "the status word never moved");

  const opened = await resolveLinkToken(w.db, linksDeps(), minted.token);
  assert.equal(opened.status, "ok");
  assert.equal(opened.token.scope, "view", "an unsealed report takes no comment");
  assert.equal(opened.token.storedScope, "comment");
});

test("a draft, an archived report or any other status word is unknown", async () => {
  const w = await world({ tier: "a" });
  const minted = await mintFor(w);
  for (const word of ["draft", "archived", ""]) {
    await w.db.execute({ sql: "UPDATE reports SET status = ? WHERE id = ?", args: [word, w.report.id] });
    assert.deepEqual(await resolveLinkToken(w.db, linksDeps(), minted.token), { status: "unknown" },
      `${JSON.stringify(word)} is not a report a mailed link may open`);
  }

  // Back to live: the very same token opens again, because nothing about the link itself changed.
  await w.db.execute({ sql: "UPDATE reports SET status = 'live' WHERE id = ?", args: [w.report.id] });
  const opened = await resolveLinkToken(w.db, linksDeps(), minted.token);
  assert.equal(opened.status, "ok");
  assert.equal(opened.token.scope, "comment");
});