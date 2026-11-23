// The public reports door: the page a mailed link opens, the comment box on it, and the little
// newline-JSON listener a later PR's systemd unit hands a socket fd to.
//
// Harness: a real init-db'd scratch crow.db (the reports tables are init-db's own) copied per test, the
// artifacts bundle's own tables and blob store (a document version with a readable index.html, written by
// the bundle's own `createArtifact`), a real approved recipient and a real token through `mintLinkToken`,
// the bundle's `comments.js` as the `deps.comments` seam, and the keychain seed injected through the same
// `loadSeed` seam `approvals.js` uses. The handler is called with plain objects (no socket) except in the
// socket tests, which listen on a unix socket inside this test's own temp directory.
//
// Everything a reader sees is the fixed wording in `recipient-copy.js`, so the assertions quote it
// rather than re-typing it.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { once } from "node:events";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = mkdtempSync(join(tmpdir(), "reports-public-door-"));
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
const {
  REPORTS_DOOR_SOCKET_UNIT, closeDoorServer, createDoorHandler, createDoorServer, listenDoor,
  startActivatedDoor,
} = await import("../servers/gateway/reports/public-door.js");
const { PROXY_SOCKET_UNIT, pickActivatedFd } = await import("../servers/gateway/proxy-socket.js");
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

async function freshDb() {
  const dir = join(root, "t" + (++copies));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
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

/* ------------------------------------------------------------------------- view */

test("view: a valid token returns the recipient view", async () => {
  clock = T0;
  const comment = await world({ tier: "a" });
  const reply = await handlerFor(comment)({ op: "view", token: comment.token });
  assert.equal(reply.status, 200);
  assert.ok(reply.html.startsWith("<!doctype html>"), "one complete page");
  assert.ok(reply.html.includes(DOC_TEXT), "the stored document is on it");
  assert.ok(reply.html.includes('method="post"'), "a comment-scope link gets the form");
  assert.ok(reply.html.includes('name="formNonce" value="'), "and a form nonce");
  assert.equal(nonceIn(reply.html), formNonceFor(hashToken(comment.token), SEED, clock),
    "the nonce is this instance's, for this token, in this window");
  assert.ok(reply.html.includes(`<h2>${copyFor("en").commentsHeading}</h2>`));

  const view = await world({ tier: "b", address: "sam@example.com" });
  const viewReply = await handlerFor(view)({ op: "view", token: view.token });
  assert.equal(viewReply.status, 200);
  assert.ok(viewReply.html.includes(DOC_TEXT));
  assert.ok(!viewReply.html.includes('name="formNonce"'), "a view-scope link carries no nonce");
  assert.ok(!viewReply.html.includes('class="comment-form"'), "and no form");
});

test("view: unknown, revoked, malformed and stored-hash tokens are 404 with the same page", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  const handler = handlerFor(w);
  const shaped = "Z".repeat(43);

  const pages = [];
  const unknown = await handler({ op: "view", token: shaped });
  assert.equal(unknown.status, 404);
  pages.push(unknown.html);
  pages.push((await handler({ op: "view", token: "abc" })).html);
  pages.push((await handler({ op: "view", token: hashToken(w.token) })).html);
  pages.push((await handler({ op: "view", token: `${shaped}?v=1` })).html);
  pages.push((await handler({ op: "view", token: `${shaped}/x` })).html);
  pages.push((await handler({ op: "view", token: `${"a".repeat(42)}=` })).html);
  pages.push((await handler({ op: "view", token: ` ${shaped} ` })).html);
  pages.push((await handler({ op: "view", token: 7 })).html);
  pages.push((await handler({ op: "view" })).html);

  // A token that really existed and was revoked: the same page, byte for byte, as one that never was.
  await revokeLinkTokens(w.db, linksDeps(w.runtime), { reportId: w.report.id });
  const revoked = await handler({ op: "view", token: w.token });
  assert.equal(revoked.status, 404);
  pages.push(revoked.html);

  for (const html of pages) {
    assert.equal(html, pages[0], "every refusal is the one fixed page");
  }
  assert.ok(pages[0].includes(copyFor("en").unknownLink));
  assert.doesNotMatch(pages[0], /<script/i);
});

test("view: expired token is 410 with the expired page", async () => {
  clock = T0;
  const w = await world({ tier: "a", linkDays: 1 });
  assert.equal(w.minted.expiresAt, T0 + DAY_MS);
  clock = T0 + 2 * DAY_MS;
  try {
    const reply = await handlerFor(w)({ op: "view", token: w.token });
    assert.equal(reply.status, 410);
    assert.ok(reply.html.includes(copyFor("en").expired));
    assert.ok(!reply.html.includes(DOC_TEXT), "nothing of the report is shown");
  } finally {
    clock = T0;
  }
});

test("view: preview-run token, failed-send token, revoked-recipient token are 404", async () => {
  clock = T0;

  // A hand-written token row pointing at a preview run: a preview is unapproved text, never a page.
  const preview = await world({ tier: "a" });
  await addRun(preview.db, { id: PREVIEW_RUN, reportId: preview.report.id, trigger: "preview" });
  await addVersionRow(preview.db, {
    artifactId: preview.artifactId, n: preview.versionN + 1, reportId: preview.report.id,
    runId: PREVIEW_RUN, trigger: "preview",
  });
  await addSend(preview.db, {
    id: PREVIEW_SEND, runId: PREVIEW_RUN, reportId: preview.report.id,
    recipientId: preview.recipient.id,
  });
  const raw = randomBytes(32).toString("base64url");
  await preview.db.execute({
    sql: `INSERT INTO report_link_tokens
            (id, report_id, recipient_id, run_id, send_id, artifact_id, version_n, token_hash, scope,
             approval_nonce, created_at, expires_at)
          VALUES ('rlt-preview0000000001', ?, ?, ?, ?, ?, ?, ?, 'view', ?, ?, ?)`,
    args: [preview.report.id, preview.recipient.id, PREVIEW_RUN, PREVIEW_SEND, preview.artifactId,
      preview.versionN + 1, hashToken(raw), await currentNonce(preview.db, preview.recipient.id),
      T0, T0 + DAY_MS],
  });
  assert.equal((await handlerFor(preview)({ op: "view", token: raw })).status, 404);

  // A send that failed never put a working link in front of a reader.
  const failed = await world({ tier: "a", address: "sam@example.com" });
  await failed.db.execute({
    sql: "UPDATE report_sends SET status = 'failed' WHERE id = ?", args: [SEND],
  });
  assert.equal((await handlerFor(failed)({ op: "view", token: failed.token })).status, 404);

  // A revoked recipient: its approval nonce is gone, so every token minted for it is dead.
  const revoked = await world({ tier: "a", address: "kim@example.com" });
  await revokeRecipient(revoked.db, { ...approvalsDeps(), artifacts: revoked.runtime }, {
    recipientId: revoked.recipient.id, actor: OWNER,
  });
  assert.equal((await handlerFor(revoked)({ op: "view", token: revoked.token })).status, 404);
});

test("view: es Accept-Language renders the Spanish page", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  const reply = await handlerFor(w)({
    op: "view", token: w.token, acceptLanguage: "es-MX,es;q=0.9,en;q=0.4",
  });
  assert.equal(reply.status, 200);
  assert.ok(reply.html.includes('<html lang="es">'));
  assert.ok(reply.html.includes(copyFor("es").commentsHeading));
  assert.ok(reply.html.includes(copyFor("es").addComment));
  assert.ok(!reply.html.includes(copyFor("en").commentsHeading));

  // The notice pages follow the header too.
  const missing = await handlerFor(w)({ op: "view", token: "abc", acceptLanguage: "es" });
  assert.equal(missing.status, 404);
  assert.ok(missing.html.includes(copyFor("es").unknownLink));
});

test("view: a malformed request is a bare 400, and an internal failure is the unavailable page",
  async () => {
    clock = T0;
    const w = await world({ tier: "a" });
    const handler = handlerFor(w);
    for (const request of [null, "view", 7, [], {}, { op: "delete", token: w.token },
      { op: "comment", token: w.token }, { op: "comment", token: w.token, text: "hi" },
      { op: "comment", token: w.token, formNonce: "0".repeat(64) }]) {
      const reply = await handler(request);
      assert.deepEqual(reply, { status: 400 }, JSON.stringify(request));
    }

    // No artifacts runtime: the version cannot be read, so the page is the fixed unavailable one.
    const noArtifacts = createDoorHandler(w.db, {
      loadSeed: () => ({ seed: SEED }), now: () => clock, comments: bundleComments,
    });
    const unavailable = await noArtifacts({ op: "view", token: w.token });
    assert.equal(unavailable.status, 503);
    assert.ok(unavailable.html.includes(copyFor("en").unavailable));
    assert.ok(!unavailable.html.includes(DOC_TEXT));

    // A comment-scope page cannot be given a nonce without a seed either. The resolve needs the seed
    // too (the recipient's seal is checked with it), so the links seam is given one and only the
    // door's own render path is left without: that is the moment a page has to say "unavailable".
    const noSeed = createDoorHandler(w.db, {
      ...doorDeps(w),
      loadSeed: () => null,
      approvals: { loadSeed: () => ({ seed: SEED }), now: () => clock },
    });
    const noSeedReply = await noSeed({ op: "view", token: w.token });
    assert.equal(noSeedReply.status, 503);
    assert.ok(noSeedReply.html.includes(copyFor("en").unavailable));
    assert.ok(!noSeedReply.html.includes(DOC_TEXT), "no part of the report leaks with it");
  });

/* --------------------------------------------------------------------- comment */

test("comment: ok path writes a tainted contact comment and returns the A9 line and a view that contains the comment",
  async () => {
    clock = T0;
    const w = await world({ tier: "a" });
    const handler = handlerFor(w);
    const view = await handler({ op: "view", token: w.token });
    const text = "Please add the <b>address</b> & phone.";

    const reply = await handler({
      op: "comment", token: w.token, text, formNonce: nonceIn(view.html),
    });
    assert.equal(reply.status, 200);
    assert.equal(reply.ok, true);
    assert.equal(reply.line, copyFor("en").sent, "the fixed sent line");
    assert.ok(reply.html.includes(copyFor("en").sent), "shown above the form");
    assert.ok(reply.html.includes('class="notice notice-ok"'));
    assert.ok(reply.html.includes("Please add the &lt;b&gt;address&lt;/b&gt; &amp; phone."),
      "the reader's words are on the page, escaped by the view");
    assert.ok(!reply.html.includes("<b>address</b>"), "and never as markup");

    const { rows: comments } = await w.db.execute({
      sql: "SELECT author_kind, author_id, text, tainted FROM artifact_comments", args: [],
    });
    assert.equal(comments.length, 1);
    assert.equal(comments[0].author_kind, "contact", "a reader writes as a contact");
    assert.equal(comments[0].author_id, w.recipient.id);
    assert.equal(Number(comments[0].tainted), 1, "one outside person's words, never trusted input");
    assert.equal(comments[0].text, text);

    const { rows: side } = await w.db.execute({
      sql: "SELECT via, report_id, recipient_id, run_id FROM report_recipient_comments", args: [],
    });
    assert.equal(side.length, 1);
    assert.equal(side[0].via, "link");
    assert.equal(side[0].report_id, w.report.id);
    assert.equal(side[0].recipient_id, w.recipient.id);
    assert.equal(side[0].run_id, RUN);
  });

test("comment with a stale formNonce is refused", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  const handler = handlerFor(w);
  const view = await handler({ op: "view", token: w.token });
  const nonce = nonceIn(view.html);

  clock = T0 + 3 * FORM_NONCE_WINDOW_MS;
  try {
    const reply = await handler({ op: "comment", token: w.token, text: "too late?", formNonce: nonce });
    assert.equal(reply.status, 200);
    assert.equal(reply.ok, false);
    assert.equal(reply.error, "form_expired");
    assert.equal(reply.line, copyFor("en").errFormExpired, "the fixed form-expired line");
    assert.ok(reply.html.includes(copyFor("en").errFormExpired));
    const { rows } = await w.db.execute({ sql: "SELECT id FROM artifact_comments", args: [] });
    assert.equal(rows.length, 0, "nothing was written");
  } finally {
    clock = T0;
  }
});

test("comment with a nonce for another token is refused", async () => {
  clock = T0;
  const mine = await world({ tier: "a" });
  const other = await world({ tier: "a", address: "sam@example.com" });
  const otherView = await handlerFor(other)({ op: "view", token: other.token });

  const reply = await handlerFor(mine)({
    op: "comment", token: mine.token, text: "hello", formNonce: nonceIn(otherView.html),
  });
  assert.equal(reply.error, "form_expired", "a nonce is bound to the one token it was made for");
  const { rows } = await mine.db.execute({ sql: "SELECT id FROM artifact_comments", args: [] });
  assert.equal(rows.length, 0);
});

test("a nonce made without the gateway secret is refused", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  const handler = handlerFor(w);
  const hash = hashToken(w.token);
  const window = Math.floor(T0 / FORM_NONCE_WINDOW_MS);
  const forged = [
    createHmac("sha256", hash).update(`${hash}:${window}`).digest("hex"),
    createHmac("sha256", hash).update(String(window)).digest("hex"),
    createHash("sha256").update(`${hash}:${window}`).digest("hex"),
    createHash("sha256").update(w.token).digest("hex"),
  ];
  for (const nonce of forged) {
    const reply = await handler({ op: "comment", token: w.token, text: "forged", formNonce: nonce });
    assert.equal(reply.error, "form_expired", "the token hash is not the key");
    assert.equal(reply.line, copyFor("en").errFormExpired);
  }
  const { rows } = await w.db.execute({ sql: "SELECT id FROM artifact_comments", args: [] });
  assert.equal(rows.length, 0);
});

test("formNonce is keyed by the gateway secret, not the token hash", async () => {
  clock = T0;
  const hash = "a".repeat(64);
  assert.notDeepEqual(formNonceKey(SEED), approvalSealKey(SEED),
    "the form key is a different subkey from the approval seal key");
  assert.notEqual(formNonceFor(hash, SEED, T0), formNonceFor(hash, OTHER_SEED, T0),
    "two seeds give two nonces for the same token hash");
  assert.notEqual(formNonceFor(hash, SEED, T0), formNonceFor(hash, SEED, T0 + FORM_NONCE_WINDOW_MS),
    "and the nonce moves with the ten-minute window");

  // The window rule: this window and the one before it, and nothing older.
  const nonce = formNonceFor(hash, SEED, T0);
  assert.equal(verifyFormNonce(nonce, hash, SEED, T0), true, "the window it was made in");
  assert.equal(verifyFormNonce(nonce, hash, SEED, T0 + FORM_NONCE_WINDOW_MS), true,
    "the previous window is still accepted (a form is good for 10 to 20 minutes)");
  assert.equal(verifyFormNonce(nonce, hash, SEED, T0 + 2 * FORM_NONCE_WINDOW_MS), false,
    "two windows back is refused");
  assert.equal(verifyFormNonce(nonce, hash, SEED, T0 - FORM_NONCE_WINDOW_MS), false,
    "and a future window is not a licence");

  // End to end: a nonce minted under another seed cannot post here, on the same page's form.
  const w = await world({ tier: "a" });
  const foreign = formNonceFor(hashToken(w.token), OTHER_SEED, T0);
  const reply = await handlerFor(w)({
    op: "comment", token: w.token, text: "foreign", formNonce: foreign,
  });
  assert.equal(reply.error, "form_expired");
});

test("verifyFormNonce never throws on garbage", () => {
  const hash = "b".repeat(64);
  const garbage = [
    undefined, null, "", "zz", "not a nonce", 7, {}, [], "0".repeat(63), "0".repeat(65),
    "A".repeat(64), `${"0".repeat(64)}\n`,
  ];
  for (const nonce of garbage) {
    assert.equal(verifyFormNonce(nonce, hash, SEED, T0), false, String(nonce));
  }
  for (const badHash of [undefined, null, "", 7, {}]) {
    assert.equal(verifyFormNonce(formNonceFor(hash, SEED, T0), badHash, SEED, T0), false);
  }
  for (const badSeed of [undefined, null, "", "seed", 7, Buffer.alloc(0)]) {
    assert.equal(verifyFormNonce(formNonceFor(hash, SEED, T0), hash, badSeed, T0), false);
  }
  for (const badNow of [undefined, NaN, Infinity, "soon"]) {
    assert.doesNotThrow(() => verifyFormNonce(formNonceFor(hash, SEED, T0), hash, SEED, badNow));
  }
});

test("a view-scope token cannot post a comment", async () => {
  clock = T0;
  const w = await world({ tier: "b" });
  const handler = handlerFor(w);
  const reply = await handler({
    op: "comment", token: w.token, text: "let me in", formNonce: "0".repeat(64),
  });
  assert.equal(reply.status, 200);
  assert.equal(reply.ok, false);
  assert.equal(reply.error, "view_only");
  assert.equal(reply.line, copyFor("en").errViewOnly, "the fixed view-only line");
  assert.ok(reply.html.includes(copyFor("en").errViewOnly), "the line is in the notice slot");
  assert.ok(reply.html.includes(DOC_TEXT), "on the report's own page");
  assert.ok(!reply.html.includes('class="comment-form"'), "with no form to offer");
  const { rows } = await w.db.execute({ sql: "SELECT id FROM artifact_comments", args: [] });
  assert.equal(rows.length, 0);
});

test("comment errors map to the plain lines", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  const handler = handlerFor(w);
  const nonce = nonceIn((await handler({ op: "view", token: w.token })).html);

  const empty = await handler({ op: "comment", token: w.token, text: "   ", formNonce: nonce });
  assert.equal(empty.error, "empty");
  assert.equal(empty.line, copyFor("en").errEmpty);

  const long = await handler({
    op: "comment", token: w.token, text: "x".repeat(4001), formNonce: nonce,
  });
  assert.equal(long.error, "too_long");
  assert.equal(long.line, copyFor("en").errTooLong);

  // The daily cap: 20 in 24 hours, the 21st refused with the fixed rate line.
  for (let i = 1; i <= 20; i += 1) {
    const posted = await handler({
      op: "comment", token: w.token, text: `note ${i}`, formNonce: nonce,
    });
    assert.equal(posted.ok, true, `comment ${i} is accepted`);
  }
  const capped = await handler({ op: "comment", token: w.token, text: "note 21", formNonce: nonce });
  assert.equal(capped.status, 200);
  assert.equal(capped.ok, false);
  assert.equal(capped.error, "rate_limited");
  assert.equal(capped.line, copyFor("en").errRate);
  const { rows } = await w.db.execute({
    sql: "SELECT COUNT(*) AS n FROM artifact_comments", args: [],
  });
  assert.equal(Number(rows[0].n), 20, "the refused comment never reached the thread store");
});

test("the raw token never appears in any reply", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  const handler = handlerFor(w);
  const view = await handler({ op: "view", token: w.token, acceptLanguage: "es" });
  const replies = [
    view,
    await handler({ op: "view", token: `${w.token}x` }),
    await handler({ op: "view", token: w.token, acceptLanguage: "en" }),
    await handler({ op: "comment", token: w.token, text: "ok", formNonce: nonceIn(view.html) }),
    await handler({ op: "comment", token: w.token, text: "stale", formNonce: "0".repeat(64) }),
    await handler({ op: "comment", token: w.token, text: "", formNonce: nonceIn(view.html) }),
    await handler({ op: "nope", token: w.token }),
    await handler({ op: "view", token: w.token.split("").reverse().join("") }),
  ];
  for (const reply of replies) {
    const dump = JSON.stringify(reply);
    assert.equal(dump.includes(w.token), false, "no reply echoes the raw token");
    assert.equal(dump.includes(hashToken(w.token)), false, "and not even its hash in a page");
  }
});

/* ------------------------------------------------------ SF2: the window on the door */

test("SF2: a link for a run past the verified window stays readable and takes no comment", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  // A window of two runs, approved: of the three runs below, only runs 2 and 3 still take comments.
  await updateReportColumns(w.db, w.report.id, { comment_window_runs: 2 });
  const report = await goLiveReport(w.db, await getReport(w.db, w.report.id));
  const runTwo = await addRunLink(w, { runId: "rrn-00000000000000c2", sendId: "rsd-00000000000000c2" });
  const runThree = await addRunLink(w, { runId: "rrn-00000000000000c3", sendId: "rsd-00000000000000c3" });
  assert.deepEqual([w.versionN, runTwo.versionN, runThree.versionN], [1, 2, 3]);

  const handler = handlerFor(w);
  const linksD = linksDeps(w.runtime);
  const old = await resolveLinkToken(w.db, linksD, w.token);
  assert.equal(old.status, "ok");
  assert.equal(old.token.versionN, w.versionN, "the first link opens the first run's version");

  // The page is built (nothing about the read is refused) and carries no comment form.
  const view = await handler({ op: "view", token: w.token });
  assert.equal(view.status, 200);
  assert.ok(view.html.includes(DOC_TEXT), "the report is still readable");
  assert.ok(!view.html.includes('class="comment-form"'), "but it offers no form");
  assert.ok(!view.html.includes('name="formNonce"'));

  // A hand-made post is refused with the B6 line, in English and in Spanish.
  await assert.rejects(() => postRecipientComment(w.db, doorDeps(w), {
    resolved: old, text: "one more thing about run one",
  }), (err) => {
    assert.equal(err.code, "view_only");
    return true;
  });
  assert.equal(copyFor("en").errViewOnly, "Comments aren't open on this link.");
  assert.equal(copyFor("es").errViewOnly, "Este enlace no admite comentarios.");
  for (const [acceptLanguage, table] of [["en", copyFor("en")], ["es", copyFor("es")]]) {
    const reply = await handler({
      op: "comment",
      token: w.token,
      text: "one more thing about run one",
      formNonce: formNonceFor(hashToken(w.token), SEED, clock),
      acceptLanguage,
    });
    assert.equal(reply.status, 200);
    assert.equal(reply.ok, false);
    assert.equal(reply.error, "view_only");
    assert.equal(reply.line, table.errViewOnly);
    assert.ok(reply.html.includes(table.errViewOnly), "the fixed line is on the page");
    assert.ok(!reply.html.includes('class="comment-form"'), "and still no form");
  }
  const { rows: written } = await w.db.execute({ sql: "SELECT id FROM artifact_comments", args: [] });
  assert.equal(written.length, 0, "a closed version never reaches the thread store");

  // Runs 2 and 3 are inside the window: their links still answer a form and still take a comment.
  for (const [label, token, body] of [["run 2", runTwo.token, "a question about run two"],
    ["run 3", runThree.token, "and about the newest run"]]) {
    const page = await handler({ op: "view", token });
    assert.equal(page.status, 200, label);
    assert.ok(page.html.includes('class="comment-form"'), `${label} offers the form`);
    const posted = await handler({
      op: "comment", token, text: body, formNonce: nonceIn(page.html), acceptLanguage: "en",
    });
    assert.equal(posted.ok, true, label);
    assert.equal(posted.line, copyFor("en").sent);
  }
  const { rows: after } = await w.db.execute({ sql: "SELECT id FROM artifact_comments", args: [] });
  assert.equal(after.length, 2, "one comment from each run inside the window");
});

/* ------------------------------------------- the report's own standing on the door */
//
// A token says which version and which recipient it opens; the report's status says whether there is a
// report to act on at all. `live` over a seal that still verifies behaves as every test above says,
// `paused` keeps the page readable and takes no comment (the B6 line, in both languages), and any other
// status word is the same 404 an unknown token gets.

test("a paused report's page is readable and takes no comment", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  await w.db.execute({ sql: "UPDATE reports SET status = 'paused' WHERE id = ?", args: [w.report.id] });
  const handler = handlerFor(w);

  const page = await handler({ op: "view", token: w.token });
  assert.equal(page.status, 200, "a paused report is still readable");
  assert.ok(page.html.includes(DOC_TEXT));
  assert.ok(!page.html.includes('class="comment-form"'), "and offers no comment form");
  assert.ok(!page.html.includes('name="formNonce"'));

  assert.equal(copyFor("en").errViewOnly, "Comments aren't open on this link.");
  assert.equal(copyFor("es").errViewOnly, "Este enlace no admite comentarios.");
  for (const [acceptLanguage, table] of [["en", copyFor("en")], ["es", copyFor("es")]]) {
    const reply = await handler({
      op: "comment",
      token: w.token,
      text: "one more thing about this run",
      formNonce: formNonceFor(hashToken(w.token), SEED, clock),
      acceptLanguage,
    });
    assert.equal(reply.status, 200);
    assert.equal(reply.ok, false);
    assert.equal(reply.error, "view_only");
    assert.equal(reply.line, table.errViewOnly);
    assert.ok(reply.html.includes(table.errViewOnly), "the fixed line is on the page");
    assert.ok(!reply.html.includes('class="comment-form"'), "and still no form");
  }
  const { rows } = await w.db.execute({ sql: "SELECT id FROM artifact_comments", args: [] });
  assert.equal(rows.length, 0, "a paused report never takes a comment");
});

test("a report live by status over a broken seal is read as paused", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  // A direct UPDATE of a live-set column: the word still says live, the approval behind it is gone.
  await w.db.execute({
    sql: "UPDATE reports SET delivery_mode = 'email_full' WHERE id = ?", args: [w.report.id],
  });
  const moved = await getReport(w.db, w.report.id);
  assert.equal(moved.status, "live", "the status word never moved");
  const handler = handlerFor(w);

  const page = await handler({ op: "view", token: w.token });
  assert.equal(page.status, 200);
  assert.ok(page.html.includes(DOC_TEXT));
  assert.ok(!page.html.includes('class="comment-form"'), "an unsealed report takes no comment");

  const reply = await handler({
    op: "comment",
    token: w.token,
    text: "let me in",
    formNonce: formNonceFor(hashToken(w.token), SEED, clock),
  });
  assert.equal(reply.ok, false);
  assert.equal(reply.error, "view_only");
  assert.equal(reply.line, copyFor("en").errViewOnly);
  const { rows } = await w.db.execute({ sql: "SELECT id FROM artifact_comments", args: [] });
  assert.equal(rows.length, 0);
});

test("a draft or any other status word is the same 404 an unknown token gets", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  const handler = handlerFor(w);
  const unknown = await handler({ op: "view", token: "Z".repeat(43) });
  assert.equal(unknown.status, 404);

  for (const word of ["draft", "archived", ""]) {
    await w.db.execute({ sql: "UPDATE reports SET status = ? WHERE id = ?", args: [word, w.report.id] });
    const reply = await handler({ op: "view", token: w.token });
    assert.equal(reply.status, 404, `${JSON.stringify(word)} is not a report a mailed link may open`);
    assert.equal(reply.html, unknown.html, "the one fixed refusal page, byte for byte");
  }

  // Back to live: the very same link opens again, because nothing about the token itself changed.
  await w.db.execute({ sql: "UPDATE reports SET status = 'live' WHERE id = ?", args: [w.report.id] });
  const again = await handler({ op: "view", token: w.token });
  assert.equal(again.status, 200);
  assert.ok(again.html.includes('class="comment-form"'));
});

/* ------------------------------------------------------------------- the socket */

/** Send one line and read everything back until the server ends the connection. */
function sendLine(socketPath, payload, timeoutMs = 15_000) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(socketPath);
    let buffer = "";
    const timer = setTimeout(() => {
      try { socket.destroy(); } catch { /* gone */ }
      reject(new Error("the door never answered"));
    }, timeoutMs);
    const done = () => {
      clearTimeout(timer);
      resolve(buffer);
    };
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(payload));
    socket.on("data", (chunk) => { buffer += chunk; });
    socket.on("end", done);
    socket.on("close", done);
    socket.on("error", (err) => {
      clearTimeout(timer);
      if (buffer) resolve(buffer);
      else reject(err);
    });
  });
}

function firstLine(raw) {
  return JSON.parse(raw.split("\n")[0]);
}

test("the door serves one JSON line per connection over a unix socket", async () => {
  clock = T0;
  const w = await world({ tier: "a" });
  const dir = mkdtempSync(join(root, "door-sock-"));
  const socketPath = join(dir, "door.sock");
  const server = listenDoor(createDoorServer({ db: w.db, deps: doorDeps(w) }), socketPath);
  await once(server, "listening");
  try {
    const ok = firstLine(await sendLine(socketPath, `${JSON.stringify({ op: "view", token: w.token })}\n`));
    assert.equal(ok.status, 200);
    assert.ok(ok.html.includes(DOC_TEXT));

    // A second connection is an independent request: there is no session state between them.
    const again = firstLine(await sendLine(socketPath, `${JSON.stringify({ op: "view", token: w.token })}\n`));
    assert.equal(again.status, 200);
    assert.equal(again.html, ok.html, "the same token gets the same page");

    const oversize = firstLine(await sendLine(socketPath, `${"x".repeat(70_000)}\n`));
    assert.deepEqual(oversize, { status: 400 }, "a line over the cap is refused");

    const badJson = firstLine(await sendLine(socketPath, '{"op":\n'));
    assert.deepEqual(badJson, { status: 400 }, "invalid JSON is refused");

    const notObject = firstLine(await sendLine(socketPath, "null\n"));
    assert.deepEqual(notObject, { status: 400 });
  } finally {
    await closeDoorServer(server, { force: true });
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an idle connection is answered 400 and closed", async () => {
  clock = T0;
  const w = await world({ tier: "b" });
  const dir = mkdtempSync(join(root, "door-idle-"));
  const socketPath = join(dir, "door.sock");
  const server = listenDoor(createDoorServer({ db: w.db, deps: doorDeps(w), idleMs: 150 }), socketPath);
  await once(server, "listening");
  try {
    const reply = firstLine(await sendLine(socketPath, ""));
    assert.deepEqual(reply, { status: 400 });
  } finally {
    await closeDoorServer(server, { force: true });
    rmSync(dir, { recursive: true, force: true });
  }
});

/* ----------------------------------------------------------- the activation fd */

test("pickActivatedFd picks by unit name", () => {
  const pid = 4242;
  const both = `${PROXY_SOCKET_UNIT}:${REPORTS_DOOR_SOCKET_UNIT}`;
  const env = { LISTEN_PID: String(pid), LISTEN_FDS: "2", LISTEN_FDNAMES: both };
  assert.equal(pickActivatedFd(PROXY_SOCKET_UNIT, env, pid), 3, "the proxy socket is the first fd");
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, env, pid), 4, "the door is the second");

  // Order is by NAME, never by position.
  const reversed = {
    LISTEN_PID: String(pid), LISTEN_FDS: "2",
    LISTEN_FDNAMES: `${REPORTS_DOOR_SOCKET_UNIT}:${PROXY_SOCKET_UNIT}`,
  };
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, reversed, pid), 3);
  assert.equal(pickActivatedFd(PROXY_SOCKET_UNIT, reversed, pid), 4);

  // The door unit absent: null, even though some fds were passed.
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, {
    LISTEN_PID: String(pid), LISTEN_FDS: "1", LISTEN_FDNAMES: PROXY_SOCKET_UNIT,
  }, pid), null);
  // A foreign LISTEN_PID (an inherited environment) is ignored.
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, {
    LISTEN_PID: String(pid + 1), LISTEN_FDS: "1", LISTEN_FDNAMES: REPORTS_DOOR_SOCKET_UNIT,
  }, pid), null);
  // Nameless fds are refused.
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, {
    LISTEN_PID: String(pid), LISTEN_FDS: "1",
  }, pid), null);
  // No fds at all.
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, {
    LISTEN_PID: String(pid), LISTEN_FDS: "0", LISTEN_FDNAMES: REPORTS_DOOR_SOCKET_UNIT,
  }, pid), null);
  // The proxy picker is unchanged, and is the same rule with the proxy unit name.
  assert.equal(pickActivatedFd(PROXY_SOCKET_UNIT, env, pid), 3);
});

test("startActivatedDoor with no activation fd listens on nothing and returns null", () => {
  const logged = [];
  const started = startActivatedDoor({
    db: null, env: {}, pid: process.pid, log: (line) => logged.push(line),
  });
  assert.equal(started, null, "no listener was made");
  assert.deepEqual(logged, [], "and nothing was logged, at any level");

  const foreign = startActivatedDoor({
    db: null,
    env: { LISTEN_PID: "1", LISTEN_FDS: "1", LISTEN_FDNAMES: "crow-gateway.socket" },
    pid: process.pid,
    log: (line) => logged.push(line),
  });
  assert.equal(foreign, null, "another socket unit's fd is never taken for the door");
  assert.deepEqual(logged, []);
});

/* ------------------------------------------------------ M5: the activation fd's kind */

/** Resolve once `text` appears in the stream's output. */
function waitForText(stream, text, stderr = () => "") {
  return new Promise((resolveText, reject) => {
    let buffer = "";
    stream.on("data", (chunk) => {
      buffer += chunk;
      if (buffer.includes(text)) resolveText(buffer);
    });
    stream.on("end", () => reject(new Error(`stream ended before "${text}"; stderr:\n${stderr()}`)));
    stream.on("error", reject);
  });
}

/** `promise`, or a rejection after `ms` whose message a caller builds. The timer is always cleared, so a
 *  passing race never holds the test process open. */
function withTimeout(promise, ms, message) {
  let timer;
  const guard = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message())), ms);
  });
  return Promise.race([promise, guard]).finally(() => clearTimeout(timer));
}

/**
 * Run `startActivatedDoor` in a child process that holds ONE listening fd as fd 3, exactly as systemd's
 * socket activation hands it over. The child is the only way to put a listener at fd 3 in this process,
 * and it is what the proxy socket's own activation test does.
 *
 * @param {number} fd this process's listening fd (the child receives a duplicate of it as fd 3)
 * @returns {{child: import("node:child_process").ChildProcess, stderr: () => string}}
 */
function spawnDoorOnFd(fd) {
  const script = `
    process.env.LISTEN_PID = String(process.pid);
    process.env.LISTEN_FDS = "1";
    process.env.LISTEN_FDNAMES = ${JSON.stringify(REPORTS_DOOR_SOCKET_UNIT)};
    const { startActivatedDoor } = await import(${JSON.stringify(
    pathToFileURL(join(resolve(import.meta.dirname, ".."), "servers/gateway/reports/public-door.js")).href,
  )});
    const server = startActivatedDoor({ db: null, deps: {}, log: (line) => console.log(line) });
    if (!server) { console.error("NO_LISTENER"); process.exit(3); }
  `;
  const env = { ...process.env };
  delete env.LISTEN_PID;
  delete env.LISTEN_FDS;
  delete env.LISTEN_FDNAMES;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script], {
    cwd: resolve(import.meta.dirname, ".."),
    stdio: ["ignore", "pipe", "pipe", fd],
    env,
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  return { child, stderr: () => stderr };
}

/**
 * What a client sees at a TCP address: `answered` with the bytes when anything came back, `destroyed`
 * when the peer closed or refused the connection, and `open` when it stayed silent (a listener nobody
 * answers on) until the probe gave up.
 */
function probePort(host, port, timeoutMs = 3_000) {
  return new Promise((resolveProbe) => {
    let bytes = "";
    let settled = false;
    const socket = net.connect({ host, port });
    const finish = (kind) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* already gone */ }
      resolveProbe({ kind, bytes });
    };
    const timer = setTimeout(() => finish("open"), timeoutMs);
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => { bytes += chunk; finish("answered"); });
    socket.on("close", () => finish("destroyed"));
    socket.on("error", () => finish("destroyed"));
  });
}

test("M5: a TCP listening fd is refused before it serves anything, and a unix fd still serves",
  async (t) => {
    // 1. A TCP listening fd: the kind is decided BEFORE anything is accepted, so the door logs the
    //    refusal and closes the listener with no request ever served on it.
    const tcp = net.createServer();
    await new Promise((ready) => tcp.listen(0, "127.0.0.1", ready));
    const port = tcp.address().port;
    const tcpFd = tcp._handle?.fd;
    if (!Number.isInteger(tcpFd)) {
      tcp.close();
      return t.skip("this node exposes no listening fd");
    }
    const refused = spawnDoorOnFd(tcpFd);
    try {
      await withTimeout(waitForText(refused.child.stdout, "REFUSED", refused.stderr), 20_000,
        () => `the door logged no refusal; stderr:\n${refused.stderr()}`);
      // This process's own copy of the listener goes now: the only thing that could answer is the door.
      await new Promise((closed) => tcp.close(closed));
      const heard = await probePort("127.0.0.1", port);
      assert.equal(heard.kind, "destroyed", "a client on that fd gets no reply");
      assert.equal(heard.bytes, "", "and nothing was ever read or answered on it");
    } finally {
      refused.child.kill("SIGKILL");
      try { await once(refused.child, "exit"); } catch { /* already gone */ }
      try { tcp.close(); } catch { /* already closed */ }
    }

    // 2. The gate itself: a door server that was never type-checked destroys every connection, so the
    //    refusal holds even for a listener this module did not bind.
    const gated = createDoorServer({ db: null, deps: {} });
    gated.listen(0, "127.0.0.1");
    await once(gated, "listening");
    try {
      const heard = await probePort("127.0.0.1", gated.address().port);
      assert.equal(heard.kind, "destroyed", "an unchecked listener serves nothing");
      assert.equal(heard.bytes, "");
    } finally {
      await closeDoorServer(gated, { force: true });
    }

    // 3. A unix-socket fd is the door: it says so, and it answers a line. The socket has an abstract name
    //    (a leading NUL, the proxy socket test's own trick), so closing this process's copy of the
    //    listener cannot unlink the name the child is serving on.
    const socketPath = `\0crow-report-readers-${process.pid}-${Date.now()}`;
    const handed = net.createServer();
    await new Promise((ready) => handed.listen(socketPath, ready));
    const unixFd = handed._handle?.fd;
    if (!Number.isInteger(unixFd)) {
      handed.close();
      return t.skip("this node exposes no listening fd");
    }
    const served = spawnDoorOnFd(unixFd);
    try {
      await withTimeout(waitForText(served.child.stdout, `listening on ${REPORTS_DOOR_SOCKET_UNIT}`,
        served.stderr), 20_000, () => `the door never listened; stderr:\n${served.stderr()}`);
      // Only the child may accept now: this process's copy goes, its own duplicate stays listening.
      await new Promise((closed) => handed.close(closed));
      const reply = firstLine(await sendLine(socketPath, "{}\n"));
      assert.deepEqual(reply, { status: 400 }, "a unix-socket fd still serves the door protocol");
    } finally {
      served.child.kill("SIGKILL");
      try { await once(served.child, "exit"); } catch { /* already gone */ }
    }
  });