// Recipient comments: what a reader who opened a report from a mail may write, what that reader may see,
// and how older reader threads close on their own.
//
// Harness: a real init-db'd scratch crow.db (the reports tables are init-db's own) copied per test, the
// artifacts bundle's tables created by its own `initArtifactsTables` (an existing 0.10.x style bundle
// database: this round adds nothing to it), the bundle's own `comments.js` from this repo passed as the
// `deps.comments` seam, and version/run rows written by hand so a test says exactly which version a
// comment lands on. Recipients are rows too (this module reads their display names, and a seal is the
// link resolver's job, not this module's). Every notice goes through the REAL `createNotification` with
// its fan-out turned off, so a test asserts the row the owner's bell would show.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = mkdtempSync(join(tmpdir(), "reports-recipient-comments-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");
const BUNDLE = join(REPO, "bundles", "artifacts", "server");
const bundleImport = (f) => import(pathToFileURL(join(BUNDLE, f)).href);
const bundleComments = await bundleImport("comments.js");
const { initArtifactsTables } = await bundleImport("init-tables.js");

const { createDbClient } = await import("../servers/db.js");
const { createNotification } = await import("../servers/shared/notifications.js");
const {
  createReport, getReport, saveRecipe, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const {
  DEFAULT_COMMENT_WINDOW_RUNS, liveSetFor, updateSettings,
} = await import("../servers/gateway/reports/approvals.js");
const { approvalSeal, newApprovalNonce } = await import("../servers/gateway/reports/seal.js");
const {
  NOTICE_DAY_STATE_KEY, autoResolveRecipientThreads, commentErrorLine, commentOpenFor,
  notifyTooManyThreads, postRecipientComment, visibleThreadsFor,
} = await import("../servers/gateway/reports/recipient-comments.js");

const T0 = 1_700_000_000_000;
const DAY_MS = 86_400_000;
const SEED = Buffer.alloc(32, 11);
const PROJECT = 7;
const ARTIFACT = "art-recipient-comments";
const RUN = "rrn-00000000000000d1";
const SEND = "rsd-00000000000000d1";
const BOT = "bot-1";
const OWNER = Object.freeze({ kind: "owner" });
const BOT_AUTHOR = Object.freeze({ kind: "bot", id: BOT });

const A = Object.freeze({ id: "rrc-00000000000000a1" });
const B = Object.freeze({ id: "rrc-00000000000000b2" });
const C = Object.freeze({ id: "rrc-00000000000000c3" });
const D = Object.freeze({ id: "rrc-00000000000000d4" });

/** The fixed lines this file pins, EN and ES, kept verbatim here (a test pins the table itself). */
const COPY = Object.freeze({
  errRate: {
    en: "You've sent a lot of comments recently. Try again later.",
    es: "Has enviado muchos comentarios hace poco. Inténtalo más tarde.",
  },
  errThreads: {
    en: "This report has too many open comments right now. The sender has been told.",
    es: "Este informe tiene demasiados comentarios abiertos ahora. Ya se le avisó a quien lo envió.",
  },
  errEmpty: { en: "Write a comment first.", es: "Escribe un comentario primero." },
  errTooLong: {
    en: "That comment is too long. Keep it under 4,000 characters.",
    es: "Ese comentario es demasiado largo. Debe tener menos de 4.000 caracteres.",
  },
  errViewOnly: { en: "Comments aren't open on this link.", es: "Este enlace no admite comentarios." },
  errOther: {
    en: "Your comment didn't go through. Try again later.",
    es: "Tu comentario no se envió. Inténtalo más tarde.",
  },
  you: { en: "You", es: "Tú" },
  sender: { en: "The sender", es: "Quien lo envió" },
  anotherReader: { en: "Another reader", es: "Otra persona" },
  bot: { en: `${BOT} (AI)`, es: `${BOT} (IA)` },
});

const open = [];
let copied = 0;
let clock = T0;

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

/** The notice seam: the real createNotification row, with the network fan-out turned off. */
const notifyQuietly = (db, opts) => createNotification(db, { ...opts, deliver: false });

/** The approvals seam the verified comment settings are read through: the keychain seed, the clock and a
 *  schedule a live report needs (its values are sealed and verified through this same stub). */
function approvalsDeps(over = {}) {
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => clock,
    getSchedule: async () => ({ cron: "0 7 * * 1", tz: "Europe/Berlin" }),
    registry: {},
    ...over,
  };
}

function depsFor(over = {}) {
  return { ...approvalsDeps(), comments: bundleComments, notify: notifyQuietly, ...over };
}

/**
 * Seal one report live over the values its row holds now: the write `approveGoLive` makes, minus the
 * preview run and the sender a go-live insists on. This module only ever reads the seal, so a real seal
 * over the current live set is the whole world its visibility and window come from.
 *
 * @param {object} db
 * @param {object} row the report row to seal (`id` and its current live-set values)
 * @returns {Promise<object>} the report row after the write
 */
async function goLive(db, row) {
  const saved = await saveRecipe(db, {
    reportId: row.id, recipe: { blocks: [] }, authorKind: "owner", registry: {},
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

async function freshDb() {
  const dir = join(root, "t" + (++copied));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  // Bundle-owned tables, made by the bundle's own installer: the same database an existing install has.
  await initArtifactsTables(db);
  return db;
}

async function reportRow(db, over = {}) {
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: "owner", botId: BOT, title: "Weekly listings",
  });
  await updateReportColumns(db, id, {
    artifact_id: ARTIFACT,
    comment_tier_default: "a",
    comment_visibility: "own",
    comment_window_runs: 4,
    ...over,
  });
  await db.execute({
    sql: "INSERT OR IGNORE INTO artifacts (id, title, type) VALUES (?, 'Weekly listings', 'document')",
    args: [ARTIFACT],
  });
  return getReport(db, id);
}

/** A recipient row as the approvals module leaves one: approved, its tier named. */
async function addRecipient(db, reportId, recipient, { displayName = null } = {}) {
  await db.execute({
    sql: `INSERT INTO report_recipients
            (id, report_id, address, display_name, comment_tier, state, proposed_by, approved_at,
             created_at)
          VALUES (?, ?, ?, ?, 'a', 'approved', 'owner', ?, ?)`,
    args: [recipient.id, reportId, `${recipient.id}@example.com`, displayName, T0, T0],
  });
  return recipient;
}

/** One run's artifact version, and the report-to-version map row that says a run wrote it. */
async function addVersion(db, { n, reportId, trigger = "schedule" }) {
  await db.execute({
    sql: `INSERT INTO artifact_versions
            (artifact_id, n, state, files_json, size, content_hash, made_by)
          VALUES (?, ?, 'past', '[]', 0, 'abc', 'user')`,
    args: [ARTIFACT, n],
  });
  await db.execute({
    sql: `INSERT INTO report_versions
            (artifact_id, n, report_id, run_id, "trigger", allowed_links_json, created_at)
          VALUES (?, ?, ?, ?, ?, '[]', ?)`,
    args: [ARTIFACT, n, reportId, `${RUN}-${n}`, trigger, T0],
  });
}

/** A `resolveLinkToken` "ok" answer, built by hand: this module only reads its `token`, `report`,
 *  `recipient` members (the token's own checks belong to `links.js`). */
function resolvedFor(report, recipient, { versionN, scope = "comment", tokenId = "rlt-00000000000000a1" }) {
  return {
    status: "ok",
    token: {
      id: tokenId,
      reportId: report.id,
      recipientId: recipient.id,
      runId: RUN,
      sendId: SEND,
      artifactId: ARTIFACT,
      versionN,
      scope,
      expiresAt: T0 + 180 * DAY_MS,
    },
    report,
    recipient,
  };
}

async function post(db, report, recipient, { versionN, text: body, scope = "comment", tokenId } = {}) {
  return postRecipientComment(db, depsFor(), {
    resolved: resolvedFor(report, recipient, { versionN, scope, tokenId }),
    text: body,
  });
}

async function commentRows(db) {
  return (await db.execute({
    sql: "SELECT * FROM artifact_comments ORDER BY id", args: [],
  })).rows;
}

async function sideRows(db) {
  return (await db.execute({
    sql: "SELECT * FROM report_recipient_comments ORDER BY created_at ASC, comment_id ASC", args: [],
  })).rows;
}

async function threadRows(db) {
  return (await db.execute({
    sql: "SELECT * FROM artifact_threads ORDER BY id", args: [],
  })).rows;
}

async function openThreadCount(db, recipientId = A.id) {
  const { rows } = await db.execute({
    sql: `SELECT COUNT(*) AS n FROM artifact_threads
           WHERE artifact_id = ? AND author_kind = 'contact' AND author_id = ?
             AND status <> 'resolved'`,
    args: [ARTIFACT, recipientId],
  });
  return Number(rows[0].n);
}

async function notifications(db) {
  return (await db.execute({
    sql: "SELECT * FROM notifications ORDER BY id", args: [],
  })).rows;
}

/* --------------------------------------------------------- one comment, end to end */

test("a pre-existing artifacts DB accepts a recipient comment", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db);
  const recipient = await addRecipient(db, report.id, A);
  await addVersion(db, { n: 1, reportId: report.id });

  const before = (await db.execute({ sql: "PRAGMA table_info(artifact_comments)", args: [] })).rows
    .map((column) => column.name);

  const posted = await post(db, report, recipient, { versionN: 1, text: "  Looks right to me.  " });
  assert.equal(posted.ok, true);
  assert.equal(Number.isInteger(posted.threadId), true);
  assert.equal(Number.isInteger(posted.commentId), true);

  const columns = (await db.execute({ sql: "PRAGMA table_info(artifact_comments)", args: [] })).rows
    .map((column) => column.name);
  assert.deepEqual(columns, before, "a recipient comment adds no column to the bundle's tables");

  const threads = await threadRows(db);
  assert.equal(threads.length, 1);
  const thread = threads[0];
  assert.equal(Number(thread.id), posted.threadId);
  assert.equal(thread.artifact_id, ARTIFACT);
  assert.equal(Number(thread.version_n), 1);
  assert.equal(thread.author_kind, "contact", "a recipient writes as a contact, never as the owner or a bot");
  assert.equal(thread.author_id, recipient.id);
  assert.deepEqual(JSON.parse(thread.anchor_json), { kind: "whole" });
  assert.equal(thread.status, "open");

  const comments = await commentRows(db);
  assert.equal(comments.length, 1);
  assert.equal(Number(comments[0].id), posted.commentId);
  assert.equal(comments[0].author_kind, "contact");
  assert.equal(comments[0].author_id, recipient.id);
  assert.equal(comments[0].text, "Looks right to me.", "the text is trimmed, as the bundle trims it");
  assert.equal(Number(comments[0].tainted), 1, "a reader's words are never trusted input");
});

test("recipient comments are tainted contact comments mapped to the recipient", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db);
  const recipient = await addRecipient(db, report.id, A);
  await addVersion(db, { n: 1, reportId: report.id });

  const first = await post(db, report, recipient, {
    versionN: 1, text: "Please add the address.", tokenId: "rlt-0000000000000011",
  });
  const second = await post(db, report, recipient, {
    versionN: 1, text: "And the phone number.", tokenId: "rlt-0000000000000012",
  });

  const comments = await commentRows(db);
  assert.equal(comments.length, 2);
  for (const comment of comments) {
    assert.equal(comment.author_kind, "contact");
    assert.equal(comment.author_id, recipient.id);
    assert.equal(Number(comment.tainted), 1);
  }

  const rows = await sideRows(db);
  assert.equal(rows.length, 2, "every comment a recipient adds is recorded in the side table");
  assert.deepEqual(rows.map((row) => Number(row.comment_id)), [first.commentId, second.commentId],
    "a side row is keyed by the artifacts comment it records");
  for (const row of rows) {
    assert.equal(typeof row.thread_id, "string", "the thread id is held as text");
    assert.equal(row.thread_id, String(first.threadId),
      "and it is the artifacts thread the comment was written in");
    assert.equal(row.report_id, report.id);
    assert.equal(row.run_id, RUN);
    assert.equal(row.recipient_id, recipient.id);
    assert.equal(row.via, "link", "the comment came in through a mailed link");
    assert.equal(Number(row.created_at), T0);
  }
});

/* --------------------------------------------------------------------- visibility */

test("default visibility shows a recipient only their own threads", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db, { comment_visibility: "own" });
  const a = await addRecipient(db, report.id, A);
  const b = await addRecipient(db, report.id, B);
  await addVersion(db, { n: 1, reportId: report.id });

  const mine = await post(db, report, a, { versionN: 1, text: "Why is the second row missing?" });
  await bundleComments.addComment(db, {
    threadId: mine.threadId, text: "The feed it came from dropped it.", author: OWNER, tainted: false,
  });
  await bundleComments.addComment(db, {
    threadId: mine.threadId, text: "I can add it to the source instead.", author: BOT_AUTHOR, tainted: true,
  });
  const other = await post(db, report, b, { versionN: 1, text: "My own question." });

  const forA = await visibleThreadsFor(db, depsFor(), {
    report, recipient: a, artifactId: ARTIFACT, versionN: 1, lang: "en",
  });
  assert.equal(forA.length, 1, "only the thread this recipient wrote in");
  assert.equal(forA[0].id, mine.threadId);
  assert.equal(forA[0].status, "open");
  assert.deepEqual(forA[0].comments.map((comment) => comment.label),
    [COPY.you.en, COPY.sender.en, COPY.bot.en],
    "the owner's and the bot's replies inside their own thread are shown too");
  assert.deepEqual(forA[0].comments.map((comment) => comment.text), [
    "Why is the second row missing?",
    "The feed it came from dropped it.",
    "I can add it to the source instead.",
  ]);
  assert.equal(forA[0].comments.every((comment) => comment.createdAt > 0), true,
    "a comment carries its own time");

  const forB = await visibleThreadsFor(db, depsFor(), {
    report, recipient: b, artifactId: ARTIFACT, versionN: 1, lang: "en",
  });
  assert.deepEqual(forB.map((thread) => thread.id), [other.threadId]);
  assert.equal(forA.some((thread) => thread.id === other.threadId), false,
    "another recipient's thread is never on this page");
});

test("visibility all shows every recipient thread with names, and no thread of its own", async () => {
  clock = T0;
  const db = await freshDb();
  const row = await reportRow(db, { comment_visibility: "all" });
  // SF1: the visibility a reader's page obeys is the VERIFIED live set's, so the report has to carry a
  // real live seal over it (a bare draft row would fall back to `own`).
  const report = await goLive(db, row);
  const a = await addRecipient(db, report.id, A);
  const b = await addRecipient(db, report.id, B, { displayName: " Sam\u0000uel " });
  const c = await addRecipient(db, report.id, C, { displayName: "   " });
  const d = await addRecipient(db, report.id, D, { displayName: "N".repeat(80) });
  await addVersion(db, { n: 1, reportId: report.id });

  const first = await post(db, report, a, { versionN: 1, text: "From the first reader." });
  await post(db, report, b, { versionN: 1, text: "From the second reader." });
  await post(db, report, c, { versionN: 1, text: "From a reader with no name." });
  await post(db, report, d, { versionN: 1, text: "From a reader with a very long name." });
  // The owner's and the bot's replies INSIDE a reader's thread are part of the conversation the reader is
  // in, so they are shown with it.
  await bundleComments.addComment(db, {
    threadId: first.threadId, text: "Thanks, looking at it.", author: OWNER, tainted: false,
  });
  // Threads the owner and the bot started from the artifacts panel carry no recipient comment at all: they
  // are the owner's own workspace and never reach a reader's page.
  await bundleComments.addThread(db, {
    artifactId: ARTIFACT,
    versionN: 1,
    anchor: { kind: "whole" },
    text: "The sender starts a thread of their own.",
    author: OWNER,
    tainted: false,
  });
  await bundleComments.addThread(db, {
    artifactId: ARTIFACT,
    versionN: 1,
    anchor: { kind: "whole" },
    text: "The pickup starts a note of its own.",
    author: BOT_AUTHOR,
    tainted: true,
  });

  const english = await visibleThreadsFor(db, depsFor(), {
    report, recipient: a, artifactId: ARTIFACT, versionN: 1, lang: "en",
  });
  assert.equal(english.length, 4, "every recipient thread on the version, and no other thread");
  const texts = english.flatMap((thread) => thread.comments.map((comment) => comment.text));
  assert.equal(texts.includes("The sender starts a thread of their own."), false,
    "an owner-only thread is never a reader's page");
  assert.equal(texts.includes("The pickup starts a note of its own."), false,
    "nor is a bot-only one");
  const mine = english.find((thread) => thread.id === first.threadId);
  assert.deepEqual(mine.comments.map((comment) => comment.label), [COPY.you.en, COPY.sender.en],
    "the owner's reply inside the reader's own thread is shown");

  const labels = english.flatMap((thread) => thread.comments.map((comment) => comment.label));
  assert.ok(labels.includes(COPY.you.en));
  assert.ok(labels.includes(COPY.sender.en));
  assert.ok(labels.includes("Samuel"), "a display name is used and its control characters are dropped");
  assert.ok(labels.includes(COPY.anotherReader.en), "an empty display name reads as another reader");
  assert.ok(labels.includes("N".repeat(60)), "a display name is capped at 60 characters");
  assert.equal(labels.includes("N".repeat(61)), false);

  const spanish = await visibleThreadsFor(db, depsFor(), {
    report, recipient: a, artifactId: ARTIFACT, versionN: 1, lang: "es",
  });
  const esLabels = spanish.flatMap((thread) => thread.comments.map((comment) => comment.label));
  assert.ok(esLabels.includes(COPY.you.es));
  assert.ok(esLabels.includes(COPY.sender.es));
  assert.ok(esLabels.includes(COPY.anotherReader.es));
});

test("own visibility never shows a thread the owner or the bot started", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await goLive(db, await reportRow(db, { comment_visibility: "own" }));
  const a = await addRecipient(db, report.id, A);
  await addVersion(db, { n: 1, reportId: report.id });

  const mine = await post(db, report, a, { versionN: 1, text: "My own question." });
  await bundleComments.addComment(db, {
    threadId: mine.threadId, text: "The feed dropped it.", author: OWNER, tainted: false,
  });
  await bundleComments.addThread(db, {
    artifactId: ARTIFACT,
    versionN: 1,
    anchor: { kind: "whole" },
    text: "An owner note about this version.",
    author: OWNER,
    tainted: false,
  });
  await bundleComments.addThread(db, {
    artifactId: ARTIFACT,
    versionN: 1,
    anchor: { kind: "whole" },
    text: "A bot note about this version.",
    author: BOT_AUTHOR,
    tainted: true,
  });

  const visible = await visibleThreadsFor(db, depsFor(), {
    report, recipient: a, artifactId: ARTIFACT, versionN: 1, lang: "en",
  });
  assert.deepEqual(visible.map((thread) => thread.id), [mine.threadId],
    "only the reader's own thread, never an owner or bot note");
  assert.deepEqual(visible[0].comments.map((comment) => comment.label),
    [COPY.you.en, COPY.sender.en], "with the owner's reply inside it");
  const texts = visible.flatMap((thread) => thread.comments.map((comment) => comment.text));
  assert.equal(texts.includes("An owner note about this version."), false);
  assert.equal(texts.includes("A bot note about this version."), false);
});

/* ---------------------------------- SF1: the settings come from the verified live set */

test("SF1: a visibility change pauses the report, so a reader keeps `own` until a fresh go-live",
  async () => {
    clock = T0;
    const db = await freshDb();
    const report = await goLive(db, await reportRow(db, { comment_visibility: "own" }));
    const a = await addRecipient(db, report.id, A);
    const b = await addRecipient(db, report.id, B);
    await addVersion(db, { n: 1, reportId: report.id });

    const mine = await post(db, report, a, { versionN: 1, text: "Mine." });
    await post(db, report, b, { versionN: 1, text: "Theirs." });
    const seeThreads = (row) => visibleThreadsFor(db, depsFor(), {
      report: row, recipient: a, artifactId: ARTIFACT, versionN: 1, lang: "en",
    });
    assert.deepEqual((await seeThreads(report)).map((thread) => thread.id), [mine.threadId],
      "`own` shows only this reader's own thread");

    // The owner widens it on the live report: the update pauses the report and NULLs the seal in the same
    // write, so a reader keeps the NARROWEST visibility until a fresh approval.
    const paused = await updateSettings(db, depsFor(), {
      reportId: report.id, settings: { comment_visibility: "all" }, actor: OWNER,
    });
    assert.equal(paused.status, "paused", "a live-set change stops the report");
    assert.equal(paused.live_seal, null, "the seal the old visibility was approved under is gone");
    assert.deepEqual((await seeThreads(paused)).map((thread) => thread.id), [mine.threadId],
      "an unsealed row falls back to `own`, not to the column the owner just wrote");

    // A fresh preview and go-live re-approve it: what the seal says is what the page shows.
    const live = await goLive(db, paused);
    assert.equal(live.status, "live");
    assert.equal((await seeThreads(live)).length, 2, "the re-approved report shows every thread");
  });

test("SF1: a direct SQL UPDATE of comment_visibility widens nothing", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await goLive(db, await reportRow(db, { comment_visibility: "own" }));
  const a = await addRecipient(db, report.id, A);
  const b = await addRecipient(db, report.id, B);
  await addVersion(db, { n: 1, reportId: report.id });
  const mine = await post(db, report, a, { versionN: 1, text: "Mine." });
  await post(db, report, b, { versionN: 1, text: "Theirs." });

  await db.execute({
    sql: "UPDATE reports SET comment_visibility = 'all' WHERE id = ?", args: [report.id],
  });
  const moved = await getReport(db, report.id);
  assert.equal(moved.comment_visibility, "all", "the column really holds the widened word");
  const visible = await visibleThreadsFor(db, depsFor(), {
    report: moved, recipient: a, artifactId: ARTIFACT, versionN: 1, lang: "en",
  });
  assert.deepEqual(visible.map((thread) => thread.id), [mine.threadId],
    "an unsealed column change is not an approval: the reader still sees only their own thread");
});

test("SF1: the window a page and a window pass use is the sealed one, not the column", async () => {
  clock = T0;
  const db = await freshDb();
  // Sealed at two runs, and five versions in all: runs 4 and 5 still accept comments, 1 to 3 did not.
  const draft = await reportRow(db, { comment_window_runs: 2 });
  const recipient = await addRecipient(db, draft.id, A);
  for (const n of [1, 2, 3, 4, 5]) await addVersion(db, { n, reportId: draft.id });
  // Before the approval the row carries no seal, so the default window of four is the one in force.
  assert.equal(await commentOpenFor(db, depsFor(), { report: draft, versionN: 3 }), true);
  const early = await post(db, draft, recipient, { versionN: 3, text: "A question about run three." });

  const report = await goLive(db, draft);
  assert.equal(await commentOpenFor(db, depsFor(), { report, versionN: 3 }), false,
    "the sealed window of two closes run 3 (the default of four would not have)");
  assert.equal(await commentOpenFor(db, depsFor(), { report, versionN: 4 }), true);
  assert.equal(await commentOpenFor(db, depsFor(), { report, versionN: 5 }), true);
  await autoResolveRecipientThreads(db, depsFor(), { report });
  const closed = new Map((await threadRows(db)).map((thread) => [Number(thread.id), thread.status]));
  assert.equal(closed.get(early.threadId), "resolved", "the window pass closes what the sealed window passed");

  // A direct UPDATE of the column, seal untouched: the seal no longer verifies, so the DEFAULT window of
  // four is used and neither the sealed two nor the column's one is.
  await db.execute({ sql: "UPDATE reports SET comment_window_runs = 1 WHERE id = ?", args: [report.id] });
  const moved = await getReport(db, report.id);
  assert.equal(await commentOpenFor(db, depsFor(), { report: moved, versionN: 3 }), true,
    "the default window reaches back to run 3");
  assert.equal(await commentOpenFor(db, depsFor(), { report: moved, versionN: 1 }), false,
    "and no further: the column's own value is never read");
  const late = await post(db, moved, recipient, { versionN: 3, text: "A second question about run three." });
  assert.equal(late.ok, true);
  await autoResolveRecipientThreads(db, depsFor(), { report: moved });
  const after = new Map((await threadRows(db)).map((thread) => [Number(thread.id), thread.status]));
  assert.equal(after.get(late.threadId), "open", "run 3 is inside the default window, so its thread stays open");
});

/* --------------------------------------------------------------------------- caps */

test("the 21st comment of the day is refused", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db);
  const recipient = await addRecipient(db, report.id, A);
  await addVersion(db, { n: 1, reportId: report.id });

  for (let i = 1; i <= 20; i += 1) {
    const posted = await post(db, report, recipient, { versionN: 1, text: `note ${i}` });
    assert.equal(posted.ok, true, `comment ${i} is accepted`);
  }
  await assert.rejects(() => post(db, report, recipient, { versionN: 1, text: "note 21" }), (err) => {
    assert.equal(err.code, "rate_limited");
    return true;
  });
  assert.equal((await sideRows(db)).length, 20, "a refused comment is not recorded");
  assert.equal((await commentRows(db)).length, 20, "and it never reaches the thread store");

  assert.equal(commentErrorLine("rate_limited", "en"), COPY.errRate.en);
  assert.equal(commentErrorLine("rate_limited", "es"), COPY.errRate.es);
});

test("a recipient can still comment on run 30", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db, { comment_window_runs: 4 });
  const recipient = await addRecipient(db, report.id, A);

  for (let n = 1; n <= 30; n += 1) {
    await addVersion(db, { n, reportId: report.id });
    if (n <= 25) {
      const posted = await post(db, report, recipient, { versionN: n, text: `a question about run ${n}` });
      assert.equal(posted.ok, true, `run ${n} accepts one comment`);
      // One report run a day keeps the daily comment cap out of this test's way.
      clock += 25 * 60 * 60 * 1000;
    }
    const resolved = await autoResolveRecipientThreads(db, depsFor(), { report });
    assert.equal(Number.isInteger(resolved), true);
    const openCount = await openThreadCount(db);
    assert.ok(openCount <= 4, `the open thread count stays inside the window (saw ${openCount})`);
  }

  const late = await post(db, report, recipient, {
    versionN: 30, text: "the newest run still takes a comment",
  });
  assert.equal(late.ok, true, "the bundle's own 20 open thread cap never trips");

  const threads = await threadRows(db);
  assert.equal(threads.length, 26, "one thread per posted version plus the newest run's");
  const old = await visibleThreadsFor(db, depsFor(), {
    report, recipient, artifactId: ARTIFACT, versionN: 5, lang: "en",
  });
  assert.equal(old.length, 1, "a resolved thread is still readable");
  assert.equal(old[0].status, "resolved");
  assert.deepEqual(old[0].comments.map((comment) => comment.text), ["a question about run 5"]);
  assert.equal(await openThreadCount(db, recipient.id), 1, "only the newest run's thread is open");
});

/* ------------------------------------------------------------- the owner's notice */

test("too_many_threads reaches the recipient as the plain line and rings the owner once a day", async () => {
  clock = T0;
  const db = await freshDb();
  await db.execute({
    sql: "INSERT INTO project_spaces (id, uuid, slug, name) VALUES (?, ?, ?, ?)",
    args: [PROJECT, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "weekly-listings", "Weekly listings"],
  });
  // The owner switched the reports type off: an essential notice is written anyway, which is the point of
  // this one (nothing else records that readers can no longer start a thread).
  await db.execute({
    sql: "INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('notification_prefs', ?)",
    args: [JSON.stringify({ types_enabled: ["media"] })],
  });
  const report = await reportRow(db);
  const recipient = await addRecipient(db, report.id, A);
  await addVersion(db, { n: 1, reportId: report.id });
  await addVersion(db, { n: 30, reportId: report.id });

  // The bundle's own 20 open thread cap, seeded the way the store would have it.
  for (let i = 1; i <= 20; i += 1) {
    await bundleComments.addThread(db, {
      artifactId: ARTIFACT,
      versionN: 1,
      anchor: { kind: "whole" },
      text: `open thread ${i}`,
      author: { kind: "contact", id: recipient.id },
      tainted: true,
    });
  }
  assert.equal(await openThreadCount(db), 20);

  const refusal = { code: null };
  await assert.rejects(() => post(db, report, recipient, { versionN: 30, text: "one more question" }), (err) => {
    refusal.code = err.code;
    return true;
  });
  assert.equal(refusal.code, "too_many_threads");
  assert.equal(commentErrorLine("too_many_threads", "en"), COPY.errThreads.en);
  assert.equal(commentErrorLine("too_many_threads", "es"), COPY.errThreads.es);

  const rung = await notifications(db);
  assert.equal(rung.length, 1, "the owner was told once");
  assert.equal(rung[0].type, "reports");
  assert.equal(rung[0].source, "reports");
  assert.equal(rung[0].priority, "high");
  assert.equal(rung[0].title,
    "Weekly listings: too many open comments. Readers can't start new ones until older ones close.");
  assert.equal(rung[0].action_url, `/dashboard/project/weekly-listings/reports/${report.id}`);
  const remembered = (await db.execute({
    sql: "SELECT value_json FROM report_state WHERE report_id = ? AND key = ?",
    args: [report.id, NOTICE_DAY_STATE_KEY],
  })).rows[0];
  assert.equal(JSON.parse(remembered.value_json), new Date(T0).toISOString().slice(0, 10));

  await assert.rejects(() => post(db, report, recipient, { versionN: 30, text: "and another" }),
    { code: "too_many_threads" });
  assert.equal((await notifications(db)).length, 1, "a second refusal the same day rings nothing");

  clock = T0 + 25 * 60 * 60 * 1000;
  await assert.rejects(() => post(db, report, recipient, { versionN: 30, text: "the day after" }),
    { code: "too_many_threads" });
  assert.equal((await notifications(db)).length, 2, "the day after rings again");
});

test("the owner's notice is written in the owner's dashboard language", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db);
  await db.execute({
    sql: "INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES ('language', 'es')",
    args: [],
  });

  const rung = await notifyTooManyThreads(db, depsFor(), { report });
  assert.equal(rung, true);
  const rows = await notifications(db);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].title,
    "Weekly listings: demasiados comentarios abiertos. Nadie puede empezar uno nuevo hasta que se cierren los anteriores.");
  assert.equal(rows[0].action_url, "/dashboard/reports", "no project row: the reports list, never a dead link");
});

/* ------------------------------------------------------------------------ refusals */

test("a view-scope token cannot post a comment", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db);
  const recipient = await addRecipient(db, report.id, A);
  await addVersion(db, { n: 1, reportId: report.id });

  await assert.rejects(() => post(db, report, recipient, {
    versionN: 1, text: "I should not be able to say this.", scope: "view",
  }), (err) => {
    assert.equal(err.code, "view_only");
    return true;
  });
  assert.equal(commentErrorLine("view_only", "en"), COPY.errViewOnly.en);
  assert.equal(commentErrorLine("view_only", "es"), COPY.errViewOnly.es);
  assert.equal((await commentRows(db)).length, 0, "a view-only link writes nothing");
  assert.equal((await sideRows(db)).length, 0);
});

test("empty text, an over-long one and exactly 4,000 characters", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db);
  const recipient = await addRecipient(db, report.id, A);
  await addVersion(db, { n: 1, reportId: report.id });

  for (const body of ["", "   ", " \r\n\t ", null]) {
    await assert.rejects(() => post(db, report, recipient, { versionN: 1, text: body }), (err) => {
      assert.equal(err.code, "empty");
      return true;
    });
  }
  assert.equal(commentErrorLine("empty", "en"), COPY.errEmpty.en);
  assert.equal(commentErrorLine("empty", "es"), COPY.errEmpty.es);
  assert.equal((await commentRows(db)).length, 0);

  await assert.rejects(() => post(db, report, recipient, {
    versionN: 1, text: "a".repeat(4001),
  }), (err) => {
    assert.equal(err.code, "too_long");
    return true;
  });
  assert.equal(commentErrorLine("too_long", "en"), COPY.errTooLong.en);
  assert.equal(commentErrorLine("too_long", "es"), COPY.errTooLong.es);
  assert.equal((await commentRows(db)).length, 0);

  const atCap = await post(db, report, recipient, { versionN: 1, text: "a".repeat(4000) });
  assert.equal(atCap.ok, true, "exactly 4,000 characters is accepted");
  const stored = await commentRows(db);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].text.length, 4000);
});

test("an error this module never names answers the generic line", () => {
  assert.equal(commentErrorLine("other", "en"), COPY.errOther.en);
  assert.equal(commentErrorLine("other", "es"), COPY.errOther.es);
  assert.equal(commentErrorLine(undefined, "en"), COPY.errOther.en);
  assert.equal(commentErrorLine("something_else", "es"), COPY.errOther.es);
});

/* -------------------------------------------------------------------- one thread */

test("a follow-up goes into the recipient's open thread", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db);
  const recipient = await addRecipient(db, report.id, A);
  await addVersion(db, { n: 1, reportId: report.id });

  const first = await post(db, report, recipient, { versionN: 1, text: "The total looks wrong." });
  const second = await post(db, report, recipient, { versionN: 1, text: "It is off by one row." });
  assert.equal(second.threadId, first.threadId, "a follow-up continues the reader's own open thread");
  assert.notEqual(second.commentId, first.commentId);

  const threads = await threadRows(db);
  assert.equal(threads.length, 1);
  const comments = (await commentRows(db)).filter((row) => Number(row.thread_id) === first.threadId);
  assert.deepEqual(comments.map((row) => row.text), ["The total looks wrong.", "It is off by one row."]);
  assert.equal((await sideRows(db)).length, 2);
});

test("a resolved thread starts a new one", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await reportRow(db);
  const recipient = await addRecipient(db, report.id, A);
  await addVersion(db, { n: 1, reportId: report.id });

  const first = await post(db, report, recipient, { versionN: 1, text: "The first question." });
  await bundleComments.setThreadStatus(db, {
    threadId: first.threadId, status: "resolved", artifactId: ARTIFACT,
  });

  const second = await post(db, report, recipient, { versionN: 1, text: "A new question." });
  assert.notEqual(second.threadId, first.threadId, "a resolved thread never takes the next comment");

  const threads = await threadRows(db);
  assert.deepEqual(threads.map((thread) => thread.status), ["resolved", "open"]);
  const visible = await visibleThreadsFor(db, depsFor(), {
    report, recipient, artifactId: ARTIFACT, versionN: 1, lang: "en",
  });
  assert.deepEqual(visible.map((thread) => thread.status).sort(), ["open", "resolved"],
    "the closed thread stays readable beside the new one");
});

/* ------------------------------------------------------------------- the window */

test("autoResolveRecipientThreads closes only past the window or after the bot answered", async () => {
  clock = T0;
  const db = await freshDb();
  // A window of two, approved over a draft that already carried three versions: the posts below are made
  // while the row is still unsealed (the default window of four covers all three).
  const draft = await reportRow(db, { comment_window_runs: 2 });
  const recipient = await addRecipient(db, draft.id, A);

  await addVersion(db, { n: 10, reportId: draft.id });
  await addVersion(db, { n: 11, reportId: draft.id });
  await addVersion(db, { n: 12, reportId: draft.id });

  const old = await post(db, draft, recipient, { versionN: 10, text: "an old question" });
  const inside = await post(db, draft, recipient, { versionN: 11, text: "a question inside the window" });
  const newest = await post(db, draft, recipient, { versionN: 12, text: "the newest question" });

  const report = await goLive(db, draft);
  const resolved = await autoResolveRecipientThreads(db, depsFor(), { report });
  assert.ok(resolved >= 1);
  const byId = new Map((await threadRows(db)).map((thread) => [Number(thread.id), thread.status]));
  assert.equal(byId.get(old.threadId), "resolved", "a version past the window closes");
  assert.equal(byId.get(inside.threadId), "open", "a version inside the window stays open");
  assert.equal(byId.get(newest.threadId), "open");

  // The pickup answered the one inside the window: it closes even though its version is not past yet.
  await bundleComments.addComment(db, {
    threadId: inside.threadId, text: "Answered.", author: BOT_AUTHOR, tainted: true,
  });
  await autoResolveRecipientThreads(db, depsFor(), { report });
  const after = new Map((await threadRows(db)).map((thread) => [Number(thread.id), thread.status]));
  assert.equal(after.get(inside.threadId), "resolved", "a thread the bot answered closes");
  assert.equal(after.get(newest.threadId), "open", "the newest version's thread is never resolved this way");

  // Idempotent, and a pass over a report with no versions at all closes nothing.
  assert.equal(await autoResolveRecipientThreads(db, depsFor(), { report }), 0);
  const empty = await reportRow(db, { comment_window_runs: 4 });
  assert.equal(await autoResolveRecipientThreads(db, depsFor(), { report: empty }), 0);
  assert.equal(await autoResolveRecipientThreads(db, depsFor(), { report: null }), 0);
});

/* ------------------------------------------------------- SF2: the window is enforced */

test("SF2: a version past the verified window stays readable and takes no comment", async () => {
  clock = T0;
  const db = await freshDb();
  const report = await goLive(db, await reportRow(db, { comment_window_runs: 2 }));
  const recipient = await addRecipient(db, report.id, A);
  for (const n of [1, 2, 3]) await addVersion(db, { n, reportId: report.id });

  // Run 1 is past the window: its page is still built (the read is not refused), it just has no form.
  const readable = await visibleThreadsFor(db, depsFor(), {
    report, recipient, artifactId: ARTIFACT, versionN: 1, lang: "en",
  });
  assert.deepEqual(readable, [], "no thread yet, and nothing about the read is refused");
  assert.equal(await commentOpenFor(db, depsFor(), { report, versionN: 1 }), false);

  await assert.rejects(() => post(db, report, recipient, {
    versionN: 1, text: "one more thing about run one",
  }), (err) => {
    assert.equal(err.code, "view_only", "a closed version answers the line a view-only link gets");
    return true;
  });
  assert.equal(commentErrorLine("view_only", "en"), COPY.errViewOnly.en);
  assert.equal(commentErrorLine("view_only", "es"), COPY.errViewOnly.es);
  assert.equal((await commentRows(db)).length, 0, "a refused comment never reaches the thread store");
  assert.equal((await sideRows(db)).length, 0);

  const second = await post(db, report, recipient, { versionN: 2, text: "run two still takes one" });
  const third = await post(db, report, recipient, { versionN: 3, text: "and so does the newest run" });
  assert.equal(second.ok, true, "the second of the newest two runs is inside the window");
  assert.equal(third.ok, true, "the newest run is always inside it");
  assert.notEqual(second.threadId, third.threadId);
  assert.equal((await commentRows(db)).length, 2);
});

test("the default window is four runs when nothing is sealed", async () => {
  assert.equal(DEFAULT_COMMENT_WINDOW_RUNS, 4);
});