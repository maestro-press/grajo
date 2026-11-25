// A report pickup's door: `servers/gateway/reports/pickup-mcp.js` and the rails around
// `/report-pickup/mcp`, plus the model check its launcher uses (`reports/pickup-model.js`).
//
// The mount is wired exactly as `servers/gateway/boot/mcp-mounts.js` wires it (the global JSON parser →
// localTokenAuthMiddleware → the pickup mount guard → mountMcpServer), with the real MCP SDK client over
// Streamable HTTP. Tokens come from the real pickup-token module and actor signatures from the real
// per-boot key, so a request this file admits is one the gateway admits.
//
// Harness: one real init-db'd scratch crow.db (the reports tables are init-db's own) with the artifacts
// bundle's tables from the bundle's own `initArtifactsTables`, and the bundle's own `comments.js` from
// this repo passed as the `comments` seam (the same module an installed instance runs from
// `<CROW_HOME>/bundles/artifacts/server`). Every test seeds its OWN artifact, report and threads, so no
// test reads another's rows. Nothing here sends, schedules, proposes or spawns.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import express from "express";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { rmScratch } from "./helpers/safe-rm.js";

const root = mkdtempSync(join(tmpdir(), "reports-pickup-mcp-"));
/** The scratch home, held in a constant: cleanup never re-reads the env (tests/helpers/safe-rm.js). */
const CROW_HOME = join(root, "home");
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = CROW_HOME;
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");
const BUNDLE = join(REPO, "bundles", "artifacts", "server");
const bundleImport = (file) => import(pathToFileURL(join(BUNDLE, file)).href);
const bundleComments = await bundleImport("comments.js");
const { initArtifactsTables } = await bundleImport("init-tables.js");

const { createDbClient } = await import("../servers/db.js");
const { SessionManager } = await import("../servers/gateway/session-manager.js");
const { mountMcpServer } = await import("../servers/gateway/routes/mcp.js");
const { localTokenAuthMiddleware } = await import("../servers/gateway/local-token.js");
const door = await import("../servers/gateway/reports/pickup-mcp.js");
const { mailDraftMountAuth } = await import("../servers/gateway/mail-draft-mcp.js");
const { pickupCheckModel, MODEL_NOT_LOCAL } = await import("../servers/gateway/reports/pickup-model.js");
const { createReport, getReport, updateReportColumns } = await import("../servers/gateway/reports/store.js");
const {
  mintPickupToken, revokePickupToken, _resetPickupTokensForTests,
} = await import("../servers/gateway/reports/pickup-token.js");
const { mintTurnToken, _resetTurnTokensForTests } = await import("../servers/gateway/mail/drafts/turn-token.js");
const {
  initGatewayActorKey, signActor, signMailDraftActor, signReportsActor, signReportPickupActor,
  verifyReportPickupActorSig,
} = await import("../scripts/pi-bots/actor-sig.mjs");

const BOT = "draftbot";
const OTHER_BOT = "otherbot";
const PROJECT = 1;
const TURN_TIMEOUT_LONG = 300_000;
/** A mail turn token's draft id, used only to show an `mdt_` bearer opens nothing here. */
const MAIL_DRAFT_ID = "md-0123456789abcdef";
const TEST_TIMEOUT = 30_000;
const FETCH_TIMEOUT = 10_000;

const state = { db: null, crow: null, http: null, port: 0, seq: 0, artifact: 0 };

/** A fresh artifact id, so every test's threads live on their own report. */
function nextArtifact(label) {
  state.artifact += 1;
  return `art-pickup-${state.artifact}-${label}`;
}

before(async () => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
  const dir = join(root, "instance");
  mkdirSync(dir, { recursive: true });
  state.crow = join(dir, "crow.db");
  copyFileSync(MASTER, state.crow);
  state.db = createDbClient(state.crow);
  // The bundle-owned tables, made by the bundle's own installer.
  await initArtifactsTables(state.db);

  const app = express();
  app.use(express.json());
  app.use(localTokenAuthMiddleware(state.db));
  const authMiddleware = (req, res, next) => (req.localTokenAuth
    ? next()
    : res.status(401).json({ error: "unauthorized" }));
  const peerExposureGate = async () => true;
  const sessionManager = new SessionManager();

  // The pickup mount, exactly as boot installs it: the guard first, then the MCP mount.
  app.use(door.PICKUP_MCP_PREFIX, door.pickupMountAuth({ verifyActor: verifyReportPickupActorSig }));
  // A read-only probe BEHIND the guard: what the guard pinned is what a handler reads.
  app.get(door.PICKUP_MCP_PREFIX + "/claims", (req, res) => res.json(req.auth.extra));
  mountMcpServer(app, door.PICKUP_MCP_PREFIX, () => door.createPickupMcpServer({
    createDb: () => createDbClient(state.crow),
    verifyActor: verifyReportPickupActorSig,
    comments: bundleComments,
  }), sessionManager, authMiddleware, peerExposureGate);
  // The mail door's guard, so each kind's token can be tried against the other's door.
  app.use("/mail-draft", mailDraftMountAuth());
  app.get("/mail-draft/claims", (req, res) => res.json({ ok: true }));

  state.http = app.listen(0, "127.0.0.1");
  await new Promise((done, fail) => {
    state.http.once("listening", done);
    state.http.once("error", fail);
  });
  state.port = state.http.address().port;
  initGatewayActorKey();
});

after(async () => {
  await new Promise((done) => { try { state.http.close(done); } catch { done(); } });
  try { state.db.close(); } catch { /* already closed */ }
  rmScratch(root);
});

beforeEach(() => {
  _resetPickupTokensForTests();
  _resetTurnTokensForTests();
});

/* ------------------------------------------------------------------- the harness */

/** One MCP client for the pickup door, with whatever headers the case under test carries. */
async function connect(headers) {
  const transport = new StreamableHTTPClientTransport(
    new URL(`http://127.0.0.1:${state.port}${door.PICKUP_DOOR_PATH}`),
    { requestInit: { headers } },
  );
  const client = new Client({ name: "reports-pickup-test", version: "0" });
  try {
    await client.connect(transport);
  } catch (err) {
    try { await client.close(); } catch { /* ignore */ }
    try { await transport.close(); } catch { /* ignore */ }
    throw err;
  }
  return client;
}

/** A raw status, for the refusals that never reach a session. */
async function post(path, headers = {}, body = { jsonrpc: "2.0", id: 1, method: "tools/list" }) {
  const res = await fetch(`http://127.0.0.1:${state.port}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(FETCH_TIMEOUT),
  });
  const status = res.status;
  try { await res.body?.cancel(); } catch { /* already consumed */ }
  return status;
}

/** A raw GET, for the two probe routes behind each guard. */
async function get(path, headers = {}) {
  const res = await fetch(`http://127.0.0.1:${state.port}${path}`, {
    headers, signal: AbortSignal.timeout(FETCH_TIMEOUT),
  });
  let body = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body };
}

/** One tool call's JSON body. */
async function call(client, name, args = {}) {
  const result = await client.callTool({ name, arguments: args });
  const text = (result.content ?? []).map((part) => part.text ?? "").join("");
  let json = null;
  try { json = JSON.parse(text); } catch { json = null; }
  return { isError: Boolean(result.isError), text, json };
}

/** One report's artifact row, and the version every thread on it needs. */
async function addArtifact(artifactId) {
  await state.db.execute({
    sql: "INSERT OR IGNORE INTO artifacts (id, title, type) VALUES (?, 'Weekly listings', 'document')",
    args: [artifactId],
  });
  await state.db.execute({
    sql: `INSERT OR IGNORE INTO artifact_versions
            (artifact_id, n, state, files_json, size, content_hash, made_by)
          VALUES (?, 1, 'past', '[]', 0, 'abc', 'user')`,
    args: [artifactId],
  });
}

/** A thread with its first comment, written by whoever the test names. */
async function addThread(artifactId, text, { author = { kind: "owner" }, tainted = false } = {}) {
  await addArtifact(artifactId);
  return bundleComments.addThread(state.db, {
    artifactId, versionN: 1, anchor: { kind: "whole" }, text, author, tainted,
  });
}

/** One report pointing at an artifact, in the given project, and LIVE — the state a pickup's batch is
 *  actually minted in (the door refuses a draft or a paused report's batch). */
async function reportFor(artifactId, { botId = BOT, title = "Weekly listings" } = {}) {
  const { id } = await createReport(state.db, { projectId: PROJECT, owner: "owner", botId, title });
  await updateReportColumns(state.db, id, {
    status: "live",
    artifact_id: artifactId,
    comment_tier_default: "c",
    comment_visibility: "own",
    comment_window_runs: 4,
  });
  return getReport(state.db, id);
}

/** A minted token for one pickup, with the pickup and turn ids its signature is computed over. `pickupId`
 *  (optional) pins the row id, so two turns can name the SAME pickup (the reply ledger's own cases). */
function mintFor({ report, artifactId, threadIds, botId = BOT, ttlMs = TURN_TIMEOUT_LONG, pickupId } = {}) {
  state.seq += 1;
  const pickup = pickupId === undefined ? `rpu-${String(state.seq).padStart(16, "0")}` : pickupId;
  const turnId = `turn-${state.seq}`;
  const token = mintPickupToken({
    reportId: report.id,
    pickupId: pickup,
    turnId,
    botId,
    threadIds,
    commentIds: threadIds,
    artifactId,
    ttlMs,
  });
  return { token, pickupId: pickup, turnId, botId };
}

/** The actor headers a pickup turn's config carries, with any one field overridden by a case. */
function headersFor(turn, over = {}) {
  const botId = over.botId === undefined ? turn.botId : over.botId;
  const actorKind = over.actorKind === undefined ? "report-pickup" : over.actorKind;
  const signature = over.sig === undefined
    ? signReportPickupActor({ botId: turn.botId, pickupId: turn.pickupId, turnId: turn.turnId })
    : over.sig;
  const headers = {};
  if (over.token === undefined || over.token !== null) headers.authorization = `Bearer ${over.token ?? turn.token}`;
  if (actorKind !== null) headers["x-crow-actor-kind"] = actorKind;
  if (botId !== null) headers["x-crow-actor-id"] = botId;
  if (signature !== null) headers["x-crow-actor-sig"] = signature;
  return headers;
}

/** Every comment row of one thread, oldest first, as the DB holds it. */
async function commentsOf(threadId) {
  const { rows } = await state.db.execute({
    sql: "SELECT * FROM artifact_comments WHERE thread_id = ? ORDER BY id", args: [threadId],
  });
  return rows;
}

/* ================================================================ 1. the surface */

test("a pickup reaches exactly three tools", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("surface");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "Is the total right?");
  const turn = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });

  const client = await connect(headersFor(turn));
  try {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name), ["report_reply", "report_make_card", "report_propose_change"]);
    assert.deepEqual([...door.PICKUP_TOOL_NAMES], ["report_reply", "report_make_card", "report_propose_change"]);
    for (const tool of tools) assert.doesNotMatch(tool.name, /mail.*(send|schedule)/i);
  } finally { await client.close(); }
});

/* ============================================================== 2. a written reply */

test("a reply on a thread in the token's set is written as the report's bot, on its artifact", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("write");
  const report = await reportFor(artifact);
  assert.equal(report.artifact_id, artifact);
  const thread = await addThread(artifact, "Is the total right?");
  const turn = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });

  const client = await connect(headersFor(turn));
  let written = null;
  try {
    const result = await call(client, "report_reply", {
      threadId: String(thread.threadId), text: "  Yes: 412 this week.  ",
    });
    assert.equal(result.isError, false, result.text);
    assert.equal(result.json.ok, true);
    assert.equal(Number.isInteger(result.json.commentId), true);
    // The answer carries the id it wrote and nothing else — no echo of the text.
    assert.deepEqual(Object.keys(result.json).sort(), ["commentId", "ok"]);
    written = Number(result.json.commentId);
  } finally { await client.close(); }

  const rows = await commentsOf(thread.threadId);
  assert.equal(rows.length, 2, "the reply is one more comment on that thread");
  const reply = rows.find((row) => Number(row.id) === written);
  assert.ok(reply, "the answer names the row it wrote");
  assert.equal(reply.text, "Yes: 412 this week.", "the text is trimmed, as the bundle trims it");
  assert.equal(reply.author_kind, "bot");
  assert.equal(reply.author_id, BOT, "the author is the report's own bot, from the token");
  assert.equal(Number(reply.tainted), 1,
    "a pickup reply is always tainted: this turn read the whole batch, whatever this thread held");
  const { rows: threadRows } = await state.db.execute({
    sql: "SELECT artifact_id FROM artifact_threads WHERE id = ?", args: [thread.threadId],
  });
  assert.equal(threadRows[0].artifact_id, report.artifact_id, "the reply landed on the report's artifact");
});

/* ================================================== 3. a thread outside the set */

test("a thread outside the pickup's set is refused not_found, and nothing is written", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("outside");
  const report = await reportFor(artifact);
  const mine = await addThread(artifact, "the thread this pickup was given");
  const other = await addThread(artifact, "another thread on the same artifact");
  const turn = mintFor({ report, artifactId: artifact, threadIds: [String(mine.threadId)] });
  const before = (await commentsOf(other.threadId)).length;
  const mineBefore = (await commentsOf(mine.threadId)).length;

  const client = await connect(headersFor(turn));
  try {
    // A thread that EXISTS on the report's artifact but is not in the token's set answers exactly
    // what a nonexistent thread answers: one code, no oracle.
    for (const threadId of [String(other.threadId), "999999", "not-a-thread"]) {
      const result = await call(client, "report_reply", { threadId, text: "an answer nobody asked for" });
      assert.equal(result.isError, true, threadId);
      assert.deepEqual(result.json, { error: "not_found" }, `no echo for ${threadId}`);
    }
  } finally { await client.close(); }
  assert.equal((await commentsOf(other.threadId)).length, before, "the other thread got nothing");
  assert.equal((await commentsOf(mine.threadId)).length, mineBefore, "and neither did this one");
});

/* ============================================== 4. one report's token, another's */

test("report A's token cannot reply on report B's artifact or thread", { timeout: TEST_TIMEOUT }, async () => {
  const artifactA = nextArtifact("a");
  const artifactB = nextArtifact("b");
  const reportA = await reportFor(artifactA, { title: "A" });
  const reportB = await reportFor(artifactB, { title: "B" });
  const threadA = await addThread(artifactA, "A's thread");
  const threadB = await addThread(artifactB, "B's thread");
  const countB = (await commentsOf(threadB.threadId)).length;
  const countA = (await commentsOf(threadA.threadId)).length;

  // (a) A's token names A's thread only: B's thread is simply not in the set.
  const aTurn = mintFor({ report: reportA, artifactId: artifactA, threadIds: [String(threadA.threadId)] });
  const clientA = await connect(headersFor(aTurn));
  try {
    const result = await call(clientA, "report_reply", { threadId: String(threadB.threadId), text: "hello B" });
    assert.deepEqual(result.json, { error: "not_found" });
  } finally { await clientA.close(); }

  // (b) A token minted for report A whose artifact claim is B's: the thread IS in the set, so the
  // report row's own column is what refuses it.
  const crossed = mintFor({ report: reportA, artifactId: artifactB, threadIds: [String(threadB.threadId)] });
  const clientCrossed = await connect(headersFor(crossed));
  try {
    const result = await call(clientCrossed, "report_reply", { threadId: String(threadB.threadId), text: "hello B" });
    assert.deepEqual(result.json, { error: "not_found" }, "the report row's artifact is A's, not the claim's");
  } finally { await clientCrossed.close(); }

  // (c) A token naming another bot: the report row's bot is not that bot, so it refuses too (the mount
  // admits it, because the signature is that other bot's own over this same pickup and turn).
  const otherBotTurn = mintFor({
    report: reportA, artifactId: artifactA, threadIds: [String(threadA.threadId)], botId: OTHER_BOT,
  });
  const clientOther = await connect(headersFor(otherBotTurn));
  try {
    const result = await call(clientOther, "report_reply", { threadId: String(threadA.threadId), text: "hello A" });
    assert.deepEqual(result.json, { error: "not_found" }, "the report names another bot");
  } finally { await clientOther.close(); }
  assert.equal((await commentsOf(threadB.threadId)).length, countB, "B's thread got nothing");
  assert.equal((await commentsOf(threadA.threadId)).length, countA, "A's thread got nothing");

  // B's own token writes on B, which proves the refusals above were about the report, not the path.
  const bTurn = mintFor({ report: reportB, artifactId: artifactB, threadIds: [String(threadB.threadId)] });
  const clientB = await connect(headersFor(bTurn));
  try {
    const result = await call(clientB, "report_reply", { threadId: String(threadB.threadId), text: "B's own answer" });
    assert.equal(result.isError, false, result.text);
  } finally { await clientB.close(); }
  assert.equal((await commentsOf(threadB.threadId)).length, countB + 1, "exactly one reply was written");
});

/* ================================================================== 5. taint */

test("every pickup reply is written tainted, whatever the thread's own comments are", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("taint");
  const report = await reportFor(artifact);

  // A thread whose only comment is the owner's own note: its rows are clean, and the reply is STILL
  // tainted. THE RULE'S READING: taint is a property of the TURN that wrote the reply — a pickup read the
  // whole mixed batch — not of the thread's own comments, the bot or the report.
  const clean = await addThread(artifact, "My own note");
  // A thread a recipient wrote in: its comment is tainted, and so is the reply.
  const tainted = await addThread(artifact, "A recipient's words");
  await bundleComments.addComment(state.db, {
    threadId: tainted.threadId,
    text: "a reader's follow-up",
    author: { kind: "contact", id: "rrc-00000000000000a1" },
    tainted: true,
  });
  // A thread with no readable state at all: its comment rows are gone, and the reply is tainted like
  // every other pickup reply (so a row-less thread can never read as a clean one).
  const empty = await addThread(artifact, "a thread whose rows cannot be read");
  await state.db.execute({ sql: "DELETE FROM artifact_comments WHERE thread_id = ?", args: [empty.threadId] });

  const turn = mintFor({
    report,
    artifactId: artifact,
    threadIds: [String(clean.threadId), String(tainted.threadId), String(empty.threadId)],
  });
  const client = await connect(headersFor(turn));
  try {
    for (const threadId of [clean.threadId, tainted.threadId, empty.threadId]) {
      const result = await call(client, "report_reply", { threadId: String(threadId), text: "an answer" });
      assert.equal(result.isError, false, `${threadId}: ${result.text}`);
    }
  } finally { await client.close(); }

  const cleanRows = await commentsOf(clean.threadId);
  assert.equal(Number(cleanRows.at(-1).tainted), 1,
    "even a thread whose own comments are clean gets a tainted reply (the turn read a mixed batch)");
  const taintedRows = await commentsOf(tainted.threadId);
  assert.equal(Number(taintedRows.at(-1).tainted), 1, "a reply into a tainted thread is tainted");
  const emptyRows = await commentsOf(empty.threadId);
  assert.equal(emptyRows.length, 1);
  assert.equal(Number(emptyRows[0].tainted), 1, "an unreadable thread is not a clean one");
});

test("a reply in the owner's own thread is tainted when the same pickup also read a recipient's thread", { timeout: TEST_TIMEOUT }, async () => {
  // THE B1 CASE, end to end: one pickup whose batch holds a recipient's (tainted) thread X and the
  // owner's own (clean) thread Y. A reply in Y must STILL be written tainted, because the turn that wrote
  // it read X as well — otherwise outside text from X could reach Y's reply as if it were clean.
  const artifact = nextArtifact("mixed");
  const report = await reportFor(artifact);
  const ownerThread = await addThread(artifact, "My own note");
  const recipientThread = await addThread(artifact, "A recipient's words");
  await bundleComments.addComment(state.db, {
    threadId: recipientThread.threadId,
    text: "a reader's follow-up",
    author: { kind: "contact", id: "rrc-00000000000000a2" },
    tainted: true,
  });
  const turn = mintFor({
    report, artifactId: artifact, threadIds: [String(ownerThread.threadId), String(recipientThread.threadId)],
  });

  const client = await connect(headersFor(turn));
  try {
    const result = await call(client, "report_reply", {
      threadId: String(ownerThread.threadId), text: "an answer in my own thread",
    });
    assert.equal(result.isError, false, result.text);
  } finally { await client.close(); }

  const ownerRows = await commentsOf(ownerThread.threadId);
  assert.equal(Number(ownerRows.at(-1).tainted), 1,
    "the owner's own thread's reply is tainted: this pickup's batch carried a recipient's thread too");
  assert.equal(ownerRows.at(-1).author_kind, "bot", "and it is still the report's bot that wrote it");
});

/* ====================================== 5b. the report's state, the thread's state */

test("a resolved thread is refused and nothing is written", { timeout: TEST_TIMEOUT }, async () => {
  // A closed thread takes no answer: its reader is done with it. The refusal is the door's one fixed
  // code, exactly as for a thread that does not exist.
  const artifact = nextArtifact("resolved");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "a thread nobody is reading any more");
  await bundleComments.setThreadStatus(state.db, {
    threadId: thread.threadId, status: "resolved", artifactId: artifact,
  });
  const before = (await commentsOf(thread.threadId)).length;
  const turn = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });

  const client = await connect(headersFor(turn));
  try {
    const result = await call(client, "report_reply", {
      threadId: String(thread.threadId), text: "an answer into a closed thread",
    });
    assert.equal(result.isError, true, result.text);
    assert.deepEqual(result.json, { error: "not_found" }, "one fixed code, no oracle");
  } finally { await client.close(); }
  assert.equal((await commentsOf(thread.threadId)).length, before, "nothing was written");
});

test("a report that is not live (draft, paused) refuses every reply and writes nothing", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("not-live");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "a thread on a report that is not delivering");
  const before = (await commentsOf(thread.threadId)).length;

  for (const status of ["draft", "paused"]) {
    await updateReportColumns(state.db, report.id, { status });
    const turn = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });
    const client = await connect(headersFor(turn));
    try {
      const result = await call(client, "report_reply", {
        threadId: String(thread.threadId), text: "an answer nobody is delivering",
      });
      assert.equal(result.isError, true, `${status}: ${result.text}`);
      assert.deepEqual(result.json, { error: "not_found" }, status);
    } finally { await client.close(); }
    assert.equal((await commentsOf(thread.threadId)).length, before, `${status}: nothing was written`);
  }

  // The control: back to live, the same pickup shape writes one reply (so the refusals above are the
  // report's status, not a broken harness).
  await updateReportColumns(state.db, report.id, { status: "live" });
  const turn = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });
  const client = await connect(headersFor(turn));
  try {
    const result = await call(client, "report_reply", { threadId: String(thread.threadId), text: "the answer" });
    assert.equal(result.isError, false, result.text);
  } finally { await client.close(); }
  assert.equal((await commentsOf(thread.threadId)).length, before + 1, "a live report's thread takes the reply");
});

test("an open or an anchor-moved thread on a live report is accepted", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("open-states");
  const report = await reportFor(artifact);
  const open = await addThread(artifact, "an open thread");
  const moved = await addThread(artifact, "a thread whose anchor moved");
  await state.db.execute({
    sql: "UPDATE artifact_threads SET status = 'anchor-moved' WHERE id = ?", args: [moved.threadId],
  });
  const turn = mintFor({
    report, artifactId: artifact, threadIds: [String(open.threadId), String(moved.threadId)],
  });

  const client = await connect(headersFor(turn));
  try {
    for (const thread of [open, moved]) {
      const result = await call(client, "report_reply", { threadId: String(thread.threadId), text: "an answer" });
      assert.equal(result.isError, false, `${thread.threadId}: ${result.text}`);
    }
  } finally { await client.close(); }
  assert.equal((await commentsOf(open.threadId)).length, 2, "the open thread got its reply");
  assert.equal((await commentsOf(moved.threadId)).length, 2, "so did the moved-anchor thread");
});

/* ========================================= 5c. one reply per thread per pickup */

test("one pickup answers a thread once: a second reply is refused and nothing more is written", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("one-per-thread");
  const report = await reportFor(artifact);
  const first = await addThread(artifact, "the first thread of the batch");
  const second = await addThread(artifact, "the second thread of the batch");
  const secondBefore = (await commentsOf(second.threadId)).length;
  const turn = mintFor({
    report, artifactId: artifact, threadIds: [String(first.threadId), String(second.threadId)],
  });

  const client = await connect(headersFor(turn));
  try {
    const written = await call(client, "report_reply", { threadId: String(first.threadId), text: "the answer" });
    assert.equal(written.isError, false, written.text);
    const twice = await call(client, "report_reply", { threadId: String(first.threadId), text: "the same answer again" });
    assert.equal(twice.isError, true, twice.text);
    assert.deepEqual(twice.json, { error: "already_replied" }, "one pickup, one answer per thread");
    // Another thread of the SAME pickup is untouched by the refusal above.
    const other = await call(client, "report_reply", { threadId: String(second.threadId), text: "an answer here" });
    assert.equal(other.isError, false, other.text);
  } finally { await client.close(); }
  assert.equal((await commentsOf(first.threadId)).length, 2, "exactly one reply in the first thread");
  assert.equal((await commentsOf(second.threadId)).length, secondBefore + 1, "and one in the second");
});

test("two pickups' reply ledgers are independent for the same thread", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("ledgers");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "a thread two pickups were each given");
  const before = (await commentsOf(thread.threadId)).length;
  const a = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });
  const b = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });
  assert.notEqual(a.pickupId, b.pickupId, "two different pickups");

  for (const turn of [a, b]) {
    const client = await connect(headersFor(turn));
    try {
      const result = await call(client, "report_reply", { threadId: String(thread.threadId), text: "an answer" });
      assert.equal(result.isError, false, `${turn.pickupId}: ${result.text}`);
    } finally { await client.close(); }
  }
  assert.equal((await commentsOf(thread.threadId)).length, before + 2, "one reply from each pickup");
});

test("a failed write gives the reply slot back, and a retry works", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("failed-write");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "a thread whose first answer failed to write");
  const before = (await commentsOf(thread.threadId)).length;
  const turn = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });
  const claims = {
    reportId: report.id,
    pickupId: turn.pickupId,
    botId: BOT,
    artifactId: artifact,
    threadIds: [String(thread.threadId)],
    commentIds: [String(thread.threadId)],
  };
  let calls = 0;
  const seam = Object.assign({}, bundleComments, {
    addComment: async (db, args) => {
      calls += 1;
      if (calls === 1) throw Object.assign(new Error("the write failed"), { code: "other" });
      return bundleComments.addComment(db, args);
    },
  });
  const args = { threadId: String(thread.threadId), text: "the answer" };

  const first = await door.replyFromPickup(state.db, claims, args, { comments: seam });
  assert.equal(first.isError, true, "the failing seam refuses the tool call");
  assert.deepEqual(JSON.parse(first.content[0].text), { error: "other" });
  assert.equal((await commentsOf(thread.threadId)).length, before, "the failed write wrote nothing");

  const retry = await door.replyFromPickup(state.db, claims, args, { comments: seam });
  assert.equal(Boolean(retry.isError), false, "the retry is not refused as already_replied");
  assert.equal((await commentsOf(thread.threadId)).length, before + 1, "and it wrote exactly one reply");
});

test("revoking a token drops its pickup's reply ledger, so a re-minted token starts clean", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("ledger-revoke");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "a thread answered by a pickup whose turn ended");
  const before = (await commentsOf(thread.threadId)).length;
  const first = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });

  const client = await connect(headersFor(first));
  try {
    const result = await call(client, "report_reply", { threadId: String(thread.threadId), text: "the answer" });
    assert.equal(result.isError, false, result.text);
    const twice = await call(client, "report_reply", { threadId: String(thread.threadId), text: "again" });
    assert.deepEqual(twice.json, { error: "already_replied" }, "the slot is held while the turn is live");
  } finally { await client.close(); }

  revokePickupToken(first.token);
  // The same PICKUP id, re-minted for a later turn: the ledger went with the revoked token.
  const second = mintFor({
    report, artifactId: artifact, threadIds: [String(thread.threadId)], pickupId: first.pickupId,
  });
  const client2 = await connect(headersFor(second));
  try {
    const result = await call(client2, "report_reply", { threadId: String(thread.threadId), text: "the later answer" });
    assert.equal(result.isError, false, result.text);
  } finally { await client2.close(); }
  assert.equal((await commentsOf(thread.threadId)).length, before + 2, "one reply from each turn");
});

test("one pickup with TWO live tokens keeps its reply ledger when only one is revoked", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("ledger-two-tokens");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "a thread two turns of one pickup were both given");
  const before = (await commentsOf(thread.threadId)).length;

  // Two tokens for ONE pickup: a turn minted beside another live one. They share the ledger, so the
  // answer the first one writes is already an answer for the second.
  const first = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });
  const second = mintFor({
    report, artifactId: artifact, threadIds: [String(thread.threadId)], pickupId: first.pickupId,
  });
  assert.equal(second.pickupId, first.pickupId, "the two tokens name the same pickup");
  assert.notEqual(second.token, first.token);

  const client = await connect(headersFor(first));
  try {
    const written = await call(client, "report_reply", { threadId: String(thread.threadId), text: "the answer" });
    assert.equal(written.isError, false, written.text);
  } finally { await client.close(); }

  revokePickupToken(first.token);
  // Token 2 is still live and names the same pickup, so the ledger stays: the thread is answered.
  const client2 = await connect(headersFor(second));
  try {
    const twice = await call(client2, "report_reply", { threadId: String(thread.threadId), text: "the same answer again" });
    assert.equal(twice.isError, true, twice.text);
    assert.deepEqual(twice.json, { error: "already_replied" }, "the ledger outlived the token that went first");
  } finally { await client2.close(); }
  assert.equal((await commentsOf(thread.threadId)).length, before + 1, "exactly one reply was written");

  revokePickupToken(second.token);
  // No live token names the pickup any more: the ledger is gone, so a re-minted token starts clean.
  const third = mintFor({
    report, artifactId: artifact, threadIds: [String(thread.threadId)], pickupId: first.pickupId,
  });
  const client3 = await connect(headersFor(third));
  try {
    const result = await call(client3, "report_reply", { threadId: String(thread.threadId), text: "a later answer" });
    assert.equal(result.isError, false, result.text);
  } finally { await client3.close(); }
  assert.equal((await commentsOf(thread.threadId)).length, before + 2, "one reply from each pickup turn");
});

/* ================================================== 6. arguments cannot widen it */

test("arguments cannot name a bot, an author, a report, an artifact or a taint", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("arguments");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "Is the total right?");
  const turn = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });
  const before = (await commentsOf(thread.threadId)).length;

  const client = await connect(headersFor(turn));
  try {
    const extra = [
      { botId: OTHER_BOT },
      { author: { kind: "owner" } },
      { reportId: "rpt-fedcba9876543210" },
      { artifactId: artifact },
      { tainted: false },
      { threadIds: [String(thread.threadId)] },
    ];
    for (const args of extra) {
      const result = await call(client, "report_reply", {
        threadId: String(thread.threadId), text: "hi", ...args,
      });
      assert.equal(result.isError, true, JSON.stringify(args));
      assert.match(result.text, /validation/i, JSON.stringify(args));
    }
    // The required fields are still required: no thread id, no text, an empty text.
    for (const args of [
      { text: "hi" },
      { threadId: String(thread.threadId) },
      { threadId: String(thread.threadId), text: "   " },
    ]) {
      const result = await call(client, "report_reply", args);
      assert.equal(result.isError, true, JSON.stringify(args));
      assert.match(result.text, /validation/i, JSON.stringify(args));
    }
  } finally { await client.close(); }
  assert.equal((await commentsOf(thread.threadId)).length, before, "nothing was written");
});

/* ================================================================= 7. the claims */

test("a handler with no claims, or with another scope's claims, refuses unauthorized", async () => {
  const server = door.createPickupMcpServer({ createDb: () => createDbClient(state.crow), comments: bundleComments });
  assert.deepEqual(Object.keys(server._registeredTools), ["report_reply", "report_make_card", "report_propose_change"], "the three tools, by their literal names");
  const handler = server._registeredTools.report_reply.handler;
  assert.equal(typeof handler, "function");

  const args = { threadId: "1", text: "hi" };
  const cases = [
    ["no auth info at all", {}],
    ["no claims object", { authInfo: { clientId: "local-mcp" } }],
    ["another scope", { authInfo: { clientId: "local-mcp", extra: { tokenScope: "mail-draft", draftId: MAIL_DRAFT_ID } } }],
    ["the reports scope", { authInfo: { clientId: "local-mcp", extra: { tokenScope: "reports", botId: BOT } } }],
    ["another client", { authInfo: { clientId: "oauth-client", extra: { tokenScope: "report-pickup" } } }],
    ["a scope with no ids", { authInfo: { clientId: "local-mcp", extra: { tokenScope: "report-pickup" } } }],
  ];
  for (const [label, extra] of cases) {
    const result = await handler(args, extra);
    assert.equal(result.isError, true, label);
    assert.deepEqual(JSON.parse(result.content[0].text), { error: "unauthorized" }, label);
  }
});

/* ============================================================ 8. the mount guard */

test("the pickup guard admits only a live rpk_ token AND its own signature", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("guard");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "Is the total right?");
  const mine = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });
  const other = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });

  // No bearer at all, and a bearer no token store knows.
  assert.equal(await post(door.PICKUP_DOOR_PATH), 401, "no token");
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { token: "rpk_" + "0".repeat(64) })), 401,
    "an unknown rpk_ value");
  const revoked = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });
  revokePickupToken(revoked.token);
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(revoked)), 401, "a revoked token");
  const expired = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)], ttlMs: 0 });
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(expired)), 401, "an expired token");
  // A real mail turn token is no pickup token, even with a correct-shaped signature.
  const mailTurn = mintTurnToken({
    draftId: MAIL_DRAFT_ID, turnId: "turn-1", startHash: "a".repeat(64), botId: BOT, ttlMs: TURN_TIMEOUT_LONG,
  });
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { token: mailTurn })), 401, "an mdt_ token");

  // A signature is over the TOKEN's own pickup and turn: another pickup's block, another turn's, or
  // another bot's own valid signature admits nothing.
  const forOtherPickup = signReportPickupActor({ botId: BOT, pickupId: other.pickupId, turnId: other.turnId });
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { sig: forOtherPickup })), 401, "pickup B's block");
  const forOtherTurn = signReportPickupActor({ botId: BOT, pickupId: mine.pickupId, turnId: "turn-someone-else" });
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { sig: forOtherTurn })), 401, "another turn of A");
  const forOtherBot = signReportPickupActor({ botId: OTHER_BOT, pickupId: mine.pickupId, turnId: mine.turnId });
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { botId: OTHER_BOT, sig: forOtherBot })), 401,
    "another bot's own signature over the same pickup and turn");
  // Signatures in another kind's MAC domain are refused even under the pickup kind header.
  const mailSig = signMailDraftActor({ botId: BOT, draftId: mine.pickupId, turnId: mine.turnId });
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { sig: mailSig })), 401, "a mail-draft signature");
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { sig: mailSig, actorKind: "mail-draft" })), 401,
    "and under its own kind header");
  const reportsSig = signReportsActor({ botId: BOT, threadId: `${mine.pickupId}:${mine.turnId}`, gatewayType: null });
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { sig: reportsSig, actorKind: "reports" })), 401,
    "a reports-actor signature");
  const botSig = signActor({ kind: "bot", botId: BOT, threadId: `${mine.pickupId}:${mine.turnId}`, gatewayType: null });
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { sig: botSig, actorKind: "bot" })), 401,
    "a bot-kind signature");
  // Missing actor headers at all.
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { sig: null })), 401, "no signature");
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { botId: null })), 401, "no actor id");
  assert.equal(await post(door.PICKUP_DOOR_PATH, headersFor(mine, { actorKind: null })), 401, "no actor kind");

  // The correct pair passes, and what the guard pinned is what a handler reads.
  const probe = await get(door.PICKUP_MCP_PREFIX + "/claims", headersFor(mine));
  assert.equal(probe.status, 200, JSON.stringify(probe.body));
  assert.deepEqual(probe.body, {
    reportId: report.id,
    pickupId: mine.pickupId,
    botId: BOT,
    artifactId: artifact,
    threadIds: [String(thread.threadId)],
    commentIds: [String(thread.threadId)],
    tokenScope: "report-pickup",
  });
  const client = await connect(headersFor(mine));
  try {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((tool) => tool.name), ["report_reply", "report_make_card", "report_propose_change"]);
  } finally { await client.close(); }
});

/* ===================================================== 9. the two doors are apart */

test("a pickup token does not open the mail guard, and a mail turn does not open the pickup guard", { timeout: TEST_TIMEOUT }, async () => {
  const artifact = nextArtifact("doors");
  const report = await reportFor(artifact);
  const thread = await addThread(artifact, "Is the total right?");
  const pickup = mintFor({ report, artifactId: artifact, threadIds: [String(thread.threadId)] });

  // The pickup's token and its own signature, presented to the mail guard: not a mail turn token.
  assert.equal((await get("/mail-draft/claims", headersFor(pickup))).status, 401, "rpk_ on /mail-draft");
  // A real mail turn, signed for the mail door, is admitted THERE (so the 401 above is the token's
  // doing, not a broken guard).
  const mailTurn = mintTurnToken({
    draftId: MAIL_DRAFT_ID, turnId: "turn-1", startHash: "a".repeat(64), botId: BOT, ttlMs: TURN_TIMEOUT_LONG,
  });
  const mailHeaders = {
    authorization: `Bearer ${mailTurn}`,
    "x-crow-actor-kind": "mail-draft",
    "x-crow-actor-id": BOT,
    "x-crow-actor-sig": signMailDraftActor({ botId: BOT, draftId: MAIL_DRAFT_ID, turnId: "turn-1" }),
  };
  assert.equal((await get("/mail-draft/claims", mailHeaders)).status, 200, "the mail guard admits its own turn");
  // And that same mail turn, on the pickup guard, is 401 whatever it carries.
  assert.equal(await post(door.PICKUP_DOOR_PATH, mailHeaders), 401, "mdt_ on /report-pickup");
});

/* ============================================================= 10. the model gate */

test("pickupCheckModel: local ok, cloud, role ref, missing providers and an empty key refused", () => {
  const providers = [
    { id: "local", baseUrl: "http://127.0.0.1:8080/v1", host: "local" },
    { id: "cloud", baseUrl: "https://api.example.com/v1", host: "cloud" },
  ];
  const check = pickupCheckModel({ providers });
  assert.deepEqual(check({ key: "local/llama-3" }), { ok: true });
  assert.deepEqual(check({ key: "  local/llama-3  " }), { ok: true }, "the key is trimmed first");
  assert.deepEqual(check({ key: "cloud/some-model" }), { ok: false, code: MODEL_NOT_LOCAL });
  assert.deepEqual(check({ key: "nowhere/model" }), { ok: false, code: MODEL_NOT_LOCAL },
    "no provider row proves nothing local");
  assert.deepEqual(check({ key: "role:everyday" }), { ok: false, code: MODEL_NOT_LOCAL }, "a role ref is not a resolved key");
  assert.deepEqual(check({ key: "" }), { ok: false, code: MODEL_NOT_LOCAL });
  assert.deepEqual(check({ key: null }), { ok: false, code: MODEL_NOT_LOCAL });
  assert.deepEqual(check(null), { ok: false, code: MODEL_NOT_LOCAL });
  assert.equal(MODEL_NOT_LOCAL, "model_not_local");

  // A missing providers array fails closed: even a provably-local key is refused.
  assert.deepEqual(pickupCheckModel({})({ key: "local/llama-3" }), { ok: false, code: MODEL_NOT_LOCAL });
  assert.deepEqual(pickupCheckModel()({ key: "local/llama-3" }), { ok: false, code: MODEL_NOT_LOCAL });
  // A providers value of the wrong shape is missing too.
  assert.deepEqual(pickupCheckModel({ providers: { id: "local" } })({ key: "local/llama-3" }),
    { ok: false, code: MODEL_NOT_LOCAL });
});

/* ============================================================ 11. the mount exists */

test("boot mounts the pickup door behind its guard, after the /reports mount", { timeout: TEST_TIMEOUT }, async () => {
  const mounts = readFileSync(new URL("../servers/gateway/boot/mcp-mounts.js", import.meta.url), "utf8");
  const importAt = mounts.indexOf("../reports/pickup-mcp.js");
  assert.ok(importAt > 0, "boot imports the pickup door");
  const block = mounts.slice(importAt, importAt + 1500);
  const reportsAt = mounts.lastIndexOf('mountMcpServer(app, "/reports"', importAt);
  const flagAt = mounts.lastIndexOf("if (mailEnabled())", importAt);
  assert.ok(reportsAt > 0, "the pickup mount follows the /reports mount");
  assert.ok(reportsAt > flagAt, "and is NOT behind mailEnabled() (which only wraps /mail-draft)");
  assert.match(block, /app\.use\("\/report-pickup", pickupMountAuth\(/, "the guard is installed before the mount");
  assert.match(block,
    /mountMcpServer\(app, "\/report-pickup", \(\) => createPickupMcpServer\(\{ createDb: createDbClient, verifyActor: verifyReportPickupActorSig, actions: pickupActions \}\)/,
    "the mount factory names the door's verifier, so an owner-mount audit reads it as signed");

  // A booted app's shape: an unauthenticated caller reaches nothing on the door.
  assert.equal(await post(door.PICKUP_DOOR_PATH), 401, "no token on /report-pickup/mcp");
  assert.equal(await post(door.PICKUP_MCP_PREFIX + "/sse"), 401, "no token on the SSE path");
  // The Funnel twin lives in tests/auth-network.test.js; this file only pins that the path is a door.
  const { isDoorPath } = await import("../servers/shared/bot-doors.js");
  assert.equal(isDoorPath(door.PICKUP_DOOR_PATH), true, "the pickup path is a bot door");
  const funnel = await import("../servers/gateway/funnel.js");
  assert.equal(funnel.isFunnelPublicPath(door.PICKUP_DOOR_PATH), false, "and never a Funnel path");
  assert.ok(resolve(REPO, "servers/gateway/reports/pickup-mcp.js").endsWith("pickup-mcp.js"));
});
test("the guard logs one value-free line per pickup when its door session first opens", async () => {
  const lines = [];
  const pickup = { turnId: "t1", pickupId: "p1", botId: "b1", reportId: "r1", artifactId: "a1", threadIds: [], commentIds: [] };
  const guard = door.pickupMountAuth({
    verifyToken: () => pickup,
    verifyActor: () => true,
    log: (line) => lines.push(line),
  });
  const req = () => ({
    headers: { authorization: "Bearer x", "x-crow-actor-kind": "report-pickup", "x-crow-actor-id": "b1", "x-crow-actor-sig": "s" },
  });
  let passed = 0;
  for (let i = 0; i < 3; i++) guard(req(), {}, () => { passed++; });
  assert.equal(passed, 3);
  assert.deepEqual(lines, ["[report-pickup] door session opened p1"]);
});
