// The bot reports door on the wire (servers/gateway/reports/mcp.js): a real HTTP mount wired the way
// servers/gateway/index.js wires it (the global JSON parser, the real local-token middleware, the door's
// own mount guard, mountMcpServer) with a real MCP SDK client for the admitted calls and plain requests
// for the refusals.
//
// What this file pins:
//   - the door serves EXACTLY the nine report tools, and no tool name could send or schedule mail;
//   - a reports token WITH a signed `reports` actor is admitted, and every other caller shape is 401
//     (no signature, a signature for another bot or another kind, a valid signature with a token of
//     another family);
//   - the project is the verified bot's own: no tool takes one, and another project's report id answers
//     exactly what a missing or a malformed id answers;
//   - no tool approves, adds an approved recipient, applies a change, re-stamps a live report, writes a
//     schedules row or a reserved `report_state` key, and a preview answer carries no content;
//   - a status answer is counts only, and a credential request is a label with no secret.
//
// Harness: a scratch crow.db (init-db) and a scratch CROW_HOME (CROW_DATA_DIR/CROW_HOME are repointed
// before any gateway module is imported), two projects, two bots, a real reports token minted at boot
// and read back from `secrets/reports-token`, and the real per-boot actor key.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { rmScratch } from "./helpers/safe-rm.js";

const root = mkdtempSync(join(tmpdir(), "reports-mcp-"));
/** The scratch home, held in a constant: cleanup never re-reads the env (tests/helpers/safe-rm.js). */
const CROW_HOME = join(root, "home");
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = CROW_HOME;
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const { SessionManager } = await import("../servers/gateway/session-manager.js");
const { mountMcpServer } = await import("../servers/gateway/routes/mcp.js");
const {
  localTokenAuthMiddleware, generateLocalToken, generateBoardToken, ensureReportsToken,
} = await import("../servers/gateway/local-token.js");
const door = await import("../servers/gateway/reports/mcp.js");
const approvals = await import("../servers/gateway/reports/approvals.js");
const steps = await import("../servers/gateway/reports/steps.js");
const {
  createReport, getReport, saveRecipe, updateReportColumns,
} = await import("../servers/gateway/reports/store.js");
const { initGatewayActorKey, signReportsActor, verifyReportsActorSig, signSharingActor, signArtifactsActor, signActor } = await import("../scripts/pi-bots/actor-sig.mjs");

const BOT = "hank";
const OTHER_BOT = "otto";
/** The keychain seed this scratch instance holds: 32 bytes, so the keychain key file is a valid one. */
const SEED = Buffer.alloc(32, 7);
const OWNER = Object.freeze({ kind: "owner" });
const T0 = 1_700_000_000_000;
const SENDER = "ma-0011223344556677";
const CONNECTION = "conn-reports-0001";
const WARNING_SOURCE = "chart_rows_dropped";
const ERROR_SENTINEL = "SECRETERROR could not reach the mailbox";

/** A recipe that is valid under the server's own block registry and reads nothing. */
const TEXT_RECIPE = {
  blocks: [{ id: "b1", type: "text", settings: { heading: "Weekly listings", content: "Nothing yet." } }],
};
const EDITED_TEXT_RECIPE = {
  blocks: [{ id: "b1", type: "text", settings: { heading: "Weekly listings", content: "Something." } }],
};

const state = { servers: [], sessions: [], managers: [], dbs: [] };

const TEST_TIMEOUT = 30_000;
const FETCH_TIMEOUT = 10_000;

/** Close one MCP session the way a well-behaved client does: a DELETE, then the client. */
async function endSession({ client, transport }) {
  try { await transport?.terminateSession?.(); } catch { /* session already gone */ }
  try { await client?.close(); } catch { /* already closed */ }
}

/** Close an HTTP server for real: destroy live sockets, then await the close callback (bounded). */
function closeServer(server) {
  return new Promise((resolve) => {
    let settled = false;
    const done = () => { if (!settled) { settled = true; resolve(); } };
    try { server.closeAllConnections?.(); } catch { /* never listened */ }
    try { server.close(done); } catch { done(); }
    setTimeout(done, 2000).unref?.();
  });
}

after(async () => {
  for (const session of state.sessions) await endSession(session);
  for (const manager of state.managers) { try { await manager.closeAll(); } catch { /* ignore */ } }
  for (const server of state.servers) await closeServer(server);
  for (const db of state.dbs) { try { db.close(); } catch { /* ignore */ } }
  await new Promise((resolve) => setTimeout(resolve, 0));
  rmScratch(root);
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
  const raw = new Database(MASTER);
  raw.pragma("wal_checkpoint(TRUNCATE)");
  raw.close();
  initGatewayActorKey();
});

/** Write this scratch instance's keychain key, so the door's own default seed reader finds it. */
function writeKeychainKey() {
  const dir = join(CROW_HOME, "secrets");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const id = "0123456789abcdef";
  writeFileSync(join(dir, "keychain.key"), JSON.stringify({ v: 1, id, key: SEED.toString("base64") }) + "\n", { mode: 0o600 });
}

/** The approvals seam a test side seed needs: a fixed keychain seed, a clock and a preview reader. */
function depsWith(over = {}) {
  return {
    loadSeed: () => ({ seed: SEED }),
    now: () => T0,
    getRun: async () => null,
    senderReady: async () => true,
    ...over,
  };
}

/** A schedules row of a report page, so a seeded live report has one. */
async function addSchedule(db, { cron = "0 7 * * 1", tz = "Europe/Berlin" } = {}) {
  await db.execute({
    sql: "INSERT INTO schedules (task, cron_expression, tz) VALUES ('weekly-report', ?, ?)",
    args: [cron, tz],
  });
  const { rows } = await db.execute({ sql: "SELECT last_insert_rowid() AS id", args: [] });
  return Number(rows[0].id);
}

/**
 * One scratch instance: a copied crow.db, two projects, two bots, a minted reports token read back from
 * the secrets file, the real mount stack, and a listening server.
 */
async function setup() {
  rmScratch(join(CROW_HOME, "secrets"));
  writeKeychainKey();
  const dir = mkdtempSync(join(root, "t-"));
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  state.dbs.push(db);

  const projectIds = [];
  for (const name of ["alpha", "beta"]) {
    const made = await db.execute({
      sql: `INSERT INTO project_spaces (slug, name, type, status, storage_prefix)
            VALUES (?, ?, 'general', 'active', ?)`,
      args: [name, name, `projects/${name}/`],
    });
    projectIds.push(Number(made.lastInsertRowid));
  }
  const [projectA, projectB] = projectIds;
  for (const [botId, projectId] of [[BOT, projectA], [OTHER_BOT, projectB]]) {
    await db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled, project_id) VALUES (?, ?, '{}', 1, ?)",
      args: [botId, botId, projectId],
    });
  }

  await ensureReportsToken(db);
  const reportsToken = readFileSync(join(CROW_HOME, "secrets", "reports-token"), "utf8").trim();
  const boardToken = await generateBoardToken(db);
  const localToken = await generateLocalToken(db);

  const createDb = () => {
    const client = createDbClient(crow);
    state.dbs.push(client);
    return client;
  };

  const app = express();
  app.use(express.json());
  app.use(localTokenAuthMiddleware(db));
  const authMiddleware = (req, res, next) => (req.localTokenAuth
    ? next()
    : res.status(401).json({ error: "unauthorized" }));
  const sessionManager = new SessionManager();
  state.managers.push(sessionManager);
  const peerExposureGate = async () => true;

  app.use(door.REPORTS_MCP_PREFIX, door.reportsMountAuth({ createDb }));
  mountMcpServer(app, door.REPORTS_MCP_PREFIX, () => door.createReportsMcpServer({
    createDb, verifyActor: verifyReportsActorSig,
  }), sessionManager, authMiddleware, peerExposureGate);

  const server = await new Promise((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  state.servers.push(server);
  const base = `http://127.0.0.1:${server.address().port}`;

  const connect = async (headers) => {
    const transport = new StreamableHTTPClientTransport(new URL(base + door.REPORTS_DOOR_PATH), {
      requestInit: { headers },
    });
    const client = new Client({ name: "reports-door-test", version: "0" });
    try {
      await client.connect(transport);
    } catch (err) {
      try { await client.close(); } catch { /* ignore */ }
      try { await transport.close(); } catch { /* ignore */ }
      throw err;
    }
    state.sessions.push({ client, transport });
    return client;
  };

  const post = async (headers, body = { jsonrpc: "2.0", id: 1, method: "tools/list" }) => {
    const res = await fetch(base + door.REPORTS_DOOR_PATH, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    const status = res.status;
    try { await res.body?.cancel(); } catch { /* already consumed */ }
    return status;
  };

  const signingHeaders = ({ token = reportsToken, botId = BOT, threadId = "perch-1", gatewayType = "perch" } = {}) => ({
    Authorization: "Bearer " + token,
    "X-Crow-Actor-Kind": "reports",
    "X-Crow-Actor-Id": botId,
    "X-Crow-Actor-Thread": threadId,
    "X-Crow-Actor-Gateway": gatewayType,
    "X-Crow-Actor-Sig": signReportsActor({ botId, threadId, gatewayType }),
  });

  return { db, projectA, projectB, reportsToken, boardToken, localToken, connect, post, signingHeaders, base };
}

/** A tool result's JSON body. */
const payload = (result) => JSON.parse(result.content[0].text);

/** A report the owner seeded in draft, in the given project. */
async function draftReport(db, projectId, title = "Weekly listings") {
  const { id } = await createReport(db, {
    projectId, owner: "owner", botId: BOT, title,
  });
  return id;
}

/**
 * A LIVE report, seeded the way the approvals tests seed one: a schedule row, a sender, a saved
 * revision and a go-live over an injected preview.
 */
async function liveReport(db, projectId) {
  const scheduleId = await addSchedule(db);
  const { id } = await createReport(db, {
    projectId, owner: "owner", botId: BOT, title: "Weekly listings",
  });
  const saved = await saveRecipe(db, { reportId: id, recipe: TEXT_RECIPE, authorKind: "owner" });
  await updateReportColumns(db, id, {
    schedule_id: scheduleId,
    sender_account_id: SENDER,
    delivery_mode: "email_link",
    comment_tier_default: "c",
    comment_visibility: "own",
    ai_commentary: 0,
  });
  await approvals.updateSettings(db, depsWith(), {
    reportId: id, settings: { sender_account_id: SENDER }, actor: OWNER,
  });
  const runs = { "prv-1": { id: "prv-1", reportId: id, kind: "preview", status: "ok", recipeRev: saved.rev } };
  await approvals.approveGoLive(db, depsWith({ getRun: async (_db, runId) => runs[runId] ?? null }), {
    reportId: id, previewRunId: "prv-1", actor: OWNER,
  });
  const row = await getReport(db, id);
  assert.equal(row.status, "live");
  return { id, rev: saved.rev, scheduleId };
}

/** Every report taking tool, called once against one report id. */
async function everyReportTool(client, reportId) {
  return [
    await call(client, "crow_report_set_recipe", { reportId, recipe: TEXT_RECIPE }),
    await call(client, "crow_report_set_schedule", { reportId, cron: "0 7 * * 1", tz: "Europe/Berlin" }),
    await call(client, "crow_report_propose_recipient", { reportId, address: "alex@example.com" }),
    await call(client, "crow_report_propose_host", { reportId, host: "example.com" }),
    await call(client, "crow_report_propose_step", {
      reportId, stepKey: "fetch", language: "node", entry: "index.js", files: { "index.js": "console.log(1)" },
    }),
    await call(client, "crow_report_request_credential", {
      reportId, host: "example.com", header: "Authorization", format: "Bearer {}", paths: ["/api"],
    }),
    await call(client, "crow_report_preview", { reportId }),
    await call(client, "crow_report_status", { reportId }),
  ];
}

/** One tool call's raw result. */
function call(client, name, args) {
  return client.callTool({ name, arguments: args });
}

/* ------------------------------------------------------------- the surface */

test("no tool can approve, add or apply", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());

  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [...door.REPORTS_TOOL_NAMES].sort());
  for (const name of door.REPORTS_TOOL_NAMES) {
    assert.doesNotMatch(name, /approve|apply|go_live|add_recipient/, name);
  }

  const created = payload(await call(client, "crow_report_create", { title: "Weekly listings" }));
  const reportId = created.reportId;
  assert.equal(created.status, "draft");
  const beforeRow = await getReport(s.db, reportId);

  const answers = await everyReportTool(client, reportId);
  assert.equal(answers.length, 8);
  // The credential request is refused: the host is only proposed, never approved.
  assert.equal(payload(answers[5]).error, "host_not_approved");

  const recipients = await s.db.execute({
    sql: "SELECT state FROM report_recipients WHERE report_id = ?", args: [reportId],
  });
  assert.equal(recipients.rows.length, 1);
  for (const row of recipients.rows) assert.equal(row.state, "proposed", "a bot tool proposes only");

  const afterRow = await getReport(s.db, reportId);
  assert.equal(afterRow.status, beforeRow.status, "no tool moved the status");
  assert.equal(afterRow.live_seal, beforeRow.live_seal);
  assert.equal(afterRow.live_rev, beforeRow.live_rev);
  assert.equal(afterRow.approved_preview_run, beforeRow.approved_preview_run);
}, { timeout: TEST_TIMEOUT });

test("tool names avoid the mail send pattern", () => {
  const pattern = /mail.*(send|schedule)/i;
  for (const name of door.REPORTS_TOOL_NAMES) {
    assert.ok(!pattern.test(name), name);
  }
  assert.equal(door.REPORTS_TOOL_NAMES.length, 9);
});

/* ------------------------------------------------------------- proposals */

test("propose_recipient leaves state proposed", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const reportId = await draftReport(s.db, s.projectA);

  const fresh = payload(await call(client, "crow_report_propose_recipient", {
    reportId, address: "sam@example.com",
  }));
  assert.equal(fresh.state, "proposed");
  assert.match(fresh.recipientId, /^rrc-[0-9a-f]{16}$/);

  // An approved row seeded the way the owner's own route approves one, then proposed again by the bot.
  const ownerRow = await approvals.proposeRecipient(s.db, depsWith(), {
    reportId, address: "alex@example.com", proposedBy: "owner",
  });
  await approvals.approveRecipient(s.db, depsWith(), { recipientId: ownerRow.id, actor: OWNER });
  const sealBefore = (await s.db.execute({
    sql: "SELECT approval_seal, state FROM report_recipients WHERE id = ?", args: [ownerRow.id],
  })).rows[0];

  const again = payload(await call(client, "crow_report_propose_recipient", {
    reportId, address: "alex@example.com", displayName: "Someone else", commentTier: "a",
  }));
  assert.equal(again.state, "approved");
  assert.equal(again.recipientId, ownerRow.id, "a bot proposal answers the owner's row");

  const sealAfter = (await s.db.execute({
    sql: "SELECT approval_seal, state, display_name, comment_tier FROM report_recipients WHERE id = ?",
    args: [ownerRow.id],
  })).rows[0];
  assert.equal(sealAfter.state, "approved");
  assert.equal(sealAfter.approval_seal, sealBefore.approval_seal, "the approval was not rewritten");
  assert.equal(sealAfter.display_name, null, "a bot never rewrites the owner's proposal");
  assert.equal(sealAfter.comment_tier, null);
}, { timeout: TEST_TIMEOUT });

test("tools refuse a report on another project", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const foreign = await draftReport(s.db, s.projectB, "Another project's report");
  const missing = "rpt-" + "0".repeat(16);
  const malformed = "rpt-not-an-id";

  const argumentsFor = (reportId) => ([
    ["crow_report_set_recipe", { reportId, recipe: TEXT_RECIPE }],
    ["crow_report_set_schedule", { reportId, cron: "0 7 * * 1", tz: "Europe/Berlin" }],
    ["crow_report_propose_recipient", { reportId, address: "alex@example.com" }],
    ["crow_report_propose_host", { reportId, host: "example.com" }],
    ["crow_report_propose_step", {
      reportId, stepKey: "fetch", language: "node", entry: "index.js", files: { "index.js": "x" },
    }],
    ["crow_report_request_credential", {
      reportId, host: "example.com", header: "Authorization", format: "Bearer {}", paths: ["/api"],
    }],
    ["crow_report_preview", { reportId }],
    ["crow_report_status", { reportId }],
  ]);

  for (const [name, args] of argumentsFor(foreign)) {
    const otherText = (await call(client, name, { ...args, reportId: foreign })).content[0].text;
    const missingText = (await call(client, name, { ...args, reportId: missing })).content[0].text;
    const malformedText = (await call(client, name, { ...args, reportId: malformed })).content[0].text;
    assert.equal(JSON.parse(otherText).error, "not_found", `${name} on another project's report`);
    assert.equal(otherText, missingText, `${name}: a foreign report reads like a missing one`);
    assert.equal(otherText, malformedText, `${name}: a malformed id reads like a missing one`);
  }

  const untouched = await getReport(s.db, foreign);
  assert.equal(untouched.status, "draft");
  const recipients = await s.db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_recipients WHERE report_id = ?", args: [foreign],
  });
  assert.equal(Number(recipients.rows[0].n), 0, "nothing was written for the foreign report");
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- the guard */

test("forged actor id is refused", async () => {
  const s = await setup();

  // The token with no signature at all.
  assert.equal(await s.post({ Authorization: "Bearer " + s.reportsToken }), 401);

  // A signature minted for another bot, on this bot's id header.
  assert.equal(await s.post({
    ...s.signingHeaders(),
    "X-Crow-Actor-Id": OTHER_BOT,
  }), 401);

  // A signature of another kind, presented as a reports one.
  for (const sig of [
    signSharingActor({ botId: BOT, threadId: "perch-1", gatewayType: "perch" }),
    signArtifactsActor({ botId: BOT, threadId: "perch-1", gatewayType: "perch" }),
    signActor({ kind: "bot", botId: BOT, threadId: "perch-1", gatewayType: "perch" }),
  ]) {
    assert.equal(await s.post({ ...s.signingHeaders(), "X-Crow-Actor-Sig": sig }), 401);
  }

  // A valid reports signature with no token, and with a token of another family.
  const signature = signReportsActor({ botId: BOT, threadId: "perch-1", gatewayType: "perch" });
  const actorOnly = {
    "X-Crow-Actor-Kind": "reports",
    "X-Crow-Actor-Id": BOT,
    "X-Crow-Actor-Thread": "perch-1",
    "X-Crow-Actor-Gateway": "perch",
    "X-Crow-Actor-Sig": signature,
  };
  assert.equal(await s.post(actorOnly), 401);
  for (const token of [s.boardToken, s.localToken]) {
    assert.equal(await s.post({ ...actorOnly, Authorization: "Bearer " + token }), 401, `token ${token.slice(0, 6)}…`);
  }

  // And a tampered thread under the token.
  const tampered = s.signingHeaders();
  tampered["X-Crow-Actor-Thread"] = "perch-2";
  assert.equal(await s.post(tampered), 401);
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- the project */

test("a bot cannot pass a project id", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const before = await s.db.execute({ sql: "SELECT COUNT(*) AS n FROM reports", args: [] });

  for (const [name, args] of [
    ["crow_report_create", { title: "Weekly listings", projectId: s.projectB }],
    ["crow_report_create", { title: "Weekly listings", project_id: s.projectB }],
    ["crow_report_status", { reportId: "rpt-" + "0".repeat(16), projectId: s.projectB }],
    ["crow_report_preview", { reportId: "rpt-" + "0".repeat(16), project_id: s.projectB }],
  ]) {
    const result = await call(client, name, args);
    assert.equal(result.isError, true, `${name} with a project id`);
  }

  const after = await s.db.execute({ sql: "SELECT COUNT(*) AS n FROM reports", args: [] });
  assert.equal(Number(after.rows[0].n), Number(before.rows[0].n), "nothing was written");
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- the preview */

test("preview returns no content", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const reportId = await draftReport(s.db, s.projectA);

  const out = payload(await call(client, "crow_report_preview", { reportId }));
  assert.deepEqual(Object.keys(out).sort(), ["queued", "runId"]);
  assert.equal(out.queued, true);

  const { rows } = await s.db.execute({
    sql: "SELECT report_id, kind, requested_by, claimed_at FROM report_run_requests WHERE id = ?",
    args: [out.runId],
  });
  assert.equal(rows.length, 1);
  assert.equal(rows[0].report_id, reportId);
  assert.equal(rows[0].kind, "preview");
  assert.equal(rows[0].requested_by, `bot:${BOT}`);
  assert.equal(rows[0].claimed_at, null, "the door only queues the request");

  const versions = await s.db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_versions WHERE report_id = ?", args: [reportId],
  });
  assert.equal(Number(versions.rows[0].n), 0, "a preview answer carries no artifact");
  // A queued preview is a non schedule run, so custom-step.js counts it toward extra_step_runs when it
  // executes; the door itself spends nothing.
  const usage = await s.db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_usage WHERE report_id = ?", args: [reportId],
  });
  assert.equal(Number(usage.rows[0].n), 0);
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- the status */

test("status maps pause reason to a fixed code", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const reportId = await draftReport(s.db, s.projectA);
  const OWNER_WORDS = "I stopped this because of the tax situation";

  await updateReportColumns(s.db, reportId, { status: "paused", pause_reason: OWNER_WORDS });
  const own = payload(await call(client, "crow_report_status", { reportId }));
  assert.equal(own.paused, true);
  assert.equal(own.pauseCode, "paused", "an owner's own reason reads as the generic code");
  assert.equal(Object.hasOwn(own, "pauseReason"), false, "no field to carry the reason at all");
  assert.equal(JSON.stringify(own).includes(OWNER_WORDS), false, "and not the text either");

  // The one pause the product makes itself is named, and still only by its code.
  await updateReportColumns(s.db, reportId, { pause_reason: approvals.SETTINGS_CHANGED_PAUSE_REASON });
  const settings = payload(await call(client, "crow_report_status", { reportId }));
  assert.equal(settings.paused, true);
  assert.equal(settings.pauseCode, "settings_changed");
  assert.equal(JSON.stringify(settings).includes(approvals.SETTINGS_CHANGED_PAUSE_REASON), false,
    "the sentence itself stays on the owner's side");

  // A report nobody paused carries the boolean and a code, never a reason.
  await updateReportColumns(s.db, reportId, { status: "draft", pause_reason: null });
  const draft = payload(await call(client, "crow_report_status", { reportId }));
  assert.equal(draft.paused, false);
  assert.equal(draft.pauseCode, "paused");
}, { timeout: TEST_TIMEOUT });

test("preview status hides ok versus empty and warnings", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const reportId = await draftReport(s.db, s.projectA);
  const log = JSON.stringify({
    items: 0,
    sourceErrors: [],
    warnings: [{ source: "b2", message: WARNING_SOURCE }],
  });
  const runs = [
    ["rpv-ok", "preview", "ok", T0],
    ["rpv-empty", "preview", "empty", T0 + 1],
    ["rpv-failed", "preview", "failed", T0 + 2],
    ["rpv-running", "preview", "running", T0 + 3],
    ["rmn-ok", "manual", "ok", T0 + 4],
  ];
  for (const [id, trigger, status, at] of runs) {
    await s.db.execute({
      sql: `INSERT INTO report_runs
              (id, report_id, "trigger", requested_by, status, recipe_rev, block_log_json, created_at)
            VALUES (?, ?, ?, 'owner', ?, 1, ?, ?)`,
      args: [id, reportId, trigger, status, log, at],
    });
  }

  const status = payload(await call(client, "crow_report_status", { reportId }));
  const byId = new Map(status.runs.map((run) => [run.id, run]));
  assert.equal(status.runs.length, 5);
  assert.equal(byId.get("rpv-ok").status, "finished");
  assert.equal(byId.get("rpv-empty").status, "finished", "an empty preview reads the same as an ok one");
  assert.equal(byId.get("rpv-failed").status, "failed");
  assert.equal(byId.get("rpv-running").status, "running");
  for (const id of ["rpv-ok", "rpv-empty", "rpv-failed", "rpv-running"]) {
    assert.equal(Object.hasOwn(byId.get(id), "warnings"), false, `${id}: a preview carries no warning count`);
  }
  assert.equal(byId.get("rmn-ok").status, "ok", "another trigger keeps its own word");
  assert.equal(byId.get("rmn-ok").warnings, 1, "and its own count");
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- the rate caps */

test("preview is rate limited", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const now = Date.now();
  const RATE_LIMITED = "That was asked too often, so nothing was done. Try again later.";

  // Three requests nobody has claimed: one more would only lengthen the queue.
  const queued = await draftReport(s.db, s.projectA);
  for (let i = 0; i < 3; i += 1) {
    await s.db.execute({
      sql: `INSERT INTO report_run_requests (report_id, kind, requested_by, created_at)
            VALUES (?, 'preview', 'owner', ?)`,
      args: [queued, now],
    });
  }
  const refused = await call(client, "crow_report_preview", { reportId: queued });
  assert.equal(refused.isError, true);
  const body = payload(refused);
  assert.equal(body.error, "rate_limited");
  assert.equal(body.message, RATE_LIMITED);
  const waiting = await s.db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_run_requests WHERE report_id = ?", args: [queued],
  });
  assert.equal(Number(waiting.rows[0].n), 3, "nothing was queued");

  // Twenty previews inside the window, all claimed: the report has had its day.
  const busy = await draftReport(s.db, s.projectA);
  for (let i = 0; i < 20; i += 1) {
    await s.db.execute({
      sql: `INSERT INTO report_run_requests
              (report_id, kind, requested_by, created_at, claimed_at)
            VALUES (?, 'preview', 'owner', ?, ?)`,
      args: [busy, now - 1000, now - 500],
    });
  }
  const capped = payload(await call(client, "crow_report_preview", { reportId: busy }));
  assert.equal(capped.error, "rate_limited", "twenty in one window is the cap");

  // A day later the window is empty, and the same report may be previewed again.
  await s.db.execute({
    sql: "UPDATE report_run_requests SET created_at = ? WHERE report_id = ?",
    args: [now - 25 * 60 * 60 * 1000, busy],
  });
  const allowed = payload(await call(client, "crow_report_preview", { reportId: busy }));
  assert.equal(allowed.queued, true, "the cap is a window, not a total");
}, { timeout: TEST_TIMEOUT });

test("create is rate limited", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  for (let i = 0; i < 10; i += 1) {
    await createReport(s.db, {
      projectId: s.projectA, owner: "owner", botId: BOT, title: `Report ${i}`,
    });
  }
  const before = await s.db.execute({ sql: "SELECT COUNT(*) AS n FROM reports", args: [] });
  const refused = await call(client, "crow_report_create", { title: "One more" });
  assert.equal(refused.isError, true);
  assert.equal(payload(refused).error, "rate_limited");
  const after = await s.db.execute({ sql: "SELECT COUNT(*) AS n FROM reports", args: [] });
  assert.equal(Number(after.rows[0].n), Number(before.rows[0].n), "nothing was created");

  // Another bot's ten reports are not this bot's count.
  await s.db.execute({ sql: "UPDATE reports SET bot_id = ?", args: [OTHER_BOT] });
  const allowed = payload(await call(client, "crow_report_create", { title: "A new report" }));
  assert.equal(typeof allowed.reportId, "string", "the cap counts this bot's own reports");
}, { timeout: TEST_TIMEOUT });

test("status is counts only", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const reportId = await draftReport(s.db, s.projectA);
  await call(client, "crow_report_propose_recipient", { reportId, address: "alex@example.com" });
  await call(client, "crow_report_propose_host", { reportId, host: "example.com" });

  await s.db.execute({
    sql: `INSERT INTO report_credentials (report_id, host, connection_uuid, inject_json, state, created_at)
          VALUES (?, 'example.com', ?, ?, 'proposed', ?)`,
    args: [reportId, CONNECTION, JSON.stringify({
      header: "X-Api-Key", format: "{}", pathPrefixes: ["/api"], methods: ["GET"],
    }), T0],
  });
  await s.db.execute({
    sql: `INSERT INTO report_runs
            (id, report_id, "trigger", requested_by, status, recipe_rev, block_log_json, error_text, created_at)
          VALUES ('run-1', ?, 'manual', 'owner', 'failed', 1, ?, ?, ?)`,
    args: [reportId, JSON.stringify({
      items: 0,
      sourceErrors: [{ source: "b1", message: "source_down" }],
      warnings: [{ source: "b2", message: WARNING_SOURCE }],
    }), ERROR_SENTINEL, T0],
  });

  const status = payload(await call(client, "crow_report_status", { reportId }));
  const text = JSON.stringify(status);

  for (const secret of ["alex@example.com", CONNECTION, ERROR_SENTINEL, "source_down", WARNING_SOURCE, "X-Api-Key", "/api"]) {
    assert.equal(text.includes(secret), false, `the status carries ${secret}`);
  }
  assert.equal(status.status, "draft");
  assert.equal(status.live, false, "a fresh report is not live");
  assert.deepEqual(status.recipients, { proposed: 1, approved: 0, refused: 0, revoked: 0 });
  assert.deepEqual(status.hosts.map((row) => row.state), ["proposed"]);
  assert.deepEqual(Object.keys(status.credentials[0]).sort(), ["host", "state"]);
  assert.equal(status.runs.length, 1);
  assert.equal(status.runs[0].warnings, 1, "only the warning count");
  assert.deepEqual(Object.keys(status.runs[0]).sort(), [
    "createdAt", "endedAt", "id", "late", "recipeRev", "status", "trigger", "warnings",
  ]);
  assert.equal(status.scheduleProposal, null);
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- the schedule */

test("set_schedule never writes a schedule row", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const live = await liveReport(s.db, s.projectA);
  const beforeSchedules = await s.db.execute({ sql: "SELECT COUNT(*) AS n FROM schedules", args: [] });
  const beforeRow = await getReport(s.db, live.id);

  const out = payload(await call(client, "crow_report_set_schedule", {
    reportId: live.id, cron: "30 6 * * 3", tz: "America/Chicago",
  }));
  assert.deepEqual(out, { proposed: true, needsGoLive: true });

  const afterSchedules = await s.db.execute({ sql: "SELECT COUNT(*) AS n FROM schedules", args: [] });
  assert.equal(Number(afterSchedules.rows[0].n), Number(beforeSchedules.rows[0].n), "no schedules row was written");
  const after = await getReport(s.db, live.id);
  assert.equal(after.schedule_id, beforeRow.schedule_id, "the report's schedule row is unchanged");
  assert.equal(after.live_seal, beforeRow.live_seal, "a live report's seal is untouched");
  assert.equal(after.status, "live");

  const stateRow = await s.db.execute({
    sql: "SELECT value_json FROM report_state WHERE report_id = ? AND key = 'schedule_proposal'",
    args: [live.id],
  });
  const proposal = JSON.parse(stateRow.rows[0].value_json);
  assert.equal(proposal.cron, "30 6 * * 3");
  assert.equal(proposal.tz, "America/Chicago");
  assert.equal(proposal.proposedBy, `bot:${BOT}`);

  // An unparseable or non five field expression is refused and writes no proposal.
  for (const cron of ["@once", "0 7 * * * *", "not a cron"]) {
    const refused = payload(await call(client, "crow_report_set_schedule", {
      reportId: live.id, cron, tz: "America/Chicago",
    }));
    assert.equal(refused.error, "bad_schedule", cron);
  }
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- the recipe */

test("set_recipe on a live report never re-stamps", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const live = await liveReport(s.db, s.projectA);
  const beforeRow = await getReport(s.db, live.id);

  const out = payload(await call(client, "crow_report_set_recipe", {
    reportId: live.id, recipe: EDITED_TEXT_RECIPE,
  }));
  assert.equal(out.rev, 2);
  // The text block reads nothing, so this is a free change: it waits for the owner's Apply and never for
  // a fresh go-live, and the live seal is not re-stamped either way.
  assert.equal(out.pendingFreeChange, true);
  assert.equal(out.needsGoLive, false);
  assert.equal(typeof out.next, "string");

  const after = await getReport(s.db, live.id);
  assert.equal(after.live_rev, beforeRow.live_rev, "the live revision did not move");
  assert.equal(after.live_seal, beforeRow.live_seal, "the seal was not re-stamped");
  assert.equal(after.live_nonce, beforeRow.live_nonce);
  assert.equal(after.status, "live");

  const revision = await s.db.execute({
    sql: "SELECT author_kind FROM report_recipe_revisions WHERE report_id = ? AND rev = 2",
    args: [live.id],
  });
  assert.equal(revision.rows[0].author_kind, "bot");
  const authorKeys = await s.db.execute({
    sql: "SELECT key FROM report_state WHERE report_id = ? AND key LIKE 'revision_author:%'",
    args: [live.id],
  });
  assert.equal(authorKeys.rows.length, 0, "a bot save writes no author seal");
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- reserved keys */

test("no tool writes a reserved report_state key", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const created = payload(await call(client, "crow_report_create", { title: "Weekly listings" }));
  await everyReportTool(client, created.reportId);

  const { rows } = await s.db.execute({
    sql: "SELECT key FROM report_state WHERE report_id = ? ORDER BY key", args: [created.reportId],
  });
  const keys = rows.map((row) => row.key).sort();
  for (const key of keys) {
    assert.ok(["chat_thread", "schedule_proposal"].includes(key), key);
  }
  assert.deepEqual(keys, ["chat_thread", "schedule_proposal"]);
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- credentials */

test("request_credential returns a label and no secret", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  const reportId = await draftReport(s.db, s.projectA);

  const refused = payload(await call(client, "crow_report_request_credential", {
    reportId, host: "example.com", header: "Authorization", format: "Bearer {}", paths: ["/api"],
  }));
  assert.equal(refused.error, "host_not_approved", "the host must be approved first");

  // The owner approves one host the way the report page does.
  await steps.proposeHost(s.db, depsWith(), { reportId, host: "example.com" });
  await steps.approveHost(s.db, depsWith(), { reportId, host: "example.com", actor: OWNER });

  const out = payload(await call(client, "crow_report_request_credential", {
    reportId,
    host: "example.com",
    header: "Authorization",
    format: "Bearer {}",
    paths: ["/api", "/v2"],
    methods: ["GET", "HEAD"],
  }));
  assert.equal(typeof out.label, "string");
  assert.equal(typeof out.next, "string");
  assert.match(out.next, /crow_request_secret/);
  assert.match(out.next, /report-credential/);

  const parsed = steps.parseCredentialSpec(out.label);
  assert.notEqual(parsed, null, "the label round trips through the grammar");
  assert.equal(parsed.reportId, reportId);
  assert.equal(parsed.host, "example.com");
  assert.deepEqual(parsed.inject, {
    header: "Authorization",
    format: "Bearer {}",
    pathPrefixes: ["/api", "/v2"],
    methods: ["GET", "HEAD"],
  });
  assert.equal(Object.hasOwn(parsed.inject, "secret"), false, "a rule names where a value goes, never the value");
  assert.equal(out.label.includes("secret"), false, "the label names no value");

  // A second host the owner never approved is refused, and the label is not built for it.
  await steps.proposeHost(s.db, depsWith(), { reportId, host: "other.example.com" });
  const unapproved = payload(await call(client, "crow_report_request_credential", {
    reportId, host: "other.example.com", query: "token", paths: ["/api"],
  }));
  assert.equal(unapproved.error, "host_not_approved");

  // Two targets, no path list and a bad host are refused before the host read.
  for (const args of [
    { host: "example.com", header: "Authorization", query: "token", paths: ["/api"] },
    { host: "example.com", header: "Authorization", paths: [] },
    { host: "Example.com", header: "Authorization", paths: ["/api"] },
  ]) {
    const refusedShape = payload(await call(client, "crow_report_request_credential", { reportId, ...args }));
    assert.equal(refusedShape.error, "bad_credential", JSON.stringify(args));
  }
}, { timeout: TEST_TIMEOUT });

test("request_credential refuses a report another bot made", async () => {
  const s = await setup();
  const client = await s.connect(s.signingHeaders());
  // A report in THIS bot's project that another bot made, with its host approved: the report's own bot
  // is the only thing left that can refuse the label.
  const { id } = await createReport(s.db, {
    projectId: s.projectA, owner: "owner", botId: OTHER_BOT, title: "Another bot's report",
  });
  await steps.proposeHost(s.db, depsWith(), { reportId: id, host: "example.com" });
  await steps.approveHost(s.db, depsWith(), { reportId: id, host: "example.com", actor: OWNER });

  const args = { host: "example.com", header: "Authorization", format: "Bearer {}", paths: ["/api"] };
  const otherBotsReport = (await call(client, "crow_report_request_credential", {
    reportId: id, ...args,
  })).content[0].text;
  const foreignReport = (await call(client, "crow_report_request_credential", {
    reportId: await draftReport(s.db, s.projectB), ...args,
  })).content[0].text;
  const missingReport = (await call(client, "crow_report_request_credential", {
    reportId: "rpt-" + "0".repeat(16), ...args,
  })).content[0].text;

  assert.equal(JSON.parse(otherBotsReport).error, "not_found");
  assert.equal(otherBotsReport, foreignReport, "another bot's report reads like a foreign one");
  assert.equal(otherBotsReport, missingReport, "and like a missing one");
  assert.equal(otherBotsReport.includes("report-credential"), false, "no label was built");
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------- the label helper */

test("credentialSpecLabel assembles a label parseCredentialSpec reads", () => {
  const label = steps.credentialSpecLabel({
    reportId: "rpt-" + "a".repeat(16),
    host: "example.com",
    header: "X-Api-Key",
    format: "{}",
    paths: ["/api"],
    methods: ["GET"],
  });
  assert.notEqual(label, null);
  assert.deepEqual(steps.parseCredentialSpec(label), {
    reportId: "rpt-" + "a".repeat(16),
    host: "example.com",
    inject: { header: "X-Api-Key", format: "{}", pathPrefixes: ["/api"], methods: ["GET"] },
  });

  const queryLabel = steps.credentialSpecLabel({
    reportId: "rpt-" + "a".repeat(16), host: "example.com", query: "token", paths: ["/api"],
  });
  assert.deepEqual(steps.parseCredentialSpec(queryLabel), {
    reportId: "rpt-" + "a".repeat(16),
    host: "example.com",
    inject: { query: "token", pathPrefixes: ["/api"], methods: ["GET", "HEAD"] },
  });

  for (const bad of [
    { reportId: "rpt-nope", host: "example.com", header: "Authorization", paths: ["/api"] },
    { reportId: "rpt-" + "a".repeat(16), host: "example.com", header: "Authorization", paths: [] },
    { reportId: "rpt-" + "a".repeat(16), host: "example.com", header: "Host", paths: ["/api"] },
    { reportId: "rpt-" + "a".repeat(16), host: "example.com", paths: ["/api"] },
    { reportId: "rpt-" + "a".repeat(16), host: "example.com", header: "Authorization", format: "no placeholder", paths: ["/api"] },
    { reportId: "rpt-" + "a".repeat(16), host: "example.com", header: "Authorization;query=x", paths: ["/api"] },
  ]) {
    assert.equal(steps.credentialSpecLabel(bad), null, JSON.stringify(bad));
  }
});