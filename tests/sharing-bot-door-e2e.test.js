// The bot sharing door on the wire (servers/gateway/sharing-bot-mcp.js): a real HTTP mount wired the
// way servers/gateway/index.js wires it — the global JSON parser, the real local-token middleware, the
// door's own mount guard, mountMcpServer — with a real MCP SDK client for the admitted calls and plain
// requests for the refusals.
//
// What this file pins, and why it needs a real mount to pin it:
//   - the door serves EXACTLY the five tools (a test can read a constant, but only the wire proves no
//     other mount leaked in);
//   - a sharing-bot token WITH a signed `sharing` actor is admitted, and a draft lands with origin bot;
//   - every other caller shape is 401: the token with no actor headers, the token with another kind's
//     signature, the token with a signature for a different bot, the board token and the full local
//     token (the operator's) on this mount, this token on another mount, and /sharing (which is not a
//     door at all);
//   - a relayed socket (a contained bot, 127.0.77.1) may present the sharing-bot token, where the full
//     local token is refused there.
//
// Harness: a scratch crow.db (init-db) and a scratch CROW_HOME (CROW_DATA_DIR/CROW_HOME are repointed
// before any gateway module is imported, so no token file and no allow-list can land in ~/.crow); the
// real per-boot actor key, and the real token rotation.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { rmScratch } from "./helpers/safe-rm.js";

const root = mkdtempSync(join(tmpdir(), "sharing-bot-door-"));
/** The scratch home, held in a constant: cleanup never re-reads the env (tests/helpers/safe-rm.js). */
const CROW_HOME = join(root, "home");
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = CROW_HOME;
delete process.env.CROW_DB_PATH;
mkdirSync(CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const { SessionManager } = await import("../servers/gateway/session-manager.js");
const { mountMcpServer } = await import("../servers/gateway/routes/mcp.js");
const { localTokenAuthMiddleware, generateLocalToken, generateBoardToken, SHARING_BOT_TOKEN } = await import("../servers/gateway/local-token.js");
const botDefStore = await import("../servers/shared/bot-def-store.js");
const botDefMac = await import("../servers/shared/bot-def-mac.js");
const tokenMac = await import("../servers/shared/token-mac.js");
const settingsRegistry = await import("../servers/gateway/dashboard/settings/registry.js");
const door = await import("../servers/gateway/sharing-bot-mcp.js");
const acl = await import("../servers/gateway/sharing-bot/acl.js");
const store = await import("../servers/gateway/messages/drafts-store.js");
const { MESSAGES_DRAFTS_API_PREFIX, messagesDraftsRouter } = await import("../servers/gateway/routes/messages-drafts-api.js");
const { initGatewayActorKey, signSharingActor, signBoardActor, signActor } = await import("../scripts/pi-bots/actor-sig.mjs");
const { RELAY_SOURCE_V4 } = await import("../servers/shared/bot-doors.js");

const SEED = Buffer.from("a fixed keychain seed for the door's e2e");
const PEER = { crowId: "crow:peer", name: "Peer", pubkey: "02" + "a".repeat(64) };
const BOT = "hank";

const state = { servers: [], sessions: [], managers: [], dbs: [] };

/** One test's budget. A hang is a FAILURE here, never a run that never ends. */
const TEST_TIMEOUT = 30_000;
/** Every HTTP call this file makes is bounded: a route that never answers fails the test. */
const FETCH_TIMEOUT = 10_000;

/**
 * Close one MCP session the way a well-behaved client does: a DELETE, then the client.
 *
 * `Client.close()` is NOT enough. The SDK's StreamableHTTPClientTransport.close() only aborts the
 * standalone SSE stream; it never calls terminateSession(), so no DELETE reaches the mount, the
 * server-side session stays in its SessionManager store, `transport.onclose` never fires — and the
 * session logger's flush interval (servers/gateway/session-logger.js) stays armed, which alone keeps
 * this process alive forever. That was the hang.
 */
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
    // Bounded: a server whose close callback never fires must fail this file, not hang it. The timer
    // is unref'd, so it can never be the reason the process stays alive either.
    setTimeout(done, 2000).unref?.();
  });
}

after(async () => {
  // Sessions first — that is what ends the MCP session records (and the logger's interval).
  for (const session of state.sessions) await endSession(session);
  // Belt and braces: a session that never made it into `state.sessions` (a failed connect) is still
  // in a SessionManager store, and its transport must be closed here.
  for (const manager of state.managers) { try { await manager.closeAll(); } catch { /* ignore */ } }
  for (const server of state.servers) await closeServer(server);
  for (const db of state.dbs) { try { db.close(); } catch { /* ignore */ } }
  // Let recordSessionEnd's (async) tail — its own db client — finish before the scratch dir goes.
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

/**
 * One scratch instance: a copied crow.db, minted tokens, the allow-list, the real mount stack, and a
 * listening server.
 */
async function setup() {
  rmScratch(join(CROW_HOME, "secrets"));
  const dir = mkdtempSync(join(root, "t-"));
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  state.dbs.push(db);

  const contact = await db.execute({
    sql: `INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
          VALUES (?, ?, ?, ?, 'crow')`,
    args: [PEER.crowId, PEER.name, PEER.pubkey, "e".repeat(64)],
  });
  const contactId = Number(contact.lastInsertRowid);
  // Seed the bot the way real code does: through the bot-def store's writer (a sealed row), then mark
  // the bot:def era converted, so the door's readVerifiedBotDef admits an enabled, verified bot.
  const sealed = await botDefStore.writeBotDef(db, {
    bot_id: BOT, display_name: "Hank", enabled: 1, mode: "insert",
    definition: { system_prompt: "you help", models: { default: "provider/model-a" }, tools: { crow_mcp: ["crow-sharing"] } },
  });
  assert.equal(sealed.rowsAffected, 1);
  await tokenMac.markConverted(botDefMac.BOT_DEF_FAMILY, { writeSetting: (k, v, o) => settingsRegistry.writeSetting(db, k, v, o) });
  assert.equal((await botDefStore.readVerifiedBotDef(db, BOT)).ok, true, "the bot verifies");
  const written = acl.setSharingBotAclEntry(process.env.CROW_HOME, BOT, {
    contacts: [{ crow_id: PEER.crowId, secp256k1_pubkey: PEER.pubkey }],
    groups: [],
    rate: { per_hour: 20 },
  });
  assert.equal(written.ok, true);

  const sharingToken = await SHARING_BOT_TOKEN.rotate(db);
  const boardToken = await generateBoardToken(db);
  const localToken = await generateLocalToken(db);

  const createDb = () => {
    const client = createDbClient(crow);
    state.dbs.push(client);
    return client;
  };

  const app = express();
  app.use(express.json());
  // The real middleware takes a live db client (servers/gateway/index.js: localTokenAuthMiddleware(createDbClient())),
  // not a factory: passing one would make every branch throw into its own catch and authenticate nothing.
  app.use(localTokenAuthMiddleware(db));
  // The real fallback auth every gateway mount gets: a request the local-token middleware did not
  // authenticate against this mount is refused. (In production this is OAuth; 401 either way.)
  const authMiddleware = (req, res, next) => (req.localTokenAuth ? next() : res.status(401).json({ error: "unauthorized" }));
  const sessionManager = new SessionManager();
  state.managers.push(sessionManager);
  const peerExposureGate = async () => true;

  app.use(door.SHARING_BOT_MCP_PREFIX, door.sharingBotMountAuth({ createDb }));
  mountMcpServer(app, door.SHARING_BOT_MCP_PREFIX, () => door.createSharingBotServer({
    createDb, crowHome: process.env.CROW_HOME, loadSeed: async () => SEED,
  }), sessionManager, authMiddleware, peerExposureGate);
  // Another mount, to prove the sharing token opens nothing else.
  mountMcpServer(app, "/memory", () => new McpServer({ name: "crow-memory", version: "0" }), sessionManager, authMiddleware, peerExposureGate);

  // The OWNER's drafts API (the route that can actually send a bot's draft), wired the way the
  // dashboard mounts it: the dashboard's session gate in front of the real router, whose own
  // middleware then applies the real owner rule (isLocalPasswordSessionOn). A bot has no session
  // cookie, so whatever token it carries is all it could hope with — and this gate refuses it before
  // a route runs. The real local-token middleware above is mounted app-wide, so the sharing token is
  // also proven not to turn into a dashboard caller.
  const dashboardGate = (req, res, next) => {
    const token = /(?:^|;\s*)crow_session=([^;]*)/.exec(String(req.headers.cookie || ""));
    if (!token || !token[1]) return res.status(401).json({ error: "unauthorized" });
    req.dashboardSession = decodeURIComponent(token[1]);
    next();
  };
  app.use(messagesDraftsRouter(dashboardGate, { openDb: createDb }));

  const server = await new Promise((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  state.servers.push(server);
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  /** A real MCP client over Streamable HTTP with these headers. Closes itself if the connect fails. */
  const connect = async (path, headers) => {
    const transport = new StreamableHTTPClientTransport(new URL(base + path), { requestInit: { headers } });
    const client = new Client({ name: "door-test", version: "0" });
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

  /** One raw JSON-RPC POST — the shape a refused caller gets is an HTTP status, not an MCP error. */
  const post = async (path, headers, body = { jsonrpc: "2.0", id: 1, method: "tools/list" }) => {
    const res = await fetch(base + path, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    const status = res.status;
    // Release the socket: an unread body holds a keep-alive connection open past the test.
    try { await res.body?.cancel(); } catch { /* already consumed */ }
    return status;
  };

  /** The actor headers a bot's config carries (crow-server-catalog.mjs sharingBotBlock). */
  const signingHeaders = ({ token, botId = BOT, threadId = "perch-1", gatewayType = "perch" } = {}) => ({
    Authorization: "Bearer " + token,
    "X-Crow-Actor-Kind": "sharing",
    "X-Crow-Actor-Id": botId,
    "X-Crow-Actor-Thread": threadId,
    "X-Crow-Actor-Gateway": gatewayType,
    "X-Crow-Actor-Sig": signSharingActor({ botId, threadId, gatewayType }),
  });

  return { db, crow, contactId, sharingToken, boardToken, localToken, connect, post, signingHeaders, base };
}

/** A tool result's JSON body. */
const payload = (result) => JSON.parse(result.content[0].text);

/* ------------------------------------------------------------------- admitted */

test("a sharing-bot token plus a signed `sharing` actor is admitted, and the door serves exactly five tools", async () => {
  const s = await setup();
  const client = await s.connect("/sharing-bot/mcp", s.signingHeaders({ token: s.sharingToken }));
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map((tool) => tool.name).sort(), [...door.SHARING_BOT_TOOL_NAMES].sort());
}, { timeout: TEST_TIMEOUT });

test("crow_send_message over the wire creates a draft awaiting the owner — never a send", async () => {
  const s = await setup();
  const client = await s.connect("/sharing-bot/mcp", s.signingHeaders({ token: s.sharingToken }));

  const listed = payload(await client.callTool({ name: "crow_list_contacts", arguments: {} }));
  assert.deepEqual(listed.contacts, [{ kind: "contact", crow_id: PEER.crowId, name: PEER.name }]);
  assert.doesNotMatch(JSON.stringify(listed), /secp256k1/, "no key on the contact list");

  const sent = await client.callTool({ name: "crow_send_message", arguments: { contact: PEER.name, message: "Hello from the door" } });
  assert.equal(sent.isError, undefined, JSON.stringify(sent));
  const out = payload(sent);
  assert.match(out.draft_id, store.MESSAGE_DRAFT_ID_RE);
  assert.equal(out.status, door.AWAITING_OWNER);
  assert.equal(out.draft, "created");

  const draft = await store.getDraft(s.db, out.draft_id);
  assert.equal(draft.origin, "bot");
  assert.equal(draft.botId, BOT);
  assert.equal(draft.botName, "Hank");
  assert.equal(draft.state, "open");
  assert.equal(Number((await s.db.execute({ sql: "SELECT COUNT(*) AS n FROM messages" })).rows[0].n), 0, "nothing was sent");

  // One audit row per call, with the thread and gateway the actor signed.
  const { rows } = await s.db.execute({
    sql: "SELECT bot_id, thread, gateway, tool, target, outcome, draft_id FROM bot_sharing_audit ORDER BY id",
    args: [],
  });
  assert.deepEqual(rows.map((row) => [row.tool, row.outcome]), [["crow_list_contacts", "read"], ["crow_send_message", "drafted"]]);
  assert.equal(rows[1].bot_id, BOT);
  assert.equal(rows[1].thread, "perch-1");
  assert.equal(rows[1].gateway, "perch");
  assert.equal(rows[1].target, PEER.crowId);
  assert.equal(rows[1].draft_id, out.draft_id);
  assert.doesNotMatch(JSON.stringify(rows), /Hello from the door/, "the audit never carries the text");
}, { timeout: TEST_TIMEOUT });

test("a refusal comes back as an MCP error with a fixed sentence, and is audited", async () => {
  const s = await setup();
  const client = await s.connect("/sharing-bot/mcp", s.signingHeaders({ token: s.sharingToken }));
  const res = await client.callTool({ name: "crow_send_message", arguments: { contact: "crow:stranger", message: "hi" } });
  assert.equal(res.isError, true);
  const body = payload(res);
  assert.equal(body.error, "not_allowed");
  assert.match(body.message, /not on this bot's allow-list/);
  const { rows } = await s.db.execute({ sql: "SELECT outcome, draft_id FROM bot_sharing_audit", args: [] });
  assert.deepEqual(rows.map((row) => [row.outcome, row.draft_id]), [["refused:not_allowed", null]]);
}, { timeout: TEST_TIMEOUT });

test("the sharing door token cannot send a bot's draft through the owner's send route", async () => {
  const s = await setup();
  const client = await s.connect("/sharing-bot/mcp", s.signingHeaders({ token: s.sharingToken }));
  const out = payload(await client.callTool({ name: "crow_send_message", arguments: { contact: PEER.name, message: "From the bot" } }));

  const before = await store.getDraft(s.db, out.draft_id);
  assert.equal(before.state, "open", "the door left the words as a draft");
  const posted = JSON.stringify({ body: before.body, expectVersion: before.version });

  // Every shape a bot could present to the owner route: its signed door headers, the bare bearer, the
  // token posed as a session cookie (the dashboard's owner rule rejects it like any other unknown
  // session), and no credential at all. NONE of them is an owner session, which is the only thing
  // that can send.
  const shapes = [
    ["signed door headers", s.signingHeaders({ token: s.sharingToken })],
    ["bare bearer", { Authorization: "Bearer " + s.sharingToken }],
    ["token posed as a session cookie", { cookie: "crow_session=" + s.sharingToken }],
    ["no credential", {}],
  ];
  for (const [label, extra] of shapes) {
    const res = await fetch(`${s.base}${MESSAGES_DRAFTS_API_PREFIX}/${out.draft_id}/send`, {
      method: "POST",
      headers: { "content-type": "application/json", "sec-fetch-site": "same-origin", origin: s.base, ...extra },
      body: posted,
      signal: AbortSignal.timeout(FETCH_TIMEOUT),
    });
    const status = res.status;
    const text = await res.text().catch(() => "");
    assert.ok(status === 401 || status === 403, `${label}: refused with 401/403, got ${status} ${text.slice(0, 120)}`);
    const after = await store.getDraft(s.db, out.draft_id);
    assert.equal(after.state, "open", `${label}: the draft is still waiting for the owner`);
    assert.equal(after.version, before.version, `${label}: nothing moved the row`);
  }
  assert.equal(Number((await s.db.execute({ sql: "SELECT COUNT(*) AS n FROM messages" })).rows[0].n), 0,
    "no message left the instance");
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------------- refused */

test("no actor headers: the token alone is 401 (unlike the board, there is no unattributed mode)", async () => {
  const s = await setup();
  assert.equal(await s.post("/sharing-bot/mcp", { Authorization: "Bearer " + s.sharingToken }), 401);
}, { timeout: TEST_TIMEOUT });

test("a signature for the wrong kind, or for another bot, or a tampered thread, is 401", async () => {
  const s = await setup();
  // A board signature presented as a sharing one.
  assert.equal(await s.post("/sharing-bot/mcp", {
    Authorization: "Bearer " + s.sharingToken,
    "X-Crow-Actor-Kind": "sharing",
    "X-Crow-Actor-Id": BOT,
    "X-Crow-Actor-Sig": signBoardActor({ botId: BOT }),
  }), 401);
  // A phone signature over the same (bot, thread, gateway).
  assert.equal(await s.post("/sharing-bot/mcp", {
    Authorization: "Bearer " + s.sharingToken,
    "X-Crow-Actor-Kind": "sharing",
    "X-Crow-Actor-Id": BOT,
    "X-Crow-Actor-Sig": signActor({ kind: "bot", botId: BOT, threadId: "perch-1", gatewayType: "perch" }),
  }), 401);
  // A signature for one bot paired with ANOTHER bot's id in the header (the forgery shape): the MAC
  // is over the id, so it cannot verify for the id the headers claim, and the door answers before any
  // handler. (Signing as otto is otto's own credential, not a forgery — that call is admitted.)
  const borrowed = { ...s.signingHeaders({ token: s.sharingToken }), "X-Crow-Actor-Id": "otto" };
  assert.equal(await s.post("/sharing-bot/mcp", borrowed), 401);
  // A tampered thread.
  const headers = s.signingHeaders({ token: s.sharingToken });
  headers["X-Crow-Actor-Thread"] = "perch-2";
  assert.equal(await s.post("/sharing-bot/mcp", headers), 401);
}, { timeout: TEST_TIMEOUT });

test("the board token and the operator's full local token do not open the door", async () => {
  const s = await setup();
  for (const token of [s.boardToken, s.localToken]) {
    assert.equal(await s.post("/sharing-bot/mcp", s.signingHeaders({ token })), 401, `token ${token.slice(0, 6)}… must not open the door`);
  }
  // No token at all.
  assert.equal(await s.post("/sharing-bot/mcp", { "X-Crow-Actor-Kind": "sharing", "X-Crow-Actor-Id": BOT }), 401);
}, { timeout: TEST_TIMEOUT });

test("the sharing-bot token opens nothing else, and /sharing is not a door at all", async () => {
  const s = await setup();
  assert.equal(await s.post("/memory/mcp", { Authorization: "Bearer " + s.sharingToken }), 401,
    "a path-scoped token authenticates only its own mount");
  assert.equal(await s.post("/sharing/mcp", s.signingHeaders({ token: s.sharingToken })), 404, "no such mount");
}, { timeout: TEST_TIMEOUT });

test("a relayed socket (a contained bot) may present the sharing-bot token, where the operator's token is refused", async () => {
  const s = await setup();
  const middleware = localTokenAuthMiddleware(s.db);

  const relayed = (token) => ({ socket: { remoteAddress: RELAY_SOURCE_V4 }, path: "/sharing-bot/mcp", headers: { authorization: "Bearer " + token } });
  const loopback = (token) => ({ socket: { remoteAddress: "127.0.0.1" }, path: "/sharing-bot/mcp", headers: { authorization: "Bearer " + token } });

  const botReq = relayed(s.sharingToken);
  await middleware(botReq, {}, () => {});
  assert.deepEqual(botReq.localTokenAuth, { token: "local-mcp", scope: "sharing-bot" });

  const operatorReq = relayed(s.localToken);
  await middleware(operatorReq, {}, () => {});
  assert.equal(operatorReq.localTokenAuth, undefined, "a relayed socket is never the operator");

  const plainReq = loopback(s.sharingToken);
  await middleware(plainReq, {}, () => {});
  assert.deepEqual(plainReq.localTokenAuth, { token: "local-mcp", scope: "sharing-bot" }, "the operator's own loopback socket may too");
}, { timeout: TEST_TIMEOUT });