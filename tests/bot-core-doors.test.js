/**
 * The core bot doors (design D2, servers/gateway/core-bot-doors.js): /memory-bot/mcp and
 * /projects-bot/mcp, the memory and project tools served by the gateway to a bot with a VERIFIED bot
 * actor, so the bot never opens crow.db for them.
 *
 * A real HTTP mount wired the way boot/mcp-mounts.js wires it (the global JSON parser, the real
 * local-token middleware, each door's own guard, mountMcpServer with the door's caller context), a
 * real MCP SDK client for admitted calls, plain requests for refusals, and a real relayed socket
 * (bound to the egress relay's mark) for the "a relayed socket is never the owner" rule. Then the
 * catalog switch: flag off → stdio as today, flag on + the def's opt-in → HTTP door blocks, flag on
 * without the opt-in → stdio.
 *
 * Harness: a scratch crow.db (init-db) and scratch CROW_HOME / CROW_DATA_DIR, set before any server
 * module is imported, so no token file, key or row can land in a real home.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmScratch } from "./helpers/safe-rm.js";

const REPO = new URL("..", import.meta.url).pathname;
const root = mkdtempSync(join(tmpdir(), "bot-core-doors-"));
const CROW_HOME = join(root, "crow");
const DATA = join(root, "data");
mkdirSync(CROW_HOME, { recursive: true });
mkdirSync(DATA, { recursive: true });
process.env.HOME = join(root, "home");
process.env.CROW_HOME = CROW_HOME;
process.env.CROW_DATA_DIR = DATA;
delete process.env.CROW_DB_PATH;
delete process.env.CROW_BOT_CORE_DOORS;
process.env.CROW_TASKS_DB_PATH = join(DATA, "tasks.db");
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
const DB_FILE = join(DATA, "crow.db");

const TEST_TIMEOUT = 60_000;
const FETCH_TIMEOUT = 10_000;

const BOT = "door-bot";          // opted in, homed in A
const BOT2 = "door-bot-two";     // opted in, homed in A (for the session-ownership check)
const PLAIN = "plain-bot";       // never opted in
const DISABLED = "disabled-bot"; // opted in, verified, but switched off
const TAMPERED = "tampered-bot"; // opted in, then changed outside Crow (no longer verifies)

const state = { servers: [], sessions: [], managers: [], dbs: [] };
let M = {};      // modules
let db = null;
let A = null;
let B = null;
let gw = null;   // the listening gateway stand-in

async function endSession({ client, transport }) {
  try { await transport?.terminateSession?.(); } catch { /* already gone */ }
  try { await client?.close(); } catch { /* already closed */ }
}

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
  for (const client of state.dbs) { try { client.close(); } catch { /* ignore */ } }
  await new Promise((resolve) => setTimeout(resolve, 0));
  rmScratch(root);
});

const DEF = (extra = {}) => ({
  system_prompt: "you help",
  models: { default: "provider/model-a" },
  tools: { crow_mcp: ["crow-memory", "crow-projects"] },
  ...extra,
});

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env }, stdio: "pipe", cwd: REPO, timeout: 120_000 });
  M.db = await import("../servers/db.js");
  M.store = await import("../servers/shared/bot-def-store.js");
  M.mac = await import("../servers/shared/bot-def-mac.js");
  M.tokenMac = await import("../servers/shared/token-mac.js");
  M.settings = await import("../servers/gateway/dashboard/settings/registry.js");
  M.spaces = await import("../servers/shared/project-spaces.js");
  M.tokens = await import("../servers/gateway/local-token.js");
  M.sig = await import("../scripts/pi-bots/actor-sig.mjs");
  M.doors = await import("../servers/gateway/core-bot-doors.js");
  M.mcp = await import("../servers/gateway/routes/mcp.js");
  M.sessions = await import("../servers/gateway/session-manager.js");
  M.botDoors = await import("../servers/shared/bot-doors.js");
  M.research = await import("../servers/research/server.js");
  M.express = (await import("express")).default;
  M.Client = (await import("@modelcontextprotocol/sdk/client/index.js")).Client;
  M.Transport = (await import("@modelcontextprotocol/sdk/client/streamableHttp.js")).StreamableHTTPClientTransport;
  M.McpServer = (await import("@modelcontextprotocol/sdk/server/mcp.js")).McpServer;

  db = M.db.createDbClient(DB_FILE);
  state.dbs.push(db);
  M.sig.initGatewayActorKey();
  // Ready the provenance columns the projects server reads.
  M.research.createProjectServer(DB_FILE, { actor: { kind: "owner" } }).close();

  A = Number((await M.spaces.createProjectSpace(db, { name: "Home Alpha", description: "alpha description" })).id);
  B = Number((await M.spaces.createProjectSpace(db, { name: "Other Bravo", description: "bravo description" })).id);

  for (const [botId, def] of [[BOT, DEF({ core_doors: true })], [BOT2, DEF({ core_doors: true })], [PLAIN, DEF()], [TAMPERED, DEF({ core_doors: true })], [DISABLED, DEF({ core_doors: true })]]) {
    const res = await M.store.writeBotDef(db, { bot_id: botId, display_name: botId, definition: def, enabled: botId === DISABLED ? 0 : 1, project_id: A, mode: "insert" });
    assert.equal(res.rowsAffected, 1, botId);
  }
  // The bot:def era (what the pre-listen converter marks), then a change made OUTSIDE Crow: the row
  // keeps its MAC but no longer verifies.
  await M.tokenMac.markConverted(M.mac.BOT_DEF_FAMILY, { writeSetting: (k, v, o) => M.settings.writeSetting(db, k, v, o) });
  await db.execute({
    sql: "UPDATE pi_bot_defs SET definition = ? WHERE bot_id = ?",
    args: [JSON.stringify(DEF({ core_doors: true, permission_policy: { write_paths: ["/"] } })), TAMPERED],
  });
  assert.equal((await M.store.readVerifiedBotDef(db, BOT)).ok, true, "the opted-in bot verifies");
  assert.equal((await M.store.readVerifiedBotDef(db, TAMPERED)).ok, false, "the tampered bot does not");

  gw = await startGateway();
});

/** The gateway stand-in: the real middleware, the real guards and mounts, one listening server. */
async function startGateway() {
  const memoryToken = await M.tokens.MEMORY_BOT_TOKEN.rotate(db);
  const projectsToken = await M.tokens.PROJECTS_BOT_TOKEN.rotate(db);
  const sharingToken = await M.tokens.SHARING_BOT_TOKEN.rotate(db);
  const localToken = await M.tokens.generateLocalToken(db);

  const createDb = () => {
    const client = M.db.createDbClient(DB_FILE);
    state.dbs.push(client);
    return client;
  };
  const app = M.express();
  app.use(M.express.json());
  app.use(M.tokens.localTokenAuthMiddleware(db));
  const authMiddleware = (req, res, next) => (req.localTokenAuth ? next() : res.status(401).json({ error: "unauthorized" }));
  const sessionManager = new M.sessions.SessionManager();
  state.managers.push(sessionManager);
  const peerGate = async () => true;
  const storesOf = (name) => () => [sessionManager.getStore(name, "streamable"), sessionManager.getStore(name, "sse")];

  // Wired exactly as boot/mcp-mounts.js wires them.
  app.use("/memory-bot", M.doors.coreBotDoorMountAuth("memory", { createDb, sessionStores: storesOf("memory-bot") }));
  M.mcp.mountMcpServer(app, "/memory-bot", () => M.doors.createMemoryBotServer({ dbPath: DB_FILE }), sessionManager, authMiddleware, peerGate, { callerFor: M.doors.coreBotDoorCaller("memory") });
  app.use("/projects-bot", M.doors.coreBotDoorMountAuth("projects", { createDb, sessionStores: storesOf("projects-bot") }));
  M.mcp.mountMcpServer(app, "/projects-bot", () => M.doors.createProjectsBotServer({ dbPath: DB_FILE }), sessionManager, authMiddleware, peerGate, { callerFor: M.doors.coreBotDoorCaller("projects") });
  // The owner's own /memory, to prove a door token opens nothing else.
  M.mcp.mountMcpServer(app, "/memory", () => new M.McpServer({ name: "crow-memory", version: "0" }), sessionManager, authMiddleware, peerGate);

  const server = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  state.servers.push(server);
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;

  const connect = async (path, headers) => {
    const transport = new M.Transport(new URL(base + path), { requestInit: { headers } });
    const client = new M.Client({ name: "door-test", version: "0" });
    try {
      await client.connect(transport);
    } catch (err) {
      try { await client.close(); } catch { /* ignore */ }
      throw err;
    }
    state.sessions.push({ client, transport });
    return { client, transport };
  };

  /** One raw JSON-RPC POST, optionally from a given local source address (the relay's mark). */
  const post = (path, headers, { body = { jsonrpc: "2.0", id: 1, method: "tools/list" }, localAddress } = {}) => new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request({
      host: "127.0.0.1", port, path, method: "POST", agent: false,
      ...(localAddress ? { localAddress } : {}),
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "content-length": Buffer.byteLength(data), ...headers },
      timeout: FETCH_TIMEOUT,
    }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end(data);
  });

  const signed = (door, { token, botId = BOT, threadId = "perch-1", gatewayType = "perch", kind } = {}) => {
    const k = kind || door;
    const signer = { memory: M.sig.signMemoryActor, projects: M.sig.signProjectsActor, sharing: M.sig.signSharingActor }[k];
    return {
      Authorization: "Bearer " + token,
      "X-Crow-Actor-Kind": k,
      "X-Crow-Actor-Id": botId,
      "X-Crow-Actor-Thread": threadId,
      "X-Crow-Actor-Gateway": gatewayType,
      "X-Crow-Actor-Sig": signer({ botId, threadId, gatewayType }),
    };
  };

  return { memoryToken, projectsToken, sharingToken, localToken, connect, post, signed, base };
}

const text = (r) => (r.content || []).map((c) => c.text).join("\n");
const call = (client, name, args = {}) => client.callTool({ name, arguments: args });

/* ---------------------------------------------------------------------- admitted */

test("memory door: token + signed `memory` actor admits the bot, and a write lands in its verified home project", async () => {
  const { client } = await gw.connect("/memory-bot/mcp", gw.signed("memory", { token: gw.memoryToken }));
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  assert.ok(names.includes("crow_store_memory") && names.includes("crow_search_memories"), names.join(","));

  const stored = await call(client, "crow_store_memory", { content: "door memory row", category: "general" });
  assert.equal(stored.isError, undefined, text(stored));
  const { rows } = await db.execute({ sql: "SELECT project_id FROM memories WHERE content = ?", args: ["door memory row"] });
  assert.equal(rows.length, 1);
  assert.equal(Number(rows[0].project_id), A, "the bot's write lands in its home project");

  // Naming a project it holds no share of is refused.
  const other = await call(client, "crow_store_memory", { content: "elsewhere", project_id: B });
  assert.equal(other.isError, true, text(other));
}, { timeout: TEST_TIMEOUT });

test("projects door: the verified bot sees its home project only, and another project is refused", async () => {
  const { client } = await gw.connect("/projects-bot/mcp", gw.signed("projects", { token: gw.projectsToken }));
  const listed = text(await call(client, "crow_list_projects", {}));
  assert.ok(listed.includes("Home Alpha"), listed);
  assert.ok(!listed.includes("Other Bravo"), listed);

  const refused = await call(client, "crow_project_get", { project_id: B });
  assert.equal(refused.isError, true, text(refused));
  assert.ok(!text(refused).includes("Other Bravo"), text(refused));

  const note = await call(client, "crow_add_note", { content: "door note body" });
  assert.equal(note.isError, undefined, text(note));
  const { rows } = await db.execute({ sql: "SELECT project_id FROM research_notes WHERE content = ?", args: ["door note body"] });
  assert.equal(Number(rows[0].project_id), A, "an omitted project_id is the verified home project");
}, { timeout: TEST_TIMEOUT });

/* ---------------------------------------------------------------------- refused */

test("every other caller shape is 401 before any handler", async () => {
  const mem = "/memory-bot/mcp";
  const proj = "/projects-bot/mcp";
  const cases = [
    ["no bearer", mem, {}],
    ["door token, no actor headers", mem, { Authorization: "Bearer " + gw.memoryToken }],
    ["door token, wrong signature", mem, { ...gw.signed("memory", { token: gw.memoryToken }), "X-Crow-Actor-Sig": "0".repeat(64) }],
    ["door token, a signature for another bot", mem, { ...gw.signed("memory", { token: gw.memoryToken }), "X-Crow-Actor-Id": BOT2 }],
    ["door token, another door's kind (sharing)", mem, gw.signed("memory", { token: gw.memoryToken, kind: "sharing" })],
    ["memory token + memory signature on the projects door", proj, gw.signed("memory", { token: gw.memoryToken })],
    ["projects token + projects signature on the memory door", mem, gw.signed("projects", { token: gw.projectsToken })],
    ["memory signature replayed as projects", proj, { ...gw.signed("memory", { token: gw.projectsToken }), "X-Crow-Actor-Kind": "projects" }],
    ["the sharing door's token", mem, gw.signed("memory", { token: gw.sharingToken })],
    ["the operator's full local token", mem, gw.signed("memory", { token: gw.localToken })],
  ];
  for (const [label, path, headers] of cases) {
    assert.equal(await gw.post(path, headers), 401, label);
  }
  // A door token opens no other mount: the owner's /memory refuses it.
  assert.equal(await gw.post("/memory/mcp", gw.signed("memory", { token: gw.memoryToken })), 401, "memory-bot token on /memory");
}, { timeout: TEST_TIMEOUT });

test("a relayed socket presenting the owner's token is refused; only the door token plus a signature admits it", async () => {
  const relay = M.botDoors.RELAY_SOURCE_V4;
  // The operator's full local token from a contained bot's socket: refused (both at the transport
  // half and by the door's own guard).
  assert.equal(await gw.post("/memory-bot/mcp", gw.signed("memory", { token: gw.localToken }), { localAddress: relay }), 401);
  assert.equal(await gw.post("/memory/mcp", { Authorization: "Bearer " + gw.localToken }, { localAddress: relay }), 401, "and on the owner's own mount");
  // The door token plus a valid signature from the same relayed socket: admitted (an initialize).
  const init = {
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "relay-test", version: "0" } },
  };
  assert.equal(await gw.post("/memory-bot/mcp", gw.signed("memory", { token: gw.memoryToken }), { localAddress: relay, body: init }), 200);
}, { timeout: TEST_TIMEOUT });

test("an unverified, an unknown and a not-opted-in bot are refused 403 at the door", async () => {
  for (const [label, botId] of [["changed outside Crow", TAMPERED], ["never opted in", PLAIN], ["disabled", DISABLED], ["unknown", "no-such-bot"]]) {
    assert.equal(await gw.post("/memory-bot/mcp", gw.signed("memory", { token: gw.memoryToken, botId })), 403, `memory: ${label}`);
    assert.equal(await gw.post("/projects-bot/mcp", gw.signed("projects", { token: gw.projectsToken, botId })), 403, `projects: ${label}`);
  }
}, { timeout: TEST_TIMEOUT });

test("a session belongs to the verified tuple that opened it", async () => {
  const { transport } = await gw.connect("/memory-bot/mcp", gw.signed("memory", { token: gw.memoryToken }));
  const sid = transport.sessionId;
  assert.ok(sid, "the session has an id");
  // Another opted-in, verified bot presenting that session id: refused.
  assert.equal(await gw.post("/memory-bot/mcp", { ...gw.signed("memory", { token: gw.memoryToken, botId: BOT2 }), "mcp-session-id": sid }), 401);
  // The same bot on another thread: refused too.
  assert.equal(await gw.post("/memory-bot/mcp", { ...gw.signed("memory", { token: gw.memoryToken, threadId: "perch-2" }), "mcp-session-id": sid }), 401);
}, { timeout: TEST_TIMEOUT });

/** Open an SSE session on `base`+path with `headers`; resolves {sessionId, close}. */
function openSse(base, path, headers) {
  return new Promise((resolve, reject) => {
    const req = http.get(base + path, { headers, agent: false }, (res) => {
      let buf = "";
      res.setEncoding("utf8");
      res.on("data", (d) => {
        buf += d;
        const m = /sessionId=([^\s&]+)/.exec(buf);
        if (m) resolve({ sessionId: m[1], close: () => req.destroy() });
      });
    });
    req.on("error", reject);
    setTimeout(() => reject(new Error("no sse endpoint event")), FETCH_TIMEOUT).unref();
  });
}

test("a session id from the header or the query never reaches another bot's session", async () => {
  const hdr = (botId) => gw.signed("memory", { token: gw.memoryToken, botId });
  const sse = await openSse(gw.base, "/memory-bot/sse", hdr(BOT));
  try {
    const { transport } = await gw.connect("/memory-bot/mcp", hdr(BOT2));
    const msg = (extra, q) => gw.post(`/memory-bot/messages?sessionId=${q}`, { ...hdr(BOT2), ...extra });
    // Header: B's own streamable session. Query: A's SSE session. Refused at the door.
    assert.equal(await msg({ "mcp-session-id": transport.sessionId }, sse.sessionId), 401, "both id sources present");
    // Only A's SSE id in the query: refused by the door's owner check.
    assert.equal(await msg({}, sse.sessionId), 401, "another bot's SSE session");
    // A itself reaches its own session (accepted).
    assert.equal(await gw.post(`/memory-bot/messages?sessionId=${sse.sessionId}`, hdr(BOT),
      { body: { jsonrpc: "2.0", id: 9, method: "ping" } }), 202, "the owner");
  } finally { sse.close(); }
}, { timeout: TEST_TIMEOUT });

test("the handlers enforce session ownership themselves, whatever the guard checked", async () => {
  // A mount whose guard has NO session-store check, so only routes/mcp.js can refuse.
  const createDb = () => { const c = M.db.createDbClient(DB_FILE); state.dbs.push(c); return c; };
  const app = M.express();
  app.use(M.express.json());
  app.use(M.tokens.localTokenAuthMiddleware(db));
  const sm = new M.sessions.SessionManager();
  state.managers.push(sm);
  const auth = (req, res, next) => (req.localTokenAuth ? next() : res.status(401).json({ error: "unauthorized" }));
  app.use("/memory-bot", M.doors.coreBotDoorMountAuth("memory", { createDb }));
  M.mcp.mountMcpServer(app, "/memory-bot", () => M.doors.createMemoryBotServer({ dbPath: DB_FILE }), sm, auth, async () => true, { callerFor: M.doors.coreBotDoorCaller("memory") });
  app.use("/open", (req, res, next) => { req.auth = { clientId: null }; next(); });
  M.mcp.mountMcpServer(app, "/open", () => new M.McpServer({ name: "open", version: "0" }), sm, (q, r, n) => n(), async () => true, { callerFor: () => ({ caller: null, peer: false, crossHost: false }) });
  const server = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  state.servers.push(server);
  const base = `http://127.0.0.1:${server.address().port}`;
  const port = server.address().port;
  const hdr = (botId) => gw.signed("memory", { token: gw.memoryToken, botId });
  const raw = (path, headers, method = "POST") => new Promise((resolve, reject) => {
    const data = JSON.stringify({ jsonrpc: "2.0", id: 5, method: "ping" });
    const req = http.request({ host: "127.0.0.1", port, path, method, agent: false,
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...(method === "POST" ? { "content-length": Buffer.byteLength(data) } : {}), ...headers }, timeout: FETCH_TIMEOUT },
    (res) => { let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => resolve({ status: res.statusCode, body: b })); });
    req.on("error", reject);
    req.end(method === "POST" ? data : undefined);
  });
  const sse = await openSse(base, "/memory-bot/sse", hdr(BOT));
  try {
    const other = await raw(`/memory-bot/messages?sessionId=${sse.sessionId}`, hdr(BOT2));
    const unknown = await raw(`/memory-bot/messages?sessionId=nope`, hdr(BOT2));
    assert.equal(other.status, 400);
    assert.deepEqual(other, unknown, "same answer as an unknown session");
    assert.equal((await raw(`/memory-bot/messages?sessionId=${sse.sessionId}`, hdr(BOT))).status, 202, "owner");
  } finally { sse.close(); }
  // Streamable: B cannot use A's id on POST/GET/DELETE (same answer as unknown), even with no guard store check.
  const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } };
  const opened = await new Promise((resolve, reject) => {
    const data = JSON.stringify(init);
    const req = http.request({ host: "127.0.0.1", port, path: "/memory-bot/mcp", method: "POST", agent: false,
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "content-length": Buffer.byteLength(data), ...hdr(BOT) } },
    (res) => { res.resume(); res.on("end", () => resolve(res.headers["mcp-session-id"])); });
    req.on("error", reject); req.end(data);
  });
  assert.ok(opened);
  for (const method of ["POST", "GET", "DELETE"]) {
    const r = await raw("/memory-bot/mcp", { ...hdr(BOT2), "mcp-session-id": opened }, method);
    const u = await raw("/memory-bot/mcp", { ...hdr(BOT2), "mcp-session-id": "nope" }, method);
    assert.equal(r.status, u.status, method);
    assert.equal(r.body, u.body, method);
    assert.equal(r.status, 400, method);
  }
  // An owner-less mount is unchanged: any caller continues an owner-less session.
  const openInit = await new Promise((resolve, reject) => {
    const data = JSON.stringify(init);
    const req = http.request({ host: "127.0.0.1", port, path: "/open/mcp", method: "POST", agent: false,
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", "content-length": Buffer.byteLength(data) } },
    (res) => { res.resume(); res.on("end", () => resolve(res.headers["mcp-session-id"])); });
    req.on("error", reject); req.end(data);
  });
  assert.ok(openInit, "owner-less session opens");
  assert.equal((await raw("/open/mcp", { "mcp-session-id": openInit })).status, 200, "owner-less session continues");
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------- the security table, through the doors */

test("projects door: member and data-backend writes stay refused or home-scoped for the bot", async () => {
  const { client } = await gw.connect("/projects-bot/mcp", gw.signed("projects", { token: gw.projectsToken }));
  const contact = Number((await db.execute({
    sql: "INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type) VALUES (?,?,?,?, 'crow')",
    args: ["crow:door-peer", "Door Peer", "02" + "b".repeat(64), "f".repeat(64)],
  })).lastInsertRowid);
  const members = async () => Number((await db.execute({ sql: "SELECT COUNT(*) AS n FROM project_members WHERE contact_id = ?", args: [contact] })).rows[0].n);

  for (const project of [A, B]) {
    for (const [name, args] of [
      ["crow_add_member", { project_id: project, contact_id: contact, role: "editor" }],
      ["crow_remove_member", { project_id: project, contact_id: contact }],
    ]) {
      const r = await call(client, name, args);
      assert.equal(r.isError, true, `${name} on #${project}: ${text(r)}`);
      assert.match(text(r), /operator only/, `${name} on #${project}`);
    }
  }
  assert.equal(await members(), 0, "no membership row was written");

  // A backend on another project: refused; one there already is invisible and cannot be removed.
  const reg = await call(client, "crow_register_backend", { name: "x", backend_type: "mcp_server", project_id: B, connection_ref: JSON.stringify({ command: "node", args: ["x.js"] }) });
  assert.equal(reg.isError, true, text(reg));
  const backend = Number((await db.execute({
    sql: "INSERT INTO data_backends (project_id, name, backend_type, connection_ref, status) VALUES (?, 'bravo-db', 'mcp_server', '{}', 'pending')",
    args: [B],
  })).lastInsertRowid);
  const removed = await call(client, "crow_remove_backend", { id: backend, confirm_token: "" });
  assert.equal(removed.isError, true, text(removed));
  assert.match(text(removed), /Not found/, text(removed));
  const listed = text(await call(client, "crow_list_backends", {}));
  assert.ok(!listed.includes("bravo-db"), listed);
  assert.equal(Number((await db.execute({ sql: "SELECT COUNT(*) AS n FROM data_backends WHERE id = ?", args: [backend] })).rows[0].n), 1);
}, { timeout: TEST_TIMEOUT });

test("memory door: notification settings, schedules and global context stay the operator's", async () => {
  const { client } = await gw.connect("/memory-bot/mcp", gw.signed("memory", { token: gw.memoryToken }));
  const prefsBefore = (await db.execute({ sql: "SELECT value FROM dashboard_settings WHERE key = 'notification_prefs'", args: [] })).rows[0]?.value ?? null;
  const schedulesBefore = Number((await db.execute({ sql: "SELECT COUNT(*) AS n FROM schedules", args: [] })).rows[0].n);

  for (const [name, args] of [
    ["crow_notification_settings", { action: "set", types_enabled: [] }],
    ["crow_notification_settings", { action: "get" }],
    ["crow_create_schedule", { task: "remind me", cron_expression: "0 9 * * *" }],
    ["crow_create_schedule", { task: `pipeline:botcron:${BOT}`, cron_expression: "0 9 * * *", type: "bot_routine" }],
    ["crow_list_schedules", {}],
    ["crow_update_schedule", { id: 1, enabled: false }],
    ["crow_dismiss_all_notifications", {}],
    ["crow_regenerate_embeddings", {}],
    ["crow_dream", { dry_run: false }],
  ]) {
    const r = await call(client, name, args);
    assert.equal(r.isError, true, `${name} ${JSON.stringify(args)}: ${text(r)}`);
  }
  // A context write with no project lands on the bot's OWN project override, never the global
  // section; the writing rules are refused outright.
  const globalOf = async (key) => (await db.execute({
    sql: "SELECT content FROM crow_context WHERE section_key = ? AND project_id IS NULL AND device_id IS NULL",
    args: [key],
  })).rows[0]?.content ?? null;
  const identityBefore = await globalOf("identity");
  await call(client, "crow_update_context_section", { section_key: "identity", content: "I am the owner now" });
  assert.equal(await globalOf("identity"), identityBefore, "the global identity section is unchanged");
  const style = await call(client, "crow_update_context_section", { section_key: "writing_style", content: "x", project_id: A });
  assert.match(text(style), /only be changed by the operator/, text(style));

  const prefsAfter = (await db.execute({ sql: "SELECT value FROM dashboard_settings WHERE key = 'notification_prefs'", args: [] })).rows[0]?.value ?? null;
  assert.equal(prefsAfter, prefsBefore, "notification_prefs unchanged");
  assert.equal(Number((await db.execute({ sql: "SELECT COUNT(*) AS n FROM schedules", args: [] })).rows[0].n), schedulesBefore, "no schedule written");
}, { timeout: TEST_TIMEOUT });

/* ------------------------------------------------------------------ server factories */

test("the factories build only for an admitted request, with a frozen bot base actor", () => {
  assert.throws(() => M.doors.createMemoryBotServer({ caller: null }), /guard admitted/);
  assert.throws(() => M.doors.createProjectsBotServer({ caller: { doorScope: "memory-bot", botId: BOT } }), /guard admitted/,
    "a memory-door caller never builds the projects server");
  let seen = null;
  M.doors.createMemoryBotServer({ caller: { doorScope: "memory-bot", botId: BOT, threadId: "t-1" }, createServer: (_p, opts) => { seen = opts; return {}; } });
  assert.deepEqual({ ...seen.actor }, { kind: "bot", id: BOT, botSession: true });
  assert.equal(Object.isFrozen(seen.actor), true);
  assert.equal(seen.actorThread, "t-1");
  assert.equal(typeof seen.summaryAskerRank, "function");
});

test("a contained (relayed) bot gets no new egress through the projects door; a host-tier bot keeps it", async () => {
  let seen = null;
  const spy = (_p, opts) => { seen = opts; return {}; };
  const mine = async () => ({ ok: true });
  M.doors.createProjectsBotServer({ caller: { doorScope: "projects-bot", botId: BOT, relayed: true }, createServer: spy, fetchPage: mine, webSearch: mine });
  assert.notEqual(seen.fetchPage, mine);
  assert.notEqual(seen.webSearch, mine);
  const fetched = await seen.fetchPage("https://example.com/");
  assert.equal(fetched.ok, false);
  assert.equal((await seen.webSearch({ query: "x" })).ok, false);

  M.doors.createProjectsBotServer({ caller: { doorScope: "projects-bot", botId: BOT, relayed: false }, createServer: spy, fetchPage: mine, webSearch: mine });
  assert.equal(seen.fetchPage, mine);
  assert.equal(seen.webSearch, mine);
});

test("the summary-recall rank of an unverified bot is the cloud", async () => {
  let seen = null;
  M.doors.createMemoryBotServer({ caller: { doorScope: "memory-bot", botId: TAMPERED }, createServer: (_p, opts) => { seen = opts; return {}; } });
  assert.equal(await seen.summaryAskerRank({ kind: "bot", id: TAMPERED }), 2);
});

/* ----------------------------------------------------------------------- the catalog */

test("catalog: flag off → stdio as today; flag on + opt-in → HTTP door blocks; flag on without opt-in → stdio", async () => {
  const { writeBotMcp } = await import("../scripts/pi-bots/mcp_writer.mjs");
  const session = mkdtempSync(join(root, "session-"));
  const build = (def, env, crowHome = CROW_HOME) => writeBotMcp(def, {
    write: false, sessionDir: session, crowHome, canonical: { mcpServers: {} },
    botId: BOT, threadId: "perch-1", gatewayType: "perch", env,
  });
  const isStdio = (block) => !!(block && typeof block.command === "string" && !block.url);

  const off = build(DEF({ core_doors: true }), {});
  assert.ok(isStdio(off.json.mcpServers["crow-memory"]), "flag off: crow-memory is stdio");
  assert.ok(isStdio(off.json.mcpServers["crow-projects"]), "flag off: crow-projects is stdio");
  assert.equal(off.coreDoors, null);

  const on = build(DEF({ core_doors: true }), { CROW_BOT_CORE_DOORS: "1" });
  const mem = on.json.mcpServers["crow-memory"];
  const proj = on.json.mcpServers["crow-projects"];
  assert.match(mem.url, /^http:\/\/127\.0\.0\.1:\d+\/memory-bot\/mcp$/);
  assert.match(proj.url, /^http:\/\/127\.0\.0\.1:\d+\/projects-bot\/mcp$/);
  assert.equal(mem.command, undefined);
  assert.equal(mem.env, undefined, "a door block carries no env (no CROW_DB_PATH, no actor env)");
  assert.equal(mem.headers["X-Crow-Actor-Kind"], "memory");
  assert.equal(proj.headers["X-Crow-Actor-Kind"], "projects");
  assert.equal(mem.headers["X-Crow-Actor-Id"], BOT);
  assert.equal(mem.headers.Authorization, "Bearer " + readFileSync(M.tokens.MEMORY_BOT_TOKEN.path(), "utf8").trim());
  assert.equal(M.sig.verifyMemoryActorSig({ botId: BOT, threadId: "perch-1", gatewayType: "perch", sig: mem.headers["X-Crow-Actor-Sig"] }), true);
  assert.equal(M.sig.verifyProjectsActorSig({ botId: BOT, threadId: "perch-1", gatewayType: "perch", sig: proj.headers["X-Crow-Actor-Sig"] }), true);
  assert.equal(M.sig.verifyProjectsActorSig({ botId: BOT, threadId: "perch-1", gatewayType: "perch", sig: mem.headers["X-Crow-Actor-Sig"] }), false,
    "a memory signature is not a projects signature");
  assert.ok(on.servers.includes("crow-memory") && on.servers.includes("crow-projects"));
  assert.deepEqual(on.coreDoors.served.sort(), ["crow-memory", "crow-projects"]);
  assert.ok(!on.journalGuarded.includes("crow-memory"), "a door block touches no crow.db");

  const noOptIn = build(DEF(), { CROW_BOT_CORE_DOORS: "1" });
  assert.ok(isStdio(noOptIn.json.mcpServers["crow-memory"]), "flag on, no opt-in: stdio");
  assert.ok(isStdio(noOptIn.json.mcpServers["crow-projects"]));

  const notTrue = build(DEF({ core_doors: "true" }), { CROW_BOT_CORE_DOORS: "1" });
  assert.ok(isStdio(notTrue.json.mcpServers["crow-memory"]), "only the boolean true opts in");

  // Flag on + opt-in on an instance whose doors have no token yet: stdio, and the writer says why.
  const bare = mkdtempSync(join(root, "bare-home-"));
  const fallback = build(DEF({ core_doors: true }), { CROW_BOT_CORE_DOORS: "1" }, bare);
  assert.ok(isStdio(fallback.json.mcpServers["crow-memory"]));
  assert.ok(fallback.warnings.some((w) => /crow-memory.*stdio child.*core door/.test(w)), fallback.warnings.join("\n"));
}, { timeout: TEST_TIMEOUT });

test("the door paths are bot doors, the owner paths are not, and the writer allows the door urls", async () => {
  const { isDoorPath } = M.botDoors;
  const { isOwnerProjectUrl } = await import("../scripts/pi-bots/mcp_writer.mjs");
  for (const p of ["/memory-bot/mcp", "/projects-bot/mcp"]) {
    assert.equal(isDoorPath(p), true, p);
    assert.equal(isOwnerProjectUrl("http://127.0.0.1:3001" + p), false, p);
  }
  for (const p of ["/memory/mcp", "/projects/mcp"]) {
    assert.equal(isDoorPath(p), false, p);
    assert.equal(isOwnerProjectUrl("http://127.0.0.1:3001" + p), true, p);
  }
  const { ACTOR_SIGN_KINDS } = await import("../servers/gateway/routes/actor-sign.js");
  assert.ok(ACTOR_SIGN_KINDS.includes("memory") && ACTOR_SIGN_KINDS.includes("projects"));
});

test("flag off: the core doors are not mounted at all (the boot step throws before mounting)", async () => {
  const fs = await import("node:fs");
  const src = fs.readFileSync(new URL("../servers/gateway/boot/mcp-mounts.js", import.meta.url), "utf8");
  const flagAt = src.indexOf("coreDoorsFlagOn()");
  const mountAt = src.indexOf('app.use("/memory-bot"');
  assert.ok(flagAt > 0 && flagAt < mountAt, "the flag is checked before either door mounts");
  const { coreDoorsFlagOn } = await import("../servers/shared/core-doors-flag.js");
  assert.equal(coreDoorsFlagOn({}), false);
  assert.equal(coreDoorsFlagOn({ CROW_BOT_CORE_DOORS: "1" }), true);
});
