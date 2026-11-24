/**
 * A contained bot never authenticates as the owner through OAuth or a dashboard
 * session.
 *
 * The hole this closes: a contained bot's only path to its gateway is the egress
 * relay, and every socket the relay opens is bound to `RELAY_SOURCE_V4`
 * (`servers/shared/bot-doors.js`), so the gateway can recognise it. The doors
 * already refuse the operator's FULL local token on such a socket
 * (`localTokenAuthMiddleware`, tests/local-token-relayed.test.js) because crow.db
 * is bound read-write into the bot. The OAuth fallback had no such check: a bot
 * could write its own `oauth_tokens` row and present it as `Bearer <token>` on
 * /board/mcp, /phone/mcp or /artifacts/mcp, and every mount OAuth admits calls
 * the caller the owner (`routes/mcp.js` callerFor → "owner-remote" → the board,
 * phone and artifacts guards resolve the owner actor).
 *
 * The fix lives in ONE place every OAuth fallback passes through —
 * `createBearerAuthMiddleware` (servers/gateway/bearer-auth.js), the instance
 * servers/gateway/index.js builds and hands to every mount — plus the two
 * session-cookie readers in dashboard/auth.js (dashboardAuth, sessionFromRequest)
 * and the login gate. Nothing here is per-mount.
 *
 * Real sockets, real DB, real tokens: the client binds the relay mark with
 * `localAddress`, exactly how the relay marks its upstream connections
 * (tests/internal-guard.test.js's pattern); the token is a real row in a real
 * `oauth_tokens` table verified by the real CrowOAuthProvider.verifyAccessToken;
 * the mounts are real mountMcpServer mounts (the tool surface is a stub — the
 * AUTH BOUNDARY is what is under test, as in tests/board-mcp.test.js's /memory
 * mount).
 *
 * Non-relayed behaviour is asserted in the same file: the same token from plain
 * loopback still opens every mount, a door token still opens its own mount from
 * a relayed socket, and a dashboard session still works from loopback.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { createBearerAuthMiddleware } from "../servers/gateway/bearer-auth.js";
import { createOAuthProvider, DASHBOARD_CLIENT_ID } from "../servers/gateway/auth.js";
import { localTokenAuthMiddleware } from "../servers/gateway/local-token.js";
import { mountMcpServer } from "../servers/gateway/routes/mcp.js";
import { SessionManager } from "../servers/gateway/session-manager.js";
import {
  dashboardAuth, sessionFromRequest, loginNetworkAllowed, hashToken,
} from "../servers/gateway/dashboard/auth.js";
import { RELAY_SOURCE_V4 } from "../servers/shared/bot-doors.js";
import { createDbClient } from "../servers/db.js";
import { writeSetting } from "../servers/gateway/dashboard/settings/registry.js";

const RELAY = RELAY_SOURCE_V4;          // the mark a relayed socket carries
const LOOPBACK = "127.0.0.1";

// The client_id a real OAuth client row carries; the token is a plain OAuth
// access token (never the 'dashboard' id, which verifyAccessToken excludes).
const OAUTH_CLIENT = "3f1a9d24-6b52-4c1e-9a77-2f0c5a1d8e34";
const OAUTH_TOKEN = "relay-test-oauth-access-token";
const BOGUS_TOKEN = "relay-test-not-a-real-token";
const BOARD_TOKEN = "relay-test-board-token";
const SESSION_TOKEN = "relay-test-dashboard-session";

const SAVED = {};
for (const k of ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH", "CROW_DASHBOARD_PUBLIC"]) SAVED[k] = process.env[k];

let root, dbPath, db, provider, server, port;

/** Every mount OAuth can admit: the three bot doors that resolve an owner actor,
 *  and two core mounts for contrast. */
const MOUNTS = ["/board/mcp", "/phone/mcp", "/artifacts/mcp", "/memory/mcp", "/router/mcp"];

before(async () => {
  root = mkdtempSync(join(tmpdir(), "oauth-relay-"));
  process.env.CROW_HOME = root;
  process.env.CROW_DATA_DIR = join(root, "data");
  dbPath = join(root, "crow.db");
  process.env.CROW_DB_PATH = dbPath;
  delete process.env.CROW_DASHBOARD_PUBLIC;

  // The tables these rails read. A real, separate .db file: the provider's
  // verifyAccessToken and the local-token settings reads are the production
  // ones, not stubs.
  const raw = new Database(dbPath);
  raw.exec(`
    CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY, metadata TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE oauth_tokens (token TEXT PRIMARY KEY, token_type TEXT NOT NULL, client_id TEXT NOT NULL,
      scopes TEXT DEFAULT '', resource TEXT, expires_at TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, event_type TEXT NOT NULL, actor TEXT,
      ip_address TEXT, details TEXT, created_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE dashboard_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT DEFAULT (datetime('now')));
    CREATE TABLE dashboard_settings_overrides (key TEXT NOT NULL, instance_id TEXT NOT NULL, value TEXT NOT NULL,
      updated_at TEXT DEFAULT (datetime('now')), lamport_ts INTEGER DEFAULT 0, PRIMARY KEY (key, instance_id));
    -- What a contained bot can do for itself: crow.db is bound read-write, so
    -- this row is one the bot writes.
    INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at, resource)
      VALUES ('${hashToken(OAUTH_TOKEN)}', 'access', '${OAUTH_CLIENT}', 'mcp:tools',
              datetime('now', '+3600 seconds'), NULL);
    -- A live dashboard session, the cookie half of the same test.
    INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at)
      VALUES ('${hashToken(SESSION_TOKEN)}', 'access', '${DASHBOARD_CLIENT_ID}', 'dashboard',
              datetime('now', '+3600 seconds'));
  `);
  raw.close();

  db = createDbClient(dbPath);
  // The path-scoped board token a relayed bot legitimately holds. Seeded the way the PRODUCT
  // writes it — a local-scope override (design OQ-8: a per-instance token key is never read from
  // the global `dashboard_settings` row, so a global fixture would now seed nothing).
  await writeSetting(db, "mcp_board_token_hash", hashToken(BOARD_TOKEN), { scope: "local" });
  provider = createOAuthProvider(dbPath);

  const authMiddleware = createBearerAuthMiddleware({
    verifier: { verifyAccessToken: (token) => provider.verifyAccessToken(token) },
    requiredScopes: [],
    resourceMetadataUrl: "https://crow.example.ts.net/.well-known/oauth-protected-resource",
  });

  const app = express();
  app.use(express.json());
  // servers/gateway/index.js's order: the local-token rail first, then the
  // mounts, each falling back to the ONE shared bearer middleware.
  app.use(localTokenAuthMiddleware(db));
  const sessionManager = new SessionManager();
  for (const mount of ["/board", "/phone", "/artifacts", "/memory", "/router"]) {
    mountMcpServer(app, mount, () => new McpServer({ name: `stub${mount}`, version: "0" }), sessionManager, authMiddleware);
  }
  // The dashboard's session rails (dashboardAuth on /dashboard/* and on the
  // /api/* JSON rails, as boot/feature-mounts.js mounts them). The paths are
  // stand-ins for the real routes; the middleware is the real one.
  app.get("/dashboard/attention", dashboardAuth, (req, res) => res.json({ ok: "dashboard", session: Boolean(req.dashboardSession) }));
  app.get("/api/models", dashboardAuth, (req, res) => res.json({ ok: "api", session: Boolean(req.dashboardSession) }));

  server = http.createServer(app);
  await new Promise((r) => server.listen(0, LOOPBACK, r));
  port = server.address().port;
});

after(async () => {
  server?.closeAllConnections?.();
  await new Promise((r) => (server ? server.close(() => r()) : r()));
  try { provider?.db.close(); } catch {}
  try { db?.close(); } catch {}
  try { rmSync(root, { recursive: true, force: true }); } catch {}
  for (const [k, v] of Object.entries(SAVED)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

const INITIALIZE = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "oauth-relay-test", version: "0" } },
};

function request(method, path, { localAddress = LOOPBACK, headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const data = body === null ? null : JSON.stringify(body);
    const req = http.request({
      host: LOOPBACK, port, path, method, localAddress,
      headers: {
        accept: "application/json, text/event-stream",
        ...(data === null ? {} : { "content-type": "application/json", "content-length": Buffer.byteLength(data) }),
        ...headers,
      },
    }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (d) => { text += d; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: text }));
    });
    req.on("error", reject);
    req.end(data ?? undefined);
  });
}

const mcpInit = (path, opts = {}) => request("POST", path, { body: INITIALIZE, ...opts });

test("the token is a real one: the real provider verifies it", async () => {
  // The precondition for everything below — verified by the real provider, not a
  // fake verifier, so "refused on a relayed socket" cannot be a bad-token artefact.
  const info = await provider.verifyAccessToken(OAUTH_TOKEN);
  assert.equal(info.clientId, OAUTH_CLIENT);
  assert.deepEqual(info.scopes, ["mcp:tools"]);
});

test("every mount refuses a valid OAuth token on a relayed socket", async () => {
  // The refusal a relayed socket already gets for the full local token: it is not
  // authenticated, so the OAuth verifier rejects it — 401, the SDK's
  // WWW-Authenticate header, {error:"invalid_token", error_description:"Invalid token"}.
  // Taken from the same middleware with a token that does not exist, so the two
  // answers are compared, not assumed.
  const reference = await mcpInit("/memory/mcp", { headers: { authorization: `Bearer ${BOGUS_TOKEN}` } });
  assert.equal(reference.status, 401, "an unknown token is a 401 (the local-token relay refusal)");
  assert.match(String(reference.headers["www-authenticate"] || ""), /^Bearer error="invalid_token"/);

  for (const path of MOUNTS) {
    const r = await mcpInit(path, { localAddress: RELAY, headers: { authorization: `Bearer ${OAUTH_TOKEN}` } });
    assert.equal(r.status, 401, `${path}: a valid OAuth token is refused on a relayed socket`);
    assert.equal(r.body, reference.body, `${path}: same body as the local-token relay refusal`);
    assert.equal(r.headers["www-authenticate"], reference.headers["www-authenticate"], `${path}: same challenge`);
  }
});

test("the same token from plain loopback still authenticates every mount (unchanged)", async () => {
  for (const path of MOUNTS) {
    const r = await mcpInit(path, { headers: { authorization: `Bearer ${OAUTH_TOKEN}` } });
    assert.equal(r.status, 200, `${path}: non-relayed OAuth callers are untouched`);
    assert.match(r.body, /"serverInfo"/, `${path}: the real MCP initialize answered`);
  }
});

test("a relayed socket still reaches its own door with the path-scoped board token", async () => {
  const r = await mcpInit("/board/mcp", { localAddress: RELAY, headers: { authorization: `Bearer ${BOARD_TOKEN}` } });
  assert.equal(r.status, 200, "the board token is how a contained bot legitimately calls /board/mcp");
});

test("the path-scoped board token still opens nothing else", async () => {
  const r = await mcpInit("/memory/mcp", { localAddress: RELAY, headers: { authorization: `Bearer ${BOARD_TOKEN}` } });
  assert.equal(r.status, 401, "the board token stays path-scoped");
});

test("a dashboard session cookie on a relayed socket is refused for /dashboard and /api", async () => {
  const cookie = { cookie: `crow_session=${SESSION_TOKEN}` };
  // CROW_DASHBOARD_PUBLIC opens the network gate for EVERY caller, which is the
  // shape the mark's own check must survive: the relay mark is about the socket,
  // not about the network policy.
  const saved = process.env.CROW_DASHBOARD_PUBLIC;
  process.env.CROW_DASHBOARD_PUBLIC = "true";
  try {
    for (const path of ["/dashboard/attention", "/api/models"]) {
      const ok = await request("GET", path, { headers: cookie });
      assert.equal(ok.status, 200, `${path}: the live session still works from loopback`);
      assert.deepEqual(JSON.parse(ok.body), { ok: path.startsWith("/api") ? "api" : "dashboard", session: true });

      const refused = await request("GET", path, { localAddress: RELAY, headers: cookie });
      assert.equal(refused.status, 403, `${path}: a relayed socket with a session cookie is refused`);
      assert.doesNotMatch(refused.body, /"ok"/, `${path}: the handler never ran`);
    }
  } finally {
    if (saved === undefined) delete process.env.CROW_DASHBOARD_PUBLIC; else process.env.CROW_DASHBOARD_PUBLIC = saved;
  }
});

test("sessionFromRequest hands a relayed socket no session, and an unchanged one to loopback", async () => {
  const req = (localAddress) => ({ socket: { remoteAddress: localAddress }, headers: { cookie: `crow_session=${SESSION_TOKEN}` } });
  // The network gate is opened for this test (CROW_DASHBOARD_PUBLIC) so the only
  // difference between the two calls is the socket's mark.
  const saved = process.env.CROW_DASHBOARD_PUBLIC;
  process.env.CROW_DASHBOARD_PUBLIC = "true";
  try {
    assert.equal(await sessionFromRequest(req(LOOPBACK)), SESSION_TOKEN, "a loopback session is still a session");
    assert.equal(await sessionFromRequest(req(RELAY)), null, "a relayed socket never has one");
    const v4mapped = await sessionFromRequest({ socket: { remoteAddress: "::ffff:" + RELAY }, headers: { cookie: `crow_session=${SESSION_TOKEN}` } });
    assert.equal(v4mapped, null, "the v4-mapped spelling of the mark too");
  } finally {
    if (saved === undefined) delete process.env.CROW_DASHBOARD_PUBLIC; else process.env.CROW_DASHBOARD_PUBLIC = saved;
  }
});

test("a relayed socket may not sign in either (crow.db holds the password hash)", () => {
  const req = (localAddress) => ({ socket: { remoteAddress: localAddress }, headers: {} });
  assert.equal(loginNetworkAllowed(req(LOOPBACK)), true, "the owner at this machine's console is unchanged");
  assert.equal(loginNetworkAllowed(req(RELAY)), false, "the relay's mark is never a password entry point");
  assert.equal(loginNetworkAllowed(req("::ffff:" + RELAY)), false);
});