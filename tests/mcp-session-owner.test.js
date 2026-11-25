/**
 * Session ownership in routes/mcp.js is keyed on the OAuth client (req.auth.clientId), not the
 * connection: a connector that continues its session from a NEW TCP connection keeps working, a
 * different client sees the same answer as an unknown session id, and an owner-less mount is unchanged.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

const FETCH_TIMEOUT = 10_000;
const ACCEPT = "application/json, text/event-stream";
const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "0" } } };
const LIST = { jsonrpc: "2.0", id: 2, method: "tools/list" };
const PING = { jsonrpc: "2.0", id: 3, method: "ping" };

let server, port, manager;

/** One request on its own socket (agent:false), no content-length on GET/DELETE. */
function raw(path, { method = "POST", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const data = method === "POST" ? JSON.stringify(body ?? PING) : undefined;
    const req = http.request({ host: "127.0.0.1", port, path, method, agent: false, timeout: FETCH_TIMEOUT,
      headers: { "content-type": "application/json", accept: ACCEPT, ...(data ? { "content-length": Buffer.byteLength(data) } : {}), ...headers } },
    (res) => { let b = ""; res.on("data", (d) => { b += d; }); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: b })); });
    req.on("error", reject);
    req.end(data);
  });
}

function openSse(path, headers) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path, headers, agent: false }, (res) => {
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

const as = (clientId) => ({ "x-test-client": clientId });
const open = async (path, headers) => {
  const r = await raw(path, { headers, body: INIT });
  assert.equal(r.status, 200);
  assert.ok(r.headers["mcp-session-id"]);
  return r.headers["mcp-session-id"];
};

before(async () => {
  const express = (await import("express")).default;
  const { mountMcpServer } = await import("../servers/gateway/routes/mcp.js");
  const { SessionManager } = await import("../servers/gateway/session-manager.js");
  const { McpServer } = await import("@modelcontextprotocol/sdk/server/mcp.js");
  const app = express();
  app.use(express.json());
  manager = new SessionManager();
  const factory = () => { const s = new McpServer({ name: "t", version: "0" }); s.tool("noop", "noop", async () => ({ content: [{ type: "text", text: "ok" }] })); return s; };
  const opts = { callerFor: () => ({ caller: null, peer: false, crossHost: false }) };
  const stub = (req, res, next) => { req.auth = { clientId: req.headers["x-test-client"] || null, scopes: [] }; next(); };
  mountMcpServer(app, "/own", factory, manager, stub, async () => true, opts);
  mountMcpServer(app, "/open", factory, manager, (q, r, n) => n(), async () => true, opts);
  server = await new Promise((resolve) => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  port = server.address().port;
});

after(async () => {
  try { await manager?.closeAll(); } catch { /* ignore */ }
  try { server?.closeAllConnections?.(); } catch { /* ignore */ }
  await new Promise((resolve) => { try { server.close(resolve); } catch { resolve(); } setTimeout(resolve, 2000).unref?.(); });
});

test("the same client continues a streamable session from a new connection", async () => {
  const sid = await open("/own/mcp", as("connector-A"));
  const r = await raw("/own/mcp", { headers: { ...as("connector-A"), "mcp-session-id": sid }, body: LIST });
  assert.equal(r.status, 200);
  assert.match(r.body, /noop/);
});

test("the same client posts to its SSE session from a new connection", async () => {
  const sse = await openSse("/own/sse", as("connector-A"));
  try {
    const r = await raw(`/own/messages?sessionId=${sse.sessionId}`, { headers: as("connector-A"), body: PING });
    assert.equal(r.status, 202);
  } finally { sse.close(); }
});

test("a different client gets the unknown-session answer on every path", async () => {
  const sid = await open("/own/mcp", as("connector-A"));
  for (const method of ["POST", "GET", "DELETE"]) {
    const other = await raw("/own/mcp", { method, headers: { ...as("connector-B"), "mcp-session-id": sid } });
    const unknown = await raw("/own/mcp", { method, headers: { ...as("connector-B"), "mcp-session-id": "nope" } });
    assert.equal(other.status, unknown.status, method);
    assert.equal(other.body, unknown.body, method);
    assert.equal(other.status, 400, method);
  }
  const sse = await openSse("/own/sse", as("connector-A"));
  try {
    const other = await raw(`/own/messages?sessionId=${sse.sessionId}`, { headers: as("connector-B") });
    const unknown = await raw("/own/messages?sessionId=nope", { headers: as("connector-B") });
    assert.equal(other.status, unknown.status);
    assert.equal(other.body, unknown.body);
    assert.equal(other.status, 400);
  } finally { sse.close(); }
  // A's session survived B's attempts (including the DELETE).
  assert.equal((await raw("/own/mcp", { headers: { ...as("connector-A"), "mcp-session-id": sid }, body: LIST })).status, 200);
});

test("an owner-less mount continues a session from a new connection", async () => {
  const sid = await open("/open/mcp", {});
  const r = await raw("/open/mcp", { headers: { "mcp-session-id": sid }, body: LIST });
  assert.equal(r.status, 200);
  const sse = await openSse("/open/sse", {});
  try { assert.equal((await raw(`/open/messages?sessionId=${sse.sessionId}`, { body: PING })).status, 202); } finally { sse.close(); }
});
