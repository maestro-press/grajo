/**
 * THE MEMORY SERVER'S OWN OUTBOUND CALLS (class 1 of the confused-deputy fix).
 *
 * `servers/memory/embeddings.js` and `servers/memory/rerank.js` run in the
 * memory MCP server — a SEPARATE process — and they read `providers` rows
 * (`base_url`, `api_key`), which a contained bot can write because crow.db is
 * bound read-write into its sandbox. They then POST with the row's
 * `Authorization`. That is the same shape the gateway's own forward paths close
 * (models/self-target.js + ai/adapter-guard.js), so they go through the SAME
 * guard, not a second copy of the rules:
 *
 *   - a forbidden target (IPv4/IPv6 link-local, cloud metadata) is refused for
 *     every caller — an IP literal had never been judged before;
 *   - an own-host target is allowed only at the operations these clients send
 *     (`/v1/embeddings`, `/v1/rerank`, and the health probe's `/v1/models`), and
 *     NEVER receives the row's key;
 *   - a rebindable DNS name is resolved ONCE and the socket is pinned to the
 *     vetted answer.
 *
 * Real loopback listeners and a real temp DB (never the live one).
 */
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Readable } from "node:stream";
import { isIP } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "memory-target-guard-"));
const dbPath = join(dir, "crow.db");
const saved = {};
for (const k of ["CROW_DB_PATH", "CROW_MODELS_JSON", "CROW_EMBED_PROVIDER", "CROW_RERANK_PROVIDER"]) saved[k] = process.env[k];
process.env.CROW_DB_PATH = dbPath;
process.env.CROW_MODELS_JSON = "";   // hermetic: never the real models.json

let createDbClient;
let embedText, embedProviderInfo;
let rerank;

const servers = [];
const hits = [];
after(async () => {
  for (const s of servers) {
    try { s.closeAllConnections?.(); } catch { /* already gone */ }
    await new Promise((r) => s.close(() => r()));
  }
  for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  rmSync(dir, { recursive: true, force: true });
});

/** A real HTTP listener on loopback that records every request it sees. */
async function listen(handler) {
  const server = http.createServer((req, res) => {
    const rec = { method: req.method, path: req.url, headers: req.headers, body: "" };
    req.on("data", (c) => { rec.body += c.toString("utf8"); });
    req.on("end", () => { hits.push(rec); handler(req, res, rec); });
  });
  servers.push(server);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return { port, base: `http://127.0.0.1:${port}` };
}

/** One providers row, as a bot would write it. */
async function seedProvider(id, { baseUrl, apiKey = null, task = "embed" }) {
  const db = createDbClient();
  try {
    await db.execute("CREATE TABLE IF NOT EXISTS providers (id TEXT PRIMARY KEY, base_url TEXT, api_key TEXT, models TEXT, gpu_policy TEXT, disabled INTEGER DEFAULT 0)");
    await db.execute({ sql: "DELETE FROM providers WHERE id = ?", args: [id] });
    await db.execute({
      sql: "INSERT INTO providers (id, base_url, api_key, models, disabled) VALUES (?, ?, ?, ?, 0)",
      args: [id, baseUrl, apiKey, JSON.stringify([{ id: `m-${id}`, task }])],
    });
  } finally { db.close?.(); }
}

/** A resolver whose answers are scripted per call; `calls` records every ask. */
function fakeLookup(answers) {
  const calls = [];
  const fn = (host, options, cb) => {
    if (typeof options === "function") { cb = options; options = {}; }
    const list = answers[Math.min(calls.length, answers.length - 1)] || [];
    calls.push(host);
    if (!list.length) return cb(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
    const mapped = list.map((address) => ({ address, family: isIP(address) }));
    if (options && options.all) return cb(null, mapped);
    return cb(null, mapped[0].address, mapped[0].family);
  };
  fn.calls = calls;
  return fn;
}

/** The address a pinned transport was told to connect to (round A's trick). */
const pinnedRequest = (payload, calls) => async (url, opts) => {
  const looked = await new Promise((resolve, reject) => {
    opts.lookupFn(new URL(url).hostname, { all: true }, (e, a) => (e ? reject(e) : resolve(a)));
  });
  calls.push({ url, looked, headers: opts.headers });
  return {
    status: 200,
    headers: { "content-type": "application/json" },
    stream: Readable.from([Buffer.from(JSON.stringify(payload))]),
    deadline: Date.now() + 5000,
  };
};

before(async () => {
  ({ createDbClient } = await import("../servers/db.js"));
  ({ embedText, embedProviderInfo } = await import("../servers/memory/embeddings.js"));
  ({ rerank } = await import("../servers/memory/rerank.js"));
});

beforeEach(() => { hits.length = 0; });

// ---------------------------------------------------------------------------
// An own-host embedding / rerank / models endpoint still works, with no key.
// ---------------------------------------------------------------------------

test("an own-host embedding server is dialled at /v1/embeddings and never sees the row's key", async () => {
  const s = await listen((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ data: [{ embedding: [0.25, 0.5] }] }));
  });
  await seedProvider("own-embed", { baseUrl: `${s.base}/v1`, apiKey: "row-key-must-not-travel" });
  const vec = await embedText("hello", { providerName: "own-embed" });
  assert.deepEqual([...vec], [0.25, 0.5]);
  assert.deepEqual(hits.map((h) => `${h.method} ${h.path}`), ["POST /v1/embeddings"]);
  assert.equal(hits[0].headers.authorization, undefined, "no provider key rides a request that lands on this box");
});

test("an own-host reranker is dialled at /v1/rerank and never sees the row's key", async () => {
  const s = await listen((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ results: [{ index: 1, relevance_score: 0.9 }, { index: 0, relevance_score: 0.1 }] }));
  });
  await seedProvider("own-rerank", { baseUrl: `${s.base}/v1`, apiKey: "row-key-must-not-travel", task: "rerank" });
  const out = await rerank("q", [{ id: 1, text: "a" }, { id: 2, text: "b" }], { topK: 2, providerName: "own-rerank" });
  assert.deepEqual(out.map((c) => c.id), [2, 1]);
  assert.deepEqual(hits.map((h) => `${h.method} ${h.path}`), ["POST /v1/rerank"]);
  assert.equal(hits[0].headers.authorization, undefined);
});

test("the embedding health probe may read /v1/models on this box, and still sends no key", async () => {
  const s = await listen((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ data: [{ id: "bge-m3" }] }));
  });
  await seedProvider("own-embed-info", { baseUrl: `${s.base}/v1`, apiKey: "row-key-must-not-travel" });
  const info = await embedProviderInfo("own-embed-info");
  assert.equal(info.ok, true, JSON.stringify(info));
  assert.equal(info.model, "bge-m3");
  assert.deepEqual(hits.map((h) => `${h.method} ${h.path}`), ["GET /v1/models"]);
  assert.equal(hits[0].headers.authorization, undefined);
});

// ---------------------------------------------------------------------------
// The two refusals: a forbidden address, and an own-host path that is not one
// of these clients' operations. Neither opens a socket.
// ---------------------------------------------------------------------------

test("a bot-written embedding row pointing at cloud metadata is refused and nothing is dialled", async () => {
  await seedProvider("meta-embed", { baseUrl: "http://169.254.169.254/v1", apiKey: "row-key" });
  const origFetch = globalThis.fetch;
  const dialled = [];
  globalThis.fetch = async (url) => { dialled.push(String(url)); throw new Error("dialled"); };
  try {
    await assert.rejects(() => embedText("hello", { providerName: "meta-embed" }), (e) => e.code === "SELF_TARGET_REFUSED");
  } finally { globalThis.fetch = origFetch; }
  assert.deepEqual(dialled, []);
});

test("a bot-written row pointing at an own-host route that is not an embed/rerank call is refused", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end("{}"); });
  await seedProvider("attack-embed", { baseUrl: `${s.base}/llm/acquire?x=`, apiKey: "row-key" });
  await assert.rejects(() => embedText("hello", { providerName: "attack-embed" }), (e) => e.code === "SELF_TARGET_REFUSED");
  // rerank never throws on a provider failure: it falls back to the input order.
  const out = await rerank("q", [{ id: 1, text: "a" }, { id: 2, text: "b" }], { topK: 2, providerName: "attack-embed" });
  assert.deepEqual(out.map((c) => c.id), [1, 2]);
  assert.equal(out[0].relevance, undefined, "no reranker answer was used");
  assert.deepEqual(hits, [], "the model lifecycle route was never reached");
});

// ---------------------------------------------------------------------------
// A rebindable name: one resolution, pinned; the loopback rebind is never used.
// ---------------------------------------------------------------------------

test("a rebindable embedding host is resolved ONCE and pinned to the vetted address", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end("{}"); });
  const lookupFn = fakeLookup([["203.0.113.40"], ["127.0.0.1"]]);
  const calls = [];
  await seedProvider("rebind-embed", { baseUrl: `http://rebind.example.test:${s.port}/v1`, apiKey: "row-key" });
  const vec = await embedText("hello", {
    providerName: "rebind-embed",
    guard: { lookupFn, requestFn: pinnedRequest({ data: [{ embedding: [1, 0] }] }, calls) },
  });
  assert.deepEqual([...vec], [1, 0]);
  assert.equal(lookupFn.calls.length, 1, "the name was resolved exactly once");
  assert.deepEqual(calls[0].looked.map((a) => a.address), ["203.0.113.40"], "the socket was given only the vetted answer");
  assert.equal(calls[0].headers.Authorization, "Bearer row-key", "a pinned public host keeps its key");
  assert.deepEqual(hits, [], "the loopback listener (the rebind target) was never reached");
});

test("a rebindable host that answers with THIS box is refused for embeddings, and nothing is dialled", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end("{}"); });
  const lookupFn = fakeLookup([["127.0.0.1"]]);
  const calls = [];
  await seedProvider("rebind-own", { baseUrl: `http://rebind.example.test:${s.port}/v1`, apiKey: "row-key" });
  await assert.rejects(
    () => embedText("hello", { providerName: "rebind-own", guard: { lookupFn, requestFn: pinnedRequest({ data: [] }, calls) } }),
    (e) => e.code === "SELF_TARGET_REFUSED",
  );
  assert.deepEqual(calls, []);
  assert.deepEqual(hits, []);
});