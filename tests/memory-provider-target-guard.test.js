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

import { isKnownLocalModelTarget } from "../servers/gateway/models/local-model-servers.js";
import { spawnUntrustedListener } from "./fixtures/untrusted-listener.mjs";

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

// ---------------------------------------------------------------------------
// THE LISTENER HALF, from this process: /v1/embeddings on an own-host port is
// only a model server when something outside crow.db vouches the port AND the
// process holding the LISTEN socket is not a bot (models/local-model-servers.js).
// A contained bot shares the host network and can write this very row, then
// listen on the port itself with a relay — so "loopback, /v1/embeddings" alone
// must never be enough.
//
// Red-first: the bot's listener is a real HTTP server in a SEPARATE process of
// the same uid (tests/fixtures/untrusted-listener.mjs), and a control request
// proves it is alive after the refusals.
// ---------------------------------------------------------------------------

test("RED FIRST: the bot's own listener on an own-host port receives nothing from embedText, vouched or not", async () => {
  const bot = await spawnUntrustedListener();
  const home = join(dir, "empty-home");
  try {
    await seedProvider("squat-embed", { baseUrl: `http://127.0.0.1:${bot.port}/v1`, apiKey: "row-key-must-not-travel" });
    // Nothing vouches the port: refused before any listener is even considered.
    await assert.rejects(
      () => embedText("the owner's private notes", { providerName: "squat-embed", guard: { knownLocalTargetFn: (url) => isKnownLocalModelTarget(url, { crowHome: home }) } }),
      (e) => e.code === "SELF_TARGET_REFUSED",
    );
    // ... and when a Docker publish DOES vouch the port (the model container's own
    // port, the squat), the socket's owner decides: it is not a process Crow
    // started, so it is refused too.
    await assert.rejects(
      () => embedText("the owner's private notes", {
        providerName: "squat-embed",
        guard: { knownLocalTargetFn: (url) => isKnownLocalModelTarget(url, { crowHome: home, dockerEntries: [{ address: "127.0.0.1", port: bot.port }] }) },
      }),
      (e) => e.code === "SELF_TARGET_REFUSED",
    );
    // SECURITY: a bounded window plus the fixture's own sync round-trip, so a
    // late-arriving hit is SEEN rather than missed — the security half never passes
    // by asserting too early (L2).
    await bot.settle();
    assert.deepEqual(bot.hits, [], `SECURITY: bot received bytes: ${JSON.stringify(bot.hits)}`);
    assert.deepEqual(hits, [], `SECURITY: an in-process fixture received bytes: ${JSON.stringify(hits)}`);

    // CONTROL: the listener is reachable, so this is the refusal and not a dead fixture.
    await bot.control({ method: "POST", path: "/v1/embeddings" });
    assert.deepEqual(bot.hits, ["POST /v1/embeddings"], `CONTROL: bot liveness probe not observed (${JSON.stringify(bot.hits)})`);
  } finally {
    await bot.close();
  }
});

// ---------------------------------------------------------------------------
// THE JUDGED ADDRESS IS THE DIALED ADDRESS (memory half). A NAME stands for
// several addresses (`localhost` is 127.0.0.1 AND ::1), the vouch is asked about
// ONE of them, and the request must go to THAT one — not to whatever a second
// resolution of the name would answer. Red-first: the resolver answers ::1 first
// and 127.0.0.1 second, a TRUSTED listener (this process) holds [::1]:P and an
// UNTRUSTED one (a separate process of the same uid) holds 127.0.0.1:P.
// ---------------------------------------------------------------------------

/** A TRUSTED listener on [::1] (this process holds the socket), answering an
 * embedding request. `null` when this box has no IPv6 loopback. */
async function trustedLoopback6() {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method, path: req.url, authorization: req.headers.authorization || null });
    req.on("data", () => {});
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: [{ embedding: [0.5, 0.25] }] }));
    });
  });
  const listening = await new Promise((resolve) => {
    server.once("error", () => resolve(false));
    server.listen(0, "::1", () => resolve(true));
  });
  if (!listening) { try { server.close(); } catch { /* never bound */ } return null; }
  return {
    port: server.address().port,
    seen,
    close: () => new Promise((r) => { try { server.closeAllConnections?.(); } catch { /* gone */ } server.close(() => r()); }),
  };
}

/** The own-host vouch with this box's real /proc, a Docker publish vouching the
 * port (so the LISTENER half decides) and the caller's ONE dial address. */
const vouchAt = (home, port) => (url, dialAddresses) => isKnownLocalModelTarget(url, {
  crowHome: home, dockerEntries: [{ address: null, port }], dialAddresses,
});

test("RED FIRST: an embedding row naming localhost is dialled on the address the vouch judged (::1), never on the bot's 127.0.0.1 of the same port", async (t) => {
  const trusted = await trustedLoopback6();
  if (!trusted) return t.skip("this box has no [::1] loopback to listen on");
  const port = trusted.port;
  const bot = await spawnUntrustedListener({ address: "127.0.0.1", port });
  const home = join(dir, "dial-home");
  try {
    await seedProvider("dial-embed", { baseUrl: `http://localhost:${port}/v1`, apiKey: "row-key-must-not-travel" });
    const lookupFn = fakeLookup([["::1"], ["127.0.0.1"]]);
    const vec = await embedText("hello", {
      providerName: "dial-embed",
      guard: { lookupFn, knownLocalTargetFn: vouchAt(home, port) },
    });
    assert.deepEqual([...vec], [0.5, 0.25], "the trusted ::1 listener answered");
    assert.deepEqual(trusted.seen.map((h) => `${h.method} ${h.path}`), ["POST /v1/embeddings"]);
    assert.equal(trusted.seen[0].authorization, null, "an own-host target never carries the row's key");
    await bot.settle();
    assert.deepEqual(bot.hits, [], `SECURITY: the bot's 127.0.0.1 socket on the SAME port received bytes: ${JSON.stringify(bot.hits)}`);
    assert.equal(lookupFn.calls.length, 1, "the name was resolved exactly once: the judged address is the dialed one");

    // REVERSE: the same name answering 127.0.0.1 first. The judged address is the
    // bot's, so the row is refused — a trusted socket on ::1 of the same port does
    // not vouch it.
    const before = trusted.seen.length;
    const reverse = fakeLookup([["127.0.0.1"], ["::1"]]);
    await assert.rejects(
      () => embedText("the owner's private notes", { providerName: "dial-embed", guard: { lookupFn: reverse, knownLocalTargetFn: vouchAt(home, port) } }),
      (e) => e.code === "SELF_TARGET_REFUSED",
    );
    assert.equal(reverse.calls.length, 1);
    await bot.settle();
    assert.deepEqual(bot.hits, [], `SECURITY: nothing reached the bot: ${JSON.stringify(bot.hits)}`);
    assert.equal(trusted.seen.length, before, "and the trusted ::1 socket was not dialled either");

    // CONTROL: the bot's listener is alive and reachable from this process.
    await bot.control({ method: "POST", path: "/v1/embeddings" });
    assert.deepEqual(bot.hits, ["POST /v1/embeddings"], `CONTROL: bot liveness probe not observed (${JSON.stringify(bot.hits)})`);
  } finally {
    await bot.close();
    await trusted.close();
  }
});

// ---------------------------------------------------------------------------
// One refusal is ONE log line: a security refusal is never retried. `embedText`
// retries a transient transport failure once; retrying `SELF_TARGET_REFUSED` would
// repeat a decision that cannot change and print the door's line twice.
// ---------------------------------------------------------------------------

test("a refused embedText logs exactly one line (no retry of a security refusal), and rerank degrades with one line", async () => {
  const bot = await spawnUntrustedListener();
  // An empty home: nothing vouches the bot's port, so the guard refuses it and
  // prints its one line per call.
  const home = join(dir, "one-line-home");
  try {
    await seedProvider("one-line-embed", { baseUrl: `http://127.0.0.1:${bot.port}/v1`, apiKey: "row-key-must-not-travel" });
    const lines = [];
    const guard = { knownLocalTargetFn: (url) => isKnownLocalModelTarget(url, { crowHome: home }), logFn: (l) => lines.push(l), providerId: "one-line-embed" };
    await assert.rejects(
      () => embedText("the owner's private notes", { providerName: "one-line-embed", guard }),
      (e) => e.code === "SELF_TARGET_REFUSED",
    );
    assert.equal(lines.length, 1, `one call is one line:\n${lines.join("\n")}`);

    const out = await rerank("q", [{ id: 1, text: "a" }, { id: 2, text: "b" }], { topK: 2, providerName: "one-line-embed", guard });
    assert.deepEqual(out.map((c) => c.id), [1, 2], "the reranker degrades to the input order");
    assert.equal(lines.length, 2, `one rerank call is one more line:\n${lines.join("\n")}`);
    await bot.settle();
    assert.deepEqual(bot.hits, [], `SECURITY: neither call reached the bot's listener: ${JSON.stringify(bot.hits)}`);
  } finally {
    await bot.close();
  }
});