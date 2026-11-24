/**
 * THE OPERATOR'S HEALTH MATRIX (class 4 of the confused-deputy fix).
 *
 * `servers/shared/providers.js` `probeProvider` runs from the dashboard
 * ("Test" on the Models page and the health tab) and reads the same
 * bot-writable `providers` row: it GETs `${base_url}/models` WITH the row's
 * `api_key`. So it goes through the same guard as every other request-time
 * read of that row:
 *
 *   - a forbidden target (link-local / cloud metadata) is refused;
 *   - an own-host target is allowed only at `/v1/models` (the one operation a
 *     probe sends) and NEVER receives the row's key;
 *   - a rebindable DNS name is resolved once and pinned.
 *
 * A refused probe is an ordinary `{ ok: false, error }` — the matrix keeps
 * working, one provider just reads as unreachable.
 */
import { test, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Readable } from "node:stream";
import { isIP } from "node:net";

import { probeProvider } from "../servers/shared/providers.js";

const servers = [];
const hits = [];
after(async () => {
  for (const s of servers) {
    try { s.closeAllConnections?.(); } catch { /* already gone */ }
    await new Promise((r) => s.close(() => r()));
  }
});

async function listen(handler) {
  const server = http.createServer((req, res) => {
    hits.push({ method: req.method, path: req.url, headers: req.headers });
    handler(req, res);
  });
  servers.push(server);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return { port, base: `http://127.0.0.1:${port}` };
}

beforeEach(() => { hits.length = 0; });

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

test("an own-host provider is probed at /v1/models and never sees the row's key", async () => {
  const s = await listen((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ data: [{ id: "crow-local-27b" }] }));
  });
  const r = await probeProvider("crow-local", { baseUrl: `${s.base}/v1`, apiKey: "row-key-must-not-travel", host: "local" });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(r.models, ["crow-local-27b"]);
  assert.deepEqual(hits.map((h) => `${h.method} ${h.path}`), ["GET /v1/models"]);
  assert.equal(hits[0].headers.authorization, undefined, "no provider key rides a probe that lands on this box");
});

test("a bot-written row pointing at an own-host route that is not /v1/models is refused, and nothing is dialled", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end("{}"); });
  for (const baseUrl of [`${s.base}/llm/acquire?x=`, `${s.base}/llm/models/m/start`]) {
    const r = await probeProvider("bot-written", { baseUrl, apiKey: "row-key", host: "local" });
    assert.equal(r.ok, false, JSON.stringify(r));
    assert.match(String(r.error), /Crow will not contact that address/);
  }
  assert.deepEqual(hits, [], "the model lifecycle routes were never reached");
});

test("a provider row pointing at cloud metadata is refused and nothing is dialled", async () => {
  const dialled = [];
  const r = await probeProvider("meta", { baseUrl: "http://169.254.169.254/v1", apiKey: "row-key" }, {
    guard: { fetchFn: async (url) => { dialled.push(String(url)); throw new Error("dialled"); } },
  });
  assert.equal(r.ok, false, JSON.stringify(r));
  assert.match(String(r.error), /Crow will not contact that address/);
  assert.deepEqual(dialled, []);
});

test("a rebindable provider name is resolved ONCE and pinned to the vetted address, keeping its key", async () => {
  const lookupFn = fakeLookup([["203.0.113.60"], ["127.0.0.1"]]); // public, then the rebind
  const calls = [];
  const r = await probeProvider("cloud-row", { baseUrl: "https://api.example.test/v1", apiKey: "cloud-key", host: "cloud" }, {
    guard: { lookupFn, requestFn: pinnedRequest({ data: [{ id: "m1" }] }, calls) },
  });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(r.models, ["m1"]);
  assert.equal(lookupFn.calls.length, 1, "the name was resolved exactly once");
  assert.deepEqual(calls[0].looked.map((a) => a.address), ["203.0.113.60"]);
  assert.equal(calls[0].headers.Authorization, "Bearer cloud-key", "a pinned public host keeps its key");
});

test("a rebindable name that answers with THIS box is refused, and nothing is dialled", async () => {
  const lookupFn = fakeLookup([["127.0.0.1"]]);
  const calls = [];
  const r = await probeProvider("rebind", { baseUrl: "https://rebind.example.test/v1", apiKey: "row-key", host: "cloud" }, {
    guard: { lookupFn, requestFn: pinnedRequest({ data: [] }, calls) },
  });
  assert.equal(r.ok, false, JSON.stringify(r));
  assert.match(String(r.error), /Crow will not contact that address/);
  assert.deepEqual(calls, []);
});