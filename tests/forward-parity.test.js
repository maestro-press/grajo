/**
 * FORWARD PARITY: the confused-deputy rules hold for EVERY caller, not only a
 * relayed one, and a rebindable DNS name never keeps a bearer unless its
 * connection is pinned.
 *
 * `providers.base_url` (and its `api_key`) is bot-writable in a contained bot's
 * crow.db, and every forward the gateway makes for a request reads that row:
 * the model door's `forwardDoor`, the voice path's `handleChat`, and the
 * background jobs' `completeText` (session summaries, report commentary,
 * Ramble). A target on THIS box (any port) is allowed only for an exact
 * `/v1/<op>` or `/llm/v1/<op>` model call with no query and no fragment, for the
 * operator's own voice turn and a scheduled job exactly as for a bot; for a
 * relayed caller `/llm/v1/<op>` is additionally limited to this gateway's own
 * listen port (a co-hosted sibling's model door is not the bot's to drive).
 *
 * A DNS name target that is not localhost/*.localhost/*.ts.net is resolved ONCE
 * and the connection is pinned to that answer, for every caller: a public cloud
 * host keeps its bearer because the socket goes to the vetted address, a name
 * that answers with this host is refused, and the second (rebinding) answer an
 * attacker's resolver would give is never used.
 *
 * Real sockets (the relay mark is bound with `localAddress`), real routers, real
 * listeners. No database: every read the router does is a test seam.
 */
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync } from "node:fs";
import { Readable } from "node:stream";
import express from "express";

import llmRouterRouter, { completeText } from "../servers/gateway/routes/llm-router.js";
import { RELAY_SOURCE_V4 } from "../servers/shared/bot-doors.js";
import { safeRequest } from "../servers/gateway/models/safe-upstream.js";
import { isAllowedSelfForward, isRebindableHost } from "../servers/gateway/models/self-target.js";

const RELAY = RELAY_SOURCE_V4;
const LOOPBACK = "127.0.0.1";
const PUBLIC = "203.0.113.10"; // a documentation address: never actually dialled

/** A request from a chosen SOURCE address — the only way to carry the relay mark. */
function request(base, method, path, { localAddress = LOOPBACK, headers = {}, body = null } = {}) {
  const url = new URL(base);
  return new Promise((resolve, reject) => {
    const data = body === null ? null : JSON.stringify(body);
    const req = http.request({
      host: url.hostname, port: url.port, path, method, localAddress,
      headers: {
        ...(data === null ? {} : { "content-type": "application/json", "content-length": Buffer.byteLength(data) }),
        ...headers,
      },
    }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (d) => { text += d; });
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, body: text, json });
      });
    });
    req.on("error", reject);
    req.end(data ?? undefined);
  });
}

/** A resolver whose answers are scripted per call; `calls` records every ask. */
function fakeLookup(answerFn) {
  const calls = [];
  const fn = (host, options, callback) => {
    if (typeof options === "function") { callback = options; options = {}; }
    const opts = typeof options === "number" ? { family: options } : (options || {});
    const answer = answerFn(host, calls.length);
    calls.push({ host, answer });
    if (!answer) return callback(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
    const family = answer.includes(":") ? 6 : 4;
    if (opts.all) return callback(null, [{ address: answer, family }]);
    return callback(null, answer, family);
  };
  fn.calls = calls;
  return fn;
}

const response = (payload, status = 200) => ({
  status,
  headers: { "content-type": "application/json" },
  stream: Readable.from([Buffer.from(JSON.stringify(payload))]),
  deadline: Date.now() + 5000,
});

// ---------------------------------------------------------------------------
// The gateway under test, a real "own host, another port" listener, and the
// seams the router reads instead of a database.
// ---------------------------------------------------------------------------

let target;        // an own-host listener on another port (the attack's destination)
let targetPort;
let targetHits;    // { path, headers } of every request that reached it
let gateway;
let base;
let gwPort;
let providers;     // the door's provider map (bot-writable row shape)
let voiceUp;       // what resolveKeyFn answers for the voice path
let acquired;      // providers maybeAcquireLocalProvider was asked for
let currentLookup; // the resolver the router uses (rebinding tests script it)
let requestImpl;   // the transport a pinned forward goes through
let requestCalls;  // { url, headers, looked } per pinned forward

const listen = (srv) => new Promise((r) => srv.listen(0, LOOPBACK, () => r(srv.address().port)));

before(async () => {
  targetHits = [];
  target = http.createServer((req, res) => {
    targetHits.push({ path: req.url, headers: req.headers });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ hit: req.url }));
  });
  targetPort = await listen(target);

  providers = {};
  acquired = [];
  requestCalls = [];
  currentLookup = fakeLookup(() => null);
  requestImpl = safeRequest;

  const app = express();
  app.use(express.json());
  app.use(llmRouterRouter({
    acquireFn: async (id) => { acquired.push(id); return true; },
    resolveKeyFn: async () => voiceUp,
    probeReadyFn: async () => true,
    warmFn: async () => true,
    loadProvidersFn: () => ({ providers }),
    remoteAddressFn: (req) => req.socket?.remoteAddress || "",
    resolveVoiceKeysFn: async () => ({ fast: "crow-voice/qwen3.5-4b", escalate: "crow-chat/qwen3.6-35b-a3b" }),
    classifyDoorCallerFn: async () => ({ cls: "loopback" }),
    recordUsageFn: async () => {},
    nowFn: Date.now,
    enforceFn: () => false,
    logFn: () => {},
    lookupFn: (host, options, cb) => currentLookup(host, options, cb),
    listenPortsFn: () => new Set([gwPort]),
    requestFn: (url, opts) => {
      const rec = { url, headers: opts.headers, looked: null };
      requestCalls.push(rec);
      return requestImpl(url, opts).then((r) => { rec.looked = r?._looked ?? rec.looked; return r; });
    },
  }));

  gateway = http.createServer(app);
  gwPort = await listen(gateway);
  base = `http://127.0.0.1:${gwPort}`;
  // What self-target.js reads as "this gateway's own door" (door.js: PORT, else
  // CROW_GATEWAY_PORT, else 3001). Set for the duration of this file only.
  process.env.PORT = String(gwPort);
});

after(async () => {
  delete process.env.PORT;
  for (const s of [gateway, target]) { s?.closeAllConnections?.(); await new Promise((r) => (s ? s.close(() => r()) : r())); }
});

beforeEach(() => {
  providers = {};
  voiceUp = null;
  acquired = [];
  targetHits = [];
  requestCalls = [];
  currentLookup = fakeLookup(() => null);
  requestImpl = safeRequest;
});

const chat = ({ localAddress = LOOPBACK, model = "crow-companion" } = {}) =>
  request(base, "POST", "/llm/v1/chat/completions", { localAddress, body: { model, messages: [{ role: "user", content: "hi" }] } });
const door = (provider, { localAddress = LOOPBACK, model = "m" } = {}) =>
  request(base, "POST", `/llm/p/${provider}/v1/chat/completions`, { localAddress, body: { model, messages: [{ role: "user", content: "hi" }] } });

/** A pinned forward: drive the lookup the socket would use and record the answer. */
const pinnedRequest = () => async (url, opts) => {
  const looked = await new Promise((resolve, reject) => {
    opts.lookupFn(new URL(url).hostname, { all: true }, (e, a) => (e ? reject(e) : resolve(a)));
  });
  requestCalls.at(-1).looked = looked;
  return response({ choices: [{ message: { content: "ok" } }] });
};

const completeAt = (baseUrl, over = {}) => completeText({ model: "p/m", prompt: "hi" }, {
  resolveKeyFn: async () => ({ baseUrl, model: "m", apiKey: "row-key", host: "cloud" }),
  lookupFn: (host, options, cb) => currentLookup(host, options, cb),
  requestFn: (url, opts) => {
    const rec = { url, headers: opts.headers, looked: null };
    requestCalls.push(rec);
    return requestImpl(url, opts).then((r) => { rec.looked = r?._looked ?? rec.looked; return r; });
  },
  reservationFn: () => null,
  recordUsageFn: async () => {},
  ...over,
});

// ---------------------------------------------------------------------------
// The rule itself (unit): the sibling-gateway refinement, and the EOF nit.
// ---------------------------------------------------------------------------

test("self-target.js: /llm/v1 is this gateway's door only on a port it listens on; /v1 is allowed anywhere on this host", () => {
  assert.equal(isAllowedSelfForward("http://127.0.0.1:3001/llm/v1/chat/completions", { relayed: true, self: true }), true);
  assert.equal(isAllowedSelfForward("http://127.0.0.1:3008/llm/v1/chat/completions", { relayed: true, self: false }), false, "a co-hosted sibling gateway's model door");
  assert.equal(isAllowedSelfForward("http://127.0.0.1:3008/LLM/v1/completions", { relayed: true, self: false }), false, "case-insensitive, as Express routes it");
  assert.equal(isAllowedSelfForward("http://127.0.0.1:3008/v1/chat/completions", { relayed: true, self: false }), true, "a model server's own port");
  assert.equal(isAllowedSelfForward("http://127.0.0.1:3001/llm/v1/chat/completions", { relayed: false, self: false }), true, "the owner may use any door");
  assert.equal(isAllowedSelfForward("http://127.0.0.1:3001/llm/acquire?x=", { relayed: false }), false);
  assert.equal(isAllowedSelfForward("http://127.0.0.1:3001/llm/acquire?x=", { relayed: true, self: true }), false);
});

test("self-target.js ends with a newline (repository hygiene nit)", () => {
  const src = readFileSync(new URL("../servers/gateway/models/self-target.js", import.meta.url), "utf8");
  assert.equal(src.endsWith("\n"), true);
});

// ---------------------------------------------------------------------------
// (1) EVERY CALLER: a row pointing at a non-model route on this host.
// ---------------------------------------------------------------------------

test("a NON-relayed voice turn whose row points at /llm/acquire?x= on this host is refused, and the route is never hit", async () => {
  voiceUp = { baseUrl: `http://127.0.0.1:${targetPort}/llm/acquire?x=`, model: "m", apiKey: "row-key" };
  const r = await chat();
  assert.equal(r.status, 403, r.body);
  assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
  assert.deepEqual(targetHits, [], "the model lifecycle route was never reached");
});

test("a NON-relayed completeText job whose row points at /llm/acquire?x= on this host is refused, and the route is never hit", async () => {
  await assert.rejects(
    () => completeAt(`http://127.0.0.1:${targetPort}/llm/acquire?x=`),
    (e) => e.code === "SELF_TARGET_REFUSED",
  );
  assert.deepEqual(targetHits, [], "the scheduled job never re-entered the gateway");
});

test("a NON-relayed voice turn at an ALLOWED own-host path still forwards, with no bearer (nothing regressed)", async () => {
  voiceUp = { baseUrl: `http://127.0.0.1:${targetPort}/v1`, model: "m", apiKey: "row-key" };
  const r = await chat();
  assert.equal(r.status, 200, r.body);
  assert.deepEqual(targetHits.map((h) => h.path), ["/v1/chat/completions"]);
  assert.equal(targetHits[0].headers.authorization, undefined, "no provider key on a forward that lands on this box");
});

test("a NON-relayed completeText job at an ALLOWED own-host path still forwards, with no bearer", async () => {
  const text = await completeAt(`http://127.0.0.1:${targetPort}/v1`);
  assert.equal(text, "", "the fake model server answers no choices");
  assert.deepEqual(targetHits.map((h) => h.path), ["/v1/chat/completions"]);
  assert.equal(targetHits[0].headers.authorization, undefined);
});

// ---------------------------------------------------------------------------
// (3) A REFUSED TURN NEVER STARTS OR EVICTS A MODEL.
// ---------------------------------------------------------------------------

test("a refused voice turn does not call acquire (non-relayed and relayed)", async () => {
  voiceUp = { baseUrl: `http://127.0.0.1:${targetPort}/llm/acquire?x=`, model: "m", apiKey: "row-key" };
  assert.equal((await chat()).status, 403);
  assert.deepEqual(acquired, [], "a refused non-relayed turn never starts or evicts a model");
  // No query this time, so the relayed leg is refused by the own-host PATH rule
  // (its own SELF_TARGET_REFUSED), not by the relayed no-query rule.
  voiceUp = { baseUrl: `http://127.0.0.1:${targetPort}/llm/acquire`, model: "m", apiKey: "row-key" };
  const relayed = await chat({ localAddress: RELAY });
  assert.equal(relayed.status, 403, relayed.body);
  assert.equal(relayed.json?.error?.code, "SELF_TARGET_REFUSED");
  assert.deepEqual(acquired, [], "a refused relayed turn neither");
  assert.deepEqual(targetHits, []);
});

// ---------------------------------------------------------------------------
// (1b) FORBIDDEN TARGETS: link-local / cloud metadata is refused for EVERY
// caller, judged on the address, before any acquire and before any socket.
// A provider row is bot-writable, so the operator's own voice turn and a
// scheduled job are not privileged callers here either.
// ---------------------------------------------------------------------------

test("a NON-relayed voice turn pointed at cloud metadata (169.254.169.254) is refused before any acquire or dial", async () => {
  voiceUp = { baseUrl: "http://169.254.169.254/v1", model: "m", apiKey: "row-key" };
  const r = await chat();
  assert.equal(r.status, 400, r.body);
  assert.equal(r.json?.error?.code, "FORBIDDEN_TARGET");
  assert.deepEqual(acquired, [], "a refused turn never starts or evicts a model");
  assert.deepEqual(requestCalls, [], "nothing was dialled");
  assert.deepEqual(targetHits, []);
});

test("a NON-relayed completeText job pointed at cloud metadata is refused, and nothing is dialled", async () => {
  const dialled = [];
  await assert.rejects(
    () => completeAt("http://169.254.169.254/v1", { fetchFn: async (url) => { dialled.push(url); throw new Error("dialled"); } }),
    (e) => e.code === "FORBIDDEN_TARGET",
  );
  assert.deepEqual(dialled, [], "the metadata endpoint was never contacted");
  assert.deepEqual(requestCalls, []);
});

test("a RELAYED voice turn pointed at cloud metadata keeps its existing FORBIDDEN_TARGET refusal", async () => {
  voiceUp = { baseUrl: "http://169.254.169.254/v1", model: "m", apiKey: "row-key" };
  const r = await chat({ localAddress: RELAY });
  assert.equal(r.status, 400, r.body);
  assert.equal(r.json?.error?.code, "FORBIDDEN_TARGET");
  assert.deepEqual(acquired, []);
  assert.deepEqual(requestCalls, []);
});

// ---------------------------------------------------------------------------
// (2) REBINDING: one resolution, pinned, for every caller.
// ---------------------------------------------------------------------------

test("a rebindable name for a NON-relayed voice turn is resolved ONCE and pinned: the bearer never reaches the loopback listener", async () => {
  currentLookup = fakeLookup((host, n) => (n === 0 ? PUBLIC : LOOPBACK)); // public, then the rebind
  requestImpl = pinnedRequest();
  voiceUp = { baseUrl: `http://rebind.example.test:${targetPort}/v1`, model: "m", apiKey: "row-key" };
  const r = await chat();
  assert.equal(r.status, 200, r.body);
  assert.equal(currentLookup.calls.length, 1, "the name is resolved exactly once");
  assert.equal(requestCalls.length, 1);
  assert.equal(requestCalls[0].looked?.[0]?.address, PUBLIC, "the socket was pinned to the vetted answer, never to the rebind");
  assert.equal(requestCalls[0].headers.Authorization, "Bearer row-key", "a pinned public host keeps its bearer");
  assert.deepEqual(targetHits, [], "the loopback listener the second answer named saw nothing");
});

test("a rebindable name for a NON-relayed completeText job is resolved ONCE and pinned too", async () => {
  currentLookup = fakeLookup((host, n) => (n === 0 ? PUBLIC : LOOPBACK));
  requestImpl = pinnedRequest();
  const text = await completeAt(`http://rebind.example.test:${targetPort}/v1`);
  assert.equal(text, "ok");
  assert.equal(currentLookup.calls.length, 1);
  assert.equal(requestCalls[0].looked?.[0]?.address, PUBLIC);
  assert.equal(requestCalls[0].headers.Authorization, "Bearer row-key");
  assert.deepEqual(targetHits, []);
});

test("a rebindable name that answers with THIS host is refused, for the voice path and completeText, with nothing dialled", async () => {
  currentLookup = fakeLookup(() => LOOPBACK);
  requestImpl = pinnedRequest();
  voiceUp = { baseUrl: `http://rebind.example.test:${targetPort}/v1`, model: "m", apiKey: "row-key" };
  const r = await chat();
  assert.equal(r.status, 403, r.body);
  assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
  await assert.rejects(() => completeAt(`http://rebind.example.test:${targetPort}/v1`), (e) => e.code === "SELF_TARGET_REFUSED");
  assert.deepEqual(requestCalls, [], "nothing was dialled");
  assert.deepEqual(targetHits, []);
});

test("a name that does not resolve is refused (fail closed), for the voice path and completeText", async () => {
  currentLookup = fakeLookup(() => null);
  requestImpl = pinnedRequest();
  voiceUp = { baseUrl: "http://rebind.example.test/v1", model: "m", apiKey: "row-key" };
  assert.equal((await chat()).status, 403);
  await assert.rejects(() => completeAt("http://rebind.example.test/v1"), (e) => e.code === "SELF_TARGET_REFUSED");
  assert.deepEqual(requestCalls, []);
});

test("a PUBLIC cloud host still gets its bearer, voice path and completeText", async () => {
  currentLookup = fakeLookup(() => PUBLIC);
  requestImpl = pinnedRequest();
  voiceUp = { baseUrl: `http://cloud.example.test:${targetPort}/v1`, model: "m", apiKey: "row-key" };
  const r = await chat();
  assert.equal(r.status, 200, r.body);
  assert.equal(requestCalls.at(-1).headers.Authorization, "Bearer row-key");
  assert.equal(requestCalls.at(-1).looked?.[0]?.address, PUBLIC);
  const text = await completeAt(`http://cloud.example.test:${targetPort}/v1`);
  assert.equal(text, "ok");
  assert.equal(requestCalls.at(-1).headers.Authorization, "Bearer row-key");
  assert.equal(requestCalls.at(-1).looked?.[0]?.address, PUBLIC);
  assert.deepEqual(targetHits, []);
});

// ---------------------------------------------------------------------------
// (4) Voice-path parity with the door: relayed address class + no query.
// ---------------------------------------------------------------------------

test("a RELAYED voice target that fails the door's local address class is refused before any acquire", async () => {
  voiceUp = { baseUrl: "http://203.0.113.9:8011/v1", model: "m", apiKey: "row-key" };
  const r = await chat({ localAddress: RELAY });
  assert.equal(r.status, 400, r.body);
  assert.equal(r.json?.error?.code, "NOT_FORWARDABLE");
  assert.deepEqual(acquired, []);
  assert.deepEqual(requestCalls, []);
});

test("a RELAYED voice target carrying a query string is refused, even on a local-class host", async () => {
  voiceUp = { baseUrl: "http://10.99.99.99:8011/v1?x=", model: "m", apiKey: "row-key" };
  const r = await chat({ localAddress: RELAY });
  assert.equal(r.status, 400, r.body);
  assert.equal(r.json?.error?.code, "NOT_FORWARDABLE");
  assert.deepEqual(acquired, []);
  assert.deepEqual(requestCalls, []);
});

test("a RELAYED voice target whose name does not resolve is refused (the door's fail-closed rule)", async () => {
  currentLookup = fakeLookup(() => null);
  voiceUp = { baseUrl: "http://never-resolves.example.ts.net:8011/v1", model: "m", apiKey: "row-key" };
  const r = await chat({ localAddress: RELAY });
  assert.equal(r.status, 403, r.body);
  assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
  assert.deepEqual(acquired, []);
  assert.deepEqual(targetHits, []);
});

// ---------------------------------------------------------------------------
// (6) SIBLING GATEWAYS: a co-hosted gateway's model door is not this gateway's.
// ---------------------------------------------------------------------------

test("a RELAYED door call to /llm/v1 on another own-host port is refused; /v1 on that port still forwards", async () => {
  providers = { sib: { baseUrl: `http://127.0.0.1:${targetPort}/llm/v1`, apiKey: "none", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } };
  const refused = await door("sib", { localAddress: RELAY });
  assert.equal(refused.status, 403, refused.body);
  assert.equal(refused.json?.error?.code, "SELF_TARGET_REFUSED");
  assert.deepEqual(targetHits, [], "the sibling gateway's model door was never driven");

  providers = { native: { baseUrl: `http://127.0.0.1:${targetPort}/v1`, apiKey: "none", models: [{ id: "m" }], gpuPolicy: { runtime: "native", owner: "me", port: 1 } } };
  const ok = await door("native", { localAddress: RELAY });
  assert.equal(ok.status, 200, ok.body);
  assert.deepEqual(targetHits.map((h) => h.path), ["/v1/chat/completions"], "a model server's own port stays forwardable");
});

// ---------------------------------------------------------------------------
// The peer relay's name rule is the voice path's (the e2e lives in
// tests/peer-relay.test.js, which owns the relay fixture); the predicate here.
// ---------------------------------------------------------------------------

test("a relayed peer gateway_url must be an IP literal, localhost or a tailnet name", () => {
  for (const u of ["http://192.0.2.10:3001/", "http://127.0.0.1:3001/", "http://localhost:3001/", "http://peer.example.ts.net:3001/"]) {
    assert.equal(isRebindableHost(u), false, u);
  }
  for (const u of ["http://peer.example.test:3001/", "http://192.0.2.10.nip.io:3001/"]) {
    assert.equal(isRebindableHost(u), true, u);
  }
});

// ---------------------------------------------------------------------------
// (7) N1: an UNRESOLVED host is refused for EVERY caller, not only a relayed
// one. `*.ts.net` is not rebindable (MagicDNS), so such a name used to take the
// "no pin" branch: the forward left with the fetch making the ONLY resolution
// of it. The request would fail on that second lookup anyway — and this removes
// the second, unchecked resolution.
// ---------------------------------------------------------------------------

test("an unresolved *.ts.net name is refused by the voice path, completeText and the door, relayed AND non-relayed", async () => {
  // A SCRIPTED resolver, never real DNS: every path judges the name through the
  // same seam, so `lookupFn.calls` is the proof that the name was asked once by
  // US and never left to the fetch.
  const lookupFn = fakeLookup(() => null);   // the resolver answers nothing
  currentLookup = lookupFn;
  requestImpl = pinnedRequest();
  voiceUp = { baseUrl: "http://never-resolves.example.ts.net:8003/v1", model: "m", apiKey: "row-key" };
  for (const localAddress of [LOOPBACK, RELAY]) {
    const r = await chat({ localAddress });
    assert.equal(r.status, 403, r.body);
    assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
  }
  assert.deepEqual(acquired, [], "a refused turn never starts or evicts a model");
  assert.deepEqual(requestCalls, [], "nothing was dialled (and no resolution left to a fetch)");
  assert.deepEqual(targetHits, []);

  await assert.rejects(
    () => completeAt("http://never-resolves.example.ts.net:8003/v1"),
    (e) => e.code === "SELF_TARGET_REFUSED",
    "a scheduled job is not a privileged caller",
  );
  assert.deepEqual(requestCalls, []);

  // the door forwards to a tailnet name, so an unresolved one used to reach
  // forwardDoor's fetch (a 502 after the fetch's own lookup).
  providers = { peer: { baseUrl: "http://never-resolves.example.ts.net:8003/v1", apiKey: "none", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } };
  const before = lookupFn.calls.filter((c) => c.host === "never-resolves.example.ts.net").length;
  for (const localAddress of [LOOPBACK, RELAY]) {
    const d = await door("peer", { localAddress });
    assert.equal(d.status, 403, d.body);
    assert.equal(d.json?.error?.code, "SELF_TARGET_REFUSED");
  }
  assert.equal(
    lookupFn.calls.filter((c) => c.host === "never-resolves.example.ts.net").length, before + 2,
    "the door judges the name with the same scripted resolver (one ask per forward, real DNS never consulted)",
  );
  assert.deepEqual(targetHits, []);
});

// ---------------------------------------------------------------------------
// (8) N2: an IPv4 embedded in NAT64 decides the address class.
// `[64:ff9b::a9fe:a9fe]` IS 169.254.169.254 through a translator, and every one
// of these paths classified it as "not this host" and dialled it.
// ---------------------------------------------------------------------------

test("NAT64-embedded cloud metadata is refused by the voice path, completeText and the door (N2)", async () => {
  voiceUp = { baseUrl: "http://[64:ff9b::a9fe:a9fe]/v1", model: "m", apiKey: "row-key" };
  for (const localAddress of [LOOPBACK, RELAY]) {
    const r = await chat({ localAddress });
    assert.equal(r.status, 400, r.body);
    assert.equal(r.json?.error?.code, "FORBIDDEN_TARGET");
  }
  assert.deepEqual(acquired, []);
  assert.deepEqual(requestCalls, [], "nothing was dialled");

  await assert.rejects(
    () => completeAt("http://[64:ff9b::a9fe:a9fe]/v1"),
    (e) => e.code === "FORBIDDEN_TARGET",
  );
  assert.deepEqual(requestCalls, []);

  providers = { meta: { baseUrl: "http://[64:ff9b::a9fe:a9fe]/v1", apiKey: "none", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } };
  const d = await door("meta");
  assert.equal(d.status, 400, d.body);
  assert.equal(d.json?.error?.code, "FORBIDDEN_TARGET");
  assert.deepEqual(requestCalls, []);
  assert.deepEqual(targetHits, [], "the metadata endpoint was never contacted");
});