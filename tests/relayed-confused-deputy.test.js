/**
 * THE CONFUSED DEPUTY: a relayed socket must never make the gateway fetch its
 * own routes.
 *
 * A contained bot has crow.db bound read-write, so it can write the rows the
 * gateway reads when it forwards a request:
 *
 *   providers.base_url / api_key / gpu_policy    the model door and the voice path
 *   crow_instances.gateway_url                   the peer relay
 *
 * Point one of those at THIS gateway on its OWN listen port and the forward
 * leaves as a FRESH, UNMARKED loopback socket carrying a bearer the bot chose —
 * the egress relay's mark (isRelayedSocket, servers/shared/bot-doors.js) is gone
 * on the hop the gateway opens, so every "a relayed socket never authenticates
 * as the owner" rule is bypassed in one hop. `/llm/models/<m>/start?x=` is the
 * canonical target: `${base}/chat/completions` turns that base into the model
 * START route (the query swallows the appended path segment).
 *
 * What stays: the gateway's own `/llm/v1` door, which is a bot door already (a
 * bot may call it with no bearer at all) — the `crow-llm` provider row
 * (base_url http://localhost:3001/llm/v1) keeps working, with NO Authorization
 * header attached. The rules hold for EVERY caller now, not only a relayed one:
 * an operator voice turn or a background job reads the same bot-writable row, so
 * its forward is judged by the same path rule and a rebindable DNS name is
 * resolved once and pinned (tests/forward-parity.test.js).
 *
 * Real sockets (the client binds the relay mark with `localAddress`, exactly how
 * the relay opens its upstream connections), real routers, a real upstream
 * model server. No database: every read the router does is a test seam.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Readable } from "node:stream";
import { networkInterfaces } from "node:os";
import express from "express";
import { WebSocketServer, WebSocket } from "ws";

import llmRouterRouter, { completeText } from "../servers/gateway/routes/llm-router.js";
import { createKioskRuntime } from "../bundles/kiosk/server/runtime.js";
import { RELAY_SOURCE_V4, isRelayedSocket } from "../servers/shared/bot-doors.js";
import {
  gatewayListenPorts, isOwnHostAddress, isOwnHostTarget, isSelfTarget, ownTargetOf, isAllowedSelfPath,
  isRebindableHost, targetHost,
} from "../servers/gateway/models/self-target.js";

const RELAY = RELAY_SOURCE_V4;   // the mark a relayed socket carries
const LOOPBACK = "127.0.0.1";

/** A non-loopback address of this box (for "the host's own IP:3001 counts too"). */
function ownNonLoopbackAddress() {
  for (const entries of Object.values(networkInterfaces())) {
    for (const e of entries || []) {
      if (!e || e.internal) continue;
      if (e.family !== "IPv4") continue;
      if (e.address.startsWith("127.")) continue;
      return e.address;
    }
  }
  return null;
}

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

// ---------------------------------------------------------------------------
// The model door and the voice path, on the gateway's OWN port (PORT is what
// servers/gateway/models/door.js reads for the listen port, and self-target.js
// judges "this gateway" by exactly that).
// ---------------------------------------------------------------------------

let upstream;            // a real, already-running "local model" on its own port
let redirector;          // a model server that answers 307 instead of serving
let redirectTo = null;   // where the redirector points
let redirectorHits;
let gateway;             // the app under test
let base;                // gateway URL (loopback)
let gwPort;
let upstreamSeen = [];   // what the model upstream saw
let gatewaySeen = [];    // headers of every request that reached the gateway itself
let started = [];        // POSTs that reached the model lifecycle route
let providers = {};      // the door's provider map (bot-writable row shape)
let voiceUp = null;      // what resolveKeyFn answers for the voice path

before(async () => {
  upstream = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      upstreamSeen.push({ path: req.url, headers: req.headers, body });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, from: "upstream", path: req.url }));
    });
  });
  await new Promise((r) => upstream.listen(0, LOOPBACK, r));
  const upUrl = `http://127.0.0.1:${upstream.address().port}/v1`;

  const app = express();
  app.use(express.json());
  // Everything the gateway receives (including a forward it made to itself).
  app.use((req, _res, next) => { gatewaySeen.push({ path: req.originalUrl, headers: req.headers }); next(); });
  // The model lifecycle route the attack aims at (GET /llm/models exists too; the
  // start/evict routes are POST and are exactly what a forward would reach).
  app.post("/llm/models/:model/start", (req, res) => {
    started.push(req.params.model);
    res.json({ started: req.params.model });
  });
  app.use(llmRouterRouter({
    acquireFn: async () => true,
    resolveKeyFn: async (key) => voiceUp || ({ baseUrl: upUrl, model: String(key).split("/")[1], apiKey: null }),
    probeReadyFn: async () => true,
    warmFn: async () => true,
    loadProvidersFn: () => ({ providers }),
    // The REAL source rule: the socket's own address, never a test override.
    remoteAddressFn: (req) => req.socket?.remoteAddress || "",
    resolveVoiceKeysFn: async () => ({ fast: "crow-voice/qwen3.5-4b", escalate: "crow-chat/qwen3.6-35b-a3b" }),
    classifyDoorCallerFn: async () => ({ cls: "loopback" }),
    recordUsageFn: async () => {},
    nowFn: Date.now,
    enforceFn: () => false,
    logFn: () => {},
  }));

  gateway = http.createServer(app);
  await new Promise((r) => gateway.listen(0, LOOPBACK, r));
  gwPort = gateway.address().port;
  base = `http://127.0.0.1:${gwPort}`;
  // A model server that answers 307 to whatever `redirectTo` says. It must never
  // be followed: Node would follow it on a fresh socket of its own, outside every
  // own-host check the router made.
  redirectorHits = [];
  redirector = http.createServer((req, res) => {
    redirectorHits.push(req.url);
    res.writeHead(307, { location: redirectTo || "http://127.0.0.1:1/nowhere" });
    res.end();
  });
  await new Promise((r) => redirector.listen(0, LOOPBACK, r));
  // What the router reads as "the gateway's own listen port" (door.js: PORT, else
  // CROW_GATEWAY_PORT, else 3001). Set for the duration of this file only.
  process.env.PORT = String(gwPort);
  // The voice fast/escalate rows live on their own upstream, as on a real box.
  voiceUp = { baseUrl: upUrl, model: "qwen3.5-4b", apiKey: null };
});

after(async () => {
  delete process.env.PORT;
  for (const s of [gateway, upstream, redirector]) { s?.closeAllConnections?.(); await new Promise((r) => (s ? s.close(() => r()) : r())); }
});

const doorCall = (provider, { localAddress = LOOPBACK, model = "m" } = {}) =>
  request(base, "POST", `/llm/p/${provider}/v1/chat/completions`,
    { localAddress, body: { model, messages: [{ role: "user", content: "hi" }] } });
const chatCall = ({ localAddress = LOOPBACK, model = "crow-voice/qwen3.5-4b" } = {}) =>
  request(base, "POST", "/llm/v1/chat/completions", { localAddress, body: { model, messages: [{ role: "user", content: "hi" }] } });

/** The attack row: an opt-in provider whose base_url is this gateway's own port
 *  and whose path is the model lifecycle route (`?x=` swallows `/chat/completions`). */
function attackRow(host) {
  return {
    baseUrl: `http://${host}:${gwPort}/llm/models/m/start?x=`,
    apiKey: "bot-chosen-key",
    models: [{ id: "m" }],
    gpuPolicy: { door_forward: true },
  };
}

// ---------------------------------------------------------------------------
// The helper itself.
// ---------------------------------------------------------------------------

const OWN = new Set(["localhost", "127.0.0.1", "::1", "10.0.0.5", "100.64.20.1"]);

test("self-target.js: loopback, the unspecified address and every own address are this host", () => {
  for (const a of ["127.0.0.1", "127.0.77.1", "::1", "[::1]", "0.0.0.0", "::", "10.0.0.5", "100.64.20.1", "::ffff:10.0.0.5"]) {
    assert.equal(isOwnHostAddress(a, OWN), true, a);
  }
  for (const a of ["10.0.0.6", "100.64.20.2", "192.0.2.10", "fd7a:115c:a1e0::99", "2606:4700::1111", "", null, undefined, "metadata"]) {
    assert.equal(isOwnHostAddress(a, OWN), false, String(a));
  }
});

test("self-target.js: names are resolved before the decision (localhost, this host's own name)", async () => {
  const lookup = (table) => (host, _o, cb) => {
    const answer = table[host];
    if (!answer) return cb(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
    return cb(null, answer.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })));
  };
  const ports = new Set([3001]);

  // localhost is loopback by definition, no resolver consulted.
  assert.deepEqual(await ownTargetOf("http://localhost:3001/llm/v1", { ports, ownAddrs: OWN }), { own: true, self: true, port: 3001, resolved: true, unresolved: false });
  // A name resolving to this box, on the gateway port: this gateway.
  const own = await ownTargetOf("http://crow.example.test:3001/x", { ports, ownAddrs: OWN, lookupFn: lookup({ "crow.example.test": ["10.0.0.5"] }) });
  assert.deepEqual(own, { own: true, self: true, port: 3001, resolved: true, unresolved: false });
  // Same name, a model server's own port: this host, not this gateway.
  assert.deepEqual(await ownTargetOf("http://crow.example.test:18102/v1", { ports, ownAddrs: OWN, lookupFn: lookup({ "crow.example.test": ["10.0.0.5"] }) }),
    { own: true, self: false, port: 18102, resolved: true, unresolved: false });
  // A remote name (a peer gateway on the same port) is somebody else's.
  assert.equal(await isSelfTarget("http://peer.example.test:3001/llm/v1", { ports, ownAddrs: OWN, lookupFn: lookup({ "peer.example.test": ["100.64.20.2"] }) }), false);
  assert.equal(await isOwnHostTarget("http://peer.example.test:3001/llm/v1", { ownAddrs: OWN, lookupFn: lookup({ "peer.example.test": ["100.64.20.2"] }) }), false);
  // A name that does not resolve is reported DISTINCTLY (fail closed), never as
  // "not this host": our lookup and the fetch's are two resolutions of it.
  assert.deepEqual(await ownTargetOf("http://nope.example.test:3001/", { ownAddrs: OWN, lookupFn: lookup({}) }),
    { own: false, self: false, port: 3001, resolved: false, unresolved: true });
  // A resolver that throws, and one that never answers, are the same answer.
  assert.equal((await ownTargetOf("http://nope.example.test:3001/", { ownAddrs: OWN, lookupFn: () => { throw Object.assign(new Error("boom"), { code: "ETIMEOUT" }); } })).unresolved, true);
  assert.equal((await ownTargetOf("http://nope.example.test:3001/", { ownAddrs: OWN, lookupFn: (_h, _o, cb) => cb(Object.assign(new Error("ETIMEOUT"), { code: "ETIMEOUT" })) })).unresolved, true);
  // An own address on ANY port is still this host (the api_key / peer-relay rule).
  assert.equal(await isOwnHostTarget("http://127.0.0.1:9/", { ownAddrs: OWN }), true);
  assert.equal(targetHost("http://[::1]:3001/"), "::1");
  assert.deepEqual([...gatewayListenPorts({ PORT: "3008" })], [3008]);
});

test("self-target.js: the PATH rule — on this host only /v1/<op> and /llm/v1/<op>, no query, no fragment", () => {
  for (const p of [
    "/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/rerank",
    "/llm/v1/chat/completions", "/llm/v1/completions", "/llm/v1/embeddings", "/llm/v1/rerank",
    "/LLM/v1/completions",
  ]) assert.equal(isAllowedSelfPath(`http://127.0.0.1:3001${p}`), true, p);
  for (const p of [
    // a query is the load-bearing half: `${base}/chat/completions` swallows the
    // operation into it, which turns a base_url into the model lifecycle route
    "/llm/acquire?x=", "/llm/models/m/start?x=", "/v1/chat/completions?x=", "/v1?x=/chat/completions",
    // anything that is not one of the four operations
    "/llm/models/m/start", "/llm/acquire", "/api/reload-backends", "/relay/store",
    "/v1", "/v1/", "/llm/v1", "/llm/v1/", "/v1/models", "/v1/chat/completions/extra",
    "/llm/p/crow-voice/v1/chat/completions", "/llm/c/x/v1/chat/completions", "/llm/v1x/chat/completions",
    "/storage/x", "/api/kiosk/internal/announce", "/dashboard/x",
    // a fragment, and a path a later layer could decode into another route
    "/v1/chat/completions#/llm/models/m/start",
    "/llm/v1/%2e%2e/llm/models/m/start", "/llm/v1/../llm/models/m/start", "/v1//chat/completions",
  ]) assert.equal(isAllowedSelfPath(`http://127.0.0.1:3001${p}`), false, p);
});

test("self-target.js: a relayed forward may not be rebound through a foreign DNS name", () => {
  for (const u of ["http://127.0.0.1:8011/v1", "http://[::1]:8011/v1", "http://203.0.113.5/v1", "http://localhost:8011/v1", "http://crow.example.ts.net:8011/v1"]) {
    assert.equal(isRebindableHost(u), false, u);
  }
  for (const u of ["http://evil.example/v1", "http://crow.example.test:8011/v1", "http://127.0.0.1.nip.io/v1", "http://ts.net.evil.example/v1", "http://nodot/v1"]) {
    assert.equal(isRebindableHost(u), true, u);
  }
  assert.equal(isRebindableHost("not a url"), false, "an unparseable URL is judged by the fetch, not here");
});

// ---------------------------------------------------------------------------
// (c) The confused deputy on the model door.
// ---------------------------------------------------------------------------

test("RELAYED door call to a provider row on this gateway's port: refused, and the models route is never invoked", async () => {
  started = []; providers = { attack: attackRow("127.0.0.1") };
  const r = await doorCall("attack", { localAddress: RELAY });
  assert.equal(r.status, 403, r.body);
  assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
  assert.deepEqual(started, [], "the model start/evict route was never reached");
});

test("RELAYED door call on the host's own non-loopback address: the same refusal", async (t) => {
  const ip = ownNonLoopbackAddress();
  if (!ip) return t.skip("this box has no non-loopback IPv4 address to name");
  started = []; providers = { attack: attackRow(ip) };
  const r = await doorCall("attack", { localAddress: RELAY });
  assert.equal(r.status, 403, r.body);
  assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
  assert.deepEqual(started, []);
});

test("the SAME door call from plain loopback is refused TOO (the rule is every caller's)", async () => {
  started = []; providers = { attack: attackRow("127.0.0.1") };
  const r = await doorCall("attack");
  assert.equal(r.status, 403, r.body);
  assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
  assert.deepEqual(started, [], "a non-relayed caller no longer runs the model lifecycle route either");
});

test("a RELAYED door call to a real loopback model server on its own port still forwards", async () => {
  started = []; upstreamSeen = [];
  const upUrl = `http://127.0.0.1:${upstream.address().port}/v1`;
  providers = { "crow-voice": { baseUrl: upUrl, apiKey: "none", models: [{ id: "qwen3.5-4b" }], gpuPolicy: { runtime: "native", owner: "me", port: 1 } } };
  const r = await doorCall("crow-voice", { localAddress: RELAY, model: "qwen3.5-4b" });
  assert.equal(r.status, 200, r.body);
  assert.match(upstreamSeen.at(-1).path, /\/chat\/completions$/);
});

// ---------------------------------------------------------------------------
// (a) THE PATH RULE replaces the port rule: co-hosted sibling gateways exist
// (crow :3001 and crow-r4 :3008 on one box), so "own host, a port I do not
// listen on" is still this box's own loopback work.
// ---------------------------------------------------------------------------

/** The prod-shaped own-host rows: every one of these base paths must stay forwardable. */
const PROD_OWN_BASES = (up) => [
  `${up}/v1`,                                  // 127.0.0.1:8020/v1, :18100/v1, :8012/v1, :18080/v1
  `http://localhost:${gwPort}/llm/v1`,         // the crow-llm alias row
];

test("PATH rule: a target on this host at ANY port is refused unless it is /v1/<op> or /llm/v1/<op> with no query", async () => {
  started = []; upstreamSeen = []; gatewaySeen = [];
  const up = `http://127.0.0.1:${upstream.address().port}`;
  // A SECOND loopback port (not the gateway's): the port rule this replaces
  // allowed every one of these, because only `self` ports were off limits.
  for (const baseUrl of [
    `${up}/llm/acquire?x=`,                 // -> /llm/models/m/start?x= swallows /chat/completions
    `${up}/v1/chat/completions?x=`,         // a query, even on the right path
    `${up}/llm/models/m/start?x=`,          // the model lifecycle route by name
    `${up}/llm/p/other/v1`,                 // a co-hosted sibling gateway's provider door
    `${up}/llm/c/cloud/v1`,                 // the cloud door
    `${up}/api/kiosk/internal/announce`,    // the kiosk announce route
  ]) {
    providers = { attack: { baseUrl, apiKey: "bot-chosen-key", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } };
    const r = await doorCall("attack", { localAddress: RELAY });
    assert.equal(r.status, 403, `${baseUrl}: ${r.body}`);
    assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED", baseUrl);
  }
  assert.deepEqual(upstreamSeen, [], "that second loopback port was never contacted");
  assert.deepEqual(started, []);

  // …and the same host, the same second port, a plain model server on /v1: forwards.
  providers = { ok: { baseUrl: `${up}/v1`, apiKey: "none", models: [{ id: "m" }], gpuPolicy: { runtime: "native", owner: "me", port: 1 } } };
  const good = await doorCall("ok", { localAddress: RELAY });
  assert.equal(good.status, 200, good.body);
  assert.equal(upstreamSeen.at(-1).path, "/v1/chat/completions");
  // The prod own-host rows' base paths (crow-dsv4/qwen/crow-vision/strixfold are
  // all `<ip>:<port>/v1`) are exactly the shape above.
  for (const b of PROD_OWN_BASES(up)) assert.equal(isAllowedSelfPath(`${b.replace(/\/+$/, "")}/chat/completions`), true, b);
});

test("PATH rule: this box's own NON-loopback address on another port is refused too (the port rule's gap)", async (t) => {
  const ip = ownNonLoopbackAddress();
  if (!ip) return t.skip("this box has no non-loopback IPv4 address to name");
  started = []; upstreamSeen = [];
  const up = `http://${ip}:${upstream.address().port}`;
  providers = { attack: { baseUrl: `${up}/llm/acquire?x=`, apiKey: "bot-chosen-key", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } };
  const r = await doorCall("attack", { localAddress: RELAY });
  assert.equal(r.status, 403, r.body);
  assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
  assert.deepEqual(upstreamSeen, [], "nothing on the second port was dialled");
});

test("FAIL CLOSED: a target whose name does not resolve is never cleared as 'not this host' for a relayed caller", async () => {
  started = []; upstreamSeen = [];
  // A `*.ts.net` name: the door's own address class admits it (a local-class
  // name), so this reaches the resolver — and the resolver has no answer here.
  // An arbitrary name (`x.invalid`) is already refused earlier by the door's
  // address class, which is why this case has to use a tailnet-shaped name.
  providers = { attack: { baseUrl: "http://never-resolves.example.ts.net:8011/v1", apiKey: "bot-chosen-key", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } };
  const r = await doorCall("attack", { localAddress: RELAY });
  assert.equal(r.status, 403, r.body);
  assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
  assert.deepEqual(upstreamSeen, []);
  assert.deepEqual(started, []);
});

// ---------------------------------------------------------------------------
// (2) NO REDIRECTS. A 3xx from a model server is a 502, never followed: Node
// would follow it on a fresh socket outside every check above.
// ---------------------------------------------------------------------------

test("NO REDIRECTS: a model server answering 307 is not followed, by the door or the voice path", async () => {
  started = []; upstreamSeen = []; gatewaySeen = []; redirectorHits = [];
  redirectTo = `http://127.0.0.1:${gwPort}/llm/models/m/start`;
  const red = `http://127.0.0.1:${redirector.address().port}/v1`;
  providers = { "crow-voice": { baseUrl: red, apiKey: "none", models: [{ id: "qwen3.5-4b" }], gpuPolicy: { runtime: "native", owner: "me", port: 1 } } };
  for (const localAddress of [LOOPBACK, RELAY]) {
    const r = await doorCall("crow-voice", { localAddress, model: "qwen3.5-4b" });
    assert.equal(r.status, 502, `${localAddress}: ${r.body}`);
    assert.equal(r.json?.error?.code, "UPSTREAM_UNREACHABLE");
  }
  voiceUp = { baseUrl: red, model: "qwen3.5-4b", apiKey: "none" };
  try {
    for (const localAddress of [LOOPBACK, RELAY]) {
      const r = await chatCall({ localAddress });
      assert.equal(r.status, 502, `${localAddress}: ${r.body}`);
      assert.equal(r.json?.error?.code, "UPSTREAM_UNREACHABLE");
    }
  } finally { voiceUp = null; }
  assert.equal(redirectorHits.length, 4, "the model server was asked, four times");
  assert.deepEqual(started, [], "the redirect target (this gateway's own models route) recorded zero hits");
  assert.equal(gatewaySeen.some((g) => g.path.startsWith("/llm/models")), false, "nothing re-entered the gateway");
  assert.deepEqual(upstreamSeen, []);
});

test("completeText: a redirect is an error, and an own-host target never carries the row's key", async () => {
  redirectTo = `http://127.0.0.1:${gwPort}/llm/models/m/start`;
  await assert.rejects(() => completeText({ model: "p/m", prompt: "hi" }, {
    resolveKeyFn: async () => ({ baseUrl: `http://127.0.0.1:${redirector.address().port}/v1`, model: "m", apiKey: "row-key", host: "local" }),
    reservationFn: () => null, recordUsageFn: async () => {},
  }), /upstream status 307/);

  const seenInit = [];
  const fetchFn = async (url, init) => { seenInit.push({ url, headers: init.headers, redirect: init.redirect }); return { ok: true, json: async () => ({ choices: [{ message: { content: "S" } }] }) }; };
  // An OWN-HOST target rides the verified transport (`requestFn`), never `fetch`:
  // fetch cannot verify the socket it got (H1). The header rule is the same one.
  const requestFn = async (url, opts) => {
    seenInit.push({ url, headers: opts.headers, redirect: "manual", verifiedConnection: opts.verifiedConnection || null });
    return { status: 200, headers: { "content-type": "application/json" }, stream: Readable.from([Buffer.from(JSON.stringify({ choices: [{ message: { content: "S" } }] }))]) };
  };
  const at = (baseUrl) => async () => ({ baseUrl, model: "m", apiKey: "row-key", host: "local" });
  await completeText({ model: "p/m", prompt: "hi" }, { fetchFn, requestFn, resolveKeyFn: at(`http://127.0.0.1:${upstream.address().port}/v1`), reservationFn: () => null, recordUsageFn: async () => {} });
  assert.equal(seenInit.at(-1).headers.Authorization, undefined, "an own-host target gets no bearer, relayed or not");
  assert.ok(seenInit.at(-1).verifiedConnection, "and its connection is verified before a byte is written");
  await completeText({ model: "p/m", prompt: "hi" }, { fetchFn, resolveKeyFn: at("http://203.0.113.5/v1"), reservationFn: () => null, recordUsageFn: async () => {} });
  assert.equal(seenInit.at(-1).headers.Authorization, "Bearer row-key", "a target that is NOT this host keeps it (unchanged)");
  assert.equal(seenInit.at(-1).redirect, "manual", "and never a followed redirect");
});

test("crow-llm (the prod-shaped alias row on localhost:3001/llm/v1) is never a forward at all: the door refuses it as unmanaged", async () => {
  started = []; gatewaySeen = []; upstreamSeen = [];
  // No gpu_policy, no bundleId: an alias row for CLIENTS (a bot, pi) that dial
  // this gateway's own /llm/v1 directly. doorKindOf says "unmanaged", so the
  // door refuses it for every caller — a relayed one included — before any fetch.
  providers = { "crow-llm": { baseUrl: `http://localhost:${gwPort}/llm/v1`, apiKey: "none", models: [{ id: "crow" }] } };
  for (const localAddress of [LOOPBACK, RELAY]) {
    const r = await doorCall("crow-llm", { localAddress, model: "crow" });
    assert.equal(r.status, 400, r.body);
    assert.equal(r.json?.error?.code, "NOT_FORWARDABLE");
  }
  assert.deepEqual(started, []);
  assert.deepEqual(upstreamSeen, []);
  assert.deepEqual(gatewaySeen.map((g) => g.path), [
    "/llm/p/crow-llm/v1/chat/completions",
    "/llm/p/crow-llm/v1/chat/completions",
  ], "the gateway never fetched itself: two requests in, nothing re-entered");

  // What a client (or a contained bot) does instead: call the gateway's own
  // /llm/v1 door, which is a bot door and needs no bearer. Unchanged.
  const direct = await chatCall({ localAddress: RELAY });
  assert.equal(direct.status, 200, direct.body);
});

test("an OPT-IN row on this gateway's own /llm/v1: the forward is still attempted (the bot door), with NO provider key", async () => {
  started = []; gatewaySeen = []; upstreamSeen = [];
  providers = {
    "self-door": {
      baseUrl: `http://localhost:${gwPort}/llm/v1`,
      apiKey: "provider-key-that-must-not-travel",
      models: [{ id: "m" }],
      gpuPolicy: { door_forward: true },
    },
  };
  const r = await doorCall("self-door", { localAddress: RELAY });
  // The forward left (the /llm/v1 door is a path a relayed caller may already
  // call directly), and the receiving door refused the hop it carries — the
  // gateway's own loop protection, not the bot's privilege.
  assert.equal(r.status, 508, r.body);
  assert.equal(r.json?.error?.code, "DOOR_LOOP");
  const selfHop = gatewaySeen.filter((g) => g.path.startsWith("/llm/v1/chat/completions"));
  assert.equal(selfHop.length, 1, JSON.stringify(gatewaySeen.map((g) => g.path)));
  assert.equal(selfHop[0].headers.authorization, undefined, "no provider api_key on a forward that lands on this box");
  assert.deepEqual(started, []);
});

test("the strip is UNCONDITIONAL: the same own-host row from a NON-relayed caller carries no key either", async () => {
  gatewaySeen = []; upstreamSeen = [];
  providers = {
    "self-door": {
      baseUrl: `http://localhost:${gwPort}/llm/v1`,
      apiKey: "provider-key-that-must-not-travel",
      models: [{ id: "m" }],
      gpuPolicy: { door_forward: true },
    },
  };
  const r = await doorCall("self-door");
  assert.equal(r.status, 508, r.body);
  const selfHop = gatewaySeen.filter((g) => g.path.startsWith("/llm/v1/chat/completions"));
  assert.equal(selfHop.length, 1);
  assert.equal(selfHop[0].headers.authorization, undefined,
    "the key came from the same bot-writable row; none of the server types Crow launches on this host takes a bearer");
});

// ---------------------------------------------------------------------------
// (d) The voice/chat path (resolveKeyFn), which had no address check at all.
// ---------------------------------------------------------------------------

test("RELAYED voice turn whose fast key resolves to this gateway's port: refused before the fetch", async () => {
  started = []; upstreamSeen = [];
  voiceUp = { baseUrl: `http://127.0.0.1:${gwPort}/llm/models/m/start?x=`, model: "m", apiKey: "bot-chosen-key" };
  try {
    const r = await chatCall({ localAddress: RELAY });
    assert.equal(r.status, 403, r.body);
    assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
    assert.deepEqual(started, [], "the models route was never reached");
    assert.deepEqual(upstreamSeen, []);
  } finally {
    voiceUp = null;
  }
});

test("the same voice turn from plain loopback is refused TOO (the rule is every caller's)", async () => {
  started = [];
  voiceUp = { baseUrl: `http://127.0.0.1:${gwPort}/llm/models/m/start?x=`, model: "m", apiKey: "bot-chosen-key" };
  try {
    const r = await chatCall();
    assert.equal(r.status, 403, r.body);
    assert.equal(r.json?.error?.code, "SELF_TARGET_REFUSED");
    assert.deepEqual(started, [], "a non-relayed voice turn never runs the model lifecycle route either");
  } finally {
    voiceUp = null;
  }
});

test("the OWN-HOST upstream needs no bearer: the same forward from plain loopback carries no Authorization either, and answers 200", async () => {
  upstreamSeen = [];
  // A row with a key SET, the way an operator-edited row looks. None of the
  // server types Crow launches on this host takes one (native llama-server is
  // spawned without --api-key, an inference bundle registers apiKey "none", an
  // external engine has no auth at all), so it must not travel to this box.
  providers = { "crow-voice": { baseUrl: `http://127.0.0.1:${upstream.address().port}/v1`, apiKey: "row-key-that-must-not-travel", models: [{ id: "qwen3.5-4b" }], gpuPolicy: { runtime: "native", owner: "me", port: 1 } } };
  for (const localAddress of [LOOPBACK, RELAY]) {
    const r = await doorCall("crow-voice", { localAddress, model: "qwen3.5-4b" });
    assert.equal(r.status, 200, `${localAddress}: ${r.body}`);
    assert.equal(upstreamSeen.at(-1).headers.authorization, undefined, `${localAddress}: no bearer`);
  }
  voiceUp = { baseUrl: `http://127.0.0.1:${upstream.address().port}/v1`, model: "qwen3.5-4b", apiKey: "voice-row-key" };
  // No provider rows: a qualified id would resolve through the DOOR again, and
  // this leg is the VOICE path (the fast/escalate key resolved by resolveKeyFn).
  providers = {};
  try {
    for (const localAddress of [LOOPBACK, RELAY]) {
      const r = await chatCall({ localAddress, model: "crow-companion" });
      assert.equal(r.status, 200, `${localAddress}: ${r.body}`);
      assert.equal(upstreamSeen.at(-1).headers.authorization, undefined, `${localAddress}: no bearer on the voice path`);
    }
  } finally { voiceUp = null; }
});

test("RELAYED voice turn whose model key resolves to a foreign DNS NAME: refused on the string, with no lookup and no fetch", async () => {
  started = []; upstreamSeen = []; gatewaySeen = []; providers = {};
  voiceUp = { baseUrl: "http://evil.example/v1", model: "m", apiKey: "bot-chosen-key" };
  try {
    const r = await chatCall({ localAddress: RELAY });
    // 400 (the rebinding rule, judged on the host string alone). A 403 would mean
    // a resolver was consulted (the unresolved rule) and a 502 that we fetched.
    assert.equal(r.status, 400, r.body);
    assert.equal(r.json?.error?.code, "NOT_FORWARDABLE");
    assert.deepEqual(upstreamSeen, [], "no fetch");
    assert.deepEqual(gatewaySeen.map((g) => g.path), ["/llm/v1/chat/completions"], "nothing left the router");
    assert.deepEqual(started, []);
  } finally { voiceUp = null; }
});

// ---------------------------------------------------------------------------
// (b) The kiosk WebSocket on the relay mark, and the required wiring.
// ---------------------------------------------------------------------------

const kioskDeps = (over = {}) => ({
  Router: express.Router, json: express.json, WebSocketServer,
  isAllowedNetwork: () => true,
  isRelayed: (req) => isRelayedSocket(req.socket),
  csrfMiddleware: (_req, _res, next) => next(),
  openDb: () => ({ execute: async () => ({ rows: [] }), close() {} }),
  deviceStore: { listDevices: async () => [], findDevice: async () => null, verifyToken: async () => null, normalizeKioskSettings: (x) => x },
  settings: { readSetting: async () => null, writeSetting: async () => {} },
  voice: { runVoiceTurn: async () => ({ route: "fast", timings: {} }), speakText: async () => true },
  announceToken: { validate: async () => false },
  themeCss: () => "",
  files: { publicDir: new URL("../bundles/kiosk/public/", import.meta.url).pathname, birdSvgPath: new URL("../bundles/ramble/server/bird-svg.cjs", import.meta.url).pathname },
  log: () => {},
  ...over,
});

/** The upgrade's answer: the status code a refusal wrote, or "open" once a 101 lands. */
function upgradeAnswer(port, { localAddress = LOOPBACK } = {}) {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}/api/kiosk/session`, { localAddress });
    ws.on("open", () => { resolve("open"); ws.close(); });
    ws.on("unexpected-response", (_req, res) => { resolve(res.statusCode); ws.terminate(); });
    ws.on("error", () => resolve("error"));
  });
}

test("kiosk: the display socket refuses a relayed socket, and still accepts the operator's own", async () => {
  const rt = createKioskRuntime(kioskDeps());
  const app = express();
  app.use(rt.router((_req, _res, next) => next()));
  const srv = http.createServer(app);
  rt.attachUpgrade(srv);
  await new Promise((r) => srv.listen(0, LOOPBACK, r));
  const port = srv.address().port;
  try {
    assert.equal(await upgradeAnswer(port, { localAddress: RELAY }), 403, "a relayed socket never opens a display session");
    assert.equal(await upgradeAnswer(port), "open", "this machine's own display is untouched");
  } finally {
    rt.stop();
    srv.closeAllConnections?.();
    await new Promise((r) => srv.close(() => r()));
  }
});

test("kiosk: a runtime built without isRelayed throws instead of failing open", () => {
  const deps = kioskDeps();
  delete deps.isRelayed;
  assert.throws(() => createKioskRuntime(deps), /isRelayed is required/);
});

test("kiosk: a predicate that throws is treated as relayed (fail closed)", async () => {
  const rt = createKioskRuntime(kioskDeps({ isRelayed: () => { throw new Error("boom"); } }));
  const app = express();
  app.use(rt.router((_req, _res, next) => next()));
  const srv = http.createServer(app);
  rt.attachUpgrade(srv);
  await new Promise((r) => srv.listen(0, LOOPBACK, r));
  const port = srv.address().port;
  try {
    assert.equal(await upgradeAnswer(port), 403);
    const internal = await request(`http://127.0.0.1:${port}`, "GET", "/api/kiosk/internal/displays", { headers: { authorization: "Bearer whatever" } });
    assert.equal(internal.status, 403);
    assert.equal(internal.json?.error, "loopback_only");
  } finally {
    rt.stop();
    srv.closeAllConnections?.();
    await new Promise((r) => srv.close(() => r()));
  }
});