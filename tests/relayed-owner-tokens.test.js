/**
 * A token whose verifier lives in bot-writable crow.db is never accepted from a
 * relayed socket — the rest of the class `tests/oauth-refused-on-relay.test.js`
 * and `tests/local-token-relayed.test.js` open for OAuth and the full local MCP
 * token.
 *
 * A contained bot has crow.db bound read-write. Every credential below is a hash
 * the bot could therefore write for itself:
 *
 *   mcp_local_token_hash / mcp_models_token_hash   dashboard_settings (local token, models token)
 *   crow_instances.auth_token_hash                 the paired-instance bearer
 *   the services/satellite-tools token families    the loopback tool mounts
 *   kiosk_announce_token_hash                      the kiosk's announce token
 *   the first-run setup token, and the backup endpoint's loopback rule   owner authority
 *
 * None of them is a path-scoped door token, so none may authenticate a socket
 * the egress relay opened (`RELAY_SOURCE_V4`, servers/shared/bot-doors.js). What
 * a relayed caller keeps is asserted in the same tests: the model door's own
 * source rule (a bot reaches /llm/v1 and /llm/p with no bearer at all) is
 * untouched, and the same token from plain loopback still works everywhere.
 *
 * Real sockets, real DB (scripts/init-db.js in the suite's scratch home), real
 * tokens: the client binds the relay mark with `localAddress` — how the relay
 * marks its upstream connections — and the servers are the real routers and
 * middleware.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";

import llmRouterRouter from "../servers/gateway/routes/llm-router.js";
import llmModelsRouter from "../servers/gateway/routes/llm-models.js";
import { instanceAuthMiddleware, validateInstanceToken } from "../servers/gateway/instance-registry.js";
import { loopbackActorGate } from "../servers/gateway/loopback-gate.js";
import { allowFirstRun } from "../servers/gateway/dashboard/setup-token.js";
import { requireLocalhost } from "../servers/gateway/routes/admin-backup.js";
import { validateLocalToken, validateModelsToken } from "../servers/gateway/local-token.js";
import { writeSetting } from "../servers/gateway/dashboard/settings/registry.js";
import { RELAY_SOURCE_V4 } from "../servers/shared/bot-doors.js";
import { classifyPeer } from "../servers/shared/peer-class.js";
import { createDbClient } from "../servers/db.js";
import { createKioskRuntime } from "../bundles/kiosk/server/runtime.js";
import * as deviceStore from "../servers/shared/device-store.js";
import { WebSocketServer } from "ws";
import { wrapPcmAsWav } from "../servers/gateway/voice/turn-helpers.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RELAY = RELAY_SOURCE_V4;      // the mark a relayed socket carries
const LOOPBACK = "127.0.0.1";

const LOCAL_TOKEN = "relay-test-full-local-token";
const MODELS_TOKEN = "relay-test-models-token";
const PEER_TOKEN = "relay-test-paired-instance-token";
const ANNOUNCE_TOKEN = "relay-test-kiosk-announce-token";

// Its own home and database inside the suite's scratch home (unsets = not run
// through npm test: refuse).
if (!process.env.CROW_HOME) throw new Error("run through npm test (scripts/run-suite.mjs), never raw node --test");
const HOME = join(process.env.CROW_HOME, "relayed-owner-tokens");
mkdirSync(join(HOME, "data"), { recursive: true });
const SAVED = {};
for (const k of ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH", "CROW_SETUP_TOKEN"]) SAVED[k] = process.env[k];
process.env.CROW_HOME = HOME;
process.env.CROW_DATA_DIR = join(HOME, "data");
delete process.env.CROW_DB_PATH;
delete process.env.CROW_SETUP_TOKEN;

const sha = (s) => createHash("sha256").update(s).digest("hex");

let db, mainServer, kioskServer, kioskRuntime, upstream, upstreamSeen = [];
let mainBase, kioskBase;

/** A request from a chosen source address — the only way to carry the relay mark. */
function request(base, method, path, { localAddress = LOOPBACK, headers = {}, body = null } = {}) {
  const url = new URL(base);
  return new Promise((resolve2, reject) => {
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
      res.on("end", () => resolve2({ status: res.statusCode, headers: res.headers, body: text }));
    });
    req.on("error", reject);
    req.end(data ?? undefined);
  });
}

before(async () => {
  // The real schema, so every validator below is the production one (the
  // settings registry resolves per-instance overrides, the instance registry
  // needs its own row).
  execFileSync(process.execPath, [join(ROOT, "scripts", "init-db.js")], { env: process.env, stdio: "ignore", timeout: 120_000 });
  db = createDbClient();
  // The rows a contained bot could write for itself: real hashes, real tokens. Seeded the way the
  // PRODUCT writes them — a local-scope override (design OQ-8: a per-instance token key is never
  // read from the global `dashboard_settings` row, so a global fixture would now seed nothing).
  await writeSetting(db, "mcp_local_token_hash", sha(LOCAL_TOKEN), { scope: "local" });
  await writeSetting(db, "mcp_models_token_hash", sha(MODELS_TOKEN), { scope: "local" });
  await db.execute({
    sql: "INSERT OR REPLACE INTO crow_instances (id, name, crow_id, auth_token_hash, trusted, status) VALUES (?, ?, ?, ?, 1, 'active')",
    args: ["peer-a", "A paired peer", "peer-crow-id", sha(PEER_TOKEN)],
  });

  // A local model upstream, so an admitted door request really answers 200.
  upstream = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      upstreamSeen.push({ path: req.url, body });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
  });
  await new Promise((r) => upstream.listen(0, LOOPBACK, r));
  const upUrl = `http://127.0.0.1:${upstream.address().port}/v1`;
  const providers = {
    "crow-voice": { baseUrl: upUrl, apiKey: "none", models: [{ id: "qwen3.5-4b" }], gpuPolicy: { runtime: "native", owner: "me", port: 1 } },
  };

  const app = express();
  app.use(express.json());
  // The gateway's rail order, reduced to what matters here: instance auth, then
  // the model routes (both with their REAL credential checks).
  app.use(instanceAuthMiddleware(db));
  app.use(llmRouterRouter({
    acquireFn: async () => true,
    resolveKeyFn: async (key) => ({ baseUrl: upUrl, model: key.split("/")[1], apiKey: null }),
    probeReadyFn: async () => true,
    warmFn: async () => true,
    loadProvidersFn: () => ({ providers }),
    // The REAL source rule: the socket's own address, not a test override.
    remoteAddressFn: (req) => req.socket?.remoteAddress || "",
    resolveVoiceKeysFn: async () => ({ fast: "crow-voice/qwen3.5-4b", escalate: "crow-chat/qwen3.6-35b-a3b" }),
    recordUsageFn: async () => {},
    nowFn: Date.now,
    enforceFn: () => false,
    logFn: () => {},
  }));
  app.use(llmModelsRouter({ loadProvidersFn: () => ({ providers: {} }) }));
  app.get("/whoami", (req, res) => res.json({ instance: req.instanceAuth?.instance?.id ?? null }));
  app.post("/api/admin/backup", requireLocalhost, (req, res) => res.json({ ok: true }));

  mainServer = http.createServer(app);
  await new Promise((r) => mainServer.listen(0, LOOPBACK, r));
  mainBase = `http://127.0.0.1:${mainServer.address().port}`;

  // The kiosk's real router, over a real socket, with its announce token.
  const kioskApp = express();
  kioskRuntime = createKioskRuntime({
    Router: express.Router, json: express.json, WebSocketServer,
    isAllowedNetwork: () => true,
    csrfMiddleware: (req, res, next) => next(),
    // A fresh client per use, as bundles/kiosk/panel/routes.js passes it (the
    // runtime closes the client it opened).
    openDb: () => createDbClient(),
    deviceStore,
    settings: { readSetting: async () => null, writeSetting: async () => {} },
    voice: { runVoiceTurn: async () => ({ route: "fast", timings: {} }), speakText: async () => true },
    sttWarmup: async () => {},
    resolveDisplayBird: async () => ({ species: "crow", seed: 0, mood: "happy", outfit: null, source: "default" }),
    themeCss: () => ":root{--k-sky:#eef1f3}",
    files: {
      publicDir: join(ROOT, "bundles", "kiosk", "public"),
      birdSvgPath: join(ROOT, "bundles", "ramble", "server", "bird-svg.cjs"),
    },
    announceToken: { validate: async (d, t) => t === ANNOUNCE_TOKEN },
    // Exactly what bundles/kiosk/panel/routes.js passes: core's bot relay mark.
    isRelayed: (req) => req.socket?.remoteAddress === RELAY || req.socket?.remoteAddress === "::ffff:" + RELAY,
    wrapPcmAsWav,
    log: () => {},
  });
  kioskApp.use(kioskRuntime.router((req, res, next) => next()));
  kioskServer = http.createServer(kioskApp);
  kioskRuntime.attachUpgrade(kioskServer);
  await new Promise((r) => kioskServer.listen(0, LOOPBACK, r));
  kioskBase = `http://127.0.0.1:${kioskServer.address().port}`;
});

after(async () => {
  try { kioskRuntime?.stop?.(); } catch {}
  for (const s of [mainServer, kioskServer, upstream]) {
    s?.closeAllConnections?.();
    await new Promise((r) => (s ? s.close(() => r()) : r()));
  }
  try { db?.close(); } catch {}
  try { rmSync(HOME, { recursive: true, force: true }); } catch {}
  for (const [k, v] of Object.entries(SAVED)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
});

const chat = (opts) => request(mainBase, "POST", "/llm/v1/chat/completions",
  { body: { model: "crow-voice/qwen3.5-4b", messages: [{ role: "user", content: "hi" }] }, ...opts });
/** A source the door's rule refuses, so the bearer is the ONLY thing that could admit it. */
const FORWARDED = { "x-forwarded-for": "203.0.113.9" };

test("the tokens are real, and the model door refuses them on a relayed socket", async () => {
  // Precondition for everything below: not stubs, so "refused on a relayed
  // socket" cannot be a bad-token artefact.
  assert.equal(await validateLocalToken(db, LOCAL_TOKEN), true);
  assert.equal(await validateModelsToken(db, MODELS_TOKEN), true);
  assert.equal((await validateInstanceToken(db, PEER_TOKEN))?.id, "peer-a");

  // The full local token and the models token ARE the escapes from the source
  // rule when the socket is not relayed…
  const loopbackLocal = await chat({ headers: { authorization: `Bearer ${LOCAL_TOKEN}`, ...FORWARDED } });
  assert.equal(loopbackLocal.status, 200, "a non-relayed caller with a valid local token is untouched");
  const loopbackModels = await chat({ headers: { authorization: `Bearer ${MODELS_TOKEN}`, ...FORWARDED } });
  assert.equal(loopbackModels.status, 200, "…and the models token is the door's other bearer, as before");

  // …and they open nothing at all on a relayed socket.
  for (const [name, token] of [["local", LOCAL_TOKEN], ["models", MODELS_TOKEN]]) {
    const r = await chat({ localAddress: RELAY, headers: { authorization: `Bearer ${token}`, ...FORWARDED } });
    assert.equal(r.status, 403, `the ${name} token must not admit a relayed socket`);
    assert.equal(JSON.parse(r.body).error.code, "DOOR_SOURCE_REFUSED");
  }
});

test("the model door's own relayed path still works: no bearer, no forwarding header", async () => {
  // A contained bot reaches /llm/v1 and /llm/p on its loopback mark, with no
  // bearer at all. That is the legitimate door and it stays open.
  const r = await chat({ localAddress: RELAY });
  assert.equal(r.status, 200, "a relayed bot's own door is untouched");
  assert.match(upstreamSeen.at(-1).path, /chat\/completions$/);
});

test("/llm/models (lifecycle): both bearer tokens work on loopback and neither on a relayed socket", async () => {
  for (const [name, token] of [["local", LOCAL_TOKEN], ["models", MODELS_TOKEN]]) {
    const ok = await request(mainBase, "GET", "/llm/models", { headers: { authorization: `Bearer ${token}` } });
    assert.equal(ok.status, 200, `${name}: the lifecycle API is reachable with its token from loopback`);
    assert.match(ok.body, /"models"/);

    const refused = await request(mainBase, "GET", "/llm/models",
      { localAddress: RELAY, headers: { authorization: `Bearer ${token}` } });
    assert.equal(refused.status, 401, `${name}: a relayed socket is refused, whatever token it carries`);
    assert.match(JSON.parse(refused.body).error.message, /bearer token required/);
  }
  // No bearer, no party — the relay changes nothing about that part.
  assert.equal((await request(mainBase, "GET", "/llm/models", { localAddress: RELAY })).status, 401);
});

test("instance auth: a relayed socket is never the paired instance", async () => {
  const ok = await request(mainBase, "GET", "/whoami", { headers: { authorization: `Bearer ${PEER_TOKEN}` } });
  assert.equal(ok.status, 200);
  assert.deepEqual(JSON.parse(ok.body), { instance: "peer-a" }, "a peer's bearer names the peer from loopback");

  const refused = await request(mainBase, "GET", "/whoami",
    { localAddress: RELAY, headers: { authorization: `Bearer ${PEER_TOKEN}` } });
  assert.equal(refused.status, 200);
  assert.deepEqual(JSON.parse(refused.body), { instance: null }, "on a relayed socket the token authenticates nothing");
});

test("a loopback tool mount refuses a relayed socket before the family token is even read", async () => {
  const req = (localAddress) => ({
    socket: { remoteAddress: localAddress }, headers: { authorization: "Bearer family-token" }, instanceAuth: null,
  });
  const deps = { validateToken: async () => true, verify: async () => ({ kind: "bot", botId: "b" }), resolve: async () => ({ scope: "own" }) };

  const ok = await loopbackActorGate(req(LOOPBACK), deps);
  assert.equal(ok.ok, true, "the operator's own services/satellite-tools mount is untouched");

  const refused = await loopbackActorGate(req(RELAY), deps);
  assert.deepEqual(refused, { ok: false, status: 404, code: "not_found" },
    "a relayed socket gets the non-local answer, as if it were remote");
});

test("first-run setup: a relayed socket neither gets the loopback exemption nor may use the setup token", async () => {
  const passwd = join(HOME, "passwd");
  writeFileSync(passwd, "root:x:0:0:root:/root:/bin/bash\nowner:x:1000:1000::/home/owner:/bin/bash\n");
  const opts = { crowHome: HOME, hasPassword: false, env: {}, passwdPath: passwd, uid: 1000 };
  const req = (localAddress) => ({
    socket: { remoteAddress: localAddress },
    headers: { host: "127.0.0.1:3001" },
    body: {},
  });

  assert.deepEqual(allowFirstRun(req(LOOPBACK), opts), { allowed: true, token: null },
    "the owner at this machine's console still sets the first password");
  assert.equal(allowFirstRun(req(RELAY), opts).allowed, false,
    "a relayed socket is not this machine's console, so it never gets the exemption");

  // The token itself does not help it either: the refusal is about the socket.
  const { token } = allowFirstRun(req(LOOPBACK), opts);   // creates/reads the file-backed token
  void token;
  const { getSetupToken } = await import("../servers/gateway/dashboard/setup-token.js");
  const real = getSetupToken({ crowHome: HOME }).token;
  const withToken = (localAddress) => ({
    socket: { remoteAddress: localAddress }, headers: { host: "127.0.0.1:3001" }, body: { setup_token: real },
  });
  assert.equal(allowFirstRun(withToken(LOOPBACK), opts).allowed, true, "the setup link works on this machine");
  assert.equal(allowFirstRun(withToken(RELAY), opts).allowed, false, "and never from a relayed socket");
});

test("admin backup: 'localhost only' does not include the relay's loopback mark", async () => {
  const onBox = (localAddress) => {
    const req = { socket: { remoteAddress: localAddress }, headers: {} };
    req.crowPeer = classifyPeer(req);
    return req;
  };
  const req = onBox(LOOPBACK);
  let passed = false;
  requireLocalhost(req, { status: () => ({ json: () => {} }) }, () => { passed = true; });
  assert.equal(passed, true, "the operator's own console may run a backup");

  const relayed = onBox(RELAY);
  assert.equal(relayed.crowPeer.via, "local", "the mark IS loopback by address, which is exactly why it needs the check");
  const results = [];
  requireLocalhost(relayed, { status: (s) => ({ json: (b) => { results.push({ status: s, body: b }); } }) },
    () => assert.fail("a relayed socket must never reach the handler"));
  assert.equal(results[0].status, 403);

  // …and over a real socket, the route answers both.
  assert.equal((await request(mainBase, "POST", "/api/admin/backup", { body: {} })).status, 200);
  assert.equal((await request(mainBase, "POST", "/api/admin/backup", { body: {}, localAddress: RELAY })).status, 403);
});

test("kiosk announce: the internal routes refuse a relayed socket, with the token or without", async () => {
  const headers = { authorization: `Bearer ${ANNOUNCE_TOKEN}` };
  const ok = await request(kioskBase, "GET", "/api/kiosk/internal/displays", { headers });
  assert.equal(ok.status, 200, "the kiosk's own tool server, over loopback, still announces");
  assert.match(ok.body, /"displays"/);

  const withToken = await request(kioskBase, "GET", "/api/kiosk/internal/displays", { localAddress: RELAY, headers });
  assert.equal(withToken.status, 403, "a relayed socket never reaches the announce routes with the token");
  assert.match(withToken.body, /loopback_only/);

  const noToken = await request(kioskBase, "GET", "/api/kiosk/internal/displays", { localAddress: RELAY });
  assert.equal(noToken.status, 403, "and the token is never even looked at: the answer is the loopback rule, not 401");
});