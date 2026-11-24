/**
 * THE ADAPTER GUARD (round B of the confused-deputy fix): every model call a
 * provider adapter makes passes the own-host path rule and DNS pinning.
 *
 * Round A put that rule on the door (`routes/llm-router.js`), the voice route
 * (`handleChat`) and `completeText`. But the REAL in-process voice loop
 * (`voice/turn.js` → `ai/provider.js` `createAdapterFromProfile`) and dashboard
 * chat (`routes/chat.js`) call the model through the provider ADAPTER — which
 * opened its own `fetch` — so a bot that writes a `providers` row could make the
 * owner's next kiosk/glasses/phone/dashboard turn POST to
 * `http://127.0.0.1:<port>/llm/acquire?x=` (the appended `/chat/completions`
 * swallowed by the query) on a fresh, unmarked, loopback-trusted socket, or
 * rebind a name to 127.0.0.1, carrying the row's key along.
 *
 * These tests drive the REAL adapters (openai / anthropic / google / ollama),
 * the real `ai/vision.js` model call and real HTTP listeners on loopback — not
 * mocks of the request sites. Each request kind is exercised four ways:
 *   (i)   an allowed own-host `/v1` server: works, and the row's key is never
 *         sent (`Authorization` absent on the wire);
 *   (ii)  a bot-written own-host row at `/llm/acquire?x=`: refused with
 *         SELF_TARGET_REFUSED before any socket, the listener is never hit;
 *   (iii) a rebinding name (a fake resolver answers a public address first, then
 *         127.0.0.1): the ONE vetted answer is pinned, the loopback listener is
 *         never reached;
 *   (iv)  a public host stub through the pinned transport: the key is KEPT and
 *         the SSE body still streams incrementally (not buffered).
 * Plus the fleet's enabled provider rows as one decision table (no network) and
 * the two real consumer paths (a voice turn, the dashboard chat route) against a
 * bot-written attack row.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { isIP } from "node:net";
import { PassThrough } from "node:stream";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

import createOpenAIAdapter from "../servers/gateway/ai/adapters/openai.js";
import createAnthropicAdapter from "../servers/gateway/ai/adapters/anthropic.js";
import createGoogleAdapter from "../servers/gateway/ai/adapters/google.js";
import createOllamaAdapter from "../servers/gateway/ai/adapters/ollama.js";
import { analyzeImage } from "../servers/gateway/ai/vision.js";
import { createAdapterFromProfile } from "../servers/gateway/ai/provider.js";
import {
  judgeAdapterTarget, guardedFetch, withoutCredentials, carriesCredentials,
  responseFromStream, selfTargetRefused, SELF_REFUSED_MESSAGE,
} from "../servers/gateway/ai/adapter-guard.js";
import { isKnownLocalModelTarget } from "../servers/gateway/models/local-model-servers.js";
import { fakeProcRoot, loopbackLookup } from "./fixtures/vouch-proc.mjs";
import { harness } from "./fixtures/voice-turn-harness.mjs";

// Placeholder-safe addresses only (public hygiene): the box's own tailnet IP is
// 100.64.20.1, a LAN peer is 10.0.0.x, a tailnet peer is another 100.64.20.x, and
// public-host stubs live in TEST-NET-3 (203.0.113.0/24).
const OWN_IP = "100.64.20.1";
const LAN_PEER = "10.0.0.50";
const TAILNET_PEER = "100.64.20.9";
const PUBLIC = "203.0.113.9";
const OWN = new Set(["127.0.0.1", OWN_IP]);

// --- listeners ---------------------------------------------------------------

const servers = [];
after(async () => {
  for (const s of servers) {
    try { s.closeAllConnections?.(); } catch { /* already gone */ }
    await new Promise((r) => s.close(() => r()));
  }
});

/** A real HTTP listener on loopback that records every request it sees. */
async function listen(handler) {
  const hits = [];
  const server = http.createServer((req, res) => {
    const rec = { method: req.method, url: req.url, path: req.url, headers: req.headers, body: "", acked: null };
    hits.push(rec);
    req.on("data", (c) => { rec.body += c.toString("utf8"); });
    req.on("end", () => handler(req, res, rec));
  });
  servers.push(server);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return { hits, port, base: `http://127.0.0.1:${port}` };
}

const sse = (obj) => `data: ${JSON.stringify(obj)}\n\n`;
const SSE = { "content-type": "text/event-stream" };
const chatChunk = (text) => sse({ choices: [{ index: 0, delta: { content: text } }] });
const chunkText = (chunk) => JSON.parse(String(chunk).replace(/^data: /, "")).choices[0].delta.content;

/** A fake resolver: every answer comes from `answers`, one entry per call (the
 *  last entry repeats), so "public, then the rebind" is expressible. */
function fakeLookup(answers) {
  const calls = [];
  const fn = (host, opts, cb) => {
    const list = answers[Math.min(calls.length, answers.length - 1)] || [];
    calls.push(host);
    if (!list.length) return cb(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
    return cb(null, list.map((address) => ({ address, family: isIP(address) })));
  };
  fn.calls = calls;
  return fn;
}

/** Answer the lookup the socket would use and record what it said (round A's
 *  `pinnedRequest` trick): the proof that the pin, not a second resolution, is
 *  what a rebindable name connects to. */
const pinnedRequest = (streamFor, calls) => async (url, opts) => {
  const looked = await new Promise((resolve, reject) => {
    opts.lookupFn(new URL(url).hostname, { all: true }, (e, a) => (e ? reject(e) : resolve(a)));
  });
  calls.push({ url, looked, headers: opts.headers, opts });
  return { status: 200, headers: SSE, stream: streamFor() };
};

test("no chat-adapter model request opens its own socket: every request site is guardedFetch", () => {
  // The guard only covers calls that go THROUGH it, so the request sites are
  // pinned here: an adapter that grows a bare `fetch` again would silently
  // reopen the hole this round closes.
  const sites = [
    "../servers/gateway/ai/adapters/openai.js",
    "../servers/gateway/ai/adapters/anthropic.js",
    "../servers/gateway/ai/adapters/google.js",
    "../servers/gateway/ai/adapters/ollama.js",
    "../servers/gateway/ai/vision.js",
    "../servers/gateway/ai/provider.js",
  ];
  for (const rel of sites) {
    const src = readFileSync(new URL(rel, import.meta.url), "utf8");
    assert.match(src, /from "\.\.?\/(ai\/)?adapter-guard\.js"|from "\.\/adapter-guard\.js"/, `${rel} must import the guard`);
    assert.match(src, /guardedFetch\(/, `${rel} must call guardedFetch`);
    const raw = src.split("\n").map((line, i) => [i + 1, line])
      .filter(([, line]) => /(^|[^A-Za-z_.])fetch\s*\(/.test(line))
      .filter(([, line]) => !/guardedFetch|fetchFn/.test(line))
      .filter(([, line]) => !/^\s*(\*|\/\/)/.test(line));   // comment mentions are fine
    assert.deepEqual(raw, [], `${rel} still opens its own request: ${JSON.stringify(raw)}`);
  }
});

// ---------------------------------------------------------------------------
// The fleet's enabled provider rows, as one decision table (no network).
// ---------------------------------------------------------------------------

/**
 * Mirrors the enabled rows on the fleet's two instances (the operator's box and
 * the peer install): every one of them must pass the guard unchanged, the only
 * change being that an OWN-HOST row loses its key. Real tailnet IPs are written
 * here as 100.64.20.x placeholders and the LAN peer as 10.0.0.x; the SHAPE is
 * what matters — own tailnet IP on ports 8001-8014, loopback, a LAN peer, a
 * tailnet peer, and public cloud hosts.
 */
/**
 * The own-host VOUCH (`models/local-model-servers.js`) is exercised for real in
 * `tests/local-model-allowlist.test.js` (fake /proc, fake vouch snapshot, real
 * listeners). THIS file's decision table is about the ADDRESS and PATH rule, so
 * the vouch is stubbed to "vouched": no model server listens on the fixture
 * addresses below in a test sandbox.
 */
const vouched = async () => ({ local: true, reason: "vouched" });

const FLEET_ROWS = [
  // [id, base_url, operation, own-host?]
  ["crow-chat", `http://${OWN_IP}:8003/v1`, "chat/completions", true],
  ["cloud-openai-87b335f1", "https://api.z.ai/api/coding/paas/v4", "chat/completions", false],
  ["crow-local", `http://${OWN_IP}:8003/v1`, "chat/completions", true],
  ["zai-coding", "https://api.z.ai/api/coding/paas/v4", "chat/completions", false],
  ["crow-voice", `http://${OWN_IP}:8011/v1`, "chat/completions", true],
  ["crow-local-27b", `http://${OWN_IP}:8006/v1`, "chat/completions", true],
  ["crow-local-27b-copilot", `http://${OWN_IP}:8010/v1`, "chat/completions", true],
  ["Qwen Cloud", "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1", "chat/completions", false],
  ["crow-local-27b-512k", `http://${OWN_IP}:8014/v1`, "chat/completions", true],
  ["qwen3.5-4b", "http://127.0.0.1:18100/v1", "chat/completions", true],
  ["raven-flash-next", `http://${LAN_PEER}:8030/v1`, "chat/completions", false],
  ["qwen-cloud", "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1", "chat/completions", false],
  ["crow-embed", `http://${OWN_IP}:8004/v1`, "embeddings", true],
  ["crow-vision", "http://127.0.0.1:8012/v1", "chat/completions", true],
  ["openrouter", "https://openrouter.ai/api/v1", "chat/completions", false],
  // the co-hosted second instance's rows
  ["crow-llm", "http://localhost:3001/llm/v1", "chat/completions", true],
  ["crow-dispatch", `http://${OWN_IP}:8001/v1`, "chat/completions", true],
  ["crow-swap-coder", `http://${OWN_IP}:8003/v1`, "chat/completions", true],
  ["crow-swap-deep", `http://${OWN_IP}:8003/v1`, "chat/completions", true],
  ["crow-local-122b", `http://${OWN_IP}:8004/v1`, "chat/completions", true],
  ["crow-local-oss", `http://${OWN_IP}:8005/v1`, "chat/completions", true],
  ["crow-local-nemotron", `http://${OWN_IP}:8008/v1`, "chat/completions", true],
  ["crow-local-nano", `http://${OWN_IP}:8009/v1`, "chat/completions", true],
  // the peer instance's embedding row (a remote tailnet peer, not own-host)
  ["grackle-embed", `http://${TAILNET_PEER}:9100/v1`, "embeddings", false],
];

test("every enabled provider row on the fleet passes the adapter guard, and only own-host rows lose their key", async () => {
  // A stub resolver for the public cloud rows (no network in this test): a name
  // never answers with this host, so the pin is what a cloud host rides.
  const lookupFn = (host, opts, cb) => cb(null, [{ address: PUBLIC, family: 4 }]);
  for (const [id, base, op, own] of FLEET_ROWS) {
    const url = `${base.replace(/\/+$/, "")}/${op}`;
    const decision = await judgeAdapterTarget(url, { ownAddrs: OWN, lookupFn, knownLocalTargetFn: vouched });
    assert.notEqual(decision.mode, "refused", `${id} (${url}) must stay usable`);
    if (own) {
      assert.equal(decision.mode, "own", `${id} (${url}) is this host`);
      assert.equal(withoutCredentials({ "Content-Type": "application/json", Authorization: "Bearer row-key" }).Authorization, undefined, id);
    } else {
      assert.equal(decision.mode === "pinned" || decision.mode === "direct", true, `${id} (${url}) is remote`);
      assert.equal(carriesCredentials({ "Content-Type": "application/json", Authorization: "Bearer row-key" }), true, id);
    }
  }
});

test("the guard's refusal is the existing fixed wording, never the bot-written URL", () => {
  const err = selfTargetRefused();
  assert.equal(err.code, "SELF_TARGET_REFUSED");
  assert.equal(err.message, SELF_REFUSED_MESSAGE);
  assert.equal(err.message, "Crow will not contact that address");
});

// ---------------------------------------------------------------------------
// The prod own-host SHAPES and the REAL vouch (models/local-model-servers.js):
// a Docker-published port whose LISTEN socket docker-proxy holds as ROOT (uid 0)
// is trusted without a pid lookup, which is what keeps a container-installed
// model usable. Nothing here is dialled.
// ---------------------------------------------------------------------------

test("the prod own-host model shapes pass the real vouch (a docker-proxy uid-0 listener on a Docker-published port)", async () => {
  const procRoot = fakeProcRoot({ rows: [
    { address: "127.0.0.1", port: 8012, uid: 0 },     // crow-vision, a container
    { address: "127.0.0.1", port: 11434, uid: 0 },    // the Ollama bundle (compose publishes 127.0.0.1:11434)
    { address: "100.64.20.5", port: 8004, uid: 0 },   // crow-embed, a container on this box's tailnet address
  ] });
  const vouchDeps = {
    crowHome: procRoot, procRoot, uid: 7100, selfPid: -1,
    ownAddrs: new Set(["127.0.0.1", "100.64.20.5"]), lookupFn: loopbackLookup,
    dockerEntries: [
      { address: "127.0.0.1", port: 8012 },
      { address: "127.0.0.1", port: 11434 },
      { address: "100.64.20.5", port: 8004 },
    ],
  };
  const knownLocalTargetFn = (url) => isKnownLocalModelTarget(url, vouchDeps);
  // 100.64.20.5 is THIS box's tailnet address in these tests (the placeholder for
  // the real one), so the judge is told it is own-host — the same seam the fleet
  // table above uses.
  const ownAddrs = vouchDeps.ownAddrs;
  try {
    const rows = [
      ["http://127.0.0.1:8012/v1/chat/completions", "model"],
      ["http://127.0.0.1:8012/v1/models", "probe"],
      ["http://localhost:11434/api/chat", "ollama"],
      ["http://localhost:11434/api/embed", "ollama"],
      ["http://100.64.20.5:8004/v1/embeddings", "model"],
    ];
    for (const [url, kind] of rows) {
      const d = await judgeAdapterTarget(url, { kind, knownLocalTargetFn, ownAddrs, lookupFn: loopbackLookup });
      assert.equal(d.mode, "own", `${url} (${kind}) is a prod shape and must stay usable`);
    }
    // The SAME addresses with nothing vouching them: refused. A vouch is not a
    // port number and not an address class (the vouch is what Docker supplies).
    const unvouched = (url) => isKnownLocalModelTarget(url, { ...vouchDeps, dockerEntries: [] });
    for (const [url, kind] of rows) {
      const d = await judgeAdapterTarget(url, { kind, knownLocalTargetFn: unvouched, ownAddrs, lookupFn: loopbackLookup });
      assert.equal(d.mode, "refused", `${url} with nothing vouching the port`);
    }
  } finally {
    rmSync(procRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// FORBIDDEN TARGETS (link-local / cloud metadata), for EVERY caller and judged
// on the address: an IP LITERAL never reached the name-based checks before, so
// `http://169.254.169.254/v1/chat/completions` was called "not this host" and
// dialled. The bot-writable row makes that refusal every caller's business.
// ---------------------------------------------------------------------------

test("a forbidden target is refused for every caller, literal or resolved, and nothing is dialled", async () => {
  for (const url of [
    "http://169.254.169.254/v1/chat/completions",
    "http://169.254.170.2/v1/embeddings",
    "http://[::ffff:169.254.169.254]/v1/chat/completions",
    "http://metadata.google.internal/computeMetadata/v1",
    "http://[fe80::1]/v1/chat/completions",
  ]) {
    const decision = await judgeAdapterTarget(url);
    assert.equal(decision.mode, "refused", url);
  }
  // a NAME whose answer is the metadata address is refused too (one resolution)
  const lookupFn = fakeLookup([["169.254.169.254"]]);
  assert.equal((await judgeAdapterTarget("http://metadata.example.test/v1/chat/completions", { lookupFn })).mode, "refused");
  assert.equal(lookupFn.calls.length, 1);

  // the real adapter never opens a socket
  const dialled = [];
  const adapter = createOpenAIAdapter({
    baseUrl: "http://169.254.169.254/v1", apiKey: "row-key", model: "m",
    guard: { fetchFn: async (u) => { dialled.push(u); return new Response("{}", { status: 200 }); } },
  });
  await assert.rejects(
    () => adapter.chatStream([{ role: "user", content: "hi" }], []).next(),
    (e) => e.code === "SELF_TARGET_REFUSED" && e.message === SELF_REFUSED_MESSAGE,
  );
  assert.deepEqual(dialled, [], "no transport was opened");
});

// ---------------------------------------------------------------------------
// (i) an ALLOWED own-host /v1 server: works, and the row's key never rides it.
// ---------------------------------------------------------------------------

test("streaming chat through the openai adapter to an allowed own-host /v1 server streams incrementally, with no Authorization", async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const timer = setTimeout(() => release(false), 3000);
  const s = await listen((req, res, rec) => {
    res.writeHead(200, SSE);
    res.write(chatChunk("Hel"));
    // The second half is written only once the CLIENT has already seen the first
    // delta: a buffered body could never reach this point.
    gate.then((acked) => {
      rec.acked = acked;
      res.write(chatChunk("lo"));
      res.end("data: [DONE]\n\n");
    });
  });
  const adapter = createOpenAIAdapter({ baseUrl: `${s.base}/v1`, apiKey: "bot-key", model: "m" });
  const deltas = [];
  let done = null;
  for await (const ev of adapter.chatStream([{ role: "user", content: "hi" }], [])) {
    if (ev.type === "content_delta") {
      deltas.push(ev.text);
      release(true);
    }
    if (ev.type === "done") done = ev;
  }
  clearTimeout(timer);
  assert.deepEqual(deltas, ["Hel", "lo"]);
  assert.equal(s.hits[0].acked, true, "the first delta arrived while the response was still open");
  assert.equal(s.hits[0].path, "/v1/chat/completions");
  assert.equal(s.hits[0].headers.authorization, undefined, "no key on a request that lands on this box");
  assert.ok(done);
});

test("a plain completion through the openai adapter to an allowed own-host /v1 server answers with no Authorization", async () => {
  const s = await listen((req, res) => {
    res.writeHead(200, SSE);
    res.write(chatChunk("Lisbon"));
    res.write(chatChunk(" is the capital."));
    res.end(`${sse({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 7, completion_tokens: 4 } })}data: [DONE]\n\n`);
  });
  const adapter = createOpenAIAdapter({ baseUrl: `${s.base}/v1`, apiKey: "bot-key", model: "m" });
  const events = [];
  for await (const ev of adapter.chatStream([{ role: "user", content: "capital of Portugal?" }], [])) events.push(ev);
  assert.equal(events.filter((e) => e.type === "content_delta").map((e) => e.text).join(""), "Lisbon is the capital.");
  assert.equal(events.at(-1).type, "done");
  assert.equal(events.at(-1).usage.input_tokens, 7);
  assert.equal(s.hits[0].headers.authorization, undefined);
});

test("a tool-call response through the openai adapter to an allowed own-host /v1 server passes through unchanged", async () => {
  const s = await listen((req, res) => {
    res.writeHead(200, SSE);
    res.write(sse({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, id: "c1", type: "function", function: { name: "crow_wm", arguments: "" } }] } }] }));
    res.write(sse({ choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: "{\"command\":\"list\"}" } }] } }] }));
    res.write(sse({ choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }] }));
    res.end("data: [DONE]\n\n");
  });
  const adapter = createOpenAIAdapter({ baseUrl: `${s.base}/v1`, apiKey: "bot-key", model: "m" });
  const calls = [];
  for await (const ev of adapter.chatStream([{ role: "user", content: "show the list" }], [{ name: "crow_wm", inputSchema: { type: "object" } }])) {
    if (ev.type === "tool_call") calls.push(ev);
  }
  assert.deepEqual(calls, [{ type: "tool_call", id: "c1", name: "crow_wm", arguments: { command: "list" } }]);
  assert.equal(s.hits[0].headers.authorization, undefined);
});

test("a vision request with an image part through the openai adapter to an allowed own-host /v1 server passes the image unchanged", async () => {
  const s = await listen((req, res) => {
    res.writeHead(200, SSE);
    res.write(chatChunk("a bird on a wire"));
    res.end("data: [DONE]\n\n");
  });
  const dataUrl = "data:image/png;base64,iVBORw0KGgo=";
  const adapter = createOpenAIAdapter({ baseUrl: `${s.base}/v1`, apiKey: "bot-key", model: "vision" });
  const events = [];
  for await (const ev of adapter.chatStream(
    [{ role: "user", content: "what is this?", _imageUrls: [dataUrl] }],
    [],
  )) events.push(ev);
  const sent = JSON.parse(s.hits[0].body);
  assert.deepEqual(sent.messages[0].content, [
    { type: "text", text: "what is this?" },
    { type: "image_url", image_url: { url: dataUrl } },
  ], "the image content part is unchanged");
  assert.deepEqual(events.filter((e) => e.type === "content_delta").map((e) => e.text), ["a bird on a wire"]);
  assert.equal(s.hits[0].headers.authorization, undefined);

  // ai/vision.js's own model call (the glasses / library caption path) is the
  // same request shape and the same guard.
  const v = await listen((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ choices: [{ message: { content: "a bird" } }] }));
  });
  const out = await analyzeImage({
    providerConfig: { baseUrl: `${v.base}/v1`, apiKey: "bot-key", model: "vision" },
    prompt: "describe",
    imageBytes: Buffer.from("\x89PNG", "latin1"),
    mime: "image/png",
  });
  assert.equal(out.description, "a bird");
  assert.equal(JSON.parse(v.hits[0].body).messages[0].content[0].type, "image_url");
  assert.equal(v.hits[0].headers.authorization, undefined);
});

// ---------------------------------------------------------------------------
// (ii) a bot-written own-host row at /llm/acquire?x=: refused, never dialled.
// ---------------------------------------------------------------------------

test("a bot-written own-host row at /llm/acquire?x= is refused by the openai adapter and the route is never hit", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end("{}"); });
  const adapter = createOpenAIAdapter({ baseUrl: `${s.base}/llm/acquire?x=`, apiKey: "bot-key", model: "m" });
  await assert.rejects(
    () => adapter.chatStream([{ role: "user", content: "hi" }], []).next(),
    (e) => e.code === "SELF_TARGET_REFUSED" && e.message === SELF_REFUSED_MESSAGE,
  );
  assert.deepEqual(s.hits, [], "the model lifecycle route was never reached");
});

test("every adapter module refuses an own-host target that is not a model-operation path", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end("{}"); });
  const adapters = [
    // openai: the query swallows the appended /chat/completions
    createOpenAIAdapter({ baseUrl: `${s.base}/llm/acquire?x=`, apiKey: "k", model: "m" }),
    // anthropic: /v1/messages is not an operation a request may run here
    createAnthropicAdapter({ baseUrl: `${s.base}/v1`, apiKey: "k", model: "m" }),
    // google: a Gemini URL always carries a query
    createGoogleAdapter({ baseUrl: `${s.base}/v1beta`, apiKey: "k", model: "m" }),
    // ollama: `/api/chat` is allowed on an own-host OLLAMA port only (11434, the
    // bundle's fixed published port), so this listener's ephemeral port is not
    // an Ollama — the store's bundle works because it IS on 11434
    // (`tests/ollama-own-host-guard.test.js`).
    createOllamaAdapter({ baseUrl: s.base, apiKey: "k", model: "m" }),
  ];
  for (const adapter of adapters) {
    await assert.rejects(
      () => adapter.chatStream([{ role: "user", content: "hi" }], []).next(),
      (e) => e.code === "SELF_TARGET_REFUSED",
      `${adapter.name} must refuse an own-host target it may not drive`,
    );
  }
  assert.deepEqual(s.hits, [], "no adapter opened a socket");
});

test("guardedFetch drops x-api-key and api-key too, and never a credential on an own-host target", async () => {
  const s = await listen((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
  const res = await guardedFetch(`${s.base}/v1/embeddings`, {
    headers: { "Content-Type": "application/json", Authorization: "Bearer a", "x-api-key": "b", "api-key": "c", "x-goog-api-key": "d" },
    body: JSON.stringify({ input: "x" }),
  });
  assert.equal(res.status, 200);
  assert.equal(s.hits[0].headers.authorization, undefined);
  assert.equal(s.hits[0].headers["x-api-key"], undefined);
  assert.equal(s.hits[0].headers["api-key"], undefined);
  assert.equal(s.hits[0].headers["x-goog-api-key"], undefined);
});

// ---------------------------------------------------------------------------
// (iii) a rebinding name: one resolution, pinned; loopback never reached.
// ---------------------------------------------------------------------------

test("a rebinding name is resolved ONCE and pinned to the vetted address, never to the loopback answer", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end(JSON.stringify({ choices: [] })); });
  const lookupFn = fakeLookup([[PUBLIC], ["127.0.0.1"]]);
  const calls = [];
  const adapter = createOpenAIAdapter({
    baseUrl: `http://rebind.example.test:${s.port}/v1`, apiKey: "row-key", model: "m",
    guard: {
      lookupFn,
      requestFn: pinnedRequest(() => {
        const stream = new PassThrough();
        stream.end(`${chatChunk("pinned")}data: [DONE]\n\n`);
        return stream;
      }, calls),
    },
  });
  const deltas = [];
  for await (const ev of adapter.chatStream([{ role: "user", content: "hi" }], [])) {
    if (ev.type === "content_delta") deltas.push(ev.text);
  }
  assert.deepEqual(deltas, ["pinned"]);
  assert.equal(lookupFn.calls.length, 1, "the name was resolved exactly once");
  assert.deepEqual(calls[0].looked.map((a) => a.address), [PUBLIC], "the socket was given only the vetted address");
  assert.equal(calls[0].headers.Authorization, "Bearer row-key", "a pinned public name keeps its key");
  assert.deepEqual(s.hits, [], "the loopback listener (the rebind target) was never reached");
});

test("a name whose answer is a MIX of this host and a public address is a rebinding attempt: refused, nothing dialled", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end("{}"); });
  const lookupFn = fakeLookup([[PUBLIC, "127.0.0.1"]]);
  const calls = [];
  const adapter = createOpenAIAdapter({
    baseUrl: `http://mixed.example.test:${s.port}/v1`, apiKey: "row-key", model: "m",
    guard: { lookupFn, requestFn: pinnedRequest(() => new PassThrough(), calls) },
  });
  await assert.rejects(() => adapter.chatStream([{ role: "user", content: "hi" }], []).next(), (e) => e.code === "SELF_TARGET_REFUSED");
  assert.deepEqual(calls, [], "no transport was opened");
  assert.deepEqual(s.hits, []);
});

test("a name that does not resolve is refused (fail closed), and nothing is dialled", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end("{}"); });
  const lookupFn = fakeLookup([[]]);   // ENOTFOUND
  const calls = [];
  const adapter = createOpenAIAdapter({
    baseUrl: `http://nowhere.example.test:${s.port}/v1`, apiKey: "row-key", model: "m",
    guard: { lookupFn, requestFn: pinnedRequest(() => new PassThrough(), calls) },
  });
  await assert.rejects(() => adapter.chatStream([{ role: "user", content: "hi" }], []).next(), (e) => e.code === "SELF_TARGET_REFUSED");
  assert.deepEqual(calls, []);
  assert.deepEqual(s.hits, []);
});

// ---------------------------------------------------------------------------
// N1: an UNRESOLVED host is refused for EVERY caller. A `*.ts.net` name (or any
// name) the resolver does not answer for used to take the `direct` branch — no
// pin, plain fetch — so the request left with the ONLY resolution of that name
// performed by the fetch itself, which is the rebinding window this guard
// exists to close. The request would fail on that second lookup anyway.
// ---------------------------------------------------------------------------

test("an unresolved host is refused for every caller, `*.ts.net` (not rebindable) included", async () => {
  for (const host of ["never-resolves.example.ts.net", "nowhere.example.test"]) {
    const lookupFn = fakeLookup([[]]);   // the resolver answers nothing
    const dialled = [];
    const pinnedCalls = [];
    const adapter = createOpenAIAdapter({
      baseUrl: `http://${host}:8003/v1`, apiKey: "row-key", model: "m",
      guard: {
        lookupFn,
        requestFn: pinnedRequest(() => new PassThrough(), pinnedCalls),
        // the `direct` branch's transport: before the fix this is what dialled
        fetchFn: async (u) => { dialled.push(u); throw new Error("dialled"); },
      },
    });
    await assert.rejects(
      () => adapter.chatStream([{ role: "user", content: "hi" }], []).next(),
      (e) => e.code === "SELF_TARGET_REFUSED" && e.message === SELF_REFUSED_MESSAGE,
      host,
    );
    assert.deepEqual(dialled, [], `${host}: no plain fetch on an unresolved name`);
    assert.deepEqual(pinnedCalls, [], `${host}: no pinned socket either`);
    assert.equal(lookupFn.calls.length, 1, `${host}: the name was asked exactly once`);
    // and the decision itself says so, for every kind
    for (const kind of ["model", "probe", "speech", "ollama"]) {
      const d = await judgeAdapterTarget(`http://${host}:8003/v1/chat/completions`, { lookupFn: fakeLookup([[]]), kind });
      assert.equal(d.mode, "refused", `${host} (${kind})`);
    }
  }
});

// ---------------------------------------------------------------------------
// N2: an IPv4 embedded in an IPv6 address (NAT64, SIIT, 6to4, Teredo) decides.
// `[64:ff9b::a9fe:a9fe]` IS 169.254.169.254 through a NAT64 translator, and it
// used to be "not this host" and simply dialled.
// ---------------------------------------------------------------------------

test("a metadata IPv4 embedded in NAT64 is refused, while a public IPv6 literal still works (N2)", async () => {
  for (const url of [
    "http://[64:ff9b::a9fe:a9fe]/v1/chat/completions",   // NAT64 → 169.254.169.254
    "http://[64:ff9b::a9fe:a9fe]/api/chat",              // and for the ollama kind
    "http://[::ffff:0:a9fe:a9fe]/v1/embeddings",         // SIIT
    "http://[2002:a9fe:a9fe::1]/v1/models",              // 6to4
  ]) {
    assert.equal((await judgeAdapterTarget(url)).mode, "refused", url);
    assert.equal((await judgeAdapterTarget(url, { kind: "ollama" })).mode, "refused", url);
  }
  const dialled = [];
  const adapter = createOpenAIAdapter({
    baseUrl: "http://[64:ff9b::a9fe:a9fe]/v1", apiKey: "k", model: "m",
    guard: { fetchFn: async (u) => { dialled.push(u); return new Response("{}", { status: 200 }); } },
  });
  await assert.rejects(() => adapter.chatStream([{ role: "user", content: "hi" }], []).next(), (e) => e.code === "SELF_TARGET_REFUSED");
  assert.deepEqual(dialled, [], "the NAT64 metadata endpoint was never contacted");

  // a normal public IPv6 literal is not this host and is not forbidden: allowed.
  for (const url of ["http://[2606:4700:4700::1111]/v1/chat/completions", "http://[64:ff9b::808:808]/v1/chat/completions"]) {
    assert.notEqual((await judgeAdapterTarget(url)).mode, "refused", url);
  }
});

// ---------------------------------------------------------------------------
// (iv) a public host through the pinned transport: key kept, SSE incremental.
// ---------------------------------------------------------------------------

test("a public-host stub through the pinned lookup keeps its Authorization and streams incrementally", async () => {
  const lookupFn = fakeLookup([[PUBLIC]]);
  const stream = new PassThrough();
  let release;
  const gate = new Promise((r) => { release = r; });
  const timer = setTimeout(() => release(false), 3000);
  const calls = [];
  const adapter = createOpenAIAdapter({
    baseUrl: "https://api.example.test/v1", apiKey: "cloud-key", model: "m",
    guard: {
      lookupFn,
      requestFn: async (url, opts) => {
        const r = await pinnedRequest(() => stream, calls)(url, opts);
        stream.write(chatChunk("Hel"));
        gate.then((acked) => { calls[0].acked = acked; stream.end(`${chatChunk("lo")}data: [DONE]\n\n`); });
        return r;
      },
    },
  });
  const deltas = [];
  for await (const ev of adapter.chatStream([{ role: "user", content: "hi" }], [])) {
    if (ev.type === "content_delta") { deltas.push(ev.text); release(true); }
  }
  clearTimeout(timer);
  assert.deepEqual(deltas, ["Hel", "lo"]);
  assert.equal(calls[0].acked, true, "the pinned body streamed as it arrived");
  assert.equal(calls[0].headers.Authorization, "Bearer cloud-key", "a public cloud host keeps its key");
  assert.deepEqual(calls[0].looked.map((a) => a.address), [PUBLIC]);
  assert.equal(lookupFn.calls.length, 1);
});

test("responseFromStream exposes the fetch Response surface the adapters read", async () => {
  const stream = new PassThrough();
  const res = responseFromStream({ status: 201, headers: { "content-type": "application/json" }, stream });
  stream.end(JSON.stringify({ hello: "world" }));
  assert.equal(res.ok, true);
  assert.equal(res.status, 201);
  assert.equal(res.headers.get("content-type"), "application/json");
  assert.deepEqual(await res.json(), { hello: "world" });
});

// ---------------------------------------------------------------------------
// The two real consumer paths, end to end, against a bot-written attack row.
// ---------------------------------------------------------------------------

test("a voice turn (voice/turn.js → provider adapter) whose row points at an own-host /llm/acquire?x= is refused and never dials it", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end(JSON.stringify({ ok: true })); });
  const h = harness({ rounds: [[{ type: "content_delta", text: "should never be spoken" }, { type: "done" }]] });
  // The production `/turn.js` factory, verbatim: the adapter comes from the
  // provider layer, which resolved the row's base_url.
  h.deps.createChatAdapter = async () => (await createAdapterFromProfile(
    { provider: "openai", apiKey: "bot-key", baseUrl: `${s.base}/llm/acquire?x=`, model: "m" },
    "m",
  )).adapter;
  const r = await h.runner.runVoiceTurn({ db: {}, device: h.device, transcript: "what is the capital of Portugal?", sink: h.sink });
  assert.equal(r.failed, "error", "the turn failed rather than reaching the attack route");
  assert.deepEqual(s.hits, [], "the model lifecycle route was never reached");
  assert.deepEqual(h.calls.spoken, [], "nothing the bot wrote was spoken as an answer");
  assert.ok(h.calls.logs.some((m) => m.includes(SELF_REFUSED_MESSAGE)), h.calls.logs.join("\n"));
});

test("the dashboard chat route (routes/chat.js → provider adapter) is refused when a bot wrote the provider row", async () => {
  const s = await listen((req, res) => { res.writeHead(200); res.end(JSON.stringify({ ok: true })); });

  const dataDir = mkdtempSync(join(tmpdir(), "adapter-guard-chat-data-"));
  const home = mkdtempSync(join(tmpdir(), "adapter-guard-chat-home-"));
  const prev = { CROW_DATA_DIR: process.env.CROW_DATA_DIR, HOME: process.env.HOME, CROW_HOME: process.env.CROW_HOME };
  process.env.CROW_DATA_DIR = dataDir;
  process.env.HOME = home;
  process.env.CROW_HOME = join(home, ".crow");
  let server = null;
  let db = null;
  try {
    execFileSync(process.execPath, ["scripts/init-db.js"], {
      env: { ...process.env, CROW_DATA_DIR: dataDir }, stdio: "pipe", cwd: new URL("..", import.meta.url).pathname,
    });
    const { createDbClient } = await import("../servers/db.js");
    db = createDbClient();
    await db.execute({
      sql: `INSERT INTO providers (id, base_url, host, models, disabled, lamport_ts, instance_id)
            VALUES (?, ?, 'local', ?, 0, 1, 'test-instance')`,
      args: ["bot-written", `${s.base}/llm/acquire?x=`, JSON.stringify([{ id: "m", task: "chat" }])],
    });
    const { default: express } = await import("express");
    const { default: chatRouter } = await import("../servers/gateway/routes/chat.js");
    const app = express();
    app.use(express.json());
    // Out of scope for THIS fix, but load-bearing for the test: chat.js aborts a
    // generation on `req.on("close")`, and on Node >= 16 that event fires when
    // the request BODY completes (not when the client goes away) — on this Node
    // every dashboard chat turn is aborted before its first model call (reported
    // as a new, unfixed class). Neutralizing it here is what lets the route reach
    // the adapter at all; the guard's decision does not depend on it.
    app.use((req, _res, next) => {
      const realOn = req.on.bind(req);
      req.on = (event, fn) => (event === "close" ? req : realOn(event, fn));
      next();
    });
    app.use(chatRouter((req, res, next) => next()));   // dashboardAuth stub — auth is not under test
    await new Promise((resolve) => { server = app.listen(0, "127.0.0.1", resolve); });
    const base = `http://127.0.0.1:${server.address().port}`;

    const conv = await (await fetch(`${base}/api/chat/conversations`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: "attack" }),
    })).json();
    assert.equal(conv.provider, "bot-written", JSON.stringify(conv));

    const res = await fetch(`${base}/api/chat/conversations/${conv.id}/messages`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ content: "hello" }),
    });
    const body = await res.text();
    assert.match(body, /event: error/, body);
    assert.match(body, /SELF_TARGET_REFUSED/, body);
    assert.doesNotMatch(body, /event: content/, body);
    assert.deepEqual(s.hits, [], "the model lifecycle route was never reached");

    // CONTROL on the same route, through the same adapter: a row at an ALLOWED
    // own-host /v1 path IS dialled, and carries no key. Without this half,
    // "the attack listener saw nothing" could just mean the route called no model.
    const allowed = await listen((req, res2) => {
      res2.writeHead(200, SSE);
      res2.write(chatChunk("answered"));
      res2.end("data: [DONE]\n\n");
    });
    await db.execute({
      sql: `INSERT INTO providers (id, base_url, host, models, disabled, lamport_ts, instance_id)
            VALUES (?, ?, 'local', ?, 0, 1, 'test-instance')`,
      args: ["bot-written-allowed", `${allowed.base}/v1`, JSON.stringify([{ id: "m", task: "chat" }])],
    });
    const conv2 = await (await fetch(`${base}/api/chat/conversations`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ title: "control", provider: "bot-written-allowed", model: "m" }),
    })).json();
    assert.equal(conv2.provider, "bot-written-allowed", JSON.stringify(conv2));
    const controlBody = await fetch(`${base}/api/chat/conversations/${conv2.id}/messages`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ content: "hello" }),
    }).then((r) => r.text());
    assert.deepEqual(allowed.hits.map((h) => h.path), ["/v1/chat/completions"], controlBody);
    assert.equal(allowed.hits[0].headers.authorization, undefined, "and carries no key");
  } finally {
    if (server) await new Promise((r) => server.close(() => r()));
    try { db?.close?.(); } catch { /* already closed */ }
    for (const [k, v] of Object.entries(prev)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});