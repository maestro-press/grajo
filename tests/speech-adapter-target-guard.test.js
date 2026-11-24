/**
 * SPEECH ADAPTERS (class 2 of the confused-deputy fix): every STT/TTS request
 * goes through the same guard as a chat model call.
 *
 * A speech profile's `baseUrl`/`apiKey` live in bot-writable `dashboard_settings`
 * (`stt_profiles` / `tts_profiles`), and the adapters send AUDIO plus a
 * credential (`Authorization`, `Ocp-Apim-Subscription-Key`, `xi-api-key`,
 * Deepgram's `Token ...`) to whatever endpoint the profile names. So the rules
 * are `ai/adapter-guard.js`'s, not a second copy:
 *
 *   - a forbidden target (link-local / cloud metadata) is refused for everyone;
 *   - an own-host target is allowed ONLY at the operations these adapters send —
 *     `/v1/audio/transcriptions`, `/v1/audio/speech`, `/v1/audio/voices` and
 *     whisper.cpp's `/inference` — as EXACT paths, computed on the FINAL request
 *     URL each adapter builds, so a profile whose base already ends in `/v1`
 *     (kokoro, faster-whisper) keeps working; a hosted base such as groq's
 *     `/openai/v1` is not this host and never reaches the own-host rule, and the
 *     same shape pointed at a loopback server is refused. An own-host speech
 *     server never receives a credential;
 *   - a rebindable DNS name is resolved once and pinned.
 *
 * Real loopback listeners, real adapters. The prod profile SHAPES (STT groq,
 * STT faster-whisper, TTS edge, TTS kokoro, plus the hosted defaults) are one
 * decision table below.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { WebSocketServer } from "ws";

import createGroqStt from "../servers/gateway/ai/stt/adapters/groq.js";
import createFasterWhisper from "../servers/gateway/ai/stt/adapters/fasterwhisper.js";
import createOpenAIStt from "../servers/gateway/ai/stt/adapters/openai.js";
import createDeepgram from "../servers/gateway/ai/stt/adapters/deepgram.js";
import createWhisperCpp from "../servers/gateway/ai/stt/adapters/whispercpp.js";
import createKokoro from "../servers/gateway/ai/tts/adapters/kokoro.js";
import createEdge from "../servers/gateway/ai/tts/adapters/edge.js";
import createAzure from "../servers/gateway/ai/tts/adapters/azure.js";
import createElevenLabs from "../servers/gateway/ai/tts/adapters/elevenlabs.js";
import createOpenAITts from "../servers/gateway/ai/tts/adapters/openai.js";
import createPiper from "../servers/gateway/ai/tts/adapters/piper.js";
import {
  judgeAdapterTarget, guardedFetch, withoutCredentials, carriesCredentials,
  guardSocketTarget, selfTargetRefused, SELF_REFUSED_MESSAGE,
} from "../servers/gateway/ai/adapter-guard.js";

const AUDIO = Buffer.from("ID3fake-mp3-bytes");

// --- listeners ---------------------------------------------------------------

const servers = [];
after(async () => {
  for (const s of servers) {
    try { s.closeAllConnections?.(); } catch { /* already gone */ }
    await new Promise((r) => s.close(() => r()));
  }
});

function listen(handler) {
  const hits = [];
  const server = http.createServer((req, res) => {
    const rec = { method: req.method, path: req.url, headers: req.headers };
    hits.push(rec);
    req.on("data", () => {});
    req.on("end", () => handler(req, res, rec));
  });
  servers.push(server);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({ hits, port, base: `http://127.0.0.1:${port}` });
    });
  });
}

const json = (res, body) => { res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
const audio = (res) => { res.writeHead(200, { "content-type": "audio/mpeg" }); res.end(AUDIO); };

async function collect(it) {
  const out = [];
  for await (const c of it) out.push(c);
  return Buffer.concat(out);
}

// ---------------------------------------------------------------------------
// Every adapter's request site is the guard (an adapter that grows a bare
// `fetch` again would silently reopen the hole this round closes).
// ---------------------------------------------------------------------------

test("no STT/TTS adapter opens its own socket: each one imports the guard and calls guardedFetch", () => {
  const dirs = ["stt", "tts"];
  for (const dir of dirs) {
    for (const name of ["azure", "deepgram", "edge", "elevenlabs", "fasterwhisper", "groq", "kokoro", "openai", "piper", "whispercpp"]) {
      let src;
      try { src = readFileSync(new URL(`../servers/gateway/ai/${dir}/adapters/${name}.js`, import.meta.url), "utf8"); }
      catch { continue; }
      assert.match(src, /from "\.\.\/\.\.\/adapter-guard\.js"/, `${dir}/${name}.js must import the guard`);
      assert.match(src, /guardedFetch\(|guardSocketTarget\(/, `${dir}/${name}.js must call the guard`);
      const raw = src.split("\n").map((line, i) => [i + 1, line])
        .filter(([, line]) => /(^|[^A-Za-z_.])fetch\s*\(/.test(line))
        .filter(([, line]) => !/guardedFetch|fetchFn/.test(line))
        .filter(([, line]) => !/^\s*(\*|\/\/)/.test(line));
      assert.deepEqual(raw, [], `${dir}/${name}.js still opens its own request: ${JSON.stringify(raw)}`);
    }
  }
});

// ---------------------------------------------------------------------------
// The prod profile SHAPES (crow + raven), as one decision table. Every one of
// them must stay usable, and only an own-host profile loses its key.
// `finalUrl` is the URL the adapter actually builds.
// ---------------------------------------------------------------------------

async function decide(finalUrl, headers, lookupFn) {
  const decision = await judgeAdapterTarget(finalUrl, { kind: "speech", lookupFn: lookupFn || publicLookup });
  return { mode: decision.mode, headers: decision.mode === "own" ? withoutCredentials(headers) : headers };
}

/** A stub resolver: every public name answers a documentation address, so the
 *  decision is this file's, not the sandbox's DNS. */
function publicLookup(host, opts, cb) {
  const list = [{ address: "203.0.113.70", family: 4 }];
  if (opts && typeof opts === "object" && opts.all) return cb(null, list);
  return cb(null, list[0].address, list[0].family);
}

test("the prod speech profiles stay allowed: own-host ones lose the key, hosted ones keep it", async () => {
  const rows = [
    // [label, final request URL the adapter builds, headers it sends, own-host?]
    ["stt groq (default)", "https://api.groq.com/openai/v1/audio/transcriptions", { Authorization: "Bearer gsk-row" }, false],
    ["stt faster-whisper (own box)", "http://localhost:8004/v1/audio/transcriptions", { Authorization: "Bearer not-needed" }, true],
    ["stt openai (default)", "https://api.openai.com/v1/audio/transcriptions", { Authorization: "Bearer sk-row" }, false],
    ["stt whisper.cpp (own box)", "http://127.0.0.1:9000/inference", {}, true],
    ["tts kokoro (own box, base ends in /v1)", "http://localhost:8880/v1/audio/speech", { Authorization: "Bearer not-needed" }, true],
    ["tts kokoro voices (own box)", "http://localhost:8880/v1/audio/voices", { Authorization: "Bearer not-needed" }, true],
    ["tts openai (default)", "https://api.openai.com/v1/audio/speech", { Authorization: "Bearer sk-row" }, false],
    ["tts elevenlabs (default)", "https://api.elevenlabs.io/v1/text-to-speech/vid/stream?output_format=mp3_44100_128", { "xi-api-key": "xi-row" }, false],
    ["tts azure (default region)", "https://eastus.tts.speech.microsoft.com/cognitiveservices/v1", { "Ocp-Apim-Subscription-Key": "az-row" }, false],
    ["stt deepgram (default)", "https://api.deepgram.com/v1/listen?model=nova-3", { Authorization: "Token dg-row" }, false],
  ];
  for (const [label, url, headers, own] of rows) {
    const r = await decide(url, headers);
    assert.notEqual(r.mode, "refused", `${label} (${url}) must stay usable`);
    if (own) {
      assert.equal(r.mode, "own", `${label} (${url}) is this host`);
      assert.equal(carriesCredentials(r.headers), false, `${label}: no credential to an own-host speech server`);
    } else {
      assert.equal(carriesCredentials(r.headers), true, `${label}: a hosted endpoint keeps its key`);
    }
  }
  // Edge is WebSocket/CLI based and its one HTTP request is a fixed Microsoft
  // URL with no credential; it must be reachable and carry nothing.
  const edge = await decide("https://speech.platform.bing.com/consumer/speech/synthesize/readaloud/voices/list?trustedclienttoken=x", {});
  assert.notEqual(edge.mode, "refused");
});

// ---------------------------------------------------------------------------
// An own-host speech server still works, and never sees a credential.
// ---------------------------------------------------------------------------

test("faster-whisper on this box is dialled at /v1/audio/transcriptions with no Authorization", async () => {
  const s = await listen((req, res) => json(res, { text: "hello there", language: "en" }));
  const a = createFasterWhisper({ baseUrl: `${s.base}/v1`, apiKey: "row-key" });
  const out = await a.transcribe(Buffer.from("RIFF...."), { model: "Systran/faster-whisper-large-v3" });
  assert.equal(out.text, "hello there");
  assert.deepEqual(s.hits.map((h) => `${h.method} ${h.path}`), ["POST /v1/audio/transcriptions"]);
  assert.equal(s.hits[0].headers.authorization, undefined);
});

test("kokoro on this box keeps working with its prod base_url (http://localhost:8880/v1): /v1/audio/speech and /v1/audio/voices, no Authorization", async () => {
  const s = await listen((req, res) => {
    if (req.url === "/v1/audio/voices") return json(res, { voices: ["af_bella", "af_heart"] });
    return audio(res);
  });
  // The PROD shape: the profile's base ends in /v1, and the adapter must not
  // produce /v1/v1/audio/speech.
  const a = createKokoro({ baseUrl: `${s.base}/v1`, apiKey: "not-needed" });
  const bytes = await collect(a.synthesize("hi", "af_bella"));
  assert.deepEqual(bytes, AUDIO);
  const voices = await a.listVoices();
  assert.deepEqual(voices.map((v) => v.id), ["af_bella", "af_heart"]);
  assert.deepEqual(s.hits.map((h) => `${h.method} ${h.path}`), ["POST /v1/audio/speech", "GET /v1/audio/voices"]);
  for (const h of s.hits) assert.equal(h.headers.authorization, undefined);
});

test("whisper.cpp on this box is dialled at POST /inference", async () => {
  const s = await listen((req, res) => json(res, { text: "  hi  " }));
  const a = createWhisperCpp({ baseUrl: s.base });
  assert.equal((await a.transcribe(Buffer.from("RIFF...."))).text, "hi");
  assert.deepEqual(s.hits.map((h) => `${h.method} ${h.path}`), ["POST /inference"]);
});

test("an own-host speech target is allowed at the EXACT four operations only, never a path that merely ends in one", async () => {
  for (const path of ["/v1/audio/transcriptions", "/v1/audio/speech", "/v1/audio/voices", "/inference"]) {
    const d = await judgeAdapterTarget(`http://127.0.0.1:8004${path}`, { kind: "speech" });
    assert.equal(d.mode, "own", `${path} is a reviewed speech operation`);
  }
  for (const path of [
    "/x/v1/audio/speech",
    "/llm/v1/audio/transcriptions",
    "/foo/inference",
    "/openai/v1/audio/transcriptions",
    "/v1/audio/speech?x=",
    "/v1/audio/speech/../acquire",
  ]) {
    const d = await judgeAdapterTarget(`http://127.0.0.1:8004${path}`, { kind: "speech" });
    assert.equal(d.mode, "refused", `${path} is not a reviewed speech operation on this box`);
  }
});

test("a hosted-shaped STT profile pointed at a loopback server (groq /openai/v1) is refused", async () => {
  const s = await listen((req, res) => json(res, { text: "ok" }));
  const a = createGroqStt({ baseUrl: `${s.base}/openai/v1`, apiKey: "gsk-row" });
  await assert.rejects(
    () => a.transcribe(Buffer.from("RIFF....")),
    (e) => e.code === "SELF_TARGET_REFUSED" && e.message === SELF_REFUSED_MESSAGE,
  );
  assert.deepEqual(s.hits, [], "no request reached this box at a path that only ends in a speech operation");
});

test("the same adapters keep their key on a real hosted endpoint (judged, never dialled)", async () => {
  for (const [url, headers] of [
    ["https://api.groq.com/openai/v1/audio/transcriptions", { Authorization: "Bearer gsk-row" }],
    ["https://api.openai.com/v1/audio/transcriptions", { Authorization: "Bearer sk-row" }],
  ]) {
    const d = await judgeAdapterTarget(url, { kind: "speech", lookupFn: publicLookup });
    assert.notEqual(d.mode, "refused", url);
    assert.equal(carriesCredentials(headers), true, url);
  }
});

// ---------------------------------------------------------------------------
// The refusals: a forbidden address, and an own-host path that is not one of
// the reviewed speech operations. Neither opens a socket.
// ---------------------------------------------------------------------------

test("a speech profile pointed at cloud metadata is refused and nothing is dialled", async () => {
  const a = createFasterWhisper({ baseUrl: "http://169.254.169.254/v1", apiKey: "row-key" });
  await assert.rejects(
    () => a.transcribe(Buffer.from("RIFF....")),
    (e) => e.code === "SELF_TARGET_REFUSED" && e.message === SELF_REFUSED_MESSAGE,
  );
  const b = createKokoro({ baseUrl: "http://169.254.169.254/v1" });
  await assert.rejects(() => collect(b.synthesize("hi")), (e) => e.code === "SELF_TARGET_REFUSED");
});

test("a bot-written speech profile pointing at an own-host route that is not a speech operation is refused", async () => {
  const s = await listen((req, res) => json(res, {}));
  for (const make of [
    () => createFasterWhisper({ baseUrl: `${s.base}/llm/acquire?x=`, apiKey: "k" }),
    () => createWhisperCpp({ baseUrl: `${s.base}/llm/acquire` }),
  ]) {
    const a = make();
    await assert.rejects(() => a.transcribe(Buffer.from("RIFF....")), (e) => e.code === "SELF_TARGET_REFUSED");
  }
  // An own-host TTS profile at a route of ours: /llm/acquire?x= swallows the
  // appended /v1/audio/speech into a query, and the query rule refuses it.
  const k = createKokoro({ baseUrl: `${s.base}/llm/acquire?x=` });
  await assert.rejects(() => collect(k.synthesize("hi")), (e) => e.code === "SELF_TARGET_REFUSED");
  assert.deepEqual(s.hits, [], "no request reached this box's own routes");
});

// ---------------------------------------------------------------------------
// The live (WebSocket) Deepgram path: the connect is judged too.
// ---------------------------------------------------------------------------

test("a deepgram live connect to this box is refused before a socket, and a rebindable name is pinned to the vetted address", async () => {
  const wss = new WebSocketServer({ host: "127.0.0.1", port: 0 });
  await new Promise((r) => wss.on("listening", r));
  const port = wss.address().port;
  let connections = 0;
  wss.on("connection", () => { connections++; });
  try {
    const a = createDeepgram({ baseUrl: `http://127.0.0.1:${port}`, apiKey: "dg-row" });
    await assert.rejects(async () => {
      for await (const _ of a.transcribeStream((async function* () { yield Buffer.alloc(2); })(), {})) { /* none */ }
    }, (e) => e.code === "SELF_TARGET_REFUSED");
    assert.equal(connections, 0, "no WebSocket handshake reached this box");
  } finally {
    await new Promise((r) => wss.close(r));
  }

  // A rebindable name: the guard answers with a lookup pinned to the ONE vetted
  // address (the loopback answer is never used).
  const lookupFn = (host, opts, cb) => cb(null, [{ address: "203.0.113.50", family: 4 }]);
  const opts = await guardSocketTarget("wss://speech.example.test/v1/listen?model=nova-3", { lookupFn });
  assert.equal(typeof opts.lookup, "function");
  const looked = await new Promise((resolve, reject) => opts.lookup("speech.example.test", { all: true }, (e, a) => (e ? reject(e) : resolve(a))));
  assert.deepEqual(looked.map((a) => a.address), ["203.0.113.50"]);
  // A name that does not resolve is refused (fail closed).
  await assert.rejects(
    () => guardSocketTarget("wss://nowhere.example.test/v1/listen", { lookupFn: (h, o, cb) => cb(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" })) }),
    (e) => e.code === "SELF_TARGET_REFUSED",
  );
});

// ---------------------------------------------------------------------------
// The defaults the other adapters still build (no profile base_url at all).
// ---------------------------------------------------------------------------

test("the built-in default endpoints are all still allowed (nothing a fresh install does is refused)", async () => {
  const ok = async (url) => assert.notEqual((await judgeAdapterTarget(url, { kind: "speech", lookupFn: publicLookup })).mode, "refused", url);
  await ok("https://api.openai.com/v1/audio/transcriptions");
  await ok("https://api.deepgram.com/v1/listen?model=nova-3");
  await ok("https://api.elevenlabs.io/v1/voices");
  await ok("https://api.elevenlabs.io/v1/text-to-speech/x/stream?output_format=mp3");
  // …and the adapter default for each is what the judge was given.
  assert.equal(createOpenAIStt({}).name, "openai-stt");
  assert.equal(createAzure({}).name, "azure-tts");
  assert.equal(createElevenLabs({}).name, "elevenlabs");
  assert.equal(createOpenAITts({}).name, "openai-tts");
  assert.equal(createEdge({}).name, "edge-tts");
  assert.equal(createPiper({}).name, "piper");
});

test("guardedFetch's own-host refusal drops every speech credential name too", async () => {
  const s = await listen((req, res) => json(res, { ok: true }));
  await guardedFetch(`${s.base}/v1/audio/transcriptions`, {
    headers: { Authorization: "Token dg", "Ocp-Apim-Subscription-Key": "az", "xi-api-key": "xi" },
    body: "x",
    guard: { kind: "speech" },
  });
  assert.equal(s.hits[0].headers.authorization, undefined);
  assert.equal(s.hits[0].headers["ocp-apim-subscription-key"], undefined);
  assert.equal(s.hits[0].headers["xi-api-key"], undefined);
});

test("selfTargetRefused is the one fixed wording (no new user-visible text)", () => {
  assert.equal(selfTargetRefused().code, "SELF_TARGET_REFUSED");
  assert.equal(selfTargetRefused().message, "Crow will not contact that address");
});