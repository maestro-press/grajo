/**
 * OLLAMA ON THIS HOST (security review, item a).
 *
 * The confused-deputy rule refuses every own-host target that is not an exact
 * `/v1/<op>` or `/llm/v1/<op>` model operation — but the store's Ollama bundle
 * auto-configures provider "ollama" at `http://localhost:11434`
 * (`routes/bundles.js` `getAiProviderConfig`), and Ollama's native API is
 * `/api/chat` (the adapter) and `/api/embed` (`ai/provider.js`
 * `getEmbedding`). So the blanket rule broke that install, and the fix is a
 * NEW, NARROW guard kind (`"ollama"`) with its own reviewed operation list and
 * a PORT ALLOW-LIST:
 *
 *   - the two native operations, exact path, no query, no fragment;
 *   - never a credential (`Authorization` is dropped on an own-host target);
 *   - and ONLY on an own-host OLLAMA port: 11434, the port the store's bundle
 *     publishes FIXED in `bundles/ollama/docker-compose.yml`
 *     (`127.0.0.1:11434:11434`; the bundle's OLLAMA_HOST is a full URL setting,
 *     `routes/bundles.js` getAiProviderConfig, not a port option — so there is no
 *     operator-chosen Ollama port to read instead). An ALLOW-list, not a
 *     deny-list of gateway ports: EVERY other own-host port is refused for this
 *     kind — 80/443 behind a local Caddy, a co-hosted gateway on 3001/3002/3008,
 *     3009, 8080, any port a bot chose.
 *
 * Every other kind keeps the rule it had: the chat-model kind still refuses
 * `/api/chat` on ANY own-host port, and a remote Ollama (LAN, tailnet, another
 * container — where a gateway port is somebody else's) is untouched.
 *
 * Real listeners on loopback, the real adapter and the real `getEmbedding`
 * path; no mocks of the request sites.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import createOllamaAdapter from "../servers/gateway/ai/adapters/ollama.js";
import createOpenAIAdapter from "../servers/gateway/ai/adapters/openai.js";
import {
  judgeAdapterTarget, guardedFetch, selfPathAllowed, SELF_REFUSED_MESSAGE,
} from "../servers/gateway/ai/adapter-guard.js";
import {
  OLLAMA_OWN_HOST_PORTS, isOwnHostOllamaPort, isAllowedSelfOllamaPath, SELF_OLLAMA_PATHS,
} from "../servers/gateway/models/self-target.js";
import { getEmbedding, invalidateConfigCache } from "../servers/gateway/ai/provider.js";

const OLLAMA_PORT = 11434;

/** Own-host ports an Ollama may NOT be driven at. Under the old gateway-port
 *  deny-list every one of these was reachable: 8080, 3009 and 80/443 (a local
 *  Caddy) were never on it, and "any own-host port a bot picks" was not either —
 *  exactly the gap the allow-list closes. */
const REFUSED_OWN_HOST_PORTS = [80, 443, 3001, 3008, 3009, 8080];

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
    const rec = { method: req.method, path: req.url, headers: req.headers, body: "" };
    hits.push(rec);
    req.on("data", (c) => { rec.body += c.toString("utf8"); });
    req.on("end", () => handler(req, res, rec));
  });
  servers.push(server);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  return { hits, port, base: `http://127.0.0.1:${port}` };
}

/** A listener on a NAMED port, or null when the port is taken on this box (a
 *  live gateway on 3001, a local Caddy on 80/443, a developer's Ollama on
 *  11434) or cannot be bound at all. */
async function listenAt(port, handler) {
  const hits = [];
  const server = http.createServer((req, res) => {
    const rec = { method: req.method, path: req.url, headers: req.headers, body: "" };
    hits.push(rec);
    req.on("data", (c) => { rec.body += c.toString("utf8"); });
    req.on("end", () => handler(req, res, rec));
  });
  try {
    await new Promise((res, rej) => {
      server.once("error", rej);
      server.listen(port, "127.0.0.1", res);
    });
  } catch {
    try { server.close(); } catch { /* never listened */ }
    return null;
  }
  servers.push(server);
  return { hits, port, base: `http://127.0.0.1:${port}` };
}

/** Ollama streams NDJSON, one JSON object per line. */
const ollamaChatBody = (text) =>
  `${JSON.stringify({ message: { role: "assistant", content: text }, done: false })}\n` +
  `${JSON.stringify({ message: { role: "assistant", content: "" }, done: true, prompt_eval_count: 3, eval_count: 1 })}\n`;

/**
 * The ONE dev-box listener on Ollama's own port, shared by every test that needs
 * the real thing (a second bind of the same port would fail and silently skip
 * the rest). It answers the two native operations and records every hit; each
 * test clears `hits` before it starts. `null` when the port is taken on this box
 * (a real Ollama, or another process) — those tests then skip.
 */
let ollamaListener;
async function ownHostOllama() {
  if (ollamaListener !== undefined) return ollamaListener;
  const s = await listenAt(OLLAMA_PORT, (req, res, rec) => {
    if (rec.path === "/api/chat") {
      res.writeHead(200, { "content-type": "application/x-ndjson" });
      res.end(ollamaChatBody("Hello from the box"));
      return;
    }
    if (rec.path === "/api/embed") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ embeddings: [[0.1, 0.2, 0.3]] }));
      return;
    }
    res.writeHead(404);
    res.end("{}");
  });
  ollamaListener = s ? { get hits() { return s.hits; }, get port() { return s.port; }, get base() { return s.base; }, clear() { s.hits.length = 0; } } : null;
  return ollamaListener;
}

// ---------------------------------------------------------------------------
// The rule itself: the two operations, and the own-host port ALLOW-list.
// ---------------------------------------------------------------------------

test("the ollama allowance is exactly Ollama's two native operations (no /api/tags: no Crow code calls it)", () => {
  assert.deepEqual([...SELF_OLLAMA_PATHS], ["/api/chat", "/api/embed"]);
  for (const url of ["http://127.0.0.1:11434/api/chat", "http://127.0.0.1:11434/api/embed", "http://127.0.0.1:11434/api/embed/"]) {
    assert.equal(isAllowedSelfOllamaPath(url), true, url);
  }
  for (const url of [
    "http://127.0.0.1:11434/api/tags",          // not called by Crow code
    "http://127.0.0.1:11434/api/pull",
    "http://127.0.0.1:11434/api/chat?x=",        // a query is never an operation
    "http://127.0.0.1:11434/api/chat#f",
    "http://127.0.0.1:11434/api/chat/../tags",
    "http://127.0.0.1:11434/api/%63hat",
    "http://127.0.0.1:11434/v1/chat/completions", // the model kind's path, not this one
    "http://127.0.0.1:11434/api",
  ]) {
    assert.equal(isAllowedSelfOllamaPath(url), false, url);
  }
});

test("OLLAMA_OWN_HOST_PORTS is the port the Ollama bundle publishes (the compose file is the source of truth)", () => {
  const compose = readFileSync(new URL("../bundles/ollama/docker-compose.yml", import.meta.url), "utf8");
  // `- "127.0.0.1:11434:11434"` in bundles/ollama/docker-compose.yml: the
  // bundle's published HOST port, FIXED. Its OLLAMA_HOST setting is a full URL,
  // not a port option, so there is no operator-chosen Ollama port to read
  // instead; if the bundle ever makes one configurable, read it from there.
  const published = [...compose.matchAll(/^\s*-\s*"(?:\d+\.\d+\.\d+\.\d+:)?(\d+):\d+"/gm)].map((m) => Number(m[1]));
  assert.deepEqual(published, [OLLAMA_PORT], "bundles/ollama/docker-compose.yml's published port changed: update OLLAMA_OWN_HOST_PORTS");
  assert.deepEqual([...OLLAMA_OWN_HOST_PORTS], published);
  for (const p of published) assert.equal(isOwnHostOllamaPort(p), true, String(p));
  for (const p of [...REFUSED_OWN_HOST_PORTS, 11435, 18100, 8003]) assert.equal(isOwnHostOllamaPort(p), false, String(p));
  assert.equal(isOwnHostOllamaPort(undefined), false, "an unknown port fails closed");
  assert.equal(isOwnHostOllamaPort("http"), false, "a non-numeric port fails closed");
});

// ---------------------------------------------------------------------------
// The decision: own-host Ollama allowed ONLY on its own port; EVERY other
// own-host port refused; the chat-model kind unchanged.
// ---------------------------------------------------------------------------

test("judgeAdapterTarget: an own-host Ollama port is allowed at /api/chat and /api/embed, and at nothing else", async () => {
  for (const url of ["http://127.0.0.1:11434/api/chat", "http://localhost:11434/api/embed", `http://127.0.0.1:${OLLAMA_PORT}/api/embed`]) {
    const d = await judgeAdapterTarget(url, { kind: "ollama" });
    assert.equal(d.mode, "own", `${url} must be usable (the store's Ollama bundle)`);
  }
  // the same host, the same kind, a path Ollama's reviewed list does not have
  for (const url of ["http://127.0.0.1:11434/api/tags", "http://127.0.0.1:11434/api/chat?x=", "http://127.0.0.1:11434/api/pull"]) {
    assert.equal((await judgeAdapterTarget(url, { kind: "ollama" })).mode, "refused", url);
  }
});

test("judgeAdapterTarget: EVERY other own-host port is refused for both Ollama operations (an allow-list, not a gateway deny-list)", async () => {
  for (const port of REFUSED_OWN_HOST_PORTS) {
    for (const path of ["/api/chat", "/api/embed"]) {
      for (const host of ["127.0.0.1", "localhost"]) {
        const url = `http://${host}:${port}${path}`;
        assert.equal((await judgeAdapterTarget(url, { kind: "ollama" })).mode, "refused", `${url} is this box, and not an Ollama port`);
      }
      assert.equal(selfPathAllowed(`http://127.0.0.1:${port}${path}`, "ollama", { port }), false, `:${port}${path}`);
    }
  }
  // …and the port that IS Ollama's is the one the rule allows.
  for (const path of ["/api/chat", "/api/embed"]) {
    assert.equal(selfPathAllowed(`http://127.0.0.1:${OLLAMA_PORT}${path}`, "ollama", { port: OLLAMA_PORT }), true, path);
  }
  assert.equal(selfPathAllowed("http://127.0.0.1:11434/api/chat", "ollama"), false, "an unstated port fails closed");
});

test("the chat-model kind still refuses /api/chat on ANY own-host port (only the ollama kind is widened)", async () => {
  for (const port of [OLLAMA_PORT, ...REFUSED_OWN_HOST_PORTS, 18100]) {
    assert.equal(selfPathAllowed(`http://127.0.0.1:${port}/api/chat`, "model"), false, String(port));
    assert.equal((await judgeAdapterTarget(`http://127.0.0.1:${port}/api/chat`)).mode, "refused", String(port));
    assert.equal((await judgeAdapterTarget(`http://127.0.0.1:${port}/api/embed`, { kind: "probe" })).mode, "refused", String(port));
  }
  // a chat row through the real openai adapter: `/chat/completions` under `/api`
  // is not a model operation on this host, so it is refused and never dialled.
  const s = await listen((req, res) => { res.writeHead(200); res.end("{}"); });
  const adapter = createOpenAIAdapter({ baseUrl: `${s.base}/api`, apiKey: "row-key", model: "m" });
  await assert.rejects(
    () => adapter.chatStream([{ role: "user", content: "hi" }], []).next(),
    (e) => e.code === "SELF_TARGET_REFUSED",
  );
  assert.deepEqual(s.hits, []);
});

test("a REMOTE Ollama is unchanged: another host's Ollama (or even its gateway port) is not this box", async () => {
  for (const url of ["http://10.0.0.50:11434/api/chat", "http://100.64.20.9:11434/api/embed", "http://10.0.0.50:3001/api/chat", "http://10.0.0.50:8080/api/embed"]) {
    const d = await judgeAdapterTarget(url, { kind: "ollama" });
    assert.notEqual(d.mode, "refused", `${url} is another machine`);
  }
});

// ---------------------------------------------------------------------------
// (i) The store's install: an own-host Ollama on 11434 works, with no key.
// ---------------------------------------------------------------------------

test("the ollama adapter streams from an own-host /api/chat on Ollama's port, and never sends Authorization", async (t) => {
  const s = await ownHostOllama();
  if (!s) return t.skip("port 11434 is in use on this box (a real Ollama)");
  s.clear();
  const adapter = createOllamaAdapter({ baseUrl: s.base, model: "llama3.1" });
  const deltas = [];
  let done = null;
  for await (const ev of adapter.chatStream([{ role: "user", content: "hi" }], [])) {
    if (ev.type === "content_delta") deltas.push(ev.text);
    if (ev.type === "done") done = ev;
  }
  assert.deepEqual(deltas, ["Hello from the box"]);
  assert.deepEqual(done.usage, { input_tokens: 3, output_tokens: 1 });
  assert.deepEqual(s.hits.map((h) => h.path), ["/api/chat"]);
  assert.equal(s.hits[0].headers.authorization, undefined, "no credential on a request that lands on this box");
  assert.equal(JSON.parse(s.hits[0].body).model, "llama3.1");
});

test("the Ollama embedding path (ai/provider.js getEmbedding) reaches an own-host /api/embed with no Authorization", async (t) => {
  const s = await ownHostOllama();
  if (!s) return t.skip("port 11434 is in use on this box (a real Ollama)");
  s.clear();

  // The provider config comes from <CROW_HOME>/.env (env-manager), which is what
  // routes/bundles.js writes for the Ollama bundle (AI_PROVIDER=ollama,
  // AI_BASE_URL=http://localhost:11434).
  const home = mkdtempSync(join(tmpdir(), "ollama-guard-home-"));
  const prev = { CROW_HOME: process.env.CROW_HOME, CROW_APP_ENV_PATH: process.env.CROW_APP_ENV_PATH };
  try {
    writeFileSync(join(home, ".env"), `AI_PROVIDER=ollama\nAI_BASE_URL=${s.base}\nAI_MODEL=nomic-embed-text\n`);
    process.env.CROW_HOME = home;
    delete process.env.CROW_APP_ENV_PATH;
    invalidateConfigCache();
    const vec = await getEmbedding("the capital of Portugal");
    assert.ok(vec instanceof Float32Array, "an own-host Ollama embedding now works (it was refused before)");
    assert.equal(vec.length, 3);
    assert.deepEqual(s.hits.map((h) => h.path), ["/api/embed"]);
    assert.equal(s.hits[0].headers.authorization, undefined);
    assert.equal(JSON.parse(s.hits[0].body).model, "nomic-embed-text");
  } finally {
    invalidateConfigCache();
    for (const [k, v] of Object.entries(prev)) { if (v == null) delete process.env[k]; else process.env[k] = v; }
    rmSync(home, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// The other half: an own-host port that is NOT Ollama's is never opened.
// ---------------------------------------------------------------------------

test("guardedFetch and the adapter refuse an own-host port that is not Ollama's, and that listener is never hit", async () => {
  // A real listener on a port a bot could pick. Under the old deny-list this
  // was a legal own-host Ollama ("8080 is not a gateway port"); now the port
  // itself is the rule, so nothing may reach it.
  const s = await listen((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ embeddings: [[1]] }));
  });
  for (const path of ["/api/chat", "/api/embed"]) {
    await assert.rejects(
      () => guardedFetch(`${s.base}${path}`, {
        headers: { "Content-Type": "application/json", Authorization: "Bearer row-key", "x-api-key": "b" },
        body: JSON.stringify({ model: "m", input: "x" }),
        guard: { kind: "ollama" },
      }),
      (e) => e.code === "SELF_TARGET_REFUSED" && e.message === SELF_REFUSED_MESSAGE,
      path,
    );
    const adapter = createOllamaAdapter({ baseUrl: s.base, model: "m" });
    await assert.rejects(
      () => adapter.chatStream([{ role: "user", content: "hi" }], []).next(),
      (e) => e.code === "SELF_TARGET_REFUSED",
      path,
    );
  }
  assert.deepEqual(s.hits, [], "the bot-chosen port was never driven");
});

test("guardedFetch on the own-host Ollama port drops a credential", async (t) => {
  const s = await ownHostOllama();
  if (!s) return t.skip("port 11434 is in use on this box (a real Ollama)");
  s.clear();
  const res = await guardedFetch(`${s.base}/api/embed`, {
    headers: { "Content-Type": "application/json", Authorization: "Bearer row-key", "x-api-key": "b" },
    body: JSON.stringify({ model: "nomic-embed-text", input: "x" }),
    guard: { kind: "ollama" },
  });
  assert.equal(res.status, 200);
  assert.deepEqual(s.hits.map((h) => h.path), ["/api/embed"]);
  assert.equal(s.hits[0].headers.authorization, undefined);
  assert.equal(s.hits[0].headers["x-api-key"], undefined);
});

test("a real listener on any OTHER own-host port (a gateway's, a Caddy's, a free one) is refused and never hit", async () => {
  // 3001/3008/3002 are co-hosted gateway ports, 3009 and 8080 are ports the old
  // deny-list never covered, 80/443 are a local Caddy. Whichever of them this
  // box lets us bind, the rule must keep every byte away.
  for (const port of [3001, 3002, 3008, 3009, 8080, 80, 443]) {
    const s = await listenAt(port, (req, res) => { res.writeHead(200); res.end("{}"); });
    if (!s) continue;   // a live gateway / Caddy / another process holds it, or no privilege to bind it
    for (const path of ["/api/chat", "/api/embed"]) {
      await assert.rejects(
        () => guardedFetch(`http://127.0.0.1:${port}${path}`, { body: "{}", guard: { kind: "ollama" } }),
        (e) => e.code === "SELF_TARGET_REFUSED",
        `:${port}${path}`,
      );
    }
    const adapter = createOllamaAdapter({ baseUrl: s.base, model: "m" });
    await assert.rejects(() => adapter.chatStream([{ role: "user", content: "hi" }], []).next(), (e) => e.code === "SELF_TARGET_REFUSED");
    assert.deepEqual(s.hits, [], `the non-Ollama own-host port ${port} was never driven`);
  }
});