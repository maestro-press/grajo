/**
 * THE LISTENER HALF OF THE OWN-HOST RULE (adapter guard + `completeText`).
 *
 * Round A gave the model door, the voice route and `completeText` the own-host
 * PATH rule, and round B gave every provider ADAPTER the same rule (address
 * class, path, no credential, DNS pinning). Both judged the ADDRESS. The gap: a
 * contained bot shares the host network (CROW_PI_CONTAIN_NET=off) and has
 * crow.db bound read-write, so it writes the very row that names
 * `http://127.0.0.1:<free port>/v1` and then LISTENS THERE ITSELF with a relay.
 * "Loopback, `/v1/chat/completions`, no query" passes every check — and the
 * owner's content (or a speech profile's audio) leaves the box through the bot.
 *
 * So an own-host target must ALSO pass `isKnownLocalModelTarget`
 * (servers/gateway/models/local-model-servers.js): the port vouched by a source
 * OUTSIDE crow.db (a Docker/bundle-compose publish, a live native reservation, an
 * operator pin, this gateway's own listen port, or a listening socket this very
 * process owns) AND the process holding the LISTEN socket is not a bot.
 *
 * Red-first. The bot's listener here is a REAL HTTP server in a SEPARATE PROCESS
 * of the same uid (`tests/fixtures/untrusted-listener.mjs`), which is what
 * "listener-not-trusted" means; every refused path is followed by a CONTROL
 * request from the test process, so "it received nothing" cannot mean "the
 * fixture was dead". Two ports are used: one nothing vouches for at all, and one
 * a Docker publish vouches (the squat: the port legitimately IS the model's).
 *
 * The memory MCP server's own calls (`embedText`/`rerank`) run in a separate
 * process and are covered by the same guard; its half of this red-first test
 * lives in `tests/memory-provider-target-guard.test.js`, where the temp db
 * fixture already is.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import createOpenAIAdapter from "../servers/gateway/ai/adapters/openai.js";
import createFasterWhisper from "../servers/gateway/ai/stt/adapters/fasterwhisper.js";
import { completeText } from "../servers/gateway/routes/llm-router.js";
import { SELF_REFUSED_MESSAGE } from "../servers/gateway/ai/adapter-guard.js";
import { isKnownLocalModelTarget } from "../servers/gateway/models/local-model-servers.js";
import { safeRequest } from "../servers/gateway/models/safe-upstream.js";
import { CONNECTION_NOT_TRUSTED } from "../servers/gateway/models/verified-connect.js";
import { spawnUntrustedListener } from "./fixtures/untrusted-listener.mjs";
import { spawnReusePortListener } from "./fixtures/reuseport-listener.mjs";

const HOME = mkdtempSync(join(tmpdir(), "local-model-vouch-home-"));
after(() => rmSync(HOME, { recursive: true, force: true }));

const BOT_KEY = "bot-written-key";

/** The REAL predicate, judging the real /proc, with no vouch source at all.
 * `crowHome` is this file's empty home so nothing on the real box can vouch. */
const unvouched = (url) => isKnownLocalModelTarget(url, { crowHome: HOME });

/** The same predicate, with a Docker publish vouching `port` on loopback — the
 * port of a model container that is running (or stopped: a stopped container
 * keeps its bindings, which is exactly the squat). */
const vouchedByDocker = (port) => (url) => isKnownLocalModelTarget(url, {
  crowHome: HOME,
  dockerEntries: [{ address: "127.0.0.1", port }],
});

/** Every refused request path, driven against one bot listener. */
async function refusalsAllSee(botPort, known, providerId, logs) {
  const base = `http://127.0.0.1:${botPort}/v1`;
  // The adapter/speech guard's fixed wording (ai/adapter-guard.js).
  const refusedByGuard = (e) => e.code === "SELF_TARGET_REFUSED" && e.message === SELF_REFUSED_MESSAGE;
  // `completeText`'s own existing refusal shape (`selfRefused()` in
  // routes/llm-router.js): the same code, its own message. No new wording.
  const refusedByJob = (e) => e.code === "SELF_TARGET_REFUSED" && e.message === "completeText: refused, the model is on this gateway";

  // 1. The scheduled-job path (session summaries, report commentary, Ramble).
  await assert.rejects(
    () => completeText({ model: `${providerId}/m`, prompt: "the owner's private notes" }, {
      resolveKeyFn: async () => ({ baseUrl: base, model: "m", apiKey: BOT_KEY, host: "local" }),
      reservationFn: () => null,
      recordUsageFn: async () => {},
      knownLocalTargetFn: known,
      logFn: (line) => logs.push(line),
    }),
    refusedByJob,
    "completeText must refuse the bot's listener",
  );

  // 2. The provider ADAPTER (kiosk/glasses/phone voice turns, dashboard chat).
  const adapter = createOpenAIAdapter({
    baseUrl: base, apiKey: BOT_KEY, model: "m",
    guard: { knownLocalTargetFn: known, providerId, logFn: (line) => logs.push(line) },
  });
  await assert.rejects(
    () => adapter.chatStream([{ role: "user", content: "hi" }], []).next(),
    refusedByGuard,
    "the openai adapter must refuse the bot's listener",
  );

  // 3. A SPEECH profile (audio plus a credential in bot-writable settings).
  const stt = createFasterWhisper({
    baseUrl: base, apiKey: BOT_KEY,
    guard: { knownLocalTargetFn: known, providerId, logFn: (line) => logs.push(line) },
  });
  await assert.rejects(
    () => stt.transcribe(Buffer.from("RIFF....")),
    refusedByGuard,
    "a speech transcribe must refuse the bot's listener",
  );
}

test("RED FIRST: on an UNVOUCHED own-host port, the bot's listener receives nothing from completeText, an OpenAI chat or a speech transcribe", async () => {
  const bot = await spawnUntrustedListener();
  try {
    const logs = [];
    await refusalsAllSee(bot.port, unvouched, "squat", logs);
    // SECURITY: a bounded window plus the fixture's own sync round-trip, so a
    // late-arriving hit is SEEN rather than missed (L2).
    await bot.settle();
    assert.deepEqual(bot.hits, [], `SECURITY: bot received bytes: ${JSON.stringify(bot.hits)}`);
    assert.equal(logs.length, 3, logs.join("\n"));
    assert.deepEqual(logs, [
      `[door] own-host target 127.0.0.1:${bot.port} is not a known model server (provider squat, not-vouched)`,
      `[door] own-host target 127.0.0.1:${bot.port} is not a known model server (provider squat, not-vouched)`,
      `[door] own-host target 127.0.0.1:${bot.port} is not a known model server (provider squat, not-vouched)`,
    ], "one log line per refusal, in the door's fixed shape");

    // CONTROL: the listener is alive and reachable from this process, so
    // "nothing arrived" is the refusal and not a dead fixture.
    await bot.control({ method: "POST", path: "/v1/chat/completions" });
    assert.deepEqual(bot.hits, ["POST /v1/chat/completions"], `CONTROL: bot liveness probe not observed (${JSON.stringify(bot.hits)})`);
  } finally {
    await bot.close();
  }
});

test("RED FIRST: on a VOUCHED own-host port (a Docker publish, i.e. the model container's own port), the bot's listener still receives nothing", async () => {
  const bot = await spawnUntrustedListener();
  try {
    const logs = [];
    // The port IS the model's — that is the attack. Docker's binding vouches it;
    // the LISTEN socket belongs to a process Crow never started, so the rule's
    // second half refuses.
    await refusalsAllSee(bot.port, vouchedByDocker(bot.port), "squat", logs);
    await bot.settle();
    assert.deepEqual(bot.hits, [], `SECURITY: a vouched port held by a bot's own process received bytes: ${JSON.stringify(bot.hits)}`);
    assert.equal(logs.length, 3, logs.join("\n"));
    for (const line of logs) {
      assert.equal(line, `[door] own-host target 127.0.0.1:${bot.port} is not a known model server (provider squat, listener-not-trusted)`);
    }

    await bot.control({ method: "POST", path: "/v1/embeddings" });
    assert.deepEqual(bot.hits, ["POST /v1/embeddings"], `CONTROL: bot liveness probe not observed (${JSON.stringify(bot.hits)})`);
  } finally {
    await bot.close();
  }
});

test("the vouch is not a port number and not an address class: the same listener IS reached when this process is the one holding the socket", async () => {
  // The other half of the same rule, so "it refused" cannot be a blanket refusal
  // of loopback: a listener in THIS process passes the "socket owned by this
  // process" vouch (nothing a bot writes into crow.db can make the gateway open a
  // listening socket), so the very same URLs work with nothing stubbed.
  const http = await import("node:http");
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push(req.url);
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: "answers" } }] })}\n\n`);
    res.end("data: [DONE]\n\n");
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  try {
    const adapter = createOpenAIAdapter({ baseUrl: `http://127.0.0.1:${port}/v1`, apiKey: BOT_KEY, model: "m" });
    const deltas = [];
    for await (const ev of adapter.chatStream([{ role: "user", content: "hi" }], [])) {
      if (ev.type === "content_delta") deltas.push(ev.text);
    }
    assert.deepEqual(deltas, ["answers"]);
    assert.deepEqual(seen, ["/v1/chat/completions"]);
  } finally {
    await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
  }
});

// ---------------------------------------------------------------------------
// H1 — THE ACCEPTED CONNECTION (real kernel). llama.cpp's server sets
// SO_REUSEPORT, so a same-uid bot can open its OWN listener on the model's port
// BETWEEN the LISTEN check and the connect and the kernel may hand it the
// connection; a pooled keep-alive socket would stretch one win over many requests.
// The forward therefore opens the socket itself, verifies the ACCEPTED end before
// writing a request byte, and never pools it.
// ---------------------------------------------------------------------------

/** A trusted listener in THIS process that shares its port with a reuseport
 * listener (H1): it counts accepted connections, requests and the `Connection`
 * header each request carried — enough to prove "one connection per forward" and
 * "this was the socket that answered". */
async function trustedReusePortListener() {
  const http = await import("node:http");
  const seen = [];
  let connections = 0;
  const server = http.createServer({ reusePort: true }, (req, res) => {
    seen.push({ method: req.method, path: req.url, connection: req.headers.connection || null });
    // SSE, so the provider adapter's streaming path reads the same bytes the first
    // test's `safeRequest` only checks the status of.
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: "answers" } }] })}\n\n`);
    res.end("data: [DONE]\n\n");
  });
  server.on("connection", () => { connections += 1; });
  const listening = await new Promise((resolve) => {
    server.once("error", () => resolve(false));
    server.listen({ port: 0, host: "127.0.0.1", reusePort: true }, () => resolve(true));
  });
  if (!listening) { try { server.close(); } catch { /* never bound */ } return null; }
  return {
    server,
    port: server.address().port,
    seen,
    get connections() { return connections; },
    close: () => new Promise((r) => { try { server.closeAllConnections?.(); } catch { /* gone */ } server.close(() => r()); }),
  };
}

test("RED FIRST (H1): over 50 forwards the kernel hands SOME connections to a same-uid SO_REUSEPORT bot, and not one request reaches it — each forward opens its own connection", async (t) => {
  const trusted = await trustedReusePortListener();
  if (!trusted) return t.skip("this Node runtime cannot open a reuseport listener");
  const bot = await spawnReusePortListener({ address: "127.0.0.1", port: trusted.port });
  try {
    const url = `http://127.0.0.1:${trusted.port}/v1/chat/completions`;
    let answered = 0;
    let refused = 0;
    for (let i = 0; i < 50; i++) {
      try {
        const res = await safeRequest(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ model: "m", messages: [{ role: "user", content: `turn ${i}` }] }),
          timeoutMs: 4_000,
          idleTimeoutMs: 0,
          allowAddressFn: () => true,
          lookupFn: () => { throw new Error("an own-host literal must not be resolved"); },
          verifiedConnection: { address: "127.0.0.1" },
        });
        assert.equal(res.status, 200);
        res.stream.destroy();
        answered += 1;
      } catch (err) {
        assert.equal(err.code, CONNECTION_NOT_TRUSTED, `unexpected transport error: ${err.code || err.message}`);
        refused += 1;
      }
    }
    assert.equal(answered + refused, 50);
    assert.ok(answered > 0, "the model's own listener answered some forwards");
    // The child's CONN/HIT reports travel over an asynchronous pipe: take the ack
    // round-trip before reading them, so "the bot received nothing" is a fact and
    // "the kernel gave it connections" is not read too early (L2).
    await bot.settle();
    assert.ok(bot.connections > 0, "the kernel DID hand some connections to the bot's reuseport socket (otherwise this test proves nothing)");
    assert.ok(refused > 0, "every connection the kernel gave to the bot was refused");
    // THE ASSERTION THAT MATTERS: no request line, header or body byte ever
    // reached the bot — its accepted connections were refused before a write.
    assert.deepEqual(bot.hits, [], `SECURITY: the bot's reuseport listener received bytes: ${JSON.stringify(bot.hits)}`);
    // Keep-alive reuse is gone: one connection per forward that the model answered,
    // and every one of them said `Connection: close`.
    assert.equal(trusted.connections, answered, "each forward opened its own connection (nothing pooled)");
    assert.deepEqual([...new Set(trusted.seen.map((s) => s.connection))], ["close"]);
    assert.equal(trusted.seen.length, answered);
  } finally {
    await bot.close();
    await trusted.close();
  }
});

test("RED FIRST (H1): an ADAPTER forward to a vouched port the bot sometimes wins is refused as connection-not-trusted, never sent, and the next forward starts from a fresh connect", async (t) => {
  const trusted = await trustedReusePortListener();
  if (!trusted) return t.skip("this Node runtime cannot open a reuseport listener");
  const bot = await spawnReusePortListener({ address: "127.0.0.1", port: trusted.port });
  const logs = [];
  try {
    // The vouch is stubbed to "vouched" on purpose: the LISTEN half is not what is
    // under test here. This is the window AFTER it — the connection the forward
    // actually gets.
    const adapter = createOpenAIAdapter({
      baseUrl: `http://127.0.0.1:${trusted.port}/v1`, apiKey: BOT_KEY, model: "m",
      guard: {
        knownLocalTargetFn: async () => ({ local: true, reason: "vouched", address: "127.0.0.1" }),
        providerId: "squat",
        logFn: (line) => logs.push(line),
      },
    });
    let answered = 0;
    let refused = 0;
    for (let i = 0; i < 40; i++) {
      try {
        const deltas = [];
        for await (const ev of adapter.chatStream([{ role: "user", content: "hi" }], [])) {
          if (ev.type === "content_delta") deltas.push(ev.text);
        }
        assert.deepEqual(deltas, ["answers"]);
        answered += 1;
      } catch (err) {
        assert.equal(err.code, "SELF_TARGET_REFUSED", `unexpected error: ${err.code || err.message}`);
        assert.equal(err.message, SELF_REFUSED_MESSAGE);
        refused += 1;
      }
    }
    assert.equal(answered + refused, 40);
    assert.ok(answered > 0 && refused > 0, `expected a mix, got ${answered} answered / ${refused} refused`);
    await bot.settle();
    assert.deepEqual(bot.hits, [], `SECURITY: no adapter request ever reached the bot: ${JSON.stringify(bot.hits)}`);
    // One line per refused forward, in the door's fixed shape, with the reason the
    // race exists for — and no line for the ones the model answered.
    assert.equal(logs.length, refused, logs.join("\n"));
    for (const line of logs) {
      assert.equal(line, `[door] own-host target 127.0.0.1:${trusted.port} is not a known model server (provider squat, connection-not-trusted)`);
    }
  } finally {
    await bot.close();
    await trusted.close();
  }
});