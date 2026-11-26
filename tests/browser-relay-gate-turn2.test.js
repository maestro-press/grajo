/**
 * The cleanup's verification scan must WAIT for the closes it issued (turn 2, prod regression
 * 1.9.2).
 *
 * A real Chromium answers `Target.closeTarget` BEFORE the target is destroyed (and
 * `Target.disposeBrowserContext` before the context and its pages are gone). The cleanup closes
 * every page, then lists the targets a few milliseconds later for the verification scan — and
 * still sees the page it just closed (`attached: true`, its own gate record already
 * `closed: true, gateClosed: true`). The scan treats any non-replacement, non-exempt target as
 * dirty, returns false, and the stop path kills Chromium and restarts the container. It hits on
 * turn 2, when the page the previous turn's client used is the previous cleanup's replacement
 * page, and it is intermittent live (~1 in 3).
 *
 * The fixture used to destroy targets synchronously, so no test ever saw it. The knob
 * `FAKE_CHROME_DESTROY_DELAY_MS` (tests/fixtures/fake-chromium-gate.mjs) gives the fixture the
 * real order: the close is answered at once and the target (or context) stays listed for that
 * many ms.
 *
 * The tests, all driving the real relay (bundles/browser/cdp-relay.mjs, no-flag mode):
 *   a. the exact two-turn sequence, and the gate reaches IDLE after each turn;
 *   b. a page in a NON-default context: the context disposal is the last thing that leaves the
 *      listing, so the check after the disposal is exercised too;
 *   c. FAIL CLOSED: a close that outlives the cleanup budget still takes the stop path;
 *   d. NOTHING RELAXED: a target the gate did not close, still listed at the scan, fails the
 *      scan AT ONCE (no waiting, no forgiving) with the delay knob on;
 *   e. the boot neutralisation (a context at launch) is the same cleanup, and reaches ready;
 *   e2. FAIL CLOSED: a page the gate never closed itself — one the browser made in a
 *      NON-default context after the navigation pass, which only the context disposal took
 *      away — is not waited on, so the scan fails and the stop path decides;
 *   f. the reverse: a non-page target the GATE closed (an unrecorded worker the remainder loop
 *      closes) IS waited on, so the cleanup still reaches IDLE with the destroy delay on;
 *   g. a worker that attaches MID-CLEANUP — after the remainder listing, before the scan — is a
 *      close of this run too (`closeGateTarget`), so the scan waits for it and the cleanup
 *      reaches IDLE.
 *
 * The helpers are copies of the ones in tests/browser-relay-gate-sigterm.test.js (as that file
 * copies them from tests/browser-relay-gate.test.js): the files stay independent.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import WebSocket from "ws";
import { readTrace } from "./fixtures/read-trace.mjs";

const RELAY = fileURLToPath(new URL("../bundles/browser/cdp-relay.mjs", import.meta.url));
const FIXTURE = fileURLToPath(new URL("./fixtures/fake-chromium-gate.mjs", import.meta.url));
const TOKEN = "5a7c1f".repeat(10) + "c0de";

/** The guard's init-script marker: the constant the relay's coverage rule looks for. */
const MARKER = "crow-private-address-guard:v1";
/** Playwright wraps every init script, so the marker is never the first line of `source`. */
const MARKER_WRAPPED = `(() => {\n  // ${MARKER}\n})();`;
/** The `exceptionsHash` a declaring client sends; logged, used for nothing else. */
const EXCEPTIONS_HASH = "0123456789abcdef";
/** The intent header: a client that wants the gate to treat it as guard-bearing. */
const INTENT_HEADER = "X-Crow-Guard-Client";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------
// the relay under test
// ---------------------------------------------------------------------------------------

/**
 * One relay run: the real relay in no-flag mode, its Chromium the gate fixture, both on this
 * test's own temp dir. The gate's timing caps are shortened to the shape the tests assert (a
 * deadline that is enforced and read from the environment), never switched off.
 */
async function startRelay(t, extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), "crow-gate-turn2-"));
  writeFileSync(join(dir, "token"), TOKEN + "\n", { mode: 0o600 });
  let logs = "";
  const ctx = { dir, readyFile: join(dir, "ready"), tracePath: join(dir, "chromium.log"), logs: () => logs };
  const child = spawn(process.execPath, [RELAY], {
    env: {
      ...process.env,
      CDP_PORT: "0",
      CROW_CDP_TOKEN_FILE: join(dir, "token"),
      CROW_CDP_READY_FILE: ctx.readyFile,
      CROW_CDP_CHROMIUM_ARGV: JSON.stringify([process.execPath, FIXTURE]),
      FAKE_CHROME_LOG: ctx.tracePath,
      // Headful Chromium exits on its last page; the fixture does the same, so a cleanup that
      // gets the replacement wrong is visible as the browser going away.
      FAKE_EXIT_ON_NO_PAGES: "1",
      CROW_CDP_DEBUG: "0",
      CROW_CDP_START_DEADLINE_MS: "5000",
      CROW_CDP_CONNECTING_DEADLINE_MS: "4000",
      CROW_CDP_CLEANUP_BUDGET_MS: "4000",
      CROW_CDP_COMMIT_BUDGET_MS: "3000",
      CROW_CDP_SETTLE_MS: "300",
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  ctx.child = child;
  child.stdout.on("data", (d) => { logs += d; });
  child.stderr.on("data", (d) => { logs += d; });
  ctx.exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
  ctx.trace = () => readTrace(ctx.tracePath);
  ctx.records = (type) => ctx.trace().filter((r) => r.t === type);
  ctx.pid = () => ctx.records("pid")[0]?.pid ?? null;
  ctx.stop = async () => {
    const pid = ctx.pid();
    if (pid) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
    try { child.kill("SIGKILL"); } catch { /* gone */ }
    await Promise.race([ctx.exited, sleep(3000)]);
    rmSync(dir, { recursive: true, force: true });
  };
  t.after(ctx.stop);
  return ctx;
}

/** The ready file: written only after the gate is ready. */
async function waitReady(ctx, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { return JSON.parse(readFileSync(ctx.readyFile, "utf8")); } catch { /* not yet */ }
    if (ctx.child.exitCode !== null) throw new Error(`the relay exited before it was ready:\n${ctx.logs()}`);
    await sleep(50);
  }
  throw new Error(`the relay never became ready:\n${ctx.logs()}`);
}

/** One hand-written HTTP request; `ws` will not let a test forge the Host header. */
function httpRaw(port, text, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let buf = "";
    let done = false;
    const finish = () => { if (done) return; done = true; try { socket.destroy(); } catch { /* gone */ } resolve(buf); };
    const socket = net.connect(port, "127.0.0.1", () => { try { socket.write(text); } catch { finish(); } });
    socket.setTimeout(timeoutMs, finish);
    socket.on("data", (d) => { buf += d; });
    socket.on("end", finish);
    socket.on("close", finish);
    socket.on("error", finish);
  });
}

function parseReply(raw) {
  const [head, ...rest] = String(raw || "").split("\r\n\r\n");
  const lines = head.split("\r\n");
  const status = Number((lines[0] || "").split(" ")[1] || 0);
  const headers = {};
  for (const line of lines.slice(1)) {
    const i = line.indexOf(":");
    if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  const body = rest.join("\r\n\r\n");
  let json = null;
  try { json = JSON.parse(body); } catch { /* not JSON */ }
  return { status, headers, body, json, raw };
}

function request(port, { path = "/json/version", method = "GET", token = TOKEN, host = null } = {}) {
  const lines = [`${method} ${path} HTTP/1.1`, `Host: ${host === null ? `127.0.0.1:${port}` : host}`, "Connection: close", "Accept: application/json"];
  if (token !== null) lines.push(`Authorization: Bearer ${token}`);
  return httpRaw(port, lines.join("\r\n") + "\r\n\r\n").then(parseReply);
}

/** Wait for one of the relay's own log lines (the gate announces its state on every move). */
async function waitLog(ctx, re, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (re.test(ctx.logs())) return;
    if (ctx.child.exitCode !== null) break;
    await sleep(25);
  }
  assert.fail(`the relay never logged ${re}; its log was:\n${ctx.logs()}`);
}

const countLog = (ctx, re) => ctx.logs().split("\n").filter((l) => re.test(l)).length;

/**
 * Wait for a FURTHER line matching `re`, past the `already` ones the log carries: the gate logs
 * `gate state IDLE` at start-up, so "the next IDLE" is the only thing a cleanup test may wait
 * for.
 */
async function waitLogAfter(ctx, re, already, timeoutMs = 12000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (countLog(ctx, re) > already) return;
    if (ctx.child.exitCode !== null) break;
    await sleep(25);
  }
  assert.fail(`the relay never logged a further ${re} (already ${already}); its log was:\n${ctx.logs()}`);
}

/**
 * The gate is up. Three independent pieces of evidence, because each one alone has been
 * satisfied by an accident before: the ready line, the field in `/json/version`, and the gate's
 * own browser session being the FIRST one the fixture ever handed out.
 */
async function gateUp(ctx, version) {
  assert.equal(version.json?.["Crow-Guard"], "gate/1", "/json/version carries `Crow-Guard: gate/1` while the gate is ready");
  await waitLog(ctx, /gate ready/);
  assert.ok(
    ctx.records("recv").some((r) => r.method === "Target.setAutoAttach" && r.sessionId === "S1"),
    "the gate's own browser session is the first session the fixture hands out (S1), created before any client",
  );
}

/** A relay whose gate is ready, plus the WebSocket URL. */
async function withGate(t, env, fn) {
  const ctx = await startRelay(t, env);
  const ready = await waitReady(ctx);
  const version = await request(ready.port, { token: TOKEN });
  await gateUp(ctx, version);
  return fn({ ctx, ready, version, wsUrl: version.json?.webSocketDebuggerUrl });
}

// ---------------------------------------------------------------------------------------
// clients
// ---------------------------------------------------------------------------------------

/**
 * One CDP client over the relay. A PLAIN client (`header: false`) changes no gate state; a
 * GUARD-BEARING client (`header: true`) sends `X-Crow-Guard-Client: 1`, auto-attaches, and on
 * every target it is handed does what Playwright does: resume it, hook it (`Fetch.enable {*}`,
 * the marker-bearing main-world script, a nested auto-attach), then declare with
 * `Crow.guardReady`.
 */
function client(wsUrl, opts = {}) {
  const header = opts.header === true;
  const hook = opts.hook !== false;
  const attach = opts.attach !== undefined ? opts.attach === true : header || hook;
  const nest = opts.nest !== false && attach;
  const patterns = opts.patterns === undefined ? [{ urlPattern: "*", requestStage: "Request" }] : opts.patterns;
  const markerSource = opts.markerSource === undefined ? MARKER_WRAPPED : opts.markerSource;
  const utilityScript = opts.utilityScript !== false;
  const declare = opts.declare !== false;

  const headers = { Authorization: `Bearer ${TOKEN}` };
  if (header) headers[INTENT_HEADER] = "1";
  const ws = new WebSocket(wsUrl, { headers, perMessageDeflate: false, handshakeTimeout: 5000 });

  const messages = [];
  const events = [];
  const attached = []; // { sessionId, targetId, type } for every attach event this client saw
  const consumed = new Set();
  const pending = new Map();
  const waiters = [];
  let nextId = 0;
  let closeInfo = null;
  const autoContinue = opts.autoContinue !== false;

  const opened = new Promise((resolve, reject) => { ws.once("open", () => resolve()); ws.once("error", reject); });

  const call = (method, params, sessionId, timeoutMs = 8000) => {
    const id = ++nextId;
    const frame = { id, method, ...(params !== undefined ? { params } : {}), ...(sessionId ? { sessionId } : {}) };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (pending.delete(id)) reject(new Error(`no reply to ${method} (id ${id}) within ${timeoutMs} ms`));
      }, timeoutMs);
      pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
      try { ws.send(JSON.stringify(frame)); } catch { /* the socket is gone; the timer reports it */ }
    });
  };

  async function hookSession(sessionId) {
    // Playwright's order: resume first, hook afterwards.
    await call("Runtime.runIfWaitingForDebugger", {}, sessionId).catch(() => null);
    if (nest) await call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId).catch(() => null);
    if (c.hookEnabled === false) return;
    if (patterns) await call("Fetch.enable", { handleAuthRequests: true, patterns }, sessionId).catch(() => null);
    if (markerSource !== null) {
      await call("Page.addScriptToEvaluateOnNewDocument", { source: markerSource }, sessionId).catch(() => null);
    }
    if (utilityScript) await call("Page.addScriptToEvaluateOnNewDocument", { source: "", worldName: "__playwright_utility_world__" }, sessionId).catch(() => null);
  }

  ws.on("message", (data) => {
    let msg;
    try { msg = JSON.parse(String(data)); } catch { return; }
    messages.push(msg);
    if (msg.id !== undefined) {
      const settle = pending.get(msg.id);
      if (settle) { pending.delete(msg.id); settle(msg); return; }
    }
    if (typeof msg.method === "string") {
      events.push(msg);
      if (msg.method === "Target.attachedToTarget" && msg.params && msg.params.sessionId) {
        const info = msg.params.targetInfo || {};
        attached.push({ sessionId: msg.params.sessionId, targetId: info.targetId, type: info.type });
        if (attach) void hookSession(msg.params.sessionId);
      } else if (msg.method === "Fetch.requestPaused" && autoContinue) {
        const requestId = msg.params && msg.params.requestId;
        void call("Fetch.continueRequest", { requestId }, msg.sessionId).catch(() => null);
      }
    }
    for (const w of [...waiters]) {
      let index = -1;
      for (let i = 0; i < messages.length; i++) {
        if (consumed.has(i)) continue;
        if (w.pred(messages[i])) { index = i; break; }
      }
      if (index < 0) continue;
      consumed.add(index);
      waiters.splice(waiters.indexOf(w), 1);
      w.resolve(messages[index]);
    }
  });
  ws.on("close", (code, reason) => {
    closeInfo = { code, reason: String(reason || "") };
    for (const [id, settle] of [...pending]) { pending.delete(id); settle({ id, error: { code: -1, message: "the socket closed" } }); }
  });
  ws.on("error", () => { /* 'close' follows */ });

  const c = {
    ws,
    header,
    messages,
    events,
    attached,
    opened,
    hookEnabled: hook,
    closeInfo: () => closeInfo,
    call,
    of: (method) => events.filter((m) => m.method === method),
    sessionFor: (targetId) => attached.filter((a) => a.targetId === targetId).at(-1)?.sessionId ?? null,
    close() { try { ws.close(); } catch { /* gone */ } },
    /** A SIGKILLed MCP: the socket goes without a close frame. */
    kill() { try { ws.terminate(); } catch { try { ws._socket?.destroy(); } catch { /* gone */ } } },
  };

  c.armed = (async () => {
    await opened;
    if (attach) await call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }).catch(() => null);
    if (header && declare) {
      c.declareReply = await call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH }).catch(() => null);
    }
  })();
  return c;
}

const plainClient = (wsUrl, opts = {}) => client(wsUrl, { header: false, ...opts });
const guardClient = (wsUrl, opts = {}) => client(wsUrl, { header: true, ...opts });

// ---------------------------------------------------------------------------------------
// pages and the fixture's own trace
// ---------------------------------------------------------------------------------------

/** Create a page through `c` (as about:blank) and navigate it on an explicit session. */
async function makePage(c, url = "about:blank") {
  const created = await c.call("Target.createTarget", { url: "about:blank" });
  const targetId = created.result?.targetId;
  assert.ok(targetId, `the fixture handed back a page: ${JSON.stringify(created)}`);
  const attached = await c.call("Target.attachToTarget", { targetId, flatten: true });
  const sessionId = attached.result?.sessionId;
  assert.ok(sessionId, `the relay handed back a session for ${targetId}: ${JSON.stringify(attached)}`);
  if (url !== "about:blank") await c.call("Page.navigate", { url }, sessionId);
  return { targetId, sessionId };
}

/** Wait for the client's own auto-attach to hand it a session on this target. */
async function waitSession(c, targetId, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const sessionId = c.sessionFor(targetId);
    if (sessionId) return sessionId;
    await sleep(25);
  }
  assert.fail(`the client was never handed a session on ${targetId} (it saw ${JSON.stringify(c.attached)})`);
}

/** A plain observer: it changes no gate state and can read the browser's own lists. */
async function observer(wsUrl) {
  const c = plainClient(wsUrl, { attach: false });
  await c.armed;
  return c;
}

/** The pages a `Target.getTargets` answer carries, through the relay. */
async function listedPages(c) {
  const reply = await c.call("Target.getTargets");
  assert.ok(reply.result, `Target.getTargets answered: ${JSON.stringify(reply)}`);
  return reply.result.targetInfos.filter((info) => info.type === "page");
}

/** The relay must not have taken the stop path, and must still be running. */
function assertStillServing(ctx) {
  assert.equal(
    ctx.logs().includes("the stop path"),
    false,
    `the relay must not take the stop path; its log was:\n${ctx.logs()}`,
  );
  assert.equal(ctx.child.exitCode, null, `the relay is still running; its log was:\n${ctx.logs()}`);
}

// ---------------------------------------------------------------------------------------
// a — the exact two-turn sequence
// ---------------------------------------------------------------------------------------

test("a: turn 2 — a cleanup that closes the previous replacement still reaches IDLE", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_DESTROY_DELAY_MS: "150" }, async ({ ctx, wsUrl }) => {
    // TURN 1: a guard-bearing client creates a page, navigates it, and drops.
    const idlesBefore1 = countLog(ctx, /gate state IDLE/);
    const guard1 = guardClient(wsUrl);
    await guard1.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page1 = await makePage(guard1, "https://bot.example/turn-1");
    guard1.kill();
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore1);

    // The page the cleanup left: the replacement the turn-2 client will use.
    const replacement = ctx.records("create-target").at(-1)?.targetId;
    assert.ok(replacement, `the cleanup created its replacement page: ${JSON.stringify(ctx.records("create-target"))}`);
    assert.notEqual(replacement, page1.targetId, "turn 1's cleanup closed the bot page and left a fresh one");

    // TURN 2: a fresh guard-bearing client attaches to the one page left (the replacement),
    // uses it, and drops.
    const idlesBefore2 = countLog(ctx, /gate state IDLE/);
    const guard2 = guardClient(wsUrl);
    await guard2.armed;
    const session2 = await waitSession(guard2, replacement);
    const evaluated = await guard2.call("Runtime.evaluate", { expression: "1 + 1", returnByValue: true }, session2);
    assert.ok(evaluated && !evaluated.error, `Runtime.evaluate on the replacement page: ${JSON.stringify(evaluated)}`);
    guard2.kill();
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore2);

    // …and exactly one page is left, the turn-2 cleanup's own replacement.
    const obs = await observer(wsUrl);
    const pages = await listedPages(obs);
    const all = (await obs.call("Target.getTargets")).result.targetInfos;
    obs.close();
    assert.equal(pages.length, 1, `exactly one page is left: ${JSON.stringify(all)}`);
    assert.equal(all.length, 1, `and nothing else: ${JSON.stringify(all)}`);
    assert.equal(pages[0].url, "about:blank", `the page left is a fresh about:blank replacement: ${JSON.stringify(pages[0])}`);
    assertStillServing(ctx);
  });
});

// ---------------------------------------------------------------------------------------
// b — a page in a non-default context (the disposal's own race)
// ---------------------------------------------------------------------------------------

test("b: a page in a non-default context — the disposed context's own check still ends in IDLE", async (t) => {
  await withGate(t, {
    FAKE_CHROME_EXTENSION_WORKERS: "",
    FAKE_CHROME_DESTROY_DELAY_MS: "150",
    // The cleanup's page closes are answered 600 ms late, so the pages are long gone from the
    // listing by the time the CONTEXT is disposed: the context (and its pages) is the last
    // thing that leaves, which is the check after the disposal.
    FAKE_CHROME_DELAY_METHODS: "Target.closeTarget:600",
  }, async ({ ctx, wsUrl }) => {
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const contextReply = await guard.call("Target.createBrowserContext", {});
    const contextId = contextReply.result?.browserContextId;
    assert.ok(contextId, `the fixture handed out a browser context: ${JSON.stringify(contextReply)}`);
    const created = await guard.call("Target.createTarget", { url: "about:blank", browserContextId: contextId });
    const targetId = created.result?.targetId;
    assert.ok(targetId, `a page in that context: ${JSON.stringify(created)}`);
    const attachReply = await guard.call("Target.attachToTarget", { targetId, flatten: true });
    const sessionId = attachReply.result?.sessionId;
    assert.ok(sessionId, `a session on it: ${JSON.stringify(attachReply)}`);
    const nav = await guard.call("Page.navigate", { url: "https://bot.example/context" }, sessionId);
    assert.ok(nav.result?.loaderId, `the page navigated: ${JSON.stringify(nav)}`);

    guard.kill();
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);

    const obs = await observer(wsUrl);
    const contexts = await obs.call("Target.getBrowserContexts");
    const pages = await listedPages(obs);
    obs.close();
    assert.deepEqual(contexts.result?.browserContextIds ?? [], [], `the context was disposed: ${JSON.stringify(contexts)}`);
    assert.equal(pages.length, 1, `only the replacement page is left: ${JSON.stringify(pages)}`);
    assertStillServing(ctx);
  });
});

// ---------------------------------------------------------------------------------------
// c — FAIL CLOSED: a close that outlives the budget
// ---------------------------------------------------------------------------------------

test("c: fail closed — a closed page that does not leave the list in the budget still stops the browser", async (t) => {
  await withGate(t, {
    FAKE_CHROME_EXTENSION_WORKERS: "",
    // The destroy is 2000 ms away; the cleanup has 500 ms, so the page it closed is still
    // listed when the budget runs out.
    FAKE_CHROME_DESTROY_DELAY_MS: "2000",
    CROW_CDP_CLEANUP_BUDGET_MS: "500",
  }, async ({ ctx, wsUrl }) => {
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page = await makePage(guard, "https://bot.example/slow-destroy");
    assert.ok(page.targetId);

    const droppedAt = Date.now();
    guard.kill();
    await waitLog(ctx, /the stop path: the cleanup could not leave the pages clean/);
    const afterStop = Date.now() - droppedAt;
    assert.ok(afterStop < 1800, `the 500 ms budget decided, not the 2000 ms destroy (the stop came ${afterStop} ms after the drop)`);
    assert.ok(
      ctx.records("recv").some((r) => r.method === "Target.closeTarget"),
      "the cleanup had closed a target before it scanned",
    );

    const exit = await Promise.race([ctx.exited, sleep(15000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `the relay exits after the stop path; its log was:\n${ctx.logs()}`);
    assert.notEqual(exit.code, 0, `the stop path never exits 0 (code ${exit.code}, signal ${exit.signal}); its log was:\n${ctx.logs()}`);
  });
});

// ---------------------------------------------------------------------------------------
// d — NOTHING RELAXED: a target the gate did not close fails the scan at once
// ---------------------------------------------------------------------------------------

test("d: nothing relaxed — an unrecorded extra target at the scan fails it at once, with the delay knob on", async (t) => {
  await withGate(t, {
    FAKE_CHROME_EXTENSION_WORKERS: "",
    FAKE_CHROME_DESTROY_DELAY_MS: "150",
    // The start page is closed before the cleanup runs, so the cleanup has no page of its own
    // to close: nothing in its scan has anything to wait for when the extra target shows.
    FAKE_EXIT_ON_NO_PAGES: "0",
  }, async ({ ctx, wsUrl }) => {
    const obs = await observer(wsUrl);
    // The start page goes, closed by a CLIENT (not the gate), and the destroy lands.
    const closed = await obs.call("Target.closeTarget", { targetId: "P1" });
    assert.equal(closed.result?.success, true, `the start page closed: ${JSON.stringify(closed)}`);
    await sleep(400);
    // An extra target NOTHING is in front of: its owner is a target id no session has, so it is
    // announced to no session at all and the gate has no record and no session for it — it is
    // only ever LISTED in `Target.getTargets`.
    const spawned = await obs.call("Test.spawnTarget", { type: "worker", url: "https://bot.example/ghost.js", ownerId: "P-none" });
    const ghostId = spawned.result?.targetId;
    assert.ok(ghostId, `an extra, unannounced target exists: ${JSON.stringify(spawned)}`);
    assert.equal(
      ctx.records("recv").some((r) => r.method === "Target.attachedToTarget" && r.params?.targetInfo?.targetId === ghostId),
      false,
      `no session was ever told about ${ghostId}`,
    );

    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const droppedAt = Date.now();
    guard.kill();
    // Fail closed AT ONCE: the cleanup's budget is 4000 ms and the destroy knob is 150 ms, so a
    // scan that waited on (or forgave) a target the gate did not close would either take
    // seconds or pass. Neither may happen.
    await waitLog(ctx, /the stop path: the cleanup could not leave the pages clean/);
    const afterStop = Date.now() - droppedAt;
    assert.ok(afterStop < 2000, `the scan failed at once, it did not wait for the budget or the destroy (${afterStop} ms after the drop)`);
    obs.close();
  });
});

// ---------------------------------------------------------------------------------------
// e — the boot neutralisation is the same cleanup
// ---------------------------------------------------------------------------------------

test("e: the boot neutralisation disposes a context at launch and the gate still comes up", async (t) => {
  // A browser that starts with a context of its own is not at the neutral state, so the start
  // sequence runs the SAME cleanup (`startCleanup` -> `runCleanupSequence`); a disposal that is
  // still listed for a moment must not fail the start.
  await withGate(t, {
    FAKE_CHROME_EXTENSION_WORKERS: "",
    FAKE_CHROME_DESTROY_DELAY_MS: "150",
    FAKE_CHROME_START_CONTEXT: "1",
  }, async ({ ctx, wsUrl }) => {
    await waitLog(ctx, /gate state IDLE/);
    const obs = await observer(wsUrl);
    const contexts = await obs.call("Target.getBrowserContexts");
    const pages = await listedPages(obs);
    obs.close();
    assert.deepEqual(contexts.result?.browserContextIds ?? [], [], `the launch context was disposed: ${JSON.stringify(contexts)}`);
    assert.equal(pages.length, 1, `one about:blank page is left: ${JSON.stringify(pages)}`);
    assertStillServing(ctx);
  });
});

// ---------------------------------------------------------------------------------------
// e2 — FAIL CLOSED: a page only the CONTEXT DISPOSAL took away is not a close of this run
// ---------------------------------------------------------------------------------------

test("e2: a page the gate never closed — made in a non-default context after the navigation pass — still takes the stop path", async (t) => {
  await withGate(t, {
    FAKE_CHROME_EXTENSION_WORKERS: "",
    FAKE_CHROME_DESTROY_DELAY_MS: "400",
    // The browser makes a page in a fresh context of its own right after the cleanup's first
    // blank navigation: a popup that appears between the navigation pass and the scan. Nothing
    // the gate asked for closes it; only the cleanup's context disposal does, in the fixture.
    FAKE_CHROME_LATE_CONTEXT_PAGE_AFTER_NAVIGATE: "1",
  }, async ({ ctx, wsUrl }) => {
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page = await makePage(guard, "https://bot.example/late-popup-parent");
    assert.ok(page.targetId);

    const droppedAt = Date.now();
    guard.kill();
    // A page the gate did not close is never waited on, skipped or forgiven: the scan fails and
    // the stop path decides.
    await waitLog(ctx, /the stop path: the cleanup could not leave the pages clean/);
    const afterStop = Date.now() - droppedAt;

    const late = ctx.records("late-page").at(-1);
    assert.ok(late, `the browser made the late page: ${JSON.stringify(ctx.trace().slice(-10))}`);
    assert.match(String(late.contextId), /^C\d+$/, `the late page is in a NON-default context: ${JSON.stringify(late)}`);
    assert.equal(
      ctx.records("recv").some((r) => r.method === "Target.closeTarget" && r.params?.targetId === late.targetId),
      false,
      `the gate never sent a close for ${late.targetId} (only the context disposal took it away)`,
    );
    assert.ok(afterStop < 2500, `the scan failed on a page the gate did not close (${afterStop} ms after the drop)`);

    const exit = await Promise.race([ctx.exited, sleep(15000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `the relay exits after the stop path; its log was:\n${ctx.logs()}`);
    assert.notEqual(exit.code, 0, `the stop path never exits 0 (code ${exit.code}, signal ${exit.signal}); its log was:\n${ctx.logs()}`);
  });
});

// ---------------------------------------------------------------------------------------
// f — an unrecorded non-page target the remainder loop closes IS waited on
// ---------------------------------------------------------------------------------------

test("f: an unrecorded worker the remainder loop closes still ends in IDLE, with the destroy delay on", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_DESTROY_DELAY_MS: "400" }, async ({ ctx, wsUrl }) => {
    const obs = await observer(wsUrl);
    // A target NOTHING is in front of: its owner is a target id no session has, so it is
    // announced to no session and the gate has no record and no session for it. Only the
    // cleanup's remainder loop ever closes it — and that is a close of THIS run.
    const spawned = await obs.call("Test.spawnTarget", { type: "worker", url: "https://bot.example/ghost.js", ownerId: "P-none" });
    const ghostId = spawned.result?.targetId;
    assert.ok(ghostId, `an unannounced worker exists: ${JSON.stringify(spawned)}`);
    assert.equal(
      ctx.records("recv").some((r) => r.method === "Target.attachedToTarget" && r.params?.targetInfo?.targetId === ghostId),
      false,
      `no session was ever told about ${ghostId}`,
    );

    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill();
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);

    // The remainder loop closed it, and the scan WAITED for that close to land (400 ms away).
    assert.ok(
      ctx.records("recv").some((r) => r.method === "Target.closeTarget" && r.params?.targetId === ghostId),
      `the cleanup's remainder loop closed ${ghostId}`,
    );
    const pages = await listedPages(obs);
    const all = (await obs.call("Target.getTargets")).result.targetInfos;
    obs.close();
    assert.equal(all.some((info) => info.targetId === ghostId), false, `the worker is gone: ${JSON.stringify(all)}`);
    assert.equal(pages.length, 1, `only the replacement page is left: ${JSON.stringify(pages)}`);
    assertStillServing(ctx);
  });
});

// ---------------------------------------------------------------------------------------
// g — a worker that attaches MID-CLEANUP (after the remainder listing) is waited on too
// ---------------------------------------------------------------------------------------

test("g: a worker the gate closes mid-cleanup — after the remainder listing — still ends in IDLE", async (t) => {
  await withGate(t, {
    FAKE_CHROME_EXTENSION_WORKERS: "",
    FAKE_CHROME_DESTROY_DELAY_MS: "300",
    // The worker attaches at the instant the cleanup disposes the guard's context, which is
    // AFTER the cleanup's remainder listing and BEFORE its verification scan: the one window in
    // which a target can attach without that listing ever carrying it. It is not exempt (a bot
    // URL, a shared worker), so `onGateAttached` closes it.
    FAKE_CHROME_WORKER_ON_CONTEXT_DISPOSE: "shared_worker|https://bot.example/late-shared.js",
  }, async ({ ctx, wsUrl }) => {
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    // A context for the cleanup to dispose (the moment the worker shows up), and a page for the
    // cleanup's own navigation pass.
    const contextReply = await guard.call("Target.createBrowserContext", {});
    assert.ok(contextReply.result?.browserContextId, `the fixture handed out a browser context: ${JSON.stringify(contextReply)}`);
    const page = await makePage(guard, "https://bot.example/worker-parent");
    assert.ok(page.targetId);

    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill();
    // The close `closeGateTarget` sent is a close of THIS run, so the scan waits for the
    // worker's destroy (300 ms away) instead of failing on a target the gate closed itself.
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);

    const late = ctx.records("late-worker").at(-1);
    assert.ok(late, `the browser made the mid-cleanup worker: ${JSON.stringify(ctx.trace().slice(-10))}`);
    assert.equal(late.type, "shared_worker", `a shared worker, never component-extension-exempt: ${JSON.stringify(late)}`);
    assert.ok(
      ctx.records("recv").some((r) => r.method === "Target.closeTarget" && r.params?.targetId === late.targetId),
      `the gate closed ${late.targetId} while it cleaned up`,
    );

    const obs = await observer(wsUrl);
    const all = (await obs.call("Target.getTargets")).result.targetInfos;
    obs.close();
    assert.equal(all.some((info) => info.targetId === late.targetId), false, `the worker is gone: ${JSON.stringify(all)}`);
    assert.equal(all.filter((info) => info.type === "page").length, 1, `only the replacement page is left: ${JSON.stringify(all)}`);
    assertStillServing(ctx);
  });
});