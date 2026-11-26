/**
 * The relay's REPLY ORDERING contract for a target it is about to hand a client (RED tests).
 *
 * Playwright's `context.newPage()` sends `Target.createTarget` on the client's own connection
 * and looks the new page up by `targetId` the moment the reply lands: it REQUIRES that
 * client's `Target.attachedToTarget` for the new target to arrive FIRST (with the event
 * second, the lookup is `undefined` and `newPage()` throws). The relay holds a client-bound
 * attach event until the gate's own interception on that target is acknowledged
 * (`record.pendingEvents` / `record.acks`), so the reply must be held behind that event too —
 * and must fail closed, never arrive out of order.
 *
 * These tests drive the real relay (bundles/browser/cdp-relay.mjs, no-flag mode) against
 * tests/fixtures/fake-chromium-gate.mjs, exactly as tests/browser-relay-gate.test.js does;
 * the fixture's `FAKE_CHROME_NEW_PAGE_ACK_DELAY_MS` knob holds the gate's ack for the page a
 * `Target.createTarget` just made, which is the window the ordering rule has to cover. The
 * client-side helpers are copied from that file (one relay, one client shape, one fake browser).
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
const TOKEN = "9c4d2e".repeat(10) + "beef";

/** The guard's init-script marker: the constant the coverage rule looks for. */
const MARKER = "crow-private-address-guard:v1";
/** Playwright wraps every init script, so the marker is never the first line of `source`. */
const MARKER_WRAPPED = `(() => {\n  // ${MARKER}\n})();`;
/** The `exceptionsHash` a declaring client sends. */
const EXCEPTIONS_HASH = "0123456789abcdef";
/** The intent header: a client that wants the gate to treat it as guard-bearing. */
const INTENT_HEADER = "X-Crow-Guard-Client";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------
// the relay under test
// ---------------------------------------------------------------------------------------

/**
 * One relay run: the real relay in no-flag mode, its Chromium the gate fixture, both on this
 * test's own temp dir. The gate's timing caps keep the shape the tests assert (a deadline
 * that is enforced and read from the environment), never switched off.
 */
async function startRelay(t, extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), "crow-gate-order-"));
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

function request(port, { path = "/json/version", token = TOKEN } = {}) {
  const lines = [`GET ${path} HTTP/1.1`, `Host: 127.0.0.1:${port}`, "Connection: close", "Accept: application/json"];
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

/**
 * The gate is up: the ready line, the field in `/json/version`, and the gate's own browser
 * session being the FIRST session the fixture ever handed out.
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
  const version = await request(ready.port);
  await gateUp(ctx, version);
  return fn({ ctx, ready, version, wsUrl: version.json?.webSocketDebuggerUrl });
}

// ---------------------------------------------------------------------------------------
// clients
// ---------------------------------------------------------------------------------------

/**
 * One CDP client over the relay (the shape tests/browser-relay-gate.test.js drives).
 *
 * A PLAIN client (`header: false`) changes no gate state. A GUARD-BEARING client (`header:
 * true`) sends `X-Crow-Guard-Client: 1`, auto-attaches, and on every target it is handed does
 * what Playwright does: resume it, hook it (`Fetch.enable {*}` plus the marker-bearing
 * main-world init script), then declare with `Crow.guardReady`.
 *
 * The message list is in ARRIVAL ORDER, which is what every test here reads: it is the only
 * place the order of an event against a reply is visible.
 */
function client(wsUrl, opts = {}) {
  const header = opts.header === true;
  const hook = opts.hook !== false;
  const attach = opts.attach !== undefined ? opts.attach === true : header || hook;

  const headers = { Authorization: `Bearer ${TOKEN}` };
  if (header) headers[INTENT_HEADER] = "1";
  const ws = new WebSocket(wsUrl, { headers, perMessageDeflate: false, handshakeTimeout: 5000 });

  const messages = [];
  const events = [];
  const attached = [];
  const consumed = new Set();
  const pending = new Map();
  const waiters = [];
  let nextId = 0;
  let closeInfo = null;

  const opened = new Promise((resolve, reject) => { ws.once("open", () => resolve()); ws.once("error", reject); });

  const call = (method, params, sessionId, timeoutMs = 8000) => {
    const id = ++nextId;
    const frame = { id, method, ...(params !== undefined ? { params } : {}), ...(sessionId ? { sessionId } : {}) };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (pending.delete(id)) reject(new Error(`no reply to ${method} (id ${id}) within ${timeoutMs} ms; saw ${JSON.stringify(messages.map((m) => m.method || `id=${m.id}`)).slice(0, 400)}`));
      }, timeoutMs);
      pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
      try { ws.send(JSON.stringify(frame)); } catch { /* the socket is gone; the timer reports it */ }
    });
  };
  const send = (method, params, sessionId) => {
    const id = ++nextId;
    const frame = { id, method, ...(params !== undefined ? { params } : {}), ...(sessionId ? { sessionId } : {}) };
    try { ws.send(JSON.stringify(frame)); } catch { /* gone */ }
    return id;
  };

  async function hookSession(sessionId) {
    await call("Runtime.runIfWaitingForDebugger", {}, sessionId).catch(() => null);
    await call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId).catch(() => null);
    await call("Fetch.enable", { handleAuthRequests: true, patterns: [{ urlPattern: "*", requestStage: "Request" }] }, sessionId).catch(() => null);
    await call("Page.addScriptToEvaluateOnNewDocument", { source: MARKER_WRAPPED }, sessionId).catch(() => null);
    await call("Page.addScriptToEvaluateOnNewDocument", { source: "", worldName: "__playwright_utility_world__" }, sessionId).catch(() => null);
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
    closeInfo: () => closeInfo,
    send,
    call,
    hookSession,
    /** The next message (event or reply) matching `pred`, consumed once. */
    waitFor(pred, timeoutMs = 6000, label = "a message") {
      const scan = () => {
        for (let i = 0; i < messages.length; i++) {
          if (consumed.has(i)) continue;
          if (pred(messages[i])) return i;
        }
        return -1;
      };
      const found = scan();
      if (found >= 0) { consumed.add(found); return Promise.resolve(messages[found]); }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const at = waiters.indexOf(entry);
          if (at >= 0) waiters.splice(at, 1);
          reject(new Error(`timed out waiting for ${label}; saw ${JSON.stringify(messages.map((m) => m.method || `id=${m.id}`)).slice(0, 400)}`));
        }, timeoutMs);
        const entry = {
          pred,
          resolve: (m) => { clearTimeout(timer); resolve(m); },
        };
        waiters.push(entry);
      });
    },
    /** The index in the arrival order of the reply to `id`, or -1. */
    replyIndex: (id) => messages.findIndex((m) => m.id === id && m.method === undefined),
    /** The index in the arrival order of the attach event for `targetId`, or -1. */
    attachIndex: (targetId) => messages.findIndex((m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === targetId),
    close() { try { ws.close(); } catch { /* gone */ } },
    /** A SIGKILLed MCP: the socket goes without a close frame. */
    kill() { try { ws.terminate(); } catch { try { ws._socket?.destroy(); } catch { /* gone */ } } },
  };

  const armed = (async () => {
    await opened;
    if (attach) await call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }).catch(() => null);
    if (header) c.declareReply = await call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH }).catch(() => null);
  })();
  c.armed = armed;
  return c;
}

const plainClient = (wsUrl, opts = {}) => client(wsUrl, { header: false, ...opts });
const guardClient = (wsUrl, opts = {}) => client(wsUrl, { header: true, ...opts });

// ---------------------------------------------------------------------------------------
// 1. the reply may never overtake the client's attach event
// ---------------------------------------------------------------------------------------

test("1: a client that auto-attached is handed Target.attachedToTarget for the new page BEFORE the createTarget reply", async (t) => {
  // The gate's ack for the new page is held for 400 ms: the window in which the reply used to
  // overtake the event (the live Chromium 145 evidence).
  await withGate(t, { FAKE_CHROME_NEW_PAGE_ACK_DELAY_MS: "400" }, async ({ wsUrl }) => {
    const guard = guardClient(wsUrl);
    await guard.armed;

    const created = await guard.call("Target.createTarget", { url: "about:blank" }, undefined, 8000);
    const targetId = created.result?.targetId;
    assert.ok(targetId, `the browser made a page: ${JSON.stringify(created)}`);

    // On a relay that gets this wrong the event still arrives, just later: wait for it, so the
    // failure below is the ORDER, never a timeout.
    await guard.waitFor(
      (m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === targetId,
      6000, `the client's attach event for ${targetId}`,
    );
    const attachAt = guard.attachIndex(targetId);
    const replyAt = guard.replyIndex(created.id);
    assert.ok(attachAt >= 0 && replyAt >= 0, `both are in the arrival order (attach ${attachAt}, reply ${replyAt})`);
    assert.ok(
      attachAt < replyAt,
      `the attach event must arrive BEFORE the reply that names the target (Playwright looks it up on the reply): the client saw ${JSON.stringify(guard.messages.map((m) => m.method || `id=${m.id}`))}`,
    );
  });
});

// ---------------------------------------------------------------------------------------
// 2. a client that never auto-attached never waits
// ---------------------------------------------------------------------------------------

test("2: a client that never called Target.setAutoAttach gets its createTarget reply at once (no hold)", async (t) => {
  await withGate(t, { FAKE_CHROME_NEW_PAGE_ACK_DELAY_MS: "900" }, async ({ wsUrl }) => {
    const raw = plainClient(wsUrl, { attach: false });
    await raw.armed;

    const started = Date.now();
    const created = await raw.call("Target.createTarget", { url: "about:blank" }, undefined, 6000);
    const elapsed = Date.now() - started;
    assert.ok(created.result?.targetId, `the reply is a success: ${JSON.stringify(created)}`);
    assert.ok(elapsed < 500, `no event is coming for this client, so nothing may hold the reply (${elapsed} ms)`);
    await sleep(200);
    assert.equal(
      raw.messages.filter((m) => m.method === "Target.attachedToTarget").length, 0,
      "a client that never auto-attached is handed no attach event",
    );
  });
});

// ---------------------------------------------------------------------------------------
// 3. a gate that never acks answers with an error, inside the bound
// ---------------------------------------------------------------------------------------

test("3: a gate ack that never arrives turns the held reply into an error inside the bound", async (t) => {
  // The bound is 300 ms and the fixture's ack 900 ms: the error can only come from the bound.
  await withGate(t, { FAKE_CHROME_NEW_PAGE_ACK_DELAY_MS: "900", CROW_CDP_RESPONSE_HOLD_MS: "300" }, async ({ wsUrl }) => {
    const c = plainClient(wsUrl); // auto-attaches, so its reply is held behind its own event
    await c.armed;

    const started = Date.now();
    const created = await c.call("Target.createTarget", { url: "about:blank" }, undefined, 6000);
    const elapsed = Date.now() - started;
    assert.equal(created.result, undefined, `never a success for a page the relay could not cover: ${JSON.stringify(created)}`);
    assert.equal(created.error?.code, -32000, `the refusal is a CDP error: ${JSON.stringify(created)}`);
    assert.match(
      String(created.error?.message), /Target\.createTarget: the relay could not cover the new page in time/,
      "the error names the command and the reason",
    );
    assert.ok(elapsed >= 250, `it waited for its bound, not longer (${elapsed} ms)`);
    assert.ok(elapsed < 850, `the bound answered, not the late ack (${elapsed} ms)`);
  });
});

// ---------------------------------------------------------------------------------------
// 4. a client closing while its reply is held
// ---------------------------------------------------------------------------------------

test("4: a client that closes while its reply is held does not crash the relay, and the next client works", async (t) => {
  await withGate(t, { FAKE_CHROME_NEW_PAGE_ACK_DELAY_MS: "900" }, async ({ ctx, wsUrl }) => {
    const doomed = plainClient(wsUrl); // auto-attaches: its reply IS held
    await doomed.armed;
    doomed.send("Target.createTarget", { url: "about:blank" });
    await sleep(150);
    assert.equal(
      doomed.messages.filter((m) => m.result?.targetId !== undefined).length, 0,
      "the reply is held behind the client's own attach event while the gate's ack is outstanding",
    );
    doomed.kill(); // no close frame: a SIGKILLed MCP
    await sleep(1200); // past the fixture's ack, so the held reply would have been released

    assert.equal(ctx.child.exitCode, null, `the relay is still up after the client went away:\n${ctx.logs()}`);
    const next = plainClient(wsUrl, { attach: false });
    await next.armed;
    const created = await next.call("Target.createTarget", { url: "about:blank" }, undefined, 6000);
    assert.ok(created.result?.targetId, `the next client is served normally: ${JSON.stringify(created)}`);
  });
});

// ---------------------------------------------------------------------------------------
// 5. the explicit attach is unchanged
// ---------------------------------------------------------------------------------------

test("5: an explicit Target.attachToTarget on a target whose event is held still answers with its session", async (t) => {
  await withGate(t, { FAKE_CHROME_NEW_PAGE_ACK_DELAY_MS: "400" }, async ({ wsUrl }) => {
    const guard = guardClient(wsUrl);
    await guard.armed;

    // The guard's attach event for this page is held for the gate's ack, so the page IS a held
    // target — and the raw client's replies must not wait for the guard's event.
    const raw = plainClient(wsUrl, { attach: false });
    await raw.armed;
    const created = await raw.call("Target.createTarget", { url: "about:blank" }, undefined, 6000);
    const targetId = created.result?.targetId;
    assert.ok(targetId, `the browser made a page: ${JSON.stringify(created)}`);

    const attached = await raw.call("Target.attachToTarget", { targetId, flatten: true }, undefined, 6000);
    const sessionId = attached.result?.sessionId;
    assert.ok(sessionId, `the explicit attach is still answered with a session: ${JSON.stringify(attached)}`);
    assert.equal(attached.error, undefined, "and it is not refused");

    const echoed = await raw.call("Test.echo", { value: "explicit-attach" }, sessionId, 6000);
    assert.equal(echoed.result?.got, sessionId, "the session the attach named is usable");
  });
});