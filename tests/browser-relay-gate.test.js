/**
 * The relay's private-address GUARD GATE (RED tests).
 *
 * These tests drive the real relay (bundles/browser/cdp-relay.mjs, no-flag mode) against
 * tests/fixtures/fake-chromium-gate.mjs, a fake Chromium that models the four facts the
 * gate's rules are made of: a target auto-attached with `waitForDebuggerOnStart` is HELD
 * until every announcer resumes it (a shared/service worker runs on the FIRST resumer), a
 * request chains through the Fetch-enabled sessions of its target newest-first with the
 * oldest last, request ids are per session, and a page is only "at about:blank" for real
 * once its `Page.frameNavigated` commit has been emitted.
 *
 * Everything asserted here is the contract the gate has to satisfy; the gate does not exist
 * yet, so every test is red. The fixture's own knobs are the only way to see inside the
 * relay: `recv` records are the pipe order (the gate's commands and a client's alike),
 * `t: "..."` records are what the browser did.
 *
 * Session ids are readable: `S1` is the FIRST browser session the fixture hands out (the
 * gate's own, created before any client can connect), a client's own session is `S2`,
 * `S3`, ..., and auto-attached children are `A...`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import WebSocket from "ws";

const RELAY = fileURLToPath(new URL("../bundles/browser/cdp-relay.mjs", import.meta.url));
const FIXTURE = fileURLToPath(new URL("./fixtures/fake-chromium-gate.mjs", import.meta.url));
const TOKEN = "9c4d2e".repeat(10) + "beef";

/** The guard's init-script marker: the constant the coverage test looks for. */
const MARKER = "crow-private-address-guard:v1";
/** Playwright wraps every init script, so the marker is never the first line of `source`. */
const MARKER_WRAPPED = `(() => {\n  // ${MARKER}\n})();`;
/** The `exceptionsHash` a declaring client sends; logged, used for nothing else. */
const EXCEPTIONS_HASH = "0123456789abcdef";
/** The intent header: a client that wants the gate to treat it as guard-bearing. */
const INTENT_HEADER = "X-Crow-Guard-Client";
/**
 * The one component-extension id the relay pins in code: the worker a Chromium 145.0.7632.6
 * start (Playwright 1.58.2's chromium-1208) LISTS as `thunk.js` and never attaches.
 */
const COMPONENT_EXTENSION_ID = "nkeimhogjdpnpccoofpliimaahmaaome";
/** An extension id nothing allow-lists: no exemption may ever be guessed from an origin. */
const UNKNOWN_EXTENSION_ID = "evilextidnotonthelist";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------
// the relay under test
// ---------------------------------------------------------------------------------------

/** A loopback port nobody is using, for the one test that must reach the port pre-ready. */
function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/**
 * One relay run: the real relay in no-flag mode, its Chromium the gate fixture, both on this
 * test's own temp dir. The gate's timing caps are shortened to the shape the tests assert (a
 * deadline that is enforced and read from the environment), never switched off.
 */
async function startRelay(t, extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), "crow-gate-relay-"));
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
  ctx.port = Number(extraEnv.CDP_PORT) > 0 ? Number(extraEnv.CDP_PORT) : null;
  child.stdout.on("data", (d) => { logs += d; });
  child.stderr.on("data", (d) => { logs += d; });
  ctx.exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
  ctx.trace = () => {
    try { return readFileSync(ctx.tracePath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
  };
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

/** A hand-written WebSocket upgrade, so the STATUS can be asserted (503 before ready). */
function rawUpgrade(port, { path, token = TOKEN, host = null, headers = {}, timeoutMs = 2000 } = {}) {
  const key = randomBytes(16).toString("base64");
  const lines = [
    `GET ${path} HTTP/1.1`,
    `Host: ${host === null ? `127.0.0.1:${port}` : host}`,
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Key: ${key}`,
    "Sec-WebSocket-Version: 13",
  ];
  if (token !== null) lines.push(`Authorization: Bearer ${token}`);
  for (const [name, value] of Object.entries(headers)) lines.push(`${name}: ${value}`);
  return httpRaw(port, lines.join("\r\n") + "\r\n\r\n", timeoutMs).then(parseReply);
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
 * Wait for a FURTHER line matching `re`, past the `already` ones the log carries. The gate logs
 * `gate state IDLE` at start-up and again after every cleanup, so "the next IDLE" is the only
 * thing a cleanup test may wait for: `waitLog` alone would match the start-up line at once.
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
 * satisfied by an accident before: the ready line, the field in `/json/version`, and the
 * gate's own browser session being the FIRST one the fixture ever handed out.
 */
async function gateUp(ctx, ready, version) {
  assert.equal(version.json?.["Crow-Guard"], "gate/1", "/json/version carries `Crow-Guard: gate/1` while the gate is ready");
  await waitLog(ctx, /gate ready/);
  assert.ok(
    ctx.records("recv").some((r) => r.method === "Target.setAutoAttach" && r.sessionId === "S1"),
    "the gate's own browser session is the first session the fixture hands out (S1), created before any client",
  );
}

/** A relay whose gate is ready, plus the WebSocket URL and the parsed version body. */
async function withGate(t, env, fn) {
  const ctx = await startRelay(t, env);
  const ready = await waitReady(ctx);
  const version = await request(ready.port, { token: TOKEN });
  await gateUp(ctx, ready, version);
  return fn({ ctx, ready, version, wsUrl: version.json?.webSocketDebuggerUrl });
}

// ---------------------------------------------------------------------------------------
// clients
// ---------------------------------------------------------------------------------------

/**
 * One CDP client over the relay.
 *
 * A PLAIN client (`header: false`) is the live-tile watcher / external CDP user: it changes
 * no gate state. A GUARD-BEARING client (`header: true`) sends `X-Crow-Guard-Client: 1`,
 * auto-attaches, and on every target it is handed does what Playwright does (S5 case 2):
 * `Runtime.runIfWaitingForDebugger` FIRST, then `Fetch.enable {*}` and the marker-bearing
 * main-world init script, plus the empty utility-world script and a nested auto-attach (so a
 * client can be handed an iframe's iframe) — then declares with `Crow.guardReady`.
 */
function client(wsUrl, opts = {}) {
  const header = opts.header === true;
  const hook = opts.hook !== false;
  const attach = opts.attach !== undefined ? opts.attach === true : header || hook;
  const nest = opts.nest !== false && attach;
  const patterns = opts.patterns === undefined ? [{ urlPattern: "*", requestStage: "Request" }] : opts.patterns;
  const markerSource = opts.markerSource === undefined ? MARKER_WRAPPED : opts.markerSource;
  const markerWorldName = typeof opts.markerWorldName === "string" ? opts.markerWorldName : undefined;
  const utilityScript = opts.utilityScript !== false;
  const declare = opts.declare !== false;
  const declareOnOpen = opts.declareOnOpen === true;
  const hookDelayMs = Number(opts.hookDelayMs || 0);
  const refuse = opts.refuse === true;

  const headers = { Authorization: `Bearer ${TOKEN}` };
  if (header) headers[INTENT_HEADER] = "1";
  const ws = new WebSocket(wsUrl, { headers, perMessageDeflate: false, handshakeTimeout: 5000 });

  const messages = [];
  const events = [];
  const attached = []; // { sessionId, targetId, type } for every attach event this client saw
  const consumed = new Set(); // message indices a `waitFor` already took
  const pending = new Map();
  const waiters = [];
  let nextId = 0;
  let closeInfo = null;
  let autoContinue = opts.autoContinue !== false;

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
  const send = (method, params, sessionId) => {
    const id = ++nextId;
    const frame = { id, method, ...(params !== undefined ? { params } : {}), ...(sessionId ? { sessionId } : {}) };
    try { ws.send(JSON.stringify(frame)); } catch { /* gone */ }
    return id;
  };

  async function hookSession(sessionId) {
    // Playwright's order (S5 case 2): resume first, hook afterwards. Every auto-attaching
    // client resumes what it is handed — a client that hooks nothing still resumes, which is
    // the "declared but hooked nothing" shape (and the only thing that leaves its page runnable).
    await call("Runtime.runIfWaitingForDebugger", {}, sessionId).catch(() => null);
    // The nested auto-attach goes on every session this client is handed, hooked or not: it is
    // how Chromium comes to announce the target's OWN children here (an iframe, and the iframe
    // inside that iframe), whatever the client then does with them.
    if (nest) await call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId).catch(() => null);
    // The client's CURRENT flag, read at call time: hooking is something a live client starts
    // and stops (a guard reconnecting, and these tests), so the constructor's value never decides.
    if (c.hookEnabled === false) return;
    if (hookDelayMs) await sleep(hookDelayMs);
    if (patterns) await call("Fetch.enable", { handleAuthRequests: true, patterns }, sessionId).catch(() => null);
    if (markerSource !== null) {
      await call("Page.addScriptToEvaluateOnNewDocument", {
        source: markerSource,
        ...(markerWorldName ? { worldName: markerWorldName } : {}),
      }, sessionId).catch(() => null);
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
        if (refuse) void call("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" }, msg.sessionId).catch(() => null);
        else void call("Fetch.continueRequest", { requestId }, msg.sessionId).catch(() => null);
      }
    }
    for (const w of [...waiters]) {
      // Re-scan from the start: an earlier message may have been taken since this waiter
      // was registered, and a waiter takes exactly one message.
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
    /** Whether this client installs hooks on what it is handed; `hook: false` starts it false. */
    hookEnabled: hook,
    closeInfo: () => closeInfo,
    send,
    call,
    hookSession,
    /** Every event of one method. */
    of: (method) => events.filter((m) => m.method === method),
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
    /** The last session this client was handed for `targetId` (its page/iframe session). */
    sessionFor: (targetId) => attached.filter((a) => a.targetId === targetId).at(-1)?.sessionId ?? null,
    close() { try { ws.close(); } catch { /* gone */ } },
    /** A SIGKILLed MCP: the socket goes without a close frame. */
    kill() { try { ws.terminate(); } catch { try { ws._socket?.destroy(); } catch { /* gone */ } } },
  };

  const armed = (async () => {
    await opened;
    // Queued in the same tick the socket opens: before the relay can have told this client
    // its browser session id, which is exactly the pre-session queue the gate has to handle.
    if (declareOnOpen) c.declareReply = await call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH }).catch(() => null);
    if (attach) await call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }).catch(() => null);
    if (header && declare && !declareOnOpen) {
      c.declareReply = await call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH }).catch(() => null);
    }
  })();
  c.armed = armed;
  return c;
}

const plainClient = (wsUrl, opts = {}) => client(wsUrl, { header: false, ...opts });
const guardClient = (wsUrl, opts = {}) => client(wsUrl, { header: true, ...opts });

async function waitClosed(c, timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs && !c.closeInfo()) await sleep(25);
  return c.closeInfo();
}

// ---------------------------------------------------------------------------------------
// pages, coverage, and what the fixture recorded
// ---------------------------------------------------------------------------------------

/**
 * Create a page through `c` (as about:blank, the only shape the relay allows) and navigate it
 * on an explicit session, so a client that does not auto-attach can still make pages.
 */
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

const liveTargets = async (c) => (await c.call("Target.getTargets")).result?.targetInfos ?? [];

/** The target ids the fixture lists right now (a snapshot a test can name the new one against). */
async function targetIds(c) {
  const state = (await c.call("Test.state")).result;
  return new Set((state?.targets ?? []).map((t) => t.id));
}

/**
 * The id of a target the fixture lists that `known` did not carry. A `Target.createTarget`
 * reply can be HELD (behind the client's own attach event, which is held for the gate's ack),
 * so a test that has to act inside that window cannot wait for the reply to learn the id.
 */
async function waitNewTarget(c, known, timeoutMs = 4000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const state = (await c.call("Test.state")).result;
    const fresh = (state?.targets ?? []).map((t) => t.id).filter((id) => !known.has(id));
    if (fresh.length) return fresh.at(-1);
    await sleep(10);
  }
  assert.fail("the fixture never listed a new target");
}

/** One request from a page, as the fixture's Fetch chain sees it: passed, failed, held or closed. */
async function probe(c, targetId, url = "https://bot.example/probe", timeoutMs = 5000) {
  const reply = await c.call("Test.request", { targetId, url }, undefined, timeoutMs);
  if (reply.result) return reply.result;
  return { outcome: `error:${reply.error?.message ?? "no reply"}`, via: [] };
}

/**
 * The page cannot get a request out. Two fixture outcomes satisfy that: `failed` for a page
 * that runs and whose request the gate stops, and `held` for a target that was never
 * resumed (the fixture's model holds a target until EVERY announcer resumes it, so a page
 * the gate refuses to resume runs nothing at all). `passed` never does.
 */
async function assertUncovered(c, targetId, message) {
  const outcome = await probe(c, targetId);
  assert.ok(outcome.outcome === "failed" || outcome.outcome === "held", `${message} (outcome: ${JSON.stringify(outcome)})`);
  return outcome.outcome;
}

/** Poll until the page's requests pass, i.e. some guard-bearing client demonstrably covers it. */
async function waitCovered(c, targetId, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    last = await probe(c, targetId);
    if (last?.outcome === "passed") return last;
    await sleep(50);
  }
  assert.fail(`the page ${targetId} was never covered (last outcome: ${JSON.stringify(last)})`);
}

/**
 * Poll until the fixture says the target runs. A target is held while any announcer of it has
 * not resumed it, so this is how a test waits out another client's announce-then-resume round
 * trip instead of racing it (a held target answers every request with `held`).
 */
async function waitRunning(c, targetId, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const state = await c.call("Test.state", { targetId });
    if (state.result?.target?.running === true) return true;
    await sleep(50);
  }
  return false;
}

/** Wait for one record of the fixture's trace. */
async function waitTrace(ctx, pred, timeoutMs = 5000, label = "a trace record") {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const hit = ctx.trace().find(pred);
    if (hit) return hit;
    await sleep(25);
  }
  assert.fail(`the fixture never recorded ${label}`);
}

/**
 * A page the guard's own auto-attach hands it, and that it covers (Playwright's `Fetch.enable`
 * and marker script on the session the attach event named). `sessionId` is the session that
 * carried the event, i.e. the one a child's attach event is announced on.
 */
async function coverPage(observer, guard) {
  const created = await observer.call("Target.createTarget", { url: "about:blank" });
  const targetId = created.result.targetId;
  const attach = await guard.waitFor(
    (m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === targetId,
    6000, `the guard's attach event for ${targetId}`,
  );
  await waitCovered(observer, targetId);
  return { targetId, sessionId: attach.params.sessionId };
}

/** An iframe under `parentId`, announced to and covered by the same guard. */
async function coverChild(observer, guard, parentId, url) {
  const spawned = await observer.call("Test.spawnTarget", { type: "iframe", ownerId: parentId, url });
  const targetId = spawned.result.targetId;
  await guard.waitFor(
    (m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === targetId,
    6000, `the guard's attach event for ${targetId}`,
  );
  await waitCovered(observer, targetId);
  return targetId;
}

/** The relay session id a client's own commands are stamped with, read from the fixture. */
async function sessionIdOf(ctx, marker) {
  const rec = await waitTrace(
    ctx,
    (r) => r.t === "recv" && r.method === "Test.echo" && r.params?.value === marker,
    4000,
    `a Test.echo carrying ${marker}`,
  );
  return rec.sessionId;
}

/** The gate's own session for a target: a Fetch.enable on it that no client of ours sent. */
function gateSessionFor(ctx, targetId, clientSessions) {
  return ctx.trace()
    .filter((r) => r.t === "recv" && r.method === "Fetch.enable" && r.sessionId && !clientSessions.has(r.sessionId))
    .filter((r) => {
      const enabled = ctx.records("fetch-enable").find((f) => f.sessionId === r.sessionId);
      return enabled && enabled.targetId === targetId;
    })
    .at(-1)?.sessionId ?? null;
}

/** A process is gone when /proc no longer has it (a zombie counts as gone). */
function pidGone(pid) {
  if (!pid) return true;
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const close = stat.lastIndexOf(")");
    const state = close >= 0 ? stat.slice(close + 2, close + 3) : "";
    return state === "Z" || state === "X";
  } catch {
    try { process.kill(pid, 0); return false; } catch { return true; }
  }
}

async function waitPidGone(pid, timeoutMs = 4000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pidGone(pid)) return true;
    await sleep(50);
  }
  return false;
}

/** `gateReady` is false: the port is gone, or it answers without `Crow-Guard`. */
async function gateReadyFalse(port) {
  if (!port) return true;
  const reply = await request(port, { token: TOKEN });
  if (reply.status === 0) return true;
  return reply.json?.["Crow-Guard"] === undefined;
}

/** The index of the last `recv` the fixture recorded for a client-sent marker command. */
function markerIndex(trace, method, value) {
  return trace.findLastIndex((r) => r.t === "recv" && r.method === method && r.params?.value === value);
}

// ---------------------------------------------------------------------------------------
// 2. gateReady is false from listen
// ---------------------------------------------------------------------------------------

test("2a: in the pre-ready window an upgrade is 503, /json/version has no Crow-Guard and there is no ready file; after ready all three flip", async (t) => {
  const port = await freePort();
  // A gate that cannot finish inside its start window, but whose port is already listening:
  // the fixture takes 1 s (its reply cap) to answer the gate's first Fetch.enable.
  const ctx = await startRelay(t, { CDP_PORT: String(port), FAKE_CHROME_DELAY_METHODS: "Fetch.enable:1500" });

  const deadline = Date.now() + 6000;
  let first = null;
  while (Date.now() < deadline) {
    const reply = await request(port, { token: TOKEN });
    if (reply.status > 0) { first = reply; break; }
    if (ctx.child.exitCode !== null) break;
    await sleep(20);
  }
  assert.ok(first, `the relay must be listening before the gate is ready; its log was:\n${ctx.logs()}`);
  assert.equal(first.status, 200, first.raw.slice(0, 200));
  assert.equal(first.json?.["Crow-Guard"], undefined, "no Crow-Guard while the gate is not ready");
  const path = new URL(first.json.webSocketDebuggerUrl).pathname;

  // Negative: no client can connect before the gate is installed (600 ms is plenty for the
  // response head; a 101 keeps the socket open, so the helper resolves on its own timeout).
  assert.equal((await rawUpgrade(port, { path, token: TOKEN, timeoutMs: 600 })).status, 503, "an upgrade before the gate is ready is refused");
  assert.equal(existsSync(ctx.readyFile), false, "the ready file is written only after the gate is ready");

  // Control: after ready, exactly the same upgrade is a 101 and the field is there.
  const ready = await waitReady(ctx);
  const version = await request(ready.port, { token: TOKEN });
  assert.equal(version.json?.["Crow-Guard"], "gate/1", "Crow-Guard appears once the gate is ready");
  assert.equal((await rawUpgrade(ready.port, { path, token: TOKEN, timeoutMs: 600 })).status, 101, "control: a ready gate upgrades the same client");
});

test("2b: a gate that cannot install inside CROW_CDP_START_DEADLINE_MS logs one line, writes no ready file and exits non-zero", async (t) => {
  const ctx = await startRelay(t, { FAKE_CHROME_FAIL_METHODS: "Fetch.enable", CROW_CDP_START_DEADLINE_MS: "1000" });
  const exit = await Promise.race([ctx.exited, sleep(9000).then(() => "timeout")]);
  assert.notEqual(exit, "timeout", `a gate that cannot install must not serve on; its log was:\n${ctx.logs()}`);
  assert.notEqual(exit.code, 0, "the relay exits non-zero (the container recycles)");
  assert.equal(existsSync(ctx.readyFile), false, "no ready file for a gate that never installed");
  const gateLines = ctx.logs().split("\n").filter((l) => /\bgate\b/i.test(l) && l.trim() !== "");
  assert.equal(gateLines.length, 1, `exactly one line about it, got ${JSON.stringify(gateLines)}`);
});

// ---------------------------------------------------------------------------------------
// 3. the handshake, and what counts as coverage
// ---------------------------------------------------------------------------------------

test("3a: a client without the intent header never becomes a guard, and the page it hooks stays uncovered", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);

    // It does everything a Playwright guard does, except say it is one. In IDLE that changes
    // nothing on the wire: the gate passes every request by design, so this page passes too
    // (control). The next page is the one this test is really about.
    const idles = countLog(ctx, /gate state IDLE/);
    const transitions = countLog(ctx, /gate state (CONNECTING|GUARDED)/);
    const plain = plainClient(wsUrl, { hook: true });
    await plain.armed;
    const idlePage = await makePage(plain, "https://bot.example/plain-idle");
    await sleep(300);
    assert.equal(countLog(ctx, /gate state (CONNECTING|GUARDED)/), transitions, "a non-intent client changes no gate state");
    assert.equal(countLog(ctx, /gate state IDLE/), idles, "the gate is still IDLE");
    assert.equal((await probe(observer, idlePage.targetId)).outcome, "passed", "control: in IDLE the gate passes a page it has not covered");

    // A negative about coverage only means something while a REAL guard is in the state: in
    // IDLE the gate passes everything on purpose. So a guard client that declared (GUARDED)
    // but has hooked nothing yet is connected first, and the same page is made again.
    const guard = guardClient(wsUrl, { hook: false });
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    // The state the guard left behind: the plain client below must not add a line to it.
    const guardedTransitions = countLog(ctx, /gate state (CONNECTING|GUARDED)/);

    const { targetId } = await makePage(plain, "https://bot.example/plain");
    await guard.waitFor(
      (m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === targetId,
      6000, `the guard's attach event for ${targetId}`,
    );
    await sleep(300);
    assert.equal(countLog(ctx, /gate state (CONNECTING|GUARDED)/), guardedTransitions, "the non-intent client moves no gate state, in GUARDED either");

    // Negative: a non-guard client's hooks do not cover the page, so while GUARDED it cannot
    // get a request out.
    await assertUncovered(observer, targetId, "a page hooked only by a non-intent client must not get a request out");

    // Control: once a GUARD-BEARING client has hooked that same page, it passes.
    const sessionId = guard.sessionFor(targetId);
    assert.ok(sessionId, "the guard was handed the page's session");
    guard.hookEnabled = true;
    await guard.hookSession(sessionId);
    await waitCovered(observer, targetId);
  });
});

test("3b: a guard client that declares but hooks nothing leaves the page uncovered (control: hooked, it passes)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);
    // Created in IDLE, so it runs: the only thing missing is coverage.
    const { targetId } = await makePage(observer, "https://bot.example/unhooked");
    assert.equal((await probe(observer, targetId)).outcome, "passed", "control: IDLE passes it");

    const guard = guardClient(wsUrl, { hook: false });
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    await assertUncovered(observer, targetId, "declared, but hooked nothing, so the page is not covered");

    const sessionId = guard.sessionFor(targetId);
    assert.ok(sessionId, "the guard was handed the page's session");
    guard.hookEnabled = true;
    await guard.hookSession(sessionId);
    await waitCovered(observer, targetId);
  });
});

test("3c: coverage needs a Fetch.enable whose patterns include \"*\" (control: the \"*\" pattern covers)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;

    const narrow = guardClient(wsUrl, { patterns: [{ urlPattern: "https://*.example.test/*", requestStage: "Request" }] });
    await narrow.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const untouched = await makePage(observer, "https://bot.example/narrow");
    await sleep(300);
    await assertUncovered(observer, untouched.targetId, "a pattern that is not \"*\" does not cover");

    // Control: a guard whose patterns reach every request covers.
    const full = guardClient(wsUrl);
    await full.armed;
    await waitCovered(observer, untouched.targetId);
  });
});

test("3d: only a main-world init script carrying the marker covers — not the bare utility-world script, not a script without the marker", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;

    // (a) the marker script delivered to a utility world: a worldName means "not main world".
    // This client also declares, so it is the one GUARDED is waited for AFTER.
    const utilityWorld = guardClient(wsUrl, { markerWorldName: "__playwright_utility_world__" });
    await utilityWorld.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const a = await makePage(observer, "https://bot.example/world");
    await sleep(300);
    await assertUncovered(observer, a.targetId, "a marker script in a named world does not cover");

    // (b) a main-world script with no marker.
    const noMarker = guardClient(wsUrl, { markerSource: "(() => {\n  // nothing to see here\n})();" });
    await noMarker.armed;
    const b = await makePage(observer, "https://bot.example/no-marker");
    await sleep(300);
    await assertUncovered(observer, b.targetId, "a script without the marker does not cover");

    // (c) only Playwright's bare empty utility-world script (no marker script at all).
    const bareUtility = guardClient(wsUrl, { markerSource: null });
    await bareUtility.armed;
    const c = await makePage(observer, "https://bot.example/bare-utility");
    await sleep(300);
    await assertUncovered(observer, c.targetId, "the bare utility-world script alone does not cover");

    // Control: the same hooking, with the marked main-world script, covers.
    const good = guardClient(wsUrl);
    await good.armed;
    await waitCovered(observer, a.targetId);
  });
});

test("3e: the marker test is \"contains\" — the source Playwright wraps around it covers", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;

    // A near miss first: the marker as a prefix of something else, in the main world. This
    // client declares too, so GUARDED is waited for after it has connected and declared.
    const nearMiss = guardClient(wsUrl, { markerSource: `(() => {\n  // ${MARKER.slice(0, -1)}2\n})();` });
    await nearMiss.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const miss = await makePage(observer, "https://bot.example/near-miss");
    await sleep(300);
    await assertUncovered(observer, miss.targetId, "a different marker is not the marker");

    // Control: the marker wrapped mid-script, exactly as Playwright wraps every init script.
    const good = guardClient(wsUrl);
    await good.armed;
    await waitCovered(observer, miss.targetId);
  });
});

test("3f: Crow.guardReady is never forwarded — not with a sessionId, not from the pre-session queue — and its reply is {}", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const c = guardClient(wsUrl, { declare: false });
    await c.armed;
    const marker = `own-session-${randomBytes(3).toString("hex")}`;
    await c.call("Test.echo", { value: marker });
    const ownSession = await sessionIdOf(ctx, marker);

    // (i) carrying a sessionId: handled by the same code, never routed to the pipe.
    const withSession = await c.call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH }, ownSession);
    assert.deepEqual(withSession.result, {}, "Crow.guardReady answers {}");
    assert.equal(withSession.error, undefined, "and it is not an error for the intended client");
    await waitLog(ctx, /gate state (CONNECTING|GUARDED)/);

    // (ii) queued in the same tick the socket opened, before the relay had told this client
    // its browser session id.
    const early = guardClient(wsUrl, { declareOnOpen: true });
    await early.armed;
    assert.ok(early.declareReply, "the queued declaration got a reply");
    assert.deepEqual(early.declareReply.result, {}, "the queued Crow.guardReady is handled the same");
    assert.equal(early.declareReply.error, undefined, "…and it is not an error");

    // Neither ever reached the fixture.
    assert.equal(ctx.records("recv").filter((r) => typeof r.method === "string" && r.method.startsWith("Crow.")).length, 0, "no Crow.* method ever reaches the pipe");
  });
});

test("3g: a client without the header gets an error from Crow.guardReady and from any other Crow.* method, and neither reaches the fixture", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const plain = plainClient(wsUrl, { attach: false });
    await plain.armed;

    const declaration = await plain.call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH });
    assert.equal(typeof declaration.error, "object", `a non-intent client may not declare: ${JSON.stringify(declaration)}`);

    const other = await plain.call("Crow.somethingElse", { v: 1 });
    assert.equal(typeof other.error, "object", `any other Crow.* method is an error: ${JSON.stringify(other)}`);

    assert.equal(ctx.records("recv").filter((r) => typeof r.method === "string" && r.method.startsWith("Crow.")).length, 0, "neither reached the pipe");
    assert.equal(countLog(ctx, /gate state (CONNECTING|GUARDED)/), 0, "and neither changed the state");
  });
});

// ---------------------------------------------------------------------------------------
// 4. the state machine, through the log lines and the behaviour
// ---------------------------------------------------------------------------------------

test("4a: IDLE at start — a request from a page passes with no client, and the gate's session came first", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    await waitLog(ctx, /gate state IDLE/);
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    assert.equal((await probe(observer, "P1", "https://bot.example/idle")).outcome, "passed", "in clean IDLE a request passes");
  });
});

test("4b: an intent client moves the gate to CONNECTING — every request fails and a new target is held", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    assert.equal((await probe(observer, "P1", "https://bot.example/before")).outcome, "passed", "control: IDLE passes");

    // The header alone is intent: the client never declares.
    const intent = guardClient(wsUrl, { declare: false, hook: false });
    await intent.armed;
    await waitLog(ctx, /gate state CONNECTING/);

    await assertUncovered(observer, "P1", "CONNECTING fails every request, or holds the page that would make one");

    const spawned = await observer.call("Test.spawnTarget", { type: "page", url: "about:blank" });
    const targetId = spawned.result.targetId;
    await sleep(200);
    assert.equal((await probe(observer, targetId, "https://bot.example/held")).outcome, "held", "a new target is held in CONNECTING");
  });
});

test("4c: Crow.guardReady moves the gate to GUARDED — the hooked page passes, an unhooked one fails", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state CONNECTING/);
    await waitLog(ctx, /gate state GUARDED/);

    const hooked = await makePage(guard, "https://bot.example/hooked");
    await waitCovered(observer, hooked.targetId);
    // The negative needs a page this guard never hooks. A page in another browser context is
    // not out of a browser-level auto-attacher's reach (Chromium reports every context's
    // targets there), so the page is simply one the guard is handed while it is not hooking.
    guard.hookEnabled = false;
    const other = await makePage(guard, "https://bot.example/unhooked");
    await sleep(300);
    await assertUncovered(observer, other.targetId, "a page the declared guard never hooked is uncovered");
    assert.equal((await probe(observer, hooked.targetId)).outcome, "passed", "control: the hooked page still passes");
    guard.hookEnabled = true;
  });
});

test("4d: the last guard's socket closing moves to CLEANUP and then to IDLE", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page = await makePage(guard, "https://bot.example/to-clean");
    await waitCovered(observer, page.targetId);

    // Counted BEFORE the drop: the cleanup can reach IDLE between the CLEANUP line being read
    // and the count being taken, so a count taken then would wait for an IDLE already there.
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill(); // no close frame: a SIGKILLed MCP
    await waitLog(ctx, /gate state CLEANUP/);
    // The cleanup creates its own fresh replacement and closes every page it found — P1
    // included — so "IDLE passes again" is about the SURVIVING page, read from the fixture.
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);
    assert.ok(countLog(ctx, /gate state CLEANUP/) >= 1, "CLEANUP was announced");
    const replacement = ctx.records("create-target").at(-1)?.targetId;
    assert.ok(replacement, "the cleanup created the replacement page");
    assert.notEqual(replacement, page.targetId, "the surviving page is the fresh replacement, not the bot's page");
    assert.equal(ctx.records("close-target").some((r) => r.targetId === "P1"), true, "the cleanup closed the start page, so probing P1 could only see a closed target");
    assert.equal((await observer.call("Test.state", { targetId: replacement })).result?.target?.closed, false, "the replacement is open");
    assert.equal((await probe(observer, replacement, "https://bot.example/after-idle")).outcome, "passed", "IDLE passes again");
  });
});

test("4e: an intent client that never declares is dropped at CROW_CDP_CONNECTING_DEADLINE_MS (control: a declaring client is not)", async (t) => {
  await withGate(t, { CROW_CDP_CONNECTING_DEADLINE_MS: "800" }, async ({ ctx, wsUrl }) => {
    const started = Date.now();
    const silent = guardClient(wsUrl, { declare: false, hook: false });
    await silent.armed;
    const closed = await waitClosed(silent, 5000);
    assert.ok(closed, "the relay drops a client that never declares");
    const elapsed = Date.now() - started;
    assert.ok(elapsed >= 600, `it waited for the deadline, not longer and not shorter (${elapsed} ms)`);
    assert.ok(elapsed < 3000, `the deadline is read from the cap, not hard-coded (${elapsed} ms)`);
    await waitLog(ctx, /deadline/i);
    assert.ok(countLog(ctx, /gate state CLEANUP/) >= 1, "and the cleanup trigger is announced");

    // Control: the same client, declaring, is kept.
    const declaring = guardClient(wsUrl);
    await declaring.armed;
    await waitLog(ctx, /gate state GUARDED/);
    await sleep(1200);
    assert.equal(declaring.closeInfo(), null, "a declaring client is not dropped");
  });
});

test("4f: a second intent client counts as CONNECTING only until it declares or is dropped, and the first client's page stays covered", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const first = guardClient(wsUrl);
    await first.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page = await makePage(first, "https://bot.example/first-guard");
    await waitCovered(observer, page.targetId);
    const connecting = countLog(ctx, /gate state CONNECTING/);

    const second = guardClient(wsUrl, { declare: false, hook: false });
    await second.armed;
    await waitLog(ctx, /gate state CONNECTING/);
    assert.ok(countLog(ctx, /gate state CONNECTING/) > connecting, "a second intent client is announced as CONNECTING");

    // It hooks nothing but it does what Playwright does with what it is handed: resume it. Its
    // auto-attach is a NEW announcer of the page, which leaves the page held until that resume
    // lands, so wait for the page to run again before probing — otherwise the probe sees the
    // announce, not the coverage rule.
    assert.equal(await waitRunning(observer, page.targetId), true, "the second client resumed the page it was handed");

    // Documented behaviour: coverage is per page, so the first client's page still passes.
    assert.equal((await probe(observer, page.targetId)).outcome, "passed", "per-page coverage survives another client connecting");

    await second.call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH });
    await waitLog(ctx, /gate state GUARDED/);
    assert.equal((await probe(observer, page.targetId)).outcome, "passed", "and after it declares");

    second.kill();
    await sleep(500);
    assert.equal(countLog(ctx, /gate state CLEANUP/), 0, "one guard left: no cleanup");

    first.kill();
    await waitLog(ctx, /gate state CLEANUP/);
  });
});

// ---------------------------------------------------------------------------------------
// 5. cleanup: the order, and the one stop path
// ---------------------------------------------------------------------------------------

/**
 * A live bot page plus its guard, and a plain observer that outlives the cleanup. Returns
 * everything the order tests need, and the marker command that pins "the drop happened here"
 * in the fixture's trace.
 */
async function armedPageAndGuard(ctx, wsUrl) {
  const observer = plainClient(wsUrl, { attach: false });
  await observer.armed;
  const guard = guardClient(wsUrl);
  await guard.armed;
  await waitLog(ctx, /gate state GUARDED/);
  const page = await makePage(guard, "https://bot.example/");
  await waitCovered(observer, page.targetId);
  return { observer, guard, page };
}

test("5a: cleanup order — a fresh about:blank replacement first, a navigate for every page, a close only after its commit, the scan before IDLE", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    const marker = `drop-${randomBytes(3).toString("hex")}`;
    await guard.call("Test.echo", { value: marker });
    guard.kill();
    await waitLog(ctx, /gate state CLEANUP/);
    await waitLog(ctx, /gate state IDLE/, 12000);

    const trace = ctx.trace();
    const at = markerIndex(trace, "Test.echo", marker);
    assert.ok(at >= 0, "the drop marker is in the trace");

    // The FIRST command of the cleanup is the fresh replacement page.
    const firstCreate = trace.findIndex((r, i) => i > at && r.t === "recv" && r.method === "Target.createTarget");
    assert.ok(firstCreate > at, "the cleanup creates a replacement page");
    assert.equal(trace[firstCreate].params?.url, "about:blank", "the replacement is about:blank");
    const beforeCreate = trace.slice(at, firstCreate);
    assert.equal(beforeCreate.filter((r) => r.t === "close-target").length, 0, "nothing is closed before the replacement exists");
    assert.equal(beforeCreate.filter((r) => r.t === "recv" && r.method === "Page.navigate").length, 0, "nothing is navigated before the replacement exists");

    // Every page is navigated to about:blank, INCLUDING P1, which already was.
    const navigated = trace.slice(firstCreate).filter((r) => r.t === "navigate").map((r) => r.targetId);
    assert.ok(navigated.includes("P1"), "P1 (already at about:blank) is navigated too");
    assert.ok(navigated.includes(page.targetId), "the bot page is navigated");

    // A close is only ever written after the page's own commit was observed.
    // A close is only ever written after the page's own commit was observed. Section 4 closes
    // non-page targets (a held worker, anything the gate will not run) without any navigation,
    // so the rule is about the closes of PAGES.
    const pageIds = new Set(["P1", ...trace.filter((r) => r.t === "create-target").map((r) => r.targetId)]);
    const closes = trace.map((r, i) => ({ r, i })).filter(({ r }) => r.t === "close-target" && pageIds.has(r.targetId));
    assert.ok(closes.length >= 1, "the bot page is closed");
    for (const { r, i } of closes) {
      const commit = trace.findLastIndex((n, j) => j < i && n.t === "navigate" && n.targetId === r.targetId && n.committed === true);
      assert.ok(commit >= 0 && commit < i, `the close of ${r.targetId} follows its committed navigate`);
    }

    // The verification scan is read after the last close, i.e. before IDLE.
    const lastClose = trace.findLastIndex((r) => r.t === "close-target");
    const scan = trace.findIndex((r, i) => i > lastClose && r.t === "recv" && r.method === "Target.getTargets");
    assert.ok(scan > lastClose, "Target.getTargets is read after the closes (the clean scan)");
  });
});

test("5a-1: a page the gate never resumed is closed during cleanup without a navigate (control: a live page is navigated, and its close follows its commit)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    // The live page: the guard hooks it, so the gate resumes it.
    const page = await makePage(guard, "https://bot.example/live");
    await waitCovered(observer, page.targetId);

    // A page the guard never hooks: held by the gate, so it runs nothing and is never resumed.
    guard.hookEnabled = false;
    const spawned = await observer.call("Test.spawnTarget", { type: "page", url: "https://bot.example/held" });
    const heldId = spawned.result.targetId;
    await waitTrace(ctx, (r) => r.t === "fetch-enable" && r.targetId === heldId, 4000, `the gate's Fetch.enable on ${heldId}`);
    assert.equal((await observer.call("Test.state", { targetId: heldId })).result.target.running, false, "the held page runs nothing");
    assert.equal(ctx.records("resumed").some((r) => r.targetId === heldId), false, "nothing ever resumed it");

    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill();
    await waitLog(ctx, /gate state CLEANUP/);
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);

    const clientSessions = new Set([...guard.attached.map((a) => a.sessionId), ...observer.attached.map((a) => a.sessionId)]);
    const heldSession = gateSessionFor(ctx, heldId, clientSessions);
    assert.ok(heldSession, "the gate has its own session on the held page");
    assert.equal(ctx.records("close-target").some((r) => r.targetId === heldId), true, "the held page is closed");
    assert.equal(ctx.records("navigate").filter((r) => r.targetId === heldId).length, 0, "a page that never ran is never navigated");
    assert.equal(
      ctx.records("recv").filter((r) => r.method === "Page.navigate" && r.sessionId === heldSession).length,
      0,
      "no Page.navigate went out on its session",
    );
    // The cleanup finished clean: closing what run nothing needs no stop path.
    assert.equal(ctx.child.exitCode, null, "the relay is still running");
    assert.doesNotMatch(ctx.logs(), /the stop path/, "the cleanup ended in IDLE, not in the stop path");
    assert.equal((await observer.call("Test.state", { targetId: heldId })).result.target.closed, true, "the fixture says the held page is closed");

    // Control: the live page IS navigated, and its close follows its commit.
    const liveNav = ctx.records("navigate").filter((r) => r.targetId === page.targetId && r.url === "about:blank");
    assert.equal(liveNav.length, 1, "the cleanup navigated the live page once");
    assert.equal(liveNav[0].committed, true, "…and that navigation committed");
    const trace = ctx.trace();
    const liveCommit = trace.findLastIndex((r) => r.t === "navigate" && r.targetId === page.targetId && r.committed === true);
    const liveClose = trace.findIndex((r) => r.t === "close-target" && r.targetId === page.targetId);
    assert.ok(liveClose > liveCommit, "the live page's close follows its commit");
  });
});

test("5a-2: script is off on every live page before the cleanup's first Page.enable and navigate, and never back on (control: the replacement is untouched)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { guard, page } = await armedPageAndGuard(ctx, wsUrl);
    const clientSessions = new Set(guard.attached.map((a) => a.sessionId));
    const liveIds = ["P1", page.targetId]; // P1 is resumed at start (the gate's IDLE pass)
    const marker = `drop-${randomBytes(3).toString("hex")}`;
    await guard.call("Test.echo", { value: marker });
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill();
    await waitLog(ctx, /gate state CLEANUP/);
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);

    const trace = ctx.trace();
    const at = markerIndex(trace, "Test.echo", marker);
    assert.ok(at >= 0, "the drop marker is in the trace");
    const firstEnable = trace.findIndex((r, i) => i > at && r.t === "recv" && r.method === "Page.enable");
    const firstNavigate = trace.findIndex((r, i) => i > at && r.t === "navigate" && r.url === "about:blank");
    assert.ok(firstEnable > at, "the cleanup enabled a page");
    assert.ok(firstNavigate > at, "the cleanup navigated a live page");

    for (const targetId of liveIds) {
      const sessionId = gateSessionFor(ctx, targetId, clientSessions);
      assert.ok(sessionId, `the gate has its own session on ${targetId}`);
      const off = trace.findIndex(
        (r, i) => i > at && r.t === "recv" && r.method === "Emulation.setScriptExecutionDisabled" && r.sessionId === sessionId && r.params?.value === true,
      );
      assert.ok(off > at, `script execution was turned off on ${targetId}'s session`);
      assert.ok(off < firstEnable, `script is off on ${targetId} before the cleanup's first Page.enable (${off} < ${firstEnable})`);
      assert.ok(off < firstNavigate, `…and before its first Page.navigate (${off} < ${firstNavigate})`);
      assert.equal(
        trace.filter(
          (r, i) => i > at && r.t === "recv" && r.method === "Emulation.setScriptExecutionDisabled" && r.sessionId === sessionId && r.params?.value === false,
        ).length,
        0,
        `script execution is never turned back on for a cleaned page (${targetId})`,
      );
    }

    // Control: the replacement page is neither switched nor navigated.
    const replacement = ctx.records("create-target").at(-1)?.targetId;
    assert.ok(replacement, "the cleanup created the replacement page");
    assert.ok(!liveIds.includes(replacement), "the replacement is a new target");
    const replacementSession = gateSessionFor(ctx, replacement, clientSessions);
    assert.ok(replacementSession, "the gate has its own session on the replacement");
    assert.equal(
      trace.filter((r) => r.t === "recv" && r.method === "Emulation.setScriptExecutionDisabled" && r.sessionId === replacementSession).length,
      0,
      "the replacement page is not touched by the script switch",
    );
    assert.equal(ctx.records("navigate").filter((r) => r.targetId === replacement).length, 0, "and it is never navigated");
  });
});

test("5b: the surviving page is the replacement — a new target id, one history entry, and the relay never navigates it", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    guard.kill();
    await waitLog(ctx, /gate state IDLE/, 12000);

    const pages = (await liveTargets(observer)).filter((t) => t.type === "page");
    assert.equal(pages.length, 1, `exactly one page is left: ${JSON.stringify(pages)}`);
    const replacement = pages[0].targetId;
    assert.notEqual(replacement, "P1", "the start page is not reused");
    assert.notEqual(replacement, page.targetId, "the bot page is not reused");
    assert.equal(pages[0].url, "about:blank");

    const state = (await observer.call("Test.state", { targetId: replacement })).result;
    assert.equal(state.target.history.length, 1, "the replacement has one history entry");
    assert.equal(ctx.records("navigate").filter((r) => r.targetId === replacement).length, 0, "the relay never navigates the replacement");
  });
});

test("5c: a page that never commits is NEVER closed — the relay takes the stop path", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    await observer.call("Test.setCommit", { targetId: page.targetId, commit: false });
    await observer.call("Page.navigate", { url: "https://bot.example/never-commits" }, guard.sessionFor(page.targetId));
    guard.kill();

    const exit = await Promise.race([ctx.exited, sleep(7000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `a page that never commits must not be closed and must not be waited on forever; log:\n${ctx.logs()}`);
    assert.notEqual(exit.code, 0, "the stop path exits non-zero");
    assert.equal(ctx.records("close-target").filter((r) => r.targetId === page.targetId).length, 0, "the non-committing page is never closed");
    assert.equal(ctx.records("browser-close").length, 0, "and Browser.close is never written on the stop path");
    const pid = ctx.pid();
    assert.ok(pid, "the fixture recorded its pid");
    assert.ok(await waitPidGone(pid), "the Chromium process group was SIGKILLed (the fixture's pid is gone)");
  });
});

test("5d: non-default browser contexts are disposed during cleanup", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, guard } = await armedPageAndGuard(ctx, wsUrl);
    const created = await observer.call("Target.createBrowserContext");
    const contextId = created.result.browserContextId;
    await observer.call("Target.createTarget", { url: "about:blank", browserContextId: contextId });
    // Counted BEFORE the drop: the cleanup (which disposes the context) can reach IDLE between
    // the CLEANUP line being read and the count being taken.
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill();
    // The start-up log already carries "gate state IDLE", so CLEANUP comes first and then the
    // NEXT IDLE: otherwise this reads the dispose records of a cleanup still in flight.
    await waitLog(ctx, /gate state CLEANUP/);
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);
    const disposed = ctx.records("dispose-context").map((r) => r.id);
    assert.ok(disposed.includes(contextId), `the bot's own context is disposed: ${JSON.stringify(disposed)}`);
  });
});

test("5d-5: a browser that starts with a non-default browser context takes the full neutralisation (control: a clean start is skipped)", async (t) => {
  // The only page is the browser's own clean default-context about:blank; the context of its
  // own is what says the browser is not at the neutral state.
  await withGate(t, { FAKE_CHROME_START_CONTEXT: "1", FAKE_CHROME_EXTENSION_WORKERS: "" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);
    const contextIds = ctx.records("start-context").map((r) => r.id);
    assert.equal(contextIds.length, 1, `the fixture started with one non-default context: ${JSON.stringify(contextIds)}`);

    const replacement = ctx.records("create-target").at(-1)?.targetId;
    assert.ok(replacement, "the start created the fresh replacement page");
    assert.notEqual(replacement, "P1", "…and it is not the start page");
    assert.equal(ctx.records("close-target").some((r) => r.targetId === "P1"), true, "the start page was closed");
    assert.ok(ctx.records("dispose-context").some((r) => r.id === contextIds[0]), "the non-default context was disposed");
  });

  // Control: one clean about:blank page and nothing else — there is nothing to neutralise.
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);
    assert.equal(ctx.records("create-target").length, 0, "control: no replacement page is created");
    assert.equal(ctx.records("close-target").length, 0, "control: nothing is closed");
    assert.equal(ctx.records("dispose-context").length, 0, "control: no context is disposed");
    const state = (await observer.call("Test.state", { targetId: "P1" })).result.target;
    assert.equal(state.closed, false, "control: the start page is the page that survives");
    assert.equal(state.history.length, 1, "control: and it is still the fresh start page");
  });
});

test("5d-6: a start page whose targetInfo carries NO url is not the neutral state — the full neutralisation runs (control: an about:blank start page is skipped)", async (t) => {
  await withGate(t, { FAKE_CHROME_START_PAGE_NO_URL: "1", FAKE_CHROME_EXTENSION_WORKERS: "" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);

    // The fixture's own record of the start page: no url key at all, which is NOT about:blank.
    const startPage = ctx.records("start-page")[0];
    assert.ok(startPage, "the fixture recorded its start page");
    assert.equal("url" in startPage, false, `the start page's targetInfo carried no url: ${JSON.stringify(startPage)}`);

    const replacement = ctx.records("create-target").at(-1)?.targetId;
    assert.ok(replacement, "the start created the fresh replacement page");
    assert.notEqual(replacement, "P1", "…and it is not the start page");
    assert.equal(ctx.records("close-target").some((r) => r.targetId === "P1"), true, "the start page was closed");
    const state = (await observer.call("Test.state", { targetId: replacement })).result.target;
    assert.equal(state.closed, false, "the replacement is the page that survives");
    const pages = (await liveTargets(observer)).filter((info) => info.type === "page");
    assert.equal(pages.length, 1, `one page is left: ${JSON.stringify(pages)}`);
    assert.equal(pages[0].targetId, replacement, "and it is the replacement");
  });

  // Control: one clean about:blank page and nothing else — there is nothing to neutralise.
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);
    const startPage = ctx.records("start-page")[0];
    assert.equal(startPage?.url, "about:blank", `control: the start page is at about:blank: ${JSON.stringify(startPage)}`);
    assert.equal(ctx.records("create-target").length, 0, "control: no replacement page is created");
    assert.equal(ctx.records("close-target").length, 0, "control: nothing is closed");
    assert.equal(ctx.records("navigate").length, 0, "control: nothing is navigated");
  });
});

// ---------------------------------------------------------------------------------------
// 5b. the barrier, and the resume rules
// ---------------------------------------------------------------------------------------

test("5b-1: no client attach event arrives before the gate's Fetch.enable and nested auto-attach are acknowledged — at depth 2 as well", async (t) => {
  // The fixture holds every Fetch.enable reply for 300 ms, which is exactly the ack the
  // client-bound attach event has to wait for.
  await withGate(t, { FAKE_CHROME_DELAY_METHODS: "Fetch.enable:300" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;

    const started = Date.now();
    const created = await observer.call("Target.createTarget", { url: "about:blank" });
    const targetId = created.result.targetId;
    await observer.waitFor((m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === targetId, 6000, `the attach event for ${targetId}`);
    const waited = Date.now() - started;
    assert.ok(waited >= 250, `the attach event waited for the gate's ack (${waited} ms)`);
    await waitTrace(ctx, (r) => r.t === "fetch-enable" && r.targetId === targetId, 4000, "the gate's Fetch.enable on the new page");

    // Depth 2: an iframe inside an iframe. The gate's nested auto-attach is the ack in between.
    const frameStart = Date.now();
    const frame = await observer.call("Test.spawnTarget", { type: "iframe", ownerId: targetId, url: "https://bot.example/frame" });
    const frameId = frame.result.targetId;
    await observer.waitFor((m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === frameId, 6000, `the attach event for ${frameId}`);
    const frameWaited = Date.now() - frameStart;
    assert.ok(frameWaited >= 250, `the iframe's attach event waited for the gate's ack (${frameWaited} ms)`);

    const innerStart = Date.now();
    const inner = await observer.call("Test.spawnTarget", { type: "iframe", ownerId: frameId, url: "https://bot.example/inner" });
    const innerId = inner.result.targetId;
    await observer.waitFor((m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === innerId, 8000, `the depth-2 attach event for ${innerId}`);
    const innerWaited = Date.now() - innerStart;
    assert.ok(innerWaited >= 250, `the depth-2 attach event waited for the gate's nested ack (${innerWaited} ms)`);
    await waitTrace(ctx, (r) => r.t === "fetch-enable" && r.targetId === innerId, 4000, "the gate's Fetch.enable on the depth-2 iframe");

    // Control: with the ack delay removed, the same event is not held.
    await observer.call("Test.delayReplies", { method: "Fetch.enable", ms: 0 });
    const controlStart = Date.now();
    const quick = await observer.call("Target.createTarget", { url: "about:blank" });
    await observer.waitFor((m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === quick.result.targetId, 6000, "the control attach event");
    const controlWaited = Date.now() - controlStart;
    assert.ok(controlWaited < 250, `control: no ack delay, no hold (${controlWaited} ms)`);
  });
});

test("5b-2: coverage-gated resume — a page does not run until the guard has hooked it, even after runIfWaitingForDebugger", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    // Playwright's order: resume first, hook 400 ms later.
    const guard = guardClient(wsUrl, { hookDelayMs: 400 });
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const created = await observer.call("Target.createTarget", { url: "about:blank" });
    const targetId = created.result.targetId;
    const held = (await observer.call("Test.state", { targetId })).result.target;
    assert.equal(held.running, false, "the page is held: the client resumed it, the gate has not (no coverage yet)");
    assert.equal((await probe(observer, targetId, "https://bot.example/while-held")).outcome, "held", "and a held page runs nothing");

    const deadline = Date.now() + 5000;
    let running = false;
    while (Date.now() < deadline) {
      running = (await observer.call("Test.state", { targetId })).result.target.running === true;
      if (running) break;
      await sleep(50);
    }
    assert.equal(running, true, "once the guard's Fetch.enable {*} and marker script are seen, the gate resumes it");
    await waitCovered(observer, targetId);
  });
});

test("5b-3: in IDLE a new page resumes at once; a dedicated worker resumes with its covered owner", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);

    // IDLE: nothing is held over, so the operator's own pages are not stuck.
    const idlePage = await observer.call("Target.createTarget", { url: "about:blank" });
    const idleId = idlePage.result.targetId;
    await sleep(200);
    assert.equal((await observer.call("Test.state", { targetId: idleId })).result.target.running, true, "in IDLE a new page runs at once");

    // GUARDED: a dedicated worker resumes with its covered owner (Fetch does not exist on a
    // worker target, so a rule that waited for the worker's own coverage would hang it).
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page = await makePage(guard, "https://bot.example/with-worker");
    await waitCovered(observer, page.targetId);
    const worker = await observer.call("Test.spawnTarget", { type: "worker", ownerId: page.targetId, url: "https://bot.example/worker.js" });
    const workerId = worker.result.targetId;
    const deadline = Date.now() + 5000;
    let running = false;
    while (Date.now() < deadline) {
      running = (await observer.call("Test.state", { targetId: workerId })).result.target.running === true;
      if (running) break;
      await sleep(50);
    }
    assert.equal(running, true, "the dedicated worker resumes once its owning page is covered");
  });
});

test("5b-4: shared and service workers are closed, swallowed and never resumed (control: a page is forwarded)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    for (const type of ["shared_worker", "service_worker"]) {
      const spawned = await observer.call("Test.spawnTarget", { type, url: `https://bot.example/${type}.js` });
      const targetId = spawned.result.targetId;
      const spawnAt = ctx.trace().findLastIndex((r) => r.t === "spawn-target" && r.targetId === targetId);
      await waitTrace(ctx, (r) => r.t === "close-target" && r.targetId === targetId, 5000, `the close of ${targetId}`);

      const trace = ctx.trace();
      const closeAt = trace.findIndex((r) => r.t === "close-target" && r.targetId === targetId);
      assert.ok(closeAt > spawnAt, "the close follows the spawn");
      const between = trace.slice(spawnAt, closeAt).filter((r) => r.t === "recv" && r.method === "Target.detachFromTarget");
      assert.equal(between.length, 0, `no detach precedes the close of ${targetId} (a detach can count as the resume)`);
      assert.equal(ctx.records("resumed").filter((r) => r.targetId === targetId).length, 0, `the gate never resumes ${targetId}`);
      // Swallowed: the client-bound attach event never reaches a recording client.
      assert.equal(observer.attached.filter((a) => a.targetId === targetId).length, 0, `the client never sees the attach event for ${targetId}`);
      assert.equal(guard.attached.filter((a) => a.targetId === targetId).length, 0, `nor the guard for ${targetId}`);
    }

    // Control: a page's attach event IS forwarded.
    const page = await observer.call("Target.createTarget", { url: "about:blank" });
    const pageId = page.result.targetId;
    await observer.waitFor((m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === pageId, 6000, `the attach event for ${pageId}`);
  });
});

test("5b-5: a chrome-extension:// worker at an allow-listed id present at gate start survives; a page-created one and an unknown extension id are closed", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: COMPONENT_EXTENSION_ID }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const component = ctx.records("extension-worker");
    assert.equal(component.length, 1, `the fixture made the one allow-listed component worker: ${JSON.stringify(component)}`);
    await sleep(800);
    const closed = new Set(ctx.records("close-target").map((r) => r.targetId));
    for (const worker of component) {
      assert.equal(closed.has(worker.targetId), false, `a component-extension worker present at gate start is NOT closed (${worker.url})`);
      const infos = await liveTargets(observer);
      assert.ok(infos.some((i) => i.targetId === worker.targetId), "…and it is still listed");
    }

    // A page-created service worker, and one at an extension id that was NOT there at start.
    const pageWorker = await observer.call("Test.spawnTarget", { type: "service_worker", url: "https://bot.example/page-sw.js" });
    await waitTrace(ctx, (r) => r.t === "close-target" && r.targetId === pageWorker.result.targetId, 5000, "the page-created service worker's close");
    const unknown = await observer.call("Test.spawnTarget", { type: "service_worker", url: `chrome-extension://${UNKNOWN_EXTENSION_ID}/background.js` });
    await waitTrace(ctx, (r) => r.t === "close-target" && r.targetId === unknown.result.targetId, 5000, "the unknown-extension worker's close");
  });
});

test("5b-11: a component-extension worker is never handed to a client — no attach event, an explicit attach is refused, and it stays open (control: a page's attach event is forwarded)", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: COMPONENT_EXTENSION_ID }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);
    await waitTrace(ctx, (r) => r.t === "extension-worker", 4000, "the component-extension worker");
    const workers = ctx.records("extension-worker");
    assert.equal(workers.length, 1, `the fixture made the one allow-listed component worker: ${JSON.stringify(workers)}`);
    // This client auto-attached at connect: its browser session is what the fixture announces
    // them to, which is exactly the event the relay has to swallow.
    await sleep(500);

    for (const worker of workers) {
      assert.equal(
        observer.attached.filter((a) => a.targetId === worker.targetId).length,
        0,
        `a client never sees an attach event for a component-extension worker (${worker.url})`,
      );
      assert.equal(
        ctx.records("resumed").some((r) => r.targetId === worker.targetId),
        true,
        `…while the gate's own resume is what runs it (${worker.url})`,
      );
      const state = (await observer.call("Test.state", { targetId: worker.targetId })).result.target;
      assert.equal(state.closed, false, `the worker is left open (${worker.url})`);
      assert.ok((await liveTargets(observer)).some((i) => i.targetId === worker.targetId), "…and still listed");
    }

    // An explicit attach to it is refused here, and never reaches the fixture.
    const refused = await observer.call("Target.attachToTarget", { targetId: workers[0].targetId, flatten: true });
    assert.equal(typeof refused.error, "object", `an explicit attach to a component-extension worker is refused: ${JSON.stringify(refused)}`);
    assert.equal(
      ctx.records("recv").filter((r) => r.method === "Target.attachToTarget" && r.params?.targetId === workers[0].targetId).length,
      0,
      "and it never reached the fixture",
    );

    // Control: a page's attach event IS forwarded.
    const page = await observer.call("Target.createTarget", { url: "about:blank" });
    const pageId = page.result.targetId;
    await observer.waitFor((m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === pageId, 6000, `the attach event for ${pageId}`);
  });
});

test("5b-6: other, prerender and unknown target types are held and closed, never resumed", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    for (const type of ["other", "prerender", "worklet"]) {
      const spawned = await observer.call("Test.spawnTarget", { type, url: "https://bot.example/x" });
      const targetId = spawned.result.targetId;
      await waitTrace(ctx, (r) => r.t === "close-target" && r.targetId === targetId, 5000, `the close of the ${type} target ${targetId}`);
      assert.equal(ctx.records("resumed").filter((r) => r.targetId === targetId).length, 0, `a ${type} target is never resumed`);
    }
  });
});

test("5b-7: a client Target.attachToTarget is held until the gate's acks, and refused for a target the gate never attached", async (t) => {
  // 500 ms of ack delay on the gate's own Fetch.enable: long enough that the explicit attach is
  // issued INSIDE that window and can only be answered after it closes.
  await withGate(t, { FAKE_CHROME_DELAY_METHODS: "Fetch.enable:500" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;

    // The createTarget REPLY is held behind this client's attach event, and that event is held
    // for the gate's Fetch.enable ack — so the targetId is read from the fixture, and the
    // explicit attach goes out while the ack is still pending. That is the case this test is
    // about: the old shape awaited the createTarget reply first, which now already means the
    // ack landed, so the attach it timed was never the one being held.
    const known = await targetIds(observer);
    const createdStart = Date.now();
    const createdReply = observer.call("Target.createTarget", { url: "about:blank" });
    const targetId = await waitNewTarget(observer, known);
    await waitTrace(ctx, (r) => r.t === "fetch-enable" && r.targetId === targetId, 4000, "the gate's Fetch.enable on the new page");

    const attachStart = Date.now();
    const attachId = observer.send("Target.attachToTarget", { targetId, flatten: true });
    // While the ack is pending the command is still on the client's side of the relay: the
    // fixture has no record of it, because it has not been written to the pipe at all.
    await sleep(150);
    assert.equal(
      ctx.records("recv").filter((r) => r.method === "Target.attachToTarget" && r.params?.targetId === targetId).length,
      0,
      "the explicit attach is still held: it has not reached the pipe while the gate's ack is pending",
    );
    const attached = await observer.waitFor((m) => m.id === attachId, 6000, "the explicit attach's reply");
    const waited = Date.now() - attachStart;
    assert.ok(attached.result?.sessionId, "the explicit attach is answered");
    assert.ok(waited >= 400, `it was held until the gate's Fetch.enable ack landed (${waited} ms)`);
    // The reply held in front of it waited for the same ack, and is the page the fixture listed.
    assert.ok(Date.now() - createdStart >= 400, "the createTarget reply held in front of the attach waited for that ack too");
    const created = await createdReply;
    assert.equal(created.result?.targetId, targetId, "the held createTarget reply names the page the fixture listed");

    // Pipe order, from the fixture's own records: the attach only reached Chromium once the
    // gate had taken its interception place on that page.
    const trace = ctx.trace();
    const gateInterception = trace.findIndex((r) => r.t === "fetch-enable" && r.targetId === targetId);
    const attachRecv = trace.findLastIndex((r) => r.t === "recv" && r.method === "Target.attachToTarget" && r.params?.targetId === targetId);
    assert.ok(gateInterception >= 0, "the fixture recorded the gate's Fetch.enable for that page");
    assert.ok(attachRecv > gateInterception, "the attach reached the pipe only after the gate's interception place was taken");

    // Control: no ack delay, no hold.
    await observer.call("Test.delayReplies", { method: "Fetch.enable", ms: 0 });
    const quick = await observer.call("Target.createTarget", { url: "about:blank" });
    const controlStart = Date.now();
    await observer.call("Target.attachToTarget", { targetId: quick.result.targetId, flatten: true });
    assert.ok(Date.now() - controlStart < 250, "control: without the delay the attach is not held");

    // A targetId that exists nowhere: the gate has no session for it, so the attach is refused
    // here and the fixture never sees a request for it at all.
    const hiddenId = "NOSUCH";
    const refused = await observer.call("Target.attachToTarget", { targetId: hiddenId, flatten: true });
    assert.equal(typeof refused.error, "object", `an attach to a target the gate never attached is refused: ${JSON.stringify(refused)}`);
    assert.equal(
      ctx.records("recv").filter((r) => r.method === "Target.attachToTarget" && r.params?.targetId === hiddenId).length,
      0,
      "and it never reached the fixture",
    );
  });
});

test("5b-8: a client Target.attachToTarget for a known shared worker is refused and never reaches the fixture", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const spawned = await observer.call("Test.spawnTarget", { type: "shared_worker", url: "https://bot.example/known-sw.js" });
    const targetId = spawned.result.targetId;
    await waitTrace(ctx, (r) => r.t === "close-target" && r.targetId === targetId, 5000, "the shared worker's close");

    const refused = await observer.call("Target.attachToTarget", { targetId, flatten: true });
    assert.equal(typeof refused.error, "object", `a known shared worker is never attachable: ${JSON.stringify(refused)}`);
    assert.equal(
      ctx.records("recv").filter((r) => r.method === "Target.attachToTarget" && r.params?.targetId === targetId).length,
      0,
      "and the attach never reached the fixture",
    );
  });
});

test("5b-9: a failed gate ack with the target still listed takes the stop path", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    // Every Fetch.enable from here on fails: the gate cannot take its oldest-interceptor
    // place on the next page, and that page is still listed.
    await observer.call("Test.failCommands", { methods: ["Fetch.enable"] });
    const created = await observer.call("Target.createTarget", { url: "about:blank" });
    const targetId = created.result.targetId;

    const exit = await Promise.race([ctx.exited, sleep(8000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `a failed gate ack with the target still listed is gate loss, i.e. the stop path; log:\n${ctx.logs()}`);
    assert.notEqual(exit.code, 0, "the relay exits non-zero");
    assert.equal(ctx.records("browser-close").length, 0, "and it does not close the browser first");
    assert.ok(await gateReadyFalse(ctx.port ?? (await waitReadyOrNull(ctx))), "gate ready is no longer true");
    void targetId;
  });
});

/** The port, when the relay got as far as writing its ready file. */
async function waitReadyOrNull(ctx) {
  try { return JSON.parse(readFileSync(ctx.readyFile, "utf8")).port; } catch { return null; }
}

test("5b-10: a buffered client attach event for a target that is already gone is dropped, never forwarded", async (t) => {
  // 800 ms of ack delay on the gate's own Fetch.enable: long enough for ANOTHER client to close
  // the page (and for the gate to notice the detach and settle) while this client's attach
  // event is still buffered behind that ack. The close cannot be waited on the createTarget
  // reply any more: that reply is exactly what the buffered event is holding back.
  await withGate(t, { FAKE_CHROME_DELAY_METHODS: "Fetch.enable:800" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    const closer = plainClient(wsUrl, { attach: false });
    await closer.armed;

    const known = await targetIds(observer);
    const createdReply = observer.call("Target.createTarget", { url: "about:blank" });
    const targetId = await waitNewTarget(observer, known);
    await waitTrace(ctx, (r) => r.t === "fetch-enable" && r.targetId === targetId, 4000, "the gate's Fetch.enable on the new page");
    assert.equal(
      observer.attached.filter((a) => a.targetId === targetId).length,
      0,
      "the attach event is still buffered (behind the gate's ack) when the page is closed",
    );

    // The browser side closes it: another client, while the view's ack is still pending.
    const closed = await closer.call("Target.closeTarget", { targetId });
    assert.equal(closed.result?.success, true, `the fixture closed the page: ${JSON.stringify(closed)}`);

    // Fail closed: the reply the event was ordering is an ERROR, never a success a client could
    // not use (there is no page to look up).
    const reply = await createdReply;
    assert.equal(typeof reply.error, "object", `a create whose page is gone is answered with an error: ${JSON.stringify(reply)}`);
    assert.equal(reply.result, undefined, "and it carries no targetId for a page that no longer exists");
    assert.match(String(reply.error?.message ?? ""), /could not cover/, "it is the relay's fail-closed error, not the browser's");

    await sleep(300);
    assert.equal(observer.attached.filter((a) => a.targetId === targetId).length, 0, "the buffered event for a target that is gone is dropped");
    assert.equal(ctx.child.exitCode, null, "and a target that was simply closed is not gate loss");

    // The relay stays up and serving: with the ack delay gone, a fresh page is created and its
    // attach event arrives (the drop above took nothing else with it).
    await observer.call("Test.delayReplies", { method: "Fetch.enable", ms: 0 });
    const after = await observer.call("Target.createTarget", { url: "about:blank" });
    const afterId = after.result?.targetId;
    assert.ok(afterId, `the relay still creates pages after the drop: ${JSON.stringify(after)}`);
    await observer.waitFor((m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === afterId, 6000, `the attach event for ${afterId}`);
  });
});

// ---------------------------------------------------------------------------------------
// 5c. coverage details, in the order the relay writes them
// ---------------------------------------------------------------------------------------

test("5c-1: coverage clears when Fetch.disable is FORWARDED — the released request must fail at the gate (control: an unrelated command keeps it)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    // This guard answers nothing on its own (autoContinue:false): every request it is handed
    // stays paused until this test answers it, so a probe would never get a reply. Coverage is
    // therefore shown by WHERE a request ends up, not by a probe.
    const guard = guardClient(wsUrl, { autoContinue: false });
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const page = await makePage(guard, "https://bot.example/disable");
    const sessionId = guard.sessionFor(page.targetId);
    assert.ok(sessionId, "the guard has its session for the page");
    // The page runs only once the gate resumed it, which in GUARDED it does only when the
    // guard's Fetch.enable and marker script are acknowledged: that latch is the coverage
    // check, and it cannot hang the way a probe on this guard can.
    assert.equal(await waitRunning(observer, page.targetId), true, "the gate resumed the page: it is covered");

    // Covered: a request the guard holds and then continues is passed by the older gate session.
    const first = observer.call("Test.request", { targetId: page.targetId, url: "https://bot.example/covered" }, undefined, 8000);
    const firstPause = await guard.waitFor(
      (m) => m.method === "Fetch.requestPaused" && m.sessionId === sessionId && m.params?.request?.url === "https://bot.example/covered",
      6000, "the first paused request",
    );
    await guard.call("Fetch.continueRequest", { requestId: firstPause.params.requestId }, sessionId);
    assert.equal((await first).result?.outcome, "passed", "the covering guard's page passes: the gate continues what the guard released");

    // The guard holds a request and then disables Fetch: the fixture releases it onward to the
    // older (gate) session, which must already have stopped covering the page.
    const released = observer.call("Test.request", { targetId: page.targetId, url: "https://bot.example/released" }, undefined, 8000);
    await guard.waitFor(
      (m) => m.method === "Fetch.requestPaused" && m.sessionId === sessionId && m.params?.request?.url === "https://bot.example/released",
      6000, "the released paused request",
    );
    await guard.call("Fetch.disable", {}, sessionId);
    assert.equal((await released).result?.outcome, "failed", "the relay cleared coverage BEFORE writing Fetch.disable");

    // The fixture's own record says whose session failed it: the gate's, not the guard's.
    const clientSessions = new Set([...guard.attached.map((a) => a.sessionId)]);
    const gateSession = gateSessionFor(ctx, page.targetId, clientSessions);
    assert.ok(gateSession, "the gate has its own session on the page");
    const record = await waitTrace(ctx, (r) => r.t === "request" && r.url === "https://bot.example/released", 4000, "the released request's record");
    assert.equal(record.outcome, "failed", "the released request fails");
    assert.ok(record.via.includes(gateSession), `it failed at the gate's own session (${JSON.stringify(record)})`);

    // Control: an unrelated command keeps coverage, so the same released request passes.
    await guard.call("Fetch.enable", { handleAuthRequests: true, patterns: [{ urlPattern: "*", requestStage: "Request" }] }, sessionId);
    await sleep(100);
    const kept = observer.call("Test.request", { targetId: page.targetId, url: "https://bot.example/kept" }, undefined, 8000);
    const keptPause = await guard.waitFor(
      (m) => m.method === "Fetch.requestPaused" && m.sessionId === sessionId && m.params?.request?.url === "https://bot.example/kept",
      6000, "the second paused request",
    );
    await guard.call("Page.enable", {}, sessionId);
    await guard.call("Fetch.continueRequest", { requestId: keptPause.params.requestId }, sessionId);
    assert.equal((await kept).result?.outcome, "passed", "control: an unrelated command leaves coverage in place");
  });
});

test("5c-2: the session-to-target map comes only from the fixture's events — a client param naming another targetId is ignored", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const mine = await makePage(guard, "https://bot.example/mine");
    await waitCovered(observer, mine.targetId);

    // A page the guard is handed and does not hook: the only thing that could claim it is a
    // forged param naming its targetId (a browser-level auto-attacher sees every context, so
    // hiding it in one is no longer how a page stays out of reach).
    guard.hookEnabled = false;
    const other = await observer.call("Test.spawnTarget", { type: "page", url: "https://bot.example/other" });
    const otherId = other.result.targetId;
    await sleep(200);
    await assertUncovered(observer, otherId, "control: it starts uncovered");

    // The client names that targetId on ITS OWN session: the map must come from events only.
    const sessionId = guard.sessionFor(mine.targetId);
    await guard.call("Fetch.enable", { handleAuthRequests: true, patterns: [{ urlPattern: "*", requestStage: "Request" }], targetId: otherId }, sessionId);
    await guard.call("Page.addScriptToEvaluateOnNewDocument", { source: MARKER_WRAPPED, targetId: otherId }, sessionId);
    await sleep(200);
    await assertUncovered(observer, otherId, "a param naming another targetId does not cover it");
    assert.equal((await probe(observer, mine.targetId)).outcome, "passed", "control: the session's own page is still covered");
  });
});

test("5c-3: params naming a gate session are refused and change nothing (control: the same call on the client's own session works)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page = await makePage(guard, "https://bot.example/params");
    await waitCovered(observer, page.targetId);

    const clientSessions = new Set([...guard.attached.map((a) => a.sessionId)]);
    const gateSession = gateSessionFor(ctx, page.targetId, clientSessions);
    assert.ok(gateSession, "the gate has its own session on the page");

    const refused = await guard.call("Target.detachFromTarget", { sessionId: gateSession });
    assert.equal(typeof refused.error, "object", `a param naming a gate session is refused: ${JSON.stringify(refused)}`);
    // The same rule on the Fetch side: a request id can never be driven through the gate's
    // session (the envelope is the gate's, so it is refused before anything is routed).
    const fetchRefused = await guard.call("Fetch.continueRequest", { requestId: "R1" }, gateSession);
    assert.equal(typeof fetchRefused.error, "object", `a command on a gate session is refused: ${JSON.stringify(fetchRefused)}`);
    await sleep(400);
    assert.equal(countLog(ctx, /gate state CLEANUP/), 0, "the gate's state does not change");
    assert.equal((await probe(observer, page.targetId)).outcome, "passed", "and the page stays covered");
    assert.ok(ctx.trace().some((r) => r.t === "recv" && r.method === "Fetch.enable" && r.sessionId === gateSession), "the gate session is still the fixture's");

    // Control: the same call against the client's own session works.
    const ownSession = guard.sessionFor(page.targetId);
    const accepted = await guard.call("Target.detachFromTarget", { sessionId: ownSession });
    assert.equal(accepted.error, undefined, `the client may detach its own session: ${JSON.stringify(accepted)}`);
    await waitTrace(ctx, (r) => r.t === "detached" && r.sessionId === ownSession, 4000, "the fixture accepting the client's own detach");
  });
});

test("5c-4: Target.sendMessageToTarget and setAutoAttach {flatten:false} are refused outright and never reach the fixture", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page = await makePage(guard, "https://bot.example/non-flat");
    const sessionId = guard.sessionFor(page.targetId);

    const nested = await guard.call("Target.sendMessageToTarget", { sessionId, message: JSON.stringify({ id: 1, method: "Target.createTarget", params: { url: "https://x" } }) });
    assert.equal(typeof nested.error, "object", `Target.sendMessageToTarget is refused: ${JSON.stringify(nested)}`);
    const nonFlat = await guard.call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: false }, sessionId);
    assert.equal(typeof nonFlat.error, "object", `setAutoAttach {flatten:false} is refused: ${JSON.stringify(nonFlat)}`);

    assert.equal(ctx.records("recv").filter((r) => r.method === "Target.sendMessageToTarget").length, 0, "no target-command transport reached the pipe");
    assert.equal(ctx.records("recv").filter((r) => r.method === "Target.setAutoAttach" && r.params?.flatten === false).length, 0, "no non-flat auto-attach reached the pipe");
    assert.equal(ctx.records("create-target").filter((r) => r.url === "https://x").length, 0, "and the wrapped Target.createTarget {url} did not either");
  });
});

test("5c-4b: Target.exposeDevToolsProtocol and Target.attachToTarget {flatten:false} are refused and never reach the fixture (control: a flatten:true attach is answered)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const plain = plainClient(wsUrl, { attach: false });
    await plain.armed;
    const page = await makePage(plain, "https://bot.example/no-second-driver");

    // A second protocol driver on a target the gate is in front of: answered with an error here.
    const exposed = await plain.call("Target.exposeDevToolsProtocol", { targetId: page.targetId, bindingName: "__crow_second_driver" });
    assert.equal(typeof exposed.error, "object", `Target.exposeDevToolsProtocol is refused: ${JSON.stringify(exposed)}`);
    assert.equal(
      ctx.records("recv").filter((r) => r.method === "Target.exposeDevToolsProtocol").length,
      0,
      "and never reached the fixture",
    );

    // A non-flat attach: its commands travel in a param the relay does not route.
    const nonFlat = await plain.call("Target.attachToTarget", { targetId: page.targetId, flatten: false });
    assert.equal(typeof nonFlat.error, "object", `Target.attachToTarget {flatten:false} is refused: ${JSON.stringify(nonFlat)}`);
    assert.equal(
      ctx.records("recv").filter((r) => r.method === "Target.attachToTarget" && r.params?.flatten === false).length,
      0,
      "no non-flat attach reached the fixture",
    );
    assert.equal(
      ctx.records("recv").filter((r) => r.method === "Target.attachToTarget").length,
      1,
      "the fixture saw only the flat attach makePage made",
    );

    // Control: an explicit flatten:true attach is still relayed and answered.
    const flat = await plain.call("Target.attachToTarget", { targetId: page.targetId, flatten: true });
    assert.ok(flat.result?.sessionId, `control: a flatten:true attach is answered: ${JSON.stringify(flat)}`);
    assert.equal(ctx.records("recv").filter((r) => r.method === "Target.attachToTarget" && r.params?.flatten === true).length, 2, "control: it reached the fixture");
  });
});

test("5c-5: a gate session id is never in the relay's owner map — guessing S1 gets \"Session not owned\"", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const plain = plainClient(wsUrl, { attach: false });
    await plain.armed;
    const refused = await plain.call("Test.echo", { value: "guess" }, "S1");
    assert.equal(refused.error?.code, -32001, `a gate session is not owned by any client: ${JSON.stringify(refused)}`);
    assert.equal(refused.error?.message, "Session not owned");
    assert.equal(ctx.records("recv").filter((r) => r.method === "Test.echo" && r.params?.value === "guess").length, 0, "and the guess never reached the fixture");
  });
});

test("5c-6: a sessionless (browser-level) Target.detachFromTarget ends coverage by sessionId BEFORE the command is forwarded", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    // This guard hooks ONLY the session this test hands it (`attach: false`, and it answers
    // nothing on its own): a request it is handed stays paused until this test answers it, so
    // where a request a detach RELEASES ends up is the evidence. Its coverage sits on the
    // page's EXPLICITLY attached session — the fixture announces a detach event only for an
    // auto-attached child — so the event path cannot end coverage in time here, and the relay's
    // pre-forward rule is the only thing that can.
    const guard = guardClient(wsUrl, { attach: false, autoContinue: false });
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const page = await makePage(guard, "https://bot.example/sessionless");
    const sessionId = page.sessionId;
    assert.ok(sessionId, "the guard has an explicitly attached session for the page");
    await guard.hookSession(sessionId);
    assert.equal(await waitRunning(observer, page.targetId), true, "the gate resumed the page: it is covered");

    /** One request as the fixture's Fetch chain sees it, paused at the guard's own session. */
    const pausedAtGuard = async (url) => {
      const reply = observer.call("Test.request", { targetId: page.targetId, url }, undefined, 8000);
      const paused = await guard.waitFor(
        (m) => m.method === "Fetch.requestPaused" && m.sessionId === sessionId && m.params?.request?.url === url,
        6000, `the paused request for ${url}`,
      );
      return { reply, requestId: paused.params.requestId };
    };

    // Control (i): the page is covered — a request the guard releases passes.
    const first = await pausedAtGuard("https://bot.example/guard-covered");
    await guard.call("Fetch.continueRequest", { requestId: first.requestId }, sessionId);
    assert.equal((await first.reply).result?.outcome, "passed", "control: the covered page passes");

    // Control (ii): a sessionless detach naming ANOTHER client's session changes nothing here.
    const otherPage = await observer.call("Target.createTarget", { url: "about:blank" });
    const otherAttach = await observer.call("Target.attachToTarget", { targetId: otherPage.result.targetId, flatten: true });
    const otherSession = otherAttach.result?.sessionId;
    assert.ok(otherSession, "the observer holds a session of its own");
    const elsewhere = await guard.call("Target.detachFromTarget", { sessionId: otherSession });
    assert.equal(elsewhere.error, undefined, `the sessionless detach is forwarded: ${JSON.stringify(elsewhere)}`);
    await waitTrace(ctx, (r) => r.t === "detached" && r.sessionId === otherSession, 4000, "the fixture detaching the other client's session");
    const second = await pausedAtGuard("https://bot.example/still-covered");
    await guard.call("Fetch.continueRequest", { requestId: second.requestId }, sessionId);
    assert.equal((await second.reply).result?.outcome, "passed", "control: another client's session is not this page's coverage");

    // The negative: the guard holds a request and detaches that very session with a
    // sessionless (browser-level) Target.detachFromTarget that names it in params.
    const released = await pausedAtGuard("https://bot.example/released-by-detach");
    const detach = await guard.call("Target.detachFromTarget", { sessionId });
    assert.equal(detach.error, undefined, `the sessionless detach is forwarded: ${JSON.stringify(detach)}`);
    assert.equal((await released.reply).result?.outcome, "failed", "the request the detach released must fail at the gate: coverage goes first");

    // The fixture says whose session failed it: the gate's own, older one. (`attach: false`
    // means neither client saw an attach event, so the two explicit sessions are named here.)
    const clientSessions = new Set([
      sessionId,
      otherSession,
      ...guard.attached.map((a) => a.sessionId),
      ...observer.attached.map((a) => a.sessionId),
    ]);
    const gateSession = gateSessionFor(ctx, page.targetId, clientSessions);
    assert.ok(gateSession, "the gate has its own session on the page");
    const record = await waitTrace(ctx, (r) => r.t === "request" && r.url === "https://bot.example/released-by-detach", 4000, "the released request's record");
    assert.ok(record.via.includes(gateSession), `it failed at the gate's own session (${JSON.stringify(record)})`);
  });
});

test("5c-7: a sessionless (browser-level) Target.detachFromTarget ends coverage for that targetId (control: another client's target is untouched)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const page = await makePage(guard, "https://bot.example/by-target");
    assert.ok(guard.sessionFor(page.targetId), "the guard has its own session for the page");
    await waitCovered(observer, page.targetId);

    // Control: a sessionless detach naming a target this guard does not own on its own leaves
    // this page covered (only sessions the CALLER owns are cleared).
    const otherPage = await observer.call("Target.createTarget", { url: "about:blank" });
    const otherAttach = await observer.call("Target.attachToTarget", { targetId: otherPage.result.targetId, flatten: true });
    assert.ok(otherAttach.result?.sessionId, "the observer holds a session of its own");
    const elsewhere = await guard.call("Target.detachFromTarget", { targetId: otherPage.result.targetId });
    assert.equal(elsewhere.error, undefined, `the sessionless detach is forwarded: ${JSON.stringify(elsewhere)}`);
    assert.equal((await probe(observer, page.targetId)).outcome, "passed", "control: another client's target is not this page's coverage");

    // The negative: the same sessionless command, naming THIS page's targetId.
    const detach = await guard.call("Target.detachFromTarget", { targetId: page.targetId });
    assert.equal(detach.error, undefined, `the sessionless detach is forwarded: ${JSON.stringify(detach)}`);
    await assertUncovered(observer, page.targetId, "a detach by targetId ends the page's coverage");
  });
});

test("5c-8: only a Fetch.enable pattern that reaches every request covers, and a later enable REPLACES it", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page = await makePage(guard, "https://bot.example/fetch-patterns");
    const sessionId = guard.sessionFor(page.targetId);
    assert.ok(sessionId, "the guard has its own session for the page");
    await waitCovered(observer, page.targetId);
    const enable = (patterns) => guard.call("Fetch.enable", { handleAuthRequests: true, patterns }, sessionId);

    // (a) a resourceType narrows what the session sees: not coverage any more.
    await enable([{ urlPattern: "*", resourceType: "Document", requestStage: "Request" }]);
    await assertUncovered(observer, page.targetId, "a pattern naming a resourceType does not cover");

    // Control: Playwright's own pattern covers.
    await enable([{ urlPattern: "*", requestStage: "Request" }]);
    await waitCovered(observer, page.targetId);

    // (b) the Response stage sees nothing at request time.
    await enable([{ urlPattern: "*", requestStage: "Response" }]);
    await assertUncovered(observer, page.targetId, "a Response-stage pattern does not cover");

    // Control: a bare `{}` pattern has no urlPattern, so it reaches every request.
    await enable([{}]);
    await waitCovered(observer, page.targetId);

    // (c) a later Fetch.enable REPLACES the earlier patterns: the good set is gone with it.
    await enable([{ urlPattern: "https://*.example.test/*", requestStage: "Request" }]);
    await assertUncovered(observer, page.targetId, "a second, narrower Fetch.enable replaces the earlier pattern set");
  });
});

test("5c-9: a parent session's detach ends coverage for its whole subtree (control: a different parent's child keeps its own)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const first = await coverPage(observer, guard);
    const firstChild = await coverChild(observer, guard, first.targetId, "https://bot.example/child");
    const second = await coverPage(observer, guard);
    const secondChild = await coverChild(observer, guard, second.targetId, "https://bot.example/other-child");

    // A sessionless detach naming the session that carried the child's attach event. That child
    // gets no detach event of its own, so only the relay's own subtree rule can end coverage.
    const detach = await guard.call("Target.detachFromTarget", { sessionId: first.sessionId });
    assert.equal(detach.error, undefined, `the sessionless detach is forwarded: ${JSON.stringify(detach)}`);
    await assertUncovered(observer, firstChild, "a parent session's detach ends its child's coverage");

    // Control: the other parent, and the child it announced, keep their coverage.
    assert.equal((await probe(observer, secondChild)).outcome, "passed", "control: a different parent's child keeps its coverage");
    assert.equal((await probe(observer, second.targetId)).outcome, "passed", "control: the other parent page too");
  });
});

test("5c-10: Target.setAutoAttach {autoAttach:false} on a parent ends its children's coverage (control: the parent and another parent's child keep theirs)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const first = await coverPage(observer, guard);
    const firstChild = await coverChild(observer, guard, first.targetId, "https://bot.example/child");
    const second = await coverPage(observer, guard);
    const secondChild = await coverChild(observer, guard, second.targetId, "https://bot.example/other-child");

    const off = await guard.call("Target.setAutoAttach", { autoAttach: false, waitForDebuggerOnStart: true, flatten: true }, first.sessionId);
    assert.equal(off.error, undefined, `auto-attach off is forwarded: ${JSON.stringify(off)}`);
    await assertUncovered(observer, firstChild, "auto-attach off on the parent ends the coverage of the child it announced");

    // Control: only the subtree below the parent ends — the parent's own coverage, and another
    // parent's child, stay.
    assert.equal((await probe(observer, first.targetId)).outcome, "passed", "control: the parent session keeps its own coverage");
    assert.equal((await probe(observer, secondChild)).outcome, "passed", "control: another parent's child keeps its coverage");
  });
});

test("5c-11: Page.disable forwarded on a session ends its marker coverage (control: another session keeps its own)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const first = await coverPage(observer, guard);
    const second = await coverPage(observer, guard);

    const off = await guard.call("Page.disable", {}, first.sessionId);
    assert.equal(off.error, undefined, `Page.disable is forwarded: ${JSON.stringify(off)}`);
    await waitTrace(ctx, (r) => r.t === "recv" && r.method === "Page.disable" && r.sessionId === first.sessionId, 4000, "the forwarded Page.disable");
    await assertUncovered(observer, first.targetId, "Page.disable ends that session's coverage");

    // Control: the marker coverage of another session is that session's own.
    assert.equal((await probe(observer, second.targetId)).outcome, "passed", "control: another session's page keeps its coverage");
  });
});

test("5c-12: a coverage ack for a session that is no longer the current one for its target sets nothing (control: the current session's own ack covers)", async (t) => {
  // Every Fetch.enable reply is held 400 ms, so an ack can land AFTER the target was announced
  // again under the same id (a new session, the target held anew).
  await withGate(t, { FAKE_CHROME_DELAY_METHODS: "Fetch.enable:400" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const page = await coverPage(observer, guard);
    const frameId = await coverChild(observer, guard, page.targetId, "https://bot.example/stale");
    const staleSession = guard.sessionFor(frameId);
    assert.ok(staleSession, "the guard has its session for the iframe");

    // From here the guard hooks nothing: a session announced later cannot earn coverage back.
    guard.hookEnabled = false;
    const stale = guard.call(
      "Fetch.enable",
      { handleAuthRequests: true, patterns: [{ urlPattern: "*", requestStage: "Request" }] },
      staleSession,
    );
    // The same target id announced again: the attach event makes a NEW session the current one,
    // and the held Fetch.enable ack for the old one lands afterwards.
    const again = await observer.call("Test.spawnTarget", { type: "iframe", id: frameId, ownerId: page.targetId, url: "https://bot.example/stale-again" });
    assert.equal(again.result?.targetId, frameId, "the fixture re-announced the same target id");
    await guard.waitFor(
      (m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === frameId && m.params?.sessionId !== staleSession,
      6000, `a new attach event for ${frameId}`,
    );
    await stale;
    await sleep(300);
    await assertUncovered(observer, frameId, "the ack of a session that is no longer the current one earns nothing");

    // Control: the same held ack on the session that IS the current one covers its target.
    guard.hookEnabled = true;
    const current = await coverChild(observer, guard, page.targetId, "https://bot.example/current");
    assert.equal((await probe(observer, current)).outcome, "passed", "control: the current session's ack covers its target");
  });
});

// ---------------------------------------------------------------------------------------
// 5d. gate loss, and cleanup as a deferral
// ---------------------------------------------------------------------------------------

test("5d-1: an iframe swap with the same targetId does not stop the relay in either order, and the re-attached iframe starts uncovered and held", async (t) => {
  await withGate(t, { CROW_CDP_SETTLE_MS: "300" }, async ({ ctx, wsUrl }) => {
    // Only the gate and the guard auto-attach here: the fixture's swap drops the NEWEST child
    // session of the target, and that has to be the guard's for "uncovered" to mean anything.
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = guardClient(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);
    const page = await makePage(guard, "https://bot.example/oopif");
    await waitCovered(observer, page.targetId);

    const frame = await observer.call("Test.spawnTarget", { type: "iframe", ownerId: page.targetId, url: "https://bot.example/frame" });
    const frameId = frame.result.targetId;
    await waitCovered(observer, frameId);

    for (const order of ["attach-detach", "detach-attach"]) {
      // From here the guard stops hooking: the swapped-in session has to start uncovered.
      guard.hookEnabled = false;
      await observer.call("Test.swapIframe", { targetId: frameId, order });
      await sleep(1200); // the settle, plus the round trip it makes
      assert.equal(ctx.child.exitCode, null, `the relay survives an OOPIF swap (${order})`);
      assert.equal(countLog(ctx, /gate state CLEANUP/), 0, `no cleanup for a swap (${order})`);
      const newSession = guard.sessionFor(frameId);
      assert.ok(newSession, "the swapped-in session was announced");
      assert.equal((await probe(observer, frameId)).outcome, "held", `the swapped-in iframe is held until it is re-hooked (${order})`);

      guard.hookEnabled = true;
      await guard.hookSession(newSession);
      await waitCovered(observer, frameId);
    }
  });
});

test("5d-2: a gate session dropped while its target stays listed takes gate loss after the settle (control: a target that is then destroyed does not)", async (t) => {
  await withGate(t, { CROW_CDP_SETTLE_MS: "300" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    const clientSessions = new Set(guard.attached.map((a) => a.sessionId));
    const gateSession = gateSessionFor(ctx, page.targetId, clientSessions);
    assert.ok(gateSession, "the gate has its own session on the page");

    await observer.call("Test.dropSession", { sessionId: gateSession });
    const exit = await Promise.race([ctx.exited, sleep(8000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `gate loss is the stop path; log:\n${ctx.logs()}`);
    assert.notEqual(exit.code, 0, "the relay exits non-zero");
    assert.ok(await gateReadyFalse(ctx.port ?? (await waitReadyPath(ctx))), "gate ready is no longer true");
  });

  // Control: the same drop on a target that is then destroyed is an ordinary close.
  await withGate(t, { CROW_CDP_SETTLE_MS: "300" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    const clientSessions = new Set(guard.attached.map((a) => a.sessionId));
    const gateSession = gateSessionFor(ctx, page.targetId, clientSessions);
    assert.ok(gateSession, "the gate has its own session on the control page");
    await observer.call("Test.dropSession", { sessionId: gateSession });
    await observer.call("Target.closeTarget", { targetId: page.targetId });
    await sleep(1500);
    assert.equal(ctx.child.exitCode, null, "a target that is destroyed is not gate loss");
    assert.equal(countLog(ctx, /gate state CLEANUP/), 0, "and it triggers no cleanup");
  });
});

/** The port from the ready file, or the relay's own log line, for a late gate-ready check. */
async function waitReadyPath(ctx) {
  try { return JSON.parse(readFileSync(ctx.readyFile, "utf8")).port; } catch { /* removed on stop */ }
  const m = /127\.0\.0\.1:(\d+)/.exec(ctx.logs());
  return m ? Number(m[1]) : null;
}

test("5d-3: during CLEANUP a new upgrade and a connected client's input are deferred, Target.createTarget errors, and all resume at IDLE", async (t) => {
  await withGate(t, { CROW_CDP_CLEANUP_BUDGET_MS: "6000" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    // Slow the cleanup down on both of its load-bearing commands.
    await observer.call("Test.delayReplies", { method: "Target.createTarget", ms: 700 });
    await observer.call("Test.delayReplies", { method: "Page.navigate", ms: 700 });
    void page;

    guard.kill();
    await waitLog(ctx, /gate state CLEANUP/);

    // A new upgrade is accepted, but its first command is answered only after IDLE.
    const late = plainClient(wsUrl, { attach: false });
    await late.opened;
    const lateCall = late.call("Test.echo", { value: "late" }, undefined, 12000);
    await sleep(400);
    assert.equal(late.messages.filter((m) => m.result?.value === "late").length, 0, "a new client's command waits for IDLE");

    // Target.createTarget from any client is answered with an error during CLEANUP.
    const created = await observer.call("Target.createTarget", { url: "about:blank" }, undefined, 2000);
    assert.equal(typeof created.error, "object", `createTarget is refused during CLEANUP: ${JSON.stringify(created)}`);

    // A connected non-gate client's input is held.
    const held = observer.call("Test.echo", { value: "held-in-cleanup" }, undefined, 12000);
    await sleep(400);
    assert.equal(observer.messages.filter((m) => m.result?.value === "held-in-cleanup").length, 0, "a connected client's input is held");

    await waitLog(ctx, /gate state IDLE/, 12000);
    assert.equal((await lateCall).result?.value, "late", "all resume at IDLE (the new client)");
    assert.equal((await held).result?.value, "held-in-cleanup", "all resume at IDLE (the connected client)");
    const after = await observer.call("Target.createTarget", { url: "about:blank" });
    assert.ok(after.result?.targetId, "and createTarget works again");
  });
});

/**
 * A covered page's own request, armed to land in whatever state `trigger` starts, and what the
 * Fetch chain did with it. The fixture slows its own cleanup commands down, so the page is
 * still open when its request fires.
 */
async function pageRequestDuring(t, trigger) {
  let record = null;
  await withGate(t, { CROW_CDP_CLEANUP_BUDGET_MS: "8000" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    void guard;
    await observer.call("Test.delayReplies", { method: "Target.createTarget", ms: 800 });
    await observer.call("Test.delayReplies", { method: "Page.navigate", ms: 800 });
    const url = `https://bot.example/page-request-${randomBytes(3).toString("hex")}`;
    await observer.call("Test.armPageRequest", { targetId: page.targetId, url, ms: 600 });
    await trigger({ ctx, observer });
    record = await waitTrace(ctx, (r) => r.t === "request" && r.url === url, 8000, `the covered page's request ${url}`);
  });
  return record;
}

test("5d-4: in CLEANUP every request fails, a covered page's too — a client's Browser.close and SIGTERM alike (control: the same page's request passes in GUARDED)", async (t) => {
  // (i) the cleanup a client's Browser.close starts. The guard stays connected throughout, so
  // the page is still covered: only the state may fail the request.
  const viaClose = await pageRequestDuring(t, async ({ observer }) => {
    void observer.call("Browser.close").catch(() => null);
  });
  assert.equal(viaClose.outcome, "failed", `a covered page's request during the Browser.close cleanup fails: ${JSON.stringify(viaClose)}`);

  // (ii) the cleanup SIGTERM starts.
  const viaSignal = await pageRequestDuring(t, async ({ ctx }) => { ctx.child.kill("SIGTERM"); });
  assert.equal(viaSignal.outcome, "failed", `a covered page's request during the SIGTERM cleanup fails: ${JSON.stringify(viaSignal)}`);

  // Control: the same page, the same armed request, in GUARDED — it passes.
  const guarded = await pageRequestDuring(t, async ({ ctx }) => { await waitLog(ctx, /gate state GUARDED/); });
  assert.equal(guarded.outcome, "passed", `control: the covered page's request passes in GUARDED: ${JSON.stringify(guarded)}`);
});

// ---------------------------------------------------------------------------------------
// 5e. shutdown paths (the relay in no-flag mode; SIGTERM is the stop that runs cleanup)
// ---------------------------------------------------------------------------------------

test("5e-1: SIGTERM writes Browser.close only after a clean scan (a page that never commits takes the stop path instead)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { guard } = await armedPageAndGuard(ctx, wsUrl);
    void guard;
    ctx.child.kill("SIGTERM");
    const exit = await Promise.race([ctx.exited, sleep(12000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `SIGTERM must finish; log:\n${ctx.logs()}`);
    assert.equal(exit.code, 0, "a clean scan closes the browser and exits 0");

    const trace = ctx.trace();
    const close = trace.findIndex((r) => r.t === "browser-close");
    assert.ok(close >= 0, "Browser.close is written after the clean scan");
    const lastClose = trace.findLastIndex((r) => r.t === "close-target");
    assert.ok(lastClose >= 0 && lastClose < close, "the pages are closed first");
    const scan = trace.findIndex((r, i) => i > lastClose && r.t === "recv" && r.method === "Target.getTargets");
    assert.ok(scan > lastClose && scan < close, "and the verification scan is read between the closes and Browser.close");
  });

  // The stop path: a page that will not commit is never closed, so the browser is killed
  // instead — Browser.close is never written.
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    await observer.call("Test.setCommit", { targetId: page.targetId, commit: false });
    await observer.call("Page.navigate", { url: "https://bot.example/never" }, guard.sessionFor(page.targetId));
    ctx.child.kill("SIGTERM");
    const exit = await Promise.race([ctx.exited, sleep(12000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `the stop path must finish; log:\n${ctx.logs()}`);
    assert.notEqual(exit.code, 0, "the stop path exits non-zero");
    assert.equal(ctx.records("browser-close").length, 0, "and Browser.close is never written");
  });
});

test("5e-2: a client's Browser.close is intercepted, runs the cleanup first and closes only on a clean scan", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, page } = await armedPageAndGuard(ctx, wsUrl);
    await observer.call("Browser.close");
    const exit = await Promise.race([ctx.exited, sleep(12000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `an intercepted Browser.close must finish; log:\n${ctx.logs()}`);

    const trace = ctx.trace();
    const close = trace.findIndex((r) => r.t === "browser-close");
    assert.ok(close >= 0, "the browser is closed in the end");
    const replacement = trace.findIndex((r) => r.t === "create-target" && r.url === "about:blank");
    assert.ok(replacement >= 0 && replacement < close, "the fresh replacement came first");
    const closedBot = trace.findIndex((r) => r.t === "close-target" && r.targetId === page.targetId);
    assert.ok(closedBot >= 0 && closedBot < close, "the bot page was cleaned up before Browser.close");
  });

  // The stop path: a page that will not commit is never closed, so the cleanup that a
  // client's Browser.close runs can never be clean — the browser is stopped instead.
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    await observer.call("Test.setCommit", { targetId: page.targetId, commit: false });
    await observer.call("Page.navigate", { url: "https://bot.example/never-commits" }, guard.sessionFor(page.targetId));
    void observer.call("Browser.close").catch(() => null);
    const exit = await Promise.race([ctx.exited, sleep(12000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `an unclean cleanup must not leave the relay in CLEANUP; log:\n${ctx.logs()}`);
    assert.notEqual(exit.code, 0, "the stop path exits non-zero");
    assert.equal(ctx.records("browser-close").length, 0, "and the client's Browser.close is never written");
    const pid = ctx.pid();
    assert.ok(pid, "the fixture recorded its pid");
    assert.ok(await waitPidGone(pid), "the Chromium process group was SIGKILLed (the fixture's pid is gone)");
  });
});

test("5e-4: a guard client dropping while a Browser.close cleanup is in flight still ends in the stop path when that cleanup is unclean (control: a clean one closes)", async (t) => {
  // Unclean in flight: the bot page will not commit, so the cleanup cannot finish clean.
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    await observer.call("Test.setCommit", { targetId: page.targetId, commit: false });
    await observer.call("Page.navigate", { url: "https://bot.example/never-commits" }, guard.sessionFor(page.targetId));
    void observer.call("Browser.close").catch(() => null);
    await waitLog(ctx, /gate state CLEANUP/);
    // The drop that used to find a cleanup already running and attach no stop path at all.
    guard.kill();
    const exit = await Promise.race([ctx.exited, sleep(12000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `the gate must not stay in CLEANUP after the guard drop; log:\n${ctx.logs()}`);
    assert.notEqual(exit.code, 0, "the stop path exits non-zero");
    assert.equal(ctx.records("browser-close").length, 0, "and Browser.close is never written");
    const pid = ctx.pid();
    assert.ok(pid, "the fixture recorded its pid");
    assert.ok(await waitPidGone(pid), "the Chromium process group was SIGKILLed (the fixture's pid is gone)");
  });

  // Control: the same drop inside a cleanup that IS clean ends in IDLE, and the client's
  // Browser.close is written.
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, guard } = await armedPageAndGuard(ctx, wsUrl);
    // Slow the cleanup so the drop lands inside it.
    await observer.call("Test.delayReplies", { method: "Page.navigate", ms: 400 });
    void observer.call("Browser.close").catch(() => null);
    await waitLog(ctx, /gate state CLEANUP/);
    guard.kill();
    const exit = await Promise.race([ctx.exited, sleep(12000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", `a clean cleanup finishes after the drop; log:\n${ctx.logs()}`);
    assert.equal(exit.code, 0, "control: a clean cleanup takes no stop path");
    assert.equal(ctx.records("browser-close").length, 1, "control: and the client's Browser.close IS written");
  });
});

test("5e-3: a client's Browser.crash passes through to the fixture", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    await observer.call("Browser.crash").catch(() => null);
    await waitTrace(ctx, (r) => r.t === "browser-crash", 6000, "the fixture crashing");
    const exit = await Promise.race([ctx.exited, sleep(8000).then(() => "timeout")]);
    assert.notEqual(exit, "timeout", "the relay does not outlive a crashed browser");
    assert.notEqual(exit.code, 0, "and it exits non-zero");
  });
});

// ---------------------------------------------------------------------------------------
// 5f. the report pipe (fd 5) in --attach mode: `closing` on a graceful close, `kill` on the
//     stop path, never the other way round
// ---------------------------------------------------------------------------------------

/**
 * The relay in `--attach` mode: the shape the supervisor gives it (Chromium's pipe on fds 3
 * and 4, a report pipe on fd 5), with the fixture as this process's own child, so no supervisor
 * and no uid drop are involved. `ctx.report` holds every fd 5 line after the `ready` one.
 */
async function startAttached(t, extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), "crow-gate-attach-"));
  writeFileSync(join(dir, "token"), TOKEN + "\n", { mode: 0o600 });
  let logs = "";
  const ctx = { dir, tracePath: join(dir, "chromium.log"), report: [], readyInfo: null, logs: () => logs };
  const chrome = spawn(process.execPath, [FIXTURE], {
    env: { ...process.env, FAKE_CHROME_LOG: ctx.tracePath, FAKE_EXIT_ON_NO_PAGES: "1", ...extraEnv },
    stdio: ["ignore", "inherit", "inherit", "pipe", "pipe"],
  });
  ctx.chrome = chrome;
  const relay = spawn(process.execPath, [RELAY, "--attach"], {
    env: {
      ...process.env,
      CDP_PORT: "0",
      CROW_CDP_TOKEN_FILE: join(dir, "token"),
      CROW_CDP_DEBUG: "0",
      CROW_CDP_START_DEADLINE_MS: "5000",
      CROW_CDP_CONNECTING_DEADLINE_MS: "4000",
      CROW_CDP_CLEANUP_BUDGET_MS: "4000",
      CROW_CDP_COMMIT_BUDGET_MS: "3000",
      CROW_CDP_SETTLE_MS: "300",
      CROW_CDP_CLOSE_TIMEOUT_MS: "1500",
      ...extraEnv,
    },
    // Chromium's pipe on fds 3 and 4, exactly as the supervisor hands it over.
    stdio: ["ignore", "pipe", "pipe", chrome.stdio[3], chrome.stdio[4], "pipe"],
  });
  ctx.relay = relay;
  relay.stdout.on("data", (d) => { logs += d; });
  relay.stderr.on("data", (d) => { logs += d; });
  let buf = "";
  relay.stdio[5].on("data", (d) => {
    buf += d;
    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).replace(/\r$/, "");
      buf = buf.slice(nl + 1);
      const ready = /^ready (\{.*\})$/.exec(line);
      if (!ctx.readyInfo && ready) { try { ctx.readyInfo = JSON.parse(ready[1]); } catch { /* not the ready line */ } }
      else ctx.report.push(line);
    }
  });
  ctx.exited = new Promise((resolve) => relay.once("exit", (code, signal) => resolve({ code, signal })));
  ctx.trace = () => {
    try { return readFileSync(ctx.tracePath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch { return []; }
  };
  ctx.records = (type) => ctx.trace().filter((r) => r.t === type);
  ctx.pid = () => ctx.records("pid")[0]?.pid ?? null;
  ctx.stop = async () => {
    const pid = ctx.pid();
    if (pid) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
    try { relay.kill("SIGKILL"); } catch { /* gone */ }
    await Promise.race([ctx.exited, sleep(3000)]);
    rmSync(dir, { recursive: true, force: true });
  };
  t.after(ctx.stop);
  return ctx;
}

/** The port the attached relay reports on fd 5. */
async function waitAttachedReady(ctx, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (ctx.readyInfo) return ctx.readyInfo.port;
    if (ctx.relay.exitCode !== null) throw new Error(`the attached relay exited before it was ready:\n${ctx.logs()}`);
    await sleep(25);
  }
  throw new Error(`the attached relay never reported ready on fd 5:\n${ctx.logs()}`);
}

/**
 * Every fd 5 line after the ready one, once the report pipe has ended (the relay is gone). The
 * relay's last line is written on its way out, so reading the fd to its end is what makes the
 * list complete instead of racing the exit.
 */
async function reportLines(ctx, timeoutMs = 5000) {
  const stream = ctx.relay.stdio[5];
  if (!stream.readableEnded && !stream.destroyed) {
    await Promise.race([
      new Promise((resolve) => { stream.once("end", resolve); stream.once("close", resolve); }),
      sleep(timeoutMs),
    ]);
  }
  await sleep(25);
  return ctx.report;
}

test("5f: a clean Browser.close writes `closing` on fd 5 (and no `kill`); the stop path writes `kill` (and no `closing`)", async (t) => {
  // (i) a graceful close: a client's Browser.close is forwarded after a clean scan.
  const ctx = await startAttached(t);
  const version = await request(await waitAttachedReady(ctx), { token: TOKEN });
  assert.equal(version.status, 200, version.raw.slice(0, 200));
  const closer = plainClient(version.json.webSocketDebuggerUrl, { attach: false });
  await closer.armed;
  void closer.call("Browser.close").catch(() => null);
  const exit = await Promise.race([ctx.exited, sleep(12000).then(() => "timeout")]);
  assert.notEqual(exit, "timeout", `the relay exits once the browser has closed; log:\n${ctx.logs()}`);
  assert.equal(exit.code, 0, `a graceful close is not a stop path: ${ctx.logs()}`);
  assert.deepEqual(await reportLines(ctx), ["closing"], `the closing line is the only thing on fd 5 after ready: ${JSON.stringify(ctx.report)}`);
  assert.equal(ctx.records("browser-close").length, 1, "the browser was asked to close once");

  // (ii) the stop path: a gate session lost while its target stays listed is not a close.
  const stopped = await startAttached(t);
  const stoppedVersion = await request(await waitAttachedReady(stopped), { token: TOKEN });
  const observer = plainClient(stoppedVersion.json.webSocketDebuggerUrl, { attach: false });
  await observer.armed;
  const gateSession = gateSessionFor(stopped, "P1", new Set(observer.attached.map((a) => a.sessionId)));
  assert.ok(gateSession, "the gate has its own session on the start page");
  await observer.call("Test.dropSession", { sessionId: gateSession });
  const stopExit = await Promise.race([stopped.exited, sleep(12000).then(() => "timeout")]);
  assert.notEqual(stopExit, "timeout", `the stop path finishes; log:\n${stopped.logs()}`);
  assert.notEqual(stopExit.code, 0, "the stop path is never a clean exit");
  assert.deepEqual(await reportLines(stopped), ["kill"], `the stop path writes the kill line, once, and never the closing line: ${JSON.stringify(stopped.report)}`);
  assert.equal(stopped.records("browser-close").length, 0, "and Browser.close is never written on the stop path");
});

// ---------------------------------------------------------------------------------------
// T-A / T-B: the two shapes a REAL Chromium has and the fixture used to get wrong
// (observed in the real image: the default context id is opaque, and the component-extension
// workers are not in the gate's first target listing). The fixture's DEFAULT is now the real
// shape, so every test above runs against it too.
// ---------------------------------------------------------------------------------------

test("T-A: an opaque default-context id (a real Chromium's) — the gate reaches ready and IDLE, and a cleanup disposes only contexts a bot created", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);

    // The fixture is the real shape now: an opaque default context id, and the default context
    // is NOT one of the `browserContextIds`.
    const state = (await observer.call("Test.state")).result;
    const defaultContextId = state.defaultContextId;
    assert.equal(state.legacyDefaultContext, false, "the fixture's default is the real shape, not the old literal one");
    assert.equal(typeof defaultContextId, "string");
    assert.notEqual(defaultContextId, "default", 'a real default context id is opaque, not the literal "default"');
    assert.deepEqual(
      (await observer.call("Target.getBrowserContexts")).result,
      { browserContextIds: [], defaultBrowserContextId: defaultContextId },
      "exactly what a real Chromium answers at idle",
    );
    for (const info of await liveTargets(observer)) {
      assert.equal(info.browserContextId, defaultContextId, `every target created without a context carries the opaque id (${info.targetId})`);
    }

    // A full cleanup: a bot page, plus a browser context the bot created.
    const { guard, page } = await armedPageAndGuard(ctx, wsUrl);
    const botContext = (await observer.call("Target.createBrowserContext")).result.browserContextId;
    const inBotContext = await observer.call("Target.createTarget", { url: "about:blank", browserContextId: botContext });
    assert.ok(inBotContext.result?.targetId, `a page in the bot's own context: ${JSON.stringify(inBotContext)}`);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill();
    await waitLog(ctx, /gate state CLEANUP/);
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);

    // The default context is never disposed (it is not in `browserContextIds`, and it is not
    // "default" either: it is the id Chromium itself named).
    const disposed = ctx.records("dispose-context").map((r) => r.id);
    assert.deepEqual(disposed, [botContext], `only the context the bot created is disposed: ${JSON.stringify(disposed)}`);
    assert.equal(disposed.includes(defaultContextId), false, "the default context is never disposed");

    // …and the scan that ends the cleanup judged the replacement's opaque id as the default.
    const survivors = (await liveTargets(observer)).filter((info) => info.type === "page");
    assert.equal(survivors.length, 1, `one page is left: ${JSON.stringify(survivors)}`);
    assert.notEqual(survivors[0].targetId, page.targetId, "the surviving page is the fresh replacement, not the bot's page");
    assert.equal(survivors[0].browserContextId, defaultContextId, "and it is in the default context");
  });
});

test("T-A (older build): the literal \"default\" listed in browserContextIds is still the default context — ready, IDLE, and a clean cleanup", async (t) => {
  await withGate(t, { FAKE_CHROME_LEGACY_DEFAULT_CONTEXT: "1" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);

    const state = (await observer.call("Test.state")).result;
    assert.equal(state.legacyDefaultContext, true);
    assert.equal(state.defaultContextId, "default");
    assert.deepEqual(
      (await observer.call("Target.getBrowserContexts")).result,
      { browserContextIds: ["default"] },
      "the older shape: the default context IS listed, and there is no defaultBrowserContextId",
    );

    const { guard } = await armedPageAndGuard(ctx, wsUrl);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill();
    await waitLog(ctx, /gate state CLEANUP/);
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);
    assert.deepEqual(ctx.records("dispose-context").map((r) => r.id), [], "the listed default context is never disposed");
    const pages = (await liveTargets(observer)).filter((info) => info.type === "page");
    assert.equal(pages.length, 1, `one page is left: ${JSON.stringify(pages)}`);
    assert.equal(pages[0].browserContextId, "default", "the replacement is in the default context");
  });
});

test("T-B: component-extension workers that attach AFTER the gate's first listing are exempt — start reaches ready and a cleanup tolerates them (5b-5's after-ready unknown id is still closed)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);

    // (i) The fixture made the one component-extension worker the allow-list pins, and the
    //      relay's first `Target.getTargets` was answered BEFORE it existed — the real browser's
    //      shape, and the reason the first-listing-only rule missed it. It is created on a timer
    //      after that listing, so wait for the fixture to record it: asserting at once would
    //      measure the timer, not the rule.
    await waitTrace(ctx, (r) => r.t === "extension-worker", 4000, "the component-extension worker");
    const workers = ctx.records("extension-worker");
    assert.equal(workers.length, 1, `the one component worker a real Chromium has here: ${JSON.stringify(workers)}`);
    assert.deepEqual(workers.map((r) => r.url), [`chrome-extension://${COMPONENT_EXTENSION_ID}/background.js`]);
    assert.equal(workers.every((r) => r.at !== "start"), true, "it was created after the first listing, not inside it");
    const trace = ctx.trace();
    const firstListing = trace.findIndex((r) => r.t === "recv" && r.method === "Target.getTargets");
    const firstWorker = trace.findIndex((r) => r.t === "extension-worker");
    assert.ok(firstListing >= 0, "the gate listed the targets at start");
    assert.ok(firstWorker > firstListing, "and the worker postdates that listing, as it does in the real browser");

    // (ii) The start reached ready and IDLE anyway, and no component worker was closed.
    const closedAtStart = ctx.records("close-target").map((r) => r.targetId);
    for (const worker of workers) {
      assert.equal(closedAtStart.includes(worker.targetId), false, `a component-extension worker is NOT closed (${worker.url})`);
    }
    const listedNow = await liveTargets(observer);
    for (const worker of workers) {
      assert.ok(listedNow.some((info) => info.targetId === worker.targetId), `…and it is still listed (${worker.url})`);
    }

    // (iii) A cleanup tolerates it: it is not a page, not held, and not closed; the scan after
    //       the cleanup comes back clean and the gate reaches IDLE.
    const { guard, page } = await armedPageAndGuard(ctx, wsUrl);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill();
    await waitLog(ctx, /gate state CLEANUP/);
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);
    const closedAfterCleanup = ctx.records("close-target").map((r) => r.targetId);
    for (const worker of workers) {
      assert.equal(closedAfterCleanup.includes(worker.targetId), false, `a cleanup leaves a component-extension worker alone (${worker.url})`);
    }
    const afterCleanup = (await liveTargets(observer)).filter((info) => info.type === "page");
    assert.equal(afterCleanup.length, 1, `one page is left after the cleanup: ${JSON.stringify(afterCleanup)}`);
    assert.notEqual(afterCleanup[0].targetId, page.targetId, "and it is the fresh replacement");

    // (iv) 5b-5's row, unchanged: a chrome-extension:// worker for an id first seen AFTER the
    //      gate is ready is closed like any other worker.
    const unknown = await observer.call("Test.spawnTarget", { type: "service_worker", url: `chrome-extension://${UNKNOWN_EXTENSION_ID}/background.js` });
    await waitTrace(ctx, (r) => r.t === "close-target" && r.targetId === unknown.result.targetId, 5000, "the after-ready unknown-extension worker's close");
  });
});

// ---------------------------------------------------------------------------------------
// T6: every relay-SYNTHESISED reply echoes the request's sessionId
//
// A real MCP (server/gate-client.js `sendGuardReady`) declares through
// `browser.newBrowserCDPSession()`, i.e. a SECOND browser session of its own, so its
// `Crow.guardReady` carries a `sessionId`. Playwright routes a response WITHOUT one to the
// ROOT session, which has no callback for that id, and its `_CRSession._onMessage` then runs
// `assert(!object.id)` — an uncaught exception that kills the whole MCP process a moment
// after the guard was declared. So a relay-handled reply carries the request's sessionId
// back, exactly as a forwarded reply does, and is stripped only when it is that client's own
// browser session (`S_c`), which is what every forwarded reply on it does too.
// ---------------------------------------------------------------------------------------

test("T6-a: a relay-handled Crow.guardReady reply carries the request's sessionId (a real MCP declares on a browser session of its own)", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const guard = guardClient(wsUrl, { declare: false });
    await guard.armed;

    // Exactly `sendGuardReady`: a browser session of its own first, then the declaration on it.
    const browserSession = await guard.call("Target.attachToBrowserTarget", {});
    const secondSession = browserSession.result?.sessionId;
    assert.ok(secondSession, `the client got a second browser session: ${JSON.stringify(browserSession)}`);

    const reply = await guard.call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH }, secondSession);
    assert.deepEqual(reply.result, {}, `Crow.guardReady still answers {}: ${JSON.stringify(reply)}`);
    assert.equal(reply.error, undefined, "and it is not an error for the intended client");
    assert.equal(
      reply.sessionId,
      secondSession,
      "the reply carries the request's sessionId — a sessionless reply is routed to Playwright's root session, where its _onMessage assertion kills the MCP",
    );
    await waitLog(ctx, /gate state (CONNECTING|GUARDED)/);

    // Control: it was never forwarded — this is a relay-synthesised reply, not Chromium's.
    assert.equal(ctx.records("recv").filter((r) => typeof r.method === "string" && r.method.startsWith("Crow.")).length, 0, "no Crow.* method reached the pipe");
  });
});

test("T6-b: the relay's error replies carry the request's sessionId too — unknown Crow.*, a non-intent declaration, and the forward-time refusals", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    // (i) an unknown `Crow.*` method, sent on a browser session the client holds.
    const guard = guardClient(wsUrl, { declare: false });
    await guard.armed;
    const second = (await guard.call("Target.attachToBrowserTarget", {})).result?.sessionId;
    assert.ok(second, "the guard client got a second browser session");
    const unknown = await guard.call("Crow.somethingElse", { v: 1 }, second);
    assert.equal(typeof unknown.error, "object", `any other Crow.* method is refused: ${JSON.stringify(unknown)}`);
    assert.equal(unknown.sessionId, second, "the method-not-found reply carries the request's sessionId");

    // (ii) a NON-intent client's declaration, on a browser session of its own.
    const plain = plainClient(wsUrl, { attach: false });
    await plain.armed;
    const plainSecond = (await plain.call("Target.attachToBrowserTarget", {})).result?.sessionId;
    assert.ok(plainSecond, "the plain client got a second browser session");
    const refused = await plain.call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH }, plainSecond);
    assert.equal(typeof refused.error, "object", `a non-intent client may not declare: ${JSON.stringify(refused)}`);
    assert.equal(refused.sessionId, plainSecond, "the refusal carries the request's sessionId");

    // (iii) The forward-time refusals: the same rule, on a page session the client holds.
    const page = await makePage(plain, "https://bot.example/t6-refusals");
    const sessionId = page.sessionId;
    const refusals = [
      ["Target.createTarget", { url: "https://private.example/" }],
      ["Target.sendMessageToTarget", { sessionId, message: JSON.stringify({ id: 1, method: "Target.createTarget", params: {} }) }],
      ["Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: false }],
    ];
    for (const [method, params] of refusals) {
      const reply = await plain.call(method, params, sessionId);
      assert.equal(typeof reply.error, "object", `${method} is refused: ${JSON.stringify(reply)}`);
      assert.equal(reply.sessionId, sessionId, `${method}'s refusal carries the request's sessionId`);
    }

    // …and a command naming a session the client does not own.
    const notOwned = await plain.call("Test.echo", { value: `t6-guess-${randomBytes(3).toString("hex")}` }, "S1");
    assert.equal(notOwned.error?.code, -32001, `a session the client does not own is refused: ${JSON.stringify(notOwned)}`);
    assert.equal(notOwned.sessionId, "S1", "the -32001 reply carries the sessionId the request named");

    // Control: the client's OWN browser session is stripped, as every forwarded reply on it is.
    const own = await sessionIdOf(ctx, (() => {
      const marker = `t6-own-${randomBytes(3).toString("hex")}`;
      void plain.call("Test.echo", { value: marker });
      return marker;
    })());
    assert.ok(own, "the client's own browser session, as the fixture saw it");
    const onOwn = await plain.call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: false }, own);
    assert.equal(typeof onOwn.error, "object", `the non-flat auto-attach is refused: ${JSON.stringify(onOwn)}`);
    assert.equal(onOwn.sessionId, undefined, "a reply on the client's own S_c is stripped, exactly as a forwarded reply is");

    assert.equal(ctx.records("recv").filter((r) => typeof r.method === "string" && r.method.startsWith("Crow.")).length, 0, "no Crow.* method ever reached the pipe");
  });
});

// ---------------------------------------------------------------------------------------
// S7: a component-extension worker that is LISTED but never ATTACHED (Chromium 145)
//
// Chromium 145.0.7632.6 (Playwright 1.58.2's chromium-1208) LISTS
// `service_worker chrome-extension://<component id>/thunk.js` in `Target.getTargets` and never
// sends the gate's browser auto-attacher an `attachedToTarget` for it, so the attach path — the
// only place an exemption used to be granted — never sees it. The gate now also records the
// allow-listed id from its OWN listings while `!gateReady`. Two different things follow, and
// they are not the same rule:
//  - an extension worker off the allow-list fails the start closed, with one log line naming
//    the id (S7-2b);
//  - any other non-page target at start is simply not exempt: it is neutralised the way every
//    other pre-existing target is, i.e. the start's own cleanup closes it (S7-2).
// The fixture models the shape with `FAKE_CHROME_LISTED_ONLY_TARGETS` (a target in every
// listing, never announced).
//
// The exemption is a targetId RECORDED BEFORE `gateReady`, and nothing else — never an origin,
// and never a `shared_worker`: S7-5 shows that a worker at an allow-listed id first seen after
// ready is closed anyway, and S7-6 shows that a shared worker at that id is not exempt at all
// (listed at start, or attached before ready).
// ---------------------------------------------------------------------------------------

/** The env a listed-only target needs: the attach-late default workers would only add noise. */
const listedOnly = (entry) => ({ FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_LISTED_ONLY_TARGETS: entry });

/**
 * A start that must fail closed: the relay exits non-zero, writes no ready file, and says so on
 * the start sequence's own line. The wait is bounded, so a start that hangs fails here too.
 */
async function startFailed(ctx) {
  const exit = await Promise.race([ctx.exited, sleep(12000).then(() => "timeout")]);
  assert.notEqual(exit, "timeout", `the start has to fail instead of serving; its log was:\n${ctx.logs()}`);
  assert.notEqual(exit.code, 0, `the relay exits non-zero (the container recycles): ${ctx.logs()}`);
  assert.equal(existsSync(ctx.readyFile), false, "no ready file for a start that failed");
  assert.match(ctx.logs(), /the start sequence failed/, `the start sequence's own line is what says it: ${ctx.logs()}`);
}

test("S7-1 + S7-3: a listed-only allow-listed worker is exempt — start reaches IDLE, it is never closed, a cleanup leaves it — while one appearing after ready is still closed", async (t) => {
  await withGate(t, listedOnly(`service_worker|chrome-extension://${COMPONENT_EXTENSION_ID}/thunk.js`), async ({ ctx, wsUrl }) => {
    const listed = await waitTrace(ctx, (r) => r.t === "listed-only-target", 4000, "the listed-only component worker");
    assert.equal(listed.type, "service_worker");
    assert.equal(listed.url, `chrome-extension://${COMPONENT_EXTENSION_ID}/thunk.js`);
    // The start reached ready and IDLE with it in the browser's own listing (withGate waited for
    // both ends of that: the ready line and the gate's state).
    await waitLog(ctx, /gate state IDLE/);

    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    await sleep(200);
    assert.equal(
      ctx.records("close-target").some((r) => r.targetId === listed.targetId),
      false,
      "a component-extension worker the browser only LISTED is never closed",
    );
    assert.ok((await liveTargets(observer)).some((info) => info.targetId === listed.targetId), "…and it is still listed");
    // …and the start JUDGED that state clean instead of neutralising it: no replacement page was
    // ever created (a start that had to neutralise would create one first).
    assert.equal(ctx.records("create-target").length, 0, "the start tolerated the listing; it did not run a cleanup");

    // (S7-3) A worker that appears AFTER ready, at an id nothing allow-lists, is closed as any
    // other worker is: the listing exemption is a start-time fact and nothing more.
    const late = await observer.call("Test.spawnTarget", { type: "service_worker", url: "chrome-extension://zzz/background.js" });
    await waitTrace(ctx, (r) => r.t === "close-target" && r.targetId === late.result.targetId, 5000, "the after-ready extension worker's close");

    // A guard connect and its drop run a full cleanup: replacement page first, the bot's page
    // closed after its commit, the browser context handled — and the listed-only worker left
    // exactly where it was (it has no gate record at all).
    const { guard, page } = await armedPageAndGuard(ctx, wsUrl);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill();
    await waitLog(ctx, /gate state CLEANUP/);
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);

    assert.equal(
      ctx.records("close-target").some((r) => r.targetId === listed.targetId),
      false,
      "the cleanup does not close the listed-only component-extension worker either",
    );
    assert.ok((await liveTargets(observer)).some((info) => info.targetId === listed.targetId), "it is still listed after the cleanup");
    const pages = (await liveTargets(observer)).filter((info) => info.type === "page");
    assert.equal(pages.length, 1, `exactly one page is left: ${JSON.stringify(pages)}`);
    assert.notEqual(pages[0].targetId, page.targetId, "and it is the fresh replacement, not the bot's page");
  });
});

test("S7-2b: an extension worker off the component allow-list fails the start closed, listed or attached before ready", async (t) => {
  const line = `unknown extension worker at start, not on the component allow-list: ${UNKNOWN_EXTENSION_ID}`;

  // (i) listed only, never attached: the listing path is the one that has to see it.
  const listedCtx = await startRelay(t, listedOnly(`service_worker|chrome-extension://${UNKNOWN_EXTENSION_ID}/x.js`));
  await startFailed(listedCtx);
  assert.ok(listedCtx.logs().includes(line), `one line names the id, so a Chromium upgrade that changed it is visible: ${listedCtx.logs()}`);
  assert.equal(listedCtx.records("close-target").length, 0, "the start stops on the id instead of closing it and serving afterwards");

  // (ii) the same id arriving by an ATTACH event before ready (the fixture's delayed workers).
  const attachedCtx = await startRelay(t, { FAKE_CHROME_EXTENSION_WORKERS: UNKNOWN_EXTENSION_ID });
  await startFailed(attachedCtx);
  assert.ok(attachedCtx.logs().includes(line), `the attach path logs the same line: ${attachedCtx.logs()}`);
  assert.equal(
    attachedCtx.logs().split("\n").filter((l) => l.includes(`component allow-list: ${UNKNOWN_EXTENSION_ID}`)).length,
    1,
    "ONE distinct line per unknown id, never two for the same id",
  );
});

test("S7-2: a listed-only target that is not the exempt component-extension worker is NOT exempt — the start's cleanup closes it", async (t) => {
  const cases = [
    ["a service worker at a non-extension url", "service_worker|https://example.test/sw.js"],
    ["the allow-listed id at the wrong target type", `worker|chrome-extension://${COMPONENT_EXTENSION_ID}/w.js`],
    ["a look-alike scheme", `service_worker|chrome-extension-fake://${COMPONENT_EXTENSION_ID}/x.js`],
  ];
  for (const [label, entry] of cases) {
    // withGate waits for the ready file and the gate's own IDLE, so a start that had to
    // neutralise this target DID reach ready afterwards: this row is about the close, not
    // about a start failure.
    await withGate(t, listedOnly(entry), async ({ ctx, wsUrl }) => {
      const listed = await waitTrace(ctx, (r) => r.t === "listed-only-target", 4000, `the listed-only target (${label})`);
      assert.equal(listed.url, entry.slice(entry.indexOf("|") + 1), `${label}: the fixture listed the target the env asked for`);

      // NOT tolerated as exempt: the start's cleanup closed it.
      const closed = await waitTrace(
        ctx,
        (r) => r.t === "close-target" && r.targetId === listed.targetId,
        8000,
        `the close of ${listed.targetId} (${label})`,
      );
      assert.equal(closed.type, listed.type, `${label}: the target the listing named is the one that was closed`);

      // …and that close came from the START's own cleanup (a replacement page first), not from
      // a 5b-style after-ready rule: the target existed before the gate was ready.
      const trace = ctx.trace();
      const replacement = trace.findIndex((r) => r.t === "create-target");
      const closeAt = trace.findIndex((r) => r.t === "close-target" && r.targetId === listed.targetId);
      assert.ok(replacement >= 0 && replacement < closeAt, `${label}: the close follows the start's replacement page, so it is the neutralisation`);
      assert.doesNotMatch(ctx.logs(), /the start sequence failed/, `${label}: a listed target that is not exempt does not fail the start`);
      assert.equal(ctx.child.exitCode, null, `${label}: the relay is still serving`);

      // The fixture drops a closed target from its listing (what a real browser does).
      const observer = plainClient(wsUrl, { attach: false });
      await observer.armed;
      assert.equal(
        (await liveTargets(observer)).some((info) => info.targetId === listed.targetId),
        false,
        `${label}: the closed target is gone from the listing`,
      );
    });
  }
});

test("S7-4: a listed-only worker is never handed to a client — no attach event, and an explicit attach is refused", async (t) => {
  await withGate(t, listedOnly(`service_worker|chrome-extension://${COMPONENT_EXTENSION_ID}/thunk.js`), async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);
    const listed = await waitTrace(ctx, (r) => r.t === "listed-only-target", 4000, "the listed-only component worker");
    await sleep(400);
    assert.equal(
      observer.attached.filter((a) => a.targetId === listed.targetId).length,
      0,
      "a client never sees an attach event for a worker the browser never announced",
    );
    const refused = await observer.call("Target.attachToTarget", { targetId: listed.targetId, flatten: true });
    assert.equal(typeof refused.error, "object", `an explicit attach to it is refused: ${JSON.stringify(refused)}`);
    assert.equal(
      ctx.records("recv").filter((r) => r.method === "Target.attachToTarget" && r.params?.targetId === listed.targetId).length,
      0,
      "and it never reached the fixture",
    );
  });
});

test("S7-5: a worker at an allow-listed id first appearing AFTER ready is closed and never resumed — the exemption is a recorded targetId, never an origin", async (t) => {
  await withGate(t, listedOnly(`service_worker|chrome-extension://${COMPONENT_EXTENSION_ID}/thunk.js`), async ({ ctx, wsUrl }) => {
    const listed = await waitTrace(ctx, (r) => r.t === "listed-only-target", 4000, "the listed-only component worker");
    const observer = plainClient(wsUrl, { attach: true, hook: false });
    await observer.armed;
    await waitLog(ctx, /gate state IDLE/);

    // The start-time worker is exempt (the S7-1 shape), which is also the positive control:
    // a relay that exempted nothing would satisfy the negatives below for the wrong reason.
    await sleep(200);
    assert.equal(
      ctx.records("close-target").some((r) => r.targetId === listed.targetId),
      false,
      "control: the exempt start-time worker is not closed",
    );
    assert.ok((await liveTargets(observer)).some((info) => info.targetId === listed.targetId), "control: …and it is still listed");

    for (const [label, type, path] of [
      ["a second service worker", "service_worker", "background.js"],
      ["a new shared worker", "shared_worker", "shared.js"],
    ]) {
      const spawned = await observer.call("Test.spawnTarget", { type, url: `chrome-extension://${COMPONENT_EXTENSION_ID}/${path}` });
      const targetId = spawned.result.targetId;
      assert.notEqual(targetId, listed.targetId, `${label}: the fixture made a NEW targetId at the same allow-listed id`);
      await waitTrace(ctx, (r) => r.t === "close-target" && r.targetId === targetId, 6000, `the close of ${label} (${targetId})`);
      assert.equal(ctx.records("resumed").some((r) => r.targetId === targetId), false, `${label}: never resumed`);
      assert.equal(observer.attached.filter((a) => a.targetId === targetId).length, 0, `${label}: and no client is handed its attach event`);
      assert.equal((await liveTargets(observer)).some((info) => info.targetId === targetId), false, `${label}: the closed target is gone from the listing`);
    }

    // Closing the later ones changes nothing about the recorded one.
    assert.equal(
      ctx.records("close-target").some((r) => r.targetId === listed.targetId),
      false,
      "the recorded start-time worker is still exempt after the later workers were closed",
    );
    assert.ok((await liveTargets(observer)).some((info) => info.targetId === listed.targetId), "…and still listed");
  });
});

test("S7-6: a shared_worker at an allow-listed id is NOT exempt — listed at start, or attached before ready", async (t) => {
  // (i) LISTED at start. The listing records nothing for a shared worker (the exemption is a
  // service worker's alone), so the start's own cleanup closes it exactly as S7-2's rule says:
  // replacement page first, then the close.
  await withGate(t, listedOnly(`shared_worker|chrome-extension://${COMPONENT_EXTENSION_ID}/shared.js`), async ({ ctx, wsUrl }) => {
    const listed = await waitTrace(ctx, (r) => r.t === "listed-only-target", 4000, "the listed-only shared worker");
    assert.equal(listed.type, "shared_worker", "the fixture listed a shared_worker at the allow-listed id");
    const closed = await waitTrace(
      ctx,
      (r) => r.t === "close-target" && r.targetId === listed.targetId,
      8000,
      `the close of ${listed.targetId}`,
    );
    assert.equal(closed.type, "shared_worker", "the target the listing named is the one that was closed");
    const trace = ctx.trace();
    const replacement = trace.findIndex((r) => r.t === "create-target");
    const closeAt = trace.findIndex((r) => r.t === "close-target" && r.targetId === listed.targetId);
    assert.ok(replacement >= 0 && replacement < closeAt, "the close follows the start's replacement page, so it is the neutralisation");
    assert.equal(ctx.records("resumed").some((r) => r.targetId === listed.targetId), false, "it is never resumed");
    assert.doesNotMatch(ctx.logs(), /the start sequence failed/, "a shared worker is closed, not judged as an unknown extension id");
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    assert.equal(
      (await liveTargets(observer)).some((info) => info.targetId === listed.targetId),
      false,
      "the closed target is gone from the listing",
    );
  });

  // (ii) ATTACHED before ready: the fixture's component worker, created as a shared_worker a
  // moment after the gate's first listing (the T-B shape). The attach path does not record it
  // either, so it is closed instead of tolerated.
  await withGate(
    t,
    { FAKE_CHROME_EXTENSION_WORKERS: COMPONENT_EXTENSION_ID, FAKE_CHROME_EXTENSION_WORKER_TYPE: "shared_worker" },
    async ({ ctx, wsUrl }) => {
      const worker = await waitTrace(ctx, (r) => r.t === "extension-worker", 4000, "the component shared worker");
      assert.equal(worker.type, "shared_worker", "the fixture made the component worker as a shared_worker");
      assert.equal(worker.at === "start", false, "it attached after the gate's first listing, as a real browser's workers do");
      await waitTrace(ctx, (r) => r.t === "close-target" && r.targetId === worker.targetId, 8000, `the close of ${worker.targetId}`);
      assert.equal(
        ctx.records("resumed").some((r) => r.targetId === worker.targetId),
        false,
        "a shared worker at an allow-listed id is never resumed",
      );
      assert.doesNotMatch(ctx.logs(), /the start sequence failed/, "…and it does not fail the start either: it is simply not exempt");
      const observer = plainClient(wsUrl, { attach: true, hook: false });
      await observer.armed;
      await sleep(300);
      assert.equal(
        observer.attached.filter((a) => a.targetId === worker.targetId).length,
        0,
        "no client is handed its attach event",
      );
      assert.equal(
        (await liveTargets(observer)).some((info) => info.targetId === worker.targetId),
        false,
        "and it is gone from the listing",
      );
    },
  );
});