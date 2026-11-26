/**
 * The relay must fail EVERY request while a container stop is closing Chromium (RED tests).
 *
 * The bug these tests are about: on SIGTERM (a `docker stop`) the relay's `shutdown()` runs the
 * cleanup, the cleanup ENDS by entering gate state IDLE (every request passes), and only THEN is
 * `Browser.close` written. A real Chromium keeps running its pages between that and its own exit
 * — pagehide beacons, image requests — so those requests LEAK: they pass a gate that has already
 * declared itself open. The intended fix: on the shutdown path (SIGTERM, and a client's
 * `Browser.close`) the gate stays in CLEANUP (every request FAILS) until the browser has exited;
 * IDLE is never entered on that path. A normal guard-drop cleanup that is NOT followed by a close
 * still ends in IDLE (the control below).
 *
 * What makes a request visible in the close window is the fixture knob
 * `FAKE_CHROME_CLOSE_HANDLE_DELAY_MS`: on `Browser.close` the fake traces the close and answers
 * as it always did, but it does not exit (and does not close fd 4) for that many ms, so its
 * `Test.armPageRequest` timers keep firing and the relay's answers to the requests they make
 * still arrive. The relay cannot arm anything in that window itself — a client's input is
 * DEFERRED once CLEANUP starts — so the requests are armed before the stop is triggered, as a
 * burst over a span that covers it, on every page id that could be live when they fire: the
 * pages that exist now, and the ids the cleanup's own replacement page can take (the replacement
 * does not exist yet, and `Test.armPageRequest` resolves its targetId when the timer fires, so an
 * id that never becomes a page is a harmless `closed` record).
 *
 * Everything here drives the real relay (bundles/browser/cdp-relay.mjs, no-flag mode) against
 * tests/fixtures/fake-chromium-gate.mjs. The helpers are copies of the ones in
 * tests/browser-relay-gate.test.js (as tests/browser-relay-gate-ordering.test.js does it): the
 * two files must stay independent.
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
  const dir = mkdtempSync(join(tmpdir(), "crow-gate-stop-"));
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
 * The lines the relay logged AFTER the (already + 1)-th `gate state CLEANUP` line — the cleanup
 * this test triggered — or null when that line never came. Read from the whole log once the
 * process has exited, so "no later IDLE" is about the run, not about a race with a poll.
 */
function stateLinesAfterCleanup(logs, already) {
  const lines = logs.split("\n");
  let seen = 0;
  for (let i = 0; i < lines.length; i++) {
    if (!/gate state CLEANUP/.test(lines[i])) continue;
    seen++;
    if (seen > already) return lines.slice(i + 1);
  }
  return null;
}

/**
 * The gate is up. Three independent pieces of evidence, because each one alone has been
 * satisfied by an accident before: the ready line, the field in `/json/version`, and the gate's
 * own browser session being the FIRST one the fixture ever handed out.
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

/** The relay exited (asserting it did not hang). */
async function waitExit(ctx, timeoutMs = 15000) {
  const exit = await Promise.race([ctx.exited, sleep(timeoutMs).then(() => "timeout")]);
  assert.notEqual(exit, "timeout", `the relay must finish; its log was:\n${ctx.logs()}`);
  // The exit event can land a moment before the last stdout chunk is read.
  await sleep(150);
  return exit;
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
  const markerWorldName = typeof opts.markerWorldName === "string" ? opts.markerWorldName : undefined;
  const utilityScript = opts.utilityScript !== false;
  const declare = opts.declare !== false;
  const hookDelayMs = Number(opts.hookDelayMs || 0);

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
    // Playwright's order: resume first, hook afterwards.
    await call("Runtime.runIfWaitingForDebugger", {}, sessionId).catch(() => null);
    if (nest) await call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sessionId).catch(() => null);
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
    send,
    call,
    hookSession,
    of: (method) => events.filter((m) => m.method === method),
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
          reject(new Error(`timed out waiting for ${label}`));
        }, timeoutMs);
        const entry = {
          pred,
          resolve: (m) => { clearTimeout(timer); resolve(m); },
        };
        waiters.push(entry);
      });
    },
    sessionFor: (targetId) => attached.filter((a) => a.targetId === targetId).at(-1)?.sessionId ?? null,
    close() { try { ws.close(); } catch { /* gone */ } },
    /** A SIGKILLed MCP: the socket goes without a close frame. */
    kill() { try { ws.terminate(); } catch { try { ws._socket?.destroy(); } catch { /* gone */ } } },
  };

  const armed = (async () => {
    await opened;
    if (attach) await call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }).catch(() => null);
    if (header && declare) {
      c.declareReply = await call("Crow.guardReady", { v: 1, exceptionsHash: EXCEPTIONS_HASH }).catch(() => null);
    }
  })();
  c.armed = armed;
  return c;
}

const plainClient = (wsUrl, opts = {}) => client(wsUrl, { header: false, ...opts });
const guardClient = (wsUrl, opts = {}) => client(wsUrl, { header: true, ...opts });

// ---------------------------------------------------------------------------------------
// pages, requests, and the fixture's own trace
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

/** One request from a page, as the fixture's Fetch chain sees it: passed, failed, held or closed. */
async function probe(c, targetId, url = "https://bot.example/probe", timeoutMs = 5000) {
  const reply = await c.call("Test.request", { targetId, url }, undefined, timeoutMs);
  if (reply.result) return reply.result;
  return { outcome: `error:${reply.error?.message ?? "no reply"}`, via: [] };
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

/** A live bot page plus its guard, and a plain observer that outlives the cleanup. */
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

/**
 * The page ids a request could land on inside the stop: the pages that exist now, plus the ids
 * the cleanup's own replacement page can take. The replacement does not exist yet and cannot be
 * named any other way; `Test.armPageRequest` resolves its targetId when the timer fires, so an
 * id that never becomes a page (or one of a closed page) is a harmless `closed` record, and the
 * id that becomes the replacement is the request that matters. The fixture's own target ids end
 * in a running number (`P1`, `P2`, …), so the next page id continues the highest one listed.
 */
async function candidatePageIds(observer) {
  const state = (await observer.call("Test.state")).result;
  const targets = state?.targets ?? [];
  const ids = new Set(targets.filter((t) => t.type === "page").map((t) => t.id));
  let highest = 0;
  for (const target of targets) {
    const m = /^[A-Z]+(\d+)$/.exec(String(target.id));
    if (m) highest = Math.max(highest, Number(m[1]));
  }
  for (let i = 1; i <= 4; i++) ids.add(`P${highest + i}`);
  return [...ids];
}

/** One `Test.armPageRequest` may be armed at most this far ahead: the fixture's own cap. */
const ARM_CAP_MS = 5000;
/** How far apart the burst's waves are sent — and so how much later than the first arm the stop is. */
const ARM_WAVE_OFFSET_MS = 500;

/**
 * Arm a page request on every candidate id, `ms` from now, over a span that covers the whole
 * stop: the fixture's own timers fire them whatever the relay is doing, which is how a request
 * lands between `Browser.close` and Chromium's exit. Everything goes out BEFORE the stop is
 * triggered (the caller triggers it when this returns) — once CLEANUP starts the relay defers a
 * client's input, so nothing more can be armed in that window.
 *
 * The span has to cover a SLOW stop too: the cleanup's own budget (4000 ms here) plus its settle
 * (300 ms) plus the fixture's close delay, which is why it is about 5500 ms. One arm cannot
 * reach that far — the fixture caps `ms` at ARM_CAP_MS — so the burst is armed in WAVES: each
 * wave is armed from ITS OWN send time, and the waves are ARM_WAVE_OFFSET_MS apart. The last
 * wave is what the caller's stop runs inside, so its arms are the ones that have to reach past
 * the close; the earlier ones only overlap it.
 */
async function armPageRequestBurst(observer, ctx, ids, { url, until = 5500, step = 25 } = {}) {
  const armedRequests = () => ctx.records("recv").filter((r) => r.method === "Test.armPageRequest").length;
  const before = armedRequests();
  let sent = 0;
  for (let base = 0; ; base += ARM_WAVE_OFFSET_MS) {
    const span = Math.min(ARM_CAP_MS, until - base);
    for (let ms = 0; ms <= span; ms += step) {
      for (const targetId of ids) {
        observer.send("Test.armPageRequest", { targetId, url: `${url}#${targetId}@${base + ms}`, ms });
        sent++;
      }
    }
    if (base + span >= until) break;
    await sleep(ARM_WAVE_OFFSET_MS);
  }
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (armedRequests() >= before + sent) return sent;
    await sleep(100);
  }
  assert.fail(`the fixture armed ${armedRequests() - before} of the ${sent} requested page requests`);
}

/**
 * The index of the last `recv` the fixture recorded for a client's `Test.echo` marker: the
 * place in the trace a test pinned with a command it sent itself.
 */
function markerIndex(trace, marker) {
  return trace.findLastIndex((r) => r.t === "recv" && r.method === "Test.echo" && r.params?.value === marker);
}

/** Every `t: "request"` record the fixture wrote after the `Browser.close` record. */
function requestsAfterBrowserClose(trace) {
  const at = trace.findIndex((r) => r.t === "browser-close");
  assert.ok(at >= 0, "Browser.close reached the fixture");
  return trace.slice(at + 1).filter((r) => r.t === "request");
}

/**
 * The requests that landed after `Browser.close` may only ever have been stopped: `failed` for a
 * page the gate is in front of, `held` for a target nothing resumed, `closed` for one the
 * cleanup already closed. `passed` is the leak this file is about.
 */
function assertNonePassedAfterBrowserClose(trace) {
  const after = requestsAfterBrowserClose(trace);
  assert.ok(after.length > 0, "the armed burst landed at least one request after Browser.close");
  for (const record of after) {
    assert.ok(
      record.outcome === "failed" || record.outcome === "closed" || record.outcome === "held",
      `a request after Browser.close may never pass: ${JSON.stringify(record)}`,
    );
  }
  assert.ok(
    after.some((record) => record.outcome === "failed"),
    `at least one request after Browser.close was FAILED by the gate, not merely closed: ${JSON.stringify(after.slice(0, 6))}`,
  );
}

/**
 * No gate state but CLEANUP may follow the CLEANUP this stop started, up to the relay's exit:
 * the gate re-opening (IDLE, GUARDED or CONNECTING) is what lets a page's pagehide traffic out
 * while the browser is still closing.
 */
function assertStayedInCleanup(ctx, cleanupsBefore) {
  const after = stateLinesAfterCleanup(ctx.logs(), cleanupsBefore);
  assert.ok(after, `the relay announced CLEANUP for this stop; its log was:\n${ctx.logs()}`);
  const reopened = after.filter((line) => /gate state (IDLE|GUARDED|CONNECTING)/.test(line));
  assert.deepEqual(reopened, [], `the gate may not leave CLEANUP while the browser is closing: ${JSON.stringify(reopened)}`);
}

// ---------------------------------------------------------------------------------------
// 1 & 2 — the container stop (SIGTERM)
// ---------------------------------------------------------------------------------------

test("1: SIGTERM — a page request that lands in the close window is stopped, not passed (exit 0, one Browser.close)", async (t) => {
  // The fixture keeps serving for 600 ms after `Browser.close`: the close window a real
  // Chromium has while it commits its cookie store and its pages run their last requests.
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const { observer, page } = await armedPageAndGuard(ctx, wsUrl);
    const ids = await candidatePageIds(observer);
    const marker = `sigterm-${Date.now()}`;
    await armPageRequestBurst(observer, ctx, ids, { url: `https://bot.example/${marker}` });

    ctx.child.kill("SIGTERM");
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a clean scan closes the browser and exits 0; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");

    const trace = ctx.trace();
    // The bot page really was the thing the cleanup took away, so the requests after the close
    // are about the page the cleanup left (the fresh replacement).
    assert.equal(trace.some((r) => r.t === "close-target" && r.targetId === page.targetId), true, "the cleanup closed the bot page");
    assertNonePassedAfterBrowserClose(trace);
  });
});

test("2: SIGTERM — the gate stays in CLEANUP from the stop to the relay's exit", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    await armedPageAndGuard(ctx, wsUrl);
    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    ctx.child.kill("SIGTERM");
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a clean scan closes the browser and exits 0; its log was:\n${ctx.logs()}`);
    assertStayedInCleanup(ctx, cleanupsBefore);
  });
});

// ---------------------------------------------------------------------------------------
// 3 — the same stop, started by a client's Browser.close
// ---------------------------------------------------------------------------------------

test("3: a client's Browser.close — the close window is CLEANUP too, and the gate never leaves it", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const { observer, page } = await armedPageAndGuard(ctx, wsUrl);
    const ids = await candidatePageIds(observer);
    const marker = `client-close-${Date.now()}`;
    await armPageRequestBurst(observer, ctx, ids, { url: `https://bot.example/${marker}` });

    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    void observer.call("Browser.close").catch(() => null);
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a clean scan closes the browser and exits 0; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");

    const trace = ctx.trace();
    assert.equal(trace.some((r) => r.t === "close-target" && r.targetId === page.targetId), true, "the cleanup closed the bot page");
    assertNonePassedAfterBrowserClose(trace);
    assertStayedInCleanup(ctx, cleanupsBefore);
  });
});

// ---------------------------------------------------------------------------------------
// 4 — the control: a guard drop with NO close still ends in IDLE
// ---------------------------------------------------------------------------------------

test("4: control — a guard dropping with no close ends in IDLE, the replacement passes, and Browser.close is never written", async (t) => {
  await withGate(t, {}, async ({ ctx, wsUrl }) => {
    const { observer, guard } = await armedPageAndGuard(ctx, wsUrl);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    guard.kill(); // no close frame: a SIGKILLed MCP
    await waitLog(ctx, /gate state CLEANUP/);
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);

    const replacement = ctx.records("create-target").at(-1)?.targetId;
    assert.ok(replacement, "the cleanup created the replacement page");
    const outcome = await probe(observer, replacement, "https://bot.example/after-idle");
    assert.equal(outcome.outcome, "passed", `control: IDLE passes again: ${JSON.stringify(outcome)}`);
    assert.equal(ctx.records("browser-close").length, 0, "and this path writes no Browser.close");
  });
});

// ---------------------------------------------------------------------------------------
// 6 & 7 — a client's Browser.close racing the stop path
//
// The close decision is ONE boolean the relay sets before a cleanup (`closeAfterCleanup`), and
// two DIFFERENT triggers set it: the stop path's SIGTERM, and a client's `Browser.close`. The
// client path also has a reason to undo it — its asker has gone, so no close will be written and
// nothing else would end the CLEANUP it started. If a SIGTERM joined that same cleanup, undoing
// it hands the gate to IDLE while the stop path is still about to write `Browser.close`: every
// request passes from there on. Test 6 is that race; test 7 is the one legitimate re-open it
// must not take away (a close whose asker is gone, with no stop path involved).
//
// Both make the cleanup long enough to act inside it (`Test.delayReplies` on `Page.navigate`,
// 400 ms per live page), so the client's socket is gone — `client.closed` is true — before the
// cleanup ends.
// ---------------------------------------------------------------------------------------

test("6: race — a SIGTERM joining a client's Browser.close keeps the gate in CLEANUP and stops the page traffic", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const { observer, page } = await armedPageAndGuard(ctx, wsUrl);
    // A cleanup long enough that the socket can go and a SIGTERM can join it: every live page's
    // `Page.navigate` is answered 400 ms late.
    await observer.call("Test.delayReplies", { method: "Page.navigate", ms: 400 });
    const ids = await candidatePageIds(observer);
    const marker = `race-${Date.now()}`;
    await armPageRequestBurst(observer, ctx, ids, { url: `https://bot.example/${marker}` });

    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    // The client asks for the close (the reply never comes: `Browser.close` is relay-handled),
    // then goes away, so `client.closed` is true when the cleanup ends.
    void observer.call("Browser.close").catch(() => null);
    await waitLogAfter(ctx, /gate state CLEANUP/, cleanupsBefore);
    observer.kill();
    // The relay observes the drop while the cleanup is still running, and THEN the container-
    // stop joins that same cleanup run.
    await sleep(100);
    ctx.child.kill("SIGTERM");

    await waitExit(ctx);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");

    const trace = ctx.trace();
    assert.equal(trace.some((r) => r.t === "close-target" && r.targetId === page.targetId), true, "the cleanup closed the bot page");
    // The requests that landed after `Browser.close` are all stopped, none passed (the gate
    // re-opening is what lets pagehide traffic out while the browser still runs).
    assertNonePassedAfterBrowserClose(trace);
    // …and the gate never left CLEANUP: the client path may not undo the stop path's decision.
    assertStayedInCleanup(ctx, cleanupsBefore);
  });
});

test("7: control — a client's Browser.close whose asker is gone re-opens the gate and writes no Browser.close", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    await observer.call("Test.delayReplies", { method: "Page.navigate", ms: 400 });
    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    void observer.call("Browser.close").catch(() => null);
    await waitLogAfter(ctx, /gate state CLEANUP/, cleanupsBefore);
    observer.kill();

    // The scan ended clean but nobody is left to ask Chromium to close: no `Browser.close` goes
    // out, so this is the ONE path that must re-open the gate — otherwise it would stay CLEANUP
    // (every request failed) for the rest of the relay's life.
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);
    assert.equal(ctx.records("browser-close").length, 0, "no Browser.close is written for an asker that is gone");
    assert.equal(ctx.records("close-target").some((r) => r.targetId === page.targetId), true, "the cleanup still closed the bot page");

    const replacement = ctx.records("create-target").at(-1)?.targetId;
    assert.ok(replacement, "the cleanup created the replacement page");
    const outcome = await waitCovered(guard, replacement);
    assert.equal(outcome.outcome, "passed", `the gate re-opened: a request on the replacement page passes: ${JSON.stringify(outcome)}`);
  });
});

// ---------------------------------------------------------------------------------------
// 5 — the rule itself, read out of the relay's source
// ---------------------------------------------------------------------------------------

/**
 * One function's source text, from `function <name>(` to the next two-space-indented
 * `function` — the shape every function inside `createRelay` has.
 */
function sourceOfFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `the relay defines ${name}`);
  const end = source.indexOf("\n  function ", start);
  return source.slice(start, end > start ? end : undefined);
}

/**
 * The text of every `.catch(...)` body in a slice, with its parentheses matched, so a static
 * assertion can say what a catch DOES rather than what token sits near it.
 */
function catchBodies(text) {
  const out = [];
  let at = text.indexOf(".catch(");
  while (at >= 0) {
    let depth = 0;
    let i = at + ".catch(".length - 1; // the opening paren
    for (; i < text.length; i++) {
      if (text[i] === "(") depth++;
      else if (text[i] === ")") { depth--; if (depth === 0) break; }
    }
    out.push(text.slice(at + ".catch(".length, i));
    at = text.indexOf(".catch(", i);
  }
  return out;
}

test("5: onGateRequestPaused decides every request in one pass expression (static)", () => {
  const source = readFileSync(RELAY, "utf8");
  const body = sourceOfFunction(source, "onGateRequestPaused");
  // The closed-target rule this expression STARTS with is test 13's to pin, exactly: it is a
  // request from a page the GATE closed itself, which must fail in every state (IDLE included)
  // because the document can still answer `requestPaused` on a session that has not detached
  // yet. The whole rule lives in this one expression, so no state can route around it.
  assert.match(
    body,
    /const pass = /,
    `onGateRequestPaused must decide every request in one pass expression, not in a branch beside it; the body was:\n${body}`,
  );
});

// ---------------------------------------------------------------------------------------
// 8, 9 & 10 — a close that may not be written, a close that never comes, and the cleanup a
// guard's own drop starts inside the close window
//
// Two more shapes of the same frame. A `Browser.close` that carries a `sessionId` is a close
// Chromium refuses (only the browser session may close the browser): it answers an error and
// closes nothing, so the relay's cleanup had already run for nothing, the gate sat in CLEANUP
// (closeIntents above zero) for the rest of the relay's life, every request failed, and one
// frame from a bot was enough to wedge it. The rule is: refuse it BEFORE any cleanup starts, and
// change nothing (test 8).
//
// A forwarded close is not an exit, either. Chromium may answer `Browser.close` and not go; the
// graceful `shutdown()` bounds that wait with `closeTimeoutMs` and kills the browser when it
// overruns, and the client path must take the same stop path instead of waiting forever
// (test 9).
//
// And Playwright's own order (test 10): it sends `Browser.close` from the guard and disconnects
// the instant the reply lands. That drop is a guard drop, and a guard drop starts a cleanup — a
// SECOND one, inside the close window the first one opened, creating and then having to close a
// page of its own. A cleanup may not start while a close is owed.
// ---------------------------------------------------------------------------------------

/** Is this pid alive? (`EPERM` is a live process this test may not signal.) */
const alive = (pid) => {
  try { process.kill(pid, 0); return true; } catch (err) { return !!err && err.code === "EPERM"; }
};

/** Wait for a pid to be really gone: a SIGKILLed Chromium is reparented and reaped, not instant. */
async function waitPidGone(pid, timeoutMs = 4000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!alive(pid)) return true;
    await sleep(25);
  }
  return !alive(pid);
}

/**
 * Wait for the fixture's `browser-close` trace record — the moment Chromium was asked to close,
 * which is the clock the fixture's own exit (`FAKE_CHROME_CLOSE_HANDLE_DELAY_MS`) runs from.
 * Returns the time the record was SEEN.
 */
async function waitBrowserClose(ctx, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (ctx.records("browser-close").length > 0) return Date.now();
    if (ctx.child.exitCode !== null) break;
    await sleep(10);
  }
  assert.fail(`Browser.close never reached the fixture; the relay's log was:\n${ctx.logs()}`);
}

test("8: a Browser.close carrying a sessionId is refused before any cleanup starts, and changes nothing", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "" }, async ({ ctx, wsUrl }) => {
    const { observer, page } = await armedPageAndGuard(ctx, wsUrl);
    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    const createdBefore = ctx.records("create-target").length;

    // The frame that wedged a relay: a close naming a session that is not the browser's own.
    const reply = await observer.call("Browser.close", undefined, "bogus");
    assert.ok(reply && reply.error, `a Browser.close naming a sessionId is refused with a JSON-RPC error: ${JSON.stringify(reply)}`);
    assert.equal(reply.result, undefined, `the refusal is an error, never a result: ${JSON.stringify(reply)}`);

    // Long enough for a cleanup to have started and announced itself had one been started.
    await sleep(400);
    assert.equal(ctx.records("browser-close").length, 0, "nothing was forwarded to Chromium as a close");
    assert.equal(countLog(ctx, /gate state CLEANUP/), cleanupsBefore, `the refusal started no cleanup; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("create-target").length, createdBefore, "the refusal ran no cleanup: no replacement page was created");

    // …and the gate is exactly where it was: GUARDED, so a request on the covered page passes.
    const outcome = await probe(observer, page.targetId);
    assert.equal(outcome.outcome, "passed", `the covered page still passes: ${JSON.stringify(outcome)}`);
    assert.equal(ctx.child.exitCode, null, `the relay is still running; its log was:\n${ctx.logs()}`);
  });
});

test("9: a client's Browser.close that Chromium does not honour takes the stop path at closeTimeoutMs, not forever", async (t) => {
  // Chromium would take 2000 ms to exit on its own; the relay's close timeout is 1000 ms. A relay
  // that merely waits would exit 0 at ~2000 ms (the fixture's own exit), so the stop path is
  // visible twice over: a NON-ZERO exit, well before the fixture's own exit.
  await withGate(
    t,
    { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "2000", CROW_CDP_CLOSE_TIMEOUT_MS: "1000" },
    async ({ ctx, wsUrl }) => {
      const { observer } = await armedPageAndGuard(ctx, wsUrl);
      const pid = ctx.pid();
      assert.ok(pid, "the fixture recorded its own pid");

      void observer.call("Browser.close").catch(() => null);
      const closeAt = await waitBrowserClose(ctx);
      const exit = await waitExit(ctx, 4000);
      const elapsed = Date.now() - closeAt;

      assert.notEqual(exit.code, 0, `a close Chromium did not honour within 1000 ms is a stop, not a clean exit (code ${exit.code}, signal ${exit.signal}); its log was:\n${ctx.logs()}`);
      assert.ok(
        elapsed < 1900,
        `the relay took the stop path after its 1000 ms close timeout, not the fixture's own 2000 ms exit: it exited ${elapsed} ms after Browser.close`,
      );
      assert.equal(await waitPidGone(pid), true, `Chromium was killed with the relay, not left running; its log was:\n${ctx.logs()}`);
    },
  );
});

test("10: a guard's Browser.close followed by its own drop runs ONE cleanup, not a second inside the close window", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await armedPageAndGuard(ctx, wsUrl);
    const ids = await candidatePageIds(observer);
    const marker = `guard-close-${Date.now()}`;
    await armPageRequestBurst(observer, ctx, ids, { url: `https://bot.example/${marker}`, until: 1200, step: 25 });

    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    const createdBefore = ctx.records("create-target").length;
    // Playwright's own order: ask for the close, and drop the guard the moment the reply lands.
    await guard.call("Browser.close", undefined, undefined, 15000).catch(() => null);
    guard.kill();

    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a close Chromium honours is a clean exit, even with the guard gone; its log was:\n${ctx.logs()}`);
    assert.equal(
      countLog(ctx, /gate state CLEANUP/),
      cleanupsBefore + 1,
      `exactly one cleanup ran (one CLEANUP transition); its log was:\n${ctx.logs()}`,
    );
    assert.equal(
      ctx.records("create-target").length,
      createdBefore + 1,
      `only one cleanup ran: one about:blank replacement page, not two (${JSON.stringify(ctx.records("create-target").map((r) => r.targetId))})`,
    );
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");
    const trace = ctx.trace();
    assert.equal(trace.some((r) => r.t === "close-target" && r.targetId === page.targetId), true, "the one cleanup closed the bot page");
    assertNonePassedAfterBrowserClose(trace);
  });
});

// ---------------------------------------------------------------------------------------
// 11 — a SIGTERM that joins a close already forwarded (review minor m2)
//
// The stop path's own cleanup is the cleanup that a client's `Browser.close` has ALREADY run
// and completed: when the `browser-close` record is in the fixture's trace, the pages have been
// cleaned and the close is owed. `shutdown()` runs a SECOND cleanup anyway — another
// about:blank replacement, another round of navigates and closes, against a browser that is on
// its way out. What it owes instead is a wait: Chromium's own exit, bounded by
// `closeTimeoutMs`, and then the stop path exactly as today. The gate stays CLEANUP throughout
// (test 2's rule), so the pages' last traffic still fails.
// ---------------------------------------------------------------------------------------

test("11: SIGTERM after a client's Browser.close was already forwarded runs no second cleanup — one replacement, exit 0, gate stays CLEANUP", async (t) => {
  // The fixture keeps serving for 800 ms after `Browser.close`: long enough that a second
  // cleanup's replacement page is created and traced inside the close window.
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "800" }, async ({ ctx, wsUrl }) => {
    const { observer, page } = await armedPageAndGuard(ctx, wsUrl);
    const ids = await candidatePageIds(observer);
    const marker = `sigterm-after-close-${Date.now()}`;
    // A span that covers the whole stop, close window included (800 ms here, not 600).
    await armPageRequestBurst(observer, ctx, ids, { url: `https://bot.example/${marker}`, until: 8000 });

    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    const blankBefore = ctx.records("create-target").filter((r) => r.url === "about:blank").length;
    void observer.call("Browser.close").catch(() => null);
    // The close is FORWARDED: the cleanup it ran is over, and the browser is closing.
    await waitBrowserClose(ctx);
    assert.equal(
      ctx.records("create-target").filter((r) => r.url === "about:blank").length,
      blankBefore + 1,
      `the close's own cleanup created its one replacement page (${JSON.stringify(ctx.records("create-target"))})`,
    );

    // …and now the container stop joins it.
    ctx.child.kill("SIGTERM");
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a close Chromium honours is a clean exit, and a stop that joins it does not change that; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written once — by the client path, never a second time by the stop path");

    const trace = ctx.trace();
    const at = trace.findIndex((r) => r.t === "browser-close");
    assert.ok(at >= 0, "Browser.close reached the fixture");
    const after = trace.slice(at + 1);
    assert.deepEqual(
      after.filter((r) => r.t === "create-target"),
      [],
      `no second cleanup ran: nothing creates a page after Browser.close (${JSON.stringify(after.filter((r) => r.t === "create-target"))})`,
    );
    assert.equal(
      trace.filter((r) => r.t === "create-target" && r.url === "about:blank").length,
      blankBefore + 1,
      `exactly ONE cleanup ran, so exactly one about:blank replacement page (plus the page this test made): ${JSON.stringify(trace.filter((r) => r.t === "create-target").map((r) => r.targetId))}`,
    );
    assert.equal(trace.some((r) => r.t === "close-target" && r.targetId === page.targetId), true, "the one cleanup closed the bot page");
    assertNonePassedAfterBrowserClose(trace);
    assertStayedInCleanup(ctx, cleanupsBefore);
  });
});

// ---------------------------------------------------------------------------------------
// 12 — a close that starts a cleanup underneath the flush it is in (review minor m3)
//
// `flush()` reads the gate state ONCE, before its loop, and then forwards every queued frame.
// A queue can hold [Browser.close, Target.createTarget]: the first frame is relay-handled, it
// starts a cleanup SYNCHRONOUSLY (the gate is CLEANUP before `handleBrowserClose` returns), and
// the loop then forwards the next frame into that cleanup — a page opened in the very window
// the gate exists to keep closed. The state has to be re-read for every frame.
//
// The construction is the one the relay itself provides: a client that connects DURING a
// cleanup gets no browser session until IDLE (`idleWaiters`), so its frames sit in the
// pre-session queue, in order, whatever they are — `Target.createTarget` included, which the
// CLEANUP-time deferral would otherwise answer with an error. The queue is flushed by
// `attachBrowserSession` at IDLE, which is where the loop runs.
// ---------------------------------------------------------------------------------------

test("12: a Browser.close queued during a cleanup is flushed at IDLE and the Target.createTarget behind it is NOT forwarded", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "800" }, async ({ ctx, wsUrl }) => {
    const { observer, guard } = await armedPageAndGuard(ctx, wsUrl);
    // A cleanup long enough that a client can connect inside it and have both frames held.
    await observer.call("Test.delayReplies", { method: "Page.navigate", ms: 700 });

    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    // The drop marker: everything after it in the fixture's trace belongs to the cleanup this
    // test starts and the batch below, so "a page nothing but a client asked for" is about the
    // frames under test, not the page this test made on purpose.
    const marker = `flush-behind-close-${Date.now()}`;
    await guard.call("Test.echo", { value: marker });
    guard.kill();
    await waitLogAfter(ctx, /gate state CLEANUP/, cleanupsBefore);

    // The batch, in this order, while the gate is in CLEANUP: a client with no browser session
    // yet, so both frames are queued and nothing of them reaches the browser.
    const late = plainClient(wsUrl, { attach: false });
    await late.opened;
    late.send("Browser.close");
    late.send("Target.createTarget", { url: "about:blank" });
    assert.equal(countLog(ctx, /gate state IDLE/), idlesBefore, "both frames were sent during the cleanup, before IDLE");
    assert.equal(ctx.records("browser-close").length, 0, "and neither had reached the browser yet (they are queued)");

    // The cleanup ends, the queue is flushed: Browser.close goes first…
    await waitBrowserClose(ctx);
    await waitExit(ctx);

    assert.equal(ctx.records("browser-close").length, 1, "the queued Browser.close IS forwarded, exactly once");
    const trace = ctx.trace();
    const at = markerIndex(trace, marker);
    assert.ok(at >= 0, "the drop marker is in the trace");
    // …and the createTarget queued BEHIND it may never be forwarded: the close it follows has
    // just put the gate in CLEANUP. Only the gate's own browser session (S1) may create a page
    // after the drop (that is the close's cleanup replacement); a client's createTarget on the
    // pipe is the leak.
    const clientCreates = trace.filter((r, i) => i > at && r.t === "recv" && r.method === "Target.createTarget" && r.sessionId !== "S1");
    assert.deepEqual(
      clientCreates,
      [],
      `the Target.createTarget queued behind a Browser.close may not be forwarded: the close started a CLEANUP under the flush (${JSON.stringify(clientCreates)})`,
    );
    assert.ok(
      trace.some((r, i) => i > at && r.t === "recv" && r.method === "Target.createTarget" && r.sessionId === "S1"),
      "the close's own cleanup still created its replacement page on the gate's session",
    );
  });
});

// ---------------------------------------------------------------------------------------
// 13 — the closed-target rule is keyed on the GATE's own flag (review major M2)
//
// The rule that fails a request from a closed target record was keyed on `record.closed`, and
// `closed` is also set by Chromium events the gate never chose: `Target.targetCrashed` (and
// `Target.targetDestroyed`, and a settle that finds the target gone). So a page that CRASHED
// took the cleanup's rule with it — its requests failed for the rest of the relay's life, where
// the gate would have passed them (a crash is not a close the gate performed). The flag is the
// GATE's: `gateClosed`, set only where the gate closes a target itself, and never by an event.
//
// (Test 14 would drive that behaviourally — a covered page whose target crashed keeps passing in
// GUARDED. It is not built here because the fixture has no hook that emits
// `Target.targetCrashed`: `Test.event` sends only `Test.event`, `Target.destroyed` comes from a
// close (a real close), and `Browser.crash` takes the whole fixture process down. A behaviour
// test for this needs either a fixture hook or a real Chromium; the static rule below is what
// this file can pin.)
// ---------------------------------------------------------------------------------------

test("13: onGateRequestPaused keys the closed-target rule on gateClosed, and the gate sets it wherever IT closes a target (static)", () => {
  const source = readFileSync(RELAY, "utf8");
  const body = sourceOfFunction(source, "onGateRequestPaused");
  // The exact shape of the rule, not just a token that appears somewhere in the function: the
  // gate's own close is the FIRST conjunct of the `pass` expression, so no state (IDLE,
  // GUARDED, coverage) can let a request from a page the gate closed through — while a record
  // closed by a CRASH is not touched by it.
  assert.match(
    body,
    /const pass = !\(record && record\.gateClosed\) &&/,
    `onGateRequestPaused must fail a request whose target the GATE closed (gateClosed, in the pass expression itself), and only that one; the body was:\n${body}`,
  );
  assert.equal(
    /record\.closed/.test(body),
    false,
    `the pass expression is not keyed on record.closed: a crashed target sets that too; the body was:\n${body}`,
  );
  // The cleanup closes targets on three separate
  // paths (a page it never resumed, a page whose commit it observed, the remainder), and
  // closeGateTarget closes the targets the gate will not run at all.
  const assignments = [...source.matchAll(/gateClosed = true/g)].length;
  assert.ok(
    assignments >= 3,
    `the cleanup's own close paths set gateClosed (found ${assignments}, expected at least 3), so a page it closed keeps failing while a crashed one does not`,
  );
  const closeBody = sourceOfFunction(source, "closeGateTarget");
  assert.match(closeBody, /record\.gateClosed = true/, `closeGateTarget sets gateClosed too; its body was:\n${closeBody}`);
});

// ---------------------------------------------------------------------------------------
// 15 — a throw between closeIntents++ and the exit timeout (review minor m1)
//
// `handleBrowserClose` counts the close FIRST (`closeIntents++`) — that is what keeps the gate
// in CLEANUP — and arms the exit timeout LAST, after `forwardToPipe`. Anything that throws in
// between (a pipe write, a bookkeeping slip, `reportClosing`) leaves the count above zero with
// no timer to bring it back to zero: the gate stays CLEANUP and every request fails for the rest
// of the relay's life. The arm therefore has to happen before the close is forwarded (or in a
// `finally`), and the `.catch` must take the stop path instead of swallowing the failure.
// ---------------------------------------------------------------------------------------

test("15: handleBrowserClose arms its exit timeout even when a step throws, and its catch takes the stop path (static)", () => {
  const source = readFileSync(RELAY, "utf8");
  const body = sourceOfFunction(source, "handleBrowserClose");
  const forwardAt = body.indexOf("forwardToPipe(client, msg)");
  assert.ok(forwardAt >= 0, `handleBrowserClose forwards the close through forwardToPipe; the body was:\n${body}`);
  const armedAt = body.indexOf("Promise.race");
  const finallyAt = body.indexOf("finally");
  assert.ok(
    finallyAt >= 0 || (armedAt >= 0 && armedAt < forwardAt),
    `the close timeout is armed inside a finally or BEFORE the close is forwarded: a throw between closeIntents++ and the arm would leave the count above zero with no timer, and the gate in CLEANUP for the rest of the relay's life; the body was:\n${body}`,
  );
  const catches = catchBodies(body);
  assert.ok(catches.length >= 1, `handleBrowserClose catches its own failures (the body was:\n${body})`);
  assert.ok(
    catches.some((text) => text.includes("stopPath")),
    `a failure inside handleBrowserClose takes the stop path, it is never swallowed; the catch bodies were:\n${JSON.stringify(catches)}`,
  );
});

// ---------------------------------------------------------------------------------------
// 16, 17 & 18 — a request held at a LIVE client's OWN Fetch session
//
// A guard-bearing client has its own Fetch-enabled session on the page, NEWER than the gate's
// (the gate's session is the oldest auto-attacher, so the fixture's Fetch chain visits the
// client's session FIRST and the gate's last). A page request that pauses at the client's
// session is held there, and the relay will not let the client answer it once the shutdown's
// CLEANUP has started (`fromClient` → `deferInput`, released only by `flush` at IDLE, which a
// stop never reaches). The cleanup then closes the page: every session of that target detaches
// at once — the relay's own detach is what the fixture sees — the Fetch chain advances past the
// sessions that vanished, and the request PASSES. The gate, which would have FAILED it in
// CLEANUP (test 20's control), never saw it at all. In a real container that leaked
// `bcnl_beacon` + `bcnl_img` in 5 of 6 `docker stop` runs while the gate sat in CLEANUP.
//
// Dropping the client first does not leak: its session detaches BEFORE the page does, so the
// held request is released onward to the gate and failed there (that released-onward shape is
// what test 19 ends with).
//
// The arming is `Test.request`, not `Test.armPageRequest`: `Test.armPageRequest` models a
// request that every newer session has ALREADY continued (`oldestOnly` — it enters the chain at
// the gate's own session), which is exactly the one chain that cannot show this. `Test.request`
// takes the FULL chain (the client's session first), and the fixture writes its final outcome
// to its trace whether or not the reply ever reaches this test — which is why the assertion is
// read out of the trace, not out of a reply.
// ---------------------------------------------------------------------------------------

/**
 * Poll until the fixture reports a target RUNNING: a page that is still held runs nothing, so a
 * request issued at it would be recorded `held` and never reach the Fetch chain.
 */
async function waitRunning(observer, targetId, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    last = (await observer.call("Test.state", { targetId })).result?.target ?? null;
    if (last && !last.closed && last.running && !last.held) return last;
    await sleep(25);
  }
  assert.fail(`the page ${targetId} never started running (last state: ${JSON.stringify(last)})`);
}

/**
 * A request that pauses at the guard CLIENT's own session first and is left unanswered, so it
 * is in flight and held when the caller triggers the stop. Returns the session it is held at,
 * proven twice over: by the `Fetch.requestPaused` event the client itself received on that
 * session, and (below) by the `via` the fixture writes when the request finally ends.
 */
async function issueHeldRequest(guard, observer, targetId, url) {
  const guardSession = guard.sessionFor(targetId);
  assert.ok(guardSession, `the guard client has its own session on ${targetId} (a request cannot pause there otherwise)`);
  observer.send("Test.request", { targetId, url });
  const paused = await guard.waitFor(
    (m) => m.method === "Fetch.requestPaused" && m.params?.request?.url === url,
    8000,
    `the request ${url} to pause at the guard client's own Fetch session`,
  );
  assert.equal(
    paused.sessionId,
    guardSession,
    `the request paused at the guard CLIENT's session (newer than the gate's), not at the gate's: ${JSON.stringify(paused)}`,
  );
  return guardSession;
}

/**
 * The final outcome of one request, as the fixture recorded it. `held` is acceptable (the
 * relay may leave the request sitting at the client's session) and so are `failed` and
 * `closed` — `passed` is the leak this file is about: the request reached the network with the
 * gate in CLEANUP and never in front of it. When the fixture DID finish it, `via` must start at
 * the client's own session, which is what proves the construction (the chain was not restricted
 * to the gate's session).
 */
function assertRequestNotPassed(ctx, url, clientSessionId) {
  const finished = ctx.records("request").filter((r) => r.url === url);
  assert.deepEqual(
    finished.filter((r) => r.outcome === "passed"),
    [],
    `a request held at a live client's own Fetch session may not PASS when the cleanup closes the page out from under it — the gate never saw it, and it would have failed it in CLEANUP: ${JSON.stringify(finished)}`,
  );
  if (finished.length) {
    assert.equal(
      finished[0].via[0],
      clientSessionId,
      `the fixture's trace must show the request pausing at the client's own session first (via[0] is the newest session in the chain): ${JSON.stringify(finished[0])}`,
    );
  }
  return finished;
}

/** A guard client that hooks its pages but never answers a paused request. */
const holdingGuard = (wsUrl) => guardClient(wsUrl, { autoContinue: false });

/** A live page, a guard client holding its Fetch session, and a plain observer that outlives it. */
async function pageWithHoldingGuard(ctx, wsUrl) {
  const observer = plainClient(wsUrl, { attach: false });
  await observer.armed;
  const guard = holdingGuard(wsUrl);
  await guard.armed;
  await waitLog(ctx, /gate state GUARDED/);
  const page = await makePage(guard, "https://bot.example/");
  await waitRunning(observer, page.targetId);
  return { observer, guard, page };
}

test("16: SIGTERM — a request held at a live guard client's own Fetch session is not passed by the cleanup", async (t) => {
  // The close window a real Chromium has; the fixture keeps serving inside it.
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await pageWithHoldingGuard(ctx, wsUrl);
    const url = `https://bot.example/held-at-client-sigterm-${Date.now()}`;
    const guardSession = await issueHeldRequest(guard, observer, page.targetId, url);

    ctx.child.kill("SIGTERM");
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a clean scan closes the browser and exits 0; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");

    const trace = ctx.trace();
    assert.equal(trace.some((r) => r.t === "close-target" && r.targetId === page.targetId), true, "the cleanup closed the page the held request was on");
    assertRequestNotPassed(ctx, url, guardSession);
  });
});

test("17: another client's Browser.close — the request held at the guard's own session is not passed either", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await pageWithHoldingGuard(ctx, wsUrl);
    const url = `https://bot.example/held-at-client-close-${Date.now()}`;
    const guardSession = await issueHeldRequest(guard, observer, page.targetId, url);

    // The asker is a DIFFERENT client (plain, no Fetch session on the page): the held request
    // belongs to the guard, and the close that starts the cleanup belongs to nobody's session.
    void observer.call("Browser.close").catch(() => null);
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a close Chromium honours is a clean exit; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");

    const trace = ctx.trace();
    assert.equal(trace.some((r) => r.t === "close-target" && r.targetId === page.targetId), true, "the cleanup closed the page the held request was on");
    assertRequestNotPassed(ctx, url, guardSession);
  });
});

test("18: the asker's OWN held request — a client's Browser.close while its own Fetch session holds a request is not passed", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await pageWithHoldingGuard(ctx, wsUrl);
    const url = `https://bot.example/held-at-asker-${Date.now()}`;
    const guardSession = await issueHeldRequest(guard, observer, page.targetId, url);

    // The client that asks for the close is the one whose own session holds the request: it
    // cannot answer it (CLEANUP defers its input), and the cleanup that its close started is
    // what closes the page. Its `Browser.close` reply is NOT asserted: it may or may not come
    // back before the relay drops it.
    guard.send("Browser.close");
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a close Chromium honours is a clean exit; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");

    const trace = ctx.trace();
    assert.equal(trace.some((r) => r.t === "close-target" && r.targetId === page.targetId), true, "the cleanup closed the page the asker's own session held the request on");
    assertRequestNotPassed(ctx, url, guardSession);
  });
});

// ---------------------------------------------------------------------------------------
// 19 — the turn-end CLEANUP, with a SECOND guard-bearing client still attached
//
// The turn-end cleanup trigger is `dropClient`'s `if (wasIntent && gateReady && !stopping)`
// branch, and it is guarded by a scan of the remaining clients: a CLEANUP is entered only when
// NO other client with the intent header is still attached (`enterCleanup`, which also refuses
// while a close is owed or a cleanup is already in flight). `recomputeState` never sets CLEANUP
// at all — it counts guards and connecting clients, and CLEANUP is sticky until a cleanup ends
// (`recomputeState` returns immediately while the state IS CLEANUP). So the state machine
// CANNOT enter a turn-end CLEANUP while another guard-bearing client is still attached, and the
// leak of tests 16-18 cannot be reached that way — with guard B still holding its page, guard
// A dropping changes nothing at all.
//
// That is what this test proves: with guard B attached (declared, holding an unanswered request
// at its own Fetch session) and guard A dropping, there is NO `gate state CLEANUP`, no
// replacement page, and the held request is still held — not passed, not handed anywhere. Then
// guard B itself goes, and the ONE cleanup that drop starts is the release the request was
// waiting for: guard B's session detaches before the page does, the fixture advances the request
// onward to the gate's session, and the gate fails it in CLEANUP (never `passed`).
// ---------------------------------------------------------------------------------------

/** Poll until the fixture has recorded the final outcome of one request. */
async function waitRequestRecord(ctx, url, timeoutMs = 12000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = ctx.records("request").find((r) => r.url === url);
    if (found) return found;
    if (ctx.child.exitCode !== null) break;
    await sleep(25);
  }
  assert.fail(`the fixture never finished the request ${url}; its last request records were:\n${JSON.stringify(ctx.records("request").slice(-5))}`);
}

test("19: with a second guard-bearing client attached, a guard's drop starts NO cleanup — the held request stays held", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    // Guard A is a guard-bearing client with NO page of its own (`attach: false`): it exists to
    // be the second declared guard the drop scan sees.
    const guardA = guardClient(wsUrl, { attach: false });
    const guardB = holdingGuard(wsUrl);
    await guardA.armed;
    await guardB.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const page = await makePage(guardB, "https://bot.example/");
    await waitRunning(observer, page.targetId);
    const url = `https://bot.example/held-through-a-turn-end-${Date.now()}`;
    const bSession = await issueHeldRequest(guardB, observer, page.targetId, url);

    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    const createdBefore = ctx.records("create-target").length;

    // Guard A's turn ends; guard B is still attached with its request held.
    guardA.kill();
    // A cleanup announces itself SYNCHRONOUSLY when a drop triggers one (`setState("CLEANUP")`
    // inside `enterCleanup`), so this window is far more than one cleanup would need to appear.
    await sleep(700);
    assert.equal(
      countLog(ctx, /gate state CLEANUP/),
      cleanupsBefore,
      `a guard drop with ANOTHER guard-bearing client still attached may not start a cleanup; the log was:\n${ctx.logs()}`,
    );
    assert.equal(ctx.records("create-target").length, createdBefore, `no cleanup ran, so no replacement page was created (${JSON.stringify(ctx.records("create-target").map((r) => r.targetId))})`);
    assert.equal(countLog(ctx, /gate state IDLE/), idlesBefore, `and nothing moved the gate either; the log was:\n${ctx.logs()}`);
    assert.deepEqual(ctx.records("request").filter((r) => r.url === url), [], "the request is still held at guard B's own session: nothing closed the page, so nothing released it");
    assert.equal(ctx.child.exitCode, null, `the relay is still running; its log was:\n${ctx.logs()}`);

    // …and now the LAST guard-bearing client goes. THIS is the turn-end cleanup, and it is the
    // one that must not let the request it held pass: guard B's session detaches first, the
    // request is released onward to the gate's session, and the gate fails it in CLEANUP.
    guardB.kill();
    await waitLogAfter(ctx, /gate state CLEANUP/, cleanupsBefore);
    const record = await waitRequestRecord(ctx, url);
    assert.equal(record.outcome, "failed", `the released request reached the gate's session in CLEANUP and the gate FAILED it: ${JSON.stringify(record)}`);
    assert.equal(record.via[0], bSession, `and it really came off guard B's own session first: ${JSON.stringify(record)}`);
    assertRequestNotPassed(ctx, url, bSession);
  });
});

// ---------------------------------------------------------------------------------------
// 20 — the control: with NO guard client at all, the same SIGTERM cleanup fails the requests
//
// Nothing is in front of the pages but the gate's own session, so the fixture's chain has one
// entry and `Test.armPageRequest` (which enters at the OLDEST interception) starts there. Every
// request that lands after the cleanup began — the close window included — is FAILED by the
// gate's `onGateRequestPaused` rule for CLEANUP. This is the behaviour tests 16-18 must not be
// able to route around: it passes before and after the fix, and it is the same rig, the same
// burst and the same assertions as test 1, minus the guard client.
// ---------------------------------------------------------------------------------------

test("20: control — with no guard client at all, requests armed into the SIGTERM cleanup are failed by the gate", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    // A plain client's page: the gate auto-attaches and, in IDLE, resumes it at once.
    const page = await makePage(observer, "https://bot.example/");
    await waitRunning(observer, page.targetId);

    const ids = await candidatePageIds(observer);
    const marker = `no-guard-${Date.now()}`;
    await armPageRequestBurst(observer, ctx, ids, { url: `https://bot.example/${marker}` });

    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    ctx.child.kill("SIGTERM");
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a clean scan closes the browser and exits 0; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");

    const trace = ctx.trace();
    assert.equal(trace.some((r) => r.t === "close-target" && r.targetId === page.targetId), true, "the cleanup closed the page this test made");
    assertNonePassedAfterBrowserClose(trace);
    assertStayedInCleanup(ctx, cleanupsBefore);
  });
});

// ---------------------------------------------------------------------------------------
// 21 & 22 — the same held-request leak with NO close in it, and one level deeper
//
// Test 21 is the turn-end CLEANUP (a guard's own drop, the `dropClient` trigger) with the held
// request in a PLAIN client's Fetch session. `releaseClientSessions` is what a guard drop runs
// before the cleanup: it clears and forgets EVERY client session — a plain client's included,
// since a plain client's `Fetch.enable {*}` sits in the same chain, newer than the gate's — and
// the relay's own `Target.detachFromTarget` goes out with NO envelope (the root).
//
// Real Chromium looks a session up for `Target.detachFromTarget` only in the session that OWNS
// it (the envelope of the `Target.attachToTarget` / `Target.setAutoAttach` that created it): a
// client's child sessions are owned by the client's own browser session `S_c`, so a root-sent
// detach of one answers "No session with given id" and detaches nothing. The session therefore
// survives, the request stays held in it, the cleanup's `Target.closeTarget` takes every session
// of the target at once, and the request advances past the sessions that vanished and PASSES —
// with the gate never in front of it. The fixture now models the ownership rule, so this file
// sees it; the relay names the owner and the request reaches the gate instead.
//
// Test 22 is the same shape one level deeper: a session announced by a session (an iframe the
// client auto-attached under its own page session), owned by that page session and not by `S_c`.
// ---------------------------------------------------------------------------------------

test("21: a plain client's held request — the turn-end CLEANUP (a guard's drop) may not pass it", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = holdingGuard(wsUrl); // the one guard-bearing client, and it answers nothing
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    // A PLAIN client (no intent header) that does what Playwright does on every page it is
    // handed — `Fetch.enable {*}` and the marker script — and never answers a paused request.
    // Its session is the NEWEST Fetch interception on the page, so a request pauses there first,
    // and the relay's coverage rule does not count it (only a declaring, intent-bearing client
    // covers a page).
    const holder = plainClient(wsUrl, { autoContinue: false });
    await holder.armed;
    const page = await makePage(holder, "https://bot.example/");
    await waitRunning(observer, page.targetId);
    const holderSession = holder.sessionFor(page.targetId);
    assert.ok(holderSession, `the plain client has its own Fetch session on ${page.targetId}`);

    const url = `https://bot.example/held-at-a-plain-client-${Date.now()}`;
    observer.send("Test.request", { targetId: page.targetId, url });
    const paused = await holder.waitFor(
      (m) => m.method === "Fetch.requestPaused" && m.params?.request?.url === url,
      8000,
      `the request ${url} to pause at the plain client's own Fetch session`,
    );
    assert.equal(paused.sessionId, holderSession, `the request paused at the plain client's session, not the gate's: ${JSON.stringify(paused)}`);

    const cleanupsBefore = countLog(ctx, /gate state CLEANUP/);
    const idlesBefore = countLog(ctx, /gate state IDLE/);
    // The only guard-bearing client goes: the turn-end cleanup, which ends in IDLE (no close is
    // owed on this path), so "the cleanup is over" is the next IDLE line.
    guard.kill();
    await waitLogAfter(ctx, /gate state CLEANUP/, cleanupsBefore);
    await waitLogAfter(ctx, /gate state IDLE/, idlesBefore);

    const trace = ctx.trace();
    assert.equal(
      trace.some((r) => r.t === "close-target" && r.targetId === page.targetId),
      true,
      "the cleanup closed the page the held request was on",
    );
    const record = await waitRequestRecord(ctx, url);
    assert.notEqual(
      record.outcome,
      "passed",
      `a request the cleanup's own close released may not PASS: the gate never saw it, and it would have failed it in CLEANUP (${JSON.stringify(record)})`,
    );
    assert.equal(record.via[0], holderSession, `the fixture's trace shows it paused at the plain client's own session first: ${JSON.stringify(record)}`);
  });
});

test("22: a request held at a NESTED child session — a client's Browser.close may not pass it", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const observer = plainClient(wsUrl, { attach: false });
    await observer.armed;
    const guard = holdingGuard(wsUrl);
    await guard.armed;
    await waitLog(ctx, /gate state GUARDED/);

    const page = await makePage(guard, "https://bot.example/nested");
    await waitRunning(observer, page.targetId);
    const pageSession = guard.sessionFor(page.targetId);
    assert.ok(pageSession, `the guard has its own session on ${page.targetId}`);

    // An iframe the guard is handed THROUGH ITS OWN PAGE SESSION (the relay's nested
    // auto-attach), so that session owns the iframe's session — not the guard's `S_c`. The
    // guard hooks it, which is where the request below will be held.
    const iframeUrl = `https://bot.example/iframe-${Date.now()}`;
    const spawned = await observer.call("Test.spawnTarget", { type: "iframe", ownerId: page.targetId, url: iframeUrl });
    const iframeId = spawned.result?.targetId;
    assert.ok(iframeId, `the fixture spawned an iframe under ${page.targetId}: ${JSON.stringify(spawned)}`);
    await guard.waitFor(
      (m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === iframeId,
      8000,
      `the guard's nested attach event for ${iframeId}`,
    );
    await waitRunning(observer, iframeId);
    const nestedSession = guard.sessionFor(iframeId);
    assert.ok(nestedSession, `the guard has a session for ${iframeId}`);
    assert.notEqual(nestedSession, pageSession, "the iframe's session is a session of its own, one level below the page's");

    const url = `https://bot.example/held-at-a-nested-session-${Date.now()}`;
    observer.send("Test.request", { targetId: iframeId, url });
    const paused = await guard.waitFor(
      (m) => m.method === "Fetch.requestPaused" && m.params?.request?.url === url,
      8000,
      `the request ${url} to pause at the guard's nested session`,
    );
    assert.equal(paused.sessionId, nestedSession, `the request paused at the NESTED session, not at the page's: ${JSON.stringify(paused)}`);

    // A client's `Browser.close`, from a client that holds nothing on the iframe: the cleanup
    // that follows is the one that closes the targets out from under the held request.
    void observer.call("Browser.close").catch(() => null);
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a close Chromium honours is a clean exit; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");

    const trace = ctx.trace();
    assert.equal(
      trace.some((r) => r.t === "close-target" && (r.targetId === iframeId || r.targetId === page.targetId)),
      true,
      "the cleanup closed the page or the iframe the held request was on",
    );
    const record = await waitRequestRecord(ctx, url);
    assert.notEqual(
      record.outcome,
      "passed",
      `a request held at a NESTED session may not PASS when the cleanup closes the target out from under it — the gate never saw it (${JSON.stringify(record)})`,
    );
    assert.equal(record.via[0], nestedSession, `the fixture's trace shows it paused at the nested session first: ${JSON.stringify(record)}`);
  });
});

// ---------------------------------------------------------------------------------------
// 23 — an explicit attach the CLIENT issued on one of its own session's envelopes
//
// `sessionParent` is what tells `releaseClientSessions` that a session is NESTED (it dies with
// the parent that owns it) rather than top-level (the relay detaches it itself, on the client's
// `S_c`). An attach EVENT names its parent (`onClientAttached`); an attach RESPONSE did not — and
// a response can announce a child whose real owner is not `S_c` at all: a client may send
// `Target.attachToTarget` with the envelope of one of its OWN page sessions, and Chromium then
// owns the new child with that page session. Detached on `S_c` — where the relay put it before
// this test — the command is refused ("No session with given id") and detaches nothing, so the
// relay's own release never reaches the session the client attached.
//
// What the fixture can and cannot show, honestly: it does create the child under the page
// session's envelope (the `recv` record below proves the attach went out there), and it does
// model the ownership rule, so the child goes with its owner — which is why the held request
// cannot PASS here even with the bookkeeping missing: `T1`'s own detach already took the child
// away (verified against the relay before the fix: outcome `failed`, `via` `["T2","A3"]`, and
// the child's later detach answered with no error because the session was already gone). The
// FIXTURE therefore cannot distinguish the two bookings behaviourally, so the not-passed
// assertion below is the shape that must hold, and the bookkeeping itself is pinned statically
// the fallback this test's review asked for. Test 22 pins the same nesting for an attach EVENT.
// ---------------------------------------------------------------------------------------

test("23: an explicit attach on the client's own page-session envelope — the request its child holds is not passed", async (t) => {
  await withGate(t, { FAKE_CHROME_EXTENSION_WORKERS: "", FAKE_CHROME_CLOSE_HANDLE_DELAY_MS: "600" }, async ({ ctx, wsUrl }) => {
    const { observer, guard, page } = await pageWithHoldingGuard(ctx, wsUrl);
    const pageSession = page.sessionId;
    assert.ok(pageSession, `the guard has its own session on ${page.targetId}`);

    // The client attaches the page AGAIN, from its own page session's envelope: the child the
    // response announces is owned by that page session, not by the client's `S_c`.
    const attached = await guard.call("Target.attachToTarget", { targetId: page.targetId, flatten: true }, pageSession);
    const childSession = attached.result?.sessionId;
    assert.ok(childSession, `the relay answered the attach with a session: ${JSON.stringify(attached)}`);
    assert.notEqual(childSession, pageSession, "the child the response announced is a session of its own");
    assert.ok(
      ctx.records("recv").some((r) => r.method === "Target.attachToTarget" && r.sessionId === pageSession && r.params?.targetId === page.targetId),
      `the attach reached Chromium on the page session's envelope, so the page session owns the child (${JSON.stringify(ctx.records("recv").filter((r) => r.method === "Target.attachToTarget"))})`,
    );
    // Hook the child: it is the newest interception on the page, so a request pauses there first.
    await guard.call("Fetch.enable", { handleAuthRequests: true, patterns: [{ urlPattern: "*", requestStage: "Request" }] }, childSession);

    const url = `https://bot.example/held-at-an-attach-response-child-${Date.now()}`;
    observer.send("Test.request", { targetId: page.targetId, url });
    const paused = await guard.waitFor(
      (m) => m.method === "Fetch.requestPaused" && m.params?.request?.url === url,
      8000,
      `the request ${url} to pause at the session the attach response created`,
    );
    assert.equal(paused.sessionId, childSession, `the request paused at the CHILD the attach response announced, not at the page session: ${JSON.stringify(paused)}`);

    // A client's `Browser.close`, from another client: the cleanup that follows releases every
    // client's sessions (`releaseClientSessions`), and closes the page out from under the held
    // request. The page session owns the child, so the child may go with IT — never with a
    // detach the browser refuses, and never into the target close still holding the request.
    void observer.call("Browser.close").catch(() => null);
    const exit = await waitExit(ctx);
    assert.equal(exit.code, 0, `a close Chromium honours is a clean exit; its log was:\n${ctx.logs()}`);
    assert.equal(ctx.records("browser-close").length, 1, "Browser.close is written exactly once");

    const record = await waitRequestRecord(ctx, url);
    assert.notEqual(
      record.outcome,
      "passed",
      `a request held at a child an explicit attach created on the client's own page session may not PASS when the cleanup closes the target out from under it — the gate never saw it (${JSON.stringify(record)})`,
    );
    assert.equal(record.via[0], childSession, `the fixture's trace shows it paused at the child session first: ${JSON.stringify(record)}`);

    // …and the bookkeeping that makes that child NESTED, which the run above cannot show on its
    // own (see this test's header): the fixture takes a child away with the OWNER's own detach
    // (`T1` here), so the relay's later detach of the child lands on a session Chromium has
    // already dropped and answers nothing — a relay that books the child as TOP-LEVEL produces
    // this same trace and this same outcome here, while in the browser that detach is refused on
    // an envelope that does not own it. Test 22 pins the nesting for an attach EVENT; this pins
    // the RESPONSE path, which is where it was missing: the parent is the ENVELOPE the attach was
    // forwarded on.
    const source = readFileSync(RELAY, "utf8");
    const forward = sourceOfFunction(source, "forwardToPipe");
    assert.match(
      forward,
      /entry\.envelope = sessionId/,
      `forwardToPipe must record the envelope its frame went out on — it is the owner Chromium gives the session an attach RESPONSE announces; the body was:\n${forward}`,
    );
    const response = sourceOfFunction(source, "fromPipe");
    assert.match(
      response,
      /registerSession\(announced, client\);[\s\S]{0,1500}?sessionParent\.set\(announced, entry\.envelope\)/,
      `the attach-RESPONSE path must book the announced session's parent as the envelope the attach went out on (a page or child session of the client's own owns it then, and the child dies with it — a detach on S_c is refused); the body was:\n${response}`,
    );
  });
});