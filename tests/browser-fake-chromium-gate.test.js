/**
 * tests/fixtures/fake-chromium-gate.mjs on its own: spawned with the real pipe pair (our
 * fd 3 = its commands in, our fd 4 = its replies and events out, JSON + NUL) and driven
 * directly, with no relay in between.
 *
 * Each test is one small observation of the model the relay's gate rules rest on: who is
 * held and by whom, what a shared worker does with its first resumer, the order of the
 * Fetch chain, release on disable, per-session request ids, and the commit that a close is
 * allowed to follow.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const FIXTURE = fileURLToPath(new URL("./fixtures/fake-chromium-gate.mjs", import.meta.url));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Spawn the fixture and wrap the pipe as a tiny CDP client: `call` waits for the reply with
 * that id, `waitEvent` for the next matching message no earlier wait has taken.
 */
function start(t, env = {}) {
  const dir = mkdtempSync(join(tmpdir(), "crow-fake-gate-"));
  const tracePath = join(dir, "trace.log");
  const child = spawn(process.execPath, [FIXTURE], {
    env: { ...process.env, FAKE_CHROME_LOG: tracePath, ...env },
    stdio: ["ignore", "inherit", "inherit", "pipe", "pipe"],
  });
  const messages = [];
  const consumed = new Set(); // message indices a waitEvent already took
  const waiters = [];
  const pending = new Map();
  let nextId = 0;
  let parts = [];

  const input = child.stdio[4];
  input.on("data", (chunk) => {
    let at = 0;
    for (;;) {
      const nul = chunk.indexOf(0, at);
      if (nul === -1) { parts.push(chunk.subarray(at)); return; }
      parts.push(chunk.subarray(at, nul));
      const frame = Buffer.concat(parts).toString("utf8");
      parts = [];
      at = nul + 1;
      let msg;
      try { msg = JSON.parse(frame); } catch { continue; }
      messages.push(msg);
      if (msg.id !== undefined && pending.has(msg.id)) {
        const resolve = pending.get(msg.id);
        pending.delete(msg.id);
        resolve(msg);
      }
      for (const w of [...waiters]) w.check();
    }
  });

  const exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));

  const write = (msg) => {
    try { child.stdio[3].write(JSON.stringify(msg) + "\0"); } catch { /* gone */ }
  };
  child.stdio[3].on("error", () => { /* the pipe closed under us; the reply timeouts report it */ });
  input.on("error", () => { /* same */ });

  const call = (method, params, sessionId) => {
    const id = ++nextId;
    const frame = { id, method, ...(params !== undefined ? { params } : {}), ...(sessionId ? { sessionId } : {}) };
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        if (pending.delete(id)) reject(new Error(`no reply to ${method} (exit ${child.exitCode}, ${messages.length} messages, trace: ${JSON.stringify(traceLines().slice(-3))})`));
      }, 5000);
      pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
      write(frame);
    });
  };

  /**
   * The next message, in arrival order, that `pred` accepts and no earlier wait has taken.
   * Consumption is per message, so a wait after the event has already arrived still finds
   * it, and waiting twice takes two different events.
   */
  const waitEvent = (pred, timeoutMs = 3000) => {
    const scan = () => {
      for (let i = 0; i < messages.length; i++) {
        if (consumed.has(i)) continue;
        if (pred(messages[i])) return { index: i, message: messages[i] };
      }
      return null;
    };
    const hit = scan();
    if (hit) { consumed.add(hit.index); return Promise.resolve(hit.message); }
    return new Promise((resolve, reject) => {
      const waiter = {
        check: () => {
          const found = scan();
          if (!found) return;
          consumed.add(found.index);
          clearTimeout(timer);
          const at = waiters.indexOf(waiter);
          if (at >= 0) waiters.splice(at, 1);
          resolve(found.message);
        },
      };
      const timer = setTimeout(() => {
        const at = waiters.indexOf(waiter);
        if (at >= 0) waiters.splice(at, 1);
        reject(new Error("timeout waiting for a message"));
      }, timeoutMs);
      waiters.push(waiter);
    });
  };

  const traceLines = () => {
    try {
      return readFileSync(tracePath, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    } catch { return []; }
  };

  const ctx = {
    child,
    call,
    waitEvent,
    messages,
    exited,
    stop: async () => {
      try { child.kill("SIGKILL"); } catch { /* gone */ }
      await Promise.race([exited, sleep(2000)]);
      try { child.stdio[3].destroy(); } catch { /* gone */ }
      try { child.stdio[4].destroy(); } catch { /* gone */ }
      rmSync(dir, { recursive: true, force: true });
    },
    records: (type) => traceLines().filter((r) => r.t === type),
    trace: traceLines,
  };
  t.after(ctx.stop);
  return ctx;
}

/** A browser session with auto-attach on, and the child session it got for `targetId`. */
async function autoAttachBrowser(c, { waitForDebugger = false } = {}) {
  const browserSession = (await c.call("Target.attachToBrowserTarget")).result.sessionId;
  await c.call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: waitForDebugger, flatten: true }, browserSession);
  return browserSession;
}

const attached = (browserSession, targetId) =>
  (m) => m.method === "Target.attachedToTarget" && m.sessionId === browserSession && (!targetId || m.params.targetInfo.targetId === targetId);

const paused = (sessionId, requestId) =>
  (m) => m.method === "Fetch.requestPaused" && m.sessionId === sessionId && (!requestId || m.params.requestId === requestId);

test("the initial state is one running page, P1, at about:blank", async (t) => {
  const c = start(t);
  const version = await c.call("Browser.getVersion");
  assert.equal(version.result.product, "FakeChrome/1.0.0");
  const infos = (await c.call("Target.getTargets")).result.targetInfos;
  assert.deepEqual(infos.map((i) => i.targetId), ["P1"]);
  assert.equal(infos[0].type, "page");
  assert.equal(infos[0].url, "about:blank");
  const state = (await c.call("Test.state")).result;
  assert.equal(state.targets[0].running, true);
  assert.equal(state.targets[0].held, false);
});

test("setAutoAttach announces P1 with waitingForDebugger and holds it until that child resumes", async (t) => {
  const c = start(t);
  const browserSession = await autoAttachBrowser(c, { waitForDebugger: true });
  const attach = await c.waitEvent(attached(browserSession, "P1"));
  assert.equal(attach.params.waitingForDebugger, true);
  const child = attach.params.sessionId;

  // Held: a held target runs nothing.
  assert.equal((await c.call("Test.request", { targetId: "P1", url: "http://example.test/a" })).result.outcome, "held");

  await c.call("Runtime.runIfWaitingForDebugger", {}, child);
  assert.equal((await c.call("Test.request", { targetId: "P1", url: "http://example.test/a" })).result.outcome, "passed");
  assert.deepEqual(c.records("resumed").map((r) => r.targetId), ["P1"]);
});

test("two auto-attachers: a page stays held until BOTH of them resume it", async (t) => {
  const c = start(t);
  const first = await autoAttachBrowser(c, { waitForDebugger: true });
  const second = await autoAttachBrowser(c, { waitForDebugger: true });
  const firstChild = (await c.waitEvent(attached(first, "P1"))).params.sessionId;
  const secondChild = (await c.waitEvent(attached(second, "P1"))).params.sessionId;

  await c.call("Runtime.runIfWaitingForDebugger", {}, firstChild);
  // Control: one resumer is not enough.
  assert.equal((await c.call("Test.state", { targetId: "P1" })).result.target.held, true);
  assert.equal((await c.call("Test.request", { targetId: "P1", url: "http://example.test/b" })).result.outcome, "held");

  await c.call("Runtime.runIfWaitingForDebugger", {}, secondChild);
  assert.equal((await c.call("Test.state", { targetId: "P1" })).result.target.running, true);
  assert.equal((await c.call("Test.request", { targetId: "P1", url: "http://example.test/b" })).result.outcome, "passed");
  assert.equal(c.records("resumed").length, 1);
});

test("a shared worker runs as soon as the FIRST resumer resumes it", async (t) => {
  const c = start(t);
  const first = await autoAttachBrowser(c, { waitForDebugger: true });
  const second = await autoAttachBrowser(c, { waitForDebugger: true });
  await c.call("Runtime.runIfWaitingForDebugger", {}, (await c.waitEvent(attached(first, "P1"))).params.sessionId);
  await c.call("Runtime.runIfWaitingForDebugger", {}, (await c.waitEvent(attached(second, "P1"))).params.sessionId);

  // Ownerless, so the browser-level auto-attachers are the ones that see it.
  const { targetId } = (await c.call("Test.spawnTarget", { type: "shared_worker", url: "http://example.test/sw.js" })).result;
  const one = await c.waitEvent(attached(first, targetId));
  const two = await c.waitEvent(attached(second, targetId));
  assert.equal(one.params.waitingForDebugger, true);
  assert.equal(two.params.waitingForDebugger, true);

  await c.call("Runtime.runIfWaitingForDebugger", {}, one.params.sessionId);
  const state = (await c.call("Test.state", { targetId })).result.target;
  assert.equal(state.running, true);
  assert.equal(state.held, false);
  assert.deepEqual(state.waiting, []);
});

test("the Fetch chain is newest session first, an override reaches the older session, a fail stops it", async (t) => {
  const c = start(t);
  const browserSession = await autoAttachBrowser(c);
  const older = (await c.waitEvent(attached(browserSession, "P1"))).params.sessionId;
  const newer = (await c.call("Target.attachToTarget", { targetId: "P1", flatten: true })).result.sessionId;
  await c.call("Fetch.enable", { patterns: [{ urlPattern: "*" }] }, older);
  await c.call("Fetch.enable", { patterns: [{ urlPattern: "*" }] }, newer);

  // Newest first: the request pauses on the explicitly attached (later) session.
  const pending = c.call("Test.request", { targetId: "P1", url: "http://example.test/one" });
  const firstPause = await c.waitEvent(paused(newer));
  assert.equal(firstPause.params.frameId, "P1");

  await c.call("Fetch.continueRequest", { requestId: firstPause.params.requestId, url: "http://example.test/two" }, newer);
  const secondPause = await c.waitEvent(paused(older));
  assert.equal(secondPause.params.request.url, "http://example.test/two");
  assert.equal(secondPause.params.requestId, firstPause.params.requestId);
  await c.call("Fetch.continueRequest", { requestId: secondPause.params.requestId }, older);

  const passed = (await pending).result;
  assert.equal(passed.outcome, "passed");
  assert.equal(passed.finalUrl, "http://example.test/two");
  assert.deepEqual(passed.via, [newer, older]);

  // A fail on the newest session stops it: the older one never sees it.
  const stopped = c.call("Test.request", { targetId: "P1", url: "http://example.test/three" });
  const stopPause = await c.waitEvent(paused(newer));
  await c.call("Fetch.failRequest", { requestId: stopPause.params.requestId, errorReason: "BlockedByClient" }, newer);
  const failed = (await stopped).result;
  assert.equal(failed.outcome, "failed");
  assert.deepEqual(failed.via, [newer]);

  // Control: with Fetch not enabled anywhere, the same request passes.
  await c.call("Fetch.disable", {}, older);
  await c.call("Fetch.disable", {}, newer);
  const control = (await c.call("Test.request", { targetId: "P1", url: "http://example.test/four" })).result;
  assert.equal(control.outcome, "passed");
  assert.deepEqual(control.via, []);
});

test("Fetch.disable on the holding session releases the request onward", async (t) => {
  const c = start(t);
  const browserSession = await autoAttachBrowser(c);
  const older = (await c.waitEvent(attached(browserSession, "P1"))).params.sessionId;
  const newer = (await c.call("Target.attachToTarget", { targetId: "P1", flatten: true })).result.sessionId;
  await c.call("Fetch.enable", { patterns: [{ urlPattern: "*" }] }, older);
  await c.call("Fetch.enable", { patterns: [{ urlPattern: "*" }] }, newer);

  const pending = c.call("Test.request", { targetId: "P1", url: "http://example.test/release" });
  const held = await c.waitEvent(paused(newer));
  await c.call("Fetch.disable", {}, newer);

  // Released to the next OLDER session, not dropped.
  const moved = await c.waitEvent(paused(older, held.params.requestId));
  assert.equal(moved.params.request.url, "http://example.test/release");
  await c.call("Fetch.continueRequest", { requestId: moved.params.requestId }, older);

  const result = (await pending).result;
  assert.equal(result.outcome, "passed");
  assert.deepEqual(result.via, [newer, older]);
  assert.equal(c.records("fetch-disable").length, 1);
});

test("only the session holding a request may answer it", async (t) => {
  const c = start(t);
  const browserSession = await autoAttachBrowser(c);
  const older = (await c.waitEvent(attached(browserSession, "P1"))).params.sessionId;
  const newer = (await c.call("Target.attachToTarget", { targetId: "P1", flatten: true })).result.sessionId;
  await c.call("Fetch.enable", { patterns: [{ urlPattern: "*" }] }, older);
  await c.call("Fetch.enable", { patterns: [{ urlPattern: "*" }] }, newer);

  const pending = c.call("Test.request", { targetId: "P1", url: "http://example.test/scoped" });
  const held = await c.waitEvent(paused(newer));

  // Request ids are scoped per session: the older session's attempt changes nothing.
  const refused = await c.call("Fetch.continueRequest", { requestId: held.params.requestId }, older);
  assert.equal(refused.error.code, -32602);
  assert.equal(refused.error.message, "Invalid InterceptionId");

  // The request is still with the session that holds it.
  await c.call("Fetch.continueRequest", { requestId: held.params.requestId }, newer);
  await c.call("Fetch.continueRequest", { requestId: (await c.waitEvent(paused(older, held.params.requestId))).params.requestId }, older);
  const result = (await pending).result;
  assert.equal(result.outcome, "passed");
  assert.deepEqual(result.via, [newer, older]);
});

test("Page.navigate answers with a loaderId that the frameNavigated carries, and a non-committing page emits nothing", async (t) => {
  const c = start(t);
  const browserSession = await autoAttachBrowser(c);
  const child = (await c.waitEvent(attached(browserSession, "P1"))).params.sessionId;
  await c.call("Page.enable", {}, child);

  const nav = (await c.call("Page.navigate", { url: "http://example.test/committed" }, child)).result;
  assert.equal(nav.frameId, "P1");
  assert.match(nav.loaderId, /^L\d+$/);
  const event = await c.waitEvent((m) => m.method === "Page.frameNavigated" && m.sessionId === child);
  assert.equal(event.params.frame.loaderId, nav.loaderId);
  assert.equal(event.params.frame.url, "http://example.test/committed");
  assert.equal((await c.call("Page.getNavigationHistory", {}, child)).result.currentIndex, 1);
  assert.equal(c.records("navigate").at(-1).committed, true);

  // Control: a page that never commits answers with a loaderId but emits no such event.
  await c.call("Test.setCommit", { targetId: "P1", commit: false });
  const silent = (await c.call("Page.navigate", { url: "http://example.test/never" }, child)).result;
  assert.match(silent.loaderId, /^L\d+$/);
  await assert.rejects(c.waitEvent((m) => m.method === "Page.frameNavigated", 150));
  assert.equal((await c.call("Test.state", { targetId: "P1" })).result.target.url, "http://example.test/committed");
  assert.equal(c.records("navigate").at(-1).committed, false);
});

test("closing the last page exits with FAKE_EXIT_ON_NO_PAGES=1", async (t) => {
  const c = start(t, { FAKE_EXIT_ON_NO_PAGES: "1" });
  assert.equal((await c.call("Target.closeTarget", { targetId: "nope" })).result.success, false);
  assert.equal((await c.call("Target.closeTarget", { targetId: "P1" })).result.success, true);
  const exit = await Promise.race([c.exited, sleep(3000).then(() => "did-not-exit")]);
  assert.deepEqual(exit, { code: 0, signal: null });
  const closed = c.records("close-target");
  assert.equal(closed.length, 1);
  assert.equal(closed[0].targetId, "P1");
  assert.equal(closed[0].running, true);
  assert.equal(c.records("no-pages").length, 1);
});

test("a cross-site iframe swap keeps one listed target, in either event order", async (t) => {
  const c = start(t);
  const browserSession = await autoAttachBrowser(c, { waitForDebugger: true });
  const pageSession = (await c.waitEvent(attached(browserSession, "P1"))).params.sessionId;
  await c.call("Runtime.runIfWaitingForDebugger", {}, pageSession);
  await c.call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, pageSession);

  await c.call("Test.spawnTarget", { type: "iframe", url: "http://a.example.test/frame", ownerId: "P1", id: "FR1" });
  const first = await c.waitEvent(attached(pageSession, "FR1"));
  await c.call("Runtime.runIfWaitingForDebugger", {}, first.params.sessionId);

  const listedFrameIds = async () =>
    (await c.call("Target.getTargets")).result.targetInfos.map((i) => i.targetId).filter((id) => id === "FR1");

  // attach-detach: the new session is announced before the old one's detach.
  await c.call("Test.swapIframe", { targetId: "FR1", order: "attach-detach" });
  const attachOne = await c.waitEvent(attached(pageSession, "FR1"), 2000);
  const detachOne = await c.waitEvent((m) => m.method === "Target.detachedFromTarget" && m.sessionId === pageSession, 2000);
  assert.equal(attachOne.params.sessionId !== first.params.sessionId, true);
  assert.equal(detachOne.params.sessionId, first.params.sessionId);
  assert.ok(c.messages.indexOf(attachOne) < c.messages.indexOf(detachOne));
  assert.deepEqual(await listedFrameIds(), ["FR1"]);

  // detach-attach: the reverse order for the same targetId.
  await c.call("Test.swapIframe", { targetId: "FR1", order: "detach-attach" });
  const detachTwo = await c.waitEvent((m) => m.method === "Target.detachedFromTarget" && m.sessionId === pageSession, 2000);
  const attachTwo = await c.waitEvent(attached(pageSession, "FR1"), 2000);
  assert.equal(detachTwo.params.sessionId, attachOne.params.sessionId);
  assert.ok(c.messages.indexOf(detachTwo) < c.messages.indexOf(attachTwo));
  // The swapped-in session starts held, as the auto-attacher's setting says.
  assert.equal(attachTwo.params.waitingForDebugger, true);
  assert.equal((await c.call("Test.state", { targetId: "FR1" })).result.target.held, true);
  assert.deepEqual(await listedFrameIds(), ["FR1"]);
  assert.equal(c.records("swap-iframe").length, 2);
});

test("a browser-level auto-attacher is handed the targets of EVERY context; a target session only its owner's children", async (t) => {
  const c = start(t);
  const browserSession = await autoAttachBrowser(c);
  await c.waitEvent(attached(browserSession, "P1"));

  // A page a bot opened in a context of its own. A browser-level auto-attach reports it — that
  // is what a real Chromium does, and without it no browser-level guard could ever see such a
  // page. The context is part of the announcement, not a filter on it.
  const contextId = (await c.call("Target.createBrowserContext")).result.browserContextId;
  const { targetId } = (await c.call("Target.createTarget", { url: "about:blank", browserContextId: contextId })).result;
  const announce = await c.waitEvent(attached(browserSession, targetId));
  assert.equal(announce.params.targetInfo.browserContextId, contextId);

  // That page's own session is a target session: it is handed that target's children, and a
  // child with an owner is never announced to a browser-level session (control below).
  const pageSession = announce.params.sessionId;
  await c.call("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }, pageSession);
  const frame = (await c.call("Test.spawnTarget", { type: "iframe", url: "https://x.example.test/frame", ownerId: targetId })).result;
  await c.waitEvent(attached(pageSession, frame.targetId));
  await assert.rejects(c.waitEvent(attached(browserSession, frame.targetId), 200));
});

