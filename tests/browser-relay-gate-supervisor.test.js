/**
 * The SUPERVISOR side of the browser gate (plan revision 5.1, rows 1, 2, 3, 4, 5 and 7;
 * section 2 step 5 "Verify and stop path").
 *
 * Everything the gate's stop path needs lives in the same file as the relay
 * (bundles/browser/cdp-relay.mjs) but in the OTHER process: the root supervisor that owns
 * Chromium. Six things are asserted here:
 *
 *  - the KILL LINE. fd 5 stays open for the relay's life; after `ready` the supervisor keeps
 *    one line reader on it, accepts `kill`, and SIGKILLs Chromium's whole process group on
 *    that line or on EOF of fd 5 — at once, in every supervisor state, independent of the
 *    relay's `exit` event and its 500 ms grace. `closing` is the one other line, and it
 *    softens EOF only: it says Browser.close went out after a clean scan, so Chromium's own
 *    exit is waited for inside the stop budget instead of being SIGKILLed on the way out.
 *  - the HOLDER. A non-reading child of the supervisor (`node cdp-relay.mjs --holder`, its
 *    own process group, Chromium's pipe on fds 3/4) keeps the browser from seeing pipe EOF
 *    while the supervisor reacts, and is SIGKILLed only after Chromium is confirmed gone.
 *  - RESTORE. On every launch, before Chromium starts, the profile's session state is
 *    removed and its startup choice is `session.restore_on_startup` 5 — unconditionally, with
 *    no read of `profile.exit_type` (the delivered `markProfileExitClean` only acts on a
 *    "Crashed" record, which a short-uptime SIGKILL never leaves; that is the CONTROL).
 *  - the STOP BUDGET, `cleanupMs + closeTimeoutMs + 2000`, with the entrypoint and compose
 *    outlasting it.
 *  - SIGTERM's TIMING. The same cleanup-first stop, signalled the instant the ready file appears
 *    and before the ready line at all: the first closes Chromium through the relay and exits 0,
 *    the second stops at once, exits 0, and leaves neither Chromium nor its holder behind.
 *
 * The Chromium stand-in is tests/fixtures/fake-chromium-gate.mjs (it answers the gate's
 * commands), spawned through the existing CROW_CDP_CHROMIUM_ARGV seam; the supervisor and
 * the relay are the real ones, with CROW_CDP_RELAY_UID/GID set to this process's ids so no
 * root is needed. Everything is timed with short caps (CROW_CDP_CLEANUP_BUDGET_MS,
 * CROW_CDP_CLOSE_TIMEOUT_MS), so no single run takes more than a second or two.
 *
 * No docker, no real Chromium, no network beyond loopback. Every wait is bounded, and the
 * caps are short, so each run finishes in a second or two: the bounds are what make a red
 * run FAIL rather than hang, which matters while the feature is missing.
 *
 * What counts as evidence, stated so nothing here is over-read: where a test says the browser
 * died BY the group kill, the evidence is the supervisor's own `killing the browser group`
 * line (plus, in the stop-path test, a non-zero supervisor exit). The stand-in has no exit
 * hook and the kernel does not publish a reaped child's signal through /proc, so no test in
 * this file claims a signal number it cannot see.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, readlinkSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import net from "node:net";
import WebSocket from "ws";
import { readTrace } from "./fixtures/read-trace.mjs";

const RELAY = fileURLToPath(new URL("../bundles/browser/cdp-relay.mjs", import.meta.url));
const FIXTURE = fileURLToPath(new URL("./fixtures/fake-chromium-gate.mjs", import.meta.url));
const ENTRYPOINT = fileURLToPath(new URL("../bundles/browser/entrypoint.sh", import.meta.url));
const COMPOSE = fileURLToPath(new URL("../bundles/browser/docker-compose.yml", import.meta.url));

/** 64 hex characters, the shape the manifest's hex32 mint produces. */
const TOKEN = "5c1d7a".repeat(10) + "beef";

/** The guard's init-script marker: the gate counts a main-world script that contains it. */
const MARKER = "crow-private-address-guard:v1";
/** Playwright wraps every init script, so the marker is never the first line of `source`. */
const MARKER_WRAPPED = `(() => {\n  // ${MARKER}\n})();`;

/** This process's uid/gid: the "gateway uid" in these tests (the supervisor drops to it). */
const ME_UID = typeof process.getuid === "function" ? process.getuid() : 0;
const ME_GID = typeof process.getgid === "function" ? process.getgid() : 0;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// /proc: process groups, parents, fds, and "is it gone"
// ---------------------------------------------------------------------------

const readText = (p) => { try { return readFileSync(p, "utf8"); } catch { return null; } };
const readLink = (p) => { try { return readlinkSync(p); } catch { return null; } };

/** Every fd target of one pid (`socket:[n]`, `/path`, …), or [] when unreadable. */
function fdTargets(pid) {
  const out = [];
  let fds = [];
  try { fds = readdirSync(`/proc/${pid}/fd`); } catch { return out; }
  for (const fd of fds) { const t = readLink(`/proc/${pid}/fd/${fd}`); if (t) out.push(t); }
  return out;
}

/**
 * One whitespace-separated field of /proc/<pid>/stat, 1-based as the kernel numbers them.
 * `comm` is parenthesised and may itself contain spaces, so the split starts after the
 * LAST ")" — the same shape the relay's own `chromiumIsGone` reads.
 */
function statField(pid, n) {
  const text = readText(`/proc/${pid}/stat`);
  if (!text) return null;
  const close = text.lastIndexOf(")");
  if (close < 0) return null;
  const fields = text.slice(close + 2).trim().split(/\s+/); // field 3 onwards
  return fields[n - 3] ?? null;
}

const pgidOf = (pid) => { const v = statField(pid, 5); return v === null ? null : Number(v); };
const ppidOf = (pid) => { const v = statField(pid, 4); return v === null ? null : Number(v); };

/**
 * Gone means "no /proc entry, or a reaped-pending zombie". `kill -0` alone is not enough: a
 * zombie the supervisor has not reaped yet still answers it.
 */
function processGone(pid) {
  const state = statField(pid, 3);
  return state === null || state === "Z" || state === "X";
}

/** True once `pid` is gone; polls, so a zombie that lingers a moment does not fail the wait. */
async function waitGone(pid, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (processGone(pid)) return true;
    await sleep(10);
  }
  return processGone(pid);
}

/** `kill -0 -<pgid>`: is ANY process of that group still there? ESRCH is the only "gone". */
function groupAlive(pgid) {
  try { process.kill(-pgid, 0); return true; } catch (err) { return err.code !== "ESRCH"; }
}

/** Every direct child of one pid, for a failure message (never for the lookup itself). */
function childPidsOf(parentPid) {
  const out = [];
  let names = [];
  try { names = readdirSync("/proc"); } catch { return out; }
  for (const name of names) {
    if (!/^\d+$/.test(name)) continue;
    if (ppidOf(Number(name)) === parentPid) out.push(Number(name));
  }
  return out;
}

/**
 * The supervisor's holder children: a direct child whose argv carries `--holder`. The
 * lookup is by argv, never by "a child of the supervisor": Chromium and the relay are its
 * children too, and the holder is the one thing that must not be confused with either.
 */
function holderChildrenOf(parentPid) {
  const out = [];
  let names = [];
  try { names = readdirSync("/proc"); } catch { return out; }
  for (const name of names) {
    if (!/^\d+$/.test(name)) continue;
    const pid = Number(name);
    if (ppidOf(pid) !== parentPid) continue;
    const argv = (readText(`/proc/${pid}/cmdline`) || "").split("\0").filter(Boolean);
    if (!argv.includes("--holder")) continue;
    out.push({ pid, argv });
  }
  return out;
}

// ---------------------------------------------------------------------------
// the relay's host contract: one HTTP read of /json/version, one gated WebSocket
// ---------------------------------------------------------------------------

function httpRaw(port, text, timeoutMs = 5000) {
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
  const [head, ...rest] = raw.split("\r\n\r\n");
  const lines = head.split("\r\n");
  const status = Number((lines[0] || "").split(" ")[1] || 0);
  const body = rest.join("\r\n\r\n");
  let json = null;
  try { json = JSON.parse(body); } catch { /* not JSON */ }
  return { status, body, json, raw };
}

function request(port, { path = "/json/version", token = null } = {}) {
  const lines = [`GET ${path} HTTP/1.1`, `Host: 127.0.0.1:${port}`, "Connection: close", "Accept: application/json"];
  if (token !== null) lines.push(`Authorization: Bearer ${token}`);
  return httpRaw(port, lines.join("\r\n") + "\r\n\r\n").then(parseReply);
}

/**
 * A gate client: the intent header the MCP sends (`X-Crow-Guard-Client: 1`) plus the relay's
 * bearer. `kill()` destroys the socket the way a SIGKILLed MCP's socket dies (no close
 * frame), which is what the cleanup trigger is defined on.
 */
function openClient(wsUrl, { token = TOKEN, guard = false } = {}) {
  const headers = { Authorization: `Bearer ${token}` };
  if (guard) headers["X-Crow-Guard-Client"] = "1";
  const ws = new WebSocket(wsUrl, { headers, perMessageDeflate: false, handshakeTimeout: 5000 });
  const messages = [];
  const waiters = [];
  ws.on("message", (data) => {
    const msg = JSON.parse(String(data));
    messages.push(msg);
    for (const w of [...waiters]) {
      if (!w.pred(msg)) continue;
      const at = waiters.indexOf(w);
      if (at >= 0) waiters.splice(at, 1);
      w.resolve(msg);
    }
  });
  ws.on("error", () => { /* 'close' follows */ });
  const client = {
    ws,
    messages,
    opened: new Promise((resolve, reject) => { ws.once("open", resolve); ws.once("error", reject); }),
    send: (obj) => ws.send(JSON.stringify(obj)),
    request(id, method, params = {}, sessionId) {
      client.send({ id, method, params, ...(sessionId ? { sessionId } : {}) });
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const at = waiters.findIndex((w) => w.id === id);
          if (at >= 0) waiters.splice(at, 1);
          reject(new Error(`no reply to ${method} (id ${id}); had ${JSON.stringify(messages.map((m) => m.method || `id=${m.id}`)).slice(0, 300)}`));
        }, 5000);
        waiters.push({ id, pred: (m) => m.id === id, resolve: (m) => { clearTimeout(timer); resolve(m); } });
      });
    },
    /** The first message (already arrived, or still to come) matching `pred`. */
    waitFor(pred, timeoutMs = 5000, label = "a message") {
      const found = messages.find(pred);
      if (found) return Promise.resolve(found);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const at = waiters.indexOf(entry);
          if (at >= 0) waiters.splice(at, 1);
          reject(new Error(`no ${label}; had ${JSON.stringify(messages.map((m) => m.method || `id=${m.id}`)).slice(0, 300)}`));
        }, timeoutMs);
        const entry = { pred, resolve: (m) => { clearTimeout(timer); resolve(m); } };
        waiters.push(entry);
      });
    },
    /** A SIGKILLed MCP: the socket goes away with no close frame and no warning. */
    kill() { try { ws.terminate(); } catch { /* gone */ } },
  };
  return client;
}

// ---------------------------------------------------------------------------
// a supervised run (`--supervise`), with the "gateway" uid set to this process's
// ---------------------------------------------------------------------------

/**
 * Caps for every run in this file, so nothing waits on a production number: the relay's
 * cleanup budget and the browser-close timeout only shorten how long a stop takes, they
 * never change what is asserted.
 */
const BASE_ENV = {
  CDP_PORT: "0",
  CROW_CDP_DEBUG: "0",
  // The stand-in exits when its last page closes, exactly like headful Chromium.
  FAKE_EXIT_ON_NO_PAGES: "1",
  CROW_CDP_CLOSE_TIMEOUT_MS: "1500",
  CROW_CDP_CLEANUP_BUDGET_MS: "600",
  // Never inherit a real profile from the environment: a restore case passes its own.
  CROW_CHROMIUM_PROFILE: "",
};

async function startSupervised(t, extraEnv = {}) {
  const dir = mkdtempSync(join(tmpdir(), "crow-cdp-sup-gate-"));
  writeFileSync(join(dir, "token"), TOKEN + "\n", { mode: 0o600 });
  let logs = "";
  const ctx = {
    dir,
    readyFile: join(dir, "ready"),
    tracePath: join(dir, "chromium.log"),
    logs: () => logs,
  };
  const child = spawn(process.execPath, [RELAY, "--supervise"], {
    env: {
      ...process.env,
      ...BASE_ENV,
      CROW_CDP_TOKEN_FILE: join(dir, "token"),
      CROW_CDP_READY_FILE: ctx.readyFile,
      CROW_CDP_CHROMIUM_ARGV: JSON.stringify([process.execPath, FIXTURE]),
      CROW_CDP_RELAY_UID: String(ME_UID),
      CROW_CDP_RELAY_GID: String(ME_GID),
      FAKE_CHROME_LOG: ctx.tracePath,
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
  ctx.stop = async () => {
    const pid = ctx.records("pid")[0]?.pid;
    if (pid) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
    try { child.kill("SIGKILL"); } catch { /* gone */ }
    await Promise.race([ctx.exited, sleep(3000)]);
    rmSync(dir, { recursive: true, force: true });
  };
  t.after(ctx.stop);
  return ctx;
}

/** The ready file the supervisor writes once the relay reports ready on fd 5. */
async function waitReady(ctx, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { return JSON.parse(readFileSync(ctx.readyFile, "utf8")); } catch { /* not yet */ }
    if (ctx.child.exitCode !== null) throw new Error("the supervisor exited before it was ready:\n" + ctx.logs());
    await sleep(50);
  }
  throw new Error("the supervisor never became ready:\n" + ctx.logs());
}

/** The fake Chromium's own pid, from the first line it writes. */
function chromiumPid(ctx) {
  const pid = ctx.records("pid")[0]?.pid;
  assert.ok(pid, "the fake Chromium recorded its pid");
  return pid;
}

/** The fake Chromium's pid, waiting for its first trace line (Chromium starts before the gate). */
async function waitChromiumPid(ctx, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const pid = ctx.records("pid")[0]?.pid;
    if (pid) return pid;
    if (ctx.child.exitCode !== null) throw new Error("the supervisor exited before Chromium started:\n" + ctx.logs());
    await sleep(5);
  }
  throw new Error("Chromium never started:\n" + ctx.logs());
}

/**
 * The ready file, read in a tight loop so a test can time a signal from the moment it appeared:
 * `at` is the file's own mtime, in epoch milliseconds.
 */
async function waitReadyFile(ctx, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const raw = readFileSync(ctx.readyFile, "utf8");
      return { info: JSON.parse(raw), at: statSync(ctx.readyFile).mtimeMs };
    } catch { /* not yet */ }
    if (ctx.child.exitCode !== null) throw new Error("the supervisor exited before it was ready:\n" + ctx.logs());
    await sleep(5);
  }
  throw new Error("the supervisor never became ready:\n" + ctx.logs());
}

/** The supervisor's group kill, as the supervisor logs it (the stop path's own evidence). */
const groupKillLines = (ctx) => ctx.logs().split("\n").filter((l) => l.includes("killing the browser group"));

/** Wait for the supervisor to exit, or null when it is still running after `ms`. */
const waitExit = (ctx, ms) => Promise.race([ctx.exited, sleep(ms).then(() => null)]);

/**
 * Wait until the fixture says one target runs, i.e. the gate has resumed it.
 */
async function waitRunning(client, targetId, timeoutMs = 6000) {
  const deadline = Date.now() + timeoutMs;
  let id = 100;
  let state = null;
  while (Date.now() < deadline) {
    const reply = await client.request(++id, "Test.state", { targetId });
    state = reply.result?.target ?? null;
    if (state && state.running === true) return state;
    await sleep(25);
  }
  assert.fail(`the page ${targetId} was never resumed (last state: ${JSON.stringify(state)})`);
}

/**
 * A gate client with a LIVE page whose navigation will not commit.
 *
 * The page is covered the way a Playwright guard covers one — the gate hands this client the
 * page's session, the client resumes it and then enables Fetch `*` plus the marker-bearing
 * main-world init script, so the gate resumes the page too — and only then is
 * `Test.setCommit false` set, so every later `Page.navigate` on it answers a loaderId that no
 * commit ever follows. The cleanup therefore navigates a resumed page and waits out its commit
 * budget, which is the shape that takes the stop path (a page the gate never resumed runs
 * nothing and is closed as it is, without a navigate at all).
 */
async function openClientWithNonCommittingPage(ctx, ready) {
  const version = await request(ready.port, { token: TOKEN });
  assert.equal(version.status, 200, version.raw.slice(0, 200));
  const client = openClient(version.json.webSocketDebuggerUrl, { guard: true });
  await client.opened;
  // The declaration half of "guard-bearing": the intent header (above) and Crow.guardReady.
  await client.request(1, "Crow.guardReady", { v: 1, exceptionsHash: "0".repeat(64) });
  // A guard auto-attaches at the browser level, which is how the gate hands it a page.
  await client.request(2, "Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });
  const spawned = await client.request(3, "Test.spawnTarget", { type: "page", url: "https://bot.example/never-commits" });
  const targetId = spawned.result?.targetId;
  assert.ok(targetId, "the page was created: " + JSON.stringify(spawned));
  const attach = await client.waitFor(
    (m) => m.method === "Target.attachedToTarget" && m.params?.targetInfo?.targetId === targetId,
    6000,
    `the attach event for ${targetId}`,
  );
  const sessionId = attach.params?.sessionId;
  assert.ok(sessionId, `the gate gave this client a session for ${targetId}`);
  // Playwright's order: resume first, then hook. The `*` pattern and the marker script are
  // what make this page covered, which is what makes the gate resume it.
  await client.request(4, "Runtime.runIfWaitingForDebugger", {}, sessionId);
  await client.request(5, "Fetch.enable", { handleAuthRequests: true, patterns: [{ urlPattern: "*", requestStage: "Request" }] }, sessionId);
  await client.request(6, "Page.addScriptToEvaluateOnNewDocument", { source: MARKER_WRAPPED }, sessionId);
  await waitRunning(client, targetId);
  await client.request(7, "Test.setCommit", { targetId, commit: false });
  return { client, targetId };
}

// ---------------------------------------------------------------------------
// 1. the holder child
// ---------------------------------------------------------------------------

test("the holder: a non-reading child of the supervisor, its own process group, Chromium's pipe on fds 3/4", async (t) => {
  const ctx = await startSupervised(t);
  const ready = await waitReady(ctx);
  const relayPid = ready.pid;
  const chromePid = chromiumPid(ctx);

  const holders = holderChildrenOf(ctx.child.pid);
  assert.equal(
    holders.length,
    1,
    `the supervisor keeps exactly one holder child (a child whose argv names --holder); children seen: ${childPidsOf(ctx.child.pid).join(", ")}`,
  );
  const holder = holders[0];
  assert.match(String(holder.argv[1] || ""), /cdp-relay\.mjs$/, `the holder is this same file, started with --holder (argv: ${holder.argv.join(" ")})`);

  // It holds Chromium's pipe: fd 3 and fd 4, both socket ends.
  for (const fd of [3, 4]) {
    const target = readLink(`/proc/${holder.pid}/fd/${fd}`);
    assert.match(String(target), /^socket:\[\d+\]$/, `the holder's fd ${fd} is a pipe end (the browser's CDP stream stays open past the relay's death)`);
  }

  // …and it is in its own process group: a SIGKILL aimed at Chromium's group must not take
  // it, and one aimed at it must not take the supervisor.
  const holderPgid = pgidOf(holder.pid);
  assert.notEqual(holderPgid, null, "the holder has a process group");
  assert.notEqual(holderPgid, pgidOf(ctx.child.pid), "the holder is not in the supervisor's process group");
  assert.notEqual(holderPgid, pgidOf(chromePid), "the holder is not in Chromium's process group");

  // The existing property still holds: the supervisor itself holds neither its old copies of
  // the pipe nor the relay's ends.
  const relayPipe = [readLink(`/proc/${relayPid}/fd/3`), readLink(`/proc/${relayPid}/fd/4`)];
  for (const target of relayPipe) assert.match(String(target), /^socket:\[\d+\]$/, "the relay's fds 3/4 are the pipe's socket ends");
  const supFds = fdTargets(ctx.child.pid);
  for (const target of relayPipe) assert.ok(!supFds.includes(target), `the supervisor still holds the relay's ${target}`);
  for (const fd of [3, 4]) {
    const target = readLink(`/proc/${chromePid}/fd/${fd}`);
    assert.match(String(target), /^socket:\[\d+\]$/, `Chromium's fd ${fd} is a pipe end`);
    assert.ok(!supFds.includes(target), `the supervisor still holds Chromium's ${target}`);
  }
  // The holder keeps the SAME side of each socketpair as the relay — the supervisor's own end,
  // handed to both children — so their fd 3/4 inodes are EQUAL. A socketpair's two ends are
  // different sockets, and it is only Chromium's end that differs; the holder's job is to keep
  // the supervisor's end open past the relay's death, so it must NOT be a copy of Chromium's
  // ends (Chromium already holds those, so they would keep nothing open). Sharing the end is
  // safe because the holder never reads it, so it cannot race the relay for frames. Read all
  // three from /proc here rather than trusting either process to report it.
  for (const fd of [3, 4]) {
    const relayEnd = readLink(`/proc/${relayPid}/fd/${fd}`);
    const holderEnd = readLink(`/proc/${holder.pid}/fd/${fd}`);
    const chromeEnd = readLink(`/proc/${chromePid}/fd/${fd}`);
    assert.match(String(holderEnd), /^socket:\[\d+\]$/, `the holder's fd ${fd} is a socket end`);
    assert.equal(
      holderEnd,
      relayEnd,
      `the holder's fd ${fd} is the supervisor's side of the pipe, the same socket the relay holds (holder ${holderEnd}, relay ${relayEnd})`,
    );
    assert.notEqual(holderEnd, chromeEnd, `the holder's fd ${fd} is not Chromium's own end of the pair (holder ${holderEnd}, Chromium ${chromeEnd})`);
  }

  // A graceful stop leaves no holder behind: it is SIGKILLed after Chromium is confirmed
  // gone, and in every finish().
  ctx.child.kill("SIGTERM");
  const exit = await waitExit(ctx, 20000);
  assert.ok(exit, "the supervisor stops on SIGTERM:\n" + ctx.logs());
  assert.equal(exit.code, 0, "a clean stop still exits 0: " + ctx.logs());
  assert.equal(await waitGone(holder.pid, 4000), true, `the holder (pid ${holder.pid}) is gone with the supervisor`);
  assert.equal(await waitGone(chromePid, 4000), true, "and so is Chromium");
});

// CONTROL: the holder lookup is by `--holder` in argv, not "any child".
test("CONTROL: the holder lookup matches --holder in argv and not a plain child", async (t) => {
  const plain = spawn(process.execPath, ["-e", "setTimeout(() => {}, 5000)"], { stdio: "ignore" });
  const flagged = spawn(process.execPath, ["-e", "setTimeout(() => {}, 5000)", "--", "--holder"], { stdio: "ignore" });
  t.after(() => {
    try { plain.kill("SIGKILL"); } catch { /* gone */ }
    try { flagged.kill("SIGKILL"); } catch { /* gone */ }
  });
  const deadline = Date.now() + 5000;
  let found = [];
  while (Date.now() < deadline) {
    found = holderChildrenOf(process.pid).map((h) => h.pid);
    if (found.includes(flagged.pid) && !found.includes(plain.pid)) break;
    await sleep(25);
  }
  assert.ok(found.includes(flagged.pid), `a child whose argv names --holder is found (lookup saw ${JSON.stringify(found)})`);
  assert.equal(found.includes(plain.pid), false, "a plain child of the same parent is not mistaken for the holder");
});

// ---------------------------------------------------------------------------
// 2. the kill line, and the stop path it triggers
// ---------------------------------------------------------------------------

test("the stop path: a page that never commits is never closed, and the group is killed before the pipe closes", async (t) => {
  const ctx = await startSupervised(t);
  const ready = await waitReady(ctx);
  const chromePid = chromiumPid(ctx);
  const chromePgid = pgidOf(chromePid);
  assert.equal(chromePgid, chromePid, "the fake Chromium leads its own process group: the group is what the supervisor must kill");

  const { client, targetId } = await openClientWithNonCommittingPage(ctx, ready);
  // CONTROL: the page this test is about is live. A page the gate never resumed is closed as
  // it is, with no navigate to wait on, and would take a different outcome entirely.
  assert.equal(
    ctx.records("resumed").some((r) => r.targetId === targetId),
    true,
    `the page ${targetId} was resumed: it is a live page the cleanup navigates`,
  );

  // The guard client dies the way a SIGKILLed MCP dies: no close frame, no cleanup of its
  // own. That is the cleanup trigger.
  client.kill();

  const exit = await waitExit(ctx, 9000);
  assert.ok(exit, `the supervisor exits after the stop path (nothing happened for 9 s; log:\n${ctx.logs()})`);
  assert.equal(typeof exit.code, "number", `the supervisor exited on its own, not by a signal: ${ctx.logs()}`);
  assert.notEqual(exit.code, 0, `the stop path is a non-zero exit, so the container recycles: ${ctx.logs()}`);

  // The kill line reached the supervisor: it kills the group itself, once. A group that
  // died of pipe EOF instead would have ended Chromium in the fixture's own `end` handler,
  // which is why the supervisor's own kill has to be the observable.
  const kills = groupKillLines(ctx);
  assert.equal(
    kills.length,
    1,
    `the supervisor logs its group kill exactly once (a second line would mean two stop paths raced): ${JSON.stringify(kills)}`,
  );

  assert.equal(await waitGone(chromePid, 4000), true, "Chromium's pid is gone");
  assert.equal(groupAlive(chromePgid), false, `kill -0 -${chromePgid} fails: the whole group is gone, not only the browser process`);

  // Nothing was closed on the way: a page that never committed is not a page a close may
  // follow (section 4 step 4), and the stop path is not a graceful close.
  assert.deepEqual(
    ctx.records("close-target").filter((r) => r.targetId === targetId),
    [],
    "no Target.closeTarget for the page that never committed",
  );
  assert.deepEqual(ctx.records("close-target"), [], "no Target.closeTarget at all on the stop path");
  assert.equal(ctx.records("browser-close").length, 0, "no Browser.close on the stop path (it skips the cookie commit on purpose)");
  assert.equal(ctx.records("recv").some((r) => r.method === "Browser.close"), false, "…and Browser.close never reached the pipe");
  assert.equal(ctx.records("exiting").length, 0, "the fixture never took its own exit path: it did not outlive the group kill");
});

// CONTROL: the pre-existing behaviour — a relay that dies takes Chromium's group with it.
// It must keep holding, so the assertions above are about the new path and not about
// "something in this harness always reaps the fake".
test("CONTROL: SIGKILL only the relay — the supervisor still takes Chromium's group down", async (t) => {
  const ctx = await startSupervised(t);
  const ready = await waitReady(ctx);
  const chromePid = chromiumPid(ctx);
  process.kill(ready.pid, "SIGKILL");
  assert.equal(await waitGone(chromePid, 5000), true, `Chromium's pid ${chromePid} disappears after the relay is killed (log:\n${ctx.logs()})`);
  const exit = await waitExit(ctx, 8000);
  assert.ok(exit, "the supervisor exits too (a relay that dies is a dead container):\n" + ctx.logs());
});

// ---------------------------------------------------------------------------
// 3. EOF on fd 5 after ready is a kill
// ---------------------------------------------------------------------------

test("EOF on fd 5 kills the group at once — not after the old 500 ms grace", async (t) => {
  const ctx = await startSupervised(t);
  const ready = await waitReady(ctx);
  const relayPid = ready.pid;
  const chromePid = chromiumPid(ctx);

  const started = Date.now();
  process.kill(relayPid, "SIGKILL");
  const gone = await waitGone(chromePid, 3000);
  const elapsed = Date.now() - started;

  assert.equal(gone, true, `Chromium's pid ${chromePid} is gone after the relay died (log:\n${ctx.logs()})`);
  assert.ok(
    elapsed < 400,
    `the group kill came ${elapsed} ms after the relay's death: EOF on fd 5 is itself a kill signal and is acted on at once, not after the ` +
      "500 ms grace the relay's `exit` path sits behind",
  );
  // EOF and the relay's exit both arrive here; the kill must be the supervisor's own, on the
  // fd 5 path — today Chromium happens to exit by itself on the pipe EOF, so the log line is
  // what tells the two apart.
  assert.ok(
    groupKillLines(ctx).length >= 1,
    `the group kill is the supervisor's (its own "killing the browser group"), not the browser's pipe-EOF exit: ${JSON.stringify(ctx.logs().slice(-800))}`,
  );
});

// ---------------------------------------------------------------------------
// 3b. a graceful close: `closing` on fd 5, and Chromium's own exit
// ---------------------------------------------------------------------------

/**
 * A Chromium that closes its pipe and exits a second later with 7, the way a real browser
 * leaves while it commits its cookie store: `browser-close` is the last thing it puts on the
 * pipe, and the delay is the window a group kill would land in.
 */
const CLOSING_ENV = { FAKE_CHROME_CLOSE_EXIT_MS: "1000", FAKE_CHROME_CLOSE_EXIT_CODE: "7" };

/** A plain (non-guard) client on a supervised relay, and one `Browser.close` from it. */
async function sendCleanBrowserClose(ready) {
  const version = await request(ready.port, { token: TOKEN });
  assert.equal(version.status, 200, version.raw.slice(0, 200));
  const client = openClient(version.json.webSocketDebuggerUrl);
  await client.opened;
  client.send({ id: 1, method: "Browser.close", params: {} });
  return client;
}

test("a clean Browser.close: the relay's closing line keeps Chromium alive for its own exit", async (t) => {
  const ctx = await startSupervised(t, CLOSING_ENV);
  const ready = await waitReady(ctx);
  const chromePid = chromiumPid(ctx);
  await sendCleanBrowserClose(ready);

  const exit = await waitExit(ctx, 12000);
  assert.ok(exit, `the supervisor exits after the close (log:\n${ctx.logs()})`);
  assert.match(ctx.logs(), /graceful close on fd 5/, `the supervisor saw the closing line: ${JSON.stringify(ctx.logs().slice(-800))}`);
  assert.equal(ctx.records("browser-close").length, 1, "the browser was asked to close over the pipe, once");
  // The fixture's own exit code, which only reaches the supervisor because the process was
  // allowed to finish: a SIGKILLed browser leaves no code at all.
  assert.equal(exit.code, 7, `Chromium exited by itself and the supervisor exits with its code (log:\n${ctx.logs()})`);
  assert.deepEqual(ctx.records("closed-by-itself").map((r) => r.code), [7], "Chromium reached its own exit");
  assert.deepEqual(groupKillLines(ctx), [], `no group kill on a graceful close: ${JSON.stringify(groupKillLines(ctx))}`);
  assert.equal(await waitGone(chromePid, 4000), true, "Chromium's pid is gone");
});

// CONTROL: nothing softened — a relay that dies with no `closing` line still takes the group
// down at once, on the same Chromium that would have exited by itself.
test("CONTROL: with no closing line, EOF on fd 5 still kills the group at once", async (t) => {
  const ctx = await startSupervised(t, CLOSING_ENV);
  const ready = await waitReady(ctx);
  const chromePid = chromiumPid(ctx);

  const started = Date.now();
  process.kill(ready.pid, "SIGKILL");
  assert.equal(await waitGone(chromePid, 3000), true, `Chromium's pid ${chromePid} is gone after the relay died (log:\n${ctx.logs()})`);
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 900, `the group kill came ${elapsed} ms after the relay's death, not after a stop budget`);
  assert.deepEqual(ctx.records("closed-by-itself"), [], "the browser never reached its own exit");
  assert.ok(groupKillLines(ctx).length >= 1, `the group kill is the supervisor's: ${JSON.stringify(ctx.logs().slice(-600))}`);
});

// CONTROL: `closing` does not disarm the kill, it only defers it — a browser that closes its
// pipe and then never exits is SIGKILLed when the stop budget runs out.
test("CONTROL: a Chromium that never exits after the closing line is killed when the stop budget runs out", async (t) => {
  // It closes its pipe at once (so the relay exits) and then sits on a 60 s timer.
  const ctx = await startSupervised(t, { FAKE_CHROME_CLOSE_EXIT_MS: "60000" });
  const ready = await waitReady(ctx);
  const chromePid = chromiumPid(ctx);
  const started = Date.now();
  await sendCleanBrowserClose(ready);

  const exit = await waitExit(ctx, 20000);
  assert.ok(exit, `the supervisor exits (log:\n${ctx.logs()})`);
  assert.deepEqual(ctx.records("closed-by-itself"), [], "the browser never exited by itself");
  assert.ok(groupKillLines(ctx).length >= 1, `the group was killed: ${JSON.stringify(ctx.logs().slice(-600))}`);
  const elapsed = Date.now() - started;
  assert.ok(elapsed >= 3500, `the kill waited for the stop budget (600 + 1500 + 2000 ms): ${elapsed} ms`);
  assert.notEqual(exit.code, 0, "a browser that had to be killed is not a clean stop");
  assert.equal(await waitGone(chromePid, 4000), true, "Chromium's pid is gone");
});

// CONTROL: EOF is the only thing `closing` softens — a `kill` line, and any other line, is the
// stop path in the closing state too.
test("CONTROL: a kill line, or any other line, still kills after closing; EOF alone waits", async () => {
  const { relayReportAction } = await import("../bundles/browser/cdp-relay.mjs");
  assert.equal(relayReportAction("kill", { closing: false }), "kill", "a kill line before closing");
  assert.equal(relayReportAction("kill", { closing: true }), "kill", "a kill line AFTER closing still kills");
  assert.equal(relayReportAction("KILL", { closing: true }), "kill", "…and so does any other line in the closing state");
  assert.equal(relayReportAction("closing", { closing: false }), "closing", "the closing line is its own action");
  assert.equal(relayReportAction(null, { closing: false }), "kill", "EOF with no closing line kills at once");
  assert.equal(relayReportAction(null, { closing: true }), "wait", "EOF after closing waits for Chromium");
});

// ---------------------------------------------------------------------------
// 4. any other line on fd 5 (static: a stand-in relay would be the only other way in)
// ---------------------------------------------------------------------------

/**
 * The line-reader shape, read out of the supervisor's own code: an exact `kill` comparison,
 * and — within a few hundred characters of it — a log line naming the group kill plus a call
 * that kills. Comments are stripped first: prose about the line is not a reader for it.
 */
function killLineReaderShape(source) {
  const code = codeOnly(source);
  const exactKillCompare = /(===|==|!==|!=)\s*"kill"/.test(code);
  const logAt = code.indexOf("killing the browser group");
  const window = logAt >= 0 ? code.slice(Math.max(0, logAt - 1200), logAt + 1200) : "";
  // "Logs and kills": the log line and, beside it, a call that kills (whatever the helper is
  // named). The alternative — "else it is ignored" — has no kill within reach of the line.
  const logsAndKills = logAt >= 0 && /\w*[Kk]ill\w*\s*\(/.test(window);
  const readerOnFd5 = /stdio\[5\]/.test(code);
  return { exactKillCompare, logsAndKills, readerOnFd5 };
}

/** Whole `/* … *\/` blocks and `//` lines removed: assertions are about what runs. */
function codeOnly(source) {
  return String(source)
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .filter((l) => !/^\s*\/\//.test(l))
    .join("\n");
}

test("fd 5 after ready accepts exactly the line `kill`, and anything else is logged and kills too", () => {
  const shape = killLineReaderShape(readFileSync(RELAY, "utf8"));
  assert.equal(shape.exactKillCompare, true, 'the supervisor compares the line to exactly "kill": the one word the relay may send');
  assert.equal(
    shape.logsAndKills,
    true,
    'any other line is a broken relay: it is logged ("killing the browser group") and kills, never ignored',
  );
  assert.equal(shape.readerOnFd5, true, "the supervisor's own reader on the relay's report pipe (fd 5) is still there to be extended");
});

// CONTROL: the shape check is not vacuous — it fails on a source without the comparison and
// without the log-and-kill.
test("CONTROL: the line-reader shape check fails on a source that lacks it", () => {
  const source = readFileSync(RELAY, "utf8");
  assert.equal(killLineReaderShape(source.replace(/"kill"/g, '"KILL"')).exactKillCompare, false, "no exact `kill` comparison");
  assert.equal(
    killLineReaderShape(source.replace(/killing the browser group/g, "stopping the browser")).logsAndKills,
    false,
    "no log line for the group kill",
  );
  assert.equal(
    killLineReaderShape('function onLine(line) { if (line === "kill") go(); log("unexpected"); go(); }').logsAndKills,
    false,
    "a reader that logs but names no group kill does not pass",
  );
  // …and a reader that DOES compare `kill` and log-and-kill passes both shape checks, so the
  // checks above are about the source and not about a shape nothing could satisfy.
  const good = [
    "function onReportLine(line) {",
    '  const text = line.trim();',
    '  if (text === "kill") { killGroup(); return; }',
    "  log(`unexpected line on fd 5 (${text.length} bytes): killing the browser group`);",
    '  killChromiumGroup("SIGKILL");',
    "}",
  ].join("\n");
  const shape = killLineReaderShape(good);
  assert.equal(shape.exactKillCompare, true, "a real reader compares the line to `kill`");
  assert.equal(shape.logsAndKills, true, "…and logs and kills on anything else");
});

// ---------------------------------------------------------------------------
// 5. restore: unconditional, before Chromium starts
// ---------------------------------------------------------------------------

/** A fresh profile DIRECTORY (removed with the test). */
function makeProfileDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "crow-cdp-sup-profile-"));
  t.after(() => { try { rmSync(dir, { recursive: true, force: true }); } catch { /* gone */ } });
  return dir;
}

const prefsFile = (profile) => join(profile, "Default", "Preferences");

/** The session state a launch could restore: Default/Sessions/* plus the four beside it. */
const SESSION_FILE_NAMES = ["Session_13300000000000001", "Session_13300000000000002"];
const SIDE_SESSION_NAMES = ["Current Session", "Current Tabs", "Last Session", "Last Tabs"];

/**
 * A profile with its session state on disk and `prefs` in Default/Preferences. `prefs` may be
 * an object (written as JSON), a raw string (an unparseable file), or null (no file at all).
 */
function profileWith(t, prefs) {
  const profile = makeProfileDir(t);
  const def = join(profile, "Default");
  mkdirSync(join(def, "Sessions"), { recursive: true });
  const files = [];
  for (const name of SESSION_FILE_NAMES) {
    const p = join(def, "Sessions", name);
    writeFileSync(p, "a saved session a launch could restore");
    files.push(p);
  }
  for (const name of SIDE_SESSION_NAMES) {
    const p = join(def, name);
    writeFileSync(p, "a saved session a launch could restore");
    files.push(p);
  }
  let raw = null;
  if (prefs !== null) {
    raw = typeof prefs === "string" ? prefs : JSON.stringify(prefs);
    writeFileSync(join(def, "Preferences"), raw);
  }
  return { profile, def, prefs: prefsFile(profile), raw, files };
}

/** The profile as Chromium saw it the moment it started (the fake's own startup read). */
function profileAtLaunch(ctx) {
  const snap = ctx.records("profile")[0];
  assert.ok(snap, "the fake Chromium read the profile when it started");
  return snap;
}

test("restore: every launch clears the saved session and points startup at the new tab page, without reading exit_type", async (t) => {
  const problems = [];
  const check = async (label, fn) => {
    try {
      await fn();
    } catch (err) {
      problems.push(`${label}: ${(err && err.message) || String(err)}`);
    }
  };

  /** The shape a ~10 s SIGKILL leaves (Chromium writes the exit record periodically). */
  const SHORT_UPTIME = { profile: {}, session: { restore_on_startup: 1 } };
  /** The shape the exit cleanup's Browser.crash leaves after a long uptime. */
  const LONG_UPTIME = {
    profile: { exit_type: "Crashed", exited_cleanly: false, name: "Person 1" },
    session: { restore_on_startup: 1, startup_urls: "https://operator.example/start" },
    foo: 1,
  };

  // The CONTROL runs FIRST, so it is measured even while the cases are red: the delivered
  // markProfileExitClean is gated on `profile.exit_type === "Crashed"`, and a short-uptime
  // SIGKILL leaves no exit_type at all — which is exactly why the restore handling is now
  // unconditional instead of being an extra branch of that function.
  await check("CONTROL markProfileExitClean on a profile with no exit_type", async () => {
    const m = await import("../bundles/browser/cdp-relay.mjs");
    const p = profileWith(t, SHORT_UPTIME);
    const before = readFileSync(p.prefs, "utf8");
    m.markProfileExitClean(p.profile);
    assert.equal(readFileSync(p.prefs, "utf8"), before, "the delivered markProfileExitClean leaves a profile with no exit_type byte for byte alone");
    assert.equal(JSON.parse(before).session.restore_on_startup, 1, "…so restore_on_startup stays 1 (the tabs would come back)");
    for (const f of p.files) assert.equal(existsSync(f), true, "…and every saved session file is still there");
  });

  /** Launch supervised and assert the launch-time snapshot is the cleaned one. */
  const expectCleaned = async (p, label) => {
    const ctx = await startSupervised(t, { CROW_CHROMIUM_PROFILE: p.profile });
    await waitReady(ctx);
    const at = profileAtLaunch(ctx);
    assert.equal(at.path, p.prefs, `${label}: the fake read the profile under its --user-data-dir`);
    assert.ok(at.profile, `${label}: Chromium had a Preferences to parse at launch (saw ${JSON.stringify(String(at.raw).slice(0, 200))})`);
    assert.equal(at.profile?.session?.restore_on_startup, 5, `${label}: session.restore_on_startup is 5 (the new tab page) before Chromium starts (saw ${at.raw})`);
    assert.equal(at.profile?.profile?.exit_type, "Normal", `${label}: the exit record says "Normal" (saw ${at.raw})`);
    assert.equal(at.profile?.profile?.exited_cleanly, true, `${label}: and exited_cleanly is true (saw ${at.raw})`);
    // The on-disk file says the same as the launch snapshot.
    const onDisk = JSON.parse(readFileSync(p.prefs, "utf8"));
    assert.equal(onDisk?.session?.restore_on_startup, 5, `${label}: the setting on disk is the new tab page`);
    for (const f of p.files) assert.equal(existsSync(f), false, `${label}: ${f} was removed`);
    // The argv switch the bubble is hidden with stays.
    const argv = ctx.records("argv")[0]?.argv || [];
    assert.ok(argv.includes("--hide-crash-restore-bubble"), `${label}: --hide-crash-restore-bubble is still in Chromium's argv (${argv.join(" ")})`);
    return at;
  };

  // (1) SHORT-uptime shape: no exit_type at all.
  await check("SHORT-uptime shape (no exit_type, restore_on_startup 1)", async () => {
    const p = profileWith(t, SHORT_UPTIME);
    const at = await expectCleaned(p, "SHORT-uptime shape");
    assert.equal(at.profile.profile?.exit_type, "Normal", "the missing record is written as a clean one");
  });

  // (2) LONG-uptime / crashed shape: same result, and the rest of the file survives.
  await check("long-uptime (Crashed) shape", async () => {
    const p = profileWith(t, LONG_UPTIME);
    const at = await expectCleaned(p, "Crashed shape");
    assert.equal(at.profile.session.startup_urls, "https://operator.example/start", "the other keys of `session` survive");
    assert.equal(at.profile.foo, 1, "and the rest of the file");
    assert.equal(at.profile.profile.name, "Person 1", "and the other keys of `profile`");
  });

  // (3) restore_on_startup 3 ("open a specific page") is 5 as well: the rule is
  // unconditional, and the cost (the operator's own tabs are no longer restored, ever) is
  // the documented trade.
  await check("restore_on_startup 3 is set to 5 as well", async () => {
    const p = profileWith(t, {
      profile: { exit_type: "Normal", exited_cleanly: true },
      session: { restore_on_startup: 3, startup_urls: "https://operator.example/start" },
    });
    const at = await expectCleaned(p, "restore_on_startup 3");
    assert.equal(at.profile.session.startup_urls, "https://operator.example/start", "the operator's start pages are kept; only the choice changes");
  });

  // (4) No Preferences file: nothing is created, nothing throws (waitReady would have
  // thrown), and the session state still goes.
  await check("no Preferences file at all", async () => {
    const p = profileWith(t, null);
    const ctx = await startSupervised(t, { CROW_CHROMIUM_PROFILE: p.profile });
    await waitReady(ctx);
    assert.equal(existsSync(p.prefs), false, "no Default/Preferences file is created for a profile that has none");
    assert.equal(profileAtLaunch(ctx).raw, null, "there was nothing for Chromium to read");
    for (const f of p.files) assert.equal(existsSync(f), false, `${f} was removed (the removal does not depend on a Preferences file)`);
  });

  // (5) Unparseable Preferences: the bytes are left alone, the session files still go.
  await check("unparseable Preferences", async () => {
    const garbage = "{not json at all";
    const p = profileWith(t, garbage);
    const ctx = await startSupervised(t, { CROW_CHROMIUM_PROFILE: p.profile });
    await waitReady(ctx);
    assert.equal(readFileSync(p.prefs, "utf8"), garbage, "an unparseable Preferences is left byte for byte alone");
    assert.equal(profileAtLaunch(ctx).raw, garbage, "…and was still garbage when Chromium launched");
    for (const f of p.files) assert.equal(existsSync(f), false, `${f} was removed even though the Preferences could not be rewritten`);
  });

  assert.deepEqual(problems, [], `restore has to be unconditional (r5.1 row 1):\n${problems.join("\n")}`);
});

// ---------------------------------------------------------------------------
// 6. the stop budget: supervision, entrypoint and compose have to line up
// ---------------------------------------------------------------------------

/** The seconds the entrypoint's own shutdown() waits for the supervisor before SIGKILLing it. */
function entrypointShutdownWaitSeconds(shell) {
  const at = shell.indexOf("shutdown() {");
  assert.notEqual(at, -1, "the entrypoint still has a shutdown() that stops the supervisor");
  const end = shell.indexOf("\n}\n", at);
  assert.notEqual(end, -1, "…and this test can read its body");
  const body = shell.slice(at, end);
  const seq = /\bseq 1 (\d+)/.exec(body);
  const nap = /\bsleep ([0-9.]+)/.exec(body);
  const timeout = /\btimeout (\d+)\b/.exec(body);
  const candidates = [];
  // A counted loop with a sleep is the shape it has today; a bare sleep or `timeout N` are
  // the other two ways the same wait can be written.
  if (seq && nap) candidates.push(Number(seq[1]) * Number(nap[1]));
  else if (nap) candidates.push(Number(nap[1]));
  if (timeout) candidates.push(Number(timeout[1]));
  assert.ok(candidates.length > 0, `the wait is a sleep (a counted loop or a bare one) or a timeout (${JSON.stringify(body.slice(0, 200))})`);
  return Math.max(...candidates);
}

/**
 * The supervisor's SIGTERM budget statement: every `;`-statement that adds the 2 s margin to
 * closeTimeoutMs. Statements, not lines, so a budget written over several lines is still one
 * expression to this check.
 */
function stopBudgetStatements(source) {
  return codeOnly(source)
    .split(";")
    .map((s) => s.replace(/\s+/g, " ").trim())
    .filter((s) => /closeTimeoutMs/.test(s) && /\b(2000|2_000)\b/.test(s));
}

test("the supervisor's SIGTERM budget is cleanupMs + closeTimeoutMs + 2000, and the entrypoint and compose outlast it", () => {
  const relaySource = readFileSync(RELAY, "utf8");
  const code = codeOnly(relaySource);

  // (a) the cleanup cap exists, defaults to the relay's 5000 ms, and reaches the relay.
  const capLine = code.split("\n").find((l) => /CROW_CDP_CLEANUP_BUDGET_MS/.test(l) && /\bcap\(/.test(l));
  assert.ok(
    capLine,
    "capsFromEnv reads CROW_CDP_CLEANUP_BUDGET_MS: the supervisor's stop budget has to cover the relay's own cleanup, and that cap is the only number that bounds it",
  );
  assert.match(capLine, /\b(5000|5_000)\b/, `the cap defaults to 5000 ms, the relay's own default (${capLine.trim()})`);
  const envKeys = /const RELAY_ENV_KEYS = \[([\s\S]*?)\];/.exec(code);
  assert.ok(envKeys, "RELAY_ENV_KEYS is still a literal array this test can read");
  assert.ok(
    envKeys[1].includes("CROW_CDP_CLEANUP_BUDGET_MS"),
    "CROW_CDP_CLEANUP_BUDGET_MS is forwarded to the relay, so the supervisor's budget and the relay's cleanup cannot drift apart",
  );

  // (b) the stop budget adds all three terms, and it is a sum (a cleanup that finishes inside
  // its cap, then a close inside its own, then 2 s of slack).
  const budget = stopBudgetStatements(relaySource);
  assert.equal(budget.length, 1, `exactly one expression adds the 2 s margin to closeTimeoutMs (found ${budget.length}: ${JSON.stringify(budget)})`);
  assert.match(budget[0], /cleanupMs/, `the cleanup cap is in the SIGTERM budget: ${budget[0]}`);
  assert.match(budget[0], /closeTimeoutMs/, `…with the browser-close timeout: ${budget[0]}`);
  assert.ok(
    /cleanupMs\s*\+\s*[^;]*closeTimeoutMs|closeTimeoutMs\s*\+\s*[^;]*cleanupMs/.test(budget[0]),
    `…and both are ADDED, so the budget covers a cleanup and then a close: ${budget[0]}`,
  );

  // (c) the entrypoint waits at least 5 + 10 + 2 seconds for the supervisor.
  const wait = entrypointShutdownWaitSeconds(readFileSync(ENTRYPOINT, "utf8").split("\n").filter((l) => !/^\s*#/.test(l)).join("\n"));
  assert.ok(
    wait >= 17,
    `the entrypoint's shutdown() waits ${wait}s for the supervisor: the supervisor's own budget is cleanup 5 s + close 10 s + 2 s = 17 s, and a ` +
      "SIGKILL in the middle of a cleanup is a stop path on every restart",
  );

  // (d) compose's stop_grace_period is not shorter than that, and does not cut the
  // entrypoint's own wait short.
  const grace = /stop_grace_period:\s*(\d+)s/.exec(readFileSync(COMPOSE, "utf8"));
  assert.ok(grace, "compose still declares stop_grace_period");
  const graceSeconds = Number(grace[1]);
  assert.ok(graceSeconds >= 17, `compose's stop_grace_period is ${graceSeconds}s; it has to cover the 17 s the supervisor may spend stopping`);
  assert.ok(graceSeconds >= wait, `compose's stop_grace_period (${graceSeconds}s) must not cut the entrypoint's own ${wait}s wait short`);
});

// CONTROL: the two parsers above read the shapes the contract can be written in, so a red
// assertion in the test before this one is about the source and not about a parser that
// cannot see a wait at all.
test("CONTROL: the budget and entrypoint parsers read a shape that satisfies the contract", () => {
  assert.equal(
    entrypointShutdownWaitSeconds("shutdown() {\n  for i in $(seq 1 40); do\n    sleep 0.5\n  done\n  exit 0\n}\n"),
    20,
    "a counted wait is read as N × sleep",
  );
  assert.equal(entrypointShutdownWaitSeconds("shutdown() {\n  sleep 20\n  exit 0\n}\n"), 20, "a bare sleep is read as itself");
  assert.equal(
    entrypointShutdownWaitSeconds("shutdown() {\n  timeout 25 tail --pid=1 -f /dev/null\n  exit 0\n}\n"),
    25,
    "a timeout is read as itself",
  );

  const synthetic = "const budgetMs = caps.cleanupMs\n  + caps.closeTimeoutMs\n  + 2000;\n";
  const found = stopBudgetStatements(synthetic);
  assert.equal(found.length, 1, "a budget written over three lines is still one expression");
  assert.match(found[0], /cleanupMs/, "…that names the cleanup cap");
  assert.match(found[0], /closeTimeoutMs/, "…and the browser-close timeout");
  assert.ok(/cleanupMs\s*\+\s*[^;]*closeTimeoutMs/.test(found[0]), "…and adds them");
  assert.deepEqual(stopBudgetStatements("const budgetMs = caps.closeTimeoutMs + 2000;"), ["const budgetMs = caps.closeTimeoutMs + 2000"], "a budget with no cleanup cap is still one expression (and it fails the assertion above)");

  // The real entrypoint's own wait has to parse to a number: a parser typo here would make the
  // assertion above throw or read 0 rather than judge the entrypoint.
  const wait = entrypointShutdownWaitSeconds(readFileSync(ENTRYPOINT, "utf8").split("\n").filter((l) => !/^\s*#/.test(l)).join("\n"));
  assert.ok(wait > 0 && wait < 300, `the entrypoint's shutdown wait parses to ${wait}s`);
});

// ---------------------------------------------------------------------------
// 7. SIGTERM while the relay is mid-cleanup
// ---------------------------------------------------------------------------

test("SIGTERM mid-cleanup: the kill line is honoured in the stopping state", async (t) => {
  // A production-length cleanup budget on purpose: the SIGTERM has to land while the relay
  // is still inside the cleanup, with a page that will never commit.
  const ctx = await startSupervised(t, { CROW_CDP_CLEANUP_BUDGET_MS: "5000", CROW_CDP_CLOSE_TIMEOUT_MS: "3000" });
  const ready = await waitReady(ctx);
  const chromePid = chromiumPid(ctx);
  const chromePgid = pgidOf(chromePid);

  const { client, targetId } = await openClientWithNonCommittingPage(ctx, ready);
  assert.equal(
    ctx.records("resumed").some((r) => r.targetId === targetId),
    true,
    `the page ${targetId} was resumed: the cleanup has a live page whose commit never arrives`,
  );

  // 1) the guard client dies: the relay enters its cleanup with a page that never commits.
  client.kill();
  await sleep(250);
  // 2) docker stop lands while that cleanup is still running.
  ctx.child.kill("SIGTERM");

  const exit = await waitExit(ctx, 15000);
  assert.ok(exit, `the supervisor stops inside its own budget (log:\n${ctx.logs()})`);
  assert.equal(ctx.records("browser-close").length, 0, "no Browser.close: a page that never committed goes to the stop path, not to a graceful close");
  assert.deepEqual(
    ctx.records("close-target").filter((r) => r.targetId === targetId),
    [],
    "…and the page that never committed is not closed on the way",
  );
  assert.ok(
    groupKillLines(ctx).length >= 1,
    `the kill line is honoured while a SIGTERM is in progress: the stopping state must not swallow it (log:\n${ctx.logs()})`,
  );
  assert.equal(await waitGone(chromePid, 4000), true, "the browser's group is dead (the fixture died to the group kill, not to a close)");
  assert.equal(groupAlive(chromePgid), false, `kill -0 -${chromePgid} fails`);
});

// CONTROL: the same SIGTERM with nothing to clean up is a graceful close, and exit 0. It is
// the pre-existing shape (the supervisor's SIGTERM path), so it has to stay green.
test("CONTROL: SIGTERM with a clean browser closes Chromium through the relay and exits 0", async (t) => {
  const ctx = await startSupervised(t);
  await waitReady(ctx);
  ctx.child.kill("SIGTERM");
  const exit = await waitExit(ctx, 20000);
  assert.ok(exit, `the supervisor stops: ${ctx.logs()}`);
  assert.equal(exit.code, 0, `a clean stop exits 0: ${ctx.logs()}`);
  assert.equal(ctx.records("browser-close").length, 1, "Chromium was asked to close over the pipe");
  assert.equal(ctx.records("recv").some((r) => r.method === "Browser.close"), true, "…and Browser.close reached the pipe");
});

// ---------------------------------------------------------------------------
// 8. SIGTERM's timing: the same stop at either end of the start sequence
// ---------------------------------------------------------------------------

/**
 * The same stop, signalled the instant the ready file appears (within ~300 ms of the relay's
 * ready line): it is still the cleanup-first graceful close, and a clean scan exits 0 — never a
 * signal death, and never the stop path.
 */
test("SIGTERM within 300 ms of the ready line: a clean scan closes Chromium through the relay and exits 0", async (t) => {
  const ctx = await startSupervised(t);
  const ready = await waitReadyFile(ctx);
  const signalledAt = Date.now();
  ctx.child.kill("SIGTERM");
  const exit = await waitExit(ctx, 20000);
  assert.ok(exit, `the supervisor stops: ${ctx.logs()}`);
  assert.ok(
    signalledAt - ready.at < 300,
    `the SIGTERM landed ${Math.round(signalledAt - ready.at)} ms after the ready line, i.e. while this stop is at its earliest`,
  );
  assert.equal(exit.code, 0, `a SIGTERM stop on a clean scan is a clean stop, not a signal death: ${ctx.logs()}`);
  assert.equal(ctx.records("browser-close").length, 1, "the cleanup-first path ran: Chromium was closed through the relay");
  assert.deepEqual(groupKillLines(ctx), [], `the group was not SIGKILLed: ${JSON.stringify(groupKillLines(ctx))}`);
  assert.equal(await waitGone(chromiumPid(ctx), 4000), true, "Chromium's pid is gone");
});

// CONTROL: the same stop at the same moment is NOT clean when the scan is not: a page whose
// commit never arrives takes the stop path, and the supervisor exits non-zero.
test("CONTROL: SIGTERM right after ready with a page that never commits takes the stop path", async (t) => {
  const ctx = await startSupervised(t);
  const ready = await waitReady(ctx);
  const { targetId } = await openClientWithNonCommittingPage(ctx, ready);
  assert.equal(
    ctx.records("resumed").some((r) => r.targetId === targetId),
    true,
    `the page ${targetId} is a live page the cleanup has to navigate`,
  );
  ctx.child.kill("SIGTERM");
  const exit = await waitExit(ctx, 20000);
  assert.ok(exit, `the supervisor stops: ${ctx.logs()}`);
  assert.notEqual(exit.code, 0, `an unclean scan is not a clean stop: ${ctx.logs()}`);
  assert.equal(ctx.records("browser-close").length, 0, "no Browser.close on the stop path");
  assert.ok(groupKillLines(ctx).length >= 1, `the group kill is the supervisor's: ${JSON.stringify(ctx.logs().slice(-600))}`);
  assert.equal(await waitGone(chromiumPid(ctx), 4000), true, "Chromium's pid is gone");
});

/**
 * A SIGTERM that lands before the relay ever reported ready: nothing was served, so there is no
 * cleanup and no close to ask for. The supervisor stops at once (not after the whole stop
 * budget), exits 0 for the clean stop it is, and leaves neither Chromium nor its holder behind.
 */
test("SIGTERM before the ready line: the supervisor stops promptly, exits 0, and orphans nothing", async (t) => {
  const ctx = await startSupervised(t);
  const chromePid = await waitChromiumPid(ctx);
  const holders = holderChildrenOf(ctx.child.pid).map((h) => h.pid);
  assert.equal(existsSync(ctx.readyFile), false, "this SIGTERM lands before the ready file is written");
  assert.equal(ctx.child.exitCode, null, "CONTROL: without the signal the supervisor is still running");

  const signalledAt = Date.now();
  ctx.child.kill("SIGTERM");
  const exit = await waitExit(ctx, 20000);
  assert.ok(exit, `the supervisor stops on a SIGTERM that early: ${ctx.logs()}`);
  const elapsed = Date.now() - signalledAt;
  assert.equal(exit.code, 0, `a SIGTERM stop exits 0, not by a signal: ${ctx.logs()}`);
  assert.ok(elapsed < 3000, `the stop is prompt (${elapsed} ms): a relay that never reported ready leaves no cleanup to wait for`);
  assert.equal(await waitGone(chromePid, 4000), true, "Chromium's pid is gone: nothing is orphaned");
  for (const pid of holders) assert.equal(await waitGone(pid, 4000), true, `the holder (pid ${pid}) is gone with the supervisor`);
  assert.deepEqual(holderChildrenOf(ctx.child.pid), [], "no holder child outlives the supervisor");
  assert.equal(existsSync(ctx.readyFile), false, "no ready file is left behind");
});

// CONTROL: the same SIGTERM during a graceful close. The relay's `closing` line is what the
// SIGTERM path has to honour too: Chromium is left to commit and exit by itself, and the stop
// is still a clean one.
test("SIGTERM during a graceful close: `closing` keeps Chromium alive for its own exit, and the stop exits 0", async (t) => {
  const ctx = await startSupervised(t, CLOSING_ENV);
  await waitReady(ctx);
  ctx.child.kill("SIGTERM");
  const exit = await waitExit(ctx, 20000);
  assert.ok(exit, `the supervisor stops: ${ctx.logs()}`);
  assert.match(ctx.logs(), /graceful close on fd 5/, `the closing line was seen: ${JSON.stringify(ctx.logs().slice(-800))}`);
  assert.equal(exit.code, 0, `a SIGTERM stop on a clean scan exits 0: ${ctx.logs()}`);
  assert.deepEqual(ctx.records("closed-by-itself").map((r) => r.code), [7], "Chromium reached its own exit, not a kill");
  assert.deepEqual(groupKillLines(ctx), [], `no group kill on the way out: ${JSON.stringify(groupKillLines(ctx))}`);
});