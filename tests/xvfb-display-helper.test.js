// UNIT (no browser, no Xvfb): the display-litter helper behind the live headful
// case. Its job is to answer "is display :n really in use?" rather than "does a
// lock file exist?" — the live test used to SIGKILL Xvfb, which leaves
// /tmp/.X<n>-lock and /tmp/.X11-unix/X<n> behind forever, so after enough runs
// the picker could not find a free display.
//
// Every path here is injected through `opts` into a mkdtemp directory (lockDir +
// socketDir): nothing in this file reads or writes the real /tmp X-litter, so the
// tests are safe to run beside a real X server and in parallel with the suite.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { rmScratch } from "./helpers/safe-rm.js";
import {
  displayState,
  isPidAlive,
  pickFreeDisplay,
  removeStaleDisplayFiles,
  stopXvfb,
} from "./helpers/xvfb-display.mjs";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const lockPath = (lockDir, n) => join(lockDir, `.X${n}-lock`);
const socketPath = (socketDir, n) => join(socketDir, `X${n}`);
/** Xvfb writes "%10d\n" — keep the fixture byte-identical to the real thing. */
const lockText = (pid) => `${String(pid).padStart(10, " ")}\n`;

/** A private lockDir/socketDir pair, deleted (safely) after the test. */
function makeDirs(t) {
  const root = mkdtempSync(join(tmpdir(), "crow-xvfb-helper-"));
  const lockDir = join(root, "lock");
  const socketDir = join(root, ".X11-unix");
  mkdirSync(lockDir, { recursive: true });
  mkdirSync(socketDir, { recursive: true });
  t.after(() => rmScratch(root));
  return { root, lockDir, socketDir, opts: { lockDir, socketDir } };
}

/** A pid that is definitely dead: a node that ran to completion and was reaped. */
async function deadPid() {
  const child = spawn(process.execPath, ["-e", ""], { stdio: "ignore" });
  const pid = child.pid;
  await new Promise((resolve, reject) => {
    child.once("exit", resolve);
    child.once("error", reject);
  });
  return pid;
}

/** A real unix-socket listener at `path` (what a live X display looks like). */
async function listenUnix(t, path) {
  const server = createServer(() => {});
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(path, resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return server;
}

async function waitForFiles(files, ms = 10000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (files.every((f) => existsSync(f))) return true;
    await sleep(25);
  }
  return false;
}

function waitForExit(child, ms = 10000) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    child.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

/**
 * Spawn a fake "Xvfb": it writes its own pid into `lockDir/.X<n>-lock` in Xvfb's
 * "%10d\n" format and creates `socketDir/X<n>`, then either waits for a signal
 * (`onTerm: "exit"` honours SIGTERM, `"ignore"` survives it) or exits at once.
 * Detached, like the real one, so the helper signals the whole process group.
 */
function startFakeXvfb(t, { lockDir, socketDir, n, onTerm = "exit", exitAfterFiles = false }) {
  const lock = lockPath(lockDir, n);
  const sock = socketPath(socketDir, n);
  const script = [
    'const fs = require("node:fs");',
    `fs.writeFileSync(${JSON.stringify(lock)}, String(process.pid).padStart(10, " ") + "\\n");`,
    `fs.writeFileSync(${JSON.stringify(sock)}, "");`,
    ...(exitAfterFiles
      ? []
      : [
          `process.on("SIGTERM", () => { ${onTerm === "exit" ? "process.exit(0);" : "/* keep running */"} });`,
          "setInterval(() => {}, 1000);",
        ]),
  ].join("\n");
  const child = spawn(process.execPath, ["-e", script], {
    stdio: ["ignore", "ignore", "pipe"],
    detached: true,
  });
  let log = "";
  child.stderr.on("data", (d) => {
    if (log.length < 4000) log += d.toString();
  });
  // Safety net: a failed assertion must not leave a fake Xvfb behind.
  t.after(() => {
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      /* already gone */
    }
  });
  return { child, log: () => log.trim() };
}

// ---------------------------------------------------------------------------
// isPidAlive
// ---------------------------------------------------------------------------

test("isPidAlive: a live pid is alive, a reaped child and junk are not", async () => {
  const dead = await deadPid();
  assert.equal(isPidAlive(process.pid), true, "the test runner is alive");
  assert.equal(isPidAlive(dead), false, "a child that exited and was reaped is dead");
  assert.equal(isPidAlive(0), false, "0 is not a pid to signal");
  assert.equal(isPidAlive(-1), false, "-1 is not a single pid");
  assert.equal(isPidAlive(1.5), false, "a non-integer is not a pid");
  assert.equal(isPidAlive("123"), false, "a string is not a pid");
  assert.equal(isPidAlive(NaN), false);
});

// ---------------------------------------------------------------------------
// displayState
// ---------------------------------------------------------------------------

test("displayState: a readable lock with a dead pid is stale", async (t) => {
  const { lockDir, opts } = makeDirs(t);
  const dead = await deadPid();
  writeFileSync(lockPath(lockDir, 90), lockText(dead));
  assert.equal(await displayState(90, opts), "stale");
});

test("displayState: a readable lock with a live pid is taken, socket or not", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  writeFileSync(lockPath(lockDir, 90), lockText(process.pid));
  assert.equal(await displayState(90, opts), "taken", "no socket at all, but the owner pid is alive");
  writeFileSync(socketPath(socketDir, 90), "");
  assert.equal(await displayState(90, opts), "taken");
});

test("displayState: a garbage lock with no socket is stale", async (t) => {
  const { lockDir, opts } = makeDirs(t);
  writeFileSync(lockPath(lockDir, 90), "not-a-pid\n");
  assert.equal(await displayState(90, opts), "stale");
});

test("displayState: a garbage lock with a live listener is taken", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  writeFileSync(lockPath(lockDir, 90), "not-a-pid\n");
  await listenUnix(t, socketPath(socketDir, 90));
  assert.equal(await displayState(90, opts), "taken");
});

test("displayState: nothing at all is free", async (t) => {
  const { opts } = makeDirs(t);
  assert.equal(await displayState(90, opts), "free");
});

test("displayState: no lock, a socket with a live listener is taken; a dead socket is stale", async (t) => {
  const { socketDir, opts } = makeDirs(t);
  await listenUnix(t, socketPath(socketDir, 90));
  assert.equal(await displayState(90, opts), "taken");
  // A leftover socket file with nobody listening is litter, not a display.
  writeFileSync(socketPath(socketDir, 91), "");
  assert.equal(await displayState(91, opts), "stale");
});

test("displayState: an injected socketListening decides an unreadable lock's display", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  writeFileSync(lockPath(lockDir, 90), "not-a-pid\n");
  writeFileSync(socketPath(socketDir, 90), "");
  const asked = [];
  const taken = await displayState(90, {
    ...opts,
    socketListening: async (path) => {
      asked.push(path);
      return true;
    },
  });
  assert.equal(taken, "taken");
  assert.deepEqual(asked, [socketPath(socketDir, 90)], "the injected probe is asked about this display's socket");
  assert.equal(await displayState(90, { ...opts, socketListening: async () => false }), "stale");
});

// ---------------------------------------------------------------------------
// pickFreeDisplay
// ---------------------------------------------------------------------------

test("pickFreeDisplay claims a stale display and removes its litter, leaving a taken one alone", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  const dead = await deadPid();
  // 90: a live owner (taken). 91: a dead owner with stale files (stale).
  writeFileSync(lockPath(lockDir, 90), lockText(process.pid));
  writeFileSync(socketPath(socketDir, 90), "");
  writeFileSync(lockPath(lockDir, 91), lockText(dead));
  writeFileSync(socketPath(socketDir, 91), "");

  const picked = await pickFreeDisplay({ from: 90, to: 95, lockDir, socketDir });

  assert.equal(picked, 91, "the first FREE or STALE display in the range, never a taken one");
  assert.equal(existsSync(lockPath(lockDir, 91)), false, "the stale lock was removed");
  assert.equal(existsSync(socketPath(socketDir, 91)), false, "the stale socket was removed");
  assert.equal(existsSync(lockPath(lockDir, 90)), true, "a taken display's lock is untouched");
  assert.equal(existsSync(socketPath(socketDir, 90)), true, "a taken display's socket is untouched");
  assert.equal(await displayState(91, opts), "free", "the claimed display is now free for the child to use");
});

test("pickFreeDisplay returns null when every display in the range is taken", async (t) => {
  const { lockDir, opts } = makeDirs(t);
  for (let n = 90; n < 95; n++) writeFileSync(lockPath(lockDir, n), lockText(process.pid));

  assert.equal(await pickFreeDisplay({ from: 90, to: 95, ...opts }), null);
  for (let n = 90; n < 95; n++) {
    assert.equal(existsSync(lockPath(lockDir, n)), true, `display ${n}'s live lock is untouched`);
  }
});

// ---------------------------------------------------------------------------
// removeStaleDisplayFiles
// ---------------------------------------------------------------------------

test("removeStaleDisplayFiles removes a stale display's lock and socket", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  const dead = await deadPid();
  writeFileSync(lockPath(lockDir, 90), lockText(dead));
  writeFileSync(socketPath(socketDir, 90), "");

  assert.equal(await removeStaleDisplayFiles(90, opts), true);
  assert.equal(existsSync(lockPath(lockDir, 90)), false);
  assert.equal(existsSync(socketPath(socketDir, 90)), false);
});

test("removeStaleDisplayFiles never removes a lock whose pid is alive", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  writeFileSync(lockPath(lockDir, 90), lockText(process.pid));
  writeFileSync(socketPath(socketDir, 90), "");

  assert.equal(await removeStaleDisplayFiles(90, opts), false);
  assert.equal(existsSync(lockPath(lockDir, 90)), true, "the lock of a live pid is left alone");
  assert.equal(existsSync(socketPath(socketDir, 90)), true, "and so is its socket");
});

// ---------------------------------------------------------------------------
// stopXvfb
// ---------------------------------------------------------------------------

test("stopXvfb: a child that exits on SIGTERM is stopped and its lock+socket are removed", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  const n = 90;
  const { child, log } = startFakeXvfb(t, { lockDir, socketDir, n, onTerm: "exit" });
  assert.ok(
    await waitForFiles([lockPath(lockDir, n), socketPath(socketDir, n)]),
    `the fake Xvfb wrote its lock and socket (stderr: ${log()})`,
  );
  let exitSignal = "none";
  child.once("exit", (_code, signal) => {
    exitSignal = signal ?? "code";
  });

  await stopXvfb(child, n, { lockDir, socketDir, termMs: 3000, killMs: 2000 });

  assert.equal(isPidAlive(child.pid), false, "the child is gone");
  assert.equal(exitSignal, "code", "it exited on its own SIGTERM handler, no SIGKILL needed");
  assert.equal(existsSync(lockPath(lockDir, n)), false, "the lock did not outlive the display");
  assert.equal(existsSync(socketPath(socketDir, n)), false, "the socket did not outlive the display");
});

test("stopXvfb: a child that ignores SIGTERM is SIGKILLed, and its lock+socket are still removed", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  const n = 91;
  const { child, log } = startFakeXvfb(t, { lockDir, socketDir, n, onTerm: "ignore" });
  assert.ok(
    await waitForFiles([lockPath(lockDir, n), socketPath(socketDir, n)]),
    `the fake Xvfb wrote its lock and socket (stderr: ${log()})`,
  );
  let exitSignal = "none";
  child.once("exit", (_code, signal) => {
    exitSignal = signal ?? "code";
  });

  await stopXvfb(child, n, { lockDir, socketDir, termMs: 300, killMs: 2000 });

  assert.equal(isPidAlive(child.pid), false, "the SIGKILL fallback ended it");
  assert.equal(exitSignal, "SIGKILL", "it really had to be killed");
  assert.equal(existsSync(lockPath(lockDir, n)), false, "the lock was cleaned up even though the child did not");
  assert.equal(existsSync(socketPath(socketDir, n)), false);
});

test("stopXvfb: a child that already exited still has its stale files removed, and it does not throw", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  const n = 92;
  const { child, log } = startFakeXvfb(t, { lockDir, socketDir, n, exitAfterFiles: true });
  await waitForExit(child);
  assert.ok(
    await waitForFiles([lockPath(lockDir, n), socketPath(socketDir, n)]),
    `the fake Xvfb wrote its lock and socket before exiting (stderr: ${log()})`,
  );
  assert.equal(isPidAlive(child.pid), false, "the child is already gone");

  await stopXvfb(child, n, { lockDir, socketDir, termMs: 200, killMs: 200 });

  assert.equal(existsSync(lockPath(lockDir, n)), false, "the stale lock of the dead child is removed");
  assert.equal(existsSync(socketPath(socketDir, n)), false);
});

test("stopXvfb never deletes a lock owned by a live, unrelated pid", async (t) => {
  const { lockDir, socketDir, opts } = makeDirs(t);
  const n = 93;
  const { child, log } = startFakeXvfb(t, { lockDir, socketDir, n, exitAfterFiles: true });
  await waitForExit(child);
  assert.ok(
    await waitForFiles([lockPath(lockDir, n), socketPath(socketDir, n)]),
    `the fake Xvfb wrote its files before exiting (stderr: ${log()})`,
  );
  // The litter is real, but its lock names a pid that is alive (this runner):
  // the display is TAKEN, and nothing may be unlinked.
  writeFileSync(lockPath(lockDir, n), lockText(process.pid));

  await stopXvfb(child, n, { lockDir, socketDir, termMs: 200, killMs: 200 });

  assert.equal(existsSync(lockPath(lockDir, n)), true, "a live pid's lock is not removed");
  assert.equal(existsSync(socketPath(socketDir, n)), true, "and neither is its socket");
});