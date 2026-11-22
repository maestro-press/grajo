/**
 * Peer-pair port reservation (tests/fixtures/peer-pair.mjs).
 *
 * Two REAL gateways paired by the real CLI share a box with every other test
 * file in the suite — and with every other suite run (worktrees, a benchmark,
 * a subagent). An instance that has already SERVED cannot move its port on a
 * pairing reboot (its peers hold it), so across that reboot its port sits
 * unbound. CI's E-F7 reboot of `bravo` died on
 * `listen EADDRINUSE 0.0.0.0:27126`: another test's brief bind-probe found the
 * port free while bravo was down and its gateway took it.
 *
 * The fixture now RESERVES a picked port cross-process (a pid file created
 * O_EXCL), holds that lock for the instance's whole life and retries the SAME
 * port with backoff when a served instance meets EADDRINUSE. A lock left by a
 * gone process is reclaimed by RENAMING it out of the way (only one reclaimer
 * can win the rename), never by unlink+recreate.
 *
 * This file pins all three, and the CONTROL test asserts what the reservation
 * is doing: with it switched off, the same cross-process scenario no longer
 * refuses, so the protected assertion cannot pass vacuously.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { existsSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  Instance,
  reservePort,
  tryReserve,
  releasePort,
  _setPortReservation,
  bootWithPortRetry,
  portReservationDir,
  reclaimStaleLock,
  lockStashPath,
  recheckStashedLock,
  REBOOT_PORT_RETRY_DELAYS,
} from "./fixtures/peer-pair.mjs";

// The suite runner does not scope TMPDIR (scripts/run-suite.mjs), so the
// reservation directory is per test file here: a private dir makes the
// reclaim assertions exact and keeps this file's locks out of the shared
// os.tmpdir()/crow-test-ports-<uid> the rest of the suite uses.
const PORTS_DIR = mkdtempSync(join(tmpdir(), "pt-port-locks-"));
process.env.CROW_TEST_PORTS_DIR = PORTS_DIR;
process.on("exit", () => { try { rmSync(PORTS_DIR, { recursive: true, force: true }); } catch { /* gone */ } });

const FIXTURE = new URL("./fixtures/peer-pair.mjs", import.meta.url).href;
const lockFile = (port) => join(PORTS_DIR, String(port));

/** A child process that reserves one port with the fixture's own reservePort and holds it until it dies. */
function holdPortInChild() {
  const code = `
    const { reservePort } = await import(${JSON.stringify(FIXTURE)});
    const port = await reservePort();
    console.log("PORT " + port);
    // Keep the reservation (and the process) alive until the parent kills us:
    // the lock is released at exit, which a SIGKILL never reaches.
    process.stdin.resume();
    await new Promise(() => {});`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", code], {
    cwd: new URL("..", import.meta.url).pathname,
    env: { ...process.env, CROW_TEST_PORTS_DIR: PORTS_DIR },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let err = "";
  child.stderr.on("data", (c) => { err += c; });
  const exited = new Promise((r) => child.once("exit", (code_, signal) => r({ code: code_, signal })));
  const port = new Promise((resolve, reject) => {
    let out = "";
    const timer = setTimeout(() => reject(new Error(`child never printed its port; stderr:\n${err.slice(-2000)}`)), 30_000);
    child.stdout.on("data", (c) => {
      out += c;
      const m = out.match(/PORT (\d+)/);
      if (m) { clearTimeout(timer); resolve(Number(m[1])); }
    });
    exited.then(({ code: c2, signal }) => { clearTimeout(timer); reject(new Error(`child exited (${c2}/${signal}) before reserving; stderr:\n${err.slice(-2000)}`)); });
  });
  return { child, port, exited, stderr: () => err };
}

async function killChild(h) {
  try { h.child.kill("SIGKILL"); } catch { /* gone */ }
  await h.exited;
}

/** Bind `port` on the gateway's own address, or resolve false if something else has it. */
function bind(port) {
  return new Promise((resolve) => {
    const s = createServer();
    s.once("error", () => resolve(null));
    s.listen(port, "0.0.0.0", () => resolve(s));
  });
}

function closeServer(s) {
  return new Promise((r) => { s.closeAllConnections?.(); s.close(() => r()); });
}

// ---- (a) the reservation is cross-process --------------------------------

test("a port reserved by another process is refused while that process lives, and its stale lock is reclaimed after it dies", { timeout: 120_000 }, async () => {
  const h = holdPortInChild();
  try {
    const port = await h.port;
    assert.equal(existsSync(lockFile(port)), true, "the child left a lock file for its port");
    assert.equal(readFileSync(lockFile(port), "utf8").trim(), String(h.child.pid), "the lock names the child, so a live pid is what protects it");

    // The picker uses the same helper, so this is what another test file's
    // freePort() would see for a port this fixture already holds.
    assert.equal(tryReserve(port), false, "another process's reservation is refused");

    // SIGKILL: the child never reaches its own exit handler, so the lock file
    // is exactly what a killed suite run leaves behind.
    await killChild(h);
    assert.equal(existsSync(lockFile(port)), true, "the lock outlives the process that took it");
    assert.equal(tryReserve(port), true, "a dead owner's lock is reclaimed");
  } finally {
    await killChild(h);
  }
});

// ---- (b) CONTROL: it checks the switch, not the flake ---------------------
//
// With the reservation off the shared lock is never consulted, so the
// cross-process refusal above disappears — that is all this pins (the
// assertion above cannot pass vacuously). It is NOT a reproduction of the CI
// flake: the behaviour itself is pinned by the cross-process test above, the
// served-reboot test and the retry tests below.
test("CONTROL: with the reservation switched off the same port is not refused, so the test above is not vacuous", { timeout: 120_000 }, async () => {
  const h = holdPortInChild();
  try {
    const port = await h.port;
    assert.equal(existsSync(lockFile(port)), true, "the child (reservation on) took the lock");

    _setPortReservation(false);
    try {
      // The same call the protected test asserts is false; without the shared
      // lock nothing is consulted, which is exactly the pre-fix behaviour the
      // flake lived in.
      assert.equal(tryReserve(port), true, "unprotected: the other process's claim is invisible");
      const picked = await reservePort();
      assert.notEqual(picked, undefined);
      assert.equal(existsSync(lockFile(picked)), false, "unprotected: freePort takes no lock file");
      releasePort(picked);
    } finally {
      _setPortReservation(true);
    }

    assert.equal(tryReserve(port), false, "back to the protected behaviour in the same scenario");
  } finally {
    await killChild(h);
  }
});

// ---- (c) a served instance retries its OWN port, never a new one ---------

test("a served instance retries the SAME port and comes up when a transient holder releases it", { timeout: 120_000 }, async () => {
  const port = await reservePort();
  const holder = await bind(port);
  assert.ok(holder, `test could not hold ${port}`);
  // What happened, in order. The holder is released from INSIDE the attempt
  // that meets it, never by a wall-clock timer: this box runs the whole suite
  // at once, so a `setTimeout(600)` release racing 5.75 s of backoff timers can
  // lose (the release fires after the retries are spent and r.ok is false) and
  // a "released at 600 ms, attempted after that" pair of clock reads is a bet on
  // timer precision. What is asserted here is the ORDER of events and the count.
  const events = [];
  const attempts = []; // one record per attempt, in order
  let releasedInside = 0;
  try {
    const r = await bootWithPortRetry({
      served: true,
      start: async () => {
        const s = await bind(port); // the SAME port, every attempt
        const n = attempts.length + 1;
        if (s) {
          attempts.push({ n, ok: true, port: s.address()?.port ?? null });
          events.push(`attempt ${n}: bound ${port}`);
          await closeServer(s);
          return { ok: true };
        }
        attempts.push({ n, ok: false, port: null });
        events.push(`attempt ${n}: met the holder`);
        if (n === 2) {
          // Awaited before this attempt returns, so the release is complete
          // before the backoff can expire and the next attempt starts: the
          // third attempt is deterministically the first one on a free port.
          await closeServer(holder);
          releasedInside = n;
          events.push(`attempt ${n}: holder closed before returning addrInUse`);
        }
        return { addrInUse: true };
      },
    });
    assert.deepEqual(attempts.slice(0, 2).map((a) => a.ok), [false, false], `the first two attempts did meet the holder: ${JSON.stringify(events)}`);
    assert.deepEqual(events.slice(0, 3), [
      "attempt 1: met the holder",
      "attempt 2: met the holder",
      "attempt 2: holder closed before returning addrInUse",
    ], `the holder was released inside the second attempt, not by a timer: ${JSON.stringify(events)}`);
    assert.equal(releasedInside, 2, "the release came from the second attempt");
    assert.equal(r.ok, true, "the retry brought the instance up");
    assert.equal(r.addrInUse, undefined);
    assert.ok(r.attempts >= 3, `a later attempt came up only after the release: ${JSON.stringify(events)}`);
    assert.equal(r.attempts, attempts.length);
    assert.equal(attempts.at(-1).ok, true, `the attempt that succeeded came after the release: ${JSON.stringify(events)}`);
    assert.equal(attempts.at(-1).port, port, "it came up on the SAME port, never a new one");
    assert.deepEqual(REBOOT_PORT_RETRY_DELAYS, [250, 500, 1_000, 2_000, 2_000], "the shipped backoff is what a reboot gets");
  } finally {
    await closeServer(holder);
    releasePort(port);
  }
});

test("a served instance whose port stays held gives up after the retries", { timeout: 120_000 }, async () => {
  const port = await reservePort();
  const holder = await bind(port);
  assert.ok(holder, `test could not hold ${port}`);
  let tried = 0;
  try {
    const r = await bootWithPortRetry({
      served: true,
      // The real delays here would only make the test slow: what is asserted is
      // the attempt COUNT (one attempt plus one per entry), never the elapsed
      // time, so no timer precision is involved.
      delays: [10, 10, 10, 10, 10],
      start: async () => { tried += 1; return { addrInUse: true }; },
    });
    assert.equal(r.addrInUse, true);
    assert.equal(r.attempts, 6, "one attempt plus five retries");
    assert.equal(tried, 6);
  } finally {
    await closeServer(holder);
    releasePort(port);
  }
});

test("a gateway rebooted after serving a port another process holds says so, instead of 'exited during boot'", { timeout: 300_000 }, async () => {
  const inst = await new Instance("held", "100.64.20.14").init();
  const port = inst.port;
  let holder = null;
  try {
    await inst.boot(); // it has now served: its port is what peers hold
    await inst.stop();
    holder = await bind(port);
    assert.ok(holder, `could not hold ${port}`);
    // The holder is never released, so every attempt fails for the same reason
    // and the outcome does not depend on how long the backoff (5.75 s) takes on
    // a loaded box — only on the fact that no attempt ever succeeds.
    await assert.rejects(inst.boot(), (err) => {
      assert.match(err.message, new RegExp(`^held: port ${port} is held by another process \\(reboot after serving cannot move ports\\)`));
      assert.match(err.message, /EADDRINUSE/, "the log tail comes with it");
      return true;
    });
    assert.equal(inst.port, port, "the port did not move");
  } finally {
    if (holder) await closeServer(holder);
    await inst.cleanup();
  }
});

// ---- the reclaim itself --------------------------------------------------

test("two reclaim attempts on the same stale lock leave exactly one owner", async () => {
  let port = 31_500;
  while (existsSync(lockFile(port))) port += 1; // never a port this file already holds
  writeFileSync(lockFile(port), "999999999\n"); // a dead pid: the shape a killed suite run leaves
  try {
    const first = reclaimStaleLock(lockFile(port));
    // A second reclaimer that read the same stale lock calls the helper after
    // the winner's rename: the path is gone, so it gets ENOENT.
    const second = reclaimStaleLock(lockFile(port));
    assert.equal(first, true, "the first reclaimer wins the rename");
    assert.equal(second, false, "the loser sees ENOENT and treats the port as taken this round");
    assert.equal(existsSync(lockFile(port)), false, "the stale lock is out of the way, not left for the loser to claim");
    assert.deepEqual(readdirSync(PORTS_DIR).filter((f) => f.includes(".reclaim.")), [], "the renamed copy is unlinked, never left as a second lock");
    // Exactly one process can win the O_EXCL create that follows.
    assert.equal(tryReserve(port), true, "the surviving create takes the port");
    assert.equal(readFileSync(lockFile(port), "utf8").trim(), String(process.pid), "the one owner is this process");
    assert.equal(tryReserve(port), false, "a second reservation of the same port is refused");
  } finally {
    releasePort(port);
  }
});

// ---- the rename is atomic but not conditional ---------------------------
//
// A reclaimer that stalls between its own staleLock() check and its rename can
// land the rename on a FRESH lock another reclaimer created meanwhile. The
// rename cannot see that; the recheck after it can, and must put the lock back.
// The interleaving is staged by hand (the stalled reclaimer supplies the
// rename, the post-check helper is called next) rather than by a timer.
test("a stalled reclaimer puts a fresh lock it renamed aside back, instead of taking the port", async () => {
  let port = 31_900;
  while (existsSync(lockFile(port))) port += 1; // never a port this file already holds
  const path = lockFile(port);
  // The shape a killed suite run leaves: a lock whose owner is gone.
  writeFileSync(path, "999999999\n");
  try {
    // Reclaimer A wins the stale lock and creates a FRESH one naming a live
    // pid — this process, which holds the port from here on. B has already
    // passed its stale check by now (that is the stall).
    assert.equal(tryReserve(port), true, "A reclaimed the stale lock and owns the port");
    assert.equal(readFileSync(path, "utf8").trim(), String(process.pid), "A's lock names a live pid");

    // B's rename, on the path A's lock now occupies, then B's recheck.
    const stash = lockStashPath(path);
    renameSync(path, stash);
    assert.equal(existsSync(path), false, "B's rename did move a lock aside (that is the race)");
    assert.equal(recheckStashedLock(path, stash), false, "B does not win: what it renamed is a live lock, not a stale one");
    assert.equal(existsSync(path), true, "A's fresh lock is back at the path");
    assert.equal(readFileSync(path, "utf8").trim(), String(process.pid), "and it is still A's, unclobbered");
    assert.deepEqual(readdirSync(PORTS_DIR).filter((f) => f.includes(".reclaim.")), [], "no stash files remain");
    assert.equal(tryReserve(port), false, "B treats the port as taken this round");

    // A lock created while B still held the stash is protected too: the restore
    // is link(2), so it fails EEXIST and leaves that lock alone.
    const stash2 = lockStashPath(path);
    renameSync(path, stash2);
    writeFileSync(path, "999999998\n");
    assert.equal(recheckStashedLock(path, stash2), false, "B loses when the path was refilled while it held the stash");
    assert.equal(readFileSync(path, "utf8").trim(), "999999998", "the lock that reappeared is untouched (link never overwrites)");
    assert.deepEqual(readdirSync(PORTS_DIR).filter((f) => f.includes(".reclaim.")), [], "no stash files remain");
  } finally {
    releasePort(port);
  }
});

test("a lock past the age cap, or one naming this pid that we do not hold, is stale", async () => {
  // An ALIVE pid (this file's parent) on a lock older than the cap reads as a
  // reused pid on a persistent box, so the age is what makes it stale.
  let aged = 31_700;
  while (existsSync(lockFile(aged))) aged += 1;
  writeFileSync(lockFile(aged), `${process.ppid}\n`);
  const sevenHoursAgo = Date.now() / 1000 - 7 * 60 * 60;
  utimesSync(lockFile(aged), sevenHoursAgo, sevenHoursAgo);
  try {
    assert.equal(tryReserve(aged), true, "a lock older than 6 h is reclaimed even though its pid is alive");
    assert.equal(readFileSync(lockFile(aged), "utf8").trim(), String(process.pid));
  } finally {
    releasePort(aged);
  }

  // A leftover lock that names OUR pid but that this process never took (an
  // earlier run whose pid came round again) is stale, not "live self".
  let leftover = aged + 1;
  while (existsSync(lockFile(leftover))) leftover += 1;
  writeFileSync(lockFile(leftover), `${process.pid}\n`);
  try {
    assert.equal(tryReserve(leftover), true, "a leftover lock naming this pid is reclaimed");
    assert.equal(readFileSync(lockFile(leftover), "utf8").trim(), String(process.pid));
  } finally {
    releasePort(leftover);
  }
});

// ---- the lock directory itself -------------------------------------------

test("the reservation directory is the env override and each lock names its owner", async () => {
  assert.equal(portReservationDir(), PORTS_DIR);
  let port = 30_999;
  while (!tryReserve(port)) port += 1; // never a port this file already holds
  try {
    assert.equal(readFileSync(lockFile(port), "utf8").trim(), String(process.pid));
    assert.equal(tryReserve(port), false, "this process's own live lock is not handed out twice");
  } finally {
    releasePort(port);
  }
  assert.equal(existsSync(lockFile(port)), false, "releasePort removes it");
});