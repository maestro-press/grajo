/**
 * Browser bundle: downloads are allowed only around the critical section
 * (crow_browser_download used to leave Browser.setDownloadBehavior("allow") set
 * on the session for good).
 *
 * The "who has downloads on" bookkeeping is a DIRECTORY of lease files, not an
 * in-process counter, because the setting is browser-wide while the callers are
 * not: a second MCP process (a Gmail turn beside a Perch turn, a restart's
 * leftover) must not have its download cancelled by the other process putting
 * the browser-wide default back.
 *
 * Per call: write `<pid>-<random>` (JSON {pid, pidns, start, deadline}) in
 * leaseDir, send allow, run fn, remove the lease, and send default ONLY when no
 * live lease remains. A lease is live iff its deadline is in the future and —
 * only when its `pidns` is THIS process's PID namespace — its pid is alive: bots
 * run under bwrap --unshare-pid, so a cross-namespace pid probe is a false ESRCH
 * that would delete a live lease. Dead, expired and unparseable leases are
 * deleted while checking and ignored; a fresh `.tmp` name (a write in progress)
 * is skipped. A lease that cannot be written is fail-closed: no allow, fn never
 * runs, the error propagates (one console.error line) — no lease means downloads
 * stay off.
 *
 * The session is read through a getter (a reconnect swaps it mid-flight) and the
 * reset is bounded: a wedged session must not hang the download call.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync, unlinkSync, utimesSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const {
  withDownloadsAllowed, resetDownloadsOnNewSession, RESET_TIMEOUT_MS, DEFAULT_LEASE_DEADLINE_MS,
  MAX_LEASE_MS, DOWNLOAD_TIMEOUT_CAP_MS,
} = await import("../bundles/browser/server/download-behavior.js");

const DOWNLOAD_PATH = "/tmp/crow-downloads";

/** A fake CDP session that records every send. `failOn` decides which sends reject. */
function makeCdp({ failOn, hangOn } = {}) {
  const calls = [];
  return {
    calls,
    async send(method, params) {
      calls.push({ method, params });
      if (hangOn && hangOn(method, params)) return new Promise(() => {}); // never settles
      if (failOn && failOn(method, params)) throw new Error(`send rejected: ${params?.behavior ?? method}`);
    },
  };
}

/** The behavior of each recorded send, in order. */
function behaviors(cdp) {
  return cdp.calls.map((c) => c.params?.behavior);
}

function assertAllSetDownloadBehavior(cdp) {
  for (const call of cdp.calls) {
    assert.equal(call.method, "Browser.setDownloadBehavior", JSON.stringify(call));
  }
}

/** Let the already-started async work reach its next await. */
const tick = () => new Promise((resolve) => setImmediate(resolve));

/** Several macrotask turns: the lease write and the allow send are separate awaits. */
async function settle(rounds = 8) {
  for (let i = 0; i < rounds; i++) await tick();
}

/** Run `fn` with console.error captured; return { value, lines } (or rethrow). */
async function captureConsoleError(fn) {
  const lines = [];
  const original = console.error;
  console.error = (...args) => { lines.push(args.map(String).join(" ")); };
  try {
    return { value: await fn(), lines };
  } finally {
    console.error = original;
  }
}

/** A throwaway lease directory, removed from disk when the body is done. */
async function withLeaseDir(body) {
  const leaseDir = mkdtempSync(join(tmpdir(), "crow-dl-lease-"));
  try {
    return await body(leaseDir);
  } finally {
    rmSync(leaseDir, { recursive: true, force: true });
  }
}

/** The lease files currently in `leaseDir` (the replacement for the old counter). */
function leaseFiles(leaseDir) {
  return readdirSync(leaseDir);
}

function assertNoLeases(leaseDir) {
  assert.equal(
    leaseFiles(leaseDir).length,
    0,
    `expected every lease file to be gone, got ${JSON.stringify(leaseFiles(leaseDir))}`,
  );
}

/** Write a lease file by hand (another process's, or a stale one). Returns its name. */
function plantLease(leaseDir, {
  name,
  pid = process.pid,
  start = Date.now(),
  deadline = Date.now() + 60_000,
  pidns = OUR_PIDNS,
} = {}) {
  const fileName = name || `${pid}-${Math.random().toString(16).slice(2)}`;
  writeFileSync(join(leaseDir, fileName), JSON.stringify({ pid, pidns, start, deadline }));
  return fileName;
}

/** Write a lease file's TEXT by hand (for values JSON.stringify cannot express). Returns its name. */
function plantRawLease(leaseDir, text, name) {
  const fileName = name || `raw-${Math.random().toString(16).slice(2)}`;
  writeFileSync(join(leaseDir, fileName), text);
  return fileName;
}

/** Ten years in ms: a deadline no download could ever still need. */
const TEN_YEARS_MS = 10 * 365 * 24 * 60 * 60 * 1000;
/** A PID namespace that is certainly not this one, spelled as /proc spells it. */
const FOREIGN_PIDNS = "pid:[999999999]";

/** A pid that is certainly dead: a child that ran to completion and was reaped. */
function deadPid() {
  const child = spawnSync(process.execPath, ["-e", ""]);
  assert.equal(typeof child.pid, "number", "spawnSync must report the child's pid");
  return child.pid;
}

/** This process's PID namespace, read exactly the way the module reads it. */
function ownPidns() {
  try {
    return readlinkSync("/proc/self/ns/pid");
  } catch {
    return null;
  }
}

const OUR_PIDNS = ownPidns();

/** A PID namespace that is certainly not this one (the host's, typically). */
const OTHER_PIDNS = "pid:[1]";
test("successful fn: sends allow then default and returns the result", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp();
    const result = await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.equal(result, "done");
    assertAllSetDownloadBehavior(cdp);
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assert.deepEqual(cdp.calls[0].params, { behavior: "allow", downloadPath: DOWNLOAD_PATH });
    assert.deepEqual(cdp.calls[1].params, { behavior: "default" });
    assertNoLeases(leaseDir);
  }));

test("a throwing fn propagates its error and still ends with default", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp();
    const boom = new Error("click failed");
    await assert.rejects(
      () => withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => { throw boom; }, { leaseDir }),
      (err) => err === boom,
    );
    assertAllSetDownloadBehavior(cdp);
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("a timeout-like failure VALUE still resets, and passes through untouched", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp();
    const failure = { ok: false, timeout: true, message: "navigation timed out" };
    const result = await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => failure, { leaseDir });
    assert.equal(result, failure);
    assertAllSetDownloadBehavior(cdp);
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("caller abort: an AbortError-like rejection still resets", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp();
    const aborted = new Error("the operation was aborted");
    aborted.name = "AbortError";
    await assert.rejects(
      () => withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => { throw aborted; }, { leaseDir }),
      (err) => err === aborted,
    );
    assertAllSetDownloadBehavior(cdp);
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("overlapping calls in this process: one default only, when the LAST call finishes", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp();
    let finishFirst;
    let finishSecond;
    const firstBody = new Promise((resolve) => { finishFirst = resolve; });
    const secondBody = new Promise((resolve) => { finishSecond = resolve; });

    const first = withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, () => firstBody, { leaseDir });
    const second = withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, () => secondBody, { leaseDir });
    await settle();

    assert.equal(leaseFiles(leaseDir).length, 2, "both calls hold a lease of their own");
    assert.deepEqual(behaviors(cdp), ["allow", "allow"]);

    finishFirst("one");
    assert.equal(await first, "one");
    await settle();
    assert.equal(leaseFiles(leaseDir).length, 1, "the finished call's lease is gone, the running one's is live");
    assert.deepEqual(behaviors(cdp), ["allow", "allow"], "the first call must not reset while the second is in flight");

    finishSecond("two");
    assert.equal(await second, "two");
    await settle();
    assertNoLeases(leaseDir);
    assertAllSetDownloadBehavior(cdp);
    assert.deepEqual(behaviors(cdp), ["allow", "allow", "default"]);
    assert.deepEqual(cdp.calls[2].params, { behavior: "default" });
  }));

test("a rejected reset is logged once and never overrides a successful fn", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp({ failOn: (method, params) => params?.behavior === "default" });
    const { value, lines } = await captureConsoleError(() =>
      withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "kept", { leaseDir }));
    assert.equal(value, "kept");
    assertAllSetDownloadBehavior(cdp);
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assert.equal(lines.length, 1, `expected one console.error line, got ${JSON.stringify(lines)}`);
    assertNoLeases(leaseDir);
  }));

test("a rejected reset leaves a throwing fn's own error as what propagates", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp({ failOn: (method, params) => params?.behavior === "default" });
    const boom = new Error("download body failed");
    const { lines } = await captureConsoleError(async () => {
      await assert.rejects(
        () => withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => { throw boom; }, { leaseDir }),
        (err) => err === boom,
      );
    });
    assertAllSetDownloadBehavior(cdp);
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assert.equal(lines.length, 1, `expected one console.error line, got ${JSON.stringify(lines)}`);
    assertNoLeases(leaseDir);
  }));

test("an allow send that fails propagates, still clears its lease, and attempts a reset", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp({ failOn: (method, params) => params?.behavior === "allow" });
    await assert.rejects(
      () => withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "never runs", { leaseDir }),
      /send rejected: allow/,
    );
    assertAllSetDownloadBehavior(cdp);
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("a null session at START: throws 'no CDP session', clears its lease, no reset attempt", () =>
  withLeaseDir(async (leaseDir) => {
    const { lines } = await captureConsoleError(async () => {
      await assert.rejects(
        () => withDownloadsAllowed(() => null, DOWNLOAD_PATH, async () => "never runs", { leaseDir }),
        { message: "no CDP session" },
      );
    });
    assert.deepEqual(lines, [], `a null session must not be logged, got ${JSON.stringify(lines)}`);
    assertNoLeases(leaseDir);
  }));

test("a session swapped mid-flight: allow goes to A, the single default to B", () =>
  withLeaseDir(async (leaseDir) => {
    const sessionA = makeCdp();
    const sessionB = makeCdp();
    let holder = sessionA;

    const result = await withDownloadsAllowed(() => holder, DOWNLOAD_PATH, async () => {
      holder = sessionB; // a reconnect during the download
      return "swapped";
    }, { leaseDir });

    assert.equal(result, "swapped");
    assert.deepEqual(behaviors(sessionA), ["allow"], "the old session is never reset");
    assert.deepEqual(behaviors(sessionB), ["default"], "the reset lands on the CURRENT session");
    assert.deepEqual(sessionB.calls[0].params, { behavior: "default" });
    assertNoLeases(leaseDir);
  }));

test("a null session at RESET time: no throw, no log", () =>
  withLeaseDir(async (leaseDir) => {
    const session = makeCdp();
    let reads = 0;
    const getSession = () => (reads++ === 0 ? session : null);

    const { value, lines } = await captureConsoleError(() =>
      withDownloadsAllowed(getSession, DOWNLOAD_PATH, async () => "kept", { leaseDir }));

    assert.equal(value, "kept");
    assert.deepEqual(behaviors(session), ["allow"], "no reset on a null session");
    assert.deepEqual(lines, [], `a null session must not be logged, got ${JSON.stringify(lines)}`);
    assertNoLeases(leaseDir);
  }));

test("a hung reset is bounded: the call finishes, one log line, every lease gone", () =>
  withLeaseDir(async (leaseDir) => {
    const session = makeCdp({ hangOn: (method, params) => params?.behavior === "default" });
    const startedAt = Date.now();

    const { value, lines } = await captureConsoleError(() =>
      withDownloadsAllowed(() => session, DOWNLOAD_PATH, async () => "kept", { leaseDir }));

    const elapsed = Date.now() - startedAt;
    assert.equal(value, "kept");
    assert.deepEqual(behaviors(session), ["allow", "default"]);
    assert.ok(
      elapsed >= RESET_TIMEOUT_MS - 100 && elapsed < RESET_TIMEOUT_MS + 1000,
      `expected the reset to give up after about ${RESET_TIMEOUT_MS} ms, took ${elapsed} ms`,
    );
    assert.equal(lines.length, 1, `expected one console.error line, got ${JSON.stringify(lines)}`);
    assert.match(lines[0], /restoring the default download behavior timed out/);
    assertNoLeases(leaseDir);
  }));

test("resetDownloadsOnNewSession: sends default when idle, nothing held, nothing for null", () =>
  withLeaseDir(async (leaseDir) => {
    // Idle: the safety net puts the browser-wide default back.
    const idle = makeCdp();
    await resetDownloadsOnNewSession(idle, { leaseDir });
    assertAllSetDownloadBehavior(idle);
    assert.deepEqual(behaviors(idle), ["default"]);
    assertNoLeases(leaseDir);

    // Null: nothing to send to, and nothing to log about.
    const { lines } = await captureConsoleError(async () => {
      assert.equal(await resetDownloadsOnNewSession(null, { leaseDir }), undefined);
    });
    assert.deepEqual(lines, []);

    // A download in flight: turning the setting off would break it, so the safety
    // net stays out of the way (checked on a DIFFERENT session, to prove the send
    // was skipped rather than merely sent elsewhere).
    const busy = makeCdp();
    let finish;
    const body = new Promise((resolve) => { finish = resolve; });
    const running = withDownloadsAllowed(() => busy, DOWNLOAD_PATH, () => body, { leaseDir });
    await settle();
    assert.equal(leaseFiles(leaseDir).length, 1, "the running call holds a live lease");

    const other = makeCdp();
    await resetDownloadsOnNewSession(other, { leaseDir });
    assert.deepEqual(other.calls, [], "no reset while a call holds downloads on");

    finish("done");
    assert.equal(await running, "done");
    await settle();
    assert.deepEqual(behaviors(busy), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("resetDownloadsOnNewSession never throws on a wedged session", () =>
  withLeaseDir(async (leaseDir) => {
    const session = makeCdp({ failOn: (method, params) => params?.behavior === "default" });
    const { lines } = await captureConsoleError(async () => {
      await resetDownloadsOnNewSession(session, { leaseDir });
    });
    assert.deepEqual(behaviors(session), ["default"]);
    assert.equal(lines.length, 1, `expected one console.error line, got ${JSON.stringify(lines)}`);
  }));

test("a foreign LIVE lease keeps the default back after a finishing call", () =>
  withLeaseDir(async (leaseDir) => {
    // Another process is mid-download right now.
    const foreign = plantLease(leaseDir, { pid: process.ppid, deadline: Date.now() + 60 * 60 * 1000 });

    const first = makeCdp();
    const result = await withDownloadsAllowed(() => first, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.equal(result, "done");
    assert.deepEqual(behaviors(first), ["allow"], "no default while another process's lease is live");
    assert.deepEqual(leaseFiles(leaseDir), [foreign], "the call's OWN lease is gone, the foreign one remains");

    // The other process finishes: the next call may put the default back.
    rmSync(join(leaseDir, foreign));
    const second = makeCdp();
    const again = await withDownloadsAllowed(() => second, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.equal(again, "done");
    assert.deepEqual(behaviors(second), ["allow", "default"], "exactly one default once no lease is live");
    assertNoLeases(leaseDir);
  }));

test("a DEAD pid's lease in THIS pid namespace is deleted while checking: the default IS sent", () =>
  withLeaseDir(async (leaseDir) => {
    const pid = deadPid();
    // A future deadline does not save it: a dead holder cannot be downloading.
    const stale = plantLease(leaseDir, {
      name: `${pid}-crashed`, pid, pidns: OUR_PIDNS, deadline: Date.now() + 60_000,
    });

    const cdp = makeCdp();
    const result = await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.equal(result, "done");
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assert.equal(leaseFiles(leaseDir).includes(stale), false, "the dead lease is deleted while checking");
    assertNoLeases(leaseDir);
  }));

test("a DEAD pid in ANOTHER pid namespace is still LIVE until its deadline: no default, file kept", () =>
  withLeaseDir(async (leaseDir) => {
    // bwrap --unshare-pid: the writer's pid means nothing here, so ESRCH from a
    // probe in this namespace must not be trusted to delete the lease.
    const pid = deadPid();
    const foreign = plantLease(leaseDir, {
      name: `${pid}-sandboxed`, pid, pidns: OTHER_PIDNS, deadline: Date.now() + 60_000,
    });

    const cdp = makeCdp();
    const result = await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.equal(result, "done");
    assert.deepEqual(behaviors(cdp), ["allow"], "a live lease in another namespace keeps the default back");
    assert.deepEqual(leaseFiles(leaseDir), [foreign], "the other namespace's lease is kept");

    // Past its deadline it is abandoned, whoever wrote it: judged by the deadline alone.
    plantLease(leaseDir, {
      name: `${pid}-sandboxed`, pid, pidns: OTHER_PIDNS, deadline: Date.now() - 1000,
    });
    const next = makeCdp();
    await withDownloadsAllowed(() => next, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.deepEqual(behaviors(next), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("a lease with NO pidns (written before pidns existed) is judged by its deadline alone", () =>
  withLeaseDir(async (leaseDir) => {
    const pid = deadPid();
    const legacy = plantLease(leaseDir, { name: `${pid}-legacy`, pid, pidns: null, deadline: Date.now() + 60_000 });

    const cdp = makeCdp();
    await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.deepEqual(behaviors(cdp), ["allow"], "an unknown namespace is treated as possibly live");
    assert.deepEqual(leaseFiles(leaseDir), [legacy]);
  }));

test("a FRESH .tmp lease file is ignored and left in place", () =>
  withLeaseDir(async (leaseDir) => {
    // A writer mid-rename: half-written content must never be read as a lease,
    // and it must not be deleted out from under the writer either.
    const tmpName = `${process.pid}-being-written.tmp`;
    writeFileSync(join(leaseDir, tmpName), '{"pid": 12');

    const cdp = makeCdp();
    const result = await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.equal(result, "done");
    assert.deepEqual(behaviors(cdp), ["allow", "default"], "a .tmp name is not a lease");
    assert.deepEqual(leaseFiles(leaseDir), [tmpName], "the fresh .tmp file is left alone");
  }));

test("an ABANDONED .tmp lease file (older than a minute) is deleted", () =>
  withLeaseDir(async (leaseDir) => {
    const tmpName = `${process.pid}-died-mid-write.tmp`;
    const tmpFile = join(leaseDir, tmpName);
    writeFileSync(tmpFile, '{"pid": 12');
    const longAgo = new Date(Date.now() - 5 * 60 * 1000);
    utimesSync(tmpFile, longAgo, longAgo);

    const cdp = makeCdp();
    await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("a lease file that cannot be removed is logged once and never thrown", () =>
  withLeaseDir(async (leaseDir) => {
    // Replace this call's own lease with a NON-EMPTY DIRECTORY of the same name:
    // unlink then fails with something other than ENOENT (EISDIR/EPERM).
    let swapped = null;
    const { value, lines } = await captureConsoleError(() =>
      withDownloadsAllowed(() => makeCdp(), DOWNLOAD_PATH, async () => {
        const own = readdirSync(leaseDir).filter((name) => !name.endsWith(".tmp"));
        assert.equal(own.length, 1, `expected exactly this call's lease, got ${JSON.stringify(own)}`);
        swapped = own[0];
        unlinkSync(join(leaseDir, swapped));
        mkdirSync(join(leaseDir, swapped));
        writeFileSync(join(leaseDir, swapped, "not-empty"), "x");
        return "done";
      }, { leaseDir }));

    assert.equal(value, "done", "a sticky lease must never fail the download");
    const removalLines = lines.filter((line) => /could not remove a download lease/.test(line));
    assert.equal(
      removalLines.length,
      1,
      `expected exactly one lease-removal console.error line, got ${JSON.stringify(lines)}`,
    );
    assert.ok(swapped, "the test must have swapped the lease");
  }));

test("an EXPIRED lease from a live pid is ignored and deleted: the default IS sent", () =>
  withLeaseDir(async (leaseDir) => {
    // process.ppid is alive, but its deadline has passed: it is not downloading.
    const stale = plantLease(leaseDir, { name: `${process.ppid}-expired`, pid: process.ppid, deadline: Date.now() - 1000 });

    const cdp = makeCdp();
    const result = await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.equal(result, "done");
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assert.equal(leaseFiles(leaseDir).includes(stale), false, "the expired lease is deleted while checking");
    assertNoLeases(leaseDir);
  }));

test("resetDownloadsOnNewSession is skipped while a foreign live lease exists, and sends default once it is gone", () =>
  withLeaseDir(async (leaseDir) => {
    const foreign = plantLease(leaseDir, { pid: process.ppid, deadline: Date.now() + 60 * 60 * 1000 });

    const busy = makeCdp();
    await resetDownloadsOnNewSession(busy, { leaseDir });
    assert.deepEqual(busy.calls, [], "no reset while another process holds downloads on");

    rmSync(join(leaseDir, foreign));
    const idle = makeCdp();
    await resetDownloadsOnNewSession(idle, { leaseDir });
    assertAllSetDownloadBehavior(idle);
    assert.deepEqual(behaviors(idle), ["default"]);
    assertNoLeases(leaseDir);
  }));

test("an UNPARSEABLE lease file is ignored and deleted: the default IS sent", () =>
  withLeaseDir(async (leaseDir) => {
    writeFileSync(join(leaseDir, "not-a-lease"), "{ this is not json");

    const cdp = makeCdp();
    const result = await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => "done", { leaseDir });
    assert.equal(result, "done");
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("a leaseDir that cannot be written fails closed: fn never runs, the allow is never sent, one log line", () =>
  withLeaseDir(async (leaseDir) => {
    // A path INSIDE a regular file: the lease write fails with ENOTDIR.
    const fileAsDir = join(leaseDir, "not-a-dir");
    writeFileSync(fileAsDir, "a regular file, so a lease cannot be written inside it");
    const unwritable = join(fileAsDir, "leases");

    const cdp = makeCdp();
    let fnRan = false;
    const { lines } = await captureConsoleError(async () => {
      await assert.rejects(
        () => withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => { fnRan = true; return "never"; }, { leaseDir: unwritable }),
        (err) => err instanceof Error,
      );
    });

    assert.equal(fnRan, false, "no lease means downloads stay off: the download body must not run");
    assert.deepEqual(cdp.calls, [], "the allow send is never attempted without a lease");
    assert.equal(lines.length, 1, `expected one console.error line, got ${JSON.stringify(lines)}`);
  }));

test("a planted far-future lease is honoured inside MAX_LEASE_MS and abandoned past it", () =>
  withLeaseDir(async (leaseDir) => {
    const T0 = 1_700_000_000_000;
    const planted = plantLease(leaseDir, {
      name: "planted-foreign", pid: process.pid, pidns: FOREIGN_PIDNS, start: T0, deadline: T0 + TEN_YEARS_MS,
    });

    // A second in: the lease is inside its window, so the default stays back.
    const early = makeCdp();
    await resetDownloadsOnNewSession(early, { leaseDir, now: () => T0 + 1000 });
    assert.deepEqual(early.calls, [], "a lease inside its window keeps the default back");
    assert.deepEqual(leaseFiles(leaseDir), [planted], "the honoured lease is kept");

    // One ms past the longest lease this bundle can take: abandoned, deleted.
    const late = makeCdp();
    await resetDownloadsOnNewSession(late, { leaseDir, now: () => T0 + MAX_LEASE_MS + 1 });
    assertAllSetDownloadBehavior(late);
    assert.deepEqual(behaviors(late), ["default"], "a lease older than MAX_LEASE_MS is abandoned");
    assertNoLeases(leaseDir);
  }));

test("the writer clamps an over-long deadline to MAX_LEASE_MS", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp();
    let lease;
    const result = await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => {
      const [name] = leaseFiles(leaseDir).filter((fileName) => !fileName.endsWith(".tmp"));
      assert.ok(name, "the call must have written a lease");
      lease = JSON.parse(readFileSync(join(leaseDir, name), "utf8"));
      return "done";
    }, { leaseDir, deadlineMs: MAX_LEASE_MS * 10 });

    assert.equal(result, "done");
    assert.ok(lease, "fn must have read this call's lease");
    assert.equal(
      lease.deadline - lease.start,
      MAX_LEASE_MS,
      "an over-long ask is clamped to MAX_LEASE_MS",
    );
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("a lease written for MAX_LEASE_MS is honoured inside it and abandoned at it", () =>
  withLeaseDir(async (leaseDir) => {
    const cdp = makeCdp();
    const result = await withDownloadsAllowed(() => cdp, DOWNLOAD_PATH, async () => {
      const [name] = leaseFiles(leaseDir).filter((fileName) => !fileName.endsWith(".tmp"));
      assert.ok(name, "the call must have written a lease");
      const lease = JSON.parse(readFileSync(join(leaseDir, name), "utf8"));
      assert.equal(lease.deadline - lease.start, MAX_LEASE_MS, "a MAX_LEASE_MS ask is written whole");

      // One ms inside the longest lease this module honours: still live.
      const early = makeCdp();
      await resetDownloadsOnNewSession(early, { leaseDir, now: () => lease.start + MAX_LEASE_MS - 1 });
      assert.deepEqual(early.calls, [], "a lease inside MAX_LEASE_MS keeps the default back");
      assert.equal(leaseFiles(leaseDir).includes(name), true, "the honoured lease is kept");

      // At exactly MAX_LEASE_MS it is over, whatever the file's own deadline says.
      const late = makeCdp();
      await resetDownloadsOnNewSession(late, { leaseDir, now: () => lease.start + MAX_LEASE_MS });
      assertAllSetDownloadBehavior(late);
      assert.deepEqual(behaviors(late), ["default"], "a lease at MAX_LEASE_MS is abandoned");

      return "done";
    }, { leaseDir, deadlineMs: MAX_LEASE_MS });

    assert.equal(result, "done");
    assert.deepEqual(behaviors(cdp), ["allow", "default"]);
    assertNoLeases(leaseDir);
  }));

test("a lease whose start is in the future is invalid: deleted at once, default sent", () =>
  withLeaseDir(async (leaseDir) => {
    const now = 1_700_000_000_000;
    plantLease(leaseDir, {
      name: "future-start", pid: process.pid, pidns: FOREIGN_PIDNS,
      start: now + 60 * 60 * 1000, deadline: now + TEN_YEARS_MS,
    });

    const cdp = makeCdp();
    await resetDownloadsOnNewSession(cdp, { leaseDir, now: () => now });
    assert.deepEqual(behaviors(cdp), ["default"]);
    assertNoLeases(leaseDir);
  }));

test("a start inside the clock skew is honoured, a start past it is invalid", () =>
  withLeaseDir(async (leaseDir) => {
    const now = 1_700_000_000_000;

    const inside = plantLease(leaseDir, {
      name: "skew-inside", pid: process.pid, pidns: FOREIGN_PIDNS,
      start: now + 4000, deadline: now + TEN_YEARS_MS,
    });
    const skewed = makeCdp();
    await resetDownloadsOnNewSession(skewed, { leaseDir, now: () => now });
    assert.deepEqual(skewed.calls, [], "a start inside the 5000 ms skew is honoured");
    assert.deepEqual(leaseFiles(leaseDir), [inside]);

    rmSync(join(leaseDir, inside));
    plantLease(leaseDir, {
      name: "skew-outside", pid: process.pid, pidns: FOREIGN_PIDNS,
      start: now + 6000, deadline: now + TEN_YEARS_MS,
    });
    const past = makeCdp();
    await resetDownloadsOnNewSession(past, { leaseDir, now: () => now });
    assert.deepEqual(behaviors(past), ["default"], "a start past the skew is invalid");
    assertNoLeases(leaseDir);
  }));

test("a lease with an unrepresentable or non-numeric deadline is invalid: deleted, default sent", () =>
  withLeaseDir(async (leaseDir) => {
    const now = 1_700_000_000_000;
    const head = `"pid":${process.pid},"pidns":${JSON.stringify(FOREIGN_PIDNS)},"start":${now}`;
    const cases = [
      // Infinity: JSON.stringify would write null, so the text is written by hand.
      [`{${head},"deadline":Infinity}`, "deadline Infinity"],
      [`{${head},"deadline":null}`, "deadline null"],
      [`{${head},"deadline":"9999999999999"}`, "deadline as a string"],
      // NaN is not JSON either: written through JSON.stringify it becomes null.
      [JSON.stringify({ pid: process.pid, pidns: FOREIGN_PIDNS, start: now, deadline: NaN }), "deadline NaN"],
    ];

    for (const [text, label] of cases) {
      const name = plantRawLease(leaseDir, text, `deadline-${label.replace(/\W+/g, "-")}`);
      const cdp = makeCdp();
      await resetDownloadsOnNewSession(cdp, { leaseDir, now: () => now });
      assert.deepEqual(behaviors(cdp), ["default"], `expected a default for ${label}`);
      assert.equal(leaseFiles(leaseDir).includes(name), false, `${label} must be deleted`);
      assertNoLeases(leaseDir);
    }
  }));

test("a lease whose start is a string is invalid: deleted, default sent", () =>
  withLeaseDir(async (leaseDir) => {
    const now = 1_700_000_000_000;
    const name = plantLease(leaseDir, {
      name: "string-start", pid: process.pid, pidns: FOREIGN_PIDNS,
      start: String(now), deadline: now + TEN_YEARS_MS,
    });

    const cdp = makeCdp();
    await resetDownloadsOnNewSession(cdp, { leaseDir, now: () => now });
    assert.deepEqual(behaviors(cdp), ["default"]);
    assert.equal(leaseFiles(leaseDir).includes(name), false, "a string start must be deleted");
    assertNoLeases(leaseDir);
  }));

test("a normal live lease from this process is still honoured", () =>
  withLeaseDir(async (leaseDir) => {
    const now = 1_700_000_000_000;
    const live = plantLease(leaseDir, {
      name: "normal", pid: process.pid, pidns: OUR_PIDNS, start: now, deadline: now + 60_000,
    });

    const cdp = makeCdp();
    await resetDownloadsOnNewSession(cdp, { leaseDir, now: () => now });
    assert.deepEqual(cdp.calls, [], "a live lease keeps the default back");
    assert.deepEqual(leaseFiles(leaseDir), [live], "the live lease is kept");
  }));

test("derivation: MAX_LEASE_MS sits 30000 ms above the download tool's timeout cap", () => {
  assert.equal(
    MAX_LEASE_MS,
    DOWNLOAD_TIMEOUT_CAP_MS + 30000,
    "the longest lease must outlive the longest wait by the same 30 s the tool's own lease uses",
  );
  assert.ok(
    MAX_LEASE_MS >= DEFAULT_LEASE_DEADLINE_MS,
    `MAX_LEASE_MS (${MAX_LEASE_MS}) must not be below DEFAULT_LEASE_DEADLINE_MS (${DEFAULT_LEASE_DEADLINE_MS})`,
  );
});

test("derivation: DOWNLOAD_TIMEOUT_CAP_MS is the crow_browser_download timeout_ms .max()", async () => {
  const { DEFAULT_MAX_TOOL_ACTION_MS } =
    await import("../bundles/browser/server/page-ownership.js");
  assert.equal(
    DOWNLOAD_TIMEOUT_CAP_MS,
    DEFAULT_MAX_TOOL_ACTION_MS - 5000,
    "the cap is the tool action limit minus its written-out margin",
  );

  const serverPath = fileURLToPath(new URL("../bundles/browser/server/server.js", import.meta.url));
  const source = readFileSync(serverPath, "utf8");
  // The tool's registration line, so the block sliced out is THIS tool and nothing earlier.
  const blockStart = source.indexOf('server.tool(\n    "crow_browser_download",');
  assert.ok(blockStart !== -1, "server.js must define the crow_browser_download tool");
  // The next two-space comment line closes the block (the handler's own comments are deeper).
  const blockEnd = source.indexOf("\n  // ", blockStart);
  const block = blockEnd > blockStart ? source.slice(blockStart, blockEnd) : source.slice(blockStart);

  assert.ok(block.includes("timeout_ms:"), "the crow_browser_download block must declare timeout_ms");
  assert.ok(
    block.includes(".max(DEFAULT_MAX_TOOL_ACTION_MS - 5000)"),
    "the timeout_ms schema must be capped by the written-out literal .max(DEFAULT_MAX_TOOL_ACTION_MS - 5000)",
  );
});

test("static: server.js imports withDownloadsAllowed and sends no setDownloadBehavior itself", () => {
  const serverPath = fileURLToPath(new URL("../bundles/browser/server/server.js", import.meta.url));
  const source = readFileSync(serverPath, "utf8");

  assert.match(
    source,
    /import\s*\{[^}]*\bwithDownloadsAllowed\b[^}]*\}\s*from\s*["']\.\/download-behavior\.js["']/,
    "server.js must import withDownloadsAllowed from ./download-behavior.js",
  );
  assert.match(
    source,
    /import\s*\{[^}]*\bresetDownloadsOnNewSession\b[^}]*\}\s*from\s*["']\.\/download-behavior\.js["']/,
    "server.js must import resetDownloadsOnNewSession from ./download-behavior.js",
  );
  assert.equal(
    source.includes("setDownloadBehavior"),
    false,
    "server.js must not call Browser.setDownloadBehavior: download-behavior.js is the only caller",
  );
});

test("static: server.js resets a new CDP session BEFORE Network.enable, with one shared lease dir", () => {
  const serverPath = fileURLToPath(new URL("../bundles/browser/server/server.js", import.meta.url));
  const source = readFileSync(serverPath, "utf8");

  const resetMatch = source.match(/await resetDownloadsOnNewSession\(cdpSession[^)]*\)/);
  assert.ok(
    resetMatch,
    "server.js must run the reconnect safety net on a new CDP session, passing its lease opts",
  );
  const resetIndex = resetMatch.index;

  // The two-space `function` line that opens the block the reset lives in.
  const enclosing = [...source.slice(0, resetIndex).matchAll(/^ {2}(?:async )?function\s+\w+/gm)].pop();
  assert.ok(enclosing, "the reset must live inside a function");
  const functionStart = enclosing.index;
  const functionEnd = source.indexOf("\n  }\n", resetIndex);
  assert.ok(functionEnd > resetIndex, "could not find the end of the function holding the reset");
  const functionBody = source.slice(functionStart, functionEnd);

  const networkIndex = functionBody.indexOf("Network.enable");
  assert.ok(networkIndex !== -1, "the reset's function must also enable Network (the blocked-hosts setup)");
  assert.ok(
    networkIndex > resetIndex - functionStart,
    "the reset must run BEFORE Network.enable: a fresh session is cleaned up before anything uses it",
  );

  assert.ok(
    source.includes('stateDir("browser-download-leases")'),
    'server.js must pass one lease dir, stateDir("browser-download-leases"), to both withDownloadsAllowed and resetDownloadsOnNewSession',
  );
});

test("static: download-behavior.js ends with exactly one newline", () => {
  const modulePath = fileURLToPath(new URL("../bundles/browser/server/download-behavior.js", import.meta.url));
  const source = readFileSync(modulePath, "utf8");
  assert.equal(source.endsWith("\n"), true, "download-behavior.js must end with a newline");
  assert.equal(source.endsWith("\n\n"), false, "download-behavior.js must not end with a blank line");
});