/**
 * Downloads, scoped to the one call that needs them.
 *
 * `Browser.setDownloadBehavior` is a BROWSER-WIDE setting: turning it on is not
 * per-page and not per-call. crow_browser_download used to send `{behavior:
 * "allow"}` and never put it back, so every later turn of every bot kept
 * downloads allowed on the operator's shared browser for the rest of the
 * process's life.
 *
 * So downloads are allowed only around the critical section, and the "who has
 * downloads on" bookkeeping is a DIRECTORY of lease files, not an in-process
 * counter: the setting is browser-wide while its callers are not. A second MCP
 * child of the same instance (a Gmail turn beside a Perch turn, a restart's
 * leftover) must not have its download cancelled by this process putting the
 * browser-wide default back, so the leases live under the shared state root —
 * the same `stateDir` the downloads themselves use — and every child of one
 * instance sees the same directory.
 *
 * Per call: write `<pid>-<random>` (JSON {pid, pidns, start, deadline}) into the
 * lease directory, send `allow`, run `fn`, remove the lease, and send `default`
 * ONLY when no live lease remains. A lease is live iff its holder is alive and
 * `now < deadline`; dead, expired and unparseable leases are deleted while
 * checking and ignored. A lease that cannot be written is fail-closed: no
 * `allow`, `fn` never runs, and the error propagates — no lease means downloads
 * stay off.
 *
 * A lease records the writer's PID NAMESPACE (`pidns`, `/proc/self/ns/pid`) next
 * to its pid. Bots run under `bwrap --unshare-pid`, so a pid is only meaningful
 * inside the namespace that wrote it: probing a sandboxed writer's pid from the
 * host (or the reverse) fails with a false ESRCH and would delete a LIVE lease.
 * The pid-liveness test therefore applies ONLY when the lease's `pidns` is a
 * string equal to this process's own; a lease from another (or an unknown)
 * namespace is judged by its deadline alone.
 *
 * A lease is written atomically — `<name>.tmp`, then rename to `<name>` — so a
 * reader never sees a half-written lease. The live check SKIPS (never deletes) a
 * `.tmp` name unless its mtime is older than a minute: a fresh one is a write in
 * progress, an old one is a writer that died mid-write.
 *
 * Accepted residual: a download that STARTS in the instant between another
 * process's lease check and its `default` landing can still be cancelled. The
 * window is narrow (one CDP round trip) and bounded by `RESET_TIMEOUT_MS`. And a
 * lease directory that can never be read keeps the fail-safe "live", so the
 * default is withheld rather than risked.
 *
 * `"default"`, NOT `"deny"`: `deny` would break the operator's own manual
 * downloads in the VNC viewer, and the viewer is a human using this same
 * browser.
 *
 * The session is asked for through a getter, never captured: a reconnect (a
 * restart, a dropped CDP session) hands out a NEW session, and a reset sent on
 * the old, dead one would leave the new one allowing downloads for good.
 *
 * The reset is BOUNDED: `page.context().newCDPSession()` can hand out a session
 * whose transport is already wedged, and a download call must not hang forever
 * waiting for a courtesy cleanup.
 */
import {
  mkdirSync, readdirSync, readFileSync, readlinkSync, renameSync, statSync, unlinkSync, writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

/** How long the reset send may take before it is given up on, in ms. */
export const RESET_TIMEOUT_MS = 2000;

/** How long a lease may be held before it counts as abandoned, unless told otherwise. */
export const DEFAULT_LEASE_DEADLINE_MS = 60000;

const RESET_TIMEOUT_MESSAGE = "[browser] restoring the default download behavior timed out";
const RESET_FAILED_MESSAGE = "[browser] could not restore the default download behavior:";
const LEASE_WRITE_FAILED_MESSAGE = "[browser] could not take a download lease:";
const LEASE_CHECK_FAILED_MESSAGE = "[browser] could not check the download leases:";
const LEASE_REMOVE_FAILED_MESSAGE = "[browser] could not remove a download lease:";

/** A `.tmp` lease name older than this was abandoned mid-write, not being written. */
const STALE_TMP_LEASE_MS = 60000;

/**
 * This process's PID namespace, spelled the way `/proc/self/ns/pid` spells it
 * (e.g. `pid:[4026531836]`), or null when it cannot be read.
 * @returns {string|null}
 */
function readOwnPidns() {
  try {
    return readlinkSync("/proc/self/ns/pid");
  } catch {
    return null;
  }
}

/** Read once: a process cannot move to another PID namespace. */
const OWN_PIDNS = readOwnPidns();

/** Sentinel for "the send did not settle in time". */
const TIMED_OUT = Symbol("reset-timeout");

/**
 * Best-effort, bounded `default` send. Never throws and never rejects: the
 * caller's own result (or its own error) is the real outcome of the call, and a
 * browser that will not take `default` back must not turn a finished download
 * into a failure — nor may it outlive the call's own timeout.
 * @param {object} cdpSession - a non-null CDP session with `send`
 */
async function resetDownloads(cdpSession) {
  let timer;
  // The no-op catch is attached BEFORE the race: a send that settles late (after
  // the timeout won) is then ignored, never an unhandled rejection.
  const rawSend = Promise.resolve()
    .then(() => cdpSession.send("Browser.setDownloadBehavior", { behavior: "default" }));
  rawSend.catch(() => { /* a late failure is not the caller's problem */ });
  const send = rawSend.then((value) => ({ value }), (err) => ({ err }));
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve(TIMED_OUT), RESET_TIMEOUT_MS);
  });
  try {
    const outcome = await Promise.race([send, timeout]);
    if (outcome === TIMED_OUT) {
      console.error(RESET_TIMEOUT_MESSAGE);
      return;
    }
    if ("err" in outcome) {
      console.error(RESET_FAILED_MESSAGE, outcome.err?.message || outcome.err);
    }
  } catch (err) {
    console.error(RESET_FAILED_MESSAGE, err?.message || err);
  } finally {
    // Cleared as soon as the send settles (or the timeout fires), so a finished
    // call never holds the process open for the rest of the window.
    clearTimeout(timer);
  }
}

/**
 * Remove a lease file, best-effort: a lease that is already gone is gone. Never
 * throws. `log` is for THIS call's own lease, where a failure to release it is
 * worth exactly one console.error line (and nothing more).
 * @param {string} leaseFile
 * @param {{ log?: boolean }} [opts]
 */
function removeLease(leaseFile, opts = {}) {
  try {
    unlinkSync(leaseFile);
  } catch (err) {
    if (err?.code === "ENOENT") return;
    if (opts.log) console.error(LEASE_REMOVE_FAILED_MESSAGE, err?.message || err);
  }
}

/**
 * Is `pid` a running process? ESRCH means no such process; EPERM means it exists
 * but belongs to someone else — which counts as ALIVE (fail safe: do not reset).
 * @param {number} pid
 * @returns {boolean}
 */
function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code !== "ESRCH";
  }
}

/**
 * Does anyone still hold downloads on in `leaseDir`?
 *
 * A lease is live iff it parses, its deadline is still in the future, and — only
 * when it was written in THIS PID namespace — its pid is alive. A lease from
 * another (or an unknown) namespace is judged by its deadline alone: its pid
 * means nothing here, and a false ESRCH would delete a live lease. Unparseable,
 * dead and expired leases are deleted while checking and ignored; a `.tmp` name
 * is skipped unless it is old enough to be an abandoned write. Any fs error
 * while checking is treated as "live" (fail safe: do not put the browser-wide
 * default back under a possible download) and reported in ONE console.error
 * line — this helper never throws.
 *
 * @param {string} [leaseDir]
 * @returns {boolean} true when a live lease remains (or could not be ruled out)
 */
function hasLiveLease(leaseDir) {
  if (!leaseDir) return false;
  let names;
  try {
    names = readdirSync(leaseDir);
  } catch (err) {
    // No directory yet: nobody has ever taken a lease here.
    if (err?.code === "ENOENT") return false;
    console.error(LEASE_CHECK_FAILED_MESSAGE, err?.message || err);
    return true;
  }
  const now = Date.now();
  for (const name of names) {
    const leaseFile = join(leaseDir, name);
    if (name.endsWith(".tmp")) {
      // A write in progress (skip it), or one whose writer died mid-write (delete
      // it once it is old enough to rule out). Never a lease either way.
      let stats;
      try {
        stats = statSync(leaseFile);
      } catch (err) {
        if (err?.code === "ENOENT") continue;
        console.error(LEASE_CHECK_FAILED_MESSAGE, err?.message || err);
        return true;
      }
      if (now - stats.mtimeMs > STALE_TMP_LEASE_MS) removeLease(leaseFile);
      continue;
    }
    let raw;
    try {
      raw = readFileSync(leaseFile, "utf8");
    } catch (err) {
      // Vanished between readdir and read: it holds nothing.
      if (err?.code === "ENOENT") continue;
      console.error(LEASE_CHECK_FAILED_MESSAGE, err?.message || err);
      return true;
    }
    let lease;
    try {
      lease = JSON.parse(raw);
    } catch {
      removeLease(leaseFile);
      continue;
    }
    if (!lease || !Number.isInteger(lease.pid) || typeof lease.deadline !== "number") {
      removeLease(leaseFile);
      continue;
    }
    // A pid only means something inside the namespace that wrote it: only trust
    // the liveness probe when the lease names THIS process's PID namespace.
    const sameNamespace = typeof lease.pidns === "string" && lease.pidns === OWN_PIDNS;
    if (sameNamespace && !pidAlive(lease.pid)) {
      removeLease(leaseFile);
      continue;
    }
    if (lease.deadline <= now) {
      removeLease(leaseFile);
      continue;
    }
    return true;
  }
  return false;
}

/**
 * Take this call's lease, or throw. A lease that cannot be written is
 * fail-closed: without it another process could put the default back under this
 * download, so the download must not start.
 *
 * Written atomically: `<name>.tmp` first, then renamed onto `<name>`, so a
 * concurrent reader sees either no lease or a whole one.
 *
 * @param {string} leaseDir
 * @param {number} deadlineMs
 * @returns {string} the lease file's path
 */
function takeLease(leaseDir, deadlineMs) {
  const leaseFile = join(leaseDir, `${process.pid}-${randomBytes(8).toString("hex")}`);
  const tmpFile = `${leaseFile}.tmp`;
  try {
    mkdirSync(leaseDir, { recursive: true });
    writeFileSync(tmpFile, JSON.stringify({
      pid: process.pid,
      pidns: OWN_PIDNS,
      start: Date.now(),
      deadline: Date.now() + deadlineMs,
    }));
    renameSync(tmpFile, leaseFile);
  } catch (err) {
    // A half-written .tmp is not a lease; drop it silently (the checker would
    // eventually collect it, but there is no reason to leave it behind).
    try { unlinkSync(tmpFile); } catch { /* never taken, or already gone */ }
    console.error(LEASE_WRITE_FAILED_MESSAGE, err?.message || err);
    throw new Error(`could not take a download lease in ${leaseDir}: ${err?.message || err}`);
  }
  return leaseFile;
}

/**
 * Run `fn` with browser-wide downloads allowed into `downloadPath`.
 *
 * The lease is written BEFORE anything else: it is what tells the other MCP
 * children of this instance that a download is in flight. The allow send is
 * inside the try: if it fails, `fn` never runs, the lease is still removed, and
 * the send's error propagates.
 *
 * The session is read TWICE — once for the allow, once for the final reset —
 * so the reset lands on whichever session is current when the download is done.
 * A null session is an error for the allow (there is nothing to allow on) and
 * silently skipped for the reset (there is nothing to put back).
 *
 * @template T
 * @param {() => (object|null)} getSession - returns the CURRENT CDP session, or null
 * @param {string} downloadPath - the container-side directory downloads land in
 * @param {() => Promise<T>} fn
 * @param {{ leaseDir?: string, deadlineMs?: number }} [opts]
 * @returns {Promise<T>}
 */
export async function withDownloadsAllowed(getSession, downloadPath, fn, opts = {}) {
  const leaseDir = opts.leaseDir;
  const deadlineMs = typeof opts.deadlineMs === "number" ? opts.deadlineMs : DEFAULT_LEASE_DEADLINE_MS;
  const leaseFile = takeLease(leaseDir, deadlineMs);
  try {
    const session = getSession();
    if (!session) throw new Error("no CDP session");
    await session.send("Browser.setDownloadBehavior", { behavior: "allow", downloadPath });
    return await fn();
  } finally {
    removeLease(leaseFile, { log: true });
    // Only the LAST caller out turns them back off — and "last" is judged across
    // processes, so a download another MCP child is still waiting on is never
    // cancelled by this one finishing. An earlier caller would pull the setting
    // out from under a call that is still waiting for its file.
    if (!hasLiveLease(leaseDir)) {
      const session = getSession();
      // Nothing current to reset: no log, no throw — a session that went away
      // took the browser-wide setting with it.
      if (session) await resetDownloads(session);
    }
  }
}

/**
 * Safety net for a fresh CDP session: a reconnect without a reset in between
 * would otherwise leave downloads allowed on the browser for good.
 *
 * Only when no live lease remains: a reset while a download is in flight (here
 * or in another MCP child of this instance) would turn the setting off under the
 * download that is still waiting for its file. Best-effort and bounded like
 * every other reset — this must never throw into the connect path.
 *
 * @param {object|null} session - the newly made CDP session, or null
 * @param {{ leaseDir?: string }} [opts]
 */
export async function resetDownloadsOnNewSession(session, opts = {}) {
  if (!session) return;
  try {
    if (hasLiveLease(opts.leaseDir)) return;
    await resetDownloads(session);
  } catch (err) {
    console.error(LEASE_CHECK_FAILED_MESSAGE, err?.message || err);
  }
}
