/**
 * X display bookkeeping for the live headful case: is display `:n` really IN
 * USE, or is its `/tmp` litter left over from an Xvfb somebody killed?
 *
 * The old headful test picked a display by `existsSync("/tmp/.X<n>-lock")` and
 * stopped its Xvfb with SIGKILL. An X server killed with SIGKILL cannot unlink
 * its own lock (`/tmp/.X<n>-lock`) or socket (`/tmp/.X11-unix/X<n>`), so every
 * run left one more pair behind — and since the picker treated ANY lock as
 * taken, after ~50 runs there was "no free X display number between :90 and
 * :139" even though nothing was running.
 *
 * So the state of a display is judged from its owner, not from a file existing:
 *
 *   "taken"  something is using (or owns) this display — never touch its files
 *   "stale"  only litter is there: a dead owner's lock, a socket nobody listens on
 *   "free"   no lock and no socket
 *
 * A live unix-socket listener at `X<n>` outranks a lock that names a dead pid:
 * that shape is a display whose lock was left behind by a killed server while
 * ANOTHER server now owns the display (a different namespace, a reused number),
 * and unlinking that socket would break the live server for every new client.
 * The dead-pid lock is still litter when nothing listens — it just has to be
 * cleaned together with the socket.
 *
 * Every path a test touches is injected through `opts`, so the unit tests run
 * entirely in a mkdtemp directory and never see the real /tmp X-litter.
 */
import { existsSync, readFileSync, rmSync } from "node:fs";
import { createConnection } from "node:net";
import { join } from "node:path";

/** Xvfb's defaults, and what every caller here wants. */
const DEFAULTS = {
  lockDir: "/tmp",
  socketDir: "/tmp/.X11-unix",
  from: 90,
  to: 140, // exclusive, like a range check
  socketListening: null, // filled in below: the unix-socket probe
  termMs: 3000,
  killMs: 2000,
};

const lockPath = (lockDir, n) => join(lockDir, `.X${n}-lock`);
const socketPath = (socketDir, n) => join(socketDir, `X${n}`);

/**
 * Is `pid` an alive process? Only a positive integer is a pid at all (0 and -1
 * are signal broadcasts, "123" a string); EPERM means the process exists but is
 * not ours, which is still alive.
 */
export function isPidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return Boolean(err && err.code === "EPERM");
  }
}

/**
 * The default listener probe: can a unix socket be connected at `path` within
 * ~500 ms? A leftover socket FILE (nobody listening) refuses or errors at once;
 * a live X server accepts. Never throws, never keeps the socket.
 */
function probeSocket(path, timeoutMs = 500) {
  return new Promise((resolve) => {
    let settled = false;
    let timer = null;
    const socket = createConnection({ path });
    const finish = (value) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      socket.removeAllListeners();
      socket.destroy();
      resolve(value);
    };
    timer = setTimeout(() => finish(false), timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

/** Defaults on the left, the caller's opts on the right (undefined wins nothing). */
function config(opts) {
  const merged = { ...DEFAULTS, ...(opts || {}) };
  if (typeof merged.socketListening !== "function") merged.socketListening = probeSocket;
  return merged;
}

/** The pid Xvfb wrote into the lock ("%10d\n"), or null if it is unreadable junk. */
function readLockPid(path) {
  let text;
  try {
    text = readFileSync(path, "utf8").trim();
  } catch {
    return null; // unreadable: judge the display by its socket below
  }
  if (!/^\d+$/.test(text)) return null;
  const pid = Number(text);
  return Number.isInteger(pid) && pid > 0 ? pid : null;
}

/** "free" | "stale" | "taken" for display `:n` (see the file header). */
export async function displayState(n, opts) {
  const cfg = config(opts);
  const lock = lockPath(cfg.lockDir, n);
  const socket = socketPath(cfg.socketDir, n);
  const hasLock = existsSync(lock);
  const hasSocket = existsSync(socket);

  // A lock naming a live process is the cheapest and strongest answer.
  if (hasLock) {
    const pid = readLockPid(lock);
    if (pid !== null && isPidAlive(pid)) return "taken";
  }
  // A live listener outranks a dead-pid or unreadable lock: the display is in use.
  if (hasSocket && (await cfg.socketListening(socket))) return "taken";

  if (hasLock) return "stale"; // a dead owner's lock, or a lock nobody can read
  if (hasSocket) return "stale"; // a socket file nobody listens on
  return "free";
}

/**
 * Remove display `:n`'s litter — but nothing at all if the display is TAKEN.
 * A lock whose pid is alive is never unlinked; neither is a live server's
 * socket. Returns true when the display may now be used.
 */
export async function removeStaleDisplayFiles(n, opts) {
  const cfg = config(opts);
  if ((await displayState(n, cfg)) === "taken") return false;
  try {
    rmSync(lockPath(cfg.lockDir, n), { force: true });
    rmSync(socketPath(cfg.socketDir, n), { force: true });
  } catch {
    // Best effort: a lock owned by another user cannot be unlinked, and the
    // caller's next display is the answer, not a crash.
  }
  return true;
}

/**
 * The first display in [from, to) that is free or was successfully cleaned:
 * the number, or null when every one of them is taken. Never a taken display.
 */
export async function pickFreeDisplay(opts) {
  const cfg = config(opts);
  for (let n = cfg.from; n < cfg.to; n++) {
    const state = await displayState(n, cfg);
    if (state === "free") return n;
    if (state === "stale" && (await removeStaleDisplayFiles(n, cfg))) return n;
  }
  return null;
}

/** Resolve once the child has exited (or `ms` passed): true when it exited. */
function waitForExit(child, ms) {
  const exited = () => child.exitCode !== null || child.signalCode !== null;
  if (exited()) return Promise.resolve(true);
  return new Promise((resolve) => {
    const onExit = () => {
      clearTimeout(timer);
      resolve(true);
    };
    const timer = setTimeout(() => {
      child.removeListener("exit", onExit);
      resolve(exited());
    }, ms);
    child.once("exit", onExit);
  });
}

/** Signal the child's process group (it is spawned detached), else the child. */
function signal(child, sig) {
  try {
    process.kill(-child.pid, sig);
    return;
  } catch {
    /* no group of its own, or already gone */
  }
  try {
    process.kill(child.pid, sig);
  } catch {
    /* already gone */
  }
}

/**
 * Stop display `:n`'s Xvfb and remove its lock and socket. Idempotent (call it
 * from `t.after` and again on the success path) and never throws: a stop that
 * fails must not turn into a test error about the stop.
 *
 * SIGTERM to the process group first (an X server that gets it shuts down and
 * unlinks its own files); SIGKILL to the group only if it is still alive after
 * `termMs`. Either way the files are cleaned up at the end — that is the part a
 * killed Xvfb cannot do for itself.
 */
export async function stopXvfb(child, n, opts) {
  const cfg = config(opts);
  try {
    if (child && typeof child.pid === "number" && child.pid > 0) {
      const exited = () => child.exitCode !== null || child.signalCode !== null;
      if (!exited()) {
        signal(child, "SIGTERM");
        if (!(await waitForExit(child, cfg.termMs)) && !exited()) {
          signal(child, "SIGKILL");
          await waitForExit(child, cfg.killMs);
        }
      }
    }
  } catch {
    /* a stop never throws (a bad child object, a signal race) */
  }
  try {
    await removeStaleDisplayFiles(n, cfg);
  } catch {
    /* best effort, see above */
  }
}