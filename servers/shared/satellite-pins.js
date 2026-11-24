/**
 * The satellite ADDRESS PIN (SAT-1 follow-up, the peer-origin pin's shape).
 *
 * `satellites.tailnet_host` is a plain crow.db column, and a contained bot has crow.db bound
 * read-write. Every sender used to dial `https://<that host>` and attach an ed25519 management-key
 * signature plus the request BODY (an add-on's env values, a bot's tool arguments, a whole encrypted
 * backup). The signature covers method, path, body, satellite id, ts, nonce and caller — NOT the
 * destination — and the response signature only stops a rogue host from answering: it can still
 * harvest the body and deny service. So the host a satellite is dialled at is recorded HERE, in
 * <CROW_HOME>/secrets (the dir the pi sandbox hides from bots), at pairing time, and every sender
 * asks this module for its URL. Nothing a bot writes into crow.db can move a satellite call.
 *
 * File format (mode 0600):
 *   {
 *     "<satellite-id>": { "pinned_host": "sat1.example.ts.net", "pinned_at": "ISO-8601" }
 *   }
 *
 * The one-time pin-backfill marker is NOT a key in this file: every top-level key is a satellite
 * id, so a marker key would be an entry any store writer could clobber (the exact bug the peer
 * credential store documents). It lives in its own
 * <CROW_HOME>/secrets/satellite-pin-backfill.json (see satellitePinBackfillPath).
 *
 * Exports are synchronous and shared (no gateway imports), so the CLI, the gateway and the tests
 * all load the same rules. NOTHING here puts a host, URL or address into a thrown message or a log
 * line: those reach logs, error reports and an operator's terminal, and the address is exactly
 * what a hostile row tried to choose.
 */
import {
  chmodSync, closeSync, constants as fsc, fsyncSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync,
  readdirSync, readSync, renameSync, statSync, unlinkSync, writeSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { isIP } from "node:net";
import { randomBytes } from "node:crypto";
import { secretsDir } from "./secret-values.js";
import { isSatelliteId } from "./satellite-protocol.js";

// ── the host form ───────────────────────────────────────────────────────────

const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const HOST_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})*$`);
const MAX_HOST_LEN = 253;
/** Printable ASCII only: this single class refuses every space, control character and non-ASCII. */
const NON_PRINTABLE_ASCII = /[^\x21-\x7e]/;

/** True for an IPv4 literal inside the tailnet range 100.64.0.0/10. */
export function isTailnetIPv4(h) {
  if (isIP(h) !== 4) return false;
  const [a, b] = h.split(".").map(Number);
  return a === 100 && b >= 64 && b <= 127;
}

/**
 * The pinned form of a satellite address, or null.
 *
 * Accepts exactly: a MagicDNS name (`<machine>.<tailnet>.ts.net`, valid labels) or a
 * 100.64.0.0/10 IPv4 literal. Uppercase is lowercased. Everything else is REFUSED, never repaired
 * and never trimmed: a port, user info, a path, a query, a fragment, a bracketed IPv6 literal, any
 * whitespace (leading, trailing or inner), a trailing dot, a non-ASCII/IDN name, an empty or
 * non-string value, and the decimal/octal/hex integer spellings of an IPv4 address
 * (`2130706433`, `0177.0.0.1`, `0x7f.1`) — those are exactly the forms a string comparison would
 * miss while the fetch's own URL parser still dials them.
 *
 * The old pairing-time `normalizeHost` lives here now (this module is shared, pairing.js re-exports
 * it), and it is stricter in two places a pair host never needs: it does not strip a trailing dot
 * (a pin is compared exactly, so silently rewriting the input would let two spellings disagree),
 * and a MagicDNS name needs a machine label AND a tailnet label before `.ts.net`.
 */
export function normalizeSatelliteHost(input) {
  if (typeof input !== "string") return null;
  // No trim(): leading/trailing whitespace is a refusal, not something to clean up.
  if (!input || input.length > MAX_HOST_LEN) return null;
  if (NON_PRINTABLE_ASCII.test(input)) return null;
  if (input.endsWith(".")) return null;
  const h = input.toLowerCase();
  if (isIP(h)) return isTailnetIPv4(h) ? h : null;
  if (!HOST_RE.test(h)) return null;
  if (!h.endsWith(".ts.net")) return null;
  // <machine>.<tailnet>.ts.net: a bare "a.ts.net" is not a MagicDNS endpoint.
  return h.split(".").length >= 4 ? h : null;
}

// ── paths ───────────────────────────────────────────────────────────────────

/**
 * The pin store: <CROW_HOME>/secrets/satellite-pins.json (the same 700 dir, and the same
 * CROW_HOME resolution, as the peer credential store). CROW_SATELLITE_PINS_PATH names another file
 * (tests, odd layouts). Resolved at CALL time, never at module load: an ESM import is hoisted
 * above the gateway's in-body .env loader, so a module-load constant would silently ignore a
 * CROW_HOME set only in .env.
 */
export function satellitePinsPath(env = process.env) {
  const o = env.CROW_SATELLITE_PINS_PATH;
  if (o) return resolve(o);
  return join(secretsDir(env), "satellite-pins.json");
}

/**
 * The one-time backfill marker FILE (never a key in the pin store): its own file, beside the
 * store, so it follows the same CROW_HOME scoping. CROW_SATELLITE_PIN_BACKFILL_PATH names it
 * explicitly (tests, odd layouts).
 */
export function satellitePinBackfillPath(env = process.env) {
  const o = env.CROW_SATELLITE_PIN_BACKFILL_PATH;
  if (o) return resolve(o);
  return join(dirname(satellitePinsPath(env)), "satellite-pin-backfill.json");
}

// ── reading ─────────────────────────────────────────────────────────────────

/** This user's uid, or undefined where the platform has none (the check is then skipped). */
function ownUid() {
  try { return process.getuid?.(); } catch { return undefined; }
}

/** A pin store or marker larger than this is not one (and is not read into memory). */
const MAX_PRIVATE_FILE_BYTES = 1024 * 1024;

/**
 * The text of a file we may trust to be the pin store or the backfill marker: lstat FIRST (a
 * SYMLINK is refused outright — never followed, never written through, and it reads as absent),
 * then open with O_NOFOLLOW and fstat the fd, so the file read is the file checked (a swap between
 * the two is a different inode and is refused). Returns `{ mode, text }`, or null for anything
 * else: missing, a symlink, a directory or FIFO, another user's file, an unreadable file.
 */
function readPrivateFile(path) {
  const uid = ownUid();
  let fd;
  try {
    const lst = lstatSync(path);
    if (lst.isSymbolicLink() || !lst.isFile()) return null;
    if (uid !== undefined && lst.uid !== uid) return null;
    fd = openSync(path, fsc.O_RDONLY | fsc.O_NOFOLLOW | (fsc.O_NONBLOCK || 0));
    const st = fstatSync(fd);
    if (!st.isFile() || st.ino !== lst.ino || st.dev !== lst.dev) return null;
    if (uid !== undefined && st.uid !== uid) return null;
    if (st.size > MAX_PRIVATE_FILE_BYTES) return null;
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) {
      const n = readSync(fd, buf, off, st.size - off, off);
      if (n <= 0) break;
      off += n;
    }
    return { mode: st.mode & 0o777, text: buf.subarray(0, off).toString("utf8") };
  } catch {
    return null;
  } finally {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* closed */ } }
  }
}

const _warned = new Set();
function warnOnce(key, msg) {
  if (_warned.has(key)) return;
  _warned.add(key);
  try { console.warn(msg); } catch { /* no console */ }
}

/** A pin entry: a plain object carrying a string `pinned_host`. Anything else is not one. */
function isPinEntry(v) {
  return Boolean(v) && typeof v === "object" && !Array.isArray(v) && typeof v.pinned_host === "string";
}

/**
 * The store as written, or {} when it is missing, unreadable, unparseable, a symlink (which reads
 * as "no pins" — every sender then refuses no-pin rather than trusting a file a link names), or
 * world/group readable (a pin store a bot shell could read is not a trust boundary). Never throws.
 */
function readStoreRaw(path) {
  const f = readPrivateFile(path);
  if (!f) return {};
  if (f.mode !== 0o600) {
    warnOnce(`mode:${path}`, `[satellite-pins] the satellite pin store has mode ${f.mode.toString(8)}; expected 600 — refusing to read it`);
    return {};
  }
  if (!f.text.trim()) return {};
  try {
    const o = JSON.parse(f.text);
    return o && typeof o === "object" && !Array.isArray(o) ? o : {};
  } catch {
    return {};
  }
}

/**
 * Only real entries: a key that is a satellite id, and a value carrying a string `pinned_host`.
 * Every reader goes through this, so a hand-written marker key (`done_at`, `__meta`) is skipped
 * rather than iterated as a satellite.
 */
function validEntries(all) {
  const out = {};
  for (const [id, v] of Object.entries(all)) {
    if (!isSatelliteId(id)) continue;
    if (!isPinEntry(v)) continue;
    out[id] = v;
  }
  return out;
}

/**
 * The pinned host for one satellite, or null (no pin, bad id, or an unreadable store). Never throws.
 * `env` (default process.env) must be the SAME env the caller's key read uses: the store path and
 * the secrets dir are both resolved through it, so a caller may not gate on one home and sign with
 * another.
 */
export function getSatellitePin(satId, { env } = {}) {
  if (!isSatelliteId(satId)) return null;
  try {
    const entry = readStoreRaw(satellitePinsPath(env || process.env))[satId];
    return isPinEntry(entry) ? entry.pinned_host : null;
  } catch {
    return null;
  }
}

/** Every pin, `{ id, host }`, skipping any key that is not a satellite id or a pin entry. */
export function listSatellitePins({ env } = {}) {
  let all = {};
  try { all = validEntries(readStoreRaw(satellitePinsPath(env || process.env))); } catch { all = {}; }
  return Object.entries(all).map(([id, v]) => ({ id, host: v.pinned_host }));
}

// ── writing: one lock for every writer ──────────────────────────────────────
//
// The gateway (a pairing ceremony, the boot backfill) and the owner's CLI can write at the same
// moment. Like the peer credential store, each write takes an exclusive lockfile, re-reads the
// file INSIDE the lock, applies its change, and renames a per-writer tmp file into place, so no
// writer can drop another's pin.

const LOCK_WAIT_MS = 5_000;
const LOCK_STALE_MS = 30_000;
const _sleepCell = new Int32Array(new SharedArrayBuffer(4));
function sleepSync(ms) { Atomics.wait(_sleepCell, 0, 0, ms); }

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (err) { return err.code === "EPERM"; }
}

let _bootId;
function bootId() {
  if (_bootId === undefined) {
    try { _bootId = readFileSync("/proc/sys/kernel/random/boot_id", "utf-8").trim() || null; } catch { _bootId = null; }
  }
  return _bootId;
}

function readLock(lockPath) {
  try { return JSON.parse(readFileSync(lockPath, "utf-8")); } catch { return null; }
}

function lockAgeMs(lockPath, holder) {
  const ts = Number(holder?.ts);
  if (Number.isFinite(ts)) return Date.now() - ts;
  try { return Date.now() - statSync(lockPath).mtimeMs; } catch { return 0; }
}

/** A lock older than LOCK_STALE_MS whose holder is gone: dead pid, another boot, or a torn write. */
function isStale(lockPath, holder) {
  if (lockAgeMs(lockPath, holder) <= LOCK_STALE_MS) return false;
  if (!holder || typeof holder !== "object") return true;
  if (holder.boot && bootId() && holder.boot !== bootId()) return true;
  return !pidAlive(Number(holder.pid));
}

function acquireLock(lockPath, waitMs = LOCK_WAIT_MS) {
  const started = Date.now();
  const me = { pid: process.pid, ts: Date.now(), boot: bootId(), nonce: randomBytes(6).toString("hex") };
  let holder = null;
  for (;;) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      try { writeSync(fd, JSON.stringify(me)); } finally { closeSync(fd); }
      return me;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
    }
    holder = readLock(lockPath);
    if (isStale(lockPath, holder)) {
      // Break by rename, then check it was the lock we judged: a racing breaker may already have
      // replaced it with a live one.
      const aside = `${lockPath}.${process.pid}.${randomBytes(4).toString("hex")}.stale`;
      try {
        renameSync(lockPath, aside);
        const moved = readLock(aside);
        const same = (moved === null && holder === null) || (moved && holder && moved.nonce === holder.nonce && moved.pid === holder.pid);
        if (!same && !isStale(aside, moved)) {
          try { const fd = openSync(lockPath, "wx", 0o600); try { writeSync(fd, JSON.stringify(moved)); } finally { closeSync(fd); } } catch { /* taken */ }
        }
        try { unlinkSync(aside); } catch { /* gone */ }
      } catch { /* someone else broke it */ }
      continue;
    }
    if (Date.now() - started > waitMs) throw new Error("the satellite pin store is locked by another writer");
    sleepSync(2 + Math.floor(Math.random() * 5));
  }
}

function releaseLock(lockPath, me) {
  const cur = readLock(lockPath);
  if (cur && cur.nonce === me.nonce && cur.pid === me.pid) {
    try { unlinkSync(lockPath); } catch { /* already gone */ }
  }
}

function ensureDirFor(dest) {
  try { mkdirSync(dirname(dest), { recursive: true, mode: 0o700 }); } catch { /* exists or read-only */ }
  try {
    const st = statSync(dirname(dest));
    if (st.uid === process.getuid?.() && (st.mode & 0o777) !== 0o700) chmodSync(dirname(dest), 0o700);
  } catch { /* best effort */ }
}

function fsyncDir(dir) {
  let fd;
  try { fd = openSync(dir, "r"); fsyncSync(fd); } catch { /* not supported here */ } finally { if (fd !== undefined) try { closeSync(fd); } catch { /* closed */ } }
}

/**
 * Write `data` to `dest` (600) through a per-writer tmp file: fsync, rename, fsync the dir.
 *
 * The destination must not be a symlink. rename() replaces a NAME, so it would not follow the link
 * — but it would happily replace the link with our file, which means this module writes "the pin
 * store" (or "the marker") while whatever wrote that link keeps aiming the name somewhere else.
 * A symlink (or any non-regular file) at the destination is a refusal.
 */
function writeDurable(dest, data) {
  let cur = null;
  try { cur = lstatSync(dest); } catch { /* absent: fine */ }
  if (cur && (cur.isSymbolicLink() || !cur.isFile())) throw new Error("the destination is not a regular file; refusing to write it");
  const tmp = `${dest}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    const fd = openSync(tmp, "wx", 0o600);
    try { writeSync(fd, data); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(tmp, dest);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* never created */ }
    throw err;
  }
  chmodSync(dest, 0o600);
  fsyncDir(dirname(dest));
}

/** Under the store lock, any `<store>.<pid>.<hex>.tmp` belongs to a writer that died mid-write. */
function removeCrashedTmps(dest) {
  const prefix = basename(dest) + ".";
  let names = [];
  try { names = readdirSync(dirname(dest)); } catch { return; }
  for (const n of names) {
    if (n.startsWith(prefix) && /^\d+\.[0-9a-f]{12}\.tmp$/.test(n.slice(prefix.length))) {
      try { unlinkSync(join(dirname(dest), n)); } catch { /* gone */ }
    }
  }
}

/**
 * Strict read for writers: a store we cannot read safely is never overwritten. A symlink at the
 * store path is a REFUSAL, not an empty store: writing would either follow it (pins landing in a
 * file an attacker named) or replace it, and neither is a store this module owns.
 */
function readForWrite(dest) {
  let lst;
  try { lst = lstatSync(dest); } catch { return {}; } // no store yet: nothing to preserve
  if (lst.isSymbolicLink() || !lst.isFile()) throw new Error("the satellite pin store is not a regular file; refusing to write it");
  const f = readPrivateFile(dest);
  if (!f) throw new Error("the satellite pin store could not be read; refusing to write it");
  if (f.mode !== 0o600) throw new Error("the satellite pin store is not mode 600; refusing to write it");
  if (!f.text.trim()) return {};
  const o = JSON.parse(f.text);
  return o && typeof o === "object" && !Array.isArray(o) ? o : {};
}

/**
 * Run `mutator(all)` on the store under the store lock; `all` is the file as read INSIDE the lock.
 * The mutator changes it in place and returns `{ write: false }` to skip the write, or any other
 * value (returned to the caller). Synchronous, so callers stay synchronous.
 */
function updatePins(mutator, env) {
  const dest = satellitePinsPath(env || process.env);
  ensureDirFor(dest);
  const lockPath = `${dest}.lock`;
  const me = acquireLock(lockPath);
  try {
    removeCrashedTmps(dest);
    const all = readForWrite(dest);
    const out = mutator(all);
    if (!(out && out.write === false)) writeDurable(dest, `${JSON.stringify(all, null, 2)}\n`);
    return out;
  } finally {
    releaseLock(lockPath, me);
  }
}

/**
 * Record (or replace) the host pinned to a satellite. Returns true on success; false — writing
 * NOTHING — for an id that is not a satellite id, a host that does not normalize, or a store that
 * cannot be written (a caller must treat false as "this satellite has no usable address").
 */
export function pinSatelliteHost(satId, host, { env } = {}) {
  if (!isSatelliteId(satId)) return false;
  const h = normalizeSatelliteHost(host);
  if (!h) return false;
  try {
    const r = updatePins((all) => {
      all[satId] = { pinned_host: h, pinned_at: new Date().toISOString() };
      return { pinned: true };
    }, env);
    return !!(r && r.pinned);
  } catch (err) {
    // Never the host, never the path, never err.message (a JSON.parse error quotes the file, and the
    // file is where a hostile host would be): only that the write did not happen.
    warnOnce("write", `[satellite-pins] a pin was not written (${typeof err?.code === "string" ? err.code : "write_failed"})`);
    return false;
  }
}

/** Remove a satellite's pin. Returns true when an entry was removed. */
export function unpinSatellite(satId, { env } = {}) {
  if (!isSatelliteId(satId)) return false;
  try {
    const r = updatePins((all) => {
      if (!Object.prototype.hasOwnProperty.call(all, satId)) return { write: false, removed: false };
      delete all[satId];
      return { removed: true };
    }, env);
    return !!(r && r.removed);
  } catch {
    return false;
  }
}

// ── the one-time backfill marker (its own file, never a store key) ──────────

/**
 * The marker's value (ISO-8601), or null when it is absent or unusable. A symlink reads as
 * UNUSABLE (null), so a link planted at the marker path cannot make the backfill look done — and
 * markSatellitePinBackfillDone() refuses to write over that link, so the retry it triggers cannot
 * turn into an overwrite either.
 */
export function satellitePinBackfillDoneAt({ env } = {}) {
  const f = readPrivateFile(satellitePinBackfillPath(env || process.env));
  if (!f || f.mode !== 0o600) return null;
  try {
    const o = JSON.parse(f.text);
    const v = typeof o === "string" ? o : o?.done_at;
    return typeof v === "string" && v ? v : null;
  } catch {
    return null;
  }
}

/** Record the one-time backfill marker. True when it was written; never touches the pin store. */
export function markSatellitePinBackfillDone(at = new Date().toISOString(), { env } = {}) {
  const p = satellitePinBackfillPath(env || process.env);
  try {
    ensureDirFor(p);
    writeDurable(p, `${JSON.stringify({ done_at: at }, null, 2)}\n`);
    return true;
  } catch {
    return false;
  }
}

// ── the gate every sender asks ──────────────────────────────────────────────

/**
 * May this satellite be dialled at `rowHost` (the value in its crow.db row)? Pure and synchronous
 * (one store read, no lock); never throws, never logs.
 *
 * `{ ok: true, host }` only when a pin exists AND the row's value normalizes to exactly it. Else
 * `{ ok: false, reason }` with one of:
 *   no-pin    no pin for this id (unpaired by this code, or a pairing from before the pin)
 *   bad-host  the row's value is not a satellite address at all (a port, path, userinfo, IDN …)
 *   mismatch  the row points somewhere other than the pin
 */
export function satelliteUrlAllowed(satId, rowHost, { env } = {}) {
  const pin = getSatellitePin(satId, { env });
  if (!pin) return { ok: false, reason: "no-pin" };
  const host = normalizeSatelliteHost(rowHost);
  if (!host) return { ok: false, reason: "bad-host" };
  if (normalizeSatelliteHost(pin) !== host) return { ok: false, reason: "mismatch" };
  return { ok: true, host };
}

/**
 * The same gate for a whole `satellites` row: `{ ok: true, host }` or `{ ok: false, reason }`.
 *
 * This is the one way a caller OUTSIDE this module may ask about the row's address, and it reads
 * `sat.tailnet_host` HERE (the inventory forbids reading it under servers/gateway/satellites/), so
 * a sender can take one row object without ever touching the value itself.
 */
export function satelliteRowAllowed(sat, { env } = {}) {
  return satelliteUrlAllowed(sat?.id, sat?.tailnet_host, { env });
}

/**
 * The refusal line. Only a satellite ID (which is never a host) and the reason code: a row's host
 * is exactly what a hostile writer chose, so it never reaches a log.
 */
export function logSatellitePinRefusal(satId, reason) {
  const label = isSatelliteId(satId) ? satId : "(unknown)";
  try { console.warn(`[satellite-pin] refused ${label} (${reason})`); } catch { /* no console */ }
}

/**
 * THE CHOKE POINT: the base URL a satellite request goes to, `https://<PINNED host>`.
 *
 * `sat` is a `satellites` row (`id`, `tailnet_host`). The row's value is never dialled: it is only
 * compared with the pin, so a rewritten row refuses instead of naming a destination. When it
 * refuses, throws an Error with `code: "pin_refused"`, `reason` and a FIXED message (no host, no
 * URL, no address) — the caller's own failure shape carries it from there.
 */
export function satelliteBaseUrlFor(sat, { env } = {}) {
  const id = sat?.id;
  const verdict = satelliteUrlAllowed(id, sat?.tailnet_host, { env });
  if (!verdict.ok) {
    logSatellitePinRefusal(id, verdict.reason);
    // Built inline: this module must not import gateway code (satFail lives in satellites/client.js)
    // — the CLI and the tests load it too.
    throw Object.assign(new Error("satellite is not at its paired address"), { code: "pin_refused", reason: verdict.reason });
  }
  return `https://${verdict.host}`;
}