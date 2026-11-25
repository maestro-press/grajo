/**
 * Peer credentials store for cross-host gateway-to-gateway RPC.
 *
 * Each entry in <instance home>/secrets/peer-tokens.json (CROW_HOME, default
 * ~/.crow — see peerTokensFile below) binds an instance ID to the
 * plaintext credentials this node needs to make outbound calls to that
 * peer AND to verify inbound calls from it. Because both sides use the
 * same file shape, pairing is symmetric: a single ceremony provisions
 * both directions.
 *
 * File format (mode 0600):
 *   {
 *     "<instance-id>": {
 *       "auth_token":    "<64 hex chars>",   // Bearer token (this node -> peer)
 *       "signing_key":   "<64 hex chars>",   // HMAC key (shared, both directions)
 *       "inbound_token": "<64 hex chars>",   // Bearer token peer uses TO us (optional
 *                                            //   — inbound validation goes through the
 *                                            //   existing instanceAuthMiddleware which
 *                                            //   hashes against crow_instances.auth_token_hash)
 *       "created_at":    "ISO-8601",
 *       "rotated_at":    "ISO-8601 | null",
 *       "pinned_origin": "http://host:port"  // the peer's gateway ORIGIN, recorded
 *                                            //   here at pairing (optional: absent
 *                                            //   on pairs made before the pin)
 *     }
 *   }
 *
 * The one-time pin-backfill marker is NOT a key in this file: it lives in its
 * own <CROW_HOME>/secrets/peer-pin-backfill.json (see peerPinBackfillPath),
 * because every top-level key here is an instance id — a marker key would be
 * an entry the trust sweeper deletes and any store writer could clobber. A
 * legacy top-level "pin_backfill_done_at" string is migrated out on first read.
 *
 *
 * Why pinned_origin lives HERE and not in crow_instances: that row is
 * bot-writable (a contained bot has crow.db bound read-write, and instance
 * sync writes it too), so a URL read from it can never decide where a peer
 * bearer or a pair-key signature goes. This file is under <CROW_HOME>/secrets,
 * which the pi sandbox hides from bots. Every credential sender asks
 * peerUrlAllowed() before attaching anything.
 *
 * Security notes:
 *   - File is verified 0600 at load time; loudly warns and refuses to use
 *     credentials if permissions are looser.
 *   - auth_token and signing_key are independent. Reusing one for the other
 *     is an explicit non-goal.
 *   - Rotation: callers can rewrite the entry; `rotated_at` is metadata only.
 */

import {
  existsSync, readFileSync, writeFileSync, mkdirSync, statSync, chmodSync, renameSync,
  openSync, writeSync, closeSync, unlinkSync, fsyncSync, readdirSync, lstatSync, realpathSync,
} from "fs";
import { resolve, dirname, basename, join } from "path";
import { resolveCrowHome } from "./crow-home.js";
// The secrets-directory helper lives on its own (see ./secrets-dir.js and the re-export below):
// the key-keeping modules take it from there, so this module stays off a bot host's import graph.
import { ensureSecretsDir } from "./secrets-dir.js";
import { randomBytes } from "crypto";

// peer-tokens.json is an INSTANCE-scoped resource: it must honor CROW_HOME
// like every other instance-home path (see servers/gateway/bundles-config.js).
// A process running with CROW_HOME=<instance> (e.g. the MPA gateway under
// ~/.crow-mpa) must never silently read — or sign with — another instance's
// credentials; that hardcoded-homedir fallback is exactly what produced the
// missing_peer_credentials / hmac_mismatch misdiagnosis of 2026-07-12.
// Resolution order: CROW_PEER_TOKENS_PATH > CROW_HOME > homedir()/.crow.
// Resolved at CALL time, not module load: ESM hoists static imports, so this
// module is evaluated BEFORE the gateway's in-body .env loader runs — a
// module-load constant would silently ignore a CROW_HOME set only in .env,
// recreating the very wrong-instance failure this resolution exists to stop.
//
// The default lives in <CROW_HOME>/secrets (700), the dir the pi sandbox
// hides from bots behind a tmpfs: a same-uid bot with a shell must not be able
// to open every pair's bearer and signing key by path. Older versions kept it
// at <CROW_HOME>/peer-tokens.json; that file is moved here once (at gateway
// boot, or by the first reader or writer that finds it), and one re-created
// there later is set aside, never merged (see reconcileLegacyLocked).
function peerTokensFile() {
  return activeOverride() || resolve(resolveCrowHome(), "secrets", "peer-tokens.json");
}

/** The pre-secrets/ location, or null when an override names the store. */
function legacyPeerTokensFile() {
  if (activeOverride()) return null;
  return resolve(resolveCrowHome(), "peer-tokens.json");
}

/** The legacy top-level store key that used to hold the pin-backfill marker. */
export const PIN_BACKFILL_KEY = "pin_backfill_done_at";

/** Top-level keys that MAY be store metadata (a legacy marker), never a peer entry. */
const STORE_META_KEYS = new Set([PIN_BACKFILL_KEY]);

/** A real peer entry: a plain object. A string under a metadata key is not one. */
function isPeerEntry(v) {
  return Boolean(v) && typeof v === "object" && !Array.isArray(v);
}

/** A path with its existing ancestors' symlinks resolved (the file itself may not exist). */
function realish(p) {
  const abs = resolve(p);
  try { return realpathSync(abs); } catch { /* not there yet */ }
  try { return join(realpathSync(dirname(abs)), basename(abs)); } catch { return abs; }
}

/**
 * CROW_PEER_TOKENS_PATH, when it names a store of its own. An override that
 * resolves to the OLD default (<CROW_HOME>/peer-tokens.json, as units written
 * before the move carry) is outdated: it is treated as the old location and
 * moved into secrets/ like any other, so such a unit does not stay exposed.
 * An override anywhere else outside <CROW_HOME>/secrets is honoured, with a
 * warning (once per process, so at every boot) that bot shells can read it.
 */
function activeOverride() {
  const o = process.env.CROW_PEER_TOKENS_PATH;
  if (!o) return null;
  const home = resolveCrowHome();
  const ro = realish(o);
  if (ro === realish(resolve(home, "peer-tokens.json"))) {
    warnOnce(`override-legacy:${o}`, `[peer-credentials] CROW_PEER_TOKENS_PATH=${o} names the old default location; it is outdated and ignored: ` +
      `the store is moved to and used at ${resolve(home, "secrets", "peer-tokens.json")}. Remove the override from the unit.`);
    return null;
  }
  const secretsReal = realish(resolve(home, "secrets"));
  if (!ro.startsWith(secretsReal + "/")) {
    warnOnce(`override-exposed:${o}`, `[peer-credentials] WARNING: CROW_PEER_TOKENS_PATH=${o} is outside ${secretsReal}; ` +
      `the pi sandbox does not hide it, so a bot shell running as this user can read every peer key in it. Move it under ${secretsReal} or drop the override.`);
  }
  return o;
}

function ensureDir() {
  // Anchor on the resolved tokens path: with CROW_PEER_TOKENS_PATH set to an
  // arbitrary location, we must create THAT file's parent, not ~/.crow.
  const dir = dirname(peerTokensFile());
  if (activeOverride()) {
    try { mkdirSync(dir, { recursive: true }); } catch {}
    return;
  }
  ensureSecretsDir(dir);
}

/** Create <CROW_HOME>/secrets 700 (or tighten an existing one we own).
 *
 * Defined in `./secrets-dir.js` and re-exported here so the key-keeping modules (`token-mac.js`,
 * `bot-def-mac.js`) can take just this helper without pulling this credential store into a bot host
 * process's import graph; every existing importer of `ensureSecretsDir` from here keeps working.
 */
export { ensureSecretsDir };

/**
 * Verify the file is mode 0600 (owner rw only). Returns true if OK or the
 * file does not exist; false (+ warning) if loose permissions detected.
 */
function checkPermissions(path) {
  try {
    if (!existsSync(path)) return true;
    const s = statSync(path);
    // Allow 0600 only. Mask for world/group bits.
    const mode = s.mode & 0o777;
    if (mode !== 0o600) {
      console.warn(
        `[peer-credentials] WARNING: ${path} has mode ${mode.toString(8)}; expected 600. ` +
        `Refusing to load. Fix with: chmod 600 ${path}`
      );
      return false;
    }
    return true;
  } catch (err) {
    console.warn(`[peer-credentials] Cannot stat ${path}: ${err.message}`);
    return false;
  }
}

/**
 * Load the peer-tokens.json file. Returns an empty object if missing or
 * if permissions check fails. A store still (or again) at the pre-secrets/
 * path is first moved (or set aside) under the lock; if that cannot run (a
 * read-only view) and only the old file exists, it is read where it is.
 */
export function loadPeerCreds() {
  let p = peerTokensFile();
  const legacy = legacyPeerTokensFile();
  if (legacy && existsSync(legacy)) {
    try { reconcileLegacyIfDue(); } catch (err) { warnOnce(`reconcile:${legacy}`, `[peer-credentials] could not move ${legacy} into ${p}: ${err.message}`); }
    // Only before this host's first move (the old layout still in force).
    if (!existsSync(p) && !existsSync(p + MIGRATED_SUFFIX) && existsSync(legacy)) p = legacy;
  }
  if (!checkPermissions(p)) return {};
  try {
    if (!existsSync(p)) return {};
    const parsed = JSON.parse(readFileSync(p, "utf-8"));
    // A legacy store-metadata value (the old one-time pin backfill marker) is
    // never a peer entry: callers iterate this object as "peers", and an
    // orphan-key report that named the marker would be noise the operator
    // cannot act on. An OBJECT under that same key is a real peer with that id
    // (its marker lives in its own file now), so it is left alone.
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      for (const k of STORE_META_KEYS) {
        if (Object.prototype.hasOwnProperty.call(parsed, k) && !isPeerEntry(parsed[k])) delete parsed[k];
      }
    }
    return parsed;
  } catch (err) {
    console.warn(`[peer-credentials] Failed to parse ${p}: ${err.message}`);
    return {};
  }
}

/** The store exactly as written (metadata included), or {} when unreadable. */
function readStoreRaw() {
  let p = peerTokensFile();
  const legacy = legacyPeerTokensFile();
  if (legacy && existsSync(legacy)) {
    try { reconcileLegacyIfDue(); } catch { /* read the file where it is */ }
    if (!existsSync(p) && !existsSync(p + MIGRATED_SUFFIX) && existsSync(legacy)) p = legacy;
  }
  if (!checkPermissions(p)) return {};
  try {
    if (!existsSync(p)) return {};
    const o = JSON.parse(readFileSync(p, "utf-8"));
    return o && typeof o === "object" && !Array.isArray(o) ? o : {};
  } catch { return {}; }
}

const _warned = new Set();
function warnOnce(key, msg) {
  if (_warned.has(key)) return;
  _warned.add(key);
  console.warn(msg);
}

// ---------------------------------------------------------------------------
// Writes: one lock for every writer (PT-1).
//
// Every writer (the gateway's trust sweeper and boot reconcile, the enroll
// route and its rollback, the pair CLI, stdio revokes) used to do an
// unlocked read-modify-write through one shared "<file>.tmp", so two
// processes could lose each other's updates and drop a live peer's key.
// Now each write takes an exclusive lockfile, re-reads the file INSIDE the
// lock, applies its change, and renames a per-writer tmp file into place.
// ---------------------------------------------------------------------------

const LOCK_WAIT_MS = 5_000;
const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_LOG_MS = 100;
const _sleepCell = new Int32Array(new SharedArrayBuffer(4));
function sleepSync(ms) { Atomics.wait(_sleepCell, 0, 0, ms); }

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (err) { return err.code === "EPERM"; }
}

// This boot's id: a lock written by a pid from an EARLIER boot is stale even
// if that pid number is alive again now (pid reuse after a reboot/OOM).
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

/** A lock older than LOCK_STALE_MS whose holder is gone: dead pid, another boot, or unreadable content. */
function isStale(lockPath, holder) {
  if (lockAgeMs(lockPath, holder) <= LOCK_STALE_MS) return false;
  if (!holder || typeof holder !== "object") return true; // empty or torn write
  if (holder.boot && bootId() && holder.boot !== bootId()) return true;
  return !pidAlive(Number(holder.pid));
}

function acquireStoreLock(lockPath, waitMs = LOCK_WAIT_MS) {
  const started = Date.now();
  const me = { pid: process.pid, ts: Date.now(), boot: bootId(), nonce: randomBytes(6).toString("hex") };
  let holder = null;
  for (;;) {
    try {
      const fd = openSync(lockPath, "wx", 0o600);
      try { writeSync(fd, JSON.stringify(me)); } finally { closeSync(fd); }
      const waited = Date.now() - started;
      if (waited > LOCK_WAIT_LOG_MS) {
        console.warn(`[peer-credentials] store lock waited ${waited} ms (holder pid ${holder?.pid ?? "?"})`);
      }
      return me;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
    }
    holder = readLock(lockPath);
    if (isStale(lockPath, holder)) {
      console.warn(`[peer-credentials] breaking a stale store lock (holder pid ${holder?.pid ?? "?"}, ${lockAgeMs(lockPath, holder)} ms old)`);
      // Break by renaming to a unique name, then check it was the lock we
      // judged: a racing breaker may already have replaced it with a live one.
      const aside = `${lockPath}.${process.pid}.${randomBytes(4).toString("hex")}.stale`;
      try {
        renameSync(lockPath, aside);
        const moved = readLock(aside);
        const same = (moved === null && holder === null) || (moved && holder && moved.nonce === holder.nonce && moved.pid === holder.pid);
        if (!same && !isStale(aside, moved)) {
          // We moved a live holder's lock: put it back if the slot is still free.
          try { const fd = openSync(lockPath, "wx", 0o600); try { writeSync(fd, JSON.stringify(moved)); } finally { closeSync(fd); } } catch { /* taken */ }
        }
        try { unlinkSync(aside); } catch { /* gone */ }
      } catch { /* someone else broke it */ }
      continue;
    }
    if (Date.now() - started > waitMs) {
      throw new Error(`[peer-credentials] could not lock ${lockPath} within ${waitMs} ms (holder pid ${holder?.pid ?? "?"})`);
    }
    sleepSync(2 + Math.floor(Math.random() * 5));
  }
}

function releaseStoreLock(lockPath, me) {
  const cur = readLock(lockPath);
  if (cur && cur.nonce === me.nonce && cur.pid === me.pid) {
    try { unlinkSync(lockPath); } catch { /* already gone */ }
  }
}

/** Strict read for writers: a store we cannot read safely is never overwritten. */
function readForWrite(p) {
  if (!existsSync(p)) return {};
  const mode = statSync(p).mode & 0o777;
  if (mode !== 0o600) {
    throw new Error(`[peer-credentials] ${p} has mode ${mode.toString(8)}; expected 600. Refusing to write. Fix with: chmod 600 ${p}`);
  }
  const raw = readFileSync(p, "utf-8");
  return raw.trim() ? JSON.parse(raw) : {};
}

// Test seam: called at named points of a durable write (crash tests).
let _fault = null;
export function _setPeerCredsFaultForTest(fn) { _fault = typeof fn === "function" ? fn : null; }

function fsyncDir(dir) {
  let fd;
  try { fd = openSync(dir, "r"); fsyncSync(fd); } catch { /* not supported here */ } finally { if (fd !== undefined) try { closeSync(fd); } catch {} }
}

/** Write `data` to `dest` (600) through a per-writer tmp file: fsync, rename, fsync the dir. */
function writeDurable(dest, data) {
  const tmp = `${dest}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    const fd = openSync(tmp, "wx", 0o600);
    try { writeSync(fd, data); fsyncSync(fd); } finally { closeSync(fd); }
    _fault?.("tmp-written");
    // renameSync is atomic on POSIX for same-filesystem rename
    renameSync(tmp, dest);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* never created */ }
    throw err;
  }
  // Belt & suspenders — re-apply mode in case renameSync preserved different perms
  chmodSync(dest, 0o600);
  fsyncDir(dirname(dest));
  _fault?.("renamed");
}

function writeStore(dest, creds) {
  writeDurable(dest, JSON.stringify(creds, null, 2));
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

/** Copy `from` to `to` durably, verify the bytes, then remove `from`. */
function moveVerified(from, to, bytes = readFileSync(from)) {
  writeDurable(to, bytes);
  if (!readFileSync(to).equals(bytes)) throw new Error(`[peer-credentials] copy of ${from} to ${to} did not verify; old file kept`);
  unlinkSync(from);
  fsyncDir(dirname(from));
}

/** The PT-1 one-time snapshot and its marker move along with the store. */
function movePt1Files(legacy, dest) {
  const prefix = basename(legacy) + ".pre-pt1.";
  let names = [];
  try { names = readdirSync(dirname(legacy)); } catch { return; }
  for (const n of names) {
    if (!n.startsWith(prefix)) continue;
    const from = join(dirname(legacy), n);
    const to = `${dest}.pre-pt1.${n.slice(prefix.length)}`;
    try {
      const bytes = readFileSync(from);
      if (existsSync(to)) {
        if (readFileSync(to).equals(bytes) || n === basename(legacy) + ".pre-pt1.done") { unlinkSync(from); continue; }
        console.warn(`[peer-credentials] ${from} and ${to} both exist and differ; both kept (shred the old one once verified)`);
        continue;
      }
      moveVerified(from, to, bytes);
    } catch (err) {
      console.warn(`[peer-credentials] could not move ${from}: ${err.message}`);
    }
  }
}

/**
 * Move a single-writer secret file (the peer-relay token) from its old path
 * into the secrets dir: copy (600, fsync), verify, remove the old one. When
 * both exist the new one wins; the old one is removed only when identical.
 */
export function migrateLegacySecretFile(from, to) {
  if (!existsSync(from)) return { action: "none" };
  ensureSecretsDir(dirname(to));
  removeCrashedTmps(to);
  const bytes = readFileSync(from);
  if (!existsSync(to)) {
    moveVerified(from, to, bytes);
    console.log(`[secrets] moved ${from} -> ${to} (mode 600, hidden from bot sandboxes)`);
    return { action: "moved" };
  }
  if (readFileSync(to).equals(bytes)) {
    unlinkSync(from);
    return { action: "removed-identical" };
  }
  console.error(`[secrets] WARNING: both ${from} and ${to} exist and differ; using ${to} and keeping both. Shred ${from} once checked.`);
  return { action: "kept-both" };
}

const MIGRATED_SUFFIX = ".migrated";

/**
 * Once this host is on the secrets/ layout (the marker beside the store), a
 * file at the old path is never adopted: a bot shell inside the sandbox can
 * still WRITE there, so merging it would let a bot plant a peer key in the
 * store it cannot read. It is an older process's write (or a plant): saved
 * aside in the hidden dir for the operator, removed from the old path, and
 * logged with the peer ids it names (never a key).
 */
function setAsideLegacy(legacy, dest, bytes) {
  const aside = `${dest}.legacy-${Date.now()}`;
  writeDurable(aside, bytes);
  unlinkSync(legacy);
  let ids = "?";
  try { const o = JSON.parse(bytes.toString("utf-8") || "{}"); ids = Object.keys(o || {}).join(", ") || "none"; } catch { ids = "unparseable"; }
  console.error(`[peer-credentials] WARNING: ${legacy} was re-created after the store moved to ${dest} (an older Crow process, or a bot). ` +
    `It was NOT merged; saved at ${aside} (mode 600, peers: ${ids}). Restart any older Crow process; re-pair a peer it paired, or merge by hand, then shred ${aside}.`);
  return { action: "set-aside", aside };
}

function writeMarker(dest) {
  const marker = dest + MIGRATED_SUFFIX;
  if (!existsSync(marker)) writeFileSync(marker, `${new Date().toISOString()}\n`, { mode: 0o600 });
}

/**
 * With the store lock held: move a store at the pre-secrets/ path, or set
 * aside one re-created there later. Takes that path's own lock too, so an
 * older writer's read-modify-write there finishes first (older code only
 * knows that lock; new code always takes the store lock first, so the two
 * never deadlock).
 */
function reconcileLegacyLocked(dest, waitMs = LOCK_WAIT_MS) {
  const legacy = legacyPeerTokensFile();
  if (!legacy) return { action: "none" };
  if (!existsSync(legacy)) {
    // First contact on the new layout: from now on the old path is untrusted.
    if (existsSync(dirname(dest))) { try { writeMarker(dest); } catch { /* read-only view */ } }
    return { action: "none" };
  }
  const legacyLock = `${legacy}.lock`;
  const lme = acquireStoreLock(legacyLock, waitMs);
  try {
    if (!existsSync(legacy)) return { action: "none" };
    removeCrashedTmps(dest);
    const st = lstatSync(legacy);
    if (!st.isFile() || st.uid !== process.getuid?.()) {
      warnOnce(`nonfile:${legacy}`, `[peer-credentials] WARNING: ${legacy} is not a regular file of this user; not moved or read. Remove it by hand.`);
      return { action: "kept-both" };
    }
    const migrated = existsSync(dest + MIGRATED_SUFFIX);
    const oldBytes = readFileSync(legacy);
    if (!existsSync(dest)) {
      if (migrated) return setAsideLegacy(legacy, dest, oldBytes);
      writeDurable(dest, oldBytes);
      if (!readFileSync(dest).equals(oldBytes)) throw new Error(`[peer-credentials] copy of ${legacy} to ${dest} did not verify; old file kept`);
      writeMarker(dest);
      unlinkSync(legacy);
      fsyncDir(dirname(legacy));
      movePt1Files(legacy, dest);
      console.log(`[peer-credentials] moved the peer credential store ${legacy} -> ${dest} (mode 600, hidden from bot sandboxes)`);
      return { action: "moved" };
    }
    if (readFileSync(dest).equals(oldBytes)) {
      writeMarker(dest);
      unlinkSync(legacy);
      movePt1Files(legacy, dest);
      console.log(`[peer-credentials] removed ${legacy}: identical to ${dest}`);
      return { action: "removed-identical" };
    }
    if (migrated) return setAsideLegacy(legacy, dest, oldBytes);
    console.error(`[peer-credentials] WARNING: both ${legacy} and ${dest} exist and differ; using ${dest} and keeping both. ` +
      `Compare them, merge any peer you still need into ${dest}, then shred ${legacy}.`);
    return { action: "kept-both" };
  } finally {
    releaseStoreLock(legacyLock, lme);
  }
}

/** Take the store lock and reconcile the old path. */
function reconcileLegacy(waitMs = LOCK_WAIT_MS) {
  ensureDir();
  const dest = peerTokensFile();
  const lockPath = `${dest}.lock`;
  const me = acquireStoreLock(lockPath, waitMs);
  try { return reconcileLegacyLocked(dest, waitMs); } finally { releaseStoreLock(lockPath, me); }
}

// Readers (a hot path) wait briefly for the locks, and a state they could not
// settle (kept both, a busy or planted lock) is retried at most once a minute.
const READER_LOCK_WAIT_MS = 250;
const READER_RETRY_MS = 60_000;
const _unsettledAt = new Map();
function reconcileLegacyIfDue() {
  const legacy = legacyPeerTokensFile();
  const at = _unsettledAt.get(legacy);
  if (at !== undefined && Date.now() - at < READER_RETRY_MS) return { action: "kept-both" };
  let r;
  try { r = reconcileLegacy(READER_LOCK_WAIT_MS); } catch (err) { _unsettledAt.set(legacy, Date.now()); throw err; }
  if (r.action === "kept-both") _unsettledAt.set(legacy, Date.now()); else _unsettledAt.delete(legacy);
  return r;
}

/**
 * The one-time boot migration (the gateway runs it before the PT-1 sweeper).
 * Idempotent; also run lazily by every reader and writer that finds a store
 * at the old path. Returns { action: "none" | "moved" | "removed-identical"
 * | "kept-both" | "set-aside" }.
 */
export function migratePeerCredsStore() {
  if (!legacyPeerTokensFile()) return { action: "none" };
  return reconcileLegacy();
}

/**
 * Run `mutator(all)` on the store under the store lock. `all` is the file as
 * read INSIDE the lock; the mutator changes it in place and returns
 * `{ write: false }` to skip the write, or any other value (returned to the
 * caller). Synchronous: callers stay synchronous.
 */
export function updatePeerCreds(mutator) {
  ensureDir();
  const dest = peerTokensFile();
  const lockPath = `${dest}.lock`;
  const me = acquireStoreLock(lockPath);
  try {
    // A store still at the old path is moved first (or one re-created there
    // set aside), so this write can never strand it. After the move a failure
    // there (e.g. a lock a bot planted beside the old path) never blocks a
    // write: the old path holds nothing the store needs.
    try { reconcileLegacyLocked(dest); } catch (err) {
      if (!existsSync(dest + MIGRATED_SUFFIX)) throw err;
      warnOnce(`reconcile-w:${dest}`, `[peer-credentials] could not clear the old store path: ${err.message}`);
    }
    const all = readForWrite(dest);
    const out = mutator(all);
    if (!(out && out.write === false)) writeStore(dest, all);
    return out;
  } finally {
    releaseStoreLock(lockPath, me);
  }
}

/**
 * Get credentials for a specific peer. Returns null if not paired.
 */
export function getPeerCreds(instanceId) {
  const all = loadPeerCreds();
  return all[instanceId] || null;
}

/**
 * Upsert credentials for a peer. Preserves any existing fields not in
 * `patch` — including `pinned_origin`, so a token rotation or a re-enroll that
 * reuses this entry never drops the paired gateway origin (a pairing that
 * WANTS to move the pin calls pinPeerOrigin explicitly). Sets created_at on
 * first write, rotated_at on subsequent writes.
 */
export function setPeerCreds(instanceId, patch) {
  return updatePeerCreds((all) => {
    const existing = all[instanceId] || {};
    const now = new Date().toISOString();
    const next = {
      ...existing,
      ...patch,
      created_at: existing.created_at || now,
      rotated_at: existing.created_at ? now : null,
    };
    all[instanceId] = next;
    return next;
  });
}

/**
 * Remove credentials for a peer. Returns true when an entry was removed.
 */
export function deletePeerCreds(instanceId) {
  return updatePeerCreds((all) => {
    if (!Object.prototype.hasOwnProperty.call(all, instanceId)) return { write: false, deleted: false };
    delete all[instanceId];
    return { deleted: true };
  }).deleted;
}

// ---------------------------------------------------------------------------
// The paired gateway ORIGIN (security stopgap).
//
// Every sender of a peer credential used to take its destination straight from
// crow_instances.gateway_url — a row a contained bot can write. A bot rewrote
// it to its own server and collected the peer bearer on the owner's next call.
// So the peer's gateway ORIGIN is recorded in THIS store (which bots cannot
// read) at pairing, and a credential may only go to a URL whose origin is that
// recorded origin. The owner re-pins deliberately when a peer legitimately
// moves (scripts/cli/peer-pin.js) — nothing a bot writes can re-pin.
// ---------------------------------------------------------------------------

/**
 * The origin form of a gateway URL: `protocol//host:port`, lower-case, with the
 * default port made explicit (http 80, https 443). Null for anything that is
 * not an http(s) URL with a host and without userinfo. Path, query and fragment
 * are ignored (an install's gateway URL may carry a base path); no DNS is done,
 * so a name stays exactly the name written and an IPv6 literal keeps its
 * brackets.
 */
export function normalizeGatewayOrigin(url) {
  if (typeof url !== "string") return null;
  const s = url.trim();
  if (!s) return null;
  let u;
  try { u = new URL(s); } catch { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  if (u.username || u.password) return null;
  const host = u.hostname; // URL already lower-cases it and keeps [..] for IPv6
  if (!host) return null;
  const port = u.port || (u.protocol === "http:" ? "80" : "443");
  return `${u.protocol}//${host}:${port}`;
}

/**
 * Record (or replace) the gateway origin pinned to a paired peer. Returns false
 * — and writes nothing — when the URL does not normalize or the peer has no
 * entry (a pin never invents a peer). Synchronous, under the store lock.
 */
export function pinPeerOrigin(instanceId, url) {
  const origin = normalizeGatewayOrigin(url);
  if (!origin || typeof instanceId !== "string" || !instanceId) return false;
  try {
    const r = updatePeerCreds((all) => {
      const entry = all[instanceId];
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) return { write: false, pinned: false };
      entry.pinned_origin = origin;
      return { pinned: true };
    });
    return !!(r && r.pinned);
  } catch { return false; }
}

/**
 * May a peer credential be sent to `url` for `instanceId`? Pure and synchronous
 * (no locking beyond the store read); never throws, never logs the URL.
 *
 * `{ ok: true }` only when there is a credential entry, it carries a
 * `pinned_origin`, and this URL normalizes to exactly that origin.
 * Otherwise `{ ok: false, reason }` with one of:
 *   bad-url   the URL is not a usable http(s) origin
 *   no-creds  the peer is not paired (no entry in the store)
 *   no-pin    paired before the pin existed and never backfilled/re-pinned
 *   mismatch  the URL's origin is not the paired one
 */
export function peerUrlAllowed(instanceId, url) {
  const want = normalizeGatewayOrigin(url);
  if (!want) return { ok: false, reason: "bad-url" };
  let entry = null;
  try { entry = getPeerCreds(instanceId); } catch { entry = null; }
  if (!entry || typeof entry !== "object") return { ok: false, reason: "no-creds" };
  const pinned = typeof entry.pinned_origin === "string" ? entry.pinned_origin : "";
  if (!pinned) return { ok: false, reason: "no-pin" };
  if (pinned !== want) return { ok: false, reason: "mismatch" };
  return { ok: true };
}

/**
 * The one-time pin-backfill marker FILE. Not a key in the credential store:
 * every top-level store key is an instance id, so a marker there was an entry
 * (the trust sweeper deleted it, and `setPeerCreds`/`deletePeerCreds` on that
 * id clobbered it — after which a later boot backfilled again from rows a bot
 * can write). It sits beside the credential store, so it follows the same
 * CROW_HOME / CROW_PEER_TOKENS_PATH scoping and the same 0700 dir.
 * CROW_PEER_PIN_BACKFILL_PATH names it explicitly (tests, odd layouts).
 */
export function peerPinBackfillPath() {
  const o = process.env.CROW_PEER_PIN_BACKFILL_PATH;
  if (o) return resolve(o);
  return resolve(dirname(peerTokensFile()), "peer-pin-backfill.json");
}

/** The marker file's value (ISO-8601), or null when it is absent/unusable. */
function readPinBackfillFile() {
  const p = peerPinBackfillPath();
  if (!checkPermissions(p)) return null;
  try {
    if (!existsSync(p)) return null;
    const o = JSON.parse(readFileSync(p, "utf-8"));
    const v = typeof o === "string" ? o : o?.done_at;
    return typeof v === "string" && v ? v : null;
  } catch { return null; }
}

/** Write the marker durably (0600, tmp + rename + fsync), inside the secrets dir. */
function writePinBackfillFile(at) {
  const p = peerPinBackfillPath();
  ensureSecretsDir(dirname(p));
  writeDurable(p, `${JSON.stringify({ done_at: at }, null, 2)}\n`);
}

/**
 * Move a legacy top-level marker STRING out of the store into its own file and
 * drop the key. Only ever touches a string value: an object under the same key
 * is a peer whose id happens to be that name, and is left alone.
 */
function migrateLegacyPinMarker() {
  let raw;
  try { raw = readStoreRaw(); } catch { return; }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return;
  if (!Object.prototype.hasOwnProperty.call(raw, PIN_BACKFILL_KEY)) return;
  const v = raw[PIN_BACKFILL_KEY];
  if (typeof v !== "string" || !v) return;
  if (!readPinBackfillFile()) {
    try { writePinBackfillFile(v); } catch (err) {
      // The old key still gates the backfill; leave it in place.
      warnOnce(`pin-migrate:${peerTokensFile()}`, `[peer-credentials] could not move the pin-backfill marker into ${peerPinBackfillPath()}: ${err.message}`);
      return;
    }
  }
  try {
    updatePeerCreds((all) => {
      if (!Object.prototype.hasOwnProperty.call(all, PIN_BACKFILL_KEY)) return { write: false };
      if (isPeerEntry(all[PIN_BACKFILL_KEY])) return { write: false };
      delete all[PIN_BACKFILL_KEY];
      return {};
    });
  } catch { /* the file is authoritative: the next boot reads only it */ }
}

/** The one-time gateway-origin backfill marker (ISO-8601), or null. */
export function pinBackfillDoneAt() {
  const file = readPinBackfillFile();
  if (file) return file;
  // A store written by a version that kept the marker as a key still counts:
  // move it to its own file (and drop the key) on first read.
  try { migrateLegacyPinMarker(); } catch { /* read-only view */ }
  const migrated = readPinBackfillFile();
  if (migrated) return migrated;
  try {
    const v = readStoreRaw()[PIN_BACKFILL_KEY];
    return typeof v === "string" && v ? v : null;
  } catch { return null; }
}

/**
 * Record the one-time backfill marker. True when it was written; false when the
 * marker file could not be written (the caller then leaves the backfill to
 * retry). Never writes the credential store.
 */
export function markPinBackfillDone(at = new Date().toISOString()) {
  try {
    writePinBackfillFile(at);
  } catch { return false; }
  try { migrateLegacyPinMarker(); } catch { /* the file is authoritative now */ }
  return true;
}

/**
 * A fetch that NEVER follows a redirect: `redirect: "manual"`, and any 3xx is
 * thrown as an error instead of being handed back. A peer that answers 307
 * would otherwise move a peer bearer (or a pair-key signature) to a host none
 * of the origin checks judged, on a fresh socket of Node's own choosing.
 *
 * The error is a FIXED message: no status, and never the redirect target or its
 * origin. Such a message reaches logs, error reports and an operator's terminal,
 * and the target is exactly the address a hostile peer chose — naming it hands
 * that choice a louder audience than the peer itself had.
 */
export function noRedirectFetch(fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== "function") throw new TypeError("noRedirectFetch needs a fetch function");
  return async (url, init = {}) => {
    const res = await fetchImpl(url, { ...init, redirect: "manual" });
    if (res && res.status >= 300 && res.status < 400) {
      try { res.body?.cancel?.()?.catch?.(() => {}); } catch { /* irrelevant */ }
      throw new Error("peer redirect refused");
    }
    return res;
  };
}

/**
 * The mint time of a store entry, epoch ms: rotated_at || created_at. An
 * entry with neither (hand-written legacy) counts as minted before any revoke.
 */
export function entryMintMs(entry) {
  const t = Date.parse(entry?.rotated_at || entry?.created_at || "");
  return Number.isFinite(t) ? t : -Infinity;
}

/**
 * Generate a new 32-byte hex token or signing key.
 */
export function generateSecret() {
  return randomBytes(32).toString("hex");
}

/**
 * Resolve the path for operators to reference (e.g. "chmod 600" hints).
 */
export function peerTokensPath() {
  return peerTokensFile();
}
