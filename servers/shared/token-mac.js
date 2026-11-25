/**
 * Keyed (HMAC) verifiers for the stored credentials the gateway checks.
 *
 * A stored verifier used to be a plain function of the raw secret — `sha256Hex(token)`, or
 * `scrypt(password)` — so anything with WRITE access to crow.db could plant a value it
 * computed and then present the matching secret (a contained bot has that write access). This
 * module makes the stored value depend on a key the bot cannot read:
 *
 *   <CROW_HOME>/secrets/token-hmac.key      32 random bytes, dir 0700, file 0600
 *   <CROW_HOME>/secrets/token-hmac-state.json  the per-family era markers, 0600
 *
 * THE STORED FORM (design §2.2):
 *
 *   stored = "h1." + keyId + "." +
 *            hex( HMAC-SHA256(K, "crow-token-mac-v1\0" + family + "\0" + sha256hex(token)) )
 *
 * The inner `sha256hex(token)` is exactly TODAY's stored value, which is what lets a boot
 * converter rewrite every existing row offline: no raw token is needed to convert, and the
 * "legacy accepted but unprotected" window collapses to zero.
 *
 * THE FAMILY DOMAIN IS MANDATORY (§2.3). HMAC alone stops a bot from COMPUTING a verifier; it
 * does not stop it from COPYING one. A bot knows its own board token and can read that token's
 * `h1.` value out of `mcp_board_token_hash`, then write the same value into
 * `mcp_local_token_hash` or an OAuth access row. Binding `family` into the MAC input means the
 * copied value only verifies under the family it was minted for. Row ids are NOT bound: the
 * lookup tables (`oauth_tokens`, `crow_instances`, `report_link_tokens`) are searched BY the
 * stored value, before any row is known.
 *
 * THE LEGACY FORM IS AN ALARM, NEVER A CREDENTIAL (§3.3). After a family has been converted,
 * a bare 64-hex stored value is refused and `legacyAlarm()` logs it (the console line once per
 * family per 24 h, one audit row per DISTINCT row reference in that window, capped) through the
 * injected `auditLog`. That copy is LOG-ONLY in this PR: it is not a bell, a notification or a
 * translated string, because user-visible copy is pending approval.
 *
 * KEY STATES (§2.6): `keyState()` classifies this process's key as "ok", "first-boot" (NO key
 * file AND no state file at all AND no era — the only state a key may be created in), "lost"
 * (no key but a state file, an era marker, a DB mirror or `h1.` values exist, or the state
 * cannot be read/cannot be parsed) or "invalid" (the key is present but unreadable/empty/wrong
 * length/not owner-only/wrong owner, including a directory or a symlink where the file
 * belongs). "lost" and "invalid" NEVER auto-create a replacement: every stored-verifier check
 * fails closed and an operator resets it deliberately.
 *
 * The key is read ONCE per process (§2.1) and the in-process cache is authoritative after
 * that; a key file replaced underneath a running process is not adopted silently — an explicit
 * `reloadTokenMacKey()` reports the mismatch as a `TOKEN_MAC_KEY_CHANGED` refusal, and a file
 * that went missing or unreadable as `TOKEN_MAC_KEY_LOST` / `TOKEN_MAC_KEY_INVALID` while the
 * loaded key is kept.
 *
 * The key-less legacy fall-through of §2.6 row 4 also requires a RECORDED boot verdict: only a
 * scan that checked both the DB mirror and the `h1.` values and found neither may accept a
 * legacy value (`noteEraEvidence`, or the boot's `ensureKey`). A boot that found the key lost
 * records that, stickily, so a later validator asking without evidence still refuses.
 *
 * The state file is a read-modify-write shared by owner CLIs too, so every writer takes a
 * cross-process `O_EXCL` lock (`<state>.lock`) and re-reads under it.
 *
 * DEVIATION FROM §2.2, password only: the scrypt SALT is bound into the pepper's MAC input
 * (`domain + "password" + NUL + salt + NUL + keyHex`). §2.2 spells the input without the salt;
 * binding it costs nothing (the salt is stored beside the MAC) and keeps two equally guarded
 * verifiers from colliding on the same scrypt output. Tokens are unchanged.
 *
 * HOST-ONLY. This module holds a key, so it must never be reachable from bot code;
 * `tests/bot-seed-import-guard.test.js` keeps it in the same guarded set as the identity seed.
 * It imports no auth/db code, so a validator can import it without a cycle.
 */
import {
  chmodSync, closeSync, fsyncSync, linkSync, lstatSync, openSync, readFileSync, renameSync,
  unlinkSync, writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { createHash, createHmac, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { resolveCrowHome } from "./crow-home.js";
// A tiny fs helper of its own: importing it from ./peer-credentials.js would drag the peer credential
// store into a bot host process's import graph (tests/no-peer-key-in-bot-process.test.js).
import { ensureSecretsDir } from "./secrets-dir.js";

const scryptAsync = promisify(scryptCb);

const KEY_VERSION = 1;
const STATE_VERSION = 1;
const MAC_VERSION = "h1";
/** Domain prefix of every MAC input. The NUL keeps it from running into `family`. */
const MAC_DOMAIN = "crow-token-mac-v1\0";
/** Separator between the domain, the family and the inner sha256 hex. */
const FIELD_SEP = "\0";
const KEY_ID_RE = /^[0-9a-f]{16}$/;
const HEX64 = /^[0-9a-fA-F]{64}$/;
/** A 64-byte scrypt output, hex — the password key half of today's `salt:key`. */
const SCRYPT_HEX = /^[0-9a-fA-F]{128}$/;
const HEX_ANY = /^[0-9a-fA-F]+$/;
/** Lowercase only: `keyId` and the MAC hex are minted lowercase, so any other case is not it. */
const H1_STORED = /^h1\.([0-9a-f]{16})\.([0-9a-f]{64})$/;
/** A state lock may be abandoned (its writer crashed) after this long. */
const STATE_LOCK_STALE_MS = 30 * 1000;
/** Lock acquisition attempts (~5 ms apart) before a writer gives up and throws. */
const STATE_LOCK_ATTEMPTS = 400;
const STATE_LOCK_SLEEP_MS = 5;
/** Distinct legacy rows audited per family per alarm window. */
const ALARM_MAX_ROWS = 100;
const PEPPER_STORED = /^p2\$([0-9a-fA-F]{1,128})\$([0-9a-fA-F]{64})$/;
/** A family must be printable ASCII and can never carry the field separator. */
const FAMILY_RE = /^[\x21-\x7e]+$/;

/** One console alarm per family per 24 h (§3.3). */
export const TOKEN_MAC_ALARM_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * The fixed domain strings of every credential store §1 lists. A later PR's converter and its
 * boot scan iterate this list; the setting keys ARE their own family, so a value in either
 * settings store (override row or global row) verifies the same way.
 */
export const TOKEN_MAC_FAMILIES = Object.freeze([
  // §1a — settings-backed hashes (`servers/gateway/local-token.js` and friends).
  "mcp_local_token_hash",
  "mcp_board_token_hash",
  "mcp_phone_token_hash",
  "mcp_artifacts_token_hash",
  "mcp_models_token_hash",
  "mcp_peer_relay_token_hash",
  "mcp_llm_cloud_token_hash",
  "mcp_services_token_hash",
  "mcp_satellite_tools_token_hash",
  "mcp_secrets_token_hash",
  "mcp_sharing_bot_token_hash",
  "mcp_reports_token_hash",
  "mcp_memory_bot_token_hash",
  "mcp_projects_bot_token_hash",
  "mcp_mail_hook_token_hash",
  "kiosk_announce_token_hash",
  // §1b — table-backed hashes, looked up BY the stored value.
  "oauth:access",
  "oauth:refresh",
  "dashboard:session",
  "peer:inbound",
  "report:link",
  // §1d — bot DEFINITIONS (`pi_bot_defs`): one MAC per row over the canonical form of
  // (bot_id, enabled, project_id, definition, generation), so a contained bot that can write
  // crow.db cannot raise its own policy (`tools.crow_mcp`, `permission_policy`, `write_paths`,
  // `project_id`, remote servers). See `servers/shared/bot-def-mac.js` (host-only) for the
  // canonical form and the replay counter; the family domain here is what keeps a bot's
  // definition MAC from ever being replayed as a token verifier, and vice versa.
  "bot:def",
  // §1c / §2.2 — the dashboard password (the `p2$` form below).
  "password",
]);

/** The family of the dashboard password's `p2$` form. */
export const PASSWORD_FAMILY = "password";

/** `token_hmac_era:<family>` — the one-way DB mirror of the secrets-side era marker (§2.5). */
export function eraSettingKey(family) {
  return `token_hmac_era:${assertFamily(family)}`;
}

/** A coded failure of the key itself, never of a credential. */
export class TokenMacKeyError extends Error {
  constructor(code, state, path) {
    const why = state === "invalid" ? "is unreadable"
      : state === "lost" ? "is lost"
        : state === "changed" ? "changed on disk under this process"
          : "does not exist";
    super(`token-mac key ${why}: ${path}`);
    this.name = "TokenMacKeyError";
    this.code = code;
    this.state = state;
    this.path = path;
  }
}

/** A coded failure of the secrets-side state file, never of a credential. */
export class TokenMacStateError extends Error {
  constructor(code, message, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = "TokenMacStateError";
    this.code = code;
  }
}

function corruptStateError(path) {
  return new TokenMacStateError(
    "TOKEN_MAC_STATE_CORRUPT",
    `token-mac state ${path} is corrupt (not an object carrying an object "families"); writer refused, file left untouched`,
  );
}

function assertFamily(family) {
  if (typeof family !== "string" || !FAMILY_RE.test(family)) {
    throw new TypeError("token-mac family must be a non-empty printable-ASCII string (the MAC domain)");
  }
  return family;
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

// ─── the key file ───────────────────────────────────────────────────────────

function secretsDirFor({ crowHome, path } = {}) {
  return path ? dirname(path) : join(crowHome || resolveCrowHome(), "secrets");
}

/** `<CROW_HOME>/secrets/token-hmac.key` (or the test seam's path). */
export function tokenMacKeyPath(opts = {}) {
  return opts.path || join(secretsDirFor(opts), "token-hmac.key");
}

/** `<CROW_HOME>/secrets/token-hmac-state.json` (beside the key it describes). */
export function tokenMacStatePath(opts = {}) {
  return opts.statePath || join(secretsDirFor(opts), "token-hmac-state.json");
}

/**
 * `"ok" | "missing" | "invalid"` for the key FILE; `key` is `{ id, secret }` when ok.
 *
 * lstat, not stat: a SYMLINK where the key belongs is invalid, so a link planted in `secrets/`
 * cannot point the verifier at a file a bot wrote. The file must also be owner-only (no group
 * or other bits) and owned by this process's uid, otherwise it is not the file we minted.
 */
function keyFileState(path) {
  let st;
  try {
    st = lstatSync(path);
  } catch (err) {
    return { state: err.code === "ENOENT" ? "missing" : "invalid", key: null };
  }
  if (!st.isFile()) return { state: "invalid", key: null };
  if ((st.mode & 0o077) !== 0) return { state: "invalid", key: null };
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
    return { state: "invalid", key: null };
  }
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return { state: "invalid", key: null };
  }
  try {
    const j = JSON.parse(raw);
    const secret = Buffer.from(String(j?.key || ""), "base64");
    if (j?.v !== KEY_VERSION || typeof j.id !== "string" || !KEY_ID_RE.test(j.id) || secret.length !== 32) {
      return { state: "invalid", key: null };
    }
    return { state: "ok", key: { id: j.id, secret } };
  } catch {
    return { state: "invalid", key: null };
  }
}

/** Read-once cache: a rotated key file takes effect on the next process (or a reload). */
const keyCache = new Map();

/**
 * Key paths whose file an explicit reload found MISSING or unreadable while a key was already
 * loaded. The cached key stays authoritative (a reload never drops it), and this mark keeps a
 * later `keyState()` — after the cache is gone — from answering "first-boot": this box is not
 * new, its key file just moved. Cleared only by `forgetTokenMacKey()`.
 */
const degradedKeys = new Set();

/**
 * Per-process, per-key-path verdict of the BOOT scan (M2): what this process concluded about
 * era evidence the last time anything looked.
 *
 *   "lost"        — the boot found era evidence (a DB mirror, `h1.` rows, a state file) but no
 *                   usable key. STICKY: a later caller asking WITHOUT that evidence can never
 *                   downgrade it back to first-boot, so a bot that plants a legacy sha256 and
 *                   deletes what it can reach still cannot get it accepted.
 *   "no-evidence" — the boot examined BOTH pieces of evidence, both were false, and the box
 *                   really is new. This is the ONLY verdict under which a key-less process may
 *                   accept the legacy form (§2.6 row 4); no verdict at all means nothing
 *                   vouched for "new", so the refusal stands.
 *
 * Once a key is loaded or created the verdict is irrelevant (the key answers first). Only
 * `forgetTokenMacKey()` (the test seam) clears it.
 */
const bootVerdicts = new Map();

function cachedKey(path) {
  return keyCache.get(path) || null;
}

/** Test seam: forget a cached key and every in-process key verdict (a fresh CROW_HOME). */
export function forgetTokenMacKey(path) {
  if (path) {
    keyCache.delete(path);
    degradedKeys.delete(path);
    bootVerdicts.delete(path);
    return;
  }
  keyCache.clear();
  degradedKeys.clear();
  bootVerdicts.clear();
}

/**
 * Create the key, crash-atomically: write and fsync a 0600 temp file, hard-link it to the
 * final name (link never overwrites; EEXIST means another writer won — use theirs), remove the
 * temp, fsync the dir. A crash can leave a stray temp but never an empty key. Same pattern as
 * `csrf.key` and `keychain.key`.
 */
function createKey(path) {
  ensureSecretsDir(dirname(path));
  const secret = randomBytes(32);
  const id = sha256Hex(secret).slice(0, 16);
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify({ v: KEY_VERSION, id, key: secret.toString("base64") }) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    linkSync(tmp, path);
  } catch (err) {
    if (err.code !== "EEXIST") {
      try { unlinkSync(tmp); } catch { /* already gone */ }
      throw err;
    }
  } finally {
    try { unlinkSync(tmp); } catch { /* already gone */ }
  }
  try {
    const dfd = openSync(dirname(path), "r");
    fsyncSync(dfd);
    closeSync(dfd);
  } catch { /* best effort */ }
  const after = keyFileState(path);
  if (after.state !== "ok") throw new TokenMacKeyError("TOKEN_MAC_KEY_INVALID", "invalid", path);
  keyCache.set(path, after.key);
  return after.key;
}

/**
 * Explicitly re-read the key file (an operator rotation, a CLI after a reset).
 *
 * A key already loaded in this process is AUTHORITATIVE: if the file now carries a different
 * id, this throws `TOKEN_MAC_KEY_CHANGED` and keeps the loaded key, so a process can never
 * mint half its values under one key and half under another ("no silent mixed minting"). A
 * restart adopts the new key cleanly. The same hold applies when the file is gone or broken:
 * clearing the cache there would let the next `keyState()`/`ensureKey()` treat the box as new
 * (or adopt a freshly written file) behind the caller's back, so the loaded key is KEPT, the
 * path is marked degraded, and this throws `TOKEN_MAC_KEY_LOST` / `TOKEN_MAC_KEY_INVALID`.
 * Returns the key when the file still matches (or was not loaded yet); throws
 * `TOKEN_MAC_KEY_MISSING` / `TOKEN_MAC_KEY_INVALID` when there is no loaded key to keep.
 */
export function reloadTokenMacKey(opts = {}) {
  const path = tokenMacKeyPath(opts);
  const cached = keyCache.get(path);
  const next = keyFileState(path);
  if (next.state !== "ok") {
    if (cached) {
      degradedKeys.add(path);
      throw new TokenMacKeyError(
        next.state === "missing" ? "TOKEN_MAC_KEY_LOST" : "TOKEN_MAC_KEY_INVALID",
        next.state === "missing" ? "lost" : "invalid",
        path,
      );
    }
    throw new TokenMacKeyError(
      next.state === "missing" ? "TOKEN_MAC_KEY_MISSING" : "TOKEN_MAC_KEY_INVALID",
      next.state === "missing" ? "missing" : "invalid",
      path,
    );
  }
  if (cached && cached.id !== next.key.id) {
    // Fail closed and keep the old key: the caller must restart, not mix eras. The cache is
    // deliberately NOT replaced, so every later call in this process stays on the old key.
    throw new TokenMacKeyError("TOKEN_MAC_KEY_CHANGED", "changed", path);
  }
  degradedKeys.delete(path);
  keyCache.set(path, next.key);
  return next.key;
}

// ─── the state file ────────────────────────────────────────────────────────

function emptyState(path, { exists = false, corrupt = false } = {}) {
  return {
    path, exists, corrupt,
    v: STATE_VERSION,
    key_id: null,
    created_at: null,
    families: {},
    password_set_at: null,
  };
}

/**
 * The secrets-side state (§2.5): `key_id`, `created_at`, per family
 * `{ converted_at, count, rollback_file }`, and `password_set_at`.
 *
 * The three outcomes are kept apart on purpose:
 *   - ENOENT is ABSENT (`exists: false`) — a real first boot, never an error.
 *   - any OTHER read error (EACCES, EIO, EMFILE, …) is THROWN as
 *     `TOKEN_MAC_STATE_UNREADABLE`: it is transient, and treating it as "no era" would fail
 *     open, so the caller retries rather than guessing.
 *   - structural damage (unparseable JSON, not an object, a non-object `families`) is
 *     `corrupt: true`, which every reader fails closed on and every writer refuses.
 */
export function readState(opts = {}) {
  const path = tokenMacStatePath(opts);
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    if (err.code === "ENOENT") return emptyState(path, { exists: false });
    throw new TokenMacStateError(
      "TOKEN_MAC_STATE_UNREADABLE",
      `token-mac state ${path} could not be read: ${err.message}`,
      err,
    );
  }
  let j;
  try {
    j = JSON.parse(raw);
  } catch {
    return emptyState(path, { exists: true, corrupt: true });
  }
  if (!j || typeof j !== "object" || Array.isArray(j)) return emptyState(path, { exists: true, corrupt: true });
  const families = j.families === undefined ? {} : j.families;
  if (!families || typeof families !== "object" || Array.isArray(families)) {
    return emptyState(path, { exists: true, corrupt: true });
  }
  return {
    path,
    exists: true,
    corrupt: false,
    v: Number.isInteger(j.v) ? j.v : STATE_VERSION,
    key_id: typeof j.key_id === "string" ? j.key_id : null,
    created_at: typeof j.created_at === "string" ? j.created_at : null,
    families,
    password_set_at: typeof j.password_set_at === "string" ? j.password_set_at : null,
  };
}

/** Write the state file atomically (0600 temp + fsync + rename + fsync dir). */
function writeState(state, opts = {}) {
  const path = tokenMacStatePath(opts);
  ensureSecretsDir(dirname(path));
  const body = {
    v: STATE_VERSION,
    key_id: state.key_id ?? null,
    created_at: state.created_at ?? null,
    families: state.families || {},
    password_set_at: state.password_set_at ?? null,
  };
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(body, null, 2) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, path);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw err;
  }
  try { chmodSync(path, 0o600); } catch { /* the temp was created 0600 */ }
  try {
    const dfd = openSync(dirname(path), "r");
    fsyncSync(dfd);
    closeSync(dfd);
  } catch { /* best effort */ }
  return path;
}

/** Serialize read-modify-write of one state file inside this process. */
const stateLocks = new Map();
function withStateLock(path, fn) {
  const prev = stateLocks.get(path) || Promise.resolve();
  const next = prev.then(fn, fn);
  stateLocks.set(path, next.then(() => {}, () => {}));
  return next;
}

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Take over a lock abandoned by a crashed writer, without letting two takers both "win".
 *
 * The naive version — lstat the lock, unlink it when old, retry — loses the race: two writers
 * can both lstat the same stale lock, both unlink, and the second unlink then removes the FRESH
 * lock the first one just created, so both hold "the" lock. Here the stale lock is never
 * unlinked in place: it is RENAMED aside first and the renamed inode is compared with the one
 * that was stat'ed as stale. Two takers can both rename, but only the one whose renamed inode
 * IS the stale one proceeds; an inode mismatch means a fresh lock was displaced, so the
 * take-over is abandoned and the lock is put back (by link, which never clobbers an existing
 * path). The caller then simply retries O_EXCL.
 *
 * lstat, never stat: a SYMLINK (or any non-regular file) at the lock path is not a lock this
 * module writes, so it is never stale and never removed — the writer keeps retrying and fails
 * closed with TOKEN_MAC_STATE_LOCKED.
 *
 * @returns {boolean} true when a stale lock was taken over and the caller may retry at once
 */
function takeOverStaleLock(lockPath) {
  let stale;
  try {
    stale = lstatSync(lockPath);
  } catch {
    return false; // released between our failed O_EXCL and this lstat
  }
  if (!stale.isFile()) return false;
  if (Date.now() - stale.mtimeMs <= STATE_LOCK_STALE_MS) return false;
  const aside = `${lockPath}.stale-${process.pid}-${randomBytes(4).toString("hex")}`;
  try {
    renameSync(lockPath, aside);
  } catch {
    return false; // another taker got there, or the writer released it: just retry
  }
  let moved;
  try {
    moved = lstatSync(aside);
  } catch {
    return false;
  }
  if (moved.ino !== stale.ino || moved.dev !== stale.dev) {
    // We renamed away a lock that is NOT the stale one we stat'ed (a fresh writer replaced it
    // in between). Never take that over: put it back if the path is still free — link, not
    // rename, so a third writer's lock can never be overwritten.
    try { linkSync(aside, lockPath); } catch { /* the path is occupied again: it is superseded */ }
    try { unlinkSync(aside); } catch { /* already gone */ }
    return false;
  }
  try { unlinkSync(aside); } catch { /* another taker was faster; the O_EXCL retry decides */ }
  return true;
}

/**
 * Cross-process read-modify-write lock for the state file: `<state>.lock`, created `O_EXCL`
 * 0600 carrying the owner's pid and timestamp. Owner CLIs load this same module beside the
 * gateway, so an in-process promise chain is not enough. A lock older than 30 s was abandoned
 * (its writer crashed) and is taken over by an inode-checked rename (`takeOverStaleLock`);
 * acquisition is retried a bounded number of times, then throws `TOKEN_MAC_STATE_LOCKED`.
 *
 * The critical section MUST be synchronous (no await), so the lock is never held across
 * unrelated I/O. Acquisition BLOCKS THE EVENT LOOP for up to ~2 s when the lock is contended
 * (400 attempts, 5 ms apart) — it is a boot/CLI path and must never run on a request path.
 */
function withStateFileLock(path, fn) {
  const lockPath = `${path}.lock`;
  ensureSecretsDir(dirname(path));
  let fd = null;
  for (let attempt = 0; attempt < STATE_LOCK_ATTEMPTS; attempt += 1) {
    try {
      fd = openSync(lockPath, "wx", 0o600);
      break;
    } catch (err) {
      if (err.code !== "EEXIST") throw err;
      if (takeOverStaleLock(lockPath)) continue; // the stale lock is gone: try O_EXCL at once
      sleepSync(STATE_LOCK_SLEEP_MS);
    }
  }
  if (fd === null) {
    throw new TokenMacStateError(
      "TOKEN_MAC_STATE_LOCKED",
      `token-mac state ${path} is locked by another process (${lockPath}); giving up after ${STATE_LOCK_ATTEMPTS} attempts`,
    );
  }
  try {
    try { writeSync(fd, JSON.stringify({ pid: process.pid, ts: new Date().toISOString() })); } catch { /* the O_EXCL file is the lock */ }
    return fn();
  } finally {
    try { closeSync(fd); } catch { /* already closed */ }
    try { unlinkSync(lockPath); } catch { /* already gone */ }
  }
}

/**
 * Record the key's identity in the state file, re-reading it UNDER the cross-process lock.
 * A corrupt or unreadable state is a hard failure and is NEVER rewritten here: throwing is
 * the fail-closed answer, and the file stays exactly as the operator left it.
 */
function rememberKeyInState(key, opts = {}) {
  const path = tokenMacStatePath(opts);
  withStateFileLock(path, () => {
    const st = readState(opts);
    if (st.corrupt) throw corruptStateError(path);
    if (st.key_id === key.id && st.created_at) return;
    writeState({
      ...st,
      key_id: key.id,
      created_at: st.created_at || new Date().toISOString(),
    }, opts);
  });
}

/**
 * Has this family's era begun? TRUE when EITHER copy says so — the secrets-side marker or the
 * one-way `token_hmac_era:<family>` DB mirror (§2.5). A bot can delete the mirror, never the
 * secrets copy, so a `secrets/` restore from an older backup still refuses legacy values as
 * long as the DB still carries the mirror.
 *
 * FAIL CLOSED: a corrupt state file, an UNREADABLE state file (EACCES/EIO/…) or a settings
 * reader that throws all answer TRUE. "We could not tell" is never "not converted".
 *
 * `readSetting` is injected: `(key) => value|null`, the dashboard settings reader.
 */
export async function familyConverted(family, { readSetting, ...location } = {}) {
  assertFamily(family);
  let st;
  try {
    st = readState(location);
  } catch {
    return true;
  }
  if (st.corrupt) return true;
  if (st.families[family]?.converted_at) return true;
  if (typeof readSetting === "function") {
    try {
      return eraValueIsConverted(await readSetting(eraSettingKey(family)));
    } catch {
      return true;
    }
  }
  return false;
}

/** The mirror's value is any non-empty epoch marker; "0"/"false"/"" mean "not converted". */
function eraValueIsConverted(value) {
  if (value === null || value === undefined) return false;
  const v = String(value).trim();
  return v !== "" && v !== "0" && v.toLowerCase() !== "false";
}

/**
 * Mark a family converted: `converted_at`, the row count and the rollback-file name land in
 * the secrets-side state file, and `token_hmac_era:<family>` (local scope) is written as the
 * one-way DB mirror when a `writeSetting` is injected.
 *
 * ADD-ONLY: this module has no API that removes a marker, and marking an already-converted
 * family is a no-op (the first `converted_at` wins — a converter must never re-run and launder
 * a post-conversion write, §3.3). A bot can reach neither copy.
 *
 * The read-modify-write happens UNDER the cross-process state lock and re-reads the file there,
 * so a concurrent writer's sibling family is preserved. A CORRUPT or UNREADABLE state file is
 * refused with a `TokenMacStateError`; nothing is renamed, rewritten or started over (renaming
 * it aside would drop every other family's era and fail open).
 *
 * @returns {Promise<{family: string, changed: boolean, converted_at: string}>}
 */
export async function markConverted(family, {
  count = null, rollbackFile = null, at, writeSetting, ...location
} = {}) {
  assertFamily(family);
  const path = tokenMacStatePath(location);
  const result = await withStateLock(path, async () => withStateFileLock(path, () => {
    const st = readState(location);
    if (st.corrupt) throw corruptStateError(path);
    const existing = st.families[family];
    if (existing && typeof existing === "object" && existing.converted_at) {
      return { family, changed: false, converted_at: existing.converted_at };
    }
    const converted_at = at || new Date().toISOString();
    writeState({
      ...st,
      families: {
        ...st.families,
        [family]: {
          converted_at,
          count: Number.isFinite(count) ? count : null,
          rollback_file: rollbackFile || null,
        },
      },
    }, location);
    return { family, changed: true, converted_at };
  }));
  if (result.changed && typeof writeSetting === "function") {
    try {
      // Local scope: this instance's own store, never synced (§2.5).
      await writeSetting(eraSettingKey(family), result.converted_at, { scope: "local" });
    } catch (err) {
      console.warn(`[token-mac] could not mirror ${eraSettingKey(family)} into the DB: ${err.message}`);
    }
  }
  return result;
}

/**
 * OPERATOR-ONLY CLEAR — the single exception to this module's add-only rule (§2.6).
 *
 * Clears the named families' era markers from the secrets-side state file, under the same
 * cross-process lock every other writer takes, and re-reads the file there so no sibling
 * writer's family is lost. Nothing here can be reached by a bot: this is an operator-shell
 * tool's entry point, and a static test pins that no file under `servers/` names it.
 *
 * THE RESET CLI DOES NOT CALL THIS, and must not: the three families stay CONVERTED THROUGHOUT
 * a reset, which is what keeps it from opening a laundering window (a converted family means
 * "a bare sha256 is not a credential here", so a legacy row a bot inserts between the reset and
 * the next gateway boot is refused and alarmed, not converted). `scripts/token-hmac.mjs
 * --reset` moves the key aside, empties `oauth_tokens` itself (it has the DB open for the same
 * run) and re-marks the families CONVERTED with `markConverted`, with `adoptOperatorKey`
 * minting the new key. The CLI therefore clears no era at any point.
 *
 * The export stays as the documented way for an operator tool to clear ONE family's era IN
 * PLACE: only the families named are touched, so every sibling family's era and
 * `password_set_at` survive and the state file is never renamed aside. It does NOT touch the DB
 * mirror (`token_hmac_era:<family>`); that is the caller's, as `markConverted` writes it.
 *
 * @param {string[]} families family names whose markers are cleared
 * @returns {Promise<{cleared: string[], path: string}>}
 */
export async function resetFamiliesForOperator(families, location = {}) {
  if (!Array.isArray(families)) throw new TypeError("resetFamiliesForOperator needs an array of family names");
  for (const family of families) assertFamily(family);
  const path = tokenMacStatePath(location);
  return withStateLock(path, async () => withStateFileLock(path, () => {
    const st = readState(location);
    if (!st.exists) return { cleared: [], path };
    if (st.corrupt) throw corruptStateError(path);
    const next = { ...st.families };
    const cleared = [];
    for (const family of families) {
      if (next[family] === undefined) continue;
      delete next[family];
      cleared.push(family);
    }
    writeState({ ...st, families: next }, location);
    return { cleared, path };
  }));
}

/**
 * OPERATOR RESET, part two — mint the REPLACEMENT key after the old one was moved aside.
 *
 * Only `scripts/token-hmac.mjs --reset` calls this (an operator-shell tool, run with the
 * gateway stopped), and `tests/token-mac-oauth.test.js` pins that no file under `servers/`
 * names it. It is the ONE place this module will create a key while a state file already
 * exists, because the operator deliberately retired the key that file describes; every other
 * path (`ensureKey`) still refuses to replace a lost or invalid key. Nothing here can be
 * reached by a bot.
 *
 * It keeps every other field of the state file — sibling families' eras, `password_set_at` —
 * and moves only `key_id`/`created_at` to the new key, so the file is never renamed aside. A
 * corrupt or unreadable state file is REFUSED (nothing overwritten, nothing renamed); the
 * caller reports it and the box stays fail-closed.
 *
 * @returns {{ id: string, secret: Buffer }} the new key
 */
export function adoptOperatorKey({ at, ...location } = {}) {
  const path = tokenMacKeyPath(location);
  const statePath = tokenMacStatePath(location);
  const key = createKey(path);
  withStateFileLock(statePath, () => {
    const st = readState(location);
    if (st.corrupt) throw corruptStateError(statePath);
    writeState({
      ...st,
      key_id: key.id,
      created_at: at || new Date().toISOString(),
    }, location);
  });
  return key;
}

// ─── key states (§2.6) ─────────────────────────────────────────────────────
/**
 * Record what a caller's era scan found, for that key path. The evidence flags are NOT
 * optional: a caller that forgot to scan gets a TypeError instead of a quiet "no evidence".
 *
 * `true` on either flag records a sticky "lost"; both `false` records "no-evidence" only when
 * the disk agrees the box is new (`keyState()` is first-boot). A recorded "lost" is never
 * downgraded, so a later caller (or a bot's delete of the DB mirror) cannot re-open the
 * key-less legacy fall-through. A key that is already loaded or on disk makes the verdict
 * irrelevant: `keyState()` answers first.
 *
 * @param {{ mirrorConverted: boolean, h1ValuesExist: boolean, crowHome?: string, path?: string,
 *           statePath?: string }} opts
 * @returns {"lost"|"no-evidence"|null} the verdict now recorded for that path (null when the
 *          key is present, so no verdict is needed)
 * @throws {TypeError} when either evidence flag is not a boolean
 */
export function noteEraEvidence(opts = {}) {
  const { mirrorConverted, h1ValuesExist } = opts;
  if (typeof mirrorConverted !== "boolean" || typeof h1ValuesExist !== "boolean") {
    throw new TypeError(
      "noteEraEvidence requires explicit mirrorConverted and h1ValuesExist booleans",
    );
  }
  return recordEraEvidence(opts);
}

/** The shared core of `noteEraEvidence` and the boot's own `ensureKey` scan (flags validated). */
function recordEraEvidence({ mirrorConverted, h1ValuesExist, ...location } = {}) {
  const path = tokenMacKeyPath(location);
  // A USABLE KEY ANSWERS FOR ITSELF. Evidence matters only for a key-less process: a converted
  // install (an era marker, `h1.` rows) that still holds its key file must load that key on a
  // cold start, or every restart of a converted box would refuse every credential and the boot
  // converter could never run. Only when there is NO usable key does a recorded "lost" stand —
  // and it stands stickily, because that is what a bot must not be able to undo.
  const file = keyFileState(path);
  if (file.state === "ok") {
    keyCache.set(path, file.key);
    return null;
  }
  if (mirrorConverted === true || h1ValuesExist === true) {
    bootVerdicts.set(path, "lost");
    return "lost";
  }
  if (bootVerdicts.get(path) === "lost") return "lost"; // evidence is sticky, never downgraded
  const state = keyState(location);
  if (state === "first-boot") {
    bootVerdicts.set(path, "no-evidence");
    return "no-evidence";
  }
  if (state === "lost") {
    bootVerdicts.set(path, "lost");
    return "lost";
  }
  return bootVerdicts.get(path) ?? null;
}

/**
 * `"ok" | "first-boot" | "lost" | "invalid"`.
 *
 * "first-boot" is the ONLY state a key may be created in, and it requires NO state file at
 * all: no key file, no `key_id`, no `password_set_at`, no family marker, no DB mirror and no
 * `h1.` value anywhere (pass `h1ValuesExist` when a caller scanned a store). A state file that
 * exists but records nothing is still evidence this box booted this version once, so it counts
 * as "lost". "lost" is no usable key but any evidence the box is not new — creating a new key
 * there would silently log every client out and hand the box to whoever asked; the operator
 * runs the reset CLI instead. It is also the answer for a state file that cannot be parsed OR
 * cannot be read (EACCES/EIO/…): "we could not tell" is never first-boot. "invalid" (bad
 * JSON, wrong length, loose mode, foreign owner, a directory or a symlink where the file
 * belongs) is never replaced automatically either.
 *
 * Once a key is loaded in this process it is authoritative and this returns "ok" without
 * touching the disk (§2.1); a rotation takes effect on the next process or an explicit
 * `reloadTokenMacKey()`.
 *
 * A verdict recorded earlier in this process (`noteEraEvidence`, or the boot's `ensureKey`)
 * OUTRANKS the disk's ABSENCE of a key: once a look at the stores found era evidence and no key,
 * a later look that asks without that evidence cannot answer "first-boot", even if the evidence
 * it saw is gone (a bot can delete the DB mirror and its own `h1.` rows). It never outranks a
 * usable key FILE, though — `recordEraEvidence` records nothing while one is present, so a
 * converted install's cold start still loads its key.
 *
 * @param {{ crowHome?: string, path?: string, statePath?: string,
 *           mirrorConverted?: boolean, h1ValuesExist?: boolean }} [opts] test seams
 */
export function keyState(opts = {}) {
  const path = tokenMacKeyPath(opts);
  if (keyCache.has(path)) return "ok";
  if (degradedKeys.has(path)) return "lost"; // a reload saw the key file vanish under us
  if (bootVerdicts.get(path) === "lost") return "lost"; // a boot already found the key lost
  const file = keyFileState(path);
  if (file.state === "ok") {
    keyCache.set(path, file.key);
    return "ok";
  }
  if (file.state === "invalid") return "invalid";
  let st;
  try {
    st = readState(opts);
  } catch {
    return "lost"; // unreadable state: an era MAY exist, so never first-boot
  }
  if (st.corrupt) return "lost";
  if (st.exists) return "lost"; // the state file records the key, the password or an era
  if (opts.mirrorConverted === true) return "lost";
  if (opts.h1ValuesExist === true) return "lost";
  return "first-boot";
}

/**
 * The key as `{ id, secret }`, created only in the "first-boot" state.
 *
 * Creating a key is the one irreversible decision in this module, so `allowCreate: true` also
 * requires the caller to state BOTH pieces of era evidence it checked (`mirrorConverted` and
 * `h1ValuesExist`) as explicit booleans. A missing flag is a programmer error, never `false`:
 * defaulting them would let a caller that forgot to scan fail open and mint a key over an era.
 *
 * The scan is also RECORDED for the process (see `noteEraEvidence`), so a refused boot leaves
 * a sticky "lost" verdict behind and later validators cannot re-interpret the missing key as
 * first-boot.
 *
 * @param {{ allowCreate?: boolean, crowHome?: string, path?: string, statePath?: string,
 *           mirrorConverted?: boolean, h1ValuesExist?: boolean }} [opts]
 * @throws {TypeError} when `allowCreate` is true and either evidence flag is not a boolean
 * @throws {TokenMacKeyError} for "lost" and "invalid" (never creates), and for "first-boot"
 *         when `allowCreate` is false
 */
export function ensureKey({ allowCreate = false, ...opts } = {}) {
  if (allowCreate
    && (typeof opts.mirrorConverted !== "boolean" || typeof opts.h1ValuesExist !== "boolean")) {
    throw new TypeError(
      "ensureKey({allowCreate:true}) requires explicit mirrorConverted and h1ValuesExist booleans",
    );
  }
  if (typeof opts.mirrorConverted === "boolean" && typeof opts.h1ValuesExist === "boolean") {
    // The boot's own scan is the better evidence: remember it before asking about the key.
    recordEraEvidence(opts);
  }
  const path = tokenMacKeyPath(opts);
  const state = keyState(opts);
  if (state === "ok") {
    const cached = cachedKey(path);
    if (cached) return cached;
    throw new TokenMacKeyError("TOKEN_MAC_KEY_INVALID", "invalid", path);
  }
  if (state === "first-boot") {
    if (!allowCreate) throw new TokenMacKeyError("TOKEN_MAC_KEY_MISSING", "missing", path);
    const key = createKey(path);
    rememberKeyInState(key, opts);
    return key;
  }
  throw new TokenMacKeyError(
    state === "lost" ? "TOKEN_MAC_KEY_LOST" : "TOKEN_MAC_KEY_INVALID",
    state,
    path,
  );
}

// ─── the MAC ───────────────────────────────────────────────────────────────

/** `hex(HMAC-SHA256(K, "crow-token-mac-v1\0" + family + "\0" + innerHex))`. */
function macHex(key, family, innerHex) {
  return createHmac("sha256", key.secret)
    .update(MAC_DOMAIN + family + FIELD_SEP + innerHex)
    .digest("hex");
}

function h1Value(key, family, innerHex) {
  return `${MAC_VERSION}.${key.id}.${macHex(key, family, innerHex)}`;
}

/** `"h1." + keyId + "." + hex( HMAC-SHA256(K, "crow-token-mac-v1\0" + family + "\0" + sha256hex(token)) )` */
export function macToken(family, token, opts = {}) {
  assertFamily(family);
  const key = ensureKey(opts);
  return h1Value(key, family, sha256Hex(String(token)));
}

/**
 * The same `h1.` value from a stored legacy sha256 hex — the offline converter's entry point.
 * No raw token and no DB transaction with the key: the stored value IS the MAC input.
 */
export function macFromLegacy(family, legacySha256Hex, opts = {}) {
  assertFamily(family);
  if (typeof legacySha256Hex !== "string" || !HEX64.test(legacySha256Hex)) {
    throw new TypeError("macFromLegacy needs a 64-character sha256 hex (today's stored form)");
  }
  const key = ensureKey(opts);
  return h1Value(key, family, legacySha256Hex.toLowerCase());
}

function safeEqualHex(a, b) {
  const left = Buffer.from(String(a), "hex");
  const right = Buffer.from(String(b), "hex");
  if (left.length === 0 || left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Verify a presented token against a stored verifier.
 *
 * @param {string} family the store's fixed domain (§2.2)
 * @param {string} token the raw secret the caller presented
 * @param {string} stored the value in the DB (an `h1.` value, or the legacy 64-hex form)
 * @param {{ converted?: boolean, rowRef?: string, audit?: Function, alarm?: boolean,
 *           crowHome?: string, path?: string, statePath?: string }} [opts]
 * @returns {{ ok: boolean, form: "h1"|"legacy"|"foreign"|"invalid", reason?: string }}
 *   - `h1` under the CURRENT key and a matching MAC → ok
 *   - `h1` under ANOTHER keyId → `{ ok: false, form: "foreign" }` (a restore mismatch: refuse
 *     and say why; the operator's key was replaced or lost)
 *   - bare 64-hex and `converted: false` → today's behaviour: compare sha256hex(token)
 *   - bare 64-hex and `converted: true` → `{ ok: false, form: "legacy" }` AND the legacy alarm
 *     (the row was written by something that does not hold the key)
 *   - anything else → `{ ok: false, form: "invalid" }`
 *
 * `form` names the shape that was RECOGNISED, not the verdict: a well-formed `h1.` value under
 * the current key whose MAC does not match answers `{ ok: false, form: "h1" }`, and a bare hex
 * that does not match answers `{ ok: false, form: "legacy" }`.
 *
 * `converted` is REQUIRED and must be a boolean (§"fail-closed defaults"): a defaulted `false`
 * would accept a legacy value in a converted family, so a caller that forgot to pass it gets a
 * TypeError instead of a quiet fall open.
 *
 * When the KEY cannot be loaded the answer is a refusal with `form: "invalid"` and a `reason`
 * (`key-lost` / `key-invalid` / `key-missing`) — EXCEPT the §2.6 row 4 case: no key at all,
 * `converted: false` (an install whose secrets were never written, so no era exists) AND a
 * recorded boot verdict of exactly "no-evidence" (a scan that checked the mirror and the `h1.`
 * values and found neither) keeps accepting a legacy 64-hex value through the timing-safe
 * sha256 compare. No verdict, a "lost" verdict, or a lost/invalid key refuses everything.
 * All secret comparisons go through `crypto.timingSafeEqual`.
 */
export function verifyStored(family, token, stored, opts = {}) {
  assertFamily(family);
  const { converted, rowRef = null, audit, alarm = true } = opts;
  if (typeof converted !== "boolean") {
    throw new TypeError(
      "verifyStored requires opts.converted to be an explicit boolean: a default would fail open",
    );
  }
  const refuse = (form, reason) => (reason ? { ok: false, form, reason } : { ok: false, form });

  // A non-string or empty presented secret can never be a credential. Refuse it here so the
  // legacy compare never gets `String(undefined)` as an input.
  if (typeof token !== "string" || token === "") return refuse("invalid");
  if (typeof stored !== "string" || stored === "") return refuse("invalid");

  const key = loadKeyForVerify(opts);
  if (!key.ok) {
    // §2.6 row 4: no key and no era keeps accepting the legacy form, so an install that never
    // converted (no secrets dir, an env-only setup) is not locked out — but ONLY on a boot that
    // actually checked both pieces of evidence and recorded that verdict. Without one (a
    // validator asking cold, or a boot that found the key lost) the refusal stands, so a bot
    // cannot delete the mirror and plant sha256(token) into a key-less process. An h1 value is
    // unverifiable here; a lost/invalid key refuses both forms.
    if (key.reason === "key-missing" && converted === false && HEX64.test(stored)
      && bootVerdicts.get(tokenMacKeyPath(opts)) === "no-evidence") {
      return safeEqualHex(sha256Hex(token), stored) ? { ok: true, form: "legacy" } : refuse("legacy");
    }
    return refuse("invalid", key.reason);
  }

  const h1 = H1_STORED.exec(stored);
  if (h1) {
    if (h1[1] !== key.key.id) return refuse("foreign");
    const expected = macHex(key.key, family, sha256Hex(token));
    return safeEqualHex(expected, h1[2]) ? { ok: true, form: "h1" } : refuse("h1");
  }

  if (HEX64.test(stored)) {
    if (converted) {
      if (alarm) {
        try { legacyAlarm(family, rowRef, { audit }); } catch { /* the alarm never blocks the refusal */ }
      }
      return refuse("legacy");
    }
    return safeEqualHex(sha256Hex(token), stored) ? { ok: true, form: "legacy" } : refuse("legacy");
  }

  return refuse("invalid");
}

/** The key for a verifier, mapped onto the `{ok, reason}` shape the refusal path needs. */
function loadKeyForVerify(opts) {
  try {
    return { ok: true, key: ensureKey({ ...opts, allowCreate: false }) };
  } catch (err) {
    if (err instanceof TokenMacKeyError) {
      const reason = err.state === "lost" ? "key-lost" : err.state === "invalid" ? "key-invalid" : "key-missing";
      return { ok: false, reason };
    }
    throw err;
  }
}

/**
 * Verify a stored value that must be an `h1.` MAC over `value` under `family` — the TOKEN-LESS
 * form of `verifyStored`, for a caller whose stored value is a MAC over a DOCUMENT rather than a
 * verifier over a raw secret (the `bot:def` family, whose MAC input is a bot definition's
 * canonical form).
 *
 * There is deliberately no legacy branch and no era to consult: a bare sha256 is refused
 * whatever the family's era says, because this module never minted one for such a caller. So the
 * answer cannot fail open — the worst case is refusing a value an older release would have
 * accepted, and no release ever wrote one.
 *
 * @returns {{ok: boolean, form: "h1"|"foreign"|"invalid", reason?: string}} `reason` is the
 *          key problem (`key-lost` / `key-invalid` / `key-missing`) when the key is unusable.
 */
export function verifyMacValue(family, value, stored, opts = {}) {
  assertFamily(family);
  const loaded = loadKeyForVerify(opts);
  if (!loaded.ok) return { ok: false, form: "invalid", reason: loaded.reason };
  if (typeof stored !== "string") return { ok: false, form: "invalid" };
  const h1 = H1_STORED.exec(stored);
  if (!h1) return { ok: false, form: "invalid" };
  if (h1[1] !== loaded.key.id) return { ok: false, form: "foreign" };
  const expected = macHex(loaded.key, family, sha256Hex(String(value)));
  return safeEqualHex(expected, h1[2]) ? { ok: true, form: "h1" } : { ok: false, form: "h1" };
}

// ─── the legacy alarm (§3.3) — LOG-ONLY in this PR ─────────────────────────

/** family → `{ at, rows:Set }` for the current alarm window (ms). */
const alarmSeen = new Map();

/** Test seam: forget the in-process alarm de-duplication. */
export function forgetTokenMacAlarms() {
  alarmSeen.clear();
}

/** A row reference that could be a stored verifier is never printed. */
function redactRowRef(rowRef) {
  if (rowRef === null || rowRef === undefined) return "";
  const value = String(rowRef);
  if (/^[0-9a-f]{64}$/i.test(value) || value.startsWith("h1.")) return "[redacted]";
  return value.slice(0, 120);
}

/**
 * Report a refused old-style (legacy) credential record.
 *
 * LOG-ONLY, deliberately: one `console.warn` line plus one `auditLog("token_legacy_form",
 * { family, row })` through the injected function. No bell, no notification, no i18n — the
 * user-visible copy is pending approval, so this PR adds no string a person sees in the UI.
 *
 * De-duplication is split: the CONSOLE line is at most one per family per 24 h (an attacker
 * cannot flush the log by retrying), while the AUDIT row is written once per DISTINCT row
 * reference in that window (capped at 100 per family), so an operator sees which rows were
 * written rather than only the first. A row reference that looks like a stored verifier (64
 * hex, or an `h1.` value) is printed as `[redacted]`.
 *
 * @param {string} family
 * @param {string|null} rowRef a row id or setting key, for the audit detail (never a secret)
 * @param {{ audit?: (eventType: string, details: object) => any, now?: number,
 *           windowMs?: number }} [opts]
 * @returns {boolean} true when this call emitted the console alarm, false when it was
 *          de-duplicated (an audit row for a new rowRef may still have been written)
 */
export function legacyAlarm(family, rowRef = null, opts = {}) {
  assertFamily(family);
  const now = Number.isFinite(opts.now) ? opts.now : Date.now();
  const windowMs = Number.isFinite(opts.windowMs) ? opts.windowMs : TOKEN_MAC_ALARM_WINDOW_MS;
  let window = alarmSeen.get(family);
  const raised = !window || now < window.at || now - window.at >= windowMs;
  if (raised) {
    window = { at: now, rows: new Set() };
    alarmSeen.set(family, window);
    const row = redactRowRef(rowRef);
    console.warn(
      `[token-mac] refused an old-style credential record for ${family}${row ? ` (row ${row})` : ""}: after the keyed-hash `
      + "conversion a bare sha256 is never a credential, so something without the key wrote this row. "
      + "Nothing was changed.",
    );
  }
  const row = rowRef === null || rowRef === undefined ? null : String(rowRef);
  if (!window.rows.has(row) && window.rows.size < ALARM_MAX_ROWS) {
    window.rows.add(row);
    if (typeof opts.audit === "function") {
      try {
        const pending = opts.audit("token_legacy_form", { family, row });
        if (pending && typeof pending.catch === "function") pending.catch(() => {});
      } catch { /* the audit log is best effort; the refusal already happened */ }
    }
  }
  return raised;
}

// ─── the password pepper (§2.2, §2.4 — implemented, wired by a later PR) ───

/**
 * The MAC over a password's scrypt key hex:
 * `HMAC(K, domain + "password" + "\0" + salt + "\0" + keyHex)`.
 *
 * The SALT is bound into the input (a deliberate hygiene deviation from §2.2, which spells the
 * input without it): the salt is stored beside the MAC anyway, and binding it keeps the same
 * scrypt output under two salts from producing the same verifier.
 */
function pepperMacHex(key, scryptKeyHex, salt) {
  return macHex(key, PASSWORD_FAMILY, `${salt}${FIELD_SEP}${scryptKeyHex.toLowerCase()}`);
}

/**
 * `p2$<scrypt salt>$<hex HMAC(K, "crow-token-mac-v1\0password\0" + salt + "\0" + scrypt key hex)>`
 *
 * The scrypt output itself is NOT stored any more; the salt is (scrypt needs it) and the MAC
 * is the verifier. Replacing this value requires the key, so a DB writer cannot plant a
 * password — and deleting it is what `password_set_at` in the state file covers (§2.4).
 *
 * @param {string} scryptKeyHex the 64-byte scrypt output, hex (today's `salt:key` second half)
 * @param {{ salt: string } & object} opts the scrypt salt that produced it, plus key seams
 */
export function pepperPassword(scryptKeyHex, { salt, ...keyOpts } = {}) {
  if (typeof scryptKeyHex !== "string" || !SCRYPT_HEX.test(scryptKeyHex)) {
    throw new TypeError("pepperPassword needs the 64-byte scrypt output as hex (128 hex characters)");
  }
  if (typeof salt !== "string" || salt === "" || !HEX_ANY.test(salt)) {
    throw new TypeError("pepperPassword needs the scrypt salt (hex) that produced that key");
  }
  const key = ensureKey(keyOpts);
  return `p2$${salt}$${pepperMacHex(key, scryptKeyHex, salt)}`;
}

/** `{ salt, mac }` from a `p2$…$…` value, or null for anything else. */
export function parsePepper(stored) {
  if (typeof stored !== "string") return null;
  const m = PEPPER_STORED.exec(stored);
  return m ? { salt: m[1], mac: m[2].toLowerCase() } : null;
}

/**
 * True when `scryptKeyHex` is the key the `p2$` value was minted from. Timing-safe; a legacy
 * `salt:key` value, an unknown shape or a missing key answers false (never throws, never
 * accepts).
 */
export function verifyPepper(stored, scryptKeyHex, keyOpts = {}) {
  const parsed = parsePepper(stored);
  if (!parsed) return false;
  if (typeof scryptKeyHex !== "string" || !SCRYPT_HEX.test(scryptKeyHex)) return false;
  const loaded = loadKeyForVerify(keyOpts);
  if (!loaded.ok) return false;
  return safeEqualHex(pepperMacHex(loaded.key, scryptKeyHex, parsed.salt), parsed.mac);
}

/**
 * The whole password check for the `p2$` form: scrypt the presented password with the stored
 * salt (Node's defaults, 64-byte key — the same parameters today's `hashPassword` uses), then
 * the timing-safe MAC compare. A wrong password, an unknown form or a missing key is false.
 */
export async function verifyPepperPassword(password, stored, keyOpts = {}) {
  const parsed = parsePepper(stored);
  if (!parsed) return false;
  const loaded = loadKeyForVerify(keyOpts);
  if (!loaded.ok) return false;
  let derived;
  try {
    derived = await scryptAsync(String(password), parsed.salt, 64);
  } catch {
    return false;
  }
  return safeEqualHex(pepperMacHex(loaded.key, derived.toString("hex"), parsed.salt), parsed.mac);
}

/**
 * Convert a legacy `salt:key` password hash to the `p2$` form without the password — the
 * converter's entry point (the key hex IS the MAC input, exactly as for tokens).
 */
export function pepperFromLegacy(legacySaltColonKey, keyOpts = {}) {
  if (typeof legacySaltColonKey !== "string") throw new TypeError("pepperFromLegacy needs a `salt:key` value");
  const at = legacySaltColonKey.indexOf(":");
  if (at <= 0) throw new TypeError("pepperFromLegacy needs a `salt:key` value");
  return pepperPassword(legacySaltColonKey.slice(at + 1), { salt: legacySaltColonKey.slice(0, at), ...keyOpts });
}