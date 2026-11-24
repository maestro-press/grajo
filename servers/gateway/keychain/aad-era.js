/**
 * The keychain's AAD era — where a keychain value became BOUND to its row.
 *
 * `crow_keychain.secret_sealed` used to be sealed with secret-box v1, which carries NO
 * associated data: every blob opened under the keychain key alone, so a copy of any row's
 * `secret_sealed` + `key_id` opened in any other row. `servers/gateway/keychain/store.js`
 * now seals v2 (`enc:v2:`, AES-GCM with the row's own `rowAad`), and the value belongs to
 * exactly one row.
 *
 * THE ERA. Once this instance has CONVERTED its rows (boot/keychain-aad.js), a v1 blob is
 * no longer a value Crow wrote — nothing in this release seals one — so a keychain row that
 * still holds one is refused exactly like an unreadable row (never opened, never handed to
 * an add-on child), recorded (`keychain_legacy_form`) and reported once a day in the bell.
 * Before the era v1 rows open as they always did.
 *
 * THREE ONE-WAY TRIGGERS, any one of them is enough:
 *
 *   1. the state file `<secrets dir>/keychain-aad-state.json` —
 *      `{converted_at, key_id, rows, snapshot}`, 0600 in a 0700 dir, written atomically.
 *      It is HOST state (a bot can write crow.db), so it is read hardened: opened
 *      O_NOFOLLOW/O_NONBLOCK, judged on its own fd (regular file, this process's uid, mode
 *      & 0o022 === 0) and capped, so a symlink, a FIFO, a foreign or group-writable file is
 *      not proof of anything. Cached per process and re-read when its identity changes
 *      (mtime/size/ino), because `extensionSecretsSync` runs on the pibot host's hot path.
 *   2. the DB mirror setting `keychain_aad_era` (local scope, a `dashboard_settings_overrides`
 *      row), so a crow.db restored without the state file still knows its rows were
 *      converted. It is a BOT-WRITABLE row: refusing a v1 blob on it is the fail-closed
 *      reading, but the boot converter is stricter (`boot/keychain-aad.js`) — it trusts the
 *      mirror as "already converted" only when a v2 row also OPENS under the current key, and
 *      otherwise alarms the mirror, ignores it and converts the rows.
 *   3. any `enc:v2:` keychain row at all. Nothing in this release seals one except the
 *      conversion (and the writers, which only ever run after it), so a v2 row IS evidence a
 *      conversion ran — whatever the state file or the mirror say, and whether this process
 *      can read them or not. (For REFUSING a v1 blob that is the fail-closed reading; the
 *      boot converter's own crash-vs-fresh decision is stricter — see boot/keychain-aad.js.)
 *
 * THE SECRETS DIR, NOT A HOME. Every function here takes the SECRETS DIRECTORY the key file
 * lives in (`<CROW_HOME>/secrets`, or the pibot host's fd-anchored `/proc/self/fd/<N>`), never
 * a Crow home: the pibot host reads the key through an anchored fd and has no home path for
 * it, and deriving one from the key path by stripping two components turned that path into
 * `/proc/self/fd/secrets/…` — a state file that never existed, so the era rested on the
 * bot-writable mirror alone. Callers holding a home use `aadSecretsDirFromHome`, callers
 * holding a key path `aadSecretsDirFromKeyPath`.
 *
 * This module is reached from the pibot host's spawn hydration (through
 * servers/shared/addon-secrets.js -> keychain/store.js), so it imports nothing but node
 * builtins and the shared home resolver, and it never opens the keychain key.
 */
import {
  closeSync, constants, fstatSync, fsyncSync, mkdirSync, openSync, readSync, renameSync,
  unlinkSync, writeSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { resolveCrowHome } from "../../shared/crow-home.js";

/** The local-scope dashboard setting that mirrors "this database's keychain is converted". */
export const AAD_ERA_SETTING = "keychain_aad_era";
/** The state file's name inside the secrets dir. */
export const AAD_STATE_FILENAME = "keychain-aad-state.json";
/** A state file bigger than this is not one this instance wrote (it holds four fields). */
export const MAX_STATE_BYTES = 8192;
/**
 * The one bell: the same bare "Crow alert" title the provider-key alerts use (no body). Its
 * explanatory sentence waits for the owner's copy pass; the audit row carries the detail.
 */
export const LEGACY_FORM_BELL = "Crow alert";
/** The audit event every refused legacy row is recorded under. */
export const LEGACY_FORM_EVENT = "keychain_legacy_form";

/** The secrets dir a Crow home owns: `<CROW_HOME>/secrets` (where the key and its state live). */
export function aadSecretsDirFromHome(crowHome) {
  return join(crowHome, "secrets");
}

/** The secrets dir a keychain key path names: `<secrets>/keychain.key` → `<secrets>`. */
export function aadSecretsDirFromKeyPath(keyPath) {
  return dirname(keyPath);
}

/** `<secretsDir>/keychain-aad-state.json`. */
export function keychainAadStatePath(secretsDir) {
  return join(secretsDir, AAD_STATE_FILENAME);
}

/** This process's uid, or null on a platform that has none. */
function ourUid() {
  return typeof process.getuid === "function" ? process.getuid() : null;
}

/** The secrets dir to read the state file from; null when none can be resolved (no file then). */
function safeSecretsDir(secretsDir) {
  if (typeof secretsDir === "string" && secretsDir !== "") return secretsDir;
  try {
    return aadSecretsDirFromHome(resolveCrowHome());
  } catch {
    return null;
  }
}

// ─── the state file ─────────────────────────────────────────────────────────

/** Per-path cache: `{ key, result }`, where `key` is the fd's identity (mtime/size/ino/…). */
const stateCache = new Map();

/** Test seam: forget every cached state-file read (a test's next "boot"). */
export function _resetAadStateCacheForTest() {
  stateCache.clear();
  alarmedRows.clear();
  mirrorUntrustedAlarmed = false;
}

/**
 * Read the state file HARDENED and cached. Result:
 *   `{state: "converted", doc}`  — a well-formed state file (converted_at present);
 *   `{state: "absent"}`           — no such path (ENOENT);
 *   `{state: "unreadable"}`       — anything else: a symlink, a FIFO, a foreign/loose file,
 *                                    an oversize or malformed body.
 * Never throws.
 */
export function readAadState(secretsDir) {
  const dir = safeSecretsDir(secretsDir);
  if (!dir) return { state: "absent" };
  const path = keychainAadStatePath(dir);
  let fd = null;
  try {
    try {
      fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (err) {
      if (err?.code === "ENOENT") {
        stateCache.delete(path);
        return { state: "absent" };
      }
      return { state: "unreadable" };
    }
    const stat = fstatSync(fd);
    const cacheKey = `${stat.mtimeMs}:${stat.size}:${stat.ino}:${stat.mode}:${stat.uid}`;
    const cached = stateCache.get(path);
    if (cached && cached.key === cacheKey) return cached.result;
    const result = judgeStateFd(fd, stat);
    stateCache.set(path, { key: cacheKey, result });
    return result;
  } catch {
    return { state: "unreadable" };
  } finally {
    if (fd !== null) { try { closeSync(fd); } catch { /* already closed */ } }
  }
}

/** The body of the state file, judged from the very fd it was read from. */
function judgeStateFd(fd, stat) {
  if (!stat.isFile()) return { state: "unreadable" };
  if (stat.size > MAX_STATE_BYTES) return { state: "unreadable" };
  if ((stat.mode & 0o022) !== 0) return { state: "unreadable" };
  const uid = ourUid();
  if (uid !== null && stat.uid !== uid) return { state: "unreadable" };
  const buffer = Buffer.alloc(MAX_STATE_BYTES + 1);
  let total = 0;
  while (total < buffer.length) {
    const read = readSync(fd, buffer, total, buffer.length - total, null);
    if (read <= 0) break;
    total += read;
  }
  if (total > MAX_STATE_BYTES) return { state: "unreadable" };
  let doc;
  try {
    doc = JSON.parse(buffer.toString("utf8", 0, total));
  } catch {
    return { state: "unreadable" };
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc) || typeof doc.converted_at !== "string") {
    return { state: "unreadable" };
  }
  return { state: "converted", doc };
}

/**
 * Write the era state file atomically: the secrets dir at 0700, the temp file created EXCLUSIVELY
 * at 0600, fsync'd, renamed into place, the directory fsync'd. Returns the path.
 */
export function writeAadState(secretsDir, { keyId = null, rows = 0, snapshot = null, now = new Date() } = {}) {
  const dir = safeSecretsDir(secretsDir);
  if (!dir) throw new Error("keychain-aad: no secrets directory to record the era in");
  const path = keychainAadStatePath(dir);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp-${process.pid}-${Date.now().toString(16)}`;
  const doc = {
    converted_at: (now instanceof Date ? now : new Date()).toISOString(),
    key_id: keyId === null ? null : String(keyId),
    rows: Number(rows) || 0,
    snapshot: snapshot === null ? null : String(snapshot),
  };
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(doc) + "\n");
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
  try {
    const dfd = openSync(dirname(path), "r");
    fsyncSync(dfd);
    closeSync(dfd);
  } catch { /* best effort */ }
  stateCache.delete(path);
  return path;
}

/** Remove the era state file (the downgrade tool). Missing is fine. */
export function removeAadState(secretsDir) {
  const dir = safeSecretsDir(secretsDir);
  if (!dir) return;
  const path = keychainAadStatePath(dir);
  try { unlinkSync(path); } catch { /* already gone */ }
  stateCache.delete(path);
}

/** Does the state file alone say converted? (No DB needed; used by the sync comparators.) */
export function eraConvertedFromFile(secretsDir) {
  return readAadState(secretsDir).state === "converted";
}

// ─── the DB mirror + the v2 evidence (both handle shapes) ──────────────────

/** The era mirror setting, from a better-sqlite3 handle. Missing tables read as "absent". */
export function mirrorConvertedSync(rawDb) {
  if (!rawDb || typeof rawDb.prepare !== "function") return false;
  for (const sql of [
    `SELECT 1 AS hit FROM dashboard_settings_overrides WHERE key = ? LIMIT 1`,
    `SELECT 1 AS hit FROM dashboard_settings WHERE key = ? LIMIT 1`,
  ]) {
    try {
      if (rawDb.prepare(sql).get(AAD_ERA_SETTING)) return true;
    } catch { /* no such table on an old store */ }
  }
  return false;
}

/**
 * Any `enc:v2:` keychain row? (Evidence that a conversion ran, even without a marker.) The
 * prefix is matched with `substr`, never SQLite's case-insensitive LIKE: only the exact form
 * this release writes counts, and a row in any other spelling is a row that opens nothing.
 */
export function anyV2RowSync(rawDb) {
  if (!rawDb || typeof rawDb.prepare !== "function") return false;
  try {
    return !!rawDb.prepare("SELECT 1 AS hit FROM crow_keychain WHERE substr(secret_sealed, 1, 7) = 'enc:v2:' LIMIT 1").get();
  } catch {
    return false;
  }
}

/** The era mirror setting, from a libsql-shaped client. */
export async function mirrorConvertedAsync(db) {
  if (!db || typeof db.execute !== "function") return false;
  for (const sql of [
    "SELECT 1 AS hit FROM dashboard_settings_overrides WHERE key = ? LIMIT 1",
    "SELECT 1 AS hit FROM dashboard_settings WHERE key = ? LIMIT 1",
  ]) {
    try {
      const { rows } = await db.execute({ sql, args: [AAD_ERA_SETTING] });
      if (rows && rows.length > 0) return true;
    } catch { /* no such table on an old store */ }
  }
  return false;
}

/** Any `enc:v2:` keychain row? (libsql-shaped client.) */
export async function anyV2RowAsync(db) {
  if (!db || typeof db.execute !== "function") return false;
  try {
    const { rows } = await db.execute("SELECT 1 AS hit FROM crow_keychain WHERE substr(secret_sealed, 1, 7) = 'enc:v2:' LIMIT 1");
    return !!(rows && rows.length > 0);
  } catch {
    return false;
  }
}

/**
 * The era verdict for a SYNCHRONOUS caller (`extensionSecretsSync`, `readableSecretsSync`, the
 * boot scan): the state file OR the DB mirror OR any `enc:v2:` row. The third one is what makes
 * a v1 blob fail CLOSED: a v2 row means a conversion ran, whatever a bot may have deleted from
 * crow.db (the mirror) or whatever the state file's state is (absent, unreadable, malformed).
 * It judges the row PREFIX only, not the row's key id — a v2 row under another key id is one
 * this machine cannot open either way, so it is still proof that no v1 value here is Crow's.
 */
export function eraConvertedSync(rawDb, secretsDir) {
  if (readAadState(secretsDir).state === "converted") return true;
  if (mirrorConvertedSync(rawDb)) return true;
  return anyV2RowSync(rawDb);
}

/** The same verdict for an async caller (`openEntrySecret`, `serviceSecretsFor`, …). */
export async function eraConvertedAsync(db, secretsDir) {
  if (readAadState(secretsDir).state === "converted") return true;
  if (await mirrorConvertedAsync(db)) return true;
  return anyV2RowAsync(db);
}

/** Write the DB mirror (better-sqlite3). The state file is the primary trigger; this is the
 *  one a crow.db restored without the state file still carries. */
export function writeAadMirrorSync(rawDb, instanceId, { now = new Date() } = {}) {
  if (typeof instanceId !== "string" || instanceId === "") return false;
  try {
    rawDb.prepare(
      `INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at, lamport_ts)
       VALUES (?, ?, ?, ?, 0)
       ON CONFLICT(key, instance_id) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    ).run(AAD_ERA_SETTING, instanceId, (now instanceof Date ? now : new Date()).toISOString());
    return true;
  } catch {
    return false;
  }
}

/** Remove the DB mirror rows (the downgrade tool): every instance's, never only this one's. */
export function removeAadMirrorSync(rawDb) {
  let removed = 0;
  for (const sql of [
    "DELETE FROM dashboard_settings_overrides WHERE key = ?",
    "DELETE FROM dashboard_settings WHERE key = ?",
  ]) {
    try { removed += rawDb.prepare(sql).run(AAD_ERA_SETTING).changes; } catch { /* no such table */ }
  }
  return removed;
}

// ─── the alarm ──────────────────────────────────────────────────────────────

/**
 * Rows this process already alarmed, so one planted row read on every bot turn does not
 * write an audit row per turn. Bounded: an alarm is a diagnostic, not a ledger.
 */
const alarmedRows = new Set();
const MAX_ALARMED_ROWS = 1000;

function alarmKey(row) {
  return `${row?.id ?? "?"}|${row?.kind ?? "?"}|${String(row?.secret_sealed ?? "").slice(0, 24)}`;
}

function shouldAlarm(row) {
  const key = alarmKey(row);
  if (alarmedRows.has(key)) return false;
  if (alarmedRows.size >= MAX_ALARMED_ROWS) alarmedRows.clear();
  alarmedRows.add(key);
  return true;
}

/** The audit details of one refusal: the row's id and kind — never a value, blob or key id. */
function alarmDetails(row) {
  return JSON.stringify({ id: Number(row?.id) || null, kind: typeof row?.kind === "string" ? row.kind : null });
}

/**
 * Whether the untrusted-mirror alarm was already raised in this process (one audit row and one
 * bell per boot, however many times the boot pass looks). Reset by the test seam above.
 */
let mirrorUntrustedAlarmed = false;

/** One bell per 24 h, `source = "security"`: the fixed sentence, nothing else. */
const BELL_SQL_ASYNC =
  "INSERT INTO notifications (type, source, title, body, priority) VALUES ('system', 'security', ?, NULL, 'normal')";
const BELL_EXISTS_ASYNC =
  "SELECT 1 AS hit FROM notifications WHERE source = 'security' AND title = ? AND created_at > datetime('now', '-1 day') LIMIT 1";

/**
 * Record one refused legacy row, SYNCHRONOUSLY (the pibot host's reader, the boot scan):
 * an `audit_log` row `keychain_legacy_form` plus the one bell (deduped per 24 h and per
 * process). Best effort by design — an alarm must never turn a refusal into a different
 * failure.
 */
export function raiseLegacyFormAlarmSync(rawDb, row) {
  if (!rawDb || typeof rawDb.prepare !== "function") return;
  if (!shouldAlarm(row)) return;
  try {
    rawDb.prepare("INSERT INTO audit_log (event_type, details) VALUES (?, ?)").run(LEGACY_FORM_EVENT, alarmDetails(row));
  } catch { /* no audit_log on an old store */ }
  try {
    const q = rawDb.prepare("SELECT 1 AS hit FROM notifications WHERE source = 'security' AND title = ? AND created_at > datetime('now', '-1 day') LIMIT 1");
    if (!q.get(LEGACY_FORM_BELL)) rawDb.prepare(BELL_SQL_ASYNC).run(LEGACY_FORM_BELL);
  } catch { /* no notifications table */ }
}

/** The same alarm for a libsql-shaped client. */
export async function raiseLegacyFormAlarmAsync(db, row) {
  if (!db || typeof db.execute !== "function") return;
  if (!shouldAlarm(row)) return;
  try {
    await db.execute({ sql: "INSERT INTO audit_log (event_type, details) VALUES (?, ?)", args: [LEGACY_FORM_EVENT, alarmDetails(row)] });
  } catch { /* no audit_log on an old store */ }
  try {
    const { rows } = await db.execute({ sql: BELL_EXISTS_ASYNC, args: [LEGACY_FORM_BELL] });
    if (!rows || rows.length === 0) await db.execute({ sql: BELL_SQL_ASYNC, args: [LEGACY_FORM_BELL] });
  } catch { /* no notifications table */ }
}

/**
 * The DB mirror (`keychain_aad_era`) says "already converted" while nothing else backs it: no
 * host state file, and no `enc:v2:` row that opens under this key. That mirror is one row in a
 * bot-writable table, so it is not proof of an era — the boot converter IGNORES it and converts
 * the owner's rows instead. This records that once: the same `keychain_legacy_form` audit event
 * (its details name the mirror, never a value or a blob) and the same bare `security` bell the
 * legacy refusals ring, deduped per 24 h and per process. Best effort; never throws.
 */
export function raiseMirrorUntrustedAlarmSync(rawDb) {
  if (!rawDb || typeof rawDb.prepare !== "function") return;
  if (mirrorUntrustedAlarmed) return;
  mirrorUntrustedAlarmed = true;
  try {
    rawDb.prepare("INSERT INTO audit_log (event_type, details) VALUES (?, ?)").run(LEGACY_FORM_EVENT, JSON.stringify({ mirror: AAD_ERA_SETTING }));
  } catch { /* no audit_log on an old store */ }
  try {
    const q = rawDb.prepare("SELECT 1 AS hit FROM notifications WHERE source = 'security' AND title = ? AND created_at > datetime('now', '-1 day') LIMIT 1");
    if (!q.get(LEGACY_FORM_BELL)) rawDb.prepare(BELL_SQL_ASYNC).run(LEGACY_FORM_BELL);
  } catch { /* no notifications table */ }
}