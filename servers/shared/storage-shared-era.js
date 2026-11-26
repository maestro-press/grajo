/**
 * storage-shared-era — where THIS instance's `storage.shared.*` credentials became BOUND.
 *
 * Release 2 of the storage AAD arc. Release 1 made every reader able to open an `enc:v2:`
 * credential (bound to its setting key, the normalized endpoint and the SSL flag); release 2
 * converts this instance's two credential rows once (`boot/storage-shared-aad.js`) and records
 * the ERA here. From then on a reader REFUSES `enc:v1:` and plaintext for these two settings
 * (`storage_credentials_pre_era`): after the conversion nothing Crow runs here writes a v1 value
 * or a plaintext one, so the only writer left is a bot with crow.db write access.
 *
 * THE ERA IS ONE-WAY AND PER INSTANCE. It is NEVER derived from `peersStorageAadCapable` or any
 * `tailnet_sync_sa:*` row: those are bot-writable overrides, and a live check would let one
 * bot-written row re-open v1 acceptance after the conversion.
 *
 * TWO RECORDS, the same pair the keychain's era uses (servers/gateway/keychain/aad-era.js):
 *
 *   1. the HOST state file `<secrets dir>/storage-shared-aad-state.json` — `{converted_at, rows}`,
 *      0600 in a 0700 dir, written atomically. crow.db is bot-writable, so this file is the
 *      primary proof. It is read hardened: opened O_NOFOLLOW/O_NONBLOCK, judged on its own fd
 *      (regular file, this process's uid, no group/other write bit) and size-capped, so a symlink,
 *      a FIFO or a foreign or group-writable file is not proof of anything. Cached per path and
 *      re-read when its identity changes.
 *   2. the DB mirror: a `storage_shared_aad_era` row in `dashboard_settings_overrides` (local
 *      scope, never synced), so a crow.db restored without the state file still knows. It is a
 *      BOT-WRITABLE row, so it may only ADD refusals: a reader treats it as "era on", and the boot
 *      converter NEVER skips the conversion on the mirror alone.
 *
 * THE SECRETS DIR, NOT A HOME. Every function takes the SECRETS DIRECTORY itself (a real
 * `<CROW_HOME>/secrets`, or a host's fd-anchored `/proc/self/fd/<N>`), and joins the file name
 * onto it. It never strips path components to find a home: that is how the pibot host's anchored
 * path became `/proc/self/fd/secrets/...` for the keychain (#119). A caller with no directory in
 * hand gets `<resolveCrowHome()>/secrets`.
 *
 * This module is reached from the storage client (which bundle MCP children load), so it imports
 * nothing but node builtins and the shared home resolver, and it never touches an identity.
 * Nothing in it throws except the two writers; no function logs a value.
 */
import {
  closeSync, constants, fstatSync, fsyncSync, mkdirSync, openSync, readSync, renameSync,
  unlinkSync, writeSync,
} from "node:fs";
import { join } from "node:path";
import { resolveCrowHome } from "./crow-home.js";

/** The local-scope dashboard setting that mirrors "this database's credentials are converted". */
export const STORAGE_ERA_SETTING = "storage_shared_aad_era";
/** The state file's name inside the secrets dir. */
export const STORAGE_ERA_STATE_FILENAME = "storage-shared-aad-state.json";
/** The state file holds two fields; anything bigger is not one this instance wrote. */
export const STORAGE_ERA_MAX_STATE_BYTES = 8192;

/** `<crowHome>/secrets`. */
export function storageEraSecretsDirFromHome(crowHome) {
  return join(crowHome, "secrets");
}

/** `<secretsDir>/storage-shared-aad-state.json`. */
export function storageEraStatePath(secretsDir) {
  return join(secretsDir, STORAGE_ERA_STATE_FILENAME);
}

/** The secrets dir to use: the one given, else `<resolveCrowHome()>/secrets`, else null. */
function safeSecretsDir(secretsDir) {
  if (typeof secretsDir === "string" && secretsDir !== "") return secretsDir;
  try {
    return storageEraSecretsDirFromHome(resolveCrowHome());
  } catch {
    return null;
  }
}

function ourUid() {
  return typeof process.getuid === "function" ? process.getuid() : null;
}

const stateCache = new Map();

/** Test seam: forget every cached state-file read. */
export function _resetStorageEraCacheForTest() {
  stateCache.clear();
}

/**
 * Read the state file hardened and cached. `{state: "converted", doc}`, `{state: "absent"}` (no
 * such path) or `{state: "unreadable"}` (a symlink, a FIFO, a foreign or loose file, an oversize
 * or malformed body). Never throws.
 */
export function readStorageEraState(secretsDir) {
  const dir = safeSecretsDir(secretsDir);
  if (!dir) return { state: "absent" };
  const path = storageEraStatePath(dir);
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

function judgeStateFd(fd, stat) {
  if (!stat.isFile()) return { state: "unreadable" };
  if (stat.size > STORAGE_ERA_MAX_STATE_BYTES) return { state: "unreadable" };
  if ((stat.mode & 0o022) !== 0) return { state: "unreadable" };
  const uid = ourUid();
  if (uid !== null && stat.uid !== uid) return { state: "unreadable" };
  const buffer = Buffer.alloc(STORAGE_ERA_MAX_STATE_BYTES + 1);
  let total = 0;
  while (total < buffer.length) {
    const read = readSync(fd, buffer, total, buffer.length - total, null);
    if (read <= 0) break;
    total += read;
  }
  if (total > STORAGE_ERA_MAX_STATE_BYTES) return { state: "unreadable" };
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

/** Write the state file atomically (dir 0700, temp created exclusively at 0600, fsync, rename). */
export function writeStorageEraState(secretsDir, { rows = 0, now = new Date() } = {}) {
  const dir = safeSecretsDir(secretsDir);
  if (!dir) throw new Error("storage-shared-era: no secrets directory to record the era in");
  const path = storageEraStatePath(dir);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp-${process.pid}-${Date.now().toString(16)}`;
  const doc = {
    converted_at: (now instanceof Date ? now : new Date()).toISOString(),
    rows: Number(rows) || 0,
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
    const dfd = openSync(dir, "r");
    fsyncSync(dfd);
    closeSync(dfd);
  } catch { /* best effort */ }
  stateCache.delete(path);
  return path;
}

/** Remove the state file (a downgrade tool, or a test). Missing is fine. */
export function removeStorageEraState(secretsDir) {
  const dir = safeSecretsDir(secretsDir);
  if (!dir) return;
  const path = storageEraStatePath(dir);
  try { unlinkSync(path); } catch { /* already gone */ }
  stateCache.delete(path);
}

// ─── the DB mirror ─────────────────────────────────────────────────────────

/** The mirror from a better-sqlite3 handle. A missing table reads as "no mirror". */
export function storageEraMirrorSync(rawDb) {
  if (!rawDb || typeof rawDb.prepare !== "function") return false;
  try {
    return !!rawDb.prepare("SELECT 1 AS hit FROM dashboard_settings_overrides WHERE key = ? LIMIT 1").get(STORAGE_ERA_SETTING);
  } catch {
    return false;
  }
}

/** The mirror from a libsql-shaped client. */
export async function storageEraMirrorAsync(db) {
  if (!db || typeof db.execute !== "function") return false;
  try {
    const { rows } = await db.execute({
      sql: "SELECT 1 AS hit FROM dashboard_settings_overrides WHERE key = ? LIMIT 1",
      args: [STORAGE_ERA_SETTING],
    });
    return !!(rows && rows.length > 0);
  } catch {
    return false;
  }
}

/**
 * The era verdict for a SYNCHRONOUS reader: the host state file OR the DB mirror. Either is
 * enough to REFUSE; neither is ever derived from peer capability rows.
 */
export function storageEraOnSync(rawDb, secretsDir) {
  if (readStorageEraState(secretsDir).state === "converted") return true;
  return storageEraMirrorSync(rawDb);
}

/** The same verdict for an async reader. */
export async function storageEraOnAsync(db, secretsDir) {
  if (readStorageEraState(secretsDir).state === "converted") return true;
  return storageEraMirrorAsync(db);
}

/** Write the DB mirror (better-sqlite3). The state file stays the primary trigger. */
export function writeStorageEraMirrorSync(rawDb, instanceId, { now = new Date() } = {}) {
  if (typeof instanceId !== "string" || instanceId === "") return false;
  const at = (now instanceof Date ? now : new Date()).toISOString();
  try {
    rawDb.prepare(
      `INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at, lamport_ts)
       VALUES (?, ?, ?, ?, 0)
       ON CONFLICT(key, instance_id) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    ).run(STORAGE_ERA_SETTING, instanceId, at, at);
    return true;
  } catch {
    try { console.warn("[storage-aad] era mirror write failed"); } catch { /* never throws */ }
    return false;
  }
}
