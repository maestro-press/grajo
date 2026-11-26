/**
 * The Shared Storage AAD boot pass — it NEVER seals anything.
 *
 * The conversion of `storage.shared.access_key` / `secret_key` to the bound form (`enc:v2:`,
 * AAD = setting key + normalized endpoint + SSL flag) is done by exactly ONE writer: the OWNER's
 * settings save (servers/gateway/dashboard/settings/sections/shared-storage.js). A boot-time
 * re-seal was rejected in review because it would BIND WHATEVER THE DATABASE HOLDS:
 *   - a bot that re-pointed `storage.shared.endpoint` before boot would have its address bound
 *     to the owner's real credentials;
 *   - an EXCHANGED pair (access and secret v1 blobs swapped) passes every blob-level check,
 *     because a v1 blob opens under either setting name.
 * The owner's save has a check no boot pass has: its MinIO pre-flight proves the pair works at
 * the address being saved, so an exchanged pair or a re-pointed endpoint fails at the real store
 * and nothing is written.
 *
 * WHAT THIS PASS STILL DOES (never throws; never writes a credential row):
 *   1. the era is already recorded (the HOST state file): catch the DB mirror up if it is gone,
 *      and scan — a stored credential not in the bound form rings the owner alert (deduped by
 *      the day).
 *   2. otherwise ONLY when the fleet gate passes (`gate()`, peersStorageAadCapable at level 2).
 *      A release-1 (`sa:1`) peer can READ a bound value but still WRITES `enc:v1:` on an owner
 *      save; once this instance has an era it DROPS that v1 on arrival (instance-sync.js) and
 *      keeps its own v2, so the two would diverge. The era therefore waits until every peer
 *      advertises `sa>=2`:
 *        a. neither credential row exists (an env-only install): record the era;
 *        b. both rows are ALREADY `enc:v2:` and OPEN under the current endpoint and SSL flag
 *           (the owner's save committed and the process died before the era write): record the
 *           era;
 *        c. anything else (v1, plaintext, junk, one row, a bound row that does not open) is left
 *           exactly as it is, no era is recorded, and one value-free line says the next owner
 *           save converts it. A bound row that does not open also rings the owner alert.
 *   The era is written state-file first, then the DB mirror. The mirror alone never counts.
 *
 * Nothing here logs or writes a key, plaintext, endpoint or blob.
 */
import { join } from "node:path";
import Database from "better-sqlite3";
import { resolveCrowHome, resolveInstanceDataDir } from "../../shared/crow-home.js";
import {
  STORAGE_SHARED_CREDENTIAL_KEYS, normalizeStorageEndpoint, openStorageSharedValue, parseStorageUseSSL,
} from "../../shared/storage-shared-seal.js";
import {
  readStorageEraState, storageEraMirrorSync, storageEraSecretsDirFromHome, writeStorageEraMirrorSync,
  writeStorageEraState,
} from "../../shared/storage-shared-era.js";
import { noteStorageCredentialRefusal } from "../../shared/storage-shared-alert.js";

const KEY_ENDPOINT = "storage.shared.endpoint";
const KEY_USE_SSL = "storage.shared.use_ssl";
const [KEY_ACCESS, KEY_SECRET] = STORAGE_SHARED_CREDENTIAL_KEYS;
const ALL_KEYS = [KEY_ENDPOINT, KEY_USE_SSL, KEY_ACCESS, KEY_SECRET];
const V2_PREFIX = "enc:v2:";

function readRows(db) {
  const rows = db.prepare(`SELECT key, value FROM dashboard_settings WHERE key IN (${ALL_KEYS.map(() => "?").join(",")})`).all(...ALL_KEYS);
  return new Map(rows.map((r) => [r.key, r.value]));
}

/**
 * @param {object} options
 * @param {string} [options.dbPath]
 * @param {string} [options.crowHome]
 * @param {string} [options.secretsDir]
 * @param {object|null} [options.identity]
 * @param {() => Promise<boolean>|boolean} [options.gate]  absent = closed
 * @param {string} [options.mirrorInstanceId]
 * @param {(line: string) => void} [options.log]
 * @param {Date} [options.now]
 * @returns {Promise<{state: string, alarms: number, changed: boolean}>}
 */
export async function runStorageSharedAadBoot(options = {}) {
  const out = { state: "noop", alarms: 0, changed: false };
  const log = typeof options.log === "function" ? options.log : () => {};
  const now = options.now instanceof Date ? options.now : new Date();
  const crowHome = typeof options.crowHome === "string" && options.crowHome ? options.crowHome : safeHome();
  if (!crowHome) { out.state = "no-home"; return out; }
  const secretsDir = typeof options.secretsDir === "string" && options.secretsDir
    ? options.secretsDir
    : storageEraSecretsDirFromHome(crowHome);
  const dbPath = typeof options.dbPath === "string" && options.dbPath ? options.dbPath : defaultDbPath(crowHome);

  let db = null;
  try {
    db = new Database(dbPath, { fileMustExist: true });
    db.pragma("busy_timeout = 10000");
    db.prepare("SELECT COUNT(*) AS c FROM sqlite_master").get();
  } catch {
    try { db?.close(); } catch { /* already closed */ }
    log("  storage AAD: the database could not be read; nothing recorded");
    out.state = "db-error";
    return out;
  }

  const alarm = (reason) => { noteStorageCredentialRefusal(reason); out.alarms += 1; };

  try {
    // 1. The era is recorded (the HOST state file; the mirror alone never counts as "done").
    const fileState = readStorageEraState(secretsDir).state;
    const mirrorSays = storageEraMirrorSync(db);
    if (fileState === "converted") {
      out.state = "converted-earlier";
      if (!mirrorSays && typeof options.mirrorInstanceId === "string" && options.mirrorInstanceId !== "") {
        writeStorageEraMirrorSync(db, options.mirrorInstanceId, { now });
      }
      scanAfterEra(db, alarm, log);
      return out;
    }

    // 2. The fleet gate. Closed (or absent) records nothing.
    let open = false;
    try { open = typeof options.gate === "function" ? (await options.gate()) === true : false; } catch { open = false; }
    if (!open) {
      out.state = "gate-closed";
      log("  storage AAD: a paired peer has not advertised support yet; nothing recorded");
      return out;
    }

    let rows;
    try { rows = readRows(db); } catch { rows = new Map(); } // no settings table: nothing stored

    // 2a. No credential rows (an env-only install): the era.
    const access = rows.get(KEY_ACCESS);
    const secret = rows.get(KEY_SECRET);
    if (access === undefined && secret === undefined) {
      recordEra(db, secretsDir, { rows: 0, now, options, log });
      out.state = "marked-empty";
      out.changed = true;
      return out;
    }

    // 2b. Both rows already bound and opening for THIS address: the era only.
    const bothBound = typeof access === "string" && typeof secret === "string"
      && access.startsWith(V2_PREFIX) && secret.startsWith(V2_PREFIX);
    if (bothBound) {
      const endpoint = rows.get(KEY_ENDPOINT);
      const useSSL = parseStorageUseSSL(rows.get(KEY_USE_SSL));
      let normalizable = true;
      try { normalizeStorageEndpoint(endpoint); } catch { normalizable = false; }
      const identity = options.identity || null;
      const opens = normalizable && identity
        && [[KEY_ACCESS, access], [KEY_SECRET, secret]].every(([settingKey, value]) => {
          const r = openStorageSharedValue(value, { settingKey, endpoint, useSSL, identity, era: false });
          return r.ok && r.version === "v2";
        });
      if (opens) {
        recordEra(db, secretsDir, { rows: 2, now, options, log });
        out.state = "marked-bound";
        out.changed = true;
        return out;
      }
      out.state = "bound-unopenable";
      log("  storage AAD: the stored bound credentials do not open for the stored address; no era was recorded");
      alarm("storage_credentials_unbound");
      return out;
    }

    // 2c. Everything else is left exactly as it is: the owner's save converts it.
    out.state = "awaiting-owner-save";
    log("  storage AAD: the stored credentials are not in the bound form; the next owner save of Shared Storage converts them");
    return out;
  } catch {
    log("  storage AAD: the pass stopped on an unexpected error; nothing further was recorded");
    out.state = "error";
    return out;
  } finally {
    try { db.close(); } catch { /* already closed */ }
  }
}

/** The state file first (primary proof), then the best-effort DB mirror. */
function recordEra(db, secretsDir, { rows, now, options, log }) {
  try {
    writeStorageEraState(secretsDir, { rows, now });
  } catch {
    log("  storage AAD: the era state file could not be written; the next boot records it");
    return false;
  }
  if (typeof options.mirrorInstanceId === "string" && options.mirrorInstanceId !== "") {
    writeStorageEraMirrorSync(db, options.mirrorInstanceId, { now });
  }
  return true;
}

/** After the era: a stored credential that is not bound is refused by every reader; ring the alert. */
function scanAfterEra(db, alarm, log) {
  let rows;
  try { rows = readRows(db); } catch { return; }
  for (const key of [KEY_ACCESS, KEY_SECRET]) {
    const value = rows.get(key);
    if (value === undefined) continue;
    if (typeof value !== "string" || !value.startsWith(V2_PREFIX)) {
      alarm("storage_credentials_pre_era");
      log("  storage AAD: a stored shared storage credential is not in the bound form; it is refused");
      return;
    }
  }
}

function defaultDbPath(crowHome) {
  if (process.env.CROW_DB_PATH) return process.env.CROW_DB_PATH;
  return join(resolveInstanceDataDir({ ...process.env, CROW_HOME: crowHome }), "crow.db");
}

function safeHome() {
  try { return resolveCrowHome(); } catch { return null; }
}
