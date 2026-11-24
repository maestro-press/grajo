/**
 * The shared seal pass for saved provider API keys (design §3.1–§3.5).
 *
 * One function, `sealPlaintextKeys(dbPath, …)`, does the whole job for a
 * database file — the migration 0040 calls it, the dry-run tool calls it
 * through the real migration runner, and phase 2's boot wiring will call the
 * same thing. It is deliberately SYNCHRONOUS in its database work (one
 * better-sqlite3 handle, one transaction) and async only for the online
 * `.backup()` the pre-seal copy needs.
 *
 * What a pass does, in order:
 *
 *   1. open the database and make sure it holds a `providers` table (absent is a
 *      DEFERRAL, not a failure: the store may not exist yet);
 *   2. refuse when the database does not belong to `crowHome` (see
 *      dbBelongsToHome) — sealing with one instance's key file a database that
 *      belongs to another instance is how a keychain gets orphaned;
 *   3. read the key file's state and classify every `providers.api_key` cell by
 *      SHAPE (servers/shared/provider-key-shape.js): none, plain, envelope,
 *      malformed;
 *   4. decide the key (§3.2 below): use the one on disk; mint one ONLY when that
 *      cannot orphan anything; otherwise REFUSE and alert `keychain-key-missing`;
 *   5. take a verified pre-seal backup (§3.5) before anything is written;
 *   6. rewrite the cloud-door consent entries that named a plaintext key into the
 *      sealed-key form (one transaction, with 7);
 *   7. seal every plaintext cell and rewrite its row — `updated_at` and
 *      `lamport_ts` untouched, because this is not a user edit;
 *   8. prove it, inside the same transaction: re-read each written cell, open it
 *      and compare it to the plaintext byte for byte, then commit;
 *   8b. scan the live crow.db AND its -wal for the plaintexts (an EARLIER write's
 *      freed page keeps its bytes: secure_delete only covers this connection's
 *      own writes). A hit is `secure_delete = ON; VACUUM` plus a truncated WAL
 *      checkpoint — but ONLY in the one pass that runs before the HTTP listeners
 *      open (`allowVacuum: true`, which the gateway's own boot pass and nothing
 *      else passes). Every other pass — migration 0040's post-settle child, the
 *      post-listen boot pass, the hourly tick — persists the residue marker and
 *      never rebuilds the file. The boot pass also demands free space first (on
 *      the database's own filesystem and, when SQLite's temp dir is elsewhere, on
 *      that one too), rings ONE bell when there is too little, and spends AT MOST
 *      ONE rebuild per pending period: a re-scan that still finds a value means it
 *      lives in a LIVE cell elsewhere (a profile blob, a memory, a chat), which no
 *      rebuild can remove — so the pass says so in one fixed count-only line,
 *      clears the marker and stops rescanning; a busy VACUUM or checkpoint just
 *      leaves the marker for the next boot;
 *   9. prune old backups (retention, §3.5) after a verified pass.
 *
 * §3.2, the key-state table (what a missing key means here):
 *
 *   key ok                  → seal with it.
 *   key missing, nothing to seal, no envelope stored
 *                           → nothing to do (no mint, no alert).
 *   key missing, plaintext rows, NO envelope and NO crow_keychain rows
 *                           → mint (mintIfSafe) and seal: a first key, nothing lost.
 *   key missing, plaintext rows, an envelope stored OR crow_keychain rows exist
 *                           → REFUSE: minting would orphan the sealed values.
 *   key invalid (unreadable) → REFUSE: a damaged key file may still be restorable.
 *   any refusal, with something to seal
 *                           → alert `keychain-key-missing`, body = KEY_SAVE_REFUSED.
 *
 * Nothing in this module — no log line, no alert, no return value, no thrown
 * error — ever carries a key value, an envelope, a key id or a driver message.
 * Deferral reasons are fixed tokens; counts are numbers and one backup path.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import {
  chmodSync, closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, renameSync,
  statSync, statfsSync, unlinkSync, writeFileSync,
} from "node:fs";
import { join, resolve, dirname } from "node:path";
import Database from "better-sqlite3";
import { writeAlertFile } from "../../shared/alert-spool.js";
import { resolveCrowHome, resolveInstanceDataDir, isWithin } from "../../shared/crow-home.js";
import {
  CONSENT_FP_PREFIX,
  parseStoredKey,
  providerKeyFp,
  sealedConsentFingerprint,
} from "../../shared/provider-key-shape.js";
import { KEY_SAVE_REFUSED } from "../addon-secrets-seal.js";
import { createKeychainKey, keychainKeyState, loadKeychainKey } from "./key.js";
import { open as openProviderKey, seal as sealProviderKey } from "./provider-key-box.js";

/** The alert codes this pass raises (§3.4). */
export const SWEEP_ALERTS = Object.freeze({
  KEY_MISSING: "keychain-key-missing",
  BACKUP_FAILED: "provider-keys-backup-failed",
  HOME_MISMATCH: "provider-keys-home-mismatch",
  VERIFY_FAILED: "provider-keys-verify-failed",
  DB_ERROR: "provider-keys-db-error",
  /** Residue found, the boot pass could not rebuild the file: too little disk. */
  VACUUM_SKIPPED: "provider-keys-vacuum-skipped",
});

/** `<CROW_HOME>/secrets/backups/provider-keys` — 0700, one verified copy per pass. */
export const BACKUP_SUBDIR = Object.freeze(["secrets", "backups", "provider-keys"]);
/**
 * Retention (design §3.5, review round 1 M2/L4): the newest BACKUP_KEEP copies
 * plus the FIRST pre-seal copy — the operator's rollback point — and nothing
 * else. A bot that writes one plaintext row an hour used to cost a full crow.db
 * copy per pass for 14 days; a hard cap cannot fill a disk.
 */
export const BACKUP_KEEP = 2;
/**
 * A pass that finds a verified copy younger than this takes NO new one: the
 * newest copy already holds the pre-seal state of the operator's real keys, and
 * a bot-written plaintext row needs no rollback copy of its own (round 1, M2).
 */
export const BACKUP_FRESH_MS = 24 * 60 * 60 * 1000;
/** Free space demanded before a copy is attempted, as a multiple of the database size. */
export const FREE_SPACE_FACTOR = 1.2;
/**
 * Free space demanded before a VACUUM, as a multiple of (crow.db + its -wal): the
 * rebuild writes a complete second copy of the file before it replaces the old
 * one, and in WAL mode it also writes roughly one database's worth of WAL beside
 * crow.db, so a disk too full for that is not risked. (A rebuild that does run
 * out of space is not a corrupt file — SQLite rolls the statement back — but the
 * residue would still be there for the next boot, and a VACUUM that fails on a
 * serving box is churn for nothing.)
 */
export const VACUUM_FREE_SPACE_FACTOR = 1.1;
/**
 * Free space demanded on the ONE filesystem that carries both copies, as a
 * multiple of (crow.db + its -wal): SQLite's temp dir is on the same device as the
 * database, so the rebuild's copy and the new WAL land together there.
 */
export const VACUUM_SAME_DEVICE_FACTOR = 2.1;
/**
 * The residue marker (design §3.5, round 1 H3): `<CROW_HOME>/secrets/provider-keys-state.json`,
 * 0600, NEVER in crow.db (a bot can write crow.db). "pending" means a pass left
 * plaintext bytes in freed space it could not reclaim yet (a pass with no VACUUM
 * to spend, a low disk, or a busy VACUUM/WAL checkpoint), so every later pass —
 * the hourly one included — must scan again even when it has no plaintext of its
 * own. Only the boot-before-listen pass may finish the job (VACUUM).
 */
export const RESIDUE_STATE_FILENAME = "provider-keys-state.json";
/**
 * The fingerprint form for a sealed key (`HMAC(salt, "fp1:" + fp16)`), re-exported
 * from the pure shape module so readers outside the gateway can use it without
 * loading the keychain. Phase 2's cloud-consent.js adopts it.
 */
export { CONSENT_FP_PREFIX, sealedConsentFingerprint };

const CONSENT_KEY = "llm_cloud_door_rows";
const CONSENT_SALT_KEY = "llm_cloud_consent_salt";

/**
 * One bell. The title is always writeAlertFile's own default ("Crow alert"); a
 * body is carried only by the refusals that have a fixed sentence for the
 * operator — the vacuum-skipped alert has none yet, so it goes without.
 */
function raiseAlert(code, body = null) {
  try {
    writeAlertFile({ code, body });
  } catch {
    // writeAlertFile never throws; this is belt and braces, and an alerting
    // failure must never become the pass's failure.
  }
}

function deferredResult(reason, counts) {
  return { deferred: true, reason, counts };
}

/** sha256 over a stored cell's text (the backup's per-row proof). Never logged. */
function valueDigest(value) {
  return createHash("sha256").update(String(value ?? ""), "utf8").digest("hex");
}

/** A filename-safe stamp from the pass's clock. */
function backupStamp(now = new Date()) {
  const d = now instanceof Date ? now : new Date(now);
  return (Number.isNaN(d.getTime()) ? new Date() : d).toISOString().replace(/[:.]/g, "-");
}

/** The pass's clock in milliseconds (the `now` option is a Date or a factory). */
function clockMs(now) {
  const value = now instanceof Date ? now : (typeof now === "function" ? now() : new Date());
  const ms = value instanceof Date ? value.getTime() : Number(value);
  return Number.isFinite(ms) ? ms : Date.now();
}

/** This home's backup directory. */
export function backupDirFor(crowHome) {
  return join(crowHome, ...BACKUP_SUBDIR);
}

// ─── cloud-door consent fingerprints (design §3.1 step 8) ───────────────────

/**
 * The fingerprint cloud-consent.js stores TODAY, over a PLAINTEXT key:
 * `HMAC-SHA256(salt, trimmed key)` hex, first 16. Kept here (not re-imported)
 * so the rewrite can recognise exactly what it is converting, and so nothing in
 * this pass depends on cloud-consent.js's keyFingerprint, which phase 2 changes.
 */
export function legacyConsentFingerprint(salt, plaintext) {
  const trimmed = typeof plaintext === "string" ? plaintext.trim() : "";
  return createHmac("sha256", Buffer.from(salt, "hex")).update(trimmed).digest("hex").slice(0, 16);
}

/**
 * The fingerprint for a SEALED key, and the helper phase 2's cloud-consent.js
 * adopts: `HMAC-SHA256(salt, "fp1:" + fp16)` hex, first 16 (defined in the pure
 * shape module, re-exported above).
 */

/** Constant-time-ish hex equality for fingerprints (equal length only). */
function sameHex(a, b) {
  return typeof a === "string" && typeof b === "string" && a.length === b.length && a === b;
}

function tableExists(db, name) {
  try {
    return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
  } catch {
    return false;
  }
}

/**
 * Rewrite the consent entries that named a plaintext key. Returns how many were
 * rewritten. A row whose entry does not fingerprint the plaintext it still holds
 * is NOT touched: consent is only ever converted for the exact key it was
 * granted for, and an entry for some other key stays as the (now stale, hence
 * refusing) record it is.
 *
 * @param {import("better-sqlite3").Database} db
 * @param {Map<string, string>} plaintextById provider id → the plaintext it held
 * @param {{rows: Record<string, object>}} consent a mutable copy of the consent map
 * @param {string} salt
 * @returns {number}
 */
function rewriteConsentInMap(consent, plaintextById, salt) {
  let rewritten = 0;
  for (const [rowId, entry] of Object.entries(consent)) {
    const plaintext = plaintextById.get(rowId);
    if (typeof plaintext !== "string" || plaintext === "") continue;
    if (!entry || typeof entry !== "object" || typeof entry.keyFp !== "string") continue;
    const fp16 = providerKeyFp(plaintext);
    if (!fp16) continue;
    if (!sameHex(entry.keyFp, legacyConsentFingerprint(salt, plaintext))) continue;
    entry.keyFp = sealedConsentFingerprint(salt, fp16);
    rewritten += 1;
  }
  return rewritten;
}

function readConsent(db) {
  try {
    if (!tableExists(db, "dashboard_settings")) return null;
    const row = db.prepare("SELECT value FROM dashboard_settings WHERE key = ?").get(CONSENT_KEY);
    if (!row || typeof row.value !== "string" || row.value === "") return null;
    const parsed = JSON.parse(row.value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const saltRow = db.prepare("SELECT value FROM dashboard_settings WHERE key = ?").get(CONSENT_SALT_KEY);
    const salt = typeof saltRow?.value === "string" && /^[0-9a-f]{64}$/.test(saltRow.value) ? saltRow.value : null;
    if (!salt) return null;
    return { consent: parsed, salt };
  } catch {
    return null;
  }
}

// ─── the pre-seal backup (design §3.5) ─────────────────────────────────────

function ensureBackupDir(dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
}

/** Free space for a copy of `size` bytes must be >= FREE_SPACE_FACTOR × size. */
function hasFreeSpace(dir, size) {
  const st = statfsSync(dir);
  const available = Number(st.bavail) * Number(st.bsize);
  return Number.isFinite(available) && available >= size * FREE_SPACE_FACTOR;
}

/** Verify a fresh copy: quick_check, providers count, and a digest per row. */
function verifyCopy(copyPath, { providersCount, rowDigests }) {
  let copy = null;
  try {
    copy = new Database(copyPath, { fileMustExist: true });
    const check = copy.pragma("quick_check");
    const verdict = Array.isArray(check) ? String(check[0]?.quick_check ?? check[0]) : String(check);
    if (verdict !== "ok") return { ok: false };
    if (!tableExists(copy, "providers")) return { ok: false };
    const count = Number(copy.prepare("SELECT COUNT(*) AS c FROM providers").get()?.c ?? -1);
    if (count !== providersCount) return { ok: false };
    const read = copy.prepare("SELECT api_key FROM providers WHERE id = ?");
    for (const { id, digest } of rowDigests) {
      const row = read.get(id);
      if (!row || valueDigest(row.api_key) !== digest) return { ok: false };
    }
    // Fold any WAL into the copy so one self-contained file can be renamed in.
    try { copy.pragma("wal_checkpoint(TRUNCATE)"); } catch { /* not a WAL copy */ }
    return { ok: true };
  } catch {
    return { ok: false };
  } finally {
    if (copy) { try { copy.close(); } catch { /* already closed */ } }
  }
}

/** The mtime of the newest copy on disk (null when there is none). */
function newestBackupMs(crowHome) {
  const dir = backupDirFor(crowHome);
  let names;
  try { names = readdirSync(dir); } catch { return null; }
  let newest = null;
  for (const name of names) {
    if (!/^crow-pre-(?:seal|unseal)-.+\.db$/.test(name)) continue;
    try {
      const st = statSync(join(dir, name));
      if (newest === null || st.mtimeMs > newest) newest = st.mtimeMs;
    } catch { /* vanished */ }
  }
  return newest;
}

/**
 * Take one verified pre-write copy into `<crowHome>/secrets/backups/provider-keys`.
 * Returns `{ok:true, path:null}` when a fresh verified copy already exists (and
 * none is taken), `{ok:true, path}` for a new copy, or `{ok:false, reason}`; the
 * caller alerts. A copy that FAILS its own verification is `backup-failed`, not a
 * seal-verify failure: nothing was sealed yet.
 */
async function makeVerifiedBackup(db, dbPath, crowHome, { now, prefix, providersCount, rowDigests, nowMs }) {
  const newest = newestBackupMs(crowHome);
  if (newest !== null && Number.isFinite(nowMs) && nowMs - newest <= BACKUP_FRESH_MS) {
    return { ok: true, path: null, reused: true };
  }
  const dir = backupDirFor(crowHome);
  try {
    ensureBackupDir(dir);
  } catch {
    return { ok: false, reason: "backup-failed", step: "backup-dir" };
  }
  let size;
  try {
    size = statSync(dbPath).size;
  } catch {
    return { ok: false, reason: "backup-failed", step: "backup-stat" };
  }
  try {
    if (!hasFreeSpace(dir, size)) return { ok: false, reason: "backup-failed", step: "low-space" };
  } catch {
    return { ok: false, reason: "backup-failed", step: "low-space" };
  }

  const name = `${prefix}-${backupStamp(now)}.db`;
  const finalPath = join(dir, name);
  const tmpPath = join(dir, `.${name}.${process.pid}.tmp`);
  try {
    // 0600 FROM CREATION: a crow.db copy holds every saved key.
    closeSync(openSync(tmpPath, "wx", 0o600));
    await db.backup(tmpPath);
    chmodSync(tmpPath, 0o600);
  } catch {
    try { unlinkSync(tmpPath); } catch { /* nothing to remove */ }
    return { ok: false, reason: "backup-failed", step: "backup-write" };
  }
  const verdict = verifyCopy(tmpPath, { providersCount, rowDigests });
  if (!verdict.ok) {
    try { unlinkSync(tmpPath); } catch { /* nothing to remove */ }
    return { ok: false, reason: "backup-failed", step: "copy-check" };
  }
  for (const suffix of ["-wal", "-shm"]) {
    try { unlinkSync(tmpPath + suffix); } catch { /* no sidecar */ }
  }
  try {
    renameSync(tmpPath, finalPath);
  } catch {
    try { unlinkSync(tmpPath); } catch { /* nothing to remove */ }
    return { ok: false, reason: "backup-failed", step: "backup-rename" };
  }
  return { ok: true, path: finalPath };
}

/**
 * Retention (§3.5, round 1 M2/L4): keep the newest BACKUP_KEEP copies plus the
 * FIRST pre-seal copy (the oldest, and the only one that predates any seal), and
 * delete every other copy — a hard cap, so a bot that writes one plaintext row an
 * hour cannot fill the disk with one full copy per pass.
 *
 * Called only after a pass that verified everything it wrote AND read every
 * envelope on the instance: with `unreadable > 0` nothing is deleted at all (§3.5
 * — the copies are the only remaining way back).
 */
function pruneBackups(crowHome, { unreadable = 0 } = {}) {
  if (unreadable > 0) return 0;
  const dir = backupDirFor(crowHome);
  let names;
  try { names = readdirSync(dir); } catch { return 0; }
  const copies = [];
  for (const name of names) {
    if (!/^crow-pre-(?:seal|unseal)-.+\.db$/.test(name)) continue;
    try {
      const st = statSync(join(dir, name));
      copies.push({ name, mtimeMs: st.mtimeMs });
    } catch { /* vanished */ }
  }
  copies.sort((a, b) => b.mtimeMs - a.mtimeMs);
  const keep = new Set(copies.slice(0, BACKUP_KEEP).map((c) => c.name));
  const firstSeal = copies.filter((c) => c.name.startsWith("crow-pre-seal-")).at(-1);
  if (firstSeal) keep.add(firstSeal.name);
  let removed = 0;
  for (const copy of copies) {
    if (keep.has(copy.name)) continue;
    try { unlinkSync(join(dir, copy.name)); removed += 1; } catch { /* kept */ }
  }
  return removed;
}

// ─── freed-space residue (design §3.5; review round 1 H3, M3) ──────────────

/**
 * A seal proof that did not round-trip. Distinct from every other transaction
 * failure (a lost write race, SQLITE_BUSY) so the pass can report the right code:
 * this one is `seal-verify-failed`, anything else is `db-error`.
 */
class SealVerifyError extends Error {
  constructor() {
    super("provider-key seal did not verify");
    this.code = "PROVIDER_KEY_VERIFY_MISMATCH";
  }
}
const isVerifyMismatch = (err) => err?.code === "PROVIDER_KEY_VERIFY_MISMATCH";

/** One streaming pass, in 1 MiB chunks, per needle. Never logged, never returned. */
const RESIDUE_CHUNK_BYTES = 1 << 20;
/** A needle shorter than this is not searched: it would match almost any file. */
const RESIDUE_MIN_NEEDLE = 4;

/**
 * Set once a pass that MAY rebuild the file has scanned it in this process. The
 * post-listen boot pass runs minutes later on the same file; a second full scan of
 * a large crow.db on the event loop buys nothing the marker does not already say
 * (review round 2, NIT). Never cleared: a process boots once.
 */
let residueScannedThisBoot = false;

/** Test-only: called once per whole-file residue scan (the reads this flag bounds). */
let _scanProbeForTest = null;
export function _setResidueScanProbeForTest(fn) {
  _scanProbeForTest = typeof fn === "function" ? fn : null;
}

/** Test-only: forget that this process already scanned (a test's next "boot"). */
export function _resetResidueBootScanForTest() {
  residueScannedThisBoot = false;
}

/** `<CROW_HOME>/secrets/provider-keys-state.json` — the residue marker (§3.5). */
export function residueStatePath(crowHome) {
  return join(crowHome, "secrets", RESIDUE_STATE_FILENAME);
}

/**
 * The marker's document: `{residue: "pending", at, vacuumAlerted?}`. Absent or
 * unreadable reads as `{}` — no residue this pass knows of.
 */
function readResidueState(crowHome) {
  try {
    const doc = JSON.parse(existsSync(residueStatePath(crowHome)) ? readFileSync(residueStatePath(crowHome), "utf8") : "{}");
    return doc && typeof doc === "object" && !Array.isArray(doc) ? doc : {};
  } catch {
    return {};
  }
}

/** Is a pass still looking for freed-space residue? (Absent/unreadable = no.) */
function residuePending(crowHome) {
  return readResidueState(crowHome).residue === "pending";
}

/**
 * Set or clear the residue marker. 0600, atomic (temp + rename, the temp created
 * EXCLUSIVELY with a random suffix so two writers in one directory can never
 * adopt each other's half-written file — review round 2, NIT). Never in crow.db:
 * a contained bot can write that file, and this marker must be the host's.
 *
 * `vacuumAlerted` records that this pending period already rang its one
 * `provider-keys-vacuum-skipped` bell: a pass that meets the same unresolved
 * residue (an hourly tick, every boot until the disk frees up) must not spool
 * another file each time. The flag lives and dies with the marker.
 * Best effort — a missing marker only means a later pass skips a rescan.
 */
function setResiduePending(crowHome, pending, { vacuumAlerted = false } = {}) {
  const path = residueStatePath(crowHome);
  try {
    if (!pending) {
      try { unlinkSync(path); } catch { /* already gone */ }
      return;
    }
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
    const doc = { residue: "pending", at: new Date().toISOString() };
    if (vacuumAlerted) doc.vacuumAlerted = true;
    const fd = openSync(tmp, "wx", 0o600);
    try {
      writeFileSync(fd, JSON.stringify(doc) + "\n");
    } finally {
      closeSync(fd);
    }
    chmodSync(tmp, 0o600);
    renameSync(tmp, path);
  } catch { /* best effort */ }
}

/** Keep the marker pending WITHOUT forgetting whether this period already alerted. */
function keepResiduePending(crowHome) {
  setResiduePending(crowHome, true, { vacuumAlerted: readResidueState(crowHome).vacuumAlerted === true });
}

/**
 * WHICH of `needles` does `filePath` hold? Indices into `needles`, from one
 * streaming read: a 1 MiB window with an overlap of (longest needle - 1) bytes, so
 * a value straddling a chunk boundary is still found. Empty for an absent file (no
 * -wal yet); an unreadable file answers EVERY index — "cannot prove clean" is
 * treated as residue.
 */
function fileMatchesOf(filePath, needles, maxLen) {
  const hits = new Set();
  let fd;
  try {
    fd = openSync(filePath, "r");
  } catch (err) {
    if (err?.code !== "ENOENT") for (let i = 0; i < needles.length; i += 1) hits.add(i);
    return hits;
  }
  try {
    const buffer = Buffer.allocUnsafe(RESIDUE_CHUNK_BYTES + maxLen);
    let carry = 0;
    for (;;) {
      const read = readSync(fd, buffer, carry, RESIDUE_CHUNK_BYTES, null);
      if (read <= 0) return hits;
      const length = carry + read;
      const window = buffer.subarray(0, length);
      for (let i = 0; i < needles.length; i += 1) {
        if (!hits.has(i) && window.indexOf(needles[i]) !== -1) hits.add(i);
      }
      if (hits.size === needles.length) return hits;
      carry = Math.min(maxLen - 1, length);
      if (carry > 0) buffer.copy(buffer, 0, length - carry, length);
    }
  } catch {
    for (let i = 0; i < needles.length; i += 1) hits.add(i);
    return hits;
  } finally {
    try { closeSync(fd); } catch { /* already closed */ }
  }
}

/**
 * The live database file and its WAL — the two the plaintext pages can be in — as
 * the indices of `needles` still found. One scan, so the count a refusal reports
 * costs no extra reads.
 */
function databaseMatchesOf(dbPath, needles, maxLen) {
  if (_scanProbeForTest) _scanProbeForTest();
  const hits = fileMatchesOf(dbPath, needles, maxLen);
  if (hits.size === needles.length) return hits;
  for (const i of fileMatchesOf(`${dbPath}-wal`, needles, maxLen)) hits.add(i);
  return hits;
}

/**
 * `PRAGMA wal_checkpoint(TRUNCATE)`, with the returned row's `busy` flag read
 * (review round 1, M3 — the old call ignored it). Up to three tries with a short
 * wait between them; `true` means the WAL folded and was truncated (or there is
 * no WAL to fold), `false` means it is still busy.
 */
function checkpointTruncate(db) {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    let rows;
    try {
      rows = db.pragma("wal_checkpoint(TRUNCATE)");
    } catch {
      return false;
    }
    const row = Array.isArray(rows) ? rows[0] : null;
    // No row: not a WAL database — nothing to fold, nothing to truncate.
    if (!row || !Number(row.busy)) return true;
    sleepMs(20 * (attempt + 1));
  }
  return false;
}

/** A short synchronous wait between checkpoint retries (never a spin). */
function sleepMs(ms) {
  try { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); } catch { /* no wait available */ }
}

/**
 * Test-only: replace the free-space probe (bytes available on a directory's
 * filesystem). The real one is fs.statfsSync; a low-disk build is not something
 * a test can make on a real disk of its own.
 */
let _freeSpaceForTest = null;
export function _setFreeSpaceForTest(fn) {
  _freeSpaceForTest = typeof fn === "function" ? fn : null;
}

/**
 * Test-only: replace the device probe (which filesystem a path lives on). A test
 * cannot move its scratch temp dir onto another filesystem, and the VACUUM demand
 * depends on whether the database and SQLite's temp dir share one.
 */
let _deviceForTest = null;
export function _setDeviceForTest(fn) {
  _deviceForTest = typeof fn === "function" ? fn : null;
}

/** Bytes available on `dir`'s filesystem, or null when that cannot be known. */
function availableBytes(dir) {
  if (_freeSpaceForTest) {
    const n = Number(_freeSpaceForTest(dir));
    return Number.isFinite(n) ? n : null;
  }
  try {
    const st = statfsSync(dir);
    const n = Number(st.bavail) * Number(st.bsize);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

/**
 * SQLite's temp directory on Linux (os_unix.c `unixTempFile`): SQLITE_TMPDIR, then
 * TMPDIR, then /var/tmp, /usr/tmp, /tmp — the first that exists. VACUUM builds its
 * copy of the database HERE, so its filesystem has to hold it too.
 */
export function sqliteVacuumTempDir(env = process.env) {
  for (const dir of [env.SQLITE_TMPDIR, env.TMPDIR, "/var/tmp", "/usr/tmp", "/tmp"]) {
    if (typeof dir !== "string" || dir === "") continue;
    try { if (statSync(dir).isDirectory()) return dir; } catch { /* not there: the next one */ }
  }
  return null;
}

/** The device a path's filesystem lives on, or null when it cannot be known. */
function deviceOf(path) {
  if (_deviceForTest) {
    const dev = Number(_deviceForTest(path));
    return Number.isFinite(dev) ? dev : null;
  }
  try { return statSync(path).dev; } catch { return null; }
}

/**
 * Is there room to rebuild the database? In WAL mode a VACUUM writes the copy into
 * SQLite's temp dir AND writes roughly one database's worth of WAL beside crow.db,
 * so the demand depends on where that temp dir is:
 *
 *   - same device as the database: ONE filesystem carries both copies, so it needs
 *     VACUUM_SAME_DEVICE_FACTOR × (crow.db + its -wal);
 *   - another device: the database's own needs VACUUM_FREE_SPACE_FACTOR ×
 *     (crow.db + its -wal) and the temp dir VACUUM_FREE_SPACE_FACTOR × crow.db.
 *
 * Unknown is `false`: a skipped rebuild costs only another pending period, and a
 * rebuild that runs out of space rolls back cleanly (SQLite undoes the whole
 * VACUUM — it does not leave a corrupt file), but it would churn a serving box for
 * nothing and the residue would still wait for the next boot.
 */
function hasVacuumSpace(dbPath) {
  let dbSize = 0;
  let walSize = 0;
  try { dbSize = statSync(dbPath).size; } catch { return false; }
  try { walSize = statSync(`${dbPath}-wal`).size; } catch { /* no -wal: nothing to count */ }
  const total = dbSize + walSize;
  const free = availableBytes(dirname(resolve(dbPath)));
  if (free === null) return false;
  const tempDir = sqliteVacuumTempDir();
  const dbDev = deviceOf(dbPath);
  const tempDev = tempDir === null ? null : deviceOf(tempDir);
  // An unknown temp dir or device is judged as the SAME filesystem: that is the
  // demand that covers both copies landing together.
  if (tempDir === null || dbDev === null || tempDev === null || tempDev === dbDev) {
    return free >= total * VACUUM_SAME_DEVICE_FACTOR;
  }
  const tempFree = availableBytes(tempDir);
  if (tempFree === null) return false;
  return free >= total * VACUUM_FREE_SPACE_FACTOR && tempFree >= dbSize * VACUUM_FREE_SPACE_FACTOR;
}

/**
 * Get the sealed plaintexts out of FREED space (review round 1 H3; round 2: the
 * VACUUM is the boot-before-listen pass's alone).
 *
 * `secure_delete` only covers the writes THIS connection makes: a plaintext an
 * EARLIER build or connection wrote and over-wrote survives in a free page, so a
 * byte scan of crow.db (and its -wal, which held the pre-seal pages) can still
 * find it after the seal.
 *
 * A hit is only REPAIRED here when `allowVacuum` is set — a `secure_delete = ON;
 * VACUUM` plus a fold + truncate of the WAL, which rewrites the whole file while
 * the gateway is serving and so belongs to the one pass that runs before the
 * listeners open. Every other pass (the post-listen boot pass, the hourly tick,
 * migration 0040's post-settle child) persists the marker and leaves the file
 * alone; a low disk or a busy VACUUM/checkpoint does the same in the boot pass.
 * The marker is cleared ONLY once a scan of the files comes back clean — never
 * "by construction" — and the low-disk skip rings one bell per pending period,
 * because the residue it could not clear is one condition, not one per pass.
 *
 * ONE rebuild per pending period (review round 2, M1). VACUUM removes FREED pages,
 * never a live cell: a key whose plaintext also sits in a profile blob, a memory or
 * a chat cannot be wiped from here, so when the re-scan after a successful rebuild
 * still finds it the pass concludes "live copies elsewhere", says so in one fixed
 * count-only line, clears the marker and stops looking. Without that bound every
 * boot would rebuild the whole file and every hourly pass would re-scan the whole
 * database on the event loop for an answer nothing can change.
 *
 * The needles are the values this pass sealed, plus — on a RETRY, where those
 * buffers are gone — every envelope opened with the key. Values are never logged.
 *
 * @returns {boolean} true when the files are verified clean (nothing to look for,
 *   nothing found, or the wipe ran and only live copies remain)
 */
function clearFreedSpace({
  db, dbPath, crowHome, plaintexts, envelopeRows, key, allowVacuum, skipScan = false, log = () => {},
}) {
  // A pass that MAY rebuild the file has scanned these files in this process: the
  // post-listen pass minutes later has nothing new to read (review round 2, NIT).
  if (allowVacuum === true) residueScannedThisBoot = true;
  if (skipScan) return !residuePending(crowHome);
  const values = plaintexts.filter((v) => typeof v === "string" && v.length >= RESIDUE_MIN_NEEDLE);
  if (residuePending(crowHome) && key) {
    for (const { id, stored } of envelopeRows) {
      const opened = openProviderKey({ slotId: id, stored, key });
      if (typeof opened === "string" && opened.length >= RESIDUE_MIN_NEEDLE) values.push(opened);
    }
  }
  const unique = [...new Set(values)];
  if (unique.length === 0) {
    // Nothing to look for. With the marker set (a retry that cannot open a single
    // envelope: no key here) it stays pending for the pass that can.
    return !residuePending(crowHome);
  }
  const needles = unique.map((value) => Buffer.from(value, "utf8"));
  const maxLen = needles.reduce((n, b) => Math.max(n, b.length), 0);
  if (databaseMatchesOf(dbPath, needles, maxLen).size === 0) {
    setResiduePending(crowHome, false);
    return true;
  }
  // A hit. Only the boot-before-listen pass may rebuild the file; every other
  // pass records the residue so the next boot's pass knows where to look.
  if (allowVacuum !== true) {
    keepResiduePending(crowHome);
    return false;
  }
  // The rebuild needs room for its copy, on the database's filesystem and on
  // SQLite's temp dir when that is a different one.
  if (!hasVacuumSpace(dbPath)) {
    const already = readResidueState(crowHome).vacuumAlerted === true;
    setResiduePending(crowHome, true, { vacuumAlerted: true });
    if (!already) raiseAlert(SWEEP_ALERTS.VACUUM_SKIPPED);
    return false;
  }
  // A hit: rebuild the file with freed pages zeroed, then fold the WAL back in.
  try {
    db.pragma("secure_delete = ON");
    db.exec("VACUUM");
  } catch {
    keepResiduePending(crowHome);
    return false;
  }
  if (!checkpointTruncate(db)) {
    keepResiduePending(crowHome);
    return false;
  }
  // The rebuild ran. A needle that survives it lives in a LIVE cell — VACUUM cannot
  // remove one — so this is where the freed-space job ends (review round 2, M1):
  // the copy is gone, what remains is somebody's data, and rebuilding again would
  // answer the same way on every boot. One fixed, count-only line; no key id, no
  // value, no location.
  const still = databaseMatchesOf(dbPath, needles, maxLen);
  if (still.size > 0) {
    setResiduePending(crowHome, false);
    log(`  provider keys: ${still.size} key(s) also stored elsewhere in the database; free-space wipe done`);
    return true;
  }
  setResiduePending(crowHome, false);
  return true;
}

// ─── the home check ────────────────────────────────────────────────────────

/**
 * Does `dbPath` belong to the instance whose home is `crowHome`? True when the
 * process env names the same home AND the database sits inside that instance's
 * data dir (servers/shared/crow-home.js's own resolver, so a co-hosted gateway
 * is judged exactly as it boots). A different home in the env is a mismatch even
 * when the paths would agree: the key file would be read from a home the
 * process is not running as.
 */
export function dbBelongsToHome(dbPath, crowHome, env = process.env) {
  if (typeof dbPath !== "string" || dbPath === "" || typeof crowHome !== "string" || crowHome === "") return false;
  if (env.CROW_HOME && resolve(env.CROW_HOME) !== resolve(crowHome)) return false;
  let dataDir;
  try {
    dataDir = resolveInstanceDataDir({ ...env, CROW_HOME: crowHome });
  } catch {
    return false;
  }
  return isWithin(dbPath, dataDir) || isWithin(dbPath, crowHome);
}

// ─── the pass ──────────────────────────────────────────────────────────────

/**
 * Seal every plaintext `providers.api_key` in `dbPath`. Never throws: every
 * failure is `{deferred: true, reason}` with fixed-token reasons, so a migration
 * retries and an operator reads a code, never a driver message.
 *
 * @param {string} dbPath
 * @param {{crowHome?: string, now?: (() => Date)|Date, mintIfSafe?: boolean,
 *          allowVacuum?: boolean, log?: (line: string) => void}} [options]
 *   `allowVacuum` (default false) lets this pass REBUILD crow.db to get plaintext
 *   bytes out of freed space. Only the gateway's boot pass that runs before the
 *   HTTP listeners open passes true; every later pass (the post-listen boot
 *   pass, the hourly tick, migration 0040's post-settle child) leaves the
 *   residue marker for the next boot instead.
 * @returns {Promise<{deferred: boolean, reason?: string,
 *            counts: {sealed:number, alreadySealed:number, keyless:number,
 *                     unreadable:number, consentRewritten:number, backup:string|null,
 *                     residue?: "pending"}}>}
 */
export async function sealPlaintextKeys(dbPath, options = {}) {
  const counts = { sealed: 0, alreadySealed: 0, keyless: 0, unreadable: 0, consentRewritten: 0, backup: null };
  const log = typeof options.log === "function" ? options.log : () => {};
  try {
    return await sealPass(dbPath, options, counts, log);
  } catch {
    // No driver message ever reaches the operator, the spool or the return.
    raiseAlert(SWEEP_ALERTS.DB_ERROR);
    log("  provider keys: the pass stopped on a database error");
    return deferredResult("db-error", counts);
  }
}

async function sealPass(dbPath, options, counts, log) {
  const crowHome = typeof options.crowHome === "string" && options.crowHome ? options.crowHome : resolveCrowHome();
  const now = options.now ?? (() => new Date());
  const mintIfSafe = options.mintIfSafe !== false;
  const allowVacuum = options.allowVacuum === true;
  // A residue retry with no plaintext of its own re-reads the whole database. The
  // boot-before-listen pass read it already in this process, so the pass that runs
  // minutes later (the post-listen one) leaves that read to it — the marker and the
  // next boot are unaffected (review round 2, NIT). A pass that SEALED something
  // still scans: those bytes are the ones that just moved.
  const skipResidueScan = allowVacuum !== true && residueScannedThisBoot;

  // 1. The database itself.
  let db;
  try {
    db = new Database(dbPath, { fileMustExist: true });
    db.pragma("busy_timeout = 10000");
    // Touch a real page before anything else: a file that is not a database
    // opens (better-sqlite3 only checks existence) and fails its first read.
    db.prepare("SELECT COUNT(*) AS c FROM sqlite_master").get();
  } catch {
    try { db?.close(); } catch { /* already closed */ }
    raiseAlert(SWEEP_ALERTS.DB_ERROR);
    log("  provider keys: the database could not be read");
    return deferredResult("db-error", counts);
  }

  try {
    if (!tableExists(db, "providers")) {
      log("  providers: absent, nothing to seal");
      return deferredResult("providers-absent", counts);
    }

    // 2. The home the key file belongs to must be the database's home.
    if (!dbBelongsToHome(dbPath, crowHome)) {
      raiseAlert(SWEEP_ALERTS.HOME_MISMATCH);
      log("  provider keys: the database does not belong to this Crow home");
      return deferredResult("home-mismatch", counts);
    }

    // 3. Classify every stored cell by SHAPE. Values never leave this function.
    const rows = db.prepare("SELECT id, api_key FROM providers ORDER BY id").all();
    const plainRows = [];
    const plaintextById = new Map();
    const envelopeRows = [];
    for (const row of rows) {
      const parsed = parseStoredKey(row.api_key);
      if (parsed.kind === "none") { counts.keyless += 1; continue; }
      if (parsed.kind === "malformed") { counts.unreadable += 1; continue; }
      if (parsed.kind === "envelope") { envelopeRows.push({ id: row.id, stored: row.api_key, parsed }); continue; }
      plainRows.push({ id: row.id, plaintext: row.api_key });
      plaintextById.set(row.id, row.api_key);
    }

    // 4. The key (the §3.2 table).
    const state = keychainKeyState({ crowHome });
    let key = state.key;
    if (!key && plainRows.length > 0) {
      const keychainRows = tableExists(db, "crow_keychain")
        ? Number(db.prepare("SELECT COUNT(*) AS c FROM crow_keychain").get()?.c ?? 0)
        : 0;
      const mintable = mintIfSafe
        && state.state === "missing"
        && envelopeRows.length === 0
        && keychainRows === 0;
      if (!mintable) {
        // A new key here would orphan every sealed value already on this
        // instance (or a damaged key file still holds the way back).
        raiseAlert(SWEEP_ALERTS.KEY_MISSING, KEY_SAVE_REFUSED);
        log(`  provider keys: refused (${state.state === "invalid" ? "key-invalid" : "key-missing"})`);
        return deferredResult(state.state === "invalid" ? "key-invalid" : "key-missing", counts);
      }
      try {
        key = createKeychainKey({ crowHome });
      } catch {
        key = null;
      }
      if (!key) {
        raiseAlert(SWEEP_ALERTS.KEY_MISSING, KEY_SAVE_REFUSED);
        log("  provider keys: refused (key-missing)");
        return deferredResult("key-missing", counts);
      }
      log("  provider keys: minted this instance's first keychain key");
    }

    // With a key, say how the already-sealed rows read. (Without one there is
    // nothing to open; they were counted by shape above.)
    for (const { id, stored } of envelopeRows) {
      const opened = key ? openProviderKey({ slotId: id, stored, key }) : null;
      if (typeof opened === "string") counts.alreadySealed += 1;
      else counts.unreadable += 1;
    }

    if (plainRows.length === 0) {
      // Nothing to seal: no backup, no consent rewrite, no write at all — UNLESS a
      // previous pass left plaintext residue in freed space it could not reclaim.
      // Then this pass (the hourly one included) rescans with the envelopes' own
      // plaintexts as needles (review round 1, H3) — while a marker exists.
      if (residuePending(crowHome)) {
        const clean = clearFreedSpace({
          db, dbPath, crowHome, plaintexts: [], envelopeRows, key, allowVacuum, skipScan: skipResidueScan, log,
        });
        if (!clean) counts.residue = "pending";
        log(
          `  provider keys: ${counts.alreadySealed} already sealed, ${counts.keyless} without a key, ` +
          (clean ? "freed space clean" : "freed space still being cleared"),
        );
        return { deferred: false, counts };
      }
      log(`  provider keys: ${counts.alreadySealed} already sealed, ${counts.keyless} without a key, nothing to do`);
      return { deferred: false, counts };
    }

    // 5. A verified pre-seal copy BEFORE any write (§3.5). At most one a day: the
    // newest copy already holds the pre-seal state of the operator's real keys
    // (round 1, M2), so a bot-written plaintext row costs no new full copy.
    const rowDigests = plainRows.map((r) => ({ id: r.id, digest: valueDigest(r.plaintext) }));
    const backup = await makeVerifiedBackup(db, dbPath, crowHome, {
      now, prefix: "crow-pre-seal", providersCount: rows.length, rowDigests, nowMs: clockMs(now),
    });
    if (!backup.ok) {
      // A copy that fails its own verification is a BACKUP failure: nothing was
      // sealed yet, so it says nothing about the seal (round 1, NIT).
      raiseAlert(SWEEP_ALERTS.BACKUP_FAILED);
      log(`  provider keys: refused (${backup.reason}: ${backup.step})`);
      return deferredResult(backup.reason, counts);
    }
    counts.backup = backup.path;

    // 6–8. Consent rewrite, the seal and its proof: ONE transaction.
    const consentDoc = readConsent(db);
    const consent = consentDoc ? { ...consentDoc.consent } : null;
    const providerCount = rows.length;

    const pass = db.transaction(() => {
      // Consent first: its fingerprint names the key this row held, and after
      // the UPDATE below it no longer does.
      let rewritten = 0;
      if (consent) {
        rewritten = rewriteConsentInMap(consent, plaintextById, consentDoc.salt);
        if (rewritten > 0) {
          db.prepare("UPDATE dashboard_settings SET value = ?, updated_at = datetime('now') WHERE key = ?")
            .run(JSON.stringify(consent), CONSENT_KEY);
        }
      }

      // A guarded write: only a row that still holds the exact plaintext this
      // pass read is rewritten, so a save that landed in between is not
      // clobbered (the next pass seals the new value).
      const update = db.prepare("UPDATE providers SET api_key = ? WHERE id = ? AND api_key = ?");
      const readBack = db.prepare("SELECT api_key FROM providers WHERE id = ?");
      const proofs = [];
      for (const { id, plaintext } of plainRows) {
        const envelope = sealProviderKey({ slotId: id, plaintext, key });
        if (update.run(envelope, id, plaintext).changes !== 1) throw new Error("provider-key write lost a race");
        proofs.push({ id, plaintext });
      }
      // The proof is inside the transaction: a value that does not round-trip
      // rolls the whole pass back instead of leaving a half-sealed database.
      for (const { id, plaintext } of proofs) {
        const opened = openProviderKey({ slotId: id, stored: readBack.get(id)?.api_key, key });
        if (opened !== plaintext) throw new SealVerifyError();
      }
      if (Number(db.prepare("SELECT COUNT(*) AS c FROM providers").get()?.c) !== providerCount) {
        throw new SealVerifyError();
      }
      return rewritten;
    });

    try {
      // §3.1 step 5: freed pages are zeroed, so the old plaintext cells do not
      // survive in the file's free space; BEGIN IMMEDIATE takes the write lock up
      // front; and step 9's checkpoint folds the WAL (which held the plaintext
      // pages) back into the file and truncates it.
      db.pragma("secure_delete = ON");
      counts.consentRewritten = pass.immediate();
      counts.sealed = plainRows.length;
    } catch (err) {
      // A verify mismatch is `seal-verify-failed`; anything else (a lost write
      // race, SQLITE_BUSY, a driver error) is a `db-error` (round 1, NIT).
      if (isVerifyMismatch(err)) {
        raiseAlert(SWEEP_ALERTS.VERIFY_FAILED);
        log("  provider keys: the seal did not verify, nothing was written");
        return deferredResult("seal-verify-failed", counts);
      }
      raiseAlert(SWEEP_ALERTS.DB_ERROR);
      log("  provider keys: the seal stopped on a database error");
      return deferredResult("db-error", counts);
    }

    // 8b. The plaintext may survive in freed space an EARLIER write left behind
    // (secure_delete only covers this connection's own writes). Do it now, while
    // the plaintexts are still in hand: a later pass has to open the envelopes to
    // get them back (review round 1, H3).
    const clean = clearFreedSpace({
      db, dbPath, crowHome, plaintexts: plainRows.map((r) => r.plaintext), envelopeRows, key, allowVacuum, log,
    });
    if (!clean) counts.residue = "pending";
    // The buffers are no longer needed: drop every reference so the values live
    // only in this pass's own scope, which is about to end.
    for (const r of plainRows) r.plaintext = null;
    plainRows.length = 0;
    plaintextById.clear();

    // 9. Retention, only now that the pass verified (and only when every envelope
    // on the instance opened — round 1, L4).
    pruneBackups(crowHome, { unreadable: counts.unreadable });

    log(
      `  provider keys: ${counts.sealed} sealed, ${counts.alreadySealed} already sealed, ` +
      `${counts.keyless} without a key, ${counts.unreadable} unreadable, ` +
      `${counts.consentRewritten} consent rewritten` +
      (counts.residue ? ", freed space still being cleared" : ""),
    );
    return { deferred: false, counts };
  } finally {
    try { db.close(); } catch { /* already closed */ }
  }
}

// ─── the unseal pass (design §3.3, the ops tool) ───────────────────────────

/**
 * Put every sealed provider key back in the clear, for the unseal tool. Takes a
 * verified `crow-pre-unseal-<ts>.db` copy first, writes in ONE transaction, and
 * leaves `updated_at` and `lamport_ts` untouched — an unseal is a reversal of a
 * local migration, not an edit. Never throws.
 *
 * @param {string} dbPath
 * @param {{crowHome?: string, now?: (() => Date)|Date,
 *          log?: (line: string) => void}} [options]
 * @returns {Promise<{deferred: boolean, reason?: string,
 *            counts: {unsealed:number, keyless:number, unreadable:number, backup:string|null}}>}
 */
export async function unsealAllKeys(dbPath, options = {}) {
  const counts = { unsealed: 0, keyless: 0, unreadable: 0, backup: null };
  const log = typeof options.log === "function" ? options.log : () => {};
  const crowHome = typeof options.crowHome === "string" && options.crowHome ? options.crowHome : resolveCrowHome();
  const now = options.now ?? (() => new Date());

  let db;
  try {
    db = new Database(dbPath, { fileMustExist: true });
    db.pragma("busy_timeout = 10000");
    db.prepare("SELECT COUNT(*) AS c FROM sqlite_master").get();
  } catch {
    try { db?.close(); } catch { /* already closed */ }
    raiseAlert(SWEEP_ALERTS.DB_ERROR);
    return deferredResult("db-error", counts);
  }

  try {
    if (!tableExists(db, "providers")) return deferredResult("providers-absent", counts);
    if (!dbBelongsToHome(dbPath, crowHome)) {
      raiseAlert(SWEEP_ALERTS.HOME_MISMATCH);
      return deferredResult("home-mismatch", counts);
    }

    const rows = db.prepare("SELECT id, api_key FROM providers ORDER BY id").all();
    const envelopes = [];
    for (const row of rows) {
      const parsed = parseStoredKey(row.api_key);
      if (parsed.kind === "none") { counts.keyless += 1; continue; }
      if (parsed.kind === "malformed") { counts.unreadable += 1; continue; }
      if (parsed.kind === "envelope") envelopes.push({ id: row.id, stored: row.api_key });
    }

    // Opening needs the key: no key, nothing to unseal. And nothing to open
    // means nothing to write — no backup, no transaction, no churn.
    if (envelopes.length === 0) {
      log(`  provider keys: ${counts.keyless} without a key, ${counts.unreadable} unreadable, nothing to unseal`);
      return { deferred: false, counts };
    }
    const key = loadKeychainKey({ crowHome });
    if (!key) {
      raiseAlert(SWEEP_ALERTS.KEY_MISSING, KEY_SAVE_REFUSED);
      return deferredResult("key-missing", counts);
    }

    const backup = await makeVerifiedBackup(db, dbPath, crowHome, {
      now,
      prefix: "crow-pre-unseal",
      providersCount: rows.length,
      rowDigests: envelopes.map((r) => ({ id: r.id, digest: valueDigest(r.stored) })),
    });
    if (!backup.ok) {
      raiseAlert(SWEEP_ALERTS.BACKUP_FAILED);
      log(`  provider keys: refused (${backup.reason}: ${backup.step})`);
      return deferredResult(backup.reason, counts);
    }
    counts.backup = backup.path;

    const pass = db.transaction(() => {
      const update = db.prepare("UPDATE providers SET api_key = ? WHERE id = ? AND api_key = ?");
      for (const { id, stored } of envelopes) {
        const plaintext = openProviderKey({ slotId: id, stored, key });
        if (typeof plaintext !== "string" || plaintext === "") throw new SealVerifyError();
        if (update.run(plaintext, id, stored).changes !== 1) throw new Error("provider-key write lost a race");
        counts.unsealed += 1;
      }
    });
    try {
      pass();
    } catch (err) {
      counts.unsealed = 0;
      if (isVerifyMismatch(err)) {
        raiseAlert(SWEEP_ALERTS.VERIFY_FAILED);
        return deferredResult("seal-verify-failed", counts);
      }
      raiseAlert(SWEEP_ALERTS.DB_ERROR);
      return deferredResult("db-error", counts);
    }

    pruneBackups(crowHome, { unreadable: counts.unreadable });
    log(`  provider keys: ${counts.unsealed} unsealed, ${counts.keyless} without a key, ${counts.unreadable} unreadable`);
    return { deferred: false, counts };
  } catch {
    raiseAlert(SWEEP_ALERTS.DB_ERROR);
    return deferredResult("db-error", counts);
  } finally {
    try { db.close(); } catch { /* already closed */ }
  }
}

/** Is there a verified pre-seal copy on disk for this home? (The dry-run's check.) */
export function backupFiles(crowHome) {
  const dir = backupDirFor(crowHome);
  let names;
  try { names = readdirSync(dir); } catch { return []; }
  return names
    .filter((n) => /^crow-pre-(?:seal|unseal)-.+\.db$/.test(n))
    .map((n) => join(dir, n))
    .filter((p) => existsSync(p))
    .sort();
}

