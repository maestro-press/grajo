/**
 * The keychain AAD conversion — one boot pass that makes every saved password BOUND to
 * its row, and then records the era in which an old-style (`enc:v1:`) value is REFUSED.
 *
 * WHY. `crow_keychain.secret_sealed` was sealed with secret-box v1: AES-256-GCM under the
 * keychain's own key with NO associated data, so any row's blob opened in any other row. A
 * bot with crow.db write access could copy the Mail password's blob into its own add-on's
 * row and be handed the plaintext at its next spawn. `servers/gateway/keychain/store.js` now
 * seals v2 (bound to the row, `rowAad`), so a copied blob fails its tag check.
 *
 * WHAT THIS PASS DOES, in order (never throws):
 *   1. is the era already recorded? Then a boot SCAN only: every remaining `enc:v1:` row is
 *      refused from now on, so each one is recorded (`keychain_legacy_form`) and the one bell is
 *      raised (deduped per 24 h). The HOST state file alone is proof; the bot-writable
 *      `keychain_aad_era` DB mirror is proof only together with a `enc:v2:` row that OPENS
 *      under this key (the M2 evidence) — a mirror a bot planted before the first boot is
 *      alarmed, ignored, and the pass converts everything as it always would.
 *   2. no keychain key file, no `crow_keychain` table, or zero rows → record the era right
 *      away (nothing to convert; a fresh install starts in v2). With NO key file nothing is
 *      recorded at all: this boot cannot prove it could open anything, so v1 stays accepted
 *      and one line says so.
 *   3. otherwise, with rows to look at:
 *      (a) a VERIFIED copy of the database into
 *          `<CROW_HOME>/secrets/backups/keychain-aad/crow-pre-aad-<ts>.db` (0600 in 0700,
 *          quick_check + a row-count and per-blob-digest check of the copy) — kept as the
 *          oldest plus the newest two copies;
 *      (b) a snapshot of every `enc:v1:` row under the CURRENT key id —
 *          `{id, kind, bundle_id, env_key, connection_uuid, sha256(secret_sealed)}` into
 *          `secrets/keychain-aad-rollback-<ts>.json` (0600, atomic). Digests only, never
 *          plaintext;
 *      (b2) the anti-laundering screen, in two halves.
 *          THE DUPLICATE HALF IS A GATE. Two rows that share one 12-byte GCM nonce are BOTH
 *          refused: random nonces mean two genuine rows never share one, so one of them is a
 *          copy. The nonce is read from the DECODED bytes, never from the string, because
 *          Node's base64 decoder ignores whitespace and a missing `=` pad: `blob + "\n"`,
 *          `"enc:v1: " + body` and a padding-stripped body are different strings that open to
 *          the same plaintext, and grouping them by the raw string was bypassable exactly that
 *          way (a bot copied the Mail blob into its own row with a trailing newline). Any v1
 *          candidate whose body is not canonical base64 is refused as well — it is not a form
 *          this release wrote — and it is refused, never converted.
 *          THE BOUND-COLUMN HALF IS ADVISORY, NOT A GATE. `installed.json`, `mcp-addons.json`,
 *          `service_connections` and `mail_accounts` are all writable by a bot, so a row that
 *          names nothing real is only a row somebody bound CARELESSLY; refusing it catches
 *          that mistake, and a bot that can write those tables can make any row pass anyway.
 *          It is therefore never allowed to refuse a row when the screen cannot KNOW (no
 *          installed.json, no such table — see `screenCandidates`), and it must never become
 *          a fail-closed gate: the owner's own rows would be the first thing it refused.
 *          A refused row stays v1 (and is therefore refused after the era: the owner re-enters
 *          it), is alarmed, and is counted.
 *          WHY THE SOURCE OF A DUPLICATE IS REFUSED TOO. There is no sound tiebreak between
 *          the two rows sharing a nonce: every column that distinguishes them (kind, bundle id,
 *          env key, connection uuid, label, status, id) is bot-writable, and the earlier row is
 *          not more likely to be the genuine one. Refusing only the copy would let a bot keep
 *          the source when the copy looks sloppier; refusing only the source would let it
 *          launder a copy into a row it may name. So both stay v1 and the owner re-enters the
 *          password. This adds no new denial a bot could not already cause: with crow.db
 *          read-write it can break a Mail password by deleting its row outright.
 *          The residual: a single planted copy whose source row the attacker DELETED is
 *          indistinguishable from a genuine row and is converted (the same accepted residual as
 *          the token conversion's D5);
 *      (c) ONE `BEGIN IMMEDIATE` transaction: the candidates are RE-SELECTED inside it, a row
 *          whose blob or bound columns moved since the pre-read is skipped and alarmed (never a
 *          rollback), and each remaining v1 value is opened (no AAD), resealed v2 with the AAD
 *          of its own row, and UPDATE'd with a compare-and-swap on the exact blob AND the bound
 *          columns the AAD is built from. A candidate that does not open, opens to nothing or is
 *          no longer the exact `enc:v1:` form is refused and skipped — one junk row a bot planted
 *          can never block the pass. The Export fingerprints of the converted rows move from the
 *          old blob's hash to the new one IN THE SAME TRANSACTION (the plaintext is unchanged),
 *          so off-site backups and the Export reminder see no change;
 *      (d) the proof: re-read every converted row and open it with its AAD, comparing the
 *          plaintext in memory (never logged) — INSIDE the transaction, so a value that does
 *          not round-trip rolls the whole pass back;
 *      (e) only then: the era state file, then the DB mirror. A `PRAGMA wal_checkpoint(TRUNCATE)`
 *          follows the commit, so no converted v1 blob survives in `crow.db-wal`;
 *      Every row under a FOREIGN key id is left untouched (it is already unreadable) and counted.
 *      Any other failure rolls the transaction back, removes the snapshot this pass wrote,
 *      records nothing and logs one line — every row stays v1 and still opens.
 *
 * A CRASH BETWEEN (c) AND (e) is the interesting one: the next boot finds no marker but v2 rows.
 * CRASH EVIDENCE is a v2 row that OPENS with its own AAD under the current key — a bot cannot
 * forge one before the conversion — so a planted `enc:v2:` blob is refused, alarmed and ignored
 * for this decision instead of blocking every owner row forever. It then converts ONLY the rows
 * its newest snapshot lists that still hold the blob the snapshot hashed, and REFUSES (alarms)
 * any other v1 row it meets — the same anti-laundering rule as `boot/token-hmac-settings.js`, so a
 * v1 value written after the snapshot can never be laundered into a converted one. With v2 rows
 * and no readable snapshot at all, nothing is converted: every v1 row is alarmed and the era is
 * recorded over them.
 *
 * Boot also always leaves the STATE FILE behind once the era is known: an era evidenced by the DB
 * mirror or by v2 rows (but with no readable state file) writes it, so the host-only trigger is
 * present after every boot and crow.db alone can never downgrade the era (`keychain/aad-era.js`).
 *
 * CALLED from `servers/gateway/index.js` pre-listen (its own DB handle) and from the satellite
 * agent's boot (satellite.db holds its own `crow_keychain`, sealed under `$SAT_HOME`'s key).
 * Nothing here logs a value, a blob or a key id.
 */
import { chmodSync, closeSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";
import Database from "better-sqlite3";
import { resolveCrowHome, resolveInstanceDataDir } from "../../shared/crow-home.js";
import {
  isCanonicalSealed, openSecret, openSecretBound, sealSecretBound, sealedNonceHex,
} from "../../sharing/secret-box.js";
import { installedPath, readInstalled } from "../bundle-core.js";
import { keychainKeyState } from "../keychain/key.js";
import { MAIL_BUNDLE, isSystemBundleId, rowAad } from "../keychain/store.js";
import { exportFingerprint, remapExportFingerprintsSync } from "../keychain/export-fingerprint.js";
import {
  aadSecretsDirFromHome, mirrorConvertedSync, raiseLegacyFormAlarmSync, raiseMirrorUntrustedAlarmSync,
  noteSecurityWriteFailure, readAadState, writeAadMirrorSync, writeAadState,
} from "../keychain/aad-era.js";

/** `<CROW_HOME>/secrets/backups/keychain-aad` — 0700, one verified copy per conversion. */
export const AAD_BACKUP_SUBDIR = Object.freeze(["secrets", "backups", "keychain-aad"]);
export const AAD_BACKUP_PREFIX = "crow-pre-aad";
/** Snapshots live beside the key: `<CROW_HOME>/secrets/keychain-aad-rollback-<ts>.json`. */
export const AAD_ROLLBACK_PREFIX = "keychain-aad-rollback-";
export const AAD_SNAPSHOT_VERSION = 1;
/** The newest two copies plus the oldest are kept (a hard cap, like the provider-key pass). */
export const AAD_BACKUP_KEEP = 2;

const V1_PREFIX = "enc:v1:";
/** The exact-prefix test every scan uses: SQLite's LIKE is case-insensitive, this is not. */
const V1_SQL = "substr(secret_sealed, 1, 7) = 'enc:v1:'";
const V2_SQL = "substr(secret_sealed, 1, 7) = 'enc:v2:'";

function tableExists(db, name) {
  try {
    return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name);
  } catch {
    return false;
  }
}

const digestOf = (value) => createHash("sha256").update(String(value ?? ""), "utf8").digest("hex");
const stamp = (now) => (now instanceof Date ? now : new Date()).toISOString().replace(/[:.]/g, "-");

function ensureDir(dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
}

/** Write `body` to `dir/name` atomically at 0600 (temp created exclusively, fsync, rename). */
function writePrivateJson(dir, name, body) {
  ensureDir(dir);
  const final = join(dir, name);
  const tmp = `${final}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(body) + "\n");
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  try {
    renameSync(tmp, final);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw err;
  }
  return final;
}

function backupDirFor(crowHome) {
  return join(crowHome, ...AAD_BACKUP_SUBDIR);
}

/**
 * Take one VERIFIED copy of the database. → `{ok: true, path}` or `{ok: false}`.
 * The copy is judged by its own connection: `quick_check`, the `crow_keychain` row count and
 * the digest of every row this pass is about to rewrite.
 */
async function makeVerifiedBackup(db, dbPath, crowHome, { now, rows, rowCount }) {
  const dir = backupDirFor(crowHome);
  try {
    ensureDir(dir);
    statSync(dbPath);
  } catch {
    return { ok: false };
  }
  const name = `${AAD_BACKUP_PREFIX}-${stamp(now)}.db`;
  const final = join(dir, name);
  const tmp = join(dir, `.${name}.${process.pid}.tmp`);
  try {
    closeSync(openSync(tmp, "wx", 0o600));
    await db.backup(tmp);
    chmodSync(tmp, 0o600);
  } catch {
    try { unlinkSync(tmp); } catch { /* nothing to remove */ }
    return { ok: false };
  }
  let copy = null;
  try {
    copy = new Database(tmp, { fileMustExist: true });
    const check = copy.pragma("quick_check");
    const verdict = Array.isArray(check) ? String(check[0]?.quick_check ?? check[0]) : String(check);
    if (verdict !== "ok") throw new Error("quick_check");
    const count = Number(copy.prepare("SELECT COUNT(*) AS c FROM crow_keychain").get()?.c ?? -1);
    if (rowCount !== null && count !== rowCount) throw new Error("row count");
    const read = copy.prepare("SELECT secret_sealed FROM crow_keychain WHERE id = ?");
    for (const r of rows) {
      const got = read.get(r.id);
      if (!got || digestOf(got.secret_sealed) !== r.hash) throw new Error("blob digest");
    }
  } catch {
    try { unlinkSync(tmp); } catch { /* nothing to remove */ }
    return { ok: false };
  } finally {
    if (copy) { try { copy.close(); } catch { /* already closed */ } }
  }
  for (const suffix of ["-wal", "-shm"]) {
    try { unlinkSync(tmp + suffix); } catch { /* no sidecar */ }
  }
  try {
    renameSync(tmp, final);
  } catch {
    try { unlinkSync(tmp); } catch { /* nothing to remove */ }
    return { ok: false };
  }
  pruneBackups(dir);
  return { ok: true, path: final };
}

/**
 * The same verified pre-conversion copy the pass takes, exported for the operator's
 * downgrade tool (scripts/ops/keychain-aad-downgrade.mjs), so both write the identical copy
 * shape and retention.
 */
export async function keychainAadVerifiedBackup(db, dbPath, crowHome, { now, rows = [], rowCount = null } = {}) {
  return makeVerifiedBackup(db, dbPath, crowHome, { now, rows, rowCount });
}

/** Keep the newest AAD_BACKUP_KEEP copies plus the oldest one; delete the rest. */
function pruneBackups(dir) {
  let names;
  try { names = readdirSync(dir); } catch { return; }
  const copies = [];
  for (const name of names) {
    if (!/^crow-pre-aad-.+\.db$/.test(name)) continue;
    try { copies.push({ name, mtimeMs: statSync(join(dir, name)).mtimeMs }); } catch { /* vanished */ }
  }
  if (copies.length <= AAD_BACKUP_KEEP + 1) return;
  copies.sort((a, b) => b.mtimeMs - a.mtimeMs);
  const keep = new Set(copies.slice(0, AAD_BACKUP_KEEP).map((c) => c.name));
  keep.add(copies[copies.length - 1].name); // the oldest: the operator's furthest-back point
  for (const copy of copies) {
    if (keep.has(copy.name)) continue;
    try { unlinkSync(join(dir, copy.name)); } catch { /* kept */ }
  }
}

/** The newest readable conversion snapshot, or null. */
function newestSnapshot(crowHome) {
  const dir = aadSecretsDirFromHome(crowHome);
  let names;
  try { names = readdirSync(dir); } catch { return null; }
  let best = null;
  for (const name of names) {
    if (!name.startsWith(AAD_ROLLBACK_PREFIX) || !name.endsWith(".json")) continue;
    let body;
    let mtimeMs;
    try {
      const path = join(dir, name);
      mtimeMs = lstatSync(path).mtimeMs;
      body = JSON.parse(readFileSync(path, "utf8"));
    } catch {
      continue;
    }
    if (!body || body.v !== AAD_SNAPSHOT_VERSION || !Array.isArray(body.rows)) continue;
    if (!best || mtimeMs > best.mtimeMs) best = { name, body, mtimeMs };
  }
  return best;
}

/**
 * The ids this instance has installed, from `<CROW_HOME>/installed.json` through bundle-core's
 * own reader (array, or the legacy id-keyed object) — or NULL when that cannot be KNOWN: no
 * file, a file that does not parse into entries, or an empty list. A converter that cannot know
 * skips the bound-column check for extension rows rather than refusing rows nobody can vouch for.
 */
function installedIdsOrNull(crowHome) {
  const path = installedPath(crowHome);
  try { if (!statSync(path).isFile()) return null; } catch { return null; }
  const ids = new Set();
  for (const entry of readInstalled(path)) {
    if (entry && typeof entry.id === "string" && entry.id !== "") ids.add(entry.id);
  }
  // A custom MCP add-on (Extensions → "add an MCP server") is not in installed.json: its entry
  // lives in <CROW_HOME>/mcp-addons.json, keyed by id, and its keychain rows carry that id.
  for (const id of mcpAddonIds(crowHome)) ids.add(id);
  return ids.size === 0 ? null : ids;
}

/** The entry ids of `<CROW_HOME>/mcp-addons.json` (an id-keyed object); none when absent or unreadable. */
function mcpAddonIds(crowHome) {
  try {
    const all = JSON.parse(readFileSync(join(crowHome || resolveCrowHome(), "mcp-addons.json"), "utf8"));
    if (!all || typeof all !== "object" || Array.isArray(all)) return [];
    return Object.keys(all).filter((id) => id !== "");
  } catch {
    return [];
  }
}

/**
 * The 12-byte GCM nonce of every `enc:v1:` row, by how many rows carry it. The comparison is on
 * the DECODED bytes (`sealedNonceHex`), never on the stored string: `blob + "\n"`, a leading
 * space after the prefix and a padding-stripped body all decode to the same nonce, so a copy
 * re-encoded that way is still a copy (random nonces mean two genuine rows never share one).
 */
function duplicatedNonces(db) {
  const counts = new Map();
  try {
    const rows = db.prepare(`SELECT secret_sealed AS blob FROM crow_keychain WHERE ${V1_SQL}`).all();
    for (const row of rows) {
      const nonce = sealedNonceHex(String(row.blob ?? ""));
      if (nonce === null) continue;
      counts.set(nonce, (counts.get(nonce) ?? 0) + 1);
    }
  } catch { /* no table: nothing to compare */ }
  const out = new Set();
  for (const [nonce, n] of counts) if (n > 1) out.add(nonce);
  return out;
}

/** Does this kind 'service' row name a connection row, or a Mail account under Crow Mail's bundle? */
function serviceRowIsReal(db, row, { hasConnections, hasMail }) {
  const uuid = String(row.connection_uuid);
  if (hasConnections) {
    try { if (db.prepare("SELECT 1 AS hit FROM service_connections WHERE uuid = ? LIMIT 1").get(uuid)) return true; } catch { /* cannot know */ }
  }
  if (hasMail && row.bundle_id === MAIL_BUNDLE) {
    try { if (db.prepare("SELECT 1 AS hit FROM mail_accounts WHERE id = ? LIMIT 1").get(uuid)) return true; } catch { /* cannot know */ }
  }
  return false;
}

/**
 * The anti-laundering screen (M1). → `{safe, unsafe, unknown}`: the rows this pass may convert,
 * the rows it REFUSES (a blob that is not exactly `enc:v1:` in canonical base64, a blob that
 * shares its GCM nonce with another row — a copy — or bound columns that name nothing real — they
 * stay v1, are alarmed, and are refused after the era, so the owner re-enters them) and whether
 * any check had to be skipped for lack of local knowledge.
 *
 * ADVISORY, NOT A GATE: the BOUND-COLUMN half reads `installed.json`, `mcp-addons.json`,
 * `service_connections` and `mail_accounts`, and a bot with crow.db write access (or the home's
 * files) writes every one of them. So it only catches a row somebody bound CARELESSLY — it can
 * never prove a row is genuine, and a bot that wants a row to pass can make it pass. It is
 * therefore deliberately NOT fail-closed: when this screen cannot know (no installed.json, no
 * such table) it says so (`unknown`) and lets the row through rather than refusing the owner's
 * own rows. The exact-form and nonce checks above it do not depend on local knowledge and are
 * the part that decides a copy.
 */
function screenCandidates(db, crowHome, rows) {
  const out = { safe: [], unsafe: [], unknown: false };
  if (!Array.isArray(rows) || rows.length === 0) return out;
  const copies = duplicatedNonces(db);
  const installed = installedIdsOrNull(crowHome);
  const hasConnections = tableExists(db, "service_connections");
  const hasMail = tableExists(db, "mail_accounts");
  for (const row of rows) {
    const blob = String(row.secret_sealed ?? "");
    // SQLite's LIKE is case-insensitive; only the exact form this release wrote is a value.
    if (!blob.startsWith(V1_PREFIX)) { out.unsafe.push(row); continue; }
    // The base64 decoder ignores whitespace and a missing `=` pad, so a re-spelled body is a
    // different string that opens to the same plaintext. Only a body that re-encodes to itself is
    // a form this release wrote; anything else is refused (never converted, never resealed under
    // this row) and alarmed.
    if (!isCanonicalSealed(blob)) { out.unsafe.push(row); continue; }
    // One nonce in two rows = one copy (random nonces): BOTH rows are refused, never just one.
    const nonce = sealedNonceHex(blob);
    if (nonce === null || copies.has(nonce)) { out.unsafe.push(row); continue; }
    if (row.kind === "extension") {
      if (!installed) out.unknown = true;
      else if (!installed.has(String(row.bundle_id ?? "")) && !isSystemBundleId(row.bundle_id)) { out.unsafe.push(row); continue; }
    } else if (row.kind === "service") {
      const uuid = typeof row.connection_uuid === "string" && row.connection_uuid !== "" ? row.connection_uuid : null;
      if (!uuid) { out.unsafe.push(row); continue; }
      if (!hasConnections && !hasMail) { out.unknown = true; out.safe.push(row); continue; }
      if (serviceRowIsReal(db, row, { hasConnections, hasMail })) { out.safe.push(row); continue; }
      if (!hasMail && row.bundle_id === MAIL_BUNDLE) { out.unknown = true; out.safe.push(row); continue; }
      out.unsafe.push(row);
      continue;
    }
    out.safe.push(row);
  }
  return out;
}

/**
 * CRASH EVIDENCE (M2): a v2 row that OPENS with its own AAD under the current key. A bot cannot
 * forge one before the conversion (it has no key), so a planted `enc:v2:` blob is not evidence
 * and must not block every owner row. → `{open, broken}`.
 */
function openableV2Rows(db, key) {
  let rows;
  try {
    rows = db.prepare(`SELECT id, kind, bundle_id, env_key, connection_uuid, key_id, secret_sealed FROM crow_keychain WHERE ${V2_SQL} AND key_id = ? ORDER BY id`).all(key.id);
  } catch { return { open: 0, broken: [] }; }
  let open = 0;
  const broken = [];
  for (const row of rows) {
    try {
      const value = openSecretBound(row.secret_sealed, { seed: key.seed }, rowAad(row, key.id));
      if (typeof value === "string") { open += 1; continue; }
    } catch { /* not a value this key and row can open */ }
    broken.push(row);
  }
  return { open, broken };
}

/** Does every column the AAD is built from still hold the value the pre-read saw? */
function sameBoundRow(a, b) {
  return Number(a?.id) === Number(b?.id)
    && String(a?.secret_sealed ?? "") === String(b?.secret_sealed ?? "")
    && String(a?.kind ?? "") === String(b?.kind ?? "")
    && String(a?.key_id ?? "") === String(b?.key_id ?? "")
    && String(a?.bundle_id ?? "") === String(b?.bundle_id ?? "")
    && String(a?.env_key ?? "") === String(b?.env_key ?? "")
    && String(a?.connection_uuid ?? "") === String(b?.connection_uuid ?? "");
}

/**
 * Run the pass. Never throws: every outcome is a small fixed-token result.
 *
 * @param {{dbPath?: string, crowHome?: string, log?: (line: string) => void, now?: Date,
 *          mirror?: boolean, mirrorInstanceId?: string,
 *          verifyProof?: (info: {converted: number}) => void,
 *          beforeConvert?: (info: {candidates: number}) => void}} [options]
 *   `mirrorInstanceId` is the id the DB mirror is written under (the caller owns that lookup,
 *   because the satellite has no instance registry and must not load one). `verifyProof` is a
 *   TEST seam, called inside the conversion transaction after the real proof; it must throw to
 *   simulate a failed verification. `beforeConvert` is the other TEST seam: it runs after the
 *   snapshot and before the transaction, so a test can move a row the way a concurrent writer
 *   would (the transaction re-selects the candidates and skips what moved).
 * @returns {Promise<{state: string, rows: number, v1: number, converted: number,
 *   verified: number, refused: number, unsafe: number, foreignKey: number, alarms: number,
 *   backup: string|null, snapshot: string|null, changed: boolean}>}
 */
export async function runKeychainAadBoot(options = {}) {
  const out = {
    state: "noop", rows: 0, v1: 0, converted: 0, verified: 0, refused: 0, unsafe: 0, foreignKey: 0,
    alarms: 0, backup: null, snapshot: null, changed: false,
  };
  const log = typeof options.log === "function" ? options.log : () => {};
  const now = options.now instanceof Date ? options.now : new Date();
  const crowHome = typeof options.crowHome === "string" && options.crowHome ? options.crowHome : safeHome();
  if (!crowHome) { out.state = "no-home"; return out; }
  // The era state file lives in the SECRETS DIR, never at a home-derived path (the pibot host
  // reads the key through `dirname(keyPath)`, which must be the same dir this writes).
  const secretsDir = aadSecretsDirFromHome(crowHome);
  const dbPath = typeof options.dbPath === "string" && options.dbPath ? options.dbPath : defaultDbPath(crowHome);

  let db = null;
  try {
    db = new Database(dbPath, { fileMustExist: true });
    db.pragma("busy_timeout = 10000");
    db.prepare("SELECT COUNT(*) AS c FROM sqlite_master").get();
  } catch {
    try { db?.close(); } catch { /* already closed */ }
    log("  keychain AAD: the database could not be read; nothing converted");
    out.state = "db-error";
    return out;
  }

  // Read before the era check: the repaired state file records this key's id.
  const keyState = keychainKeyState({ crowHome });

  try {
    // 1. The era is already recorded: scan and alarm only. The HOST state file is proof by
    //    itself. The `keychain_aad_era` DB mirror is only a row in a bot-writable table, so it is
    //    trusted only when something in this database proves a conversion really ran: a `enc:v2:`
    //    row that OPENS with its own AAD under the current key (the M2 evidence a bot cannot
    //    forge before the conversion). A mirror planted before the first boot is ALARMED and
    //    IGNORED, so the pass below converts every genuine row and then writes a correct mirror —
    //    and a marker that only crow.db carries is still re-written as the host-only state file,
    //    so a bot with crow.db write access can never downgrade the era by deleting the mirror.
    const fileState = readAadState(secretsDir).state;
    const mirrorSays = mirrorConvertedSync(db);
    let mirrorTrusted = fileState === "converted";
    if (!mirrorTrusted && mirrorSays) {
      mirrorTrusted = keyState.key ? openableV2Rows(db, keyState.key).open > 0 : false;
      if (!mirrorTrusted) {
        // Fail OPEN here, deliberately: refusing every v1 row on the word of a bot-writable row
        // would let a bot with crow.db write access deny the owner every saved password for good
        // (the write of the state file made it permanent before this check existed).
        raiseMirrorUntrustedAlarmSync(db);
        out.alarms += 1;
        log("  keychain AAD: the database marker is not backed by any bound keychain row — ignored, and the conversion runs");
      }
    }
    if (mirrorTrusted) {
      out.state = "converted-earlier";
      if (fileState !== "converted") recordEraStateFile(db, secretsDir, keyState.key?.id ?? null, now, log);
      // Catch the DB mirror up when the host state file proves the era and the mirror is gone
      // (a bot deleted it, or a build whose mirror write never landed). It is only a refusal
      // trigger, so re-writing it can never accept anything.
      if (!mirrorSays && options.mirror !== false && typeof options.mirrorInstanceId === "string" && options.mirrorInstanceId !== "") {
        try { writeAadMirrorSync(db, options.mirrorInstanceId, { now }); } catch (err) { noteSecurityWriteFailure("era mirror catch-up", err); }
      }
      if (!tableExists(db, "crow_keychain")) return out;
      const legacy = db.prepare(`SELECT id, kind, secret_sealed FROM crow_keychain WHERE ${V1_SQL} ORDER BY id`).all();
      out.v1 = legacy.length;
      for (const row of legacy) {
        raiseLegacyFormAlarmSync(db, row);
        out.alarms += 1;
      }
      out.refused = legacy.length;
      const odd = oddFormV1Rows(db);
      for (const row of odd) {
        raiseLegacyFormAlarmSync(db, row);
        out.alarms += 1;
      }
      out.refused += odd.length;
      if (legacy.length > 0) {
        log(`  keychain AAD: ${legacy.length} old-style keychain row(s) found after conversion — refused, not opened`);
      }
      if (odd.length > 0) {
        log(`  keychain AAD: ${odd.length} row(s) hold a value in an unrecognised old form — refused, not opened`);
      }
      return out;
    }

    const hasTable = tableExists(db, "crow_keychain");
    const rows = hasTable ? db.prepare("SELECT COUNT(*) AS c FROM crow_keychain").get() : null;
    out.rows = Number(rows?.c ?? 0);

    // 2. No key file: this boot cannot prove it could open anything, so it records nothing.
    if (!keyState.key) {
      log(`  keychain AAD: no keychain key on this machine (${keyState.state}); the conversion is skipped and old-style values stay accepted`);
      out.state = "skipped-key-missing";
      return out;
    }

    // 3. Nothing to convert: record the era so a fresh install starts in v2.
    if (out.rows === 0) {
      await markEra(db, secretsDir, { keyId: keyState.key.id, rows: 0, snapshot: null, now, mirror: options.mirror, mirrorInstanceId: options.mirrorInstanceId });
      out.state = "marked-empty";
      out.changed = true;
      log("  keychain AAD: no saved passwords yet; this instance now uses bound values");
      return out;
    }

    // 4. The candidate rows (the EXACT old form only: LIKE would also match "ENC:V1:…").
    const allV1 = db.prepare(
      `SELECT id, kind, bundle_id, env_key, connection_uuid, key_id, secret_sealed FROM crow_keychain WHERE ${V1_SQL} ORDER BY id`,
    ).all();
    out.v1 = allV1.length;
    const mine = allV1.filter((r) => r.key_id === keyState.key.id);
    out.foreignKey = allV1.length - mine.length;
    if (out.foreignKey > 0) {
      log(`  keychain AAD: ${out.foreignKey} row(s) sealed under another key were left untouched`);
    }

    // 4b. The anti-laundering screen: a copied blob or a row bound to nothing real is refused
    //     (and alarmed) instead of being resealed under the copy's own row.
    const screen = screenCandidates(db, crowHome, mine);
    const screenedRefused = screen.unsafe;
    const safeMine = screen.safe;
    if (screen.unknown) {
      log("  keychain AAD: the installed add-ons are not known on this home, so the bound-row check of extension rows was skipped");
    }
    if (screenedRefused.length > 0) {
      for (const row of screenedRefused) {
        raiseLegacyFormAlarmSync(db, row);
        out.alarms += 1;
      }
      out.unsafe = screenedRefused.length;
      out.refused += screenedRefused.length;
      log(`  keychain AAD: ${screenedRefused.length} row(s) failed the bound-row check (a copied value or an unknown owner) — left in the old form, refused`);
    }
    for (const row of oddFormV1Rows(db)) {
      raiseLegacyFormAlarmSync(db, row);
      out.alarms += 1;
      out.refused += 1;
    }

    const pendingAll = newestSnapshot(crowHome);
    // A snapshot written under another key id names rows of an era this box no longer holds.
    const pending = pendingAll && pendingAll.body.key_id === keyState.key.id ? pendingAll : null;
    // CRASH evidence is a v2 row that OPENS (M2), never a planted blob.
    const v2 = openableV2Rows(db, keyState.key);
    for (const row of v2.broken) {
      raiseLegacyFormAlarmSync(db, row);
      out.alarms += 1;
      out.refused += 1;
    }
    if (v2.broken.length > 0) {
      log(`  keychain AAD: ${v2.broken.length} bound row(s) do not open under this key — refused, and not counted as evidence of a conversion`);
    }
    const crash = !pending && v2.open > 0;
    let candidates;
    let refusedRows = [];
    if (pending) {
      // A crash interrupted the conversion: ONLY the rows its snapshot names, and only while
      // they still hold the exact blob it hashed. Anything else waits for the alarm, never for
      // a conversion — a value written after the snapshot must not be laundered.
      const listed = new Map();
      for (const row of pending.body.rows) {
        if (row && typeof row.hash === "string") listed.set(Number(row.id), row.hash);
      }
      candidates = safeMine.filter((r) => listed.get(Number(r.id)) === digestOf(r.secret_sealed));
      refusedRows = safeMine.filter((r) => !candidates.includes(r));
      out.snapshot = pending.name;
    } else if (crash) {
      // V2 rows and no marker and no snapshot to name what was converted: convert nothing.
      candidates = [];
      refusedRows = safeMine;
      log("  keychain AAD: converted rows found without a conversion record; only the era is recorded");
    } else {
      candidates = safeMine;
    }

    for (const row of refusedRows) {
      raiseLegacyFormAlarmSync(db, row);
      out.alarms += 1;
    }
    out.refused += refusedRows.length;

    // 5. The verified backup, before anything is written.
    const snapshotRows = candidates.map((r) => ({
      id: Number(r.id),
      kind: r.kind,
      bundle_id: r.bundle_id ?? null,
      env_key: r.env_key ?? null,
      connection_uuid: r.connection_uuid ?? null,
      hash: digestOf(r.secret_sealed),
    }));
    if (candidates.length > 0) {
      const backup = await makeVerifiedBackup(db, dbPath, crowHome, { now, rows: snapshotRows, rowCount: out.rows });
      if (!backup.ok) {
        log("  keychain AAD: the pre-conversion backup did not verify; nothing was converted and no era was recorded");
        out.state = "backup-failed";
        return out;
      }
      out.backup = backup.path;
    }

    // 6. The snapshot (only when this pass is not resuming an interrupted one).
    let snapshotName = pending ? pending.name : null;
    if (!pending && candidates.length > 0) {
      snapshotName = `${AAD_ROLLBACK_PREFIX}${stamp(now)}.json`;
      try {
        writePrivateJson(secretsDir, snapshotName, {
          v: AAD_SNAPSHOT_VERSION,
          key_id: keyState.key.id,
          created_at: (now instanceof Date ? now : new Date()).toISOString(),
          rows: snapshotRows,
        });
      } catch {
        log("  keychain AAD: the conversion snapshot could not be written; nothing was converted and no era was recorded");
        out.state = "snapshot-failed";
        return out;
      }
      out.snapshot = snapshotName;
    }

    // 7. Convert + prove, in ONE transaction. A row that does not open, opens to nothing, is no
    //    longer the exact old form, or moved under us is REFUSED and skipped — never an abort:
    //    one junk row a bot planted must not keep every other row in a refused form forever.
    if (typeof options.beforeConvert === "function") options.beforeConvert({ candidates: candidates.length });
    let convertedRows = [];
    if (candidates.length > 0) {
      db.pragma("secure_delete = ON");
      const skippedInside = [];
      const pass = db.transaction(() => {
        // RE-SELECT inside BEGIN IMMEDIATE: the pre-read happened before the backup and the
        // snapshot (seconds ago), and another writer may have moved a row in between.
        const live = db.prepare(
          `SELECT id, kind, bundle_id, env_key, connection_uuid, key_id, secret_sealed FROM crow_keychain WHERE key_id = ? AND ${V1_SQL}`,
        ).all(keyState.key.id);
        const liveById = new Map(live.map((r) => [Number(r.id), r]));
        const update = db.prepare(
          "UPDATE crow_keychain SET secret_sealed = ? WHERE id = ? AND secret_sealed = ? AND kind IS ? AND bundle_id IS ? AND env_key IS ? AND connection_uuid IS ? AND key_id = ?",
        );
        const readBack = db.prepare("SELECT secret_sealed, kind, bundle_id, env_key, connection_uuid FROM crow_keychain WHERE id = ?");
        const proofs = [];
        const pairs = [];
        for (const row of candidates) {
          const now_ = liveById.get(Number(row.id));
          if (!now_ || !sameBoundRow(now_, row)) { skippedInside.push(row); continue; }
          let plaintext = null;
          try { plaintext = openSecret(now_.secret_sealed, { seed: keyState.key.seed }); } catch { plaintext = null; }
          if (typeof plaintext !== "string" || plaintext === "") { skippedInside.push(now_); continue; }
          const sealed = sealSecretBound(plaintext, { seed: keyState.key.seed }, rowAad(now_, keyState.key.id));
          const changed = update.run(
            sealed, now_.id, now_.secret_sealed, now_.kind, now_.bundle_id ?? null, now_.env_key ?? null,
            now_.connection_uuid ?? null, now_.key_id,
          ).changes;
          if (changed !== 1) { skippedInside.push(now_); continue; }
          pairs.push({ id: Number(now_.id), from: exportFingerprint(now_.secret_sealed), to: exportFingerprint(sealed) });
          proofs.push({ id: now_.id, plaintext });
        }
        for (const proof of proofs) {
          const got = readBack.get(proof.id);
          const opened = openSecretBound(got?.secret_sealed, { seed: keyState.key.seed }, rowAad(got, keyState.key.id));
          if (opened !== proof.plaintext) throw new Error("a converted keychain row did not verify");
          proof.plaintext = null;
        }
        // The off-site backup gate and the Export reminder fingerprint `secret_sealed`; the
        // plaintext did not change, so each converted row's fingerprint moves with its blob in
        // THIS transaction (a value nobody exported stays unexported).
        remapExportFingerprintsSync(db, pairs);
        if (typeof options.verifyProof === "function") options.verifyProof({ converted: proofs.length });
        return proofs.map((p) => p.id);
      });
      try {
        convertedRows = pass.immediate();
      } catch {
        if (!pending && snapshotName) {
          try { unlinkSync(join(secretsDir, snapshotName)); } catch { /* already gone */ }
        }
        log("  keychain AAD: the conversion did not verify; it was rolled back, every value is unchanged and still accepted");
        out.state = "verify-failed";
        out.snapshot = pending ? pending.name : null;
        return out;
      }
      for (const row of skippedInside) {
        raiseLegacyFormAlarmSync(db, row);
        out.alarms += 1;
        out.refused += 1;
      }
      if (skippedInside.length > 0) {
        log(`  keychain AAD: ${skippedInside.length} row(s) could not be converted as they stand (they do not open, or they moved) — left in the old form, refused`);
      }
      // The committed v1 blobs must not survive in the write-ahead log (secure_delete covers the
      // main file; the checkpoint takes the WAL with it). Best effort: a busy WAL is retried by
      // SQLite's own checkpointing, and this never fails the pass.
      try { db.pragma("wal_checkpoint(TRUNCATE)"); } catch { /* another writer held the WAL */ }
    }
    out.converted = convertedRows.length;
    out.verified = convertedRows.length;

    // 8. The era, last: the state file first, then the DB mirror.
    await markEra(db, secretsDir, { keyId: keyState.key.id, rows: out.converted, snapshot: snapshotName, now, mirror: options.mirror, mirrorInstanceId: options.mirrorInstanceId });
    out.state = candidates.length > 0 || pending || crash || out.unsafe > 0 ? "converted" : "marked";
    out.changed = true;
    if (out.converted > 0) {
      log(`  keychain AAD: ${out.converted} saved password(s) converted to bound values (snapshot secrets/${snapshotName})`);
    }
    return out;
  } catch {
    log("  keychain AAD: the pass stopped on an unexpected error; nothing was recorded");
    out.state = "error";
    return out;
  } finally {
    try { db.close(); } catch { /* already closed */ }
  }
}

/** The rows whose blob LOOKS like the old form (SQLite LIKE is case-insensitive) but is not. */
function oddFormV1Rows(db) {
  try {
    return db.prepare(`SELECT id, kind, secret_sealed FROM crow_keychain WHERE secret_sealed LIKE 'enc:v1:%' AND NOT (${V1_SQL}) ORDER BY id`).all();
  } catch {
    return [];
  }
}

/**
 * Write the era state file for an era the DB mirror (or the v2 rows) already proves. Never
 * throws: a home whose secrets dir cannot be written still has the mirror, and the pass goes on.
 */
function recordEraStateFile(db, secretsDir, keyId, now, log) {
  let rows = 0;
  try { rows = Number(db.prepare(`SELECT COUNT(*) AS c FROM crow_keychain WHERE ${V2_SQL}`).get()?.c ?? 0); } catch { rows = 0; }
  try {
    writeAadState(secretsDir, { keyId, rows, snapshot: null, now });
    log("  keychain AAD: the era was proven by the database alone; its state file was written again");
    return true;
  } catch (err) {
    noteSecurityWriteFailure("era state file write", err);
    log("  keychain AAD: the era state file could not be written; the database marker still enforces it");
    return false;
  }
}

/** Record the era: the state file, then (best effort) the local-scope DB mirror. */
async function markEra(db, secretsDir, { keyId, rows, snapshot, now, mirror, mirrorInstanceId }) {
  try {
    writeAadState(secretsDir, { keyId, rows, snapshot, now });
  } catch (err) {
    noteSecurityWriteFailure("era state file write", err);
    return false;
  }
  if (mirror === false) return true;
  try {
    // The CALLER owns the instance id (the gateway's instance registry); a pass that has none —
    // the satellite, the dry-run tool — writes only the state file, which is the primary trigger.
    if (typeof mirrorInstanceId === "string" && mirrorInstanceId !== "") writeAadMirrorSync(db, mirrorInstanceId, { now });
  } catch (err) {
    // The state file is the primary trigger; the mirror is the extra one (and its writer logs).
    noteSecurityWriteFailure("era mirror write", err);
  }
  return true;
}

/** CROW_DB_PATH → `<instance data dir>/crow.db`, exactly as the gateway resolves it at boot. */
function defaultDbPath(crowHome) {
  if (process.env.CROW_DB_PATH) return process.env.CROW_DB_PATH;
  return join(resolveInstanceDataDir({ ...process.env, CROW_HOME: crowHome }), "crow.db");
}

/** `resolveCrowHome()` without throwing (a test process may have no home to resolve). */
function safeHome() {
  try { return resolveCrowHome(); } catch { return null; }
}