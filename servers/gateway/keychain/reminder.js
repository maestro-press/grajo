/**
 * Keychain Export reminder (recovery keys, queue item 30, decision 2026-10-16).
 *
 * A key an extension saved to the keychain (Crow generated it, or it was kept from an older
 * install) exists only on this machine: the keychain never syncs, and backups never copy
 * secrets/. The user's passphrase-encrypted Export is the one off-machine copy. So while an
 * extension entry is in no Export, the Nest shows an info issue (health signal
 * "keychainExport"), and the install log says so.
 *
 * "In an Export" = the entry's sealed value was fingerprinted by the last export, or it came
 * in through an Import (it is in that file). A re-sealed value (a re-mint, a re-save) has a
 * new fingerprint, so it counts again. The one re-seal that is NOT a new value is the AAD
 * conversion (same plaintext, new ciphertext): `remapExportFingerprintsSync` in
 * `keychain/export-fingerprint.js` moves those fingerprints inside the conversion transaction,
 * so a converted entry neither re-appears in this reminder nor closes the off-site upload gate.
 * The fingerprints are a LOCAL setting (not in the sync allowlist): another instance's export
 * says nothing about this machine's keys. audit_log is not used: it is pruned after 90 days.
 * Manual entries are the user's own and never counted.
 */
import { readSetting, writeSetting } from "../dashboard/settings/registry.js";
import { EXPORT_FINGERPRINTS_SETTING, exportFingerprint } from "./export-fingerprint.js";
import { ensureKeychainTable } from "./store.js";

/** The local-scope setting this record lives in (see export-fingerprint.js). */
export const LAST_EXPORT_SETTING = EXPORT_FINGERPRINTS_SETTING;

const fp = exportFingerprint;

async function readState(db) {
  try {
    const v = JSON.parse((await readSetting(db, LAST_EXPORT_SETTING)) || "null");
    if (v && typeof v === "object" && v.fp && typeof v.fp === "object") return v;
  } catch { /* none or damaged: nothing counts as exported */ }
  return { at: null, fp: {} };
}

async function rows(db, keyId, { activeOnly = true, ids = null } = {}) {
  await ensureKeychainTable(db);
  const { rows: r } = await db.execute({ sql: `SELECT id, secret_sealed FROM crow_keychain WHERE kind = 'extension' AND key_id = ?${activeOnly ? " AND status = 'active'" : ""}`, args: [String(keyId || "")] });
  return ids ? r.filter((x) => ids.has(Number(x.id))) : r;
}
const activeRows = (db, keyId, ids = null) => rows(db, keyId, { ids });

/**
 * Fingerprints of every readable extension entry (any status: the Export carries removed
 * extensions' entries too). Take it BEFORE the Export is built, so an entry saved while it
 * is sealed counts as not exported (a false reminder, never a false all-clear).
 */
export async function exportSnapshot(db, keyId) {
  const fps = {};
  for (const r of await rows(db, keyId, { activeOnly: false })) fps[Number(r.id)] = fp(r.secret_sealed);
  return fps;
}

/**
 * A snapshot taken before the Export was built, with the rows the Export could NOT open taken
 * back out. Those rows were never in the file, so their current blob must not read "exported":
 * the reminder keeps listing them as not exported, and `offsiteKeyInExport` stays false for a
 * refused off-site key (its upload gate must not open on a key the owner's file does not hold).
 * The snapshot is still taken BEFORE the seal, so an entry saved while the file was built is
 * fingerprinted by neither (a false reminder, never a false all-clear).
 */
export function snapshotWithout(snapshot, ids) {
  if (!snapshot || typeof snapshot !== "object") return snapshot;
  const skip = new Set((Array.isArray(ids) ? ids : []).map(Number));
  if (skip.size === 0) return snapshot;
  const out = {};
  for (const [id, value] of Object.entries(snapshot)) if (!skip.has(Number(id))) out[id] = value;
  return out;
}

/** After an Export built from `snapshot` was sealed. */
export async function recordKeychainExport(db, keyId, snapshot = null, at = new Date()) {
  const fps = snapshot || (await exportSnapshot(db, keyId));
  await writeSetting(db, LAST_EXPORT_SETTING, JSON.stringify({ at: at.toISOString(), fp: fps }), { scope: "local" });
}

/** After an Import: the imported entries are in the file they came from. */
export async function recordKeychainImport(db, keyId, ids) {
  if (!Array.isArray(ids) || ids.length === 0) return;
  const st = await readState(db);
  for (const r of await activeRows(db, keyId, new Set(ids.map(Number)))) st.fp[Number(r.id)] = fp(r.secret_sealed);
  await writeSetting(db, LAST_EXPORT_SETTING, JSON.stringify(st), { scope: "local" });
}

export async function lastKeychainExport(db) {
  return (await readState(db)).at;
}

/**
 * Whether ONE entry's current sealed value is in the last recorded Export. The vault upload gate
 * needs a yes/no per entry (the off-site backup key), which unexportedCount cannot answer.
 */
export async function entryInLastExport(db, id) {
  await ensureKeychainTable(db);
  const row = (await db.execute({ sql: "SELECT secret_sealed FROM crow_keychain WHERE id = ?", args: [Number(id)] })).rows[0];
  if (!row) return false;
  const st = await readState(db);
  return st.fp[Number(id)] !== undefined && st.fp[Number(id)] === fp(row.secret_sealed);
}

/** Active, readable extension entries whose current sealed value is in no Export. */
export async function unexportedCount(db, keyId) {
  if (!keyId) return 0;
  const st = await readState(db);
  let n = 0;
  for (const r of await activeRows(db, keyId)) if (st.fp[Number(r.id)] !== fp(r.secret_sealed)) n++;
  return n;
}
