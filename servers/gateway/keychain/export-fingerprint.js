/**
 * The keychain Export's fingerprint record — the one thing that remembers WHICH sealed blobs the
 * owner's passphrase-encrypted Export holds (`servers/gateway/keychain/reminder.js` writes it, the
 * off-site backup upload gate reads it through `offsiteKeyInExport`).
 *
 * A fingerprint is `sha256(secret_sealed)` (32 hex chars): the record names a row id and a blob,
 * never a value, so it can live in a dashboard setting. That means a blob that is RE-SEALED with
 * new ciphertext — the AAD conversion (`boot/keychain-aad.js` seals every v1 row v2, same
 * plaintext) — no longer matches its fingerprint: the Export would look stale, the reminder would
 * light up, and the off-site upload would stop for a key the owner had already exported.
 *
 * `remapExportFingerprintsSync` moves each converted row's fingerprint from the old blob's hash to
 * the new one, inside the conversion's own transaction, and only when the stored fingerprint is
 * still the OLD blob's (a later Export's fingerprint is never overwritten). Kept out of
 * reminder.js so the boot pass (which must not reach the dashboard settings registry) can share
 * the exact hash and key name.
 */
import { createHash } from "node:crypto";

/** The local-scope dashboard setting the Export fingerprints live in. */
export const EXPORT_FINGERPRINTS_SETTING = "keychain_export_fingerprints";

/** The fingerprint of one sealed blob: sha256, 32 hex chars. */
export function exportFingerprint(sealed) {
  return createHash("sha256").update(String(sealed)).digest("hex").slice(0, 32);
}

/**
 * After a conversion: point every converted row's fingerprint at its new blob. `pairs` is
 * `[{ id, from, to }]` (old hash → new hash). Returns how many fingerprints moved. Never throws:
 * a database without the settings tables simply has no fingerprints to fix.
 */
export function remapExportFingerprintsSync(rawDb, pairs) {
  if (!rawDb || typeof rawDb.prepare !== "function" || !Array.isArray(pairs) || pairs.length === 0) return 0;
  const byId = new Map(pairs.map((p) => [String(p.id), p]));
  let moved = 0;
  const targets = [
    { table: "dashboard_settings_overrides", scoped: true },
    { table: "dashboard_settings", scoped: false },
  ];
  for (const { table, scoped } of targets) {
    let rows;
    try {
      rows = rawDb.prepare(`SELECT ${scoped ? "instance_id, " : ""}value FROM ${table} WHERE key = ?`).all(EXPORT_FINGERPRINTS_SETTING);
    } catch {
      continue; // no such table on an old store
    }
    for (const row of rows) {
      let doc;
      try { doc = JSON.parse(String(row.value ?? "")); } catch { continue; }
      if (!doc || typeof doc !== "object" || !doc.fp || typeof doc.fp !== "object") continue;
      let changed = 0;
      for (const [id, fingerprint] of Object.entries(doc.fp)) {
        const pair = byId.get(String(id));
        if (!pair || pair.from !== fingerprint) continue;
        doc.fp[id] = pair.to;
        changed += 1;
      }
      if (changed === 0) continue;
      try {
        if (scoped) {
          rawDb.prepare(`UPDATE ${table} SET value = ? WHERE key = ? AND instance_id = ?`)
            .run(JSON.stringify(doc), EXPORT_FINGERPRINTS_SETTING, row.instance_id);
        } else {
          rawDb.prepare(`UPDATE ${table} SET value = ? WHERE key = ?`).run(JSON.stringify(doc), EXPORT_FINGERPRINTS_SETTING);
        }
        moved += changed;
      } catch { /* the setting is not this pass's to fix */ }
    }
  }
  return moved;
}