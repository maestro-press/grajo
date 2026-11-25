/**
 * The SETTINGS-BACKED keyed verifiers (§1a / §8 PR 3a of the keyed-token-hashes design).
 *
 * Every per-instance static token the gateway mints keeps its verifier in a dashboard setting
 * (`mcp_local_token_hash`, `mcp_board_token_hash`, … , `kiosk_announce_token_hash`). Those
 * settings live in bot-writable crow.db, so a stored verifier that is a plain function of the
 * raw secret (`sha256(token)`) is a credential a contained bot can forge. Each one is now an
 * `h1.` MAC under `<CROW_HOME>/secrets/token-hmac.key` (`servers/shared/token-mac.js`), and the
 * setting key IS the MAC's family domain: a value copied from another family's setting never
 * verifies here.
 *
 * THE OVERRIDE IS THE WHOLE ANSWER (design OQ-8, DECIDED 2026-11-23). These keys are
 * per-instance and the product only ever writes them with `{ scope: "local" }`, so a GLOBAL
 * `dashboard_settings` row for one is never a legitimate value: it is the SECOND write target a
 * contained bot has — overwrite the override, or delete it and insert a global row. Validators
 * and every other reader of the family therefore never fall back (`readStoredSettingsToken`);
 * the boot converter MOVES a legacy global-row value into this instance's override ONCE, so no
 * working token is lost and no client breaks, and alarms any global row it meets afterwards
 * (`boot/token-hmac-settings.js`) instead of reading it.
 *
 * `converted` ALWAYS comes from `familyConverted` (the secrets-side state file OR the
 * `token_hmac_era:<family>` DB mirror, failing closed) — never a literal, per PR 1's shipped
 * notes. The one process-local addition is `forceRefuseSettingsLegacy`, the boot's per-family
 * failure path: a family this process could not convert refuses its legacy values here for the
 * rest of the process. It is never persisted, so the next boot resumes.
 *
 * ERA EVIDENCE OUTSIDE THE BOOT. The gateway's pre-listen boot (`boot/token-hmac-settings.js`)
 * is the real scan. A process that validates one of these tokens without it — a unit test, a
 * CLI, a panel harness — gets the same scan once, here, from the store it is about to read (the
 * era mirror + any `h1.` value, recorded with `noteEraEvidence`), exactly as `token-store.js`
 * does for the `oauth_tokens` families. It is not a fail-open: "lost" is sticky and the
 * secrets-side state file answers "lost" on its own; production never reaches it because the
 * boot runs before listen.
 *
 * HOST-ONLY. It holds (through token-mac) the HMAC key, so it must never be reachable from bot
 * code; `tests/bot-seed-import-guard.test.js` keeps that in step.
 */
import { join } from "node:path";
import { auditLog } from "../db.js";
import { resolveCrowHome } from "../shared/crow-home.js";
import {
  ensureKey, familyConverted, keyState, macToken, noteEraEvidence, tokenMacKeyPath, verifyStored,
} from "../shared/token-mac.js";
import { readSetting } from "./dashboard/settings/registry.js";
import { getOrCreateLocalInstanceId } from "./instance-registry.js";

/**
 * Every settings-backed family this PR converts (§1a). The names ARE the setting keys, exactly
 * as `TOKEN_MAC_FAMILIES` in token-mac.js reserves them — `mcp_mail_hook_token_hash` is reserved
 * there but has no store on this release, so it is not a family here yet.
 */
export const SETTINGS_TOKEN_FAMILIES = Object.freeze([
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
]);

/**
 * The families whose RAW token is on disk under `CROW_HOME` (the path is the one the family's
 * own mint function writes). The converter re-hashes the FILE to prove a stored legacy value is
 * that token before it converts it — and it trusts the file only when it is a regular file of
 * this process's uid, not group/world-writable, in a directory that is likewise ours
 * (`trustedProofFile` in `boot/token-hmac-settings.js`), because a symlink or a loose file is
 * something a bot shell can plant. A value no trustworthy file backs is refused, never converted.
 */
export const RAW_TOKEN_FILES = Object.freeze({
  mcp_board_token_hash: "board-token",
  mcp_phone_token_hash: "phone-token",
  mcp_artifacts_token_hash: "artifacts-token",
  mcp_models_token_hash: "models-token",
  mcp_peer_relay_token_hash: join("secrets", "peer-relay-token"),
  kiosk_announce_token_hash: "kiosk-announce-token",
});

/**
 * The families a boot ROTATES (a fresh random value every start), so the converter has nothing
 * to convert: converting the stored value instead would launder whatever a bot had written
 * there. The converter RUNS that rotation itself, before it marks the family converted
 * (`BOOT_ROTATORS` in `boot/token-hmac-settings.js`), and `boot/mcp-mounts.js` rotates the same
 * families again later in the same pre-listen boot — so no boot can ever leave a family marked
 * converted over an old-style value.
 */
export const ROTATED_AT_BOOT = Object.freeze([
  "mcp_llm_cloud_token_hash",
  "mcp_services_token_hash",
  "mcp_satellite_tools_token_hash",
  "mcp_secrets_token_hash",
  "mcp_sharing_bot_token_hash",
  "mcp_reports_token_hash",
  "mcp_memory_bot_token_hash",
  "mcp_projects_bot_token_hash",
  "mcp_mail_hook_token_hash",
]);

/** A pre-conversion stored verifier: the old code's `sha256hex(token)`. */
const LEGACY_STORED = /^[0-9a-f]{64}$/;

/** The raw token file backing `family`, or null when that family has none. */
export function settingsTokenRawFile(family, home) {
  const name = RAW_TOKEN_FILES[family];
  if (!name) return null;
  return join(home || resolveCrowHome(), name);
}

export function isLegacyStored(value) {
  return typeof value === "string" && LEGACY_STORED.test(value.toLowerCase());
}

/**
 * `readSetting` with "this DB has no settings store at all" (a unit-test stub, an older store)
 * answering null. Any OTHER read failure is rethrown, so `familyConverted` fails CLOSED on it.
 */
async function settingsReader(db, key) {
  try {
    return await readSetting(db, key);
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return null;
    throw err;
  }
}

/**
 * The families `SETTINGS_TOKEN_FAMILIES` is the CONVERTER's list, not a validator gate: the
 * path-scoped factory also serves a caller that names its own key (a test harness, a family an
 * add-on adds later), so `mintSettingsToken`/`verifySettingsToken` accept any printable-ASCII
 * family (`token-mac` asserts the shape and it is the MAC's domain).
 */

/**
 * Read `family` from THIS INSTANCE'S OVERRIDE ONLY — never the global row (design OQ-8).
 *
 * Every reader of a `mcp_*_token_hash` / `kiosk_announce_token_hash` value goes through here:
 * the validators (`verifySettingsToken`), the `ensure*` mint decisions and the boot rotation's
 * old-value read. A global row is not a fallback any more; the converter deletes it or moves it
 * into the override on the conversion boot, and only alarms it afterwards.
 *
 * `null` when the store holds nothing (or the table does not exist yet: a unit-test stub). Any
 * OTHER read failure is thrown, so a validator fails closed rather than treating an I/O error as
 * "no token".
 *
 * @returns {Promise<string|null>}
 */
export async function readStoredSettingsToken(db, family) {
  let localId;
  try {
    localId = getOrCreateLocalInstanceId();
  } catch (err) {
    if (!/no such table/i.test(String(err?.message || ""))) throw err;
    return null;
  }
  try {
    const { rows } = await db.execute({
      sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ?",
      args: [family, localId],
    });
    const value = rows?.[0]?.value;
    return value === undefined || value === null ? null : String(value);
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return null;
    throw err;
  }
}

/**
 * Every stored form of `family`, one entry per store that holds one:
 * `[{ store: "local", value, instanceId } | { store: "global", value, instanceId: null }]`.
 * The VALIDATE path reads the override only (`readStoredSettingsToken`); this is for the converter
 * and the alarm scan, which must still SEE both — a value planted in the global row is a row
 * something without the key wrote, even though nothing reads it as a credential any more.
 */
export async function storedForms(db, family) {
  const forms = [];
  let localId;
  try {
    localId = getOrCreateLocalInstanceId();
  } catch (err) {
    if (!/no such table/i.test(String(err?.message || ""))) throw err;
    localId = null;
  }
  if (localId) {
    try {
      const { rows } = await db.execute({
        sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ?",
        args: [family, localId],
      });
      const value = rows?.[0]?.value;
      if (value !== undefined && value !== null) forms.push({ store: "local", value: String(value), instanceId: localId });
    } catch (err) {
      if (!/no such table/i.test(String(err?.message || ""))) throw err;
    }
  }
  try {
    const { rows } = await db.execute({
      sql: "SELECT value FROM dashboard_settings WHERE key = ?",
      args: [family],
    });
    const value = rows?.[0]?.value;
    if (value !== undefined && value !== null) forms.push({ store: "global", value: String(value), instanceId: null });
  } catch (err) {
    if (!/no such table/i.test(String(err?.message || ""))) throw err;
  }
  return forms;
}

/** Rewrite ONE store's row for `family` — the store the converter found that value in. */
export async function writeStoredForm(db, family, { store, value, instanceId }) {
  if (store === "local") {
    await db.execute({
      sql: `INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at)
            VALUES (?, ?, ?, datetime('now'))
            ON CONFLICT(key, instance_id) DO UPDATE SET
              value = excluded.value, updated_at = datetime('now')`,
      args: [family, instanceId || getOrCreateLocalInstanceId(), value],
    });
    return;
  }
  if (store === "global") {
    await db.execute({
      sql: `INSERT INTO dashboard_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')`,
      args: [family, value],
    });
    return;
  }
  throw new TypeError(`writeStoredForm needs store "local" or "global", got ${String(store)}`);
}

/**
 * Delete ONE store's row for `family`, and only while it still holds `value` (compare-and-swap).
 * The converter uses it for the two OQ-8 moves: retiring the global row it moved into the
 * override, and retiring an anomalous global row nothing may read. A row somebody changed in
 * between is left alone — a CAS that misses writes nothing.
 */
export async function deleteStoredForm(db, family, { store, value, instanceId }) {
  if (store === "local") {
    await db.execute({
      sql: "DELETE FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ? AND value = ?",
      args: [family, instanceId || getOrCreateLocalInstanceId(), String(value)],
    });
    return;
  }
  if (store === "global") {
    await db.execute({
      sql: "DELETE FROM dashboard_settings WHERE key = ? AND value = ?",
      args: [family, String(value)],
    });
    return;
  }
  throw new TypeError(`deleteStoredForm needs store "local" or "global", got ${String(store)}`);
}

// ─── era verdict, with the §M2 process-local refusal ──────────────────────

/**
 * Families whose conversion FAILED in this process (the boot's per-family failure path).
 * GATEWAY-PROCESS-ONLY, never stored: the alternative to refusing is failing OPEN, because a
 * boot that could not convert a family cannot vouch that its stored value is keyed. Cleared
 * only by `forgetForcedSettingsLegacyRefusal()` (the test seam).
 */
const forcedLegacyRefusal = new Set();

/** Refuse legacy (bare sha256) values for `family` for the rest of THIS process. */
export function forceRefuseSettingsLegacy(family) {
  if (!SETTINGS_TOKEN_FAMILIES.includes(family)) {
    throw new TypeError(`token-settings needs a known family, got ${String(family)}`);
  }
  forcedLegacyRefusal.add(family);
}

/** Test seam: forget the in-process "refuse legacy" override (one family, or all of them). */
export function forgetForcedSettingsLegacyRefusal(family) {
  if (family === undefined) forcedLegacyRefusal.clear();
  else forcedLegacyRefusal.delete(family);
}

/** `familyConverted(family)` with the DB mirror wired to this client and the §M2 override first. */
export async function settingsFamilyConverted(family, db) {
  if (forcedLegacyRefusal.has(family)) return true;
  return familyConverted(family, { readSetting: (key) => settingsReader(db, key) });
}

// ─── the once-per-process era scan (see the module header) ────────────────

/** keyPath → the evidence this process scanned, so a validator never repeats it. */
const eraEvidence = new Map();

/** Test seam: forget the once-per-process era scan. */
export function forgetSettingsTokenEvidence() {
  eraEvidence.clear();
}

/** Is there an `h1.` value in either settings store? "Could not tell" answers true (§2.6). */
export async function h1ValuesExist(db) {
  for (const [table, where] of [
    ["dashboard_settings", ""],
    ["dashboard_settings_overrides", " AND instance_id = ?"],
  ]) {
    let args = [];
    if (where) {
      try { args = [getOrCreateLocalInstanceId()]; } catch { continue; }
    }
    try {
      // eslint-disable-next-line no-await-in-loop -- at most two stores
      const { rows } = await db.execute({
        sql: `SELECT 1 AS present FROM ${table} WHERE value LIKE 'h1.%'${where} LIMIT 1`,
        args,
      });
      // The probe selects a literal, so its VALUE is checked: a stub DB that answers every
      // query with some unrelated row must not read as "an h1 value exists".
      if (rows?.some((row) => Number(row?.present) === 1)) return true;
    } catch (err) {
      if (/no such table/i.test(String(err?.message || ""))) continue;
      return true; // cannot tell → never "this box is new"
    }
  }
  return false;
}

async function scanSettingsEraEvidence(db) {
  const keyPath = tokenMacKeyPath();
  const cached = eraEvidence.get(keyPath);
  if (cached) return cached;
  // Only a KEY-LESS box needs a recorded verdict: a loaded key answers for itself, and a
  // lost/invalid key refuses whatever a scan would say.
  if (keyState() !== "first-boot") return { mirrorConverted: true, h1ValuesExist: false };
  let mirrorConverted = false;
  for (const family of SETTINGS_TOKEN_FAMILIES) {
    // eslint-disable-next-line no-await-in-loop -- thirteen families, once per process
    if (await settingsFamilyConverted(family, db)) {
      mirrorConverted = true;
      break;
    }
  }
  const h1 = await h1ValuesExist(db);
  // ONLY the innocent verdict is recorded and cached: recording "lost" from a validator's scan
  // (a route test's stub DB, a half-open database) would stick this whole process at "lost".
  if (mirrorConverted || h1) return { mirrorConverted, h1ValuesExist: h1 };
  const evidence = { mirrorConverted: false, h1ValuesExist: false };
  noteEraEvidence(evidence);
  eraEvidence.set(keyPath, evidence);
  return evidence;
}

/**
 * The key for a WRITE, created only when this really is a first boot (no key, no state file,
 * no era mirror, no `h1.` value). In the gateway the pre-listen boot has already done this; the
 * create path exists so a harness or a CLI behaves like an installed box. Never a fallback to
 * sha256, never a replacement for a lost key.
 */
export async function ensureSettingsKey(db) {
  const evidence = await scanSettingsEraEvidence(db);
  if (evidence.mirrorConverted || evidence.h1ValuesExist) return ensureKey({ allowCreate: false });
  return ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
}

/** The stored verifier of a freshly minted raw token for `family`. */
export async function mintSettingsToken(db, family, token) {
  await ensureSettingsKey(db);
  return macToken(family, token);
}

/**
 * Verify a presented token against `family`'s stored value.
 *
 * The value is read OVERRIDE-ONLY (design OQ-8): a global `dashboard_settings` row for a
 * per-instance token key is never consulted, so a bot's second write target proves nothing.
 *
 * `converted` comes from `settingsFamilyConverted`, so a bare sha256 in a converted family is
 * refused AND alarmed (log + audit row, never user-visible text) with the family as the row
 * reference. A keyed value under another family's domain, or under another keyId, never
 * verifies: the family is inside the MAC.
 *
 * @returns {Promise<boolean>}
 */
export async function verifySettingsToken(db, family, token, opts = {}) {
  if (typeof token !== "string" || token === "") return false;
  await scanSettingsEraEvidence(db);
  const stored = await readStoredSettingsToken(db, family);
  if (typeof stored !== "string" || stored === "") return false;
  const converted = await settingsFamilyConverted(family, db);
  const verdict = verifyStored(family, token, stored, {
    converted,
    rowRef: family,
    audit: typeof opts.audit === "function"
      ? opts.audit
      : (eventType, details) => auditLog(db, eventType, { details }),
  });
  return verdict.ok === true;
}