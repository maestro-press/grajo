/**
 * The `oauth_tokens` store's keyed verifiers (§8 PR 2 of the keyed-token-hashes design).
 *
 * Three credential families share this one table, and each gets its own MAC domain
 * (`servers/shared/token-mac.js`):
 *
 *   oauth:access       token_type='access'  AND client_id <> 'dashboard'
 *   oauth:refresh      token_type='refresh' (whatever its client — a refresh row is never a session)
 *   dashboard:session  token_type='access'  AND client_id = 'dashboard'
 *
 * The three predicates are disjoint and together cover every row the schema's CHECK
 * allows (`token_type IN ('access','refresh')` in scripts/init-db.js and in
 * auth.js's initOAuthTables), so the boot converter visits each row in exactly one
 * family.
 *
 * WHY A LOOKUP TRIES TWO VALUES. Rows are found BY their stored value (it is the
 * primary key), and the stored value may be either form:
 *   - `h1.<keyId>.<mac>`  — every row this version writes;
 *   - a bare sha256 hex   — every row written before the family was converted, and
 *                           (after conversion) a forged or stale row written by
 *                           something that does not hold the key.
 * So `findTokenRow` computes the keyed value for the presented token AND the old
 * sha256, and lets `verifyStored` decide: the legacy form authenticates only while
 * `familyConverted` is false, and after that it is refused AND raises the legacy alarm
 * (§3.3). The legacy value is looked up in BOTH eras on purpose — that is what makes a
 * converted family see an old-style row at validation time instead of only at boot.
 *
 * `converted` ALWAYS comes from `familyConverted` (state file OR DB mirror, failing
 * closed). It is never a literal: the PR 1 shipped notes require it (§8). The one
 * process-local addition is `forceRefuseLegacy` — the boot's per-family failure path
 * (§M2), which must refuse in THIS process because it could not vouch for that
 * family's rows. It is never persisted; the next boot resumes from the snapshot.
 *
 * ERA EVIDENCE OUTSIDE THE BOOT. The gateway's pre-listen boot (`boot/token-hmac.js`)
 * is the real scan. A process that loads `auth.js`/`dashboard/auth.js` without that
 * boot — a unit test, a CLI — gets the same scan once, here, from the store it is
 * about to read (DB mirror + any `h1.` row, recorded with `noteEraEvidence`). That is
 * not a fail-open: the verdict is sticky ("lost" is never downgraded), the secrets-side
 * state file still answers "lost" on its own, and production never reaches it because
 * the boot runs before listen. It lets the module-level harnesses keep an unconverted
 * install working exactly as §2.6 row 4 describes.
 */
import { createHash } from "node:crypto";
import { auditLog } from "../db.js";
import {
  TokenMacKeyError, ensureKey, eraSettingKey, familyConverted, keyState, legacyAlarm, macToken,
  noteEraEvidence, tokenMacKeyPath, verifyStored,
} from "../shared/token-mac.js";
import { readSetting } from "./dashboard/settings/registry.js";

/** OAuth access tokens (everything that is not a dashboard session). */
export const OAUTH_ACCESS_FAMILY = "oauth:access";
/** OAuth refresh tokens. */
export const OAUTH_REFRESH_FAMILY = "oauth:refresh";
/** Dashboard session rows (`client_id='dashboard'`), the cookie half of the design. */
export const DASHBOARD_SESSION_FAMILY = "dashboard:session";

/** The families this module owns — the three the boot converter visits. */
export const TOKEN_STORE_FAMILIES = Object.freeze([
  OAUTH_ACCESS_FAMILY,
  OAUTH_REFRESH_FAMILY,
  DASHBOARD_SESSION_FAMILY,
]);

/**
 * The SQL predicate that selects exactly one family's rows. Exported because the boot
 * converter and its post-conversion scan must select the SAME rows the validators do.
 */
export const FAMILY_PREDICATE = Object.freeze({
  [OAUTH_ACCESS_FAMILY]: "token_type = 'access' AND client_id <> 'dashboard'",
  [OAUTH_REFRESH_FAMILY]: "token_type = 'refresh'",
  [DASHBOARD_SESSION_FAMILY]: "token_type = 'access' AND client_id = 'dashboard'",
});

/** A pre-conversion stored verifier: today's `sha256hex(token)`, in either hex case. */
const LEGACY_STORED = /^[0-9a-f]{64}$/i;

/**
 * True for a bare sha256 stored value (the form the converter rewrites, §3.2).
 *
 * CASE-INSENSITIVE, matching `verifyStored`'s own `HEX64` (case-insensitive) + byte compare in
 * token-mac.js: an UPPERCASE stored value is a working legacy credential there, so a
 * lowercase-only test here would leave it unconverted and un-alarmed at boot while the validator
 * kept accepting it. It is treated as legacy everywhere — converted, refused, alarmed.
 */
export function isLegacyStored(value) {
  return typeof value === "string" && LEGACY_STORED.test(value);
}

/**
 * The PRE-CONVERSION stored form of a token — a lookup key and the converter's input,
 * never something a validator writes. `macFromLegacy` turns it into this era's `h1.`
 * value offline.
 */
export function legacyStoredHash(token) {
  return createHash("sha256").update(String(token)).digest("hex");
}

/**
 * The one definition of the era mirror read, with "this DB has no settings store at all"
 * (a unit-test DB that only created `oauth_tokens`) answering "no mirror". Any OTHER
 * read failure is rethrown, so `familyConverted` fails CLOSED on it as designed.
 *
 * RESIDUAL, named deliberately: a database without the settings table reads as "no mirror"
 * rather than "lost". The secrets-side STATE FILE is the primary trigger for the era (and the
 * copy no bot can reach), so this only shapes a bare harness; it stays as is because a stub DB
 * answering "no such table" would otherwise read as "era lost" for every caller.
 */
async function mirrorReader(db, key) {
  try {
    return await readSetting(db, key);
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return null;
    throw err;
  }
}

/**
 * Families whose conversion FAILED in this process (the boot's per-family failure path, §M2).
 *
 * This is a GATEWAY-PROCESS-ONLY override, never a stored era: nothing is written for it, so
 * the next boot still resumes from that family's rollback snapshot and converts. It exists
 * because the alternative to refusing is failing OPEN — a boot whose converter threw for a
 * family cannot vouch that its rows are converted, so until a later boot does, a bare sha256
 * there is not a credential. Cleared only by `forgetForcedLegacyRefusal()` (the test seam).
 */
const forcedLegacyRefusal = new Set();

/**
 * Refuse legacy (bare sha256) values for `family` for the rest of THIS process (§M2).
 *
 * Consulted FIRST by `tokenFamilyConverted`, so every validator in this process — the OAuth
 * fallback, the session readers, `viewerOf` — sees the family as converted and refuses (and
 * alarms) an old-style row instead of accepting it.
 */
export function forceRefuseLegacy(family) {
  if (!FAMILY_PREDICATE[family]) throw new TypeError(`token-store needs a known family, got ${String(family)}`);
  forcedLegacyRefusal.add(family);
}

/** Test seam: forget the in-process "refuse legacy" override (one family, or all of them). */
export function forgetForcedLegacyRefusal(family) {
  if (family === undefined) forcedLegacyRefusal.clear();
  else forcedLegacyRefusal.delete(family);
}

/** `familyConverted(family)` with the DB mirror wired to this client and the §M2 override first. */
export async function tokenFamilyConverted(family, db) {
  // FIRST: a family this process failed to convert refuses legacy values whatever the disk says.
  if (forcedLegacyRefusal.has(family)) return true;
  return familyConverted(family, { readSetting: (key) => mirrorReader(db, key) });
}

// ─── the once-per-process era scan (see the module header) ─────────────────

/** keyPath → the evidence this process scanned, so a validator never repeats it. */
const eraEvidence = new Map();

/** Test seam: forget the once-per-process era scan. */
export function forgetTokenStoreEvidence() {
  eraEvidence.clear();
}

async function scanEraEvidence(db) {
  const keyPath = tokenMacKeyPath();
  const cached = eraEvidence.get(keyPath);
  if (cached) return cached;
  // Only a KEY-LESS box needs a recorded verdict: a loaded key answers for itself, and a
  // lost/invalid key refuses whatever a scan would say. On a healthy install this is the
  // whole cost (a cached-key check), and no query is added to a request.
  if (keyState() !== "first-boot") return { mirrorConverted: true, h1ValuesExist: false };
  let mirrorConverted = false;
  for (const family of TOKEN_STORE_FAMILIES) {
    if (await tokenFamilyConverted(family, db)) {
      mirrorConverted = true;
      break;
    }
  }
  let h1ValuesExist;
  try {
    const { rows } = await db.execute({
      sql: "SELECT 1 AS present FROM oauth_tokens WHERE token LIKE 'h1.%' LIMIT 1",
      args: [],
    });
    // The probe selects a literal, so its VALUE is checked: a stub DB that answers every
    // query with some unrelated row must not read as "an h1. row exists".
    h1ValuesExist = rows.some((row) => Number(row?.present) === 1);
  } catch {
    // "We could not tell" is never "this box is new" (§2.6).
    h1ValuesExist = true;
  }
  // ONLY the innocent verdict is recorded and cached. The boot scan (`boot/token-hmac.js`)
  // is the trusted one and records "lost" when it finds evidence; a validator's scan is not
  // (a route test's stub DB, a half-open database), and recording "lost" from it would stick
  // this whole process at "lost". Recording nothing is fail-closed: with evidence present
  // and no key, the key-less legacy fall-through is already closed, so the refusal stands.
  if (mirrorConverted || h1ValuesExist) return { mirrorConverted, h1ValuesExist };
  const evidence = { mirrorConverted: false, h1ValuesExist: false };
  noteEraEvidence(evidence);
  eraEvidence.set(keyPath, evidence);
  return evidence;
}

/**
 * The key for a WRITE, created only when this really is a first boot (no key, no state
 * file, no DB mirror, no `h1.` row). In the gateway the pre-listen boot has already
 * done this, so a writer just loads the cached key; the create path only exists so a
 * module-level harness (a test, a CLI) behaves like an installed box instead of failing
 * every login. Never a fallback to sha256, never a replacement for a lost key.
 */
export async function ensureStoreKey(db) {
  const evidence = await scanEraEvidence(db);
  if (evidence.mirrorConverted || evidence.h1ValuesExist) {
    // Evidence of an era but no usable key: NEVER mint a key over it. `allowCreate: false`
    // is what answers with the proper key-lost / key-invalid / key-missing error, and it
    // records no boot verdict (a validator's or a stub reader's scan is not the boot).
    return ensureKey({ allowCreate: false });
  }
  return ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
}

/** Store the verifier of a freshly minted raw token for `family`. */
export async function mintStoreToken(db, family, token) {
  await ensureStoreKey(db);
  return macToken(family, token);
}

/** The stored values a presented token may hold: the keyed form, plus the old sha256. */
export function storedCandidates(family, token) {
  const out = [];
  try {
    out.push(macToken(family, token));
  } catch (err) {
    // A lost/invalid key means this process can compute no `h1.` value; the legacy
    // lookup below still runs so `verifyStored` answers (and refuses) on evidence.
    if (!(err instanceof TokenMacKeyError)) throw err;
  }
  out.push(legacyStoredHash(token));
  return out;
}

/**
 * Find the live row for a presented token, or null.
 *
 * Verifies with `verifyStored` under `family` and the `converted` verdict from
 * `familyConverted`, so a legacy row in a converted family is refused AND alarmed with
 * the row's id (never its value).
 *
 * @param {object} db crow.db client
 * @param {string} family one of TOKEN_STORE_FAMILIES
 * @param {string} token the raw token presented by the caller
 * @param {{ extraWhere?: string, extraArgs?: any[], orderBy?: string }} [opts]
 *        `extraWhere` is appended inside the family condition (it starts with " AND ").
 * @returns {Promise<object|null>} the row (`rowid`, `token`, and the table's columns)
 */
export async function findTokenRow(db, family, token, opts = {}) {
  const predicate = FAMILY_PREDICATE[family];
  if (!predicate) throw new TypeError(`token-store needs a known family, got ${String(family)}`);
  if (typeof token !== "string" || token === "") return null;
  const { extraWhere = "", extraArgs = [], orderBy = "" } = opts;
  await scanEraEvidence(db);
  const converted = await tokenFamilyConverted(family, db);
  for (const candidate of storedCandidates(family, token)) {
    // eslint-disable-next-line no-await-in-loop -- at most two candidates
    const { rows } = await db.execute({
      sql: `SELECT rowid AS rowid, * FROM oauth_tokens WHERE token = ? AND (${predicate})${extraWhere}${orderBy}`,
      args: [candidate, ...extraArgs],
    });
    const row = rows[0];
    if (!row) continue;
    const verdict = verifyStored(family, token, candidate, {
      converted,
      rowRef: row.rowid ?? null,
      audit: (eventType, details) => auditLog(db, eventType, { details }),
    });
    if (verdict.ok) return row;
  }
  return null;
}

/**
 * Revoke a token in every form it may be stored under: the keyed value now, and the
 * pre-conversion sha256 (§ "revocation paths must match both forms"). Unfiltered by
 * family, like the `DELETE … WHERE token = ?` this replaces: the stored value is the
 * primary key, and only a row minted from this raw token can hold either candidate.
 *
 * @returns {Promise<number>} rows deleted
 */
export async function deleteTokenRow(db, family, token) {
  if (typeof token !== "string" || token === "") return 0;
  let deleted = 0;
  for (const candidate of storedCandidates(family, token)) {
    // eslint-disable-next-line no-await-in-loop -- at most two candidates
    const res = await db.execute({ sql: "DELETE FROM oauth_tokens WHERE token = ?", args: [candidate] });
    deleted += Number(res?.rowsAffected ?? 0) || 0;
  }
  return deleted;
}

/**
 * Every dashboard session EXCEPT the one holding `keep` — the password-change rule in
 * dashboard/auth.js `setPassword`. Both stored forms of the kept token are excluded, so
 * a password change during the (crash/pending) unconverted state never signs the
 * changing device out.
 */
export async function deleteDashboardSessionsExcept(db, family, keep) {
  const candidates = keep ? storedCandidates(family, keep) : [];
  const placeholders = candidates.map(() => "?").join(", ");
  const sql = candidates.length
    ? `DELETE FROM oauth_tokens WHERE client_id = 'dashboard' AND token NOT IN (${placeholders})`
    : "DELETE FROM oauth_tokens WHERE client_id = 'dashboard'";
  const res = await db.execute({ sql, args: candidates });
  return Number(res?.rowsAffected ?? 0) || 0;
}

export { eraSettingKey, legacyAlarm };