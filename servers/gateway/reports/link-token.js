/**
 * The `report_link_tokens.token_hash` store's keyed verifiers (§8 PR 5a of the keyed-token-hashes
 * design), family `report:link`.
 *
 * A report link is a 43-character raw token in a mail; the row keeps a verifier of it. That used to
 * be `sha256hex(token)`, a plain function of the secret, so anything with WRITE access to crow.db
 * (a contained bot has it) could insert a link row for an approved recipient (the approval nonce is
 * readable) and then read the report and comment as that recipient through the PUBLIC door. The
 * stored value is now an `h1.` MAC under `<CROW_HOME>/secrets/token-hmac.key` in the family domain
 * `report:link` (`servers/shared/token-mac.js`), so a planted value cannot verify, and a value
 * copied from ANOTHER family never verifies here either (the family is inside the MAC input).
 *
 * A LOOKUP TRIES TWO VALUES (the shape of `peer-inbound-token.js`): the keyed form and the old
 * sha256. The legacy form authenticates only while `familyConverted` says the family is not
 * converted; after that it is refused AND alarmed (`token_legacy_form`, row id only). A keyed row
 * is preferred over a legacy twin. A lost or invalid key refuses (fail closed): the resolve answers
 * its existing `unknown`.
 *
 * NOT THE COMMENT-FORM NONCE. The public door binds its comment-form nonce to the sha256 of the
 * RAW token from the URL (the plain helper in links.js), never to the stored value, so a form minted before the conversion keeps verifying after it. That helper is unchanged.
 *
 * `converted` always comes from `familyConverted` (state file OR the DB mirror, failing closed);
 * the one process-local addition is `forceRefuseReportLinkLegacy`, the boot's failure path.
 *
 * REACHABILITY. This module holds the MAC key through token-mac, so it must not be reachable from a
 * bot entry; `tests/bot-seed-import-guard.test.js` is what proves that. The public-link listener
 * (a separate minimal process) never imports it.
 */
import { createHash } from "node:crypto";
import { auditLog } from "../../db.js";
import {
  TokenMacKeyError, ensureKey, familyConverted, keyState, macToken, noteEraEvidence, tokenMacKeyPath,
  verifyStored,
} from "../../shared/token-mac.js";
import { readSetting } from "../dashboard/settings/registry.js";

/** The fixed MAC domain of this store. */
export const REPORT_LINK_FAMILY = "report:link";

const LEGACY_STORED = /^[0-9a-f]{64}$/i;

/** True for a bare sha256 stored value (either hex case counts as legacy, like `verifyStored`). */
export function isLegacyStored(value) {
  return typeof value === "string" && LEGACY_STORED.test(value);
}

function isKeyedStored(value) {
  return typeof value === "string" && value.startsWith("h1.");
}

/** The pre-conversion stored form of a raw token: a lookup key and the converter's input. */
export function legacyLinkHash(raw) {
  return createHash("sha256").update(String(raw), "utf8").digest("hex");
}

async function mirrorReader(db, key) {
  try {
    return await readSetting(db, key);
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return null;
    throw err;
  }
}

const forcedLegacyRefusal = new Set();

/** Refuse legacy (bare sha256) link values for the rest of THIS process (boot failure path). */
export function forceRefuseReportLinkLegacy() {
  forcedLegacyRefusal.add(REPORT_LINK_FAMILY);
}

/** Test seam: forget the in-process refusal. */
export function forgetForcedReportLinkLegacyRefusal() {
  forcedLegacyRefusal.clear();
}

/** `familyConverted` with the DB mirror wired to this client and the process-local refusal first. */
export async function reportLinkFamilyConverted(db) {
  if (forcedLegacyRefusal.has(REPORT_LINK_FAMILY)) return true;
  return familyConverted(REPORT_LINK_FAMILY, { readSetting: (key) => mirrorReader(db, key) });
}

const eraEvidence = new Map();

/** Test seam: forget the once-per-process era scan. */
export function forgetReportLinkEvidence() {
  eraEvidence.clear();
}

/** Does ANY link row hold an `h1.` value? "Could not tell" answers true. */
export async function h1ValuesExist(db) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT 1 AS present FROM report_link_tokens WHERE token_hash LIKE 'h1.%' LIMIT 1",
      args: [],
    });
    return rows?.some((row) => Number(row?.present) === 1) === true;
  } catch (err) {
    // No table at all is a store with no link rows: no era evidence there.
    if (/no such table/i.test(String(err?.message || ""))) return false;
    return true;
  }
}

async function scanEraEvidence(db) {
  const keyPath = tokenMacKeyPath();
  const cached = eraEvidence.get(keyPath);
  if (cached) return cached;
  if (keyState() !== "first-boot") return { mirrorConverted: true, h1ValuesExist: false };
  const mirrorConverted = await reportLinkFamilyConverted(db);
  const h1 = await h1ValuesExist(db);
  if (mirrorConverted || h1) return { mirrorConverted, h1ValuesExist: h1 };
  const evidence = { mirrorConverted: false, h1ValuesExist: false };
  noteEraEvidence(evidence);
  eraEvidence.set(keyPath, evidence);
  return evidence;
}

/** The key for a WRITE, created only on a true first boot; never a replacement for a lost key. */
export async function ensureReportLinkKey(db) {
  const evidence = await scanEraEvidence(db);
  if (evidence.mirrorConverted || evidence.h1ValuesExist) return ensureKey({ allowCreate: false });
  return ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
}

/** The stored verifier for a freshly minted raw token. Throws on a key problem (never sha256). */
export async function mintReportLinkHash(db, raw) {
  await ensureReportLinkKey(db);
  return macToken(REPORT_LINK_FAMILY, String(raw));
}

/** The stored values a presented token may hold: the keyed form (when computable), then sha256. */
export function reportLinkCandidates(raw) {
  const out = [];
  try {
    out.push(macToken(REPORT_LINK_FAMILY, String(raw)));
  } catch (err) {
    if (!(err instanceof TokenMacKeyError)) throw err;
  }
  out.push(legacyLinkHash(raw));
  return out;
}

/**
 * Find the link row (selected with `columns`) a presented raw token authenticates, or null.
 * `verifyStored` decides: the legacy form only while the family is unconverted, otherwise refused
 * and alarmed with the row id. Keyed rows are verified before legacy ones.
 *
 * A database error PROPAGATES to the caller (which answers `unknown`).
 */
export async function findLinkRowByToken(db, raw, { columns }) {
  if (typeof raw !== "string" || raw === "") return null;
  await scanEraEvidence(db);
  const converted = await reportLinkFamilyConverted(db);
  const candidates = reportLinkCandidates(raw);
  const legacy = candidates[candidates.length - 1];
  const keyed = candidates[0];
  const { rows } = await db.execute({
    sql: `SELECT ${columns} FROM report_link_tokens WHERE token_hash IN (?, ?)`,
    args: [keyed, legacy],
  });
  const found = Array.isArray(rows) ? rows : [];
  const ordered = [
    ...found.filter((row) => isKeyedStored(row?.token_hash)),
    ...found.filter((row) => !isKeyedStored(row?.token_hash)),
  ];
  for (const row of ordered) {
    const verdict = verifyStored(REPORT_LINK_FAMILY, raw, row.token_hash, {
      converted,
      rowRef: row.id ?? null,
      audit: (eventType, details) => auditLog(db, eventType, { details }),
    });
    if (verdict.ok) return row;
  }
  return null;
}
