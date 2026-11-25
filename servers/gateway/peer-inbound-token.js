/**
 * The `crow_instances.auth_token_hash` store's keyed verifiers (§1b / §8 PR 4 of the
 * keyed-token-hashes design).
 *
 * A paired instance authenticates with a raw bearer; today the row keeps
 * `sha256hex(bearer)`, which is a plain function of the secret — so anything with WRITE access
 * to crow.db (a contained bot has it) could plant a value it computed and then present the
 * matching bearer as that peer. The stored value is now an `h1.` MAC under
 * `<CROW_HOME>/secrets/token-hmac.key` in the family domain `peer:inbound`
 * (`servers/shared/token-mac.js`), so a planted value cannot verify and a value copied from
 * ANOTHER family never verifies here either (the family is inside the MAC input).
 *
 * WHY A LOOKUP TRIES TWO VALUES. Rows are searched BY their stored value, and the value may be
 * either form:
 *   - `h1.<keyId>.<mac>`  — every value this version writes;
 *   - a bare sha256 hex   — every row written before the family was converted, and (after
 *                           conversion) a forged or stale row written by something that does
 *                           not hold the key.
 * So `findPeerByBearer` computes the keyed value for the presented bearer AND the old sha256,
 * and lets `verifyStored` decide: the legacy form authenticates only while `familyConverted`
 * says the family is not converted, and after that it is refused AND raises the legacy alarm
 * (§3.3, log + audit only). The legacy value is looked up in BOTH eras on purpose — that is
 * what makes a converted family see an old-style row at validation time instead of only at
 * boot. When BOTH forms match a row (a legacy twin beside the real converted row) the KEYED row
 * is verified first, so a stale or planted legacy row can never shadow the real peer.
 *
 * `converted` ALWAYS comes from `familyConverted` (state file OR the `token_hmac_era:<family>`
 * DB mirror, failing closed). It is never a literal, per PR 1's shipped notes. The one
 * process-local addition is `forceRefusePeerLegacy` — the boot's per-family failure path
 * (§M2), which must refuse in THIS process because it could not vouch for that family's rows.
 * It is never persisted, so the next boot resumes from the snapshot.
 *
 * ERA EVIDENCE OUTSIDE THE BOOT. The gateway's pre-listen boot (`boot/token-hmac-peers.js`) is
 * the real scan. A process that loads this module without it — a unit test, a CLI, a module
 * harness — gets the same scan once, here, from the store it is about to read (DB mirror + any
 * `h1.` row, recorded with `noteEraEvidence`). That is not a fail-open: "lost" is sticky, the
 * secrets-side state file still answers "lost" on its own, and production never reaches it
 * because the boot runs before listen.
 *
 * THIS MODULE IS HOST-ONLY (it holds, through token-mac, the MAC key), so it is reached in two
 * ways and never statically from a bot-reachable file:
 *   - `servers/shared/peer-bearer.js` is the seam: this module INSTALLS its `find`/`mint` there
 *     at evaluation time, and `servers/gateway/instance-registry.js` (which IS bot-reachable,
 *     through scripts/pi-bots) calls the seam instead of importing this file;
 *   - host-side callers that mint directly (the enroll route, the pairing CLI, the sharing
 *     server, the operator tools) import it themselves.
 *
 * `inbound_bearer_sha256` (see peer-credentials.js) is NOT a verifier and is never consulted
 * here: it exists only so the re-pair proof (design D4) can keep being keyed by the value the
 * peer's OWN install computes. Nothing compares a presented bearer against it.
 */
import { createHash, randomBytes } from "node:crypto";
import { auditLog } from "../db.js";
import {
  TokenMacKeyError, ensureKey, familyConverted, keyState, macToken, noteEraEvidence, tokenMacKeyPath,
  verifyStored,
} from "../shared/token-mac.js";
import { TRUSTED_PEER_SQL } from "../shared/peer-trust.js";
import { installPeerBearer } from "../shared/peer-bearer.js";
import { readSetting } from "./dashboard/settings/registry.js";

/** The fixed MAC domain of this store (§2.2/§2.3). */
export const PEER_INBOUND_FAMILY = "peer:inbound";

/** A pre-conversion stored verifier: the old code's `sha256hex(bearer)`, in either hex case. */
const LEGACY_STORED = /^[0-9a-f]{64}$/i;

/**
 * True for a bare sha256 stored value (the form the converter rewrites, §3.2).
 *
 * CASE-INSENSITIVE on purpose: `verifyStored`'s own 64-hex test is case-insensitive
 * (`HEX64` in token-mac.js) and `safeEqualHex` compares the bytes, so an UPPERCASE stored value
 * really is a working legacy credential. A lowercase-only test here would leave such a row
 * unconverted and un-alarmed at boot while the validator kept accepting it — the divergence this
 * converter exists to close. It is treated as legacy everywhere: converted, refused, alarmed.
 */
export function isLegacyStored(value) {
  return typeof value === "string" && LEGACY_STORED.test(value);
}

/** True for a stored value in the keyed form — the one that always wins a lookup. */
function isKeyedStored(value) {
  return typeof value === "string" && value.startsWith("h1.");
}

/**
 * The PRE-CONVERSION stored form of a bearer — a lookup key, the converter's input, and the
 * value the re-pair proof is keyed by (design D4). Never something a validator WRITES.
 */
export function legacyStoredHash(bearer) {
  return createHash("sha256").update(String(bearer)).digest("hex");
}

/**
 * The lookup both the validator and the boot scan use, so the two cannot drift apart: the one
 * trust predicate (PT-1) is applied INSIDE the query, and the presented bearer may match either
 * stored form.
 */
const PEER_BEARER_SQL = `SELECT rowid AS rowid, * FROM crow_instances WHERE auth_token_hash IN (?, ?) AND ${TRUSTED_PEER_SQL}`;

/**
 * `readSetting` for the era mirror, with "this DB has no settings store at all" (a unit-test
 * DB that only created `crow_instances`) answering "no mirror". Any OTHER read failure is
 * rethrown, so `familyConverted` fails CLOSED on it as designed.
 *
 * RESIDUAL, named deliberately: a database with no settings table reads as "no mirror" rather
 * than as `lost`, so on such a box the DB mirror is not what keeps the era — the secrets-side
 * STATE FILE is the primary trigger, and it is the copy no bot can reach. Production always has
 * the table, so this only shapes a bare harness; it is left as is rather than made to fail
 * closed, because a stub DB answering "no such table" would then read as "era lost" for every
 * caller in the process.
 */
async function mirrorReader(db, key) {
  try {
    return await readSetting(db, key);
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return null;
    throw err;
  }
}

// ─── era verdict, with the §M2 process-local refusal ──────────────────────

/**
 * Set when this process's boot could not convert the family. GATEWAY-PROCESS-ONLY, never
 * stored: a boot that could not vouch for the rows cannot fail OPEN, so until a later boot
 * converts them a bare sha256 is not a credential here. Cleared only by
 * `forgetForcedPeerLegacyRefusal()` (the test seam).
 */
const forcedLegacyRefusal = new Set();

/** Refuse legacy (bare sha256) values for `peer:inbound` for the rest of THIS process. */
export function forceRefusePeerLegacy() {
  forcedLegacyRefusal.add(PEER_INBOUND_FAMILY);
}

/** Test seam: forget the in-process "refuse legacy" override. */
export function forgetForcedPeerLegacyRefusal() {
  forcedLegacyRefusal.clear();
}

/** `familyConverted(family)` with the DB mirror wired to this client and the §M2 override first. */
export async function peerFamilyConverted(db) {
  if (forcedLegacyRefusal.has(PEER_INBOUND_FAMILY)) return true;
  return familyConverted(PEER_INBOUND_FAMILY, { readSetting: (key) => mirrorReader(db, key) });
}

// ─── the once-per-process era scan (see the module header) ────────────────

/** keyPath → the evidence this process scanned, so a validator never repeats it. */
const eraEvidence = new Map();

/** Test seam: forget the once-per-process era scan. */
export function forgetPeerInboundEvidence() {
  eraEvidence.clear();
}

/** Does ANY `crow_instances` row hold an `h1.` value? "Could not tell" answers true (§2.6). */
export async function h1ValuesExist(db) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT 1 AS present FROM crow_instances WHERE auth_token_hash LIKE 'h1.%' LIMIT 1",
      args: [],
    });
    // The probe selects a literal, so its VALUE is checked: a stub DB that answers every query
    // with some unrelated row must not read as "an h1. row exists".
    return rows?.some((row) => Number(row?.present) === 1) === true;
  } catch {
    // "We could not tell" is never "this box is new" (§2.6).
    return true;
  }
}

async function scanEraEvidence(db) {
  const keyPath = tokenMacKeyPath();
  const cached = eraEvidence.get(keyPath);
  if (cached) return cached;
  // Only a KEY-LESS box needs a recorded verdict: a loaded key answers for itself, and a
  // lost/invalid key refuses whatever a scan would say. On a healthy install this is the whole
  // cost (a cached-key check), and no query is added to a request.
  if (keyState() !== "first-boot") return { mirrorConverted: true, h1ValuesExist: false };
  const mirrorConverted = await peerFamilyConverted(db);
  const h1 = await h1ValuesExist(db);
  // ONLY the innocent verdict is recorded and cached: recording "lost" from a validator's scan
  // (a route test's stub DB, a half-open database) would stick this whole process at "lost".
  // Recording nothing is fail-closed, and production never reaches it (the boot runs first).
  if (mirrorConverted || h1) return { mirrorConverted, h1ValuesExist: h1 };
  const evidence = { mirrorConverted: false, h1ValuesExist: false };
  noteEraEvidence(evidence);
  eraEvidence.set(keyPath, evidence);
  return evidence;
}

/**
 * The key for a WRITE, created only when this really is a first boot (no key, no state file,
 * no DB mirror, no `h1.` row). In the gateway the pre-listen boot has already done this; the
 * create path exists so a harness or a CLI behaves like an installed box. Never a fallback to
 * sha256, never a replacement for a lost key.
 */
export async function ensurePeerKey(db) {
  const evidence = await scanEraEvidence(db);
  if (evidence.mirrorConverted || evidence.h1ValuesExist) {
    // Evidence of an era but no usable key: NEVER mint a key over it. `allowCreate` false is
    // what answers with the proper key-lost / key-invalid / key-missing error.
    return ensureKey({ allowCreate: false });
  }
  return ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
}

/** The stored verifier of a raw bearer, for the row that peer's bearer authenticates. */
export async function mintPeerInbound(db, bearer) {
  await ensurePeerKey(db);
  return macToken(PEER_INBOUND_FAMILY, String(bearer));
}

/**
 * The gateway-side counterpart of `generateAuthToken()` (instance-registry.js), which stays
 * key-free because it is reachable from bot code: the token is minted here and so is the value
 * to STORE for it.
 *
 * @param {object} db crow.db client
 * @returns {Promise<{token: string, hash: string}>} the raw bearer and its `h1.` verifier
 */
export async function mintPeerAuthToken(db) {
  const token = randomBytes(32).toString("hex");
  return { token, hash: await mintPeerInbound(db, token) };
}

/** The stored values a presented bearer may hold: the keyed form, plus the old sha256. */
export function peerInboundCandidates(bearer) {
  const out = [];
  try {
    out.push(macToken(PEER_INBOUND_FAMILY, String(bearer)));
  } catch (err) {
    // A lost/invalid key means this process can compute no `h1.` value; the legacy lookup below
    // still runs so `verifyStored` answers (and refuses) on evidence.
    if (!(err instanceof TokenMacKeyError)) throw err;
  }
  out.push(legacyStoredHash(bearer));
  return out;
}

/**
 * Find the trusted peer row a presented bearer authenticates, or null.
 *
 * Verifies with `verifyStored` under `peer:inbound` and the verdict from `familyConverted`, so a
 * legacy row in a converted family is refused AND alarmed with the row's id (never its value).
 * The trust predicate (PT-1) is part of the query, so an untrusted, paused or revoked peer is
 * never even looked at.
 *
 * A database error PROPAGATES: `validateInstanceToken` retries it on a fresh client (the
 * 2026-06-14 corruption incident), and a silent null there is what turned a database fault into
 * a total federation blackout.
 *
 * @param {object} db crow.db client
 * @param {string} bearer the raw bearer presented by the caller
 * @param {{ channel?: string }} [opts] `channel` labels the alarm's audit detail, nothing else
 * @returns {Promise<object|null>} the row, or null
 */
export async function findPeerByBearer(db, bearer, opts = {}) {
  if (typeof bearer !== "string" || bearer === "") return null;
  await scanEraEvidence(db);
  const converted = await peerFamilyConverted(db);
  // Both stored forms in ONE query. The legacy candidate is always present (it is the last
  // element); the keyed one only fills the other slot — with the same value when this process
  // cannot compute an `h1.` form at all (a lost/invalid key), which then simply finds nothing.
  const candidates = peerInboundCandidates(bearer);
  const legacy = candidates[candidates.length - 1];
  const keyed = candidates[0];
  const { rows } = await db.execute({ sql: PEER_BEARER_SQL, args: [keyed, legacy] });
  const found = Array.isArray(rows) ? rows : [];
  if (found.length === 0) return null;
  // THE KEYED FORM WINS, whatever order the store answers in. A legacy value equal to
  // `sha256(bearer)` can sit in a SECOND trusted row beside the real converted one (a stale row
  // from before the conversion, or one written by something that knows the bearer), and a
  // `rows[0]` answer would let that row shadow the real peer: in a converted family the legacy
  // value is refused, so the lookup would answer "no peer" for a peer that is right there. So
  // every keyed row is verified first; a legacy row is considered only when none qualifies
  // (which is also when its refusal + alarm is the right verdict).
  const keyedRows = found.filter((row) => isKeyedStored(row?.auth_token_hash));
  const legacyRows = found.filter((row) => !isKeyedStored(row?.auth_token_hash));
  for (const row of [...keyedRows, ...legacyRows]) {
    // By construction the row's value is one of the two candidates, so it is the value to verify —
    // and `verifyStored` decides (the legacy form only while the family is not converted).
    const verdict = verifyStored(PEER_INBOUND_FAMILY, bearer, row.auth_token_hash, {
      converted,
      rowRef: row.id ?? row.rowid ?? null,
      audit: (eventType, details) => auditLog(db, eventType, {
        details: opts.channel ? { ...details, channel: opts.channel } : details,
      }),
    });
    if (verdict.ok) return row;
  }
  return null;
}

/**
 * Verify a presented bearer against ONE row that is already in hand (the cross-host signed-call
 * path, which resolves the peer by its `X-Crow-Source` header first). Same domain, same era
 * rule, same alarm: a bare sha256 authenticates only while the family is not converted.
 *
 * @param {object} db crow.db client (the era mirror lives here)
 * @param {object|null} row a `crow_instances` row
 * @param {string} bearer the raw bearer the caller presented
 * @param {{ channel?: string }} [opts]
 * @returns {Promise<boolean>}
 */
export async function verifyPeerBearer(db, row, bearer, opts = {}) {
  const stored = row?.auth_token_hash;
  if (typeof stored !== "string" || stored === "") return false;
  if (typeof bearer !== "string" || bearer === "") return false;
  await scanEraEvidence(db);
  const converted = await peerFamilyConverted(db);
  const verdict = verifyStored(PEER_INBOUND_FAMILY, bearer, stored, {
    converted,
    rowRef: row.id ?? row.rowid ?? null,
    audit: (eventType, details) => auditLog(db, eventType, {
      details: opts.channel ? { ...details, channel: opts.channel } : details,
    }),
  });
  return verdict.ok === true;
}

// ─── the seam (servers/shared/peer-bearer.js) ─────────────────────────────
//
// `servers/gateway/instance-registry.js` is bot-reachable, so it calls these through the seam
// instead of importing this file. Loading this module IS the installation; the gateway does it
// at boot (servers/gateway/index.js) and every host-side tool that needs it imports it.
installPeerBearer({ find: findPeerByBearer, mint: mintPeerInbound });