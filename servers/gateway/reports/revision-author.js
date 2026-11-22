/**
 * The revision author seal: proof that the OWNER saved one recipe revision.
 *
 * WHY THIS EXISTS: the source gate's third approval path (source-approvals.js) reads a report's revision
 * history and asks, for each revision that carried a block's settings, whether the OWNER put them there.
 * The row it used to read for that answer is `report_recipe_revisions.author_kind`, a plain column: it
 * says who a save claimed to be, not who wrote the revision. A revision becomes owner-written evidence
 * only when it carries a seal made under the keychain key, which no bot can read through the database.
 *
 * WHERE A SEAL LIVES: `report_state` under `revision_author:<rev>`, as JSON `{nonce, seal}` (no column,
 * and no schema change). The `revision_author:` prefix is RESERVED: a recipe block's `setState` refuses it
 * (`isReservedStateKey`, artifact-bridge.js), and only the store's own save path writes it.
 *
 * THE WRITING HALF is in store.js's `saveRecipe`, which takes an optional `authorSeal` callback: on an
 * owner save the callback makes `{nonce, seal}` before the transaction, and the state row is written in
 * the SAME transaction as the revision row, so a save that loses the compare-and-set writes no seal. A
 * bot save never passes a callback and writes no seal, and a caller that saves an owner revision without
 * one writes no seal either: such a revision is simply not owner-chain evidence. approvals.js builds the
 * callback for the owner's own save path (`ownerAuthorSealerFor`).
 *
 * THE SEAL is seal.js's `author` kind over `{reportId, rev, recipeHash, authorKind, nonce}`: the revision
 * number and the recipe hash are inside it, so a seal copied onto another revision, another report or
 * another recipe verifies for none of them.
 *
 * THE HASH IS RECOMPUTED, and this is what makes the answer worth trusting: the revision row's
 * `recipe_hash` column is a cache beside `recipe_json`, so a tampered recipe body under an intact hash
 * column would otherwise read as the revision the seal covers. A row counts only when
 * `recipeHash(JSON.parse(recipe_json))` equals that column AND the seal verifies over it. The recipe hash
 * needs no block registry (`recipe-hash.js`), so this reads exactly the hash the save wrote.
 *
 * READING IS FAIL CLOSED, ALWAYS: a missing state row, a value that is not `{nonce, seal}` in hex, a seal
 * that does not verify, an unreadable recipe body, a hash column that disagrees with the body, no
 * keychain seed and a database error all answer "not owner-written". Nothing here throws, and a read that
 * fails part way answers with the revisions it proved and no others.
 *
 * THE SEED IS A PARAMETER, not a deps member: the modules that hold the approvals seam (approvals.js and
 * source-approvals.js) load it with `approvalInternals.seedOf` and hand it over, so this module imports
 * nothing from them and there is no cycle. A seed that is absent, empty or not bytes means no revision can
 * be proved.
 */
import { recipeHash } from "./recipe-hash.js";
import { approvalSeal, newApprovalNonce, verifyApprovalSeal } from "./seal.js";

/** The `report_state` key prefix a revision's author seal lives under (reserved: no block may write it). */
export const REVISION_AUTHOR_PREFIX = "revision_author:";

/** The kind tag the shared encoder seals an owner revision under (seal.js's `author` field list). */
const AUTHOR_SEAL_KIND = "author";

/** A seal is 32 bytes as 64 lower-case hex; a nonce is 16 bytes as 32 lower-case hex. */
const SEAL_HEX = /^[0-9a-f]{64}$/;
const NONCE_HEX = /^[0-9a-f]{32}$/;

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** Are these usable keychain seed bytes? Anything else proves nothing. */
function isSeed(seed) {
  if (Buffer.isBuffer(seed)) return seed.length > 0;
  return seed instanceof Uint8Array && seed.length > 0;
}

/**
 * The `report_state` key one revision's author seal lives under. Exported for a caller that reads the seal
 * rows itself (`ownerChainAnswers` in source-approvals.js, which reads them once for a whole paged pass).
 *
 * @param {number|string} rev
 * @returns {string}
 */
export function authorKeyOf(rev) {
  return `${REVISION_AUTHOR_PREFIX}${rev}`;
}

/**
 * Make a revision's author seal: a fresh nonce and the hex HMAC over the report, the revision, that
 * revision's recipe hash, the author kind and the nonce.
 *
 * Only an owner save seals a revision (a bot's save writes no seal at all), and the caller only reaches
 * here with a loaded keychain seed: a missing one throws from the caller's own seed reader
 * (`keychain_key_missing`), and a seed that is not bytes throws `bad_seal_seed` from seal.js.
 *
 * @param {Buffer|Uint8Array} seed the keychain key's seed
 * @param {{reportId: string, rev: number, recipeHash: string, authorKind: string}} fields
 * @returns {{nonce: string, seal: string}}
 * @throws {Error} `bad_seal_field` / `bad_seal_seed`
 */
export function sealAuthorRevision(seed, { reportId, rev, recipeHash: hash, authorKind } = {}) {
  const nonce = newApprovalNonce();
  const fields = {
    reportId: text(reportId),
    rev: Number(rev),
    recipeHash: text(hash),
    authorKind: text(authorKind),
    nonce,
  };
  return { nonce, seal: approvalSeal(AUTHOR_SEAL_KIND, fields, seed) };
}

/**
 * A report's revision-author seal rows, `revision_author:<rev>` -> its stored `value_json`.
 *
 * ONE read of the whole prefix: a revision's seal row is keyed by its own number, so the rows are a map
 * rather than one query per revision. The prefix filter is repeated in JS (LIKE's `_` is a wildcard, so the
 * statement's pattern can only narrow the read): a key the exact prefix does not start is not one of these.
 * The rows are small (a 32-hex nonce and a 64-hex seal each), so a caller paging the revision rows can read
 * them once for the whole pass instead of per page.
 *
 * Never throws: a read this database refuses leaves the map empty, which proves no revision.
 *
 * @param {object} db
 * @param {string} reportId
 * @returns {Promise<Map<string, string>>}
 */
export async function ownerAuthorStates(db, reportId) {
  const states = new Map();
  try {
    if (typeof reportId !== "string" || !reportId) return states;
    const stateRows = await db.execute({
      sql: "SELECT key, value_json FROM report_state WHERE report_id = ? AND key LIKE ?",
      args: [reportId, `${REVISION_AUTHOR_PREFIX}%`],
    });
    for (const row of stateRows.rows) {
      const key = text(row.key);
      if (!key.startsWith(REVISION_AUTHOR_PREFIX)) continue;
      if (typeof row.value_json === "string") states.set(key, row.value_json);
    }
    return states;
  } catch {
    // A read this database refuses proves nothing: an empty map answers "not owner-written" for every row.
    return new Map();
  }
}

/**
 * Is ONE revision row PROVABLY owner-written? The per-row half of `ownerSealedRevisions`, reusable by a
 * caller that already holds the row and that revision's `revision_author:<rev>` value (`ownerChainAnswers`
 * in source-approvals.js, which reads the revision rows in pages and the seal rows once).
 *
 * Every check has to hold: the row's `author_kind` is `owner`, the state value parses to a 32-hex nonce and
 * a 64-hex seal, the row's `recipe_hash` column is 64 hex and EQUALS the hash recomputed from its own
 * `recipe_json`, and the seal verifies over the report, the revision, that hash, `authorKind: "owner"` and
 * the nonce under this keychain seed.
 *
 * Never throws: anything else (a missing value, a seed that is not bytes, an unreadable body) answers
 * `false`, which is the side that gates the block.
 *
 * @param {Buffer|Uint8Array|null} seed the keychain key's seed, loaded by the caller; null means none
 * @param {string} reportId
 * @param {object} row a `report_recipe_revisions` row (`rev`, `author_kind`, `recipe_json`, `recipe_hash`)
 * @param {string|null|undefined} stateValueJson that revision's `revision_author:<rev>` value_json
 * @returns {boolean}
 */
export function verifyOwnerRevisionRow(seed, reportId, row, stateValueJson) {
  try {
    if (!isSeed(seed)) return false;
    if (typeof reportId !== "string" || !reportId) return false;
    if (row == null || typeof row !== "object") return false;
    const rev = Number(row.rev);
    if (!Number.isInteger(rev) || rev < 1) return false;
    if (text(row.author_kind) !== "owner") return false;
    if (typeof stateValueJson !== "string") return false;
    let value;
    try {
      value = JSON.parse(stateValueJson);
    } catch {
      return false;
    }
    if (value == null || typeof value !== "object" || Array.isArray(value)) return false;
    const nonce = text(value.nonce);
    const seal = text(value.seal);
    if (!NONCE_HEX.test(nonce) || !SEAL_HEX.test(seal)) return false;
    const storedHash = text(row.recipe_hash);
    if (!SEAL_HEX.test(storedHash)) return false;
    let recomputed;
    try {
      recomputed = recipeHash(JSON.parse(text(row.recipe_json)));
    } catch {
      return false;
    }
    if (recomputed !== storedHash) return false;
    const fields = {
      reportId, rev, recipeHash: storedHash, authorKind: "owner", nonce,
    };
    return verifyApprovalSeal(AUTHOR_SEAL_KIND, fields, seal, seed) === true;
  } catch {
    return false;
  }
}

/**
 * The revisions up to `upToRev` that are PROVABLY owner-written, as a set of revision numbers.
 *
 * One read of the revision rows and one read of the report's `revision_author:` state rows, then one
 * `verifyOwnerRevisionRow` per row. (`ownerChainAnswers` in source-approvals.js is the caller that pages
 * the revision rows instead of reading them in one go; it shares the same per-row check.)
 *
 * Never throws: anything else (and any read the database refuses) leaves that revision out of the set.
 *
 * @param {object} db
 * @param {Buffer|Uint8Array|null} seed the keychain key's seed, loaded by the caller; null means none
 * @param {string} reportId
 * @param {number} upToRev the newest revision the caller cares about (the head being previewed)
 * @returns {Promise<Set<number>>}
 */
export async function ownerSealedRevisions(db, seed, reportId, upToRev) {
  const sealed = new Set();
  try {
    if (typeof reportId !== "string" || !reportId) return sealed;
    if (!isSeed(seed)) return sealed;
    const head = Number(upToRev);
    if (!Number.isInteger(head) || head < 1) return sealed;

    const revisions = await db.execute({
      sql: `SELECT rev, author_kind, recipe_json, recipe_hash FROM report_recipe_revisions
             WHERE report_id = ? AND rev <= ? ORDER BY rev ASC`,
      args: [reportId, head],
    });
    const states = await ownerAuthorStates(db, reportId);
    for (const row of revisions.rows) {
      const rev = Number(row.rev);
      if (!Number.isInteger(rev) || rev < 1) continue;
      if (verifyOwnerRevisionRow(seed, reportId, row, states.get(authorKeyOf(rev)))) sealed.add(rev);
    }
    return sealed;
  } catch {
    // A read this database refuses proves nothing: answer with what was already proved, and no more.
    return sealed;
  }
}