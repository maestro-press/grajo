/**
 * Source approvals: the owner's OK for one draft block's exact settings, and the rule a gated preview
 * reads before any source runs at all.
 *
 * WHY THIS EXISTS: a live report always runs its sealed revision, so a bot that saves a new source into
 * a live report changes nothing until the owner goes live on it. A PREVIEW is different: it runs the
 * head revision, which a bot may have written. Without a gate, a bot could name another mailbox, another
 * URL or another file and have the very next preview read it. So a preview runs a source-shaped block
 * only when its CONTENT is approved, in one of three ways:
 *
 *   (a) the block's exact `{type, settings}` (its settings hash, under any block id) appears in the
 *       report's VERIFIED live set recipe, which is the revision the owner sealed and nobody edits;
 *   (b) the owner approved that block id at that exact settings hash as a draft block (`approveSource`),
 *       which is stored in `report_state` under `source_approval:<blockId>`;
 *   (c) that exact settings hash, under that block id, has an UNBROKEN owner-introduced history: the
 *       owner put these settings there at one revision, and every revision from that one up to the head
 *       being previewed carries the same id at the same hash, with no gap. "The owner put them there"
 *       means that revision carries a SEALED author proof (`revision-author.js`: seal.js's `author` kind
 *       over the report, the revision and that revision's recipe hash, under the keychain key) — the
 *       `author_kind` column alone is not evidence, because it is a plain column any writer can set.
 *
 * Everything else is gated, whoever asked for the preview and whoever saved the recipe last: a later
 * owner save of a block a bot introduced is not an approval, the owner's removal followed by a bot's
 * re-add of the identical settings is not one either, and a bot's save of a block the owner wrote stays
 * ungated only while the settings are identical, because the owner first put that content there and
 * nothing took it away in between.
 *
 * WHICH PREVIEWS ARE GATED: every `preview` run. A scheduled or manual run executes the sealed live
 * revision, which the owner approved, so it is not gated.
 *
 * Anything else is the one sentence `Source <blockId> is waiting for your OK`, and the executor turns it
 * into a source error BEFORE the block's `run` is called: no request, no mailbox read, no file read. A
 * `kind: "custom"` block is gated the same way (a bot changing its `params` is a different step input
 * to approve), on top of its own step approval rail (steps.js).
 *
 * REVISIONS SAVED BEFORE THE AUTHOR SEAL EXISTED are not owner-chain evidence: they carry no
 * `revision_author:<rev>` proof, so a history that leans on one is gated where it used to be open (fail
 * closed). The owner has two ways forward, both already in place: approve the block's settings as a draft
 * source (`approveSource`, path b), or save the recipe again (`ownerSaveRecipe` seals that revision) and
 * go live on it (path a). Both live instance databases held zero reports when this shipped, so nothing
 * live changed behaviour.
 *
 * `mail_alerts` has one extra rule, in both cases: the block's `accountId` must be the account the
 * report is about. That account is the VERIFIED live set's sealed sender when the live set verifies, and
 * otherwise the report row's own `sender_account_id` ONLY behind the report's own SENDER SEAL
 * (`senderSealVerifies`, sender-seal.js), which the owner's settings save writes over the account it puts
 * on the row. A live set is read here for a caller that hands none, which is what a PREVIEW does, so the
 * row fallback is for a report with no live set at all. The unsealed column is never trusted on its own:
 * `updateSettings` is the owner's route, and a direct UPDATE of `sender_account_id` would otherwise point
 * a never-live report's mail block at another mailbox. A report that was never live and whose sender was
 * set some other way therefore names no account, and its mail block waits like any other unapproved
 * source, whatever its head revision is. Crow Mail's anti-goal is that no bot reads mail outside a
 * drafting turn; a bot proposing a label is fine, a bot pointing the report at a mailbox the owner never
 * chose is not. Keep `sender_account_id` owner-only as well: it is the account a draft's mail block is
 * measured against.
 *
 * REPORTS WHOSE SENDER PREDATES THE SENDER SEAL have no `sender_seal` row, so a draft preview does not
 * trust their row sender. The owner re-saves the sender in the report's settings (the same value is fine)
 * and it is sealed. A live report is unaffected, because the live seal already covers the sender.
 *
 * There is no second account approval here either: the one account the report names is the only one, and
 * a report that names none (a draft with no sender, or a seal that no longer verifies over a row that
 * holds no account) answers "not ok" for mail.
 *
 * THE STORE: an approval is `{settingsHash, nonce, seal}` in `report_state`. That store is a block's
 * shared key/value space, so the whole `source_approval:` prefix is RESERVED: the executor's block
 * `setState` seam refuses it (`isReservedStateKey`, artifact-bridge.js), and only this module (the
 * gateway's own code, never a recipe) writes it. A revoke writes `null`, which drops the seal: an old
 * seal can never re-approve a row (the same rule as every other approval in this tree). The
 * `revision_author:` prefix is reserved for the same reason, and belongs to revision-author.js. So is
 * the `sender_seal` key, which belongs to sender-seal.js.
 *
 * THE SEAL: an HMAC over `{reportId, blockId, settingsHash, nonce}` as seal.js's `source` kind, under the
 * reports seal domain (`seal.js`'s `approvalSealKey`, the subkey derived from the keychain seed) and in
 * seal.js's own length-prefixed, type-tagged, version-tagged encoding. The field list is pinned in
 * seal.js beside every other kind's, and `reports-seal.test.js` pins that list. Verification is constant
 * time and never throws.
 *
 * REPLAY, and its limit: a revoke nulls the row, so an old seal cannot re-approve through this module. A
 * direct SQL writer that copied an old `source_approval:` row back after a revoke would be re-approving
 * with it until the row changes again, which is the limit every approval kind in seal.js shares: a seal
 * is a tamper check over content, not a clock and not a capability.
 *
 * STALENESS: an approval names one settings hash. `settingsHashOf` is the sha256 of the canonical JSON of
 * `{type, settings}`, with the block's `id` left out on purpose: renaming a block id does not change what
 * the owner approved, but the id stays the APPROVAL KEY, so approvals do not follow a block around. A
 * single setting changed anywhere (a label, a folder, `sinceDays`, a URL's host, path or query, a method)
 * is a different hash, so the approval stops applying and the block waits for the owner again.
 *
 * `deps` is the approvals seam (`loadSeed`, `now`, `registry`), read through `approvalInternals`.
 */
import { createHash } from "node:crypto";
import { approvalInternals, verifyLive } from "./approvals.js";
import { BLOCK_ID_RE, BLOCKS } from "./blocks/index.js";
import { canonicalJson } from "./recipe-hash.js";
import { ownerSealedRevisions } from "./revision-author.js";
import { approvalSeal, newApprovalNonce, verifyApprovalSeal } from "./seal.js";
import { senderSealVerifies } from "./sender-seal.js";
import { getRevision, getState, recordAudit, setState } from "./store.js";

const { fail, requireOwner, requireReport, resolveDeps, seedOf, text } = approvalInternals;

/* ------------------------------------------------------------------------- the words */

/** The `report_state` key prefix a source approval lives under (reserved: no block may write it). */
export const SOURCE_APPROVAL_PREFIX = "source_approval:";

/** The block kind the mail account rule below is about. */
export const SOURCE_APPROVAL_KIND = "source";

/** The block kinds a source approval covers: a source, and a `custom` step's own settings. */
export const SOURCE_APPROVAL_KINDS = Object.freeze([SOURCE_APPROVAL_KIND, "custom"]);

/** The audit kind a source decision writes (`report_approvals_audit.kind`). */
export const SOURCE_AUDIT_KIND = "source";

/** The one sentence a preview answers for a source the owner has not approved. */
export function waitingForOkText(blockId) {
  return `Source ${text(blockId)} is waiting for your OK`;
}

/* --------------------------------------------------------------------------- the seal */

/** A seal is 32 bytes as 64 lower-case hex; a nonce is 16 bytes as 32 lower-case hex. */
const SEAL_HEX = /^[0-9a-f]{64}$/;
const NONCE_HEX = /^[0-9a-f]{32}$/;

/** The kind tag the shared encoder seals a source approval under (seal.js's `source` field list). */
const SOURCE_SEAL_KIND = "source";

/**
 * This seam's keychain seed as bytes, or null.
 *
 * The author-seal readers take a seed rather than the seam, so that `revision-author.js` imports nothing
 * from this tree's approvals modules; a missing or unreadable seed is null here, and a null seed proves no
 * revision and names no account, which is the fail-closed answer.
 */
async function seedOrNull(deps) {
  try {
    return await seedOf(resolveDeps(deps));
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------------ the hash */

/**
 * The settings hash the owner approves: the sha256 of the canonical JSON of `{type, settings}`.
 *
 * The block's `id` is deliberately not part of it, so renaming an id does not change what was approved
 * (the id is the approval KEY, and an approval does not follow a block to a new id). Every setting is
 * part of it, so a changed label, folder, `sinceDays`, URL host, path or query is a different hash.
 *
 * @param {object} block a recipe block
 * @returns {string} 64 lower-case hex characters
 * @throws {Error} `bad_json` for a settings value canonical JSON cannot carry
 */
export function settingsHashOf(block) {
  const type = block != null && typeof block === "object" ? text(block.type) : "";
  const settings = block != null && typeof block === "object" && block.settings !== undefined
    ? block.settings
    : {};
  return createHash("sha256").update(canonicalJson({ type, settings }), "utf8").digest("hex");
}

/* ----------------------------------------------------------------------- the recipe */

/** A block id as the approval key it also is in `report_state`. */
function blockIdOf(value) {
  if (typeof value !== "string" || !BLOCK_ID_RE.test(value)) throw fail("bad_input", "blockId");
  return value;
}

/** The blocks of the report's HEAD revision. A report nobody saved yet has none. */
async function headBlocks(db, report) {
  const rev = Number(report.recipe_rev);
  if (!Number.isInteger(rev) || rev < 1) return [];
  const revision = await getRevision(db, report.id, rev);
  if (!revision) return [];
  let recipe;
  try {
    recipe = JSON.parse(text(revision.recipe_json));
  } catch {
    return [];
  }
  return Array.isArray(recipe?.blocks) ? recipe.blocks : [];
}

/** The block with one id, or null. */
function blockById(blocks, blockId) {
  for (const block of blocks) {
    if (block != null && typeof block === "object" && block.id === blockId) return block;
  }
  return null;
}

/**
 * The kind of one block type: the server's own registry first, then the caller's narrowed one. A type
 * neither knows, or one with no declared kind, answers null (which is never `source`).
 */
function kindOfBlock(d, type) {
  if (typeof type !== "string" || !type) return null;
  if (Object.hasOwn(BLOCKS, type)) return BLOCKS[type].kind;
  const registry = d.registry;
  if (registry == null || typeof registry !== "object" || !Object.hasOwn(registry, type)) return null;
  const entry = registry[type];
  return entry != null && typeof entry === "object" && typeof entry.kind === "string" ? entry.kind : null;
}

/* --------------------------------------------------------------------- the approval */

/**
 * The owner's approval of one draft block, at the settings the report's HEAD revision holds now.
 *
 * Owner only. The block must be in the head recipe and must be a registry `kind: "source"` or
 * `kind: "custom"` block: a shape or present block reads nothing worth approving, so either is
 * `bad_input`. The decision is about the settings the owner's VIEW carried, so `expectedSettingsHash` is
 * that view's `settingsHash` and a head revision that moved since (another hash) answers
 * `source_changed` and writes nothing. What is stored is `{settingsHash, nonce, seal}` under
 * `source_approval:<blockId>`, with a fresh nonce, plus one `source` audit row naming the block.
 *
 * @param {object} db
 * @param {object} deps `loadSeed`, `now`, `registry`
 * @param {{reportId: string, blockId: string, expectedSettingsHash: string,
 *   actor: {kind: "owner"}}} input
 * @returns {Promise<{ok: true, blockId: string, settingsHash: string}>}
 * @throws {Error} `owner_only`, `bad_input`, `not_found`, `source_changed`, `keychain_key_missing`
 */
export async function approveSource(db, deps, {
  reportId, blockId, expectedSettingsHash, actor,
} = {}) {
  requireOwner(actor);
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  const id = blockIdOf(blockId);
  const block = blockById(await headBlocks(db, report), id);
  if (!block) throw fail("not_found", "block");
  if (!SOURCE_APPROVAL_KINDS.includes(kindOfBlock(d, block.type))) throw fail("bad_input", "block_type");
  let settingsHash;
  try {
    settingsHash = settingsHashOf(block);
  } catch {
    throw fail("bad_input", "settings");
  }
  // The tap approves what the owner SAW: a save between that view and this decision is a different
  // source, and the owner has not read it.
  if (typeof expectedSettingsHash !== "string" || expectedSettingsHash !== settingsHash) {
    throw fail("source_changed");
  }
  const seed = await seedOf(d);
  const nonce = newApprovalNonce();
  const seal = approvalSeal(SOURCE_SEAL_KIND, { reportId: report.id, blockId: id, settingsHash, nonce }, seed);
  await setState(db, report.id, SOURCE_APPROVAL_PREFIX + id, { settingsHash, nonce, seal });
  await recordAudit(db, {
    reportId: report.id,
    kind: SOURCE_AUDIT_KIND,
    subject: id,
    actor: "owner",
    decided: "approved",
    at: d.now(),
  });
  return { ok: true, blockId: id, settingsHash };
}

/**
 * Does this block id still carry the owner's approval for exactly this block's settings? `true` only
 * when the state row exists, its seal verifies over the report, the block id and the stored hash, and
 * the stored hash is the hash of the block as it is NOW. A direct UPDATE of the state row, a changed
 * setting, a revoked (nulled) row and a missing keychain seed are all `false`. Never throws.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {string} reportId
 * @param {object} block a recipe block
 * @returns {Promise<boolean>}
 */
export async function verifySourceApproval(db, deps, reportId, block) {
  try {
    if (typeof reportId !== "string" || !reportId) return false;
    const blockId = text(block?.id);
    if (!BLOCK_ID_RE.test(blockId)) return false;
    const row = await getState(db, reportId, SOURCE_APPROVAL_PREFIX + blockId);
    if (row == null || typeof row !== "object" || Array.isArray(row)) return false;
    const settingsHash = text(row.settingsHash);
    const nonce = text(row.nonce);
    const seal = text(row.seal);
    if (!SEAL_HEX.test(settingsHash) || !NONCE_HEX.test(nonce) || !SEAL_HEX.test(seal)) return false;
    if (settingsHash !== settingsHashOf(block)) return false;
    const d = resolveDeps(deps);
    return verifyApprovalSeal(
      SOURCE_SEAL_KIND,
      { reportId, blockId, settingsHash, nonce },
      seal,
      await seedOf(d),
    );
  } catch {
    return false;
  }
}

/**
 * The owner's revocation of one draft source approval: the state value is written `null`, so the seal
 * and its nonce are gone and an old seal can never re-approve the row, plus one `revoked` audit row.
 *
 * The block does not have to be in the head recipe: a revoke clears a decision about a block id, and a
 * block a bot removed from the recipe must still be clearable.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, blockId: string, actor: {kind: "owner"}}} input
 * @returns {Promise<{ok: true, blockId: string}>}
 * @throws {Error} `owner_only`, `bad_input`, `not_found`
 */
export async function revokeSource(db, deps, { reportId, blockId, actor } = {}) {
  requireOwner(actor);
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  const id = blockIdOf(blockId);
  await setState(db, report.id, SOURCE_APPROVAL_PREFIX + id, null);
  await recordAudit(db, {
    reportId: report.id,
    kind: SOURCE_AUDIT_KIND,
    subject: id,
    actor: "owner",
    decided: "revoked",
    at: d.now(),
  });
  return { ok: true, blockId: id };
}

/* ------------------------------------------------------------------------ the read */

/** Does the sealed live set's own recipe carry a block with this settings hash, under any id? */
function sealedCovers(recipe, settingsHash) {
  const blocks = Array.isArray(recipe?.blocks) ? recipe.blocks : [];
  for (const block of blocks) {
    if (block == null || typeof block !== "object") continue;
    try {
      if (settingsHashOf(block) === settingsHash) return true;
    } catch {
      // A block whose settings canonical JSON cannot carry is not the one that was approved.
    }
  }
  return false;
}

/**
 * The mail account this report is about, as the approval rails see it: the VERIFIED live set's sealed
 * sender account when the live set verified, and otherwise the report row's own `sender_account_id` ONLY
 * behind the owner's sender seal (`senderSealVerifies`, sender-seal.js).
 *
 * The row column is never trusted on its own. A never-live report has no live set, and a draft's mail
 * block is exactly what a preview is for, so there has to be a fallback; the fallback is allowed only
 * behind a seal the owner's settings save wrote over that account, so a direct UPDATE of the column (or a
 * bot's save of a mail block) cannot point a preview at a mailbox the owner never chose. "" when the
 * report names no account, or when nothing proves the account is the owner's choice.
 *
 * A `live` of null is not "this report has none": a PREVIEW is handed that by `run.js`, and a live
 * report whose head is a newer save (a bot's free change) still has its sealed revision. So null reads
 * the live set through `verifyLive` and uses its sealed sender when it resolves, and only a report with
 * no live set at all reaches the row fallback.
 *
 * The keychain seed is loaded here, through the approvals seam, and handed to sender-seal.js, which
 * imports nothing from this module or from approvals.js. Never throws: a missing seed, an unreadable
 * state row and a database error all answer "".
 *
 * @param {object} db
 * @param {object} [deps] the approvals seam (`loadSeed`)
 * @param {object|null} live the verified live set (`verifyLive`), or null for a caller that has none
 * @param {object|null} report a report row
 * @returns {Promise<string>}
 */
export async function approvedSenderAccount(db, deps, live, report) {
  try {
    // A caller with no live set in hand (a preview) still gets the sealed sender of a live report: the
    // set is read here, so a head revision a bot saved is not what a mail block is measured against.
    const resolved = live == null && report != null && typeof report === "object"
      ? await verifyLive(db, deps, report)
      : live;
    const sealedLive = text(resolved?.senderAccountId);
    if (sealedLive) return sealedLive;
    const rowAccount = text(report?.sender_account_id);
    if (!rowAccount) return "";
    if (!(await senderSealVerifies(db, await seedOrNull(deps), report))) return "";
    return rowAccount;
  } catch {
    return "";
  }
}

/**
 * Is this block's `accountId` the mail account this report is about
 * (`approvedSenderAccount`)? A report that names no approved account answers no, so nothing approves a
 * mailbox the owner never chose, and the account only counts when the live seal or the owner's sender
 * seal names it. Never throws.
 */
async function accountCovers(db, deps, live, report, block) {
  const approved = await approvedSenderAccount(db, deps, live, report);
  const accountId = text(block?.settings?.accountId).trim();
  return approved !== "" && accountId === approved;
}

/**
 * The head revision's source-shaped blocks as the owner's view reads them: `{blockId, type,
 * settingsHash, approved}`. `settingsHash` is what an approval hands back, and `approved` is whether an
 * approval for exactly these settings still verifies. A report nobody saved yet has an empty list.
 *
 * @param {object} db
 * @param {object} deps the approvals seam
 * @param {string} reportId
 * @returns {Promise<{blockId: string, type: string, settingsHash: string|null, approved: boolean}[]>}
 * @throws {Error} `bad_input`, `not_found`
 */
export async function listDraftSources(db, deps, reportId) {
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  const out = [];
  for (const block of await headBlocks(db, report)) {
    if (block == null || typeof block !== "object") continue;
    const blockId = text(block.id);
    if (!BLOCK_ID_RE.test(blockId)) continue;
    if (!SOURCE_APPROVAL_KINDS.includes(kindOfBlock(d, block.type))) continue;
    let settingsHash = null;
    try {
      settingsHash = settingsHashOf(block);
    } catch {
      settingsHash = null;
    }
    out.push({
      blockId,
      type: text(block.type),
      settingsHash,
      approved: await verifySourceApproval(db, deps, report.id, block),
    });
  }
  return out;
}

/**
 * The one separator in the key of a continuity answer: a block id and a settings hash, which can never
 * collide (a block id holds no NUL, a hash is 64 hex characters).
 */
const ANSWER_SEP = "\u0000";

/** The key one (block id, settings hash) continuity answer is stored under. */
export function chainKeyOf(blockId, settingsHash) {
  return `${blockId}${ANSWER_SEP}${text(settingsHash)}`;
}

/**
 * Every (block id, settings hash) pair the report's revisions still carry at `headRev`, with the answer
 * rule (c) gives it, from ONE pass over the report's revisions.
 *
 * The answer for a pair is whether an unbroken OWNER-introduced run of revisions carries that block id at
 * that settings hash from the revision that started the run up to and including `headRev`. A revision
 * that does not carry the id, or carries it at another hash, ENDS the run: the settings the owner once
 * put there are gone. Only an OWNER-WRITTEN revision that puts these exact settings back where they were
 * missing starts a new run, so:
 *
 *   - an owner add, an owner removal and a bot's re-add of the identical settings is gated,
 *   - an owner add, a bot's settings change away and back is gated,
 *   - an owner add that later owner and bot revisions leave alone is ungated,
 *   - an owner's re-add after a bot removed the block is ungated again, because that re-add is the
 *     owner putting the content there.
 *
 * WHAT "OWNER-WRITTEN" MEANS: the revision carries a sealed author proof (`ownerSealedRevisions`,
 * revision-author.js): the `author_kind` column says `owner`, the `revision_author:<rev>` state row holds a
 * nonce and a seal, the revision's own recipe body recomputes to its `recipe_hash` column, and the seal
 * verifies over the report, the revision and that hash under the keychain seed. A row whose column was
 * flipped by a direct UPDATE, a seal copied from another revision or report, a tampered recipe body and
 * a revision saved before the seal existed all read as bot-written. A revision saved without an author
 * seal is therefore never owner-chain evidence: the owner's paths forward are `approveSource` (path b) or
 * a fresh owner save plus go-live (path a).
 *
 * Continuity is what makes a bot's re-add count for nothing while a reverted settings change still does:
 * a revision that carries the id at the hash keeps the run alive whoever wrote it, so an owner re-save of
 * settings a bot introduced (the id carried them already) never starts a run of its own.
 *
 * A MISSING REVISION NUMBER ENDS EVERY RUN: the pass reaches the revisions in order, and a row whose
 * number does not follow the one before it (the first row must be revision 1) means a revision between
 * them is gone, so a run that looked unbroken is not one. A deleted revision therefore breaks the chain
 * exactly where a revision nobody can read would, and only a revision that is itself owner-written can
 * start a run after the hole.
 *
 * ONE READ, then a lookup: only one hash per block id can be carried at the head revision (a revision
 * holds one block per id), so one pass tracks `block id -> {hash, chain}` and the map holds the answer
 * for each pair that survived. A run of a recipe asks this ONCE and reuses the map for every gated block
 * (`isSourceApprovedForBot`'s `gate`), rather than reading every revision again per block.
 *
 * Never throws: a revision that cannot be read ends the run at that revision, a read the database refuses
 * is no chain at all (an empty map answers `false` for every pair), and a seed that cannot be loaded
 * leaves no revision proved, so every pair is gated.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {number} headRev the revision being previewed
 * @param {object} [deps] the approvals seam (`loadSeed`)
 * @returns {Promise<Map<string, boolean>>} `chainKeyOf(blockId, settingsHash)` -> answer
 */
export async function ownerChainAnswers(db, reportId, headRev, deps) {
  const answers = new Map();
  if (typeof reportId !== "string" || !reportId) return answers;
  if (!Number.isInteger(headRev) || headRev < 1) return answers;
  let rows;
  try {
    ({ rows } = await db.execute({
      sql: `SELECT rev, author_kind, recipe_json FROM report_recipe_revisions
             WHERE report_id = ? AND rev <= ? ORDER BY rev ASC`,
      args: [reportId, headRev],
    }));
  } catch {
    return answers;
  }
  const sealedOwnerRevs = await ownerSealedRevisions(db, await seedOrNull(deps), reportId, headRev);
  /** block id -> {hash, chain}: the state the last revision carrying that id left behind. */
  const carried = new Map();
  /** The revision number the previous row carried: 0 before the first one, so a first row must be 1. */
  let previousRev = 0;
  for (const row of rows) {
    const rev = Number(row.rev);
    // A number that does not follow the previous row's is a hole in the history (a revision deleted
    // between two saves), and a hole ends every run: what the rows on either side of it carry is not one
    // unbroken stretch of revisions.
    if (!Number.isInteger(rev) || rev !== previousRev + 1) carried.clear();
    if (Number.isInteger(rev)) previousRev = rev;
    let blocks;
    try {
      blocks = JSON.parse(text(row.recipe_json))?.blocks;
    } catch {
      blocks = null;
    }
    const present = new Map();
    if (Array.isArray(blocks)) {
      for (const block of blocks) {
        if (block == null || typeof block !== "object") continue;
        const blockId = text(block.id);
        if (!BLOCK_ID_RE.test(blockId)) continue;
        try {
          present.set(blockId, settingsHashOf(block));
        } catch {
          // A block whose settings canonical JSON cannot carry is not the one that was approved.
        }
      }
    }
    // A revision that does not carry an id at all ends that id's run.
    for (const blockId of [...carried.keys()]) {
      if (!present.has(blockId)) carried.delete(blockId);
    }
    // The revision that finds the id without these settings starts a run only when the OWNER wrote it,
    // and "wrote it" means the revision carries a sealed author proof, never the author_kind column.
    const ownerWrote = sealedOwnerRevs.has(Number(row.rev));
    for (const [blockId, hash] of present) {
      const prior = carried.get(blockId);
      if (prior && prior.hash === hash) continue;
      carried.set(blockId, { hash, chain: ownerWrote });
    }
  }
  for (const [blockId, state] of carried) answers.set(chainKeyOf(blockId, state.hash), state.chain === true);
  return answers;
}

/**
 * The continuity answers for one gated block: a caller's per-run map when it is one built for this exact
 * head revision, else a fresh single read.
 */
async function chainAnswersFor(db, reportId, headRev, gate, deps) {
  if (gate != null && typeof gate === "object" && gate.ownerChain instanceof Map
    && Number(gate.headRev) === headRev) {
    return gate.ownerChain;
  }
  return ownerChainAnswers(db, reportId, headRev, deps);
}

/**
 * May a gated preview run this source-shaped block? `{ok: true}` when the block's exact
 * `{type, settings}` appears in the report's verified live set recipe, or when the owner approved that
 * block id at that exact settings hash as a draft block, or when that hash under that block id has an
 * unbroken owner-introduced history up to the head revision (`ownerChainAnswers`); otherwise
 * `{ok: false, text}` with the one sentence the owner reads. A `mail_alerts` block needs the report's
 * own approved mail account as well, in every case (`approvedSenderAccount`: the sealed live sender, or
 * the row's sender only behind the owner's sender seal).
 *
 * `gate` is a caller's per-run continuity map (`{headRev, ownerChain}` from `ownerChainAnswers`), so a
 * run reads the report's revisions ONCE and asks this for every gated block in that run. A gate for
 * another head revision, or none at all, is a fresh single read for this block alone.
 *
 * Never throws: a report whose seal will not verify reads as "no live set", and a broken state row or a
 * revision read that fails reads as "not approved", which is the safe side to be wrong on.
 *
 * @param {object} db
 * @param {object} deps the approvals seam
 * @param {object|null} report a report row
 * @param {object} block a recipe block (`{id, type, settings}`)
 * @param {{headRev?: number, ownerChain?: Map<string, boolean>}|null} [gate] the run's own answers
 * @returns {Promise<{ok: true}|{ok: false, text: string}>}
 */
export async function isSourceApprovedForBot(db, deps, report, block, gate = null) {
  const blockId = text(block?.id);
  const waiting = { ok: false, text: waitingForOkText(blockId) };
  try {
    const settingsHash = settingsHashOf(block);
    const live = report != null && typeof report === "object" ? await verifyLive(db, deps, report) : null;
    const sealed = live != null && sealedCovers(live.recipe, settingsHash);
    let ownerChain = false;
    if (!sealed) {
      const headRev = Number(report?.recipe_rev);
      if (typeof report?.id === "string" && BLOCK_ID_RE.test(blockId)
        && Number.isInteger(headRev) && headRev >= 1) {
        const answers = await chainAnswersFor(db, report.id, headRev, gate, deps);
        ownerChain = answers.get(chainKeyOf(blockId, settingsHash)) === true;
      }
    }
    const approved = sealed
      || ownerChain
      || (await verifySourceApproval(db, deps, report?.id, block));
    if (!approved) return waiting;
    if (text(block?.type) === "mail_alerts" && !(await accountCovers(db, deps, live, report, block))) {
      return waiting;
    }
    return { ok: true };
  } catch {
    return waiting;
  }
}