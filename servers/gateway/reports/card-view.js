/**
 * The report card's one read: everything a report's card in a Perch chat draws, in one JSON object.
 *
 * WHAT THIS IS: the owner's view of one report in a chat, built from ONE owner-only call. The card is
 * drawn from this answer and from nothing else, so it carries the FULL settings of everything the card
 * offers to act on: a bot's pending free change with both sides' settings, and the head settings of
 * every draft source waiting for an OK. A card that showed a summary and applied something else would
 * put a one-tap approval over content the owner never saw.
 *
 * WHAT IT NEVER CARRIES: a seal, a nonce, a token or a secret. Every list here is one of the reports
 * modules' own views (approvals.js, steps.js, source-approvals.js, run.js), and each of those drops its
 * seals and nonces; the credential view names a keychain row and its rule, never a value. This module
 * reads no seal column and writes nothing at all: it is a reader, and it never writes a `report_state`
 * key.
 *
 * BOUNDS: at most 20 recipients, 20 steps, 20 hosts, 20 credential bindings and 40 changes, and a
 * settings object over 16 KB of JSON is replaced by `{_truncated: true}`, with its `settingsHash` kept
 * on a source entry and `truncated: true` added to the entry: a settings object too large to show is
 * one the card must not offer to approve either.
 *
 * `changes` is only ever about a live report with `pending_free_change` set. It compares the head
 * revision with the live revision and carries each side's whole settings object so the owner reads
 * exactly what a one-tap Apply would put under their approval. Three shapes of entry, and every one of
 * them is something an Apply would make live:
 *   - a block that was added, changed or removed, matched by block id (`blockId`, `type`, `kind`,
 *     `change`) with both sides' whole settings;
 *   - a RECIPE-LEVEL key that differs (`blockId: null`, `type: "recipe"`), one entry per top-level key
 *     other than `blocks` (`emptyText` and anything a later save adds), each side's value written as a
 *     one-key object so the card prints it with the same `key: value` lines it prints settings with;
 *   - a reordering of the block ids the two revisions have in common (`blockId: null`,
 *     `type: "order"`), with each side's id order under `{order: [ids]}`.
 * When either revision cannot be read or parsed, `changes` is empty and the answer also carries
 * `changesUnreadable: true`, so the card can say so rather than offer Apply on a diff it cannot show.
 *
 * WHAT AN APPLY IS BOUND TO: `computeReportChanges` answers the WHOLE diff, the head revision it was
 * computed from and `changesHash`, a sha256 over the canonical JSON of every entry (each side's
 * settings) plus both revisions AND both revisions' own stored `recipe_hash`. The hashes are folded in
 * on purpose: a save can differ in something no entry spells out, and a difference the card does not
 * show must still move the digest. `POST /:id/apply` recomputes that diff and refuses unless the
 * caller sends back exactly this `headRev` and `changesHash`, so a tap applies what the card showed
 * and never a save that landed after it. The card lists at most 40 entries: when the diff has more,
 * or one entry's settings is over the 16 KB bound, it also carries `changesTruncated: true`, and Apply
 * is refused on it, because the hash is always the digest of the full diff and never of the cut list.
 *
 * `deps` is the approvals seam the routes already build (loadSeed, registry, getSchedule) plus one
 * optional reader:
 *   - `getAccount(db, accountId)`: the Crow Mail account row a report's sender names. The default is
 *     mail/store/accounts.js's own reader.
 */
import { createHash } from "node:crypto";
import { isLive, listRecipients, liveSetFor } from "./approvals.js";
import { BLOCKS } from "./blocks/index.js";
import { getAccount } from "../mail/store/accounts.js";
import { listRuns } from "./run.js";
import { listDraftSources } from "./source-approvals.js";
import { HOST_APPROVAL_LINE, listCredentials, listHosts, listStepsForPage, stepDiff } from "./steps.js";
import { getRevision, getState } from "./store.js";

/** How many rows of each list a card carries. `MAX_CHANGES` is only how many a card LISTS: the diff
 *  and its digest are computed over every entry, and a longer diff is marked `changesTruncated`. */
const MAX_RECIPIENTS = 20;
const MAX_STEPS = 20;
const MAX_HOSTS = 20;
const MAX_CREDENTIALS = 20;
const MAX_CHANGES = 40;

/** How much of one settings object the card carries, as JSON text. */
const SETTINGS_MAX_BYTES = 16 * 1024;

/** What a settings object over the bound is replaced by. */
const TRUNCATED_SETTINGS = Object.freeze({ _truncated: true });

/** The two recipient states the card shows: a person the owner has to decide about, and one decided. */
const VISIBLE_RECIPIENT_STATES = Object.freeze(["proposed", "approved"]);

/** The one state a step, a host or a credential binding is listed in. */
const PROPOSED = "proposed";

/** The `report_state` key a proposed schedule lives under (`{cron, tz}`). */
const SCHEDULE_PROPOSAL_KEY = "schedule_proposal";

/** How many runs the preview lookup reads through (`listRuns`' own page is smaller). */
const PREVIEW_RUN_PAGE = 200;

/** The account transport word that makes a sender a reports-only Google account. */
const GOOGLE_REPORTS_TRANSPORT = "gmail_api";

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** A value's JSON text, or null when JSON cannot carry it faithfully. */
function jsonOf(value) {
  try {
    const json = JSON.stringify(value);
    return typeof json === "string" ? json : null;
  } catch {
    return null;
  }
}

/**
 * One settings object as the card carries it: the object itself, untouched, or the truncation marker
 * when it is larger than the bound (or cannot be written as JSON at all).
 *
 * @param {*} settings a block's `settings`
 * @returns {{value: *, truncated: boolean}}
 */
function boundedSettings(settings) {
  if (settings === undefined) return { value: null, truncated: false };
  const json = jsonOf(settings);
  if (json == null || Buffer.byteLength(json, "utf8") > SETTINGS_MAX_BYTES) {
    return { value: { ...TRUNCATED_SETTINGS }, truncated: true };
  }
  return { value: settings, truncated: false };
}

/* ------------------------------------------------------------------------ block kinds */

/**
 * The kind of one block type: the server's own registry first, then the caller's narrower one. A type
 * neither knows answers null, which is never `source` here (see `changeKind` for the null-registry
 * case).
 */
function kindOfType(registry, type) {
  if (typeof type !== "string" || !type) return null;
  if (Object.hasOwn(BLOCKS, type)) return BLOCKS[type].kind;
  if (registry == null || typeof registry !== "object" || !Object.hasOwn(registry, type)) return null;
  const entry = registry[type];
  return entry != null && typeof entry === "object" && typeof entry.kind === "string" ? entry.kind : null;
}

/**
 * Does the registry (the server's first, then the caller's) mark this type source-bearing? A `shape`
 * block that reads something the owner approved (`enrich_lookup` joins another source block's items)
 * is source-bearing whatever its kind is called, and a change to it is never a free one.
 */
function isSourceBearingType(registry, type) {
  if (typeof type !== "string" || !type) return false;
  if (Object.hasOwn(BLOCKS, type)) return BLOCKS[type].sourceBearing === true;
  if (registry == null || typeof registry !== "object" || !Object.hasOwn(registry, type)) return false;
  const entry = registry[type];
  return entry != null && typeof entry === "object" && entry.sourceBearing === true;
}

/**
 * A changed block's kind, as the card names it: `source` for a source-shaped or source-bearing type,
 * `custom` for the report's own step (which is source-bearing too, and keeps its own kind because its
 * approval is a step revision), `free` for anything else. A caller with no block registry at all
 * (`registry: null`) is the same fail-closed case the approvals module gives it: every block counts as
 * source-bearing, so an unknown type is never shown as free.
 */
function changeKind(registry, type) {
  if (registry === null) return "source";
  const kind = kindOfType(registry, type);
  if (kind === "source") return "source";
  if (kind === "custom") return "custom";
  // A shape block that reads something the owner approved (`enrich_lookup`) is source-bearing whatever
  // its kind is called, so a change to it is never shown as a free one.
  if (isSourceBearingType(registry, type)) return "source";
  return "free";
}

/* --------------------------------------------------------------------- recipe blocks */

/**
 * One saved revision as this module reads it: its parsed recipe, that recipe's blocks and the revision
 * row's own stored `recipe_hash`. Null when the revision is missing, or when its text is not a recipe.
 * A report nobody saved yet (revision 0) answers null here, like a revision that cannot be read.
 */
async function revisionOf(db, reportId, rev) {
  const number = Number(rev);
  if (!Number.isInteger(number) || number < 1) return null;
  let revision;
  try {
    revision = await getRevision(db, reportId, number);
  } catch {
    return null;
  }
  if (!revision) return null;
  let recipe;
  try {
    recipe = JSON.parse(text(revision.recipe_json));
  } catch {
    return null;
  }
  if (recipe == null || typeof recipe !== "object" || Array.isArray(recipe) || !Array.isArray(recipe.blocks)) {
    return null;
  }
  return { recipe, blocks: recipe.blocks, hash: text(revision.recipe_hash) };
}

/** The blocks of one saved revision, or null when the revision cannot be read as a recipe. */
async function blocksOf(db, reportId, rev) {
  const revision = await revisionOf(db, reportId, rev);
  return revision == null ? null : revision.blocks;
}

/** The blocks of a list by id, the first of each id winning (a duplicate id is not one block twice). */
function blocksById(blocks) {
  const map = new Map();
  for (const block of blocks) {
    if (block == null || typeof block !== "object" || Array.isArray(block)) continue;
    const id = typeof block.id === "string" ? block.id : "";
    if (!id || map.has(id)) continue;
    map.set(id, block);
  }
  return map;
}

/** Do two blocks say the same thing? The type and the settings, not the id they are matched by. */
function sameBlock(left, right) {
  if (text(left?.type) !== text(right?.type)) return false;
  const a = jsonOf(left?.settings === undefined ? null : left.settings);
  const b = jsonOf(right?.settings === undefined ? null : right.settings);
  return a != null && a === b;
}

/**
 * One entry of `changes`, as the diff computes it: which block, of what type and kind, added, changed
 * or removed, with each side's WHOLE settings object (null on the side the block is missing from).
 */
function diffEntry(registry, blockId, headBlock, liveBlock, change) {
  const type = text((headBlock ?? liveBlock)?.type);
  return {
    blockId,
    type,
    kind: changeKind(registry, type),
    change,
    before: liveBlock == null || liveBlock.settings === undefined ? null : liveBlock.settings,
    after: headBlock == null || headBlock.settings === undefined ? null : headBlock.settings,
  };
}

/**
 * Every added, changed or removed block between the head revision and the live one, matched by block
 * id, in head order and then the live revision's removed blocks in its own order. Unbounded: what a
 * card lists is a later cut of this list, and the hash is over all of it.
 */
function diffEntries(registry, headBlocks, liveBlocks) {
  const head = blocksById(headBlocks);
  const sealed = blocksById(liveBlocks);
  const out = [];
  for (const [id, block] of head) {
    if (!sealed.has(id)) {
      out.push(diffEntry(registry, id, block, null, "added"));
      continue;
    }
    const before = sealed.get(id);
    if (!sameBlock(block, before)) out.push(diffEntry(registry, id, block, before, "changed"));
  }
  for (const [id, block] of sealed) {
    if (!head.has(id)) out.push(diffEntry(registry, id, null, block, "removed"));
  }
  return out;
}

/**
 * The recipe-level keys that differ between the live revision and the head, one entry each: every
 * top-level key other than `blocks`. Each side is that key's WHOLE value as a one-key object, the same
 * `{[key]: value}` shape a block entry carries as its settings, so the card prints both sides with the
 * `key: value` lines it already has. A key present on one side only reads null on the other.
 *
 * These are free by construction: `blocks` is the one top-level key a run reads as instructions, and a
 * key that is not that one (a run's empty text, a heading) is presentational. `recipe_hash` is folded
 * into the digest as well, so a difference no entry here spells out still moves the hash.
 */
function recipeChanges(headRecipe, liveRecipe) {
  const keys = new Set([...Object.keys(headRecipe), ...Object.keys(liveRecipe)]);
  const out = [];
  for (const key of [...keys].sort()) {
    if (key === "blocks") continue;
    const after = headRecipe[key];
    const before = liveRecipe[key];
    if (jsonOf(after) === jsonOf(before)) continue;
    out.push({
      blockId: null,
      type: "recipe",
      kind: "free",
      change: "changed",
      before: { [key]: before === undefined ? null : before },
      after: { [key]: after === undefined ? null : after },
    });
  }
  return out;
}

/** The block ids of one revision in its own order, the first of each id winning (as `blocksById`). */
function orderOf(blocks) {
  return [...blocksById(blocks).keys()];
}

/**
 * The reordering entry, when the two revisions order the block ids they have IN COMMON differently.
 * Only the common ids count: a block added or removed already has its own entry, and its position
 * relative to the others is what that entry is about. Both sides are `{order: [ids]}` so the card
 * prints them with the same lines it prints settings with.
 */
function orderChange(headBlocks, liveBlocks) {
  const after = orderOf(headBlocks);
  const before = orderOf(liveBlocks);
  const liveIds = new Set(before);
  const common = new Set(after.filter((id) => liveIds.has(id)));
  const headOrder = after.filter((id) => common.has(id));
  const liveOrder = before.filter((id) => common.has(id));
  if (canonicalText(headOrder) === canonicalText(liveOrder)) return null;
  return {
    blockId: null,
    type: "order",
    kind: "free",
    change: "changed",
    before: { order: liveOrder },
    after: { order: headOrder },
  };
}

/** A value with every object's keys sorted, so two equal settings objects write the same text. */
function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) sorted[key] = canonicalValue(value[key]);
    return sorted;
  }
  return value;
}

/** One value as canonical JSON text. */
function canonicalText(value) {
  return JSON.stringify(canonicalValue(value));
}

/** Does this settings object fit the card's bound? */
function oversizedSettings(settings) {
  if (settings === undefined) return false;
  const json = jsonOf(settings);
  return json == null || Buffer.byteLength(json, "utf8") > SETTINGS_MAX_BYTES;
}

/**
 * The digest of one whole diff: sha256 over the canonical JSON of every entry (both sides' whole
 * settings, their block id, type, kind and change word) together with the head and live revisions and
 * BOTH revisions' own stored `recipe_hash`. The same diff in any key order hashes alike; a cut or
 * bounded list hashes differently from the diff it came from, which is what keeps a truncated diff from
 * ever matching a tap; and a save that differs in something no entry spells out still moves the digest,
 * because the two revisions' `recipe_hash` values are part of what is hashed.
 *
 * @param {number} headRev the head revision the diff was computed from
 * @param {number|null} liveRev the live revision it was compared with
 * @param {Array<{blockId: string|null, type: string, kind: string, change: string, before: *,
 *   after: *}>} entries the diff's entries
 * @param {{head?: string, live?: string}|null} [hashes] the two revisions' stored `recipe_hash`
 * @returns {string} 64 lowercase hex characters
 */
export function changesHashOf(headRev, liveRev, entries, hashes = null) {
  const changes = (Array.isArray(entries) ? entries : []).map((entry) => ({
    blockId: entry?.blockId == null ? null : entry.blockId,
    type: entry?.type,
    kind: entry?.kind,
    change: entry?.change,
    before: entry?.before === undefined ? null : entry.before,
    after: entry?.after === undefined ? null : entry.after,
  }));
  const recipeHashes = { head: text(hashes?.head), live: text(hashes?.live) };
  return createHash("sha256")
    .update(canonicalText({ headRev, liveRev, recipeHashes, changes }), "utf8")
    .digest("hex");
}

/** One diff entry as the card carries it: each side bounded, and `truncated` when either was cut. */
function cardChangeEntry(entry) {
  const before = boundedSettings(entry.before);
  const after = boundedSettings(entry.after);
  const out = {
    blockId: entry.blockId,
    type: entry.type,
    kind: entry.kind,
    change: entry.change,
    before: before.value,
    after: after.value,
  };
  if (before.truncated || after.truncated) out.truncated = true;
  return out;
}

/* -------------------------------------------------------------------------- the parts */

/** The sender account a report names, or null when it names none (or the row cannot be read). */
async function senderOf(db, deps, report) {
  const accountId = text(report?.sender_account_id);
  if (!accountId) return null;
  const reader = typeof deps?.getAccount === "function" ? deps.getAccount : getAccount;
  let account = null;
  try {
    account = await reader(db, accountId);
  } catch {
    account = null;
  }
  if (account == null || typeof account !== "object") return null;
  const address = text(account.address);
  if (!address) return null;
  return {
    accountId,
    address,
    // The column a reports-only Google account is marked with may not exist on this schema: a row that
    // carries no transport is an ordinary Crow Mail account.
    kind: account.transport === GOOGLE_REPORTS_TRANSPORT ? "google_reports" : "crow_mail",
  };
}

/**
 * The report's own enabled schedule row, as the live set reads it: `deps.getSchedule` when the caller
 * injected one, otherwise the live set's own resolved `cron`/`tz`. Null when the report has no enabled
 * schedule (or none that resolves).
 */
async function scheduleOf(db, deps, report) {
  try {
    if (typeof deps?.getSchedule === "function") {
      const row = await deps.getSchedule(db, report);
      const cron = row == null ? "" : text(row.cron).trim();
      if (!cron) return null;
      return { cron, tz: text(row.tz) };
    }
    const live = await liveSetFor(db, deps, report);
    if (!text(live.cron)) return null;
    return { cron: text(live.cron), tz: text(live.tz) };
  } catch {
    return null;
  }
}

/** The `{cron, tz}` a bot proposed, or null. Only the two strings are read out of the state value. */
async function scheduleProposalOf(db, reportId) {
  let value;
  try {
    value = await getState(db, reportId, SCHEDULE_PROPOSAL_KEY);
  } catch {
    return null;
  }
  if (value == null || typeof value !== "object" || Array.isArray(value)) return null;
  const cron = typeof value.cron === "string" ? value.cron : "";
  if (!cron) return null;
  return { cron, tz: typeof value.tz === "string" ? value.tz : "" };
}

/**
 * The newest preview run of this report, and whether it is of the head revision: `current` is true
 * only when that run finished `ok` or `empty` at the revision the report holds now.
 */
async function previewOf(db, reportId, headRev) {
  let runs = [];
  try {
    runs = await listRuns(db, reportId, { limit: PREVIEW_RUN_PAGE });
  } catch {
    return null;
  }
  const run = runs.find((row) => row != null && row.trigger === "preview");
  if (!run) return null;
  const recipeRev = run.recipeRev == null ? null : Number(run.recipeRev);
  const finished = run.status === "ok" || run.status === "empty";
  return {
    runId: run.id,
    status: run.status,
    recipeRev: Number.isFinite(recipeRev) ? recipeRev : null,
    current: finished && recipeRev === headRev,
  };
}

/**
 * The head revision's source-shaped blocks whose source approval does not hold, each with its FULL
 * head settings: what the card's "Approve source" tap is about.
 */
async function sourcesOf(db, deps, report) {
  let listed;
  try {
    listed = await listDraftSources(db, deps, report.id);
  } catch {
    return [];
  }
  const waiting = listed.filter((row) => row != null && row.approved !== true);
  if (!waiting.length) return [];
  const byId = blocksById(await blocksOf(db, report.id, Number(report.recipe_rev)) ?? []);
  const out = [];
  for (const row of waiting) {
    const block = byId.get(row.blockId);
    if (block == null) continue;
    const { value, truncated } = boundedSettings(block.settings);
    const entry = {
      blockId: row.blockId,
      type: text(row.type),
      settingsHash: row.settingsHash == null ? null : text(row.settingsHash),
      settings: value,
    };
    if (truncated) entry.truncated = true;
    out.push(entry);
  }
  return out;
}

/** The people the owner has been asked about, or has approved, on this report. */
async function recipientsOf(db, deps, report) {
  let rows;
  try {
    rows = await listRecipients(db, report.id, deps);
  } catch {
    return [];
  }
  const out = [];
  for (const row of rows) {
    if (row == null || !VISIBLE_RECIPIENT_STATES.includes(row.state)) continue;
    out.push({
      id: text(row.id),
      address: text(row.address),
      displayName: row.displayName == null ? null : text(row.displayName),
      commentTier: row.commentTier == null ? null : text(row.commentTier),
      state: row.state,
      proposedBy: text(row.proposedBy),
    });
    if (out.length >= MAX_RECIPIENTS) break;
  }
  return out;
}

/** One step's files as the card carries them: the per-file line diff of the proposal. */
function diffFilesOf(diff) {
  const files = Array.isArray(diff?.files) ? diff.files : [];
  return files.map((file) => ({
    path: text(file?.path),
    status: text(file?.status),
    added: Number(file?.added) || 0,
    removed: Number(file?.removed) || 0,
    lines: (Array.isArray(file?.lines) ? file.lines : []).map((line) => ({
      op: text(line?.op),
      text: text(line?.text),
    })),
  }));
}

/** Every step key whose newest revision is still waiting for the owner, with its diff. */
async function stepsOf(db, deps, report) {
  let rows;
  try {
    rows = await listStepsForPage(db, report.id, deps);
  } catch {
    return [];
  }
  const out = [];
  for (const row of rows) {
    if (row == null || row.state !== PROPOSED) continue;
    if (out.length >= MAX_STEPS) break;
    let files = [];
    try {
      files = diffFilesOf(await stepDiff(db, report.id, row.stepKey, row.rev));
    } catch {
      files = [];
    }
    out.push({
      stepKey: text(row.stepKey),
      rev: Number(row.rev),
      language: text(row.language),
      entry: text(row.entry),
      bundleHash: row.bundleHash == null ? null : text(row.bundleHash),
      proposedBy: text(row.proposedBy),
      files,
    });
  }
  return out;
}

/** The sites waiting for an OK, each with the sentence the owner is shown beside the tap. */
async function hostsOf(db, deps, report) {
  let rows;
  try {
    rows = await listHosts(db, report.id, deps);
  } catch {
    return [];
  }
  const out = [];
  for (const row of rows) {
    if (row == null || row.state !== PROPOSED) continue;
    out.push({ host: text(row.host), notice: HOST_APPROVAL_LINE });
    if (out.length >= MAX_HOSTS) break;
  }
  return out;
}

/** The credential bindings waiting for an OK: the keychain reference and the rule, never a secret. */
async function credentialsOf(db, deps, report) {
  let rows;
  try {
    rows = await listCredentials(db, report.id, deps);
  } catch {
    return [];
  }
  const out = [];
  for (const row of rows) {
    if (row == null || row.state !== PROPOSED) continue;
    out.push({
      host: text(row.host),
      connectionUuid: text(row.connectionUuid),
      injectHash: row.injectHash == null ? null : text(row.injectHash),
      inject: row.inject == null ? null : row.inject,
    });
    if (out.length >= MAX_CREDENTIALS) break;
  }
  return out;
}

/**
 * One report's pending free change: the WHOLE diff between its head revision and its live one (blocks,
 * recipe-level keys and the block order), the digest over that diff, and whether it is a diff a card
 * can carry.
 *
 * `unreadable` means either revision could not be read or parsed: there is no diff to show, and Apply
 * is refused on it. `truncated` means the diff has more entries than a card lists, or one entry's
 * settings is larger than the bound: the card lists what fits and Apply is refused, because
 * `changesHash` is the digest of the whole diff and never of the list a card shows.
 *
 * Nothing is pending on a report, or its seal does not verify: the diff is empty and the digest is
 * the one an empty diff at these revisions has, so no tap can be mistaken for one that showed a change.
 *
 * @param {object} db
 * @param {object} report a `reports` row
 * @param {object} [deps] the approvals seam (`registry`, and whatever `isLive` reads)
 * @param {boolean|null} [live] the report's liveness as `isLive` answered it, when the caller has it
 * @returns {Promise<{changes: Array<object>, truncated: boolean, unreadable: boolean, headRev: number,
 *   changesHash: string}>}
 */
export async function computeReportChanges(db, report, deps = null, live = null) {
  const headNumber = Number(report?.recipe_rev);
  const liveNumber = report?.live_rev == null ? null : Number(report.live_rev);
  const headRev = Number.isFinite(headNumber) ? headNumber : 0;
  const liveRev = Number.isFinite(liveNumber) ? liveNumber : null;
  const empty = (unreadable) => ({
    changes: [],
    truncated: false,
    unreadable,
    headRev,
    changesHash: changesHashOf(headRev, liveRev, []),
  });
  const reportIsLive = live == null ? await isLive(db, deps, report) : live === true;
  if (Number(report?.pending_free_change) !== 1 || !reportIsLive) return empty(false);
  const head = await revisionOf(db, report.id, headRev);
  const liveRevision = await revisionOf(db, report.id, liveRev);
  if (!head || !liveRevision) return empty(true);
  const registry = deps == null ? undefined : deps.registry;
  const entries = diffEntries(registry, head.blocks, liveRevision.blocks);
  entries.push(...recipeChanges(head.recipe, liveRevision.recipe));
  const reorder = orderChange(head.blocks, liveRevision.blocks);
  if (reorder) entries.push(reorder);
  const truncated = entries.length > MAX_CHANGES
    || entries.some((entry) => oversizedSettings(entry.before) || oversizedSettings(entry.after));
  return {
    changes: entries.slice(0, MAX_CHANGES).map(cardChangeEntry),
    truncated,
    unreadable: false,
    headRev,
    changesHash: changesHashOf(headRev, liveRev, entries, {
      head: head.hash,
      live: liveRevision.hash,
    }),
  };
}

/* --------------------------------------------------------------------------- the card */

/**
 * The whole card for one report, from one read.
 *
 * @param {object} db
 * @param {object} [deps] the approvals seam; `getAccount` may be injected
 * @param {object} report a `reports` row
 * @returns {Promise<object>} the card, JSON-safe, with no seal, nonce, token or secret in it
 */
export async function buildReportCardView(db, deps, report) {
  if (report == null || typeof report !== "object" || !text(report.id)) {
    const err = new Error("not_found");
    err.code = "not_found";
    throw err;
  }
  const headRev = Number(report.recipe_rev);
  const liveRev = report.live_rev == null ? null : Number(report.live_rev);
  const live = await isLive(db, deps, report);
  const card = {
    report: {
      id: text(report.id),
      title: text(report.title),
      status: text(report.status),
      live,
      pauseReason: report.pause_reason == null ? null : text(report.pause_reason),
      recipeRev: Number.isFinite(headRev) ? headRev : 0,
      liveRev: Number.isFinite(liveRev) ? liveRev : null,
      pendingFreeChange: Number(report.pending_free_change) === 1,
      deliveryMode: text(report.delivery_mode),
    },
    sender: await senderOf(db, deps, report),
    schedule: await scheduleOf(db, deps, report),
    scheduleProposal: await scheduleProposalOf(db, report.id),
    preview: await previewOf(db, report.id, Number.isFinite(headRev) ? headRev : 0),
    changes: [],
    sources: await sourcesOf(db, deps, report),
    recipients: await recipientsOf(db, deps, report),
    steps: await stepsOf(db, deps, report),
    hosts: await hostsOf(db, deps, report),
    credentials: await credentialsOf(db, deps, report),
  };
  const change = await computeReportChanges(db, report, deps, live);
  card.changes = change.changes;
  card.headRev = change.headRev;
  card.changesHash = change.changesHash;
  if (change.unreadable) card.changesUnreadable = true;
  if (change.truncated) card.changesTruncated = true;
  return card;
}

export default buildReportCardView;