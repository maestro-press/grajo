/**
 * The reports store: the report row, its recipe revisions, its own key/value state and its approval
 * audit trail.
 *
 * A report row is returned exactly as the database writes it (snake_case), because the approvals
 * module and the routes read the columns they set: `status`, `recipe_rev`, `recipe_hash`,
 * `sources_hash`, `live_rev`, `live_seal`, `live_nonce`, `sender_account_id` and the rest. Nothing
 * secret is stored here: a credential is named by its keychain row, never by the secret.
 *
 * `saveRecipe` is the only writer of a recipe. It validates and hashes the recipe first (a refused
 * recipe writes nothing at all), then in ONE transaction reads the head revision, moves the head under a
 * compare-and-set on the revision it read, and inserts the revision row. An owner save may also write the
 * revision's author seal into `report_state` in that same transaction (see THE AUTHOR SEAL below). A
 * revision row is never updated, so a reader can always see what was saved at rev N; the head columns are
 * the fast path.
 *
 * Times are epoch ms from an injected clock (`now`), so a test's fake clock moves them. Which function
 * answers a missing report how:
 *   - `getReport`, `getRevision`, `getState` return null (a caller that lists or reads handles absence).
 *   - `saveRecipe`, `setState`, `updateReportColumns`, `recordAudit` throw `Error` with
 *     `code: "not_found"` (a caller that writes must not silently write nowhere).
 * Every refusal is an Error with a `code` string: `bad_input`, `bad_author_kind`, `bad_recipe` (an
 * unknown block type, a missing or repeated block id, a block's own settings, or the recipe hash),
 * `not_found` or `conflict`.
 *
 * The stores never set a status word a report cannot be in: `status` and the delivery, tier and
 * visibility words are validated by the caller that owns them (the approvals module and the routes).
 * What this module validates is the shape it writes: ids, titles, author kinds and column names.
 */
import { randomBytes } from "node:crypto";
import { BLOCKS, blockRegistry, validateRecipe } from "./blocks/index.js";
import { canonicalJson, recipeHash, sourcesHash } from "./recipe-hash.js";

/** The two writers of a recipe revision: the owner, or a bot acting in the report's project. */
export const REPORT_AUTHOR_KINDS = Object.freeze(["owner", "bot"]);

/** How many blocks one recipe may hold: a recipe is a page of settings, not a database. */
export const MAX_RECIPE_BLOCKS = 60;

/** The decision words `report_approvals_audit` may hold. */
export const APPROVAL_DECISIONS = Object.freeze(["approved", "refused", "revoked"]);

/** The recipe a brand-new report starts from: no blocks, nothing read, nothing sent. */
export const EMPTY_RECIPE_JSON = '{"blocks":[]}';

const REPORT_COLUMNS = `id, project_id, owner, bot_id, title, status, recipe_json, recipe_rev,
  recipe_hash, sources_hash, schedule_id, delivery_mode, comment_tier_default, comment_visibility,
  ai_commentary, model_ref, pause_reason, notify_every_run, sender_account_id, artifact_id, live_rev,
  live_seal, live_nonce, approved_preview_run, pending_free_change, created_at, updated_at`;

/** A list row is the same head without the recipe body: a list never needs every block's settings. */
const REPORT_LIST_COLUMNS = `id, project_id, owner, bot_id, title, status, recipe_rev, recipe_hash,
  sources_hash, schedule_id, delivery_mode, comment_tier_default, comment_visibility, ai_commentary,
  model_ref, pause_reason, notify_every_run, sender_account_id, artifact_id, live_rev, live_seal,
  live_nonce, approved_preview_run, pending_free_change, created_at, updated_at`;

const REVISION_COLUMNS = `report_id, rev, recipe_json, recipe_hash, sources_hash, author_kind,
  created_at`;

/**
 * The columns `updateReportColumns` may write: the head's settings and approval bookkeeping. Never `id`,
 * `project_id`, `owner` or the head recipe columns (which only `saveRecipe` moves), and never
 * `created_at`.
 */
const WRITABLE_COLUMNS = Object.freeze([
  "bot_id", "title", "status", "schedule_id", "delivery_mode", "comment_tier_default",
  "comment_visibility", "ai_commentary", "model_ref", "pause_reason", "notify_every_run",
  "sender_account_id", "artifact_id", "live_rev", "live_seal", "live_nonce", "approved_preview_run",
  "pending_free_change",
]);
const WRITABLE = new Set(WRITABLE_COLUMNS);

/** The `report_state` key prefix an owner revision's author seal lives under (revision-author.js reads
 *  the same keys; this module writes them, so the literal is here and the reader is there). */
const REVISION_AUTHOR_STATE_PREFIX = "revision_author:";

/** A seal is 64 lower-case hex; a nonce is 32. An answer that is not this pair writes no seal. */
const AUTHOR_SEAL_HEX = /^[0-9a-f]{64}$/;
const AUTHOR_NONCE_HEX = /^[0-9a-f]{32}$/;

const ID_RE = /^rpt-[0-9a-f]{16}$/;

function fail(code, detail) {
  const err = new Error(detail ? `${code}: ${detail}` : code);
  err.code = code;
  if (detail) err.detail = detail;
  return err;
}

function idOf(value, field = "reportId") {
  if (typeof value !== "string" || !ID_RE.test(value)) throw fail("bad_input", field);
  return value;
}

function clockOf(now) {
  return Number.isFinite(now) ? Number(now) : Date.now();
}

/* -------------------------------------------------------------- the authoredBy stamp */

/** One block without its `authoredBy` key, so a caller-sent stamp can never survive a save. */
function withoutStamp(block) {
  if (block == null || typeof block !== "object" || Array.isArray(block)) return block;
  if (!Object.hasOwn(block, "authoredBy")) return block;
  const { authoredBy, ...rest } = block;
  return rest;
}

/** The markdown a `text` block writes, for comparison: "" when it has none, null for anything but `text`. */
function textOfBlock(block) {
  if (block == null || typeof block !== "object" || block.type !== "text") return null;
  const settings = block.settings;
  if (settings == null || typeof settings !== "object" || Array.isArray(settings)) return "";
  const heading = typeof settings.heading === "string" ? settings.heading : "";
  const body = typeof settings.content === "string"
    ? settings.content
    : (typeof settings.text === "string" ? settings.text : "");
  return `${comparableText(heading)}\u0000${comparableText(body)}`;
}

/**
 * Text as the stamp compares it: CRLF and lone CR are one line break, and trailing whitespace on a line
 * (or a trailing blank line) counts for nothing. A save that round-trips a recipe through a form must not
 * look like an edit, because an edit re-stamps the block with the writer's own kind.
 */
function comparableText(value) {
  return String(value == null ? "" : value)
    .replace(/\r\n?/g, "\n")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/[ \t]+$/, "")
    .replace(/\n+$/, "");
}

/** The previous revision's recipe as an object, or null when there is no readable one. */
function previousRecipeOf(revision) {
  if (revision == null) return null;
  try {
    const recipe = JSON.parse(revision.recipe_json);
    return recipe != null && typeof recipe === "object" && Array.isArray(recipe.blocks) ? recipe : null;
  } catch {
    return null;
  }
}

/** A block's own `authoredBy` stamp when it is one this module writes, else null. */
function stampOf(block) {
  const value = block == null ? null : block.authoredBy;
  return value === "owner" || value === "bot" ? value : null;
}

/**
 * Stamp `authoredBy` on every `text` block whose own words changed in this save, and strip a stamp the
 * caller sent from every block. See `saveRecipe`'s header for the rule.
 *
 * An UNCHANGED block keeps the stamp it already carries. A block that carries none (a recipe written
 * before the stamp existed, or a row inserted straight into the database) is always `"bot"`: it has not
 * proved that an owner wrote it, and the run neutralises its links. The previous revision's own
 * `author_kind` says who last saved the RECIPE, which is not the same as who wrote THIS block (an owner
 * who fixes block B has not become the author of block A), so it is never inherited.
 *
 * An edited block takes this save's `authorKind`, and only an owner save can stamp `"owner"`.
 *
 * @param {object} recipe the recipe the caller handed over
 * @param {object|null} previous the head revision's recipe, or null for the first save
 * @param {"owner"|"bot"} authorKind who is saving
 * @returns {object} the recipe to validate, hash and store
 */
export function stampAuthoredBy(recipe, previous, authorKind) {
  if (recipe == null || typeof recipe !== "object" || Array.isArray(recipe)) return recipe;
  const blocks = Array.isArray(recipe.blocks) ? recipe.blocks : null;
  if (!blocks) return recipe;
  const previousBlocks = new Map();
  if (previous != null && Array.isArray(previous.blocks)) {
    for (const block of previous.blocks) {
      if (block != null && typeof block === "object" && typeof block.id === "string") {
        previousBlocks.set(block.id, block);
      }
    }
  }
  const stamped = blocks.map((block) => {
    const clean = withoutStamp(block);
    const text = textOfBlock(clean);
    if (text == null) return clean;
    const before = previousBlocks.get(clean.id);
    const changed = before == null || textOfBlock(withoutStamp(before)) !== text;
    const keptStamp = stampOf(before) ?? "bot";
    return { ...clean, authoredBy: changed ? authorKind : keptStamp };
  });
  return { ...recipe, blocks: stamped };
}

/* ------------------------------------------------------------------------- the report */

/**
 * Create a report in `draft` at revision 0 with an empty recipe. No revision row is written: revision 0
 * is the state of a report nobody has saved yet, and every save starts at rev 1.
 *
 * An empty `botId` is stored as NULL: "no bot" is null in this column, and the go-live seal reads both
 * spellings as "", so a row that carried the empty string would be indistinguishable to a reader.
 *
 * @param {object} db a libsql-shaped client
 * @param {{projectId: number, owner: string, botId?: string|null, title: string}} fields
 * @returns {Promise<{id: string}>}
 */
export async function createReport(db, { projectId, owner, botId = null, title } = {}) {
  if (!Number.isInteger(projectId)) throw fail("bad_input", "projectId");
  if (typeof owner !== "string" || !owner.trim()) throw fail("bad_input", "owner");
  if (typeof title !== "string" || !title.trim()) throw fail("bad_input", "title");
  if (botId != null && typeof botId !== "string") throw fail("bad_input", "botId");
  const bot = botId ? botId : null;
  const id = "rpt-" + randomBytes(8).toString("hex");
  const at = clockOf(undefined);
  await db.execute({
    sql: `INSERT INTO reports (id, project_id, owner, bot_id, title, recipe_json, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [id, projectId, owner.trim(), bot, title.trim(), EMPTY_RECIPE_JSON, at, at],
  });
  return { id };
}

/**
 * One report, every column, snake_case, or null when there is no such report.
 *
 * @param {object} db
 * @param {string} id
 * @returns {Promise<object|null>}
 */
export async function getReport(db, id) {
  if (typeof id !== "string" || !id) return null;
  const { rows } = await db.execute({
    sql: `SELECT ${REPORT_COLUMNS} FROM reports WHERE id = ?`,
    args: [id],
  });
  return rows[0] ?? null;
}

/**
 * Reports newest first, without their recipe bodies. `projectId` narrows the list to one project's
 * reports; omitted (or null), every report is listed.
 *
 * @param {object} db
 * @param {{projectId?: number|null}} [opts]
 * @returns {Promise<object[]>}
 */
export async function listReports(db, { projectId } = {}) {
  if (projectId != null && !Number.isInteger(projectId)) throw fail("bad_input", "projectId");
  const where = projectId == null ? "" : "WHERE project_id = ?";
  const { rows } = await db.execute({
    sql: `SELECT ${REPORT_LIST_COLUMNS} FROM reports ${where} ORDER BY created_at DESC, id DESC`,
    args: projectId == null ? [] : [projectId],
  });
  return rows;
}

/**
 * Save a recipe: validate it, hash it, then move the report's head and insert its revision in ONE
 * transaction.
 *
 * THE `authoredBy` STAMP (server-side, never the caller's): every `text` block whose own words (its
 * `content`/`text` setting OR its `heading`) changed in this save is stamped with this save's
 * `authorKind`, and a block that did not change keeps the stamp it already carried. A block that carries
 * NO stamp (`authoredBy` missing, or a value this module never writes) is `"bot"`: a recipe written
 * before the stamp existed, or a row inserted straight into the database, is therefore never treated as
 * owner-written, and the PREVIOUS revision's `author_kind` is not inherited either (an owner who edits
 * one block has not become the author of another). A new block counts as changed. The comparison
 * normalises line endings and trailing whitespace, so a save that round-trips a recipe cannot flip a
 * stamp. The stamp is part of the block object, so it is inside both recipe hashes, and it is what lets
 * the run decide whether a bot-written text block still goes through link neutralising. A caller may not
 * set it: any `authoredBy` a recipe arrives with is stripped first, from every block, so the stamp always
 * names the writer the server knows. The head revision the stamp is compared against is the SAME read the
 * compare-and-set below uses (`headRev`), never a second read inside the transaction.
 *
 * The block registry the recipe is VALIDATED against is always the server's own (`blocks/index.js`'s
 * `BLOCKS`): a caller's `registry` never decides what a save accepts, so a caller that declares its own
 * types or skips the real settings checks cannot write a recipe the server could not run. `registry`
 * only affects what `sourcesHash` counts as source-bearing. A recipe the registry refuses - an unknown
 * block type, a missing or repeated id, a block's own settings - is `bad_recipe` with the first error
 * path as its detail, and nothing is written. A recipe above `MAX_RECIPE_BLOCKS` is `bad_recipe` with
 * the detail `too_many_blocks`.
 *
 * The head move is the compare-and-set (`recipe_rev` equal to the revision that was read), so two
 * concurrent saves cannot both claim rev N + 1; the loser gets `code: "conflict"` and nothing is
 * written. Revision 0 has no row - a report nobody has saved yet is at 0 - so the first save is rev 1.
 *
 * THE AUTHOR SEAL (`authorSeal`, optional): a caller may hand over an async callback that makes
 * `{nonce, seal}` for one revision. On an OWNER save (`authorKind === "owner"`) it is awaited BEFORE the
 * transaction, with the revision and the recipe hash this save is about, and its answer is written to
 * `report_state` under `revision_author:<rev>` inside the SAME transaction as the revision row, so a save
 * that loses the compare-and-set (or is refused before it) writes no seal. A BOT save never calls it and
 * never writes a seal, whatever a caller passed. A save with no callback writes no seal either: an owner
 * revision saved that way is not evidence that the owner wrote it, which is the safe side to be wrong on
 * (revision-author.js is the reader). This module imports no seal code: the callback is the whole seam.
 * An answer that is not `{nonce: 32 hex, seal: 64 hex}` writes no seal rather than a broken one.
 *
 * @param {object} db
 * @param {{reportId: string, recipe: object, authorKind: "owner"|"bot",
 *   registry?: Record<string, {sourceBearing?: boolean}>|null, now?: number,
 *   authorSeal?: ((fields: {reportId: string, rev: number, recipeHash: string,
 *     authorKind: "owner"}) => Promise<{nonce: string, seal: string}|null>)|null}} fields
 * @returns {Promise<{rev: number, hash: string, sourcesHash: string}>}
 * @throws {Error} `bad_input`, `bad_author_kind`, `bad_recipe`, `not_found`, `conflict`
 */
export async function saveRecipe(db, { reportId, recipe, authorKind, registry = blockRegistry, now, authorSeal } = {}) {
  idOf(reportId);
  if (!REPORT_AUTHOR_KINDS.includes(authorKind)) throw fail("bad_author_kind", "authorKind");
  // The stamp is read from the head revision's own recipe, so it needs that row before the transaction.
  // `headRev` is also what the compare-and-set below compares against: ONE read of the head decides both
  // what this save stamps and whether it is still the head it read, so a concurrent save can only lose
  // the race (`conflict`), never have its revision stamped from another revision's recipe.
  const headRow = await db.execute({
    sql: "SELECT recipe_rev FROM reports WHERE id = ?",
    args: [reportId],
  });
  if (!headRow.rows[0]) throw fail("not_found", "report");
  const headRev = Number(headRow.rows[0].recipe_rev) || 0;
  const previousRevision = headRev > 0 ? await getRevision(db, reportId, headRev) : null;
  const stamped = stampAuthoredBy(recipe, previousRecipeOf(previousRevision), authorKind);
  // Before the transaction: a refused recipe leaves the row and the revision table exactly as they
  // were, with no transaction ever opened. The REAL registry is the one that validates, whatever a
  // caller passed: `registry` only narrows the sources hash below.
  const errors = validateRecipe(stamped, BLOCKS);
  if (errors.length) throw fail("bad_recipe", errors[0]);
  if (stamped.blocks.length > MAX_RECIPE_BLOCKS) throw fail("bad_recipe", "too_many_blocks");
  const hash = recipeHash(stamped);
  const srcHash = sourcesHash(stamped, registry);
  const recipeJson = canonicalJson(stamped);
  const at = clockOf(now);
  // The author seal, made before the transaction: an owner save is the only writer of one, and a callback
  // that answers nothing (or nothing seal-shaped) writes no seal at all rather than a broken one.
  let authorProof = null;
  if (authorKind === "owner" && typeof authorSeal === "function") {
    const answer = await authorSeal({ reportId, rev: headRev + 1, recipeHash: hash, authorKind });
    const nonce = answer != null && typeof answer === "object" ? answer.nonce : null;
    const seal = answer != null && typeof answer === "object" ? answer.seal : null;
    if (typeof nonce === "string" && AUTHOR_NONCE_HEX.test(nonce)
      && typeof seal === "string" && AUTHOR_SEAL_HEX.test(seal)) {
      authorProof = { nonce, seal };
    }
  }

  return db.runTransaction((run) => {
    const head = run({ sql: "SELECT recipe_rev FROM reports WHERE id = ?", args: [reportId] }).rows[0];
    if (!head) throw fail("not_found", "report");
    const rev = headRev + 1;

    const moved = run({
      sql: `UPDATE reports
               SET recipe_json = ?, recipe_rev = ?, recipe_hash = ?, sources_hash = ?, updated_at = ?
             WHERE id = ? AND recipe_rev = ?`,
      args: [recipeJson, rev, hash, srcHash, at, reportId, headRev],
    });
    if (moved.rowsAffected !== 1) throw fail("conflict", "recipe_rev");

    run({
      sql: `INSERT INTO report_recipe_revisions (${REVISION_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      args: [reportId, rev, recipeJson, hash, srcHash, authorKind, at],
    });
    // The seal rides the same transaction as the revision it is about: a refused save leaves neither.
    if (authorProof) {
      run({
        sql: `INSERT INTO report_state (report_id, key, value_json, updated_at) VALUES (?, ?, ?, ?)
              ON CONFLICT(report_id, key) DO UPDATE SET value_json = excluded.value_json,
                updated_at = excluded.updated_at`,
        args: [reportId, `${REVISION_AUTHOR_STATE_PREFIX}${rev}`, canonicalJson(authorProof), at],
      });
    }
    return { rev, hash, sourcesHash: srcHash };
  });
}

/**
 * One saved revision, or null when the report has no revision at that number.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {number} rev
 * @returns {Promise<object|null>}
 */
export async function getRevision(db, reportId, rev) {
  if (typeof reportId !== "string" || !reportId) return null;
  if (!Number.isInteger(rev)) return null;
  const { rows } = await db.execute({
    sql: `SELECT ${REVISION_COLUMNS} FROM report_recipe_revisions WHERE report_id = ? AND rev = ?`,
    args: [reportId, rev],
  });
  return rows[0] ?? null;
}

/* -------------------------------------------------------------------------- the state */

/**
 * One `report_state` value, parsed from its JSON, or null when the key has never been written.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {string} key
 * @returns {Promise<*|null>}
 */
export async function getState(db, reportId, key) {
  if (typeof reportId !== "string" || !reportId) return null;
  if (typeof key !== "string" || !key) return null;
  const { rows } = await db.execute({
    sql: "SELECT value_json FROM report_state WHERE report_id = ? AND key = ?",
    args: [reportId, key],
  });
  if (!rows[0]) return null;
  try {
    return JSON.parse(rows[0].value_json);
  } catch {
    return null;
  }
}

/**
 * Write one `report_state` value (JSON, upsert) for a report that exists, and read it back.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {string} key
 * @param {*} value anything JSON can carry faithfully
 * @returns {Promise<{key: string, value: *, updatedAt: number}>}
 * @throws {Error} `bad_input` or `not_found`
 */
export async function setState(db, reportId, key, value) {
  idOf(reportId);
  if (typeof key !== "string" || !key) throw fail("bad_input", "key");
  const json = canonicalJson(value);
  const found = await db.execute({ sql: "SELECT id FROM reports WHERE id = ?", args: [reportId] });
  if (!found.rows[0]) throw fail("not_found", "report");
  const at = clockOf(undefined);
  const [, read] = await db.batch([
    {
      sql: `INSERT INTO report_state (report_id, key, value_json, updated_at) VALUES (?, ?, ?, ?)
            ON CONFLICT(report_id, key) DO UPDATE SET value_json = excluded.value_json,
              updated_at = excluded.updated_at`,
      args: [reportId, key, json, at],
    },
    { sql: "SELECT updated_at FROM report_state WHERE report_id = ? AND key = ?", args: [reportId, key] },
  ]);
  return { key, value, updatedAt: read.rows[0]?.updated_at ?? at };
}

/* ------------------------------------------------------------------------ the head columns */

/**
 * Update named head columns on one report (the approvals module's write path), setting `updated_at`
 * with them. A column that is not in WRITABLE_COLUMNS throws, so this cannot be talked into moving the
 * head recipe, the report's id or its owner.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {Record<string, *>} columns column name to value (snake_case, as the schema names them)
 * @returns {Promise<object>} the report row after the write
 * @throws {Error} `bad_input`, `unknown_column` or `not_found`
 */
export async function updateReportColumns(db, reportId, columns) {
  idOf(reportId);
  if (columns == null || typeof columns !== "object" || Array.isArray(columns)) {
    throw fail("bad_input", "columns");
  }
  const names = Object.keys(columns);
  if (!names.length) throw fail("bad_input", "columns");
  for (const name of names) {
    if (!WRITABLE.has(name)) throw fail("unknown_column", name);
  }
  const assignments = names.map((name) => `${name} = ?`).join(", ");
  const args = names.map((name) => (columns[name] === undefined ? null : columns[name]));
  const at = clockOf(undefined);
  const result = await db.execute({
    sql: `UPDATE reports SET ${assignments}, updated_at = ? WHERE id = ?`,
    args: [...args, at, reportId],
  });
  if (result.rowsAffected !== 1) throw fail("not_found", "report");
  return getReport(db, reportId);
}

/* ----------------------------------------------------------------------------- the audit */

/**
 * Append one approval decision to `report_approvals_audit`. `actor` is a short token (`owner`, a bot
 * id) when it is a string; any other value is stored as its canonical JSON. `subject` names what was
 * decided (a recipient address, a host, a proposal id) and may be null.
 *
 * @param {object} db
 * @param {{reportId: string, kind: string, subject?: string|null, actor?: string|object|null,
 *   decided: "approved"|"refused"|"revoked", at?: number}} fields
 * @returns {Promise<{id: number}>}
 * @throws {Error} `bad_input` or `not_found`
 */
export async function recordAudit(db, { reportId, kind, subject = null, actor = null, decided, at } = {}) {
  idOf(reportId);
  if (typeof kind !== "string" || !kind) throw fail("bad_input", "kind");
  if (!APPROVAL_DECISIONS.includes(decided)) throw fail("bad_input", "decided");
  if (subject != null && typeof subject !== "string") throw fail("bad_input", "subject");
  let actorText = null;
  if (typeof actor === "string") actorText = actor;
  else if (actor != null && typeof actor === "object") actorText = canonicalJson(actor);
  else if (actor != null) throw fail("bad_input", "actor");
  const stamp = clockOf(at);
  const results = await db.batch([
    {
      sql: `INSERT INTO report_approvals_audit (report_id, kind, subject, actor, decided, at)
            SELECT ?, ?, ?, ?, ?, ?
            WHERE EXISTS (SELECT 1 FROM reports WHERE id = ?)`,
      args: [reportId, kind, subject, actorText, decided, stamp, reportId],
    },
    { sql: "SELECT last_insert_rowid() AS id", args: [] },
    { sql: "SELECT id FROM reports WHERE id = ?", args: [reportId] },
  ]);
  if (!results[2].rows[0]) throw fail("not_found", "report");
  return { id: Number(results[1].rows[0]?.id ?? 0) };
}