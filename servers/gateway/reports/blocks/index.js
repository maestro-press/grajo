/**
 * The block registry: the one module-level list of what a report recipe may name, what each kind of
 * block does with the owner's approval, and what a save refuses.
 *
 * `BLOCKS` is the full registry (type -> `{type, kind, sourceBearing, validate, run?}`) and
 * `blockRegistry` is the narrow view the recipe hashes take (`{type: {sourceBearing, kind}}`).
 * `sourceBearing` is the seal rule: a block that reads something the owner approved, or sends the
 * report's items to a model, is source-bearing, so changing it (or adding, removing or reordering one)
 * moves `sourcesHash` and needs a fresh go-live. A block that only selects or arranges data is free.
 *
 * ADDING OR CHANGING A REGISTRY ENTRY'S `sourceBearing` CHANGES EXISTING SEALED `sourcesHash` VALUES:
 * a revision sealed while a type counted one way recomputes to a different hash under a registry that
 * counts it the other way, so every report sealed before that change stops verifying and must go live
 * again. Treat a flag change as a migration, not a tweak.
 *
 * KINDS, and what the run executor (blocks/run-recipe.js) does with each:
 *   - `source`: reads something (a feed, a mailbox, a file). `sourceBearing: true`, so it carries its own
 *     `validate` and `run`. A source block with no `run` (a type registered by metadata only) is a NAMED
 *     source error at run time (`source_not_available`), never a silent skip.
 *   - `shape`: filters, sorts or annotates the items a source produced. Never reads anything new, so a
 *     failure is a warning, not a source error.
 *   - `present`: turns items into a document section. Has no `run` in this round: the executor skips it.
 *     `ai_commentary` and `annotate` send items to a model, so they are `sourceBearing: true`.
 *   - `custom`: runs the report's own approved step. `sourceBearing: true`.
 *
 * `validate(settings)` answers a list of error tokens (field names, never prose), and `validateRecipe`
 * prefixes each with the block's path (`blocks[2].field`) so a refusal names what to fix. A registry
 * entry that carries no `validate` (a test's narrow stub registry) only has its `settings` checked for
 * being an object.
 */
import { MODEL_BLOCK_TYPES } from "../recipe-hash.js";
import { customBlock } from "./custom.js";
import { httpJsonBlock } from "./sources/http-json.js";
import { mailAlertsBlock } from "./sources/mail-alerts.js";
import { rssBlock } from "./sources/rss.js";
import { workspaceFileBlock } from "./sources/workspace-file.js";
import { dedupeSeenBlock } from "./shape/dedupe-seen.js";
import { diffLastBlock } from "./shape/diff-last.js";
import { enrichLookupBlock } from "./shape/enrich-lookup.js";
import { filterBlock } from "./shape/filter.js";
import { sortBlock } from "./shape/sort.js";

/** A block id: lower case, starts with a letter, short enough to sit in a `report_state` key. */
export const BLOCK_ID_RE = /^[a-z][a-z0-9_-]{0,31}$/;

/** The kinds the run executor knows how to route. */
export const BLOCK_KINDS = Object.freeze(["source", "shape", "present", "custom"]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

/** The validation a metadata-only entry carries: its settings must at least be an object. */
function settingsObject(settings) {
  return isPlainObject(settings) ? [] : ["settings"];
}

/** A present block: it renders, it does not read. Model-calling present blocks are source-bearing. */
function presentEntry(type, sourceBearing) {
  return Object.freeze({
    type,
    kind: "present",
    sourceBearing,
    validate: settingsObject,
  });
}

const REGISTERED = [
  // Sources: each one reads something the owner approved, and each one refuses on its own terms.
  httpJsonBlock,
  rssBlock,
  mailAlertsBlock,
  workspaceFileBlock,
  // Shape blocks: they only select or arrange items a source already produced.
  filterBlock,
  sortBlock,
  dedupeSeenBlock,
  diffLastBlock,
  enrichLookupBlock,
  // The report's own approved step.
  customBlock,
  // Present blocks: the document assembly that calls them arrives in a later round.
  presentEntry("table", false),
  presentEntry("cards", false),
  presentEntry("chart", false),
  presentEntry("map", false),
  presentEntry("text", false),
  ...MODEL_BLOCK_TYPES.map((type) => presentEntry(type, true)),
];

function buildRegistry(entries) {
  const out = {};
  for (const entry of entries) {
    if (!entry || typeof entry !== "object") throw new Error("block_entry");
    if (typeof entry.type !== "string" || !entry.type) throw new Error("block_type");
    if (!BLOCK_KINDS.includes(entry.kind)) throw new Error("block_kind");
    if (typeof entry.sourceBearing !== "boolean") throw new Error("block_source_bearing");
    if (typeof entry.validate !== "function") throw new Error("block_validate");
    if (entry.run !== undefined && typeof entry.run !== "function") throw new Error("block_run");
    if (Object.hasOwn(out, entry.type)) throw new Error("block_duplicate");
    out[entry.type] = entry;
  }
  return Object.freeze(out);
}

/** The full registry: type -> `{type, kind, sourceBearing, validate, run?}`. */
export const BLOCKS = buildRegistry(REGISTERED);

/**
 * The view the recipe hashes take: type -> `{sourceBearing, kind}`. Nothing else reads this, so a new
 * registry entry automatically reaches `sourcesHash` with the flag it declares.
 */
export const blockRegistry = Object.freeze(Object.fromEntries(
  Object.entries(BLOCKS).map(([type, entry]) => [type, Object.freeze({
    sourceBearing: entry.sourceBearing,
    kind: entry.kind,
  })]),
));

/** The entry for one type: the caller's registry first, then the full registry's own entry. */
function entryFor(registry, type) {
  if (typeof type !== "string" || !type) return null;
  const fromRegistry = registry != null && typeof registry === "object" && Object.hasOwn(registry, type)
    ? registry[type]
    : null;
  if (fromRegistry != null && typeof fromRegistry === "object") return fromRegistry;
  return Object.hasOwn(BLOCKS, type) ? BLOCKS[type] : null;
}

/**
 * The settings check for one type: the caller's own, else the full registry's (a narrow stub registry
 * that only declares `sourceBearing` still gets the server's real checks for a type the server ships).
 */
function validatorFor(registry, type) {
  for (const entry of [entryFor(registry, type), Object.hasOwn(BLOCKS, type) ? BLOCKS[type] : null]) {
    if (entry && typeof entry.validate === "function") return entry.validate;
  }
  return null;
}

/**
 * Everything wrong with a recipe, as a list of paths: the recipe itself, an unknown block type, a
 * missing or malformed or repeated block id, and each block's own settings checks.
 *
 * A `registry` narrows what counts as a known type (and, when its entries carry `validate`, what gets
 * checked); the full registry backs it up, so the server's own save path validates every setting. An
 * explicit `null` registry checks only the shape and the ids, which is what a caller measuring "no
 * registry at all" (every block source-bearing) asks for.
 *
 * @param {*} recipe
 * @param {Record<string, {validate?: Function}>|null} [registry]
 * @returns {string[]} error paths, empty when the recipe is acceptable
 */
export function validateRecipe(recipe, registry = BLOCKS) {
  if (!isPlainObject(recipe)) return ["recipe"];
  const blocks = recipe.blocks;
  if (!Array.isArray(blocks)) return ["blocks"];
  const errors = [];
  const ids = new Set();
  blocks.forEach((block, index) => {
    const path = `blocks[${index}]`;
    if (!isPlainObject(block)) {
      errors.push(path);
      return;
    }
    const entry = registry == null ? null : entryFor(registry, block.type);
    if (registry != null) {
      if (typeof block.type !== "string" || !block.type) errors.push(`${path}.type`);
      else if (!entry) errors.push(`${path}.type_unknown`);
    }
    if (typeof block.id !== "string" || !BLOCK_ID_RE.test(block.id)) errors.push(`${path}.id`);
    else if (ids.has(block.id)) errors.push(`${path}.id_duplicate`);
    else ids.add(block.id);
    if (registry == null) return;
    const validateFn = validatorFor(registry, block.type);
    if (validateFn) {
      const found = validateFn(block.settings);
      if (Array.isArray(found)) for (const token of found) errors.push(`${path}.${token}`);
    } else if (!isPlainObject(block.settings)) {
      errors.push(`${path}.settings`);
    }
  });
  return errors;
}