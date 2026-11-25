/**
 * What a report pickup may SUGGEST changing, as an ALLOW-list.
 *
 * A pickup turn reads comments written by people outside Crow, and `report_propose_change` turns what it
 * decides into a pending free change the owner applies with one tap. So the patch it may carry is as
 * small as can be and is described by what IS allowed, never by what is refused: a block type, a setting
 * key or a patch key that is not named below is `not_proposable`, whatever it is called, so a block type
 * or setting added to the registry later is NOT proposable until someone adds it here on purpose.
 *
 * A patch is `{blocks: [{id, settings}]}`:
 *   - it edits blocks that ALREADY EXIST in the report's current head recipe, found by `id`; it cannot
 *     add, remove, reorder or retype a block, and it has no key for anything but `blocks`, so it cannot
 *     reach recipients, hosts, endpoints, credentials, secrets, custom-step code or bundles, the
 *     schedule or its send target, or any other column;
 *   - each entry carries only `id` and `settings`, and `settings` is merged over that block's own
 *     settings, key by key;
 *   - the target block's type must be on `PROPOSABLE_SETTINGS` (below), and every settings key on that
 *     type's own list. The listed types are the presentation and shaping blocks (`text`, `table`,
 *     `cards`, `sort`, `filter`, `map`); every source block (`http_json`, `rss`, `mail_alerts`,
 *     `workspace_file`), every block that sends items to a model (`ai_commentary`, `annotate`), `custom`,
 *     `chart` (its spec can name external data), and the shaping blocks that read a second source
 *     (`enrich_lookup`, `dedupe_seen`, `diff_last`) are absent, so a patch cannot touch a source or any
 *     source-bearing setting;
 *   - values are plain data: short strings, finite numbers, booleans, lists of strings (column and field
 *     names) and, for `filter`'s `all`, a list of `{field, op, value}` conditions. Anything else is refused.
 *
 * The result still goes through `botSaveRecipe`, which validates it against the full block registry and
 * lands it as the existing pending free change; this module only decides what may be tried.
 *
 * Pure: no imports, so the pickup door can carry it without reaching anything else.
 */

/** Block type -> the setting keys a pickup may change on it. The whole allow-list. */
export const PROPOSABLE_SETTINGS = Object.freeze({
  text: Object.freeze(["heading", "content", "text"]),
  table: Object.freeze(["heading", "maxRows", "columns"]),
  cards: Object.freeze(["heading", "maxRows", "fields"]),
  sort: Object.freeze(["field", "direction"]),
  filter: Object.freeze(["all", "field", "op", "value"]),
  map: Object.freeze(["latField", "lonField", "labelField"]),
});

/** The condition keys inside `filter`'s `all` list. */
const CONDITION_KEYS = Object.freeze(["field", "op", "value"]);

const MAX_PATCH_BLOCKS = 20;
const MAX_STRING = 4000;
const MAX_LIST = 50;
const MAX_CONDITIONS = 20;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function ownKeysAre(object, allowed) {
  return Object.keys(object).every((key) => allowed.includes(key));
}

function okString(value) {
  return typeof value === "string" && value.length <= MAX_STRING;
}

function okPrimitive(value) {
  if (typeof value === "string") return value.length <= MAX_STRING;
  if (typeof value === "number") return Number.isFinite(value);
  return typeof value === "boolean";
}

function okStringList(value) {
  return Array.isArray(value) && value.length <= MAX_LIST && value.every(okString);
}

function okConditions(value) {
  return Array.isArray(value) && value.length <= MAX_CONDITIONS && value.every((condition) =>
    isPlainObject(condition) && ownKeysAre(condition, CONDITION_KEYS)
    && (!Object.hasOwn(condition, "field") || okString(condition.field))
    && (!Object.hasOwn(condition, "op") || okString(condition.op))
    && (!Object.hasOwn(condition, "value") || okPrimitive(condition.value)));
}

/** One setting's value, by key: lists for the field lists, conditions for `all`, primitives otherwise. */
function okValue(key, value) {
  if (key === "columns" || key === "fields") return okStringList(value);
  if (key === "all") return okConditions(value);
  return okPrimitive(value);
}

/**
 * Judge a patch against the report's CURRENT head recipe.
 *
 * @param {unknown} patch what the model sent
 * @param {{blocks?: object[]}|null} head the head recipe, parsed
 * @returns {{ok: true, recipe: object}|{ok: false}} the recipe to save (the head with the patch merged,
 *   nothing else changed), or a refusal with no detail (the caller answers `not_proposable`)
 */
export function applyProposablePatch(patch, head) {
  if (!isPlainObject(patch) || !ownKeysAre(patch, ["blocks"])) return { ok: false };
  const entries = patch.blocks;
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_PATCH_BLOCKS) return { ok: false };
  if (!isPlainObject(head) || !Array.isArray(head.blocks)) return { ok: false };

  const byId = new Map();
  for (const entry of entries) {
    if (!isPlainObject(entry) || !ownKeysAre(entry, ["id", "settings"])) return { ok: false };
    if (typeof entry.id !== "string" || byId.has(entry.id)) return { ok: false };
    if (!isPlainObject(entry.settings) || Object.keys(entry.settings).length === 0) return { ok: false };
    byId.set(entry.id, entry.settings);
  }

  const seen = new Set();
  const blocks = head.blocks.map((block) => {
    if (!isPlainObject(block) || typeof block.id !== "string" || !byId.has(block.id)) return block;
    seen.add(block.id);
    const allowed = typeof block.type === "string" && Object.hasOwn(PROPOSABLE_SETTINGS, block.type)
      ? PROPOSABLE_SETTINGS[block.type] : null;
    const changes = byId.get(block.id);
    if (!allowed || !ownKeysAre(changes, allowed)) return null;
    for (const [key, value] of Object.entries(changes)) {
      if (!okValue(key, value)) return null;
    }
    return { ...block, settings: { ...(isPlainObject(block.settings) ? block.settings : {}), ...changes } };
  });
  // A block that failed its check, or a patch naming a block the recipe does not have.
  if (blocks.includes(null) || seen.size !== byId.size) return { ok: false };
  return { ok: true, recipe: { ...head, blocks } };
}
