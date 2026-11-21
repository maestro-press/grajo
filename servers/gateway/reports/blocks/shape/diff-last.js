/**
 * The `diff_last` block: mark each item against the last run. It reads nothing new, so it is free, and
 * it writes one `report_state` value.
 *
 * Settings: `{keyField}`. State key: `last:<blockId>`, holding `{<key>: <hash of the whole item>}`. Every
 * item keeps its fields and gains `_diff`:
 *   - `new`: the key was not in the last map;
 *   - `changed`: the key was, and the item's own hash moved;
 *   - `same`: the key was, and the item is unchanged.
 * An item whose key was in the last map and is not in this one is appended as `{<keyField>: <key>,
 * _diff: "gone"}`: the key is all a "gone" line needs, and the last run's item is not kept around.
 *
 * The map is capped at 5000 keys (the newest are kept) so a report whose keys grow every run cannot grow
 * `report_state` without bound.
 *
 * NOTHING IS WRITTEN HERE: the block only buffers the new value through `ctx.setState`, and the run
 * engine applies it after a run that ends well. A failed run, or any preview, leaves `report_state` as
 * it was. An item with no value for `keyField` gets `_diff: "new"` and is not remembered.
 */
import { createHash } from "node:crypto";
import { canonicalJson } from "../../recipe-hash.js";

/** How many keys one report's `last` map may hold. */
export const MAX_LAST_KEYS = 5000;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

/** The field reader the shape blocks share: an item's own key, or a dotted path into its objects. */
function readField(item, field) {
  if (item == null || typeof field !== "string" || !field) return undefined;
  if (Object.hasOwn(item, field)) return item[field];
  let cursor = item;
  for (const part of field.split(".")) {
    if (cursor == null || typeof cursor !== "object" || !Object.hasOwn(cursor, part)) return undefined;
    cursor = cursor[part];
  }
  return cursor;
}

function hashOf(value) {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

/** A null-prototype copy, so a key like `__proto__` is stored as data and not as a prototype. */
function plainCopy(value) {
  const out = Object.create(null);
  if (isPlainObject(value)) {
    for (const key of Object.keys(value)) out[key] = value[key];
  }
  return out;
}

/** The map with at most `max` keys: the oldest insertions go first. */
function capped(map, max) {
  const keys = Object.keys(map);
  if (keys.length <= max) return map;
  const out = Object.create(null);
  for (const key of keys.slice(keys.length - max)) out[key] = map[key];
  return out;
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  if (typeof settings.keyField !== "string" || !settings.keyField) errors.push("keyField");
  return errors;
}

async function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const keyField = settings.keyField;
  const stateKey = "last:" + String(ctx.blockId ?? "");
  const last = plainCopy(await ctx.getState(stateKey));
  const items = Array.isArray(input?.items) ? input.items : [];
  const next = Object.create(null);
  const present = new Set();
  const out = [];
  for (const item of items) {
    const key = readField(item, keyField);
    let diff = "new";
    if (key !== undefined && key !== null && key !== "") {
      const id = String(key);
      const hash = hashOf(item);
      present.add(id);
      const known = Object.hasOwn(last, id);
      if (known && last[id] === hash) diff = "same";
      else if (known) diff = "changed";
      next[id] = hash;
    }
    out.push({ ...item, _diff: diff });
  }
  const kept = capped(next, MAX_LAST_KEYS);
  for (const id of Object.keys(last)) {
    if (present.has(id)) continue;
    out.push({ [keyField]: id, _diff: "gone" });
  }
  ctx.setState(stateKey, kept);
  return { items: out };
}

export const diffLastBlock = Object.freeze({
  type: "diff_last",
  kind: "shape",
  sourceBearing: false,
  validate,
  run,
});