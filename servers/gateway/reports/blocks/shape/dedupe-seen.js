/**
 * The `dedupe_seen` block: drop the items the report has already shown, and re-surface one whose listed
 * fields changed. It reads nothing new, so it is free, and it writes one `report_state` value.
 *
 * Settings: `{keyField, refreshFields?: string[]}`. State key: `seen:<blockId>`, holding
 * `{<key>: <hash of the refresh fields' values>}`, capped at 5000 keys (the oldest are dropped).
 *   - a key never seen: kept, and its hash recorded;
 *   - a key seen with the same hash: dropped;
 *   - a key seen with a different hash: kept with `_resurfaced: true`, and the hash replaced.
 *
 * `refreshFields` absent means "the key alone": a seen key is dropped, and nothing can re-surface it.
 *
 * NOTHING IS WRITTEN HERE: the block only buffers the new value through `ctx.setState`, and the run
 * engine applies it after a run that ends well. A failed run, or any preview, leaves `report_state` as
 * it was. An item with no value for `keyField` cannot be deduped, so it is kept untouched.
 *
 * State keys are built from the block's id, which is why a block id may not contain a colon and why
 * `ctx.setState` refuses the keys the artifact bridge owns.
 */
import { createHash } from "node:crypto";
import { canonicalJson } from "../../recipe-hash.js";
import { carryUntrusted } from "../../untrusted-items.js";

/** How many keys one report's `seen` map may hold. */
export const MAX_SEEN_KEYS = 5000;

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
  if (settings.refreshFields !== undefined) {
    if (!Array.isArray(settings.refreshFields)) errors.push("refreshFields");
    else if (!settings.refreshFields.every((field) => typeof field === "string" && field)) {
      errors.push("refreshFields");
    }
  }
  return errors;
}

async function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const keyField = settings.keyField;
  const refreshFields = Array.isArray(settings.refreshFields) ? settings.refreshFields : [];
  const stateKey = "seen:" + String(ctx.blockId ?? "");
  const seen = plainCopy(await ctx.getState(stateKey));
  const items = Array.isArray(input?.items) ? input.items : [];
  const kept = [];
  for (const item of items) {
    const key = readField(item, keyField);
    if (key === undefined || key === null || key === "") {
      kept.push(item);
      continue;
    }
    const id = String(key);
    const hash = hashOf(refreshFields.map((field) => {
      const value = readField(item, field);
      return value === undefined ? null : value;
    }));
    const known = Object.hasOwn(seen, id);
    if (known && seen[id] === hash) continue;
    // A re-surfaced item is a rebuilt one: it carries the mark of the item it was built from
    // (untrusted-items.js).
    kept.push(known ? carryUntrusted(item, { ...item, _resurfaced: true }) : item);
    seen[id] = hash;
  }
  ctx.setState(stateKey, capped(seen, MAX_SEEN_KEYS));
  return { items: kept };
}

export const dedupeSeenBlock = Object.freeze({
  type: "dedupe_seen",
  kind: "shape",
  sourceBearing: false,
  validate,
  run,
});