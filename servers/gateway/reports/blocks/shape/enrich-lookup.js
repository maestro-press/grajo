/**
 * The `enrich_lookup` block: add fields from an earlier source block's items to this block's items.
 *
 * Settings: `{source, joinField, lookupKey, fields, prefix?}`. `source` names an EARLIER source block by
 * its id; the run executor keeps every source block's output for the rest of the run, and this block
 * joins `fields` from the matching row of that output onto each of its own items. `prefix` (default
 * none) is put in front of every added field name, so a join cannot silently overwrite a field the item
 * already carries under the same name.
 *
 * It is SOURCE-BEARING (`sourceBearing: true`), because which earlier source it reads is exactly what
 * the owner approved; its own settings are part of `sourcesHash`. A join whose source block did not run
 * in this recipe throws `source_not_found`, which the executor records as a warning: an enrich block is
 * a shape block, and its failure does not fail the run.
 */

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function fail(code) {
  const err = new Error(code);
  err.code = code;
  return err;
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

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  for (const name of ["source", "joinField", "lookupKey"]) {
    if (typeof settings[name] !== "string" || !settings[name]) errors.push(name);
  }
  if (!Array.isArray(settings.fields) || settings.fields.length === 0) errors.push("fields");
  else if (!settings.fields.every((field) => typeof field === "string" && field)) errors.push("fields");
  if (settings.prefix !== undefined && typeof settings.prefix !== "string") errors.push("prefix");
  return errors;
}

async function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const retained = ctx.sources instanceof Map ? ctx.sources.get(settings.source) : undefined;
  if (!Array.isArray(retained)) throw fail("source_not_found");
  const index = new Map();
  for (const row of retained) {
    const key = readField(row, settings.lookupKey);
    if (key === undefined || key === null || key === "") continue;
    const id = String(key);
    if (!index.has(id)) index.set(id, row);
  }
  const prefix = typeof settings.prefix === "string" ? settings.prefix : "";
  const items = Array.isArray(input?.items) ? input.items : [];
  return {
    items: items.map((item) => {
      const key = readField(item, settings.joinField);
      if (key === undefined || key === null || key === "") return item;
      const row = index.get(String(key));
      if (!row) return item;
      const extra = {};
      for (const field of settings.fields) {
        const value = readField(row, field);
        if (value !== undefined) extra[prefix + field] = value;
      }
      return { ...item, ...extra };
    }),
  };
}

export const enrichLookupBlock = Object.freeze({
  type: "enrich_lookup",
  kind: "shape",
  sourceBearing: true,
  validate,
  run,
});