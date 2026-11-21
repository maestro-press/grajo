/**
 * The `sort` block: order the items by one field. It reads nothing new, so it is free.
 *
 * Settings: `{field, direction: "asc"|"desc"}`. The sort is STABLE (items with equal keys keep their
 * order, which is what makes a second sort on another field possible at all), numbers compare as
 * numbers, and an item with no value for the field sorts last in both directions rather than jumping to
 * the top of a descending list.
 */

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

function isMissing(value) {
  return value === undefined || value === null || value === "";
}

function isNumeric(value) {
  if (typeof value === "number") return Number.isFinite(value);
  return typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value));
}

function bothNumbers(a, b) {
  return isNumeric(a) && isNumeric(b);
}

/** A negative/zero/positive comparison of two present values. */
function comparePresent(a, b) {
  if (bothNumbers(a, b)) {
    const left = Number(a);
    const right = Number(b);
    return left === right ? 0 : (left < right ? -1 : 1);
  }
  const left = String(a);
  const right = String(b);
  return left === right ? 0 : (left < right ? -1 : 1);
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  if (typeof settings.field !== "string" || !settings.field) errors.push("field");
  if (settings.direction !== "asc" && settings.direction !== "desc") errors.push("direction");
  return errors;
}

function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const items = Array.isArray(input?.items) ? input.items : [];
  const descending = settings.direction === "desc";
  const rows = items.map((item, index) => ({ item, index }));
  rows.sort((left, right) => {
    const a = readField(left.item, settings.field);
    const b = readField(right.item, settings.field);
    const aMissing = isMissing(a);
    const bMissing = isMissing(b);
    if (aMissing || bMissing) {
      if (aMissing && bMissing) return left.index - right.index;
      return aMissing ? 1 : -1;
    }
    const order = comparePresent(a, b);
    if (order !== 0) return descending ? -order : order;
    return left.index - right.index;
  });
  return { items: rows.map((row) => row.item) };
}

export const sortBlock = Object.freeze({
  type: "sort",
  kind: "shape",
  sourceBearing: false,
  validate,
  run,
});