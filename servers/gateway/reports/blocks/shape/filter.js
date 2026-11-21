/**
 * The `filter` block: keep the items a condition set matches. It reads nothing new, so it is free (a
 * settings change applies with an automatic preview, and never moves `sourcesHash`).
 *
 * Settings: `{field, op, value?}` for one condition, or `{all: [{field, op, value?}, ...]}` for several
 * (every one must match). Ops: `eq`, `ne`, `contains`, `gt`, `gte`, `lt`, `lte`, `exists`. `exists` needs
 * no `value`; every other op does. Ordering ops compare numbers as numbers and anything else as text;
 * `contains` is case-insensitive.
 *
 * `field` is the item's own key, and a dotted path walks nested objects (`attributes.title`).
 */

const OPS = Object.freeze(["eq", "ne", "contains", "gt", "gte", "lt", "lte", "exists"]);

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
  return value === undefined || value === null;
}

function isNumeric(value) {
  if (typeof value === "number") return Number.isFinite(value);
  return typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value));
}

function bothNumbers(a, b) {
  return isNumeric(a) && isNumeric(b);
}

function same(actual, expected) {
  if (isMissing(actual) && isMissing(expected)) return true;
  if (bothNumbers(actual, expected)) return Number(actual) === Number(expected);
  if (isMissing(actual) || isMissing(expected)) return false;
  return String(actual) === String(expected);
}

function contains(actual, expected) {
  if (isMissing(actual)) return false;
  const needle = String(expected == null ? "" : expected).toLowerCase();
  if (Array.isArray(actual)) {
    return actual.some((entry) => String(entry == null ? "" : entry).toLowerCase().includes(needle));
  }
  return String(actual).toLowerCase().includes(needle);
}

/** A negative/zero/positive comparison, or null when the two cannot be ordered. */
function compare(actual, expected) {
  if (isMissing(actual) || isMissing(expected)) return null;
  if (bothNumbers(actual, expected)) {
    const left = Number(actual);
    const right = Number(expected);
    return left === right ? 0 : (left < right ? -1 : 1);
  }
  const left = String(actual);
  const right = String(expected);
  return left === right ? 0 : (left < right ? -1 : 1);
}

function matches(item, condition) {
  const actual = readField(item, condition.field);
  const expected = condition.value;
  switch (condition.op) {
    case "exists": return !isMissing(actual) && actual !== "";
    case "eq": return same(actual, expected);
    case "ne": return !same(actual, expected);
    case "contains": return contains(actual, expected);
    case "gt": { const c = compare(actual, expected); return c !== null && c > 0; }
    case "gte": { const c = compare(actual, expected); return c !== null && c >= 0; }
    case "lt": { const c = compare(actual, expected); return c !== null && c < 0; }
    case "lte": { const c = compare(actual, expected); return c !== null && c <= 0; }
    default: return false;
  }
}

function conditionsOf(settings) {
  if (Array.isArray(settings.all)) return settings.all;
  return [settings];
}

function validateCondition(condition) {
  if (!isPlainObject(condition)) return ["conditions"];
  const errors = [];
  if (typeof condition.field !== "string" || !condition.field) errors.push("field");
  if (typeof condition.op !== "string" || !OPS.includes(condition.op)) errors.push("op");
  else if (condition.op !== "exists" && condition.value === undefined) errors.push("value");
  return errors;
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  if (Object.hasOwn(settings, "all")) {
    if (!Array.isArray(settings.all) || settings.all.length === 0) return ["all"];
    const errors = [];
    settings.all.forEach((condition, index) => {
      for (const token of validateCondition(condition)) errors.push(`all[${index}].${token}`);
    });
    return errors;
  }
  return validateCondition(settings);
}

function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const conditions = conditionsOf(settings);
  const items = Array.isArray(input?.items) ? input.items : [];
  return { items: items.filter((item) => conditions.every((condition) => matches(item, condition))) };
}

export const filterBlock = Object.freeze({
  type: "filter",
  kind: "shape",
  sourceBearing: false,
  validate,
  run,
});