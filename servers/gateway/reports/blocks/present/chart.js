/**
 * The `chart` present block: a Vega-Lite spec as one fenced `vega-lite` block, with inline data only.
 *
 * Settings: `{spec: object, dataFrom?: "items"}`. The spec's data is the run's own items, written INTO
 * the fence as `data.values`, so the block never points a renderer at a URL: a spec carrying `url`,
 * `href` or `datasets` anywhere is refused (`external_data`), and an authored spec over 64 KB is refused
 * (`spec_too_large`). The chart counts as one of the document's 12 specs (the document LEXES the fence
 * count out of the markdown it writes).
 *
 * ONLY THE FIELDS THE SPEC READS GO IN: every `field`/`groupby` the spec names (in `encoding`, a
 * `transform`, a tooltip, a sort) is collected, and each row is written with just those keys, so a
 * 2000-row chart does not carry every column of every item into a version. When rows have to be dropped
 * to fit 64 KB (or the row cap), the run gets a warning with the code word `chart_rows_dropped`: a chart
 * that quietly shows fewer rows than the report is a wrong report.
 *
 * The renderer turns the fence into an SVG at save time. When its renderer is down the version keeps the
 * fence as code under `RENDERER_DOWN_NOTE` (the artifact renderer's own note), which is why a refused
 * spec is a present-block warning rather than a run that never happened.
 */
const SPEC_MAX_BYTES = 64 * 1024;
const VALUES_MAX = 2000;
const EXTERNAL_KEYS = new Set(["url", "href", "datasets"]);

/** The spec keys that name the data fields a chart reads. */
const FIELD_KEYS = new Set(["field", "groupby"]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function fail(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  if (!isPlainObject(settings.spec)) errors.push("spec");
  if (Object.hasOwn(settings, "dataFrom") && settings.dataFrom !== "items") errors.push("dataFrom");
  return errors;
}

/** The first key a spec uses to reach outside itself, or "" when it stays inline. */
function externalKey(node, depth = 0) {
  if (depth > 24) return "depth";
  if (Array.isArray(node)) {
    for (const entry of node) {
      const found = externalKey(entry, depth + 1);
      if (found) return found;
    }
    return "";
  }
  if (!isPlainObject(node)) return "";
  for (const [key, value] of Object.entries(node)) {
    if (EXTERNAL_KEYS.has(key)) return key;
    const found = externalKey(value, depth + 1);
    if (found) return found;
  }
  return "";
}

function jsonBytes(value) {
  const json = JSON.stringify(value);
  if (typeof json !== "string") throw fail("bad_spec");
  return Buffer.byteLength(json, "utf8");
}

/**
 * Every field name a spec reads, from any `field` or `groupby` it carries: an encoding channel, a
 * transform, a tooltip, a sort. A spec that names none of them has no data to narrow.
 */
function referencedFields(spec) {
  const fields = new Set();
  const walk = (node, depth) => {
    if (depth > 24) return;
    if (Array.isArray(node)) {
      for (const entry of node) walk(entry, depth + 1);
      return;
    }
    if (!isPlainObject(node)) return;
    for (const [key, value] of Object.entries(node)) {
      if (FIELD_KEYS.has(key)) {
        if (typeof value === "string" && value) fields.add(value);
        else if (Array.isArray(value)) {
          for (const entry of value) if (typeof entry === "string" && entry) fields.add(entry);
        }
      }
      walk(value, depth + 1);
    }
  };
  walk(spec, 0);
  return fields;
}

/** One row with only the fields the spec reads; the row itself when the spec reads none of them. */
function narrowRow(item, fields) {
  if (!fields.size || !isPlainObject(item)) return item;
  const row = {};
  for (const field of fields) if (Object.hasOwn(item, field)) row[field] = item[field];
  return row;
}

/**
 * The spec with the items as its inline data, cut down until it fits the renderer's 64 KB limit. A spec
 * that is over the limit with no data at all is refused: the renderer would refuse it too.
 *
 * @returns {{chart: object, rows: number}} the spec, and how many rows it carries
 */
function withInlineData(spec, items) {
  const fields = referencedFields(spec);
  let values = items.slice(0, VALUES_MAX).map((item) => narrowRow(item, fields));
  for (;;) {
    const candidate = { ...spec, data: { values } };
    if (jsonBytes(candidate) <= SPEC_MAX_BYTES) return { chart: candidate, rows: values.length };
    if (values.length === 0) throw fail("spec_too_large");
    values = values.slice(0, Math.floor(values.length / 2));
  }
}

function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const spec = isPlainObject(settings.spec) ? settings.spec : null;
  if (!spec) throw fail("bad_settings");
  if (jsonBytes(spec) > SPEC_MAX_BYTES) throw fail("spec_too_large");
  const external = externalKey(spec);
  if (external) throw fail("external_data");
  const items = Array.isArray(input?.items) ? input.items : [];
  const sections = Array.isArray(input?.sections) ? input.sections : [];
  const { chart, rows } = withInlineData(spec, items);
  const markdown = "```vega-lite\n" + JSON.stringify(chart) + "\n```";
  const section = { type: "chart", blockId: ctx.blockId, markdown, specs: 1 };
  const out = { items, sections: [...sections, section] };
  // Never silently: a chart drawn from fewer rows than the run carries says so in the run's warnings.
  if (rows < items.length) out.warnings = [{ message: "chart_rows_dropped" }];
  return out;
}

export const chartBlock = Object.freeze({
  type: "chart",
  kind: "present",
  sourceBearing: false,
  validate,
  run,
});