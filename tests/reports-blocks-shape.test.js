// The shape blocks, on their own: filter's ops, a stable numeric sort, dedupe_seen's re-surface rule,
// diff_last's four marks, and the enrich join. Every block gets a bare `ctx` (no database handle at all
// except where a test hands one that refuses to be used), so a buffered state write is the only side
// effect a shape block can have.
import { test } from "node:test";
import assert from "node:assert/strict";

const { filterBlock } = await import("../servers/gateway/reports/blocks/shape/filter.js");
const { sortBlock } = await import("../servers/gateway/reports/blocks/shape/sort.js");
const { dedupeSeenBlock } = await import("../servers/gateway/reports/blocks/shape/dedupe-seen.js");
const { diffLastBlock } = await import("../servers/gateway/reports/blocks/shape/diff-last.js");
const { enrichLookupBlock } = await import("../servers/gateway/reports/blocks/shape/enrich-lookup.js");
const { BLOCKS, blockRegistry, validateRecipe } = await import(
  "../servers/gateway/reports/blocks/index.js"
);

/**
 * A block's `ctx`: the flowing input is passed to `run`, the state starts from `initial` and every
 * `setState` is recorded. `db` is a handle that throws on any use, so a block that reaches for the
 * database instead of buffering fails the test loudly.
 */
function context(settings, { id = "b1", state = {}, sources = new Map(), db } = {}) {
  const writes = [];
  const memory = new Map(Object.entries(state));
  const ctx = {
    db: db ?? { execute() { throw new Error("a shape block touched the database"); } },
    deps: {},
    report: { id: "rpt-0000000000000000" },
    run: { trigger: "manual" },
    live: null,
    block: { id, type: "shape", settings },
    blockId: id,
    sources,
    async getState(key) { return memory.has(key) ? memory.get(key) : null; },
    setState(key, value) { writes.push({ key, value }); memory.set(key, value); },
  };
  return { ctx, writes, memory };
}

const LISTINGS = Object.freeze([
  { id: "a", title: "Lovely flat", price: 100, tags: ["new"] },
  { id: "b", title: "Cottage", price: 250, tags: [] },
  { id: "c", title: "Flat with garden", price: "250", tags: ["garden"] },
  { id: "d", title: "Loft", price: 90 },
]);

/** The state a block would read on the next run, keyed the way `getState` looks it up. */
function stateAfter(writes) {
  return Object.fromEntries(writes.map((write) => [write.key, write.value]));
}

async function runFilter(settings, items = LISTINGS) {
  const { ctx } = context(settings);
  return (await filterBlock.run(ctx, { items, sections: [] })).items;
}

/* ------------------------------------------------------------------------- filter */

test("filter keeps what each op matches, and only that", async () => {
  assert.deepEqual((await runFilter({ field: "price", op: "eq", value: 100 })).map((i) => i.id), ["a"]);
  assert.deepEqual((await runFilter({ field: "price", op: "eq", value: "250" })).map((i) => i.id), ["b", "c"],
    "a numeric string and a number are the same value");
  assert.deepEqual((await runFilter({ field: "title", op: "ne", value: "Loft" })).map((i) => i.id),
    ["a", "b", "c"]);
  assert.deepEqual((await runFilter({ field: "title", op: "contains", value: "FLAT" })).map((i) => i.id),
    ["a", "c"], "contains is case-insensitive");
  assert.deepEqual((await runFilter({ field: "tags", op: "contains", value: "garden" })).map((i) => i.id),
    ["c"], "contains looks inside an array's values");
  assert.deepEqual((await runFilter({ field: "price", op: "gt", value: 100 })).map((i) => i.id), ["b", "c"],
    "gt compares numbers as numbers, so 250 is over 100 whatever its spelling");
  assert.deepEqual((await runFilter({ field: "price", op: "gte", value: 100 })).map((i) => i.id),
    ["a", "b", "c"]);
  assert.deepEqual((await runFilter({ field: "price", op: "lt", value: 250 })).map((i) => i.id), ["a", "d"]);
  assert.deepEqual((await runFilter({ field: "price", op: "lte", value: 100 })).map((i) => i.id), ["a", "d"]);
  assert.deepEqual((await runFilter({ field: "tags", op: "exists" })).map((i) => i.id), ["a", "b", "c"],
    "an empty array still exists, a missing field does not");
  assert.deepEqual((await runFilter({ field: "price", op: "gt", value: 1000 })), []);
});

test("filter with several conditions keeps only items that match every one", async () => {
  const kept = await runFilter({
    all: [
      { field: "title", op: "contains", value: "flat" },
      { field: "price", op: "lte", value: 100 },
    ],
  });
  assert.deepEqual(kept.map((i) => i.id), ["a"]);
});

test("filter walks a dotted field path", async () => {
  const items = [{ attributes: { rooms: 2 } }, { attributes: { rooms: 4 } }, {}];
  assert.deepEqual((await runFilter({ field: "attributes.rooms", op: "gte", value: 3 }, items)).length, 1);
  assert.deepEqual((await runFilter({ field: "attributes.rooms", op: "exists" }, items)).length, 2);
});

/* --------------------------------------------------------------------------- sort */

test("sort is numeric and stable", async () => {
  const items = [{ p: "20" }, { p: 3 }, { p: 100 }, { p: 3 }];
  const { ctx } = context({ field: "p", direction: "asc" });
  const asc = (await sortBlock.run(ctx, { items })).items;
  assert.deepEqual(asc.map((i) => i.p), [3, 3, "20", 100], "numbers sort as numbers, not as text");
  assert.equal(asc[0], items[1], "the first of two equal keys keeps its place");
  assert.equal(asc[1], items[3]);
  assert.equal(asc[2], items[0]);
  const desc = (await sortBlock.run(context({ field: "p", direction: "desc" }).ctx, { items })).items;
  assert.deepEqual(desc.map((i) => i.p), [100, "20", 3, 3]);
  assert.equal(desc[2], items[1], "descending is stable too");
  assert.equal(desc[3], items[3]);
});

test("sort puts an item with no value last in both directions", async () => {
  const items = [{ p: 2 }, {}, { p: 1 }];
  const asc = (await sortBlock.run(context({ field: "p", direction: "asc" }).ctx, { items })).items;
  assert.deepEqual(asc.map((i) => i.p), [1, 2, undefined]);
  const desc = (await sortBlock.run(context({ field: "p", direction: "desc" }).ctx, { items })).items;
  assert.deepEqual(desc.map((i) => i.p), [2, 1, undefined]);
});

/* -------------------------------------------------------------------- dedupe_seen */

test("dedupe_seen re-surfaces only on a listed field change", async () => {
  const first = context({ keyField: "id", refreshFields: ["title"] });
  const seeOnce = await dedupeSeenBlock.run(first.ctx, { items: [{ id: "a", title: "One", price: 1 }] });
  assert.deepEqual(seeOnce.items, [{ id: "a", title: "One", price: 1 }]);
  assert.equal(first.writes.length, 1, "one buffered state write");
  assert.equal(first.writes[0].key, "seen:b1", "the state key names the block");

  // Same key, same listed field, an UNLISTED field changed: dropped.
  const againContext = context({ keyField: "id", refreshFields: ["title"] }, { state: stateAfter(first.writes) });
  const again = await dedupeSeenBlock.run(againContext.ctx, { items: [{ id: "a", title: "One", price: 999 }] });
  assert.deepEqual(again.items, []);
  assert.equal(againContext.writes.length, 1, "nothing new is kept, and the buffered write is the only one");
  assert.equal(againContext.writes[0].value.a, first.writes[0].value.a, "the stored hash is unchanged");

  // The listed field changed: kept, marked.
  const changedContext = context({ keyField: "id", refreshFields: ["title"] }, { state: stateAfter(first.writes) });
  const resurfaced = await dedupeSeenBlock.run(changedContext.ctx, {
    items: [{ id: "a", title: "One, reduced", price: 1 }],
  });
  assert.deepEqual(resurfaced.items, [{ id: "a", title: "One, reduced", price: 1, _resurfaced: true }]);

  // A brand new key is kept unmarked.
  const newContext = context({ keyField: "id", refreshFields: ["title"] }, { state: stateAfter(first.writes) });
  const fresh = await dedupeSeenBlock.run(newContext.ctx, { items: [{ id: "z", title: "New" }] });
  assert.deepEqual(fresh.items, [{ id: "z", title: "New" }]);
  assert.deepEqual(Object.keys(newContext.writes[0].value).sort(), ["a", "z"]);
});

test("dedupe_seen without refresh fields drops every seen key", async () => {
  const first = context({ keyField: "id" });
  await dedupeSeenBlock.run(first.ctx, { items: [{ id: "a", title: "One" }] });
  const second = context({ keyField: "id" }, { state: stateAfter(first.writes) });
  const out = await dedupeSeenBlock.run(second.ctx, { items: [{ id: "a", title: "Two" }] });
  assert.deepEqual(out.items, []);
});

test("dedupe_seen keeps an item it cannot key, and caps its map", async () => {
  const { ctx, writes } = context({ keyField: "id" }, {
    state: { "seen:b1": Object.fromEntries(Array.from({ length: 5001 }, (_, i) => ["k" + i, "h" + i])) },
  });
  const out = await dedupeSeenBlock.run(ctx, { items: [{ title: "no key" }, { id: "fresh" }] });
  assert.deepEqual(out.items, [{ title: "no key" }, { id: "fresh" }]);
  const stored = writes[0].value;
  assert.equal(Object.keys(stored).length, 5000, "the map is capped");
  assert.equal(Object.hasOwn(stored, "k0"), false, "the oldest key was dropped");
  assert.equal(Object.hasOwn(stored, "k5000"), true, "the newest seeded key stayed");
  assert.equal(Object.hasOwn(stored, "fresh"), true, "and the new key was recorded");
});

/* --------------------------------------------------------------------- diff_last */

test("diff_last marks new, changed, same and gone", async () => {
  const first = context({ keyField: "id" });
  const one = await diffLastBlock.run(first.ctx, {
    items: [{ id: "a", title: "One" }, { id: "b", title: "Two" }],
  });
  assert.deepEqual(one.items.map((i) => [i.id, i._diff]), [["a", "new"], ["b", "new"]]);
  assert.equal(first.writes[0].key, "last:b1");

  const second = context({ keyField: "id" }, { state: stateAfter(first.writes) });
  const two = await diffLastBlock.run(second.ctx, {
    items: [
      { id: "a", title: "One" },
      { id: "b", title: "Two, reduced" },
      { id: "c", title: "Three" },
    ],
  });
  assert.deepEqual(two.items.map((i) => [i.id, i._diff]), [
    ["a", "same"], ["b", "changed"], ["c", "new"],
  ]);
  assert.deepEqual(Object.keys(second.writes[0].value).sort(), ["a", "b", "c"],
    "the stored map is this run's items");
  // `b` stays present, so nothing is gone yet. Now drop `a` and `c`: they are appended, key only.
  const third = context({ keyField: "id" }, { state: stateAfter(second.writes) });
  const out = (await diffLastBlock.run(third.ctx, {
    items: [{ id: "b", title: "Two, reduced" }],
  })).items;
  assert.deepEqual(out.map((i) => [i.id, i._diff]), [
    ["b", "same"], ["a", "gone"], ["c", "gone"],
  ]);
  assert.deepEqual(out[1], { id: "a", _diff: "gone" });
  assert.deepEqual(Object.keys(third.writes[0].value).sort(), ["b"],
    "the stored map is this run's items only");
});

test("diff_last appends a gone line that carries only the key", async () => {
  const first = context({ keyField: "id" });
  await diffLastBlock.run(first.ctx, { items: [{ id: "a", title: "One" }, { id: "b", title: "Two" }] });
  const second = context({ keyField: "id" }, { state: stateAfter(first.writes) });
  const out = (await diffLastBlock.run(second.ctx, { items: [{ id: "b", title: "Two" }] })).items;
  assert.deepEqual(out, [{ id: "b", title: "Two", _diff: "same" }, { id: "a", _diff: "gone" }]);
  assert.equal(Object.hasOwn(out[1], "title"), false, "a gone line carries no stale text");
});

/* ---------------------------------------------------------------- enrich_lookup */

test("enrich_lookup joins fields from an earlier source block's items", async () => {
  const sources = new Map([["feed", [
    { external_id: "a", score: 10, region: "north" },
    { external_id: "b", score: 20, region: "south" },
  ]]]);
  const { ctx } = context(
    { source: "feed", joinField: "id", lookupKey: "external_id", fields: ["score"], prefix: "feed_" },
    { sources },
  );
  const out = (await enrichLookupBlock.run(ctx, {
    items: [{ id: "a" }, { id: "b" }, { id: "zzz" }],
  })).items;
  assert.deepEqual(out, [{ id: "a", feed_score: 10 }, { id: "b", feed_score: 20 }, { id: "zzz" }],
    "an item with no match comes through untouched");
});

test("enrich_lookup refuses a source block that did not run", async () => {
  const { ctx } = context({ source: "feed", joinField: "id", lookupKey: "id", fields: ["score"] });
  await assert.rejects(
    () => enrichLookupBlock.run(ctx, { items: [{ id: "a" }] }),
    (err) => err && err.code === "source_not_found",
  );
});

/* ----------------------------------------------------------------- the validators */

test("each shape block rejects settings it cannot run", () => {
  const cases = [
    [filterBlock, { op: "eq", value: 1 }, ["field"]],
    [filterBlock, { field: "x", op: "matches", value: 1 }, ["op"]],
    [filterBlock, { field: "x", op: "eq" }, ["value"]],
    [filterBlock, { field: "x", op: "exists" }, []],
    [filterBlock, { all: [] }, ["all"]],
    [filterBlock, { all: [{ field: "", op: "nope" }] }, ["all[0].field", "all[0].op"]],
    [filterBlock, "nope", ["settings"]],
    [sortBlock, { field: "x" }, ["direction"]],
    [sortBlock, { direction: "asc" }, ["field"]],
    [sortBlock, { field: "x", direction: "up" }, ["direction"]],
    [dedupeSeenBlock, {}, ["keyField"]],
    [dedupeSeenBlock, { keyField: "id", refreshFields: "title" }, ["refreshFields"]],
    [dedupeSeenBlock, { keyField: "id", refreshFields: [""] }, ["refreshFields"]],
    [diffLastBlock, { keyField: 7 }, ["keyField"]],
    [enrichLookupBlock, {}, ["source", "joinField", "lookupKey", "fields"]],
    [enrichLookupBlock, { source: "s", joinField: "a", lookupKey: "b", fields: [] }, ["fields"]],
    [enrichLookupBlock, { source: "s", joinField: "a", lookupKey: "b", fields: ["c"], prefix: 1 }, ["prefix"]],
    [enrichLookupBlock, { source: "s", joinField: "a", lookupKey: "b", fields: ["c"] }, []],
  ];
  for (const [block, settings, expected] of cases) {
    assert.deepEqual(block.validate(settings), expected, `${block.type} ${JSON.stringify(settings)}`);
  }
});

/* -------------------------------------------------------------------- the registry */

test("the registry marks sources, custom and model blocks source-bearing and shapes free", () => {
  for (const type of ["http_json", "rss", "mail_alerts", "workspace_file", "custom", "enrich_lookup",
    "ai_commentary", "annotate"]) {
    assert.equal(BLOCKS[type].sourceBearing, true, type);
    assert.equal(blockRegistry[type].sourceBearing, true, type);
  }
  for (const type of ["filter", "sort", "dedupe_seen", "diff_last", "table", "cards", "chart", "map",
    "text"]) {
    assert.equal(BLOCKS[type].sourceBearing, false, type);
    assert.equal(blockRegistry[type].sourceBearing, false, type);
  }
  assert.equal(BLOCKS.custom.kind, "custom");
  assert.equal(BLOCKS.http_json.kind, "source");
  assert.equal(BLOCKS.filter.kind, "shape");
  assert.equal(BLOCKS.table.kind, "present");
  for (const type of ["http_json", "rss", "mail_alerts", "workspace_file"]) {
    assert.equal(typeof BLOCKS[type].run, "function", type);
  }
  assert.ok(Object.isFrozen(BLOCKS) && Object.isFrozen(blockRegistry));
});

test("validateRecipe names the block and the field", () => {
  assert.deepEqual(validateRecipe({ blocks: [] }), []);
  assert.deepEqual(validateRecipe({ blocks: [{ id: "b1", type: "filter", settings: { field: "x", op: "eq", value: 1 } }] }), []);
  assert.deepEqual(validateRecipe({ blocks: [{ id: "b1", type: "nope", settings: {} }] }),
    ["blocks[0].type_unknown"]);
  assert.deepEqual(validateRecipe({ blocks: [{ type: "filter", settings: { field: "x", op: "exists" } }] }),
    ["blocks[0].id"]);
  assert.deepEqual(validateRecipe({ blocks: [
    { id: "b1", type: "filter", settings: { field: "x", op: "exists" } },
    { id: "b1", type: "sort", settings: { field: "x", direction: "asc" } },
  ] }), ["blocks[1].id_duplicate"]);
  assert.deepEqual(validateRecipe({ blocks: [{ id: "B1", type: "filter", settings: { field: "x", op: "exists" } }] }),
    ["blocks[0].id"], "an id is lower case and starts with a letter");
  assert.deepEqual(validateRecipe({ blocks: [{ id: "b1", type: "filter" }] }), ["blocks[0].settings"]);
  assert.deepEqual(validateRecipe({ blocks: [{ id: "b1", type: "filter", settings: { field: "x" } }] }),
    ["blocks[0].op"]);
});