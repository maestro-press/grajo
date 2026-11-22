/**
 * The Attention sheet's Fix-it cards (guard test).
 *
 * One pending card per source the gateway can raise is seeded through
 * store.upsertItem with the remedies/context the real detectors store (see
 * tests/helpers/fix-it-seed.js), then the sheet fragment
 * (GET /dashboard/attention/fragment) is rendered and every card is checked
 * against what the row/code says it should show.
 *
 * The first test is a DRIFT GUARD: the seeded sources must cover every detector
 * source the gateway registers (the boot checks, the two event detectors and the
 * bundle-bind-drift family), so a new detector cannot ship without a card being
 * rendered here.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { escapeHtml } from "../servers/gateway/dashboard/shared/components.js";

const REPO = join(import.meta.dirname, "..");
const dir = mkdtempSync(join(tmpdir(), "fixit-attention-cards-"));
process.env.CROW_DATA_DIR = dir;
mkdirSync(join(dir, "home"), { recursive: true });
process.env.CROW_HOME = join(dir, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");

const esc = (value) => escapeHtml(String(value ?? ""));

let db, idx, registry, seed, store;
let seeded, models, rowsById, fragment;
let server, base;

/** The generated part of one card only (the wrapper div opens its own region). */
function cardRegion(html, id) {
  const start = html.indexOf(`data-fixit-item="${id}"`);
  assert.ok(start >= 0, `the sheet must render a card for item ${id} (data-fixit-item)`);
  const next = html.indexOf('data-fixit-item="', start + 1);
  return html.slice(start, next === -1 ? undefined : next);
}

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env }, stdio: "pipe", cwd: REPO,
  });

  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient();
  idx = await import("../servers/gateway/fix-it/index.js");
  registry = await import("../servers/shared/fix-it/registry.js");
  store = await import("../servers/shared/fix-it/store.js");
  seed = await import("./helpers/fix-it-seed.js");

  assert.equal(typeof idx.fixItCardModels, "function",
    "servers/gateway/fix-it/index.js must export fixItCardModels(db, { lang, req }) — the one card model both renderers use");
  assert.equal(typeof idx.renderFixItSheetCards, "function",
    "servers/gateway/fix-it/index.js must export renderFixItSheetCards(db, { lang, req })");

  idx.wireFixIt();
  seeded = await seed.seedFixItCards(db);

  rowsById = new Map();
  for (const card of seeded.cards) rowsById.set(card.id, await store.getItem(db, card.id));

  const { default: express } = await import("express");
  const { healthAttentionRouter } = await import("../servers/gateway/dashboard/panels/health.js");
  const app = express();
  // The fragment route must accept injected signals the way notificationsRouter
  // does, so the health half of the sheet is fixed in a test (the fix-it half is
  // what this file is about; the injection only keeps it deterministic).
  app.use(healthAttentionRouter({
    createDbClient,
    collectSignals: async () => ({ ok: true, issues: [], details: [], links: [] }),
  }));
  await new Promise((resolve) => { server = app.listen(0, "127.0.0.1", resolve); });
  base = "http://127.0.0.1:" + server.address().port;

  const res = await fetch(base + "/dashboard/attention/fragment");
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("cache-control"), "no-store");
  fragment = await res.text();

  models = await idx.fixItCardModels(db, { lang: "en" });
});

after(() => {
  if (server) server.close();
  try { db.close(); } catch {}
  try { rmSync(dir, { recursive: true, force: true }); } catch {}
});

test("the seed covers every detector source the gateway registers", async () => {
  const expected = seed.expectedCardSources();
  const covered = new Set(seeded.cards.map((card) => card.source));
  for (const source of expected) {
    assert.ok(covered.has(source),
      `tests/helpers/fix-it-seed.js seeds no card for the detector source "${source}" — a new detector (or a new card source) must get a pending card in the seed, so the attention sheet's rendering of it is checked`);
  }
  const extra = [...covered].filter((source) => !expected.has(source));
  assert.deepEqual(extra, [], "the seed covers sources no detector raises");
});

test("one sheet card per pending card, each with its own item id", () => {
  assert.equal(models.length, seeded.cards.length,
    "fixItCardModels must return one model per pending fix_it_items row");
  const badges = (fragment.match(/data-fixit-item="/g) || []).length;
  assert.equal(badges, models.length, "the sheet must render one card per pending card");
  for (const card of seeded.cards) {
    assert.ok(models.some((m) => m.id === card.id),
      `the model list is missing the card for "${card.key}" (item ${card.id})`);
  }
});

test("every card shows its title, why, remedies and a dismiss form", () => {
  const modelById = new Map(models.map((m) => [m.id, m]));
  for (const card of seeded.cards) {
    const row = rowsById.get(card.id);
    const model = modelById.get(card.id);
    const region = cardRegion(fragment, card.id);
    const where = `card "${card.key}" (${card.source}, item ${card.id})`;

    // The expected title/why: from the row for a stored card, from the model for
    // the three code-held sources (their row is never rendered).
    const codeHeld = seed.CODE_HELD_SOURCES.includes(card.source);
    const title = codeHeld ? model.title : row.title;
    const why = codeHeld ? model.why : row.why;
    assert.ok(region.includes(esc(title)), `${where}: title "${title}" is not in the card`);
    if (why) assert.ok(region.includes(esc(why)), `${where}: why text is not in the card`);

    // One dismiss form: action=dismiss + item_id + return=sheet + _csrf.
    assert.ok(region.includes('name="action" value="dismiss"'), `${where}: no dismiss action field`);
    assert.ok(region.includes(`name="item_id" value="${card.id}"`), `${where}: no item_id field`);
    assert.ok(region.includes('name="return" value="sheet"'), `${where}: no return=sheet field`);
    assert.ok(region.includes('name="_csrf"'), `${where}: no _csrf field`);
    assert.ok(region.includes("Not now"), `${where}: the dismiss button does not say "Not now"`);
    assert.ok(region.includes('action="/dashboard/fix-it/action"'), `${where}: nothing posts to /dashboard/fix-it/action`);

    for (const remedy of model.remedies) {
      assert.ok(region.includes(esc(remedy.label)), `${where}: remedy label "${remedy.label}" is not rendered`);
      if (remedy.kind === "link") {
        const href = remedy.href || idx.linkRemedyTarget(remedy);
        assert.ok(href, `${where}: the link remedy "${remedy.label}" has no code-held target (linkRemedyTarget)`);
        assert.ok(region.includes(`href="${esc(href)}"`), `${where}: the link remedy "${remedy.label}" does not link to ${href}`);
        continue;
      }
      if (remedy.kind === "gated" || remedy.kind === "confirm") {
        assert.match(region, /<button[^>]*disabled/, `${where}: the gated remedy "${remedy.label}" must render disabled`);
        continue;
      }
      // An instant remedy: a form carrying its own action_id, registered.
      assert.ok(remedy.actionId, `${where}: the form remedy "${remedy.label}" has no actionId`);
      assert.equal(typeof registry.getRemedy(remedy.actionId), "function",
        `${where}: the action_id "${remedy.actionId}" is not registered after wireFixIt()`);
      assert.ok(region.includes(`name="action_id" value="${esc(remedy.actionId)}"`),
        `${where}: no action_id field for "${remedy.actionId}"`);
    }
  }
});

test("the count badge, the technical details and the gated button", () => {
  const bootGuard = cardRegion(fragment, seeded.ids["boot-guard"]);
  assert.ok(bootGuard.includes("×2"), "a card seen twice shows the ×2 badge");

  const peer = cardRegion(fragment, seeded.ids["remote-exposure"]);
  assert.match(peer, /<details/, "a card with context rows carries a Technical details block");
  assert.equal(/<details[^>]*\bopen\b/.test(peer), false, "Technical details start collapsed");
  assert.ok(peer.includes("Technical details"), "the details summary says Technical details");
  assert.ok(peer.includes("Capability:"), "the details block labels the capability row");
  assert.ok(peer.includes("funkwhale"), "the details block carries the capability");
  assert.ok(peer.includes("Requesting instance:"), "the details block labels the requesting instance");

  const caddy = cardRegion(fragment, seeded.ids["caddy-proxy-socket"]);
  assert.ok(caddy.includes("Caddyfile:"), "the Caddy card's details name the Caddyfile");

  const gated = cardRegion(fragment, seeded.ids["gated-confirm"]);
  assert.match(gated, /<button[^>]*disabled/, "the confirm remedy renders disabled");
  assert.match(gated, /Coming soon/, "the disabled remedy says why (Coming soon)");
});

test("stored titles, whys and context values are escaped", () => {
  const region = cardRegion(fragment, seeded.ids["xss"]);
  assert.ok(region.includes("&lt;script&gt;"), "the stored title/why is escaped, not dropped");
  assert.equal(region.includes("<script"), false, "no stored markup reaches the sheet as markup");
  assert.equal(fragment.includes("<script"), false, "the whole fragment carries no script tag");
});

test("an empty table renders no cards at all", async () => {
  const other = mkdtempSync(join(tmpdir(), "fixit-attention-cards-empty-"));
  try {
    execFileSync(process.execPath, ["scripts/init-db.js"], {
      env: { ...process.env, CROW_DATA_DIR: other }, stdio: "pipe", cwd: REPO,
    });
    const { createDbClient } = await import("../servers/db.js");
    const emptyDb = createDbClient(join(other, "crow.db"));
    try {
      assert.equal(await idx.renderFixItSheetCards(emptyDb, { lang: "en" }), "",
        "renderFixItSheetCards is the empty string when nothing is pending");
      assert.equal(await idx.renderFixItCards(emptyDb, { lang: "en" }), "",
        "the Nest renderer is the empty string when nothing is pending");
    } finally {
      emptyDb.close();
    }
  } finally {
    try { rmSync(other, { recursive: true, force: true }); } catch {}
  }
});