/**
 * A remote-exposure card's button words come from CODE, by the button's action
 * id, for EVERY row of that source — the red (pre-fix) tests.
 *
 * The card grants one peer access to one capability, for a duration the operator
 * picks. Its three buttons ("Allow for 30 days" / "… 7 days" / "Allow until I
 * remove it") are the only thing that tells the operator WHAT the click will do,
 * so the words must be the code's, keyed by the action id the click posts — never
 * `fix_it_items.remedies[i].label`, which is a crow.db column the add-ons sharing
 * the database can write.
 *
 * Before the fix the code label was applied only when the row carried a usable
 * `context.card` (fix-it/card-copy.js `renderStoredCard`); every other row of
 * this source rendered its stored label. So a legacy row (written before
 * `context.card` existed) or a forged row could put any words over a button that
 * grants a peer access. These tests pin:
 *
 *   1. a forged row — with no `context.card`, and with a valid one — renders the
 *      code's label for the action id it actually posts (EN and ES);
 *   2. a legacy row (no `context.card`) with genuine action ids renders the code
 *      labels, not the arbitrary stored ones (EN and ES);
 *   3. an action id this card does not own — an invented `…-999d`, and the
 *      pre-N1b legacy `expose-capability` id — renders no button at all, and a
 *      stored `kind: "link"` remedy over an Allow action is not rendered as a
 *      link either (its stored href is never read);
 *   4. a genuine card (peer-card-policy.js `cardRemedies()`) renders exactly the
 *      three code labels, in order; and every OTHER source keeps its existing
 *      label rule — the stored label when the row has no `context.card`, the
 *      code label when it has one.
 *
 * Every row is seeded into a scratch crow.db (init-db + createDbClient, exactly
 * like tests/fix-it-card-render.test.js) and read back through
 * `fixItCardModels(db, { lang })` — the ONE card model both renderers (the Nest's
 * Fix-it section and the Attention sheet) turn into buttons.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO = join(import.meta.dirname, "..");

// ── the scratch instance, set BEFORE any gateway module is imported ──────────
const scratch = mkdtempSync(join(tmpdir(), "fixit-remote-labels-"));
process.env.CROW_DATA_DIR = scratch;
process.env.CROW_HOME = join(scratch, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(scratch, "tasks.db");

let db, idx, store, policy;

/** The source the remote-exposure detector writes its cards under. */
const SOURCE = "remote-exposure";

/** The three labels the code holds for this card, in button order. */
const CODE_LABELS = {
  en: ["Allow for 30 days", "Allow for 7 days", "Allow until I remove it"],
  es: ["Permitir durante 30 días", "Permitir durante 7 días", "Permitir hasta que yo lo quite"],
};
/** The same three buttons' action ids, in the order the card offers them. */
const ACTION_IDS = ["expose-capability-30d", "expose-capability-7d", "expose-capability-forever"];

before(async () => {
  mkdirSync(process.env.CROW_HOME, { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env }, stdio: "pipe", cwd: REPO,
  });
  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient();
  idx = await import("../servers/gateway/fix-it/index.js");
  store = await import("../servers/shared/fix-it/store.js");
  policy = await import("../servers/gateway/fix-it/peer-card-policy.js");
  assert.equal(typeof idx.fixItCardModels, "function", "fix-it/index.js must export fixItCardModels(db, { lang })");
  idx.wireFixIt();
});

after(() => {
  try { db?.close(); } catch { /* already closed */ }
  try { rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ }
});

/** Every row in this file is written straight into crow.db — no detector needed. */
async function clearCards() {
  await db.execute({ sql: "DELETE FROM fix_it_items", args: [] });
}

/** Store one card row and answer its id. */
async function seedRow({ source = SOURCE, dedupKey, title = "Stored title", why = "Stored body", remedies, context = null }) {
  const { id } = await store.upsertItem(db, {
    source, dedupKey, title, why, severity: "warn", remedies, context,
  });
  return id;
}

/** One row's model in `lang`. */
async function modelFor(id, lang) {
  const models = await idx.fixItCardModels(db, { lang });
  const model = models.find((m) => m.id === id);
  assert.ok(model, `${lang}: fixItCardModels returned no model for item ${id}`);
  return model;
}

const labelsOf = (model) => model.remedies.map((r) => r.label);

/** The `context.card` a genuine remote-exposure card carries. */
const remoteCard = (peer, capability) => ({
  capability,
  requestingInstance: peer,
  card: { code: SOURCE, values: { peer: "Glasses", capability, requestingInstance: peer } },
});

// ─────────────────────────────────────────────────────────────────────────────
// 1. A forged row: the label follows the action id it posts
// ─────────────────────────────────────────────────────────────────────────────
test("a forged row's label never renders — the button says what the code says for its action id", async () => {
  await clearCards();
  // "Allow for 7 days" over the button that posts the FOREVER action: the stored
  // label is a lie about the grant; the code's words for that id are the truth.
  const forged = [{
    label: "Allow for 7 days",
    actionId: "expose-capability-forever",
    kind: "instant",
    args: { capability: "funkwhale", requestingInstance: "peer-forged", days: 7 },
  }];

  const bare = await seedRow({ dedupKey: "forged/no-card", remedies: forged });
  const withCard = await seedRow({
    dedupKey: "forged/with-card",
    remedies: forged,
    context: remoteCard("peer-forged", "funkwhale"),
  });

  for (const [what, id] of [["no context.card", bare], ["a valid context.card", withCard]]) {
    for (const lang of ["en", "es"]) {
      const model = await modelFor(id, lang);
      assert.deepEqual(labelsOf(model), [CODE_LABELS[lang][2]],
        `${lang}: ${what}: the forever button's words come from code`);
      assert.equal(model.remedies[0].actionId, "expose-capability-forever",
        `${lang}: ${what}: the button still posts the action it names`);
      assert.equal(JSON.stringify(model.remedies).includes("Allow for 7 days"), false,
        `${lang}: ${what}: the stored label never reaches the button`);
    }
  }

  // Both renderers turn the ONE model into markup, so the page carries the
  // code's words too — and never the forged ones.
  const es = await idx.renderFixItCards(db, { lang: "es" });
  assert.ok(es.includes("Permitir hasta que yo lo quite"), "the Nest's card shows the code's ES label");
  assert.equal(es.split("Permitir durante 7 días").length - 1, 0,
    "no button says 7 days for an action that grants forever");
  const en = await idx.renderFixItCards(db, { lang: "en" });
  assert.equal(en.split("Allow for 7 days").length - 1, 0, "no button anywhere says \"Allow for 7 days\" for the forever action");
  await clearCards();
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. A legacy row (no context.card) with genuine action ids
// ─────────────────────────────────────────────────────────────────────────────
test("a legacy row with no context.card renders the code labels for genuine action ids (EN and ES)", async () => {
  await clearCards();
  const stored = "Stored words a crow.db writer chose";
  const id = await seedRow({
    dedupKey: "legacy/genuine",
    remedies: ACTION_IDS.map((actionId) => ({ label: stored, actionId, kind: "instant", args: {} })),
  });

  for (const lang of ["en", "es"]) {
    const model = await modelFor(id, lang);
    assert.deepEqual(labelsOf(model), CODE_LABELS[lang],
      `${lang}: a legacy row's three genuine buttons carry the code's labels, in order`);
    assert.equal(JSON.stringify(model.remedies).includes(stored), false,
      `${lang}: the stored label is not rendered`);
  }
  await clearCards();
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. An action id this card does not own renders nothing
// ─────────────────────────────────────────────────────────────────────────────
test("an action id the remote-exposure card does not own renders no button at all", async () => {
  await clearCards();
  const id = await seedRow({
    dedupKey: "unknown/action-ids",
    remedies: [
      { label: "Allow for 999 days", actionId: "expose-capability-999d", kind: "instant", args: {} },
      // The pre-N1b card's one Allow button (all peers, no expiry): no code words.
      { label: "Allow", actionId: "expose-capability", kind: "instant", args: {} },
      // A stored link over an Allow action: still not a link (the href is crow.db data).
      { kind: "link", label: "Allow until I remove it", actionId: "expose-capability-forever", href: "https://evil.example/allow" },
    ],
  });

  for (const lang of ["en", "es"]) {
    const model = await modelFor(id, lang);
    assert.deepEqual(model.remedies, [],
      `${lang}: none of the three unowned remedies is offered`);
  }
  const html = await idx.renderFixItCards(db, { lang: "en" });
  assert.equal(html.includes("evil.example"), false, "a stored href never reaches the page");
  assert.equal(html.includes("Allow for 999 days"), false, "a stored label with no code words never reaches the page");
  await clearCards();
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. A genuine card, and every other source's unchanged label rule
// ─────────────────────────────────────────────────────────────────────────────
test("a genuine card renders exactly the three code labels in order", async () => {
  await clearCards();
  const id = await seedRow({
    dedupKey: "genuine/card",
    remedies: policy.cardRemedies("funkwhale", "peer-glasses"),
    context: remoteCard("peer-glasses", "funkwhale"),
  });

  for (const lang of ["en", "es"]) {
    const model = await modelFor(id, lang);
    assert.deepEqual(labelsOf(model), CODE_LABELS[lang], `${lang}: the three labels, in order`);
    assert.deepEqual(model.remedies.map((r) => [r.kind, r.actionId]),
      ACTION_IDS.map((actionId) => ["form", actionId]), `${lang}: the three actions, in order`);
  }
  await clearCards();
});

test("every other source keeps its label rule: stored without context.card, code with one", async () => {
  await clearCards();
  const OTHER = "data-backend-reapproval";
  const stored = "Stored words for the Projects button";
  const remedy = [{ label: stored, actionId: "open-projects-page", kind: "link" }];

  const bare = await seedRow({ source: OTHER, dedupKey: "other/no-card", remedies: remedy });
  const withCard = await seedRow({
    source: OTHER,
    dedupKey: "other/with-card",
    remedies: remedy,
    context: { card: { code: OTHER, values: { n: 3 } } },
  });

  for (const lang of ["en", "es"]) {
    // Unchanged: a row written before `context.card` keeps its stored label in
    // every language, and its destination is still the code-held one.
    const legacy = await modelFor(bare, lang);
    assert.deepEqual(labelsOf(legacy), [stored], `${lang}: another source's legacy row keeps its stored label`);
    assert.deepEqual(legacy.remedies.map((r) => [r.kind, r.href]),
      [["link", idx.LINK_REMEDIES["open-projects-page"]]], `${lang}: …and its code-held href`);

    // Unchanged: with a usable context.card the code label wins.
    const copy = await modelFor(withCard, lang);
    assert.deepEqual(labelsOf(copy), [lang === "es" ? "Abrir la página de Proyectos" : "Open the Projects page"],
      `${lang}: another source's code label still wins when the row carries context.card`);
  }
  await clearCards();
});
// ─────────────────────────────────────────────────────────────────────────────
// 5. A stored LINK over an Allow action is neither a link nor a button
// ─────────────────────────────────────────────────────────────────────────────
test("a stored link over an Allow action renders no link and no Allow button", async () => {
  await clearCards();
  // A crow.db writer's best shot: the code OWNS this action id (so the row is
  // not filtered out for an unknown id), it asks for the most generous duration,
  // and it carries a well-formed absolute href. The action id is still not a
  // destination this file holds, so the link has no target — and a link is
  // navigation only, so rendering it as one would fire no remedy at all.
  const href = "https://evil.example/allow-capability";
  const id = await seedRow({
    dedupKey: "link/over-allow",
    remedies: [{
      kind: "link",
      label: "Allow for 30 days",
      actionId: "expose-capability-30d",
      href,
    }],
  });

  for (const lang of ["en", "es"]) {
    const model = await modelFor(id, lang);
    assert.deepEqual(model.remedies, [],
      `${lang}: a link entry over an Allow action is not offered at all`);
  }

  const html = await idx.renderFixItCards(db, { lang: "en" });
  assert.equal(html.includes("evil.example"), false, "the stored href never reaches the page");
  assert.equal(html.includes(`href="${href}"`), false, "…not as this link either");
  assert.equal(html.includes("data-fixit-link"), false, "no link is rendered for this card");
  assert.equal(html.includes('value="expose-capability-30d"'), false,
    "nor is it turned into a form that posts the Allow action");
  for (const label of CODE_LABELS.en) {
    assert.equal(html.includes(label), false,
      `no button says "${label}" — the card grants nothing here`);
  }
  await clearCards();
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. A gated ("confirm") Allow action still says the code's words
// ─────────────────────────────────────────────────────────────────────────────
test("a gated remedy on the forever action renders the code's forever label (EN), never the stored one", async () => {
  await clearCards();
  const stored = "Allow permanently, right now";
  const id = await seedRow({
    dedupKey: "gated/forever",
    remedies: [{
      kind: "confirm",
      label: stored,
      actionId: "expose-capability-forever",
      args: { capability: "funkwhale", requestingInstance: "peer-gated" },
    }],
  });

  const model = await modelFor(id, "en");
  assert.equal(model.remedies.length, 1, "the gated Allow action is still offered");
  const [remedy] = model.remedies;
  assert.equal(remedy.label, CODE_LABELS.en[2], "the button's words are the code's forever label");
  assert.equal(remedy.kind, "gated", "it stays gated — the code label does not make it one-tap");
  assert.equal(remedy.gatedKind, "confirm", "…and the stored kind is what gates it");
  assert.equal(remedy.actionId, "expose-capability-forever", "it still posts the action it names");
  assert.equal(JSON.stringify(model.remedies).includes(stored), false,
    "the stored label never reaches the button");

  const html = await idx.renderFixItCards(db, { lang: "en" });
  assert.equal(html.includes(CODE_LABELS.en[2]), true, "the page shows the code's forever label");
  assert.equal(html.includes(stored), false, "…and never the stored one");
  assert.equal(html.includes('value="expose-capability-forever"'), true, "the button posts the forever action");
  await clearCards();
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Two rows' worth of the same action id — both buttons say the code's words
// ─────────────────────────────────────────────────────────────────────────────
test("every button for the same action id carries the code label, whatever each stored label says", async () => {
  await clearCards();
  const storedA = "Grant it for a whole year";
  const storedB = "Grant it permanently and forget about it";
  const id = await seedRow({
    dedupKey: "duplicate/seven-days",
    remedies: [
      { kind: "instant", label: storedA, actionId: "expose-capability-7d", args: {} },
      { kind: "instant", label: storedB, actionId: "expose-capability-7d", args: {} },
    ],
  });

  const model = await modelFor(id, "en");
  assert.equal(model.remedies.length, 2, "both stored entries render a button");
  for (const remedy of model.remedies) {
    assert.equal(remedy.actionId, "expose-capability-7d", "each posts the 7-day action");
    assert.equal(remedy.label, CODE_LABELS.en[1], "each says the code's 7-day words");
  }
  assert.equal(JSON.stringify(model.remedies).includes(storedA), false, "no stored label reaches a button");
  assert.equal(JSON.stringify(model.remedies).includes(storedB), false, "…for either entry");

  const html = await idx.renderFixItCards(db, { lang: "en" });
  assert.equal(html.split(CODE_LABELS.en[1]).length - 1, 2,
    "every rendered button for this action id carries the code's 7-day label");
  assert.equal(html.includes(storedA), false, "the first stored label never reaches the page");
  assert.equal(html.includes(storedB), false, "the second stored label never reaches the page");
  await clearCards();
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. Action ids that are prototype keys render nothing
// ─────────────────────────────────────────────────────────────────────────────
test("action ids that name Object.prototype members render no button at all", async () => {
  await clearCards();
  const ODD_IDS = ["__proto__", "constructor", "toString"];
  const id = await seedRow({
    dedupKey: "odd/action-ids",
    remedies: ODD_IDS.map((actionId) => ({
      kind: "instant",
      label: `Allow through ${actionId}`,
      actionId,
      args: {},
    })),
  });

  for (const lang of ["en", "es"]) {
    const model = await modelFor(id, lang);
    assert.deepEqual(model.remedies, [],
      `${lang}: "constructor", "toString" and "__proto__" are not action ids this card owns`);
  }

  const html = await idx.renderFixItCards(db, { lang: "en" });
  for (const actionId of ODD_IDS) {
    assert.equal(html.includes(`value="${actionId}"`), false,
      `no button posts ${actionId}`);
    assert.equal(html.includes(`Allow through ${actionId}`), false,
      `the stored label beside ${actionId} never reaches the page`);
  }
  await clearCards();
});
