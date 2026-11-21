// The Sharing Fix-it card (bot-door plan, section 5): an enabled bot whose definition selects
// `crow-sharing` but which has no allow-list entry, and the one-click undo that takes messaging away.
//
// Harness: a real init-db'd scratch crow.db, the real Fix-it store, the real detector and remedy, and a
// scratch CROW_HOME for the allow-list file. The remedy's owner gate is stubbed (the real one needs a
// password session in crow.db) exactly as tests/fix-it-* do.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { rmScratch } from "./helpers/safe-rm.js";

const root = mkdtempSync(join(tmpdir(), "fix-it-sharing-bot-"));
process.env.CROW_DATA_DIR = join(root, "home");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const DB_FILE = join(root, "home", "crow.db");
// The allow-list's own directory, held in a CONSTANT: a cleanup must never re-read process.env to
// decide what to delete (tests/test-cleanup-hygiene.test.js).
const SECRETS_DIR = join(root, "home", "secrets");

const { createDbClient } = await import("../servers/db.js");
const fixitStore = await import("../servers/shared/fix-it/store.js");
const acl = await import("../servers/gateway/sharing-bot/acl.js");
const detector = await import("../servers/gateway/fix-it/detectors/sharing-bot-acl.js");
const remedy = await import("../servers/gateway/fix-it/remedies/remove-bot-sharing.js");
const idx = await import("../servers/gateway/fix-it/index.js");
const { t, fill } = await import("../servers/gateway/dashboard/shared/i18n.js");

const PUBKEY = "02" + "a".repeat(64);
let db;

after(() => {
  if (db) { try { db.close(); } catch { /* already closed */ } }
  rmScratch(root);
});

before(() => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "home") },
    stdio: "pipe",
    cwd: REPO,
  });
  db = createDbClient(DB_FILE);
});

beforeEach(async () => {
  await db.execute("DELETE FROM pi_bot_defs");
  await db.execute("DELETE FROM fix_it_items");
  rmScratch(SECRETS_DIR);
  remedy._setOwnerCheckForTest(async () => true);
});

/** The store shape the boot pass hands a detector: the db-bound upsert + resolve. */
const store = {
  get db() { return db; },
  upsertItem: (item) => fixitStore.upsertItem(db, item),
  resolveByKey: (source, key) => fixitStore.resolveByKey(db, source, key),
  listBySource: (source) => fixitStore.listBySource(db, source),
  markResolved: (id) => fixitStore.markResolved(db, id),
};

async function seedBot(botId, { name = "Hank", def = {}, enabled = 1 } = {}) {
  await db.execute({
    sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES (?, ?, ?, ?)",
    args: [botId, name, JSON.stringify(def), enabled],
  });
}

const sharingDef = (...entries) => ({ tools: { crow_mcp: ["crow-memory/crow_remember", ...entries] } });

async function pending() {
  return fixitStore.listPending(db);
}

/* ------------------------------------------------------------------- the card */

test("a new card names the bot, links to its Bot Builder page and offers the undo; every spelling of the server counts", async () => {
  await seedBot("hank", { def: sharingDef("crow-sharing/crow_send_message", "crow-sharing__crow_send_group_message") });
  const out = await detector.default.check(store, { crowHome: process.env.CROW_HOME });
  assert.deepEqual(out.cards, ["hank"]);

  const items = await pending();
  assert.equal(items.length, 1);
  const item = items[0];
  assert.equal(item.source, detector.SOURCE);
  assert.equal(item.title, fill(t("botbuilder.sharing.fixitTitle", "en"), { bot: "Hank" }));
  assert.equal(item.why, t("botbuilder.sharing.intro", "en"));
  const link = item.remedies.find((r) => r.actionId === detector.OPEN_BOT_BUILDER_ACTION);
  assert.equal(link.kind, "link");
  assert.equal(link.args.bot, "hank");
  const undo = item.remedies.find((r) => r.actionId === remedy.ACTION_ID);
  assert.equal(undo.kind, "instant");
  assert.equal(undo.label, t("botbuilder.sharing.fixitUndo", "en"));
  assert.equal(undo.args.bot, "hank");
});

/* A bot with no display name is named by its ID: the card is about ONE bot, and a generic English
   phrase would name nobody (and could not be translated into the language the card is shown in). */
test("a nameless bot's title is filled with its id, never with a generic phrase", async () => {
  await seedBot("hank", { name: "", def: sharingDef("crow-sharing/crow_send_message") });
  await detector.default.check(store, { crowHome: process.env.CROW_HOME });
  const item = (await pending())[0];
  assert.equal(item.title, fill(t("botbuilder.sharing.fixitTitle", "en"), { bot: "hank" }));
  assert.doesNotMatch(item.title, /this bot/);
  assert.equal(item.context.bot, "hank", "the id the link and the undo take is unchanged");
  assert.equal(item.context.name, "", "and no name was invented for it");
});

/* The Detector stores EN (a boot pass has no language); the CARD is rendered from code in the
   dashboard's language, the retired-bundle card's rule — title, body and both button labels. */
test("the card renders in the dashboard's language: Spanish buttons, Spanish title, the approved body", async () => {
  await seedBot("hank", { def: sharingDef("crow-sharing/crow_send_message") });
  await detector.default.check(store, { crowHome: process.env.CROW_HOME });

  const es = await idx.renderFixItCards(db, { lang: "es", req: { csrfToken: "tok-es" } });
  assert.ok(es.includes("Compartir"), "the Bot Builder link says Compartir, not Sharing");
  assert.ok(es.includes("Quitar la mensajería a este bot"), "the undo's label is Spanish too");
  assert.ok(es.includes(fill(t("botbuilder.sharing.fixitTitle", "es"), { bot: "Hank" })), "the title names the bot in Spanish");
  assert.ok(es.includes(t("botbuilder.sharing.intro", "es")), "the body is the approved intro key");
  assert.ok(!es.includes(t("botbuilder.sharing.fixitUndo", "en")), "no stored English label leaks into the Spanish card");

  const en = await idx.renderFixItCards(db, { lang: "en", req: { csrfToken: "tok-en" } });
  assert.ok(en.includes(t("botbuilder.sharing.heading", "en")));
  assert.ok(en.includes(t("botbuilder.sharing.fixitUndo", "en")));
  assert.ok(en.includes(t("botbuilder.sharing.intro", "en")));
  assert.ok(en.includes(fill(t("botbuilder.sharing.fixitTitle", "en"), { bot: "Hank" })));
});

test("the card clears itself when the bot gets an allow-list entry, and when the def stops selecting crow-sharing", async () => {
  await seedBot("hank", { def: sharingDef("crow-sharing/crow_send_message") });
  await detector.default.check(store, { crowHome: process.env.CROW_HOME });
  assert.equal((await pending()).length, 1);

  acl.setSharingBotAclEntry(process.env.CROW_HOME, "hank", { contacts: [], groups: [], rate: { per_hour: 5 } });
  await detector.default.check(store, { crowHome: process.env.CROW_HOME });
  assert.equal((await pending()).length, 0, "an ACL entry answers the card");

  rmScratch(SECRETS_DIR);
  await db.execute("DELETE FROM pi_bot_defs");
  await seedBot("hank", { def: sharingDef("crow-sharing/crow_send_message") });
  await detector.default.check(store, { crowHome: process.env.CROW_HOME });
  assert.equal((await pending()).length, 1);
  await db.execute({
    sql: "UPDATE pi_bot_defs SET definition = ? WHERE bot_id = 'hank'",
    args: [JSON.stringify({ tools: { crow_mcp: ["crow-memory/crow_remember"] } })],
  });
  await detector.default.check(store, { crowHome: process.env.CROW_HOME });
  assert.equal((await pending()).length, 0, "a def that no longer selects it answers the card");
});

test("a bot with no sharing selection, a disabled bot, and an unreadable allow-list file raise no card", async () => {
  await seedBot("quiet", { def: sharingDef() });
  await seedBot("off", { name: "Off", def: sharingDef("crow-sharing/crow_send_message"), enabled: 0 });
  let out = await detector.default.check(store, { crowHome: process.env.CROW_HOME });
  assert.deepEqual(out.cards, []);
  assert.equal((await pending()).length, 0);

  await seedBot("hank", { def: sharingDef("crow-sharing/crow_send_message") });
  // An unreadable file is not "no permission": the bot did not lose anything, the file is broken.
  out = await detector.default.check(store, {
    crowHome: process.env.CROW_HOME,
    readAcl: () => ({ ok: false, reason: "unreadable" }),
  });
  assert.deepEqual(out.cards, []);
  assert.equal((await pending()).length, 0);
});

/* ------------------------------------------------------------------ the undo */

test("the undo removes every crow-sharing entry and nothing else, and answers the card as resolved", async () => {
  const def = { tools: { crow_mcp: ["crow-memory/crow_remember", "crow-sharing/crow_send_message", "crow-sharing__crow_list_contacts", "board/board_list"] }, models: { default: "m" } };
  await seedBot("hank", { def });
  await detector.default.check(store, { crowHome: process.env.CROW_HOME });
  const item = (await pending())[0];

  const result = await remedy.default({ bot: "hank" }, { item, db, req: {} });
  assert.equal(result.resolved, true);
  const row = (await db.execute({ sql: "SELECT definition FROM pi_bot_defs WHERE bot_id = 'hank'" })).rows[0];
  const next = JSON.parse(row.definition);
  assert.deepEqual(next.tools.crow_mcp, ["crow-memory/crow_remember", "board/board_list"]);
  assert.deepEqual(next.models, { default: "m" }, "nothing else moved");
  assert.equal(remedy.withoutSharingSelections(next), null, "there is nothing left to remove");
});

// The undo writes with a compare-and-set on the definition TEXT it read. Another save (a second tab, a
// peer, an approved skill) landing in that window must win: the remedy applies nothing and says so,
// leaving the newer definition exactly as its writer left it.
test("a concurrent def save beats the undo's compare-and-set: nothing is applied and the card stays", async () => {
  await seedBot("hank", { def: sharingDef("crow-sharing/crow_send_message") });
  await detector.default.check(store, { crowHome: process.env.CROW_HOME });
  const item = (await pending())[0];

  // The definition as the other writer saves it: still selects Sharing, and adds a tool of its own.
  const newer = { tools: { crow_mcp: ["crow-memory/crow_remember", "crow-sharing/crow_send_message", "board/board_list"] }, models: { default: "saved-elsewhere" } };

  /** A db that lets the concurrent save land BETWEEN the remedy's read and its UPDATE. */
  const racing = {
    execute: async (query) => {
      if (/SELECT definition FROM pi_bot_defs/.test(String(query.sql))) {
        const read = await db.execute(query);
        await db.execute({
          sql: "UPDATE pi_bot_defs SET definition = ? WHERE bot_id = 'hank'",
          args: [JSON.stringify(newer)],
        });
        return read;
      }
      return db.execute(query);
    },
  };

  const result = await remedy.default({ bot: "hank" }, { item, db: racing, req: {} });
  assert.equal(result.resolved, false, "the card is not answered by a write that never happened");
  assert.equal(result.flash, "fixit_error");

  const row = (await db.execute({ sql: "SELECT definition FROM pi_bot_defs WHERE bot_id = 'hank'" })).rows[0];
  assert.deepEqual(JSON.parse(row.definition), newer, "the newer definition is the one on disk, untouched");
});

test("the undo refuses a non-owner and a card naming somebody who is not a bot, and changes nothing", async () => {
  await seedBot("hank", { def: sharingDef("crow-sharing/crow_send_message") });
  const item = { context: { bot: "hank" } };

  remedy._setOwnerCheckForTest(async () => false);
  const denied = await remedy.default({ bot: "hank" }, { item, db, req: {} });
  assert.equal(denied.resolved, false);
  let def = JSON.parse((await db.execute({ sql: "SELECT definition FROM pi_bot_defs WHERE bot_id = 'hank'" })).rows[0].definition);
  assert.deepEqual(def.tools.crow_mcp.filter((e) => e.startsWith("crow-sharing")), ["crow-sharing/crow_send_message"]);

  remedy._setOwnerCheckForTest(async () => true);
  for (const bad of ["", "../etc/passwd", "not a bot id", "x".repeat(80)]) {
    const r = await remedy.default({ bot: bad }, { item: { context: {} }, db, req: {} });
    assert.equal(r.resolved, false, `refused: ${JSON.stringify(bad)}`);
  }
  def = JSON.parse((await db.execute({ sql: "SELECT definition FROM pi_bot_defs WHERE bot_id = 'hank'" })).rows[0].definition);
  assert.equal(def.tools.crow_mcp.includes("crow-sharing/crow_send_message"), true);
});