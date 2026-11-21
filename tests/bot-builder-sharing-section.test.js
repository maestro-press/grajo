/**
 * Bot Builder → Safety → Sharing (bot-door plan, PR B): panels/bot-builder/sharing-section.js.
 *
 * Harness: a real init-db'd scratch crow.db, a scratch CROW_HOME for the allow-list FILE, the real
 * section render, and the real owner route (sharing-bot-acl-api.js) mounted with the owner gate
 * stubbed — the section's Save is a plain PUT of the ticked ids, and this file proves the two ends
 * meet without a browser: what the section draws, and what the route pins when the section's own
 * payload is posted.
 */
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import Database from "better-sqlite3";
import { rmScratch } from "./helpers/safe-rm.js";

const root = mkdtempSync(join(tmpdir(), "bot-sharing-section-"));
process.env.CROW_DATA_DIR = join(root, "home");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const DB_FILE = join(root, "home", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const { renderSharingSection } = await import("../servers/gateway/dashboard/panels/bot-builder/sharing-section.js");
const { sharingBotAclRouter } = await import("../servers/gateway/routes/sharing-bot-acl-api.js");
const acl = await import("../servers/gateway/sharing-bot/acl.js");
const identity = await import("../servers/sharing/identity.js");
const { t, fill } = await import("../servers/gateway/dashboard/shared/i18n.js");

const BOT = "hank";
const PEER_KEY = "02" + "a".repeat(64);
const PEER_ED = "e".repeat(64);
const CARA_KEY = "02" + "b".repeat(64);
const CARA_ED = "f".repeat(64);

let db;
let server;
let groupId = 0;

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "home") },
    stdio: "pipe",
    cwd: REPO,
  });
  db = createDbClient(DB_FILE);

  const { default: express } = await import("express");
  const app = express();
  const noAuth = (req, res, next) => next();
  app.use(express.json());
  app.use(sharingBotAclRouter(noAuth, { openDb: () => createDbClient(DB_FILE), ownerCheck: async () => true }));
  await new Promise((r) => { server = app.listen(0, "127.0.0.1", r); });
});

after(async () => {
  if (server) { server.closeAllConnections?.(); await new Promise((r) => server.close(r)); }
  try { db && db.close(); } catch { /* already closed */ }
  rmScratch(root);
});

beforeEach(async () => {
  await db.execute("DELETE FROM contacts");
  await db.execute("DELETE FROM contact_group_members");
  await db.execute("DELETE FROM contact_groups");
  rmScratch(join(root, "home", "secrets"));
  /* Two contacts and one room with a member: the shape a real instance has after two invites. */
  await db.execute({
    sql: `INSERT INTO contacts (id, crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
          VALUES (1, 'crow:peer', 'Sam', ?, ?, 'crow')`,
    args: [PEER_KEY, PEER_ED],
  });
  await db.execute({
    sql: `INSERT INTO contacts (id, crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
          VALUES (2, 'crow:cara', 'Cara', ?, ?, 'crow')`,
    args: [CARA_KEY, CARA_ED],
  });
  const insertedGroup = Number((await db.execute({
    sql: "INSERT INTO contact_groups (name, room_uid, host_crow_id, mode) VALUES ('The Den', ?, 'crow:me', 'addressed')",
    args: ["r".repeat(32)],
  })).lastInsertRowid);
  groupId = insertedGroup;
  await db.execute({ sql: "INSERT INTO contact_group_members (group_id, contact_id) VALUES (?, 1)", args: [insertedGroup] });
});

const render = (lang = "en") => renderSharingSection({ db, def: {}, lang, botId: BOT, crowHome: process.env.CROW_HOME });

function writeEntry({ contacts = [], groups = [] } = {}) {
  const written = acl.setSharingBotAclEntry(process.env.CROW_HOME, BOT, { contacts, groups, rate: { per_hour: 20 } });
  assert.equal(written.ok, true);
}

function request(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? null : JSON.stringify(body);
    const req = http.request({
      host: "127.0.0.1",
      port: server.address().port,
      method,
      path,
      headers: payload ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) } : {},
    }, (res) => {
      let text = "";
      res.on("data", (c) => { text += c; });
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* not json */ }
        resolve({ status: res.statusCode, text, json });
      });
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

/* ------------------------------------------------------------------ render */

test("the section lists the instance's contacts and groups, with the allow-list ticked", async () => {
  writeEntry({ contacts: [{ crow_id: "crow:peer", secp256k1_pubkey: PEER_KEY }], groups: [{ id: groupId, members: [{ crow_id: "crow:peer", secp256k1_pubkey: PEER_KEY }] }] });
  const html = await render();

  assert.ok(html.includes(`data-testid="sharing-save"`), "it has its own Save");
  assert.ok(html.includes("The Den"), "the room is listed");
  const sam = /<input type="checkbox" name="sharing_contact" value="crow:peer" checked>/.exec(html);
  assert.ok(sam, "the allowed contact is ticked");
  const cara = /<input type="checkbox" name="sharing_contact" value="crow:cara">/.exec(html);
  assert.ok(cara, "the others are offered, unticked");
  assert.ok(new RegExp(`<input type="checkbox" name="sharing_group" value="${groupId}" checked>`).test(html), "the group is ticked");
  assert.ok(!html.includes(t("botbuilder.sharing.none", "en")), "nothing is empty, so no empty line");
  for (const key of ["botbuilder.sharing.heading", "botbuilder.sharing.intro", "botbuilder.sharing.contacts", "botbuilder.sharing.groups", "botbuilder.sharing.save"]) {
    assert.ok(html.includes(t(key, "en")), key + " reaches the page from i18n");
  }
});

test("an allowed contact shows the safety number it was pinned with — and nothing when it has re-keyed", async () => {
  const myEd = identity.loadOrCreateIdentity().ed25519Pubkey;
  const safety = identity.computeSafetyNumber(myEd, PEER_ED);
  writeEntry({ contacts: [{ crow_id: "crow:peer", secp256k1_pubkey: PEER_KEY }] });
  const pinned = await render();
  assert.ok(pinned.includes(fill(t("botbuilder.sharing.pinned", "en"), { n: safety })),
    "the symmetric safety number, worded as the copy table words it");

  /* The same contact, re-keyed since: the allow-list pins the OLD key, so the number printed would be
     a number for a key the bot may not use. */
  writeEntry({ contacts: [{ crow_id: "crow:peer", secp256k1_pubkey: "02" + "9".repeat(64) }] });
  const moved = await render();
  assert.equal(moved.includes(safety), false, "no safety number for a key that is not the pinned one");
});

test("nothing allowed says so, and an empty bot still gets the lists", async () => {
  writeEntry({ contacts: [], groups: [] });
  const html = await render();
  assert.ok(html.includes(`data-testid="sharing-none"`), "the approved 'cannot message anyone yet' line");
  assert.ok(html.includes(t("botbuilder.sharing.none", "en")));
  assert.ok(html.includes('value="crow:peer"'), "the contacts are still there to tick");
});

test("a contact's name is text, and the Spanish copy is its own", async () => {
  await db.execute({ sql: "UPDATE contacts SET display_name = ? WHERE id = 1", args: ["<b>Sam</b>"] });
  const html = await render();
  assert.ok(html.includes("&lt;b&gt;Sam&lt;/b&gt;"), "a name that looks like markup is escaped");
  assert.equal(html.includes("<b>Sam</b>"), false);

  const es = await render("es");
  assert.ok(es.includes(t("botbuilder.sharing.heading", "es")));
  assert.notEqual(t("botbuilder.sharing.intro", "es"), t("botbuilder.sharing.intro", "en"));
  assert.notEqual(t("botbuilder.sharing.pinned", "es"), t("botbuilder.sharing.pinned", "en"));
});

test("the save is a fetch to the ACL owner route with the page's CSRF token and ids only", async () => {
  writeEntry({ contacts: [], groups: [] });
  const html = await render();
  assert.ok(html.includes(`data-url="/dashboard/bot-builder/api/sharing/${BOT}"`), "the existing owner route");
  assert.ok(html.includes("window.crowCsrf"), "the server-bound token helper, never a cookie");
  assert.ok(html.includes("'X-Crow-Csrf'"), "echoed as the header the route checks");
  assert.ok(/body:JSON\.stringify\(\{contacts:contacts,groups:groups\}\)/.test(html),
    "ids only: a browser never sends a key");
  assert.ok(html.includes('method:\'PUT\''), "the route's own verb");
  assert.equal(html.includes("innerHTML"), false, "nothing is written as markup");
});

/* --------------------------------------------------------- the two ends meet */

test("posting what the section sends pins the key from the live row, not from the browser", async () => {
  const res = await request("PUT", `/dashboard/bot-builder/api/sharing/${BOT}`, {
    contacts: ["crow:peer"],
    groups: [String(groupId)],
  });
  assert.equal(res.status, 200, res.text);
  const entry = acl.readBotAcl(process.env.CROW_HOME, BOT).entry;
  assert.deepEqual(entry.contacts, [{ crow_id: "crow:peer", secp256k1_pubkey: PEER_KEY }]);
  assert.deepEqual(entry.groups[0].members, [{ crow_id: "crow:peer", secp256k1_pubkey: PEER_KEY }]);
  assert.deepEqual(entry.rate, { per_hour: 20 });

  /* And the section now draws that save back. */
  const html = await render();
  assert.ok(/name="sharing_contact" value="crow:peer" checked/.test(html));
  assert.ok(new RegExp(`name="sharing_group" value="${groupId}" checked`).test(html));
});

test("a contact that is not a real row is refused, and the allow-list is left alone", async () => {
  writeEntry({ contacts: [{ crow_id: "crow:peer", secp256k1_pubkey: PEER_KEY }] });
  const res = await request("PUT", `/dashboard/bot-builder/api/sharing/${BOT}`, {
    contacts: ["crow:nobody"],
    groups: [],
  });
  assert.equal(res.status, 400, res.text);
  assert.equal(res.json.error, "unknown_contact");
  assert.deepEqual(acl.readBotAcl(process.env.CROW_HOME, BOT).entry.contacts,
    [{ crow_id: "crow:peer", secp256k1_pubkey: PEER_KEY }], "nothing changed");
});

/* ---------------------------------------------------------------- the door */

test("after a save, a draft from that bot is allowed and an unlisted contact is not", async () => {
  const res = await request("PUT", `/dashboard/bot-builder/api/sharing/${BOT}`, { contacts: ["crow:cara"], groups: [] });
  assert.equal(res.status, 200, res.text);
  const { readDraftBotAcl, botAudienceRefusal } = await import("../servers/gateway/messages/drafts-bot-acl.js");
  const entry = readDraftBotAcl({ botId: BOT }, process.env.CROW_HOME).entry;
  const allowed = botAudienceRefusal({
    origin: "bot", conversationKind: "contact", conversationId: 2,
    recipients: [{ contactId: 2, crowId: "crow:cara", pubkey: CARA_KEY }],
  }, entry);
  assert.equal(allowed, null, "the ticked contact is allowed");
  const refused = botAudienceRefusal({
    origin: "bot", conversationKind: "contact", conversationId: 1,
    recipients: [{ contactId: 1, crowId: "crow:peer", pubkey: PEER_KEY }],
  }, entry);
  assert.equal(refused, "not_allowed", "the unticked one is not");
});

/* --------------------------------------------------------------- the page */

test("the Safety tab renders the section, beside the email-send card and outside its form", async () => {
  writeEntry({ contacts: [], groups: [] });
  const { renderSafety } = await import("../servers/gateway/dashboard/panels/bot-builder/tab-safety.js");
  const html = await renderSafety({
    db,
    def: { permission_policy: { external_send: "draft_only" } },
    lang: "en",
    botId: BOT,
    crowHome: process.env.CROW_HOME,
    hidden: () => "",
    bot: null,
  });
  assert.ok(html.includes('data-testid="sharing-save"'), "the Sharing section is on the Safety tab");
  assert.ok(html.includes(t("botbuilder.sharing.heading", "en")));
  /* It must not become part of the def save: a nested form is invalid, and a checkbox here is a
     permission, never a definition field. */
  const formEnd = html.indexOf("</form>");
  const sharingAt = html.indexOf('data-testid="sharing-save"');
  assert.ok(formEnd > -1 && sharingAt > formEnd, "the section sits after the safety form closes");
  assert.equal(html.includes('id="btb-sharing"'), true);
});