// The bot sharing door's rules (servers/gateway/sharing-bot/*.js): a bot's message is ALWAYS a draft,
// the allow-list is the only address book, a re-keyed contact is a different person, the owner's open
// draft is never overwritten, the rate cap counts what the audit trail recorded, and the inbox is
// received-only, allow-list-only, read-only.
//
// Every case goes through `runDoorCall` — the same function the MCP tools are thin wrappers over — so
// the audit row for each call is written here too, exactly as on the wire. No MCP and no HTTP in this
// file: tests/sharing-bot-door-e2e.test.js drives the mount (token + signed actor + 401s).
//
// Harness: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR, so nothing can touch the
// real ~/.crow), a scratch CROW_HOME for the allow-list file, and the real modules — only the clock and
// the draft seal seed are injected.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

const root = mkdtempSync(join(tmpdir(), "sharing-bot-mcp-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const store = await import("../servers/gateway/messages/drafts-store.js");
const acl = await import("../servers/gateway/sharing-bot/acl.js");
const audit = await import("../servers/gateway/sharing-bot/audit.js");
const inbox = await import("../servers/gateway/sharing-bot/inbox.js");
const { runDoorCall } = await import("../servers/gateway/sharing-bot/call.js");
const { SHARING_BOT_TOOL_NAMES } = await import("../servers/gateway/sharing-bot-mcp.js");

const SEED = Buffer.from("a fixed keychain seed for the sharing door");
const BOT = "hank";
const BOT_NAME = "Hank";
const NOW = 1_767_225_600_000;
const PEER = { crowId: "crow:peer", name: "Peer", pubkey: "02" + "a".repeat(64) };
const OTHER = { crowId: "crow:other", name: "Other", pubkey: "02" + "b".repeat(64) };
const LATE = { crowId: "crow:late", name: "Late", pubkey: "02" + "c".repeat(64) };

const open = [];

after(() => {
  for (const db of open) {
    try { db.close(); } catch { /* already closed */ }
  }
  rmSync(root, { recursive: true, force: true });
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
  const raw = new Database(MASTER);
  raw.pragma("wal_checkpoint(TRUNCATE)");
  raw.close();
});

beforeEach(() => {
  rmSync(join(root, "home", "secrets"), { recursive: true, force: true });
});

let n = 0;

async function addContact(db, { crowId, name, pubkey, blocked = 0 }) {
  const res = await db.execute({
    sql: `INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type, is_blocked)
          VALUES (?, ?, ?, ?, 'crow', ?)`,
    args: [crowId, name, pubkey, "e".repeat(64), blocked],
  });
  return Number(res.lastInsertRowid);
}

async function addRoom(db, { name, memberIds }) {
  const res = await db.execute({
    sql: "INSERT INTO contact_groups (name, room_uid, host_crow_id, mode) VALUES (?, ?, 'crow:me', 'addressed')",
    args: [name, "r".repeat(32)],
  });
  const groupId = Number(res.lastInsertRowid);
  for (const contactId of memberIds) {
    await db.execute({ sql: "INSERT INTO contact_group_members (group_id, contact_id) VALUES (?, ?)", args: [groupId, contactId] });
  }
  return groupId;
}

/** One private copy of the master DB, the bot's def row, two contacts and a room. */
async function fixture({ rate = 20, allow = [PEER] } = {}) {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  await db.execute({
    sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES (?, ?, '{}', 1)",
    args: [BOT, BOT_NAME],
  });
  const peerId = await addContact(db, PEER);
  const otherId = await addContact(db, OTHER);
  const roomId = await addRoom(db, { name: "Den", memberIds: [peerId] });
  const plainId = Number((await db.execute({ sql: "INSERT INTO contact_groups (name) VALUES ('Choir')" })).lastInsertRowid);

  if (allow && allow.length) {
    const written = acl.setSharingBotAclEntry(process.env.CROW_HOME, BOT, {
      contacts: allow.map((contact) => ({ crow_id: contact.crowId, secp256k1_pubkey: contact.pubkey })),
      groups: [{ id: roomId, members: [{ crow_id: PEER.crowId, secp256k1_pubkey: PEER.pubkey }] }],
      rate: { per_hour: rate },
    });
    assert.equal(written.ok, true, "the fixture's allow-list was written");
  }

  return { db, crow, peerId, otherId, roomId, plainId, opts: { loadSeed: async () => SEED } };
}

/** The door's own call path: rules + rate cap + exactly one audit row, as the mount runs it. */
function doorCall(f, tool, args = {}) {
  return runDoorCall(f.db, { tool, claims: { botId: BOT, threadId: "perch-1", gatewayType: "perch" }, args }, {
    crowHome: process.env.CROW_HOME, now: NOW, loadSeed: f.opts.loadSeed,
  });
}

const sendPeer = (f, over = {}) => doorCall(f, "crow_send_message", { contact: PEER.crowId, message: "Are we still on for Saturday?", ...over });
const sendRoom = (f, over = {}) => doorCall(f, "crow_send_group_message", { group: String(f.roomId), message: "Hello den", ...over });

/* -------------------------------------------------------------------- the surface */

test("the door is exactly the five tools, and no door module can send", () => {
  assert.deepEqual([...SHARING_BOT_TOOL_NAMES].sort(), [
    "crow_bot_inbox", "crow_list_contacts", "crow_list_crosspost_transforms",
    "crow_send_group_message", "crow_send_message",
  ]);
  // The structural claim the whole design rests on: a bot's words can only become a draft. The door's
  // modules import no transport and no room/peer send, so no edit below can quietly grow one.
  for (const file of [
    "sharing-bot-mcp.js", "sharing-bot/call.js", "sharing-bot/messages.js",
    "sharing-bot/contacts.js", "sharing-bot/inbox.js",
  ]) {
    const src = readFileSync(join(REPO, "servers", "gateway", file), "utf8");
    for (const forbidden of ["drafts-send.js", "handlePeerSend", "sendOperatorRoomMessage", "getManagersOrNull", "nostrManager", "peer-messages.js"]) {
      assert.equal(src.includes(forbidden), false, `${file} must not reach ${forbidden}`);
    }
  }
});

/* ------------------------------------------------------------------- the draft */

test("a bot message is a draft: origin bot, the pinned audience, nothing sent, and no text in the audit", async () => {
  const f = await fixture();
  const out = await sendPeer(f);
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.outcome, "drafted");
  assert.equal(out.data.status, "awaiting_owner");
  assert.equal(out.data.draft, "created");
  assert.match(out.data.draft_id, store.MESSAGE_DRAFT_ID_RE);

  const draft = await store.getDraft(f.db, out.data.draft_id);
  assert.equal(draft.state, "open");
  assert.equal(draft.origin, "bot");
  assert.equal(draft.botId, BOT);
  assert.equal(draft.botName, BOT_NAME, "the name the owner will read is snapshotted (and sealed)");
  assert.equal(draft.conversationKind, "contact");
  assert.equal(draft.conversationId, f.peerId);
  assert.deepEqual(draft.recipients, [{ contactId: f.peerId, crowId: PEER.crowId, pubkey: PEER.pubkey }]);

  // Nothing was sent: no outbound row exists, and the draft is still waiting for the owner.
  assert.equal(Number((await f.db.execute({ sql: "SELECT COUNT(*) AS n FROM messages" })).rows[0].n), 0);

  const calls = await audit.listBotSharingCalls(f.db, BOT);
  assert.equal(calls.length, 1, "exactly one audit row per call");
  assert.equal(calls[0].tool, "crow_send_message");
  assert.equal(calls[0].outcome, "drafted");
  assert.equal(calls[0].draftId, out.data.draft_id);
  assert.equal(calls[0].target, PEER.crowId);
  assert.equal(calls[0].thread, "perch-1");
  assert.equal(calls[0].gateway, "perch");
  assert.doesNotMatch(JSON.stringify(calls), /Saturday/, "the audit never carries the message text");
  // The store's own audit row is a bot's draft by a bot.
  const trail = await store.listAudit(f.db, out.data.draft_id);
  assert.deepEqual(trail.map((row) => [row.action, row.actor, row.actorId]), [["create", "bot", BOT]]);
});

test("the bot revises its OWN open draft; one conversation never holds two", async () => {
  const f = await fixture();
  const first = await sendPeer(f);
  const second = await sendPeer(f, { message: "Sunday, then?" });
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.equal(second.outcome, "revised");
  assert.equal(second.data.draft, "revised");
  assert.equal(second.data.draft_id, first.data.draft_id, "the same row, not a second draft");
  const draft = await store.getDraft(f.db, first.data.draft_id);
  assert.equal(draft.body, "Sunday, then?");
  assert.equal(draft.version, 2);
  assert.equal((await store.listDrafts(f.db, { state: "open" })).length, 1);
});

test("the allow-list is the only address book: an existing contact outside it is not_allowed", async () => {
  const f = await fixture();
  const byCrowId = await sendPeer(f, { contact: OTHER.crowId });
  assert.equal(byCrowId.ok, false);
  assert.equal(byCrowId.code, "not_allowed");
  const byName = await sendPeer(f, { contact: "Other" });
  assert.equal(byName.code, "not_allowed");
  assert.equal((await store.listDrafts(f.db, {})).length, 0, "nothing was written for an unknown target");

  // A name that IS on the list resolves — names are matched only among allow-listed entries.
  const allowed = await sendPeer(f, { contact: "Peer" });
  assert.equal(allowed.ok, true, JSON.stringify(allowed));
  assert.equal(allowed.target, PEER.crowId);

  // And every refusal is audited, with no draft id.
  const calls = await audit.listBotSharingCalls(f.db, BOT);
  assert.deepEqual(calls.map((call) => call.outcome).sort(),
    ["drafted", "refused:not_allowed", "refused:not_allowed"]);
  for (const call of calls) if (call.outcome.startsWith("refused:")) assert.equal(call.draftId, null);
});

test("a bot with no allow-list entry may message nobody; an unreadable file is a different refusal", async () => {
  const f = await fixture({ allow: [] });
  const none = await sendPeer(f);
  assert.equal(none.ok, false);
  assert.equal(none.code, "no_allowlist");

  // A damaged file narrows a bot to nothing — it is never read as "no restrictions".
  mkdirSync(join(process.env.CROW_HOME, "secrets"), { recursive: true, mode: 0o700 });
  const { writeFileSync } = await import("node:fs");
  writeFileSync(acl.sharingBotAclPath(process.env.CROW_HOME), "{broken", { mode: 0o600 });
  const broken = await sendPeer(f);
  assert.equal(broken.code, "acl_unreadable");
  const listed = await doorCall(f, "crow_list_contacts");
  assert.equal(listed.code, "acl_unreadable");
  const inboxRead = await doorCall(f, "crow_bot_inbox", {});
  assert.equal(inboxRead.code, "acl_unreadable");
});

test("a re-keyed contact, a blocked contact and a vanished one each keep their own refusal", async () => {
  const f = await fixture();
  await f.db.execute({ sql: "UPDATE contacts SET secp256k1_pubkey = ? WHERE id = ?", args: ["02" + "9".repeat(64), f.peerId] });
  assert.equal((await sendPeer(f)).code, "pubkey_changed", "the pinned key is the permission");

  await f.db.execute({ sql: "UPDATE contacts SET is_blocked = 1 WHERE id = ?", args: [f.peerId] });
  // Blocked wins over the key check: a blocked contact is not a send to re-point.
  assert.equal((await sendPeer(f)).code, "blocked");

  await f.db.execute({ sql: "DELETE FROM contacts WHERE id = ?", args: [f.peerId] });
  assert.equal((await sendPeer(f)).code, "contact_gone");
  assert.equal((await store.listDrafts(f.db, {})).length, 0, "no refusal wrote a draft");
});

test("the owner's open draft is never overwritten; once the owner edits a bot's draft it is frozen", async () => {
  const f = await fixture();
  const ownerDraft = await store.createDraft(f.db, {
    conversationKind: "contact", conversationId: f.peerId, body: "mine to write",
    recipients: [{ contactId: f.peerId, crowId: PEER.crowId, pubkey: PEER.pubkey }],
    expectVersion: 0,
  }, f.opts);
  const refused = await sendPeer(f);
  assert.equal(refused.code, "owner_draft_open");
  assert.equal((await store.getDraft(f.db, ownerDraft.draft.id)).body, "mine to write", "the owner's words stand");

  // Now a bot draft the owner edits by hand: the bot may not revise it again.
  await store.discardDraft(f.db, ownerDraft.draft.id, {}, f.opts);
  const botDraft = await sendPeer(f);
  assert.equal(botDraft.ok, true);
  await store.updateBody(f.db, botDraft.data.draft_id, { body: "the owner's version", expectVersion: 1 }, f.opts);
  const frozen = await sendPeer(f, { message: "the bot tries again" });
  assert.equal(frozen.code, "owner_edited");
  assert.equal((await store.getDraft(f.db, botDraft.data.draft_id)).body, "the owner's version");
});

test("the rate cap counts the drafts the trail recorded, and a refusal says so", async () => {
  const f = await fixture({ rate: 2 });
  assert.equal((await sendPeer(f)).ok, true);
  assert.equal((await sendRoom(f)).ok, true, "a room draft shares the bot's budget");
  assert.equal(await audit.countDraftsSince(f.db, BOT, NOW - 3_600_000), 2);

  const over = await sendPeer(f, { message: "one too many" });
  assert.equal(over.ok, false);
  assert.equal(over.code, "rate_limited");
  // The trail is the cap's own bookkeeping: only drafts count, never a refusal or a read.
  await doorCall(f, "crow_list_contacts");
  assert.equal(await audit.countDraftsSince(f.db, BOT, NOW - 3_600_000), 2);

  // A window that has rolled over starts empty again.
  const later = await runDoorCall(f.db, {
    tool: "crow_send_message", claims: { botId: BOT }, args: { contact: PEER.crowId, message: "next hour" },
  }, { crowHome: process.env.CROW_HOME, now: NOW + 3_600_001, loadSeed: f.opts.loadSeed });
  assert.equal(later.ok, true, "the window is one hour, not forever");
});

/* -------------------------------------------------------------------- groups */

test("an allow-listed room drafts one room message; a changed member set refuses", async () => {
  const f = await fixture();
  const out = await sendRoom(f, { group: "Den" });
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.target, String(f.roomId));
  const draft = await store.getDraft(f.db, out.data.draft_id);
  assert.equal(draft.conversationKind, "room");
  assert.equal(draft.conversationId, f.roomId);
  assert.deepEqual(draft.recipients, [{ contactId: f.peerId, crowId: PEER.crowId, pubkey: PEER.pubkey }]);

  // Somebody joins the room: the permission named a member set, and this is not it.
  const lateId = await addContact(f.db, LATE);
  await f.db.execute({ sql: "INSERT INTO contact_group_members (group_id, contact_id) VALUES (?, ?)", args: [f.roomId, lateId] });
  assert.equal((await sendRoom(f, { message: "still here?" })).code, "group_changed");
});

test("a plain group has no thread to draft into, and a group outside the allow-list is refused", async () => {
  const f = await fixture();
  assert.equal((await sendRoom(f, { group: String(f.plainId) })).code, "not_allowed",
    "the plain group is not on the allow-list at all");

  // An allow-list entry naming a plain group: the door still refuses it, by its own code.
  acl.setSharingBotAclEntry(process.env.CROW_HOME, BOT, {
    contacts: [{ crow_id: PEER.crowId, secp256k1_pubkey: PEER.pubkey }],
    groups: [{ id: f.plainId, members: [{ crow_id: PEER.crowId, secp256k1_pubkey: PEER.pubkey }] }],
    rate: { per_hour: 20 },
  });
  assert.equal((await sendRoom(f, { group: String(f.plainId) })).code, "group_not_a_room");
});

test("crow_list_contacts reports names and ids only, from the allow-list", async () => {
  const f = await fixture();
  const out = await doorCall(f, "crow_list_contacts");
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.deepEqual(out.data.contacts, [{ kind: "contact", crow_id: PEER.crowId, name: "Peer" }]);
  assert.deepEqual(out.data.groups.map((group) => [group.kind, group.group_id, group.name]), [["room", f.roomId, "Den"]]);
  const serialized = JSON.stringify(out.data);
  assert.doesNotMatch(serialized, /secp256k1|pubkey|02aaaa/, "no key ever leaves on this tool");
  assert.doesNotMatch(serialized, /crow:other|Other/, "nobody outside the allow-list is listed");
  assert.equal((await audit.listBotSharingCalls(f.db, BOT))[0].outcome, "read");
});

/* --------------------------------------------------------------------- inbox */

test("the inbox is received-only, allow-list-only, and never marks anything read", async () => {
  const f = await fixture();
  await f.db.execute({
    sql: "INSERT INTO messages (contact_id, content, direction, is_read, created_at) VALUES (?, ?, 'received', 0, '2026-11-19 10:00:00')",
    args: [f.peerId, "hello from the peer"],
  });
  await f.db.execute({
    sql: "INSERT INTO messages (contact_id, content, direction, is_read, created_at) VALUES (?, ?, 'sent', 1, '2026-11-19 10:01:00')",
    args: [f.peerId, "the owner's own words"],
  });
  await f.db.execute({
    sql: "INSERT INTO messages (contact_id, content, direction, is_read, created_at) VALUES (?, ?, 'received', 0, '2026-11-19 10:02:00')",
    args: [f.otherId, "not for this bot"],
  });

  const out = await doorCall(f, "crow_bot_inbox", { limit: 20 });
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(out.data.messages.length, 1, "one message: the peer's, not the owner's and not a stranger's");
  const item = out.data.messages[0];
  assert.equal(item.text, "hello from the peer");
  assert.equal(item.untrusted, true);
  assert.deepEqual(item.from, { name: "Peer", crow_id: PEER.crowId });
  assert.equal(item.conversation.kind, "contact");
  assert.equal(item.received_at, Date.parse("2026-11-19T10:00:00Z"));
  assert.equal(out.data.cursor, inbox.formatInboxCursor(Number(item.id.slice(1)), 0));

  // Read-only: the unread badge is the owner's.
  const unread = await f.db.execute({ sql: "SELECT is_read FROM messages WHERE contact_id = ? AND direction = 'received'", args: [f.peerId] });
  assert.equal(Number(unread.rows[0].is_read), 0, "a bot reading a message does not mark it read");

  // The cursor advances over what was returned: nothing is repeated, nothing is skipped.
  const next = await doorCall(f, "crow_bot_inbox", { cursor: out.data.cursor, limit: 20 });
  assert.deepEqual(next.data.messages, []);
  assert.equal(next.data.cursor, out.data.cursor);

  // The audit rows for the reads carry the returned ids and the cursor — and no text. (Newest first,
  // so the cursor-continuation call is the empty one.)
  const reads = (await audit.listBotSharingCalls(f.db, BOT)).filter((call) => call.tool === "crow_bot_inbox");
  assert.equal(reads.length, 2);
  assert.deepEqual(reads[1].refs.ids, [item.id]);
  assert.equal(reads[1].refs.cursor, out.data.cursor);
  assert.deepEqual(reads[0].refs.ids, [], "the continuation returned nothing");
  for (const read of reads) assert.doesNotMatch(JSON.stringify(read), /hello from the peer/);
});

test("a sender whose pinned key changed is dropped from the inbox, and a room only speaks through its pinned members", async () => {
  const f = await fixture();
  await f.db.execute({
    sql: "INSERT INTO messages (contact_id, content, direction, created_at) VALUES (?, 'old key', 'received', '2026-11-19 10:00:00')",
    args: [f.peerId],
  });
  await f.db.execute({
    sql: "INSERT INTO room_messages (group_id, msg_uid, sender_contact_id, content, direction, created_at) VALUES (?, ?, ?, 'in the den', 'received', '2026-11-19 10:05:00')",
    args: [f.roomId, "m1", f.peerId],
  });
  // A host-relayed row: somebody who is NOT a member of this instance wrote into the room, so the
  // receiving host stored it with no sender contact. It is nobody this bot may read (rule 2), not the
  // host's own words — those are `direction = 'sent'` and never reach this query at all.
  await f.db.execute({
    sql: "INSERT INTO room_messages (group_id, msg_uid, sender_contact_id, content, direction, created_at) VALUES (?, ?, NULL, 'from a stranger via the host', 'received', '2026-11-19 10:06:00')",
    args: [f.roomId, "m2"],
  });

  // The contact is re-keyed after the room was allowed: its DM and its room row both disappear, and the
  // sender-less row was never this bot's to read.
  await f.db.execute({ sql: "UPDATE contacts SET secp256k1_pubkey = ? WHERE id = ?", args: ["02" + "9".repeat(64), f.peerId] });
  const page = await doorCall(f, "crow_bot_inbox", { limit: 20 });
  assert.equal(page.ok, true);
  assert.deepEqual(page.data.messages.map((item) => item.text), [],
    "a re-keyed sender is not the person who was allowed, and a row with no sender is not a member here");

  // Restore the key: both the DM and the member's room row come back, and the room item names its room.
  // The sender-less row stays out.
  await f.db.execute({ sql: "UPDATE contacts SET secp256k1_pubkey = ? WHERE id = ?", args: [PEER.pubkey, f.peerId] });
  const all = await doorCall(f, "crow_bot_inbox", { limit: 20 });
  assert.deepEqual(all.data.messages.map((item) => item.text), ["old key", "in the den"]);
  const room = all.data.messages.find((item) => item.id.startsWith("r"));
  assert.deepEqual(room.conversation, { kind: "room", group_id: f.roomId, name: "Den" });
  assert.deepEqual(room.from, { name: "Peer", crow_id: PEER.crowId });
});

test("the inbox caps the text and the page, and refuses a cursor it did not issue", async () => {
  const f = await fixture();
  const long = "x".repeat(inbox.MAX_INBOX_TEXT_CHARS + 500);
  await f.db.execute({
    sql: "INSERT INTO messages (contact_id, content, direction, created_at) VALUES (?, ?, 'received', '2026-11-19 10:00:00')",
    args: [f.peerId, long],
  });
  for (let i = 1; i <= 3; i += 1) {
    await f.db.execute({
      sql: "INSERT INTO messages (contact_id, content, direction, created_at) VALUES (?, ?, 'received', ?)",
      args: [f.peerId, `second ${i}`, `2026-11-19 10:0${i}:00`],
    });
  }
  const page = await doorCall(f, "crow_bot_inbox", { limit: 2 });
  assert.equal(page.data.messages.length, 2);
  assert.equal(page.data.messages[0].text.length, inbox.MAX_INBOX_TEXT_CHARS);

  assert.equal((await doorCall(f, "crow_bot_inbox", { cursor: "nope" })).code, "bad_cursor");
  assert.equal((await doorCall(f, "crow_bot_inbox", { cursor: "p1" })).code, "bad_cursor", "both marks or nothing");
});

test("draft_updates: only this bot's own drafts, and a state change shows up once", async () => {
  const f = await fixture();
  // Another bot's draft, in the conversation this bot never touches: it is not this caller's row.
  const otto = await store.createDraft(f.db, {
    conversationKind: "contact", conversationId: f.otherId, body: "otto's words",
    recipients: [{ contactId: f.otherId, crowId: OTHER.crowId, pubkey: OTHER.pubkey }],
    origin: "bot", botId: "otto", botName: "Otto", expectVersion: 0,
  }, f.opts);
  assert.equal(otto.ok, true, "the other bot's draft exists");

  const mine = await sendPeer(f);
  assert.equal(mine.ok, true, JSON.stringify(mine));

  const first = await doorCall(f, "crow_bot_inbox", {});
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.deepEqual(first.data.draft_updates, [{ draft_id: mine.data.draft_id, state: "open" }],
    "exactly this bot's draft: not another bot's, and no message text");
  assert.doesNotMatch(JSON.stringify(first.data.draft_updates), /Saturday/, "no draft body on this channel");
  assert.ok(!JSON.stringify(first.data.draft_updates).includes(otto.draft.id), "another bot's draft never appears");

  // The owner discards it: one state change, reported once, then the cursor is caught up.
  await store.discardDraft(f.db, mine.data.draft_id, {}, { ...f.opts, now: NOW + 60_000 });
  const second = await doorCall(f, "crow_bot_inbox", { cursor: first.data.cursor });
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.deepEqual(second.data.draft_updates, [{ draft_id: mine.data.draft_id, state: "discarded" }]);
  const third = await doorCall(f, "crow_bot_inbox", { cursor: second.data.cursor });
  assert.deepEqual(third.data.draft_updates, [], "the same change is never reported twice");
  assert.equal(third.data.cursor, second.data.cursor);

  // The trail records which drafts the bot was told about — ids only. (Newest first: the caught-up
  // call carries no draft ids, the two before it do.)
  const reads = (await audit.listBotSharingCalls(f.db, BOT)).filter((call) => call.tool === "crow_bot_inbox");
  assert.equal(reads[0].refs.drafts, undefined, "a call with nothing to report records no draft id");
  assert.deepEqual(reads[1].refs.drafts, [mine.data.draft_id]);
  for (const read of reads) assert.doesNotMatch(JSON.stringify(read), /Saturday/);
});

test("an old-format inbox cursor is still accepted and still advances the draft mark", async () => {
  const f = await fixture();
  // The shape every cursor had before draft_updates existed: `p<id>.r<id>`, with no `.d` part.
  const legacy = inbox.formatInboxCursor(0, 0);
  assert.equal(legacy, "p0.r0");
  const empty = await doorCall(f, "crow_bot_inbox", { cursor: legacy });
  assert.equal(empty.ok, true, JSON.stringify(empty));
  assert.deepEqual(empty.data.draft_updates, []);

  const mine = await sendPeer(f);
  assert.equal(mine.ok, true);
  const page = await doorCall(f, "crow_bot_inbox", { cursor: legacy });
  assert.equal(page.ok, true, JSON.stringify(page));
  assert.deepEqual(page.data.draft_updates.map((update) => [update.draft_id, update.state]),
    [[mine.data.draft_id, "open"]], "the old cursor's draft mark is 0, so the draft is reported once");
  assert.match(page.data.cursor, /^p0\.r0\.d[0-9]+\.imsgd-[0-9a-f]{32}$/,
    "and the answer carries the new shape: the millisecond AND the row it reached");
  const continued = await doorCall(f, "crow_bot_inbox", { cursor: page.data.cursor });
  assert.deepEqual(continued.data.draft_updates, []);
});

test("the audit refuses a nonsense outcome and stores ids-only refs", async () => {
  const f = await fixture();
  await assert.rejects(() => audit.recordBotSharingCall(f.db, {
    botId: BOT, tool: "crow_send_message", outcome: "sent", ts: NOW,
  }), /outcome/, "a door call is never recorded as a send");
  const id = await audit.recordBotSharingCall(f.db, {
    botId: BOT, tool: "crow_bot_inbox", outcome: "read", ts: NOW,
    // A caller cannot smuggle a free-form string into refs_json.
    refs: { ids: ["p1", "words that are not ids", 7], cursor: "p1.r0" },
  });
  assert.ok(id > 0);
  const [row] = await audit.listBotSharingCalls(f.db, BOT);
  assert.deepEqual(row.refs, { ids: ["p1"], cursor: "p1.r0" });
});

test("an unknown tool is refused without an audit row (the mount never routes it)", async () => {
  const f = await fixture();
  const out = await runDoorCall(f.db, { tool: "crow_share", claims: { botId: BOT }, args: {} }, { crowHome: process.env.CROW_HOME, now: NOW });
  assert.equal(out.ok, false);
  assert.equal(out.code, "unauthorized");
  assert.equal((await audit.listBotSharingCalls(f.db, BOT)).length, 0);
});

/* ------------------------------------------------------------------ concurrency */

// A bot's revise is a compare-and-set like every other draft write: it read the row, decided to
// replace the body, and then wrote. An owner's autosave landing between those two steps is the one
// sequence that must never end with the bot's words over the owner's — the owner is the person the
// draft is FOR, and the door's `owner_edited` check only sees edits that finished before the read.
test("a bot's revise loses to an owner edit that landed between its read and its write", async () => {
  const f = await fixture();
  const first = await sendPeer(f);
  assert.equal(first.ok, true, JSON.stringify(first));
  const read = await store.getOpenDraft(f.db, "contact", f.peerId);
  assert.equal(read.version, 1, "the row the bot is about to revise");

  // THE INTERLEAVING: the bot read version 1; the owner's autosave then lands (version 2); only then
  // does the bot's write go through. The proxy applies the owner's edit immediately before the store's
  // revise UPDATE reaches the table — the exact millisecond window, with the real store on both sides.
  let ownerEditApplied = false;
  const raced = {
    execute: async (query) => {
      const sql = String(query.sql);
      if (!ownerEditApplied && sql.includes("UPDATE message_drafts") && sql.includes("version = version + 1")) {
        ownerEditApplied = true;
        const edited = await store.updateBody(f.db, read.id, { body: "the owner's words", expectVersion: read.version }, f.opts);
        assert.equal(edited.ok, true, "the owner's autosave landed first");
      }
      return f.db.execute(query);
    },
  };
  const out = await runDoorCall(raced, {
    tool: "crow_send_message",
    claims: { botId: BOT, threadId: "perch-1", gatewayType: "perch" },
    args: { contact: PEER.crowId, message: "the bot's words" },
  }, { crowHome: process.env.CROW_HOME, now: NOW + 1000, loadSeed: f.opts.loadSeed });

  assert.equal(ownerEditApplied, true, "the owner's edit really did interleave");
  assert.equal(out.ok, false, JSON.stringify(out));
  assert.equal(out.code, "draft_changed", "the refusal the door already uses for a lost race");
  const after = await store.getDraft(f.db, read.id);
  assert.equal(after.body, "the owner's words", "the owner's text stands");
  assert.equal(after.version, 2, "and the bot moved nothing (one owner edit, no bot edit)");
  const trail = await store.listAudit(f.db, read.id);
  assert.deepEqual(trail.map((row) => [row.action, row.actor]), [["create", "bot"], ["edit", "owner"]],
    "no `edit` row claims the bot overwrote it");
  const calls = await audit.listBotSharingCalls(f.db, BOT);
  assert.equal(calls[0].outcome, "refused:draft_changed");
});

/* ----------------------------------------------------------- inbox paging (ids, rooms, drafts) */

const STRANGER = { crowId: "crow:stranger", name: "Stranger", pubkey: "02" + "d".repeat(64) };

/** One `room_messages` row, with an explicit id so a test can place it precisely on the id axis. */
async function addRoomMessage(db, { id, groupId, senderContactId, content, createdAt }) {
  await db.execute({
    sql: `INSERT INTO room_messages (id, group_id, msg_uid, sender_contact_id, content, direction, created_at)
          VALUES (?, ?, ?, ?, ?, 'received', ?)`,
    args: [id, groupId, `uid-${id}`, senderContactId, content, createdAt],
  });
}

// Ids are compared as NUMBERS. `p9` and `p10` share a timestamp in any real page cut (both rows can
// land in the same second), and a string comparison puts "p10" before "p9" — so the page would return
// 10, move the cursor past it, and 9 could never be reached again.
test("the inbox pages by numeric id: a cut between ids 9 and 10 returns both", async () => {
  const f = await fixture();
  for (const [id, body] of [[9, "nine"], [10, "ten"]]) {
    await f.db.execute({
      sql: "INSERT INTO messages (id, contact_id, content, direction, created_at) VALUES (?, ?, ?, 'received', '2026-11-19 10:00:00')",
      args: [id, f.peerId, body],
    });
  }

  const first = await doorCall(f, "crow_bot_inbox", { limit: 1 });
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.deepEqual(first.data.messages.map((item) => item.text), ["nine"], "the lower id comes first");
  assert.equal(first.data.cursor, "p9.r0");
  const second = await doorCall(f, "crow_bot_inbox", { cursor: first.data.cursor, limit: 1 });
  assert.deepEqual(second.data.messages.map((item) => item.text), ["ten"],
    "the same-millisecond row above the cut is still reachable");
  assert.equal(second.data.cursor, "p10.r0");
});

// The room query used to take `limit` rows and THEN drop the ones from senders who are not pinned, so a
// run of strangers' rows filled the window, was thrown away, and the cursor stood still. Filtering is
// now done in SQL (and includes only the pinned member's contact ids), so the page is filled with rows
// the bot may actually read.
test("a run of rows from senders who are not pinned cannot starve the page", async () => {
  const f = await fixture();
  const strangerId = await addContact(f.db, STRANGER);
  // limit + 5 strangers first, then the one row the bot is allowed to read.
  for (let i = 1; i <= 8; i += 1) {
    await addRoomMessage(f.db, {
      id: i, groupId: f.roomId, senderContactId: strangerId,
      content: `stranger ${i}`, createdAt: `2026-11-19 10:0${i % 10}:00`,
    });
  }
  await addRoomMessage(f.db, {
    id: 9, groupId: f.roomId, senderContactId: f.peerId,
    content: "the pinned one", createdAt: "2026-11-19 11:00:00",
  });

  const page = await doorCall(f, "crow_bot_inbox", { limit: 3 });
  assert.equal(page.ok, true, JSON.stringify(page));
  assert.deepEqual(page.data.messages.map((item) => item.text), ["the pinned one"],
    "the pinned member's row is found even though eight strangers' rows come first");
  assert.equal(page.data.cursor, "p0.r9");
});

// Every allow-listed room shares the ONE `r<id>` mark, so the room rows must be paged by ID across
// rooms. Sorting the merged set by time instead let one room's high-id row move the mark past a second
// room's still-unread low-id rows, which then never came back.
test("a shared room cursor never steps over a row in another allow-listed room", async () => {
  const f = await fixture();
  // A second room this bot may read, with the same pinned member.
  const second = await f.db.execute({
    sql: "INSERT INTO contact_groups (name, room_uid, host_crow_id, mode) VALUES ('Nest', ?, 'crow:me', 'addressed')",
    args: ["s".repeat(32)],
  });
  const secondRoomId = Number(second.lastInsertRowid);
  await f.db.execute({ sql: "INSERT INTO contact_group_members (group_id, contact_id) VALUES (?, ?)", args: [secondRoomId, f.peerId] });
  const written = acl.setSharingBotAclEntry(process.env.CROW_HOME, BOT, {
    contacts: [{ crow_id: PEER.crowId, secp256k1_pubkey: PEER.pubkey }],
    groups: [
      { id: f.roomId, members: [{ crow_id: PEER.crowId, secp256k1_pubkey: PEER.pubkey }] },
      { id: secondRoomId, members: [{ crow_id: PEER.crowId, secp256k1_pubkey: PEER.pubkey }] },
    ],
    rate: { per_hour: 20 },
  });
  assert.equal(written.ok, true);

  // The Den's rows hold the HIGH ids with the EARLIEST timestamps; the Nest's hold the LOW ids with the
  // latest. A time-ordered page takes the Den's 100..102 first, and the mark it produces (r102) is
  // above every Nest row — that is the skip this test pins.
  for (const [id, content] of [[5, "nest one"], [6, "nest two"], [7, "nest three"]]) {
    await addRoomMessage(f.db, { id, groupId: secondRoomId, senderContactId: f.peerId, content, createdAt: "2026-11-19 12:00:00" });
  }
  for (const [id, content] of [[100, "den one"], [101, "den two"], [102, "den three"]]) {
    await addRoomMessage(f.db, { id, groupId: f.roomId, senderContactId: f.peerId, content, createdAt: "2026-11-19 09:00:00" });
  }

  const seen = [];
  let cursor = null;
  for (let page = 0; page < 6; page += 1) {
    const out = await doorCall(f, "crow_bot_inbox", { ...(cursor ? { cursor } : {}), limit: 3 });
    assert.equal(out.ok, true, JSON.stringify(out));
    if (!out.data.messages.length) break;
    seen.push(...out.data.messages.map((item) => item.text));
    cursor = out.data.cursor;
  }
  assert.deepEqual(seen.slice().sort(),
    ["den one", "den three", "den two", "nest one", "nest three", "nest two"],
    "every row of both rooms is returned exactly once");
  assert.equal(new Set(seen).size, 6, "and none of them twice");
});

// `draft_updates` mark is compound — `(updated_at, id)` — because every write inside the same
// millisecond ties. With a bare `updated_at > mark` and a page cut at LIMIT, the drafts that shared the
// boundary millisecond were skipped forever.
test("draft_updates pages a shared millisecond, and never skips a draft inside it", async () => {
  const f = await fixture();
  const made = [];
  for (let i = 0; i < 3; i += 1) {
    const out = await store.createDraft(f.db, {
      conversationKind: "contact",
      conversationId: 100 + i,
      body: `draft ${i}`,
      recipients: [{ contactId: 100 + i, crowId: `crow:d${i}`, pubkey: PEER.pubkey }],
      origin: "bot", botId: BOT, botName: BOT_NAME, expectVersion: 0,
    }, { ...f.opts, now: NOW });
    assert.equal(out.ok, true, JSON.stringify(out));
    made.push(out.draft.id);
  }

  const seen = [];
  let cursor = null;
  for (let page = 0; page < 6; page += 1) {
    const out = await doorCall(f, "crow_bot_inbox", { ...(cursor ? { cursor } : {}), limit: 1 });
    assert.equal(out.ok, true, JSON.stringify(out));
    if (!out.data.draft_updates.length) break;
    seen.push(...out.data.draft_updates.map((update) => update.draft_id));
    cursor = out.data.cursor;
  }
  assert.deepEqual(seen.slice().sort(), made.slice().sort(), "all three drafts, at one millisecond each page");
  assert.equal(new Set(seen).size, 3, "and none reported twice");

  // The cursor is the old shape plus the id half (`p.r.d<ms>.i<draft id>`), and a cursor minted before
  // that half still parses — it restarts at its millisecond instead of skipping it.
  const all = await doorCall(f, "crow_bot_inbox", {});
  assert.equal(all.data.draft_updates.length, 3);
  assert.match(all.data.cursor, /^p0\.r0\.d1767225600000\.imsgd-[0-9a-f]{32}$/,
    "the mark names the millisecond AND the row it reached");
  const legacyMark = await doorCall(f, "crow_bot_inbox", { cursor: `p0.r0.d${NOW}` });
  assert.equal(legacyMark.ok, true, JSON.stringify(legacyMark));
  assert.equal(legacyMark.data.draft_updates.length, 3, "an id-less mark restarts at that millisecond");
});