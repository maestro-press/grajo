// `sent_by_bot` on the wire (bot-door plan, section 4 step 7): a bot's draft, sent by the OWNER, is
// attributed on the room transport by a fixed id in the envelope's payload — beside the visible
// `Sent by <bot> (bot)` first line, never instead of it.
//
// The 1:1 peer send is plain text, so there is no field to carry there; the fixed first line is the
// whole attribution (drafts-send.js's header says why an envelope would be read as a control message
// and never reach the chat). These tests pin the parts that do carry it: the room envelope itself, the
// operator's room send, and the id's flattening.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmScratch } from "./helpers/safe-rm.js";

const root = mkdtempSync(join(tmpdir(), "message-drafts-sent-by-bot-"));
process.env.CROW_DATA_DIR = root;
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;

const { createDbClient } = await import("../servers/db.js");
const { buildRoomMessageEnvelope } = await import("../servers/sharing/room-fanout.js");
const { sendOperatorRoomMessage } = await import("../servers/gateway/dashboard/panels/messages/room-send.js");
const { outboundText, sentByBotId } = await import("../servers/gateway/messages/drafts-send.js");

let db;
let roomId;

after(() => {
  if (db) { try { db.close(); } catch { /* already closed */ } }
  rmScratch(root);
});

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: root },
    stdio: "pipe",
    cwd: REPO,
  });
  db = createDbClient(join(root, "crow.db"));
  const contact = await db.execute({
    sql: `INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
          VALUES ('crow:peer', 'Peer', ?, ?, 'crow')`,
    args: ["02" + "a".repeat(64), "e".repeat(64)],
  });
  const room = await db.execute({
    sql: "INSERT INTO contact_groups (name, room_uid, host_crow_id, mode) VALUES ('Den', ?, 'crow:me', 'addressed')",
    args: ["r".repeat(32)],
  });
  roomId = Number(room.lastInsertRowid);
  await db.execute({
    sql: "INSERT INTO contact_group_members (group_id, contact_id) VALUES (?, ?)",
    args: [roomId, Number(contact.lastInsertRowid)],
  });
});

const params = {
  roomUid: "r".repeat(32), roomName: "Den", hostCrowId: "crow:me",
  msgUid: "m".repeat(32), author: { kind: "human", crow_id: "crow:me" }, text: "Hello den",
  addressedTo: [], ts: "2026-11-19T00:00:00.000Z",
};

test("the room envelope carries sent_by_bot when there is a bot, and omits the field otherwise", () => {
  const withBot = JSON.parse(buildRoomMessageEnvelope({ ...params, sentByBot: "hank" }));
  assert.equal(withBot.subtype, "room_message");
  assert.equal(withBot.payload.sent_by_bot, "hank");
  assert.equal(withBot.payload.text, "Hello den");

  const owner = JSON.parse(buildRoomMessageEnvelope(params));
  assert.equal(Object.hasOwn(owner.payload, "sent_by_bot"), false, "an owner's room message carries no marker");

  const blank = JSON.parse(buildRoomMessageEnvelope({ ...params, sentByBot: "   " }));
  assert.equal(Object.hasOwn(blank.payload, "sent_by_bot"), false);
});

test("a bot draft's send stamps the id; an owner's does not", () => {
  assert.equal(sentByBotId({ origin: "bot", botId: "hank" }), "hank");
  assert.equal(sentByBotId({ origin: "owner", botId: null }), null);
  // A hostile id cannot smuggle whitespace or control characters into a payload.
  assert.equal(sentByBotId({ origin: "bot", botId: "hank\nsent_by_bot:other" }), "hanksent_by_bot:other");
  assert.equal(sentByBotId({ origin: "bot", botId: "\u202e" }), "\u202e", "a format char is not whitespace, but it is one line");
});

test("the operator's room send fans out an envelope that names the bot whose draft it was", async () => {
  const sent = [];
  const nostrManager = { sendControl: async (contact, envelope) => { sent.push(JSON.parse(envelope)); return { eventId: "e" }; } };
  const result = await sendOperatorRoomMessage({
    db,
    managers: { identity: { crowId: "crow:me", displayName: "Me" }, nostrManager },
    groupId: roomId,
    message: "Sent by Hank (bot)\nHello den",
    sentByBot: "hank",
  });
  assert.equal(result.ok, true);
  assert.equal(sent.length, 1);
  assert.equal(sent[0].payload.sent_by_bot, "hank");
  assert.equal(sent[0].payload.text, "Sent by Hank (bot)\nHello den", "the visible line still rides as the text");

  const owner = [];
  await sendOperatorRoomMessage({
    db,
    managers: { identity: { crowId: "crow:me", displayName: "Me" }, nostrManager: { sendControl: async (c, e) => { owner.push(JSON.parse(e)); } } },
    groupId: roomId,
    message: "Hello den",
  });
  assert.equal(Object.hasOwn(owner[0].payload, "sent_by_bot"), false);
});

test("the visible first line is unchanged by the new field", () => {
  const draft = { origin: "bot", botId: "hank", botName: "Hank" };
  assert.equal(outboundText(draft, "Hello"), "Sent by Hank (bot)\nHello");
  assert.equal(outboundText({ origin: "owner" }, "Hello"), "Hello");
});

// The plain contact-group fan-out (`crow_send_group_message`) once carried a `sent_by_bot` spread fed by
// an `internalSentByBot` construction option — and NO caller ever set it. The field is the room
// transport's (`sendOperatorRoomMessage` → `buildRoomMessageEnvelope`, argued in room-send.js and
// drafts-send.js); a dead option beside it was a second, unexercised way to stamp attribution, which
// is exactly the kind of seam a later caller sets by accident.
test("`sent_by_bot` belongs to the room transport alone: the group fan-out has no attribution option", () => {
  const src = readFileSync(new URL("../servers/sharing/tools/messaging.js", import.meta.url), "utf8");
  assert.equal(/internalSentByBot/.test(src), false, "the option no caller set is gone");
  assert.equal(/\bsent_by_bot\s*:/.test(src), false, "and the group_message payload has no such key");

  // The room path keeps it — same name, one owner.
  const room = readFileSync(new URL("../servers/sharing/room-fanout.js", import.meta.url), "utf8");
  assert.match(room, /sent_by_bot/);
  const roomSend = readFileSync(new URL("../servers/gateway/dashboard/panels/messages/room-send.js", import.meta.url), "utf8");
  assert.match(roomSend, /sentByBot/);
});