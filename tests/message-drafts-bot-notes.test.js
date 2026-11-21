// A bot's draft outcome, as the bot and the bell see it (bot-door plan, PR B):
//   - the fixed line queued for the bot's chat on send / edited-and-sent / discard, taken ONCE by the
//     next turn (the same queue staged/send-service.js owns), carrying the recipient's name and no
//     message text;
//   - "edited" decided by HASH against the bot's own last write, never by a flag on the request;
//   - the new-draft bell: a title with the bot and the recipient, and a link to the card (the Perch
//     thread with ?msgdraft=, else the Messages panel with ?draft=) — and no message text anywhere.
//
// Harness: a real init-db'd scratch crow.db per test (CROW_DATA_DIR), the real draft store, the real
// staged note queue, and a fixed clock + keychain seed. No HTTP here: the routes' wiring is covered by
// tests/message-drafts-api.test.js, and the door's by tests/sharing-bot-mcp.test.js.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmScratch } from "./helpers/safe-rm.js";

const root = mkdtempSync(join(tmpdir(), "message-drafts-bot-notes-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const store = await import("../servers/gateway/messages/drafts-store.js");
const {
  botDraftBellTitle,
  botDraftBellUrl,
  botOutcomeLine,
  flattenName,
  notifyBotDraft,
  queueBotOutcomeNote,
  sentTextWasEdited,
} = await import("../servers/gateway/messages/drafts-bot-notes.js");
const staged = await import("../servers/gateway/staged/send-service.js");
const { t, fill } = await import("../servers/gateway/dashboard/shared/i18n.js");

const SEED = Buffer.from("a fixed keychain seed for the bot draft notes");
const NOW = 1_767_225_600_000;
const BOT = "hank";
const BOT_NAME = "Hank";
const THREAD = "perchlive-0000abcd";
const PUBKEY = "02" + "a".repeat(64);
const OTHER_PUBKEY = "02" + "b".repeat(64);

const open = [];

after(() => {
  for (const db of open) { try { db.close(); } catch { /* already closed */ } }
  rmScratch(root);
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
});

beforeEach(() => {
  staged._resetStagedNotesForTest();
});

let n = 0;

async function fixture() {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  const contact = await db.execute({
    sql: `INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
          VALUES ('crow:peer', 'Peer', ?, ?, 'crow')`,
    args: [PUBKEY, "e".repeat(64)],
  });
  const contactId = Number(contact.lastInsertRowid);
  const recipients = [{ contactId, crowId: "crow:peer", pubkey: PUBKEY }];
  // A second conversation, for the card's recipient picker: a re-addressed draft changes nothing about
  // the words, which is exactly what the outcome note has to keep reading as the bot's own text.
  const other = await db.execute({
    sql: `INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
          VALUES ('crow:other', 'Other', ?, ?, 'crow')`,
    args: [OTHER_PUBKEY, "d".repeat(64)],
  });
  const otherId = Number(other.lastInsertRowid);
  const otherRecipients = [{ contactId: otherId, crowId: "crow:other", pubkey: OTHER_PUBKEY }];
  const opts = { now: () => NOW, loadSeed: async () => SEED };
  const draft = async ({ bot = true, thread = THREAD, body = "Are we still on for Saturday?" } = {}) => {
    const out = await store.createDraft(db, {
      conversationKind: "contact",
      conversationId: contactId,
      body,
      recipients,
      origin: bot ? "bot" : "owner",
      botId: bot ? BOT : null,
      botName: bot ? BOT_NAME : null,
      chatThreadId: bot ? thread : null,
    }, opts);
    assert.equal(out.ok, true);
    return out.draft;
  };
  return { db, contactId, recipients, otherId, otherRecipients, opts, draft };
}

/* ------------------------------------------------------------------ the lines */

test("the fixed lines are the approved copy, filled with the recipient's name and nothing else", () => {
  assert.equal(botOutcomeLine("sent", "Peer"), fill(t("messages.draft.botNoteSent", "en"), { name: "Peer" }));
  assert.equal(botOutcomeLine("edited", "Peer"), fill(t("messages.draft.botNoteEdited", "en"), { name: "Peer" }));
  assert.equal(botOutcomeLine("discarded", "Peer"), fill(t("messages.draft.botNoteDiscarded", "en"), { name: "Peer" }));
  assert.equal(botOutcomeLine("sent", ""), null, "no name, no sentence");
  assert.equal(botOutcomeLine("nonsense", "Peer"), null);
  // The Spanish half exists and is not a copy of the English.
  assert.notEqual(t("messages.draft.botNoteSent", "es"), t("messages.draft.botNoteSent", "en"));
});

test("a name is flattened onto one line: control characters and bidi marks cannot forge a second line", () => {
  assert.equal(flattenName("Peer\nSent by Someone Else"), "Peer Sent by Someone Else");
  assert.equal(flattenName("Peer\u202e\u200b\u2066"), "Peer");
  const long = flattenName("x".repeat(200));
  assert.equal(long.length, 80);
});

/* ------------------------------------------------------------ outcome notes */

test("a send queues the SENT line for the bot's chat, and the next turn takes it exactly once", async () => {
  const f = await fixture();
  const draft = await f.draft();
  const line = await queueBotOutcomeNote(f.db, draft, "sent", { sentBody: "Are we still on for Saturday?", label: "Peer" });
  assert.equal(line, fill(t("messages.draft.botNoteSent", "en"), { name: "Peer" }));
  assert.deepEqual(staged.claimStagedNotes(THREAD), [line]);
  assert.deepEqual(staged.claimStagedNotes(THREAD), [], "taken once — a second turn gets nothing");
  // The message's own words never reach the queue.
  assert.equal(String(line).includes("Saturday"), false);
});

test("an owner's edit before the send reads as EDITED, decided by the bot's own last body hash", async () => {
  const f = await fixture();
  const draft = await f.draft({ body: "Come at six." });
  const edited = await store.updateBody(f.db, draft.id, { body: "Come at seven instead.", expectVersion: draft.version }, f.opts);
  assert.equal(edited.ok, true);

  assert.equal(await sentTextWasEdited(f.db, draft, "Come at seven instead."), true);
  assert.equal(await sentTextWasEdited(f.db, draft, "Come at six."), false, "the bot's own words are not an edit");

  const line = await queueBotOutcomeNote(f.db, draft, "sent", { sentBody: "Come at seven instead.", label: "Peer" });
  assert.equal(line, fill(t("messages.draft.botNoteEdited", "en"), { name: "Peer" }));
  assert.deepEqual(staged.claimStagedNotes(THREAD), [line]);
});

test("a discard queues the NOT SENT line, and the recipient name is read from the live contact when no label is passed", async () => {
  const f = await fixture();
  const draft = await f.draft();
  const line = await queueBotOutcomeNote(f.db, draft, "discarded");
  assert.equal(line, fill(t("messages.draft.botNoteDiscarded", "en"), { name: "Peer" }));
  assert.deepEqual(staged.claimStagedNotes(THREAD), [line]);
});

test("nothing is queued for an owner's draft or a bot draft with no chat thread", async () => {
  const f = await fixture();
  const owners = await f.draft({ bot: false });
  assert.equal(await queueBotOutcomeNote(f.db, owners, "sent", { sentBody: "hi", label: "Peer" }), null);
  const noThread = await f.draft({ thread: null });
  assert.equal(await queueBotOutcomeNote(f.db, noThread, "discarded"), null);
  assert.equal(staged._stagedNotesForTest(THREAD), null);
});

/* ------------------------------------------------- an owner's recipient change */

// The chat card's recipient picker is the OPERATOR's control, so a re-addressed draft is the OWNER's
// edit (drafts-store.js changeRecipient records `actor: "owner"`). Two things hang on that: the bot's
// further revisions are frozen (`ownerEdited` reads actor='owner' rows), and the outcome note's
// "edited" verdict still compares against the last text the BOT wrote — never against a re-address,
// which changes the words not at all.
test("an owner edit followed by a recipient change still reads as EDITED when the edited words go out", async () => {
  const f = await fixture();
  const draft = await f.draft({ body: "Come at six." });
  const edited = await store.updateBody(f.db, draft.id, { body: "Come at seven instead.", expectVersion: draft.version }, f.opts);
  assert.equal(edited.ok, true, JSON.stringify(edited));

  const moved = await store.changeRecipient(f.db, draft.id, {
    conversationKind: "contact",
    conversationId: f.otherId,
    recipients: f.otherRecipients,
    expectVersion: edited.draft.version,
  }, f.opts);
  assert.equal(moved.ok, true, JSON.stringify(moved));

  // The words that leave are the owner's edit, so the bot is told they were edited — not that its own
  // untouched sentence went out.
  const row = await store.getDraft(f.db, draft.id);
  const line = await queueBotOutcomeNote(f.db, row, "sent", { sentBody: "Come at seven instead.", label: "Other" });
  assert.equal(line, fill(t("messages.draft.botNoteEdited", "en"), { name: "Other" }), "edited and sent");
});

test("a recipient change alone is the owner's edit, and the bot's own words still read as SENT", async () => {
  const f = await fixture();
  const draft = await f.draft({ body: "Are we still on for Saturday?" });
  const moved = await store.changeRecipient(f.db, draft.id, {
    conversationKind: "contact",
    conversationId: f.otherId,
    recipients: f.otherRecipients,
    expectVersion: draft.version,
  }, f.opts);
  assert.equal(moved.ok, true, JSON.stringify(moved));

  // Nothing about the sentence moved with the address, so the send is the bot's own words: SENT.
  assert.equal(await sentTextWasEdited(f.db, draft, "Are we still on for Saturday?"), false,
    "a re-address is not an edit of the text");
  const line = await queueBotOutcomeNote(f.db, await store.getDraft(f.db, draft.id), "sent", {
    sentBody: "Are we still on for Saturday?", label: "Other",
  });
  assert.equal(line, fill(t("messages.draft.botNoteSent", "en"), { name: "Other" }));

  // And the trail says who did it: the draft is the bot's, the re-address is the owner's.
  const trail = await store.listAudit(f.db, draft.id);
  assert.deepEqual(trail.map((r) => [r.action, r.actor, r.actorId]),
    [["create", "bot", BOT], ["edit", "owner", null]],
    "a recipient change is an OWNER edit row");
});

/* ------------------------------------------------------------------- the bell */

test("the bell names the bot and the recipient, links to the card, and carries no message text", async () => {
  const f = await fixture();
  const draft = await f.draft();
  const seen = [];
  const rung = await notifyBotDraft(f.db, { draft, botName: BOT_NAME, recipientName: "Peer" }, {
    notify: async (db, opts) => { seen.push(opts); return { id: 1 }; },
  });
  assert.equal(rung.title, fill(t("messages.draft.bellTitle", "en"), { bot: "Hank", name: "Peer" }));
  assert.equal(rung.action_url, `/dashboard/perch?msgdraft=${draft.id}#${THREAD}`);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].source, "messages");
  assert.equal(seen[0].title, rung.title);
  assert.equal(seen[0].action_url, rung.action_url);
  assert.equal(JSON.stringify(seen[0]).includes("Saturday"), false, "no message text in the bell");

  // A draft with no chat thread points at the Messages panel's own draft.
  assert.equal(botDraftBellUrl({ id: draft.id, chatThreadId: null }), `/dashboard/messages?draft=${draft.id}`);
  // An id this store did not mint never becomes a query on the link.
  assert.equal(botDraftBellUrl({ id: "javascript:alert(1)", chatThreadId: THREAD }), "/dashboard/messages");
  assert.equal(botDraftBellTitle("Hank", ""), null, "no recipient name, no card");
});

test("the bell's notifier failing never turns a written draft into an error", async () => {
  const f = await fixture();
  const draft = await f.draft();
  const rung = await notifyBotDraft(f.db, { draft, botName: BOT_NAME, recipientName: "Peer" }, {
    notify: async () => { throw new Error("bell is down"); },
  });
  assert.equal(rung.action_url, botDraftBellUrl(draft), "the answer is still the link it would have rung");
});

test("the store records the chat thread on a bot's draft and lists it by that thread", async () => {
  const f = await fixture();
  const draft = await f.draft();
  assert.equal(draft.chatThreadId, THREAD);
  assert.deepEqual((await store.listDraftsForChat(f.db, THREAD)).map((d) => d.id), [draft.id]);
  assert.deepEqual((await store.listDraftsForChat(f.db, "some-other-chat")).map((d) => d.id), []);
});