/**
 * The message draft card in a Perch chat (sharing-bot door plan, PR B):
 * servers/gateway/dashboard/perch-hub/msg-draft-card.js, spliced into the hub client.
 *
 * Harness: the whole emitted Perch client runs in a vm against a fake DOM and a scripted fetch
 * (tests/fixtures/perch-hub-vm.mjs), so these tests exercise the real IIFE — the list read, the
 * draft read, the autosave debounce, Send, Discard, the `msg_draft` frame and `?msgdraft=` — with no
 * browser and no server.
 *
 * The rules this file pins, beyond "it renders":
 *  - the card is built from the fetched answer ONLY, through textContent: a recipient, a bot name and
 *    a body that look like markup are text;
 *  - the fixed "Sent by <bot> (bot)" line is the approved copy, greyed and NOT a field;
 *  - every write carries the version the card was drawn from, and a 409 `changed` never overwrites —
 *    it says "This draft changed somewhere else." and offers Reload;
 *  - a draft whose seal does not verify shows the unverified sentence and NO Send;
 *  - the recipient picker offers exactly the bot's allow-list;
 *  - the module emits no backtick and no dollar-brace (it is spliced inside a template literal), in
 *    both languages, and the whole client still compiles.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mountHub, openChatSession, findByClass, stdFetch, makeResponse, FakeEventSource } from "./fixtures/perch-hub-vm.mjs";
import { perchMsgDraftCardJs } from "../servers/gateway/dashboard/perch-hub/msg-draft-card.js";
import { t, fill } from "../servers/gateway/dashboard/shared/i18n.js";

const SID = "perchlive-aaaaaaaa";
const SECOND = "perchlive-bbbbbbbb";
const ID = "msgd-" + "a".repeat(32);
const TWO_SESSIONS = {
  birds: [{
    id: "r4",
    name: "R4 Assistant",
    perch_attached: true,
    state: "working",
    sessions: [
      { sessionId: SID, state: "awake", cardId: null, pendingUi: false, projectId: 7 },
      { sessionId: SECOND, state: "awake", cardId: null, pendingUi: false, projectId: 7 },
    ],
  }],
};

/** One draft row as the owner's draft route answers it (store columns, camel-cased). */
const draft = (over = {}) => ({
  id: ID,
  conversationKind: "contact",
  conversationId: 1,
  origin: "bot",
  botId: "hank",
  botName: "Hank",
  chatThreadId: SID,
  projectId: null,
  state: "open",
  version: 1,
  body: "Hello Sam",
  recipients: [{ contactId: 1, crowId: "crow:peer", pubkey: "02" + "a".repeat(64) }],
  sentAt: null,
  sentMessageId: null,
  failReason: null,
  label: "Sam",
  createdAt: 1,
  updatedAt: 1,
  ...over,
});

/** The allow-list the route resolved for this bot: two contacts, one room. */
const allowedFor = () => ({
  contacts: [
    { conversationId: 1, crowId: "crow:peer", name: "Sam", blocked: false },
    { conversationId: 2, crowId: "crow:cara", name: "Cara", blocked: false },
  ],
  groups: [{ conversationId: 7, name: "The Den" }],
});

/** The whole answer of GET /dashboard/messages/api/drafts/:id. */
const payload = (over = {}) => ({
  draft: draft(over.draft),
  audit: [],
  seal_ok: over.seal_ok === undefined ? true : over.seal_ok,
  allowed: over.allowed === undefined ? allowedFor() : over.allowed,
});

const tick = () => new Promise((r) => setTimeout(r, 0));
async function settle(times = 6) { for (let i = 0; i < times; i += 1) await tick(); }

/**
 * Mount the real client with a scripted draft surface. `state.drafts` maps a draft id to the answer
 * its GET returns (a function is called per read); `state.list` is the chat's ids; `state.reply`
 * answers the next write.
 */
async function mount(state = {}) {
  const calls = [];
  const impl = (method, path, opts) => {
    const body = opts && opts.body ? JSON.parse(opts.body) : null;
    calls.push({ method, path, body });
    if (path === "/roost" && state.roost) return makeResponse(200, state.roost);
    if (/\/interactive\/[^/]+\/msg-drafts$/.test(path) && method === "GET") {
      const list = state.list !== undefined
        ? (typeof state.list === "function" ? state.list() : state.list)
        : Object.keys(state.drafts || {});
      return makeResponse(200, { drafts: list.map((id) => ({ id })) });
    }
    const m = /^\/dashboard\/messages\/api\/drafts\/(msgd-[0-9a-f]{32})(?:\/([a-z-]+))?$/.exec(path);
    if (m) {
      const id = m[1];
      if (method === "GET") {
        const answer = (state.drafts || {})[id] || payload();
        return makeResponse(200, typeof answer === "function" ? answer() : answer);
      }
      const reply = typeof state.reply === "function" ? state.reply(m[2], id, body) : state.reply;
      return makeResponse(reply ? reply.status : 200, reply ? (reply.json === undefined ? { ok: true } : reply.json) : { ok: true });
    }
    return stdFetch()(method, path);
  };
  const hub = await mountHub({ fetchImpl: impl, lang: state.lang || "en" });
  return { hub, calls };
}

async function open(hub, sid = SID) {
  await openChatSession(hub, sid);
  await settle();
}

function all(hub, cls) {
  const out = [];
  const walk = (n) => {
    if (String(n.className || "").split(" ").includes(cls)) out.push(n);
    for (const c of n.children || []) walk(c);
  };
  walk(hub.els["perch-transcript"]);
  return out;
}
const text = (hub, cls) => (all(hub, cls)[0] || {}).textContent || "";
const reads = (calls) => calls.filter((c) => c.method === "GET" && c.path.indexOf("/dashboard/messages/api/drafts/") === 0);
const writes = (calls) => calls.filter((c) => c.method !== "GET");
const card = (hub) => findByClass(hub.els["perch-transcript"], "mmsg-card");

/** The autosave's own timer: 800 ms after the last keystroke. */
function autosaveTimerIds(hub) {
  return [...hub.timerDelays].filter(([, delay]) => delay === 800).map(([id]) => id);
}
function fireAutosave(hub) {
  for (const id of autosaveTimerIds(hub)) {
    const fn = hub.timers.get(id);
    if (fn) fn();
  }
}

/** Type into the card's textarea the way a person does: set the value, fire the input handler. */
function type(hub, value) {
  const box = findByClass(card(hub), "mmsg-body");
  assert.ok(box, "the card has an editable textarea");
  box.value = value;
  box.oninput();
  return box;
}

/* ------------------------------------------------------------------ static */

test("the module output carries no backtick and no dollar-brace, and the whole client compiles", async () => {
  const vm = await import("node:vm");
  const { perchHubJs } = await import("../servers/gateway/dashboard/perch-hub/client.js");
  for (const lang of ["en", "es"]) {
    const js = perchMsgDraftCardJs(lang);
    assert.equal(js.includes("`"), false, `${lang}: no backtick`);
    assert.equal(js.includes("${"), false, `${lang}: no dollar-brace`);
    assert.doesNotThrow(() => new vm.Script(perchHubJs(lang)), `${lang}: the emitted client compiles`);
    assert.ok(perchHubJs(lang).includes("mmsgFrame"), `${lang}: the card is spliced into the client`);
  }
});

/* The one draft sentence that is deliberately identical in both languages: `sentByLine` is a PREVIEW
   of the line that is actually sent, and the server builds that line in English (drafts-send.js
   SENT_BY_PREFIX) — the wire text does not translate. It is on the global parity test's IDENTICAL_OK
   for the same reason, and that list's anti-rot check keeps this one honest. */
const SAME_IN_SPANISH = new Set(["messages.draft.sentByLine"]);

test("no i18n key is printed, and every card sentence has its own Spanish", () => {
  for (const key of ["messages.draft.cardHead", "messages.draft.to", "messages.draft.sentByLine",
    "messages.draft.send", "messages.draft.discard", "messages.draft.discardConfirm",
    "messages.draft.saved", "messages.draft.saving", "messages.draft.changedElsewhere",
    "messages.draft.reload", "messages.draft.sentReceipt", "messages.draft.discardedReceipt",
    "messages.draft.unverified", "messages.draft.errPubkey", "messages.draft.errBlocked",
    "messages.draft.errNotAllowed", "messages.draft.errGroupChanged", "messages.draft.errDraftWaiting",
    "messages.draft.errSendFailed"]) {
    assert.ok(t(key, "en").length > 0, key + " (en)");
    if (SAME_IN_SPANISH.has(key)) {
      assert.equal(t(key, "es"), t(key, "en"), key + ": the sent line goes out in English, so the preview is English in both languages");
    } else {
      assert.notEqual(t(key, "en"), t(key, "es"), key + ": the Spanish is its own sentence");
    }
    const js = perchMsgDraftCardJs("en") + perchMsgDraftCardJs("es");
    assert.equal(js.includes(key), false, key + ": the key itself is never printed");
  }
});

/* ------------------------------------------------------------------ render */

test("the card is built from its own read, through textContent, with the fixed sent-by line", async () => {
  const { hub } = await mount({
    drafts: {
      [ID]: payload({
        draft: { body: "Hello <b>Sam</b>,\nsee you at 6", botName: "<i>Hank</i>", label: "<u>Sam</u>" },
        allowed: { contacts: [{ conversationId: 1, crowId: "crow:peer", name: "<script>x</script>", blocked: false }], groups: [] },
      }),
    },
  });
  await open(hub);

  assert.ok(card(hub), "the card is in the transcript");
  assert.equal(text(hub, "mmsg-head"), fill(t("messages.draft.cardHead", "en"), { bot: "<i>Hank</i>" }),
    "a bot name that looks like markup is text");
  assert.equal(text(hub, "mmsg-label"), t("messages.draft.to", "en"));
  assert.equal(text(hub, "mmsg-sentby"), fill(t("messages.draft.sentByLine", "en"), { bot: "<i>Hank</i>" }),
    "the approved fixed line, with the (bot) marker");
  const box = findByClass(card(hub), "mmsg-body");
  assert.equal(box.value, "Hello <b>Sam</b>,\nsee you at 6", "the body is the textarea's value, not markup");
  assert.equal(box.children.length, 0, "nothing was parsed into the field");
  /* The picker's option text is text too. */
  const picker = findByClass(card(hub), "mmsg-recipient-picker");
  assert.equal(picker.children[0].textContent, "<script>x</script>");
  /* No page markup was created from any of it. */
  assert.equal(findByClass(card(hub), "script"), null);
  assert.equal(findByClass(card(hub), "b"), null);
});

test("the recipient picker offers exactly the bot's allow-list, with the draft's own recipient selected", async () => {
  const { hub } = await mount({ drafts: { [ID]: payload() } });
  await open(hub);
  const picker = findByClass(card(hub), "mmsg-recipient-picker");
  assert.ok(picker, "a bot's draft gets a picker, not a chip");
  assert.deepEqual(picker.children.map((o) => o.value), ["contact:1", "contact:2", "room:7"],
    "the ACL entries and nothing else");
  assert.deepEqual(picker.children.map((o) => o.textContent), ["Sam", "Cara", "The Den"]);
  assert.equal(picker.children[0].getAttribute("selected"), "selected", "the draft's own recipient");
  assert.equal(findByClass(card(hub), "mmsg-chip"), null, "no chip beside the picker");
});

test("an owner's draft shows a chip and no sent-by line: nothing claims a bot wrote it", async () => {
  const { hub } = await mount({
    drafts: { [ID]: payload({ draft: { origin: "owner", botId: null, botName: null }, allowed: null }) },
  });
  await open(hub);
  assert.equal(findByClass(card(hub), "mmsg-recipient-picker"), null, "no picker for the owner's own words");
  assert.equal(text(hub, "mmsg-chip"), "Sam", "a plain chip names the recipient");
  assert.equal(findByClass(card(hub), "mmsg-sentby"), null, "no 'Sent by' line for the owner");
});

test("a recipient the bot may no longer write to is shown, not hidden, and the picker never re-selects", async () => {
  const { hub } = await mount({
    drafts: { [ID]: payload({ allowed: { contacts: [{ conversationId: 2, crowId: "crow:cara", name: "Cara", blocked: false }], groups: [] } }) },
  });
  await open(hub);
  const picker = findByClass(card(hub), "mmsg-recipient-picker");
  const first = picker.children[0];
  assert.equal(first.value, "", "the draft's own (no longer allowed) recipient is the selected entry");
  assert.equal(first.textContent, "Sam", "named by the read, never by the picker's own invention");
  assert.equal(first.disabled, true, "and it cannot be picked again");
  assert.deepEqual(picker.children.slice(1).map((o) => o.textContent), ["Cara"], "the allow-list as choices");
});

test("a draft's sent-by line is the SERVER's flattened name, so a bot called 'Hank (bot)' reads as the wire does", async () => {
  // The bot's own name carries a `(bot)`. The wire flattens it before appending the fixed marker
  // (drafts-send.js sentByBotName → `Sent by Hank (bot)`), and the card must promise exactly that —
  // drawing the raw name would print `Sent by Hank (bot) (bot)` over a message that does not say so.
  const { hub } = await mount({
    drafts: { [ID]: payload({ draft: { botName: "Hank (bot)", sent_by_name: "Hank" } }) },
  });
  await open(hub);

  const line = text(hub, "mmsg-sentby");
  assert.equal(line, "Sent by Hank (bot)", "the line the recipient will read");
  assert.equal(line, fill(t("messages.draft.sentByLine", "en"), { bot: "Hank" }));
  assert.equal((String(line).match(/\(bot\)/gi) || []).length, 1, "one marker, the code's — never two");

  // The card still names the bot itself (the heading is not the attribution line).
  assert.equal(text(hub, "mmsg-head"), fill(t("messages.draft.cardHead", "en"), { bot: "Hank (bot)" }));
});

test("a recipient the target conversation already has a draft in says so, and never reads as a lost save", async () => {
  // The route answers 409 owner_draft_open when the conversation the picker chose already holds an open
  // draft. That has its own approved sentence in both languages (send or discard the draft that is
  // already there) — never "changed somewhere else" (nothing about this row moved, and Reload would
  // fix nothing) and never the "not sent, try again" copy (nothing was attempted).
  for (const lang of ["en", "es"]) {
    const { hub } = await mount({
      lang,
      drafts: { [ID]: payload() },
      reply: { status: 409, json: { error: "owner_draft_open" } },
    });
    await open(hub);
    const picker = findByClass(card(hub), "mmsg-recipient-picker");
    picker.value = "contact:2";
    picker.onchange();
    await settle();

    assert.equal(text(hub, "mmsg-status"), t("messages.draft.errDraftWaiting", lang), `owner_draft_open (${lang})`);
    assert.notEqual(text(hub, "mmsg-status"), t("messages.draft.changedElsewhere", lang),
      "nothing about this row moved, so the row did not change somewhere else");
    assert.notEqual(text(hub, "mmsg-status"), t("messages.draft.errSendFailed", lang));
    assert.equal(findByClass(card(hub), "mmsg-reload"), null, "and nothing offers a Reload that would fix nothing");
  }
});

/* ---------------------------------------------------------------- autosave */

test("typing autosaves through the draft route with the version the card was drawn from", async () => {
  const { hub, calls } = await mount({
    drafts: { [ID]: payload() },
    reply: { status: 200, json: { draft: draft({ version: 2, body: "Hello Sam, Tuesday" }) } },
  });
  await open(hub);
  const box = type(hub, "Hello Sam, Tuesday");
  assert.equal(text(hub, "mmsg-status"), "", "nothing is written before the pause");

  fireAutosave(hub);
  await settle();
  assert.equal(text(hub, "mmsg-status"), t("messages.draft.saved", "en"));
  const patch = calls.find((c) => c.method === "PATCH");
  assert.equal(patch.path, "/dashboard/messages/api/drafts/" + ID + "/body");
  assert.deepEqual(patch.body, { body: "Hello Sam, Tuesday", expectVersion: 1 });

  /* The next keystroke posts the version the answer handed back, not the one it was drawn from. */
  box.value = "Hello Sam, Tuesday at ten";
  box.oninput();
  fireAutosave(hub);
  await settle();
  assert.deepEqual(calls.filter((c) => c.method === "PATCH")[1].body,
    { body: "Hello Sam, Tuesday at ten", expectVersion: 2 });
});

test("a lost compare-and-set says so and offers Reload instead of overwriting", async () => {
  let readsSoFar = 0;
  const { hub, calls } = await mount({
    drafts: {
      [ID]: () => {
        readsSoFar += 1;
        return readsSoFar === 1
          ? payload()
          : payload({ draft: { version: 3, body: "the other tab's words" } });
      },
    },
    reply: { status: 409, json: { error: "changed" } },
  });
  await open(hub);
  type(hub, "my own words");
  fireAutosave(hub);
  await settle();
  assert.equal(text(hub, "mmsg-status"), t("messages.draft.changedElsewhere", "en"));
  const reload = findByClass(card(hub), "mmsg-reload");
  assert.ok(reload, "Reload is offered");
  assert.equal(reload.textContent, t("messages.draft.reload", "en"));

  const before = reads(calls).length;
  reload.onclick();
  await settle();
  assert.equal(reads(calls).length, before + 1, "Reload reads the row again");
  assert.equal(findByClass(card(hub), "mmsg-body").value, "the other tab's words",
    "and the field now holds what the server holds");
});

test("a frame carrying newer words does not clobber unsaved local ones", async () => {
  const { hub, calls } = await mount({ list: [ID], drafts: { [ID]: payload() } });
  await open(hub);
  type(hub, "unsaved local words");
  const es = FakeEventSource.instances[FakeEventSource.instances.length - 1];

  const before = reads(calls).length;
  es._serverFrame("msg_draft", { type: "msg_draft", id: ID });
  await settle();
  assert.equal(reads(calls).length, before + 1, "the frame re-reads the draft");
  assert.equal(findByClass(card(hub), "mmsg-body").value, "unsaved local words",
    "the person's own unsaved words are still there");
  assert.equal(text(hub, "mmsg-status"), "", "and nothing is claimed about a save");
});

/* -------------------------------------------------------------------- send */

test("Send sends exactly the text on screen, then the card is a one-line receipt", async () => {
  let sent = false;
  const { hub, calls } = await mount({
    list: () => (sent ? [] : [ID]),
    drafts: { [ID]: () => (sent
      ? payload({ draft: { state: "sent", sentAt: 5 } })
      : payload()) },
    reply: () => {
      sent = true;
      return { status: 200, json: { ok: true, draft: draft({ state: "sent", sentAt: 5 }) } };
    },
  });
  await open(hub);
  type(hub, "Hello Sam, Tuesday");
  findByClass(card(hub), "mmsg-send").onclick();
  await settle();

  const post = writes(calls).find((c) => c.path.endsWith("/send"));
  assert.deepEqual(post.body, { body: "Hello Sam, Tuesday", expectVersion: 1 },
    "what leaves is what the person saw, with the version it was drawn from");
  assert.equal(text(hub, "mmsg-receipt"), fill(t("messages.draft.sentReceipt", "en"), { name: "Sam" }));
  assert.equal(findByClass(card(hub), "mmsg-send"), null, "a receipt has nothing to press");
  assert.equal(all(hub, "mmsg-card").length, 1, "one card, not two");
});

test("a send's refusal codes each show their approved sentence, in both languages", async () => {
  const cases = [
    ["pubkey_changed", "messages.draft.errPubkey", { name: "Sam" }],
    ["blocked", "messages.draft.errBlocked", { name: "Sam" }],
    ["not_allowed", "messages.draft.errNotAllowed", { bot: "Hank", name: "Sam" }],
    ["group_changed", "messages.draft.errGroupChanged", null],
    ["recipients_changed", "messages.draft.errGroupChanged", null],
    ["send_failed", "messages.draft.errSendFailed", null],
    ["delivery_failed", "messages.draft.errSendFailed", null],
  ];
  for (const [code, key, vars] of cases) {
    for (const lang of ["en", "es"]) {
      const { hub } = await mount({
        lang,
        drafts: { [ID]: payload() },
        reply: { status: 502, json: { error: code } },
      });
      await open(hub);
      findByClass(card(hub), "mmsg-send").onclick();
      await settle();
      const want = vars ? fill(t(key, lang), vars) : t(key, lang);
      assert.equal(text(hub, "mmsg-status"), want, `${code} (${lang})`);
    }
  }
});

test("a draft whose seal does not verify says so and has no Send at all", async () => {
  const { hub } = await mount({ drafts: { [ID]: payload({ seal_ok: false }) } });
  await open(hub);
  assert.equal(text(hub, "mmsg-unverified"), t("messages.draft.unverified", "en"));
  assert.equal(findByClass(card(hub), "mmsg-send"), null, "nothing to press that the server would refuse");
  assert.ok(findByClass(card(hub), "mmsg-discard"), "the sentence says to discard it, so Discard is there");
  assert.equal(findByClass(card(hub), "mmsg-body"), null, "and nothing to edit: the row cannot be sent");
  assert.equal(findByClass(card(hub), "mmsg-card").getAttribute("aria-label"),
    fill(t("messages.draft.cardHead", "en"), { bot: "Hank" }), "the card still names the bot");
});

/* ----------------------------------------------------------------- discard */

test("Discard asks first: a declined confirmation writes nothing, a given one leaves the receipt", async () => {
  let discarded = false;
  const { hub, calls } = await mount({
    list: () => (discarded ? [] : [ID]),
    drafts: { [ID]: () => (discarded ? payload({ draft: { state: "discarded" } }) : payload()) },
    reply: () => {
      discarded = true;
      return { status: 200, json: { ok: true, draft: draft({ state: "discarded" }) } };
    },
  });
  await open(hub);

  hub.sandbox.confirm = () => false;
  findByClass(card(hub), "mmsg-discard").onclick();
  await settle();
  assert.equal(writes(calls).length, 0, "a declined confirmation posts nothing");

  hub.sandbox.confirm = (message) => {
    assert.equal(message, t("messages.draft.discardConfirm", "en"), "the approved confirmation copy");
    return true;
  };
  findByClass(card(hub), "mmsg-discard").onclick();
  await settle();
  const post = writes(calls).find((c) => c.path.endsWith("/discard"));
  assert.deepEqual(post.body, { expectVersion: 1 });
  assert.equal(text(hub, "mmsg-receipt"), t("messages.draft.discardedReceipt", "en"));
});

/* ------------------------------------------------------------- the URL card */

test("?msgdraft= mounts that card at the top of the panel, and a malformed id asks for nothing", async () => {
  const { hub, calls } = await mount({ list: [] });
  hub.location.search = "?msgdraft=" + ID;
  await open(hub);
  const node = card(hub);
  assert.ok(node, "the query card is on screen");
  assert.ok(reads(calls).some((c) => c.path === "/dashboard/messages/api/drafts/" + ID));
  assert.equal(hub.els["perch-transcript"].children[0], node, "mounted at the top of the chat panel");
  assert.ok(String(node.className).includes("mmsg-query"), "and outlined, so a bell's link is findable");

  /* A session switch keeps it, and never mounts a second one. */
  await openChatSession(hub, SECOND);
  await settle();
  assert.equal(all(hub, "mmsg-card").length, 1, "one card, not two");
  assert.equal(hub.els["perch-transcript"].children[0], node, "back at the top");

  for (const bad of ["msgd-ZZZZ", "../drafts", ID.toUpperCase(), "msgd-0123", ""]) {
    const malformed = await mount({ list: [] });
    malformed.hub.location.search = "?msgdraft=" + bad;
    await open(malformed.hub);
    assert.equal(reads(malformed.calls).length, 0, `no read for ${JSON.stringify(bad)}`);
    assert.equal(card(malformed.hub), null);
  }
});

/* -------------------------------------------------------- the recipient pick */

test("choosing another allowed recipient re-addresses the draft with the version it was drawn from", async () => {
  let moved = false;
  const { hub, calls } = await mount({
    drafts: { [ID]: () => (moved
      ? payload({ draft: { conversationId: 2, conversationKind: "contact", label: "Cara" } })
      : payload()) },
    reply: () => {
      moved = true;
      return { status: 200, json: { draft: draft({ conversationId: 2, label: "Cara" }) } };
    },
  });
  await open(hub);
  const picker = findByClass(card(hub), "mmsg-recipient-picker");
  picker.value = "contact:2";
  picker.onchange();
  await settle();

  const post = writes(calls).find((c) => c.path.endsWith("/recipient"));
  assert.ok(post, "the picker posts the choice");
  assert.deepEqual(post.body, { conversationKind: "contact", conversationId: 2, expectVersion: 1 });
  assert.equal(findByClass(card(hub), "mmsg-recipient-picker").children[1].getAttribute("selected"), "selected",
    "the picker now shows the new recipient");
});

test("a recipient the allow-list does not cover shows the refusal sentence and changes nothing", async () => {
  const { hub, calls } = await mount({
    drafts: { [ID]: payload() },
    reply: { status: 409, json: { error: "not_allowed", version: 1, draft: draft() } },
  });
  await open(hub);
  const picker = findByClass(card(hub), "mmsg-recipient-picker");
  picker.value = "contact:2";
  picker.onchange();
  await settle();
  assert.equal(text(hub, "mmsg-status"), fill(t("messages.draft.errNotAllowed", "en"), { bot: "Hank", name: "Sam" }));
  assert.ok(reads(calls).length >= 1, "the card was read at least once");
});

/* ---------------------------------------------------------------- the frames */

test("a msg_draft frame for another chat's draft never reaches this card", async () => {
  const { hub, calls } = await mount({ list: [ID], drafts: { [ID]: payload() } });
  await open(hub);
  const before = reads(calls).length;
  const es = FakeEventSource.instances[FakeEventSource.instances.length - 1];
  es._serverFrame("msg_draft", { type: "msg_draft", id: "not-a-draft" });
  await settle();
  assert.equal(reads(calls).length, before, "a malformed id asks for nothing");
});

test("the chat's own list is pruned: a draft that leaves the list leaves the transcript", async () => {
  let listNow = [ID];
  const { hub } = await mount({ list: () => listNow, drafts: { [ID]: payload() } });
  await open(hub);
  assert.ok(card(hub), "the draft is drawn");
  listNow = [];
  await openChatSession(hub, SECOND);
  await settle();
  assert.equal(card(hub), null, "and gone once no chat's list names it");
});