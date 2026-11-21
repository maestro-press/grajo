/**
 * msg-draft-card-live — the message draft card in a REAL browser (sharing-bot door plan, PR B).
 *
 * What is real: the dashboard router (so `/dashboard/perch` and `/dashboard/messages` are the pages
 * the product serves, with the layout's `<meta name="crow-csrf">`), the emitted Perch client, the real
 * Crow Messages draft store and its owner routes, the real allow-list file, and the vendored Turbo.
 * What is stubbed: the interactive engine's own half — `/roost`, a session's transcript and options,
 * and the chat's event stream (which forwards the gateway's real `message-drafts:changed` bus event as
 * the `{type:"msg_draft", id}` frame the product's own route sends) — and the delivery, which writes
 * the local row a real relay would have written. Nothing leaves the box.
 *
 * What it proves, in one flow:
 *   1. a stub BOT draft appears as a card in its Perch chat, and in the Messages Drafts list;
 *   2. the Perch card's autosave reaches a second tab's Messages composer live (no reload);
 *   3. Send from the Messages tab turns the Perch card into a receipt, live;
 *   4. the card's recipient picker offers exactly the bot's allow-list.
 *
 * Skips cleanly without Chrome (CROW_REQUIRE_TEST_CHROME=1 turns that into a failure).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { startHeadlessChrome } from "./fixtures/headless-chrome.mjs";
import { actAsServe, serveHeaders } from "./fixtures/serve-peer.mjs";
import { rmScratch } from "./helpers/safe-rm.js";

actAsServe();

const dir = mkdtempSync(join(tmpdir(), "msg-draft-card-live-"));
process.env.CROW_DATA_DIR = dir;
process.env.CROW_HOME = join(dir, "home");
mkdirSync(process.env.CROW_HOME, { recursive: true });
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");
const REPO = new URL("..", import.meta.url).pathname;
const SESSION = "msg-card-live-session";
const SID = "perchlive-aaaaaaa1";
const PEER_KEY = "02" + "a".repeat(64);
const CARA_KEY = "02" + "b".repeat(64);
const ROOM_NAME = "The Den";

let server = null;
let base = "";
let chrome = null;
let bus = null;
let setLang = null;
let t = null;
let fill = null;

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dir },
    stdio: "pipe",
    cwd: REPO,
  });
  const { hashToken } = await import("../servers/gateway/dashboard/auth.js");
  const raw = new Database(join(dir, "crow.db"));
  raw.prepare("INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at) VALUES (?, 'access', 'dashboard', 'dashboard', datetime('now','+1 day'))")
    .run(hashToken(SESSION));
  raw.pragma("wal_checkpoint(TRUNCATE)");
  raw.close();

  ({ t, fill } = await import("../servers/gateway/dashboard/shared/i18n.js"));
  const { createDbClient } = await import("../servers/db.js");
  const { writeSetting } = await import("../servers/gateway/dashboard/settings/registry.js");
  setLang = async (lang) => {
    const db = createDbClient();
    try { await writeSetting(db, "language", lang); } finally { db.close(); }
  };
  await setLang("en");

  const { default: dashboardRouter } = await import("../servers/gateway/dashboard/index.js");
  const { default: streamsRouter } = await import("../servers/gateway/routes/streams.js");
  const { default: peerMessagesRouter } = await import("../servers/gateway/routes/peer-messages.js");
  const { default: perchInteractiveApiRouter } = await import("../servers/gateway/routes/perch-interactive-api.js");
  const { setMessagesDraftsRuntime } = await import("../servers/gateway/routes/messages-drafts-api.js");
  const { parseCookies } = await import("../servers/gateway/dashboard/auth.js");
  const { default: express } = await import("express");
  bus = (await import("../servers/shared/event-bus.js")).default;

  // The delivery half of a draft send: the local row a relay would have written.
  setMessagesDraftsRuntime({
    send: async (db, draft, text) => {
      const r = await db.execute({
        sql: `INSERT INTO messages (contact_id, content, direction, is_read, delivery_status, created_at)
              VALUES (?, ?, 'sent', 1, 'relayed', datetime('now'))`,
        args: [draft.conversationId, text],
      });
      return { ok: true, messageId: String(r.lastInsertRowid) };
    },
  });

  const app = express();
  app.use(express.static(new URL("../servers/gateway/public", import.meta.url).pathname));
  app.use((req, res, next) => {
    const cookies = parseCookies(req);
    if (cookies.crow_session) req.dashboardSession = cookies.crow_session;
    next();
  });

  /* The engine's own half, stubbed: a roost with one live session, its (empty) transcript and
     options, and its event stream. The stream is a real text/event-stream, and every gateway bus
     write for THIS chat becomes the same `{type:"msg_draft", id}` frame the product's own route
     sends — that is what makes "live" here mean live, without an engine. */
  app.use("/dashboard/perch-api", (req, res, next) => {
    const url = String(req.originalUrl || req.url);
    if (req.method === "GET" && /\/roost(\?|$)/.test(url)) {
      res.json({
        birds: [{ id: "hank", name: "Hank", perch_attached: true, state: "working",
          sessions: [{ sessionId: SID, state: "awake", cardId: null, pendingUi: false, projectId: null }] }],
      });
      return;
    }
    if (req.method === "GET" && /\/interactive\/[^/]+\/transcript$/.test(url)) { res.json({ events: [] }); return; }
    if (req.method === "GET" && /\/interactive\/[^/]+\/options$/.test(url)) {
      res.json({ models: [], thinkingLevels: [] });
      return;
    }
    if (req.method === "GET" && /\/interactive\/([^/]+)\/events$/.test(url)) {
      const sid = decodeURIComponent(/\/interactive\/([^/]+)\/events$/.exec(url)[1]);
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-store",
        Connection: "keep-alive",
      });
      res.write("event: state\ndata: " + JSON.stringify({ type: "state", state: "waiting-user", label: "Hank" }) + "\n\n");
      const onDraft = (payload) => {
        try {
          if (!payload || String(payload.chatThreadId ?? "") !== sid) return;
          const id = typeof payload.draftId === "string" ? payload.draftId : "";
          if (!id) return;
          res.write("event: msg_draft\ndata: " + JSON.stringify({ type: "msg_draft", id }) + "\n\n");
        } catch { /* a closed stream is the client's business */ }
      };
      bus.on("message-drafts:changed", onDraft);
      req.on("close", () => { try { bus.off("message-drafts:changed", onDraft); } catch { /* gone */ } });
      return;
    }
    next();
  });

  const noAuth = (req, res, next) => next();
  app.use(streamsRouter(noAuth));
  app.use(peerMessagesRouter(noAuth));
  app.use(perchInteractiveApiRouter(noAuth, {
    engine: () => ({ message: async () => ({ turnId: "t1" }), subscribe: async () => () => {} }),
    annotate: async (m) => m,
    providerModels: () => [],
    piProviders: () => null,
    ownerCheck: async () => true,
    stagedGmail: () => null,
  }));
  app.use(dashboardRouter(noAuth));

  chrome = await startHeadlessChrome();
  await new Promise((resolve) => { server = app.listen(0, "127.0.0.1", resolve); });
  base = "http://127.0.0.1:" + server.address().port;
});

after(async () => {
  if (server) {
    try { server.closeAllConnections?.(); } catch { /* already gone */ }
    try { server.close(); } catch { /* already gone */ }
  }
  if (chrome) await chrome.close();
  try {
    const mod = await import("../servers/gateway/routes/messages-drafts-api.js");
    mod.clearMessagesDraftsRuntime();
  } catch { /* never loaded */ }
  rmScratch(dir);
});

/* ------------------------------------------------------------------ fixtures */

/** Two contacts and a room, the shape a real instance has after two invites. */
function seedPeople() {
  const raw = new Database(join(dir, "crow.db"));
  try {
    for (const table of ["message_drafts", "message_draft_audit", "messages", "contact_group_members", "contact_groups", "contacts"]) {
      try { raw.prepare(`DELETE FROM ${table}`).run(); } catch { /* table absent */ }
    }
    raw.prepare(`INSERT INTO contacts (id, crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
                 VALUES (1, 'crow:peer', 'Sam', ?, ?, 'crow')`).run(PEER_KEY, "e".repeat(64));
    raw.prepare(`INSERT INTO contacts (id, crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
                 VALUES (2, 'crow:cara', 'Cara', ?, ?, 'crow')`).run(CARA_KEY, "f".repeat(64));
    const roomId = Number(raw.prepare("INSERT INTO contact_groups (name, room_uid, host_crow_id, mode) VALUES (?, ?, 'crow:me', 'addressed')")
      .run(ROOM_NAME, "r".repeat(32)).lastInsertRowid);
    raw.prepare("INSERT INTO contact_group_members (group_id, contact_id) VALUES (?, 1)").run(roomId);
    raw.prepare("INSERT OR REPLACE INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('hank', 'Hank', ?, 1)")
      .run(JSON.stringify({ name: "Hank", gateway: "perch", tools: { crow_mcp: ["crow-sharing/crow_send_message"] } }));
    return { roomId };
  } finally {
    raw.pragma("wal_checkpoint(TRUNCATE)");
    raw.close();
  }
}

/** The bot's allow-list: the peer contact and the room — never Cara's contact. */
async function seedAcl(roomId) {
  const acl = await import("../servers/gateway/sharing-bot/acl.js");
  acl.setSharingBotAclEntry(process.env.CROW_HOME, "hank", {
    contacts: [{ crow_id: "crow:peer", secp256k1_pubkey: PEER_KEY }],
    groups: [{ id: roomId, members: [{ crow_id: "crow:peer", secp256k1_pubkey: PEER_KEY }] }],
    rate: { per_hour: 20 },
  });
}

/** The bot's draft, written the way the door writes it: origin bot, name snapshot, chat thread. */
async function seedBotDraft(body) {
  const { createDbClient } = await import("../servers/db.js");
  const { createDraft } = await import("../servers/gateway/messages/drafts-store.js");
  const { resolveConversation } = await import("../servers/gateway/messages/conversations.js");
  const db = createDbClient();
  try {
    const conversation = await resolveConversation(db, { kind: "contact", id: 1 });
    assert.equal(conversation.ok, true, "the peer conversation resolves");
    const out = await createDraft(db, {
      conversationKind: "contact",
      conversationId: 1,
      body,
      recipients: conversation.recipients,
      origin: "bot",
      botId: "hank",
      botName: "Hank",
      chatThreadId: SID,
    });
    assert.equal(out.ok, true, JSON.stringify(out));
    return out.draft;
  } finally {
    db.close();
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const PERCH_READY = "document.readyState === 'complete' && !!document.querySelector('#perch-transcript') && !document.documentElement.hasAttribute('aria-busy')";
const MESSAGES_READY = "document.readyState === 'complete' && !!document.querySelector('.msg-hub') && !document.documentElement.hasAttribute('aria-busy')";
const TWO_FRAMES = "new Promise(function(r){requestAnimationFrame(function(){requestAnimationFrame(function(){r(1);});});})";

/** A tab at a viewport, signed in, on a page of this app. */
async function open(path, ready = PERCH_READY) {
  const target = await (await fetch(chrome.cdp + "/json/new?about:blank", { method: "PUT" })).json();
  const { default: WebSocket } = await import("ws");
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.once("open", r); ws.once("error", j); });
  let id = 0;
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const mine = ++id;
    const on = (raw) => {
      const m = JSON.parse(raw);
      if (m.id !== mine) return;
      ws.off("message", on);
      m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result || {});
    };
    ws.on("message", on);
    ws.send(JSON.stringify({ id: mine, method, params }));
  });
  const ev = async (expression) => {
    const out = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (out.exceptionDetails) throw new Error("page threw: " + JSON.stringify(out.exceptionDetails));
    return out.result.value;
  };
  const errors = [];
  ws.on("message", (raw) => {
    const m = JSON.parse(raw);
    if (m.method === "Runtime.exceptionThrown") {
      errors.push((m.params.exceptionDetails.exception || {}).description || m.params.exceptionDetails.text);
    }
  });
  const until = async (expression, what, ms = 15000) => {
    const end = Date.now() + ms;
    for (;;) {
      let v = null;
      try { v = await ev(expression); } catch { /* mid-navigation */ }
      if (v) return v;
      if (Date.now() > end) {
        let where = "";
        try { where = await ev("location.href"); } catch {}
        throw new Error("timed out waiting for " + what + " (" + expression + ") at " + where
          + (errors.length ? "; page errors: " + errors.slice(-4).join(" | ") : ""));
      }
      await sleep(80);
    }
  };
  await send("Page.enable");
  await send("Runtime.enable");
  await send("Network.enable");
  await send("Network.clearBrowserCookies");
  await send("Network.setExtraHTTPHeaders", { headers: serveHeaders("operator@example.invalid") });
  await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await send("Network.setCookie", { name: "crow_session", value: SESSION, url: base, path: "/" });
  await send("Page.navigate", { url: base + path });
  await until(ready, "the page");
  await ev(TWO_FRAMES);

  const clickSel = async (sel) => {
    await ev(`(function(){ var e=document.querySelector(${JSON.stringify(sel)}); if(!e) return 0;
      e.scrollIntoView({ block: 'center' }); return 1; })()`);
    await sleep(150);
    const p = await ev(`(function(){ var e=document.querySelector(${JSON.stringify(sel)}); if(!e) return null;
      var b=e.getBoundingClientRect(); return { x: b.left + b.width/2, y: b.top + b.height/2 }; })()`);
    assert.ok(p, "no element " + sel);
    for (const type of ["mousePressed", "mouseReleased"]) {
      await send("Input.dispatchMouseEvent", { type, x: p.x, y: p.y, button: "left", clickCount: 1 });
    }
    await sleep(80);
  };
  const typeInto = async (sel, text) => {
    await ev(`(function(){ var e=document.querySelector(${JSON.stringify(sel)}); e.focus(); return 1; })()`);
    await send("Input.insertText", { text });
    await sleep(60);
  };
  const text = (sel) => ev(`(function(){ var e=document.querySelector(${JSON.stringify(sel)}); return e ? e.textContent : null; })()`);
  const count = (sel) => ev(`document.querySelectorAll(${JSON.stringify(sel)}).length`);
  return { send, ev, until, clickSel, typeInto, text, count, errors, close: async () => {
    ws.close();
    await fetch(chrome.cdp + "/json/close/" + target.id).catch(() => {});
  } };
}

/* ------------------------------------------------------------------- the test */

test("1280×800 en: a bot's draft is a card in its chat and a row in Messages; edit → live composer; Send → receipt; the picker is the allow-list", async (ctx) => {
  if (!chrome) return ctx.skip("no headless Chrome");
  await setLang("en");
  const { roomId } = seedPeople();
  await seedAcl(roomId);
  const draft = await seedBotDraft("Hello Sam, Tuesday works");

  const cardHead = fill(t("messages.draft.cardHead", "en"), { bot: "Hank" });
  const sentBy = fill(t("messages.draft.sentByLine", "en"), { bot: "Hank" });
  const cardSel = `.mmsg-card[data-msgdraft-id="${draft.id}"]`;
  const perch = await open("/dashboard/perch#" + SID);
  let messages = null;
  try {
    /* 1. The card, in its own chat. */
    await perch.until(`!!document.querySelector(${JSON.stringify(cardSel)})`, "the draft card in the Perch chat");
    assert.equal(await perch.text(cardSel + " .mmsg-head"), cardHead, "the card names the bot that wrote it");
    assert.equal(await perch.text(cardSel + " .mmsg-sentby"), sentBy,
      "the fixed greyed line the message will begin with");
    assert.equal(await perch.ev(`document.querySelector(${JSON.stringify(cardSel + " .mmsg-body")}).value`),
      "Hello Sam, Tuesday works", "the words are in the textarea");

    /* 4 (first half). The picker offers the allow-list and nothing else. */
    const options = await perch.ev(`Array.from(document.querySelectorAll(${JSON.stringify(cardSel + " .mmsg-recipient-picker option")}))
      .map(function(o){ return o.textContent; })`);
    assert.deepEqual(options, ["Sam", ROOM_NAME], "the peer contact and the room — never the unlisted contact");

    /* 1 (second half). The same draft is a row in the Messages Drafts list, with its bot chip. */
    messages = await open("/dashboard/messages", MESSAGES_READY);
    await messages.until(`document.querySelectorAll('.msg-drafts-row[data-draft-id="${draft.id}"]').length === 1`,
      "the draft in the Messages list");
    assert.match(await messages.text(`.msg-drafts-row[data-draft-id="${draft.id}"] .msg-drafts-by`), /Hank/,
      "the row carries the bot chip");
    await messages.clickSel(".msg-avatar-item[data-type='peer']");
    await messages.until("!!document.getElementById('msg-input')", "the peer's composer");
    await messages.until(`(function(){ var e=document.getElementById('msg-input'); return e && e.value === 'Hello Sam, Tuesday works'; })()`,
      "the composer pre-filled from the same draft");

    /* 2. An edit in the Perch card reaches the Messages composer LIVE (bus → crow-draft → re-read). */
    await perch.typeInto(cardSel + " .mmsg-body", " at ten.");
    await perch.until(`(function(){ var e=document.querySelector(${JSON.stringify(cardSel + " .mmsg-status")});
      return e && e.textContent === ${JSON.stringify(t("messages.draft.saved", "en"))}; })()`, "the card's Saved line");
    await messages.until(`(function(){ var e=document.getElementById('msg-input');
      return e && e.value.indexOf('at ten.') >= 0; })()`, "the editor's words in the Messages composer, live");

    /* 3. Send from Messages turns the Perch card into a receipt, live (the same bus event, this time
       as a msg_draft frame on the chat's own stream). */
    await messages.typeInto("#msg-input", "");
    await messages.clickSel("#msg-send-btn");
    const receipt = fill(t("messages.draft.sentReceipt", "en"), { name: "Sam" });
    await perch.until(`(function(){ var e=document.querySelector(${JSON.stringify(cardSel + " .mmsg-receipt")});
      return e && e.textContent === ${JSON.stringify(receipt)}; })()`, "the card's receipt after Send");
    assert.equal(await perch.count(cardSel + " .mmsg-body"), 0, "and nothing left to type");
    assert.equal(await perch.count(cardSel + " .mmsg-send"), 0, "nothing left to press");
    await messages.until(`document.querySelectorAll('.msg-drafts-row').length === 0`, "the row gone from Messages");

    assert.deepEqual(perch.errors, [], "no page errors in the Perch tab");
    assert.deepEqual(messages.errors, [], "no page errors in the Messages tab");
  } finally {
    await perch.close();
    if (messages) await messages.close();
  }
});

test("1280×800 en: ?msgdraft=<id> opens that card at the top of the panel, outlined", async (ctx) => {
  if (!chrome) return ctx.skip("no headless Chrome");
  await setLang("en");
  const { roomId } = seedPeople();
  await seedAcl(roomId);
  const draft = await seedBotDraft("A draft a bell links to");

  const tab = await open("/dashboard/perch?msgdraft=" + draft.id + "#" + SID);
  try {
    await tab.until(`!!document.querySelector('.mmsg-card[data-msgdraft-id="${draft.id}"]')`, "the query card");
    assert.ok(await tab.ev(`(function(){ var t=document.getElementById('perch-transcript');
      var c=t.children[0]; return !!c && c.className.indexOf('mmsg-card') >= 0 && c.className.indexOf('mmsg-query') >= 0; })()`),
      "mounted first in the panel, and outlined so the link's target is findable");
    assert.deepEqual(tab.errors, [], "no page errors");
  } finally {
    await tab.close();
  }
});