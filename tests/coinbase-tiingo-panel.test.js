/**
 * The Stock prices (Tiingo) part of the Trading panel: the one state field
 * `GET /api/coinbase/panel` gains, in each of its six shapes, whether stock trading is configured
 * at all (`equity_enabled`, and the card that hides itself when it is false), and the card the page
 * renders — a password field for the token, Test, Save and Disconnect, the free-plan link, and a
 * client script that posts to the three routes and keeps the pasted value until a Save works.
 *
 * The routes are built the way `coinbase-panel.test.js` builds them: the shared harness's real
 * express app over the panel's router, a real keychain, one init-db database per test and the
 * harness's fake trading engine (whose `/status` this file answers from a script, so the engine's
 * own `equity.prices` is what the panel reads). The page is rendered through the panel file's own
 * handler, exactly as the dashboard renders it. Every token here is synthetic, and the canary is
 * the value no answer, no audit row and no rendered page may ever carry.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";

import {
  scaffold,
  cleanupScratch,
  renderPanelPage,
} from "./helpers/coinbase-panel-harness.mjs";

const K = await import("../servers/gateway/keychain/store.js");

// The four sentences the state field answers with, word for word.
const MESSAGE_CONNECTED = "Stock prices are connected (Tiingo).";
const MESSAGE_MISSING =
  "Stock prices are not connected, so practice stock orders will not fill. " +
  "Paste your free Tiingo token below.";
const MESSAGE_REJECTED = "Tiingo did not accept the token. Paste it again.";
const MESSAGE_COINBASE_OFF = "Connect Coinbase first, then add stock prices.";
// The fifth state: Tiingo is limiting Crow, so the prices wait on their own.
const MESSAGE_PAUSED =
  "Stock prices are paused for now (Tiingo is limiting requests); they will resume on their own.";

const TIINGO_TOKEN = "tiingo" + "1f4c8a2d6b9e0";
const CANARY = "canary" + "7a3e5d1b9c2f4";

after(() => {
  cleanupScratch();
});

/** The engine's `/status`, with an equity block the test decides. */
function statusBody({ prices = "missing", pricesMessage = null, enabled = true } = {}) {
  return {
    halted: false,
    halted_books: { dry: false, live: false },
    halt_reasons: { dry: null, live: null },
    bots: [],
    recent_alerts: [],
    live_switches: { live_enabled: false, ai_live_enabled: false, ceiling: true },
    drawdown: { dry: null, live: null },
    products: ["BTC-USDC"],
    equity: { enabled, prices, prices_message: pricesMessage },
  };
}

/**
 * One panel with the engine's `/status` scripted. `prices` is what the engine reports for the
 * equity block and `enabled` is whether stock trading is configured at all; `connect` decides
 * whether a Coinbase connection stands.
 */
async function panelScaffold({ connect = true, prices = "missing", pricesMessage = null, enabled = true } = {}) {
  const h = await scaffold();
  if (connect) {
    h.connectAnswer = await h.connect();
  }
  h.fake.next("GET", "/status", { status: 200, body: statusBody({ prices, pricesMessage, enabled }) });
  return h;
}

/** The HTML of the Stock prices card: from its title to the next section heading. */
function stockPricesCard(content) {
  const html = String(content);
  const at = html.indexOf("Stock prices (Tiingo)");
  assert.notEqual(at, -1, "the page carries a Stock prices (Tiingo) card");
  const next = html.indexOf("<h2", at + 1);
  return next === -1 ? html.slice(at) : html.slice(at, next);
}

/**
 * The card's own Stock prices script, mounted on a fake DOM: the same section of the rendered page
 * script, with a stub `api`, `say`, `fail`, `load`, `S` and `document` around it. A press runs the
 * real click handler the page installs, so the token field's value afterwards is what a browser
 * would keep once that answer came back.
 */
function mountTiingoCard(scripts) {
  const source = String(scripts);
  const start = source.indexOf("// ---- Stock prices (Tiingo)");
  const end = source.indexOf("// ---- pending approvals", start + 1);
  assert.notEqual(start, -1, "the page script carries the Stock prices card's own section");
  assert.ok(end > start, "the card's section ends where the next card's begins");

  const nodes = new Map();
  function node(id) {
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        value: "",
        hidden: false,
        textContent: "",
        className: "",
        listeners: {},
        addEventListener(type, handler) {
          this.listeners[type] = handler;
        },
      });
    }
    return nodes.get(id);
  }

  const sent = [];
  const said = [];
  const queue = [];
  let loads = 0;
  const S = { done: "Done." };
  const document = { getElementById: (id) => node(id) };
  const api = (method, path, body) => {
    sent.push({ method, path, body });
    const next = queue.length ? queue.shift() : { ok: true };
    if (next && next.down === true) {
      const failure = new Error("the engine is down");
      failure.data = { message: "Crow could not connect to the trading engine." };
      return Promise.reject(failure);
    }
    return Promise.resolve(next);
  };
  const say = (text, bad) => { said.push({ text, bad }); };
  const fail = (err) => { said.push({ text: (err && err.data && err.data.message) || "", bad: true }); };
  const load = () => { loads += 1; };

  const build = new Function(
    "document",
    "S",
    "api",
    "say",
    "fail",
    "load",
    `${source.slice(start, end)}\nreturn { renderPrices: renderPrices };`,
  );
  const card = build(document, S, api, say, fail, load);

  /** One press of a card button, then the turn of the event loop that answers it. */
  async function press(id) {
    const handler = node(id).listeners.click;
    assert.equal(typeof handler, "function", `the card script wires a click handler for ${id}`);
    handler();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  return {
    node,
    press,
    sent,
    said,
    answer: (value) => queue.push(value),
    get loads() { return loads; },
    get renderPrices() { return card.renderPrices; },
  };
}

// ---- the six states of `prices` --------------------------------------------------------------

test("panel_prices_coinbase_off", async () => {
  const h = await panelScaffold({ connect: false, prices: "missing" });
  try {
    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json && panel.json.ok, true);
    assert.deepEqual(panel.json.prices, { state: "coinbase_off", message: MESSAGE_COINBASE_OFF });
    assert.deepEqual(Object.keys(panel.json.prices).sort(), ["message", "state"]);
  } finally {
    await h.close();
  }
});

test("panel_prices_missing", async () => {
  const h = await panelScaffold({ connect: true, prices: "missing" });
  try {
    assert.equal(h.connectAnswer.status, 200, h.connectAnswer.text);
    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.deepEqual(panel.json.prices, { state: "missing", message: MESSAGE_MISSING });
    assert.deepEqual(Object.keys(panel.json.prices).sort(), ["message", "state"]);
  } finally {
    await h.close();
  }
});

test("panel_prices_connected", async () => {
  const h = await panelScaffold({ connect: true, prices: "connected" });
  try {
    assert.equal(h.connectAnswer.status, 200, h.connectAnswer.text);
    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.deepEqual(panel.json.prices, { state: "connected", message: MESSAGE_CONNECTED });
    assert.deepEqual(Object.keys(panel.json.prices).sort(), ["message", "state"]);
  } finally {
    await h.close();
  }
});

test("panel_prices_rejected", async () => {
  // The engine's own words for its refusal never reach the page: the state's fixed sentence does.
  const h = await panelScaffold({ connect: true, prices: "rejected", pricesMessage: CANARY });
  try {
    assert.equal(h.connectAnswer.status, 200, h.connectAnswer.text);
    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.deepEqual(panel.json.prices, { state: "rejected", message: MESSAGE_REJECTED });
    assert.deepEqual(Object.keys(panel.json.prices).sort(), ["message", "state"]);
    assert.equal(panel.text.includes(CANARY), false, "the engine's own sentence is not repeated");
  } finally {
    await h.close();
  }
});

test("panel_prices_paused", async () => {
  // Tiingo is limiting Crow: the token is fine, so the panel says the prices wait on their own.
  const h = await panelScaffold({ connect: true, prices: "paused" });
  try {
    assert.equal(h.connectAnswer.status, 200, h.connectAnswer.text);
    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.deepEqual(panel.json.prices, { state: "paused", message: MESSAGE_PAUSED });
    assert.deepEqual(Object.keys(panel.json.prices).sort(), ["message", "state"]);
  } finally {
    await h.close();
  }
});

test("panel_prices_missing_when_the_engine_is_down", async () => {
  const h = await panelScaffold({ connect: true, prices: "connected" });
  try {
    assert.equal(h.connectAnswer.status, 200, h.connectAnswer.text);
    await h.fake.close();
    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.engine.reachable, false);
    assert.deepEqual(panel.json.prices, { state: "missing", message: MESSAGE_MISSING });
    assert.equal(panel.json.equity_enabled, false, "an engine that did not answer enables no stock trading");
  } finally {
    await h.close();
  }
});

// ---- whether stock trading is configured at all -----------------------------------------------

test("panel_state_carries_equity_enabled", async () => {
  const on = await panelScaffold({ connect: true, prices: "connected", enabled: true });
  try {
    assert.equal(on.connectAnswer.status, 200, on.connectAnswer.text);
    const panel = await on.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.equity_enabled, true, "the engine's equity.enabled is what the panel reads");
  } finally {
    await on.close();
  }

  const off = await panelScaffold({ connect: true, prices: "connected", enabled: false });
  try {
    assert.equal(off.connectAnswer.status, 200, off.connectAnswer.text);
    const panel = await off.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.equity_enabled, false, "stocks off in the engine is off in the panel state");
  } finally {
    await off.close();
  }
});

test("the_card_is_hidden_when_stock_trading_is_off", async () => {
  const page = await renderPanelPage();
  const card = mountTiingoCard(page.scripts);
  assert.equal(typeof card.renderPrices, "function", "the page script draws the Stock prices card");

  // Stock trading is configured: the card is there to read and fill in.
  card.renderPrices({ equity_enabled: true, prices: { state: "missing", message: MESSAGE_MISSING } });
  assert.equal(card.node("cb-tiingo").hidden, false, "the card shows while stock trading is on");

  // Stock trading is off in the engine: the whole card goes, not just its buttons.
  card.renderPrices({ equity_enabled: false, prices: { state: "missing", message: MESSAGE_MISSING } });
  assert.equal(card.node("cb-tiingo").hidden, true, "the whole card is hidden while stock trading is off");
});

// ---- the page itself -------------------------------------------------------------------------

test("the_panel_renders_the_stock_prices_card", async () => {
  const page = await renderPanelPage();
  const content = page.content;
  const card = stockPricesCard(content);

  // The card sits after Connect, and names itself.
  assert.ok(
    content.indexOf("Stock prices (Tiingo)") > content.indexOf("<h2>Connect</h2>"),
    "the card comes after the Connect card",
  );

  // A password-type field for the token, never autofilled.
  const inputs = card.match(/<input\b[^>]*>/g) || [];
  const password = inputs.find((tag) => /type="password"/.test(tag));
  assert.ok(password, `the card has a password-type token field: ${card}`);
  assert.match(password, /autocomplete="off"/, "the token field is never autofilled");
  assert.equal(
    /\bvalue="[^"]+"/.test(password),
    false,
    "the token field starts empty: the page carries no token",
  );

  // Test, Save and Disconnect.
  for (const label of ["Test", "Save", "Disconnect"]) {
    assert.match(card, new RegExp(`>\\s*${label}\\s*<`), `the card has its ${label} button`);
  }

  // No 2FA field anywhere inside the card: the token only reads public prices.
  assert.equal(
    /<input[^>]*inputmode="numeric"/.test(card),
    false,
    `the card has no code field: ${card}`,
  );
  assert.equal(/data-field="totp"/.test(card), false, `the card has no 2FA input: ${card}`);
  assert.equal(/<input[^>]*\bid="[^"]*code/i.test(card), false, `no code input in the card: ${card}`);

  // The free personal plan, by its own address.
  assert.ok(card.includes("https://www.tiingo.com/"), "the card names the Tiingo site");
  assert.match(card, /href="https:\/\/www\.tiingo\.com\/?"/, "the address is a link");
});

test("the_panel_script_posts_to_the_three_tiingo_routes", async () => {
  const page = await renderPanelPage();
  const card = stockPricesCard(page.content);
  const scripts = page.scripts;

  // The three paths the script posts to, whichever way it spells them.
  const routes = {
    test: /["'`](?:\/api\/coinbase)?\/tiingo\/test["'`]/,
    save: /["'`](?:\/api\/coinbase)?\/tiingo["'`]/,
    disconnect: /["'`](?:\/api\/coinbase)?\/tiingo\/disconnect["'`]/,
  };
  for (const [name, pattern] of Object.entries(routes)) {
    assert.match(scripts, pattern, `the page script posts to the ${name} route`);
  }

  // The field the presses read, taken from the card the page renders.
  const passwordTag = (card.match(/<input\b[^>]*type="password"[^>]*>/) || [])[0];
  assert.ok(passwordTag, "the card has a password-type token field");
  const idMatch = /id="([^"]+)"/.exec(passwordTag);
  assert.ok(idMatch, `the token field carries an id the script can find: ${passwordTag}`);
  assert.ok(scripts.includes(idMatch[1]), "the script reads the token field by its own id");
});

/** The id of the token field the rendered card carries. */
function tokenFieldId(card) {
  const tag = (card.match(/<input\b[^>]*type="password"[^>]*>/) || [])[0];
  assert.ok(tag, "the card has a password-type token field");
  const idMatch = /id="([^"]+)"/.exec(tag);
  assert.ok(idMatch, `the token field carries an id: ${tag}`);
  return idMatch[1];
}

test("test_and_save_keep_the_pasted_token_until_a_save_works", async () => {
  const page = await renderPanelPage();
  const fieldId = tokenFieldId(stockPricesCard(page.content));
  const card = mountTiingoCard(page.scripts);

  // Test that passes: the pasted value is still there, so Save needs no second paste.
  card.node(fieldId).value = TIINGO_TOKEN;
  card.answer({ ok: true, message: "Tiingo accepted the token." });
  await card.press("cb-tiingo-test");
  assert.match(String(card.sent.at(-1).path), /\/tiingo\/test$/, "Test posts to the test route");
  assert.deepEqual(card.sent.at(-1).body, { token: TIINGO_TOKEN });
  assert.equal(card.said.at(-1).text, "Tiingo accepted the token.", "the answer's own sentence is shown");
  assert.equal(card.node(fieldId).value, TIINGO_TOKEN, "a Test that passed leaves the token in the field");

  // Test that failed (the engine refused, so the answer was a refusal): the field keeps the value
  // so the owner can correct a typo and try again.
  card.answer({ down: true });
  await card.press("cb-tiingo-test");
  assert.equal(card.said.at(-1).bad, true, "a Test that failed is shown as a failure");
  assert.equal(card.node(fieldId).value, TIINGO_TOKEN, "a Test that failed leaves the field filled");

  // Save that worked: the value has been sealed, so the field is emptied and the panel re-read.
  card.answer({ ok: true, message: "Stock prices connected." });
  await card.press("cb-tiingo-save");
  assert.match(String(card.sent.at(-1).path), /\/tiingo$/, "Save posts to the save route");
  assert.equal(card.sent.at(-1).body.token, TIINGO_TOKEN);
  assert.equal(card.node(fieldId).value, "", "a Save that worked clears the field");
  assert.ok(card.loads >= 1, "a Save that worked re-reads the panel");

  // Save that failed: nothing was sealed, so the field keeps what was typed.
  card.node(fieldId).value = TIINGO_TOKEN;
  card.answer({ down: true });
  await card.press("cb-tiingo-save");
  assert.equal(card.node(fieldId).value, TIINGO_TOKEN, "a Save that failed leaves the field filled");

  // An answer that says it failed without a refusal status is a failed Save too.
  card.node(fieldId).value = TIINGO_TOKEN;
  card.answer({ ok: false, code: "TOKEN_REJECTED", message: MESSAGE_REJECTED });
  await card.press("cb-tiingo-save");
  assert.equal(card.node(fieldId).value, TIINGO_TOKEN, "an answer with ok false leaves the field filled");

  // Disconnect forgets the token, so nothing typed is worth keeping.
  card.node(fieldId).value = TIINGO_TOKEN;
  card.answer({ ok: true, message: "Stock prices disconnected." });
  await card.press("cb-tiingo-disconnect");
  assert.equal(card.node(fieldId).value, "", "a Disconnect clears the field");
});

test("no_sealed_token_reaches_the_page_or_the_panel_state", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    const row = (await h.connections()).filter((entry) => entry.status === "active")[0];
    assert.ok(row, "the connection stands");

    // The state the card can carry: a sealed token on the connection, and an engine that echoes
    // it back in its own message.
    await K.saveServiceSecret(h.db, await h.key(), {
      connectionUuid: row.uuid,
      bundleId: "coinbase",
      envKey: "TIINGO_TOKEN",
      label: "Coinbase \u2014 Stock prices \u2014 TIINGO_TOKEN",
      secret: CANARY,
    });
    h.fake.next("GET", "/status", {
      status: 200,
      body: statusBody({ prices: "rejected", pricesMessage: CANARY }),
    });

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.prices.state, "rejected");
    assert.equal(panel.json.prices.message, MESSAGE_REJECTED);
    assert.equal(panel.text.includes(CANARY), false, "the panel answer carries no token");
    assert.equal(panel.text.includes(TIINGO_TOKEN), false);

    const state = await h.get("/api/coinbase/tiingo/state");
    assert.equal(state.status, 200, state.text);
    assert.equal(state.text.includes(CANARY), false, "the state answer carries no token");

    const page = await renderPanelPage();
    assert.equal((page.content + page.scripts).includes(CANARY), false, "the rendered page carries no token");
    assert.equal((page.content + page.scripts).includes(TIINGO_TOKEN), false);
  } finally {
    await h.close();
  }
});