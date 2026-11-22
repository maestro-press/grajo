/**
 * The Trading panel's routes: the gates in front of every privileged action, the kill switch, the
 * caps form and its drawdown warning, the live switches as the engine reports them, the bot
 * controls, the aggregated panel state, the boot-time loops and the page the owner opens.
 *
 * A scratch Crow home (an init-db database, a real keychain, a real sealed connection), a real
 * express app over the panel's router, and a fake trading engine that checks the approval MAC on
 * every privileged route and logs the key each request was signed with. The step-up gate is the
 * dashboard's real one with its two seams injected, so its replay guard and its lockout are what
 * the routes meet.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";

import {
  scaffold,
  cleanupScratch,
  createFakeEngine,
  renderPanelPage,
  within,
  waitFor,
  signedHeaders,
  fakeBot,
  fakePreview,
  CROW_HOME,
  SESSION,
  ENGINE_TOKEN,
  INSTALL_TOKEN,
  KEY_NAME,
  PRIVATE_KEY,
  TOTP,
  TWO_FACTOR_MESSAGE,
  TOTP_REQUIRED_MESSAGE,
  STEP_UP_LOCKED_MESSAGE,
  LOCAL_LOGIN_CODE,
  KILL_CONFIRM_MESSAGE,
  KILL_NOT_READY_MESSAGE,
  WOULD_HALT_MESSAGE,
  WOULD_HALT_PRACTICE_MESSAGE,
  DISCONNECT_UNFINISHED_MESSAGE,
  ENGINE_DOWN_NOTE,
  CONNECTED_PREFIX,
  GRID_NOTE,
  CAP,
  defaultCaps,
  defaultCeilings,
  KILL_SUCCESS_MESSAGE,
  KILL_ENGINE_DOWN_MESSAGE,
  KILL_ENGINE_REFUSED_MESSAGE,
  KILL_PARTIAL_MESSAGE,
  SWITCH_MESSAGE,
  SWITCH_UNCHANGED_MESSAGE,
  SWITCH_NOT_CONNECTED_MESSAGE,
  fakeOrder,
  importPanelRoutes,
  REPO,
} from "./helpers/coinbase-panel-harness.mjs";

const { COPY_STEPS } = await import("../bundles/coinbase/panel/connect.js");
const { createEngineClient } = await import("../bundles/coinbase/server/engine-client.js");

// The two sentences this file pins, word for word.
const MESSAGE_BOT_PRACTICE =
  "Back to practice. The bot's orders waiting on Coinbase were cancelled and it now trades with " +
  "pretend money. Nothing was sold.";
const MESSAGE_HALT_CLEARED =
  "Resumed. Crow may trade again. Bots that were stopped stay stopped; " +
  "create a new bot to trade again.";
// The three pause sentences this file pins, word for word.
const MESSAGE_BOT_PAUSED =
  "Paused. Its waiting orders on Coinbase were cancelled, and it places no new ones until you resume.";
const MESSAGE_BOT_PAUSE_INCOMPLETE =
  "Paused, but Crow couldn't cancel every waiting order on Coinbase. Press Pause again, or cancel " +
  "them in the Coinbase app: Crow portfolio \u2192 Open orders.";
// A second Pause pressed moments after the first: one plain sentence, no engine words.
const MESSAGE_BOT_PAUSE_TOO_SOON =
  "Pause was just pressed for this bot. Wait a few seconds and press Pause again.";
// The two sentences a pause refused for a race keeps: plain words, and never the engine's.
const MESSAGE_PAUSE_IN_PROGRESS = "This bot is being paused. Wait a few seconds and try again.";
const MESSAGE_PAUSE_CHANGED =
  "This bot changed while it was being paused. Check it, and press Pause again if it still needs it.";

after(() => {
  cleanupScratch();
});

/** The body the panel sent the engine to create a bot. */
function createdBotBody(fake) {
  const records = fake.calls("POST", "/bots");
  assert.ok(records.length > 0, "the panel asked the engine to create a bot");
  return JSON.parse(records[records.length - 1].body);
}

function assertCarriesNoSecret(text, secrets, label) {
  for (const secret of secrets) {
    if (typeof secret !== "string" || secret.length === 0) continue;
    assert.equal(String(text).includes(secret), false, `${label} carried a secret`);
  }
}

/** Every `dashboard_settings` row, so a test can show a read or a save wrote none. */
async function settingRows(h) {
  const result = await h.db.execute({
    sql: "SELECT key, value FROM dashboard_settings ORDER BY key",
    args: [],
  });
  return (result && Array.isArray(result.rows) ? result.rows : []).map((row) => ({
    key: String(row.key),
    value: String(row.value ?? ""),
  }));
}

// ---- the page's own client script, in a bare vm ------------------------------------------------

/**
 * The Trading page's client script, run in a vm over the smallest DOM that lets its listeners
 * install themselves, so a test reads the body the switches form itself posts.
 *
 * `panelState` is what the page's own poll (`GET /panel`) answers; left out, the poll never
 * settles, which is the page before any poll has answered. Every fetch is recorded.
 */
async function runPanelScript(options = {}) {
  const settings = options || {};
  const page = await renderPanelPage();

  const elements = new Map();
  function element(name) {
    const listeners = Object.create(null);
    return {
      id: name,
      value: "",
      checked: false,
      hidden: false,
      className: "",
      innerHTML: "",
      textContent: "",
      content: { firstElementChild: null },
      children: [],
      listeners,
      addEventListener(type, handler) {
        if (!listeners[type]) listeners[type] = [];
        listeners[type].push(handler);
      },
      removeEventListener() {},
      appendChild(child) {
        this.children.push(child);
        return child;
      },
      setAttribute() {},
      getAttribute() { return null; },
      querySelector() { return null; },
      querySelectorAll() { return []; },
      contains() { return false; },
      closest() { return null; },
    };
  }

  const document = {
    activeElement: null,
    getElementById(id) {
      const key = String(id);
      if (!elements.has(key)) elements.set(key, element(key));
      return elements.get(key);
    },
    createElement: (tag) => element(String(tag)),
    querySelector: () => null,
    querySelectorAll: () => [],
  };

  const answer = (body) => ({ ok: true, status: 200, text: async () => JSON.stringify(body) });
  const fetches = [];
  const sandbox = {
    document,
    fetch(url, init) {
      fetches.push({ url: String(url), init: init || {} });
      if (String(url).endsWith("/panel")) {
        return Object.hasOwn(settings, "panelState") && settings.panelState !== undefined
          ? Promise.resolve(answer(settings.panelState))
          : new Promise(() => {});
      }
      return Promise.resolve(answer({ ok: true, projects: [] }));
    },
    setInterval() { return 1; },
    clearInterval() {},
    setTimeout() { return 1; },
    clearTimeout() {},
    console,
  };
  vm.createContext(sandbox);
  sandbox.window = sandbox;
  vm.runInContext(page.scripts, sandbox);

  const flush = async () => {
    for (let i = 0; i < 4; i += 1) await new Promise((resolve) => setImmediate(resolve));
  };

  return {
    fetches,
    flush,
    el: (id) => document.getElementById(String(id)),
    /** Let the switches form's own submit listener run, as pressing Save does. */
    submit() {
      const form = elements.get("cb-switches");
      assert.ok(form, "the page carries the switches form");
      const handlers = form.listeners.submit || [];
      assert.ok(handlers.length > 0, "the page listens for the switches form's submit");
      for (const handler of handlers) handler({ preventDefault() {} });
    },
    /** Every POST /switches body the page sent, decoded. */
    switchBodies: () =>
      fetches
        .filter((call) => call.init.method === "POST" && String(call.url).endsWith("/api/coinbase/switches"))
        .map((call) => JSON.parse(call.init.body)),
    /**
     * Press one button on one bot card: the #cb-bots click listener runs with a fake button and
     * the card it sits in. `fields` is what the card's inputs hold, by `data-field` name, as the
     * input objects the handler reads (`{ value }` for a box, `{ checked }` for a tick box); a
     * name left out is an input the card does not carry.
     */
    clickBot(act, botId, fields = {}) {
      const box = document.getElementById("cb-bots");
      const handlers = box.listeners.click || [];
      assert.ok(handlers.length > 0, "the page listens for clicks in the bots box");
      const card = {
        getAttribute(name) { return name === "data-bot" ? String(botId) : null; },
        querySelector(selector) {
          const match = /^\[data-field="([^"]+)"\]$/.exec(String(selector));
          if (!match) return null;
          return Object.hasOwn(fields, match[1]) ? fields[match[1]] : null;
        },
      };
      const button = {
        getAttribute(name) { return name === "data-act" ? String(act) : null; },
        closest(selector) { return selector === ".cb-bot" ? card : null; },
      };
      const event = {
        target: { closest: (selector) => (selector === "button[data-act]" ? button : null) },
      };
      for (const handler of handlers) handler(event);
    },
    /** Every POST .../mode body the page sent, decoded. */
    modeBodies: () =>
      fetches
        .filter((call) => call.init.method === "POST" && /\/bots\/[^/]+\/mode$/.test(String(call.url)))
        .map((call) => JSON.parse(call.init.body)),
  };
}

// ---- 1. every privileged action needs 2FA switched on -----------------------------------------

test("test_privileged_refused_without_2fa", async () => {
  const h = await scaffold({ twoFactor: false });
  try {
    h.fake.state.bots = [fakeBot({ id: "bot-live1", mode: "live" })];
    h.fake.state.previews = [fakePreview({ preview_id: "pv-1" })];

    const attempts = [
      ["/api/coinbase/caps", { caps: { [CAP.DAILY]: "100" }, totp: TOTP }],
      ["/api/coinbase/switches", { live_enabled: true, totp: TOTP }],
      ["/api/coinbase/bots/bot-live1/mode", { mode: "live", acknowledge_live: true, capital_quote: "10.00", totp: TOTP }],
      ["/api/coinbase/halt/clear", { acknowledge_rebase: true, totp: TOTP }],
      ["/api/coinbase/bots/bot-live1/resume", { acknowledge_rebase: true, totp: TOTP }],
      ["/api/coinbase/previews/pv-1/approve", { hash: "a".repeat(64), totp: TOTP }],
    ];

    for (const [path, body] of attempts) {
      const r = await h.post(path, body);
      assert.equal(r.status, 403, `${path}: ${r.text}`);
      assert.equal(r.json?.ok, false, path);
      assert.equal(r.json?.code, "two_factor_required", path);
      assert.equal(r.json?.message, TWO_FACTOR_MESSAGE, path);
    }

    // A live-bot resume reads the engine's own bot list to learn which book the bot is on before
    // the full gate runs, so reads may reach it; nothing that could act on the account may.
    const writes = h.fake.state.requests.filter((record) => record.method !== "GET");
    assert.deepEqual(writes, [], "no engine call other than a read was made");
  } finally {
    await h.close();
  }
});

// ---- 2. a peer session gets nothing ------------------------------------------------------------

test("test_privileged_refused_for_peer_session", async () => {
  const h = await scaffold({ isLocal: false });
  try {
    const attempts = [
      ["GET", "/api/coinbase/panel"],
      ["GET", "/api/coinbase/projects"],
      ["GET", "/api/coinbase/connect/state"],
      ["POST", "/api/coinbase/connect/test", { key_name: KEY_NAME, private_key: PRIVATE_KEY, totp: TOTP }],
      ["POST", "/api/coinbase/kill", { confirm: true }],
      ["POST", "/api/coinbase/caps", { caps: {}, totp: TOTP }],
      ["POST", "/api/coinbase/switches", { live_enabled: true, totp: TOTP }],
      ["POST", "/api/coinbase/bots", { product: "BTC-USDC", strategy: "rebalance" }],
      ["POST", "/api/coinbase/bots/bot-1/pause"],
      ["POST", "/api/coinbase/bots/bot-1/stop"],
      ["POST", "/api/coinbase/bots/bot-1/mode", { mode: "live", acknowledge_live: true, totp: TOTP }],
      ["POST", "/api/coinbase/bots/bot-1/resume", { acknowledge_rebase: true, totp: TOTP }],
      ["POST", "/api/coinbase/bots/bot-1/recenter", { center: "100", totp: TOTP }],
      ["POST", "/api/coinbase/halt/clear", { acknowledge_rebase: true, totp: TOTP }],
      ["POST", "/api/coinbase/previews/pv-1/approve", { hash: "a".repeat(64), totp: TOTP }],
      ["POST", "/api/coinbase/previews/pv-1/reject", {}],
    ];

    for (const [method, path, body] of attempts) {
      const r = method === "GET" ? await h.get(path) : await h.post(path, body);
      assert.equal(r.status, 403, `${method} ${path}: ${r.text}`);
      assert.equal(r.json?.ok, false, `${method} ${path}`);
      assert.equal(r.json?.code, LOCAL_LOGIN_CODE, `${method} ${path}`);
    }

    assert.equal(h.fake.state.requests.length, 0, "the engine was never asked");
  } finally {
    await h.close();
  }
});

// ---- 3. a fresh code, and one code is never used twice ----------------------------------------

test("test_privileged_needs_fresh_code", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);

    const capsBody = (totp) => ({ caps: { [CAP.DAILY]: "150" }, totp });

    const wrong = await h.post("/api/coinbase/caps", capsBody("000000"));
    assert.equal(wrong.status, 403, wrong.text);
    assert.equal(wrong.json?.code, "totp_required");
    assert.equal(wrong.json?.message, TOTP_REQUIRED_MESSAGE);

    const empty = await h.post("/api/coinbase/caps", capsBody(""));
    assert.equal(empty.status, 403, empty.text);
    assert.equal(empty.json?.code, "totp_required");
    assert.equal(empty.json?.message, TOTP_REQUIRED_MESSAGE);

    const code = h.freshCode();
    const accepted = await h.post("/api/coinbase/caps", capsBody(code));
    assert.equal(accepted.status, 200, accepted.text);

    const reused = await h.post("/api/coinbase/caps", capsBody(code));
    assert.equal(reused.status, 403, reused.text);
    assert.equal(reused.json?.code, "totp_required", "the gate refuses a code it already accepted");

    assert.equal(h.fake.calls("POST", "/caps").length, 1, "only the accepted call reached the engine");

    let last = null;
    for (let attempt = 0; attempt < 6; attempt += 1) {
      last = await h.post("/api/coinbase/caps", capsBody("000000"));
    }
    assert.equal(last.status, 429, last.text);
    assert.equal(last.json?.ok, false);
    assert.equal(last.json?.code, "step_up_locked");
    assert.equal(last.json?.message, STEP_UP_LOCKED_MESSAGE);
    assert.equal(h.fake.calls("POST", "/caps").length, 1, "a locked gate sends nothing");
  } finally {
    await h.close();
  }
});

// ---- 4. privileged calls are signed with the sealed owner secret ------------------------------

test("test_privileged_signed_with_sealed_secret", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);

    const created = await h.post("/api/coinbase/bots", { product: "BTC-USDC", strategy: "rebalance" });
    assert.ok(created.status === 200 || created.status === 201, created.text);
    const botId = createdBotBody(h.fake).id;

    const switches = await h.post("/api/coinbase/switches", { live_enabled: true, totp: h.freshCode() });
    assert.equal(switches.status, 200, switches.text);

    const mode = await h.post(`/api/coinbase/bots/${botId}/mode`, {
      mode: "live",
      acknowledge_live: true,
      capital_quote: "10.00",
      capital_base: "0",
      totp: h.freshCode(),
    });
    assert.equal(mode.status, 200, mode.text);

    const caps = await h.post("/api/coinbase/caps", { caps: { [CAP.DAILY]: "150" }, totp: h.freshCode() });
    assert.equal(caps.status, 200, caps.text);

    const cleared = await h.post("/api/coinbase/halt/clear", { acknowledge_rebase: true, totp: h.freshCode() });
    assert.equal(cleared.status, 200, cleared.text);

    const signed = [
      ["POST", "/switches"],
      ["POST", `/bots/${botId}/mode`],
      ["POST", "/caps"],
      ["POST", "/halt/clear"],
    ];
    for (const [method, path] of signed) {
      const record = h.fake.last(method, path);
      assert.ok(record, `${path} reached the engine`);
      assert.equal(record.mac, "owner", `${path} was signed with the sealed owner secret`);
    }

    // The browser never carries the MAC key, the engine token or the install token; the key the
    // owner pasted rides only in the connect body, which is the owner typing it.
    const sealed = [h.fake.state.pinSecret, ENGINE_TOKEN, INSTALL_TOKEN, PRIVATE_KEY, KEY_NAME];
    for (const exchange of h.exchanges) {
      if (exchange.method !== "POST") continue;
      if (exchange.path === "/api/coinbase/connect") continue;
      assertCarriesNoSecret(exchange.requestBody, sealed, exchange.path);
    }
  } finally {
    await h.close();
  }
});

// ---- 5. no secret ever reaches the browser ----------------------------------------------------

test("test_secret_never_sent_to_browser", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    await h.get("/api/coinbase/panel");
    await h.get("/api/coinbase/projects");
    await h.post("/api/coinbase/kill", { confirm: true });

    const page = await renderPanelPage();
    const secrets = [KEY_NAME, PRIVATE_KEY, h.fake.state.pinSecret, ENGINE_TOKEN, INSTALL_TOKEN];

    for (const exchange of h.exchanges) {
      assertCarriesNoSecret(exchange.responseText, secrets, `${exchange.method} ${exchange.path} answer`);
    }
    assertCarriesNoSecret(page.content + page.scripts, secrets, "the page");
  } finally {
    await h.close();
  }
});

// ---- 6. the panel shows the last four characters of each fingerprint --------------------------

test("test_panel_shows_last4_only", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    const connection = panel.json.connection;
    assert.equal(connection.connected, true);
    assert.equal(connection.key_last4, h.fake.state.keyLast4);
    assert.equal(connection.portfolio_last4, h.fake.state.portfolioLast4);
    assert.equal(connection.key_last4.length, 4);
    assert.equal(connection.portfolio_last4.length, 4);
    assert.match(String(connection.message), /portfolio/i);
    assert.equal(panel.text.includes(KEY_NAME), false);
    assert.equal(panel.text.includes(PRIVATE_KEY), false);
  } finally {
    await h.close();
  }
});

// ---- 7. the kill switch takes one confirmation and no code ------------------------------------

test("test_kill_requires_confirm", async () => {
  const h = await scaffold();
  try {
    const refused = await h.post("/api/coinbase/kill", {});
    assert.equal(refused.status, 400, refused.text);
    assert.equal(refused.json?.ok, false);
    assert.equal(refused.json?.code, "confirm_required");
    assert.equal(refused.json?.message, KILL_CONFIRM_MESSAGE);
    assert.equal(h.fake.calls("POST", "/kill").length, 0, "nothing was stopped");

    const killed = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(killed.status, 200, killed.text);
    assert.equal(killed.json?.ok, true);
    assert.match(String(killed.json?.message), /Resume trading/);

    const records = h.fake.calls("POST", "/kill");
    assert.equal(records.length, 1);
    assert.equal(records[0].mac, "none", "the kill switch is never blocked by an approval");
  } finally {
    await h.close();
  }
});

// ---- 8. the kill switch is local-session only, and never queues behind a connect --------------

test("test_kill_needs_no_code_and_no_2fa", async () => {
  const h = await scaffold();
  try {
    const hold = h.fake.holdNext("POST", "/credentials");
    const connecting = h.connect();
    await waitFor(() => h.fake.calls("POST", "/credentials").length === 1);

    // The connect is past its gate and holds the connect mutex; the kill cannot wait for it.
    h.flags.twoFactor = false;
    const killed = await within(h.post("/api/coinbase/kill", { confirm: true }), "kill during connect");
    assert.equal(killed.status, 200, killed.text);
    assert.equal(killed.json?.ok, true);
    assert.equal(h.fake.calls("POST", "/kill").length, 1, "the kill reached the engine mid-connect");

    hold.release();
    const connected = await within(connecting, "connect");
    assert.equal(connected.status, 200, connected.text);

    h.flags.isLocal = false;
    const peer = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(peer.status, 403, peer.text);
    assert.equal(peer.json?.code, LOCAL_LOGIN_CODE);
    assert.equal(h.fake.calls("POST", "/kill").length, 1, "a peer's kill never reached the engine");
  } finally {
    await h.close();
  }
});

// ---- 9. the kill answer and the panel say the engine cannot cancel yet ------------------------

test("test_kill_note_when_credentials_not_ready", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    h.fake.state.credentials = "not_ready";

    const killed = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(killed.status, 200, killed.text);
    assert.ok(String(killed.json?.message).includes(KILL_NOT_READY_MESSAGE), killed.text);

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.engine.reachable, true);
    assert.equal(panel.json.engine.credentials, "not_ready");
    assert.equal(panel.json.engine.note, KILL_NOT_READY_MESSAGE);
  } finally {
    await h.close();
  }
});

// ---- 10. Resume trading clears the halt, with a code and a signature --------------------------

test("test_halt_clear_after_kill", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    assert.equal((await h.post("/api/coinbase/kill", { confirm: true })).status, 200);

    const halted = await h.get("/api/coinbase/panel");
    assert.equal(halted.status, 200, halted.text);
    assert.equal(halted.json.engine.halted, true);

    const noCode = await h.post("/api/coinbase/halt/clear", { acknowledge_rebase: true });
    assert.equal(noCode.status, 403, noCode.text);
    assert.equal(noCode.json?.code, "totp_required");
    assert.equal(h.fake.calls("POST", "/halt/clear").length, 0, "nothing cleared without a code");

    const cleared = await h.post("/api/coinbase/halt/clear", {
      acknowledge_rebase: true,
      totp: h.freshCode(),
    });
    assert.equal(cleared.status, 200, cleared.text);
    assert.equal(cleared.json?.message, MESSAGE_HALT_CLEARED);

    const records = h.fake.calls("POST", "/halt/clear");
    assert.equal(records.length, 1);
    assert.equal(records[0].mac, "owner");
    assert.deepEqual(JSON.parse(records[0].body), { acknowledge_rebase: true });

    const after = await h.get("/api/coinbase/panel");
    assert.equal(after.json.engine.halted, false);
  } finally {
    await h.close();
  }
});

// ---- 11. pause and stop need only a local session ---------------------------------------------

test("test_pause_stop_need_only_local_session", async () => {
  const h = await scaffold({ twoFactor: false });
  try {
    h.fake.state.bots = [fakeBot({ id: "bot-pause1" })];

    const paused = await h.post("/api/coinbase/bots/bot-pause1/pause");
    assert.equal(paused.status, 200, paused.text);
    assert.equal(paused.json?.ok, true);
    const pauseRecords = h.fake.calls("POST", "/bots/bot-pause1/pause");
    assert.equal(pauseRecords.length, 1);
    assert.equal(pauseRecords[0].mac, "none", "pause is a bearer-only call");

    const stopped = await h.post("/api/coinbase/bots/bot-pause1/stop");
    assert.equal(stopped.status, 200, stopped.text);
    assert.equal(stopped.json?.ok, true);
    assert.equal(h.fake.calls("POST", "/bots/bot-pause1/stop").length, 1);
  } finally {
    await h.close();
  }
});

// ---- 11a. pause cancels the bot's waiting orders, and says so in the owner's words -----------

test("test_pause_success_copy_cancelled_waiting_orders", async () => {
  const h = await scaffold();
  try {
    h.fake.state.bots = [fakeBot({ id: "bot-pause2", status: "ACTIVE" })];
    h.fake.state.orders.dry = [fakeOrder({ bot: "bot-pause2", client_order_id: "cid-pause-0001" })];

    const paused = await h.post("/api/coinbase/bots/bot-pause2/pause");
    assert.equal(paused.status, 200, paused.text);
    assert.equal(paused.json?.ok, true);
    assert.equal(
      paused.json?.message,
      MESSAGE_BOT_PAUSED,
      "the answer says the waiting orders were cancelled and no new ones are placed",
    );
    assert.equal(paused.json?.bot?.status, "PAUSED", "the engine's own bot row comes back");

    const records = h.fake.calls("POST", "/bots/bot-pause2/pause");
    assert.equal(records.length, 1, "the engine was asked once");
    assert.equal(records[0].mac, "none", "pause stays a bearer-only call");
    assert.equal(
      paused.text.includes("cid-pause-0001"),
      false,
      "no client order id reaches the page",
    );
  } finally {
    await h.close();
  }
});

// ---- 11a-bis. a pause the engine could not finish keeps its code and hides its words ----------

test("test_pause_incomplete_502_keeps_code_and_hides_engine_words", async () => {
  const h = await scaffold();
  try {
    h.fake.state.bots = [fakeBot({ id: "bot-pause3", status: "ACTIVE" })];
    h.fake.state.orders.dry = [fakeOrder({ bot: "bot-pause3" })];

    // The engine's own detail carries exchange wording and a machine code after the fixed prefix.
    const engineWords = "Coinbase refused the cancel: RATE_LIMITED upstream-wording-9f31";
    h.fake.next("POST", "/bots/bot-pause3/pause", {
      status: 502,
      body: { code: "PAUSE_INCOMPLETE", detail: `PAUSE_INCOMPLETE: ${engineWords}` },
    });

    const paused = await h.post("/api/coinbase/bots/bot-pause3/pause");
    assert.equal(paused.status, 502, paused.text);
    assert.equal(paused.json?.ok, false, "a pause that could not finish is never a success");
    assert.equal(paused.json?.code, "PAUSE_INCOMPLETE", "the machine code is kept");
    assert.equal(
      paused.json?.message,
      MESSAGE_BOT_PAUSE_INCOMPLETE,
      "the page gets the fixed sentence, not the engine's",
    );
    assert.equal(
      paused.text.includes(engineWords),
      false,
      "none of the engine's own words reach the page",
    );
    assert.equal(paused.text.includes("RATE_LIMITED"), false, "no engine code leaks into the sentence");
    assert.equal(paused.text.includes("PAUSE_INCOMPLETE:"), false, "the engine's detail is not repeated");
  } finally {
    await h.close();
  }
});

// ---- 11a-ter. a Pause pressed moments after the last one is answered in the page's own words --

test("test_pause_too_soon_plain_sentence", async () => {
  const h = await scaffold();
  try {
    h.fake.state.bots = [fakeBot({ id: "bot-pause4", status: "PAUSED" })];

    // The engine's own detail carries a machine code and its own made-up sentence after it.
    const engineWords = "engine-wording-2b7c: the pause debounce tripped";
    h.fake.next("POST", "/bots/bot-pause4/pause", {
      status: 429,
      body: { detail: `PAUSE_TOO_SOON: ${engineWords}` },
    });

    const tooSoon = await h.post("/api/coinbase/bots/bot-pause4/pause");
    assert.equal(tooSoon.status, 429, tooSoon.text);
    assert.equal(tooSoon.json?.ok, false, "a debounced pause is never a success");
    assert.equal(tooSoon.json?.code, "PAUSE_TOO_SOON", "the machine code is kept");
    assert.equal(
      tooSoon.json?.message,
      MESSAGE_BOT_PAUSE_TOO_SOON,
      "the page gets its own sentence, not the engine's",
    );
    assert.equal(tooSoon.text.includes(engineWords), false, "no engine wording reaches the page");
    assert.equal(
      tooSoon.text.includes("PAUSE_TOO_SOON:"),
      false,
      "the engine's detail is not repeated",
    );
  } finally {
    await h.close();
  }
});

// ---- 11a-quater. calling resume or recenter while a pause runs is one plain sentence --------

test("test_resume_pause_in_progress_plain_sentence", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    h.fake.state.bots = [fakeBot({ id: "bot-race1", status: "PAUSED" })];

    // The engine's own detail carries a machine code and its own made-up sentence after it.
    const engineWords = "engine-wording-8d2a: the runner is still sweeping this bot";
    h.fake.next("POST", "/bots/bot-race1/resume", {
      status: 409,
      body: { detail: `PAUSE_IN_PROGRESS: ${engineWords}` },
    });

    const resumed = await h.post("/api/coinbase/bots/bot-race1/resume", { acknowledge_rebase: true });
    assert.equal(resumed.status, 409, resumed.text);
    assert.equal(resumed.json?.ok, false, "a resume while a pause runs is never a success");
    assert.equal(resumed.json?.code, "PAUSE_IN_PROGRESS", "the machine code is kept");
    assert.equal(
      resumed.json?.message,
      MESSAGE_PAUSE_IN_PROGRESS,
      "the page gets its own sentence, not the engine's",
    );
    assert.equal(resumed.text.includes(engineWords), false, "no engine wording reaches the page");
    assert.equal(
      resumed.text.includes("PAUSE_IN_PROGRESS:"),
      false,
      "the engine's detail is not repeated",
    );

    // The recenter route runs through the same mapping.
    const recenterWords = "engine-wording-31fe: still sweeping this bot";
    h.fake.next("POST", "/bots/bot-race1/recenter", {
      status: 409,
      body: { detail: `PAUSE_IN_PROGRESS: ${recenterWords}` },
    });
    const recentered = await h.post("/api/coinbase/bots/bot-race1/recenter", { center: "60000" });
    assert.equal(recentered.status, 409, recentered.text);
    assert.equal(recentered.json?.ok, false);
    assert.equal(recentered.json?.code, "PAUSE_IN_PROGRESS", "the machine code is kept");
    assert.equal(recentered.json?.message, MESSAGE_PAUSE_IN_PROGRESS);
    assert.equal(recentered.text.includes(recenterWords), false, "no engine wording reaches the page");
  } finally {
    await h.close();
  }
});

// ---- 11a-quinquies. a bot that changed while it was paused says so in the page's words ------

test("test_pause_changed_plain_sentence", async () => {
  const h = await scaffold();
  try {
    h.fake.state.bots = [fakeBot({ id: "bot-race2", status: "ACTIVE" })];

    // The engine's own detail carries a machine code and its own made-up sentence after it.
    const engineWords = "engine-wording-5b9c: the bot was edited mid-sweep";
    h.fake.next("POST", "/bots/bot-race2/pause", {
      status: 409,
      body: { detail: `PAUSE_CHANGED: ${engineWords}` },
    });

    const paused = await h.post("/api/coinbase/bots/bot-race2/pause");
    assert.equal(paused.status, 409, paused.text);
    assert.equal(paused.json?.ok, false, "a pause that raced a change is never a success");
    assert.equal(paused.json?.code, "PAUSE_CHANGED", "the machine code is kept");
    assert.equal(
      paused.json?.message,
      MESSAGE_PAUSE_CHANGED,
      "the page gets its own sentence, not the engine's",
    );
    assert.equal(paused.text.includes(engineWords), false, "no engine wording reaches the page");
    assert.equal(
      paused.text.includes("PAUSE_CHANGED:"),
      false,
      "the engine's detail is not repeated",
    );
    assert.equal(h.fake.calls("POST", "/bots/bot-race2/pause").length, 1, "the engine was asked once");
  } finally {
    await h.close();
  }
});

// ---- 11b. back to practice needs the local session only, and sends no capital --------------

test("test_back_to_practice_needs_local_session_only", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    h.fake.state.bots = [fakeBot({ id: "bot-back1", mode: "live" })];

    // Two-factor sign-in off, no code at all: moving a bot back to practice still works.
    h.flags.twoFactor = false;
    const switched = await h.post("/api/coinbase/bots/bot-back1/mode", { mode: "dry" });
    assert.equal(switched.status, 200, switched.text);
    assert.equal(switched.json?.ok, true);
    assert.equal(switched.json?.message, MESSAGE_BOT_PRACTICE);

    const records = h.fake.calls("POST", "/bots/bot-back1/mode");
    assert.equal(records.length, 1, "the engine was asked once");
    assert.deepEqual(JSON.parse(records[0].body), { mode: "dry" }, "a dry switch carries no capital");
    assert.equal(records[0].mac, "owner", "the engine's own route still takes the owner's signature");

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    const shown = (panel.json.bots || []).find((row) => row.id === "bot-back1");
    assert.ok(shown, "the bot is still listed");
    assert.equal(shown.badge, "PRACTICE");

    // Going the other way is unchanged: two-factor off refuses a live switch, and the engine is
    // never asked.
    const live = await h.post("/api/coinbase/bots/bot-back1/mode", {
      mode: "live",
      acknowledge_live: true,
    });
    assert.equal(live.status, 403, live.text);
    assert.equal(live.json?.code, "two_factor_required");
    assert.equal(h.fake.calls("POST", "/bots/bot-back1/mode").length, 1, "nothing reached the engine");

    // A mode that is neither is answered only after the local session check, then as a 400.
    h.flags.isLocal = false;
    const peer = await h.post("/api/coinbase/bots/bot-back1/mode", { mode: "dry" });
    assert.equal(peer.status, 403, peer.text);
    assert.equal(peer.json?.code, LOCAL_LOGIN_CODE);
    const peerBogus = await h.post("/api/coinbase/bots/bot-back1/mode", { mode: "sideways" });
    assert.equal(peerBogus.status, 403, peerBogus.text);
    assert.equal(peerBogus.json?.code, LOCAL_LOGIN_CODE);
    assert.equal(h.fake.calls("POST", "/bots/bot-back1/mode").length, 1, "a peer's switch never reached the engine");

    h.flags.isLocal = true;
    const bogus = await h.post("/api/coinbase/bots/bot-back1/mode", { mode: "sideways" });
    assert.equal(bogus.status, 400, bogus.text);
    assert.equal(bogus.json?.code, "invalid");
    assert.equal(bogus.json?.message, "Choose Practice or Live.");
    assert.equal(h.fake.calls("POST", "/bots/bot-back1/mode").length, 1, "an invalid mode sends nothing");
  } finally {
    await h.close();
  }
});

// ---- 11c. a Go-live switch carries the starting coin amount the owner typed -------------------

test("test_live_mode_carries_the_starting_coin_amount", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    h.fake.state.bots = [fakeBot({ id: "bot-coin1", mode: "dry" })];

    const switched = await h.post("/api/coinbase/bots/bot-coin1/mode", {
      mode: "live",
      acknowledge_live: true,
      capital_quote: "10.00",
      capital_base: "0.25",
      totp: h.freshCode(),
    });
    assert.equal(switched.status, 200, switched.text);
    const records = h.fake.calls("POST", "/bots/bot-coin1/mode");
    assert.equal(records.length, 1, "the engine was asked once");
    const body = JSON.parse(records[0].body);
    assert.equal(body.capital_base, "0.25", "the coin amount reached the engine as text");
    assert.equal(body.capital_quote, "10.00", "the starting money is unchanged");

    // A negative starting coin is refused here, in plain words, and the engine never hears of it.
    const negative = await h.post("/api/coinbase/bots/bot-coin1/mode", {
      mode: "live",
      acknowledge_live: true,
      capital_quote: "10.00",
      capital_base: "-1",
      totp: h.freshCode(),
    });
    assert.equal(negative.status, 400, negative.text);
    assert.equal(negative.json?.ok, false);
    assert.equal(negative.json?.code, "invalid");
    assert.equal(negative.json?.message, "Starting coin must be zero or more.");
    assert.equal(h.fake.calls("POST", "/bots/bot-coin1/mode").length, 1, "nothing reached the engine");
  } finally {
    await h.close();
  }
});

// ---- 11c-2. a capital value has to be a plain non-negative decimal --------------------------

test("test_live_mode_refuses_non_plain_capital", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    h.fake.state.bots = [fakeBot({ id: "bot-plain1", mode: "dry" })];

    const badBases = [-1e21, "1e9", "-0.5", "NaN", "Infinity", 1e21];
    for (const capitalBase of badBases) {
      const answer = await h.post("/api/coinbase/bots/bot-plain1/mode", {
        mode: "live",
        acknowledge_live: true,
        capital_quote: "10.00",
        capital_base: capitalBase,
        totp: h.freshCode(),
      });
      assert.equal(answer.status, 400, `${String(capitalBase)}: ${answer.text}`);
      assert.equal(answer.json?.ok, false);
      assert.equal(answer.json?.code, "invalid");
      assert.equal(answer.json?.message, "Starting coin must be zero or more.");
      assert.equal(h.fake.calls("POST", "/bots/bot-plain1/mode").length, 0, "nothing reached the engine");
    }

    // The starting money is held to the same shape, in the number sentence.
    const badQuote = await h.post("/api/coinbase/bots/bot-plain1/mode", {
      mode: "live",
      acknowledge_live: true,
      capital_quote: "1e9",
      capital_base: "0",
      totp: h.freshCode(),
    });
    assert.equal(badQuote.status, 400, badQuote.text);
    assert.equal(badQuote.json?.ok, false);
    assert.equal(badQuote.json?.code, "invalid");
    assert.equal(badQuote.json?.message, "That is not a number Crow can use.");
    assert.equal(h.fake.calls("POST", "/bots/bot-plain1/mode").length, 0, "nothing reached the engine");

    // A plain value goes through, and reaches the engine as text.
    for (const capitalBase of ["0", "12.5"]) {
      h.fake.state.bots = [fakeBot({ id: "bot-plain1", mode: "dry" })];
      const before = h.fake.calls("POST", "/bots/bot-plain1/mode").length;
      const switched = await h.post("/api/coinbase/bots/bot-plain1/mode", {
        mode: "live",
        acknowledge_live: true,
        capital_quote: "10.00",
        capital_base: capitalBase,
        totp: h.freshCode(),
      });
      assert.equal(switched.status, 200, switched.text);
      const records = h.fake.calls("POST", "/bots/bot-plain1/mode");
      assert.equal(records.length - before, 1, "the engine was asked once");
      const body = JSON.parse(records[records.length - 1].body);
      assert.equal(body.capital_base, capitalBase, "the coin amount reached the engine as text");
      assert.equal(body.capital_quote, "10.00");
    }
  } finally {
    await h.close();
  }
});

// ---- 11d. Practice resume and recenter need the local session only; Live keeps the full gate --

test("test_practice_resume_recenter_need_local_session_only", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    h.fake.state.bots = [
      fakeBot({ id: "bot-practice2", mode: "dry", status: "PAUSED" }),
      fakeBot({ id: "bot-live3", mode: "live", status: "PAUSED" }),
    ];

    // Two-factor sign-in off, no code at all: a Practice bot starts again and moves its middle.
    h.flags.twoFactor = false;
    const resumed = await h.post("/api/coinbase/bots/bot-practice2/resume", { acknowledge_rebase: true });
    assert.equal(resumed.status, 200, resumed.text);
    assert.equal(resumed.json?.ok, true);
    assert.equal(h.fake.calls("POST", "/bots/bot-practice2/resume").length, 1, "the practice resume ran");

    const recentered = await h.post("/api/coinbase/bots/bot-practice2/recenter", { center: "60000" });
    assert.equal(recentered.status, 200, recentered.text);
    assert.equal(recentered.json?.ok, true);
    assert.equal(h.fake.calls("POST", "/bots/bot-practice2/recenter").length, 1, "the practice recenter ran");

    // The same two actions on a Live bot are privileged: with two-factor off they are refused,
    // and the engine's own resume/recenter never runs.
    const liveResume = await h.post("/api/coinbase/bots/bot-live3/resume", { acknowledge_rebase: true });
    assert.equal(liveResume.status, 403, liveResume.text);
    assert.equal(liveResume.json?.ok, false);
    assert.equal(liveResume.json?.code, "two_factor_required");
    assert.equal(liveResume.json?.message, TWO_FACTOR_MESSAGE);
    assert.equal(h.fake.calls("POST", "/bots/bot-live3/resume").length, 0, "a live resume never reached the engine");

    const liveRecenter = await h.post("/api/coinbase/bots/bot-live3/recenter", { center: "60000" });
    assert.equal(liveRecenter.status, 403, liveRecenter.text);
    assert.equal(liveRecenter.json?.code, "two_factor_required");
    assert.equal(h.fake.calls("POST", "/bots/bot-live3/recenter").length, 0, "a live recenter never reached the engine");

    // With two-factor on, a Live resume still needs a fresh code.
    h.flags.twoFactor = true;
    const noCode = await h.post("/api/coinbase/bots/bot-live3/resume", { acknowledge_rebase: true });
    assert.equal(noCode.status, 403, noCode.text);
    assert.equal(noCode.json?.code, "totp_required");
    assert.equal(noCode.json?.message, TOTP_REQUIRED_MESSAGE);
    assert.equal(h.fake.calls("POST", "/bots/bot-live3/resume").length, 0, "still nothing reached the engine");

    const withCode = await h.post("/api/coinbase/bots/bot-live3/resume", {
      acknowledge_rebase: true,
      totp: h.freshCode(),
    });
    assert.equal(withCode.status, 200, withCode.text);
    assert.equal(h.fake.calls("POST", "/bots/bot-live3/resume").length, 1, "the live resume ran once gated");
  } finally {
    await h.close();
  }
});

// ---- 11e. a bot row whose mode is not exactly "dry" is treated as Live -----------------------

test("test_unknown_bot_mode_is_treated_as_live", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    const odd = fakeBot({ id: "bot-odd1", mode: "LIVE", status: "PAUSED" });
    const missing = fakeBot({ id: "bot-odd2", status: "PAUSED" });
    delete missing.mode;
    h.fake.state.bots = [odd, missing, fakeBot({ id: "bot-dry9", mode: "dry", status: "PAUSED" })];

    // Two-factor off, no code at all: a row that does not say "dry" keeps the full gate.
    h.flags.twoFactor = false;
    for (const id of ["bot-odd1", "bot-odd2"]) {
      const resumed = await h.post(`/api/coinbase/bots/${id}/resume`, { acknowledge_rebase: true });
      assert.equal(resumed.status, 403, resumed.text);
      assert.equal(resumed.json?.ok, false);
      assert.equal(resumed.json?.code, "two_factor_required");
      assert.equal(resumed.json?.message, TWO_FACTOR_MESSAGE);
      assert.equal(h.fake.calls("POST", `/bots/${id}/resume`).length, 0, "nothing reached the engine");

      const recentered = await h.post(`/api/coinbase/bots/${id}/recenter`, { center: "60000" });
      assert.equal(recentered.status, 403, recentered.text);
      assert.equal(recentered.json?.code, "two_factor_required");
      assert.equal(h.fake.calls("POST", `/bots/${id}/recenter`).length, 0, "nothing reached the engine");
    }

    // The row that says "dry" is the control: the local session alone starts it again.
    const practice = await h.post("/api/coinbase/bots/bot-dry9/resume", { acknowledge_rebase: true });
    assert.equal(practice.status, 200, practice.text);
    assert.equal(practice.json?.ok, true);
    assert.equal(h.fake.calls("POST", "/bots/bot-dry9/resume").length, 1);

    // Two-factor on: a fresh code is asked for before either action.
    h.flags.twoFactor = true;
    for (const id of ["bot-odd1", "bot-odd2"]) {
      const noCode = await h.post(`/api/coinbase/bots/${id}/resume`, { acknowledge_rebase: true });
      assert.equal(noCode.status, 403, noCode.text);
      assert.equal(noCode.json?.code, "totp_required");
      assert.equal(noCode.json?.message, TOTP_REQUIRED_MESSAGE);
      assert.equal(h.fake.calls("POST", `/bots/${id}/resume`).length, 0, "nothing reached the engine");
    }

    const withCode = await h.post("/api/coinbase/bots/bot-odd1/resume", {
      acknowledge_rebase: true,
      totp: h.freshCode(),
    });
    assert.equal(withCode.status, 200, withCode.text);
    assert.equal(h.fake.calls("POST", "/bots/bot-odd1/resume").length, 1, "the resume ran once gated");

    const recenterWithCode = await h.post("/api/coinbase/bots/bot-odd2/recenter", {
      center: "60000",
      totp: h.freshCode(),
    });
    assert.equal(recenterWithCode.status, 200, recenterWithCode.text);
    assert.equal(h.fake.calls("POST", "/bots/bot-odd2/recenter").length, 1, "the recenter ran once gated");
  } finally {
    await h.close();
  }
});

// ---- 12. the caps form stops at a ceiling, and money is compared as a decimal -----------------

test("test_caps_form_stops_at_ceiling", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);

    const above = await h.post("/api/coinbase/caps", {
      caps: { [CAP.DAILY]: "200.01" },
      totp: h.freshCode(),
    });
    assert.equal(above.status, 422, above.text);
    assert.equal(above.json?.ok, false);
    assert.equal(above.json?.code, "above_ceiling");
    assert.match(String(above.json?.message), /above the limit/i);
    assert.match(String(above.json?.message), /200/);
    assert.equal(h.fake.calls("POST", "/caps").length, 0, "nothing was sent to the engine");

    // Equal to the ceiling, written with two decimals: a decimal comparison, not a string one.
    const equal = await h.post("/api/coinbase/caps", {
      caps: { [CAP.DAILY]: "200.00" },
      totp: h.freshCode(),
    });
    assert.equal(equal.status, 200, equal.text);
    const accepted = h.fake.calls("POST", "/caps");
    assert.equal(accepted.length, 1);
    assert.equal(Number(JSON.parse(accepted[0].body).caps[CAP.DAILY]), 200);

    const countAbove = await h.post("/api/coinbase/caps", {
      caps: { [CAP.ORDERS]: "31" },
      totp: h.freshCode(),
    });
    assert.equal(countAbove.status, 422, countAbove.text);
    assert.equal(countAbove.json?.code, "above_ceiling");
    assert.equal(h.fake.calls("POST", "/caps").length, 1);

    const countEqual = await h.post("/api/coinbase/caps", {
      caps: { [CAP.ORDERS]: "30" },
      totp: h.freshCode(),
    });
    assert.equal(countEqual.status, 200, countEqual.text);
    assert.equal(h.fake.calls("POST", "/caps").length, 2);
  } finally {
    await h.close();
  }
});

// ---- 14. the panel passes the engine's cap shapes through unchanged ----------------------------

test("test_caps_get_shapes", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);

    const caps = { ...defaultCaps(), [CAP.DAILY]: "123.45", [CAP.ORDERS]: 7, [CAP.DRAWDOWN]: "12.5" };
    const ceilings = { ...defaultCeilings() };
    const usedToday = {
      dry: {
        daily_notional_usd: "12.30",
        ai_daily_notional_usd: "0",
        orders_last_hour: 3,
        ai_orders_last_hour: 0,
      },
      live: {
        daily_notional_usd: "0.00",
        ai_daily_notional_usd: "0",
        orders_last_hour: 0,
        ai_orders_last_hour: 0,
      },
    };
    h.fake.state.caps = caps;
    h.fake.state.ceilings = ceilings;
    h.fake.state.usedToday = usedToday;

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.deepEqual(panel.json.limits.caps, caps);
    assert.deepEqual(panel.json.limits.ceilings, ceilings);
    assert.deepEqual(panel.json.limits.used_today, usedToday);
    assert.equal(typeof panel.json.limits.caps[CAP.DAILY], "string");
    assert.equal(typeof panel.json.limits.caps[CAP.ORDERS], "number");
    assert.equal(typeof panel.json.limits.used_today.dry.orders_last_hour, "number");
  } finally {
    await h.close();
  }
});

// ---- 15. the live switches: they come from the engine, only a turn ON needs a code -------------

test("test_live_switch_on_needs_code_off_does_not", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);

    // Two-factor sign-in off: turning a switch ON is refused before the engine hears of it.
    h.flags.twoFactor = false;
    const refused = await h.post("/api/coinbase/switches", { live_enabled: true });
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.json?.code, "two_factor_required");
    assert.equal(h.fake.calls("POST", "/switches").length, 0);

    h.flags.twoFactor = true;
    const on = await h.post("/api/coinbase/switches", { live_enabled: true, totp: h.freshCode() });
    assert.equal(on.status, 200, on.text);
    const switched = h.fake.calls("POST", "/switches");
    assert.equal(switched.length, 1);
    assert.equal(switched[0].mac, "owner");
    assert.deepEqual(JSON.parse(switched[0].body), { live_enabled: true });

    // The panel reads the switch from the engine's own status, not from anything it stored.
    const shown = await h.get("/api/coinbase/panel");
    assert.equal(shown.status, 200, shown.text);
    assert.equal(shown.json.switches.live_enabled, true);

    // OFF never needs a code, and never needs two-factor sign-in.
    h.flags.twoFactor = false;
    const off = await h.post("/api/coinbase/switches", { live_enabled: false });
    assert.equal(off.status, 200, off.text);
    assert.equal(h.fake.calls("POST", "/switches").length, 2);

    h.flags.twoFactor = true;
    assert.equal((await h.disconnect()).status, 200);

    // A Disconnect keeps no mirror of the switches: there is none to keep.
    const after = await h.get("/api/coinbase/panel");
    assert.equal(after.status, 200, after.text);
    assert.deepEqual(after.json.switches, h.fake.state.switches);
    assert.equal(await h.setting("coinbase_switches"), null, "nothing is written under coinbase_switches");
  } finally {
    await h.close();
  }
});

test("test_switches_read_from_engine_status", async () => {
  const h = await scaffold();
  try {
    // A row an older install would have kept: the panel must neither read it nor write it.
    await h.db.execute({
      sql: "INSERT INTO dashboard_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))",
      args: ["coinbase_switches", JSON.stringify({ live_enabled: false, ai_live_enabled: false, ceiling: true })],
    });
    assert.equal((await h.connect()).status, 200);
    const before = await settingRows(h);
    h.fake.state.switches = { live_enabled: true, ai_live_enabled: false, ceiling: true };

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.deepEqual(panel.json.switches, { live_enabled: true, ai_live_enabled: false, ceiling: true });
    assert.ok(
      h.fake.calls("GET", "/status").length >= 1,
      "the switches came from the engine's own status",
    );

    const after = await settingRows(h);
    assert.deepEqual(after, before, "reading the panel writes no dashboard_settings row");
    assert.equal(
      after.filter((row) => row.key === "coinbase_book_peak").length,
      0,
      "no high-water mark is kept in the database",
    );

    const switched = await h.post("/api/coinbase/switches", { ai_live_enabled: true, totp: h.freshCode() });
    assert.equal(switched.status, 200, switched.text);
    assert.deepEqual(await settingRows(h), before, "saving a switch writes no mirror");
  } finally {
    await h.close();
  }
});

test("test_switch_off_other_stays_on_needs_no_code", async () => {
  const h = await scaffold();
  try {
    h.fake.state.switches = { live_enabled: true, ai_live_enabled: true, ceiling: true };
    assert.equal((await h.connect()).status, 200);

    // Two-factor sign-in is off, no code is sent, and the AI switch goes OFF on its own.
    h.flags.twoFactor = false;
    const aiOff = await h.post("/api/coinbase/switches", { ai_live_enabled: false });
    assert.equal(aiOff.status, 200, aiOff.text);
    assert.equal(aiOff.json?.ok, true);
    const records = h.fake.calls("POST", "/switches");
    assert.equal(records.length, 1);
    assert.deepEqual(JSON.parse(records[0].body), { ai_live_enabled: false });
    assert.equal(h.fake.state.switches.ai_live_enabled, false);
    assert.equal(h.fake.state.switches.live_enabled, true, "the other switch stays on");

    // Live is already on: re-sending true is no change, so no code and no two-factor either.
    const resent = await h.post("/api/coinbase/switches", { live_enabled: true, ai_live_enabled: false });
    assert.equal(resent.status, 200, resent.text);
    assert.equal(resent.json?.ok, true);
    assert.equal(h.fake.state.switches.live_enabled, true);

    // A turn ON from OFF is the privileged case; with two-factor off it is refused first.
    const before = h.fake.calls("POST", "/switches").length;
    const aiOn = await h.post("/api/coinbase/switches", { ai_live_enabled: true });
    assert.equal(aiOn.status, 403, aiOn.text);
    assert.equal(aiOn.json?.code, "two_factor_required");
    assert.equal(h.fake.calls("POST", "/switches").length, before, "nothing reached the engine");

    // With two-factor on, the same turn is refused until a fresh code is there.
    h.flags.twoFactor = true;
    const noCode = await h.post("/api/coinbase/switches", { ai_live_enabled: true });
    assert.equal(noCode.status, 403, noCode.text);
    assert.equal(noCode.json?.code, "totp_required");
    assert.equal(h.fake.calls("POST", "/switches").length, before, "nothing reached the engine");
  } finally {
    await h.close();
  }
});

test("test_switch_messages_per_switch", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);

    const liveOn = await h.post("/api/coinbase/switches", { live_enabled: true, totp: h.freshCode() });
    assert.equal(liveOn.status, 200, liveOn.text);
    assert.equal(liveOn.json?.message, SWITCH_MESSAGE.LIVE_ON);

    const liveOff = await h.post("/api/coinbase/switches", { live_enabled: false });
    assert.equal(liveOff.status, 200, liveOff.text);
    assert.equal(liveOff.json?.message, SWITCH_MESSAGE.LIVE_OFF);

    const aiOn = await h.post("/api/coinbase/switches", { ai_live_enabled: true, totp: h.freshCode() });
    assert.equal(aiOn.status, 200, aiOn.text);
    assert.equal(aiOn.json?.message, SWITCH_MESSAGE.AI_ON);

    const aiOff = await h.post("/api/coinbase/switches", { ai_live_enabled: false });
    assert.equal(aiOff.status, 200, aiOff.text);
    assert.equal(aiOff.json?.message, SWITCH_MESSAGE.AI_OFF);

    // Both changed at once: the two sentences, one space apart.
    const both = await h.post("/api/coinbase/switches", {
      live_enabled: true,
      ai_live_enabled: true,
      totp: h.freshCode(),
    });
    assert.equal(both.status, 200, both.text);
    assert.equal(both.json?.message, `${SWITCH_MESSAGE.LIVE_ON} ${SWITCH_MESSAGE.AI_ON}`);
    assert.equal(h.fake.calls("POST", "/switches").length, 5);

    // Both are already on: nothing is left to send, so nothing is sent and no code is asked for.
    const unchanged = await h.post("/api/coinbase/switches", {
      live_enabled: true,
      ai_live_enabled: true,
    });
    assert.equal(unchanged.status, 200, unchanged.text);
    assert.equal(unchanged.json?.ok, true);
    assert.equal(unchanged.json?.message, SWITCH_UNCHANGED_MESSAGE);
    assert.equal(h.fake.calls("POST", "/switches").length, 5, "nothing was sent for an unchanged save");
  } finally {
    await h.close();
  }
});

// ---- 15b. an OFF is always sent, and a status read that fails decides nothing -------------------

test("test_switch_off_sent_when_status_read_fails", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    // The engine will not say what its switches are: the OFF still goes, and its answer decides.
    h.fake.next("GET", "/status", { status: 500, body: { detail: "the status read failed" } });

    const off = await h.post("/api/coinbase/switches", { live_enabled: false });
    assert.equal(off.status, 200, off.text);
    assert.equal(off.json?.ok, true, off.text);

    const records = h.fake.calls("POST", "/switches");
    assert.equal(records.length, 1, "the OFF reached the engine even though /status failed");
    assert.deepEqual(JSON.parse(records[0].body), { live_enabled: false });

    // The answer is the engine's own result, never an invented one.
    assert.equal(off.json?.message, SWITCH_MESSAGE.LIVE_OFF);
    assert.equal(off.json?.switches?.live_enabled, false);
    assert.equal(h.fake.state.switches.live_enabled, false);
  } finally {
    await h.close();
  }
});

test("test_switch_off_always_sent_even_if_status_says_off", async () => {
  const h = await scaffold();
  try {
    h.fake.state.switches = { live_enabled: false, ai_live_enabled: false, ceiling: true };
    assert.equal((await h.connect()).status, 200);

    const off = await h.post("/api/coinbase/switches", { live_enabled: false });
    assert.equal(off.status, 200, off.text);
    assert.equal(off.json?.ok, true, off.text);
    assert.equal(off.json?.message, SWITCH_MESSAGE.LIVE_OFF);

    const records = h.fake.calls("POST", "/switches");
    assert.equal(records.length, 1, "an OFF is sent whether or not /status says it is already off");
    assert.deepEqual(JSON.parse(records[0].body), { live_enabled: false });
  } finally {
    await h.close();
  }
});

test("test_switch_on_with_failed_status_needs_full_gate", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    // Neither attempt gets a switch state from the engine: an ON then needs the full gate.
    h.fake.next("GET", "/status", { status: 500, body: { detail: "the status read failed" } });
    h.fake.next("GET", "/status", { status: 500, body: { detail: "the status read failed" } });

    const withoutCode = await h.post("/api/coinbase/switches", { live_enabled: true });
    assert.equal(withoutCode.status, 403, withoutCode.text);
    assert.equal(withoutCode.json?.ok, false);
    assert.equal(withoutCode.json?.code, "totp_required");
    assert.equal(h.fake.calls("POST", "/switches").length, 0, "nothing reached the engine without a code");

    const withCode = await h.post("/api/coinbase/switches", {
      live_enabled: true,
      totp: h.freshCode(),
    });
    assert.equal(withCode.status, 200, withCode.text);
    assert.equal(withCode.json?.ok, true, withCode.text);

    const records = h.fake.calls("POST", "/switches");
    assert.equal(records.length, 1, "the ON went once the full gate was met");
    assert.deepEqual(JSON.parse(records[0].body), { live_enabled: true });
    assert.equal(h.fake.state.switches.live_enabled, true);
  } finally {
    await h.close();
  }
});

test("test_switch_on_unpinned_no_connection_409", async () => {
  const h = await scaffold();
  try {
    // Nothing was ever connected: no row here, and the engine holds no pin either.
    assert.equal(h.fake.state.pinned, false, "the engine holds no pin");
    assert.equal((await h.connections()).length, 0, "and this install holds no connection row");

    // Turning something ON with nothing connected is refused, and the engine hears no switch.
    const on = await h.post("/api/coinbase/switches", { live_enabled: true, totp: h.freshCode() });
    assert.equal(on.status, 409, on.text);
    assert.equal(on.json?.ok, false, "a save that switched nothing is never a success");
    assert.equal(on.json?.code, "not_connected");
    assert.equal(on.json?.message, SWITCH_NOT_CONNECTED_MESSAGE);
    assert.equal(h.fake.calls("POST", "/switches").length, 0, "no switch call with nothing connected");

    // The AI switch earns the same answer, with no connection row and no code of its own.
    const ai = await h.post("/api/coinbase/switches", { ai_live_enabled: true, totp: h.freshCode() });
    assert.equal(ai.status, 409, ai.text);
    assert.equal(ai.json?.ok, false);
    assert.equal(ai.json?.code, "not_connected");
    assert.equal(ai.json?.message, SWITCH_NOT_CONNECTED_MESSAGE);
    assert.equal(h.fake.calls("POST", "/switches").length, 0, "still nothing was sent");
  } finally {
    await h.close();
  }
});

test("test_switch_not_connected_client_result_409", async () => {
  const fake = await createFakeEngine();
  // The connection stands and the engine holds its pin, but this install has no sealed owner
  // secret to sign with: the engine client's own answer is NOT_CONNECTED at status 0.
  const h = await scaffold({
    fake,
    engineClientFactory: () => createEngineClient({
      baseUrl: fake.baseUrl,
      token: ENGINE_TOKEN,
      secretProvider: async (kind) => (kind === "install" ? INSTALL_TOKEN : null),
    }),
  });
  try {
    assert.equal((await h.connect()).status, 200);
    assert.equal((await h.connections()).length, 1, "the connection row stands");
    assert.equal(fake.state.pinned, true, "the engine holds the pin");

    const on = await h.post("/api/coinbase/switches", { live_enabled: true, totp: h.freshCode() });
    assert.equal(on.status, 409, on.text);
    assert.equal(on.json?.ok, false);
    assert.equal(on.json?.code, "not_connected", "a missing sealed secret is a state, not a 502");
    assert.equal(on.json?.message, SWITCH_NOT_CONNECTED_MESSAGE);
    assert.notEqual(
      on.json?.message,
      "Trading is not connected",
      "the engine client's own wording never reaches the owner",
    );
    assert.equal(fake.calls("POST", "/switches").length, 0, "with no key there was nothing to send");
  } finally {
    await h.close();
  }
});

test("test_switch_on_not_connected_409", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    // The engine lost its pin: its own health says nothing is connected.
    h.fake.state.pinned = false;

    // Turning something ON with nothing connected is refused, and the engine hears nothing.
    const on = await h.post("/api/coinbase/switches", { live_enabled: true, totp: h.freshCode() });
    assert.equal(on.status, 409, on.text);
    assert.equal(on.json?.ok, false);
    assert.equal(on.json?.code, "not_connected");
    assert.equal(on.json?.message, SWITCH_NOT_CONNECTED_MESSAGE);
    assert.equal(h.fake.calls("POST", "/switches").length, 0, "no switch call with nothing connected");

    // An OFF is still sent. An engine holding no pin refuses the owner's signature outright, and
    // its own refusal is what the page reports.
    const off = await h.post("/api/coinbase/switches", { live_enabled: false });
    const sent = h.fake.calls("POST", "/switches");
    assert.equal(sent.length, 1, "the OFF still reached the engine");
    assert.deepEqual(JSON.parse(sent[0].body), { live_enabled: false });
    assert.equal(sent[0].mac, "none", "an unpinned engine never reads a signature as the owner's");
    assert.equal(off.status, 403, off.text);
    assert.equal(off.json?.ok, false, off.text);
    assert.equal(off.json?.code, "APPROVAL_INVALID", "the engine's own refusal reaches the page");

    // A refusal from the engine is never dressed up as a success.
    h.fake.state.pinned = true;
    h.fake.next("POST", "/switches", { status: 403, body: { detail: "APPROVAL_INVALID" } });
    const refused = await h.post("/api/coinbase/switches", { ai_live_enabled: false });
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.json?.ok, false);
    assert.equal(refused.json?.code, "APPROVAL_INVALID");
  } finally {
    await h.close();
  }
});

test("test_switch_page_script_sends_unchecked_when_last_switches_null", async () => {
  // Before any poll has answered there is nothing to compare against: every unchecked box goes
  // into the body as an OFF, so pressing Save can always turn a switch off.
  const fresh = await runPanelScript();
  fresh.submit();
  const freshBodies = fresh.switchBodies();
  assert.equal(freshBodies.length, 1, "the form posted once");
  assert.deepEqual(freshBodies[0], { live_enabled: false, ai_live_enabled: false });

  // Once a poll has answered, a checked box that is already where the engine has it is not sent.
  const polled = await runPanelScript({
    panelState: {
      switches: { live_enabled: true, ai_live_enabled: false, ceiling: true },
      connection: { connected: true },
      engine: { reachable: true },
      bots: [],
      previews: [],
      recent_previews: [],
      open_orders: { dry: [], live: [] },
      alerts: [],
      fills: [],
      pnl: { bots: {} },
      limits: {},
      products: [],
      drawdown: {},
    },
  });
  await polled.flush();
  assert.equal(polled.el("cb-sw-live").checked, true, "the poll ticked the live box");
  assert.equal(polled.el("cb-sw-ai").checked, false, "the poll left the AI box unticked");

  polled.el("cb-sw-ai").checked = true;
  polled.submit();
  const polledBodies = polled.switchBodies();
  assert.equal(polledBodies.length, 1, "the form posted once");
  assert.equal(
    Object.hasOwn(polledBodies[0], "live_enabled"),
    false,
    "a checked box that did not change is not sent",
  );
  assert.deepEqual(polledBodies[0], { ai_live_enabled: true });
});

// ---- 15c. the Go-live form carries the starting coin amount, and only a decimal goes out ----

test("test_page_go_live_sends_the_starting_coin_amount", async () => {
  // The field is on the card, labelled in the owner's words.
  const page = await renderPanelPage();
  const html = page.content + page.scripts;
  assert.ok(html.includes("Starting coin amount (optional)"), "the form names the starting coin field");
  assert.match(html, /data-field="capital_base" inputmode="decimal"/, "the field is a decimal input");
  assert.ok(
    !/capital_base:\s*"0"/.test(page.scripts),
    "the live body no longer hard-codes the starting coin",
  );

  // A typed amount travels as the decimal text the owner typed.
  const typed = await runPanelScript();
  typed.clickBot("live", "bot-page1", {
    ack: { checked: true },
    capital_quote: { value: "10.00" },
    capital_base: { value: "0.25" },
  });
  await typed.flush();
  const typedBodies = typed.modeBodies();
  assert.equal(typedBodies.length, 1, "the form posted once");
  assert.equal(typedBodies[0].mode, "live");
  assert.equal(typedBodies[0].acknowledge_live, true);
  assert.equal(typedBodies[0].capital_quote, "10.00", "the starting money is unchanged");
  assert.equal(typedBodies[0].capital_base, "0.25");

  // Blank means none of the coin: the engine is told "0".
  const blank = await runPanelScript();
  blank.clickBot("live", "bot-page2", {
    ack: { checked: true },
    capital_quote: { value: "10.00" },
    capital_base: { value: "   " },
  });
  await blank.flush();
  const blankBodies = blank.modeBodies();
  assert.equal(blankBodies.length, 1, "the form posted once");
  assert.equal(blankBodies[0].capital_base, "0");

  // Anything that is not a plain amount is refused in one plain sentence, and nothing is posted.
  for (const text of ["abc", "1,5", "-1", "1e3", "0.1.2"]) {
    const bad = await runPanelScript();
    bad.clickBot("live", "bot-page3", {
      ack: { checked: true },
      capital_quote: { value: "10.00" },
      capital_base: { value: text },
    });
    await bad.flush();
    assert.deepEqual(bad.modeBodies(), [], `nothing was posted for "${text}"`);
    assert.match(
      String(bad.el("cb-say").textContent),
      /not a number Crow can use/i,
      `the owner is told in plain words for "${text}"`,
    );
  }
});

// ---- 16. a new bot is a Practice rebalancer ------------------------------------------------

test("test_create_bot_defaults_to_practice_rebalance", async () => {
  const h = await scaffold();
  try {
    const created = await h.post("/api/coinbase/bots", { product: "BTC-USDC", strategy: "rebalance" });
    assert.ok(created.status === 200 || created.status === 201, created.text);
    assert.equal(created.json?.ok, true);

    const body = createdBotBody(h.fake);
    assert.equal(body.product, "BTC-USDC");
    assert.equal(body.strategy, "rebalance");
    assert.deepEqual(body.params, { target_base_pct: 50 });
    assert.equal(String(body.capital_base), "0");
    assert.equal(Object.hasOwn(body, "mode"), false, "the panel never names a book");
    assert.match(String(body.id), /^bot-[0-9a-f]{6}$/);

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.json.bots.length, 1);
    assert.equal(panel.json.bots[0].badge, "PRACTICE");
  } finally {
    await h.close();
  }
});

// ---- 17. a bot the engine paused says it needs attention --------------------------------------

test("test_bot_paused_shows_needs_attention", async () => {
  const h = await scaffold();
  try {
    h.fake.state.bots = [fakeBot({ id: "bot-paused1", status: "PAUSED" })];

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.bots.length, 1);
    assert.match(String(panel.json.bots[0].note), /needs attention/i);
  } finally {
    await h.close();
  }
});

// ---- 17b. only a pause the owner did not ask for needs attention ----------------------------

test("test_paused_reason_decides_needs_attention_note", async () => {
  const h = await scaffold();
  try {
    h.fake.state.bots = [
      fakeBot({ id: "bot-owner-pause", status: "PAUSED", paused_reason: "owner" }),
      fakeBot({ id: "bot-drawdown-pause", status: "PAUSED", paused_reason: "drawdown" }),
      fakeBot({ id: "bot-null-pause", status: "PAUSED", paused_reason: null }),
    ];

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    const byId = new Map((panel.json.bots || []).map((row) => [row.id, row]));

    const owner = byId.get("bot-owner-pause");
    assert.ok(owner, "the bot the owner paused is listed");
    assert.equal(
      /needs attention/i.test(String(owner.note ?? "")),
      false,
      `a bot the owner paused needs no attention note: ${owner.note}`,
    );

    const drawdown = byId.get("bot-drawdown-pause");
    assert.ok(drawdown, "the bot the drawdown paused is listed");
    assert.match(
      String(drawdown.note),
      /needs attention/i,
      "a bot the drawdown paused still needs attention",
    );

    const noReason = byId.get("bot-null-pause");
    assert.ok(noReason, "a paused bot with no reason is listed");
    assert.match(
      String(noReason.note),
      /needs attention/i,
      "a paused bot with no reason still needs attention",
    );
  } finally {
    await h.close();
  }
});

// ---- 18. a grid bot says honestly what it is -------------------------------------------------

test("test_grid_note", async () => {
  const h = await scaffold();
  try {
    h.fake.state.bots = [
      fakeBot({
        id: "bot-grid1",
        strategy: "grid",
        params: {
          center: "60000",
          step_pct: "1",
          levels_below: 3,
          levels_above: 3,
          quote_per_buy: "5",
          rebuy_sizing: "proceeds",
        },
      }),
    ];

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.bots[0].strategy, "grid");
    assert.equal(panel.json.bots[0].note, GRID_NOTE);
  } finally {
    await h.close();
  }
});

// ---- 19. the open orders box, filled from the engine's own /orders -----------------------------

test("test_open_orders_box", async () => {
  const h = await scaffold();
  try {
    h.fake.state.orders = {
      dry: [
        fakeOrder({
          book: "dry",
          client_order_id: "cid-dry-0001",
          bot: "bot-dry-1",
          product: "BTC-USDC",
          side: "BUY",
          size: "0.0010",
          price: "60000.00",
          created_at: 1710000100,
        }),
      ],
      live: [
        fakeOrder({
          book: "live",
          client_order_id: "cid-live-0001",
          bot: "bot-live-1",
          product: "ETH-USDC",
          side: "SELL",
          size: "0.0020",
          price: "61000.00",
          created_at: 1710000200,
        }),
      ],
    };

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.open_orders.dry.length, 1, panel.text);
    assert.equal(panel.json.open_orders.live.length, 1, panel.text);

    const dry = panel.json.open_orders.dry[0];
    assert.deepEqual(Object.keys(dry).sort(), ["bot", "created_at", "price", "product", "side", "size"]);
    assert.equal(dry.bot, "bot-dry-1");
    assert.equal(dry.product, "BTC-USDC");
    assert.equal(dry.side, "BUY");
    assert.equal(dry.size, "0.0010");
    assert.equal(dry.price, "60000.00");
    assert.equal(dry.created_at, 1710000100);
    assert.equal(dry.book, undefined, "the book is the box, not a column");

    assert.equal(panel.text.includes("cid-dry-0001"), false, "no client order id reaches the page");
    assert.equal(panel.text.includes("cid-live-0001"), false, "no client order id reaches the page");

    const asked = h.fake.state.requests.filter(
      (record) => record.method === "GET" && String(record.path).startsWith("/orders"),
    );
    assert.ok(asked.some((record) => record.path === "/orders?book=dry"), "the dry book was read");
    assert.ok(asked.some((record) => record.path === "/orders?book=live"), "the live book was read");

    const page = await renderPanelPage();
    const html = page.content + page.scripts;
    assert.match(html, /Open orders/, "the page shows the Open orders box");
    assert.ok(html.includes("No open orders."), "the empty box has its own sentence");
  } finally {
    await h.close();
  }
});

// ---- 20. an engine that is down is a state, not a failed page --------------------------------

test("test_engine_unreachable_panel_state", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    await h.fake.close();

    const panel = await within(h.get("/api/coinbase/panel"), "panel while the engine is down");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json?.ok, true);
    assert.equal(panel.json.engine.reachable, false);
    assert.equal(panel.json.engine.note, ENGINE_DOWN_NOTE);
    assert.deepEqual(panel.json.bots, []);
  } finally {
    await h.close();
  }
});

// ---- 21. a Disconnect that never finished says so --------------------------------------------

test("test_disconnect_unfinished_message", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    const rows = await h.connections();
    assert.equal(rows.length, 1);
    await h.setRowConfig(rows[0].uuid, { disconnecting: true });

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.connection.disconnect_unfinished, true);
    assert.equal(panel.json.connection.message, DISCONNECT_UNFINISHED_MESSAGE);
  } finally {
    await h.close();
  }
});

// ---- 22. a real connect writes the project id, and a failing writer changes no answer --------

test("test_onconnected_writes_project_id", async () => {
  const h = await scaffold();
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    assert.equal(h.saveBundleEnvCalls.length, 1);
    assert.equal(h.saveBundleEnvCalls[0].bundleId, "coinbase");
    assert.deepEqual(h.saveBundleEnvCalls[0].envVars, {
      CROW_COINBASE_PROJECT_ID: String(h.projectId),
    });
  } finally {
    await h.close();
  }

  const throwing = await scaffold({
    saveBundleEnv: async () => {
      throw new Error("the bundle env writer failed");
    },
  });
  try {
    const connected = await throwing.connect();
    assert.equal(connected.status, 200, connected.text);
    assert.equal(connected.json?.ok, true);
    assert.equal(throwing.saveBundleEnvCalls.length, 1, "the writer was asked once");
  } finally {
    await throwing.close();
  }
});

// ---- 23. a real disconnect clears the project id ---------------------------------------------

test("test_disconnect_clears_project_id", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);

    const disconnected = await h.disconnect();
    assert.equal(disconnected.status, 200, disconnected.text);
    assert.ok(h.saveBundleEnvCalls.length >= 2, "connect and disconnect both wrote");
    const last = h.saveBundleEnvCalls[h.saveBundleEnvCalls.length - 1];
    assert.equal(last.bundleId, "coinbase");
    assert.deepEqual(last.envVars, { CROW_COINBASE_PROJECT_ID: "" });
  } finally {
    await h.close();
  }
});

// ---- 24. the loops start at mount, before anybody opens the panel ----------------------------

test("test_loops_start_at_mount_without_panel_open", async () => {
  const started = [];
  const firstHandles = [];
  const h = await scaffold({
    mode: "default",
    startLoopsImpl: (options) => {
      started.push(options);
      const handle = { stopped: false, stop() { handle.stopped = true; } };
      firstHandles.push(handle);
      return handle;
    },
  });
  try {
    assert.equal(started.length, 1, "the loops started once at mount, before any request");

    const loops = started[0];
    assert.equal(typeof loops.client?.health, "function", "the loops got an engine client");
    assert.equal(typeof loops.connection?.get, "function", "the loops got the connection store");
    assert.match(String(loops.holder), /^gw-/);
    assert.equal(typeof loops.notify, "function");
    assert.equal(typeof loops.getProjectId, "function");

    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);

    const store = await loops.connection.get();
    assert.ok(store, "the store answers for the connection just made");
    assert.equal(Number(store.projectId), h.projectId, "the loops hold the real connection store");

    const second = [];
    const module = await import("../bundles/coinbase/panel/routes.js");
    module.default((req, _res, next) => { req.dashboardSession = SESSION; next(); }, {
      db: h.db,
      crowHome: CROW_HOME,
      startLoopsImpl: (options) => {
        second.push(options);
        return { stop() {} };
      },
    });

    assert.equal(second.length, 1, "the second mount starts the loops too");
    assert.equal(firstHandles[0].stopped, true, "mounting again stops the previous loops");
  } finally {
    await h.close();
  }
});

// ---- 25. CSRF on every state-changing panel request ------------------------------------------

test("test_csrf_enforced", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);

    const refused = await h.post(
      "/api/coinbase/caps",
      { caps: { [CAP.DAILY]: "150" }, totp: h.freshCode() },
      { csrf: false },
    );
    assert.equal(refused.status, 403, refused.text);
    assert.equal(h.fake.calls("POST", "/caps").length, 0, "nothing reached the engine");

    const accepted = await h.post("/api/coinbase/caps", {
      caps: { [CAP.DAILY]: "150" },
      totp: h.freshCode(),
    });
    assert.equal(accepted.status, 200, accepted.text);
    assert.equal(h.fake.calls("POST", "/caps").length, 1);

    const read = await h.get("/api/coinbase/panel", { csrf: false });
    assert.equal(read.status, 200, read.text);
  } finally {
    await h.close();
  }
});

// ---- 26. the page itself ---------------------------------------------------------------------

test("test_page_handler_html", async () => {
  const h = await scaffold();
  try {
    const page = await renderPanelPage();
    const html = page.content + page.scripts;

    assert.equal(page.title, "Trading");
    assert.ok(html.includes(COPY_STEPS), "the Connect steps are on the page");
    assert.match(html, /KILL SWITCH/);
    assert.match(html, /Resume trading/);
    assert.match(html, /Not now/);
    assert.match(html, /PRACTICE/);
    assert.match(html, /LIVE/);
    assert.match(html, /Practice/);
    assert.match(html, /Open orders/, "the page shows the open-orders box");

    const secrets = [KEY_NAME, PRIVATE_KEY, ENGINE_TOKEN, INSTALL_TOKEN];
    assertCarriesNoSecret(html, secrets, "the page");

    const focusId = "pv-focus-7c1";
    const plain = await renderPanelPage();
    assert.equal(plain.content.includes(focusId), false);

    const focused = await renderPanelPage({ query: { preview: focusId } });
    assert.ok(
      focused.content.includes(focusId) || focused.scripts.includes(focusId),
      "the page pointed at that preview",
    );

    const hostile = `<img src=x onerror="alert(1)">`;
    const escaped = await renderPanelPage({ query: { preview: hostile } });
    const escapedHtml = escaped.content + escaped.scripts;
    assert.equal(escapedHtml.includes(hostile), false, "a query value is not pasted in raw");
    assert.ok(escapedHtml.includes("&lt;img"), "the query value is escaped");

    assert.equal(h.fake.state.requests.length, 0, "rendering the page calls no engine route");
  } finally {
    await h.close();
  }
});

test("test_page_carries_back_to_practice", async () => {
  const h = await scaffold();
  try {
    const page = await renderPanelPage();
    const html = page.content + page.scripts;
    assert.ok(html.includes("Back to practice"), "the bot card offers a way back to practice");
    assert.equal(h.fake.state.requests.length, 0, "rendering the page calls no engine route");
  } finally {
    await h.close();
  }
});

// ---- 27. the whole way through, in plain words, over HTTP only -------------------------------

test("test_walkthrough_non_technical", async () => {
  const h = await scaffold();
  try {
    const page = await renderPanelPage();
    const html = page.content + page.scripts;
    assert.ok(html.includes(COPY_STEPS), "the page carries the Connect steps");
    assert.equal(/terminal/i.test(html), false, "no step asks for a terminal");

    const opened = await h.get("/api/coinbase/panel");
    assert.equal(opened.status, 200, opened.text);
    assert.equal(opened.json.connection.connected, false);
    assert.equal(opened.json.engine.reachable, true);

    const tested = await h.testKey();
    assert.equal(tested.status, 200, tested.text);
    assert.equal(tested.json?.ok, true);
    assert.equal(h.fake.state.pinned, false, "a test installs nothing");

    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    assert.ok(String(connected.json?.message).startsWith(CONNECTED_PREFIX), connected.text);
    assert.equal(h.fake.state.pinned, true);

    const created = await h.post("/api/coinbase/bots", { product: "BTC-USDC", strategy: "rebalance" });
    assert.ok(created.status === 200 || created.status === 201, created.text);
    const botId = createdBotBody(h.fake).id;

    const listed = await h.get("/api/coinbase/panel");
    const practiceBot = listed.json.bots.find((row) => row.id === botId);
    assert.ok(practiceBot, "the new bot is in the panel state");
    assert.equal(practiceBot.status, "ACTIVE");
    assert.equal(practiceBot.badge, "PRACTICE");

    h.flags.twoFactor = false;
    const early = await h.post(`/api/coinbase/bots/${botId}/mode`, {
      mode: "live",
      acknowledge_live: true,
      capital_quote: "10.00",
      capital_base: "0",
      totp: h.freshCode(),
    });
    assert.equal(early.status, 403, early.text);
    assert.equal(early.json?.code, "two_factor_required");
    assert.equal(early.json?.message, TWO_FACTOR_MESSAGE);
    assert.equal(h.fake.calls("POST", `/bots/${botId}/mode`).length, 0);

    h.flags.twoFactor = true;
    const switched = await h.post("/api/coinbase/switches", { live_enabled: true, totp: h.freshCode() });
    assert.equal(switched.status, 200, switched.text);

    const live = await h.post(`/api/coinbase/bots/${botId}/mode`, {
      mode: "live",
      acknowledge_live: true,
      capital_quote: "10.00",
      capital_base: "0",
      totp: h.freshCode(),
    });
    assert.equal(live.status, 200, live.text);
    const modeRecords = h.fake.calls("POST", `/bots/${botId}/mode`);
    assert.equal(modeRecords.length, 1);
    assert.equal(modeRecords[0].mac, "owner");

    const after = await h.get("/api/coinbase/panel");
    const liveBot = after.json.bots.find((row) => row.id === botId);
    assert.ok(liveBot, "the bot is still listed");
    assert.equal(liveBot.badge, "LIVE");
    assert.equal(after.json.switches.live_enabled, true);
  } finally {
    await h.close();
  }
});

// ---- 28. the drawdown warning compares the save against the engine's own reading ----------------

test("test_drawdown_warning_from_engine", async () => {
  const h = await scaffold();
  try {
    assert.equal((await h.connect()).status, 200);
    h.fake.state.drawdown = {
      dry: { equity: "0", hwm: "0", pct: null },
      live: { equity: "85.00", hwm: "100.00", pct: "15" },
    };

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.equal(panel.json.drawdown.live, "15", "the page shows the engine's own reading");
    assert.equal(panel.json.drawdown.dry, null);

    // A cap at today's fall would stop the live book this moment: that asks again.
    const atCap = await h.post("/api/coinbase/caps", {
      caps: { [CAP.DRAWDOWN]: "15" },
      totp: h.freshCode(),
    });
    assert.equal(atCap.status, 409, atCap.text);
    assert.equal(atCap.json?.ok, false);
    assert.equal(atCap.json?.code, "would_halt");
    assert.equal(atCap.json?.book, "live");
    assert.equal(atCap.json?.message, WOULD_HALT_MESSAGE);
    assert.equal(h.fake.calls("POST", "/caps").length, 0, "a warning sends nothing");

    const roomy = await h.post("/api/coinbase/caps", {
      caps: { [CAP.DRAWDOWN]: "20" },
      totp: h.freshCode(),
    });
    assert.equal(roomy.status, 200, roomy.text);
    assert.equal(h.fake.calls("POST", "/caps").length, 1);

    // No reading from the engine for a book is no warning for it.
    h.fake.state.drawdown = {
      dry: { equity: "0", hwm: "0", pct: null },
      live: { equity: "85.00", hwm: "100.00", pct: null },
    };
    const noReading = await h.post("/api/coinbase/caps", {
      caps: { [CAP.DRAWDOWN]: "15" },
      totp: h.freshCode(),
    });
    assert.equal(noReading.status, 200, noReading.text);
    assert.equal(h.fake.calls("POST", "/caps").length, 2);

    // The practice book speaks for itself.
    h.fake.state.drawdown = {
      dry: { equity: "85.00", hwm: "100.00", pct: "15" },
      live: { equity: "85.00", hwm: "100.00", pct: null },
    };
    const practice = await h.post("/api/coinbase/caps", {
      caps: { [CAP.DRAWDOWN]: "15" },
      totp: h.freshCode(),
    });
    assert.equal(practice.status, 409, practice.text);
    assert.equal(practice.json?.code, "would_halt");
    assert.equal(practice.json?.book, "dry");
    assert.equal(practice.json?.message, WOULD_HALT_PRACTICE_MESSAGE);
    assert.equal(h.fake.calls("POST", "/caps").length, 2, "a warning sends nothing");

    // The panel keeps no high-water mark of its own.
    assert.equal(await h.setting("coinbase_book_peak"), null);
    const rows = await settingRows(h);
    assert.equal(rows.filter((row) => row.key === "coinbase_book_peak").length, 0);
  } finally {
    await h.close();
  }
});

// ---- 29. the products the create form offers come from the engine's status --------------------

test("test_products_from_engine_status", async () => {
  const h = await scaffold();
  try {
    h.fake.state.products = ["ETH-USDC", "SOL-USDC"];

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.deepEqual(panel.json.products, ["ETH-USDC", "SOL-USDC"]);

    const page = await renderPanelPage();
    const html = page.content + page.scripts;
    assert.equal(html.includes("BTC-USDC"), false, "the page carries no hard-coded product list");
    assert.match(html, /No products are set up yet\./, "the empty form has its own sentence");
  } finally {
    await h.close();
  }
});

// ---- 30. the production mount: the default export, its own client and its own loops -----------

test("test_default_export_real_client_kill_panel_loops", async () => {
  const h = await scaffold({ mode: "default", engineClientFactory: null, realLoops: true });
  try {
    h.fake.state.bots = [fakeBot({ id: "bot-real-1", product: "ETH-USDC" })];
    h.fake.state.credentials = "ready";

    const killed = await within(h.post("/api/coinbase/kill", { confirm: true }), "kill over the real client");
    assert.equal(killed.status, 200, killed.text);
    assert.equal(killed.json?.ok, true);
    assert.equal(killed.json?.message, KILL_SUCCESS_MESSAGE);

    const kills = h.fake.calls("POST", "/kill");
    assert.equal(kills.length, 1, "the kill reached the fake engine");
    assert.equal(
      kills[0].headers.authorization,
      `Bearer ${ENGINE_TOKEN}`,
      "the client read its token from the install's own .env",
    );
    assert.equal(kills[0].mac, "none", "the kill switch needs no approval signature");

    const panel = await h.get("/api/coinbase/panel");
    assert.equal(panel.status, 200, panel.text);
    assert.deepEqual((panel.json?.bots || []).map((row) => row.id), ["bot-real-1"]);

    // The loops the default export started are the real ones, over the same client.
    const leased = await waitFor(() => h.fake.callsMatching("POST", "/lease").length >= 1);
    assert.ok(leased, "the started loops asked the engine for the lease");
    const read = await waitFor(() => h.fake.callsMatching("GET", "/events").length >= 1);
    assert.ok(read, "the started loops read the event feed");

    const lease = h.fake.callsMatching("POST", "/lease")[0];
    assert.equal(lease.headers.authorization, `Bearer ${ENGINE_TOKEN}`);
    assert.equal(lease.mac, "install", "an unpinned engine takes the lease with the install token");
  } finally {
    await h.close();
  }
});

// ---- 31. the kill switch's two failure copies --------------------------------------------------

test("test_kill_engine_down_copy", async () => {
  const h = await scaffold({ engineClientFactory: null });
  try {
    await h.fake.close();

    const killed = await within(h.post("/api/coinbase/kill", { confirm: true }), "kill with the engine down");
    assert.equal(killed.status, 502, killed.text);
    assert.equal(killed.json?.ok, false);
    assert.equal(killed.json?.code, "engine_unreachable");
    assert.equal(killed.json?.message, KILL_ENGINE_DOWN_MESSAGE);
  } finally {
    await h.close();
  }
});

test("test_kill_partial_copy", async () => {
  const h = await scaffold();
  try {
    h.fake.next("POST", "/kill", { status: 502, body: { halted: true, detail: "the sweep failed" } });

    const killed = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(killed.status, 502, killed.text);
    assert.equal(killed.json?.ok, false);
    assert.equal(killed.json?.code, "kill_partial");
    assert.equal(killed.json?.message, KILL_PARTIAL_MESSAGE);
    assert.equal(h.fake.calls("POST", "/kill").length, 1);
  } finally {
    await h.close();
  }
});

// ---- 31b. only an engine that said it halted is a partial kill ---------------------------------

test("test_kill_failure_kinds", async () => {
  const h = await scaffold();
  try {
    // A refused token: the engine answered, but it did not say it halted. It refused Crow's own
    // token, so nobody was reached and the owner cancels by hand.
    h.fake.next("POST", "/kill", { status: 401, body: { detail: "unauthorized" } });
    const unauthorized = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(unauthorized.status, 502, unauthorized.text);
    assert.equal(unauthorized.json?.ok, false);
    assert.equal(unauthorized.json?.code, "engine_unreachable");
    assert.equal(unauthorized.json?.message, KILL_ENGINE_REFUSED_MESSAGE);

    // A 500 with no halt flag on it is the same answer.
    h.fake.next("POST", "/kill", { status: 500, body: { detail: "the sweep failed" } });
    const failed = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(failed.status, 502, failed.text);
    assert.equal(failed.json?.ok, false);
    assert.equal(failed.json?.code, "engine_unreachable");
    assert.equal(failed.json?.message, KILL_ENGINE_DOWN_MESSAGE);

    // Only a body that says halted:true means trading stopped while orders may still rest.
    h.fake.next("POST", "/kill", { status: 502, body: { halted: true, detail: "the sweep failed" } });
    const partial = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(partial.status, 502, partial.text);
    assert.equal(partial.json?.ok, false);
    assert.equal(partial.json?.code, "kill_partial");
    assert.equal(partial.json?.message, KILL_PARTIAL_MESSAGE);

    assert.equal(h.fake.calls("POST", "/kill").length, 3, "the engine answered all three");

    // Nothing answers at all: nothing was stopped, and nobody was reached.
    await h.fake.close();
    const refused = await within(h.post("/api/coinbase/kill", { confirm: true }), "kill with the engine gone");
    assert.equal(refused.status, 502, refused.text);
    assert.equal(refused.json?.ok, false);
    assert.equal(refused.json?.code, "engine_unreachable");
    assert.equal(refused.json?.message, KILL_ENGINE_DOWN_MESSAGE);
  } finally {
    await h.close();
  }
});

// ---- 31c. a token the engine refused has its own copy ------------------------------------------

test("test_kill_401_copy", async () => {
  const h = await scaffold();
  try {
    // The engine refused Crow's own token: it was reached but will not take our calls, so nothing
    // was stopped and the owner cancels by hand at Coinbase.
    h.fake.next("POST", "/kill", { status: 401, body: { detail: "unauthorized" } });
    const unauthorized = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(unauthorized.status, 502, unauthorized.text);
    assert.equal(unauthorized.json?.ok, false);
    assert.equal(unauthorized.json?.code, "engine_unreachable");
    assert.equal(unauthorized.json?.message, KILL_ENGINE_REFUSED_MESSAGE);

    // The other refusal of our own token says exactly the same thing.
    h.fake.next("POST", "/kill", { status: 403, body: { detail: "APPROVAL_INVALID" } });
    const forbidden = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(forbidden.status, 502, forbidden.text);
    assert.equal(forbidden.json?.ok, false);
    assert.equal(forbidden.json?.code, "engine_unreachable");
    assert.equal(forbidden.json?.message, KILL_ENGINE_REFUSED_MESSAGE);

    // Any other failure — a 500 without a halt flag — keeps the "engine is down" sentence.
    h.fake.next("POST", "/kill", { status: 500, body: { detail: "the sweep failed" } });
    const failed = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(failed.status, 502, failed.text);
    assert.equal(failed.json?.ok, false);
    assert.equal(failed.json?.code, "engine_unreachable");
    assert.equal(failed.json?.message, KILL_ENGINE_DOWN_MESSAGE);
    assert.notEqual(failed.json?.message, KILL_ENGINE_REFUSED_MESSAGE);

    assert.equal(h.fake.calls("POST", "/kill").length, 3, "the engine answered all three");
  } finally {
    await h.close();
  }
});

// ---- 32. the kill switch works even when panel/connect.js will not load ------------------------

test("test_kill_works_when_connect_module_fails", async () => {
  const brokenDir = join(CROW_HOME, "bundles", "coinbase", "panel");
  mkdirSync(brokenDir, { recursive: true });
  const broken = join(brokenDir, "connect.js");
  writeFileSync(broken, 'throw new Error("this installed copy of connect.js will not load");\n', "utf8");

  const h = await scaffold({ mode: "default", routesModule: await importPanelRoutes("connect-down") });
  try {
    h.flags.twoFactor = false;
    h.flags.isLocal = true;

    const killed = await within(h.post("/api/coinbase/kill", { confirm: true }), "kill without the Connect module");
    assert.equal(killed.status, 200, killed.text);
    assert.equal(killed.json?.ok, true);
    assert.equal(h.fake.calls("POST", "/kill").length, 1, "the kill still reached the engine");

    h.flags.isLocal = false;
    const peer = await h.post("/api/coinbase/kill", { confirm: true });
    assert.equal(peer.status, 403, peer.text);
    assert.equal(peer.json?.ok, false);
    assert.equal(peer.json?.code, LOCAL_LOGIN_CODE);
    assert.equal(h.fake.calls("POST", "/kill").length, 1, "a peer's kill never reached the engine");
  } finally {
    await h.close();
    rmSync(broken, { force: true });
  }
});

// ---- 33. a bundle-env write that answers non-200 is logged by its code only --------------------

test("test_onconnected_non200_logged_code_only", async () => {
  const bodyText = "secret-ish text that must stay out of the log";
  const h = await scaffold({
    saveBundleEnv: async () => ({ status: 500, body: { error: bodyText } }),
  });
  const warnings = [];
  const realWarn = console.warn;
  console.warn = (...args) => { warnings.push(args.map((arg) => String(arg)).join(" ")); };
  try {
    const connected = await h.connect();
    assert.equal(connected.status, 200, connected.text);
    assert.equal(connected.json?.ok, true, "the Connect answer still succeeds");
  } finally {
    console.warn = realWarn;
    await h.close();
  }

  const logged = warnings.join("\n");
  assert.match(logged, /500/, "the status a failed write answered is logged");
  assert.equal(logged.includes(bodyText), false, "the write's body text never reaches the log");
});

// ---- 34. the panel makes every bot id itself ---------------------------------------------------

test("test_create_bot_ignores_client_id", async () => {
  const h = await scaffold();
  try {
    const created = await h.post("/api/coinbase/bots", {
      product: "BTC-USDC",
      strategy: "rebalance",
      id: "evil-id",
    });
    assert.ok(created.status === 200 || created.status === 201, created.text);

    const body = createdBotBody(h.fake);
    assert.match(String(body.id), /^bot-[0-9a-f]{6}$/);
    assert.notEqual(body.id, "evil-id", "the id a browser sent was ignored");
  } finally {
    await h.close();
  }
});

// ---- 35. two copies of routes.js in one process still start one set of loops -------------------

test("test_loops_guard_once_per_process", async () => {
  const h = await scaffold();
  const handles = { a: [], b: [] };
  try {
    const modA = await importPanelRoutes("loops-guard-one");
    const modB = await importPanelRoutes("loops-guard-two");
    assert.notEqual(modA.default, modB.default, "the two mounts come from two module copies");

    const auth = (req, _res, next) => { req.dashboardSession = SESSION; next(); };
    const mount = (module, bucket) => module.default(auth, {
      db: h.db,
      crowHome: CROW_HOME,
      authMiddleware: auth,
      isLocalSession: async () => true,
      is2faEnabled: async () => true,
      startLoopsImpl: () => {
        const handle = { stopped: false, stop() { handle.stopped = true; } };
        handles[bucket].push(handle);
        return handle;
      },
      engineClientFactory: () => ({ health: async () => ({ ok: true, data: {} }) }),
    });

    mount(modA, "a");
    assert.equal(handles.a.length, 1, "the first mount starts its loops");
    assert.equal(handles.a[0].stopped, false);

    mount(modB, "b");
    assert.equal(handles.b.length, 1, "the second mount starts its own loops");
    assert.equal(handles.a[0].stopped, true, "the second mount stops the first mount's loops");

    const live = [...handles.a, ...handles.b].filter((handle) => handle.stopped !== true);
    assert.equal(live.length, 1, "one set of loops is live in this process");
  } finally {
    for (const handle of [...handles.a, ...handles.b]) {
      try { handle.stop(); } catch { /* already stopped */ }
    }
    await h.close();
  }
});

// ---- 36. express comes from the app root, never from the bundle --------------------------------

test("test_no_express_dependency", () => {
  const pkg = JSON.parse(readFileSync(join(REPO, "bundles", "coinbase", "package.json"), "utf8"));
  const deps = pkg.dependencies && typeof pkg.dependencies === "object" ? pkg.dependencies : {};
  assert.equal(Object.hasOwn(deps, "express"), false, "express is not a bundle dependency");

  for (const rel of ["panel/connect.js", "panel/routes.js"]) {
    const source = readFileSync(join(REPO, "bundles", "coinbase", rel), "utf8");
    assert.equal(/from\s+["']express["']/.test(source), false, `${rel} has no static express import`);
    assert.equal(/require\(\s*["']express["']\s*\)/.test(source), false, `${rel} does not require express`);
  }
});

// ---- 37. the fake engine refuses an owner MAC while it holds no pin ---------------------------

/** One direct call to the fake engine, signed with `key` the way the engine client signs. */
async function callEngine(fake, key, method, path, bodyText) {
  const headers = { authorization: `Bearer ${ENGINE_TOKEN}` };
  if (bodyText !== undefined) headers["content-type"] = "application/json";
  if (key) Object.assign(headers, signedHeaders(key, { method, path, body: bodyText ?? "" }));
  const res = await fetch(fake.baseUrl + path, {
    method,
    headers,
    body: bodyText === undefined ? undefined : bodyText,
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, text, json };
}

test("test_fake_engine_refuses_owner_mac_when_unpinned", async () => {
  const fake = await createFakeEngine();
  const ownerSecret = "test-owner-secret-unpinned-5c17";
  try {
    // The engine still remembers the owner's key but holds no pin, so it has nothing to check a
    // signature against: that is the state a restart or a wiped volume leaves behind.
    fake.state.pinSecret = ownerSecret;
    fake.state.pinned = false;
    fake.state.bots = [fakeBot({ id: "bot-unpinned-1", mode: "live" })];
    fake.state.previews = [fakePreview({ preview_id: "pv-unpinned-1" })];

    const privileged = [
      ["POST", "/switches", JSON.stringify({ live_enabled: true })],
      ["POST", "/caps", JSON.stringify({ caps: { [CAP.DAILY]: "100" } })],
      ["POST", "/bots/bot-unpinned-1/mode", JSON.stringify({ mode: "live", acknowledge_live: true })],
      ["POST", "/bots/bot-unpinned-1/resume", JSON.stringify({ acknowledge_rebase: true })],
      ["POST", "/bots/bot-unpinned-1/recenter", JSON.stringify({ center: "60000" })],
      ["POST", "/halt/clear", JSON.stringify({ acknowledge_rebase: true })],
      ["POST", "/ai/previews/pv-unpinned-1/approve", JSON.stringify({ hash: "a".repeat(64) })],
      ["POST", "/credentials/forget", undefined],
      ["DELETE", "/credentials", undefined],
    ];

    for (const [method, path, bodyText] of privileged) {
      const answer = await callEngine(fake, ownerSecret, method, path, bodyText);
      assert.equal(answer.status, 403, `${method} ${path} answered ${answer.status}`);
      assert.equal(answer.json?.detail, "APPROVAL_INVALID", `${method} ${path}: ${answer.text}`);
      const record = fake.last(method, path);
      assert.ok(record, `${method} ${path} reached the engine`);
      assert.equal(record.mac, "none", `${method} ${path} was not read as the owner's`);
      assert.equal(record.ownerRefused, true, `${method} ${path} was refused as an owner MAC`);
    }

    // Nothing was acted on: the switches, the halt, the bot and the proposal are as they were.
    assert.deepEqual(fake.state.switches, { live_enabled: false, ai_live_enabled: false, ceiling: true });
    assert.equal(fake.state.halted, false);
    assert.equal(fake.state.bots[0].status, "ACTIVE");
    assert.equal(fake.state.bots[0].mode, "live", "the bot was live and stayed live");
    assert.equal(fake.state.previews[0].state, "pending");
    assert.equal(fake.state.caps[CAP.DAILY], "200", "no cap was written");
    assert.equal(fake.state.pinned, false, "and no pin appeared");

    // The install token is still the key an unpinned engine takes: that is how a first pin is made.
    const leaseBody = JSON.stringify({ holder: "gw-test-unpinned" });
    const lease = await callEngine(fake, INSTALL_TOKEN, "POST", "/lease", leaseBody);
    assert.equal(lease.status, 200, lease.text);
    assert.equal(fake.last("POST", "/lease").mac, "install");

    // A call with no signature at all is still refused by the privileged routes themselves.
    const unsigned = await callEngine(fake, null, "POST", "/switches", JSON.stringify({ live_enabled: true }));
    assert.equal(unsigned.status, 403, unsigned.text);
    assert.equal(unsigned.json?.detail, "APPROVAL_INVALID");

    // And once the pin is back, the same signed call is the owner's again.
    fake.state.pinned = true;
    const pinnedSwitch = await callEngine(fake, ownerSecret, "POST", "/switches", JSON.stringify({ live_enabled: true }));
    assert.equal(pinnedSwitch.status, 200, pinnedSwitch.text);
    assert.equal(fake.last("POST", "/switches").mac, "owner");
    assert.equal(fake.state.switches.live_enabled, true);
  } finally {
    await fake.close();
  }
});