/**
 * The Coinbase bundle's MCP server (Task 11): the exact tool set, the dry-only
 * bot creation, the live-bot refusals, the order tools that never approve, the
 * plain sentences a refusal earns, and the secret-free environment it runs in.
 *
 * Every tool is driven through the real MCP SDK: a `Client` over an
 * `InMemoryTransport` pair wired to `createCoinbaseServer`, with the real
 * `createEngineClient` pointed at the harness fake engine. One test spawns the
 * bundle's own stdio entry as a child, so what that child reads and sends is the
 * child's own doing. Nothing here is a real key, amount or person: the install
 * token is minted at run time and every figure is a test figure.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import {
  REPO,
  ENGINE_TOKEN,
  createFakeEngine,
  fakeBot,
  fakePreview,
  cleanupScratch,
} from "./helpers/coinbase-panel-harness.mjs";
import { rmScratch } from "./helpers/safe-rm.js";
import { createEngineClient } from "../bundles/coinbase/server/engine-client.js";
import { createCoinbaseServer } from "../bundles/coinbase/server/server.js";

const BUNDLE_DIR = join(REPO, "bundles", "coinbase");
const SERVER_DIR = join(BUNDLE_DIR, "server");
const INDEX = join(SERVER_DIR, "index.js");
const PROJECT_ID = "p-test";
const APPROVAL_LINK = (previewId) => `/dashboard/coinbase?preview=${previewId}`;
const WAITING_SENTENCE = "Waiting for your approval in the Crow dashboard.";
const ENGINE_DOWN_SENTENCE = "The trading engine is not responding. Try again in a minute.";
const GENERIC_SENTENCE = "Something went wrong reading the trading engine.";
const UNSTATED_SENTENCE = "The trading engine could not complete that request.";
// The one sentence the price read earns when the engine has no price right now.
const NO_PRICE_SENTENCE = "No price is available for that product right now.";
// The one sentence a refused engine address earns, and the one every refusal sentence must be.
const ENGINE_URL_SENTENCE = "The engine address must be a plain http address on this computer.";
const PREVIEW_LIMIT_SENTENCE =
  "Too many proposals are waiting for the owner's answer or were asked for this hour.";
const BOT_LIMIT_SENTENCE =
  "There are too many bots running or created this hour. Stop one you no longer need, or try again later.";
// The one sentence both order tools must carry about who approves a proposal.
const APPROVE_SENTENCE = "Only the owner can approve it, in the Crow dashboard; this tool cannot.";
// The pause tool's own copy: what it says it does, and the two answers it can give.
const PAUSE_DESCRIPTION =
  "Pauses one bot and cancels its waiting orders on Coinbase. A paused bot places no new orders " +
  "until it is resumed; use stop instead when the bot is finished for good.";
const PAUSE_MESSAGE = "The bot is paused and its waiting orders were cancelled.";
const PAUSE_INCOMPLETE_SENTENCE =
  "The bot is paused, but some of its waiting orders may still be on Coinbase. Call pause again, " +
  "or cancel them in the Coinbase app: Crow portfolio \u2192 Open orders.";
// A pause called again moments after the last one is asked to wait, in one plain sentence.
const PAUSE_TOO_SOON_SENTENCE =
  "That bot was only just asked to pause. Wait a few seconds and call pause again.";
// A pause that raced another pause, and one that raced a change: one plain sentence each.
const PAUSE_IN_PROGRESS_SENTENCE =
  "That bot is being paused. Wait a few seconds and try again.";
const PAUSE_CHANGED_SENTENCE =
  "That bot changed while it was being paused. Check it, and call pause again if it still needs it.";

// The exact tool list the design rules, and nothing else.
const TOOL_NAMES = [
  "crow_cb_balances",
  "crow_cb_bots",
  "crow_cb_bot_status",
  "crow_cb_fills",
  "crow_cb_pnl",
  "crow_cb_price",
  "crow_cb_bot_pause",
  "crow_cb_bot_resume",
  "crow_cb_bot_stop",
  "crow_cb_bot_recenter",
  "crow_cb_bot_create",
  "crow_cb_order_preview",
  "crow_cb_order_place",
  "crow_cb_order_cancel",
];

// What a tool must never be named, carry as an input, or accept as a value.
const FORBIDDEN_IN_TOOLS = /approve|mode|switch|credential|caps|lease|transfer|withdraw|convert|kill/i;

// The server code itself must never name the owner's key material, the install
// token, or the provider that hands out signing keys.
const FORBIDDEN_IN_SOURCE =
  /install_token|INSTALL_TOKEN|readInstallToken|keychain|secretProvider|COINBASE_PRIVATE_KEY|COINBASE_KEY_NAME|COINBASE_APPROVE_SECRET|serviceSecretsFor/i;

// The only two environment keys the server entry may read: the engine's address
// and the project that owns the audit trail. The bearer token comes from the
// bundle's own `.env`, through engine-client.js.
const ALLOWED_ENV_KEYS = new Set(["CROW_COINBASE_ENGINE_URL", "CROW_COINBASE_PROJECT_ID"]);

// Files that were already in the bundle before this server: they are read, not
// written, and engine-client.js is where the engine token is read from.
const PRE_EXISTING_SERVER_FILES = new Set([
  "app-root.js",
  "engine-client.js",
  "loops.js",
  "mac.js",
  "notifier.js",
]);

// The routes the MCP server is allowed to make the engine see.
const ALLOWED_ROUTES = [
  ["GET", /^\/balances$/],
  ["GET", /^\/price$/],
  ["GET", /^\/bots$/],
  ["GET", /^\/pnl$/],
  ["GET", /^\/bots\/[^/]+\/fills$/],
  ["GET", /^\/ai\/previews$/],
  ["POST", /^\/bots$/],
  ["POST", /^\/bots\/[^/]+\/pause$/],
  ["POST", /^\/bots\/[^/]+\/stop$/],
  ["POST", /^\/bots\/[^/]+\/resume$/],
  ["POST", /^\/bots\/[^/]+\/recenter$/],
  ["POST", /^\/ai\/previews$/],
  ["POST", /^\/ai\/orders\/[^/]+\/cancel$/],
];

// ---- fixtures ---------------------------------------------------------------------------------

const openedFakes = [];
const openedConnections = [];
const scratchHomes = [];

async function openFake() {
  const fake = await createFakeEngine();
  openedFakes.push(fake);
  return fake;
}

function engineClientFor(fake) {
  return createEngineClient({ baseUrl: fake.baseUrl, token: ENGINE_TOKEN, source: "mcp" });
}

/** An MCP client over a fresh server, talking in memory. */
async function connect({ client, projectId = PROJECT_ID } = {}) {
  const server = createCoinbaseServer({ client, projectId });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const sdk = new Client({ name: "coinbase-mcp-test", version: "0.0.0" });
  await server.connect(serverSide);
  await sdk.connect(clientSide);
  openedConnections.push(async () => {
    await sdk.close();
    await server.close();
  });
  return sdk;
}

/** One server over the harness fake engine, and the client that drives it. */
async function connectToFake(fake) {
  return connect({ client: engineClientFor(fake) });
}

function textOf(result) {
  const blocks = result && Array.isArray(result.content) ? result.content : [];
  return blocks
    .filter((block) => block && block.type === "text")
    .map((block) => String(block.text ?? ""))
    .join("\n");
}

async function call(sdk, name, args = {}) {
  const result = await sdk.callTool({ name, arguments: args });
  return { result, text: textOf(result), isError: result?.isError === true };
}

/** Every input-schema property name and enum value of one tool, at any depth. */
function schemaWords(schema, out = { names: [], enums: [] }) {
  if (!schema || typeof schema !== "object") return out;
  if (Array.isArray(schema)) {
    for (const item of schema) schemaWords(item, out);
    return out;
  }
  if (schema.properties && typeof schema.properties === "object") {
    for (const [name, sub] of Object.entries(schema.properties)) {
      out.names.push(name);
      schemaWords(sub, out);
    }
  }
  if (Array.isArray(schema.enum)) out.enums.push(...schema.enum.map((value) => String(value)));
  for (const key of ["items", "additionalProperties", "anyOf", "oneOf", "allOf", "not"]) {
    if (schema[key] && typeof schema[key] === "object") schemaWords(schema[key], out);
  }
  return out;
}

/** Every environment key a source file reads through `process.env`. */
function envKeysIn(source) {
  const names = new Set();
  const pattern =
    /process\.env(?:\.([A-Za-z_][A-Za-z0-9_]*)|\[\s*["']([A-Za-z_][A-Za-z0-9_]*)["']\s*\])/g;
  for (const match of String(source).matchAll(pattern)) names.add(match[1] || match[2]);
  return [...names];
}

/** Valid arguments for every tool, in an order the fake engine can carry out. */
function argsForEveryTool(overrides = {}) {
  const base = {
    crow_cb_balances: {},
    crow_cb_bots: {},
    crow_cb_bot_status: { bot_id: "bot-test-1" },
    crow_cb_fills: { bot_id: "bot-test-1", limit: 2 },
    crow_cb_pnl: {},
    crow_cb_price: { product: "BTC-USDC" },
    crow_cb_bot_pause: { bot_id: "bot-test-1" },
    crow_cb_bot_resume: { bot_id: "bot-test-1", acknowledge_rebase: true },
    crow_cb_bot_stop: { bot_id: "bot-test-1" },
    crow_cb_bot_recenter: { bot_id: "bot-test-1", center: "60000" },
    crow_cb_bot_create: {
      id: "bot-new-1",
      product: "BTC-USDC",
      strategy: "rebalance",
      params: { target_base_pct: 50 },
      capital_quote: "10.00",
      capital_base: "0",
    },
    crow_cb_order_preview: {
      product: "BTC-USDC",
      side: "BUY",
      size: "0.0010",
      limit_price: "60000",
    },
    crow_cb_order_place: { preview_id: "pv-audit-1" },
    crow_cb_order_cancel: { client_order_id: "cid-audit-1" },
  };
  return { ...base, ...overrides };
}

/** A fake engine carrying one bot, its pnl, five fills and two scripted answers. */
async function seededFake() {
  const fake = await openFake();
  fake.state.bots.push(fakeBot({ id: "bot-test-1" }));
  fake.state.pnl.bots = {
    "bot-test-1": { bot: "bot-test-1", realized_pnl: "pnl-marker-77", unrealized_pnl: "0" },
  };
  fake.state.fills["bot-test-1"] = Array.from({ length: 5 }, (_unused, i) => ({
    id: `f5-0${i}`,
    client_order_id: `cid-fill-${i}`,
    bot: "bot-test-1",
    product: "BTC-USDC",
    side: "BUY",
    size: "0.0010",
    price: "60000.00",
  }));
  fake.next("POST", "/ai/previews", { status: 200, body: fakePreview({ preview_id: "pv-audit-1" }) });
  fake.next("POST", "/ai/orders/cid-audit-1/cancel", {
    status: 200,
    body: { cid: "cid-audit-1", cancelled: true },
  });
  fake.state.previews.push(fakePreview({ preview_id: "pv-audit-1", state: "pending" }));
  return fake;
}

after(async () => {
  for (const close of openedConnections.reverse()) {
    try {
      await close();
    } catch {
      // a connection already gone
    }
  }
  for (const fake of openedFakes) {
    // Across this whole file, no tool may ever steer a request at an approval route.
    const approved = fake.state.requests
      .filter((record) => /approve/i.test(String(record.path)))
      .map((record) => `${record.method} ${record.path}`);
    assert.deepEqual(approved, [], "no request ever reaches an approval route");
    try {
      await fake.close();
    } catch {
      // the fake is already gone
    }
  }
  for (const home of scratchHomes) {
    try {
      rmScratch(home);
    } catch {
      // already gone
    }
  }
  cleanupScratch();
});

// ---- 1. the tool list -------------------------------------------------------------------------

test("test_tool_list_exact", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);
  const { tools } = await sdk.listTools();
  const names = tools.map((tool) => tool.name).sort();

  assert.equal(TOOL_NAMES.length, 14, "the design names 14 tools");
  assert.deepEqual(names, [...TOOL_NAMES].sort(), "the tool list is exactly the design's 14 names");
  assert.equal(names.includes("crow_cb_price"), true, "the engine's price read is served");
  // The engine has no bot-update route, so a tool for it would only ever fail.
  assert.equal(names.includes("crow_cb_bot_update"), false, "there is no bot-update tool");

  for (const tool of tools) {
    assert.doesNotMatch(tool.name, FORBIDDEN_IN_TOOLS, `${tool.name} is named plainly`);
    const words = schemaWords(tool.inputSchema);
    for (const word of words.names) {
      assert.doesNotMatch(word, FORBIDDEN_IN_TOOLS, `${tool.name} takes no input named ${word}`);
    }
    for (const value of words.enums) {
      assert.doesNotMatch(value, FORBIDDEN_IN_TOOLS, `${tool.name} accepts no value named ${value}`);
    }
  }
});

// ---- 2. a new bot is always a practice bot ----------------------------------------------------

test("test_create_bot_always_dry", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);
  const createArgs = argsForEveryTool().crow_cb_bot_create;

  const created = await call(sdk, "crow_cb_bot_create", createArgs);
  assert.equal(created.isError, false, `creating a bot is answered, not refused: ${created.text}`);

  const posts = fake.state.requests.filter(
    (record) => record.method === "POST" && record.path === "/bots",
  );
  assert.equal(posts.length, 1, "one bot, one create request");
  const body = JSON.parse(posts[0].body);
  assert.deepEqual(
    Object.keys(body).sort(),
    ["capital_base", "capital_quote", "id", "params", "product", "strategy"],
    "the engine is sent exactly the six bot fields",
  );
  assert.equal("mode" in body, false, "no mode ever goes out with a new bot");
  assert.equal(fake.state.bots.length, 1);
  assert.equal(fake.state.bots[0].mode, "dry", "the engine made a practice bot");

  // The tool has no mode input at all.
  const { tools } = await sdk.listTools();
  const createTool = tools.find((tool) => tool.name === "crow_cb_bot_create");
  assert.ok(createTool, "the create tool is registered");
  assert.equal(
    "mode" in (createTool.inputSchema.properties || {}),
    false,
    "the create tool takes no mode",
  );

  // Asking for a live bot anyway changes nothing the engine sees.
  try {
    await sdk.callTool({
      name: "crow_cb_bot_create",
      arguments: { ...createArgs, id: "bot-new-2", mode: "live" },
    });
  } catch {
    // the SDK is free to refuse the extra argument outright
  }
  for (const post of fake.state.requests.filter(
    (record) => record.method === "POST" && record.path === "/bots",
  )) {
    assert.equal("mode" in JSON.parse(post.body), false, "no create request carried a mode");
  }
  for (const bot of fake.state.bots) {
    assert.equal(bot.mode, "dry", `${bot.id} is a practice bot`);
  }
});

// ---- 2b. the create tool's strategy and params are typed -------------------------------------

test("test_create_bot_params_typed", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);
  const botPosts = () =>
    fake.state.requests.filter((record) => record.method === "POST" && record.path === "/bots");

  // 1. The published params schema is a closed object carrying every field the
  //    engine's two strategies read, each one described and each one optional.
  const { tools } = await sdk.listTools();
  const createTool = tools.find((tool) => tool.name === "crow_cb_bot_create");
  assert.ok(createTool, "the create tool is registered");
  const paramsSchema = (createTool.inputSchema.properties || {}).params;
  assert.ok(paramsSchema, "the create tool publishes a params schema");
  assert.equal(paramsSchema.type, "object", "params is an object");
  assert.equal(paramsSchema.additionalProperties, false, "params refuses an unknown field");
  assert.deepEqual(
    Object.keys(paramsSchema.properties || {}).sort(),
    [
      "band_pts",
      "center",
      "levels_above",
      "levels_below",
      "min_trade_quote",
      "quote_per_buy",
      "rebuy_sizing",
      "reprice_after_s",
      "step_pct",
      "target_base_pct",
    ],
    "params names exactly the settings the engine's strategies read",
  );
  const requiredParams = Array.isArray(paramsSchema.required) ? paramsSchema.required : [];
  for (const [name, sub] of Object.entries(paramsSchema.properties || {})) {
    assert.equal(typeof sub.description, "string", `${name} is described`);
    assert.ok(sub.description.length > 0, `${name} carries a description`);
    assert.equal(requiredParams.includes(name), false, `${name} is optional`);
  }
  assert.equal(
    JSON.stringify(createTool.inputSchema).includes('"$ref"'),
    false,
    "the create schema carries no $ref",
  );

  // 2. The strategy is one of the engine's two, and nothing else.
  const strategySchema = (createTool.inputSchema.properties || {}).strategy;
  assert.deepEqual(strategySchema.enum, ["grid", "rebalance"], "the strategy is an enum of two");

  // 3. A complete grid bot reaches the engine with its params, untouched.
  const gridArgs = {
    id: "bot-grid-1",
    product: "BTC-USDC",
    strategy: "grid",
    params: {
      center: "60000",
      step_pct: "1",
      levels_below: 3,
      levels_above: 3,
      quote_per_buy: "5",
      rebuy_sizing: "proceeds",
    },
    capital_quote: "100.00",
    capital_base: "0",
  };
  const beforeGrid = botPosts().length;
  const gridCreated = await call(sdk, "crow_cb_bot_create", gridArgs);
  assert.equal(gridCreated.isError, false, `a grid bot is created: ${gridCreated.text}`);
  const gridPosts = botPosts();
  assert.equal(gridPosts.length, beforeGrid + 1, "a valid grid create reaches the engine once");
  const gridBody = JSON.parse(gridPosts[gridPosts.length - 1].body);
  assert.equal(gridBody.strategy, "grid", "the engine is sent the grid strategy");
  assert.deepEqual(gridBody.params, gridArgs.params, "the engine is sent the grid params");

  // 4. and 5. A params key the schema does not name, and a strategy it does not
  // name, are both refused before anything reaches the engine.
  const baseArgs = argsForEveryTool().crow_cb_bot_create;
  const refused = async (args, why) => {
    const before = botPosts().length;
    let thrown = null;
    let result = null;
    try {
      result = await sdk.callTool({ name: "crow_cb_bot_create", arguments: args });
    } catch (error) {
      // the SDK is free to refuse the arguments outright
      thrown = error;
    }
    assert.ok(
      thrown !== null || result?.isError === true,
      `${why} is refused: ${thrown ? thrown.message : textOf(result)}`,
    );
    assert.equal(botPosts().length, before, `${why} never reaches the engine`);
  };

  await refused(
    { ...baseArgs, id: "bot-unknown-key", params: { target_base_pct: 50, bogus: 1 } },
    "a params key the schema does not name",
  );
  await refused(
    { ...baseArgs, id: "bot-martingale", strategy: "martingale" },
    "a strategy that is not the engine's",
  );
});

// ---- 3. a live bot may only be paused or stopped ----------------------------------------------

test("test_live_bot_only_pause_stop", async () => {
  const fake = await openFake();
  fake.state.bots.push(fakeBot({ id: "bot-live", mode: "live", status: "ACTIVE" }));
  fake.state.bots.push(fakeBot({ id: "bot-dry-1", mode: "dry", status: "PAUSED" }));
  const sdk = await connectToFake(fake);
  const live = () => fake.state.bots.find((bot) => bot.id === "bot-live");
  const dry = () => fake.state.bots.find((bot) => bot.id === "bot-dry-1");

  const paused = await call(sdk, "crow_cb_bot_pause", { bot_id: "bot-live" });
  assert.equal(paused.isError, false, `pausing a live bot is allowed: ${paused.text}`);
  assert.equal(live().status, "PAUSED", "the engine paused the live bot");

  const stopped = await call(sdk, "crow_cb_bot_stop", { bot_id: "bot-live" });
  assert.equal(stopped.isError, false, `stopping a live bot is allowed: ${stopped.text}`);
  assert.equal(live().status, "STOPPED", "the engine stopped the live bot");

  const resumed = await call(sdk, "crow_cb_bot_resume", {
    bot_id: "bot-live",
    acknowledge_rebase: true,
  });
  assert.equal(resumed.isError, true, "resuming a live bot from here is refused");
  assert.match(resumed.text, /Live bots can only be paused or stopped from here/, resumed.text);

  const recentered = await call(sdk, "crow_cb_bot_recenter", {
    bot_id: "bot-live",
    center: "60000",
  });
  assert.equal(recentered.isError, true, "recentering a live bot from here is refused");
  assert.match(recentered.text, /Live bots can only be paused or stopped from here/, recentered.text);

  assert.equal(live().status, "STOPPED", "the refused resume changed nothing");
  assert.equal(fake.state.bots.find((bot) => bot.id === "bot-live").params.center, undefined);

  for (const path of ["/bots/bot-live/resume", "/bots/bot-live/recenter"]) {
    const record = fake.last("POST", path);
    assert.ok(record, `${path} reached the engine`);
    assert.equal(record.mac, "none", `${path} carried no MAC`);
  }
  for (const answer of [resumed, recentered]) {
    assert.equal(answer.text.includes("LIVE_NEEDS_OWNER"), false, "no engine code leaks into the answer");
  }

  // A practice bot is still the AI's to resume and recenter.
  const dryResumed = await call(sdk, "crow_cb_bot_resume", {
    bot_id: "bot-dry-1",
    acknowledge_rebase: true,
  });
  assert.equal(dryResumed.isError, false, `a practice bot resumes: ${dryResumed.text}`);
  assert.equal(dry().status, "ACTIVE", "the engine resumed the practice bot");

  const dryRecentered = await call(sdk, "crow_cb_bot_recenter", {
    bot_id: "bot-dry-1",
    center: "60000",
  });
  assert.equal(dryRecentered.isError, false, `a practice bot recenters: ${dryRecentered.text}`);
  assert.equal(dry().params.center, "60000", "the engine recentered the practice bot");
});

// ---- 3b. pause says what it did to the bot's waiting orders ------------------------------------

test("test_bot_pause_copy", async () => {
  const fake = await openFake();
  fake.state.bots.push(fakeBot({ id: "bot-test-1", status: "ACTIVE" }));
  const sdk = await connectToFake(fake);

  const { tools } = await sdk.listTools();
  const tool = tools.find((candidate) => candidate.name === "crow_cb_bot_pause");
  assert.ok(tool, "the pause tool is registered");
  assert.equal(tool.description, PAUSE_DESCRIPTION, "the description says pause cancels waiting orders");
  assert.equal(
    PAUSE_DESCRIPTION.includes("use stop instead"),
    true,
    "the description points at stop for a bot that is finished for good",
  );

  const paused = await call(sdk, "crow_cb_bot_pause", { bot_id: "bot-test-1" });
  assert.equal(paused.isError, false, `pausing a bot is answered: ${paused.text}`);
  const answer = JSON.parse(paused.text);
  assert.equal(answer.message, PAUSE_MESSAGE, "the answer says the waiting orders were cancelled");
  assert.equal(answer.bot?.status, "PAUSED", "the engine's own bot row comes back");
  assert.equal(
    fake.state.bots.find((bot) => bot.id === "bot-test-1").status,
    "PAUSED",
    "the engine paused the bot",
  );
});

test("test_bot_pause_incomplete_plain_sentence", async () => {
  const fake = await openFake();
  fake.state.bots.push(fakeBot({ id: "bot-test-1", status: "ACTIVE" }));
  const sdk = await connectToFake(fake);

  // The engine's own detail carries exchange wording and a machine code after the fixed prefix.
  const engineWords = "Coinbase refused the cancel: RATE_LIMITED upstream-wording-9f31";
  fake.next("POST", "/bots/bot-test-1/pause", {
    status: 502,
    body: { code: "PAUSE_INCOMPLETE", detail: `PAUSE_INCOMPLETE: ${engineWords}` },
  });

  const paused = await call(sdk, "crow_cb_bot_pause", { bot_id: "bot-test-1" });
  assert.equal(paused.isError, true, "a pause that could not cancel everything is an error");
  assert.equal(paused.text, PAUSE_INCOMPLETE_SENTENCE, `the fixed sentence is the answer: ${paused.text}`);
  assert.equal(paused.text.includes(engineWords), false, "no exchange wording reaches the answer");
  assert.equal(paused.text.includes("RATE_LIMITED"), false, "no engine code leaks into the answer");
  assert.equal(paused.text.includes("PAUSE_INCOMPLETE"), false, "the machine code is never spoken");
  assert.doesNotMatch(paused.text, /^\s+at /m, "the answer carries no stack line");
});

test("test_bot_pause_too_soon_plain_sentence", async () => {
  const fake = await openFake();
  fake.state.bots.push(fakeBot({ id: "bot-test-1", status: "PAUSED" }));
  const sdk = await connectToFake(fake);

  // The engine's own detail carries a machine code and its own made-up sentence after it.
  const engineWords = "engine-wording-4c18: the pause debounce tripped";
  fake.next("POST", "/bots/bot-test-1/pause", {
    status: 429,
    body: { detail: `PAUSE_TOO_SOON: ${engineWords}` },
  });

  const tooSoon = await call(sdk, "crow_cb_bot_pause", { bot_id: "bot-test-1" });
  assert.equal(tooSoon.isError, true, "a debounced pause is an error");
  assert.equal(
    tooSoon.text,
    PAUSE_TOO_SOON_SENTENCE,
    `the fixed sentence is the answer: ${tooSoon.text}`,
  );
  assert.equal(tooSoon.text.includes(engineWords), false, "no engine wording reaches the answer");
  assert.equal(tooSoon.text.includes("PAUSE_TOO_SOON"), false, "the machine code is never spoken");
  assert.equal(
    tooSoon.text.includes("Too many requests"),
    false,
    "the generic rate-limit sentence is not the answer",
  );
  assert.doesNotMatch(tooSoon.text, /^\s+at /m, "the answer carries no stack line");
});

test("test_bot_pause_in_progress_plain_sentence", async () => {
  const fake = await openFake();
  fake.state.bots.push(fakeBot({ id: "bot-test-1", status: "PAUSED" }));
  const sdk = await connectToFake(fake);

  // The engine's own detail carries a machine code and its own made-up sentence after it.
  const engineWords = "engine-wording-6e13: the runner is still sweeping this bot";
  fake.next("POST", "/bots/bot-test-1/pause", {
    status: 409,
    body: { code: "PAUSE_IN_PROGRESS", detail: `PAUSE_IN_PROGRESS: ${engineWords}` },
  });

  const inProgress = await call(sdk, "crow_cb_bot_pause", { bot_id: "bot-test-1" });
  assert.equal(inProgress.isError, true, "a pause that is still running is an error");
  assert.equal(
    inProgress.text,
    PAUSE_IN_PROGRESS_SENTENCE,
    `the fixed sentence is the answer: ${inProgress.text}`,
  );
  assert.equal(inProgress.text.includes(engineWords), false, "no engine wording reaches the answer");
  assert.equal(inProgress.text.includes("PAUSE_IN_PROGRESS"), false, "the machine code is never spoken");
  assert.equal(
    inProgress.text.includes("could not complete"),
    false,
    "the generic failure sentence is not the answer",
  );
  assert.doesNotMatch(inProgress.text, /^\s+at /m, "the answer carries no stack line");
});

test("test_bot_pause_changed_plain_sentence", async () => {
  const fake = await openFake();
  fake.state.bots.push(fakeBot({ id: "bot-test-1", status: "PAUSED" }));
  const sdk = await connectToFake(fake);

  // The engine's own detail carries a machine code and its own made-up sentence after it.
  const engineWords = "engine-wording-2f47: the bot was edited mid-sweep";
  fake.next("POST", "/bots/bot-test-1/pause", {
    status: 409,
    body: { detail: `PAUSE_CHANGED: ${engineWords}` },
  });

  const changed = await call(sdk, "crow_cb_bot_pause", { bot_id: "bot-test-1" });
  assert.equal(changed.isError, true, "a pause that raced a change is an error");
  assert.equal(
    changed.text,
    PAUSE_CHANGED_SENTENCE,
    `the fixed sentence is the answer: ${changed.text}`,
  );
  assert.equal(changed.text.includes(engineWords), false, "no engine wording reaches the answer");
  assert.equal(changed.text.includes("PAUSE_CHANGED"), false, "the machine code is never spoken");
  assert.equal(
    changed.text.includes("could not complete"),
    false,
    "the generic failure sentence is not the answer",
  );
  assert.doesNotMatch(changed.text, /^\s+at /m, "the answer carries no stack line");
});

// ---- 4. the order tools never approve ---------------------------------------------------------

test("test_order_place_never_approves", async () => {
  const fake = await openFake();
  const enginePreview = fakePreview({ preview_id: "pv-place-1" });
  fake.next("POST", "/ai/previews", { status: 200, body: enginePreview });
  fake.state.previews.push(fakePreview({ preview_id: "pv-place-1", state: "pending" }));
  fake.state.previews.push(fakePreview({ preview_id: "pv-placed-1", state: "placed" }));
  fake.state.previews.push(fakePreview({ preview_id: "pv-expired-1", state: "expired" }));
  const sdk = await connectToFake(fake);

  const preview = await call(sdk, "crow_cb_order_preview", {
    product: "BTC-USDC",
    side: "BUY",
    size: "0.0010",
    limit_price: "60000",
  });
  assert.equal(preview.isError, false, `a preview is measured, not refused: ${preview.text}`);
  assert.match(preview.text, /pv-place-1/, "the preview id comes back");
  assert.equal(
    preview.text.includes(APPROVAL_LINK("pv-place-1")),
    true,
    "the answer carries the dashboard approval link",
  );
  assert.equal(preview.text.includes(enginePreview.hash), false, "the engine's hash never comes back");

  const placed = await call(sdk, "crow_cb_order_place", { preview_id: "pv-place-1" });
  assert.equal(placed.isError, false, `placing a pending preview is answered: ${placed.text}`);
  assert.match(placed.text, /"state": "pending"/, "the state is the proposal's own state");
  assert.equal(placed.text.includes(APPROVAL_LINK("pv-place-1")), true, "the approval link comes back");
  assert.equal(
    placed.text.includes(WAITING_SENTENCE),
    true,
    "the plain sentence says what happens next",
  );

  const unknown = await call(sdk, "crow_cb_order_place", { preview_id: "pv-nope-1" });
  assert.equal(unknown.isError, true, "an unknown proposal is an error");
  assert.match(unknown.text, /No order proposal with that id\./, unknown.text);

  for (const [previewId, state] of [
    ["pv-placed-1", "placed"],
    ["pv-expired-1", "expired"],
  ]) {
    const answer = await call(sdk, "crow_cb_order_place", { preview_id: previewId });
    const says = new RegExp(state, "i");
    assert.match(answer.text, says, `the answer says the proposal is ${state}: ${answer.text}`);
    assert.equal(
      answer.text.includes("/dashboard/coinbase?preview="),
      false,
      `a ${state} proposal carries no approval link`,
    );
    assert.equal(answer.text.includes(WAITING_SENTENCE), false, `a ${state} proposal is not waiting`);
  }

  // Nothing here ever steered a request at an approval route (the file-wide scan in `after`
  // holds this for every test; here it is stated for this one too).
  assert.deepEqual(
    fake.state.requests
      .filter((record) => /approve/i.test(String(record.path)))
      .map((record) => `${record.method} ${record.path}`),
    [],
    "no approve request reached the engine",
  );
});

// ---- 5. no Coinbase secret in the server's world ---------------------------------------------

test("test_mcp_env_has_no_coinbase_secrets", async () => {
  // (a) what the sources say.
  const files = readdirSync(SERVER_DIR).filter((name) => name.endsWith(".js"));
  assert.ok(files.includes("index.js"), "the stdio entry ships");
  assert.ok(files.includes("server.js"), "the server factory ships");

  const checked = files.filter(
    (name) => name === "index.js" || name === "server.js" || !PRE_EXISTING_SERVER_FILES.has(name),
  );
  for (const name of checked) {
    const source = readFileSync(join(SERVER_DIR, name), "utf8");
    assert.doesNotMatch(
      source,
      FORBIDDEN_IN_SOURCE,
      `${name} names no install token, key material or secret provider`,
    );
    for (const key of envKeysIn(source)) {
      assert.ok(
        ALLOWED_ENV_KEYS.has(key),
        `${name} reads only ${[...ALLOWED_ENV_KEYS].join(" / ")} from the environment (found ${key})`,
      );
    }
  }

  // (b) what the running child reads and sends.
  const fake = await openFake();
  const home = mkdtempSync(join(tmpdir(), "crow-coinbase-mcp-home-"));
  scratchHomes.push(home);
  const installToken = randomBytes(32).toString("base64url");
  mkdirSync(join(home, "bundles", "coinbase"), { recursive: true });
  writeFileSync(
    join(home, "bundles", "coinbase", ".env"),
    `CROW_COINBASE_ENGINE_TOKEN=${ENGINE_TOKEN}\n`,
    { mode: 0o600 },
  );
  mkdirSync(join(home, "coinbase", "install"), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, "coinbase", "install", "install_token"), `${installToken}\n`, {
    mode: 0o644,
  });

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [INDEX],
    env: { CROW_HOME: home, CROW_COINBASE_ENGINE_URL: fake.baseUrl },
    stderr: "pipe",
  });
  const child = new Client({ name: "coinbase-mcp-child", version: "0.0.0" });
  await child.connect(transport);
  try {
    const { tools } = await child.listTools();
    assert.deepEqual(
      tools.map((tool) => tool.name).sort(),
      [...TOOL_NAMES].sort(),
      "the child serves the same tool list",
    );

    const balances = await child.callTool({ name: "crow_cb_balances", arguments: {} });
    const balancesText = textOf(balances);

    assert.ok(fake.state.requests.length > 0, "the child reached the fake engine");
    for (const record of fake.state.requests) {
      assert.equal(
        record.headers.authorization,
        `Bearer ${ENGINE_TOKEN}`,
        `${record.method} ${record.path} carried the engine token from the bundle .env`,
      );
      assert.equal(record.headers["x-crow-source"], "mcp", `${record.path} is tagged as an MCP call`);
      for (const header of ["x-crow-signature", "x-crow-timestamp", "x-crow-nonce"]) {
        assert.equal(header in record.headers, false, `${record.path} carried no ${header}`);
      }
      assert.equal(
        JSON.stringify(record.headers).includes(installToken),
        false,
        `${record.path} carried no install token in a header`,
      );
      assert.equal(
        String(record.body || "").includes(installToken),
        false,
        `${record.path} carried no install token in its body`,
      );
    }
    assert.equal(
      balancesText.includes(installToken),
      false,
      "the install token never reaches the tool's answer",
    );
  } finally {
    await child.close();
  }

  // Without the bundle `.env` the child says so in one sentence and stops, and
  // the operator is shown no stack.
  const bare = mkdtempSync(join(tmpdir(), "crow-coinbase-mcp-bare-"));
  scratchHomes.push(bare);
  const exit = await runToEnd(bare);
  assert.notEqual(exit.code, 0, `the child exits non-zero without a token: ${exit.stderr}`);
  assert.match(exit.stderr, /Coinbase engine token not found/, exit.stderr);
  assert.doesNotMatch(exit.stderr, /^\s+at /m, `the child prints no stack: ${exit.stderr}`);
});

/**
 * Run the stdio entry against one Crow home, with nothing on its stdin, and read its end.
 *
 * `extraEnv` is added to the child's few environment keys, and a child that neither
 * answers nor ends within `timeoutMs` is killed and reported as `timedOut`, so a
 * broken entry fails its test instead of hanging the file.
 */
function runToEnd(home, extraEnv = {}, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [INDEX], {
      env: { PATH: process.env.PATH || "", HOME: process.env.HOME || "", CROW_HOME: home, ...extraEnv },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    let timer = null;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(result);
    };
    timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // the child is already gone
      }
      finish({ code: null, stdout, stderr, timedOut: true });
    }, timeoutMs);
    if (typeof timer.unref === "function") timer.unref();
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (error) =>
      finish({ code: null, stdout, stderr: `${stderr}${error.message}`, timedOut: false }),
    );
    child.on("close", (code) => finish({ code, stdout, stderr, timedOut: false }));
  });
}

// ---- 6. every engine call is tagged for the audit trail ---------------------------------------

test("test_control_tools_tagged_for_audit", async () => {
  const fake = await seededFake();
  const sdk = await connectToFake(fake);
  const args = argsForEveryTool();

  // The price read has no default answer on the fake: it answers from a script here.
  fake.state.scripted.push({
    method: "GET",
    path: "/price?product=BTC-USDC",
    status: 200,
    body: { product: "BTC-USDC", price: "60000.5", ts: 1700000000.5 },
  });

  for (const name of TOOL_NAMES) {
    await call(sdk, name, args[name]);
  }

  assert.ok(fake.state.requests.length > 0, "the tools reached the engine");
  for (const record of fake.state.requests) {
    assert.equal(
      record.headers["x-crow-source"],
      "mcp",
      `${record.method} ${record.path} is tagged as an MCP call`,
    );
  }
  assert.ok(
    fake.state.requests.length >= TOOL_NAMES.length,
    `${TOOL_NAMES.length} tools made at least one request each (saw ${fake.state.requests.length})`,
  );

  for (const record of fake.state.requests) {
    const path = String(record.path).split("?")[0];
    const allowed = ALLOWED_ROUTES.some(
      ([method, pattern]) => method === record.method && pattern.test(path),
    );
    assert.equal(allowed, true, `${record.method} ${path} is one the MCP server may make`);
  }
});

// ---- 7. an engine that is not there, and one that breaks --------------------------------------

test("test_engine_down_plain_message", async () => {
  const fake = await openFake();
  const baseUrl = fake.baseUrl;
  await fake.close();

  const down = createEngineClient({ baseUrl, token: ENGINE_TOKEN, source: "mcp" });
  const sdk = await connect({ client: down });
  const args = argsForEveryTool();
  for (const name of TOOL_NAMES) {
    const answer = await call(sdk, name, args[name]);
    assert.equal(answer.isError, true, `${name} is an error while the engine is down`);
    assert.equal(answer.text, ENGINE_DOWN_SENTENCE, `${name} answers in one plain sentence`);
    assert.equal(answer.text.includes("ECONNREFUSED"), false, `${name} names no socket error`);
    assert.equal(answer.text.includes("fetch"), false, `${name} names no fetch`);
    assert.doesNotMatch(answer.text, /^\s+at /m, `${name} carries no stack line`);
    assert.equal(answer.text.includes(ENGINE_TOKEN), false, `${name} carries no token`);
  }

  // A client that throws instead of answering is the generic sentence, and the
  // error's own words stay out of it.
  const exploding = {};
  for (const method of [
    "balances",
    "bots",
    "botFills",
    "pnl",
    "createBot",
    "botPause",
    "botStop",
    "botResume",
    "botRecenter",
    "aiPreview",
    "aiPreviews",
    "aiCancel",
  ]) {
    exploding[method] = () => {
      throw new Error("boom secret-xyz");
    };
  }
  const broken = await connect({ client: exploding });
  const caught = await call(broken, "crow_cb_balances", {});
  assert.equal(caught.isError, true, "a throwing client is an error");
  assert.equal(caught.text, GENERIC_SENTENCE, "a throwing client earns the generic sentence");
  assert.equal(caught.text.includes("boom"), false, "the error's message never leaks");
  assert.equal(caught.text.includes("secret-xyz"), false, "nothing of the error leaks");
});

// ---- 11. the engine address, and the fixed sentences a refusal earns --------------------------

test("test_engine_url_must_be_loopback", async () => {
  const fake = await openFake();
  const port = new URL(fake.baseUrl).port;

  // A real install: the bundle's own `.env` carries a token, so the address is the only
  // thing that can stop this child.
  const home = mkdtempSync(join(tmpdir(), "crow-coinbase-mcp-url-home-"));
  scratchHomes.push(home);
  mkdirSync(join(home, "bundles", "coinbase"), { recursive: true });
  writeFileSync(join(home, "bundles", "coinbase", ".env"), `CROW_COINBASE_ENGINE_TOKEN=${ENGINE_TOKEN}\n`, {
    mode: 0o600,
  });

  // Everything but a plain http address on this computer: https, another host, a link-local
  // address, userinfo, a look-alike name, another scheme, and a string that is not a URL.
  const refused = [
    "https://127.0.0.1:1",
    "http://example.invalid:1",
    "http://169.254.169.254",
    `http://user:pw@127.0.0.1:${port}`,
    "http://127.0.0.1.evil.test:1",
    "ftp://127.0.0.1",
    "not a url",
  ];

  for (const value of refused) {
    const run = await runToEnd(home, { CROW_COINBASE_ENGINE_URL: value });
    assert.equal(run.timedOut, false, `${value} ends instead of serving`);
    assert.notEqual(run.code, 0, `${value} exits non-zero: ${run.stderr}`);
    assert.equal(
      run.stderr.includes(ENGINE_URL_SENTENCE),
      true,
      `${value} earns the one plain sentence: ${run.stderr}`,
    );
    assert.doesNotMatch(run.stderr, /^\s+at /m, `${value} prints no stack: ${run.stderr}`);
    assert.equal(run.stderr.includes(value), false, `the refused address ${JSON.stringify(value)} is not echoed`);
    assert.equal(run.stdout, "", `${value} serves nothing on stdout`);
  }

  // Refusing the address happens before anything is sent anywhere.
  assert.deepEqual(
    fake.state.requests.map((record) => `${record.method} ${record.path}`),
    [],
    "no refused address reached the engine",
  );

  // The two loopback spellings still start the server: the tool list is what it serves.
  for (const value of [`http://127.0.0.1:${port}`, `http://localhost:${port}`]) {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [INDEX],
      env: { CROW_HOME: home, CROW_COINBASE_ENGINE_URL: value },
      stderr: "pipe",
    });
    const child = new Client({ name: "coinbase-mcp-url-child", version: "0.0.0" });
    await child.connect(transport);
    try {
      const { tools } = await child.listTools();
      assert.deepEqual(
        tools.map((tool) => tool.name).sort(),
        [...TOOL_NAMES].sort(),
        `${value} still serves the tool list`,
      );
    } finally {
      await child.close();
    }
  }
});

test("test_server_errors_hide_engine_text", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);
  const jwtShape = "eyJhbGciOi.synthetic.payload";
  const exchangeWords = "exchange said no";

  for (const status of [502, 503, 500]) {
    fake.next("GET", "/balances", {
      status,
      body: {
        code: "EXCHANGE_ERROR",
        detail: `EXCHANGE_ERROR: ${jwtShape} ${exchangeWords}`,
        message: `upstream said ${jwtShape} ${exchangeWords}`,
      },
    });

    const failure = await call(sdk, "crow_cb_balances", {});
    assert.equal(failure.isError, true, `a ${status} is an error`);
    assert.equal(failure.text, UNSTATED_SENTENCE, `a ${status} answers the fixed sentence`);
    assert.equal(failure.text.includes(jwtShape), false, `a ${status} carries none of the token's shape`);
    assert.equal(failure.text.includes(exchangeWords), false, `a ${status} carries none of the exchange's words`);
    assert.equal(failure.text.includes("EXCHANGE_ERROR"), false, `a ${status} names no engine code`);
    assert.doesNotMatch(failure.text, /^\s+at /m, `a ${status} carries no stack line`);
  }
});

test("test_preview_limit_plain", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);
  const previewArgs = argsForEveryTool().crow_cb_order_preview;

  // The engine's own preview limit: a fixed sentence, and no countdown.
  fake.next("POST", "/ai/previews", {
    status: 429,
    body: { code: "PREVIEW_LIMIT", message: "whatever" },
  });
  const limited = await call(sdk, "crow_cb_order_preview", previewArgs);
  assert.equal(limited.isError, true, "a full proposal shelf is a refusal");
  assert.equal(limited.text, PREVIEW_LIMIT_SENTENCE, "the preview limit earns its own sentence");
  assert.equal(/second/i.test(limited.text), false, `the preview limit names no seconds: ${limited.text}`);
  assert.equal(limited.text.includes("whatever"), false, "the engine's own message is not repeated");

  // Any other 429 still carries the countdown.
  fake.next("POST", "/ai/previews", {
    status: 429,
    body: { code: "RATE_LIMITED", message: "slow down" },
  });
  const generic = await call(sdk, "crow_cb_order_preview", previewArgs);
  assert.equal(generic.isError, true, "a generic 429 is a refusal");
  assert.match(
    generic.text,
    /^Too many requests\. Try again in \d+ seconds\.$/,
    `a generic 429 still says how long to wait: ${generic.text}`,
  );
});

test("test_bot_limit_plain", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);

  fake.next("POST", "/bots", {
    status: 429,
    body: { detail: "BOT_LIMIT: Too many bots are running. Stop one before creating another." },
  });

  const refused = await call(sdk, "crow_cb_bot_create", argsForEveryTool().crow_cb_bot_create);
  assert.equal(refused.isError, true, "the engine's bot limit is a refusal");
  assert.equal(refused.text, BOT_LIMIT_SENTENCE, "the bot limit earns its own sentence");
  assert.equal(refused.text.includes("Too many bots are running."), false, "the engine's own words are not repeated");
  assert.equal(/second/i.test(refused.text), false, `the bot limit names no countdown: ${refused.text}`);
});

// ---- 8. cancelling is for AI orders only ------------------------------------------------------

test("test_order_cancel_ai_only", async () => {
  const fake = await openFake();
  fake.next("POST", "/ai/orders/cid-other/cancel", {
    status: 403,
    body: { code: "NOT_OWNER", message: "That order was not placed by the AI." },
  });
  fake.next("POST", "/ai/orders/cid-x/cancel", {
    status: 200,
    body: { cid: "cid-x", cancelled: true },
  });
  const sdk = await connectToFake(fake);

  const refused = await call(sdk, "crow_cb_order_cancel", { client_order_id: "cid-other" });
  assert.equal(refused.isError, true, "an order the AI did not place cannot be cancelled");
  assert.match(refused.text, /That order was not placed by the AI\./, refused.text);

  const cancelled = await call(sdk, "crow_cb_order_cancel", { client_order_id: "cid-x" });
  assert.equal(cancelled.isError, false, `a 200 answer is data: ${cancelled.text}`);
  const cancelledAnswer = JSON.parse(cancelled.text);
  assert.equal(
    cancelledAnswer.client_order_id,
    "cid-x",
    "the answer carries the engine's own cid as the client order id",
  );
  assert.equal(cancelledAnswer.cancelled, true, "the answer says the order is cancelled");
  assert.equal("state" in cancelledAnswer, false, "the answer carries no state key");

  for (const id of ["cid/../x", "..", "cid/123"]) {
    const bad = await call(sdk, "crow_cb_order_cancel", { client_order_id: id });
    assert.equal(bad.isError, true, `the id ${JSON.stringify(id)} is refused`);
    assert.match(bad.text, /That id is not valid\./, bad.text);
    assert.equal(
      fake.state.requests.some((record) => String(record.path).includes("cid/")),
      false,
      `the id ${JSON.stringify(id)} never reached the engine`,
    );
  }
});

// ---- 9. the reads ------------------------------------------------------------------------------

test("test_read_tools", async () => {
  const fake = await seededFake();
  fake.next("GET", "/balances", {
    status: 200,
    body: { quote: "USDC", available: "balances-marker-42", book: "dry" },
  });
  const sdk = await connectToFake(fake);

  const status = await call(sdk, "crow_cb_bot_status", { bot_id: "bot-test-1" });
  assert.equal(status.isError, false, `a known bot is answered: ${status.text}`);
  assert.match(status.text, /BTC-USDC/, "the bot's own row comes back");
  assert.match(status.text, /pnl-marker-77/, "the bot's pnl entry comes back with it");

  const missing = await call(sdk, "crow_cb_bot_status", { bot_id: "bot-nope" });
  assert.equal(missing.isError, true, "an unknown bot is an error");
  assert.match(missing.text, /No bot with that id\./, missing.text);

  const twoFills = await call(sdk, "crow_cb_fills", { bot_id: "bot-test-1", limit: 2 });
  assert.equal(twoFills.isError, false, `the fills are answered: ${twoFills.text}`);
  assert.equal(twoFills.text.includes("f5-04"), true, "the newest fill is there");
  assert.equal(twoFills.text.includes("f5-03"), true, "the second newest fill is there");
  for (const gone of ["f5-02", "f5-01", "f5-00"]) {
    assert.equal(twoFills.text.includes(gone), false, `${gone} is outside the last two`);
  }

  fake.state.fills["bot-test-1"] = Array.from({ length: 25 }, (_unused, i) => ({
    id: `f25-${String(i).padStart(2, "0")}`,
    client_order_id: `cid-many-${i}`,
    bot: "bot-test-1",
  }));
  const capped = await call(sdk, "crow_cb_fills", { bot_id: "bot-test-1" });
  assert.equal(capped.isError, false, `the fills are answered without a limit: ${capped.text}`);
  assert.equal(capped.text.includes("f25-24"), true, "the newest of the many fills is there");
  assert.equal(capped.text.includes("f25-05"), true, "the twentieth newest fill is still inside the cap");
  for (const gone of ["f25-04", "f25-00"]) {
    assert.equal(capped.text.includes(gone), false, `${gone} is beyond the default cap`);
  }

  const balances = await call(sdk, "crow_cb_balances", {});
  assert.equal(balances.isError, false, `the balances are answered: ${balances.text}`);
  assert.match(balances.text, /balances-marker-42/, "the engine's balances come back");

  const bots = await call(sdk, "crow_cb_bots", {});
  assert.equal(bots.isError, false, `the bots are answered: ${bots.text}`);
  assert.match(bots.text, /bot-test-1/, "the engine's bots come back");

  const pnl = await call(sdk, "crow_cb_pnl", {});
  assert.equal(pnl.isError, false, `the pnl is answered: ${pnl.text}`);
  assert.match(pnl.text, /pnl-marker-77/, "the engine's pnl comes back");
});

// ---- 9b. the price read --------------------------------------------------------------------------

test("test_price_tool", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);

  fake.state.scripted.push({
    method: "GET",
    path: "/price?product=BTC-USDC",
    status: 200,
    body: { product: "BTC-USDC", price: "60000.5", ts: 1700000000.5 },
  });

  const priced = await call(sdk, "crow_cb_price", { product: "BTC-USDC" });
  assert.equal(priced.isError, false, `a price is answered: ${priced.text}`);
  const answer = JSON.parse(priced.text);
  assert.equal(answer.product, "BTC-USDC", "the product comes back");
  assert.equal(answer.price, "60000.5", "the price comes back as the decimal string the engine sent");
  assert.equal(answer.ts, 1700000000.5, "the engine's own stamp comes back with it");

  const asked = fake.last("GET", "/price?product=BTC-USDC");
  assert.ok(asked, "the price read reached the engine");
  assert.equal(asked.headers.authorization, `Bearer ${ENGINE_TOKEN}`, "the read carried the engine token");
  assert.equal(asked.headers["x-crow-source"], "mcp", "the price read is tagged as an MCP call");
  assert.equal(
    ["x-crow-signature", "x-crow-timestamp", "x-crow-nonce"].some((header) => header in asked.headers),
    false,
    "a read is bearer only, never signed",
  );

  // A product this engine does not trade: the engine's own plain message is the answer.
  fake.state.scripted.push({
    method: "GET",
    path: "/price?product=NOPE-USDC",
    status: 400,
    body: { detail: "That product is not one this engine trades." },
  });
  const unknown = await call(sdk, "crow_cb_price", { product: "NOPE-USDC" });
  assert.equal(unknown.isError, true, "a product the engine does not trade is an error");
  assert.equal(unknown.text, "That product is not one this engine trades.", unknown.text);

  // A price the engine could not get is the fixed sentence every server error earns.
  fake.state.scripted.push({
    method: "GET",
    path: "/price?product=ETH-USDC",
    status: 502,
    body: { detail: "PRICE_UNAVAILABLE", message: "upstream said no" },
  });
  const broken = await call(sdk, "crow_cb_price", { product: "ETH-USDC" });
  assert.equal(broken.isError, true, "a 502 is an error");
  assert.equal(broken.text, UNSTATED_SENTENCE, `a 502 answers the fixed sentence: ${broken.text}`);
  assert.equal(broken.text.includes("PRICE_UNAVAILABLE"), false, "no engine code leaks into the answer");
  assert.equal(broken.text.includes("upstream said no"), false, "the engine's own words are not repeated");
  assert.doesNotMatch(broken.text, /^\s+at /m, "a 502 carries no stack line");
});

test("test_price_503_plain", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);

  // The engine has no price for the pair right now: this read answers the engine's
  // own fixed sentence, not the generic server-error one.
  fake.next("GET", "/price?product=BTC-USDC", {
    status: 503,
    body: { detail: NO_PRICE_SENTENCE },
  });
  const unavailable = await call(sdk, "crow_cb_price", { product: "BTC-USDC" });
  assert.equal(unavailable.isError, true, "no price right now is a refusal");
  assert.equal(
    unavailable.text,
    NO_PRICE_SENTENCE,
    `the price read says it in one sentence: ${unavailable.text}`,
  );
  assert.equal(unavailable.text.includes("HTTP_503"), false, "no engine code leaks into the answer");
  assert.equal(unavailable.text.includes(UNSTATED_SENTENCE), false, "the price read keeps its own sentence");
  assert.doesNotMatch(unavailable.text, /^\s+at /m, "the answer carries no stack line");

  // Every other server error on the same read is still the generic sentence.
  fake.next("GET", "/price?product=ETH-USDC", {
    status: 502,
    body: { detail: "PRICE_UNAVAILABLE", message: "upstream said no" },
  });
  const broken = await call(sdk, "crow_cb_price", { product: "ETH-USDC" });
  assert.equal(broken.isError, true, "a 502 is an error");
  assert.equal(broken.text, UNSTATED_SENTENCE, `a 502 keeps the fixed sentence: ${broken.text}`);
  assert.equal(broken.text.includes("upstream said no"), false, "a 502 repeats nothing of the engine's own words");

  // A 503 on another tool is unchanged: only the price read has the price sentence.
  fake.next("GET", "/balances", {
    status: 503,
    body: { detail: "the engine is busy" },
  });
  const other = await call(sdk, "crow_cb_balances", {});
  assert.equal(other.isError, true, "a 503 on another tool is an error");
  assert.equal(other.text, UNSTATED_SENTENCE, `another tool keeps the fixed sentence: ${other.text}`);
  assert.equal(other.text.includes(NO_PRICE_SENTENCE), false, "another tool does not borrow the price sentence");
  assert.equal(other.text.includes("the engine is busy"), false, "the engine's own words are not repeated");
});

// ---- 10. the descriptions say only what is true ------------------------------------------------

test("test_descriptions_honest", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);
  const { tools } = await sdk.listTools();

  for (const tool of tools) {
    const description = String(tool.description ?? "");
    assert.ok(description.trim().length > 0, `${tool.name} has a description`);
    assert.ok(description.length <= 400, `${tool.name}'s description stays short`);
    // The one approvable sentence is the honest statement, not a claim: it says who approves,
    // so it is taken out before the claim check looks at the rest of the description.
    const withoutApproval = description.split(APPROVE_SENTENCE).join("");
    assert.doesNotMatch(
      withoutApproval,
      /(can|will|may|able to) (approve|switch|move money)/i,
      `${tool.name} never claims the AI can approve, switch or move money`,
    );
  }

  // Both order tools say, in the same words, who approves a proposal and that this tool cannot.
  for (const name of ["crow_cb_order_preview", "crow_cb_order_place"]) {
    const tool = tools.find((candidate) => candidate.name === name);
    assert.ok(tool, `${name} is registered`);
    const description = String(tool.description ?? "");
    assert.equal(
      description.includes(APPROVE_SENTENCE),
      true,
      `${name} carries the exact sentence about who approves: ${description}`,
    );
  }
});

// ---- the manifest ships this server ------------------------------------------------------------

test("manifest_version_bumped", () => {
  const manifest = JSON.parse(readFileSync(join(BUNDLE_DIR, "manifest.json"), "utf8"));
  assert.equal(manifest.version, "0.4.14", `the bundle version is bumped (found ${manifest.version})`);
});