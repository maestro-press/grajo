/**
 * Finance T7 — the stock (equity) side of the Coinbase bundle, end to end at the bundle's edges:
 * the seven equity environment variables in the manifest and in both compose anchors, the registry
 * entry that carries them, the MCP preview tool's stock words and the equity block it passes
 * through unchanged (minus anything that is not one of its five facts, and minus a money fact that
 * is not the engine's own string), the approval card's two stock lines, the three shapes its money
 * line can take and their place on the card, and the trading guide's stocks section and its Stock
 * prices part (the one address it carries, the wait between price requests and the live-order line).
 *
 * The engine's own numbers are read out of `limits.py`, so a manifest default that drifts from the
 * engine's `DEFAULT_EQUITY_*` constant fails here. Every engine answer comes from the harness fake
 * engine on loopback; every figure is a test figure and every scratch dir lives under os.tmpdir().
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

import {
  REPO,
  ENGINE_TOKEN,
  createFakeEngine,
  fakePreview,
  cleanupScratch,
} from "./helpers/coinbase-panel-harness.mjs";
import { createEngineClient } from "../bundles/coinbase/server/engine-client.js";
import { createCoinbaseServer } from "../bundles/coinbase/server/server.js";
import { describePreview } from "../bundles/coinbase/panel/approve.js";
import { validateManifest } from "../scripts/lib/bundle-contract.mjs";

const BUNDLE_DIR = join(REPO, "bundles", "coinbase");
const MANIFEST = JSON.parse(readFileSync(join(BUNDLE_DIR, "manifest.json"), "utf8"));
const COMPOSE = readFileSync(join(BUNDLE_DIR, "docker-compose.yml"), "utf8");
const LIMITS_PY = readFileSync(join(BUNDLE_DIR, "engine", "src", "crow_coinbase", "limits.py"), "utf8");
const GUIDE = readFileSync(join(REPO, "docs", "guide", "trading.md"), "utf8");

const PORTFOLIO_ID = "CROW_COINBASE_EQUITY_PORTFOLIO_ID";
const EQUITY_ENV = {
  CROW_COINBASE_EQUITY_PRODUCTS: { default: "", advanced: false, constant: "DEFAULT_EQUITY_PRODUCTS" },
  CROW_COINBASE_EQUITY_LIVE: { default: "false", advanced: true, constant: "DEFAULT_EQUITY_LIVE" },
  CROW_COINBASE_EQUITY_MAX_ORDER_USD: { default: "100", advanced: false, constant: "DEFAULT_EQUITY_MAX_ORDER_USD" },
  CROW_COINBASE_EQUITY_DAILY_NOTIONAL_USD: {
    default: "200",
    advanced: false,
    constant: "DEFAULT_EQUITY_DAILY_NOTIONAL_USD",
  },
  CROW_COINBASE_EQUITY_AI_CAPITAL_USD: { default: "0", advanced: false, constant: "DEFAULT_EQUITY_AI_CAPITAL_USD" },
  CROW_COINBASE_EQUITY_DRAWDOWN_ALERT_PCT: {
    default: "20",
    advanced: false,
    constant: "DEFAULT_EQUITY_DRAWDOWN_ALERT_PCT",
  },
  // Reserved for a later step: an id for a stock key, never a secret, and no engine value.
  [PORTFOLIO_ID]: { default: "", advanced: true, constant: null },
};
const EQUITY_NAMES = Object.keys(EQUITY_ENV);

// The two sentences the contract fixes for the market, and the pool line's own words.
const MARKET_OPEN = "The stock market is open right now.";
const MARKET_CLOSED = "The stock market is closed right now, so a stock order cannot be placed until it opens.";

const envVar = (name) => (MANIFEST.env_vars || []).find((v) => v && v.name === name);

/** Every name a compose environment anchor declares, in file order. */
function anchorNames(text, anchor) {
  const lines = String(text).split("\n");
  const start = lines.findIndex((l) => l.trim().startsWith(`${anchor}:`));
  assert.ok(start >= 0, `compose has the ${anchor} anchor`);
  const names = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (!/^\s/.test(lines[i])) break; // the next top-level key ends the anchor
    const m = /^\s+([A-Za-z_][A-Za-z0-9_]*):/.exec(lines[i]);
    if (m) names.push(m[1]);
  }
  return names;
}

/** The trimmed entry lines of one compose environment anchor. */
function anchorLines(text, anchor) {
  const lines = String(text).split("\n");
  const start = lines.findIndex((l) => l.trim().startsWith(`${anchor}:`));
  assert.ok(start >= 0, `compose has the ${anchor} anchor`);
  const entries = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (!/^\s/.test(lines[i])) break;
    const m = /^\s+([A-Za-z_][A-Za-z0-9_]*:\s*.*)$/.exec(lines[i]);
    if (m) entries.push(m[1].trim());
  }
  return entries;
}

/** The right-hand side of one default assignment in limits.py. */
function pythonConstant(name) {
  const found = new RegExp(`^${name}(?::[^=\\n]*)?\\s*=\\s*(.+)$`, "m").exec(LIMITS_PY);
  assert.ok(found, `limits.py declares ${name}`);
  return found[1].trim();
}

/** The body of one `## ` section of a guide, by its heading line. */
function guideSection(text, heading) {
  const lines = String(text).split("\n");
  const at = lines.findIndex((line) => line.trim() === heading);
  assert.ok(at >= 0, `the guide has the ${heading} section`);
  const end = lines.findIndex((line, i) => i > at && /^## /.test(line));
  return lines.slice(at + 1, end === -1 ? lines.length : end).join("\n");
}

/** That constant as the text an environment variable would carry. */
function pythonDefault(name) {
  const raw = pythonConstant(name);
  const money = /^D\("([^"]*)"\)$/.exec(raw);
  if (money) return money[1];
  if (raw === "True") return "true";
  if (raw === "False") return "false";
  if (/^\(\s*\)$/.test(raw)) return "";
  assert.fail(`limits.py's ${name} is a value this test can read (found ${raw})`);
}

// ---- 1. the manifest ---------------------------------------------------------------------------

test("test_equity_env_vars_in_manifest", () => {
  const check = validateManifest(MANIFEST, BUNDLE_DIR);
  assert.deepEqual(check.errors, [], `manifest errors: ${check.errors.join("; ")}`);
  assert.equal(check.ok, true, check.errors.join("; "));
  assert.equal(MANIFEST.version, "0.4.15", `the bundle version is 0.4.15 (found ${MANIFEST.version})`);

  for (const name of EQUITY_NAMES) {
    const spec = EQUITY_ENV[name];
    const ev = envVar(name);
    assert.ok(ev, `${name} is declared`);
    assert.equal(String(ev.default), spec.default, `${name} defaults to ${JSON.stringify(spec.default)}`);
    assert.equal(ev.required, false, `${name} is not required`);
    assert.notEqual(ev.secret, true, `${name} is not a secret`);
    if (spec.advanced) {
      assert.equal(ev.advanced, true, `${name} is an advanced setting`);
    }

    // The manifest default is the engine's own default, read from limits.py.
    if (spec.constant !== null) {
      const expected = pythonDefault(spec.constant);
      const bothNumeric = /^\d+(?:\.\d+)?$/.test(expected) && /^\d+(?:\.\d+)?$/.test(String(ev.default));
      if (bothNumeric) {
        assert.equal(
          Number(ev.default),
          Number(expected),
          `${name} matches ${spec.constant} (${expected})`,
        );
      } else {
        assert.equal(ev.default, expected, `${name} matches ${spec.constant} (${expected})`);
      }
    }
  }

  // The products setting is empty by default, and it says so in the owner's words.
  const products = envVar("CROW_COINBASE_EQUITY_PRODUCTS");
  const description = String(products.description ?? "");
  assert.match(description, /NVDA-USD/, `the products description names a stock example: ${description}`);
  assert.match(description, /off/i, `the products description says stocks are off: ${description}`);
  assert.match(description, /empty/i, `the products description says when they are off: ${description}`);

  // Live stock trading is not available yet, and its own words say so: a confirmed order preview
  // comes first, and no proposal of any kind is called recorded.
  const liveDescription = String(envVar("CROW_COINBASE_EQUITY_LIVE").description ?? "");
  assert.match(
    liveDescription,
    /cannot be turned on yet/,
    `the live setting says live stock trading cannot be turned on yet: ${liveDescription}`,
  );
  assert.match(
    liveDescription,
    /confirmed order preview/,
    `the live setting names the confirmed order preview it waits for: ${liveDescription}`,
  );
  assert.doesNotMatch(
    liveDescription,
    /recorded/,
    `the live setting promises no recorded proposal: ${liveDescription}`,
  );

  // The portfolio id is reserved for a later step, and it asks for no key of any kind.
  const portfolioDescription = String(envVar(PORTFOLIO_ID).description ?? "");
  assert.match(
    portfolioDescription,
    /Leave it empty/,
    `the portfolio id says to leave it empty: ${portfolioDescription}`,
  );
  assert.doesNotMatch(
    portfolioDescription,
    /main key/,
    `the portfolio id names no main key: ${portfolioDescription}`,
  );
  assert.doesNotMatch(
    portfolioDescription,
    /second key/,
    `the portfolio id names no second key: ${portfolioDescription}`,
  );

  // No equity key or secret may ever be an environment variable.
  for (const ev of MANIFEST.env_vars || []) {
    const name = String(ev.name ?? "");
    assert.doesNotMatch(name, /EQUITY.*(KEY|SECRET)/, `${name} is no equity key or secret`);
  }
});

// ---- 2. the compose anchors ---------------------------------------------------------------------

test("test_equity_env_vars_in_compose", () => {
  const engineNames = anchorNames(COMPOSE, "x-coinbase-env");
  const watchdogNames = anchorNames(COMPOSE, "x-coinbase-watchdog-env");
  assert.ok(engineNames.length > 0, "the engine anchor declares names");
  assert.ok(watchdogNames.length > 0, "the watchdog anchor declares names");

  // The engine reads all seven; the watchdog carries the six `Limits.from_env` reads.
  for (const name of EQUITY_NAMES) {
    assert.ok(engineNames.includes(name), `the engine anchor declares ${name}`);
    if (name === PORTFOLIO_ID) {
      assert.equal(
        watchdogNames.includes(name),
        false,
        "the watchdog anchor leaves out the optional stocks portfolio id",
      );
    } else {
      assert.ok(watchdogNames.includes(name), `the watchdog anchor declares ${name}`);
    }
  }

  // Each one is `${NAME:-<default>}`, with the manifest's own default.
  for (const [anchor, names] of [
    ["x-coinbase-env", engineNames],
    ["x-coinbase-watchdog-env", watchdogNames],
  ]) {
    const lines = anchorLines(COMPOSE, anchor);
    for (const name of EQUITY_NAMES) {
      if (!names.includes(name)) continue;
      const line = lines.find((entry) => entry.startsWith(`${name}:`));
      assert.ok(line, `${anchor} has a ${name} line`);
      const wanted = `\${${name}:-${manifestDefault(name)}}`;
      assert.equal(line.includes(wanted), true, `${anchor}'s ${name} line reads ${wanted}: ${line}`);
    }
  }

  // No compose line carries an equity key or secret.
  for (const line of COMPOSE.split("\n")) {
    assert.doesNotMatch(line, /EQUITY.*(KEY|SECRET)/, `no equity key or secret in: ${line.trim()}`);
  }
});

/** The manifest default of one equity variable, as the compose file spells it. */
function manifestDefault(name) {
  const ev = envVar(name);
  assert.ok(ev, `${name} is declared, so its compose default is known`);
  return String(ev.default ?? "");
}

// ---- 3. the registry entry ---------------------------------------------------------------------

test("test_registry_entry_matches_manifest", () => {
  const registry = JSON.parse(readFileSync(join(REPO, "registry", "add-ons.json"), "utf8"));
  const entry = (registry["add-ons"] || []).find((candidate) => candidate && candidate.id === "coinbase");
  assert.ok(entry, "the registry has a coinbase entry");
  assert.equal(entry.version, MANIFEST.version, `the registry version matches the manifest (${MANIFEST.version})`);

  const names = (entry.env_vars || []).map((ev) => String((ev && ev.name) ?? ""));
  for (const name of EQUITY_NAMES) {
    assert.ok(names.includes(name), `the registry entry lists ${name}`);
  }

  // The registry is the manifest's own words for the equity settings, not a stale copy of them.
  for (const name of EQUITY_NAMES) {
    const listed = (entry.env_vars || []).find((ev) => ev && ev.name === name);
    assert.ok(listed, `the registry entry has a ${name} row`);
    assert.equal(
      String(listed.description ?? ""),
      String(envVar(name).description ?? ""),
      `the registry carries the manifest's own description of ${name}`,
    );
  }
});

// ---- 4. the MCP preview tool -------------------------------------------------------------------

const openedFakes = [];
const openedConnections = [];

async function openFake() {
  const fake = await createFakeEngine();
  openedFakes.push(fake);
  return fake;
}

/** One server over the harness fake engine, and the client that drives it. */
async function connectToFake(fake) {
  const client = createEngineClient({ baseUrl: fake.baseUrl, token: ENGINE_TOKEN, source: "mcp" });
  const server = createCoinbaseServer({ client, projectId: "p-test" });
  const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
  const sdk = new Client({ name: "coinbase-equities-test", version: "0.0.0" });
  await server.connect(serverSide);
  await sdk.connect(clientSide);
  openedConnections.push(async () => {
    await sdk.close();
    await server.close();
  });
  return sdk;
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

test("test_mcp_preview_mentions_stocks_and_passes_equity_block", async () => {
  const fake = await openFake();
  const sdk = await connectToFake(fake);

  const { tools } = await sdk.listTools();
  const previewTool = tools.find((candidate) => candidate.name === "crow_cb_order_preview");
  assert.ok(previewTool, "the preview tool is registered");
  const description = String(previewTool.description ?? "");
  assert.match(description, /stock/i, `the preview description mentions stocks: ${description}`);
  assert.match(description, /NVDA-USD/, `the preview description names a stock example: ${description}`);
  const productArg = (previewTool.inputSchema.properties || {}).product;
  assert.ok(productArg, "the preview tool has a product argument");
  assert.match(
    String(productArg.description ?? ""),
    /stock/i,
    `the product argument mentions stocks: ${productArg.description}`,
  );

  const HASH = "f0".repeat(32);
  const ENGINE_EQUITY = {
    session_open: false,
    pool_capital: "100",
    pool_used: "10",
    pool_left: "90",
    pool_left_after: "40",
    secret: "x",
  };
  const WHITELIST = ["session_open", "pool_capital", "pool_used", "pool_left", "pool_left_after"];
  const ARGS = { product: "NVDA-USD", side: "BUY", size: "0.5", limit_price: "180" };
  const stockPreview = (overrides = {}) =>
    fakePreview({
      preview_id: "pv-equity-1",
      product: "NVDA-USD",
      side: "BUY",
      size: "0.5",
      limit_price: "180",
      requested_limit_price: "180",
      notional: "90",
      limits: [
        { name: "equity_max_order_usd", limit: "100", used_after: "90" },
        { name: "ai_orders_per_hour", limit: "10", used_after: "1" },
      ],
      hash: HASH,
      ...overrides,
    });

  // (a) a stock proposal with an equity block: the five facts come back, nothing else does.
  fake.next("POST", "/ai/previews", { status: 200, body: stockPreview({ equity: ENGINE_EQUITY }) });
  const withEquity = await call(sdk, "crow_cb_order_preview", ARGS);
  assert.equal(withEquity.isError, false, `a stock preview is measured: ${withEquity.text}`);
  const answer = JSON.parse(withEquity.text);
  assert.deepEqual(
    answer.equity,
    { session_open: false, pool_capital: "100", pool_used: "10", pool_left: "90", pool_left_after: "40" },
    "the equity block carries the five facts, with the engine's own values",
  );
  assert.deepEqual(Object.keys(answer.equity).sort(), [...WHITELIST].sort(), "no other field rides along");
  assert.equal("secret" in answer.equity, false, "the engine's own extra field is dropped");
  assert.equal("hash" in answer, false, "the engine's hash is still never carried");
  assert.equal(withEquity.text.includes(HASH), false, "the engine's hash appears nowhere in the answer");

  // (b) a preview with no equity block has no equity key at all.
  fake.next("POST", "/ai/previews", { status: 200, body: fakePreview({ preview_id: "pv-crypto-1" }) });
  const plain = await call(sdk, "crow_cb_order_preview", ARGS);
  assert.equal(plain.isError, false, `a crypto preview is measured: ${plain.text}`);
  const plainAnswer = JSON.parse(plain.text);
  assert.equal("equity" in plainAnswer, false, "a preview without an equity block carries no equity key");

  // (c) anything that is not a plain object with a boolean session_open is dropped.
  const dropped = [
    ["a string", "stock-market-closed"],
    ["an array", ["session_open", false]],
    ["null", null],
    ["an object without session_open", { pool_left: "90", pool_left_after: "40" }],
    ["an object whose session_open is not a boolean", { session_open: "true", pool_left: "90" }],
  ];
  for (const [why, equity] of dropped) {
    fake.next("POST", "/ai/previews", { status: 200, body: stockPreview({ equity }) });
    const notEquity = await call(sdk, "crow_cb_order_preview", ARGS);
    assert.equal(notEquity.isError, false, `${why} is a measured preview: ${notEquity.text}`);
    assert.equal(
      "equity" in JSON.parse(notEquity.text),
      false,
      `${why} is not passed through as an equity block`,
    );
  }

  // (d) a money fact is kept only as the engine's own string: a true/false or a number is dropped,
  // never repaired, and the strings beside it keep the engine's own digits.
  const typed = { session_open: false, pool_capital: "100", pool_used: true, pool_left: 90, pool_left_after: "40" };
  fake.next("POST", "/ai/previews", { status: 200, body: stockPreview({ equity: typed }) });
  const mixedFacts = await call(sdk, "crow_cb_order_preview", ARGS);
  assert.equal(mixedFacts.isError, false, `a stock preview with mixed money facts is measured: ${mixedFacts.text}`);
  assert.deepEqual(
    JSON.parse(mixedFacts.text).equity,
    { session_open: false, pool_capital: "100", pool_left_after: "40" },
    "a money fact that is not the engine's own string is dropped, and the strings are kept as they came",
  );

  // A block whose money facts are all true/false still passes on the one fact it can state.
  fake.next("POST", "/ai/previews", {
    status: 200,
    body: stockPreview({ equity: { session_open: true, pool_left: false, pool_left_after: true } }),
  });
  const flagsOnly = await call(sdk, "crow_cb_order_preview", ARGS);
  assert.equal(flagsOnly.isError, false, `a stock preview with only flags is measured: ${flagsOnly.text}`);
  assert.deepEqual(
    JSON.parse(flagsOnly.text).equity,
    { session_open: true },
    "no money fact that is not a string rides along",
  );
});

// ---- 5. the approval card ----------------------------------------------------------------------

const NOW = 1_700_000_000;
const CARD_LIMITS = [{ name: "ai_max_order_usd", limit: "25", used_after: "60" }];
const TIME_LINE = "10 minutes left to approve it.";
// The card's lines as they stand today, built from the same row: practice, resting, the limit, time.
const EXISTING_LINES = [
  "Practice: no real money",
  "It rests on the order book and fills only at that price or better.",
  "Crow's limit on most for one AI order is 25. This order would bring today to 60.",
  TIME_LINE,
];
const CARD_EQUITY = {
  session_open: false,
  pool_capital: "100",
  pool_used: "10",
  pool_left: "90",
  pool_left_after: "40",
  secret: "x",
};

function cardRow(overrides = {}) {
  return {
    preview_id: "pv-card-1",
    state: "pending",
    book: "dry",
    product: "NVDA-USD",
    side: "BUY",
    size: "0.5",
    limit_price: "180",
    requested_limit_price: "180",
    notional: "90",
    limits: CARD_LIMITS,
    expires_at: NOW + 600,
    refusal: null,
    message: null,
    ...overrides,
  };
}

test("test_panel_card_shows_stock_session_and_pool", () => {
  // (a) a closed market: the two stock lines sit right before the time line.
  const closed = describePreview(cardRow({ equity: CARD_EQUITY }), { now: NOW });
  assert.equal(closed.lines.length, 6, `the card gains exactly two lines: ${closed.lines.join(" | ")}`);
  assert.deepEqual(closed.lines.slice(0, 3), EXISTING_LINES.slice(0, 3), "the existing lines are unchanged");
  assert.equal(closed.lines[closed.lines.length - 1], TIME_LINE, "the time line is still the last line");
  assert.equal(
    closed.lines[closed.lines.length - 3],
    MARKET_CLOSED,
    `the card says the stock market is closed: ${closed.lines[closed.lines.length - 3]}`,
  );
  assert.equal(
    closed.lines[closed.lines.length - 2],
    "Money left for stock trades: 90 (40 after this order).",
    `both amounts read on one line, in the engine's digits: ${closed.lines[closed.lines.length - 2]}`,
  );

  // (b) an open market says so instead.
  const open = describePreview(cardRow({ equity: { ...CARD_EQUITY, session_open: true } }), { now: NOW });
  assert.equal(open.lines[open.lines.length - 3], MARKET_OPEN, "the card says the stock market is open");
  assert.equal(open.lines.includes(MARKET_CLOSED), false, "an open market is never called closed");

  // (c) a preview with no equity block reads exactly as it does today.
  const bare = describePreview(cardRow(), { now: NOW });
  assert.deepEqual(bare.lines, EXISTING_LINES, "a preview without an equity block keeps its own lines");

  // (d) the three equity limits read in plain words, not as a variable name.
  const labels = {
    equity_max_order_usd: /most for one stock order/,
    equity_daily_notional_usd: /stock orders a day/,
    equity_ai_capital_usd: /money set aside for AI stock trades/,
  };
  const names = Object.keys(labels);
  const equityLimits = names.map((name) => ({ name, limit: "100", used_after: "50" }));
  const card = describePreview(cardRow({ limits: equityLimits }), { now: NOW });
  names.forEach((name, i) => {
    const line = String(card.lines[2 + i]);
    assert.match(line, labels[name], `${name} reads in plain words: ${line}`);
    assert.equal(line.includes(name.replace(/[_-]+/g, " ")), false, `${name} is not spelled out raw: ${line}`);
  });
});

/** The card's money line (or lines): a line about the money left for stock trades. */
function moneyLines(card) {
  return card.lines.filter((line) => String(line).startsWith("Money left for stock trades"));
}

test("test_panel_card_money_line_never_prints_an_empty_amount", () => {
  const cardFor = (equity) => describePreview(cardRow({ equity }), { now: NOW });
  const open = { session_open: true };

  // Both amounts: the one line the card has always shown, with the engine's own digits.
  const both = cardFor({ ...open, pool_left: "90", pool_left_after: "40" });
  assert.deepEqual(
    moneyLines(both),
    ["Money left for stock trades: 90 (40 after this order)."],
    `both amounts read as one line: ${moneyLines(both).join(" | ")}`,
  );

  // Only the money left before the order: the line stops after that amount.
  const onlyLeft = cardFor({ ...open, pool_left: "90" });
  assert.deepEqual(
    moneyLines(onlyLeft),
    ["Money left for stock trades: 90."],
    `the money left alone reads as its own line: ${moneyLines(onlyLeft).join(" | ")}`,
  );

  // Only the money left after the order: the line says so, and holds no empty pair of brackets.
  const onlyAfter = cardFor({ ...open, pool_left_after: "40" });
  assert.deepEqual(
    moneyLines(onlyAfter),
    ["Money left for stock trades after this order: 40."],
    `the money left after alone reads as its own line: ${moneyLines(onlyAfter).join(" | ")}`,
  );

  // An empty string is no amount at all, so it is left out rather than printed.
  const blankLeft = cardFor({ ...open, pool_left: "", pool_left_after: "40" });
  assert.deepEqual(
    moneyLines(blankLeft),
    ["Money left for stock trades after this order: 40."],
    `an empty amount is never printed: ${moneyLines(blankLeft).join(" | ")}`,
  );

  // Neither amount: no money line at all, and the market line stays where it was.
  const neither = cardFor({ ...open });
  assert.deepEqual(moneyLines(neither), [], "no money line is printed when neither amount is known");
  assert.equal(neither.lines.includes(MARKET_OPEN), true, "the market line stays on the card");
  assert.equal(neither.lines.length, 5, `the market line is the only stock line: ${neither.lines.join(" | ")}`);

  // The engine's digits are never rounded, on either line.
  const digits = cardFor({ ...open, pool_left: "90.25", pool_left_after: "1.2345" });
  assert.deepEqual(
    moneyLines(digits),
    ["Money left for stock trades: 90.25 (1.2345 after this order)."],
    `both amounts keep the engine's digits: ${moneyLines(digits).join(" | ")}`,
  );

  // No line the card builds ever shows an empty amount or a doubled space.
  for (const card of [both, onlyLeft, onlyAfter, blankLeft, neither, digits]) {
    for (const line of card.lines) {
      assert.equal(String(line).includes("()"), false, `no empty brackets on: ${line}`);
      assert.equal(String(line).includes("  "), false, `no doubled space on: ${line}`);
    }
  }
});

// ---- 6. the trading guide ----------------------------------------------------------------------

test("test_trading_guide_has_stocks_section", () => {
  const lines = GUIDE.split("\n");
  const proposals = lines.findIndex((line) => line.trim() === "## AI order proposals");
  const stocks = lines.findIndex((line) => line.trim() === "## Stocks (off by default)");
  const kill = lines.findIndex((line) => line.trim() === "## The kill switch");
  assert.ok(proposals >= 0, "the guide has the AI order proposals section");
  assert.ok(kill >= 0, "the guide has the kill switch section");
  assert.ok(stocks >= 0, "the guide has a Stocks (off by default) section");
  assert.ok(stocks > proposals, "the stocks section comes after the AI order proposals section");
  assert.ok(stocks < kill, "the stocks section comes before the kill switch section");

  const end = lines.findIndex((line, i) => i > stocks && /^## /.test(line));
  const body = lines.slice(stocks + 1, end === -1 ? lines.length : end).join("\n");
  assert.ok(body.trim().length > 0, "the stocks section has a body");
  assert.match(body, /off by default/i, `the section says stocks are off by default: ${body}`);
  assert.match(body, /limit order/i, `the section says a stock order is a limit order: ${body}`);
  assert.match(body, /regular market session/i, `the section names the regular market session: ${body}`);
  assert.match(body, /alert/i, `the section says Crow raises an alert: ${body}`);
  assert.match(body, /never stops trading/i, `the section says Crow never stops trading on a drop: ${body}`);

  // Live stock trading is not available yet, and the section says what it waits for.
  assert.match(
    body,
    /cannot be turned on yet/i,
    `the section says live stock trading cannot be turned on yet: ${body}`,
  );
  assert.match(body, /confirmed order preview/i, `the section names the confirmed order preview: ${body}`);
  assert.doesNotMatch(body, /recorded proposal/i, `the section promises no recorded proposal: ${body}`);

  // Stocks Crow cannot confirm turn themselves off, with an alert, and coins keep trading.
  assert.match(body, /turns stock trading off by itself/i, `the section says stock trading turns itself off: ${body}`);
  assert.match(body, /trading coins/i, `the section says coins keep trading: ${body}`);
  assert.match(body, /as usual/i, `the section says coins trade as usual: ${body}`);

  // A stock Crow no longer lists is sold by hand, in the Coinbase app.
  assert.match(body, /no longer lists/i, `the section covers a stock Crow no longer lists: ${body}`);
  assert.match(body, /by hand/i, `the section says such a stock is sold by hand: ${body}`);
  assert.match(body, /Coinbase app/i, `the section says where it is sold: ${body}`);

  // The rate line: a price about every 1.5 to 4 minutes, 90 seconds with one stock listed, 170
  // with two and 255 with three, more stocks a longer wait, and a pause of Crow's own once the
  // allowance is used up.
  const pricesSection = guideSection(GUIDE, "## Stock prices");
  assert.match(
    pricesSection,
    /1\.5 to 4 minutes/i,
    `the price line gives the wait: ${pricesSection}`,
  );
  assert.match(
    pricesSection,
    /90 seconds/i,
    `the price line gives the wait for one stock: ${pricesSection}`,
  );
  assert.match(
    pricesSection,
    /170 seconds/i,
    `the price line gives the wait for two stocks: ${pricesSection}`,
  );
  assert.match(
    pricesSection,
    /255 seconds/i,
    `the price line gives the wait for three stocks: ${pricesSection}`,
  );
  assert.match(
    pricesSection,
    /(per stock|for each stock)/i,
    `the wait is stated per stock: ${pricesSection}`,
  );
  assert.match(pricesSection, /more stocks/i, `the line says more stocks mean a longer wait: ${pricesSection}`);
  assert.match(
    pricesSection,
    /the longer the wait/i,
    `the line says more stocks mean a longer wait: ${pricesSection}`,
  );
  assert.match(
    pricesSection,
    /pauses on its own/i,
    `the line says the pause is Crow's own, not the owner's to trigger: ${pricesSection}`,
  );
  assert.match(pricesSection, /allowance/i, `the line names the allowance it pauses on: ${pricesSection}`);

  // The two stock-order ages: a practice order takes a price up to five minutes old, and a live
  // order (when live stock trading exists) will take one no older than two.
  assert.match(
    pricesSection,
    /5 minutes/i,
    `the line gives the practice price's age: ${pricesSection}`,
  );
  assert.match(
    pricesSection,
    /2 minutes/i,
    `the line gives the live price's age: ${pricesSection}`,
  );

  // The live-order line: the practice-only price is also what a live stock order will be checked
  // against once live stock trading exists.
  assert.match(
    pricesSection,
    /real orders always go to Coinbase/i,
    `the price line keeps the live-order promise: ${pricesSection}`,
  );
  assert.match(
    pricesSection,
    /live stock orders/i,
    `the line says live stock orders are checked too: ${pricesSection}`,
  );
  assert.match(
    pricesSection,
    /checked against (this|the) price/i,
    `the line says a live stock order is checked against this price: ${pricesSection}`,
  );

  // No URL was added by the stocks section, and the one address in the guide is Tiingo's own, in
  // the Stock prices part: nothing else, and no bare link anywhere.
  assert.doesNotMatch(body, /https?:\/\//i, "the stocks section carries no URL");
  const urls = (GUIDE.match(/https?:\/\/\S+/g) || []).map((url) => url.replace(/[).,;:'"]+$/, ""));
  assert.deepEqual(
    urls,
    ["https://www.tiingo.com/"],
    `the guide carries exactly the Tiingo address, in the Stock prices part: ${urls.join(", ")}`,
  );
  assert.doesNotMatch(
    GUIDE,
    /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/,
    "the guide carries no email address",
  );
});

after(async () => {
  for (const close of openedConnections.reverse()) {
    try {
      await close();
    } catch {
      // a connection already gone
    }
  }
  for (const fake of openedFakes) {
    try {
      await fake.close();
    } catch {
      // the fake is already gone
    }
  }
  cleanupScratch();
});