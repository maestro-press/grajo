/**
 * The Coinbase bundle's MCP server: the thin tool layer the AI reaches the trading
 * engine through.
 *
 * Every tool is one call on the engine client, and every answer is either one small
 * plain object or one plain sentence. The engine is what enforces the limits, the
 * owner's approval and the live-book rules; nothing here re-implements them, and
 * nothing here can approve, switch a book on, change a limit or move money.
 *
 * The engine has no bot-update route, so `crow_cb_bot_update` is NOT registered: this
 * server never ships a tool that can only fail. Every other route the engine serves is
 * reached by one of the fourteen tools below.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const VERSION = "1.0.0";
const APPROVAL_ROUTE = "/dashboard/coinbase";

// The sentences a refusal earns. One sentence each, no engine codes and no stack.
const UNREACHABLE_SENTENCE = "The trading engine is not responding. Try again in a minute.";
const OWNER_SENTENCE =
  "Live bots can only be paused or stopped from here. Use the Trading panel for anything else.";
const NOT_CONNECTED_SENTENCE = "Trading is not connected.";
const UNEXPECTED_SENTENCE = "Something went wrong reading the trading engine.";
const UNSTATED_SENTENCE = "The trading engine could not complete that request.";
// The one sentence the price read earns when the engine has no price to quote right
// now: a 503 from GET /price is a cache with no usable snapshot, not a server fault.
const NO_PRICE_SENTENCE = "No price is available for that product right now.";
const WAITING_SENTENCE = "Waiting for your approval in the Crow dashboard.";
const PREVIEW_LIMIT_SENTENCE =
  "Too many proposals are waiting for the owner's answer or were asked for this hour.";
const BOT_LIMIT_SENTENCE =
  "There are too many bots running or created this hour. Stop one you no longer need, or try again later.";
// A pause that cancelled everything, and one that could not: the bot is paused either way.
const PAUSE_MESSAGE = "The bot is paused and its waiting orders were cancelled.";
const PAUSE_INCOMPLETE_SENTENCE =
  "The bot is paused, but some of its waiting orders may still be on Coinbase. Call pause again, " +
  "or cancel them in the Coinbase app: Crow portfolio \u2192 Open orders.";
// Pause called again moments after the last one: the engine's debounce, in one plain sentence.
const PAUSE_TOO_SOON_SENTENCE =
  "That bot was only just asked to pause. Wait a few seconds and call pause again.";
// The two races a pause can lose: another pause still running, and the bot changing mid-sweep.
const PAUSE_IN_PROGRESS_SENTENCE = "That bot is being paused. Wait a few seconds and try again.";
const PAUSE_CHANGED_SENTENCE =
  "That bot changed while it was being paused. Check it, and call pause again if it still needs it.";
// The one sentence both order tools carry about who approves a proposal.
const APPROVER_SENTENCE = "Only the owner can approve it, in the Crow dashboard; this tool cannot.";

const DEFAULT_FILLS_LIMIT = 20;
const MAX_FILLS_LIMIT = 100;
const DEFAULT_RETRY_AFTER_S = 60;

/** One text block holding a small plain object. */
function answer(data) {
  return { content: [{ type: "text", text: JSON.stringify(data, null, 2) }] };
}

/** One text block holding a single plain sentence, marked as an error. */
function sentence(text) {
  return { content: [{ type: "text", text }], isError: true };
}

/** A sentence always ends with a full stop, so the answer reads as one sentence. */
function asSentence(text) {
  const trimmed = String(text ?? "").trim();
  if (trimmed === "") return UNSTATED_SENTENCE;
  return /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}

/**
 * The one plain sentence a failed engine call earns.
 *
 * The engine client answers `{ok:false, code, status, message}` and never throws,
 * so the mapping lives here and nowhere else in the tool layer.
 */
function refusalSentence(result) {
  const failed = result && typeof result === "object" ? result : {};
  const code = typeof failed.code === "string" ? failed.code : "";
  const status = Number.isFinite(failed.status) ? failed.status : 0;
  // Nothing was reached at all (status 0), so this is the engine being away, not its answer.
  if (code === "ENGINE_UNREACHABLE") return UNREACHABLE_SENTENCE;
  // A pause that could not cancel every waiting order is stated in its own words before the
  // server-error branch below: the bot IS paused, and saying only "could not complete" would
  // hide the orders that may still rest on the exchange.
  if (code === "PAUSE_INCOMPLETE") return PAUSE_INCOMPLETE_SENTENCE;
  // The pause debounce has its own sentence, and it is answered before the generic
  // rate-limit branch below: no countdown, and nothing of the engine's own words.
  if (code === "PAUSE_TOO_SOON") return PAUSE_TOO_SOON_SENTENCE;
  // A pause that raced another pause, and one that raced a change, each get their own
  // sentence before the generic branches: the engine's detail says nothing the AI needs.
  if (code === "PAUSE_IN_PROGRESS") return PAUSE_IN_PROGRESS_SENTENCE;
  if (code === "PAUSE_CHANGED") return PAUSE_CHANGED_SENTENCE;
  // The engine's own fault, or the exchange's, is never repeated in its own words: a server
  // error can carry anything, and the tool layer says only that it could not be done.
  if (status >= 500) return UNSTATED_SENTENCE;
  if (code === "LIVE_NEEDS_OWNER" || code === "APPROVAL_INVALID" || code === "NOT_ALLOWED") {
    return OWNER_SENTENCE;
  }
  if (code === "ENGINE_AUTH" || code === "NOT_CONNECTED") return NOT_CONNECTED_SENTENCE;
  // The two 429s with a sentence of their own say it without a countdown, so they are
  // answered before the generic rate-limit branch below.
  if (code === "PREVIEW_LIMIT") return PREVIEW_LIMIT_SENTENCE;
  if (code === "BOT_LIMIT") return BOT_LIMIT_SENTENCE;
  if (code === "RATE_LIMITED" || status === 429) {
    const wait = Number.isFinite(failed.retryAfterS) ? failed.retryAfterS : DEFAULT_RETRY_AFTER_S;
    return `Too many requests. Try again in ${wait} seconds.`;
  }
  // Anything else is the engine's own message, which the client has already redacted.
  return asSentence(failed.message);
}

/** The answer for one failed engine call. */
function refusal(result) {
  return sentence(refusalSentence(result));
}

/** Wrap a handler so an unexpected throw never leaks its words or its stack. */
function guarded(handler) {
  return async (args) => {
    try {
      return await handler(args && typeof args === "object" ? args : {});
    } catch {
      return sentence(UNEXPECTED_SENTENCE);
    }
  };
}

/** The approval link for one proposal, in the Crow dashboard. */
function approvalLink(previewId) {
  return `${APPROVAL_ROUTE}?preview=${encodeURIComponent(String(previewId))}`;
}

// The five stock facts a proposal may carry, in the engine's own order: whether the
// stock market is open, then the money set aside for AI stock trades, what of it is
// used, what is left, and what would be left after this order. Nothing else rides along.
const EQUITY_FLAG = "session_open";
const EQUITY_MONEY = ["pool_capital", "pool_used", "pool_left", "pool_left_after"];

/**
 * The engine's stock block, or null when there is nothing a reader can trust.
 *
 * It is passed on only when it is a plain object with a real true/false answer for
 * whether the stock market is open; the money facts are kept only as the engine's own
 * strings, so a true/false or a number there is dropped, never repaired. An extra field,
 * a string "true" or a list is dropped whole.
 */
function equityBlock(equity) {
  if (!equity || typeof equity !== "object" || Array.isArray(equity)) return null;
  if (typeof equity[EQUITY_FLAG] !== "boolean") return null;
  const out = { [EQUITY_FLAG]: equity[EQUITY_FLAG] };
  for (const name of EQUITY_MONEY) {
    const value = equity[name];
    if (typeof value === "string") out[name] = value;
  }
  return out;
}

/**
 * The small plain object one proposal is reported as.
 *
 * The engine's own `hash` is deliberately left out: it is the approval MAC's
 * material, and this layer never carries it.
 */
function previewSummary(preview) {
  const row = preview && typeof preview === "object" ? preview : {};
  const out = {
    preview_id: row.preview_id ?? null,
    state: row.state ?? null,
    product: row.product ?? null,
    side: row.side ?? null,
    size: row.size ?? null,
    limit_price: row.limit_price ?? null,
    notional: row.notional ?? null,
    limits: Array.isArray(row.limits) ? row.limits : [],
    expires_at: row.expires_at ?? null,
  };
  if (row.refusal !== undefined && row.refusal !== null) out.refusal = row.refusal;
  if (typeof row.message === "string" && row.message) out.message_from_engine = row.message;
  // A proposal about a stock carries the engine's stock facts; one about a coin carries
  // no such key at all, so an answer for a coin reads exactly as it did before.
  const equity = equityBlock(row.equity);
  if (equity) out.equity = equity;
  return out;
}

/** What a proposal's state means, in plain words. */
function stateWords(state) {
  const text = typeof state === "string" ? state : "";
  if (text === "placed") return "already placed";
  if (text === "expired") return "expired";
  if (text === "rejected") return "rejected";
  if (text === "cancelled" || text === "canceled") return "cancelled";
  return text === "" ? "no longer open" : `in the state "${text}"`;
}

/** The rows of a list-shaped engine answer, or an empty list. */
function rowsOf(data) {
  return Array.isArray(data) ? data : [];
}

/** One proposal from a list-shaped answer, by its id. */
function proposalById(data, previewId) {
  const rows = Array.isArray(data) ? data : Array.isArray(data && data.previews) ? data.previews : [];
  return rows.find((row) => row && typeof row === "object" && row.preview_id === previewId) || null;
}

/**
 * The bundle's MCP server: fourteen tools over one engine client.
 *
 * `projectId` is accepted for the bundle's own bookkeeping; the audit trail is the
 * engine's business, so nothing here reads it.
 */
export function createCoinbaseServer({ client, projectId } = {}) {
  void projectId;
  const server = new McpServer({ name: "crow-coinbase", version: VERSION });

  // ---- reads ------------------------------------------------------------------

  server.tool(
    "crow_cb_balances",
    "The balances the trading engine reports for each book.",
    {},
    guarded(async () => {
      const result = await client.balances();
      if (!result || result.ok !== true) return refusal(result);
      return answer({ balances: result.data ?? null });
    }),
  );

  server.tool(
    "crow_cb_bots",
    "Every trading bot on this engine: its product, strategy, status and book.",
    {},
    guarded(async () => {
      const result = await client.bots();
      if (!result || result.ok !== true) return refusal(result);
      return answer({ bots: rowsOf(result.data) });
    }),
  );

  server.tool(
    "crow_cb_bot_status",
    "One bot's own row, together with its profit-and-loss entry.",
    { bot_id: z.string().min(1).describe("The bot's id") },
    guarded(async ({ bot_id }) => {
      const listed = await client.bots();
      if (!listed || listed.ok !== true) return refusal(listed);
      const found = rowsOf(listed.data).find((bot) => bot && bot.id === bot_id) || null;
      if (!found) return sentence("No bot with that id.");

      const pnl = await client.pnl();
      if (!pnl || pnl.ok !== true) return refusal(pnl);
      const byBot = pnl.data && typeof pnl.data === "object" ? pnl.data.bots : null;
      const entry = byBot && typeof byBot === "object" ? byBot[bot_id] ?? null : null;

      return answer({ ...found, pnl: entry });
    }),
  );

  server.tool(
    "crow_cb_fills",
    "The most recent fills of one bot, newest last.",
    {
      bot_id: z.string().min(1).describe("The bot's id"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(MAX_FILLS_LIMIT)
        .optional()
        .default(DEFAULT_FILLS_LIMIT)
        .describe(`How many of the newest fills to return (default ${DEFAULT_FILLS_LIMIT})`),
    },
    guarded(async ({ bot_id, limit }) => {
      const wanted = Number.isFinite(limit)
        ? Math.min(Math.max(Math.trunc(limit), 1), MAX_FILLS_LIMIT)
        : DEFAULT_FILLS_LIMIT;
      const result = await client.botFills(bot_id);
      if (!result || result.ok !== true) return refusal(result);
      const all = rowsOf(result.data);
      const fills = all.slice(Math.max(0, all.length - wanted));
      return answer({ bot_id, count: fills.length, fills });
    }),
  );

  server.tool(
    "crow_cb_pnl",
    "Profit and loss per bot, as the engine reports it.",
    {},
    guarded(async () => {
      const result = await client.pnl();
      if (!result || result.ok !== true) return refusal(result);
      return answer({ pnl: result.data ?? null });
    }),
  );

  server.tool(
    "crow_cb_price",
    "The engine's current price for one trading pair, from its own market data.",
    { product: z.string().min(1).describe("The trading pair, for example BTC-USDC") },
    guarded(async ({ product }) => {
      const result = await client.getPrice(product);
      if (!result || result.ok !== true) {
        // Only this read turns a 503 into its own sentence: the engine answered that it
        // holds no usable price for the pair, which is not the failure a 500 earns. Every
        // other failed status, and a 503 on any other tool, keeps the usual refusal.
        if (result && result.status === 503) return sentence(NO_PRICE_SENTENCE);
        return refusal(result);
      }
      const data = result.data && typeof result.data === "object" ? result.data : {};
      // Exactly the engine's three fields: the pair, its price as the decimal string the
      // engine sent, and the stamp of the snapshot that price came from.
      return answer({
        product: data.product ?? null,
        price: data.price ?? null,
        ts: data.ts ?? null,
      });
    }),
  );

  // ---- control ----------------------------------------------------------------

  server.tool(
    "crow_cb_bot_pause",
    "Pauses one bot and cancels its waiting orders on Coinbase. A paused bot places no new orders " +
      "until it is resumed; use stop instead when the bot is finished for good.",
    { bot_id: z.string().min(1).describe("The bot's id") },
    guarded(async ({ bot_id }) => {
      const result = await client.botPause(bot_id);
      if (!result || result.ok !== true) return refusal(result);
      return answer({ bot: result.data ?? null, message: PAUSE_MESSAGE });
    }),
  );

  server.tool(
    "crow_cb_bot_resume",
    "Resumes one bot. Resuming re-bases the bot's high-water mark, so its range starts from here. A live bot cannot be resumed from here.",
    {
      bot_id: z.string().min(1).describe("The bot's id"),
      acknowledge_rebase: z
        .literal(true)
        .describe("Agrees that resuming re-bases the bot's high-water mark"),
    },
    guarded(async ({ bot_id, acknowledge_rebase }) => {
      const result = await client.botResume(bot_id, { acknowledge_rebase: acknowledge_rebase === true });
      if (!result || result.ok !== true) return refusal(result);
      return answer({ bot: result.data ?? null, message: "The bot is running again." });
    }),
  );

  server.tool(
    "crow_cb_bot_stop",
    "Stops one bot. Use pause instead when the bot may continue later.",
    { bot_id: z.string().min(1).describe("The bot's id") },
    guarded(async ({ bot_id }) => {
      const result = await client.botStop(bot_id);
      if (!result || result.ok !== true) return refusal(result);
      return answer({ bot: result.data ?? null, message: "The bot is stopped." });
    }),
  );

  server.tool(
    "crow_cb_bot_recenter",
    "Re-centers one bot's range on a given price. A live bot cannot be recentered from here.",
    {
      bot_id: z.string().min(1).describe("The bot's id"),
      center: z
        .union([z.string().min(1), z.number()])
        .describe("The price to center the bot's range on"),
    },
    guarded(async ({ bot_id, center }) => {
      const price = Number(center);
      if (!Number.isFinite(price) || price <= 0) {
        return sentence("The center price must be a positive number.");
      }
      const result = await client.botRecenter(bot_id, { center: String(center) });
      if (!result || result.ok !== true) return refusal(result);
      return answer({ bot: result.data ?? null, message: "The bot's range is centered on that price." });
    }),
  );

  server.tool(
    "crow_cb_bot_create",
    "Creates one bot from these six fields. New bots always start in practice: nothing is placed with real money.",
    {
      id: z.string().min(1).describe("The id for the new bot"),
      product: z.string().min(1).describe("The trading pair, for example BTC-USDC"),
      strategy: z
        .enum(["grid", "rebalance"])
        .describe(
          "The bot's strategy: grid places levels below and sells above a center, " +
            "rebalance holds a target share of the coin",
        ),
      params: z
        .object({
          target_base_pct: z
            .union([z.string().min(1), z.number()])
            .optional()
            .describe(
              "rebalance: the share of the holding to keep in the coin, as a percentage above 0 and below 100",
            ),
          band_pts: z
            .union([z.string().min(1), z.number()])
            .optional()
            .describe(
              "rebalance: how far the weight may drift from that target before it trades, in percentage points",
            ),
          min_trade_quote: z
            .union([z.string().min(1), z.number()])
            .optional()
            .describe("rebalance: the smallest trade worth placing, in quote (cash)"),
          reprice_after_s: z
            .union([z.string().min(1), z.number()])
            .optional()
            .describe(
              "rebalance: how long an unfilled order rests before it is replaced, in seconds",
            ),
          center: z
            .union([z.string().min(1), z.number()])
            .optional()
            .describe("grid: the price the levels are built around"),
          step_pct: z
            .union([z.string().min(1), z.number()])
            .optional()
            .describe("grid: the gap between two levels, in percent"),
          levels_below: z
            .union([z.string().min(1), z.number()])
            .optional()
            .describe("grid: how many levels to place below the center, a whole number of at least 1"),
          levels_above: z
            .union([z.string().min(1), z.number()])
            .optional()
            .describe("grid: how many levels to place above the center, a whole number of at least 1"),
          quote_per_buy: z
            .union([z.string().min(1), z.number()])
            .optional()
            .describe("grid: the quote (cash) each buy spends"),
          rebuy_sizing: z
            .enum(["proceeds", "fixed"])
            .optional()
            .describe(
              "grid: what a buy after a sell spends, the sell's own proceeds or the fixed quote per buy",
            ),
        })
        .strict()
        .describe(
          "The strategy's own settings: send only the fields the chosen strategy reads, and no others",
        ),
      capital_quote: z.string().min(1).describe("Starting quote (cash) capital"),
      capital_base: z.string().min(1).describe("Starting base (coin) capital"),
    },
    guarded(async ({ id, product, strategy, params, capital_quote, capital_base }) => {
      // Exactly the six fields go out: a new bot has no mode to send, so it can only
      // be a practice bot.
      const body = { id, product, strategy, params, capital_quote, capital_base };
      const result = await client.createBot(body);
      if (!result || result.ok !== true) return refusal(result);
      return answer({ bot: result.data ?? null, message: "The bot is created and starts in practice." });
    }),
  );

  // ---- trading ----------------------------------------------------------------

  server.tool(
    "crow_cb_order_preview",
    "Measures one order against the engine's limits and returns a proposal; nothing is placed. " +
      "A stock such as NVDA-USD may be proposed when stocks are enabled; a stock order only " +
      "goes out in the regular market session, and its proposal shows the stock limits and the " +
      `money left for stocks. ${APPROVER_SENTENCE}`,
    {
      product: z
        .string()
        .min(1)
        .describe(
          "The trading pair, for example BTC-USDC, or a stock such as NVDA-USD when stocks are " +
            "enabled. A stock order only goes out in the regular market session",
        ),
      side: z.enum(["BUY", "SELL"]).describe("Which way the order goes"),
      size: z.string().min(1).describe("The order size, as the engine takes it"),
      limit_price: z.string().min(1).describe("The limit price for the order"),
    },
    guarded(async ({ product, side, size, limit_price }) => {
      const result = await client.aiPreview({ product, side, size, limit_price });
      if (!result || result.ok !== true) return refusal(result);
      const summary = previewSummary(result.data);
      const out = {
        ...summary,
        message: "The order was measured against the limits. Nothing is placed until you approve it in the Crow dashboard.",
      };
      if (typeof summary.preview_id === "string" && summary.preview_id) {
        out.approval_link = approvalLink(summary.preview_id);
      }
      return answer(out);
    }),
  );

  server.tool(
    "crow_cb_order_place",
    "Reports one order proposal's current state and its approval link. " +
      "A stock such as NVDA-USD may be proposed when stocks are enabled; a stock order only " +
      "goes out in the regular market session, and its proposal shows the stock limits and the " +
      `money left for stocks. ${APPROVER_SENTENCE}`,
    { preview_id: z.string().min(1).describe("The proposal's id, from a preview") },
    guarded(async ({ preview_id }) => {
      const listed = await client.aiPreviews();
      if (!listed || listed.ok !== true) return refusal(listed);
      const found = proposalById(listed.data, preview_id);
      if (!found) return sentence("No order proposal with that id.");

      const out = previewSummary(found);
      if (out.state === "pending") {
        out.approval_link = approvalLink(preview_id);
        out.message = WAITING_SENTENCE;
        return answer(out);
      }
      out.message = `This order proposal is ${stateWords(out.state)}.`;
      return answer(out);
    }),
  );

  server.tool(
    "crow_cb_order_cancel",
    "Cancels an order the AI placed. An order placed any other way is refused by the engine.",
    {
      client_order_id: z
        .string()
        .min(1)
        .describe("The client order id of the order the AI placed"),
    },
    guarded(async ({ client_order_id }) => {
      const result = await client.aiCancel(client_order_id);
      if (!result || result.ok !== true) return refusal(result);
      const data = result.data && typeof result.data === "object" ? result.data : {};
      // The engine answers a cancel with its own `cid` and `cancelled` pair; those two
      // fields are the whole answer, so nothing else is reported back.
      return answer({
        client_order_id: data.cid ?? client_order_id,
        cancelled: data.cancelled === true,
      });
    }),
  );

  return server;
}