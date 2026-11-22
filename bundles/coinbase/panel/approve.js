/**
 * The Trading panel's AI order previews, in plain words: the sentence and the lines a person
 * reads on the card, and the two acts on that card — approve it once, or say "not now".
 *
 * Nothing here talks to a browser, a database or a file. `approvePreview` and `rejectPreview` take
 * the engine client the routes built, so the panel's own page can describe a preview with no
 * engine at all, and the approve route can refuse one without placing anything.
 *
 * Two rules shape the code:
 *
 * - An approval places exactly what the card said. The engine's listing is read again first, and
 *   an approval that names any other hash, a preview that is no longer waiting, or one whose
 *   window has closed is refused here, before the engine hears anything. Nothing is ever
 *   re-priced, and the engine is asked to approve the hash it listed — never something else.
 * - Money keeps the engine's digits. Every amount is the engine's own string, written out in full
 *   (an amount that arrived in exponent notation is expanded, never rounded), so what the card
 *   says is what the order carries.
 *
 * The copy the owner owes is fixed here, in one place, and no message ever carries a machine code,
 * a hash, a key or a secret.
 */

const MESSAGE_APPROVED = "Approved. Placing your order now.";
const MESSAGE_REJECTED = "Okay, not now.";
const MESSAGE_GONE = "That proposal is gone. Ask again.";
const MESSAGE_NOT_PENDING = "That proposal is no longer waiting for you.";
const MESSAGE_EXPIRED = "This proposal expired. Ask again.";
const MESSAGE_CHANGED = "This proposal changed. Look at it again before approving.";
const MESSAGE_ENGINE = "The trading engine could not complete that request";

const LIVE_LINE = "Live: real money";
const PRACTICE_LINE = "Practice: no real money";
const RESTING_LINE = "It rests on the order book and fills only at that price or better.";

const CODE_NOT_FOUND = "not_found";
const CODE_NOT_PENDING = "not_pending";
const CODE_EXPIRED = "expired";
const CODE_CHANGED = "changed";
const CODE_ENGINE_UNREACHABLE = "ENGINE_UNREACHABLE";

// A size the engine wrote as a whole number of coins reads with at least four places, so a tiny
// slice is never shown as "0".
const SIZE_MIN_DECIMALS = 4;

// What each limit the engine reports is called, in plain words. An unknown name is spelled out.
const LIMIT_LABELS = {
  ai_max_order_usd: "most for one AI order",
  ai_daily_notional_usd: "AI orders a day",
  ai_orders_per_hour: "AI orders an hour",
  ai_capital_usd: "money set aside for AI trades",
  daily_notional_usd: "how much can be traded a day",
  orders_per_hour: "orders an hour",
  portfolio_drawdown_pct: "how far the portfolio may fall before Crow stops trading",
  bot_max_order_usd: "most for one bot order",
  max_bot_capital_usd: "most one bot may hold",
};

// ---- small helpers ----------------------------------------------------------------------------

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function text(value) {
  if (value === undefined || value === null) return "";
  return String(value).trim();
}

function numberOrNull(value) {
  if (value === undefined || value === null) return null;
  const raw = typeof value === "number" ? value : Number(text(value));
  return Number.isFinite(raw) ? raw : null;
}

/**
 * The clock these functions date a preview against, in epoch seconds. The routes keep a
 * millisecond clock; a preview is born and expires in epoch seconds, so a millisecond value is
 * read as one. An unusable clock falls back to the wall clock.
 */
function nowSeconds(value) {
  const raw = value === undefined || value === null ? Date.now() : value;
  const number = typeof raw === "number" ? raw : Number(raw);
  if (!Number.isFinite(number)) return Math.floor(Date.now() / 1000);
  return Math.floor(number >= 1e11 ? number / 1000 : number);
}

/**
 * A number written out in plain decimal digits. An exponent form ("1.2e-7") becomes the full
 * written amount, so no card ever prints exponent notation. Anything else is kept exactly as the
 * engine wrote it: this is string handling, never floating-point rounding of money.
 */
function plainDecimal(value) {
  const raw = text(value);
  if (raw === "") return "";
  const match = /^([+-]?)(\d*)(?:\.(\d*))?[eE]([+-]?\d+)$/.exec(raw);
  if (!match) return raw;
  const sign = match[1] === "-" ? "-" : "";
  const whole = match[2] || "";
  const fraction = match[3] || "";
  const exponent = Number.parseInt(match[4], 10);
  if (!Number.isFinite(exponent)) return raw;
  const digits = whole + fraction;
  if (digits === "") return raw;
  const pointAt = whole.length + exponent;
  if (pointAt <= 0) return `${sign}0.${"0".repeat(-pointAt)}${digits}`;
  if (pointAt >= digits.length) return `${sign}${digits}${"0".repeat(pointAt - digits.length)}`;
  return `${sign}${digits.slice(0, pointAt)}.${digits.slice(pointAt)}`;
}

/** A size in the engine's own digits, never below four decimal places. */
function sizeText(value) {
  const raw = plainDecimal(value);
  if (raw === "") return "";
  const dot = raw.indexOf(".");
  if (dot === -1) return `${raw}.${"0".repeat(SIZE_MIN_DECIMALS)}`;
  let decimals = raw.slice(dot + 1);
  // Trailing zeros beyond the fourth place carry no information; the digits that do stay.
  while (decimals.length > SIZE_MIN_DECIMALS && decimals.endsWith("0")) {
    decimals = decimals.slice(0, -1);
  }
  while (decimals.length < SIZE_MIN_DECIMALS) decimals += "0";
  return `${raw.slice(0, dot)}.${decimals}`;
}

/** The currency a product is priced in ("BTC-USDC" -> "USDC"), or "" when the name has none. */
function quoteCurrency(product) {
  const raw = text(product);
  const dash = raw.lastIndexOf("-");
  if (dash <= 0 || dash === raw.length - 1) return "";
  const quote = raw.slice(dash + 1);
  return /^[A-Z0-9]{2,10}$/.test(quote) ? quote : "";
}

/** "buy" / "sell" / whatever the engine said, as the opening word of the sentence. */
function sideText(side) {
  const raw = text(side);
  if (raw === "") return "Order";
  const lower = raw.toLowerCase();
  if (lower === "buy" || lower === "sell") return lower.charAt(0).toUpperCase() + lower.slice(1);
  return raw;
}

/** "Practice" / "Live", the word the lines use for the book. */
function bookWord(book) {
  return text(book).toLowerCase() === "live" ? "Live" : "Practice";
}

function limitLabel(name) {
  const raw = text(name);
  if (raw === "") return "this order";
  if (Object.hasOwn(LIMIT_LABELS, raw)) return LIMIT_LABELS[raw];
  return raw.replace(/[_-]+/g, " ");
}

function limitLine(entry) {
  const row = isPlainObject(entry) ? entry : {};
  const label = limitLabel(row.name);
  const limit = plainDecimal(row.limit);
  const usedAfter = plainDecimal(row.used_after);
  if (limit && usedAfter) {
    return `Crow's limit on ${label} is ${limit}. This order would bring today to ${usedAfter}.`;
  }
  if (limit) return `Crow's limit on ${label} is ${limit}.`;
  return `A limit applies to ${label}.`;
}

function timeLine(secondsLeft) {
  if (secondsLeft === null) return "No time limit is set on this proposal.";
  if (secondsLeft <= 0) return "This proposal has expired.";
  if (secondsLeft < 60) return "Less than a minute is left to approve it.";
  const minutes = Math.floor(secondsLeft / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} left to approve it.`;
  const hours = Math.round(minutes / 60);
  return `${hours} hour${hours === 1 ? "" : "s"} left to approve it.`;
}

/** The plain sentence: what would be placed, at what price, for about how much. */
function summaryOf(row) {
  const product = text(row.product);
  const size = sizeText(row.size);
  const limit = plainDecimal(row.limit_price);
  const notional = plainDecimal(row.notional);
  const quote = quoteCurrency(product);

  const parts = [sideText(row.side)];
  if (size) parts.push(size);
  if (product) parts.push(product);
  if (limit) {
    parts.push(`with a limit order at ${limit}${quote ? ` ${quote}` : ""}`);
  } else {
    parts.push("at the market");
  }
  if (notional) parts.push(`(about ${notional}${quote ? ` ${quote}` : ""} in total)`);
  return parts.join(" ");
}

// ---- the card ---------------------------------------------------------------------------------

/**
 * One preview as the owner reads it.
 *
 * @param {object} preview a row from the engine's `GET /ai/previews`, untouched
 * @param {{now?: number}} [options] `now` in epoch seconds (a millisecond value is read as one)
 * @returns {{summary: string, lines: string[], badge: "LIVE"|"PRACTICE", seconds_left: number,
 *   expired: boolean}}
 */
export function describePreview(preview, options = {}) {
  const row = isPlainObject(preview) ? preview : {};
  const now = nowSeconds(options && options.now);
  const expiresAt = numberOrNull(row.expires_at);
  // A preview with no window at all is not expired by a missing field; only a closed window is.
  const expired = expiresAt !== null && expiresAt <= now;
  const seconds = expiresAt === null ? null : Math.max(0, Math.floor(expiresAt - now));

  const live = bookWord(row.book) === "Live";
  const limits = Array.isArray(row.limits) ? row.limits : [];
  const lines = [
    live ? LIVE_LINE : PRACTICE_LINE,
    RESTING_LINE,
    ...limits.map((entry) => limitLine(entry)),
    timeLine(seconds),
  ];

  return {
    summary: summaryOf(row),
    lines,
    badge: live ? "LIVE" : "PRACTICE",
    seconds_left: seconds === null ? 0 : seconds,
    expired,
  };
}

// ---- the two acts -----------------------------------------------------------------------------

/** The engine's own refusal, in its own words: status, code and message pass through together. */
function engineRefusal(result) {
  const row = isPlainObject(result) ? result : {};
  const status = Number.isFinite(row.status) && row.status > 0 ? row.status : 502;
  const code = typeof row.code === "string" && row.code ? row.code : CODE_ENGINE_UNREACHABLE;
  const message = typeof row.message === "string" && row.message ? row.message : MESSAGE_ENGINE;
  return { ok: false, status, code, message };
}

function refusal(status, code, message) {
  return { ok: false, status, code, message };
}

function listedRows(result) {
  if (!isPlainObject(result) || result.ok !== true) return null;
  const data = result.data;
  if (Array.isArray(data)) return data;
  if (isPlainObject(data) && Array.isArray(data.previews)) return data.previews;
  return [];
}

/**
 * Approve exactly what the card showed, once.
 *
 * The engine's listing is read again (never a cached copy) and the preview is checked against it:
 * an id nobody holds, a proposal that is no longer waiting, a window that has closed and a hash
 * that is not the listed one are all refused here, and the engine places nothing. Only the listed
 * hash is ever sent.
 *
 * @param {{client: object, previewId: string, hash: string, now?: number}} options
 * @returns {Promise<{ok: true, message: string, preview: object} |
 *   {ok: false, status: number, code: string, message: string}>}
 */
export async function approvePreview(options = {}) {
  const config = options || {};
  const client = config.client;
  const previewId = text(config.previewId);
  const hash = text(config.hash);
  const now = nowSeconds(config.now);

  if (!client || typeof client.aiPreviews !== "function") {
    return refusal(502, CODE_ENGINE_UNREACHABLE, MESSAGE_ENGINE);
  }

  let listing;
  try {
    listing = await client.aiPreviews();
  } catch {
    return refusal(502, CODE_ENGINE_UNREACHABLE, MESSAGE_ENGINE);
  }
  const rows = listedRows(listing);
  if (rows === null) return engineRefusal(listing);

  const preview = rows.find(
    (row) => isPlainObject(row) && text(row.preview_id) === previewId,
  );
  if (!preview) return refusal(404, CODE_NOT_FOUND, MESSAGE_GONE);
  if (text(preview.state) !== "pending") return refusal(409, CODE_NOT_PENDING, MESSAGE_NOT_PENDING);

  const expiresAt = numberOrNull(preview.expires_at);
  if (expiresAt !== null && expiresAt <= now) return refusal(409, CODE_EXPIRED, MESSAGE_EXPIRED);

  const listedHash = text(preview.hash);
  if (!listedHash || hash !== listedHash) return refusal(409, CODE_CHANGED, MESSAGE_CHANGED);

  if (typeof client.approve !== "function") {
    return refusal(502, CODE_ENGINE_UNREACHABLE, MESSAGE_ENGINE);
  }
  let result;
  try {
    result = await client.approve(previewId, listedHash);
  } catch {
    return refusal(502, CODE_ENGINE_UNREACHABLE, MESSAGE_ENGINE);
  }
  if (!isPlainObject(result) || result.ok !== true) return engineRefusal(result);

  const data = isPlainObject(result.data) ? result.data : {};
  const card = describePreview(preview, { now });
  return {
    ok: true,
    message: MESSAGE_APPROVED,
    preview: {
      ...card,
      preview_id: previewId,
      hash: listedHash,
      book: text(data.book) || text(preview.book) || "dry",
      state: text(data.state) || "placed",
    },
  };
}

/**
 * "Not now": one call to the engine, one plain answer. Nothing is placed and nothing is described.
 *
 * @param {{client: object, previewId: string}} options
 * @returns {Promise<{ok: true, message: string} |
 *   {ok: false, status: number, code: string, message: string}>}
 */
export async function rejectPreview(options = {}) {
  const config = options || {};
  const client = config.client;
  const previewId = text(config.previewId);

  if (!client || typeof client.aiReject !== "function") {
    return refusal(502, CODE_ENGINE_UNREACHABLE, MESSAGE_ENGINE);
  }
  let result;
  try {
    result = await client.aiReject(previewId);
  } catch {
    return refusal(502, CODE_ENGINE_UNREACHABLE, MESSAGE_ENGINE);
  }
  if (!isPlainObject(result) || result.ok !== true) return engineRefusal(result);
  return { ok: true, message: MESSAGE_REJECTED };
}