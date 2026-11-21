/**
 * A model-supplied regex filter, run against page-controlled link text and hrefs.
 *
 * `new RegExp(filter, "i")` on a page's own words hands the pattern's input to the
 * page: `(a+)+$` against a 2000-character anchor label wedges the event loop. The
 * match therefore runs inside `node:vm`, with one total timeout for the whole pass,
 * so a pathological pattern is cut off instead of blocking the server.
 */
import vm from "node:vm";

export const MAX_PATTERN_LEN = 200;
export const MAX_TEST_LEN = 2000;
export const MAX_URL_FILTER_LEN = 500;
export const FILTER_TIMEOUT_MS = 250;

const ERROR_TOO_LONG = `filter pattern is too long (max ${MAX_PATTERN_LEN} characters); use a shorter pattern`;
const ERROR_TOO_SLOW = "filter pattern took too long; use a simpler pattern";
const ERROR_INVALID = "filter pattern is not a valid regular expression; fix or simplify it";
const ERROR_URL_FILTER_TOO_LONG = `filter_url_pattern is too long (max ${MAX_URL_FILTER_LEN} characters); give a shorter list of parts`;

/**
 * The matching script, compiled once and run in a fresh context per call. It sees only
 * the globals `pattern`, `texts` and `hrefs` (plain data) and returns the indexes that
 * matched, so nothing from this process is reachable from inside it. No `g` flag, so no
 * `lastIndex` state carries between links.
 */
const MATCH_SCRIPT = new vm.Script(`
  (() => {
    const re = new RegExp(pattern, "i");
    const hits = [];
    for (let i = 0; i < texts.length; i += 1) {
      if (re.test(texts[i]) || re.test(hrefs[i])) hits.push(i);
    }
    return hits;
  })()
`);

const ERROR_PLAIN_TEXT = "filter_url_pattern is plain text now, not a regex: give part of the URL, or several parts separated by |";

/** Two-character sequences and single characters that only make sense as regex syntax. */
const REGEX_TOKENS = [".*", ".+", "[", "]", "(", ")", "{", "}"];

/**
 * Parse a model-supplied capture filter into plain case-sensitive alternatives.
 *
 * The filter matches against URLs the page chooses, so a regex would let the page feed
 * a pathological string to a pattern the model supplied. Refusing regex syntax outright
 * keeps that surface closed without a sandbox: the answer is simpler input, not a slow
 * match. `.` `?` `&` `=` `/` `+` and `*` stay allowed on their own (they are ordinary URL
 * characters); only `.*`, `.+` and the bracket/brace/paren forms are refused.
 *
 * Anchors are refused per alternative, not per string: `x$|y` and `a|^b` are refused
 * because a part still reads as anchor syntax, while a `^` or `$` in the middle of a part
 * (`a$b`, `a^b`) is ordinary text.
 *
 * Returns `{ ok: true, parts }` (empty array means "no filter") or `{ ok: false, error }`.
 */
export function parseUrlFilter(value) {
  if (value === undefined || value === null || value === "") return { ok: true, parts: [] };
  const raw = String(value);

  if (raw.length > MAX_URL_FILTER_LEN) return { ok: false, error: ERROR_URL_FILTER_TOO_LONG };

  if (raw.includes("\\") || REGEX_TOKENS.some((token) => raw.includes(token))) {
    return { ok: false, error: ERROR_PLAIN_TEXT };
  }

  const parts = raw.split("|").filter((p) => p !== "");
  if (parts.length === 0) return { ok: false, error: ERROR_PLAIN_TEXT };
  if (parts.some((part) => part.startsWith("^") || part.endsWith("$"))) {
    return { ok: false, error: ERROR_PLAIN_TEXT };
  }
  return { ok: true, parts };
}

/**
 * Plain, case-sensitive substring test for a page-controlled URL (`String#includes`).
 *
 * `parts` comes from `parseUrlFilter`: the URL is captured when it contains ANY part.
 * An empty/absent `parts` means "no filter" and matches everything.
 */
export function urlContainsFilter(url, parts) {
  if (!Array.isArray(parts) || parts.length === 0) return true;
  const text = String(url);
  return parts.some((part) => text.includes(part));
}

function testString(value) {
  if (typeof value === "string") return value.slice(0, MAX_TEST_LEN);
  if (value === null || value === undefined) return "";
  return String(value).slice(0, MAX_TEST_LEN);
}

/**
 * Filter `links` by `pattern` (case-insensitive, matching text OR href).
 *
 * Returns `{ ok: true, links }` with the ORIGINAL link objects, in their original
 * order, or `{ ok: false, error }` with a message meant for the model. One timeout
 * covers the whole pass; each tested string is truncated to `MAX_TEST_LEN` first.
 */
export function filterLinks(links, pattern, { timeoutMs = FILTER_TIMEOUT_MS } = {}) {
  const list = Array.isArray(links) ? links : [];
  if (typeof pattern !== "string") return { ok: false, error: ERROR_INVALID };
  if (pattern.length > MAX_PATTERN_LEN) return { ok: false, error: ERROR_TOO_LONG };

  const texts = [];
  const hrefs = [];
  for (const link of list) {
    texts.push(testString(link?.text));
    hrefs.push(testString(link?.href));
  }

  const limit = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : FILTER_TIMEOUT_MS;
  const context = vm.createContext({ pattern, texts, hrefs });

  let raw;
  try {
    raw = MATCH_SCRIPT.runInContext(context, { timeout: limit });
  } catch (err) {
    if (err?.code === "ERR_SCRIPT_EXECUTION_TIMEOUT" || err?.name === "TimeoutError") {
      return { ok: false, error: ERROR_TOO_SLOW };
    }
    return { ok: false, error: ERROR_INVALID };
  }

  // Copy the indexes out of the vm realm; nothing else crosses back.
  const matched = Array.from(raw, (i) => (Number.isInteger(i) ? i : -1))
    .filter((i) => i >= 0 && i < list.length);

  return { ok: true, links: matched.map((i) => list[i]) };
}