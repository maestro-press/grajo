/**
 * Fetch a web page for citation: the guarded request (this half) and, later in this file, the
 * page extraction built on it. Shared by the research server and the reader bundle (bundles
 * import it through the app root, never a relative path).
 *
 * The URLs come from bots, which may be prompt-injected, so the request is an SSRF guard first:
 *
 * - Scheme: only http: and https:. A URL carrying credentials (`user:pass@`) is refused.
 * - Address: every connection goes through `guardedLookup`, which resolves the name ONCE and hands
 *   the socket exactly the addresses it checked. There is no second resolution between the check
 *   and the connect, so a DNS answer that changes between calls (rebinding) cannot steer the
 *   socket somewhere unchecked: the connected IP is the checked IP. `agent: false` gives each hop a
 *   fresh socket, so no pooled connection skips the lookup. Node does not call `lookup` for an
 *   IP-literal host, so literals are checked up front, before `request()`.
 * - Redirects: followed by hand, at most MAX_REDIRECTS, and every hop re-runs the scheme,
 *   credential and address checks.
 * - Size: a declared Content-Length over `maxBytes` is refused before the body is read; otherwise
 *   the DECOMPRESSED bytes are counted while streaming and the stream is destroyed when they pass
 *   `maxBytes` (a small gzip bomb trips it). Over the cap is an error; there is no partial result.
 * - Time: one AbortSignal.timeout is created when the call starts and covers every hop and every
 *   body read, so a slow redirect chain or a server dripping a byte at a time cannot hold the
 *   caller past `timeoutMs`. The abort surfaces as ETIMEDOUT.
 *
 * Caller headers: `headers` (optional, added for the reports sources) is an object merged over the
 * defaults for the FIRST hop, and again on a later hop only when the redirect target has the same
 * origin (protocol, host, port) as the hop that sent them. A hop that crosses to another origin is
 * sent without them, and every hop after it as well, so a credential put in a header can never ride
 * a redirect to another site. The four names that frame the request itself (`host`, `content-length`,
 * `transfer-encoding`, `connection`) are ignored wherever they appear. With no `headers` the request
 * is byte-identical to what this file sent before that option existed.
 *
 * Redirect hops a caller narrows: `onHop` (optional) is called with the parsed URL of each redirect
 * target BEFORE that hop is requested, and anything but `true` aborts the chain with
 * EREDIRECT_REFUSED and sends nothing to that target. It never sees the first request (the caller
 * chose that URL itself), and with no `onHop` the chain is exactly what it was before the option
 * existed. The reports sources use it to keep a credentialed request inside one origin and one path
 * prefix.
 *
 * Errors carry `code`: EBADURL, EBLOCKED, EREDIRECTS, EREDIRECT_REFUSED, ETOOBIG, EBADENCODING,
 * ETIMEDOUT, or the DNS/socket code (ENOTFOUND, ECONNREFUSED, ...). Non-2xx responses resolve; the
 * caller decides.
 *
 * `allowPrivate` exists only for the reader's operator opt-out. The research server never passes
 * it: bots choose its URLs.
 */
import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import zlib from "node:zlib";
import { isIP } from "node:net";
import { pipeline } from "node:stream/promises";
import { isPublicEgressIp } from "./ip-classify.js";
import { createHash } from "node:crypto";
import { extractInWorker } from "./fetch-page-worker.js";

export const FETCH_TIMEOUT_MS = 15000;
export const MAX_PAGE_BYTES = 5 * 1024 * 1024;
export const MAX_REDIRECTS = 5;
export const USER_AGENT = "Mozilla/5.0 (compatible; Crow-Research/1.0)";

const DEFAULT_ACCEPT = "text/html, application/xhtml+xml, text/plain;q=0.9, application/pdf;q=0.8, */*;q=0.5";

const fail = (code, message) => Object.assign(new Error(message), { code });

/**
 * A dns.lookup-shaped function that resolves once, refuses the whole answer if any address is not
 * allowed, and returns exactly the checked addresses to the socket.
 */
function guardedLookup({ lookup, isAllowedAddress }) {
  return (hostname, options, callback) => {
    if (typeof options === "function") { callback = options; options = {}; }
    lookup(hostname, { ...options, all: true }, (err, addrs) => {
      if (err) return callback(err);
      const list = (Array.isArray(addrs) ? addrs : [addrs]).map((a) => (typeof a === "string" ? { address: a, family: isIP(a) } : a));
      const bad = list.find((a) => !isAllowedAddress(a.address));
      if (!list.length || bad) {
        return callback(Object.assign(fail("EBLOCKED", `${hostname} resolves to a non-public address (${bad ? bad.address : "none"})`), { address: bad ? bad.address : null }));
      }
      if (options && options.all) return callback(null, list); // autoSelectFamily path
      callback(null, list[0].address, list[0].family);
    });
  };
}

/** Parse (against `base` for a redirect) and vet one hop's URL. Throws EBADURL / EBLOCKED. */
function checkHop(href, isAllowedAddress, base) {
  let url;
  try { url = new URL(href, base); } catch { throw fail("EBADURL", `not a valid URL: ${String(href).slice(0, 200)}`); }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw fail("EBADURL", `unsupported URL scheme: ${url.protocol}`);
  if (url.username || url.password) throw fail("EBADURL", "URLs with credentials are refused");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (!host) throw fail("EBADURL", "URL has no host");
  if (isIP(host) && !isAllowedAddress(host)) throw Object.assign(fail("EBLOCKED", `${host} is a non-public address`), { address: host });
  return url;
}

/** The headers a request carries when the caller adds none. */
function defaultHeaders(accept) {
  return { "User-Agent": USER_AGENT, Accept: accept, "Accept-Encoding": "gzip, deflate, br" };
}

/** The header names that frame the request itself, so a caller never sets them. */
const FRAMING_HEADERS = new Set(["host", "content-length", "transfer-encoding", "connection"]);

/**
 * A caller's own headers as a plain object, or null when it supplies none worth sending. The framing
 * names are dropped and a value that is not a string, a number or a list of those is dropped with it.
 */
function callerHeaders(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return null;
  const out = {};
  let any = false;
  for (const [name, raw] of Object.entries(value)) {
    if (typeof name !== "string" || !name) continue;
    if (FRAMING_HEADERS.has(name.trim().toLowerCase())) continue;
    if (raw == null) continue;
    if (Array.isArray(raw)) {
      const list = raw.filter((entry) => typeof entry === "string" || typeof entry === "number").map(String);
      if (!list.length) continue;
      out[name] = list;
      any = true;
      continue;
    }
    if (typeof raw !== "string" && typeof raw !== "number") continue;
    out[name] = String(raw);
    any = true;
  }
  return any ? out : null;
}

/** Two hops are the same origin when protocol, host and port all match (an implied port is ""). */
function sameOrigin(left, right) {
  return left.protocol === right.protocol && left.hostname === right.hostname && left.port === right.port;
}

/** Send one GET; resolves with the response (headers in, body unread). */
function requestOnce(url, { accept, lookup, signal, headers }) {
  const mod = url.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = mod.request(url, {
      method: "GET",
      headers: headers ? { ...defaultHeaders(accept), ...headers } : defaultHeaders(accept),
      lookup,
      agent: false,
      signal,
    });
    req.once("response", resolve);
    req.once("error", reject);
    req.end();
  });
}

function decoderFor(encoding) {
  const enc = String(encoding || "").trim().toLowerCase();
  if (!enc || enc === "identity") return null;
  if (enc === "gzip" || enc === "x-gzip") return zlib.createGunzip();
  if (enc === "deflate") return zlib.createInflate();
  if (enc === "br") return zlib.createBrotliDecompress();
  throw fail("EBADENCODING", `unsupported Content-Encoding: ${enc.slice(0, 100)}`);
}

/** Read the (decompressed) body, failing with ETOOBIG as soon as it passes maxBytes. */
async function readBody(res, { maxBytes, signal }) {
  const declared = Number(res.headers["content-length"]);
  if (Number.isFinite(declared) && declared > maxBytes) {
    res.destroy();
    throw fail("ETOOBIG", `declared Content-Length ${declared} exceeds ${maxBytes} bytes`);
  }
  let decoder;
  try { decoder = decoderFor(res.headers["content-encoding"]); } catch (err) { res.destroy(); throw err; }
  const chunks = [];
  let total = 0;
  const sink = async function (source) {
    for await (const chunk of source) {
      total += chunk.length;
      if (total > maxBytes) throw fail("ETOOBIG", `response body exceeds ${maxBytes} bytes`);
      chunks.push(chunk);
    }
  };
  await (decoder ? pipeline(res, decoder, sink, { signal }) : pipeline(res, sink, { signal }));
  return Buffer.concat(chunks);
}

function parseContentType(header) {
  const raw = String(header || "");
  const content_type = raw.split(";")[0].trim().toLowerCase();
  const m = raw.match(/;\s*charset\s*=\s*"?([^";\s]+)"?/i);
  return { content_type, charset: m ? m[1].toLowerCase() : null };
}

const GUARD_CODES = new Set([
  "EBADURL", "EBLOCKED", "EREDIRECTS", "EREDIRECT_REFUSED", "ETOOBIG", "EBADENCODING",
]);
const isAbort = (err) => err && (err.name === "AbortError" || err.name === "TimeoutError" || err.code === "ABORT_ERR");

/**
 * GET a URL through the SSRF guard. See the file header for the contract, including how a caller's
 * `headers` are carried (first hop, then same-origin hops only) and how `onHop` narrows the redirect
 * chain (each target is offered to it before that hop is requested).
 * @returns {Promise<{final_url: string, http_status: number, content_type: string, charset: string|null, buffer: Buffer}>}
 */
export async function guardedRequest(url, opts = {}) {
  const {
    maxBytes = MAX_PAGE_BYTES,
    timeoutMs = FETCH_TIMEOUT_MS,
    accept = DEFAULT_ACCEPT,
    allowPrivate = false,
    lookup = dns.lookup,
    onHop = null,
  } = opts;
  const isAllowedAddress = allowPrivate ? () => true : (opts.isAllowedAddress || isPublicEgressIp);
  const signal = AbortSignal.timeout(timeoutMs); // ONE deadline for every hop and body read
  const connectLookup = guardedLookup({ lookup, isAllowedAddress });

  try {
    let current = checkHop(url, isAllowedAddress);
    // The caller's headers ride the first hop; a redirect that leaves this origin drops them for good.
    let hopHeaders = callerHeaders(opts.headers);
    for (let hop = 0; ; hop++) {
      const res = await requestOnce(current, { accept, lookup: connectLookup, signal, headers: hopHeaders });
      const status = res.statusCode;
      const location = res.headers.location;
      if (status >= 300 && status < 400 && location) {
        res.destroy(); // never read a redirect body
        if (hop >= MAX_REDIRECTS) throw fail("EREDIRECTS", `more than ${MAX_REDIRECTS} redirects`);
        const next = checkHop(location, isAllowedAddress, current);
        // The caller's own rule for a hop, asked before anything is sent to that target: a predicate
        // that does not answer `true` ends the chain here.
        if (typeof onHop === "function" && onHop(next) !== true) {
          throw fail("EREDIRECT_REFUSED", `redirect to ${next.href.slice(0, 200)} is not allowed here`);
        }
        if (hopHeaders && !sameOrigin(current, next)) hopHeaders = null;
        current = next;
        continue;
      }
      const buffer = await readBody(res, { maxBytes, signal });
      return { final_url: current.href, http_status: status, ...parseContentType(res.headers["content-type"]), buffer };
    }
  } catch (err) {
    // A guard refusal wins over a deadline that fired after it; any other failure once the
    // deadline has passed (AbortError, TimeoutError, a socket torn down by the abort) is ETIMEDOUT.
    if (GUARD_CODES.has(err?.code)) throw err;
    if (isAbort(err) || signal.aborted) throw Object.assign(fail("ETIMEDOUT", `timed out after ${timeoutMs} ms`), { cause: err });
    throw err;
  }
}

export const EXTRACT_TIMEOUT_MS = 10000;
export const FETCHED_TEXT_MAX = 200000;
export const PREVIEW_CHARS = 1200;
export const REFETCH_AFTER_DAYS = 30;
export const FULL_TEXT_MARKER = "\n\n[crow: full page text]\n\n";

/**
 * Whether a stored fetched_text may be a cut copy of its page. fetchPage cuts at FETCHED_TEXT_MAX,
 * except when the cap lands inside the full-text marker: it then stores the readable text alone,
 * up to FULL_TEXT_MARKER.length chars short of the cap. Conservative: a page that happens to end
 * in that window reads as maybe-cut, so a quote not found there is "not checked", never a misquote.
 */
export function storedTextMaybeTruncated(text) {
  return String(text || "").length > FETCHED_TEXT_MAX - FULL_TEXT_MARKER.length;
}

/** Split stored fetched text back into the readable part and the full-body part. */
export function splitFetchedText(text) {
  const s = String(text || "");
  const i = s.indexOf(FULL_TEXT_MARKER);
  if (i < 0) return { readable: s, body: s };
  return { readable: s.slice(0, i), body: s.slice(i + FULL_TEXT_MARKER.length) };
}

const REASONS = {
  EBLOCKED: "the address is not public",
  ENOTFOUND: "could not resolve the host",
  EAI_AGAIN: "could not resolve the host",
  ETIMEDOUT: "timed out",
  ETOOBIG: "the page is over 5 MB",
  EREDIRECTS: "too many redirects",
  EBADURL: "only http and https URLs",
  EBADENCODING: "the page uses an unsupported compression",
  ECONNREFUSED: "the server refused the connection",
  Z_DATA_ERROR: "the page's compressed data is corrupt",
};
const reasonFor = (err) => REASONS[err?.code] || `the page could not be fetched (${err?.code || "unknown error"})`;

function decode(buffer, charset) {
  let dec;
  try { dec = new TextDecoder(charset || "utf-8", { fatal: false }); } catch { dec = new TextDecoder("utf-8", { fatal: false }); }
  return dec.decode(buffer);
}

const sha256hex = (s) => createHash("sha256").update(s).digest("hex");

/** The failure object fetchPage returns when the guarded request itself throws. */
export function failedRequest(err) {
  return { ok: false, fetch_status: "failed", reason: reasonFor(err), final_url: null, http_status: null };
}

/**
 * Fetch a page and extract citable text. Never throws. Two exports share the work: `fetchPage`
 * (the guarded request, then `pageFromResponse`) and `pageFromResponse` (the extraction half, so
 * a fixture can run a canned response through the real extraction without touching the network).
 * @returns {Promise<object>} on failure { ok: false, fetch_status: "failed", reason, final_url,
 *   http_status }; on success { ok: true, fetch_status: "fetched" | "fetched_no_text", final_url,
 *   http_status, content_type, fetched_at, text, readable_text, truncated, sha256 }
 */
export async function fetchPage(url, opts = {}) {
  const { extractTimeoutMs = EXTRACT_TIMEOUT_MS, workerUrl, ...reqOpts } = opts;
  let res;
  try {
    res = await guardedRequest(url, reqOpts);
  } catch (err) {
    return failedRequest(err);
  }
  return pageFromResponse(res, { extractTimeoutMs, workerUrl });
}

/**
 * The post-request half of fetchPage. `res` is the guardedRequest result
 * { final_url, http_status, content_type, charset, buffer }.
 */
export async function pageFromResponse(res, { extractTimeoutMs = EXTRACT_TIMEOUT_MS, workerUrl } = {}) {
  const failed = (reason) => ({ ok: false, fetch_status: "failed", reason, final_url: res.final_url, http_status: res.http_status });
  if (res.http_status < 200 || res.http_status >= 300) return failed(`HTTP ${res.http_status}`);

  const base = { ok: true, final_url: res.final_url, http_status: res.http_status, content_type: res.content_type, fetched_at: new Date().toISOString() };
  const noText = () => ({ ...base, fetch_status: "fetched_no_text", text: null, readable_text: "", truncated: false, sha256: null });

  let readable;
  let body;
  if (res.content_type === "text/html" || res.content_type === "application/xhtml+xml") {
    const html = decode(res.buffer, res.charset);
    const out = await extractInWorker(html, res.final_url, { timeoutMs: extractTimeoutMs, ...(workerUrl ? { workerUrl } : {}) });
    if (out.error) return failed(out.error === "extract_timeout" ? "extraction timed out" : "extraction failed");
    ({ readable, body } = out);
    if (!readable && !body) return noText();
  } else if (res.content_type === "text/plain" || res.content_type === "text/markdown") {
    readable = body = decode(res.buffer, res.charset);
    if (!readable.trim()) return noText();
  } else {
    return noText();
  }

  let truncated = false;
  let text;
  if (body === readable) {
    text = readable;
  } else if (readable.length + FULL_TEXT_MARKER.length >= FETCHED_TEXT_MAX) {
    // The cap lands inside the readable text or the marker: keep only the readable text (a
    // partial marker would store a half-split copy), cut below if needed.
    text = readable;
    truncated = true;
  } else {
    text = readable + FULL_TEXT_MARKER + body;
  }
  if (text.length > FETCHED_TEXT_MAX) { text = text.slice(0, FETCHED_TEXT_MAX); truncated = true; }
  const readable_text = text.length >= readable.length ? readable : text; // readable may itself be cut
  return { ...base, fetch_status: "fetched", text, readable_text, truncated, sha256: sha256hex(text) };
}
