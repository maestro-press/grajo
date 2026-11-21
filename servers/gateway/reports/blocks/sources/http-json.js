/**
 * The `http_json` block: one JSON document from one host the owner approved, and the array of items
 * inside it.
 *
 * Settings: `{url, method: "GET", itemsPath?, credential?: {host}, userAgent?}`.
 *   - `method` is GET and nothing else. A report reads; it never writes to a site.
 *   - `itemsPath` is a dotted path to the array (`data.items`), and an empty or absent path means the
 *     document itself is the array. A plain object in the array is an item; anything else (a string, a
 *     number, a list) becomes `{value: <it>}`, so every item is an object the shape blocks can read.
 *     At most `MAX_ITEMS` items are kept.
 *   - `credential: {host}` names the site the report's approved credential binding belongs to. It sends
 *     a secret, so it is also the block's strictest path (below).
 *   - `userAgent` is the `User-Agent` this request sends instead of the guarded request's own default. It
 *     is plain text the owner typed: printable ASCII, 1 to 120 characters, no leading or trailing
 *     whitespace and not whitespace only, and no control character (so no
 *     line break can be spliced into a header). It is NEVER defaulted here: absent means the guard's own
 *     default agent, byte for byte what this block sent before the setting existed. It rides EVERY request
 *     the block makes, credentialed or not, through the guarded request's `headers` option, which carries
 *     a caller's headers on the first hop and on later hops only while they stay on the same origin: a
 *     redirect that crosses to another origin is sent with the default agent, the guard's own rule (see
 *     servers/shared/fetch-page.js). It is a source setting like the URL, so it is inside the sealed
 *     `sourcesHash`: changing it needs the owner's tap. A credential rule that attaches its secret to the
 *     `user-agent` header itself (in any case) is a conflict this setting cannot win: the request is
 *     refused with `user_agent_conflict` and nothing is sent.
 *
 * THE HOST IS CHECKED BEFORE ANYTHING ELSE, AND ON EVERY HOP: the report's approved and verified host
 * rows are read ONCE before the request, and the URL's host must be on that list, or the block answers
 * `host_unapproved` with no request made. The same list is handed to the guarded request as a
 * SYNCHRONOUS `onHop` predicate, so every redirect target's host is checked before that hop is
 * requested: a hop to a host this report has not approved answers `redirect_refused` and is never
 * contacted. The host of the response's `final_url` must pass the host rule once the request is over,
 * so a response that came from somewhere else answers `host_unapproved` and contributes no items. The
 * request itself goes through the injected `ctx.fetch` seam, which is `guardedRequest`
 * (`servers/shared/fetch-page.js`): only http and https, a private or link-local address refused, a byte
 * cap, and the caller's `onHop` asked on every hop. A build with no seam answers `fetch_not_available`
 * rather than opening a socket of its own.
 *
 * A CREDENTIALED REQUEST (`credential` set):
 *   - it SPENDS THE REPORT'S DAY: a credentialed request is one of the day's `extra_step_runs`, so the
 *     run's own claim (`ctx.extraStepClaim`, built by the run executor) is taken HERE, after the rule
 *     was resolved and allowed and before the request is sent. A request whose credential is refused
 *     spends nothing, because nothing was read. A block run outside a run executor has no claim and
 *     takes none.
 *   - the URL must be https on the default port (empty or 443), the credential's host must be the URL's
 *     host, and the report must hold an approved, verified inject rule for that host from
 *     `injectRulesFor` whose methods cover GET and whose path prefixes cover this path. The rule is bound
 *     to that EXACT ORIGIN: a URL that names another port is another origin, and an approval for the
 *     default port does not cover it. The path rule is DENY BY DEFAULT and reads the pathname the URL
 *     STRING wrote, before `new URL` normalises it: that raw pathname must be made only of
 *     `A-Za-z0-9-._~/` (so no `%`, no `;`, no backslash, nothing else), no segment may be `.` or start
 *     with `..`, and only then must it sit at or under one of the rule's prefixes on WHOLE SEGMENTS
 *     (`/api` covers `/api` and `/api/x`, never `/apix`). Anything else is `credential_not_allowed`: a
 *     path spelling the owner never approved, a rule for another path, another port, another method or
 *     another site is not this request's rule.
 *   - the secret is read from that rule's `secret()` AT CALL TIME (never stored, never in a table), and
 *     it goes in exactly one place: the rule's header (through the guarded request's `headers` option,
 *     which carries it on the first hop and drops it on any cross-origin redirect), or the query of the
 *     FIRST request URL. A redirect hop's URL is built from the server's `Location` header, so the query
 *     is not carried to it.
 *   - the redirect chain is narrowed to the rule AND to the approved hosts: the guarded request is handed
 *     an `onHop` predicate that answers `true` only for a hop whose host is on the report's approved
 *     list, on the same origin, and whose PARSED (normalised) pathname passes the same deny-by-default
 *     helper the first request passed. The raw-pathname rule is the first request's; a hop's path is
 *     what `new URL` made of the server's `Location`. A hop outside that answers `EREDIRECT_REFUSED`
 *     (this block's `redirect_refused`) and nothing is sent to it.
 *   - the secret is echoed back at nobody: when a credential was sent, a body whose raw text, or whose
 *     parsed document (every key and every value, at any depth), carries the secret in ANY spelling
 *     (raw, percent-encoded in either case, `+` for a space, base64, base64url, hex in either case, or
 *     the formatted header value with its base64) answers `credential_echoed` and no items. A server
 *     that reflects the credential into its answer is a server whose answer is not data. The walk of the
 *     parsed document is what catches a secret whose own characters the document escapes (`"` and `\`).
 *   - every error text this block answers is a code word, and it is passed through `redactSecrets` with
 *     the secret and its URL-encoded and base64 forms, so a server that echoes the secret into a body or
 *     a thrown error that quotes the request URL cannot put it in a run's error text.
 *
 * The two helpers `sourceHostApproved` and `fetchSourceBytes` are exported because `rss` is the other
 * URL source and needs the same host rule and the same guarded fetch. They live here rather than in a
 * fifth file because the registry is one module per block type.
 *
 * NOTHING HEAVY LOADS WITH THE REGISTRY: `steps.js` (the host and credential approvals) is imported on
 * first use, and the guarded request is the caller's seam rather than an import. This module is loaded
 * by the block registry, which the store reads on every recipe save of every server.
 *
 * This block stores no state: nothing here calls `ctx.setState`.
 */
import { redactSecrets } from "../../../../shared/redact-secrets.js";

/** How many items one document may contribute. */
export const MAX_ITEMS = 5000;

/** The bytes one response may carry. The guarded request's own cap, named here for the seam's shape. */
export const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

/** The milliseconds one response may take, every hop and every body read included. */
export const REQUEST_TIMEOUT_MS = 15000;

const SETTING_KEYS = new Set(["url", "method", "itemsPath", "credential", "userAgent"]);

/**
 * A `User-Agent` the owner may set: printable ASCII (0x20 to 0x7e) only, 1 to 120 characters, no leading
 * or trailing whitespace and not whitespace only. CR, LF and
 * every other control character are refused here, so no value can splice a second header line.
 */
const USER_AGENT_RE = /^[\x20-\x7e]{1,120}$/;

/** Is this a User-Agent this block may send? The shape above, and the value is the words it reads as. */
function userAgentOk(value) {
  return typeof value === "string" && USER_AGENT_RE.test(value) && value.trim() === value;
}

/** A lower-case host name with at least two labels: the shape a credential binds. */
const HOST_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

/** The guarded request's own refusals: a URL or an address the guard would not send to. */
const GUARD_REFUSALS = new Set(["EBADURL", "EBLOCKED", "EREDIRECTS"]);

/** The approvals module, imported on first use so a recipe save does not load the keychain. */
let stepsModule = null;

function loadSteps() {
  if (!stepsModule) stepsModule = import("../../steps.js");
  return stepsModule;
}

export function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

/** One value as a string, never "undefined" and never a throw. */
export function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** The code word a failed guarded request answers, never the guard's own message text. */
export function fetchErrorCode(err) {
  const code = err && typeof err.code === "string" ? err.code : "";
  if (code === "fetch_not_available") return "fetch_not_available";
  if (code === "ETOOBIG") return "too_large";
  if (code === "EREDIRECT_REFUSED") return "redirect_refused";
  if (GUARD_REFUSALS.has(code)) return "blocked_address";
  return "fetch_failed";
}

/** The secret and the two encoded forms of it that a URL or a log line could carry. */
export function secretForms(secret) {
  if (typeof secret !== "string" || !secret) return [];
  return [secret, encodeURIComponent(secret), Buffer.from(secret, "utf8").toString("base64")];
}

/** A percent-encoded value with every hexadecimal escape in lower case (`%2B` -> `%2b`). */
function lowerCaseEscapes(value) {
  return value.replace(/%[0-9A-F]{2}/g, (escape) => escape.toLowerCase());
}

/**
 * Every spelling a credential could come back as: the secret itself, its URL encoding in both cases of
 * hexadecimal escape, the form encoding (`+` for a space), base64, base64url and hex, and, when one was
 * sent, the formatted header value with its own base64. Empty strings and repeats are dropped.
 *
 * @param {string} secret
 * @param {string} [headerValue] the whole header value the request carried, e.g. `Bearer <secret>`
 * @returns {string[]}
 */
export function echoForms(secret, headerValue = "") {
  if (typeof secret !== "string" || !secret) return [];
  const bytes = Buffer.from(secret, "utf8");
  const encoded = encodeURIComponent(secret);
  const forms = [
    secret,
    encoded,
    lowerCaseEscapes(encoded),
    encoded.replace(/%20/g, "+"),
    secret.split(" ").join("+"),
    bytes.toString("base64"),
    bytes.toString("base64url"),
    bytes.toString("hex"),
    bytes.toString("hex").toUpperCase(),
  ];
  if (typeof headerValue === "string" && headerValue) {
    forms.push(headerValue, Buffer.from(headerValue, "utf8").toString("base64"));
  }
  return [...new Set(forms.filter((form) => typeof form === "string" && form))];
}

/** Does any of these spellings appear in this text? */
export function carriesSecret(value, forms) {
  if (typeof value !== "string" || !value) return false;
  if (!Array.isArray(forms) || forms.length === 0) return false;
  return forms.some((form) => value.includes(form));
}

/**
 * Does any string in this parsed document carry one of these spellings? Every key and every value is
 * tested at any depth, as the string it really is: a body's own escaping (`\"`, `\\`, `\uXXXX`) is not
 * in the parsed string, and the raw-text check cannot see through it.
 *
 * @param {*} value the parsed document
 * @param {string[]} forms the spellings a secret could come back as
 * @returns {boolean}
 */
export function carriesSecretIn(value, forms) {
  if (!Array.isArray(forms) || forms.length === 0) return false;
  const seen = new Set();
  const stack = [value];
  while (stack.length > 0) {
    const node = stack.pop();
    if (typeof node === "string") {
      if (carriesSecret(node, forms)) return true;
      continue;
    }
    if (node == null || typeof node !== "object") continue;
    if (seen.has(node)) continue;
    seen.add(node);
    if (Array.isArray(node)) {
      for (const item of node) stack.push(item);
      continue;
    }
    for (const [key, field] of Object.entries(node)) {
      if (carriesSecret(key, forms)) return true;
      stack.push(field);
    }
  }
  return false;
}

/** The redaction every error text in this block passes through. */
export function redactWith(message, secrets) {
  return redactSecrets(text(message), Array.isArray(secrets) ? secrets : []);
}

/**
 * The characters a credentialed request's pathname may carry, written out in full. It is an allowlist,
 * not a list of known-bad escapes: percent-encoding of any kind, `;` (a matrix parameter a server may
 * strip before its own routing), a backslash and everything else is refused, because every one of them
 * is a spelling some layer between here and the site could read as a different path.
 */
const SAFE_RAW_PATH_RE = /^[A-Za-z0-9\-._~\/]*$/;

/** The scheme and authority of a URL string: up to the first `/`, `?`, `#` or `\` (a special URL's
 *  own authority terminator, since the parser treats a backslash as a slash there). */
const URL_HEAD_RE = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#\\]*/;

/**
 * Does this pathname sit at or under this prefix, on WHOLE segments? `/api` covers `/api` and `/api/x`
 * and never `/apix` or `/api..`; a prefix that already ends in `/` is used as it is.
 *
 * @param {string} pathname
 * @param {string} prefix
 * @returns {boolean}
 */
export function pathWithinPrefix(pathname, prefix) {
  if (typeof pathname !== "string" || !pathname) return false;
  if (typeof prefix !== "string" || !prefix) return false;
  if (pathname === prefix) return true;
  return pathname.startsWith(prefix.endsWith("/") ? prefix : prefix + "/");
}

/**
 * The pathname a URL string carries, exactly as it was written: from the character after the authority
 * up to the `?` or `#`. `new URL` resolves dot segments and decodes encoded dots before its `pathname`
 * can be read (`/api/%2e%2e/x` becomes `/x`), so the credentialed check reads the caller's own text
 * instead and decides on what was asked for, not on what a parser made of it. An absent path is the
 * `/` the request really sends; a string this cannot read is null, which the check refuses.
 *
 * @param {string} href the URL as a string
 * @returns {string|null}
 */
export function rawPathOf(href) {
  if (typeof href !== "string" || !href) return null;
  const head = URL_HEAD_RE.exec(href);
  if (!head) return null;
  const rest = href.slice(head[0].length);
  const cut = rest.search(/[?#]/);
  const path = cut === -1 ? rest : rest.slice(0, cut);
  return path === "" ? "/" : path;
}

/**
 * May a credential ride this pathname? Deny by default: the pathname, unmodified, must be made only of
 * the characters in `SAFE_RAW_PATH_RE`, no segment may be `.` or start with `..`, and only then does it
 * have to sit at or under one of the rule's prefixes on whole segments. A path this cannot read is a
 * path the owner never approved.
 *
 * @param {string} rawPathname the pathname as the URL string wrote it
 * @param {string[]} prefixes the rule's own list
 * @returns {boolean}
 */
export function credentialPathAllowed(rawPathname, prefixes) {
  if (typeof rawPathname !== "string" || !rawPathname) return false;
  if (!SAFE_RAW_PATH_RE.test(rawPathname)) return false;
  for (const segment of rawPathname.split("/")) {
    if (segment === "." || segment.startsWith("..")) return false;
  }
  if (!Array.isArray(prefixes)) return false;
  return prefixes.some((prefix) => pathWithinPrefix(rawPathname, prefix));
}

/** An absolute http(s) URL with no credentials in it, or null. */
export function httpUrlOf(value) {
  if (typeof value !== "string" || !value) return null;
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  if (!url.hostname) return null;
  return url;
}

/**
 * The hosts this report may reach right now, as a synchronous predicate over a URL: every approved host
 * row whose seal still verifies is read ONCE here, so a redirect hop can be checked on the hop
 * (`guardedRequest`'s `onHop` is synchronous). No database or no saved report is an empty list, and no
 * host is on it.
 *
 * @param {object} ctx the block's context
 * @returns {Promise<(url: URL) => boolean>}
 */
export async function approvedHostRule(ctx) {
  const reportId = text(ctx?.report?.id);
  if (!reportId || !ctx?.db) return () => false;
  const { hostAllowed, listHosts } = await loadSteps();
  let hosts = [];
  try {
    const rows = await listHosts(ctx.db, reportId, ctx.deps ?? {});
    hosts = rows
      .filter((row) => row != null && row.verified === true)
      .map((row) => text(row.host))
      .filter((host) => host !== "");
  } catch {
    hosts = [];
  }
  return (url) => {
    if (url == null || typeof url !== "object" || typeof url.hostname !== "string") return false;
    return hostAllowed(url.hostname.replace(/^\[|\]$/g, ""), hosts);
  };
}

/**
 * Does this URL's host pass the report's own host approvals? A report id and a database are both
 * needed to answer yes: without either, nothing is approved.
 *
 * @param {object} ctx the block's context
 * @param {URL} url
 * @returns {Promise<boolean>}
 */
export async function sourceHostApproved(ctx, url) {
  const reportId = text(ctx?.report?.id);
  if (!reportId || !ctx.db) return false;
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const { hostApproved } = await loadSteps();
  return hostApproved(ctx.db, ctx.deps ?? {}, reportId, host);
}

/**
 * One GET through the injected seam, answering the guarded request's shape
 * `{final_url, http_status, content_type, charset, buffer}`. A build with no seam is a refusal here
 * rather than a socket opened quietly. `opts.onHop` rides the request so the guard asks this block's
 * own rule before each redirect hop.
 *
 * @param {object} ctx
 * @param {string} url
 * @param {{headers?: object, accept?: string, onHop?: (url: URL) => boolean}} [opts]
 * @returns {Promise<object>}
 * @throws {Error} `fetch_not_available` when no seam is injected, else the seam's own error
 */
export async function fetchSourceBytes(ctx, url, opts = {}) {
  if (typeof ctx?.fetch !== "function") {
    const err = new Error("fetch_not_available");
    err.code = "fetch_not_available";
    throw err;
  }
  const request = { maxBytes: MAX_RESPONSE_BYTES, timeoutMs: REQUEST_TIMEOUT_MS };
  if (opts.accept) request.accept = opts.accept;
  if (opts.headers) request.headers = opts.headers;
  if (typeof opts.onHop === "function") request.onHop = opts.onHop;
  return ctx.fetch(url, request);
}

/** The response body as text, in the charset it declared and utf-8 otherwise. */
export function bodyTextOf(response) {
  const body = response && response.buffer;
  if (typeof body === "string") return body;
  if (body == null) return "";
  const bytes = body instanceof Uint8Array ? body : null;
  if (!bytes) return "";
  const charset = text(response.charset) || "utf-8";
  try {
    return new TextDecoder(charset, { fatal: false }).decode(bytes);
  } catch {
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }
}

/** The value at a dotted path inside `value`, or undefined when the path is not there. */
export function readPath(value, path) {
  const parts = text(path).split(".").filter((part) => part !== "");
  let cursor = value;
  for (const part of parts) {
    if (cursor == null || typeof cursor !== "object" || !Object.hasOwn(cursor, part)) return undefined;
    cursor = cursor[part];
  }
  return cursor;
}

/** One element of the array as an item: a plain object as it is, anything else wrapped. */
export function itemOf(value) {
  if (isPlainObject(value)) return value;
  return { value };
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  for (const key of Object.keys(settings)) {
    if (!SETTING_KEYS.has(key)) errors.push(key);
  }
  if (!httpUrlOf(settings.url)) errors.push("url");
  if (settings.method !== undefined && settings.method !== "GET") errors.push("method");
  if (settings.itemsPath !== undefined && typeof settings.itemsPath !== "string") errors.push("itemsPath");
  if (settings.userAgent !== undefined) {
    if (!userAgentOk(settings.userAgent)) errors.push("userAgent");
  }
  if (settings.credential !== undefined) {
    const credential = settings.credential;
    if (!isPlainObject(credential)) {
      errors.push("credential");
    } else {
      for (const key of Object.keys(credential)) {
        if (key !== "host") errors.push(`credential.${key}`);
      }
      if (typeof credential.host !== "string" || !HOST_RE.test(credential.host)) {
        errors.push("credential.host");
      }
    }
  }
  return errors;
}

/**
 * The credential this request may carry: the header or the first-hop URL, or the code word that says
 * why it may not. `rawPathname` is the path the caller's URL string wrote, which is what the path rule
 * reads; `pathPrefixes` is the rule's own list, which the redirect predicate re-checks.
 *
 * @returns {Promise<{headers?: object, url?: string, secret?: string, headerValue?: string,
 *   pathPrefixes?: string[], code?: string}>}
 */
async function credentialFor(ctx, url, host, rawPathname) {
  if (url.protocol !== "https:") return { code: "credential_not_allowed" };
  // The rule is bound to one exact origin. A URL that names another port is another origin (`new URL`
  // leaves an https default port empty), and the owner's approval does not cover it.
  if (url.port !== "" && url.port !== "443") return { code: "credential_not_allowed" };
  const reportId = text(ctx?.report?.id);
  if (!reportId || !ctx.db) return { code: "credential_not_allowed" };
  let rules;
  try {
    const { injectRulesFor } = await loadSteps();
    rules = await injectRulesFor(ctx.db, ctx.deps ?? {}, { reportId });
  } catch {
    return { code: "credential_not_allowed" };
  }
  const rule = Array.isArray(rules) ? rules.find((entry) => entry && entry.host === host) : null;
  if (!rule) return { code: "credential_not_allowed" };
  if (!Array.isArray(rule.methods) || !rule.methods.includes("GET")) return { code: "credential_not_allowed" };
  const prefixes = Array.isArray(rule.pathPrefixes) ? rule.pathPrefixes : [];
  if (!credentialPathAllowed(rawPathname, prefixes)) return { code: "credential_not_allowed" };
  const secret = typeof rule.secret === "function" ? text(rule.secret()) : "";
  if (!secret) return { code: "credential_unavailable" };
  if (typeof rule.header === "string" && rule.header) {
    const format = typeof rule.format === "string" && rule.format.includes("{}") ? rule.format : "{}";
    const headerValue = format.replace("{}", secret);
    return { headers: { [rule.header]: headerValue }, secret, headerValue, pathPrefixes: prefixes };
  }
  if (typeof rule.query === "string" && rule.query) {
    const separator = url.search === "" ? "?" : "&";
    return {
      url: `${url.href}${separator}${encodeURIComponent(rule.query)}=${encodeURIComponent(secret)}`,
      secret,
      pathPrefixes: prefixes,
    };
  }
  return { code: "credential_not_allowed" };
}

/** Does this resolved credential attach its secret to the `user-agent` header, in any case? */
function credentialSendsAgent(credential) {
  return isPlainObject(credential?.headers)
    && Object.keys(credential.headers).some((name) => name.toLowerCase() === "user-agent");
}

async function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const secrets = [];
  const refuse = (code) => ({ sourceError: { message: redactWith(code, secrets) } });

  const url = httpUrlOf(settings.url);
  if (!url) return refuse("bad_settings");
  if (settings.method !== undefined && settings.method !== "GET") return refuse("bad_method");

  // The host is checked before anything reaches the network, and the same list narrows every hop.
  const hostOk = await approvedHostRule(ctx);
  if (!hostOk(url)) return refuse("host_unapproved");

  const host = url.hostname.replace(/^\[|\]$/g, "");
  const userAgent = typeof settings.userAgent === "string" ? settings.userAgent : "";
  let requestUrl = url;
  let headers = null;
  let credential = null;
  if (settings.credential !== undefined) {
    if (!isPlainObject(settings.credential) || settings.credential.host !== host) {
      return refuse("credential_not_allowed");
    }
    credential = await credentialFor(ctx, url, host, rawPathOf(settings.url));
    if (credential.code) return refuse(credential.code);
    // The owner's own agent and a credential whose secret rides the `user-agent` header (in any case)
    // cannot both be sent: one of the two would silently replace the other, so neither is. Refused here,
    // before the claim, so a refused request spends nothing.
    if (userAgent && credentialSendsAgent(credential)) return refuse("user_agent_conflict");
    // The rule is resolved and allowed, so this request really is one of the day's extra step runs: the
    // run's claim is taken here and nowhere earlier, so a refused credential spends nothing. A claim
    // that finds the cap used up throws `cap_reached`, which the executor records against this block.
    if (typeof ctx?.extraStepClaim === "function") await ctx.extraStepClaim();
    if (credential.secret) secrets.push(...secretForms(credential.secret));
    if (credential.headers) headers = { ...credential.headers };
    if (credential.url) requestUrl = credential.url;
  }

  // The owner's own agent, when the owner set one, on every request this block makes. It is applied
  // after the credential's header so a setting the owner approved is what the site is told, and the
  // guard carries it on the first hop and on same-origin hops only. Absent, the guard's default is sent.
  if (userAgent) headers = { ...(headers || {}), "User-Agent": userAgent };

  // What the credential sent may not come back: every spelling of it, and the header value itself.
  const echoed = credential && credential.secret
    ? echoForms(credential.secret, credential.headerValue || "")
    : [];
  // A redirect may not walk a request out of the approved hosts: the host is checked on every hop, and
  // a credentialed request is kept inside its origin and its path prefixes on top of that.
  const onHop = (hop) => hostOk(hop) && (!credential || !credential.secret
    || (hop.origin === url.origin && credentialPathAllowed(hop.pathname, credential.pathPrefixes)));

  let response;
  try {
    response = await fetchSourceBytes(ctx, typeof requestUrl === "string" ? requestUrl : requestUrl.href, {
      accept: "application/json, text/json;q=0.9, */*;q=0.5",
      ...(headers ? { headers } : {}),
      onHop,
    });
  } catch (err) {
    return refuse(fetchErrorCode(err));
  }

  const status = Number(response?.http_status);
  if (!Number.isFinite(status) || status < 200 || status >= 300) return refuse("http_error");

  // The host the response really came from, after any redirect it followed.
  const finalUrl = httpUrlOf(text(response?.final_url));
  if (!finalUrl || !(await sourceHostApproved(ctx, finalUrl))) return refuse("host_unapproved");

  const body = bodyTextOf(response);
  if (!body) return refuse("bad_response");
  if (carriesSecret(body, echoed)) return refuse("credential_echoed");

  let document;
  try {
    document = JSON.parse(body);
  } catch {
    return refuse("bad_response");
  }

  // The same check against what the body parses to: an escaped copy (`\u0073\u0033...`, or a secret
  // holding `"` or `\`, which the document escapes) is not the secret in the raw text, but it is one in
  // the document.
  if (echoed.length && carriesSecretIn(document, echoed)) return refuse("credential_echoed");

  const found = readPath(document, settings.itemsPath);
  if (!Array.isArray(found)) return refuse(settings.itemsPath ? "items_not_found" : "bad_response");

  const items = [];
  for (const entry of found.slice(0, MAX_ITEMS)) items.push(itemOf(entry));
  return { items };
}

export const httpJsonBlock = Object.freeze({
  type: "http_json",
  kind: "source",
  sourceBearing: true,
  validate,
  run,
});