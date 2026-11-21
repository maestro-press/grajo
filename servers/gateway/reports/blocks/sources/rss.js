/**
 * The `rss` block: one RSS 2.0 or Atom feed from one host the owner approved.
 *
 * Settings: `{url}`. Nothing else: a feed needs no credential, and the plan gives it none.
 *
 * The rules are `http_json`'s, which is why the host rule and the guarded fetch are imported from there:
 * the report's approved and verified host rows are read ONCE before the request, the URL's host must be
 * on that list, and the same list rides the request as a synchronous `onHop` predicate, so every
 * redirect hop's host is checked before that hop is requested. The request goes through the injected
 * `ctx.fetch` seam (`guardedRequest`, so only http and https, a private address refused, a byte cap), and
 * a build with no seam answers `fetch_not_available`. The host of the response's `final_url` must pass
 * the host rule too: a feed that redirects to a host this report has not approved answers
 * `host_unapproved` and contributes no items, and a hop to such a host answers `redirect_refused` and is
 * never contacted.
 *
 * Parsing uses the XML parser this repository already has: `linkedom`'s `DOMParser` (a production
 * dependency, already used by `servers/shared/fetch-page-worker.js`), in `text/xml` mode. No XML parser
 * was added for this block and none is hand-rolled here. It is imported on first use, so loading the
 * block registry (a recipe save) does not load a parser. The parser decodes a feed's character
 * references once; nothing here decodes them again, so a body that spelled `&amp;lt;script&amp;gt;`
 * arrives as the text `&lt;script&gt;` and never as a tag.
 *
 * Items are `{title, link, published, summary}`, every field a string:
 *   - `title` and `published` are the feed's own text, trimmed and left as the feed wrote it (an Atom
 *     entry's `published`, or its `updated` when it has none; an RSS item's `pubDate`);
 *   - `link` is an absolute http(s) URL or "", so nothing else can reach a document as a link;
 *   - `summary` is the item's `description`/`summary`/`content` with its markup stripped: the tags are
 *     removed once, after the parser has decoded the references.
 * At most `MAX_FEED_ITEMS` items are kept.
 *
 * This block stores no state: nothing here calls `ctx.setState`.
 */
import {
  approvedHostRule, bodyTextOf, fetchErrorCode, fetchSourceBytes, httpUrlOf, isPlainObject, redactWith,
  sourceHostApproved, text,
} from "./http-json.js";

/** How many feed items one run keeps. */
export const MAX_FEED_ITEMS = 500;

/** The most characters one text field of one item may hold. */
const FIELD_MAX = 2000;

/** The XML parser, imported on first use. */
let domParserModule = null;

async function loadDomParser() {
  if (!domParserModule) domParserModule = import("linkedom");
  return (await domParserModule).DOMParser;
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  for (const key of Object.keys(settings)) {
    if (key !== "url") errors.push(key);
  }
  if (!httpUrlOf(settings.url)) errors.push("url");
  return errors;
}

/** Cut a value to `max` characters, never through a surrogate pair. */
function cut(value, max) {
  if (value.length <= max) return value;
  let end = max;
  const last = value.charCodeAt(end - 1);
  if (last >= 0xd800 && last <= 0xdbff) end -= 1;
  return value.slice(0, end);
}

/**
 * A field's text with its markup removed, once: the parser has already decoded the document's
 * character references, and a second decode would turn a body's own `&lt;script&gt;` text into a tag.
 */
function stripTags(value) {
  const raw = text(value);
  if (!raw) return "";
  const withoutBlocks = raw
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, " ")
    .replace(/<[^>]*>/g, " ");
  return cut(withoutBlocks.replace(/\s+/g, " ").trim(), FIELD_MAX);
}

/** A link as the item may carry it: an absolute http(s) URL, or "" for anything else. */
function safeLink(value) {
  const candidate = text(value).trim();
  if (!candidate) return "";
  return httpUrlOf(candidate) ? candidate : "";
}

/** The lower-case local name of an element, with any namespace prefix dropped (`dc:date` -> `date`). */
function localNameOf(node) {
  const name = text(node?.localName || node?.nodeName);
  const colon = name.indexOf(":");
  return (colon >= 0 ? name.slice(colon + 1) : name).toLowerCase();
}

/** The child elements of `node` whose local name is one of `names`. */
function childrenNamed(node, names) {
  const wanted = new Set(names.map((name) => name.toLowerCase()));
  const out = [];
  const children = node?.childNodes;
  if (!children) return out;
  for (let i = 0; i < children.length; i += 1) {
    const child = children[i];
    if (child?.nodeType !== 1) continue;
    if (wanted.has(localNameOf(child))) out.push(child);
  }
  return out;
}

/** The text of the first child element with one of `names`, or "". */
function childText(node, names) {
  const [first] = childrenNamed(node, names);
  return first ? text(first.textContent).trim() : "";
}

/** An Atom `link`: the `rel="alternate"` one when there is one, else the first one with an href. */
function atomLink(entry) {
  const links = childrenNamed(entry, ["link"]);
  const alternate = links.find((link) => text(link.getAttribute("rel")).toLowerCase() === "alternate");
  const chosen = alternate || links.find((link) => text(link.getAttribute("href")));
  if (chosen) return text(chosen.getAttribute("href")).trim();
  return links.length ? text(links[0].textContent).trim() : "";
}

function rssItem(node) {
  return {
    title: cut(childText(node, ["title"]), FIELD_MAX),
    link: safeLink(childText(node, ["link"])),
    published: cut(childText(node, ["pubdate", "published", "date", "updated"]), FIELD_MAX),
    summary: stripTags(childText(node, ["description", "summary", "encoded", "content"])),
  };
}

function atomItem(node) {
  return {
    title: cut(childText(node, ["title"]), FIELD_MAX),
    link: safeLink(atomLink(node)),
    published: cut(childText(node, ["published", "updated"]), FIELD_MAX),
    summary: stripTags(childText(node, ["summary", "content"])),
  };
}

/**
 * The items of a feed document, or null when the document is not an RSS or Atom feed. Never throws: a
 * parser that fails on garbage is `null`, which the block answers as `bad_response`.
 */
function parseFeed(xml, Parser) {
  if (typeof xml !== "string" || !xml.trim()) return null;
  let document;
  try {
    document = new Parser().parseFromString(xml, "text/xml");
  } catch {
    return null;
  }
  const root = document?.documentElement;
  if (!root) return null;
  const rootName = localNameOf(root);
  if (rootName === "rss" || rootName === "rdf") {
    return Array.from(document.getElementsByTagName("item")).map(rssItem);
  }
  if (rootName === "feed") {
    return Array.from(document.getElementsByTagName("entry")).map(atomItem);
  }
  return null;
}

async function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const refuse = (code) => ({ sourceError: { message: redactWith(code, []) } });

  const url = httpUrlOf(settings.url);
  if (!url) return refuse("bad_settings");

  // The host is checked before anything reaches the network, and the same list narrows every hop.
  const hostOk = await approvedHostRule(ctx);
  if (!hostOk(url)) return refuse("host_unapproved");

  let response;
  try {
    response = await fetchSourceBytes(ctx, url.href, {
      accept: "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.5",
      onHop: (hop) => hostOk(hop),
    });
  } catch (err) {
    return refuse(fetchErrorCode(err));
  }

  const status = Number(response?.http_status);
  if (!Number.isFinite(status) || status < 200 || status >= 300) return refuse("http_error");

  // The host the feed really came from, after any redirect it followed.
  const finalUrl = httpUrlOf(text(response?.final_url));
  if (!finalUrl || !(await sourceHostApproved(ctx, finalUrl))) return refuse("host_unapproved");

  const items = parseFeed(bodyTextOf(response), await loadDomParser());
  if (!items) return refuse("bad_response");
  return { items: items.slice(0, MAX_FEED_ITEMS) };
}

export const rssBlock = Object.freeze({
  type: "rss",
  kind: "source",
  sourceBearing: true,
  validate,
  run,
});