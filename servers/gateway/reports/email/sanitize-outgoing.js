/**
 * What one report email may carry out of Crow: an allow-list sanitiser for the html, and one rule for
 * every link.
 *
 * THE HTML is cleaned by sanitize-html with an allow-list, never a deny-list: a tag, an attribute or a
 * URL scheme that is not named in `options()` below does not come out the other side. There is no
 * `style` attribute and no `<style>`/`<link>` element at all, so a stylesheet import and a `url()` in a
 * style cannot survive; every `on*` handler is gone because no attribute outside the allow-list
 * survives; a `script`, `style`, `form`, `iframe`, `object`, `embed`, an SVG or MathML island and every
 * other non-content element is dropped WITH its contents (`nonTextTags`).
 *
 * THE ONE IMAGE a report email may carry is an inline base64 png, jpeg or gif. An `<img>` whose `src`
 * is anything else — every http(s) image, a protocol-relative one, a non-image `data:` URL, an empty
 * src — is removed whole by `exclusiveFilter`, because a remote image in an email is a request the
 * reader's mail client makes to a host the report never named (a tracking pixel).
 *
 * THE RULE, FOR EMAILS ONLY: any web address in an outgoing report email that is not on the report's
 * allowed list is replaced outright by `[link removed]` (copy.js's EMAIL_LINK_REMOVED). NO HOST IS SHOWN.
 * A web address is a run that starts with `http://`, `https://` (in any case) or `www.` and continues
 * until whitespace, `<`, `>`, a quote or a backtick, minus the punctuation a sentence leaves on its end
 * (`. , ; : ! ? ) ] }`), which stays in the text after the replacement. The run is allowed only when it
 * is verbatim one of the allowed URLs, which is the set of URLs the run's own items carry. The in-Crow
 * document render (neutralize-links.js) is a different path and still names a refused host; this module
 * is the mail path only and does not call it.
 *
 * A MARKER IS NEVER A TRUST SIGNAL. Nothing that looks like `[link removed: ...]` or `[link removed]` in
 * the input is skipped, rewritten or read as one: the text is scanned left to right and EVERY refused run
 * is replaced, so a fake marker becomes a marker inside a marker (`[link removed: [link removed]]`) and
 * the address inside it is gone either way.
 *
 * A URL THAT IS PLAIN TEXT IN THE HTML is judged too: a mail client autolinks a bare `http(s)://...` or
 * `www.` run in a body, so text is a way to a host just as an anchor is. The run is matched ANYWHERE in
 * the text, whatever leads up to it: a client autolinks `x.https://host`, `a//https://host`,
 * `me@www.host` and `abchttps://host` just the same, so the character before a run is never a reason to
 * let it through. That is the fail-closed side of it: a marker over an address the reader could have
 * typed costs a line, a live link the report never offered costs the click.
 *
 * INVISIBLE CHARACTERS AND CHARACTER REFERENCES ARE NOT PART OF A WORD to a reader of html, so they are
 * not part of one to this pass either: the html's text is judged through `normalizeView`
 * (normalize-text.js), which decodes the character references (with any number of leading zeros, and the
 * named references it lists) that write a character nobody sees, and removes the whole Unicode invisible
 * and format class (a zero-width space or joiner, the word joiner, a byte order mark, a soft hyphen, a
 * variation selector, a tag character, the Hangul filler) and every control character. So
 * `ht<U+200B>tps://host` and `https://evil<U+00AD>.host` are read as the one run a mail client draws.
 * The map back from that view keeps every character outside a refused run exactly as it was written; the
 * invisible characters INSIDE the run go with it. A text with no URL in it is left exactly as it was.
 *
 * AN ANCHOR IS JUDGED BY ITS HREF. A `mailto:` link is judged like an http(s) one (`http`, `https` and
 * `mailto` are the only schemes the sanitiser keeps for an anchor, so `javascript:`, `vbscript:` and
 * `data:` hrefs are already gone by then, their text left behind). An anchor whose href is in the allowed
 * set is kept exactly as it came; EVERY OTHER anchor that has an href is replaced whole — its words, its
 * tags and its href — by `[link removed]`, because a reader must not see a click that leads nowhere the
 * report offered. An anchor with no href at all is not a link: its tag goes and its text stays.
 *
 * AN ALLOWED ANCHOR MUST NOT SHOW ANOTHER URL. An anchor kept because its `href` is in the allowed set can
 * still read as a link to somewhere else: `<a href="https://ok.example/">https://evil.example/x</a>` is
 * a click that looks like a different destination. So the visible text of a kept anchor is read too: when
 * it carries a URL run that is not verbatim the anchor's own href, the anchor's words are replaced by the
 * href itself, markup and all, because the words and the destination must not disagree. Text with no such
 * run (`Open the listing`) is left alone, and so is an anchor whose text is its own URL.
 *
 * AN IMAGE CARRIES NO FREE TEXT, AND NO SIZE IT DID NOT WRITE AS A NUMBER. `alt` and `title` are not in
 * `OUTGOING_ALLOWED_ATTRIBUTES` for `img` at all, so an email carries no image description and no image
 * attribute whose value is words a reader reads; there is nothing on an image to judge as text. The two
 * attributes an image may carry besides its `src` — `width` and `height` — are kept only as plain
 * integers (digits only, one to four of them, 1..4000) and dropped otherwise, so a value can never carry
 * a unit or a second attribute into the mail. `colspan` and `rowspan` on a cell follow the same rule
 * (1..100). Every attribute is decided by the parser over the parsed values (`transformTags`), never by a
 * regular expression over the serialised tag: an unquoted value, a quote inside another attribute's value
 * or any tag shape can never make this module edit text it did not parse as that attribute.
 *
 * JOINED TEXT: a reader's mail client reads the rendered line, not one text node at a time, so
 * `ht<b></b>tps://host` and `https://ev<i>il</i>.host` are a link there while no single text node in them
 * names a URL. A block element (p, div, td, th, li, blockquote, h1-h4, pre, and the document root) whose
 * rendered text carries a URL run that only becomes whole once the markup between its text nodes is
 * dropped is therefore FLATTENED: every inline element inside it (an anchor, a span, b, i, u, em, strong,
 * code, an image, any other inline tag) is replaced by its text, a `br` stays a line break, and the
 * flattened line is judged as text. A block in which every URL run lies inside one text node is left
 * exactly as it was, so formatting is kept wherever nothing was split. The joined line is read with the
 * invisible characters removed too (see above), so a run split by markup and hidden in the same way is
 * still one run to this pass. An allowed anchor in such a block still works; the same words inside a
 * flattened block are text, judged the way any text is. This pass fails closed: html it cannot read (a
 * closing tag with no opening tag) and a run still split after flattening both answer "".
 *
 * THE TEXT PART IS JUDGED EXACTLY AS IT IS SENT. A plain-text client decodes no character reference and
 * joins nothing, so that half is stripped of the characters nobody sees (`stripInvisible`:
 * normalize-text.js — control characters with `\n`, `\r` and `\t` kept, and the default-ignorable and
 * format class) and every refused run in the SAME stripped text is replaced by `[link removed]`. That is
 * what `neutralizeTextRuns` is, and what the layout runs over its final body: no decoding, no markdown
 * joining, so `https&#x3A;//host` stays the literal text it is and is not a URL to this pass at all.
 *
 * Nothing here throws: a missing part is "", and a part this module cannot clean is dropped rather
 * than passed through.
 */
import sanitize from "sanitize-html";
import { EMAIL_LINK_REMOVED } from "./copy.js";
import { normalizeForLinkCheck, normalizeView, stripInvisible } from "./normalize-text.js";

/** The tags an outgoing report email may carry. Anything else is dropped. */
export const OUTGOING_ALLOWED_TAGS = Object.freeze([
  "a", "b", "blockquote", "br", "code", "div", "em",
  "h1", "h2", "h3", "h4", "hr",
  "i", "img", "li", "ol", "p", "pre", "span", "strong",
  "table", "tbody", "td", "th", "thead", "tr", "u", "ul",
]);

/** Per tag, the only attributes that survive. There is no `style` and no `class` anywhere. */
export const OUTGOING_ALLOWED_ATTRIBUTES = Object.freeze({
  a: Object.freeze(["href"]),
  img: Object.freeze(["src", "width", "height"]),
  td: Object.freeze(["colspan", "rowspan"]),
  th: Object.freeze(["colspan", "rowspan"]),
});

/**
 * Elements that are not content: dropped together with everything inside them. sanitize-html's own list
 * is script/style/textarea/option; the rest are active content or a document-level element an email body
 * has no use for, and dropping their contents is what keeps a nested tag from reopening itself.
 */
const NON_TEXT_TAGS = Object.freeze([
  "script", "style", "textarea", "option", "title", "xmp", "plaintext", "noembed", "noframes",
  "iframe", "frame", "frameset", "object", "embed", "applet", "form", "select", "button",
  "svg", "math", "link", "meta", "base", "noscript", "template", "video", "audio", "source",
]);

/** The only image source an email may carry: an inline base64 png, jpeg or gif. */
const DATA_IMAGE = /^data:image\/(?:png|jpeg|gif);base64,[A-Za-z0-9+/]+={0,2}$/i;

/** Is this `src` the one image an email may carry? */
function isAllowedImageSrc(src) {
  return typeof src === "string" && DATA_IMAGE.test(src);
}

/** A plain integer as an attribute may carry one: digits only, no sign, no unit, no second word. */
const PLAIN_INTEGER = /^[0-9]+$/;

/** The longest a plain integer may be written; the whole accepted range is at most four digits. */
const PLAIN_INTEGER_MAX_DIGITS = 4;

/**
 * One parsed attribute kept only when it is a plain integer in `min..max`; a unit, a sign, an exponent, a
 * second word or a longer number means the attribute is dropped. The value the parser read is what is
 * judged and written back, so nothing is ever rewritten over the serialised tag.
 */
function keepPlainInteger(attribs, name, min, max) {
  if (!Object.hasOwn(attribs, name)) return;
  const value = attribs[name];
  if (typeof value !== "string" || value.length > PLAIN_INTEGER_MAX_DIGITS || !PLAIN_INTEGER.test(value)) {
    delete attribs[name];
    return;
  }
  const number = Number(value);
  if (number < min || number > max) delete attribs[name];
}

/** A `transformTags` entry keeping only the named attributes whose parsed value is a plain integer. */
function plainIntegers(limits) {
  return (tagName, attribs) => {
    const kept = { ...attribs };
    for (const [name, [min, max]] of Object.entries(limits)) keepPlainInteger(kept, name, min, max);
    return { tagName, attribs: kept };
  };
}

/** The sanitiser's options for one call, built fresh so no call can see another's state. */
function options() {
  return {
    allowedTags: [...OUTGOING_ALLOWED_TAGS],
    allowedAttributes: {
      a: [...OUTGOING_ALLOWED_ATTRIBUTES.a],
      img: [...OUTGOING_ALLOWED_ATTRIBUTES.img],
      td: [...OUTGOING_ALLOWED_ATTRIBUTES.td],
      th: [...OUTGOING_ALLOWED_ATTRIBUTES.th],
    },
    allowedSchemes: ["http", "https", "mailto"],
    // `data:` is allowed for an image only; `exclusiveFilter` below keeps just the three image types,
    // so a non-image data URL and every http(s) image are removed with the tag.
    allowedSchemesByTag: { img: ["data"] },
    allowedSchemesAppliedToAttributes: ["href", "src"],
    allowProtocolRelative: false,
    disallowedTagsMode: "discard",
    nonTextTags: [...NON_TEXT_TAGS],
    // A `style` attribute can never be kept, so the CSS is never parsed.
    parseStyleAttributes: false,
    selfClosing: ["img", "br", "hr"],
    // A width, a height, a colspan or a rowspan survives only as the plain integer it was parsed as. The
    // free-text attributes (`alt`, `title`) are simply not kept for an image, so nothing on a tag is words.
    transformTags: {
      img: plainIntegers({ width: [1, 4000], height: [1, 4000] }),
      td: plainIntegers({ colspan: [1, 100], rowspan: [1, 100] }),
      th: plainIntegers({ colspan: [1, 100], rowspan: [1, 100] }),
    },
    exclusiveFilter: (frame) => frame.tag === "img" && !isAllowedImageSrc(frame.attribs.src),
  };
}

/**
 * One html document (or fragment) with everything the allow-list does not name removed.
 *
 * @param {*} html untrusted html
 * @returns {string} the cleaned html, or "" when it is not a string or cannot be cleaned
 */
export function sanitizeHtml(html) {
  const source = typeof html === "string" ? html : "";
  if (!source) return "";
  try {
    return sanitize(source, options());
  } catch {
    // A sanitiser that fails vouches for nothing, so the part is dropped rather than passed through.
    return "";
  }
}

/** Text for display: the characters that would otherwise start markup or end an attribute. */
function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * A web address run: the two schemes a mail client autolinks, and a bare `www.` host, matched ANYWHERE in
 * the text. Whatever leads up to the run (`.`, `/`, `@`, `:`, `-`, a letter, a digit, an `_`, a letter of
 * any script) is the reader's own text and is kept, because a mail client autolinks the run after it just
 * the same; the run itself stops at whitespace, markup, a quote or a backtick.
 */
const TEXT_URL = /https?:\/\/[^\s<>"'`]+|www\.[^\s<>"'`]+/gi;

/** Punctuation a sentence leaves on the end of a URL, which is not part of it. */
const TRAILING_PUNCTUATION = /[.,;:!?)\]}]+$/;

/**
 * Every web address run in this text, in order, as offsets into it: `url` is the run with the punctuation
 * a sentence leaves on its end taken off (that punctuation stays in the text).
 */
function urlRuns(text) {
  const source = typeof text === "string" ? text : "";
  const runs = [];
  const pattern = new RegExp(TEXT_URL.source, "gi");
  let match;
  while ((match = pattern.exec(source)) !== null) {
    if (!match[0]) {
      pattern.lastIndex += 1;
      continue;
    }
    const trailing = (TRAILING_PUNCTUATION.exec(match[0]) || [""])[0];
    const url = trailing ? match[0].slice(0, -trailing.length) : match[0];
    if (!url) continue;
    runs.push({ url, start: match.index, end: match.index + url.length });
  }
  return runs;
}

/** Every run in this text that is not verbatim one of the allowed URLs. */
function refusedRuns(text, allowed) {
  return urlRuns(text).filter((run) => !allowed.has(run.url));
}

/**
 * Every refused run in this text replaced by `[link removed]`, the text around it left exactly as it was
 * written. The text is read the way a mail client draws it (`normalizeView`: references decoded, the
 * invisible and format classes and every control character removed), and every offset is mapped back, so a
 * refusal costs the run and nothing else.
 */
function replaceRefusedRuns(source, allowed) {
  const text = typeof source === "string" ? source : "";
  if (!text) return "";
  const view = normalizeView(text);
  let out = "";
  let cursor = 0;
  for (const run of refusedRuns(view.text, allowed)) {
    const start = view.at[run.start].from;
    const end = view.at[run.end - 1].to;
    out += text.slice(cursor, start) + EMAIL_LINK_REMOVED;
    cursor = end;
  }
  return out + text.slice(cursor);
}

/** One html text node with every refused run replaced by `[link removed]` (see replaceRefusedRuns). */
function neutralizeTextUrls(source, allowed) {
  return replaceRefusedRuns(source, allowed);
}

/**
 * This plain text as it is judged AND as it is sent: the characters nobody sees stripped first
 * (`stripInvisible`), then every refused run in that same stripped text replaced by `[link removed]`.
 * Nothing is decoded and nothing is joined, because a plain-text client does neither.
 */
function neutralizePlainText(source, allowed) {
  const text = stripInvisible(typeof source === "string" ? source : "");
  if (!text) return "";
  let out = "";
  let cursor = 0;
  for (const run of refusedRuns(text, allowed)) {
    out += text.slice(cursor, run.start) + EMAIL_LINK_REMOVED;
    cursor = run.end;
  }
  return out + text.slice(cursor);
}

/**
 * Does this kept anchor's own visible text name a web address other than its href? The text is read the
 * way any text is (the character references put back, the invisible class looked through, punctuation off
 * the end), so `https://evil&#46;example/x` is the URL it draws. A run that is not verbatim the href
 * means the words and the destination disagree.
 */
function namesAnotherUrl(text, href) {
  for (const run of urlRuns(normalizeView(decodeEntities(text)).text)) if (run.url !== href) return true;
  return false;
}

/** The caller's allowed set. A Set or an array is read entry by entry; anything else allows nothing. */
function toAllowedSet(allowedUrls) {
  const set = new Set();
  if (allowedUrls == null || typeof allowedUrls === "string") return set;
  if (typeof allowedUrls[Symbol.iterator] !== "function") return set;
  for (const url of allowedUrls) if (typeof url === "string") set.add(url);
  return set;
}

const ENTITY = /&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|([a-zA-Z][a-zA-Z0-9]{1,9}));/g;
const NAMED_ENTITIES = Object.freeze({ amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00a0" });

/**
 * The value an attribute had before the sanitiser escaped it, so it can be compared with the run's
 * allowed URLs verbatim: sanitize-html writes `&` as `&amp;` and `"` as `&quot;`, and the allowed set
 * holds the URL as the run's items wrote it.
 */
function decodeEntities(value) {
  return String(value).replace(ENTITY, (whole, dec, hex, name) => {
    const code = dec != null ? Number(dec) : hex != null ? Number.parseInt(hex, 16) : -1;
    if (code >= 0) {
      try {
        return String.fromCodePoint(code);
      } catch {
        return "";
      }
    }
    return Object.hasOwn(NAMED_ENTITIES, name) ? NAMED_ENTITIES[name] : whole;
  });
}

/* ------------------------------------------------------------------ joined text */

/**
 * The block elements whose rendered text is judged as one line. Inline markup inside one of these is what
 * can split a URL in the reader's eyes, so these are the elements flattened when it does.
 */
const BLOCK_TAGS = new Set([
  "blockquote", "div", "h1", "h2", "h3", "h4", "li", "ol", "p", "pre", "table", "tbody", "td",
  "th", "thead", "tr", "ul",
]);

/** The elements the sanitiser writes without a closing tag. */
const VOID_TAGS = new Set(["br", "hr", "img"]);

/** One tag in html this module already cleaned: every attribute value it writes is quoted. */
const TAG_SOURCE = `<(/?)([a-zA-Z][a-zA-Z0-9]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>`;

/**
 * This html as a tree of text and element nodes, or null when it is not one this module can read (a
 * closing tag with no opening tag, a tag left open at the end). The sanitiser writes every open element's
 * closing tag and escapes every text node, and a `>` inside an attribute value sits inside its quotes.
 */
function parseNodes(source) {
  const tag = new RegExp(TAG_SOURCE, "g");
  const root = [];
  const stack = [{ name: "#root", children: root }];
  let index = 0;
  let match;
  while ((match = tag.exec(source)) !== null) {
    const raw = match[0];
    const name = match[2].toLowerCase();
    if (match.index > index) {
      stack[stack.length - 1].children.push({ type: "text", value: source.slice(index, match.index) });
    }
    index = match.index + raw.length;
    if (match[1] === "/") {
      if (stack.length < 2 || stack[stack.length - 1].name !== name) return null;
      stack.pop();
      continue;
    }
    const selfClosing = /\/\s*>$/.test(raw) || VOID_TAGS.has(name);
    const node = { type: "element", name, open: raw, selfClosing, children: [] };
    stack[stack.length - 1].children.push(node);
    if (!selfClosing) stack.push(node);
  }
  if (index < source.length) {
    stack[stack.length - 1].children.push({ type: "text", value: source.slice(index) });
  }
  return stack.length === 1 ? root : null;
}

/** A run of rendered text: one piece per text node, and for each gap whether a client may join across it. */
function newLayout() {
  return { html: "", pieces: [], joinable: [], nextJoinable: null };
}

/** The next piece of rendered text, on the far side of markup a client may or may not join across. */
function addPiece(layout, text, joinable) {
  if (!text) return;
  if (layout.pieces.length > 0) {
    layout.joinable.push(layout.nextJoinable === null ? joinable === true : layout.nextJoinable);
  }
  layout.pieces.push(text);
  layout.nextJoinable = null;
}

/** Another layout's text appended after this one's, the gap between the two as `joinable` says. */
function appendLayout(layout, child, joinable) {
  for (let index = 0; index < child.pieces.length; index += 1) {
    const gap = index === 0 ? joinable === true : child.joinable[index - 1] === true;
    addPiece(layout, child.pieces[index], gap);
  }
  if (child.pieces.length === 0 && joinable === false) layout.nextJoinable = false;
}

/** The same text with every gap a client may join made one piece: the text nodes it reads as one line. */
function coalesceJoinable(layout) {
  const out = { html: layout.html, pieces: [], joinable: [], nextJoinable: layout.nextJoinable };
  for (let index = 0; index < layout.pieces.length; index += 1) {
    if (index > 0 && layout.joinable[index - 1] === true) {
      out.pieces[out.pieces.length - 1] += layout.pieces[index];
      continue;
    }
    if (out.pieces.length > 0) out.joinable.push(false);
    out.pieces.push(layout.pieces[index]);
  }
  return out;
}

/**
 * Does a URL run in this rendered text only become whole once the markup between two of its pieces is
 * dropped? Such a run is one a mail client could autolink while a judge reading one text node at a time
 * saw no URL at all. The pieces are read as a reader sees them (the invisible characters removed), so a
 * run hidden behind markup and an invisible character both at once is one run here too.
 */
function hasJoinableSplit(layout) {
  if (layout.pieces.length < 2) return false;
  let text = "";
  const boundaries = [];
  for (let index = 0; index < layout.pieces.length; index += 1) {
    text += normalizeForLinkCheck(layout.pieces[index]);
    if (layout.joinable[index] === true) boundaries.push(text.length);
  }
  if (boundaries.length === 0) return false;
  const run = new RegExp(TEXT_URL.source, "gi");
  let match;
  while ((match = run.exec(text)) !== null) {
    if (!match[0]) {
      run.lastIndex += 1;
      continue;
    }
    const start = match.index;
    const end = start + match[0].length;
    for (const at of boundaries) if (at > start && at < end) return true;
  }
  return false;
}

/** One element's content: flattened when a URL in it is only whole once inline markup is dropped. */
function contentOf(node, flattenMode) {
  if (node.children.length === 0) return newLayout();
  if (flattenMode) return coalesceJoinable(renderNodes(node.children, true));
  const plain = renderNodes(node.children, false);
  if (!hasJoinableSplit(plain)) return plain;
  return coalesceJoinable(renderNodes(node.children, true));
}

/**
 * One run of sibling nodes rendered, with the text it shows in the order a reader meets it. With
 * `flattenMode` every inline element is replaced by its text and a `br` stays a line break, which is what
 * a flattened block is.
 */
function renderNodes(nodes, flattenMode) {
  const layout = newLayout();
  for (const node of nodes) {
    if (node.type === "text") {
      layout.html += node.value;
      addPiece(layout, node.value, true);
      continue;
    }
    const content = contentOf(node, flattenMode);
    if (node.name === "br") {
      layout.html += node.open;
      layout.nextJoinable = false;
      continue;
    }
    const closing = node.selfClosing ? "" : `</${node.name}>`;
    if (BLOCK_TAGS.has(node.name)) {
      layout.nextJoinable = false;
      layout.html += node.open + content.html + closing;
      appendLayout(layout, content, false);
      layout.nextJoinable = false;
      continue;
    }
    // An inline element: kept as it is, or, in a block that is being flattened, replaced by its text.
    layout.html += flattenMode ? content.html : node.open + content.html + closing;
    appendLayout(layout, content, true);
    if (layout.nextJoinable === null) layout.nextJoinable = true;
  }
  return layout;
}

/**
 * The text of one html in the order a reader meets it, with the gaps a mail client would join marked: true
 * where only inline markup sits between two text nodes, false where a block or a break does. Used as the
 * backstop, so it reads the tree exactly as it is and never flattens anything itself.
 */
function readingText(nodes, layout) {
  for (const node of nodes) {
    if (node.type === "text") {
      addPiece(layout, node.value, true);
      continue;
    }
    if (node.name === "br") {
      layout.nextJoinable = false;
      continue;
    }
    if (VOID_TAGS.has(node.name)) continue;
    if (BLOCK_TAGS.has(node.name)) {
      layout.nextJoinable = false;
      readingText(node.children, layout);
      layout.nextJoinable = false;
      continue;
    }
    readingText(node.children, layout);
  }
  return layout;
}

/** An anchor's opening tag as the sanitiser writes one; its attributes are escaped, so it holds no `>`. */
const ANCHOR_OPEN = /^<a(?=[\s/>])/i;
/** An anchor's closing tag. */
const ANCHOR_CLOSE = /^<\/a[\s>]/i;
/** The href value in a tag the sanitiser wrote: always double-quoted, never holding a raw `>`. */
const HREF_ATTRIBUTE = /(?:^|\s)href\s*=\s*"([^"]*)"/i;

/**
 * Every `<a>` in this html judged against the allowed set, and every plain-text URL outside a kept
 * anchor judged with it. A kept link is written back exactly as it came; an anchor whose href is refused
 * is replaced whole — words, href and tags — by `[link removed]`; an anchor with no href is not a link,
 * so its tag goes and its words stay. The walk is over tags, not over a regular expression: the html it
 * reads is sanitizeHtml's own output, where every attribute value and every text node is escaped (no raw
 * `<` or `>` inside one) and every non-void element has its own closing tag, so a stack of the anchors
 * still open is the whole nesting story. The words of a kept anchor are collected as the walk passes them,
 * and at the closing tag an anchor whose words name another URL is written back showing its own href
 * instead (see AN ALLOWED ANCHOR MUST NOT SHOW ANOTHER URL in the header), so the click and the words
 * always agree.
 */
function rewriteAnchors(source, allowed) {
  let out = "";
  let index = 0;
  const open = [];
  /** The text between two tags: the visible words of a kept anchor are judged at its close, everything
   *  else here. */
  const textPart = (slice) => {
    const anchor = open.length > 0 ? open[open.length - 1] : null;
    if (anchor === null || !anchor.kept) return neutralizeTextUrls(slice, allowed);
    anchor.text += slice;
    return slice;
  };
  while (index < source.length) {
    const start = source.indexOf("<", index);
    if (start < 0) {
      out += textPart(source.slice(index));
      break;
    }
    out += textPart(source.slice(index, start));
    const end = source.indexOf(">", start);
    if (end < 0) {
      out += source.slice(start);
      break;
    }
    const tag = source.slice(start, end + 1);
    if (ANCHOR_CLOSE.test(tag)) {
      const anchor = open.pop();
      if (anchor === undefined) {
        // A closer with no opener is not a link: the tag goes and the text between stays.
      } else if (anchor.kept) {
        // The words and the destination must agree: an anchor whose words name another URL shows its own
        // href instead, markup and all, so nothing it said can pass for a way somewhere else.
        out = namesAnotherUrl(anchor.text, anchor.href)
          ? out.slice(0, anchor.at) + escapeHtml(anchor.href) + tag
          : out + tag;
      } else if (anchor.marker) {
        // A refused anchor goes whole: its words, its href and both of its tags are one refusal.
        out = out.slice(0, anchor.at) + anchor.marker;
      } else {
        // No destination: not a link, so both tags go and the words stay, with no refusal at all.
      }
      index = end + 1;
      continue;
    }
    if (ANCHOR_OPEN.test(tag)) {
      const match = HREF_ATTRIBUTE.exec(tag);
      const written = match ? match[1] : "";
      const href = decodeEntities(written);
      if (!href.trim()) {
        open.push({ kept: false, marker: "", at: out.length });
      } else if (allowed.has(href) || allowed.has(written)) {
        out += tag;
        open.push({ kept: true, href, at: out.length, text: "" });
      } else {
        open.push({ kept: false, marker: EMAIL_LINK_REMOVED, at: out.length });
      }
      index = end + 1;
      continue;
    }
    // Every other tag is kept exactly as the sanitiser wrote it: its attributes were already decided by
    // the allow-list over the parsed values, so there is no free-text value left to judge here.
    out += tag;
    index = end + 1;
  }
  // An anchor the sanitiser left unclosed still gets its refusal, so nothing is ever silent.
  for (let at = open.length - 1; at >= 0; at -= 1) {
    const anchor = open[at];
    if (anchor.kept || !anchor.marker) continue;
    out = out.slice(0, anchor.at) + anchor.marker;
  }
  return out;
}

/**
 * This html with every anchor and every plain-text web address judged: a link survives only when its href
 * is in `allowedUrls` verbatim (http(s) or a `mailto:` written there), a bare `http(s)://` or `www.` run in
 * a text node survives only when it is in that set too, and every other one is replaced by
 * `[link removed]`. A URL that is only whole once inline markup between two text nodes is dropped is
 * judged on the flattened block (see JOINED TEXT above), so the reader's own mail client cannot join what
 * this module read separately.
 *
 * @param {*} html html that has already been through sanitizeHtml
 * @param {string[]|Set<string>} [allowedUrls] the URLs the run's own items carry
 * @returns {string} the html, or "" when this module cannot read it
 */
export function neutralizeHtmlLinks(html, allowedUrls) {
  const source = typeof html === "string" ? html : "";
  if (!source) return "";
  try {
    const allowed = toAllowedSet(allowedUrls);
    const nodes = parseNodes(source);
    if (nodes === null) return "";
    const flattened = contentOf({ children: nodes }, false);
    // The backstop reads the html that is about to be judged: a run a client could join across the markup
    // left in it would slip past a judge that reads one text node at a time, so it is not passed on.
    const check = parseNodes(flattened.html);
    if (check === null) return "";
    if (hasJoinableSplit(readingText(check, newLayout()))) return "";
    return rewriteAnchors(flattened.html, allowed);
  } catch {
    // Fails closed: an html body with links this module could not judge is dropped, never passed on.
    return "";
  }
}

/**
 * One outgoing email body: the html cleaned and its links judged, the plain text stripped and judged.
 *
 * @param {{html?: string, text?: string}|null|undefined} parts the body's two halves
 * @param {string[]|Set<string>} [allowedUrls] the URLs the run's own items carry
 * @returns {{html: string, text: string}} a missing or unreadable half is ""
 */
export function sanitizeOutgoing(parts, allowedUrls) {
  const source = parts != null && typeof parts === "object" ? parts : {};
  const allowed = toAllowedSet(allowedUrls);
  let html = "";
  let text = "";
  try {
    html = neutralizeHtmlLinks(sanitizeHtml(source.html), allowed);
  } catch {
    html = "";
  }
  try {
    // The text half is judged exactly as it is sent: stripped of the characters nobody sees, then every
    // refused run replaced. Nothing is decoded, because a plain-text client decodes nothing.
    text = neutralizePlainText(source.text, allowed);
  } catch {
    text = "";
  }
  return { html, text };
}

/**
 * The FINAL plain-text half of a mail judged exactly as a plain-text client receives it: the control and
 * invisible characters stripped (with `\n`, `\r` and `\t` kept) and every `http(s)://` and `www.` run in
 * the SAME stripped text, unless that exact URL is in `allowedUrls`, replaced by `[link removed]`. Nothing
 * is decoded and nothing is joined, so a character reference is the literal text it is. The layout runs
 * this over the finished body text, before its own footer goes on. It never throws: a text that cannot be
 * judged answers "", because a mail body with a link this module could not read is not sent.
 *
 * @param {*} text the plain-text body as it stands
 * @param {string[]|Set<string>} [allowedUrls] the URLs the run's own items carry
 * @returns {string} the text with every refused run become `[link removed]`
 */
export function neutralizeTextRuns(text, allowedUrls) {
  const source = typeof text === "string" ? text : "";
  if (!source) return "";
  try {
    return neutralizePlainText(source, toAllowedSet(allowedUrls));
  } catch {
    return "";
  }
}