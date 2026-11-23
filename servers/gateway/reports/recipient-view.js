/**
 * The recipient view: one stored document version, made safe and self-contained for a reader with no
 * Crow account, plus that reader's comment thread underneath it.
 *
 * WHY SELF-CONTAINED: a recipient page is opened from a mail, so it is the ONE page that leaves this
 * instance's dashboard. It must not make a single request back to Crow for content: every picture is
 * inlined as a `data:` URI, every stylesheet is written into the document, and no script is emitted at
 * all. Nothing about the owner's instance (an asset path, a storage host, a session) is part of the page
 * a reader receives. The page also carries `referrer: no-referrer`, so a link a reader follows learns
 * nothing about where they came from.
 *
 * WHY THE LINKS ARE REBUILT RATHER THAN KEPT: the document renderer makes every external anchor inert
 * (`render.js` `inertLinks`: the href moves to `data-inert-href` and the URL becomes the title), because
 * inside the dashboard a live link would navigate the frame. A recipient view is not a frame: the click
 * is the point. A link becomes clickable again ONLY when its URL is one of the run's own items
 * (`allowedLinks`, recorded with the version by the artifact bridge), so a body a source wrote cannot
 * hand a reader a destination the report never offered. Every other inert anchor stays inert AND shows
 * its URL as plain text, so the reader can still see where it pointed, and can copy it if they choose.
 *
 * WHY THE COMPARISON NORMALISES: `data-inert-href` holds the href as sanitize-html wrote it, so a query
 * string arrives as `&amp;` and a non-ASCII path arrives percent-encoded, while `allowedLinks` carries
 * the URL as the run recorded it. A raw string compare would fail for exactly the URLs a reader most
 * wants (a listing with a query). Both sides are therefore decoded and serialised through `new URL`, and
 * an unparsable URL never matches anything.
 *
 * WHY THE DEFENSIVE PASS RUNS ANYWAY: the stored page is written by the renderer, but a version's HTML is
 * still data that a report body helped shape, so this module does not trust it: it runs the transformed
 * body through sanitize-html with an allow-list built for this document shape, and then adds its own
 * comment form AFTER the pass (so reader-authored text and the form never travel through the same path
 * as document HTML). A tag, an attribute or a scheme the allow-list does not name is gone.
 *
 * WHY NO STORED STYLESHEET SURVIVES: keeping the CSS the renderer wrote into the version's head would
 * keep the page looking as the owner approved it, and an earlier version of this module did keep it
 * after filtering out `@import`, `url(` and `expression(`. That filter was a raw-text parser
 * differential: a `</style` variant, a CSS escape such as `\75 rl(` or `@\69mport`, or a `<` inside the
 * sheet can slip past a regex filter that a browser's CSS and HTML parsers read differently, and a
 * stored `style` attribute is a URL a reader's browser would fetch. Nothing stored is passed through
 * now: every `style` element and every `style` attribute in a stored page is dropped by the defensive
 * pass, and the only sheets a recipient page carries are constants in this repo's own code
 * (`RECIPIENT_DOC_CSS`, `SPEC_FIGURE_CSS`, `VIEW_CSS`).
 *
 * WHY THE CHART HAS A CEILING: a recipient page is one HTTP response, and an instance must not turn a
 * large rendered chart into a multi-megabyte reply a mail client will choke on. One asset over 1 MB, or
 * more than 6 MB of assets in one view, is replaced by the fixed plain line, and so is an asset that
 * cannot be read: a broken picture is never a broken page.
 *
 * NO SCRIPT, ANYWHERE: the output contains no `script` element, no `on*` attribute and no `javascript:`
 * URL, and a test pins that against hostile document HTML.
 */
import sanitize from "sanitize-html";
import { loadArtifactsRuntime } from "./artifact-bridge.js";
import { copyFor, RECIPIENT_COPY } from "./recipient-copy.js";

/** The most one inlined asset may weigh. */
export const MAX_ASSET_BYTES = 1_000_000;

/** The most all inlined assets of one view may weigh together. */
export const MAX_TOTAL_BYTES = 6_000_000;

/** The content types an inlined image may claim: an image, never a document or a script. */
const IMAGE_TYPE = /^image\/[a-z0-9][a-z0-9.+-]{0,60}$/i;

/** A `data:` image source this page will keep (what the inliner writes, and nothing else). */
const INLINE_IMAGE_SRC = /^data:image\/(?:png|jpeg|gif|webp|svg\+xml|avif);base64,[A-Za-z0-9+/]+={0,2}$/i;

/** The tags a rendered document (and this module's own note line) may carry. */
const ALLOWED_TAGS = Object.freeze([
  "a", "b", "blockquote", "br", "caption", "code", "dd", "del", "div", "dl", "dt", "em",
  "figcaption", "figure", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "li", "mark",
  "ol", "p", "pre", "s", "small", "span", "strong", "sub", "sup", "table", "tbody", "td",
  "tfoot", "th", "thead", "tr", "u", "ul",
]);

/** Per tag, the attributes that survive the defensive pass. No `style`, and so no `on*` either. */
const ALLOWED_ATTRIBUTES = Object.freeze({
  a: Object.freeze(["href", "target", "rel", "title", "data-inert-href"]),
  img: Object.freeze(["src", "alt", "width", "height"]),
  td: Object.freeze(["colspan", "rowspan"]),
  th: Object.freeze(["colspan", "rowspan"]),
  ol: Object.freeze(["start"]),
  div: Object.freeze(["id", "class"]),
  // `class` on a figure keeps the renderer's `figure.spec` chart shape addressable by
  // `SPEC_FIGURE_CSS`. It is the same kind of value `div`, `p` and `span` already may carry.
  figure: Object.freeze(["class"]),
  p: Object.freeze(["id", "class"]),
  span: Object.freeze(["class"]),
  code: Object.freeze(["class"]),
  pre: Object.freeze(["class"]),
  h1: Object.freeze(["id"]),
  h2: Object.freeze(["id"]),
  h3: Object.freeze(["id"]),
  h4: Object.freeze(["id"]),
  h5: Object.freeze(["id"]),
  h6: Object.freeze(["id"]),
});

/**
 * Elements dropped together with everything inside them: active content and document-level tags.
 *
 * `style` is here on purpose and is the whole answer to stored CSS: a version's own stylesheet is
 * discarded with its content instead of being filtered for dangerous constructs (see the header). The
 * sanitiser's `nonTextTags` handling is what makes the content of a raw-text element vanish rather than
 * reach the output as text, so a sheet holding a `</style` variant or a `<` leaves nothing behind.
 */
const NON_TEXT_TAGS = Object.freeze([
  "script", "style", "textarea", "option", "title", "xmp", "plaintext", "noembed", "noframes",
  "iframe", "frame", "frameset", "object", "embed", "applet", "form", "select", "button",
  "svg", "math", "link", "meta", "base", "noscript", "template", "video", "audio", "source",
]);

/**
 * The document stylesheet, copied character for character from `DOC_CSS` in
 * bundles/artifacts/server/render.js.
 *
 * WHY A COPY AND NOT AN IMPORT: the recipient view may not pass a STORED sheet through (see the header),
 * and it also may not import the bundle, because a bundle is installed at runtime and the installed copy
 * can be older than this file. The sheet it shows is therefore a constant of this repo's own code, and
 * the drift guard in `tests/reports-recipient-view.test.js` reads the renderer's source and fails when
 * the two stop matching, so a renderer CSS change forces this copy to be updated in the same commit.
 */
export const RECIPIENT_DOC_CSS = `body{font:16px/1.6 system-ui,sans-serif;max-width:46rem;margin:0 auto;padding:1.5rem;color:#1d1d1f;background:#fff}
@media (prefers-color-scheme:dark){body{color:#e8e8ea;background:#151517}}
.blk{scroll-margin-top:1rem}.blk:target{outline:2px solid #e2a03f;outline-offset:4px;border-radius:4px}
a[data-inert-href]{text-decoration:underline dotted;cursor:help}
img{max-width:100%}pre{overflow:auto}table{border-collapse:collapse}td,th{border:1px solid #8884;padding:.25rem .5rem}
@media print{body{max-width:none;padding:0}.blk:target{outline:none}}`;

/**
 * The rule the renderer emits for a chart (`figure.spec`), copied from render.js for the same reason as
 * `RECIPIENT_DOC_CSS`: without it an inlined chart overflows the reader's column. It is emitted only when
 * the sanitised page actually holds a figure, exactly as the renderer writes it only for a rendered one.
 */
export const SPEC_FIGURE_CSS =
  "figure.spec{margin:1rem 0}figure.spec img{display:block;max-width:100%;height:auto}";

/**
 * The stylesheet this module adds for the recipient page's own chrome and comments. Always inline and
 * always the last sheet, so the chrome and comment rules win where one overlaps a document rule. It also
 * carries the body rules itself, because a notice page (an expired or unknown link) has no document sheet
 * at all and must still read as a page.
 */
export const VIEW_CSS = `body{font:16px/1.6 system-ui,sans-serif;max-width:46rem;margin:0 auto;padding:1.5rem;color:#1d1d1f;background:#fff}
@media (prefers-color-scheme:dark){body{color:#e8e8ea;background:#151517}}
img{max-width:100%}pre{overflow:auto}table{border-collapse:collapse}td,th{border:1px solid #8884;padding:.25rem .5rem}
.chart-note{font-style:italic;opacity:.75}
.comments{margin-top:2.5rem;border-top:1px solid #8884;padding-top:1rem}
.comment-thread{margin:1rem 0}
.thread-closed{font-size:.85rem;text-transform:uppercase;letter-spacing:.04em;opacity:.7}
.comment{margin:.5rem 0 1rem}
.comment-label{font-weight:600;margin:0}
.comment-text{margin:.15rem 0 0;white-space:pre-wrap}
.notice{padding:.5rem .75rem;border-radius:6px;background:#8881}
.notice-error{background:#c3332a22}
form.comment-form{display:flex;flex-direction:column;gap:.5rem;margin-top:1.5rem}
form.comment-form textarea{min-height:6rem;font:inherit;padding:.5rem}
form.comment-form button{align-self:flex-start;font:inherit;padding:.5rem 1rem}`;

/**
 * The characters that would otherwise start markup: text and attribute values both go through this.
 *
 * @param {*} value anything
 * @returns {string}
 */
function escText(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/** An attribute value: the text escapes plus a quote. */
function escAttr(value) {
  return escText(value).replace(/"/g, "&quot;");
}

/**
 * The HTML entities a stored attribute can carry, decoded.
 *
 * The stored href is written by sanitize-html, which escapes `&`, `<`, `>` and `"`; a URL marked wrote
 * keeps `&` in a query. Numeric references are decoded too, because a hand-edited version (or an older
 * renderer) may have used one. An unknown entity is left exactly as it was: it was not an escape.
 *
 * @param {*} value an attribute value or text as stored
 * @returns {string}
 */
function decodeEntities(value) {
  return String(value == null ? "" : value).replace(
    /&(?:#([0-9]{1,7})|#[xX]([0-9a-fA-F]{1,6})|(amp|lt|gt|quot|apos|nbsp));/g,
    (whole, dec, hex, named) => {
      if (dec != null) {
        const code = Number(dec);
        return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
      }
      if (hex != null) {
        const code = Number.parseInt(hex, 16);
        return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
      }
      switch (named) {
        case "amp": return "&";
        case "lt": return "<";
        case "gt": return ">";
        case "quot": return '"';
        case "apos": return "'";
        case "nbsp": return "\u00a0";
        default: return whole;
      }
    },
  );
}

/**
 * The serialised form of an http(s) URL, or null.
 *
 * `new URL(...).href` is the normaliser the renderer's own link destination uses, so a URL a cell wrote
 * and a URL an attribute carries land on the same string when they mean the same page.
 *
 * @param {*} raw a decoded URL
 * @returns {string|null}
 */
function normalizeHttpUrl(raw) {
  if (typeof raw !== "string" || !raw) return null;
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  return url.href;
}

/**
 * The value of the first `name="..."` attribute in one tag, or null.
 *
 * The renderer and sanitize-html both write double-quoted attributes, which is the contract every caller
 * here is under. The scan is linear and the name must follow whitespace, so `data-inert-href` can never
 * be found when `href` is looked for (and the other way round).
 *
 * @param {string} tag a tag's text, with or without its closing `>`
 * @param {string} name the attribute name
 * @returns {string|null}
 */
function attrOf(tag, name) {
  const text = tag.endsWith(">") ? tag.slice(0, -1) : tag;
  const key = " " + name + '="';
  const at = text.indexOf(key);
  if (at < 0) return null;
  const start = at + key.length;
  const end = text.indexOf('"', start);
  return end < 0 ? null : text.slice(start, end);
}

/** The tag text with one `name="..."` attribute removed, everything else untouched. */
function dropAttr(tag, name) {
  const key = " " + name + '="';
  const at = tag.indexOf(key);
  if (at < 0) return tag;
  const end = tag.indexOf('"', at + key.length);
  if (end < 0) return tag;
  return tag.slice(0, at) + tag.slice(end + 1);
}

/** The tag text with `name` set to a new value (added when it is missing, replaced when it is not). */
function setAttr(tag, name, value) {
  return dropAttr(tag, name) + ` ${name}="${escAttr(value)}"`;
}

/** Does this `src` name something other than a path inside the version (a scheme, a fragment)? */
function isOutsideVersion(src) {
  return /^[a-z][a-z0-9+.-]*:/i.test(src) || src.startsWith("//") || src.startsWith("#");
}

/**
 * Every anchor that came from the run's own items becomes a real link; every other inert anchor keeps
 * its URL in the text.
 *
 * @param {string} html the transformed body
 * @param {Set<string>} allowed normalised URLs from the version's recorded link set
 * @returns {string}
 */
function restoreLinks(html, allowed) {
  let out = "";
  let i = 0;
  const lower = html.toLowerCase();
  for (;;) {
    const at = lower.indexOf("<a", i);
    if (at < 0) { out += html.slice(i); break; }
    const next = lower.charAt(at + 2);
    if (!(next === " " || next === "\t" || next === "\n" || next === "\r" || next === ">")) {
      out += html.slice(i, at + 2);
      i = at + 2;
      continue;
    }
    const end = lower.indexOf(">", at);
    if (end < 0) { out += html.slice(i); break; }
    out += html.slice(i, at);
    let tag = html.slice(at, end);
    if (tag.endsWith("/")) tag = tag.slice(0, -1);
    const inert = attrOf(tag, "data-inert-href");
    if (inert == null) {
      out += tag + ">";
      i = end + 1;
      continue;
    }
    const url = decodeEntities(inert);
    const normalised = normalizeHttpUrl(url);
    if (normalised != null && allowed.has(normalised)) {
      // A link the run offered: the URL it recorded is the href, opened in a new tab with no handle on
      // this page, and the title that only repeated the URL goes with the inert shape.
      let kept = dropAttr(dropAttr(dropAttr(dropAttr(tag, "data-inert-href"), "title"), "href"), "target");
      kept = dropAttr(kept, "rel");
      out += setAttr(setAttr(setAttr(kept, "href", normalised), "target", "_blank"), "rel", "noopener noreferrer") + ">";
      i = end + 1;
      continue;
    }
    // A link the run never offered: it stays inert, and the reader can still read where it pointed.
    // The inert value is written back exactly as it came, so the entity escapes it already carries are
    // never escaped twice and a later reader parses the URL it was.
    const kept = dropAttr(dropAttr(tag, "href"), "data-inert-href") + ` data-inert-href="${inert}"`;
    out += kept + ">";
    const close = lower.indexOf("</a>", end + 1);
    if (close < 0) {
      out += escText(` (${url})`);
      i = end + 1;
      continue;
    }
    out += html.slice(end + 1, close) + escText(` (${url})`);
    i = close;
  }
  return out;
}

/**
 * Every image the document points at inside its own version becomes a `data:` URI.
 *
 * An image with a path this version does not hold, one over either cap, and one whose asset cannot be
 * read is replaced (whole tag) by the fixed plain line: a reader gets a sentence, never a broken
 * image box and never a request to another host.
 *
 * @param {string} html the transformed body
 * @param {{readAsset: Function, note: string}} input
 * @returns {Promise<string>}
 */
async function inlineImages(html, { readAsset, note }) {
  let out = "";
  let i = 0;
  let total = 0;
  const lower = html.toLowerCase();
  const noteHtml = `<p class="chart-note">${escText(note)}</p>`;
  for (;;) {
    const at = lower.indexOf("<img", i);
    if (at < 0) { out += html.slice(i); break; }
    const next = lower.charAt(at + 4);
    if (!(next === " " || next === "\t" || next === "\n" || next === "\r" || next === ">")) {
      out += html.slice(i, at + 4);
      i = at + 4;
      continue;
    }
    const end = lower.indexOf(">", at);
    if (end < 0) { out += html.slice(i); break; }
    let tag = html.slice(at, end);
    if (tag.endsWith("/")) tag = tag.slice(0, -1).trimEnd();
    const src = decodeEntities(attrOf(tag, "src"));
    if (!src || isOutsideVersion(src)) {
      // An absolute URL, a `data:` image, or a scheme the sanitiser will judge: left for the pass.
      out += html.slice(i, end + 1);
      i = end + 1;
      continue;
    }
    const path = versionPathOf(src);
    let asset = null;
    try {
      asset = path ? await readAsset(path) : null;
    } catch {
      asset = null;
    }
    const rawBody = asset == null ? null : asset.body;
    const body = rawBody instanceof Uint8Array ? Buffer.from(rawBody) : null;
    const type = asset && typeof asset.contentType === "string" ? asset.contentType : "";
    const fits = body != null && body.length > 0 && body.length <= MAX_ASSET_BYTES
      && total + body.length <= MAX_TOTAL_BYTES && IMAGE_TYPE.test(type);
    if (!fits) {
      out += html.slice(i, at) + noteHtml;
      i = end + 1;
      continue;
    }
    total += body.length;
    out += html.slice(i, at) + setAttr(tag, "src", `data:${type};base64,${body.toString("base64")}`) + ">";
    i = end + 1;
  }
  return out;
}

/**
 * The path inside the version an image's relative `src` names, or null when it cannot name one.
 *
 * A query or a fragment is not part of a stored path, `..` is never followed, and a percent-encoded
 * segment is decoded (the renderer writes a path as-is, but a version may hold a name an older renderer
 * escaped).
 */
function versionPathOf(src) {
  let path = src.split("#")[0].split("?")[0];
  while (path.startsWith("./")) path = path.slice(2);
  if (!path || path.startsWith("/")) return null;
  if (path.split("/").some((segment) => segment === ".." || segment === ".")) return null;
  try {
    path = decodeURIComponent(path);
  } catch {
    return null;
  }
  return path || null;
}

/** The `<head>` of a stored page, or "". */
function headOf(html) {
  const m = /<head\b[^>]*>([\s\S]*?)<\/head\s*>/i.exec(html);
  return m ? m[1] : "";
}

/** The body content of a stored page: what is inside `<body>`, or the document without its head. */
function bodyOf(html) {
  const m = /<body\b[^>]*>([\s\S]*?)<\/body\s*>/i.exec(html);
  if (m) return m[1];
  return html
    .replace(/<!doctype[^>]*>/i, "")
    .replace(/<head\b[^>]*>[\s\S]*?<\/head\s*>/i, "")
    .replace(/<\/?html\b[^>]*>/gi, "");
}

/** The stored page's title text, decoded and flattened to one line, or "". */
function titleOf(html) {
  const m = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(headOf(html));
  if (!m) return "";
  return decodeEntities(m[1]).replace(/\s+/g, " ").trim().slice(0, 200);
}

/**
 * Does the sanitised body hold a rendered chart? The spec figure rule is emitted only when it does, the
 * way the renderer writes that rule only for a version with a rendered figure.
 */
function hasFigure(html) {
  return /<figure\b/i.test(html);
}

/** The sanitiser options for this document shape, built fresh for each view. */
function sanitizeOptions(allowed) {
  return {
    allowedTags: [...ALLOWED_TAGS],
    allowedAttributes: Object.fromEntries(
      Object.entries(ALLOWED_ATTRIBUTES).map(([tag, names]) => [tag, [...names]]),
    ),
    allowedSchemes: ["http", "https"],
    allowedSchemesByTag: { img: ["data"] },
    allowedSchemesAppliedToAttributes: ["href", "src"],
    allowProtocolRelative: false,
    disallowedTagsMode: "discard",
    nonTextTags: [...NON_TEXT_TAGS],
    // Belt and braces on stored CSS: no allowed-attribute list names `style`, so a stored style
    // attribute is dropped. Not parsing them at all also keeps the sanitiser from handing back a
    // re-serialised style value, which would be CSS this module did not choose.
    parseStyleAttributes: false,
    selfClosing: ["img", "br", "hr"],
    transformTags: {
      // An anchor keeps only an absolute http(s) destination, and every live one opens in a new tab
      // without a handle on this page. A relative href would point at a page a recipient does not have.
      a: (tagName, attribs) => {
        const kept = { ...attribs };
        const normalised = normalizeHttpUrl(kept.href);
        if (normalised == null || !allowed.has(normalised)) {
          delete kept.href;
          delete kept.target;
          delete kept.rel;
        } else {
          kept.href = normalised;
          kept.target = "_blank";
          kept.rel = "noopener noreferrer";
        }
        return { tagName, attribs: kept };
      },
    },
    // An image survives only as an inline `data:` image: a remote one would be a request a reader's
    // browser makes to a host the report never named.
    exclusiveFilter: (frame) => frame.tag === "img"
      && !INLINE_IMAGE_SRC.test(String(frame.attribs == null ? "" : frame.attribs.src || "")),
  };
}

/** One body through the allow-list. A pass that fails vouches for nothing, so it drops the body. */
function keepSafeHtml(html, allowed) {
  if (typeof html !== "string" || !html) return "";
  try {
    return sanitize(html, sanitizeOptions(allowed));
  } catch {
    return "";
  }
}

/** A comment's text as the page shows it: escaped, with its own newlines as line breaks. */
function commentText(value) {
  return escText(value).replace(/\r\n|\r|\n/g, "<br>");
}

/**
 * The comments section, or "" when a view-scope link has nothing to show.
 *
 * The heading is the comments-heading line and every label is the caller's already-decided display label
 * (a recipient's own name, the sender, a bot's own display name), so this module never guesses who
 * wrote what. Texts are escaped here and never travel through the sanitiser: reader-written text and
 * the form are the one part of the page this module produces itself.
 */
function commentsSection({ table, threads, commentForm }) {
  const list = Array.isArray(threads) ? threads.filter((t) => t && typeof t === "object") : [];
  if (!list.length && commentForm == null) return "";
  const parts = [`<section class="comments"><h2>${escText(table.commentsHeading)}</h2>`];
  if (commentForm != null) {
    const notice = commentForm.notice;
    if (notice && typeof notice === "object" && notice.text) {
      const kind = notice.kind === "ok" ? "ok" : "error";
      parts.push(`<p class="notice notice-${kind}">${escText(notice.text)}</p>`);
    }
  }
  if (!list.length) {
    parts.push(`<p class="no-comments">${escText(table.noComments)}</p>`);
  }
  for (const thread of list) {
    const resolved = thread.status === "resolved";
    parts.push(`<article class="comment-thread${resolved ? " comment-thread-closed" : ""}">`);
    if (resolved) parts.push(`<p class="thread-closed">${escText(table.closed)}</p>`);
    const comments = Array.isArray(thread.comments) ? thread.comments : [];
    for (const comment of comments) {
      if (!comment || typeof comment !== "object") continue;
      parts.push('<div class="comment">');
      parts.push(`<p class="comment-label">${escText(comment.label)}</p>`);
      parts.push(`<p class="comment-text">${commentText(comment.text)}</p>`);
      parts.push("</div>");
    }
    parts.push("</article>");
  }
  if (commentForm != null) {
    // Posts back to the page's own URL: the listener maps a POST on `/r/<token>` to this token, so the
    // form carries no token of its own and a copied form cannot be pointed at another report.
    //
    // A caller may pass a notice with NO nonce: that is a refusal rendered on a view-only link, where
    // the refusal line has to be shown and there is no form to offer (the reader cannot post there at
    // all). Only a nonce means "this page accepts a comment".
    if (typeof commentForm.nonce === "string") {
      parts.push('<form class="comment-form" method="post" action="">');
      parts.push(`<input type="hidden" name="formNonce" value="${escAttr(commentForm.nonce)}">`);
      parts.push(`<label for="comment-text">${escText(table.addComment)}</label>`);
      parts.push('<textarea id="comment-text" name="text" maxlength="4000" required></textarea>');
      parts.push(`<button type="submit">${escText(table.sendComment)}</button>`);
      parts.push("</form>");
    }
  }
  parts.push("</section>");
  return parts.join("\n");
}

/** The chrome every recipient page shares: doctype, language, meta, title, inline styles, body. */
function pageShell({ language, title, sheets, body }) {
  const styles = sheets.map((css) => `<style>${css}</style>`).join("\n");
  return `<!doctype html>
<html lang="${language}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escText(title)}</title>
${styles}
</head>
<body>
${body}
</body>
</html>`;
}

/** The language a page is written in, from the same prefix rule the copy table uses. */
function normalizeLang(lang) {
  const table = copyFor(lang);
  return table === RECIPIENT_COPY.es ? "es" : "en";
}

/**
 * Build the complete page a recipient is shown for one version.
 *
 * @param {{indexHtml?: string, readAsset?: Function, allowedLinks?: string[], threads?: object[],
 *   commentForm?: object|null, lang?: string}} input
 *   `indexHtml` is the stored index.html of the version, `readAsset(path)` resolves a path inside that
 *   version to `{body: Buffer, contentType}`, `allowedLinks` is the version's recorded link set,
 *   `threads` is already labelled and `commentForm` is null for a view-scope link (a refusal line with
 *   no nonce is a notice without a form; see `commentsSection`).
 * @returns {Promise<string>} one complete HTML document
 */
export async function buildRecipientView({
  indexHtml,
  readAsset,
  allowedLinks = [],
  threads = [],
  commentForm = null,
  lang = "en",
} = {}) {
  const language = normalizeLang(lang);
  const table = copyFor(language);
  const html = typeof indexHtml === "string" ? indexHtml : "";
  const read = typeof readAsset === "function" ? readAsset : async () => null;
  const allowed = new Set();
  if (Array.isArray(allowedLinks)) {
    for (const link of allowedLinks) {
      const normalised = normalizeHttpUrl(link);
      if (normalised != null) allowed.add(normalised);
    }
  }

  const restored = restoreLinks(bodyOf(html), allowed);
  const inlined = await inlineImages(restored, { readAsset: read, note: table.chartTooLarge });
  const safeBody = keepSafeHtml(inlined, allowed);
  const comments = commentsSection({ table, threads, commentForm });
  // Only this module's own constants are ever written as a stylesheet: the document sheet, the spec
  // figure rule when a chart survived the pass, then this module's chrome. Nothing from the stored page
  // reaches `sheets` (see the header on why no stored sheet is filtered or kept).
  return pageShell({
    language,
    title: titleOf(html),
    sheets: [RECIPIENT_DOC_CSS, ...(hasFigure(safeBody) ? [SPEC_FIGURE_CSS] : []), VIEW_CSS],
    body: `${safeBody}\n${comments}`.trimEnd(),
  });
}

/**
 * The minimal page a recipient sees when there is no report to show: an expired link, an unknown one, or
 * a report this instance cannot render right now. It carries the one line and nothing else.
 *
 * @param {{kind?: "expired"|"unknown"|"unavailable", lang?: string}} input
 * @returns {string} one complete HTML document
 */
export function renderRecipientNotice({ kind = "unknown", lang = "en" } = {}) {
  const language = normalizeLang(lang);
  const table = copyFor(language);
  const line = kind === "expired" ? table.expired : kind === "unavailable" ? table.unavailable : table.unknownLink;
  return pageShell({
    language,
    title: line,
    sheets: [VIEW_CSS],
    body: `<p class="recipient-notice">${escText(line)}</p>`,
  });
}

/**
 * The stored document a token's version names, and the readers a caller needs to build its page.
 *
 * WHAT IS REFUSED: a version that does not exist, one the tripwire flagged, one with no `index.html`, and
 * one whose `index.html` cannot be read all answer null. So does an artifact that is not the KIND a
 * document renderer produces: `loadVersionForView` is the door a recipient link opens, and this module
 * knows how to make safe exactly one shape of page (the one `renderVersion("document", ...)` writes). A
 * `page`, `diagram`, `data` or any other artifact version can legitimately carry an `index.html` too, so
 * existence alone would let a link to one of those through a renderer nobody hardened. The artifact row
 * is therefore read as well and its `type` has to be `document`; a missing row, any other type, or an
 * error reading the row answers null, and the door says 404 the way it does for a missing version.
 *
 * WHAT `readAsset` IS: a reader bound to THIS version's own file list, so a path outside it (a traversal,
 * another version's file, an absolute path) answers null instead of reading storage. `listAssets` names
 * the paths the version holds.
 *
 * @param {object} db a libsql-shaped client
 * @param {{artifacts?: object}} deps the artifacts runtime seam (`{artifacts}` in a test)
 * @param {{artifactId?: string, n?: number}} input the pinned version
 * @returns {Promise<{indexHtml: string, readAsset: Function, listAssets: Function}|null>}
 */
export async function loadVersionForView(db, deps, { artifactId, n } = {}) {
  if (typeof artifactId !== "string" || !artifactId) return null;
  const version = Number(n);
  if (!Number.isInteger(version) || version < 1) return null;
  let runtime;
  try {
    runtime = await loadArtifactsRuntime(deps);
  } catch {
    return null;
  }
  const store = runtime == null ? null : runtime.store;
  const blobs = runtime == null ? null : runtime.blobs;
  if (!store || typeof store.getVersion !== "function" || typeof store.getArtifact !== "function"
    || !blobs || typeof blobs.get !== "function") return null;

  // The kind of the artifact comes first: a non-document artifact may still hold an `index.html`, and
  // this module only knows how to make one shape of page safe.
  let artifact;
  try {
    artifact = await store.getArtifact(db, artifactId);
  } catch {
    return null;
  }
  if (!artifact || artifact.type !== "document") return null;

  const row = await store.getVersion(db, artifactId, version);
  if (!row || row.flagged_reason) return null;
  let files;
  try {
    files = JSON.parse(row.files_json);
  } catch {
    return null;
  }
  if (!Array.isArray(files)) return null;
  const index = files.find((file) => file && file.path === "index.html");
  if (!index) return null;
  const indexBody = await blobs.get(index.key);
  if (!indexBody) return null;

  const readAsset = async (path) => {
    if (typeof path !== "string" || !path) return null;
    const file = files.find((entry) => entry && entry.path === path);
    if (!file) return null;
    const body = await blobs.get(file.key);
    if (!body) return null;
    return { body, contentType: file.contentType };
  };
  const listAssets = async () => files.map((file) => (file && typeof file.path === "string" ? file.path : "")).filter(Boolean);
  return { indexHtml: indexBody.toString("utf8"), readAsset, listAssets };
}