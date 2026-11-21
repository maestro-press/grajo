/**
 * Link neutralising for text nobody approved: a model's commentary, a bot's own `text` block, and a
 * custom step's section.
 *
 * A report body carries text a source wrote, and a model (or a bot) can write a URL that came from
 * nowhere: a made-up host, a redirect, a `javascript:` payload. The rule is one line: a URL survives
 * only when that exact string appears verbatim in the run's own items, which is the set the reader can
 * already see. Everything else becomes plain text naming the host it pointed at (`[link removed:
 * example.net]`), so the reader sees what was offered without a clickable way to it. `javascript:`,
 * `data:` and every other non-http(s) scheme are never kept, whatever set is passed in.
 *
 * WHO READS THE TEXT: not a scanner of this module's own, but the SAME markdown lexer the artifact
 * renderer uses for a report's document (`marked`: GFM, `breaks: true`, the options
 * `servers/blog/renderer.js` sets on the instance its `markdownBlocks` lexes with). A shape the
 * renderer reads as a link is therefore a shape this module judges, and there is no second grammar to
 * fall behind it. The walk is over TOKENS, and the markdown is rebuilt from each token's own `raw` with
 * only the link-shaped leaves replaced, so a heading, a table, a list or a fence keeps the text it had.
 *
 * What it judges, token by token:
 *   - `link`: its `href`, from an inline `[text](url)`, a reference `[text][label]` resolved against
 *     the document's own `[label]: url` definitions, or a shortcut `[label]`. A kept link is written
 *     back inline, which retires the definition line it came from. GFM's bare `https://...` and `www.`
 *     links and `<https://...>` autolinks arrive here too, as a `link` whose `raw` IS the URL, and they
 *     are written back as the URL they are;
 *   - `image`: DROPPED. An image in text nobody approved is a request the reader's browser would make
 *     to a host the recipe never named (finding 8): there is no allowed-image set here, so the whole
 *     image goes rather than being kept or marked;
 *   - `code`: a fenced `vega-lite`, `mermaid` or `d2` block keeps its place but its info string becomes
 *     `text`, so the artifacts renderer draws code instead of a picture. A model, a bot-authored text
 *     block or a custom step may not put a rendered chart or diagram into a report;
 *   - `url` and `autolink`: the same rule, for any lexer version that keeps those types separate;
 *   - `def`: never survives, so a definition line cannot smuggle a URL past the rule;
 *   - `html`: EVERY raw HTML token becomes escaped text, whatever it carries. A URL in one of its
 *     `href=`/`src=` attributes is judged first, so a refused one shows as the same host-only marker
 *     instead of the full untrusted URL, and no URL in the escaped text can autolink either.
 *
 * AN UNTRUSTED BODY MAY NOT CARRY A HEADING. With `{demoteHeadings: true}` every `heading` token the
 * walk meets is rewritten as bold text of the words it holds, in the same pass that judges the links.
 * The token is what decides, not a line rule: an ATX heading, a setext heading, and a heading nested in
 * a blockquote, in a list item or in a table cell all face it, and each becomes `**...**`. The document's
 * own headings come from the recipe and from the assembly, so text nobody approved cannot put one in.
 *
 * A SHORTCUT REFERENCE MAY NOT RESOLVE AFTER THE JOIN. A definition line never survives the walk (see
 * `def`), but the WORDS `[docs]` in the text are a shortcut reference the renderer resolves against any
 * definition in the document it ends up in, including a `[docs]: url` an owner's own block wrote in
 * another section: that definition never belonged to this text, and the link it makes was never in the
 * allowed set. With `demoteHeadings` on, a leaf `text` token's brackets are written `\[` and `\]`, so the
 * words stay and nothing in the text can resolve; a real `link` token is judged as it always is.
 *
 * THE CLOSER IS THE LEXER'S. An unterminated fence at the end of the text is closed, because joined to the
 * section after it, it would swallow that section. Which fence that is is decided by the SAME lexer the
 * walk uses and not by a line scan (`openFenceCloser`): only a fence the lexer reads as a TOP-LEVEL fenced
 * `code` block whose own raw carries no closer line is one, written with its own indent and marker. A fence
 * a list item or a blockquote holds ends with its container, and a column-0 closer appended after it would
 * itself be a NEW top-level opener that swallows the table and the attribution written after it.
 *
 * A kept link whose visible text names a DIFFERENT host than its target is rewritten to show the
 * target's host (`[example.net](https://example.com/a)` reads `[example.com](https://example.com/a)`),
 * so the words and the destination cannot disagree, unless the text was already rewritten from a child
 * link. A link title is untrusted text too and is dropped with the rest of it. The marker itself names
 * the host and nothing else: its path, query and scheme are gone, and a host that begins with `www.`
 * has that dot escaped, so the marker is not a link either.
 *
 * THE BACKSTOP: the result is lexed a second time, and every link, image, autolink and raw HTML URL in
 * it must be in the allowed set (and, when headings are demoted, no heading may be left in it). Text the
 * walk could not rewrite safely (a token whose children cannot be placed inside its own `raw`, a lexer
 * that throws, a body over `MAX_LEX_CHARS`) is escaped whole: brackets, angle brackets, the scheme's own
 * colon and (when headings are demoted) every heading marker, so nothing in it can read as a link or a
 * heading, and (when headings are demoted) its unterminated fence is closed. If even that does not pass
 * the backstop the answer is the empty string: this module fails closed.
 *
 * THE LAST LINE IS READ AS IF IT ENDED. A text with no final line break lexes its last line as paragraph
 * text, so a fence opener there would demote nothing and close nothing, and would open a real fence once
 * the document is joined together. Every text is therefore lexed with that break, and the answer loses it
 * again, so nothing gains or loses a line break except the closer such a fence needs.
 *
 * Exported for the report mail path (a later round) as well as the document assembly that uses it now.
 */
import { Marked } from "marked";

/**
 * The lexer both passes read the text with: the artifacts renderer's document path
 * (`markdownBlocks` in servers/blog/renderer.js) lexes with the module-wide `marked` instance, which
 * that file configures as `{gfm: true, breaks: true}`. Same library, same options, and an instance of
 * this module's own so neither side can move the other's defaults. A text is always read as one ending
 * with a line break (see `lexOrNull`): the line break is what makes a fence opener on the last line a
 * fence, as it is once the text is joined to what follows it.
 */
const markdown = new Marked({ gfm: true, breaks: true });

/** The longest body this module lexes. Past it the whole text is escaped instead. */
const MAX_LEX_CHARS = 64 * 1024;

const NO_HOST = "[link removed: link]";

/**
 * The caller's allowed set as a Set of strings. A Set or an array is read entry by entry, and anything
 * else allows nothing at all, which fails closed.
 */
function toAllowedSet(allowedUrls) {
  const set = new Set();
  if (allowedUrls == null || typeof allowedUrls === "string") return set;
  if (typeof allowedUrls[Symbol.iterator] !== "function") return set;
  for (const url of allowedUrls) if (typeof url === "string") set.add(url);
  return set;
}

/**
 * The caller's options as this module reads them. `demoteHeadings` is off unless a caller asks for it: it
 * is for text nobody approved (a model's commentary, a bot's text block, a custom step's section).
 */
function optionsOf(options) {
  return { demoteHeadings: options != null && options.demoteHeadings === true };
}

/** A URL's host (no port, no path), or "" when it is not a URL this module can read. */
function hostOf(url) {
  try {
    const parsed = new URL(String(url));
    return parsed.hostname || "";
  } catch {
    return "";
  }
}

/** Is this URL kept: http(s) only, and the exact string in the caller's allowed set? */
function keepsAsLink(url, allowed) {
  if (typeof url !== "string" || !url) return false;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return false;
  return allowed.has(url);
}

/**
 * What a refused URL becomes: plain text naming the host only. A host that begins with `www.` has its
 * dot escaped, because `www.` followed by a host is itself a GFM autolink: the marker must not be a
 * link either, and markdown renders the escaped dot as the dot it is.
 */
function removedText(url) {
  const host = hostOf(url);
  if (!host) return NO_HOST;
  return `[link removed: ${host.replace(/^www\./i, "www\\\.")}]`;
}

/** Text for display: the three characters that would otherwise start markup. */
function escapeText(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/** File extensions that look like a host's last label but are not one. */
const NOT_A_TLD = new Set([
  "pdf", "md", "txt", "csv", "json", "html", "htm", "xml", "png", "jpg", "jpeg", "gif", "svg", "webp",
  "zip", "doc", "docx", "xls", "xlsx", "mp3", "mp4", "mov", "py", "js", "mjs", "css",
]);

const HOST_TOKEN = /(?:^|[^\w.@/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?![\w-])/gi;
const FULL_URL = /https?:\/\/[^\s<>()[\]"'`]+/gi;

/** Every host a stretch of visible text names: full URLs, and bare host-shaped words. */
function hostsIn(text) {
  const hosts = [];
  for (const match of String(text).matchAll(FULL_URL)) {
    const host = hostOf(match[0]);
    if (host) hosts.push(host.toLowerCase());
  }
  for (const match of String(text).matchAll(HOST_TOKEN)) {
    const tld = String(match[2] || "").toLowerCase();
    if (NOT_A_TLD.has(tld)) continue;
    hosts.push(String(match[1] || "").toLowerCase());
  }
  return hosts;
}

/** Does this visible link text name a host other than its target's? */
function namesAnotherHost(visible, url) {
  const target = hostOf(url).toLowerCase();
  if (!target) return false;
  return hostsIn(visible).some((host) => host !== target);
}

/** The visible text a kept link shows: the target's host when the words name another host. */
function visibleLabel(rawLabel, rendered, href) {
  const source = String(rawLabel == null ? "" : rawLabel);
  const text = String(rendered == null ? "" : rendered);
  if (text !== source) return text; // a child link was already rewritten: its text is the answer
  if (!source.trim()) return hostOf(href) || "";
  if (namesAnotherHost(source, href)) return hostOf(href) || "";
  return source;
}

/** A destination as the inline markdown form can carry it: `<...>` when it holds a parenthesis. */
function destination(href) {
  return /[()\s]/.test(href) ? `<${href}>` : href;
}

/** The `href`/`src` values of one raw HTML token, in order. */
const URL_ATTR = /\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;

/** Does this raw HTML carry a URL outside the allowed set? */
function htmlHasForeignUrl(raw, allowed) {
  for (const match of String(raw).matchAll(URL_ATTR)) {
    const value = String(match[1] ?? match[2] ?? match[3] ?? "").trim();
    if (!keepsAsLink(value, allowed)) return true;
  }
  return false;
}

/**
 * A stretch of text with its URLs made unreadable to the renderer's autolink rule: the scheme's colon,
 * `www.`'s dot and an `@` all become character references, which a browser still draws as `:` `.` `@`.
 * Used on text that must not read as a link (an escaped raw HTML token, a body escaped whole, and a
 * recipe string, which document.js's `escapeRecipeText` breaks the same way). The `www` prefix keeps its
 * own case: only the dot after it is broken.
 */
export function breakUrlText(text) {
  return String(text)
    .replace(/(?:https?|ftp):/gi, (scheme) => scheme.replace(":", "&#58;"))
    .replace(/(www)\./gi, (_whole, prefix) => `${prefix}&#46;`)
    .replace(/@/g, "&#64;");
}

/** One raw HTML token as escaped text, with a refused `href`/`src` value replaced by the host-only
 *  marker first, and no URL left able to autolink. */
function escapedHtml(raw, allowed) {
  const judged = String(raw).replace(URL_ATTR, (whole, doubleQuoted, singleQuoted, bare) => {
    const value = String(doubleQuoted ?? singleQuoted ?? bare ?? "").trim();
    if (!value || keepsAsLink(value, allowed)) return whole;
    return whole.replace(value, removedText(value));
  });
  return breakUrlText(escapeText(judged));
}

/** The child tokens of a container token, or null for a leaf. */
function childrenOf(token) {
  if (Array.isArray(token.tokens)) return token.tokens;
  if (Array.isArray(token.items)) return token.items;
  if (Array.isArray(token.header) || Array.isArray(token.rows)) {
    const cells = [];
    if (Array.isArray(token.header)) for (const cell of token.header) cells.push(cell);
    if (Array.isArray(token.rows)) {
      for (const row of token.rows) if (Array.isArray(row)) for (const cell of row) cells.push(cell);
    }
    return cells;
  }
  return null;
}

/**
 * Where a child token's own text sits inside its parent's `raw`. A token's `raw` is that text for most
 * tokens; a table cell is the exception this walker reads by `text`, because marked builds a cell from
 * its trimmed source and keeps no `raw` on it.
 */
function sourceOfToken(token) {
  if (token == null || typeof token !== "object") return "";
  if (typeof token.raw === "string" && token.raw) return token.raw;
  if (typeof token.text === "string") return token.text;
  return "";
}

/** A token's own URL: a link's or an image's `href`, an autolink's target. */
function hrefOfToken(token) {
  if (typeof token.href === "string" && token.href) return token.href;
  if (typeof token.text === "string") return token.text;
  return "";
}

/** A `link` token as markdown: kept inline and allowed, or the host-only marker. */
function renderLinkToken(token, allowed, opts) {
  const href = typeof token.href === "string" ? token.href : "";
  const raw = typeof token.raw === "string" ? token.raw : "";
  // A GFM bare autolink arrives as a link token whose own raw IS the URL (or the `<...>` around it):
  // it is written back as the URL it is, not as a bracketed link.
  if (raw === href || raw === `<${href}>`) return keepsAsLink(href, allowed) ? href : removedText(href);
  const rawLabel = typeof token.text === "string" ? token.text : "";
  const rendered = Array.isArray(token.tokens) ? renderTokens(token.tokens, allowed, opts) : rawLabel;
  if (!keepsAsLink(href, allowed)) return removedText(href);
  return `[${visibleLabel(rawLabel, rendered, href)}](${destination(href)})`;
}

/** A `image` token: dropped whole, see the header's finding 8 note. */
function renderImageToken() {
  return "";
}

/** The fence languages the artifacts renderer draws as a picture (its own `SPEC_ENGINES`). */
const SPEC_FENCE_LANGS = new Set(["vega-lite", "mermaid", "d2"]);

/** The first line of a stretch of markdown, or the whole of it when it carries no break. */
function firstLineOf(text) {
  const index = text.indexOf("\n");
  return index < 0 ? text : text.slice(0, index);
}

/**
 * A fence opener line as the renderer's own lexer reads one: up to three spaces of indent, three or more
 * backticks or tildes, and for a backtick fence an info string that carries no backtick.
 */
function fenceOpenerLine(line) {
  const match = /^( {0,3})(`{3,}|~{3,})([^\n]*)$/.exec(String(line));
  if (!match) return null;
  const marker = match[2];
  const info = match[3];
  if (marker[0] === "`" && info.includes("`")) return null;
  return { indent: match[1], marker, info };
}

/**
 * An info string's first word, read the way the renderer reads it: every Unicode space (NBSP and the
 * other Zs code points included) trimmed from both ends, a backslash before an ASCII character undone,
 * and the word lower-cased.
 */
function infoWord(info) {
  return String(info)
    .replace(/\\([\x21-\x7e])/g, "$1")
    .trim()
    .split(/\s+/)[0]
    .toLowerCase();
}

/** A fence opener line whose engine is one the artifacts renderer draws, or null. */
function specFenceOpener(line) {
  const opener = fenceOpenerLine(line);
  if (!opener) return null;
  return SPEC_FENCE_LANGS.has(infoWord(opener.info)) ? opener : null;
}

/** Is this raw code token a fence in one of the spec languages? */
function isSpecFenceRaw(raw) {
  return specFenceOpener(firstLineOf(String(raw))) !== null;
}

/** Is this line the closer of the fence opened with `marker`? */
function isFenceCloser(line, marker) {
  return new RegExp(`^ {0,3}${marker[0]}{${marker.length},}[ \\t]*$`).test(line);
}

/**
 * A fenced spec block as plain code: the same fence (its leading indent included), its info string
 * replaced by `text`. The fence's own body is left exactly as written, so a reader still sees the thing
 * the model put there.
 */
function demotedFence(raw) {
  const text = String(raw);
  const line = firstLineOf(text);
  const opener = specFenceOpener(line);
  if (!opener) return raw;
  return `${opener.indent}${opener.marker}text` + text.slice(line.length);
}

/**
 * The same demotion as a line rewrite, for a body escaped whole: every line that opens a spec fence keeps
 * its indent and marker and takes `text` as its info string. A line that is not one of the three engines
 * is left alone, and so is a fence body.
 */
function demoteSpecFenceLines(text) {
  const lines = String(text).split("\n");
  let open = null;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (open) {
      if (isFenceCloser(line, open)) open = null;
      continue;
    }
    const opener = fenceOpenerLine(line);
    if (!opener) continue;
    open = opener.marker;
    const spec = specFenceOpener(line);
    if (spec) lines[index] = `${spec.indent}${spec.marker}text`;
  }
  return lines.join("\n");
}

/**
 * Does a fenced code token's raw end with a line that closes the fence its first line opened? The first
 * line IS the opener, so it is never read as the closer of itself; the lines after it are read from the
 * last one back, blank lines skipped.
 */
function rawEndsClosed(raw, marker) {
  const lines = String(raw).split("\n").slice(1);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const line = lines[index];
    if (/^[ \t]*$/.test(line)) continue;
    return isFenceCloser(line, marker);
  }
  return false;
}

/**
 * The closing fence an unterminated fence at the end of this markdown needs, else "". Exported because the
 * document assembly closes every section with the same answer (`document.js`'s `fenceCloser`).
 *
 * A fence opened in text nobody approved would otherwise swallow every section written after it, so the
 * text is read with the final line break it is joined with, and the LAST top-level block is asked. Only a
 * fenced `code` token whose own raw carries no closer line ends open. A fence nested in a list item or a
 * blockquote is not one: that container ends with the fence, so nothing is appended, because a column-0
 * closer after such a fence would itself be a NEW top-level opener and would swallow what follows it. The
 * closer is written with the opener's own indent and a marker as long as the opener's.
 */
export function openFenceCloser(markdownText) {
  const source = typeof markdownText === "string" ? markdownText : "";
  if (!source) return "";
  let tokens;
  try {
    tokens = markdown.lexer(source.endsWith("\n") ? source : `${source}\n`);
  } catch {
    return "";
  }
  if (!Array.isArray(tokens)) return "";
  let last = null;
  for (let index = tokens.length - 1; index >= 0; index -= 1) {
    const token = tokens[index];
    if (token == null || token.type === "space") continue;
    last = token;
    break;
  }
  if (last == null || last.type !== "code" || typeof last.raw !== "string") return "";
  const opener = fenceOpenerLine(firstLineOf(last.raw));
  if (!opener) return "";
  if (rawEndsClosed(last.raw, opener.marker)) return "";
  return `\n${opener.indent}${opener.marker}`;
}

/**
 * A leaf text token's brackets escaped, so a shortcut reference in text nobody approved cannot resolve
 * against a definition an owner's own block left in the joined document (see the header). Markdown draws
 * an escaped bracket as the bracket it is, so the words read the same.
 */
function escapeBrackets(text) {
  return String(text).replace(/\[/g, "\\[").replace(/\]/g, "\\]");
}

/** A bare URL or an autolink: the URL itself when it is allowed, else the host-only marker. */
function renderBareToken(token, allowed) {
  const url = hrefOfToken(token);
  return keepsAsLink(url, allowed) ? url : removedText(url);
}

/**
 * Heading markers made literal wherever they could start one: every `#`, and a line that is nothing but
 * `=` or `-`, which is what a setext underline looks like. A backslash before it is the character it
 * precedes, so the reader still sees the mark and the lexer reads text.
 */
function breakHeadings(text) {
  return String(text)
    .replace(/#/g, "\\#")
    .replace(/^([ \t]*)(=+|-+)[ \t\r]*$/gm, (whole, lead, marks) => `${lead}\\${marks}`);
}

/**
 * The whole text escaped: brackets, angle brackets and the scheme's own colon, so nothing in it can be
 * read back as a link, an image, an autolink or a tag, and (when headings are demoted) no heading marker
 * either.
 */
function escapeWhole(text, opts) {
  const escaped = String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\[/g, "\\[")
    .replace(/\]/g, "\\]");
  const broken = opts.demoteHeadings ? breakHeadings(escaped) : escaped;
  return breakUrlText(demoteSpecFenceLines(broken));
}

/**
 * A `heading` token as bold text of its own words, whatever wrote it and wherever it sits. Its children
 * are walked, so a link inside a heading is judged like any other, and the answer always ends with a
 * blank line, so a setext underline that followed it cannot join it back into a heading.
 */
function renderHeadingToken(token, allowed, opts) {
  const rendered = Array.isArray(token.tokens)
    ? renderTokens(token.tokens, allowed, opts)
    : String(token.text == null ? "" : token.text);
  const words = rendered.trim();
  // Always a blank line after it: a demoted heading followed by `---` would otherwise be a setext
  // heading again when the answer is read back.
  return words ? `**${words}**\n\n` : "\n\n";
}

/** One token as markdown, its own links judged and its children's rewritten. */
function renderToken(token, allowed, opts) {
  if (token == null || typeof token !== "object") return "";
  // A table cell carries no `raw`: its own `text` is the source the tokens inside it were read from.
  const raw = typeof token.raw === "string"
    ? token.raw
    : (typeof token.text === "string" ? token.text : "");
  switch (token.type) {
    case "def":
      return "";
    case "html":
      return escapedHtml(raw || String(token.text || ""), allowed);
    case "link":
      return renderLinkToken(token, allowed, opts);
    case "image":
      return renderImageToken();
    case "code":
      return demotedFence(raw);
    case "text":
      // Only a LEAF text token is rewritten here: one that carries children is walked below, so the
      // links inside it are judged and its own leaves take the escape.
      if (opts.demoteHeadings && !Array.isArray(token.tokens)) return escapeBrackets(raw);
      break;
    case "url":
    case "autolink":
      return renderBareToken(token, allowed);
    case "heading":
      if (opts.demoteHeadings) return renderHeadingToken(token, allowed, opts);
      break;
    default:
      break;
  }
  const kids = childrenOf(token);
  if (!kids || !kids.length) return raw;
  let out = "";
  let cursor = 0;
  for (const kid of kids) {
    const kidSource = sourceOfToken(kid);
    const rendered = renderToken(kid, allowed, opts);
    const at = kidSource ? raw.indexOf(kidSource, cursor) : -1;
    if (at < 0) {
      // A child whose own text cannot be placed inside the parent's raw: when the child needs no
      // change the parent's own text already carries it; when it does, this token is escaped whole
      // rather than emitted with a link the walk could not judge.
      if (!kidSource || rendered === kidSource) continue;
      return escapeWhole(raw, opts);
    }
    out += raw.slice(cursor, at) + rendered;
    cursor = at + kidSource.length;
  }
  return out + raw.slice(cursor);
}

/** Every token of one list, in order. */
function renderTokens(tokens, allowed, opts) {
  let out = "";
  for (const token of tokens) out += renderToken(token, allowed, opts);
  return out;
}

/**
 * The text's tokens, or null when the lexer refuses them. A text whose last line carries no line break is
 * lexed as if it had one: `x\n\`\`\`` with no final break is one paragraph to the lexer, while the same
 * line joined to the section written after it opens a real fence. A fence opener on the LAST line is
 * therefore a fence here too, so the walk demotes it and the closer sees it.
 */
function lexOrNull(text) {
  const source = typeof text === "string" ? text : "";
  const padded = source.endsWith("\n") ? source : `${source}\n`;
  try {
    const tokens = markdown.lexer(padded);
    return Array.isArray(tokens) ? tokens : null;
  } catch {
    return null;
  }
}

/**
 * Does this markdown still carry a link, image, autolink or raw HTML URL outside the allowed set, or (when
 * headings are demoted) a heading the walk failed to turn into text?
 */
function hasForeignUrl(markdownText, allowed, opts) {
  const tokens = lexOrNull(markdownText);
  if (!tokens) return true;
  const seen = new Set();
  const stack = [...tokens];
  while (stack.length) {
    const token = stack.pop();
    if (token == null || typeof token !== "object" || seen.has(token)) continue;
    seen.add(token);
    // A spec fence that survived the walk would be drawn as a picture: fail closed.
    if (token.type === "code" && isSpecFenceRaw(token.raw || "")) return true;
    if (opts.demoteHeadings && token.type === "heading") return true;
    if (token.type === "html") {
      if (htmlHasForeignUrl(token.raw || token.text || "", allowed)) return true;
      continue;
    }
    if (token.type === "link" || token.type === "image" || token.type === "url"
      || token.type === "autolink") {
      if (!keepsAsLink(hrefOfToken(token), allowed)) return true;
    }
    const kids = childrenOf(token);
    if (kids) for (const kid of kids) stack.push(kid);
  }
  return false;
}

/**
 * Neutralise every URL in `text` that the allowed set does not name verbatim.
 *
 * @param {string} input the untrusted markdown (model answer, a bot-written text block, a step's section)
 * @param {string[]|Set<string>} allowedUrls the URLs the report's own items carry, verbatim
 * @param {{demoteHeadings?: boolean}} [options] `demoteHeadings` rewrites every heading token as bold
 *   text of its own words, in this same pass (see AN UNTRUSTED BODY MAY NOT CARRY A HEADING)
 * @returns {string} the same text with refused URLs become plain `[link removed: <host>]` text, images
 *   dropped, a fenced spec demoted to code and (on request) every heading demoted to bold text; "" when
 *   nothing of it could be kept
 */
export function neutralizeLinks(input, allowedUrls, options) {
  const text = typeof input === "string" ? input : input == null ? "" : String(input);
  if (!text) return "";
  const allowed = toAllowedSet(allowedUrls);
  const opts = optionsOf(options);
  if (text.length > MAX_LEX_CHARS) {
    const escaped = escapeWhole(text, opts);
    const closed = opts.demoteHeadings ? escaped + openFenceCloser(escaped) : escaped;
    return hasForeignUrl(closed, allowed, opts) ? "" : closed;
  }
  // `lexOrNull` reads a text with no final line break as one that carries it, so the walk's own answer can
  // end with a break this text never had: it is dropped again below.
  const padded = !text.endsWith("\n");
  const tokens = lexOrNull(text);
  // An EMPTY answer is a real answer (a body that was nothing but a dropped image), so the walk's own
  // success is tracked rather than read off `out`: only a walk that did not finish falls back.
  let out = "";
  let walked = false;
  if (tokens) {
    try {
      out = renderTokens(tokens, allowed, opts);
      walked = true;
    } catch {
      walked = false;
    }
  }
  if (walked) {
    if (padded && out.endsWith("\n")) out = out.slice(0, -1);
    if (opts.demoteHeadings) out += openFenceCloser(out);
    if (!hasForeignUrl(out, allowed, opts)) return out;
  }
  const escaped = escapeWhole(text, opts);
  const closed = opts.demoteHeadings ? escaped + openFenceCloser(escaped) : escaped;
  if (!hasForeignUrl(closed, allowed, opts)) return closed;
  return "";
}