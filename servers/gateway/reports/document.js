/**
 * Report document assembly: the present blocks' sections become the run's artifact `source`.
 *
 * The shape is the one the artifacts renderer requires for a `document` version (see
 * bundles/artifacts/server/render.js), `{markdown, assets?}`, plus the links the run may show and a
 * small summary. A bare markdown string would lose the map plot's own file, so the source is always an
 * object here.
 *
 * WHAT THE BODY IS, in order:
 *   1. the late line, for a run the engine marked late (`run.late`), which is the first line of the body;
 *   2. the present blocks' sections in recipe order (the executor hands them over in that order);
 *   3. every AI section (a main model block or an `annotate` one) LAST, under one `##` heading that says
 *      who wrote it: `## AI commentary (written by <bot name>, not part of the fixed report)`. The `##` is
 *      the assembly's own: an untrusted body may carry no heading (every model, bot and step path demotes
 *      them), so a bot's bold line can only ever sit beside the attribution, never pass for it.
 * A run that found nothing has one body line instead of any section: `emptyText`, defaulting to
 * `Nothing new this time.` (a recipe may set its own; it is a presentational setting).
 *
 * THE TWO LIMITS are the artifact renderer's own, and both are checked HERE, before the bridge writes a
 * version: markdown over `documentMarkdownBytes` (256 KB) or more than `specsPerVersion` (12) fenced
 * charts. A document over either fails the run with one sentence naming both numbers and what to do.
 * The numbers are copied from bundles/artifacts/server/limits.js rather than imported: a `servers/`
 * module never imports bundle code statically (a bundle is something a person installs), and the copy is
 * pinned to the bundle's LIMITS by tests/reports-document.test.js. The chart count is LEXED from the
 * markdown that will be written (`countSpecFences`), never read from a section's own `specs` field: a
 * section is written by a block, and a custom step's own word is not evidence about its own output. The
 * count is also VOUCHED FOR: only a chart section's own output may contribute a spec fence, so a body
 * carrying more fences than those sections account for fails closed on the same too-large path.
 *
 * HOW A SECTION IS JOINED, and what one section may not do to the next:
 *   - its leading blank lines and its trailing whitespace are dropped, and NOTHING else. A section's
 *     first line keeps its own indent, because that indent is what decides whether the line is an
 *     indented code block or live markdown once it sits in the document: a `trim()` here would turn
 *     `    [x](url)` (a code line to the lexer) into a link in the body;
 *   - an unterminated fence is closed at the end of EVERY section, trusted or not, so a section cannot
 *     swallow the table or the attribution written after it even when `neutralizeLinks` is bypassed. WHICH
 *     fence is open is the lexer's answer, not a line scan's: a fence inside a list item or a blockquote
 *     ends with its own container, so it gets no closer (a column-0 closer after it would be a NEW
 *     top-level opener and would swallow what follows). The helper is `neutralizeLinks`'s own
 *     (`openFenceCloser`), so both paths close the same fences and no others;
 *   - an untrusted section's link reference definitions are dropped (`dropDefinitions`), so a
 *     `[x]: url` line in one section cannot resolve a `[x]` written in another;
 *   - the boundary between two sections is a blank line, and (in front of an UNTRUSTED section whose first
 *     line is indented or opens a blockquote, when the section before it ends inside a list or a
 *     blockquote) a thematic break `***` (`boundarySeparator`). A container left open would absorb that
 *     first line as its own markdown, which turns a section's indented code line into live markdown.
 *     `***` carries no heading (unlike a setext underline, which would join the line before it) and no
 *     link, and the line after it is a fresh indented code block. Between two parts the owner wrote there
 *     is no rule: an owner's own indented line joining an owner's own list is the owner's markdown, and a
 *     rule between two trusted parts is only noise;
 *   - after joining, the ASSEMBLED body is lexed and every link, image, bare URL, raw HTML token and
 *     heading it carries is compared with the parts that carried them (`assertJoinClean`). The budget is
 *     what the trusted sections (an owner's own text block, tables, cards, charts, maps, the assembly's
 *     own lines) carry, plus what an untrusted section carries only when the run's allowed set names the
 *     href and the shape is a link rather than an image, HTML or heading. A shape the joined body carries
 *     beyond that budget was made by the join or by a part nobody approved, and the run fails closed on
 *     the assembly's existing `too_large` code rather than writing a body with it. The join may also not
 *     LOSE a block: a trusted part keeps at least the top-level tokens it lexes to on its own, or the run
 *     fails on that same code.
 *
 * WHAT A RECIPE STRING MAY NOT DO: a recipe is bot-authorable, so the words it contributes to the body
 * (`emptyText`, a heading, a table column name, a card field name, the bot's display name) all go
 * through ONE helper, `escapeRecipeText`: escaped markdown, no line break, and nothing that could
 * autolink. A value read from the run's own items is `escapeMd`/`cellMarkdown` instead: it is data the
 * reader can already see, and its bare URLs are left as the words they are.
 *
 * THE ALLOWED LINKS are the http(s) URLs found verbatim in the run's items' own string fields: the set a
 * reader can already see in the report data. `neutralizeLinks` keeps a URL only from this set, so this is
 * the one place that set is built. `normalizeAllowedLinks` (the artifact bridge's) applies the record's
 * own caps: 2000 links, 2048 characters each, http(s) only.
 */
import { Marked } from "marked";
import { normalizeAllowedLinks } from "./artifact-bridge.js";
import { breakUrlText, openFenceCloser } from "./email/neutralize-links.js";
import { isUntrustedItem } from "./untrusted-items.js";

/** The line a late run starts with. */
export const LATE_LINE = "This run is late: Crow was off at the scheduled time.";

/** The body of a run that found nothing. */
export const DEFAULT_EMPTY_TEXT = "Nothing new this time.";

/** The one sentence a document over a size limit fails with. */
export const TOO_LARGE_TEXT =
  "This report is too large to save (over 256 KB of text or more than 12 charts). Narrow the filters or split it.";

/** The name a document with no readable bot name gives its AI section. */
export const UNNAMED_BOT = "bot";

/**
 * The artifact renderer's document limits: `documentMarkdownBytes` and `specsPerVersion`. See the header
 * for why these two numbers are held here.
 */
export const DOCUMENT_LIMITS = Object.freeze({
  documentMarkdownBytes: 256 * 1024,
  specsPerVersion: 12,
});

/** The section types that are a model's own writing, so they always come last. */
export const AI_SECTION_TYPES = Object.freeze(["ai_commentary", "annotate"]);

/**
 * The fence languages the artifacts renderer draws as a picture rather than as code (its own
 * `SPEC_ENGINES`): a fenced block in one of these is one of the document's twelve specs.
 */
export const SPEC_FENCE_LANGS = Object.freeze(["vega-lite", "mermaid", "d2"]);

/**
 * The section types whose own output may carry a chart or diagram fence: the `chart` block writes one
 * `vega-lite` fence, and no other block writes a fence of a spec engine at all. The assembly compares the
 * body's lexed count against these sections (see `assembleDocument`).
 */
export const SPEC_SECTION_TYPES = Object.freeze(["chart"]);

function fail(code, message) {
  const err = new Error(message || code);
  err.code = code;
  return err;
}

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

/**
 * One item's field: its own key, or a dotted path into its objects (`attributes.title`). The same reader
 * the shape blocks use, so a column name means one thing across a recipe.
 */
export function readItemField(item, field) {
  if (item == null || typeof field !== "string" || !field) return undefined;
  if (Object.hasOwn(item, field)) return item[field];
  let cursor = item;
  for (const part of field.split(".")) {
    if (cursor == null || typeof cursor !== "object" || !Object.hasOwn(cursor, part)) return undefined;
    cursor = cursor[part];
  }
  return cursor;
}

/** The run's own day as `YYYY-MM-DD`, from its start time, else the injected clock. */
export function runDayText(run, deps = {}) {
  const started = Number(run?.startedAt ?? run?.started_at ?? run?.createdAt ?? run?.created_at);
  const clock = typeof deps?.now === "function" ? Number(deps.now()) : NaN;
  const ms = Number.isFinite(started) ? started : (Number.isFinite(clock) ? clock : Date.now());
  const at = new Date(ms);
  return Number.isFinite(at.getTime()) ? at.toISOString().slice(0, 10) : "";
}

/**
 * The characters that must never end the line a value is written on: a raw CR or LF would break a table
 * cell (or a heading) in two, and the invisible line separators would do the same. A run of them becomes
 * one space, so the value stays where it was put and stays on one line.
 */
const LINE_BREAKING = /[\r\n\u000b\u000c\u0085\u00a0\u2028\u2029]+/g;

/**
 * A value at the START of a line must not open a block: `#` a heading, `-`/`+` a list item, `=` a setext
 * underline, digits with `.` or `)` an ordered one, or a run of three or more `~`/backticks a code fence.
 * The marker is backslash-escaped (markdown draws an escaped character as itself), and only the marker:
 * `-5` and `#tag` are left alone. A leading `>` needs no help here, because `escapeMd` has already
 * written it as `&gt;`.
 */
function escapeLineStart(text) {
  const lead = /^\s*/.exec(text)[0];
  const rest = text.slice(lead.length);
  const ordered = /^(\d{1,9})([.)])(?=\s|$)/.exec(rest);
  if (ordered) return `${lead}${ordered[1]}\\${ordered[2]}${rest.slice(ordered[0].length)}`;
  if (/^#{1,6}(?=\s|$)/.test(rest) || /^[-+](?=\s|$)/.test(rest) || /^=+/.test(rest)
    || /^[~`]{3,}/.test(rest)) {
    return `${lead}\\${rest}`;
  }
  return text;
}

/**
 * Escape a value for a markdown table cell or a heading: pipes, backticks, brackets and HTML, with every
 * line break flattened to one space and no block marker left able to open a line. This is the escaping
 * for a value READ FROM DATA; a recipe's own words take `escapeRecipeText`, which breaks autolinks too.
 */
export function escapeMd(value) {
  const flat = String(value == null ? "" : value).replace(LINE_BREAKING, " ");
  const escaped = flat
    .replace(/\\/g, "\\\\")
    .replace(/&/g, "&amp;")
    .replace(/\|/g, "\\|")
    .replace(/`/g, "\\`")
    .replace(/\[/g, "\\[")
    .replace(/\]/g, "\\]")
    .replace(/\*/g, "\\*")
    .replace(/_/g, "\\_")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return escapeLineStart(escaped);
}

/**
 * A recipe string as inert markdown: `escapeMd`, and then nothing in it that could autolink, because
 * `www.` and a scheme's colon become character references (the trick neutralize-links uses on text that
 * must not read as a link). A recipe is bot-authorable, so the empty-run line, a heading, a table column
 * name, a card field name and a bot's display name all take this ONE helper. `escapeMd` has already
 * flattened every line break, so the answer is one line.
 */
export function escapeRecipeText(value) {
  return breakUrlText(escapeMd(value));
}

/**
 * The characters that make a value unfit to be a link destination, tested on the value AS IT ARRIVED.
 * `new URL()` strips tabs, newlines and spaces and will happily read `<`, `|` and a backslash inside a
 * path, so a value carrying one would reach the destination in a shape the source value never had.
 */
const UNSAFE_DESTINATION = /[<>|\\\s\u0000-\u001f\u007f-\u009f\u2028\u2029]/;

/**
 * The href a source-data value may become: `new URL(value).href`, for an http(s) value only, or "" when
 * the value may not be a link destination at all. The refusal list is checked BEFORE normalisation: a
 * value holding `<`, `>`, whitespace, `|`, a backslash or a control character is not a destination, and
 * the caller renders it as escaped plain text instead.
 */
export function linkDestination(value) {
  if (typeof value !== "string" || !value) return "";
  if (UNSAFE_DESTINATION.test(value)) return "";
  if (!/^https?:\/\//i.test(value)) return "";
  let url;
  try {
    url = new URL(value);
  } catch {
    return "";
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return "";
  return url.href;
}

/**
 * One cell as markdown: escaped text, or a link when the value is a whole http(s) URL. A `javascript:`
 * or `data:` value is never a link, because it never reaches the link branch: it is escaped text. The
 * destination is `linkDestination`'s normalised href and the link text is escaped markdown of the value
 * as written, so the words a reader sees and the destination cannot disagree. The text branch is also
 * breakUrlText's: a value reading `www.evil.example` or `x@evil.example` is words, not an autolink.
 */
export function cellMarkdown(value) {
  if (value == null) return "";
  const text = typeof value === "string"
    ? value
    : (typeof value === "number" || typeof value === "boolean" ? String(value) : safeJson(value));
  const href = linkDestination(text);
  if (href) return `[${escapeMd(text)}](<${href}>)`;
  return breakUrlText(escapeMd(text));
}

/** A value JSON can write, or its text spelling when it cannot (a cycle, a bigint). */
function safeJson(value) {
  try {
    const json = JSON.stringify(value);
    return json == null ? String(value) : json;
  } catch {
    return String(value);
  }
}

const URL_IN_TEXT = /https?:\/\/[^\s<>"'`]+/gi;

/** Sentence punctuation, brackets and a full stop a URL in prose picks up from the sentence around it. */
const URL_TRAILING = ".,;:!?)]";

/**
 * Every http(s) URL a string carries: as written, and (when it differs) in the `new URL(v).href` form a
 * cell's link destination has, because `https://example.com` and `https://example.com/` are two strings
 * and the set this builds has to hold BOTH the words a source wrote and the href a cell emits.
 */
function urlsIn(text, out) {
  if (typeof text !== "string" || !text) return;
  for (const match of text.matchAll(URL_IN_TEXT)) {
    const whole = match[0];
    let url = whole;
    while (url && URL_TRAILING.includes(url[url.length - 1])) url = url.slice(0, -1);
    if (!url) continue;
    out.push(url);
    // The `new URL(v).href` form of the URL as the sentence spells it AND of the whole value: a cell
    // whose value IS the URL emits the normalised href, which is a different string from either.
    for (const candidate of [url, whole]) {
      const href = linkDestination(candidate);
      if (href && href !== url) out.push(href);
    }
  }
}

/** How deep into a nested item field the link walk goes: a column may name a dotted path, not a forest. */
const MAX_FIELD_DEPTH = 8;

/** Every URL one item field carries, at any depth (a nested object is a dotted column's data). */
function fieldLinks(node, out, depth) {
  if (depth > MAX_FIELD_DEPTH) return;
  if (typeof node === "string") {
    urlsIn(node, out);
    return;
  }
  if (Array.isArray(node)) {
    for (const entry of node) fieldLinks(entry, out, depth + 1);
    return;
  }
  if (!isPlainObject(node)) return;
  for (const value of Object.values(node)) fieldLinks(value, out, depth + 1);
}

/**
 * The URLs the run's items carry, verbatim, in item order: every string field, every string in a field's
 * array (mail items carry their own `links[]`), and every string inside a nested object (a column or a
 * card field may name a dotted path such as `attributes.link`). A link a model wrote is kept only when
 * it is one of these, so this set is exactly what the reader can already see.
 *
 * ITEMS A CUSTOM STEP PRODUCED CONTRIBUTE NOTHING (untrusted-items.js). Such an item is data the
 * document shows, never evidence about where a link may point: a step's own URL would otherwise approve
 * itself here, for its own section and for every block after it.
 *
 * @param {object[]} items
 * @returns {string[]} un-normalised URLs, duplicates included (the caller's normaliser caps and dedupes)
 */
export function itemLinks(items) {
  const found = [];
  for (const item of Array.isArray(items) ? items : []) {
    if (!isPlainObject(item)) continue;
    if (isUntrustedItem(item)) continue;
    for (const value of Object.values(item)) fieldLinks(value, found, 1);
  }
  return found;
}

/** How many items the shape blocks marked as new by `diff_last`. */
export function newCountOf(items) {
  if (!Array.isArray(items)) return 0;
  return items.filter((item) => isPlainObject(item) && item._diff === "new").length;
}

/** Is this run one the engine recorded as late? The run row stores 1, the mapped row either. */
function isLateRun(run) {
  if (run == null) return false;
  return run.late === true || Number(run.late) === 1;
}

/** Is this section a model block's own writing? */
export function isAiSection(section) {
  return !!section && typeof section === "object" && AI_SECTION_TYPES.includes(section.type);
}

/**
 * The `##` heading the AI sections sit under, naming the bot that wrote them (a recipe-bound name). The
 * level is the assembly's own: no section's text may carry a heading, so this one is a heading no bot's
 * bold line can be mistaken for.
 */
export function aiHeading(botName) {
  const name = escapeRecipeText(String(botName == null ? "" : botName).trim()) || UNNAMED_BOT;
  return `## AI commentary (written by ${name}, not part of the fixed report)`;
}

/**
 * One section's markdown as it goes into the body: its leading blank lines and its trailing whitespace are
 * dropped, and nothing else. The first line's own indentation is part of what the line means once the
 * section is joined to the ones before it (four spaces make it an indented code block), so it is never
 * trimmed away here.
 */
function sectionBody(markdown) {
  return String(markdown).replace(/^(?:[ \t]*\n)+/, "").replace(/\s+$/, "");
}

/**
 * The closing fence an unterminated fence at the end of this markdown needs, else "". Applied at the end
 * of every section, trusted or not, and independently of `neutralizeLinks`: a fence a section leaves open
 * would otherwise swallow the table, the next section or the attribution written after it.
 *
 * WHICH fence, and whether any, is `neutralizeLinks`'s own answer (`openFenceCloser`, shared so both paths
 * agree): only a fence the lexer reads as a top-level block whose raw carries no closer line is closed,
 * with its own indent. A fence a list item or a blockquote holds ends with that container, and a column-0
 * closer after it would be a NEW top-level opener that swallows the table and the attribution.
 */
function fenceCloser(markdown) {
  return openFenceCloser(markdown);
}

/** Is this section's markdown text nobody approved: a model's, a custom step's, a bot's text block? */
function isUntrustedSection(section) {
  if (isAiSection(section)) return true;
  if (section.type === "custom") return true;
  // A `text` block rides with the `authoredBy` stamp its recipe block carries: text.js renders an owner's
  // own body and heading as written and neutralises every other stamp, so only an explicit `owner` stamp
  // is trusted here, and a section that carries none is neutralised like a bot's.
  if (section.type === "text") return section.authoredBy !== "owner";
  return false;
}

/** One part of the body: its markdown, who wrote it, and the tokens it lexes to (null if unreadable). */
function makePart(text, trusted) {
  return { text, trusted, tokens: tokensOf(text) };
}

/**
 * One section as the part it contributes: its own leading blank lines and trailing whitespace dropped, its
 * link reference definitions dropped when nobody approved the text, and an unterminated fence closed at
 * its end. Null for a section that contributes nothing (empty, blank, or nothing but definitions).
 */
function sectionPart(section) {
  const body = sectionBody(section.markdown);
  if (!body) return null;
  const untrusted = isUntrustedSection(section);
  const text = untrusted ? sectionBody(dropDefinitions(body)) : body;
  if (!text) return null;
  return makePart(text + fenceCloser(text), !untrusted);
}

/** The parts joined in order, each boundary the separator the pair of them needs. */
function joinParts(parts) {
  let out = "";
  for (let index = 0; index < parts.length; index += 1) {
    if (index > 0) out += boundarySeparator(parts[index - 1], parts[index]);
    out += parts[index].text;
  }
  return out;
}

/**
 * A markdown's tokens as the renderer's own lexer reads them, or null when the lexer refuses it. A body
 * the lexer refuses fails the run before it is written (`countSpecFences` reads it as over the limit), so
 * a null here is only ever carried, never turned into a document.
 */
function tokensOf(text) {
  try {
    const tokens = markdownLexer.lexer(String(text));
    return Array.isArray(tokens) ? tokens : null;
  } catch {
    return null;
  }
}

/** The child tokens of a container token, in reading order. */
function childTokens(token) {
  const kids = [];
  for (const key of ["tokens", "items", "header"]) {
    if (Array.isArray(token[key])) for (const kid of token[key]) kids.push(kid);
  }
  if (Array.isArray(token.rows)) {
    for (const row of token.rows) if (Array.isArray(row)) for (const kid of row) kids.push(kid);
  }
  return kids;
}

/** Every token a markdown carries, at any depth (a table cell, a list item, a blockquote). */
function allTokensOf(tokens) {
  const all = [];
  const seen = new Set();
  const stack = Array.isArray(tokens) ? [...tokens] : [];
  while (stack.length) {
    const token = stack.pop();
    if (token == null || typeof token !== "object" || seen.has(token)) continue;
    seen.add(token);
    all.push(token);
    for (const kid of childTokens(token)) stack.push(kid);
  }
  return all;
}

/**
 * A markdown with its link reference definitions taken out, the lexer's way: every top-level `def`
 * token's own text goes, and the line breaks it carried stay, so the blocks around it are not glued
 * together. Only a top-level definition reaches another section: one written inside a blockquote or a
 * list item is scoped to that container by the renderer's own grammar.
 */
function dropDefinitions(text) {
  const source = String(text);
  const tokens = tokensOf(source);
  if (!tokens) return source;
  let out = "";
  let cursor = 0;
  for (const token of tokens) {
    if (token == null || token.type !== "def" || typeof token.raw !== "string" || !token.raw) continue;
    const at = source.indexOf(token.raw, cursor);
    if (at < 0) continue;
    const breaks = token.raw.split("\n").length - 1;
    out += source.slice(cursor, at) + "\n".repeat(breaks);
    cursor = at + token.raw.length;
  }
  return out + source.slice(cursor);
}

/** The body of a run that found nothing: the recipe's own words, else the default. */
function emptyTextOf(emptyText) {
  if (typeof emptyText === "string" && emptyText.trim()) return escapeRecipeText(emptyText.trim());
  return DEFAULT_EMPTY_TEXT;
}

/** The lexer the spec count reads with: the artifacts renderer's own document options. */
const markdownLexer = new Marked({ gfm: true, breaks: true });

/** The token types a clickable link is spelled with: see `assertJoinClean`. */
const LINK_TOKEN_TYPES = Object.freeze(["link", "image", "url", "autolink"]);

/** A token's own URL: a link's or an image's `href`, a bare URL's or autolink's target. */
function hrefOf(token) {
  if (typeof token?.href === "string" && token.href) return token.href;
  if (typeof token?.text === "string") return token.text;
  return "";
}

/**
 * One part's judged shapes: its link tokens with their own hrefs, and how many raw HTML tokens and
 * headings it carries, at any depth. A `space` token carries none of them and is not asked.
 */
function partShapes(tokens) {
  const shapes = { links: [], html: 0, headings: 0 };
  for (const token of allTokensOf(tokens)) {
    if (token.type === "html") shapes.html += 1;
    else if (token.type === "heading") shapes.headings += 1;
    else if (LINK_TOKEN_TYPES.includes(token.type)) {
      shapes.links.push({ type: token.type, href: hrefOf(token) });
    }
  }
  return shapes;
}

/** The last block a part lexes to, the `space` tokens between blocks left out, or null. */
function lastBlockOf(tokens) {
  if (!Array.isArray(tokens)) return null;
  for (let index = tokens.length - 1; index >= 0; index -= 1) {
    const token = tokens[index];
    if (token == null || token.type === "space") continue;
    return token;
  }
  return null;
}

/**
 * Does this part's first line let the part before it carry it on? An indented line joins a list item's own
 * markdown and a `>` line joins a blockquote; both are what `boundarySeparator` guards against.
 */
function opensInsideContainer(part) {
  const first = String(part?.text == null ? "" : part.text).split("\n")[0];
  return /^[ \t]/.test(first) || /^[ \t]*>/.test(first);
}

/**
 * What sits between two parts. A blank line is the separator a document has always used, and it is
 * enough unless the part before leaves a container open that the part after would carry on: a list or a
 * blockquote running on absorbs an indented line as its own markdown, which is how an indented code line
 * of a section nobody approved becomes live markdown of the report. In that one case a thematic break ends
 * the container first. `***` adds no heading (a setext underline would join the line before it), no raw
 * HTML and no link, and an indented line after it is a fresh indented code block, so the line keeps the
 * indent it came with.
 *
 * The rule is only for a part nobody approved: between two parts the owner wrote there is nothing to
 * guard, and an owner's own indented line joining an owner's own list is the owner's own markdown, so no
 * visible rule is drawn there.
 */
function boundarySeparator(previous, next) {
  if (next == null || next.trusted) return "\n\n";
  if (!opensInsideContainer(next)) return "\n\n";
  const last = lastBlockOf(previous?.tokens);
  if (last == null || last.type === "list" || last.type === "blockquote") return "\n\n***\n\n";
  return "\n\n";
}

/** One part's top-level blocks: the tokens the lexer put in the document's own list, `space` left out. */
function topLevelCount(tokens) {
  if (!Array.isArray(tokens)) return 0;
  return tokens.filter((token) => token != null && token.type !== "space").length;
}

/**
 * The blocks the parts carry on their own, which the join may not take away. A part the owner wrote counts
 * all of its own top-level blocks, except one whose first line is indented or quoted after a part that
 * ends in a list or a blockquote: that line may join the container before it (no rule is drawn between two
 * parts the owner wrote, see `boundarySeparator`), and it is the owner's own markdown either way.
 */
function expectedTopLevel(parts) {
  let expected = 0;
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (!part || part.trusted !== true) continue;
    if (index > 0 && opensInsideContainer(part)) {
      const last = lastBlockOf(parts[index - 1]?.tokens);
      if (last != null && (last.type === "list" || last.type === "blockquote")) continue;
    }
    expected += topLevelCount(part.tokens);
  }
  return expected;
}

/**
 * The joined body may carry no link, image, bare URL, raw HTML token or heading beyond what its parts
 * account for. A trusted part accounts for all of its own. An untrusted part accounts only for its link
 * tokens whose href the run's allowed set names, and never for an image, raw HTML or heading: nothing
 * there approved those. A shape the joined body carries past that budget was made by the join itself (a
 * `[x]` in one section resolved by a definition in another) or came from a part nobody approved, so the
 * document fails closed on the existing assembly code rather than being written with it.
 *
 * The join may not LOSE a block either. The bottom-level guard is the lexer's own count: the trusted parts
 * keep at least the top-level blocks they lex to on their own (see `expectedTopLevel`), so a join that
 * swallows an owner's table or the attribution fails on the same code.
 *
 * @param {string} markdownText the joined body
 * @param {{text: string, trusted: boolean, tokens: object[]|null}[]} parts
 * @param {Set<string>} allowedSet the run's allowed links
 * @returns {void}
 * @throws {Error} `too_large` with `TOO_LARGE_TEXT` when the body carries a shape its parts do not, or
 *   loses a top-level block a trusted part carried
 */
function assertJoinClean(markdownText, parts, allowedSet) {
  const budget = { links: 0, html: 0, headings: 0 };
  const trustedHrefs = new Set();
  for (const part of parts) {
    const shapes = partShapes(part.tokens);
    if (part.trusted) {
      budget.links += shapes.links.length;
      budget.html += shapes.html;
      budget.headings += shapes.headings;
      for (const link of shapes.links) trustedHrefs.add(link.href);
      continue;
    }
    budget.links += shapes.links.filter((link) => link.type !== "image" && allowedSet.has(link.href)).length;
  }
  const joinedTokens = tokensOf(markdownText);
  const joined = partShapes(joinedTokens);
  const beyond = joined.links.length > budget.links || joined.html > budget.html
    || joined.headings > budget.headings;
  // A link the joined body shows must be one the run's own data carries or one a trusted part wrote, so
  // a definition an owner's block leaves behind still cannot send a reader anywhere else.
  const foreign = joined.links.some((link) => !allowedSet.has(link.href) && !trustedHrefs.has(link.href));
  if (beyond || foreign) throw fail("too_large", TOO_LARGE_TEXT);
  if (topLevelCount(joinedTokens) < expectedTopLevel(parts)) throw fail("too_large", TOO_LARGE_TEXT);
}

/** A code token's language, spelled the way the artifacts renderer spells it. */
function fenceLangOf(token) {
  return String(token?.lang || "").trim().split(/\s+/)[0].toLowerCase();
}

/**
 * How many chart/diagram fences a document carries, LEXED from the markdown that will be written. The
 * artifacts renderer counts its own `SPEC_ENGINES` over the top-level blocks it renders, so this counts
 * the same tokens, and a section's `specs` field is never asked.
 *
 * A markdown the lexer refuses counts as over the limit: a body this module cannot read is not one it
 * hands to a renderer that reads it the same way.
 *
 * @param {string} markdownText
 * @returns {number} the fence count, or Infinity when the body cannot be lexed
 */
export function countSpecFences(markdownText) {
  if (typeof markdownText !== "string" || !markdownText) return 0;
  let tokens;
  try {
    tokens = markdownLexer.lexer(markdownText);
  } catch {
    return Number.POSITIVE_INFINITY;
  }
  let count = 0;
  for (const token of tokens) {
    if (token != null && token.type === "code" && SPEC_FENCE_LANGS.includes(fenceLangOf(token))) {
      count += 1;
    }
  }
  return count;
}

/**
 * Assemble one run's document.
 *
 * @param {{report?: object|null, run?: object|null, sections?: object[], items?: object[],
 *   allowedLinks?: string[], botName?: string, emptyText?: string, limits?: object}} [input]
 * @returns {{source: {markdown: string, assets?: object[]}, allowedLinks: string[],
 *   summary: {count: number, newCount: number, headline: string}}}
 * @throws {Error} `too_large` with `TOO_LARGE_TEXT` when the markdown or the spec count is over a limit,
 *   when the body carries a spec fence no chart section's output accounts for, or when the joined body
 *   carries a link, an image, raw HTML or a heading its own parts do not account for
 */
export function assembleDocument({
  report = null, run = null, sections = [], items = [], allowedLinks = [], botName = "",
  emptyText = DEFAULT_EMPTY_TEXT, limits = DOCUMENT_LIMITS,
} = {}) {
  const list = Array.isArray(sections) ? sections.filter((section) => section && typeof section.markdown === "string") : [];
  const allItems = Array.isArray(items) ? items : [];
  const links = normalizeAllowedLinks([
    ...itemLinks(allItems),
    ...(Array.isArray(allowedLinks) ? allowedLinks : []),
  ]);

  const parts = [];
  const included = [];
  if (isLateRun(run)) parts.push(makePart(LATE_LINE, true));
  if (!allItems.length) {
    parts.push(makePart(emptyTextOf(emptyText), true));
  } else {
    for (const section of list) {
      if (isAiSection(section)) continue;
      const part = sectionPart(section);
      if (!part) continue;
      parts.push(part);
      included.push(section);
    }
    const aiParts = [];
    for (const section of list) {
      if (!isAiSection(section)) continue;
      const part = sectionPart(section);
      if (part) aiParts.push({ section, part });
    }
    if (aiParts.length) {
      parts.push(makePart(aiHeading(botName), true));
      for (const { section, part } of aiParts) {
        parts.push(part);
        included.push(section);
      }
    }
  }

  // Only what the body actually carries ships with it. The chart count is lexed from the body below:
  // a section's own `specs` is a claim about itself, and the custom block's is untrusted.
  const assets = [];
  for (const section of included) {
    if (Array.isArray(section.assets)) for (const asset of section.assets) assets.push(asset);
  }

  const markdown = joinParts(parts);
  const specs = countSpecFences(markdown);
  const limitBytes = Number(limits?.documentMarkdownBytes ?? DOCUMENT_LIMITS.documentMarkdownBytes);
  const limitSpecs = Number(limits?.specsPerVersion ?? DOCUMENT_LIMITS.specsPerVersion);
  if (Number.isFinite(limitBytes) && limitBytes > 0
    && Buffer.byteLength(markdown, "utf8") > limitBytes) {
    throw fail("too_large", TOO_LARGE_TEXT);
  }
  if (Number.isFinite(limitSpecs) && limitSpecs >= 0 && specs > limitSpecs) {
    throw fail("too_large", TOO_LARGE_TEXT);
  }
  // Only a chart section's own output may contribute a spec fence. The count above is lexed from the
  // joined body, so a fence any other section carried into it is a picture nothing here vouched for: the
  // document fails closed on the same path rather than being written with it.
  const vouchedSpecs = included.reduce((count, section) => (
    SPEC_SECTION_TYPES.includes(section.type) ? count + countSpecFences(sectionBody(section.markdown)) : count
  ), 0);
  if (specs > vouchedSpecs) throw fail("too_large", TOO_LARGE_TEXT);
  assertJoinClean(markdown, parts, new Set(links));

  const source = { markdown };
  if (assets.length) source.assets = assets;
  return {
    source,
    allowedLinks: links,
    summary: {
      count: allItems.length,
      newCount: newCountOf(allItems),
      headline: String(allItems.length),
    },
  };
}