/**
 * sanitizeOutgoing: what a report email may carry out of Crow.
 *
 * The html is cleaned by an allow-list, not a deny-list: a script, a handler, a form, a frame, an
 * object, a stylesheet or a `style` attribute never survives, a `javascript:` or non-image `data:`
 * href loses its href (the text stays), and an image is kept only as an inline base64 png, jpeg or gif
 * so a remote image can never be a tracking pixel.
 *
 * Then one rule judges every link, in both halves of the mail: a web address that is not verbatim one of
 * the run's own URLs is replaced outright by `[link removed]`, with no host named. In the html the text is
 * read the way a mail client draws it (character references decoded, the invisible and format classes
 * removed), a block whose URL only becomes whole once inline markup is dropped is flattened first, and an
 * anchor is judged by its href (a refused one goes whole). The plain text is stripped of what a plain-text
 * client never draws and judged exactly as it is sent, so nothing there is decoded or joined.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  neutralizeHtmlLinks,
  sanitizeHtml,
  sanitizeOutgoing,
} from "../servers/gateway/reports/email/sanitize-outgoing.js";
import { normalizeView } from "../servers/gateway/reports/email/normalize-text.js";
import { EMAIL_LINK_REMOVED } from "../servers/gateway/reports/email/copy.js";

const ALLOWED = ["https://good.example/a", "https://good.example/b?x=1&y=2", "mailto:alex@example.com"];

const htmlOf = (html, allowed = []) => sanitizeOutgoing({ html }, allowed).html;
const textOf = (text, allowed = []) => sanitizeOutgoing({ text }, allowed).text;

/** The one text a refused address leaves. */
const GONE = EMAIL_LINK_REMOVED;

/* --------------------------------------------------------------------- the sanitiser */

test("a script tag and its code are dropped", () => {
  const html = htmlOf('<p>hello</p><script>alert("x")</script>');
  assert.equal(html, "<p>hello</p>");
});

test("an onclick handler is dropped and its tag kept", () => {
  const html = htmlOf('<p onclick="alert(1)">hello</p>');
  assert.equal(html, "<p>hello</p>");
});

test("form and input are dropped", () => {
  const html = htmlOf('<form action="https://evil.example/steal"><input name="q"><button>go</button></form><p>after</p>');
  assert.equal(html, "<p>after</p>");
});

test("iframe, object and embed are dropped", () => {
  assert.equal(htmlOf('<iframe src="https://evil.example/"></iframe>'), "");
  assert.equal(htmlOf('<object data="https://evil.example/x"></object>'), "");
  assert.equal(htmlOf('<embed src="https://evil.example/x">'), "");
});

test("a javascript: href is removed and its text stays", () => {
  const html = htmlOf('<a href="javascript:alert(1)">click</a>');
  assert.equal(html, "click");
});

test("a data:text/html href is removed and its text stays", () => {
  const html = htmlOf('<a href="data:text/html;base64,PHNjcmlwdD4=">click</a>');
  assert.equal(html, "click");
});

test("every casing and encoding of javascript: is refused", () => {
  const html = htmlOf(
    '<a href="jav&#x61;script:alert(1)">a</a>'
    + '<a href="JaVaScRiPt:alert(2)">b</a>'
    + '<a href="java&#9;script:alert(3)">c</a>'
    + '<a href="&#106;avascript:alert(4)">d</a>',
  );
  assert.equal(html, "abcd");
  assert.ok(!html.toLowerCase().includes("javascript"));
});

test("an inline base64 png/jpeg/gif image is kept", () => {
  const png = htmlOf('<img src="data:image/png;base64,iVBORw0KGgo=">');
  assert.equal(png, '<img src="data:image/png;base64,iVBORw0KGgo=" />');
  assert.ok(htmlOf('<img src="data:image/jpeg;base64,abcd=">').includes("data:image/jpeg"));
  assert.ok(htmlOf('<img src="data:image/gif;base64,abcd=">').includes("data:image/gif"));
});

test("a non-image data: image source and every remote image are dropped with the tag", () => {
  assert.equal(htmlOf('<img src="data:image/svg+xml;base64,PHN2Zz4=">'), "");
  assert.equal(htmlOf('<img src="data:text/html;base64,PHNjcmlwdD4=">'), "");
  assert.equal(htmlOf('<img src="https://tracker.example/p.gif" width="1" height="1">'), "");
  assert.equal(htmlOf('<img src="//tracker.example/p.gif">'), "");
  assert.equal(htmlOf('<img src="pixel.gif">'), "");
  assert.equal(htmlOf("<img>"), "");
});

test("a style tag and a style attribute with an import or url() are dropped", () => {
  const html = htmlOf(
    '<style>@import url("https://evil.example/x.css");</style>'
    + '<p style="background:url(https://evil.example/p.gif)">hello</p>',
  );
  assert.equal(html, "<p>hello</p>");
  assert.ok(!html.includes("@import"));
  assert.ok(!html.includes("style"));
});

test("a link rel=stylesheet is dropped", () => {
  assert.equal(htmlOf('<link rel="stylesheet" href="https://evil.example/x.css"><p>hello</p>'), "<p>hello</p>");
});

test("non-string and missing input is an empty part, never a throw", () => {
  assert.deepEqual(sanitizeOutgoing(), { html: "", text: "" });
  assert.deepEqual(sanitizeOutgoing(null, null), { html: "", text: "" });
  assert.deepEqual(sanitizeOutgoing({ html: 42, text: 42 }), { html: "", text: "" });
  assert.deepEqual(sanitizeOutgoing({ html: null, text: undefined }), { html: "", text: "" });
  assert.equal(sanitizeHtml(42), "");
  assert.equal(sanitizeHtml(null), "");
  assert.equal(neutralizeHtmlLinks(null), "");
  assert.equal(neutralizeHtmlLinks('<a href="https://evil.example/">x</a>', "not a list"), GONE);
});

/* ------------------------------------------------------------------------ the anchors */

test("an allowed link is kept", () => {
  const html = htmlOf('<p><a href="https://good.example/a">go</a></p>', ALLOWED);
  assert.equal(html, '<p><a href="https://good.example/a">go</a></p>');
  // The allowed URL is the run's own, so its `&` (written `&amp;` in the html) still matches verbatim.
  assert.equal(
    htmlOf('<a href="https://good.example/b?x=1&amp;y=2">go</a>', ALLOWED),
    '<a href="https://good.example/b?x=1&amp;y=2">go</a>',
  );
  assert.equal(htmlOf('<a href="mailto:alex@example.com">mail</a>', ALLOWED), '<a href="mailto:alex@example.com">mail</a>');
});

test("a refused anchor is replaced whole, words and href, by the refusal text", () => {
  assert.equal(
    htmlOf('<p><a href="https://evil.example/secret/path?q=1">click</a></p>', ALLOWED),
    `<p>${GONE}</p>`,
  );
  const marked = htmlOf('<p>See <a href="https://evil.example/x"><b>the list</b></a> now.</p>', ALLOWED);
  assert.equal(marked, `<p>See ${GONE} now.</p>`);
  assert.ok(!marked.includes("<a "), "no anchor survives");
  assert.ok(!marked.includes("evil.example"), "no host is named");
});

test("a mailto link that is not allowed is replaced whole too", () => {
  const html = htmlOf('<a href="mailto:someone@evil.example">write</a>', ALLOWED);
  assert.equal(html, GONE);
});

test("an anchor with no href is not a link: its tag goes and its text stays", () => {
  assert.equal(htmlOf('<p><a name="top">Open the listing</a></p>', ALLOWED), "<p>Open the listing</p>");
});

test("a bare URL in a text node of the html is judged too", () => {
  assert.equal(htmlOf("<td>https://evil.example/cell</td>", ALLOWED), `<td>${GONE}</td>`);
  assert.equal(htmlOf("<p>see www.evil.example now</p>", ALLOWED), `<p>see ${GONE} now</p>`);
  assert.equal(htmlOf("<p>https://good.example/a</p>", ALLOWED),
    "<p>https://good.example/a</p>", "the run's own URL is kept verbatim");
});

test("a kept anchor's own text is never touched", () => {
  const html = '<a href="https://good.example/a">https://good.example/a</a>';
  assert.equal(htmlOf(html, ALLOWED), html);
});

/* -------------------------------------- an allowed anchor may not show a different URL */

/** The allowed set for these cases: `ok.example` is one of the run's own URLs. */
const OK = [...ALLOWED, "https://ok.example/"];
/** An allowed anchor, opened. */
const OK_OPEN = '<a href="https://ok.example/">';

test("an allowed anchor whose text shows another URL is rewritten to its href", () => {
  const rewritten = `${OK_OPEN}https://ok.example/</a>`;
  assert.equal(htmlOf(`${OK_OPEN}https://evil.example/x</a>`, OK), rewritten);
  assert.equal(htmlOf(`${OK_OPEN}www.evil.example</a>`, OK), rewritten);
  // An entity in the words, and an entity in the scheme, draw the same URL as the plain spelling.
  assert.equal(htmlOf(`${OK_OPEN}https://evil&#46;example/x</a>`, OK), rewritten);
  assert.equal(htmlOf(`${OK_OPEN}ht&#116;ps://evil.example/x</a>`, OK), rewritten);
  // An invisible character in the words is not part of them to a reader either.
  assert.equal(htmlOf(`${OK_OPEN}ht\u200btps://evil.example/x</a>`, OK), rewritten);
});

test("an allowed anchor whose words are markup around another URL is rewritten to its href", () => {
  assert.equal(
    htmlOf(`${OK_OPEN}<b>https://evil.example/x</b></a>`, OK),
    `${OK_OPEN}https://ok.example/</a>`,
  );
});

test("an allowed anchor whose URL is split by markup is rewritten to its href", () => {
  // The run only becomes whole once the `<b>` is dropped, so the anchor's own words are flattened to the
  // run first, and the anchor then shows its href because those words name another URL.
  const split = htmlOf(`${OK_OPEN}https://ev<b>il</b>.example/x</a>`, OK);
  assert.equal(split, `${OK_OPEN}https://ok.example/</a>`);
  assert.ok(!/https?:\/\/evil\.example/i.test(split), split);
});

test("an allowed anchor whose words carry no URL is unchanged", () => {
  assert.equal(htmlOf(`${OK_OPEN}Open the listing</a>`, OK), `${OK_OPEN}Open the listing</a>`);
  assert.equal(htmlOf(`${OK_OPEN}https://ok.example/</a>`, OK), `${OK_OPEN}https://ok.example/</a>`);
  assert.equal(
    htmlOf('<a href="https://good.example/b?x=1&amp;y=2">https://good.example/b?x=1&amp;y=2</a>', ALLOWED),
    '<a href="https://good.example/b?x=1&amp;y=2">https://good.example/b?x=1&amp;y=2</a>',
  );
});

/* --------------------------------------------------------------- the plain-text half */

test("a foreign link inside the text part is judged exactly as it is sent", () => {
  // No markdown parsing: the bare run between the brackets is the address, and it goes.
  assert.equal(textOf("Read [the notes](https://evil.example/notes) now.", ALLOWED),
    `Read [the notes](${GONE}) now.`);
  assert.equal(textOf("See https://evil.example/notes for more.", ALLOWED),
    `See ${GONE} for more.`);
  assert.equal(textOf("see www.evil.example now", ALLOWED), `see ${GONE} now`);
});

test("an allowed URL is kept verbatim in the text part", () => {
  assert.equal(
    textOf("See https://good.example/a and www.good.example/x.", [...ALLOWED, "www.good.example/x"]),
    "See https://good.example/a and www.good.example/x.",
  );
});

test("a sentence's own punctuation after a refused run stays where it was written", () => {
  assert.equal(textOf("Go to https://evil.example/a, then stop.", ALLOWED),
    `Go to ${GONE}, then stop.`);
  assert.equal(textOf("Go to https://evil.example/a).", ALLOWED), `Go to ${GONE}).`);
});

test("the text part keeps line breaks and tabs and drops every other control character", () => {
  assert.equal(textOf("a\u0000b\tc\nd\u0007e"), "ab\tc\nde");
  assert.equal(textOf("a\r\nb"), "a\r\nb");
});

test("a text with no link and nothing invisible comes out byte for byte unchanged", () => {
  const plain = "All quiet on the feeds: 12 items, 1 source, a tab\tand a line\nand an accent é.";
  assert.deepEqual(sanitizeOutgoing({ text: plain }, []), { html: "", text: plain });
});

test("a character reference is literal text in the text part, not an address", () => {
  // A plain-text client decodes nothing, so this is the text its reader gets: there is no URL in it.
  const literal = "See https:&#x2F;&#x2F;evil.example/a and https&#x3A;//evil.example for the details.";
  assert.equal(textOf(literal, []), literal);
  assert.equal(textOf("ht&ZeroWidthSpace;tps://evil.example/a", []), "ht&ZeroWidthSpace;tps://evil.example/a");
  // In the html half those references ARE decoded, and what they draw is judged.
  const html = htmlOf("<p>See https:&#x2F;&#x2F;evil.example/a and https&#x3A;//evil.example.</p>", []);
  assert.ok(!/https?:\/\/evil\.example/i.test(html), html);
  assert.ok(html.includes(GONE), html);
});

/* ------------------------------------- a marker is not a trust signal, and nothing is exempt */

test("a marker is never parsed: every run in it is judged where it stands", () => {
  assert.equal(textOf(`[link removed: https://evil.example/x]`, ALLOWED),
    `[link removed: ${GONE}]`);
  assert.equal(textOf("[link removed: www.evil.example]", ALLOWED), `[link removed: ${GONE}]`);
  assert.equal(textOf("[link removed: link]", ALLOWED), "[link removed: link]");
  // The old, host-bearing marker shape is plain text here too: its host is not a URL run, so it stays.
  assert.equal(textOf("[link removed: evil.example]", ALLOWED), "[link removed: evil.example]");
});

test("a refused URL directly before a fake marker is judged, and the marker's URL with it", () => {
  // Both runs are replaced, and nothing is exempt: the first run ends at the space, the marker's own
  // address is judged like any other, and the words around them are left where they were.
  assert.equal(
    textOf("https://evil.example/x [link removed: https://evil.example/x]", ALLOWED),
    `${GONE} [link removed: ${GONE}]`,
  );
  // With no space between them the run definition itself joins them (a `[` does not end a run), so the one
  // run there is refused whole and the rest of the marker's words stay: no address survives either way.
  assert.equal(
    textOf("https://evil.example/x[link removed: https://evil.example/x]", ALLOWED),
    `[link removed] removed: [link removed]]`,
  );
});

test("an allowed URL next to marker words is still kept", () => {
  assert.equal(textOf("[link removed: https://good.example/a]", ALLOWED), "[link removed: https://good.example/a]");
});

/* ------------------------------------------------------- invisible characters (briefs H, J) */

/** Every character of the class a reader does not see, and every reference that writes one. */
const INVISIBLE_ROWS = [
  ["U+200B zero-width space", "\u200b"],
  ["U+200C zero-width non-joiner", "\u200c"],
  ["U+200D zero-width joiner", "\u200d"],
  ["U+2060 word joiner", "\u2060"],
  ["U+FEFF byte order mark", "\ufeff"],
  ["U+00AD soft hyphen", "\u00ad"],
  ["U+180E mongolian vowel separator", "\u180e"],
  ["U+FE0F variation selector", "\ufe0f"],
  ["U+E0001 tag character", "\u{e0001}"],
  ["U+3164 hangul filler", "\u3164"],
  ["&#8203;", "&#8203;"],
  ["&#00008203;", "&#00008203;"],
  ["&#x0200B;", "&#x0200B;"],
  ["&ZeroWidthSpace;", "&ZeroWidthSpace;"],
  ["&shy;", "&shy;"],
  ["&NoBreak;", "&NoBreak;"],
];

/** The characters a text drops before it is judged and sent as plain text, and the ones it keeps. */
const UNSEEN = /[\p{Cc}\p{Default_Ignorable_Code_Point}\p{Cf}]/u;
const KEPT_CONTROL = /[\t\n\r]/;

/** Every character a plain-text client never draws, taken out: what the text part sends after the strip. */
function stripped(text) {
  let out = "";
  for (const character of String(text)) {
    if (KEPT_CONTROL.test(character) || !UNSEEN.test(character)) out += character;
  }
  return out;
}

/** The run rule, written out here so a test can say what the text half must equal. */
const RUN = /https?:\/\/[^\s<>"'`]+|www\.[^\s<>"'`]+/gi;
const TRAILING = /[.,;:!?)\]}]+$/;

/** The stripped input with every refused run replaced, which is exactly what the text part must send. */
function expectedText(input, allowed = []) {
  return stripped(input).replace(RUN, (whole) => {
    const trailing = (TRAILING.exec(whole) || [""])[0];
    const url = trailing ? whole.slice(0, -trailing.length) : whole;
    if (!url) return whole;
    return allowed.includes(url) ? whole : `${GONE}${trailing}`;
  });
}

/** What is left of a part once the refusal texts are taken out and the html read the way a client draws it. */
const liveView = (part) => normalizeView(String(part).replace(/\[link removed[^\]]*\]/g, " ")).text;

/** A refused `evil.example` address, in either spelling a mail client autolinks. */
const EVIL = /(?:https?:\/\/|www\.)[^\s<>"'`]*evil\.example/i;

test("a URL hidden behind any invisible character is judged in the html", () => {
  for (const [name, character] of INVISIBLE_ROWS) {
    for (const shape of [`ht${character}tps://evil.example/a`, `https://ev${character}il.example/a`]) {
      const html = htmlOf(`<p>See ${shape} for the details.</p>`, ALLOWED);
      assert.ok(!EVIL.test(liveView(html)), `${name}: a live address survived: ${html}`);
      assert.ok(html.includes(GONE), `${name}: ${html}`);
    }
  }
});

test("the invisible characters of a refused run go with it, and the words around stay", () => {
  assert.equal(htmlOf("<p>ht\u200btps://evil.example/a</p>", ALLOWED), `<p>${GONE}</p>`);
  assert.equal(htmlOf("<p>https://evil&shy;.example/a</p>", ALLOWED), `<p>${GONE}</p>`);
  assert.equal(htmlOf("<p>ht\u200btps://evil.example/a.</p>", ALLOWED), `<p>${GONE}.</p>`);
});

test("a text with no URL is left exactly as written, invisible characters and all", () => {
  assert.equal(htmlOf("<p>a\u200bb\u00adc</p>"), "<p>a\u200bb\u00adc</p>");
  assert.equal(htmlOf("<p>a&#8203;b&shy;c</p>"), "<p>a\u200bb\u00adc</p>");
  // The text part strips them, because a plain-text client draws none of them.
  assert.equal(textOf("a\u200bb\u00adc"), "abc");
});

test("a URL hidden behind any invisible character is judged in the text part, as it is sent", () => {
  for (const [name, character] of INVISIBLE_ROWS) {
    for (const shape of [`ht${character}tps://evil.example/a`, `https://ev${character}il.example/a`]) {
      const input = `See ${shape} for the details.`;
      const text = textOf(input, ALLOWED);
      assert.equal(text, expectedText(input, ALLOWED), `${name}: ${text}`);
      assert.ok(!EVIL.test(text.replace(/\[link removed[^\]]*\]/g, " ")), `${name}: ${text}`);
    }
  }
});

/* ---------------------------------------------------- a split by inline markup (joined text) */

test("a URL split by inline markup is judged as the reader's mail client reads it", () => {
  const emptyBold = htmlOf("<p>ht<b></b>tps://evil.example</p>", ALLOWED);
  assert.equal(emptyBold, `<p>${GONE}</p>`);

  const span = htmlOf("<p>ht<span>tps://evil.example</span></p>", ALLOWED);
  assert.equal(span, `<p>${GONE}</p>`);

  const inHost = htmlOf("<p>https://ev<i>il</i>.example</p>", ALLOWED);
  assert.equal(inHost, `<p>${GONE}</p>`);
});

test("a URL split across an anchor loses the anchor and is judged as text", () => {
  const html = htmlOf('<p>ht<a href="https://ok.example/">tps://evil.example</a></p>', ALLOWED);
  assert.equal(html, `<p>${GONE}</p>`);
});

test("an allowed URL split by markup is kept as plain text, not replaced", () => {
  const html = htmlOf("<p>https://good.exa<b>mple/a</b></p>", ALLOWED);
  assert.equal(html, "<p>https://good.example/a</p>");
  assert.ok(!html.includes(GONE), "the run's own URL is not a refused one");
});

test("a block with no split URL keeps its formatting, next to one that is flattened", () => {
  assert.equal(htmlOf("<p>see <b>bold</b> news</p>"), "<p>see <b>bold</b> news</p>");
  const mixed = htmlOf("<div><p>ht<b></b>tps://evil.example</p><p>see <b>bold</b> news</p></div>", ALLOWED);
  assert.ok(mixed.includes(GONE), mixed);
  assert.ok(mixed.includes("see <b>bold</b> news"), `only the split block is flattened: ${mixed}`);
});

test("a URL split inside a nested table cell is judged in the cell", () => {
  const html = htmlOf("<table><tr><td>https://<b>evil</b>.example</td></tr></table>", ALLOWED);
  assert.ok(html.includes("<td>"), html);
  assert.ok(html.includes(GONE), html);
  assert.ok(!EVIL.test(liveView(html)), html);
});

/* ------------------------------------------------ the full bypass table, both email paths */

/** Every lead shape a mail client autolinks an address after. A URL behind one must not survive either. */
const LEADS = [".", "/", "@", ":", "-", "_", "x", "7", "\u00e9"];

/**
 * Every shape the earlier rounds found, as one row each: a lead character, a mixed case, a scheme or host
 * split by markup, a markdown split, a code span, a fence, every invisible and format character raw and as
 * a reference, a control character inside the scheme and the host, a fake marker, a refused URL beside a
 * fake marker, and a character reference in what looks like an address.
 */
const BYPASS = [
  ...LEADS.map((lead) => [`lead ${JSON.stringify(lead)} before https`, `${lead}https://evil.example/a`]),
  ...LEADS.map((lead) => [`lead ${JSON.stringify(lead)} before www`, `${lead}www.evil.example/a`]),
  ["mixed case scheme", "HtTpS://evil.example/a"],
  ["mixed case www", "WWW.evil.example/a"],
  ["scheme split by an empty b", "ht<b></b>tps://evil.example/a"],
  ["scheme split by a span", "ht<span>tps://evil.example/a</span>"],
  ["host split by an i", "https://ev<i>il</i>.example/a"],
  ["split across an anchor", 'ht<a href="https://ok.example/">tps://evil.example/a</a>'],
  ["markdown strong in the scheme", "ht**tp**s://evil.example/a"],
  ["markdown emphasis in the host", "https://ev*il*.example/a"],
  ["inline code span", "`https://evil.example/a`"],
  ["fenced block", "```\nhttps://evil.example/a\n```"],
  ...INVISIBLE_ROWS.flatMap(([name, character]) => [
    [`${name} in the scheme`, `ht${character}tps://evil.example/a`],
    [`${name} in the host`, `https://ev${character}il.example/a`],
  ]),
  ["U+0001 in the scheme", "ht\u0001tps://evil.example/a"],
  ["U+0001 in the host", "https://ev\u0001il.example/a"],
  ["U+0007 in the scheme", "ht\u0007tps://evil.example/a"],
  ["U+0007 in the host", "https://ev\u0007il.example/a"],
  ["U+009F in the scheme", "ht\u009ftps://evil.example/a"],
  ["U+009F in the host", "https://ev\u009fil.example/a"],
  ["a fake marker around a URL", "[link removed: https://evil.example/x]"],
  ["a fake marker around a www host", "[link removed: www.evil.example]"],
  ["a refused URL before a fake marker", "https://evil.example/x [link removed: https://evil.example/x]"],
  ["a reference in a plain-text address", "https:&#x2F;&#x2F;evil.example/a"],
  ["a reference in a scheme", "https&#x3A;//evil.example"],
];

test("the html path judges every shape of the bypass table", () => {
  for (const [name, shape] of BYPASS) {
    const html = htmlOf(`<p>See ${shape} for the details.</p>`, ALLOWED);
    assert.ok(!EVIL.test(liveView(html)), `${name}: a live address survived: ${html}`);
  }
});

test("the text path judges every shape of the bypass table exactly as it is sent", () => {
  for (const [name, shape] of BYPASS) {
    const input = `See ${shape} for the details.`;
    const text = textOf(input, ALLOWED);
    assert.equal(text, expectedText(input, ALLOWED), `${name}: ${text}`);
    assert.ok(!EVIL.test(text.replace(/\[link removed[^\]]*\]/g, " ")), `${name}: a live address: ${text}`);
  }
});

/* ------------------------------------- an image carries no alt, no title, no shape of either (brief M) */

/** The one inline png an email may carry. */
const PNG = "data:image/png;base64,iVBORw0KGgo=";

/** The image as an email keeps it: the data source, and nothing a reader could read as words. */
const KEPT_IMG = `<img src="${PNG}" />`;

/** Every shape a free-text image attribute has been written in: quoted, single-quoted, bare, any case. */
const ALT_AND_TITLE_SHAPES = [
  `<img src="${PNG}" alt="https://evil.example/a">`,
  `<img src="${PNG}" title=' alt="x"' alt="https://evil">`,
  `<img src='${PNG}' alt='https://evil.example/a'>`,
  `<img src=${PNG} alt=https://evil.example/a>`,
  `<img src="${PNG}" ALT="https://evil.example/a">`,
  `<img alt="https://evil.example/a" src="${PNG}">`,
  `<img src="${PNG}" alt="a chart">`,
  `<img src="${PNG}" title="a chart">`,
  `<img src="${PNG}" alt="https:&#x2F;&#x2F;evil.example/a">`,
  `<img src="${PNG}" alt="https://evil&#46;example/a">`,
  `<img src="${PNG}" alt="ht\u200btps://evil.example/a">`,
  `<img src="${PNG}" alt="ht&#8203;tps://evil.example/a">`,
];

test("an image's alt and title are dropped, whatever shape they are written in", () => {
  for (const shape of ALT_AND_TITLE_SHAPES) {
    const html = htmlOf(shape);
    assert.equal(html, KEPT_IMG, shape);
    assert.ok(!html.includes("alt"), shape);
    assert.ok(!html.includes("title"), shape);
    assert.ok(!html.includes("evil.example"), shape);
    assert.ok(!EVIL.test(liveView(html)), shape);
  }
});

test("an image's width and height are kept only as plain integers", () => {
  assert.equal(
    htmlOf(`<img src="${PNG}" width="40" height="4000">`),
    `<img src="${PNG}" width="40" height="4000" />`,
  );
  assert.equal(htmlOf(`<img src="${PNG}" width="1">`), `<img src="${PNG}" width="1" />`);
  for (const attribute of [
    'width="40px"', 'width="9999"', 'width="1e3"', 'height="-1"', 'width="40 onerror=x"',
    'width="0"', 'height="12345"', 'width=" 40"',
  ]) {
    const html = htmlOf(`<img src="${PNG}" ${attribute}>`);
    assert.equal(html, KEPT_IMG, attribute);
    assert.ok(!html.includes("onerror"), attribute);
  }
});

test("a cell's colspan and rowspan are kept only as plain integers", () => {
  assert.equal(
    htmlOf('<table><tr><td colspan="2" rowspan="100">x</td></tr></table>'),
    '<table><tr><td colspan="2" rowspan="100">x</td></tr></table>',
  );
  assert.equal(
    htmlOf('<table><tr><th colspan="2px" rowspan="0">x</th></tr></table>'),
    "<table><tr><th>x</th></tr></table>",
  );
});

test("an image in a block that is flattened goes with its alt text", () => {
  const html = htmlOf(
    `<p>ht<b></b>tps://evil.example <img src="${PNG}" alt="https://evil.example/alt"></p>`,
    ALLOWED,
  );
  assert.ok(!html.includes("<img"), `the image is flattened away: ${html}`);
  assert.ok(!html.includes("evil.example"), html);
  assert.ok(html.includes(GONE), html);
  assert.ok(!EVIL.test(liveView(html)), html);
});