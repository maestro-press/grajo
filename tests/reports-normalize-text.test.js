/**
 * normalize-text.js: the one way a report mail path reads a text before it judges its links.
 *
 * A mail client draws a URL out of the characters a reader can see: a character reference is decoded, the
 * Unicode default-ignorables and format characters are dropped, and a control character is drawn as
 * nothing. So every row below is a URL a reader would get a live link from in the html half, and that half
 * may not carry it outside the `[link removed]` text. The plain-text half is judged as it is sent: no
 * reference is decoded there, and `stripInvisible` only drops what nobody draws. The last row is the
 * control: an ordinary text must come out exactly as it did before, because this pass removes nothing a
 * reader sees.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeForLinkCheck, stripInvisible } from "../servers/gateway/reports/email/normalize-text.js";
import { sanitizeOutgoing } from "../servers/gateway/reports/email/sanitize-outgoing.js";
import { defaultLayout } from "../servers/gateway/reports/email/default-layout.js";

const LINK = "https://crow.example/reports/rpt-1/runs/run-1";
const REPORT = { title: "Morning brief" };
const RUN = { status: "ok", late: 0, errorText: null };

/** One body through the layout, the way delivery builds it. */
const layoutOf = (markdown, allowedLinks = []) => defaultLayout({
  report: REPORT, run: RUN, document: { markdown }, link: LINK,
  deliveryMode: "email_full", allowedLinks,
});

/** A part with the refusal texts Crow wrote taken out: only a URL a reader could still reach is left. */
const outsideMarkers = (part) => String(part).replace(/\[link removed[^\]]*\]/g, " ");

/** No `evil.example` URL run outside a marker, in a part. */
function assertNoLiveRun(part, label) {
  const outside = outsideMarkers(part);
  assert.ok(!/https?:\/\/evil\.example/i.test(outside), `${label}: a live URL survived: ${JSON.stringify(part)}`);
  assert.ok(!/www\.evil\.example/i.test(outside), `${label}: a www host survived: ${JSON.stringify(part)}`);
}

/** Every shape a reader's client reads as the URL `https://evil.example/a`, split one way or another. */
const BYPASS_SHAPES = [
  ["U+0001 in the scheme", "ht\u0001tps://evil.example/a"],
  ["U+0001 in the host", "https://ev\u0001il.example/a"],
  ["U+0007 in the scheme", "ht\u0007tps://evil.example/a"],
  ["U+0007 in the host", "https://ev\u0007il.example/a"],
  ["U+009F in the scheme", "ht\u009ftps://evil.example/a"],
  ["U+009F in the host", "https://ev\u009fil.example/a"],
  ["decimal reference with leading zeros", "ht&#00008203;tps://evil.example/a"],
  ["hex reference with leading zeros", "ht&#x0200B;tps://evil.example/a"],
  ["capital hex reference", "ht&#X200b;tps://evil.example/a"],
  ["&ZeroWidthSpace;", "ht&ZeroWidthSpace;tps://evil.example/a"],
  ["&NoBreak;", "ht&NoBreak;tps://evil.example/a"],
  ["&shy; in the host", "https://evil&shy;.example/a"],
  ["U+180E", "ht\u180etps://evil.example/a"],
  ["U+2060", "ht\u2060tps://evil.example/a"],
  ["U+FE0F", "ht\ufe0ftps://evil.example/a"],
  ["U+E0001 tag character", "ht\u{E0001}tps://evil.example/a"],
  ["U+200B", "ht\u200btps://evil.example/a"],
  ["U+200E left-to-right mark", "ht\u200etps://evil.example/a"],
  ["a fake marker", "[link removed: https://evil.example/x]"],
];

test("the html path judges every bypass shape", () => {
  for (const [name, shape] of BYPASS_SHAPES) {
    const html = sanitizeOutgoing({ html: `<p>See ${shape} for the details.</p>` }, []).html;
    assertNoLiveRun(html, `html path, ${name}`);
  }
});

test("the layout judges every bypass shape in its html and its text", () => {
  for (const [name, shape] of BYPASS_SHAPES) {
    const out = layoutOf(`See ${shape} for the details.\n`);
    assertNoLiveRun(out.html, `layout html, ${name}`);
    assertNoLiveRun(out.text, `layout text, ${name}`);
  }
});

test("the layout keeps a document with none of these characters byte for byte", () => {
  const out = layoutOf("See https://good.example/a for the details.", ["https://good.example/a"]);
  assert.equal(out.text, `See https://good.example/a for the details.\n\nOpen this report: ${LINK}`);
  assert.ok(out.html.startsWith('<p>See <a href="https://good.example/a">https://good.example/a</a> for the details.</p>'),
    out.html);
  assert.ok(out.html.endsWith(`<p>Open this report: <a href="${LINK}">${LINK}</a></p>`), out.html);
  assert.ok(!out.html.includes("[link removed"), out.html);
});

test("normalizeForLinkCheck reads the references and drops the class a reader does not see", () => {
  const cases = [
    ["ht&#00008203;tps://x", "https://x"],
    ["ht&#x0200B;tps://x", "https://x"],
    ["ht&#X200b;tps://x", "https://x"],
    ["ht&ZeroWidthSpace;tps://x", "https://x"],
    ["ht&NoBreak;tps://x", "https://x"],
    ["https://evil&shy;.x", "https://evil.x"],
    ["a&nbsp;b", "a b"],
    ["a\u200bb\u2060c\u180ed\ufe0fe\u{E0001}f\u200eg", "abcdefg"],
    ["a\u0001b\u0007c\u009fd", "abcd"],
    ["a\tb\nc\rd", "a\tb\nc\rd"],
    ["plain words, no class at all", "plain words, no class at all"],
  ];
  for (const [input, expected] of cases) assert.equal(normalizeForLinkCheck(input), expected, input);
});

test("a text with none of these characters is left exactly as it was", () => {
  assert.deepEqual(
    sanitizeOutgoing({ html: "<p>hello there</p>", text: "hello there" }, []),
    { html: "<p>hello there</p>", text: "hello there" },
  );
  assert.equal(normalizeForLinkCheck("plain words, no class at all"), "plain words, no class at all");
});

test("a missing or non-string text is an empty view, never a throw", () => {
  assert.equal(normalizeForLinkCheck(undefined), "");
  assert.equal(normalizeForLinkCheck(null), "");
  assert.equal(normalizeForLinkCheck(42), "");
  assert.equal(stripInvisible(undefined), "");
  assert.equal(stripInvisible(null), "");
  assert.equal(stripInvisible(42), "");
});

test("stripInvisible drops what nobody draws and decodes nothing", () => {
  const cases = [
    // The classes a plain-text client never draws, with the three whitespace controls kept.
    ["a\u200bb\u2060c\u180ed\ufe0fe\u{e0001}f\u3164g", "abcdefg"],
    ["a\u0001b\u0007c\u009fd", "abcd"],
    ["a\t b\n c\r d", "a\t b\n c\r d"],
    // Nothing is decoded: a reference is the literal text a plain-text reader gets.
    ["ht&#8203;tps://x", "ht&#8203;tps://x"],
    ["ht&#x0200B;tps://x", "ht&#x0200B;tps://x"],
    ["ht&ZeroWidthSpace;tps://x", "ht&ZeroWidthSpace;tps://x"],
    ["&shy;&NoBreak;&nbsp;", "&shy;&NoBreak;&nbsp;"],
    ["plain words, no class at all", "plain words, no class at all"],
  ];
  for (const [input, expected] of cases) assert.equal(stripInvisible(input), expected, JSON.stringify(input));
});