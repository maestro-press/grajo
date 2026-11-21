/**
 * defaultLayout: the email one report run sends.
 *
 * What the body is depends on the delivery mode (the document, rendered, sanitised and judged, or the
 * honest line and nothing else), the footer with the recipient's link and comment line is added AFTER the
 * body is sanitised and cannot be removed or imitated, and a custom step's own email body replaces the
 * document body but never the footer.
 *
 * One rule covers both halves of the mail: a web address the run's own items do not carry is replaced by
 * `[link removed]`, with no host named. The html half is judged the way a mail client draws it (references
 * decoded, the invisible class removed, a block joined across inline markup), the plain-text half exactly
 * as it is sent (nothing decoded, nothing joined).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultLayout, SUBJECT_MAX } from "../servers/gateway/reports/email/default-layout.js";
import { LATE_LINE } from "../servers/gateway/reports/document.js";
import { normalizeView } from "../servers/gateway/reports/email/normalize-text.js";
import {
  COMMENT_THERE_LINE,
  EMAIL_LINK_REMOVED,
  EMPTY_LINE,
  FALLBACK_SUBJECT,
  LINK_MODE_OK_LINE,
  OPEN_REPORT_PREFIX,
  REPLY_TO_COMMENT_LINE,
  RUN_FAILED_FALLBACK_LINE,
} from "../servers/gateway/reports/email/copy.js";

const LINK = "https://crow.example/reports/rpt-1/runs/run-1";
const REPORT = { title: "Morning brief" };
const OK_RUN = { status: "ok", late: 0, errorText: null };
const DOC = { markdown: "All quiet on the feeds.\n" };

/** The one text a refused address leaves. */
const GONE = EMAIL_LINK_REMOVED;

/** The real footer, exactly as the layout writes it. */
const footerHtml = (tier) => {
  const lines = [`<p>${OPEN_REPORT_PREFIX}<a href="${LINK}">${LINK}</a></p>`];
  if (tier === "a") lines.push(`<p>${COMMENT_THERE_LINE}</p>`);
  if (tier === "b") lines.push(`<p>${REPLY_TO_COMMENT_LINE}</p>`);
  return lines.join("\n");
};
const footerText = (tier) => {
  const lines = [OPEN_REPORT_PREFIX + LINK];
  if (tier === "a") lines.push(COMMENT_THERE_LINE);
  if (tier === "b") lines.push(REPLY_TO_COMMENT_LINE);
  return lines.join("\n");
};

const build = (extra) => defaultLayout({
  report: REPORT, run: OK_RUN, document: DOC, link: LINK, deliveryMode: "email_full", ...extra,
});

test("the footer names the link, and the tier's comment line follows", () => {
  const a = build({ tier: "a" });
  assert.equal(a.subject, "Morning brief");
  assert.ok(a.text.endsWith(footerText("a")), "the footer is the last thing in the text");
  assert.ok(a.html.endsWith(footerHtml("a")), "the footer is the last thing in the html");

  const b = build({ tier: "b" });
  assert.ok(b.text.endsWith(footerText("b")));
  assert.ok(b.html.endsWith(footerHtml("b")));

  const c = build({ tier: "c" });
  assert.ok(c.text.endsWith(footerText("c")));
  assert.ok(c.html.endsWith(footerHtml("c")));
  assert.ok(!c.text.includes("comment"), "tier c is told nothing about commenting");
  assert.ok(!c.html.includes("comment"));

  const none = build({ tier: null });
  assert.ok(none.text.endsWith(footerText(null)));
});

test("the document is carried, rendered, with the link for this reader", () => {
  const out = build({});
  assert.ok(out.html.startsWith("<p>All quiet on the feeds.</p>"));
  assert.ok(out.text.startsWith("All quiet on the feeds."));
  assert.ok(out.html.includes(`href="${LINK}"`));
  assert.ok(out.text.includes(LINK));
});

test("both carries the document too", () => {
  const out = build({ deliveryMode: "both" });
  assert.ok(out.html.includes("All quiet on the feeds."));
  assert.ok(out.html.endsWith(footerHtml(null)));
});

test("an empty override falls back to the default body", () => {
  const out = build({ override: { html: "", text: "" } });
  assert.ok(out.html.includes("All quiet on the feeds."));
  assert.ok(out.html.endsWith(footerHtml(null)));
});

test("an override replaces the document body but cannot carry a script", () => {
  const out = build({ override: { html: '<p>custom body</p><script>alert("x")</script>', text: "custom body" } });
  assert.ok(out.html.includes("<p>custom body</p>"));
  assert.ok(!out.html.includes("<script"), "the override is sanitised");
  assert.ok(!out.html.includes("All quiet on the feeds."), "the override replaced the document");
  assert.ok(out.text.includes("custom body"));
  assert.ok(out.html.endsWith(footerHtml(null)), "the footer is still appended after sanitising");
  assert.ok(out.text.endsWith(footerText(null)));
});

test("an override cannot contain the footer itself: exactly one real footer, at the end", () => {
  const fake = `${OPEN_REPORT_PREFIX}https://fake.example/`;
  const out = build({ override: { html: `<p>${fake}</p>`, text: fake } });
  assert.equal(out.html.match(/Open this report:/g).length, 2, "the override's own words and the real footer");
  assert.equal((out.html.match(new RegExp(`href="${LINK}"`, "g")) || []).length, 1, "one real link");
  assert.ok(out.html.endsWith(footerHtml(null)));
  assert.ok(out.html.lastIndexOf("Open this report:") > out.html.indexOf("[link removed]"));
  assert.ok(out.text.endsWith(footerText(null)));
  assert.ok(!out.text.includes("https://fake.example/"), "a refused address in the text is replaced");
});

test("an empty run uses the empty line", () => {
  const out = build({ run: { status: "empty", late: 0, errorText: null }, document: null });
  assert.ok(out.text.includes(EMPTY_LINE));
  assert.ok(out.html.includes(EMPTY_LINE));
  assert.ok(out.text.endsWith(footerText(null)));
});

test("a failed run names the source it could not reach", () => {
  const out = build({
    run: { status: "failed", late: 0, errorText: "Couldn't reach Example News. Check the feed address." },
    document: null,
  });
  assert.ok(out.text.includes("Couldn't reach Example News."));
  assert.ok(out.html.includes("Example News"));
  assert.ok(out.text.endsWith(footerText(null)));
});

test("a failed run with no error text still says the run did not finish", () => {
  const out = build({ run: { status: "failed", late: 0, errorText: "   " }, document: null });
  assert.ok(out.text.includes(RUN_FAILED_FALLBACK_LINE));
});

test("a failed run's honest line is never replaced by a custom body or a document", () => {
  const out = build({
    run: { status: "failed", late: 0, errorText: "Couldn't reach Example News." },
    document: DOC,
    override: { html: "<p>custom body</p>", text: "custom body" },
  });
  assert.ok(out.text.includes("Couldn't reach Example News."), "the honest line is the body");
  assert.ok(out.html.includes("Example News"));
  assert.ok(!out.text.includes("custom body"), "a custom template never overrides it");
  assert.ok(!out.html.includes("custom body"));
  assert.ok(!out.text.includes("All quiet on the feeds."), "and no half report is mailed either");
  assert.ok(out.text.endsWith(footerText(null)), "the footer is still the last thing");
});

test("a run row's snake_case error text is read too", () => {
  const out = build({
    run: { status: "failed", late: 0, error_text: "Couldn't reach Example News." },
    document: null,
  });
  assert.ok(out.text.includes("Couldn't reach Example News."));
  assert.ok(!out.text.includes(RUN_FAILED_FALLBACK_LINE));
});

test("the failure line is collapsed to one bounded line", () => {
  const out = build({
    run: { status: "failed", late: 0, errorText: "Couldn't reach\tExample\n\nNews. " + "x".repeat(2000) },
    document: null,
  });
  const firstLine = out.text.split("\n")[0];
  assert.equal(firstLine, "Couldn't reach Example News. " + "x".repeat(2000).slice(0, 500 - "Couldn't reach Example News. ".length));
  assert.ok(firstLine.length <= 500);
});

test("email_link carries the honest line and no report content", () => {
  const out = build({ deliveryMode: "email_link" });
  assert.ok(out.text.includes(LINK_MODE_OK_LINE));
  assert.ok(!out.text.includes("All quiet on the feeds."));
  assert.ok(!out.html.includes("All quiet on the feeds."));
  assert.ok(out.text.endsWith(footerText(null)));
  // An override cannot put report content into a link-only email either.
  const withOverride = build({ deliveryMode: "email_link", override: { html: "<p>custom body</p>", text: "custom body" } });
  assert.ok(!withOverride.html.includes("custom body"));
  assert.ok(withOverride.html.includes(LINK_MODE_OK_LINE));
});

test("the late line comes first, and is not repeated when the document already starts with it", () => {
  const late = build({ run: { status: "ok", late: 1, errorText: null } });
  assert.ok(late.text.startsWith(LATE_LINE), "the late line is the first line of the text");
  assert.ok(late.html.startsWith(`<p>${LATE_LINE}</p>`));

  const already = build({ run: { status: "ok", late: 1, errorText: null }, document: { markdown: `${LATE_LINE}\n\nAll quiet on the feeds.\n` } });
  assert.equal(already.text.split(LATE_LINE).length - 1, 1, "the assembly's own late line is the only one");
  assert.ok(already.text.startsWith(LATE_LINE));
});

test("the late line is put back when a custom body replaces the document that carried it", () => {
  const out = build({
    run: { status: "ok", late: 1, errorText: null },
    document: { markdown: `${LATE_LINE}\n\nAll quiet on the feeds.\n` },
    override: { html: "<p>custom body</p>", text: "custom body" },
  });
  assert.ok(out.text.startsWith(LATE_LINE));
  assert.ok(out.html.includes("custom body"));
});

test("a table cell that is a whole URL is a link only when the run's own items carry it", () => {
  const markdown = [
    "| Source | Link |",
    "| --- | --- |",
    "| Good | [https://good.example/a](https://good.example/a) |",
    "| Odd | [https://evil.example/x](https://evil.example/x) |",
    "",
  ].join("\n");
  const out = build({ document: { markdown }, allowedLinks: ["https://good.example/a"] });
  assert.ok(out.html.includes('href="https://good.example/a"'), "the run's own URL is a live link");
  assert.ok(!out.html.includes('href="https://evil.example/x"'), "a URL the run's items do not carry is not");
  assert.ok(out.html.includes(GONE), "the refused cell is the one refusal text, with no host named");
  assert.ok(!out.html.includes("evil.example"), "and no host is shown");
});

test("the subject is bounded, one line, and free of control characters", () => {
  const out = defaultLayout({
    report: { title: `  Daily\r\n\tbrief ${"x".repeat(400)}  ` },
    run: OK_RUN, document: DOC, link: LINK, deliveryMode: "email_full",
  });
  assert.ok(out.subject.length <= SUBJECT_MAX);
  assert.ok(!/[\r\n\t]/.test(out.subject));
  assert.ok(out.subject.startsWith("Daily brief x"));
  assert.equal(out.subject, out.subject.trim());
  assert.equal(out.subject.length, SUBJECT_MAX);
});

test("the subject is the fallback when the title has nothing usable", () => {
  const out = build({ report: { title: " \r\n\t " } });
  assert.equal(out.subject, FALLBACK_SUBJECT);
  const missing = build({ report: null });
  assert.equal(missing.subject, FALLBACK_SUBJECT);
});

test("a title carrying markup cannot put markup in the email", () => {
  const out = build({ report: { title: "Daily <script>alert(1)</script> brief" } });
  assert.ok(!out.html.includes("<script"), "the title is not written into the html body");
  assert.ok(out.subject.includes("<script>"), "the subject keeps the words as words");
});

test("an override that splits a URL across markup cannot slip a link into the mail", () => {
  const split = build({ override: { html: "<p>ht<b></b>tps://evil.example/x</p>", text: "" } });
  assert.ok(!split.html.includes("https://evil.example"), split.html);
  assert.equal(split.html, `<p>${GONE}</p>\n${footerHtml(null)}`);
  assert.ok(split.html.endsWith(footerHtml(null)), "the footer still goes on last");

  const kept = build({ override: { html: "<p>see <b>bold</b> news</p>", text: "see bold news" } });
  assert.ok(kept.html.includes("see <b>bold</b> news"), "formatting stays where no URL was split");
});

test("a layout with no link, or a mode it does not build, is bad_input", () => {
  const bad = (extra) => assert.throws(
    () => defaultLayout({ report: REPORT, run: OK_RUN, document: DOC, link: LINK, deliveryMode: "email_full", ...extra }),
    (err) => err.code === "bad_input",
  );
  bad({ link: "" });
  bad({ link: "   " });
  bad({ link: null });
  bad({ deliveryMode: "crow_only" });
  bad({ deliveryMode: "dashboard" });
  bad({ deliveryMode: undefined });
});

/* --------------------------------------------------- the email path's one link rule */

/** The refusal texts taken out, then the part read the way a client draws it. */
const liveView = (part) => normalizeView(String(part).replace(/\[link removed[^\]]*\]/g, " ")).text;

/** The same part with the refusal texts taken out, as it is sent. */
const withoutRefusals = (text) => String(text).replace(/\[link removed[^\]]*\]/g, " ");

/** A refused `evil.example` address, in either spelling a mail client autolinks. */
const EVIL = /(?:https?:\/\/|www\.)[^\s<>"'`]*evil\.example/i;

/** The characters a text part drops, and the ones it keeps: what the plain-text half is judged on. */
const UNSEEN = /[\p{Cc}\p{Default_Ignorable_Code_Point}\p{Cf}]/u;
const KEPT_CONTROL = /[\t\n\r]/;

function stripped(text) {
  let out = "";
  for (const character of String(text)) {
    if (KEPT_CONTROL.test(character) || !UNSEEN.test(character)) out += character;
  }
  return out;
}

/** The run rule, as the text half applies it: the stripped input, every refused run replaced. */
const RUN = /https?:\/\/[^\s<>"'`]+|www\.[^\s<>"'`]+/gi;
const TRAILING = /[.,;:!?)\]}]+$/;

function expectedText(input, allowed = []) {
  return stripped(input).replace(RUN, (whole) => {
    const trailing = (TRAILING.exec(whole) || [""])[0];
    const url = trailing ? whole.slice(0, -trailing.length) : whole;
    if (!url) return whole;
    return allowed.includes(url) ? whole : `${GONE}${trailing}`;
  });
}

test("a foreign www. link in a document is the one refusal text, in the html and the text", () => {
  const out = build({ document: { markdown: "See www.evil.example for the details.\n" } });
  assert.equal((out.html.match(/\[link removed/g) || []).length, 1, out.html);
  assert.ok(out.html.includes(GONE), out.html);
  assert.ok(!out.html.includes("www."), out.html);
  assert.equal((out.text.match(/\[link removed/g) || []).length, 1, out.text);
  assert.ok(out.text.includes(GONE), out.text);
  assert.ok(!out.text.includes("www."), out.text);
});

test("a foreign https link on a www host leaves one refusal and no www. in either half", () => {
  const out = build({ document: { markdown: "See https://www.evil.example/p for the details.\n" } });
  assert.equal((out.html.match(/\[link removed/g) || []).length, 1, out.html);
  assert.ok(!out.html.includes("www."), out.html);
  assert.equal((out.text.match(/\[link removed/g) || []).length, 1, out.text);
  assert.ok(!out.text.includes("www."), out.text);
  assert.ok(!EVIL.test(liveView(out.html)), out.html);
  assert.ok(!EVIL.test(withoutRefusals(out.text)), out.text);
});

test("a URL split by markdown strong in the document is one refusal", () => {
  const out = build({ document: { markdown: "See ht**tp**s://evil.example/a for the details.\n" } });
  assert.equal((out.html.match(/\[link removed/g) || []).length, 1, out.html);
  assert.ok(!EVIL.test(liveView(out.html)), out.html);
  assert.ok(!EVIL.test(withoutRefusals(out.text)), out.text);
});

test("a URL split by markdown emphasis reads as one refusal", () => {
  const out = build({ document: { markdown: "See https://ev*il*.example/a for the details.\n" } });
  const words = out.html.replace(/<[^>]*>/g, "");
  assert.ok(words.includes(GONE), out.html);
  assert.ok(!EVIL.test(liveView(out.html)), out.html);
});

test("a URL hidden behind an invisible character is refused in the document's html", () => {
  const shapes = [
    "ht\u200btps://evil.example/a",
    "ht&#8203;tps://evil.example/a",
    "https://evil&shy;.example/a",
    "ht**tp**s://evil.example/a",
    "https://ev*il*.example/a",
    "x.https://evil.example/a",
    "me@www.evil.example",
  ];
  for (const shape of shapes) {
    const out = build({ document: { markdown: `See ${shape} for the details.\n` } });
    assert.ok(!EVIL.test(liveView(out.html)), `${shape}: the html kept a live address: ${out.html}`);
    // The text half is the raw document judged as it is sent, so no address run survives there either.
    assert.ok(!EVIL.test(withoutRefusals(out.text)), `${shape}: the text kept a live address: ${out.text}`);
  }
});

/* ------------------------------------------ the whole invisible class in the text part (brief J) */

test("a URL split by any invisible or format character is refused in the text part", () => {
  const shapes = [
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
    ["&ZeroWidthSpace;", "&ZeroWidthSpace;"],
    ["&NoBreak;", "&NoBreak;"],
    ["&#00008203;", "&#00008203;"],
    ["&#x0200B;", "&#x0200B;"],
    ["&#X200b;", "&#X200b;"],
    ["&shy;", "&shy;"],
  ];
  for (const [name, character] of shapes) {
    const markdown = `See ht${character}tps://evil.example/a for the details.\n`;
    const out = build({ document: { markdown } });
    assert.equal(out.text, `${expectedText(markdown)}\n\n${footerText(null)}`, `${name}: ${out.text}`);
    assert.ok(!EVIL.test(withoutRefusals(out.text)), `${name}: the text kept an address: ${out.text}`);
    assert.ok(!EVIL.test(liveView(out.html)), `${name}: the html kept a live address: ${out.html}`);
  }
});

/* ------------------------------------- the plain-text half is judged on its final text (brief J) */

test("a URL in an inline code span is judged in the text part", () => {
  const markdown = "See `https://evil.example/a` for the details.\n";
  const out = build({ document: { markdown } });
  assert.equal(out.text, `${expectedText(markdown)}\n\n${footerText(null)}`);
  assert.ok(out.text.startsWith("See `[link removed]` for the details."), out.text);
  assert.ok(!EVIL.test(withoutRefusals(out.text)), out.text);
  assert.ok(out.text.endsWith(footerText(null)), "the footer is still the last thing");
});

test("a URL in a fenced block is judged in the text part", () => {
  const markdown = "Before.\n\n```\nhttps://evil.example/a\n```\n\nAfter.\n";
  const out = build({ document: { markdown } });
  assert.equal(out.text, `${expectedText(markdown)}\n\n${footerText(null)}`);
  assert.ok(!EVIL.test(withoutRefusals(out.text)), out.text);
});

test("a run split by markdown emphasis is judged in the text part", () => {
  for (const shape of ["ht**tp**s://evil.example/a", "https://ev*il*.example/a"]) {
    const markdown = `See ${shape} for the details.\n`;
    const out = build({ document: { markdown } });
    // The text half is not markdown-aware: a run the asterisks split is the one run this pass reads, and a
    // `ht**tp**s://` spelling is not a run to it at all, so nothing live survives either way.
    assert.equal(out.text, `${expectedText(markdown)}\n\n${footerText(null)}`, shape);
    assert.ok(!EVIL.test(withoutRefusals(out.text)), `${shape}: ${out.text}`);
  }
});

test("an allowed URL in a code span is kept in both parts", () => {
  const out = build({
    document: { markdown: "See `https://good.example/a` for the details.\n" },
    allowedLinks: ["https://good.example/a"],
  });
  assert.ok(out.text.includes("https://good.example/a"), out.text);
  assert.ok(!out.text.includes(GONE), out.text);
  assert.ok(out.html.includes("https://good.example/a"), out.html);
  assert.ok(!out.html.includes(GONE), out.html);
});

test("an allowed URL is kept in both parts of a document", () => {
  const out = build({ document: { markdown: "See https://good.example/a for the details.\n" }, allowedLinks: ["https://good.example/a"] });
  assert.ok(out.text.startsWith("See https://good.example/a for the details."), out.text);
  assert.ok(out.html.startsWith('<p>See <a href="https://good.example/a">https://good.example/a</a>'), out.html);
  assert.ok(!out.html.includes(GONE), out.html);
});

test("an ordinary text part with no URL is unchanged byte for byte", () => {
  const markdown = "All quiet on the feeds.";
  const out = build({ document: { markdown } });
  assert.equal(out.text, `All quiet on the feeds.\n\n${footerText(null)}`);
  assert.ok(!out.text.includes(GONE), out.text);
});

test("a fake marker in the document is judged in both halves", () => {
  const out = build({ document: { markdown: "See [link removed: https://evil.example/x] for the details.\n" } });
  // The renderer turns the address inside the fake marker into a link whose own text carries the closing
  // bracket, and a refused anchor goes whole: the bracket goes with it, and the address is gone.
  assert.ok(out.html.includes(`[link removed: ${GONE}`), out.html);
  assert.ok(out.text.startsWith(`See [link removed: ${GONE}] for the details.`), out.text);
  assert.ok(out.text.endsWith(`\n\n${footerText(null)}`), out.text);
  assert.ok(!EVIL.test(liveView(out.html)), out.html);
  assert.ok(!EVIL.test(withoutRefusals(out.text)), out.text);
});

/* ----------------------------------------- the full bypass table, through both email paths */

/** Every lead shape a mail client autolinks an address after. */
const LEADS = [".", "/", "@", ":", "-", "_", "x", "7", "\u00e9"];

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

/** Every shape the earlier rounds found, one row each (see the sanitize-outgoing table). */
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

test("a document under email_full judges every shape in its html and its text", () => {
  for (const [name, shape] of BYPASS) {
    const markdown = `See ${shape} for the details.\n`;
    const out = build({ document: { markdown } });
    assert.ok(!EVIL.test(liveView(out.html)), `${name}: the html kept a live address: ${out.html}`);
    assert.equal(out.text, `${expectedText(markdown)}\n\n${footerText(null)}`, `${name}: ${out.text}`);
    assert.ok(!EVIL.test(withoutRefusals(out.text)), `${name}: the text kept an address: ${out.text}`);
    assert.ok(out.html.endsWith(footerHtml(null)), `${name}: the footer is still the last thing`);
  }
});

test("an override judges every shape in its html and its text", () => {
  for (const [name, shape] of BYPASS) {
    const html = `<p>See ${shape} for the details.</p>`;
    const text = `See ${shape} for the details.`;
    const out = build({ override: { html, text } });
    assert.ok(!EVIL.test(liveView(out.html)), `${name}: the html kept a live address: ${out.html}`);
    assert.equal(out.text, `${expectedText(text)}\n\n${footerText(null)}`, `${name}: ${out.text}`);
    assert.ok(!EVIL.test(withoutRefusals(out.text)), `${name}: the text kept an address: ${out.text}`);
  }
});

/* --------------------------- an override image carries no alt and only integer sizes (brief M) */

/** The one inline png an emailed body may carry; a markdown image would be a remote request instead. */
const PNG = "data:image/png;base64,iVBORw0KGgo=";

test("an override's image carries no alt and no title", () => {
  const out = build({
    override: {
      html: `<p>chart <img src="${PNG}" title=' alt="x"' alt="https://evil.example/alt"> here</p>`,
      text: "chart",
    },
  });
  assert.ok(out.html.startsWith(`<p>chart <img src="${PNG}" /> here</p>`), out.html);
  assert.ok(!out.html.includes("alt"), out.html);
  assert.ok(!out.html.includes("title"), out.html);
  assert.ok(!out.html.includes("evil.example"), out.html);
  assert.ok(!EVIL.test(liveView(out.html)), out.html);
  assert.ok(out.html.endsWith(footerHtml(null)), "the footer is still the last thing");
});

test("an override's image keeps a plain-integer size and drops any other value", () => {
  const kept = build({ override: { html: `<p><img src="${PNG}" width="40" height="400"></p>`, text: "" } });
  assert.ok(kept.html.includes(`<img src="${PNG}" width="40" height="400" />`), kept.html);
  for (const attribute of ['width="40px"', 'width="9999"', 'width="1e3"', 'height="-1"', 'width="40 onerror=x"']) {
    const out = build({ override: { html: `<p><img src="${PNG}" ${attribute}></p>`, text: "" } });
    assert.ok(out.html.includes(`<p><img src="${PNG}" /></p>`), `${attribute}: ${out.html}`);
    assert.ok(!out.html.includes("onerror"), out.html);
  }
});