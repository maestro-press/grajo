// The recipient view: the page a person who was mailed a report link actually sees.
//
// Harness: the view builder called directly with a stored index.html in the exact shapes
// bundles/artifacts/server/render.js writes (`<a data-inert-href="..." title="...">`, a
// `<figure class="spec"><img src="__render/b1.svg">`) and a `readAsset` that answers from a Map, so every
// assertion is about the markup this module produces. The `loadVersionForView` case at the end uses the
// real artifacts bundle: a scratch crow.db (CROW_DATA_DIR under a temp dir, so a real Crow data dir can
// never be touched), the bundle's own init-tables, a local blob store, and a real document version with
// one uploaded image, the way tests/reports-document.test.js builds one.
//
// Stored styles are part of the harness on purpose: the renderer writes a `<style>` into a version's
// head, and this module must not pass ANY of it through, so the helpers below can put a sheet in the
// head or the body and the tests assert only this repo's own CSS constants survive.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-recipient-view-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const {
  MAX_ASSET_BYTES, MAX_TOTAL_BYTES, RECIPIENT_DOC_CSS, SPEC_FIGURE_CSS, VIEW_CSS, buildRecipientView,
  loadVersionForView, renderRecipientNotice,
} = await import("../servers/gateway/reports/recipient-view.js");
const { RECIPIENT_COPY, copyFor, pickLang } = await import("../servers/gateway/reports/recipient-copy.js");
const bundleStore = await import("../bundles/artifacts/server/store.js");
const { initArtifactsTables } = await import("../bundles/artifacts/server/init-tables.js");
const { createBlobStore } = await import("../bundles/artifacts/server/blob-store-minio.js");
const bundleLimits = await import("../bundles/artifacts/server/limits.js");
const { markdownBlocks } = await import("../servers/blog/renderer.js");

const openDbs = [];
let copies = 0;

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
});

after(() => {
  for (const db of openDbs) { try { db.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

/* ------------------------------------------------------------------------- the harness */

const STORED_CSS = "body{font:16px/1.6 system-ui,sans-serif}";

/** A stored page in the shape render.js writes one: doctype, head with the document CSS, body with main. */
function doc(body, { title = "Weekly listings", css = STORED_CSS } = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">`
    + `<meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>`
    + `<style>${css}</style></head><body><main>\n${body}\n</main></body></html>`;
}

/** Every `<style>` element's text in a produced page, in document order (attribute-less, as built). */
function styleSheets(html) {
  return [...html.matchAll(/<style>([\s\S]*?)<\/style>/g)].map((m) => m[1]);
}

/** An anchor exactly as render.js `inertLinks` leaves one. */
const anchor = (href, text) => `<a data-inert-href="${href}" title="${href}">${text}</a>`;

/** A chart block exactly as render.js writes one. */
const chart = (src = "__render/b1.svg") => `<figure class="spec"><img src="${src}" alt="Chart"></figure>`;

/** An asset reader over a plain Map, the shape `loadVersionForView` hands the builder. */
function assets(entries) {
  const files = new Map(Object.entries(entries));
  return async (path) => files.get(path) ?? null;
}

/** The one attribute value as it sits in the HTML, decoded the way a browser parses it. */
function attrIn(tag, name) {
  const m = new RegExp(`\\s${name}="([^"]*)"`).exec(tag);
  return m ? m[1].replace(/&amp;/g, "&").replace(/&quot;/g, '"') : null;
}

/** The first anchor tag with the given text, as it came out of the builder. */
function anchorTag(html, text) {
  const m = new RegExp(`<a\\b[^>]*>${text.replace(/[.*+?^${}()|[\\]\\\\]/g, "\\\\$&")}</a>`).exec(html);
  return m ? m[0] : "";
}

/**
 * The body region of a produced page.
 *
 * Scans that look for a marker stay here, because the page's own stylesheet also names some of them
 * (`a[data-inert-href]` is a rule in the document sheet), so a whole-document scan can find the CSS
 * rule instead of the element and then look for an `<a` that is not there.
 */
function bodyRegion(html) {
  const m = /<body\b[^>]*>([\s\S]*)<\/body\s*>/i.exec(html);
  return m ? m[1] : html;
}

/** The anchor element around the first occurrence of a marker (an attribute, a word). */
function anchorAround(html, marker) {
  const body = bodyRegion(html);
  const at = body.indexOf(marker);
  if (at < 0) return "";
  const start = body.lastIndexOf("<a", at);
  const close = body.indexOf("</a>", at);
  return start < 0 || close < 0 ? "" : body.slice(start, close + 4);
}

/* ------------------------------------------------------------------------- links */

test("public view: a listing link is clickable and goes to the listing", async () => {
  const cases = [
    { href: "https://example.com/a", allowed: "https://example.com/a" },
    { href: "https://example.com/x?a=1&amp;b=2", allowed: "https://example.com/x?a=1&b=2" },
    { href: "https://example.com/caf%C3%A9", allowed: "https://example.com/café" },
    { href: "https://example.com/a%20b", allowed: "https://example.com/a b" },
  ];
  for (const item of cases) {
    const html = await buildRecipientView({
      indexHtml: doc(anchor(item.href, "Open the listing")),
      readAsset: assets({}),
      allowedLinks: [item.allowed],
    });
    const tag = anchorTag(html, "Open the listing");
    assert.ok(tag, `${item.href}: the anchor is there`);
    const href = attrIn(tag, "href");
    assert.equal(href, new URL(item.allowed).href, `${item.href}: the href is the normalised URL`);
    assert.equal(attrIn(tag, "target"), "_blank", `${item.href}: it opens in a new tab`);
    assert.equal(attrIn(tag, "rel"), "noopener noreferrer", `${item.href}: with no handle on the page`);
    assert.equal(attrIn(tag, "data-inert-href"), null, `${item.href}: the inert shape is gone`);
    assert.equal(attrIn(tag, "title"), null, `${item.href}: the title that only repeated the URL is gone`);
    assert.ok(tag.includes(">Open the listing</a>"), `${item.href}: the visible text is kept`);
  }
});

test("public view: a chart is visible", async () => {
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="2"/></svg>');
  const html = await buildRecipientView({
    indexHtml: doc(chart("__render/b1.svg")),
    readAsset: assets({ "__render/b1.svg": { body: svg, contentType: "image/svg+xml" } }),
  });
  assert.ok(!html.includes('src="__render'), "no relative render path survives");
  const srcs = [...html.matchAll(/\ssrc="([^"]*)"/g)].map((m) => m[1]);
  assert.equal(srcs.length, 1, "one image");
  assert.ok(srcs.every((src) => src.startsWith("data:")), "every src is a data URI");
  assert.equal(srcs[0], `data:image/svg+xml;base64,${svg.toString("base64")}`);
  assert.ok(html.includes('alt="Chart"'), "the document's own alt text is kept");
  assert.ok(html.includes('class="spec"'), "the figure keeps the class the spec rule targets");
  assert.ok(html.includes(`<style>${RECIPIENT_DOC_CSS}</style>`),
    "the document stylesheet is this repo's own constant, not the stored one");
  assert.ok(html.includes(`<style>${SPEC_FIGURE_CSS}</style>`), "a chart brings the spec figure rule");
  assert.deepEqual(styleSheets(html), [RECIPIENT_DOC_CSS, SPEC_FIGURE_CSS, VIEW_CSS],
    "document, figure and chrome sheets, and nothing else");
  assert.ok(!html.includes(STORED_CSS), "the stored sheet is not passed through");
});

test("a link not in the items stays inert", async () => {
  const html = await buildRecipientView({
    indexHtml: doc(anchor("https://evil.example/x", "The listing")),
    readAsset: assets({}),
    allowedLinks: ["https://example.com/a"],
  });
  const tag = anchorAround(html, "data-inert-href");
  assert.ok(tag, "the anchor is still there");
  assert.equal(attrIn(tag, "href"), null, "no href was restored");
  assert.equal(attrIn(tag, "data-inert-href"), "https://evil.example/x", "the inert attribute is kept");
  assert.ok(tag.includes("(https://evil.example/x)"), "the reader can still see where it points");
});

/* ------------------------------------------------------------------------- size caps */

test("an oversized chart is replaced by the plain line", async () => {
  const big = Buffer.alloc(MAX_ASSET_BYTES + 1, 0x78);
  const readAsset = assets({ "__render/b1.svg": { body: big, contentType: "image/svg+xml" } });
  const en = await buildRecipientView({ indexHtml: doc(chart()), readAsset });
  assert.ok(en.includes(`<p class="chart-note">${copyFor("en").chartTooLarge}</p>`),
    "the EN line is the fixed sentence");
  assert.equal(RECIPIENT_COPY.en.chartTooLarge, "This chart is too large to show here.");
  assert.ok(!en.includes('src="data:'), "nothing was inlined");

  const es = await buildRecipientView({ indexHtml: doc(chart()), readAsset, lang: "es" });
  assert.ok(es.includes(`<p class="chart-note">${copyFor("es").chartTooLarge}</p>`),
    "the ES line is the fixed sentence");
  assert.ok(!es.includes('src="data:'), "nothing was inlined in Spanish either");
});

test("the whole view stops at 6 MB of images, and each chart still shows after it", async () => {
  // Each chart is under the per-asset cap, so only the total cap can refuse one here.
  const each = Buffer.alloc(900_000, 0x78);
  const entries = {};
  const body = [];
  for (let i = 1; i <= 8; i++) {
    entries[`__render/b${i}.svg`] = { body: each, contentType: "image/svg+xml" };
    body.push(chart(`__render/b${i}.svg`));
  }
  const html = await buildRecipientView({ indexHtml: doc(body.join("\n")), readAsset: assets(entries) });
  const inlined = (html.match(/src="data:image\/svg\+xml;base64,/g) || []).length;
  const notes = (html.match(/<p class="chart-note">/g) || []).length;
  assert.equal(inlined, Math.floor(MAX_TOTAL_BYTES / 900_000), "only what fits in 6 MB is inlined");
  assert.equal(inlined + notes, 8, "every chart is either shown or named as too large");
  assert.ok(notes >= 1, "the charts past the cap carry the plain line");
});

test("an asset that cannot be read is the plain line, never a broken image", async () => {
  const html = await buildRecipientView({
    indexHtml: doc(chart("__render/missing.svg")),
    readAsset: assets({}),
  });
  assert.ok(html.includes(`<p class="chart-note">${copyFor("en").chartTooLarge}</p>`));
  assert.ok(!html.includes("<img"), "no image tag survives");
});

/* ------------------------------------------------------------------------- hostile input */

test("the view contains no script, iframe, object or on* attribute", async () => {
  const hostile = doc(`
<script>alert(1)</script>
<iframe src="https://evil.example/frame"></iframe>
<object data="https://evil.example/obj"></object>
<embed src="https://evil.example/e">
<p onclick="alert(1)">words</p>
<p style="background:url(javascript:alert(1))">styled</p>
<a href="javascript:alert(1)">a bad link</a>
<a data-inert-href="https://evil.example/x" title="https://evil.example/x" onclick="alert(1)">inert</a>
<img src="__render/b1.svg" onerror="alert(1)" alt="Chart">
`);
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"></svg>');
  const html = await buildRecipientView({
    indexHtml: hostile,
    readAsset: assets({ "__render/b1.svg": { body: svg, contentType: "image/svg+xml" } }),
  });
  assert.doesNotMatch(html, /<script/i);
  assert.doesNotMatch(html, /<iframe/i);
  assert.doesNotMatch(html, /<object/i);
  assert.doesNotMatch(html, /<embed/i);
  assert.doesNotMatch(html, /<form/i, "no form unless the comment scope adds one");
  assert.doesNotMatch(html, /\son[a-z]+\s*=/i, "no event handler attribute");
  assert.doesNotMatch(html, /\sstyle="/i, "no style attribute");
  assert.doesNotMatch(html, /href="javascript:/i);
  assert.doesNotMatch(html, /src="javascript:/i);
  assert.ok(html.includes(">words</p>"), "the words a hostile tag wrapped are still there");
  assert.ok(html.includes('src="data:image/svg+xml;base64,'), "the real chart was still inlined");
});

test("a stylesheet that tries to fetch or execute is dropped whole", async () => {
  const html = await buildRecipientView({
    indexHtml: doc("<p>Words</p>", { css: `body{background:url(https://evil.example/p.png)}p{color:red}` }),
    readAsset: assets({}),
  });
  assert.ok(!html.includes("evil.example"), "the sheet is gone, not edited");
  assert.ok(!html.includes("color:red"), "no stored rule reaches the page");
  assert.ok(html.includes("<p>Words</p>"), "the document itself still renders");
  assert.ok(html.includes(`<style>${RECIPIENT_DOC_CSS}</style>`),
    "the page carries this repo's own sheet instead");
});

test("no stored style element or style attribute ever reaches the reader", async () => {
  // WHY THIS SHAPE: a regex filter over a stored sheet cannot be trusted, because a browser's CSS and
  // HTML parsers read the raw text differently. Each sheet below is a variant that used to get past such
  // a filter: a `</style` that ends the element early, CSS escapes that spell `url(` and `@import`, and a
  // `<` inside the sheet. Nothing stored is filtered any more, so none of them reach the output at all.
  // The escaping variants sit in the HEAD, where a stored document's own sheet lives and where the old
  // filter read it; the body carries the raw-text and attribute variants, which the sanitiser is the only
  // thing standing between a reader and. Every one of them must be absent from the output.
  const stored = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Weekly listings</title>`
    + `<style>p{color:red}</style>`
    + `<style></style><script>alert(1)</script></style>`
    + `<style>body{background:\\75 rl(https://evil.example/x)}</style>`
    + `<style>@\\69mport "https://evil.example/y";</style>`
    + `</head><body><main>`
    + `<style>p::after{content:"<img src=https://evil.example/w>"}</style>`
    + `<p style="background:url(https://evil.example/z)">Words</p>`
    + `<p>More words</p>`
    + `</main></body></html>`;
  const html = await buildRecipientView({ indexHtml: stored, readAsset: assets({}) });

  for (const needle of [
    "evil.example", "</style><script>", "alert(1)", "\\75 rl(", "@\\69mport", "<script", "<img",
    "color:red", "url(",
  ]) {
    assert.ok(!html.includes(needle), `${needle} is not in the view`);
  }
  assert.doesNotMatch(html, /\sstyle="/i, "no style attribute survives");
  assert.deepEqual(styleSheets(html), [RECIPIENT_DOC_CSS, VIEW_CSS],
    "the only style elements are the builder's own, each equal to a constant");
  assert.ok(html.includes("<p>Words</p>"), "the text the hostile tags wrapped still renders");
  assert.ok(html.includes("<p>More words</p>"));
});

test("the copied stylesheets still match the renderer's own", () => {
  // WHY A TEXT READ AND NOT AN IMPORT: the recipient view may not pass a stored sheet through and may not
  // import the bundle (an installed copy can be older than this file), so it carries its own copy of the
  // renderer's two sheets. Reading bundles/artifacts/server/render.js as TEXT makes a renderer CSS change
  // fail here until RECIPIENT_DOC_CSS / SPEC_FIGURE_CSS are updated in the same commit, and it keeps the
  // guard working when the bundle module itself cannot be loaded.
  const renderer = readFileSync(join(REPO, "bundles/artifacts/server/render.js"), "utf8");
  assert.ok(renderer.includes(RECIPIENT_DOC_CSS), "DOC_CSS is copied character for character");
  assert.ok(renderer.includes(SPEC_FIGURE_CSS), "the spec figure rule is copied character for character");
});

/* ------------------------------------------------------------------------- comments */

test("comment form only for a comment-scope link", async () => {
  const view = await buildRecipientView({ indexHtml: doc("<p>Words</p>"), readAsset: assets({}) });
  assert.ok(!view.includes('class="comments"'), "a view-scope link with no threads has no comment section");
  assert.ok(!view.includes('class="comment-form"'));
  assert.ok(!view.includes(copyFor("en").commentsHeading), "and no heading either");

  const comment = await buildRecipientView({
    indexHtml: doc("<p>Words</p>"),
    readAsset: assets({}),
    commentForm: { nonce: 'a"b&c' },
  });
  assert.ok(comment.includes(`<h2>${copyFor("en").commentsHeading}</h2>`));
  assert.ok(comment.includes(`<p class="no-comments">${copyFor("en").noComments}</p>`));
  assert.ok(comment.includes('<form class="comment-form" method="post" action="">'));
  assert.ok(comment.includes('name="formNonce" value="a&quot;b&amp;c"'), "the nonce is escaped");
  assert.ok(comment.includes(`<label for="comment-text">${copyFor("en").addComment}</label>`));
  assert.ok(comment.includes('name="text" maxlength="4000" required'));
  assert.ok(comment.includes(`<button type="submit">${copyFor("en").sendComment}</button>`));

  const noticed = await buildRecipientView({
    indexHtml: doc("<p>Words</p>"),
    readAsset: assets({}),
    commentForm: { nonce: "n", notice: { kind: "error", text: copyFor("en").errEmpty } },
  });
  assert.ok(noticed.includes(`<p class="notice notice-error">${copyFor("en").errEmpty}</p>`),
    "the caller's fixed line lands in the notice slot");
  assert.ok(noticed.indexOf('class="notice') < noticed.indexOf('class="comment-form"'),
    "the notice sits above the form");
});

test("threads render escaped with a Closed tag", async () => {
  const threads = [{
    id: "t1",
    status: "resolved",
    comments: [
      { label: "You", text: "Line one\nLine <b>two</b> & more", createdAt: 1 },
      { label: "Listings bot (AI)", text: "Done.", createdAt: 2 },
    ],
  }];
  const html = await buildRecipientView({
    indexHtml: doc("<p>Words</p>"),
    readAsset: assets({}),
    threads,
    commentForm: { nonce: "n" },
  });
  assert.ok(html.includes(`<p class="thread-closed">${copyFor("en").closed}</p>`),
    "a resolved thread carries the fixed Closed tag");
  assert.ok(html.includes("Line one<br>Line &lt;b&gt;two&lt;/b&gt; &amp; more"), "text is escaped, newlines are breaks");
  assert.ok(!html.includes("<b>two</b>"), "no markup from a comment reaches the page");
  assert.ok(html.includes('<p class="comment-label">You</p>'));
  assert.ok(html.includes('<p class="comment-label">Listings bot (AI)</p>'));

  // A view-scope link that already has a thread shows it, still without a form.
  const viewOnly = await buildRecipientView({
    indexHtml: doc("<p>Words</p>"),
    readAsset: assets({}),
    threads: [{ id: "t2", status: "open", comments: [{ label: "The sender", text: "Hello", createdAt: 1 }] }],
  });
  assert.ok(viewOnly.includes('class="comments"'), "the thread is shown");
  assert.ok(viewOnly.includes("Hello"));
  assert.ok(!viewOnly.includes('class="comment-form"'), "a view-scope link gets no form");
  assert.ok(!viewOnly.includes('class="thread-closed"'), "an open thread carries no Closed tag");
});

/* ------------------------------------------------------------------------- chrome and copy */

test("es renders the Spanish chrome", async () => {
  const html = await buildRecipientView({
    indexHtml: doc("<p>Hola</p>"),
    readAsset: assets({}),
    commentForm: { nonce: "n" },
    lang: "es",
  });
  assert.ok(html.startsWith("<!doctype html>"));
  assert.ok(html.includes('<html lang="es">'));
  assert.ok(html.includes(`<h2>${copyFor("es").commentsHeading}</h2>`));
  assert.ok(html.includes('<meta name="referrer" content="no-referrer">'));
  assert.ok(html.includes("<title>Weekly listings</title>"), "the document's own title, escaped");

  const notice = renderRecipientNotice({ kind: "expired", lang: "es" });
  assert.ok(notice.includes('<html lang="es">'));
  assert.ok(notice.includes(copyFor("es").expired));
  assert.ok(!notice.includes("<p>Hola</p>"));
});

test("the notice pages carry only the fixed line", () => {
  const cases = [
    ["expired", copyFor("en").expired],
    ["unknown", copyFor("en").unknownLink],
    ["unavailable", copyFor("en").unavailable],
  ];
  for (const [kind, line] of cases) {
    const html = renderRecipientNotice({ kind });
    assert.ok(html.startsWith("<!doctype html>"), `${kind}: a complete document`);
    assert.ok(html.includes(line), `${kind}: the fixed line`);
    assert.ok(html.includes('<meta name="referrer" content="no-referrer">'), `${kind}: no referrer`);
    assert.doesNotMatch(html, /<script/i, `${kind}: no script`);
    assert.equal((html.match(/<p\b/g) || []).length, 1, `${kind}: one paragraph, the line`);
  }
});

test("pickLang reads the header, and never throws", () => {
  assert.equal(pickLang("es"), "es");
  assert.equal(pickLang("es-MX,en;q=0.9"), "es", "the first tag decides when it is Spanish");
  assert.equal(pickLang("en;q=0.5,es;q=0.9"), "es", "otherwise the strongest tag does");
  assert.equal(pickLang("en-US,en;q=0.9"), "en");
  assert.equal(pickLang("es;q=0"), "en", "a zero weight is not a choice");
  assert.equal(pickLang("fr-FR,de;q=0.8"), "en", "a language this product does not speak is English");
  assert.equal(pickLang(undefined), "en");
  assert.equal(pickLang(null), "en");
  assert.equal(pickLang(""), "en");
  assert.equal(pickLang("*"), "en");
  assert.equal(pickLang(";;;,,,q=x"), "en");
  assert.equal(pickLang(7), "en");
});

test("the copy tables have the same keys, no em dash, and one place for {bot}", () => {
  const en = Object.keys(RECIPIENT_COPY.en).sort();
  const es = Object.keys(RECIPIENT_COPY.es).sort();
  assert.deepEqual(es, en, "EN and ES carry exactly the same keys");
  assert.deepEqual(en, [
    "addComment", "anotherReader", "bot", "chartTooLarge", "closed", "commentsHeading", "errEmpty",
    "errFormExpired", "errOther", "errRate", "errThreads", "errTooLong", "errViewOnly", "expired",
    "noComments", "sendComment", "sender", "sent", "unavailable", "unknownLink", "you",
  ]);
  for (const lang of ["en", "es"]) {
    for (const [key, value] of Object.entries(RECIPIENT_COPY[lang])) {
      assert.equal(typeof value, "string", `${lang}.${key} is a string`);
      assert.ok(value.length > 0, `${lang}.${key} is not empty`);
      assert.ok(!value.includes("\u2014"), `${lang}.${key} carries no em dash`);
    }
  }
  assert.ok(RECIPIENT_COPY.en.bot.includes("{bot}"), "the bot name stays a placeholder");
  assert.ok(RECIPIENT_COPY.es.bot.includes("{bot}"), "in both languages");
  assert.equal(copyFor("en"), RECIPIENT_COPY.en);
  assert.equal(copyFor("es"), RECIPIENT_COPY.es);
  assert.equal(copyFor("es-MX"), RECIPIENT_COPY.es);
  assert.equal(copyFor("xx"), RECIPIENT_COPY.en);
  assert.equal(copyFor(undefined), RECIPIENT_COPY.en);
});

test("recipient copy is the fixed wording", () => {
  // The wording is pasted here character for character instead of being read from anywhere: a
  // paraphrase, a re-diacritic or a "4000" in place of "4,000" has to fail. The keys are in the table's
  // own role order: the three notice pages, the chart note, the comment chrome, the author labels and
  // the refusal lines.
  const approvedEn = {
    expired: "This report link has expired. Ask the sender for a new one.",
    unknownLink: "This link doesn't open a report. Ask the sender for a new one.",
    unavailable: "This report is unavailable right now. Try again in a few minutes.",
    chartTooLarge: "This chart is too large to show here.",
    commentsHeading: "Comments",
    noComments: "No comments yet.",
    addComment: "Add a comment",
    sendComment: "Send comment",
    sent: "Thanks. Your comment was sent.",
    you: "You",
    sender: "The sender",
    bot: "{bot} (AI)",
    anotherReader: "Another reader",
    closed: "Closed",
    errRate: "You've sent a lot of comments recently. Try again later.",
    errThreads: "This report has too many open comments right now. The sender has been told.",
    errFormExpired: "This page was open too long. Reload it and try again.",
    errEmpty: "Write a comment first.",
    errTooLong: "That comment is too long. Keep it under 4,000 characters.",
    errViewOnly: "Comments aren't open on this link.",
    errOther: "Your comment didn't go through. Try again later.",
  };
  const approvedEs = {
    expired: "Este enlace del informe ha caducado. Pide uno nuevo a quien te lo envió.",
    unknownLink: "Este enlace no abre ningún informe. Pide uno nuevo a quien te lo envió.",
    unavailable: "Este informe no está disponible ahora. Inténtalo de nuevo en unos minutos.",
    chartTooLarge: "Este gráfico es demasiado grande para mostrarlo aquí.",
    commentsHeading: "Comentarios",
    noComments: "Aún no hay comentarios.",
    addComment: "Añade un comentario",
    sendComment: "Enviar comentario",
    sent: "Gracias. Tu comentario se envió.",
    you: "Tú",
    sender: "Quien lo envió",
    bot: "{bot} (IA)",
    anotherReader: "Otra persona",
    closed: "Cerrado",
    errRate: "Has enviado muchos comentarios hace poco. Inténtalo más tarde.",
    errThreads: "Este informe tiene demasiados comentarios abiertos ahora. Ya se le avisó a quien lo envió.",
    errFormExpired: "Esta página estuvo abierta demasiado tiempo. Vuelve a cargarla e inténtalo de nuevo.",
    errEmpty: "Escribe un comentario primero.",
    errTooLong: "Ese comentario es demasiado largo. Debe tener menos de 4.000 caracteres.",
    errViewOnly: "Este enlace no admite comentarios.",
    errOther: "Tu comentario no se envió. Inténtalo más tarde.",
  };
  assert.deepEqual(RECIPIENT_COPY.en, approvedEn, "every EN line is the fixed wording, word for word");
  assert.deepEqual(RECIPIENT_COPY.es, approvedEs, "every ES line is the fixed wording, word for word");
});

/* --------------------------------------------------------------- the stored version read */

async function freshDb() {
  const dir = join(root, "t" + (++copies));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  openDbs.push(db);
  return db;
}

test("loadVersionForView reads the version's own files, and refuses a missing or flagged one", async () => {
  const db = await freshDb();
  await initArtifactsTables(db);
  const dataDir = join(root, "blobs", "1");
  mkdirSync(dataDir, { recursive: true });
  const blobs = await createBlobStore(db, dataDir, { forceKind: "local" });
  const runtime = { store: bundleStore, initArtifactsTables, blobs, markdownBlocks, limits: bundleLimits.LIMITS };

  const plot = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>');
  const { id, versionN } = await bundleStore.createArtifact(db, blobs, {
    title: "Weekly listings",
    type: "document",
    source: {
      markdown: "![plot](plot.svg)\n\nSome words.",
      title: "Weekly listings",
      assets: [{ path: "plot.svg", contentType: "image/svg+xml", base64: plot.toString("base64") }],
    },
    actor: { kind: "session" },
  }, { markdownBlocks });

  const loaded = await loadVersionForView(db, { artifacts: runtime }, { artifactId: id, n: versionN });
  assert.ok(loaded, "the version is readable");
  assert.ok(loaded.indexHtml.includes('<img src="plot.svg"'), "the stored page references its own asset");
  const asset = await loaded.readAsset("plot.svg");
  assert.equal(asset.contentType, "image/svg+xml");
  assert.deepEqual(asset.body, plot);
  assert.equal(await loaded.readAsset("other.png"), null, "a path the version does not hold is null");
  assert.equal(await loaded.readAsset("../../../etc/passwd"), null, "a traversal is null");
  assert.ok((await loaded.listAssets()).includes("index.html"));

  const html = await buildRecipientView({ indexHtml: loaded.indexHtml, readAsset: loaded.readAsset });
  assert.ok(html.includes("Some words."), "the stored text is in the view");
  assert.ok(html.includes(`data:image/svg+xml;base64,${plot.toString("base64")}`), "the uploaded image is inlined");

  assert.equal(await loadVersionForView(db, { artifacts: runtime }, { artifactId: id, n: 99 }), null,
    "a version that does not exist is null");
  await db.execute({
    sql: "UPDATE artifact_versions SET flagged_reason = 'tripwire' WHERE artifact_id = ? AND n = ?",
    args: [id, versionN],
  });
  assert.equal(await loadVersionForView(db, { artifacts: runtime }, { artifactId: id, n: versionN }), null,
    "a flagged version is never served");
});

test("loadVersionForView refuses an artifact that is not a document", async () => {
  const db = await freshDb();
  await initArtifactsTables(db);
  const dataDir = join(root, "blobs", "kind");
  mkdirSync(dataDir, { recursive: true });
  const blobs = await createBlobStore(db, dataDir, { forceKind: "local" });
  const runtime = { store: bundleStore, initArtifactsTables, blobs, markdownBlocks, limits: bundleLimits.LIMITS };

  const { id, versionN } = await bundleStore.createArtifact(db, blobs, {
    title: "Weekly listings",
    type: "document",
    source: { markdown: "# Weekly listings\n\nSome words.", title: "Weekly listings" },
    actor: { kind: "session" },
  }, { markdownBlocks });

  assert.ok(await loadVersionForView(db, { artifacts: runtime }, { artifactId: id, n: versionN }),
    "a document artifact's version is readable");

  // An artifact row that cannot be read is a refusal, never an exception out of the door.
  const unreadable = {
    ...runtime,
    store: { ...bundleStore, getArtifact: async () => { throw new Error("unreadable artifacts table"); } },
  };
  assert.equal(await loadVersionForView(db, { artifacts: unreadable }, { artifactId: id, n: versionN }), null,
    "an artifact row that cannot be read is null");

  // The store's own `type` CHECK allows page/document/diagram/data and more, so an `index.html` is not
  // unique to a document. Rewriting the row's kind is the cheapest honest way to build the case: the
  // version and its index.html stay exactly as they were, and only the kind says `page`.
  await db.execute({ sql: "UPDATE artifacts SET type = 'page' WHERE id = ?", args: [id] });
  assert.equal(await loadVersionForView(db, { artifacts: runtime }, { artifactId: id, n: versionN }), null,
    "another kind is refused even though its version and index.html exist");

  await db.execute({ sql: "UPDATE artifacts SET deleted_at = ? WHERE id = ?", args: [Date.now(), id] });
  assert.equal(await loadVersionForView(db, { artifacts: runtime }, { artifactId: id, n: versionN }), null,
    "a deleted artifact is refused too: its row cannot be read");
});