// The report document: the source shape the artifacts renderer requires, the order of its body, the two
// limits checked before a version is written, and the link set a version may show.
//
// Harness: `assembleDocument` called directly (it is pure), and the real artifacts renderer and version
// writer from this repo's bundle folder for the two acceptance cases, the way
// tests/reports-artifact-bridge.test.js loads them (a scratch crow.db, a local blob store).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = mkdtempSync(join(tmpdir(), "reports-document-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const BUNDLE = join(REPO, "bundles", "artifacts", "server");
const bundleImport = (file) => import(pathToFileURL(join(BUNDLE, file)).href);
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const { createReport, getReport } = await import("../servers/gateway/reports/store.js");
const { writeRunVersion } = await import("../servers/gateway/reports/artifact-bridge.js");
const {
  AI_SECTION_TYPES, DEFAULT_EMPTY_TEXT, DOCUMENT_LIMITS, LATE_LINE, TOO_LARGE_TEXT, aiHeading,
  assembleDocument, cellMarkdown, countSpecFences, escapeMd, escapeRecipeText, itemLinks, linkDestination,
} = await import("../servers/gateway/reports/document.js");
const { markdownBlocks } = await import("../servers/blog/renderer.js");
const { Marked } = await import("marked");
const md = new Marked({ gfm: true, breaks: true });
const { renderVersion } = await import(pathToFileURL(join(BUNDLE, "render.js")).href);
const bundleStore = await bundleImport("store.js");
const { initArtifactsTables } = await bundleImport("init-tables.js");
const { createBlobStore } = await bundleImport("blob-store-minio.js");
const bundleLimits = await bundleImport("limits.js");

const PROJECT = 7;
const T0 = 1_700_000_000_000;
const RUN = Object.freeze({ id: "rrn-0000000000000000", trigger: "manual", startedAt: T0, createdAt: T0 });

const ITEMS = Object.freeze([
  { title: "Flat with a view", link: "https://example.com/a" },
  { title: "Small studio", link: "https://example.com/b" },
]);

const TABLE = Object.freeze({
  type: "table",
  blockId: "t1",
  markdown: `| title | link |
| --- | --- |
| Flat with a view | [https://example.com/a](<https://example.com/a>) |`,
});

const CHART = Object.freeze({
  type: "chart",
  blockId: "c1",
  markdown: "```vega-lite\n{\"mark\":\"bar\",\"data\":{\"values\":[]}}\n```",
  specs: 1,
});

/** A map section as the block writes it: the plot file plus the list of its points. */
function mapSection(name = "m1") {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="2"/></svg>`;
  return {
    type: "map",
    blockId: name,
    markdown: `![1](map-${name}.svg)\n\n1. 52.50, 13.40`,
    assets: [{ path: `map-${name}.svg`, contentType: "image/svg+xml", base64: Buffer.from(svg).toString("base64") }],
  };
}

const AI = Object.freeze({ type: "ai_commentary", blockId: "ai1", markdown: "Two listings are new." });

const SPEC_LANGS = Object.freeze(["vega-lite", "mermaid", "d2"]);
const ATTRIBUTION = "AI commentary (written by Listings bot, not part of the fixed report)";

/**
 * Every token the renderer's own lexer finds in a stretch of markdown, at any depth, plus the top-level
 * blocks the renderer's `markdownBlocks` builds: whether something is a heading, a link or a fence is
 * answered by the renderer's grammar, never by this test's own idea of one.
 */
function allTokens(markdown) {
  const found = [];
  const seen = new Set();
  const stack = [...md.lexer(markdown)];
  while (stack.length) {
    const token = stack.pop();
    if (token == null || typeof token !== "object" || seen.has(token)) continue;
    seen.add(token);
    found.push(token);
    for (const key of ["tokens", "items", "header"]) if (Array.isArray(token[key])) stack.push(...token[key]);
    if (Array.isArray(token.rows)) for (const row of token.rows) stack.push(...row);
  }
  return found;
}

/** The shapes a document carries that a section must not be able to put there by itself. */
function shapesOf(markdown, allowed = []) {
  const tokens = allTokens(markdown);
  const ofType = (type) => tokens.filter((token) => token.type === type);
  return {
    headings: ofType("heading").map((token) => ({ depth: token.depth, text: String(token.text || "") })),
    foreignLinks: ["link", "image", "url", "autolink"].flatMap(ofType)
      .map((token) => String(token.href || ""))
      .filter((href) => !allowed.includes(href)),
    images: ofType("image").length,
    html: ofType("html").length,
    specs: markdownBlocks(markdown).filter((block) => block.type === "code" && SPEC_LANGS.includes(block.lang)),
  };
}

/**
 * The first lines a section may not make live once it is joined to the sections before it: four spaces of
 * indent make the line an indented code block, so dropping the indent turns a line the lexer reads as
 * inert into live markdown of the document.
 */
const INDENTED_FIRST_LINES = Object.freeze([
  "    ## x",
  "    [x](https://evil.example)",
  "    ![p](https://evil.example/p.png)",
  "    <img src=https://evil.example/p.png>",
  "    ```vega-lite\n    {}\n    ```",
]);

/** A section of `type` whose first line carries the indent, asserted inert in the assembled document. */
function assertIndentedFirstLineInert(type, markdown) {
  const out = assembleDocument({
    run: RUN,
    sections: [TABLE, { type, blockId: "s1", markdown }],
    items: ITEMS,
    botName: "Listings bot",
  });
  const shapes = shapesOf(out.source.markdown, out.allowedLinks);
  const label = `${type} ${JSON.stringify(markdown)}`;
  assert.deepEqual(shapes.foreignLinks, [], `${label}: no link outside the allowed set`);
  assert.equal(shapes.images, 0, `${label}: no image`);
  assert.equal(shapes.html, 0, `${label}: no raw html`);
  assert.deepEqual(shapes.specs, [], `${label}: no spec fence`);
  const own = shapes.headings.filter((heading) => !heading.text.startsWith("AI commentary (written by"));
  assert.deepEqual(own, [], `${label}: no heading of its own`);
}

/* ------------------------------------------------------------------------- the body order */

test("ai section is last and labelled", () => {
  const out = assembleDocument({
    report: { title: "Weekly listings" },
    run: RUN,
    sections: [AI, TABLE, { type: "text", blockId: "t1b", markdown: "Opening words." }],
    items: ITEMS,
    botName: "Listings bot",
  });
  const markdown = out.source.markdown;
  const aiAt = markdown.indexOf(aiHeading("Listings bot"));
  assert.equal(aiAt > markdown.indexOf("Opening words."), true, "the AI heading comes after every section");
  assert.equal(aiHeading("Listings bot"),
    `## ${ATTRIBUTION}`);
  assert.equal(markdown.endsWith("Two listings are new."), true, "the AI body closes the document");
  assert.equal(markdown.split(aiHeading("Listings bot")).length, 2, "one AI heading, whatever the count");
});

test("two AI sections sit under one heading at the end", () => {
  const annotate = { type: "annotate", blockId: "an1", markdown: "Annotated." };
  const out = assembleDocument({
    run: RUN, sections: [AI, TABLE, annotate], items: ITEMS, botName: "Listings bot",
  });
  assert.equal(out.source.markdown.split(aiHeading("Listings bot")).length, 2);
  assert.ok(out.source.markdown.indexOf("Annotated.") > out.source.markdown.indexOf(aiHeading("Listings bot")));
  assert.deepEqual([...AI_SECTION_TYPES], ["ai_commentary", "annotate"]);
});

test("the AI attribution is the document's own h2 heading, and the only heading it writes", () => {
  const out = assembleDocument({ run: RUN, sections: [TABLE, AI], items: ITEMS, botName: "Listings bot" });
  const shapes = shapesOf(out.source.markdown, out.allowedLinks);
  assert.deepEqual(shapes.headings, [{ depth: 2, text: ATTRIBUTION }],
    "one h2, the attribution; a model's bold line cannot read as one");
});

/* ------------------------------------------------- a section's first line keeps its own indent */

test("an indented first line of an AI section stays inert in the document", () => {
  for (const markdown of INDENTED_FIRST_LINES) assertIndentedFirstLineInert("ai_commentary", markdown);
});

test("an indented first line of a custom section stays inert in the document", () => {
  for (const markdown of INDENTED_FIRST_LINES) assertIndentedFirstLineInert("custom", markdown);
});

test("an indented first line of a bot's text body stays inert in the document", () => {
  for (const markdown of INDENTED_FIRST_LINES) assertIndentedFirstLineInert("text", markdown);
});

test("a section's leading blank lines still go, and its trailing whitespace with them", () => {
  const out = assembleDocument({
    run: RUN,
    sections: [{ type: "text", blockId: "t0", markdown: "\n\n  Opening words.  \n\n" }, TABLE],
    items: ITEMS,
  });
  assert.ok(out.source.markdown.startsWith("  Opening words.\n\n| title |"),
    "the indent of the first line is kept, the blank lines before it and the stray spaces after it are not");
});

test("an unclosed fence in an untrusted section cannot swallow the table or the attribution", () => {
  // This is the direct assemble path: nothing here runs neutralizeLinks, so the closing fence has to be
  // the assembly's own. Every untrusted section type is covered, and the sentinel after the document is
  // what a fence left open would eat.
  for (const type of ["custom", "text", "ai_commentary", "annotate"]) {
    const out = assembleDocument({
      run: RUN,
      sections: [
        { type, blockId: "s1", markdown: "words\n\n```\nnot closed" },
        TABLE,
        AI,
      ],
      items: ITEMS,
      botName: "Listings bot",
    });
    const blocks = markdownBlocks(`${out.source.markdown}\n\nsentinel line`);
    assert.ok(blocks.some((block) => block.type === "paragraph" && block.text.includes("sentinel line")),
      `${type}: the fence is closed`);
    assert.ok(blocks.some((block) => block.type === "table"), `${type}: the owner table is still a table`);
    assert.ok(blocks.some((block) => block.type === "heading" && block.text.includes("not part of the fixed report")),
      `${type}: the attribution is still a heading`);
  }
});

test("a fence a list item or a blockquote holds needs no closer, so it cannot open one at the top level", () => {
  // A fence inside a list item or a blockquote ends with its own container. A column-0 closer appended
  // after it would itself be a NEW top-level opener, and it would swallow the table and the attribution.
  for (const type of ["custom", "text"]) {
    for (const tail of ["- item\n\n  ```\n  x", "1. a\n   ~~~~\n   b", "- a\n  ```vega-lite\n  {}"]) {
      const out = assembleDocument({
        run: RUN,
        sections: [{ type, blockId: "s1", markdown: tail }, TABLE, AI],
        items: ITEMS,
        botName: "Listings bot",
      });
      const blocks = markdownBlocks(out.source.markdown);
      const label = `${type} ${JSON.stringify(tail)}`;
      assert.ok(blocks.some((block) => block.type === "table"), `${label}: the owner table is still a table`);
      const heading = blocks.find((block) => block.type === "heading");
      assert.ok(heading && heading.text.includes("not part of the fixed report"),
        `${label}: the attribution is still a heading`);
      assert.deepEqual(blocks.filter((block) => block.type === "code"), [],
        `${label}: the section left no top-level code block behind`);
    }
  }
});

test("a top-level fence left open is still closed, with its own indent and marker", () => {
  const out = assembleDocument({
    run: RUN,
    sections: [{ type: "custom", blockId: "s1", markdown: "words\n\n  ````\nnot closed" }, TABLE, AI],
    items: ITEMS,
    botName: "Listings bot",
  });
  const blocks = markdownBlocks(out.source.markdown);
  assert.ok(blocks.some((block) => block.type === "table"), "the table is still a table");
  assert.ok(blocks.some((block) => block.type === "heading" && block.text.includes("not part of the fixed report")),
    "the attribution is still a heading");
  const code = blocks.find((block) => block.type === "code");
  assert.ok(code, "the fence is still a code block of its own");
  assert.ok(!String(code.text || "").includes("title"), "and its closer ended it before the table");
});

/* ------------------------------------------------- a boundary a section cannot carry across */

/** The code blocks the renderer's own lexer reads, at any depth. */
function codeBlocks(markdown) {
  return allTokens(markdown).filter((token) => token.type === "code");
}

test("a list in one section cannot carry an indented first line of the next", () => {
  // Four spaces of indent make a line an indented code block, which is why a section's first line keeps
  // its indent. The line here is inert on its own; joined straight onto the list before it, with nothing
  // but a blank line in between, the list item takes it as its own paragraph and the link goes live.
  const out = assembleDocument({
    run: RUN,
    sections: [
      { type: "text", blockId: "s1", markdown: "- item" },
      { type: "text", blockId: "s2", markdown: "    continued [x](https://evil.example)" },
    ],
    items: ITEMS,
  });
  const markdown = out.source.markdown;
  const shapes = shapesOf(markdown, out.allowedLinks);
  assert.deepEqual(shapes.foreignLinks, [], "the indented line's link is not live in the body");
  assert.deepEqual(shapes.headings, [], "the separator adds no heading and no setext heading");
  assert.equal(shapes.html, 0, "and no raw html");
  const indented = codeBlocks(markdown).find((token) => String(token.text || "").includes("continued"));
  assert.ok(indented, "the line is a fresh indented code block");
  assert.ok(String(indented.raw || "").includes("    continued [x](https://evil.example)"),
    "with the indent it was written with");
  assert.ok(markdown.includes("***"), "a thematic break ends the list before it");
});

test("a section that opens a blockquote cannot join the blockquote before it", () => {
  const out = assembleDocument({
    run: RUN,
    sections: [
      { type: "text", blockId: "s1", markdown: "> quoted words" },
      { type: "text", blockId: "s2", markdown: "> continued" },
    ],
    items: ITEMS,
  });
  assert.ok(out.source.markdown.includes("> quoted words\n\n***\n\n> continued"),
    "the two quotes are ended by a thematic break, so neither section writes inside the other");
});

test("no rule is drawn between two parts the owner wrote", () => {
  // The rule exists to stop a section nobody approved turning an indented line into live markdown of a
  // container before it. Between two parts the owner wrote there is nothing to guard, and a visible rule
  // there is only noise.
  const out = assembleDocument({
    run: RUN,
    sections: [
      { type: "text", authoredBy: "owner", blockId: "o1", markdown: "- one\n- two" },
      { type: "text", authoredBy: "owner", blockId: "o2", markdown: "> a note" },
    ],
    items: ITEMS,
  });
  assert.ok(out.source.markdown.includes("- two\n\n> a note"), "the two trusted parts sit side by side");
  assert.ok(!out.source.markdown.includes("***"), "with no visible rule between them");
});

test("an owner's indented line after the owner's own list joins it, and is not refused", () => {
  const out = assembleDocument({
    run: RUN,
    sections: [
      { type: "text", authoredBy: "owner", blockId: "o1", markdown: "- one" },
      { type: "text", authoredBy: "owner", blockId: "o2", markdown: "    second paragraph of the item" },
    ],
    items: ITEMS,
  });
  assert.equal(out.source.markdown, "- one\n\n    second paragraph of the item");
  assert.deepEqual(markdownBlocks(out.source.markdown).map((block) => block.type), ["list"],
    "one list, its item carrying the owner's own second paragraph");
});

test("a reference definition in one section cannot resolve a link written in another", () => {
  const out = assembleDocument({
    run: RUN,
    sections: [
      { type: "custom", blockId: "s1", markdown: "The note.\n\n[x]: https://evil.example" },
      { type: "text", blockId: "s2", markdown: "See [x] for more." },
    ],
    items: ITEMS,
  });
  const markdown = out.source.markdown;
  assert.deepEqual(shapesOf(markdown, out.allowedLinks).foreignLinks, [], "no link token in the body");
  assert.ok(!markdown.includes("evil.example"), "no definition survives into the assembled text");
  assert.ok(markdown.includes("See [x] for more."), "the use stays the words it is");
});

test("a fence left open in one section is closed before the section after it", () => {
  const out = assembleDocument({
    run: RUN,
    sections: [
      { type: "custom", blockId: "s1", markdown: "words\n\n````\nnot closed" },
      { type: "text", blockId: "s2", markdown: "- item" },
      TABLE,
      AI,
    ],
    items: ITEMS,
    botName: "Listings bot",
  });
  const blocks = markdownBlocks(out.source.markdown);
  assert.ok(blocks.some((block) => block.type === "list"), "the section after the fence is not inside it");
  assert.ok(blocks.some((block) => block.type === "table"), "the owner table is still a table");
  assert.ok(blocks.some((block) => block.type === "heading" && block.text.includes("not part of the fixed report")),
    "and the attribution is still a heading");
});

test("a plain boundary keeps the blank line it always had", () => {
  const out = assembleDocument({
    run: RUN,
    sections: [TABLE, { type: "text", blockId: "t2", markdown: "Closing words." }],
    items: ITEMS,
  });
  const markdown = out.source.markdown;
  assert.ok(markdown.endsWith("| Flat with a view | [https://example.com/a](<https://example.com/a>) |\n\nClosing words."),
    "the table and the section after it are joined by the one blank line");
  assert.ok(!markdown.includes("***"), "no separator where the part before leaves nothing open");
  assert.equal(countSpecFences(markdown), 0);
});

test("a foreign link from a bot section fails the run closed", () => {
  // The blocks neutralise their own text, so this is the assembly's own seam: a section carrying a link
  // the run's items do not name may not be written into a version.
  for (const type of ["custom", "text", "ai_commentary"]) {
    assert.throws(() => assembleDocument({
      run: RUN,
      sections: [TABLE, { type, blockId: "s1", markdown: "see [x](https://evil.example)" }],
      items: ITEMS,
    }), (err) => {
      assert.equal(err.code, "too_large", `${type}: the assembly fails closed`);
      assert.equal(err.message, TOO_LARGE_TEXT);
      return true;
    });
  }
});

test("an owner's definition cannot arm a link in a bot section", () => {
  assert.throws(() => assembleDocument({
    run: RUN,
    sections: [
      { type: "text", authoredBy: "owner", blockId: "t1", markdown: "[x]: https://evil.example" },
      { type: "text", authoredBy: "bot", blockId: "s1", markdown: "See [x]." },
    ],
    items: ITEMS,
  }), (err) => {
    assert.equal(err.code, "too_large", "a link the join created is not written");
    assert.equal(err.message, TOO_LARGE_TEXT);
    return true;
  });
});

test("an owner's own markdown keeps its heading and its link", () => {
  const out = assembleDocument({
    run: RUN,
    sections: [
      { type: "text", authoredBy: "owner", blockId: "t1", markdown: "## Week one\n\nSee [the note](https://example.net/x)." },
      { type: "text", authoredBy: "bot", blockId: "s1", markdown: "Body words." },
      TABLE,
    ],
    items: ITEMS,
  });
  const shapes = shapesOf(out.source.markdown, out.allowedLinks);
  assert.deepEqual(shapes.headings, [{ depth: 2, text: "Week one" }], "the owner's heading is kept");
  assert.deepEqual(shapes.foreignLinks, ["https://example.net/x"],
    "and so is the owner's own link, though the run's items do not carry it");
});

test("late run starts with the late line", () => {
  const out = assembleDocument({ run: { ...RUN, late: 1 }, sections: [TABLE], items: ITEMS });
  assert.ok(out.source.markdown.startsWith(LATE_LINE + "\n\n"), "the late line is the first line");
  const notLate = assembleDocument({ run: { ...RUN, late: 0 }, sections: [TABLE], items: ITEMS });
  assert.ok(!notLate.source.markdown.includes(LATE_LINE));
});

test("empty run body uses emptyText", () => {
  const out = assembleDocument({ run: RUN, sections: [TABLE, AI], items: [] });
  assert.equal(out.source.markdown, DEFAULT_EMPTY_TEXT);
  assert.equal(out.summary.count, 0);
  const own = assembleDocument({ run: RUN, sections: [TABLE], items: [], emptyText: "No listings this week." });
  assert.equal(own.source.markdown, "No listings this week.");
});

/* ------------------------------------------------------------ a recipe's own words */

test("escapeMd flattens a line break and closes a block marker at the start of a value", () => {
  assert.equal(escapeMd("a\r\nb"), "a b");
  assert.equal(escapeMd("a\n\nb"), "a b", "a run of breaks is one space");
  assert.equal(escapeMd("a\u00a0b"), "a b");
  assert.equal(escapeMd("a\u2028b"), "a b");
  assert.equal(escapeMd("## heading"), "\\## heading");
  assert.equal(escapeMd("- item"), "\\- item");
  assert.equal(escapeMd("+ item"), "\\+ item");
  assert.equal(escapeMd("1. item"), "1\\. item");
  assert.equal(escapeMd("1) item"), "1\\) item");
  assert.equal(escapeMd("= underline"), "\\= underline");
  assert.equal(escapeMd("~~~vega-lite {}"), "\\~~~vega-lite {}", "a tilde fence cannot open a line");
  assert.equal(escapeMd("> quote"), "&gt; quote", "a quote marker is already escaped text");
  assert.equal(escapeMd("-5 degrees"), "-5 degrees", "only a marker is escaped");
  assert.equal(escapeMd("#tag"), "#tag");
});

test("a recipe string cannot autolink", () => {
  assert.equal(escapeRecipeText("www.evil.example"), "www&#46;evil.example",
    "the `www.` prefix is broken, so the host cannot autolink");
  assert.equal(escapeRecipeText("https://evil.example/x"), "https&#58;//evil.example/x");
  assert.equal(escapeRecipeText("two\nlines"), "two lines", "a recipe string is one line");
  assert.equal(escapeRecipeText("## Listings"), "\\## Listings");
  // The bot's own display name reaches the AI heading, so it takes the same rule.
  assert.equal(aiHeading("www.evil.example"),
    "## AI commentary (written by www&#46;evil.example, not part of the fixed report)");
  assert.equal(aiHeading("a\nb"), "## AI commentary (written by a b, not part of the fixed report)");
});

test("an emptyText that opens a tilde fence adds no spec fence", () => {
  const out = assembleDocument({
    run: RUN, sections: [TABLE], items: [], emptyText: "~~~vega-lite {\"mark\":\"bar\"}",
  });
  assert.equal(countSpecFences(out.source.markdown), 0, "the escaped run cannot open a chart fence");
  const specs = markdownBlocks(out.source.markdown)
    .filter((block) => block.type === "code" && ["vega-lite", "mermaid", "d2"].includes(block.lang));
  assert.deepEqual(specs, []);
});

test("an emptyText with a link, an image or HTML is inert", () => {
  const nasty = "See [the note](https://example.net/x) ![chart](https://example.net/i.png) "
    + "<b>hi</b> www.evil.example";
  const out = assembleDocument({ run: RUN, sections: [TABLE], items: [], emptyText: nasty });
  const markdown = out.source.markdown;
  assert.ok(!markdown.includes("](https://example.net"), "no link syntax survives");
  assert.ok(!markdown.includes("![chart]"), "no image syntax survives");
  assert.ok(!markdown.includes("<b>"), "no raw html survives");
  assert.ok(!markdown.includes("www.evil.example"), "the host is broken, so it cannot autolink");
  assert.ok(markdown.includes("See \\[the note\\]"), "the words are still there, as text");
});

/* ---------------------------------------------------------------------- the limits */

test("a run over 256 KB or 12 charts fails with the too-large line", () => {
  const huge = { type: "text", blockId: "t1", markdown: "x".repeat(300 * 1024) };
  assert.throws(() => assembleDocument({ run: RUN, sections: [huge], items: ITEMS }), (err) => {
    assert.equal(err.code, "too_large");
    assert.equal(err.message, TOO_LARGE_TEXT);
    return true;
  });

  const charts = Array.from({ length: 13 }, (_v, i) => ({ ...CHART, blockId: `c${i}` }));
  assert.throws(() => assembleDocument({ run: RUN, sections: charts, items: ITEMS }), (err) => {
    assert.equal(err.code, "too_large");
    assert.equal(err.message, TOO_LARGE_TEXT);
    return true;
  });

  // Twelve charts and just under the byte limit are both fine, so the refusal is the limit, not charts.
  const twelve = assembleDocument({ run: RUN, sections: charts.slice(0, 12), items: ITEMS });
  assert.equal(twelve.source.markdown.split("```vega-lite").length - 1, 12);
  const nearly = assembleDocument({
    run: RUN,
    sections: [{ type: "text", blockId: "t1", markdown: "y".repeat(200 * 1024) }],
    items: ITEMS,
  });
  assert.equal(nearly.source.markdown.length, 200 * 1024);
});

test("the document limits are the renderer's own numbers", () => {
  assert.equal(DOCUMENT_LIMITS.documentMarkdownBytes, bundleLimits.LIMITS.documentMarkdownBytes);
  assert.equal(DOCUMENT_LIMITS.specsPerVersion, bundleLimits.LIMITS.specsPerVersion);
});

test("the chart count is lexed from the body, never taken from a section's own claim", () => {
  // A section that claims seventy charts and carries none is not over the limit.
  const loud = { type: "text", blockId: "t1", markdown: "plain words", specs: 70 };
  assert.equal(assembleDocument({ run: RUN, sections: [loud], items: ITEMS }).source.markdown,
    "plain words");

  // A section that claims none and carries thirteen is over it.
  const fence = Array.from({ length: 13 }, () => "```vega-lite\n{}\n```").join("\n\n");
  const quiet = { type: "custom", blockId: "s1", markdown: fence, specs: 0 };
  assert.throws(() => assembleDocument({ run: RUN, sections: [quiet], items: ITEMS }), (err) => {
    assert.equal(err.code, "too_large");
    assert.equal(err.message, TOO_LARGE_TEXT);
    return true;
  });
  assert.equal(countSpecFences("```vega-lite\n{}\n```\n\n```mermaid\ngraph LR; a-->b\n```"), 2);
  assert.equal(countSpecFences("```json\n{}\n```"), 0, "a language that is not a spec engine is not one");
});

test("a spec fence no chart section accounts for fails the run closed", () => {
  // A section of any other type may not put a picture into the body: the body's own lexed count sees the
  // fence and nothing in the assembly vouched for it, so the run fails on the existing too-large path
  // rather than writing a version whose picture was never counted.
  const forged = {
    type: "table",
    blockId: "t1",
    markdown: "| title |\n| --- |\n| one |\n\n```vega-lite\n{}\n```",
  };
  assert.throws(() => assembleDocument({ run: RUN, sections: [TABLE, forged], items: ITEMS }), (err) => {
    assert.equal(err.code, "too_large");
    assert.equal(err.message, TOO_LARGE_TEXT);
    return true;
  });

  // The same fence from a chart section's own output is a spec of the document's twelve, and passes.
  const charted = assembleDocument({ run: RUN, sections: [CHART], items: ITEMS });
  assert.equal(countSpecFences(charted.source.markdown), 1);
});

/* ---------------------------------------------------------------- writing the run's version */

const openDbs = [];
let blobs = 0;

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

/** A fresh crow.db and the artifacts runtime a version write takes, the bridge's own seam. */
async function freshRuntime() {
  const dir = join(root, "t" + openDbs.length);
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  openDbs.push(db);
  await initArtifactsTables(db);
  const dataDir = join(root, "blobs", String(++blobs));
  mkdirSync(dataDir, { recursive: true });
  const blobStore = await createBlobStore(db, dataDir, { forceKind: "local" });
  return {
    db,
    runtime: { store: bundleStore, initArtifactsTables, blobs: blobStore, markdownBlocks, limits: bundleLimits.LIMITS },
  };
}

test("the written version carries the document's own assets", async () => {
  const { db, runtime } = await freshRuntime();
  const { id } = await createReport(db, { projectId: PROJECT, owner: "owner", title: "Weekly listings" });
  const report = await getReport(db, id);
  const out = assembleDocument({
    report, run: RUN, sections: [TABLE, mapSection()], items: ITEMS, botName: "Listings bot",
  });

  const n = await writeRunVersion(db, { artifacts: runtime }, {
    report, run: RUN, source: out.source, allowedLinks: out.allowedLinks,
  });
  const pointed = await getReport(db, id);
  assert.match(pointed.artifact_id, /^art_/, "the bridge made the report's artifact");
  const { rows } = await db.execute({
    sql: "SELECT source_json FROM artifact_versions WHERE artifact_id = ? AND n = ?",
    args: [pointed.artifact_id, n],
  });
  const stored = JSON.parse(rows[0].source_json);
  assert.equal(stored.markdown, out.source.markdown);
  assert.equal(stored.assets.length, 1, "the map plot is a file of the version");
  assert.equal(stored.assets[0].path, "map-m1.svg");
  const versionRow = (await db.execute({
    sql: "SELECT allowed_links_json FROM report_versions WHERE artifact_id = ? AND n = ?",
    args: [pointed.artifact_id, n],
  })).rows[0];
  assert.deepEqual(JSON.parse(versionRow.allowed_links_json), ["https://example.com/a", "https://example.com/b"]);
});

/* ------------------------------------------------------------------- the allowed links */

test("allowedLinks is what the items carry, deduped and http(s) only", () => {
  const items = [
    { title: "one", text: "see https://example.com/a and https://example.com/a again" },
    { links: ["https://example.com/b", "ftp://example.com/file", 7] },
    { body: "no link here" },
  ];
  const out = assembleDocument({ run: RUN, sections: [TABLE], items });
  assert.deepEqual(out.allowedLinks, ["https://example.com/a", "https://example.com/b"]);
  assert.deepEqual(itemLinks(items).filter((url) => url.startsWith("https://example.com/b")),
    ["https://example.com/b"]);
  assert.equal(out.summary.count, 3);
});

test("summary counts the items and the ones a diff marked new", () => {
  const items = [{ title: "a", _diff: "new" }, { title: "b", _diff: "changed" }, { title: "c" }];
  const out = assembleDocument({ run: RUN, sections: [TABLE], items });
  assert.deepEqual(out.summary, { count: 3, newCount: 1, headline: "3" });
});

test("allowedLinks holds both the source string and the href a cell emits, nested fields included", () => {
  const items = [
    { title: "one", url: "https://example.com" },
    { attributes: { link: "https://example.com/\u00fcber" } },
    { text: "see https://example.com/b)." },
  ];
  const out = assembleDocument({ run: RUN, sections: [TABLE], items });
  assert.ok(out.allowedLinks.includes("https://example.com"), "the string the item carries");
  assert.ok(out.allowedLinks.includes("https://example.com/"), "and the href its cell emits");
  assert.ok(out.allowedLinks.includes("https://example.com/%C3%BCber"),
    "a nested field's non-ASCII path is recorded in the form the cell emits");
  assert.ok(out.allowedLinks.includes("https://example.com/b"),
    "the sentence's closing bracket and full stop are not part of the URL");
  assert.equal(cellMarkdown("https://example.com"),
    "[https://example.com](<https://example.com/>)");
  assert.ok(out.allowedLinks.includes(linkDestination("https://example.com")),
    "the emitted destination is in the set, so a model quoting it keeps its link");
});

/* ------------------------------------------------------------------- the link destinations */

test("a cell link's destination is the normalised href of a clean value", () => {
  assert.equal(cellMarkdown("http://example.com/a"),
    "[http://example.com/a](<http://example.com/a>)");
  assert.equal(cellMarkdown("https://example.com"),
    "[https://example.com](<https://example.com/>)", "the destination is `new URL(value).href`");
  assert.equal(linkDestination("https://example.com/a?x=1&y=2"), "https://example.com/a?x=1&y=2");
  // The link text is the value as written, escaped.
  assert.equal(cellMarkdown("https://example.com/a?x=1&y=2"),
    "[https://example.com/a?x=1&amp;y=2](<https://example.com/a?x=1&y=2>)");
});

test("a cell value's bare host or e-mail address does not autolink", () => {
  assert.equal(cellMarkdown("www.evil.example"), "www&#46;evil.example");
  assert.equal(cellMarkdown("x@evil.example"), "x&#64;evil.example");
  for (const value of ["www.evil.example", "x@evil.example"]) {
    const links = md.lexer(cellMarkdown(value))
      .filter((token) => ["link", "image", "url", "autolink"].includes(token.type));
    assert.deepEqual(links, [], `${value} adds no link`);
  }
});

test("a value that cannot be a link destination is escaped plain text", () => {
  for (const bad of [
    "http://example.com/a b",
    "http://example.com/a|b",
    "http://example.com/a<b>",
    "http://example.com/a>b",
    "http://example.com/a\\b",
    "http://example.com/a\tb",
    "http://example.com/a\u0000b",
    " http://example.com/a",
    "http://example.com/a ",
  ]) {
    assert.equal(linkDestination(bad), "", JSON.stringify(bad));
    const out = cellMarkdown(bad);
    assert.ok(!out.includes("]("), `${JSON.stringify(bad)} becomes escaped text, never a destination`);
  }
  // A non-http scheme is refused before the URL parser is asked anything.
  for (const bad of ["javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "ftp://example.com/a"]) {
    assert.equal(linkDestination(bad), "");
    assert.ok(!cellMarkdown(bad).includes("]("));
  }
});

/* ------------------------------------------------------------------ the renderer accepts it */

test("document source is {markdown} and the renderer accepts it", async () => {
  const map = mapSection();
  const out = assembleDocument({
    report: { title: "Weekly listings" },
    run: RUN,
    sections: [TABLE, CHART, map, AI],
    items: ITEMS,
    botName: "Listings bot",
  });
  assert.equal(typeof out.source.markdown, "string");
  assert.ok(!Array.isArray(out.source), "the source is the renderer's document object, not a bare string");

  const rendered = await renderVersion("document",
    { ...out.source, title: "Weekly listings" },
    { markdownBlocks });
  assert.equal(rendered.files[0].path, "index.html");
  const html = rendered.files[0].body.toString("utf8");
  assert.match(html, /<table>/);
  assert.match(html, /<h2>AI commentary \(written by Listings bot, not part of the fixed report\)<\/h2>/,
    "the attribution is the renderer's h2 heading");
  assert.match(html, /Flat with a view/);
  assert.match(html, /AI commentary \(written by Listings bot, not part of the fixed report\)/);
  const paths = rendered.files.map((file) => file.path);
  assert.ok(paths.includes("map-m1.svg"), "the plot file is written with the version");
  assert.equal(rendered.files.find((file) => file.path === "map-m1.svg").contentType, "image/svg+xml");
});