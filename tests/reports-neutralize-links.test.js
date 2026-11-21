// neutralizeLinks: a URL survives only when the report's own items carry that exact string, and every
// link shape faces the same rule in the SAME lexer the artifact renderer reads the document with
// (marked, GFM, breaks). The assertions below also re-lex the answer, so "no clickable way to a foreign
// host" is checked against the renderer's grammar and not against this module's own idea of one.
import { test } from "node:test";
import assert from "node:assert/strict";

const { breakUrlText, neutralizeLinks } = await import("../servers/gateway/reports/email/neutralize-links.js");
const { aiHeading, assembleDocument, escapeRecipeText } = await import("../servers/gateway/reports/document.js");
const { markdownBlocks } = await import("../servers/blog/renderer.js");
const { Marked } = await import("marked");

// The artifacts renderer's document options (servers/blog/renderer.js).
const md = new Marked({ gfm: true, breaks: true });

const KEPT = "https://example.com/a";
const FOREIGN = "https://example.net/x/y";
const ALLOWED = Object.freeze([KEPT]);

/** Every link, image, bare URL and raw HTML URL a stretch of markdown carries, per the renderer. */
function hrefs(markdown) {
  const found = [];
  const seen = new Set();
  const stack = [...md.lexer(markdown)];
  while (stack.length) {
    const token = stack.pop();
    if (token == null || typeof token !== "object" || seen.has(token)) continue;
    seen.add(token);
    if (["link", "image", "url", "autolink"].includes(token.type)
      && typeof token.href === "string") found.push(token.href);
    if (token.type === "html") {
      for (const match of String(token.raw || "").matchAll(/\b(?:href|src)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)) {
        found.push(String(match[1] ?? match[2] ?? match[3] ?? ""));
      }
    }
    for (const key of ["tokens", "items", "header"]) if (Array.isArray(token[key])) stack.push(...token[key]);
    if (Array.isArray(token.rows)) for (const row of token.rows) stack.push(...row);
  }
  return found;
}

/** The answer carries no link, image, bare URL or HTML URL outside `allowed`. */
function assertOnlyAllowed(markdown, allowed = ALLOWED) {
  for (const href of hrefs(markdown)) {
    assert.ok(allowed.includes(href), `unexpected href ${JSON.stringify(href)} in ${JSON.stringify(markdown)}`);
  }
}

/** The code blocks the renderer would draw as a chart or diagram. */
function specCodeBlocks(markdown) {
  return markdownBlocks(markdown).filter((block) => block.type === "code"
    && ["vega-lite", "mermaid", "d2"].includes(block.lang));
}

/** Every heading token a stretch of markdown carries, at any depth (blockquote, list, table cell). */
function headings(markdown) {
  const found = [];
  const seen = new Set();
  const stack = [...md.lexer(markdown)];
  while (stack.length) {
    const token = stack.pop();
    if (token == null || typeof token !== "object" || seen.has(token)) continue;
    seen.add(token);
    if (token.type === "heading") found.push(token);
    for (const key of ["tokens", "items", "header"]) if (Array.isArray(token[key])) stack.push(...token[key]);
    if (Array.isArray(token.rows)) for (const row of token.rows) stack.push(...row);
  }
  return found;
}

/** The option the untrusted paths pass: headings become bold text in the same pass. */
const UNTRUSTED = Object.freeze({ demoteHeadings: true });

test("an allowed markdown link and an allowed bare URL are kept", () => {
  const text = `See [the listing](${KEPT}) or ${KEPT}.`;
  assert.equal(neutralizeLinks(text, ALLOWED), text);
});

test("markdown with no link in it is returned exactly as written", () => {
  const text = [
    "## What changed",
    "",
    "| title | price |",
    "| --- | --- |",
    "| Flat with a view | 900 |",
    "",
    "- one",
    "- two",
    "",
    "```",
    "GET https://example.net/x",
    "```",
    "",
  ].join("\n");
  assert.equal(neutralizeLinks(text, ALLOWED), text);
});

test("a link the items do not carry becomes plain text naming its host", () => {
  assert.equal(neutralizeLinks(`See [the listing](${FOREIGN}).`, ALLOWED),
    "See [link removed: example.net].");
  assert.equal(neutralizeLinks(`Go to ${FOREIGN} now`, ALLOWED), "Go to [link removed: example.net] now");
  // Host only: the path, the query and the scheme are gone.
  assert.ok(!neutralizeLinks(`[x](${FOREIGN}?secret=1)`, ALLOWED).includes("secret"));
});

test("a Set works as well as an array", () => {
  assert.equal(neutralizeLinks(KEPT, new Set([KEPT])), KEPT);
  assert.equal(neutralizeLinks(FOREIGN, new Set([KEPT])), "[link removed: example.net]");
});

test("reference links resolve against the document's own definitions, which are dropped", () => {
  const kept = `[the listing][a]\n\n[a]: ${KEPT}`;
  assert.equal(neutralizeLinks(kept, ALLOWED).trim(), `[the listing](${KEPT})`);

  const foreign = `[the listing][a]\n\n[a]: ${FOREIGN}`;
  const out = neutralizeLinks(foreign, ALLOWED);
  assert.equal(out.trim(), "[link removed: example.net]");
  assert.ok(!out.includes("example.net/x"), "the definition line does not survive as text");
  assertOnlyAllowed(out);

  // The shortcut form and the collapsed form resolve the same way.
  assert.equal(neutralizeLinks(`[a]\n\n[a]: ${FOREIGN}`, ALLOWED).trim(), "[link removed: example.net]");
  assert.equal(neutralizeLinks(`[a][]\n\n[a]: ${FOREIGN}`, ALLOWED).trim(), "[link removed: example.net]");
  // An unknown label is left alone: it is not a link, so it carries no URL.
  assert.equal(neutralizeLinks("[a][gone]", ALLOWED), "[a][gone]");
  // A definition on its own leaves nothing behind, so nothing written in another section can resolve
  // against it once the document is joined.
  assert.equal(neutralizeLinks(`[a]: ${FOREIGN}`, ALLOWED), "");
  assert.equal(neutralizeLinks(`[a]: ${FOREIGN}\n`, ALLOWED), "");
});

test("autolinks face the same rule", () => {
  assert.equal(neutralizeLinks(`<${KEPT}>`, ALLOWED), KEPT);
  assert.equal(neutralizeLinks(`<${FOREIGN}>`, ALLOWED), "[link removed: example.net]");
});

test("raw html becomes inert text, and every href and src in it is judged", () => {
  const anchor = neutralizeLinks(`<a href="${KEPT}">the listing</a>`, ALLOWED);
  assert.ok(!anchor.includes("<a"), "a raw anchor is never emitted as markup");
  assert.ok(anchor.startsWith("&lt;a href="), "the whole tag is text");
  assert.deepEqual(hrefs(anchor), [], "and nothing in it is a clickable URL");

  const foreign = neutralizeLinks(`<a href="${FOREIGN}" target="_blank">the listing</a>`, ALLOWED);
  assert.ok(!foreign.includes("<a"), "no live anchor");
  assert.ok(!foreign.includes("example.net/x"), "the untrusted path is gone");
  assert.match(foreign, /\[link removed: example\.net\]/);

  const image = neutralizeLinks(`<img src="${FOREIGN}" alt="a chart">`, ALLOWED);
  assert.ok(!image.includes("<img"), "no live image element");
  assert.ok(!image.includes("example.net/x"));
  assert.match(image, /\[link removed: example\.net\]/);

  // A named anchor carries no URL, so its text stays, and the tag is still inert.
  const named = neutralizeLinks('<a name="top">Top</a>', ALLOWED);
  assert.ok(named.includes("Top"));
  assert.ok(!named.includes("<a"));
  assertOnlyAllowed(named);
});

test("an image is dropped from untrusted text, allowed or not", () => {
  // Finding 8: an image in text nobody approved is a request the reader's browser would make to a host
  // the recipe never named, so there is no allowed-image set here: the image goes.
  assert.equal(neutralizeLinks(`![a chart](${FOREIGN})`, ALLOWED), "");
  assert.equal(neutralizeLinks(`![a chart](${KEPT})`, ALLOWED), "");
  const body = neutralizeLinks(`Before. ![a chart](${KEPT}) After.`, ALLOWED);
  assert.equal(body, "Before.  After.", "the words around it are untouched");
  assert.deepEqual(hrefs(body), []);
});

test("a spec fence in untrusted text is demoted to code, whatever its engine", () => {
  const text = [
    "```vega-lite",
    '{"mark":"bar","data":{"values":[]}}',
    "```",
    "",
    "```mermaid",
    "graph LR; a-->b",
    "```",
    "",
    "```d2",
    "a -> b",
    "```",
  ].join("\n");
  const out = neutralizeLinks(text, ALLOWED);
  const codes = md.lexer(out).filter((token) => token.type === "code");
  assert.deepEqual(codes.map((token) => token.lang), ["text", "text", "text"],
    "the fences keep their place and stop being pictures");
  assert.ok(out.includes('{"mark":"bar","data":{"values":[]}}'), "the body is still shown, as code");
  assert.ok(!out.includes("```vega-lite"));
  // A language that is not a spec engine keeps its own info string.
  const plain = ["```json", "{}", "```"].join("\n");
  assert.equal(neutralizeLinks(plain, ALLOWED), plain);
});

test("an indented spec fence is demoted in place, its body untouched", () => {
  for (const indent of [" ", "  ", "   "]) {
    const body = `[x](${KEPT})`;
    const text = [
      `${indent}\`\`\`vega-lite`,
      body,
      `${indent}\`\`\``,
    ].join("\n");
    const out = neutralizeLinks(text, ALLOWED);
    const codes = md.lexer(out).filter((token) => token.type === "code");
    assert.deepEqual(codes.map((token) => token.lang), ["text"], JSON.stringify(indent));
    assert.ok(!out.includes("vega-lite"), JSON.stringify(out));
    assert.ok(out.includes(body), "the walk demotes the fence in place rather than escaping the body");
  }
});

test("a body escaped whole has its spec fence demoted before it is escaped", () => {
  const text = `${"x".repeat(64 * 1024)}\n\n\`\`\`mermaid\ngraph TD\n\`\`\`\n`;
  const out = neutralizeLinks(text, ALLOWED, UNTRUSTED);
  const codes = md.lexer(out).filter((token) => token.type === "code");
  assert.deepEqual(codes.map((token) => token.lang), ["text"], "a fence in a body too long to walk is code");
  assert.ok(!out.includes("mermaid"), "the info string is gone");
});

test("a demoted heading cannot join a following --- back into a setext heading", () => {
  const link = `[the listing](${KEPT})`;
  const text = `# x\n---\n\nSee ${link}\n\n\`\`\`mermaid\ngraph TD\n\`\`\``;
  const out = neutralizeLinks(text, ALLOWED, UNTRUSTED);
  assert.deepEqual(headings(out), []);
  assert.ok(out.includes("graph TD"), "the fence body is still shown");
  assert.deepEqual(md.lexer(out).filter((token) => token.type === "code").map((token) => token.lang), ["text"]);
  assert.ok(out.includes(link), "the walk keeps the link, so the text was not escaped whole");
});

test("javascript: and data: are never kept as a link, even when the caller passes them in", () => {
  for (const url of ["javascript:alert(1)", "data:text/html;base64,PHNjcmlwdD4=", "mailto:alex@example.com"]) {
    assert.equal(neutralizeLinks(`[click](${url})`, [url]), "[link removed: link]", url);
    assert.equal(neutralizeLinks(`![alt](${url})`, [url]), "", `${url} as an image is dropped`);
  }
  // A bare `javascript:`/`data:` value is text, not a link shape. A bare e-mail address IS one to GFM.
  assert.equal(neutralizeLinks("javascript:alert(1)", []), "javascript:alert(1)");
  assert.equal(neutralizeLinks("data:text/html;base64,PHNjcmlwdD4=", []), "data:text/html;base64,PHNjcmlwdD4=");
  const email = neutralizeLinks("mailto:alex@example.com", ["mailto:alex@example.com"]);
  assert.equal(email, "mailto:[link removed: link]");
  assertOnlyAllowed(email, []);
  // A raw anchor's href faces the same rule, inside the inert text.
  const anchor = neutralizeLinks('<a href="javascript:alert(1)">click</a>', ["javascript:alert(1)"]);
  assert.match(anchor, /\[link removed: link\]/);
  assertOnlyAllowed(anchor, []);
});

test("a parenthesised URL keeps its own closing paren and loses the prose's", () => {
  const text = `[a](${KEPT}_(b)) and (see ${FOREIGN})`;
  const allowed = [...ALLOWED, `${KEPT}_(b)`];
  const out = neutralizeLinks(text, allowed);
  assert.ok(out.startsWith("[a]("), "the kept link is still a link");
  assert.equal(hrefs(out)[0], `${KEPT}_(b)`, "its destination is exactly the allowed URL");
  assert.match(out, /\[link removed: example\.net\]/);
  assertOnlyAllowed(out, allowed);
});

test("link text naming another host is rewritten to show the target's host", () => {
  assert.equal(neutralizeLinks(`[example.net](${KEPT})`, ALLOWED), `[example.com](${KEPT})`);
  assert.equal(neutralizeLinks(`[example.net/path](${KEPT})`, ALLOWED), `[example.com](${KEPT})`);
  // Text that names the right host, or no host at all, is left as written.
  assert.equal(neutralizeLinks(`[example.com](${KEPT})`, ALLOWED), `[example.com](${KEPT})`);
  assert.equal(neutralizeLinks(`[the listing](${KEPT})`, ALLOWED), `[the listing](${KEPT})`);
});

test("a refused link keeps nothing of the target but its host", () => {
  const out = neutralizeLinks(`[example.com](${FOREIGN})`, ALLOWED);
  assert.equal(out, "[link removed: example.net]", "the label's host claim goes with the link");
});

test("plain text is untouched", () => {
  const text = "Two flats, one with a balcony. Nothing else changed.";
  assert.equal(neutralizeLinks(text, ALLOWED), text);
  assert.equal(neutralizeLinks("", ALLOWED), "");
  assert.equal(neutralizeLinks(null, ALLOWED), "");
});

/* -------------------------------------------- a fence opener on the last line of the text */

test("a fence opener on the last line is a fence, though the text ends without a line break", () => {
  // In isolation `x\n```vega-lite` with no final break lexes as one paragraph, so nothing demotes or
  // closes it; joined to the section after it the same line opens a real fence.
  assert.equal(neutralizeLinks("x\n```vega-lite", ALLOWED, UNTRUSTED), "x\n```text\n```",
    "the info string is gone and the fence is closed");
  assert.equal(neutralizeLinks("x\n````", ALLOWED, UNTRUSTED), "x\n````\n````",
    "a plain four-backtick fence is closed with its own marker");
  assert.equal(neutralizeLinks("> q\n```", ALLOWED, UNTRUSTED), "> q\n```\n```",
    "a fence after a blockquote is closed too");
  // The answer gains no line break of its own: a text that ended without one still does.
  assert.equal(neutralizeLinks("x\n```text", ALLOWED, UNTRUSTED), "x\n```text\n```");
  assert.equal(neutralizeLinks("plain words", ALLOWED, UNTRUSTED), "plain words");
});

test("a last-line fence in a custom section cannot swallow the table or the attribution", () => {
  for (const tail of ["x\n```vega-lite", "x\n````", "> q\n```"]) {
    const body = neutralizeLinks(tail, ALLOWED, UNTRUSTED);
    const out = assembleDocument({
      run: { id: "rrn-0000000000000000", startedAt: 0 },
      sections: [
        { type: "table", blockId: "t1", markdown: "| title |\n| --- |\n| one |" },
        { type: "custom", blockId: "s1", markdown: body },
        { type: "ai_commentary", blockId: "ai1", markdown: "Two listings are new." },
      ],
      items: [{ title: "one" }],
      botName: "Listings bot",
    });
    const blocks = markdownBlocks(out.source.markdown);
    const label = JSON.stringify(tail);
    assert.ok(blocks.some((block) => block.type === "table"), `${label}: the table is still a table`);
    const heading = blocks.find((block) => block.type === "heading");
    assert.ok(heading && heading.text.includes("not part of the fixed report"),
      `${label}: the attribution is outside any fence`);
    assert.deepEqual(blocks.filter((block) => block.type === "code"
      && ["vega-lite", "mermaid", "d2"].includes(block.lang)), [], `${label}: no spec fence`);
  }
});

test("a fence a list item or a blockquote holds is not a top-level fence, so it gets no closer", () => {
  // The fence ends with its own container. A column-0 closer appended after it would itself be a NEW
  // top-level opener and would swallow the owner's table and the attribution written after the section.
  for (const tail of ["- item\n\n  ```\n  x", "1. a\n   ~~~~\n   b", "- a\n  ```vega-lite\n  {}"]) {
    const body = neutralizeLinks(tail, ALLOWED, UNTRUSTED);
    const out = assembleDocument({
      run: { id: "rrn-0000000000000000", startedAt: 0 },
      sections: [
        { type: "table", blockId: "t1", markdown: "| title |\n| --- |\n| one |" },
        { type: "custom", blockId: "s1", markdown: body },
        { type: "ai_commentary", blockId: "ai1", markdown: "Two listings are new." },
      ],
      items: [{ title: "one" }],
      botName: "Listings bot",
    });
    const blocks = markdownBlocks(out.source.markdown);
    const label = JSON.stringify(tail);
    assert.ok(blocks.some((block) => block.type === "table"), `${label}: the table is still a table`);
    const heading = blocks.find((block) => block.type === "heading");
    assert.ok(heading && heading.text.includes("not part of the fixed report"),
      `${label}: the attribution is still a heading`);
    assert.deepEqual(blocks.filter((block) => block.type === "code"), [],
      `${label}: the section left no top-level code block behind`);
  }
});

test("an owner's definition cannot arm a shortcut reference in untrusted text", () => {
  // A `[docs]: url` line an owner's block wrote stays in the document. A model's `[docs]` is a shortcut
  // reference the renderer would resolve against it once the two sections are joined, so the brackets in
  // text nobody approved are written escaped and the words stay words.
  const body = neutralizeLinks("See [docs]", ALLOWED, UNTRUSTED);
  const out = assembleDocument({
    run: { id: "rrn-0000000000000000", startedAt: 0 },
    sections: [
      { type: "text", authoredBy: "owner", blockId: "o1", markdown: "[docs]: https://owner.example/d" },
      { type: "custom", blockId: "s1", markdown: body },
    ],
    items: [{ title: "one" }],
  });
  const markdown = out.source.markdown;
  assert.deepEqual(hrefs(markdown), [], "the [docs] in the section nobody approved is not a link token");
  assert.ok(markdown.includes("See \\[docs\\]"), "the words are still there, as text");
});

test("breakUrlText keeps the case of the prefix it breaks", () => {
  assert.equal(breakUrlText("WWW.Evil.Example"), "WWW&#46;Evil.Example");
  assert.equal(breakUrlText("www.evil.example"), "www&#46;evil.example");
});

test("a recipe string's e-mail address is text, not an autolink", () => {
  const out = escapeRecipeText("Pay x@evil.example");
  assert.equal(out, "Pay x&#64;evil.example");
  assert.deepEqual(md.lexer(out).filter((token) => ["link", "image", "url", "autolink"].includes(token.type)), []);
  // The bot's display name reaches the AI heading through the same helper.
  const heading = aiHeading("crow@evil.example");
  assert.deepEqual(md.lexer(heading).filter((token) => ["link", "url", "autolink"].includes(token.type)), []);
});

/* ------------------------------------------------------------------ adversarial shapes */

test("a bare www host is judged like any other link, and none of it survives", () => {
  const out = neutralizeLinks("Look at www.evil.example for more.", ALLOWED);
  assert.match(out, /\[link removed: www\\?\.evil\\?\.example\]/, "the marker names the host it offered");
  assert.deepEqual(hrefs(out), [], "and nothing in the answer is a link any more");

  const bare = neutralizeLinks("Go to www.evil.example now", ALLOWED);
  assert.match(bare, /\[link removed: www\\?\.evil\\?\.example\]/);
  assertOnlyAllowed(bare);
});

test("an uppercase scheme is judged the way the renderer reads it", () => {
  for (const text of ["HTTP://EVIL.EXAMPLE/x", "Https://evil.example/x", "visit HTTP://evil.example/a/b now"]) {
    const out = neutralizeLinks(text, ALLOWED);
    // Whatever the renderer's case rule is, the answer agrees with it: a link it reads is removed,
    // and text it does not read as a link is text.
    assertOnlyAllowed(out);
    assert.ok(out === text || out.includes("[link removed:"), text);
  }
});

test("a reference definition cannot smuggle a URL past the rule", () => {
  const out = neutralizeLinks("[x][r]\n\n[r]: http://evil.example/x", ALLOWED);
  assert.equal(out.trim(), "[link removed: evil.example]");
  assertOnlyAllowed(out);
});

test("a nested image is dropped and the link it sat in is judged on its own", () => {
  const out = neutralizeLinks("[![a](http://evil.example/i.png)](http://ok.example)", ["http://ok.example"]);
  assert.ok(!out.includes("evil.example/i.png"), "the image is gone");
  assert.ok(!out.includes("evil.example"), "and so is its host");
  assertOnlyAllowed(out, ["http://ok.example"]);
});

test("an entity-encoded scheme is not a link this module or the renderer keeps", () => {
  for (const text of [
    "[x](&#106;avascript:alert(1))",
    "[x](&amp;#106;avascript:alert(1))",
    "[x](java&#115;cript:alert(1))",
    "<a href=\"&#106;avascript:alert(1)\">x</a>",
  ]) {
    const out = neutralizeLinks(text, []);
    assert.ok(!out.includes("](&#106;avascript"), text);
    assertOnlyAllowed(out, []);
  }
});

test("an escaped bracket is text, not the start of a link, and the URL inside it is still judged", () => {
  const out = neutralizeLinks("\\[x](http://evil.example/x)", ALLOWED);
  assert.ok(out.startsWith("\\[x]("), "the escape keeps the bracket literal");
  assert.match(out, /\[link removed: evil\.example\]/);
  assertOnlyAllowed(out);
});

test("the answer stays markdown: a kept link inside a table and a heading is still a link", () => {
  const text = "## See [the listing](https://example.com/a)\n\n| a | b |\n| --- | --- |\n| [x](https://example.com/a) | y |\n";
  const out = neutralizeLinks(text, ALLOWED);
  assert.deepEqual(hrefs(out), [KEPT, KEPT], "both kept links are still links in the table and the heading");
  assert.match(out, /^## See /, "the heading marker is still there");
  assert.match(out, /\| --- \| --- \|/, "the table delimiter row is still there");
});

test("a body too long to lex is escaped whole rather than passed through", () => {
  const long = `${"x".repeat(64 * 1024)} [x](http://evil.example/x)`;
  const out = neutralizeLinks(long, ALLOWED);
  assert.ok(!out.includes("[x](http://evil.example/x)"));
  assertOnlyAllowed(out);
});

/* -------------------------------------------------------- the info string of a code fence */

/**
 * The fence opener lines a spec engine can hide in: the info string is where the renderer reads the
 * language, so every spelling marked accepts has to reach the same answer here.
 */
const SPEC_OPENERS = Object.freeze([
  "``` vega-lite",
  "```vega\\-lite",
  "```\u3000mermaid",
  "```d2 ",
  "~~~ vega-lite",
  "```\tvega-lite",
]);

test("a spec fence info string is read the way the renderer reads it", () => {
  for (const opener of SPEC_OPENERS) {
    const marker = opener.slice(0, 3);
    const fence = `${opener}\n{}\n${marker}`;
    const walked = neutralizeLinks(fence, ALLOWED);
    assert.deepEqual(specCodeBlocks(walked), [], `${JSON.stringify(opener)}: walked to code`);
    assert.ok(!/vega-lite|mermaid|d2/.test(walked), `${JSON.stringify(opener)}: the engine word is gone`);

    // The same opener in a body too long to lex, which takes the escaped-whole path.
    const escaped = neutralizeLinks(`${"x".repeat(64 * 1024)}\n\n${fence}`, ALLOWED);
    assert.deepEqual(specCodeBlocks(escaped), [], `${JSON.stringify(opener)}: escaped to code`);
    assert.ok(!/vega-lite|mermaid|d2/.test(escaped), `${JSON.stringify(opener)}: the engine word is gone`);
  }
});

test("an over-length body is closed and backstopped like the walked one", () => {
  const text = `${"x".repeat(64 * 1024)}\n\nSee [x](${FOREIGN})\n\n\`\`\`mermaid\ngraph TD`;
  const out = neutralizeLinks(text, ALLOWED, UNTRUSTED);
  assert.ok(out.length > 0, "the escaped body survives the backstop");
  assertOnlyAllowed(out);
  assert.ok(!out.includes("mermaid"), "the info string is gone");
  assert.deepEqual(specCodeBlocks(out), []);
  const blocks = markdownBlocks(`${out}\n\n| title |\n| --- |\n| one |`);
  assert.ok(blocks.some((block) => block.type === "table"), "the unterminated fence is closed at the end");
});

/* ------------------------------------------------- headings in text nobody approved */

test("every heading shape becomes bold text when the text is untrusted", () => {
  const cases = [
    ["# x", "**x**"],
    ["## x", "**x**"],
    ["Title\n=====", "**Title**"],
    ["Title\n-----", "**Title**"],
    ["> # x", "> **x**"],
    ["- # x", "- **x**"],
    ["1. ## x", "1. **x**"],
  ];
  for (const [text, expected] of cases) {
    const out = neutralizeLinks(text, ALLOWED, UNTRUSTED);
    assert.deepEqual(headings(out), [], `no heading survives ${JSON.stringify(text)}`);
    assert.ok(out.includes(expected), `${JSON.stringify(text)} gave ${JSON.stringify(out)}`);
  }
});

test("a setext heading does not swallow the text that follows it", () => {
  assert.equal(neutralizeLinks("Title\n=====\n\nbody text\n", ALLOWED, UNTRUSTED),
    "**Title**\n\nbody text\n");
  assert.equal(neutralizeLinks("Title\n-----\n\nbody text\n", ALLOWED, UNTRUSTED),
    "**Title**\n\nbody text\n");
});

test("a heading nested in a list, a blockquote or a table cell is text too", () => {
  const text = [
    "> # quoted",
    "",
    "- # listed",
    "",
    "1. ## numbered",
    "",
    "| # cell | b |",
    "| --- | --- |",
    "| a | b |",
    "",
  ].join("\n");
  const out = neutralizeLinks(text, ALLOWED, UNTRUSTED);
  assert.deepEqual(headings(out), [], "no heading survives at any depth");
  assert.match(out, /> \*\*quoted\*\*/);
  assert.match(out, /- \*\*listed\*\*/);
  assert.match(out, /1\. \*\*numbered\*\*/);
  assert.match(out, /\| --- \| --- \|/, "the table delimiter row is still a table");
  assert.ok(md.lexer(out).some((token) => token.type === "table"), "the table keeps its shape");
});

test("a link inside a demoted heading is still judged", () => {
  const out = neutralizeLinks(`## See [x](${FOREIGN})`, ALLOWED, UNTRUSTED);
  assert.deepEqual(headings(out), []);
  assert.equal(out.trim(), "**See [link removed: example.net]**");
  assertOnlyAllowed(out);
});

test("a heading is left as written when the caller does not ask for demotion", () => {
  for (const text of ["# x", "Title\n=====", "> # x"]) {
    assert.equal(neutralizeLinks(text, ALLOWED), text);
  }
});

test("a # comment inside a fence is code, and stays code", () => {
  const text = ["```", "# not a heading", "```"].join("\n");
  const out = neutralizeLinks(text, ALLOWED, UNTRUSTED);
  assert.equal(out, text);
  assert.deepEqual(headings(out), []);
});

test("a body too long to lex carries no heading marker once it is escaped", () => {
  const long = `${"x".repeat(64 * 1024)}\n\n## not a heading\n\nTitle\n=====\n`;
  const out = neutralizeLinks(long, ALLOWED, UNTRUSTED);
  assert.deepEqual(headings(out), []);
  assert.ok(out.includes("#"), "the words are still readable");
});