import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { filterLinks, parseUrlFilter, urlContainsFilter, MAX_PATTERN_LEN, MAX_TEST_LEN, MAX_URL_FILTER_LEN } from "../bundles/browser/server/safe-filter.js";

const LEAK = "filter pattern took too long; use a simpler pattern";
const TOO_LONG = "filter pattern is too long (max 200 characters); use a shorter pattern";
const INVALID = "filter pattern is not a valid regular expression; fix or simplify it";
const PLAIN = "filter_url_pattern is plain text now, not a regex: give part of the URL, or several parts separated by |";
const URL_TOO_LONG = "filter_url_pattern is too long (max 500 characters); give a shorter list of parts";

/**
 * The floor is the release that ships the current server files, not that release exactly:
 * parse the dotted version numerically (so 1.10.0 > 1.9.0) and fail only when `actual` is
 * older than `minimum`.
 */
function assertAtLeast(actual, minimum, what) {
  const parse = (v) => String(v).split(".").map((p) => Number.parseInt(p, 10) || 0);
  const a = parse(actual), m = parse(minimum);
  for (let i = 0; i < Math.max(a.length, m.length); i++) {
    const x = a[i] ?? 0, y = m[i] ?? 0;
    if (x !== y) return assert.ok(x > y, `${what}: ${actual} is older than ${minimum}`);
  }
  assert.ok(true, `${what}: ${actual} is at least ${minimum}`);
}

const FIXTURE = [
  { text: "Documentation home", href: "https://docs.example.com/", title: "Docs" },
  { text: "API reference", href: "https://api.example.com/v1", title: null },
  { text: "Blog", href: "https://example.com/blog/post-42", title: "" },
  { text: "guide to widgets", href: "https://example.com/g/1", title: "Widgets" },
  { text: "status page", href: "https://status.example.com/HIDDEN-room", title: null },
  { text: "42 answers", href: "https://example.com/answers", title: "Numbers" },
  { text: "a", href: "https://example.com/a", title: "Letter" },
  { text: "Contact", href: "https://contact.example.com/", title: null },
];

/** The exact code the handler used before: kept here as the parity reference. */
function oldFilter(links, filter) {
  const re = new RegExp(filter, "i");
  return links.filter((l) => re.test(l.text) || re.test(l.href));
}

test("catastrophic pattern is cut off by the timeout and the module stays usable", async () => {
  const links = Array.from({ length: 4 }, (_, i) => ({
    text: "a".repeat(1900) + "!",
    href: `https://example.com/${i}`,
    title: null,
  }));

  let ticks = 0;
  const timer = setInterval(() => { ticks += 1; }, 20);

  const started = Date.now();
  const r = filterLinks(links, "(a+)+$");
  const elapsed = Date.now() - started;
  const ticksAfterCall = ticks;

  await new Promise((resolve) => setTimeout(resolve, 150));
  clearInterval(timer);

  assert.deepEqual(r, { ok: false, error: LEAK });
  assert.ok(elapsed < 1500, `expected the call to return quickly, took ${elapsed}ms`);
  // The interval was blocked while the match ran; it must still fire afterwards.
  assert.ok(ticks > ticksAfterCall, "the event loop never ticked after the call returned");

  const again = filterLinks(FIXTURE, "blog");
  assert.equal(again.ok, true);
  assert.deepEqual(again.links, [FIXTURE[2]]);
});

test("pattern length is capped at MAX_PATTERN_LEN", () => {
  assert.equal(MAX_PATTERN_LEN, 200);

  const tooLong = "a".repeat(MAX_PATTERN_LEN + 1);
  assert.deepEqual(filterLinks(FIXTURE, tooLong), { ok: false, error: TOO_LONG });

  const atLimit = filterLinks(FIXTURE, "a".repeat(MAX_PATTERN_LEN));
  assert.equal(atLimit.ok, true);
  assert.deepEqual(atLimit.links, []);
});

test("an invalid pattern is refused without echoing the engine message", () => {
  const r = filterLinks(FIXTURE, "(");
  assert.deepEqual(r, { ok: false, error: INVALID });
});

test("each tested string is truncated before matching", () => {
  const links = [
    { text: "x".repeat(5000) + "needle", href: "https://example.com/long", title: null },
    { text: "x".repeat(100) + "needle", href: "https://example.com/short", title: null },
  ];

  const r = filterLinks(links, "needle");
  assert.equal(r.ok, true);
  assert.deepEqual(r.links, [links[1]]);
  assert.equal(r.links[0], links[1], "the original link object is returned");

  // Matched only when the needle sits inside the truncated window.
  const inside = filterLinks([{ text: "y".repeat(MAX_TEST_LEN - 6) + "needle", href: "" }], "needle");
  assert.equal(inside.ok, true);
  assert.equal(inside.links.length, 1);
});

test("filterLinks matches the old RegExp filter on ordinary patterns", () => {
  const patterns = [
    "docs",
    "DOCS",
    "^https",
    "api|blog",
    "[0-9]+",
    "hidden",
    "guide",
    "widget",
    "zzz",
    "a",
  ];

  for (const pattern of patterns) {
    const r = filterLinks(FIXTURE, pattern);
    assert.equal(r.ok, true, `pattern ${pattern} should be accepted`);
    assert.deepEqual(r.links, oldFilter(FIXTURE, pattern), `pattern ${pattern} diverged`);
  }

  // Order and fields survive, and the objects are the originals.
  const all = filterLinks(FIXTURE, "^https");
  assert.equal(all.links.length, FIXTURE.length);
  all.links.forEach((link, i) => {
    assert.equal(link, FIXTURE[i]);
    assert.deepEqual(Object.keys(link), ["text", "href", "title"]);
  });

  assert.deepEqual(filterLinks(FIXTURE, "HIDDEN").links, [FIXTURE[4]], "href-only match");
  assert.deepEqual(filterLinks(FIXTURE, "guide").links, [FIXTURE[3]], "text-only match");
  assert.deepEqual(filterLinks(FIXTURE, "zzz").links, [], "no match");
});

/**
 * A server file reaches an installed copy only through a manifest version change: the
 * Extensions page copies the bundle to ~/.crow/bundles/<id>/ and repairInstalledBundleAssets
 * refreshes that copy only when the repo manifest version differs from the installed one.
 * The registry is generated from the manifest, so the two must agree.
 */
test("the manifest version is bumped past the release that shipped the new server file", () => {
  const manifest = JSON.parse(
    readFileSync(fileURLToPath(new URL("../bundles/browser/manifest.json", import.meta.url)), "utf8"),
  );
  assert.equal(manifest.id, "browser");
  assertAtLeast(manifest.version, "1.8.5", "bundles/browser/manifest.json version");

  const registry = JSON.parse(
    readFileSync(fileURLToPath(new URL("../registry/add-ons.json", import.meta.url)), "utf8"),
  );
  const entries = registry["add-ons"] || registry.addons || registry;
  const entry = entries.find((a) => a.id === "browser");
  assert.ok(entry, "the registry lists the browser");
  assert.equal(
    entry.version,
    manifest.version,
    "the registry is generated: rerun `npm run build-registry` after bumping the manifest",
  );
});

test("the handler routes its filter through safe-filter.js", () => {
  const source = readFileSync(
    fileURLToPath(new URL("../bundles/browser/server/server.js", import.meta.url)),
    "utf8",
  );

  assert.match(
    source,
    /import\s*\{[^}]*\bfilterLinks\b[^}]*\}\s*from\s*"\.\/safe-filter\.js";/,
    "filterLinks must still come from safe-filter.js",
  );
  assert.ok(!source.includes("new RegExp(filter,"), "the handler must not build the regex itself");
});

test("parsed alternatives match any part of the URL", () => {
  const parsed = parseUrlFilter("fastcdn|submissions|instapage");
  assert.deepEqual(parsed, { ok: true, parts: ["fastcdn", "submissions", "instapage"] });

  for (const part of parsed.parts) {
    const url = `https://api.example.com/x/${part}/y`;
    assert.equal(urlContainsFilter(url, parsed.parts), true, `${part} should match ${url}`);
  }
  assert.equal(urlContainsFilter("https://example.com/unrelated", parsed.parts), false);
});

test("a literal dot stays literal", () => {
  const { ok, parts } = parseUrlFilter("a.b");
  assert.equal(ok, true);
  assert.deepEqual(parts, ["a.b"]);

  assert.equal(urlContainsFilter("https://x/axb", parts), false);
  assert.equal(urlContainsFilter("https://x/a.b", parts), true);
});

test("regex syntax is refused with the plain-text error", () => {
  const refused = ["a\\b", "a.*b", "a.+b", "[a]", "(a)", "a{2}", "^https", "x$"];
  for (const value of refused) {
    assert.deepEqual(parseUrlFilter(value), { ok: false, error: PLAIN }, `${JSON.stringify(value)} should be refused`);
  }
});

test("an anchor on any alternative is refused with the plain-text error", () => {
  for (const value of ["x$|y", "a|^b", "^a|b", "a|b$", "a|^b|^c$"]) {
    assert.deepEqual(parseUrlFilter(value), { ok: false, error: PLAIN }, `${JSON.stringify(value)} should be refused`);
  }
});

test("an anchor in the middle of an alternative stays literal", () => {
  assert.deepEqual(parseUrlFilter("a$b"), { ok: true, parts: ["a$b"] });
  assert.deepEqual(parseUrlFilter("a^b"), { ok: true, parts: ["a^b"] });
  assert.deepEqual(parseUrlFilter("a$b|a^b"), { ok: true, parts: ["a$b", "a^b"] });

  const parts = parseUrlFilter("a$b").parts;
  assert.equal(urlContainsFilter("https://x/a$b", parts), true);
  assert.equal(urlContainsFilter("https://x/ab", parts), false);
});

test("the parsed filter is capped at MAX_URL_FILTER_LEN", () => {
  assert.equal(MAX_URL_FILTER_LEN, 500);

  const atLimit = parseUrlFilter("a".repeat(MAX_URL_FILTER_LEN));
  assert.deepEqual(atLimit, { ok: true, parts: ["a".repeat(MAX_URL_FILTER_LEN)] });

  assert.deepEqual(parseUrlFilter("a".repeat(MAX_URL_FILTER_LEN + 1)), { ok: false, error: URL_TOO_LONG });
});

test("a former ReDoS pattern is refused instantly", () => {
  const started = Date.now();
  const parsed = parseUrlFilter("(a+)+$");
  const elapsed = Date.now() - started;
  assert.deepEqual(parsed, { ok: false, error: PLAIN });
  assert.ok(elapsed < 50, `expected the refusal under 50ms, took ${elapsed}ms`);
});

test("a filter with no non-empty alternative is refused", () => {
  assert.deepEqual(parseUrlFilter("|"), { ok: false, error: PLAIN });
  assert.deepEqual(parseUrlFilter("||"), { ok: false, error: PLAIN });
});

test("ordinary URL punctuation is not refused", () => {
  for (const value of ["api.example.com/v1?x=1&y=2", "a+b", "a*b"]) {
    assert.equal(parseUrlFilter(value).ok, true, `${JSON.stringify(value)} should be accepted`);
  }

  const query = parseUrlFilter("api.example.com/v1?x=1&y=2");
  assert.deepEqual(query, { ok: true, parts: ["api.example.com/v1?x=1&y=2"] });
  assert.equal(urlContainsFilter("https://api.example.com/v1?x=1&y=2", query.parts), true);
  assert.equal(urlContainsFilter("https://x/a+b", parseUrlFilter("a+b").parts), true);
  assert.equal(urlContainsFilter("https://x/a*b", parseUrlFilter("a*b").parts), true);
});

test("empty alternatives are dropped", () => {
  assert.deepEqual(parseUrlFilter("a||b"), { ok: true, parts: ["a", "b"] });
});

test("an empty or absent filter captures everything", () => {
  for (const value of ["", undefined, null]) {
    const parsed = parseUrlFilter(value);
    assert.deepEqual(parsed, { ok: true, parts: [] });
    assert.equal(urlContainsFilter("https://example.com/anything", parsed.parts), true);
  }
  assert.equal(urlContainsFilter("https://example.com/anything", undefined), true);
  assert.equal(urlContainsFilter("https://example.com/anything", []), true);
});

test("the substring test is case-sensitive", () => {
  const parts = parseUrlFilter("Blog").parts;
  assert.equal(urlContainsFilter("https://example.com/blog", parts), false);
  assert.equal(urlContainsFilter("https://example.com/Blog", parts), true);
});

test("a plain needle against a long URL stays cheap", () => {
  const url = "https://e.example/" + "a".repeat(100000) + "!";
  const parts = parseUrlFilter("needle").parts;
  const started = Date.now();
  const hit = urlContainsFilter(url, parts);
  const elapsed = Date.now() - started;
  assert.equal(hit, false);
  assert.ok(elapsed < 50, `expected the substring test to return under 50ms, took ${elapsed}ms`);
});

test("the capture handler uses the substring helper, not a regex", () => {
  const source = readFileSync(
    fileURLToPath(new URL("../bundles/browser/server/server.js", import.meta.url)),
    "utf8",
  );

  assert.ok(!source.includes("new RegExp(filter_url_pattern"), "the capture filter must not become a regex");
  assert.ok(source.includes("urlContainsFilter(p.response.url"), "the capture filter must use the substring helper");
  assert.ok(
    source.includes("Text; only capture responses whose URL contains it (use | for several)"),
    "the zod describe must describe plain text alternatives",
  );
});