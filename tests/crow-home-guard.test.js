/**
 * Two guards on the Crow home, both from the 2026 raw-`node --test` incident:
 *
 *   A raw `node --test` run (NOT `npm test`, whose scripts/run-suite.mjs always
 *   sets a scratch CROW_HOME) of a test that set CROW_DATA_DIR but left
 *   CROW_HOME unset resolved its Crow home to the operator's real ~/.crow and
 *   wrote token files there. Fixing every such test is not realistic (hundreds
 *   set a DB path only), so:
 *
 *   1. servers/shared/crow-home.js REFUSES the implicit default under the Node
 *      test runner (NODE_TEST_CONTEXT, which `node --test` sets in each test
 *      file's own process) instead of answering ~/.crow. Production and any
 *      call with an explicit env object keep today's answer.
 *   2. No server file may assemble the Crow home from `homedir()` itself: the
 *      resolveCrowHome() call is the one place a second instance's CROW_HOME is
 *      honoured, so a hardcoded join(homedir(), ".crow") silently reads and
 *      writes the primary instance's files.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";
import { resolveCrowHome, resolveInstanceDataDir } from "../servers/shared/crow-home.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SERVERS = join(ROOT, "servers");

/**
 * The shapes a hardcoded Crow home takes. Each matches only when `homedir()`
 * and the ".crow" literal are in the SAME expression (only whitespace — even a
 * newline — may sit between the tokens, never another statement):
 *
 *   join(homedir(), ".crow")      resolve(homedir(), ".crow", "data")
 *   homedir() + "/.crow"          `${homedir()}/.crow`
 *
 * The literal must be exactly ".crow": `join(homedir(), ".crow-satellite")` is
 * a DIFFERENT instance's default home (servers/satellite), not this one's.
 */
const PATTERNS = [
  { name: 'join(homedir(), ".crow")', re: /\b(?:join|resolve)\(\s*homedir\(\)\s*,\s*["'`]\.crow["'`]/ },
  { name: 'homedir() + "/.crow"', re: /homedir\(\)\s*\+\s*["'`]\/?\.crow["'`]/ },
  { name: "`${homedir()}/.crow`", re: /\$\{\s*homedir\(\)\s*\}\/?\.crow/ },
];

/**
 * Files allowed to name ~/.crow by hand, one line of reason each. The resolver
 * IS the place the default is assembled; nothing else may do it.
 */
const ALLOW = [
  // The ONE resolver: `resolveCrowHome()` returning join(homedir(), ".crow") is
  // its job (behind assertCrowHomeResolvable), and coHostedDataDirWarning
  // compares an instance's data dir against the host-default one by name.
  { file: "servers/shared/crow-home.js", reason: "the resolver itself (assertCrowHomeResolvable / host-default comparison)" },
];

/** Every offence in one text, as `{ line, pattern, text }`. */
function findOffences(text) {
  const out = [];
  for (const { name, re } of PATTERNS) {
    const global = new RegExp(re.source, "g");
    for (const m of text.matchAll(global)) {
      const line = text.slice(0, m.index).split("\n").length;
      const source = text.split("\n")[line - 1].trim();
      out.push({ line, pattern: name, text: source });
    }
  }
  return out;
}

/** servers/**\/*.{js,mjs}, without node_modules. */
function serverFiles(dir = SERVERS) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules") continue;
      out.push(...serverFiles(p));
    } else if (e.isFile() && /\.(?:js|mjs)$/.test(e.name)) {
      out.push(p);
    }
  }
  return out;
}

test("the hardcoded-home patterns catch every shape they exist for", () => {
  // Non-vacuous: the scanner must recognise the code it forbids, including the
  // exact line that leaked into the operator's ~/.crow (a CROW_HOME || fallback)
  // and a call split across lines.
  const fixtures = [
    'const home = process.env.CROW_HOME || join(homedir(), ".crow");',
    'return join(homedir(), ".crow", "data");',
    'const crowHome = resolve(homedir(), ".crow");',
    "return homedir() + '/.crow';",
    "return `${homedir()}/.crow`;",
    'export const CROW_DIR = process.env.CROW_HOME || join(\n  homedir(),\n  ".crow",\n);',
  ];
  for (const f of fixtures) {
    assert.ok(findOffences(f).length > 0, `scanner did not catch: ${f}`);
  }
  const fixtureOffences = findOffences(fixtures.join("\n"));
  assert.ok(fixtureOffences.every((o) => o.line >= 1 && o.text.length > 0), "offences must carry a line and its source");

  // Negative controls: a sibling instance's default home and a plain HOME
  // lookup are NOT this instance's Crow home.
  assert.equal(findOffences('return join(homedir(), ".crow-satellite");').length, 0);
  assert.equal(findOffences("const home = ctx.home || homedir();").length, 0);
  assert.equal(findOffences('return join(homedir(), "backups", "crow");').length, 0);
});

test("no server file assembles the Crow home from homedir()", () => {
  const files = serverFiles();
  assert.ok(files.length > 50, `expected to scan the whole servers tree, saw ${files.length} files`);
  const allowed = new Set(ALLOW.map((a) => a.file));
  const offences = [];
  for (const file of files) {
    const rel = relative(ROOT, file).split(sep).join("/");
    if (allowed.has(rel)) continue;
    let text;
    try { text = readFileSync(file, "utf8"); } catch { continue; }
    for (const o of findOffences(text)) offences.push(`${rel}:${o.line}  ${o.pattern}  ${o.text}`);
  }
  assert.deepEqual(offences, [], `the Crow home must come from servers/shared/crow-home.js resolveCrowHome(), not homedir():\n${offences.join("\n")}`);
});

test("resolveCrowHome refuses the implicit ~/.crow under node --test", () => {
  // `node --test` runs each file in its own process with NODE_TEST_CONTEXT set
  // (the value selects the reporter serializer). This very file is that case.
  assert.ok(process.env.NODE_TEST_CONTEXT, "expected NODE_TEST_CONTEXT — this test must run under node --test");
  const saved = process.env.CROW_HOME;
  delete process.env.CROW_HOME;
  try {
    assert.throws(
      () => resolveCrowHome(),
      (err) => err.code === "CROW_HOME_REQUIRED_IN_TESTS" && /CROW_HOME is not set under node --test/.test(err.message),
      "an implicit ~/.crow is refused under the test runner",
    );
    // An EXPLICIT env object is how a test of the default resolution asks its
    // question: it keeps today's answer (no refusal).
    assert.equal(resolveCrowHome({}), join(homedir(), ".crow"));
    // The data-dir resolver follows the same rule: with CROW_HOME unset a raw
    // test would otherwise get a half-default instance (home ~/.crow, data tmp).
    assert.throws(
      () => resolveInstanceDataDir(),
      (err) => err.code === "CROW_HOME_REQUIRED_IN_TESTS",
      "resolveInstanceDataDir refuses too",
    );
    assert.equal(resolveInstanceDataDir({}), join(homedir(), ".crow", "data"));
  } finally {
    if (saved === undefined) delete process.env.CROW_HOME;
    else process.env.CROW_HOME = saved;
  }
});

test("resolveCrowHome returns CROW_HOME when it is set", () => {
  const saved = process.env.CROW_HOME;
  process.env.CROW_HOME = join(homedir(), ".crow-guard-test");
  try {
    assert.equal(resolveCrowHome(), join(homedir(), ".crow-guard-test"));
  } finally {
    if (saved === undefined) delete process.env.CROW_HOME;
    else process.env.CROW_HOME = saved;
  }
});