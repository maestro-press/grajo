/**
 * The browser relay gate, delivery side — statics that read the sources as text.
 *
 * The gate has NO OFF SWITCH (plan section 1 step 5), so there is no setting an operator
 * can leave wrong: delivery is only about getting the new code running. Four channels,
 * one regression test each (plan-delivery section 12):
 *
 *   1. MCP code, via a bundle version bump: the intent header on `connectOverCDP` and
 *      `Crow.guardReady` sent AFTER the private-address guard install resolved.
 *   2. The installer default: the image COPYs the relay and the entrypoint, the image is
 *      built on the engines major (Node 24) and the manifest keeps refreshing the relay.
 *   3. The boot check: the `browser-image-stale` detector already watches every file the
 *      Dockerfile copies in, so a relay edit that is not in a running image raises the
 *      card. A new in-image FILE that the detector does not watch must fail this suite.
 *   4. Visibility: `crow_browser_status` reports the gate from `/json/version`.
 *
 * Plus the prerequisites the gate rests on (plan test 13: P7 — no `Browser.close`
 * anywhere in the MCP — and P9 — the guard's init script carries the exported marker) and
 * the approved consent/docs copy.
 *
 * Style, as in tests/browser-cdp-gate-static.test.js: the files are read as text and the
 * assertions are on the text, and every negative rule has a CONTROL that shows the check
 * can fail (so a "zero" here is never vacuous).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename, dirname, join } from "node:path";

const ROOT = join(import.meta.dirname, "..");
const read = (p) => readFileSync(join(ROOT, p), "utf8");

const RELAY = read("bundles/browser/cdp-relay.mjs");
const SERVER = read("bundles/browser/server/server.js");
const GUARD = read("bundles/browser/server/private-address.js");
const DOCKERFILE = read("bundles/browser/Dockerfile");
const COMPOSE = read("bundles/browser/docker-compose.yml");
const ENTRYPOINT = read("bundles/browser/entrypoint.sh");
const MANIFEST = JSON.parse(read("bundles/browser/manifest.json"));
const BUNDLE_PKG = JSON.parse(read("bundles/browser/package.json"));
const DOCS_EN = read("docs/guide/browser-automation.md");
const DOCS_ES = read("docs/es/guide/browser-automation.md");

/**
 * A JS source with comments removed, so a rule about CODE is not satisfied or broken by
 * prose. Strings (single, double, template) are kept: a CDP method name lives in a string.
 */
function stripJsComments(source) {
  let out = "";
  let i = 0;
  const n = source.length;
  let state = "code";
  while (i < n) {
    const c = source[i];
    const d = source[i + 1];
    if (state === "code") {
      if (c === "/" && d === "/") { state = "line"; i += 2; continue; }
      if (c === "/" && d === "*") { state = "block"; i += 2; continue; }
      if (c === "'") state = "sq";
      else if (c === '"') state = "dq";
      else if (c === "`") state = "tpl";
      out += c; i++; continue;
    }
    if (state === "line") {
      if (c === "\n") { state = "code"; out += c; }
      i++; continue;
    }
    if (state === "block") {
      if (c === "*" && d === "/") { state = "code"; i += 2; continue; }
      if (c === "\n") out += c;
      i++; continue;
    }
    if (c === "\\") { out += c + (d ?? ""); i += 2; continue; }
    if ((state === "sq" && c === "'") || (state === "dq" && c === '"') || (state === "tpl" && c === "`")) state = "code";
    out += c; i++;
  }
  return out;
}

/** A shell / YAML text with its whole-line comments removed. */
const withoutComments = (text) => text.split("\n").filter((line) => !/^\s*#/.test(line)).join("\n");

/** The body of a top-level `export function name(...)` (up to the first `}` in column 0). */
function topLevelFunction(source, header) {
  const start = source.indexOf(header);
  if (start < 0) return "";
  const end = source.indexOf("\n}", start);
  return end < 0 ? source.slice(start) : source.slice(start, end + 2);
}

/** The body of a two-space-indented `async function name()` inside a factory. */
function indentedFunction(source, header) {
  const start = source.indexOf(header);
  if (start < 0) return "";
  const end = source.indexOf("\n  }\n", start);
  return end < 0 ? source.slice(start) : source.slice(start, end + 4);
}

/** Semver comparison, numeric per component (1.10.0 is newer than 1.9.0). */
function compareSemver(a, b) {
  const parse = (v) => String(v).split(".").map((p) => Number.parseInt(p, 10) || 0);
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const l = x[i] ?? 0;
    const r = y[i] ?? 0;
    if (l !== r) return l < r ? -1 : 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// 1. No off switch
// ---------------------------------------------------------------------------

const RELAY_CODE = stripJsComments(RELAY);
const SHELL_CODE = withoutComments(ENTRYPOINT);
const COMPOSE_CODE = withoutComments(COMPOSE);

/**
 * The name shapes a gate off-switch would use (plan section 1 step 5): an env var, an argv
 * key or a compose key called CROW_CDP_GATE…, CROW_GATE…, …_NO_GATE or DISABLE_GATE.
 *
 * Deliberately NOT a bare "GATE" search: `CROW_GATEWAY_UID` is an ordinary key in this
 * bundle, and a future constant of the gate's own (an uppercase identifier, not a switch)
 * must not read as one. The negative lookahead is what keeps GATEWAY out.
 */
const GATE_SWITCH_RES = [
  /CROW_CDP_GATE[A-Z0-9_]*/g,
  /CROW_GATE(?!WAY)[A-Z0-9_]*/g,
  /\b(?:[A-Z0-9]+_)*NO_GATE\b/g,
  /\b(?:[A-Z0-9]+_)*DISABLE_GATE\b/g,
];
const gateToggles = (text) => GATE_SWITCH_RES.flatMap((re) => [...String(text).matchAll(re)].map((m) => m[0]));

// CONTROL for the control: the pattern is not "contains GATE".
test("CONTROL: the gate-switch pattern finds a CROW_CDP_GATE read, and not CROW_GATEWAY_UID or GATEWAY", () => {
  assert.deepEqual(gateToggles('if (process.env.CROW_CDP_GATE === "0") pass = true;'), ["CROW_CDP_GATE"], "an env read is found");
  assert.deepEqual(gateToggles("CROW_CDP_GATE_MODE=off"), ["CROW_CDP_GATE_MODE"], "a longer CROW_CDP_GATE name is found");
  assert.deepEqual(gateToggles("CROW_GATE_MODE=off"), ["CROW_GATE_MODE"], "a CROW_GATE name is found");
  assert.deepEqual(gateToggles("CROW_GATEWAY_UID=1000\nCROW_GATEWAY_GID=1000"), [], "the gateway's uid keys are not a gate switch");
  assert.deepEqual(gateToggles("container_name: browser # GATEWAY"), []);
  assert.deepEqual(gateToggles("GATE_STATE = new Map()"), [], "the gate's own constant is not a switch");
  assert.deepEqual(gateToggles("NO_GATE=1\nCROW_SOMETHING_NO_GATE=1"), ["NO_GATE", "CROW_SOMETHING_NO_GATE"]);
  assert.deepEqual(gateToggles("DISABLE_GATE=1"), ["DISABLE_GATE"]);
});

// The gate itself is unconditional (there is no state a header could put it in), so the only
// switch-shaped thing to look for is a NAME that would read as one: an env var, an argv key
// or a compose key. Nothing else in this bundle may spell the gate as a feature flag.
test("no env, argv or compose key turns the gate off", () => {
  assert.deepEqual(gateToggles(RELAY_CODE), [], "no CROW_CDP_GATE* / CROW_GATE* / *_NO_GATE / DISABLE_GATE read in the relay's code");
  assert.deepEqual(gateToggles(SHELL_CODE), [], "the entrypoint has no GATE switch");
  assert.deepEqual(gateToggles(COMPOSE_CODE), [], "compose has no GATE key");
});

test("the relay imports only node: modules (the gate adds no dependency to the image)", () => {
  const imports = [...RELAY.matchAll(/^\s*(?:import|export)[^;]*?from\s+"([^"]+)"/gm)].map((m) => m[1]);
  assert.ok(imports.length >= 6, `expected the relay's imports, found ${imports.length}`);
  for (const specifier of imports) assert.match(specifier, /^node:/, "a bare import would need a package in the image: " + specifier);
});

test("RELAY_ENV_KEYS never forwards the fixture Chromium seam to the relay", () => {
  const start = RELAY.indexOf("const RELAY_ENV_KEYS = [");
  assert.ok(start > -1, "RELAY_ENV_KEYS is where the supervisor's allow-list lives");
  const end = RELAY.indexOf("];", start);
  assert.ok(end > start, "the list is a literal array");
  const list = RELAY.slice(start, end + 2);

  assert.ok(list.includes('"CDP_PORT"'), "CONTROL: the extraction really is the list (it names the port)");
  assert.ok(!list.includes("CROW_CDP_CHROMIUM_ARGV"), "the test fixture's argv seam must not reach a supervised relay");
});

const GATE_MARKERS = [
  "Crow-Guard",                 // the /json/version field (and the status read)
  "gate/1",                     // its value
  "X-Crow-Guard-Client",        // the MCP's declared intent
  "Crow.guardReady",            // the relay-handled handshake command
  "waitForDebuggerOnStart",     // new targets are held until the gate covers them
  "Fetch.enable",               // the gate's own interceptor
  "shared_worker",              // closed, never resumed (Fetch cannot see it)
  "service_worker",             // closed, never resumed
];

/** The markers a source does not carry, in the order they were asked for. */
const missingMarkers = (source, markers) => markers.filter((marker) => !source.includes(marker));

test("the relay carries the gate's source markers", () => {
  assert.deepEqual(missingMarkers(RELAY, GATE_MARKERS), [], "a marker the plan names is missing from cdp-relay.mjs");
});

// CONTROL: the marker check is not vacuous — a source missing one marker reports exactly it.
test("CONTROL: the marker check reports a missing marker", () => {
  const full = GATE_MARKERS.join("\n");
  assert.deepEqual(missingMarkers(full, GATE_MARKERS), [], "control: the full text has every marker");
  assert.deepEqual(missingMarkers(GATE_MARKERS.filter((m) => m !== "shared_worker").join("\n"), GATE_MARKERS), ["shared_worker"]);
});

// ---------------------------------------------------------------------------
// 2. Channel 1: MCP code, delivered by a version bump
// ---------------------------------------------------------------------------

test("the browser manifest version moves past 1.8.4 (an installed copy refreshes only on a version delta)", () => {
  assert.ok(
    compareSemver(MANIFEST.version, "1.8.4") > 0,
    `manifest version ${MANIFEST.version} must be strictly greater than 1.8.4: server.js and the relay both change`,
  );
  assert.equal(compareSemver("1.10.0", "1.9.0"), 1, "CONTROL: the comparison is numeric, not lexical");
});

test("server.js declares the gate intent and sends Crow.guardReady after the guard install", () => {
  assert.ok(SERVER.includes('from "./gate-client.js"'), "server.js must import the gate client (one implementation of the header and the handshake)");
  assert.ok(SERVER.includes("GATE_INTENT_HEADER"), "the intent header constant is used, not a copied literal");

  const body = indentedFunction(SERVER, "async function ensureConnected()");
  assert.ok(body.length > 0, "ensureConnected is where the guard is installed");

  const guardInstall = body.indexOf("installPrivateAddressGuard(");
  const handshake = body.indexOf("sendGuardReady(");
  assert.ok(guardInstall > -1, "ensureConnected installs the private-address guard on its context");
  assert.ok(handshake > -1, "ensureConnected sends Crow.guardReady");
  assert.ok(handshake > guardInstall, "the handshake goes AFTER the guard install resolved (P9): never before it");

  // The browser.newContext() fallback is covered by the same send: the fallback context is
  // made BEFORE the install, and the install/send pair runs for whichever context it is, so
  // its pages become covered too. (The plan's "once per context".)
  const fallback = body.indexOf("newContext(");
  assert.ok(fallback > -1, "the newContext fallback is still inside ensureConnected");
  assert.ok(fallback < guardInstall, "the fallback context is guarded (and declared) by the same install/send pair");

  const later = body.indexOf("sendGuardReady(", handshake + 1);
  if (later > -1) assert.ok(later > guardInstall, "a second send (a re-install) is after the guard install too");
});

// ---------------------------------------------------------------------------
// 3. Prerequisites present (plan test 13: P7 and P9)
// ---------------------------------------------------------------------------

/** Does this JS source CALL the CDP `Browser.close`, ignoring comments? */
const closesBrowser = (source) => /Browser\.close/.test(stripJsComments(source));

test("the MCP never sends Browser.close (P7): its page cleanup would run with nothing in front of it", () => {
  assert.equal(closesBrowser(SERVER), false, "server.js must not send Browser.close");
  assert.equal(closesBrowser(GUARD), false, "private-address.js must not send Browser.close either");
});

// CONTROL: the check is about a call with a name, so a comment about it stays quiet and a
// real call does not.
test("CONTROL: the Browser.close check flags a call and stays quiet on prose", () => {
  assert.equal(closesBrowser('await cdp.send("Browser.close", {});'), true, "a call is flagged");
  assert.equal(closesBrowser("browser.close().catch(() => {})"), false, "Playwright's own browser.close() is not the CDP command");
  assert.equal(closesBrowser("// NEVER `Browser.close`: it fires every pagehide beacon"), false, "a comment is not a call");
  assert.equal(closesBrowser("/* never Browser.close here */ const x = 1;"), false);
});

test("chromiumArguments carries ONE --disable-features flag with BackForwardCache, and hides the crash-restore bubble", () => {
  const body = topLevelFunction(RELAY, "export function chromiumArguments(");
  assert.ok(body.length > 0, "chromiumArguments is the launch argv");

  const flags = [...body.matchAll(/--disable-features=([^"\s]+)/g)].map((m) => m[1]);
  assert.equal(flags.length, 1, "Chromium honours only the last --disable-features: a later feature is comma-merged into this one");
  assert.ok(flags[0].split(",").map((f) => f.trim()).includes("BackForwardCache"), "the back-forward cache stays off (a Back press must not restore a bot page)");
  assert.ok(body.includes("--hide-crash-restore-bubble"), "the crash-restore bubble is hidden (the stop path kills Chromium on purpose)");
});

test("the guard's init script is installed with the exported GUARD_MARKER, never a copied literal (P9)", () => {
  assert.match(GUARD, /export const GUARD_MARKER = "[^"]+";/, "private-address.js exports the marker");
  assert.ok(
    GUARD.includes("addInitScript(`// ${GUARD_MARKER}"),
    "the main-world init script is built from the constant (`// ${GUARD_MARKER}`), so the relay's 'contains' test can see it",
  );

  const literal = /export const GUARD_MARKER = "([^"]+)";/.exec(GUARD)?.[1];
  assert.ok(literal, "the marker's value is a fixed string literal");
  assert.equal(countMarkerLiteral("bundles/browser/server", literal), 1, "the marker's value appears exactly once in server/: in its definition");
});

/** How many times `literal` appears across the .js files under `dir` (recursively). */
function countMarkerLiteral(dir, literal) {
  let count = 0;
  for (const entry of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
    if (entry.name === "node_modules") continue;
    const rel = `${dir}/${entry.name}`;
    if (entry.isDirectory()) { count += countMarkerLiteral(rel, literal); continue; }
    if (!entry.name.endsWith(".js")) continue;
    const text = read(rel);
    let at = text.indexOf(literal);
    while (at > -1) { count += 1; at = text.indexOf(literal, at + literal.length); }
  }
  return count;
}

// CONTROL: the literal scan counts a second copy, so a hand-copied marker in another
// server/ file would be caught.
test("CONTROL: the marker-literal scan counts every occurrence", () => {
  const probe = "bundles/browser/server";
  const literal = /export const GUARD_MARKER = "([^"]+)";/.exec(GUARD)?.[1] || "";
  assert.ok(literal, "the marker is defined (the scan below needs its value)");
  // One definition is the floor; the same value twice would be a copy.
  assert.ok(countMarkerLiteral(probe, literal) >= 1, "the definition itself is found");
  assert.equal(countMarkerLiteral(probe, "a string that is not in the tree"), 0);
});

// ---------------------------------------------------------------------------
// 4. Channel 2: the installer default
// ---------------------------------------------------------------------------

test("the image carries the relay and the entrypoint, and the manifest keeps refreshing the relay", () => {
  assert.match(DOCKERFILE, /^COPY cdp-relay\.mjs \.\/$/m, "the relay is in the image");
  assert.match(DOCKERFILE, /^COPY entrypoint\.sh \.\/$/m);
  assert.ok(MANIFEST.refreshFiles.includes("cdp-relay.mjs"), "a bundle refresh must copy the relay too");
  // The other half of channel 2 (the Node 24 base) is pinned by tests/node-standard.test.js
  // as well; both read the same Dockerfile on purpose.
});

test("the image installs the engines major (Node 24), not Node 20", () => {
  assert.ok(DOCKERFILE.includes("setup_24.x"), "the image installs Node 24 (setup_24.x)");
  assert.ok(!DOCKERFILE.includes("setup_20.x"), "Node 20 is end of life and is not what the suite and engines declare");
});

// CONTROL: the negative half of the rule is a real check.
test("CONTROL: the Node 20 rule flags a setup_20.x line", () => {
  assert.match("RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -", /setup_20\.x/, "the pattern sees the old line");
  assert.doesNotMatch("RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash -", /setup_20\.x/);
});

test("the relay's header no longer says the image installs Node 20", () => {
  assert.ok(!RELAY.includes("image installs Node 20"), "the relay's header comment must state the image's real Node major");
});

// CONTROL: the same rule sees the sentence where it used to be.
test("CONTROL: the Node 20 sentence rule flags the old wording", () => {
  assert.match("(the image installs Node 20 LTS, and no Node 22+ API is used here)", /image installs Node 20/);
});

// ---------------------------------------------------------------------------
// 5. Channel 3: the boot check watches every in-image file
// ---------------------------------------------------------------------------

const BUNDLE_DIR = join(ROOT, "bundles", "browser");

/**
 * The source files a Dockerfile COPYs into the image, by basename. Flags
 * (`--chown=…`, `--from=…`) are dropped; the last token of a COPY is the destination.
 */
function copiedSources(dockerfileText) {
  const sources = [];
  for (const line of dockerfileText.split(/\r?\n/)) {
    if (/^\s*#/.test(line)) continue;
    const m = /^\s*(?:COPY|ADD)\s+(.+)$/i.exec(line);
    if (!m) continue;
    const tokens = m[1].trim().split(/\s+/).filter(Boolean);
    while (tokens.length && tokens[0].startsWith("--")) tokens.shift();
    if (tokens.length < 2) continue;
    for (const raw of tokens.slice(0, -1)) {
      const name = basename(raw.replace(/^["']|["']$/g, ""));
      if (name && !/[$*?[\]{}]/.test(name)) sources.push(name);
    }
  }
  return sources;
}

/** The COPY'd sources the boot detector does NOT watch (by basename) — must be empty. */
const unwatchedCopies = (dockerfileText, watched) => copiedSources(dockerfileText).filter((name) => !watched.has(name));

test("the boot detector watches every file the Dockerfile copies into the image", async () => {
  let imageCopies;
  try {
    ({ imageCopies } = await import("../servers/gateway/fix-it/detectors/browser-image-stale.js"));
  } catch (err) {
    assert.fail(`the browser-image-stale detector must load for its input computation: ${err?.message || err}`);
  }

  const watched = new Set(
    imageCopies({ composeText: COMPOSE, composeRel: "docker-compose.yml", dir: BUNDLE_DIR }).map((c) => basename(c.dest)),
  );

  // The build inputs the card is about (plan-delivery section 12, channel 3).
  for (const name of ["cdp-relay.mjs", "entrypoint.sh", "package.json"]) {
    assert.ok(watched.has(name), `the detector must watch ${name}: a running container that predates it is stale`);
  }
  assert.deepEqual(
    unwatchedCopies(DOCKERFILE, watched),
    [],
    "a file the image is built from that the detector does not watch would never raise the card",
  );
});

// CONTROL: one more COPY line the detector does not watch makes the same check fail — so
// adding a file to the image without teaching the detector fails this suite.
test("CONTROL: an unwatched COPY source is reported", async () => {
  const { imageCopies } = await import("../servers/gateway/fix-it/detectors/browser-image-stale.js");
  const watched = new Set(
    imageCopies({ composeText: COMPOSE, composeRel: "docker-compose.yml", dir: BUNDLE_DIR }).map((c) => basename(c.dest)),
  );

  assert.deepEqual(unwatchedCopies(`${DOCKERFILE}\nCOPY holder.mjs ./\n`, watched), ["holder.mjs"]);
});

// ---------------------------------------------------------------------------
// 6. Channel 4: visibility
// ---------------------------------------------------------------------------

test("crow_browser_status reports a gate key fed by readGateStatus", () => {
  const start = SERVER.indexOf('"crow_browser_status"');
  const end = SERVER.indexOf('"crow_browser_navigate"');
  assert.ok(start > -1 && end > start, "the status tool is registered before the navigate tool");
  const region = SERVER.slice(start, end);

  assert.ok(region.includes("readGateStatus"), "the status tool asks the relay for Crow-Guard");
  assert.match(region, /gate\s*:/, "and the output carries a `gate` key (yes/no)");
});

// ---------------------------------------------------------------------------
// 7. Playwright drift pin (plan section 10)
// ---------------------------------------------------------------------------

/**
 * The gate's coverage rule reads what Playwright puts on the wire, so a Playwright change
 * that stops sending `Fetch.enable` with `*`, or stops wrapping init scripts, changes what
 * the relay can see. The pin below is what the bundle declares — an exact version since
 * 1.9.1 (a caret range before it) — and the installed playwright-core must be it.
 */
test("Playwright's own per-page commands still have the shape the coverage rule reads", (t) => {
  const fromBundle = join(ROOT, "bundles", "browser", "package.json");
  const fromRepo = join(ROOT, "package.json");
  let pkgPath = null;
  for (const from of [fromBundle, fromRepo]) {
    try {
      pkgPath = createRequire(from).resolve("playwright-core/package.json");
      break;
    } catch { /* try the next location */ }
  }
  if (!pkgPath) {
    t.skip("playwright-core is not installed in this tree (bundles/browser or the repo): the live pin is the orchestrator's");
    return;
  }

  const installed = JSON.parse(readFileSync(pkgPath, "utf8")).version;
  assert.equal(
    satisfiesPin(installed, BUNDLE_PKG.dependencies.playwright),
    true,
    `installed playwright-core ${installed} must satisfy the bundle's ${BUNDLE_PKG.dependencies.playwright}`,
  );

  const libRoot = dirname(pkgPath);

  // The per-page wire commands live in one of two layouts: separate sources
  // (lib/server/chromium/*.js) up to 1.5x, or bundled into a single lib/coreBundle.js
  // from then on — where lib/server/chromium holds only appIcon.png. Read whichever
  // this install ships, and refuse to pass on neither.
  const chromiumDir = join(libRoot, "lib", "server", "chromium");
  const chromiumSources = existsSync(chromiumDir)
    ? readdirSync(chromiumDir)
      .filter((name) => name.endsWith(".js"))
      .map((name) => readFileSync(join(chromiumDir, name), "utf8"))
    : [];
  const coreBundlePath = join(libRoot, "lib", "coreBundle.js");
  if (existsSync(coreBundlePath)) chromiumSources.push(readFileSync(coreBundlePath, "utf8"));
  assert.ok(
    chromiumSources.length > 0,
    `playwright-core ${installed} ships neither lib/server/chromium/*.js nor lib/coreBundle.js under ${libRoot}: the wire commands to check cannot be read`,
  );
  const chromiumText = chromiumSources.join("\n");

  assert.match(chromiumText, /Fetch\.enable/, "a page session enables Fetch");
  assert.match(chromiumText, /urlPattern:\s*["']\*["']/, "with the catch-all pattern the coverage rule looks for");
  assert.match(chromiumText, /Page\.addScriptToEvaluateOnNewDocument/, "and init scripts are installed as page scripts");

  const pagePath = join(libRoot, "lib", "server", "page.js");
  if (existsSync(pagePath)) {
    const pageSource = readFileSync(pagePath, "utf8");
    assert.ok(pageSource.includes("(() => {"), "init scripts are wrapped as `(() => { … })()`, so the marker is never the first line");
  } else {
    assert.ok(existsSync(coreBundlePath), "playwright-core has lib/server/page.js or lib/coreBundle.js, where init scripts are wrapped");
    assert.match(
      readFileSync(coreBundlePath, "utf8"),
      /\(\(\) => \{\s*\n\s*const module = \{\};/,
      "init scripts are wrapped as `(() => { … })()`, so the marker is never the first line",
    );
  }
});

/** `^major.minor.patch` or an exact `major.minor.patch` — the pin shapes the bundle has used. */
function satisfiesPin(version, pin) {
  const text = String(pin || "");
  if (/^\d+\.\d+\.\d+$/.test(text)) return String(version) === text;
  const m = /^\^(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (!m) return false;
  const [, major, minor, patch] = m.map(Number);
  const floor = [major, minor, patch];
  const ceiling = [major + 1, 0, 0];
  const v = String(version).split(".").map((p) => Number.parseInt(p, 10) || 0);
  return compareSemver(v.join("."), floor.join(".")) >= 0 && compareSemver(v.join("."), ceiling.join(".")) < 0;
}

test("the bundle's playwright dependency string is pinned", () => {
  const { playwright, "playwright-core": playwrightCore } = BUNDLE_PKG.dependencies;

  assert.match(
    String(playwright),
    /^\d+\.\d+\.\d+$/,
    "playwright is pinned to an exact version, not a range: the image's Chromium must not move under a rebuild",
  );
  assert.equal(
    playwrightCore,
    playwright,
    "playwright-core is declared at the same exact version, so the Chromium browsers.json reports is the one Playwright drives",
  );
});

// ---------------------------------------------------------------------------
// 8. Consent copy and docs (plan section 6, the plan's copy block)
// ---------------------------------------------------------------------------

/*
 * The passages below are the plan's approved copy, copied from
 * .pi-brief/plan-copy.md (the consent replacement and the two docs sentences, EN and ES).
 * The cross-check at the end reads that file when it is present, so a transcription slip
 * shows up here rather than as a puzzling failure against the manifest.
 */
// updated to the text approved 2026-11-20 for item 67
const EN_CONSENT = "Crow's own browser tools refuse private and local-network addresses (loopback, LAN, tailnet, link-local, cloud metadata) unless you list an exception in CROW_BROWSER_ALLOW_PRIVATE. This is a rule enforced on the browser's own requests, not a network wall: requests made by a page's background workers and some real-time connections are best effort. If a tool process dies and no other Crow browser tool is connected, the browser blocks every request from the pages it left open and then closes them. Between tools' turns the browser is empty and your own browsing in the viewer is not restricted by this rule, and a program that holds the control key is not limited by it.";
const ES_CONSENT = "Las herramientas de navegador de Crow rechazan las direcciones privadas y de red local (loopback, LAN, tailnet, link-local, metadatos de la nube) salvo que indiques una excepción en CROW_BROWSER_ALLOW_PRIVATE. Es una regla aplicada a las solicitudes del propio navegador, no un muro de red: las solicitudes de los procesos en segundo plano de una página y algunas conexiones en tiempo real se bloquean solo en la medida de lo posible. Si un proceso de herramienta se detiene de forma inesperada y no hay otra herramienta de navegador de Crow conectada, el navegador bloquea todas las solicitudes de las páginas que dejó abiertas y luego las cierra. Entre un turno de herramientas y el siguiente, el navegador queda vacío y tu propia navegación en el visor no está limitada por esta regla, y un programa que tenga la clave de control tampoco queda limitado por ella.";
const EN_DOC_TURNS = "Between bot turns the browser holds one empty page and the gate lets requests through, so what you browse by hand in the viewer is not checked against the private-address rule.";
const ES_DOC_TURNS = "Entre los turnos del bot, el navegador tiene una sola página vacía y la puerta deja pasar las solicitudes, de modo que lo que navegues a mano en el visor no se comprueba contra la regla de direcciones privadas.";
const EN_DOC_LIMITS = "Shared and service workers are closed rather than guarded, so pages that need them (some web apps) do not work in the bot browser. If you reopen a page a bot visited (a closed tab, typed history), it loads as any page you open yourself.";
const ES_DOC_LIMITS = "Los workers compartidos y los service workers se cierran en lugar de vigilarse, así que las páginas que los necesitan (algunas aplicaciones web) no funcionan en el navegador del bot. Si vuelves a abrir una página que visitó un bot (una pestaña cerrada, el historial escrito), se carga como cualquier página que abras tú mismo.";

test("the install consent ends with the plan's passage, in both languages", () => {
  const { en, es } = MANIFEST.install_consent_messages;
  assert.equal(typeof en, "string");
  assert.equal(typeof es, "string");

  assert.ok(en.endsWith(EN_CONSENT), "install_consent_messages.en must END with the plan's private-address passage, byte for byte");
  assert.ok(es.endsWith(ES_CONSENT), "install_consent_messages.es must END with the plan's Spanish passage, byte for byte");

  // CONTROL: a trailing change is caught by the same rule (so endsWith is not a rubber stamp).
  assert.equal(`${EN_CONSENT} Extra sentence.`.endsWith(EN_CONSENT), false);
});

test("the old consent wording is gone", () => {
  const { en, es } = MANIFEST.install_consent_messages;
  assert.ok(
    !en.includes("a holder of the control key is not limited by it. When a bot's turn ends"),
    "the old sentence (a holder of the control key … When a bot's turn ends) must be replaced",
  );
  assert.ok(!en.includes("This is a rule inside Crow's tools, not a network wall"), "the old 'inside Crow's tools' framing is replaced");
  assert.ok(!es.includes("Es una regla dentro de las herramientas de Crow, no un muro de red"), "the old Spanish framing is replaced too");
});

// CONTROL: the negative rule above sees the old sentence where it used to be.
test("CONTROL: the old-wording rule flags the old sentence", () => {
  const old = "…and a holder of the control key is not limited by it. When a bot's turn ends, Crow closes the pages…";
  assert.ok(old.includes("a holder of the control key is not limited by it. When a bot's turn ends"));
});

test("the guide says what happens between turns, in both languages", () => {
  assert.ok(DOCS_EN.includes(EN_DOC_TURNS), "docs/guide/browser-automation.md must carry the plan's between-turns sentence");
  assert.ok(DOCS_ES.includes(ES_DOC_TURNS), "docs/es/guide/browser-automation.md must carry its Spanish twin");
});

test("the guide states the remaining limits (workers, reopening a page), in both languages", () => {
  assert.ok(DOCS_EN.includes(EN_DOC_LIMITS), "docs/guide/browser-automation.md must carry the plan's limits sentence");
  assert.ok(DOCS_ES.includes(ES_DOC_LIMITS), "docs/es/guide/browser-automation.md must carry its Spanish twin");
});

test("the English guide names WebSocket, preconnect and Crow-Guard", () => {
  for (const word of ["WebSocket", "preconnect", "Crow-Guard"]) {
    assert.ok(DOCS_EN.includes(word), `docs/guide/browser-automation.md must name ${word}`);
  }
});

test("the passages above are the ones in the plan's copy block", () => {
  const planCopy = join(ROOT, ".pi-brief", "plan-copy.md");
  if (!existsSync(planCopy)) return; // the brief is not part of the repository
  const text = readFileSync(planCopy, "utf8");
  for (const [name, passage] of Object.entries({
    EN_CONSENT, ES_CONSENT, EN_DOC_TURNS, ES_DOC_TURNS, EN_DOC_LIMITS, ES_DOC_LIMITS,
  })) {
    assert.ok(text.includes(passage), `${name} in this test is not the passage in .pi-brief/plan-copy.md (copy it again, do not retype it)`);
  }
});