/**
 * The browser image's Chromium floor — tests/browser-chromium-floor.test.js
 *
 * Release 1.9.1 moves bundles/browser's lock forward to playwright 1.65.1 (Chromium
 * 159.0.8154.6), the version every existing install's image has been running (those
 * images were built without the lock). Chromium cannot open a profile written by a
 * NEWER major — it crash-loops — so the lock must never resolve BACKWARDS from what
 * already wrote every existing profile. chromium-floor.json records that floor.
 *
 *   (a) the lock's playwright-core → a known PLAYWRIGHT_CHROMIUM_MAJOR major, at or
 *       above the floor;
 *   (b) package.json pins playwright and playwright-core EXACTLY to the lock's versions
 *       (a caret would let `npm ci`'s source move at the next lock regeneration);
 *   (c) when node_modules/playwright-core/browsers.json is present, its chromium
 *       browserVersion agrees with the table (skipped otherwise);
 *   (d) the Dockerfile records the image's Chromium in /opt/crow-chromium-version,
 *       after the playwright install line;
 *   (e) entrypoint.sh carries the downgrade guard, after the instance marker and before
 *       Xvfb starts, with the sleep before the exit;
 *   (f) manifest.json is the release that shipped the SIGTERM close-window gate fix
 *       (now 1.9.3; that fix first shipped in 1.9.2).
 *
 * Static + read-only: no docker, no build.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const BUNDLE = join(import.meta.dirname, "..", "bundles", "browser");
const read = (file) => readFileSync(join(BUNDLE, file), "utf8");
const readJson = (file) => JSON.parse(read(file));

/**
 * PLAYWRIGHT_CHROMIUM_MAJOR, imported lazily: the module reads bundles-config at load
 * time, so it must not be a static import here.
 */
async function chromiumTable() {
  const mod = await import("../servers/gateway/fix-it/browser-chromium-guard.js");
  return mod.PLAYWRIGHT_CHROMIUM_MAJOR;
}

/** The lock's playwright / playwright-core versions (the image's `npm ci` installs these). */
function lockVersions() {
  const lock = readJson("package-lock.json");
  return {
    playwright: lock?.packages?.["node_modules/playwright"]?.version,
    playwrightCore: lock?.packages?.["node_modules/playwright-core"]?.version,
  };
}

/** The lock's Chromium major through the same table the Fix-it guard uses, or null. */
async function lockChromiumMajor() {
  const { playwrightCore } = lockVersions();
  const table = await chromiumTable();
  return Object.prototype.hasOwnProperty.call(table, playwrightCore) ? table[playwrightCore] : null;
}

test("(a) the lock's Chromium is known and at or above the previous release's floor", async () => {
  const { playwrightCore } = lockVersions();
  assert.equal(typeof playwrightCore, "string", "bundles/browser/package-lock.json pins playwright-core");

  const major = await lockChromiumMajor();
  assert.equal(
    typeof major,
    "number",
    `PLAYWRIGHT_CHROMIUM_MAJOR has no entry for playwright-core ${playwrightCore}: add the Chromium major its browsers.json downloads`,
  );

  const floor = readJson("chromium-floor.json");
  assert.ok(Number.isInteger(floor.chromiumMajor), "chromium-floor.json has an integer chromiumMajor");
  assert.ok(
    major >= floor.chromiumMajor,
    `the lock (playwright-core ${playwrightCore}) would move the image to Chromium ${major}, older than the ` +
      `previous release's Chromium ${floor.chromiumMajor}: every existing profile was written by that newer ` +
      `Chromium, which cannot open it — the browser would crash-loop on start. Move the lock forward instead.`,
  );
});

test("(b) package.json pins playwright and playwright-core exactly to the lock's versions", () => {
  const pkg = readJson("package.json");
  const { playwright, playwrightCore } = lockVersions();
  const EXACT = /^\d+\.\d+\.\d+$/;

  assert.equal(typeof playwright, "string", "the lock pins playwright");
  assert.equal(typeof playwrightCore, "string", "the lock pins playwright-core");

  assert.equal(
    pkg.dependencies?.playwright,
    playwright,
    `package.json must pin playwright to the lock's ${playwright} exactly (got ${pkg.dependencies?.playwright})`,
  );
  assert.equal(
    pkg.dependencies?.["playwright-core"],
    playwrightCore,
    `package.json must declare playwright-core at the lock's ${playwrightCore} exactly (got ${pkg.dependencies?.["playwright-core"]})`,
  );
  assert.match(pkg.dependencies.playwright, EXACT, "playwright is an exact version, not a range");
  assert.match(pkg.dependencies["playwright-core"], EXACT, "playwright-core is an exact version, not a range");
});

test("(c) the installed playwright-core's browsers.json agrees with the table", async (t) => {
  const browsersPath = join(BUNDLE, "node_modules", "playwright-core", "browsers.json");
  if (!existsSync(browsersPath)) return t.skip("no node_modules/playwright-core here (the image installs it)");

  const browsers = JSON.parse(readFileSync(browsersPath, "utf8"))?.browsers ?? [];
  const chromium = browsers.find((entry) => entry.name === "chromium");
  assert.ok(chromium?.browserVersion, "browsers.json has a chromium entry with a browserVersion");

  const major = Number(String(chromium.browserVersion).split(".")[0]);
  const table = await chromiumTable();
  const { playwrightCore } = lockVersions();
  assert.equal(
    table[playwrightCore],
    major,
    `the table says playwright-core ${playwrightCore} is Chromium ${table[playwrightCore]}, but this ` +
      `playwright-core's browsers.json pins ${chromium.browserVersion}`,
  );
});

test("(d) the Dockerfile records the image's Chromium after installing it", () => {
  const df = read("Dockerfile");
  const installAt = df.indexOf("npx playwright install chromium");
  assert.ok(installAt >= 0, "the Dockerfile still installs Playwright's Chromium");

  const writeAt = df.indexOf("/opt/crow-chromium-version");
  assert.ok(writeAt > installAt, "the image's Chromium version is written AFTER the install line (before it, there is nothing to read)");

  const step = df.slice(installAt, writeAt + "/opt/crow-chromium-version".length);
  assert.match(step, /browsers\.json/, "the version comes from playwright-core's browsers.json");
  assert.match(step, /\bbrowserVersion\b/, "the version is browsers.json's chromium browserVersion");
  const runs = df.split("\n").filter((line) => line.trim().startsWith("RUN ") && line.includes("/opt/crow-chromium-version"));
  assert.equal(runs.length, 1, "one RUN writes the version file");
});

test("(e) entrypoint.sh carries the downgrade guard, after the instance marker and before Xvfb", () => {
  const ep = read("entrypoint.sh");

  // What the guard reads and says.
  assert.match(ep, /PROFILE_LAST_VERSION="\$PROFILE_DIR\/Last Version"/, "the guard reads the profile's own Last Version");
  assert.match(ep, /newer than this image's/, "the refusal names both versions");
  assert.match(ep, /\.crow-downgrade-refused/, "the refusal leaves its marker in the profile");
  assert.match(ep, /Rebuild with the current add-on or restore the previous image\./, "the refusal says what to do");

  // The exit is delayed, and only the exit: the FATAL line is printed first, then the
  // sleep, then exit 1 (a restart policy must not spin on the same profile).
  const helperAt = ep.indexOf("die_after_sleep() {");
  assert.ok(helperAt >= 0, "the delayed fatal helper exists");
  const helperEnd = ep.indexOf("\n}", helperAt);
  const helper = ep.slice(helperAt, helperEnd);
  const printAt = helper.indexOf("FATAL:");
  const sleepAt = helper.search(/\bsleep\s+"\$seconds"/);
  const exitAt = helper.indexOf("exit 1");
  assert.ok(printAt >= 0 && sleepAt > printAt, "the FATAL line is printed before the sleep");
  assert.ok(exitAt > sleepAt, "the sleep comes before the exit");
  assert.match(ep, /die_after_sleep "\$REFUSE_SLEEP"/, "the guard goes through the delayed fatal");
  assert.match(ep, /CROW_DOWNGRADE_REFUSE_SLEEP:-30/, "the delay defaults to 30 s and is overridable");

  // Order: after the instance marker, before Xvfb starts.
  const markerAt = ep.indexOf('log "profile marked for instance');
  const guardAt = ep.indexOf("--- Chromium downgrade guard ---");
  const xvfbAt = ep.indexOf('Xvfb ":${DISP_NUM}"');
  assert.ok(markerAt >= 0, "the instance-marker block is still there");
  assert.ok(guardAt > markerAt, "the downgrade guard runs after the instance marker");
  assert.ok(xvfbAt > guardAt, "the downgrade guard runs before Xvfb starts");
});

test("(f) manifest.json is the release that shipped the SIGTERM close-window gate fix", () => {
  assert.equal(readJson("manifest.json").version, "1.9.3");
});