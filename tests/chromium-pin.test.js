/**
 * The Chromium CI's live browser tests actually drive — tests/chromium-pin.test.js
 *
 * Why this exists: CI's live layout/browser tests must run the Chromium that the
 * browser bundle's LOCKED playwright ships (bundles/browser, playwright-core's
 * browsers.json: chromium / chromium-headless-shell 159.0.8154.6, revision 1255).
 * A gap between the two let a mismatch hide a real crash: the suite provisioned
 * one Chromium (whatever playwright version the workflow happened to name) while
 * the bundle installed another, so the live tests passed on a browser no install
 * ever runs — and a profile written by the bundle's newer major crash-loops when
 * anything opens it with an older one.
 *
 * The fix is two-sided, and this file pins both sides:
 *   (1) tests/fixtures/chromium-pin.mjs reads the bundle's lock (readBundleChromium)
 *       and decides whether a launched browser matches it (compareChromeVersion);
 *   (2) tests/fixtures/headless-chrome.mjs's findChrome honours that pin when
 *       choosing a downloaded browser, instead of always taking the newest dir.
 *
 * Contract only — no real browser is launched, no network, no bundle build. The
 * fixtures are empty files in throwaway temp dirs. `preferredRevisionDirs` is
 * deliberately not covered here.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { findChrome } from "./fixtures/headless-chrome.mjs";

const HERE = import.meta.dirname;
const BUNDLE_PLAYWRIGHT_CORE = join(HERE, "..", "bundles", "browser", "node_modules", "playwright-core");

/** The module under test, imported lazily so every case reports the missing module itself. */
async function pin() {
  return import("./fixtures/chromium-pin.mjs");
}

/** A throwaway dir removed when the test ends, even if an assertion throws. */
function tempDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "crow-pin-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

/** Write browsers.json (or any file) into a fresh playwright-core dir. */
function playwrightCoreDir(t, browsersJson) {
  const dir = tempDir(t);
  writeFileSync(
    join(dir, "browsers.json"),
    typeof browsersJson === "string" ? browsersJson : JSON.stringify(browsersJson),
  );
  return dir;
}

const BROWSERS_JSON = {
  browsers: [
    { name: "chromium", revision: "1255", browserVersion: "159.0.8154.6", title: "Chrome for Testing" },
    { name: "chromium-headless-shell", revision: "1255", browserVersion: "159.0.8154.6", title: "Chrome Headless Shell" },
    { name: "firefox", revision: "1572", browserVersion: "159.0" },
  ],
};

// ---------------------------------------------------------------------------
// 1. readBundleChromium — the expected Chromium comes from the bundle's own lock
// ---------------------------------------------------------------------------

test("readBundleChromium reads chromium and chromium-headless-shell from browsers.json", async (t) => {
  const { readBundleChromium } = await pin();
  const dir = playwrightCoreDir(t, BROWSERS_JSON);

  assert.deepEqual(readBundleChromium(dir), {
    version: "159.0.8154.6",
    revision: "1255",
    headlessShellRevision: "1255",
  });
});

test("readBundleChromium returns null when the dir or browsers.json is missing", async (t) => {
  const { readBundleChromium } = await pin();
  const empty = tempDir(t);

  assert.equal(readBundleChromium(join(empty, "does-not-exist")), null, "missing dir");
  assert.equal(readBundleChromium(empty), null, "dir without browsers.json");
});

test("readBundleChromium returns null for an unparsable browsers.json", async (t) => {
  const { readBundleChromium } = await pin();
  const dir = playwrightCoreDir(t, "{ this is not json ]");

  assert.equal(readBundleChromium(dir), null);
});

test("readBundleChromium returns null when there is no chromium entry", async (t) => {
  const { readBundleChromium } = await pin();
  const dir = playwrightCoreDir(t, {
    browsers: [{ name: "chromium-headless-shell", revision: "1255", browserVersion: "159.0.8154.6" }],
  });

  assert.equal(readBundleChromium(dir), null);

  const bare = playwrightCoreDir(t, { browsers: "not an array" });
  assert.equal(readBundleChromium(bare), null, "browsers is not a list");
});

test("readBundleChromium reads the real bundle lock when it is installed", async (t) => {
  const { readBundleChromium } = await pin();
  if (!existsSync(join(BUNDLE_PLAYWRIGHT_CORE, "browsers.json"))) {
    t.skip("bundles/browser/node_modules/playwright-core is not installed here");
    return;
  }

  const pinned = readBundleChromium(BUNDLE_PLAYWRIGHT_CORE);
  assert.ok(pinned, "the bundle's browsers.json has a chromium entry");
  assert.match(pinned.version, /^\d+\.\d+\.\d+\.\d+$/, "a full Chromium browserVersion");
  assert.match(pinned.revision, /^\d+$/, "a numeric revision");
  assert.match(pinned.headlessShellRevision, /^\d+$/, "a numeric headless-shell revision");
});

// ---------------------------------------------------------------------------
// 2. compareChromeVersion — does the browser we launched match the lock?
// ---------------------------------------------------------------------------

test("compareChromeVersion is ok on the same major, whatever the minor/build", async () => {
  const { compareChromeVersion } = await pin();
  const expected = "159.0.8154.6";

  assert.equal(compareChromeVersion({ launched: "159.0.8154.6", expected }).status, "ok");
  assert.equal(
    compareChromeVersion({ launched: "159.0.9000.1", expected }).status,
    "ok",
    "same major, different minor/build — still the same profile format",
  );
});

test("compareChromeVersion reads the major out of a UA-ish launched string", async () => {
  const { compareChromeVersion } = await pin();
  const expected = "159.0.8154.6";

  assert.equal(compareChromeVersion({ launched: "Chrome/159.0.8154.6", expected }).status, "ok");
  assert.equal(compareChromeVersion({ launched: "HeadlessChrome/159.0.8154.6", expected }).status, "ok");
  assert.equal(compareChromeVersion({ launched: "Chrome/159.0.1000.0", expected }).status, "ok");
});

test("compareChromeVersion warns on a major mismatch unless required", async () => {
  const { compareChromeVersion } = await pin();
  const launched = "154.0.8000.1";
  const expected = "159.0.8154.6";

  const warn = compareChromeVersion({ launched, expected, require: false });
  assert.equal(warn.status, "warn");
  assert.match(warn.message, /154\.0\.8000\.1/, "the message names the launched version");
  assert.match(warn.message, /159\.0\.8154\.6/, "the message names the expected version");

  const fail = compareChromeVersion({ launched, expected, require: true });
  assert.equal(fail.status, "fail");
  assert.match(fail.message, /154\.0\.8000\.1/, "the message names the launched version");
  assert.match(fail.message, /159\.0\.8154\.6/, "the message names the expected version");
});

test("compareChromeVersion never fails when there is nothing to compare against", async () => {
  const { compareChromeVersion } = await pin();
  const launched = "159.0.8154.6";

  for (const expected of [null, undefined, "", "unknown"]) {
    const result = compareChromeVersion({ launched, expected, require: true });
    assert.equal(result.status, "warn", `expected ${JSON.stringify(expected)} cannot be checked`);
  }
});

test("compareChromeVersion handles a launched version it cannot parse", async () => {
  const { compareChromeVersion } = await pin();
  const expected = "159.0.8154.6";

  for (const launched of [null, undefined, "", "not-a-version"]) {
    assert.equal(
      compareChromeVersion({ launched, expected, require: false }).status,
      "warn",
      `unparsable launched ${JSON.stringify(launched)} warns when not required`,
    );
    assert.equal(
      compareChromeVersion({ launched, expected, require: true }).status,
      "fail",
      `unparsable launched ${JSON.stringify(launched)} fails when required`,
    );
  }
});

// ---------------------------------------------------------------------------
// 3. preferredRevisionDirs — intentionally not covered here.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 4. findChrome honours the revision pin instead of always taking the newest dir
// ---------------------------------------------------------------------------

/** Create a fake executable browser at <base>/<dir>/<sub>/<binary>. */
function fakeBrowser(base, dir, sub, binary) {
  const binDir = join(base, dir, sub);
  mkdirSync(binDir, { recursive: true });
  const file = join(binDir, binary);
  writeFileSync(file, "");
  chmodSync(file, 0o755);
  return file;
}

const headlessShell = (base, revision) =>
  fakeBrowser(base, `chromium_headless_shell-${revision}`, "chrome-headless-shell-linux64", "chrome-headless-shell");

const fullChromium = (base, revision) => fakeBrowser(base, `chromium-${revision}`, "chrome-linux64", "chrome");

/** A CI-like env: only the download dir, no explicit binary, no system-Chrome fallback. */
const envFor = (base) => ({ PLAYWRIGHT_BROWSERS_PATH: base, GITHUB_ACTIONS: "true" });

test("findChrome picks the pinned headless-shell revision over a newer one", (t) => {
  const base = tempDir(t);
  fakeBrowser(base, "chromium_headless_shell-1243", "chrome-headless-shell-linux64", "chrome-headless-shell");
  const pinned = headlessShell(base, 1255);
  const newer = headlessShell(base, 1300);

  assert.equal(
    findChrome(envFor(base), { revisions: { headlessShell: "1255", chromium: "1255" } }),
    pinned,
    "the bundle's pinned revision (1255) wins over the newer 1300 the cache also holds",
  );
  assert.notEqual(findChrome(envFor(base), { revisions: { headlessShell: "1255" } }), newer);
});

test("findChrome keeps taking the newest headless shell when nothing is pinned", (t) => {
  const base = tempDir(t);
  headlessShell(base, 1243);
  headlessShell(base, 1255);
  const newest = headlessShell(base, 1300);

  assert.equal(
    findChrome(envFor(base), { revisions: null }),
    newest,
    "no pin (revisions: null) means the old newest-first behaviour, unchanged",
  );
});

test("findChrome falls back to the newest headless shell when the pinned revision is absent", (t) => {
  const base = tempDir(t);
  headlessShell(base, 1243);
  const newest = headlessShell(base, 1300);

  assert.equal(
    findChrome(envFor(base), { revisions: { headlessShell: "9999", chromium: "9999" } }),
    newest,
    "an un-downloaded pinned revision must not leave the suite without a browser",
  );
});

test("findChrome picks the pinned full-chromium revision when there is no headless shell", (t) => {
  const base = tempDir(t);
  fullChromium(base, 1243);
  const pinned = fullChromium(base, 1255);
  const newer = fullChromium(base, 1300);

  assert.equal(
    findChrome(envFor(base), { revisions: { headlessShell: "1255", chromium: "1255" } }),
    pinned,
    "with no headless shell installed, the pinned chromium-1255/chrome-linux64/chrome is chosen",
  );
  assert.notEqual(findChrome(envFor(base), { revisions: { chromium: "1255" } }), newer);
});

test("findChrome keeps taking the newest full chromium when nothing is pinned", (t) => {
  const base = tempDir(t);
  fullChromium(base, 1243);
  fullChromium(base, 1255);
  const newest = fullChromium(base, 1300);

  assert.equal(findChrome(envFor(base), { revisions: null }), newest);
});

test("findChrome falls back to the newest full chromium when the pinned revision is absent", (t) => {
  const base = tempDir(t);
  fullChromium(base, 1243);
  const newest = fullChromium(base, 1300);

  assert.equal(findChrome(envFor(base), { revisions: { headlessShell: "9999", chromium: "9999" } }), newest);
});