/**
 * Which Chromium the browser bundle's LOCKED playwright ships — and whether the
 * browser a live test actually launched is that one.
 *
 * The live browser tests must drive the browser a real Crow install runs, and
 * that browser is decided by whatever bundles/browser/package-lock.json pins
 * (the playwright version there → playwright-core's browsers.json: a chromium /
 * chromium-headless-shell revision, each with its own Chromium version). CI
 * provisions exactly that pair with the bundle's own CLI, and the same lock is
 * what the product image installs from — so a browser the suite inherited from
 * some other pinned playwright would be a browser no install ever runs, and a major
 * mismatch is exactly how a profile-format change turns into a green suite and
 * a crash-looping product browser.
 *
 * Two pieces:
 *   readBundleChromium(dir)  — the expected Chromium, read from a playwright-core
 *                              install's browsers.json (null when there is none);
 *   compareChromeVersion()   — ok / warn / fail for a launched browser's version
 *                              against that expectation (same MAJOR is enough:
 *                              a profile format is a major-version contract).
 *
 * Plus the resolution helpers the live tests share: playwrightCoreDirs (where
 * playwright-core may live, in priority order) and bundleChromium (the first of
 * those that carries a browsers.json pin), and describeBrowserVersions, the one
 * place that turns a launch into the human log lines the suite prints.
 *
 * Contract only — no browser, no network, no bundle build.
 */
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** The repo's own bundle checkout (this file lives in tests/fixtures/). */
const REPO_BUNDLE_PLAYWRIGHT_CORE = fileURLToPath(
  new URL("../../bundles/browser/node_modules/playwright-core", import.meta.url),
);

/**
 * The expected Chromium of a playwright-core install: what its browsers.json
 * says the locked playwright downloads.
 *
 * @param {string} dir a playwright-core package dir (one with browsers.json)
 * @returns {null | { version: string, revision: string, headlessShellRevision: string }}
 *   null when the dir, its browsers.json, its `browsers` list or the chromium
 *   entry cannot be used — i.e. nothing to pin against.
 */
export function readBundleChromium(dir) {
  if (typeof dir !== "string" || dir.length === 0) return null;
  let parsed = null;
  try {
    parsed = JSON.parse(readFileSync(join(dir, "browsers.json"), "utf8"));
  } catch {
    return null; // missing dir, missing file, or unparsable JSON
  }
  const browsers = parsed && parsed.browsers;
  if (!Array.isArray(browsers)) return null;

  const chromium = browsers.find((b) => b && b.name === "chromium");
  if (!chromium) return null;

  const version = typeof chromium.browserVersion === "string" ? chromium.browserVersion : "";
  const revision = chromium.revision == null ? "" : String(chromium.revision);
  if (!version || !revision) return null; // an entry with no version/revision pins nothing

  // The headless shell travels with chromium in one playwright release, but its
  // own revision is what names its download dir: fall back to chromium's when the
  // release ships only the full browser.
  const headlessShell = browsers.find((b) => b && b.name === "chromium-headless-shell");
  const headlessShellRevision =
    headlessShell && headlessShell.revision != null ? String(headlessShell.revision) : revision;

  return { version, revision, headlessShellRevision };
}

/** The major version out of "159.0.8154.6", "Chrome/159.0.8154.6", "HeadlessChrome/159.0.1.2". */
function majorOf(version) {
  if (typeof version !== "string") return null;
  const m = version.match(/(\d+)(?:\.\d+)+/);
  return m ? Number(m[1]) : null;
}

const shown = (version) => (version == null || version === "" ? "unknown" : String(version));

/**
 * Does the Chromium we launched match what the bundle's locked playwright ships?
 *
 * A profile written by one Chromium major is not readable by another, so the
 * MAJOR is the contract: a different minor/build is still the same profile
 * format. An expectation we cannot read, or a launched version we cannot parse,
 * is a WARN — there is nothing to compare — unless `require` is set (CI), where
 * an unparsable launch is a FAIL rather than a silent pass.
 *
 * @param {{ launched?: string|null, expected?: string|null, require?: boolean }} opts
 * @returns {{ status: "ok"|"warn"|"fail", message: string }}
 */
export function compareChromeVersion({ launched, expected, require: required = false } = {}) {
  const launchedMajor = majorOf(launched);
  const expectedMajor = majorOf(expected);

  if (expectedMajor === null) {
    return {
      status: "warn",
      message: `cannot check the launched Chromium against the browser bundle: expected ${shown(expected)} is not a version`,
    };
  }
  if (launchedMajor === null) {
    return {
      status: required ? "fail" : "warn",
      message:
        `cannot read a Chromium version out of the launched browser (${shown(launched)}), so it cannot be ` +
        `checked against the browser bundle's Chromium ${shown(expected)}`,
    };
  }
  if (launchedMajor === expectedMajor) {
    return {
      status: "ok",
      message: `launched Chromium major ${launchedMajor} matches the browser bundle's Chromium ${shown(expected)}`,
    };
  }
  return {
    status: required ? "fail" : "warn",
    message:
      `launched Chromium ${shown(launched)} is major ${launchedMajor}, but the browser bundle's locked ` +
      `playwright ships Chromium ${shown(expected)} (major ${expectedMajor}) — the live tests are driving a ` +
      "browser no Crow install runs",
  };
}

/**
 * Where playwright-core may live, in priority order: an explicit dir first, then
 * the installed bundle's, then this repo's own bundles/browser/node_modules copy.
 *
 * @param {NodeJS.ProcessEnv|object} env
 * @returns {string[]}
 */
export function playwrightCoreDirs(env = process.env) {
  return [
    env.CROW_TEST_PLAYWRIGHT_DIR,
    join(homedir(), ".crow", "bundles", "browser", "node_modules", "playwright-core"),
    REPO_BUNDLE_PLAYWRIGHT_CORE,
  ].filter((dir) => typeof dir === "string" && dir.length > 0);
}

/**
 * The bundle's Chromium pin, from the first playwright-core install that has one.
 *
 * @param {NodeJS.ProcessEnv|object} env
 * @returns {null | { dir: string, version: string, revision: string, headlessShellRevision: string }}
 */
export function bundleChromium(env = process.env) {
  for (const dir of playwrightCoreDirs(env)) {
    const pinned = readBundleChromium(dir);
    if (pinned) return { dir, ...pinned };
  }
  return null;
}

/**
 * The human log lines for one launch, plus the compareChromeVersion verdict.
 *
 * @param {{ clientVersion?: string|null, launched?: string|null, expected?: string|null, require?: boolean }} opts
 * @returns {{ lines: string[], status: "ok"|"warn"|"fail", message: string }}
 */
export function describeBrowserVersions({ clientVersion, launched, expected, require: required } = {}) {
  const compared = compareChromeVersion({ launched, expected, require: required });
  return {
    lines: [
      `playwright-core client ${shown(clientVersion)}`,
      `launched browser ${shown(launched)}`,
      `bundle expects Chromium ${shown(expected)}`,
      `${compared.status}: ${compared.message}`,
    ],
    status: compared.status,
    message: compared.message,
  };
}