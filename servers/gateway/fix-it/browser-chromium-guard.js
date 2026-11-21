/**
 * Chromium-downgrade guard for the "Restart the browser add-on" Fix-it card.
 *
 * Why this exists. The card's remedy runs the Extensions restart, which is
 * `up -d --build --force-recreate` (remedies/restart-browser-addon.js): it REBUILDS the
 * image from the files Crow just installed, and then re-creates the container on it.
 * The rebuild installs exactly what `bundles/browser/package-lock.json` pins — since 1.9.1
 * playwright-core 1.65.1, whose bundled Chromium is 159; before that 1.58.2 → Chromium 145 —
 * while the RUNNING container's persistent profile may have been written by a NEWER Chromium.
 * Chromium refuses, then crash-loops on, a profile written by a newer major than itself.
 * So a restart that moves the image backwards takes the add-on down for good: the very
 * card that was meant to fix it is what breaks it.
 *
 * So the restart is offered ONLY when it cannot move the profile backwards:
 *
 *   bundled major   what the rebuilt image's `npm ci` installs
 *   profile major   what the RUNNING container's persistent profile was last written by
 *
 * blocked = an unknown bundled major, no running container, an unreadable profile, or
 *           bundled < any profile. Everything else (equal, or an upgrade) is allowed.
 * FAIL CLOSED: every unknown is a refusal, never a maybe. The detector then HIDES the
 * card (no new copy) and the remedy refuses to restart; the add-on keeps working on the
 * old image, which is the safe outcome.
 *
 * ── Why a hand-kept version table ───────────────────────────────────────────
 * The installed bundle dir holds package-lock.json but NOT playwright-core's
 * browsers.json. A host-level node_modules/playwright-core may be absent, unlocked, or
 * simply a different version from the one the image's `npm ci` installs, so reading it
 * would answer a question nobody asked. The lock IS the authority for what the image
 * installs, and PLAYWRIGHT_CHROMIUM_MAJOR maps that pin to the Chromium major it
 * downloads. The table lists every lock pin a release has shipped: the newest is
 * playwright-core 1.65.1 → chromium browserVersion 159.0.8154.6, and the older pins
 * stay so a lock that has not moved (or a deliberate rollback) still resolves. A
 * playwright version the table does not know is UNKNOWN → blocked, and
 * tests/fix-it-browser-chromium-guard.test.js fails CI the moment
 * bundles/browser/package-lock.json moves to a version missing from the table — a lock
 * bump must add its Chromium major here in the same change.
 *
 * No import of the detector or the remedy: the detector imports the remedy, so a shared
 * module must not close that loop. That is also why the docker bounds are local
 * constants rather than the detector's exports.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CROW_HOME, manifestComposeFile } from "../bundles-config.js";
import { composeProjectName } from "../bundle-lifecycle.js";
import { composeEnv, parseDotEnv } from "../compose-guard.js";

/**
 * playwright-core version (as pinned in bundles/browser/package-lock.json) → the major
 * of the Chromium build it downloads. The table lists every lock pin a release has
 * shipped, newest first: playwright-core 1.65.1's browsers.json pins chromium
 * 159.0.8154.6, and 1.58.2's pinned 145.0.7632.6. Keep older entries — a lock that has
 * not moved yet, or a conscious rollback, must still resolve.
 */
export const PLAYWRIGHT_CHROMIUM_MAJOR = Object.freeze({
  "1.65.1": 159,
  "1.58.2": 145,
});

/** Reading one small file out of a running container (a cold exec can take a moment). */
export const PROFILE_READ_TIMEOUT_MS = 20_000;
/** `docker ps` for the bundle's compose project — never an unbounded docker call. */
export const DOCKER_PS_TIMEOUT_MS = 15_000;

/** Where Chromium records the version that last wrote the profile (the browser image's user-data-dir). */
const PROFILE_VERSION_PATH = "/root/.config/chromium-crow/Last Version";
/** The lock entry whose version decides what the image's `npm ci` installs. */
const PLAYWRIGHT_CORE_LOCK_KEY = "node_modules/playwright-core";

function readJson(path) {
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
}

/**
 * The Chromium major the installed bundle's image would install, or null when that is
 * unknown (no lock, no playwright-core entry, an unparseable lock, or a playwright
 * version this module has no table entry for).
 */
export function bundledChromiumMajor(bundleDir) {
  try {
    const lock = readJson(join(bundleDir, "package-lock.json"));
    const version = lock?.packages?.[PLAYWRIGHT_CORE_LOCK_KEY]?.version;
    if (typeof version !== "string") return null;
    const major = PLAYWRIGHT_CHROMIUM_MAJOR[version];
    return typeof major === "number" ? major : null;
  } catch {
    return null;
  }
}

/**
 * The major Chromium that last wrote the profile inside `containerId`, or null when it
 * cannot be read (exec failed, timed out, no such file, or something that is not a
 * version). Null is "unknown" and the caller fails closed on it.
 */
export async function profileChromiumMajor(containerId, runner) {
  try {
    const out = await runner("docker", ["exec", containerId, "cat", PROFILE_VERSION_PATH], { timeout: PROFILE_READ_TIMEOUT_MS });
    const match = /^(\d+)\.\d+/.exec(String(out?.stdout ?? "").trim());
    return match ? Number(match[1]) : null;
  } catch {
    return null;
  }
}

/**
 * Would rebuilding and re-creating the running containers install an OLDER Chromium than
 * their profiles were written by? `{ blocked, bundled, profiles }` — `profiles` holds one
 * entry per id (null where unreadable). Never throws: an internal error is a refusal.
 */
export async function restartWouldDowngrade({ bundleDir, ids = [], runner } = {}) {
  try {
    const bundled = bundledChromiumMajor(bundleDir);
    const list = Array.isArray(ids) ? ids.filter((id) => typeof id === "string" && id !== "") : [];
    const profiles = [];
    for (const id of list) profiles.push(await profileChromiumMajor(id, runner));
    // Fail closed on every unknown: an unreadable lock or profile, and no container at
    // all (nothing to justify the restart for), are all refusals.
    const blocked = bundled === null
      || list.length === 0
      || profiles.some((major) => major === null)
      || profiles.some((major) => bundled < major);
    return { blocked, bundled, profiles };
  } catch {
    return { blocked: true, bundled: null, profiles: [] };
  }
}

/**
 * The running container ids of `bundleDir`'s compose project — the same lookup the
 * detector does (`docker ps` by the com.docker.compose.project label, README compose
 * vars resolved). [] on any failure: a docker we cannot ask is not a reason to restart.
 */
export async function runningBrowserContainerIds({ bundleDir, crowHome = CROW_HOME, runner } = {}) {
  try {
    // Resolved per call, never at import: a remedy runs long after the module loaded.
    const dir = bundleDir || join(crowHome, "bundles", "browser");
    const manifest = readJson(join(dir, "manifest.json"));
    const composeRel = manifestComposeFile(manifest);
    if (!composeRel) return [];
    let composeText;
    try { composeText = readFileSync(join(dir, composeRel), "utf8"); } catch { return []; }
    const env = { ...parseDotEnv(join(dir, ".env")), ...composeEnv(process.env, crowHome) };
    const { stdout } = await runner("docker", [
      "ps",
      "--filter", `label=com.docker.compose.project=${composeProjectName(composeText, dir, env)}`,
      "--filter", "status=running",
      "--format", "{{.ID}}",
    ], { timeout: DOCKER_PS_TIMEOUT_MS });
    return String(stdout || "").split("\n").map((s) => s.trim()).filter(Boolean);
  } catch {
    return [];
  }
}