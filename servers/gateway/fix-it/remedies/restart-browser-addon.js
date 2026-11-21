/**
 * Instant Fix-it remedy (OWNER ONLY): restart the browser add-on, which is what
 * rebuilds its container image from the files Crow just installed.
 *
 * The card exists because a bundle refresh copies new files into
 * ~/.crow/bundles/<id>/ but never rebuilds or restarts a running container
 * (routes/bundles.js: "No automatic rebuild: Extensions Restart/Start runs
 * `up -d --build`"). So this action must run exactly that: the SAME path the
 * Restart button on an Extensions card runs, not a new docker call of our own.
 * That path is the route's local start — ownership check → the consent + compose
 * safety check on what Compose will apply NOW → `up -d --build --force-recreate`
 * → the post-restart re-check of the boot detectors.
 *
 * ── IN PROCESS, never over HTTP ─────────────────────────────────────────────
 * This used to re-POST the owner's own request to this gateway's own listener on
 * plain-HTTP loopback, carrying the forwarded Cookie and CSRF token. That can no
 * longer work: the dashboard session cookie is `__Host-crow_session`, and a
 * `__Host-` cookie is only sent over HTTPS, so the loopback request went out with
 * the stale plain `crow_session` (or none) and the route answered 403/302 — the
 * remedy could never restart anything. Instead the route's local start is a
 * module-level function (routes/bundles.js `startBundleLocal`) and this remedy
 * calls `restartBundleInProcess(BUNDLE_ID)`, which runs it with `recreate: true`
 * and no request at all: no cookie, no CSRF token, no self-call, nothing to
 * forward. The owner-only rule below is checked first (the same rule the compose
 * restore uses: a local password session on this machine, never a peer sign-in);
 * `restartBundleInProcess` is not an HTTP route and checks no session itself.
 *
 * `recreateBundleGuarded` is NOT that path: it runs `up -d --force-recreate`
 * without `--build`, so it re-creates the container from the image that is
 * already on disk — the old one — which is precisely what this card is about.
 *
 * UNDO: there is none. A rebuild replaces the running container and closes the
 * page that is open in it; the Chromium profile lives on a named volume, so
 * saved logins and cookies survive. The card says so in plain words, and offers
 * "Not now" (the shared dismissal button every Fix-it card has) for the owner
 * who does not want to lose that page right now.
 *
 * ── Why it can refuse ─────────────────────────────────────────────────────
 * `up -d --build --force-recreate` REBUILDS the image, so it installs the Chromium the
 * installed lock pins (playwright-core 1.58.2 → Chromium 145). A running container's
 * persistent profile may have been written by a NEWER Chromium (159), and Chromium
 * refuses, then crash-loops on, a profile written by a newer major version. So before
 * restarting, this remedy asks browser-chromium-guard.js whether the rebuild would go
 * BACKWARDS: an unknown account, an unreadable profile, or bundled < profile refuses
 * (fail closed) with one console.warn and no user-facing copy — the owner keeps a
 * working (old) add-on, and the card stays pending for a later attempt.
 *
 * Every non-success path writes exactly ONE console.warn line, naming a short code and
 * never a secret: `[fix-it] browser add-on: the restart did not run (<code>)`, where the
 * code is owner_only, downgrade_guard, timeout, or start_failed:<the start's own code, or
 * its error message with every whitespace run collapsed to one space, trimmed, then cut to
 * 200 characters>.
 *
 * All user-facing strings for the card live in the detector's ONE copy object
 * (fix-it/detectors/browser-image-stale.js, COPY). Copy approved by the operator
 * 2026-11-19. This file adds none: a refusal reuses the compose restore's owner-only flash,
 * and a restart that did not run falls back to the Nest's generic "Couldn't
 * apply that fix" line rather than inventing a second sentence here.
 */
import { join } from "node:path";
import { isLocalPasswordSessionOn } from "../../dashboard/local-session.js";
import { CROW_HOME } from "../../bundles-config.js";
import { dockerRunner } from "../../bundle-core.js";
import { restartWouldDowngrade, runningBrowserContainerIds } from "../browser-chromium-guard.js";
import { OWNER_ONLY_FLASH, OWNER_ONLY_MESSAGE } from "./restore-bundle-compose.js";

export const ACTION_ID = "restart-browser-addon";
/** The ONE bundle this card is about — held here, never read from the stored card. */
export const BUNDLE_ID = "browser";
/**
 * The Extensions route the Restart button calls (routes/bundles.js, `/dashboard` mount).
 * Kept as documentation of the path this remedy runs: it is no longer dialed from here
 * (see "IN PROCESS" above).
 */
export const START_ROUTE = "/dashboard/bundles/api/start";
/**
 * A first build of this image pulls Playwright's Chromium and takes minutes; a
 * rebuild after a bundle refresh only re-runs the last COPY layers. The bound
 * exists so a hung build cannot hold the click open forever.
 */
export const RESTART_TIMEOUT_MS = 15 * 60 * 1000;

/**
 * Test-only: replace the owner rule, the Chromium-downgrade guard and the restart itself.
 * None of them ever reaches docker or the network in a test.
 *
 *   owner(db, req)            -> boolean
 *   guard()                   -> { blocked: boolean } (anything but `blocked: false` refuses)
 *   startBundle(bundleId)     -> what restartBundleInProcess answers ({ ok } or { ok:false, ... })
 *   restart(bundleId, req)    -> the same, for callers that replace the restart itself
 *   timeoutMs                 -> how long the restart may take (default RESTART_TIMEOUT_MS)
 */
let _depsForTest = null;
export function _setRestartDepsForTest(deps) { _depsForTest = deps || null; }

async function isOwner(db, req) {
  if (typeof _depsForTest?.owner === "function") return (await _depsForTest.owner(db, req)) === true;
  return (await isLocalPasswordSessionOn(db, req)) === true;
}

/**
 * The Chromium-downgrade guard, for the REAL path (browser-chromium-guard.js): the
 * Restart rebuilds the image, and the rebuilt image installs the Chromium the installed
 * lock pins. A running container whose profile was written by a NEWER Chromium would
 * crash-loop on it, so that restart is never run. Resolves whatever the guard returns.
 */
async function downgradeGuard() {
  const bundleDir = join(CROW_HOME, "bundles", BUNDLE_ID);
  const runner = dockerRunner();
  const ids = await runningBrowserContainerIds({ bundleDir, crowHome: CROW_HOME, runner });
  return restartWouldDowngrade({ bundleDir, ids, runner });
}

/**
 * True when the restart must NOT run. FAIL CLOSED: only an explicit `blocked: false`
 * lets it through, so a guard that throws, or answers nothing usable, refuses.
 */
async function guardBlocksRestart() {
  try {
    const verdict = typeof _depsForTest?.guard === "function" ? await _depsForTest.guard() : await downgradeGuard();
    return verdict?.blocked !== false;
  } catch {
    return true;
  }
}

/** The answer the bound resolves with when the restart outlives it (a distinct sentinel). */
const TIMED_OUT = Symbol("restart-timed-out");

/**
 * The restart, IN PROCESS: the route's own local start with `recreate: true`
 * (routes/bundles.js `restartBundleInProcess`), bounded so a hung build cannot hold the
 * click open. Resolves `{ ok: true }` or `{ ok: false, code?, error? }` — or TIMED_OUT;
 * never throws.
 */
async function restartInProcess(req) {
  const seam = _depsForTest || null;
  const run = typeof seam?.startBundle === "function"
    ? () => seam.startBundle(BUNDLE_ID)
    // The pre-existing seam: a caller that replaces the restart itself, request and all.
    : typeof seam?.restart === "function"
      ? () => seam.restart(BUNDLE_ID, req)
      : async () => {
        // Dynamic on purpose: this module is read by the remedy registry at import,
        // long before any card is clicked, and must not drag express and the DB in.
        const { restartBundleInProcess } = await import("../../routes/bundles.js");
        return restartBundleInProcess(BUNDLE_ID);
      };
  const bound = Number.isFinite(seam?.timeoutMs) && seam.timeoutMs > 0 ? seam.timeoutMs : RESTART_TIMEOUT_MS;
  let timer = null;
  try {
    return await Promise.race([
      (async () => run())(),
      new Promise((resolve) => { timer = setTimeout(() => resolve(TIMED_OUT), bound); }),
    ]);
  } catch (err) {
    return { ok: false, error: err?.message || String(err) };
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

/**
 * The short code a refusal names in the log: the start's own code when it has one,
 * otherwise its error message. The message is collapsed to single spaces (newlines and tabs
 * included) and trimmed BEFORE it is cut to 200 characters, so the code is always ONE line;
 * it never carries a secret or a stack.
 */
function startFailureCode(out) {
  const code = typeof out?.code === "string" ? out.code.trim() : "";
  if (code) return `start_failed:${code}`;
  const message = String(out?.error ?? out?.reason ?? "").replace(/\s+/g, " ").trim();
  return `start_failed:${message ? message.slice(0, 200) : "unknown"}`;
}

/** The ONE warn line every non-success path writes. Never carries a value. */
function warnRestartDidNotRun(code) {
  console.warn(`[fix-it] browser add-on: the restart did not run (${code})`);
}

export default async function restartBrowserAddon(_args, ctx) {
  let owner = false;
  try { owner = await isOwner(ctx?.db, ctx?.req); } catch { owner = false; }
  if (!owner) {
    warnRestartDidNotRun("owner_only");
    return { resolved: false, flash: OWNER_ONLY_FLASH, message: OWNER_ONLY_MESSAGE };
  }

  // Never restart into an older Chromium than the profile holds: that would take the
  // add-on down for good. No new copy — the Nest's generic "couldn't apply" line, and
  // the card stays pending for a later attempt (after a bundle that catches up).
  if (await guardBlocksRestart()) {
    warnRestartDidNotRun("downgrade_guard");
    return { resolved: false };
  }

  const out = await restartInProcess(ctx?.req);
  if (out === TIMED_OUT) {
    // The card stays pending: the owner is told the fix did not run (the Nest's
    // generic line) and can try again, or restart from the Extensions page.
    warnRestartDidNotRun("timeout");
    return { resolved: false };
  }
  if (!out || out.ok !== true) {
    warnRestartDidNotRun(startFailureCode(out));
    return { resolved: false };
  }
  return { resolved: true };
}