/**
 * Instant Fix-it remedy (OWNER ONLY): restart the browser add-on, which is what
 * rebuilds its container image from the files Crow just installed.
 *
 * The card exists because a bundle refresh copies new files into
 * ~/.crow/bundles/<id>/ but never rebuilds or restarts a running container
 * (routes/bundles.js: "No automatic rebuild: Extensions Restart/Start runs
 * `up -d --build`"). So this action must run exactly that: the SAME path the
 * Restart button on an Extensions card runs, not a new docker call of our own.
 * That path is POST /dashboard/bundles/api/start with `{bundle_id, recreate:true}`
 * (routes/bundles.js `dispatchBundleAction`: ownership check → the consent +
 * compose safety check on what Compose will apply NOW → `up -d --build
 * --force-recreate` → the post-restart re-check of the boot detectors).
 *
 * `recreateBundleGuarded` is NOT that path: it runs `up -d --force-recreate`
 * without `--build`, so it re-creates the container from the image that is
 * already on disk — the old one — which is precisely what this card is about.
 *
 * The route is not exported as a callable function (only its HTTP route is), so
 * this remedy posts to this gateway's OWN route on loopback, carrying the
 * owner's own session cookie and CSRF token straight from the dashboard request
 * that clicked the button. Nothing is loosened by that: the request carries the
 * owner's own authority into a route that re-runs every guard itself, and the
 * owner-only rule below is checked first (the same rule the compose restore
 * uses: a local password session on this machine, never a peer sign-in).
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
 * All user-facing strings for the card live in the detector's ONE copy object
 * (fix-it/detectors/browser-image-stale.js, COPY). Copy approved by the operator
 * 2026-11-19. This file adds none: a refusal reuses the compose restore's owner-only flash,
 * and a restart that did not run falls back to the Nest's generic "Couldn't
 * apply that fix" line rather than inventing a second sentence here.
 */
import { join } from "node:path";
import { gatewayBackendPort } from "../../instance-registry.js";
import { gatewayListenHost } from "../../listen-host.js";
import { isLocalPasswordSessionOn } from "../../dashboard/local-session.js";
import { CROW_HOME } from "../../bundles-config.js";
import { dockerRunner } from "../../bundle-core.js";
import { restartWouldDowngrade, runningBrowserContainerIds } from "../browser-chromium-guard.js";
import { OWNER_ONLY_FLASH, OWNER_ONLY_MESSAGE } from "./restore-bundle-compose.js";

export const ACTION_ID = "restart-browser-addon";
/** The ONE bundle this card is about — held here, never read from the stored card. */
export const BUNDLE_ID = "browser";
/** The Extensions route the Restart button calls (routes/bundles.js, `/dashboard` mount). */
export const START_ROUTE = "/dashboard/bundles/api/start";
/**
 * A first build of this image pulls Playwright's Chromium and takes minutes; a
 * rebuild after a bundle refresh only re-runs the last COPY layers. The bound
 * exists so a hung build cannot hold the click open forever.
 */
export const RESTART_TIMEOUT_MS = 15 * 60 * 1000;

// Test-only: replace the owner rule, the Chromium-downgrade guard and the restart itself.
// None of them ever reaches docker or the network in a test.
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

/** Where to dial this gateway's own HTTP listener: loopback for a wildcard bind. */
function selfOrigin() {
  const host = gatewayListenHost();
  const dial = host === "0.0.0.0" || host === "::" || host === "" ? "127.0.0.1" : host;
  const isIpv6 = dial.includes(":") && !dial.startsWith("[");
  return `http://${isIpv6 ? `[${dial}]` : dial}:${gatewayBackendPort()}`;
}

/**
 * The default restart: POST the owner's own request to the Extensions route.
 * Resolves `{ ok, reason }`; never throws.
 */
async function restartThroughExtensionsRoute(req) {
  if (typeof _depsForTest?.restart === "function") return _depsForTest.restart(BUNDLE_ID, req);
  const cookie = typeof req?.headers?.cookie === "string" ? req.headers.cookie : "";
  // csrfMiddleware puts the crow_csrf cookie on the request; the route's own
  // double-submit check wants it echoed (the button's form sends `_csrf`).
  const csrf = typeof req?.csrfToken === "string" ? req.csrfToken : "";
  if (!cookie) return { ok: false, reason: "no dashboard session to carry to the Extensions route" };
  let res;
  try {
    res = await fetch(`${selfOrigin()}${START_ROUTE}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        cookie,
        ...(csrf ? { "x-crow-csrf": csrf } : {}),
      },
      body: JSON.stringify({ bundle_id: BUNDLE_ID, recreate: true }),
      // A refusal (an expired session) must not be followed to the login page and
      // read as an answer: this route answers JSON or nothing we can use.
      redirect: "manual",
      signal: AbortSignal.timeout(RESTART_TIMEOUT_MS),
    });
  } catch (err) {
    return { ok: false, reason: err?.message || String(err) };
  }
  let body = null;
  try { body = await res.json(); } catch { /* a non-JSON answer is a refusal we cannot read */ }
  if (res.ok && body?.ok === true) return { ok: true };
  return { ok: false, reason: String(body?.error || `HTTP ${res.status}`).trim() };
}

export default async function restartBrowserAddon(_args, ctx) {
  let owner = false;
  try { owner = await isOwner(ctx?.db, ctx?.req); } catch { owner = false; }
  if (!owner) return { resolved: false, flash: OWNER_ONLY_FLASH, message: OWNER_ONLY_MESSAGE };

  // Never restart into an older Chromium than the profile holds: that would take the
  // add-on down for good. No new copy — the Nest's generic "couldn't apply" line, and
  // the card stays pending for a later attempt (after a bundle that catches up).
  if (await guardBlocksRestart()) {
    console.warn("[fix-it] browser add-on: the restart did not run — a rebuild could install an older Chromium than the profile holds");
    return { resolved: false };
  }

  let out;
  try {
    out = await restartThroughExtensionsRoute(ctx?.req);
  } catch (err) {
    out = { ok: false, reason: err?.message || String(err) };
  }
  if (!out || out.ok !== true) {
    // The card stays pending: the owner is told the fix did not run (the Nest's
    // generic line) and can try again, or restart from the Extensions page.
    console.warn(`[fix-it] browser add-on: the restart did not run — ${out?.reason || "unknown"}`);
    return { resolved: false };
  }
  return { resolved: true };
}