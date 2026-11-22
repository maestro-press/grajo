/**
 * Where a Fix-it click sends the owner back, and the flash the next page draws.
 *
 * A POST /dashboard/fix-it/action (and the Nest's "run backup now" form) answers
 * with a redirect carrying a flash code. This module is the ONE place that knows
 *
 *   - the two places such a click may land (RETURN_TARGETS): the classic Nest and
 *     the shell's Attention sheet. The body field `return` is the only
 *     client-supplied value in the redirect, so it can never name a path: it
 *     selects between these two and nothing else (returnTargetOf).
 *   - the flash codes the destination page accepts (FLASH_CODES), the tone each
 *     one is drawn in, and its text, from the dashboard's i18n table
 *     (flashBanner). Both renderers — nest/html.js's health strip and the shell's
 *     Attention sheet — draw the same banner object, so they cannot disagree.
 *   - the two query parameters a flash may carry besides its code (`&addon=<id>`
 *     for the unwall flash, `&key=<KEY>` for a compose that needs a key set
 *     first), re-checked here because they travel in a URL.
 *
 * No value read from a request ever reaches the built URL unchecked: the target
 * comes from RETURN_TARGETS, the code from FLASH_CODES, and the two parameters
 * from their own patterns.
 */
import { t } from "../dashboard/shared/i18n.js";
import {
  FLASH_ID_RE,
  STALE_FLASH,
  UNWALLED_FLASH,
  unwalledMessageFor,
} from "./remedies/addon-unwall.js";
import {
  ALREADY_RESTARTING_FLASH,
  FLASH_KEY_RE,
  NEEDS_KEY_FLASH,
  OWNER_ONLY_FLASH,
  needsKeyMessage,
} from "./remedies/restore-bundle-compose.js";
import {
  FLASH as RETIRED_REMOVED_FLASH,
  STARTED_FLASH as RETIRED_REMOVING_FLASH,
} from "./remedies/remove-retired-bundle.js";

/**
 * The Nest's own path. Spelled in two pieces on purpose: a bare `/dashboard/nest`
 * URL is a LANDING in the new shell (it answers 303 to Chat), so a link that means
 * the classic Nest has to carry a query — the redirects built below do, and this
 * constant stays the base they are built on.
 */
const NEST_PATH = "/dashboard" + "/nest";

/**
 * The two places a Fix-it click may return to. Frozen: a request may pick an
 * entry, never add one.
 */
export const RETURN_TARGETS = Object.freeze({
  nest: NEST_PATH,
  sheet: "/dashboard/perch?sheet=attention",
});

/**
 * The one accepted value of the body's `return` field. Everything else — a
 * missing field, "nest", "SHEET", a dashboard path, an absolute URL, a protocol,
 * an array, an object — means the Nest, so a redirect never leaves the dashboard
 * and never names a client-supplied path.
 */
export function returnTargetOf(value) {
  return value === "sheet" ? "sheet" : "nest";
}

/**
 * Every flash the Nest's health strip accepts — the codes the Fix-it remedies and
 * the backup form already sent, plus `fixit_done` (a remedy that resolved and
 * changed no sharing). A code outside this list never reaches a URL or a banner.
 */
export const FLASH_CODES = Object.freeze([
  "backup_ok",
  "backup_fail",
  "fixit_fixed",
  "fixit_dismissed",
  "fixit_error",
  "fixit_not_pending",
  STALE_FLASH,
  UNWALLED_FLASH,
  OWNER_ONLY_FLASH,
  ALREADY_RESTARTING_FLASH,
  NEEDS_KEY_FLASH,
  RETIRED_REMOVED_FLASH,
  RETIRED_REMOVING_FLASH,
  "fixit_done",
]);

/**
 * The query parameter a flash may carry besides its code, re-checked here because
 * it is rendered on the next page. A parameter that belongs to another flash is
 * never added.
 */
function flashParamQuery(flash, params) {
  if (flash === UNWALLED_FLASH) {
    const id = params && typeof params.addon === "string" ? params.addon : "";
    return FLASH_ID_RE.test(id) ? `&addon=${encodeURIComponent(id)}` : "";
  }
  if (flash === NEEDS_KEY_FLASH) {
    const key = params && typeof params.key === "string" ? params.key : "";
    return FLASH_KEY_RE.test(key) ? `&key=${encodeURIComponent(key)}` : "";
  }
  return "";
}

/**
 * The redirect URL for one outcome, built from the two code-held targets only.
 * An unknown flash degrades to `fixit_error`; an unknown target to the Nest.
 *
 * @param {"nest"|"sheet"|string|undefined} target  from returnTargetOf()
 * @param {string} flash  a FLASH_CODES member
 * @param {{addon?: string, key?: string}} [params]
 */
export function returnUrl(target, flash, params) {
  const code = FLASH_CODES.includes(flash) ? flash : "fixit_error";
  const extra = flashParamQuery(code, params);
  return returnTargetOf(target) === "sheet"
    ? `${RETURN_TARGETS.sheet}&flash=${code}${extra}`
    : `${RETURN_TARGETS.nest}?flash=${code}${extra}`;
}

/**
 * The flash state a page's query string asks for: the code only when it is one of
 * FLASH_CODES, and the two parameters only when they are strings. The renderers
 * re-check the parameters themselves (the message helpers), exactly as the Nest
 * always did.
 *
 * @param {object|null|undefined} query  e.g. req.query
 * @returns {{flash: string|null, addon: string|null, key: string|null}}
 */
export function parseFlashQuery(query) {
  const q = query && typeof query === "object" ? query : {};
  return {
    flash: typeof q.flash === "string" && FLASH_CODES.includes(q.flash) ? q.flash : null,
    addon: typeof q.addon === "string" ? q.addon : null,
    key: typeof q.key === "string" ? q.key : null,
  };
}

/**
 * The banner one flash code draws: its tone and its text, or null for a code the
 * Nest does not know (the page then shows no banner at all).
 *
 *   success  `nest-flash--success` / `shell-attn-flash--success`
 *   error    `nest-flash--error`   / `shell-attn-flash--error`
 *   info     no modifier class     / `shell-attn-flash--info`
 *
 * The text is plain (the renderers escape it), and the two parameterised lines —
 * the add-on a flash may name and the key a compose needs — fall back to their
 * generic wording when the value does not pass its check.
 *
 * @param {string|null|undefined} flash
 * @param {string} [lang]
 * @param {{addon?: string|null, key?: string|null}} [params]
 * @returns {{tone: "success"|"error"|"info", text: string}|null}
 */
export function flashBanner(flash, lang = "en", { addon = null, key = null } = {}) {
  const language = lang === "es" ? "es" : "en";
  switch (flash) {
    case "backup_ok":
      return { tone: "success", text: t("health.backupDone", language) };
    case "backup_fail":
      return { tone: "error", text: t("health.backupFailed", language) };
    case "fixit_fixed":
      return { tone: "success", text: t("fixit.flash.fixed", language) };
    case "fixit_done":
      return { tone: "success", text: t("fixit.flash.done", language) };
    case "fixit_dismissed":
      return { tone: "success", text: t("fixit.flash.dismissed", language) };
    case "fixit_retired_removed":
      return { tone: "success", text: t("health.retiredRemoved", language) };
    // Started, not done: no success styling, and no claim that anything was removed yet.
    case "fixit_retired_removing":
      return { tone: "info", text: t("health.retiredRemoving", language) };
    case "fixit_error":
      return { tone: "error", text: t("fixit.flash.error", language) };
    case "fixit_not_pending":
      return { tone: "error", text: t("fixit.flash.notPending", language) };
    case UNWALLED_FLASH:
      return { tone: "success", text: unwalledMessageFor(addon, language) };
    case STALE_FLASH:
      return { tone: "error", text: t("fixit.addonWall.stale", language) };
    case OWNER_ONLY_FLASH:
      return { tone: "error", text: t("fixit.flash.ownerOnly", language) };
    // Not a failure: the start the owner asked for is already running.
    case ALREADY_RESTARTING_FLASH:
      return { tone: "info", text: t("fixit.flash.alreadyRestarting", language) };
    case NEEDS_KEY_FLASH:
      return { tone: "error", text: needsKeyMessage(key, language) };
    default:
      return null;
  }
}