/**
 * The core bot doors' rollout switch (design D2): a leaf module, no imports, so both the gateway's
 * door guard (servers/gateway/core-bot-doors.js) and the bot catalog
 * (scripts/pi-bots/crow-server-catalog.mjs, which runs in bot-host processes too) read ONE rule.
 *
 * Two halves, BOTH required before a bot's `crow-memory` / `crow-projects` selection becomes the
 * HTTP door blocks instead of stdio children:
 *
 *   1. the process env `CROW_BOT_CORE_DOORS` is on ("1", "true", "on" or "yes"; off when unset) —
 *      the instance-wide flag, off by default;
 *   2. the bot's definition carries `core_doors: true` — the per-bot canary. The definition is
 *      MAC'd (servers/shared/bot-def-mac.js), so only the owner's own writes can set it, and the
 *      door re-reads it from the VERIFIED definition before it admits a call.
 *
 * Either half off: behaviour is exactly what it was (stdio).
 */

/** The env name of the instance-wide flag. */
export const CORE_DOORS_ENV = "CROW_BOT_CORE_DOORS";

/** The per-bot opt-in, a top-level field of the bot definition. */
export const CORE_DOORS_DEF_KEY = "core_doors";

/** Is the instance-wide flag on in this env? Off for anything but an explicit yes. */
export function coreDoorsFlagOn(env = process.env) {
  const raw = env && typeof env === "object" ? env[CORE_DOORS_ENV] : undefined;
  if (typeof raw !== "string") return false;
  return ["1", "true", "on", "yes"].includes(raw.trim().toLowerCase());
}

/** Does this definition opt the bot in? Strictly the boolean `true`. */
export function defOptsIntoCoreDoors(def) {
  return !!(def && typeof def === "object" && !Array.isArray(def) && def[CORE_DOORS_DEF_KEY] === true);
}

/** Both halves: the flag is on AND the definition opted in. */
export function coreDoorsRequested(def, env = process.env) {
  return coreDoorsFlagOn(env) && defOptsIntoCoreDoors(def);
}
