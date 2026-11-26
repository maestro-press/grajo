/**
 * storage-shared-alert — the once-a-day owner alert for credentials that stopped opening.
 *
 * A reader that cannot open a `storage.shared.*` credential classifies it:
 *   `storage_credentials_unbound`  — a bound value that does not open for THIS key, endpoint and
 *                                    SSL flag (a swap, or a bot re-pointing the endpoint);
 *   `storage_credentials_pre_era`  — an old-style or plaintext value after the instance's era.
 * Storage then stops (the readers fail closed) and this module makes sure the owner HEARS about
 * it: one spool file per UTC day per instance through `writeAlertFile`, which the gateway turns
 * into one bell at boot (servers/gateway/boot/post-listen.js).
 *
 * NO NEW WORDS. The alert uses the spool's default title and carries no body: its explanatory
 * sentence waits for the owner's copy pass. The file name carries a stable code and the day, and
 * the file name IS the dedupe key, so a second refusal the same day (in any process) finds the
 * file and does nothing. Nothing here ever logs or writes a value, plaintext, endpoint or blob.
 *
 * A BOT CHILD never writes the spool: a process that carries the host-storage marker
 * (`CROW_STORAGE_FROM_HOST`) is a contained bot's MCP child, whose reads come from its own scoped
 * key and which has no business spooling anything. It logs one value-free line instead.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { alertsDirs, writeAlertFile } from "./alert-spool.js";

/** The stable code in the spool file's name (and the notification's metadata). */
export const STORAGE_ALERT_CODE = "storage_credentials_unbound";
/** The reasons that ring it. */
export const STORAGE_ALERT_REASONS = Object.freeze(["storage_credentials_unbound", "storage_credentials_pre_era"]);

const loggedDays = new Set();

/** Test seam: forget which days this process already logged. */
export function _resetStorageAlertForTest() {
  loggedDays.clear();
}

/** `YYYY-MM-DDT00:00:00.000Z` of the UTC day containing `now`: the one stamp a day's alert carries. */
function dayStamp(now) {
  const d = now instanceof Date ? now : new Date();
  return `${d.toISOString().slice(0, 10)}T00:00:00.000Z`;
}

/** The spool file name `writeAlertFile` derives from a stamp and the code (same rule as there). */
function alertFileName(at) {
  const stamp = String(at).replace(/[:.]/g, "-");
  const slug = STORAGE_ALERT_CODE.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
  return `${stamp}-${slug}.json`;
}

/**
 * Ring the owner bell once per UTC day for a refused credential. Only the two reasons above ring;
 * anything else is ignored. Never throws.
 *
 * @param {string} reason
 * @param {{now?: Date}} [opts]
 * @returns {"rang"|"already"|"log-only"|"ignored"|"failed"}
 */
export function noteStorageCredentialRefusal(reason, { now = new Date() } = {}) {
  try {
    if (!STORAGE_ALERT_REASONS.includes(reason)) return "ignored";
    const at = dayStamp(now);
    const day = at.slice(0, 10);
    const first = !loggedDays.has(`${day}:${reason}`);
    loggedDays.add(`${day}:${reason}`);

    // A bot child (or any hydrated process) logs only: it must not write the host's spool.
    if (process.env.CROW_STORAGE_FROM_HOST !== undefined) {
      if (first) console.warn(`[storage] shared credentials refused (${reason}); not spooling an alert from a bot child`);
      return "log-only";
    }

    const name = alertFileName(at);
    const dirs = alertsDirs();
    for (const dir of [dirs.pending, dirs.delivered, dirs.bad]) {
      if (existsSync(join(dir, name))) return "already";
    }
    // Default title ("Crow alert"), no body: nothing but the code and the day.
    const written = writeAlertFile({ code: STORAGE_ALERT_CODE, at });
    if (written) {
      console.warn(`[storage] shared credentials refused (${reason}); owner alert spooled`);
      return "rang";
    }
    if (first) console.warn(`[storage] shared credentials refused (${reason}); the owner alert could not be spooled`);
    return "failed";
  } catch {
    return "failed";
  }
}
