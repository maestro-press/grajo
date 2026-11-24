/**
 * Web Push — VAPID-based push notification sender
 *
 * Requires VAPID_PUBLIC_KEY + VAPID_PRIVATE_KEY env vars.
 * Generate keys: npx web-push generate-vapid-keys
 */

import webpush from "web-push";
import { t, SUPPORTED_LANGS } from "../dashboard/shared/i18n.js";
import { readSetting } from "../dashboard/settings/registry.js";

let configured = false;

/**
 * Initialize VAPID credentials for web push.
 * Called once on gateway startup.
 */
export function initWebPush() {
  const publicKey = process.env.VAPID_PUBLIC_KEY;
  const privateKey = process.env.VAPID_PRIVATE_KEY;
  const email = process.env.VAPID_EMAIL || "mailto:admin@localhost";

  if (!publicKey || !privateKey) {
    console.log("[web-push] VAPID keys not configured — push notifications disabled");
    return;
  }

  webpush.setVapidDetails(email, publicKey, privateKey);
  configured = true;
  console.log("[web-push] VAPID configured — push notifications enabled");
}

/**
 * Send a push notification to all registered subscriptions.
 *
 * @param {object} db - Database client
 * @param {object} payload
 * @param {string} payload.title - Notification title
 * @param {string} [payload.body] - Notification body text
 * @param {string} [payload.url] - Action URL on click
 * @param {number|null} [payload.id] - The notification row id (a fired recurring reminder only)
 * @param {boolean} [payload.recurring] - true only for a fired recurring reminder
 */
export async function sendPushToAll(db, { title, body, url, id = null, recurring = false }) {
  if (!configured) return;

  let rows;
  try {
    const result = await db.execute("SELECT endpoint, keys_json FROM push_subscriptions");
    rows = result.rows;
  } catch {
    // Table may not exist yet
    return;
  }

  // Bound each send (2c follow-up F2/C2a): createNotification awaits this
  // fan-out from the instance-sync apply path — an unbounded hang on a
  // half-open endpoint wedges boot or the live apply loop. `timeout` is a
  // socket-idle timeout in ms (web-push@3.6.7); a timed-out send rejects
  // into the same per-endpoint catch as any other failed send. The sends
  // run in parallel (Promise.allSettled) so N bad endpoints cost ~one cap,
  // not N×cap; push has no cross-endpoint ordering semantics, and the
  // per-endpoint try/catch keeps the 410/404 prune and last_seen
  // bookkeeping per-endpoint exactly as the serial loop did.
  const timeoutMs = parseInt(process.env.CROW_PUSH_SEND_TIMEOUT_MS, 10) || 10_000;
  // The stop action's words, in the owner's dashboard language (resolved ONCE per fan-out):
  // a service worker has no i18n module, so it can only show the label the payload carries.
  const words = await reminderWords(db, { id, recurring });
  const payload = pushPayload({ title, body, url, id, recurring, words });
  await Promise.allSettled(
    rows.map(async (row) => {
      const subscription = {
        endpoint: row.endpoint,
        keys: JSON.parse(row.keys_json),
      };
      try {
        await webpush.sendNotification(
          subscription,
          JSON.stringify(payload),
          { timeout: timeoutMs }
        );
        // Update last_seen
        await db.execute({
          sql: "UPDATE push_subscriptions SET last_seen = datetime('now') WHERE endpoint = ?",
          args: [row.endpoint],
        });
      } catch (err) {
        if (err.statusCode === 410 || err.statusCode === 404) {
          // Stale subscription — auto-remove
          await db.execute({
            sql: "DELETE FROM push_subscriptions WHERE endpoint = ?",
            args: [row.endpoint],
          });
        }
      }
    })
  );
}

/** The dashboard's language, "en" when the setting is unset, unknown or unreadable. */
async function pushLang(db) {
  try {
    const lang = await readSetting(db, "language");
    return SUPPORTED_LANGS.includes(lang) ? lang : "en";
  } catch {
    return "en";
  }
}

/**
 * The "Stop reminding" action's words (R2) and the after-stop notice (R4), resolved
 * server-side from the owner's dashboard language setting. `null` for every notification
 * that is not a fired recurring reminder with a usable id: its payload gains nothing.
 */
async function reminderWords(db, { id, recurring }) {
  const n = Number(id);
  if (recurring !== true || !Number.isInteger(n) || n <= 0) return null;
  try {
    const lang = await pushLang(db);
    return { stopLabel: t("notif.reminderStop", lang), stoppedText: t("notif.reminderStoppedToast", lang) };
  } catch {
    return null; // no i18n: the push goes out as today's, without the action
  }
}

/**
 * The JSON a push carries. `title` / `body` / `url` are exactly today's shape; a fired
 * recurring reminder adds `id` + `recurring` + the two action words, which the service
 * worker (`public/sw.js`) uses for its "Stop reminding" action and the notice it shows
 * afterwards. Never a token or anything secret: the action fetches the CSRF token itself
 * (GET /dashboard/csrf) when it is tapped. Exported for its own test.
 *
 * @param {object} input
 * @param {object|null} [input.words] reminderWords()'s answer
 * @returns {object}
 */
export function pushPayload({ title, body, url, id = null, recurring = false, words = null }) {
  const payload = { title, body: body || title, url: url || "/dashboard" };
  const n = Number(id);
  if (words && recurring === true && Number.isInteger(n) && n > 0) {
    payload.id = n;
    payload.recurring = true;
    payload.stopLabel = words.stopLabel;
    payload.stoppedText = words.stoppedText;
  }
  return payload;
}

/**
 * Get the VAPID public key for client-side subscription.
 * @returns {string|null}
 */
export function getVapidPublicKey() {
  return process.env.VAPID_PUBLIC_KEY || null;
}
