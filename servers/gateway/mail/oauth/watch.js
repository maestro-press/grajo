/**
 * Crow Mail's reconnect watch (plan 5, Task 6): the once-a-week reminder, and the words it carries,
 * for a Google sign-in that Google is about to end.
 *
 * A Google Cloud app left in **Testing** issues refresh tokens that expire after seven days
 * (https://developers.google.com/identity/protocols/oauth2 — "Refresh token expiration"), so an
 * account connected with the owner's own, unpublised client stops syncing on its own a week after the
 * grant. Nothing in the mailbox says so: the refresh simply starts answering `invalid_grant`. Crow
 * therefore says it BEFORE that happens — once, five days into the grant, while a sign-in still
 * works — and the settings card shows the same predicate with a one-tap Reconnect.
 *
 * Two facts decide it, both already stored in the grant's label (`oauth/meta.js`):
 *
 * - `provider` — only a Google grant is on this clock. A Microsoft registration has no such expiry,
 *   and a published (production) Google app's refresh tokens keep working: neither is ever prompted.
 * - `publishing` — `testing` (the owner said so), or `unknown` (Crow was not told; the honest reading
 *   is "it may be testing", and a prompt that turns out unnecessary costs one sign-in, while a missed
 *   one costs a week of silent mail).
 *
 * `grantedAt` is the other half: due means "older than `REAUTH_WARN_AFTER_MS`", so reconnecting (which
 * records a NEW `grantedAt`) re-arms the reminder for the next grant and nothing else has to be reset.
 * There is no upper bound on purpose — after seven days the token really has lapsed, and the prompt is
 * more true then, not less; it stops existing the moment the account is reconnected.
 *
 * **One bell per grant.** The tick runs every minute on the gateway's existing scheduler
 * (`servers/gateway/scheduler-hooks.js`), so the reminder is gated twice: the predicate (once the
 * grant is five days old, every tick matches) and a persisted record of which grant was already rung
 * for. That record is ONE local-scope dashboard setting — `mail_oauth_reconnect_rung`, a JSON object
 * keyed by account id whose value is the `grantedAt` it rang for — deliberately NOT a new field in
 * `mail_oauth_meta`: that map is documented as the grant's four provider-supplied facts, and a
 * "we already said this" stamp is Crow's own bookkeeping, per instance, never a property of the grant.
 * Local scope means it never travels to a paired peer, and it survives a restart, so a box that
 * restarts every night does not ring the same reminder every morning. A `createNotification` that
 * returns null (the owner has that notification type switched off) is tolerated and recorded like any
 * other: the bell is a courtesy, the card still carries the same sentence and the same button.
 *
 * The watch writes nothing else: it never marks an account, never touches a mail row and never asks the
 * keychain for anything. Its bell carries no address, no subject and no body — the approved title alone
 * (C27) — and its action link is the settings page the Reconnect button lives on.
 */
import { registerSchedulerHook, unregisterSchedulerHook } from "../../scheduler-hooks.js";
import { readSetting, writeSetting } from "../../dashboard/settings/registry.js";
import { createNotification } from "../../../shared/notifications.js";
import { MailError } from "../errors.js";
import { listAccounts } from "../store/accounts.js";
import { getOauthMeta } from "./meta.js";

/** The one id this hook registers under on the gateway's scheduler. */
export const MAIL_OAUTH_WATCH_HOOK_ID = "mail-oauth-watch";

/**
 * A Testing-mode Google refresh token lives seven days. Crow speaks up after five, which leaves two
 * days for a sign-in that needs a browser, a password and a provider page.
 */
export const TESTING_TOKEN_LIFE_MS = 7 * 24 * 3600 * 1000;
export const REAUTH_WARN_AFTER_MS = 5 * 24 * 3600 * 1000;

/** The local-scope setting that remembers which grant was already rung for (never synced). */
export const MAIL_OAUTH_WATCH_SETTING = "mail_oauth_reconnect_rung";

/**
 * The bell's title: the operator-approved copy (C27), English — a notification is stored and pushed in
 * one language, and the approved file's `en` row is what it carries.
 */
export const REAUTH_BELL_TITLE = "Reconnect Gmail to keep mail syncing";

/**
 * The sentence the sync supervisor's auth_failed notice carries for an XOAUTH2 account (the approved
 * file's C29), replacing the password sentence: an OAuth sign-in that stopped working is fixed by
 * signing in again, not by typing a password. It names no address and no password.
 */
export const OAUTH_SIGN_IN_STOPPED_TEXT = "The sign-in for this account stopped working. Reconnect to keep mail syncing.";

/** Where the bell's link lands: the settings page, whose account card carries the Reconnect button. */
export const MAIL_SETTINGS_VIEW_HREF = "/dashboard/mail?view=settings";

/**
 * The two provider words an account row and an OAuth grant may carry, mapped to `oauth/flow.js`'s own
 * provider names. An account row stores the PRESET id (`gmail`, `outlook`); a grant's meta stores the
 * provider (`google`, `microsoft`). Anything else is not a provider this watch knows.
 */
const PROVIDER_OF_PRESET = Object.freeze({
  gmail: "google",
  google: "google",
  outlook: "microsoft",
  microsoft: "microsoft",
});

/** The provider a stored account row signs in with, or null. */
export function oauthProviderOf(presetId) {
  if (typeof presetId !== "string") return null;
  const key = presetId.trim().toLowerCase();
  return Object.hasOwn(PROVIDER_OF_PRESET, key) ? PROVIDER_OF_PRESET[key] : null;
}

/**
 * Whether this grant's sign-in should be prompted about now: a Google grant whose app is in Testing
 * (or was not told), older than `REAUTH_WARN_AFTER_MS`. A production Google app, a Microsoft grant,
 * a grant with no timestamp and no grant at all are all false. `now` is a clock or a number.
 *
 * @param {{grantedAt?: number|null, publishing?: string, provider?: string|null}|null} meta
 * @param {number|(() => number)} [now]
 * @returns {boolean}
 */
export function dueForReconnect(meta, now = Date.now) {
  if (meta == null || typeof meta !== "object" || Array.isArray(meta)) return false;
  const provider = typeof meta.provider === "string" ? meta.provider.trim().toLowerCase() : "";
  if (provider !== "google") return false;
  const publishing = typeof meta.publishing === "string" ? meta.publishing.trim().toLowerCase() : "unknown";
  if (publishing !== "testing" && publishing !== "unknown") return false;
  if (!Number.isInteger(meta.grantedAt) || meta.grantedAt < 0) return false;
  let at;
  try {
    at = Number(typeof now === "function" ? now() : now);
  } catch {
    return false;
  }
  if (!Number.isFinite(at)) return false;
  return at - meta.grantedAt >= REAUTH_WARN_AFTER_MS;
}

/** The stored "already rung for this grant" map; an unreadable one reads as empty, never as a fault. */
async function readRung(db) {
  let raw = null;
  try {
    raw = await readSetting(db, MAIL_OAUTH_WATCH_SETTING);
  } catch {
    return {};
  }
  if (typeof raw !== "string" || raw === "") return {};
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const out = {};
  for (const [id, grantedAt] of Object.entries(parsed)) {
    if (Number.isInteger(grantedAt) && grantedAt >= 0) out[id] = grantedAt;
  }
  return out;
}

/**
 * One pass over every account: ring the bell for each due grant that has not been rung for yet, and
 * record the grant it rang for. Returns the count, so a caller (or a log line) can say what happened.
 *
 * The record is written only AFTER the bell was written: a `createNotification` that throws is retried
 * on the next tick rather than being swallowed for a week. A null answer (that notification type is
 * switched off) is a delivered decision, and is recorded like one.
 *
 * @param {object} db
 * @param {{now?: number|(() => number), createNotification?: Function}} [deps]
 * @returns {Promise<{reminders: number}>}
 */
export async function sweepReconnects(db, deps = {}) {
  const clock = typeof deps.now === "function" || typeof deps.now === "number" ? deps.now : Date.now;
  const read = Number(typeof clock === "function" ? clock() : clock);
  const at = Number.isFinite(read) ? Math.floor(read) : Date.now();
  const ring = typeof deps.createNotification === "function" ? deps.createNotification : createNotification;

  const rung = await readRung(db);
  const accounts = await listAccounts(db);
  let reminders = 0;

  for (const account of accounts) {
    if (account?.authKind !== "xoauth2") continue;
    // Another live Crow instance holds this address: its grant, its reminder.
    if (account.status === "claimed_elsewhere") continue;
    let meta;
    try {
      meta = await getOauthMeta(db, account.id);
    } catch (err) {
      // A label that cannot be read is not a reason to ring for the wrong account, nor to stop the
      // others: the next tick reads it again.
      if (err instanceof MailError) continue;
      throw err;
    }
    if (!dueForReconnect(meta, at)) continue;
    if (rung[account.id] === meta.grantedAt) continue;

    await ring(db, {
      title: REAUTH_BELL_TITLE,
      body: null,
      type: "system",
      source: "mail",
      priority: "normal",
      action_url: MAIL_SETTINGS_VIEW_HREF,
      metadata: { mailOauthReconnect: { accountId: account.id, grantedAt: meta.grantedAt } },
    });

    rung[account.id] = meta.grantedAt;
    await writeSetting(db, MAIL_OAUTH_WATCH_SETTING, JSON.stringify(rung), { scope: "local" });
    reminders += 1;
  }

  return { reminders };
}

/** The code a failure is reported as: a MailError's own, or `unknown` for anything else. */
function codeOf(err) {
  return err instanceof MailError ? err.code : "unknown";
}

/**
 * Register the reconnect tick on the gateway's scheduler. Registered by the mail boot
 * (`boot/mail-boot.js`) beside the mail-send hook, and only when `mailEnabled()`: a gateway that never
 * turned mail on registers nothing and never looks at a mail account.
 *
 * A sweep that throws is caught here, not left to the scheduler: a database client's error text can
 * quote a statement or a bound value, and none of that belongs in a log. The line names the event and a
 * code only, and the next tick tries again.
 *
 * @param {object} db the gateway's crow.db client
 * @param {{now?: Function, createNotification?: Function}} [deps] the test seam
 * @returns {{unregister: () => void}} the hook's own way out; idempotent
 */
export function registerOauthWatchHook(db, deps = {}) {
  if (db == null || typeof db.execute !== "function") {
    throw new TypeError("registerOauthWatchHook needs a db client");
  }
  registerSchedulerHook(MAIL_OAUTH_WATCH_HOOK_ID, {
    /** One sweep: its count on success, null when it failed (the failure is only ever a code). */
    async tick() {
      try {
        return await sweepReconnects(db, deps);
      } catch (err) {
        console.warn(`[mail-oauth-watch] sweep_failed ${codeOf(err)}`);
        return null;
      }
    },
  });
  return {
    unregister() {
      unregisterSchedulerHook(MAIL_OAUTH_WATCH_HOOK_ID);
    },
  };
}

export default registerOauthWatchHook;