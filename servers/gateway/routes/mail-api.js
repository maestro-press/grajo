/**
 * Crow Mail's private JSON API: `/dashboard/mail/api`, owner-only, never via Funnel, and a 404 for
 * every route while `CROW_MAIL` is unset.
 *
 * Every request passes the same chain, in this order, and each step refuses before the next can read
 * anything:
 *
 *   1. `dashboardAuth` on this router's own prefix, so the API is closed wherever it is mounted.
 *   2. `Cache-Control: no-store` — a mailbox list or an address must not sit in a cache.
 *   3. the flag: `mailEnabled()` false answers 404 `{error:"not_found"}`, the same answer for every
 *      route, before a database client is opened.
 *   4. the owner: `isLocalPasswordSessionOn` (this machine's own password sign-in, from the owner's
 *      client). A peer's single-sign-on session, a session minted by a login on this machine, a
 *      signed peer call and this machine's own console all get 403 `{error:"owner_only"}` with no
 *      data; no row is read before the verdict.
 *   5. this router's own `express.json({limit:"64kb"})`: a bigger body is 413 `{error:"too_large"}` and
 *      a malformed one 400 `{error:"bad_input"}`, from here rather than from the gateway's global 1mb
 *      parser (the path is in `servers/gateway/index.js`'s `_hasOwnParser`, so the global parser never
 *      sees a mail body first).
 *
 * Errors are JSON `{error, message}`. A mail failure carries its MailError code and the fixed sentence
 * from `MAIL_ERROR_TEXT`; the request-shape answers carry the codes the plan names (`not_found`,
 * `owner_only`, `too_large`, `bad_input`, `duplicate_address`). A library's `message`, a server's reply,
 * a password and a username never reach a response or a log line: a failed route logs its code only.
 *
 * CSRF is the dashboard's `csrfMiddleware`, which already guards every unsafe method on this mount, so
 * no route here handles a token itself.
 *
 * Dependencies arrive two ways, and a test may use either: through `deps`, or from the module-level set
 * `setMailApiRuntime({supervisor, adapterFactory})` makes when boot starts the supervisor (Task 21's
 * boot; `clearMailApiRuntime()` for tests and shutdown). What is absent falls back to the real thing:
 * a fresh `createDbClient()` per request closed in `finally`, `createMailCredentials({db})`, the real
 * IMAP/SMTP adapter factory, and this instance's own id and registry name. A route that needs a
 * supervisor skips it when none is set (a manual sync answers "not started", a connect stores the
 * account and starts no background sync) — it never throws because sync is not running.
 */
import { Router, json as jsonParserOf } from "express";
import { createDbClient } from "../../db.js";
import { recordServiceSecretValues } from "../../shared/secret-values.js";
import { withoutWriteContext } from "../../shared/history/write-context.js";
import { isLocalPasswordSessionOn } from "../dashboard/local-session.js";
import { createImapSmtpAdapter } from "../mail/adapter/imap-smtp.js";
import { accountsOverview } from "../mail/accounts-overview.js";
import {
  claimsFor,
  connectAccount,
  credentialsFor,
  isDuplicateAddress,
  localInstanceFor,
  logCode,
  startBackgroundSync,
} from "../mail/accounts/connect.js";
import { claimedElsewhereSentence } from "../mail/claims.js";
import { createRotationWriter } from "../mail/credentials.js";
import { MailError, MAIL_ERROR_TEXT } from "../mail/errors.js";
import { mailEnabled } from "../mail/flag.js";
import { presetFor } from "../mail/providers/presets.js";
import { deleteOauthMeta } from "../mail/oauth/meta.js";
import { createFlowStore } from "../mail/oauth/state.js";
import { deleteAccount, getAccount, listAccounts, updateAccount, MAIL_SENT_COPY_VALUES } from "../mail/store/accounts.js";
import { listFolders } from "../mail/store/messages.js";
import { readSetting, writeSetting } from "../dashboard/settings/registry.js";
import { SKIP_SPECIAL_USE } from "../mail/sync/engine.js";
import { registerActionRoutes } from "./mail-api-actions.js";
import { registerDraftRoutes } from "./mail-drafts-api.js";
import { registerMessageRoutes } from "./mail-api-messages.js";
import { registerOauthRoutes } from "./mail-api-oauth.js";
import { registerReaderRoutes } from "./mail-api-reader.js";

/** The mount point. The gateway's global JSON parser skips this prefix (see index.js `_hasOwnParser`). */
export const MAIL_API_PREFIX = "/dashboard/mail/api";

/** A mail account id, exactly what the account store mints. Anything else is a 404 here. */
export const MAIL_ACCOUNT_ID_RE = /^ma-[0-9a-f]{16}$/;

/** The status a mail failure answers with. A refused sign-in is the owner's input (400), not a fault. */
const STATUS_BY_CODE = Object.freeze({
  AUTH_FAILED: 400,
  BAD_INPUT: 400,
  NOT_FOUND: 404,
  CLAIMED_ELSEWHERE: 409,
  CHANGED: 409,
  TOO_LARGE: 413,
  TIMEOUT: 504,
  NETWORK: 502,
  TLS: 502,
  PROTOCOL: 502,
});

/** The answers that are not a MailError code. */
const FIXED_TEXT = Object.freeze({
  not_found: "Not found.",
  owner_only: "Only the owner can see this.",
  too_large: "That request is too large.",
  bad_input: "That request is not valid.",
  duplicate_address: "That address is already connected on this Crow.",
  keychain_key_missing: "The keychain key for this password is not on this machine.",
  // Plan 5: an OAuth account is made by the sign-in wizard's callback, never by the connect route.
  oauth_via_wizard: "OAuth accounts are connected through Crow's sign-in wizard.",
  internal: "Something went wrong.",
});

const SECURITIES = new Set(["ssl", "starttls", "none"]);
const PASSWORD_MAX = 1024;
const LABEL_MAX = 120;
const USERNAME_MAX = 254;
const HOST_MAX = 253;
const ADDRESS_MAX = 254;
const DIGEST_TIME_RE = /^(?:[01]\d|2[0-3]):[0-5]\d$/;
const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/;
const PATCH_FIELDS = new Set(["label", "localModelsOnly", "digestOptIn", "digestTime", "sentCopy"]);
const SKIPPED_SPECIAL_USE = new Set(SKIP_SPECIAL_USE.map((flag) => flag.toLowerCase()));

/**
 * The three settings this router's own pair reads and writes, and the `dashboard_settings` keys they
 * live under. The two working-hours keys are the schedule service's (`schedulePresets` reads them);
 * the spellings are exported here so one test can hold the two modules to the same strings.
 */
export const MAIL_WORKING_HOURS_START_SETTING = "mail.working_hours_start";
export const MAIL_WORKING_HOURS_END_SETTING = "mail.working_hours_end";
/** The owner's cloud-drafting switch, the same key `mail/drafts/turn.js` reads. Local-only, always. */
export const MAIL_CLOUD_DRAFTING_SETTING = "mail.cloud_drafting";
const MAIL_SETTINGS_FIELDS = new Set(["workingHoursStart", "workingHoursEnd", "cloudDrafting"]);
/** `HH:MM`, 24-hour: the only form a working hour is stored or accepted in. */
const HOUR_MINUTE_RE = /^(?:[01]\d|2[0-3]):[0-5]\d$/;

/* ------------------------------------------------------------------- runtime */

/** What boot sets once, so every request shares the running supervisor and its adapter factory. */
let runtime = { supervisor: null, adapterFactory: null };

/**
 * The running supervisor and adapter factory (Task 21's boot calls this). Either may be null.
 * @param {{supervisor?: object|null, adapterFactory?: Function|null}} [options]
 */
export function setMailApiRuntime({ supervisor = null, adapterFactory = null } = {}) {
  runtime = { supervisor: supervisor ?? null, adapterFactory: typeof adapterFactory === "function" ? adapterFactory : null };
}

/** Forget the runtime: shutdown, and a test that must not inherit another test's supervisor. */
export function clearMailApiRuntime() {
  runtime = { supervisor: null, adapterFactory: null };
}

/* -------------------------------------------------------------- error shape */

function messageFor(code) {
  return MAIL_ERROR_TEXT[code] || FIXED_TEXT[code] || FIXED_TEXT.internal;
}

/** One JSON error. `message` is a fixed sentence, never a caller's or a library's text. */
function sendError(res, status, code, message = null) {
  if (res.headersSent) return;
  res.status(status).json({ error: code, message: message || messageFor(code) });
}

/** A thrown mail failure as its own code and sentence: never `err.message`, never a detail sentence. */
function sendMailError(res, err) {
  // The keychain's key-missing fault is not a mail error and must not be reported as a bad password;
  // its own fixed sentence says which fault it is, and carries no path and no value.
  if (err && err.code === "KEYCHAIN_KEY_MISSING") return sendError(res, 409, "keychain_key_missing");
  // Anything else that is not a MailError is this Crow's own fault — a database write that failed, say
  // — and it answers the internal sentence: a mail-server sentence would blame the wrong machine, and
  // the failure's own text is never repeated to anybody.
  if (!(err instanceof MailError)) return sendError(res, 500, "internal");
  sendError(res, STATUS_BY_CODE[err.code] ?? 500, err.code);
}

/* ------------------------------------------------------------- validation */

/** A trimmed, bounded, control-character-free string, or null. Exported so the OAuth wizard's own
 *  field checks agree with this router's on what "clean" means. */
export function cleanText(value, max) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max || CONTROL_CHARS_RE.test(trimmed)) return null;
  return trimmed;
}

/** One plain mailbox address: one `@`, no whitespace, no control characters, no angle brackets. */
export function readPlainAddress(value) {
  if (typeof value !== "string") return null;
  const address = value.trim().toLowerCase();
  if (!address || address.length > ADDRESS_MAX) return null;
  if (/[\s\u0000-\u001f\u007f<>]/.test(address)) return null;
  const at = address.indexOf("@");
  if (at <= 0 || at !== address.lastIndexOf("@") || at === address.length - 1) return null;
  return address;
}

function readEndpoint(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return null;
  const host = typeof value.host === "string" ? value.host.trim().toLowerCase() : "";
  if (!host || host.length > HOST_MAX || /[\s\u0000-\u001f\u007f<>]/.test(host)) return null;
  if (!Number.isInteger(value.port) || value.port < 1 || value.port > 65535) return null;
  if (!SECURITIES.has(value.security)) return null;
  return { host, port: value.port, security: value.security };
}

/**
 * The body's `authKind`, or null when it names one this Crow does not know. Absent (or empty) is
 * `password`, the only kind this route can make: an OAuth account arrives through the wizard's own
 * callback (plan 5), so `xoauth2` here is answered `oauth_via_wizard` rather than half-connected.
 */
function readConnectAuthKind(body) {
  if (body == null || typeof body !== "object" || Array.isArray(body)) return null;
  const raw = body.authKind;
  if (raw === undefined || raw === null || raw === "") return "password";
  if (raw === "password" || raw === "xoauth2") return raw;
  return null;
}

/**
 * The provider preset a password connect names, or null when it names none.
 *
 * Plan 5's Gmail card sends the address, the app password and the preset's id and nothing else: a
 * preset's endpoints and its Sent-copy rule are the preset's own, so neither the page nor its client
 * script carries a host or a port, and the wizard cannot disagree with `presets.js`. A named preset
 * must be the one the ADDRESS belongs to (Gmail named for a Microsoft address is `bad_input`), must
 * itself take a password, and must offer both endpoints — `generic` offers none, so it is never
 * named this way.
 *
 * @param {object} body the request's body
 * @param {string} address the already-normalised mailbox address
 * @returns {object|null} one of PRESETS, or null
 */
function readConnectPreset(body, address) {
  const named = typeof body?.provider === "string" ? body.provider.trim() : "";
  if (named === "") return null;
  const own = presetFor(address);
  if (!own || own.id !== named) return null;
  if (!own.authKinds.includes("password")) return null;
  if (!own.imap || !own.smtp) return null;
  return own;
}

/** The connect body, or null. The account store validates it again; this is what keeps a probe from
 *  being opened for a shape the store would refuse. */
function readAccountInput(body) {
  if (body == null || typeof body !== "object" || Array.isArray(body)) return null;
  const label = cleanText(body.label, LABEL_MAX);
  if (!label) return null;
  const address = readPlainAddress(body.address);
  if (!address) return null;
  // A named preset is optional: without one, both endpoints must be in the body, exactly as before.
  const namesPreset = typeof body.provider === "string" && body.provider.trim() !== "";
  const preset = namesPreset ? readConnectPreset(body, address) : null;
  if (namesPreset && !preset) return null;
  let username = null;
  if (body.username !== undefined && body.username !== null && body.username !== "") {
    if (typeof body.username !== "string") return null;
    const trimmed = body.username.trim();
    if (!trimmed || trimmed.length > USERNAME_MAX || /[\s\u0000-\u001f\u007f<>]/.test(trimmed)) return null;
    username = trimmed;
  }
  const password = body.password;
  if (typeof password !== "string" || password === "" || password.length > PASSWORD_MAX) return null;
  const imap = readEndpoint(body.imap) ?? (preset ? { ...preset.imap } : null);
  const smtp = readEndpoint(body.smtp) ?? (preset ? { ...preset.smtp } : null);
  if (!imap || !smtp) return null;
  const input = { label, address, username, password, imap, smtp };
  // A preset a caller named is stored on the account with its own Sent-copy rule: the wizard path's
  // "app password first" must end in an account that files its Sent copy the provider's way.
  if (preset) {
    input.provider = preset.id;
    input.sentCopy = preset.sentCopy;
  }
  return input;
}

/** The settings body, or null on an unknown key or a value of the wrong type. */
function readAccountPatch(body) {
  if (body == null || typeof body !== "object" || Array.isArray(body)) return null;
  const patch = {};
  for (const [key, value] of Object.entries(body)) {
    if (!PATCH_FIELDS.has(key)) return null;
    if (key === "label") {
      const label = cleanText(value, LABEL_MAX);
      if (!label) return null;
      patch.label = label;
    } else if (key === "digestTime") {
      if (typeof value !== "string" || !DIGEST_TIME_RE.test(value)) return null;
      patch.digestTime = value;
    } else if (key === "sentCopy") {
      // `provider` or `append` and nothing else: the account store validates it again, and a value
      // outside the two words is refused here so no row is ever written with a third rule.
      if (!MAIL_SENT_COPY_VALUES.includes(value)) return null;
      patch.sentCopy = value;
    } else {
      if (typeof value !== "boolean") return null;
      patch[key] = value;
    }
  }
  return patch;
}

/**
 * The three mail settings body, or null when a key is unknown or a value is not one this Crow stores.
 *
 * Working hours are text `HH:MM`; they are written together or cleared together (`null` or `""`), so a
 * body that names one of the two without the other is refused rather than stored as half a day.
 * Cloud drafting is a boolean.
 */
function readMailSettingsPatch(body) {
  if (body == null || typeof body !== "object" || Array.isArray(body)) return null;
  const patch = {};
  for (const [key, value] of Object.entries(body)) {
    if (!MAIL_SETTINGS_FIELDS.has(key)) return null;
    if (key === "cloudDrafting") {
      if (typeof value !== "boolean") return null;
      patch.cloudDrafting = value;
      continue;
    }
    if (value === null || value === "") {
      patch[key] = null;
      continue;
    }
    if (typeof value !== "string" || !HOUR_MINUTE_RE.test(value)) return null;
    patch[key] = value;
  }
  const hasStart = Object.hasOwn(patch, "workingHoursStart");
  const hasEnd = Object.hasOwn(patch, "workingHoursEnd");
  if (hasStart !== hasEnd) return null;
  if (hasStart && (patch.workingHoursStart === null) !== (patch.workingHoursEnd === null)) return null;
  return patch;
}

/** A stored setting as the mail settings answer it: a valid `HH:MM`, else null. */
function storedHourMinute(value) {
  return typeof value === "string" && HOUR_MINUTE_RE.test(value.trim()) ? value.trim() : null;
}

/** A stored boolean setting: this feature treats "1" and "true" as on, and nothing else. */
function storedFlag(value) {
  if (value === true) return true;
  return typeof value === "string" && ["1", "true", "on", "yes"].includes(value.trim().toLowerCase());
}

/* ------------------------------------------------------------------ helpers */

/** What a connect or a settings write answers with: the row's own fields, nothing derived, no secret. */
function accountSummary(account) {
  return {
    id: account.id,
    label: account.label,
    address: account.address,
    status: account.status,
    statusDetail: account.statusDetail,
    localModelsOnly: account.localModelsOnly,
    digestOptIn: account.digestOptIn,
    digestTime: account.digestTime,
  };
}

/**
 * The mail settings page's own read: the three owner-wide settings and, per account, the Sent-copy
 * rule (a per-account choice that the settings cards show beside the account). Nothing secret and no
 * connection detail is in it.
 *
 * @param {object} db
 */
async function mailSettingsView(db) {
  const [start, end, cloud] = await Promise.all([
    readSetting(db, MAIL_WORKING_HOURS_START_SETTING),
    readSetting(db, MAIL_WORKING_HOURS_END_SETTING),
    readSetting(db, MAIL_CLOUD_DRAFTING_SETTING),
  ]);
  const sentCopies = {};
  for (const account of await listAccounts(db)) sentCopies[account.id] = account.sentCopy;
  return {
    settings: {
      workingHoursStart: storedHourMinute(start),
      workingHoursEnd: storedHourMinute(end),
      cloudDrafting: storedFlag(cloud),
    },
    sentCopies,
  };
}

/**
 * The adapter factory the routes use when boot provided none.
 *
 * `deps.tokenProviderFor(accountId)` is the per-account seam (the boot registry's own
 * `tokenProviderFor`): one provider object per account, shared with the sync worker and every action
 * adapter, so a request here never builds a second cache or a second rotation writer. The adapter is
 * handed a THIN function that asks the seam on every call, never the provider object itself: a
 * `forget()` (an account removal, or a fresh grant) retires that object, and an adapter that held it
 * would answer AUTH_FAILED/`retired` to a sign-in that should have used the new provider.
 * `deps.tokenProvider` (one provider for every account) is kept for callers from before the registry
 * and for tests; the per-account function wins when both are given. A password account is handed no
 * provider at all.
 *
 * A rotated refresh token has exactly one writer. The registry's provider writes its own rotations, so
 * an adapter built on it is handed NO writer (a second one would store the same rotation twice). A
 * single injected `tokenProvider` writes nothing itself, so the adapter keeps its own writer, bound to
 * this account id here — the one place that knows which account the adapter is for — exactly as
 * boot/mail-boot.js's default factory binds it. Without it a rotation through this seam would be
 * dropped on the floor and the next refresh would spend a token the provider had already replaced.
 *
 * Exported because it is the seam those two rules are pinned by (tests/mail-oauth-token-provider.test.js).
 *
 * @param {{adapterFactory?: Function, tokenProvider?: Function, tokenProviderFor?: Function}} deps
 * @returns {(args: {account: object, credentials: object}) => object}
 */
export function fallbackAdapterFactory(deps = {}) {
  if (typeof deps.adapterFactory === "function") return deps.adapterFactory;
  if (typeof runtime.adapterFactory === "function") return runtime.adapterFactory;
  const single = typeof deps.tokenProvider === "function" ? deps.tokenProvider : null;
  const perAccount = typeof deps.tokenProviderFor === "function" ? deps.tokenProviderFor : null;
  return ({ account, credentials }) => {
    const usesRegistry = perAccount != null && account != null && account.authKind === "xoauth2";
    // The CURRENT provider on every call, never the object: `forget()` retires the one this adapter was
    // built beside, and a reconnect's new provider must be reachable through the same adapter.
    const registryProvider = usesRegistry
      ? (request) => {
        const current = perAccount(account.id);
        if (typeof current !== "function") throw new MailError("AUTH_FAILED");
        return current(request);
      }
      : null;
    const tokenProvider = registryProvider ?? single;
    // The registry's provider is the writer; a single injected provider is not, so this factory binds
    // `createRotationWriter`'s `(accountId, {refreshToken})` to the account the adapter is for.
    let onTokenRotated = null;
    if (!usesRegistry && single != null && account != null
      && credentials != null && typeof credentials.saveSecret === "function") {
      const writeRotation = createRotationWriter(credentials);
      onTokenRotated = (refreshToken) => writeRotation(account.id, { refreshToken });
    }
    return createImapSmtpAdapter({ account, credentials, tokenProvider, onTokenRotated });
  };
}

/** The factory `ctx.adapterFactory` hands the mounted routes. */
function adapterFactoryFor(deps) {
  return fallbackAdapterFactory(deps);
}

/**
 * The forget hook boot supplied, or null: an account's removal drops its cached provider. Awaited,
 * because it settles after a rotation write that was already in the air — the sealed secrets must be
 * deleted after that row landed, or the deleted account is left holding a live refresh token.
 *
 * @param {object} deps
 * @param {string} accountId
 * @returns {Promise<void>} never rejects
 */
function forgetTokenProviderFor(deps, accountId) {
  if (typeof deps.forgetTokenProvider !== "function") return Promise.resolve();
  try {
    return Promise.resolve(deps.forgetTokenProvider(accountId)).then(() => undefined, () => undefined);
  } catch (err) {
    logCode("delete_token_provider", err);
    return Promise.resolve();
  }
}

/** The supervisor, or null: a build without sync running still serves reads and still connects. */
function supervisorFor(deps) {
  const supervisor = deps.supervisor !== undefined ? deps.supervisor : runtime.supervisor;
  return supervisor ?? null;
}

/**
 * Retire the account's sync worker BEFORE its rows go, and wait for it: the worker's run, timers,
 * watcher and both of its connections are gone by the time this resolves, so nothing of the deleted
 * account can write an orphan folder, message or sync state afterwards, or send a notice about it.
 *
 * The call is opened with no write context — the worker's own writes long outlive this request — and
 * it never throws: a supervisor without the call, or one whose stop failed, must not hold up a delete
 * the owner asked for. A supervisor that is not running simply has nothing to stop.
 */
async function stopWorkerForDelete(deps, accountId) {
  const supervisor = supervisorFor(deps);
  if (!supervisor || typeof supervisor.stopAccount !== "function") return;
  try {
    await withoutWriteContext(() => supervisor.stopAccount(accountId));
  } catch (err) {
    logCode("delete_worker", err);
  }
}

/**
 * The same, for the other half of the delete: while the id is in the supervisor's removal set no
 * worker, run or borrowed adapter may be built for it, so a `syncNow`, a `requestSync` or a
 * `withAdapter` that lands between the stop and the rows' removal cannot write after the delete (no
 * mail table row carries a foreign key). Both calls are optional and never throw: a supervisor from an
 * older build, or a fake one, must not hold up a delete.
 */
function beginRemovalFor(deps, accountId) {
  const supervisor = supervisorFor(deps);
  if (!supervisor || typeof supervisor.beginRemoval !== "function") return false;
  try {
    supervisor.beginRemoval(accountId);
    return true;
  } catch (err) {
    logCode("delete_removal_begin", err);
    return false;
  }
}

function endRemovalFor(deps, accountId, started) {
  if (started !== true) return;
  const supervisor = supervisorFor(deps);
  if (!supervisor || typeof supervisor.endRemoval !== "function") return;
  try {
    supervisor.endRemoval(accountId);
  } catch (err) {
    logCode("delete_removal_end", err);
  }
}

/* -------------------------------------------------------------------- router */

/**
 * The mail API router.
 *
 * @param {Function} dashboardAuth the dashboard's auth middleware
 * @param {{openDb?: Function, adapterFactory?: Function, supervisor?: object|null,
 *   credentials?: object, claims?: {checkClaim?: Function, writeClaim?: Function, releaseClaim?: Function},
 *   localInstance?: object|Function, tokenProvider?: Function,
 *   tokenProviderFor?: (accountId: string) => Function|null, forgetTokenProvider?: Function,
 *   recordSecrets?: Function, ownerCheck?: Function, flowStore?: object,
 *   oauthAdapterFactory?: Function, fetchImpl?: Function, endpoints?: {tokenUrl?: string},
 *   now?: () => number}} [deps]
 *   `openDb` mints the request's crow.db client; `recordSecrets(values)` records masked values and
 *   defaults to `recordServiceSecretValues`; `ownerCheck` defaults to `isLocalPasswordSessionOn`;
 *   `tokenProviderFor` is the boot registry's per-account provider (a single `tokenProvider` is the
 *   older, one-for-every-account seam) and `forgetTokenProvider(accountId)` drops one on removal;
 *   `claims` replaces the claim code (any function it leaves out stays the real one). Plan 5's OAuth
 *   wizard adds its own seams: `flowStore` (this router instance's in-memory state store — a test may
 *   inject one, and its clock), `oauthAdapterFactory` (the OAuth probe's adapter, a TEST seam),
 *   `fetchImpl` (the OAuth transport, `globalThis.fetch` by default) and `endpoints` (TEST ONLY: the
 *   loopback token URL `mail/oauth/flow.js` accepts).
 * @returns {import("express").Router}
 */
export function mailApiRouter(dashboardAuth, deps = {}) {
  const router = Router();
  const openDb = typeof deps.openDb === "function" ? deps.openDb : () => createDbClient();
  const ownerCheck = typeof deps.ownerCheck === "function" ? deps.ownerCheck : isLocalPasswordSessionOn;
  const recordSecrets = typeof deps.recordSecrets === "function" ? deps.recordSecrets : recordServiceSecretValues;
  // 64KB is generous for a connect (an address, two endpoints, a password) and small enough that a
  // mailbox body never travels through this route. The 413 and the 400 are this router's own.
  const jsonParser = jsonParserOf({ limit: "64kb" });
  // Plan 5's OAuth flow store: one per router instance, in memory only (D1 — a restart during sign-in
  // just means starting again). Every state token, PKCE verifier and pending client secret lives here
  // and nowhere else until the callback has spent it.
  const flowStore = deps.flowStore ?? createFlowStore();

  /** One client per request, closed in `finally`; a handler that throws answers its MailError code. */
  const route = (label, handler) => async (req, res) => {
    const db = openDb();
    try {
      await handler(db, req, res);
    } catch (err) {
      logCode(label, err);
      sendMailError(res, err);
    } finally {
      try {
        db.close();
      } catch {
        // Already closed is the only failure a per-request client has here.
      }
    }
  };

  router.use(MAIL_API_PREFIX, dashboardAuth);

  /** Never cached: a mailbox list or an address must not sit in a cache. */
  const guardHeaders = (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    next();
  };

  /** The flag: one answer for every route, and no database client is opened for it. */
  const flagGuard = (req, res, next) => {
    if (!mailEnabled()) return sendError(res, 404, "not_found");
    next();
  };

  /** The owner: this instance's own password session, from the owner's own client. No row is read
   *  before the verdict, so a refused request carries no data at all. */
  const ownerGuard = async (req, res, next) => {
    const db = openDb();
    try {
      let owner = false;
      try {
        owner = (await ownerCheck(db, req)) === true;
      } catch {
        owner = false;
      }
      if (!owner) return sendError(res, 403, "owner_only");
      next();
    } finally {
      try {
        db.close();
      } catch {
        // Already closed is the only failure a per-request client has here.
      }
    }
  };

  router.use(MAIL_API_PREFIX, guardHeaders);
  router.use(MAIL_API_PREFIX, flagGuard);
  router.use(MAIL_API_PREFIX, ownerGuard);
  router.use(MAIL_API_PREFIX, jsonBodyParser(jsonParser));

  /* ------------------------------------------------------------------ reads */

  // GET /accounts — the owner's accounts and the addresses held elsewhere, both without a hash.
  router.get(`${MAIL_API_PREFIX}/accounts`, route("GET /accounts", async (db, req, res) => {
    const local = await localInstanceFor(db, deps);
    res.json(await accountsOverview(db, { localInstanceId: local.instanceId }));
  }));

  // GET /accounts/:id/folders — the folders the reader's drawer shows, without the virtual ones.
  router.get(`${MAIL_API_PREFIX}/accounts/:id/folders`, route("GET /accounts/:id/folders", async (db, req, res) => {
    const id = String(req.params.id);
    if (!MAIL_ACCOUNT_ID_RE.test(id)) return sendError(res, 404, "not_found");
    const account = await getAccount(db, id);
    if (!account) return sendError(res, 404, "not_found");
    const folders = await listFolders(db, id);
    res.json({
      folders: folders
        .filter((folder) => !isSkippedFolder(folder))
        .map((folder) => ({
          id: folder.id,
          path: folder.path,
          name: folder.name ?? folder.path,
          role: folder.role,
          unreadCount: folder.unreadCount,
          totalCount: folder.totalCount,
        })),
    });
  }));

  // GET /settings — the three owner-wide mail settings and each account's Sent-copy rule. Owner-only
  // like every route here; nothing on it is a connection detail or a secret. The settings page reads
  // its stored values from this one read (the same shape the write answers with), so the markup never
  // has to carry them.
  router.get(`${MAIL_API_PREFIX}/settings`, route("GET /settings", async (db, req, res) => {
    res.json(await mailSettingsView(db));
  }));

  /* ------------------------------------------------------------------ writes */

  // PATCH /settings — working hours (both together, or both cleared) and the cloud-drafting switch.
  // An unknown key or a value this Crow does not store is a 400 and writes nothing. The cloud-drafting
  // key is written LOCAL-ONLY: whether this box may hand draft text to a cloud model is this box's
  // decision, never a setting a paired peer may turn on for it.
  router.patch(`${MAIL_API_PREFIX}/settings`, route("PATCH /settings", async (db, req, res) => {
    const patch = readMailSettingsPatch(req.body);
    if (!patch) return sendError(res, 400, "bad_input");
    if (Object.hasOwn(patch, "workingHoursStart")) {
      // Both keys move together, and clearing writes the empty string both readers read as "none set".
      await writeSetting(db, MAIL_WORKING_HOURS_START_SETTING, patch.workingHoursStart ?? "");
      await writeSetting(db, MAIL_WORKING_HOURS_END_SETTING, patch.workingHoursEnd ?? "");
    }
    if (Object.hasOwn(patch, "cloudDrafting")) {
      await writeSetting(db, MAIL_CLOUD_DRAFTING_SETTING, patch.cloudDrafting ? "1" : "0", { scope: "local" });
    }
    res.json(await mailSettingsView(db));
  }));

  // POST /accounts — one password account. The sequence itself is `connectAccount`
  // (mail/accounts/connect.js), so plan 5's OAuth callback runs the same one: a duplicate is refused
  // before anything dials, the probe comes before anything is stored, then one claim; a claim that is
  // lost afterwards is undone whole, so an address is never half-connected. An address another
  // instance holds — or a claim lost to one — answers 409 naming it; a duplicate answers
  // `duplicate_address`.
  router.post(`${MAIL_API_PREFIX}/accounts`, route("POST /accounts", async (db, req, res) => {
    const authKind = readConnectAuthKind(req.body);
    if (authKind === null) return sendError(res, 400, "bad_input");
    // OAuth arrives through the wizard's own callback (plan 5), never as a password-shaped body here.
    if (authKind === "xoauth2") return sendError(res, 400, "oauth_via_wizard");
    const input = readAccountInput(req.body);
    if (!input) return sendError(res, 400, "bad_input");

    let account;
    try {
      account = await connectAccount(db, {
        ...deps,
        // The factory this request's probe would use: the caller's, else the runtime boot published,
        // else the real adapter — the same precedence every other mail route reads.
        adapterFactory: adapterFactoryFor(deps),
        // A value, not a lookup: a connect with no supervisor running still connects, and just starts
        // no background sync.
        supervisor: supervisorFor(deps),
      }, {
        draft: input,
        authKind,
        secrets: { MAIL_PASSWORD: input.password },
      });
    } catch (err) {
      if (isDuplicateAddress(err)) return sendError(res, 409, "duplicate_address");
      if (err instanceof MailError && err.code === "CLAIMED_ELSEWHERE") {
        return sendError(res, 409, "CLAIMED_ELSEWHERE", claimedElsewhereSentence(err.instanceName));
      }
      throw err;
    }

    res.status(201).json({ account: accountSummary(account) });
  }));

  // PATCH /accounts/:id — only the settings a person edits here.
  router.patch(`${MAIL_API_PREFIX}/accounts/:id`, route("PATCH /accounts/:id", async (db, req, res) => {
    const id = String(req.params.id);
    if (!MAIL_ACCOUNT_ID_RE.test(id)) return sendError(res, 404, "not_found");
    const patch = readAccountPatch(req.body);
    if (!patch) return sendError(res, 400, "bad_input");
    const account = await updateAccount(db, id, patch);
    if (!account) return sendError(res, 404, "not_found");
    res.json({ account: accountSummary(account) });
  }));

  // DELETE /accounts/:id — the id is marked as being removed, then the worker (awaited: its run,
  // timers, watcher and both of its connections are gone before the rows are touched), then the cached
  // OAuth provider is retired and AWAITED (before the rows and the sealed secrets, so a refresh in
  // flight starts no new write and one already on its way has landed before the secrets go), then the
  // rows, the secret, the OAuth meta and the claim; the mark goes in a `finally`, so a delete that
  // fails still frees the id. A keychain, meta or claim failure after the row is gone is logged by
  // code: the secret of a deleted account is never served again, a label left behind names an id
  // nothing owns, and a claim row that cannot be tombstoned still expires with this instance's
  // liveness.
  router.delete(`${MAIL_API_PREFIX}/accounts/:id`, route("DELETE /accounts/:id", async (db, req, res) => {
    const id = String(req.params.id);
    if (!MAIL_ACCOUNT_ID_RE.test(id)) return sendError(res, 404, "not_found");
    const account = await getAccount(db, id);
    if (!account) return sendError(res, 404, "not_found");
    const local = await localInstanceFor(db, deps);
    const credentials = credentialsFor(db, deps);

    const removalBegan = beginRemovalFor(deps, id);
    try {
      await stopWorkerForDelete(deps, id);
      // The cached provider is RETIRED here and AWAITED, before its rows go and before the sealed
      // secrets are removed: a refresh still in flight starts no new rotation write, and a write that
      // was already in the air has landed by the time this resolves — so `deleteSecrets` below removes
      // the row it created rather than racing it.
      await forgetTokenProviderFor(deps, id);
      const removed = await deleteAccount(db, id);
      try {
        await credentials.deleteSecrets(id);
      } catch (err) {
        logCode("delete_secret", err);
      }
      // Plan 5's grant label goes with the account it describes. It is not a secret and nothing reads
      // one for a removed account, so a failure here is logged by code and never fails the delete.
      try {
        await deleteOauthMeta(db, id);
      } catch (err) {
        logCode("delete_oauth_meta", err);
      }
      try {
        await claimsFor(deps).releaseClaim(db, account.address, { localInstanceId: local.instanceId });
      } catch (err) {
        logCode("undo_claim", err);
      }
      res.json({ ok: true, messages: removed.messages });
    } finally {
      endRemovalFor(deps, id, removalBegan);
    }
  }));

  // POST /accounts/:id/sync — the owner's nudge. The run is the supervisor's; the answer says whether
  // one was started, never the sync's own outcome (the panel reads status for that).
  router.post(`${MAIL_API_PREFIX}/accounts/:id/sync`, route("POST /accounts/:id/sync", async (db, req, res) => {
    const id = String(req.params.id);
    if (!MAIL_ACCOUNT_ID_RE.test(id)) return sendError(res, 404, "not_found");
    const account = await getAccount(db, id);
    if (!account) return sendError(res, 404, "not_found");
    const supervisor = supervisorFor(deps);
    const started = Boolean(supervisor && typeof supervisor.syncNow === "function");
    if (started) startBackgroundSync(supervisor, id);
    res.status(started ? 202 : 200).json({ ok: true, started });
  }));

  const ctx = {
    guards: { headers: guardHeaders, flag: flagGuard, owner: ownerGuard },
    openDb,
    credentials: (db) => credentialsFor(db, deps),
    supervisor: () => supervisorFor(deps),
    adapterFactory: adapterFactoryFor(deps),
    localInstance: (db) => localInstanceFor(db, deps),
    // The masking seam the connect route uses for the password it was handed: plan 2's password route
    // records the new secret the same way, before any path can write it to a log.
    recordSecrets,
    sendError,
    sendMailError,
    logCode,
    route,
    // Plan 5's wizard: the store a `start` mints into and a `take` spends from, and the seams the two
    // provider calls need. `endpoints` is the loopback-only TEST override; production never passes it.
    flowStore,
    oauth: {
      fetchImpl: typeof deps.fetchImpl === "function" ? deps.fetchImpl : globalThis.fetch,
      endpoints: deps.endpoints ?? null,
      now: typeof deps.now === "function" ? deps.now : Date.now,
      adapterFactory: typeof deps.oauthAdapterFactory === "function" ? deps.oauthAdapterFactory : null,
      claims: deps.claims ?? null,
      forgetTokenProvider: typeof deps.forgetTokenProvider === "function" ? deps.forgetTokenProvider : null,
    },
  };

  // Task 20 fills the mailbox routes on this same router, with these same guards and helpers.
  registerMessageRoutes(router, ctx);
  // Plan 2's reader routes: the message frame and the image allow list, behind the same guards.
  registerReaderRoutes(router, ctx);
  // Plan 2's message actions: read/unread, archive, delete and move, behind the same guards.
  registerActionRoutes(router, ctx);
  // Plan 3's draft card: create, read, edit, turn, send, undo, schedule, cancel and discard, behind
  // the same flag/owner/no-store/CSRF/64 KB chain (servers/gateway/index.js's `_hasOwnParser` already
  // hands every `/dashboard/mail/api/` path to this router's own parser).
  registerDraftRoutes(router, ctx);
  // Plan 5's OAuth wizard routes and the callback (`/dashboard/mail/oauth/callback`, outside the API
  // prefix and carrying the same guards itself), behind this same router's flag/owner/no-store chain.
  registerOauthRoutes(router, ctx);

  return router;
}

/** A folder the sync engine skips (a server's virtual view of mail stored in a real folder). */
function isSkippedFolder(folder) {
  const specialUse = typeof folder.specialUse === "string" ? folder.specialUse : "";
  if (!specialUse) return false;
  return specialUse.split(/\s+/).some((token) => SKIPPED_SPECIAL_USE.has(token.trim().toLowerCase()));
}

/** A body above 64KB is `too_large`; anything else the parser refuses is `bad_input`. Neither answer
 *  repeats the parser's own message. */
function jsonBodyParser(parser) {
  return (req, res, next) => parser(req, res, (err) => {
    if (!err) return next();
    const status = Number(err.status || err.statusCode || 0);
    if (status === 413 || err.type === "entity.too.large") return sendError(res, 413, "too_large");
    return sendError(res, 400, "bad_input");
  });
}

export default mailApiRouter;