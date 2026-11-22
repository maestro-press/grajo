/**
 * Crow Mail's OAuth access-token provider: the one thing a live IMAP/SMTP session asks for an access
 * token, and the single writer of a rotated refresh token.
 *
 * One provider belongs to one account (the registry in oauth/registry.js keeps them). It reads the
 * account row for the provider name (`mail_accounts.provider`: `google`/`gmail` and
 * `microsoft`/`outlook`, nothing else), the Microsoft tenant from the account's OAuth meta
 * (oauth/meta.js, default `common`), and the credentials from the sealed keychain
 * (mail/credentials.js): `MAIL_OAUTH_CLIENT_ID`, the optional `MAIL_OAUTH_CLIENT_SECRET`, and
 * `MAIL_REFRESH_TOKEN`. The POSTs themselves are `refresh()` from oauth/flow.js, so every rule about a
 * provider's answer — what may be read from a failure body, what a fixed sentence is — stays in one
 * place, and transport is the injected `fetchImpl` (production: `globalThis.fetch`; a test points
 * `endpoints` at tests/fixtures/fake-oauth-provider.mjs). Nothing here reaches the network by itself.
 *
 * Three rules shape it:
 *
 * - **A cached token is good until `expiresAt - 60 s`.** A minute of headroom is enough for a sign-in
 *   that starts just before the hour turns over, and it keeps a mailbox's worth of connections on one
 *   token instead of one each.
 * - **One refresh at a time.** The pending promise is shared by every caller, so ten connections that
 *   all need a token at once make one POST. `forceRefresh` skips the cache but JOINS an in-flight
 *   refresh rather than starting a second — two forced refreshes racing would rotate the refresh token
 *   twice and lose one of them.
 * - **The refresh token has exactly one writer: this module.** A reply that carries a rotated token is
 *   handed to `onTokenRotated(accountId, {refreshToken})` and awaited BEFORE the access token is
 *   resolved, so a rotation is never reported as settled while its write is still in the air. If that
 *   write fails it is logged by code only (never the error's text, which can quote the token), the
 *   access token in hand is still returned, and the new refresh token stays in memory: the next
 *   refresh sends it AND retries the write. The returned object never carries `refreshToken`, so no
 *   caller can write it anywhere a second time, and an access token is never passed to a writer — an
 *   access token expires within the hour and is nothing the keychain should keep.
 *
 * `invalid_grant` is the provider saying the grant is dead: the account is marked `auth_failed` once
 * (through the injected `markAuthFailed`, when the caller supplied one — the registry supplies none by
 * default, because the sync supervisor owns the account's transition and its one bell) and every later
 * call answers AUTH_FAILED without asking the provider again — a dead grant must not be hammered, and
 * only `forget()` on the registry (a new grant, or the account's removal) clears the flag by throwing
 * the provider away. `NETWORK` changes nothing: a server that was unreachable is not a credential
 * problem. A keychain key that is not on this machine (`KeychainKeyMissingError`) travels unchanged,
 * exactly as it does through mail/credentials.js: that is the key's fault, not the token's, and
 * reporting it as a bad password would send the owner to fix the wrong thing.
 *
 * `retire()` is how a provider stops existing. The registry calls it from `forget()`: the account was
 * removed, or a fresh grant replaced the old one's. A retired provider answers AUTH_FAILED/`retired` to
 * every caller — including one already waiting on a refresh — never caches, and starts no new rotation
 * write: a refresh that was in flight when the account went must not leave a live token behind for a
 * deleted account, and one from a replaced grant must not overwrite the new grant's token. A write that
 * had ALREADY reached the keychain when `retire()` ran is not cancelled — `retire()` answers a promise
 * that settles with it, so `forget()` can be awaited and the caller's own delete of the sealed secrets
 * runs AFTER that row landed (the row it is about to remove is the one this write created).
 */
import { MailError, toMailError } from "../errors.js";
import { refresh as refreshGrant } from "./flow.js";

/** The provider names an account row may carry, mapped to oauth/flow.js's two providers. */
const PROVIDER_ALIASES = Object.freeze({
  google: "google",
  gmail: "google",
  microsoft: "microsoft",
  outlook: "microsoft",
});

/** A token is used only while it has this much life left: enough for a connection to sign in. */
const EXPIRY_SKEW_MS = 60_000;

/** An `expiresAt` a provider did not give (or gave nonsense) is an hour on the injected clock. */
const DEFAULT_LIFETIME_MS = 3_600_000;

/**
 * The allow-listed token an error contributes to a log line: its own short code when it has one,
 * otherwise the fixed code its classifier gives it. Never an error's message.
 */
function codeOf(err) {
  if (err != null && typeof err === "object" && typeof err.code === "string" && /^[A-Za-z0-9_]{1,40}$/.test(err.code)) {
    return err.code;
  }
  try {
    return toMailError(err).code;
  } catch {
    return "PROTOCOL";
  }
}

/** One log line: an event name and, when there is one, an allow-listed code. Nothing else. */
function defaultLog(line) {
  const event = typeof line?.event === "string" ? line.event : "event";
  const code = typeof line?.code === "string" ? ` ${line.code}` : "";
  console.warn(`[mail] ${event}${code}`);
}

function requireString(value, detail) {
  if (typeof value !== "string" || value === "") throw new MailError("BAD_INPUT", detail);
  return value;
}

/**
 * One account's OAuth access-token provider.
 *
 * The returned function is the `TokenProvider` contract of mail/credentials.js:
 * `async ({accountId, forceRefresh}) => ({accessToken, expiresAt})`. It is bound to `accountId`, so a
 * call naming another account is BAD_INPUT rather than a token for the wrong mailbox.
 *
 * @param {object} options
 * @param {string} options.accountId the mail account this provider serves
 * @param {(accountId: string) => Promise<object|null>} options.getAccount the account store's read
 * @param {{getSecrets: Function}} options.credentials the sealed keychain reader
 * @param {Function} [options.fetchImpl] the HTTP transport (a test injects a local fake's `fetch`)
 * @param {() => number} [options.now] the clock for `expiresAt` and the cache
 * @param {(accountId: string) => unknown} [options.markAuthFailed] called once per dead grant; the
 *   caller's own write, if it wants one. The registry passes none: the sync supervisor owns the
 *   account's `auth_failed` transition and the one notice it rings, and a write here would land first
 *   and silence that notice.
 * @param {(accountId: string, rotation: {refreshToken: string}) => unknown} [options.onTokenRotated]
 *   the one rotation writer (the registry supplies `createRotationWriter(credentials)`)
 * @param {{tokenUrl?: string}} [options.endpoints] TEST ONLY: point the POST at a fake provider
 * @param {(accountId: string) => Promise<object|null>} [options.getMeta] reads oauth/meta.js's tenant
 * @param {(line: {event: string, code?: string}) => void} [options.log] receives codes only
 * @returns {(request?: {accountId?: string, forceRefresh?: boolean}) =>
 *   Promise<{accessToken: string, expiresAt: number}>} the provider, with a `retire()` that ends it
 *   (and answers a promise that settles after a rotation write already in the air)
 */
export function createTokenProvider(options = {}) {
  const {
    accountId,
    getAccount,
    credentials,
    fetchImpl,
    now = Date.now,
    markAuthFailed = null,
    onTokenRotated = null,
    endpoints,
    getMeta = null,
    log = defaultLog,
  } = options;

  requireString(accountId, "account_id");
  if (typeof getAccount !== "function") throw new TypeError("createTokenProvider needs getAccount");
  if (!credentials || typeof credentials.getSecrets !== "function") {
    throw new TypeError("createTokenProvider needs a credentials reader");
  }
  const clock = typeof now === "function" ? now : Date.now;
  const say = (line) => {
    try {
      log(line);
    } catch {
      // A log sink that cannot take a line is never a reason to fail a sign-in.
    }
  };

  /** The in-memory token, `{accessToken, expiresAt}`, or null. */
  let cached = null;
  /** The refresh in flight, shared by every caller, or null. */
  let pending = null;
  /** Set when the provider said `invalid_grant`: no call asks for a token again until this provider goes. */
  let authFailed = false;
  /** A rotated refresh token that is newer than the keychain's copy (the one the next refresh sends). */
  let rotatedRefreshToken = null;
  /** A rotation whose keychain write failed: the next refresh retries it. */
  let unsavedRotation = false;
  /**
   * The rotation write in flight, or null. `retire()` answers it, so a caller that removes the account
   * (the registry's `forget()`, and the DELETE that awaits it) can wait for a write already on its way
   * before the sealed secrets are removed.
   */
  let inflightWrite = null;
  /** The account row, read once; only a missing row is re-read (a delete racing a sync). */
  let accountRow = null;
  /**
   * Set by `retire()`: this provider is gone (its account was removed, or a new grant replaced it).
   * A retired provider never asks for a token, never caches one and never writes a rotation — an
   * in-flight refresh's result is discarded and its caller hears AUTH_FAILED/`retired`.
   */
  let retired = false;

  /** The one answer a retired provider gives. */
  const retiredError = () => new MailError("AUTH_FAILED", "retired");

  /** The account's provider name, from the row's own `provider` column. */
  async function providerName() {
    if (accountRow == null) accountRow = await getAccount(accountId);
    if (accountRow == null) throw new MailError("AUTH_FAILED");
    const raw = typeof accountRow.provider === "string" ? accountRow.provider.trim().toLowerCase() : "";
    if (!Object.hasOwn(PROVIDER_ALIASES, raw)) throw new MailError("AUTH_FAILED");
    return PROVIDER_ALIASES[raw];
  }

  /** The Microsoft tenant the meta records, or "common". Only Microsoft's URLs carry one. */
  async function tenantName() {
    if (typeof getMeta !== "function") return "common";
    let meta = null;
    try {
      meta = await getMeta(accountId);
    } catch (err) {
      // The tenant is a detail of the URL: unreadable meta falls back to "common" and says so by code.
      say({ event: "oauth_meta_read_failed", code: codeOf(err) });
      return "common";
    }
    const tenant = meta != null && typeof meta.tenant === "string" && meta.tenant !== "" ? meta.tenant : null;
    return tenant ?? "common";
  }

  /**
   * Write one rotated refresh token to the single writer. A failure is logged by code only and leaves
   * the token in memory, so the next refresh both uses it and tries the write again.
   *
   * The write is tracked while it is in the air: `retire()` answers it, so an account's removal can wait
   * for a row that is already being written instead of deleting the keychain out from under it.
   */
  async function persistRotation(refreshToken) {
    // A rotation discovered before the provider was retired never reaches the keychain: the account may
    // already be gone, and the grant it belonged to is no longer the one in force.
    if (retired) {
      unsavedRotation = false;
      return;
    }
    if (typeof onTokenRotated !== "function") {
      unsavedRotation = false;
      return;
    }
    const write = (async () => {
      try {
        await onTokenRotated(accountId, { refreshToken });
        unsavedRotation = false;
      } catch (err) {
        unsavedRotation = true;
        say({ event: "token_rotation_failed", code: codeOf(err) });
      }
    })();
    inflightWrite = write;
    try {
      await write;
    } finally {
      if (inflightWrite === write) inflightWrite = null;
    }
  }

  /** Mark the account once for a dead grant. A marking that fails is logged by code and not retried. */
  async function refuseOnce() {
    if (authFailed) return;
    authFailed = true;
    if (typeof markAuthFailed !== "function") return;
    try {
      await markAuthFailed(accountId);
    } catch (err) {
      say({ event: "mark_auth_failed_failed", code: codeOf(err) });
    }
  }

  /** One POST: the secrets, the providers's own name and tenant, and the single rotation write. */
  async function refreshOnce() {
    if (retired) throw retiredError();
    const provider = await providerName();
    const tenant = await tenantName();

    // A keychain key that is not on this machine is the key's fault: KeychainKeyMissingError travels.
    const secrets = (await credentials.getSecrets(accountId)) ?? {};
    const clientId = typeof secrets.MAIL_OAUTH_CLIENT_ID === "string" ? secrets.MAIL_OAUTH_CLIENT_ID : "";
    if (!clientId) throw new MailError("AUTH_FAILED");
    const clientSecret = typeof secrets.MAIL_OAUTH_CLIENT_SECRET === "string" && secrets.MAIL_OAUTH_CLIENT_SECRET !== ""
      ? secrets.MAIL_OAUTH_CLIENT_SECRET
      : undefined;
    const storedRefreshToken = typeof secrets.MAIL_REFRESH_TOKEN === "string" && secrets.MAIL_REFRESH_TOKEN !== ""
      ? secrets.MAIL_REFRESH_TOKEN
      : null;
    const refreshToken = rotatedRefreshToken ?? storedRefreshToken;
    if (!refreshToken) throw new MailError("AUTH_FAILED");

    // A rotation the keychain refused last time is written again before it is spent: the provider may
    // rotate on every call, and a token that never lands would be lost with this process.
    if (unsavedRotation && rotatedRefreshToken != null) await persistRotation(rotatedRefreshToken);

    let result;
    try {
      result = await refreshGrant({
        provider,
        refreshToken,
        clientId,
        clientSecret,
        tenant,
        fetchImpl,
        now: clock,
        endpoints,
      });
    } catch (err) {
      // The grant is dead: say so once and answer AUTH_FAILED from here on. Anything else — NETWORK, a
      // protocol fault, the keychain's key-missing fault — travels as it came.
      if (err instanceof MailError && err.code === "AUTH_FAILED" && err.detail === "invalid_grant") {
        await refuseOnce();
      }
      throw err;
    }

    // The provider was retired while this refresh was in the air (its account was deleted, or a fresh
    // grant replaced this one): the answer is discarded whole — no rotation, no cache — and the caller
    // hears that the provider it asked is gone.
    if (retired) throw retiredError();

    if (result != null && typeof result.refreshToken === "string" && result.refreshToken !== "") {
      rotatedRefreshToken = result.refreshToken;
      // Awaited before the access token is resolved: a rotation is written, or reported as unwritten.
      await persistRotation(result.refreshToken);
    }

    if (result == null || typeof result.accessToken !== "string" || result.accessToken === "") {
      throw new MailError("AUTH_FAILED");
    }
    const expiresAt = Number.isFinite(result.expiresAt) ? Number(result.expiresAt) : clock() + DEFAULT_LIFETIME_MS;
    // Only the two fields a caller may have: no refresh token ever leaves this module.
    return { accessToken: result.accessToken, expiresAt };
  }

  const fresh = () => cached != null && clock() < cached.expiresAt - EXPIRY_SKEW_MS;

  /**
   * The provider itself.
   *
   * @param {{accountId?: string, forceRefresh?: boolean}} [request]
   * @returns {Promise<{accessToken: string, expiresAt: number}>}
   */
  async function tokenProvider({ accountId: requested, forceRefresh = false } = {}) {
    if (retired) throw retiredError();
    if (typeof requested === "string" && requested !== "" && requested !== accountId) {
      throw new MailError("BAD_INPUT", "account_id");
    }
    if (authFailed) throw new MailError("AUTH_FAILED", "invalid_grant");

    if (forceRefresh !== true && fresh()) {
      return { accessToken: cached.accessToken, expiresAt: cached.expiresAt };
    }
    // A forced refresh joins the one in flight rather than starting a second: two racing refreshes
    // would both rotate, and one of the two new refresh tokens would be lost.
    if (pending != null) return await pending;

    const attempt = refreshOnce().then((value) => {
      // A provider retired between the answer and here caches nothing: whoever asks next is told it is
      // gone, and a token for a closed grant is not kept in memory either.
      if (!retired) cached = value;
      return value;
    });
    pending = attempt;
    try {
      const value = await attempt;
      if (retired) throw retiredError();
      return { accessToken: value.accessToken, expiresAt: value.expiresAt };
    } finally {
      if (pending === attempt) pending = null;
    }
  }

  /**
   * End this provider for good. The registry calls this from `forget()`: the account's rows are going,
   * or a fresh grant has replaced the one this provider holds. Everything cached is dropped here, and
   * any refresh still in the air is discarded when it answers (see `refreshOnce`), so no NEW rotation
   * write starts for a grant that no longer exists.
   *
   * A keychain write that was already in the air is NOT cancelled: it is handed back as the promise this
   * answers, so `forget()` resolves after the row landed and the caller's delete of the sealed secrets
   * runs after it — the other order would leave a fresh token for the account it just removed. The
   * promise never rejects. Idempotent, and never throws.
   *
   * @returns {Promise<void>} settles once the in-flight rotation write (if any) has settled
   */
  tokenProvider.retire = function retire() {
    retired = true;
    authFailed = false;
    cached = null;
    rotatedRefreshToken = null;
    unsavedRotation = false;
    // Whoever is waiting on the in-flight refresh keeps its promise; the result is thrown away there.
    pending = null;
    accountRow = null;
    const settling = inflightWrite ?? Promise.resolve();
    return settling.then(() => undefined, () => undefined);
  };

  return tokenProvider;
}