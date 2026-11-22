/**
 * Crow Mail's per-account token provider registry: one provider per mail account, built the first time
 * anything needs a token for that account and kept for the life of the process.
 *
 * There is exactly one provider object per account because the provider itself is stateful in a way
 * that only works when it is shared: the cached access token, the refresh in flight, the "the grant is
 * dead" flag and a rotated refresh token that has not reached the keychain yet. Two providers for one
 * account would mean two refreshes racing (and one rotated refresh token lost), a dead grant asked
 * again on every connection, and a rotation retry that only half the callers know about. So
 * `tokenProviderFor(accountId)` answers the SAME function object every time it is asked, and every path
 * that signs in — the sync worker, the supervisor's short-lived action adapters, a send, the API's own
 * fallback factory — asks the registry rather than building its own.
 *
 * The rotation writer is `createRotationWriter(credentials)` (mail/credentials.js), bound once for all
 * accounts: it writes MAIL_REFRESH_TOKEN and nothing else. Nothing here writes an access token
 * anywhere, and no function in this module reads a secret directly — a provider reads only when it
 * refreshes, through the credentials reader it was built with.
 *
 * `markAuthFailed` is the caller's own hook, and the registry passes NONE by default. The provider keeps
 * its own in-memory latch (no call asks the provider again after `invalid_grant`), and the account's
 * `auth_failed` transition — with the one notice that goes with it — belongs to the sync supervisor:
 * it is the only writer that knows whether the account was already marked, and `recordAuthFailure`
 * only rings the bell when the account ENTERS `auth_failed`. A registry write here would land before
 * the error reached the supervisor, so the supervisor would find the account already marked and stay
 * silent — a dead grant would never ring the bell at all. A caller that really wants its own write (a
 * test, or a future surface with no supervisor) can still pass one.
 *
 * `forget(accountId)` RETIRES one account's provider and then drops it: the account was removed, or a
 * fresh grant replaced the old one, and the new grant must not inherit the old provider's cache or its
 * dead-grant flag. Retiring is what makes that safe for a refresh that is still in flight — a forgotten
 * provider's answer is discarded and starts no new rotation write, so a rotated token cannot outlive a
 * deleted account, nor an old grant's token overwrite the new grant's. `forget()` answers a PROMISE that
 * settles after a keychain write that was already in the air: the caller (the account's DELETE) awaits
 * it before deleting the sealed secrets, so the row that write created is the one it removes. The next
 * call builds a fresh provider.
 */
import { createRotationWriter } from "../credentials.js";
import { getAccount } from "../store/accounts.js";
import { getOauthMeta } from "./meta.js";
import { createTokenProvider } from "./token-provider.js";

/**
 * The registry.
 *
 * @param {object} options
 * @param {object} options.db the crow.db client (the account store's, the settings' and the meta's)
 * @param {{getSecrets: Function, saveSecret: Function}} options.credentials the sealed keychain reader
 * @param {Function} [options.fetchImpl] the HTTP transport; `globalThis.fetch` by default
 * @param {() => number} [options.now] the clock every provider caches against
 * @param {(accountId: string) => unknown} [options.markAuthFailed] the caller's own hook for a dead
 *   grant; NONE by default (the sync supervisor owns the account's transition and its notice)
 * @param {{tokenUrl?: string}} [options.endpoints] TEST ONLY: point the token POST at a fake provider
 * @param {(line: {event: string, code?: string}) => void} [options.log] receives codes only
 * @returns {{tokenProviderFor: (accountId: string) => Function|null, forget: (accountId: string) => Promise<void>}}
 */
export function createTokenProviderRegistry(options = {}) {
  const {
    db,
    credentials,
    fetchImpl = globalThis.fetch,
    now,
    markAuthFailed,
    endpoints,
    log,
  } = options;

  if (!db || typeof db.execute !== "function") {
    throw new TypeError("createTokenProviderRegistry needs a db client");
  }
  if (!credentials || typeof credentials.getSecrets !== "function" || typeof credentials.saveSecret !== "function") {
    throw new TypeError("createTokenProviderRegistry needs a credentials reader");
  }

  /** One provider per account id. A `Map`, so the same account always answers the same object. */
  const providers = new Map();

  const rotationWriter = createRotationWriter(credentials);
  // Nothing marks an account by default: the provider's latch is enough to stop asking, and the
  // supervisor's own recordAuthFailure is what writes `auth_failed` and rings the one bell.
  const refuse = typeof markAuthFailed === "function" ? markAuthFailed : null;

  return {
    /**
     * The provider for one account, built on first use and kept. An id that is not an account id at all
     * answers null: the caller's factory then signs in with no provider, which is AUTH_FAILED rather
     * than a provider call for something that is not a mailbox.
     *
     * @param {string} accountId
     * @returns {Function|null}
     */
    tokenProviderFor(accountId) {
      if (typeof accountId !== "string" || accountId === "") return null;
      const existing = providers.get(accountId);
      if (existing != null) return existing;
      const created = createTokenProvider({
        accountId,
        getAccount: (id) => getAccount(db, id),
        credentials,
        fetchImpl,
        now,
        markAuthFailed: refuse,
        onTokenRotated: rotationWriter,
        endpoints,
        getMeta: (id) => getOauthMeta(db, id),
        log,
      });
      providers.set(accountId, created);
      return created;
    },

    /**
     * Forget one account's provider: the account was removed, or a new grant replaced the old one. The
     * provider is RETIRED before it is dropped, so a refresh already in flight starts no new rotation
     * write (for an account that is going, or over a new grant's token). The next call builds a fresh
     * provider — fresh cache, no dead-grant flag, no in-memory rotation.
     *
     * The answer settles after a rotation write that was already in the air, so a caller that is about
     * to delete the account's sealed secrets (DELETE /accounts/:id) awaits it first and cannot leave the
     * token of a removed account behind. It never rejects, and it answers at once when nothing is in
     * flight.
     *
     * @param {string} accountId
     * @returns {Promise<void>}
     */
    forget(accountId) {
      if (typeof accountId !== "string" || accountId === "") return Promise.resolve();
      const provider = providers.get(accountId) ?? null;
      providers.delete(accountId);
      if (provider == null || typeof provider.retire !== "function") return Promise.resolve();
      try {
        return Promise.resolve(provider.retire()).then(() => undefined, () => undefined);
      } catch {
        // Retiring is bookkeeping: the entry is gone either way, and a caller's delete goes ahead.
        return Promise.resolve();
      }
    },

    /** How many providers are alive (a test's window into the cache; nothing in the app reads it). */
    size() {
      return providers.size;
    },
  };
}