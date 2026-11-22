/**
 * Crow Mail's account connect — the one sequence by which a mailbox becomes an account on this Crow —
 * and its sibling, the reconnect that replaces an existing account's secrets.
 *
 * `POST /dashboard/mail/api/accounts` used to own the connect sequence inline. It lives here so plan
 * 5's OAuth callback runs the SAME sequence instead of a second copy that drifts: one account is one
 * row, one claim and one set of sealed secrets, and the order that makes that true is worth having in
 * exactly one place.
 *
 * `connectAccount(db, deps, {draft, secrets, authKind, tokenProvider})`, in this order, each step
 * refusing before the next can store anything:
 *
 *   1. **The secrets are read first.** Every key must be one of `MAIL_SECRET_KEYS` (a key that is not
 *      is BAD_INPUT/`env_key`, before a row is read), and every value a non-empty string. A connect
 *      stores ALL of them: a password account's `MAIL_PASSWORD`, or an OAuth account's
 *      `MAIL_REFRESH_TOKEN` and the app registration it refreshes with.
 *   2. **A duplicate address is refused before anything dials** — the store's own identity rule
 *      (lower-cased) is this rule — and it is refused before the secret is even masked, so a second
 *      connect for one mailbox leaves no trace of the password that was typed.
 *   3. **Every secret value joins the masking set** (`deps.recordSecrets`, before any path can write
 *      it to a log). A recorder that cannot write its file is logged by code and never fails a
 *      connect.
 *   4. **The claim is checked**: an address another live instance holds is CLAIMED_ELSEWHERE, naming
 *      that instance for the one fixed sentence the owner sees. Nothing is dialled and nothing stored.
 *   5. **The probe** (`mail/probe.js`: sign in, list the folders, close) is what makes a refused
 *      sign-in leave no account, no secret and no claim behind. A password account is probed with a
 *      credentials reader answering with the secrets just handed in — exactly what the adapter factory
 *      would read from the keychain. An OAuth account is probed with the ONE token the caller gives
 *      (`tokenProvider`), never with the registry's: the account does not exist yet, so the registry
 *      has no provider for it, and a one-shot provider for a grant that has not been stored is
 *      precisely what the wizard has in hand.
 *   6. **The row is created** (`authKind`, and `draft.provider` / `draft.sentCopy` when the draft
 *      carries them). A duplicate that slipped past step 2 is the same BAD_INPUT/`address` refusal.
 *   7. **Then, inside ONE `try`:** one `saveSecret` per key, the claim write, the re-check, and — for an
 *      OAuth connect — the grant's non-secret label (`oauthMeta`, written by `setOauthMeta`). A claim
 *      written a moment ago can still lose to one another instance wrote concurrently (the winner is
 *      computed from the whole set), and the re-check itself can fail — a database fault there must
 *      undo the connect too, never leave the account, its secrets and the claim behind as a
 *      half-connected address peers see as held here. The undo is `undoConnect` (every secret under
 *      the account id, then the row) plus `releaseClaimQuietly`, and it is the one bug #62 was about.
 *   8. **A lost re-check is the same undo**, and answers CLAIMED_ELSEWHERE carrying the winner's name.
 *   9. **Only then** is the first sync started, in the background (`startBackgroundSync`).
 *
 *      The label is written HERE, inside that undo, and BEFORE the first sync exists — never after it
 *      by the caller: a Microsoft account's first refresh reads its tenant from the meta row, so a
 *      sync started first would refresh against `common`, and one whose meta write failed would stay
 *      on `common` for the life of the grant. An OAuth connect whose meta cannot be written is a
 *      connect that did not happen: the same undo removes the account, its secrets and its claim.
 *
 * `reconnectAccount(db, deps, {accountId, secrets, oauthMeta, tokenProvider})` keeps the account: the
 * claim must still be held locally — checked before the probe and READ AGAIN after it, immediately
 * before anything is swapped, because a claim can be taken while the probe runs — and a lost claim is a
 * fixed CLAIMED_ELSEWHERE refusal that swaps nothing. Then the account's sync worker is QUIESCED
 * (`supervisor.stopAccount`, awaited, the same call the account's DELETE makes), because a running
 * worker's adapter resolves `tokenProviderFor(id)` on every use and the registry builds a FRESH provider
 * after `forget()` — one that reads the keychain, which still holds the OLD refresh token until the swap
 * below. A refresh made in that window holds the old grant, and with a provider that rotates (Microsoft
 * does) it would write the OLD grant's rotated token over the fresh one. So, in this order: stop the
 * worker, `forget` (awaited), write the new grant's label, one `saveSecret` per key — deleting the old
 * `MAIL_OAUTH_CLIENT_SECRET` when the new grant names none, because the pair is sealed together — and
 * `forget` again, so anything built by a stray request in the meantime cannot outlive the swap. Then the
 * row is marked `active` and its worker restarted (`restartAccount`, else `syncNow`), which starts it
 * again and is itself a full sync with the new secret. A swap that fails after the quiesce starts the
 * worker again on the secrets still stored, so a failed reconnect never leaves the account unsynced.
 * `statusDetail` is cleared with the status, so an `auth_failed` account carries no stale detail once it
 * signs in again.
 *
 * The deps seams are the API router's own, resolved the same way here so a test may drive either
 * entry point: `claims` (any function it leaves out stays the real one), `credentials` (the sealed
 * keychain reader; built from `db` when absent), `adapterFactory` (the probe's factory),
 * `oauthAdapterFactory` (the probe's factory for an OAuth account — a TEST seam: production builds the
 * real adapter with the one-shot provider), `supervisor` (a value, possibly null: a connect without
 * sync still connects), `localInstance` (`{instanceId, instanceName}` or `(db) => …`), `recordSecrets`,
 * `setOauthMeta` (the grant's label writer), and `forgetTokenProvider` for a reconnect. Nothing here
 * reads a secret from the keychain to make a decision, and no function here returns one.
 */
import { recordServiceSecretValues } from "../../../shared/secret-values.js";
import { withoutWriteContext } from "../../../shared/history/write-context.js";
import { cleanPeerName } from "../../../shared/peer-label.js";
import { getInstance, getOrCreateLocalInstanceId } from "../../instance-registry.js";
import { createImapSmtpAdapter } from "../adapter/imap-smtp.js";
import { checkClaim, releaseClaim, writeClaim } from "../claims.js";
import { createMailCredentials, MAIL_SECRET_KEYS } from "../credentials.js";
import { MailError, toMailError } from "../errors.js";
import { setOauthMeta } from "../oauth/meta.js";
import { probeAccount } from "../probe.js";
import { createAccount, deleteAccount, getAccount, listAccounts, updateAccount } from "../store/accounts.js";

/** The only env keys a connect may store. Nothing else is ever written under an account id. */
const SECRET_KEYS = new Set(MAIL_SECRET_KEYS);

/* ------------------------------------------------------------------ helpers */

function fail(field) {
  throw new MailError("BAD_INPUT", field);
}

/** A route's failure in the log: the code only, so no value can travel with it. */
export function logCode(route, err) {
  try {
    console.warn(`[mail-api] ${route}: ${toMailError(err).code}`);
  } catch {
    // A log line is never worth failing a request or a connect over.
  }
}

/** Is this the store's own "two rows, one address" refusal? The answer is `duplicate_address`. */
export function isDuplicateAddress(err) {
  return err instanceof MailError && err.code === "BAD_INPUT" && err.detail === "address";
}

/**
 * One account's secrets as `[[envKey, plaintext]]`, or BAD_INPUT naming the field that is wrong — a
 * key that is not one of `MAIL_SECRET_KEYS` (nothing else is ever sealed under an account id), a value
 * that is not a non-empty string, and a connect that names no secret at all.
 */
function readSecrets(secrets) {
  if (secrets == null || typeof secrets !== "object" || Array.isArray(secrets)) fail("secrets");
  const entries = Object.entries(secrets);
  if (entries.length === 0) fail("secrets");
  for (const [key, value] of entries) {
    if (!SECRET_KEYS.has(key)) fail("env_key");
    if (typeof value !== "string" || value === "") fail("secret");
  }
  return entries;
}

/** The account's auth kind: `password` when the caller names none, and the two the store knows. */
function readAuthKind(value) {
  if (value === undefined || value === null || value === "") return "password";
  if (value === "password" || value === "xoauth2") return value;
  fail("auth_kind");
}

/* ---------------------------------------------------------------- the seams */

/** The credentials reader: the caller's, or the sealed keychain of this database. */
export function credentialsFor(db, deps = {}) {
  if (deps.credentials != null) return deps.credentials;
  return createMailCredentials({ db });
}

/** The claim code: a partial stand-in keeps the real function for whatever it leaves out. */
const REAL_CLAIMS = Object.freeze({ checkClaim, writeClaim, releaseClaim });

export function claimsFor(deps = {}) {
  const claims = deps.claims;
  if (claims == null) return REAL_CLAIMS;
  return {
    checkClaim: typeof claims.checkClaim === "function" ? claims.checkClaim : checkClaim,
    writeClaim: typeof claims.writeClaim === "function" ? claims.writeClaim : writeClaim,
    releaseClaim: typeof claims.releaseClaim === "function" ? claims.releaseClaim : releaseClaim,
  };
}

/** This instance's id and the name its own registry row carries (never an address or a mailbox host). */
async function defaultLocalInstance(db) {
  const instanceId = getOrCreateLocalInstanceId();
  let instanceName = "";
  try {
    const row = await getInstance(db, instanceId);
    instanceName = cleanPeerName(row?.name);
  } catch {
    instanceName = "";
  }
  return { instanceId, instanceName };
}

export function localInstanceFor(db, deps = {}) {
  if (typeof deps.localInstance === "function") return deps.localInstance(db);
  if (deps.localInstance != null) return Promise.resolve(deps.localInstance);
  return defaultLocalInstance(db);
}

/** The masking recorder: this instance's own secret-value set, or a test's. */
function recordSecretsFor(deps = {}) {
  return typeof deps.recordSecrets === "function" ? deps.recordSecrets : recordServiceSecretValues;
}

/** The grant label's writer: the caller's seam (a test's throwing writer), or the real one. */
function oauthMetaWriterFor(deps = {}) {
  return typeof deps.setOauthMeta === "function" ? deps.setOauthMeta : setOauthMeta;
}

/**
 * Every secret value joins the masking set before any path can write it to a log. A recorder that
 * cannot write its file is logged by code: it must never fail a connect or echo the value.
 */
async function maskSecrets(deps, entries) {
  try {
    await recordSecretsFor(deps)(entries.map(([, value]) => value));
  } catch (err) {
    logCode("record_secret", err);
  }
}

/** The probe's factory for a password account: the caller's, or the real adapter with no provider. */
function passwordProbeFactory(deps) {
  if (typeof deps.adapterFactory === "function") return deps.adapterFactory;
  return ({ account, credentials }) => createImapSmtpAdapter({ account, credentials });
}

/**
 * The probe's factory for an OAuth account. The registry's provider is never used: the account does
 * not exist yet, so `deps.tokenProviderFor(account.id)` answers nothing, and the grant being proved
 * is the one the caller just traded for. `deps.oauthAdapterFactory` is the TEST seam, handed the same
 * one-shot provider as its third argument; production builds the real adapter with it.
 */
function oauthProbeFactory(deps, tokenProvider) {
  if (typeof deps.oauthAdapterFactory === "function") {
    return (args) => deps.oauthAdapterFactory({ ...args, tokenProvider });
  }
  return ({ account, credentials }) => createImapSmtpAdapter({ account, credentials, tokenProvider });
}

function probeFactoryFor(deps, authKind, tokenProvider) {
  return authKind === "xoauth2" ? oauthProbeFactory(deps, tokenProvider) : passwordProbeFactory(deps);
}

/**
 * Is this address already connected here? The same identity the store's UNIQUE COLLATE NOCASE column
 * enforces, checked before anything is dialled: a second account for one mailbox is the owner's input,
 * not a server's verdict, so the probe at the far end of the world need not be asked at all.
 */
async function addressTaken(db, address) {
  const wanted = String(address ?? "").trim().toLowerCase();
  if (!wanted) return false;
  for (const account of await listAccounts(db)) {
    if (String(account.address).trim().toLowerCase() === wanted) return true;
  }
  return false;
}

/** The account row a probe connects: the values just typed, with no stored id behind them. */
function probeRow(draft, authKind) {
  return {
    id: "probe",
    label: draft.label,
    address: draft.address,
    username: draft.username ?? null,
    authKind,
    provider: draft.provider ?? null,
    imap: draft.imap,
    smtp: draft.smtp,
  };
}

/** The credentials reader a probe is handed: the secrets just typed, for that one connect. */
function probeCredentials(secrets) {
  return { getSecrets: async () => ({ ...secrets }) };
}

/** The columns a connect knows. The store validates every one of them again. */
function createInput(draft, authKind) {
  const input = {
    label: draft.label,
    address: draft.address,
    username: draft.username,
    authKind,
    imap: draft.imap,
    smtp: draft.smtp,
  };
  if (draft.provider !== undefined && draft.provider !== null) input.provider = draft.provider;
  if (draft.sentCopy !== undefined && draft.sentCopy !== null) input.sentCopy = draft.sentCopy;
  return input;
}

/** A claim somebody else holds, as the refusal the caller sees. `instanceName` is for that sentence. */
function claimedElsewhere(instanceName) {
  const err = new MailError("CLAIMED_ELSEWHERE");
  // The loser's display name, so the route can answer "already connected on <name>". Never a detail:
  // a name is not one of the allow-listed tokens an error may carry.
  err.instanceName = typeof instanceName === "string" ? instanceName : "";
  return err;
}

/** Undo a connect that could not be finished: every secret, then the account. Best effort, code-logged. */
async function undoConnect(db, credentials, accountId) {
  try {
    await credentials.deleteSecrets(accountId);
  } catch (err) {
    logCode("undo_secret", err);
  }
  try {
    await deleteAccount(db, accountId);
  } catch (err) {
    logCode("undo_account", err);
  }
}

async function releaseClaimQuietly(claims, db, address, localInstanceId) {
  try {
    await claims.releaseClaim(db, address, { localInstanceId });
  } catch (err) {
    logCode("undo_claim", err);
  }
}

/**
 * A sync outlives the request (or the wizard) that asked for it, so it is opened with no write
 * context: otherwise every row it wrote later would be attributed to the sign-in that happened to
 * click Connect (see the `withoutWriteContext` note in servers/gateway/dashboard/auth.js). Its failure
 * is the supervisor's to report, not this module's.
 */
export function startBackgroundSync(supervisor, accountId) {
  if (!supervisor || typeof supervisor.syncNow !== "function") return;
  withoutWriteContext(() => {
    Promise.resolve()
      .then(() => supervisor.syncNow(accountId))
      .catch((err) => logCode("background_sync", err));
  });
}

/**
 * The reconnect's half of the same idea: `restartAccount` ends the old secret's run, drops both of its
 * connections and starts one fresh full sync; a supervisor with no restart gets the sync on its own.
 * Background and code-logged, like `startBackgroundSync` — the secrets are already swapped, and a
 * restart that fails is the supervisor's to report.
 */
function restartInBackground(supervisor, accountId, label) {
  if (!supervisor) return;
  const restart = typeof supervisor.restartAccount === "function" ? supervisor.restartAccount.bind(supervisor) : null;
  const syncNow = restart === null && typeof supervisor.syncNow === "function" ? supervisor.syncNow.bind(supervisor) : null;
  if (restart === null && syncNow === null) return;
  withoutWriteContext(() => {
    Promise.resolve()
      .then(() => (restart ? restart(accountId) : syncNow(accountId)))
      .catch((err) => logCode(label, err));
  });
}

/**
 * Retire the account's cached OAuth provider and WAIT for it, when the caller gave the hook. A
 * provider's in-flight rotation write has landed by the time this resolves, so the secrets written
 * after it are the ones the account keeps. Never a reason to fail a reconnect: a service that is not
 * running has nothing to forget, and the hook's own promise never rejects.
 */
async function forgetTokenProviderFor(deps, accountId, label) {
  if (typeof deps.forgetTokenProvider !== "function") return;
  try {
    await deps.forgetTokenProvider(accountId);
  } catch (err) {
    logCode(label, err);
  }
}

/**
 * QUIESCE the account's sync worker before a swap, and say whether it was stopped.
 *
 * A running worker's adapter asks the registry for the account's provider on EVERY use
 * (`tokenProviderFor(id)`), and the registry builds a fresh provider after `forget()` — one that reads
 * the keychain, which still holds the OLD refresh token until the swap's saves land. A refresh made in
 * that window holds the old grant, and a provider that rotates (Microsoft's does) would then write the
 * OLD grant's rotated token over the fresh one. Stopping the worker first closes that window; this is
 * the same awaited call the account's DELETE makes, with its own writes attributed to nothing.
 *
 * A supervisor from before this call existed, or a test double without it, has nothing to stop: the
 * reconnect then falls back to retire → swap → retire. Never a reason to fail a reconnect.
 *
 * @returns {Promise<boolean>} whether a worker was stopped
 */
async function quiesceWorkerForSwap(deps, accountId) {
  const supervisor = deps.supervisor ?? null;
  if (!supervisor || typeof supervisor.stopAccount !== "function") return false;
  try {
    await withoutWriteContext(() => supervisor.stopAccount(accountId));
    return true;
  } catch (err) {
    logCode("reconnect_stop", err);
    return false;
  }
}

/* ------------------------------------------------------------------ connect */

/**
 * Connect one mailbox: the account row, its secrets and its claim, or nothing at all.
 *
 * @param {object} db the crow.db client
 * @param {object} [deps] the API router's own seams (see the module comment)
 * @param {{draft: object, secrets: Record<string, string>, authKind?: string,
 *   tokenProvider?: Function|null, oauthMeta?: object|null}} options `draft` is the account the caller
 *   wants (label, address, username, imap, smtp, and for an OAuth account `provider` and `sentCopy`);
 *   `secrets` is every secret to seal, keyed by `MAIL_SECRET_KEYS`; `tokenProvider` is the OAuth
 *   wizard's one-shot provider, and is refused for an OAuth connect that names none; `oauthMeta` is the
 *   grant's label (`{grantedAt, publishing, provider, tenant?}`), written before the first sync and
 *   undone with the rest of the connect if it cannot be written.
 * @returns {Promise<object>} the stored account (the store's own row; no secret on it)
 */
export async function connectAccount(db, deps = {}, options = {}) {
  if (!db || typeof db.execute !== "function") throw new TypeError("connectAccount needs a db client");
  const { draft, secrets, authKind = "password", tokenProvider = null, oauthMeta = null } = options || {};
  if (draft == null || typeof draft !== "object" || Array.isArray(draft)) fail("account");
  const entries = readSecrets(secrets);
  const kind = readAuthKind(authKind);
  if (kind === "xoauth2" && typeof tokenProvider !== "function") fail("token_provider");

  // One mailbox is one account here, and a duplicate leaves no trace of what was typed: this runs
  // before the probe and before the secret is even masked.
  if (await addressTaken(db, draft.address)) fail("address");
  const local = await localInstanceFor(db, deps);

  // Before the claim read can fail, and before the probe can put a secret in a library's message.
  await maskSecrets(deps, entries);

  const claims = claimsFor(deps);
  const claim = await claims.checkClaim(db, draft.address, { localInstanceId: local.instanceId });
  if (!claim.ok) throw claimedElsewhere(claim.instanceName);

  // Before anything is stored: a refused sign-in leaves no account, no secret and no claim behind.
  await probeAccount({
    adapterFactory: probeFactoryFor(deps, kind, tokenProvider),
    account: probeRow(draft, kind),
    credentials: probeCredentials(secrets),
  });

  const credentials = credentialsFor(db, deps);
  // A duplicate that slipped past the check above (or one that landed in between) travels as the
  // store's own BAD_INPUT/`address`, which the route answers as `duplicate_address`.
  let account = await createAccount(db, createInput(draft, kind));

  // The re-check belongs to this same failure handling: a claim written a moment ago can still lose to
  // one another instance wrote concurrently, and the re-check itself can fail — a DB fault there must
  // undo the connect too, never leave the account, its secrets and the claim behind as a half-connected
  // address peers see as held here. The grant's label is written in here as well, before the first sync
  // is started: see the module comment.
  let after;
  try {
    // A Sent-copy rule is a post-create setting in the store (`createAccount` writes only the columns
    // a connect knows), so a draft that carries one has it applied here — inside this try, so a
    // refused value undoes the whole connect rather than leaving an account with half its settings.
    if (draft.sentCopy !== undefined && draft.sentCopy !== null) {
      account = await updateAccount(db, account.id, { sentCopy: draft.sentCopy }) ?? account;
    }
    for (const [envKey, value] of entries) await credentials.saveSecret(account.id, envKey, value);
    await claims.writeClaim(db, draft.address, { localInstanceId: local.instanceId, instanceName: local.instanceName });
    after = await claims.checkClaim(db, draft.address, { localInstanceId: local.instanceId });
    // A lost claim: nothing of this connect may remain, so it takes the same undo as a failed write.
    if (!after.ok) throw claimedElsewhere(after.instanceName);
    // The grant's non-secret label, before there is a sync to read it: a Microsoft refresh takes its
    // tenant from this row, so a label written after the sync started would not reach the first refresh.
    if (oauthMeta != null) await oauthMetaWriterFor(deps)(db, account.id, oauthMeta);
  } catch (err) {
    await undoConnect(db, credentials, account.id);
    await releaseClaimQuietly(claims, db, draft.address, local.instanceId);
    throw err;
  }

  startBackgroundSync(deps.supervisor ?? null, account.id);
  return account;
}

/* --------------------------------------------------------------- reconnect */

/**
 * Replace an existing account's secrets — the "sign in again" path — and keep everything else.
 *
 * The account id, the row, its claim and its synced mail are untouched: only the sealed secrets are
 * swapped, one `saveSecret` per key, plus the one deletion a grant that names no client secret needs.
 * An account another instance has claimed since is refused with the fixed CLAIMED_ELSEWHERE sentence
 * and nothing is swapped — the address (and its mail) belongs to the other instance now, and a fresh
 * password would not change that. The claim is read before the probe AND again after it: a claim taken
 * while the probe ran is the same refusal, and nothing is stopped, retired or written for it.
 *
 * The worker is quiesced before the swap and started again after it, and the callers' `oauthMeta` (the
 * new grant's label) is written before the worker comes back: see the module comment.
 *
 * @param {object} db the crow.db client
 * @param {object} [deps] the API router's own seams, plus `forgetTokenProvider` and (for the label)
 *   `setOauthMeta`
 * @param {{accountId: string, secrets: Record<string, string>, tokenProvider?: Function|null,
 *   oauthMeta?: object|null}} options `tokenProvider` is given only by a wizard that just traded a
 *   fresh OAuth grant: the probe runs before the token is stored, so an OAuth reconnect without one is
 *   proved through the caller's own factory (the API router's resolves the registry's provider for an
 *   account that really exists), and a password account needs no provider at all. `oauthMeta` is the
 *   new grant's non-secret label; a write that fails is a reconnect that did not happen, and the
 *   worker — stopped for the swap — is started again on the secrets still stored.
 * @returns {Promise<object>} the updated account (status `active`, no detail)
 */
export async function reconnectAccount(db, deps = {}, options = {}) {
  if (!db || typeof db.execute !== "function") throw new TypeError("reconnectAccount needs a db client");
  const { accountId, secrets, tokenProvider = null, oauthMeta = null } = options || {};
  const entries = readSecrets(secrets);
  const account = await getAccount(db, accountId);
  if (!account) throw new MailError("NOT_FOUND");

  const local = await localInstanceFor(db, deps);
  const claims = claimsFor(deps);
  // The fixed refusal: the address is not ours to re-key any more, and nothing is swapped.
  const claim = await claims.checkClaim(db, account.address, { localInstanceId: local.instanceId });
  if (!claim.ok) throw new MailError("CLAIMED_ELSEWHERE");

  await maskSecrets(deps, entries);

  // Proved before anything is stored, on a reader holding only the new secrets: a refused sign-in
  // leaves the stored secret and the account exactly as they were. A one-shot provider (a fresh grant)
  // is the wizard's; without one the probe runs through the caller's own factory, which for a real
  // account id is the one that resolves the registry's provider.
  await probeAccount({
    adapterFactory: typeof tokenProvider === "function"
      ? oauthProbeFactory(deps, tokenProvider)
      : passwordProbeFactory(deps),
    account,
    credentials: probeCredentials(secrets),
  });

  // The row can have been removed while the probe ran: an id that names no account has nothing to
  // store a secret for, and the secrets go the way the delete path takes them rather than staying
  // behind under an id nothing owns.
  if (!(await getAccount(db, accountId))) {
    const stale = credentialsFor(db, deps);
    try {
      await stale.deleteSecrets(accountId);
    } catch (err) {
      logCode("reconnect", err);
    }
    throw new MailError("NOT_FOUND");
  }

  // The claim can have been taken WHILE the probe ran (the probe dials a mailbox at the far end of the
  // world, and a peer's user may have added the address in the meantime). So it is read AGAIN here,
  // after the probe and immediately before anything is swapped: a claim taken in between is the same
  // fixed refusal, and nothing is stopped, retired or written for a swap that must not happen.
  const stillOurs = await claims.checkClaim(db, account.address, { localInstanceId: local.instanceId });
  if (!stillOurs.ok) throw new MailError("CLAIMED_ELSEWHERE");

  // The worker is QUIESCED before the swap and started again at the end: a running worker's adapter
  // resolves `tokenProviderFor(id)` on every use, and the registry builds a FRESH provider after
  // `forget()` — one that reads the keychain, which still holds the OLD refresh token until the saves
  // below. A refresh made in that window holds the old grant, and with a provider that rotates
  // (Microsoft's does) it would write that grant's rotated token over the fresh one. This is the same
  // awaited call the account's DELETE makes.
  await quiesceWorkerForSwap(deps, accountId);

  const credentials = credentialsFor(db, deps);
  const hasClientSecret = entries.some(([envKey]) => envKey === "MAIL_OAUTH_CLIENT_SECRET");
  let updated;
  try {
    // Retired and AWAITED before the new secrets land: the old provider's rotation write (if one was in
    // the air) has settled, so it cannot land on top of the fresh grant — the rule DELETE follows for
    // the same reason. A fresh grant must not inherit the old provider's cache or its dead-grant flag.
    await forgetTokenProviderFor(deps, accountId, "forget_token_provider");

    // The new grant's label, before the worker exists again: a Microsoft refresh reads its tenant from
    // this row, and the worker restarted at the end of this function is the first thing to ask. A write
    // that cannot land is a reconnect that did not happen — nothing is swapped.
    if (oauthMeta != null) await oauthMetaWriterFor(deps)(db, accountId, oauthMeta);

    for (const [envKey, value] of entries) await credentials.saveSecret(accountId, envKey, value);

    // A grant that names no client secret must not keep the old registration's: the pair is sealed
    // together, and the old secret belongs to a client the new grant may not even use. One key, nothing
    // else (a password account never has it, so this never runs for one).
    if (account.authKind === "xoauth2" && !hasClientSecret) {
      await credentials.deleteSecret(accountId, "MAIL_OAUTH_CLIENT_SECRET");
    }

    // Retired AGAIN, after the fresh secrets landed: anything a stray request (an API adapter, a reader)
    // built between the retire above and these saves read the OLD grant out of the keychain, and a
    // provider that outlived the swap would spend — and write — that dead grant. The worker restarted
    // below therefore builds its provider from the new grant.
    await forgetTokenProviderFor(deps, accountId, "forget_token_provider");

    updated = await updateAccount(db, accountId, { status: "active", statusDetail: null });
  } catch (err) {
    // The worker was stopped for a swap that did not happen: it is started again on the secrets still
    // stored, so a failed reconnect never leaves the account unsynced.
    restartInBackground(deps.supervisor ?? null, accountId, "reconnect_restart");
    throw err;
  }

  if (!updated) {
    // Removed between the check above and the status write: the secret must not outlive the row.
    try {
      await credentials.deleteSecrets(accountId);
    } catch (err) {
      logCode("reconnect", err);
    }
    throw new MailError("NOT_FOUND");
  }

  restartInBackground(deps.supervisor ?? null, accountId, "reconnect_restart");
  return updated;
}

export default connectAccount;