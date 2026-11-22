/**
 * Crow Mail's OAuth wizard routes and the callback that finishes a sign-in (plan 5, Task 4b).
 *
 * Five routes, and nothing else:
 *
 *   GET  /dashboard/mail/api/oauth/redirect-uri   the exact URI the provider must be told about
 *   POST /dashboard/mail/api/oauth/check          the wizard's per-step checks (client id, redirect)
 *   POST /dashboard/mail/api/oauth/start           validates, keeps the secrets in the flow store, mints
 *                                                  the authorization URL
 *   GET  /dashboard/mail/oauth/callback           the provider's redirect: exchange, connect, redirect
 *   POST /dashboard/mail/api/accounts/:id/selftest the optional one-message self-test
 *
 * Four of them live under `/dashboard/mail/api`, so `mail-api.js` has already mounted the whole chain on
 * them (dashboard session, no-store, `CROW_MAIL` 404, the owner rule, the dashboard's CSRF rail and this
 * router's own 64 KB JSON parser). The callback is NOT under `/api` — it is the URL a provider sends a
 * browser to — so it carries the same chain itself, in the same order, and is a plain GET (the dashboard
 * session cookie is `SameSite=Lax`, which is exactly what makes that work; it is never changed to
 * `Strict`, or the callback would lose its session). Its own Funnel refusal runs even when
 * `CROW_DASHBOARD_PUBLIC=true` has opened the gateway-wide middleware: a provider redirect must never be
 * served from the public internet.
 *
 * **The flow store is the whole memory of a sign-in.** `start` mints a state token and keeps the PKCE
 * verifier, the client id and secret, the exact redirect URI, the tenant and the account draft under it,
 * in memory, keyed to the dashboard session id (`mail/oauth/state.js`). The client id and secret live
 * nowhere else until the callback has traded the code. The callback spends the token once
 * (`take(state, sessionId)`) before it reads the code, the error parameter or anything else, so a
 * missing, wrong, expired, reused or other-session state is one answer — `oauth_expired` — and stores
 * nothing. A provider `error` (the person pressed Deny) is `oauth_denied`, also storing nothing.
 *
 * **Success is `connectAccount`'s, not a second copy of it.** The callback trades the code for an access
 * token and a refresh token, records every one of them with the masking recorder before the account
 * store, the probe or the mailbox connection sees them, and hands `mail/accounts/connect.js` the same
 * draft and secrets a password connect
 * gets — plus a ONE-SHOT token provider built from the access token just issued, so the probe never asks
 * the account-keyed registry, which has no provider for an account that does not exist yet (or, on a
 * reconnect, has the dead grant's). The connect's own undo is what makes a failed probe store nothing.
 * A reconnect (`reconnectAccountId`) goes through `reconnectAccount`, which keeps the account id, its
 * claim and its mail and swaps only the sealed secrets. The grant's non-secret label
 * (`mail/oauth/meta.js`) is handed to that call as `oauthMeta` and stored by it BEFORE the first sync
 * (or the restarted worker) exists: a Microsoft refresh reads its tenant from that row, so the label
 * has to be there first, and a label that cannot be written fails the whole sign-in. Then the browser
 * is sent back to the settings view with a fixed status key.
 *
 * **A reconnect may name no registration at all.** The settings card's one Reconnect button (plan 5,
 * Task 6) posts `reconnectAccountId`, the address it shows and the provider — and no `clientId` — so
 * the registration is read server-side from the sealed keychain, exactly as the stored client secret
 * already is. Nothing about the registration, and no secret, has to be on the page for a sign-in that
 * already happened once; a page that DOES name a client id (the bring-your-own-key path) is answered as
 * before, and a page that names one of the wrong shape is still refused.
 *
 * Nothing here writes prose a person reads, translates a provider error, or echoes a value: responses
 * carry fixed codes and keys, and the callback's redirect carries a fixed key and nothing else. The
 * authorization code, the state token, the client secret, the access token and the refresh token never
 * reach a log line, an error, a response body or a URL this module builds.
 */

import { buildAuthUrl, exchangeCode, tenantFor } from "../mail/oauth/flow.js";
import { challengeFor, newVerifier } from "../mail/oauth/pkce.js";
import { connectAccount, isDuplicateAddress, reconnectAccount } from "../mail/accounts/connect.js";
import { MailError, toMailError } from "../mail/errors.js";
import { PRESETS, presetFor } from "../mail/providers/presets.js";
import { getAccount } from "../mail/store/accounts.js";
import { sessionTokenFromRequest } from "../dashboard/auth.js";
import { issuerSource, resolveIssuerUrl } from "../issuer-url.js";
import { gatewayListenPort } from "../listen-port.js";
// The mount point, the account-id rule and the two body validators plan 1 already owns. Read when the
// routes are registered (that module has finished evaluating by then), never at module load: the two
// files import each other, as mail-api-actions.js and mail-api.js already do.
import { MAIL_ACCOUNT_ID_RE, MAIL_API_PREFIX, cleanText, readPlainAddress } from "./mail-api.js";

/** The one path that is NOT under the private API prefix: the provider sends a browser here. */
export const MAIL_OAUTH_CALLBACK_PATH = "/dashboard/mail/oauth/callback";

/** Where every outcome lands, before the fixed status key is appended. */
export const MAIL_SETTINGS_VIEW_PATH = "/dashboard/mail?view=settings";

/**
 * Every status key the callback may put in that redirect. Fixed keys only: the page translates each one
 * and never renders anything a route carried.
 */
export const MAIL_OAUTH_STATUS_KEYS = Object.freeze([
  "oauth_connected",
  "oauth_denied",
  "oauth_expired",
  "oauth_failed",
  "oauth_no_refresh",
  "oauth_probe_failed",
]);

/** The fixed hint keys `POST /oauth/check` answers with. */
export const MAIL_OAUTH_HINT_KEYS = Object.freeze([
  "client_id_shape",
  "redirect_mismatch",
  "no_dashboard_address",
]);

/** The sentence the wizard shows when this machine has no dashboard address (plan 5's fixed wording). */
export const NO_DASHBOARD_ADDRESS_TEXT = "Set this machine's dashboard address first.";

/** The Funnel refusal, the same sentence the gateway-wide middleware uses for a private path. */
const FUNNEL_REFUSAL_TEXT = "Forbidden: private path not reachable via Tailscale Funnel.";

/** A GET the dashboard session did not authenticate (mounted on its own, without dashboardAuth). */
const NO_SESSION_TEXT = "Sign in to Crow first.";

/** The self-test's own message. No address, no subject a person wrote, no account detail. */
const SELFTEST_SUBJECT = "Crow mail self-test";
const SELFTEST_TEXT = "This is a test message from Crow. If you can read it, this account can send mail.";

/** Which preset a provider's OAuth accounts are stored under (`mail_accounts.provider`). */
const PRESET_ID_FOR_PROVIDER = Object.freeze({ google: "gmail", microsoft: "outlook" });
/** The reverse, tolerant of both spellings the token provider already maps (gmail/google, outlook/microsoft). */
const PROVIDER_FOR_ACCOUNT = Object.freeze({
  gmail: "google",
  google: "google",
  outlook: "microsoft",
  microsoft: "microsoft",
});

const CLIENT_ID_MAX = 256;
const CLIENT_SECRET_MAX = 1024;
const LABEL_MAX = 120;
const CHECK_STEPS = Object.freeze(["client_id", "redirect", "scopes"]);
/** A Google OAuth client id ends in this; a Microsoft one is a directory (application) GUID. */
const GOOGLE_CLIENT_ID_RE = /^[A-Za-z0-9._-]+\.apps\.googleusercontent\.com$/;
const MICROSOFT_CLIENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/;

/** A probe that failed AFTER the code was traded: these are the codes `probe.js` can answer with. */
const PROBE_FAILURE_CODES = new Set(["AUTH_FAILED", "NETWORK", "TLS", "PROTOCOL", "TIMEOUT"]);

/* ------------------------------------------------------------------ small reads */

function knownProvider(value) {
  return typeof value === "string" && Object.hasOwn(PRESET_ID_FOR_PROVIDER, value) ? value : null;
}

/** A client id of the provider's own shape, trimmed; null otherwise (BAD_INPUT at the route). */
function readClientId(provider, value) {
  if (typeof value !== "string") return null;
  const id = value.trim();
  if (!id || id.length > CLIENT_ID_MAX || CONTROL_CHARS_RE.test(id) || /\s/.test(id)) return null;
  if (provider === "google") return GOOGLE_CLIENT_ID_RE.test(id) ? id : null;
  if (provider === "microsoft") return MICROSOFT_CLIENT_ID_RE.test(id) ? id : null;
  return null;
}

/** A client secret, or null when absent. Absent is Google's normal case, and a reconnect's keychain read. */
function readClientSecret(value) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") return null;
  if (value.length > CLIENT_SECRET_MAX || CONTROL_CHARS_RE.test(value)) return null;
  return value;
}

/** The account row's own provider name as oauth/flow.js's two providers, or null. */
function providerOfAccount(account) {
  const raw = typeof account?.provider === "string" ? account.provider.trim().toLowerCase() : "";
  return Object.hasOwn(PROVIDER_FOR_ACCOUNT, raw) ? PROVIDER_FOR_ACCOUNT[raw] : null;
}

/** The preset an address is stored under (an unknown domain falls back to the provider's own hosts). */
function presetForProvider(provider, address) {
  const own = presetFor(address);
  if (own) return own.id === PRESET_ID_FOR_PROVIDER[provider] ? own : null;
  const wanted = PRESET_ID_FOR_PROVIDER[provider];
  return PRESETS.find((preset) => preset.id === wanted) ?? null;
}

/**
 * The instance's dashboard address and the callback path on it.
 *
 * `resolveIssuerUrl` degrades to `http://localhost:<port>` when `CROW_GATEWAY_URL` is unset, is not a
 * URL, or is a non-localhost http origin — and a localhost address is not one a provider can redirect a
 * browser to, so both of those are `no_dashboard_address` rather than a URI the wizard would show.
 *
 * A request that arrived through Tailscale Funnel (the gateway's own `Tailscale-Funnel-Request` marker)
 * is the same answer: the page asking is served on a Funnel origin, and this router refuses a funneled
 * callback outright, so a redirect URI on that origin could never come back. That marker is the only
 * signal Crow has for it — nothing in the config says whether the configured address is funneled, and
 * guessing from the hostname would be an invention.
 *
 * @param {object} [env]
 * @param {{funneled?: boolean}} [options] whether THIS request came through Funnel
 * @returns {{redirectUri: string|null, reason: string|null}}
 */
export function dashboardRedirectUri(env = process.env, { funneled = false } = {}) {
  if (funneled === true) return { redirectUri: null, reason: "no_dashboard_address" };
  const resolved = resolveIssuerUrl({ publicUrl: issuerSource(env), port: gatewayListenPort(env) });
  if (resolved.configured !== true || resolved.degraded === true) {
    return { redirectUri: null, reason: "no_dashboard_address" };
  }
  return { redirectUri: `${resolved.url.origin}${MAIL_OAUTH_CALLBACK_PATH}`, reason: null };
}

/** Whether this request reached Crow through Tailscale Funnel (the gateway's own marker header). */
function funneledRequest(req) {
  return Boolean(req?.headers?.["tailscale-funnel-request"]);
}

/** The dashboard session handling this request, from the auth middleware or the cookie it left. */
function sessionFor(req) {
  if (typeof req.dashboardSession === "string" && req.dashboardSession !== "") return req.dashboardSession;
  const token = sessionTokenFromRequest(req);
  return typeof token === "string" && token !== "" ? token : null;
}

/** Record secret values with the masking recorder. A recorder that cannot write never fails a sign-in. */
async function maskQuietly(recordSecrets, values, logCode, label) {
  const list = (values || []).filter((value) => typeof value === "string" && value !== "");
  if (!list.length || typeof recordSecrets !== "function") return;
  try {
    await recordSecrets(list);
  } catch (err) {
    logCode(label, err);
  }
}

/** The fixed key a connect/reconnect failure turns into. Never the error's own text. */
function statusForConnectFailure(err) {
  // A duplicate or a claim another instance holds is the person's situation, not the mailbox's refusal.
  if (isDuplicateAddress(err)) return "oauth_failed";
  if (err instanceof MailError && err.code === "CLAIMED_ELSEWHERE") return "oauth_failed";
  if (err instanceof MailError && PROBE_FAILURE_CODES.has(err.code)) return "oauth_probe_failed";
  return "oauth_failed";
}

/** The fixed code a self-test failure answers with (the keychain's key-missing fault included). */
function selftestErrorCode(err) {
  if (err != null && typeof err === "object" && err.code === "KEYCHAIN_KEY_MISSING") return "keychain_key_missing";
  try {
    return toMailError(err).code;
  } catch {
    return "internal";
  }
}

/* -------------------------------------------------------------- route registration */

/**
 * Register the wizard's routes and the callback on the mail API router.
 *
 * @param {import("express").Router} router the router `mail-api.js` already guards for the API prefix
 * @param {object} ctx the guards and per-request helpers `mail-api.js` builds: `{guards, route,
 *   sendError, logCode, openDb, credentials, supervisor, adapterFactory, localInstance, recordSecrets,
 *   flowStore, oauth}` — `guards.owner` is the owner rule the API prefix uses, `flowStore` is this
 *   router instance's own in-memory store, and `oauth` carries the injected transport/seams.
 */
export function registerOauthRoutes(router, ctx) {
  const { route, sendError, guards } = ctx;
  const logCode = typeof ctx.logCode === "function" ? ctx.logCode : () => {};
  const flowStore = ctx.flowStore;
  const oauth = ctx.oauth ?? {};
  const now = typeof oauth.now === "function" ? oauth.now : Date.now;
  const fetchImpl = typeof oauth.fetchImpl === "function" ? oauth.fetchImpl : globalThis.fetch;
  const endpoints = oauth.endpoints ?? null;
  const base = MAIL_API_PREFIX;

  /** One answer for a callback that is not the owner's: never a redirect, never a key, no data. */
  const refuse = (res, status, text) => {
    if (res.headersSent) return undefined;
    return res.status(status).type("text/plain").send(text);
  };

  /* ---------------------------------------------------------- the callback's own guards */

  // A provider redirect must never be served over Funnel, not even on an install that has opened the
  // gateway-wide middleware with CROW_DASHBOARD_PUBLIC=true. This runs before anything is read. The
  // callback's URL carries the code and the state, so no referrer is allowed to carry it on.
  const funnelGuard = (req, res, next) => {
    res.setHeader("Referrer-Policy", "no-referrer");
    if (req.headers["tailscale-funnel-request"]) return refuse(res, 403, FUNNEL_REFUSAL_TEXT);
    next();
  };

  // The dashboard session, read exactly as dashboardAuth reads it. In the mounted dashboard this has
  // already run; on its own (a test, or a router mounted without the dashboard) it is what keeps the
  // callback from spending a state token for a browser with no session at all.
  const callbackSessionGuard = (req, res, next) => {
    const sessionId = sessionFor(req);
    if (!sessionId) return refuse(res, 401, NO_SESSION_TEXT);
    req.dashboardSession = sessionId;
    next();
  };

  router.use(MAIL_OAUTH_CALLBACK_PATH, guards.headers);
  router.use(MAIL_OAUTH_CALLBACK_PATH, guards.flag);
  router.use(MAIL_OAUTH_CALLBACK_PATH, funnelGuard);
  router.use(MAIL_OAUTH_CALLBACK_PATH, callbackSessionGuard);
  router.use(MAIL_OAUTH_CALLBACK_PATH, guards.owner);

  /* ------------------------------------------------------------------- redirect-uri */

  // The exact redirect URI this instance's registration must carry. `null` and a reason when this
  // machine has no dashboard address: the wizard then keeps the app-password path usable. A wizard
  // opened over Funnel gets the same answer, because a funneled callback is refused here.
  router.get(`${base}/oauth/redirect-uri`, route("GET /oauth/redirect-uri", async (_db, req, res) => {
    const { redirectUri, reason } = dashboardRedirectUri(process.env, { funneled: funneledRequest(req) });
    res.json(redirectUri ? { redirectUri } : { redirectUri: null, reason });
  }));

  /* -------------------------------------------------------------------------- check */

  // The wizard's per-step checks, answered with fixed hint keys and nothing else.
  router.post(`${base}/oauth/check`, route("POST /oauth/check", async (_db, req, res) => {
    const body = req.body;
    if (body == null || typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");
    const step = typeof body.step === "string" ? body.step.trim() : "";
    if (!CHECK_STEPS.includes(step)) return sendError(res, 400, "bad_input");
    const provider = knownProvider(body.provider);
    if (provider === null) return sendError(res, 400, "bad_input");

    if (step === "client_id") {
      if (readClientId(provider, body.clientId)) return res.json({ ok: true, hint: null });
      return res.json({ ok: false, hint: "client_id_shape" });
    }

    if (step === "redirect") {
      const { redirectUri } = dashboardRedirectUri(process.env, { funneled: funneledRequest(req) });
      if (!redirectUri) return res.json({ ok: false, hint: "no_dashboard_address" });
      const pasted = typeof body.pastedRedirectUri === "string" ? body.pastedRedirectUri.trim() : "";
      if (pasted !== "" && pasted === redirectUri) return res.json({ ok: true, hint: null });
      return res.json({ ok: false, hint: "redirect_mismatch" });
    }

    // Scopes are Crow's own (the preset's provider table decides them), so this step only confirms the
    // provider is one this Crow knows.
    res.json({ ok: true, hint: null });
  }));

  /* -------------------------------------------------------------------------- start */

  router.post(`${base}/oauth/start`, route("POST /oauth/start", async (db, req, res) => {
    const body = req.body;
    if (body == null || typeof body !== "object" || Array.isArray(body)) return sendError(res, 400, "bad_input");

    const provider = knownProvider(body.provider);
    if (provider === null) return sendError(res, 400, "bad_input");
    const address = readPlainAddress(body.address);
    if (!address) return sendError(res, 400, "bad_input");
    const label = cleanText(body.label, LABEL_MAX);
    if (!label) return sendError(res, 400, "bad_input");
    // A client id the page did not send is not yet an error: a reconnect reads the stored registration
    // (below). One the page DID send must be of the provider's own shape.
    const sentClientId = body.clientId === undefined || body.clientId === null ? "" : body.clientId;
    let clientId = readClientId(provider, sentClientId);
    if (clientId === null && sentClientId !== "") return sendError(res, 400, "bad_input");

    let clientSecret = readClientSecret(body.clientSecret);
    if (clientSecret === null && body.clientSecret !== undefined && body.clientSecret !== null && body.clientSecret !== "") {
      return sendError(res, 400, "bad_input");
    }

    // The tenant is spliced into a Microsoft URL path, so a value that cannot be one is refused here
    // even when the provider would ignore it. An empty field is the person leaving it alone: it means
    // the same as sending none, and Microsoft's own default is "common".
    const sentTenant = typeof body.tenant === "string" && body.tenant.trim() === "" ? undefined : body.tenant;
    let tenant = null;
    try {
      if (provider === "microsoft") tenant = tenantFor(sentTenant);
      else if (sentTenant !== undefined && sentTenant !== null) tenantFor(sentTenant);
    } catch {
      return sendError(res, 400, "bad_input");
    }

    // The address's own provider decides which hosts the account is stored with; a provider that is not
    // the one this address belongs to (Gmail with Microsoft, say) is refused before anything is minted.
    const preset = presetForProvider(provider, address);
    if (!preset || !preset.imap || !preset.smtp) return sendError(res, 400, "bad_input");

    // Sign in again: the account must exist, be an OAuth account of the SAME provider and address, and a
    // missing registration — the client id, the client secret, or both — is read from the sealed
    // keychain, never from the page. That is what lets the account card's Reconnect name only the
    // account it belongs to.
    let reconnectAccount = null;
    if (body.reconnectAccountId !== undefined && body.reconnectAccountId !== null && body.reconnectAccountId !== "") {
      if (typeof body.reconnectAccountId !== "string" || !MAIL_ACCOUNT_ID_RE.test(body.reconnectAccountId)) {
        return sendError(res, 404, "not_found");
      }
      reconnectAccount = await getAccount(db, body.reconnectAccountId);
      if (!reconnectAccount) return sendError(res, 404, "not_found");
      if (reconnectAccount.authKind !== "xoauth2") return sendError(res, 400, "bad_input");
      if (reconnectAccount.address !== address) return sendError(res, 400, "bad_input");
      if (providerOfAccount(reconnectAccount) !== provider) return sendError(res, 400, "bad_input");
      if (clientId === null || clientSecret === null) {
        let stored;
        try {
          stored = await ctx.credentials(db).getSecrets(reconnectAccount.id);
        } catch (err) {
          if (err != null && err.code === "KEYCHAIN_KEY_MISSING") return sendError(res, 409, "keychain_key_missing");
          throw err;
        }
        const storedClientId = typeof stored?.MAIL_OAUTH_CLIENT_ID === "string" ? stored.MAIL_OAUTH_CLIENT_ID : "";
        // A page that named no client id (the account card's Reconnect) signs in with the registration
        // this account was connected with; its shape is checked like any other.
        if (clientId === null) clientId = readClientId(provider, storedClientId);
        // The stored secret is only sent when the page is signing in with the SAME registration: a
        // person who pasted another client id (a bring-your-own-key re-registration) must not have the
        // old registration's secret travel with it, and a page that names no secret for a new id sends
        // none at all — the provider will answer `invalid_client` if that id really needed one.
        if (clientSecret === null && storedClientId !== "" && storedClientId === clientId) {
          clientSecret = readClientSecret(stored?.MAIL_OAUTH_CLIENT_SECRET);
        }
      }
    }
    // Neither the page nor the keychain could name a registration: there is nothing to sign in with.
    if (!clientId) return sendError(res, 400, "bad_input");

    // Before the flow store, the authorization URL and any later request: the secret joins the masking set.
    await maskQuietly(ctx.recordSecrets, [clientSecret], logCode, "record_secret");

    const sessionId = sessionFor(req);
    // Unreachable under the mounted dashboard (dashboardAuth has authenticated the request); this is
    // the answer a router mounted without it gives rather than minting a flow with no session behind it.
    if (!sessionId) return sendError(res, 403, "owner_only");

    const { redirectUri, reason } = dashboardRedirectUri(process.env, { funneled: funneledRequest(req) });
    if (!redirectUri) return sendError(res, 409, reason, NO_DASHBOARD_ADDRESS_TEXT);

    const verifier = newVerifier();
    const draft = {
      label,
      address,
      username: address,
      provider: preset.id,
      sentCopy: preset.sentCopy,
      imap: { host: preset.imap.host, port: preset.imap.port, security: preset.imap.security },
      smtp: { host: preset.smtp.host, port: preset.smtp.port, security: preset.smtp.security },
    };
    if (reconnectAccount) draft.reconnectAccountId = reconnectAccount.id;

    const state = flowStore.begin({
      sessionId,
      provider,
      accountDraft: draft,
      verifier,
      clientId,
      clientSecret,
      redirectUri,
      tenant,
    });

    const authUrl = buildAuthUrl({
      provider,
      clientId,
      redirectUri,
      state,
      challenge: challengeFor(verifier),
      loginHint: address,
      tenant,
    });
    res.json({ authUrl });
  }));

  /* ----------------------------------------------------------------------- callback */

  /**
   * Spend the flow, trade the code, connect the account. Answers the fixed status key the redirect
   * carries; never throws and never returns a value from the request.
   */
  async function completeCallback(db, req) {
    const state = typeof req.query?.state === "string" ? req.query.state : "";
    const flow = flowStore.take(state, req.dashboardSession);
    if (!flow) return "oauth_expired";

    // The person pressed Deny at the provider (or the provider refused for its own reason). The state
    // has been spent; nothing else is read and nothing is stored.
    if (req.query?.error) return "oauth_denied";

    const code = typeof req.query?.code === "string" ? req.query.code : "";
    // A state that is valid but carries no code cannot be redeemed: the person starts again.
    if (!code) return "oauth_expired";

    let exchange;
    try {
      exchange = await exchangeCode({
        provider: flow.provider,
        code,
        verifier: flow.verifier,
        clientId: flow.clientId,
        clientSecret: flow.clientSecret ?? undefined,
        redirectUri: flow.redirectUri,
        tenant: flow.tenant ?? undefined,
        fetchImpl,
        endpoints,
        now,
      });
    } catch (err) {
      logCode("oauth_exchange", err);
      return "oauth_failed";
    }

    // Every value a log line could otherwise quote joins the masking set before the account store, the
    // probe or a socket sees any of them.
    await maskQuietly(ctx.recordSecrets, [code, exchange?.accessToken, exchange?.refreshToken], logCode, "record_secret");

    // The record is out of the store already; the local copy keeps nothing a later error could print.
    const clientId = flow.clientId;
    const clientSecret = flow.clientSecret;
    const tenant = flow.tenant ?? undefined;
    const provider = flow.provider;
    const draft = flow.accountDraft;
    flow.verifier = null;
    flow.clientSecret = null;

    if (typeof exchange?.refreshToken !== "string" || exchange.refreshToken === "") {
      // A grant with no refresh token is a grant Crow cannot use tomorrow: nothing is stored, and the
      // person signs in again (Google's `prompt=consent` + `access_type=offline` is what avoids it).
      return "oauth_no_refresh";
    }
    if (draft == null || typeof draft !== "object" || Array.isArray(draft)) return "oauth_failed";

    const secrets = {
      MAIL_OAUTH_CLIENT_ID: clientId,
      MAIL_REFRESH_TOKEN: exchange.refreshToken,
    };
    if (typeof clientSecret === "string" && clientSecret !== "") secrets.MAIL_OAUTH_CLIENT_SECRET = clientSecret;

    // One shot, for the probe only: the account does not exist yet (or still holds the dead grant), and
    // the registry has nothing to answer with. Every other sign-in asks the registry's provider.
    const oneShotTokenProvider = async () => ({
      accessToken: exchange.accessToken,
      expiresAt: exchange.expiresAt,
    });

    const connectDeps = {
      credentials: ctx.credentials(db),
      adapterFactory: ctx.adapterFactory,
      supervisor: ctx.supervisor(),
      localInstance: ctx.localInstance(db),
      recordSecrets: ctx.recordSecrets,
      ...(typeof oauth.claims === "object" && oauth.claims !== null ? { claims: oauth.claims } : {}),
      ...(typeof oauth.forgetTokenProvider === "function" ? { forgetTokenProvider: oauth.forgetTokenProvider } : {}),
      ...(typeof oauth.adapterFactory === "function" ? { oauthAdapterFactory: oauth.adapterFactory } : {}),
    };

    // The grant's non-secret label. It travels WITH the connect instead of being written after it: the
    // connect stores it before it starts the first sync, so a Microsoft account's first refresh already
    // has its tenant, and a label that cannot be written is a sign-in that stores nothing at all.
    const oauthMeta = { grantedAt: now(), publishing: "unknown", provider, tenant };

    try {
      if (typeof draft.reconnectAccountId === "string" && draft.reconnectAccountId !== "") {
        await reconnectAccount(db, connectDeps, {
          accountId: draft.reconnectAccountId,
          secrets,
          tokenProvider: oneShotTokenProvider,
          oauthMeta,
        });
      } else {
        await connectAccount(db, connectDeps, {
          draft,
          authKind: "xoauth2",
          secrets,
          tokenProvider: oneShotTokenProvider,
          oauthMeta,
        });
      }
    } catch (err) {
      // The connect's own undo has already removed the row, its sealed secrets and its claim.
      logCode("oauth_connect", err);
      return statusForConnectFailure(err);
    }

    return "oauth_connected";
  }

  router.get(MAIL_OAUTH_CALLBACK_PATH, route("GET /mail/oauth/callback", async (db, req, res) => {
    let status = "oauth_failed";
    try {
      status = await completeCallback(db, req);
    } catch (err) {
      logCode("oauth_callback", err);
      status = "oauth_failed";
    }
    res.redirect(302, `${MAIL_SETTINGS_VIEW_PATH}&mailStatus=${status}`);
  }));

  /* ----------------------------------------------------------------------- selftest */

  // At the person's tap only, and optional: it sends one message from the account to itself through the
  // account's own adapter, and it is a check rather than a gate (whether an account can send is computed).
  // POST only; it changes no account field.
  router.post(`${base}/accounts/:id/selftest`, route("POST /accounts/:id/selftest", async (db, req, res) => {
    const id = String(req.params.id);
    if (!MAIL_ACCOUNT_ID_RE.test(id)) return sendError(res, 404, "not_found");
    const account = await getAccount(db, id);
    if (!account) return sendError(res, 404, "not_found");

    const supervisor = ctx.supervisor();
    if (!supervisor || typeof supervisor.withAdapter !== "function") {
      return res.status(503).json({ ok: false, error: "unavailable" });
    }

    const message = {
      from: { name: account.displayName ?? null, address: account.address },
      to: [{ address: account.address }],
      subject: SELFTEST_SUBJECT,
      text: SELFTEST_TEXT,
    };
    try {
      const result = await supervisor.withAdapter(account.id, (adapter) => adapter.send(message));
      const accepted = Array.isArray(result?.accepted) ? result.accepted : [];
      if (accepted.length === 0) return res.json({ ok: false, error: "all_rejected" });
      return res.json({ ok: true });
    } catch (err) {
      logCode("POST /accounts/:id/selftest", err);
      return res.json({ ok: false, error: selftestErrorCode(err) });
    }
  }));
}

export default registerOauthRoutes;