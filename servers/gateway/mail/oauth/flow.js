/**
 * Crow Mail's OAuth 2.0 authorization-code flow with PKCE, for the two providers that will not take a
 * password: Google (Gmail over IMAP/SMTP with XOAUTH2) and Microsoft (Outlook.com / Microsoft 365 over
 * IMAP/SMTP with XOAUTH2).
 *
 * The sources every rule below comes from:
 *
 * - Google's installed-app flow — PKCE with no client secret, and `access_type=offline` together with
 *   `prompt=consent` so a refresh token is issued every time, not only on the first consent:
 *   https://developers.google.com/identity/protocols/oauth2/native-app
 * - The scope Gmail wants for IMAP/SMTP over XOAUTH2 (`https://mail.google.com/`) and the SASL
 *   exchange that consumes the access token:
 *   https://developers.google.com/gmail/imap/xoauth2-protocol
 * - Microsoft's v2 authorization-code flow — the tenant sits in BOTH endpoints, and `offline_access`
 *   is what asks for a refresh token:
 *   https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow
 * - The scopes Exchange Online accepts for IMAP and SMTP with OAuth
 *   (`https://outlook.office.com/IMAP.AccessAsUser.All`, `https://outlook.office.com/SMTP.Send`):
 *   https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
 *
 * What this module does not do: keep a token, store anything, decide when to refresh, or talk to the
 * network on its own. It builds the one URL the person is sent to, and makes the two POSTs that turn a
 * code (or a refresh token) into an access token. The caller keeps the result in the sealed keychain
 * (mail/credentials.js) and hands the access token to the XOAUTH2 login.
 *
 * Every failure is a `MailError` (mail/errors.js): `AUTH_FAILED` with an allow-listed OAuth token as
 * its detail when the provider refused, `NETWORK` when it could not be reached or took too long, and
 * `PROTOCOL` for an answer Crow could not use. A failure body is read for its `error` field and then
 * dropped: an OAuth error echoes the request (its `error_description` quotes the code, and some servers
 * quote the client secret), so no body text, no code, no token and no secret ever reaches an error
 * message, a detail, or a log — the sentences are the fixed ones in MAIL_ERROR_TEXT.
 *
 * Transport is an injected `fetchImpl`; nothing here reaches the network by itself. `endpoints` exists
 * ONLY so a test can point the two POSTs at a local fake provider (tests/fixtures/fake-oauth-provider
 * .mjs) — production callers never pass it, so the provider table stays the real one. Its one allowed
 * value is an http(s) URL on this machine's loopback (`127.0.0.1`, `::1`, `localhost`); anything else
 * is BAD_INPUT before a request is made. **PR B must never pass request data into it**: it is a fixed,
 * literal test address, never an address, a tenant or any other value a caller or a request supplied.
 */
import { MailError } from "../errors.js";

const DEFAULT_TIMEOUT_MS = 15_000;

/** A provider that omits `expires_in` (or sends nonsense) gets the RFC 6749 suggestion of an hour. */
const DEFAULT_EXPIRES_IN_SECONDS = 3600;

const TENANT_RESERVED = new Set(["common", "consumers", "organizations"]);
const TENANT_GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/**
 * One DNS label: 1-63 characters, letters, digits and inner hyphens, and neither a leading nor a
 * trailing hyphen. A verified domain is exactly these joined by single dots, so no empty label ("a..b",
 * a leading or trailing dot) and no bare "-" label can ever reach the URL path.
 */
const TENANT_LABEL = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;

/** The only hosts a TEST-ONLY `endpoints` override may point at: this machine, and nothing else. */
const TEST_ENDPOINT_HOSTS = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);
const TEST_ENDPOINT_PROTOCOLS = new Set(["http:", "https:"]);

/**
 * The two providers, frozen. `authParams` are extra authorization-URL parameters (Google's offline
 * access pair); `scopeOnRefresh` marks the provider that wants its scopes repeated on a refresh grant
 * (Microsoft does, Google does not); `{tenant}` in either URL is substituted before the call.
 */
export const PROVIDERS = Object.freeze({
  google: Object.freeze({
    id: "google",
    authUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    scopes: Object.freeze(["https://mail.google.com/"]),
    authParams: Object.freeze({ access_type: "offline", prompt: "consent" }),
    scopeOnRefresh: false,
  }),
  microsoft: Object.freeze({
    id: "microsoft",
    authUrl: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
    tokenUrl: "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
    scopes: Object.freeze([
      "https://outlook.office.com/IMAP.AccessAsUser.All",
      "https://outlook.office.com/SMTP.Send",
      "offline_access",
    ]),
    authParams: Object.freeze({}),
    scopeOnRefresh: true,
  }),
});

/** The provider entry for a name, or BAD_INPUT. `Object.hasOwn` keeps "constructor" from being a provider. */
function providerFor(provider) {
  if (typeof provider !== "string" || !Object.hasOwn(PROVIDERS, provider)) {
    throw new MailError("BAD_INPUT", "provider");
  }
  return PROVIDERS[provider];
}

function requireString(value, detail) {
  if (typeof value !== "string" || value.length === 0) throw new MailError("BAD_INPUT", detail);
  return value;
}

/**
 * The Microsoft tenant to put in the URL: the three multi-tenant words, a directory (tenant) GUID, or a
 * verified domain name — labels of letters, digits and inner hyphens joined by single dots; "common"
 * when the caller says nothing. Anything else is BAD_INPUT — the tenant is spliced into a URL path, so
 * it is never taken on trust: no empty label, no "." or "..", no label that starts or ends with "-".
 *
 * @param {string|null|undefined} tenant
 * @returns {string}
 */
export function tenantFor(tenant) {
  if (tenant === undefined || tenant === null) return "common";
  if (typeof tenant !== "string" || tenant.length === 0 || tenant.length > 253) throw new MailError("BAD_INPUT", "tenant");
  const lower = tenant.toLowerCase();
  if (TENANT_RESERVED.has(lower)) return lower;
  if (TENANT_GUID.test(tenant)) return tenant;
  if (isTenantDomain(tenant)) return lower;
  throw new MailError("BAD_INPUT", "tenant");
}

/** A verified domain name: every dot-separated label is a DNS label (see TENANT_LABEL). */
function isTenantDomain(tenant) {
  return tenant.split(".").every((label) => TENANT_LABEL.test(label));
}

/** The tenant a call needs: only Microsoft's URLs carry one. */
function tenantOf(spec, tenant) {
  return spec.authUrl.includes("{tenant}") ? tenantFor(tenant) : "";
}

/**
 * The token endpoint for a call, with the tenant substituted and any test override applied.
 *
 * `endpoints` is the TEST-ONLY seam (see the module comment). It takes a literal http(s) URL on this
 * machine's loopback and nothing else: anything else — another host, another scheme, a value that is
 * not a URL — is BAD_INPUT, thrown here, before any request is made. That is what keeps the seam from
 * ever being a way to send a token to a host a caller named. PR B must never pass request data into it.
 */
function tokenUrlFor(spec, tenant, endpoints) {
  const template = endpoints == null ? spec.tokenUrl : testEndpointUrl(endpoints);
  return template.replace("{tenant}", tenant);
}

/** The one URL a test override may name, or BAD_INPUT. */
function testEndpointUrl(endpoints) {
  if (endpoints == null || typeof endpoints !== "object" || typeof endpoints.tokenUrl !== "string") {
    throw new MailError("BAD_INPUT", "endpoints");
  }
  let url;
  try {
    url = new URL(endpoints.tokenUrl);
  } catch {
    throw new MailError("BAD_INPUT", "endpoints");
  }
  if (!TEST_ENDPOINT_PROTOCOLS.has(url.protocol) || !TEST_ENDPOINT_HOSTS.has(url.hostname.toLowerCase())) {
    throw new MailError("BAD_INPUT", "endpoints");
  }
  return endpoints.tokenUrl;
}

/** `expires_in` accepts a number or a numeric string; anything else (or 0/negative/Infinity) is an hour. */
function expiresAtFrom(body, nowFn) {
  const raw = body.expires_in;
  const seconds = typeof raw === "number"
    ? raw
    : typeof raw === "string" && /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : NaN;
  const safe = Number.isFinite(seconds) && seconds > 0 ? seconds : DEFAULT_EXPIRES_IN_SECONDS;
  return nowFn() + safe * 1000;
}

/**
 * The URL the person is sent to: an authorization request with the PKCE challenge, the exact redirect
 * URI the callback will be checked against, and the provider's own extra parameters.
 *
 * @param {object} request
 * @param {string} request.provider "google" or "microsoft"
 * @param {string} request.clientId the OAuth client id Crow was registered under
 * @param {string} request.redirectUri the callback, exactly as registered (never rebuilt from a request)
 * @param {string} request.state the flow store's state token (oauth/state.js)
 * @param {string} request.challenge `challengeFor(verifier)` (oauth/pkce.js)
 * @param {string} [request.loginHint] the address being added, so the provider preselects the account
 * @param {string} [request.tenant] a Microsoft tenant (default "common")
 * @returns {string} the authorization URL
 */
export function buildAuthUrl({ provider, clientId, redirectUri, state, challenge, loginHint, tenant } = {}) {
  const spec = providerFor(provider);
  const url = new URL(spec.authUrl.replace("{tenant}", tenantOf(spec, tenant)));
  const params = new URLSearchParams();
  params.set("response_type", "code");
  params.set("client_id", requireString(clientId, "client_id"));
  params.set("redirect_uri", requireString(redirectUri, "redirect_uri"));
  params.set("scope", spec.scopes.join(" "));
  params.set("state", requireString(state, "state"));
  params.set("code_challenge", requireString(challenge, "challenge"));
  params.set("code_challenge_method", "S256");
  if (loginHint !== undefined && loginHint !== null && loginHint !== "") {
    params.set("login_hint", requireString(loginHint, "login_hint"));
  }
  for (const [name, value] of Object.entries(spec.authParams)) params.set(name, value);
  url.search = params.toString();
  return url.toString();
}

/**
 * One token request, and the one place a provider's answer is read.
 *
 * Only the `error` field of a failure body is used, and only to pick a fixed MailError; the body itself
 * is never echoed, quoted, logged or attached. A throw from `fetchImpl` (including our own timeout
 * abort) is NETWORK, a 5xx is NETWORK, and everything else that is not a usable success is PROTOCOL.
 *
 * @returns {Promise<{accessToken: string, expiresAt: number, refreshToken?: string}>}
 */
async function postToken({ spec, tenant, form, fetchImpl, timeoutMs, now, endpoints }) {
  if (typeof fetchImpl !== "function") {
    throw new TypeError("fetchImpl is required: mail OAuth reaches the network only through an injected fetch");
  }
  const ms = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
  // One budget for the whole exchange: the same signal bounds the response HEADERS and the body that
  // follows them, so an endpoint that answers a 200 and then goes silent is ended by the timeout too.
  const signal = AbortSignal.timeout(ms);
  // Resolved BEFORE the transport's try/catch: a refused `endpoints` override is BAD_INPUT, and must
  // not be swallowed into the NETWORK a failing transport is reported as.
  const url = tokenUrlFor(spec, tenant, endpoints);
  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: form.toString(),
      signal,
    });
  } catch {
    // A refusal at the socket, a DNS failure, or the timeout above — never the error's own text.
    throw new MailError("NETWORK");
  }

  const status = typeof response?.status === "number" ? response.status : 0;
  let body = null;
  try {
    body = await response.json();
  } catch (err) {
    // Headers that arrive without an answer are a network fault, not a provider that sent no access
    // token: the timeout (or any other abort) fired while the body was still being read, and that is
    // exactly the case the abort bounds. Any other unreadable body is the protocol fault below.
    if (signal.aborted === true || (err != null && (err.name === "AbortError" || err.code === "ABORT_ERR"))) {
      throw new MailError("NETWORK");
    }
    body = null;
  }

  if (status >= 500) throw new MailError("NETWORK");

  if (!response.ok) {
    // Read the machine token and nothing else: `error_description` quotes the request.
    const token = body && typeof body.error === "string" ? body.error : null;
    if (token === "invalid_grant") throw new MailError("AUTH_FAILED", "invalid_grant");
    if (token === "invalid_client") throw new MailError("AUTH_FAILED", "invalid_client");
    throw new MailError("PROTOCOL", "other");
  }

  if (!body || typeof body.access_token !== "string" || body.access_token.length === 0) {
    throw new MailError("PROTOCOL", "no_access_token");
  }

  const result = { accessToken: body.access_token, expiresAt: expiresAtFrom(body, now) };
  if (typeof body.refresh_token === "string" && body.refresh_token.length > 0) result.refreshToken = body.refresh_token;
  return result;
}

/**
 * Redeem an authorization code for an access token (and, usually, a refresh token).
 *
 * The verifier proves this machine started the flow; the client secret is sent only when the caller has
 * one (Google's installed-app clients have none; Microsoft's confidential clients do).
 *
 * @param {object} request
 * @param {string} request.provider "google" or "microsoft"
 * @param {string} request.code the `code` the provider handed to the callback
 * @param {string} request.verifier the PKCE verifier of that flow
 * @param {string} request.clientId
 * @param {string} [request.clientSecret] only when the registered client has one
 * @param {string} request.redirectUri the same URI the authorization URL carried
 * @param {string} [request.tenant] a Microsoft tenant (default "common")
 * @param {Function} request.fetchImpl the HTTP transport (tests inject a local fake provider)
 * @param {number} [request.timeoutMs] abort the call after this long (default 15 s)
 * @param {() => number} [request.now] the clock for `expiresAt`
 * @param {{tokenUrl?: string}} [request.endpoints] TEST ONLY: point the POST at a fake provider
 * @returns {Promise<{accessToken: string, expiresAt: number, refreshToken?: string}>}
 */
export async function exchangeCode({
  provider, code, verifier, clientId, clientSecret, redirectUri, tenant,
  fetchImpl, timeoutMs = DEFAULT_TIMEOUT_MS, now = Date.now, endpoints,
} = {}) {
  const spec = providerFor(provider);
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code: requireString(code, "code"),
    redirect_uri: requireString(redirectUri, "redirect_uri"),
    client_id: requireString(clientId, "client_id"),
    code_verifier: requireString(verifier, "verifier"),
  });
  if (clientSecret !== undefined && clientSecret !== null && clientSecret !== "") {
    form.set("client_secret", requireString(clientSecret, "client_secret"));
  }
  return postToken({ spec, tenant: tenantOf(spec, tenant), form, fetchImpl, timeoutMs, now, endpoints });
}

/**
 * Trade a refresh token for a new access token. Microsoft wants the scopes repeated here; Google does
 * not. A rotated refresh token is returned when the provider sends one — the caller must then replace
 * the stored one, so a rotation is never silently dropped.
 *
 * @param {object} request
 * @param {string} request.provider "google" or "microsoft"
 * @param {string} request.refreshToken the stored refresh token
 * @param {string} request.clientId
 * @param {string} [request.clientSecret]
 * @param {string} [request.tenant] a Microsoft tenant (default "common")
 * @param {Function} request.fetchImpl
 * @param {() => number} [request.now]
 * @param {number} [request.timeoutMs]
 * @param {{tokenUrl?: string}} [request.endpoints] TEST ONLY: point the POST at a fake provider
 * @returns {Promise<{accessToken: string, expiresAt: number, refreshToken?: string}>}
 */
export async function refresh({
  provider, refreshToken, clientId, clientSecret, tenant,
  fetchImpl, now = Date.now, timeoutMs = DEFAULT_TIMEOUT_MS, endpoints,
} = {}) {
  const spec = providerFor(provider);
  const form = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: requireString(refreshToken, "refresh_token"),
    client_id: requireString(clientId, "client_id"),
  });
  if (clientSecret !== undefined && clientSecret !== null && clientSecret !== "") {
    form.set("client_secret", requireString(clientSecret, "client_secret"));
  }
  if (spec.scopeOnRefresh) form.set("scope", spec.scopes.join(" "));
  return postToken({ spec, tenant: tenantOf(spec, tenant), form, fetchImpl, timeoutMs, now, endpoints });
}