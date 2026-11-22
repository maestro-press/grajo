// Crow Mail OAuth (plan 5, Task 3a): PKCE, the flow state store, and the two provider calls.
//
// Two rules shape this file. No test touches the internet: every POST goes to a local fake provider on
// 127.0.0.1 (tests/fixtures/fake-oauth-provider.mjs) through the `endpoints` override, so the real
// provider table stays the production one. And no test carries a provider-domain ADDRESS (a public
// repository must not): the domain table is exercised through `presetForDomain` in the presets test,
// and the only address here sits at example.test.
//
// The leak test is the point of the module: a real OAuth error echoes the request — its
// `error_description` quotes the code, and some servers quote the client secret — so the fake provider
// is asked to echo both, and the thrown error is searched for either string in EVERY form a caller or a
// log could print.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { MailError } from "../servers/gateway/mail/errors.js";
import { newVerifier, challengeFor } from "../servers/gateway/mail/oauth/pkce.js";
import { createFlowStore } from "../servers/gateway/mail/oauth/state.js";
import { PROVIDERS, buildAuthUrl, exchangeCode, refresh, tenantFor } from "../servers/gateway/mail/oauth/flow.js";
import { startFakeOAuthProvider } from "./fixtures/fake-oauth-provider.mjs";

const fakes = [];
after(async () => { for (const fake of fakes) await fake.close(); });

async function fakeProvider() {
  const fake = await startFakeOAuthProvider();
  fakes.push(fake);
  return fake;
}

/** A callback on loopback, exactly as an installed app registers one. */
const REDIRECT_URI = "http://127.0.0.1:47823/mail/oauth/callback";
const CLIENT_ID = "crow-client-4f1a2b7d";
const CLIENT_SECRET = "client-secret-9d3c51aa";
const CODE = "auth-code-7c1e2d90";
const REFRESH_TOKEN = "refresh-token-5a2b";

/** The error a promise rejected with (asserting it rejected at all). */
async function failure(promise) {
  try {
    await promise;
  } catch (err) {
    return err;
  }
  assert.fail("expected the call to fail");
}

const isMailError = (code, detail = null) => (err) => {
  assert.ok(err instanceof MailError, `a MailError, got ${String(err)}`);
  assert.equal(err.code, code);
  if (detail !== null) assert.equal(err.detail, detail);
  return true;
};

/* ------------------------------------------------------------------- PKCE */

test("a verifier is 43 characters of the RFC 7636 alphabet, and no two flows share one", () => {
  const verifier = newVerifier();
  assert.equal(verifier.length, 43, "32 random bytes base64url-encode to 43 characters");
  assert.match(verifier, /^[A-Za-z0-9\-._~]{43,128}$/, "the RFC 7636 verifier alphabet, and within 43-128");
  const seen = new Set();
  for (let i = 0; i < 64; i += 1) seen.add(newVerifier());
  assert.equal(seen.size, 64, "every verifier is fresh");
});

test("challengeFor is S256, unpadded base64url, and matches RFC 7636's appendix B", () => {
  // Appendix B: the verifier the RFC uses, and the challenge it must produce.
  assert.equal(
    challengeFor("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  );
  const challenge = challengeFor(newVerifier());
  assert.equal(challenge.length, 43, "SHA-256 is 32 bytes, so 43 base64url characters");
  assert.match(challenge, /^[A-Za-z0-9\-_]+$/, "base64url without padding");
  assert.equal(challengeFor("a"), challengeFor("a"), "the same verifier always yields the same challenge");
  assert.notEqual(challengeFor("a"), challengeFor("b"));
});

/* -------------------------------------------------------- the authorization URL */

test("the Google authorization URL carries PKCE, the state, the exact redirect URI and the offline pair", () => {
  const verifier = newVerifier();
  const state = "state-token-1f2e3d";
  const url = buildAuthUrl({
    provider: "google",
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    state,
    challenge: challengeFor(verifier),
    loginHint: "alex@example.test",
  });
  const parsed = new URL(url);
  assert.equal(`${parsed.origin}${parsed.pathname}`, PROVIDERS.google.authUrl, "Google's own endpoint");
  const params = parsed.searchParams;
  assert.equal(params.get("response_type"), "code");
  assert.equal(params.get("client_id"), CLIENT_ID);
  assert.equal(params.get("redirect_uri"), REDIRECT_URI, "the exact registered URI, not a rebuilt one");
  assert.equal(params.get("scope"), PROVIDERS.google.scopes.join(" "));
  assert.deepEqual([...PROVIDERS.google.scopes], ["https://mail.google.com/"], "the scope Gmail's XOAUTH2 wants");
  assert.equal(params.get("state"), state);
  assert.equal(params.get("code_challenge"), challengeFor(verifier));
  assert.equal(params.get("code_challenge_method"), "S256");
  assert.equal(params.get("access_type"), "offline", "so a refresh token is issued");
  assert.equal(params.get("prompt"), "consent", "and issued again on a repeat consent");
  assert.equal(params.get("login_hint"), "alex@example.test");
  assert.equal(params.has("client_secret"), false, "a secret never belongs in a browser URL");
  assert.equal(params.has("code_verifier"), false, "only the challenge travels");
  assert.equal(params.has("tenant"), false);
});

test("the Microsoft authorization URL substitutes a validated tenant", () => {
  const base = { provider: "microsoft", clientId: CLIENT_ID, redirectUri: REDIRECT_URI, state: "st", challenge: challengeFor(newVerifier()) };

  const common = new URL(buildAuthUrl(base));
  assert.equal(`${common.origin}${common.pathname}`, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "a tenant nobody named is 'common'");
  assert.equal(common.searchParams.get("scope"), PROVIDERS.microsoft.scopes.join(" "));
  assert.deepEqual([...PROVIDERS.microsoft.scopes], [
    "https://outlook.office.com/IMAP.AccessAsUser.All",
    "https://outlook.office.com/SMTP.Send",
    "offline_access",
  ]);
  assert.equal(common.searchParams.get("access_type"), null, "Google's parameters are Google's only");

  const guid = "8b1c7f4e-2a3d-4c5b-9e6f-0a1b2c3d4e5f";
  const byGuid = new URL(buildAuthUrl({ ...base, tenant: guid }));
  assert.equal(`${byGuid.origin}${byGuid.pathname}`, `https://login.microsoftonline.com/${guid}/oauth2/v2.0/authorize`);

  const byDomain = new URL(buildAuthUrl({ ...base, tenant: "Contoso.Example" }));
  assert.equal(`${byDomain.origin}${byDomain.pathname}`,
    "https://login.microsoftonline.com/contoso.example/oauth2/v2.0/authorize", "a verified domain, lower-cased");

  assert.equal(tenantFor("ORGANIZATIONS"), "organizations");
  assert.equal(tenantFor(undefined), "common");
});

test("a tenant that is not a word, a GUID or a domain is refused before any URL is built", () => {
  const base = { provider: "microsoft", clientId: CLIENT_ID, redirectUri: REDIRECT_URI, state: "st", challenge: challengeFor(newVerifier()) };
  for (const tenant of ["../../evil", "comm on", "common/../..", "a?b=1", "x#y", "common\u0000", "-".repeat(300), 42, {}, []]) {
    assert.throws(() => buildAuthUrl({ ...base, tenant }), isMailError("BAD_INPUT", "tenant"), `tenant ${JSON.stringify(tenant)}`);
  }
});

test("L2: a tenant domain is dot-separated DNS labels: no empty label, no bare dot, no leading hyphen", () => {
  for (const tenant of ["..", ".", "a..b", "-a.com", "a-.com", ".a.com", "a.com.", "a._b.com", "a b.com", "a/b.com"]) {
    assert.throws(() => tenantFor(tenant), isMailError("BAD_INPUT", "tenant"), `tenant ${JSON.stringify(tenant)}`);
    assert.throws(
      () => buildAuthUrl({ provider: "microsoft", clientId: CLIENT_ID, redirectUri: REDIRECT_URI, state: "st", challenge: challengeFor(newVerifier()), tenant }),
      isMailError("BAD_INPUT", "tenant"),
      `tenant ${JSON.stringify(tenant)} in a URL`,
    );
  }
  // A real verified domain still passes, lower-cased, and so does a single label and a GUID.
  assert.equal(tenantFor("contoso.onmicrosoft.com"), "contoso.onmicrosoft.com");
  assert.equal(tenantFor("Contoso.OnMicrosoft.COM"), "contoso.onmicrosoft.com");
  assert.equal(tenantFor("contoso"), "contoso");
  assert.equal(tenantFor("a-b.c-d.example"), "a-b.c-d.example");
  assert.equal(tenantFor("8b1c7f4e-2a3d-4c5b-9e6f-0a1b2c3d4e5f"), "8b1c7f4e-2a3d-4c5b-9e6f-0a1b2c3d4e5f");
});

test("an unknown provider and a missing required parameter are BAD_INPUT, not a URL", () => {
  const base = { provider: "google", clientId: CLIENT_ID, redirectUri: REDIRECT_URI, state: "st", challenge: challengeFor(newVerifier()) };
  for (const provider of ["gmail", "constructor", "toString", "", null, undefined]) {
    assert.throws(() => buildAuthUrl({ ...base, provider }), isMailError("BAD_INPUT", "provider"));
  }
  for (const field of ["clientId", "redirectUri", "state", "challenge"]) {
    assert.throws(() => buildAuthUrl({ ...base, [field]: "" }), isMailError("BAD_INPUT"), `${field} is required`);
  }
});

/* -------------------------------------------------------------- the flow store */

test("the flow store spends a token exactly once, for the session that began it", () => {
  const store = createFlowStore();
  const verifier = newVerifier();
  const token = store.begin({
    sessionId: "session-a", provider: "google", accountDraft: { label: "Alex" }, verifier,
    clientId: CLIENT_ID, redirectUri: REDIRECT_URI,
  });
  assert.equal(typeof token, "string");
  assert.match(token, /^[A-Za-z0-9\-_]{43,}$/, "an unguessable base64url token");
  assert.equal(store.size(), 1);

  // Another session cannot spend it — and the attempt BURNS it, so a stolen token gets one try.
  assert.equal(store.take(token, "session-b"), null, "a mismatched session gets nothing");
  assert.equal(store.size(), 0, "the entry is gone even though the session did not match");
  assert.equal(store.take(token, "session-a"), null, "and the real session cannot retry");

  // The happy path: the record comes back with everything the token request needs.
  const second = store.begin({ sessionId: "session-a", provider: "microsoft", verifier, clientId: CLIENT_ID, tenant: "common" });
  const record = store.take(second, "session-a");
  assert.ok(record, "the first take of a live token returns the flow");
  assert.equal(record.provider, "microsoft");
  assert.equal(record.verifier, verifier);
  assert.equal(record.clientId, CLIENT_ID);
  assert.equal(record.tenant, "common");
  assert.equal(store.take(second, "session-a"), null, "single use");
  assert.equal(store.size(), 0);

  // Nothing that is not a live token answers with anything but null.
  for (const [a, b] of [[null, "session-a"], ["", "session-a"], [42, "session-a"], [{}, "session-a"],
    ["unknown-token", "session-a"], ["x".repeat(43), "session-a"], [token, ""], [token, null], [token, 7]]) {
    assert.equal(store.take(a, b), null, `take(${JSON.stringify(a)}, ${JSON.stringify(b)})`);
  }
  assert.throws(() => store.begin({ sessionId: "", provider: "google", verifier }), isMailError("BAD_INPUT", "session"));
  assert.throws(() => store.begin({ sessionId: "s", provider: "google", verifier: "" }), isMailError("BAD_INPUT", "verifier"));
});

test("an expired flow is deleted, not returned, and a flow exactly at its TTL is still live", () => {
  let clock = 1_000_000;
  const store = createFlowStore({ now: () => clock, ttlMs: 60_000 });
  const verifier = newVerifier();

  const atEdge = store.begin({ sessionId: "s", provider: "google", verifier });
  clock += 60_000;
  assert.ok(store.take(atEdge, "s"), "now is not yet PAST createdAt + ttl");

  const expiring = store.begin({ sessionId: "s", provider: "google", verifier });
  clock += 60_001;
  assert.equal(store.take(expiring, "s"), null, "past its TTL");
  assert.equal(store.size(), 0, "an expired flow is gone for good");
});

test("L1: begin() and take() sweep expired flows, so an abandoned flow (and its secrets) leaves memory", () => {
  let clock = 1_000_000;
  const store = createFlowStore({ now: () => clock, ttlMs: 60_000, perSessionCap: 100, totalCap: 200 });
  const verifier = newVerifier();
  const begin = (sessionId) => store.begin({
    sessionId, provider: "microsoft", verifier, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, tenant: "common",
  });

  // begin() sweeps: a flow past its TTL is gone as soon as another one starts, with no cap involved.
  const abandoned = begin("session-a");
  const alsoAbandoned = begin("session-b");
  assert.equal(store.size(), 2);
  clock += 60_001;
  const fresh = begin("session-c");
  assert.equal(store.size(), 1, "begin() dropped both expired flows (the caps never had to)");
  assert.equal(store.take(abandoned, "session-a"), null, "the expired flow is not spendable any more");
  assert.equal(store.take(alsoAbandoned, "session-b"), null);
  assert.ok(store.take(fresh, "session-c"), "the live flow is still spendable");

  // take() sweeps too: a lookup — even one for a token nobody holds — clears abandoned entries.
  const one = begin("session-a");
  const two = begin("session-b");
  assert.equal(store.size(), 2);
  clock += 60_001;
  assert.equal(store.take("unknown-token-" + "x".repeat(30), "session-a"), null);
  assert.equal(store.size(), 0, "take() swept the two expired flows");
  assert.equal(store.take(one, "session-a"), null);
  assert.equal(store.take(two, "session-b"), null);

  // A flow that is still live survives the sweep, exactly as before.
  const live = begin("session-a");
  clock += 59_999;
  const other = begin("session-b");
  assert.equal(store.size(), 2, "nothing expired was there to drop");
  assert.ok(store.take(live, "session-a"));
  assert.ok(store.take(other, "session-b"));
  assert.equal(store.size(), 0);
});

test("the caps evict a session's oldest flow, then the globally oldest", () => {
  const store = createFlowStore({ perSessionCap: 2, totalCap: 3 });
  const verifier = newVerifier();
  const begin = (sessionId) => store.begin({ sessionId, provider: "google", verifier, clientId: CLIENT_ID });

  const a1 = begin("session-a");
  const a2 = begin("session-a");
  const a3 = begin("session-a");
  assert.equal(store.size(), 2, "session-a is capped at two");
  assert.equal(store.take(a1, "session-a"), null, "the session's own oldest went");

  const b1 = begin("session-b");
  assert.equal(store.size(), 3, "another session's flow fits under the total cap");
  const b2 = begin("session-b");
  assert.equal(store.size(), 3, "the total cap holds, so the globally oldest went");
  assert.equal(store.take(a2, "session-a"), null, "which was session-a's remaining oldest flow");

  const b3 = begin("session-b");
  assert.equal(store.size(), 3, "session-b is under its own cap; nothing global had to go");
  assert.equal(store.take(b1, "session-b"), null, "session-b's oldest went, hitting its per-session cap");

  // The two newest are the ones that survived.
  assert.ok(store.take(b3, "session-b"), "the newest flow is always live");
  assert.ok(store.take(a3, "session-a"), "and so is the other session's live flow");
  assert.ok(store.take(b2, "session-b"), "and the middle one that no cap touched");
  assert.equal(store.size(), 0);
});

/* ------------------------------------------------------------ exchangeCode */
test("exchangeCode redeems the code with the verifier, and sends no client secret it was not given", async () => {
  const fake = await fakeProvider();
  const verifier = newVerifier();
  const now = 1_700_000_000_000;
  const result = await exchangeCode({
    provider: "google",
    code: CODE,
    verifier,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    fetchImpl: fetch,
    endpoints: { tokenUrl: fake.tokenUrl },
    now: () => now,
  });

  assert.equal(fake.requests.length, 1);
  const [request] = fake.requests;
  assert.equal(request.method, "POST");
  assert.equal(request.path, "/token");
  assert.deepEqual(request.form, {
    grant_type: "authorization_code",
    code: CODE,
    redirect_uri: REDIRECT_URI,
    client_id: CLIENT_ID,
    code_verifier: verifier,
  }, "the code, the exact redirect, the client id and the verifier — and nothing else");
  assert.equal(Object.hasOwn(request.form, "client_secret"), false, "a public client sends no secret");
  assert.equal(Object.hasOwn(request.form, "scope"), false, "scope belongs to the authorization URL");

  assert.equal(result.accessToken, "fake-access-token");
  assert.equal(result.refreshToken, "fake-refresh-token", "Gmail's offline access gives a refresh token");
  assert.equal(result.expiresAt, now + 3_600_000, "expires_in seconds from the injected clock");
});

test("exchangeCode sends the client secret when the caller has one, and posts to the tenant it was given", async () => {
  const fake = await fakeProvider();
  const result = await exchangeCode({
    provider: "microsoft",
    code: CODE,
    verifier: newVerifier(),
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    tenant: "contoso.example",
    fetchImpl: fetch,
    endpoints: { tokenUrl: `${fake.baseUrl}/{tenant}/oauth2/v2.0/token` },
  });
  assert.equal(result.accessToken, "fake-access-token");
  const [request] = fake.requests;
  assert.equal(request.path, "/contoso.example/oauth2/v2.0/token", "the tenant is substituted in the token URL too");
  assert.equal(request.form.client_secret, CLIENT_SECRET);
  assert.equal(request.form.grant_type, "authorization_code");
});

test("a failure body that echoes the code and the secret never reaches the error a caller can print", async () => {
  const fake = await fakeProvider();
  const verifier = newVerifier();
  // What a real OAuth server does on a bad request: it quotes the request back in error_description.
  fake.queueResponse({
    status: 400,
    body: (form) => ({
      error: "invalid_request",
      error_description: `the code ${form.code} for verifier ${form.code_verifier} with secret ${form.client_secret} was refused`,
    }),
  });

  const err = await failure(exchangeCode({
    provider: "google",
    code: CODE,
    verifier,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: REDIRECT_URI,
    fetchImpl: fetch,
    endpoints: { tokenUrl: fake.tokenUrl },
  }));

  assert.ok(err instanceof MailError);
  assert.equal(err.code, "PROTOCOL", "an answer Crow could not use");
  assert.equal(err.detail, "other");
  // Every form a caller, a log line or an error page could print: no request secret in any of them.
  const printed = [err.message, String(err), err.stack, err.code, err.detail, String(err.detail),
    JSON.stringify(err), JSON.stringify({ ...err }), JSON.stringify(err.detail), Object.keys(err).join(",")];
  for (const text of printed.filter((value) => typeof value === "string")) {
    for (const secret of [CODE, verifier, CLIENT_SECRET, "invalid_request", "error_description", "was refused"]) {
      assert.equal(text.includes(secret), false, `the error printed ${secret}`);
    }
  }
});

test("invalid_grant and invalid_client are AUTH_FAILED with the provider's own token as the detail", async () => {
  const fake = await fakeProvider();
  for (const [token, detail] of [["invalid_grant", "invalid_grant"], ["invalid_client", "invalid_client"]]) {
    fake.queueResponse({ status: 400, body: { error: token, error_description: `no: ${CLIENT_SECRET}` } });
    const err = await failure(exchangeCode({
      provider: "google", code: CODE, verifier: newVerifier(), clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI, fetchImpl: fetch, endpoints: { tokenUrl: fake.tokenUrl },
    }));
    assert.equal(err.code, "AUTH_FAILED", `${token} is a refusal, not a protocol fault`);
    assert.equal(err.detail, detail);
    assert.equal(String(err).includes(CLIENT_SECRET), false, "the echoed secret stays out of the error");
  }
});

test("a 5xx is NETWORK even when its body claims invalid_grant, and an empty 2xx is PROTOCOL", async () => {
  const fake = await fakeProvider();
  const call = () => exchangeCode({
    provider: "google", code: CODE, verifier: newVerifier(), clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI, fetchImpl: fetch, endpoints: { tokenUrl: fake.tokenUrl },
  });

  fake.queueResponse({ status: 503, body: { error: "invalid_grant" } });
  assert.equal((await failure(call())).code, "NETWORK", "the provider is down; that is not a credential problem");

  fake.queueResponse({ status: 500, body: "" });
  assert.equal((await failure(call())).code, "NETWORK");

  fake.queueResponse({ status: 200, body: { token_type: "Bearer", expires_in: 3600 } });
  const noToken = await failure(call());
  assert.equal(noToken.code, "PROTOCOL", "a 2xx with no access_token is unusable");
  assert.equal(noToken.detail, "no_access_token");

  fake.queueResponse({ status: 200, body: { access_token: 42 } });
  assert.equal((await failure(call())).code, "PROTOCOL", "an access token that is not a string is unusable");

  // A body that is not JSON at all, on a 200, is the same protocol fault — never a parse error's text.
  fake.queueResponse({ status: 200, body: "<html>nope</html>" });
  const notJson = await failure(call());
  assert.equal(notJson.code, "PROTOCOL");
  assert.equal(notJson.message, "The mail server answered with something Crow could not use.");
});

test("a provider that never answers is NETWORK, once the timeout passes", async () => {
  const fake = await fakeProvider();
  fake.queueResponse({ hang: true });
  const started = Date.now();
  const err = await failure(exchangeCode({
    provider: "google", code: CODE, verifier: newVerifier(), clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI, fetchImpl: fetch, endpoints: { tokenUrl: fake.tokenUrl }, timeoutMs: 250,
  }));
  const elapsed = Date.now() - started;
  assert.equal(err.code, "NETWORK", "a hang is a network failure, not a credential one");
  assert.ok(elapsed >= 200, `waited for the timeout (${elapsed} ms)`);
  assert.ok(elapsed < 5_000, `gave up quickly (${elapsed} ms)`);
});

test("a fetch that cannot even connect is NETWORK, with nothing of the socket error in it", async () => {
  // A throw from the transport, which is what a refused connection or a DNS failure looks like.
  const boom = Object.assign(new Error(`connect ECONNREFUSED for ${CODE}`), { code: "ECONNREFUSED" });
  const err = await failure(exchangeCode({
    provider: "google", code: CODE, verifier: newVerifier(), clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI, fetchImpl: async () => { throw boom; }, endpoints: { tokenUrl: "http://127.0.0.1:1/token" },
  }));
  assert.equal(err.code, "NETWORK");
  assert.equal(String(err).includes(CODE), false, "the fetch error's own text is never copied");
  assert.equal(err.detail, null);

  // A missing parameter is refused before any request is made — the transport is never called.
  let called = false;
  const bad = await failure(exchangeCode({
    provider: "google", code: "", verifier: newVerifier(), clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI, fetchImpl: async () => { called = true; throw boom; },
  }));
  assert.equal(bad.code, "BAD_INPUT");
  assert.equal(called, false, "nothing was sent");
});

/* ------------------------------------------------------- the test-only endpoint */

test("L3: the test-only endpoints override accepts only a loopback http(s) URL, and refuses anything else before a request", async () => {
  let called = 0;
  const transport = async () => {
    called += 1;
    throw new Error("the transport must never be reached");
  };
  const call = (endpoints) => exchangeCode({
    provider: "google", code: CODE, verifier: newVerifier(), clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI, fetchImpl: transport, endpoints,
  });

  for (const tokenUrl of [
    "https://evil.example.test/token",
    "http://example.test/token",
    "http://127.0.0.1.evil.example.test/token",
    "http://10.0.0.1/token",
    "http://100.64.20.11/token",
    "file:///etc/passwd",
    "ftp://127.0.0.1/token",
    "not a url at all",
    "//127.0.0.1/token",
  ]) {
    const err = await failure(call({ tokenUrl }));
    assert.ok(err instanceof MailError, `tokenUrl ${JSON.stringify(tokenUrl)}: a MailError, got ${String(err)}`);
    assert.equal(err.code, "BAD_INPUT", `tokenUrl ${JSON.stringify(tokenUrl)}`);
    assert.equal(err.detail, "endpoints", `tokenUrl ${JSON.stringify(tokenUrl)}`);
  }
  for (const endpoints of [{}, { tokenUrl: 42 }, { tokenUrl: null }, [], "http://127.0.0.1/token"]) {
    const err = await failure(call(endpoints));
    assert.ok(err instanceof MailError, `endpoints ${JSON.stringify(endpoints)}: a MailError, got ${String(err)}`);
    assert.equal(err.code, "BAD_INPUT", `endpoints ${JSON.stringify(endpoints)}`);
    assert.equal(err.detail, "endpoints", `endpoints ${JSON.stringify(endpoints)}`);
  }
  assert.equal(called, 0, "no request was made for a refused override");

  // The loopback forms a test may use are accepted — and `refresh` goes through the same door.
  for (const tokenUrl of [
    "http://127.0.0.1:9/token",
    "https://127.0.0.1:9/token",
    "http://localhost:9/token",
    "http://[::1]:9/token",
    "http://127.0.0.1:9/{tenant}/oauth2/v2.0/token",
  ]) {
    let seen = null;
    const result = await refresh({
      provider: "google", refreshToken: REFRESH_TOKEN, clientId: CLIENT_ID,
      endpoints: { tokenUrl },
      fetchImpl: async (url) => {
        seen = String(url);
        return new Response(JSON.stringify({ access_token: "accepted", expires_in: 60 }), {
          status: 200, headers: { "content-type": "application/json" },
        });
      },
    });
    assert.equal(result.accessToken, "accepted", `tokenUrl ${JSON.stringify(tokenUrl)}`);
    assert.equal(seen, tokenUrl.replace("{tenant}", ""), "the loopback URL was the one called");
  }
});

test("L4: a timeout while READING the body — headers arrived, the answer did not — is NETWORK, not an empty access token", async () => {
  const fake = await fakeProvider();
  fake.queueResponse({ headersThenHang: true });
  const started = Date.now();
  const err = await failure(exchangeCode({
    provider: "google", code: CODE, verifier: newVerifier(), clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI, fetchImpl: fetch, endpoints: { tokenUrl: fake.tokenUrl }, timeoutMs: 250,
  }));
  const elapsed = Date.now() - started;
  assert.equal(err.code, "NETWORK", "a body that never arrives is a network fault, not a protocol one");
  assert.equal(err.detail, null, "and it carries no token and no code");
  assert.notEqual(err.detail, "no_access_token", "the 200 without a body must not read as an empty access token");
  assert.ok(elapsed >= 200, `waited for the timeout (${elapsed} ms)`);
  assert.ok(elapsed < 5_000, `gave up quickly (${elapsed} ms)`);
  assert.equal(fake.requests.length, 1, "the one request was made, and its answer was never finished");
});

/* ------------------------------------------------------------------- refresh */

test("refresh sends the refresh grant, repeats Microsoft's scopes only, and reports a rotation", async () => {
  const fake = await fakeProvider();
  const now = 1_700_000_000_000;

  const plain = await refresh({
    provider: "google", refreshToken: REFRESH_TOKEN, clientId: CLIENT_ID,
    fetchImpl: fetch, endpoints: { tokenUrl: fake.tokenUrl }, now: () => now,
  });
  assert.equal(fake.requests.length, 1);
  assert.deepEqual(fake.requests[0].form, {
    grant_type: "refresh_token",
    refresh_token: REFRESH_TOKEN,
    client_id: CLIENT_ID,
  }, "Google's refresh grant takes no scope and no secret here");
  assert.equal(plain.accessToken, "fake-access-token-refreshed");
  assert.equal(plain.expiresAt, now + 3_600_000);
  assert.equal(Object.hasOwn(plain, "refreshToken"), false, "nothing to rotate means no refreshToken key");

  // Microsoft wants its scopes repeated, and this time the provider rotates the refresh token.
  fake.queueResponse({ status: 200, body: { access_token: "rotated-access", expires_in: 120, refresh_token: "rotated-refresh" } });
  const rotated = await refresh({
    provider: "microsoft", refreshToken: REFRESH_TOKEN, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET,
    fetchImpl: fetch, endpoints: { tokenUrl: fake.tokenUrl }, now: () => now,
  });
  assert.equal(fake.requests[1].form.scope, PROVIDERS.microsoft.scopes.join(" "));
  assert.equal(fake.requests[1].form.client_secret, CLIENT_SECRET);
  assert.equal(rotated.accessToken, "rotated-access");
  assert.equal(rotated.refreshToken, "rotated-refresh", "a rotation is reported, never dropped");
  assert.equal(rotated.expiresAt, now + 120_000);
});

test("expires_in that is missing or nonsense falls back to an hour, and a refusal is AUTH_FAILED", async () => {
  const fake = await fakeProvider();
  const now = 1_700_000_000_000;
  const call = () => refresh({
    provider: "google", refreshToken: REFRESH_TOKEN, clientId: CLIENT_ID,
    fetchImpl: fetch, endpoints: { tokenUrl: fake.tokenUrl }, now: () => now,
  });

  fake.queueResponse({ status: 200, body: { access_token: "a" } });
  assert.equal((await call()).expiresAt, now + 3_600_000, "a missing expires_in is an hour");
  fake.queueResponse({ status: 200, body: { access_token: "a", expires_in: "soon" } });
  assert.equal((await call()).expiresAt, now + 3_600_000, "so is a nonsense one");
  fake.queueResponse({ status: 200, body: { access_token: "a", expires_in: -5 } });
  assert.equal((await call()).expiresAt, now + 3_600_000);
  fake.queueResponse({ status: 200, body: { access_token: "a", expires_in: 90 } });
  assert.equal((await call()).expiresAt, now + 90_000, "a real expiry is honoured");

  fake.queueResponse({ status: 400, body: { error: "invalid_grant", error_description: "expired" } });
  const refused = await failure(call());
  assert.equal(refused.code, "AUTH_FAILED");
  assert.equal(refused.detail, "invalid_grant", "the caller re-asks the person to sign in");
  assert.equal(String(refused).includes("expired"), false);
});