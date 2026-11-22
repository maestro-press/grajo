// Crow Mail OAuth (plan 5, Task 3b): the access-token provider, the per-account registry, the meta map
// and the boot wiring that makes the provider the ONE writer of a rotated refresh token.
//
// Everything here runs against the local fake token endpoint (tests/fixtures/fake-oauth-provider.mjs)
// through the `endpoints` override, so no test reaches the internet, and against the in-process fake
// IMAP server for the end-to-end cases, so none of them dials a mailbox. Every secret in this file is a
// fixed fake, and the leak checks search the whole error, the whole log line and the whole keychain
// write list for it.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "mail-oauth-token-"));
process.env.CROW_HOME = join(root, "home");
process.env.CROW_DATA_DIR = join(root, "data");
delete process.env.CROW_DB_PATH;
mkdirSync(process.env.CROW_HOME, { recursive: true });
mkdirSync(process.env.CROW_DATA_DIR, { recursive: true });

const { createDbClient } = await import("../servers/db.js");
const { MAIL_DDL, MAIL_ACCOUNT_SEND_COLUMNS, MAIL_DRAFTS_DDL } = await import("../servers/shared/mail-schema.js");
const { MailError, MAIL_ERROR_TEXT } = await import("../servers/gateway/mail/errors.js");
const { createTokenProvider } = await import("../servers/gateway/mail/oauth/token-provider.js");
const { createTokenProviderRegistry } = await import("../servers/gateway/mail/oauth/registry.js");
const { getOauthMeta, setOauthMeta, deleteOauthMeta, MAIL_OAUTH_META_SETTING } = await import("../servers/gateway/mail/oauth/meta.js");
const { createAccount, getAccount } = await import("../servers/gateway/mail/store/accounts.js");
const { createMailCredentials } = await import("../servers/gateway/mail/credentials.js");
const { startMailSync, stopMailSync } = await import("../servers/gateway/boot/mail-boot.js");
const { fallbackAdapterFactory } = await import("../servers/gateway/routes/mail-api.js");
const { POLL_MS } = await import("../servers/gateway/mail/sync/supervisor.js");
const { startFakeOAuthProvider } = await import("./fixtures/fake-oauth-provider.mjs");
const {
  FAKE_USER, createFakeImapServer, makeRaw,
} = await import("./fixtures/fake-mail-server.mjs");

const REPO = new URL("..", import.meta.url).pathname;

const ACCOUNT_ID = "ma-0123456789abcdef";
const OTHER_ACCOUNT_ID = "ma-fedcba9876543210";
const ADDRESS = "alex@example.test";
const CLIENT_ID = "client-id-4f1a2b7d";
const CLIENT_SECRET = "client-secret-9d3c51aa";
const REFRESH_TOKEN = "refresh-token-5a2b";
const ROTATED_REFRESH = "refresh-token-rotated-9e1f";
const ACCESS_TOKEN = "access-token-7c3d";
const ROTATED_ACCESS = "access-token-rotated-2b8a";

const fakes = [];
const dbs = [];
after(async () => {
  for (const fake of fakes) await fake.close();
  for (const db of dbs) { try { db.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

async function fakeProvider() {
  const fake = await startFakeOAuthProvider();
  fakes.push(fake);
  return fake;
}

/** A mail account row as the store returns one: no secret on it, and the provider it signs in with. */
function accountRow(overrides = {}) {
  return {
    id: ACCOUNT_ID,
    address: ADDRESS,
    username: ADDRESS,
    authKind: "xoauth2",
    provider: "google",
    ...overrides,
  };
}

const defaultSecrets = (overrides = {}) => ({
  MAIL_OAUTH_CLIENT_ID: CLIENT_ID,
  MAIL_REFRESH_TOKEN: REFRESH_TOKEN,
  ...overrides,
});

/** A clock the test moves by hand. */
function makeClock(start = 1_700_000_000_000) {
  return { value: start, now() { return this.value; } };
}

/**
 * One provider over the fake endpoint, with everything a test may want to watch: the writes, the
 * account marks, the meta and the clock.
 */
function makeProvider({ fake, clock = makeClock(), account = accountRow(), secrets = defaultSecrets(), writes = [], marks = [], meta = null, onTokenRotated } = {}) {
  return createTokenProvider({
    accountId: ACCOUNT_ID,
    getAccount: async () => account,
    credentials: {
      getSecrets: async () => (typeof secrets === "function" ? secrets() : secrets),
      saveSecret: async (accountId, key, value) => { writes.push({ accountId, key, value }); return { id: 1, created: true }; },
    },
    fetchImpl: fetch,
    now: () => clock.now(),
    markAuthFailed: async (accountId) => { marks.push(accountId); },
    onTokenRotated: onTokenRotated ?? (async (accountId, rotation) => { writes.push({ accountId, key: "MAIL_REFRESH_TOKEN", value: rotation.refreshToken }); }),
    endpoints: { tokenUrl: fake.tokenUrl },
    getMeta: async () => meta,
    log: () => {},
  });
}

const isMailError = (code, detail = undefined) => (err) => {
  assert.ok(err instanceof MailError, `a MailError, got ${String(err)}`);
  assert.equal(err.code, code);
  if (detail !== undefined) assert.equal(err.detail, detail);
  return true;
};

/* -------------------------------------------------------------- the cache */

test("a cached access token answers the next call without a request, and the result carries no refresh token", async () => {
  const fake = await fakeProvider();
  const provider = makeProvider({ fake });

  const first = await provider({ accountId: ACCOUNT_ID });
  assert.equal(first.accessToken, "fake-access-token-refreshed");
  assert.equal(first.expiresAt, 1_700_000_000_000 + 3_600_000, "expires_in seconds on the injected clock");
  assert.equal(Object.hasOwn(first, "refreshToken"), false, "the provider never hands a refresh token out");
  assert.deepEqual(Object.keys(first).sort(), ["accessToken", "expiresAt"]);
  assert.equal(fake.requests.length, 1);
  assert.equal(fake.requests[0].form.grant_type, "refresh_token");
  assert.equal(fake.requests[0].form.refresh_token, REFRESH_TOKEN);
  assert.equal(fake.requests[0].form.client_id, CLIENT_ID);
  assert.equal(Object.hasOwn(fake.requests[0].form, "client_secret"), false, "no secret was stored for this client");

  const second = await provider({ accountId: ACCOUNT_ID });
  assert.equal(second.accessToken, first.accessToken);
  assert.equal(fake.requests.length, 1, "the cached token answered: no second request");
});

test("a token is refreshed once it has less than 60 seconds left, and not a moment before", async () => {
  const fake = await fakeProvider();
  const clock = makeClock();
  const provider = makeProvider({ fake, clock });

  const first = await provider({ accountId: ACCOUNT_ID });
  assert.equal(fake.requests.length, 1);
  const expiresAt = first.expiresAt;

  clock.value = expiresAt - 60_001;
  await provider({ accountId: ACCOUNT_ID });
  assert.equal(fake.requests.length, 1, "61 seconds left is still a usable token");

  clock.value = expiresAt - 60_000;
  const refreshed = await provider({ accountId: ACCOUNT_ID });
  assert.equal(fake.requests.length, 2, "60 seconds left is the headroom the provider keeps");
  assert.equal(refreshed.expiresAt, clock.value + 3_600_000, "the new token's own expiry");
});

test("two concurrent forceRefresh calls make exactly one token request", async () => {
  const fake = await fakeProvider();
  const clock = makeClock();
  const provider = makeProvider({ fake, clock });
  await provider({ accountId: ACCOUNT_ID });
  assert.equal(fake.requests.length, 1);

  const [a, b] = await Promise.all([
    provider({ accountId: ACCOUNT_ID, forceRefresh: true }),
    provider({ accountId: ACCOUNT_ID, forceRefresh: true }),
  ]);
  assert.equal(fake.requests.length, 2, "one shared refresh, not two");
  assert.equal(a.accessToken, b.accessToken);
  assert.equal(a.accessToken, "fake-access-token-refreshed");
});

/* ------------------------------------------------------------- rotation */

test("a rotated refresh token is written BEFORE the access token is resolved", async () => {
  const fake = await fakeProvider();
  fake.queueResponse({
    status: 200,
    body: { access_token: ROTATED_ACCESS, expires_in: 3600, refresh_token: ROTATED_REFRESH },
  });
  const order = [];
  const provider = makeProvider({
    fake,
    onTokenRotated: async (accountId, rotation) => {
      order.push("write");
      assert.equal(accountId, ACCOUNT_ID);
      assert.equal(rotation.refreshToken, ROTATED_REFRESH);
      await new Promise((resolve) => setImmediate(resolve));
    },
  });

  const result = await provider({ accountId: ACCOUNT_ID });
  order.push("returned");

  assert.deepEqual(order, ["write", "returned"], "the write settled before the token was handed out");
  assert.equal(result.accessToken, ROTATED_ACCESS);
  assert.equal(Object.hasOwn(result, "refreshToken"), false, "the writer is the only holder of a rotation");
});

test("a failed rotation write is logged by code only, the token is still returned, and the next refresh sends the NEW token and retries the write", async () => {
  const fake = await fakeProvider();
  fake.queueResponse({
    status: 200,
    body: { access_token: ROTATED_ACCESS, expires_in: 3600, refresh_token: ROTATED_REFRESH },
  });

  const writes = [];
  let attempt = 0;
  const warnings = [];
  const clock = makeClock();
  const provider = createTokenProvider({
    accountId: ACCOUNT_ID,
    getAccount: async () => accountRow(),
    credentials: { getSecrets: async () => defaultSecrets() },
    fetchImpl: fetch,
    now: () => clock.now(),
    markAuthFailed: async () => {},
    onTokenRotated: async (accountId, rotation) => {
      attempt += 1;
      if (attempt === 1) throw new Error(`keychain refused ${rotation.refreshToken}`);
      writes.push(rotation.refreshToken);
    },
    endpoints: { tokenUrl: fake.tokenUrl },
    getMeta: async () => null,
    log: (line) => warnings.push(line),
  });

  const saved = [];
  const originalWarn = console.warn;
  console.warn = (line) => saved.push(String(line));
  let first;
  try {
    first = await provider({ accountId: ACCOUNT_ID });
  } finally {
    console.warn = originalWarn;
  }

  assert.equal(first.accessToken, ROTATED_ACCESS, "the access token in hand is returned anyway");
  assert.equal(attempt, 1, "the write was tried");
  const logged = JSON.stringify(warnings);
  assert.ok(!logged.includes(ROTATED_REFRESH), "no rotation text in the log line");
  assert.ok(!logged.includes("refused"), "no error text in the log line");
  assert.deepEqual(warnings, [{ event: "token_rotation_failed", code: "PROTOCOL" }],
    "an unclassifiable write failure logs its fixed code and nothing else");

  // The next refresh uses the rotated token it kept in memory AND retries the write.
  await provider({ accountId: ACCOUNT_ID, forceRefresh: true });
  assert.equal(attempt, 2, "the failed write was retried");
  assert.deepEqual(writes, [ROTATED_REFRESH], "the retry wrote the rotated token");
  assert.equal(fake.requests.length, 2);
  assert.equal(fake.requests[1].form.refresh_token, ROTATED_REFRESH, "the NEW refresh token was sent");
});

/* --------------------------------------------------------- a dead grant */

test("invalid_grant marks the account once, and every later call refuses without a request", async () => {
  const fake = await fakeProvider();
  fake.queueResponse({ status: 400, body: { error: "invalid_grant", error_description: "token revoked" } });
  const marks = [];
  const provider = makeProvider({ fake, marks });

  const err = await provider({ accountId: ACCOUNT_ID }).catch((error) => error);
  assert.ok(isMailError("AUTH_FAILED", "invalid_grant")(err));
  assert.deepEqual(marks, [ACCOUNT_ID], "the account was marked once");
  assert.equal(fake.requests.length, 1);

  for (const forceRefresh of [false, true]) {
    const again = await provider({ accountId: ACCOUNT_ID, forceRefresh }).catch((error) => error);
    assert.ok(isMailError("AUTH_FAILED")(again), "a dead grant stays refused");
    assert.equal(fake.requests.length, 1, "no second call was made to the provider");
    assert.deepEqual(marks, [ACCOUNT_ID], "and the account was not marked twice");
  }
});

test("a network failure changes nothing: no mark, no flag, and the next call tries again", async () => {
  const fake = await fakeProvider();
  fake.queueResponse({ status: 503, body: { error: "server_error" } });
  const marks = [];
  const provider = makeProvider({ fake, marks });

  const err = await provider({ accountId: ACCOUNT_ID }).catch((error) => error);
  assert.ok(isMailError("NETWORK")(err));
  assert.deepEqual(marks, [], "an unreachable provider is not a bad grant");

  const next = await provider({ accountId: ACCOUNT_ID });
  assert.equal(next.accessToken, "fake-access-token-refreshed", "the retry was allowed and succeeded");
  assert.equal(fake.requests.length, 2);
});

test("an unknown provider is AUTH_FAILED before any request, and a mismatched account id is refused", async () => {
  const fake = await fakeProvider();
  for (const providerName of ["yahoo", "", null, undefined]) {
    const provider = makeProvider({ fake, account: accountRow({ provider: providerName }) });
    const err = await provider({ accountId: ACCOUNT_ID }).catch((error) => error);
    assert.ok(isMailError("AUTH_FAILED")(err), `provider ${JSON.stringify(providerName)}`);
  }
  assert.equal(fake.requests.length, 0, "nothing was asked of any provider");

  const provider = makeProvider({ fake });
  const err = await provider({ accountId: OTHER_ACCOUNT_ID }).catch((error) => error);
  assert.ok(isMailError("BAD_INPUT", "account_id")(err));
  assert.equal(fake.requests.length, 0);
});

test("the provider name comes from the account row and the tenant from the meta, else 'common'", async () => {
  const fake = await fakeProvider();
  const microsoftUrl = { tokenUrl: `${fake.baseUrl}/{tenant}/oauth2/v2.0/token` };

  for (const [name, meta, expectedPath] of [
    ["outlook", null, "/common/oauth2/v2.0/token"],
    ["microsoft", { grantedAt: 1, publishing: "production", provider: "microsoft", tenant: "contoso.example" },
      "/contoso.example/oauth2/v2.0/token"],
  ]) {
    const provider = createTokenProvider({
      accountId: ACCOUNT_ID,
      getAccount: async () => accountRow({ provider: name }),
      credentials: { getSecrets: async () => defaultSecrets() },
      fetchImpl: fetch,
      markAuthFailed: async () => {},
      onTokenRotated: async () => {},
      endpoints: microsoftUrl,
      getMeta: async () => meta,
      log: () => {},
    });
    await provider({ accountId: ACCOUNT_ID });
    assert.equal(fake.requests[fake.requests.length - 1].path, expectedPath, `provider ${name}`);
  }

  // Google's own names, and its own endpoint: no tenant anywhere.
  for (const name of ["google", "GMAIL"]) {
    const provider = makeProvider({ fake, account: accountRow({ provider: name }) });
    await provider({ accountId: ACCOUNT_ID });
    assert.equal(fake.requests[fake.requests.length - 1].path, "/token", `provider ${name}`);
  }
});

/* ------------------------------------------------------- no access token, ever */

test("an access token never reaches saveSecret, and the keychain sees only the refresh token", async () => {
  const fake = await fakeProvider();
  fake.queueResponse({
    status: 200,
    body: { access_token: ROTATED_ACCESS, expires_in: 3600, refresh_token: ROTATED_REFRESH },
  });
  const writes = [];
  const provider = makeProvider({ fake, writes });

  const result = await provider({ accountId: ACCOUNT_ID });
  assert.equal(result.accessToken, ROTATED_ACCESS);

  // The wrapper's saveSecret saw one write, and it is the refresh token.
  assert.equal(writes.length, 1);
  assert.equal(writes[0].key, "MAIL_REFRESH_TOKEN");
  assert.equal(writes[0].value, ROTATED_REFRESH);
  const surface = JSON.stringify(writes);
  assert.ok(!surface.includes(ROTATED_ACCESS), "the access token was never written");
  assert.ok(!surface.includes("expiresAt"), "no token result was persisted");
});

/* ------------------------------------------------------------- the meta map */

test("the meta is one local setting keyed by account id: validated on write, never a secret, and absent reads null", async () => {
  const db = await freshDb();
  assert.equal(await getOauthMeta(db, ACCOUNT_ID), null, "nothing recorded is null");

  // No account row is needed: the meta is a label, and the map is keyed by the id.
  const stored = await setOauthMeta(db, ACCOUNT_ID, {
    grantedAt: 1_700_000_000_000,
    publishing: "production",
    provider: "Google",
    tenant: "contoso.example",
  });
  assert.deepEqual(stored, {
    grantedAt: 1_700_000_000_000, publishing: "production", provider: "google", tenant: "contoso.example",
  });
  assert.deepEqual(await getOauthMeta(db, ACCOUNT_ID), stored);

  const rows = (await db.execute({ sql: "SELECT * FROM dashboard_settings_overrides", args: [] })).rows;
  assert.equal(rows.length, 1);
  assert.equal(rows[0].key, MAIL_OAUTH_META_SETTING, "one setting holds the whole map");
  const map = JSON.parse(rows[0].value);
  assert.equal(map[ACCOUNT_ID].publishing, "production");
  assert.equal((await db.execute({ sql: "SELECT * FROM dashboard_settings", args: [] })).rows.length, 0,
    "local scope: never the global, replicated row");

  // A second account joins the same map, and only its own entry changes.
  await setOauthMeta(db, OTHER_ACCOUNT_ID, { grantedAt: 5, publishing: "testing", provider: "microsoft" });
  assert.equal((await getOauthMeta(db, ACCOUNT_ID)).publishing, "production");
  assert.equal((await getOauthMeta(db, OTHER_ACCOUNT_ID)).publishing, "testing");

  // Dropping one account's meta (its removal) leaves the other entry alone, and is idempotent.
  assert.equal(await deleteOauthMeta(db, OTHER_ACCOUNT_ID), true);
  assert.equal(await getOauthMeta(db, OTHER_ACCOUNT_ID), null);
  assert.equal(await deleteOauthMeta(db, OTHER_ACCOUNT_ID), false, "nothing left to remove");
  assert.equal((await getOauthMeta(db, ACCOUNT_ID)).publishing, "production", "the other entry is untouched");

  // Publishing that was not named, or not one of the two words, is "unknown" — not an error.
  for (const publishing of [undefined, "unknown", "beta", 7, null]) {
    const entry = await setOauthMeta(db, ACCOUNT_ID, { grantedAt: 2, publishing, provider: "google" });
    assert.equal(entry.publishing, "unknown", `publishing ${JSON.stringify(publishing)}`);
  }

  // Bad input is BAD_INPUT and writes nothing.
  const before = JSON.stringify((await db.execute({ sql: "SELECT value FROM dashboard_settings_overrides", args: [] })).rows);
  for (const [id, entry] of [
    ["nope", { provider: "google" }],
    [ACCOUNT_ID, { provider: "" }],
    [ACCOUNT_ID, { provider: 7 }],
    [ACCOUNT_ID, { grantedAt: -1, provider: "google" }],
    [ACCOUNT_ID, { grantedAt: 1.5, provider: "google" }],
    [ACCOUNT_ID, { provider: "google", tenant: "../../evil" }],
    [ACCOUNT_ID, null],
  ]) {
    await assert.rejects(setOauthMeta(db, id, entry), (err) => err instanceof MailError && err.code === "BAD_INPUT",
      `setOauthMeta(${JSON.stringify(id)}, ${JSON.stringify(entry)})`);
  }
  const after = JSON.stringify((await db.execute({ sql: "SELECT value FROM dashboard_settings_overrides", args: [] })).rows);
  assert.equal(after, before, "a refused write changed nothing");

  const raw = (await db.execute({ sql: "SELECT value FROM dashboard_settings_overrides", args: [] })).rows[0].value;
  for (const secret of [REFRESH_TOKEN, CLIENT_ID, CLIENT_SECRET, ACCESS_TOKEN]) {
    assert.ok(!raw.includes(secret), "the meta carries no secret");
  }
});

/* --------------------------------------------------------- the registry */

test("the registry keeps one provider object per account, and forget drops it", async () => {
  const db = await freshDb();
  const credentials = { getSecrets: async () => ({}), saveSecret: async () => ({ id: 1 }) };
  const registry = createTokenProviderRegistry({ db, credentials, fetchImpl: async () => { throw new Error("no network"); } });

  const alex = registry.tokenProviderFor(ACCOUNT_ID);
  assert.equal(typeof alex, "function");
  assert.equal(registry.tokenProviderFor(ACCOUNT_ID), alex, "the same account answers the same object");
  const other = registry.tokenProviderFor(OTHER_ACCOUNT_ID);
  assert.notEqual(other, alex, "another account gets its own provider");
  assert.equal(registry.tokenProviderFor(""), null, "nothing that is not an account id gets a provider");
  assert.equal(registry.size(), 2);

  registry.forget(ACCOUNT_ID);
  assert.equal(registry.size(), 1);
  const rebuilt = registry.tokenProviderFor(ACCOUNT_ID);
  assert.notEqual(rebuilt, alex, "a forgotten account gets a fresh provider");
  assert.equal(registry.tokenProviderFor(OTHER_ACCOUNT_ID), other, "the other account was untouched");

  registry.forget("not-an-account");
  registry.forget(ACCOUNT_ID);
  registry.forget(ACCOUNT_ID);
  assert.equal(registry.size(), 1, "forgetting twice is not an error");
});

test("H2: the registry's default writes no status — the dead grant is latched in the provider alone", async () => {
  const db = await freshDb();
  const account = await createAccount(db, {
    label: "Alex",
    address: ADDRESS,
    provider: "google",
    authKind: "xoauth2",
    imap: { host: "mail.example.test", port: 993, security: "ssl" },
    smtp: { host: "mail.example.test", port: 465, security: "ssl" },
  });
  const fake = await fakeProvider();
  fake.queueResponse({ status: 400, body: { error: "invalid_grant" } });

  const credentials = {
    getSecrets: async () => defaultSecrets(),
    saveSecret: async () => ({ id: 1, created: true }),
  };
  const registry = createTokenProviderRegistry({
    db,
    credentials,
    fetchImpl: fetch,
    endpoints: { tokenUrl: fake.tokenUrl },
  });
  const provider = registry.tokenProviderFor(account.id);
  const err = await provider({ accountId: account.id }).catch((error) => error);
  assert.equal(err.code, "AUTH_FAILED");
  assert.equal(err.detail, "invalid_grant");
  // REVIEW FIX H2: the supervisor owns the transition (and its one bell), so the provider's own latch
  // is all this writes. A status write here would land before the error reached the supervisor, whose
  // recordAuthFailure only notifies on ENTERING auth_failed — the bell would never ring at all.
  assert.equal((await getAccount(db, account.id)).status, "active", "the registry writes no status");

  // The latch still holds: no second request, and the same AUTH_FAILED answer.
  for (const forceRefresh of [false, true]) {
    const again = await provider({ accountId: account.id, forceRefresh }).catch((error) => error);
    assert.equal(again.code, "AUTH_FAILED");
    assert.equal(fake.requests.length, 1, "a dead grant is not hammered");
  }
});

/* --------------------------------------- a grant that dies, and a provider that is retired */

test("H2: a grant that dies OUTSIDE the supervisor is announced exactly once by the supervisor's next run", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  const account = await xoauth2Account(db, imap, { host: "127.0.0.1", port: 1 });
  const fake = await fakeProvider();
  const home = join(root, "keychain-h2");
  mkdirSync(home, { recursive: true });
  const credentials = createMailCredentials({ db, crowHome: home });
  await credentials.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await credentials.saveSecret(account.id, "MAIL_REFRESH_TOKEN", REFRESH_TOKEN);

  // No `notify` is injected: this is the supervisor's own default bell, written with source "mail".
  const clock = makeTimerClock();
  const handle = await startMailSync({
    db,
    env: { CROW_MAIL: "1" },
    noAuth: false,
    credentials,
    oauthEndpoints: { tokenUrl: fake.tokenUrl },
    localInstance: { instanceId: "instA", instanceName: "Alpha" },
    ...clock.options(),
    log: () => {},
  });
  assert.equal(handle.started, true);
  try {
    // A live grant: the first full sync signs in and arms the watch.
    assert.equal(await until(async () => (await handle.supervisor.status(account.id)).watching === true), true,
      "the first sync succeeded on the live grant");
    assert.equal(fake.requests.length, 1);
    assert.deepEqual(await mailNotificationRows(db), [], "nothing to announce yet");

    // The grant dies at the provider. An adapter built OUTSIDE the supervisor (the routes' fallback
    // factory holds the same registry provider) is the one that meets it first.
    fake.queueResponse({ status: 400, body: { error: "invalid_grant" } });
    const provider = handle.tokenProviders.tokenProviderFor(account.id);
    const outside = await provider({ accountId: account.id, forceRefresh: true }).catch((error) => error);
    assert.equal(outside.code, "AUTH_FAILED");
    assert.equal(outside.detail, "invalid_grant");
    assert.equal((await getAccount(db, account.id)).status, "active",
      "the registry writes no status: the supervisor owns the transition");
    assert.deepEqual(await mailNotificationRows(db), [], "and a caller outside the supervisor rings no bell");

    // The supervisor's next run of that account gets AUTH_FAILED from the latched provider (it asks the
    // endpoint nothing more), makes the transition, and rings the one bell.
    const requestsBefore = fake.requests.length;
    await handle.supervisor.restartAccount(account.id);
    const after = await getAccount(db, account.id);
    assert.equal(after.status, "auth_failed");
    assert.equal(after.statusDetail, "AUTH_FAILED");
    assert.equal(fake.requests.length, requestsBefore, "the latched provider refused without a request");
    const bells = await mailNotificationRows(db);
    assert.equal(bells.length, 1, "exactly one bell");
    assert.equal(bells[0].source, "mail");
    assert.equal(bells[0].title, "Crow Mail cannot sign in");
    // Plan 5, Task 6: this account signs in with XOAUTH2, so its bell is C29 — never the sentence that
    // sends the owner looking for an app password it does not have — and it names no address.
    assert.equal(bells[0].body, "The sign-in for this account stopped working. Reconnect to keep mail syncing.");
    assert.equal(bells[0].body.includes(ADDRESS), false, "the bell carries no address");

    // The following ticks ring nothing more: the account is already auth_failed.
    await clock.advance(POLL_MS * 3);
    assert.equal((await mailNotificationRows(db)).length, 1, "no second bell on the next tick");
    assert.equal(fake.requests.length, requestsBefore);
  } finally {
    await handle.stop();
  }
});

test("M1: a refresh in flight when the account is forgotten never starts a rotation write", async () => {
  const db = await freshDb();
  const account = await createAccount(db, {
    label: "Alex",
    address: ADDRESS,
    provider: "google",
    authKind: "xoauth2",
    imap: { host: "mail.example.test", port: 993, security: "ssl" },
    smtp: { host: "mail.example.test", port: 465, security: "ssl" },
  });
  const fake = await fakeProvider();
  // The provider holds the answer: the refresh is observably in flight when the account is forgotten.
  fake.queueResponse({
    hold: true,
    status: 200,
    body: { access_token: ROTATED_ACCESS, expires_in: 3600, refresh_token: ROTATED_REFRESH },
  });

  const home = join(root, "keychain-m1");
  mkdirSync(home, { recursive: true });
  const real = createMailCredentials({ db, crowHome: home });
  await real.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await real.saveSecret(account.id, "MAIL_REFRESH_TOKEN", REFRESH_TOKEN);
  const writes = [];
  const credentials = {
    getSecrets: (id) => real.getSecrets(id),
    deleteSecrets: (id) => real.deleteSecrets(id),
    saveSecret: (id, key, value) => { writes.push({ id, key, value }); return real.saveSecret(id, key, value); },
  };

  const registry = createTokenProviderRegistry({
    db,
    credentials,
    fetchImpl: fetch,
    endpoints: { tokenUrl: fake.tokenUrl },
  });
  const provider = registry.tokenProviderFor(account.id);
  const waiting = provider({ accountId: account.id }).catch((error) => error);
  assert.equal(await until(async () => fake.requests.length === 1), true, "the refresh reached the provider");

  // The account is removed: the registry forgets (and retires) its provider BEFORE the secrets go.
  await registry.forget(account.id);
  await credentials.deleteSecrets(account.id);
  fake.releaseHeld();

  const err = await waiting;
  assert.ok(err instanceof MailError, `the waiting caller hears a MailError, got ${String(err)}`);
  assert.equal(err.code, "AUTH_FAILED");
  assert.equal(err.detail, "retired");
  assert.deepEqual(writes, [], "the retired provider wrote nothing at all");
  assert.deepEqual(await credentials.getSecrets(account.id), {}, "and no keychain row was left for the id");
  const rows = (await db.execute({
    sql: "SELECT COUNT(*) AS n FROM crow_keychain WHERE connection_uuid = ?",
    args: [account.id],
  })).rows;
  assert.equal(Number(rows[0].n), 0, "no live token left for a removed account");

  // The retired object keeps refusing, and the registry hands out a fresh provider for the id.
  for (const forceRefresh of [false, true]) {
    const again = await provider({ accountId: account.id, forceRefresh }).catch((error) => error);
    assert.equal(again.code, "AUTH_FAILED");
    assert.equal(again.detail, "retired");
  }
  assert.notEqual(registry.tokenProviderFor(account.id), provider, "forget drops the retired provider");
  assert.equal(fake.requests.length, 1, "the retired provider made no second request");
});

test("M1: a rotation that lands AFTER forget is discarded instead of overwriting the new grant's token", async () => {
  const db = await freshDb();
  const account = await createAccount(db, {
    label: "Alex",
    address: ADDRESS,
    provider: "google",
    authKind: "xoauth2",
    imap: { host: "mail.example.test", port: 993, security: "ssl" },
    smtp: { host: "mail.example.test", port: 465, security: "ssl" },
  });
  const fake = await fakeProvider();
  fake.queueResponse({ hold: true, status: 200, body: { access_token: ACCESS_TOKEN, expires_in: 3600, refresh_token: ROTATED_REFRESH } });

  const writes = [];
  const registry = createTokenProviderRegistry({
    db,
    credentials: {
      getSecrets: async () => defaultSecrets(),
      saveSecret: async (accountId, key, value) => { writes.push({ accountId, key, value }); return { id: 1, created: true }; },
    },
    fetchImpl: fetch,
    endpoints: { tokenUrl: fake.tokenUrl },
  });
  const oldGrant = registry.tokenProviderFor(account.id);
  const waiting = oldGrant({ accountId: account.id }).catch((error) => error);
  assert.equal(await until(async () => fake.requests.length === 1), true);

  // A fresh grant replaces the old one while the old refresh is still in the air.
  registry.forget(account.id);
  const newGrant = registry.tokenProviderFor(account.id);
  assert.notEqual(newGrant, oldGrant);
  fake.releaseHeld();
  assert.equal((await waiting).detail, "retired");
  assert.deepEqual(writes, [], "the old grant's rotation never reached the keychain");
});

test("M1: forget() waits for a rotation write already in flight, so DELETE leaves no token for the account", async () => {
  const db = await freshDb();
  const account = await createAccount(db, {
    label: "Alex",
    address: ADDRESS,
    provider: "google",
    authKind: "xoauth2",
    imap: { host: "mail.example.test", port: 993, security: "ssl" },
    smtp: { host: "mail.example.test", port: 465, security: "ssl" },
  });
  const fake = await fakeProvider();
  // The next refresh rotates, so the write the test holds is the rotated refresh token's.
  fake.queueResponse({
    status: 200,
    body: { access_token: ROTATED_ACCESS, expires_in: 3600, refresh_token: ROTATED_REFRESH },
  });

  const home = join(root, "keychain-m1-write");
  mkdirSync(home, { recursive: true });
  const real = createMailCredentials({ db, crowHome: home });
  await real.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await real.saveSecret(account.id, "MAIL_REFRESH_TOKEN", REFRESH_TOKEN);

  // The keychain write is HELD: the rotation reached saveSecret and its row does not exist yet, so a
  // delete that did not wait for it would find nothing to remove and the row would land afterwards.
  let releaseWrite = null;
  const writeGate = new Promise((resolve) => { releaseWrite = resolve; });
  let writeEntered = false;
  const credentials = {
    getSecrets: (id) => real.getSecrets(id),
    deleteSecrets: (id) => real.deleteSecrets(id),
    saveSecret: async (id, key, value) => {
      if (key === "MAIL_REFRESH_TOKEN") {
        writeEntered = true;
        await writeGate;
      }
      return real.saveSecret(id, key, value);
    },
  };
  const registry = createTokenProviderRegistry({
    db,
    credentials,
    fetchImpl: fetch,
    endpoints: { tokenUrl: fake.tokenUrl },
  });
  const provider = registry.tokenProviderFor(account.id);
  const refreshing = provider({ accountId: account.id }).catch((error) => error);
  assert.equal(await until(() => writeEntered), true, "the rotation write is in flight");

  // DELETE /accounts/:id, in its own order: forget() is awaited, and the sealed secrets go after it.
  let deleteDone = false;
  const deletion = (async () => {
    await registry.forget(account.id);
    await credentials.deleteSecrets(account.id);
    deleteDone = true;
  })();
  for (let i = 0; i < 40; i += 1) await new Promise((resolve) => setImmediate(resolve));
  assert.equal(deleteDone, false, "forget() does not resolve while the rotation write is still in the air");

  releaseWrite();
  await deletion;
  const failure = await refreshing;
  assert.equal(failure.code, "AUTH_FAILED", "the retired provider's caller is told it is gone");
  assert.equal(failure.detail, "retired");

  const rows = (await db.execute({
    sql: "SELECT COUNT(*) AS n FROM crow_keychain WHERE connection_uuid = ? AND env_key = 'MAIL_REFRESH_TOKEN'",
    args: [account.id],
  })).rows;
  assert.equal(Number(rows[0].n), 0,
    "the in-flight rotation landed BEFORE deleteSecrets, so no live token remains for the account");
});

test("H2: a dead grant the SUPERVISOR meets rings exactly one bell, and none on the ticks after", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  const account = await xoauth2Account(db, imap, { host: "127.0.0.1", port: 1 });
  const fake = await fakeProvider();
  // The grant is already dead when the first sync signs in.
  fake.queueResponse({ status: 400, body: { error: "invalid_grant" } });
  const home = join(root, "keychain-h2-supervisor");
  mkdirSync(home, { recursive: true });
  const credentials = createMailCredentials({ db, crowHome: home });
  await credentials.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await credentials.saveSecret(account.id, "MAIL_REFRESH_TOKEN", REFRESH_TOKEN);

  const clock = makeTimerClock();
  const handle = await startMailSync({
    db,
    env: { CROW_MAIL: "1" },
    noAuth: false,
    credentials,
    oauthEndpoints: { tokenUrl: fake.tokenUrl },
    localInstance: { instanceId: "instA", instanceName: "Alpha" },
    ...clock.options(),
    log: () => {},
  });
  try {
    assert.equal(await until(async () => (await getAccount(db, account.id)).status === "auth_failed"), true,
      "the supervisor marked the account");
    const bells = await mailNotificationRows(db);
    assert.equal(bells.length, 1, "a dead grant rings ONE bell — silence is the bug this pins");
    assert.equal(bells[0].source, "mail");
    assert.equal(fake.requests.length, 1, "the latched provider asks the endpoint nothing more");

    // The account is already auth_failed: later ticks ring nothing.
    await clock.advance(POLL_MS * 3);
    assert.equal((await mailNotificationRows(db)).length, 1, "no second bell on the next tick");
    assert.equal(fake.requests.length, 1);
  } finally {
    await handle.stop();
  }
});

/* ------------------------------------------------- the one writer, end to end */

/**
 * A scratch crow.db with the mail tables, the settings tables (the meta is a setting) and
 * `crow_instances` (the claim lookup the supervisor runs).
 */
let dbCount = 0;
const SETTINGS_DDL = `
  CREATE TABLE IF NOT EXISTS dashboard_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now')),
    lamport_ts INTEGER DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS dashboard_settings_overrides (
    key TEXT NOT NULL,
    instance_id TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT DEFAULT (datetime('now')),
    lamport_ts INTEGER DEFAULT 0,
    PRIMARY KEY (key, instance_id)
  );
  CREATE TABLE IF NOT EXISTS crow_instances (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    crow_id TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    trusted INTEGER DEFAULT 1,
    last_seen_at TEXT
  );
`;

/**
 * The bell table the supervisor's default notice writes (the columns `createNotification` inserts, and
 * the ones the unread broadcast reads). The real table comes from init-db; this is the scratch one, so
 * the H2 test can count the bells the supervisor actually rang instead of a stub's call list.
 */
const NOTIFICATIONS_DDL = `
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT DEFAULT 'system',
    source TEXT,
    title TEXT NOT NULL,
    body TEXT,
    priority TEXT DEFAULT 'normal',
    action_url TEXT,
    metadata TEXT,
    schedule_id INTEGER,
    expires_at TEXT,
    is_read INTEGER DEFAULT 0,
    is_dismissed INTEGER DEFAULT 0,
    snoozed_until TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT
  );
`;

async function freshDb() {
  const dir = join(root, "db" + (++dbCount));
  mkdirSync(dir, { recursive: true });
  const db = createDbClient(join(dir, "crow.db"));
  await db.executeMultiple(MAIL_DDL + SETTINGS_DDL + MAIL_DRAFTS_DDL + NOTIFICATIONS_DDL);
  for (const spec of MAIL_ACCOUNT_SEND_COLUMNS) {
    await db.execute({ sql: `ALTER TABLE ${spec.table} ADD COLUMN ${spec.column} ${spec.definition}`, args: [] });
  }
  dbs.push(db);
  return db;
}

/** Wait for a predicate on real time: the sockets in the end-to-end tests are real. */
async function until(predicate, { timeoutMs = 8000, intervalMs = 10 } = {}) {
  const started = Date.now();
  for (;;) {
    if (await predicate()) return true;
    if (Date.now() - started > timeoutMs) return false;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
}

/** A clock whose timers only fire when a test advances it (the supervisor's ticks and retries). */
function makeTimerClock(start = 1_700_000_000_000) {
  const timers = new Map();
  let current = start;
  let seq = 0;
  const clock = {
    now: () => current,
    setTimer(fn, ms) {
      seq += 1;
      timers.set(seq, { fn, at: current + Math.max(0, Number(ms) || 0) });
      return seq;
    },
    clearTimer(handle) { timers.delete(handle); },
    pending: () => timers.size,
    async advance(ms) {
      const target = current + ms;
      for (;;) {
        await new Promise((resolve) => setImmediate(resolve));
        let due = null;
        for (const entry of timers) {
          if (entry[1].at > target) continue;
          if (due == null || entry[1].at < due[1].at || (entry[1].at === due[1].at && entry[0] < due[0])) due = entry;
        }
        if (due == null) break;
        timers.delete(due[0]);
        if (due[1].at > current) current = due[1].at;
        due[1].fn();
      }
      current = target;
      for (let i = 0; i < 40; i += 1) await new Promise((resolve) => setImmediate(resolve));
    },
    options() {
      return { now: clock.now, setTimer: clock.setTimer, clearTimer: clock.clearTimer, random: () => 0.5 };
    },
  };
  return clock;
}

/** Every bell the supervisor rang (source "mail"), newest last. */
async function mailNotificationRows(db) {
  const { rows } = await db.execute({
    sql: "SELECT title, body, source, type FROM notifications WHERE source = 'mail' ORDER BY id",
    args: [],
  });
  return rows;
}

/** An account row over the fake servers; the credentials for it are the test's own reader. */
async function xoauth2Account(db, imap, smtp) {
  return createAccount(db, {
    label: "Alex",
    address: FAKE_USER,
    username: FAKE_USER,
    provider: "google",
    authKind: "xoauth2",
    imap: { host: imap.host, port: imap.port, security: "none" },
    smtp: { host: smtp.host, port: smtp.port, security: "none" },
  });
}

test("the boot's default factory with the real IMAP adapter writes a rotated refresh token exactly once", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  imap.deliver("INBOX", makeRaw({ subject: "a note for the one-writer test" }));
  const smtp = { host: "127.0.0.1", port: 1 };
  const account = await xoauth2Account(db, imap, smtp);

  const fake = await fakeProvider();
  // The provider rotates on the refresh the sync's first sign-in makes.
  fake.queueResponse({
    status: 200,
    body: { access_token: ROTATED_ACCESS, expires_in: 3600, refresh_token: ROTATED_REFRESH },
  });

  const home = join(root, "keychain-one-writer");
  mkdirSync(home, { recursive: true });
  const real = createMailCredentials({ db, crowHome: home });
  await real.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await real.saveSecret(account.id, "MAIL_REFRESH_TOKEN", REFRESH_TOKEN);

  const writes = [];
  const credentials = {
    getSecrets: (id) => real.getSecrets(id),
    deleteSecrets: (id) => real.deleteSecrets(id),
    saveSecret: (id, key, value) => { writes.push({ id, key, value }); return real.saveSecret(id, key, value); },
  };

  const handle = await startMailSync({
    db,
    env: { CROW_MAIL: "1" },
    noAuth: false,
    credentials,
    oauthEndpoints: { tokenUrl: fake.tokenUrl },
    localInstance: { instanceId: "instA", instanceName: "Alpha" },
    log: () => {},
  });
  assert.equal(handle.started, true);
  assert.notEqual(handle.tokenProviders, undefined, "boot built the per-account registry");

  try {
    // The first sign-in ran (the sync opened the mailbox) and the rotation was stored ONCE.
    assert.equal(await until(async () => {
      const { rows } = await db.execute({ sql: "SELECT COUNT(*) AS n FROM mail_messages WHERE account_id = ?", args: [account.id] });
      return Number(rows[0].n) === 1;
    }), true, "the first sync read the mailbox");

    assert.equal(fake.requests.length, 1, "one token request for the whole sync");
    const refreshWrites = writes.filter((write) => write.key === "MAIL_REFRESH_TOKEN");
    assert.equal(refreshWrites.length, 1, "exactly one keychain write for the rotation");
    assert.equal(refreshWrites[0].value, ROTATED_REFRESH);
    assert.deepEqual([...new Set(writes.map((write) => write.key))], ["MAIL_REFRESH_TOKEN"],
      "nothing but the refresh token was written");
    const surface = JSON.stringify(writes);
    assert.ok(!surface.includes(ROTATED_ACCESS), "no access token reached the keychain");
    assert.equal((await real.getSecrets(account.id)).MAIL_REFRESH_TOKEN, ROTATED_REFRESH,
      "the rotated token is what the keychain holds");

    // A second adapter (the action path) reuses the same provider: no second token request.
    await handle.supervisor.withAdapter(account.id, async () => {});
    assert.equal(fake.requests.length, 1, "the action adapter shared the provider's cache");
  } finally {
    await handle.stop();
  }
});

test("boot wires the registry: the sync adapter, withAdapter and the router all see the same provider object", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  imap.deliver("INBOX", makeRaw({ subject: "a note for the wiring test" }));
  const account = await xoauth2Account(db, imap, { host: "127.0.0.1", port: 1 });

  const fake = await fakeProvider();
  const home = join(root, "keychain-wiring");
  mkdirSync(home, { recursive: true });
  const real = createMailCredentials({ db, crowHome: home });
  await real.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await real.saveSecret(account.id, "MAIL_REFRESH_TOKEN", REFRESH_TOKEN);

  let handle = null;
  // The dashboard's own seam, exactly as servers/gateway/dashboard/index.js binds it.
  const routerProviders = [];
  try {
    // No tokenProvider and no adapterFactory: the test relies on boot's own defaults.
    handle = await startMailSync({
      db,
      env: { CROW_MAIL: "1" },
      noAuth: false,
      credentials: createMailCredentials({ db, crowHome: home }),
      oauthEndpoints: { tokenUrl: fake.tokenUrl },
      localInstance: { instanceId: "instA", instanceName: "Alpha" },
      log: () => {},
    });
    assert.equal(handle.started, true);
    assert.equal(typeof handle.tokenProviders.tokenProviderFor, "function");

    // The first sync finished on its own (no tokenProvider was passed by this test).
    assert.equal(await until(async () => (await handle.supervisor.status(account.id))?.watching === true), true,
      "the first full sync succeeded and the watch is armed");
    assert.equal(fake.requests.length, 1);

    const provider = handle.tokenProviders.tokenProviderFor(account.id);
    assert.equal(handle.tokenProviders.tokenProviderFor(account.id), provider, "one provider object per account");

    // The action path asks the same registry, so the same cache answers: no new token request.
    await handle.supervisor.withAdapter(account.id, async () => {});
    assert.equal(fake.requests.length, 1, "withAdapter shared the sync's provider");

    // The router's deps receive the registry's function, and the token it answers for this account is
    // the cached one — no request, which only a shared provider can do.
    const tokenProviderFor = (accountId) => {
      const value = handle.tokenProviders.tokenProviderFor(accountId);
      routerProviders.push(value);
      return value;
    };
    const routeProvider = tokenProviderFor(account.id);
    assert.equal(routeProvider, provider, "the router gets the very same provider object");
    const routeToken = await routeProvider({ accountId: account.id });
    assert.equal(typeof routeToken.accessToken, "string");
    assert.ok(routeToken.accessToken.length > 0, "the shared provider answered with a token");
    assert.equal(Object.hasOwn(routeToken, "refreshToken"), false);
    assert.equal(fake.requests.length, 1, "the router's provider answered from the shared cache");

    // And the mount itself: the dashboard passes these two functions into mailApiRouter.
    const dashboard = readFileSync(join(REPO, "servers/gateway/dashboard/index.js"), "utf8");
    assert.match(dashboard, /mailApiRouter\(dashboardAuth, \{/,
      "the mail API is mounted with the registry's seams");
    assert.match(dashboard, /tokenProviderFor: \(accountId\) => tokenProviderForAccount\(accountId\)/);
    assert.match(dashboard, /forgetTokenProvider: \(accountId\) => forgetTokenProviderForAccount\(accountId\)/);

    const mailApi = readFileSync(join(REPO, "servers/gateway/routes/mail-api.js"), "utf8");
    assert.match(mailApi, /deps\.tokenProviderFor/, "the fallback factory accepts a per-account provider");
    assert.match(mailApi, /deps\.tokenProvider\b/, "and keeps the older single-provider seam");
    assert.equal(routerProviders.length, 1);
  } finally {
    if (handle != null) await handle.stop();
    else await stopMailSync();
  }

  // A stopped service has nothing to hand out.
  assert.equal(handle.tokenProviders.size(), 1, "the registry itself is untouched by the stop");
});

test("the injected single-provider seam still signs every xoauth2 account in and keeps the adapter's rotation writer", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  imap.deliver("INBOX", makeRaw({ subject: "a note for the injected-provider test" }));
  const account = await xoauth2Account(db, imap, { host: "127.0.0.1", port: 1 });

  const home = join(root, "keychain-injected");
  mkdirSync(home, { recursive: true });
  const real = createMailCredentials({ db, crowHome: home });
  const writes = [];
  const credentials = {
    getSecrets: (id) => real.getSecrets(id),
    deleteSecrets: (id) => real.deleteSecrets(id),
    saveSecret: (id, key, value) => { writes.push({ id, key, value }); return real.saveSecret(id, key, value); },
  };

  const calls = [];
  const tokenProvider = async ({ accountId, forceRefresh }) => {
    calls.push({ accountId, forceRefresh });
    return { accessToken: "injected-access-token", expiresAt: Date.now() + 3_600_000, refreshToken: ROTATED_REFRESH };
  };

  const handle = await startMailSync({
    db,
    env: { CROW_MAIL: "1" },
    noAuth: false,
    credentials,
    tokenProvider,
    localInstance: { instanceId: "instA", instanceName: "Alpha" },
    log: () => {},
  });
  assert.equal(handle.started, true);
  assert.equal(handle.tokenProviders, null, "an injected single provider needs no registry");
  try {
    assert.equal(await until(async () => calls.length > 0), true, "the injected provider was asked for a token");
    assert.equal(calls[0].accountId, account.id);
    assert.equal(await until(async () => {
      const secrets = await real.getSecrets(account.id);
      return secrets.MAIL_REFRESH_TOKEN === ROTATED_REFRESH;
    }), true, "the adapter's own rotation writer stored the rotated refresh token");
    assert.deepEqual([...new Set(writes.map((write) => write.key))], ["MAIL_REFRESH_TOKEN"]);
  } finally {
    await handle.stop();
  }
});

test("a forgotten provider is rebuilt fresh, and a boot with no registry answers null", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  const account = await xoauth2Account(db, imap, { host: "127.0.0.1", port: 1 });
  const fake = await fakeProvider();
  const home = join(root, "keychain-forget");
  mkdirSync(home, { recursive: true });
  const credentials = createMailCredentials({ db, crowHome: home });
  await credentials.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await credentials.saveSecret(account.id, "MAIL_REFRESH_TOKEN", REFRESH_TOKEN);

  const handle = await startMailSync({
    db,
    env: { CROW_MAIL: "1" },
    noAuth: false,
    credentials,
    oauthEndpoints: { tokenUrl: fake.tokenUrl },
    localInstance: { instanceId: "instA", instanceName: "Alpha" },
    log: () => {},
  });
  try {
    const first = handle.tokenProviders.tokenProviderFor(account.id);
    handle.tokenProviders.forget(account.id);
    const second = handle.tokenProviders.tokenProviderFor(account.id);
    assert.notEqual(second, first, "a forgotten account gets a new provider");
  } finally {
    await handle.stop();
  }

  // A start that injected its own factory keeps no registry, and the router seam answers null rather
  // than inventing a provider for a service that is not running one.
  const injected = await startMailSync({
    db,
    env: { CROW_MAIL: "1" },
    noAuth: false,
    adapterFactory: () => ({ close: async () => {} }),
    localInstance: { instanceId: "instA", instanceName: "Alpha" },
    log: () => {},
  });
  assert.equal(injected.tokenProviders, null, "no registry is built when a test injects its own factory");
  await injected.stop();
});

/* ------------------------------------- the routes' fallback factory (L5) */

test("L5: the routes' fallback factory binds the rotation writer for the injected single provider", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  const account = await xoauth2Account(db, imap, { host: "127.0.0.1", port: 1 });
  const home = join(root, "keychain-l5");
  mkdirSync(home, { recursive: true });
  const real = createMailCredentials({ db, crowHome: home });
  await real.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);

  const writes = [];
  const credentials = {
    getSecrets: (id) => real.getSecrets(id),
    saveSecret: (id, key, value) => { writes.push({ id, key, value }); return real.saveSecret(id, key, value); },
  };
  const calls = [];
  // The single-provider test seam: one provider for every account, which writes nothing itself.
  const single = async ({ accountId }) => {
    calls.push(accountId);
    return { accessToken: ACCESS_TOKEN, refreshToken: ROTATED_REFRESH };
  };

  const factory = fallbackAdapterFactory({ tokenProvider: single });
  const adapter = factory({ account, credentials });
  await adapter.connect();
  try {
    assert.deepEqual(calls, [account.id], "the single provider signed this account in");
    assert.deepEqual(writes, [{ id: account.id, key: "MAIL_REFRESH_TOKEN", value: ROTATED_REFRESH }],
      "the rotation reached the keychain through a writer bound to this account id");
    assert.equal((await real.getSecrets(account.id)).MAIL_REFRESH_TOKEN, ROTATED_REFRESH);
    assert.ok(!JSON.stringify(writes).includes(ACCESS_TOKEN), "an access token is never written");
  } finally {
    await adapter.close();
  }
  assert.equal(writes.length, 1, "a close writes nothing");
});

test("L5: the registry's provider is the only rotation writer — the fallback factory adds none for it", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  const account = await xoauth2Account(db, imap, { host: "127.0.0.1", port: 1 });
  const writes = [];
  const provider = async () => ({ accessToken: ACCESS_TOKEN, refreshToken: ROTATED_REFRESH });
  const factory = fallbackAdapterFactory({ tokenProviderFor: () => provider });
  const adapter = factory({ account, credentials: { getSecrets: async () => ({}), saveSecret: async (id, key, value) => { writes.push({ id, key, value }); } } });
  await adapter.connect();
  try {
    // A second writer would store the same rotation twice: the registry's provider owns that write.
    assert.deepEqual(writes, [], "no writer was handed to an adapter built on the registry's provider");
  } finally {
    await adapter.close();
  }
});

/* ----------------------- a lazy provider: an adapter never holds a retired one */

test("R1: boot's default factory asks the registry on every call, so an adapter outlives a forget()", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  const account = await xoauth2Account(db, imap, { host: "127.0.0.1", port: 1 });
  const fake = await fakeProvider();
  const home = join(root, "keychain-r1-boot");
  mkdirSync(home, { recursive: true });
  const credentials = createMailCredentials({ db, crowHome: home });
  await credentials.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await credentials.saveSecret(account.id, "MAIL_REFRESH_TOKEN", REFRESH_TOKEN);

  const RECONNECT_REFRESH = "refresh-token-reconnect-70ab";
  let captured = null;
  const handle = await startMailSync({
    db,
    env: { CROW_MAIL: "1" },
    noAuth: false,
    credentials,
    oauthEndpoints: { tokenUrl: fake.tokenUrl },
    localInstance: { instanceId: "instA", instanceName: "Alpha" },
    // A stub supervisor: the adapter factory boot BUILT is the thing under test.
    createSupervisor: (options) => {
      captured = options;
      return {
        start: async () => {},
        stop: async () => {},
        withAdapter: async () => {},
        requestSync: async () => {},
      };
    },
    log: () => {},
  });
  assert.equal(handle.started, true);
  try {
    assert.equal(typeof captured.adapterFactory, "function");
    const adapter = captured.adapterFactory({ account, credentials });
    try {
      // The account is forgotten (a removal, or a fresh grant) and a reconnect stores a NEW token.
      await handle.tokenProviders.forget(account.id);
      await credentials.saveSecret(account.id, "MAIL_REFRESH_TOKEN", RECONNECT_REFRESH);

      // The adapter built BEFORE the forget signs in: it asks the registry for the CURRENT provider,
      // whose keychain read finds the reconnected grant. Holding the old object answers retired.
      const failure = await adapter.connect().then(() => null, (error) => error);
      assert.equal(failure, null, `the adapter signed in (${failure?.code}/${failure?.detail})`);
      assert.equal(fake.requests.length, 1);
      assert.equal(fake.requests[0].form.refresh_token, RECONNECT_REFRESH,
        "the new provider read the reconnected refresh token from the keychain");
    } finally {
      await adapter.close();
    }
  } finally {
    await handle.stop();
  }
});

test("R1: the routes' fallback factory asks tokenProviderFor on every call, so it never holds a retired provider", async () => {
  const db = await freshDb();
  const imap = await createFakeImapServer();
  fakes.push(imap);
  const account = await xoauth2Account(db, imap, { host: "127.0.0.1", port: 1 });
  const fake = await fakeProvider();
  const home = join(root, "keychain-r1-fallback");
  mkdirSync(home, { recursive: true });
  const real = createMailCredentials({ db, crowHome: home });
  await real.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await real.saveSecret(account.id, "MAIL_REFRESH_TOKEN", REFRESH_TOKEN);
  const credentials = {
    getSecrets: (id) => real.getSecrets(id),
    deleteSecrets: (id) => real.deleteSecrets(id),
    saveSecret: (id, key, value) => real.saveSecret(id, key, value),
  };
  const registry = createTokenProviderRegistry({
    db,
    credentials,
    fetchImpl: fetch,
    endpoints: { tokenUrl: fake.tokenUrl },
  });

  const factory = fallbackAdapterFactory({ tokenProviderFor: (accountId) => registry.tokenProviderFor(accountId) });
  const adapter = factory({ account, credentials });
  try {
    const RECONNECT_REFRESH = "refresh-token-reconnect-81bc";
    await registry.forget(account.id);
    await credentials.saveSecret(account.id, "MAIL_REFRESH_TOKEN", RECONNECT_REFRESH);

    const failure = await adapter.connect().then(() => null, (error) => error);
    assert.equal(failure, null, `the adapter signed in (${failure?.code}/${failure?.detail})`);
    assert.equal(fake.requests.length, 1);
    assert.equal(fake.requests[0].form.refresh_token, RECONNECT_REFRESH,
      "the factory resolved the CURRENT provider, which read the keychain");
  } finally {
    await adapter.close();
  }
});

/* --------------------------------------------------------------- the error text */

test("no access token, refresh token or client secret reaches an error a caller could print", async () => {
  const fake = await fakeProvider();
  fake.queueResponse({
    status: 400,
    body: (form) => ({
      error: "invalid_grant",
      error_description: `the refresh token ${form.refresh_token} for client ${form.client_id} is not valid`,
    }),
  });
  const provider = createTokenProvider({
    accountId: ACCOUNT_ID,
    getAccount: async () => accountRow(),
    credentials: { getSecrets: async () => defaultSecrets({ MAIL_OAUTH_CLIENT_SECRET: CLIENT_SECRET }) },
    fetchImpl: fetch,
    markAuthFailed: async () => {},
    onTokenRotated: async () => {},
    endpoints: { tokenUrl: fake.tokenUrl },
    getMeta: async () => null,
    log: () => {},
  });

  const err = await provider({ accountId: ACCOUNT_ID }).catch((error) => error);
  assert.ok(err instanceof MailError);
  assert.equal(err.code, "AUTH_FAILED");
  assert.equal(err.message, MAIL_ERROR_TEXT.AUTH_FAILED);
  const printed = [err.message, String(err), err.stack, String(err.detail), JSON.stringify(err), Object.keys(err).join(",")];
  for (const text of printed) {
    for (const secret of [REFRESH_TOKEN, CLIENT_SECRET, ACCESS_TOKEN, "not valid"]) {
      assert.ok(!String(text).includes(secret), `the error printed ${secret}`);
    }
  }
});