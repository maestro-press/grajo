// Crow Mail plan 5, Task 4a: the connect sequence factored out of `POST /accounts`
// (servers/gateway/mail/accounts/connect.js) and the reconnect that replaces an existing account's
// secrets, plus the two changed routes (POST /accounts refuses an OAuth body, DELETE drops the OAuth
// meta).
//
// Harness: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR / CROW_HOME in a temp dir,
// so nothing can touch ~/.crow), the real account store, the real sealed keychain reader and the real
// claim code, an in-memory fake mail adapter, a recording supervisor, and — for the two route tests —
// an express app wired the way the dashboard mounts the mail API (the router's own flag/owner body
// chain, an auth stub in place of the session gate). No pi, no network, no host config.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";

const root = mkdtempSync(join(tmpdir(), "mail-connect-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { default: express } = await import("express");
const { createDbClient } = await import("../servers/db.js");
const { connectAccount, reconnectAccount } = await import("../servers/gateway/mail/accounts/connect.js");
const { mailApiRouter, clearMailApiRuntime, MAIL_API_PREFIX } = await import("../servers/gateway/routes/mail-api.js");
const { MailError } = await import("../servers/gateway/mail/errors.js");
const { createMailCredentials } = await import("../servers/gateway/mail/credentials.js");
const { checkClaim, claimKey, listClaims, releaseClaim, writeClaim } = await import("../servers/gateway/mail/claims.js");
const { getAccount } = await import("../servers/gateway/mail/store/accounts.js");
const { getOauthMeta, setOauthMeta } = await import("../servers/gateway/mail/oauth/meta.js");
const { createTokenProviderRegistry } = await import("../servers/gateway/mail/oauth/registry.js");
const { createFakeMailAdapter } = await import("./fixtures/fake-mail-adapter.mjs");
const { startFakeOAuthProvider } = await import("./fixtures/fake-oauth-provider.mjs");

const ADDRESS = "alex@example.com";
const PASSWORD = "hunter2-app-password";
const NEW_PASSWORD = "hunter2-app-password-two";
const USERNAME = "alexuser";
const LOCAL = { instanceId: "instA", instanceName: "Delta" };
const PEER = "instB";
const EMAIL_RE = /^ma-[0-9a-f]{16}$/;

const IMAP = { host: "mail.example.test", port: 993, security: "ssl" };
const SMTP = { host: "mail.example.test", port: 465, security: "ssl" };

/** The password form's draft: what readAccountInput hands the connect route. */
const DRAFT = { label: "Personal", address: ADDRESS, username: USERNAME, imap: IMAP, smtp: SMTP };

/** An OAuth wizard's draft: the provider and the Sent-copy rule the wizard chose. */
const OAUTH_ACCOUNT = {
  label: "Google",
  address: ADDRESS,
  username: ADDRESS,
  provider: "google",
  sentCopy: "append",
  imap: IMAP,
  smtp: SMTP,
};

const OAUTH_SECRETS = {
  MAIL_REFRESH_TOKEN: "refresh-token-5a2b",
  MAIL_OAUTH_CLIENT_ID: "client-id-4f1a2b7d",
  MAIL_OAUTH_CLIENT_SECRET: "client-secret-9d3c51aa",
};

const open = [];
const servers = [];
const fakes = [];
after(() => {
  clearMailApiRuntime();
  for (const s of servers) s.close();
  for (const c of open) { try { c.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});
after(async () => {
  for (const fake of fakes) await fake.close();
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
});

beforeEach(() => {
  clearMailApiRuntime();
  process.env.CROW_MAIL = "1";
});

const flush = (rounds = 40) => (async () => {
  for (let i = 0; i < rounds; i += 1) await new Promise((r) => setImmediate(r));
})();

/* ------------------------------------------------------------------ harness */

let n = 0;

/**
 * One test's world: a fresh copy of the schema, the real keychain reader over its own client, a fake
 * mail adapter whose factory records every probe, a recording supervisor and an in-memory masking
 * recorder. `deps` is exactly what `mailApiRouter` would hand `connectAccount`.
 */
async function world(overrides = {}) {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");

  const db = createDbClient(crow);
  const credDb = createDbClient(crow);
  open.push(db, credDb);

  const real = createMailCredentials({ db: credDb, crowHome: process.env.CROW_HOME });
  const saves = [];
  const deletes = [];
  // One key deleted on its own (a re-keyed grant that names no client secret).
  const keyDeletes = [];
  const credentials = overrides.credentials ?? {
    getSecrets: (id) => real.getSecrets(id),
    deleteSecrets: (id) => { deletes.push(id); return real.deleteSecrets(id); },
    async deleteSecret(id, key) { keyDeletes.push({ id, key }); return real.deleteSecret(id, key); },
    async saveSecret(id, key, value) { saves.push({ id, key }); return real.saveSecret(id, key, value); },
  };

  const factoryCalls = [];
  const adapterFactory = overrides.adapterFactory ?? ((args) => {
    factoryCalls.push(args);
    return createFakeMailAdapter();
  });
  const oauthFactoryCalls = [];
  const oauthAdapterFactory = overrides.oauthAdapterFactory ?? ((args) => {
    oauthFactoryCalls.push(args);
    return createFakeMailAdapter();
  });

  const supervisorCalls = [];
  const supervisor = overrides.supervisor === null ? null : (overrides.supervisor ?? {
    async syncNow(id) { supervisorCalls.push(["syncNow", id]); },
    async restartAccount(id) { supervisorCalls.push(["restartAccount", id]); },
  });

  const recorded = [];
  const deps = {
    credentials,
    adapterFactory,
    oauthAdapterFactory,
    supervisor,
    localInstance: LOCAL,
    recordSecrets: (values) => { recorded.push(values); },
    ...(overrides.deps ?? {}),
  };

  const count = async (table, where = "", args = []) => {
    const { rows } = await db.execute({ sql: `SELECT COUNT(*) AS n FROM ${table} ${where}`, args });
    return Number(rows[0].n);
  };
  const keychainRows = async (accountId) => (await db.execute({
    sql: "SELECT env_key, secret_sealed FROM crow_keychain WHERE connection_uuid = ? ORDER BY env_key",
    args: [accountId],
  })).rows;

  return { db, crow, credentials, saves, deletes, keyDeletes, deps, factoryCalls, oauthFactoryCalls,
    supervisorCalls, supervisor, recorded, count, keychainRows };
}

/** One peer instance in this world's registry, so its claim counts as live. */
async function peerInstance(db) {
  await db.execute({
    sql: "INSERT INTO crow_instances (id, name, crow_id, status) VALUES (?, 'Echo', 'crow:mail', 'active')",
    args: [PEER],
  });
}

/** Our own claim row, live or tombstoned, as the claim code reads it back. */
async function ownClaim(db) {
  return (await listClaims(db, ADDRESS)).find((claim) => claim.key === claimKey(ADDRESS, LOCAL.instanceId)) ?? null;
}

/* -------------------------------------------------- connect: the refusals */

test("a peer-claimed address is refused before anything is dialled, and stores nothing", async () => {
  const w = await world();
  await peerInstance(w.db);
  await writeClaim(w.db, ADDRESS, { localInstanceId: PEER, instanceName: "Echo", now: 1_000 });

  await assert.rejects(
    () => connectAccount(w.db, w.deps, { draft: DRAFT, secrets: { MAIL_PASSWORD: PASSWORD } }),
    (err) => {
      assert.ok(err instanceof MailError, `a MailError, got ${String(err)}`);
      assert.equal(err.code, "CLAIMED_ELSEWHERE");
      assert.equal(err.instanceName, "Echo", "the loser's name travels for the one fixed sentence");
      return true;
    },
  );
  assert.deepEqual(w.factoryCalls, [], "nothing was dialled");
  assert.equal(await w.count("mail_accounts"), 0);
  assert.equal(await w.count("crow_keychain"), 0);
  assert.deepEqual(await ownClaim(w.db), null, "we wrote no claim of our own");
});

test("a duplicate address is the duplicate refusal, and the second password is never stored or masked", async () => {
  const w = await world();
  const first = await connectAccount(w.db, w.deps, { draft: DRAFT, secrets: { MAIL_PASSWORD: PASSWORD } });
  assert.match(first.id, EMAIL_RE);
  assert.equal(w.factoryCalls.length, 1, "the first connect probed once");
  const recordedBefore = w.recorded.length;

  for (const address of ["Alex@Example.COM", " ALEX@example.com "]) {
    await assert.rejects(
      () => connectAccount(w.db, w.deps, { draft: { ...DRAFT, address }, secrets: { MAIL_PASSWORD: NEW_PASSWORD } }),
      (err) => {
        assert.equal(err.code, "BAD_INPUT");
        assert.equal(err.detail, "address", "the store's own duplicate signal");
        return true;
      },
      address,
    );
  }
  assert.equal(w.factoryCalls.length, 1, "the duplicates never dialled the server");
  assert.equal(await w.count("mail_accounts"), 1, "no second account");
  assert.equal(await w.count("crow_keychain"), 1, "no second secret");
  assert.equal((await w.credentials.getSecrets(first.id)).MAIL_PASSWORD, PASSWORD, "the first secret is untouched");
  assert.equal(w.recorded.length, recordedBefore, "a duplicate's password is never masked either");
});

test("a refused secret key stores nothing: no probe, no row, no secret, no claim", async () => {
  const w = await world();
  await assert.rejects(
    () => connectAccount(w.db, w.deps, {
      draft: DRAFT,
      secrets: { MAIL_PASSWORD: PASSWORD, MAIL_NOT_A_KEY: "x" },
    }),
    (err) => {
      assert.equal(err.code, "BAD_INPUT");
      assert.equal(err.detail, "env_key");
      return true;
    },
  );
  assert.deepEqual(w.factoryCalls, [], "nothing was dialled");
  assert.equal(await w.count("mail_accounts"), 0);
  assert.equal(await w.count("crow_keychain"), 0);
  assert.deepEqual(await ownClaim(w.db), null);
  assert.deepEqual(w.recorded, [], "not even the accepted value was masked for a connect that never ran");

  // The same rule, one route further out: a password account with no secret at all is refused too.
  await assert.rejects(
    () => connectAccount(w.db, w.deps, { draft: DRAFT, secrets: {} }),
    (err) => err instanceof MailError && err.code === "BAD_INPUT" && err.detail === "secrets",
  );
});

/* --------------------------------------- connect: the undo, and EVERY secret */

test("a lost re-check removes the row and EVERY saved secret, and releases the claim", async () => {
  const w = await world();
  await peerInstance(w.db);
  // The re-check reads a peer's earlier claim: our write was a moment too late, and the winner is Echo.
  let checks = 0;
  const deps = {
    ...w.deps,
    claims: {
      async checkClaim(db, address, options) {
        checks += 1;
        if (checks === 2) return { ok: false, instanceName: "Echo" };
        return checkClaim(db, address, options);
      },
      writeClaim,
      releaseClaim,
    },
  };

  await assert.rejects(
    () => connectAccount(w.db, deps, { draft: OAUTH_ACCOUNT, authKind: "xoauth2", secrets: OAUTH_SECRETS, tokenProvider: async () => ({ accessToken: "a" }) }),
    (err) => {
      assert.equal(err.code, "CLAIMED_ELSEWHERE");
      assert.equal(err.instanceName, "Echo");
      return true;
    },
  );
  assert.equal(checks, 2, "the re-check after the claim write is the one that lost");

  const id = w.saves[0]?.id;
  assert.ok(id, "the account's secrets really were saved before the loss");
  assert.deepEqual(
    w.saves.map((save) => save.key).sort(),
    Object.keys(OAUTH_SECRETS).sort(),
    "saved for every key the caller named, one by one",
  );
  assert.deepEqual(await w.count("mail_accounts", "WHERE id = ?", [id]), 0, "the row was undone");
  assert.deepEqual(await w.keychainRows(id), [], "every secret of that account was undone, not just one");
  assert.ok(w.deletes.includes(id), "the undo removed them under the account id");

  const ours = await ownClaim(w.db);
  assert.ok(ours, "our claim row is still there");
  assert.equal(ours.released, true, "…as a tombstone, so the address is not held by a phantom");
  assert.deepEqual(
    await checkClaim(w.db, ADDRESS, { localInstanceId: "instC" }),
    { ok: true },
    "the address is free for another instance",
  );
  await flush();
  assert.deepEqual(w.supervisorCalls, [], "no sync of an account that does not exist");
});

test("a re-check that throws is undone the same way: no row, no secret, a released claim", async () => {
  const w = await world();
  let checks = 0;
  const boom = new Error("SQLITE_IOERR: disk I/O error (dashboard_settings)");
  const deps = {
    ...w.deps,
    claims: {
      async checkClaim(db, address, options) {
        checks += 1;
        if (checks === 2) throw boom;
        return checkClaim(db, address, options);
      },
      writeClaim,
      releaseClaim,
    },
  };

  await assert.rejects(
    () => connectAccount(w.db, deps, { draft: OAUTH_ACCOUNT, authKind: "xoauth2", secrets: OAUTH_SECRETS, tokenProvider: async () => ({ accessToken: "a" }) }),
    (err) => err === boom,
    "the fault itself travels: the route decides what a non-mail failure looks like",
  );

  const id = w.saves[0]?.id;
  assert.ok(id);
  assert.equal(await w.count("mail_accounts", "WHERE id = ?", [id]), 0, "the row was undone");
  assert.equal(await w.count("mail_accounts", "WHERE address = ?", [ADDRESS]), 0);
  assert.deepEqual(await w.keychainRows(id), [], "every saved secret was undone");
  const ours = await ownClaim(w.db);
  assert.equal(ours?.released, true, "the claim is a tombstone, so the address is not held by a phantom");
  await flush();
  assert.deepEqual(w.supervisorCalls, [], "no sync of an account that does not exist");
});

/* -------------------------------------------------- connect: the OAuth probe */

test("an OAuth probe uses the one-shot provider and never the registry's", async () => {
  const w = await world();
  const registryAsks = [];
  const oneShot = async () => ({ accessToken: "one-shot-access", expiresAt: Date.now() + 3_600_000 });
  const deps = {
    ...w.deps,
    tokenProviderFor: (accountId) => { registryAsks.push(accountId); return null; },
    tokenProvider: () => { registryAsks.push("single"); throw new MailError("AUTH_FAILED"); },
    adapterFactory: () => { throw new Error("the password probe factory must not build an OAuth probe"); },
  };

  const account = await connectAccount(w.db, deps, {
    draft: OAUTH_ACCOUNT,
    authKind: "xoauth2",
    secrets: OAUTH_SECRETS,
    tokenProvider: oneShot,
  });

  assert.equal(w.oauthFactoryCalls.length, 1, "the OAuth probe was built once");
  const probe = w.oauthFactoryCalls[0];
  assert.equal(probe.tokenProvider, oneShot, "the caller's one-shot provider is what the probe signs in with");
  assert.equal(probe.account.authKind, "xoauth2");
  assert.equal(probe.account.id, "probe", "the probe runs before any account exists");
  assert.deepEqual(registryAsks, [], "the registry was never asked for a provider");

  const stored = await getAccount(w.db, account.id);
  assert.equal(stored.authKind, "xoauth2");
  assert.equal(stored.provider, "google");
  assert.equal(stored.sentCopy, "append", "the wizard's Sent-copy rule is stored");
  assert.deepEqual(
    w.saves.map((save) => save.key).sort(),
    Object.keys(OAUTH_SECRETS).sort(),
    "every secret the wizard handed over is sealed",
  );
  assert.deepEqual((await w.credentials.getSecrets(account.id)), OAUTH_SECRETS);

  // An OAuth connect without a provider is refused outright: there is nothing to prove the grant with.
  await assert.rejects(
    () => connectAccount(w.db, deps, {
      draft: { ...OAUTH_ACCOUNT, address: "sam@example.com" },
      authKind: "xoauth2",
      secrets: OAUTH_SECRETS,
    }),
    (err) => err instanceof MailError && err.code === "BAD_INPUT" && err.detail === "token_provider",
  );
});

/* ------------------------------------------------ connect: the happy password path */

test("a password connect stores the row, the sealed secret and the claim, and starts the first sync", async () => {
  const w = await world();
  const account = await connectAccount(w.db, w.deps, { draft: DRAFT, secrets: { MAIL_PASSWORD: PASSWORD } });

  assert.match(account.id, EMAIL_RE);
  assert.equal(account.authKind, "password");
  assert.deepEqual(await w.credentials.getSecrets(account.id), { MAIL_PASSWORD: PASSWORD });
  assert.deepEqual(await checkClaim(w.db, ADDRESS, { localInstanceId: LOCAL.instanceId }), { ok: true });
  assert.equal((await ownClaim(w.db)).instanceName, LOCAL.instanceName);
  assert.deepEqual(w.recorded, [[PASSWORD]], "the password joined the masking set, before any I/O");
  assert.equal(w.factoryCalls.length, 1, "one probe, through the caller's own factory");

  await flush();
  assert.deepEqual(w.supervisorCalls, [["syncNow", account.id]], "the first sync is started in the background");
});

test("a connect with no supervisor still connects and starts nothing", async () => {
  const w = await world({ supervisor: null });
  const account = await connectAccount(w.db, w.deps, { draft: DRAFT, secrets: { MAIL_PASSWORD: PASSWORD } });
  assert.match(account.id, EMAIL_RE);
  await flush();
  assert.deepEqual(w.supervisorCalls, []);
});

/* ------------------------------------------- connect: the grant's label comes first */

test("an OAuth connect records the grant's meta BEFORE the first sync starts", async () => {
  const w = await world();
  const seen = [];
  const deps = {
    ...w.deps,
    // The first sync is what reads the meta (a Microsoft refresh takes its tenant from it), so what it
    // sees is the whole point: the label has to be stored before the sync is started, not after it.
    supervisor: { async syncNow(id) { seen.push({ id, meta: await getOauthMeta(w.db, id) }); } },
  };
  const meta = { grantedAt: 1_700_000_000_000, publishing: "unknown", provider: "google" };

  const account = await connectAccount(w.db, deps, {
    draft: OAUTH_ACCOUNT,
    authKind: "xoauth2",
    secrets: OAUTH_SECRETS,
    tokenProvider: async () => ({ accessToken: "a" }),
    oauthMeta: meta,
  });
  await flush();

  assert.equal(seen.length, 1, "the account got its first sync");
  assert.ok(seen[0].meta, "the meta was already stored when that sync started");
  assert.equal(seen[0].meta.grantedAt, meta.grantedAt);
  assert.equal(seen[0].meta.provider, "google");
  assert.deepEqual(await getOauthMeta(w.db, account.id), {
    grantedAt: meta.grantedAt, publishing: "unknown", provider: "google",
  });
});

test("a meta write that fails is a failed connect: no row, no secret, no claim, no sync", async () => {
  const w = await world();
  const boom = new Error("SQLITE_FULL: database or disk is full (dashboard_settings)");
  const deps = { ...w.deps, setOauthMeta: async () => { throw boom; } };

  await assert.rejects(
    () => connectAccount(w.db, deps, {
      draft: OAUTH_ACCOUNT,
      authKind: "xoauth2",
      secrets: OAUTH_SECRETS,
      tokenProvider: async () => ({ accessToken: "a" }),
      oauthMeta: { provider: "google" },
    }),
    (err) => err === boom,
    "the fault itself travels: a route decides what a non-mail failure looks like",
  );

  assert.equal(await w.count("mail_accounts"), 0, "the account was undone");
  assert.equal(await w.count("crow_keychain"), 0, "every secret was undone");
  assert.deepEqual(
    await checkClaim(w.db, ADDRESS, { localInstanceId: "instC" }),
    { ok: true },
    "the claim was released: the address is free for another instance",
  );
  await flush();
  assert.deepEqual(w.supervisorCalls, [], "no sync of an account that does not exist");
});

/* ------------------------------------------------------------- reconnect */

test("reconnect refuses when the claim is held elsewhere, and swaps nothing", async () => {
  const w = await world();
  const account = await connectAccount(w.db, w.deps, { draft: DRAFT, secrets: { MAIL_PASSWORD: PASSWORD } });
  await flush();
  w.supervisorCalls.length = 0;
  const savesBefore = w.saves.length;
  // Echo claims the same address with an earlier time, so the pure winner is Echo from here on.
  await peerInstance(w.db);
  await writeClaim(w.db, ADDRESS, { localInstanceId: PEER, instanceName: "Echo", now: 1_000 });
  const forbid = [];
  const deps = { ...w.deps, forgetTokenProvider: (id) => forbid.push(id) };

  await assert.rejects(
    () => reconnectAccount(w.db, deps, { accountId: account.id, secrets: { MAIL_PASSWORD: NEW_PASSWORD } }),
    (err) => {
      assert.equal(err.code, "CLAIMED_ELSEWHERE");
      assert.equal(err.instanceName, undefined, "the refusal here is the fixed sentence, with no name");
      return true;
    },
  );
  assert.equal(w.saves.length, savesBefore, "no secret was written");
  assert.equal((await w.credentials.getSecrets(account.id)).MAIL_PASSWORD, PASSWORD, "the stored secret is the old one");
  assert.deepEqual(forbid, [], "the cached provider was not rotated away for a swap that never happened");
  await flush();
  assert.deepEqual(w.supervisorCalls, [], "no worker was restarted");
  assert.equal((await getAccount(w.db, account.id)).status, "active", "the row is untouched");
});

test("reconnect keeps the id and the claim, retires the provider, swaps every secret and restarts the worker", async () => {
  const w = await world();
  const account = await connectAccount(w.db, w.deps, { draft: OAUTH_ACCOUNT, authKind: "xoauth2", secrets: OAUTH_SECRETS, tokenProvider: async () => ({ accessToken: "a" }) });
  await flush();
  w.supervisorCalls.length = 0;

  // The account signed out: the row says so, with a detail code the reconnect must clear.
  await w.db.execute({ sql: "UPDATE mail_accounts SET status = 'auth_failed', status_detail = 'AUTH_FAILED' WHERE id = ?", args: [account.id] });
  const claimBefore = await ownClaim(w.db);
  const order = [];
  const deps = {
    ...w.deps,
    forgetTokenProvider: (id) => order.push(["forget", id]),
    credentials: {
      getSecrets: (id) => w.credentials.getSecrets(id),
      deleteSecrets: (id) => w.credentials.deleteSecrets(id),
      async saveSecret(id, key, value) {
        order.push(["save", key]);
        return w.credentials.saveSecret(id, key, value);
      },
    },
  };

  const fresh = {
    MAIL_REFRESH_TOKEN: "refresh-token-rotated-9e1f",
    MAIL_OAUTH_CLIENT_ID: OAUTH_SECRETS.MAIL_OAUTH_CLIENT_ID,
    MAIL_OAUTH_CLIENT_SECRET: OAUTH_SECRETS.MAIL_OAUTH_CLIENT_SECRET,
  };
  const updated = await reconnectAccount(w.db, deps, { accountId: account.id, secrets: fresh });

  assert.equal(updated.id, account.id, "the account keeps its id");
  assert.equal(updated.address, ADDRESS);
  assert.equal(updated.status, "active");
  assert.equal(updated.statusDetail, null, "the auth_failed detail goes with the status");
  assert.deepEqual(await w.credentials.getSecrets(account.id), fresh, "only the secrets were swapped");
  assert.deepEqual(w.deletes, [], "a reconnect deletes nothing, not even the old secret");

  const claimAfter = await ownClaim(w.db);
  assert.equal(claimAfter.key, claimBefore.key, "the claim row is the same one");
  assert.equal(claimAfter.claimedAt, claimBefore.claimedAt, "and keeps its place in the claim queue");
  assert.equal(claimAfter.released, false);

  // The old provider is retired and AWAITED before the new secrets land, so a rotation write that was
  // in the air cannot land on top of the fresh grant; only then is the worker restarted.
  assert.deepEqual(order.slice(0, 1), [["forget", account.id]]);
  assert.equal(order.filter(([what]) => what === "save").length, 3, "one save per key, and nothing else");
  assert.equal(order.findIndex(([what]) => what === "save") > order.findIndex(([what]) => what === "forget"), true,
    "forget comes before the first save");

  await flush();
  assert.deepEqual(w.supervisorCalls, [["restartAccount", account.id]], "the worker is restarted, not re-created");
  assert.equal(await w.count("mail_accounts"), 1);
});

test("reconnect falls back to syncNow when the supervisor cannot restart", async () => {
  const w = await world();
  const account = await connectAccount(w.db, w.deps, { draft: DRAFT, secrets: { MAIL_PASSWORD: PASSWORD } });
  await flush();
  w.supervisorCalls.length = 0;
  const deps = {
    ...w.deps,
    supervisor: { async syncNow(id) { w.supervisorCalls.push(["syncNow", id]); } },
  };

  await reconnectAccount(w.db, deps, { accountId: account.id, secrets: { MAIL_PASSWORD: NEW_PASSWORD } });
  await flush();
  assert.deepEqual(w.supervisorCalls, [["syncNow", account.id]]);
  assert.equal((await w.credentials.getSecrets(account.id)).MAIL_PASSWORD, NEW_PASSWORD);
});

test("reconnect of an unknown account is NOT_FOUND, and stores nothing", async () => {
  const w = await world();
  await assert.rejects(
    () => reconnectAccount(w.db, w.deps, { accountId: "ma-0123456789abcdef", secrets: { MAIL_PASSWORD: PASSWORD } }),
    (err) => err instanceof MailError && err.code === "NOT_FOUND",
  );
  assert.equal(await w.count("crow_keychain"), 0);
  await assert.rejects(
    () => reconnectAccount(w.db, w.deps, { accountId: "not-an-account", secrets: { MAIL_PASSWORD: PASSWORD } }),
    (err) => err instanceof MailError && err.code === "NOT_FOUND",
  );
});

test("reconnect retires the account's worker before the swap, and starts it again afterwards", async () => {
  const w = await world();
  const account = await connectAccount(w.db, w.deps, { draft: OAUTH_ACCOUNT, authKind: "xoauth2", secrets: OAUTH_SECRETS, tokenProvider: async () => ({ accessToken: "a" }) });
  await flush();

  const order = [];
  const deps = {
    ...w.deps,
    supervisor: {
      async syncNow(id) { order.push(["syncNow", id]); },
      async stopAccount(id) { order.push(["stopAccount", id]); },
      async restartAccount(id) { order.push(["restartAccount", id]); },
    },
    forgetTokenProvider: (id) => order.push(["forget", id]),
    credentials: {
      getSecrets: (id) => w.credentials.getSecrets(id),
      deleteSecrets: (id) => w.credentials.deleteSecrets(id),
      deleteSecret: (id, key) => w.credentials.deleteSecret(id, key),
      async saveSecret(id, key, value) {
        order.push(["save", key]);
        return w.credentials.saveSecret(id, key, value);
      },
    },
  };

  await reconnectAccount(w.db, deps, {
    accountId: account.id,
    secrets: { ...OAUTH_SECRETS, MAIL_REFRESH_TOKEN: "refresh-token-new-9e1f" },
  });
  await flush();

  const indexOf = (what) => order.findIndex(([name]) => name === what);
  assert.equal(indexOf("stopAccount"), 0, "the worker is stopped first: the swap happens on a quiet account");
  assert.equal(indexOf("forget"), 1, "then the cached provider is retired");
  assert.ok(order.filter(([name]) => name === "save").length === 3, "one save per key");
  assert.equal(
    order.map(([name]) => name).at(-2),
    "forget",
    "the provider is retired once more after the swap, so a provider built in between cannot outlive it",
  );
  assert.deepEqual(order.at(-1), ["restartAccount", account.id], "and only then is the worker started again");

  // The account is left usable: the worker was restarted, not merely stopped.
  assert.equal((await getAccount(w.db, account.id)).status, "active");
});

test("a reconnect with no stopAccount to call still retires the provider before and after the swap", async () => {
  const w = await world();
  const account = await connectAccount(w.db, w.deps, { draft: OAUTH_ACCOUNT, authKind: "xoauth2", secrets: OAUTH_SECRETS, tokenProvider: async () => ({ accessToken: "a" }) });
  await flush();

  const order = [];
  const deps = {
    ...w.deps,
    // A supervisor from before `stopAccount` existed (or a bare test double): the fallback is the same
    // retire → swap → retire order, without the quiesce.
    supervisor: { async syncNow(id) { order.push(["syncNow", id]); }, async restartAccount(id) { order.push(["restartAccount", id]); } },
    forgetTokenProvider: (id) => order.push(["forget", id]),
    credentials: {
      getSecrets: (id) => w.credentials.getSecrets(id),
      deleteSecrets: (id) => w.credentials.deleteSecrets(id),
      deleteSecret: (id, key) => w.credentials.deleteSecret(id, key),
      async saveSecret(id, key, value) {
        order.push(["save", key]);
        return w.credentials.saveSecret(id, key, value);
      },
    },
  };

  await reconnectAccount(w.db, deps, {
    accountId: account.id,
    secrets: { ...OAUTH_SECRETS, MAIL_REFRESH_TOKEN: "refresh-token-new-9e1f" },
  });
  await flush();

  const names = order.map(([name]) => name);
  assert.equal(names[0], "forget", "the cached provider is retired first");
  assert.equal(names.filter((name) => name === "forget").length, 2, "and once more after the swap");
  assert.equal(names.includes("stopAccount"), false, "there is no stop to call");
  assert.deepEqual(order.filter(([name]) => name === "restartAccount"), [["restartAccount", account.id]]);
  assert.deepEqual(
    await w.credentials.getSecrets(account.id),
    { ...OAUTH_SECRETS, MAIL_REFRESH_TOKEN: "refresh-token-new-9e1f" },
  );
});

test("a provider the worker builds after the retire cannot write the old grant over the new one", async () => {
  const fake = await startFakeOAuthProvider();
  fakes.push(fake);
  const w = await world();
  const OLD = {
    MAIL_REFRESH_TOKEN: "refresh-token-old-5a2b",
    MAIL_OAUTH_CLIENT_ID: "client-id-4f1a2b7d",
  };
  const account = await connectAccount(w.db, w.deps, {
    draft: OAUTH_ACCOUNT, authKind: "xoauth2", secrets: OLD,
    tokenProvider: async () => ({ accessToken: "one-shot-access" }),
  });
  await flush();

  // The real registry, over the local fake token endpoint: the provider it builds reads the keychain,
  // which still holds the OLD refresh token in the window between the retire and the swap. Its rotation
  // write is held until the test has let the swap finish — that parked write is exactly the one that
  // used to land on top of the fresh grant.
  let releaseRotation;
  const rotationGate = new Promise((resolve) => { releaseRotation = resolve; });
  const rotationWrites = [];
  const registryCredentials = {
    getSecrets: (id) => w.credentials.getSecrets(id),
    saveSecret: (id, key, value) => {
      if (key === "MAIL_REFRESH_TOKEN") {
        const write = rotationGate.then(() => w.credentials.saveSecret(id, key, value));
        rotationWrites.push(write);
        return write;
      }
      return w.credentials.saveSecret(id, key, value);
    },
  };
  const registry = createTokenProviderRegistry({
    db: w.db,
    credentials: registryCredentials,
    endpoints: { tokenUrl: fake.tokenUrl },
  });
  // The refreshes are answered with a rotation, held until the test says so: Microsoft does this every
  // time. Two are queued because the worker may ask more than once (see the forget hook below).
  fake.queueResponse({
    hold: true,
    body: { access_token: "old-grant-access", expires_in: 3600, refresh_token: "old-grant-rotated-1" },
  });
  fake.queueResponse({
    hold: true,
    body: { access_token: "old-grant-access-2", expires_in: 3600, refresh_token: "old-grant-rotated-2" },
  });

  const calls = [];
  let running = true;
  // Every token the still-running worker asked the registry for.
  const workerAsks = [];
  const NEW_TOKEN = "refresh-token-new-9e1f";
  const deps = {
    ...w.deps,
    supervisor: {
      async syncNow() {},
      // The delete route's own call: awaited, and it is what leaves the account quiet for the swap.
      async stopAccount(id) { calls.push(["stopAccount", id]); running = false; },
      async restartAccount(id) { calls.push(["restartAccount", id]); running = true; },
    },
    // A running worker's adapter resolves `tokenProviderFor(id)` on EVERY use, and the registry builds a
    // fresh provider after `forget()` — so a worker that was never stopped simply asks again after each
    // retire, and the LAST provider it holds is the one no delete removes. Nothing asks once the worker
    // has been stopped for the swap.
    forgetTokenProvider: async (id) => {
      calls.push(["forget", id]);
      await registry.forget(id);
      if (running) {
        workerAsks.push(registry.tokenProviderFor(id)({ accountId: id, forceRefresh: true }).catch(() => {}));
      }
    },
  };

  const updated = await reconnectAccount(w.db, deps, {
    accountId: account.id,
    secrets: { MAIL_REFRESH_TOKEN: NEW_TOKEN, MAIL_OAUTH_CLIENT_ID: OLD.MAIL_OAUTH_CLIENT_ID },
  });
  assert.equal(updated.id, account.id);

  // Whatever the worker managed to start, let it finish: a rotation write that has not landed yet is
  // precisely the token that used to overwrite the fresh grant. The worker's refreshes were issued
  // during the reconnect, so wait until they have reached the fake — the queued answers are held, and
  // they must be the answers those requests get.
  for (let i = 0; i < 100 && fake.requests.length < workerAsks.length; i += 1) await flush(2);
  assert.equal(fake.requests.length, workerAsks.length, "every ask the worker made reached the token endpoint");
  fake.releaseHeld();
  releaseRotation();
  await Promise.all(workerAsks);
  await Promise.all(rotationWrites.map((write) => write.catch(() => {})));
  await flush();

  assert.deepEqual(
    await w.credentials.getSecrets(account.id),
    { MAIL_REFRESH_TOKEN: NEW_TOKEN, MAIL_OAUTH_CLIENT_ID: OLD.MAIL_OAUTH_CLIENT_ID },
    "the new grant's refresh token is the one the keychain keeps",
  );
  assert.equal(fake.requests.length, 0, "the quiesced worker never refreshed with the old grant");
  assert.deepEqual(
    calls.filter(([what]) => what !== "forget"),
    [["stopAccount", account.id], ["restartAccount", account.id]],
    "the worker was stopped before the swap and started again after it",
  );
});

test("a claim taken while the probe runs swaps nothing", async () => {
  const w = await world();
  const account = await connectAccount(w.db, w.deps, { draft: OAUTH_ACCOUNT, authKind: "xoauth2", secrets: OAUTH_SECRETS, tokenProvider: async () => ({ accessToken: "a" }) });
  await flush();
  w.supervisorCalls.length = 0;
  const savesBefore = w.saves.length;
  const forgets = [];
  const stops = [];
  let checks = 0;
  const deps = {
    ...w.deps,
    supervisor: {
      async syncNow(id) { w.supervisorCalls.push(["syncNow", id]); },
      async restartAccount(id) { w.supervisorCalls.push(["restartAccount", id]); },
      async stopAccount(id) { stops.push(id); w.supervisorCalls.push(["stopAccount", id]); },
    },
    forgetTokenProvider: (id) => forgets.push(id),
    claims: {
      async checkClaim(db, address, options) {
        checks += 1;
        // The second read is the one after the probe: the address was claimed elsewhere meanwhile.
        if (checks === 2) return { ok: false, instanceName: "Echo" };
        return checkClaim(db, address, options);
      },
      writeClaim,
      releaseClaim,
    },
  };

  await assert.rejects(
    () => reconnectAccount(w.db, deps, {
      accountId: account.id,
      secrets: { ...OAUTH_SECRETS, MAIL_REFRESH_TOKEN: "refresh-token-new-9e1f" },
      tokenProvider: async () => ({ accessToken: "new-grant", expiresAt: Date.now() + 3_600_000 }),
    }),
    (err) => {
      assert.equal(err.code, "CLAIMED_ELSEWHERE");
      return true;
    },
  );

  assert.equal(checks, 2, "the claim was read again after the probe");
  assert.equal(w.oauthFactoryCalls.length, 2, "the probe really did run in between");
  assert.equal(w.saves.length, savesBefore, "no secret was written");
  assert.deepEqual(forgets, [], "the cached provider was not retired for a swap that never happened");
  assert.deepEqual(stops, [], "and the worker was not stopped either");
  await flush();
  assert.deepEqual(w.supervisorCalls, [], "nothing was started, stopped or restarted");
  assert.equal(
    (await w.credentials.getSecrets(account.id)).MAIL_REFRESH_TOKEN,
    OAUTH_SECRETS.MAIL_REFRESH_TOKEN,
    "the stored grant is untouched",
  );
});

test("a reconnect records the new grant's meta, and a meta write that fails swaps no secret", async () => {
  const w = await world();
  const account = await connectAccount(w.db, w.deps, { draft: OAUTH_ACCOUNT, authKind: "xoauth2", secrets: OAUTH_SECRETS, tokenProvider: async () => ({ accessToken: "a" }) });
  await flush();
  await setOauthMeta(w.db, account.id, { grantedAt: 1_000, publishing: "unknown", provider: "google" });

  // The new grant's own label: a fresh grantedAt, and for a Microsoft account its real tenant.
  const seen = [];
  const restarts = [];
  const deps = {
    ...w.deps,
    supervisor: {
      async syncNow() {},
      async restartAccount(id) { restarts.push(id); seen.push(await getOauthMeta(w.db, id)); },
    },
  };
  const meta = { grantedAt: 1_800_000_000_000, publishing: "unknown", provider: "google" };
  await reconnectAccount(w.db, deps, {
    accountId: account.id,
    secrets: { ...OAUTH_SECRETS, MAIL_REFRESH_TOKEN: "refresh-token-new-9e1f" },
    oauthMeta: meta,
  });
  await flush();
  assert.deepEqual(restarts, [account.id]);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].grantedAt, meta.grantedAt, "the new grant's grantedAt is in place before the worker restarts");

  // A meta write that cannot land: the reconnect fails and NOTHING is swapped — and the worker that was
  // stopped for the swap is started again, so a failed reconnect does not leave the account unsynced.
  const boom = new Error("SQLITE_FULL: database or disk is full (dashboard_settings)");
  const before = await w.credentials.getSecrets(account.id);
  const failing = { ...deps, setOauthMeta: async () => { throw boom; } };
  restarts.length = 0;
  await assert.rejects(
    () => reconnectAccount(w.db, failing, {
      accountId: account.id,
      secrets: { ...OAUTH_SECRETS, MAIL_REFRESH_TOKEN: "refresh-token-that-must-not-land" },
      oauthMeta: { grantedAt: 1_900_000_000_000, publishing: "unknown", provider: "google" },
    }),
    (err) => err === boom,
  );
  assert.deepEqual(await w.credentials.getSecrets(account.id), before, "no secret was swapped");
  assert.equal((await getOauthMeta(w.db, account.id)).grantedAt, meta.grantedAt, "and no meta was written");
  await flush();
  assert.deepEqual(restarts, [account.id], "the worker is started again on the secrets still stored");
});

test("a reconnect whose new grant names no client secret deletes the old one, and only that key", async () => {
  const w = await world();
  const account = await connectAccount(w.db, w.deps, { draft: OAUTH_ACCOUNT, authKind: "xoauth2", secrets: OAUTH_SECRETS, tokenProvider: async () => ({ accessToken: "a" }) });
  await flush();

  const fresh = {
    MAIL_OAUTH_CLIENT_ID: "client-id-different-7c2e",
    MAIL_REFRESH_TOKEN: "refresh-token-new-9e1f",
  };
  const updated = await reconnectAccount(w.db, w.deps, { accountId: account.id, secrets: fresh });
  assert.equal(updated.id, account.id);
  assert.deepEqual(
    await w.credentials.getSecrets(account.id),
    fresh,
    "the old registration's secret is gone with the grant that names none",
  );
  assert.deepEqual(
    w.keyDeletes,
    [{ id: account.id, key: "MAIL_OAUTH_CLIENT_SECRET" }],
    "one key, that account, and nothing else",
  );

  // A password account never touches the OAuth client keys, whatever its secrets name.
  const password = await connectAccount(w.db, w.deps, { draft: { ...DRAFT, address: "sam@example.com" }, secrets: { MAIL_PASSWORD: PASSWORD } });
  w.keyDeletes.length = 0;
  await reconnectAccount(w.db, w.deps, { accountId: password.id, secrets: { MAIL_PASSWORD: NEW_PASSWORD } });
  assert.deepEqual(w.keyDeletes, [], "a password reconnect deletes no key");
});

/* ------------------------------------------------------------- the routes */

/** One request against `server`. */
function call(server, method, path, body) {
  const payload = body === undefined ? null : JSON.stringify(body);
  const headers = payload === null
    ? {}
    : { "content-type": "application/json", "content-length": Buffer.byteLength(payload) };
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: server.address().port, method, path, headers }, (res) => {
      let text = "";
      res.on("data", (c) => { text += c; });
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, text, json });
      });
    });
    req.on("error", reject);
    req.end(payload === null ? undefined : payload);
  });
}

/** The mail API on a real socket, with the dashboard's auth gate stubbed out for this test. */
async function routeWorld(options = {}) {
  const w = await world(options);
  const opened = { n: 0, closed: 0 };
  const openDb = () => {
    opened.n += 1;
    const client = createDbClient(w.crow);
    const close = client.close.bind(client);
    client.close = () => { opened.closed += 1; return close(); };
    return options.wrapDb == null ? client : (options.wrapDb(client) ?? client);
  };
  const app = express();
  app.use(mailApiRouter((req, res, next) => next(), {
    ...w.deps,
    openDb,
    // The owner gate is the dashboard's real one; this file is about the connect, so the session check
    // is answered yes here (tests/mail-api-accounts.test.js owns the gate itself).
    ownerCheck: async () => true,
  }));
  const server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.push(server);
  return { ...w, server, opened };
}

const BODY = { ...DRAFT, password: PASSWORD };

test("POST /accounts refuses an OAuth body with oauth_via_wizard, and still takes a password", async () => {
  const w = await routeWorld();
  const path = `${MAIL_API_PREFIX}/accounts`;

  for (const authKind of ["xoauth2"]) {
    const refused = await call(w.server, "POST", path, { ...BODY, authKind });
    assert.equal(refused.status, 400, refused.text);
    assert.equal(refused.json.error, "oauth_via_wizard");
    assert.equal(refused.text.includes(ADDRESS), false, "the answer names no address");
    assert.equal(refused.text.includes(PASSWORD), false, "the answer carries no secret");
  }
  // Even an OAuth body with no password — the shape a wizard's body would have — is that answer, not
  // a generic bad_input: the route knows what an OAuth connect is and where it belongs.
  const bare = await call(w.server, "POST", path, { label: "Google", address: ADDRESS, provider: "google", authKind: "xoauth2" });
  assert.equal(bare.status, 400, bare.text);
  assert.equal(bare.json.error, "oauth_via_wizard");

  assert.equal(await w.count("mail_accounts"), 0, "nothing was stored");
  assert.deepEqual(w.factoryCalls, [], "nothing was dialled");

  // An authKind this Crow does not know is the body's own fault, and `password` is the default.
  const unknown = await call(w.server, "POST", path, { ...BODY, authKind: "oauth-maybe" });
  assert.equal(unknown.status, 400, unknown.text);
  assert.equal(unknown.json.error, "bad_input");

  const accepted = await call(w.server, "POST", path, { ...BODY, authKind: "password" });
  assert.equal(accepted.status, 201, accepted.text);
  assert.equal(accepted.json.account.address, ADDRESS);
  assert.equal(await w.count("mail_accounts"), 1);

  // And the same body with no authKind at all is a password connect, exactly as before.
  const second = await call(w.server, "POST", path, { ...BODY, address: "sam@example.com" });
  assert.equal(second.status, 201, second.text);
  assert.equal(await w.count("mail_accounts"), 2);
  assert.equal(w.opened.n, w.opened.closed, "one client per request, closed");
});

test("a duplicate and a lost claim still answer their own 409s through the connect route", async () => {
  const w = await routeWorld();
  const path = `${MAIL_API_PREFIX}/accounts`;
  assert.equal((await call(w.server, "POST", path, BODY)).status, 201);

  const duplicate = await call(w.server, "POST", path, { ...BODY, address: "Alex@Example.COM" });
  assert.equal(duplicate.status, 409, duplicate.text);
  assert.deepEqual(duplicate.json, {
    error: "duplicate_address",
    message: "That address is already connected on this Crow.",
  });

  // A peer's older claim lands after the duplicate check of a fresh address: the named 409 survives the
  // move to connectAccount.
  await peerInstance(w.db);
  await writeClaim(w.db, "sam@example.com", { localInstanceId: PEER, instanceName: "Echo", now: 1_000 });
  const claimed = await call(w.server, "POST", path, { ...BODY, address: "sam@example.com" });
  assert.equal(claimed.status, 409, claimed.text);
  assert.deepEqual(claimed.json, {
    error: "CLAIMED_ELSEWHERE",
    message: "This account is already connected on Echo",
  });
  assert.equal(await w.count("mail_accounts"), 1);
});

test("DELETE drops the account's OAuth meta, and a meta write that fails does not fail the delete", async () => {
  const w = await routeWorld();
  const path = `${MAIL_API_PREFIX}/accounts`;

  const created = await call(w.server, "POST", path, BODY);
  assert.equal(created.status, 201, created.text);
  const id = created.json.account.id;
  await setOauthMeta(w.db, id, { provider: "google", publishing: "testing" });
  assert.ok(await getOauthMeta(w.db, id), "the grant label is recorded");

  const deleted = await call(w.server, "DELETE", `${path}/${id}`);
  assert.equal(deleted.status, 200, deleted.text);
  assert.deepEqual(deleted.json, { ok: true, messages: 0 });
  assert.equal(await getOauthMeta(w.db, id), null, "the label went with the account");
  assert.equal(await w.count("mail_accounts"), 0);

  // The same delete with a meta write that cannot land: the account still goes, and the failure is a
  // code in the log — never the request's answer.
  const failing = await routeWorld({
    wrapDb: (client) => {
      const real = client.execute.bind(client);
      client.execute = async (query, ...rest) => {
        const args = query && typeof query === "object" ? (query.args ?? []) : [];
        if (args[0] === "mail_oauth_meta") throw new Error("SQLITE_FULL: database or disk is full (dashboard_settings_overrides)");
        return real(query, ...rest);
      };
      return client;
    },
  });
  const second = await call(failing.server, "POST", path, BODY);
  assert.equal(second.status, 201, second.text);
  const secondId = second.json.account.id;
  await setOauthMeta(failing.db, secondId, { provider: "google" });

  const lines = [];
  const originalWarn = console.warn;
  console.warn = (...args) => { lines.push(args.map((a) => String(a)).join(" ")); };
  let refused;
  try {
    refused = await call(failing.server, "DELETE", `${path}/${secondId}`);
  } finally {
    console.warn = originalWarn;
  }
  assert.equal(refused.status, 200, refused.text);
  assert.deepEqual(refused.json, { ok: true, messages: 0 });
  assert.equal(await failing.count("mail_accounts"), 0, "the account was removed anyway");
  assert.ok(await getOauthMeta(failing.db, secondId), "…and the label stayed, which nothing reads");
  assert.ok(lines.some((line) => line.includes("delete_oauth_meta")), "the failure is a code in the log");
  assert.equal(lines.join("\n").includes("SQLITE_FULL"), false, "the log carries the code, never the store's text");
});