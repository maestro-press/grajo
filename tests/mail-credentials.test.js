// Crow Mail credentials (Task 5 of plan 1): a password or refresh token in the sealed keychain, keyed
// by the mail account id, never in mail_accounts and never in an error. Every test uses a scratch DB
// built from MAIL_DDL and its own temporary crowHome, so the keychain key is a throwaway file.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDbClient } from "../servers/db.js";
import { MAIL_DDL, MAIL_ACCOUNT_SEND_COLUMNS } from "../servers/shared/mail-schema.js";
import { MAIL_ERROR_TEXT, MailError } from "../servers/gateway/mail/errors.js";
import { createAccount } from "../servers/gateway/mail/store/accounts.js";
import {
  ensureKeychainTable, ensureWriteKey, listEntries, saveServiceSecret, serviceSecretsFor, deleteEntry,
  KeychainKeyMissingError,
} from "../servers/gateway/keychain/store.js";
import { loadKeychainKey } from "../servers/gateway/keychain/key.js";
import {
  MAIL_BUNDLE_ID, MAIL_SECRET_KEYS, createMailCredentials, createRotationWriter, authFor,
} from "../servers/gateway/mail/credentials.js";

const ALEX = "alex@example.com";
const SAM = "sam@example.com";
const PASSWORD = "app-pass-9f2c";
const OTHER_PASSWORD = "app-pass-5b71";
const HUNTER = "hunter2";
const CLIENT_ID = "client-id-4f1a2b7d";
const CLIENT_SECRET = "client-secret-9d3c51aa";
const SAM_CLIENT_SECRET = "client-secret-1b7e0f42";

const dirs = [];
after(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

function tmp(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  dirs.push(dir);
  return dir;
}

const freshHome = () => tmp("crow-mail-cred-home-");

async function freshDb() {
  const db = createDbClient(join(tmp("crow-mail-cred-db-"), "crow.db"));
  await db.executeMultiple(MAIL_DDL);
  // The account send columns (plan 3's A3) are ADD COLUMN specs of their own, not part of MAIL_DDL.
  for (const spec of MAIL_ACCOUNT_SEND_COLUMNS) {
    await db.execute({ sql: `ALTER TABLE ${spec.table} ADD COLUMN ${spec.column} ${spec.definition}`, args: [] });
  }
  return db;
}

function accountInput(address = ALEX, overrides = {}) {
  return {
    label: "Alex",
    address,
    imap: { host: "mail.example.test", port: 993, security: "ssl" },
    smtp: { host: "mail.example.test", port: 465, security: "ssl" },
    ...overrides,
  };
}

function mailCode(code) {
  return (err) => {
    assert.ok(err instanceof MailError, `expected a MailError, got ${err && err.name}`);
    assert.equal(err.code, code);
    return true;
  };
}

/** Every row of the keychain table, whatever its columns — the leak check reads all of them. */
async function keychainRows(db) {
  return (await db.execute("SELECT * FROM crow_keychain")).rows;
}

function assertNoPlaintext(rows, ...needles) {
  for (const row of rows) {
    for (const [column, value] of Object.entries(row)) {
      const text = value == null ? "" : String(value);
      for (const needle of needles) {
        assert.ok(!text.includes(needle), `crow_keychain.${column} carries a plaintext secret`);
      }
    }
  }
}

/* ------------------------------------------------------------------ save / read */

test("a saved password reads back through getSecrets, and every keychain column stays ciphertext", async () => {
  const db = await freshDb();
  const home = freshHome();
  const account = await createAccount(db, accountInput(ALEX));
  const credentials = createMailCredentials({ db, crowHome: home });

  const saved = await credentials.saveSecret(account.id, "MAIL_PASSWORD", PASSWORD);
  assert.ok(Number(saved.id) > 0);
  assert.equal(saved.created, true);

  assert.deepEqual(await credentials.getSecrets(account.id), { MAIL_PASSWORD: PASSWORD });

  const rows = await keychainRows(db);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, "service");
  assert.equal(rows[0].bundle_id, MAIL_BUNDLE_ID);
  assert.equal(rows[0].env_key, "MAIL_PASSWORD");
  assert.equal(rows[0].connection_uuid, account.id);
  assert.equal(rows[0].status, "active");
  assert.equal(rows[0].label, `Mail: ${ALEX}`, "the row names the account's address for the panel");
  assert.equal(rows[0].username, null, "nothing but the label and the sealed value describes the account");
  assertNoPlaintext(rows, PASSWORD);
});

test("the account row keeps no secret: mail_accounts is what the API may return", async () => {
  const db = await freshDb();
  const account = await createAccount(db, accountInput(ALEX));
  await createMailCredentials({ db, crowHome: freshHome() }).saveSecret(account.id, "MAIL_PASSWORD", PASSWORD);
  const rows = (await db.execute("SELECT * FROM mail_accounts")).rows;
  assert.equal(rows.length, 1);
  assertNoPlaintext(rows, PASSWORD);
});

test("a second save of the same key updates the row in place", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  const account = await createAccount(db, accountInput(ALEX));
  const first = await credentials.saveSecret(account.id, "MAIL_PASSWORD", PASSWORD);
  const second = await credentials.saveSecret(account.id, "MAIL_PASSWORD", OTHER_PASSWORD);
  assert.equal(second.id, first.id);
  assert.equal(second.created, false);
  assert.deepEqual(await credentials.getSecrets(account.id), { MAIL_PASSWORD: OTHER_PASSWORD });
  const rows = await keychainRows(db);
  assert.equal(rows.length, 1);
  assertNoPlaintext(rows, PASSWORD, OTHER_PASSWORD);
});

test("only the mail env keys are accepted, and only with a non-empty secret", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  const account = await createAccount(db, accountInput(ALEX));

  await assert.rejects(credentials.saveSecret(account.id, "IMAP_PASSWORD", PASSWORD), mailCode("BAD_INPUT"));
  await assert.rejects(credentials.saveSecret(account.id, "MAIL_PASSWORD", ""), mailCode("BAD_INPUT"));
  await assert.rejects(credentials.saveSecret(account.id, "MAIL_PASSWORD", null), mailCode("BAD_INPUT"));
  await assert.rejects(credentials.saveSecret("", "MAIL_PASSWORD", PASSWORD), mailCode("BAD_INPUT"));
  await ensureKeychainTable(db);
  assert.equal((await keychainRows(db)).length, 0, "a refused save writes no row");

  assert.deepEqual(MAIL_SECRET_KEYS, [
    "MAIL_PASSWORD", "MAIL_REFRESH_TOKEN", "MAIL_OAUTH_CLIENT_ID", "MAIL_OAUTH_CLIENT_SECRET",
  ]);
  await credentials.saveSecret(account.id, "MAIL_REFRESH_TOKEN", "refresh-token-1");
  assert.deepEqual(await credentials.getSecrets(account.id), { MAIL_REFRESH_TOKEN: "refresh-token-1" });

  // A near miss of a real key is still refused: the list is exact, never a prefix or a pattern.
  for (const key of ["MAIL_OAUTH_CLIENT", "MAIL_OAUTH", "OAUTH_CLIENT_SECRET", "MAIL_CLIENT_SECRET",
    "mail_oauth_client_id", "MAIL_OAUTH_CLIENT_ID ", " MAIL_PASSWORD"]) {
    await assert.rejects(credentials.saveSecret(account.id, key, PASSWORD), mailCode("BAD_INPUT"), JSON.stringify(key));
  }
});

/* ------------------------------------------- OAuth client keys (plan 5, Task 2) */

// An OAuth sign-in needs the app registration's own pair (client id and client secret) beside the
// refresh token, so both are keychain keys of the account like the other two. They are still sealed:
// the client secret is a secret, and the pair is useless without the token it refreshes.
const OAUTH_KEYS = Object.freeze(["MAIL_OAUTH_CLIENT_ID", "MAIL_OAUTH_CLIENT_SECRET"]);

test("the OAuth client id and secret save, read back, and stay out of every plaintext column", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  const account = await createAccount(db, accountInput(ALEX));

  const savedId = await credentials.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  const savedSecret = await credentials.saveSecret(account.id, "MAIL_OAUTH_CLIENT_SECRET", CLIENT_SECRET);
  assert.equal(savedId.created, true);
  assert.equal(savedSecret.created, true);

  assert.deepEqual(await credentials.getSecrets(account.id), {
    MAIL_OAUTH_CLIENT_ID: CLIENT_ID,
    MAIL_OAUTH_CLIENT_SECRET: CLIENT_SECRET,
  });

  const rows = await keychainRows(db);
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((r) => r.env_key).sort(), [...OAUTH_KEYS].sort());
  for (const row of rows) {
    // env_key holds the KEY NAME, which is metadata; the value is nowhere in plaintext.
    assert.equal(row.kind, "service");
    assert.equal(row.bundle_id, MAIL_BUNDLE_ID);
    assert.equal(row.connection_uuid, account.id);
    assert.equal(row.status, "active");
    assert.equal(row.label, `Mail: ${ALEX}`, "the label names the account, never a credential");
    for (const column of ["label", "username", "url", "env_key"]) {
      const text = row[column] == null ? "" : String(row[column]);
      assert.ok(!text.includes(CLIENT_ID), `crow_keychain.${column} carries the client id`);
      assert.ok(!text.includes(CLIENT_SECRET), `crow_keychain.${column} carries the client secret`);
    }
    assert.equal(row.username ?? null, null);
    assert.equal(row.url ?? null, null);
  }
  assertNoPlaintext(rows, CLIENT_ID, CLIENT_SECRET);
});

test("all four keys of one account go together, and another account's rows are untouched", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  const alex = await createAccount(db, accountInput(ALEX));
  const sam = await createAccount(db, accountInput(SAM));

  await credentials.saveSecret(alex.id, "MAIL_PASSWORD", PASSWORD);
  await credentials.saveSecret(alex.id, "MAIL_REFRESH_TOKEN", "refresh-alex");
  await credentials.saveSecret(alex.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await credentials.saveSecret(alex.id, "MAIL_OAUTH_CLIENT_SECRET", CLIENT_SECRET);
  await credentials.saveSecret(sam.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await credentials.saveSecret(sam.id, "MAIL_OAUTH_CLIENT_SECRET", SAM_CLIENT_SECRET);

  const out = await credentials.deleteSecrets(alex.id);
  assert.equal(out.deleted, 4, "every one of the four keys went with the account");
  assert.deepEqual(await credentials.getSecrets(alex.id), {});
  assert.equal((await db.execute({
    sql: "SELECT COUNT(*) AS n FROM crow_keychain WHERE connection_uuid = ?", args: [alex.id],
  })).rows[0].n, 0);

  assert.deepEqual(await credentials.getSecrets(sam.id), {
    MAIL_OAUTH_CLIENT_ID: CLIENT_ID,
    MAIL_OAUTH_CLIENT_SECRET: SAM_CLIENT_SECRET,
  }, "the other account keeps its own pair");
  assertNoPlaintext(await keychainRows(db), CLIENT_SECRET, SAM_CLIENT_SECRET);
});

test("a mail row for an OAuth key still lists in the keychain panel and is not the panel's to delete", async () => {
  const db = await freshDb();
  const home = freshHome();
  const credentials = createMailCredentials({ db, crowHome: home });
  const account = await createAccount(db, accountInput(ALEX));
  await credentials.saveSecret(account.id, "MAIL_OAUTH_CLIENT_ID", CLIENT_ID);
  await credentials.saveSecret(account.id, "MAIL_OAUTH_CLIENT_SECRET", CLIENT_SECRET);
  const key = await ensureWriteKey(db, { crowHome: home });

  const entries = await listEntries(db, { keyId: key.id });
  const mine = entries.filter((entry) => entry.connection_uuid === account.id);
  assert.equal(mine.length, 2, "the panel's reader sees both OAuth rows");
  assert.deepEqual(mine.map((e) => e.env_key).sort(), [...OAUTH_KEYS].sort());
  for (const entry of mine) {
    assert.equal(entry.kind, "service");
    assert.equal(entry.bundle_id, MAIL_BUNDLE_ID);
    assert.equal(entry.label, `Mail: ${ALEX}`);
    assert.equal(entry.readable, true);
  }
  const listed = JSON.stringify(entries);
  assert.ok(!listed.includes(CLIENT_ID), "no listed field carries the client id");
  assert.ok(!listed.includes(CLIENT_SECRET), "no listed field carries the client secret");

  // Its lifetime is the account's: the keychain page may not purge a mail row, the account delete is.
  for (const entry of mine) {
    await assert.rejects(deleteEntry(db, entry.id), (err) => err.code === "KEYCHAIN_MAIL_ROW");
  }
  assert.equal((await listEntries(db, { keyId: key.id })).length, 2, "both rows are still there");
});

test("the row falls back to the account id when the mail_accounts row is gone", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  const orphanId = "ma-0123456789abcdef";
  await credentials.saveSecret(orphanId, "MAIL_PASSWORD", PASSWORD);
  const rows = await keychainRows(db);
  assert.equal(rows[0].label, `Mail: ${orphanId}`);
  assert.equal(rows[0].connection_uuid, orphanId);
  assert.deepEqual(await credentials.getSecrets(orphanId), { MAIL_PASSWORD: PASSWORD });
});

test("nothing saved is an empty object, not an error — including from a home with no key file", async () => {
  const db = await freshDb();
  const id = "ma-0123456789abcdef";

  // A credentials object whose crowHome holds no keychain.key at all, on a table that was never created.
  const keylessHome = freshHome();
  assert.equal(loadKeychainKey({ crowHome: keylessHome }), null);
  const keyless = createMailCredentials({ db, crowHome: keylessHome });
  assert.deepEqual(await keyless.getSecrets(id), {}, "no rows and no key file: nothing saved");

  // The same home once rows exist under another machine's key: the fault is the key, never {}.  A row
  // that is there and cannot be opened is not "nothing saved".
  const account = await createAccount(db, accountInput(ALEX));
  const sealedElsewhere = createMailCredentials({ db, crowHome: freshHome() });
  await sealedElsewhere.saveSecret(account.id, "MAIL_PASSWORD", PASSWORD);
  assert.deepEqual(await keyless.getSecrets(id), {}, "another account's rows are not this account's");
  await assert.rejects(keyless.getSecrets(account.id), (err) => {
    assert.ok(err instanceof KeychainKeyMissingError, `expected the key-missing fault, got ${err && err.name}`);
    assert.equal(err.code, "KEYCHAIN_KEY_MISSING");
    return true;
  });
});

test("rows sealed under another machine's key raise the key-missing fault unchanged", async () => {
  const db = await freshDb();
  const account = await createAccount(db, accountInput(ALEX));
  await createMailCredentials({ db, crowHome: freshHome() }).saveSecret(account.id, "MAIL_PASSWORD", PASSWORD);

  // The same crow.db, a machine whose keychain.key is not there (a restore without the key file).
  const restored = createMailCredentials({ db, crowHome: freshHome() });
  await assert.rejects(restored.getSecrets(account.id), (err) => {
    assert.ok(err instanceof KeychainKeyMissingError);
    assert.equal(err.code, "KEYCHAIN_KEY_MISSING");
    return true;
  });
});

/* ------------------------------------------------------------------- deletion */

test("deleteSecrets removes one account's rows and leaves another account's alone", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  const alex = await createAccount(db, accountInput(ALEX));
  const sam = await createAccount(db, accountInput(SAM));
  await credentials.saveSecret(alex.id, "MAIL_PASSWORD", PASSWORD);
  await credentials.saveSecret(alex.id, "MAIL_REFRESH_TOKEN", "refresh-alex");
  await credentials.saveSecret(sam.id, "MAIL_PASSWORD", OTHER_PASSWORD);

  const out = await credentials.deleteSecrets(alex.id);
  assert.equal(out.deleted, 2);
  assert.deepEqual(await credentials.getSecrets(alex.id), {});
  assert.deepEqual(await credentials.getSecrets(sam.id), { MAIL_PASSWORD: OTHER_PASSWORD });

  // REVIEW FOCUS 5: no row is left under the removed account's connection_uuid.
  const left = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM crow_keychain WHERE connection_uuid = ?", args: [alex.id],
  });
  assert.equal(Number(left.rows[0].n), 0);
  assert.equal((await keychainRows(db)).length, 1);
  assertNoPlaintext(await keychainRows(db), PASSWORD, "refresh-alex");
});

/* ------------------------------------------------------------------- authFor */

const XOAUTH2_ACCOUNT = Object.freeze({
  id: "ma-0123456789abcdef",
  address: ALEX,
  username: ALEX,
  authKind: "xoauth2",
});

test("authFor returns the saved password for a password account", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  const account = await createAccount(db, accountInput(ALEX));
  await credentials.saveSecret(account.id, "MAIL_PASSWORD", PASSWORD);
  assert.deepEqual(await authFor(account, { credentials }), { user: ALEX, pass: PASSWORD });
});

test("authFor refuses a password account with no saved password", async () => {
  const db = await freshDb();
  const account = await createAccount(db, accountInput(ALEX));
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  await assert.rejects(authFor(account, { credentials }), mailCode("AUTH_FAILED"));
  await assert.rejects(authFor(account, {}), mailCode("AUTH_FAILED"));
});

test("authFor asks the token provider for an xoauth2 account, forwarding forceRefresh", async () => {
  const calls = [];
  const noCredentials = {};
  const tokenProvider = async (arg) => {
    calls.push(arg);
    return { accessToken: "access-token-1", expiresAt: Date.now() + 3_600_000 };
  };

  assert.deepEqual(
    await authFor(XOAUTH2_ACCOUNT, { credentials: noCredentials, tokenProvider }),
    { user: ALEX, accessToken: "access-token-1" },
  );
  assert.deepEqual(calls, [{ accountId: XOAUTH2_ACCOUNT.id, forceRefresh: false }]);

  await authFor(XOAUTH2_ACCOUNT, { credentials: noCredentials, tokenProvider, forceRefresh: true });
  assert.deepEqual(calls[1], { accountId: XOAUTH2_ACCOUNT.id, forceRefresh: true });
});

test("authFor refuses xoauth2 with no provider or no usable token", async () => {
  await assert.rejects(authFor(XOAUTH2_ACCOUNT, { credentials: {} }), mailCode("AUTH_FAILED"));
  await assert.rejects(
    authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider: async () => ({}) }),
    mailCode("AUTH_FAILED"),
  );
  await assert.rejects(
    authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider: async () => ({ accessToken: "" }) }),
    mailCode("AUTH_FAILED"),
  );
});

test("REVIEW FOCUS 2 — a provider error carrying a secret surfaces as AUTH_FAILED without it", async () => {
  const tokenProvider = async () => {
    const err = new Error(`refresh rejected for ${HUNTER}`);
    err.response = `AUTHENTICATE XOAUTH2 ${HUNTER}`;
    err.responseText = `bad token ${HUNTER}`;
    err.command = `AUTH ${HUNTER}`;
    err.code = HUNTER;
    throw err;
  };

  let thrown = null;
  try {
    await authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider });
  } catch (err) {
    thrown = err;
  }
  assert.ok(thrown instanceof MailError);
  assert.equal(thrown.code, "AUTH_FAILED");
  assert.equal(thrown.message, "Crow could not sign in to the mail server.");
  assert.equal(thrown.detail, null, "a library code never becomes the detail");
  const surface = [thrown.message, String(thrown.detail), thrown.code, String(thrown), JSON.stringify(thrown), thrown.stack].join("\n");
  assert.ok(!surface.includes(HUNTER), "no error field quotes the provider's text");
});

test("H1: a provider's own MailError keeps its code, so a NETWORK blip is not read as a dead credential", async () => {
  for (const thrown of [
    new MailError("NETWORK", "ECONNRESET"),
    new MailError("NETWORK"),
    new MailError("PROTOCOL", "no_access_token"),
    new MailError("TIMEOUT", "ETIMEDOUT"),
    new MailError("AUTH_FAILED", "invalid_grant"),
  ]) {
    const tokenProvider = async () => { throw thrown; };
    let caught = null;
    try {
      await authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider });
    } catch (err) {
      caught = err;
    }
    assert.equal(caught.code, thrown.code, "its code is what the supervisor decides on");
    // REVIEW FIX R3: a code whose send-side meaning would be "the outcome is unknown" is tagged
    // `token` here — the refresh failed before any connection existed, so nothing was sent. The code
    // itself is unchanged, so the supervisor's back-off is not affected.
    if (thrown.code === "AUTH_FAILED") {
      assert.equal(caught, thrown, "a dead grant travels as the very error the provider threw");
      assert.equal(caught.detail, thrown.detail);
    } else {
      assert.equal(caught.detail, "token", `${thrown.code} arrives tagged as a token failure`);
    }
  }
});

test("R3: a provider's NETWORK/PROTOCOL/TIMEOUT failure arrives as `token`: nothing was sent", async () => {
  for (const code of ["NETWORK", "PROTOCOL", "TIMEOUT"]) {
    const tokenProvider = async () => { throw new MailError(code, "ECONNRESET"); };
    const err = await authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider }).catch((error) => error);
    assert.ok(err instanceof MailError, `${code}: a MailError`);
    assert.equal(err.code, code, `${code}: the code the supervisor backs off on is unchanged`);
    assert.equal(err.detail, "token", `${code}: tagged as a token failure`);
    assert.equal(err.message, MAIL_ERROR_TEXT[code], "the fixed sentence is the code's own");
  }

  // A dead grant is a credential answer, not a network fault: its own detail survives the trip.
  for (const detail of ["invalid_grant", "retired"]) {
    const thrown = new MailError("AUTH_FAILED", detail);
    const tokenProvider = async () => { throw thrown; };
    const err = await authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider }).catch((error) => error);
    assert.equal(err, thrown, `${detail}: travels as it was thrown`);
    assert.equal(err.detail, detail);
  }

  // Keychain faults are not token failures either.
  const missing = new KeychainKeyMissingError();
  const tokenProvider = async () => { throw missing; };
  const err = await authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider }).catch((error) => error);
  assert.equal(err, missing);
});

test("H1: only a failure that is NOT a MailError is flattened to AUTH_FAILED, without its text or its code", async () => {
  const tokenProvider = async () => {
    // A library error that classifies as a network fault AND quotes the token: neither may survive.
    throw Object.assign(new Error(`refresh refused for ${HUNTER}`), { code: "ECONNRESET" });
  };
  let thrown = null;
  try {
    await authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider });
  } catch (err) {
    thrown = err;
  }
  assert.ok(thrown instanceof MailError);
  assert.equal(thrown.code, "AUTH_FAILED", "an unclassified library error is still a refused sign-in");
  assert.equal(thrown.detail, null, "and the library's own code is never the detail");
  assert.ok(!String(thrown.message).includes(HUNTER));
});

test("authFor refuses an account with no id or an unknown auth kind", async () => {
  await assert.rejects(authFor(null, {}), mailCode("BAD_INPUT"));
  await assert.rejects(authFor({ username: ALEX, authKind: "password" }, {}), mailCode("BAD_INPUT"));
  await assert.rejects(authFor({ id: "ma-0123456789abcdef", username: ALEX, authKind: "oauth9" }, {}), mailCode("BAD_INPUT"));
});

/* ------------------------------------------------------------- token rotation */

test("the rotation writer stores a rotated refresh token and ignores an empty call", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  const account = await createAccount(db, accountInput(ALEX));
  const write = createRotationWriter(credentials);

  assert.deepEqual(await write(account.id, { refreshToken: "refresh-1" }), { saved: true });
  assert.deepEqual(await credentials.getSecrets(account.id), { MAIL_REFRESH_TOKEN: "refresh-1" });

  for (const arg of [{ refreshToken: "" }, { refreshToken: null }, {}, undefined]) {
    assert.deepEqual(await write(account.id, arg), { saved: false });
  }
  assert.deepEqual(await credentials.getSecrets(account.id), { MAIL_REFRESH_TOKEN: "refresh-1" });
});

test("the rotation writer never persists an access token", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  const account = await createAccount(db, accountInput(ALEX));
  const write = createRotationWriter(credentials);

  await write(account.id, { refreshToken: "refresh-2", accessToken: "access-token-2", expiresAt: 1 });
  assert.deepEqual(await credentials.getSecrets(account.id), { MAIL_REFRESH_TOKEN: "refresh-2" });
  const rows = await keychainRows(db);
  assert.deepEqual(rows.map((r) => r.env_key), ["MAIL_REFRESH_TOKEN"]);
  assertNoPlaintext(rows, "access-token-2");
});

test("authFor hands a rotated refresh token to the writer only when one is supplied", async () => {
  const tokenProvider = async () => ({ accessToken: "access-token-3", refreshToken: "refresh-3" });
  const writes = [];

  const auth = await authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider });
  assert.equal(auth.accessToken, "access-token-3");
  assert.deepEqual(writes, [], "no writer, no write");

  await authFor(XOAUTH2_ACCOUNT, {
    credentials: {},
    tokenProvider,
    rotation: async (accountId, value) => { writes.push([accountId, value]); },
  });
  assert.deepEqual(writes, [[XOAUTH2_ACCOUNT.id, { refreshToken: "refresh-3" }]]);
  assert.ok(!JSON.stringify(writes).includes("access-token-3"), "an access token never reaches the writer");
});

test("a failing rotation writer is reported without failing the sign-in and without its text", async () => {
  const tokenProvider = async () => ({ accessToken: "access-token-4", refreshToken: "refresh-4" });
  const auth = await authFor(XOAUTH2_ACCOUNT, {
    credentials: {},
    tokenProvider,
    rotation: async () => { throw new Error(`keychain write failed for ${HUNTER}`); },
  });
  assert.deepEqual(auth, { user: ALEX, accessToken: "access-token-4", rotationFailed: true });
  assert.equal(auth.rotationFailed, true, "a fixed boolean, never the writer's error");
  assert.deepEqual(Object.keys(auth).sort(), ["accessToken", "rotationFailed", "user"]);
  assert.ok(!JSON.stringify(auth).includes(HUNTER), "no error text rides along with the flag");
});

test("a key-missing fault from the rotation writer is rethrown unchanged", async () => {
  const tokenProvider = async () => ({ accessToken: "access-token-5", refreshToken: "refresh-5" });
  await assert.rejects(
    authFor(XOAUTH2_ACCOUNT, {
      credentials: {},
      tokenProvider,
      rotation: async () => { throw new KeychainKeyMissingError(); },
    }),
    keyMissingFault,
  );
});

/* ------------------------------------------------------------ keychain panel */

test("a mail row lists in the keychain panel without its secret", async () => {
  const db = await freshDb();
  const home = freshHome();
  const credentials = createMailCredentials({ db, crowHome: home });
  const account = await createAccount(db, accountInput(ALEX));
  await credentials.saveSecret(account.id, "MAIL_PASSWORD", PASSWORD);
  await ensureWriteKey(db, { crowHome: home });

  const entries = await listEntries(db, { keyId: loadKeychainKey({ crowHome: home }).id });
  const row = entries.find((e) => e.connection_uuid === account.id);
  assert.ok(row, "the panel's reader sees the mail row");
  assert.equal(row.kind, "service");
  assert.equal(row.bundle_id, MAIL_BUNDLE_ID);
  assert.equal(row.label, `Mail: ${ALEX}`);
  assert.equal(row.readable, true);
  assert.equal(row.status, "active");

  // The whole listed result, not a chosen subset of fields: neither the secret nor its sealed text is
  // anywhere in what the panel is handed, whatever column a future reader adds.
  const sealed = (await db.execute({
    sql: "SELECT secret_sealed FROM crow_keychain WHERE connection_uuid = ?", args: [account.id],
  })).rows[0].secret_sealed;
  assert.ok(typeof sealed === "string" && sealed.length > 0, "the row itself is sealed, not empty");
  const listed = JSON.stringify(entries);
  assert.ok(!listed.includes(PASSWORD), "no field of any listed entry carries the secret");
  assert.ok(!listed.includes(sealed), "no field of any listed entry carries the sealed text either");

  const { renderPasswordsPage } = await import("../servers/gateway/dashboard/settings/sections/passwords.js");
  const html = renderPasswordsPage({ entries, method: "none", lang: "en" });
  assert.match(html, /Mail: alex@example\.com/);
  assert.match(html, /<td>Crow Mail<\/td>/);
  assert.ok(!html.includes(PASSWORD), "the rendered page never carries the secret");
  assert.ok(!html.includes(sealed), "the rendered page never carries the sealed text");
});

/* ------------------------------------------------------------------ mail scope */

/** A call that must fail with MailError BAD_INPUT and leave the keychain table byte-identical. */
async function refusesAndChangesNothing(db, call) {
  const before = await keychainRows(db);
  await assert.rejects(call(), mailCode("BAD_INPUT"));
  assert.deepEqual(await keychainRows(db), before, "the refused call touched no row");
}

const MALFORMED_IDS = Object.freeze([
  "", " ", "ma-", "ma-0123", "ma-0123456789abcde", "ma-0123456789abcdef0",
  "ma-0123456789ABCDEF", "MA-0123456789abcdef", "ma-0123456789abcdeZ",
  "ma_0123456789abcdef", " ma-0123456789abcdef", "ma-0123456789abcdef ",
  "acct-0123456789abcdef", null, 42,
]);

test("every call needs an account id in the store's ma-<16 hex> form", async () => {
  const db = await freshDb();
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  for (const bad of MALFORMED_IDS) {
    const shown = JSON.stringify(bad);
    await assert.rejects(credentials.saveSecret(bad, "MAIL_PASSWORD", PASSWORD), mailCode("BAD_INPUT"), `saveSecret ${shown}`);
    await assert.rejects(credentials.getSecrets(bad), mailCode("BAD_INPUT"), `getSecrets ${shown}`);
    await assert.rejects(credentials.deleteSecrets(bad), mailCode("BAD_INPUT"), `deleteSecrets ${shown}`);
  }
  await ensureKeychainTable(db);
  assert.equal((await keychainRows(db)).length, 0, "a refused call writes no row");
});

test("a row of another bundle under the same uuid is never read, overwritten or deleted", async () => {
  const db = await freshDb();
  const home = freshHome();
  const account = await createAccount(db, accountInput(ALEX));
  const credentials = createMailCredentials({ db, crowHome: home });
  const key = await ensureWriteKey(db, { crowHome: home });
  // A project connection's secret that shares the uuid and the env key mail would read.
  await saveServiceSecret(db, key, {
    connectionUuid: account.id,
    bundleId: "some-addon",
    envKey: "MAIL_PASSWORD",
    label: "Another bundle's connection",
    secret: OTHER_PASSWORD,
  });
  assert.equal((await keychainRows(db)).length, 1);

  await refusesAndChangesNothing(db, () => credentials.getSecrets(account.id));
  await refusesAndChangesNothing(db, () => credentials.saveSecret(account.id, "MAIL_PASSWORD", PASSWORD));
  await refusesAndChangesNothing(db, () => credentials.saveSecret(account.id, "MAIL_REFRESH_TOKEN", "refresh-token-9"));
  await refusesAndChangesNothing(db, () => credentials.deleteSecrets(account.id));

  // Its own bundle still reads exactly what it saved: nothing was read, overwritten or removed.
  assert.deepEqual(
    await serviceSecretsFor(db, key, account.id, { allowedKeys: MAIL_SECRET_KEYS }),
    { MAIL_PASSWORD: OTHER_PASSWORD },
  );
  const rows = await keychainRows(db);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].bundle_id, "some-addon");
});

test("a keychain row with no bundle under the same uuid is refused too", async () => {
  const db = await freshDb();
  const account = await createAccount(db, accountInput(ALEX));
  const credentials = createMailCredentials({ db, crowHome: freshHome() });
  await ensureKeychainTable(db);
  await db.execute({
    sql: `INSERT INTO crow_keychain (kind, label, bundle_id, env_key, secret_sealed, key_id, origin, status, connection_uuid)
          VALUES ('service', 'No bundle', NULL, 'MAIL_PASSWORD', 'sealed-placeholder', 'k1', 'typed', 'active', ?)`,
    args: [account.id],
  });
  assert.equal((await keychainRows(db)).length, 1);

  await refusesAndChangesNothing(db, () => credentials.getSecrets(account.id));
  await refusesAndChangesNothing(db, () => credentials.saveSecret(account.id, "MAIL_PASSWORD", PASSWORD));
  await refusesAndChangesNothing(db, () => credentials.deleteSecrets(account.id));
});

/* ------------------------------------------------- key-missing faults travel as they are */

function keyMissingFault(err) {
  assert.ok(err instanceof KeychainKeyMissingError, `expected the key-missing fault, got ${err && err.name}`);
  assert.ok(!(err instanceof MailError), "a missing key is not a mail error");
  assert.equal(err.code, "KEYCHAIN_KEY_MISSING");
  return true;
}

test("a key-missing fault on the password path is not reported as a bad password", async () => {
  const account = { id: "ma-0123456789abcdef", address: ALEX, username: ALEX, authKind: "password" };
  const credentials = { getSecrets: async () => { throw new KeychainKeyMissingError(); } };
  await assert.rejects(authFor(account, { credentials }), keyMissingFault);

  // And through the real keychain: a crow.db whose key file is not on this machine.
  const db = await freshDb();
  const stored = await createAccount(db, accountInput(ALEX));
  await createMailCredentials({ db, crowHome: freshHome() }).saveSecret(stored.id, "MAIL_PASSWORD", PASSWORD);
  const restored = createMailCredentials({ db, crowHome: freshHome() });
  await assert.rejects(authFor(stored, { credentials: restored }), keyMissingFault);
});

test("a key-missing fault from the token provider is rethrown unchanged", async () => {
  const tokenProvider = async () => { throw new KeychainKeyMissingError(); };
  await assert.rejects(authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider }), keyMissingFault);
  // Including on the retry the adapter runs after AUTH_FAILED.
  await assert.rejects(
    authFor(XOAUTH2_ACCOUNT, { credentials: {}, tokenProvider, forceRefresh: true }),
    keyMissingFault,
  );
});

/* --------------------------------------- raw database text never leaves the module */

function explodingDb() {
  const boom = async () => { throw new Error(`SQLITE_ERROR: ${HUNTER} no such value`); };
  return { execute: boom, executeMultiple: boom, batch: boom };
}

/** A wrapped failure: a MailError with its fixed sentence and no database text anywhere on it. */
function assertWrappedNoLeak(thrown) {
  assert.ok(thrown instanceof MailError, `expected a MailError, got ${thrown && thrown.name}`);
  assert.equal(thrown.message, MAIL_ERROR_TEXT[thrown.code], "the fixed sentence for its code");
  const surface = [thrown.message, String(thrown.detail), thrown.code, String(thrown),
    JSON.stringify(thrown), thrown.stack].join("\n");
  assert.ok(!surface.includes(HUNTER), "no field quotes the database's text");
  assert.ok(!surface.includes(PASSWORD), "no field quotes a saved secret");
  return true;
}

async function rejection(call) {
  try {
    await call();
  } catch (err) {
    return err;
  }
  assert.fail("expected the call to fail");
}

test("a failing database leaves saveSecret, getSecrets and deleteSecrets as fixed mail errors", async () => {
  const credentials = createMailCredentials({ db: explodingDb(), crowHome: freshHome() });
  const id = "ma-0123456789abcdef";
  // saveSecret fails in its label lookup first, before any key or row is written.
  assertWrappedNoLeak(await rejection(() => credentials.saveSecret(id, "MAIL_PASSWORD", PASSWORD)));
  assertWrappedNoLeak(await rejection(() => credentials.getSecrets(id)));
  assertWrappedNoLeak(await rejection(() => credentials.deleteSecrets(id)));
});

test("a failing database on the password path of authFor leaves a fixed mail error", async () => {
  const account = { id: "ma-0123456789abcdef", address: ALEX, username: ALEX, authKind: "password" };
  assertWrappedNoLeak(await rejection(() => authFor(account, {
    credentials: { getSecrets: async () => { throw new Error(`keychain read failed for ${HUNTER}`); } },
  })));
  assertWrappedNoLeak(await rejection(() => authFor(account, {
    credentials: createMailCredentials({ db: explodingDb(), crowHome: freshHome() }),
  })));
});