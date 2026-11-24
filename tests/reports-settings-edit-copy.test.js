// Crow Recurring Reports: the settings form's approved copy, and the sender list the form's menu is
// built from.
//
// Two things here, both pinned by hand:
//   - the eight new strings the owner's settings form shows (its sender label, its Save button, the line
//     a live report carries, and the four answers a save gets back). The English and Spanish of each are
//     written out in full, on purpose: an approved sentence that drifts has to fail here rather than
//     change silently.
//   - `listSendReadyAccounts`, which is the same rule as `senderReady` over the whole account list. It
//     answers `{id, address}` pairs and nothing else, in the owner's order, from the rows one account read
//     already answered (checked side by side, at most the first 50), and a failure is an empty list.
//
// Harness for the second half: a real init-db'd scratch crow.db copied per test (CROW_DATA_DIR and
// CROW_HOME under a temp dir, so nothing reaches a real Crow), real mail account rows and the keychain
// save path (`createMailCredentials`), which is how a credential really gets on this machine.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-settings-copy-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { translations, t } = await import("../servers/gateway/dashboard/shared/i18n.js");
const { listSendReadyAccounts } = await import("../servers/gateway/reports/sender-ready.js");
const { createDbClient } = await import("../servers/db.js");
const { createAccount, updateAccount } = await import("../servers/gateway/mail/store/accounts.js");
const { createMailCredentials } = await import("../servers/gateway/mail/credentials.js");

const open = [];

after(() => {
  for (const db of open) { try { db.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
});

/* ------------------------------------------------------------------ the copy */

/**
 * The settings form's approved strings, exactly as they were approved. Both languages are spelled out so
 * a wording change, a reworded Spanish line or a lost apostrophe fails here.
 */
const APPROVED = {
  "projectReports.settings.senderLabel": {
    en: "Sending account",
    es: "Cuenta de envío",
  },
  "projectReports.settings.save": {
    en: "Save settings",
    es: "Guardar ajustes",
  },
  "projectReports.settings.liveWarning": {
    en: "Saving changes pauses this report until you approve it again.",
    es: "Al guardar los cambios, este informe se pausa hasta que lo apruebes de nuevo.",
  },
  "projectReports.settings.saved": {
    en: "Settings saved.",
    es: "Ajustes guardados.",
  },
  "projectReports.settings.savedPaused": {
    en: "Settings saved. The report is paused until you approve it again.",
    es: "Ajustes guardados. El informe está en pausa hasta que lo apruebes de nuevo.",
  },
  "projectReports.settings.windowRange": {
    en: "Choose a number from 1 to 50.",
    es: "Elige un número del 1 al 50.",
  },
  "projectReports.settings.nothingChanged": {
    en: "Nothing changed.",
    es: "No hubo cambios.",
  },
  "projectReports.settings.senderNotReady": {
    en: "That account can't send right now. Choose another one, or sign in to it again in Mail.",
    es: "Esa cuenta no puede enviar ahora. Elige otra o vuelve a iniciar sesión en ella en Correo.",
  },
};

test("the settings form's eight strings are the approved words, in both languages", () => {
  const keys = Object.keys(APPROVED);
  assert.equal(keys.length, 8, "eight new strings, no more");
  for (const key of keys) {
    const row = translations[key];
    assert.ok(row, `${key} is in the table`);
    assert.equal(row.en, APPROVED[key].en, `${key}: English is the approved sentence`);
    assert.equal(row.es, APPROVED[key].es, `${key}: Spanish is the approved sentence`);
    // The page renders through t(), so the same words come back from the lookup a page uses.
    assert.equal(t(key, "en"), APPROVED[key].en, `${key}: English through t()`);
    assert.equal(t(key, "es"), APPROVED[key].es, `${key}: Spanish through t()`);
    assert.notEqual(row.es, row.en, `${key} is really translated`);
  }
});

/* ------------------------------------------------------- the send-ready account list */

let n = 0;

async function freshDb() {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  return db;
}

const ENDPOINT = { host: "mail.example.test", port: 993, security: "ssl" };

/**
 * One real mail account, and (when `secret` is given) the credential a password or an OAuth account
 * signs in with. `createdAt` pins the order `listAccounts` answers in, which is the order this list
 * keeps.
 */
async function addAccount(db, { address, authKind = "password", secret = null, createdAt = 1 }) {
  const local = address.split("@")[0];
  const account = await createAccount(db, {
    label: local,
    address,
    username: local,
    authKind,
    imap: ENDPOINT,
    smtp: { ...ENDPOINT, port: 465 },
  });
  if (secret) {
    const key = authKind === "xoauth2" ? "MAIL_REFRESH_TOKEN" : "MAIL_PASSWORD";
    await createMailCredentials({ db, crowHome: process.env.CROW_HOME }).saveSecret(account.id, key, secret);
  }
  await db.execute({ sql: "UPDATE mail_accounts SET created_at = ? WHERE id = ?", args: [createdAt, account.id] });
  return account;
}

test("an active account with its credential is listed as an id and an address, in the owner's own order", async () => {
  const db = await freshDb();
  const first = await addAccount(db, {
    address: "alex@example.com", secret: "app-password-value", createdAt: 10,
  });
  const second = await addAccount(db, {
    address: "sam@example.com", authKind: "xoauth2", secret: "refresh-token-value", createdAt: 20,
  });
  const options = await listSendReadyAccounts(db);
  assert.deepEqual(options, [
    { id: first.id, address: "alex@example.com" },
    { id: second.id, address: "sam@example.com" },
  ]);
  for (const option of options) {
    assert.deepEqual(Object.keys(option), ["id", "address"],
      "the menu gets the id a save writes and the address a person reads, nothing else");
  }
});

test("a signed-out account is not listed, even with its credential on this machine", async () => {
  const db = await freshDb();
  await addAccount(db, { address: "alex@example.com", secret: "app-password-value", createdAt: 10 });
  const signedOut = await addAccount(db, {
    address: "sam@example.com", secret: "app-password-value", createdAt: 20,
  });
  await updateAccount(db, signedOut.id, { status: "auth_failed" });
  assert.deepEqual((await listSendReadyAccounts(db)).map((option) => option.address), ["alex@example.com"]);
});

test("an active account with no credential saved here is not listed", async () => {
  const db = await freshDb();
  await addAccount(db, { address: "alex@example.com", secret: "app-password-value", createdAt: 10 });
  await addAccount(db, { address: "sam@example.com", createdAt: 20 });
  assert.deepEqual((await listSendReadyAccounts(db)).map((option) => option.address), ["alex@example.com"]);
});

test("an account whose sign-in kind this Crow does not know is not listed", async () => {
  // The store refuses such a kind (createAccount validates it), so the row is written the way an older
  // or hand-edited crow.db would carry one. It is otherwise perfectly ready: active, with a credential.
  const db = await freshDb();
  await addAccount(db, { address: "alex@example.com", secret: "app-password-value", createdAt: 10 });
  const legacy = await addAccount(db, {
    address: "sam@example.com", secret: "app-password-value", createdAt: 20,
  });
  await db.execute({ sql: "UPDATE mail_accounts SET auth_kind = 'oauth_legacy' WHERE id = ?", args: [legacy.id] });
  assert.deepEqual((await listSendReadyAccounts(db)).map((option) => option.address), ["alex@example.com"]);
});

test("an account list that cannot be read is an empty list, never a failure", async () => {
  const broken = {
    execute: async () => { throw new Error("the account table is not there"); },
  };
  assert.deepEqual(await listSendReadyAccounts(broken), []);
  // A list a reader cannot use is empty too, rather than a throw into the page.
  assert.deepEqual(await listSendReadyAccounts({}), []);
});

test("no accounts at all is an empty list", async () => {
  const db = await freshDb();
  assert.deepEqual(await listSendReadyAccounts(db), []);
});

test("the owner's order holds when the accounts are checked at the same time", async () => {
  const db = await freshDb();
  // Saved out of order on purpose: the list answers oldest first, whatever order the concurrent reads
  // finish in.
  const rows = [
    ["four@example.com", 40], ["one@example.com", 10], ["six@example.com", 60],
    ["two@example.com", 20], ["five@example.com", 50], ["three@example.com", 30],
  ];
  const byAddress = new Map();
  for (const [address, createdAt] of rows) {
    const account = await addAccount(db, { address, secret: "app-password-value", createdAt });
    byAddress.set(address, account.id);
  }
  const options = await listSendReadyAccounts(db);
  assert.deepEqual(options.map((option) => option.address), [
    "one@example.com", "two@example.com", "three@example.com",
    "four@example.com", "five@example.com", "six@example.com",
  ], "the list keeps the order listAccounts answered in");
  assert.deepEqual(options.map((option) => option.id), [
    byAddress.get("one@example.com"), byAddress.get("two@example.com"), byAddress.get("three@example.com"),
    byAddress.get("four@example.com"), byAddress.get("five@example.com"), byAddress.get("six@example.com"),
  ], "each id stays beside its own row");
});

test("only the first 50 accounts are considered", async () => {
  const db = await freshDb();
  const ids = [];
  for (let i = 1; i <= 60; i += 1) {
    const address = `person${String(i).padStart(2, "0")}@example.com`;
    const account = await addAccount(db, { address, secret: "app-password-value", createdAt: i });
    ids.push(account.id);
  }
  const options = await listSendReadyAccounts(db);
  assert.equal(options.length, 50, "sixty ready accounts answer fifty");
  assert.deepEqual(options.map((option) => option.id), ids.slice(0, 50), "the first fifty the owner added, in order");
  assert.equal(options.some((option) => option.id === ids[50]), false, "nothing from after the cap");
});

test("an account whose secret cannot be read is dropped, and the others stay", async () => {
  const db = await freshDb();
  const first = await addAccount(db, { address: "alex@example.com", secret: "app-password-value", createdAt: 10 });
  const broken = await addAccount(db, { address: "sam@example.com", secret: "app-password-value", createdAt: 20 });
  const third = await addAccount(db, { address: "jo@example.com", secret: "app-password-value", createdAt: 30 });
  // A keychain row under another bundle for that account's uuid is a real read fault: the credentials
  // read refuses the uuid rather than serve a row mail does not own.
  await db.execute({
    sql: `INSERT INTO crow_keychain (kind, label, bundle_id, env_key, secret_sealed, key_id, origin, status,
            connection_uuid, created_at, updated_at)
          VALUES ('service', 'another project', 'some-other-bundle', 'SOME_KEY', 'sealed-elsewhere',
            'key-id-elsewhere', 'typed', 'active', ?, '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z')`,
    args: [broken.id],
  });
  await assert.rejects(
    createMailCredentials({ db, crowHome: process.env.CROW_HOME }).getSecrets(broken.id),
    "the credentials read really throws for that account",
  );
  assert.deepEqual((await listSendReadyAccounts(db)).map((option) => option.id), [first.id, third.id],
    "the account that could not be read is left out, the ones around it are not");
});

test("the account table is read once for the whole list, not once per account", async () => {
  const db = await freshDb();
  for (const [address, createdAt] of [
    ["one@example.com", 10], ["two@example.com", 20], ["three@example.com", 30],
  ]) {
    await addAccount(db, { address, secret: "app-password-value", createdAt });
  }
  // A pass-through client that counts the statements naming mail_accounts: one read answers the whole
  // list, so a per-account getAccount would show up here.
  let accountReads = 0;
  const counting = {
    execute(query, ...rest) {
      const sql = typeof query === "string" ? query : String(query && query.sql ? query.sql : "");
      if (sql.includes("mail_accounts")) accountReads += 1;
      return db.execute(query, ...rest);
    },
    executeMultiple(sql, ...rest) { return db.executeMultiple(sql, ...rest); },
    batch(...args) { return db.batch(...args); },
    close() {},
  };
  const options = await listSendReadyAccounts(counting);
  assert.equal(options.length, 3, "all three accounts are ready");
  assert.equal(accountReads, 1, "the account table is read once for the whole list");
});